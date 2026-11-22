// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The send path: queued PDUs in order, up to 8 per sendmsg, zero-copy from
//! `zc_min` bytes.

use std::ptr::{self, NonNull};

use crate::block::try_box;
use crate::list::BoxList;
use crate::out::Out;
use crate::reactor::{Handler, Reactor, TAG_ZC, UD_SEND};
use crate::ring::{
    CQE_F_MORE, CQE_F_NOTIF, IOSQE_FIXED_FILE, NOTIF_USAGE_ZC_COPIED, OP_SEND,
    OP_SEND_ZC, OP_SENDMSG, OP_SENDMSG_ZC, SEND_ZC_REPORT_USAGE, Sqe,
};

const MAXIOV: usize = 64;
const MAXOUTS: usize = 8;

const NO_IOV: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};

// The tag of a completion is in the low 3 bits of the gather's address.
const _: () = assert!(align_of::<Gather>() >= 8);

/// The PDUs of one send.
#[derive(Debug)]
pub struct Gather {
    pub(crate) outs: BoxList<Out>,
    iov: [libc::iovec; MAXIOV],
    niov: usize,
    first: usize,
    hdr: libc::msghdr,
    total: usize,
    sent: usize,
    zc: bool,
    /// Zero-copy sends without their result yet.
    results: u32,
    /// Notifications that are still due.
    notifs: u32,
    done: bool,
}

impl Gather {
    pub(crate) fn new() -> Gather {
        Gather {
            outs: BoxList::new(),
            iov: [NO_IOV; MAXIOV],
            niov: 0,
            first: 0,
            // SAFETY: a zeroed msghdr is valid and empty.
            hdr: unsafe { std::mem::zeroed() },
            total: 0,
            sent: 0,
            zc: false,
            results: 0,
            notifs: 0,
            done: false,
        }
    }

    /// Empty a gather that has no outs.
    fn reset(&mut self) {
        self.niov = 0;
        self.first = 0;
        self.total = 0;
        self.sent = 0;
        self.zc = false;
        self.results = 0;
        self.notifs = 0;
        self.done = false;
    }

    /// Skip the first `n` bytes that are left.
    fn advance(&mut self, n: usize) {
        let mut left = n;
        while left > 0 && self.first < self.niov {
            let v = &mut self.iov[self.first];
            if left < v.iov_len {
                // SAFETY: the vector has more than `left` bytes.
                v.iov_base =
                    unsafe { v.iov_base.cast::<u8>().add(left) }.cast();
                v.iov_len -= left;
                return;
            }
            left -= v.iov_len;
            self.first += 1;
        }
    }

    /// The SQE for the bytes that are left.
    fn sqe(&mut self) -> Sqe {
        let n = self.niov - self.first;
        let iov = &mut self.iov[self.first..self.niov];
        let flags = (libc::MSG_WAITALL | libc::MSG_NOSIGNAL) as u32;
        let ioprio = if self.zc { SEND_ZC_REPORT_USAGE } else { 0 };
        let mut s = if n == 1 {
            Sqe {
                opcode: if self.zc { OP_SEND_ZC } else { OP_SEND },
                addr: iov[0].iov_base as u64,
                // A PDU has less than 16 MiB. A longer one sends nothing.
                len: u32::try_from(iov[0].iov_len).unwrap_or(0),
                ..Sqe::ZERO
            }
        } else {
            // SAFETY: a zeroed msghdr is valid and empty.
            self.hdr = unsafe { std::mem::zeroed() };
            self.hdr.msg_iov = iov.as_mut_ptr();
            self.hdr.msg_iovlen = n;
            Sqe {
                opcode: if self.zc { OP_SENDMSG_ZC } else { OP_SENDMSG },
                addr: (&raw const self.hdr) as u64,
                len: 1,
                ..Sqe::ZERO
            }
        };
        s.ioprio = ioprio;
        s.op_flags = flags;
        s.flags = IOSQE_FIXED_FILE;
        s
    }
}

/// Where a send gets its gather.
#[derive(Debug, Clone, Copy)]
enum Which {
    /// The gather in the reactor.
    Main,
    /// A zero-copy gather that the send owns.
    Zc(NonNull<Gather>),
}

impl<S> Reactor<S> {
    /// An out from the free list, or None without memory.
    #[inline]
    pub fn new_out(&mut self) -> Option<Box<Out>> {
        let mut o = match self.outs.take() {
            Some(mut o) => {
                o.reset();
                o
            }
            None => try_box(Out::new)?,
        };
        o.pooled = true;
        Some(o)
    }

    /// Free the storage and the out on the reactor thread.
    #[inline]
    pub fn free_out(&mut self, mut o: Box<Out>) {
        o.drop_data(Some(&mut self.blocks));
        if o.pooled {
            self.outs.put(o);
        }
    }

    pub(crate) fn release_outs<H: Handler<State = S>>(
        &mut self,
        mut l: BoxList<Out>,
    ) {
        while let Some(o) = l.pop() {
            H::release_out(self, o);
        }
    }

    pub(crate) fn kick_send<H: Handler<State = S>>(&mut self) {
        if self.sending || self.stopping || self.sendq.is_empty() {
            return;
        }
        let g = &mut self.gather;
        g.reset();
        for _ in 0..MAXOUTS {
            let Some(o) = self.sendq.first() else {
                break;
            };
            let nseg = usize::from(o.nseg);
            if g.niov + nseg > MAXIOV {
                break;
            }
            let Some(o) = self.sendq.pop() else {
                break;
            };
            for s in &o.segs[..nseg] {
                g.iov[g.niov] = *s;
                g.niov += 1;
                g.total += s.iov_len;
            }
            g.outs.push(o);
        }
        if self.zc_on
            && self.gather.total >= self.cfg.zc_min
            && self.zc_pinned + self.gather.total <= self.cfg.zc_max_pinned
            && let Some(z) = self.zc_gather()
        {
            self.submit_send::<H>(Which::Zc(z));
            return;
        }
        self.submit_send::<H>(Which::Main);
    }

    /// Move the main gather to a zero-copy gather of its own.
    fn zc_gather(&mut self) -> Option<NonNull<Gather>> {
        let mut z = match self.zcs.take() {
            Some(z) => z,
            None => try_box(Gather::new)?,
        };
        let g = &mut self.gather;
        z.reset();
        z.outs = std::mem::take(&mut g.outs);
        z.iov[..g.niov].copy_from_slice(&g.iov[..g.niov]);
        z.niov = g.niov;
        z.total = g.total;
        z.zc = true;
        self.zc_pinned += z.total;
        g.reset();
        // The send owns the gather until zc_settle().
        Some(NonNull::from(Box::leak(z)))
    }

    fn submit_send<H: Handler<State = S>>(&mut self, w: Which) {
        let g = match w {
            Which::Main => &mut self.gather,
            // SAFETY: the send owns the gather, with no other reference.
            Which::Zc(p) => unsafe { &mut *p.as_ptr() },
        };
        let mut s = g.sqe();
        s.user_data = match w {
            Which::Main => UD_SEND,
            Which::Zc(p) => p.as_ptr() as u64 | TAG_ZC,
        };
        // SAFETY: the gather keeps its outs and their lent memory until done.
        if !unsafe { self.push_sqe(s) } {
            self.sending = false;
            if let Which::Zc(p) = w {
                // No operation names the gather now. Its PDUs go back after
                // the notifications that it is owed.
                // SAFETY: as above.
                unsafe { (*p.as_ptr()).done = true };
                self.zc_settle::<H>(p);
            }
            self.fail::<H>(libc::EIO);
            return;
        }
        if let Which::Zc(p) = w {
            // SAFETY: as above.
            unsafe { (*p.as_ptr()).results += 1 };
        }
        self.sending = true;
    }

    pub(crate) fn on_send<H: Handler<State = S>>(&mut self, res: i32) {
        if res < 0 {
            let e = -res;
            if !self.stopping && (e == libc::EINTR || e == libc::EAGAIN) {
                self.submit_send::<H>(Which::Main);
                return;
            }
            self.sending = false;
            let outs = std::mem::take(&mut self.gather.outs);
            self.release_outs::<H>(outs);
            if !self.stopping {
                self.end::<H>(libc::ECONNABORTED);
            }
            return;
        }
        let n = res.unsigned_abs() as usize;
        let g = &mut self.gather;
        g.sent += n;
        if g.sent < g.total && !self.stopping {
            if n == 0 {
                self.sending = false;
                let outs = std::mem::take(&mut self.gather.outs);
                self.release_outs::<H>(outs);
                self.end::<H>(libc::ECONNABORTED);
                return;
            }
            g.advance(n);
            self.submit_send::<H>(Which::Main);
            return;
        }
        self.sending = false;
        let outs = std::mem::take(&mut self.gather.outs);
        self.release_outs::<H>(outs);
    }

    /// A completion of the zero-copy send of the gather at `ud`.
    pub(crate) fn on_zc<H: Handler<State = S>>(
        &mut self,
        ud: u64,
        res: i32,
        flags: u32,
    ) {
        let Some(p) = NonNull::new(ud as *mut Gather) else {
            return;
        };
        // SAFETY: `ud` is the gather that the send owns, with no other use.
        let g = unsafe { &mut *p.as_ptr() };
        if flags & CQE_F_NOTIF != 0 {
            if res.cast_unsigned() & NOTIF_USAGE_ZC_COPIED != 0 {
                self.zc_on = false;
            }
            g.notifs -= 1;
            self.zc_notifs -= 1;
            self.zc_settle::<H>(p);
            return;
        }
        g.results -= 1;
        if flags & CQE_F_MORE != 0 {
            g.notifs += 1;
            self.zc_notifs += 1;
            self.ops += 1;
        }
        if res < 0 {
            let e = -res;
            if !self.stopping
                && g.sent == 0
                && (e == libc::EOPNOTSUPP
                    || e == libc::ENOMEM
                    || e == libc::EINVAL)
            {
                // Nothing went out. Send the PDUs again with a copy.
                self.zc_on = false;
                let mut outs = std::mem::take(&mut g.outs);
                outs.concat(&mut self.sendq);
                self.sendq = outs;
            } else if !self.stopping && (e == libc::EINTR || e == libc::EAGAIN)
            {
                self.submit_send::<H>(Which::Zc(p));
                return;
            } else if !self.stopping {
                self.end::<H>(libc::ECONNABORTED);
            }
            self.sending = false;
            g.done = true;
            self.zc_settle::<H>(p);
            return;
        }
        let n = res.unsigned_abs() as usize;
        g.sent += n;
        if g.sent < g.total && !self.stopping && n > 0 {
            g.advance(n);
            self.submit_send::<H>(Which::Zc(p));
            return;
        }
        let short = g.sent < g.total;
        g.done = true;
        if short && !self.stopping {
            self.end::<H>(libc::ECONNABORTED);
        }
        self.sending = false;
        self.zc_settle::<H>(p);
    }

    /// Release the PDUs of a zero-copy send once the kernel is done.
    fn zc_settle<H: Handler<State = S>>(&mut self, p: NonNull<Gather>) {
        {
            // SAFETY: as in on_zc().
            let g = unsafe { &*p.as_ptr() };
            if !g.done || g.results != 0 || g.notifs != 0 {
                return;
            }
        }
        // SAFETY: zc_gather() leaked the box, and no operation names it now.
        let mut z = unsafe { Box::from_raw(p.as_ptr()) };
        self.zc_pinned -= z.total;
        let outs = std::mem::take(&mut z.outs);
        self.release_outs::<H>(outs);
        self.zcs.put(z);
    }
}
