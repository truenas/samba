// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The receive path. A PDU that fits a class 0 block arrives in it. A larger
//! one gets its own block, with a copy of the read-ahead bytes only.

use std::ptr;
use std::sync::atomic::Ordering;

use crate::block::Block;
use crate::reactor::{Handler, Reactor, UD_RECV};
use crate::ring::{IOSQE_FIXED_FILE, OP_RECV, Sqe};

/// The bytes of the length header of a PDU.
const HDR: u32 = 4;

impl<S> Reactor<S> {
    fn arm_recv<H: Handler<State = S>>(&mut self, len: u32, exact: bool) {
        let Some(b) = self.cur.as_ref() else {
            return;
        };
        let s = Sqe {
            opcode: OP_RECV,
            flags: IOSQE_FIXED_FILE,
            fd: 0,
            // SAFETY: `have` is below the capacity of the block.
            addr: unsafe { b.data().add(self.have as usize) } as u64,
            len,
            op_flags: if exact { libc::MSG_WAITALL as u32 } else { 0 },
            user_data: UD_RECV,
            ..Sqe::ZERO
        };
        // SAFETY: `cur` keeps the block, untouched until the completion.
        if unsafe { self.push_sqe(s) } {
            self.recv_armed = true;
        } else {
            self.fail::<H>(libc::EIO);
        }
    }

    /// The length after the header in the first 4 bytes of a PDU.
    #[inline]
    fn frame_len<H: Handler<State = S>>(d: [u8; 4]) -> u32 {
        if H::NBT {
            u32::from_be_bytes([0, d[1], d[2], d[3]])
        } else {
            u32::from_be_bytes(d)
        }
    }

    /// Take the slots that other threads released. True if under the cap.
    fn take_releases(&mut self) -> bool {
        let mut n = self.sh().released.swap(0, Ordering::Acquire);
        if n == 0 {
            self.sh().cap_wait.store(true, Ordering::SeqCst);
            n = self.sh().released.swap(0, Ordering::SeqCst);
            if n == 0 {
                self.capped = true;
                return false;
            }
        }
        self.sh().cap_wait.store(false, Ordering::Relaxed);
        self.capped = false;
        self.inflight -= n;
        self.inflight < self.cfg.max_inflight
    }

    /// Release an in-flight slot on the reactor thread.
    #[inline]
    pub fn release(&mut self) {
        self.inflight -= 1;
        if self.capped {
            // Other threads need not wake the reactor for releases now.
            self.capped = false;
            self.sh().cap_wait.store(false, Ordering::Relaxed);
        }
    }

    /// The next whole PDU and its length after the header, with one
    /// in-flight slot. Else arm a read and return None.
    pub(crate) fn next_pdu<H: Handler<State = S>>(
        &mut self,
    ) -> Option<(Block, u32)> {
        if self.recv_armed || self.stopping {
            return None;
        }
        if self.inflight >= self.cfg.max_inflight && !self.take_releases() {
            return None;
        }
        let (cap, data) = if let Some(b) = &self.cur {
            (b.cap(), b.data())
        } else {
            let Some(b) = self.blocks.get_class(0) else {
                self.fail::<H>(libc::ENOMEM);
                return None;
            };
            self.have = 0;
            self.total = 0;
            let b = self.cur.insert(b);
            (b.cap(), b.data())
        };
        if self.have < HDR {
            let room = cap - self.have;
            let want = self.cfg.readahead.max(HDR - self.have);
            self.arm_recv::<H>(want.min(room), false);
            return None;
        }
        if self.total == 0 {
            // SAFETY: the kernel wrote the first `have` (4 or more) bytes.
            let len = Self::frame_len::<H>(unsafe { *data.cast::<[u8; 4]>() });
            if len > 0x00ff_ffff {
                self.fail::<H>(libc::EIO);
                return None;
            }
            self.total = HDR + len;
        }
        if self.have >= self.total {
            return self.take_pdu::<H>();
        }
        if self.total > cap {
            self.place::<H>()?;
        }
        self.arm_recv::<H>(self.total - self.have, true);
        None
    }

    /// Move the PDU in `cur` to a block of its own.
    #[cold]
    #[inline(never)]
    fn place<H: Handler<State = S>>(&mut self) -> Option<()> {
        let Some(big) = self.blocks.get(self.total as usize) else {
            self.fail::<H>(libc::ENOMEM);
            return None;
        };
        let b = self.cur.replace(big)?;
        // SAFETY: `b` has `have` bytes, and `big` has room for the PDU.
        unsafe {
            ptr::copy_nonoverlapping(
                b.data(),
                self.cur.as_ref()?.data(),
                self.have as usize,
            );
        }
        self.blocks.put(b);
        Some(())
    }

    fn take_pdu<H: Handler<State = S>>(&mut self) -> Option<(Block, u32)> {
        let b = self.cur.take()?;
        let total = self.total;
        let extra = self.have - total;
        self.have = 0;
        self.total = 0;
        if extra > 0 {
            // The header read took the start of the next PDU.
            let Some(nb) = self.blocks.get_class(0) else {
                self.blocks.put(b);
                self.fail::<H>(libc::ENOMEM);
                return None;
            };
            // SAFETY: the kernel wrote the `extra` bytes, which fit `nb`.
            unsafe {
                ptr::copy_nonoverlapping(
                    b.data().add(total as usize),
                    nb.data(),
                    extra as usize,
                );
            }
            self.cur = Some(nb);
            self.have = extra;
        }
        self.inflight += 1;
        Some((b, total - HDR))
    }

    pub(crate) fn on_recv<H: Handler<State = S>>(&mut self, res: i32) {
        self.recv_armed = false;
        if res > 0 {
            self.have += res.unsigned_abs();
            return;
        }
        if self.stopping {
            return;
        }
        match -res {
            0 => self.end::<H>(0),
            libc::EINTR | libc::EAGAIN => {}
            e => self.end::<H>(e),
        }
    }
}
