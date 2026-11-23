// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The interim responses of jobs that run past 500 microseconds, as smbd
//! sends them, with one ring timer per connection.

use truenas_smbros::{Shim, ShimReactor, Sqe, TAG_UPPER, sys};

use crate::crypto::{CryptoOps, Seal};
use crate::upper::Layer;
use crate::wire::{
    NBT_HDR_SIZE, NT_STATUS_PENDING, SMB2_HDR_ASYNC_ID, SMB2_HDR_CREDIT,
    SMB2_HDR_FLAG_ASYNC, SMB2_HDR_FLAG_SIGNED, SMB2_HDR_FLAGS, SMB2_HDR_LENGTH,
    SMB2_HDR_MAGIC, SMB2_HDR_MESSAGE_ID, SMB2_HDR_OPCODE, SMB2_HDR_SESSION_ID,
    SMB2_HDR_SIGNATURE, SMB2_HDR_SIZE, SMB2_HDR_STATUS, SMB2_TF_NONCE,
    SMB2_TF_SIZE, le32, put16, put32, set_nbt_len,
};

/// As in `smb2_read.c`, `smb2_write.c` and `smb2_flush.c`.
const AFTER_NS: u64 = 500 * 1000;
/// The handler id of the timer completion, above the tag bits.
pub(crate) const TIMER_ID: u64 = 1;
/// smbd sends the 0x21 to match Windows Server 2008 R2.
const BODY: [u8; 9] = [9, 0, 0, 0, 0, 0, 0, 0, 0x21];
const HEAD_MAX: usize = NBT_HDR_SIZE + SMB2_TF_SIZE + SMB2_HDR_SIZE;
const QLEN: usize = 256;
const NS_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug)]
struct Entry {
    deadline: u64,
    /// The file I/O of the job ended.
    done: bool,
    /// The offset of the SMB2 header in `head`.
    hdr: u8,
    seal: Seal,
    head: [u8; HEAD_MAX],
}

impl Default for Entry {
    fn default() -> Self {
        Entry {
            deadline: 0,
            done: false,
            hdr: 0,
            seal: Seal::default(),
            head: [0; HEAD_MAX],
        }
    }
}

/// `struct __kernel_timespec`.
#[repr(C)]
#[derive(Debug, Default)]
struct KTimespec {
    sec: i64,
    nsec: i64,
}

/// The interim responses of one connection.
#[derive(Debug)]
pub(crate) struct Interims {
    q: Box<[Entry]>,
    /// The index and the number of the first job in `q`.
    head: usize,
    first: u64,
    len: usize,
    armed: bool,
    /// A retraction moves it on, so a retracted timer's CQE is stale.
    generation: u64,
    ts: KTimespec,
}

fn timer_ud(generation: u64) -> u64 {
    (generation << 8) | (TIMER_ID << 3) | TAG_UPPER
}

impl Interims {
    pub(crate) fn new() -> Interims {
        Interims {
            q: (0..QLEN).map(|_| Entry::default()).collect(),
            head: 0,
            first: 0,
            len: 0,
            armed: false,
            generation: 0,
            ts: KTimespec::default(),
        }
    }

    fn at(&mut self, i: usize) -> &mut Entry {
        &mut self.q[(self.head + i) % QLEN]
    }

    /// Remove the first entry and give back its seal.
    fn pop_front(&mut self) -> (bool, Seal) {
        let e = &mut self.q[self.head];
        let got = (e.done, std::mem::take(&mut e.seal));
        self.head = (self.head + 1) % QLEN;
        self.len -= 1;
        self.first += 1;
        got
    }

    fn arm(&mut self, r: &mut ShimReactor, after: u64) {
        self.ts = KTimespec {
            sec: i64::try_from(after / NS_PER_SEC).unwrap_or(i64::MAX),
            nsec: i64::try_from(after % NS_PER_SEC).unwrap_or(0),
        };
        let s = Sqe {
            opcode: Sqe::OP_TIMEOUT,
            fd: -1,
            addr: (&raw const self.ts) as u64,
            len: 1,
            user_data: timer_ud(self.generation),
            ..Sqe::ZERO
        };
        // SAFETY: the timespec is in local state that outlives operations.
        if unsafe { r.push_sqe(s) } {
            self.armed = true;
        }
    }

    /// Retract the timer when no job is left.
    fn retract(&mut self, r: &mut ShimReactor) {
        let ud = timer_ud(self.generation);
        self.generation += 1;
        self.armed = false;
        let s = Sqe {
            opcode: Sqe::OP_TIMEOUT_REMOVE,
            fd: -1,
            addr: ud,
            ..Sqe::ZERO
        };
        // SAFETY: a timeout removal names no memory.
        unsafe { r.push_sqe_uncounted(s) };
    }

    /// Queue the interim response for the reply in `head`. Returns the
    /// number of the job, or None if the queue is full.
    pub(crate) fn watch(
        &mut self,
        r: &mut ShimReactor,
        head: &[u8],
        seal: &Seal,
        nonce: &[u8; 16],
    ) -> Option<u64> {
        if self.len == QLEN {
            return None;
        }
        let hdr = seal.hdr();
        let n = self.len;
        let e = self.at(n);
        e.deadline = sys::now_ns() + AFTER_NS;
        e.done = false;
        e.hdr = u8::try_from(hdr).unwrap_or(0);
        e.head[..hdr + SMB2_HDR_SIZE]
            .copy_from_slice(&head[..hdr + SMB2_HDR_SIZE]);
        if hdr > NBT_HDR_SIZE {
            // smbd encrypts an interim response with a nonce of its own.
            let at = NBT_HDR_SIZE + SMB2_TF_NONCE;
            e.head[at..at + 16].copy_from_slice(nonce);
        }
        e.seal = seal.interim();
        self.len += 1;
        if !self.armed {
            self.arm(r, AFTER_NS);
        }
        Some(self.first + self.len as u64 - 1)
    }

    /// The I/O of job `seq` ended. After an interim response, the reply in
    /// `buf` becomes the final response.
    pub(crate) fn finish(
        &mut self,
        r: &mut ShimReactor,
        seq: u64,
        buf: &mut [u8],
        hdr: usize,
    ) {
        if seq < self.first {
            set_async(&mut buf[hdr..hdr + SMB2_HDR_SIZE]);
        } else {
            let i = usize::try_from(seq - self.first).unwrap_or(QLEN);
            if i < self.len {
                self.at(i).done = true;
            }
            // Remove the ended jobs at the front now.
            while self.len > 0 && self.q[self.head].done {
                drop(self.pop_front());
            }
        }
        if self.armed && self.len == 0 {
            self.retract(r);
        }
    }

    /// Send the interim responses that are due and arm the next deadline.
    pub(crate) fn on_timer(
        &mut self,
        r: &mut ShimReactor,
        ops: Option<&CryptoOps>,
        ud: u64,
        res: i32,
    ) {
        if ud >> 8 != self.generation || !self.armed || res != -libc::ETIME {
            return;
        }
        self.armed = false;
        if r.stopping {
            return;
        }
        let now = sys::now_ns();
        while self.len > 0 {
            let e = &self.q[self.head];
            if !e.done && e.deadline > now {
                break;
            }
            // The reply grants no credits after an interim response, so a
            // client without the interim response loses them. smbd closes
            // the connection then.
            if !e.done
                && let Err(err) = send_interim(r, ops, e)
            {
                r.fail::<Shim<Layer>>(err);
                return;
            }
            drop(self.pop_front());
        }
        if self.len > 0 {
            let next = self.q[self.head].deadline - now;
            self.arm(r, next);
        }
    }

    pub(crate) fn clear(&mut self) {
        while self.len > 0 {
            drop(self.pop_front());
        }
    }
}

/// As `smbd_smb2_request_pending_timer()` builds it. The errno if it
/// cannot go out: ENOMEM without memory, as smbd's `NT_STATUS_NO_MEMORY`.
fn send_interim(
    r: &mut ShimReactor,
    ops: Option<&CryptoOps>,
    e: &Entry,
) -> Result<(), libc::c_int> {
    let Some(mut o) = r.new_out() else {
        return Err(libc::ENOMEM);
    };
    let hdr = usize::from(e.hdr);
    let len = hdr + SMB2_HDR_SIZE + BODY.len();
    let pdu = o.inline_zeroed(len);
    pdu[..hdr].copy_from_slice(&e.head[..hdr]);
    let src = &e.head[hdr..hdr + SMB2_HDR_SIZE];
    let h = &mut pdu[hdr..hdr + SMB2_HDR_SIZE];
    h[..4].copy_from_slice(&SMB2_HDR_MAGIC);
    put16(h, SMB2_HDR_LENGTH, 64);
    put32(h, SMB2_HDR_STATUS, NT_STATUS_PENDING);
    for (at, n) in [
        (SMB2_HDR_OPCODE, 2),
        (SMB2_HDR_CREDIT, 2),
        (SMB2_HDR_MESSAGE_ID, 8),
        (SMB2_HDR_SESSION_ID, 8),
        (SMB2_HDR_SIGNATURE, 16),
    ] {
        h[at..at + n].copy_from_slice(&src[at..at + n]);
    }
    mark_async(h, le32(src, SMB2_HDR_FLAGS) & !SMB2_HDR_FLAG_SIGNED);
    pdu[hdr + SMB2_HDR_SIZE..].copy_from_slice(&BODY);
    set_nbt_len(pdu);
    if !e.seal.apply(ops, pdu) {
        r.free_out(o);
        return Err(libc::ECONNABORTED);
    }
    o.set_inline(len);
    r.queue_reply(o);
    Ok(())
}

/// Set `flags` and the async flag. smbd uses the `MessageId` as `AsyncId`.
fn mark_async(h: &mut [u8], flags: u32) {
    put32(h, SMB2_HDR_FLAGS, flags | SMB2_HDR_FLAG_ASYNC);
    h.copy_within(
        SMB2_HDR_MESSAGE_ID..SMB2_HDR_MESSAGE_ID + 8,
        SMB2_HDR_ASYNC_ID,
    );
}

/// Make the reply the final response after an interim one, with no
/// credits.
fn set_async(h: &mut [u8]) {
    mark_async(h, le32(h, SMB2_HDR_FLAGS));
    h[SMB2_HDR_CREDIT..SMB2_HDR_CREDIT + 2].fill(0);
}
