// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The file I/O of a READ, WRITE or FLUSH that smbd gives to a reactor. The
//! reactor fixes smbd's reply after a short transfer or an error.

use std::ffi::c_int;

use truenas_smbros::{
    Block, Conn, Linked, Msg, MsgKind, Shim, ShimReactor, Sqe, try_box,
};

use crate::crypto::{Seal, TN_SMBSRV_DECRYPTED};
use crate::file::{Hold, hold_free};
use crate::upper::{Layer, Local};
use crate::wire::{
    NBT_HDR_SIZE, NT_STATUS_DISK_FULL, NT_STATUS_END_OF_FILE,
    NT_STATUS_UNSUCCESSFUL, SMB2_HDR_MAGIC, SMB2_HDR_NEXT_COMMAND,
    SMB2_HDR_OPCODE, SMB2_HDR_SIZE, SMB2_HDR_STATUS, SMB2_OP_FLUSH,
    SMB2_OP_READ, SMB2_OP_WRITE, SMB2_RW_COUNT, SMB2_TF_SIZE, is_magic, le16,
    le32, put32, set_nbt_len,
};

/// The job keeps reply heads up to this size in its own storage.
pub(crate) const HEAD_INLINE: usize = 192;

// An error response fits the inline head, and a heap head is longer.
const _: () =
    assert!(HEAD_INLINE >= NBT_HDR_SIZE + SMB2_TF_SIZE + SMB2_HDR_SIZE + 9);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Work {
    Read,
    Write,
    Flush,
    /// Send an error response with `status`.
    Fail,
}

// The tag of a completion is in the low 3 bits of the job's address.
const _: () = assert!(align_of::<Job>() >= 8);

/// The file I/O of one request.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct Job {
    msg: Msg,
    pub(crate) work: Work,
    /// The status of the error response of a failed job.
    pub(crate) status: u32,
    pub(crate) who: u16,
    pub(crate) fd: c_int,
    pub(crate) hold: Option<Box<Hold>>,
    pub(crate) offset: u64,
    pub(crate) count: u32,
    pub(crate) minimum: u32,
    /// The PDU of a WRITE and the offset of its data in the block.
    pub(crate) body: Option<Block>,
    pub(crate) data_at: usize,
    /// The reply of a READ. It has the head, then the data.
    reply: Option<Block>,
    pub(crate) seal: Seal,
    pub(crate) nonce: [u8; 16],
    /// The number of the job in the interim queue.
    watch: Option<u64>,
    pub(crate) head_len: usize,
    /// A head longer than `HEAD_INLINE`.
    head_heap: Option<Vec<u8>>,
    /// True if the job is from the free list of its reactor.
    pooled: bool,
    head: [u8; HEAD_INLINE],
}

// SAFETY: Job starts with its Msg, whose first field is the Link.
unsafe impl Linked for Job {}

// SAFETY: a job moves to its reactor with what it owns, in no list.
unsafe impl Send for Job {}

impl Job {
    fn new() -> Job {
        Job {
            msg: Msg::new(MsgKind::Job),
            work: Work::Fail,
            status: 0,
            who: 0,
            fd: -1,
            hold: None,
            offset: 0,
            count: 0,
            minimum: 0,
            body: None,
            data_at: 0,
            reply: None,
            seal: Seal::default(),
            nonce: [0; 16],
            watch: None,
            head_len: 0,
            head_heap: None,
            pooled: false,
            head: [0; HEAD_INLINE],
        }
    }

    /// A job from the free list of `l` on the reactor thread, else from the
    /// heap.
    pub(crate) fn get(l: Option<&mut Local>) -> Option<Box<Job>> {
        if let Some(l) = l {
            let mut j = match l.jobs_free.take() {
                Some(mut j) => {
                    j.msg = Msg::new(MsgKind::Job);
                    j.watch = None;
                    j
                }
                None => try_box(Job::new)?,
            };
            j.pooled = true;
            return Some(j);
        }
        try_box(Job::new)
    }

    /// Copy the head of the reply from `iov`. False without memory.
    ///
    /// # Safety
    ///
    /// Each vector points to `iov_len` readable bytes, `len` in all.
    pub(crate) unsafe fn set_head(
        &mut self,
        iov: &[libc::iovec],
        len: usize,
    ) -> bool {
        let dst = if len > HEAD_INLINE {
            let mut v = Vec::new();
            if v.try_reserve_exact(len).is_err() {
                return false;
            }
            v.resize(len, 0);
            self.head_heap.insert(v).as_mut_slice()
        } else {
            &mut self.head[..len]
        };
        let mut at = 0;
        for v in iov.iter().filter(|v| v.iov_len > 0) {
            // SAFETY: as the caller says.
            let src = unsafe {
                std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len)
            };
            dst[at..at + src.len()].copy_from_slice(src);
            at += src.len();
        }
        self.head_len = len;
        true
    }

    /// The head storage, with room for an error response.
    fn head_buf(&mut self) -> &mut [u8] {
        match &mut self.head_heap {
            Some(v) => v.as_mut_slice(),
            None => &mut self.head,
        }
    }
}

/// True if the PDU is one plain or decrypted SMB2 READ, WRITE or FLUSH.
/// smbd checks the other conditions for a job.
pub(crate) fn delegable(pdu: &[u8], flags: u32) -> bool {
    let hdr = if flags & TN_SMBSRV_DECRYPTED != 0 {
        pdu.get(SMB2_TF_SIZE..).unwrap_or(&[])
    } else {
        pdu
    };
    if hdr.len() < SMB2_HDR_SIZE || !is_magic(hdr, SMB2_HDR_MAGIC) {
        return false;
    }
    let op = le16(hdr, SMB2_HDR_OPCODE);
    (op == SMB2_OP_READ || op == SMB2_OP_WRITE || op == SMB2_OP_FLUSH)
        && le32(hdr, SMB2_HDR_NEXT_COMMAND) == 0
}

/// Set the count of the READ or WRITE reply with its header at `hdr`.
fn set_count(buf: &mut [u8], hdr: usize, n: usize) {
    put32(
        buf,
        hdr + SMB2_RW_COUNT,
        u32::try_from(n).unwrap_or(u32::MAX),
    );
}

/// Make the reply an error response as `smbd_smb2_request_error()` does.
/// Returns its length.
fn error_reply(buf: &mut [u8], hdr: usize, status: u32) -> usize {
    let len = hdr + SMB2_HDR_SIZE + 9;
    put32(buf, hdr + SMB2_HDR_STATUS, status);
    buf[hdr + SMB2_HDR_SIZE..len].copy_from_slice(&[9, 0, 0, 0, 0, 0, 0, 0, 0]);
    set_nbt_len(&mut buf[..len]);
    len
}

/// The NTSTATUS of `err` in smbd's table, or `NT_STATUS_UNSUCCESSFUL`.
fn status_of(l: &Local, err: i32) -> u32 {
    let s = usize::try_from(err)
        .ok()
        .and_then(|e| l.errmap.get(e).copied())
        .unwrap_or(0);
    if s == 0 { NT_STATUS_UNSUCCESSFUL } else { s }
}

fn force_bit(c: &Conn, write: bool, n: u32) -> u8 {
    let on = if write { c.force_write } else { c.force_read };
    if on && n as usize >= c.force_min {
        Sqe::ASYNC
    } else {
        0
    }
}

/// Free a job on the reactor thread.
pub(crate) fn destroy(r: &mut ShimReactor, l: &mut Local, mut j: Box<Job>) {
    if let Some(h) = j.hold.take() {
        hold_free(h);
    }
    j.seal = Seal::default();
    if let Some(b) = j.body.take() {
        r.blocks.put(b);
    }
    if let Some(b) = j.reply.take() {
        r.blocks.put(b);
    }
    j.head_heap = None;
    if j.pooled {
        l.jobs_free.put(j);
    }
}

/// Free a job that never reached its reactor.
pub(crate) fn destroy_foreign(mut j: Box<Job>) {
    if let Some(h) = j.hold.take() {
        hold_free(h);
    }
}

/// Where the reply of a finished job is, and its length.
enum Reply {
    Head(usize),
    /// The reply of a READ.
    Block(Block, usize),
}

/// Sign or encrypt the reply, then queue it. A failure closes the
/// connection, as in smbd.
fn finish(r: &mut ShimReactor, l: &mut Local, mut j: Box<Job>, reply: Reply) {
    let jj = &mut *j;
    let hdr = jj.seal.hdr();
    let watch = jj.watch.take();
    let (mut owned, buf): (Option<Block>, &mut [u8]) = match reply {
        Reply::Head(len) => match &mut jj.head_heap {
            Some(v) => (None, &mut v[..len]),
            None => (None, &mut jj.head[..len]),
        },
        Reply::Block(block, len) => {
            // SAFETY: the job wrote `len` bytes, and no I/O uses the block.
            let bytes =
                unsafe { std::slice::from_raw_parts_mut(block.data(), len) };
            (Some(block), bytes)
        }
    };
    if let Some(seq) = watch {
        l.interims.finish(r, seq, buf, hdr);
    }
    let len = buf.len();
    if !jj.seal.apply(l.ops.as_ref(), buf) {
        if let Some(block) = owned.take() {
            r.blocks.put(block);
        }
        r.end::<Shim<Layer>>(libc::ECONNABORTED);
    } else if let Some(mut out) = r.new_out() {
        if let Some(block) = owned.take() {
            out.set_block(block, len);
        } else if !out.set_inline_from(buf)
            && let Some(block) = r.blocks.get(len)
        {
            // SAFETY: the block has room for `len` bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr(), block.data(), len);
            }
            out.set_block(block, len);
        }
        r.queue_reply(out);
    } else {
        if let Some(block) = owned.take() {
            r.blocks.put(block);
        }
        r.end::<Shim<Layer>>(libc::ENOMEM);
    }
    // Free the slot and the hold only after the reply is queued.
    r.release();
    destroy(r, l, j);
}

fn fail(r: &mut ShimReactor, l: &mut Local, mut j: Box<Job>, status: u32) {
    let hdr = j.seal.hdr();
    let len = error_reply(j.head_buf(), hdr, status);
    finish(r, l, j, Reply::Head(len));
}

pub(crate) fn run(r: &mut ShimReactor, l: &mut Local, mut j: Box<Job>) {
    // The interim wait starts before the I/O. An error reply goes at once.
    if j.work != Work::Fail {
        let head_len = j.head_len;
        let jj = &mut *j;
        let head: &[u8] = match &jj.head_heap {
            Some(v) => v,
            None => &jj.head[..head_len],
        };
        jj.watch = l.interims.watch(r, head, &jj.seal, &jj.nonce);
    }
    let mut sqe = Sqe {
        fd: j.fd,
        personality: j.who,
        ..Sqe::ZERO
    };
    match j.work {
        Work::Read => {
            let Some(block) = r.blocks.get(j.head_len + j.count as usize)
            else {
                return fail(r, l, j, NT_STATUS_UNSUCCESSFUL);
            };
            let head_len = j.head_len;
            let src = j.head_buf().as_ptr();
            // SAFETY: the block has room for the head and the data.
            unsafe {
                std::ptr::copy_nonoverlapping(src, block.data(), head_len);
            }
            sqe.opcode = Sqe::OP_READ;
            sqe.flags = force_bit(r.h.conn(), false, j.count);
            // SAFETY: the data starts after the head in the block.
            sqe.addr = unsafe { block.data().add(head_len) } as u64;
            sqe.len = j.count;
            sqe.off = j.offset;
            j.reply = Some(block);
        }
        Work::Write => {
            let Some(data) = j.body.as_ref().map(Block::data) else {
                return fail(r, l, j, NT_STATUS_UNSUCCESSFUL);
            };
            sqe.opcode = Sqe::OP_WRITE;
            sqe.flags = force_bit(r.h.conn(), true, j.count);
            // SAFETY: delegate() checked that the data is in the body.
            sqe.addr = unsafe { data.add(j.data_at) } as u64;
            sqe.len = j.count;
            sqe.off = j.offset;
        }
        Work::Flush => sqe.opcode = Sqe::OP_FSYNC,
        Work::Fail => {
            let status = j.status;
            return fail(r, l, j, status);
        }
    }
    let raw = Box::into_raw(j);
    sqe.user_data = raw as u64;
    // SAFETY: the job owns the I/O's blocks and lives until the completion.
    if !unsafe { r.push_sqe(sqe) } {
        // SAFETY: the ring did not take the SQE, so the job is still ours.
        let j = unsafe { Box::from_raw(raw) };
        fail(r, l, j, NT_STATUS_UNSUCCESSFUL);
    }
}

pub(crate) fn on_done(
    r: &mut ShimReactor,
    l: &mut Local,
    mut j: Box<Job>,
    res: i32,
) {
    let hdr = j.seal.hdr();
    let got = usize::try_from(res).unwrap_or(0);
    match j.work {
        Work::Read => {
            let Some(mut block) = j.reply.take() else {
                return fail(r, l, j, NT_STATUS_UNSUCCESSFUL);
            };
            let mut len = j.head_len + got;
            if got > 0 {
                // As in aio_pread_smb2_done(), even below `minimum`.
                if let Some(file) = j.hold.as_ref().and_then(|h| h.file()) {
                    file.set_pos(j.offset + got as u64);
                }
            }
            let need = len.max(hdr + SMB2_HDR_SIZE + 9);
            if len < need {
                // SAFETY: the block has room for an error reply.
                unsafe { block.data().add(len).write_bytes(0, need - len) };
            }
            // SAFETY: the head, the data and the zeros fill `need` bytes.
            let buf = unsafe { block.bytes_mut(need) };
            if res < 0 {
                len = error_reply(buf, hdr, status_of(l, -res));
            } else if got == 0 || got < j.minimum as usize {
                len = error_reply(buf, hdr, NT_STATUS_END_OF_FILE);
            } else if got < j.count as usize {
                set_count(buf, hdr, got);
                set_nbt_len(&mut buf[..len]);
            }
            finish(r, l, j, Reply::Block(block, len));
        }
        Work::Write => {
            if let Some(block) = j.body.take() {
                r.blocks.put(block);
            }
            let mut len = j.head_len;
            let count = j.count as usize;
            let buf = j.head_buf();
            if res < 0 {
                len = error_reply(buf, hdr, status_of(l, -res));
            } else if got == 0 && count != 0 {
                len = error_reply(buf, hdr, NT_STATUS_DISK_FULL);
            } else if got != count {
                set_count(buf, hdr, got);
            }
            finish(r, l, j, Reply::Head(len));
        }
        Work::Flush => {
            let mut len = j.head_len;
            // This matches smbd_smb2_flush_done().
            if res < 0 {
                len = error_reply(j.head_buf(), hdr, status_of(l, -res));
            }
            finish(r, l, j, Reply::Head(len));
        }
        Work::Fail => destroy(r, l, j),
    }
}
