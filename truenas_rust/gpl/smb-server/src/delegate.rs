// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The C function that gives the file I/O of a request to its reactor.

use std::ffi::{c_int, c_void};
use std::ptr::NonNull;

use truenas_smbros::{Conn, Pdu, iov_of};

use crate::crypto::Seal;
use crate::file::{Hold, hold_free};
use crate::job::{Job, Work, destroy_foreign};
use crate::keys::{Keys, unpin};
use crate::upper::{Layer, local_parts};
use crate::wire::{
    NBT_HDR_SIZE, NT_STATUS_FILE_CLOSED, SMB2_HDR_SIZE, SMB2_OP_FLUSH,
    SMB2_OP_READ, SMB2_OP_WRITE,
};

/// The file I/O of a job, for `tn_smbsrv_delegate()`.
#[repr(C)]
#[derive(Debug)]
pub struct Io {
    /// The SMB2 opcode. READ is 8, WRITE is 9 and FLUSH is 7.
    pub opcode: u16,
    /// The kernel does the I/O with the credentials of this identity of
    /// `conn`. See `tn_smbros_conn_register_self()`. It must not be 0.
    pub who: u16,
    /// A `TN_SMBSRV_SEAL_*` value for the reply.
    pub seal: c_int,
    /// The file offset and the byte count of a READ or WRITE.
    pub offset: u64,
    pub count: u32,
    /// A READ of less data than this gets an error response.
    pub minimum: u32,
    /// The offset of the WRITE data in the `data` of the PDU event.
    pub data_ofs: usize,
    /// The nonce of an interim response with `TN_SMBSRV_SEAL_ENCRYPT`. It
    /// goes into the transform header as smbd puts its nonces there.
    pub pending_nonce_low: u64,
    pub pending_nonce_high: u64,
}

fn check(
    conn: &Conn,
    p: Option<&Pdu>,
    iov: Option<&[libc::iovec]>,
    io: &Io,
    seal: &Seal,
) -> c_int {
    // Identity 0 is the reactor thread's own credentials.
    if io.who == 0 || conn.ext::<Layer>().is_none() {
        return libc::EINVAL;
    }
    let Some(p) = p.filter(|p| p.deferred() && p.has_block()) else {
        return libc::EINVAL;
    };
    // The count of a READ or WRITE reply ends 8 bytes into the body. A
    // FLUSH reply has a body of 4 bytes.
    let min_body = match io.opcode {
        SMB2_OP_READ => 8,
        SMB2_OP_WRITE => {
            let end = io.data_ofs.checked_add(io.count as usize);
            if end.is_none_or(|e| e > p.len() as usize) {
                return libc::EINVAL;
            }
            8
        }
        SMB2_OP_FLUSH => 4,
        _ => return libc::EINVAL,
    };
    let Some(iov) = iov else {
        return libc::EINVAL;
    };
    let head_len: usize = iov.iter().map(|v| v.iov_len).sum();
    if head_len < seal.hdr() + SMB2_HDR_SIZE + min_body {
        return libc::EINVAL;
    }
    0
}

/// Give the file I/O of the SMB2 READ, WRITE or FLUSH in the PDU of `buf`
/// to the reactor of `conn`. `iov` has the reply that the caller built for
/// a full transfer. For a READ, the reply ends before the data. The reactor
/// does `io` on the file of `hold` and sends the reply. After a short
/// transfer, it sets the count in the reply. After an error, it sends an
/// error response. A READ that returns no data is an error. A WRITE that
/// writes none of its data is also an error.
///
/// With `TN_SMBSRV_SEAL_SIGN`, the reactor signs the reply with the signing
/// key of `keys`. With `TN_SMBSRV_SEAL_ENCRYPT`, `iov` has the transform
/// header with its nonce after the NBT header. The reactor then encrypts
/// the reply with the encryption key of `keys`. The reactor closes the
/// connection if it cannot sign or encrypt the reply.
///
/// If the I/O runs longer than 500 microseconds, the reactor sends an
/// interim response as smbd does. That response has the credits of the
/// reply and is not signed. It is encrypted with the nonce of `io` like the
/// reply. The reply then has the async flag and grants no credits.
///
/// In all cases, this function takes ownership of `hold` and `keys`. For a
/// WRITE, it can move the bytes of the PDU out of `buf`. So the caller must
/// not read the `data` of the PDU event after the call. The caller can free
/// `buf`. Returns 0 or an errno. ENOKEY if `keys` does not have the key for
/// the seal. ENOKEY also if the seal is not a `TN_SMBSRV_SEAL_*` value.
///
/// # Safety
///
/// `conn` is from `tn_smbros_adopt()`. `buf` is the live `buf` of a PDU
/// event of `conn`. `iov` has `iovcnt` vectors of readable memory. `io`
/// points to a `struct tn_smbsrv_io`. The caller does not use `hold` and
/// `keys` again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_delegate(
    conn: *mut Conn,
    buf: *mut c_void,
    iov: *const libc::iovec,
    iovcnt: c_int,
    hold: *mut Hold,
    keys: *mut Keys,
    io: *const Io,
) -> c_int {
    // SAFETY: the caller passes a valid io and gives up its key reference.
    let (io, pin) = unsafe { (&*io, unpin(keys)) };
    let seal = Seal::of(io.seal, pin);
    let Some(hold) = NonNull::new(hold) else {
        return libc::EBADF;
    };
    // SAFETY: the caller gives up its hold, a leaked box.
    let mut hold = unsafe { Box::from_raw(hold.as_ptr()) };
    let Some(seal) = seal else {
        hold_free(hold);
        return libc::ENOKEY;
    };
    // SAFETY: the caller passes a live connection, buffer and vectors.
    let (conn, p, iov) =
        unsafe { (&*conn, buf.cast::<Pdu>().as_mut(), iov_of(iov, iovcnt)) };
    let err = check(conn, p.as_deref(), iov, io, &seal);
    if err != 0 {
        hold_free(hold);
        return err;
    }
    let (Some(p), Some(iov)) = (p, iov) else {
        hold_free(hold);
        return libc::EINVAL;
    };
    let head_len: usize = iov.iter().map(|v| v.iov_len).sum();
    // SAFETY: a C function holds no borrow of the reactor at its start.
    let mut local = unsafe { conn.local() };
    // SAFETY: as above.
    let mut parts =
        local.as_deref_mut().and_then(|r| unsafe { local_parts(r) });
    let Some(mut j) = Job::get(parts.as_mut().map(|(_, l)| &mut **l)) else {
        hold_free(hold);
        return libc::ENOMEM;
    };
    // SAFETY: the caller passes vectors of readable memory.
    if !unsafe { j.set_head(iov, head_len) } {
        hold_free(hold);
        if let Some((r, l)) = parts {
            crate::job::destroy(r, l, j);
        }
        return libc::ENOMEM;
    }
    j.seal = seal;
    j.who = io.who;
    j.fd = hold.file().map_or(-1, crate::file::OpenFile::fd);
    j.offset = io.offset;
    j.count = io.count;
    j.minimum = io.minimum;
    j.nonce[..8].copy_from_slice(&io.pending_nonce_low.to_le_bytes());
    j.nonce[8..].copy_from_slice(&io.pending_nonce_high.to_le_bytes());
    if hold.start() {
        match io.opcode {
            SMB2_OP_READ => j.work = Work::Read,
            SMB2_OP_WRITE => {
                j.work = Work::Write;
                // smbd does not read the data of the event after this call.
                j.body = p.take_block();
                j.data_at = NBT_HDR_SIZE + io.data_ofs;
            }
            _ => j.work = Work::Flush,
        }
    } else {
        j.work = Work::Fail;
        j.status = NT_STATUS_FILE_CLOSED;
    }
    j.hold = Some(hold);
    // The job gets the in-flight slot of the PDU.
    p.give_slot();
    if let Some((_, l)) = parts {
        l.jobs.push(j);
        return 0;
    }
    let m = NonNull::from(Box::leak(j)).cast();
    // SAFETY: the job starts with its Msg. A post gives it to the reactor.
    if !unsafe { conn.post(m) } {
        // SAFETY: the post failed, so the job is still ours.
        destroy_foreign(unsafe { Box::from_raw(m.cast::<Job>().as_ptr()) });
        return libc::ECONNRESET;
    }
    0
}
