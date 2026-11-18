// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The file I/O of a READ, WRITE or FLUSH that smbd gives to the reactor
//! of the request. smbd builds the reply for a full transfer. The reactor
//! does the I/O and sends the reply. It corrects the reply after a short
//! transfer or an error.

use std::ffi::{c_int, c_void};
use std::ops::Range;
use std::sync::Arc;

use truenas_ros::net::server::{BodyRecycler, Deferred};
use truenas_ros::uring_fs::{File, FsConn, Personality, RwFlags};
use truenas_smbros::{
    Buf, Conn, ConnState, Job, PLACE_MIN, errno_of, iov_gather, iov_of,
};

use crate::ConnExt;
use crate::crypto::{CryptoOps, Keys, Seal, TN_SMBSRV_DECRYPTED};
use crate::file::Hold;
use crate::pending::Watch;
use crate::wire::{
    NT_STATUS_DISK_FULL, NT_STATUS_END_OF_FILE, NT_STATUS_FILE_CLOSED,
    NT_STATUS_UNSUCCESSFUL, SMB2_HDR_MAGIC, SMB2_HDR_NEXT_COMMAND,
    SMB2_HDR_OPCODE, SMB2_HDR_SIZE, SMB2_HDR_STATUS, SMB2_OP_FLUSH,
    SMB2_OP_READ, SMB2_OP_WRITE, SMB2_RW_COUNT, SMB2_TF_SIZE, le16, le32,
    set_nbt_len,
};

/// True if the PDU is one unencrypted or decrypted SMB2 READ, WRITE or
/// FLUSH. smbd can give the reactor a job for such a PDU. smbd checks the
/// other conditions.
pub(crate) fn delegable(pdu: &[u8], crypto: u32) -> bool {
    let hdr = if crypto & TN_SMBSRV_DECRYPTED != 0 {
        pdu.get(SMB2_TF_SIZE..).unwrap_or_default()
    } else {
        pdu
    };
    if hdr.len() < SMB2_HDR_SIZE || hdr[..4] != SMB2_HDR_MAGIC {
        return false;
    }
    let op = le16(hdr, SMB2_HDR_OPCODE);
    matches!(op, SMB2_OP_READ | SMB2_OP_WRITE | SMB2_OP_FLUSH)
        && le32(hdr, SMB2_HDR_NEXT_COMMAND) == 0
}

/// Set the count of the READ or WRITE reply in `buf` to `n`. Its SMB2
/// header starts at `hdr`.
fn set_count(buf: &mut [u8], hdr: usize, n: usize) {
    let n = u32::try_from(n).unwrap_or(u32::MAX);
    let at = hdr + SMB2_RW_COUNT;
    buf[at..at + 4].copy_from_slice(&n.to_le_bytes());
}

/// Make the reply in `buf` an error response with `status` like
/// `smbd_smb2_request_error()` does. Its SMB2 header starts at `hdr`. The
/// result has the header, an 8-byte body and 1 byte of error data.
fn error_reply(buf: &mut Vec<u8>, hdr: usize, status: u32) {
    buf.truncate(hdr + SMB2_HDR_SIZE);
    let at = hdr + SMB2_HDR_STATUS;
    buf[at..at + 4].copy_from_slice(&status.to_le_bytes());
    buf.extend_from_slice(&[9, 0, 0, 0, 0, 0, 0, 0, 0]);
    set_nbt_len(buf);
}

/// The NTSTATUS for the errno of `e` in the table `map` of smbd.
/// `NT_STATUS_UNSUCCESSFUL` if `map` has 0 or no value for it.
fn status_of(e: &truenas_ros::Error, map: &[u32]) -> u32 {
    usize::try_from(errno_of(e))
        .ok()
        .and_then(|i| map.get(i))
        .copied()
        .filter(|&status| status != 0)
        .unwrap_or(NT_STATUS_UNSUCCESSFUL)
}

/// Complete the READ reply in `buf` like `smb2_read_complete()` does. `buf`
/// has the head of the reply and then the bytes read. The SMB2 header
/// starts at `hdr`.
fn finish_read(
    buf: &mut Vec<u8>,
    hdr: usize,
    res: truenas_ros::Result<i32>,
    count: usize,
    minimum: usize,
    map: &[u32],
) {
    match res {
        Ok(n) => {
            let n = usize::try_from(n).unwrap_or(0);
            if n == 0 || n < minimum {
                error_reply(buf, hdr, NT_STATUS_END_OF_FILE);
            } else if n < count {
                set_count(buf, hdr, n);
                set_nbt_len(buf);
            }
        }
        Err(e) => error_reply(buf, hdr, status_of(&e, map)),
    }
}

/// Complete the WRITE reply in `head` like `smb2_write_complete_internal()`
/// does. Its SMB2 header starts at `hdr`.
fn finish_write(
    head: &mut Vec<u8>,
    hdr: usize,
    res: truenas_ros::Result<i32>,
    count: usize,
    map: &[u32],
) {
    match res.map(|n| usize::try_from(n).unwrap_or(0)) {
        Ok(n) if n == count => {}
        Ok(0) => error_reply(head, hdr, NT_STATUS_DISK_FULL),
        Ok(n) => set_count(head, hdr, n),
        Err(e) => error_reply(head, hdr, status_of(&e, map)),
    }
}

/// What a job needs to finish and send its reply.
#[derive(Debug)]
struct Ending {
    seal: Seal,
    crypto: Option<CryptoOps>,
    errmap: Arc<[u32]>,
    /// The interim response of the job, if it can get one.
    watch: Option<Watch>,
}

impl Ending {
    /// Sign or encrypt the reply in `buf` as smbd asked. Then send the
    /// reply. After an interim response, the reply is the final response.
    /// If the signing or encryption fails, close the connection like smbd
    /// does.
    fn send(self, deferred: Deferred, mut buf: Vec<u8>, pooled: bool) {
        if let Some(w) = self.watch {
            w.finish(&mut buf, self.seal.hdr());
        }
        if !self.seal.apply(self.crypto.as_ref(), &mut buf) {
            deferred.close();
        } else if pooled {
            deferred.reply_recycled(buf);
        } else {
            deferred.reply(buf);
        }
    }
}

/// An SMB2 READ. The kernel does the I/O with the credentials of `who`.
#[derive(Debug)]
struct Read {
    who: Personality,
    file: File,
    hold: Hold,
    offset: u64,
    count: usize,
    minimum: usize,
}

/// An SMB2 WRITE of `body[data]`.
#[derive(Debug)]
struct Write {
    who: Personality,
    file: File,
    hold: Hold,
    offset: u64,
    body: Vec<u8>,
    data: Range<usize>,
}

#[derive(Debug)]
struct Flush {
    who: Personality,
    file: File,
    hold: Hold,
}

#[derive(Debug)]
enum Work {
    Read(Read),
    Write(Write),
    Flush(Flush),
    /// smbd closed the file before it gave the job to the reactor. The reply
    /// is an error response with this status.
    Fail(u32),
}

/// A job from smbd for the reactor. `head` is the reply that smbd built.
/// For a READ, it ends before the data.
#[derive(Debug)]
struct Delegated {
    work: Work,
    head: Vec<u8>,
    end: Ending,
    /// The nonce of an encrypted interim response.
    nonce: [u8; 16],
}

// A READ, WRITE or FLUSH job queues its reply before it drops its hold. So
// smbd gets TN_SMBSRV_IDLE after the reactor queued the replies of the
// jobs. A CLOSE that waits for the jobs then sends its reply after theirs.

impl Read {
    fn run(
        self,
        fs: &mut FsConn<'_>,
        deferred: Deferred,
        recycler: Option<BodyRecycler>,
        head: &[u8],
        end: Ending,
    ) {
        let Read {
            who,
            file,
            hold,
            offset,
            count,
            minimum,
        } = self;
        let size = head.len() + count;
        let pooled = recycler.is_some();
        let mut buf = recycler
            .map_or_else(|| Vec::with_capacity(size), |r| r.claim(size));
        buf.extend_from_slice(head);
        let flags = RwFlags::empty();
        fs.pread_spare(who, file, buf, count, offset, flags, move |done, _| {
            let res = done.result();
            let mut buf = done.into_value();
            // A read that returns data moves the file position. This
            // matches aio_pread_smb2_done(). A read of less than `minimum`
            // also moves it.
            if let Ok(n) = res
                && let Ok(n) = u64::try_from(n)
                && n > 0
            {
                hold.file().set_pos(offset + n);
            }
            let hdr = end.seal.hdr();
            finish_read(&mut buf, hdr, res, count, minimum, &end.errmap);
            end.send(deferred, buf, pooled);
            drop(hold);
        });
    }
}

impl Write {
    fn run(
        self,
        fs: &mut FsConn<'_>,
        deferred: Deferred,
        recycler: Option<BodyRecycler>,
        mut head: Vec<u8>,
        end: Ending,
    ) {
        let Write {
            who,
            file,
            hold,
            offset,
            body,
            data,
        } = self;
        let count = data.len();
        let flags = RwFlags::empty();
        fs.pwritev2_owned(
            who,
            file,
            body,
            data,
            offset,
            flags,
            move |done, _| {
                let res = done.result();
                let body = done.into_value();
                if let Some(r) = recycler
                    && body.capacity() >= PLACE_MIN
                {
                    r.recycle(body);
                }
                finish_write(
                    &mut head,
                    end.seal.hdr(),
                    res,
                    count,
                    &end.errmap,
                );
                end.send(deferred, head, false);
                drop(hold);
            },
        );
    }
}

impl Flush {
    fn run(
        self,
        fs: &mut FsConn<'_>,
        deferred: Deferred,
        mut head: Vec<u8>,
        end: Ending,
    ) {
        let Flush { who, file, hold } = self;
        fs.fsync(who, file, move |done, _| {
            // This matches smbd_smb2_flush_done().
            if let Err(e) = done.result() {
                let status = status_of(&e, &end.errmap);
                error_reply(&mut head, end.seal.hdr(), status);
            }
            end.send(deferred, head, false);
            drop(hold);
        });
    }
}

impl Job for Delegated {
    fn run(
        self: Box<Self>,
        conn: &ConnState,
        fs: &mut FsConn<'_>,
        deferred: Deferred,
        recycler: Option<BodyRecycler>,
    ) {
        let Delegated {
            work,
            mut head,
            mut end,
            nonce,
        } = *self;
        // The wait for an interim response starts before the file I/O. An
        // error reply goes out at once.
        if !matches!(work, Work::Fail(_))
            && let Some(ext) = conn.ext::<ConnExt>()
        {
            end.watch = Some(ext.interims.watch(fs, &head, &end.seal, &nonce));
        }
        match work {
            Work::Read(w) => w.run(fs, deferred, recycler, &head, end),
            Work::Write(w) => w.run(fs, deferred, recycler, head, end),
            Work::Flush(w) => w.run(fs, deferred, head, end),
            Work::Fail(status) => {
                error_reply(&mut head, end.seal.hdr(), status);
                end.send(deferred, head, false);
            }
        }
    }
}

/// The file I/O of a job, for `tn_smbsrv_delegate()`.
#[repr(C)]
#[derive(Debug)]
pub struct Io {
    /// The SMB2 opcode. READ is 8, WRITE is 9 and FLUSH is 7.
    opcode: u16,
    /// The kernel does the I/O with the credentials of this identity of
    /// `conn`. See `tn_smbros_conn_register_self()`. It must not be 0.
    who: u16,
    /// A `TN_SMBSRV_SEAL_*` value for the reply.
    seal: c_int,
    /// The file offset and the byte count of a READ or WRITE.
    offset: u64,
    count: u32,
    /// A READ of less data than this gets an error response.
    minimum: u32,
    /// The offset of the WRITE data in the `data` of the PDU event.
    data_ofs: usize,
    /// The nonce of an interim response with `TN_SMBSRV_SEAL_ENCRYPT`. It
    /// goes into the transform header as smbd puts its nonces there.
    pending_nonce_low: u64,
    pending_nonce_high: u64,
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
    // SAFETY: the caller passes a valid `io`.
    let io = unsafe { &*io };
    // SAFETY: the caller transfers ownership of `keys`.
    let seal = unsafe { Seal::of(io.seal, keys) };
    if hold.is_null() {
        return libc::EBADF;
    }
    // SAFETY: the caller transfers ownership of `hold`.
    let hold = *unsafe { Box::from_raw(hold) };
    let Some(seal) = seal else {
        return libc::ENOKEY;
    };
    // Identity 0 means the credentials of the reactor thread. A job must
    // not run with those.
    let Some(who) = Personality::from_raw(io.who) else {
        return libc::EINVAL;
    };
    // SAFETY: the caller passes a live connection and buffer.
    let (conn, buf) = unsafe { (&*conn, &mut *buf.cast::<Buf>()) };
    let Some(ext) = conn.state().ext::<ConnExt>() else {
        return libc::EINVAL;
    };
    let count = usize::try_from(io.count).unwrap_or(usize::MAX);
    // The count of a READ or WRITE reply ends 8 bytes into the body. The
    // data of a WRITE must be in the body of a PDU that can still get a job.
    let (min_body, data) = match io.opcode {
        SMB2_OP_READ => (8, 0..0),
        SMB2_OP_WRITE => match io.data_ofs.checked_add(count) {
            Some(end) if end <= buf.body().len() && buf.delegable() => {
                (8, io.data_ofs..end)
            }
            _ => return libc::EINVAL,
        },
        SMB2_OP_FLUSH => (0, 0..0),
        _ => return libc::EINVAL,
    };
    // SAFETY: the caller passes `iovcnt` vectors.
    let Some(iov) = (unsafe { iov_of(iov, iovcnt) }) else {
        return libc::EINVAL;
    };
    // SAFETY: each vector points to readable memory.
    let head = unsafe { iov_gather(iov) };
    if head.len() < seal.hdr() + SMB2_HDR_SIZE + min_body {
        return libc::EINVAL;
    }
    let work = match hold.start() {
        None => Work::Fail(NT_STATUS_FILE_CLOSED),
        Some((file, hold)) => match io.opcode {
            SMB2_OP_READ => Work::Read(Read {
                who,
                file,
                hold,
                offset: io.offset,
                count,
                minimum: usize::try_from(io.minimum).unwrap_or(usize::MAX),
            }),
            SMB2_OP_WRITE => Work::Write(Write {
                who,
                file,
                hold,
                offset: io.offset,
                body: buf.take_body(),
                data,
            }),
            _ => Work::Flush(Flush { who, file, hold }),
        },
    };
    let end = Ending {
        seal,
        crypto: ext.crypto,
        errmap: Arc::clone(&ext.errmap),
        watch: None,
    };
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&io.pending_nonce_low.to_le_bytes());
    nonce[8..].copy_from_slice(&io.pending_nonce_high.to_le_bytes());
    let job = Delegated {
        work,
        head,
        end,
        nonce,
    };
    conn.delegate(buf, Box::new(job))
}

#[cfg(test)]
mod tests {
    use super::delegable;
    use crate::crypto::TN_SMBSRV_DECRYPTED;

    #[test]
    fn a_short_decrypted_pdu_is_not_delegable() {
        assert!(!delegable(&[0; 10], TN_SMBSRV_DECRYPTED));
    }
}
