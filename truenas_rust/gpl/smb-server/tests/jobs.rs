// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of delegated jobs through the C functions, on a pair of Unix
//! sockets and a file.

#![allow(unsafe_code)]
// The test patterns use the low byte of a number.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::ffi::{c_int, c_void};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::ptr;
use std::time::{Duration, Instant};

use truenas_smb_server::ffi::{
    tn_smbsrv_attach, tn_smbsrv_delegate, tn_smbsrv_file_busy,
    tn_smbsrv_file_close, tn_smbsrv_file_hold, tn_smbsrv_file_new,
    tn_smbsrv_keys_pin, tn_smbsrv_session_keys,
};
use truenas_smb_server::{
    CryptoOps, Io, Keys, OpenFile, TN_SMBSRV_IDLE, TN_SMBSRV_SEAL_ENCRYPT,
    TN_SMBSRV_SEAL_NONE,
};
use truenas_smbros::ffi::{
    TN_SMBROS_CLOSED, TN_SMBROS_PDU, tn_smbros_adopt, tn_smbros_buf_delegable,
    tn_smbros_buf_free, tn_smbros_close, tn_smbros_conn_root,
    tn_smbros_ctx_free, tn_smbros_ctx_new, tn_smbros_next,
};
use truenas_smbros::{Conn, Ctx, TnSmbrosEvent};

const NONE: usize = usize::MAX;
const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
const TF_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];
const OP_FLUSH: u16 = 7;
const OP_READ: u16 = 8;
const OP_WRITE: u16 = 9;
const SESSION: u64 = 9;
const STATUS_PENDING: u32 = 0x0000_0103;

unsafe extern "C" fn failing_encrypt(
    _key: *mut c_void,
    _iov: *mut libc::iovec,
    _n: c_int,
) -> u32 {
    0xC000_0001
}

static FAILING_OPS: CryptoOps = CryptoOps {
    thread_init: None,
    sign: None,
    check: None,
    encrypt: Some(failing_encrypt),
    decrypt: None,
};

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A context with this layer and one connection that can get jobs.
struct Rig {
    ctx: *mut Ctx,
    conn: *mut Conn,
    peer: UnixStream,
    _sock: UnixStream,
}

impl Rig {
    fn new() -> Rig {
        Rig::attached(ptr::null())
    }

    fn attached(ops: *const CryptoOps) -> Rig {
        let ctx = tn_smbros_ctx_new();
        assert!(!ctx.is_null());
        // SAFETY: the context is live, and `ops` is NULL or static.
        assert!(unsafe { tn_smbsrv_attach(ctx, ops, ptr::null(), 0) });
        let (peer, sock) = UnixStream::pair().unwrap();
        // A missing reply fails the test instead of hanging it.
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut err = 0;
        // SAFETY: the context is live and the socket is open.
        let conn = unsafe {
            tn_smbros_adopt(
                ctx,
                sock.as_raw_fd(),
                1,
                16,
                true,
                NONE,
                NONE,
                NONE,
                &raw mut err,
            )
        };
        assert!(!conn.is_null(), "adopt failed with {err}");
        Rig {
            ctx,
            conn,
            peer,
            _sock: sock,
        }
    }

    /// The next event, after up to 5 seconds.
    fn next(&self) -> TnSmbrosEvent {
        let end = Instant::now() + Duration::from_secs(5);
        let mut ev = TnSmbrosEvent::bare(0, 0);
        while Instant::now() < end {
            // SAFETY: the context is live, and `ev` has room for an event.
            if unsafe { tn_smbros_next(self.ctx, &raw mut ev) } {
                return ev;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("no event came");
    }

    /// Send an SMB2 request of `op` with `body` and return its PDU event.
    fn request(&mut self, op: u16, body: &[u8]) -> TnSmbrosEvent {
        let mut b = vec![0u8; 4 + 64];
        b.extend_from_slice(body);
        let len = u32::try_from(b.len() - 4).unwrap().to_be_bytes();
        b[1..4].copy_from_slice(&len[1..]);
        b[4..8].copy_from_slice(&SMB2_MAGIC);
        b[8..10].copy_from_slice(&64u16.to_le_bytes());
        b[16..18].copy_from_slice(&op.to_le_bytes());
        self.peer.write_all(&b).unwrap();
        let ev = self.next();
        assert_eq!(ev.kind, TN_SMBROS_PDU);
        // SAFETY: the event has a live buffer.
        assert!(unsafe { tn_smbros_buf_delegable(ev.buf) });
        ev
    }

    /// Give the job of `ev` to the reactor with the reply head `head`.
    fn delegate(
        &self,
        ev: &TnSmbrosEvent,
        file: *mut OpenFile,
        io: &Io,
        head: &[u8],
    ) {
        assert_eq!(self.try_delegate(ev, file, io, head, ptr::null_mut()), 0);
    }

    fn try_delegate(
        &self,
        ev: &TnSmbrosEvent,
        file: *mut OpenFile,
        io: &Io,
        head: &[u8],
        keys: *mut Keys,
    ) -> c_int {
        let v = libc::iovec {
            iov_base: head.as_ptr().cast_mut().cast(),
            iov_len: head.len(),
        };
        // SAFETY: all arguments are live. The function owns the hold.
        let rc = unsafe {
            tn_smbsrv_delegate(
                self.conn,
                ev.buf,
                &raw const v,
                1,
                tn_smbsrv_file_hold(file),
                keys,
                io,
            )
        };
        // SAFETY: the test owns the buffer and does not use it again.
        unsafe { tn_smbros_buf_free(ev.buf) };
        rc
    }

    /// Keys of `SESSION` with only an encryption key.
    fn encrypt_keys(&self) -> *mut Keys {
        let key = ptr::without_provenance_mut::<c_void>(7);
        // SAFETY: the connection is live. The key is never dereferenced.
        unsafe {
            assert_eq!(
                tn_smbsrv_session_keys(
                    self.conn,
                    SESSION,
                    1,
                    ptr::null_mut(),
                    key,
                    ptr::null_mut(),
                ),
                0
            );
            tn_smbsrv_keys_pin(self.conn, SESSION, 1)
        }
    }

    /// Read one reply PDU. Returns the message without the NBT header.
    fn reply(&mut self) -> Vec<u8> {
        let mut nbt = [0u8; 4];
        self.peer.read_exact(&mut nbt).unwrap();
        let len = u32::from_be_bytes([0, nbt[1], nbt[2], nbt[3]]) as usize;
        let mut msg = vec![0u8; len];
        self.peer.read_exact(&mut msg).unwrap();
        msg
    }

    /// The reply after any interim responses.
    fn final_reply(&mut self) -> Vec<u8> {
        loop {
            let msg = self.reply();
            if le32(&msg, 8) != STATUS_PENDING {
                return msg;
            }
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        // SAFETY: the test does not use them after this.
        unsafe {
            tn_smbros_close(self.conn);
            tn_smbros_ctx_free(self.ctx);
        }
    }
}

/// A reply head of a READ or WRITE for `count` bytes: the NBT header, the
/// SMB2 header and 16 bytes of the body.
fn head(count: u32, data: bool) -> Vec<u8> {
    let mut h = vec![0u8; 4 + 64 + 16];
    let len = 64 + 16 + if data { count } else { 0 };
    h[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
    h[4..8].copy_from_slice(&SMB2_MAGIC);
    h[4 + 68..4 + 72].copy_from_slice(&count.to_le_bytes());
    h
}

fn io(opcode: u16, who: u16, offset: u64, count: u32, data_ofs: usize) -> Io {
    Io {
        opcode,
        who,
        seal: TN_SMBSRV_SEAL_NONE,
        offset,
        count,
        minimum: 0,
        data_ofs,
        pending_nonce_low: 0,
        pending_nonce_high: 0,
    }
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir()
        .join(format!("tn-smbsrv-{name}-{}", std::process::id()))
}

/// A file of `len` bytes. Byte i is i % 251.
fn test_file(name: &str, len: usize) -> File {
    let path = temp_path(name);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    f.write_all(&data).unwrap();
    f
}

/// A FIFO that the test reads and writes. A read waits for data.
fn test_fifo(name: &str) -> File {
    let path = temp_path(name);
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid C string.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    f
}

/// The reactor reads the file of a delegated READ into the reply, sets
/// the count after a short read and answers a read past the end with
/// `NT_STATUS_END_OF_FILE`. smbd gets the IDLE event after the reply and
/// the position of the last read at the close.
#[test]
fn a_delegated_read_sends_the_data() {
    let f = test_file("read", 4096);
    let mut rig = Rig::new();
    // SAFETY: the connection is live.
    let who = unsafe { tn_smbros_conn_root(rig.conn) };
    assert_ne!(who, 0);
    // SAFETY: the file stays open until the close below.
    let file = unsafe { tn_smbsrv_file_new(rig.ctx, f.as_raw_fd(), 7) };
    for (offset, count, got) in [(100u64, 1000u32, 1000usize), (4000, 1000, 96)]
    {
        let ev = rig.request(OP_READ, &[0u8; 49]);
        // SAFETY: the file is open.
        assert!(!unsafe { tn_smbsrv_file_busy(file) });
        rig.delegate(
            &ev,
            file,
            &io(OP_READ, who, offset, count, 0),
            &head(count, true),
        );
        let msg = rig.final_reply();
        assert_eq!(msg.len(), 64 + 16 + got);
        assert_eq!(le32(&msg, 68) as usize, got);
        let start = usize::try_from(offset).unwrap();
        assert!(
            msg[80..]
                .iter()
                .enumerate()
                .all(|(i, &x)| x == ((start + i) % 251) as u8)
        );
        let ev = rig.next();
        assert_eq!((ev.kind, ev.cookie), (TN_SMBSRV_IDLE, 7));
    }
    let ev = rig.request(OP_READ, &[0u8; 49]);
    rig.delegate(&ev, file, &io(OP_READ, who, 9000, 10, 0), &head(10, true));
    let msg = rig.final_reply();
    assert_eq!(msg.len(), 64 + 9);
    assert_eq!(le32(&msg, 8), 0xC000_0011);
    let mut pos = 0u64;
    // SAFETY: the file is open, and no job uses it now.
    assert!(unsafe { tn_smbsrv_file_close(file, &raw mut pos) });
    assert_eq!(pos, 4096);
}

/// The reactor writes the data of a delegated WRITE from the block of the
/// PDU and sends the reply.
#[test]
fn a_delegated_write_writes_the_data() {
    let f = test_file("write", 0);
    let mut rig = Rig::new();
    // SAFETY: the connection is live.
    let who = unsafe { tn_smbros_conn_root(rig.conn) };
    // SAFETY: the file stays open until the close below.
    let file = unsafe { tn_smbsrv_file_new(rig.ctx, f.as_raw_fd(), 8) };
    let mut body = vec![0u8; 48];
    body.extend((0..3000).map(|i| (i % 13) as u8));
    let ev = rig.request(OP_WRITE, &body);
    rig.delegate(
        &ev,
        file,
        &io(OP_WRITE, who, 10, 3000, 64 + 48),
        &head(3000, false),
    );
    let msg = rig.reply();
    assert_eq!(msg.len(), 64 + 16);
    assert_eq!(le32(&msg, 68), 3000);
    // SAFETY: the file is open, and no job uses it now.
    unsafe { tn_smbsrv_file_close(file, ptr::null_mut()) };
    let mut data = Vec::new();
    let mut g = f;
    std::io::Seek::rewind(&mut g).unwrap();
    g.read_to_end(&mut data).unwrap();
    assert_eq!(data.len(), 3010);
    assert!(
        data[10..]
            .iter()
            .enumerate()
            .all(|(i, &x)| x == (i % 13) as u8)
    );
}

/// A job that runs past 500 microseconds gets an unsigned interim response
/// with the credits of the reply. The final reply then has the async flag
/// and grants no credits.
#[test]
fn a_slow_job_gets_an_interim_response() {
    let mut fifo = test_fifo("fifo");
    let mut rig = Rig::new();
    // SAFETY: the connection is live.
    let who = unsafe { tn_smbros_conn_root(rig.conn) };
    // SAFETY: the FIFO stays open until the close below.
    let file = unsafe { tn_smbsrv_file_new(rig.ctx, fifo.as_raw_fd(), 9) };
    let ev = rig.request(OP_READ, &[0u8; 49]);
    // SAFETY: the file is open.
    assert!(!unsafe { tn_smbsrv_file_busy(file) });
    let mut h = head(100, true);
    h[4 + 14..4 + 16].copy_from_slice(&33u16.to_le_bytes());
    h[4 + 16..4 + 20].copy_from_slice(&0x09u32.to_le_bytes());
    h[4 + 24..4 + 32].copy_from_slice(&7u64.to_le_bytes());
    rig.delegate(&ev, file, &io(OP_READ, who, 0, 100, 0), &h);
    // The read waits for data in the FIFO.
    let interim = rig.reply();
    assert_eq!(interim.len(), 64 + 9);
    assert_eq!(le32(&interim, 8), 0x0000_0103);
    assert_eq!(le16(&interim, 14), 33);
    assert_eq!(le32(&interim, 16), 0x03);
    assert_eq!(le64(&interim, 32), 7);
    assert_eq!(interim[64..], [9, 0, 0, 0, 0, 0, 0, 0, 0x21]);
    fifo.write_all(&[5u8; 100]).unwrap();
    let msg = rig.reply();
    assert_eq!(msg.len(), 64 + 16 + 100);
    assert_eq!(le16(&msg, 14), 0);
    assert_eq!(le32(&msg, 16), 0x0b);
    assert_eq!(le64(&msg, 24), 7);
    assert_eq!(le64(&msg, 32), 7);
    assert!(msg[80..].iter().all(|&x| x == 5));
    let ev = rig.next();
    assert_eq!((ev.kind, ev.cookie), (TN_SMBSRV_IDLE, 9));
    // SAFETY: the file is open, and no job uses it now.
    unsafe { tn_smbsrv_file_close(file, ptr::null_mut()) };
}

/// The reply of a job with an interim response grants no credits. So a
/// connection whose interim response cannot be encrypted closes, as in
/// smbd.
#[test]
fn an_unsealable_interim_response_closes_the_connection() {
    let fifo = test_fifo("noseal");
    let mut rig = Rig::attached(&raw const FAILING_OPS);
    // SAFETY: the connection is live.
    let who = unsafe { tn_smbros_conn_root(rig.conn) };
    // SAFETY: the FIFO stays open until the close below.
    let file = unsafe { tn_smbsrv_file_new(rig.ctx, fifo.as_raw_fd(), 11) };
    let keys = rig.encrypt_keys();
    assert!(!keys.is_null());
    let mut h = vec![0u8; 4 + 52 + 64 + 16];
    let len = u32::try_from(h.len() - 4 + 100).unwrap();
    h[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
    h[4..8].copy_from_slice(&TF_MAGIC);
    h[48..56].copy_from_slice(&SESSION.to_le_bytes());
    h[56..60].copy_from_slice(&SMB2_MAGIC);
    h[56 + 68..56 + 72].copy_from_slice(&100u32.to_le_bytes());
    let mut io = io(OP_READ, who, 0, 100, 0);
    io.seal = TN_SMBSRV_SEAL_ENCRYPT;
    let ev = rig.request(OP_READ, &[0u8; 49]);
    // The read of the FIFO waits, so the interim response is due.
    assert_eq!(rig.try_delegate(&ev, file, &io, &h, keys), 0);
    assert_eq!(rig.next().kind, TN_SMBROS_CLOSED);
    rig.peer
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut byte = [0u8; 1];
    assert!(!matches!(rig.peer.read(&mut byte), Ok(n) if n > 0));
    // SAFETY: the file is open. The close ends the job.
    unsafe { tn_smbsrv_file_close(file, ptr::null_mut()) };
}

/// A FLUSH reply head has the 4 bytes of the body.
#[test]
fn a_flush_reply_head_without_its_body_is_refused() {
    let f = test_file("flush", 16);
    let mut rig = Rig::new();
    // SAFETY: the connection is live.
    let who = unsafe { tn_smbros_conn_root(rig.conn) };
    // SAFETY: the file stays open until the close below.
    let file = unsafe { tn_smbsrv_file_new(rig.ctx, f.as_raw_fd(), 12) };
    for (body, want) in [(0usize, libc::EINVAL), (3, libc::EINVAL), (4, 0)] {
        let ev = rig.request(OP_FLUSH, &[0u8; 20]);
        let mut h = vec![0u8; 4 + 64 + body];
        let len = u32::try_from(64 + body).unwrap();
        h[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        h[4..8].copy_from_slice(&SMB2_MAGIC);
        let io = io(OP_FLUSH, who, 0, 0, 0);
        let rc = rig.try_delegate(&ev, file, &io, &h, ptr::null_mut());
        assert_eq!(rc, want, "a body of {body} bytes");
    }
    assert_eq!(rig.final_reply().len(), 64 + 4);
    // SAFETY: the file is open, and no job uses it now.
    unsafe { tn_smbsrv_file_close(file, ptr::null_mut()) };
}

/// The delegate refuses a vector with bytes at NULL, as the other calls
/// that take vectors do. Without that, `Job::set_head()` would build a slice
/// from the null pointer. The two rows differ only in the base.
#[test]
fn a_delegated_vector_of_bytes_at_null_is_refused() {
    let f = test_file("nullvec", 16);
    let mut rig = Rig::new();
    // SAFETY: the connection is live.
    let who = unsafe { tn_smbros_conn_root(rig.conn) };
    // SAFETY: the file stays open until the close below.
    let file = unsafe { tn_smbsrv_file_new(rig.ctx, f.as_raw_fd(), 13) };
    let mut h = [0u8; 4 + 64 + 4];
    h[3] = 64 + 4;
    h[4..8].copy_from_slice(&SMB2_MAGIC);
    for (at_null, want) in [(true, libc::EINVAL), (false, 0)] {
        let ev = rig.request(OP_FLUSH, &[0u8; 20]);
        let v = libc::iovec {
            iov_base: if at_null {
                ptr::null_mut()
            } else {
                h.as_mut_ptr().cast()
            },
            iov_len: h.len(),
        };
        let io = io(OP_FLUSH, who, 0, 0, 0);
        // SAFETY: all arguments are live. The call owns the hold.
        let rc = unsafe {
            tn_smbsrv_delegate(
                rig.conn,
                ev.buf,
                &raw const v,
                1,
                tn_smbsrv_file_hold(file),
                ptr::null_mut(),
                &raw const io,
            )
        };
        // SAFETY: the test owns the buffer and does not use it again.
        unsafe { tn_smbros_buf_free(ev.buf) };
        assert_eq!(rc, want, "bytes at NULL: {at_null}");
    }
    assert_eq!(rig.final_reply().len(), 64 + 4);
    // SAFETY: the file is open, and no job uses it now.
    unsafe { tn_smbsrv_file_close(file, ptr::null_mut()) };
}
