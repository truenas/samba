// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! Tests of the shim through its C functions, on a pair of Unix sockets.

#![allow(unsafe_code)]
// The test patterns use the low byte of a number.
#![allow(clippy::cast_possible_truncation)]

use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, Instant};

use truenas_smbros::ffi::{
    TN_SMBROS_CLOSED, TN_SMBROS_PDU, TN_SMBROS_SENT, tn_smbros_adopt,
    tn_smbros_buf_free, tn_smbros_close, tn_smbros_ctx_free,
    tn_smbros_ctx_inline, tn_smbros_ctx_new, tn_smbros_next, tn_smbros_send,
};
use truenas_smbros::{Conn, Ctx, Pdu, TnSmbrosEvent};

const NONE: usize = usize::MAX;
/// The capacity of the receive block of a connection.
const SMALL: usize = 20 * 1024;

fn iov(b: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: b.as_ptr().cast_mut().cast(),
        iov_len: b.len(),
    }
}

/// A context with one connection on a socket pair. The test has `peer`.
struct Rig {
    ctx: *mut Ctx,
    conn: *mut Conn,
    peer: UnixStream,
    _sock: UnixStream,
}

impl Rig {
    fn new(zero_copy_min: usize) -> Rig {
        Rig::with_ctx(tn_smbros_ctx_new(), zero_copy_min)
    }

    fn with_ctx(ctx: *mut Ctx, zero_copy_min: usize) -> Rig {
        assert!(!ctx.is_null());
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
                false,
                NONE,
                NONE,
                zero_copy_min,
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

    /// A PDU with `len` bytes after the NBT header. Byte i of the message is
    /// i + seed.
    fn pdu(len: usize, seed: u8) -> Vec<u8> {
        let mut b = vec![0u8; 4 + len];
        b[1..4]
            .copy_from_slice(&u32::try_from(len).unwrap().to_be_bytes()[1..]);
        for (i, x) in b[4..].iter_mut().enumerate() {
            *x = (i as u8).wrapping_add(seed);
        }
        b
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

/// Check a PDU event of `len` bytes made by `Rig::pdu()` with `seed`, and
/// free its buffer. Returns the class of its block.
fn check_pdu(ev: &TnSmbrosEvent, len: usize, seed: u8) -> u8 {
    assert_eq!(ev.kind, TN_SMBROS_PDU);
    assert_eq!(ev.len, len);
    // SAFETY: the event owns a live PDU.
    let (class, data) = unsafe { &*ev.buf.cast::<Pdu>() }.block_info().unwrap();
    // smbd reads the PDU where the kernel put it.
    assert_eq!(ev.data, data.wrapping_add(4));
    // SAFETY: the event has `len` bytes at `data`.
    let got = unsafe { std::slice::from_raw_parts(ev.data, len) };
    assert!(
        got.iter()
            .enumerate()
            .all(|(i, &x)| x == (i as u8).wrapping_add(seed))
    );
    // SAFETY: the test owns the buffer and does not use it again.
    unsafe { tn_smbros_buf_free(ev.buf) };
    class
}

/// A PDU that fits the receive block arrives in it. A larger PDU arrives in
/// a block of its own, so the reactor copies only the bytes of its header
/// read.
#[test]
fn a_pdu_arrives_in_its_block() {
    let small = SMALL;
    let cases = [
        (100, false),
        (small - 4, false),
        (small - 3, true),
        (64 * 1024 + 112, true),
        (1 << 20, true),
    ];
    let mut rig = Rig::new(NONE);
    for (i, &(len, placed)) in cases.iter().enumerate() {
        let seed = u8::try_from(i).unwrap();
        rig.peer.write_all(&Rig::pdu(len, seed)).unwrap();
        let ev = rig.next();
        assert_eq!(check_pdu(&ev, len, seed) > 0, placed);
    }
}

/// The header read can take the start of the next PDU. The reactor then
/// gives both PDUs in order.
#[test]
fn two_pdus_in_one_write_arrive_in_order() {
    let mut rig = Rig::new(NONE);
    let mut b = Rig::pdu(50, 1);
    b.extend(Rig::pdu(70, 2));
    rig.peer.write_all(&b).unwrap();
    check_pdu(&rig.next(), 50, 1);
    check_pdu(&rig.next(), 70, 2);
}

fn send_lent(zero_copy_min: usize) {
    let mut rig = Rig::new(zero_copy_min);
    let head = [7u8; 10];
    let body = vec![9u8; 100_000];
    let vecs = [iov(&head), iov(&body)];
    let mut lent = false;
    // SAFETY: the vectors live until the SENT event below.
    let rc = unsafe {
        tn_smbros_send(rig.conn, vecs.as_ptr(), 2, 4096, 42, &raw mut lent)
    };
    assert_eq!(rc, 0);
    assert!(lent);
    let mut got = vec![0u8; head.len() + body.len()];
    rig.peer.read_exact(&mut got).unwrap();
    assert_eq!(&got[..10], &head);
    assert!(got[10..].iter().all(|&x| x == 9));
    let ev = rig.next();
    assert_eq!(ev.kind, TN_SMBROS_SENT);
    assert_eq!(ev.cookie, 42);
}

/// The reactor sends long vectors from the caller's memory and gives them
/// back with a SENT event.
#[test]
fn a_send_lends_long_vectors_until_sent() {
    send_lent(NONE);
}

/// A vector with bytes at NULL is refused. One with no bytes is not.
#[test]
fn a_vector_of_bytes_at_null_is_refused() {
    let rig = Rig::new(NONE);
    let head = [7u8; 10];
    let mut lent = false;
    for (len, want) in [(5usize, libc::EINVAL), (0, 0)] {
        let vecs = [
            iov(&head),
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: len,
            },
        ];
        // SAFETY: the vectors live until the call returns, and none is lent.
        let rc = unsafe {
            tn_smbros_send(rig.conn, vecs.as_ptr(), 2, NONE, 0, &raw mut lent)
        };
        assert_eq!(rc, want, "a vector of {len} bytes at NULL");
    }
}

/// Unix sockets do not send without a copy. The reactor sends the PDU
/// again with a copy.
#[test]
fn a_zero_copy_send_arrives_whole() {
    send_lent(64 * 1024);
}

static ECHO_CONN: AtomicPtr<Conn> = AtomicPtr::new(ptr::null_mut());

/// An inline function that sends each PDU back on the reactor thread.
unsafe extern "C" fn echo(_: *mut c_void, ev: *mut TnSmbrosEvent) -> bool {
    // SAFETY: the reactor passes a valid event.
    let ev = unsafe { &*ev };
    let mut hdr = u32::try_from(ev.len).unwrap().to_be_bytes();
    hdr[0] = ev.nbt_type;
    // SAFETY: the event has `len` bytes at `data`.
    let data = unsafe { std::slice::from_raw_parts(ev.data, ev.len) };
    let vecs = [iov(&hdr), iov(data)];
    let mut lent = false;
    let conn = ECHO_CONN.load(Ordering::Acquire);
    // SAFETY: the connection is live, and the shim copies all vectors.
    let rc = unsafe {
        tn_smbros_send(conn, vecs.as_ptr(), 2, NONE, 0, &raw mut lent)
    };
    assert_eq!(rc, 0);
    // SAFETY: the function owns the buffer when it returns true.
    unsafe { tn_smbros_buf_free(ev.buf) };
    true
}

/// smbd runs PDUs inline on the reactor thread and sends replies from
/// there. The reactor holds no borrow of itself while smbd runs.
#[test]
fn an_inline_run_replies_on_the_reactor() {
    let ctx = tn_smbros_ctx_new();
    // SAFETY: the context is live, and `echo` runs on any reactor thread.
    assert!(unsafe { tn_smbros_ctx_inline(ctx, Some(echo), ptr::null_mut()) });
    let mut rig = Rig::with_ctx(ctx, NONE);
    ECHO_CONN.store(rig.conn, Ordering::Release);
    for i in 0..3u8 {
        let p = Rig::pdu(200 + usize::from(i), i);
        rig.peer.write_all(&p).unwrap();
        let mut got = vec![0u8; p.len()];
        rig.peer.read_exact(&mut got).unwrap();
        assert_eq!(got, p);
    }
}

/// A peer that closes its end gives a CLOSED event with no error.
#[test]
fn a_closed_peer_gives_a_closed_event() {
    let rig = Rig::new(NONE);
    rig.peer.shutdown(Shutdown::Both).unwrap();
    let ev = rig.next();
    assert_eq!(ev.kind, TN_SMBROS_CLOSED);
    assert_eq!(ev.error, 0);
}
