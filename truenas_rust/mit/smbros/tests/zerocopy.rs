// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! Tests of zero-copy sends on a loopback TCP pair. A Unix socket refuses
//! them.

#![allow(unsafe_code)]
// The test patterns use the low byte of a number.
#![allow(clippy::cast_possible_truncation)]

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use truenas_smbros::ffi::{
    TN_SMBROS_SENT, tn_smbros_adopt, tn_smbros_close, tn_smbros_ctx_free,
    tn_smbros_ctx_new, tn_smbros_next, tn_smbros_send,
};
use truenas_smbros::{Conn, Ctx, TnSmbrosEvent};

const NONE: usize = usize::MAX;
const ZC_MIN: usize = 64 * 1024;
/// The loopback buffers hold `REPLIES` replies of this many lent bytes.
const BODY: usize = 100_000;
const REPLIES: usize = 8;

/// A connection on a loopback TCP pair. The test has `peer`.
struct Rig {
    ctx: *mut Ctx,
    conn: *mut Conn,
    peer: TcpStream,
    _sock: TcpStream,
}

impl Rig {
    fn new(zero_copy_min: usize) -> Rig {
        let ctx = tn_smbros_ctx_new();
        assert!(!ctx.is_null());
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (sock, _) = l.accept().unwrap();
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

    /// Lend `bodies` as `bodies.len()` replies, each with a short header.
    fn send_lent(&self, bodies: &[Vec<u8>]) {
        for (i, b) in bodies.iter().enumerate() {
            let head = [7u8; 10];
            let vecs = [iov(&head), iov(b)];
            let mut lent = false;
            // SAFETY: the vectors live until the SENT events below.
            let rc = unsafe {
                tn_smbros_send(
                    self.conn,
                    vecs.as_ptr(),
                    2,
                    4096,
                    i as u64,
                    &raw mut lent,
                )
            };
            assert_eq!(rc, 0);
            assert!(lent, "a {BODY} byte vector is lent");
        }
    }

    /// The number of SENT events in the next `ms` milliseconds.
    fn sent_events(&self, ms: u64) -> usize {
        let end = Instant::now() + Duration::from_millis(ms);
        let mut n = 0;
        let mut ev = TnSmbrosEvent::bare(0, 0);
        while Instant::now() < end {
            // SAFETY: the context is live, and `ev` has room for an event.
            if unsafe { tn_smbros_next(self.ctx, &raw mut ev) } {
                n += usize::from(ev.kind == TN_SMBROS_SENT);
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        n
    }

    fn read_all(&mut self, bytes: usize) {
        let mut got = vec![0u8; bytes];
        self.peer.read_exact(&mut got).unwrap();
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

fn iov(b: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: b.as_ptr().cast_mut().cast(),
        iov_len: b.len(),
    }
}

fn lent_bodies() -> Vec<Vec<u8>> {
    (0..REPLIES).map(|i| vec![i as u8; BODY]).collect()
}

/// The lent memory of a zero-copy reply goes back at the notification of
/// its send, not at its result. A peer that reads nothing holds it. With
/// copies, the same peer holds nothing.
#[test]
fn a_lent_reply_goes_back_at_the_notification() {
    let bodies = lent_bodies();
    let copied = {
        let rig = Rig::new(NONE);
        rig.send_lent(&bodies);
        let n = rig.sent_events(600);
        let mut rig = rig;
        rig.read_all(REPLIES * (BODY + 10));
        n
    };
    assert_eq!(copied, REPLIES, "a copying send needs no notification");
    let mut rig = Rig::new(ZC_MIN);
    rig.send_lent(&bodies);
    let held = REPLIES - rig.sent_events(600);
    assert!(held > 0, "a zero-copy reply waits for its notification");
    rig.read_all(REPLIES * (BODY + 10));
    let back = REPLIES - held + rig.sent_events(2000);
    assert_eq!(back, REPLIES, "every lent reply comes back");
}

/// A notification cannot be cancelled. The teardown waits for the ones it
/// owes, and resets the connection of a peer that reads nothing after one
/// second.
#[test]
fn a_teardown_waits_for_its_notifications() {
    let bodies = lent_bodies();
    let start = {
        let rig = Rig::new(ZC_MIN);
        rig.send_lent(&bodies);
        assert_eq!(rig.sent_events(400), 0, "no reply is back yet");
        Instant::now()
    };
    let took = start.elapsed();
    assert!(
        took < Duration::from_secs(10),
        "the teardown ended: {took:?}"
    );
    assert!(
        took > Duration::from_millis(500),
        "the teardown waited for the notifications it owed: {took:?}"
    );
}
