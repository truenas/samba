// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of signing with fake crypto functions. A fake signature is a
//! checksum of the message and the number of vectors that the signer got.

#![allow(unsafe_code)]
// The test checksum uses the low bits of numbers.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::ffi::{c_int, c_void};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::ptr;
use std::time::{Duration, Instant};

use truenas_smb_server::ffi::{
    tn_smbsrv_attach, tn_smbsrv_keys_pin, tn_smbsrv_send_sealed,
    tn_smbsrv_session_drop, tn_smbsrv_session_keys,
};
use truenas_smb_server::{
    CryptoOps, SignPart, TN_SMBSRV_KEY_FREE, TN_SMBSRV_SIGNED_OK,
};
use truenas_smbros::ffi::{
    TN_SMBROS_PDU, TN_SMBROS_SENT, tn_smbros_adopt, tn_smbros_buf_free,
    tn_smbros_close, tn_smbros_ctx_free, tn_smbros_ctx_new, tn_smbros_next,
};
use truenas_smbros::{Conn, Ctx, TnSmbrosEvent};

const SESSION: u64 = 9;
const GENERATION: u64 = 3;
const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// The checksum of the bytes of `iov` but bytes 48 to 63 of the first
/// vector, the signature of an SMB2 header.
///
/// # Safety
///
/// Each vector points to `iov_len` readable bytes.
unsafe fn checksum(iov: &[libc::iovec]) -> u64 {
    let mut s = 0u64;
    for (i, v) in iov.iter().enumerate() {
        // SAFETY: as the caller says.
        let b = unsafe {
            std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len)
        };
        for (j, &x) in b.iter().enumerate() {
            if i == 0 && (48..64).contains(&j) {
                continue;
            }
            s = s.wrapping_mul(31).wrapping_add(u64::from(x));
        }
    }
    s
}

/// Put the checksum in bytes 48 to 55 and the number of vectors in bytes
/// 56 to 63.
unsafe extern "C" fn fake_sign(
    _key: *mut c_void,
    iov: *mut libc::iovec,
    n: c_int,
) -> u32 {
    // SAFETY: the reactor passes `n` vectors of one message.
    let iov = unsafe { std::slice::from_raw_parts(iov, n as usize) };
    // SAFETY: as above.
    let s = unsafe { checksum(iov) };
    // SAFETY: the first vector is the 64-byte SMB2 header.
    let hdr = unsafe {
        std::slice::from_raw_parts_mut(iov[0].iov_base.cast::<u8>(), 64)
    };
    hdr[48..56].copy_from_slice(&s.to_le_bytes());
    hdr[56..64].copy_from_slice(&u64::from(n as u32).to_le_bytes());
    0
}

unsafe extern "C" fn fake_check(
    _key: *mut c_void,
    iov: *mut libc::iovec,
    n: c_int,
) -> u32 {
    // SAFETY: as in fake_sign().
    let iov = unsafe { std::slice::from_raw_parts(iov, n as usize) };
    // SAFETY: as in fake_sign().
    let s = unsafe { checksum(iov) };
    // SAFETY: as in fake_sign().
    let hdr =
        unsafe { std::slice::from_raw_parts(iov[0].iov_base.cast::<u8>(), 64) };
    if hdr[48..56] == s.to_le_bytes() {
        0
    } else {
        0xC000_0022
    }
}

static OPS: CryptoOps = CryptoOps {
    thread_init: None,
    sign: Some(fake_sign),
    check: Some(fake_check),
    encrypt: None,
    decrypt: None,
};

/// Sign the SMB2 message `msg` as `fake_sign()` does.
fn sign(msg: &mut [u8]) {
    let v = libc::iovec {
        iov_base: msg.as_mut_ptr().cast(),
        iov_len: msg.len(),
    };
    // SAFETY: the vector covers `msg`.
    unsafe { fake_sign(ptr::null_mut(), (&raw const v).cast_mut(), 1) };
}

/// True if the signature of `msg` is right.
fn signed(msg: &[u8]) -> bool {
    let v = libc::iovec {
        iov_base: msg.as_ptr().cast_mut().cast(),
        iov_len: msg.len(),
    };
    // SAFETY: the vector covers `msg`, and the check does not change it.
    unsafe { fake_check(ptr::null_mut(), (&raw const v).cast_mut(), 1) == 0 }
}

/// The number of vectors that the reactor gave `fake_sign()` for `msg`.
fn vectors(msg: &[u8]) -> u64 {
    u64::from_le_bytes(msg[56..64].try_into().unwrap())
}

/// A key value for smbd's functions. The fake functions do not read it.
fn key(n: usize) -> *mut c_void {
    ptr::without_provenance_mut(n)
}

struct Rig {
    ctx: *mut Ctx,
    conn: *mut Conn,
    peer: UnixStream,
    _sock: UnixStream,
}

impl Rig {
    fn new() -> Rig {
        let ctx = tn_smbros_ctx_new();
        // SAFETY: the context is live, and OPS is a static table.
        assert!(unsafe {
            tn_smbsrv_attach(ctx, &raw const OPS, ptr::null(), 0)
        });
        let (peer, sock) = UnixStream::pair().unwrap();
        // A missing reply fails the test instead of hanging it.
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut err = 0;
        let none = usize::MAX;
        // SAFETY: the context is live and the socket is open.
        let conn = unsafe {
            tn_smbros_adopt(
                ctx,
                sock.as_raw_fd(),
                1,
                16,
                false,
                none,
                none,
                none,
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

    fn reply(&mut self) -> Vec<u8> {
        let mut nbt = [0u8; 4];
        self.peer.read_exact(&mut nbt).unwrap();
        let len = u32::from_be_bytes([0, nbt[1], nbt[2], nbt[3]]) as usize;
        let mut msg = vec![0u8; len];
        self.peer.read_exact(&mut msg).unwrap();
        msg
    }

    /// Give the session the signing key `key`.
    fn keys(&self, generation: u64, key: *mut c_void) {
        // SAFETY: the connection is live. The function owns the key.
        let rc = unsafe {
            tn_smbsrv_session_keys(
                self.conn,
                SESSION,
                generation,
                key,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0);
    }

    /// Send the request `m`. Returns the flags and the tag of its event.
    fn check(&mut self, m: &[u8]) -> (u32, u64) {
        let mut pdu = u32::try_from(m.len()).unwrap().to_be_bytes().to_vec();
        pdu.extend_from_slice(m);
        self.peer.write_all(&pdu).unwrap();
        let ev = self.next();
        assert_eq!(ev.kind, TN_SMBROS_PDU);
        // SAFETY: the test owns the buffer and does not use it again.
        unsafe { tn_smbros_buf_free(ev.buf) };
        (ev.flags, ev.tag)
    }

    /// Send `vecs` with the messages of `parts` signed. A part is the index
    /// and the number of its vectors.
    fn send_signed(
        &mut self,
        vecs: &[&[u8]],
        parts: &[(c_int, c_int)],
        lend_min: usize,
    ) -> Vec<u8> {
        let iov: Vec<libc::iovec> = vecs
            .iter()
            .map(|b| libc::iovec {
                iov_base: b.as_ptr().cast_mut().cast(),
                iov_len: b.len(),
            })
            .collect();
        let parts: Vec<SignPart> = parts
            .iter()
            .map(|&(iov, iovcnt)| {
                // SAFETY: the connection is live.
                let keys = unsafe {
                    tn_smbsrv_keys_pin(self.conn, SESSION, GENERATION)
                };
                assert!(!keys.is_null());
                SignPart { keys, iov, iovcnt }
            })
            .collect();
        let mut lent = false;
        // SAFETY: the vectors live until SENT. The function owns the keys.
        let rc = unsafe {
            tn_smbsrv_send_sealed(
                self.conn,
                iov.as_ptr(),
                c_int::try_from(iov.len()).unwrap(),
                lend_min,
                5,
                &raw mut lent,
                ptr::null_mut(),
                parts.as_ptr(),
                parts.len(),
            )
        };
        assert_eq!(rc, 0);
        assert!(lent);
        let msg = self.reply();
        let ev = self.next();
        assert_eq!((ev.kind, ev.cookie), (TN_SMBROS_SENT, 5));
        msg
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

/// An SMB2 message of `session` with the signed flag.
fn message(session: u64, body: usize) -> Vec<u8> {
    let mut m = vec![0u8; 64 + body];
    m[..4].copy_from_slice(&SMB2_MAGIC);
    m[4..6].copy_from_slice(&64u16.to_le_bytes());
    m[12..14].copy_from_slice(&5u16.to_le_bytes());
    m[16..20].copy_from_slice(&8u32.to_le_bytes());
    m[40..48].copy_from_slice(&session.to_le_bytes());
    for (i, x) in m[64..].iter_mut().enumerate() {
        *x = i as u8;
    }
    m
}

/// The reactor checks the signature of a request with the keys of its
/// session. It signs a reply in place, or on a copy if libcli cannot take
/// the layout of the vectors. smbd gets the keys back after the drop of
/// the session.
#[test]
fn the_reactor_checks_and_signs() {
    let mut rig = Rig::new();
    let key = key(1);
    rig.keys(GENERATION, key);
    for good in [true, false] {
        let mut m = message(SESSION, 57);
        sign(&mut m);
        if !good {
            m[70] ^= 1;
        }
        let (flags, tag) = rig.check(&m);
        if good {
            assert_eq!((flags, tag), (TN_SMBSRV_SIGNED_OK, GENERATION));
        } else {
            assert_eq!(flags, 0);
        }
    }
    let m = message(SESSION, 8);
    let nbt = u32::try_from(m.len() + 1000).unwrap().to_be_bytes();
    let dyn_part = vec![7u8; 1000];
    // The message is two copied vectors and one lent vector. The reactor
    // signs it in place.
    let vecs: [&[u8]; 4] = [&nbt, &m[..64], &m[64..], &dyn_part];
    let got = rig.send_signed(&vecs, &[(1, 3)], 512);
    assert!(signed(&got));
    assert_eq!(vectors(&got), 3);
    assert_eq!(&got[64..72], &m[64..]);
    // libcli cannot take six lent vectors. The reactor signs a copy.
    let parts = vec![3u8; 600];
    let nbt = u32::try_from(64 + 6 * 600).unwrap().to_be_bytes();
    let mut vecs: Vec<&[u8]> = vec![&nbt, &m[..64]];
    vecs.extend(std::iter::repeat_n(&parts[..], 6));
    let got = rig.send_signed(&vecs, &[(1, 7)], 512);
    assert!(signed(&got));
    assert_eq!(vectors(&got), 2);
    assert_eq!(got.len(), 64 + 3600);
    // SAFETY: the connection is live.
    unsafe { tn_smbsrv_session_drop(rig.conn, SESSION) };
    let ev = rig.next();
    assert_eq!((ev.kind, ev.buf), (TN_SMBSRV_KEY_FREE, key));
}

/// The reactor signs each message of a compound reply in place, also where
/// a message starts or ends inside a copied vector.
#[test]
fn the_reactor_signs_a_compound_in_place() {
    let mut rig = Rig::new();
    rig.keys(GENERATION, key(2));
    let (m1, m2) = (message(SESSION, 16), message(SESSION, 16));
    let (dyn1, tail1, dyn2) = (vec![1u8; 600], vec![2u8; 8], vec![3u8; 600]);
    let nbt = u32::try_from(2 * 80 + 600 + 8 + 600).unwrap().to_be_bytes();
    let vecs: [&[u8]; 8] = [
        &nbt,
        &m1[..64],
        &m1[64..],
        &dyn1,
        &tail1,
        &m2[..64],
        &m2[64..],
        &dyn2,
    ];
    let got = rig.send_signed(&vecs, &[(1, 4), (5, 3)], 512);
    let (r1, r2) = got.split_at(80 + 600 + 8);
    assert!(signed(r1) && signed(r2));
    // The body of the first message spans three segments. The header of
    // the second starts 8 bytes into a segment.
    assert_eq!((vectors(r1), vectors(r2)), (4, 3));
    assert_eq!(r1[680..], tail1);
    assert_eq!(r2[64..80], m2[64..]);
}

/// After smbd replaces the keys of a session, the reactor checks with the
/// new keys and smbd gets the old key back. A session without keys gets no
/// check.
#[test]
fn the_reactor_uses_new_keys_after_a_change() {
    let mut rig = Rig::new();
    let (k1, k2) = (key(3), key(4));
    rig.keys(GENERATION, k1);
    let mut m = message(SESSION, 20);
    sign(&mut m);
    // The first check fills the key cache of the reactor. The second finds
    // the keys in the cache.
    for _ in 0..2 {
        assert_eq!(rig.check(&m), (TN_SMBSRV_SIGNED_OK, GENERATION));
    }
    rig.keys(GENERATION + 1, k2);
    let ev = rig.next();
    assert_eq!((ev.kind, ev.buf), (TN_SMBSRV_KEY_FREE, k1));
    assert_eq!(rig.check(&m), (TN_SMBSRV_SIGNED_OK, GENERATION + 1));
    let mut other = message(SESSION + 1, 20);
    sign(&mut other);
    assert_eq!(rig.check(&other).0, 0);
    // SAFETY: the connection is live.
    unsafe { tn_smbsrv_session_drop(rig.conn, SESSION) };
    let ev = rig.next();
    assert_eq!((ev.kind, ev.buf), (TN_SMBSRV_KEY_FREE, k2));
}
