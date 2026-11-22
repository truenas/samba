// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Signing and encryption on the reactors with smbd's functions and keys.

use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::Arc;

use truenas_smbros::{
    Conn, Shim, ShimReactor, iov_of, make_out, release_out, send_out,
};

use crate::keys::{KeyCache, KeyTable, Keys, pin, unpin};
use crate::plan::Plan;
use crate::upper::{Layer, local_parts};
use crate::wire::{
    NBT_HDR_SIZE, NT_STATUS_UNSUCCESSFUL, SMB2_HDR_FLAG_CHAINED,
    SMB2_HDR_FLAG_SIGNED, SMB2_HDR_FLAGS, SMB2_HDR_MAGIC,
    SMB2_HDR_NEXT_COMMAND, SMB2_HDR_OPCODE, SMB2_HDR_SESSION_ID, SMB2_HDR_SIZE,
    SMB2_OP_CANCEL, SMB2_OP_NEGPROT, SMB2_OP_SESSSETUP, SMB2_TF_MAGIC,
    SMB2_TF_MSG_SIZE, SMB2_TF_SESSION_ID, SMB2_TF_SIZE, is_magic, le16, le32,
    le64,
};

/// A flag of a PDU event. The reactor decrypted the request. `data` has the
/// transform header and the decrypted message. `tag` has the generation of
/// the keys. See `tn_smbsrv_session_keys()`.
pub const TN_SMBSRV_DECRYPTED: u32 = 1;
/// A flag of a PDU event. The reactor could not decrypt the request. The
/// attempt changed `data`. `status` has the NTSTATUS. `tag` has the
/// generation of the keys.
pub const TN_SMBSRV_DECRYPT_FAILED: u32 = 2;
/// A flag of a PDU event. Each signature of the request is correct. `tag`
/// has the generation of the keys.
pub const TN_SMBSRV_SIGNED_OK: u32 = 4;

/// The reactor sends the reply of a job as it is.
pub const TN_SMBSRV_SEAL_NONE: c_int = 0;
/// The reactor signs the reply of a job.
pub const TN_SMBSRV_SEAL_SIGN: c_int = 1;
/// The reactor encrypts the reply of a job.
pub const TN_SMBSRV_SEAL_ENCRYPT: c_int = 2;

/// A crypto function of smbd. It works in place and returns an NTSTATUS.
pub(crate) type CryptoFn =
    unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32;

/// The SMB2 signing and encryption functions of the caller. The reactors
/// call them on their own threads with the keys from
/// `tn_smbsrv_session_keys()`. `iov[0]` is the SMB2 header or the transform
/// header. `iov[1]` is the rest. Each function works in place. It returns
/// an NTSTATUS. `check` does not change the PDU.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CryptoOps {
    /// Each reactor thread calls this first. NULL is allowed.
    pub thread_init: Option<unsafe extern "C" fn()>,
    // Not `CryptoFn`: cbindgen makes nullable C pointers of these types.
    pub sign: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
    pub check: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
    pub encrypt: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
    pub decrypt: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
}

/// Run smbd's `f` with `key` on `iov`. `NT_STATUS_UNSUCCESSFUL` if `f` or
/// `key` is missing.
pub(crate) fn host_crypto(
    f: Option<CryptoFn>,
    key: *mut c_void,
    iov: &mut [libc::iovec],
) -> u32 {
    let Some(f) = f else {
        return NT_STATUS_UNSUCCESSFUL;
    };
    if key.is_null() {
        return NT_STATUS_UNSUCCESSFUL;
    }
    let n = c_int::try_from(iov.len()).unwrap_or(0);
    // SAFETY: smbd's function gets a key of smbd and the caller's vectors.
    unsafe { f(key, iov.as_mut_ptr(), n) }
}

/// Run `f` on `buf`, split at `at`.
fn host_crypto_split(
    f: Option<CryptoFn>,
    key: *mut c_void,
    buf: &mut [u8],
    at: usize,
) -> u32 {
    let (head, rest) = buf.split_at_mut(at);
    let mut iov = [
        libc::iovec {
            iov_base: head.as_mut_ptr().cast(),
            iov_len: head.len(),
        },
        libc::iovec {
            iov_base: rest.as_mut_ptr().cast(),
            iov_len: rest.len(),
        },
    ];
    host_crypto(f, key, &mut iov)
}

/// What `open_pdu()` found.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Opened {
    pub(crate) flags: u32,
    pub(crate) status: u32,
    pub(crate) tag: u64,
}

/// The most messages that the reactor checks in one PDU.
const MAXMSG: usize = 64;

/// The length, flags, opcode and session of the SMB2 message at `at`.
fn message(pdu: &[u8], at: usize) -> Option<(usize, u32, u16, u64)> {
    let rest = &pdu[at..];
    if rest.len() < SMB2_HDR_SIZE + 2
        || !is_magic(rest, SMB2_HDR_MAGIC)
        || le16(rest, 4) != 64
    {
        return None;
    }
    let next = le32(rest, SMB2_HDR_NEXT_COMMAND) as usize;
    let len = match next {
        0 => rest.len(),
        n if n < SMB2_HDR_SIZE + 2 || n > rest.len() => return None,
        n => n,
    };
    Some((
        len,
        le32(rest, SMB2_HDR_FLAGS),
        le16(rest, SMB2_HDR_OPCODE),
        le64(rest, SMB2_HDR_SESSION_ID),
    ))
}

/// The number of messages of `pdu` and their one session, if all are signed
/// and none is a NEGOTIATE, `SESSION_SETUP` or CANCEL.
fn signed_messages(pdu: &[u8]) -> Option<(usize, u64)> {
    let mut n = 0;
    let mut session: Option<u64> = None;
    let mut at = 0;
    while at < pdu.len() {
        if n == MAXMSG {
            return None;
        }
        let (len, flags, op, field) = message(pdu, at)?;
        if flags & SMB2_HDR_FLAG_SIGNED == 0
            || op == SMB2_OP_NEGPROT
            || op == SMB2_OP_SESSSETUP
            || op == SMB2_OP_CANCEL
        {
            return None;
        }
        let id = if flags & SMB2_HDR_FLAG_CHAINED != 0 {
            // A related first message has no session in smbd.
            session?
        } else {
            field
        };
        if session.is_some_and(|s| s != id) {
            return None;
        }
        session = Some(id);
        n += 1;
        at += len;
    }
    Some((n, session?))
}

/// Decrypt `pdu` in place or check its signatures. None, with the PDU
/// unchanged, if smbd must do it.
pub(crate) fn open_pdu(
    ops: &CryptoOps,
    kc: &mut KeyCache,
    t: &KeyTable,
    pdu: &mut [u8],
) -> Option<Opened> {
    if pdu.len() >= SMB2_TF_SIZE && is_magic(pdu, SMB2_TF_MAGIC) {
        // Clients send one encrypted message per PDU. smbd decrypts others.
        if SMB2_TF_SIZE + le32(pdu, SMB2_TF_MSG_SIZE) as usize != pdu.len() {
            return None;
        }
        let k = kc.find(t, le64(pdu, SMB2_TF_SESSION_ID))?;
        if ops.decrypt.is_none() || k.decrypt.is_null() {
            return None;
        }
        // A failed decryption changes the PDU, so smbd uses this status.
        let status =
            host_crypto_split(ops.decrypt, k.decrypt, pdu, SMB2_TF_SIZE);
        let flags = if status == 0 {
            TN_SMBSRV_DECRYPTED
        } else {
            TN_SMBSRV_DECRYPT_FAILED
        };
        return Some(Opened {
            flags,
            status,
            tag: k.generation,
        });
    }
    let (n, session) = signed_messages(pdu)?;
    let k = kc.find(t, session)?;
    let mut at = 0;
    for _ in 0..n {
        let (len, ..) = message(pdu, at)?;
        let msg = &mut pdu[at..at + len];
        if host_crypto_split(ops.check, k.sign, msg, SMB2_HDR_SIZE) != 0 {
            return None;
        }
        at += len;
    }
    Some(Opened {
        flags: TN_SMBSRV_SIGNED_OK,
        status: 0,
        tag: k.generation,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SealKind {
    #[default]
    None,
    Sign,
    Encrypt,
}

/// The protection of the reply of a job.
#[derive(Debug, Default)]
pub(crate) struct Seal {
    pub(crate) kind: SealKind,
    pub(crate) keys: Option<Arc<Keys>>,
}

impl Seal {
    /// The seal of a `TN_SMBSRV_SEAL_*` value with the keys of `pin`. None
    /// for a bad value or a missing key.
    pub(crate) fn of(seal: c_int, pin: Option<Arc<Keys>>) -> Option<Seal> {
        let kind = match seal {
            TN_SMBSRV_SEAL_NONE => return Some(Seal::default()),
            TN_SMBSRV_SEAL_SIGN => SealKind::Sign,
            TN_SMBSRV_SEAL_ENCRYPT => SealKind::Encrypt,
            _ => return None,
        };
        let k = pin?;
        let key = if kind == SealKind::Sign {
            k.sign
        } else {
            k.encrypt
        };
        (!key.is_null()).then_some(Seal {
            kind,
            keys: Some(k),
        })
    }

    /// The offset of the SMB2 header in the reply.
    #[inline]
    pub(crate) fn hdr(&self) -> usize {
        if self.kind == SealKind::Encrypt {
            NBT_HDR_SIZE + SMB2_TF_SIZE
        } else {
            NBT_HDR_SIZE
        }
    }

    /// smbd encrypts an interim response like the reply but does not sign
    /// it.
    pub(crate) fn interim(&self) -> Seal {
        if self.kind != SealKind::Encrypt {
            return Seal::default();
        }
        Seal {
            kind: SealKind::Encrypt,
            keys: self.keys.clone(),
        }
    }

    /// Sign or encrypt the finished reply in `buf`. False on failure.
    pub(crate) fn apply(
        &self,
        ops: Option<&CryptoOps>,
        buf: &mut [u8],
    ) -> bool {
        let Some(ops) = ops else {
            return self.kind == SealKind::None;
        };
        match (self.kind, &self.keys) {
            (SealKind::None, _) => true,
            (SealKind::Sign, Some(k)) => {
                sign_msg(ops, k, &mut buf[NBT_HDR_SIZE..])
            }
            (SealKind::Encrypt, Some(k)) => encrypt_pdu(ops, k, buf),
            _ => false,
        }
    }
}

pub(crate) fn sign_msg(ops: &CryptoOps, k: &Keys, msg: &mut [u8]) -> bool {
    msg.len() > SMB2_HDR_SIZE
        && host_crypto_split(ops.sign, k.sign, msg, SMB2_HDR_SIZE) == 0
}

/// Encrypt `buf`. smbd put the transform header with its nonce after the
/// NBT header.
pub(crate) fn encrypt_pdu(ops: &CryptoOps, k: &Keys, buf: &mut [u8]) -> bool {
    buf.len() > NBT_HDR_SIZE + SMB2_TF_SIZE
        && host_crypto_split(
            ops.encrypt,
            k.encrypt,
            &mut buf[NBT_HDR_SIZE..],
            SMB2_TF_SIZE,
        ) == 0
}

/// One SMB2 message of a reply that `tn_smbsrv_send_sealed()` signs.
#[repr(C)]
#[derive(Debug)]
pub struct SignPart {
    /// Keys from `tn_smbsrv_keys_pin()`. The reactor signs the message with
    /// their signing key.
    pub keys: *mut Keys,
    /// The message is the `iovcnt` vectors of the reply that start at index
    /// `iov`.
    pub iov: c_int,
    pub iovcnt: c_int,
}

impl SignPart {
    /// The byte range of the message in the PDU of `iov`.
    fn range(&self, iov: &[libc::iovec]) -> Option<(usize, usize)> {
        let first = usize::try_from(self.iov).ok()?;
        let count = usize::try_from(self.iovcnt).ok()?;
        let msg = iov.get(first..first.checked_add(count)?)?;
        let start: usize = iov[..first].iter().map(|v| v.iov_len).sum();
        let len: usize = msg.iter().map(|v| v.iov_len).sum();
        Some((start, start + len))
    }
}

/// Make the reactor drop its cached keys, so smbd gets old keys back soon.
fn keys_changed(conn: &Conn) {
    // SAFETY: a C function holds no borrow of the reactor at its start.
    if let Some(mut r) = unsafe { conn.local() } {
        // SAFETY: as above.
        if let Some((_, l)) = unsafe { local_parts(&mut r) } {
            l.keys.clear();
        }
        return;
    }
    if let Some(ext) = conn.ext::<Layer>() {
        ext.post_keys_msg(conn);
    }
}

/// Give the reactor of `conn` the keys of `session_id`. `sign` is the
/// signing key of the channel. `encrypt` is the key for replies. `decrypt`
/// is the key for requests. The new keys replace the old keys of the
/// session on `conn`. `generation` is the caller's number for these keys.
///
/// This function takes ownership of the keys in all cases. Later,
/// `tn_smbros_next()` returns each key in a `TN_SMBSRV_KEY_FREE` event.
/// Returns 0, or ENOTSUP if the reactors have no crypto functions.
///
/// # Safety
///
/// `conn` is from `tn_smbros_adopt()`. Each key is NULL or a key for the
/// crypto functions of smbd. The caller does not give the same key to
/// another connection.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_session_keys(
    conn: *mut Conn,
    session_id: u64,
    generation: u64,
    sign: *mut c_void,
    encrypt: *mut c_void,
    decrypt: *mut c_void,
) -> c_int {
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    let hub = conn.hub_ref();
    // On an error, the drop of the keys gives each key back.
    let keys = Arc::new(Keys::new(hub, generation, sign, encrypt, decrypt));
    let Some(ext) = conn.ext::<Layer>().filter(|e| e.ops.is_some()) else {
        return libc::ENOTSUP;
    };
    match ext.keys.insert(session_id, keys) {
        Ok(old) => drop(old),
        Err(keys) => {
            drop(keys);
            return libc::ENOMEM;
        }
    }
    keys_changed(conn);
    0
}

/// Remove the keys of `session_id` from `conn`. References from
/// `tn_smbsrv_keys_pin()` are still valid.
///
/// # Safety
///
/// `conn` is from `tn_smbros_adopt()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_session_drop(
    conn: *mut Conn,
    session_id: u64,
) {
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    let Some(ext) = conn.ext::<Layer>() else {
        return;
    };
    if let Some(k) = ext.keys.remove(session_id) {
        drop(k);
        keys_changed(conn);
    }
}

/// A reference to the keys of `session_id` on `conn`. NULL if `conn` has no
/// keys of `session_id` with this `generation`. Give the reference to
/// `tn_smbsrv_delegate()` or `tn_smbsrv_send_sealed()`, or free it with
/// `tn_smbsrv_keys_unpin()`.
///
/// # Safety
///
/// `conn` is from `tn_smbros_adopt()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_keys_pin(
    conn: *mut Conn,
    session_id: u64,
    generation: u64,
) -> *mut Keys {
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    let Some(ext) = conn.ext::<Layer>() else {
        return ptr::null_mut();
    };
    // SAFETY: a C function holds no borrow of the reactor at its start.
    if let Some(mut r) = unsafe { conn.local() } {
        // SAFETY: as above.
        if let Some((_, l)) = unsafe { local_parts(&mut r) } {
            return match l.keys.find(&ext.keys, session_id) {
                Some(k) if k.generation == generation => pin(Arc::clone(k)),
                _ => ptr::null_mut(),
            };
        }
    }
    match ext.keys.find(session_id) {
        Some(k) if k.generation == generation => pin(k),
        _ => ptr::null_mut(),
    }
}

/// Free a reference from `tn_smbsrv_keys_pin()`. NULL is allowed.
///
/// # Safety
///
/// `pin` is NULL or is from `tn_smbsrv_keys_pin()`. The caller does not use
/// it again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_keys_unpin(pin: *mut Keys) {
    // SAFETY: the caller gives up its reference.
    drop(unsafe { unpin(pin) });
}

/// Queue the reply in `iov` like `tn_smbros_send()` does. The reactor signs
/// or encrypts the reply before it sends it. Pass `encrypt` or `sign`, not
/// both. With `encrypt`, the caller puts the transform header with the
/// nonce after the NBT header. The reactor then encrypts the PDU with the
/// encryption key of `encrypt`. With `sign`, the reactor signs each of the
/// `nsign` messages in `sign`. The reactor closes the connection if it
/// cannot sign or encrypt the reply.
///
/// Encryption is done in place, so it overwrites the lent vectors, as
/// smbd's own encryption of a reply does.
///
/// In all cases, this function takes ownership of `encrypt` and of the keys
/// in `sign`. Returns 0 or an errno. ENOKEY if a part has no signing key or
/// the reactors have no crypto functions.
///
/// # Safety
///
/// The conditions of `tn_smbros_send()` apply. `sign` is NULL or has
/// `nsign` parts. `encrypt` and the keys of each part are NULL or are from
/// `tn_smbsrv_keys_pin()`. The caller does not use them again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_send_sealed(
    conn: *mut Conn,
    iov: *const libc::iovec,
    iovcnt: c_int,
    lend_min: usize,
    sent_cookie: u64,
    lent: *mut bool,
    encrypt: *mut Keys,
    sign: *const SignPart,
    nsign: usize,
) -> c_int {
    // SAFETY: the caller passes `iovcnt` vectors.
    let iov = unsafe { iov_of(iov, iovcnt) };
    // Each key goes into the plan or is dropped before an error return.
    // SAFETY: the caller gives up its reference.
    let encrypt = unsafe { unpin(encrypt) };
    let parts = if sign.is_null() {
        &[]
    } else {
        // SAFETY: the caller passes `nsign` parts.
        unsafe { std::slice::from_raw_parts(sign, nsign) }
    };
    let Some(mut plan) = Plan::get(encrypt) else {
        for part in parts {
            // SAFETY: the caller gives up the reference of each part.
            drop(unsafe { unpin(part.keys) });
        }
        return libc::ENOMEM;
    };
    let mut err = 0;
    for part in parts {
        // SAFETY: the caller gives up the reference of each part.
        let k = unsafe { unpin(part.keys) };
        match (k, iov.and_then(|v| part.range(v))) {
            (Some(k), Some(rg)) if !k.sign.is_null() => {
                if !plan.sign(k, rg) {
                    err = libc::ENOMEM;
                }
            }
            (Some(k), _) if k.sign.is_null() => err = libc::ENOKEY,
            (None, _) => err = libc::ENOKEY,
            _ => err = libc::EINVAL,
        }
    }
    let Some(iov) = iov else {
        return libc::EINVAL;
    };
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    if conn.ext::<Layer>().is_none_or(|e| e.ops.is_none()) {
        return libc::ENOKEY;
    }
    if err != 0 {
        return err;
    }
    if !plan.valid(parts.len()) {
        return libc::EINVAL;
    }
    // SAFETY: a C function holds no borrow of the reactor at its start.
    let mut local = unsafe { conn.local() };
    // SAFETY: the caller keeps the vectors readable until TN_SMBROS_SENT.
    let Some(mut o) =
        (unsafe { make_out(local.as_deref_mut(), iov, lend_min) })
    else {
        return libc::ENOMEM;
    };
    o.cookie = sent_cookie;
    // SAFETY: the caller passes room for a bool.
    unsafe { lent.write(o.lent) };
    o.plan = plan.into_raw();
    o.finish = true;
    match local.as_deref_mut() {
        Some(r) => send_finished(r, o),
        None => send_out(conn, None, o),
    }
    0
}

/// Sign or encrypt `o` on its reactor `r`, then queue it.
fn send_finished(r: &mut ShimReactor, mut o: Box<truenas_smbros::Out>) {
    if !<Layer as truenas_smbros::Upper>::finish_out(r, &mut o) {
        release_out(r, o);
        r.end::<Shim<Layer>>(libc::ECONNABORTED);
        return;
    }
    r.queue_api(o);
}
