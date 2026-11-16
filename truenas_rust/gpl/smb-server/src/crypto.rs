// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Signing and encryption with smbd's functions and the keys of the
//! sessions. A reactor decrypts a request or checks its signatures before
//! smbd gets it. A reactor also signs or encrypts a reply before it sends
//! the reply.

use std::ffi::{c_int, c_void};
use std::ops::Range;
use std::ptr;
use std::sync::Arc;

use truenas_ros::net::server::PushPart;
use truenas_smbros::{Conn, NBT_HDR_SIZE, Note, Poster, iov_of, lock};

use crate::wire::{
    NT_STATUS_UNSUCCESSFUL, SMB2_HDR_FLAG_CHAINED, SMB2_HDR_FLAG_SIGNED,
    SMB2_HDR_FLAGS, SMB2_HDR_MAGIC, SMB2_HDR_NEXT_COMMAND, SMB2_HDR_OPCODE,
    SMB2_HDR_SESSION_ID, SMB2_HDR_SIZE, SMB2_OP_CANCEL, SMB2_OP_NEGPROT,
    SMB2_OP_SESSSETUP, SMB2_TF_MAGIC, SMB2_TF_MSG_SIZE, SMB2_TF_SESSION_ID,
    SMB2_TF_SIZE, le16, le32, le64,
};
use crate::{ConnExt, TN_SMBSRV_KEY_FREE};

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

/// A crypto function of smbd. It works in place on the vectors of one PDU
/// with a key. It returns an NTSTATUS.
type CryptoFn =
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
    pub(crate) thread_init: Option<unsafe extern "C" fn()>,
    // These fields do not use `CryptoFn`. With the written-out types,
    // cbindgen makes nullable C pointers.
    sign: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
    check: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
    encrypt: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
    decrypt: Option<
        unsafe extern "C" fn(*mut c_void, *mut libc::iovec, c_int) -> u32,
    >,
}

/// A key that smbd gave to one connection. Only the reactor of the
/// connection uses it. smbd frees it on its main thread after
/// `TN_SMBSRV_KEY_FREE`.
#[derive(Debug)]
struct HostKey {
    key: *mut c_void,
    poster: Poster,
}

// SAFETY: only the reactor of the connection passes the key to smbd's
// functions. smbd frees the key on its main thread.
unsafe impl Send for HostKey {}
// SAFETY: the reason for Send applies here too.
unsafe impl Sync for HostKey {}

impl Drop for HostKey {
    fn drop(&mut self) {
        self.poster.post(Box::new(KeyFree(self.key)));
    }
}

/// A key for smbd to free.
#[derive(Debug)]
struct KeyFree(*mut c_void);

// SAFETY: only smbd's main thread uses the pointer of the event. That
// thread frees the key.
unsafe impl Send for KeyFree {}

impl Note for KeyFree {
    fn take(self: Box<Self>) -> Option<(c_int, u64, *mut c_void)> {
        Some((TN_SMBSRV_KEY_FREE, 0, self.0))
    }
}

/// The keys of one session on one connection, from
/// `tn_smbsrv_session_keys()`. A `struct tn_smbsrv_keys` pointer is one
/// reference to them.
#[derive(Debug)]
pub struct Keys {
    /// The number that smbd gave these keys.
    generation: u64,
    /// The signing key of the channel.
    sign: Option<HostKey>,
    /// The key that encrypts replies.
    encrypt: Option<HostKey>,
    /// The key that decrypts requests.
    decrypt: Option<HostKey>,
}

/// Take ownership of the reference `pin` from smbd. None for NULL.
///
/// # Safety
///
/// `pin` is NULL or is from `tn_smbsrv_keys_pin()`. The caller does not use
/// it again.
unsafe fn unpin(pin: *mut Keys) -> Option<Arc<Keys>> {
    // SAFETY: the caller transfers a reference from Arc::into_raw().
    (!pin.is_null()).then(|| unsafe { Arc::from_raw(pin.cast_const()) })
}

/// Split `buf` at `at` into two vectors for smbd's functions.
fn split_iov(buf: &mut [u8], at: usize) -> [libc::iovec; 2] {
    let (head, rest) = buf.split_at_mut(at);
    [
        libc::iovec {
            iov_base: head.as_mut_ptr().cast(),
            iov_len: head.len(),
        },
        libc::iovec {
            iov_base: rest.as_mut_ptr().cast(),
            iov_len: rest.len(),
        },
    ]
}

/// Run smbd's `f` with `key` on `buf`, split at `at`. Returns the NTSTATUS
/// of `f`. `NT_STATUS_UNSUCCESSFUL` if `f` or `key` is missing.
fn host_crypto(
    f: Option<CryptoFn>,
    key: Option<&HostKey>,
    buf: &mut [u8],
    at: usize,
) -> u32 {
    let (Some(f), Some(key)) = (f, key) else {
        return NT_STATUS_UNSUCCESSFUL;
    };
    let mut iov = split_iov(buf, at);
    // SAFETY: `f` and `key` are from smbd. The two vectors point into
    // `buf`. `f` does not keep them.
    unsafe { f(key.key, iov.as_mut_ptr(), 2) }
}

/// Sign the SMB2 message in `msg`. False on failure.
fn sign_msg(ops: &CryptoOps, keys: &Keys, msg: &mut [u8]) -> bool {
    msg.len() > SMB2_HDR_SIZE
        && host_crypto(ops.sign, keys.sign.as_ref(), msg, SMB2_HDR_SIZE) == 0
}

/// Encrypt the PDU in `buf`. The transform header is after the NBT header.
/// smbd built that header and set its nonce. False on failure.
fn encrypt_pdu(ops: &CryptoOps, keys: &Keys, buf: &mut [u8]) -> bool {
    buf.len() > NBT_HDR_SIZE + SMB2_TF_SIZE
        && host_crypto(
            ops.encrypt,
            keys.encrypt.as_ref(),
            &mut buf[NBT_HDR_SIZE..],
            SMB2_TF_SIZE,
        ) == 0
}

/// The protection of the reply of a job.
#[derive(Debug)]
pub(crate) enum Seal {
    None,
    Sign(Arc<Keys>),
    Encrypt(Arc<Keys>),
}

impl Seal {
    /// The `Seal` for the `TN_SMBSRV_SEAL_*` value `seal`. This function
    /// takes ownership of the reference `pin`. None if the key for `seal`
    /// is missing. None if `seal` is not a `TN_SMBSRV_SEAL_*` value.
    ///
    /// # Safety
    ///
    /// `pin` is NULL or is from `tn_smbsrv_keys_pin()`. The caller does not
    /// use it again.
    pub(crate) unsafe fn of(seal: c_int, pin: *mut Keys) -> Option<Seal> {
        // SAFETY: the caller transfers ownership of `pin`.
        match (seal, unsafe { unpin(pin) }) {
            (TN_SMBSRV_SEAL_SIGN, Some(k)) if k.sign.is_some() => {
                Some(Seal::Sign(k))
            }
            (TN_SMBSRV_SEAL_ENCRYPT, Some(k)) if k.encrypt.is_some() => {
                Some(Seal::Encrypt(k))
            }
            (TN_SMBSRV_SEAL_NONE, _) => Some(Seal::None),
            _ => None,
        }
    }

    /// The offset of the SMB2 header in the reply.
    pub(crate) fn hdr(&self) -> usize {
        match self {
            Seal::Encrypt(_) => NBT_HDR_SIZE + SMB2_TF_SIZE,
            _ => NBT_HDR_SIZE,
        }
    }

    /// Sign or encrypt the finished reply in `buf`. False on failure.
    pub(crate) fn apply(
        &self,
        ops: Option<&CryptoOps>,
        buf: &mut [u8],
    ) -> bool {
        let Some(ops) = ops else {
            return matches!(self, Seal::None);
        };
        match self {
            Seal::None => true,
            Seal::Sign(keys) => sign_msg(ops, keys, &mut buf[NBT_HDR_SIZE..]),
            Seal::Encrypt(keys) => encrypt_pdu(ops, keys, buf),
        }
    }
}

/// Decrypt the request in `pdu` in place, or check its signatures. Returns
/// the `TN_SMBSRV_*` flags, the NTSTATUS of a failed decryption and the
/// generation of the keys. Returns None for a PDU that smbd must handle
/// itself, for example after a wrong signature. Such a PDU is unchanged.
pub(crate) fn open_pdu(
    ext: &ConnExt,
    pdu: &mut [u8],
) -> Option<(u32, u32, u64)> {
    let ops = ext.crypto.as_ref()?;
    if pdu.len() >= SMB2_TF_SIZE && pdu[..4] == SMB2_TF_MAGIC {
        // Clients send one encrypted message per PDU. smbd decrypts any
        // other PDU itself.
        let size = usize::try_from(le32(pdu, SMB2_TF_MSG_SIZE)).ok()?;
        if SMB2_TF_SIZE.checked_add(size) != Some(pdu.len()) {
            return None;
        }
        let keys = ext.keys_of(le64(pdu, SMB2_TF_SESSION_ID))?;
        if ops.decrypt.is_none() || keys.decrypt.is_none() {
            return None;
        }
        // A failed decryption changes the PDU. So smbd uses this status. It
        // does not decrypt the PDU again.
        let status =
            host_crypto(ops.decrypt, keys.decrypt.as_ref(), pdu, SMB2_TF_SIZE);
        return Some(match status {
            0 => (TN_SMBSRV_DECRYPTED, 0, keys.generation),
            status => (TN_SMBSRV_DECRYPT_FAILED, status, keys.generation),
        });
    }
    let (session_id, msgs) = signed_messages(pdu)?;
    let keys = ext.keys_of(session_id)?;
    for at in msgs {
        let status = host_crypto(
            ops.check,
            keys.sign.as_ref(),
            &mut pdu[at],
            SMB2_HDR_SIZE,
        );
        if status != 0 {
            return None;
        }
    }
    Some((TN_SMBSRV_SIGNED_OK, 0, keys.generation))
}

/// The session and the byte range of each message of `pdu`. None unless
/// every message is signed and all have one session. None if a message is
/// a NEGOTIATE, `SESSION_SETUP` or CANCEL. smbd selects the keys for those.
/// The ranges match `smbd_smb2_inbuf_parse_compound()`.
fn signed_messages(pdu: &[u8]) -> Option<(u64, Vec<Range<usize>>)> {
    let mut msgs = Vec::new();
    let mut session: Option<u64> = None;
    let mut at = 0;
    while at < pdu.len() {
        let rest = &pdu[at..];
        if rest.len() < SMB2_HDR_SIZE + 2
            || rest[..4] != SMB2_HDR_MAGIC
            || le16(rest, 4) != 64
        {
            return None;
        }
        let flags = le32(rest, SMB2_HDR_FLAGS);
        if flags & SMB2_HDR_FLAG_SIGNED == 0
            || matches!(
                le16(rest, SMB2_HDR_OPCODE),
                SMB2_OP_NEGPROT | SMB2_OP_SESSSETUP | SMB2_OP_CANCEL
            )
        {
            return None;
        }
        let id = match (flags & SMB2_HDR_FLAG_CHAINED != 0, session) {
            (true, Some(prev)) => prev,
            // smbd has no session for a related first message. See
            // smbd_smb2_request_check_session().
            (true, None) => return None,
            (false, _) => le64(rest, SMB2_HDR_SESSION_ID),
        };
        if session.is_some_and(|s| s != id) {
            return None;
        }
        session = Some(id);
        let next = usize::try_from(le32(rest, SMB2_HDR_NEXT_COMMAND)).ok()?;
        let len = match next {
            0 => rest.len(),
            n if n < SMB2_HDR_SIZE + 2 || n > rest.len() => return None,
            n => n,
        };
        msgs.push(at..at + len);
        at += len;
    }
    Some((session?, msgs))
}

/// One SMB2 message of a reply that `tn_smbsrv_send_sealed()` signs.
#[repr(C)]
#[derive(Debug)]
pub struct SignPart {
    /// Keys from `tn_smbsrv_keys_pin()`. The reactor signs the message with
    /// their signing key.
    keys: *mut Keys,
    /// The message is the `iovcnt` vectors of the reply that start at index
    /// `iov`.
    iov: c_int,
    iovcnt: c_int,
}

impl SignPart {
    /// The byte range of the message in the PDU of `iov`. The PDU starts
    /// with the NBT header. None if `iov` lacks the vectors.
    fn range(&self, iov: &[libc::iovec]) -> Option<Range<usize>> {
        let first = usize::try_from(self.iov).ok()?;
        let count = usize::try_from(self.iovcnt).ok()?;
        let msg = iov.get(first..first.checked_add(count)?)?;
        let start: usize = iov[..first].iter().map(|v| v.iov_len).sum();
        let len: usize = msg.iter().map(|v| v.iov_len).sum();
        Some(start..start + len)
    }
}

/// The protection of a reply from `tn_smbsrv_send_sealed()`.
#[derive(Debug)]
enum ReplySeal {
    Encrypt(Arc<Keys>),
    /// The keys and the byte range of each SMB2 message to sign.
    Sign(Vec<(Arc<Keys>, Range<usize>)>),
}

impl ReplySeal {
    /// Sign or encrypt the PDU in `buf`. False on failure.
    fn apply(&self, ops: &CryptoOps, buf: &mut [u8]) -> bool {
        match self {
            ReplySeal::Encrypt(keys) => encrypt_pdu(ops, keys, buf),
            ReplySeal::Sign(msgs) => msgs.iter().all(|(keys, at)| {
                buf.get_mut(at.clone())
                    .is_some_and(|msg| sign_msg(ops, keys, msg))
            }),
        }
    }
}

/// The `HostKey` of `key`. None for NULL.
fn host_key(poster: &Poster, key: *mut c_void) -> Option<HostKey> {
    (!key.is_null()).then(|| HostKey {
        key,
        poster: poster.clone(),
    })
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
    let poster = conn.poster();
    let keys = Keys {
        generation,
        sign: host_key(&poster, sign),
        encrypt: host_key(&poster, encrypt),
        decrypt: host_key(&poster, decrypt),
    };
    // On ENOTSUP, the drop of `keys` posts a KEY_FREE event for each key.
    let Some(ext) =
        conn.state().ext::<ConnExt>().filter(|e| e.crypto.is_some())
    else {
        return libc::ENOTSUP;
    };
    lock(&ext.keys).insert(session_id, Arc::new(keys));
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
    let Some(ext) = conn.state().ext::<ConnExt>() else {
        return;
    };
    let keys = lock(&ext.keys).remove(&session_id);
    drop(keys);
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
    let keys = conn
        .state()
        .ext::<ConnExt>()
        .and_then(|ext| ext.keys_of(session_id));
    match keys {
        Some(keys) if keys.generation == generation => {
            Arc::into_raw(keys).cast_mut()
        }
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
    // SAFETY: the caller transfers ownership of `pin`.
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
    // SAFETY: the caller transfers ownership of `encrypt`.
    let encrypt = unsafe { unpin(encrypt) };
    let sign = if sign.is_null() {
        &[]
    } else {
        // SAFETY: the caller passes `nsign` parts.
        unsafe { std::slice::from_raw_parts(sign, nsign) }
    };
    // This function owns the keys of every part. So the loop calls unpin()
    // for each part before this function can return an error.
    let mut msgs = Vec::with_capacity(sign.len());
    let mut err = 0;
    for part in sign {
        // SAFETY: the caller transfers ownership of the keys of the part.
        let keys = unsafe { unpin(part.keys) }.filter(|k| k.sign.is_some());
        match (keys, iov.and_then(|iov| part.range(iov))) {
            (Some(keys), Some(at)) => msgs.push((keys, at)),
            (None, _) => err = libc::ENOKEY,
            (Some(_), None) => err = libc::EINVAL,
        }
    }
    let Some(iov) = iov else {
        return libc::EINVAL;
    };
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    let ops = conn.state().ext::<ConnExt>().and_then(|ext| ext.crypto);
    let Some(ops) = ops else {
        return libc::ENOKEY;
    };
    if err != 0 {
        return err;
    }
    let seal = match (encrypt, sign.is_empty()) {
        (Some(keys), true) if keys.encrypt.is_some() => {
            ReplySeal::Encrypt(keys)
        }
        (None, false) => ReplySeal::Sign(msgs),
        _ => return libc::EINVAL,
    };
    // SAFETY: the caller keeps the lent vectors valid until TN_SMBROS_SENT.
    let (parts, any_lent) = unsafe { conn.parts(iov, lend_min, sent_cookie) };
    // SAFETY: the caller passes room for a bool.
    unsafe { lent.write(any_lent) };
    // The reactor runs the closure on its thread before it queues the reply
    // for sending. The closure replaces the parts with a signed or
    // encrypted copy. This drops the lent parts.
    conn.send_finished(
        parts,
        Box::new(move |parts: &mut Vec<PushPart>| {
            let size = parts.iter().map(|p| p.as_slice().len()).sum();
            let mut buf = Vec::with_capacity(size);
            for p in parts.iter() {
                buf.extend_from_slice(p.as_slice());
            }
            if !seal.apply(&ops, &mut buf) {
                return false;
            }
            *parts = vec![PushPart::Owned(buf)];
            true
        }),
    );
    0
}

#[cfg(test)]
mod tests {
    use super::{Seal, TN_SMBSRV_SEAL_NONE};

    #[test]
    fn seal_none_needs_no_keys() {
        // SAFETY: a NULL pin is allowed.
        let seal =
            unsafe { Seal::of(TN_SMBSRV_SEAL_NONE, std::ptr::null_mut()) };
        assert!(matches!(seal, Some(Seal::None)));
    }

    #[test]
    fn an_unknown_seal_is_refused() {
        for value in [3, -1] {
            // SAFETY: a NULL pin is allowed.
            let seal = unsafe { Seal::of(value, std::ptr::null_mut()) };
            assert!(seal.is_none());
        }
    }
}
