// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The layer of smbd above the `truenas_smbros` shim. The
//! reactors sign, check, encrypt and decrypt PDUs with smbd's functions and
//! keys. They also do the file I/O of the READ, WRITE and FLUSH requests
//! that smbd gives them.

#![allow(unsafe_code)]

mod crypto;
mod delegate;
mod file;
mod pending;
mod wire;

use std::any::Any;
use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::{Arc, Mutex};

use truenas_ros::net::server::PushHandle;
use truenas_smbros::{ConnState, Ctx, TN_SMBROS_UPPER, Upper, Verdict, lock};

use crypto::{CryptoOps, Keys};
// The C interface has these constants.
pub use crypto::{
    TN_SMBSRV_DECRYPT_FAILED, TN_SMBSRV_DECRYPTED, TN_SMBSRV_SEAL_ENCRYPT,
    TN_SMBSRV_SEAL_NONE, TN_SMBSRV_SEAL_SIGN, TN_SMBSRV_SIGNED_OK,
};

/// An event kind of `tn_smbros_next()`. The last job of a file ended.
/// `cookie` is the cookie of `tn_smbsrv_file_new()`. See
/// `tn_smbsrv_file_busy()`.
pub const TN_SMBSRV_IDLE: c_int = TN_SMBROS_UPPER;
/// An event kind of `tn_smbros_next()`. `buf` is a key that the caller gave
/// to `tn_smbsrv_session_keys()`. No reactor uses the key now. The caller
/// frees it.
pub const TN_SMBSRV_KEY_FREE: c_int = TN_SMBROS_UPPER + 1;

/// The layer of smbd above the reactors. Each process has one.
#[derive(Debug)]
struct Layer {
    crypto: Option<CryptoOps>,
    /// The NTSTATUS of each errno.
    errmap: Arc<[u32]>,
}

/// The state of the layer for one connection.
#[derive(Debug)]
pub(crate) struct ConnExt {
    pub(crate) crypto: Option<CryptoOps>,
    pub(crate) errmap: Arc<[u32]>,
    /// The keys of the sessions on the connection, by session id.
    pub(crate) keys: Mutex<HashMap<u64, Arc<Keys>>>,
    /// The interim responses of the jobs on the connection.
    pub(crate) interims: Arc<pending::Interims>,
}

impl ConnExt {
    pub(crate) fn keys_of(&self, session_id: u64) -> Option<Arc<Keys>> {
        lock(&self.keys).get(&session_id).cloned()
    }
}

impl Upper for Layer {
    fn start(
        &self,
        _conn: &ConnState,
        push: &PushHandle,
    ) -> Option<Box<dyn Any + Send + Sync>> {
        // start() runs on the reactor thread of the new connection.
        if let Some(init) = self.crypto.and_then(|ops| ops.thread_init) {
            // SAFETY: tn_smbsrv_attach() requires functions that any
            // reactor thread can call.
            unsafe { init() };
        }
        Some(Box::new(ConnExt {
            crypto: self.crypto,
            errmap: Arc::clone(&self.errmap),
            keys: Mutex::new(HashMap::new()),
            interims: Arc::new(pending::Interims::new(
                self.crypto,
                push.clone(),
            )),
        }))
    }

    /// The timer of the interim responses, see pending.rs.
    fn fs_ops(&self) -> u32 {
        1
    }

    fn incoming(&self, conn: &ConnState, pdu: &mut [u8]) -> Verdict {
        let Some(ext) = conn.ext::<ConnExt>() else {
            return Verdict::default();
        };
        let (flags, status, tag) =
            crypto::open_pdu(ext, pdu).unwrap_or_default();
        Verdict {
            flags,
            status,
            tag,
            job: delegate::delegable(pdu, flags),
        }
    }
}

/// Attach this layer to the reactors of `ctx`. Call this one time, before
/// the first `tn_smbros_adopt()`. `ops` is the table of crypto functions or
/// NULL. `errmap` has the NTSTATUS of each errno below `len`. The reactors
/// use it for the error responses of jobs. They use
/// `NT_STATUS_UNSUCCESSFUL` if `errmap` has 0 or no value for the errno.
/// False if `ctx` has a layer already.
///
/// # Safety
///
/// `ctx` is from `tn_smbros_ctx_new()`. `ops` is NULL or a table of
/// functions that any reactor thread can call. `errmap` is NULL or has
/// `len` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_attach(
    ctx: *mut Ctx,
    ops: *const CryptoOps,
    errmap: *const u32,
    len: usize,
) -> bool {
    // SAFETY: the caller passes a live context and a table or NULL.
    let (ctx, crypto) = unsafe { (&*ctx, ops.as_ref().copied()) };
    let errmap: Arc<[u32]> = if errmap.is_null() {
        Arc::new([])
    } else {
        // SAFETY: the caller passes `len` values.
        unsafe { std::slice::from_raw_parts(errmap, len) }.into()
    };
    ctx.set_upper(Arc::new(Layer { crypto, errmap }))
}
