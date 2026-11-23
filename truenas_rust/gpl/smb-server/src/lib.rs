// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The layer of smbd above the `truenas_smbros` shim: crypto and file I/O
//! on the reactors. `include/truenas_smb_server.h` is the C interface.

#![allow(unsafe_code)]

// The modules with C functions come first, in the order of the header.
mod crypto;
mod delegate;
mod file;

mod job;
mod keys;
mod pending;
mod plan;
mod upper;
mod wire;

use std::ffi::c_int;
use std::sync::Arc;

use truenas_smbros::{Ctx, TN_SMBROS_UPPER};

// The C interface has these constants and types.
pub use crypto::{
    CryptoOps, SignPart, TN_SMBSRV_DECRYPT_FAILED, TN_SMBSRV_DECRYPTED,
    TN_SMBSRV_SEAL_ENCRYPT, TN_SMBSRV_SEAL_NONE, TN_SMBSRV_SEAL_SIGN,
    TN_SMBSRV_SIGNED_OK,
};
pub use delegate::Io;
pub use file::OpenFile;
pub use keys::{KeyCache, KeyTable, Keys};
use upper::{Global, LAYER, Layer};

/// The C functions, for Rust callers and tests.
pub mod ffi {
    pub use crate::crypto::{
        tn_smbsrv_keys_pin, tn_smbsrv_keys_unpin, tn_smbsrv_send_sealed,
        tn_smbsrv_session_drop, tn_smbsrv_session_keys,
    };
    pub use crate::delegate::tn_smbsrv_delegate;
    pub use crate::file::{
        tn_smbsrv_file_busy, tn_smbsrv_file_close, tn_smbsrv_file_hold,
        tn_smbsrv_file_new, tn_smbsrv_file_seq_bump, tn_smbsrv_file_seq_old,
        tn_smbsrv_file_take_pos, tn_smbsrv_hold_free, tn_smbsrv_hold_seq,
    };
    pub use crate::tn_smbsrv_attach;
}

/// An event kind of `tn_smbros_next()`. The last job of a file ended.
/// `cookie` is the cookie of `tn_smbsrv_file_new()`. See
/// `tn_smbsrv_file_busy()`.
pub const TN_SMBSRV_IDLE: c_int = TN_SMBROS_UPPER;
/// An event kind of `tn_smbros_next()`. `buf` is a key that the caller gave
/// to `tn_smbsrv_session_keys()`. No reactor uses the key now. The caller
/// frees it.
pub const TN_SMBSRV_KEY_FREE: c_int = TN_SMBROS_UPPER + 1;

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
    let (ctx, ops) = unsafe { (&*ctx, ops.as_ref().copied()) };
    let errmap: Arc<[u32]> = if errmap.is_null() {
        Arc::from([])
    } else {
        // SAFETY: the caller passes `len` values.
        unsafe { std::slice::from_raw_parts(errmap, len) }.into()
    };
    ctx.attach::<Layer>(&LAYER, Global { ops, errmap })
}
