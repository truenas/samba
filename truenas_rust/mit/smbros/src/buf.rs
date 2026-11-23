// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The C functions for the buffer of a PDU event.

use std::ffi::c_void;
use std::sync::atomic::Ordering;

use crate::pdu::{Pdu, pdu_free};

/// Free the buffer of a PDU event.
///
/// # Safety
///
/// `buf` is NULL or the `buf` of a PDU event. The caller does not use it
/// after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_free(buf: *mut c_void) {
    if buf.is_null() {
        return;
    }
    // SAFETY: the caller gives up the buffer, a leaked box.
    pdu_free(unsafe { Box::from_raw(buf.cast::<Pdu>()) });
}

/// True if `tn_smbros_close()` has not run for the connection of `buf`.
/// False if `buf` is NULL.
///
/// # Safety
///
/// `buf` is NULL or the live `buf` of a PDU event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_open(buf: *const c_void) -> bool {
    // SAFETY: the caller passes NULL or a live buffer.
    unsafe { buf.cast::<Pdu>().as_ref() }
        .is_some_and(|p| !p.conn().closed.load(Ordering::Acquire))
}

/// True if the PDU of `buf` can still get a job. The layer above the shim
/// selects such PDUs on a connection adopted with `delegate`. Such a PDU
/// counts against `max_in_flight` until the caller gives it a job or
/// releases it.
///
/// # Safety
///
/// `buf` is NULL or the live `buf` of a PDU event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_delegable(buf: *const c_void) -> bool {
    // SAFETY: the caller passes NULL or a live buffer.
    unsafe { buf.cast::<Pdu>().as_ref() }.is_some_and(|p| p.deferred)
}

/// Release the PDU of `buf` without a job. Call this as soon as the caller
/// knows that the PDU gets no job. Then the reactor can read more PDUs.
/// `tn_smbros_buf_free()` also releases the PDU.
///
/// # Safety
///
/// `buf` is NULL or the live `buf` of a PDU event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_release(buf: *mut c_void) {
    // SAFETY: the caller passes NULL or a live buffer that it owns.
    if let Some(p) = unsafe { buf.cast::<Pdu>().as_mut() }
        && p.deferred
    {
        p.deferred = false;
        p.conn().release_slot();
    }
}
