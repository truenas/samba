// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! A shim between an SMB server and `truenas_ros`. A reactor thread with its
//! own ring reads and sends the PDUs of one connection.
//! `include/truenas_smbros.h` is the C interface.

#![allow(unsafe_code)]

mod buf;
mod conn;
mod ctx;
mod reactor;
mod send;
mod upper;

use std::sync::{Mutex, MutexGuard, PoisonError};

pub use buf::Buf;
pub use conn::{Conn, ConnState};
pub use ctx::{Ctx, Poster, TN_SMBROS_UPPER, TnSmbrosEvent};
pub use reactor::{NBT_HDR_SIZE, PLACE_MIN, errno_of};
pub use send::{iov_gather, iov_of};
pub use upper::{Job, Note, Upper, Verdict};

/// Lock `m`. Ignore poison from a panic.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
