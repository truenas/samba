// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The client of `truenas_smbhad` in smbd: the connection to the local
//! daemon, the record of a durable handle, the durable cookie of
//! `vfs_zfs_core` and the fence through the epoch file. smbd links the static
//! library and includes `include/truenas_smbhad_client.h`, see `ffi`.

pub mod conn;
pub mod cookie;
pub mod ffi;
pub mod record;

pub use conn::{Batch, Connection, Error};
