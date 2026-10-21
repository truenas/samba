// truenas_smbhad: durable SMB handle state for TrueNAS HA.
//
// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Replicates every durable handle that smbd holds on the active controller
//! to the memory of the standby controller.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod daemon;
pub use truenas_smbhad_proto::epoch;
pub mod ids;
pub mod notify;
pub mod primary;
pub mod proto;
pub mod role;
pub mod serve;
pub mod standby;
pub mod store;
