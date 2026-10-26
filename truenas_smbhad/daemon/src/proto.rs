// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The messages of the daemon: the shared messages of
//! `truenas_smbhad_proto`, and the replication protocol between the two
//! daemons.

pub use truenas_smbhad_proto::*;

pub mod repl;

#[cfg(test)]
pub(crate) mod tests {
    use super::{Owner, Record};
    use truenas_xdr::VarOpaque;

    /// A record of share "data" with unique id 7, for the unit tests
    pub(crate) fn record(id: u64, pid: u32, body: &[u8]) -> Record {
        Record {
            id,
            share: "data".to_owned(),
            owner: Owner { pid, unique_id: 7 },
            flags: 0,
            body: VarOpaque(body.to_vec()),
        }
    }
}
