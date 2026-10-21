// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire formats.
//!
//! Each message is a 4-byte big-endian length and an XDR body (RFC 4506).
//! `truenas_xdr` encodes the body. smbd uses these messages through the
//! client library (`truenas_smbhad_client`). The tests check the bytes.

#![forbid(unsafe_code)]

pub mod epoch;
pub mod local;

use serde::{Deserialize, Serialize};
use truenas_xdr::{FixedOpaque, VarOpaque, XdrEnum, XdrUnion};

/// Version of both protocols. Each side sends it in its first message.
pub const VERSION: u32 = 1;

/// The oldest replication version that a daemon accepts. The primary uses
/// the lower version of the two daemons, so the controllers of an HA pair
/// can run different versions during an upgrade. A new version must keep
/// the messages of the older versions.
pub const MIN_VERSION: u32 = 1;

/// Largest message body, in bytes, that each side accepts.
pub const MAX_FRAME: usize = 16 << 20;

/// An HA controller: its slot in the chassis, as `failover.node` of the
/// middleware reports it.
#[derive(XdrEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Node {
    /// Node A.
    A = 1,
    /// Node B.
    B = 2,
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Node::A => "A",
            Node::B => "B",
        })
    }
}

impl std::str::FromStr for Node {
    type Err = String;

    fn from_str(s: &str) -> Result<Node, String> {
        match s {
            "A" => Ok(Node::A),
            "B" => Ok(Node::B),
            _ => Err(format!("node {s:?}: not A or B")),
        }
    }
}

/// The kernel's boot id in binary.
pub type BootId = FixedOpaque<16>;

/// The smbd process that holds a handle. A disconnected handle has pid 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    /// Process id.
    pub pid: u32,
    /// `server_id.unique_id`. It identifies the process if the kernel
    /// reuses its pid.
    pub unique_id: u64,
}

impl Owner {
    /// The owner of a disconnected durable handle.
    pub const DISCONNECTED: Owner = Owner {
        pid: 0,
        unique_id: 0,
    };

    /// Whether `other` is this process. A `unique_id` of 0 matches any
    /// process with the same pid: cleanupd knows only the pid. Pid 0 matches
    /// nothing.
    pub fn matches(self, other: Owner) -> bool {
        self.pid != 0
            && self.pid == other.pid
            && (self.unique_id == 0 || self.unique_id == other.unique_id)
    }
}

/// One durable handle, as smbd records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The open's persistent id.
    pub id: u64,
    /// Share name, at most 256 bytes.
    pub share: String,
    /// The process that holds the handle.
    pub owner: Owner,
    /// smbd's flags, opaque to the daemon.
    pub flags: u32,
    /// smbd's XDR record of the handle, opaque to the daemon.
    pub body: VarOpaque,
}

/// An operation that changes the copy.
#[derive(XdrUnion, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Op {
    /// Adds the record, or replaces the record with the same id.
    Put(Record) = 1,
    /// Removes the record with this id.
    Del(u64) = 2,
}

/// When the daemon replies to a `Submit`.
#[derive(XdrEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum SyncLevel {
    /// No reply.
    None = 0,
    /// The daemon replies after it applies the operations to its copy.
    Local = 1,
    /// The daemon replies after the standby acknowledges the operations, or
    /// after it fences the standby's copy.
    Remote = 2,
}

/// Whether the standby's copy contains the operations that smbd submitted.
#[derive(XdrEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Protection {
    /// No replication. The system is not HA, or the role is `none`.
    None = 0,
    /// The standby's copy is not protected. In a `Synced` reply, the copy is
    /// fenced. In `HelloOk`, the fence can still be in progress.
    Unprotected = 1,
    /// The standby's copy is current and restorable.
    Protected = 2,
}

/// Largest record body that the daemon keeps. smbd sends a delete for a
/// larger record: the standby then does not restore the handle.
pub const MAX_RECORD_BYTES: usize = 64 << 10;

/// Encodes `v` as one framed XDR message. `None` if `v` has no encoding or
/// is larger than `MAX_FRAME`.
pub fn encode<T: Serialize>(v: &T) -> Option<Vec<u8>> {
    frame(&truenas_xdr::to_bytes(v).ok()?)
}

/// Adds the length prefix to an encoded body. Returns `None` if `body` is
/// larger than `MAX_FRAME`.
pub fn frame(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() > MAX_FRAME {
        return None;
    }
    let len = u32::try_from(body.len()).ok()?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Some(out)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) mod tests {
    use super::*;
    use truenas_xdr::{from_bytes, to_bytes};

    pub(crate) fn record(id: u64, pid: u32, body: &[u8]) -> Record {
        Record {
            id,
            share: "data".to_owned(),
            owner: Owner { pid, unique_id: 7 },
            flags: 0,
            body: VarOpaque(body.to_vec()),
        }
    }

    #[test]
    fn a_put_is_its_discriminant_then_the_record() {
        let bytes = to_bytes(&Op::Put(record(0x0102, 9, b"abc"))).unwrap();
        #[rustfmt::skip]
        let want: &[u8] = &[
            0, 0, 0, 1,                         // put
            0, 0, 0, 0, 0, 0, 1, 2,             // id
            0, 0, 0, 4, b'd', b'a', b't', b'a', // share
            0, 0, 0, 9,                         // owner.pid
            0, 0, 0, 0, 0, 0, 0, 7,             // owner.unique_id
            0, 0, 0, 0,                         // flags
            0, 0, 0, 3, b'a', b'b', b'c', 0,    // body, padded
        ];
        assert_eq!(bytes, want);
        assert_eq!(
            from_bytes::<Op>(&bytes).unwrap(),
            Op::Put(record(0x0102, 9, b"abc"))
        );
    }

    #[test]
    fn a_delete_is_its_discriminant_then_the_id() {
        let bytes = to_bytes(&Op::Del(5)).unwrap();
        assert_eq!(bytes, [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 5]);
    }

    #[test]
    fn a_node_is_an_xdr_enum_and_parses_from_a_or_b() {
        assert_eq!(to_bytes(&Node::A).unwrap(), [0, 0, 0, 1]);
        assert_eq!(to_bytes(&Node::B).unwrap(), [0, 0, 0, 2]);
        assert!(from_bytes::<Node>(&[0, 0, 0, 3]).is_err());
        assert_eq!("A".parse::<Node>(), Ok(Node::A));
        assert_eq!("B".parse::<Node>(), Ok(Node::B));
        assert!("MANUAL".parse::<Node>().is_err());
        assert!("a".parse::<Node>().is_err());
    }

    #[test]
    fn a_frame_is_a_big_endian_length_then_the_body() {
        assert_eq!(frame(b"xy").unwrap(), [0, 0, 0, 2, b'x', b'y']);
        assert!(frame(&vec![0; MAX_FRAME + 1]).is_none());
    }
}
