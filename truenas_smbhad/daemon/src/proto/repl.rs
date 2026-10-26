// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The protocol between the standby and the primary, on the internal link.
//!
//! The standby sends a `ReplRequest`. The primary replies with a
//! `ReplReply`. The primary does not reply to a `Poll` until it has data to
//! send or a heartbeat is due. Each `Poll` acknowledges every operation up
//! to its sequence number.

use super::{BootId, Node, Op, Record};
use crate::auth::{Nonce, Proof};
use serde::{Deserialize, Serialize};
use truenas_xdr::XdrUnion;

/// The first request on each connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplHello {
    /// The highest version that the standby speaks, `super::VERSION`.
    pub version: u32,
    /// The standby's node.
    pub node: Node,
    /// The standby's boot id.
    pub boot: BootId,
    /// The standby's random nonce.
    pub nonce: Nonce,
}

/// The reply to `ReplHello`. The primary sends its proof first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The version of the session: the lower of `super::VERSION` and the
    /// version in the `ReplHello`.
    pub version: u32,
    /// The primary's node.
    pub node: Node,
    /// The primary's random nonce.
    pub nonce: Nonce,
    /// `auth::proof(Side::Primary, ...)`.
    pub proof: Proof,
}

/// A chunk of a full resync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The primary's generation.
    pub generation: u64,
    /// The standby sets its copy's tag to this value after the last chunk.
    pub tag: u64,
    /// The node whose smbd wrote the records.
    pub writer_node: Node,
    /// The boot of that node.
    pub writer_boot: BootId,
    /// This is the first chunk. The standby clears its copy.
    pub first: bool,
    /// This is the last chunk. The copy is complete.
    pub last: bool,
    /// The sequence number at the snapshot point. The first batch starts at
    /// `seq + 1`.
    pub seq: u64,
    /// The chunk's records, in id order.
    pub records: Vec<Record>,
}

/// Operations that the primary applied after the snapshot point, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// Sequence number of the first operation.
    pub first_seq: u64,
    /// The operations.
    pub ops: Vec<Op>,
}

/// A message from the standby to the primary.
#[derive(XdrUnion, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ReplRequest {
    /// See `ReplHello`.
    Hello(ReplHello) = 1,
    /// `auth::proof(Side::Standby, ...)`.
    Prove(Proof) = 2,
    /// The highest sequence number that the standby applied, 0 for none. The
    /// first `Poll` after `Welcome` asks for a full resync.
    Poll(u64) = 3,
}

/// A message from the primary to the standby.
#[derive(XdrUnion, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ReplReply {
    /// See `Challenge`.
    Challenge(Challenge) = 1,
    /// The handshake is complete. The value is the primary's generation.
    Welcome(u64) = 2,
    /// See `Snapshot`.
    Snapshot(Snapshot) = 3,
    /// See `Batch`.
    Batch(Batch) = 4,
    /// The primary has nothing to send. The value is its current sequence
    /// number.
    Heartbeat(u64) = 5,
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::single_match_else
)]
mod tests {
    use super::*;
    use crate::proto::VERSION;
    use truenas_xdr::{from_bytes, to_bytes};

    #[test]
    fn every_request_and_reply_round_trips() {
        let requests = [
            ReplRequest::Hello(ReplHello {
                version: VERSION,
                node: Node::B,
                boot: [4; 16].into(),
                nonce: [5; 32].into(),
            }),
            ReplRequest::Prove([6; 32].into()),
            ReplRequest::Poll(99),
        ];
        for r in requests {
            assert_eq!(
                from_bytes::<ReplRequest>(&to_bytes(&r).unwrap()).unwrap(),
                r
            );
        }
        let replies = [
            ReplReply::Challenge(Challenge {
                version: VERSION,
                node: Node::A,
                nonce: [8; 32].into(),
                proof: [9; 32].into(),
            }),
            ReplReply::Welcome(3),
            ReplReply::Snapshot(Snapshot {
                generation: 3,
                tag: 12,
                writer_node: Node::A,
                writer_boot: [1; 16].into(),
                first: true,
                last: false,
                seq: 1000,
                records: vec![crate::proto::tests::record(1, 0, b"r")],
            }),
            ReplReply::Batch(Batch {
                first_seq: 1001,
                ops: vec![Op::Del(1)],
            }),
            ReplReply::Heartbeat(1001),
        ];
        for r in replies {
            assert_eq!(
                from_bytes::<ReplReply>(&to_bytes(&r).unwrap()).unwrap(),
                r
            );
        }
    }

    #[test]
    fn a_poll_is_its_discriminant_then_the_sequence_number() {
        let bytes = to_bytes(&ReplRequest::Poll(0x0102)).unwrap();
        assert_eq!(bytes, [0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 1, 2]);
    }
}
