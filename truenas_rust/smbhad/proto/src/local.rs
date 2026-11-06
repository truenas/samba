// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The protocol between smbd and the local daemon, on `smbd.sock`.
//!
//! smbd sends a `Request`. The daemon replies with a `Reply`. A connection
//! has at most one request that waits for a reply. The daemon does not reply
//! to a `Submit` with `SyncLevel::None` or to a `ForgetOwner`.

use super::{BootId, Node, Op, Owner, Protection, Record, SyncLevel};
use serde::{Deserialize, Serialize};
use truenas_xdr::{XdrEnum, XdrUnion};

/// The kind of smbd process that opens a connection.
#[derive(XdrEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Client {
    /// A session process.
    Worker = 1,
    /// The parent process. Only the parent can send `Rehydrate` and `Done`.
    Parent = 2,
    /// cleanupd. It reports smbd processes that exit uncleanly.
    Cleanupd = 3,
    /// The scavenger. It removes expired disconnected handles.
    Scavenger = 4,
}

/// The first request on each connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// `super::VERSION`.
    pub version: u32,
    /// The kind of smbd process.
    pub role: Client,
    /// The process that connects.
    pub owner: Owner,
}

/// Operations on the copy. The daemon applies them in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submit {
    /// When the daemon replies.
    pub sync: SyncLevel,
    /// The operations.
    pub ops: Vec<Op>,
}

/// A request for one page of a rehydration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rehydrate {
    /// 0 for the first page, else the `next_cursor` of the previous page.
    pub cursor: u64,
    /// Maximum size of the page's records, in encoded bytes.
    pub max_bytes: u32,
}

/// A message from smbd to the daemon.
#[derive(XdrUnion, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Request {
    /// See `Hello`.
    Hello(Hello) = 1,
    /// See `Submit`.
    Submit(Submit) = 2,
    /// Removes every record that this process still owns. The process exited
    /// uncleanly. With `unique_id` 0: every process with this pid, except a
    /// live process with this pid that connected (the kernel reused the pid).
    ForgetOwner(Owner) = 3,
    /// See `Rehydrate`.
    Rehydrate(Rehydrate) = 4,
    /// Ends the rehydration. The next generation becomes the copy.
    Done = 5,
}

/// The reply to `Hello`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloOk {
    /// `super::VERSION`.
    pub version: u32,
    /// A new value each time the daemon starts. A process that gets a new
    /// value submits all its handles again.
    pub instance: u64,
    /// Current protection.
    pub protection: Protection,
    /// Current epoch.
    pub epoch: u64,
    /// Path of the epoch file. smbd fences through this file if it cannot
    /// reach the daemon.
    pub epoch_file: String,
    /// This controller.
    pub node: Node,
}

/// The reply to a `Submit` with `SyncLevel::Local` or `SyncLevel::Remote`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Synced {
    /// Whether the standby's copy contains the submitted operations.
    pub protection: Protection,
    /// The epoch at the time of the reply.
    pub epoch: u64,
}

/// Where the copy in a rehydration comes from.
#[derive(XdrEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Origin {
    /// There is no valid copy to restore.
    None = 0,
    /// smbd on this controller wrote the records.
    Own = 1,
    /// The other controller sent the records.
    Replica = 2,
}

/// The reply to `Rehydrate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehydratePage {
    /// Where the copy comes from.
    pub origin: Origin,
    /// The current epoch.
    pub epoch: u64,
    /// The node whose smbd wrote the records.
    pub writer_node: Node,
    /// The boot of that node.
    pub writer_boot: BootId,
    /// Cursor for the next page.
    pub next_cursor: u64,
    /// This is the last page.
    pub last: bool,
    /// The page's records, in id order.
    pub records: Vec<Record>,
}

/// Why the daemon refused a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// An errno value.
    pub code: i32,
    /// The error text for the log.
    pub message: String,
}

/// A message from the daemon to smbd.
#[derive(XdrUnion, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Reply {
    /// See `HelloOk`.
    HelloOk(HelloOk) = 1,
    /// See `Synced`.
    Synced(Synced) = 2,
    /// See `RehydratePage`.
    RehydratePage(RehydratePage) = 4,
    /// The reply to `Done`. The value is the new generation.
    DoneOk(u64) = 5,
    /// See `Failure`.
    Error(Failure) = 99,
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
    use crate::VERSION;
    use truenas_xdr::{from_bytes, to_bytes};

    #[test]
    fn hello_has_the_layout_smbd_writes() {
        let hello = Request::Hello(Hello {
            version: VERSION,
            role: Client::Worker,
            owner: Owner {
                pid: 4242,
                unique_id: 0x1122_3344_5566_7788,
            },
        });
        let bytes = to_bytes(&hello).unwrap();
        #[rustfmt::skip]
        let want: &[u8] = &[
            0, 0, 0, 1,                                     // hello
            0, 0, 0, 1,                                     // version
            0, 0, 0, 1,                                     // worker
            0, 0, 0x10, 0x92,                               // pid 4242
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // unique_id
        ];
        assert_eq!(bytes, want);
        assert_eq!(from_bytes::<Request>(&bytes).unwrap(), hello);
    }

    #[test]
    fn done_is_a_bare_discriminant() {
        assert_eq!(to_bytes(&Request::Done).unwrap(), [0, 0, 0, 5]);
    }

    #[test]
    fn every_request_and_reply_round_trips() {
        let requests = [
            Request::Submit(Submit {
                sync: SyncLevel::Remote,
                ops: vec![
                    Op::Put(crate::tests::record(1, 10, b"x")),
                    Op::Del(2),
                ],
            }),
            Request::ForgetOwner(Owner {
                pid: 10,
                unique_id: 3,
            }),
            Request::Rehydrate(Rehydrate {
                cursor: 17,
                max_bytes: 1 << 20,
            }),
        ];
        for r in requests {
            assert_eq!(
                from_bytes::<Request>(&to_bytes(&r).unwrap()).unwrap(),
                r
            );
        }
        let replies = [
            Reply::HelloOk(HelloOk {
                version: VERSION,
                instance: 9,
                protection: Protection::Protected,
                epoch: 4,
                epoch_file: "/var/db/system/samba4/smbhad.epoch".to_owned(),
                node: Node::A,
            }),
            Reply::Synced(Synced {
                protection: Protection::Unprotected,
                epoch: 5,
            }),
            Reply::RehydratePage(RehydratePage {
                origin: Origin::Replica,
                epoch: 5,
                writer_node: Node::B,
                writer_boot: [2; 16].into(),
                next_cursor: 0,
                last: true,
                records: vec![crate::tests::record(3, 0, b"body")],
            }),
            Reply::DoneOk(2),
            Reply::Error(Failure {
                code: 13,
                message: "only the parent rehydrates".to_owned(),
            }),
        ];
        for r in replies {
            assert_eq!(from_bytes::<Reply>(&to_bytes(&r).unwrap()).unwrap(), r);
        }
    }
}
