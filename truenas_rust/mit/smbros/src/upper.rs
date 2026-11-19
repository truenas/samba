// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The interface for the layer of the SMB server above the shim. The shim
//! reads only the framing of a PDU, not its content.

use std::any::Any;
use std::ffi::{c_int, c_void};
use std::fmt::Debug;

use truenas_ros::net::server::{BodyRecycler, Deferred, PushHandle};
use truenas_ros::uring_fs::FsConn;

use crate::conn::ConnState;

/// The result of `Upper::incoming()` for a new PDU.
#[derive(Debug, Clone, Copy, Default)]
pub struct Verdict {
    /// The owner gets `flags`, `status` and `tag` in the event of the PDU.
    pub flags: u32,
    pub status: u32,
    pub tag: u64,
    /// True if the owner can give the reactor a job for the PDU. The shim
    /// ignores it on a connection without `delegate`.
    pub job: bool,
}

/// The layer of the server above the shim. A reactor calls it on its
/// thread.
pub trait Upper: Debug + Send + Sync {
    /// Runs on the thread of a new connection before `tn_smbros_adopt()`
    /// returns. `push` sends PDUs on the connection, in order with the
    /// replies of jobs. `ConnState::ext()` returns the result.
    fn start(
        &self,
        conn: &ConnState,
        push: &PushHandle,
    ) -> Option<Box<dyn Any + Send + Sync>>;

    /// Runs for each new PDU before the owner gets it. The layer can change
    /// the PDU in place.
    fn incoming(&self, conn: &ConnState, pdu: &mut [u8]) -> Verdict;

    /// The file ops that the layer keeps on the ring of a connection with
    /// `delegate`, besides the one of each job.
    fn fs_ops(&self) -> u32 {
        0
    }
}

/// Work for a PDU. The owner gives it to the reactor with
/// `Conn::delegate()`.
pub trait Job: Debug + Send {
    /// Runs on the reactor thread of `conn`. `fs` does file I/O on the ring
    /// of the reactor. The job answers `reply`.
    fn run(
        self: Box<Self>,
        conn: &ConnState,
        fs: &mut FsConn<'_>,
        reply: Deferred,
        recycler: Option<BodyRecycler>,
    );
}

/// An event of the upper layer for the owner thread.
pub trait Note: Debug + Send {
    /// Runs on the owner thread in `tn_smbros_next()`. Returns the kind, the
    /// cookie and the `buf` of the event. If it returns `None`,
    /// `tn_smbros_next()` drops the event.
    fn take(self: Box<Self>) -> Option<(c_int, u64, *mut c_void)>;
}
