// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The socket layer of an SMB server on `io_uring`: one reactor thread and
//! ring per connection. `include/truenas_smbros.h` is the C interface.

#![allow(unsafe_code)]

// The modules with C functions come first, in the order of the header.
mod buf;
mod conn;
mod ctx;
mod send;

mod block;
mod hub;
mod list;
mod out;
mod pdu;
pub mod placement;
mod reactor;
mod recv;
mod ring;
mod shim;
pub mod sys;
mod transmit;
mod upper;

use std::sync::{Mutex, MutexGuard, PoisonError};

pub use block::{Block, FreeList, Pool, try_box};
pub use conn::Conn;
pub use ctx::{Ctx, InlineFn, TN_SMBROS_UPPER, TnSmbrosEvent};
pub use hub::{Hub, HubRef};
pub use list::{BoxList, Link, Linked, List, Msg, MsgKind, Node, Push, Stack};
pub use out::Out;
pub use pdu::{NBT_HDR_SIZE, Pdu};
pub use reactor::{
    Borrow, Config, Handler, Reactor, ReactorCell, Shared, TAG_OP, TAG_UPPER,
    run,
};
pub use ring::{Ring, Sqe};
pub use send::{drop_foreign, iov_of, make_out, send_out};
pub use shim::{Shim, ShimHandler, ShimState, release_out, split};
pub use upper::{EV_UPPER, ShimReactor, Upper, UpperVt, Verdict};

/// The C functions, for Rust callers and tests.
pub mod ffi {
    pub use crate::buf::{
        tn_smbros_buf_delegable, tn_smbros_buf_free, tn_smbros_buf_open,
        tn_smbros_buf_release,
    };
    pub use crate::conn::{
        tn_smbros_adopt, tn_smbros_close, tn_smbros_conn_register_self,
        tn_smbros_conn_root,
    };
    pub use crate::ctx::{
        TN_SMBROS_CLOSED, TN_SMBROS_PDU, TN_SMBROS_SENT, tn_smbros_ctx_ack,
        tn_smbros_ctx_fd, tn_smbros_ctx_free, tn_smbros_ctx_inline,
        tn_smbros_ctx_new, tn_smbros_ctx_wake, tn_smbros_next,
    };
    pub use crate::send::tn_smbros_send;
}

/// Lock `m`. Ignore poison from a panic.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
