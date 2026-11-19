// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! One adopted connection, and the identities in the ring of its reactor.
//! The reactor and the owner share the state of the connection.

use std::any::Any;
use std::collections::VecDeque;
use std::ffi::c_int;
use std::os::fd::BorrowedFd;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;

use truenas_ros::net::server::{PushHandle, ShutdownHandle};
use truenas_ros::uring_fs::SelfRegistrar;

use crate::ctx::{Ctx, Poster, Reactor, Shared};
use crate::lock;
use crate::reactor::{
    errno_of, force_async, reactor, reactor_signals, restore_signals,
};
use crate::upper::Job;

/// Jobs from the owner that the reactor has not started.
#[derive(Debug, Default)]
pub(crate) struct Jobs {
    /// The jobs in the order of their redeliveries.
    pub(crate) queue: VecDeque<Box<dyn Job>>,
    /// True after the reactor stopped. Then `Conn::delegate()` refuses new
    /// jobs.
    pub(crate) stopped: bool,
}

/// What the owner and the reactor of one connection share.
pub struct ConnState {
    pub(crate) cookie: u64,
    /// True after the owner closes the connection.
    pub(crate) closed: AtomicBool,
    /// The number of PDUs of this connection in the event queue.
    pub(crate) queued: AtomicUsize,
    /// True if the owner can give jobs to the reactor.
    pub(crate) delegate: bool,
    pub(crate) jobs: Mutex<Jobs>,
    /// Sends used bodies back to the reactor for its pool.
    pub(crate) back: mpsc::Sender<Vec<u8>>,
    /// Registers the credentials of a calling thread in the ring of the
    /// reactor. Empty until the reactor has created its ring.
    pub(crate) creds: OnceLock<SelfRegistrar>,
    /// The identity of root in the ring. 0 until the reactor registers it.
    pub(crate) root: AtomicU16,
    /// The value that `Upper::start()` returned.
    pub(crate) ext: OnceLock<Box<dyn Any + Send + Sync>>,
}

impl std::fmt::Debug for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnState")
            .field("cookie", &self.cookie)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl ConnState {
    /// The state of the upper layer for this connection.
    pub fn ext<T: Any>(&self) -> Option<&T> {
        self.ext.get()?.downcast_ref()
    }
}

/// One adopted connection, from `tn_smbros_adopt()`.
pub struct Conn {
    pub(crate) state: Arc<ConnState>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) push: PushHandle,
    stop: ShutdownHandle,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Conn {
    pub fn state(&self) -> &ConnState {
        &self.state
    }

    pub fn poster(&self) -> Poster {
        Poster(Arc::clone(&self.shared))
    }
}

/// Serve the connected socket `sock` on a new reactor thread. The reactor
/// uses a duplicate of `sock`. The caller still owns `sock`.
/// `max_in_flight` bounds the PDUs in the queue, the PDUs that can still
/// get a job and the jobs that run. With `delegate`, the caller can give
/// the reactor a job for a PDU. The layer above the shim has the function
/// for that. A file read of a job of `async_read_min` bytes or more carries
/// `IOSQE_ASYNC`. A hot read on ZFS does not sleep, so without the flag one
/// io-wq worker runs all such reads of the ring. `async_write_min` does the
/// same for writes. A flagged write skips the kernel's queue for its file,
/// so the writes of one file can run at the same time. `usize::MAX` flags
/// none. `truenas_ros` has one floor, so the smaller one applies to both.
/// The reactor thread is named `smbros-<n>`, numbered from 0 in each
/// process.
/// NULL on failure, with the errno in `*err` if `err` is not NULL.
///
/// # Safety
///
/// `ctx` is a live context from `tn_smbros_ctx_new()`. `sock` is an open
/// descriptor. `err` is NULL or writable.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn tn_smbros_adopt(
    ctx: *mut Ctx,
    sock: c_int,
    cookie: u64,
    max_in_flight: u32,
    delegate: bool,
    async_read_min: usize,
    async_write_min: usize,
    err: *mut c_int,
) -> *mut Conn {
    let fail = |e: c_int| {
        if !err.is_null() {
            // SAFETY: the caller passes NULL or room for an int.
            unsafe { err.write(e) };
        }
        ptr::null_mut()
    };
    // SAFETY: the caller passes a live context.
    let ctx = unsafe { &*ctx };
    let shared = Arc::clone(&ctx.shared);
    if sock < 0 {
        return fail(libc::EBADF);
    }
    // SAFETY: the caller keeps the descriptor open during the call.
    let dup = unsafe { BorrowedFd::borrow_raw(sock) }.try_clone_to_owned();
    let sock = match dup {
        Ok(fd) => fd,
        Err(e) => return fail(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let (back, back_rx) = mpsc::channel();
    let state = Arc::new(ConnState {
        cookie,
        closed: AtomicBool::new(false),
        queued: AtomicUsize::new(0),
        delegate,
        jobs: Mutex::new(Jobs::default()),
        back,
        creds: OnceLock::new(),
        root: AtomicU16::new(0),
        ext: OnceLock::new(),
    });
    let (tx, rx) = mpsc::sync_channel(1);
    let st = Arc::clone(&state);
    let conn_shared = Arc::clone(&shared);
    let max_in_flight = usize::try_from(max_in_flight).unwrap_or(usize::MAX);
    let force = force_async(async_read_min, async_write_min);
    let name =
        format!("smbros-{}", ctx.adopted.fetch_add(1, Ordering::Relaxed));
    // The reactor gets its signal mask when it starts. So no signal goes to
    // it before it can block the signal.
    let old_mask = reactor_signals();
    let spawned = thread::Builder::new().name(name).spawn(move || {
        reactor(&shared, &st, sock, max_in_flight, force, back_rx, &tx);
    });
    restore_signals(&old_mask);
    let Ok(thread) = spawned else {
        return fail(libc::EAGAIN);
    };
    match rx.recv() {
        Ok(Ok((push, stop))) => {
            let mut reactors = lock(&ctx.reactors);
            // A thread that ended needs no join.
            reactors.retain(|r| !r.thread.is_finished());
            reactors.push(Reactor {
                stop: stop.clone(),
                thread,
            });
            drop(reactors);
            Box::into_raw(Box::new(Conn {
                state,
                shared: conn_shared,
                push,
                stop,
            }))
        }
        // The reactor returns after it reports the failure.
        Ok(Err(e)) => {
            let _ = thread.join();
            fail(e)
        }
        Err(_) => {
            let _ = thread.join();
            fail(libc::EIO)
        }
    }
}

/// Stop the reactor of `conn` and free `conn`. After that,
/// `tn_smbros_next()` returns no PDU or CLOSED event of `conn`.
///
/// # Safety
///
/// `conn` is NULL or a connection from `tn_smbros_adopt()`. The caller does
/// not use `conn` after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_close(conn: *mut Conn) {
    if conn.is_null() {
        return;
    }
    // SAFETY: the caller passes a connection from tn_smbros_adopt() and
    // does not use it again.
    let conn = unsafe { Box::from_raw(conn) };
    conn.state.closed.store(true, Ordering::Relaxed);
    conn.stop.shutdown();
}

/// The identity of root on `conn`. An identity is an `io_uring` personality
/// in the ring of a reactor. The kernel does the file I/O of a job with the
/// credentials of one identity. An identity is a number other than 0. It is
/// valid only for its own `conn`.
///
/// The reactor registers root with the credentials of the thread that
/// called `tn_smbros_adopt()`. So call `tn_smbros_adopt()` as root.
///
/// # Safety
///
/// `conn` is a live connection from `tn_smbros_adopt()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_conn_root(conn: *const Conn) -> u16 {
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    conn.state.root.load(Ordering::Acquire)
}

/// Register the current credentials of the calling thread as an identity
/// on `conn`. Any thread can call this. The identity does not change when
/// the thread changes its credentials later. 0 on failure, with the errno
/// in `*err` if `err` is not NULL.
///
/// # Safety
///
/// `conn` is a live connection from `tn_smbros_adopt()`. `err` is NULL or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_conn_register_self(
    conn: *const Conn,
    err: *mut c_int,
) -> u16 {
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    let res = match conn.state.creds.get() {
        Some(reg) => reg.register_self().map_err(|e| errno_of(&e)),
        None => Err(libc::ENOTCONN),
    };
    match res {
        Ok(who) => who.id(),
        Err(e) => {
            if !err.is_null() {
                // SAFETY: the caller passes NULL or room for an int.
                unsafe { err.write(e) };
            }
            0
        }
    }
}
