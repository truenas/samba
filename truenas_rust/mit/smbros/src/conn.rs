// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! One adopted connection. The owner, the reactor and the PDUs that it gave
//! out each hold a reference.

use std::any::TypeId;
use std::cell::UnsafeCell;
use std::ffi::c_int;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::ptr::{self, NonNull};
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, Ordering,
};
use std::sync::mpsc;
use std::thread;

use crate::ctx::{Ctx, Thr};
use crate::hub::{EV_CLOSED, Hub, HubRef, hub_ref, hub_unref};
use crate::list::{Node, Stack};
use crate::reactor::{Borrow, Config, ReactorCell, Shared};
use crate::shim::ShimState;
use crate::sys;
use crate::upper::{Upper, UpperVt};

/// The bytes of blocks that a reactor keeps for reuse.
const BUDGET: usize = 64 << 20;
/// The glibc default. Inline runs of smbd use this stack.
const STACK_SIZE: usize = 8 << 20;

/// One adopted connection, from `tn_smbros_adopt()`.
#[derive(Debug)]
pub struct Conn {
    pub(crate) refs: AtomicU32,
    pub(crate) sh: Shared,
    hub: NonNull<Hub>,
    pub(crate) cookie: u64,
    pub(crate) delegate: bool,
    /// True after the owner closed the connection.
    pub(crate) closed: AtomicBool,
    /// The PDUs of this connection in the event queue.
    pub(crate) queued: AtomicU32,
    pub(crate) root: AtomicU16,
    /// PDUs that other threads freed, for the reactor to reuse.
    pub(crate) ret: Stack,
    closed_ev: UnsafeCell<Node>,
    pub(crate) closed_err: AtomicI32,
    /// A forced file I/O of `force_min` bytes or more gets `IOSQE_ASYNC`.
    pub force_read: bool,
    pub force_write: bool,
    pub force_min: usize,
    /// The reactor while it runs. Only its own thread uses it.
    cell: AtomicPtr<ReactorCell<ShimState>>,
    vt: &'static UpperVt,
    ext_type: TypeId,
    /// The state of the layer above, a leaked box.
    ext: NonNull<()>,
}

// SAFETY: shared fields are atomic, immutable, Sync or used by one thread.
unsafe impl Send for Conn {}
// SAFETY: as for Send.
unsafe impl Sync for Conn {}

impl Drop for Conn {
    fn drop(&mut self) {
        // SAFETY: the box is from vt.ext_new(), and this is its last use.
        unsafe { (self.vt.ext_free)(self.ext) };
        // SAFETY: the connection had a reference to the hub.
        unsafe { hub_unref(self.hub) };
    }
}

impl Conn {
    pub fn hub(&self) -> &Hub {
        // SAFETY: the connection keeps a reference to its hub.
        unsafe { self.hub.as_ref() }
    }

    /// A counted reference to the hub of the connection.
    pub fn hub_ref(&self) -> HubRef {
        HubRef::new(self.hub)
    }

    pub fn cookie(&self) -> u64 {
        self.cookie
    }

    /// True after the owner closed the connection.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// The state of the layer `U`, if the connection has that layer.
    #[inline]
    pub fn ext<U: Upper>(&self) -> Option<&U::Ext> {
        if self.ext_type != TypeId::of::<U>() {
            return None;
        }
        // SAFETY: the type matches, so `ext` is a box of U::Ext.
        Some(unsafe { self.ext.cast::<U::Ext>().as_ref() })
    }

    /// The reactor of the connection if the caller runs on it.
    ///
    /// # Safety
    ///
    /// The caller holds no borrow of the reactor. A C function that smbd
    /// calls holds none at its start.
    #[inline]
    pub unsafe fn local(&self) -> Option<Borrow<'_, ShimState>> {
        if !self.sh.on_thread() {
            return None;
        }
        let cell = self.cell.load(Ordering::Relaxed);
        if cell.is_null() {
            return None;
        }
        // SAFETY: the cell lives while set, and the caller holds no borrow.
        Some(unsafe { (*cell).borrow() })
    }

    pub(crate) fn set_cell(&self, cell: &ReactorCell<ShimState>) {
        self.cell
            .store(ptr::from_ref(cell).cast_mut(), Ordering::Relaxed);
    }

    pub(crate) fn clear_cell(&self) {
        self.cell.store(ptr::null_mut(), Ordering::Relaxed);
    }

    /// Release an in-flight slot of the reactor.
    pub fn release_slot(&self) {
        // SAFETY: the callers hold no borrow of the reactor.
        match unsafe { self.local() } {
            Some(mut r) => r.release(),
            None => self.sh.release(),
        }
    }

    /// Give the reactor a message. False if it stopped. Then the caller
    /// keeps `m`.
    ///
    /// # Safety
    ///
    /// As for `Shared::post()`.
    pub unsafe fn post(&self, m: NonNull<crate::list::Msg>) -> bool {
        // SAFETY: as the caller says.
        unsafe { self.sh.post(m) }
    }

    pub(crate) fn closed_ev(&self) -> NonNull<Node> {
        // SAFETY: UnsafeCell::get() is never null.
        unsafe { NonNull::new_unchecked(self.closed_ev.get()) }
    }

    /// # Safety
    ///
    /// `n` is the `closed_ev` of a connection.
    pub(crate) unsafe fn from_closed_ev(n: NonNull<Node>) -> NonNull<Conn> {
        // SAFETY: as the caller says.
        unsafe {
            n.byte_sub(std::mem::offset_of!(Conn, closed_ev))
                .cast::<Conn>()
        }
    }
}

pub(crate) fn conn_ref(c: NonNull<Conn>) {
    // SAFETY: the caller has a reference, so the connection is live.
    unsafe { c.as_ref() }.refs.fetch_add(1, Ordering::Relaxed);
}

/// The last reference frees the connection.
///
/// # Safety
///
/// The caller has a reference and does not use it after this call.
pub(crate) unsafe fn conn_unref(c: NonNull<Conn>) {
    // SAFETY: as the caller says.
    if unsafe { c.as_ref() }.refs.fetch_sub(1, Ordering::AcqRel) == 1 {
        // SAFETY: no other reference is left. The box is from adopt.
        drop(unsafe { Box::from_raw(c.as_ptr()) });
    }
}

/// What `tn_smbros_adopt()` gives the thread of a new reactor.
#[derive(Debug)]
pub(crate) struct Start {
    pub(crate) conn: NonNull<Conn>,
    pub(crate) cfg: Config,
    pub(crate) sock: OwnedFd,
    /// 0 when the reactor runs, else the errno of its failure.
    pub(crate) ready: mpsc::SyncSender<c_int>,
}

// SAFETY: the connection is Sync, and the thread gets its own reference.
unsafe impl Send for Start {}

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
/// none. One floor, the smaller one, applies to both.
/// A reply of `zero_copy_min` bytes or more goes out without the kernel's
/// copy. The kernel then reads it until the peer acknowledges it, so
/// `TN_SMBROS_SENT` for its lent vectors comes only then. `usize::MAX`
/// copies every reply. The reactor thread is named `smbros-<n>`, numbered
/// from 0 in each process.
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
    zero_copy_min: usize,
    err: *mut c_int,
) -> *mut Conn {
    let fail = |e: c_int| {
        if !err.is_null() {
            // SAFETY: the caller passes NULL or room for an int.
            unsafe { err.write(e) };
        }
        ptr::null_mut()
    };
    if sock < 0 {
        return fail(libc::EBADF);
    }
    // SAFETY: the caller passes a live context.
    let ctx = unsafe { &*ctx };
    ctx.reap_done();
    // SAFETY: the caller keeps the descriptor open during the call.
    let dup = unsafe { BorrowedFd::borrow_raw(sock) }.try_clone_to_owned();
    let dup = match dup {
        Ok(fd) => fd,
        Err(e) => return fail(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let sh = match Shared::new() {
        Ok(sh) => sh,
        Err(e) => return fail(e),
    };
    let hub = ctx.hub_ptr();
    // SAFETY: the context keeps the hub live.
    let vt = unsafe { hub.as_ref() }.vt();
    hub_ref(hub);
    let conn = Box::new(Conn {
        // The owner, the reactor and the record of the thread.
        refs: AtomicU32::new(3),
        sh,
        hub,
        cookie,
        delegate,
        closed: AtomicBool::new(false),
        queued: AtomicU32::new(0),
        root: AtomicU16::new(0),
        ret: Stack::new(),
        closed_ev: UnsafeCell::new(Node::new(EV_CLOSED)),
        closed_err: AtomicI32::new(0),
        // One floor applies to both classes.
        force_read: async_read_min != usize::MAX,
        force_write: async_write_min != usize::MAX,
        force_min: async_read_min.min(async_write_min),
        cell: AtomicPtr::new(ptr::null_mut()),
        vt,
        ext_type: (vt.id)(),
        // SAFETY: as above.
        ext: (vt.ext_new)(unsafe { hub.as_ref() }),
    });
    let c = NonNull::from(Box::leak(conn));
    let cfg = Config {
        max_inflight: max_in_flight.max(1),
        zc_min: zero_copy_min,
        zc_max_pinned: zero_copy_min.max(64 << 20),
        budget: BUDGET,
        ..Config::default()
    };
    let (tx, rx) = mpsc::sync_channel(1);
    let start = Start {
        conn: c,
        cfg,
        sock: dup,
        ready: tx,
    };
    let name = format!("smbros-{}", ctx.next_index());
    let main = vt.main;
    // The thread starts with all signals blocked.
    let old = sys::block_signals();
    let spawned = thread::Builder::new()
        .name(name)
        .stack_size(STACK_SIZE)
        .spawn(move || main(start));
    sys::restore_signals(&old);
    let release = |c: NonNull<Conn>| {
        // SAFETY: no thread uses the connection now, so this frees it.
        unsafe {
            c.as_ref().refs.store(1, Ordering::Relaxed);
            conn_unref(c);
        }
    };
    let Ok(handle) = spawned else {
        release(c);
        return fail(libc::EAGAIN);
    };
    let e = rx.recv().unwrap_or(libc::EIO);
    if e != 0 {
        let _ = handle.join();
        release(c);
        return fail(e);
    }
    ctx.push_thr(Thr { handle, conn: c });
    c.as_ptr()
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
    let Some(c) = NonNull::new(conn) else {
        return;
    };
    // SAFETY: the caller passes its connection.
    let conn = unsafe { c.as_ref() };
    conn.closed.store(true, Ordering::Release);
    // SAFETY: a C function holds no borrow at its start.
    if let Some(mut r) = unsafe { conn.local() } {
        r.stopping = true;
    }
    conn.sh.request_stop();
    // SAFETY: this is the reference of the owner.
    unsafe { conn_unref(c) };
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
    conn.root.load(Ordering::Acquire)
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
    let id = conn.sh.register_self();
    if let Ok(who) = u16::try_from(id)
        && who != 0
    {
        return who;
    }
    if !err.is_null() {
        // SAFETY: the caller passes NULL or room for an int.
        unsafe { err.write(if id < 0 { -id } else { libc::EIO }) };
    }
    0
}
