// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The context of a process: the event queue of the owner thread and the
//! reactor threads.

use std::any::Any;
use std::ffi::{c_int, c_void};
use std::os::unix::thread::JoinHandleExt;
use std::ptr::{self, NonNull};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;

use crate::conn::{Conn, conn_unref};
use crate::hub::{
    Attached, EV_CLOSED, EV_PDU, EV_SENT, Hub, HubRef, InlineHook, hub_unref,
};
use crate::lock;
use crate::out::Out;
use crate::pdu::{Pdu, pdu_free};
use crate::sys;
use crate::upper::{Upper, UpperVt};

/// The event kind for a new PDU of a connection.
pub const TN_SMBROS_PDU: c_int = 1;
/// The event kind for a closed connection.
pub const TN_SMBROS_CLOSED: c_int = 2;
/// The event kind for lent memory that the reactor no longer uses. See
/// `tn_smbros_send()`.
pub const TN_SMBROS_SENT: c_int = 3;
/// The layer above the shim uses the event kinds from this value up.
pub const TN_SMBROS_UPPER: c_int = 16;

/// A function that runs a new PDU on the reactor thread that calls it. It
/// returns true if it ran the PDU. Then it owns `ev->buf`, as with an event
/// from `tn_smbros_next()`. If it returns false, it does not keep or free
/// `ev->buf`. Then the shim queues the PDU. The arguments are the `private`
/// pointer of `tn_smbros_ctx_inline()` and the event.
pub type InlineFn =
    unsafe extern "C" fn(*mut c_void, *mut TnSmbrosEvent) -> bool;

/// An event for the caller, from `tn_smbros_next()`.
#[repr(C)]
#[derive(Debug)]
pub struct TnSmbrosEvent {
    /// The `cookie` of `tn_smbros_adopt()` in a PDU or CLOSED event. The
    /// `sent_cookie` of `tn_smbros_send()` in a SENT event.
    pub cookie: u64,
    /// `TN_SMBROS_PDU`, `TN_SMBROS_CLOSED`, `TN_SMBROS_SENT` or a kind of
    /// the layer above the shim.
    pub kind: c_int,
    /// The first byte of the NBT header in a PDU event.
    pub nbt_type: u8,
    /// The message of a PDU event, without the 4-byte NBT header.
    pub data: *mut u8,
    pub len: usize,
    /// The buffer of a PDU event. It owns `data`. Free it with
    /// `tn_smbros_buf_free()`.
    pub buf: *mut c_void,
    /// The errno of a CLOSED event. 0 means that the peer closed the
    /// connection.
    pub error: c_int,
    /// In a PDU event, `flags`, `status` and `tag` are values of the layer
    /// above the shim. The header of that layer describes them.
    pub flags: u32,
    pub status: u32,
    pub tag: u64,
}

impl TnSmbrosEvent {
    /// An event of `kind` without a PDU.
    pub fn bare(cookie: u64, kind: c_int) -> Self {
        Self {
            cookie,
            kind,
            nbt_type: 0,
            data: ptr::null_mut(),
            len: 0,
            buf: ptr::null_mut(),
            error: 0,
            flags: 0,
            status: 0,
            tag: 0,
        }
    }
}

/// A reactor thread and a reference to its connection.
#[derive(Debug)]
pub(crate) struct Thr {
    pub(crate) handle: JoinHandle<()>,
    pub(crate) conn: NonNull<Conn>,
}

// SAFETY: the connection is Sync, and the record has its own reference.
unsafe impl Send for Thr {}

/// The context of a process, from `tn_smbros_ctx_new()`.
#[derive(Debug)]
pub struct Ctx {
    hub: NonNull<Hub>,
    /// The process that made the context. A forked child has no reactors.
    pid: u32,
    /// For the reactor thread names.
    adopted: AtomicU32,
    thrs: Mutex<Vec<Thr>>,
}

impl Ctx {
    pub fn hub(&self) -> &Hub {
        // SAFETY: the context keeps a reference to its hub.
        unsafe { self.hub.as_ref() }
    }

    pub(crate) fn hub_ptr(&self) -> NonNull<Hub> {
        self.hub
    }

    pub fn hub_ref(&self) -> HubRef {
        HubRef::new(self.hub)
    }

    pub(crate) fn next_index(&self) -> u32 {
        self.adopted.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn push_thr(&self, t: Thr) {
        lock(&self.thrs).push(t);
    }

    /// Join the reactor threads that ended.
    pub(crate) fn reap_done(&self) {
        let done: Vec<Thr> = {
            let mut thrs = lock(&self.thrs);
            if !thrs.iter().any(|t| t.handle.is_finished()) {
                return;
            }
            let (done, keep) = std::mem::take(&mut *thrs)
                .into_iter()
                .partition(|t| t.handle.is_finished());
            *thrs = keep;
            done
        };
        for t in done {
            reap_thr(t);
        }
    }

    /// Attach the layer `U` before the first `tn_smbros_adopt()`. False if
    /// `ctx` has a layer or `vt` is not the table of `U`.
    pub fn attach<U: Upper>(&self, vt: &'static UpperVt, g: U::Global) -> bool {
        if (vt.id)() != std::any::TypeId::of::<U>() {
            return false;
        }
        let global: Box<dyn Any + Send + Sync> = Box::new(g);
        self.hub().attached.set(Attached { vt, global }).is_ok()
    }
}

/// Join the thread of `t`, or detach it if it is the calling thread.
fn reap_thr(t: Thr) {
    let id = usize::try_from(t.handle.as_pthread_t()).unwrap_or(0);
    if id == sys::thread_self() {
        drop(t.handle);
    } else {
        let _ = t.handle.join();
    }
    // SAFETY: this is the reference of the record.
    unsafe { conn_unref(t.conn) };
}

/// Make the context of the process. Use one per process. NULL on failure,
/// with errno set.
#[unsafe(no_mangle)]
pub extern "C" fn tn_smbros_ctx_new() -> *mut Ctx {
    let Ok(hub) = Hub::new() else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(Ctx {
        hub,
        pid: std::process::id(),
        adopted: AtomicU32::new(0),
        thrs: Mutex::new(Vec::new()),
    }))
}

/// Stop the reactors of `ctx` and wait for their threads to end. Drop the
/// events that `tn_smbros_next()` did not return. Free `ctx`. After that,
/// no reactor uses memory of the caller. Call this on the thread of
/// `tn_smbros_next()`. The caller still closes each connection with
/// `tn_smbros_close()`. In a forked child, this call does nothing.
///
/// # Safety
///
/// `ctx` is NULL or a context from `tn_smbros_ctx_new()`. The caller does
/// not use `ctx` after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_ctx_free(ctx: *mut Ctx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: the caller passes a context from tn_smbros_ctx_new().
    let x = unsafe { &*ctx };
    if std::process::id() != x.pid {
        // The context and its threads belong to the parent.
        return;
    }
    let thrs = std::mem::take(&mut *lock(&x.thrs));
    for t in &thrs {
        // SAFETY: the record keeps the connection live.
        unsafe { t.conn.as_ref() }.sh.request_stop();
    }
    for t in thrs {
        reap_thr(t);
    }
    // SAFETY: no reactor is left, and the caller gives up the context.
    let x = unsafe { Box::from_raw(ctx) };
    // SAFETY: as above.
    unsafe {
        x.hub().drop_events();
        hub_unref(x.hub);
    }
}

/// The eventfd that becomes readable when the queue has events.
///
/// # Safety
///
/// `ctx` is a live context from `tn_smbros_ctx_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_ctx_fd(ctx: *const Ctx) -> c_int {
    // SAFETY: the caller passes a live context.
    unsafe { &*ctx }.hub().efd()
}

/// Clear the eventfd. Call this before the calls to `tn_smbros_next()` that
/// empty the queue.
///
/// # Safety
///
/// `ctx` is a live context from `tn_smbros_ctx_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_ctx_ack(ctx: *mut Ctx) {
    // SAFETY: the caller passes a live context.
    sys::drain_eventfd(unsafe { &*ctx }.hub().efd());
}

/// Make the eventfd readable, even if the queue is empty. This wakes the
/// thread of `tn_smbros_next()`.
///
/// # Safety
///
/// `ctx` is a live context from `tn_smbros_ctx_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_ctx_wake(ctx: *const Ctx) {
    // SAFETY: the caller passes a live context.
    sys::poke(unsafe { &*ctx }.hub().efd());
}

/// Set the inline function of the reactors to `func`. Call this before the
/// first `tn_smbros_adopt()`. A reactor calls `func` with `private` and each
/// new PDU. It does not call `func` while its connection has a PDU in the
/// queue. False if `func` is NULL or the reactors have a function already.
///
/// # Safety
///
/// `ctx` is a live context from `tn_smbros_ctx_new()`. `func` with
/// `private` is safe to call on any reactor thread until
/// `tn_smbros_ctx_free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_ctx_inline(
    ctx: *mut Ctx,
    // `InlineFn` written out, so cbindgen makes a nullable C pointer.
    func: Option<unsafe extern "C" fn(*mut c_void, *mut TnSmbrosEvent) -> bool>,
    private: *mut c_void,
) -> bool {
    // SAFETY: the caller passes a live context.
    let ctx = unsafe { &*ctx };
    let Some(func) = func else {
        return false;
    };
    ctx.hub().inline.set(InlineHook { func, private }).is_ok()
}

/// Move the next event of the queue to `*ev`. False if the queue is empty.
/// This call drops the PDU and CLOSED events of a closed connection. It
/// returns every SENT event.
///
/// # Safety
///
/// `ctx` is a live context from `tn_smbros_ctx_new()`. `ev` points to
/// writable memory for one event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_next(
    ctx: *mut Ctx,
    ev: *mut TnSmbrosEvent,
) -> bool {
    // SAFETY: the caller passes a live context and room for one event.
    let (hub, ev) = unsafe { ((*ctx).hub(), &mut *ev) };
    loop {
        // SAFETY: only the owner thread calls tn_smbros_next().
        let Some(n) = (unsafe { hub.next_node() }) else {
            return false;
        };
        // SAFETY: the queue gave up the node, and its kind names its owner.
        match unsafe { n.as_ref().kind } {
            EV_PDU => {
                // SAFETY: as above.
                let mut p = unsafe { Pdu::from_ev(n) };
                let c = p.conn();
                c.queued.fetch_sub(1, Ordering::AcqRel);
                if c.closed.load(Ordering::Relaxed) {
                    pdu_free(p);
                    continue;
                }
                // Free the slot now unless the PDU can still get a job.
                if !p.delegable && p.deferred {
                    p.deferred = false;
                    p.conn().release_slot();
                }
                *ev = p.event();
                Box::leak(p);
                return true;
            }
            EV_CLOSED => {
                // SAFETY: as above.
                let c = unsafe { Conn::from_closed_ev(n) };
                // SAFETY: the event has a reference to the connection.
                let conn = unsafe { c.as_ref() };
                let skip = conn.closed.load(Ordering::Relaxed);
                *ev = TnSmbrosEvent {
                    error: conn.closed_err.load(Ordering::Relaxed),
                    ..TnSmbrosEvent::bare(conn.cookie, TN_SMBROS_CLOSED)
                };
                // SAFETY: this is the reference of the event.
                unsafe { conn_unref(c) };
                if skip {
                    continue;
                }
                return true;
            }
            EV_SENT => {
                // SAFETY: as above.
                let o = unsafe { Out::from_ev(n) };
                *ev = TnSmbrosEvent::bare(o.cookie, TN_SMBROS_SENT);
                return true;
            }
            _ => {
                // SAFETY: as above. The layer above posted the node.
                if unsafe { (hub.vt().take_note)(n, ev) } {
                    return true;
                }
            }
        }
    }
}
