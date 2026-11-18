// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The context of a process. It has the event queue of the owner thread,
//! its eventfd and the reactor threads.

use std::collections::VecDeque;
use std::ffi::{c_int, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use truenas_ros::net::server::{Deferred, ShutdownHandle};

use crate::buf::Buf;
use crate::conn::ConnState;
use crate::lock;
use crate::upper::{Note, Upper, Verdict};

/// The event kind for a new PDU of a connection.
pub const TN_SMBROS_PDU: c_int = 1;
/// The event kind for a closed connection.
pub const TN_SMBROS_CLOSED: c_int = 2;
/// The event kind for lent memory that the reactor no longer uses. See
/// `tn_smbros_send()`.
pub const TN_SMBROS_SENT: c_int = 3;
/// The layer above the shim uses the event kinds from this value up.
pub const TN_SMBROS_UPPER: c_int = 16;

/// An event in the queue for the owner thread.
#[derive(Debug)]
pub(crate) enum Event {
    /// A new PDU. `buf` has its deferred reply.
    Pdu {
        buf: Box<Buf>,
        nbt_type: u8,
        verdict: Verdict,
    },
    Closed {
        conn: Arc<ConnState>,
        error: c_int,
    },
    /// The reactor no longer uses the memory that a send lent it. The owner
    /// can free the memory then. So the owner gets this event for a closed
    /// connection too.
    Sent {
        cookie: u64,
    },
    Note(Box<dyn Note>),
}

/// A function that runs a new PDU on the reactor thread that calls it. It
/// returns true if it ran the PDU. Then it owns `ev->buf`, as with an event
/// from `tn_smbros_next()`. If it returns false, it does not keep or free
/// `ev->buf`. Then the shim queues the PDU. The arguments are the `private`
/// pointer of `tn_smbros_ctx_inline()` and the event.
pub type InlineFn =
    unsafe extern "C" fn(*mut c_void, *mut TnSmbrosEvent) -> bool;

#[derive(Debug, Clone, Copy)]
pub(crate) struct InlineHook {
    pub(crate) func: InlineFn,
    pub(crate) private: *mut c_void,
}

// SAFETY: tn_smbros_ctx_inline() requires a function that every reactor
// thread can call. Only that function uses `private`.
unsafe impl Send for InlineHook {}
// SAFETY: as for Send.
unsafe impl Sync for InlineHook {}

/// The event queue of a process, its eventfd and the hooks of its reactors.
#[derive(Debug)]
pub(crate) struct Shared {
    queue: Mutex<VecDeque<Event>>,
    efd: OwnedFd,
    pub(crate) upper: OnceLock<Arc<dyn Upper>>,
    pub(crate) inline: OnceLock<InlineHook>,
}

impl Shared {
    pub(crate) fn post(&self, ev: Event) {
        let was_empty = {
            let mut q = lock(&self.queue);
            let was_empty = q.is_empty();
            q.push_back(ev);
            was_empty
        };
        // The owner empties the queue after each wake. So only a post to an
        // empty queue needs a wake.
        if was_empty {
            self.wake();
        }
    }

    fn wake(&self) {
        let one: u64 = 1;
        // SAFETY: `one` has the 8 bytes that the write reads.
        unsafe {
            libc::write(
                self.efd.as_raw_fd(),
                (&raw const one).cast::<c_void>(),
                8,
            );
        }
    }
}

/// Queues the events of the upper layer for the owner thread.
#[derive(Debug, Clone)]
pub struct Poster(pub(crate) Arc<Shared>);

impl Poster {
    pub fn post(&self, note: Box<dyn Note>) {
        self.0.post(Event::Note(note));
    }
}

/// The handles that stop and join one reactor thread.
#[derive(Debug)]
pub(crate) struct Reactor {
    pub(crate) stop: ShutdownHandle,
    pub(crate) thread: thread::JoinHandle<()>,
}

/// The context of a process, from `tn_smbros_ctx_new()`.
#[derive(Debug)]
pub struct Ctx {
    pub(crate) shared: Arc<Shared>,
    /// The reactor threads that `tn_smbros_ctx_free()` stops and joins.
    pub(crate) reactors: Mutex<Vec<Reactor>>,
    /// The ID of the process that made the context. A forked child does not
    /// have the reactor threads of that process.
    pid: u32,
}

impl Ctx {
    /// Set the upper layer of the reactors. Call this before the first
    /// `tn_smbros_adopt()`. False if an upper layer is set already.
    pub fn set_upper(&self, upper: Arc<dyn Upper>) -> bool {
        self.shared.upper.set(upper).is_ok()
    }

    pub fn poster(&self) -> Poster {
        Poster(Arc::clone(&self.shared))
    }
}

/// An event for the caller, from `tn_smbros_next()`.
#[repr(C)]
#[derive(Debug)]
pub struct TnSmbrosEvent {
    /// The `cookie` of `tn_smbros_adopt()` in a PDU or CLOSED event. The
    /// `sent_cookie` of `tn_smbros_send()` in a SENT event.
    pub(crate) cookie: u64,
    /// `TN_SMBROS_PDU`, `TN_SMBROS_CLOSED`, `TN_SMBROS_SENT` or a kind of
    /// the layer above the shim.
    pub(crate) kind: c_int,
    /// The first byte of the NBT header in a PDU event.
    pub(crate) nbt_type: u8,
    /// The message of a PDU event, without the 4-byte NBT header.
    pub(crate) data: *mut u8,
    pub(crate) len: usize,
    /// The buffer of a PDU event. It owns `data`. Free it with
    /// `tn_smbros_buf_free()`.
    pub(crate) buf: *mut c_void,
    /// The errno of a CLOSED event. 0 means that the peer closed the
    /// connection.
    pub(crate) error: c_int,
    /// In a PDU event, `flags`, `status` and `tag` are values of the layer
    /// above the shim. The header of that layer describes them.
    pub(crate) flags: u32,
    pub(crate) status: u32,
    pub(crate) tag: u64,
}

impl TnSmbrosEvent {
    /// An event of `kind` without a PDU.
    pub(crate) fn bare(cookie: u64, kind: c_int) -> Self {
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

    /// Make the event of a new PDU. The event owns `buf`. `buf` still has
    /// the deferred reply of a PDU that can get a job. This returns the
    /// reply of any other PDU.
    pub(crate) fn pdu(
        mut buf: Box<Buf>,
        nbt_type: u8,
        verdict: &Verdict,
    ) -> (Self, Option<Deferred>) {
        let keep = if buf.conn.delegate && verdict.job {
            None
        } else {
            buf.deferred.take()
        };
        let cookie = buf.conn.cookie;
        let ev = Self {
            nbt_type,
            // The storage of the body does not move while the box exists.
            data: buf.body.as_mut_ptr(),
            len: buf.body.len(),
            buf: Box::into_raw(buf).cast::<c_void>(),
            flags: verdict.flags,
            status: verdict.status,
            tag: verdict.tag,
            ..Self::bare(cookie, TN_SMBROS_PDU)
        };
        (ev, keep)
    }
}

/// Make the context of the process. Use one per process. NULL on failure,
/// with errno set.
#[unsafe(no_mangle)]
pub extern "C" fn tn_smbros_ctx_new() -> *mut Ctx {
    // SAFETY: eventfd has no pointer arguments.
    let fd =
        unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if fd < 0 {
        return ptr::null_mut();
    }
    // SAFETY: `fd` is a new descriptor that nothing else owns.
    let efd = unsafe { OwnedFd::from_raw_fd(fd) };
    Box::into_raw(Box::new(Ctx {
        shared: Arc::new(Shared {
            queue: Mutex::new(VecDeque::new()),
            efd,
            upper: OnceLock::new(),
            inline: OnceLock::new(),
        }),
        reactors: Mutex::new(Vec::new()),
        pid: std::process::id(),
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
    // SAFETY: the caller passes a context from tn_smbros_ctx_new(). A
    // reactor can use it until the joins below.
    let c = unsafe { &*ctx };
    if std::process::id() != c.pid {
        // A forked child has none of these threads. It cannot join them.
        // The context and its events belong to the parent.
        return;
    }
    let reactors = std::mem::take(&mut *lock(&c.reactors));
    for r in &reactors {
        r.stop.shutdown();
    }
    let me = thread::current().id();
    for r in reactors {
        if r.thread.thread().id() == me {
            // The owner can exit on a reactor thread. A thread cannot join
            // itself.
            std::mem::forget(r);
            continue;
        }
        let _ = r.thread.join();
    }
    // SAFETY: no reactor uses the context now. The caller does not use it
    // after this call.
    let Ctx { shared, .. } = *unsafe { Box::from_raw(ctx) };
    // The drop of an event can post another event. So drop the events
    // outside the lock.
    loop {
        let events = std::mem::take(&mut *lock(&shared.queue));
        if events.is_empty() {
            break;
        }
        drop(events);
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
    let ctx = unsafe { &*ctx };
    ctx.shared.efd.as_raw_fd()
}

/// Clear the eventfd. Call this before the calls to `tn_smbros_next()` that
/// empty the queue.
///
/// # Safety
///
/// `ctx` is a live context from `tn_smbros_ctx_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_ctx_ack(ctx: *mut Ctx) {
    let mut count: u64 = 0;
    // SAFETY: the caller passes a live context.
    let ctx = unsafe { &*ctx };
    // SAFETY: the read writes at most 8 bytes into `count`. It fails with
    // EAGAIN if the eventfd is clear.
    unsafe {
        libc::read(
            ctx.shared.efd.as_raw_fd(),
            (&raw mut count).cast::<c_void>(),
            8,
        );
    }
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
    let ctx = unsafe { &*ctx };
    ctx.shared.wake();
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
    // This is `InlineFn` written out. cbindgen does not make a nullable C
    // pointer of `Option<InlineFn>`.
    func: Option<unsafe extern "C" fn(*mut c_void, *mut TnSmbrosEvent) -> bool>,
    private: *mut c_void,
) -> bool {
    // SAFETY: the caller passes a live context.
    let ctx = unsafe { &*ctx };
    let Some(func) = func else {
        return false;
    };
    ctx.shared.inline.set(InlineHook { func, private }).is_ok()
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
    // SAFETY: the caller passes a live context.
    let shared = unsafe { &(*ctx).shared };
    loop {
        let next = lock(&shared.queue).pop_front();
        let Some(next) = next else {
            return false;
        };
        let out = match next {
            Event::Pdu {
                buf,
                nbt_type,
                verdict,
            } => {
                buf.conn.queued.fetch_sub(1, Ordering::AcqRel);
                if buf.conn.closed.load(Ordering::Relaxed) {
                    continue;
                }
                // The owner has the PDU. The reactor can read the next one.
                let (ev, keep) = TnSmbrosEvent::pdu(buf, nbt_type, &verdict);
                if let Some(d) = keep {
                    d.reply(Vec::new());
                }
                ev
            }
            Event::Closed { conn, error } => {
                if conn.closed.load(Ordering::Relaxed) {
                    continue;
                }
                TnSmbrosEvent {
                    error,
                    ..TnSmbrosEvent::bare(conn.cookie, TN_SMBROS_CLOSED)
                }
            }
            Event::Sent { cookie } => {
                TnSmbrosEvent::bare(cookie, TN_SMBROS_SENT)
            }
            Event::Note(note) => {
                let Some((kind, cookie, buf)) = note.take() else {
                    continue;
                };
                TnSmbrosEvent {
                    buf,
                    ..TnSmbrosEvent::bare(cookie, kind)
                }
            }
        };
        // SAFETY: the caller passes room for one event.
        unsafe { ev.write(out) };
        return true;
    }
}
