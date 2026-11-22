// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The event queue of a process and what its reactors share.

use std::any::Any;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::conn::{Conn, conn_unref};
use crate::ctx::InlineFn;
use crate::list::{List, Node, Push, Stack};
use crate::out::Out;
use crate::pdu::{Pdu, pdu_free};
use crate::placement::Group;
use crate::sys;
use crate::upper::{NO_UPPER, Upper, UpperVt};

/// The kinds of node in the event queue.
pub(crate) const EV_PDU: u8 = 1;
pub(crate) const EV_CLOSED: u8 = 2;
pub(crate) const EV_SENT: u8 = 3;

/// The inline function of the reactors and its argument.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InlineHook {
    pub(crate) func: InlineFn,
    pub(crate) private: *mut c_void,
}

// SAFETY: tn_smbros_ctx_inline() requires a function for any thread.
unsafe impl Send for InlineHook {}
// SAFETY: as for Send.
unsafe impl Sync for InlineHook {}

/// The layer above the shim.
#[derive(Debug)]
pub(crate) struct Attached {
    pub(crate) vt: &'static UpperVt,
    pub(crate) global: Box<dyn Any + Send + Sync>,
}

/// The context, each connection and each object that posts events hold a
/// reference.
#[derive(Debug)]
pub struct Hub {
    refs: AtomicU32,
    queue: Stack,
    /// Events that the owner thread took from `queue` and did not return.
    taken: UnsafeCell<List>,
    efd: OwnedFd,
    pub(crate) inline: OnceLock<InlineHook>,
    pub(crate) attached: OnceLock<Attached>,
    pub(crate) group: Group,
}

// SAFETY: only the owner thread uses `taken`. The rest is Sync.
unsafe impl Sync for Hub {}
// SAFETY: as for Sync.
unsafe impl Send for Hub {}

impl Hub {
    /// A new hub with one reference, or the errno.
    pub(crate) fn new() -> Result<NonNull<Hub>, i32> {
        let fd = sys::eventfd(libc::EFD_NONBLOCK)?;
        let hub = Box::new(Hub {
            refs: AtomicU32::new(1),
            queue: Stack::new(),
            taken: UnsafeCell::new(List::new()),
            // SAFETY: the eventfd is new and nothing else owns it.
            efd: unsafe { OwnedFd::from_raw_fd(fd) },
            inline: OnceLock::new(),
            attached: OnceLock::new(),
            group: Group::default(),
        });
        Ok(NonNull::from(Box::leak(hub)))
    }

    pub(crate) fn efd(&self) -> i32 {
        self.efd.as_raw_fd()
    }

    pub(crate) fn vt(&self) -> &'static UpperVt {
        self.attached.get().map_or(&NO_UPPER, |a| a.vt)
    }

    /// The state of the layer `U` for the process, if `U` is attached.
    pub fn global<U: Upper>(&self) -> Option<&U::Global> {
        self.attached.get()?.global.downcast_ref()
    }

    /// Queue an event for the owner. Only a post to an empty queue wakes
    /// the owner, which empties the queue after each wake.
    ///
    /// # Safety
    ///
    /// `n` is valid and in no list until the owner takes it. Its kind tells
    /// which object has it.
    pub unsafe fn post(&self, n: NonNull<Node>) {
        // SAFETY: as the caller says. The queue is never closed.
        if unsafe { self.queue.push(n.cast()) } == Push::First {
            sys::poke(self.efd());
        }
    }

    /// # Safety
    ///
    /// No other thread uses `taken` at the same time.
    pub(crate) unsafe fn next_node(&self) -> Option<NonNull<Node>> {
        // SAFETY: as the caller says.
        let taken = unsafe { &mut *self.taken.get() };
        if let Some(l) = taken.pop() {
            return Some(l.cast());
        }
        *taken = self.queue.take();
        taken.pop().map(NonNull::cast)
    }

    /// # Safety
    ///
    /// As for `next_node()`.
    pub(crate) unsafe fn drop_events(&self) {
        loop {
            let mut l = self.queue.take();
            // SAFETY: as the caller says.
            l.concat(unsafe { &mut *self.taken.get() });
            if l.is_empty() {
                return;
            }
            while let Some(n) = l.pop() {
                // SAFETY: the queue gave up the node.
                unsafe { drop_event(self.vt(), n.cast()) };
            }
        }
    }
}

/// # Safety
///
/// The queue gave up `n`. Its kind tells which object has it.
unsafe fn drop_event(vt: &UpperVt, n: NonNull<Node>) {
    // SAFETY: as the caller says.
    unsafe {
        match n.as_ref().kind {
            EV_PDU => {
                let p = Pdu::from_ev(n);
                p.conn().queued.fetch_sub(1, Ordering::Relaxed);
                pdu_free(p);
            }
            EV_CLOSED => conn_unref(Conn::from_closed_ev(n)),
            EV_SENT => drop(Out::from_ev(n)),
            _ => (vt.drop_note)(n),
        }
    }
}

pub(crate) fn hub_ref(h: NonNull<Hub>) {
    // SAFETY: the caller has a reference, so the hub is live.
    unsafe { h.as_ref() }.refs.fetch_add(1, Ordering::Relaxed);
}

/// The last reference frees the hub.
///
/// # Safety
///
/// The caller has a reference and does not use it after this call.
pub(crate) unsafe fn hub_unref(h: NonNull<Hub>) {
    // SAFETY: as the caller says.
    if unsafe { h.as_ref() }.refs.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    // SAFETY: no other reference is left, so no other thread uses the hub.
    unsafe {
        h.as_ref().drop_events();
        drop(Box::from_raw(h.as_ptr()));
    }
}

/// A counted reference to a hub.
#[derive(Debug)]
pub struct HubRef(NonNull<Hub>);

// SAFETY: the hub is Sync, and the reference count is atomic.
unsafe impl Send for HubRef {}
// SAFETY: as for Send.
unsafe impl Sync for HubRef {}

impl HubRef {
    pub(crate) fn new(h: NonNull<Hub>) -> HubRef {
        hub_ref(h);
        HubRef(h)
    }

    pub fn hub(&self) -> &Hub {
        // SAFETY: the reference keeps the hub live.
        unsafe { self.0.as_ref() }
    }
}

impl Clone for HubRef {
    fn clone(&self) -> Self {
        HubRef::new(self.0)
    }
}

impl Drop for HubRef {
    fn drop(&mut self) {
        // SAFETY: this is the reference of `self`.
        unsafe { hub_unref(self.0) };
    }
}
