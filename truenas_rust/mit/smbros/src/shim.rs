// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The handler of an adopted connection's reactor, and its thread. Each PDU
//! goes to the owner inline or through the event queue.

use std::any::TypeId;
use std::ffi::c_int;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;

use crate::block::{Block, FreeList, try_box};
use crate::conn::{Conn, Start, conn_ref, conn_unref};
use crate::hub::EV_SENT;
use crate::list::{BoxList, Msg, Node};
use crate::out::Out;
use crate::pdu::{Pdu, pdu_reuse};
use crate::placement::Mover;
use crate::reactor::{Handler, Reactor, ReactorCell, run};
use crate::upper::{ShimReactor, Upper};

/// The state of the shim on a reactor thread.
#[derive(Debug)]
pub struct ShimState {
    conn: NonNull<Conn>,
    pub(crate) pdus: FreeList<Pdu>,
    /// PDUs that the reactor gave out and did not get back.
    pub(crate) out_pdus: u32,
    mover: Mover,
    /// The inbox drain with the hooks of the layer.
    drain: fn(&mut ShimReactor),
    /// The local state of the layer, a leaked box.
    upper: NonNull<()>,
    upper_type: TypeId,
}

impl ShimState {
    pub fn conn(&self) -> &Conn {
        // SAFETY: the reactor keeps a reference to its connection.
        unsafe { self.conn.as_ref() }
    }
}

/// The connection of `r` with a lifetime apart from `r`.
fn conn_of<'a>(r: &ShimReactor) -> &'a Conn {
    // SAFETY: the reactor's reference outlives every use of the reactor.
    unsafe { r.h.conn.as_ref() }
}

/// # Safety
///
/// The reactor runs the layer `U`. No other reference to the local state is
/// live while the result lives.
unsafe fn split_unchecked<U: Upper>(
    r: &mut ShimReactor,
) -> (&mut ShimReactor, &mut U::Local) {
    let p = r.h.upper.cast::<U::Local>();
    // SAFETY: as the caller says. The local state is a box of its own.
    (r, unsafe { &mut *p.as_ptr() })
}

/// The reactor and the local state of its layer `U`, for a C function on
/// the reactor thread. None if the reactor runs another layer.
///
/// # Safety
///
/// No other reference to the local state is live while the result lives,
/// as at the start of a C function that smbd calls inline.
pub unsafe fn split<U: Upper>(
    r: &mut ShimReactor,
) -> Option<(&mut ShimReactor, &mut U::Local)> {
    if r.h.upper_type != TypeId::of::<U>() {
        return None;
    }
    // SAFETY: the type matches, and the caller vouches for the rest.
    Some(unsafe { split_unchecked::<U>(r) })
}

impl Reactor<ShimState> {
    /// Queue an out from a hook. Unlike `queue()`, it does not drain the
    /// inbox, so hooks do not nest.
    pub fn queue_reply(&mut self, o: Box<Out>) {
        if o.nseg == 0 {
            release_out(self, o);
            return;
        }
        self.sendq.push(o);
    }

    /// Queue an out from a C function on the reactor thread.
    pub fn queue_api(&mut self, o: Box<Out>) {
        let drain = self.h.drain;
        if let Some(o) = self.queue_with(o, drain) {
            release_out(self, o);
        }
    }
}

/// The reactor is done with `o`. An out with lent memory goes to the owner
/// as a SENT event.
pub fn release_out(r: &mut ShimReactor, mut o: Box<Out>) {
    let hub = conn_of(r).hub();
    if !o.plan.is_null() {
        (hub.vt().drop_plan)(&mut o, Some(&mut r.blocks));
    }
    if o.lent {
        o.drop_data(Some(&mut r.blocks));
        post_sent(hub, o);
        return;
    }
    r.free_out(o);
}

pub(crate) fn post_sent(hub: &crate::hub::Hub, o: Box<Out>) {
    let o = Box::leak(o);
    o.ev = Node::new(EV_SENT);
    // SAFETY: the node is in a leaked out, and its kind tells so.
    unsafe { hub.post(NonNull::from(&mut o.ev)) };
}

fn on_closed(r: &mut ShimReactor, err: c_int) {
    let c = r.h.conn;
    let conn = conn_of(r);
    conn.closed_err.store(err, Ordering::Relaxed);
    conn_ref(c);
    // SAFETY: the reference above keeps the node until the owner takes it.
    unsafe { conn.hub().post(conn.closed_ev()) };
}

/// The handler of a connection with the layer `U`.
#[derive(Debug)]
pub struct ShimHandler<U>(PhantomData<U>);

pub type Shim<U> = ShimHandler<U>;

impl<U: Upper> ShimHandler<U> {
    #[cold]
    #[inline(never)]
    fn no_pdu(r: &mut ShimReactor, b: Block) {
        r.blocks.put(b);
        r.release();
        r.fail::<Self>(libc::ENOMEM);
    }
}

impl<U: Upper> Handler for ShimHandler<U> {
    type State = ShimState;
    const NBT: bool = true;

    fn on_pdu(cell: &ReactorCell<ShimState>, block: Block, len: u32) {
        // SAFETY: the reactor holds no borrow while it runs this hook.
        let mut guard = unsafe { cell.borrow() };
        let r = &mut *guard;
        let owner = r.h.conn;
        let conn = conn_of(r);
        let hub = conn.hub();
        r.h.mover.tick(&hub.group);
        let pooled = r.h.pdus.take();
        let Some(mut pdu) = pooled.or_else(|| try_box(|| Pdu::new(owner)))
        else {
            Self::no_pdu(r, block);
            return;
        };
        r.h.out_pdus += 1;
        pdu.fill(block, len);
        // SAFETY: this reactor runs U, and no hook runs now.
        let (r, local) = unsafe { split_unchecked::<U>(r) };
        pdu.verdict = U::incoming(r, local, pdu.data());
        pdu.delegable = conn.delegate && pdu.verdict.job;
        if let Some(hook) = hub.inline.get()
            && conn.queued.load(Ordering::Acquire) == 0
            && !conn.closed.load(Ordering::Relaxed)
        {
            let delegable = pdu.delegable;
            pdu.deferred = delegable;
            let mut ev = pdu.event();
            let raw = Box::into_raw(pdu);
            // smbd can use the reactor while it runs the PDU.
            drop(guard);
            // SAFETY: the hook owns `raw` only if it returns true.
            if unsafe { (hook.func)(hook.private, &raw mut ev) } {
                // The owner has the PDU now. It can have freed it already.
                if !delegable {
                    // SAFETY: no borrow is live now.
                    unsafe { cell.borrow() }.release();
                }
                return;
            }
            // SAFETY: the hook did not take the PDU.
            pdu = unsafe { Box::from_raw(raw) };
        }
        pdu.deferred = true;
        conn.queued.fetch_add(1, Ordering::AcqRel);
        let node = pdu.ev_node();
        Box::leak(pdu);
        // SAFETY: the node is in a leaked PDU, and its kind tells so.
        unsafe { hub.post(node) };
    }

    fn on_msg(r: &mut ShimReactor, m: NonNull<Msg>) {
        // SAFETY: this reactor runs U, and hooks do not nest.
        let (r, l) = unsafe { split_unchecked::<U>(r) };
        U::on_msg(r, l, m);
    }

    fn drop_msg(r: &mut ShimReactor, m: NonNull<Msg>) {
        // SAFETY: as in on_msg().
        let (r, l) = unsafe { split_unchecked::<U>(r) };
        U::drop_msg(r, l, m);
    }

    fn finish_out(r: &mut ShimReactor, o: &mut Out) -> bool {
        U::finish_out(r, o)
    }

    fn release_out(r: &mut ShimReactor, o: Box<Out>) {
        release_out(r, o);
    }

    fn on_closed(r: &mut ShimReactor, err: c_int) {
        on_closed(r, err);
    }

    fn on_batch(r: &mut ShimReactor) {
        let conn = conn_of(r);
        if conn.ret.ready() {
            // SAFETY: each link is a PDU that pdu_return() leaked.
            let mut l = unsafe { BoxList::<Pdu>::from_raw(conn.ret.take()) };
            while let Some(p) = l.pop() {
                pdu_reuse(r, p);
            }
        }
        // SAFETY: as in on_msg().
        let (r, l) = unsafe { split_unchecked::<U>(r) };
        U::on_batch(r, l);
    }

    #[inline]
    fn pending(r: &ShimReactor) -> bool {
        // SAFETY: this reactor runs U, with no hook running.
        U::pending(unsafe { r.h.upper.cast::<U::Local>().as_ref() })
    }

    fn on_cqe(r: &mut ShimReactor, ud: u64, res: i32) {
        // SAFETY: as in on_msg().
        let (r, l) = unsafe { split_unchecked::<U>(r) };
        U::on_cqe(r, l, ud, res);
    }

    fn on_stop(r: &mut ShimReactor) {
        // SAFETY: as in on_msg().
        let (r, l) = unsafe { split_unchecked::<U>(r) };
        U::on_stop(r, l);
    }

    /// The PDUs that are still out keep the connection until freed.
    fn on_end(r: &mut ShimReactor) {
        {
            // SAFETY: as in on_msg().
            let (r, l) = unsafe { split_unchecked::<U>(r) };
            U::on_end(r, l);
        }
        let conn = conn_of(r);
        conn.refs.fetch_add(r.h.out_pdus, Ordering::Relaxed);
        // SAFETY: as in on_batch().
        let mut l = unsafe { BoxList::<Pdu>::from_raw(conn.ret.close()) };
        let mut n = 0;
        while let Some(mut p) = l.pop() {
            if let Some(b) = p.take_block() {
                r.blocks.put(b);
            }
            n += 1;
        }
        conn.refs.fetch_sub(n, Ordering::Relaxed);
        r.h.out_pdus = 0;
    }
}

/// Abort on a panic, which would end only the thread and leave smbd waiting.
struct AbortOnPanic;

impl Drop for AbortOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

/// The reactor thread of a new connection with the layer `U`.
pub(crate) fn reactor_main<U: Upper>(st: Start) {
    let _abort = AbortOnPanic;
    let Start {
        conn: c,
        cfg,
        sock,
        ready,
    } = st;
    // SAFETY: the reactor's reference lasts until the conn_unref() below.
    let conn: &Conn = unsafe { c.as_ref() };
    let state = ShimState {
        conn: c,
        pdus: FreeList::new(256),
        out_pdus: 0,
        mover: Mover::new(),
        drain: Reactor::drain_inbox::<ShimHandler<U>>,
        upper: NonNull::dangling(),
        upper_type: TypeId::of::<U>(),
    };
    // SAFETY: the connection owns `sh` and outlives the reactor.
    let made =
        unsafe { Reactor::new(NonNull::from(&conn.sh), cfg, sock, state) };
    let r = match made {
        Ok(r) => r,
        Err(e) => {
            let _ = ready.send(e);
            return;
        }
    };
    // This thread has the credentials of the owner, which adopts as root.
    let id = conn.sh.register_self();
    let Ok(root) = u16::try_from(id) else {
        conn.sh.clear_ring();
        drop(r);
        let _ = ready.send(if id < 0 { -id } else { libc::EIO });
        return;
    };
    if root == 0 {
        conn.sh.clear_ring();
        drop(r);
        let _ = ready.send(libc::EIO);
        return;
    }
    conn.root.store(root, Ordering::Release);
    let cell = ReactorCell::new(r);
    conn.set_cell(&cell);
    conn.hub().group.join();
    {
        // SAFETY: smbd does not use the reactor before the send below.
        let mut r = unsafe { cell.borrow() };
        let local = U::start(&mut r);
        r.h.upper = NonNull::from(Box::leak(Box::new(local))).cast();
    }
    let _ = ready.send(0);
    run::<ShimHandler<U>>(&cell);
    conn.sh.clear_thread();
    conn.clear_cell();
    let r = cell.into_inner();
    // SAFETY: the box is from U::start() above, and the reactor ended.
    drop(unsafe { Box::from_raw(r.h.upper.cast::<U::Local>().as_ptr()) });
    drop(r);
    conn.hub().group.leave();
    // SAFETY: this is the reference of the reactor.
    unsafe { conn_unref(c) };
}
