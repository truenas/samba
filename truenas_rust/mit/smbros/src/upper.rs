// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The interface to the layer above the shim. Reactors call its hooks
//! statically. The C functions use `UpperVt`.

use std::any::TypeId;
use std::ptr::NonNull;

use crate::block::Pool;
use crate::conn::Start;
use crate::ctx::TnSmbrosEvent;
use crate::hub::Hub;
use crate::list::{Msg, Node};
use crate::out::Out;
use crate::reactor::Reactor;
use crate::shim::{ShimState, reactor_main};

/// The first kind of node in the event queue that the layer above uses.
pub const EV_UPPER: u8 = 16;

/// What the layer above says about a new PDU.
#[derive(Debug, Clone, Copy, Default)]
pub struct Verdict {
    /// The owner gets `flags`, `status` and `tag` in the event of the PDU.
    pub flags: u32,
    pub status: u32,
    pub tag: u64,
    /// True if the owner can give the reactor a job for the PDU.
    pub job: bool,
}

pub type ShimReactor = Reactor<ShimState>;

/// The layer above the shim. All but `ext_new()`, `drop_plan()`,
/// `take_note()` and `drop_note()` run on the reactor thread. Hooks must not
/// nest, so they queue with `queue_reply()`.
pub trait Upper: Sized + 'static {
    /// The state of the layer for the process.
    type Global: Send + Sync + 'static;
    /// The state of the layer on one reactor thread.
    type Local;
    /// The state of the layer for one connection, shared with smbd.
    type Ext: Send + Sync;

    /// In `tn_smbros_adopt()`. `g` is None if the layer is not attached.
    fn ext_new(g: Option<&Self::Global>) -> Self::Ext;
    /// A new reactor, before `tn_smbros_adopt()` returns.
    fn start(r: &mut ShimReactor) -> Self::Local;
    /// A new PDU, before the owner gets it. It can change the PDU in place.
    fn incoming(
        r: &mut ShimReactor,
        l: &mut Self::Local,
        pdu: &mut [u8],
    ) -> Verdict;
    /// The reactor hooks of `Handler` with the same names.
    fn on_msg(r: &mut ShimReactor, l: &mut Self::Local, m: NonNull<Msg>);
    fn drop_msg(r: &mut ShimReactor, l: &mut Self::Local, m: NonNull<Msg>);
    fn on_batch(r: &mut ShimReactor, l: &mut Self::Local);
    fn pending(l: &Self::Local) -> bool;
    fn on_cqe(r: &mut ShimReactor, l: &mut Self::Local, ud: u64, res: i32);
    fn on_stop(r: &mut ShimReactor, l: &mut Self::Local);
    fn on_end(r: &mut ShimReactor, l: &mut Self::Local);
    fn finish_out(r: &mut ShimReactor, o: &mut Out) -> bool;
    /// Free the plan of `o`. `pool` is None off the reactor thread.
    fn drop_plan(o: &mut Out, pool: Option<&mut Pool>);
    /// Fill `ev` from an event node of the layer. False skips the event.
    ///
    /// # Safety
    ///
    /// `n` is a node of the layer that the queue gave up.
    unsafe fn take_note(n: NonNull<Node>, ev: &mut TnSmbrosEvent) -> bool;
    /// Free an event node of the layer that the owner does not get.
    ///
    /// # Safety
    ///
    /// As for `take_note()`.
    unsafe fn drop_note(n: NonNull<Node>);
}

/// The functions of a layer that the C functions call.
#[derive(Debug)]
pub struct UpperVt {
    pub(crate) id: fn() -> TypeId,
    pub(crate) main: fn(Start),
    pub(crate) ext_new: fn(&Hub) -> NonNull<()>,
    pub(crate) ext_free: unsafe fn(NonNull<()>),
    pub(crate) drop_plan: fn(&mut Out, Option<&mut Pool>),
    pub(crate) take_note: unsafe fn(NonNull<Node>, &mut TnSmbrosEvent) -> bool,
    pub(crate) drop_note: unsafe fn(NonNull<Node>),
}

fn ext_new<U: Upper>(hub: &Hub) -> NonNull<()> {
    let ext = U::ext_new(hub.global::<U>());
    NonNull::from(Box::leak(Box::new(ext))).cast()
}

/// # Safety
///
/// `p` is from `ext_new::<U>()` and nothing uses it after this call.
unsafe fn ext_free<U: Upper>(p: NonNull<()>) {
    // SAFETY: as the caller says.
    drop(unsafe { Box::from_raw(p.cast::<U::Ext>().as_ptr()) });
}

impl UpperVt {
    pub const fn of<U: Upper>() -> UpperVt {
        UpperVt {
            id: TypeId::of::<U>,
            main: reactor_main::<U>,
            ext_new: ext_new::<U>,
            ext_free: ext_free::<U>,
            drop_plan: U::drop_plan,
            take_note: U::take_note,
            drop_note: U::drop_note,
        }
    }
}

/// The layer of a context without one attached.
#[derive(Debug)]
pub(crate) struct NoUpper;

pub(crate) static NO_UPPER: UpperVt = UpperVt::of::<NoUpper>();

impl Upper for NoUpper {
    type Global = ();
    type Local = ();
    type Ext = ();

    fn ext_new(_g: Option<&()>) {}
    fn start(_r: &mut ShimReactor) {}
    fn incoming(_r: &mut ShimReactor, (): &mut (), _pdu: &mut [u8]) -> Verdict {
        Verdict::default()
    }
    fn on_msg(_r: &mut ShimReactor, (): &mut (), _m: NonNull<Msg>) {}
    fn drop_msg(_r: &mut ShimReactor, (): &mut (), _m: NonNull<Msg>) {}
    fn on_batch(_r: &mut ShimReactor, (): &mut ()) {}
    fn pending((): &()) -> bool {
        false
    }
    fn on_cqe(_r: &mut ShimReactor, (): &mut (), _ud: u64, _res: i32) {}
    fn on_stop(_r: &mut ShimReactor, (): &mut ()) {}
    fn on_end(_r: &mut ShimReactor, (): &mut ()) {}
    fn finish_out(_r: &mut ShimReactor, _o: &mut Out) -> bool {
        false
    }
    fn drop_plan(_o: &mut Out, _pool: Option<&mut Pool>) {}
    unsafe fn take_note(_n: NonNull<Node>, _ev: &mut TnSmbrosEvent) -> bool {
        false
    }
    unsafe fn drop_note(_n: NonNull<Node>) {}
}
