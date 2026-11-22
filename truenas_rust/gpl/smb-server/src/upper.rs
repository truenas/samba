// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hooks of this layer in the shim's reactors.

use std::cell::UnsafeCell;
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use truenas_smbros::{
    BoxList, Conn, EV_UPPER, FreeList, Msg, MsgKind, Node, Out, Pool,
    ShimReactor, TAG_OP, TnSmbrosEvent, Upper, UpperVt, Verdict, split,
};

use crate::crypto::{CryptoOps, open_pdu};
use crate::file::{drop_idle, take_idle};
use crate::job::{self, Job};
use crate::keys::{KeyCache, KeyTable, drop_key_free, take_key_free};
use crate::pending::{Interims, TIMER_ID};
use crate::plan::Plan;

/// The kinds of the event nodes of this layer.
pub(crate) const EV_IDLE: u8 = EV_UPPER;
pub(crate) const EV_KEY_FREE: u8 = EV_UPPER + 1;

#[derive(Debug)]
pub(crate) struct Layer;

pub(crate) static LAYER: UpperVt = UpperVt::of::<Layer>();

#[derive(Debug)]
pub(crate) struct Global {
    pub(crate) ops: Option<CryptoOps>,
    /// The NTSTATUS of each errno, a copy of smbd's table.
    pub(crate) errmap: Arc<[u32]>,
}

#[derive(Debug)]
pub(crate) struct Ext {
    pub(crate) keys: KeyTable,
    pub(crate) ops: Option<CryptoOps>,
    /// Tells the reactor that the table changed.
    keys_msg: UnsafeCell<Msg>,
    /// True while `keys_msg` is in the inbox of the reactor.
    keys_msg_queued: AtomicBool,
}

// SAFETY: the flag gives `keys_msg` to one poster, then to the reactor.
unsafe impl Sync for Ext {}
// SAFETY: as for Sync.
unsafe impl Send for Ext {}

impl Ext {
    /// Tell the reactor that the key table changed, unless the message is
    /// in its inbox already.
    pub(crate) fn post_keys_msg(&self, conn: &Conn) {
        if self
            .keys_msg_queued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let Some(m) = NonNull::new(self.keys_msg.get()) else {
            return;
        };
        // SAFETY: the flag gives this thread the message until the post.
        if !unsafe { conn.post(m) } {
            // The reactor ended. It dropped its cache.
            self.keys_msg_queued.store(false, Ordering::Release);
        }
    }

    fn is_keys_msg(&self, m: NonNull<Msg>) -> bool {
        ptr::eq(m.as_ptr(), self.keys_msg.get())
    }
}

#[derive(Debug)]
pub(crate) struct Local {
    /// Jobs that smbd gave inline and that did not start yet.
    pub(crate) jobs: BoxList<Job>,
    pub(crate) jobs_free: FreeList<Job>,
    pub(crate) interims: Interims,
    pub(crate) keys: KeyCache,
    pub(crate) ops: Option<CryptoOps>,
    pub(crate) errmap: Arc<[u32]>,
}

/// # Safety
///
/// As for `truenas_smbros::split()`.
pub(crate) unsafe fn local_parts(
    r: &mut ShimReactor,
) -> Option<(&mut ShimReactor, &mut Local)> {
    // SAFETY: as the caller says.
    unsafe { split::<Layer>(r) }
}

fn ops_of(r: &ShimReactor) -> Option<CryptoOps> {
    r.h.conn().ext::<Layer>().and_then(|e| e.ops)
}

impl Upper for Layer {
    type Global = Global;
    type Local = Local;
    type Ext = Ext;

    fn ext_new(g: Option<&Global>) -> Ext {
        Ext {
            keys: KeyTable::default(),
            ops: g.and_then(|g| g.ops),
            keys_msg: UnsafeCell::new(Msg::new(MsgKind::Other)),
            keys_msg_queued: AtomicBool::new(false),
        }
    }

    fn start(r: &mut ShimReactor) -> Local {
        let g = r.h.conn().hub().global::<Layer>();
        let ops = g.and_then(|g| g.ops);
        if let Some(init) = ops.and_then(|o| o.thread_init) {
            // SAFETY: tn_smbsrv_attach() requires functions for any thread.
            unsafe { init() };
        }
        Local {
            jobs: BoxList::new(),
            jobs_free: FreeList::new(64),
            interims: Interims::new(),
            keys: KeyCache::default(),
            ops,
            errmap: g.map_or_else(|| Arc::from([]), |g| Arc::clone(&g.errmap)),
        }
    }

    fn incoming(r: &mut ShimReactor, l: &mut Local, pdu: &mut [u8]) -> Verdict {
        let mut v = Verdict::default();
        if let Some(ops) = &l.ops
            && let Some(ext) = r.h.conn().ext::<Layer>()
            && let Some(o) = open_pdu(ops, &mut l.keys, &ext.keys, pdu)
        {
            v.flags = o.flags;
            v.status = o.status;
            v.tag = o.tag;
        }
        v.job = job::delegable(pdu, v.flags);
        v
    }

    fn on_msg(r: &mut ShimReactor, l: &mut Local, m: NonNull<Msg>) {
        // SAFETY: an inbox message is valid until the reactor runs it.
        if unsafe { m.as_ref() }.kind == MsgKind::Job {
            // SAFETY: a job message is the first field of a leaked job.
            let j = unsafe { Box::from_raw(m.cast::<Job>().as_ptr()) };
            job::run(r, l, j);
            return;
        }
        if let Some(ext) = r.h.conn().ext::<Layer>()
            && ext.is_keys_msg(m)
        {
            // A change after this store sends the message again.
            ext.keys_msg_queued.store(false, Ordering::Release);
            l.keys.clear();
        }
    }

    fn drop_msg(r: &mut ShimReactor, l: &mut Local, m: NonNull<Msg>) {
        // SAFETY: as in on_msg().
        if unsafe { m.as_ref() }.kind == MsgKind::Job {
            // SAFETY: as in on_msg().
            let j = unsafe { Box::from_raw(m.cast::<Job>().as_ptr()) };
            job::destroy(r, l, j);
        }
    }

    fn on_batch(r: &mut ShimReactor, l: &mut Local) {
        while let Some(j) = l.jobs.pop() {
            job::run(r, l, j);
        }
    }

    #[inline]
    fn pending(l: &Local) -> bool {
        !l.jobs.is_empty()
    }

    fn on_cqe(r: &mut ShimReactor, l: &mut Local, ud: u64, res: i32) {
        if ud & 7 == TAG_OP {
            // SAFETY: `ud` is the job that job::run() leaked.
            let j = unsafe { Box::from_raw(ud as *mut Job) };
            job::on_done(r, l, j, res);
        } else if (ud >> 3) & 0x1f == TIMER_ID {
            l.interims.on_timer(r, l.ops.as_ref(), ud, res);
        }
    }

    /// Drop the jobs that did not start.
    fn on_stop(r: &mut ShimReactor, l: &mut Local) {
        while let Some(j) = l.jobs.pop() {
            job::destroy(r, l, j);
        }
    }

    fn on_end(_r: &mut ShimReactor, l: &mut Local) {
        l.interims.clear();
        l.jobs_free = FreeList::new(0);
        l.keys.clear();
    }

    /// Sign or encrypt an out of `tn_smbsrv_send_sealed()`.
    fn finish_out(r: &mut ShimReactor, o: &mut Out) -> bool {
        // SAFETY: the plan of an out is from Plan::into_raw().
        let plan = unsafe {
            Plan::from_raw(std::mem::replace(&mut o.plan, ptr::null_mut()))
        };
        o.finish = false;
        ops_of(r).is_some_and(|ops| plan.apply(&ops, o, &mut r.blocks))
    }

    fn drop_plan(o: &mut Out, _pool: Option<&mut Pool>) {
        // SAFETY: as in finish_out().
        drop(unsafe {
            Plan::from_raw(std::mem::replace(&mut o.plan, ptr::null_mut()))
        });
    }

    unsafe fn take_note(n: NonNull<Node>, ev: &mut TnSmbrosEvent) -> bool {
        // SAFETY: the queue gave up the node of this layer.
        match unsafe { n.as_ref() }.kind {
            // SAFETY: the kind tells which object has the node.
            EV_IDLE => unsafe { take_idle(n, ev) },
            EV_KEY_FREE => {
                // SAFETY: as above.
                unsafe { take_key_free(n, ev) };
                true
            }
            _ => false,
        }
    }

    unsafe fn drop_note(n: NonNull<Node>) {
        // SAFETY: as in take_note().
        match unsafe { n.as_ref() }.kind {
            // SAFETY: as in take_note().
            EV_IDLE => unsafe { drop_idle(n) },
            // SAFETY: as in take_note().
            EV_KEY_FREE => unsafe { drop_key_free(n) },
            _ => {}
        }
    }
}
