// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The open files of smbd that jobs use, and the holds of the jobs.

use std::cell::RefCell;
use std::ffi::c_int;
use std::mem::ManuallyDrop;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use truenas_smbros::{Ctx, HubRef, Node, TnSmbrosEvent, lock, try_box};

use crate::TN_SMBSRV_IDLE;
use crate::upper::EV_IDLE;

/// One job in the state of a file that smbd gave to a reactor.
const RUNNING: u64 = 1;
const RUNNING_MASK: u64 = (1 << 30) - 1;
/// One job that smbd did not give to a reactor yet.
const PENDING: u64 = 1 << 30;
const PENDING_MASK: u64 = RUNNING_MASK << 30;
const JOBS: u64 = RUNNING_MASK | PENDING_MASK;
/// smbd waits for `TN_SMBSRV_IDLE` after the last job.
const WAIT_EVENT: u64 = 1 << 62;
/// A thread of smbd blocks until the last running job ends.
const WAIT_BLOCK: u64 = 1 << 63;

/// One outstanding request of the current channel sequence, for the checks
/// of [MS-SMB2] 3.3.5.2.10.
const SEQ_CUR: u64 = 1;
const SEQ_CUR_MASK: u64 = 0xff_ffff;
/// One job of an older channel sequence.
const SEQ_OLD: u64 = 1 << 24;
const SEQ_OLD_MASK: u64 = SEQ_CUR_MASK << 24;
/// The epoch counts the changes of the channel sequence.
const SEQ_EPOCH_SHIFT: u32 = 48;

fn seq_epoch(v: u64) -> u16 {
    (v >> SEQ_EPOCH_SHIFT) as u16
}

/// No position from a read.
const NO_POS: u64 = u64::MAX;
/// The holds that one thread keeps for reuse.
const CACHE_MAX: usize = 64;

/// An open file of the caller, from `tn_smbsrv_file_new()`. The reactors
/// do file I/O with the descriptor of the caller. The file counts each job
/// from `tn_smbsrv_file_hold()` until the hold is freed. A job is pending
/// until the caller gives its hold to `tn_smbsrv_delegate()`. Then the job
/// is running. The caller closes the descriptor only after
/// `tn_smbsrv_file_close()`. So the number cannot refer to another file
/// while a job uses it.
#[derive(Debug)]
pub struct OpenFile {
    /// smbd's descriptor. Only smbd closes it.
    fd: c_int,
    /// The counts of running and pending jobs, and the wait flags.
    state: AtomicU64,
    seq: AtomicU64,
    /// The end of the last read that returned data, or `NO_POS`.
    pos: AtomicU64,
    /// True if smbd closed the file.
    closed: AtomicBool,
    cookie: u64,
    hub: HubRef,
    /// `tn_smbsrv_file_close()` waits on `idle` for the running jobs.
    lock: Mutex<()>,
    idle: Condvar,
}

impl OpenFile {
    pub(crate) fn fd(&self) -> c_int {
        self.fd
    }

    pub(crate) fn set_pos(&self, pos: u64) {
        self.pos.store(pos, Ordering::Release);
    }

    fn take_pos(&self) -> Option<u64> {
        let p = self.pos.swap(NO_POS, Ordering::AcqRel);
        (p != NO_POS).then_some(p)
    }
}

/// The event for `TN_SMBSRV_IDLE`. The last job of a file ended.
#[repr(C)]
#[derive(Debug)]
struct IdleNote {
    node: Node,
    file: Arc<OpenFile>,
}

/// Fill `ev` from an IDLE node. False if smbd closed the file.
///
/// # Safety
///
/// `n` is the node of a leaked `IdleNote`.
pub(crate) unsafe fn take_idle(
    n: NonNull<Node>,
    ev: &mut TnSmbrosEvent,
) -> bool {
    // SAFETY: as the caller says.
    let i = unsafe { Box::from_raw(n.cast::<IdleNote>().as_ptr()) };
    // smbd frees the cookie when it closes the file.
    if i.file.closed.load(Ordering::Relaxed) {
        return false;
    }
    *ev = TnSmbrosEvent::bare(i.file.cookie, TN_SMBSRV_IDLE);
    true
}

/// Free an IDLE node that smbd does not get.
///
/// # Safety
///
/// As for `take_idle()`.
pub(crate) unsafe fn drop_idle(n: NonNull<Node>) {
    // SAFETY: as the caller says.
    drop(unsafe { Box::from_raw(n.cast::<IdleNote>().as_ptr()) });
}

/// One job of a file, from `tn_smbsrv_file_hold()`. The file counts the job
/// until the hold is freed. The job is pending until the caller gives the
/// hold to `tn_smbsrv_delegate()`. Then the job is running.
#[derive(Debug)]
pub struct Hold {
    file: Option<Arc<OpenFile>>,
    running: bool,
    /// True if the job counts as an outstanding request of the open.
    counted: bool,
    /// The epoch in which the job counts as current.
    epoch: u16,
}

// smbd holds a hold as a pointer to its box, so the cache keeps boxes.
thread_local! {
    #[allow(clippy::vec_box)]
    static HOLDS: RefCell<Vec<Box<Hold>>> = const { RefCell::new(Vec::new()) };
}

impl Hold {
    /// A new pending job of `file`. None without memory.
    fn new(file: &Arc<OpenFile>) -> Option<Box<Hold>> {
        let cached = HOLDS.try_with(|c| c.borrow_mut().pop()).ok().flatten();
        let mut h = match cached {
            Some(h) => h,
            None => try_box(|| Hold {
                file: None,
                running: false,
                counted: false,
                epoch: 0,
            })?,
        };
        file.state.fetch_add(PENDING, Ordering::AcqRel);
        h.file = Some(Arc::clone(file));
        h.running = false;
        h.counted = false;
        h.epoch = 0;
        Some(h)
    }

    pub(crate) fn file(&self) -> Option<&OpenFile> {
        self.file.as_deref()
    }

    fn count_seq(&mut self, current: bool) {
        let Some(f) = &self.file else {
            return;
        };
        if self.counted {
            return;
        }
        let one = if current { SEQ_CUR } else { SEQ_OLD };
        let e = seq_epoch(f.seq.fetch_add(one, Ordering::AcqRel));
        self.epoch = if current { e } else { e.wrapping_sub(1) };
        self.counted = true;
    }

    /// Mark the job as running. False if smbd closed the file.
    pub(crate) fn start(&mut self) -> bool {
        let Some(f) = &self.file else {
            return false;
        };
        if f.closed.load(Ordering::Relaxed) {
            return false;
        }
        // One step, so the count of jobs is never zero in between.
        f.state
            .fetch_add(RUNNING.wrapping_sub(PENDING), Ordering::AcqRel);
        self.running = true;
        true
    }
}

/// Free the hold `h`. The last job of its file posts the IDLE event or
/// wakes `tn_smbsrv_file_close()`.
pub(crate) fn hold_free(mut h: Box<Hold>) {
    let Some(f) = h.file.take() else {
        return;
    };
    if h.counted {
        // The epoch tells if tn_smbsrv_file_seq_bump() made the job old.
        let _ = f.seq.try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
            let one = if seq_epoch(v) == h.epoch {
                SEQ_CUR
            } else {
                SEQ_OLD
            };
            Some(v - one)
        });
    }
    let one = if h.running { RUNNING } else { PENDING };
    let old = f.state.fetch_sub(one, Ordering::AcqRel);
    if old & JOBS == one
        && old & WAIT_EVENT != 0
        && let Some(n) = try_box(|| IdleNote {
            node: Node::new(EV_IDLE),
            file: Arc::clone(&f),
        })
    {
        let n = Box::leak(n);
        // SAFETY: the node starts a leaked IdleNote, as its kind tells.
        unsafe { f.hub.hub().post(NonNull::from(&mut n.node)) };
    }
    if h.running && old & RUNNING_MASK == RUNNING && old & WAIT_BLOCK != 0 {
        // The waiter holds the lock from its check to its wait.
        let _guard = lock(&f.lock);
        f.idle.notify_all();
    }
    drop(f);
    // An ending thread has no cache. Then the hold is freed.
    let _ = HOLDS.try_with(|c| {
        let mut c = c.borrow_mut();
        if c.len() < CACHE_MAX {
            c.push(h);
        }
    });
}

/// Make the open file of `fd`. The IDLE events of the file have `cookie`.
/// Free the file with `tn_smbsrv_file_close()`. NULL if `fd` is negative.
///
/// # Safety
///
/// `ctx` is from `tn_smbros_ctx_new()`. The caller keeps `fd` open until
/// `tn_smbsrv_file_close()` returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_file_new(
    ctx: *mut Ctx,
    fd: c_int,
    cookie: u64,
) -> *mut OpenFile {
    if fd < 0 {
        return ptr::null_mut();
    }
    // SAFETY: the caller passes a live context.
    let hub = unsafe { &*ctx }.hub_ref();
    Arc::into_raw(Arc::new(OpenFile {
        fd,
        state: AtomicU64::new(0),
        seq: AtomicU64::new(0),
        pos: AtomicU64::new(NO_POS),
        closed: AtomicBool::new(false),
        cookie,
        hub,
        lock: Mutex::new(()),
        idle: Condvar::new(),
    }))
    .cast_mut()
}

/// The file of smbd's reference, without taking the reference.
///
/// # Safety
///
/// `file` is from `tn_smbsrv_file_new()` and smbd did not close it.
unsafe fn file_ref(file: *const OpenFile) -> ManuallyDrop<Arc<OpenFile>> {
    // SAFETY: as the caller says. ManuallyDrop keeps smbd's reference.
    ManuallyDrop::new(unsafe { Arc::from_raw(file) })
}

/// Count a new pending job of `file`. Returns the hold of the job. Give the
/// hold to `tn_smbsrv_delegate()`, or free it with `tn_smbsrv_hold_free()`.
/// The hold is still valid after `tn_smbsrv_file_close()`.
///
/// # Safety
///
/// `file` is from `tn_smbsrv_file_new()`. The caller did not call
/// `tn_smbsrv_file_close()` on it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_file_hold(
    file: *const OpenFile,
) -> *mut Hold {
    // SAFETY: as the caller says.
    let f = unsafe { file_ref(file) };
    Hold::new(&f).map_or(ptr::null_mut(), Box::into_raw)
}

/// Free a hold that the caller did not delegate. NULL is allowed.
///
/// # Safety
///
/// `hold` is NULL or is from `tn_smbsrv_file_hold()`. The caller does not
/// use it again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_hold_free(hold: *mut Hold) {
    if !hold.is_null() {
        // SAFETY: the caller gives up its hold, a leaked box.
        hold_free(unsafe { Box::from_raw(hold) });
    }
}

/// Count the job of `hold` as an outstanding request of the open. smbd uses
/// this count for the channel sequence checks of [MS-SMB2] 3.3.5.2.10.
/// `current` is true for the current channel sequence of the open. It is
/// false for an older one. The count lasts until the hold is freed. The
/// caller then does not count the request itself.
///
/// # Safety
///
/// `hold` is from `tn_smbsrv_file_hold()`. The caller still owns it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_hold_seq(hold: *mut Hold, current: bool) {
    // SAFETY: the caller passes NULL or its hold.
    if let Some(h) = unsafe { hold.as_mut() } {
        h.count_seq(current);
    }
}

/// The number of jobs of `file` that count as outstanding requests of
/// older channel sequences.
///
/// # Safety
///
/// `file` is from `tn_smbsrv_file_new()`. The caller did not call
/// `tn_smbsrv_file_close()` on it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_file_seq_old(file: *const OpenFile) -> u32 {
    // SAFETY: the caller passes a live file.
    let v = unsafe { &*file }.seq.load(Ordering::Acquire);
    u32::try_from((v & SEQ_OLD_MASK) >> 24).unwrap_or(u32::MAX)
}

/// Call this when the channel sequence of the open changes. The jobs that
/// counted as current then count as old.
///
/// # Safety
///
/// `file` is from `tn_smbsrv_file_new()`. The caller did not call
/// `tn_smbsrv_file_close()` on it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_file_seq_bump(file: *const OpenFile) {
    // SAFETY: the caller passes a live file.
    let file = unsafe { &*file };
    let _ = file
        .seq
        .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
            let cur = v & SEQ_CUR_MASK;
            let old = (v & SEQ_OLD_MASK) >> 24;
            let epoch = u64::from(seq_epoch(v).wrapping_add(1));
            Some((epoch << SEQ_EPOCH_SHIFT) | ((old + cur) << 24))
        });
}

/// Write the new position of the open to `*pos`. The position is the end of
/// the last delegated read that returned data. False if no such read ended
/// after the last call.
///
/// # Safety
///
/// `file` is from `tn_smbsrv_file_new()`. The caller did not call
/// `tn_smbsrv_file_close()` on it. `pos` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_file_take_pos(
    file: *const OpenFile,
    pos: *mut u64,
) -> bool {
    // SAFETY: the caller passes a live file.
    let Some(p) = unsafe { &*file }.take_pos() else {
        return false;
    };
    if pos.is_null() {
        return false;
    }
    // SAFETY: the caller passes room for the position.
    unsafe { pos.write(p) };
    true
}

/// True if `file` has pending or running jobs. After this call,
/// `tn_smbros_next()` returns `TN_SMBSRV_IDLE` with the cookie of `file`
/// each time the last job of `file` ends. The reactor queues the reply of
/// each job before that event. `tn_smbros_next()` drops the IDLE events of
/// a closed file.
///
/// # Safety
///
/// `file` is from `tn_smbsrv_file_new()`. The caller did not call
/// `tn_smbsrv_file_close()` on it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_file_busy(file: *const OpenFile) -> bool {
    // SAFETY: the caller passes a live file.
    let file = unsafe { &*file };
    file.state.fetch_or(WAIT_EVENT, Ordering::AcqRel) & JOBS != 0
}

/// Close `file`. This call blocks until the running jobs of `file` end.
/// After that, the caller can close the descriptor. A pending job that the
/// caller delegates later does no file I/O. The reactor answers it with
/// `NT_STATUS_FILE_CLOSED`. `pos` can be NULL. True if this call wrote a
/// position to `*pos`. See `tn_smbsrv_file_take_pos()`.
///
/// # Safety
///
/// `file` is from `tn_smbsrv_file_new()`. The caller does not use it after
/// this call. `pos` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbsrv_file_close(
    file: *const OpenFile,
    pos: *mut u64,
) -> bool {
    if file.is_null() {
        return false;
    }
    // SAFETY: the caller gives up its reference.
    let file = unsafe { Arc::from_raw(file) };
    // No pending job starts after this.
    file.closed.store(true, Ordering::Relaxed);
    let old = file.state.fetch_or(WAIT_BLOCK, Ordering::AcqRel);
    if old & RUNNING_MASK != 0 {
        let mut guard = lock(&file.lock);
        while file.state.load(Ordering::Acquire) & RUNNING_MASK != 0 {
            guard = file
                .idle
                .wait(guard)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
    // No read runs now, so the position is final.
    let Some(p) = file.take_pos() else {
        return false;
    };
    if pos.is_null() {
        return false;
    }
    // SAFETY: the caller passes room for the position.
    unsafe { pos.write(p) };
    true
}
