// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The open files of smbd. The reactors do file I/O with smbd's descriptor
//! of each file. smbd closes the descriptor only when no job uses it.

use std::ffi::{c_int, c_void};
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use truenas_ros::uring_fs::File;
use truenas_smbros::{Ctx, Note, Poster, lock};

use crate::TN_SMBSRV_IDLE;

/// One job in `OpenFile::state` that smbd gave to a reactor.
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

/// `OpenFile::seq` counts the jobs that are outstanding requests of the
/// open. smbd uses the counts for the channel sequence checks of
/// [MS-SMB2] 3.3.5.2.10. This is one job of the current channel sequence.
const SEQ_CUR: u64 = 1;
const SEQ_CUR_MASK: u64 = 0xff_ffff;
/// One job of an older channel sequence.
const SEQ_OLD: u64 = 1 << 24;
const SEQ_OLD_MASK: u64 = SEQ_CUR_MASK << 24;
/// The epoch counts the changes of the channel sequence. A job counts as
/// current until the epoch changes.
const SEQ_EPOCH_SHIFT: u32 = 48;

fn seq_epoch(v: u64) -> u16 {
    // The shift leaves 16 bits.
    #[allow(clippy::cast_possible_truncation)]
    let e = (v >> SEQ_EPOCH_SHIFT) as u16;
    e
}

/// No position from a read.
const NO_POS: u64 = u64::MAX;

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
    fd: ManuallyDrop<Arc<OwnedFd>>,
    /// The counts of running and pending jobs, and the wait flags.
    state: AtomicU64,
    /// The channel sequence counts. See `SEQ_CUR`.
    seq: AtomicU64,
    /// The end of the last read that returned data, or `NO_POS`.
    pos: AtomicU64,
    /// True if smbd closed the file. Only the thread that runs smbd uses
    /// this flag.
    closed: AtomicBool,
    cookie: u64,
    poster: Poster,
    /// `tn_smbsrv_file_close()` waits on `idle` for the running jobs.
    lock: Mutex<()>,
    idle: Condvar,
}

impl OpenFile {
    pub(crate) fn set_pos(&self, pos: u64) {
        self.pos.store(pos, Ordering::Release);
    }

    /// Move the position of the last read to `*pos`. False if there is none
    /// or `pos` is NULL.
    ///
    /// # Safety
    ///
    /// `pos` is NULL or writable.
    unsafe fn take_pos(&self, pos: *mut u64) -> bool {
        let p = self.pos.swap(NO_POS, Ordering::AcqRel);
        if p == NO_POS || pos.is_null() {
            return false;
        }
        // SAFETY: the caller passes room for a position.
        unsafe { pos.write(p) };
        true
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        // SAFETY: nothing uses `self.fd` after this drop.
        let fd = unsafe { ManuallyDrop::take(&mut self.fd) };
        // Only smbd closes the descriptor. After that, the number can refer
        // to another file. If a job that ended still has a clone, this code
        // leaks the reference. Then no drop closes the descriptor.
        match Arc::try_unwrap(fd) {
            Ok(fd) => {
                let _ = fd.into_raw_fd();
            }
            Err(fd) => std::mem::forget(fd),
        }
    }
}

/// The event for `TN_SMBSRV_IDLE`. The last job of a file ended.
#[derive(Debug)]
struct Idle(Arc<OpenFile>);

impl Note for Idle {
    fn take(self: Box<Self>) -> Option<(c_int, u64, *mut c_void)> {
        // smbd frees the cookie when it closes the file.
        if self.0.closed.load(Ordering::Relaxed) {
            return None;
        }
        Some((TN_SMBSRV_IDLE, self.0.cookie, ptr::null_mut()))
    }
}

/// One job of a file, from `tn_smbsrv_file_hold()`. The file counts the job
/// until the hold is freed. The job is pending until the caller gives the
/// hold to `tn_smbsrv_delegate()`. Then the job is running.
#[derive(Debug)]
pub struct Hold {
    file: Arc<OpenFile>,
    running: bool,
    /// The epoch in which the job counts as current. An old job has an
    /// earlier epoch. None if the job does not count.
    seq: Option<u16>,
}

impl Hold {
    fn new(file: &Arc<OpenFile>) -> Hold {
        file.state.fetch_add(PENDING, Ordering::AcqRel);
        Hold {
            file: Arc::clone(file),
            running: false,
            seq: None,
        }
    }

    pub(crate) fn file(&self) -> &OpenFile {
        &self.file
    }

    /// Count the job as an outstanding request of the open until the hold
    /// drops. `current` is true for the current channel sequence.
    fn count_seq(&mut self, current: bool) {
        if self.seq.is_some() {
            return;
        }
        let one = if current { SEQ_CUR } else { SEQ_OLD };
        let old = self.file.seq.fetch_add(one, Ordering::AcqRel);
        let epoch = seq_epoch(old);
        self.seq = Some(if current {
            epoch
        } else {
            epoch.wrapping_sub(1)
        });
    }

    /// Mark the job as running. Returns the descriptor for the I/O and the
    /// hold. None if smbd closed the file.
    pub(crate) fn start(mut self) -> Option<(File, Hold)> {
        if self.file.closed.load(Ordering::Relaxed) {
            return None;
        }
        // One atomic step moves the job from pending to running. So the
        // count of jobs is never zero in between.
        self.file
            .state
            .fetch_add(RUNNING.wrapping_sub(PENDING), Ordering::AcqRel);
        self.running = true;
        let fd = File::from_shared(Arc::clone(&*self.file.fd));
        Some((fd, self))
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let file = &self.file;
        if let Some(epoch) = self.seq {
            // tn_smbsrv_file_seq_bump() moves the current jobs to the old
            // count. The epoch shows which count has this job.
            let _ =
                file.seq
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                        let one = if seq_epoch(v) == epoch {
                            SEQ_CUR
                        } else {
                            SEQ_OLD
                        };
                        Some(v - one)
                    });
        }
        let one = if self.running { RUNNING } else { PENDING };
        let old = file.state.fetch_sub(one, Ordering::AcqRel);
        if old & JOBS == one && old & WAIT_EVENT != 0 {
            file.poster.post(Box::new(Idle(Arc::clone(file))));
        }
        if self.running
            && old & RUNNING_MASK == RUNNING
            && old & WAIT_BLOCK != 0
        {
            // The waiter has `lock` locked from its check of the count until
            // its wait. So this notification cannot occur between the two.
            let _guard = lock(&file.lock);
            file.idle.notify_all();
        }
    }
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
    let poster = unsafe { (*ctx).poster() };
    // SAFETY: the caller keeps `fd` open. The drop of `OpenFile` does not
    // close it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Arc::into_raw(Arc::new(OpenFile {
        fd: ManuallyDrop::new(Arc::new(fd)),
        state: AtomicU64::new(0),
        seq: AtomicU64::new(0),
        pos: AtomicU64::new(NO_POS),
        closed: AtomicBool::new(false),
        cookie,
        poster,
        lock: Mutex::new(()),
        idle: Condvar::new(),
    }))
    .cast_mut()
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
    // SAFETY: the reference of the caller keeps the file live. This code
    // borrows that reference and does not drop it.
    let file = ManuallyDrop::new(unsafe { Arc::from_raw(file) });
    Box::into_raw(Box::new(Hold::new(&file)))
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
        // SAFETY: the caller transfers ownership of the hold.
        drop(unsafe { Box::from_raw(hold) });
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
    // SAFETY: the caller passes a live hold.
    if let Some(hold) = unsafe { hold.as_mut() } {
        hold.count_seq(current);
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
    // SAFETY: the reference of the caller keeps the file live.
    let v = unsafe { &*file }.seq.load(Ordering::Acquire);
    // The count has 24 bits.
    #[allow(clippy::cast_possible_truncation)]
    let old = ((v & SEQ_OLD_MASK) >> 24) as u32;
    old
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
    // SAFETY: the reference of the caller keeps the file live.
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
    // SAFETY: the reference of the caller keeps the file live. The caller
    // passes room for a position.
    unsafe { (*file).take_pos(pos) }
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
    // SAFETY: the reference of the caller keeps the file live.
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
    // SAFETY: the caller transfers its reference from tn_smbsrv_file_new().
    let file = unsafe { Arc::from_raw(file) };
    // No pending job starts after this. Only the running jobs can still
    // use the descriptor.
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
    // No read runs now. So the position is final.
    // SAFETY: the caller passes NULL or room for a position.
    unsafe { file.take_pos(pos) }
}
