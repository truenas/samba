// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! Small wrappers of the libc calls that the reactors use.

use std::ffi::c_int;

pub(crate) const NS_PER_SEC: u64 = 1_000_000_000;
pub(crate) const NS_PER_MS: u64 = 1_000_000;

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec to `ts`.
    unsafe { libc::clock_gettime(clock, &raw mut ts) };
    u64::try_from(ts.tv_sec).unwrap_or(0) * NS_PER_SEC
        + u64::try_from(ts.tv_nsec).unwrap_or(0)
}

/// Monotonic time in nanoseconds.
pub fn now_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

/// Cheaper than `now_ns()`, in steps of a scheduler tick.
pub(crate) fn coarse_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC_COARSE)
}

/// CPU time of the calling thread in nanoseconds.
pub fn thread_cpu_ns() -> u64 {
    clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
}

pub(crate) fn sleep_ns(ns: u64) {
    std::thread::sleep(std::time::Duration::from_nanos(ns));
}

/// Write 1 to the eventfd `fd`. Errors do not matter for a wake.
pub fn poke(fd: c_int) {
    let one: u64 = 1;
    // SAFETY: the write reads the 8 bytes of `one`.
    unsafe { libc::write(fd, (&raw const one).cast(), 8) };
}

/// Clear the counter of the eventfd `fd`. False if the read failed.
pub fn drain_eventfd(fd: c_int) -> bool {
    let mut v: u64 = 0;
    // SAFETY: the read writes at most 8 bytes into `v`.
    unsafe { libc::read(fd, (&raw mut v).cast(), 8) == 8 }
}

/// A new eventfd with `flags` and `EFD_CLOEXEC`.
///
/// # Errors
///
/// The errno of `eventfd()`.
pub fn eventfd(flags: c_int) -> Result<c_int, c_int> {
    // SAFETY: eventfd has no pointer arguments.
    let fd = unsafe { libc::eventfd(0, flags | libc::EFD_CLOEXEC) };
    if fd < 0 { Err(errno()) } else { Ok(fd) }
}

pub fn errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

pub fn gettid() -> libc::pid_t {
    // SAFETY: gettid has no arguments.
    unsafe { libc::gettid() }
}

/// The `pthread_t` of the calling thread as a number.
#[inline]
pub(crate) fn thread_self() -> usize {
    // pthread_t and usize have 64 bits on the x86-64 target of the tree.
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: pthread_self has no arguments.
    unsafe {
        libc::pthread_self() as usize
    }
}

/// Block all signals of the calling thread but SIGSEGV and SIGBUS, so the
/// owner's fault handler still runs. Returns the old mask.
pub fn block_signals() -> libc::sigset_t {
    // glibc writes only the first 8 bytes of a sigset_t.
    // SAFETY: zeros are a valid sigset_t.
    let (mut set, mut old): (libc::sigset_t, libc::sigset_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    // SAFETY: both sets are live.
    unsafe {
        libc::sigfillset(&raw mut set);
        libc::sigdelset(&raw mut set, libc::SIGSEGV);
        libc::sigdelset(&raw mut set, libc::SIGBUS);
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const set, &raw mut old);
    }
    old
}

pub fn restore_signals(old: &libc::sigset_t) {
    // SAFETY: `old` is a mask from block_signals().
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, old, std::ptr::null_mut());
    }
}

const IORING_REGISTER_PERSONALITY: libc::c_uint = 9;

/// Register the caller's credentials as a personality of the ring. The id
/// or -errno.
pub(crate) fn register_personality(ring_fd: c_int) -> c_int {
    // SAFETY: this register operation takes no argument memory.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring_fd,
            IORING_REGISTER_PERSONALITY,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    if rc < 0 {
        -errno()
    } else {
        c_int::try_from(rc).unwrap_or(-libc::EINVAL)
    }
}
