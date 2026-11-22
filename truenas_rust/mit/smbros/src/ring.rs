// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! An `io_uring` ring on the raw system calls, with SQEs and CQEs used in
//! place as liburing does.

use std::ffi::c_int;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::sys;

pub(crate) const OP_FSYNC: u8 = 3;
pub(crate) const OP_SENDMSG: u8 = 9;
pub(crate) const OP_TIMEOUT: u8 = 11;
pub(crate) const OP_TIMEOUT_REMOVE: u8 = 12;
pub(crate) const OP_ASYNC_CANCEL: u8 = 14;
pub(crate) const OP_READ: u8 = 22;
pub(crate) const OP_WRITE: u8 = 23;
pub(crate) const OP_SEND: u8 = 26;
pub(crate) const OP_RECV: u8 = 27;
pub(crate) const OP_SEND_ZC: u8 = 47;
pub(crate) const OP_SENDMSG_ZC: u8 = 48;

pub(crate) const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub(crate) const IOSQE_ASYNC: u8 = 1 << 4;
pub(crate) const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

pub(crate) const CQE_F_MORE: u32 = 1 << 1;
pub(crate) const CQE_F_NOTIF: u32 = 1 << 3;
pub(crate) const SEND_ZC_REPORT_USAGE: u16 = 1 << 3;
pub(crate) const NOTIF_USAGE_ZC_COPIED: u32 = 1 << 31;
pub(crate) const ASYNC_CANCEL_ANY: u32 = 1 << 2;

const SETUP_CQSIZE: u32 = 1 << 3;
const FEAT_SINGLE_MMAP: u32 = 1 << 0;
const ENTER_GETEVENTS: u32 = 1 << 0;
const SQ_CQ_OVERFLOW: u32 = 1 << 1;
const OFF_SQ_RING: libc::off_t = 0;
const OFF_SQES: libc::off_t = 0x1000_0000;
const REGISTER_FILES: libc::c_uint = 2;

/// `struct io_uring_sqe`. The unions are the fields that the reactors use.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    /// `rw_flags`, `msg_flags`, `timeout_flags` or `cancel_flags`.
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub file_index: u32,
    pub addr3: u64,
    pub pad: u64,
}

const _: () = assert!(mem::size_of::<Sqe>() == 64);
const _: () = assert!(mem::size_of::<Cqe>() == 16);
const _: () = assert!(mem::size_of::<Params>() == 120);
// map() reads the ring offsets from these members.
const _: () = assert!(mem::offset_of!(Params, sq_off) == 40);
const _: () = assert!(mem::offset_of!(Params, cq_off) == 80);
const _: () = assert!(mem::size_of::<SqOffsets>() == 40);
const _: () = assert!(mem::size_of::<CqOffsets>() == 40);

impl Sqe {
    /// The opcodes and flags that the layer above the shim uses.
    pub const OP_FSYNC: u8 = OP_FSYNC;
    pub const OP_TIMEOUT: u8 = OP_TIMEOUT;
    pub const OP_TIMEOUT_REMOVE: u8 = OP_TIMEOUT_REMOVE;
    pub const OP_READ: u8 = OP_READ;
    pub const OP_WRITE: u8 = OP_WRITE;
    pub const ASYNC: u8 = IOSQE_ASYNC;

    pub const ZERO: Sqe = Sqe {
        opcode: 0,
        flags: 0,
        ioprio: 0,
        fd: 0,
        off: 0,
        addr: 0,
        len: 0,
        op_flags: 0,
        user_data: 0,
        buf_index: 0,
        personality: 0,
        file_index: 0,
        addr3: 0,
        pad: 0,
    };
}

/// `struct io_uring_cqe`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct SqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct CqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqOffsets,
    cq_off: CqOffsets,
}

#[derive(Debug)]
struct Map {
    at: *mut u8,
    len: usize,
}

impl Map {
    fn new(fd: c_int, len: usize, off: libc::off_t) -> Result<Map, c_int> {
        // SAFETY: the kernel maps a new range that no Rust object uses.
        let at = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                off,
            )
        };
        if at == libc::MAP_FAILED {
            return Err(sys::errno());
        }
        Ok(Map { at: at.cast(), len })
    }

    fn at<T>(&self, off: u32) -> *mut T {
        // SAFETY: the kernel gives offsets within the map.
        unsafe { self.at.add(off as usize) }.cast()
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        // SAFETY: the map is from mmap() and nothing uses it after this.
        unsafe { libc::munmap(self.at.cast(), self.len) };
    }
}

/// An `io_uring` ring. Only its reactor thread uses it.
#[derive(Debug)]
pub struct Ring {
    sq_head: *const AtomicU32,
    sq_ktail: *const AtomicU32,
    sq_flags: *const AtomicU32,
    sq_mask: u32,
    sq_entries: u32,
    sqes: *mut Sqe,
    /// The tail after the last SQE that the reactor wrote.
    sq_tail: u32,
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const Cqe,
    _sq_map: Map,
    _entry_map: Map,
    // The last field, so it drops after the maps.
    fd: OwnedFd,
}

impl Ring {
    /// A ring with `entries` submissions and `cq_entries` completions.
    ///
    /// # Errors
    ///
    /// The errno of the failed call.
    pub fn new(entries: u32, cq_entries: u32) -> Result<Ring, c_int> {
        let mut p = Params {
            flags: SETUP_CQSIZE,
            cq_entries,
            ..Params::default()
        };
        // SAFETY: io_uring_setup writes the params of the new ring.
        let rc = unsafe {
            libc::syscall(libc::SYS_io_uring_setup, entries, &raw mut p)
        };
        if rc < 0 {
            return Err(sys::errno());
        }
        let fd = c_int::try_from(rc).map_err(|_| libc::EINVAL)?;
        // SAFETY: the ring descriptor is new and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::map(fd, &p)
    }

    fn map(owned: OwnedFd, p: &Params) -> Result<Ring, c_int> {
        let fd = owned.as_raw_fd();
        // Every kernel with the operations of the reactors maps both rings
        // at once.
        if p.features & FEAT_SINGLE_MMAP == 0 {
            return Err(libc::ENOSYS);
        }
        let sq_len = (p.sq_off.array + p.sq_entries * 4) as usize;
        let cq_len = p.cq_off.cqes as usize
            + p.cq_entries as usize * mem::size_of::<Cqe>();
        let sq_map = Map::new(fd, sq_len.max(cq_len), OFF_SQ_RING)?;
        let entry_map = Map::new(
            fd,
            p.sq_entries as usize * mem::size_of::<Sqe>(),
            OFF_SQES,
        )?;
        let cq = &sq_map;
        let array: *mut u32 = sq_map.at(p.sq_off.array);
        for i in 0..p.sq_entries {
            // SAFETY: the array has sq_entries slots.
            unsafe { array.add(i as usize).write_volatile(i) };
        }
        let sq_ktail: *const AtomicU32 = sq_map.at(p.sq_off.tail);
        Ok(Ring {
            sq_head: sq_map.at(p.sq_off.head),
            sq_ktail,
            sq_flags: sq_map.at(p.sq_off.flags),
            // SAFETY: the kernel wrote these values at setup.
            sq_mask: unsafe { *sq_map.at::<u32>(p.sq_off.ring_mask) },
            sq_entries: p.sq_entries,
            sqes: entry_map.at.cast(),
            // SAFETY: the tail is an AtomicU32 in the map.
            sq_tail: unsafe { (*sq_ktail).load(Ordering::Relaxed) },
            cq_head: cq.at(p.cq_off.head),
            cq_tail: cq.at(p.cq_off.tail),
            // SAFETY: as for sq_mask.
            cq_mask: unsafe { *cq.at::<u32>(p.cq_off.ring_mask) },
            cqes: cq.at(p.cq_off.cqes),
            _sq_map: sq_map,
            _entry_map: entry_map,
            fd: owned,
        })
    }

    pub fn fd(&self) -> c_int {
        self.fd.as_raw_fd()
    }

    /// Register `fds` as the fixed files of the ring.
    ///
    /// # Errors
    ///
    /// The errno of the failed call.
    pub fn register_files(&self, fds: &[c_int]) -> Result<(), c_int> {
        // SAFETY: the call reads `fds.len()` descriptors.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd(),
                REGISTER_FILES,
                fds.as_ptr(),
                libc::c_uint::try_from(fds.len()).unwrap_or(0),
            )
        };
        if rc < 0 { Err(sys::errno()) } else { Ok(()) }
    }

    /// Write `s` into a free slot of the submission queue. False if full.
    ///
    /// # Safety
    ///
    /// The memory and the objects that `s` names stay valid, and nothing
    /// else uses the memory that the kernel writes, until the completion
    /// of `s`.
    #[inline]
    pub unsafe fn push(&mut self, s: Sqe) -> bool {
        // SAFETY: the head is an AtomicU32 in the map.
        let head = unsafe { (*self.sq_head).load(Ordering::Acquire) };
        if self.sq_tail.wrapping_sub(head) >= self.sq_entries {
            return false;
        }
        // SAFETY: the kernel does not read the slot until the tail moves.
        unsafe {
            self.sqes
                .add((self.sq_tail & self.sq_mask) as usize)
                .write(s);
        }
        self.sq_tail = self.sq_tail.wrapping_add(1);
        true
    }

    fn enter(&mut self, wait: u32) -> c_int {
        // SAFETY: the tail is an AtomicU32 in the map.
        unsafe { (*self.sq_ktail).store(self.sq_tail, Ordering::Release) };
        // SAFETY: as above.
        let head = unsafe { (*self.sq_head).load(Ordering::Acquire) };
        let pending = self.sq_tail.wrapping_sub(head);
        let mut flags = 0;
        if wait > 0 {
            flags |= ENTER_GETEVENTS;
        } else {
            // SAFETY: the flags are an AtomicU32 in the map.
            let f = unsafe { (*self.sq_flags).load(Ordering::Relaxed) };
            if f & SQ_CQ_OVERFLOW != 0 {
                flags |= ENTER_GETEVENTS;
            } else if pending == 0 {
                return 0;
            }
        }
        // SAFETY: without a signal mask, the call reads no caller memory.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                self.fd(),
                pending,
                wait,
                flags,
                ptr::null::<libc::c_void>(),
                0_usize,
            )
        };
        if rc < 0 {
            -sys::errno()
        } else {
            c_int::try_from(rc).unwrap_or(c_int::MAX)
        }
    }

    pub fn submit(&mut self) -> c_int {
        self.enter(0)
    }

    /// Submit and wait for `n` completions.
    pub fn submit_and_wait(&mut self, n: u32) -> c_int {
        self.enter(n)
    }

    /// The position of the first completion that the reactor has not read.
    #[inline]
    pub fn cq_head(&self) -> u32 {
        // SAFETY: the head is an AtomicU32 in the map.
        unsafe { (*self.cq_head).load(Ordering::Relaxed) }
    }

    /// The position after the last completion of the kernel.
    #[inline]
    pub fn cq_tail(&self) -> u32 {
        // SAFETY: the tail is an AtomicU32 in the map.
        unsafe { (*self.cq_tail).load(Ordering::Acquire) }
    }

    #[inline]
    pub fn cq_ready(&self) -> bool {
        self.cq_tail() != self.cq_head()
    }

    /// The completion at position `i`, read in place.
    ///
    /// # Safety
    ///
    /// `i` is from the head up to the tail.
    #[inline]
    pub unsafe fn cqe(&self, i: u32) -> Cqe {
        // SAFETY: the kernel does not reuse `i` until the head passes it.
        unsafe { *self.cqes.add((i & self.cq_mask) as usize) }
    }

    /// Give the completions before position `head` back to the kernel.
    #[inline]
    pub fn cq_set_head(&mut self, head: u32) {
        // SAFETY: as in cq_head().
        unsafe { (*self.cq_head).store(head, Ordering::Release) };
    }
}
