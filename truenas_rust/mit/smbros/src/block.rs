// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! Data blocks, the block pool of a reactor and free lists of objects.

use std::alloc::{self, Layout};
use std::mem;
use std::ptr::{self, NonNull};

/// The bytes before the data of a block.
const HDR: usize = 64;
const NCLASS: usize = 12;

/// The 4 KiB hold the headers of a READ reply or of a WRITE.
const fn cap_of(class: u8) -> u32 {
    ((16 * 1024) << class) + 4 * 1024
}

/// The smallest class with room for `size` bytes.
fn class_for(size: usize) -> Option<u8> {
    let mut c = 0;
    while usize::from(c) < NCLASS {
        if cap_of(c) as usize >= size {
            return Some(c);
        }
        c += 1;
    }
    None
}

#[repr(C)]
struct Hdr {
    next: *mut Hdr,
    cap: u32,
    class: u8,
}

const _: () = assert!(mem::size_of::<Hdr>() <= HDR);

fn layout(cap: u32) -> Layout {
    // The size is below isize::MAX and 16 is a power of two.
    Layout::from_size_align(HDR + cap as usize, 16).unwrap()
}

/// A data block. It owns its allocation.
#[derive(Debug)]
pub struct Block(NonNull<Hdr>);

// SAFETY: a block is plain memory that one owner uses at a time.
unsafe impl Send for Block {}

impl Block {
    #[cold]
    #[inline(never)]
    fn alloc(class: u8) -> Option<Block> {
        let cap = cap_of(class);
        // SAFETY: the layout has a size above zero.
        let raw = unsafe { alloc::alloc(layout(cap)) };
        // The layout has an alignment of 16, which suits the header.
        #[allow(clippy::cast_ptr_alignment)]
        let p = NonNull::new(raw.cast::<Hdr>())?;
        // SAFETY: the allocation has room for the header.
        unsafe {
            p.as_ptr().write(Hdr {
                next: ptr::null_mut(),
                cap,
                class,
            });
        }
        Some(Block(p))
    }

    #[inline]
    pub fn cap(&self) -> u32 {
        // SAFETY: the header of an owned block is valid.
        unsafe { (*self.0.as_ptr()).cap }
    }

    #[inline]
    pub fn class(&self) -> u8 {
        // SAFETY: as in cap().
        unsafe { (*self.0.as_ptr()).class }
    }

    /// The data of the block, `cap()` bytes.
    #[inline]
    pub fn data(&self) -> *mut u8 {
        // SAFETY: the data starts HDR bytes into the allocation.
        unsafe { self.0.as_ptr().cast::<u8>().add(HDR) }
    }

    /// # Safety
    ///
    /// `len` is at most `cap()`. The bytes are initialized, and the kernel
    /// does not write them while the slice lives.
    #[inline]
    pub unsafe fn bytes_mut(&mut self, len: usize) -> &mut [u8] {
        // SAFETY: as the caller says.
        unsafe { std::slice::from_raw_parts_mut(self.data(), len) }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        let cap = self.cap();
        // SAFETY: the block owns its allocation of this layout.
        unsafe { alloc::dealloc(self.0.as_ptr().cast(), layout(cap)) };
    }
}

/// The blocks that a reactor keeps for reuse, up to `budget` bytes.
#[derive(Debug)]
pub struct Pool {
    free: [*mut Hdr; NCLASS],
    held: usize,
    budget: usize,
}

impl Pool {
    pub fn new(budget: usize) -> Pool {
        Pool {
            free: [ptr::null_mut(); NCLASS],
            held: 0,
            budget,
        }
    }

    #[inline]
    pub fn get_class(&mut self, class: u8) -> Option<Block> {
        let slot = &mut self.free[class as usize];
        let Some(p) = NonNull::new(*slot) else {
            return Block::alloc(class);
        };
        // SAFETY: each pointer of a free list is a block that put() kept.
        unsafe {
            *slot = (*p.as_ptr()).next;
            (*p.as_ptr()).next = ptr::null_mut();
            self.held -= (*p.as_ptr()).cap as usize;
        }
        Some(Block(p))
    }

    /// A block with room for `size` bytes, or None.
    #[inline]
    pub fn get(&mut self, size: usize) -> Option<Block> {
        self.get_class(class_for(size)?)
    }

    #[inline]
    pub fn put(&mut self, b: Block) {
        let cap = b.cap() as usize;
        if self.held + cap > self.budget {
            return;
        }
        let p = b.0;
        mem::forget(b);
        let slot = &mut self.free[usize::from(
            // SAFETY: the header of an owned block is valid.
            unsafe { (*p.as_ptr()).class },
        )];
        // SAFETY: the pool owns the block now.
        unsafe { (*p.as_ptr()).next = *slot };
        *slot = p.as_ptr();
        self.held += cap;
    }

    /// The bytes of the blocks that the pool keeps.
    pub fn held(&self) -> usize {
        self.held
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        for slot in &mut self.free {
            while let Some(p) = NonNull::new(*slot) {
                // SAFETY: as in get_class().
                *slot = unsafe { (*p.as_ptr()).next };
                drop(Block(p));
            }
        }
        self.held = 0;
    }
}

/// Objects that one thread reuses, up to `max`.
#[derive(Debug)]
pub struct FreeList<T> {
    v: Vec<Box<T>>,
    max: usize,
}

impl<T> FreeList<T> {
    pub fn new(max: usize) -> Self {
        FreeList {
            v: Vec::with_capacity(max),
            max,
        }
    }

    /// The caller sets the fields of the object.
    #[inline]
    pub fn take(&mut self) -> Option<Box<T>> {
        self.v.pop()
    }

    #[inline]
    pub fn put(&mut self, b: Box<T>) {
        if self.v.len() < self.max {
            self.v.push(b);
        }
    }
}

/// A new box with the value of `f`, or None without memory.
#[cold]
#[inline(never)]
pub fn try_box<T>(f: impl FnOnce() -> T) -> Option<Box<T>> {
    let l = Layout::new::<T>();
    if l.size() == 0 {
        return Some(Box::new(f()));
    }
    // SAFETY: the layout has a size above zero.
    let p = NonNull::new(unsafe { alloc::alloc(l) }.cast::<T>())?;
    // SAFETY: the global allocator made `p` with the layout of T.
    unsafe {
        p.as_ptr().write(f());
        Some(Box::from_raw(p.as_ptr()))
    }
}
