// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! Intrusive lists, and a stack that any thread can push to.

use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The link of an object in a list.
#[repr(C)]
#[derive(Debug)]
pub struct Link {
    next: *mut Link,
}

impl Link {
    pub const fn new() -> Self {
        Link {
            next: ptr::null_mut(),
        }
    }
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}

/// A node of the event queue. `kind` tells which object has the node.
#[repr(C)]
#[derive(Debug, Default)]
pub struct Node {
    pub link: Link,
    pub kind: u8,
}

impl Node {
    pub const fn new(kind: u8) -> Self {
        Node {
            link: Link::new(),
            kind,
        }
    }
}

/// The kinds of message that other threads give a reactor.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgKind {
    Send,
    Job,
    Other,
}

/// The first field of an object in the inbox of a reactor.
#[repr(C)]
#[derive(Debug)]
pub struct Msg {
    pub link: Link,
    pub kind: MsgKind,
}

impl Msg {
    pub const fn new(kind: MsgKind) -> Self {
        Msg {
            link: Link::new(),
            kind,
        }
    }
}

/// A FIFO list of links that one thread uses.
#[derive(Debug)]
pub struct List {
    head: *mut Link,
    tail: *mut Link,
}

impl Default for List {
    fn default() -> Self {
        Self::new()
    }
}

impl List {
    pub const fn new() -> Self {
        List {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// # Safety
    ///
    /// `n` is valid and in no other list until a pop returns it.
    pub unsafe fn push(&mut self, n: NonNull<Link>) {
        // SAFETY: `n` and the tail are valid links.
        unsafe {
            (*n.as_ptr()).next = ptr::null_mut();
            if self.tail.is_null() {
                self.head = n.as_ptr();
            } else {
                (*self.tail).next = n.as_ptr();
            }
        }
        self.tail = n.as_ptr();
    }

    pub fn pop(&mut self) -> Option<NonNull<Link>> {
        let n = NonNull::new(self.head)?;
        // SAFETY: the links of the list are valid.
        unsafe {
            self.head = (*n.as_ptr()).next;
            (*n.as_ptr()).next = ptr::null_mut();
        }
        if self.head.is_null() {
            self.tail = ptr::null_mut();
        }
        Some(n)
    }

    pub fn first(&self) -> Option<NonNull<Link>> {
        NonNull::new(self.head)
    }

    /// Append the items of `o` in order and empty `o`.
    pub fn concat(&mut self, o: &mut List) {
        if o.head.is_null() {
            return;
        }
        if self.tail.is_null() {
            self.head = o.head;
        } else {
            // SAFETY: the tail is a link of this list.
            unsafe { (*self.tail).next = o.head };
        }
        self.tail = o.tail;
        *o = List::new();
    }

    /// The items from the top `h` of a stack, in push order.
    fn reverse(h: usize) -> List {
        let mut n = h as *mut Link;
        let tail = n;
        let mut prev = ptr::null_mut();
        while !n.is_null() {
            // SAFETY: the links of a stack are valid.
            unsafe {
                let next = (*n).next;
                (*n).next = prev;
                prev = n;
                n = next;
            }
        }
        List { head: prev, tail }
    }
}

/// The result of a push to a `Stack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// The stack was empty before.
    First,
    More,
    /// The stack is closed. The caller keeps the item.
    Dead,
}

const DEAD: usize = 1;

/// A multi-producer stack. The consumer takes all items with one exchange,
/// so it has no ABA problem. After `close()`, a push is refused.
#[derive(Debug, Default)]
pub struct Stack {
    head: AtomicUsize,
}

impl Stack {
    pub const fn new() -> Self {
        Stack {
            head: AtomicUsize::new(0),
        }
    }

    /// # Safety
    ///
    /// `n` is valid and in no other list. Unless the push returns `Dead`,
    /// it stays valid until the consumer takes it.
    pub unsafe fn push(&self, n: NonNull<Link>) -> Push {
        let mut cur = self.head.load(Ordering::Relaxed);
        loop {
            if cur == DEAD {
                return Push::Dead;
            }
            // SAFETY: no other thread uses `n` until the push succeeds.
            unsafe { (*n.as_ptr()).next = cur as *mut Link };
            match self.head.compare_exchange_weak(
                cur,
                n.as_ptr() as usize,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return if cur == 0 { Push::First } else { Push::More };
                }
                Err(seen) => cur = seen,
            }
        }
    }

    #[inline]
    pub fn ready(&self) -> bool {
        let h = self.head.load(Ordering::Relaxed);
        h != 0 && h != DEAD
    }

    /// Take every item, in push order.
    pub fn take(&self) -> List {
        if !self.ready() {
            return List::new();
        }
        List::reverse(self.head.swap(0, Ordering::Acquire))
    }

    /// Refuse later pushes. Returns the items that are left, in push order.
    pub fn close(&self) -> List {
        let h = self.head.swap(DEAD, Ordering::Acquire);
        if h == DEAD {
            return List::new();
        }
        List::reverse(h)
    }
}

/// A type whose pointer is also a pointer to its link.
///
/// # Safety
///
/// The type is `#[repr(C)]` and its first field is a `Link` or starts with
/// one.
pub unsafe trait Linked {}

/// A FIFO list of boxed objects that one thread uses.
#[derive(Debug)]
pub struct BoxList<T: Linked> {
    raw: List,
    _owns: PhantomData<Box<T>>,
}

impl<T: Linked> Default for BoxList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Linked> BoxList<T> {
    pub const fn new() -> Self {
        BoxList {
            raw: List::new(),
            _owns: PhantomData,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn push(&mut self, b: Box<T>) {
        let n = NonNull::from(Box::leak(b)).cast::<Link>();
        // SAFETY: the list owns the leaked box until a pop.
        unsafe { self.raw.push(n) };
    }

    pub fn pop(&mut self) -> Option<Box<T>> {
        let n = self.raw.pop()?;
        // SAFETY: each link of the list is a box that push() leaked.
        Some(unsafe { Box::from_raw(n.cast::<T>().as_ptr()) })
    }

    pub fn first(&self) -> Option<&T> {
        let n = self.raw.first()?;
        // SAFETY: as in pop(). The list keeps the box.
        Some(unsafe { n.cast::<T>().as_ref() })
    }

    /// Append the items of `o` in order and empty `o`.
    pub fn concat(&mut self, o: &mut BoxList<T>) {
        self.raw.concat(&mut o.raw);
    }

    /// # Safety
    ///
    /// Each link of `raw` is the link of a leaked `Box<T>`.
    pub unsafe fn from_raw(raw: List) -> Self {
        BoxList {
            raw,
            _owns: PhantomData,
        }
    }
}

impl<T: Linked> Drop for BoxList<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}
