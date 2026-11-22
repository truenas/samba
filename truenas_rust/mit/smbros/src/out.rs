// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! A PDU to send: short vectors copied, long vectors lent by the caller.

use std::mem::{MaybeUninit, offset_of};
use std::ptr::{self, NonNull};

use crate::block::{Block, Pool};
use crate::list::{Linked, Msg, MsgKind, Node};

pub(crate) const MAXSEG: usize = 16;
/// The out keeps copies of up to this many bytes in its own storage.
pub(crate) const INLINE: usize = 448;

const NO_SEG: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};

/// A PDU to send.
#[repr(C)]
#[derive(Debug)]
pub struct Out {
    pub msg: Msg,
    /// The node of the event that tells the owner that lent memory is free.
    pub ev: Node,
    pub segs: [libc::iovec; MAXSEG],
    pub nseg: u8,
    /// True if a segment is the memory of the caller.
    pub lent: bool,
    /// True if the out is from the free list of its reactor.
    pub pooled: bool,
    /// True if the layer above finishes the PDU on the reactor first.
    pub finish: bool,
    pub cookie: u64,
    /// Owned bytes in a block of the reactor's pool.
    pub block: Option<Block>,
    /// Owned bytes on the heap, used as spare capacity.
    pub heap: Option<Vec<u8>>,
    /// The plan of the layer above for `finish`.
    pub plan: *mut (),
    pub data: [MaybeUninit<u8>; INLINE],
}

// SAFETY: Out starts with its Msg, whose first field is the Link.
unsafe impl Linked for Out {}

// SAFETY: an out owns its storage, and lent segments live until SENT.
unsafe impl Send for Out {}

impl Default for Out {
    fn default() -> Self {
        Self::new()
    }
}

impl Out {
    pub fn new() -> Out {
        Out {
            msg: Msg::new(MsgKind::Send),
            ev: Node::new(0),
            segs: [NO_SEG; MAXSEG],
            nseg: 0,
            lent: false,
            pooled: false,
            finish: false,
            cookie: 0,
            block: None,
            heap: None,
            plan: ptr::null_mut(),
            data: [MaybeUninit::uninit(); INLINE],
        }
    }

    /// Set the fields of a reused out. Its storage was dropped before.
    #[inline]
    pub fn reset(&mut self) {
        self.msg = Msg::new(MsgKind::Send);
        self.ev = Node::new(0);
        self.nseg = 0;
        self.lent = false;
        self.pooled = false;
        self.finish = false;
        self.cookie = 0;
        self.plan = ptr::null_mut();
    }

    pub fn bytes(&self) -> usize {
        self.segs[..usize::from(self.nseg)]
            .iter()
            .map(|s| s.iov_len)
            .sum()
    }

    /// Make `b` the only segment, with `len` bytes.
    #[inline]
    pub fn set_block(&mut self, b: Block, len: usize) {
        self.segs[0] = libc::iovec {
            iov_base: b.data().cast(),
            iov_len: len,
        };
        self.nseg = 1;
        self.block = Some(b);
    }

    /// Make the inline storage the only segment, with `len` bytes.
    #[inline]
    pub fn set_inline(&mut self, len: usize) {
        self.segs[0] = libc::iovec {
            iov_base: self.data.as_mut_ptr().cast(),
            iov_len: len,
        };
        self.nseg = 1;
    }

    /// The first `len` bytes of the inline storage, set to zero.
    pub fn inline_zeroed(&mut self, len: usize) -> &mut [u8] {
        let d = &mut self.data[..len];
        d.fill(MaybeUninit::new(0));
        // SAFETY: the bytes are initialized, with the layout of u8.
        unsafe { &mut *(ptr::from_mut(d) as *mut [u8]) }
    }

    /// Copy `src` into the inline storage and make it the only segment.
    /// False if `src` does not fit.
    #[inline]
    pub fn set_inline_from(&mut self, src: &[u8]) -> bool {
        if src.len() > INLINE {
            return false;
        }
        // SAFETY: `src` fits in the storage and does not overlap it.
        unsafe {
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.data.as_mut_ptr().cast::<u8>(),
                src.len(),
            );
        }
        self.set_inline(src.len());
        true
    }

    /// Copy the vectors shorter than `lend_min` and lend the others. `pool`
    /// is the block pool if the caller is the reactor. False without memory
    /// or for a vector with bytes at NULL.
    ///
    /// # Safety
    ///
    /// Each vector points to `iov_len` readable bytes.
    pub unsafe fn fill(
        &mut self,
        iov: &[libc::iovec],
        lend_min: usize,
        pool: Option<&mut Pool>,
    ) -> bool {
        let mut lend = lend_min;
        let mut owned = 0;
        let mut nlent = 0;
        for v in iov.iter().filter(|v| v.iov_len > 0) {
            if v.iov_base.is_null() {
                return false;
            }
            if v.iov_len < lend {
                owned += v.iov_len;
            } else {
                nlent += 1;
            }
        }
        // One owned segment can sit between each two lent ones.
        if 2 * nlent + 1 > MAXSEG {
            lend = usize::MAX;
            owned = iov.iter().map(|v| v.iov_len).sum();
        }
        let dst: *mut u8 = if owned <= INLINE {
            self.data.as_mut_ptr().cast()
        } else if let Some(p) = pool {
            let Some(b) = p.get(owned) else {
                return false;
            };
            self.block.insert(b).data()
        } else {
            let mut v = Vec::new();
            if v.try_reserve_exact(owned).is_err() {
                return false;
            }
            self.heap.insert(v).as_mut_ptr()
        };
        let mut at = 0;
        let mut k = 0;
        let mut open = false;
        for v in iov {
            let len = v.iov_len;
            let src = v.iov_base.cast::<u8>();
            if len == 0 {
                continue;
            }
            if len < lend {
                // SAFETY: `src` is readable, and `dst` has `owned` bytes.
                unsafe { ptr::copy_nonoverlapping(src, dst.add(at), len) };
                if open {
                    self.segs[k - 1].iov_len += len;
                } else {
                    self.segs[k] = libc::iovec {
                        // SAFETY: `at` is within the storage.
                        iov_base: unsafe { dst.add(at) }.cast(),
                        iov_len: len,
                    };
                    k += 1;
                    open = true;
                }
                at += len;
            } else {
                self.segs[k] = *v;
                k += 1;
                open = false;
                self.lent = true;
            }
        }
        // At most MAXSEG segments, see above.
        self.nseg = u8::try_from(k).unwrap_or(0);
        true
    }

    /// # Safety
    ///
    /// `n` is the `ev` of a leaked `Box<Out>`.
    pub(crate) unsafe fn from_ev(n: NonNull<Node>) -> Box<Out> {
        // SAFETY: as the caller says.
        unsafe {
            Box::from_raw(
                n.as_ptr().byte_sub(offset_of!(Out, ev)).cast::<Out>(),
            )
        }
    }

    /// Free the owned storage. `pool` is the block pool if the caller is
    /// the reactor.
    #[inline]
    pub fn drop_data(&mut self, pool: Option<&mut Pool>) {
        if let Some(b) = self.block.take() {
            match pool {
                Some(p) => p.put(b),
                None => drop(b),
            }
        }
        self.heap = None;
        self.nseg = 0;
    }
}
