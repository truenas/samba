// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The `buf` of a PDU event, with the block of the PDU's bytes.

use std::ffi::c_void;
use std::mem::offset_of;
use std::ptr::NonNull;

use crate::block::Block;
use crate::conn::{Conn, conn_unref};
use crate::ctx::{TN_SMBROS_PDU, TnSmbrosEvent};
use crate::hub::EV_PDU;
use crate::list::{Linked, Msg, MsgKind, Node, Push};
use crate::upper::{ShimReactor, Verdict};

/// The bytes of the NBT header of a PDU.
pub const NBT_HDR_SIZE: usize = 4;

/// The `buf` of a PDU event.
#[repr(C)]
#[derive(Debug)]
pub struct Pdu {
    /// The link in the stack of PDUs that other threads freed.
    msg: Msg,
    ev: Node,
    conn: NonNull<Conn>,
    block: Option<Block>,
    len: u32,
    nbt_type: u8,
    /// True if the owner can give the reactor a job for the PDU.
    pub(crate) delegable: bool,
    /// True while the PDU has an in-flight slot that the owner releases.
    pub(crate) deferred: bool,
    pub(crate) verdict: Verdict,
}

// SAFETY: Pdu starts with its Msg, whose first field is the Link.
unsafe impl Linked for Pdu {}

// SAFETY: one owner at a time uses a PDU. The connection is Sync.
unsafe impl Send for Pdu {}

impl Pdu {
    pub(crate) fn new(conn: NonNull<Conn>) -> Pdu {
        Pdu {
            msg: Msg::new(MsgKind::Other),
            ev: Node::new(EV_PDU),
            conn,
            block: None,
            len: 0,
            nbt_type: 0,
            delegable: false,
            deferred: false,
            verdict: Verdict::default(),
        }
    }

    /// Give the PDU a block with `len` bytes after the NBT header.
    pub(crate) fn fill(&mut self, b: Block, len: u32) {
        // SAFETY: the first byte of a whole PDU came from the kernel.
        self.nbt_type = unsafe { *b.data() };
        self.block = Some(b);
        self.len = len;
        self.delegable = false;
        self.deferred = false;
        self.verdict = Verdict::default();
    }

    pub fn conn(&self) -> &Conn {
        // SAFETY: the PDU holds a reference to the connection.
        unsafe { self.conn.as_ref() }
    }

    /// The message without the NBT header.
    pub fn data(&mut self) -> &mut [u8] {
        match &mut self.block {
            // SAFETY: the kernel wrote the whole PDU into the block.
            Some(b) => unsafe {
                &mut b.bytes_mut(NBT_HDR_SIZE + self.len as usize)
                    [NBT_HDR_SIZE..]
            },
            None => &mut [],
        }
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True if the PDU has an in-flight slot that the owner releases.
    pub fn deferred(&self) -> bool {
        self.deferred
    }

    /// The PDU no longer has its in-flight slot. A job has it now.
    pub fn give_slot(&mut self) {
        self.deferred = false;
    }

    pub fn has_block(&self) -> bool {
        self.block.is_some()
    }

    /// The class and the data of the block of the PDU.
    pub fn block_info(&self) -> Option<(u8, *mut u8)> {
        self.block.as_ref().map(|b| (b.class(), b.data()))
    }

    /// Take the block of the PDU for a job.
    pub fn take_block(&mut self) -> Option<Block> {
        self.block.take()
    }

    /// The event of the PDU. The event does not own the PDU.
    pub(crate) fn event(&mut self) -> TnSmbrosEvent {
        let cookie = self.conn().cookie;
        let data = self
            .block
            .as_ref()
            // SAFETY: the data of the message starts after the header.
            .map_or(std::ptr::null_mut(), |b| unsafe {
                b.data().add(NBT_HDR_SIZE)
            });
        TnSmbrosEvent {
            nbt_type: self.nbt_type,
            data,
            len: self.len as usize,
            buf: std::ptr::from_mut(self).cast::<c_void>(),
            flags: self.verdict.flags,
            status: self.verdict.status,
            tag: self.verdict.tag,
            ..TnSmbrosEvent::bare(cookie, TN_SMBROS_PDU)
        }
    }

    pub(crate) fn ev_node(&mut self) -> NonNull<Node> {
        NonNull::from(&mut self.ev)
    }

    /// The PDU of the event node `n`. The box owns the PDU again.
    ///
    /// # Safety
    ///
    /// `n` is the `ev` of a leaked `Box<Pdu>`.
    #[allow(clippy::unnecessary_box_returns)]
    pub(crate) unsafe fn from_ev(n: NonNull<Node>) -> Box<Pdu> {
        // SAFETY: as the caller says.
        unsafe {
            Box::from_raw(
                n.as_ptr().byte_sub(offset_of!(Pdu, ev)).cast::<Pdu>(),
            )
        }
    }
}

/// Put `p` and its block back on the reactor thread.
#[inline]
pub(crate) fn pdu_reuse(r: &mut ShimReactor, mut p: Box<Pdu>) {
    if let Some(b) = p.block.take() {
        r.blocks.put(b);
    }
    r.h.pdus.put(p);
    r.h.out_pdus -= 1;
}

/// Give back the PDU `p` from any thread.
pub(crate) fn pdu_return(p: Box<Pdu>) {
    let c = p.conn;
    // SAFETY: `p` holds a reference until the push, which `conn` precedes.
    let conn: &Conn = unsafe { c.as_ref() };
    // SAFETY: the caller holds no borrow of the reactor.
    if let Some(mut r) = unsafe { conn.local() } {
        pdu_reuse(&mut r, p);
        return;
    }
    let n = NonNull::from(Box::leak(p));
    // SAFETY: the stack owns the leaked PDU unless the push is refused.
    if unsafe { conn.ret.push(n.cast()) } == Push::Dead {
        // The reactor ended. It counted this PDU as a reference.
        // SAFETY: the push was refused, so the PDU is still ours.
        drop(unsafe { Box::from_raw(n.as_ptr()) });
        // SAFETY: the PDU had a reference to the connection.
        unsafe { conn_unref(c) };
    }
}

/// Free the PDU `p` from any thread.
pub(crate) fn pdu_free(mut p: Box<Pdu>) {
    if p.deferred {
        p.deferred = false;
        p.conn().release_slot();
    }
    pdu_return(p);
}
