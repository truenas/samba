// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The signing or encryption of a reply from `tn_smbsrv_send_sealed()`, in
//! place if libcli can take the layout of the vectors, else on a copy.

use std::cell::RefCell;
use std::ptr;
use std::sync::Arc;

use truenas_smbros::{Out, Pool, try_box};

use crate::crypto::{CryptoOps, encrypt_pdu, host_crypto, sign_msg};
use crate::keys::Keys;
use crate::wire::{NBT_HDR_SIZE, SMB2_HDR_SIZE, SMB2_TF_SIZE};

/// `smb2_signing_sign_pdu()` asserts on more vectors per message.
const SIGN_MAX_IOV: usize = 4;
/// The plans that one thread keeps for reuse.
const CACHE_MAX: usize = 64;

const NO_IOV: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};

/// A message to sign, with its byte range in the PDU.
#[derive(Debug)]
struct SignMsg {
    keys: Arc<Keys>,
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
struct Data {
    encrypt: Option<Arc<Keys>>,
    msgs: Vec<SignMsg>,
}

// An out holds a plan as a pointer to its box, so the cache keeps boxes.
thread_local! {
    #[allow(clippy::vec_box)]
    static CACHE: RefCell<Vec<Box<Data>>> = const { RefCell::new(Vec::new()) };
}

/// The plan of one reply.
#[derive(Debug)]
pub(crate) struct Plan(Option<Box<Data>>);

impl Drop for Plan {
    fn drop(&mut self) {
        let Some(mut d) = self.0.take() else {
            return;
        };
        d.encrypt = None;
        d.msgs.clear();
        // An ending thread has no cache. Then the plan is freed.
        let _ = CACHE.try_with(|c| {
            let mut c = c.borrow_mut();
            if c.len() < CACHE_MAX {
                c.push(d);
            }
        });
    }
}

impl Plan {
    /// A plan that encrypts with `encrypt`, or signs with the keys that
    /// `sign()` adds. None without memory.
    pub(crate) fn get(encrypt: Option<Arc<Keys>>) -> Option<Plan> {
        let cached = CACHE.try_with(|c| c.borrow_mut().pop()).ok().flatten();
        let mut d = match cached {
            Some(d) => d,
            None => try_box(Data::default)?,
        };
        d.encrypt = encrypt;
        Some(Plan(Some(d)))
    }

    /// Sign the bytes `rg` of the PDU with `keys`. False without memory.
    pub(crate) fn sign(&mut self, keys: Arc<Keys>, rg: (usize, usize)) -> bool {
        if let Some(d) = &mut self.0 {
            if d.msgs.try_reserve(1).is_err() {
                return false;
            }
            d.msgs.push(SignMsg {
                keys,
                start: rg.0,
                end: rg.1,
            });
        }
        true
    }

    /// True if the plan encrypts with a key and signs nothing, or signs
    /// `nparts` messages and does not encrypt.
    pub(crate) fn valid(&self, nparts: usize) -> bool {
        self.0.as_ref().is_some_and(|d| match &d.encrypt {
            Some(k) => nparts == 0 && !k.encrypt.is_null(),
            None => nparts > 0,
        })
    }

    pub(crate) fn into_raw(mut self) -> *mut () {
        self.0
            .take()
            .map_or(ptr::null_mut(), |d| Box::into_raw(d).cast())
    }

    /// # Safety
    ///
    /// `p` is NULL or from `into_raw()`, and nothing uses it after this.
    pub(crate) unsafe fn from_raw(p: *mut ()) -> Plan {
        if p.is_null() {
            return Plan(None);
        }
        // SAFETY: as the caller says.
        Plan(Some(unsafe { Box::from_raw(p.cast::<Data>()) }))
    }

    /// Sign or encrypt the PDU of `o`, in place or on a copy from `pool`
    /// that replaces its segments.
    pub(crate) fn apply(
        &self,
        ops: &CryptoOps,
        o: &mut Out,
        pool: &mut Pool,
    ) -> bool {
        let Some(d) = &self.0 else {
            return false;
        };
        let nseg = usize::from(o.nseg);
        if let Some(ok) = d.apply_in_place(ops, &o.segs[..nseg]) {
            return ok;
        }
        let total = o.bytes();
        let Some(b) = pool.get(total) else {
            return false;
        };
        let buf = b.data();
        let mut at = 0;
        for s in &o.segs[..nseg] {
            // SAFETY: the segments are readable and fit in `buf`.
            unsafe {
                ptr::copy_nonoverlapping(
                    s.iov_base.cast::<u8>(),
                    buf.add(at),
                    s.iov_len,
                );
            }
            at += s.iov_len;
        }
        // SAFETY: the copy above initialized `total` bytes of `buf`.
        let ok = d.apply_flat(ops, unsafe {
            std::slice::from_raw_parts_mut(buf, total)
        });
        o.drop_data(Some(pool));
        o.block = Some(b);
        o.segs[0] = libc::iovec {
            iov_base: buf.cast(),
            iov_len: total,
        };
        o.nseg = 1;
        ok
    }
}

impl Data {
    /// Sign or encrypt the PDU of `segs` in place. None, with nothing
    /// changed, if libcli cannot take this layout.
    fn apply_in_place(
        &self,
        ops: &CryptoOps,
        segs: &[libc::iovec],
    ) -> Option<bool> {
        let total: usize = segs.iter().map(|s| s.iov_len).sum();
        let mut iov = [NO_IOV; 32];
        if let Some(k) = &self.encrypt {
            let tf = NBT_HDR_SIZE + SMB2_TF_SIZE;
            if total <= tf {
                return Some(false);
            }
            if slice_iov(segs, NBT_HDR_SIZE, tf, &mut iov[..1]) != Some(1) {
                return None;
            }
            let n = slice_iov(segs, tf, total, &mut iov[1..])?;
            return Some(
                host_crypto(ops.encrypt, k.encrypt, &mut iov[..=n]) == 0,
            );
        }
        for m in &self.msgs {
            let h = m.start + SMB2_HDR_SIZE;
            if m.end - m.start <= SMB2_HDR_SIZE {
                return Some(false);
            }
            if m.end > total
                || slice_iov(segs, m.start, h, &mut iov[..1]) != Some(1)
            {
                return None;
            }
            slice_iov(segs, h, m.end, &mut iov[1..SIGN_MAX_IOV])?;
        }
        for m in &self.msgs {
            let h = m.start + SMB2_HDR_SIZE;
            slice_iov(segs, m.start, h, &mut iov[..1]);
            let n = slice_iov(segs, h, m.end, &mut iov[1..SIGN_MAX_IOV])?;
            if host_crypto(ops.sign, m.keys.sign, &mut iov[..=n]) != 0 {
                return Some(false);
            }
        }
        Some(true)
    }

    fn apply_flat(&self, ops: &CryptoOps, buf: &mut [u8]) -> bool {
        if let Some(k) = &self.encrypt {
            return encrypt_pdu(ops, k, buf);
        }
        self.msgs.iter().all(|m| {
            m.end <= buf.len()
                && sign_msg(ops, &m.keys, &mut buf[m.start..m.end])
        })
    }
}

/// The vectors that cover [start, end) of the PDU made of `segs`, written
/// to `out`. None if the PDU is shorter or `out` is too small.
fn slice_iov(
    segs: &[libc::iovec],
    start: usize,
    end: usize,
    out: &mut [libc::iovec],
) -> Option<usize> {
    let mut n = 0;
    let mut at = 0;
    for s in segs {
        let lo = start.max(at);
        let hi = end.min(at + s.iov_len);
        if lo < hi {
            let slot = out.get_mut(n)?;
            *slot = libc::iovec {
                // SAFETY: `lo - at` is within the segment.
                iov_base: unsafe { s.iov_base.cast::<u8>().add(lo - at) }
                    .cast(),
                iov_len: hi - lo,
            };
            n += 1;
        }
        at += s.iov_len;
    }
    (end <= at).then_some(n)
}
