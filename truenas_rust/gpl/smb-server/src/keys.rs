// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The keys of the sessions: a table per connection and a cache per
//! reactor.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use truenas_smbros::{HubRef, Node, TnSmbrosEvent, lock, try_box};

use crate::TN_SMBSRV_KEY_FREE;
use crate::upper::EV_KEY_FREE;

/// The keys of one session on one connection, from
/// `tn_smbsrv_session_keys()`. A `struct tn_smbsrv_keys` pointer is one
/// reference to them.
#[derive(Debug)]
pub struct Keys {
    /// The number that smbd gave these keys.
    pub(crate) generation: u64,
    /// The signing key of the channel.
    pub(crate) sign: *mut c_void,
    /// The key that encrypts replies.
    pub(crate) encrypt: *mut c_void,
    /// The key that decrypts requests.
    pub(crate) decrypt: *mut c_void,
    hub: HubRef,
}

// SAFETY: smbd's functions take the keys on any thread until KEY_FREE.
unsafe impl Send for Keys {}
// SAFETY: as for Send.
unsafe impl Sync for Keys {}

impl Keys {
    pub fn new(
        hub: HubRef,
        generation: u64,
        sign: *mut c_void,
        encrypt: *mut c_void,
        decrypt: *mut c_void,
    ) -> Keys {
        Keys {
            generation,
            sign,
            encrypt,
            decrypt,
            hub,
        }
    }
}

impl Drop for Keys {
    /// The last reference gives each key back to smbd.
    fn drop(&mut self) {
        for key in [self.sign, self.encrypt, self.decrypt] {
            post_key_free(&self.hub, key);
        }
    }
}

/// A key for a `TN_SMBSRV_KEY_FREE` event.
#[repr(C)]
#[derive(Debug)]
struct KeyNote {
    node: Node,
    key: *mut c_void,
}

/// Give `key` back to smbd. Without memory, smbd does not get it back.
pub(crate) fn post_key_free(hub: &HubRef, key: *mut c_void) {
    if key.is_null() {
        return;
    }
    let Some(n) = try_box(|| KeyNote {
        node: Node::new(EV_KEY_FREE),
        key,
    }) else {
        return;
    };
    let n = Box::leak(n);
    // SAFETY: the node starts a leaked KeyNote, as its kind tells.
    unsafe { hub.hub().post(NonNull::from(&mut n.node)) };
}

/// # Safety
///
/// `n` is the node of a leaked `KeyNote`.
pub(crate) unsafe fn take_key_free(n: NonNull<Node>, ev: &mut TnSmbrosEvent) {
    // SAFETY: as the caller says.
    let k = unsafe { Box::from_raw(n.cast::<KeyNote>().as_ptr()) };
    *ev = TnSmbrosEvent {
        buf: k.key,
        ..TnSmbrosEvent::bare(0, TN_SMBSRV_KEY_FREE)
    };
}

/// # Safety
///
/// `n` is the node of a leaked `KeyNote`.
pub(crate) unsafe fn drop_key_free(n: NonNull<Node>) {
    // SAFETY: as the caller says.
    drop(unsafe { Box::from_raw(n.cast::<KeyNote>().as_ptr()) });
}

/// Take the reference `pin` back from smbd. None for NULL.
///
/// # Safety
///
/// `pin` is NULL or from `tn_smbsrv_keys_pin()`, and smbd does not use it
/// again.
pub(crate) unsafe fn unpin(pin: *mut Keys) -> Option<Arc<Keys>> {
    // SAFETY: the caller gives a reference from Arc::into_raw().
    (!pin.is_null()).then(|| unsafe { Arc::from_raw(pin.cast_const()) })
}

pub(crate) fn pin(k: Arc<Keys>) -> *mut Keys {
    Arc::into_raw(k).cast_mut()
}

/// The keys of the sessions on one connection.
#[derive(Debug, Default)]
pub struct KeyTable {
    items: Mutex<Vec<(u64, Arc<Keys>)>>,
    /// Each change adds 1.
    version: AtomicU32,
}

impl KeyTable {
    pub(crate) fn find(&self, session: u64) -> Option<Arc<Keys>> {
        let items = lock(&self.items);
        items
            .iter()
            .find(|e| e.0 == session)
            .map(|e| Arc::clone(&e.1))
    }

    /// Put `keys` in for `session`. Returns the keys that it replaced.
    ///
    /// # Errors
    ///
    /// Gives `keys` back without memory.
    pub fn insert(
        &self,
        session: u64,
        keys: Arc<Keys>,
    ) -> Result<Option<Arc<Keys>>, Arc<Keys>> {
        let mut items = lock(&self.items);
        let old = if let Some(e) = items.iter_mut().find(|e| e.0 == session) {
            Some(std::mem::replace(&mut e.1, keys))
        } else {
            if items.try_reserve(1).is_err() {
                return Err(keys);
            }
            items.push((session, keys));
            None
        };
        self.version.fetch_add(1, Ordering::Release);
        Ok(old)
    }

    pub(crate) fn remove(&self, session: u64) -> Option<Arc<Keys>> {
        let mut items = lock(&self.items);
        let i = items.iter().position(|e| e.0 == session)?;
        let (_, k) = items.swap_remove(i);
        self.version.fetch_add(1, Ordering::Release);
        Some(k)
    }
}

/// The keys that a reactor found last. It looks again after the table
/// changed.
#[derive(Debug, Default)]
pub struct KeyCache {
    keys: Option<Arc<Keys>>,
    session: u64,
    version: u32,
}

impl KeyCache {
    #[inline]
    pub fn find(&mut self, t: &KeyTable, session: u64) -> Option<&Arc<Keys>> {
        let v = t.version.load(Ordering::Acquire);
        if self.keys.is_some() && self.session == session && self.version == v {
            return self.keys.as_ref();
        }
        self.fill(t, session, v)
    }

    #[cold]
    #[inline(never)]
    fn fill(
        &mut self,
        t: &KeyTable,
        session: u64,
        v: u32,
    ) -> Option<&Arc<Keys>> {
        self.keys = t.find(session);
        self.session = session;
        self.version = v;
        self.keys.as_ref()
    }

    /// Drop the cached keys, so smbd gets them back before the next PDU.
    pub fn clear(&mut self) {
        self.keys = None;
    }
}
