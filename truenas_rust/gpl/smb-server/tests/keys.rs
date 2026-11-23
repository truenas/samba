// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the key table of a connection and the key cache of a reactor.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;

use truenas_smb_server::ffi::tn_smbsrv_attach;
use truenas_smb_server::{KeyCache, KeyTable, Keys, TN_SMBSRV_KEY_FREE};
use truenas_smbros::TnSmbrosEvent;
use truenas_smbros::ffi::{
    tn_smbros_ctx_free, tn_smbros_ctx_new, tn_smbros_next,
};

/// The cache finds the keys again only after the table changed. The last
/// reference to replaced keys gives them back to smbd.
#[test]
fn the_key_cache_follows_the_table() {
    let ctx = tn_smbros_ctx_new();
    // SAFETY: the context is live.
    assert!(unsafe { tn_smbsrv_attach(ctx, ptr::null(), ptr::null(), 0) });
    // SAFETY: the context is live until the free below.
    let hub = unsafe { &*ctx }.hub_ref();
    let key = ptr::dangling_mut::<c_void>();
    let null = ptr::null_mut();
    let k1 = Arc::new(Keys::new(hub.clone(), 1, key, null, null));
    let k2 = Arc::new(Keys::new(hub, 2, null, null, null));
    let t = KeyTable::default();
    let mut kc = KeyCache::default();
    assert!(t.insert(7, Arc::clone(&k1)).unwrap().is_none());
    assert!(Arc::ptr_eq(kc.find(&t, 7).unwrap(), &k1));
    assert_eq!(Arc::strong_count(&k1), 3);
    let old = t.insert(7, Arc::clone(&k2)).unwrap().unwrap();
    assert!(Arc::ptr_eq(&old, &k1));
    assert!(Arc::ptr_eq(kc.find(&t, 7).unwrap(), &k2));
    // The cache dropped k1, so only the test has it now.
    drop(old);
    assert_eq!(Arc::strong_count(&k1), 1);
    assert!(kc.find(&t, 9).is_none());
    kc.clear();
    drop(k1);
    let mut ev = TnSmbrosEvent::bare(0, 0);
    // SAFETY: the context is live, and `ev` has room for an event.
    assert!(unsafe { tn_smbros_next(ctx, &raw mut ev) });
    assert_eq!((ev.kind, ev.buf), (TN_SMBSRV_KEY_FREE, key));
    drop((t, k2));
    // SAFETY: the test does not use the context after this.
    unsafe { tn_smbros_ctx_free(ctx) };
}
