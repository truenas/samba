// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The PDUs that the owner sends.

use std::ffi::c_int;
use std::ptr::NonNull;

use crate::block::try_box;
use crate::conn::Conn;
use crate::hub::Hub;
use crate::list::Msg;
use crate::out::Out;
use crate::shim::post_sent;
use crate::upper::ShimReactor;

/// The vectors at `iov`. None for a negative count, for NULL with a count
/// above 0, or for a vector with bytes at NULL.
///
/// # Safety
///
/// A non-NULL `iov` points to `iovcnt` vectors that are valid for `'a`.
pub unsafe fn iov_of<'a>(
    iov: *const libc::iovec,
    iovcnt: c_int,
) -> Option<&'a [libc::iovec]> {
    let count = usize::try_from(iovcnt).ok()?;
    if count == 0 {
        return Some(&[]);
    }
    if iov.is_null() {
        return None;
    }
    // SAFETY: the caller passes `count` vectors at `iov`.
    let v = unsafe { std::slice::from_raw_parts(iov, count) };
    v.iter()
        .all(|v| !v.iov_base.is_null() || v.iov_len == 0)
        .then_some(v)
}

/// An out for `iov`, from the free list of `r` unless the owner frees it.
/// None without memory.
///
/// # Safety
///
/// Each vector points to `iov_len` readable bytes.
pub unsafe fn make_out(
    mut r: Option<&mut ShimReactor>,
    iov: &[libc::iovec],
    lend_min: usize,
) -> Option<Box<Out>> {
    let lends = iov.iter().any(|v| v.iov_len > 0 && v.iov_len >= lend_min);
    let mut o = match r.as_deref_mut() {
        Some(r) if !lends => r.new_out()?,
        _ => try_box(Out::new)?,
    };
    // SAFETY: as the caller says.
    unsafe { o.fill(iov, lend_min, r.map(|r| &mut r.blocks)) }.then_some(o)
}

/// Queue `o` on `c`. `r` is the reactor of `c` if the caller runs on it.
pub fn send_out(c: &Conn, r: Option<&mut ShimReactor>, o: Box<Out>) {
    if let Some(r) = r {
        r.queue_api(o);
        return;
    }
    let m = NonNull::from(Box::leak(o)).cast::<Msg>();
    // SAFETY: the out starts with its Msg. A post gives it to the reactor.
    if !unsafe { c.post(m) } {
        // SAFETY: the post failed, so the out is still ours.
        drop_foreign(c.hub(), unsafe {
            Box::from_raw(m.cast::<Out>().as_ptr())
        });
    }
}

/// Free an out off its reactor thread.
pub fn drop_foreign(hub: &Hub, mut o: Box<Out>) {
    if !o.plan.is_null() {
        (hub.vt().drop_plan)(&mut o, None);
    }
    o.drop_data(None);
    if o.lent {
        post_sent(hub, o);
    }
}

/// Queue the PDU in `iov` for sending. The shim copies the vectors shorter
/// than `lend_min`. The reactor sends the others from the caller's memory.
/// The call sets `*lent` to true if there are any. If so, the caller keeps
/// those vectors valid and unchanged until `tn_smbros_next()` returns
/// `TN_SMBROS_SENT` with `sent_cookie`. Returns 0 or an errno.
///
/// # Safety
///
/// `conn` is a live connection from `tn_smbros_adopt()`. `iov` points to
/// `iovcnt` vectors of readable memory. `iov` can be NULL if `iovcnt` is 0.
/// `lent` is writable. The caller keeps the vectors of `lend_min` bytes or
/// more valid and unchanged until `TN_SMBROS_SENT` with `sent_cookie`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_send(
    conn: *mut Conn,
    iov: *const libc::iovec,
    iovcnt: c_int,
    lend_min: usize,
    sent_cookie: u64,
    lent: *mut bool,
) -> c_int {
    // SAFETY: the caller passes `iovcnt` vectors.
    let Some(iov) = (unsafe { iov_of(iov, iovcnt) }) else {
        return libc::EINVAL;
    };
    // SAFETY: the caller passes a live connection.
    let conn = unsafe { &*conn };
    // SAFETY: a C function holds no borrow at its start.
    let mut local = unsafe { conn.local() };
    // SAFETY: the caller passes vectors of readable memory.
    let Some(mut o) =
        (unsafe { make_out(local.as_deref_mut(), iov, lend_min) })
    else {
        return libc::ENOMEM;
    };
    o.cookie = sent_cookie;
    // SAFETY: the caller passes room for a bool.
    unsafe { lent.write(o.lent) };
    send_out(conn, local.as_deref_mut(), o);
    0
}
