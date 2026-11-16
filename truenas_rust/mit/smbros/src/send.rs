// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The PDUs that the owner sends. The shim copies small parts. The owner
//! lends large parts to the reactor.

use std::ffi::c_int;
use std::sync::Arc;

use truenas_ros::net::server::{Lent, PushFinish, PushPart};

use crate::conn::Conn;
use crate::ctx::{Event, Shared};

/// The vectors at `iov`. None for a negative count, and for a NULL `iov`
/// with a count above 0. A count of 0 gives an empty slice, and `iov` can
/// be NULL then.
///
/// # Safety
///
/// If `iov` is not NULL, it points to `iovcnt` vectors. They are valid for
/// `'a`.
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
    Some(unsafe { std::slice::from_raw_parts(iov, count) })
}

/// The bytes of each vector of `iov` that is not empty.
///
/// # Safety
///
/// Each vector points to `iov_len` readable bytes. The bytes are valid for
/// the lifetime of `iov`.
unsafe fn iov_bytes(iov: &[libc::iovec]) -> impl Iterator<Item = &[u8]> {
    iov.iter().filter(|v| v.iov_len > 0).map(|v| {
        // SAFETY: the caller passes vectors of readable memory.
        unsafe {
            std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len)
        }
    })
}

/// The bytes of `iov` in one buffer.
///
/// # Safety
///
/// Each vector points to `iov_len` readable bytes.
pub unsafe fn iov_gather(iov: &[libc::iovec]) -> Vec<u8> {
    let mut out = Vec::with_capacity(iov.iter().map(|v| v.iov_len).sum());
    // SAFETY: the caller passes vectors of readable memory.
    for bytes in unsafe { iov_bytes(iov) } {
        out.extend_from_slice(bytes);
    }
    out
}

/// Posts `Event::Sent` when the last lent part of a send is dropped.
#[derive(Debug)]
struct SentGuard {
    shared: Arc<Shared>,
    cookie: u64,
}

impl Drop for SentGuard {
    fn drop(&mut self) {
        self.shared.post(Event::Sent {
            cookie: self.cookie,
        });
    }
}

impl Conn {
    /// Make the parts of a PDU from `iov`. Copy the vectors under
    /// `lend_min` bytes, and lend the others. The owner gets
    /// `TN_SMBROS_SENT` with `sent_cookie` after the last lent part is
    /// dropped. The `bool` is true if a part is lent.
    ///
    /// # Safety
    ///
    /// The vectors of `iov` point to readable memory. The caller keeps the
    /// vectors of `lend_min` bytes or more valid and unchanged until
    /// `TN_SMBROS_SENT` with `sent_cookie`.
    pub unsafe fn parts(
        &self,
        iov: &[libc::iovec],
        lend_min: usize,
        sent_cookie: u64,
    ) -> (Vec<PushPart>, bool) {
        let mut parts = Vec::new();
        let mut owned = Vec::new();
        let mut guard: Option<Arc<SentGuard>> = None;
        // SAFETY: the caller passes vectors of readable memory.
        for bytes in unsafe { iov_bytes(iov) } {
            if bytes.len() < lend_min {
                owned.extend_from_slice(bytes);
                continue;
            }
            if !owned.is_empty() {
                parts.push(PushPart::Owned(std::mem::take(&mut owned)));
            }
            let g = Arc::clone(guard.get_or_insert_with(|| {
                Arc::new(SentGuard {
                    shared: Arc::clone(&self.shared),
                    cookie: sent_cookie,
                })
            }));
            // SAFETY: the caller keeps the vector valid and unchanged until
            // TN_SMBROS_SENT. The guard posts that event after the last lent
            // part is dropped.
            parts.push(PushPart::Lent(unsafe {
                Lent::new(bytes.as_ptr(), bytes.len(), move || drop(g))
            }));
        }
        if !owned.is_empty() {
            parts.push(PushPart::Owned(owned));
        }
        // After this return, only the lent parts have references to the guard.
        (parts, guard.is_some())
    }

    /// Send `parts` after the reactor runs `finish` on them. The reactor
    /// runs `finish` on its thread, in the send order of the connection.
    /// `finish` returns false to close the connection.
    pub fn send_finished(&self, parts: Vec<PushPart>, finish: PushFinish) {
        self.push.push_parts_finished(parts, finish);
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
    if iov.iter().all(|v| v.iov_len < lend_min) {
        // SAFETY: the caller passes room for a bool.
        unsafe { lent.write(false) };
        // SAFETY: the caller passes vectors of readable memory.
        conn.push.push(unsafe { iov_gather(iov) });
        return 0;
    }
    // SAFETY: the caller keeps the lent vectors valid and unchanged until
    // TN_SMBROS_SENT.
    let (parts, any_lent) = unsafe { conn.parts(iov, lend_min, sent_cookie) };
    // SAFETY: the caller passes room for a bool.
    unsafe { lent.write(any_lent) };
    conn.push.push_parts(parts);
    0
}

#[cfg(test)]
mod tests {
    use super::iov_of;

    #[test]
    fn a_null_iov_without_vectors_is_empty() {
        // SAFETY: a count of 0 reads no vectors.
        let iov = unsafe { iov_of(std::ptr::null(), 0) };
        assert_eq!(iov.map(<[libc::iovec]>::len), Some(0));
    }

    #[test]
    fn a_null_iov_with_vectors_is_refused() {
        // SAFETY: iov_of checks for NULL before it reads.
        let iov = unsafe { iov_of(std::ptr::null(), 2) };
        assert!(iov.is_none());
    }
}
