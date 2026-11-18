// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The buffer of a PDU event. The owner can give the reactor a job for the
//! PDU.

use std::ffi::{c_int, c_void};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use truenas_ros::net::server::Deferred;

use crate::conn::{Conn, ConnState};
use crate::lock;
use crate::reactor::PLACE_MIN;
use crate::upper::Job;

/// The `buf` of a PDU event. It owns the bytes of the PDU.
#[derive(Debug)]
pub struct Buf {
    pub(crate) conn: Arc<ConnState>,
    pub(crate) body: Vec<u8>,
    /// The deferred reply of the PDU. It is `Some` while the PDU is queued
    /// or can still get a job.
    pub(crate) deferred: Option<Deferred>,
}

impl Drop for Buf {
    /// Answer the deferred reply with no bytes. An empty reply sends
    /// nothing. Send body storage of `PLACE_MIN` bytes or more back to the
    /// reactor for its pool.
    fn drop(&mut self) {
        if let Some(d) = self.deferred.take() {
            d.reply(Vec::new());
        }
        if self.body.capacity() >= PLACE_MIN {
            // The send fails after the reactor ends. Dropping the error
            // frees the body.
            let _ = self.conn.back.send(std::mem::take(&mut self.body));
        }
    }
}

impl Buf {
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Take the bytes for a job. The event no longer has them.
    pub fn take_body(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.body)
    }

    /// True if the PDU can still get a job.
    pub fn delegable(&self) -> bool {
        self.deferred.is_some()
    }
}

impl Conn {
    /// Queue `job` for the PDU of `buf`. The reactor runs it on its thread.
    /// EINVAL if the PDU cannot get a job. ECONNRESET if the reactor
    /// stopped. An error drops the job.
    pub fn delegate(&self, buf: &mut Buf, job: Box<dyn Job>) -> c_int {
        let Some(deferred) = buf.deferred.take() else {
            return libc::EINVAL;
        };
        let mut jobs = lock(&self.state.jobs);
        if jobs.stopped {
            drop(jobs);
            drop(job);
            return libc::ECONNRESET;
        }
        // Only the owner adds jobs. So the queue has the jobs in the order
        // of their redeliveries.
        jobs.queue.push_back(job);
        drop(jobs);
        deferred.redeliver();
        0
    }
}

/// Free the buffer of a PDU event.
///
/// # Safety
///
/// `buf` is NULL or the `buf` of a PDU event. The caller does not use it
/// after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_free(buf: *mut c_void) {
    if buf.is_null() {
        return;
    }
    // SAFETY: the caller passes the buffer of an event and does not use it
    // again.
    drop(unsafe { Box::from_raw(buf.cast::<Buf>()) });
}

/// True if `tn_smbros_close()` has not run for the connection of `buf`.
/// False if `buf` is NULL.
///
/// # Safety
///
/// `buf` is NULL or the live `buf` of a PDU event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_open(buf: *const c_void) -> bool {
    // SAFETY: the caller passes NULL or a live buffer.
    unsafe { buf.cast::<Buf>().as_ref() }
        .is_some_and(|b| !b.conn.closed.load(Ordering::Acquire))
}

/// True if the PDU of `buf` can still get a job. The layer above the shim
/// selects such PDUs on a connection adopted with `delegate`. Such a PDU
/// counts against `max_in_flight` until the caller gives it a job or
/// releases it.
///
/// # Safety
///
/// `buf` is NULL or the live `buf` of a PDU event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_delegable(buf: *const c_void) -> bool {
    // SAFETY: the caller passes NULL or a live buffer.
    unsafe { buf.cast::<Buf>().as_ref() }.is_some_and(Buf::delegable)
}

/// Release the PDU of `buf` without a job. Call this as soon as the caller
/// knows that the PDU gets no job. Then the reactor can read more PDUs.
/// `tn_smbros_buf_free()` also releases the PDU.
///
/// # Safety
///
/// `buf` is NULL or the live `buf` of a PDU event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tn_smbros_buf_release(buf: *mut c_void) {
    // SAFETY: the caller passes NULL or a live buffer.
    if let Some(b) = unsafe { buf.cast::<Buf>().as_mut() }
        && let Some(d) = b.deferred.take()
    {
        d.reply(Vec::new());
    }
}

#[cfg(test)]
mod tests {
    use super::tn_smbros_buf_open;

    #[test]
    fn a_null_buf_is_not_open() {
        // SAFETY: tn_smbros_buf_open checks for NULL before it reads.
        assert!(!unsafe { tn_smbros_buf_open(std::ptr::null()) });
    }
}
