// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The interim responses of jobs. smbd answers a READ, WRITE or FLUSH that
//! still runs after 500 microseconds with an interim response
//! (`smbd_smb2_request_pending_queue()`). A job does the same. The interim
//! response grants the credits of the reply, so the final reply grants
//! none. The job stays a request in flight until its final reply.
//!
//! One ring timer per connection serves all its jobs. The timer fires at the
//! deadline of the oldest job that can still get an interim response. A job
//! that ends before its deadline adds no ring operation and no allocation.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use truenas_ros::net::server::PushHandle;
use truenas_ros::uring_fs::{FsConn, FsDone};
use truenas_smbros::{NBT_HDR_SIZE, lock};

use crate::crypto::{CryptoOps, Seal};
use crate::wire::{
    NT_STATUS_PENDING, SMB2_HDR_ASYNC_ID, SMB2_HDR_CREDIT, SMB2_HDR_FLAG_ASYNC,
    SMB2_HDR_FLAG_SIGNED, SMB2_HDR_FLAGS, SMB2_HDR_LENGTH, SMB2_HDR_MAGIC,
    SMB2_HDR_MESSAGE_ID, SMB2_HDR_OPCODE, SMB2_HDR_SESSION_ID,
    SMB2_HDR_SIGNATURE, SMB2_HDR_SIZE, SMB2_HDR_STATUS, SMB2_TF_NONCE,
    SMB2_TF_SIZE, le32, set_nbt_len,
};

/// The time after which a job gets an interim response, as in
/// `smb2_read.c`, `smb2_write.c` and `smb2_flush.c`.
const AFTER: Duration = Duration::from_micros(500);
/// The body and the error data of an interim response. smbd sends the 0x21
/// to match Windows Server 2008 R2.
const BODY: [u8; 9] = [9, 0, 0, 0, 0, 0, 0, 0, 0x21];
/// The NBT header, the transform header and the SMB2 header of a reply.
const HEAD_MAX: usize = NBT_HDR_SIZE + SMB2_TF_SIZE + SMB2_HDR_SIZE;

/// The interim responses of one connection: the jobs that can still get
/// one, and the timer that sends them. Only the reactor of the connection
/// uses it.
#[derive(Debug)]
pub(crate) struct Interims {
    crypto: Option<CryptoOps>,
    push: PushHandle,
    queue: Mutex<Queue>,
}

#[derive(Debug, Default)]
struct Queue {
    /// The jobs that can still get an interim response, in the order they
    /// started. All jobs wait `AFTER`, so this is also the order of their
    /// deadlines.
    jobs: VecDeque<Entry>,
    /// The number of the first job in `jobs`. Each job gets the next
    /// number.
    first: u64,
    /// True while the timer runs.
    armed: bool,
}

/// A job that can still get an interim response.
#[derive(Debug)]
struct Entry {
    deadline: Instant,
    /// The file I/O of the job ended.
    done: bool,
    /// The headers of the interim response, from `copy_head()`.
    head: [u8; HEAD_MAX],
    seal: Seal,
}

/// The interim response of a running job.
#[derive(Debug)]
pub(crate) struct Watch {
    seq: u64,
    interims: Arc<Interims>,
}

impl Queue {
    /// Add a job. Returns its number.
    fn push(&mut self, e: Entry) -> u64 {
        self.jobs.push_back(e);
        self.first + self.jobs.len() as u64 - 1
    }

    /// Remove the jobs that ended or reached their deadline by `now`. Give
    /// each one that still runs to `send`.
    fn due(&mut self, now: Instant, mut send: impl FnMut(Entry)) {
        while let Some(e) =
            self.jobs.pop_front_if(|e| e.done || e.deadline <= now)
        {
            self.first += 1;
            if !e.done {
                send(e);
            }
        }
    }

    /// The file I/O of job `seq` ended. Returns true if the job left the
    /// queue at its deadline, so it got an interim response.
    fn end(&mut self, seq: u64) -> bool {
        let Some(at) = seq.checked_sub(self.first) else {
            return true;
        };
        if let Some(e) =
            usize::try_from(at).ok().and_then(|i| self.jobs.get_mut(i))
        {
            e.done = true;
        }
        // Remove the ended jobs at the front now, not when the timer fires.
        while self.jobs.pop_front_if(|e| e.done).is_some() {
            self.first += 1;
        }
        false
    }
}

impl Interims {
    pub(crate) fn new(crypto: Option<CryptoOps>, push: PushHandle) -> Self {
        Interims {
            crypto,
            push,
            queue: Mutex::default(),
        }
    }

    /// Queue the interim response for the reply in `head`. The SMB2 header
    /// of the reply starts at `seal.hdr()`. An encrypted interim response
    /// gets `nonce`. Arm the timer if it does not run.
    pub(crate) fn watch(
        self: &Arc<Self>,
        fs: &mut FsConn<'_>,
        head: &[u8],
        seal: &Seal,
        nonce: &[u8; 16],
    ) -> Watch {
        let e = Entry {
            deadline: Instant::now() + AFTER,
            done: false,
            head: copy_head(head, seal.hdr(), nonce),
            seal: seal.interim(),
        };
        let mut q = lock(&self.queue);
        let seq = q.push(e);
        if !q.armed {
            self.arm(&mut q, fs, AFTER);
        }
        Watch {
            seq,
            interims: Arc::clone(self),
        }
    }

    /// Arm the timer to fire after `after`. If the ring refuses the timer,
    /// the next job arms a new one.
    fn arm(
        self: &Arc<Self>,
        q: &mut Queue,
        fs: &mut FsConn<'_>,
        after: Duration,
    ) {
        let me = Arc::clone(self);
        q.armed = fs
            .timeout(after, move |done, fs| me.fire(&done, fs))
            .is_some();
    }

    /// The timer ended. Send the interim responses that are due, and arm
    /// the timer for the next deadline.
    fn fire(self: &Arc<Self>, done: &FsDone, fs: &mut FsConn<'_>) {
        // A refused timer ends with an error and never ran, so `armed` is
        // not about it. The close of the connection also ends the timer
        // with an error.
        if done.result().is_err() {
            return;
        }
        let mut q = lock(&self.queue);
        q.armed = false;
        let now = Instant::now();
        q.due(now, |e| self.send(&e));
        if let Some(e) = q.jobs.front() {
            let after = e.deadline.saturating_duration_since(now);
            self.arm(&mut q, fs, after);
        }
    }

    /// Send the interim response of `e`. If it cannot be encrypted, the
    /// final reply cannot be either, and the reactor closes the connection.
    fn send(&self, e: &Entry) {
        let mut pdu = interim(&e.head, e.seal.hdr());
        if e.seal.apply(self.crypto.as_ref(), &mut pdu) {
            self.push.push(pdu);
        }
    }
}

impl Watch {
    /// The file I/O of the job ended. After an interim response, make the
    /// reply in `buf` the final response as smbd does. Its SMB2 header
    /// starts at `hdr`.
    pub(crate) fn finish(self, buf: &mut [u8], hdr: usize) {
        if lock(&self.interims.queue).end(self.seq) {
            set_async(buf, hdr);
        }
    }
}

/// The headers of the reply in `head` up to the end of its SMB2 header,
/// which starts at `hdr`. A transform header gets `nonce`, because smbd
/// encrypts an interim response with a nonce of its own.
fn copy_head(head: &[u8], hdr: usize, nonce: &[u8; 16]) -> [u8; HEAD_MAX] {
    let n = hdr + SMB2_HDR_SIZE;
    let mut out = [0; HEAD_MAX];
    out[..n].copy_from_slice(&head[..n]);
    if hdr > NBT_HDR_SIZE {
        let at = NBT_HDR_SIZE + SMB2_TF_NONCE;
        out[at..at + nonce.len()].copy_from_slice(nonce);
    }
    out
}

/// The interim response for the headers in `head`, as
/// `smbd_smb2_request_pending_timer()` builds it. The SMB2 header of the
/// reply starts at `hdr`. The encryption (`smb2_signing_encrypt_pdu()`)
/// fills in the rest of a transform header.
fn interim(head: &[u8], hdr: usize) -> Vec<u8> {
    let out = &head[hdr..hdr + SMB2_HDR_SIZE];
    let mut pdu = Vec::with_capacity(hdr + SMB2_HDR_SIZE + BODY.len());
    pdu.extend_from_slice(&head[..hdr]);
    let mut h = [0u8; SMB2_HDR_SIZE];
    h[..4].copy_from_slice(&SMB2_HDR_MAGIC);
    h[SMB2_HDR_LENGTH..SMB2_HDR_LENGTH + 2]
        .copy_from_slice(&64u16.to_le_bytes());
    h[SMB2_HDR_STATUS..SMB2_HDR_STATUS + 4]
        .copy_from_slice(&NT_STATUS_PENDING.to_le_bytes());
    for (at, len) in [
        (SMB2_HDR_OPCODE, 2),
        (SMB2_HDR_CREDIT, 2),
        (SMB2_HDR_MESSAGE_ID, 8),
        (SMB2_HDR_SESSION_ID, 8),
        (SMB2_HDR_SIGNATURE, 16),
    ] {
        h[at..at + len].copy_from_slice(&out[at..at + len]);
    }
    mark_async(&mut h, le32(out, SMB2_HDR_FLAGS) & !SMB2_HDR_FLAG_SIGNED);
    pdu.extend_from_slice(&h);
    pdu.extend_from_slice(&BODY);
    set_nbt_len(&mut pdu);
    pdu
}

/// Make the reply in `buf` the final response of a request with an interim
/// response. Its SMB2 header starts at `hdr`. The reply grants no credits.
fn set_async(buf: &mut [u8], hdr: usize) {
    let h = &mut buf[hdr..hdr + SMB2_HDR_SIZE];
    let flags = le32(h, SMB2_HDR_FLAGS);
    mark_async(h, flags);
    h[SMB2_HDR_CREDIT..SMB2_HDR_CREDIT + 2].fill(0);
}

/// Set the flags of the SMB2 header `h` to `flags` and the async flag, and
/// set the `AsyncId`. smbd uses the `MessageId` as the `AsyncId`.
fn mark_async(h: &mut [u8], flags: u32) {
    let flags = flags | SMB2_HDR_FLAG_ASYNC;
    h[SMB2_HDR_FLAGS..SMB2_HDR_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
    h.copy_within(
        SMB2_HDR_MESSAGE_ID..SMB2_HDR_MESSAGE_ID + 8,
        SMB2_HDR_ASYNC_ID,
    );
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{BODY, Entry, HEAD_MAX, Queue, copy_head, interim, set_async};
    use crate::crypto::Seal;
    use crate::wire::{SMB2_HDR_SIZE, le16, le32, le64};

    /// A reply header with the NBT header before it: WRITE, 33 credits,
    /// the server-to-redir and signed flags, `MessageId` 7, `TreeId` 5 and
    /// `SessionId` 9.
    fn reply() -> Vec<u8> {
        let mut b = vec![0u8; 4 + SMB2_HDR_SIZE + 17];
        let h = &mut b[4..];
        h[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        h[12..14].copy_from_slice(&9u16.to_le_bytes());
        h[14..16].copy_from_slice(&33u16.to_le_bytes());
        h[16..20].copy_from_slice(&0x09u32.to_le_bytes());
        h[24..32].copy_from_slice(&7u64.to_le_bytes());
        h[36..40].copy_from_slice(&5u32.to_le_bytes());
        h[40..48].copy_from_slice(&9u64.to_le_bytes());
        h[48..64].fill(0xaa);
        b
    }

    #[test]
    fn an_interim_response_is_smbds() {
        let pdu = interim(&reply(), 4);
        assert_eq!(pdu.len(), 4 + SMB2_HDR_SIZE + BODY.len());
        assert_eq!(&pdu[1..4], &[0, 0, 73]);
        let h = &pdu[4..];
        assert_eq!(le16(h, 4), 64);
        assert_eq!(le32(h, 8), 0x103);
        assert_eq!(le16(h, 12), 9);
        assert_eq!(le16(h, 14), 33, "the interim response has the credits");
        assert_eq!(le32(h, 16), 0x03, "async, not signed");
        assert_eq!(le64(h, 24), 7);
        assert_eq!(le64(h, 32), 7, "the AsyncId is the MessageId");
        assert_eq!(le64(h, 40), 9);
        assert_eq!(&h[48..64], &[0xaa; 16]);
        assert_eq!(&h[64..], &BODY);
    }

    #[test]
    fn an_encrypted_interim_response_has_its_nonce() {
        let mut head = vec![0u8; 4];
        let mut tf = [0u8; 52];
        tf[..4].copy_from_slice(&[0xfd, b'S', b'M', b'B']);
        tf[20..36].fill(0xee);
        tf[44..52].copy_from_slice(&9u64.to_le_bytes());
        head.extend_from_slice(&tf);
        head.extend_from_slice(&reply()[4..]);
        let pdu = interim(&copy_head(&head, 56, &[0x11; 16]), 56);
        assert_eq!(pdu.len(), 56 + SMB2_HDR_SIZE + BODY.len());
        assert_eq!(&pdu[24..40], &[0x11; 16], "not the nonce of the reply");
        assert_eq!(le64(&pdu, 48), 9);
        assert_eq!(le32(&pdu[56..], 8), 0x103);
    }

    #[test]
    fn the_final_response_grants_no_credits() {
        let mut b = reply();
        set_async(&mut b, 4);
        let h = &b[4..];
        assert_eq!(le16(h, 14), 0);
        assert_eq!(le32(h, 16), 0x0b, "the async flag is added");
        assert_eq!(le64(h, 32), 7, "the AsyncId replaces the TreeId");
        assert_eq!(le64(h, 24), 7);
    }

    /// A queued job with its deadline `ms` milliseconds after `t0`.
    fn job(t0: Instant, ms: u64) -> Entry {
        Entry {
            deadline: t0 + Duration::from_millis(ms),
            done: false,
            head: [0; HEAD_MAX],
            seal: Seal::None,
        }
    }

    #[test]
    fn a_job_that_ends_in_time_gets_no_interim_response() {
        let t0 = Instant::now();
        let mut q = Queue::default();
        let a = q.push(job(t0, 1));
        assert!(!q.end(a));
        assert!(q.jobs.is_empty(), "a left the queue when it ended");
        q.due(t0 + Duration::from_millis(2), |_| panic!("a ended in time"));
    }

    #[test]
    fn a_job_at_its_deadline_gets_an_interim_response() {
        let t0 = Instant::now();
        let mut q = Queue::default();
        let a = q.push(job(t0, 1));
        let b = q.push(job(t0, 2));
        let mut sent = Vec::new();
        q.due(t0 + Duration::from_millis(1), |e| sent.push(e.deadline));
        assert_eq!(sent, [t0 + Duration::from_millis(1)]);
        assert!(q.end(a), "a left the queue at its deadline");
        assert!(!q.end(b), "b is still in the queue");
        q.due(t0 + Duration::from_millis(3), |_| panic!("b ended in time"));
        assert!(q.jobs.is_empty());
        let c = q.push(job(t0, 4));
        assert_eq!(c, 2, "the numbers go on after the queue empties");
    }

    #[test]
    fn an_ended_job_does_not_hold_back_the_next_deadline() {
        let t0 = Instant::now();
        let mut q = Queue::default();
        let a = q.push(job(t0, 1));
        q.push(job(t0, 5));
        q.end(a);
        q.due(t0, |_| panic!("nothing is due"));
        let next = q.jobs.front().map(|e| e.deadline);
        assert_eq!(next, Some(t0 + Duration::from_millis(5)));
    }
}
