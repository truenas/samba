// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The primary role without I/O.
//!
//! `serve` passes requests and timer ticks to it and runs the `Effect`s that
//! it returns. An `Effect` is an epoch file write or the close of a
//! replication connection. Replies that must wait are kept as `Waiter`s. The
//! core runs on the server thread. It uses no locks.

use crate::auth::{self, LinkKey, Nonce, Side, Transcript};
use crate::epoch::{self, Bumped};
use crate::proto::encode;
use crate::proto::local::{HelloOk, Origin, RehydratePage, Reply, Synced};
use crate::proto::repl::{Batch, Challenge, ReplReply, ReplRequest, Snapshot};
use crate::proto::{self, BootId, Node, Op, Owner, Protection, VERSION};
use crate::store::{self, Header, Store};
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use truenas_ros::log::{Level, Logger};
use truenas_xdr::FixedOpaque;

/// A request that gets its reply later. The core replies to it or closes its
/// connection.
pub trait Waiter {
    /// Sends the framed reply `bytes`.
    fn reply(self, bytes: Vec<u8>);
    /// Closes the connection without a reply.
    fn close(self);
}

/// An action that the I/O layer runs for the core. `Bump` and `Advance`
/// report their result to the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Fence. Write an epoch above `floor` to the epoch file. Then call
    /// `Primary::epoch_bumped` with the result.
    Bump {
        /// The new epoch must be greater than this value.
        floor: u64,
    },
    /// Make the replica restorable. Write `tag` to the epoch file. Then call
    /// `Primary::epoch_advanced` with the result.
    Advance {
        /// The tag of the complete replica.
        tag: u64,
        /// The epoch that the core wrote last. The write fails if the file
        /// contains another epoch.
        from: u64,
    },
    /// Close the replication connection `conn`.
    Close {
        /// The connection number given to `Primary::repl_connect`.
        conn: u64,
    },
    /// Stop the primary. Start a new primary with an empty copy and a new
    /// instance. smbd then sends its handles again.
    Restart,
    /// Read the epoch file. Then call `Primary::epoch_read` with `writes`
    /// and the result.
    Read {
        /// The number of epoch file writes that the core started before.
        writes: u64,
    },
}

/// An error from an advance of the epoch file.
#[derive(Debug)]
pub enum AdvanceError {
    /// Another writer changed the epoch file.
    Stale {
        /// The epoch in the file.
        current: u64,
    },
    /// The write failed. It is not known if the file contains the tag.
    Failed(String),
}

/// The settings and the identity that the core uses.
#[derive(Clone, Debug)]
pub struct Settings {
    /// If the core holds a poll for this time, it replies with a heartbeat.
    pub heartbeat: Duration,
    /// The standby must send its next request within this time after a reply.
    pub link_timeout: Duration,
    /// The core loses the standby when the unacknowledged operations exceed
    /// this number of bytes.
    pub max_lag_bytes: usize,
    /// The size limit of a snapshot chunk, a batch and a rehydration page,
    /// in bytes.
    pub chunk_bytes: usize,
    /// The maximum size of a record body, in bytes.
    pub max_record_bytes: usize,
    /// The path of the epoch file. `HelloOk` reports it.
    pub epoch_file: String,
    /// This controller.
    pub node: Node,
    /// The boot id of this controller.
    pub boot: BootId,
    /// A random value that identifies this primary. `HelloOk` reports it.
    /// smbd sends all its handles again when it changes.
    pub instance: u64,
    /// The source of random bytes for nonces.
    pub random: fn(&mut [u8]),
}

/// The protection state of the primary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// A bump of the epoch file is not complete. Promises wait.
    Fencing,
    /// No replica is restorable.
    Unprotected,
    /// A standby receives a snapshot.
    Resyncing,
    /// The standby has the complete snapshot. The core waits until the
    /// standby acknowledges every operation applied before this state.
    Reprotecting,
    /// A write of the replica tag to the epoch file is in progress.
    Advancing,
    /// The replica is restorable.
    Protected,
}

enum Stage {
    Hello,
    Prove {
        standby_node: Node,
        standby_nonce: Nonce,
        nonce: Nonce,
    },
    Ready,
    Snapshot {
        cursor: u64,
        sent_first: bool,
        sent_last: bool,
    },
    Stream,
}

struct Session<W> {
    conn: u64,
    stage: Stage,
    tag: u64,
    snap_seq: u64,
    acked: u64,
    outbox: VecDeque<(u64, Op, usize)>,
    outbox_bytes: usize,
    poll: Option<(W, Instant)>,
    deadline: Option<Instant>,
}

/// The copy, the protection state and the standby session of the primary.
pub struct Primary<W> {
    s: Settings,
    log: Logger,
    key: LinkKey,
    store: Store,
    header: Header,
    origin: Origin,
    next: Option<Store>,
    seq: u64,
    epoch: u64,
    last_tag: u64,
    reprotect_at: u64,
    state: State,
    retry_bump_at: Option<Instant>,
    /// The tag of an advance that failed after an unknown result.
    maybe_written: Option<u64>,
    /// The number of `Bump` and `Advance` effects.
    writes: u64,
    /// When `tick` reads the epoch file next.
    read_at: Option<Instant>,
    /// The local connection that started the rehydration.
    rehydrator: Option<u64>,
    /// The copy can lack changes. See `discard`.
    discarded: bool,
    session: Option<Session<W>>,
    pending: Option<Session<W>>,
    waiters: VecDeque<(u64, W)>,
    effects: Vec<Effect>,
}

impl<W> std::fmt::Debug for Primary<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Primary")
            .field("state", &self.state)
            .field("epoch", &self.epoch)
            .field("seq", &self.seq)
            .field("records", &self.store.len())
            .finish_non_exhaustive()
    }
}

fn send<W: Waiter, T: Serialize>(w: W, v: &T) {
    match encode(v) {
        Some(bytes) => w.reply(bytes),
        None => w.close(),
    }
}

fn op_charge(op: &Op) -> usize {
    match op {
        Op::Put(r) => store::charge(r),
        Op::Del(_) => 12,
    }
}

impl<W: Waiter> Primary<W> {
    /// Creates a primary that serves `store` under `epoch`. The caller has
    /// written `epoch` with `EpochFile::bump`. No replica is restorable.
    pub fn new(
        s: Settings,
        key: LinkKey,
        store: Store,
        header: Header,
        origin: Origin,
        epoch: u64,
        log: Logger,
    ) -> Primary<W> {
        let last_tag = epoch.max(header.tag);
        Primary {
            s,
            log,
            key,
            store,
            header,
            origin,
            next: None,
            seq: 0,
            epoch,
            last_tag,
            reprotect_at: 0,
            state: State::Unprotected,
            retry_bump_at: None,
            maybe_written: None,
            writes: 0,
            read_at: None,
            rehydrator: None,
            discarded: false,
            session: None,
            pending: None,
            waiters: VecDeque::new(),
            effects: Vec::new(),
        }
    }

    /// Returns the protection state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Returns the last known epoch in the epoch file.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the number of operations applied to the copy.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the number of records in the copy.
    pub fn records(&self) -> usize {
        self.store.len()
    }

    /// Returns the protection for `HelloOk` and for a `SyncLevel::Local` reply.
    pub fn protection(&self) -> Protection {
        if self.state == State::Protected && self.next.is_none() {
            Protection::Protected
        } else {
            Protection::Unprotected
        }
    }

    /// Returns true after the core asked for a restart with an empty copy.
    pub fn discarded(&self) -> bool {
        self.discarded
    }

    /// Returns and clears the effects added since the last call.
    pub fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// Returns the copy for the next role. If a rehydration is in progress,
    /// the next generation is discarded.
    pub fn into_copy(self) -> (Store, Header, Origin) {
        (self.store, self.header, self.origin)
    }

    // ---- smbd -------------------------------------------------------------

    /// Returns the `HelloOk` reply to a `Hello`.
    pub fn hello(&self) -> HelloOk {
        HelloOk {
            version: VERSION,
            instance: self.s.instance,
            protection: self.protection(),
            epoch: self.epoch,
            epoch_file: self.s.epoch_file.clone(),
            node: self.s.node,
        }
    }

    /// Replaces each put of a `Submit` that the copy cannot hold with a
    /// delete of its id: a record body larger than `max_record_bytes` or a
    /// share name longer than 256 bytes. The handle is then not restored.
    /// `serve` calls it before `submit`. Returns the number of replaced puts.
    pub fn fit_ops(&self, ops: &mut [Op]) -> usize {
        let mut replaced = 0;
        for op in ops.iter_mut() {
            if let Op::Put(r) = op
                && (r.body.0.len() > self.s.max_record_bytes
                    || r.share.len() > 256)
            {
                *op = Op::Del(r.id);
                replaced += 1;
            }
        }
        replaced
    }

    /// Applies the operations of a `Submit`. The caller then replies by the
    /// sync level: `synced()` for `SyncLevel::Local`, `sync_remote()` for
    /// `SyncLevel::Remote`.
    pub fn submit(&mut self, ops: Vec<Op>, now: Instant) {
        for op in ops {
            self.apply(op);
        }
        self.after_apply(now);
    }

    /// Deletes the records of a process that exited, except the records of
    /// the processes in `keep`.
    pub fn forget_owner(&mut self, owner: Owner, keep: &[Owner], now: Instant) {
        if let Some(next) = &mut self.next {
            next.forget_owner(owner, keep);
            return;
        }
        for id in self.store.owned_by(owner, keep) {
            self.apply(Op::Del(id));
        }
        self.after_apply(now);
    }

    /// Returns a page of the copy for the smbd parent process on the local
    /// connection `conn`. A page starts an empty next generation if its
    /// cursor is 0 or if no rehydration is in progress. Until `done`, the
    /// core applies submitted operations to the next generation only.
    pub fn rehydrate(
        &mut self,
        cursor: u64,
        max_bytes: usize,
        conn: u64,
    ) -> RehydratePage {
        if cursor == 0 || self.next.is_none() {
            self.next = Some(Store::default());
        }
        self.rehydrator = Some(conn);
        let (records, next_cursor, last) = if self.origin == Origin::None {
            (Vec::new(), 0, true)
        } else {
            self.store.page(cursor, max_bytes.min(self.s.chunk_bytes))
        };
        RehydratePage {
            origin: self.origin,
            epoch: self.epoch,
            writer_node: self.header.writer_node,
            writer_boot: self.header.writer_boot,
            next_cursor,
            last,
            records,
        }
    }

    /// Ends a rehydration. Returns the new generation number. If a
    /// rehydration is in progress, the next generation becomes the copy. The
    /// core ends the standby session and fences the replica. The standby
    /// then reconnects and gets a full resync.
    pub fn done(&mut self) -> u64 {
        if let Some(next) = self.next.take() {
            self.store = next;
        }
        self.rehydrator = None;
        self.header.generation += 1;
        self.header.tag = 0;
        self.header.writer_node = self.s.node;
        self.header.writer_boot = self.s.boot;
        self.origin = Origin::Own;
        if self.session.is_some() {
            self.lose_standby("the copy was replaced after a rehydration");
        }
        if matches!(
            self.state,
            State::Protected | State::Reprotecting | State::Advancing
        ) {
            self.fence();
        }
        if self.state == State::Unprotected {
            self.release_all();
        }
        truenas_ros::log!(
            self.log,
            Level::Notice,
            "rehydration done: generation {}, {} records",
            self.header.generation,
            self.store.len()
        );
        self.header.generation
    }

    /// Handles the close of the local connection `conn`. A parent that
    /// closes its connection before `done` ends its rehydration. The copy
    /// then has the records that the parent sent.
    pub fn local_closed(&mut self, conn: u64) {
        if self.rehydrator == Some(conn) && self.next.is_some() {
            truenas_ros::log!(
                self.log,
                Level::Warning,
                "smbd's parent closed its connection during a rehydration"
            );
            self.done();
        }
    }

    /// The reply to a submit with `SyncLevel::Local`.
    pub fn synced(&self) -> Synced {
        Synced {
            protection: self.protection(),
            epoch: self.epoch,
        }
    }

    fn reply_synced(&self, w: W, protection: Protection) {
        send(
            w,
            &Reply::Synced(Synced {
                protection,
                epoch: self.epoch,
            }),
        );
    }

    fn acked(&self) -> u64 {
        match &self.session {
            Some(s) if matches!(s.stage, Stage::Stream) => s.acked,
            _ => 0,
        }
    }

    /// Replies to `w` when the standby has the submitted operations, or
    /// after a fence. For a submit with `SyncLevel::Remote`.
    pub fn sync_remote(&mut self, w: W) {
        if self.next.is_some() {
            // A rehydration is in progress. The operations are in the next
            // generation. No standby has the next generation. The reply waits
            // until the replica is fenced.
            match self.state {
                State::Unprotected => {
                    self.reply_synced(w, Protection::Unprotected);
                }
                State::Resyncing => {
                    // The snapshot has the frozen copy without the change.
                    // Its tag is not in the epoch file yet.
                    self.lose_standby("a promise during a rehydration");
                    self.reply_synced(w, Protection::Unprotected);
                }
                State::Fencing => self.waiters.push_back((u64::MAX, w)),
                State::Protected | State::Reprotecting | State::Advancing => {
                    self.waiters.push_back((u64::MAX, w));
                    self.lose_standby("a promise during a rehydration");
                }
            }
            return;
        }
        let target = self.seq;
        match self.state {
            State::Unprotected | State::Resyncing => {
                self.reply_synced(w, Protection::Unprotected);
            }
            State::Fencing | State::Reprotecting | State::Advancing => {
                self.waiters.push_back((target, w));
            }
            State::Protected => {
                if self.acked() >= target {
                    self.reply_synced(w, Protection::Protected);
                } else {
                    self.waiters.push_back((target, w));
                }
            }
        }
    }

    fn release_acked(&mut self, acked: u64) {
        while self.waiters.front().is_some_and(|(t, _)| *t <= acked) {
            if let Some((_, w)) = self.waiters.pop_front() {
                self.reply_synced(w, Protection::Protected);
            }
        }
    }

    fn release_all(&mut self) {
        while let Some((_, w)) = self.waiters.pop_front() {
            self.reply_synced(w, Protection::Unprotected);
        }
    }

    fn apply(&mut self, op: Op) {
        if let Some(next) = &mut self.next {
            next.apply(op);
            return;
        }
        if self.origin == Origin::None {
            // Nothing was restorable at start. The first operation makes the
            // copy `Origin::Own`. The writer becomes this node and boot.
            self.origin = Origin::Own;
            self.header.writer_node = self.s.node;
            self.header.writer_boot = self.s.boot;
        }
        self.seq += 1;
        if let Some(s) = &mut self.session
            && matches!(s.stage, Stage::Snapshot { .. } | Stage::Stream)
        {
            let c = op_charge(&op);
            s.outbox_bytes += c;
            s.outbox.push_back((self.seq, op.clone(), c));
        }
        self.store.apply(op);
    }

    fn after_apply(&mut self, now: Instant) {
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.outbox_bytes > self.s.max_lag_bytes)
        {
            self.lose_standby(
                "the standby fell more than max_lag_bytes behind",
            );
            return;
        }
        self.send_batch(now);
    }

    fn send_batch(&mut self, now: Instant) {
        let chunk = self.s.chunk_bytes;
        let link_timeout = self.s.link_timeout;
        let Some(s) = &mut self.session else { return };
        if !matches!(s.stage, Stage::Stream) || s.outbox.is_empty() {
            return;
        }
        let Some((w, _)) = s.poll.take() else { return };
        let first_seq = s.outbox.front().map_or(0, |(seq, ..)| *seq);
        let mut ops = Vec::new();
        let mut bytes = 0;
        for (_, op, c) in &s.outbox {
            if !ops.is_empty() && bytes + c > chunk {
                break;
            }
            bytes += c;
            ops.push(op.clone());
        }
        s.deadline = Some(now + link_timeout);
        send(w, &ReplReply::Batch(Batch { first_seq, ops }));
    }

    // ---- the standby --------------------------------------------------------

    /// Adds a new connection from the peer address. A new connection
    /// replaces the session only after it authenticates. A connection
    /// without the key cannot end a protected session.
    pub fn repl_connect(&mut self, conn: u64, now: Instant) {
        if self.discarded {
            self.effects.push(Effect::Close { conn });
            return;
        }
        if let Some(old) = self.pending.take() {
            self.drop_pending(old);
        }
        self.pending = Some(Session {
            conn,
            stage: Stage::Hello,
            tag: 0,
            snap_seq: 0,
            acked: 0,
            outbox: VecDeque::new(),
            outbox_bytes: 0,
            poll: None,
            deadline: Some(now + self.s.link_timeout),
        });
    }

    fn drop_pending(&mut self, p: Session<W>) {
        if let Some((w, _)) = p.poll {
            w.close();
        }
        self.effects.push(Effect::Close { conn: p.conn });
    }

    /// Handles the close of a replication connection.
    pub fn repl_closed(&mut self, conn: u64) {
        if self.pending.as_ref().is_some_and(|p| p.conn == conn) {
            self.pending = None;
        } else if self.session.as_ref().is_some_and(|s| s.conn == conn) {
            self.lose_standby("the standby connection closed");
        }
    }

    /// Handles a request on a replication connection. The core replies
    /// through `w`, now or later.
    pub fn repl_request(
        &mut self,
        conn: u64,
        req: ReplRequest,
        w: W,
        now: Instant,
    ) {
        if self.pending.as_ref().is_some_and(|p| p.conn == conn) {
            self.handshake(req, w, now);
            return;
        }
        let Some(s) = self.session.as_mut().filter(|s| s.conn == conn) else {
            w.close();
            return;
        };
        s.deadline = None;
        let stage = std::mem::replace(&mut s.stage, Stage::Ready);
        match (stage, req) {
            (Stage::Ready, ReplRequest::Poll(_)) => {
                s.stage = Stage::Ready;
                match self.state {
                    // No snapshot starts during a rehydration. After `done`,
                    // the standby reconnects and gets a full resync.
                    State::Unprotected if self.next.is_none() => {
                        self.start_snapshot(w, now);
                    }
                    State::Unprotected | State::Fencing => {
                        if let Some(s) = self.session.as_mut() {
                            s.poll = Some((w, now));
                        }
                    }
                    _ => {
                        w.close();
                        self.lose_standby("a standby polled out of turn");
                    }
                }
            }
            (stage @ Stage::Snapshot { .. }, ReplRequest::Poll(acked)) => {
                s.stage = stage;
                self.snapshot_poll(acked, w, now);
            }
            (Stage::Stream, ReplRequest::Poll(acked)) => {
                s.stage = Stage::Stream;
                self.stream_poll(acked, w, now);
            }
            (stage, _) => {
                s.stage = stage;
                w.close();
                self.lose_standby("the standby broke the protocol");
            }
        }
    }

    /// Handles a request of a connection that has not authenticated yet.
    fn handshake(&mut self, req: ReplRequest, w: W, now: Instant) {
        let link_timeout = self.s.link_timeout;
        let Some(mut p) = self.pending.take() else {
            w.close();
            return;
        };
        p.deadline = None;
        let stage = std::mem::replace(&mut p.stage, Stage::Hello);
        match (stage, req) {
            (Stage::Hello, ReplRequest::Hello(h)) if h.node == self.s.node => {
                truenas_ros::log!(
                    self.log,
                    Level::Warning,
                    "a standby says that it is node {} too",
                    h.node
                );
                w.close();
                self.drop_pending(p);
            }
            (Stage::Hello, ReplRequest::Hello(h))
                if h.version >= proto::MIN_VERSION =>
            {
                let mut nonce = [0u8; 32];
                (self.s.random)(&mut nonce);
                let nonce = FixedOpaque(nonce);
                let proof = auth::proof(
                    &self.key,
                    Side::Primary,
                    &Transcript {
                        standby_node: h.node,
                        standby_nonce: &h.nonce,
                        primary_node: self.s.node,
                        primary_nonce: &nonce,
                    },
                );
                p.stage = Stage::Prove {
                    standby_node: h.node,
                    standby_nonce: h.nonce,
                    nonce,
                };
                p.deadline = Some(now + link_timeout);
                self.pending = Some(p);
                send(
                    w,
                    &ReplReply::Challenge(Challenge {
                        version: VERSION.min(h.version),
                        node: self.s.node,
                        nonce,
                        proof,
                    }),
                );
            }
            (
                Stage::Prove {
                    standby_node,
                    standby_nonce,
                    nonce,
                },
                ReplRequest::Prove(proof),
            ) => {
                let ok = auth::verify(
                    &self.key,
                    Side::Standby,
                    &Transcript {
                        standby_node,
                        standby_nonce: &standby_nonce,
                        primary_node: self.s.node,
                        primary_nonce: &nonce,
                    },
                    &proof,
                );
                if !ok {
                    truenas_ros::log!(
                        self.log,
                        Level::Warning,
                        "a standby failed authentication"
                    );
                    w.close();
                    self.drop_pending(p);
                    return;
                }
                if self.session.is_some() {
                    self.lose_standby("a new standby connection replaced it");
                }
                p.stage = Stage::Ready;
                p.deadline = Some(now + link_timeout);
                self.session = Some(p);
                truenas_ros::log!(
                    self.log,
                    Level::Notice,
                    "standby authenticated"
                );
                send(w, &ReplReply::Welcome(self.header.generation));
            }
            _ => {
                w.close();
                self.drop_pending(p);
            }
        }
    }

    fn start_snapshot(&mut self, w: W, now: Instant) {
        self.last_tag = epoch::next_tag(self.last_tag.max(self.epoch));
        let tag = self.last_tag;
        let seq = self.seq;
        let Some(s) = &mut self.session else {
            w.close();
            return;
        };
        s.tag = tag;
        s.snap_seq = seq;
        s.stage = Stage::Snapshot {
            cursor: 0,
            sent_first: false,
            sent_last: false,
        };
        self.state = State::Resyncing;
        truenas_ros::log!(
            self.log,
            Level::Notice,
            "resyncing the standby: {} records under tag {tag}",
            self.store.len()
        );
        self.snapshot_poll(0, w, now);
    }

    fn snapshot_poll(&mut self, acked: u64, w: W, now: Instant) {
        let link_timeout = self.s.link_timeout;
        let chunk = self.s.chunk_bytes;
        let Some(s) = &mut self.session else {
            w.close();
            return;
        };
        let Stage::Snapshot {
            cursor,
            sent_first,
            sent_last,
        } = &s.stage
        else {
            w.close();
            return;
        };
        let (cursor, sent_first, sent_last) =
            (*cursor, *sent_first, *sent_last);
        if sent_last {
            if acked != s.snap_seq {
                w.close();
                self.lose_standby(
                    "the standby acknowledged the wrong snapshot",
                );
                return;
            }
            s.stage = Stage::Stream;
            self.state = State::Reprotecting;
            self.reprotect_at = self.seq;
            self.stream_poll(acked, w, now);
            return;
        }
        let (records, next, last) = self.store.page(cursor, chunk);
        s.stage = Stage::Snapshot {
            cursor: next,
            sent_first: true,
            sent_last: last,
        };
        s.deadline = Some(now + link_timeout);
        send(
            w,
            &ReplReply::Snapshot(Snapshot {
                generation: self.header.generation,
                tag: s.tag,
                writer_node: self.header.writer_node,
                writer_boot: self.header.writer_boot,
                first: !sent_first,
                last,
                seq: s.snap_seq,
                records,
            }),
        );
    }

    fn stream_poll(&mut self, acked: u64, w: W, now: Instant) {
        let seq = self.seq;
        let Some(s) = &mut self.session else {
            w.close();
            return;
        };
        if acked < s.acked || acked > seq {
            w.close();
            self.lose_standby("the standby acknowledged out of range");
            return;
        }
        s.acked = acked;
        while s.outbox.front().is_some_and(|(q, ..)| *q <= acked) {
            if let Some((_, _, c)) = s.outbox.pop_front() {
                s.outbox_bytes -= c;
            }
        }
        s.poll = Some((w, now));
        let tag = s.tag;
        if self.state == State::Reprotecting && acked >= self.reprotect_at {
            self.state = State::Advancing;
            self.writes += 1;
            self.effects.push(Effect::Advance {
                tag,
                from: self.epoch,
            });
        }
        if self.state == State::Protected {
            self.release_acked(acked);
        }
        self.send_batch(now);
    }

    /// Runs the timers: the retry of a failed fence, the check of the epoch
    /// file, the handshake deadline, the heartbeat and the link timeout.
    pub fn tick(&mut self, now: Instant) {
        if self.state == State::Fencing
            && self.retry_bump_at.is_some_and(|t| t <= now)
        {
            self.retry_bump_at = None;
            self.writes += 1;
            self.effects.push(Effect::Bump {
                floor: self.floor(),
            });
        }
        // smbd fences when it cannot reach the daemon. Once a second, a
        // protected primary checks that the file still has its tag.
        if self.state == State::Protected
            && self.read_at.is_none_or(|t| t <= now)
        {
            self.read_at = Some(now + Duration::from_secs(1));
            self.effects.push(Effect::Read {
                writes: self.writes,
            });
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.deadline.is_some_and(|d| now >= d))
            && let Some(p) = self.pending.take()
        {
            self.drop_pending(p);
        }
        let heartbeat = self.s.heartbeat;
        let link_timeout = self.s.link_timeout;
        let seq = self.seq;
        let Some(s) = &mut self.session else { return };
        match s.poll.take() {
            Some((w, since)) if now.duration_since(since) >= heartbeat => {
                s.deadline = Some(now + link_timeout);
                send(w, &ReplReply::Heartbeat(seq));
            }
            Some(parked) => s.poll = Some(parked),
            None => {
                if s.deadline.is_some_and(|d| now >= d) {
                    self.lose_standby("the standby went silent");
                }
            }
        }
    }

    /// Handles the result of an `Effect::Bump`.
    pub fn epoch_bumped(
        &mut self,
        result: Result<Bumped, String>,
        now: Instant,
    ) {
        match result {
            Ok(Bumped { previous, epoch }) => {
                let foreign = previous != self.epoch
                    && Some(previous) != self.maybe_written;
                self.epoch = self.epoch.max(epoch);
                self.last_tag = self.last_tag.max(epoch);
                self.maybe_written = None;
                if foreign {
                    self.discard(previous);
                    return;
                }
                if self.state != State::Fencing {
                    return;
                }
                self.state = State::Unprotected;
                truenas_ros::log!(
                    self.log,
                    Level::Notice,
                    "fenced: epoch {epoch}, unprotected"
                );
                self.release_all();
                // No snapshot starts during a rehydration.
                let rehydrating = self.next.is_some();
                let parked = match &mut self.session {
                    Some(s)
                        if matches!(s.stage, Stage::Ready) && !rehydrating =>
                    {
                        s.poll.take().map(|(w, _)| w)
                    }
                    _ => None,
                };
                if let Some(w) = parked {
                    self.start_snapshot(w, now);
                }
            }
            Err(e) => {
                truenas_ros::log!(
                    self.log,
                    Level::Warning,
                    "fencing failed, promises stay held: {e}"
                );
                if self.state == State::Fencing {
                    self.retry_bump_at = Some(now + Duration::from_secs(1));
                }
            }
        }
    }

    /// Handles the result of an `Effect::Read`. A read is out of date if
    /// the core started a write after it.
    pub fn epoch_read(&mut self, writes: u64, result: Result<u64, String>) {
        if writes != self.writes || self.state != State::Protected {
            return;
        }
        match result {
            Ok(found) if found != self.epoch => self.discard(found),
            Ok(_) => {}
            Err(e) => truenas_ros::log!(
                self.log,
                Level::Warning,
                "reading the epoch file: {e}"
            ),
        }
    }

    /// Handles the result of an `Effect::Advance` for `tag`.
    pub fn epoch_advanced(
        &mut self,
        tag: u64,
        result: Result<(), AdvanceError>,
    ) {
        match result {
            Ok(()) => {
                self.epoch = self.epoch.max(tag);
                if self.state == State::Advancing {
                    self.state = State::Protected;
                    truenas_ros::log!(
                        self.log,
                        Level::Notice,
                        "protected: epoch {tag}"
                    );
                    let acked = self.acked();
                    self.release_acked(acked);
                }
            }
            Err(AdvanceError::Stale { current }) => {
                self.last_tag = self.last_tag.max(current);
                self.discard(current);
            }
            Err(AdvanceError::Failed(e)) => {
                truenas_ros::log!(
                    self.log,
                    Level::Warning,
                    "advancing the epoch failed: {e}"
                );
                // The file can have the tag. A later bump reads it.
                self.maybe_written = Some(tag);
                if self.state == State::Advancing {
                    self.lose_standby("the epoch file could not be advanced");
                }
            }
        }
    }

    /// The epoch file has `found`, an epoch that this core did not write.
    /// An smbd process fenced because it could not reach the daemon. The
    /// copy can lack changes of that process. A later advance must not
    /// make such a copy restorable. The core answers the waiting promises
    /// unprotected: the file holds a fence. Then the I/O layer starts a new
    /// primary with an empty copy.
    fn discard(&mut self, found: u64) {
        if self.discarded {
            return;
        }
        truenas_ros::log!(
            self.log,
            Level::Warning,
            "another writer fenced the epoch file at {found}; dropping the \
             copy of {} records",
            self.store.len()
        );
        self.discarded = true;
        if let Some(s) = self.session.take() {
            if let Some((w, _)) = s.poll {
                w.close();
            }
            self.effects.push(Effect::Close { conn: s.conn });
        }
        if let Some(p) = self.pending.take() {
            self.drop_pending(p);
        }
        self.state = State::Unprotected;
        self.release_all();
        self.effects.push(Effect::Restart);
    }

    fn floor(&self) -> u64 {
        self.epoch.max(self.last_tag)
    }

    fn fence(&mut self) {
        self.state = State::Fencing;
        self.writes += 1;
        self.effects.push(Effect::Bump {
            floor: self.floor(),
        });
    }

    fn lose_standby(&mut self, why: &str) {
        let Some(s) = self.session.take() else { return };
        truenas_ros::log!(self.log, Level::Warning, "standby lost: {why}");
        if let Some((w, _)) = s.poll {
            w.close();
        }
        self.effects.push(Effect::Close { conn: s.conn });
        match self.state {
            State::Protected | State::Reprotecting | State::Advancing => {
                self.fence();
            }
            State::Resyncing => self.state = State::Unprotected,
            State::Unprotected | State::Fencing => {}
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::single_match_else
)]
mod tests {
    use super::*;
    use crate::proto::local::Reply;
    use crate::proto::{Record, SyncLevel};
    use crate::standby::Standby;
    use std::cell::RefCell;
    use std::rc::Rc;
    use truenas_xdr::VarOpaque;

    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Reply(Vec<u8>),
        Closed,
    }

    type Slot = Rc<RefCell<Option<Outcome>>>;

    struct TestWaiter(Slot);

    impl Waiter for TestWaiter {
        fn reply(self, bytes: Vec<u8>) {
            *self.0.borrow_mut() = Some(Outcome::Reply(bytes));
        }
        fn close(self) {
            *self.0.borrow_mut() = Some(Outcome::Closed);
        }
    }

    fn waiter() -> (TestWaiter, Slot) {
        let slot: Slot = Rc::new(RefCell::new(None));
        (TestWaiter(Rc::clone(&slot)), slot)
    }

    fn zero(buf: &mut [u8]) {
        buf.fill(7);
    }

    const PNODE: Node = Node::A;
    const PB: BootId = FixedOpaque([2; 16]);
    const SNODE: Node = Node::B;
    const SB: BootId = FixedOpaque([4; 16]);

    fn settings() -> Settings {
        Settings {
            heartbeat: Duration::from_millis(100),
            link_timeout: Duration::from_millis(500),
            max_lag_bytes: 1 << 20,
            chunk_bytes: 2048,
            max_record_bytes: 1024,
            epoch_file: "/test/epoch".to_owned(),
            node: PNODE,
            boot: PB,
            instance: 1,
            random: zero,
        }
    }

    fn rec(id: u64, pid: u32, body: &[u8]) -> Record {
        Record {
            id,
            share: "data".to_owned(),
            owner: Owner { pid, unique_id: 1 },
            flags: 0,
            body: VarOpaque(body.to_vec()),
        }
    }

    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
        truenas_xdr::from_bytes(&bytes[4..]).unwrap()
    }

    /// The primary and the standby under test, and the fake epoch file.
    /// `pending` is the standby request that waits at the primary.
    struct Pair {
        p: Primary<TestWaiter>,
        sb: Standby,
        file: u64,
        conn: u64,
        open: bool,
        pending: Option<Slot>,
        now: Instant,
        /// The number of snapshots that the standby completed.
        completed: u64,
        /// The last write to the epoch file was a fence, not an advance.
        fenced_last: bool,
        /// The number of times a new primary replaced `p`.
        restarts: usize,
    }

    impl Pair {
        fn new(records: &[Record], key_s: &[u8]) -> Pair {
            let mut store = Store::default();
            for r in records {
                store.apply(Op::Put(r.clone()));
            }
            let file = 2;
            let p = Primary::new(
                settings(),
                LinkKey::derive(b"secret"),
                store,
                Header::empty(PNODE, PB),
                Origin::Own,
                file,
                Logger::silent(),
            );
            let sb = Standby::new(
                LinkKey::derive(key_s),
                SNODE,
                SB,
                zero,
                Store::default(),
                Header::empty(SNODE, SB),
                Logger::silent(),
            );
            Pair {
                p,
                sb,
                file,
                conn: 0,
                open: false,
                pending: None,
                now: Instant::now(),
                completed: 0,
                fenced_last: true,
                restarts: 0,
            }
        }

        /// Replaces the primary as `serve::run` does. The new primary keeps
        /// the copy if `keep` and the epoch file did not move.
        fn restart(&mut self, keep: bool) {
            let old = std::mem::replace(
                &mut self.p,
                Primary::new(
                    settings(),
                    LinkKey::derive(b"secret"),
                    Store::default(),
                    Header::empty(PNODE, PB),
                    Origin::Own,
                    0,
                    Logger::silent(),
                ),
            );
            let keep = keep && !old.discarded() && old.epoch() == self.file;
            let (store, header, origin) = if keep {
                old.into_copy()
            } else {
                (Store::default(), Header::empty(PNODE, PB), Origin::None)
            };
            self.file = start_fence(self.file, header.tag);
            self.fenced_last = true;
            self.p = Primary::new(
                settings(),
                LinkKey::derive(b"secret"),
                store,
                header,
                origin,
                self.file,
                Logger::silent(),
            );
            self.pending = None;
            self.open = false;
            self.restarts += 1;
        }

        fn connect(&mut self) {
            self.conn += 1;
            self.open = true;
            self.p.repl_connect(self.conn, self.now);
            let hello = self.sb.start();
            self.send(hello);
        }

        fn send(&mut self, req: ReplRequest) {
            let (w, slot) = waiter();
            self.p.repl_request(self.conn, req, w, self.now);
            self.pending = Some(slot);
            self.effects();
        }

        /// Runs the effects as the I/O layer does. Each write to the fake
        /// epoch file completes at once.
        fn effects(&mut self) {
            loop {
                let effects = self.p.take_effects();
                if effects.is_empty() {
                    return;
                }
                for e in effects {
                    match e {
                        Effect::Bump { floor } => {
                            let previous = self.file;
                            self.file = epoch::next_fence(self.file.max(floor))
                                .unwrap();
                            self.fenced_last = true;
                            let epoch = self.file;
                            self.p.epoch_bumped(
                                Ok(Bumped { previous, epoch }),
                                self.now,
                            );
                        }
                        Effect::Advance { tag, from } => {
                            if self.file == from && tag > self.file {
                                self.file = tag;
                                self.fenced_last = false;
                                self.p.epoch_advanced(tag, Ok(()));
                            } else {
                                let current = self.file;
                                self.p.epoch_advanced(
                                    tag,
                                    Err(AdvanceError::Stale { current }),
                                );
                            }
                        }
                        Effect::Close { conn } => {
                            if conn == self.conn {
                                self.open = false;
                            }
                        }
                        Effect::Restart => {
                            self.restart(false);
                            return;
                        }
                        Effect::Read { writes } => {
                            let found = self.file;
                            self.p.epoch_read(writes, Ok(found));
                        }
                    }
                }
            }
        }

        /// Delivers replies to the standby until the primary holds the next
        /// request. Returns the number of replies delivered.
        fn pump(&mut self) -> Result<usize, String> {
            let mut n = 0;
            loop {
                let Some(slot) = self.pending.clone() else {
                    return Ok(n);
                };
                let outcome = slot.borrow_mut().take();
                match outcome {
                    None => return Ok(n),
                    Some(Outcome::Closed) => {
                        self.pending = None;
                        self.open = false;
                        return Err("closed".to_owned());
                    }
                    Some(Outcome::Reply(bytes)) => {
                        n += 1;
                        let reply: ReplReply = decode(&bytes);
                        let last =
                            matches!(&reply, ReplReply::Snapshot(s) if s.last);
                        let next = self.sb.on_reply(reply)?;
                        if last {
                            self.completed += 1;
                        }
                        self.send(next);
                    }
                }
            }
        }

        fn advance(&mut self, by: Duration) {
            self.now += by;
            self.p.tick(self.now);
            self.effects();
        }

        fn submit(&mut self, ops: Vec<Op>, sync: SyncLevel) -> Option<Slot> {
            self.p.submit(ops, self.now);
            let slot = (sync == SyncLevel::Remote).then(|| {
                let (w, slot) = waiter();
                self.p.sync_remote(w);
                slot
            });
            self.effects();
            slot
        }
    }

    fn synced(slot: &Slot) -> Option<Protection> {
        match slot.borrow_mut().take() {
            Some(Outcome::Reply(b)) => match decode::<Reply>(&b) {
                Reply::Synced(s) => Some(s.protection),
                other => panic!("not synced: {other:?}"),
            },
            Some(Outcome::Closed) => panic!("closed"),
            None => None,
        }
    }

    fn protected_pair(records: &[Record]) -> Pair {
        let mut pair = Pair::new(records, b"secret");
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        pair
    }

    #[test]
    fn a_standby_resyncs_and_the_primary_becomes_protected() {
        let records: Vec<Record> =
            (1..=40).map(|i| rec(i, 10, &[i as u8; 200])).collect();
        let pair = protected_pair(&records);
        assert_eq!(pair.sb.tag(), pair.file, "the tag is the file's epoch");
        assert_eq!(pair.sb.records(), 40);
        let (store, header) = pair.sb.into_copy();
        assert_eq!(header.writer_node, PNODE);
        assert_eq!(store.page(0, usize::MAX).0, records);
    }

    #[test]
    fn a_promise_waits_for_the_standby_and_is_protected() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let slot = pair
            .submit(vec![Op::Put(rec(2, 10, b"b"))], SyncLevel::Remote)
            .unwrap();
        assert_eq!(synced(&slot), None, "held until acknowledged");
        pair.pump().unwrap();
        assert_eq!(synced(&slot), Some(Protection::Protected));
        assert_eq!(pair.sb.records(), 2);
    }

    #[test]
    fn losing_the_standby_fences_before_answering_unprotected() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let tag = pair.sb.tag();
        // The standby sends no more polls. It does not acknowledge the batch.
        let slot = pair
            .submit(vec![Op::Put(rec(1, 10, b"dirty"))], SyncLevel::Remote)
            .unwrap();
        pair.pending = None;
        // Run the effects by hand. The promise must not get a reply before
        // the bump.
        pair.p.repl_closed(pair.conn);
        let effects = pair.p.take_effects();
        assert!(effects.iter().any(|e| matches!(e, Effect::Bump { .. })));
        assert_eq!(synced(&slot), None, "not answered before the bump");
        for e in effects {
            if let Effect::Bump { floor } = e {
                let previous = pair.file;
                pair.file = pair.file.max(floor) + 1;
                let epoch = pair.file;
                pair.p
                    .epoch_bumped(Ok(Bumped { previous, epoch }), pair.now);
            }
        }
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
        assert!(pair.file > tag, "the standby's copy is fenced off");
        assert_eq!(pair.p.state(), State::Unprotected);
        let slot = pair.submit(vec![Op::Del(1)], SyncLevel::Remote).unwrap();
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
    }

    #[test]
    fn a_reconnect_resyncs_under_a_new_tag_and_protects_again() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let first_tag = pair.sb.tag();
        pair.p.repl_closed(pair.conn);
        pair.effects();
        pair.submit(vec![Op::Put(rec(2, 10, b"b"))], SyncLevel::None);
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        assert!(pair.sb.tag() > first_tag);
        assert_eq!(pair.sb.tag(), pair.file);
        assert_eq!(pair.sb.records(), 2);
    }

    #[test]
    fn heartbeats_keep_a_quiet_link_alive_and_silence_loses_it() {
        let mut pair = protected_pair(&[]);
        for _ in 0..10 {
            pair.advance(Duration::from_millis(150));
            assert_eq!(pair.pump().unwrap(), 1, "one heartbeat");
            assert_eq!(pair.p.state(), State::Protected);
        }
        // The primary sends a heartbeat. The standby sends no poll.
        pair.advance(Duration::from_millis(150));
        pair.pending = None;
        pair.advance(Duration::from_millis(600));
        assert_eq!(pair.p.state(), State::Unprotected);
        assert!(!pair.open);
    }

    #[test]
    fn falling_too_far_behind_loses_the_standby() {
        let mut pair = protected_pair(&[]);
        // The primary replies to the poll. The standby sends no next poll.
        pair.submit(vec![Op::Put(rec(1, 10, &[1; 1000]))], SyncLevel::None);
        pair.pending = None;
        for i in 2..2000 {
            pair.submit(vec![Op::Put(rec(i, 10, &[1; 1000]))], SyncLevel::None);
            if pair.p.state() != State::Protected {
                break;
            }
        }
        assert_eq!(pair.p.state(), State::Unprotected);
    }

    #[test]
    fn rehydration_freezes_the_copy_and_done_starts_a_generation() {
        let mut pair = protected_pair(&[rec(1, 10, b"a"), rec(2, 11, b"b")]);
        let page = pair.p.rehydrate(0, 1 << 20, 1);
        assert_eq!(page.origin, Origin::Own);
        assert_eq!(page.records.len(), 2);
        assert!(page.last);
        // The parent submits the records that it restored.
        pair.submit(vec![Op::Put(rec(2, 0, b"b"))], SyncLevel::None);
        assert_eq!(pair.p.records(), 2, "the frozen copy is unchanged");
        let tag = pair.sb.tag();
        let generation = pair.p.done();
        pair.effects();
        assert_eq!(generation, 1);
        assert!(pair.file > tag, "the standby's old copy is fenced off");
        assert_eq!(pair.p.records(), 1);
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        assert_eq!(pair.sb.records(), 1);
    }

    #[test]
    fn forgetting_an_owner_replicates_the_deletes() {
        let mut pair = protected_pair(&[rec(1, 10, b"a"), rec(2, 11, b"b")]);
        pair.p.forget_owner(
            Owner {
                pid: 10,
                unique_id: 1,
            },
            &[],
            pair.now,
        );
        pair.effects();
        pair.pump().unwrap();
        assert_eq!(pair.sb.records(), 1);
    }

    #[test]
    fn a_newer_standby_gets_this_version_and_an_older_one_is_refused() {
        for (version, accepted) in [
            (VERSION + 1, true),
            (proto::MIN_VERSION, true),
            (proto::MIN_VERSION - 1, false),
        ] {
            let mut pair = Pair::new(&[], b"secret");
            pair.conn += 1;
            pair.p.repl_connect(pair.conn, pair.now);
            let (w, slot) = waiter();
            let hello = ReplRequest::Hello(crate::proto::repl::ReplHello {
                version,
                node: SNODE,
                boot: SB,
                nonce: FixedOpaque([9; 32]),
            });
            pair.p.repl_request(pair.conn, hello, w, pair.now);
            let outcome = slot.borrow_mut().take();
            match outcome {
                Some(Outcome::Reply(bytes)) => {
                    assert!(accepted, "version {version} accepted");
                    let ReplReply::Challenge(c) = decode(&bytes) else {
                        panic!("no challenge");
                    };
                    assert_eq!(c.version, VERSION.min(version));
                }
                other => assert!(!accepted, "version {version}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_standby_that_says_it_is_this_node_is_refused() {
        let mut pair = Pair::new(&[], b"secret");
        pair.conn += 1;
        pair.p.repl_connect(pair.conn, pair.now);
        let (w, slot) = waiter();
        let hello = ReplRequest::Hello(crate::proto::repl::ReplHello {
            version: VERSION,
            node: PNODE,
            boot: SB,
            nonce: FixedOpaque([9; 32]),
        });
        pair.p.repl_request(pair.conn, hello, w, pair.now);
        assert!(matches!(slot.borrow_mut().take(), Some(Outcome::Closed)));
    }

    #[test]
    fn a_standby_with_another_key_is_refused() {
        let mut pair = Pair::new(&[rec(1, 10, b"a")], b"another secret");
        pair.connect();
        let err = pair.pump().unwrap_err();
        assert!(err.contains("authentication"), "{err}");
        assert_eq!(pair.p.state(), State::Unprotected);
        assert_eq!(pair.sb.tag(), 0);
    }

    #[test]
    fn promises_during_resync_are_unprotected_and_reprotection_covers_them() {
        let records: Vec<Record> =
            (1..=30).map(|i| rec(i, 10, &[0; 300])).collect();
        let mut pair = Pair::new(&records, b"secret");
        pair.connect();
        // Deliver the challenge, the welcome and the first chunk only.
        for _ in 0..3 {
            let slot = pair.pending.clone().unwrap();
            let outcome = slot.borrow_mut().take();
            let Some(Outcome::Reply(bytes)) = outcome else {
                panic!("no reply")
            };
            let next = pair.sb.on_reply(decode(&bytes)).unwrap();
            pair.send(next);
        }
        assert_eq!(pair.p.state(), State::Resyncing);
        let slot = pair
            .submit(vec![Op::Put(rec(99, 10, b"late"))], SyncLevel::Remote)
            .unwrap();
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        assert_eq!(pair.sb.records(), 31, "the promised change is replicated");
    }

    #[test]
    fn a_restarted_parent_rehydrates_again_from_the_same_frozen_copy() {
        let mut pair =
            Pair::new(&[rec(1, 10, b"a"), rec(2, 11, b"b")], b"secret");
        assert_eq!(pair.p.rehydrate(0, 1 << 20, 1).records.len(), 2);
        pair.submit(vec![Op::Put(rec(1, 0, b"a"))], SyncLevel::None);
        // The parent stops before `done`. The next parent starts at cursor 0.
        assert_eq!(pair.p.rehydrate(0, 1 << 20, 1).records.len(), 2);
        pair.submit(vec![Op::Put(rec(2, 0, b"b"))], SyncLevel::None);
        pair.p.done();
        assert_eq!(pair.p.records(), 1, "only the second baseline counts");
    }

    #[test]
    fn a_promise_during_a_rehydration_fences_instead_of_waiting() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let tag = pair.sb.tag();
        pair.p.rehydrate(0, 1 << 20, 1);
        let slot = pair
            .submit(vec![Op::Put(rec(2, 10, b"b"))], SyncLevel::Remote)
            .unwrap();
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
        assert!(pair.file > tag, "the standby's copy was fenced first");
        // The standby reconnects. It gets no resync before `done`.
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Unprotected);
        pair.advance(Duration::from_millis(150));
        assert_eq!(pair.pump().unwrap(), 1, "a heartbeat keeps it waiting");
        pair.p.done();
        pair.effects();
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        assert_eq!(pair.sb.records(), 1, "the new generation: only record 2");
    }

    /// Runs the effects. The test sets the result of each epoch file write.
    fn effects_with(pair: &mut Pair, bump_ok: bool, advance: Option<bool>) {
        for e in pair.p.take_effects() {
            match e {
                Effect::Bump { floor } => {
                    if bump_ok {
                        let previous = pair.file;
                        pair.file =
                            epoch::next_fence(pair.file.max(floor)).unwrap();
                        let epoch = pair.file;
                        pair.p.epoch_bumped(
                            Ok(Bumped { previous, epoch }),
                            pair.now,
                        );
                    } else {
                        pair.p.epoch_bumped(Err("EIO".to_owned()), pair.now);
                    }
                }
                Effect::Advance { tag, .. } => match advance {
                    Some(true) => {
                        pair.file = tag;
                        pair.p.epoch_advanced(tag, Ok(()));
                    }
                    Some(false) => pair.p.epoch_advanced(
                        tag,
                        Err(AdvanceError::Failed("EIO".to_owned())),
                    ),
                    None => {
                        let current = tag + 5;
                        pair.file = current;
                        pair.p.epoch_advanced(
                            tag,
                            Err(AdvanceError::Stale { current }),
                        );
                    }
                },
                Effect::Close { conn } => {
                    if conn == pair.conn {
                        pair.open = false;
                    }
                }
                Effect::Restart => pair.restart(false),
                Effect::Read { writes } => {
                    let found = pair.file;
                    pair.p.epoch_read(writes, Ok(found));
                }
            }
        }
    }

    /// Connects and delivers replies until the state is `State::Advancing`.
    fn until_advance(pair: &mut Pair) {
        pair.conn += 1;
        pair.p.repl_connect(pair.conn, pair.now);
        let hello = pair.sb.start();
        let (w, slot) = waiter();
        pair.p.repl_request(pair.conn, hello, w, pair.now);
        pair.pending = Some(slot);
        loop {
            let slot = pair.pending.clone().unwrap();
            let outcome = slot.borrow_mut().take();
            let Some(Outcome::Reply(bytes)) = outcome else {
                return;
            };
            let next = pair.sb.on_reply(decode(&bytes)).unwrap();
            let (w, slot) = waiter();
            pair.p.repl_request(pair.conn, next, w, pair.now);
            pair.pending = Some(slot);
            if pair.p.state() == State::Advancing {
                return;
            }
        }
    }

    #[test]
    fn a_stale_advance_drops_the_copy_and_restarts() {
        let mut pair = Pair::new(&[rec(1, 10, b"a")], b"secret");
        until_advance(&mut pair);
        let (w, slot) = waiter();
        pair.p.submit(vec![Op::Del(1)], pair.now);
        pair.p.sync_remote(w);
        assert_eq!(synced(&slot), None, "held while advancing");
        // smbd fenced. The advance finds the smbd fence in the file.
        let found = pair.file + 2;
        pair.file = found;
        let tag = match pair.p.take_effects().as_slice() {
            [Effect::Advance { tag, .. }] => *tag,
            other => panic!("{other:?}"),
        };
        pair.p
            .epoch_advanced(tag, Err(AdvanceError::Stale { current: found }));
        assert!(pair.p.discarded());
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
        let effects = pair.p.take_effects();
        assert!(effects.contains(&Effect::Restart), "{effects:?}");
        assert!(!effects.iter().any(|e| matches!(e, Effect::Advance { .. })));
        // A new standby connection is refused until the restart.
        pair.p.repl_connect(99, pair.now);
        assert_eq!(pair.p.take_effects(), vec![Effect::Close { conn: 99 }]);
        // The new primary starts with an empty copy.
        pair.restart(true);
        assert_eq!(pair.p.records(), 0);
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        assert_eq!(pair.sb.records(), 0);
        assert_eq!(pair.sb.tag(), pair.file);
    }

    #[test]
    fn a_fence_that_finds_an_smbd_fence_drops_the_copy() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let slot = pair.submit(vec![Op::Del(1)], SyncLevel::Remote).unwrap();
        // smbd fenced. Then the primary loses the standby and fences too.
        pair.file = smbd_fence(pair.file);
        pair.pending = None;
        pair.p.repl_closed(pair.conn);
        let effects = pair.p.take_effects();
        let Some(Effect::Bump { floor }) =
            effects.iter().find(|e| matches!(e, Effect::Bump { .. }))
        else {
            panic!("{effects:?}")
        };
        let previous = pair.file;
        pair.file = epoch::next_fence(previous.max(*floor)).unwrap();
        let epoch = pair.file;
        pair.p
            .epoch_bumped(Ok(Bumped { previous, epoch }), pair.now);
        assert!(pair.p.discarded());
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
        assert!(pair.p.take_effects().contains(&Effect::Restart));
    }

    #[test]
    fn a_protected_primary_finds_an_smbd_fence_within_a_second() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        pair.advance(Duration::from_millis(1100));
        let _ = pair.pump();
        assert_eq!(pair.restarts, 0, "the file has the tag");
        pair.file = smbd_fence(pair.file);
        pair.advance(Duration::from_millis(1100));
        assert_eq!(pair.restarts, 1, "the copy was dropped");
        assert_eq!(pair.p.records(), 0);
        // A read started before a write is out of date.
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        pair.now += Duration::from_millis(1100);
        pair.p.tick(pair.now);
        let read = pair.p.take_effects();
        let Some(&Effect::Read { writes }) =
            read.iter().find(|e| matches!(e, Effect::Read { .. }))
        else {
            panic!("{read:?}")
        };
        pair.pending = None;
        pair.p.repl_closed(pair.conn);
        pair.effects();
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        pair.p.epoch_read(writes, Ok(1));
        assert!(!pair.p.discarded());
    }

    #[test]
    fn a_failed_advance_that_wrote_the_tag_is_not_a_foreign_fence() {
        let mut pair = Pair::new(&[rec(1, 10, b"a")], b"secret");
        until_advance(&mut pair);
        let tag = match pair.p.take_effects().as_slice() {
            [Effect::Advance { tag, .. }] => *tag,
            other => panic!("{other:?}"),
        };
        // The write reached the file. Then an error was reported.
        pair.file = tag;
        pair.p
            .epoch_advanced(tag, Err(AdvanceError::Failed("EIO".to_owned())));
        pair.effects();
        assert!(!pair.p.discarded());
        assert_eq!(pair.p.state(), State::Unprotected);
    }

    #[test]
    fn no_snapshot_starts_during_a_rehydration() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        pair.p.rehydrate(0, 1 << 20, 1);
        // A promise during the rehydration fences. The bump waits.
        let (w, slot) = waiter();
        pair.p.submit(vec![Op::Put(rec(2, 10, b"b"))], pair.now);
        pair.p.sync_remote(w);
        let held = pair.p.take_effects();
        assert_eq!(pair.p.state(), State::Fencing);
        // A standby connects. Its first poll waits for the fence.
        pair.pending = None;
        pair.connect();
        pair.pump().unwrap();
        // The fence ends. The poll waits for the end of the rehydration.
        for e in held {
            if let Effect::Bump { floor } = e {
                let previous = pair.file;
                pair.file = epoch::next_fence(previous.max(floor)).unwrap();
                let epoch = pair.file;
                pair.p
                    .epoch_bumped(Ok(Bumped { previous, epoch }), pair.now);
            }
        }
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
        assert_eq!(pair.p.state(), State::Unprotected);
        assert_eq!(pair.pump().unwrap(), 0, "no snapshot of the frozen copy");
        pair.p.done();
        pair.effects();
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
    }

    #[test]
    fn a_promise_during_a_rehydration_and_a_snapshot_drops_the_snapshot() {
        let records: Vec<Record> =
            (1..=30).map(|i| rec(i, 10, &[0; 300])).collect();
        let mut pair = Pair::new(&records, b"secret");
        pair.connect();
        while pair.p.state() != State::Resyncing {
            deliver_one(&mut pair);
        }
        pair.p.rehydrate(0, 1 << 20, 1);
        let slot = pair
            .submit(vec![Op::Put(rec(99, 10, b"x"))], SyncLevel::Remote)
            .unwrap();
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
        assert!(!pair.open, "the snapshot of the frozen copy stopped");
        assert_eq!(pair.p.state(), State::Unprotected);
    }

    #[test]
    fn the_parents_close_ends_its_rehydration() {
        let mut pair = protected_pair(&[rec(1, 10, b"a"), rec(2, 11, b"b")]);
        pair.p.rehydrate(0, 1 << 20, 7);
        pair.submit(vec![Op::Put(rec(2, 0, b"b"))], SyncLevel::None);
        // Another connection closes. Nothing changes.
        pair.p.local_closed(8);
        assert_eq!(pair.p.records(), 2);
        pair.p.local_closed(7);
        pair.effects();
        assert_eq!(pair.p.records(), 1, "the copy has the parent's records");
        assert_eq!(pair.p.rehydrate(0, 1 << 20, 9).records.len(), 1);
    }

    /// Delivers the reply that waits for the standby and sends the next
    /// request.
    fn deliver_one(pair: &mut Pair) {
        let slot = pair.pending.clone().unwrap();
        let Some(Outcome::Reply(bytes)) = slot.borrow_mut().take() else {
            panic!("no reply");
        };
        let next = pair.sb.on_reply(decode(&bytes)).unwrap();
        pair.send(next);
    }

    #[test]
    fn an_smbd_fence_during_reprotection_stops_the_advance() {
        let mut pair = Pair::new(&[rec(1, 1, b"a")], b"secret");
        // A session lost during its snapshot leaves its tag used.
        pair.connect();
        while pair.p.state() != State::Resyncing {
            deliver_one(&mut pair);
        }
        pair.p.repl_closed(pair.conn);
        pair.effects();
        pair.pending = None;
        assert_eq!(pair.p.state(), State::Unprotected);
        // The next session gets a higher tag. A change arrives during the
        // snapshot, so the standby must acknowledge it before the advance.
        pair.connect();
        while pair.p.state() != State::Resyncing {
            deliver_one(&mut pair);
        }
        pair.submit(vec![Op::Put(rec(2, 1, b"b"))], SyncLevel::None);
        while pair.p.state() != State::Reprotecting {
            deliver_one(&mut pair);
        }
        let promise = pair
            .submit(vec![Op::Put(rec(3, 1, b"c"))], SyncLevel::Remote)
            .unwrap();
        let target = pair.p.seq();
        assert_eq!(synced(&promise), None, "the promise waits");
        // smbd gets no reply in time, fences and answers the client.
        pair.file = smbd_fence(pair.file);
        pair.fenced_last = true;
        for _ in 0..20 {
            let restorable = pair.sb.tag() != 0 && pair.sb.tag() == pair.file;
            assert!(
                !restorable || pair.sb.applied() >= target,
                "restorable replica at {} lacks the promise at {target}",
                pair.sb.applied()
            );
            let Some(slot) = pair.pending.clone() else {
                break;
            };
            let Some(Outcome::Reply(bytes)) = slot.borrow_mut().take() else {
                break;
            };
            let Ok(next) = pair.sb.on_reply(decode(&bytes)) else {
                break;
            };
            pair.send(next);
        }
    }

    /// Runs a session until it waits for the standby to acknowledge a
    /// change sent during the snapshot.
    fn until_reprotecting(pair: &mut Pair, id: u64) {
        pair.connect();
        while pair.p.state() != State::Resyncing {
            deliver_one(pair);
        }
        pair.submit(vec![Op::Put(rec(id, 1, b"b"))], SyncLevel::None);
        while pair.p.state() != State::Reprotecting {
            deliver_one(pair);
        }
    }

    #[test]
    fn a_second_smbd_fence_after_a_stale_advance_stops_the_next_advance() {
        let mut pair = Pair::new(&[rec(1, 1, b"a")], b"secret");
        // smbd fences during a reprotection. The advance is stale.
        until_reprotecting(&mut pair, 2);
        pair.file = smbd_fence(pair.file);
        let fenced_to = pair.file;
        let _ = pair.pump();
        pair.pending = None;
        assert_eq!(pair.p.state(), State::Unprotected);
        // The next session waits for its reprotection. A promise waits.
        until_reprotecting(&mut pair, 3);
        let promise = pair
            .submit(vec![Op::Put(rec(4, 1, b"c"))], SyncLevel::Remote)
            .unwrap();
        let target = pair.p.seq();
        assert_eq!(synced(&promise), None, "the promise waits");
        // smbd fences again, unless the file still holds its last fence,
        // and answers the client.
        if pair.file != fenced_to {
            pair.file = smbd_fence(pair.file);
        }
        for _ in 0..20 {
            let restorable = pair.sb.tag() != 0 && pair.sb.tag() == pair.file;
            assert!(
                !restorable || pair.sb.applied() >= target,
                "restorable replica at {} lacks the promise at {target}",
                pair.sb.applied()
            );
            let Some(slot) = pair.pending.clone() else {
                break;
            };
            let Some(Outcome::Reply(bytes)) = slot.borrow_mut().take() else {
                break;
            };
            let Ok(next) = pair.sb.on_reply(decode(&bytes)) else {
                break;
            };
            pair.send(next);
        }
    }

    #[test]
    fn a_failed_advance_fences() {
        let mut pair = Pair::new(&[rec(1, 10, b"a")], b"secret");
        until_advance(&mut pair);
        let (w, slot) = waiter();
        pair.p.submit(vec![Op::Del(1)], pair.now);
        pair.p.sync_remote(w);
        assert_eq!(synced(&slot), None, "held while advancing");
        effects_with(&mut pair, true, Some(false));
        // The failed advance lost the standby and added an `Effect::Bump`.
        effects_with(&mut pair, true, Some(false));
        assert_eq!(pair.p.state(), State::Unprotected);
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
    }

    #[test]
    fn a_failed_fence_holds_promises_and_retries() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let slot = pair.submit(vec![Op::Del(1)], SyncLevel::Remote).unwrap();
        pair.pending = None;
        pair.p.repl_closed(pair.conn);
        effects_with(&mut pair, false, None);
        assert_eq!(pair.p.state(), State::Fencing);
        assert_eq!(synced(&slot), None, "never answered unfenced");
        pair.now += Duration::from_millis(500);
        pair.p.tick(pair.now);
        assert!(pair.p.take_effects().is_empty(), "retry waits a second");
        pair.now += Duration::from_millis(600);
        pair.p.tick(pair.now);
        effects_with(&mut pair, true, None);
        assert_eq!(pair.p.state(), State::Unprotected);
        assert_eq!(synced(&slot), Some(Protection::Unprotected));
    }

    #[test]
    fn a_new_connection_replaces_a_protected_one_once_authenticated() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let before = pair.file;
        pair.connect();
        assert_eq!(pair.file, before, "nothing happens before the proof");
        assert_eq!(pair.p.state(), State::Protected);
        pair.pump().unwrap();
        assert!(pair.file > before, "replacing the session fenced it");
        assert_eq!(pair.p.state(), State::Protected);
    }

    #[test]
    fn a_connection_without_the_key_cannot_disturb_a_protected_session() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let before = pair.file;
        let protected_conn = pair.conn;
        let protected_poll = pair.pending.take();
        // A connection without the key sends a hello and then a false proof.
        let intruder = protected_conn + 100;
        pair.p.repl_connect(intruder, pair.now);
        let (w, slot) = waiter();
        let mut other = Standby::new(
            LinkKey::derive(b"guess"),
            SNODE,
            SB,
            zero,
            Store::default(),
            Header::empty(SNODE, SB),
            Logger::silent(),
        );
        let hello = other.start();
        pair.p.repl_request(intruder, hello, w, pair.now);
        assert!(matches!(*slot.borrow(), Some(Outcome::Reply(_))));
        let (w, slot) = waiter();
        pair.p.repl_request(
            intruder,
            ReplRequest::Prove(FixedOpaque([1; 32])),
            w,
            pair.now,
        );
        assert_eq!(*slot.borrow(), Some(Outcome::Closed));
        assert_eq!(pair.p.state(), State::Protected);
        assert_eq!(pair.file, before);
        // The primary closes a handshake that does not complete in time.
        pair.p.repl_connect(intruder + 1, pair.now);
        pair.conn = protected_conn;
        pair.pending = protected_poll;
        pair.advance(Duration::from_millis(100));
        pair.pump().unwrap();
        pair.advance(Duration::from_millis(100));
        pair.pump().unwrap();
        pair.advance(Duration::from_millis(400));
        let closed = pair.p.take_effects();
        assert!(
            closed.contains(&Effect::Close { conn: intruder + 1 })
                || pair.p.pending.is_none()
        );
        assert_eq!(pair.p.state(), State::Protected);
        assert_eq!(pair.file, before);
    }

    #[test]
    fn protocol_violations_drop_the_standby() {
        let cases: Vec<Box<dyn Fn(&mut Pair)>> = vec![
            // A poll before the handshake.
            Box::new(|pair: &mut Pair| {
                pair.conn += 1;
                pair.p.repl_connect(pair.conn, pair.now);
                pair.send(ReplRequest::Poll(0));
            }),
            // A false proof.
            Box::new(|pair: &mut Pair| {
                pair.connect();
                let slot = pair.pending.clone().unwrap();
                slot.borrow_mut().take();
                pair.send(ReplRequest::Prove(FixedOpaque([0; 32])));
            }),
            // An acknowledgement above the sequence number of the primary.
            Box::new(|pair: &mut Pair| {
                pair.connect();
                pair.pump().unwrap();
                pair.pending = None;
                pair.send(ReplRequest::Poll(1_000_000));
            }),
            // A second hello.
            Box::new(|pair: &mut Pair| {
                pair.connect();
                pair.pump().unwrap();
                pair.pending = None;
                let hello = pair.sb.start();
                pair.send(hello);
            }),
        ];
        for (i, case) in cases.iter().enumerate() {
            let mut pair = Pair::new(&[rec(1, 10, b"a")], b"secret");
            case(&mut pair);
            let slot = pair.pending.clone().unwrap();
            assert_eq!(*slot.borrow(), Some(Outcome::Closed), "case {i}");
            assert!(!pair.open, "case {i}: the session is gone");
            assert_ne!(pair.p.state(), State::Protected, "case {i}");
        }
        // The core closes a request on an unknown connection.
        let mut pair = Pair::new(&[], b"secret");
        let (w, slot) = waiter();
        pair.p.repl_request(42, ReplRequest::Poll(0), w, pair.now);
        assert_eq!(*slot.borrow(), Some(Outcome::Closed));
    }

    #[test]
    fn records_too_large_to_keep_become_deletes() {
        let pair = Pair::new(&[], b"secret");
        let fits = rec(1, 10, &[0; 1024]);
        let mut ops = vec![
            Op::Put(rec(2, 10, &[0; 1025])),
            Op::Put(fits.clone()),
            Op::Del(3),
        ];
        assert_eq!(pair.p.fit_ops(&mut ops), 1);
        assert_eq!(ops, vec![Op::Del(2), Op::Put(fits.clone()), Op::Del(3)]);
        let mut long = fits;
        long.share = "s".repeat(257);
        let mut ops = vec![Op::Put(long)];
        assert_eq!(pair.p.fit_ops(&mut ops), 1);
        assert_eq!(ops, vec![Op::Del(1)]);
    }

    #[test]
    fn local_and_one_way_submits_answer_as_they_should() {
        let mut pair = protected_pair(&[]);
        pair.p.submit(vec![Op::Put(rec(1, 10, b"x"))], pair.now);
        assert_eq!(
            pair.p.synced(),
            Synced {
                protection: Protection::Protected,
                epoch: pair.file
            }
        );
    }

    #[test]
    fn rehydration_pages_and_reports_a_dropped_copy_as_none() {
        let records: Vec<Record> =
            (1..=50).map(|i| rec(i, 10, &[1; 100])).collect();
        let mut pair = Pair::new(&records, b"secret");
        let mut cursor = 0;
        let mut seen = Vec::new();
        loop {
            let page = pair.p.rehydrate(cursor, 400, 1);
            assert!(page.records.len() <= 3);
            seen.extend(page.records.iter().map(|r| r.id));
            if page.last {
                break;
            }
            cursor = page.next_cursor;
        }
        assert_eq!(seen, (1..=50).collect::<Vec<_>>());
        let mut none: Primary<TestWaiter> = Primary::new(
            settings(),
            LinkKey::derive(b"secret"),
            Store::default(),
            Header::empty(PNODE, PB),
            Origin::None,
            1,
            Logger::silent(),
        );
        let page = none.rehydrate(0, 1 << 20, 1);
        assert_eq!(
            (page.origin, page.last, page.records.len()),
            (Origin::None, true, 0)
        );
    }

    #[test]
    fn forgetting_during_a_rehydration_applies_to_the_next_generation() {
        let mut pair = Pair::new(&[rec(1, 10, b"a")], b"secret");
        pair.p.rehydrate(0, 1 << 20, 1);
        pair.submit(
            vec![Op::Put(rec(1, 10, b"a")), Op::Put(rec(2, 11, b"b"))],
            SyncLevel::None,
        );
        pair.p.forget_owner(
            Owner {
                pid: 10,
                unique_id: 1,
            },
            &[],
            pair.now,
        );
        assert_eq!(pair.p.records(), 1, "the frozen copy is untouched");
        pair.p.done();
        assert_eq!(pair.p.records(), 1);
        let page = pair.p.rehydrate(0, 1 << 20, 1);
        assert_eq!(page.records[0].id, 2);
    }

    #[test]
    fn done_without_a_rehydration_keeps_the_copy_and_resyncs() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        let tag = pair.sb.tag();
        assert_eq!(pair.p.done(), 1);
        pair.effects();
        assert!(pair.file > tag);
        assert_eq!(pair.p.records(), 1);
        pair.connect();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
        assert_eq!(pair.sb.records(), 1);
    }

    #[test]
    fn batches_respect_the_chunk_size() {
        let mut pair = protected_pair(&[]);
        // The primary holds the standby poll. Submit more than one chunk.
        let parked = pair.pending.take().unwrap();
        for i in 1..=10 {
            pair.submit(vec![Op::Put(rec(i, 10, &[0; 900]))], SyncLevel::None);
        }
        // The primary sent the first batch at once. The batch has only the
        // first operation.
        let outcome = parked.borrow_mut().take();
        let Some(Outcome::Reply(bytes)) = outcome else {
            panic!()
        };
        let ReplReply::Batch(b) = decode(&bytes) else {
            panic!()
        };
        assert_eq!(b.ops.len(), 1);
        let next = pair.sb.on_reply(ReplReply::Batch(b)).unwrap();
        pair.send(next);
        // The primary sends the rest in batches of up to one chunk.
        let slot = pair.pending.clone().unwrap();
        let outcome = slot.borrow_mut().take();
        let Some(Outcome::Reply(bytes)) = outcome else {
            panic!()
        };
        let ReplReply::Batch(b) = decode(&bytes) else {
            panic!()
        };
        assert_eq!(b.ops.len(), 2, "2 x 900 bytes fit in 2048, 3 do not");
        let next = pair.sb.on_reply(ReplReply::Batch(b)).unwrap();
        pair.send(next);
        pair.pump().unwrap();
        assert_eq!(pair.sb.records(), 10);
    }

    #[test]
    fn a_fencing_primary_keeps_a_new_standby_waiting_with_heartbeats() {
        let mut pair = protected_pair(&[rec(1, 10, b"a")]);
        pair.pending = None;
        pair.p.repl_closed(pair.conn);
        // Do not run the bump yet.
        let held = pair.p.take_effects();
        assert!(held.iter().any(|e| matches!(e, Effect::Bump { .. })));
        assert_eq!(pair.p.state(), State::Fencing);
        pair.connect();
        pair.pump().unwrap();
        pair.now += Duration::from_millis(150);
        pair.p.tick(pair.now);
        assert_eq!(pair.pump().unwrap(), 1, "a heartbeat");
        for e in held {
            if let Effect::Bump { floor } = e {
                let previous = pair.file;
                pair.file = pair.file.max(floor) + 1;
                let epoch = pair.file;
                pair.p
                    .epoch_bumped(Ok(Bumped { previous, epoch }), pair.now);
            }
        }
        pair.effects();
        pair.pump().unwrap();
        assert_eq!(pair.p.state(), State::Protected);
    }

    /// The epoch that smbd's fallback fence writes over `file`.
    fn smbd_fence(file: u64) -> u64 {
        epoch::next_fence(file).unwrap()
    }

    /// The epoch that a starting daemon writes over `file` for a copy with
    /// tag `tag` (`serve::run`).
    fn start_fence(file: u64, tag: u64) -> u64 {
        epoch::next_fence(file.max(tag)).unwrap()
    }

    /// A deterministic xorshift generator for the model test.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Runs random sequences of submits, promises, partial delivery,
    /// disconnects, silence, rehydrations, epoch write results, fallback
    /// fences of smbd and daemon restarts. After each step, a restorable
    /// replica must come from an advance, not a fence, and must contain
    /// every promise that got a reply. At the end, the test ends any
    /// rehydration and reconnects the standby. Then the primary must be
    /// protected, every promise must have a reply and the replica must equal
    /// the copy.
    #[test]
    fn random_interleavings_never_restore_less_than_was_promised() {
        // Counts of the important situations across all seeds. The test
        // fails if a count is below its minimum.
        let mut restorable_checks = 0u64;
        let mut protected_answers = 0u64;
        let mut unprotected_answers = 0u64;
        let mut fences = 0u64;
        let mut restarts = 0usize;
        for seed in 1..=300u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut pair = Pair::new(&[], b"secret");
            let mut promised: Vec<(Slot, u64)> = Vec::new();
            // The highest answered target per primary (`pair.restarts`),
            // and the primary that sent the standby's replica.
            let mut max_answered: Vec<u64> = vec![0];
            let mut replica_inst = 0usize;
            // smbd skips its fence while the file holds its last fence.
            let mut smbd_fenced_to = 0u64;
            let mut rehydrating = false;
            let mut epochs = vec![pair.file];
            for step in 0..400 {
                let completed_before = pair.completed;
                let inst = pair.restarts;
                match rng.below(26) {
                    0..=6 => {
                        let n = rng.below(4) + 1;
                        let ops = (0..n)
                            .map(|_| {
                                let id = rng.below(40) + 1;
                                if rng.below(4) == 0 {
                                    Op::Del(id)
                                } else {
                                    Op::Put(rec(
                                        id,
                                        (rng.below(3) + 1) as u32,
                                        &[step as u8; 30],
                                    ))
                                }
                            })
                            .collect();
                        if rng.below(2) == 0 {
                            let slot =
                                pair.submit(ops, SyncLevel::Remote).unwrap();
                            let target = if rehydrating {
                                u64::MAX
                            } else {
                                pair.p.seq()
                            };
                            promised.push((slot, target));
                        } else {
                            pair.submit(ops, SyncLevel::None);
                        }
                    }
                    7..=14 => {
                        for _ in 0..rng.below(8) {
                            let Some(slot) = pair.pending.clone() else {
                                break;
                            };
                            let outcome = slot.borrow_mut().take();
                            match outcome {
                                Some(Outcome::Reply(bytes)) => {
                                    let reply: ReplReply = decode(&bytes);
                                    let last = matches!(
                                        &reply,
                                        ReplReply::Snapshot(s) if s.last
                                    );
                                    match pair.sb.on_reply(reply) {
                                        Ok(next) => {
                                            if last {
                                                pair.completed += 1;
                                            }
                                            pair.send(next);
                                        }
                                        Err(_) => {
                                            pair.pending = None;
                                            pair.p.repl_closed(pair.conn);
                                            pair.effects();
                                        }
                                    }
                                }
                                Some(Outcome::Closed) => pair.pending = None,
                                None => break,
                            }
                        }
                    }
                    15 => {
                        if pair.open && rng.below(3) == 0 {
                            pair.pending = None;
                            pair.p.repl_closed(pair.conn);
                            pair.effects();
                        }
                    }
                    16 => {
                        if !pair.open || pair.pending.is_none() {
                            pair.connect();
                        }
                    }
                    17 => pair.advance(Duration::from_millis(rng.below(120))),
                    18 => {
                        if rng.below(4) == 0 {
                            pair.advance(Duration::from_millis(rng.below(900)));
                        }
                    }
                    19 => {
                        if rng.below(4) == 0 {
                            if rehydrating {
                                pair.p.done();
                                pair.effects();
                                rehydrating = false;
                            } else {
                                pair.p.rehydrate(0, 1 << 20, 1);
                                rehydrating = true;
                            }
                        }
                    }
                    20 => {
                        let owner = Owner {
                            pid: (rng.below(3) + 1) as u32,
                            unique_id: 1,
                        };
                        pair.p.forget_owner(owner, &[], pair.now);
                        pair.effects();
                    }
                    21 => {
                        if pair.p.state() == State::Fencing {
                            pair.now += Duration::from_millis(1100);
                            pair.p.tick(pair.now);
                            pair.effects();
                        }
                    }
                    22 => {
                        if rng.below(4) == 0 {
                            // smbd gets no reply, fences and answers the
                            // waiting promises itself.
                            if pair.file != smbd_fenced_to {
                                pair.file = smbd_fence(pair.file);
                                pair.fenced_last = true;
                                smbd_fenced_to = pair.file;
                            }
                            for (_, target) in promised.drain(..) {
                                if target != u64::MAX {
                                    max_answered[inst] =
                                        max_answered[inst].max(target);
                                }
                            }
                        }
                    }
                    23 => {
                        if rng.below(8) == 0 {
                            // The primary role restarts in the process. smbd
                            // fences for the promises without a reply.
                            if !promised.is_empty() {
                                if pair.file != smbd_fenced_to {
                                    pair.file = smbd_fence(pair.file);
                                    pair.fenced_last = true;
                                    smbd_fenced_to = pair.file;
                                }
                                for (_, target) in promised.drain(..) {
                                    if target != u64::MAX {
                                        max_answered[inst] =
                                            max_answered[inst].max(target);
                                    }
                                }
                            }
                            pair.restart(true);
                            rehydrating = false;
                        }
                    }
                    _ => {
                        let _ = pair.pump();
                    }
                }
                // A discard restarts the primary. Its rehydration ends.
                if pair.restarts != inst {
                    rehydrating = false;
                }
                while max_answered.len() <= pair.restarts {
                    max_answered.push(0);
                }
                // Count and remove the promises that got a reply. Record the
                // highest target among them, for the primary that answered.
                promised.retain(|(slot, target)| match synced(slot) {
                    Some(p) => {
                        if p == Protection::Protected {
                            protected_answers += 1;
                        } else {
                            unprotected_answers += 1;
                        }
                        if *target != u64::MAX {
                            max_answered[inst] =
                                max_answered[inst].max(*target);
                        }
                        false
                    }
                    None => true,
                });
                let file = pair.file;
                assert!(
                    file >= *epochs.last().unwrap(),
                    "seed {seed}: the epoch went back"
                );
                if file > *epochs.last().unwrap() {
                    fences += 1;
                }
                epochs.push(file);
                if pair.completed != completed_before {
                    replica_inst = pair.restarts;
                }
                let restorable = pair.sb.tag() != 0 && pair.sb.tag() == file;
                if restorable && max_answered[pair.restarts] > 0 {
                    restorable_checks += 1;
                }
                if restorable {
                    let at = format!("seed {seed} step {step}");
                    assert!(
                        !pair.fenced_last,
                        "{at}: a fence made {file} restorable"
                    );
                    assert!(
                        pair.sb.applied() >= max_answered[replica_inst],
                        "{at}: restorable replica at {} lacks a promise at {}",
                        pair.sb.applied(),
                        max_answered[replica_inst]
                    );
                    assert!(
                        max_answered[replica_inst + 1..]
                            .iter()
                            .all(|m| *m == 0),
                        "{at}: an older replica is restorable after promises"
                    );
                }
            }
            // End any rehydration, reconnect the standby and deliver all
            // replies.
            if rehydrating {
                pair.p.done();
                pair.effects();
            }
            pair.pending = None;
            pair.p.repl_closed(pair.conn);
            pair.effects();
            for _ in 0..3 {
                pair.advance(Duration::from_millis(1100));
            }
            // An smbd fence that the primary does not know about makes the
            // first advance stale. The next session uses a higher tag.
            for _ in 0..3 {
                pair.connect();
                if pair.pump().is_ok() && pair.p.state() == State::Protected {
                    break;
                }
                pair.pending = None;
                pair.effects();
            }
            assert_eq!(pair.p.state(), State::Protected, "seed {seed}");
            for (slot, _) in &promised {
                assert!(
                    synced(slot).is_some(),
                    "seed {seed}: a promise never answered"
                );
            }
            let (want, _, _) = (pair.p.store.page(0, usize::MAX).0, 0, 0);
            let (store, header) = std::mem::replace(
                &mut pair.sb,
                Standby::new(
                    LinkKey::derive(b"x"),
                    SNODE,
                    SB,
                    zero,
                    Store::default(),
                    Header::empty(SNODE, SB),
                    Logger::silent(),
                ),
            )
            .into_copy();
            assert_eq!(header.tag, pair.file, "seed {seed}");
            assert_eq!(store.page(0, usize::MAX).0, want, "seed {seed}");
            restarts += pair.restarts;
        }
        eprintln!(
            "model: {restorable_checks} restorable checks, {protected_answers} \
             protected and {unprotected_answers} unprotected answers, {fences} \
             epoch moves, {restarts} restarts"
        );
        assert!(restorable_checks > 25_000, "{restorable_checks}");
        assert!(protected_answers > 3_000, "{protected_answers}");
        assert!(unprotected_answers > 1_000, "{unprotected_answers}");
        assert!(fences > 1_000, "{fences}");
        assert!(restarts > 300, "{restarts}");
    }
}
