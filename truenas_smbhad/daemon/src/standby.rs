// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The standby role.
//!
//! `Standby` keeps the replica. `run` connects to the primary over the
//! internal link and sends polls. The primary holds each poll until it has
//! data or a heartbeat is due.

use crate::auth::{self, LinkKey, Nonce, Side, Transcript};
use crate::config::Config;
use crate::daemon::Interrupt;
use crate::proto::encode;
use crate::proto::repl::{ReplHello, ReplReply, ReplRequest};
use crate::proto::{BootId, MAX_FRAME, MIN_VERSION, Node, Op, VERSION};
use crate::role;
use crate::store::{Header, Store};
use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use truenas_ros::log::{Level, Logger};
use truenas_ros::net::client::{
    Client, ClientConfig, ConnId, ConnectOpts, Event,
};
use truenas_ros::net::server::{
    Endian, PrefixWidth, ServerAddr, length_prefix_header,
};
use truenas_xdr::FixedOpaque;

#[derive(Debug)]
enum Stage {
    Idle,
    Hello { nonce: Nonce },
    Prove,
    Stream { in_snapshot: bool, snap_seq: u64 },
}

/// The replica and the standby side of the protocol, without I/O.
#[derive(Debug)]
pub struct Standby {
    key: LinkKey,
    node: Node,
    boot: BootId,
    random: fn(&mut [u8]),
    store: Store,
    header: Header,
    applied: u64,
    stage: Stage,
    log: Logger,
}

impl Standby {
    /// Creates a standby with the replica `store`. The first chunk of a
    /// snapshot replaces `store`.
    pub fn new(
        key: LinkKey,
        node: Node,
        boot: BootId,
        random: fn(&mut [u8]),
        store: Store,
        header: Header,
        log: Logger,
    ) -> Standby {
        Standby {
            key,
            node,
            boot,
            random,
            store,
            header,
            applied: 0,
            stage: Stage::Idle,
            log,
        }
    }

    /// Returns the first request of a new connection. Every connection
    /// starts with a full resync. `applied` starts again at 0.
    pub fn start(&mut self) -> ReplRequest {
        let mut nonce = [0u8; 32];
        (self.random)(&mut nonce);
        let nonce = FixedOpaque(nonce);
        self.applied = 0;
        self.stage = Stage::Hello { nonce };
        ReplRequest::Hello(ReplHello {
            version: VERSION,
            node: self.node,
            boot: self.boot,
            nonce,
        })
    }

    /// Applies a reply from the primary. Returns the next request.
    ///
    /// # Errors
    ///
    /// The primary failed authentication or did not follow the protocol.
    /// The caller must close the connection.
    #[allow(clippy::too_many_lines)]
    pub fn on_reply(
        &mut self,
        reply: ReplReply,
    ) -> Result<ReplRequest, String> {
        match (std::mem::replace(&mut self.stage, Stage::Idle), reply) {
            (Stage::Hello { nonce }, ReplReply::Challenge(c)) => {
                if !(MIN_VERSION..=VERSION).contains(&c.version) {
                    return Err(format!(
                        "primary speaks version {}",
                        c.version
                    ));
                }
                if c.node == self.node {
                    return Err(format!(
                        "the primary says that it is node {} too",
                        c.node
                    ));
                }
                let t = Transcript {
                    standby_node: self.node,
                    standby_nonce: &nonce,
                    primary_node: c.node,
                    primary_nonce: &c.nonce,
                };
                if !auth::verify(&self.key, Side::Primary, &t, &c.proof) {
                    return Err("the primary failed authentication".to_owned());
                }
                let proof = auth::proof(&self.key, Side::Standby, &t)
                    .map_err(|e| format!("computing the link proof: {e}"))?;
                self.stage = Stage::Prove;
                Ok(ReplRequest::Prove(proof))
            }
            (Stage::Prove, ReplReply::Welcome(_)) => {
                self.stage = Stage::Stream {
                    in_snapshot: false,
                    snap_seq: 0,
                };
                Ok(ReplRequest::Poll(0))
            }
            (
                Stage::Stream {
                    in_snapshot,
                    snap_seq,
                },
                ReplReply::Snapshot(s),
            ) => {
                if s.first {
                    self.store.clear();
                    self.header = Header {
                        generation: s.generation,
                        tag: 0,
                        writer_node: s.writer_node,
                        writer_boot: s.writer_boot,
                    };
                } else if !in_snapshot || s.seq != snap_seq {
                    return Err("a snapshot chunk out of order".to_owned());
                }
                for r in s.records {
                    self.store.apply(Op::Put(r));
                }
                if s.last {
                    self.header.tag = s.tag;
                    self.applied = s.seq;
                    self.stage = Stage::Stream {
                        in_snapshot: false,
                        snap_seq: 0,
                    };
                    truenas_ros::log!(
                        self.log,
                        Level::Notice,
                        "replica complete: {} records under tag {}",
                        self.store.len(),
                        s.tag
                    );
                    Ok(ReplRequest::Poll(s.seq))
                } else {
                    self.stage = Stage::Stream {
                        in_snapshot: true,
                        snap_seq: s.seq,
                    };
                    Ok(ReplRequest::Poll(0))
                }
            }
            (
                Stage::Stream {
                    in_snapshot: false, ..
                },
                ReplReply::Batch(b),
            ) => {
                if b.first_seq != self.applied + 1 {
                    return Err(format!(
                        "a batch from {} after {}",
                        b.first_seq, self.applied
                    ));
                }
                self.applied += b.ops.len() as u64;
                for op in b.ops {
                    self.store.apply(op);
                }
                self.stage = Stage::Stream {
                    in_snapshot: false,
                    snap_seq: 0,
                };
                Ok(ReplRequest::Poll(self.applied))
            }
            (
                Stage::Stream {
                    in_snapshot,
                    snap_seq,
                },
                ReplReply::Heartbeat(seq),
            ) => {
                if !in_snapshot && seq < self.applied {
                    return Err(format!(
                        "a heartbeat at {seq} after {}",
                        self.applied
                    ));
                }
                self.stage = Stage::Stream {
                    in_snapshot,
                    snap_seq,
                };
                Ok(ReplRequest::Poll(if in_snapshot {
                    0
                } else {
                    self.applied
                }))
            }
            (stage, reply) => {
                Err(format!("unexpected {} in {stage:?}", reply_name(&reply)))
            }
        }
    }

    /// Returns the tag of the replica, or 0 while the replica is incomplete.
    pub fn tag(&self) -> u64 {
        self.header.tag
    }

    /// Returns the last sequence number applied in this session.
    pub fn applied(&self) -> u64 {
        self.applied
    }

    /// Returns the number of records in the replica.
    pub fn records(&self) -> usize {
        self.store.len()
    }

    /// Returns the replica for the next role.
    pub fn into_copy(self) -> (Store, Header) {
        (self.store, self.header)
    }
}

fn reply_name(r: &ReplReply) -> &'static str {
    match r {
        ReplReply::Challenge(_) => "challenge",
        ReplReply::Welcome(_) => "welcome",
        ReplReply::Snapshot(_) => "snapshot",
        ReplReply::Batch(_) => "batch",
        ReplReply::Heartbeat(_) => "heartbeat",
    }
}

/// Runs the standby role until `interrupt` is raised. Returns the replica.
pub fn run(
    cfg: &Config,
    standby: Standby,
    interrupt: &Interrupt,
) -> (Store, Header) {
    let mut standby = standby;
    crate::notify::ready(&standby.log);
    let (local, peer) = match role::addresses(cfg) {
        Ok(a) => a,
        Err(e) => {
            truenas_ros::log!(
                standby.log,
                Level::Warning,
                "standby without a link: {e}"
            );
            while !interrupt.wait(Duration::from_secs(3600)) {}
            return standby.into_copy();
        }
    };
    let target = ServerAddr::Tcp(SocketAddrV4::new(peer, cfg.port));
    let mut backoff = Duration::from_millis(50);
    let mut down_logged = false;
    while !interrupt.pending() {
        let began = Instant::now();
        match session(&mut standby, cfg, &target, local, interrupt) {
            Ok(()) => break,
            Err(e) => {
                if !down_logged {
                    truenas_ros::log!(
                        standby.log,
                        Level::Warning,
                        "link to the primary at {peer}: {e}"
                    );
                    down_logged = true;
                }
            }
        }
        if began.elapsed() > Duration::from_secs(2) {
            backoff = Duration::from_millis(50);
            down_logged = false;
        }
        if interrupt.wait(backoff) {
            break;
        }
        backoff = (backoff * 2).min(Duration::from_secs(1));
    }
    standby.into_copy()
}

fn send(
    client: &mut Client<
        (),
        impl FnMut(&[u8], &mut ()) -> truenas_ros::net::Framing,
    >,
    conn: ConnId,
    req: &ReplRequest,
) -> Result<(), String> {
    let bytes = encode(req).ok_or("a request too large to frame")?;
    client
        .send(conn, bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Runs one connection to the primary. Returns `Ok` when `interrupt` is
/// raised.
fn session(
    standby: &mut Standby,
    cfg: &Config,
    target: &ServerAddr,
    local: std::net::Ipv4Addr,
    interrupt: &Interrupt,
) -> Result<(), String> {
    let client_cfg = ClientConfig {
        pool_size: 4,
        max_reply_bytes: MAX_FRAME + 4,
        connect_timeout: Some(cfg.link_timeout),
        ..ClientConfig::default()
    };
    let mut client = Client::new(
        client_cfg,
        length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
    )
    .map_err(|e| format!("client ring: {e}"))?;
    let opts = ConnectOpts {
        connect_timeout: Some(cfg.link_timeout),
        local_addr: Some(SocketAddr::V4(SocketAddrV4::new(local, 0))),
        ..ConnectOpts::default()
    };
    let conn = client
        .connect_start(target.clone(), opts)
        .map_err(|e| format!("connect: {e}"))?;
    let tick = Duration::from_millis(20);
    let deadline = Instant::now() + cfg.link_timeout * 2;
    loop {
        match client.next_event_timeout(tick).map_err(|e| e.to_string())? {
            Some(Event::Connected { .. }) => break,
            Some(Event::ConnectFailed { err, .. }) => {
                return Err(format!("connect: {err}"));
            }
            Some(_) => {}
            None => {
                if interrupt.pending() {
                    return Ok(());
                }
                if Instant::now() > deadline {
                    return Err("connect timed out".to_owned());
                }
            }
        }
    }
    let hello = standby.start();
    send(&mut client, conn, &hello)?;
    let mut last = Instant::now();
    loop {
        if interrupt.pending() {
            client.close(conn);
            return Ok(());
        }
        match client.next_event_timeout(tick).map_err(|e| e.to_string())? {
            Some(Event::Reply { body, .. }) => {
                last = Instant::now();
                let reply: ReplReply = truenas_xdr::from_bytes(&body[..])
                    .map_err(|e| format!("undecodable reply: {e}"))?;
                match standby.on_reply(reply) {
                    Ok(next) => send(&mut client, conn, &next)?,
                    Err(e) => {
                        client.close(conn);
                        return Err(e);
                    }
                }
            }
            Some(Event::Closed { reason, .. }) => {
                return Err(format!("closed ({reason:?})"));
            }
            Some(_) => {}
            None => {
                if last.elapsed() > cfg.link_timeout {
                    client.close(conn);
                    return Err("the primary went silent".to_owned());
                }
            }
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
    use crate::proto::repl::{Batch, Challenge, Snapshot};
    use crate::proto::{Owner, Record};
    use truenas_xdr::VarOpaque;

    fn fill(buf: &mut [u8]) {
        buf.fill(9);
    }

    const PNODE: Node = Node::A;
    const SNODE: Node = Node::B;
    const SB: BootId = FixedOpaque([4; 16]);

    fn rec(id: u64) -> Record {
        Record {
            id,
            share: "s".to_owned(),
            owner: Owner {
                pid: 1,
                unique_id: 1,
            },
            flags: 0,
            body: VarOpaque(vec![1, 2, 3]),
        }
    }

    fn standby_with(records: &[u64]) -> Standby {
        let mut store = Store::default();
        for id in records {
            store.apply(Op::Put(rec(*id)));
        }
        let mut header = Header::empty(PNODE, SB);
        header.tag = 7;
        Standby::new(
            LinkKey::derive(b"k").unwrap(),
            SNODE,
            SB,
            fill,
            store,
            header,
            Logger::silent(),
        )
    }

    /// Runs the handshake with a primary that has the same key.
    fn welcomed(sb: &mut Standby) {
        let ReplRequest::Hello(h) = sb.start() else {
            panic!()
        };
        let nonce = FixedOpaque([5; 32]);
        let key = LinkKey::derive(b"k").unwrap();
        let t = Transcript {
            standby_node: h.node,
            standby_nonce: &h.nonce,
            primary_node: PNODE,
            primary_nonce: &nonce,
        };
        let proof = auth::proof(&key, Side::Primary, &t).unwrap();
        let ReplRequest::Prove(p) = sb
            .on_reply(ReplReply::Challenge(Challenge {
                version: VERSION,
                node: PNODE,
                nonce,
                proof,
            }))
            .unwrap()
        else {
            panic!()
        };
        assert!(auth::verify(&key, Side::Standby, &t, &p));
        assert_eq!(
            sb.on_reply(ReplReply::Welcome(1)).unwrap(),
            ReplRequest::Poll(0)
        );
    }

    fn snap(first: bool, last: bool, seq: u64, ids: &[u64]) -> ReplReply {
        ReplReply::Snapshot(Snapshot {
            generation: 2,
            tag: 9,
            writer_node: PNODE,
            writer_boot: SB,
            first,
            last,
            seq,
            records: ids.iter().map(|i| rec(*i)).collect(),
        })
    }

    #[test]
    fn the_old_replica_stays_until_the_first_chunk_and_is_tagged_at_the_last() {
        let mut sb = standby_with(&[1, 2, 3]);
        welcomed(&mut sb);
        assert_eq!(
            (sb.tag(), sb.records()),
            (7, 3),
            "kept through the handshake"
        );
        assert_eq!(
            sb.on_reply(snap(true, false, 50, &[10])).unwrap(),
            ReplRequest::Poll(0)
        );
        assert_eq!((sb.tag(), sb.records()), (0, 1), "replaced, untagged");
        assert_eq!(
            sb.on_reply(snap(false, true, 50, &[11])).unwrap(),
            ReplRequest::Poll(50)
        );
        assert_eq!((sb.tag(), sb.records(), sb.applied()), (9, 2, 50));
        let next = sb
            .on_reply(ReplReply::Batch(Batch {
                first_seq: 51,
                ops: vec![Op::Del(10)],
            }))
            .unwrap();
        assert_eq!(next, ReplRequest::Poll(51));
        assert_eq!(
            sb.on_reply(ReplReply::Heartbeat(60)).unwrap(),
            ReplRequest::Poll(51)
        );
    }

    #[test]
    fn out_of_order_input_ends_the_session() {
        let bad: Vec<Box<dyn Fn(&mut Standby) -> Result<ReplRequest, String>>> = vec![
            Box::new(|sb| sb.on_reply(snap(false, true, 5, &[1]))),
            Box::new(|sb| {
                sb.on_reply(snap(true, false, 5, &[1]))?;
                sb.on_reply(snap(false, true, 6, &[2]))
            }),
            Box::new(|sb| {
                sb.on_reply(snap(true, true, 5, &[1]))?;
                sb.on_reply(ReplReply::Batch(Batch {
                    first_seq: 7,
                    ops: vec![],
                }))
            }),
            Box::new(|sb| {
                sb.on_reply(snap(true, false, 5, &[1]))?;
                sb.on_reply(ReplReply::Batch(Batch {
                    first_seq: 6,
                    ops: vec![],
                }))
            }),
            Box::new(|sb| {
                sb.on_reply(snap(true, true, 5, &[1]))?;
                sb.on_reply(ReplReply::Heartbeat(4))
            }),
            Box::new(|sb| sb.on_reply(ReplReply::Welcome(1))),
            Box::new(|sb| {
                sb.on_reply(ReplReply::Challenge(Challenge {
                    version: VERSION,
                    node: PNODE,
                    nonce: FixedOpaque([0; 32]),
                    proof: FixedOpaque([0; 32]),
                }))
            }),
        ];
        for (i, case) in bad.iter().enumerate() {
            let mut sb = standby_with(&[]);
            welcomed(&mut sb);
            assert!(case(&mut sb).is_err(), "case {i}");
        }
    }

    #[test]
    fn the_primary_must_prove_the_key_and_speak_this_version() {
        for (version, key) in [
            (VERSION, b"other" as &[u8]),
            (VERSION + 1, b"k"),
            (MIN_VERSION - 1, b"k"),
        ] {
            let mut sb = standby_with(&[]);
            let ReplRequest::Hello(h) = sb.start() else {
                panic!()
            };
            let nonce = FixedOpaque([5; 32]);
            let proof = auth::proof(
                &LinkKey::derive(key).unwrap(),
                Side::Primary,
                &Transcript {
                    standby_node: h.node,
                    standby_nonce: &h.nonce,
                    primary_node: PNODE,
                    primary_nonce: &nonce,
                },
            )
            .unwrap();
            let r = sb.on_reply(ReplReply::Challenge(Challenge {
                version,
                node: PNODE,
                nonce,
                proof,
            }));
            assert!(r.is_err());
        }
    }

    #[test]
    fn a_primary_that_says_it_is_this_node_is_refused() {
        let mut sb = standby_with(&[]);
        let ReplRequest::Hello(h) = sb.start() else {
            panic!()
        };
        let nonce = FixedOpaque([5; 32]);
        let proof = auth::proof(
            &LinkKey::derive(b"k").unwrap(),
            Side::Primary,
            &Transcript {
                standby_node: h.node,
                standby_nonce: &h.nonce,
                primary_node: h.node,
                primary_nonce: &nonce,
            },
        )
        .unwrap();
        let err = sb
            .on_reply(ReplReply::Challenge(Challenge {
                version: VERSION,
                node: h.node,
                nonce,
                proof,
            }))
            .unwrap_err();
        assert!(err.contains("node B too"), "{err}");
    }

    #[test]
    fn a_new_session_starts_counting_over() {
        let mut sb = standby_with(&[]);
        welcomed(&mut sb);
        sb.on_reply(snap(true, true, 500, &[1])).unwrap();
        assert_eq!(sb.applied(), 500);
        welcomed(&mut sb);
        assert_eq!(sb.applied(), 0);
        // In a new session, a heartbeat with a low sequence number is valid.
        assert_eq!(
            sb.on_reply(ReplReply::Heartbeat(3)).unwrap(),
            ReplRequest::Poll(0)
        );
    }
}
