// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the daemon binary. Each controller is a daemon process on a
//! loopback address.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::doc_markdown
)]
mod common;

use common::*;
use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use truenas_smbhad::proto::local::{Client, Hello, Origin, Reply, Request};
use truenas_smbhad::proto::{Op, Protection, Record, SyncLevel};

/// Starts the primary on A and the standby on B. Waits until A is protected.
fn pair(lab: &Lab) -> (Node, Node) {
    let mut a = lab.node("a", 0xa, A, B);
    let mut b = lab.node("b", 0xb, B, A);
    a.start("primary");
    b.start("standby");
    a.wait_protected();
    (a, b)
}

/// Makes `node` the primary. Middleware does this after the peer fails.
fn promote(node: &mut Node) {
    node.set_role("primary");
}

#[test]
fn promises_are_protected_once_the_standby_has_synced() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    for i in 0..50u64 {
        let s = smbd
            .put(vec![record(i + 1, smbd.owner, 900)], SyncLevel::Remote)
            .unwrap();
        assert_eq!(s.protection, Protection::Protected, "promise {i}");
    }
    assert_eq!(smbd.hello.epoch, lab.epoch());
}

#[test]
fn failover_restores_the_standbys_replica() {
    let lab = Lab::new();
    let (mut a, mut b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    let mut want: Vec<Record> = Vec::new();
    for i in 1..=300u64 {
        want.push(record(i, smbd.owner, (i as usize * 13) % 2000));
    }
    smbd.put(want[..200].to_vec(), SyncLevel::None);
    let s = smbd.put(want[200..].to_vec(), SyncLevel::Remote).unwrap();
    assert_eq!(s.protection, Protection::Protected);
    // Delete records 5 and 6 without a reply. Change record 1 with a
    // promise. The promise also covers the deletes.
    smbd.submit(vec![Op::Del(5), Op::Del(6)], SyncLevel::None);
    want.retain(|r| r.id != 5 && r.id != 6);
    want[0] = record(1, smbd.owner, 17);
    smbd.put(vec![want[0].clone()], SyncLevel::Remote);

    a.kill();
    promote(&mut b);
    let mut parent = b.smbd(Client::Parent, 1);
    let (page, records) = parent.rehydrate_all(64 << 10);
    assert_eq!(page.origin, Origin::Replica);
    assert_eq!(
        page.writer_node,
        truenas_smbhad::proto::Node::A,
        "written by A"
    );
    assert_eq!(sorted(records), want);
    assert_eq!(parent.done(), 1);
}

#[test]
fn a_promoted_standby_serves_smbd_while_its_link_port_is_taken() {
    let lab = Lab::new();
    let (mut a, mut b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    let want: Vec<Record> =
        (1..=20).map(|i| record(i, smbd.owner, 300)).collect();
    let s = smbd.put(want.clone(), SyncLevel::Remote).unwrap();
    assert_eq!(s.protection, Protection::Protected);

    // Another process has the link port of B when B becomes the primary.
    // B must still serve smbd: `promote` waits for an answer on smbd.sock.
    let squatter = std::net::TcpListener::bind((B, b.port)).unwrap();
    a.kill();
    promote(&mut b);
    assert!(b.log().contains("serving smbd without a standby"));
    let mut parent = b.smbd(Client::Parent, 1);
    let (page, records) = parent.rehydrate_all(64 << 10);
    assert_eq!(page.origin, Origin::Replica);
    assert_eq!(sorted(records), want);
    assert_eq!(parent.done(), 1);

    // When the port is free, B starts again with the link. A becomes its
    // standby.
    drop(squatter);
    assert!(
        wait_for(Duration::from_secs(15), || b.log().contains("is free")),
        "B never tried the port again:\n{}",
        b.log()
    );
    a.start("standby");
    b.wait_protected();
}

/// As `pair`, but the link goes through a proxy. The test can cut the link
/// while both daemons run.
fn proxied_pair(lab: &Lab) -> (Node, Node, Proxy) {
    let proxy = Proxy::new(
        SocketAddrV4::new(PROXY, lab.port),
        SocketAddrV4::new(A, lab.port),
    );
    // The proxy connects to A from A's own address.
    let mut a = lab.node("a", 0xa, A, A);
    let mut b = lab.node("b", 0xb, B, PROXY);
    a.start("primary");
    b.start("standby");
    a.wait_protected();
    (a, b, proxy)
}

#[test]
fn a_cut_link_fences_and_the_stale_replica_is_not_restored() {
    let lab = Lab::new();
    let (mut a, mut b, proxy) = proxied_pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    let s = smbd
        .put(vec![record(1, smbd.owner, 100)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
    let protected_epoch = lab.epoch();

    proxy.cut();
    // The standby cannot acknowledge the next promise. The primary answers
    // it only after the epoch file is above the tag of the standby's copy.
    let s = smbd
        .put(vec![record(1, smbd.owner, 200)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Unprotected);
    assert!(lab.epoch() > protected_epoch, "fenced before answering");
    assert_eq!(s.epoch, lab.epoch());

    // Kill the primary. The standby ran the whole time and has its old
    // replica. The promoted standby must not restore it.
    a.kill();
    promote(&mut b);
    let mut parent = b.smbd(Client::Parent, 1);
    let (page, records) = parent.rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::None);
    assert!(records.is_empty());
    assert!(b.log().contains("does not match"), "{}", b.log());
}

#[test]
fn a_hung_standby_is_detected_by_the_link_timeout() {
    let lab = Lab::new();
    let (a, b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    b.signal("-STOP");
    let began = Instant::now();
    let s = smbd
        .put(vec![record(1, smbd.owner, 10)], SyncLevel::Remote)
        .unwrap();
    let took = began.elapsed();
    b.signal("-CONT");
    assert_eq!(s.protection, Protection::Unprotected);
    assert!(
        took >= Duration::from_millis(LINK_TIMEOUT_MS / 2)
            && took < Duration::from_millis(LINK_TIMEOUT_MS * 5),
        "answered after {took:?}"
    );
    // The standby continues, reconnects and resyncs.
    a.wait_protected();
    let s = smbd
        .put(vec![record(2, smbd.owner, 10)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
}

#[test]
fn a_returning_standby_resyncs_everything_it_missed() {
    let lab = Lab::new();
    let (mut a, mut b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    smbd.put(
        (1..=50).map(|i| record(i, smbd.owner, 300)).collect(),
        SyncLevel::Remote,
    );
    let before = lab.epoch();
    b.kill();
    let s = smbd
        .put(
            (51..=80).map(|i| record(i, smbd.owner, 300)).collect(),
            SyncLevel::Remote,
        )
        .unwrap();
    assert_eq!(s.protection, Protection::Unprotected);
    smbd.submit((1..=10).map(Op::Del).collect(), SyncLevel::None);
    b.start("standby");
    a.wait_protected();
    assert!(lab.epoch() > before);
    smbd.barrier();
    a.kill();
    promote(&mut b);
    let mut parent = b.smbd(Client::Parent, 1);
    let (page, records) = parent.rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::Replica);
    let want: Vec<Record> =
        (11..=80).map(|i| record(i, smbd.owner, 300)).collect();
    assert_eq!(sorted(records), want);
}

#[test]
fn an_smbd_restart_rehydrates_the_primarys_own_copy() {
    let lab = Lab::new();
    let (a, mut b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    smbd.put(
        (1..=20).map(|i| record(i, smbd.owner, 50)).collect(),
        SyncLevel::Remote,
    );
    drop(smbd);

    // A new smbd parent rehydrates and keeps only the records with even ids,
    // as disconnected handles. (smbd keeps none after a restart; the daemon
    // takes any set.)
    let mut parent = a.smbd(Client::Parent, 1);
    let (page, records) = parent.rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::Own);
    assert_eq!(page.writer_node, truenas_smbhad::proto::Node::A);
    assert_eq!(records.len(), 20);
    let kept: Vec<Record> = records
        .into_iter()
        .filter(|r| r.id % 2 == 0)
        .map(|mut r| {
            r.owner = truenas_smbhad::proto::Owner::DISCONNECTED;
            r
        })
        .collect();
    parent.put(kept.clone(), SyncLevel::None);
    let before = lab.epoch();
    assert_eq!(parent.done(), 1);
    // The primary fences the standby's copy of the old generation. Then the
    // standby resyncs.
    assert!(wait_for(Duration::from_secs(5), || lab.epoch() > before));
    a.wait_protected();

    // A second restart gets only the records that the first restart kept.
    let mut again = a.smbd(Client::Parent, 2);
    let (_, records) = again.rehydrate_all(1 << 20);
    assert_eq!(sorted(records), kept);
    again.put(kept.clone(), SyncLevel::None);
    again.done();
    a.wait_protected();

    // After a failover, the replica on the standby has only these records.
    let mut a = a;
    a.kill();
    promote(&mut b);
    let (page, records) = b.smbd(Client::Parent, 3).rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::Replica);
    assert_eq!(sorted(records), kept);
}

#[test]
fn a_daemon_restart_on_the_primary_is_rebuilt_from_smbd() {
    let lab = Lab::new();
    let (mut a, mut b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    let all: Vec<Record> =
        (1..=30).map(|i| record(i, smbd.owner, 64)).collect();
    smbd.put(all.clone(), SyncLevel::Remote);
    let instance = smbd.hello.instance;
    let before = lab.epoch();

    a.kill();
    a.start("primary");
    // smbd sees a new instance and submits all its handles again.
    let mut smbd = a.smbd(Client::Worker, 100);
    assert_ne!(smbd.hello.instance, instance);
    assert!(smbd.hello.epoch > before, "a starting primary fences");
    a.wait_protected();
    let s = smbd.put(all.clone(), SyncLevel::Remote).unwrap();
    assert_eq!(s.protection, Protection::Protected);

    a.kill();
    promote(&mut b);
    let (page, records) = b.smbd(Client::Parent, 1).rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::Replica);
    assert_eq!(sorted(records), all);
}

#[test]
fn an_unclean_exit_drops_that_processes_handles_on_both_controllers() {
    let lab = Lab::new();
    let (mut a, mut b) = pair(&lab);
    let mut one = a.smbd(Client::Worker, dead_pid());
    let mut two = a.smbd(Client::Worker, 200);
    one.put(
        (1..=10).map(|i| record(i, one.owner, 10)).collect(),
        SyncLevel::None,
    );
    two.put(
        (11..=20).map(|i| record(i, two.owner, 10)).collect(),
        SyncLevel::None,
    );
    // A disconnected handle of process one is kept when process one exits
    // uncleanly.
    let disconnected =
        record(5, truenas_smbhad::proto::Owner::DISCONNECTED, 10);
    one.put(vec![disconnected.clone()], SyncLevel::Remote);
    two.barrier();
    let mut cleanupd = a.smbd(Client::Cleanupd, 300);
    cleanupd.forget(one.owner);
    let s = cleanupd.submit(Vec::new(), SyncLevel::Remote).unwrap();
    assert_eq!(s.protection, Protection::Protected);

    let mut want: Vec<Record> =
        (11..=20).map(|i| record(i, two.owner, 10)).collect();
    want.insert(0, disconnected);
    let (_, records) = a.smbd(Client::Parent, 1).rehydrate_all(1 << 20);
    assert_eq!(sorted(records), want);
    a.kill();
    promote(&mut b);
    let (_, records) = b.smbd(Client::Parent, 1).rehydrate_all(1 << 20);
    assert_eq!(sorted(records), want);
}

#[test]
fn a_standby_with_the_wrong_secret_is_never_trusted() {
    let lab = Lab::new();
    let mut a = lab.node("a", 0xa, A, B);
    let mut b = lab.node("b", 0xb, B, A);
    std::fs::write(lab.path("other-secret"), b"not the pwenc secret").unwrap();
    b.secret = lab.path("other-secret");
    a.start("primary");
    b.start("standby");
    let mut smbd = a.smbd(Client::Worker, 100);
    for _ in 0..10 {
        let s = smbd
            .put(vec![record(1, smbd.owner, 1)], SyncLevel::Remote)
            .unwrap();
        assert_eq!(s.protection, Protection::Unprotected);
        thread::sleep(Duration::from_millis(50));
    }
    assert!(b.log().contains("authentication"), "{}", b.log());
    a.kill();
    promote(&mut b);
    let (page, _) = b.smbd(Client::Parent, 1).rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::None);
}

#[test]
fn only_the_configured_peer_may_connect_to_the_link() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    let stranger = std::net::TcpListener::bind((STRANGER, 0)).unwrap();
    drop(stranger);
    // Connect from A. The configured peer is B. The daemon closes the
    // connection before it reads from it.
    let socket = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::V4(SocketAddrV4::new(A, lab.port)),
        Duration::from_secs(1),
    );
    if let Ok(mut s) = socket {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let _ = s.write_all(&[0, 0, 0, 4, 0, 0, 0, 1]);
        let mut buf = [0u8; 16];
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed without a reply");
    }
    assert!(a.log().contains("not the peer"), "{}", a.log());
    assert_eq!(a.protection(), Some(Protection::Protected));
}

#[test]
fn protocol_abuse_on_the_local_socket_is_contained() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    // An invalid frame closes only this connection.
    let mut raw = UnixStream::connect(a.socket()).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    raw.write_all(&[0, 0, 0, 3, 9, 9, 9]).unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(raw.read(&mut buf).unwrap_or(0), 0);
    // A request before the hello also closes the connection.
    let mut raw = UnixStream::connect(a.socket()).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    send(&mut raw, &Request::Done).unwrap();
    assert_eq!(raw.read(&mut buf).unwrap_or(0), 0);
    // A hello with a wrong version gets an error reply. Then the daemon
    // closes the connection.
    let mut raw = UnixStream::connect(a.socket()).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    send(
        &mut raw,
        &Request::Hello(Hello {
            version: 99,
            role: Client::Worker,
            owner: owner(1),
        }),
    )
    .unwrap();
    assert!(matches!(recv(&mut raw).unwrap(), Reply::Error(e) if e.code == 71));
    // A worker cannot rehydrate or end a rehydration (EACCES).
    let mut worker = a.smbd(Client::Worker, 100);
    assert!(matches!(
        worker.request(&Request::Rehydrate(truenas_smbhad::proto::local::Rehydrate {
            cursor: 0,
            max_bytes: 1000,
        })),
        Reply::Error(e) if e.code == 13
    ));
    assert!(
        matches!(worker.request(&Request::Done), Reply::Error(e) if e.code == 13)
    );
    // A record too large to keep becomes a delete of its id. The daemon
    // applies the other operations of that submit.
    worker.put(vec![record(1, worker.owner, 10)], SyncLevel::Local);
    let big = record(1, worker.owner, 64 * 1024 + 1);
    let small = record(2, worker.owner, 10);
    let s = worker.put(vec![small.clone(), big], SyncLevel::Local);
    assert!(s.is_some());
    let mut parent = a.smbd(Client::Parent, 1);
    let (_, records) = parent.rehydrate_all(1 << 20);
    assert_eq!(records, vec![small], "record 1 is gone");
    parent.done();
    a.wait_protected();
    // The daemon continues to serve other clients. Their promises are
    // protected.
    let mut other = a.smbd(Client::Worker, 200);
    let s = other
        .put(vec![record(3, other.owner, 10)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
}

/// Writes the next even epoch to the epoch file, as the fallback fence of
/// smbd does. Returns the epoch.
fn smbd_fence(lab: &Lab) -> u64 {
    truenas_smbhad::epoch::EpochFile::new(&lab.epoch_file())
        .fence(0)
        .unwrap()
        .expect("the epoch file exists")
}

#[test]
fn an_smbd_fence_makes_the_primary_drop_its_copy() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    smbd.put(
        (1..=5).map(|i| record(i, smbd.owner, 50)).collect(),
        SyncLevel::Remote,
    );
    let instance = smbd.hello.instance;
    // A process that cannot reach the daemon fences. Its changes can be
    // missing from the copy. The protected primary reads the epoch file
    // once a second.
    let fenced = smbd_fence(&lab);
    assert!(
        wait_for(Duration::from_secs(10), || a
            .log()
            .contains("another writer fenced")),
        "{}",
        a.log()
    );
    // A new primary serves an empty copy under a new instance. smbd sends
    // its handles again.
    assert!(wait_for(Duration::from_secs(10), || {
        a.try_hello().is_some_and(|h| h.instance != instance)
    }));
    assert!(lab.epoch() > fenced);
    let mut parent = a.smbd(Client::Parent, 1);
    let (page, records) = parent.rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::None);
    assert!(records.is_empty());
    parent.done();
}

#[test]
fn a_parent_that_closes_its_connection_ends_its_rehydration() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    smbd.put(
        (1..=4).map(|i| record(i, smbd.owner, 50)).collect(),
        SyncLevel::Remote,
    );
    drop(smbd);
    let mut parent = a.smbd(Client::Parent, 1);
    let (_, records) = parent.rehydrate_all(1 << 20);
    assert_eq!(records.len(), 4);
    let kept = vec![record(2, truenas_smbhad::proto::Owner::DISCONNECTED, 50)];
    parent.put(kept.clone(), SyncLevel::Local);
    let before = lab.epoch();
    drop(parent);
    // The daemon ends the rehydration and fences the old copy.
    assert!(wait_for(Duration::from_secs(5), || lab.epoch() > before));
    let mut again = a.smbd(Client::Parent, 2);
    let (_, records) = again.rehydrate_all(1 << 20);
    assert_eq!(records, kept);
    again.put(kept, SyncLevel::None);
    again.done();
    a.wait_protected();
}

#[test]
fn a_submit_that_arrives_after_its_process_was_forgotten_is_dropped() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    let pid = dead_pid();
    let mut dead = a.smbd(Client::Worker, pid);
    dead.put(vec![record(1, dead.owner, 10)], SyncLevel::Local);
    // cleanupd reports the exit of the process. A submit of the process
    // that was still in its socket is read after that.
    let mut cleanupd = a.smbd(Client::Cleanupd, 300);
    cleanupd.forget(truenas_smbhad::proto::Owner { pid, unique_id: 0 });
    cleanupd.barrier();
    dead.submit(vec![Op::Put(record(2, dead.owner, 10))], SyncLevel::None);
    // The daemon drops the submit and closes the connection.
    let mut buf = [0u8; 1];
    assert_eq!(dead.stream.read(&mut buf).unwrap_or(0), 0);
    let mut parent = a.smbd(Client::Parent, 1);
    let (_, records) = parent.rehydrate_all(1 << 20);
    assert!(records.is_empty(), "{records:?}");
    parent.done();
}

#[test]
fn a_forget_keeps_the_handles_of_a_live_process_with_that_pid() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    // The kernel gave the pid of an exited process to this process. It
    // connected before cleanupd reported the exit.
    let pid = std::process::id();
    let mut live = a.smbd(Client::Worker, pid);
    live.put(vec![record(1, live.owner, 10)], SyncLevel::Local);
    let mut cleanupd = a.smbd(Client::Cleanupd, 300);
    cleanupd.forget(truenas_smbhad::proto::Owner { pid, unique_id: 0 });
    cleanupd.barrier();
    live.put(vec![record(2, live.owner, 10)], SyncLevel::Local);
    let mut parent = a.smbd(Client::Parent, 1);
    let (_, records) = parent.rehydrate_all(1 << 20);
    assert_eq!(
        records,
        vec![record(1, live.owner, 10), record(2, live.owner, 10)]
    );
    parent.done();
}

const SESSIONS: u64 = 100;
const PROMISES: u64 = 30;

#[test]
fn many_sessions_promise_concurrently_and_all_survive_a_failover() {
    let lab = Lab::new();
    let (mut a, mut b) = pair(&lab);
    let latencies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let socket = a.socket();
    let threads: Vec<_> = (0..SESSIONS)
        .map(|n| {
            let latencies = Arc::clone(&latencies);
            let node_socket = socket.clone();
            thread::spawn(move || {
                let mut stream = UnixStream::connect(&node_socket).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let me = owner(1000 + n as u32);
                send(
                    &mut stream,
                    &Request::Hello(Hello {
                        version: truenas_smbhad::proto::VERSION,
                        role: Client::Worker,
                        owner: me,
                    }),
                )
                .unwrap();
                recv(&mut stream).unwrap();
                let mut mine = Vec::new();
                for i in 0..PROMISES {
                    let r = record(n * 1000 + i + 1, me, 200);
                    mine.push(r.clone());
                    let began = Instant::now();
                    send(
                        &mut stream,
                        &Request::Submit(
                            truenas_smbhad::proto::local::Submit {
                                sync: SyncLevel::Remote,
                                ops: vec![Op::Put(r)],
                            },
                        ),
                    )
                    .unwrap();
                    match recv(&mut stream).unwrap() {
                        Reply::Synced(s) => {
                            assert_eq!(s.protection, Protection::Protected);
                        }
                        other => panic!("{other:?}"),
                    }
                    latencies.lock().unwrap().push(began.elapsed());
                }
                mine
            })
        })
        .collect();
    let mut want: Vec<Record> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    want.sort_by_key(|r| r.id);
    let mut l = latencies.lock().unwrap().clone();
    l.sort();
    eprintln!(
        "{} promises from {SESSIONS} sessions on loopback: p50 {:?} p99 {:?} max {:?}",
        l.len(),
        l[l.len() / 2],
        l[l.len() * 99 / 100],
        l[l.len() - 1]
    );
    a.kill();
    promote(&mut b);
    let (page, records) = b.smbd(Client::Parent, 1).rehydrate_all(256 << 10);
    assert_eq!(page.origin, Origin::Replica);
    assert_eq!(sorted(records), want);
}

#[test]
fn a_large_copy_resyncs_in_chunks_under_concurrent_writes() {
    let lab = Lab::new();
    let mut a = lab.node("a", 0xa, A, B);
    let mut b = lab.node("b", 0xb, B, A);
    a.start("primary");
    let mut smbd = a.smbd(Client::Worker, 100);
    // 24 MiB of records, about six snapshot chunks of 4 MiB.
    for chunk in 0..24u64 {
        smbd.put(
            (0..64)
                .map(|i| record(chunk * 64 + i + 1, smbd.owner, 16 * 1024))
                .collect(),
            SyncLevel::None,
        );
    }
    smbd.barrier();
    // A second connection writes while the standby resyncs.
    let stop = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let writer = {
        let stop = Arc::clone(&stop);
        let writes = Arc::clone(&writes);
        let socket = a.socket();
        thread::spawn(move || {
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let me = owner(100);
            send(
                &mut stream,
                &Request::Hello(Hello {
                    version: truenas_smbhad::proto::VERSION,
                    role: Client::Worker,
                    owner: me,
                }),
            )
            .unwrap();
            recv(&mut stream).unwrap();
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let id = (n * 7919) % 1536 + 1;
                let ops = if n.is_multiple_of(5) {
                    vec![Op::Del(id)]
                } else {
                    vec![Op::Put(record(id, me, (n as usize * 31) % 4000))]
                };
                send(
                    &mut stream,
                    &Request::Submit(truenas_smbhad::proto::local::Submit {
                        sync: SyncLevel::Local,
                        ops,
                    }),
                )
                .unwrap();
                recv(&mut stream).unwrap();
                writes.store(n, Ordering::Relaxed);
            }
            n
        })
    };
    b.start("standby");
    a.wait_protected();
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    let n = writer.join().unwrap();
    assert!(n > 100, "the writer kept going during the resync: {n}");
    // One more promise covers all changes.
    let s = smbd.submit(Vec::new(), SyncLevel::Remote).unwrap();
    assert_eq!(s.protection, Protection::Protected);
    let (_, want) = a.smbd(Client::Parent, 1).rehydrate_all(1 << 20);
    // The rehydration freezes the primary's copy. Kill the primary, promote
    // the standby and compare the replica with that copy.
    a.kill();
    promote(&mut b);
    let (page, records) = b.smbd(Client::Parent, 2).rehydrate_all(300 * 1024);
    assert_eq!(page.origin, Origin::Replica);
    assert_eq!(records.len(), want.len());
    assert!(records == want, "the replica equals the primary's copy");
}

#[test]
fn rehydration_pages_through_a_copy_in_small_pages() {
    let lab = Lab::new();
    let mut a = lab.node("a", 0xa, A, B);
    a.start("primary");
    let mut smbd = a.smbd(Client::Worker, 100);
    let want: Vec<Record> = (1..=500)
        .map(|i| record(i * 3, smbd.owner, (i as usize) % 300))
        .collect();
    smbd.put(want.clone(), SyncLevel::Local);
    let mut parent = a.smbd(Client::Parent, 1);
    let (_, records) = parent.rehydrate_all(1000);
    assert_eq!(records, want, "every record once, in id order");
}

#[test]
fn sighup_restarts_the_role_and_keeps_the_copy() {
    let lab = Lab::new();
    let (mut a, _b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    let want: Vec<Record> =
        (1..=10).map(|i| record(i, smbd.owner, 40)).collect();
    smbd.put(want.clone(), SyncLevel::Remote);
    let before = lab.epoch();
    a.set_role("primary");
    a.wait_protected();
    assert!(lab.epoch() > before);
    let (page, records) = a.smbd(Client::Parent, 1).rehydrate_all(1 << 20);
    assert_eq!(page.origin, Origin::Own);
    assert_eq!(sorted(records), want);
}

#[test]
fn sigterm_stops_both_roles() {
    let lab = Lab::new();
    let (mut a, mut b) = pair(&lab);
    b.stop();
    a.stop();
    assert!(a.log().contains("stopped") && b.log().contains("stopped"));
}

#[test]
fn a_standby_that_never_finished_its_snapshot_restores_nothing() {
    let lab = Lab::new();
    let mut a = lab.node("a", 0xa, A, B);
    let mut b = lab.node("b", 0xb, B, A);
    a.start("primary");
    let mut smbd = a.smbd(Client::Worker, 100);
    for chunk in 0..32u64 {
        smbd.put(
            (0..64)
                .map(|i| record(chunk * 64 + i + 1, smbd.owner, 60 * 1024))
                .collect(),
            SyncLevel::None,
        );
    }
    smbd.barrier();
    b.start("standby");
    // Kill the primary when the resync starts.
    assert!(wait_for(Duration::from_secs(10), || a
        .log()
        .contains("resyncing")));
    a.kill();
    promote(&mut b);
    let (page, records) = b.smbd(Client::Parent, 1).rehydrate_all(1 << 20);
    if page.origin != Origin::None {
        // The whole snapshot arrived before the kill. The replica must have
        // all 2048 records (120 MiB).
        assert_eq!(records.len(), 2048, "{}", b.log());
    }
}

#[test]
fn a_hung_primary_recovers_and_protects_again() {
    let lab = Lab::new();
    let (a, b) = pair(&lab);
    let before = lab.epoch();
    a.signal("-STOP");
    std::thread::sleep(Duration::from_millis(LINK_TIMEOUT_MS * 3));
    a.signal("-CONT");
    a.wait_protected();
    let mut smbd = a.smbd(Client::Worker, 100);
    let s = smbd
        .put(vec![record(1, smbd.owner, 10)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
    assert!(
        lab.epoch() > before,
        "the stalled session was fenced and replaced"
    );
    assert!(
        b.log().contains("went silent") || b.log().contains("closed"),
        "{}",
        b.log()
    );
}

#[test]
fn reloading_the_standby_resyncs_it() {
    let lab = Lab::new();
    let (a, mut b) = pair(&lab);
    let mut smbd = a.smbd(Client::Worker, 100);
    smbd.put(
        (1..=20).map(|i| record(i, smbd.owner, 10)).collect(),
        SyncLevel::Remote,
    );
    let before = lab.epoch();
    b.set_role("standby");
    assert!(wait_for(Duration::from_secs(5), || lab.epoch() > before));
    a.wait_protected();
    let s = smbd
        .put(vec![record(21, smbd.owner, 10)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
}

/// A xorshift generator for fuzz input.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// A valid request with up to two bytes changed, or random bytes. About
    /// one frame in ten has a random length.
    fn frame(&mut self) -> Vec<u8> {
        let body = if self.next().is_multiple_of(4) {
            let n = (self.next() % 200) as usize;
            self.bytes(n)
        } else {
            let req = match self.next() % 5 {
                0 => Request::Submit(truenas_smbhad::proto::local::Submit {
                    sync: SyncLevel::Local,
                    ops: (0..self.next() % 50).map(Op::Del).collect(),
                }),
                1 => Request::Rehydrate(
                    truenas_smbhad::proto::local::Rehydrate {
                        cursor: self.next(),
                        max_bytes: self.next() as u32,
                    },
                ),
                2 => Request::ForgetOwner(owner(self.next() as u32)),
                3 => Request::Done,
                _ => Request::Hello(Hello {
                    version: truenas_smbhad::proto::VERSION,
                    role: Client::Worker,
                    owner: owner(7),
                }),
            };
            let mut b = truenas_xdr::to_bytes(&req).unwrap();
            let flips = self.next() % 3;
            for _ in 0..flips {
                if !b.is_empty() {
                    let i = (self.next() as usize) % b.len();
                    b[i] ^= self.next() as u8;
                }
            }
            b
        };
        let len = if self.next().is_multiple_of(10) {
            self.next() as u32
        } else {
            body.len() as u32
        };
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }
}

#[test]
fn fuzzed_input_on_the_local_socket_never_takes_the_daemon_down() {
    let lab = Lab::new();
    let (a, _b) = pair(&lab);
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    for _ in 0..400 {
        let Ok(mut s) = UnixStream::connect(a.socket()) else {
            continue;
        };
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        // About half of the connections send a valid hello first. The daemon
        // processes other requests only after a hello.
        if rng.next().is_multiple_of(2) {
            let _ = send(
                &mut s,
                &Request::Hello(Hello {
                    version: truenas_smbhad::proto::VERSION,
                    role: if rng.next().is_multiple_of(2) {
                        Client::Parent
                    } else {
                        Client::Worker
                    },
                    owner: owner(9),
                }),
            );
            let _ = recv(&mut s);
        }
        for _ in 0..=(rng.next() % 4) {
            let _ = s.write_all(&rng.frame());
        }
        let mut buf = [0u8; 64];
        let _ = s.read(&mut buf);
    }
    // After the fuzzing, a new parent can rehydrate and end the rehydration.
    let mut parent = a.smbd(Client::Parent, 1);
    parent.rehydrate_all(1 << 20);
    parent.done();
    a.wait_protected();
    let mut smbd = a.smbd(Client::Worker, 100);
    let s = smbd
        .put(vec![record(1, smbd.owner, 10)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
}

#[test]
fn fuzzed_input_on_the_link_never_takes_the_daemon_down() {
    let lab = Lab::new();
    // Both daemons are on A's address, with A as the peer. The primary
    // accepts the test's connections from A. They reach the handshake.
    let mut a = lab.node("a", 0xa, A, A);
    let mut b = lab.node("b", 0xb, A, A);
    a.start("primary");
    b.start("standby");
    a.wait_protected();
    let before = lab.epoch();
    let mut rng = Rng(0xfeed_0042_0042_0042);
    for i in 0..300 {
        let Ok(mut s) = TcpStream::connect_timeout(
            &std::net::SocketAddr::V4(SocketAddrV4::new(A, lab.port)),
            Duration::from_secs(1),
        ) else {
            continue;
        };
        s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let body = if i % 3 == 0 {
            // A valid hello. The primary answers with a challenge.
            let hello = truenas_smbhad::proto::repl::ReplRequest::Hello(
                truenas_smbhad::proto::repl::ReplHello {
                    version: truenas_smbhad::proto::VERSION,
                    node: truenas_smbhad::proto::Node::B,
                    boot: truenas_xdr::FixedOpaque([8; 16]),
                    nonce: truenas_xdr::FixedOpaque([9; 32]),
                },
            );
            truenas_xdr::to_bytes(&hello).unwrap()
        } else {
            let n = (rng.next() % 120) as usize;
            rng.bytes(n)
        };
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        let _ = s.write_all(&frame);
        if i % 3 == 0 {
            // Then an invalid proof.
            let prove = truenas_xdr::to_bytes(
                &truenas_smbhad::proto::repl::ReplRequest::Prove(
                    truenas_xdr::FixedOpaque([1; 32]),
                ),
            )
            .unwrap();
            let mut frame = (prove.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&prove);
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf);
            let _ = s.write_all(&frame);
        }
        let mut buf = [0u8; 64];
        let _ = s.read(&mut buf);
    }
    // Connections without the key do not change the epoch or the protection.
    assert_eq!(lab.epoch(), before, "{}", a.log());
    assert_eq!(a.protection(), Some(Protection::Protected));
    let mut smbd = a.smbd(Client::Worker, 100);
    let s = smbd
        .put(vec![record(1, smbd.owner, 10)], SyncLevel::Remote)
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
}

#[test]
fn a_copy_of_fifty_thousand_handles_resyncs_and_fails_over() {
    let lab = Lab::new();
    let mut a = lab.node("a", 0xa, A, B);
    let mut b = lab.node("b", 0xb, B, A);
    a.start("primary");
    let mut smbd = a.smbd(Client::Worker, 100);
    for chunk in 0..50u64 {
        smbd.put(
            (0..1000)
                .map(|i| record(chunk * 1000 + i + 1, smbd.owner, 964))
                .collect(),
            SyncLevel::None,
        );
    }
    smbd.barrier();
    let began = Instant::now();
    b.start("standby");
    a.wait_protected();
    let resync = began.elapsed();
    eprintln!("resync of 50,000 records of 964 bytes: {resync:?}");
    assert!(resync < Duration::from_secs(20));
    a.kill();
    let began = Instant::now();
    promote(&mut b);
    let (page, records) = b.smbd(Client::Parent, 1).rehydrate_all(4 << 20);
    eprintln!(
        "promotion and rehydration of 50,000 records: {:?}",
        began.elapsed()
    );
    assert_eq!(page.origin, Origin::Replica);
    assert_eq!(records.len(), 50_000);
}
