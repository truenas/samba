// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the client of smbd (`truenas_smbhad_client`) against the daemon
//! binary.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown
)]
mod common;

use common::*;
use std::time::Duration;
use truenas_smbhad::proto::local::{Client, Origin};
use truenas_smbhad::proto::{Node, Owner, Protection, SyncLevel};
use truenas_smbhad_client::{Batch, Connection, Error};

const TIMEOUT: Duration = Duration::from_secs(10);

fn connect(node: &common::Node, role: Client, pid: u32) -> Connection {
    let owner = Owner {
        pid,
        unique_id: u64::from(pid) * 1000 + 7,
    };
    Connection::connect(&node.socket(), role, owner, TIMEOUT).unwrap()
}

#[test]
fn a_worker_submits_and_the_parent_rehydrates_through_the_client() {
    let lab = Lab::new();
    let mut a = lab.node("a", 0xa, A, B);
    let mut b = lab.node("b", 0xb, B, A);
    a.start("primary");
    b.start("standby");
    a.wait_protected();

    let mut worker = connect(&a, Client::Worker, 100);
    assert_eq!(worker.hello().node, Node::A);
    let owner = Owner {
        pid: 100,
        unique_id: 100_007,
    };
    let mut batch = Batch::default();
    let want: Vec<_> = (1..=30).map(|i| record(i, owner, 500)).collect();
    for r in &want {
        batch.put(r.clone());
    }
    batch.del(31);
    assert_eq!(batch.len(), 31);
    let s = worker
        .submit(&mut batch, SyncLevel::Remote)
        .unwrap()
        .unwrap();
    assert_eq!(s.protection, Protection::Protected);
    assert!(batch.is_empty());

    a.kill();
    b.set_role("primary");
    let mut parent = connect(&b, Client::Parent, 1);
    let mut records = Vec::new();
    let mut cursor = 0;
    loop {
        let page = parent.rehydrate(cursor, 4096).unwrap();
        assert_eq!(page.origin, Origin::Replica);
        assert_eq!(page.writer_node, Node::A);
        records.extend(page.records);
        if page.last {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(sorted(records), want);
    assert!(parent.done().is_ok());
}

#[test]
fn the_client_reports_a_refusal_and_a_closed_connection() {
    let lab = Lab::new();
    let mut a = lab.node("a", 0xa, A, B);
    a.start("primary");
    let mut worker = connect(&a, Client::Worker, 100);
    // Only the parent can rehydrate.
    let e = worker.rehydrate(0, 4096).unwrap_err();
    assert!(matches!(e, Error::Refused(..)), "{e:?}");

    let mut worker = connect(&a, Client::Worker, 100);
    let first = worker.hello().instance;
    a.kill();
    let mut batch = Batch::default();
    batch.del(1);
    let e = worker.submit(&mut batch, SyncLevel::Local).unwrap_err();
    assert!(matches!(e, Error::Closed | Error::Io(_)), "{e:?}");
    a.start("primary");
    let worker = connect(&a, Client::Worker, 100);
    assert_ne!(worker.hello().instance, first, "a new instance");
}
