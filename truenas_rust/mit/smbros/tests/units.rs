// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! Tests of the parts of a reactor.

#![allow(unsafe_code)]

use std::ptr::NonNull;

use truenas_smbros::ffi::tn_smbros_buf_open;
use truenas_smbros::placement::{CpuSet, cpu_list, next_busy};
use truenas_smbros::{Link, Out, Pool, Push, Ring, Sqe, Stack};

/// The capacity of block class 0, the receive block of a connection.
const SMALL: usize = 20 * 1024;

#[test]
fn a_block_class_has_room_for_its_size() {
    let mut p = Pool::new(1 << 20);
    for (size, class) in [
        (100, 0),
        (SMALL, 0),
        (SMALL + 1, 1),
        ((1 << 20) + 4096, 6),
        ((16 << 20) + 4, 10),
    ] {
        let b = p.get(size).unwrap();
        assert_eq!(b.class(), class);
        assert!(b.cap() as usize >= size);
    }
    assert!(p.get((32 << 20) + 4096 + 1).is_none());
    let b = p.get(1000).unwrap();
    let at = b.data();
    p.put(b);
    assert_eq!(p.get(10).unwrap().data(), at);
}

#[test]
fn a_pool_frees_blocks_over_its_budget() {
    let mut p = Pool::new(SMALL);
    let a = p.get_class(0).unwrap();
    let b = p.get_class(0).unwrap();
    p.put(a);
    p.put(b);
    assert_eq!(p.held(), SMALL);
}

#[test]
fn a_stack_gives_its_items_in_push_order() {
    let stack = Stack::new();
    let mut links = [Link::new(), Link::new(), Link::new()];
    let [pa, pb, pc] = links.each_mut().map(NonNull::from);
    // SAFETY: the links live until the end of the test.
    unsafe {
        assert_eq!(stack.push(pa), Push::First);
        assert_eq!(stack.push(pb), Push::More);
        stack.push(pc);
    }
    let mut got = stack.take();
    assert_eq!(got.pop(), Some(pa));
    assert_eq!(got.pop(), Some(pb));
    assert_eq!(got.pop(), Some(pc));
    assert_eq!(got.pop(), None);
    // SAFETY: as above.
    unsafe { stack.push(pa) };
    let mut rest = stack.close();
    assert_eq!(rest.pop(), Some(pa));
    // SAFETY: as above.
    assert_eq!(unsafe { stack.push(pb) }, Push::Dead);
}

fn vec_of(p: &mut [u8]) -> libc::iovec {
    libc::iovec {
        iov_base: p.as_mut_ptr().cast(),
        iov_len: p.len(),
    }
}

#[test]
fn an_out_copies_short_vectors_and_lends_long_ones() {
    let mut short = [1u8; 10];
    let mut long = [2u8; 100];
    let mut tiny = [3u8; 5];
    let iov = [
        vec_of(&mut short),
        vec_of(&mut tiny),
        vec_of(&mut long),
        vec_of(&mut tiny),
    ];
    let mut out = Box::new(Out::new());
    // SAFETY: the vectors point to the arrays above.
    assert!(unsafe { out.fill(&iov, 50, None) });
    assert_eq!(out.nseg, 3);
    assert_eq!(out.segs[0].iov_len, 15);
    assert_eq!(out.segs[0].iov_base, out.data.as_mut_ptr().cast());
    assert_eq!(out.segs[1].iov_base, long.as_mut_ptr().cast());
    assert!(out.lent);
    assert_eq!(out.bytes(), 120);
    out.drop_data(None);
}

#[test]
fn an_out_with_too_many_lent_vectors_copies_them_all() {
    // An out has at most 16 segments.
    let maxseg = 16;
    let mut big = [7u8; 64];
    let iov: Vec<_> = (0..maxseg).map(|_| vec_of(&mut big)).collect();
    let mut o = Box::new(Out::new());
    // SAFETY: the vectors point to `big`.
    assert!(unsafe { o.fill(&iov, 1, None) });
    assert_eq!(o.nseg, 1);
    assert!(!o.lent);
    assert!(o.heap.is_some());
    assert_eq!(o.bytes(), 64 * maxseg);
}

#[test]
fn a_timeout_completes_on_the_ring() {
    let mut r = Ring::new(8, 16).unwrap();
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000,
    };
    let s = Sqe {
        opcode: Sqe::OP_TIMEOUT,
        fd: -1,
        addr: (&raw const ts) as u64,
        len: 1,
        user_data: 77,
        ..Sqe::ZERO
    };
    // SAFETY: `ts` lives until the completion below.
    assert!(unsafe { r.push(s) });
    assert_eq!(r.submit_and_wait(1), 1);
    let head = r.cq_head();
    assert!(r.cq_ready());
    // SAFETY: the completion is between the head and the tail.
    let c = unsafe { r.cqe(head) };
    assert_eq!(c.user_data, 77);
    assert_eq!(c.res, -libc::ETIME);
    r.cq_set_head(head + 1);
    assert!(!r.cq_ready());
}

#[test]
fn a_cpu_list_has_ranges_and_single_cpus() {
    let mut s = CpuSet::default();
    assert!(cpu_list("5,33\n", &mut s));
    assert!(s.is_set(5) && s.is_set(33) && !s.is_set(6));
    assert!(cpu_list("0-2,28-29", &mut s));
    assert!(s.is_set(1) && s.is_set(29) && !s.is_set(3));
    assert!(!cpu_list("", &mut s));
}

#[test]
fn a_reactor_changes_state_only_past_a_bound() {
    assert!(next_busy(false, 51, 100));
    assert!(!next_busy(true, 19, 100));
    assert!(!next_busy(false, 40, 100));
    assert!(next_busy(true, 40, 100));
}

#[test]
fn a_null_buf_is_not_open() {
    // SAFETY: tn_smbros_buf_open checks for NULL before it reads.
    assert!(!unsafe { tn_smbros_buf_open(std::ptr::null()) });
}
