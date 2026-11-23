// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! Where the reactors of one process run. Reactors that are not busy share
//! one home core, so a client that uses its channels in turn finds it warm.

use std::fs::File;
use std::io::Read;
use std::sync::Mutex;

use crate::lock;
use crate::sys;

/// How often a reactor checks its load.
const PERIOD_NS: u64 = 100 * sys::NS_PER_MS;
const MAX_MEMBERS: usize = 64;

/// A set of CPUs, laid out as `cpu_set_t`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CpuSet([u64; 16]);

const _: () = assert!(size_of::<CpuSet>() == size_of::<libc::cpu_set_t>());

impl CpuSet {
    fn set(&mut self, cpu: usize) {
        if cpu < 1024 {
            self.0[cpu / 64] |= 1 << (cpu % 64);
        }
    }

    pub fn is_set(&self, cpu: usize) -> bool {
        cpu < 1024 && self.0[cpu / 64] & (1 << (cpu % 64)) != 0
    }

    fn of_thread() -> CpuSet {
        let mut s = CpuSet::default();
        // SAFETY: the set has the size and layout of cpu_set_t.
        unsafe {
            libc::sched_getaffinity(
                0,
                size_of::<CpuSet>(),
                (&raw mut s).cast(),
            );
        }
        s
    }

    fn apply(&self) {
        // SAFETY: as in of_thread().
        unsafe {
            libc::sched_setaffinity(
                0,
                size_of::<CpuSet>(),
                (&raw const *self).cast(),
            );
        }
    }
}

/// Parse a CPU list such as "5,33" or "0-13,28-41" into `set`. False if it
/// has no CPU.
pub fn cpu_list(s: &str, set: &mut CpuSet) -> bool {
    *set = CpuSet::default();
    let mut any = false;
    for part in s.trim().split(',') {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
                for c in a..=b.min(1023) {
                    set.set(c);
                    any = true;
                }
            }
        } else if let Ok(c) = part.parse::<usize>() {
            set.set(c);
            any = true;
        }
    }
    any
}

fn read_small<'a>(path: &str, buf: &'a mut [u8]) -> Option<&'a str> {
    let n = File::open(path).ok()?.read(buf).ok()?;
    std::str::from_utf8(&buf[..n]).ok()
}

/// The CPU that thread `tid` of this process ran on last.
fn last_cpu(tid: libc::pid_t) -> Option<usize> {
    let mut buf = [0u8; 1024];
    let stat = read_small(&format!("/proc/self/task/{tid}/stat"), &mut buf)?;
    // Field 39 is the CPU. The fields after the name start with field 3.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(36)?
        .parse()
        .ok()
}

/// The hyperthreads of the core of `cpu`.
fn siblings(cpu: usize, set: &mut CpuSet) -> bool {
    let mut buf = [0u8; 256];
    let path = format!(
        "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
    );
    read_small(&path, &mut buf).is_some_and(|s| cpu_list(s, set))
}

/// The time the calling thread ran and waited for a CPU, in ns.
fn schedstat() -> Option<u64> {
    let mut buf = [0u8; 128];
    let s = read_small("/proc/thread-self/schedstat", &mut buf)?;
    let mut f = s.split_ascii_whitespace();
    let run: u64 = f.next()?.parse().ok()?;
    let wait: u64 = f.next()?.parse().ok()?;
    Some(run + wait)
}

#[derive(Debug)]
struct Members {
    tids: [libc::pid_t; MAX_MEMBERS],
    n: usize,
    /// The hyperthreads of the home core, set at two reactors.
    home: Option<CpuSet>,
}

/// The reactors of the process.
#[derive(Debug)]
pub(crate) struct Group(Mutex<Members>);

impl Default for Group {
    fn default() -> Self {
        Group(Mutex::new(Members {
            tids: [0; MAX_MEMBERS],
            n: 0,
            home: None,
        }))
    }
}

impl Group {
    /// Add the calling reactor. At two reactors, the home core is where the
    /// first one ran last.
    pub(crate) fn join(&self) {
        let mut g = lock(&self.0);
        if g.n < MAX_MEMBERS {
            let n = g.n;
            g.tids[n] = sys::gettid();
            g.n += 1;
        }
        if g.home.is_none() && g.n >= 2 {
            let mut home = CpuSet::default();
            if last_cpu(g.tids[0]).is_some_and(|c| siblings(c, &mut home)) {
                g.home = Some(home);
            }
        }
    }

    /// Remove the calling reactor. One reactor has no home core.
    pub(crate) fn leave(&self) {
        let tid = sys::gettid();
        let mut g = lock(&self.0);
        let n = g.n;
        if let Some(i) = g.tids[..n].iter().position(|&t| t == tid) {
            g.tids[i] = g.tids[n - 1];
            g.n -= 1;
        }
        if g.n < 2 {
            g.home = None;
        }
    }
}

/// The busy state after a reactor used a CPU for `used` of `wall` ns. Over
/// a half makes it busy and under a fifth not busy, so it does not flap.
pub fn next_busy(busy: bool, used: u64, wall: u64) -> bool {
    if used.saturating_mul(2) > wall {
        true
    } else if used.saturating_mul(5) < wall {
        false
    } else {
        busy
    }
}

/// Where one reactor runs. Only the thread of the reactor uses it.
#[derive(Debug)]
pub(crate) struct Mover {
    /// The CPU mask of the thread when it started.
    wide: CpuSet,
    /// The CPUs the thread is set to.
    applied: CpuSet,
    busy: bool,
    last: u64,
    last_ns: u64,
}

impl Mover {
    pub(crate) fn new() -> Mover {
        let wide = CpuSet::of_thread();
        Mover {
            wide,
            applied: wide,
            busy: false,
            last: sys::coarse_ns(),
            last_ns: schedstat().unwrap_or(0),
        }
    }

    /// At most once per period, move the thread to the home core while it
    /// is not busy, else to its own mask.
    #[inline]
    pub(crate) fn tick(&mut self, g: &Group) {
        let now = sys::coarse_ns();
        if now.wrapping_sub(self.last) < PERIOD_NS {
            return;
        }
        self.slow_tick(g, now);
    }

    #[cold]
    #[inline(never)]
    fn slow_tick(&mut self, g: &Group, now: u64) {
        let Some(ns) = schedstat() else {
            return;
        };
        let used = ns.saturating_sub(self.last_ns);
        let wall = now - self.last;
        self.last = now;
        self.last_ns = ns;
        self.busy = next_busy(self.busy, used, wall);
        let want = match lock(&g.0).home {
            Some(home) if !self.busy => home,
            _ => self.wide,
        };
        if want != self.applied {
            want.apply();
            self.applied = want;
        }
    }
}
