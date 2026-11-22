// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! A rosbench server on the `truenas_smbros` reactors, as rosbench-server
//! `--mode per-conn --work none --reply direct`.
//!
//! A frame is a BE32 length and a payload. A request payload has the
//! operation (0 work, 1 stop), the reply size (BE32) and the request number
//! (BE32). A reply payload has a status byte (0) and zeros.

#![allow(unsafe_code)]

use std::ffi::c_int;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::process::exit;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use truenas_smbros::{
    Block, Config, Handler, Msg, Out, Reactor, ReactorCell, Shared, lock, run,
    sys,
};

const REQUEST_MIN: u32 = 9;
const PAYLOAD_MAX: u32 = 1 << 20;
const OP_STOP: u8 = 1;
const MAX_THREADS: usize = 64;

/// The eventfd that stops the server.
static STOP_EFD: AtomicI32 = AtomicI32::new(-1);

#[derive(Debug)]
struct Bench;

/// The requests that the reactor served.
#[derive(Debug, Default)]
struct Served(u64);

type R = Reactor<Served>;

impl Bench {
    #[cold]
    #[inline(never)]
    fn refuse(r: &mut R, b: Option<Block>, err: c_int) {
        if let Some(b) = b {
            r.blocks.put(b);
        }
        r.release();
        r.end::<Bench>(err);
    }
}

impl Handler for Bench {
    type State = Served;
    const NBT: bool = false;

    fn on_pdu(cell: &ReactorCell<Served>, b: Block, len: u32) {
        // SAFETY: no borrow is live, and this hook does not re-enter.
        let mut r = unsafe { cell.borrow() };
        if len < REQUEST_MIN {
            return Bench::refuse(&mut r, Some(b), libc::EIO);
        }
        let mut head = [0u8; 5];
        // SAFETY: the kernel wrote the header and `len` (9 or more) bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                b.data().add(4),
                head.as_mut_ptr(),
                5,
            );
        }
        let size = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        if head[0] == OP_STOP {
            r.blocks.put(b);
            r.release();
            sys::poke(STOP_EFD.load(Ordering::Relaxed));
            return;
        }
        if size == 0 || size > PAYLOAD_MAX {
            return Bench::refuse(&mut r, Some(b), libc::EIO);
        }
        r.h.0 += 1;
        let total = 4 + size as usize;
        // The reply reuses the block of the request when it fits.
        let rb = if total <= b.cap() as usize {
            b
        } else {
            r.blocks.put(b);
            match r.blocks.get(total) {
                Some(nb) => nb,
                None => return Bench::refuse(&mut r, None, libc::ENOMEM),
            }
        };
        // SAFETY: the block has `total` bytes, and the kernel is done with it.
        unsafe {
            rb.data().cast::<[u8; 4]>().write(size.to_be_bytes());
            rb.data().add(4).write_bytes(0, size as usize);
        }
        let Some(mut o) = r.new_out() else {
            r.blocks.put(rb);
            return Bench::refuse(&mut r, None, libc::ENOMEM);
        };
        o.set_block(rb, total);
        r.queue::<Bench>(o);
        r.release();
    }

    fn on_msg(_r: &mut R, _m: NonNull<Msg>) {}
    fn drop_msg(_r: &mut R, _m: NonNull<Msg>) {}
    fn finish_out(_r: &mut R, _o: &mut Out) -> bool {
        true
    }
    fn release_out(r: &mut R, o: Box<Out>) {
        r.free_out(o);
    }
    fn on_closed(_r: &mut R, _err: c_int) {}
    fn on_batch(_r: &mut R) {}
    fn pending(_r: &R) -> bool {
        false
    }
    fn on_cqe(_r: &mut R, _ud: u64, _res: i32) {}
    fn on_stop(_r: &mut R) {}
    fn on_end(_r: &mut R) {}
}

/// What a reactor thread waits for.
#[derive(Debug, Default)]
struct Wait {
    sock: Option<OwnedFd>,
    quit: bool,
    busy: bool,
    /// The reactor that serves a connection now, for the stop.
    sh: Option<Arc<Shared>>,
}

/// One reactor thread and the socket it waits for.
#[derive(Debug)]
struct Slot {
    name: String,
    cpu: Option<usize>,
    tid: AtomicI32,
    served: AtomicU64,
    cpu_ns: AtomicU64,
    wait: Mutex<Wait>,
    cond: Condvar,
}

fn serve(slot: &Slot, sock: OwnedFd) {
    let Ok(sh) = Shared::new() else {
        return;
    };
    let sh = Arc::new(sh);
    let cfg = Config {
        zc_min: 64 * 1024,
        ..Config::default()
    };
    // SAFETY: `sh` outlives the reactor.
    let made =
        unsafe { Reactor::new(NonNull::from(&*sh), cfg, sock, Served(0)) };
    let Ok(r) = made else {
        return;
    };
    let cell = ReactorCell::new(r);
    let quit = {
        let mut w = lock(&slot.wait);
        w.sh = Some(Arc::clone(&sh));
        w.quit
    };
    if quit {
        sh.request_stop();
    }
    run::<Bench>(&cell);
    lock(&slot.wait).sh = None;
    let served = cell.into_inner().h.0;
    slot.served.fetch_add(served, Ordering::Relaxed);
}

fn pin(cpu: usize) {
    // SAFETY: cpu_set_t is plain data that these calls write and read.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(
            0,
            size_of::<libc::cpu_set_t>(),
            &raw const set,
        );
    }
}

fn reactor_thread(slot: &Slot) {
    sys::block_signals();
    slot.tid.store(sys::gettid(), Ordering::Release);
    if let Some(cpu) = slot.cpu {
        pin(cpu);
    }
    loop {
        let (sock, quit) = {
            let mut w = lock(&slot.wait);
            while w.sock.is_none() && !w.quit {
                w = slot
                    .cond
                    .wait(w)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            (w.sock.take(), w.quit)
        };
        if quit {
            break;
        }
        if let Some(sock) = sock {
            serve(slot, sock);
        }
        lock(&slot.wait).busy = false;
    }
    slot.cpu_ns.store(sys::thread_cpu_ns(), Ordering::Relaxed);
}

/// The reactor threads and their join handles.
#[derive(Debug, Default)]
struct Slots {
    list: Vec<(Arc<Slot>, Option<JoinHandle<()>>)>,
    cpus: Vec<usize>,
}

/// Start a new reactor thread.
fn spawn_slot(slots: &mut Slots) -> Option<Arc<Slot>> {
    let n = slots.list.len();
    if n == MAX_THREADS {
        return None;
    }
    let cpu =
        (!slots.cpus.is_empty()).then(|| slots.cpus[n % slots.cpus.len()]);
    let slot = Arc::new(Slot {
        name: format!("rb-reactor-{n}"),
        cpu,
        tid: AtomicI32::new(0),
        served: AtomicU64::new(0),
        cpu_ns: AtomicU64::new(0),
        wait: Mutex::new(Wait::default()),
        cond: Condvar::new(),
    });
    let s = Arc::clone(&slot);
    let handle = thread::Builder::new()
        .name(slot.name.clone())
        .stack_size(8 << 20)
        .spawn(move || reactor_thread(&s))
        .ok()?;
    slots.list.push((Arc::clone(&slot), Some(handle)));
    Some(slot)
}

/// A slot that waits for a socket, marked busy.
fn free_slot(slots: &Mutex<Slots>) -> Option<Arc<Slot>> {
    let mut all = lock(slots);
    for (s, _) in &all.list {
        let mut w = lock(&s.wait);
        if !w.busy && w.sock.is_none() {
            w.busy = true;
            return Some(Arc::clone(s));
        }
    }
    let s = spawn_slot(&mut all)?;
    lock(&s.wait).busy = true;
    Some(s)
}

fn accept_loop(l: &TcpListener, slots: &Mutex<Slots>) {
    loop {
        // accept() retries EINTR. Another error ends the acceptor.
        let Ok((stream, _)) = l.accept() else {
            return;
        };
        // Samba sets TCP_NODELAY on its sockets.
        let _ = stream.set_nodelay(true);
        // SAFETY: the stream gives up its descriptor here.
        let sock = unsafe { OwnedFd::from_raw_fd(stream.into_raw_fd()) };
        let Some(s) = free_slot(slots) else {
            continue;
        };
        lock(&s.wait).sock = Some(sock);
        s.cond.notify_all();
    }
}

/// Parse a CPU list such as "1,3-5".
fn parse_cpus(arg: &str) -> Option<Vec<usize>> {
    let mut v = Vec::new();
    for part in arg.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                v.extend(a.parse::<usize>().ok()?..=b.parse().ok()?);
            }
            None => v.push(part.parse().ok()?),
        }
    }
    (v.len() <= 256).then_some(v)
}

fn usage(msg: &str) -> ! {
    println!(
        "lbench: {msg}\nusage: lbench [--mode per-conn] [--work none] \
         [--reply direct|push]\n              [--port N] [--cpus LIST] \
         [--reactors N]"
    );
    exit(2);
}

/// The options of the command line.
#[derive(Debug)]
struct Opts {
    port: u16,
    reactors: usize,
    reply: String,
    cpus: Vec<usize>,
}

fn parse_args() -> Opts {
    let mut o = Opts {
        port: 18600,
        reactors: 4,
        reply: "direct".into(),
        cpus: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let Some(val) = args.next() else {
            usage("an option needs a value");
        };
        match flag.as_str() {
            "--mode" if val != "per-conn" => usage("only --mode per-conn"),
            "--work" if val != "none" => usage("only --work none"),
            "--mode" | "--work" | "--pool" | "--dir" | "--files" => {}
            "--reply" if val == "direct" || val == "push" => o.reply = val,
            "--reply" => usage("bad --reply"),
            "--port" => {
                o.port = val
                    .parse()
                    .ok()
                    .filter(|&p| p != 0)
                    .unwrap_or_else(|| usage("bad --port"));
            }
            "--cpus" => {
                o.cpus =
                    parse_cpus(&val).unwrap_or_else(|| usage("bad --cpus"));
            }
            "--reactors" => {
                o.reactors =
                    val.parse().unwrap_or_else(|_| usage("bad --reactors"));
            }
            _ => usage("unknown option"),
        }
    }
    o
}

/// Nanoseconds as seconds, for the report.
#[allow(clippy::cast_precision_loss)]
fn secs(ns: u64) -> f64 {
    ns as f64 / 1e9
}

/// The user and system CPU time of the process in seconds.
#[allow(clippy::cast_precision_loss)]
fn process_cpu() -> (f64, f64) {
    // SAFETY: getrusage writes one rusage into `ru`.
    let ru = unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &raw mut ru);
        ru
    };
    let s = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    (s(ru.ru_utime), s(ru.ru_stime))
}

fn main() {
    let o = parse_args();
    sys::block_signals();
    let Ok(efd) = sys::eventfd(0) else {
        println!("lbench: no eventfd");
        exit(1);
    };
    STOP_EFD.store(efd, Ordering::Relaxed);
    let Ok(l) =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, o.port))
    else {
        println!("lbench: cannot listen on port {}", o.port);
        exit(1);
    };
    println!(
        "server pid={} mode=per-conn work=none reply={} port={} files=0 dir=-",
        std::process::id(),
        o.reply,
        o.port
    );
    let slots = Arc::new(Mutex::new(Slots {
        list: Vec::new(),
        cpus: o.cpus,
    }));
    {
        let mut all = lock(&slots);
        for _ in 0..o.reactors {
            spawn_slot(&mut all);
        }
    }
    let started: Vec<Arc<Slot>> = lock(&slots)
        .list
        .iter()
        .map(|(s, _)| Arc::clone(s))
        .collect();
    // Wait until the threads report their ids.
    for s in &started {
        while s.tid.load(Ordering::Acquire) == 0 {
            thread::sleep(std::time::Duration::from_millis(1));
        }
        let cpu = s.cpu.map_or("-".to_string(), |c| c.to_string());
        println!(
            "server thread {} tid={} cpu={cpu}",
            s.name,
            s.tid.load(Ordering::Relaxed)
        );
    }
    let acc = Arc::clone(&slots);
    let spawned = thread::Builder::new()
        .name("rb-accept".into())
        .spawn(move || accept_loop(&l, &acc));
    if spawned.is_err() {
        exit(1);
    }
    println!("server ready");
    let _ = std::io::stdout().flush();
    while !sys::drain_eventfd(efd) && sys::errno() == libc::EINTR {}
    // Stop every reactor thread and wait for each.
    let mut all: Vec<_> = std::mem::take(&mut lock(&slots).list);
    for (s, _) in &all {
        let mut w = lock(&s.wait);
        w.quit = true;
        if let Some(sh) = &w.sh {
            sh.request_stop();
        }
        drop(w);
        s.cond.notify_all();
    }
    let mut served = 0;
    for (s, h) in &mut all {
        if let Some(h) = h.take() {
            let _ = h.join();
        }
        served += s.served.load(Ordering::Relaxed);
    }
    let (user, sys_s) = process_cpu();
    println!(
        "server done requests={served} cpu_user_s={user:.3} cpu_sys_s={sys_s:.3}"
    );
    for (s, _) in &all {
        println!(
            "server thread {} tid={} requests={} cpu_s={:.3}",
            s.name,
            s.tid.load(Ordering::Relaxed),
            s.served.load(Ordering::Relaxed),
            secs(s.cpu_ns.load(Ordering::Relaxed))
        );
    }
    let _ = std::io::stdout().flush();
}
