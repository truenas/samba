// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! A lab of two controllers on loopback addresses. Each controller is a
//! daemon process. Both controllers use the same epoch file, in the `pool`
//! directory of the lab. `Smbd` is the smbd side of the local protocol.
//! `Proxy` can cut the internal link.

#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{
    Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream,
};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use truenas_smbhad::proto::local::{
    Client, Hello, HelloOk, Origin, Rehydrate, RehydratePage, Reply, Request,
    Submit, Synced,
};
use truenas_smbhad::proto::{
    Op, Owner, Protection, Record, SyncLevel, VERSION,
};
use truenas_xdr::VarOpaque;

pub const A: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub const B: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
pub const PROXY: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
pub const STRANGER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);

pub const HEARTBEAT_MS: u64 = 50;
pub const LINK_TIMEOUT_MS: u64 = 300;

/// One test's directory, port, shared epoch file and secret.
pub struct Lab {
    pub dir: truenas_ros::TempDir,
    pub port: u16,
}

impl Lab {
    pub fn new() -> Lab {
        let dir = truenas_ros::tempdir().expect("temporary directory");
        std::fs::create_dir_all(dir.path().join("pool")).unwrap();
        std::fs::write(dir.path().join("secret"), b"0123456789abcdef-pwenc")
            .unwrap();
        Lab {
            dir,
            port: free_port(),
        }
    }

    pub fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    pub fn epoch_file(&self) -> PathBuf {
        self.path("pool/smbhad.epoch")
    }

    /// The epoch file's value, 0 when absent or damaged.
    pub fn epoch(&self) -> u64 {
        truenas_smbhad::epoch::EpochFile::new(&self.epoch_file())
            .read()
            .unwrap_or(0)
    }

    /// A controller: node A for `a`, node B for `b`. Its boot id contains
    /// `id`.
    pub fn node(
        &self,
        name: &str,
        id: u8,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Node {
        let root = self.path(name);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("boot_id"),
            format!("00000000-0000-0000-0000-0000000000{id:02x}\n"),
        )
        .unwrap();
        Node {
            name: name.to_owned(),
            slot: name.to_uppercase(),
            root,
            local,
            peer,
            port: self.port,
            epoch_file: self.epoch_file(),
            secret: self.path("secret"),
            role: "primary".to_owned(),
            child: None,
            extra: String::new(),
        }
    }
}

pub fn free_port() -> u16 {
    TcpListener::bind((A, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

pub struct Node {
    pub name: String,
    /// The node: A or B.
    pub slot: String,
    pub root: PathBuf,
    pub local: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub port: u16,
    pub epoch_file: PathBuf,
    pub secret: PathBuf,
    pub role: String,
    pub extra: String,
    child: Option<Child>,
}

impl Node {
    pub fn socket(&self) -> PathBuf {
        self.root.join("run/smbd.sock")
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("smbhad.conf")
    }

    fn log_path(&self) -> PathBuf {
        self.root.join("daemon.log")
    }

    fn write_config(&self) {
        let text = format!(
            "[smbhad]\nrole = {}\nlocal_address = {}\npeer_address = {}\nport = {}\n\
             socket_dir = {}\nepoch_file = {}\nsecret_file = {}\n\
             node = {}\nboot_id_file = {}\nallowed_uid = {}\n\
             heartbeat_ms = {HEARTBEAT_MS}\nlink_timeout_ms = {LINK_TIMEOUT_MS}\n\
             pool_size = 1024\nbacklog = 1024\n{}",
            self.role,
            self.local,
            self.peer,
            self.port,
            self.root.join("run").display(),
            self.epoch_file.display(),
            self.secret.display(),
            self.slot,
            self.root.join("boot_id").display(),
            my_uid(),
            self.extra,
        );
        std::fs::write(self.config_path(), text).unwrap();
    }

    pub fn start(&mut self, role: &str) {
        assert!(self.child.is_none(), "{} already running", self.name);
        role.clone_into(&mut self.role);
        self.write_config();
        let log = File::options()
            .create(true)
            .append(true)
            .open(self.log_path())
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_truenas_smbhad"))
            .env_remove("JOURNAL_STREAM")
            .arg("--config")
            .arg(self.config_path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn the daemon");
        self.child = Some(child);
        if role == "primary" {
            assert!(
                wait_for(Duration::from_secs(10), || self
                    .try_hello()
                    .is_some()),
                "{} did not come up as primary:\n{}",
                self.name,
                self.log()
            );
        }
    }

    /// Writes the configuration with `role` and sends SIGHUP.
    pub fn set_role(&mut self, role: &str) {
        role.clone_into(&mut self.role);
        self.write_config();
        self.signal("-HUP");
        if role == "primary" {
            assert!(
                wait_for(Duration::from_secs(10), || self
                    .try_hello()
                    .is_some()),
                "{} did not become primary:\n{}",
                self.name,
                self.log()
            );
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().expect("running").id()
    }

    pub fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .arg(sig)
            .arg(self.pid().to_string())
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill {sig} {}", self.name);
    }

    /// Kills the daemon with SIGKILL and removes its socket.
    pub fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_file(self.socket());
    }

    /// Sends SIGTERM and waits up to 5 s for the exit.
    pub fn stop(&mut self) {
        if self.child.is_some() {
            self.signal("-TERM");
            let mut c = self.child.take().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if c.try_wait().unwrap().is_some() {
                    break;
                }
                if Instant::now() > deadline {
                    let _ = c.kill();
                    let _ = c.wait();
                    panic!("{} ignored SIGTERM:\n{}", self.name, self.log());
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.log_path()).unwrap_or_default()
    }

    pub fn try_hello(&self) -> Option<HelloOk> {
        Smbd::connect(self, Client::Worker, 1).ok().map(|s| s.hello)
    }

    pub fn protection(&self) -> Option<Protection> {
        self.try_hello().map(|h| h.protection)
    }

    pub fn wait_protected(&self) {
        assert!(
            wait_for(Duration::from_secs(10), || {
                self.protection() == Some(Protection::Protected)
            }),
            "{} never became protected:\n{}",
            self.name,
            self.log()
        );
    }

    pub fn smbd(&self, role: Client, pid: u32) -> Smbd {
        Smbd::connect(self, role, pid).expect("connect to the daemon")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill();
        if std::env::var_os("SMBHAD_TEST_LOGS").is_some() {
            eprintln!("---- {} ----\n{}", self.name, self.log());
        }
    }
}

/// Calls `f` every 10 ms until it returns true. Returns false after `timeout`.
pub fn wait_for(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// smbd's side of the local protocol.
pub struct Smbd {
    pub stream: UnixStream,
    pub hello: HelloOk,
    pub owner: Owner,
}

impl Smbd {
    pub fn connect(node: &Node, role: Client, pid: u32) -> io::Result<Smbd> {
        let mut stream = UnixStream::connect(node.socket())?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let owner = Owner {
            pid,
            unique_id: u64::from(pid) * 1000 + 7,
        };
        send(
            &mut stream,
            &Request::Hello(Hello {
                version: VERSION,
                role,
                owner,
            }),
        )?;
        match recv(&mut stream)? {
            Reply::HelloOk(hello) => Ok(Smbd {
                stream,
                hello,
                owner,
            }),
            other => Err(io::Error::other(format!("hello answered {other:?}"))),
        }
    }

    pub fn request(&mut self, req: &Request) -> Reply {
        send(&mut self.stream, req).expect("send");
        recv(&mut self.stream).expect("reply")
    }

    /// Returns `None` for `SyncLevel::None`, which gets no reply.
    pub fn submit(&mut self, ops: Vec<Op>, sync: SyncLevel) -> Option<Synced> {
        let req = Request::Submit(Submit { sync, ops });
        if sync == SyncLevel::None {
            send(&mut self.stream, &req).expect("send");
            return None;
        }
        match self.request(&req) {
            Reply::Synced(s) => Some(s),
            other => panic!("submit answered {other:?}"),
        }
    }

    pub fn put(
        &mut self,
        records: Vec<Record>,
        sync: SyncLevel,
    ) -> Option<Synced> {
        self.submit(records.into_iter().map(Op::Put).collect(), sync)
    }

    pub fn forget(&mut self, owner: Owner) {
        send(&mut self.stream, &Request::ForgetOwner(owner)).expect("send");
    }

    /// Rehydrates the whole copy in pages of at most `max_bytes`. Returns
    /// the first page and all records.
    pub fn rehydrate_all(
        &mut self,
        max_bytes: u32,
    ) -> (RehydratePage, Vec<Record>) {
        let mut cursor = 0;
        let mut records = Vec::new();
        let mut first = None;
        loop {
            match self
                .request(&Request::Rehydrate(Rehydrate { cursor, max_bytes }))
            {
                Reply::RehydratePage(page) => {
                    records.extend(page.records.iter().cloned());
                    let last = page.last;
                    cursor = page.next_cursor;
                    if first.is_none() {
                        first = Some(page);
                    }
                    if last {
                        return (first.unwrap(), records);
                    }
                }
                other => panic!("rehydrate answered {other:?}"),
            }
        }
    }

    pub fn done(&mut self) -> u64 {
        match self.request(&Request::Done) {
            Reply::DoneOk(g) => g,
            other => panic!("done answered {other:?}"),
        }
    }

    /// Returns when the daemon has applied everything sent before.
    pub fn barrier(&mut self) {
        self.submit(Vec::new(), SyncLevel::Local).expect("synced");
    }
}

pub fn send(stream: &mut UnixStream, req: &Request) -> io::Result<()> {
    let body = truenas_xdr::to_bytes(req).map_err(io::Error::other)?;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    stream.write_all(&frame)
}

pub fn recv(stream: &mut UnixStream) -> io::Result<Reply> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body)?;
    truenas_xdr::from_bytes(&body).map_err(io::Error::other)
}

pub fn record(id: u64, owner: Owner, size: usize) -> Record {
    Record {
        id,
        share: "data".to_owned(),
        owner,
        flags: (id % 7) as u32,
        body: VarOpaque((0..size).map(|i| (id as usize + i) as u8).collect()),
    }
}

pub fn sorted(mut records: Vec<Record>) -> Vec<Record> {
    records.sort_by_key(|r| r.id);
    records
}

/// Forwards connections from `listen` to `target`. `cut` closes every
/// connection and refuses new ones until `restore`.
pub struct Proxy {
    cut: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    pub fn new(listen: SocketAddrV4, target: SocketAddrV4) -> Proxy {
        let listener = TcpListener::bind(listen).expect("proxy listen");
        let cut = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<Vec<TcpStream>>> =
            Arc::new(Mutex::new(Vec::new()));
        {
            let cut = Arc::clone(&cut);
            let conns = Arc::clone(&conns);
            thread::spawn(move || {
                for inbound in listener.incoming() {
                    let Ok(inbound) = inbound else { continue };
                    if cut.load(Ordering::SeqCst) {
                        let _ = inbound.shutdown(Shutdown::Both);
                        continue;
                    }
                    let Ok(outbound) =
                        TcpStream::connect(SocketAddr::V4(target))
                    else {
                        let _ = inbound.shutdown(Shutdown::Both);
                        continue;
                    };
                    let _ = inbound.set_nodelay(true);
                    let _ = outbound.set_nodelay(true);
                    {
                        let mut c = conns.lock().unwrap();
                        c.push(inbound.try_clone().unwrap());
                        c.push(outbound.try_clone().unwrap());
                    }
                    pipe(
                        inbound.try_clone().unwrap(),
                        outbound.try_clone().unwrap(),
                    );
                    pipe(outbound, inbound);
                }
            });
        }
        Proxy { cut, conns }
    }

    pub fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
        for c in self.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(Shutdown::Both);
        }
    }

    pub fn restore(&self) {
        self.cut.store(false, Ordering::SeqCst);
    }
}

fn pipe(mut from: TcpStream, mut to: TcpStream) {
    thread::spawn(move || {
        let _ = io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Both);
        let _ = from.shutdown(Shutdown::Both);
    });
}

pub fn path_exists(p: &Path) -> bool {
    p.exists()
}

/// The pid of a process that exited.
pub fn dead_pid() -> u32 {
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().expect("wait for true");
    pid
}

pub fn owner(pid: u32) -> Owner {
    Owner {
        pid,
        unique_id: u64::from(pid) * 1000 + 7,
    }
}

pub fn origin_of(page: &RehydratePage) -> Origin {
    page.origin
}
