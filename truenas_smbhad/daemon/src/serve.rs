// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The I/O of the primary role.
//!
//! One `truenas_ros` server listens on `smbd.sock` and on the internal TCP
//! address. If the TCP port is not free, the server listens on `smbd.sock`
//! only: smbd can restore from the copy without a standby. A thread tries
//! the port again and starts the role again when the port is free. A worker
//! thread writes the epoch file for the core. A ticker
//! thread sends the timer ticks for heartbeats and the link timeout. The
//! core (`primary`) runs on the server thread. The handlers share the core
//! through an `Rc` without a lock.

use crate::auth::LinkKey;
use crate::config::Config;
use crate::daemon::{Copy, Interrupt, Reason, THREAD_STACK};
use crate::epoch::{Bumped, EpochError, EpochFile};
use crate::ids;
use crate::primary::{AdvanceError, Effect, Primary, Settings, Waiter};
use crate::proto::local::{Client, Failure, Hello, Origin, Reply, Request};
use crate::proto::repl::ReplRequest;
use crate::proto::{
    BootId, MAX_FRAME, MAX_RECORD_BYTES, Node, Owner, SyncLevel, VERSION,
    encode,
};
use crate::role;
use crate::store::{Header, Store};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use truenas_ros::log::{Level, Logger};
use truenas_ros::net::server::{
    ClientAddr, ControlHandle, Deferred, Endian, Incoming, PrefixWidth,
    Protocol, PushHandle, Request as SrvRequest, Responder, Response, Server,
    ServerAddr, ServerConfig, length_prefix_header,
};

impl Waiter for Deferred {
    fn reply(self, bytes: Vec<u8>) {
        Deferred::reply(self, bytes);
    }

    fn close(self) {
        Deferred::close(self);
    }
}

/// The state of a connection.
enum Conn {
    /// A connection from an smbd process. `id` identifies it in the core.
    /// `hello` is `None` until the process sends its `Hello`.
    Local { id: u64, hello: Option<Hello> },
    /// A replication connection from the peer address. `id` identifies it
    /// in the core.
    Repl { id: u64 },
}

/// Messages from the ticker and the epoch worker to the server thread.
enum Msg {
    Tick,
    Bumped(Result<Bumped, String>),
    Advanced(u64, Result<(), AdvanceError>),
    Read(u64, Result<u64, String>),
}

/// Epoch file writes for the worker thread.
enum Job {
    Bump(u64),
    Advance(u64, u64),
    Read(u64),
}

type Core = Rc<RefCell<Primary<Deferred>>>;
type Pushes = Rc<RefCell<HashMap<u64, PushHandle>>>;

/// The local connections after their hello, by connection id.
#[derive(Default)]
struct Locals {
    /// The process of each connection, and its start time.
    owners: HashMap<u64, (Owner, Option<u64>)>,
    /// The connections of processes that exited. cleanupd reported them.
    /// Their submits can arrive after the `ForgetOwner`. The daemon drops
    /// such submits.
    gone: HashSet<u64>,
}

type LocalsRc = Rc<RefCell<Locals>>;

fn dispatch(
    core: &mut Primary<Deferred>,
    pushes: &Pushes,
    jobs: &mpsc::Sender<Job>,
    interrupt: &Interrupt,
) {
    for effect in core.take_effects() {
        match effect {
            Effect::Restart => interrupt.raise(Reason::Restart),
            Effect::Read { writes } => {
                let _ = jobs.send(Job::Read(writes));
            }
            Effect::Bump { floor } => {
                let _ = jobs.send(Job::Bump(floor));
            }
            Effect::Advance { tag, from } => {
                let _ = jobs.send(Job::Advance(tag, from));
            }
            Effect::Close { conn } => {
                if let Some(p) = pushes.borrow_mut().remove(&conn) {
                    p.close();
                }
            }
        }
    }
}

fn reply<T: serde::Serialize>(v: &T) -> Response {
    match encode(v) {
        Some(bytes) => Response::Reply(bytes),
        None => Response::Close,
    }
}

fn refuse(code: i32, message: &str) -> Response {
    reply(&Reply::Error(Failure {
        code,
        message: message.to_owned(),
    }))
}

/// Returns the copy to serve and the origin that a rehydration reports.
/// `file_epoch` is the epoch in the epoch file before this primary fences.
/// The copy of an earlier primary of this process stays only if no other
/// writer changed the epoch file since. A replica is never `Origin::Own`:
/// another controller had the pool after this controller wrote it.
fn classify(
    copy: Copy,
    file_epoch: u64,
    node: Node,
    boot: BootId,
    log: &Logger,
) -> (Store, Header, Origin) {
    let empty = || (Store::default(), Header::empty(node, boot), Origin::None);
    match copy {
        Copy::Empty => empty(),
        Copy::Own {
            store,
            header,
            origin,
            epoch,
        } => {
            if epoch == file_epoch {
                (store, header, origin)
            } else {
                truenas_ros::log!(
                    log,
                    Level::Warning,
                    "the epoch file moved from {epoch} to {file_epoch}; \
                     dropping {} records",
                    store.len()
                );
                empty()
            }
        }
        Copy::Replica { store, header } => {
            if header.tag != 0 && header.tag == file_epoch {
                truenas_ros::log!(
                    log,
                    Level::Notice,
                    "replica of {} records at tag {} matches the epoch file",
                    store.len(),
                    header.tag
                );
                (store, header, Origin::Replica)
            } else {
                truenas_ros::log!(
                    log,
                    Level::Warning,
                    "replica at tag {} does not match epoch {file_epoch}; \
                     dropping {} records",
                    header.tag,
                    store.len()
                );
                empty()
            }
        }
    }
}

/// The identity of this daemon.
#[derive(Debug)]
pub struct Identity {
    /// This controller.
    pub node: Node,
    /// The boot id of this controller.
    pub boot: BootId,
}

/// Runs the primary role until `interrupt` is raised. Returns the copy.
pub fn run(
    cfg: &Config,
    copy: Copy,
    me: &Identity,
    key: Option<LinkKey>,
    interrupt: &Arc<Interrupt>,
    log: &Logger,
) -> Copy {
    let ef = EpochFile::new(&cfg.epoch_file);
    let file_epoch = loop {
        match ef.read() {
            Ok(e) => break e,
            Err(e) => {
                truenas_ros::log!(
                    log,
                    Level::Warning,
                    "reading the epoch file: {e}"
                );
                if interrupt.wait(Duration::from_secs(1)) {
                    return copy;
                }
            }
        }
    };
    let (store, header, origin) =
        classify(copy, file_epoch, me.node, me.boot, log);
    let epoch = loop {
        match ef.bump(file_epoch.max(header.tag)) {
            Ok(b) => break b.epoch,
            Err(e) => {
                truenas_ros::log!(log, Level::Warning, "fencing at start: {e}");
                if interrupt.wait(Duration::from_secs(1)) {
                    return Copy::Own {
                        store,
                        header,
                        origin,
                        epoch: file_epoch,
                    };
                }
            }
        }
    };
    truenas_ros::log!(
        log,
        Level::Notice,
        "primary: epoch {epoch}, {} records to rehydrate ({origin:?})",
        store.len()
    );

    let link = match (&key, role::addresses(cfg)) {
        (Some(_), Ok((local, peer))) => Some((local, peer)),
        (None, _) => {
            truenas_ros::log!(
                log,
                Level::Warning,
                "no link key: serving smbd unprotected"
            );
            None
        }
        (_, Err(e)) => {
            truenas_ros::log!(log, Level::Warning, "no link to a standby: {e}");
            None
        }
    };
    let settings = Settings {
        heartbeat: cfg.heartbeat,
        link_timeout: cfg.link_timeout,
        max_lag_bytes: cfg.max_lag_bytes,
        chunk_bytes: cfg.snapshot_chunk_bytes,
        max_record_bytes: MAX_RECORD_BYTES,
        epoch_file: cfg.epoch_file.display().to_string(),
        node: me.node,
        boot: me.boot,
        instance: ids::random_u64(),
        random: crate::ids::random_fill,
    };
    let core: Core = Rc::new(RefCell::new(Primary::new(
        settings,
        key,
        store,
        header,
        origin,
        epoch,
        log.clone(),
    )));

    match serve(cfg, &core, link, interrupt, log) {
        Ok(()) => {}
        Err(e) => {
            truenas_ros::log!(log, Level::Warning, "primary stopped: {e}");
            interrupt.wait(Duration::from_secs(1));
        }
    }
    let core = match Rc::try_unwrap(core) {
        Ok(cell) => cell.into_inner(),
        Err(_) => unreachable!("the server and its handlers are gone"),
    };
    if core.discarded() {
        return Copy::Empty;
    }
    let epoch = core.epoch();
    let (store, header, origin) = core.into_copy();
    Copy::Own {
        store,
        header,
        origin,
        epoch,
    }
}

fn socket_dir(cfg: &Config) -> Result<(), String> {
    std::fs::create_dir_all(&cfg.socket_dir)
        .and_then(|()| {
            std::fs::set_permissions(
                &cfg.socket_dir,
                std::fs::Permissions::from_mode(0o700),
            )
        })
        .map_err(|e| format!("{}: {e}", cfg.socket_dir.display()))
}

#[allow(clippy::too_many_lines)]
fn serve(
    cfg: &Config,
    core: &Core,
    link: Option<(Ipv4Addr, Ipv4Addr)>,
    interrupt: &Arc<Interrupt>,
    log: &Logger,
) -> Result<(), String> {
    socket_dir(cfg)?;
    let mut addrs = vec![ServerAddr::Unix(cfg.smbd_socket())];
    let mut link = link;
    let mut link_down = None;
    if let Some((local, _)) = link {
        let addr = SocketAddrV4::new(local, cfg.port);
        // A failed bind of the server would also stop smbd.sock. After a
        // daemon restart, the kernel can hold the old listener for a short
        // time: the teardown of the old io_uring ring is asynchronous.
        let mut tries = 0;
        loop {
            match TcpListener::bind(addr) {
                Ok(probe) => {
                    drop(probe);
                    addrs.push(ServerAddr::Tcp(addr));
                    break;
                }
                Err(_) if tries < LINK_BIND_TRIES => {
                    tries += 1;
                    if interrupt.wait(LINK_BIND_WAIT) {
                        return Ok(());
                    }
                }
                Err(e) => {
                    truenas_ros::log!(
                        log,
                        Level::Warning,
                        "link port {addr}: {e}; serving smbd without a \
                         standby"
                    );
                    link = None;
                    link_down = Some(addr);
                    break;
                }
            }
        }
    }
    let peer = link.map(|(_, p)| p);
    let pushes: Pushes = Rc::new(RefCell::new(HashMap::new()));
    let locals: LocalsRc = Rc::new(RefCell::new(Locals::default()));
    let (jobs_tx, jobs_rx) = mpsc::channel::<Job>();
    let next_id = Rc::new(Cell::new(0u64));
    let allowed_uid = cfg.allowed_uid;

    let accept = {
        let log = log.clone();
        let core = Rc::clone(core);
        let pushes = Rc::clone(&pushes);
        let jobs = jobs_tx.clone();
        let interrupt = Arc::clone(interrupt);
        let next_id = Rc::clone(&next_id);
        move |inc: Incoming<'_>| -> Option<Conn> {
            match inc.peer {
                ClientAddr::Unix { cred: Some(c) } if c.uid == allowed_uid => {
                    let id = next_id.get() + 1;
                    next_id.set(id);
                    Some(Conn::Local { id, hello: None })
                }
                ClientAddr::Unix { cred } => {
                    truenas_ros::log!(
                        log,
                        Level::Warning,
                        "refused local peer {cred:?}"
                    );
                    None
                }
                ClientAddr::Inet(sa) => {
                    if peer.is_some_and(|p| sa.ip() == IpAddr::V4(p)) {
                        let id = next_id.get() + 1;
                        next_id.set(id);
                        let mut c = core.borrow_mut();
                        c.repl_connect(id, Instant::now());
                        dispatch(&mut c, &pushes, &jobs, &interrupt);
                        Some(Conn::Repl { id })
                    } else {
                        truenas_ros::log!(
                            log,
                            Level::Warning,
                            "refused {sa}: not the peer"
                        );
                        None
                    }
                }
            }
        }
    };
    let body = {
        let log = log.clone();
        let core = Rc::clone(core);
        let pushes = Rc::clone(&pushes);
        let jobs = jobs_tx.clone();
        let interrupt = Arc::clone(interrupt);
        let locals = Rc::clone(&locals);
        move |req: SrvRequest<'_, Conn>| -> Response {
            let SrvRequest {
                body,
                state,
                responder,
                ..
            } = req;
            let now = Instant::now();
            match state {
                Conn::Local { id, hello } => local(
                    &core, &pushes, &jobs, &interrupt, &locals, *id, hello,
                    &body, responder, now, &log,
                ),
                Conn::Repl { id } => {
                    let request: ReplRequest =
                        match truenas_xdr::from_bytes(&body) {
                            Ok(r) => r,
                            Err(e) => {
                                truenas_ros::log!(
                                    log,
                                    Level::Warning,
                                    "standby sent garbage: {e}"
                                );
                                return Response::Close;
                            }
                        };
                    let id = *id;
                    pushes
                        .borrow_mut()
                        .entry(id)
                        .or_insert_with(|| responder.push_handle());
                    let (deferred, permit) = responder.defer();
                    let mut c = core.borrow_mut();
                    c.repl_request(id, request, deferred, now);
                    dispatch(&mut c, &pushes, &jobs, &interrupt);
                    Response::Defer(permit)
                }
            }
        }
    };
    let protocol = Protocol {
        accept,
        header: length_prefix_header::<Conn>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let scfg = ServerConfig {
        pool_size: cfg.pool_size,
        max_request_bytes: MAX_FRAME + 4,
        unix_peercred: true,
        unlink_unix: true,
        backlog: cfg.backlog,
        ..ServerConfig::default()
    };
    let mut server = Server::with_config(addrs, scfg, protocol)
        .map_err(|e| format!("server: {e}"))?;

    {
        let core = Rc::clone(core);
        let pushes = Rc::clone(&pushes);
        let jobs = jobs_tx.clone();
        let interrupt = Arc::clone(interrupt);
        let locals = Rc::clone(&locals);
        server.set_close_hook(move |_peer, _reason, state: &mut Conn| {
            let mut c = core.borrow_mut();
            match state {
                Conn::Repl { id } => {
                    pushes.borrow_mut().remove(id);
                    c.repl_closed(*id);
                }
                Conn::Local { id, .. } => {
                    let mut l = locals.borrow_mut();
                    l.owners.remove(id);
                    l.gone.remove(id);
                    c.local_closed(*id);
                }
            }
            dispatch(&mut c, &pushes, &jobs, &interrupt);
        });
    }
    {
        let core = Rc::clone(core);
        let pushes = Rc::clone(&pushes);
        let jobs = jobs_tx.clone();
        let interrupt = Arc::clone(interrupt);
        server.set_control_hook(move |msg| {
            let Ok(msg) = msg.downcast::<Msg>() else {
                return;
            };
            let now = Instant::now();
            let mut c = core.borrow_mut();
            match *msg {
                Msg::Tick => c.tick(now),
                Msg::Bumped(r) => c.epoch_bumped(r, now),
                Msg::Advanced(tag, r) => c.epoch_advanced(tag, r),
                Msg::Read(writes, r) => c.epoch_read(writes, r),
            }
            dispatch(&mut c, &pushes, &jobs, &interrupt);
        });
    }
    drop(jobs_tx);

    let stop = Arc::new(AtomicBool::new(false));
    let ticker = {
        let control = server.control_handle();
        let stop = Arc::clone(&stop);
        let every = (cfg.heartbeat / 4).max(Duration::from_millis(5));
        thread::Builder::new()
            .name("smbhad-tick".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(every);
                    control.send(Box::new(Msg::Tick));
                }
            })
            .map_err(|e| format!("ticker: {e}"))?
    };
    let worker = {
        let control = server.control_handle();
        let ef = EpochFile::new(&cfg.epoch_file);
        thread::Builder::new()
            .name("smbhad-epoch".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || epoch_worker(&ef, &jobs_rx, &control))
            .map_err(|e| format!("epoch worker: {e}"))?
    };

    interrupt.register(server.shutdown_handle());
    let prober = link_down.and_then(|addr| {
        let stop = Arc::clone(&stop);
        let interrupt = Arc::clone(interrupt);
        let probe_log = log.clone();
        thread::Builder::new()
            .name("smbhad-link".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || link_probe(addr, &stop, &interrupt, &probe_log))
            .map_err(|e| {
                truenas_ros::log!(log, Level::Warning, "link prober: {e}");
            })
            .ok()
    });
    crate::notify::ready(log);
    let result = server.serve_forever().map_err(|e| format!("serving: {e}"));
    interrupt.unregister();
    stop.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    if let Some(p) = prober {
        let _ = p.join();
    }
    drop(server);
    let _ = worker.join();
    result
}

/// The tries of the link port at the start of a run, and the time between
/// them. After them, the primary serves smbd without the link.
const LINK_BIND_TRIES: u32 = 20;
const LINK_BIND_WAIT: Duration = Duration::from_millis(100);

/// The time between two tries of a link port that was not free.
const LINK_RETRY: Duration = Duration::from_secs(5);

/// Tries the link port every `LINK_RETRY` while the primary serves smbd
/// without the link. When the port is free, starts the role again.
fn link_probe(
    addr: SocketAddrV4,
    stop: &AtomicBool,
    interrupt: &Interrupt,
    log: &Logger,
) {
    while !interrupt.wait(LINK_RETRY) {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if TcpListener::bind(addr).is_ok() {
            truenas_ros::log!(
                log,
                Level::Notice,
                "link port {addr} is free: starting again with the link"
            );
            interrupt.raise(Reason::Link);
            return;
        }
    }
}

/// The processes of `conns` with pid `pid` that are alive: they started at
/// `current`, the start time of the process that has the pid now.
fn live(
    conns: &HashMap<u64, (Owner, Option<u64>)>,
    pid: u32,
    current: Option<u64>,
) -> Vec<Owner> {
    conns
        .values()
        .filter(|(o, start)| {
            o.pid == pid && current.is_some() && *start == current
        })
        .map(|(o, _)| *o)
        .collect()
}

/// The start time of process `pid`, in clock ticks after the boot: field 22
/// of `/proc/<pid>/stat`. `None` if no process has this pid.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 2, the command name in parentheses, can contain spaces.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn epoch_worker(
    ef: &EpochFile,
    jobs: &mpsc::Receiver<Job>,
    control: &ControlHandle,
) {
    while let Ok(job) = jobs.recv() {
        let msg = match job {
            Job::Bump(floor) => {
                Msg::Bumped(ef.bump(floor).map_err(|e| e.to_string()))
            }
            Job::Read(writes) => {
                Msg::Read(writes, ef.read().map_err(|e| e.to_string()))
            }
            Job::Advance(tag, from) => Msg::Advanced(
                tag,
                ef.advance_to(tag, from).map_err(|e| match e {
                    EpochError::Stale { current } => {
                        AdvanceError::Stale { current }
                    }
                    other => AdvanceError::Failed(other.to_string()),
                }),
            ),
        };
        control.send(Box::new(msg));
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn local(
    core: &Core,
    pushes: &Pushes,
    jobs: &mpsc::Sender<Job>,
    interrupt: &Interrupt,
    locals: &LocalsRc,
    id: u64,
    hello: &mut Option<Hello>,
    bytes: &[u8],
    responder: Responder,
    now: Instant,
    log: &Logger,
) -> Response {
    let request: Request = match truenas_xdr::from_bytes(bytes) {
        Ok(r) => r,
        Err(e) => {
            truenas_ros::log!(
                log,
                Level::Warning,
                "smbd sent an undecodable request: {e}"
            );
            return Response::Close;
        }
    };
    let mut c = core.borrow_mut();
    let response = match (hello.as_ref(), request) {
        (None, Request::Hello(h)) => {
            if h.version == VERSION {
                let ok = c.hello();
                locals
                    .borrow_mut()
                    .owners
                    .insert(id, (h.owner, start_time(h.owner.pid)));
                *hello = Some(h);
                reply(&Reply::HelloOk(ok))
            } else {
                Response::ReplyClose(
                    encode(&Reply::Error(Failure {
                        code: truenas_ros::Errno::EPROTO as i32,
                        message: format!(
                            "version {} is not {VERSION}",
                            h.version
                        ),
                    }))
                    .unwrap_or_default(),
                )
            }
        }
        (None, _) | (Some(_), Request::Hello(_)) => Response::Close,
        (Some(_), Request::Submit(_)) if locals.borrow().gone.contains(&id) => {
            truenas_ros::log!(
                log,
                Level::Warning,
                "dropped a submit of an exited process"
            );
            Response::Close
        }
        (Some(_), Request::Submit(mut sub)) => {
            let replaced = c.fit_ops(&mut sub.ops);
            if replaced != 0 {
                truenas_ros::log!(
                    log,
                    Level::Warning,
                    "{replaced} records too large to keep, deleted"
                );
            }
            c.submit(sub.ops, now);
            match sub.sync {
                SyncLevel::None => Response::Reply(Vec::new()),
                SyncLevel::Local => reply(&Reply::Synced(c.synced())),
                SyncLevel::Remote => {
                    let (deferred, permit) = responder.defer();
                    c.sync_remote(deferred);
                    Response::Defer(permit)
                }
            }
        }
        (Some(_), Request::ForgetOwner(owner)) => {
            let mut l = locals.borrow_mut();
            // cleanupd knows only the pid. The kernel can give the pid to
            // a new process before the forget arrives.
            let live = live(&l.owners, owner.pid, start_time(owner.pid));
            let gone: Vec<u64> = l
                .owners
                .iter()
                .filter(|(_, (o, _))| owner.matches(*o) && !live.contains(o))
                .map(|(&cid, _)| cid)
                .collect();
            l.gone.extend(gone);
            c.forget_owner(owner, &live, now);
            Response::Reply(Vec::new())
        }
        (Some(h), Request::Rehydrate(r)) => {
            if h.role == Client::Parent {
                reply(&Reply::RehydratePage(c.rehydrate(
                    r.cursor,
                    r.max_bytes as usize,
                    id,
                )))
            } else {
                refuse(
                    truenas_ros::Errno::EACCES as i32,
                    "only smbd's parent rehydrates",
                )
            }
        }
        (Some(h), Request::Done) => {
            if h.role == Client::Parent {
                reply(&Reply::DoneOk(c.done()))
            } else {
                refuse(
                    truenas_ros::Errno::EACCES as i32,
                    "only smbd's parent ends a rehydration",
                )
            }
        }
    };
    dispatch(&mut c, pushes, jobs, interrupt);
    response
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
    use crate::proto::{Op, Owner, Record};
    use truenas_xdr::{FixedOpaque, VarOpaque};

    const ME: Node = Node::A;
    const BOOT: BootId = FixedOpaque([2; 16]);
    const PEER: Node = Node::B;

    fn replica(tag: u64, writer: Node, boot: BootId) -> Copy {
        let mut store = Store::default();
        store.apply(Op::Put(Record {
            id: 1,
            share: "s".to_owned(),
            owner: Owner::DISCONNECTED,
            flags: 0,
            body: VarOpaque(vec![1]),
        }));
        let mut header = Header::empty(writer, boot);
        header.tag = tag;
        Copy::Replica { store, header }
    }

    #[test]
    fn a_forget_keeps_only_the_process_that_has_the_pid_now() {
        let owner = |pid, unique_id| Owner { pid, unique_id };
        let conns = HashMap::from([
            (1, (owner(7, 1), Some(100))),
            (2, (owner(7, 2), Some(200))),
            (3, (owner(8, 3), Some(200))),
            (4, (owner(7, 4), None)),
        ]);
        assert_eq!(live(&conns, 7, Some(200)), vec![owner(7, 2)]);
        assert!(live(&conns, 7, None).is_empty());
    }

    #[test]
    fn a_replica_is_restored_only_under_the_files_epoch() {
        let (s, _, origin) =
            classify(replica(5, PEER, BOOT), 5, ME, BOOT, &Logger::silent());
        assert_eq!((origin, s.len()), (Origin::Replica, 1));
        let (s, _, origin) =
            classify(replica(5, PEER, BOOT), 6, ME, BOOT, &Logger::silent());
        assert_eq!((origin, s.len()), (Origin::None, 0));
        let (s, _, origin) =
            classify(replica(0, PEER, BOOT), 0, ME, BOOT, &Logger::silent());
        assert_eq!((origin, s.len()), (Origin::None, 0), "an incomplete copy");
        // This node wrote the records in this boot, but the peer had the
        // pool after that. smbd treats it as a reboot: unflushed data is
        // lost.
        let (_, _, origin) =
            classify(replica(5, ME, BOOT), 5, ME, BOOT, &Logger::silent());
        assert_eq!(origin, Origin::Replica);
    }

    #[test]
    fn an_own_copy_stays_only_if_the_epoch_file_did_not_move() {
        let own = |epoch| {
            let Copy::Replica { store, header } = replica(0, ME, BOOT) else {
                unreachable!()
            };
            Copy::Own {
                store,
                header,
                origin: Origin::Own,
                epoch,
            }
        };
        let (s, _, origin) = classify(own(9), 9, ME, BOOT, &Logger::silent());
        assert_eq!((origin, s.len()), (Origin::Own, 1));
        // smbd fenced, or the peer was primary.
        let (s, _, origin) = classify(own(9), 10, ME, BOOT, &Logger::silent());
        assert_eq!((origin, s.len()), (Origin::None, 0));
        let (_, _, origin) =
            classify(Copy::Empty, 9, ME, BOOT, &Logger::silent());
        assert_eq!(origin, Origin::None);
    }
}
