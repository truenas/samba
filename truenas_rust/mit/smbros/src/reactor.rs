// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The thread of one connection. It runs a `truenas_ros` server that has
//! no listeners and adopts the socket. The server stops when the
//! connection closes or when the owner stops it.

use std::cell::RefCell;
use std::ffi::c_int;
use std::os::fd::OwnedFd;
use std::ptr;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};

use truenas_ros::net::server::{
    BodyRecycler, CloseReason, ForceAsync, Framing, Incoming, Protocol,
    PushHandle, Request, Response, Server, ServerAddr, ServerConfig,
    ShutdownHandle,
};

use crate::buf::Buf;
use crate::conn::ConnState;
use crate::ctx::{Event, Shared, TnSmbrosEvent};
use crate::lock;
use crate::upper::Verdict;

/// The NBT header has a type byte and a 24-bit big-endian length.
pub const NBT_HDR_SIZE: usize = 4;
/// The ring reads a body of this size or more into storage from its pool.
/// Return only such storage to the pool.
pub const PLACE_MIN: usize = 64 * 1024;

pub(crate) type Ready = Result<(PushHandle, ShutdownHandle), c_int>;

pub fn errno_of(e: &truenas_ros::Error) -> c_int {
    match e {
        truenas_ros::Error::Errno(e) => *e as c_int,
        _ => libc::EINVAL,
    }
}

fn nbt_header(buf: &[u8], _state: &mut ()) -> Framing {
    if buf.len() < NBT_HDR_SIZE {
        return Framing::Need(NBT_HDR_SIZE - buf.len());
    }
    let len = (usize::from(buf[1]) << 16)
        | (usize::from(buf[2]) << 8)
        | usize::from(buf[3]);
    Framing::Complete {
        header_len: NBT_HDR_SIZE,
        body_len: len,
    }
}

/// Give this thread the signal mask of a reactor and return the old mask.
/// A thread that this thread starts gets the same mask. A reactor blocks
/// all signals, so the owner handles them on its own thread. The exceptions
/// are SIGSEGV and SIGBUS. If a fault signal is blocked, Linux kills the
/// process without the fault handler of the owner.
pub(crate) fn reactor_signals() -> libc::sigset_t {
    // SAFETY: the calls fill local sets. pthread_sigmask changes the mask
    // of this thread only.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&raw mut set);
        libc::sigdelset(&raw mut set, libc::SIGSEGV);
        libc::sigdelset(&raw mut set, libc::SIGBUS);
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const set, &raw mut old);
        old
    }
}

/// Give this thread the mask `old` from `reactor_signals()` again.
pub(crate) fn restore_signals(old: &libc::sigset_t) {
    // SAFETY: `old` is a mask from pthread_sigmask(). The call changes the
    // mask of this thread only.
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, old, ptr::null_mut());
    }
}

/// Give a new PDU to the owner, inline or through the queue.
fn deliver(shared: &Shared, buf: Box<Buf>, nbt_type: u8, verdict: Verdict) {
    let Some(buf) = try_inline(shared, buf, nbt_type, &verdict) else {
        return;
    };
    buf.conn.queued.fetch_add(1, Ordering::AcqRel);
    shared.post(Event::Pdu {
        buf,
        nbt_type,
        verdict,
    });
}

/// Offer a new PDU to the inline function of the owner. Returns the PDU if
/// the function did not run it. A PDU does not run before the queued PDUs
/// of its connection.
fn try_inline(
    shared: &Shared,
    buf: Box<Buf>,
    nbt_type: u8,
    verdict: &Verdict,
) -> Option<Box<Buf>> {
    let Some(hook) = shared.inline.get() else {
        return Some(buf);
    };
    if buf.conn.queued.load(Ordering::Acquire) != 0
        || buf.conn.closed.load(Ordering::Relaxed)
    {
        return Some(buf);
    }
    let (mut ev, keep) = TnSmbrosEvent::pdu(buf, nbt_type, verdict);
    let buf = ev.buf.cast::<Buf>();
    // SAFETY: tn_smbros_ctx_inline() requires a function that any reactor
    // thread can call. The function keeps the buffer only if it returns
    // true.
    if unsafe { (hook.func)(hook.private, &raw mut ev) } {
        // The owner has the PDU, as in tn_smbros_next().
        if let Some(d) = keep {
            d.reply(Vec::new());
        }
        return None;
    }
    // SAFETY: the function returned false. So it did not keep the buffer.
    let mut buf = unsafe { Box::from_raw(buf) };
    if keep.is_some() {
        buf.deferred = keep;
    }
    Some(buf)
}

/// Handle the redelivery of a PDU that got a job. Run the next job on this
/// ring.
fn run_job(
    req: Request<'_, ()>,
    state: &ConnState,
    recycler: Option<BodyRecycler>,
) -> Response {
    let Request { fs, responder, .. } = req;
    let job = lock(&state.jobs).queue.pop_front();
    let (Some(job), Some(mut fs)) = (job, fs) else {
        // Without a job or `fs`, nothing answers the reply.
        return Response::Close;
    };
    let (deferred, permit) = responder.defer();
    job.run(&mut fs, deferred, recycler);
    Response::Defer(permit)
}

fn server_config(
    max_in_flight: usize,
    delegate: bool,
    delegate_async: bool,
) -> ServerConfig {
    let max_in_flight = max_in_flight.max(1);
    ServerConfig {
        pool_size: 1,
        max_request_bytes: NBT_HDR_SIZE + 0x00ff_ffff,
        max_in_flight_requests: max_in_flight,
        // The owner bounds its replies itself.
        max_send_backlog: 1 << 30,
        body_placement_threshold: Some(PLACE_MIN),
        // Each job is a request in flight. This allows one file op per job.
        fs_ops: if delegate {
            u32::try_from(max_in_flight).unwrap_or(u32::MAX)
        } else {
            0
        },
        force_async: if delegate_async {
            ForceAsync::READ | ForceAsync::WRITE
        } else {
            ForceAsync::empty()
        },
        ..ServerConfig::default()
    }
}

/// Serve `sock` until it closes or the owner stops the reactor. `back_rx`
/// receives the used bodies of the connection. The reactor sends the
/// handles of the connection to `ready`, or the errno of a failed start.
pub(crate) fn reactor(
    shared: &Arc<Shared>,
    state: &Arc<ConnState>,
    sock: OwnedFd,
    max_in_flight: usize,
    delegate_async: bool,
    back_rx: mpsc::Receiver<Vec<u8>>,
    ready: &mpsc::SyncSender<Ready>,
) {
    // This runs before tn_smbros_adopt() returns. So the state of the upper
    // layer is set when the owner gets the connection.
    let upper = shared.upper.get().cloned();
    if let Some(ext) = upper.as_ref().and_then(|u| u.start(state)) {
        let _ = state.ext.set(ext);
    }
    // Only this thread can use the recycler. The owner sends used bodies to
    // this thread. The handler of the next PDU returns them to the pool.
    let recycler: Rc<RefCell<Option<BodyRecycler>>> =
        Rc::new(RefCell::new(None));
    let body = {
        let shared = Arc::clone(shared);
        let state = Arc::clone(state);
        let recycler = Rc::clone(&recycler);
        move |req: Request<'_, ()>| {
            // A redelivery has an empty frame.
            if req.header.is_empty() {
                let r = recycler.borrow().clone();
                return run_job(req, &state, r);
            }
            let Request {
                header,
                mut body,
                responder,
                ..
            } = req;
            if let Some(r) = recycler.borrow().as_ref() {
                while let Ok(v) = back_rx.try_recv() {
                    r.recycle(v);
                }
            }
            let (deferred, permit) = responder.defer();
            let mut pdu = body.take();
            let verdict = upper.as_ref().map_or_else(Verdict::default, |u| {
                u.incoming(&state, &mut pdu)
            });
            let buf = Box::new(Buf {
                conn: Arc::clone(&state),
                body: pdu,
                deferred: Some(deferred),
            });
            deliver(&shared, buf, header[0], verdict);
            Response::Defer(permit)
        }
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: nbt_header,
        body,
    };
    let cfg = server_config(max_in_flight, state.delegate, delegate_async);
    let mut server =
        match Server::with_config(Vec::<ServerAddr>::new(), cfg, proto) {
            Ok(s) => s,
            Err(e) => {
                let _ = ready.send(Err(errno_of(&e)));
                return;
            }
        };
    *recycler.borrow_mut() = server.body_recycler();
    // The owner calls tn_smbros_adopt() as root. So this registers the
    // identity of root.
    match server.register_self() {
        Ok(p) => state.root.store(p.id(), Ordering::Release),
        Err(e) => {
            let _ = ready.send(Err(errno_of(&e)));
            return;
        }
    }
    let _ = state.creds.set(server.self_registrar());
    let stop = server.shutdown_handle();
    {
        let shared = Arc::clone(shared);
        let state = Arc::clone(state);
        let stop = stop.clone();
        server.set_close_hook(move |_peer, reason, _state| {
            let error = match reason {
                CloseReason::PeerClosed => 0,
                CloseReason::RecvError(e) => e as c_int,
                _ => libc::ECONNABORTED,
            };
            shared.post(Event::Closed {
                conn: Arc::clone(&state),
                error,
            });
            stop.shutdown();
        });
    }
    let push = match server.adopt(sock, ()) {
        Ok(p) => p,
        Err(e) => {
            let _ = ready.send(Err(errno_of(&e)));
            return;
        }
    };
    let _ = ready.send(Ok((push, stop)));
    let _ = server.serve_forever();
    // Every file op completed before serve_forever() returned. Drop the
    // jobs that did not start. With `stopped` set, the owner cannot add
    // more.
    let unstarted = {
        let mut jobs = lock(&state.jobs);
        jobs.stopped = true;
        std::mem::take(&mut jobs.queue)
    };
    drop(unstarted);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// True if `sig` is blocked on this thread.
    fn blocked(sig: c_int) -> bool {
        // SAFETY: the calls read the mask of this thread into a local set.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, ptr::null(), &raw mut set);
            libc::sigismember(&raw const set, sig) == 1
        }
    }

    const SIGNALS: [c_int; 6] = [
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGCHLD,
        libc::SIGALRM,
        libc::SIGSEGV,
        libc::SIGBUS,
    ];

    #[test]
    fn a_reactor_blocks_all_signals_but_faults() {
        std::thread::spawn(|| {
            let before = SIGNALS.map(blocked);
            let old = reactor_signals();
            let started =
                std::thread::spawn(|| SIGNALS.map(blocked)).join().unwrap();
            restore_signals(&old);
            assert_eq!(started, [true, true, true, true, false, false]);
            assert_eq!(SIGNALS.map(blocked), before);
        })
        .join()
        .unwrap();
    }
}
