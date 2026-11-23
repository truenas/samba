// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! The reactor of one connection: a thread with its own ring that reads
//! whole PDUs for a handler and sends what it queues.

use std::cell::UnsafeCell;
use std::ffi::c_int;
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::block::{Block, FreeList, Pool};
use crate::list::{BoxList, Msg, MsgKind, Push, Stack};
use crate::out::Out;
use crate::ring::{ASYNC_CANCEL_ANY, Cqe, OP_ASYNC_CANCEL, Ring, Sqe};
use crate::sys;
use crate::transmit::Gather;

/// The settings of a reactor.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// The most PDUs that the handler can have at once.
    pub max_inflight: u32,
    /// A gather of this many bytes or more goes out without the kernel's
    /// copy. `usize::MAX` copies every send.
    pub zc_min: usize,
    /// Zero-copy bytes that can wait for the peer's acknowledgement.
    pub zc_max_pinned: usize,
    /// A read for the next PDU reads up to this many bytes.
    pub readahead: u32,
    /// Bytes of blocks that the pool keeps for reuse.
    pub budget: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_inflight: 16,
            zc_min: usize::MAX,
            zc_max_pinned: 64 << 20,
            readahead: 1024,
            budget: 64 << 20,
        }
    }
}

/// The tag of a `user_data` that points to an operation of the handler.
pub const TAG_OP: u64 = 0;
pub(crate) const TAG_CORE: u64 = 1;
pub(crate) const TAG_ZC: u64 = 2;
/// The tag of the handler's other completions, with its id above bit 3.
pub const TAG_UPPER: u64 = 3;

pub(crate) const UD_RECV: u64 = (1 << 3) | TAG_CORE;
pub(crate) const UD_SEND: u64 = (2 << 3) | TAG_CORE;
const UD_WAKE: u64 = (3 << 3) | TAG_CORE;
const UD_CANCEL: u64 = (4 << 3) | TAG_CORE;
/// An uncounted completion, such as the failure of a skip-success SQE.
pub(crate) const UD_IGNORE: u64 = (5 << 3) | TAG_CORE;

const ACTIVE: u32 = 0;
const PARKED: u32 = 1;
const NOTIFIED: u32 = 2;
const DEAD: u32 = 3;

/// What other threads share with a reactor.
#[derive(Debug)]
pub struct Shared {
    /// Messages from other threads, such as sends and jobs.
    pub inbox: Stack,
    /// In-flight slots that other threads released.
    pub(crate) released: AtomicU32,
    /// True while the reactor waits for released slots.
    pub(crate) cap_wait: AtomicBool,
    /// ACTIVE, PARKED, NOTIFIED or DEAD. Only a parked reactor gets an
    /// eventfd write.
    wstate: AtomicU32,
    stop: AtomicBool,
    efd: OwnedFd,
    /// The `pthread_t` of the reactor while it runs, else 0.
    thread: AtomicUsize,
    /// The ring descriptor or -1. The lock orders registers and the close.
    gate: Mutex<c_int>,
}

impl Shared {
    /// # Errors
    ///
    /// The errno if the eventfd cannot be made.
    pub fn new() -> Result<Shared, c_int> {
        let fd = sys::eventfd(libc::EFD_NONBLOCK)?;
        Ok(Shared {
            inbox: Stack::new(),
            released: AtomicU32::new(0),
            cap_wait: AtomicBool::new(false),
            wstate: AtomicU32::new(ACTIVE),
            stop: AtomicBool::new(false),
            // SAFETY: the eventfd is new and nothing else owns it.
            efd: unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) },
            thread: AtomicUsize::new(0),
            gate: Mutex::new(-1),
        })
    }

    /// True if the caller runs on the reactor thread.
    #[inline]
    pub fn on_thread(&self) -> bool {
        self.thread.load(Ordering::Relaxed) == sys::thread_self()
    }

    pub fn poke(&self) {
        let mut cur = self.wstate.load(Ordering::Acquire);
        loop {
            if cur == NOTIFIED || cur == DEAD {
                return;
            }
            match self.wstate.compare_exchange_weak(
                cur,
                NOTIFIED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if cur == PARKED {
                        sys::poke(self.efd.as_raw_fd());
                    }
                    return;
                }
                Err(seen) => cur = seen,
            }
        }
    }

    /// Give the reactor a message. False if it stopped. Then the caller
    /// keeps `m`.
    ///
    /// # Safety
    ///
    /// `m` is valid and in no list. The reactor owns it after a true return.
    pub unsafe fn post(&self, m: NonNull<Msg>) -> bool {
        // SAFETY: as the caller says.
        match unsafe { self.inbox.push(m.cast()) } {
            Push::First => {
                self.poke();
                true
            }
            Push::More => true,
            Push::Dead => false,
        }
    }

    /// Release an in-flight slot from another thread.
    pub fn release(&self) {
        self.released.fetch_add(1, Ordering::SeqCst);
        if self.cap_wait.load(Ordering::SeqCst) {
            self.poke();
        }
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.poke();
    }

    /// Register the caller's credentials on the ring. The id or -errno.
    pub fn register_self(&self) -> c_int {
        let fd = crate::lock(&self.gate);
        if *fd < 0 {
            return -libc::ENOTCONN;
        }
        sys::register_personality(*fd)
    }

    /// Refuse register calls before the ring closes.
    pub(crate) fn clear_ring(&self) {
        *crate::lock(&self.gate) = -1;
    }

    pub(crate) fn clear_thread(&self) {
        self.thread.store(0, Ordering::Relaxed);
    }
}

/// The handler of the PDUs of a reactor, on the reactor thread.
pub trait Handler: Sized {
    type State;
    /// True for a 4-byte NBT header, false for a big-endian 32-bit length.
    const NBT: bool;

    /// A PDU in `b`, `len` bytes after the header, with one in-flight slot.
    /// It gets the cell, as its code can enter the reactor again.
    fn on_pdu(cell: &ReactorCell<Self::State>, b: Block, len: u32);
    /// An inbox message that is not a send.
    fn on_msg(r: &mut Reactor<Self::State>, m: NonNull<Msg>);
    /// The same, after the reactor stopped.
    fn drop_msg(r: &mut Reactor<Self::State>, m: NonNull<Msg>);
    /// The step of an out with `finish` set. False closes the connection.
    fn finish_out(r: &mut Reactor<Self::State>, o: &mut Out) -> bool;
    /// The reactor is done with `o`.
    fn release_out(r: &mut Reactor<Self::State>, o: Box<Out>);
    /// The connection ended. Called one time.
    fn on_closed(r: &mut Reactor<Self::State>, err: c_int);
    fn on_batch(r: &mut Reactor<Self::State>);
    /// True if the handler has local work.
    fn pending(r: &Reactor<Self::State>) -> bool;
    /// A completion with `TAG_OP` or `TAG_UPPER`.
    fn on_cqe(r: &mut Reactor<Self::State>, ud: u64, res: i32);
    /// The reactor stops, before it waits for its operations.
    fn on_stop(r: &mut Reactor<Self::State>);
    /// All operations are done.
    fn on_end(r: &mut Reactor<Self::State>);
}

/// The reactor of one connection. Only its own thread uses it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct Reactor<S> {
    pub ring: Ring,
    sh: NonNull<Shared>,
    pub h: S,
    pub cfg: Config,
    /// Fixed file 0 of the ring.
    pub(crate) sock: OwnedFd,
    pub blocks: Pool,
    pub(crate) outs: FreeList<Out>,
    pub(crate) zcs: FreeList<Gather>,

    // Receive
    pub(crate) cur: Option<Block>,
    pub(crate) have: u32,
    pub(crate) total: u32,
    pub(crate) recv_armed: bool,
    pub(crate) inflight: u32,
    pub(crate) capped: bool,

    // Send
    pub(crate) sendq: BoxList<Out>,
    pub(crate) sending: bool,
    pub(crate) gather: Gather,
    pub(crate) zc_on: bool,
    pub(crate) zc_pinned: usize,
    pub(crate) zc_notifs: u32,

    wake_buf: u64,
    /// The CQEs that are still due.
    pub(crate) ops: u32,
    pub stopping: bool,
    ended: bool,
    pub(crate) in_drain: bool,
}

impl<S> Reactor<S> {
    /// # Errors
    ///
    /// The errno if the ring cannot be made.
    ///
    /// # Safety
    ///
    /// `sh` stays valid while the reactor lives on the calling thread.
    pub unsafe fn new(
        sh: NonNull<Shared>,
        cfg: Config,
        sock: OwnedFd,
        h: S,
    ) -> Result<Reactor<S>, c_int> {
        let ring = Ring::new(256, 512)?;
        ring.register_files(&[sock.as_raw_fd()])
            .map_err(|_| libc::EIO)?;
        let r = Reactor {
            ring,
            sh,
            h,
            cfg,
            sock,
            blocks: Pool::new(cfg.budget),
            outs: FreeList::new(256),
            zcs: FreeList::new(16),
            cur: None,
            have: 0,
            total: 0,
            recv_armed: false,
            inflight: 0,
            capped: false,
            sendq: BoxList::new(),
            sending: false,
            gather: Gather::new(),
            zc_on: cfg.zc_min != usize::MAX,
            zc_pinned: 0,
            zc_notifs: 0,
            wake_buf: 0,
            ops: 0,
            stopping: false,
            ended: false,
            in_drain: false,
        };
        *crate::lock(&r.sh().gate) = r.ring.fd();
        r.sh().thread.store(sys::thread_self(), Ordering::Relaxed);
        Ok(r)
    }

    #[inline]
    pub fn sh(&self) -> &Shared {
        // SAFETY: the shared state outlives the reactor, see new().
        unsafe { self.sh.as_ref() }
    }

    /// Queue a counted operation. False if the ring stays full.
    ///
    /// # Safety
    ///
    /// The conditions of `Ring::push()` apply.
    #[inline]
    pub unsafe fn push_sqe(&mut self, s: Sqe) -> bool {
        // SAFETY: as the caller says.
        if unsafe { self.ring.push(s) } {
            self.ops += 1;
            return true;
        }
        // SAFETY: as the caller says.
        unsafe { self.push_sqe_slow(s) }
    }

    #[cold]
    #[inline(never)]
    unsafe fn push_sqe_slow(&mut self, s: Sqe) -> bool {
        self.ring.submit();
        // SAFETY: as in push_sqe().
        if unsafe { self.ring.push(s) } {
            self.ops += 1;
            return true;
        }
        false
    }

    /// As `push_sqe()`, for an SQE whose success posts no completion.
    ///
    /// # Safety
    ///
    /// The conditions of `Ring::push()` apply.
    pub unsafe fn push_sqe_uncounted(&mut self, mut s: Sqe) -> bool {
        s.user_data = UD_IGNORE;
        s.flags |= crate::ring::IOSQE_CQE_SKIP_SUCCESS;
        // SAFETY: as the caller says.
        let ok = unsafe { self.push_sqe(s) };
        if ok {
            self.ops -= 1;
        }
        ok
    }

    pub fn end<H: Handler<State = S>>(&mut self, err: c_int) {
        if !self.ended {
            self.ended = true;
            H::on_closed(self, err);
        }
        self.stopping = true;
    }

    #[cold]
    #[inline(never)]
    pub fn fail<H: Handler<State = S>>(&mut self, err: c_int) {
        self.end::<H>(err);
    }

    fn arm_wake<H: Handler<State = S>>(&mut self) {
        let s = Sqe {
            opcode: crate::ring::OP_READ,
            fd: self.sh().efd.as_raw_fd(),
            addr: (&raw mut self.wake_buf) as u64,
            len: 8,
            off: u64::MAX,
            user_data: UD_WAKE,
            ..Sqe::ZERO
        };
        // SAFETY: wake_buf is in the reactor, which outlives its operations.
        if !unsafe { self.push_sqe(s) } {
            self.fail::<H>(libc::EIO);
        }
    }

    fn on_wake<H: Handler<State = S>>(&mut self) {
        if !self.stopping {
            self.arm_wake::<H>();
        }
    }

    /// Queue `o` on the reactor thread, after the sends that other threads
    /// posted before it.
    #[inline]
    pub fn queue<H: Handler<State = S>>(&mut self, o: Box<Out>) {
        if let Some(o) = self.queue_with(o, Self::drain_inbox::<H>) {
            H::release_out(self, o);
        }
    }

    /// `queue()` with the inbox drain as a function. Gives back an out
    /// without segments.
    #[inline]
    pub fn queue_with(
        &mut self,
        o: Box<Out>,
        drain: fn(&mut Self),
    ) -> Option<Box<Out>> {
        if !self.in_drain && self.sh().inbox.ready() {
            drain(self);
        }
        if o.nseg == 0 {
            return Some(o);
        }
        self.sendq.push(o);
        None
    }

    fn accept<H: Handler<State = S>>(&mut self, mut o: Box<Out>) {
        if o.finish && !H::finish_out(self, &mut o) {
            H::release_out(self, o);
            self.end::<H>(libc::ECONNABORTED);
            return;
        }
        self.queue::<H>(o);
    }

    pub fn drain_inbox<H: Handler<State = S>>(&mut self) {
        // A send of this batch must not wait behind a newer batch.
        self.in_drain = true;
        let mut l = self.sh().inbox.take();
        while let Some(link) = l.pop() {
            let m = link.cast::<Msg>();
            // SAFETY: a Send message starts a leaked Box<Out>.
            unsafe {
                if m.as_ref().kind == MsgKind::Send {
                    self.accept::<H>(Box::from_raw(m.cast::<Out>().as_ptr()));
                } else {
                    H::on_msg(self, m);
                }
            }
        }
        self.in_drain = false;
    }

    #[inline]
    fn drain<H: Handler<State = S>>(&mut self) {
        if self.sh().stop.load(Ordering::Acquire) {
            self.stopping = true;
        }
        if self.sh().inbox.ready() {
            self.drain_inbox::<H>();
        }
    }

    fn park(&mut self) -> bool {
        let w = &self.sh().wstate;
        if w.compare_exchange(
            ACTIVE,
            PARKED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
        {
            return true;
        }
        w.store(ACTIVE, Ordering::Release);
        false
    }

    #[inline]
    fn dispatch<H: Handler<State = S>>(&mut self, c: Cqe) {
        let ud = c.user_data;
        if ud == UD_IGNORE {
            return;
        }
        self.ops -= 1;
        match ud & 7 {
            TAG_CORE => match ud {
                UD_RECV => self.on_recv::<H>(c.res),
                UD_SEND => self.on_send::<H>(c.res),
                UD_WAKE => self.on_wake::<H>(),
                _ => {}
            },
            TAG_ZC => self.on_zc::<H>(ud & !7, c.res, c.flags),
            _ => H::on_cqe(self, ud, c.res),
        }
    }

    /// Run the completions in place, 64 at most per batch.
    fn reap<H: Handler<State = S>>(&mut self) {
        loop {
            let head = self.ring.cq_head();
            let n = self.ring.cq_tail().wrapping_sub(head).min(64);
            if n == 0 {
                return;
            }
            for i in 0..n {
                // SAFETY: the position is before the tail.
                let c = unsafe { self.ring.cqe(head.wrapping_add(i)) };
                self.dispatch::<H>(c);
            }
            self.ring.cq_set_head(head.wrapping_add(n));
        }
    }

    fn teardown<H: Handler<State = S>>(&mut self) {
        self.stopping = true;
        let mut left = self.sh().inbox.close();
        while let Some(link) = left.pop() {
            let m = link.cast::<Msg>();
            // SAFETY: as in drain_inbox().
            unsafe {
                if m.as_ref().kind == MsgKind::Send {
                    let o = Box::from_raw(m.cast::<Out>().as_ptr());
                    H::release_out(self, o);
                } else {
                    H::drop_msg(self, m);
                }
            }
        }
        H::on_stop(self);
        let cancel = Sqe {
            opcode: OP_ASYNC_CANCEL,
            fd: -1,
            op_flags: ASYNC_CANCEL_ANY,
            user_data: UD_CANCEL,
            ..Sqe::ZERO
        };
        // Only the cancel ends the read of the eventfd. If the ring refuses
        // it, try again after a reap.
        // SAFETY: a cancel names no memory.
        while self.ops > 0 && !unsafe { self.push_sqe(cancel) } {
            sys::sleep_ns(sys::NS_PER_MS);
            self.reap::<H>();
        }
        // A notification cannot be cancelled. After one second, a reset of
        // the connection frees the pages.
        let deadline = sys::now_ns() + sys::NS_PER_SEC;
        let mut reset = false;
        while self.ops > 0 {
            if !reset && self.ops <= self.zc_notifs {
                if sys::now_ns() >= deadline {
                    reset_socket(&self.sock);
                    reset = true;
                } else {
                    self.ring.submit();
                    sys::sleep_ns(sys::NS_PER_MS);
                    self.reap::<H>();
                    continue;
                }
            }
            self.ring.submit_and_wait(1);
            self.reap::<H>();
        }
        let q = std::mem::take(&mut self.sendq);
        self.release_outs::<H>(q);
        let g = std::mem::take(&mut self.gather.outs);
        self.release_outs::<H>(g);
        if let Some(b) = self.cur.take() {
            self.blocks.put(b);
        }
        H::on_end(self);
        self.sh().wstate.store(DEAD, Ordering::Release);
        self.sh().clear_ring();
    }
}

/// Reset the connection with a connect to `AF_UNSPEC` (0).
fn reset_socket(sock: &OwnedFd) {
    let unspec = libc::sockaddr {
        sa_family: 0,
        sa_data: [0; 14],
    };
    let len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr>())
        .unwrap_or(0);
    // SAFETY: connect reads one sockaddr.
    unsafe { libc::connect(sock.as_raw_fd(), &raw const unspec, len) };
}

/// A reactor that inline runs of smbd can enter again. The reactor holds no
/// borrow of itself while such code runs.
#[derive(Debug)]
pub struct ReactorCell<S> {
    r: UnsafeCell<Reactor<S>>,
    #[cfg(debug_assertions)]
    busy: std::cell::Cell<bool>,
}

/// A borrow of the reactor in a `ReactorCell`.
#[derive(Debug)]
pub struct Borrow<'a, S>(&'a ReactorCell<S>);

impl<S> ReactorCell<S> {
    pub fn new(r: Reactor<S>) -> Self {
        ReactorCell {
            r: UnsafeCell::new(r),
            #[cfg(debug_assertions)]
            busy: std::cell::Cell::new(false),
        }
    }

    /// # Panics
    ///
    /// In a debug build, if the reactor is borrowed already.
    ///
    /// # Safety
    ///
    /// The caller is the reactor thread and has no other live borrow. The
    /// borrow ends before code runs that can borrow the reactor again.
    #[inline]
    pub unsafe fn borrow(&self) -> Borrow<'_, S> {
        #[cfg(debug_assertions)]
        {
            assert!(!self.busy.get(), "the reactor is borrowed already");
            self.busy.set(true);
        }
        Borrow(self)
    }

    pub fn into_inner(self) -> Reactor<S> {
        self.r.into_inner()
    }
}

impl<S> Deref for Borrow<'_, S> {
    type Target = Reactor<S>;

    #[inline]
    fn deref(&self) -> &Reactor<S> {
        // SAFETY: the borrow is the only one, see ReactorCell::borrow().
        unsafe { &*self.0.r.get() }
    }
}

impl<S> DerefMut for Borrow<'_, S> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Reactor<S> {
        // SAFETY: as in deref().
        unsafe { &mut *self.0.r.get() }
    }
}

impl<S> Drop for Borrow<'_, S> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        self.0.busy.set(false);
    }
}

/// Deliver the PDUs that are buffered and arm a read for more.
fn deliver<H: Handler>(cell: &ReactorCell<H::State>) {
    loop {
        // SAFETY: no borrow is live. The borrow ends with this statement.
        let next = unsafe { cell.borrow() }.next_pdu::<H>();
        let Some((b, len)) = next else {
            return;
        };
        H::on_pdu(cell, b, len);
    }
}

/// Serve the connection until it ends or another thread stops the reactor.
pub fn run<H: Handler>(cell: &ReactorCell<H::State>) {
    // SAFETY: each borrow ends before the next and before deliver() runs.
    let borrow = || unsafe { cell.borrow() };
    borrow().arm_wake::<H>();
    deliver::<H>(cell);
    loop {
        borrow().reap::<H>();
        deliver::<H>(cell);
        {
            let mut r = borrow();
            H::on_batch(&mut r);
            r.drain::<H>();
            if r.stopping {
                break;
            }
        }
        deliver::<H>(cell);
        let mut r = borrow();
        r.kick_send::<H>();
        if r.stopping {
            break;
        }
        if H::pending(&r) || r.ring.cq_ready() {
            continue;
        }
        if !r.park() {
            continue;
        }
        r.ring.submit_and_wait(1);
        r.sh().wstate.store(ACTIVE, Ordering::Release);
    }
    borrow().teardown::<H>();
}
