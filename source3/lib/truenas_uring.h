/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
   Unix SMB/CIFS implementation.

   Per-tevent_context Linux io_uring abstraction (TrueNAS fork).

   Public surface, by subsystem (see the section headers below for the
   full declarations):

     File I/O           tevent_req-shaped pread / pwrite / pwrite_v2 /
                        fsync wrappers; submit helpers auto-detect a
                        registered-buffer pointer and dispatch to the
                        _FIXED IORING_OP_* variants.
     Socket I/O         recv / send / sendmsg / recvmsg wrappers (no
                        zero-copy variants -- those live below).
     Zero-copy send     send_zc / sendmsg_zc, with multi-CQE bookkeeping
                        for the data + IORING_CQE_F_NOTIF pair.
     Splice             splice() wrapper used by both file <-> pipe and
                        pipe <-> socket halves of the SMB2 outbound /
                        inbound splice state machines.
     Registered bufs    IORING_REGISTER_BUFFERS pool + a 64-slot
                        allocator (acquire / release / data lookup).
     Pipe pool          Pre-acquired blocking-pipe pool used by the SMB2
                        splice state machines (body / tee / patched-
                        header pipes are pulled from here).
     AF_ALG HMAC        algif_hash open / compute / close, used by signed
                        splice for in-kernel HMAC over spliced bytes.

   The IOSQE_ASYNC threshold knob (per op class) is also exposed: ops
   whose payload exceeds the configured threshold get IOSQE_ASYNC so the
   in-kernel memcpy runs on a worker thread.

   API shape is an adaptation of Stefan Metzmacher's
   `lib/util/samba_io_uring` abstraction (upstream Samba !4453).

   Copyright (C) Stefan Metzmacher 2020,2026
   Copyright (C) iXsystems, Inc. 2026

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef TRUENAS_URING_H
#define TRUENAS_URING_H

#include "replace.h"
#include <tevent.h>
#include <sys/socket.h>  /* struct msghdr */
#include <sys/uio.h>     /* struct iovec, off_t */
#include <stdint.h>

struct truenas_uring;

/*
 * Bits per word in the packed busy-bitmap allocators. Word width is
 * uint64_t portably; the constant exists so callers can size derived
 * limits (e.g. TURING_REG_BUF_POOL_MAX below) without spelling 64.
 */
#define TURING_BUSY_BITS_PER_WORD ((unsigned int)(8 * sizeof(uint64_t)))

/*
 * Hard cap on the registered-buffer pool size. Dictated by the
 * single-uint64_t busy mask used by truenas_uring_buf_acquire /
 * _release. The lower-level truenas_uring_register_buffers /
 * _buf_index path has no such cap. The pipe pool uses a packed
 * bitmap and is uncapped.
 */
#define TURING_REG_BUF_POOL_MAX TURING_BUSY_BITS_PER_WORD

/*
 * Per-subsystem debug class for the truenas_uring fast paths. Lets
 * operators isolate this subsystem's messages via smb.conf:
 *
 *     log level = 1 truenas_uring:10
 *
 * Primed automatically by truenas_uring_get() on first use. Until
 * primed, falls back to DBGC_RPC_SRV so messages still appear. Use
 * via the class-aware DBGC_* macros, e.g.
 *
 *     DBGC_NOTICE(truenas_uring_debug_class, "...");
 */
extern int truenas_uring_debug_class;

/*
 * Op classes for the IOSQE_ASYNC threshold knob. Configured via
 * `io_uring:force_async_read_threshold` / `..._write_threshold`: ops
 * larger than the threshold get IOSQE_ASYNC set, which tells the kernel
 * to dispatch them on a worker thread instead of synchronously in the
 * syscall path. This frees the main process from blocking on memcpy
 * (relevant for buffered file I/O over the page cache).
 */
enum truenas_uring_op_class {
	TURING_OP_READ_CLASS = 0,
	TURING_OP_WRITE_CLASS = 1,
	TURING_OP_NUM_CLASSES
};

/*
 * Obtain (and lazily create) the truenas_uring associated with this
 * tevent_context. Repeat calls with the same ev return the same pointer.
 * The returned struct is talloc'd as a child of ev; its lifetime is bound
 * to the tevent_context.
 *
 * Returns NULL on failure with errno set (ENOMEM, ENOSPC, or the negated
 * io_uring init error).
 */
struct truenas_uring *truenas_uring_get(struct tevent_context *ev);

/*
 * Configure the per-op-class IOSQE_ASYNC threshold. Default is 0 (never
 * set IOSQE_ASYNC). When threshold_bytes > 0, an op of this class whose
 * payload is >= threshold_bytes gets the IOSQE_ASYNC flag on submission.
 */
void truenas_uring_set_async_threshold(struct truenas_uring *u,
				       enum truenas_uring_op_class op_class,
				       size_t threshold_bytes);

/*
 * Cap the kernel io-wq worker pool for this ring (bounds concurrent blocking
 * ops, i.e. max io_uring op concurrency for this process). values are
 * (bounded, unbounded); 0 leaves a class at the kernel default. Returns 0 or
 * -errno (non-fatal -- caller may ignore).
 */
int truenas_uring_set_iowq_max_workers(struct truenas_uring *u,
				       unsigned int bounded,
				       unsigned int unbounded);

/* ---------------- File I/O ops ---------------- */

struct tevent_req *_truenas_uring_pread_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      int fd,
					      void *buf,
					      size_t count,
					      off_t offset,
					      const char *location);
#define truenas_uring_pread_send(mem_ctx, ev, fd, buf, count, offset) \
	_truenas_uring_pread_send((mem_ctx), (ev), (fd), (buf), (count), \
				   (offset), __location__)
ssize_t truenas_uring_pread_recv(struct tevent_req *req, int *perrno);

struct tevent_req *_truenas_uring_pwrite_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       int fd,
					       const void *buf,
					       size_t count,
					       off_t offset,
					       const char *location);
#define truenas_uring_pwrite_send(mem_ctx, ev, fd, buf, count, offset) \
	_truenas_uring_pwrite_send((mem_ctx), (ev), (fd), (buf), (count), \
				    (offset), __location__)
ssize_t truenas_uring_pwrite_recv(struct tevent_req *req, int *perrno);

/*
 * pwrite variant using IORING_OP_WRITEV with RWF_* flags (e.g., RWF_APPEND
 * for atomic POSIX append). Internally uses io_uring_prep_writev2 with a
 * single-element iovec; the iovec is talloc'd as a child of the request
 * substate so it persists until the CQE has been reaped.
 *
 * rwf_flags=0 is functionally equivalent to pwrite_send but goes through
 * the writev2 prep path -- prefer pwrite_send when no RWF flags are needed.
 *
 * Counted against the write op class for IOSQE_ASYNC purposes.
 */
struct tevent_req *_truenas_uring_pwrite_v2_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  int fd,
						  const void *buf,
						  size_t count,
						  off_t offset,
						  int rwf_flags,
						  const char *location);
#define truenas_uring_pwrite_v2_send(mem_ctx, ev, fd, buf, count, off, rwf) \
	_truenas_uring_pwrite_v2_send((mem_ctx), (ev), (fd), (buf), (count), \
				       (off), (rwf), __location__)
ssize_t truenas_uring_pwrite_v2_recv(struct tevent_req *req, int *perrno);

struct tevent_req *_truenas_uring_fsync_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      int fd,
					      unsigned int flags,
					      const char *location);
#define truenas_uring_fsync_send(mem_ctx, ev, fd, flags) \
	_truenas_uring_fsync_send((mem_ctx), (ev), (fd), (flags), __location__)
int truenas_uring_fsync_recv(struct tevent_req *req, int *perrno);

/* ---------------- Splice + socket ops ---------------- */

/*
 * Splice `len` bytes between fd_in and fd_out via IORING_OP_SPLICE.
 * Exactly one of fd_in/fd_out must be a pipe (kernel requirement).
 *
 * off_in / off_out are file offsets; pass NULL to use the file's current
 * position (which is mandatory for pipes -- pipes have no seek pointer).
 * For a regular file, an explicit offset avoids racing with concurrent
 * readers/writers on the same fd.
 *
 * splice_flags accepts SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE,
 * SPLICE_F_GIFT (see splice(2)).
 *
 * Counted against the write op class for IOSQE_ASYNC purposes.
 */
struct tevent_req *_truenas_uring_splice_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       int fd_in,
					       const int64_t *off_in,
					       int fd_out,
					       const int64_t *off_out,
					       size_t len,
					       unsigned int splice_flags,
					       const char *location);
#define truenas_uring_splice_send(mem_ctx, ev, fi, oi, fo, oo, len, sf) \
	_truenas_uring_splice_send((mem_ctx), (ev), (fi), (oi), (fo), (oo), \
				    (len), (sf), __location__)
ssize_t truenas_uring_splice_recv(struct tevent_req *req, int *perrno);

/*
 * Receive up to `len` bytes from `sockfd` into `buf` via IORING_OP_RECV.
 * msg_flags is the recvmsg(2) flags set.
 *
 * Counted against the read op class for IOSQE_ASYNC purposes.
 */
struct tevent_req *_truenas_uring_recv_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     int sockfd,
					     void *buf,
					     size_t len,
					     int msg_flags,
					     const char *location);
#define truenas_uring_recv_send(mem_ctx, ev, fd, buf, len, mf) \
	_truenas_uring_recv_send((mem_ctx), (ev), (fd), (buf), (len), (mf), \
				  __location__)
ssize_t truenas_uring_recv_recv(struct tevent_req *req, int *perrno);

/*
 * Send `len` bytes from `buf` to `sockfd` via IORING_OP_SEND (NOT _ZC).
 * Single CQE -- this is the lower-overhead non-zero-copy path. Combined
 * with IOSQE_ASYNC (set via truenas_uring_set_async_threshold) the
 * in-kernel memcpy runs on a worker thread, freeing the smbd main loop
 * without paying the SEND_ZC dual-completion cost.
 *
 * Counted against the write op class for IOSQE_ASYNC purposes.
 */
struct tevent_req *_truenas_uring_send_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     int sockfd,
					     const void *buf,
					     size_t len,
					     int msg_flags,
					     const char *location);
#define truenas_uring_send_send(mem_ctx, ev, fd, buf, len, mf) \
	_truenas_uring_send_send((mem_ctx), (ev), (fd), (buf), (len), (mf), \
				  __location__)
ssize_t truenas_uring_send_recv(struct tevent_req *req, int *perrno);

/*
 * Send a multi-iov msghdr via IORING_OP_SENDMSG (NOT _ZC). `msg` must
 * stay valid until tevent_req_done fires. Single CQE.
 *
 * Counted against the write op class for IOSQE_ASYNC purposes (using
 * the total iov length).
 */
struct tevent_req *_truenas_uring_sendmsg_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						int sockfd,
						const struct msghdr *msg,
						int msg_flags,
						const char *location);
#define truenas_uring_sendmsg_send(mem_ctx, ev, fd, msg, mf) \
	_truenas_uring_sendmsg_send((mem_ctx), (ev), (fd), (msg), (mf), \
				     __location__)
ssize_t truenas_uring_sendmsg_recv(struct tevent_req *req, int *perrno);

/*
 * Receive into a msghdr via IORING_OP_RECVMSG. `msg` must stay valid
 * until tevent_req_done fires (the kernel writes into msg_iov on
 * completion and updates msg_namelen / msg_controllen).
 *
 * Counted against the read op class for IOSQE_ASYNC purposes.
 */
struct tevent_req *_truenas_uring_recvmsg_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						int sockfd,
						struct msghdr *msg,
						int msg_flags,
						const char *location);
#define truenas_uring_recvmsg_send(mem_ctx, ev, fd, msg, mf) \
	_truenas_uring_recvmsg_send((mem_ctx), (ev), (fd), (msg), (mf), \
				     __location__)
ssize_t truenas_uring_recvmsg_recv(struct tevent_req *req, int *perrno);

/*
 * Send `len` bytes from `buf` to `sockfd` via IORING_OP_SEND_ZC
 * (MSG_ZEROCOPY). The kernel pins the pages of `buf` and DMAs from them
 * directly; the buffer must remain stable until tevent_req_done fires.
 *
 * Dual-completion model: the kernel issues two CQEs --
 *   1. data CQE (with IORING_CQE_F_MORE set on success) -- bytes-sent count
 *   2. notification CQE (IORING_CQE_F_NOTIF) -- buffer no longer needed
 * tevent_req_done fires only after both have arrived.
 *
 * msg_flags is the sendmsg(2) flags set (e.g., MSG_NOSIGNAL).
 * zc_flags is the IORING_SEND_ZC_* flags set (e.g.,
 * IORING_SEND_ZC_REPORT_USAGE).
 *
 * Counted against the write op class for IOSQE_ASYNC purposes.
 */
struct tevent_req *_truenas_uring_send_zc_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						int sockfd,
						const void *buf,
						size_t len,
						int msg_flags,
						unsigned int zc_flags,
						const char *location);
#define truenas_uring_send_zc_send(mem_ctx, ev, fd, buf, len, mf, zf) \
	_truenas_uring_send_zc_send((mem_ctx), (ev), (fd), (buf), (len), \
				     (mf), (zf), __location__)
ssize_t truenas_uring_send_zc_recv(struct tevent_req *req, int *perrno);

/*
 * Send a multi-iov msghdr via IORING_OP_SENDMSG_ZC. Same dual-completion
 * model as send_zc; `msg` must stay valid until tevent_req_done fires.
 *
 * Counted against the write op class for IOSQE_ASYNC purposes (using the
 * total iov length).
 */
struct tevent_req *_truenas_uring_sendmsg_zc_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   int sockfd,
						   const struct msghdr *msg,
						   int msg_flags,
						   const char *location);
#define truenas_uring_sendmsg_zc_send(mem_ctx, ev, fd, msg, mf) \
	_truenas_uring_sendmsg_zc_send((mem_ctx), (ev), (fd), (msg), (mf), \
					__location__)
ssize_t truenas_uring_sendmsg_zc_recv(struct tevent_req *req, int *perrno);

/* ---------------- Registered buffer pool ---------------- */

/*
 * Register `nr` pre-allocated buffers with the io_uring via
 * IORING_REGISTER_BUFFERS. The kernel pins the pages for the ring's
 * lifetime (or until truenas_uring_unregister_buffers is called).
 *
 * After registration, submission helpers (pread / pwrite / send_zc)
 * automatically detect when a passed buffer pointer falls within a
 * registered region and switch to the IORING_OP_*_FIXED variant,
 * avoiding the per-op page-pinning cost. Multi-iov sendmsg_zc stays
 * on the non-fixed path because IORING_RECVSEND_FIXED_BUF only takes
 * a single contiguous buffer.
 *
 * Returns 0 on success, -errno on failure. The buffers themselves
 * remain owned by the caller; they must outlive the registration or
 * be unregistered first.
 *
 * Limitation: only one registration per ring. Re-register requires
 * unregister first (full replace; partial REGISTER_BUFFERS_UPDATE is
 * not exposed here).
 */
int truenas_uring_register_buffers(struct truenas_uring *u,
				   const struct iovec *iovs,
				   unsigned int nr);

/*
 * Tear down the registered buffer pool. After this returns,
 * truenas_uring_buf_index always returns -1.
 */
int truenas_uring_unregister_buffers(struct truenas_uring *u);

/*
 * Return the buffer index (0..nr-1) if `ptr` falls within any registered
 * buffer's [base, base+len) range, or -1 otherwise. Cheap O(nr) pointer
 * range scan. Used internally by submission helpers for FIXED-variant
 * dispatch; exposed for callers that want explicit control.
 */
int truenas_uring_buf_index(struct truenas_uring *u, const void *ptr);

/*
 * Free-slot allocator on top of the registered pool. Used by smbd's
 * encrypted-PDU path (SMB2 READ/WRITE response with SMB3 transform
 * encryption) to check out a pre-pinned buffer for the duration of a
 * request without per-PDU malloc churn.
 *
 * Slot tracking is a single-word busy bitmap, so the registered pool
 * is capped at TURING_REG_BUF_POOL_MAX slots when callers use this
 * allocator. The lower-level truenas_uring_register_buffers /
 * _buf_index path has no such cap.
 *
 * truenas_uring_buf_acquire scans for the lowest-index free slot whose
 * registered iov_len is >= size_hint; returns the slot index, or -1 if
 * nothing fits (pool not registered / all busy / all too small). Caller
 * is expected to truenas_uring_buf_release when done.
 *
 * truenas_uring_buf_data returns the slot's base pointer (and size out-
 * arg if non-NULL). The data pointer is stable for the lifetime of the
 * registration -- safe to hand to FIXED-variant submissions, which
 * truenas_uring_pread/pwrite/send_zc will auto-detect via
 * truenas_uring_buf_index.
 */
int truenas_uring_buf_acquire(struct truenas_uring *u, size_t size_hint);
void truenas_uring_buf_release(struct truenas_uring *u, int slot);
void *truenas_uring_buf_data(struct truenas_uring *u, int slot,
			     size_t *size_out);

/*
 * Higher-level helper: mmap `nr` page-aligned anonymous buffers of
 * `bufsize` each, register them with the io_uring, and have the
 * truenas_uring own the mmap region. Cleanup (unregister + munmap)
 * happens automatically when the truenas_uring is destroyed via its
 * talloc destructor.
 *
 * Idempotent: returns 0 on first successful call, -EBUSY on subsequent
 * calls (a pool is already registered). Caller can ignore -EBUSY.
 *
 * Other return values: -EINVAL (nr outside [1, TURING_REG_BUF_POOL_MAX]
 * or bufsize == 0), -ENOMEM (talloc), or any negated errno from
 * mmap()/io_uring_register_buffers().
 */
int truenas_uring_register_owned_pool(struct truenas_uring *u,
				      unsigned int nr,
				      size_t bufsize);

/*
 * Per-uring pipe pool used by the SMB2 splice state machines
 * (file <-> pipe <-> socket; signed and unsigned variants).
 *
 * Allocates `nr` pipe pairs with pipe2(O_CLOEXEC | O_NONBLOCK), each sized
 * with F_SETPIPE_SZ(pipe_size_bytes) clamped to /proc/sys/fs/pipe-max-size.
 * Closed automatically on truenas_uring destructor.
 *
 * Idempotent: -EBUSY on re-call. -EINVAL when nr/size are out of range.
 * Other return values: -ENOMEM (talloc) or any negated errno from pipe2(2)
 * or fcntl(F_SETPIPE_SZ). pipe2 failure tears down any pipes already created.
 */
int truenas_uring_register_pipe_pool(struct truenas_uring *u,
				     unsigned int nr,
				     size_t pipe_size_bytes);

/*
 * Acquired pipe handle: read-end (rfd) and write-end (wfd) of a pipe, and
 * `slot` for release. On failure rfd == wfd == slot == -1 (pool not
 * registered or all pipes busy).
 */
struct truenas_uring_pipe {
	int rfd;
	int wfd;
	int slot;
};

struct truenas_uring_pipe truenas_uring_pipe_acquire(struct truenas_uring *u);

/* Returns the pipe to the pool. The caller is responsible for draining any
 * data left in the pipe (typically via short read + discard) before release;
 * otherwise the next acquirer sees stale bytes. Releasing slot < 0 is a
 * no-op (mirrors the failure-handle pattern). */
void truenas_uring_pipe_release(struct truenas_uring *u, int slot);

/*
 * Capacity (in bytes) of each pipe in the pool, as requested via F_SETPIPE_SZ
 * at truenas_uring_register_pipe_pool() time. The real kernel capacity is >=
 * this (rounded up to whole pages), so callers may use it as a safe upper
 * bound on how much to splice into a pipe before it must be drained. Returns 0
 * if no pool is registered.
 */
size_t truenas_uring_pipe_capacity(struct truenas_uring *u);

/* ---------------- AF_ALG HMAC sockets (signed splice) ---------------- */
/*
 * Per-key AF_ALG hash socket lifecycle for streaming HMAC over SMB2 PDUs
 * without copying payload bytes back to userspace. The key is bound at
 * truenas_uring_hmac_open time; subsequent truenas_uring_hmac_compute calls
 * issue an accept(2) for a per-message op fd, feed header bytes via sendmsg
 * (talloc'd userspace), splice payload bytes from a pipe (kernel-resident),
 * read the MAC, and close the op fd.
 *
 * Typical usage from smbd's signed splice path (signed WRITE inbound or
 * signed READ outbound):
 *
 *   int hmac_fd = truenas_uring_hmac_open("hmac(sha256)", key, keylen);
 *   ...
 *   truenas_uring_hmac_compute(hmac_fd, hdr, hdr_len,
 *                              pipe_rfd, payload_len, mac, mac_len);
 *   ...
 *   truenas_uring_hmac_close(hmac_fd);
 *
 * Algorithm names follow the kernel crypto naming convention -- e.g.,
 * "hmac(sha256)" for SMB3.0+ signing, "cmac(aes)" for SMB2.x signing.
 * Returns negative -errno on failure.
 */
int truenas_uring_hmac_open(const char *alg_name,
			    const void *key, size_t keylen);

int truenas_uring_hmac_compute(int hmac_bind_fd,
			       const void *header, size_t header_len,
			       int pipe_rfd, size_t payload_len,
			       void *mac_out, size_t mac_len);

void truenas_uring_hmac_close(int hmac_bind_fd);

#endif /* TRUENAS_URING_H */
