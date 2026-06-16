/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
   Unix SMB/CIFS implementation.

   Per-tevent_context Linux io_uring abstraction (TrueNAS fork).

   Provides tevent_req-shaped wrappers around the io_uring opcodes that
   smbd's SMB2 fast paths and vfs_io_uring care about:

     File I/O           pread / pwrite / pwrite_v2 / fsync
     Socket I/O         recv / send / sendmsg / recvmsg
     Zero-copy send     send_zc / sendmsg_zc (dual-CQE: data + notif)
     Splice             splice (file <-> pipe <-> socket)

   plus three out-of-line resource pools that bolt onto the same ring:

     Registered bufs    IORING_REGISTER_BUFFERS pool with auto-FIXED
                        detection in the submit helpers (pread / pwrite /
                        send_zc dispatch to *_FIXED variants when the
                        buffer pointer lies in a registered iov)
     Pipe pool          pre-acquired blocking pipe pool used by the SMB2
                        splice state machines for body / tee / patched-
                        header pipes
     AF_ALG HMAC        algif_hash open / compute / close used by signed
                        splice WRITE for in-kernel HMAC

   The IOSQE_ASYNC threshold knob (per op class) is also exposed: ops
   whose payload exceeds the configured threshold get IOSQE_ASYNC, so
   the in-kernel memcpy runs on a worker thread and the main loop stays
   on the dispatch hot path.

   Lifecycle: one truenas_uring per tevent_context, lazily created on the
   first truenas_uring_get(ev) call and torn down when ev is freed (talloc
   destructor removes our registry entry, frees the eventfd, and exits
   the ring).

   Completion model: the io_uring is bound to an eventfd via
   io_uring_register_eventfd; the eventfd is registered with the tevent
   loop via tevent_add_fd. When CQEs arrive the eventfd fires, our fd
   handler drains the CQ, and each per-request truenas_uring_req signals
   its associated tevent_req via tevent_req_done() / tevent_req_error()
   once all expected CQEs have arrived (1 for normal ops, 2 for SEND_ZC's
   data + notification pair).

   The public API and internal lifecycle pattern (per-tevent_context
   ring, eventfd-driven CQE drain, multi-CQE bookkeeping for SEND_ZC,
   per-op talloc destructor with IORING_OP_ASYNC_CANCEL) are an
   adaptation of Stefan Metzmacher's `lib/util/samba_io_uring`
   abstraction from upstream Samba (gitlab !4453).

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

#include "replace.h"

/*
 * Mirror vfs_io_uring's compat dance: some distros define struct open_how
 * in liburing/compat.h directly rather than via linux/openat2.h, which
 * conflicts with libreplace. Hide their definition before including liburing.
 */
struct open_how;
#ifdef HAVE_STRUCT_OPEN_HOW_LIBURING_COMPAT_H
#define open_how __ignore_liburing_compat_h_open_how
#include <liburing/compat.h>
#undef open_how
#endif

#include "includes.h"
#include "system/filesys.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/debug.h"
#include "truenas_uring.h"

#include <liburing.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>   /* FIONREAD */
#include <sys/mman.h>
#include <fcntl.h>     /* F_SETPIPE_SZ, O_CLOEXEC */
#include <unistd.h>    /* pipe2, close */
#include <sys/socket.h>
#include <linux/if_alg.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define TRUENAS_URING_RING_SIZE 256

/*
 * Per-process registry mapping tevent_context -> truenas_uring. Smbd's
 * fork-per-connection model has one tevent_context per process; tools and
 * tests may use a handful. Eight slots is comfortable headroom.
 */
#define TRUENAS_URING_MAX_CTXS 8

/* TURING_BUSY_BITS_PER_WORD and TURING_REG_BUF_POOL_MAX live in
 * truenas_uring.h so they're visible to test code as well. */

enum truenas_uring_req_state {
	TURING_REQ_INIT = 0,
	TURING_REQ_RUNNING,
	TURING_REQ_COMPLETE,
	TURING_REQ_CANCELLED,
};

struct truenas_uring_req {
	const char *location;
	struct tevent_req *req;
	struct truenas_uring *u;

	/*
	 * Multi-CQE bookkeeping. Single-CQE ops set expected=1. SEND_ZC and
	 * SENDMSG_ZC set expected=2 -- one data CQE (with IORING_CQE_F_MORE
	 * set on success) plus one notification CQE (IORING_CQE_F_NOTIF) when
	 * the kernel releases the pinned send buffer. If the data CQE arrives
	 * WITHOUT F_MORE (error path) we shrink expected to received so the
	 * tevent_req completes after just the data CQE.
	 */
	uint8_t cqes_expected;
	uint8_t cqes_received;

	enum truenas_uring_req_state state;
	int saved_errno;
	ssize_t rv;
};

struct truenas_uring {
	struct tevent_context *ev;
	struct io_uring ring;
	int eventfd;
	struct tevent_fd *fde;

	/* Per-op-class IOSQE_ASYNC threshold; 0 = disabled (default). */
	size_t async_threshold[TURING_OP_NUM_CLASSES];

	/* Registered (pinned) buffer pool for IORING_OP_*_FIXED dispatch.
	 * NULL when no pool is registered. The iovec array is a talloc'd
	 * child of the truenas_uring.
	 */
	struct iovec *reg_iovs;
	unsigned int n_reg_iovs;

	/*
	 * Free-slot bitmap for the truenas_uring_buf_acquire/_release
	 * allocator. Bit i set means slot i is in use. Single-word width
	 * caps the pool at TURING_REG_BUF_POOL_MAX slots; lower-level
	 * _buf_index dispatch has no such cap.
	 */
	uint64_t buf_busy_mask;

	/*
	 * Backing mmap region when the pool was created via
	 * truenas_uring_register_owned_pool. NULL when the pool was
	 * registered with caller-owned buffers (or no pool). Freed by
	 * the truenas_uring destructor.
	 */
	void *owned_pool_pages;
	size_t owned_pool_bytes;

	/*
	 * Splice pipe pool (used by the SMB2 splice state machines for both
	 * inbound and outbound, signed and unsigned variants). NULL when
	 * not registered. Each entry is {rfd, wfd}; pipe_busy_words is a
	 * packed bitmap sized to
	 * ceil(n_pipes / TURING_BUSY_BITS_PER_WORD). Pipes are closed in
	 * the destructor.
	 */
	struct truenas_uring_pipe_entry {
		int rfd;
		int wfd;
	} *pipes;
	unsigned int n_pipes;
	uint64_t *pipe_busy_words;
	unsigned int n_pipe_busy_words;
	/*
	 * Remembered pipe capacity (F_SETPIPE_SZ argument from initial
	 * register_pipe_pool). The release path uses this to recreate a
	 * pipe pair with the same capacity when an in-place drain fails
	 * and the slot would otherwise leak residual bytes to the next
	 * acquirer. 0 = use kernel default (drain-recreate skips the
	 * F_SETPIPE_SZ step).
	 */
	size_t pipe_size_bytes;
};

struct registry_entry {
	const struct tevent_context *ev;
	struct truenas_uring *u;
};

static struct registry_entry registry[TRUENAS_URING_MAX_CTXS];

/*
 * Per-subsystem debug class. Primed by truenas_uring_get() on first
 * use so that callers can rely on it being valid the moment they have
 * a non-NULL truenas_uring*. Until primed, falls back to DBGC_RPC_SRV
 * so messages still appear if debug_add_class ever fails.
 */
int truenas_uring_debug_class = DBGC_RPC_SRV;
static bool truenas_uring_debug_class_primed;

static void truenas_uring_prime_debug_class(void)
{
	int c;

	if (truenas_uring_debug_class_primed) {
		return;
	}
	c = debug_add_class("truenas_uring");
	if (c >= 0) {
		truenas_uring_debug_class = c;
	}
	/* Mark primed even on failure so we don't retry on every
	 * truenas_uring_get(). */
	truenas_uring_debug_class_primed = true;
}

static struct truenas_uring *registry_find(const struct tevent_context *ev)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i].ev == ev) {
			return registry[i].u;
		}
	}
	return NULL;
}

static bool registry_add(const struct tevent_context *ev,
			 struct truenas_uring *u)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i].ev == NULL) {
			registry[i].ev = ev;
			registry[i].u = u;
			return true;
		}
	}
	return false;
}

static void registry_remove(const struct tevent_context *ev)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i].ev == ev) {
			registry[i].ev = NULL;
			registry[i].u = NULL;
			return;
		}
	}
}

/* ---------------- CQE processing ---------------- */

static void truenas_uring_complete_req(struct truenas_uring_req *ureq,
				       const struct io_uring_cqe *cqe)
{
	bool is_notif = (cqe->flags & IORING_CQE_F_NOTIF) != 0;
	bool has_more = (cqe->flags & IORING_CQE_F_MORE) != 0;

	ureq->cqes_received++;

	if (is_notif) {
		/*
		 * Notification CQE for SEND_ZC / SENDMSG_ZC: the kernel
		 * confirms it is done with the pinned send buffer. The cqe->res
		 * field is normally 0; if it carries an error (rare), we latch
		 * it without clobbering the data CQE's byte count.
		 */
		if (cqe->res < 0 && ureq->saved_errno == 0) {
			ureq->saved_errno = -cqe->res;
		}
	} else {
		/* Data CQE: cqe->res is bytes transferred or negated errno. */
		if (cqe->res < 0) {
			if (ureq->saved_errno == 0) {
				ureq->saved_errno = -cqe->res;
			}
			ureq->rv = -1;
		} else {
			ureq->rv = cqe->res;
		}

		/*
		 * If we expected more than one CQE but this data CQE lacks
		 * IORING_CQE_F_MORE, no notification is coming -- shrink the
		 * expectation so the tevent_req completes promptly.
		 */
		if (!has_more && ureq->cqes_expected > ureq->cqes_received) {
			ureq->cqes_expected = ureq->cqes_received;
		}
	}

	if (ureq->cqes_received < ureq->cqes_expected) {
		return;
	}

	if (ureq->state == TURING_REQ_CANCELLED) {
		/*
		 * The owning tevent_req is gone; complete bookkeeping only.
		 * Caller (cancel-drain loop in the destructor, or fd_handler)
		 * is responsible for the rest.
		 */
		return;
	}

	ureq->state = TURING_REQ_COMPLETE;
	if (ureq->saved_errno != 0 && ureq->rv < 0) {
		tevent_req_error(ureq->req, ureq->saved_errno);
		return;
	}
	tevent_req_done(ureq->req);
}

static void truenas_uring_drain_cqes(struct truenas_uring *u)
{
	unsigned head;
	struct io_uring_cqe *cqe = NULL;
	unsigned cnt = 0;

	io_uring_for_each_cqe(&u->ring, head, cqe) {
		void *data = io_uring_cqe_get_data(cqe);
		struct truenas_uring_req *ureq = NULL;

		cnt++;

		if (data == NULL) {
			/*
			 * Cancellation SQE CQE or other out-of-band
			 * completion -- nothing to dispatch.
			 */
			continue;
		}

		ureq = talloc_get_type_abort(data,
					     struct truenas_uring_req);
		truenas_uring_complete_req(ureq, cqe);
	}

	io_uring_cq_advance(&u->ring, cnt);
}

static void truenas_uring_fd_handler(struct tevent_context *ev,
				     struct tevent_fd *fde,
				     uint16_t flags,
				     void *private_data)
{
	struct truenas_uring *u = talloc_get_type_abort(
		private_data, struct truenas_uring);
	eventfd_t value;
	int ret;

	ret = eventfd_read(u->eventfd, &value);
	if (ret == -1 && errno != EAGAIN) {
		DBG_ERR("truenas_uring: eventfd_read failed: %s\n",
			strerror(errno));
		return;
	}

	truenas_uring_drain_cqes(u);
}

/* ---------------- Lifecycle ---------------- */

static int truenas_uring_destructor(struct truenas_uring *u)
{
	if (u->fde != NULL) {
		TALLOC_FREE(u->fde);
	}
	if (u->eventfd >= 0) {
		io_uring_queue_exit(&u->ring);
		close(u->eventfd);
		u->eventfd = -1;
	}
	if (u->owned_pool_pages != NULL) {
		munmap(u->owned_pool_pages, u->owned_pool_bytes);
		u->owned_pool_pages = NULL;
		u->owned_pool_bytes = 0;
	}
	if (u->pipes != NULL) {
		unsigned int i;
		for (i = 0; i < u->n_pipes; i++) {
			if (u->pipes[i].rfd >= 0) {
				close(u->pipes[i].rfd);
			}
			if (u->pipes[i].wfd >= 0) {
				close(u->pipes[i].wfd);
			}
		}
		TALLOC_FREE(u->pipes);
		TALLOC_FREE(u->pipe_busy_words);
		u->n_pipes = 0;
		u->n_pipe_busy_words = 0;
	}
	registry_remove(u->ev);
	return 0;
}

struct truenas_uring *truenas_uring_get(struct tevent_context *ev)
{
	struct truenas_uring *u = NULL;
	int ret;

	truenas_uring_prime_debug_class();

	u = registry_find(ev);
	if (u != NULL) {
		return u;
	}

	u = talloc_zero(ev, struct truenas_uring);
	if (u == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	u->ev = ev;
	u->eventfd = -1;
	talloc_set_destructor(u, truenas_uring_destructor);

	u->eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (u->eventfd == -1) {
		int saved_errno = errno;
		DBG_ERR("truenas_uring: eventfd() failed: %s\n",
			strerror(saved_errno));
		TALLOC_FREE(u);
		errno = saved_errno;
		return NULL;
	}

	ret = io_uring_queue_init(TRUENAS_URING_RING_SIZE, &u->ring, 0);
	if (ret < 0) {
		DBG_ERR("truenas_uring: io_uring_queue_init failed: %s\n",
			strerror(-ret));
		close(u->eventfd);
		u->eventfd = -1;
		TALLOC_FREE(u);
		errno = -ret;
		return NULL;
	}

	ret = io_uring_register_eventfd(&u->ring, u->eventfd);
	if (ret < 0) {
		DBG_ERR("truenas_uring: io_uring_register_eventfd failed: %s\n",
			strerror(-ret));
		io_uring_queue_exit(&u->ring);
		close(u->eventfd);
		u->eventfd = -1;
		TALLOC_FREE(u);
		errno = -ret;
		return NULL;
	}

	u->fde = tevent_add_fd(ev, u, u->eventfd, TEVENT_FD_READ,
			       truenas_uring_fd_handler, u);
	if (u->fde == NULL) {
		DBG_ERR("truenas_uring: tevent_add_fd failed for eventfd\n");
		TALLOC_FREE(u);
		errno = ENOMEM;
		return NULL;
	}

	if (!registry_add(ev, u)) {
		DBG_ERR("truenas_uring: registry full (max %d contexts)\n",
			TRUENAS_URING_MAX_CTXS);
		TALLOC_FREE(u);
		errno = ENOSPC;
		return NULL;
	}

	DBG_INFO("truenas_uring: initialized ring (size=%d, fd=%d) for ev=%p\n",
		 TRUENAS_URING_RING_SIZE, u->eventfd, ev);
	return u;
}

void truenas_uring_set_async_threshold(struct truenas_uring *u,
				       enum truenas_uring_op_class op_class,
				       size_t threshold_bytes)
{
	if (op_class >= TURING_OP_NUM_CLASSES) {
		return;
	}
	u->async_threshold[op_class] = threshold_bytes;
}

/*
 * Cap the kernel io-wq worker pool for this ring. Bounds how many blocking
 * ops (IOSQE_ASYNC reads/writes/splices punted off the main loop) run
 * concurrently -- i.e. the real "max io_uring op concurrency" for this
 * process. Critical at high process counts: the kernel default is large
 * (~512 bounded workers per ring), so thousands of smbds could otherwise
 * spawn an unbounded number of worker threads. values[0]=bounded (regular
 * file/blocking I/O), values[1]=unbounded (poll-driven net I/O); 0 leaves a
 * class at the kernel default. Returns 0 or -errno (non-fatal).
 */
int truenas_uring_set_iowq_max_workers(struct truenas_uring *u,
				       unsigned int bounded,
				       unsigned int unbounded)
{
	unsigned int values[2] = { bounded, unbounded };
	int ret = io_uring_register_iowq_max_workers(&u->ring, values);
	if (ret < 0) {
		DBG_WARNING("truenas_uring: iowq_max_workers(%u,%u) failed: "
			    "%s\n", bounded, unbounded, strerror(-ret));
	}
	return ret;
}

/* ---------------- Registered buffer pool ---------------- */

int truenas_uring_register_buffers(struct truenas_uring *u,
				   const struct iovec *iovs,
				   unsigned int nr)
{
	struct iovec *copy = NULL;
	int ret;

	if (u->reg_iovs != NULL) {
		return -EBUSY;
	}
	if (nr == 0 || iovs == NULL) {
		return -EINVAL;
	}

	copy = talloc_array(u, struct iovec, nr);
	if (copy == NULL) {
		return -ENOMEM;
	}
	memcpy(copy, iovs, nr * sizeof(*iovs));

	ret = io_uring_register_buffers(&u->ring, iovs, nr);
	if (ret < 0) {
		DBG_ERR("truenas_uring: io_uring_register_buffers(nr=%u) "
			"failed: %s\n", nr, strerror(-ret));
		TALLOC_FREE(copy);
		return ret;
	}

	u->reg_iovs = copy;
	u->n_reg_iovs = nr;
	return 0;
}

int truenas_uring_unregister_buffers(struct truenas_uring *u)
{
	int ret;

	if (u->reg_iovs == NULL) {
		return -ENOENT;
	}

	ret = io_uring_unregister_buffers(&u->ring);
	if (ret < 0) {
		DBG_ERR("truenas_uring: io_uring_unregister_buffers failed: %s\n",
			strerror(-ret));
		/* Drop our tracking anyway -- the ring may be in an odd
		 * state, but we cannot do better. */
	}

	TALLOC_FREE(u->reg_iovs);
	u->n_reg_iovs = 0;
	u->buf_busy_mask = 0;
	return ret < 0 ? ret : 0;
}

int truenas_uring_buf_index(struct truenas_uring *u, const void *ptr)
{
	unsigned int i;
	const uint8_t *p = ptr;

	if (u->reg_iovs == NULL || ptr == NULL) {
		return -1;
	}

	for (i = 0; i < u->n_reg_iovs; i++) {
		const uint8_t *base = u->reg_iovs[i].iov_base;
		size_t len = u->reg_iovs[i].iov_len;

		if (p >= base && p < base + len) {
			return (int)i;
		}
	}
	return -1;
}

int truenas_uring_buf_acquire(struct truenas_uring *u, size_t size_hint)
{
	unsigned int i;
	unsigned int limit;

	if (u->reg_iovs == NULL) {
		return -1;
	}

	limit = u->n_reg_iovs < TURING_REG_BUF_POOL_MAX ?
		u->n_reg_iovs : TURING_REG_BUF_POOL_MAX;
	for (i = 0; i < limit; i++) {
		uint64_t bit = (uint64_t)1 << i;

		if (u->buf_busy_mask & bit) {
			continue;  /* in use */
		}
		if (u->reg_iovs[i].iov_len < size_hint) {
			continue;  /* too small */
		}
		u->buf_busy_mask |= bit;
		return (int)i;
	}
	return -1;
}

void truenas_uring_buf_release(struct truenas_uring *u, int slot)
{
	if (slot < 0 || (unsigned int)slot >= TURING_REG_BUF_POOL_MAX) {
		return;
	}
	u->buf_busy_mask &= ~((uint64_t)1 << slot);
}

void *truenas_uring_buf_data(struct truenas_uring *u, int slot,
			     size_t *size_out)
{
	if (u->reg_iovs == NULL ||
	    slot < 0 || (unsigned int)slot >= u->n_reg_iovs) {
		return NULL;
	}
	if (size_out != NULL) {
		*size_out = u->reg_iovs[slot].iov_len;
	}
	return u->reg_iovs[slot].iov_base;
}

int truenas_uring_register_owned_pool(struct truenas_uring *u,
				      unsigned int nr,
				      size_t bufsize)
{
	void *pages = NULL;
	size_t total;
	struct iovec *iovs = NULL;
	unsigned int i;
	int ret;

	if (u->reg_iovs != NULL || u->owned_pool_pages != NULL) {
		return -EBUSY;
	}
	if (nr == 0 || nr > TURING_REG_BUF_POOL_MAX || bufsize == 0) {
		return -EINVAL;
	}
	total = (size_t)nr * bufsize;

	pages = mmap(NULL, total, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pages == MAP_FAILED) {
		return -errno;
	}

	iovs = talloc_array(u, struct iovec, nr);
	if (iovs == NULL) {
		munmap(pages, total);
		return -ENOMEM;
	}
	for (i = 0; i < nr; i++) {
		iovs[i].iov_base = (uint8_t *)pages + (size_t)i * bufsize;
		iovs[i].iov_len = bufsize;
	}

	ret = truenas_uring_register_buffers(u, iovs, nr);
	TALLOC_FREE(iovs);  /* register_buffers makes its own copy */
	if (ret < 0) {
		munmap(pages, total);
		return ret;
	}

	u->owned_pool_pages = pages;
	u->owned_pool_bytes = total;
	DBG_INFO("truenas_uring: owned pool registered (nr=%u, bufsize=%zu)\n",
		 nr, bufsize);
	return 0;
}

int truenas_uring_register_pipe_pool(struct truenas_uring *u,
				     unsigned int nr,
				     size_t pipe_size_bytes)
{
	struct truenas_uring_pipe_entry *pipes = NULL;
	uint64_t *busy_words = NULL;
	unsigned int n_words;
	unsigned int i;
	int saved_errno;

	if (u->pipes != NULL) {
		return -EBUSY;
	}
	if (nr == 0) {
		return -EINVAL;
	}

	n_words = (nr + TURING_BUSY_BITS_PER_WORD - 1) /
		  TURING_BUSY_BITS_PER_WORD;
	busy_words = talloc_zero_array(u, uint64_t, n_words);
	if (busy_words == NULL) {
		return -ENOMEM;
	}
	pipes = talloc_array(u, struct truenas_uring_pipe_entry, nr);
	if (pipes == NULL) {
		TALLOC_FREE(busy_words);
		return -ENOMEM;
	}
	/* Initialize to -1 so partial-failure teardown is safe. */
	for (i = 0; i < nr; i++) {
		pipes[i].rfd = -1;
		pipes[i].wfd = -1;
	}

	for (i = 0; i < nr; i++) {
		int fds[2];
		/*
		 * Blocking pipes (no O_NONBLOCK). Inbound splice (signed or
		 * unsigned) requires consuming exactly unread_bytes from the
		 * socket -- short splices on a full non-blocking pipe leave
		 * bytes on the wire that the next PDU parse would
		 * misinterpret as garbage. With blocking pipes the kernel
		 * waits for pipe room; under io_uring the wait happens on a
		 * worker thread so the main loop isn't blocked.
		 */
		if (pipe2(fds, O_CLOEXEC) == -1) {
			saved_errno = errno;
			goto teardown;
		}
		pipes[i].rfd = fds[0];
		pipes[i].wfd = fds[1];
		if (pipe_size_bytes > 0) {
			/*
			 * F_SETPIPE_SZ rounds up to a power of 2. Without
			 * CAP_SYS_RESOURCE the requested size is also capped
			 * at /proc/sys/fs/pipe-max-size (1 MiB on a stock
			 * kernel) and oversize requests return EPERM; with
			 * CAP_SYS_RESOURCE the cap is bypassed. smbd runs as
			 * root on TrueNAS so the bypass applies and we
			 * confidently size pipes to lp_smb2_max_write
			 * (default 8 MiB) without needing the operator to
			 * bump the sysctl. Failure is still non-fatal -- the
			 * pipe stays at the kernel default (16 pages = 64
			 * KiB) and the splice paths handle short pipe
			 * capacity with chunked transfers.
			 */
			if (fcntl(fds[1], F_SETPIPE_SZ,
				  (int)pipe_size_bytes) == -1) {
				DBG_WARNING("truenas_uring: F_SETPIPE_SZ(%zu) "
					    "failed: %s (using default pipe "
					    "size)\n",
					    pipe_size_bytes, strerror(errno));
			}
		}
	}

	u->pipes = pipes;
	u->n_pipes = nr;
	u->pipe_busy_words = busy_words;
	u->n_pipe_busy_words = n_words;
	u->pipe_size_bytes = pipe_size_bytes;
	DBG_INFO("truenas_uring: pipe pool registered (nr=%u, size=%zu)\n",
		 nr, pipe_size_bytes);
	return 0;

teardown:
	for (i = 0; i < nr; i++) {
		if (pipes[i].rfd >= 0) {
			close(pipes[i].rfd);
		}
		if (pipes[i].wfd >= 0) {
			close(pipes[i].wfd);
		}
	}
	TALLOC_FREE(pipes);
	TALLOC_FREE(busy_words);
	return -saved_errno;
}

struct truenas_uring_pipe truenas_uring_pipe_acquire(struct truenas_uring *u)
{
	struct truenas_uring_pipe none = { .rfd = -1, .wfd = -1, .slot = -1 };
	unsigned int w;

	if (u->pipes == NULL || u->pipe_busy_words == NULL) {
		return none;
	}
	/*
	 * Scan the busy bitmap one word at a time, skipping fully-busy
	 * words immediately. ffsll on the bit-complement gives the first
	 * free slot within the word; faster than a per-bit loop for
	 * sparse-busy pools.
	 */
	for (w = 0; w < u->n_pipe_busy_words; w++) {
		uint64_t free_bits = ~u->pipe_busy_words[w];
		int bit;
		unsigned int slot;

		if (free_bits == 0) {
			continue;
		}
		bit = __builtin_ffsll((long long)free_bits) - 1;
		slot = w * TURING_BUSY_BITS_PER_WORD + (unsigned int)bit;
		if (slot >= u->n_pipes) {
			/* Past the end -- happens when n_pipes isn't a
			 * multiple of TURING_BUSY_BITS_PER_WORD; the tail
			 * bits in the last word are unused. */
			return none;
		}
		u->pipe_busy_words[w] |= ((uint64_t)1 << bit);
		return (struct truenas_uring_pipe){
			.rfd = u->pipes[slot].rfd,
			.wfd = u->pipes[slot].wfd,
			.slot = (int)slot,
		};
	}
	return none;
}

size_t truenas_uring_pipe_capacity(struct truenas_uring *u)
{
	if (u == NULL) {
		return 0;
	}
	return u->pipe_size_bytes;
}

/* ---------------- AF_ALG HMAC sockets (signed splice) ---------------- */

int truenas_uring_hmac_open(const char *alg_name,
			    const void *key, size_t keylen)
{
	struct sockaddr_alg sa = { .salg_family = AF_ALG };
	int fd;
	int saved_errno;

	if (alg_name == NULL || strlen(alg_name) >= sizeof(sa.salg_name)) {
		return -EINVAL;
	}
	strlcpy((char *)sa.salg_type, "hash", sizeof(sa.salg_type));
	strlcpy((char *)sa.salg_name, alg_name, sizeof(sa.salg_name));

	fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		return -errno;
	}
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		saved_errno = errno;
		close(fd);
		return -saved_errno;
	}
	if (key != NULL && keylen > 0) {
		if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, keylen) == -1) {
			saved_errno = errno;
			close(fd);
			return -saved_errno;
		}
	}
	return fd;
}

int truenas_uring_hmac_compute(int hmac_bind_fd,
			       const void *header, size_t header_len,
			       int pipe_rfd, size_t payload_len,
			       void *mac_out, size_t mac_len)
{
	int op_fd = -1;
	ssize_t n;
	int saved_errno;

	op_fd = accept4(hmac_bind_fd, NULL, NULL, SOCK_CLOEXEC);
	if (op_fd == -1) {
		return -errno;
	}

	/* Feed header bytes first (typically the SMB2 transform header with
	 * the signature field zeroed). MSG_MORE keeps the hash state open. */
	if (header != NULL && header_len > 0) {
		n = send(op_fd, header, header_len,
			 (payload_len > 0) ? MSG_MORE : 0);
		if (n < 0 || (size_t)n != header_len) {
			saved_errno = (n < 0) ? errno : EIO;
			close(op_fd);
			return -saved_errno;
		}
	}

	/* Splice payload bytes from pipe into the hash op. algif_hash
	 * doesn't (yet) implement MSG_SPLICE_PAGES, so the kernel falls
	 * back to copying the pipe pages into the AHASH request inside
	 * splice_to_socket. Net: one in-kernel copy per payload byte, but
	 * the bytes never enter userspace and HMAC uses AES-NI / PMULL. */
	if (pipe_rfd >= 0 && payload_len > 0) {
		size_t remaining = payload_len;
		while (remaining > 0) {
			n = splice(pipe_rfd, NULL, op_fd, NULL, remaining, 0);
			if (n <= 0) {
				saved_errno = (n < 0) ? errno : EIO;
				close(op_fd);
				return -saved_errno;
			}
			remaining -= (size_t)n;
		}
	}

	/* Final read returns the digest. */
	n = read(op_fd, mac_out, mac_len);
	saved_errno = errno;
	close(op_fd);
	if (n < 0) {
		return -saved_errno;
	}
	if ((size_t)n != mac_len) {
		return -EIO;
	}
	return 0;
}

void truenas_uring_hmac_close(int hmac_bind_fd)
{
	if (hmac_bind_fd >= 0) {
		close(hmac_bind_fd);
	}
}

/*
 * Replace the pipe pair backing `slot` with a freshly-created one.
 * Called from truenas_uring_pipe_release when the in-place drain
 * cannot guarantee the pipe is empty (read() returned <= 0 with
 * bytes still queued). Guarantees the next acquirer of this slot
 * sees a pristine pipe rather than residual bytes from a failed
 * drain.
 *
 * Returns true on success. On failure (pipe2 ENOMEM/ENFILE/etc.)
 * the slot's fds are left at -1; caller must NOT clear the busy bit
 * for this slot -- effectively retiring it from the pool rather than
 * handing back a half-broken slot.
 */
static bool truenas_uring_pipe_replace_pair(struct truenas_uring *u, int slot)
{
	int fds[2];

	if (u->pipes[slot].rfd >= 0) {
		close(u->pipes[slot].rfd);
		u->pipes[slot].rfd = -1;
	}
	if (u->pipes[slot].wfd >= 0) {
		close(u->pipes[slot].wfd);
		u->pipes[slot].wfd = -1;
	}
	if (pipe2(fds, O_CLOEXEC) == -1) {
		int saved_errno = errno;
		/*
		 * Loud log at ERROR level via the truenas_uring class so
		 * operators see the degradation immediately even without
		 * `log level = truenas_uring:N`. The pool capacity for
		 * splice fast paths just shrank by one for the remaining
		 * lifetime of this smbd worker (= this connection in the
		 * fork-per-conn model). Repeated occurrences indicate fd
		 * exhaustion or kernel-side pipe-creation limits being
		 * hit; the operator should investigate.
		 */
		DBGC_ERR(truenas_uring_debug_class,
			 "pipe pool slot %d retired: in-place drain failed "
			 "and pipe2() recreate failed (%s). Pool capacity "
			 "for this smbd worker reduced by one; remaining "
			 "splice ops continue. If this repeats, check "
			 "RLIMIT_NOFILE, /proc/sys/fs/pipe-user-pages-soft, "
			 "and overall system fd usage. A reconnect "
			 "(client-side) or smbd restart restores full "
			 "capacity.\n",
			 slot, strerror(saved_errno));
		return false;
	}
	if (u->pipe_size_bytes > 0) {
		/* Best-effort F_SETPIPE_SZ: same fallback behavior as
		 * the initial registration. */
		(void)fcntl(fds[1], F_SETPIPE_SZ,
			    (int)u->pipe_size_bytes);
	}
	u->pipes[slot].rfd = fds[0];
	u->pipes[slot].wfd = fds[1];
	return true;
}

void truenas_uring_pipe_release(struct truenas_uring *u, int slot)
{
	int rfd;
	int avail = 0;
	bool drained_clean = true;

	if (slot < 0 || (unsigned int)slot >= u->n_pipes ||
	    u->pipe_busy_words == NULL) {
		return;
	}
	rfd = u->pipes[slot].rfd;
	/*
	 * Check whether the pipe carries leftover bytes from a failed or
	 * partial splice op. On the happy path the state machine drains
	 * the pipe end-to-end, so this is a 1-syscall NOP. On the error
	 * paths FIONREAD's reported byte count lets us drain via a
	 * blocking read sized exactly to what is queued.
	 *
	 * If FIONREAD itself fails or the drain doesn't complete cleanly
	 * (signal-interrupted read, unexpected EOF, etc.), recreate the
	 * pipe pair so residual bytes can never leak to the next acquirer
	 * of this slot.
	 */
	if (ioctl(rfd, FIONREAD, &avail) == -1) {
		drained_clean = false;
	} else if (avail > 0) {
		char drain_buf[4096];
		while (avail > 0) {
			size_t want = (size_t)avail < sizeof(drain_buf) ?
				      (size_t)avail : sizeof(drain_buf);
			ssize_t r = read(rfd, drain_buf, want);
			if (r < 0 && errno == EINTR) {
				continue;  /* signal interrupted; retry */
			}
			if (r <= 0) {
				drained_clean = false;
				break;
			}
			avail -= (int)r;
		}
	}
	if (!drained_clean) {
		if (!truenas_uring_pipe_replace_pair(u, slot)) {
			/*
			 * Replacement failed -- the slot is permanently
			 * unusable. Leave the busy bit SET so acquire
			 * never hands it back out. Effectively retires
			 * the slot from the pool for the worker's
			 * lifetime; the loud log from
			 * truenas_uring_pipe_replace_pair has already
			 * fired.
			 */
			return;
		}
	}
	u->pipe_busy_words[slot / TURING_BUSY_BITS_PER_WORD] &=
		~((uint64_t)1 << (slot % TURING_BUSY_BITS_PER_WORD));
}

/* ---------------- Per-request helpers ---------------- */

/*
 * Destructor: synchronous cancellation of in-flight SQEs. On entry the
 * owning tevent_req is being freed; we must ensure the kernel does not
 * later dereference user_data pointing to our (about-to-be-freed)
 * struct truenas_uring_req.
 *
 * Strategy: mark CANCELLED (so complete_req short-circuits the tevent_req
 * notification), submit IORING_OP_ASYNC_CANCEL, then drain CQEs until all
 * of ours have arrived. CQEs that belong to other in-flight requests are
 * processed normally (tevent_req_done schedules an immediate event rather
 * than running the callback synchronously, so no re-entry hazard).
 */
static int truenas_uring_req_destructor(struct truenas_uring_req *ureq)
{
	struct io_uring_sqe *cancel_sqe = NULL;
	struct io_uring_cqe *cqe = NULL;
	int ret;

	if (ureq->state != TURING_REQ_RUNNING) {
		return 0;
	}

	ureq->state = TURING_REQ_CANCELLED;

	cancel_sqe = io_uring_get_sqe(&ureq->u->ring);
	if (cancel_sqe == NULL) {
		/*
		 * SQ full; we can't issue the cancel. Refusing the free
		 * (returning non-zero) leaks ureq but prevents UAF.
		 */
		DBG_ERR("truenas_uring: no SQE for cancel at %s; "
			"leaking req %p\n",
			ureq->location, ureq);
		return -1;
	}
	io_uring_prep_cancel(cancel_sqe, ureq, 0);
	io_uring_sqe_set_data(cancel_sqe, NULL);

	ret = io_uring_submit(&ureq->u->ring);
	if (ret < 0) {
		DBG_ERR("truenas_uring: cancel submit failed at %s: %s; "
			"leaking req %p\n",
			ureq->location, strerror(-ret), ureq);
		return -1;
	}

	/* Drain until all expected CQEs for our request have arrived. */
	while (ureq->cqes_received < ureq->cqes_expected) {
		void *data = NULL;
		struct truenas_uring_req *target = NULL;

		ret = io_uring_wait_cqe(&ureq->u->ring, &cqe);
		if (ret < 0) {
			DBG_ERR("truenas_uring: wait_cqe in cancel "
				"failed at %s: %s; leaking req %p\n",
				ureq->location, strerror(-ret), ureq);
			return -1;
		}

		data = io_uring_cqe_get_data(cqe);
		if (data == NULL) {
			/* Cancel SQE's own CQE; skip. */
			io_uring_cqe_seen(&ureq->u->ring, cqe);
			continue;
		}

		target = talloc_get_type_abort(data,
					       struct truenas_uring_req);
		truenas_uring_complete_req(target, cqe);
		io_uring_cqe_seen(&ureq->u->ring, cqe);
	}

	return 0;
}

/* Acquire a fresh tevent_req + ureq + SQE triple. */
static struct tevent_req *truenas_uring_op_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 const char *location,
						 uint8_t cqes_expected,
						 struct truenas_uring **u_out,
						 struct io_uring_sqe **sqe_out,
						 struct truenas_uring_req **ureq_out)
{
	struct tevent_req *req = NULL;
	struct truenas_uring_req *ureq = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;

	req = tevent_req_create(mem_ctx, &ureq, struct truenas_uring_req);
	if (req == NULL) {
		return NULL;
	}

	u = truenas_uring_get(ev);
	if (u == NULL) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	sqe = io_uring_get_sqe(&u->ring);
	if (sqe == NULL) {
		tevent_req_error(req, EAGAIN);
		return tevent_req_post(req, ev);
	}

	ureq->location = location;
	ureq->req = req;
	ureq->u = u;
	ureq->cqes_expected = cqes_expected;
	ureq->state = TURING_REQ_INIT;
	talloc_set_destructor(ureq, truenas_uring_req_destructor);

	*u_out = u;
	*sqe_out = sqe;
	*ureq_out = ureq;
	return req;
}

static bool truenas_uring_op_submit(struct tevent_req *req,
				    struct truenas_uring *u,
				    struct io_uring_sqe *sqe,
				    struct truenas_uring_req *ureq,
				    uint8_t sqe_flags)
{
	int ret;

	if (sqe_flags != 0) {
		sqe->flags |= sqe_flags;
	}
	io_uring_sqe_set_data(sqe, ureq);
	ureq->state = TURING_REQ_RUNNING;

	ret = io_uring_submit(&u->ring);
	if (ret < 0) {
		/*
		 * Submit failed but the SQE is still queued in the userspace
		 * SQ ring -- a later successful submit would dispatch it with
		 * user_data still pointing at our (about-to-be-freed) request.
		 * Convert it to a no-op with NULL user_data so any future
		 * submit is harmless and the CQE handler ignores it.
		 */
		io_uring_prep_nop(sqe);
		io_uring_sqe_set_data(sqe, NULL);

		ureq->state = TURING_REQ_COMPLETE;
		tevent_req_error(req, -ret);
		return false;
	}
	return true;
}

static ssize_t truenas_uring_op_recv(struct tevent_req *req, int *perrno)
{
	const struct truenas_uring_req *ureq = tevent_req_data(
		req, struct truenas_uring_req);

	if (tevent_req_is_unix_error(req, perrno)) {
		return -1;
	}
	if (perrno != NULL) {
		*perrno = 0;
	}
	return ureq->rv;
}

/* IOSQE_ASYNC flag derived from per-uring threshold. */
static uint8_t async_flag_for(struct truenas_uring *u,
			      enum truenas_uring_op_class op_class,
			      size_t bytes)
{
	size_t threshold = u->async_threshold[op_class];

	if (threshold == 0 || bytes < threshold) {
		return 0;
	}
	return IOSQE_ASYNC;
}

static size_t msghdr_total_iov_len(const struct msghdr *msg);

/* ---------------- PREAD ---------------- */

struct tevent_req *_truenas_uring_pread_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      int fd,
					      void *buf,
					      size_t count,
					      off_t offset,
					      const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	{
		int bidx = truenas_uring_buf_index(u, buf);
		if (bidx >= 0) {
			io_uring_prep_read_fixed(sqe, fd, buf, count,
						 offset, bidx);
		} else {
			io_uring_prep_read(sqe, fd, buf, count, offset);
		}
	}

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_READ_CLASS,
						    count))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_pread_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- PWRITE ---------------- */

struct tevent_req *_truenas_uring_pwrite_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       int fd,
					       const void *buf,
					       size_t count,
					       off_t offset,
					       const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	{
		int bidx = truenas_uring_buf_index(u, buf);
		if (bidx >= 0) {
			io_uring_prep_write_fixed(sqe, fd, buf, count,
						  offset, bidx);
		} else {
			io_uring_prep_write(sqe, fd, buf, count, offset);
		}
	}

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_WRITE_CLASS,
						    count))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_pwrite_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- PWRITE V2 (writev2 + RWF flags) ---------------- */

struct tevent_req *_truenas_uring_pwrite_v2_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  int fd,
						  const void *buf,
						  size_t count,
						  off_t offset,
						  int rwf_flags,
						  const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;
	struct iovec *iov = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	/*
	 * iov must remain valid until the CQE is reaped; the kernel may
	 * dereference it lazily under IOSQE_ASYNC. Anchor it to ureq's
	 * talloc context (lifetime = duration of the tevent_req).
	 */
	iov = talloc(ureq, struct iovec);
	if (iov == NULL) {
		io_uring_prep_nop(sqe);
		io_uring_sqe_set_data(sqe, NULL);
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}
	iov->iov_base = discard_const(buf);
	iov->iov_len = count;

	io_uring_prep_writev2(sqe, fd, iov, 1, offset, rwf_flags);

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_WRITE_CLASS,
						    count))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_pwrite_v2_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- FSYNC ---------------- */

struct tevent_req *_truenas_uring_fsync_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      int fd,
					      unsigned int flags,
					      const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	io_uring_prep_fsync(sqe, fd, flags);

	/* fsync has no byte count -- never IOSQE_ASYNC. */
	if (!truenas_uring_op_submit(req, u, sqe, ureq, 0)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

int truenas_uring_fsync_recv(struct tevent_req *req, int *perrno)
{
	ssize_t rv = truenas_uring_op_recv(req, perrno);
	return rv < 0 ? -1 : 0;
}

/* ---------------- SPLICE ---------------- */

struct tevent_req *_truenas_uring_splice_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       int fd_in,
					       const int64_t *off_in,
					       int fd_out,
					       const int64_t *off_out,
					       size_t len,
					       unsigned int splice_flags,
					       const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;
	int64_t in_off = off_in ? *off_in : -1;
	int64_t out_off = off_out ? *off_out : -1;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	io_uring_prep_splice(sqe, fd_in, in_off, fd_out, out_off,
			     len, splice_flags);

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_WRITE_CLASS,
						    len))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_splice_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- RECV ---------------- */

struct tevent_req *_truenas_uring_recv_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     int sockfd,
					     void *buf,
					     size_t len,
					     int msg_flags,
					     const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	io_uring_prep_recv(sqe, sockfd, buf, len, msg_flags);

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_READ_CLASS,
						    len))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_recv_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- SEND (non-ZC) ---------------- */

struct tevent_req *_truenas_uring_send_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     int sockfd,
					     const void *buf,
					     size_t len,
					     int msg_flags,
					     const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	io_uring_prep_send(sqe, sockfd, buf, len, msg_flags);

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_WRITE_CLASS,
						    len))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_send_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- SENDMSG (non-ZC) ---------------- */

struct tevent_req *_truenas_uring_sendmsg_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						int sockfd,
						const struct msghdr *msg,
						int msg_flags,
						const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	io_uring_prep_sendmsg(sqe, sockfd, msg, msg_flags);

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_WRITE_CLASS,
						    msghdr_total_iov_len(msg)))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_sendmsg_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- RECVMSG ---------------- */

struct tevent_req *_truenas_uring_recvmsg_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						int sockfd,
						struct msghdr *msg,
						int msg_flags,
						const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/1,
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	io_uring_prep_recvmsg(sqe, sockfd, msg, msg_flags);

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_READ_CLASS,
						    msghdr_total_iov_len(msg)))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_recvmsg_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- SEND_ZC ---------------- */

struct tevent_req *_truenas_uring_send_zc_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						int sockfd,
						const void *buf,
						size_t len,
						int msg_flags,
						unsigned int zc_flags,
						const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/2,  /* data + notif */
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	{
		int bidx = truenas_uring_buf_index(u, buf);
		if (bidx >= 0) {
			io_uring_prep_send_zc_fixed(sqe, sockfd, buf, len,
						    msg_flags, zc_flags,
						    bidx);
		} else {
			io_uring_prep_send_zc(sqe, sockfd, buf, len,
					      msg_flags, zc_flags);
		}
	}

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_WRITE_CLASS,
						    len))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_send_zc_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}

/* ---------------- SENDMSG_ZC ---------------- */

static size_t msghdr_total_iov_len(const struct msghdr *msg)
{
	size_t total = 0;
	size_t i;

	if (msg == NULL || msg->msg_iov == NULL) {
		return 0;
	}
	for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
		total += msg->msg_iov[i].iov_len;
	}
	return total;
}

struct tevent_req *_truenas_uring_sendmsg_zc_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   int sockfd,
						   const struct msghdr *msg,
						   int msg_flags,
						   const char *location)
{
	struct tevent_req *req = NULL;
	struct truenas_uring *u = NULL;
	struct io_uring_sqe *sqe = NULL;
	struct truenas_uring_req *ureq = NULL;

	req = truenas_uring_op_send(mem_ctx, ev, location,
				    /*cqes_expected=*/2,  /* data + notif */
				    &u, &sqe, &ureq);
	if (req == NULL || !tevent_req_is_in_progress(req)) {
		return req;
	}

	io_uring_prep_sendmsg_zc(sqe, sockfd, msg, msg_flags);

	if (!truenas_uring_op_submit(req, u, sqe, ureq,
				     async_flag_for(u, TURING_OP_WRITE_CLASS,
						    msghdr_total_iov_len(msg)))) {
		return tevent_req_post(req, ev);
	}
	return req;
}

ssize_t truenas_uring_sendmsg_zc_recv(struct tevent_req *req, int *perrno)
{
	return truenas_uring_op_recv(req, perrno);
}
