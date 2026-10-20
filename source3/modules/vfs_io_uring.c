/*
 * Use the io_uring of Linux (>= 5.1)
 *
 * Copyright (C) Volker Lendecke 2008
 * Copyright (C) Jeremy Allison 2010
 * Copyright (C) Stefan Metzmacher 2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "replace.h"

/*
 * liburing.h only needs a forward declaration
 * of struct open_how.
 *
 * If struct open_how is defined in liburing/compat.h
 * itself, hide it away in order to avoid conflicts
 * with including linux/openat2.h or defining 'struct open_how'
 * in libreplace.
 */
struct open_how;
#ifdef HAVE_STRUCT_OPEN_HOW_LIBURING_COMPAT_H
#define open_how __ignore_liburing_compat_h_open_how
#include <liburing/compat.h>
#undef open_how
#endif /* HAVE_STRUCT_OPEN_HOW_LIBURING_COMPAT_H */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/sys_rw.h"
#include "lib/util/iov_buf.h"
#include "smbprofile.h"
#include <liburing.h>

#define	IO_URING_ASYNC_READ	0x01
#define	IO_URING_ASYNC_WRITE	0x02
#define	IO_URING_ASYNC_FSYNC	0x04

#define	VFS_URING_WRITEQ_DEFAULT	10
#define	VFS_URING_READQ_DEFAULT		20

static int vfs_io_uring_debug_level = DBGC_VFS;

#undef	DBGC_CLASS
#define	DBGC_CLASS vfs_io_uring_debug_level

struct vfs_io_uring_request;

struct vfs_io_uring_queue_config {
	int queue_sz;
	uint op_cnt;
	uint sync_cnt;
	uint async_cnt;
};

struct vfs_io_uring_batch {
	struct vfs_attr_entry *ents;	/* the caller's, filled at the wait */
	size_t count;
	size_t done;
};

struct vfs_io_uring_config {
	struct io_uring uring;
	struct tevent_fd *fde;
	/* recursion guard. See comment above vfs_io_uring_queue_run() */
	bool busy;
	/* recursion guard. See comment above vfs_io_uring_queue_run() */
	bool need_retry;
	int async_ops;
	struct vfs_io_uring_request *queue;
	struct vfs_io_uring_request *pending;
	struct vfs_io_uring_queue_config writeq;
	struct vfs_io_uring_queue_config readq;

	/* the batch ops' ring; their completions stay out of fde's */
	struct io_uring batch;
	bool batch_ready;
	bool batch_failed;
	bool fake_dctime;
	struct vfs_io_uring_batch inflight;
	uint16_t batch_personality;	/* root's, 0 if unregistered */
	struct statx *batch_bufs;
};

static int vfs_io_uring_batch_reap(struct vfs_io_uring_config *config,
				   struct vfs_attr_entry *ents);

struct vfs_io_uring_request {
	struct vfs_io_uring_request *prev, *next;
	struct vfs_io_uring_request **list_head;
	struct vfs_io_uring_config *config;
	struct tevent_req *req;
	void (*completion_fn)(struct vfs_io_uring_request *cur,
			      const char *location);
	int (*destructor_fn)(void *);
	struct timespec start_time;
	struct timespec end_time;
	unsigned sqe_flags;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
};

static void vfs_io_uring_finish_req(struct vfs_io_uring_request *cur,
				    const struct io_uring_cqe *cqe,
				    struct timespec end_time,
				    const char *location)
{
	struct tevent_req *req =
		talloc_get_type_abort(cur->req,
		struct tevent_req);
	void *state = _tevent_req_data(req);

	talloc_set_destructor(state, NULL);
	if (cur->list_head != NULL) {
		DLIST_REMOVE((*cur->list_head), cur);
		cur->list_head = NULL;
	}
	cur->cqe = *cqe;

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(cur->profile_bytes);
	cur->end_time = end_time;

	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */
	cur->completion_fn(cur, location);
}

static void vfs_io_uring_config_destroy(struct vfs_io_uring_config *config,
				        int ret,
				        const char *location)
{
	struct vfs_io_uring_request *cur = NULL, *next = NULL;
	struct timespec start_time;
	struct timespec end_time;
	struct io_uring_cqe err_cqe = {
		.res = ret,
	};

	PROFILE_TIMESTAMP(&start_time);

	if (config->batch_ready) {
		if (config->inflight.count != 0) {
			/* the kernel still writes batch_bufs */
			(void)vfs_io_uring_batch_reap(config, NULL);
		}
		io_uring_queue_exit(&config->batch);
		config->batch_ready = false;
	}
	config->batch_failed = true;

	if (config->uring.ring_fd != -1) {
		/* TODO: cancel queued and pending requests */
		TALLOC_FREE(config->fde);
		io_uring_queue_exit(&config->uring);
		config->uring.ring_fd = -1;
	}

	PROFILE_TIMESTAMP(&end_time);

	for (cur = config->pending; cur != NULL; cur = next) {
		next = cur->next;
		err_cqe.user_data = (uintptr_t)(void *)cur;
		vfs_io_uring_finish_req(cur, &err_cqe, end_time, location);
	}

	for (cur = config->queue; cur != NULL; cur = next) {
		next = cur->next;
		err_cqe.user_data = (uintptr_t)(void *)cur;
		cur->start_time = start_time;
		vfs_io_uring_finish_req(cur, &err_cqe, end_time, location);
	}
}

static int vfs_io_uring_config_destructor(struct vfs_io_uring_config *config)
{
	vfs_io_uring_config_destroy(config, -EUCLEAN, __location__);
	return 0;
}

static int vfs_io_uring_request_state_deny_destructor(struct vfs_io_uring_request *cur)
{
	/* our parent is gone */
	cur->req = NULL;

	/* remove ourself from any list */
	DLIST_REMOVE((*cur->list_head), cur);
	cur->list_head = NULL;

	/*
	 * Our state is about to go away,
	 * all we can do is shutting down the whole uring.
	 * But that's ok as we're most likely called from exit_server()
	 */
	vfs_io_uring_config_destroy(cur->config, -ESHUTDOWN, __location__);
	return 0;
}

static void vfs_io_uring_fd_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data);

static int vfs_io_uring_connect(vfs_handle_struct *handle, const char *service,
			    const char *user)
{
	int ret;
	struct vfs_io_uring_config *config;
	unsigned num_entries;
	bool sqpoll;
	bool force_aio_fsync, force_aio_read, force_aio_write;
	unsigned flags = 0;

	config = talloc_zero(handle->conn, struct vfs_io_uring_config);
	if (config == NULL) {
		DEBUG(0, ("talloc_zero() failed\n"));
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct vfs_io_uring_config,
				return -1);

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	num_entries = lp_parm_ulong(SNUM(handle->conn),
				    "io_uring",
				    "num_entries",
				    128);
	num_entries = MAX(num_entries, 1);

	sqpoll = lp_parm_bool(SNUM(handle->conn),
			     "io_uring",
			     "sqpoll",
			     false);
	if (sqpoll) {
		flags |= IORING_SETUP_SQPOLL;
	}

	force_aio_fsync = lp_parm_bool(SNUM(handle->conn),
				       "io_uring",
				       "iosqe_async_fsync",
				       false);
	if (force_aio_fsync) {
		config->async_ops |= IO_URING_ASYNC_FSYNC;
	}

	force_aio_read = lp_parm_bool(SNUM(handle->conn),
				      "io_uring",
				      "iosqe_async_read",
				      true);
	if (force_aio_read) {
		config->async_ops |= IO_URING_ASYNC_READ;
	}

	force_aio_write = lp_parm_bool(SNUM(handle->conn),
				       "io_uring",
				       "iosqe_async_write",
				       false);
	if (force_aio_write) {
		config->async_ops |= IO_URING_ASYNC_WRITE;
	}

	config->writeq.queue_sz = lp_parm_int(SNUM(handle->conn),
						   "io_uring",
						   "write_queue_sz",
						   VFS_URING_WRITEQ_DEFAULT);
	if (config->writeq.queue_sz <= 0) {
		DBG_ERR("%d: write_queue_sz parameter must be greater than 0. "
			"setting to default of %d\n",
			config->writeq.queue_sz,
			VFS_URING_WRITEQ_DEFAULT);
		config->writeq.queue_sz = VFS_URING_WRITEQ_DEFAULT;
	}

	config->readq.queue_sz = lp_parm_int(SNUM(handle->conn),
						  "io_uring",
						  "read_queue_sz",
						  VFS_URING_READQ_DEFAULT);
	if (config->readq.queue_sz <= 0) {
		DBG_ERR("%d: read_queue_sz parameter must be greater than 0. "
			"setting to default of %d\n",
			config->readq.queue_sz,
			VFS_URING_READQ_DEFAULT);
		config->readq.queue_sz = VFS_URING_READQ_DEFAULT;
	}

	config->fake_dctime =
		lp_fake_directory_create_times(SNUM(handle->conn));

	ret = io_uring_queue_init(num_entries, &config->uring, flags);
	if (ret < 0) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		errno = -ret;
		return -1;
	}

	talloc_set_destructor(config, vfs_io_uring_config_destructor);

#ifdef HAVE_IO_URING_RING_DONTFORK
	ret = io_uring_ring_dontfork(&config->uring);
	if (ret < 0) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		errno = -ret;
		return -1;
	}
#endif /* HAVE_IO_URING_RING_DONTFORK */

	config->fde = tevent_add_fd(handle->conn->sconn->ev_ctx,
				    config,
				    config->uring.ring_fd,
				    TEVENT_FD_READ,
				    vfs_io_uring_fd_handler,
				    handle);
	if (config->fde == NULL) {
		ret = errno;
		SMB_VFS_NEXT_DISCONNECT(handle);
		errno = ret;
		return -1;
	}

	return 0;
}

static void _vfs_io_uring_queue_run(struct vfs_io_uring_config *config)
{
	struct vfs_io_uring_request *cur = NULL, *next = NULL;
	struct io_uring_cqe *cqe = NULL;
	unsigned cqhead;
	unsigned nr = 0;
	struct timespec start_time;
	struct timespec end_time;
	int ret;

	PROFILE_TIMESTAMP(&start_time);

	if (config->uring.ring_fd == -1) {
		vfs_io_uring_config_destroy(config, -ESTALE, __location__);
		return;
	}

	for (cur = config->queue; cur != NULL; cur = next) {
		struct io_uring_sqe *sqe = NULL;
		void *state = _tevent_req_data(cur->req);

		next = cur->next;

		sqe = io_uring_get_sqe(&config->uring);
		if (sqe == NULL) {
			break;
		}

		talloc_set_destructor(state, cur->destructor_fn);
		DLIST_REMOVE(config->queue, cur);
		*sqe = cur->sqe;
		DLIST_ADD_END(config->pending, cur);
		cur->list_head = &config->pending;
		SMBPROFILE_BYTES_ASYNC_SET_BUSY(cur->profile_bytes);

		cur->start_time = start_time;
	}

	ret = io_uring_submit(&config->uring);
	if (ret == -EAGAIN || ret == -EBUSY) {
		/* We just retry later */
	} else if (ret < 0) {
		vfs_io_uring_config_destroy(config, ret, __location__);
		return;
	}

	PROFILE_TIMESTAMP(&end_time);

	io_uring_for_each_cqe(&config->uring, cqhead, cqe) {
		cur = (struct vfs_io_uring_request *)io_uring_cqe_get_data(cqe);
		vfs_io_uring_finish_req(cur, cqe, end_time, __location__);
		nr++;
	}

	io_uring_cq_advance(&config->uring, nr);
}

/*
 * Wrapper function to prevent recursion which could happen
 * if we called _vfs_io_uring_queue_run() directly without
 * recursion checks.
 *
 * Looking at the pread call, we can have:
 *
 * vfs_io_uring_pread_send()
 *        ->vfs_io_uring_pread_submit()  <-----------------------------------
 *                ->vfs_io_uring_request_submit()                           |
 *                        ->vfs_io_uring_queue_run()                        |
 *                                ->_vfs_io_uring_queue_run()               |
 *                                                                          |
 * But inside _vfs_io_uring_queue_run() looks like:                         |
 *                                                                          |
 * _vfs_io_uring_queue_run() {                                              |
 *      if (THIS_IO_COMPLETED) {                                            |
 *              ->vfs_io_uring_finish_req()                                 |
 *                      ->cur->completion_fn()                              |
 *      }                                                                   |
 * }                                                                        |
 *                                                                          |
 * cur->completion_fn() for pread is set to vfs_io_uring_pread_completion() |
 *                                                                          |
 * vfs_io_uring_pread_completion() {                                        |
 *      if (READ_TERMINATED) {                                              |
 *              -> tevent_req_done() - We're done, go back up the stack.    |
 *              return;                                                     |
 *      }                                                                   |
 *                                                                          |
 *      We have a short read - adjust the io vectors                        |
 *                                                                          |
 *      ->vfs_io_uring_pread_submit() ---------------------------------------
 * }
 *
 * So before calling _vfs_io_uring_queue_run() we backet it with setting
 * a flag config->busy, and unset it once _vfs_io_uring_queue_run() finally
 * exits the retry loop.
 *
 * If we end up back into vfs_io_uring_queue_run() we notice we've done so
 * as config->busy is set and don't recurse into _vfs_io_uring_queue_run().
 *
 * We set the second flag config->need_retry that tells us to loop in the
 * vfs_io_uring_queue_run() call above us in the stack and return.
 *
 * When the outer call to _vfs_io_uring_queue_run() returns we are in
 * a loop checking if config->need_retry was set. That happens if
 * the short read case occurs and _vfs_io_uring_queue_run() ended up
 * recursing into vfs_io_uring_queue_run().
 *
 * Once vfs_io_uring_pread_completion() finishes without a short
 * read (the READ_TERMINATED case, tevent_req_done() is called)
 * then config->need_retry is left as false, we exit the loop,
 * set config->busy to false so the next top level call into
 * vfs_io_uring_queue_run() won't think it's a recursed call
 * and return.
 *
 */

static void vfs_io_uring_queue_run(struct vfs_io_uring_config *config)
{
	if (config->busy) {
		/*
		 * We've recursed due to short read/write.
		 * Set need_retry to ensure we retry the
		 * io_uring_submit().
		 */
		config->need_retry = true;
		return;
	}

	/*
	 * Bracket the loop calling _vfs_io_uring_queue_run()
	 * with busy = true / busy = false.
	 * so we can detect recursion above.
	 */

	config->busy = true;

	do {
		config->need_retry = false;
		_vfs_io_uring_queue_run(config);
	} while (config->need_retry);

	config->busy = false;
}

static void vfs_io_uring_request_submit(struct vfs_io_uring_request *cur)
{
	struct vfs_io_uring_config *config = cur->config;

	if (cur->sqe_flags) {
		io_uring_sqe_set_flags(&cur->sqe, cur->sqe_flags);
	}
	io_uring_sqe_set_data(&cur->sqe, cur);
	DLIST_ADD_END(config->queue, cur);
	cur->list_head = &config->queue;

	vfs_io_uring_queue_run(config);
}

static void vfs_io_uring_fd_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data)
{
	vfs_handle_struct *handle = (vfs_handle_struct *)private_data;
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	vfs_io_uring_queue_run(config);
}

static int vfs_io_uring_openat(struct vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       struct files_struct *fsp,
			       const struct vfs_open_how *how)
{
#ifndef HAVE_IO_URING_PREP_WRITEV2
	if (fsp->fsp_flags.posix_append) {
		DBG_ERR("POSIX append-IO not supported without writev2 support");
		errno = EINVAL;
		return -1;
	}
#endif
	return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
}

struct vfs_io_uring_pread_state {
	struct files_struct *fsp;
	off_t offset;
	struct iovec iov;
	size_t nread;
	struct vfs_io_uring_request ur;
	bool is_sync_read;
};

static void vfs_io_uring_pread_submit(struct vfs_io_uring_pread_state *state);
static void vfs_io_uring_pread_completion(struct vfs_io_uring_request *cur,
					  const char *location);

static int vfs_io_uring_pread_destructor(void *data)
{
	struct vfs_io_uring_pread_state *state = NULL;

	state = talloc_get_type_abort(data, struct vfs_io_uring_pread_state);
	return vfs_io_uring_request_state_deny_destructor(&state->ur);
}

static struct tevent_req *vfs_io_uring_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_pread_state *state = NULL;
	struct vfs_io_uring_config *config = NULL;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_pread_state);
	if (req == NULL) {
		return NULL;
	}

	/*
	 * Apply backpressure to client by performing synchronous read
	 */
	if (config->readq.op_cnt > config->readq.queue_sz) {
		ssize_t nread;
		ok = sys_valid_io_range(offset, n);
		if (!ok) {
			tevent_req_error(req, EINVAL);
			return tevent_req_post(req, ev);
		}

		config->readq.sync_cnt++;
		state->is_sync_read = true;

		nread = sys_pread_full(fsp_get_io_fd(fsp), data, n, offset);
		if (nread == -1) {
			DBG_ERR("%s: read from file failed with error: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}

		state->nread = nread;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (config->async_ops & IO_URING_ASYNC_READ) {
		state->ur.sqe_flags |= IOSQE_ASYNC;
	}
	state->ur.config = config;
	state->ur.req = req;
	state->ur.completion_fn = vfs_io_uring_pread_completion;
	state->ur.destructor_fn = vfs_io_uring_pread_destructor;

	// Increment because at this point we'll hit the receive_fn
	// which decrements the op_cnt
	config->readq.op_cnt++;
	config->readq.async_cnt++;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread, profile_p,
				     state->ur.profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	ok = sys_valid_io_range(offset, n);
	if (!ok) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	state->fsp = fsp;
	state->offset = offset;
	state->iov.iov_base = (void *)data;
	state->iov.iov_len = n;
	vfs_io_uring_pread_submit(state);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static void vfs_io_uring_pread_submit(struct vfs_io_uring_pread_state *state)
{
	io_uring_prep_readv(&state->ur.sqe,
			    fsp_get_io_fd(state->fsp),
			    &state->iov, 1,
			    state->offset);
	vfs_io_uring_request_submit(&state->ur);
}

static void vfs_io_uring_pread_completion(struct vfs_io_uring_request *cur,
					  const char *location)
{
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		cur->req, struct vfs_io_uring_pread_state);
	struct iovec *iov = &state->iov;
	int num_iov = 1;
	bool ok;

	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */

	if (cur->cqe.res < 0) {
		int err = -cur->cqe.res;
		_tevent_req_error(cur->req, err, location);
		return;
	}

	if (cur->cqe.res == 0) {
		/*
		 * We reached EOF, we're done
		 */
		tevent_req_done(cur->req);
		return;
	}

	ok = iov_advance(&iov, &num_iov, cur->cqe.res);
	if (!ok) {
		/* This is not expected! */
		DBG_ERR("iov_advance() failed cur->cqe.res=%d > iov_len=%d\n",
			(int)cur->cqe.res,
			(int)state->iov.iov_len);
		tevent_req_error(cur->req, EIO);
		return;
	}

	/* sys_valid_io_range() already checked the boundaries */
	state->nread += state->ur.cqe.res;
	if (num_iov == 0) {
		/* We're done */
		tevent_req_done(cur->req);
		return;
	}

	/*
	 * sys_valid_io_range() already checked the boundaries
	 * now try to get the rest.
	 */
	state->offset += state->ur.cqe.res;
	vfs_io_uring_pread_submit(state);
}

static ssize_t vfs_io_uring_pread_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		req, struct vfs_io_uring_pread_state);
	ssize_t ret;

	if (state->is_sync_read) {
		if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
			tevent_req_received(req);
			return -1;
		}
		vfs_aio_state->error = 0;
		ret = state->nread;

		tevent_req_received(req);
		return ret;
	}

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	SMB_ASSERT(state->ur.config != NULL);
	SMB_ASSERT(state->ur.config->readq.op_cnt > 0);
	state->ur.config->readq.op_cnt--;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	ret = state->nread;

	tevent_req_received(req);
	return ret;
}

struct vfs_io_uring_pwrite_state {
	struct files_struct *fsp;
	off_t offset;
	struct iovec iov;
	size_t nwritten;
	struct vfs_io_uring_request ur;
	bool is_sync_write;
};

static void vfs_io_uring_pwrite_submit(struct vfs_io_uring_pwrite_state *state);
static void vfs_io_uring_pwrite_completion(struct vfs_io_uring_request *cur,
					   const char *location);

static int vfs_io_uring_pwrite_destructor(void *data)
{
	struct vfs_io_uring_pwrite_state *state = NULL;

	state = talloc_get_type_abort(data, struct vfs_io_uring_pwrite_state);
	return vfs_io_uring_request_state_deny_destructor(&state->ur);
}

static struct tevent_req *vfs_io_uring_pwrite_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      const void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_pwrite_state *state = NULL;
	struct vfs_io_uring_config *config = NULL;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	/*
	 * Apply backpressure to client by performing synchronous write
	 *
	 */
	if (config->writeq.op_cnt > config->writeq.queue_sz) {
		ok = sys_valid_io_range(offset, n);
		if (!ok) {
			tevent_req_error(req, EINVAL);
			return tevent_req_post(req, ev);
		}

		config->writeq.sync_cnt++;
		state->is_sync_write = true;
		state->nwritten = sys_pwrite_full(fsp_get_io_fd(fsp), data, n, offset);
		if (state->nwritten == -1) {
			DBG_ERR("%s: write to file failed with error: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (config->async_ops & IO_URING_ASYNC_WRITE) {
		state->ur.sqe_flags |= IOSQE_ASYNC;
	}
	state->ur.config = config;
	state->ur.req = req;
	state->ur.completion_fn = vfs_io_uring_pwrite_completion;
	state->ur.destructor_fn = vfs_io_uring_pwrite_destructor;

	// Increment because at this point we'll hit the receive_fn
	// which decrements the op_cnt
	config->writeq.op_cnt++;
	config->writeq.async_cnt++;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite, profile_p,
				     state->ur.profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	ok = sys_valid_io_range(offset, n);
	ok |= offset == VFS_PWRITE_APPEND_OFFSET;
	if (!ok) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	state->fsp = fsp;
	state->offset = offset;
	state->iov.iov_base = discard_const(data);
	state->iov.iov_len = n;
	vfs_io_uring_pwrite_submit(state);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static void vfs_io_uring_pwrite_submit(struct vfs_io_uring_pwrite_state *state)
{
	if (!state->fsp->fsp_flags.posix_append) {
		io_uring_prep_writev(&state->ur.sqe,
				     fsp_get_io_fd(state->fsp),
				     &state->iov, 1,
				     state->offset);
	}
	else {
#ifdef HAVE_IO_URING_PREP_WRITEV2
		io_uring_prep_writev2(&state->ur.sqe,
				      fsp_get_io_fd(state->fsp),
				      &state->iov, 1,
				      -1,
				      RWF_APPEND);
#else
		/* This should have been caught by vfs_io_uring_openat() */
		smb_panic("Unexpected POSIX append-IO");
#endif
	}
	vfs_io_uring_request_submit(&state->ur);
}

static void vfs_io_uring_pwrite_completion(struct vfs_io_uring_request *cur,
					   const char *location)
{
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		cur->req, struct vfs_io_uring_pwrite_state);
	struct iovec *iov = &state->iov;
	int num_iov = 1;
	bool ok;

	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */

	if (cur->cqe.res < 0) {
		int err = -cur->cqe.res;
		_tevent_req_error(cur->req, err, location);
		return;
	}

	if (cur->cqe.res == 0) {
		/*
		 * Ensure we can never spin.
		 */
		tevent_req_error(cur->req, ENOSPC);
		return;
	}

	ok = iov_advance(&iov, &num_iov, cur->cqe.res);
	if (!ok) {
		/* This is not expected! */
		DBG_ERR("iov_advance() failed cur->cqe.res=%d > iov_len=%d\n",
			(int)cur->cqe.res,
			(int)state->iov.iov_len);
		tevent_req_error(cur->req, EIO);
		return;
	}

	/* sys_valid_io_range() already checked the boundaries */
	state->nwritten += state->ur.cqe.res;
	if (num_iov == 0) {
		/* We're done */
		tevent_req_done(cur->req);
		return;
	}
	/*
	 * sys_valid_io_range() already checked the boundaries
	 * now try to write the rest.
	 */
	state->offset += state->ur.cqe.res;
	vfs_io_uring_pwrite_submit(state);
}

static ssize_t vfs_io_uring_pwrite_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		req, struct vfs_io_uring_pwrite_state);
	ssize_t ret;

	if (state->is_sync_write) {
		if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
			tevent_req_received(req);
			return -1;
		}

		vfs_aio_state->error = 0;
		ret = state->nwritten;

		tevent_req_received(req);
		return ret;
	}

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	SMB_ASSERT(state->ur.config != NULL);
	SMB_ASSERT(state->ur.config->writeq.op_cnt > 0);
	state->ur.config->writeq.op_cnt--;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	ret = state->nwritten;

	tevent_req_received(req);
	return ret;
}

struct vfs_io_uring_fsync_state {
	struct vfs_io_uring_request ur;
};

static void vfs_io_uring_fsync_completion(struct vfs_io_uring_request *cur,
					  const char *location);

static int vfs_io_uring_fsync_destructor(void *data)
{
	struct vfs_io_uring_fsync_state *state = NULL;

	state = talloc_get_type_abort(data, struct vfs_io_uring_fsync_state);
	return vfs_io_uring_request_state_deny_destructor(&state->ur);
}

static struct tevent_req *vfs_io_uring_fsync_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_fsync_state *state = NULL;
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	if (config->async_ops & IO_URING_ASYNC_FSYNC) {
		state->ur.sqe_flags |= IOSQE_ASYNC;
	}
	state->ur.config = config;
	state->ur.req = req;
	state->ur.completion_fn = vfs_io_uring_fsync_completion;
	state->ur.destructor_fn = vfs_io_uring_fsync_destructor;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_fsync, profile_p,
				     state->ur.profile_bytes, 0);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	io_uring_prep_fsync(&state->ur.sqe,
			    fsp_get_io_fd(fsp),
			    0); /* fsync_flags */
	vfs_io_uring_request_submit(&state->ur);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static void vfs_io_uring_fsync_completion(struct vfs_io_uring_request *cur,
					  const char *location)
{
	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */

	if (cur->cqe.res < 0) {
		int err = -cur->cqe.res;
		_tevent_req_error(cur->req, err, location);
		return;
	}

	if (cur->cqe.res > 0) {
		/* This is not expected! */
		DBG_ERR("got cur->cqe.res=%d\n", (int)cur->cqe.res);
		tevent_req_error(cur->req, EIO);
		return;
	}

	tevent_req_done(cur->req);
}

static int vfs_io_uring_fsync_recv(struct tevent_req *req,
			      struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_fsync_state *state = tevent_req_data(
		req, struct vfs_io_uring_fsync_state);

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;

	tevent_req_received(req);
	return 0;
}

static void vfs_io_uring_disconnect(vfs_handle_struct *handle)
{
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_NEXT_DISCONNECT(handle);

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	// optional logging for performance team to check whether
	// we hit sync fallback during torture run.
	if (config->writeq.sync_cnt || config->readq.sync_cnt) {
		DBG_NOTICE("Performed %u synchronous writes and %u async "
			   "writes, and %u synchronous reads and %u async "
			   "reads.\n",
			   config->writeq.sync_cnt, config->writeq.async_cnt,
			   config->readq.sync_cnt, config->readq.async_cnt);
	}
}

#define VFS_IO_URING_BATCH_ENTRIES 256
/* Stats a worker runs in a row without going back to the queue lock */
#define VFS_IO_URING_BATCH_LINK 16

static int vfs_io_uring_batch_init(struct vfs_io_uring_config *config,
				   size_t count)
{
	unsigned entries = MIN(MAX(count, 8), VFS_IO_URING_BATCH_ENTRIES);
	int ret;

	if (config->batch_failed) {
		errno = ENOSYS;
		return -1;
	}
	if (config->batch_ready) {
		return 0;
	}

	/*
	 * No DEFER_TASKRUN: a worker would hand each link back to this
	 * task instead of running it. COOP_TASKRUN: completions run their
	 * task work at this task's next kernel entry instead of
	 * interrupting it. Older kernels: no flags.
	 */
	ret = io_uring_queue_init(entries,
				  &config->batch,
				  IORING_SETUP_COOP_TASKRUN);
	if (ret == -EINVAL) {
		ret = io_uring_queue_init(entries, &config->batch, 0);
	}
	if (ret < 0) {
		DBG_NOTICE("io_uring_queue_init() for the batch ring failed: "
			   "%s\n", strerror(-ret));
		config->batch_failed = true;
		errno = ENOSYS;
		return -1;
	}
#ifdef HAVE_IO_URING_RING_DONTFORK
	ret = io_uring_ring_dontfork(&config->batch);
	if (ret < 0) {
		DBG_NOTICE("io_uring_ring_dontfork() failed: %s\n",
			   strerror(-ret));
		io_uring_queue_exit(&config->batch);
		config->batch_failed = true;
		errno = ENOSYS;
		return -1;
	}
#endif /* HAVE_IO_URING_RING_DONTFORK */
	config->batch_ready = true;

	/*
	 * Stat as root: the client holds dirfsp with FILE_LIST_DIRECTORY
	 * and a stat by name needs only traverse on it; root skips the
	 * directory's ACL walk and keeps the lookup in RCU mode. The
	 * personality snapshots the credentials, hence become_root().
	 */
	become_root();
	ret = io_uring_register_personality(&config->batch);
	unbecome_root();
	if (ret < 0) {
		DBG_NOTICE("io_uring_register_personality() failed: %s; "
			   "batch stats run as the user\n",
			   strerror(-ret));
	} else {
		config->batch_personality = ret;
	}
	return 0;
}

/* ents NULL: discard the results */
static int vfs_io_uring_batch_reap(struct vfs_io_uring_config *config,
				   struct vfs_attr_entry *ents)
{
	struct vfs_io_uring_batch *b = &config->inflight;
	int retries = 0;

	while (b->done < b->count) {
		struct io_uring_cqe *cqe = NULL;
		unsigned head;
		unsigned nr = 0;
		int ret;

		ret = io_uring_wait_cqe_nr(&config->batch,
					   &cqe,
					   b->count - b->done);
		if (ret == -EINTR) {
			continue;
		}
		if (((ret == -EAGAIN) || (ret == -EBUSY)) && (retries++ < 10)) {
			continue;
		}
		if (ret < 0) {
			/* requests may be in flight: keep the ring */
			DBG_WARNING("io_uring_wait_cqe_nr() failed: %s; "
				    "%zu of %zu entries stat'ed, batch stats "
				    "off for this connection\n",
				    strerror(-ret), b->done, b->count);
			config->batch_failed = true;
			ZERO_STRUCTP(b);
			errno = -ret;
			return -1;
		}

		io_uring_for_each_cqe(&config->batch, head, cqe) {
			size_t i = io_uring_cqe_get_data64(cqe);

			nr++;
			if (i >= b->count) {
				continue;
			}
			b->done++;
			if ((ents != NULL) && (cqe->res >= 0)) {
				sys_stat_ex_from_statx(&ents[i].st,
						       &config->batch_bufs[i],
						       config->fake_dctime);
				ents[i].got |= VFS_ATTR_STAT;
			}
		}
		io_uring_cq_advance(&config->batch, nr);
	}
	ZERO_STRUCTP(b);
	return 0;
}

static int vfs_io_uring_batch_start(struct vfs_io_uring_config *config,
				    int dirfd,
				    struct vfs_attr_entry *ents,
				    size_t count)
{
	struct vfs_io_uring_batch *b = &config->inflight;
	struct statx *bufs = NULL;
	unsigned int mask = sys_statx_mask();
	size_t submitted = 0;
	int retries = 0;

	if (vfs_io_uring_batch_init(config, count) != 0) {
		return -1;
	}
	if (talloc_array_length(config->batch_bufs) < count) {
		bufs = talloc_realloc(config, config->batch_bufs,
				      struct statx, count);
		if (bufs == NULL) {
			errno = ENOMEM;
			return -1;
		}
		config->batch_bufs = bufs;
	}
	bufs = config->batch_bufs;
	/* zeroed for memcheck, which cannot see the kernel fill them */
	memset(bufs, 0, count * sizeof(struct statx));

	*b = (struct vfs_io_uring_batch) {
		.ents = ents,
		.count = count,
	};

	while (submitted < count) {
		int ret;

		while (submitted < count) {
			struct io_uring_sqe *sqe =
				io_uring_get_sqe(&config->batch);

			if (sqe == NULL) {
				break;
			}
			io_uring_prep_statx(sqe,
					    dirfd,
					    ents[submitted].name,
					    AT_SYMLINK_NOFOLLOW,
					    mask,
					    &bufs[submitted]);
			io_uring_sqe_set_data64(sqe, submitted);
			sqe->personality = config->batch_personality;
			/* a hard link: a stat that fails does not sever it */
			if (((submitted + 1) % VFS_IO_URING_BATCH_LINK != 0) &&
			    (submitted + 1 < count)) {
				sqe->flags |= IOSQE_IO_HARDLINK;
			}
			submitted++;
		}
		SMB_ASSERT(submitted > 0);

		do {
			ret = io_uring_submit(&config->batch);
		} while ((ret == -EINTR) ||
			 (((ret == -EAGAIN) || (ret == -EBUSY)) &&
			  (retries++ < 10)));
		if (ret < 0) {
			/* requests may be in flight: keep the ring */
			DBG_WARNING("io_uring_submit() failed: %s; batch stats "
				    "off for this connection\n",
				    strerror(-ret));
			config->batch_failed = true;
			ZERO_STRUCTP(b);
			errno = -ret;
			return -1;
		}
	}
	return 0;
}

static int vfs_io_uring_batch_attr_submit(struct vfs_handle_struct *handle,
					  const struct files_struct *dirfsp,
					  struct vfs_attr_entry *ents,
					  size_t count,
					  uint32_t want)
{
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	if ((count == 0) || !(want & VFS_ATTR_STAT)) {
		errno = EINVAL;
		return -1;
	}
	if (config->inflight.count != 0) {
		errno = EBUSY;
		return -1;
	}
	return vfs_io_uring_batch_start(config,
					fsp_get_pathref_fd(dirfsp),
					ents,
					count);
}

static int vfs_io_uring_batch_attr_wait(struct vfs_handle_struct *handle,
					const struct files_struct *dirfsp,
					struct vfs_attr_entry *ents,
					size_t count)
{
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	if ((config->inflight.count == 0) ||
	    (config->inflight.ents != ents) ||
	    (config->inflight.count != count)) {
		errno = EINVAL;
		return -1;
	}
	return vfs_io_uring_batch_reap(config, ents);
}

static struct vfs_fn_pointers vfs_io_uring_fns = {
	.connect_fn = vfs_io_uring_connect,
	.openat_fn = vfs_io_uring_openat,
	.disconnect_fn = vfs_io_uring_disconnect,
	.pread_send_fn = vfs_io_uring_pread_send,
	.pread_recv_fn = vfs_io_uring_pread_recv,
	.pwrite_send_fn = vfs_io_uring_pwrite_send,
	.pwrite_recv_fn = vfs_io_uring_pwrite_recv,
	.fsync_send_fn = vfs_io_uring_fsync_send,
	.fsync_recv_fn = vfs_io_uring_fsync_recv,
	.batch_attr_submit_fn = vfs_io_uring_batch_attr_submit,
	.batch_attr_wait_fn = vfs_io_uring_batch_attr_wait,
};

static_decl_vfs;
NTSTATUS vfs_io_uring_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				  "io_uring", &vfs_io_uring_fns);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	vfs_io_uring_debug_level = debug_add_class("io_uring");
	if (vfs_io_uring_debug_level == -1) {
		vfs_io_uring_debug_level = DBGC_VFS;
		DBG_ERR("%s: Couldn't register custom debugging class!\n",
			"vfs_io_uring_init");
	} else {
		DBG_DEBUG("%s: Debug class number of io_uring: %d\n",
			  "vfs_io_uring_init", vfs_io_uring_debug_level);
	}

	return status;
}
