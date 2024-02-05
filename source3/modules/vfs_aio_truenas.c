/*
 * Copyright (C) iXsystems 2024
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
#include "lib/util/tevent_unix.h"
#include "smbd/smbd.h"
#include "libsmburing/smburing.h"
#include <liburing.h>

#define DEFAULT_URING_SZ 128
#define MODULE_NAME "aio_truenas"

struct vfs_aio_tn_config;

typedef vfs_aio_tn_pread_state {
	struct vfs_aio_tn_config *config;
	struct files_struct *fsp;
	off_t offset;
	void *data;
	size_t to_read;
	size_t nread;
	suaiocb_t *aiocb;
} tn_pread_state_t;

typedef vfs_aio_tn_pwrite_state {
	struct vfs_aio_tn_config *config;
	struct files_struct *fsp;
	off_t offset;
	void *data;
	size_t written;
	suaiocb_t *aiocb;
} tn_pwrite_state_t;

typedef vfs_aio_tn_fsync_state {
	struct vfs_aio_tn_config *config;
	struct files_struct *fsp;
	suaiocb_t *aiocb;
} tn_fsync_state_t;

typedef union truenas_aio = {
	tn_pread_state_t pread_state;
	tn_pwrite_state_t pwrite_state;
	tn_fsync_state_t fsync_state;
} tn_aio_t;

typedef int tn_aio_op_t(tn_aio_t *data);

typedef struct truenas_aio_ops {
	// async ops
	tn_aio_op_t *async_fsync_fn;
	tn_aio_op_t *async_pread_fn;
	tn_aio_op_t *async_pwrite_fn;
	// sync ops
	tn_aio_op_t *sync_fsync_fn;
	tn_aio_op_t *sync_pread_fn;
	tn_aio_op_t *sync_pwrite_fn;
} tn_aio_ops_t;

typedef struct vfs_aio_tn_config {
	tn_aio_ops_t optable;
} tn_aio_conf_t;

static void vfs_tn_aio_fd_handler(struct tevent_context *ev,
				  struct tevent_fd *fde,
				  uint16_t flags,
				  void *private_data)
{
	suctx_t *ctx = (suctx_t *)private_data;
	eventfd_t v;

	read(ctx->event_fd, &v); // reset counter

	smburing_process_events(ctx);
}

static void init_global_uring_ctx(vfs_handle_struct *handle)
{
	suctx_t *smburing_ctx = NULL;
	struct io_uring *uring = NULL;
	int ret;

	ret = io_uring_queue_init(DEFAULT_URING_SZ, uring, 0);
	SMB_ASSERT(ret == 0);

	smburing_ctx = init_smburing_ctx(handle->conn->sconn, uring);
	SMB_ASSERT(smburing_ctx != NULL);

	handle->conn->sconn->uring_ctx = smburing_ctx;

	ctx->fde = (void *)tevent_add_fd(handle->conn->sconn->ev_ctx,
					 ctx,
					 ctx->event_fd,
					 TEVENT_FD_READ,
					 vfs_tn_aio_fd_handler,
					 ctx);
}

static suaiocb_t *_vfs_truenas_get_aiocb(vfs_handle_struct *handle,
					 const char *location)
{
	if (handle->conn->sconn->uring_ctx == NULL) {
		init_global_uring_ctx(handle);
	}

	return _get_aio_cb(handle->conn->sconn->uring_ctx, location);
}
#define vfs_truenas_get_aiocb(hdl) \
	(suaiocb_t *)_vfs_truenas_get_aiocb(hdl, __location__)

static bool vfs_aio_tn_pread_completion(suaiocb_t *aiocb,
					const char *location)
{
	int ret;
	tn_read_state_t *state = tevent_req_data(aiocb->req, tn_read_state_t);

	// Fixed buffer should not be in use, but we'll err on side of caution
	release_smburing_iov(aiocb->ctx, aiocb->iov_idx);

	switch (aiocb->rv) {
	case -1:
		_tevent_req_error(aiocb->req, aiocb->saved_errno, location);
		return false;
	case 0:
		tevent_req_done(aiocb->req);
	default:
		break;
	}

	SMB_ASSERT(aiocb->rv <= state->to_read);

	state->nread += aiocb->rv;
	state->to_read -= aiocb->rv;
	state->offset += aiocb->rv;

	if (to_read != 0) {
		return handle_short_read(aiocb, state, location);
	}

	DBG_ERR("%s: short read on file %zu bytes remaining\n",
		fsp_str_dbg(fsp), state->to_read);

	ret = add_aio_read(aiocb, fsp_get_io_fd(fsp),
			   data + state->nread,
			   state->to_read,
			   state->offset);

	if (ret == -EAGAIN) {
		// Fallback to synchronous read
		aiocb->rv = pread(fsp_get_io_fd(fsp),
				   data + state->nread,
				   state->to_read,
				   state->offset);
		if (aiocb->rv == -1) {
			aiocb->saved_errno = errno;
			_tevent_req_error(aiocb->req,
				          aiocb->saved_errno,
					  location);
			return false;
		}
		tevent_req_done(aiocb->req);
		return false;
	}

	SMB_ASSERT(ret >= 0);

	// Try to pick up on short read by looping through cqes again
	return true;
}

static bool handle_short_read(tn_aio_ops_t *optable,
			      tn_aio_t *aio_op,
			      const char *location)
{
	int ret;
	tn_read_state_t *state = aio_op.pread_state;

	DBG_ERR("%s: handling short read on file [%s] - %zu bytes remaining.\n",
		location, fsp_str_dbg(state->fsp), state->to_read);

	ret = optable.async_pread_fn(aio_op);
	if (ret == -EAGAIN) {
		state->aiocb->rv = = optable.sync_pread_fn(aio_op);
		if (state->aiocb->rv == -1) {
			state->aiocb->saved_errno = errno;
			_tevent_req_error(state->aiocb->req,
				          state->aiocb->saved_errno,
					  location);
			return false;
		}
		tevent_req_done(state->aiocb->req);
		return false;
	}

	SMB_ASSERT(ret >= 0);

	// Try to pick up on short read by looping through cqes again
	return true;
}

static bool vfs_aio_tn_pread_completion_fixed(suaiocb_t *aiocb,
					      const char *location)
{
	tn_read_state_t *state = tevent_req_data(aiocb->req, tn_read_state_t);
	tn_aio_ops_t *optable = state->config->optable;
	tn_aio_t aio_op = (tn_aio_t){.pread_state = state};

	switch (aiocb->rv) {
	case -1:
		release_smburing_iov(aiocb->ctx, aiocb->iov_idx);
		_tevent_req_error(aiocb->req, aiocb->saved_errno, location);
		return false;
	case 0:
		release_smburing_iov(aiocb->ctx, aiocb->iov_idx);
		tevent_req_done(aiocb->req);
		return false;
	default:
		break;
	}

	SMB_ASSERT(aiocb->rv <= state->to_read);
	memcpy(state->data + state->nread, aiocb->iov.iov_base, aiocb->rv);

	state->nread += aiocb->rv;
	state->to_read -= aiocb->rv;
	state->offset += aiocb->rv;

	// We need to release this iov even if we did short read
	release_smburing_iov(aiocb->ctx, aiocb->iov_idx);

	if (to_read == 0) {
		tevent_req_done(aiocb->req);
		return false;
	}

	return handle_short_read(optable, &aio_op, location);
}

static bool vfs_aio_tn_pread_completion(suaiocb_t *aiocb,
					const char *location)
{
	tn_read_state_t *state = tevent_req_data(aiocb->req, tn_read_state_t);
	tn_aio_ops_t *optable = state->config->optable;
	tn_aio_t aio_op = (tn_aio_t){.pread_state = state};

	switch (aiocb->rv) {
	case -1:
		release_smburing_iov(aiocb->ctx, aiocb->iov_idx);
		_tevent_req_error(aiocb->req, aiocb->saved_errno, location);
		return false;
	case 0:
		release_smburing_iov(aiocb->ctx, aiocb->iov_idx);
		tevent_req_done(aiocb->req);
		return false;
	default:
		break;
	}

	SMB_ASSERT(aiocb->rv <= state->to_read);
	state->nread += aiocb->rv;
	state->to_read -= aiocb->rv;
	state->offset += aiocb->rv;

	// We need to release this iov even if we did short read
	release_smburing_iov(aiocb->ctx, aiocb->iov_idx);

	if (to_read == 0) {
		tevent_req_done(aiocb->req);
		return false;
	}

	return handle_short_read(optable, &aio_op, location);
}

static ssize_t vfs_aio_tn_pread_recv(struct tevent_req *req,
				     struct vfs_aio_state *vfs_aio_state)
{
	tn_read_state_t *state = tevent_req_data(aiocb->req, tn_read_state_t);
	ssize_t ret;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio-state->error = 0;
	ret = state->nread;

	TALLOC_FREE(state->aiocb);
	tevent_req_received(req);
	return ret;
}

static int _aio_async_pread(tn_aio_t *aio_data, const char *location)
{
	tn_read_state_t *state = aio_data.pread_state;

	state->aiocb->completion_function = vfs_aio_tn_pread_completion;

	return _add_aio_read(state->aiocb,
			     fsp_get_io_fd(state->fsp),
			     state->data,
			     state->n,
			     state->offset,
			     location);
}
#define aio_async_pread(aio_data)\
	_aio_async_pread(aio_data, __location__)

static int _aio_async_pread_fixed(tn_aio_t *aio_data, const char *location)
{
	int ret;
	tn_read_state_t *state = aio_data.pread_state;

	state->aiocb->completion_function = vfs_aio_tn_pread_completion_fixed;

	ret = _add_aio_read_fixed(state->aiocb,
				  fsp_get_io_fd(state->fsp),
				  state->n,
				  state->offset);
	if (ret == -ENOBUFS) {
		// Fixed buffers are exhausted fallback to normal allocation
		return _aio_async_pread(aio_data, location);
	}
	return ret;
}
#define aio_async_pread_fixed(aio_data)\
	_aio_async_pread_fixed(aio_data, __location__)

static struct tevent_req *vfs_aio_tn_pread_send(
					     struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n, off_t offset)
{
	int ret;
	struct tevent_req *req = NULL;
	tn_read_state_t *state = NULL;
	suaiocb_t *aiocb = NULL;
	tn_aio_conf_t *config = NULL;
	tn_aio_t aio_op;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				tn_aio_conf_t,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state, tn_read_state_t);
	if (req == NULL) {
		return NULL;
	}

	state->fsp = fsp;
	state->data = data;
	state->offset = offset;
	state->to_read = n;

	aiocb = vfs_truenas_get_aiocb(handle);
	SMB_ASSERT(aiocb != NULL);

	state->aiocb = aiocb;
	aiocb->req = req;
	aiocb->private_data = (void *)state;
	aio_op = (tn_aio_t){.pwrite_state = state};

	ret = config->optable.async_pread_fn(&aio_op);
	if (ret == -EAGAIN) {
		// AIO is overloaded, fallback to synchronous read
		config->optable->sync_pread_fn(&aio_op);
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	} else if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	return req;
}

static bool vfs_aio_tn_pwrite_completion(suaiocb_t *aiocb,
					 const char *location)
{
	tn_write_state_t *state = tevent_req_data(aiocb->req, tn_write_state_t);

	release_smburing_iov(aiocb->ctx, aiocb->iov_idx);

	switch (aiocb->rv) {
	case -1:
		_tevent_req_error(aiocb->req, aiocb->saved_errno, location);
		return false;
	case 0:
		tevent_req_error(cur->req, ENOSPC);
		return false;
	default:
		break;
	}

	state->nwritten += aiocb->rv;
	state->offset += aiocb->rv;
	tevent_req_done(aiocb->req);
	return false;
}

static int _aio_async_pwrite(tn_aio_t *aio_data, const char *location)
{
	tn_write_state_t *state = aio_data.pwite_state;

	state->aiocb->completion_function = vfs_aio_tn_pwrite_completion;

	return _add_aio_write(state->aiocb,
			      fsp_get_io_fd(state->fsp),
			      state->data,
			      state->n,
			      state->offset,
			      location);
}
#define aio_async_pwrite(aio_data)\
	_aio_async_pwrite(aio_data, __location__)

static int _aio_async_pwrite_fixed(tn_aio_t *aio_data, const char *location)
{
	tn_write_state_t *state = aio_data.pwrite_state;

	state->aiocb->completion_function = vfs_aio_tn_pwrite_completion;

	ret = _add_aio_pwrite_fixed(state->aiocb,
				    fsp_get_io_fd(state->fsp),
				    state->n,
				    state->offset,
				    location);
	if (ret == -ENOBUFS) {
		// Fixed buffers are exhausted fallback to normal allocation
		return _aio_async_pwrite(aio_data, location);
	}

	return ret;
}
#define aio_sync_pwrite_fixed(aio_data)\
	_aio_sync_pwrite_fixed(aio_data, __location__)

static ssize_t vfs_truenas_pwrite_recv(struct tevent_req *req,
				       struct vfs_aio_state *vfs_aio_state)
{
	tn_write_state_t *state = tevent_req_data(aiocb->req, tn_write_state_t);
	ssize_t ret;

	TALLOC_FREE(state->aiocb);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	ret = state->nwritten;

	tevent_req_received(req);
	return ret;
}


static struct tevent_req *vfs_aio_tn_pwrite_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     const void *data,
					     size_t n, off_t offset)
{
	int ret;
	struct tevent_req *req = NULL;
	tn_pwrite_state_t *state = NULL;
	suaiocb_t *aiocb = NULL;
	tn_aio_conf_t *config = NULL;
	tn_aio_t aio_op;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				tn_aio_conf_t,
				smb_panic(__location__));


	req = tevent_req_create(mem_ctx, &state, tn_read_state_t);
	if (req == NULL) {
		return NULL;
	}

	state->fsp = fsp;
	state->data = data;
	state->offset = offset;

	aiocb = vfs_truenas_get_aiocb(handle);
	SMB_ASSERT(aiocb != NULL);

	aiocb->req = req;
	aiocb->private_data = (void *)state;
	aio_op = (tn_aio_t){.pwrite_state = state};

	ret = config->optable.async_pwrite_fn(&aio_op);
	if (ret == -EAGAIN) {
		// Fallback to synchronous
		config->optable.sync_pwrite_fn(&aio_op);
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	} else if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	return req;
}

static bool vfs_aio_tn_fsync_completion(suaiocb_t *aiocb,
					const char *location)
{
	release_smburing_iov(aiocb->ctx, aiocb->iov_idx);

	switch (aiocb->rv) {
	case -1:
		_tevent_req_error(aiocb->req, aiocb->saved_errno, location);
		return false;
	case 0:
		tevent_req_done(aiocb->req);
		return false;
	default:
		break;
	}

	DBG_ERR("%d: unexpected fsync return\n", aiocb->rv);
	tevent_req_error(aiocb->req, EIO);
	return false;
}

static int _aio_async_fsync(tn_aio_t *aio_data, const char *location)
{
	tn_fsync_state_t *state = aio_data.fsync_state;

	aiocb->completion_function = vfs_aio_tn_fsync_completion;

	return _add_aio_fsync(state->aiocb, fsp_get_io_fd(state->fsp), location);
}
#define aio_async_fsync(aio_data)\
	_aio_async_fsync(aio_data, __location__)

static int _aio_sync_fsync(tn_aio_t *aio_data, const char *location)
{
	tn_fsync_state_t *state = aio_data.fsync_state;

	state->aiocb->rv = fsync(fsp_get_io_fd(state->fsp));
	if (state->aiocb->rv == -1) {
		state->aiocb->saved_errno = errno;
	}

	return state->aiocb->rv;
}
#define aio_sync_fsync(aio_data)\
	_aio_sync_fsync(aio_data, __location__)

static int vfs_tn_fsync_recv(struct tevent_req *req,
			     struct vfs_aio_state *vfs_aio_state)
{
	tn_fsync_state_t *state = tevent_req_data(aiocb->req, tn_fsync_state_t);
	TALLOC_FREE(state->aiocb);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;

	tevent_req_received(req);
	return 0;
}

static struct tevent_req *vfs_aio_tn_fsync_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp)
{
	int ret;
	struct tevent_req *req = NULL;
	tn_fsync_state_t *state = NULL;
	suaiocb_t *aiocb = NULL;
	tn_aio_conf_t *config = NULL;
	tn_aio_t aio_op;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				tn_aio_conf_t,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state, tn_fsync_state_t);
	if (req == NULL) {
		return NULL;
	}

	state->fsp = fsp;

	aiocb = vfs_truenas_get_aiocb(handle);
	SMB_ASSERT(aiocb != NULL);

	state->aiocb = aiocb;
	aiocb->req = req;
	aiocb->private_data = (void *)state;
	aio_op = (tn_aio_t){.fsync_state = state};

	ret = config->optable.async_fsync_fn(&aio_op);
	if (ret != 0) {
		if (errno == EAGAIN) {
			config->optable.sync_fsync_fn(&aio_op);
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	return req;
}

static tn_aio_ops_t fixed_op_table = {
	.async_fsync_fn = aio_async_fsync,
	.async_pread_fn = aio_async_pread_fixed,
	.async_pwrite_fn = aio_async_pwrite_fixed,
	.sync_fsync_fn = aio_sync_fsync,
	.sync_pread_fn = aio_sync_pread,
	.sync_pwrite_fn = aio_sync_pwrite,
};

static tn_aio_ops_t std_op_table = {
	.async_fsync_fn = aio_async_fsync,
	.async_pread_fn = aio_async_pread,
	.async_pwrite_fn = aio_async_pwrite,
	.sync_fsync_fn = aio_sync_fsync,
	.sync_pread_fn = aio_sync_pread,
	.sync_pwrite_fn = aio_sync_pwrite,
};

static int vfs_io_uring_connect(vfs_handle_struct *handle,
				const char *service,
				const char *user)
{
	int ret;
	tn_aio_conf_t *config = NULL;
	bool use_fixed_buffers;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->config, tn_aio_conf_t);
	if (config == NULL) {
		DBG_ERR("Memory allocation failure\n");
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, tn_aio_conf_t,
				return -1);

	use_fixed_buffers = lp_parm_bool(SNUM(handle->conn),
					 MODULE_NAME,
					 "fixed_buffers",
					 false);
	if (use_fixed_buffers) {
		config->optable = &fixed_op_table;
	} else {
		config->optable = &std_op_table;
	}

	return ret;
}

staeic struct vfs_fn_pointers vfs_aio_tn_fns = {
	.connect_fn = vfs_aio_tn_connect,
	.pread_send_fn = vfs_aio_tn_pread_send,
	.pread_recv_fn = vfs_aio_tn_pread_recv,
	.pwrite_send_fn = vfs_aio_tn_pwrite_send,
	.pwrite_recv_fn = vfs_aio_tn_pwrite_recv,
	.fsync_send_fn = vfs_aio_tn_fsync_send,
	.fsync_recv_fn = vfs_aio_tn_fsync_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_tn_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				MODULE_NAME, &vfs_aio_tn_fns);
}
