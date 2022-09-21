/*
 * Copyright (C) iXsystems 2022
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

#include "includes.h"
#include "lib/util/tevent_unix.h"
#include "lib/tevent/tevent_kqueue.h"
#include "smbd/smbd.h"
#include <aio.h>

static struct tevent_req *vfs_aio_fbsd_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n, off_t offset)
{
	int ret;
	struct tevent_req *req = NULL;
	struct tevent_aiocb *taiocbp = NULL;
	struct aiocb *iocbp = NULL;

	req = tevent_req_create(mem_ctx, &taiocbp, struct tevent_aiocb);
	if (req == NULL) {
		return NULL;
	}
	taiocbp->ev = ev;
	taiocbp->req = req;

	iocbp = tevent_ctx_get_iocb(taiocbp);
	iocbp->aio_fildes = fsp_get_io_fd(fsp);
	iocbp->aio_offset = offset;
	iocbp->aio_buf = data;
	iocbp->aio_nbytes = n;

	ret = tevent_add_aio_read(taiocbp);
	if (ret != 0) {
		if (errno == EAGAIN) {
			taiocbp->rv = pread(fsp_get_io_fd(fsp), data, n, offset);
			if (taiocbp->rv == -1) {
				taiocbp->saved_errno = errno;
			}
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	return req;
}

static ssize_t vfs_aio_fbsd_common_recv(struct tevent_req *req,
					struct vfs_aio_state *vfs_aio_state)
{
	struct tevent_aiocb *taiocbp = NULL;
	taiocbp = tevent_req_data(req, struct tevent_aiocb);
	vfs_aio_state->error = taiocbp->saved_errno;
	return taiocbp->rv;
}

static struct tevent_req *vfs_aio_fbsd_pwrite_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     const void *data,
					     size_t n, off_t offset)
{
	int ret;
	struct tevent_req *req = NULL;
	struct tevent_aiocb *taiocbp = NULL;
	struct aiocb *iocbp = NULL;

	req = tevent_req_create(mem_ctx, &taiocbp, struct tevent_aiocb);
	if (req == NULL) {
		return NULL;
	}
	taiocbp->ev = ev;
	taiocbp->req = req;

	iocbp = tevent_ctx_get_iocb(taiocbp);
	iocbp->aio_fildes = fsp_get_io_fd(fsp);
	iocbp->aio_offset = offset;
	iocbp->aio_buf = discard_const(data);
	iocbp->aio_nbytes = n;

	ret = tevent_add_aio_write(taiocbp);
	if (ret != 0) {
		if (errno == EAGAIN) {
			taiocbp->rv = pwrite(fsp_get_io_fd(fsp), data, n, offset);
			if (taiocbp->rv == -1) {
				taiocbp->saved_errno = errno;
			}
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	return req;
}

static struct tevent_req *vfs_aio_fbsd_fsync_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp)
{
	int ret;
	struct tevent_req *req = NULL;
	struct tevent_aiocb *taiocbp = NULL;
	struct aiocb *iocbp = NULL;

	req = tevent_req_create(mem_ctx, &taiocbp, struct tevent_aiocb);
	if (req == NULL) {
		return NULL;
	}
	taiocbp->ev = ev;
	taiocbp->req = req;

	iocbp = tevent_ctx_get_iocb(taiocbp);
	iocbp->aio_fildes = fsp_get_io_fd(fsp);

	ret = tevent_add_aio_fsync(taiocbp);
	if (ret != 0) {
		if (errno == EAGAIN) {
			taiocbp->rv = fsync(fsp_get_io_fd(fsp));
			if (taiocbp->rv == -1) {
				taiocbp->saved_errno = errno;
			}
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	return req;
}

static int vfs_aio_fbsd_fsync_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	return vfs_aio_fbsd_common_recv(req, vfs_aio_state);
}

static struct vfs_fn_pointers vfs_aio_fbsd_fns = {
	.pread_send_fn = vfs_aio_fbsd_pread_send,
	.pread_recv_fn = vfs_aio_fbsd_common_recv,
	.pwrite_send_fn = vfs_aio_fbsd_pwrite_send,
	.pwrite_recv_fn = vfs_aio_fbsd_common_recv,
	.fsync_send_fn = vfs_aio_fbsd_fsync_send,
	.fsync_recv_fn = vfs_aio_fbsd_fsync_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_fbsd_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_fbsd", &vfs_aio_fbsd_fns);
}
