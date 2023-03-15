/*
 * Copyright (C) iXsystems 2021
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
#include <sys/event.h>
#include <aio.h>

/*
 * If possible, wait for existing aio requests to complete.
 * May need to fine-tune the timeout later.
 */
static void vfs_aio_fbsd_request_waitcomplete(struct aiocb *iocbp)
{
	int ret;
	struct timespec timeout = {5,0};
	DBG_ERR("aio op currently in progress for "
		"fd [%d], waiting for completion\n",
		iocbp->aio_fildes);
	ret = aio_waitcomplete(&iocbp, &timeout);
	if (ret == -1) {
		DBG_ERR("aio_waitcomplete() failed "
			"%s\n", strerror(errno));
	}
	else if (ret == EINPROGRESS) {
		DBG_ERR("timer expired and aio still in-flight\n");
	}
}

/*
 * First try to cancel any pending AIO if the request is ending in
 * an unexpected fashion. Failing that, wait up to five seconds
 * for the pending AIO to complete.
 */
static void vfs_aio_fbsd_cleanup(struct tevent_req *req,
				 enum tevent_req_state req_state)
{
	int ret;
	struct aiocb *iocbp = NULL;
	switch(req_state) {
	case TEVENT_REQ_DONE:
	case TEVENT_REQ_RECEIVED:
	case TEVENT_REQ_USER_ERROR:
		break;
	default:
		iocbp = tevent_req_data(req, struct aiocb);
		if (iocbp == NULL) {
			DBG_ERR("Failed to get tevent aio request in aio "
				"aio cleanup function\n");
			return;
		}
		ret = aio_cancel(iocbp->aio_fildes, iocbp);
		if (ret == -1) {
			DBG_ERR("aio_cancel returned -1: %s\n",
				strerror(errno));
		}
		/* return 0x2 = AIO_NOTCANCELED */
		else if (ret == 2) {
			ret = aio_error(iocbp);
			if (ret == -1) {
				DBG_ERR("aio_error failed: %s\n",
					strerror(errno));
			}
			else if (ret == EINPROGRESS) {
				vfs_aio_fbsd_request_waitcomplete(iocbp);
			}
		}
		break;
	}
}

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
	taiocbp->iocbp = talloc_zero(req, struct aiocb);
	iocbp = taiocbp->iocbp;

	iocbp->aio_fildes = fsp_get_io_fd(fsp);
	iocbp->aio_offset = offset;
	iocbp->aio_buf = data;
	iocbp->aio_sigevent.sigev_notify_kevent_flags = EV_ONESHOT;
	iocbp->aio_sigevent.sigev_value.sival_ptr = req;
	iocbp->aio_sigevent.sigev_notify = SIGEV_KEVENT;
	iocbp->aio_nbytes = n;

	tevent_req_set_cleanup_fn(req, vfs_aio_fbsd_cleanup);
	ret = tevent_add_aio_read(ev, taiocbp);
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
	taiocbp->iocbp = talloc_zero(req, struct aiocb);
	iocbp = taiocbp->iocbp;
	iocbp->aio_fildes = fsp_get_io_fd(fsp);
	iocbp->aio_offset = offset;
	iocbp->aio_buf = discard_const(data);
	iocbp->aio_sigevent.sigev_value.sival_ptr = req;
	iocbp->aio_sigevent.sigev_notify_kevent_flags = EV_ONESHOT;
	iocbp->aio_sigevent.sigev_notify = SIGEV_KEVENT;
	iocbp->aio_nbytes = n;

	ret = tevent_add_aio_write(ev, taiocbp);
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
	taiocbp->iocbp = talloc_zero(req, struct aiocb);
	iocbp = taiocbp->iocbp;
	iocbp->aio_fildes = fsp_get_io_fd(fsp);
	iocbp->aio_sigevent.sigev_value.sival_ptr = req;
	iocbp->aio_sigevent.sigev_notify = SIGEV_KEVENT;
	iocbp->aio_sigevent.sigev_notify_kevent_flags = EV_ONESHOT;

	tevent_req_set_cleanup_fn(req, vfs_aio_fbsd_cleanup);
	ret = tevent_add_aio_fsync(ev, taiocbp);
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
