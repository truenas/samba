/*
 * Use the io_uring of Linux (>= 5.1) -- TrueNAS fork.
 *
 * This file was rewritten on top of source3/lib/truenas_uring (the per-
 * tevent_context io_uring abstraction). The module is now a thin VFS
 * adapter:
 *
 *   - connect: call truenas_uring_get(ev) so the per-context ring exists,
 *              then apply per-share IOSQE_ASYNC thresholds for read and
 *              write op classes (smb.conf:
 *              `io_uring:force_async_read_threshold`,
 *              `io_uring:force_async_write_threshold`).
 *
 *   - pread / pwrite / fsync: shim over the corresponding truenas_uring_*
 *              tevent_req-shaped ops, with the existing short-read /
 *              short-write retry semantics preserved by chaining a
 *              continuation tevent_req per partial completion.
 *
 *   - openat: unchanged -- still rejects O_APPEND when writev2 isn't
 *              available, since posix_append rides on prep_writev2.
 *
 * Per-share state (struct vfs_io_uring_config) is now empty; the ring,
 * eventfd, queue, and CQE dispatch all live inside truenas_uring. The
 * recursion guard and SQ-batching infrastructure are gone -- truenas_uring
 * submits each op immediately, and short-read continuations are linear
 * tevent_req chains.
 *
 * Original copyrights:
 *   Copyright (C) Volker Lendecke 2008
 *   Copyright (C) Jeremy Allison 2010
 *   Copyright (C) Stefan Metzmacher 2019
 * Refactor:
 *   Copyright (C) iXsystems, Inc. 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/sys_rw.h"
#include "smbprofile.h"
#include "lib/truenas_uring.h"

static int vfs_io_uring_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_io_uring_debug_level

/* --------------------------------------------------------------------- */
/*  connect / openat                                                     */
/* --------------------------------------------------------------------- */

static int vfs_io_uring_connect(vfs_handle_struct *handle,
				const char *service,
				const char *user)
{
	struct truenas_uring *u = NULL;
	struct tevent_context *ev = handle->conn->sconn->ev_ctx;
	size_t read_thresh, write_thresh;
	int ret;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	u = truenas_uring_get(ev);
	if (u == NULL) {
		int saved = errno;
		DBG_ERR("truenas_uring_get failed: %s\n", strerror(saved));
		SMB_VFS_NEXT_DISCONNECT(handle);
		errno = saved;
		return -1;
	}

	/*
	 * IOSQE_ASYNC threshold knobs. When set, ops at or above the
	 * threshold get IOSQE_ASYNC so the kernel processes them in a
	 * worker thread and our process is not blocked on the (kernel-side)
	 * memcpy.
	 *
	 * Defaults: 0 = disabled. Knobs are last-writer-wins across shares
	 * because the underlying ring is per-tevent_context, not per-share.
	 * Operators using the threshold should set it the same on all shares.
	 */
	read_thresh = lp_parm_ulong(SNUM(handle->conn),
				    "io_uring",
				    "force_async_read_threshold",
				    0);
	write_thresh = lp_parm_ulong(SNUM(handle->conn),
				     "io_uring",
				     "force_async_write_threshold",
				     0);
	truenas_uring_set_async_threshold(u, TURING_OP_READ_CLASS, read_thresh);
	truenas_uring_set_async_threshold(u, TURING_OP_WRITE_CLASS, write_thresh);

	return 0;
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

/* --------------------------------------------------------------------- */
/*  PREAD                                                                */
/* --------------------------------------------------------------------- */

struct vfs_io_uring_pread_state {
	struct tevent_context *ev;
	struct files_struct *fsp;
	void *buf;
	size_t count;
	off_t offset;
	size_t nread;
	struct timespec start_time;
	struct timespec end_time;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_io_uring_pread_done(struct tevent_req *subreq);
static bool vfs_io_uring_pread_submit(struct tevent_req *req);

static struct tevent_req *vfs_io_uring_pread_send(
		struct vfs_handle_struct *handle,
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct files_struct *fsp,
		void *data,
		size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_pread_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_pread_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fsp = fsp;
	state->buf = data;
	state->count = n;
	state->offset = offset;

	if (!sys_valid_io_range(offset, n)) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
	PROFILE_TIMESTAMP(&state->start_time);

	if (!vfs_io_uring_pread_submit(req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static bool vfs_io_uring_pread_submit(struct tevent_req *req)
{
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		req, struct vfs_io_uring_pread_state);
	struct tevent_req *subreq = NULL;
	uint8_t *here = (uint8_t *)state->buf + state->nread;
	size_t remaining = state->count - state->nread;
	off_t here_offset = state->offset + (off_t)state->nread;

	subreq = truenas_uring_pread_send(state, state->ev,
					  fsp_get_io_fd(state->fsp),
					  here, remaining, here_offset);
	if (subreq == NULL) {
		tevent_req_error(req, errno != 0 ? errno : ENOMEM);
		return false;
	}
	tevent_req_set_callback(subreq, vfs_io_uring_pread_done, req);
	return true;
}

static void vfs_io_uring_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		req, struct vfs_io_uring_pread_state);
	ssize_t n;
	int err = 0;

	n = truenas_uring_pread_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (n < 0) {
		tevent_req_error(req, err);
		return;
	}
	if (n == 0) {
		/* EOF -- short read is the final answer. */
		tevent_req_done(req);
		return;
	}

	state->nread += (size_t)n;
	if (state->nread < state->count) {
		/* Short read of a non-empty range; continue. */
		if (!vfs_io_uring_pread_submit(req)) {
			return;
		}
		return;
	}
	tevent_req_done(req);
}

static ssize_t vfs_io_uring_pread_recv(struct tevent_req *req,
				       struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		req, struct vfs_io_uring_pread_state);
	ssize_t ret;

	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	PROFILE_TIMESTAMP(&state->end_time);
	vfs_aio_state->duration = nsec_time_diff(&state->end_time,
						 &state->start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	ret = (ssize_t)state->nread;

	tevent_req_received(req);
	return ret;
}

/* --------------------------------------------------------------------- */
/*  PWRITE                                                               */
/* --------------------------------------------------------------------- */

struct vfs_io_uring_pwrite_state {
	struct tevent_context *ev;
	struct files_struct *fsp;
	const void *buf;
	size_t count;
	off_t offset;
	size_t nwritten;
	struct timespec start_time;
	struct timespec end_time;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_io_uring_pwrite_done(struct tevent_req *subreq);
static bool vfs_io_uring_pwrite_submit(struct tevent_req *req);

static struct tevent_req *vfs_io_uring_pwrite_send(
		struct vfs_handle_struct *handle,
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct files_struct *fsp,
		const void *data,
		size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_pwrite_state *state = NULL;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fsp = fsp;
	state->buf = data;
	state->count = n;
	state->offset = offset;

	ok = sys_valid_io_range(offset, n);
	ok |= offset == VFS_PWRITE_APPEND_OFFSET;
	if (!ok) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
	PROFILE_TIMESTAMP(&state->start_time);

	if (!vfs_io_uring_pwrite_submit(req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static bool vfs_io_uring_pwrite_submit(struct tevent_req *req)
{
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		req, struct vfs_io_uring_pwrite_state);
	struct tevent_req *subreq = NULL;
	const uint8_t *here = (const uint8_t *)state->buf + state->nwritten;
	size_t remaining = state->count - state->nwritten;
	off_t here_offset = state->offset + (off_t)state->nwritten;

	if (state->fsp->fsp_flags.posix_append) {
#ifdef HAVE_IO_URING_PREP_WRITEV2
		/*
		 * POSIX append-IO: writev2 with RWF_APPEND on the file's
		 * current EOF. The offset argument to writev2 is ignored
		 * when RWF_APPEND is set; pass -1 for clarity.
		 */
		subreq = truenas_uring_pwrite_v2_send(state, state->ev,
						      fsp_get_io_fd(state->fsp),
						      here, remaining,
						      -1, RWF_APPEND);
#else
		/* openat() should have rejected this fsp. */
		smb_panic("Unexpected POSIX append-IO");
#endif
	} else {
		subreq = truenas_uring_pwrite_send(state, state->ev,
						   fsp_get_io_fd(state->fsp),
						   here, remaining,
						   here_offset);
	}
	if (subreq == NULL) {
		tevent_req_error(req, errno != 0 ? errno : ENOMEM);
		return false;
	}
	tevent_req_set_callback(subreq, vfs_io_uring_pwrite_done, req);
	return true;
}

static void vfs_io_uring_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		req, struct vfs_io_uring_pwrite_state);
	ssize_t n;
	int err = 0;

	if (state->fsp->fsp_flags.posix_append) {
		n = truenas_uring_pwrite_v2_recv(subreq, &err);
	} else {
		n = truenas_uring_pwrite_recv(subreq, &err);
	}
	TALLOC_FREE(subreq);

	if (n < 0) {
		tevent_req_error(req, err);
		return;
	}
	if (n == 0) {
		/* Spin-protect: a writer that makes no progress is an error. */
		tevent_req_error(req, ENOSPC);
		return;
	}

	state->nwritten += (size_t)n;
	if (state->nwritten < state->count) {
		if (!vfs_io_uring_pwrite_submit(req)) {
			return;
		}
		return;
	}
	tevent_req_done(req);
}

static ssize_t vfs_io_uring_pwrite_recv(struct tevent_req *req,
					struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		req, struct vfs_io_uring_pwrite_state);
	ssize_t ret;

	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	PROFILE_TIMESTAMP(&state->end_time);
	vfs_aio_state->duration = nsec_time_diff(&state->end_time,
						 &state->start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	ret = (ssize_t)state->nwritten;

	tevent_req_received(req);
	return ret;
}

/* --------------------------------------------------------------------- */
/*  FSYNC                                                                */
/* --------------------------------------------------------------------- */

struct vfs_io_uring_fsync_state {
	struct timespec start_time;
	struct timespec end_time;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_io_uring_fsync_done(struct tevent_req *subreq);

static struct tevent_req *vfs_io_uring_fsync_send(
		struct vfs_handle_struct *handle,
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_fsync_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_fsync_state);
	if (req == NULL) {
		return NULL;
	}

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_fsync, profile_p,
				     state->profile_bytes, 0);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
	PROFILE_TIMESTAMP(&state->start_time);

	subreq = truenas_uring_fsync_send(state, ev,
					  fsp_get_io_fd(fsp), 0);
	if (subreq == NULL) {
		tevent_req_error(req, errno != 0 ? errno : ENOMEM);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_io_uring_fsync_done, req);
	return req;
}

static void vfs_io_uring_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int err = 0;
	int ret;

	ret = truenas_uring_fsync_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (ret != 0) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

static int vfs_io_uring_fsync_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_fsync_state *state = tevent_req_data(
		req, struct vfs_io_uring_fsync_state);

	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	PROFILE_TIMESTAMP(&state->end_time);
	vfs_aio_state->duration = nsec_time_diff(&state->end_time,
						 &state->start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	tevent_req_received(req);
	return 0;
}

/* --------------------------------------------------------------------- */
/*  Module registration                                                  */
/* --------------------------------------------------------------------- */

static struct vfs_fn_pointers vfs_io_uring_fns = {
	.connect_fn = vfs_io_uring_connect,
	.openat_fn = vfs_io_uring_openat,
	.pread_send_fn = vfs_io_uring_pread_send,
	.pread_recv_fn = vfs_io_uring_pread_recv,
	.pwrite_send_fn = vfs_io_uring_pwrite_send,
	.pwrite_recv_fn = vfs_io_uring_pwrite_recv,
	.fsync_send_fn = vfs_io_uring_fsync_send,
	.fsync_recv_fn = vfs_io_uring_fsync_recv,
};

static_decl_vfs;
NTSTATUS vfs_io_uring_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"io_uring", &vfs_io_uring_fns);
}
