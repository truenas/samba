/*
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) iXsystems, Inc			2023
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/tevent_unix.h"
#include "offload_token.h"

#include <jansson.h>
#include "audit_logging.h"
#include "vfs_truenas_audit.h"

#define TN_RVAL_UNIX(x) ((tn_rval_t){.error = x})
#define TN_RVAL_NTSTATUS(x) ((tn_rval_t){.status = x})

/*
 * Read and write operations (either server-side or otherwise)
 * are audited as follows:
 *
 * Per SMB Tree Connection:
 * - read and write operations counters that are incremented for each
 *   operation. For this purpose offloaded and regular operations are combined.
 *   These counters are printed on TREE DISCONNECT.
 *
 * Per open file:
 * - read and write operations counters that are incremented for each operation
 *   on the file. For this purpose offloaded and regular operations are
 *   combined. These counters are printed on file close.
 *
 * - read and write byte counters that are incremented for each operation on
 *   the file. For this purpose offloaded and regular operations are combined.
 *   These counters are printed on file close.
 *
 * Sample `event_data` for write operation is as follows:
 *  {
 *    "file": {
 *      "handle": {
 *        "type": "DEV_INO",
 *        "value": "41:14:0"
 *      }
 *    },
 *    "result": {
 *      "type": "UNIX",
 *      "value_raw": 0,
 *      "value_parsed": "SUCCESS"
 *    },
 *    "vers": "0_1"
 *  }
 *
 * NOTE: read, write, offload_read, and offload_write operations are differentiated
 * by the contents of `event` in body of JSON log message.
 */
static bool tn_log_rw_common(vfs_handle_struct *handle,
			     files_struct *fsp,
			     tn_op_t op,
			     size_t bytes,
			     tn_rval_t result)
{
	tn_audit_ext_t *fsp_ext = NULL;
	struct json_object msg, entry;
	struct timespec now, *old = NULL;
	bool ok;
	tn_audit_conf_t *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t,
				smb_panic("Failed to get config"));

	fsp_ext = (tn_audit_ext_t *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (fsp_ext == NULL) {
		return true;
	}

	switch(op) {
	case TN_OP_READ_DATA:
		old = &fsp_ext->last_read;
		config->op_cnt.read++;
		fsp_ext->ops.read_cnt++;
		if (fsp_ext->ops.read_bytes + bytes > sizeof(size_t)) {
			fsp_ext->ops.write_wrap++;
		}
		fsp_ext->ops.read_bytes += bytes;
		break;
	case TN_OP_WRITE_DATA:
		old = &fsp_ext->last_write;
		config->op_cnt.write++;
		fsp_ext->ops.write_cnt++;
		if (fsp_ext->ops.write_bytes + bytes > sizeof(size_t)) {
			fsp_ext->ops.write_wrap++;
		}
		fsp_ext->ops.write_bytes += bytes;
		break;
	case TN_OP_OFFLOAD_READ_DATA:
		old = &fsp_ext->last_offload_read;
		config->op_cnt.read++;
		fsp_ext->ops.read_cnt++;
		if (fsp_ext->ops.read_bytes + bytes > sizeof(size_t)) {
			fsp_ext->ops.write_wrap++;
		}
		fsp_ext->ops.read_bytes += bytes;
		break;
	case TN_OP_OFFLOAD_WRITE_DATA:
		old = &fsp_ext->last_offload_write;
		config->op_cnt.write++;
		fsp_ext->ops.write_cnt++;
		if (fsp_ext->ops.write_bytes + bytes > sizeof(size_t)) {
			fsp_ext->ops.write_wrap++;
		}
		fsp_ext->ops.write_bytes += bytes;
		break;
	default:
		smb_panic("Unexpected op");
	};

	if (old->tv_sec) {
		if (config->rw_interval == 0) {
			// 0 here means only log first instance
			return true;
		}
		clock_gettime_mono(&now);
		if ((now.tv_sec - old->tv_sec) < config->rw_interval) {
			return true;
		}
	}

	clock_gettime_mono(&now);

	ok = tn_init_json_msg(&msg, &entry);
	if (!ok) {
		return false;
	}

	ok = tn_add_file_to_object(fsp->fsp_name, fsp_ext, "file", FILE_ADD_HANDLE, &entry);
	if (!ok) {
		goto cleanup;
	}

	switch (op) {
	case TN_OP_READ_DATA:
	case TN_OP_WRITE_DATA:
		ok = tn_add_result_unix(result.error, &msg, &entry);
		break;
	case TN_OP_OFFLOAD_READ_DATA:
	case TN_OP_OFFLOAD_WRITE_DATA:
		ok = tn_add_result_ntstatus(result.status, &msg, &entry);
		break;
	default:
		smb_panic("Unexpected op");
	};

	if (!ok) {
		goto cleanup;
	}

	ok = tn_format_log_entry(handle, config, op, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	tn_audit_do_log(config, &msg);

	memcpy(old, &now, sizeof(struct timespec));

cleanup:
	json_free(&msg);
	json_free(&entry);
	return ok;
}

ssize_t tn_audit_pread(vfs_handle_struct *handle, files_struct *fsp,
			      void *data, size_t n, off_t offset)
{
	ssize_t result;
	bool ok;

	result = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);

	if (result > 0) {
		tn_log_rw_common(handle, fsp, TN_OP_READ_DATA,
				 result, TN_RVAL_UNIX(0));
	} else {
		tn_log_rw_common(handle, fsp, TN_OP_READ_DATA,
				 0, TN_RVAL_UNIX(errno));
	}

	return result;
}

ssize_t tn_audit_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			       const void *data, size_t n, off_t offset)
{
	ssize_t result;
	bool ok;

	result = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);

	if (result > 0) {
		tn_log_rw_common(handle, fsp, TN_OP_WRITE_DATA,
				 result, TN_RVAL_UNIX(0));
	} else {
		tn_log_rw_common(handle, fsp, TN_OP_WRITE_DATA,
				 0, TN_RVAL_UNIX(errno));
	}

	return result;
}

enum tn_async_op_type {
	TN_ASYNC_READ,
	TN_ASYNC_OFFLOAD_READ,
	TN_ASYNC_WRITE,
	TN_ASYNC_OFFLOAD_WRITE,
};

typedef struct tn_audit_asnyc_op_state {
	vfs_handle_struct *handle;
	files_struct *fsp;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
	enum tn_async_op_type op_type;
} tn_op_state_t;

static void tn_audit_async_common_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	tn_op_state_t *state = tevent_req_data(req, tn_op_state_t);

	switch(state->op_type) {
	case TN_ASYNC_READ:
		state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
		break;
	case TN_ASYNC_WRITE:
		state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
		break;
	default:
		smb_panic("unknown op type\n");
	};

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

ssize_t tn_audit_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	tn_op_state_t *state = tevent_req_data(req, tn_op_state_t);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tn_log_rw_common(state->handle, state->fsp, TN_OP_READ_DATA,
				 0, TN_RVAL_UNIX(vfs_aio_state->error));
		return -1;
	}

	tn_log_rw_common(state->handle, state->fsp, TN_OP_READ_DATA,
		         state->ret < 0 ? 0 : state->ret,
			 TN_RVAL_UNIX(0));
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct tevent_req *tn_audit_pread_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	tn_op_state_t *state;

	req = tevent_req_create(mem_ctx, &state, tn_op_state_t);
	if (req == NULL) {
		tn_log_rw_common(handle, fsp, TN_OP_READ_DATA, 0,
				 TN_RVAL_UNIX(errno));
		return NULL;
	}
	state->handle = handle;
	state->fsp = fsp;
	state->op_type = TN_ASYNC_READ;

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
					 n, offset);

	if (tevent_req_nomem(subreq, req)) {
		tn_log_rw_common(handle, fsp, TN_OP_READ_DATA, 0,
				 TN_RVAL_UNIX(errno));
		return tevent_req_post(req, ev);
	}

	/* Do logging on async callback completion */
	tevent_req_set_callback(subreq, tn_audit_async_common_done, req);
	return req;
}

ssize_t tn_audit_pwrite_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	tn_op_state_t *state = tevent_req_data(req, tn_op_state_t);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tn_log_rw_common(state->handle, state->fsp, TN_OP_WRITE_DATA,
				 0, TN_RVAL_UNIX(vfs_aio_state->error));
		return -1;
	}

	tn_log_rw_common(state->handle, state->fsp, TN_OP_WRITE_DATA,
		         state->ret < 0 ? 0 : state->ret, TN_RVAL_UNIX(0));
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct tevent_req *tn_audit_pwrite_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	const void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	tn_op_state_t *state;

	req = tevent_req_create(mem_ctx, &state, tn_op_state_t);
	if (req == NULL) {
		tn_log_rw_common(handle, fsp, TN_OP_WRITE_DATA, 0,
				 TN_RVAL_UNIX(errno));
		return NULL;
	}
	state->handle = handle;
	state->fsp = fsp;
	state->op_type = TN_ASYNC_WRITE;

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
					 n, offset);

	if (tevent_req_nomem(subreq, req)) {
		tn_log_rw_common(handle, fsp, TN_OP_WRITE_DATA, 0,
				 TN_RVAL_UNIX(errno));
		return tevent_req_post(req, ev);
	}

	/* Do logging on async callback completion */
	tevent_req_set_callback(subreq, tn_audit_async_common_done, req);
	return req;
}

static struct vfs_offload_ctx *tnaudit_offload_ctx;

typedef struct tnaudit_offload_read_state {
	struct vfs_handle_struct *handle;
	files_struct *fsp;
	uint32_t fsctl;
	uint32_t flags;
	uint64_t xferlen;
	DATA_BLOB token;
} tn_offload_read_t;

typedef struct tnaudt_offload_write_state {
	struct vfs_handle_struct *handle;
	off_t copied;
	struct files_struct *dst_fsp;
} tn_offload_write_t;

typedef struct tnaudit_offload_common_state {
	union {
		tn_offload_read_t read;
		tn_offload_write_t write;
	};
	enum tn_async_op_type op_type;
} tn_offload_common_t;

#define TNOFFLOAD_READ(x) (&x->read)
#define TNOFFLOAD_WRITE(x) (&x->write)

static void tn_audit_offload_op_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	tn_offload_common_t *state = tevent_req_data(
		req, tn_offload_common_t);
	NTSTATUS status;
	tn_offload_read_t *r_state = NULL;
	tn_offload_write_t *w_state = NULL;
	size_t bytes = 0;

	switch (state->op_type) {
	case TN_ASYNC_OFFLOAD_READ:
		r_state = TNOFFLOAD_READ(state);
		status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(subreq,
							r_state->handle,
							state,
							&r_state->flags,
							&r_state->xferlen,
							&r_state->token);
		TALLOC_FREE(subreq);
		if (tevent_req_nterror(req, status)) {
			tn_log_rw_common(r_state->handle,
					 r_state->fsp, TN_OP_OFFLOAD_READ_DATA,
					 0, TN_RVAL_NTSTATUS(status));
			return;
		}

		if (r_state->fsctl != FSCTL_SRV_REQUEST_RESUME_KEY) {
			tn_log_rw_common(r_state->handle,
					 r_state->fsp, TN_OP_OFFLOAD_READ_DATA,
					 r_state->xferlen,
					 TN_RVAL_NTSTATUS(NT_STATUS_OK));
			tevent_req_done(req);
			return;
		}

		status = vfs_offload_token_ctx_init(
			r_state->fsp->conn->sconn->client,
			&tnaudit_offload_ctx
		);

		if (tevent_req_nterror(req, status)) {
			tn_log_rw_common(r_state->handle,
					 r_state->fsp, TN_OP_OFFLOAD_READ_DATA,
					 0, TN_RVAL_NTSTATUS(status));
			return;
		}

		status = vfs_offload_token_db_store_fsp(
			tnaudit_offload_ctx,
			r_state->fsp,
			&r_state->token);

		if (tevent_req_nterror(req, status)) {
			tn_log_rw_common(r_state->handle,
					 r_state->fsp, TN_OP_OFFLOAD_READ_DATA,
					 0, TN_RVAL_NTSTATUS(status));
			return;
		}

		tn_log_rw_common(r_state->handle,
				 r_state->fsp, TN_OP_OFFLOAD_READ_DATA,
				 r_state->xferlen,
				 TN_RVAL_NTSTATUS(NT_STATUS_OK));
		break;
	case TN_ASYNC_OFFLOAD_WRITE:
		w_state = TNOFFLOAD_WRITE(state);
		status = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(w_state->handle,
							 subreq,
							 &w_state->copied);
		TALLOC_FREE(subreq);

		if (tevent_req_nterror(req, status)) {
			tn_log_rw_common(w_state->handle,
					 w_state->dst_fsp,
					 TN_OP_OFFLOAD_WRITE_DATA,
					 0, TN_RVAL_NTSTATUS(status));
			return;
		}
		bytes = w_state->copied > 0 ? w_state->copied : 0;

		tn_log_rw_common(w_state->handle,
				 w_state->dst_fsp, TN_OP_OFFLOAD_WRITE_DATA,
				 bytes,
				 TN_RVAL_NTSTATUS(NT_STATUS_OK));
		break;
	default:
		smb_panic("Unexpected operation type");
	};

	tevent_req_done(req);
}

struct tevent_req *tn_audit_offload_read_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct vfs_handle_struct *handle,
					     files_struct *fsp,
					     uint32_t fsctl,
					     uint32_t ttl,
					     off_t offset,
					     size_t to_copy)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	tn_offload_common_t *state = NULL;

	req = tevent_req_create(mem_ctx, &state, tn_offload_common_t);
	if (req == NULL) {
		return NULL;
	}
	*state = (tn_offload_common_t) {
		.op_type = TN_ASYNC_OFFLOAD_READ,
		.read = (tn_offload_read_t) {
			.handle = handle,
			.fsp = fsp,
			.fsctl = fsctl,
		},
	};

	subreq = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp,
						fsctl, ttl, offset, to_copy);
	if (tevent_req_nomem(subreq, req)) {
		NTSTATUS status = map_nt_error_from_unix(errno);
		tn_log_rw_common(handle, fsp, TN_OP_OFFLOAD_READ_DATA,
				 0, TN_RVAL_NTSTATUS(status));
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, tn_audit_offload_op_done, req);
	return req;
}

NTSTATUS tn_audit_offload_read_recv(struct tevent_req *req,
				    struct vfs_handle_struct *handle,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *flags,
				    uint64_t *xferlen,
				    DATA_BLOB *token)
{
	tn_offload_common_t *state = tevent_req_data(req, tn_offload_common_t);
	tn_offload_read_t *read_state = TNOFFLOAD_READ(state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DBG_ERR("%s: server side read failed: %s\n",
			fsp_str_dbg(read_state->fsp), nt_errstr(status));
		tevent_req_received(req);
		return status;
	}

	*flags = read_state->flags;
	*xferlen = read_state->xferlen;
	token->length = read_state->token.length;
	token->data = talloc_move(mem_ctx, &read_state->token.data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct tevent_req *tn_audit_offload_write_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t fsctl,
	DATA_BLOB *token,
	off_t transfer_offset,
	struct files_struct *dest_fsp,
	off_t dest_off,
	off_t to_copy)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	tn_offload_common_t *state = NULL;

	req = tevent_req_create(mem_ctx, &state, tn_offload_common_t);
	if (req == NULL) {
		return NULL;
	}
	*state = (tn_offload_common_t) {
		.op_type = TN_ASYNC_OFFLOAD_WRITE,
		.write = (tn_offload_write_t) {
			.handle = handle,
			.dst_fsp = dest_fsp,
		},
	};

	subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle,
						 mem_ctx,
						 ev,
						 fsctl,
						 token,
						 transfer_offset,
						 dest_fsp,
						 dest_off,
						 to_copy);
	if (tevent_req_nomem(subreq, req)) {
		NTSTATUS status = map_nt_error_from_unix(errno);
		tn_log_rw_common(handle, dest_fsp, TN_OP_OFFLOAD_WRITE_DATA,
				 0, TN_RVAL_NTSTATUS(status));
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, tn_audit_offload_op_done, req);
	return req;
}

NTSTATUS tn_audit_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied)
{
	tn_offload_common_t *state = tevent_req_data(req, tn_offload_common_t);
	tn_offload_write_t *write_state = TNOFFLOAD_WRITE(state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DBG_ERR("%s: server side copy chunk failed: %s\n",
			fsp_str_dbg(write_state->dst_fsp), nt_errstr(status));
		tevent_req_received(req);
		*copied = 0;
		return status;
	}
	*copied = write_state->copied;
	tevent_req_received(req);

	return NT_STATUS_OK;
}
