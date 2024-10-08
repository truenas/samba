/*
 *  Unix SMB/CIFS implementation.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "includes.h"
#include "smbd/globals.h"
#include "smbd/smbd.h"
#include "libcli/security/security.h"
#include "auth.h"
#include "privileges.h"
#include "system/filesys.h"
#include <linux/ioctl.h>
#include <linux/fs.h>

#include "lib/util/tevent_ntstatus.h"
#include "vfs_zfs_core.h"
#include "offload_token.h"

static void zfs_core_offload_read_done(struct tevent_req *subreq);
static void zfs_core_offload_write_done(struct tevent_req *subreq);
static struct vfs_offload_ctx *zfs_core_offload_ctx;


/*
 * Check whether block cloning is enabled and supported on the zpool
 * under the share connectpath.
 *
 * @param[in] handle - VFS handle for the tree connect
 * @param[in] ds - ZFS dataset underlying share connectpath
 * @returns bool - true if feature is enabled, false on error or if
 *     feature is disabled.
 *
 * false is returned on error with log message to prevent breaking
 * SMB share access (this will only disable support for a specific
 * FSCTL).
 */
static bool zfs_core_block_cloning_enabled(struct vfs_handle_struct *handle,
                                           struct zfs_dataset *ds)
{
	bool config_enabled;
	bool feat_enabled;

	config_enabled = lp_parm_bool(SNUM(handle->conn),
				      "zfs_core", "zfs_block_cloning", false);
	if (!config_enabled) {
		return false;
	}

	if (ds == NULL) {
		// This can happen if for some reason user has been
		// mucking in shell and decided to export non-ZFS filesystem
		return false;
	}

	if (!smb_zfs_pool_feature_enabled(ds,
					  SMBZFS_BLOCK_CLONING,
					  &feat_enabled)) {
		// libzfs call failed, which is unexpected, but we've
		// already logged.
		return false;
	}

	if (!feat_enabled) {
		DBG_ERR("%s: block cloning parameters enabled on path, "
			"however, the block cloning ZFS feature is not enabled "
			"on the underlying storage pool.\n",
			handle->conn->connectpath);
	}

	return feat_enabled;
}

struct zfs_core_offload_read_state {
	struct vfs_handle_struct *handle;
	files_struct *fsp;
	uint32_t flags;
	uint32_t fsctl;
	uint64_t xferlen;
	DATA_BLOB token;
};

/*
 * This is a wrapper around the VFS default server-side copy
 * We allocate a separate state to track whether we're performing
 * FSCTL_DUP_EXTENTS_TO_FILE when processing the async recv / done.
 */
struct tevent_req *zc_generic_offload_read_send(
	TALLOC_CTX *mem_ctx,
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
	struct zfs_core_offload_read_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct zfs_core_offload_read_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct zfs_core_offload_read_state) {
		.handle = handle,
		.fsp = fsp,
		.fsctl = fsctl,
	};

	subreq = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp,
						fsctl, ttl, offset, to_copy);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, zfs_core_offload_read_done, req);
	return req;
}

/*
 * This provides handling for FSCTL_DUP_EXTENTS_TO_FILE if server is
 * configured for block cloning and zpool supports it
 */
struct tevent_req *zc_clone_offload_read_send(
	TALLOC_CTX *mem_ctx,
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
	struct zfs_core_offload_read_state *state = NULL;
	NTSTATUS status;

	if (fsctl != FSCTL_DUP_EXTENTS_TO_FILE) {
		return zc_generic_offload_read_send(mem_ctx, ev,
						    handle, fsp,
						    fsctl, ttl,
						    offset, to_copy);
	}

	req = tevent_req_create(mem_ctx, &state,
				struct zfs_core_offload_read_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct zfs_core_offload_read_state) {
		.handle = handle,
		.fsp = fsp,
		.fsctl = fsctl,
	};

	/*
	 * We need to initialize the offload token here
	 * because we are not passing through lower VFS offload
	 * functions
	 */
	status = vfs_offload_token_ctx_init(fsp->conn->sconn->client,
					    &zfs_core_offload_ctx);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = vfs_offload_token_create_blob(state, fsp, fsctl,
					       &state->token);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = vfs_offload_token_db_store_fsp(zfs_core_offload_ctx, fsp,
						&state->token);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_done(req);

	return tevent_req_post(req, ev);
}

/*
 * Callback function for generic wrapper around COPY_CHUNK related requests
 */
static void zfs_core_offload_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = NULL;
	struct zfs_core_offload_read_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct zfs_core_offload_read_state);

	// This should only be for generic server-side copy
	SMB_ASSERT(state->fsctl != FSCTL_DUP_EXTENTS_TO_FILE);

	if (state->fsctl != FSCTL_SRV_REQUEST_RESUME_KEY) {
		tevent_req_done(req);
		return;
	}

	status = vfs_offload_token_ctx_init(state->fsp->conn->sconn->client,
					    &zfs_core_offload_ctx);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(subreq,
						state->handle,
						state,
						&state->flags,
						&state->xferlen,
						&state->token);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = vfs_offload_token_db_store_fsp(zfs_core_offload_ctx,
						state->fsp,
						&state->token);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

/*
 * Common receive function shared between all configurations
 */
static NTSTATUS zc_common_offload_read_recv(struct tevent_req *req,
					    struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    uint32_t *flags,
					    uint64_t *xferlen,
					    DATA_BLOB *token)
{
        struct zfs_core_offload_read_state *state = NULL;
	NTSTATUS status;

	state = tevent_req_data(req, struct zfs_core_offload_read_state);
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*flags = state->flags;
	*xferlen = state->xferlen;
	token->length = state->token.length;
	token->data = talloc_move(mem_ctx, &state->token.data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct zfs_core_offload_write_state {
	struct vfs_handle_struct *handle;
	off_t copied;
	struct files_struct *src_fsp;
	struct files_struct *dst_fsp;
	uint32_t fsctl;
};

static bool zc_copy_file_range_impl(int fd_in,
				    off_t off_in,
				    int fd_out,
				    off_t off_out,
				    size_t len,
				    uint flags)
{
	size_t remaining = len;
	size_t nwritten = 0;
	ssize_t rv;

	/*
	 * we must loop here because copy_file_range() may
	 * return less than the length originally requested
	 */
	while (remaining > 0) {
		off_t in = off_in + nwritten;
		off_t out = off_out + nwritten;

		rv = copy_file_range(fd_in, &in,
				     fd_out, &out,
				     remaining, flags);
		if (rv < 0) {
			return false;
		}

		/*
		 * copy_file_range() may return 0 if the specified file offset
		 * of fd_in is at or past the end of file. Receiving it while
		 * copying is unexpected (possibly truncated file), but it's
		 * unclear how this can happen. For this reason we'll
		 * assert and hopefully get corefile for investigation
		 */
		SMB_ASSERT(rv != 0);

		nwritten += rv;
		SMB_ASSERT(remaining - rv >= 0);
		remaining -= rv;
	}

	return true;
}

/*
 * async offload write send endpoint that gets called if:
 * 1. block cloning support not enabled
 * 2. block cloning is enabled, but request isn't FSCTL_DUP_EXTENTS_TO_FILE
 */
static struct tevent_req *zc_generic_offload_write_send(struct vfs_handle_struct *handle,
							TALLOC_CTX *mem_ctx,
							struct tevent_context *ev,
							uint32_t fsctl,
							DATA_BLOB *token,
							off_t transfer_offset,
							struct files_struct *dest_fsp,
							off_t dest_off,
							off_t num)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct zfs_core_offload_write_state *state = NULL;
	files_struct *src_fsp = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct zfs_core_offload_write_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct zfs_core_offload_write_state) {
		.handle = handle,
		.dst_fsp = dest_fsp,
		.fsctl = fsctl
	};

	subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle,
						 state,
						 ev,
						 fsctl,
						 token,
						 transfer_offset,
						 dest_fsp,
						 dest_off,
						 num);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				zfs_core_offload_write_done,
				req);
	return req;
}

/*
 * async offload write send endpoint that gets called if block cloning is enabled.
 * This may perform an immediate copy_file_range() loop if FSCTL_DUP_EXTENTS_TO_FILE
 * is called, otherwise it will fall back to vfs_default.
 */
static struct tevent_req *zc_clone_offload_write_send(struct vfs_handle_struct *handle,
						      TALLOC_CTX *mem_ctx,
						      struct tevent_context *ev,
						      uint32_t fsctl,
						      DATA_BLOB *token,
						      off_t transfer_offset,
						      struct files_struct *dst_fsp,
						      off_t dst_off,
						      off_t num)
{
	struct tevent_req *req = NULL;
	struct zfs_core_offload_write_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct lock_struct src_lck;
	struct lock_struct dest_lck;
	off_t src_off = transfer_offset;
	files_struct *src_fsp = NULL;
	int ret;
	bool handle_offload_write = true;
	bool do_locking = false;
	NTSTATUS status;
	bool ok;

	if (fsctl != FSCTL_DUP_EXTENTS_TO_FILE) {
		return zc_generic_offload_write_send(handle, mem_ctx, ev,
						     fsctl, token, transfer_offset,
						     dst_fsp, dst_off,
						     num);
	}

	req = tevent_req_create(mem_ctx, &state,
				struct zfs_core_offload_write_state);
	if (req == NULL) {
		return NULL;
	}

	status = vfs_offload_token_ctx_init(handle->conn->sconn->client,
					    &zfs_core_offload_ctx);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = vfs_offload_token_db_fetch_fsp(zfs_core_offload_ctx,
						token, &src_fsp);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = vfs_offload_token_check_handles(fsctl, src_fsp, dst_fsp);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	/* Update cached stat so that we have more accurate size */
	status = vfs_stat_fsp(src_fsp);

	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (src_fsp->fsp_name->st.st_ex_size < src_off + num) {
		tevent_req_nterror(req, NT_STATUS_INVALID_VIEW_SIZE);
		return tevent_req_post(req, ev);
	}

	/*
	 * copy_file_range() is called because zfs_clone_range()
	 * fails with EAGAIN if dirty data neds to be written to
	 * disk. copy_file_range() first tries to clone and then
	 * resorts to copy in this case.
	 */
	ok = zc_copy_file_range_impl(fsp_get_io_fd(src_fsp), src_off,
				     fsp_get_io_fd(dst_fsp), dst_off,
				     num, 0);
	if (!ok) {
		DBG_ERR("DUPLICATE_EXTENTS_TO_FILE from %s to %s failed with error: %s\n",
			fsp_str_dbg(src_fsp), fsp_str_dbg(dst_fsp), strerror(errno));

		/* Attempt to provide same errors as MS-FSCC 2.3.8 */
		switch(errno) {
		case EBADF:
		case EINVAL:
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			break;
		case EXDEV:
			// Windows server actually responds with NT_STATUS_INVALID_HANDLE
			// despite documentation to the contrary
			tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
		case EOPNOTSUPP:
			tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
			break;
		default:
			tevent_req_error(req, errno);
		};
		return tevent_req_post(req, ev);
	}

	*state = (struct zfs_core_offload_write_state) {
		.handle = handle,
		.dst_fsp = dst_fsp,
		.src_fsp = src_fsp,
		.fsctl = fsctl,
		.copied = num
	};

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

/*
 * This is called if:
 * 1. block cloning disabled
 * or
 * 2. COPY_CHUNK and related requests (not FSCTL_DUP_EXTENTS_TO_FILE)
 */
static void zfs_core_offload_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct zfs_core_offload_write_state *state;
	NTSTATUS status;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct zfs_core_offload_write_state);

	SMB_ASSERT(state->fsctl != FSCTL_DUP_EXTENTS_TO_FILE);

	status = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(state->handle,
						 subreq,
						 &state->copied);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS zc_common_offload_write_recv(struct vfs_handle_struct *handle,
					     struct tevent_req *req,
					     off_t *copied)
{
	struct zfs_core_offload_write_state *state = NULL;
	NTSTATUS status;

	state = tevent_req_data(req, struct zfs_core_offload_write_state);
	if (tevent_req_is_nterror(req, &status)) {
		DBG_INFO("%d: offload write from %s -> %s failed: %s\n",
			 state->fsctl, fsp_str_dbg(state->src_fsp),
			 fsp_str_dbg(state->dst_fsp),
			 nt_errstr(status));
		tevent_req_received(req);
		return status;
	}

	*copied = state->copied;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*
 * Generic VFS function endpoints that wrap around opmap loaded on during
 * initial SMB tree connection. They get loaded when vfs_zfs_core is registered
 * in the Samba VFS. Depending on server configuration they will either call
 * generic variants of the endpoints that simply wrap around vfs_default or
 * they will call variants that support block cloning.
 */
static inline const
zc_offload_ops_t *zfs_core_handle_get_offload_ops(struct vfs_handle_struct *handle)
{
	struct zfs_core_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				smb_panic(__location__));

	SMB_ASSERT(config->offload_ops != NULL);
	SMB_ASSERT((config->offload_ops->opmap_type == ZC_OFFLOAD_GENERIC) ||
		   (config->offload_ops->opmap_type == ZC_OFFLOAD_CLONE));

	return config->offload_ops;
}

struct tevent_req *zfs_core_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *hdl,
	files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_cp)
{
	const zc_offload_ops_t *ops = zfs_core_handle_get_offload_ops(hdl);

	return ops->read_send(mem_ctx, ev, hdl, fsp, fsctl, ttl, offset, to_cp);
}

NTSTATUS zfs_core_offload_read_recv(struct tevent_req *req,
				    struct vfs_handle_struct *handle,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *flags,
				    uint64_t *xferlen,
				    DATA_BLOB *token)
{
	const zc_offload_ops_t *ops = zfs_core_handle_get_offload_ops(handle);

	return ops->read_recv(req, handle, mem_ctx, flags, xferlen, token);
}

struct tevent_req *zfs_core_offload_write_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       uint32_t fsctl,
					       DATA_BLOB *token,
					       off_t transfer_offset,
					       struct files_struct *dest_fsp,
					       off_t dest_off,
					       off_t num)
{
	const zc_offload_ops_t *ops = zfs_core_handle_get_offload_ops(handle);

	return ops->write_send(
		handle, mem_ctx, ev, fsctl, token, transfer_offset,
		dest_fsp, dest_off, num
	);
}


NTSTATUS zfs_core_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied)
{
	const zc_offload_ops_t *ops = zfs_core_handle_get_offload_ops(handle);

	return ops->write_recv(handle, req, copied);
}


/* opmap handling */
/*
 * Our default offload opmap, which is basically a wrapper around
 * the vfs default offload read / write
 */
const zc_offload_ops_t zc_generic_opmap = (zc_offload_ops_t) {
	.opmap_type = ZC_OFFLOAD_GENERIC,
	.read_send = zc_generic_offload_read_send,
	.read_recv = zc_common_offload_read_recv,
	.write_send = zc_generic_offload_write_send,
	.write_recv = zc_common_offload_write_recv
};

/*
 * Opmap for TrueNAS enterprise, which adds support for
 * FSCTL_DUP_EXTENTS_TO_FILE via .write_send.
 *
 * This will be expanded as-needed.
 */
const zc_offload_ops_t zc_clone_opmap = (zc_offload_ops_t) {
	.opmap_type = ZC_OFFLOAD_CLONE,
	.read_send = zc_clone_offload_read_send,
	.read_recv = zc_common_offload_read_recv,
	.write_send = zc_clone_offload_write_send,
	.write_recv = zc_common_offload_write_recv
};

void zfs_core_set_offload_ops(struct vfs_handle_struct *handle,
			      struct zfs_core_config_data *config,
			      struct zfs_dataset *ds)
{
	SMB_ASSERT(config != NULL);
	bool block_cloning_enabled;
	const zc_offload_ops_t *opmap = NULL;

	block_cloning_enabled = zfs_core_block_cloning_enabled(handle, ds);
	opmap = block_cloning_enabled ? &zc_clone_opmap : &zc_generic_opmap;

	config->offload_ops = opmap;
}
