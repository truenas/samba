/*
 * Durable handles on ZFS
 *
 * Copyright (C) iXsystems, Inc. 2026
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

/*
 * The vfs_default cookie is wrapped in a cookie that also holds the file's
 * change cookie. ZFS changes the change cookie on every data or metadata
 * change and stores it on disk. A different change cookie at reconnect
 * means that the file changed while the handle was disconnected. This is
 * also true after a failover.
 *
 * vfs_default compares stat fields. ZFS changes the block count when a
 * transaction group syncs. If the change cookie is the same,
 * zc_durable_refresh() updates the stat in the inner cookie before
 * vfs_default compares it.
 *
 * smbd sets TRUENAS_ZFS_DURABLE_RESTORED in the cookie of each durable open
 * that it restores (truenas_hastate/restore.c). The inner cookie of a
 * restored open can come from the open, not from a disconnect.
 * vfs_default reconnects only with a cookie from a disconnect. For a
 * restored open, zc_durable_refresh() allows the reconnect after the
 * change cookie check.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "truenas_hastate/truenas_hastate.h"
#include "truenas_smbhad_client.h"
#include "vfs_zfs_core.h"

static NTSTATUS zc_durable_wrap(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				const SMB_STRUCT_STAT *st,
				DATA_BLOB inner,
				uint32_t flags,
				DATA_BLOB *cookie)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *share = lp_servicename(talloc_tos(),
				     lp_sub,
				     SNUM(handle->conn));
	struct truenas_zfs_durable_cookie zc = {
		.flags = flags,
		.change_cookie = st->st_ex_change_cookie,
		/* for the scavenger, see truenas_hastate/send.c */
		.share = share,
		.inner = inner,
	};
	bool ok;

	/* The change cookie is the only check of a reconnect. */
	if (!(st->st_ex_iflags & ST_EX_IFLAG_HAS_CHANGE_COOKIE)) {
		TALLOC_FREE(share);
		return NT_STATUS_NOT_SUPPORTED;
	}
	ok = truenas_zfs_durable_cookie_push(mem_ctx, &zc, cookie);
	TALLOC_FREE(share);
	return ok ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

/*
 * TRUENAS_ZFS_DURABLE_NO_SYNC if a flush does not write the data of fsp to
 * disk: the dataset has sync=disabled, or smbd cannot read its sync
 * property. Only truenas_hastate/hooks.c reads it.
 */
static uint32_t zc_sync_flags(struct vfs_handle_struct *handle,
			      struct files_struct *fsp)
{
	const struct zfs_dataset *ds = NULL;
	const struct zfs_dataset_prop *props = NULL;

	if (!lp_truenas_stateful_failover()) {
		return 0;
	}
	ds = zfs_core_fsp_get_ds(handle, fsp);
	if (ds != NULL) {
		props = smb_zfs_dataset_props(ds);
	}
	if ((props == NULL) || props->sync_disabled) {
		return TRUENAS_ZFS_DURABLE_NO_SYNC;
	}
	return 0;
}

NTSTATUS zfs_core_durable_cookie(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *cookie)
{
	DATA_BLOB inner = data_blob_null;
	NTSTATUS status;

	status = SMB_VFS_NEXT_DURABLE_COOKIE(handle, fsp, talloc_tos(), &inner);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = zc_durable_wrap(handle,
				 mem_ctx,
				 &fsp->fsp_name->st,
				 inner,
				 zc_sync_flags(handle, fsp),
				 cookie);
	data_blob_free(&inner);
	return status;
}

NTSTATUS zfs_core_durable_disconnect(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     const DATA_BLOB old_cookie,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *new_cookie)
{
	struct truenas_zfs_durable_cookie zc = { .flags = 0 };
	DATA_BLOB inner = old_cookie;
	DATA_BLOB new_inner = data_blob_null;
	uint32_t flags = 0;
	NTSTATUS status;

	if (truenas_zfs_durable_cookie_pull(talloc_tos(), &old_cookie, &zc)) {
		inner = zc.inner;
	}
	status = SMB_VFS_NEXT_DURABLE_DISCONNECT(handle,
						 fsp,
						 inner,
						 talloc_tos(),
						 &new_inner);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (fsp->truenas_fsp_flags & TRUENAS_FSP_HA_DIRTY) {
		/* read at reconnect by truenas_hastate_open() */
		flags |= TRUENAS_ZFS_DURABLE_DIRTY;
	}
	/* vfs_default_durable_disconnect() updated fsp->fsp_name->st */
	status = zc_durable_wrap(handle,
				 mem_ctx,
				 &fsp->fsp_name->st,
				 new_inner,
				 flags,
				 new_cookie);
	data_blob_free(&new_inner);
	return status;
}

static void zc_cookie_stat(struct vfs_default_durable_stat *dst,
			   const SMB_STRUCT_STAT *st)
{
	*dst = (struct vfs_default_durable_stat) {
		.st_ex_dev = st->st_ex_dev,
		.st_ex_ino = st->st_ex_ino,
		.st_ex_mode = st->st_ex_mode,
		.st_ex_nlink = st->st_ex_nlink,
		.st_ex_uid = st->st_ex_uid,
		.st_ex_gid = st->st_ex_gid,
		.st_ex_rdev = st->st_ex_rdev,
		.st_ex_size = st->st_ex_size,
		.st_ex_atime = st->st_ex_atime,
		.st_ex_mtime = st->st_ex_mtime,
		.st_ex_ctime = st->st_ex_ctime,
		.st_ex_btime = st->st_ex_btime,
		.st_ex_iflags = st->st_ex_iflags,
		.st_ex_blksize = st->st_ex_blksize,
		.st_ex_blocks = st->st_ex_blocks,
		.st_ex_flags = st->st_ex_flags,
	};
}

/*
 * Fails if the file has a different change cookie. Otherwise writes the
 * current stat of the file into the inner cookie.
 */
static NTSTATUS zc_durable_refresh(struct vfs_handle_struct *handle,
				   struct truenas_zfs_durable_cookie *zc)
{
	struct connection_struct *conn = handle->conn;
	struct vfs_default_durable_cookie cookie = { .version = 0 };
	struct files_struct *dirfsp = NULL;
	struct smb_filename *smb_fname = NULL;
	struct smb_filename *rel_fname = NULL;
	const SMB_STRUCT_STAT *st = NULL;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = ndr_pull_struct_blob_all(
		&zc->inner, talloc_tos(), &cookie,
		(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}
	if ((cookie.servicepath == NULL) || (cookie.base_name == NULL) ||
	    (strcmp(cookie.servicepath, conn->connectpath) != 0)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* as vfs_default_durable_reconnect() finds the file */
	status = filename_convert_dirfsp_rel(talloc_tos(),
					     conn,
					     conn->cwd_fsp,
					     cookie.base_name,
					     UCF_LCOMP_LNK_OK,
					     0,
					     &dirfsp,
					     &smb_fname,
					     &rel_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if ((smb_fname->fsp == NULL) || !S_ISREG(smb_fname->st.st_ex_mode)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	st = &smb_fname->fsp->fsp_name->st;
	if (!(st->st_ex_iflags & ST_EX_IFLAG_HAS_CHANGE_COOKIE)) {
		DBG_NOTICE("%s has no change cookie\n", cookie.base_name);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (st->st_ex_change_cookie != zc->change_cookie) {
		DBG_NOTICE("%s changed while disconnected, "
			   "change cookie %"PRIu64" != %"PRIu64"\n",
			   cookie.base_name,
			   st->st_ex_change_cookie,
			   zc->change_cookie);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* fdos_mode() sets the birth time that vfs_default compares */
	fdos_mode(smb_fname->fsp);
	zc_cookie_stat(&cookie.stat_info, &smb_fname->fsp->fsp_name->st);
	if (zc->flags & TRUENAS_ZFS_DURABLE_RESTORED) {
		cookie.allow_reconnect = true;
	}

	ndr_err = ndr_push_struct_blob(
		&zc->inner, talloc_tos(), &cookie,
		(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}
	return NT_STATUS_OK;
}

NTSTATUS zfs_core_durable_reconnect(struct vfs_handle_struct *handle,
				    struct smb_request *smb1req,
				    struct smbXsrv_open *op,
				    const DATA_BLOB old_cookie,
				    TALLOC_CTX *mem_ctx,
				    struct files_struct **fsp,
				    DATA_BLOB *new_cookie)
{
	struct truenas_zfs_durable_cookie zc = { .flags = 0 };
	DATA_BLOB new_inner = data_blob_null;
	NTSTATUS status;

	if (!truenas_zfs_durable_cookie_pull(talloc_tos(), &old_cookie, &zc)) {
		/* a cookie made before vfs_zfs_core wrapped cookies */
		return SMB_VFS_NEXT_DURABLE_RECONNECT(handle,
						      smb1req,
						      op,
						      old_cookie,
						      mem_ctx,
						      fsp,
						      new_cookie);
	}

	status = zc_durable_refresh(handle, &zc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = SMB_VFS_NEXT_DURABLE_RECONNECT(handle,
						smb1req,
						op,
						zc.inner,
						mem_ctx,
						fsp,
						&new_inner);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	/* read by truenas_hastate_open() */
	status = zc_durable_wrap(handle,
				 mem_ctx,
				 &(*fsp)->fsp_name->st,
				 new_inner,
				 (zc.flags & TRUENAS_ZFS_DURABLE_DIRTY) |
				 zc_sync_flags(handle, *fsp),
				 new_cookie);
	data_blob_free(&new_inner);
	return status;
}
