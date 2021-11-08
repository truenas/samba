/* zfs_fsrvp: a module implementing FSS using ZFS
 *
 * Copyright (C) iXsystems Inc     2021
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
#include "system/filesys.h"
#include "smbd/globals.h"
#include "modules/smb_libzfs.h"
#include "../libcli/security/security.h"
#include "../libcli/security/dom_sid.h"

#define ZFS_FSRVP_PREFIX "fss"
#define ZFS_FSRVP_MODULE "zfs_fsrvp"
#define ZFS_FSRVP_SNAPLEN 17

struct zfs_fsrvp_config_data {
	struct zfs_dataset *ds;
	char *dataset_name;
};


/*
 * Check whether a path can be shadow copied. Return the base ZFS dataset, allowing
 * the caller to determine if multiple paths lie on the same ZFS dataset.
 */
static NTSTATUS zfs_fsrvp_check_path(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     const char *service_path,
				     char **base_volume)
{
	struct zfs_fsrvp_config_data *config = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct zfs_fsrvp_config_data,
				return NT_STATUS_NO_MEMORY);

	*base_volume = talloc_strdup(mem_ctx, config->ds->dataset_name);
	DBG_INFO("zfs_fsrvp: base volume is [%s]\n", *base_volume);
	return NT_STATUS_OK;
}

static bool is_permitted_user(const struct security_token *token)
{
	bool is_disk_op, is_backup_op;
	is_disk_op = is_backup_op = false;
	is_disk_op = security_token_has_privilege(
			token,
			SEC_PRIV_DISK_OPERATOR);
	is_backup_op = security_token_has_sid(
			token,
			&global_sid_Builtin_Backup_Operators);

	return (is_disk_op || is_backup_op);
}

static NTSTATUS zfs_fsrvp_snap_create(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      const char *base_volume,
				      time_t *tstamp,
				      bool rw,
				      char **base_path,
				      char **snap_path)
{
	/*
	 * Snap_path must be set to the full path inside the
	 * correct .zfs/snapshot directory. This path is used
	 * when generating the dynamic shares for FSS.
	 *
	 * base_path is set to the ZFS dataset underlying
	 * the original service path.
	 */

	int ret;
	struct timespec ts;
	struct zfs_fsrvp_config_data *config = NULL;
	char snap_name[ZFS_FSRVP_SNAPLEN] = { 0 };

	if (!is_permitted_user(handle->conn->session_info->security_token)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct zfs_fsrvp_config_data,
				return NT_STATUS_NO_MEMORY);

	/*
	 * Snapshots take the format: "fss-<timestamp>".
	 * try to keep the snapshot name as short as possible
	 * while avoiding collisions with other snapshots.
	 * Since these may also be managed from the commandline
	 * "zfs" application, a timestamp is somewhat useful to present.
	 * FreeBSD prior to 12.0 is limited to 80 characters for the
	 * length of mountpoint names, and so shorter is better here.
	 */
	ts = timespec_current();
	snprintf(snap_name, sizeof(snap_name), "%s-%ld%ld",
		 ZFS_FSRVP_PREFIX, ts.tv_sec, ts.tv_nsec);
	become_root();
	ret = smb_zfs_snapshot(config->ds->zhandle, snap_name, false);
	unbecome_root();
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}
	DBG_INFO("Successfully snapshotted [%s]\n", snap_name);
	*snap_path = talloc_asprintf(mem_ctx, "%s/.zfs/snapshot/%s",
				     handle->conn->connectpath, snap_name);
	*base_path = talloc_strdup(mem_ctx, base_volume);
	DBG_INFO("Setting snap path to [%s] and base path to [%s]\n",
		 *snap_path, *base_path);
	return NT_STATUS_OK;
}

static NTSTATUS zfs_fsrvp_snap_delete(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      char *base_path,
				      char *snap_path)
{
	int ret;
	struct zfs_fsrvp_config_data *config = NULL;
	TALLOC_CTX *tmp_ctx;
	struct snapshot_list *to_delete = NULL;
	struct snapshot_entry *del_entry = NULL;
	char *parent = NULL;
	size_t rlen, slen;
	const char *base;

	if (!is_permitted_user(handle->conn->session_info->security_token)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct zfs_fsrvp_config_data,
				return NT_STATUS_NO_MEMORY);

	tmp_ctx = talloc_new(mem_ctx);

	/* The last component of the snapshot mp is the name of the ZFS snapshot */
	if (!parent_dirname(tmp_ctx, snap_path, &parent, &base)) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	to_delete = talloc_zero(tmp_ctx, struct snapshot_list);
	del_entry = talloc_zero(tmp_ctx, struct snapshot_entry);

	to_delete->dataset_name = talloc_strdup(tmp_ctx, base_path);
	to_delete->num_entries = 1;
	del_entry->name = talloc_strdup(tmp_ctx, base);
	DLIST_ADD(to_delete->entries, del_entry);
	become_root();
	ret = smb_zfs_delete_snapshots(config->ds->zhandle->lz,
				       tmp_ctx,
				       to_delete);
	unbecome_root();
	if (ret != 0) {
		TALLOC_FREE(tmp_ctx);
		DBG_ERR("Failed to delete snapshots: %s\n",
			strerror(errno));
		return NT_STATUS_NO_MEMORY;
	}
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static int zfs_fsrvp_connect(struct vfs_handle_struct *handle,
			     const char *service, const char *user)
{
	int ret;
	struct zfs_fsrvp_config_data *config = NULL;
	struct smblibzfshandle *libzp = NULL;
	struct dataset_list *ds_list = NULL;
	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret != 0) {
		return ret;
	}
	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &libzp, &ds_list);

	if (ds_list == NULL) {
		DBG_ERR("Failed to obtain dataset list for connect path. "
			"Path may not be a ZFS filesystem: %s\n",
			handle->conn->connectpath);
		return -1;
	}

	config = talloc_zero(handle->conn, struct zfs_fsrvp_config_data);
	if (!config) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	config->ds = ds_list->root;

	if ((strcmp(ds_list->root->mountpoint, handle->conn->connectpath) != 0) &&
	    (strlen(handle->conn->connectpath) > 15) &&
	    (strnstr(handle->conn->connectpath, "/.zfs/snapshot/", PATH_MAX) == NULL)) {
		DBG_ERR("Sharing a subdirectory inside a ZFS dataset "
			"is not permitted.: Connectpath: %s, Mountpoint: %s\n",
			handle->conn->connectpath, ds_list->root->mountpoint);
		errno = EPERM;
		return -1;
	}
	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct zfs_fsrvp_config_data,
				return -1);

	return ret;
}

static struct vfs_fn_pointers zfs_fsrvp_fns = {
	.snap_check_path_fn = zfs_fsrvp_check_path,
	.snap_create_fn = zfs_fsrvp_snap_create,
	.snap_delete_fn = zfs_fsrvp_snap_delete,
	.connect_fn = zfs_fsrvp_connect
};

NTSTATUS vfs_zfs_fsrvp_init(TALLOC_CTX *);
NTSTATUS vfs_zfs_fsrvp_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
			        "zfs_fsrvp", &zfs_fsrvp_fns);
}
