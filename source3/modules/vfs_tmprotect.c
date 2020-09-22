/* tmprotect: a module for automatic ZFS snapshot maintenance.
 *
 * Copyright (C) iXsystems Inc     2019
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
#include "smbd/globals.h"
#include "system/filesys.h"
#include "lib/util/tevent_ntstatus.h"

#include "modules/smb_libzfs.h"

#define TMPROTECT_PREFIX "aapltm"
#define TMPROTECT_MODULE "tmprotect"

static const char *null_string = NULL;
static const char **empty_list = &null_string;
static const char *default_aapl = "aapltm-*";
static const char **default_prefix = &default_aapl;

enum autorollback {A_ALWAYS, A_POWERLOSS, A_DISABLED};

struct tmprotect_config_data {
	struct smblibzfshandle *libzp;
	struct smbzhandle *hdl;
	const char **inclusions;
	const char **exclusions;
	enum autorollback autorollback;
	time_t last_snap;
	time_t oldest_snap;
};

static const struct enum_list autorollback[] = {
	{A_ALWAYS, "always"},
	{A_POWERLOSS, "powerloss"},
	{A_DISABLED, "never"},
	{ -1, NULL}
};

static void tmprotect_free_data(void **pptr) {
	/*
	 * Remove dataset flag in destructor function of VFS handle.
	 * This ensures will get triggered in case of session ending
	 * but will not be triggered in case of power loss event or
	 * application crash. The idea here is that if this function
	 * isn't called for an smb session, then the data is more
	 * likely to be questionable.
	 */
	struct tmprotect_config_data *config = NULL;

	config = talloc_get_type_abort(*pptr, struct tmprotect_config_data);
	if (config == NULL) {
		DBG_ERR("Unable to retrieve config information from handle\n");
		return;
	}
	if (config->autorollback != A_DISABLED) {
		smb_zfs_set_user_prop(config->hdl, "tm_in_progress", "false");
	}
}


static void tmprotect_disconnect(vfs_handle_struct *handle)
{
	int ret;
	time_t curtime;
	struct tmprotect_config_data *config = NULL;
	char *snapshot_name = NULL;
	time(&curtime);
	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct tmprotect_config_data,
				NULL);

	/*
	 * Time machine will back up once every 15 minutes by default.
	 * Refuse to take more frequent snapshots than that.
	 */
	if ((config->last_snap + 900) > curtime) {
		DBG_INFO("Refusing to generate new snapshot on disconnect"
			 "last snapshot is less than 15 minutes old\n");
		return;
	}
	snapshot_name = talloc_asprintf(talloc_tos(), "%s-%lu",
					TMPROTECT_PREFIX,
					curtime);

	ret = smb_zfs_snapshot(config->hdl, snapshot_name, false);
	if (ret != 0) {
		DBG_ERR("Failed to generate closing snapshot on path: %s\n",
			handle->conn->connectpath);
	}
}

static int tmprotect_connect(struct vfs_handle_struct *handle,
			     const char *service, const char *user)
{
	int ret, retention, min_snaps, enumval;
	size_t remaining_snaps;
	struct tmprotect_config_data *config = NULL;
	struct smblibzfshandle *libzp = NULL;
	struct dataset_list *ds_list = NULL;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_list *to_delete = NULL;
	struct snapshot_entry *entry = NULL;
	struct snapshot_entry *del_entry = NULL;
	time_t curtime;
	double seconds = 0.0;
	ret = retention = min_snaps = 0;
	char *backup_interrupted = NULL;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret != 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct tmprotect_config_data);
	if (!config) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}
	to_delete = talloc_zero(handle->conn, struct snapshot_list);

	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &config->libzp,
			    &ds_list);
	if (ret != 0) {
		return -1;
	}
	if (ds_list == NULL) {
		DBG_ERR("Path [%s] is not a ZFS filesystem\n",
			handle->conn->connectpath);
		errno = EINVAL;
		return -1;
	}
	config->hdl = ds_list->root->zhandle;

	/*
	 * Copy the connectpath to the config so that it's guaranteed
	 * to be available in the config destructor. It must be
	 * available so that we can unset the custom dataset property
	 * indicating that a backup is in progress.
	 */
	config->inclusions = lp_parm_string_list(SNUM(handle->conn),
						 TMPROTECT_MODULE,
						 "include", default_prefix);

	config->exclusions = lp_parm_string_list(SNUM(handle->conn),
						 TMPROTECT_MODULE,
						 "exclude", empty_list);


	enumval = lp_parm_enum(SNUM(handle->conn), TMPROTECT_MODULE,
			       "auto_rollback", autorollback, A_DISABLED);

	if (enumval == -1) {
		DBG_ERR("value for [tmprotect: auto_rollback] type unknown\n");
		errno = EINVAL;
		return -1;
	}

	config->autorollback = (enum autorollback)enumval;


	retention = lp_parm_int(SNUM(handle->conn),
				TMPROTECT_MODULE,
				"retention", 7);

	min_snaps = lp_parm_int(SNUM(handle->conn),
				TMPROTECT_MODULE,
				"min_snaps", 24);

	retention *= 86400; //convert from days to seconds

	time(&curtime);

	/*
	 * Iterate through list of snapshots with the tmprotect
	 * prefixand check for ones that we need to remove,
	 * and add them to the to_delete list.
	 */
	snapshots = zhandle_list_snapshots(config->hdl,
					   talloc_tos(),
					   false,
					   config->inclusions,
					   config->exclusions,
					   0, 0);

	for (entry = snapshots->entries; entry; entry = entry->next) {
		if ((config->last_snap == 0) ||
		    (entry->cr_time > config->last_snap)) {
			config->last_snap = entry->cr_time;
		}
		seconds = difftime(curtime, entry->cr_time);
		if (((config->oldest_snap == 0) ||
		    (entry->cr_time < config->oldest_snap)) &&
		    (seconds < retention)) {
			config->oldest_snap = entry->cr_time;
		}
		if (seconds > retention) {
			DBG_INFO("Appending [%s] to list of snapshots "
				 "to be deleted.\n", entry->name);
			del_entry = talloc_zero(talloc_tos(), struct snapshot_entry);
			del_entry->name = talloc_strdup(talloc_tos(), entry->name);
			DLIST_ADD(to_delete->entries, del_entry);
			to_delete->num_entries++;
		}
	}
	remaining_snaps = snapshots->num_entries - to_delete->num_entries;
	/*
	 * We need to ensure that we keep at least min_snaps, and that at least one
	 * of those snaps is somewhat old. Otherwise, refuse to delete. This is to
	 * address potential issue of login storm causing min_snaps to suddenly increase
	 * and trigger a pruning of useful history. It's better to err on the side of
	 * having too many snapshots.
	 */
	if (remaining_snaps > min_snaps || (config->oldest_snap > (curtime-(retention/2)))) {
		DBG_INFO("num_snaps: %zu, num_delete: %zu, remaining_snaps: %zu, "
			 "min snaps: %d\n", snapshots->num_entries,
			 to_delete->num_entries, remaining_snaps, min_snaps);
		to_delete->dataset_name = talloc_strdup(talloc_tos(), snapshots->dataset_name);
		ret = smb_zfs_delete_snapshots(config->libzp,
					       talloc_tos(),
					       to_delete);
		if (ret != 0) {
			DBG_ERR("failed to delete list of expired snapshots\n");
		}
	}
	else {
		DBG_INFO("Refusing to delete stale snapshots because "
			 "the remaining number of snapshots would "
			 "be less than the value specified in "
			 "tmprotect:min_snaps [%d]\n", min_snaps);
	}
	TALLOC_FREE(to_delete);

	switch (config->autorollback){
	case A_ALWAYS:
		smb_zfs_rollback_last(config->hdl);
		break;
	case A_POWERLOSS:
		ret = smb_zfs_get_user_prop(config->hdl,
					    talloc_tos(),
					    "tm_in_progress",
					    &backup_interrupted);
		if ((ret == 0) && (strcmp(backup_interrupted, "true") == 0)) {
			smb_zfs_rollback_last(config->hdl);
		}
		break;
	default:
		break;
	}
	if (config->autorollback != A_DISABLED) {
		smb_zfs_set_user_prop(config->hdl, "tm_in_progress", "true");
	}
	SMB_VFS_HANDLE_SET_DATA(handle, config,
				tmprotect_free_data, struct tmprotect_config_data,
				return -1);
}

static struct vfs_fn_pointers tmprotect_fns = {
	.disconnect_fn = tmprotect_disconnect,
	.connect_fn = tmprotect_connect
};

NTSTATUS vfs_tmprotect_init(TALLOC_CTX *);
NTSTATUS vfs_tmprotect_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "tmprotect", &tmprotect_fns);
}
