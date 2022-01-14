/* tmprotect: a module for automatic ZFS snapshot maintenance.
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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "system/filesys.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/security/security.h"
#include "modules/smb_libzfs.h"

#define TMPROTECT_PREFIX "aapltm"
#define TMPROTECT_MODULE "tmprotect"
#define TS_FORMAT "<date>%Y-%m-%dT%H:%M:%SZ</date>"

static const char *null_string = NULL;
static const char **empty_list = &null_string;
static const char *default_aapl = "aapltm-*";
static const char **default_prefix = &default_aapl;
static const char *tm_plist_suffix = "SnapshotHistory.plist";
static int vfs_tmprotect_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_tmprotect_debug_level

struct tmprotect_config_data {
	struct smblibzfshandle *libzp;
	struct smbzhandle *hdl;
	const char **inclusions;
	const char **exclusions;
	int retention;
	int min_snaps;
	bool enabled;
	struct smb_filename *history_file;
	time_t last_snap;
	time_t oldest_snap;
	time_t last_success;
};

static bool init_zfs(vfs_handle_struct *handle,
		     struct tmprotect_config_data *config)
{
	int ret;
	struct smblibzfshandle *libzp = NULL;
	struct dataset_list *ds_list = NULL;

	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &config->libzp,
			    &ds_list,
			    handle->conn->tcon != NULL);
	if (ret != 0) {
		DBG_ERR("Failed to initialize libzfs: %s\n", strerror(errno));
		return false;
	}
	if (ds_list == NULL) {
		DBG_ERR("Path [%s] is not a ZFS filesystem\n",
			handle->conn->connectpath);
		errno = EINVAL;
		return false;
	}
	config->hdl = ds_list->root->zhandle;

	if (ds_list->nentries) {
		DBG_ERR("SMB share contains child datasets. "
			"This is an unsupported configuration. "
			"Disabling snapshot managment\n");
		return false;
	}

	return true;
}

static bool prune_snapshots(vfs_handle_struct *handle,
			    struct tmprotect_config_data *config)
{
	int ret = 0;
	bool ok;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_list *to_delete = NULL;
	struct snapshot_entry *entry = NULL;
	double seconds = 0.0;
	size_t remaining_snaps;
	time_t curtime;

	to_delete = talloc_zero(handle->conn, struct snapshot_list);
	SMB_ASSERT(to_delete != NULL);

	config->enabled = init_zfs(handle, config);
	if (!config->enabled) {
		return false;
	}
	snapshots = zhandle_list_snapshots(config->hdl,
					   talloc_tos(),
					   false,
					   config->inclusions,
					   config->exclusions,
					   0, 0);
	SMB_ASSERT(snapshots != NULL);
	time(&curtime);
	for (entry = snapshots->entries; entry; entry = entry->next) {
		struct snapshot_entry *del_entry = NULL;

		if ((config->last_snap == 0) ||
		    (entry->cr_time > config->last_snap)) {
			config->last_snap = entry->cr_time;
		}
		seconds = difftime(curtime, entry->cr_time);
		if (((config->oldest_snap == 0) ||
		    (entry->cr_time < config->oldest_snap)) &&
		    (seconds < config->retention)) {
			config->oldest_snap = entry->cr_time;
		}
		if (seconds > config->retention) {
			DBG_INFO("Appending [%s] to list of snapshots "
				 "to be deleted.\n", entry->name);
			del_entry = talloc_zero(talloc_tos(), struct snapshot_entry);
			del_entry->name = talloc_strdup(talloc_tos(), entry->name);
			DLIST_ADD(to_delete->entries, del_entry);
			to_delete->num_entries++;
		}
	}

	remaining_snaps = snapshots->num_entries - to_delete->num_entries;
	if (remaining_snaps > config->min_snaps) {
		DBG_INFO("num_snaps: %zu, num_delete: %zu, remaining_snaps: %zu, "
			 "min snaps: %d\n", snapshots->num_entries,
			 to_delete->num_entries, remaining_snaps, config->min_snaps);
		to_delete->dataset_name = talloc_strdup(talloc_tos(), snapshots->dataset_name);
		ret = smb_zfs_delete_snapshots(config->libzp,
					       talloc_tos(),
					       to_delete);
		if (ret != 0) {
			DBG_ERR("failed to delete list of expired snapshots: %s\n",
				strerror(errno));
		}
	} else {
		DBG_INFO("Refusing to delete stale snapshots because "
			 "the remaining number of snapshots would "
			 "be less than the value specified in "
			 "tmprotect:min_snaps [%d]\n", config->min_snaps);
	}

	TALLOC_FREE(to_delete);
	TALLOC_FREE(snapshots);
	return ret == 0;
}

static bool last_snap_ts(vfs_handle_struct *handle,
			 const struct tmprotect_config_data *config,
			 time_t *ts_out)
{
	time_t timestamp = 0;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_entry *entry = NULL;

	snapshots = zhandle_list_snapshots(config->hdl,
					   talloc_tos(),
					   false,
					   config->inclusions,
					   config->exclusions,
					   0, 0);
	if (snapshots == NULL) {
		DBG_ERR("Failed to list snapshots: %s\n", strerror(errno));
		return false;
	}

	for (entry = snapshots->entries; entry; entry = entry->next) {
		if (entry->cr_time > timestamp) {
			timestamp = entry->cr_time;
		}
	}

	TALLOC_FREE(snapshots);
	*ts_out = timestamp;
	return true;
}

static bool parse_history(FILE *history, size_t *cntp, time_t *timestamp)
{
	char *line = NULL;
	size_t linecap = 0, cnt = 0;
	ssize_t linelen;

	while ((linelen = getline(&line, &linecap, history)) > 0) {
		char *begin = NULL, *end = NULL;
		size_t tm_len;
		struct tm ts;
		time_t tm_int;

		begin = strstr(line, "<date>");
		if (begin == NULL || begin == line) {
			continue;
		}

		end = strptime(begin, TS_FORMAT, &ts);
		if (end == NULL) {
			DBG_ERR("strptime() failed: %s\n", strerror(errno));
			free(line);
			return false;
		}

		cnt++;

		tm_int = mktime(&ts);
		if (*timestamp >= tm_int) {
			continue;
		}

		*timestamp = tm_int;
	}

	*cntp = cnt;
	free(line);
	return true;
}

static int tmprotect_openat(vfs_handle_struct *handle,
                            const struct files_struct *dirfsp,
                            const struct smb_filename *smb_fname,
                            files_struct *fsp,
                            int flags, mode_t mode)
{
	int fd, ret;
	struct smb_filename *resolved_fname = NULL;
	struct tmprotect_config_data *config = NULL;
	size_t cnt, flen, slen = strlen(tm_plist_suffix);
	FILE *history = NULL;
	time_t last_success = 0;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct tmprotect_config_data,
				NULL);

	ret = SMB_VFS_NEXT_OPENAT(handle,
				  dirfsp,
				  smb_fname,
				  fsp, flags, mode);

	if ((ret == -1) ||
	    (config->history_file != NULL) ||
	    fsp->fsp_flags.is_pathref) {
		return ret;
	}

	flen = strlen(fsp->fsp_name->base_name);
	if ((flen < slen) ||
	    (strcmp(tm_plist_suffix, fsp->fsp_name->base_name + (flen - slen)) != 0)) {
		return ret;
	}

	resolved_fname = SMB_VFS_REALPATH(handle->conn, handle->conn, fsp->fsp_name);
	if (resolved_fname == NULL) {
		DBG_ERR("%s: realpath() failed: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return ret;
	}

	fd = dup(ret);
	if (fd == -1) {
		DBG_ERR("%s: dup() failed: %s\n",
			smb_fname_str_dbg(resolved_fname),
			strerror(errno));
		goto err;
	}

	history = fdopen(fd, "r");
	if (history == NULL) {
		DBG_ERR("%s: fdopen() failed: %s\n",
			smb_fname_str_dbg(resolved_fname),
			strerror(errno));
		close(fd);
		goto err;
	}

	ok = parse_history(history, &cnt, &last_success);
	if (ok && cnt) {
		config->last_success = last_success;
	}

	fclose(history);
	config->history_file = resolved_fname;

	ok = prune_snapshots(handle, config);
	if (!ok) {
		DBG_ERR("Failed to prune snapshots\n");
	}
	return ret;

err:
	TALLOC_FREE(resolved_fname);
	return ret;
}


static bool history_changed(vfs_handle_struct *handle,
			    const struct tmprotect_config_data *config)
{
	bool ok, rv = false;
	NTSTATUS status;
	int fd;
	struct files_struct *tmp_fsp = NULL;
	FILE *history = NULL;
	time_t timestamp = 0;
	size_t cnt = 0;

	status = create_internal_fsp(handle->conn, config->history_file, &tmp_fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create internal FSP for %s: %s\n",
			smb_fname_str_dbg(config->history_file), nt_errstr(status));
		return false;
	}

	fd = SMB_VFS_NEXT_OPENAT(handle,
				 handle->conn->cwd_fsp,
				 config->history_file,
				 tmp_fsp,
				 O_RDONLY, 0);
	if (fd == -1) {
		DBG_ERR("%s: openat failed for history file: %s\n",
			smb_fname_str_dbg(config->history_file),
			strerror(errno));
		TALLOC_FREE(tmp_fsp);
		return false;
	}

	history = fdopen(fd, "r");
	if (history == NULL) {
		DBG_ERR("%s: fdopen() failed: %s\n",
			smb_fname_str_dbg(config->history_file),
			strerror(errno));
		close(fd);
		TALLOC_FREE(tmp_fsp);
		return false;
	}

	ok = parse_history(history, &cnt, &timestamp);
	if (ok && cnt && timestamp > config->last_success) {
		DBG_INFO("Initial last backup timestamp of tree "
			 "connection [%ld] is older than current "
			 "most recent backup [%ld]. This indicates "
			 "that a successful time machine backup "
			 "occured during this SMB connection.\n",
			 config->last_success, timestamp);
		rv = true;
	}

	DBG_INFO("Backup history file: %zu backups, last: %ld\n",
		 cnt, timestamp);
	TALLOC_FREE(tmp_fsp);
	fclose(history);

	return rv;
}

static void tmprotect_disconnect(vfs_handle_struct *handle)
{
	int ret;
	bool ok;
	time_t curtime, last_snap;
	struct tmprotect_config_data *config = NULL;
	char *snapshot_name = NULL;

	time(&curtime);
	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct tmprotect_config_data,
				NULL);

	/*
	 * This SMB session may not have been a time machine backup.
	 * In this case, skip snapshot parsing.
	 */

	if (!config->enabled || config->history_file == NULL) {
		DBG_INFO("Module was not enabled for this session\n");
		return;
	}

	ok = history_changed(handle, config);
	if (!ok) {
		DBG_INFO("No changes recorded in snapshot history file\n");
		return;
	}

	ok = last_snap_ts(handle, config, &last_snap);
	if (!ok) {
		return;
	}

	/*
	 * Time machine will back up once every 15 minutes by default.
	 * Refuse to take more frequent snapshots than that.
	 */

	if ((config->history_file == NULL) || (last_snap + 900 > curtime)) {
		DBG_ERR("Refusing to generate new snapshot on disconnect"
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
	int ret;
	struct tmprotect_config_data *config = NULL;

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

	config->inclusions = lp_parm_string_list(SNUM(handle->conn),
						 TMPROTECT_MODULE,
						 "include", default_prefix);

	config->exclusions = lp_parm_string_list(SNUM(handle->conn),
						 TMPROTECT_MODULE,
						 "exclude", empty_list);

	config->retention = lp_parm_int(SNUM(handle->conn),
					TMPROTECT_MODULE,
					"retention", 7);

	config->retention *= 86400; //convert from days to seconds
	config->min_snaps = lp_parm_int(SNUM(handle->conn),
					TMPROTECT_MODULE,
					"min_snaps", 3);

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct tmprotect_config_data,
				return -1);
	return 0;
}

static struct vfs_fn_pointers tmprotect_fns = {
	.disconnect_fn = tmprotect_disconnect,
	.connect_fn = tmprotect_connect,
	.openat_fn = tmprotect_openat,
};

NTSTATUS vfs_tmprotect_init(TALLOC_CTX *);
NTSTATUS vfs_tmprotect_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret =  smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "tmprotect", &tmprotect_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_tmprotect_debug_level = debug_add_class("tmprotect");
	if (vfs_tmprotect_debug_level == -1) {
		vfs_tmprotect_debug_level = DBGC_VFS;
		DBG_ERR("Couldn't register custom debugging class\n");
	} else {
		DBG_DEBUG("%s: Debug class number of '%s': %d\n",
		"vfs_tmprotect_init","tmprotect",vfs_tmprotect_debug_level);
	}
	return ret;
}
