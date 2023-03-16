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

static const char *default_aapl[2] = {"aapltm-*", NULL};
static const char *tm_plist_suffix = "SnapshotHistory.plist";
static int vfs_tmprotect_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_tmprotect_debug_level

struct tmprotect_config_data {
	struct smbzhandle *hdl;
	struct snap_filter *filter;
	int retention;
	int min_snaps;
	bool enabled;
	FILE *history_file;
	time_t last_snap;
	time_t oldest_snap;
	time_t last_success;
};

static bool init_zfs(vfs_handle_struct *handle,
		     struct tmprotect_config_data *config)
{
	int ret;
	struct smblibzfshandle *libzp = NULL;
	struct zfs_dataset *ds = NULL;

	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &ds,
			    handle->conn->tcon != NULL);
	if (ret != 0) {
		DBG_ERR("Failed to initialize libzfs: %s\n", strerror(errno));
		return false;
	}
	if (ds == NULL) {
		DBG_ERR("Path [%s] is not a ZFS filesystem\n",
			handle->conn->connectpath);
		errno = EINVAL;
		return false;
	}
	config->hdl = ds->zhandle;
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
					   config->filter);
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
			strlcpy(del_entry->name, entry->name,
				sizeof(del_entry->name));
			DLIST_ADD(to_delete->entries, del_entry);
			to_delete->num_entries++;
		}
	}

	remaining_snaps = snapshots->num_entries - to_delete->num_entries;
	if (remaining_snaps > config->min_snaps) {
		DBG_INFO("num_snaps: %zu, num_delete: %zu, remaining_snaps: %zu, "
			 "min snaps: %d\n", snapshots->num_entries,
			 to_delete->num_entries, remaining_snaps, config->min_snaps);
		strlcpy(to_delete->dataset_name, snapshots->dataset_name,
			sizeof(to_delete->dataset_name));
		become_root();
		ret = smb_zfs_delete_snapshots(to_delete);
		unbecome_root();
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
					   config->filter);
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

		DBG_DEBUG("Evaluating history line: %s\n", line);
		begin = strstr(line, "<date>");
		if (begin == NULL || begin == line) {
			DBG_DEBUG("skipping line: %s\n", line);
			continue;
		}

		end = strptime(begin, TS_FORMAT, &ts);
		if (end == NULL) {
			DBG_ERR("%s: strptime() failed: %s\n",
				begin, strerror(errno));
			free(line);
			return false;
		}

		cnt++;

		tm_int = mktime(&ts);
		if (*timestamp >= tm_int) {
			DBG_DEBUG("timestamp %ld is more recent than %ld\n",
				  *timestamp, tm_int);
			continue;
		}

		*timestamp = tm_int;
	}

	*cntp = cnt;
	free(line);
	rewind(history);
	return true;
}

static bool open_history(int _fd, struct tmprotect_config_data *config)
{
	FILE *history = NULL;
	const char *p = NULL;
	char buf[PATH_MAX];
	int fd;

	p = sys_proc_fd_path(_fd, buf, sizeof(buf));
	SMB_ASSERT(p != NULL);

	fd = open(p, O_RDONLY);
	if (fd == -1) {
		DBG_ERR("open() failed: %s\n", strerror(errno));
		return false;
	}

	history = fdopen(fd, "r");
	if (history == NULL) {
		DBG_ERR("fdopen() failed: %s\n",
			strerror(errno));
		close(fd);
		return false;
	}

	config->history_file = history;
	return true;
}

static int tmprotect_openat(vfs_handle_struct *handle,
                            const struct files_struct *dirfsp,
                            const struct smb_filename *smb_fname,
                            files_struct *fsp,
                            const struct vfs_open_how *how)
{
	int ret;
	struct tmprotect_config_data *config = NULL;
	size_t cnt, flen, slen = strlen(tm_plist_suffix);
	time_t last_success = 0;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct tmprotect_config_data,
				NULL);

	ret = SMB_VFS_NEXT_OPENAT(handle,
				  dirfsp,
				  smb_fname,
				  fsp, how);

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

	ok = open_history(ret, config);
	if (!ok) {
		DBG_ERR("%s at %s: failed to open history file\n",
			smb_fname_str_dbg(smb_fname), fsp_str_dbg(dirfsp));
		return ret;
	}

	ok = parse_history(config->history_file, &cnt, &last_success);
	if (ok && cnt) {
		config->last_success = last_success;
	}

	ok = prune_snapshots(handle, config);
	if (!ok) {
		DBG_ERR("Failed to prune snapshots\n");
	}
	return ret;
}


static bool history_changed(vfs_handle_struct *handle,
			    const struct tmprotect_config_data *config)
{
	bool ok, rv = false;
	time_t timestamp = 0;
	size_t cnt = 0;

	ok = parse_history(config->history_file, &cnt, &timestamp);
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

out:
	fclose(config->history_file);
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
	int ret, saved_errno;
	struct tmprotect_config_data *config = NULL;
	const char **inclusions = NULL;
	const char **exclusions = NULL;

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

	config->filter = talloc_zero(config, struct snap_filter);
	if (config->filter == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	inclusions = lp_parm_string_list(SNUM(handle->conn),
					 TMPROTECT_MODULE,
					 "include", default_aapl);
	if (inclusions != NULL) {
		config->filter->inclusions = str_list_copy(config, inclusions);
		if (config->filter->inclusions == NULL) {
			DBG_ERR("%s: str_list_copy failed: %s\n",
				service, strerror(errno));
			goto disconnect_out;
		}
	}

	exclusions = lp_parm_string_list(SNUM(handle->conn),
					 TMPROTECT_MODULE,
					 "exclude", NULL);
	if (exclusions != NULL) {
		config->filter->exclusions = str_list_copy(config, exclusions);
		if (config->filter->exclusions == NULL) {
			DBG_ERR("%s: str_list_copy failed: %s\n",
				service, strerror(errno));
			goto disconnect_out;
		}
	}

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

disconnect_out:

	TALLOC_FREE(config);
	saved_errno = errno;
	SMB_VFS_NEXT_DISCONNECT(handle);
	errno = saved_errno;
	return -1;
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
