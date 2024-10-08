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

#include "lib/util/tevent_ntstatus.h"
#include "vfs_zfs_core.h"

static int vfs_zfs_core_debug_level = DBGC_VFS;

struct zfs_dataset *smbfname_to_ds(const struct connection_struct *conn,
				   struct zfs_core_config_data *config,
				   const struct smb_filename *smb_fname)
{
	int ret;
	SMB_STRUCT_STAT sbuf;
	const SMB_STRUCT_STAT *psbuf = NULL;
	struct zfs_dataset *resolved = NULL;
	char *full_path = NULL;
	char *to_free = NULL;
	char path[PATH_MAX + 1];
	int len;

	SMB_ASSERT(config->ds != NULL);
	if (VALID_STAT(smb_fname->st)) {
		psbuf = &smb_fname->st;
	}
	else {
		ret = vfs_stat_smb_basename(discard_const(conn),
					    smb_fname, &sbuf);
		if (ret != 0) {
			DBG_ERR("Failed to stat() %s: %s\n",
				smb_fname_str_dbg(smb_fname), strerror(errno));
			return NULL;
		}
		psbuf = &sbuf;
	}

	if (psbuf->st_ex_dev == config->ds->devid) {
		return config->ds;
	}

	if (config->singleton &&
	    (config->singleton->devid == psbuf->st_ex_dev)) {
		return config->singleton;
	}

	len = full_path_tos(discard_const(conn->cwd_fsp->fsp_name->base_name),
			    smb_fname->base_name,
			    path, sizeof(path),
			    &full_path, &to_free);
	if (len == -1) {
		DBG_ERR("Could not allocate memory in full_path_tos.\n");
		return NULL;
	}

	/*
	 * Our current cache of datasets does not contain the path in
	 * question. Use libzfs to try to get it. Allocate under
	 * memory context of our dataset list.
	 */
	resolved = smb_zfs_path_get_dataset(config, path, true, true, true);
	if (resolved != NULL) {
		TALLOC_FREE(config->singleton);
		TALLOC_FREE(to_free);
		config->singleton = resolved;
		return resolved;
	}

	DBG_ERR("No dataset found for %s with device id: %lu\n",
		path, psbuf->st_ex_dev);
	TALLOC_FREE(to_free);
	errno = ENOENT;
	return NULL;
}

struct zfs_dataset *zfs_core_fsp_get_ds(struct vfs_handle_struct *handle,
					struct files_struct *fsp)
{
	struct zfs_core_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				smb_panic(__location__));

	return smbfname_to_ds(handle->conn, config, fsp->fsp_name);
}
