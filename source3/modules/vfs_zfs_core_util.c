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

const struct zfs_dataset *smbfname_to_ds(const struct connection_struct *conn,
				   struct zfs_core_config_data *config,
				   const struct smb_filename *smb_fname)
{
	int ret;
	SMB_STRUCT_STAT sbuf;
	const SMB_STRUCT_STAT *psbuf = NULL;
	const struct zfs_dataset *resolved = NULL;

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

	if (psbuf->st_ex_mnt_id == 0) {
		/*
		 * Every stat taken through our VFS carries the unique mount
		 * ID. A zero here means the SMB_STRUCT_STAT was synthesized
		 * elsewhere and there is nothing to resolve.
		 */
		DBG_ERR("%s: stat has no unique mount ID\n",
			smb_fname_str_dbg(smb_fname));
		errno = ENOTSUP;
		return NULL;
	}

	if (psbuf->st_ex_mnt_id == config->ds->mnt_id) {
		return config->ds;
	}

	resolved = smb_zfs_lookup_dataset(psbuf->st_ex_mnt_id);
	if (resolved != NULL) {
		return resolved;
	}

	DBG_ERR("%s: no dataset found for mount id: %" PRIu64 "\n",
		smb_fname_str_dbg(smb_fname), psbuf->st_ex_mnt_id);
	errno = ENOENT;
	return NULL;
}

const struct zfs_dataset *zfs_core_fsp_get_ds(struct vfs_handle_struct *handle,
					struct files_struct *fsp)
{
	struct zfs_core_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				smb_panic(__location__));

	return smbfname_to_ds(handle->conn, config, fsp->fsp_name);
}
