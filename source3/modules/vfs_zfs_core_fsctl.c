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
#include "../librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_ioctl.h"

#include "lib/util/tevent_ntstatus.h"
#include "vfs_zfs_core.h"

#define ZC_VALID_CHKSUM (CHECKSUM_TYPE_CRC32 | CHECKSUM_TYPE_CRC32 | \
	CHECKSUM_TYPE_UNCHANGED)

struct zfs_integrity_info {
	bool checksum_enabled;
	uint64_t record_size;
};

static bool zfs_core_get_integrity_info(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					struct zfs_integrity_info *info)
{
	struct zfs_dataset *ds = NULL;
	struct zfs_core_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				smb_panic(__location__));

	if (!config->zfs_integrity_streams_enabled) {
		return false;
	}

	ds = smbfname_to_ds(handle->conn, config, fsp->fsp_name);
	if (ds == NULL) {
		DBG_ERR("%s: failed to retrieve ZFS dataset info: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return false;
	}

	*info = (struct zfs_integrity_info){
		.checksum_enabled = ds->properties->checksum_enabled,
		.record_size = ds->properties->record_size,
	};

	return true;
}

static NTSTATUS zfs_core_set_integrity(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       TALLOC_CTX *mem_ctx,
				       const uint8_t *in_data,
				       uint32_t in_len)
{
	int ndr_ret;
	struct zfs_integrity_info info;
	DATA_BLOB request_blob = (DATA_BLOB) {
		.data = discard_const(in_data),
		.length = in_len
	};
	struct fsctl_set_integrity_req integrity_req = {0};
	int unsupported;

	if (!zfs_core_get_integrity_info(handle, fsp, &info)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	ndr_ret = ndr_pull_struct_blob(&request_blob, mem_ctx, &integrity_req,
				   (ndr_pull_flags_fn_t)ndr_pull_fsctl_set_integrity_req);

	if (ndr_ret != NDR_ERR_SUCCESS) {
		DBG_ERR("%s: failed to unmarshall request to set integrity\n",
			fsp_str_dbg(fsp));
		return NT_STATUS_INVALID_PARAMETER;
	}

	unsupported = integrity_req.chksum_algo & ~ZC_VALID_CHKSUM;
	if (unsupported) {
		DBG_ERR("%u: unsupported checksum algorithm\n",
			unsupported);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (integrity_req.chksum_algo == CHECKSUM_TYPE_NONE) {
		/*
		 * ZFS doesn't allow turning off checksumming on a
		 * per-file basis, and it would be somewhat insane
		 * to allow this anyway. For now we'll just fail
		 * with STATUS_ACCESS_DENIED since clients in theory
		 * should have reasonable handling for it.
		 */
		if (info.checksum_enabled) {
			DBG_INFO("%s: rejecting attempt to turn off file "
				 "checksumming.\n", fsp_str_dbg(fsp));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		if (!info.checksum_enabled) {
			/*
			 * Log an error message in case user has for
			 * some reason disabled checksum on the dataset
			 */
			DBG_ERR("%s: rejecting attempt to enable file "
				"checksumming. Checksumming is currently "
				"disabled on the underlying dataset!\n",
				fsp_str_dbg(fsp));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (integrity_req.flags & FLAG_CHECKSUM_ENFORCEMENT_OFF) {
		DBG_ERR("%s: client attempted to disable checksum "
			"enforcement, which is not permitted under ZFS.\n",
			fsp_str_dbg(fsp));

		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

static NTSTATUS zfs_core_get_integrity(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       TALLOC_CTX *mem_ctx,
				       uint8_t **out_data,
				       uint32_t max_out,
				       uint32_t *out_len)
{
	int ndr_ret;
	DATA_BLOB output = {0};
	struct integrity_state integ_state;
	struct zfs_integrity_info info;

	if (!zfs_core_get_integrity_info(handle, fsp, &info)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	integ_state = (struct integrity_state){
		.reserved = 0,
		.chksum_chunk_sz = 4096,
		.cluster_sz = info.record_size
	};

	if (info.checksum_enabled) {
		integ_state.chksum_algo = CHECKSUM_TYPE_CRC64;
	} else {
		integ_state.chksum_algo = CHECKSUM_TYPE_NONE;
		integ_state.flags = FLAG_CHECKSUM_ENFORCEMENT_OFF;
	}

	ndr_ret = ndr_push_struct_blob(
		&output, mem_ctx, &integ_state,
		(ndr_push_flags_fn_t)(ndr_push_integrity_state));
	if (ndr_ret != NDR_ERR_SUCCESS) {
		DBG_ERR("%s: failed to marshall integrity state: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (max_out < output.length) {
		DBG_ERR("%s: max output %u too small for integrity "
			"state: %ld\n", fsp_str_dbg(fsp), max_out,
			(long int)output.length);

		return NT_STATUS_INVALID_USER_BUFFER;
	}

	*out_data = output.data;
	*out_len = (uint32_t)output.length;

	return NT_STATUS_OK;
}

NTSTATUS zfs_core_fsctl(struct vfs_handle_struct *handle,
			struct files_struct *fsp,
			TALLOC_CTX *ctx,
			uint32_t function,
			uint16_t req_flags,
			const uint8_t *_in_data,
			uint32_t in_len,
			uint8_t **_out_data,
			uint32_t max_out_len,
			uint32_t *out_len)
{
	switch (function){
	case FSCTL_SET_INTEGRITY_INFORMATION:
		return zfs_core_set_integrity(handle, fsp, ctx, _in_data, in_len);

	case FSCTL_GET_INTEGRITY_INFORMATION:
		return zfs_core_get_integrity(handle, fsp, ctx, _out_data,
					      max_out_len, out_len);
	default:
		break;
	}


	return SMB_VFS_NEXT_FSCTL(handle,
				  fsp,
				  ctx,
				  function,
				  req_flags,
				  _in_data,
				  in_len,
				  _out_data,
				  max_out_len,
				  out_len);
}
