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

#include "modules/smb_libzfs.h"

enum zc_offload_map_t {ZC_OFFLOAD_GENERIC = 1, ZC_OFFLOAD_CLONE};

typedef struct zfs_core_offload_ops {
	enum zc_offload_map_t opmap_type;
	struct tevent_req *(*read_send)(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct vfs_handle_struct *handle,
					files_struct *fsp, uint32_t fsctl,
					uint32_t ttl, off_t offset,
					size_t to_copy);
	NTSTATUS (*read_recv)(struct tevent_req *req,
			      struct vfs_handle_struct *handle,
			      TALLOC_CTX *mem_ctx, uint32_t *flags,
			      uint64_t *xferlen, DATA_BLOB *token);
	struct tevent_req *(*write_send)(struct vfs_handle_struct *handle,
					 TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 uint32_t fsctl,
					 DATA_BLOB *token,
					 off_t transfer_offset,
					 struct files_struct *dest_fsp,
					 off_t dest_off,
					 off_t to_copy);
	NTSTATUS (*write_recv)(struct vfs_handle_struct *handle,
			       struct tevent_req *req,
			       off_t *copied);
} zc_offload_ops_t;

struct zfs_core_config_data {
	struct zfs_dataset *ds;
	struct zfs_dataset *singleton;
	struct zfs_dataset **created;
	size_t ncreated;
	bool zfs_space_enabled;
	bool zfs_quota_enabled;
	bool zfs_auto_create;
	bool checked;
	const char *dataset_auto_quota;
	uint64_t base_user_quota;
	const zc_offload_ops_t *offload_ops;
};

/* vfs_zfs_core_rw.c */
struct tevent_req *zfs_core_offload_read_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct vfs_handle_struct *handle, files_struct *fsp, uint32_t fsctl,
	uint32_t ttl, off_t offset, size_t to_copy);

NTSTATUS zfs_core_offload_read_recv(
	struct tevent_req *req, struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx, uint32_t *flags, uint64_t *xferlen,
	DATA_BLOB *token);

struct tevent_req *zfs_core_offload_write_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t fsctl,
	DATA_BLOB *token,
	off_t transfer_offset,
	struct files_struct *dest_fsp,
	off_t dest_off,
	off_t to_copy);

NTSTATUS zfs_core_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied);

void zfs_core_set_offload_ops(struct vfs_handle_struct *handle,
			      struct zfs_core_config_data *config,
			      struct zfs_dataset *ds);
