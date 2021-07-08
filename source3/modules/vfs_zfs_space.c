/*-
 * Copyright 2015 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "includes.h"
#include "system/filesys.h"
#include "lib/util/tevent_ntstatus.h"

#include "modules/smb_libzfs.h"

struct zfs_space_config_data {
	struct smblibzfshandle *libzp;
};

static uint64_t vfs_zfs_space_disk_free(vfs_handle_struct *handle, const struct smb_filename *smb_fname,
    uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	uint64_t res;
	char rp[PATH_MAX] = { 0 };
	struct zfs_space_config_data *config = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_space_config_data,
				return -1);

	if (realpath(smb_fname->base_name, rp) == NULL)
		return (-1);

	DEBUG(9, ("realpath = %s\n", rp));

	res = smb_zfs_disk_free(config->libzp, rp, bsize, dfree, dsize, geteuid());
	if (res == (uint64_t)-1)
		res = SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	if (res == (uint64_t)-1)
		return (res);

	DEBUG(9, ("*bsize = %" PRIu64 "\n", *bsize));
	DEBUG(9, ("*dfree = %" PRIu64 "\n", *dfree));
	DEBUG(9, ("*dsize = %" PRIu64 "\n", *dsize));

	return (res);
}

static int vfs_zfs_space_connect(struct vfs_handle_struct *handle,
                            const char *service, const char *user)
{
	int ret;
	struct zfs_space_config_data *config = NULL;
	struct smblibzfshandle *libzp = NULL;

	config = talloc_zero(handle->conn, struct zfs_space_config_data);
	if (!config) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	ret = get_smblibzfs_handle(handle->conn, &libzp);
	if (ret != 0) {
		DBG_ERR("Failed to get smblibzfs handle\n");
		errno = ENOMEM;
		return -1;
	}
	config->libzp = libzp;
	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct zfs_space_config_data,
				return -1);
	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static struct vfs_fn_pointers vfs_zfs_space_fns = {
	.disk_free_fn = vfs_zfs_space_disk_free,
	.connect_fn = vfs_zfs_space_connect
};

NTSTATUS vfs_zfs_space_init(TALLOC_CTX *);
NTSTATUS vfs_zfs_space_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
		"zfs_space", &vfs_zfs_space_fns);
}
