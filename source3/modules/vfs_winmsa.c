/*
 * ACL management VFS module
 *
 * Copyright (C) iXsystems, Inc. 2021
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "libcli/security/security.h"
#include "libcli/security/dom_sid.h"
#include "passdb/lookup_sid.h"
#include "librpc/gen_ndr/ndr_security.h"
#include <fts.h>

static NTSTATUS set_inherited_acl(vfs_handle_struct *handle,
				  files_struct *parent_fsp,
				  files_struct *target_fsp)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct security_descriptor *parent_desc = NULL;
	struct security_descriptor *psd = NULL;
	struct smb_filename *parent_dir = NULL, *atname = NULL;
	size_t size = 0;
	bool inheritable_components, ok;
	bool isdir = S_ISDIR(target_fsp->fsp_name->st.st_ex_mode);

	status = parent_pathref(frame,
				parent_fsp,
				target_fsp->fsp_name,
				&parent_dir,
				&atname);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = SMB_VFS_FGET_NT_ACL(parent_dir->fsp,
				     SECINFO_DACL, frame, &parent_desc);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to get NT ACL on [%s]: %s\n",
			 fsp_str_dbg(parent_fsp), strerror(errno));
		TALLOC_FREE(frame);
		return status;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("parent: %s\n", smb_fname_str_dbg(parent_dir));
		NDR_PRINT_DEBUG(security_descriptor, parent_desc);
	}

	ok = sd_has_inheritable_components(parent_desc, true);
	if (!ok) {
		TALLOC_FREE(frame);
		/* Nothing to inherit and not setting owner. */
		DBG_ERR("Parent ACL in destination directory [%s] has no inheritable "
			"components. Maintaining ACL from source.",
			smb_fname_str_dbg(parent_dir));
		return NT_STATUS_OK;
	}

	status = se_create_child_secdesc(frame,
					 &psd,
					 &size,
					 parent_desc,
					 NULL,
					 NULL,
					 isdir);
	if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to create child secdesc\n");
			TALLOC_FREE(frame);
			return status;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("ACL to set on [%s]\n", fsp_str_dbg(target_fsp));
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	status = SMB_VFS_FSET_NT_ACL(target_fsp,
				     SECINFO_DACL,
				     psd);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS winmsa_inherit_acl(vfs_handle_struct *handle,
				   files_struct *dirfsp,
				   const struct smb_filename *smb_fname)
{
	NTSTATUS status;
	files_struct *tmp_fsp = NULL;
	struct smb_filename *tmp_fname = NULL;
	int flags, tmp_fd, error;
	mode_t unix_mode;
	bool do_acl_inherit;

	status = create_internal_fsp(handle->conn, smb_fname, &tmp_fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create internal FSP for %s: %s\n",
			smb_fname_str_dbg(smb_fname), nt_errstr(status));
		return status;
	}

	tmp_fname = cp_smb_filename(tmp_fsp, smb_fname);

	if (!VALID_STAT(tmp_fname->st)) {
		error = SMB_VFS_STAT(handle->conn, tmp_fname);
		if (error) {
			DBG_ERR("stat failed for %s: %s\n",
				smb_fname_str_dbg(tmp_fname), strerror(errno));
                        return map_nt_error_from_unix(errno);
		}
	}

	if (S_ISDIR(tmp_fname->st.st_ex_mode)) {
		DBG_ERR("setting directory on %s\n", smb_fname_str_dbg(tmp_fname));
		flags = O_DIRECTORY;
		unix_mode = (0777 & lp_directory_mask(SNUM(handle->conn)));
	}
	else {
		flags = O_RDWR;
		unix_mode = (0777 & lp_create_mask(SNUM(handle->conn)));
	}

	/*
	 * Use fd_openat() and fd_close() for symlink safety.
	 */
	status= fd_openat(dirfsp, tmp_fname, tmp_fsp, flags, unix_mode);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to open %s, flags 0x%08x, mode: 0o%o: %s\n",
			smb_fname_str_dbg(tmp_fname), flags, unix_mode,
			nt_errstr(status));
		return status;
	}

	status = set_inherited_acl(handle, dirfsp, tmp_fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to inherit new ACL %s: %s\n",
			smb_fname_str_dbg(tmp_fname), nt_errstr(status));
	}

	status = fd_close(tmp_fsp);
	return status;
}



static bool must_inherit(vfs_handle_struct *handle,
			 files_struct *srcfsp,
			 const struct smb_filename *smb_fname_src,
			 files_struct *dstfsp,
			 const struct smb_filename *smb_fname_dst)
{
	struct smb_filename *src = NULL, *dst = NULL;
	struct smb_filename *src_atname = NULL, *dst_atname = NULL;
	bool ok;
	int error;
	NTSTATUS status;

	status = parent_pathref(handle->conn,
				srcfsp,
				smb_fname_src,
				&src,
				&src_atname);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = parent_pathref(handle->conn,
				dstfsp,
				smb_fname_dst,
				&dst,
				&dst_atname);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(src);
		TALLOC_FREE(src_atname);
		return false;
	}

	error = SMB_VFS_STAT(handle->conn, src);
	if (error) {
		DBG_ERR("stat() failed for %s: %s\n",
			smb_fname_str_dbg(src),
			strerror(errno));
		ok = false;
		goto out;
	}

	error = SMB_VFS_STAT(handle->conn, dst);
	if (error) {
		DBG_ERR("stat() failed for %s: %s\n",
			smb_fname_str_dbg(dst),
			strerror(errno));
		ok = false;
		goto out;
	}

	/* Stayed in same directory, so skip ACL change */
	if (((src->st.st_ex_dev) == (dst->st.st_ex_dev)) &&
	    ((src->st.st_ex_ino) == (dst->st.st_ex_ino))) {
		ok = false;
	}

out:
	TALLOC_FREE(src);
	TALLOC_FREE(src_atname);
	TALLOC_FREE(dst);
	TALLOC_FREE(dst_atname);
	return ok;
}

static int handle_file(vfs_handle_struct *handle,
		       FTS *ftsp,  files_struct *dirfsp,
		       const struct smb_filename *orig_dst,
		       FTSENT *entry)
{
	struct smb_filename *tmp_fname = NULL;
	int error;
	NTSTATUS status;

	tmp_fname = synthetic_smb_fname(handle->conn,
					entry->fts_accpath,
					NULL,
					NULL,
					0,
					0);

	error = SMB_VFS_STAT(handle->conn, tmp_fname);
	if (error) {
		TALLOC_FREE(tmp_fname);
		return error;
	}

	status = winmsa_inherit_acl(handle, dirfsp, tmp_fname);
	if (!NT_STATUS_IS_OK(status)) {
		error = -1;
	}
	TALLOC_FREE(tmp_fname);
	return error;
}

static int do_fts_walk(vfs_handle_struct *handle,
		       files_struct *dstfsp,
		       const struct smb_filename *dst)
{
	FTS *ftsp = NULL;
	FTSENT *entry = NULL;
	int error = 0;
	char *paths[2] = { dst->base_name, NULL };

	ftsp = fts_open(paths, (FTS_PHYSICAL | FTS_NOCHDIR), NULL);
	if (ftsp == NULL) {
		return -1;
	}

	while ((entry = fts_read(ftsp)) != NULL) {
		switch(entry->fts_info) {
		case FTS_D:
		case FTS_F:
			error += handle_file(handle, ftsp, dstfsp, dst, entry);
			break;
		case FTS_ERR:
			DBG_ERR("fts_read() [%s]: %s\n",
				entry->fts_path, strerror(entry->fts_errno));
			error += entry->fts_errno;
			break;
		}
	}

	return error;
}

static int winmsa_renameat(vfs_handle_struct *handle,
			   files_struct *srcfsp,
			   const struct smb_filename *src,
			   files_struct *dstfsp,
			   const struct smb_filename *dst)
{

	int error = 0;
	bool do_inherit;
	NTSTATUS status;
	files_struct *tmp_fsp = NULL;
	SMB_STRUCT_STAT sbuf;

	error = SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, src, dstfsp, dst);
	if (error) {
		DBG_INFO("winmsa_rename: rename failed: %s\n",
			 strerror(errno));
		return error;
	}

	error = vfs_stat_smb_basename(handle->conn, dst, &sbuf);
	if (error) {
		return error;
	}

	do_inherit = must_inherit(handle, srcfsp, src, dstfsp, dst);
	if (!do_inherit) {
		return 0;
	}

	if (S_ISDIR(sbuf.st_ex_mode)) {
		error = do_fts_walk(handle, dstfsp, dst);
		if (error) {
			return -1;
		}
	}
	else {
		status = winmsa_inherit_acl(handle, dstfsp, dst);
		if (!NT_STATUS_IS_OK(status)) {
			return -1;
		}
	}

	return 0;
}

static struct vfs_fn_pointers winmsa_fns = {
	.renameat_fn = winmsa_renameat,
};

NTSTATUS vfs_winmsa_init(TALLOC_CTX *);
NTSTATUS vfs_winmsa_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "winmsa",
				&winmsa_fns);
}
