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

#define MODNAME "winmsa"

static int vfs_winmsa_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_winmsa_debug_level
#define WINMSA_DBGLVL debuglevel_get_class(vfs_winmsa_debug_level)

static NTSTATUS set_inherited_acl(vfs_handle_struct *handle,
				  files_struct *parent_fsp,
				  files_struct *target_fsp)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct security_descriptor *parent_desc = NULL;
	struct security_descriptor *psd = NULL;
	size_t size = 0;
	bool inheritable_components, ok;
	struct dom_sid sid_owner, sid_group;
	bool isdir = S_ISDIR(target_fsp->fsp_name->st.st_ex_mode);

	status = SMB_VFS_FGET_NT_ACL(parent_fsp,
				     SECINFO_DACL | SECINFO_OWNER | SECINFO_GROUP,
				     frame, &parent_desc);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to get NT ACL on [%s]: %s\n",
			 fsp_str_dbg(parent_fsp), strerror(errno));
		TALLOC_FREE(frame);
		return status;
	}

	if (WINMSA_DBGLVL > 10) {
		DBG_DEBUG("parent: %s\n", fsp_str_dbg(parent_fsp));
		NDR_PRINT_DEBUG(security_descriptor, parent_desc);
	}

	ok = sd_has_inheritable_components(parent_desc, true);
	if (!ok) {
		TALLOC_FREE(frame);
		/* Nothing to inherit and not setting owner. */
		DBG_ERR("Parent ACL in destination directory [%s] has no inheritable "
			"components. Maintaining ACL from source.",
			fsp_str_dbg(parent_fsp));
		return NT_STATUS_OK;
	}

	uid_to_sid(&sid_owner, target_fsp->fsp_name->st.st_ex_uid);
	gid_to_sid(&sid_group, target_fsp->fsp_name->st.st_ex_gid);

	status = se_create_child_secdesc(frame,
					 &psd,
					 &size,
					 parent_desc,
					 &sid_owner,
					 &sid_group,
					 isdir);
	if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to create child secdesc\n");
			TALLOC_FREE(frame);
			return status;
	}

	if (WINMSA_DBGLVL > 10) {
		DBG_DEBUG("ACL to set on [%s]\n", fsp_str_dbg(target_fsp));
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	status = SMB_VFS_FSET_NT_ACL(target_fsp,
				     SECINFO_DACL,
				     psd);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS generate_synthetic_fsp(vfs_handle_struct *handle,
				       files_struct *dirfsp,
				       FTSENT *target,
				       files_struct **fsp_out)
{
	NTSTATUS status;
	struct smb_filename tmp_fname;
	files_struct *fsp = NULL;
	int fd;
	char tp[PATH_MAX] = {0};
	size_t dirfsp_offset = strlen(dirfsp->fsp_name->base_name) + 1;
#ifdef O_RESOLVE_BENEATH
	int flags = O_RESOLVE_BENEATH;
#else
	smb_panic("WINMSA IS NOT SUPPORTED ON THIS PLATFORM\n");
#endif
	mode_t mode = 0;

	SMB_ASSERT(sizeof(tp) > target->fts_pathlen);

	if (target->fts_pointer == NULL) {
		/* This is a faked-up FTSENT for when we rename within same directory */
		strlcpy(tp, target->fts_path, sizeof(tp));
	} else {
		if (strstr(dirfsp->fsp_name->base_name, target->fts_path) == NULL) {
			DBG_ERR("Invalid path: %s not within %s\n",
				target->fsp_path, fsp_str_dbg(dirfsp));
			return NT_STATUS_NOT_FOUND;
		}
		strlcpy(tp, target->fts_path + dirfsp_offset, target->fts_pathlen - dirfsp_offset + 1);
	}

	tmp_fname = (struct smb_filename) {
		.base_name = tp,
	};

	tmp_fname.st = (SMB_STRUCT_STAT) {
		.st_ex_mode = target->fts_statp->st_mode,
		.st_ex_nlink = target->fts_statp->st_nlink,
		.st_ex_uid = target->fts_statp->st_uid,
		.st_ex_gid = target->fts_statp->st_gid,
		.st_ex_dev = target->fts_statp->st_dev,
		.st_ex_ino = target->fts_statp->st_ino,
		.st_ex_size = target->fts_statp->st_size,
	};

	status = create_internal_fsp(handle->conn, &tmp_fname, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create internal FSP for %s: %s\n",
			smb_fname_str_dbg(&tmp_fname), nt_errstr(status));
		return status;
	}

	if (S_ISDIR(tmp_fname.st.st_ex_mode)) {
		flags |= O_DIRECTORY;
		fsp->fsp_flags.is_directory = true;
		mode = (0777 & lp_directory_mask(SNUM(handle->conn)));
	} else {
		flags |= O_RDWR;
		mode = (0777 & lp_create_mask(SNUM(handle->conn)));
	}

	fd = SMB_VFS_OPENAT(handle->conn, dirfsp, &tmp_fname, fsp, flags, mode);
	if (fd == -1) {
		DBG_ERR("%s: openat failed: %s\n", smb_fname_str_dbg(&tmp_fname), strerror(errno));
		file_free(NULL, fsp);
		return map_nt_error_from_unix(errno);
	}

	fsp->fsp_flags.is_pathref = false;
	fsp_set_fd(fsp, fd);

	*fsp_out = fsp;
	return NT_STATUS_OK;
}

static bool must_inherit(vfs_handle_struct *handle,
			 files_struct *srcfsp,
			 const struct smb_filename *smb_fname_src,
			 files_struct *dstfsp,
			 const struct smb_filename *smb_fname_dst)
{
	SMB_ASSERT(VALID_STAT(srcfsp->fsp_name->st));
	SMB_ASSERT(VALID_STAT(dstfsp->fsp_name->st));

	if (((srcfsp->fsp_name->st.st_ex_dev) == (dstfsp->fsp_name->st.st_ex_dev)) &&
	    ((srcfsp->fsp_name->st.st_ex_ino) == (dstfsp->fsp_name->st.st_ex_ino))) {
		return false;
	}

	return true;
}

static int handle_file(vfs_handle_struct *handle,
		       FTS *ftsp,  files_struct *dirfsp,
		       FTSENT *entry)
{
	struct smb_filename *tmp_fname = NULL;
	files_struct *parent = NULL, *target = NULL;
	int error;
	NTSTATUS status;
	struct stat st;

	DBG_INFO("%s: processing fts entry\n", entry->fts_path);

	if (entry->fts_level != FTS_ROOTLEVEL) {
		status = generate_synthetic_fsp(handle, dirfsp, entry->fts_parent, &parent);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("%s: failed to open parent: %s\n", entry->fts_path, strerror(errno));
			return -1;
		}
	} else {
		parent = dirfsp;
	}

	status = generate_synthetic_fsp(handle, dirfsp, entry, &target);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("%s: failed to open target: %s\n", entry->fts_path, strerror(errno));
		fd_close(parent);
		file_free(NULL, parent);
		return -1;
	}


	status = set_inherited_acl(handle, parent, target);

	if (entry->fts_level != FTS_ROOTLEVEL) {
		fd_close(parent);
		file_free(NULL, parent);
	}

	fd_close(target);
	file_free(NULL, target);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("%s: set_inherited_acl() failed: %s\n", entry->fts_path, nt_errstr(status));
		return -1;
	}

	return 0;
}

static int do_fts_walk(vfs_handle_struct *handle,
		       files_struct *dstfsp,
		       const struct smb_filename *dst)
{
	FTS *ftsp = NULL;
	FTSENT *entry = NULL;
	struct smb_filename *smb_fname = NULL;
	char *paths[2] = { NULL, NULL};
	int error = 0;

	smb_fname = full_path_from_dirfsp_atname(talloc_tos(),
						 dstfsp,
						 dst);
	if (smb_fname == NULL) {
		DBG_ERR("%s: full_path_from_dirfsp_atname() failed: %s\n",
			smb_fname_str_dbg(dst), strerror(errno));
		return -1;
	}

	paths[0] = smb_fname->base_name;

	ftsp = fts_open(paths, (FTS_PHYSICAL | FTS_NOCHDIR), NULL);
	if (ftsp == NULL) {
		DBG_ERR("%s: fts_open() failed: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
		TALLOC_FREE(smb_fname);
		return -1;
	}

	DBG_INFO("%s: fts_open() succeeded\n", smb_fname_str_dbg(smb_fname));
	while ((entry = fts_read(ftsp)) != NULL) {
		switch(entry->fts_info) {
		case FTS_D:
		case FTS_F:
			error += handle_file(handle, ftsp, dstfsp, entry);
			break;
		case FTS_ERR:
			DBG_ERR("fts_read() [%s]: %s\n",
				entry->fts_path, strerror(entry->fts_errno));
			error += entry->fts_errno;
			break;
		}
	}

	fts_close(ftsp);
	TALLOC_FREE(smb_fname);
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
	struct stat st;
	files_struct *tmp_fsp = NULL;

	DBG_INFO("renaming %s %s -> %s %s\n",
		 fsp_str_dbg(srcfsp), smb_fname_str_dbg(src),
		 fsp_str_dbg(dstfsp), smb_fname_str_dbg(dst));

	error = SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, src, dstfsp, dst);
	if (error) {
		DBG_ERR("winmsa_rename: rename failed: %s\n",
			 strerror(errno));
		return error;
	}

	if (!VALID_STAT(src->st)) {
		error = SMB_VFS_STAT(handle->conn, src);
		if (error) {
			DBG_ERR("%s: stat() failed: %s\n",
				smb_fname_str_dbg(src), strerror(errno));
			return error;
		}
	}

	/*
	 * Errors in this section of code are treated as non-fatal
	 * This is because the rename operation succeeded, but we
	 * failed to force permissions iheritance. Faliure in this
	 * case means that ACL is preserved from source.
	 */

	do_inherit = must_inherit(handle, srcfsp, src, dstfsp, dst);
	if (!do_inherit) {
		DBG_INFO("%s: skipping ACL inherit due to source "
			 "and destination being on same path\n",
			 smb_fname_str_dbg(dst));
		return 0;
	}

	if (S_ISDIR(src->st.st_ex_mode)) {
		error = do_fts_walk(handle, dstfsp, dst);
		if (error) {
			DBG_ERR("%s, %s: fts_walk() failed: %s\n",
				fsp_str_dbg(dstfsp), smb_fname_str_dbg(dst), strerror(errno));
			return 0;
		}
	} else {
		files_struct *tmp_fsp = NULL;
		struct stat st = {
			.st_uid = src->st.st_ex_uid,
			.st_gid = src->st.st_ex_gid,
			.st_mode = src->st.st_ex_mode,
			.st_nlink = src->st.st_ex_nlink,
			.st_ino = src->st.st_ex_ino,
			.st_dev = src->st.st_ex_dev,
			.st_size = src->st.st_ex_size,
		};

		FTSENT fake = (FTSENT){
			.fts_path = dst->base_name,
			.fts_pathlen = strlen(dst->base_name),
			.fts_statp = &st,
		};


		status = generate_synthetic_fsp(handle, dstfsp, &fake, &tmp_fsp);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("%s: failed to create temporary open: %s\n",
				fake.fts_path, nt_errstr(status));
			return 0;
		}

		status = set_inherited_acl(handle, dstfsp, tmp_fsp);
		fd_close(tmp_fsp);
		file_free(NULL, tmp_fsp);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("%s: set_inherited_acl() failed: %s\n",
				fake.fts_path, nt_errstr(status));
			return 0;
		}
	}

	return 0;
}

static struct vfs_fn_pointers winmsa_fns = {
	.renameat_fn = winmsa_renameat,
};

NTSTATUS vfs_winmsa_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, MODNAME,
				  &winmsa_fns);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	vfs_winmsa_debug_level = debug_add_class("winmsa");
	if (vfs_winmsa_debug_level == -1) {
		vfs_winmsa_debug_level = DBGC_VFS;
		DBG_INFO("%s: Couldn't register custom debugging class!\n",
			"vfs_winmsa_init");
	} else {
		DBG_DEBUG("%s: Debug class number of '%s': %d\n",
		"vfs_winmsa_init","winmsa",vfs_winmsa_debug_level);
	}

	return status;
}
