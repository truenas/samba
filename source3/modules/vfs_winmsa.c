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
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "zfsacl.h"
#include <fts.h>

#define MODNAME "winmsa"

static int vfs_winmsa_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_winmsa_debug_level
#define WINMSA_DBGLVL debuglevel_get_class(vfs_winmsa_debug_level)

static void dump_acl_info(zfsacl_t theacl, const char *fn)
{
	char *acltext = NULL;

	if (!CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		return;
	}

	acltext = zfsacl_to_text(theacl);
	if (acltext == NULL) {
		DBG_ERR("zfsacl_to_text() failed: %s\n", strerror(errno));
		return;
	}

	DBG_ERR("%s():\n%s\n", fn, acltext);
	free(acltext);
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

static bool _inherit_acl(int parent_fd,
			 char *victim,
			 ino_t ino,
			 bool isdir,
			 const char *location)
{
	zfsacl_t parent, payload;
	int flags = isdir ? O_DIRECTORY : O_RDWR;
	struct stat st;
	int fd;

	if (parent_fd == AT_FDCWD) {
		parent = zfsacl_get_file(".", ZFSACL_BRAND_NFSV4);
	} else {
		parent = zfsacl_get_fd(parent_fd, ZFSACL_BRAND_NFSV4);
	}

	if (parent == NULL) {
		return false;
	}

	DBG_DEBUG("Printing ACL for parent path\n");
	dump_acl_info(parent, location);

	payload = zfsacl_calculate_inherited_acl(parent, NULL, isdir);
	zfsacl_free(&parent);

	if (payload == NULL) {
		DBG_ERR("zfsacl_calculate_inherited_acl() failed: %s\n",
			strerror(errno));
		return false;
	}

	DBG_DEBUG("Calculated ACL to set on %s\n", victim);
	dump_acl_info(payload, location);

	fd = openat(parent_fd, victim, flags | O_NOFOLLOW);
	if (fd == -1) {
		DBG_ERR("%s: open() failed: %s\n", victim, strerror(errno));
		return false;
	}

	if (fstat(fd, &st)) {
		DBG_ERR("%s: fstat() failed: %s\n", victim, strerror(errno));
		close(fd);
		return false;
	}

	SMB_ASSERT(ino == st.st_ino);

	if (!zfsacl_set_fd(fd, payload)) {
		DBG_INFO("%s: zfsacl_set_fd() failed: %s\n", victim, strerror(errno));
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

#define	inherit_acl(parent_fd, victim, ino, isdir) \
	_inherit_acl(parent_fd, victim, ino, isdir, __location__)

static bool do_fts_walk(vfs_handle_struct *handle,
			files_struct *dstfsp,
			const struct smb_filename *dst)
{
	FTS *ftsp = NULL;
	FTSENT *entry = NULL;
	char *paths[2] = { NULL, NULL};
	bool ok = true;
	struct stat *pst = NULL;
	struct smb_filename *smb_fname = NULL;

	smb_fname = full_path_from_dirfsp_atname(talloc_tos(),
						 dstfsp,
						 dst);
	if (smb_fname == NULL) {
		DBG_ERR("%s: full_path_from_dirfsp_atname() failed: %s\n",
			smb_fname_str_dbg(dst), strerror(errno));
		return -1;
	}

	paths[0] = smb_fname->base_name;
	ftsp = fts_open(paths, (FTS_PHYSICAL), NULL);
	if (ftsp == NULL) {
		DBG_ERR("%s: fts_open() failed: %s\n",
			fsp_str_dbg(dstfsp), strerror(errno));
		TALLOC_FREE(smb_fname);
		return -1;
	}

	while (((entry = fts_read(ftsp)) != NULL) && ok) {
		if (entry->fts_level == FTS_ROOTLEVEL) {
			continue;
		}
		switch(entry->fts_info) {
		case FTS_D:
		case FTS_F:
			pst = entry->fts_statp;
			ok = inherit_acl(AT_FDCWD,
					 entry->fts_accpath,
					 pst->st_ino,
					 S_ISDIR(pst->st_mode));
			break;
		case FTS_ERR:
			DBG_ERR("fts_read() [%s]: %s\n",
				entry->fts_path, strerror(entry->fts_errno));
			ok = false;
			break;
		}
	}

	fts_close(ftsp);
	TALLOC_FREE(smb_fname);
	return ok;
}

static int winmsa_renameat(vfs_handle_struct *handle,
			   files_struct *srcfsp,
			   const struct smb_filename *src,
			   files_struct *dstfsp,
			   const struct smb_filename *dst)
{

	int tmpfd, error;
	bool do_inherit, ok;

	DBG_INFO("renaming %s %s -> %s %s\n",
		 fsp_str_dbg(srcfsp), smb_fname_str_dbg(src),
		 fsp_str_dbg(dstfsp), smb_fname_str_dbg(dst));

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

	tmpfd = openat(fsp_get_pathref_fd(dstfsp), "", O_RDONLY | O_EMPTY_PATH);
	if (tmpfd == -1) {
		DBG_ERR("%s: failed to reopen fd: %s\n",
			fsp_str_dbg(dstfsp), strerror(errno));
		return 0;
	}

	if (!inherit_acl(tmpfd, dst->base_name, src->st.st_ex_ino, S_ISDIR(src->st.st_ex_mode))) {
		DBG_ERR("%s: failed to inherit acl: %s\n", smb_fname_str_dbg(dst), strerror(errno));
	}
	close(tmpfd);

	if (S_ISDIR(src->st.st_ex_mode)) {
		ok = do_fts_walk(handle, dstfsp, dst);
		if (!ok) {
			DBG_INFO("%s, %s: fts_walk() failed: %s\n",
				 fsp_str_dbg(dstfsp), smb_fname_str_dbg(dst), strerror(errno));
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
