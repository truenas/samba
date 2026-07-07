/*
 * Recycle bin VFS module for Samba.
 *
 * Copyright (C) 2001, Brandon Stone, Amherst College, <bbstone@amherst.edu>.
 * Copyright (C) 2002, Jeremy Allison - modified to make a VFS module.
 * Copyright (C) 2002, Alexander Bokovoy - cascaded VFS adoption,
 * Copyright (C) 2002, Juergen Hasch - added some options.
 * Copyright (C) 2002, Simo Sorce
 * Copyright (C) 2002, Stefan (metze) Metzmacher
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "libcli/security/security.h"
#include "system/filesys.h"
#include "auth.h"
#include "source3/lib/substitute.h"

#define ALLOC_CHECK(ptr, label) do { if ((ptr) == NULL) { DBG_ERR("recycle.bin: out of memory!\n"); errno = ENOMEM; goto label; } } while(0)

static int vfs_truenas_recycle_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_truenas_recycle_debug_level

/*
 * A file on a nested child dataset is on a different mount than the share root,
 * so a single bin there would EXDEV on rename. We put the per-user bin on the
 * file's own mount and cache the mountpoint (relative to the share root) keyed
 * by the file's unique mount id.
 */
struct recycle_mount {
	uint64_t mnt_id;
	const char *root;	/* mountpoint relative to share root; "" = share root */
};

struct recycle_config_data {
	const char *repository;
	bool keeptree;
	bool versions;
	bool touch;
	mode_t subdir_mode;
	struct recycle_mount *mounts;
	size_t num_mounts;
};

static int vfs_truenas_recycle_connect(struct vfs_handle_struct *handle,
			       const char *service,
			       const char *user)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct recycle_config_data *config = NULL;
	int ret;
	int t;
	const char *buff = NULL;
	char *repository = NULL;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	if (IS_IPC(handle->conn) || IS_PRINT(handle->conn)) {
		return 0;
	}

	config = talloc_zero(handle->conn, struct recycle_config_data);
	if (config == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}
	buff = lp_parm_const_string(SNUM(handle->conn),
				    "recycle",
				    "repository",
				    ".recycle");
	repository = talloc_sub_full(
		config,
		lp_servicename(talloc_tos(), lp_sub, SNUM(handle->conn)),
		handle->conn->session_info->unix_info->unix_name,
		handle->conn->connectpath,
		handle->conn->session_info->unix_token->gid,
		handle->conn->session_info->unix_info->sanitized_username,
		handle->conn->session_info->info->domain_name,
		buff);
	if (repository == NULL) {
		DBG_ERR("talloc_sub_full() failed\n");
		TALLOC_FREE(config);
		errno = ENOMEM;
		return -1;
	}
	/* shouldn't we allow absolute path names here? --metze */
	/* Yes :-). JRA. */
	trim_char(repository, '\0', '/');
	config->repository = repository;

	config->keeptree = lp_parm_bool(SNUM(handle->conn),
					"recycle",
					"keeptree",
					False);
	config->versions = lp_parm_bool(SNUM(handle->conn),
					"recycle",
					"versions",
					False);
	config->touch = lp_parm_bool(SNUM(handle->conn),
				     "recycle",
				     "touch",
				     False);

	buff = lp_parm_const_string(SNUM(handle->conn),
				    "recycle",
				    "subdir_mode",
				    NULL);
	if (buff != NULL ) {
		sscanf(buff, "%o", &t);
	} else {
		t = S_IRUSR | S_IWUSR | S_IXUSR;
	}
	config->subdir_mode = (mode_t)t;

	SMB_VFS_HANDLE_SET_DATA(
		handle, config, NULL, struct recycle_config_data, return -1);
	return 0;
}

static bool recycle_directory_exist(vfs_handle_struct *handle, const char *dname)
{
	struct smb_filename smb_fname = {
			.base_name = discard_const_p(char, dname)
	};

	if (SMB_VFS_STAT(handle->conn, &smb_fname) == 0) {
		if (S_ISDIR(smb_fname.st.st_ex_mode)) {
			return True;
		}
	}

	return False;
}

/**
 * True iff dname exists, is a directory, and is owned by uid.
 *
 * Used to decide whether an existing per-user bin may be reused. A legitimately
 * provisioned bin is chowned to the connecting user; a bin that exists but is
 * owned by anyone else is treated as untrusted (e.g. planted) and re-provisioned,
 * which re-secures it under root. Defence in depth behind the read-only parents.
 */
static bool recycle_bin_is_users(vfs_handle_struct *handle,
				 const char *dname, uid_t uid)
{
	struct smb_filename smb_fname = {
			.base_name = discard_const_p(char, dname)
	};

	if (SMB_VFS_STAT(handle->conn, &smb_fname) != 0) {
		return false;
	}
	if (!S_ISDIR(smb_fname.st.st_ex_mode)) {
		return false;
	}

	return smb_fname.st.st_ex_uid == uid;
}

static bool recycle_file_exist(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname)
{
	struct smb_filename *smb_fname_tmp = NULL;
	bool ret = false;

	smb_fname_tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		return false;
	}

	if (SMB_VFS_STAT(handle->conn, smb_fname_tmp) == 0) {
		if (S_ISREG(smb_fname_tmp->st.st_ex_mode)) {
			ret = true;
		}
	}

	TALLOC_FREE(smb_fname_tmp);
	return ret;
}

/**
 * Create directory tree
 * @param conn connection
 * @param dname Directory tree to be created
 * @param directory mode
 * @param subdirectory mode
 * @return Returns True for success
 **/
static bool recycle_create_dir(vfs_handle_struct *handle,
			       const char *dname,
			       mode_t dir_mode,
			       mode_t subdir_mode)
{
	size_t len;
	mode_t mode = dir_mode;
	char *new_dir = NULL;
	char *tmp_str = NULL;
	char *token;
	char *tok_str;
	bool ret = False;
	char *saveptr;

	tmp_str = SMB_STRDUP(dname);
	ALLOC_CHECK(tmp_str, done);
	tok_str = tmp_str;

	len = strlen(dname)+1;
	new_dir = (char *)SMB_MALLOC(len + 1);
	ALLOC_CHECK(new_dir, done);
	*new_dir = '\0';
	if (dname[0] == '/') {
		/* Absolute path. */
		if (strlcat(new_dir,"/",len+1) >= len+1) {
			goto done;
		}
	}

	/* Create directory tree if necessary */
	for(token = strtok_r(tok_str, "/", &saveptr); token;
	    token = strtok_r(NULL, "/", &saveptr)) {
		if (strlcat(new_dir, token, len+1) >= len+1) {
			goto done;
		}
		if (recycle_directory_exist(handle, new_dir))
			DBG_DEBUG("recycle: dir %s already exists\n", new_dir);
		else {
			struct smb_filename *smb_fname = NULL;
			int retval;

			DBG_INFO("recycle: creating new dir %s\n", new_dir);

			smb_fname = cp_smb_basename(talloc_tos(), new_dir);
			if (smb_fname == NULL) {
				goto done;
			}

			retval = SMB_VFS_NEXT_MKDIRAT(handle,
					handle->conn->cwd_fsp,
					smb_fname,
					mode);
			if (retval != 0) {
				DBG_WARNING("recycle: mkdirat failed "
					"for %s with error: %s\n",
					new_dir,
					strerror(errno));
				TALLOC_FREE(smb_fname);
				ret = False;
				goto done;
			}
			TALLOC_FREE(smb_fname);
		}
		if (strlcat(new_dir, "/", len+1) >= len+1) {
			goto done;
		}
		mode = subdir_mode;
	}

	ret = True;
done:
	SAFE_FREE(tmp_str);
	SAFE_FREE(new_dir);
	return ret;
}

/**
 * Touch access or modify date
 **/
static void recycle_do_touch(vfs_handle_struct *handle,
			     const struct smb_filename *smb_fname)
{
	struct smb_filename *smb_fname_tmp = NULL;
	struct smb_file_time ft;
	int ret, err;
	NTSTATUS status;

	init_smb_file_time(&ft);

	status = synthetic_pathref(talloc_tos(),
				   handle->conn->cwd_fsp,
				   smb_fname->base_name,
				   smb_fname->stream_name,
				   NULL,
				   smb_fname->twrp,
				   smb_fname->flags,
				   &smb_fname_tmp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("synthetic_pathref for '%s' failed: %s\n",
			  smb_fname_str_dbg(smb_fname), nt_errstr(status));
		return;
	}

	/* atime */
	ft.atime = timespec_current();
	/* preserve mtime */
	ft.mtime = smb_fname_tmp->st.st_ex_mtime;

	become_root();
	ret = SMB_VFS_NEXT_FNTIMES(handle, smb_fname_tmp->fsp, &ft);
	err = errno;
	unbecome_root();
	if (ret == -1 ) {
		DBG_ERR("recycle: touching %s failed, reason = %s\n",
		        smb_fname_str_dbg(smb_fname_tmp), strerror(err));
	}

	TALLOC_FREE(smb_fname_tmp);
}

/**
 * DACL for a per-user recycle bin: the connecting user and the local
 * Administrators group each get full control, inheritable onto new files and
 * subdirectories (SEC_ACE_FLAG_OBJECT_INHERIT|CONTAINER_INHERIT). Inheritance
 * is what lets recycle:keeptree subdirectories, and the files renamed in,
 * carry the same access, so the owner can rename doomed files into the subtree.
 */
static void recycle_bin_aces(const struct dom_sid *user_sid,
			     struct security_ace aces[2])
{
	uint8_t inherit = SEC_ACE_FLAG_OBJECT_INHERIT |
			  SEC_ACE_FLAG_CONTAINER_INHERIT;

	init_sec_ace(&aces[0], user_sid, SEC_ACE_TYPE_ACCESS_ALLOWED,
		     SEC_RIGHTS_DIR_ALL, inherit);
	init_sec_ace(&aces[1], &global_sid_Builtin_Administrators,
		     SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_RIGHTS_DIR_ALL, inherit);
}

/**
 * Open a recycle bin directory (named relative to the share root) for a
 * privileged metadata operation. The caller owns the returned fsp and must
 * fd_close() + file_free() it.
 *
 * Resolved relative to the share root (cwd_fsp) with openat2's
 * RESOLVE_NO_SYMLINKS, so a swapped path component cannot redirect the caller's
 * chown/ACL set onto another target. A real fd (not O_PATH) is returned, as the
 * POSIX sys_acl_set_fd() path requires.
 */
static NTSTATUS recycle_open_bin_dir(vfs_handle_struct *handle,
				     const char *dname,
				     struct files_struct **fsp_out)
{
	connection_struct *conn = handle->conn;
	struct smb_filename *smb_fname = NULL;
	struct files_struct *fsp = NULL;
	struct vfs_open_how how = {
		.flags = O_RDONLY | O_DIRECTORY,
		.resolve = VFS_OPEN_HOW_RESOLVE_NO_SYMLINKS,
	};
	int fd;
	NTSTATUS status;

	smb_fname = synthetic_smb_fname(talloc_tos(), dname, NULL, NULL, 0, 0);
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = create_internal_fsp(conn, smb_fname, &fsp);
	TALLOC_FREE(smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("recycle: create_internal_fsp('%s') failed: %s\n",
			dname, nt_errstr(status));
		return status;
	}
	fsp->fsp_flags.is_directory = true;

	fd = SMB_VFS_NEXT_OPENAT(handle, conn->cwd_fsp, fsp->fsp_name, fsp, &how);
	if (fd == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_ERR("recycle: openat('%s') failed: %s\n",
			dname, strerror(errno));
		file_free(NULL, fsp);
		return status;
	}
	fsp_set_fd(fsp, fd);

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("recycle: stat of '%s' failed: %s\n",
			dname, nt_errstr(status));
		fd_close(fsp);
		file_free(NULL, fsp);
		return status;
	}

	*fsp_out = fsp;
	return NT_STATUS_OK;
}

/**
 * Give the per-user bin its explicit owner + Administrators DACL and owner.
 *
 * We set an NT ACL through the VFS stack rather than issuing a chmod(): on an
 * NFSv4/ZFS dataset with aclmode=restricted a chmod that would rewrite the
 * inherited ACL is rejected with EPERM, whereas an ACL set is honoured. On a
 * POSIX-ACL share the lower ACL module maps the descriptor to POSIX (default)
 * ACLs. This runs under become_root() (see recycle_provision_bin()), so the set
 * always holds CAP_FOWNER and does not depend on the caller's WRITE_ACL.
 */
static NTSTATUS recycle_set_dir_acl(vfs_handle_struct *handle,
				    const char *dname,
				    const struct security_ace *aces,
				    size_t num_aces,
				    uid_t uid,
				    gid_t gid)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct files_struct *fsp = NULL;
	struct security_acl *dacl = NULL;
	struct security_descriptor *psd = NULL;
	size_t sd_size = 0;
	NTSTATUS status;

	status = recycle_open_bin_dir(handle, dname, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/*
	 * Give the per-user bin to its owner. Best-effort: access is granted by
	 * the DACL below, not by ownership, so a chown failure is not fatal.
	 */
	if (uid != (uid_t)-1) {
		if (SMB_VFS_FCHOWN(fsp, uid, gid) != 0) {
			DBG_NOTICE("recycle: fchown('%s', %u, %u) failed: %s\n",
				   dname, (unsigned)uid, (unsigned)gid,
				   strerror(errno));
		}
	}

	dacl = make_sec_acl(frame, SECURITY_ACL_REVISION_ADS, num_aces, aces);
	if (dacl == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	psd = make_sec_desc(frame, SD_REVISION,
			    SEC_DESC_SELF_RELATIVE | SEC_DESC_DACL_PRESENT,
			    NULL, NULL, NULL, dacl, &sd_size);
	if (psd == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = SMB_VFS_FSET_NT_ACL(fsp, SECINFO_DACL, psd);

out:
	if (fsp != NULL) {
		fd_close(fsp);
		file_free(NULL, fsp);
	}
	TALLOC_FREE(frame);
	return status;
}

/*
 * A shared parent is read + traverse only; the per-user bins beneath it are
 * created by root, so no user ever needs to write it. Anything wider is a
 * needless privilege -- and if writable it lets one user plant another's bin,
 * a swap that captures the victim's deleted files. RECYCLE_PARENT_MODE is the
 * create mode (r-x for all, no write); RECYCLE_PARENT_ALLOW_MASK caps every
 * inherited ACE to the same read+traverse.
 */
#define RECYCLE_PARENT_MODE \
	(S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define RECYCLE_PARENT_ALLOW_MASK (SEC_RIGHTS_DIR_READ | SEC_DIR_TRAVERSE)

/**
 * Lock a shared parent down to read + traverse, owned by root.
 *
 * The filesystem inherits the share root's ACEs onto the parent at create, so a
 * permissive share (e.g. everyone@:modify) would leave the parent user-writable.
 * Mask every inherited ALLOW ACE down to read+traverse, and force root ownership
 * so a user who managed to pre-create the parent cannot remain its owner (and
 * thus keep the implicit WRITE_ACL that would let them re-open it). DENY ACEs
 * are left untouched -- they only further restrict.
 */
static NTSTATUS recycle_secure_parent(struct files_struct *fsp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct security_descriptor *sd = NULL;
	NTSTATUS status;
	uint32_t i;

	if (SMB_VFS_FCHOWN(fsp, 0, 0) != 0) {
		DBG_NOTICE("recycle: chown-root of '%s' failed: %s\n",
			   fsp_str_dbg(fsp), strerror(errno));
	}

	status = SMB_VFS_FGET_NT_ACL(fsp, SECINFO_DACL, frame, &sd);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	if (sd->dacl == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	for (i = 0; i < sd->dacl->num_aces; i++) {
		struct security_ace *ace = &sd->dacl->aces[i];

		if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED) {
			ace->access_mask &= RECYCLE_PARENT_ALLOW_MASK;
		}
	}

	status = SMB_VFS_FSET_NT_ACL(fsp, SECINFO_DACL, sd);
	TALLOC_FREE(frame);
	return status;
}

/**
 * Lock the shared-parent chain down to read + traverse, owned by root.
 *
 * The filesystem already inherited the share root's ACL onto each parent at
 * mkdir time (ZFS aclinherit / POSIX default ACLs), so the bin tree is reachable
 * by exactly the users the share grants -- no hardcoded/everyone@ grant needed.
 * Here we only secure it: recycle_secure_parent() strips write from every
 * inherited ALLOW ACE and forces root ownership, so no user can plant another's
 * bin. Each level (".recycle", then ".recycle/DOMAIN" for the AD
 * "recycle:repository = .recycle/%D/%U" layout) is handled. With nothing
 * inheritable on the share root, the read-only create mode is what gets locked.
 */
static NTSTATUS recycle_secure_parents(vfs_handle_struct *handle,
				       const char *base,
				       const char *parent_path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *accum = NULL;
	char *copy = NULL;
	char *tok = NULL;
	char *saveptr = NULL;
	NTSTATUS status = NT_STATUS_OK;

	copy = talloc_strdup(frame, parent_path);
	if (copy == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	for (tok = strtok_r(copy, "/", &saveptr);
	     tok != NULL;
	     tok = strtok_r(NULL, "/", &saveptr)) {
		struct files_struct *fsp = NULL;
		char *path = NULL;

		accum = (accum == NULL) ?
			talloc_strdup(frame, tok) :
			talloc_asprintf(frame, "%s/%s", accum, tok);
		if (accum == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		/*
		 * The infra parents live under base (the mount root); base
		 * itself is the dataset mountpoint -- existing data -- and must
		 * never be chowned/relocked here.
		 */
		path = (base[0] != '\0') ?
			talloc_asprintf(frame, "%s/%s", base, accum) : accum;
		if (path == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		status = recycle_open_bin_dir(handle, path, &fsp);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = recycle_secure_parent(fsp);
		fd_close(fsp);
		file_free(NULL, fsp);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	TALLOC_FREE(frame);
	return status;
}

/**
 * Create and lock down the per-user recycle bin the first time it is needed.
 *
 * The bin lives under "base", the mountpoint of the dataset the deleted file is
 * on (relative to the share root; "" for the share root itself), so the rename
 * into it stays on one mount. base is existing data and is never touched: we
 * create/lock only the ".recycle[/%D]/%U" tree beneath it.
 *
 * This runs under become_root(): the shared parent(s) may be unreachable for an
 * unprivileged user. We create the shared parent chain read-only, then the
 * per-user leaf; each shared parent keeps the ACL the filesystem inherited onto
 * it, stripped to read/traverse; and the leaf gets an owner + Administrators
 * full-control (inheriting) DACL owned by the connecting user. The AD layout
 * ".recycle/%D/%U" has two shared parents; both are handled.
 *
 * Any failure -- create, parent lockdown, or leaf ACL -- is fatal so the caller
 * purges the file rather than leave it in an unsecured bin.
 */
static NTSTATUS recycle_provision_bin(vfs_handle_struct *handle,
				      struct recycle_config_data *config,
				      const char *base)
{
	TALLOC_CTX *frame = talloc_stackframe();
	connection_struct *conn = handle->conn;
	struct security_token *token = conn->session_info->security_token;
	const struct dom_sid *user_sid = &token->sids[PRIMARY_USER_SID_INDEX];
	struct security_ace bin_aces[2];
	char *leaf = NULL;
	char *parent = NULL;
	char *full_parent = NULL;
	bool has_parent;
	NTSTATUS status;
	/*
	 * The shared parents are created read + traverse for all, never
	 * user-writable: the per-user bins beneath them are made by root, and
	 * users only traverse the parents to reach their own bin. This mode is
	 * what stands when the share root has no ACL to inherit; otherwise the
	 * filesystem-inherited ACL (secured by recycle_secure_parents()) governs.
	 */
	const mode_t parent_mode = RECYCLE_PARENT_MODE;

	recycle_bin_aces(user_sid, bin_aces);

	become_root();

	leaf = (base[0] != '\0') ?
		talloc_asprintf(frame, "%s/%s", base, config->repository) :
		talloc_strdup(frame, config->repository);
	if (leaf == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	has_parent = parent_dirname(frame, config->repository, &parent, NULL) &&
		     !ISDOT(parent);
	if (has_parent) {
		full_parent = (base[0] != '\0') ?
			talloc_asprintf(frame, "%s/%s", base, parent) : parent;
		if (full_parent == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	/*
	 * Create the shared parent chain read-only, then the per-user leaf with
	 * its own owner-writable mode (the parents already exist by then).
	 */
	if (has_parent &&
	    !recycle_create_dir(handle, full_parent, parent_mode, parent_mode)) {
		status = map_nt_error_from_unix(errno);
		DBG_ERR("recycle: could not create bin parent '%s': %s\n",
			full_parent, strerror(errno));
		goto out;
	}

	if (!recycle_create_dir(handle, leaf,
				config->subdir_mode, config->subdir_mode)) {
		status = map_nt_error_from_unix(errno);
		DBG_ERR("recycle: could not create bin '%s': %s\n",
			leaf, strerror(errno));
		goto out;
	}
	status = NT_STATUS_OK;

	if (has_parent) {
		status = recycle_secure_parents(handle, base, parent);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("recycle: failed to secure bin parent '%s': "
				"%s\n", full_parent, nt_errstr(status));
			goto out;
		}
	}

	status = recycle_set_dir_acl(handle, leaf,
				     bin_aces, 2,
				     conn->session_info->unix_token->uid,
				     conn->session_info->unix_token->gid);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("recycle: failed to set ACL on bin '%s': %s\n",
			leaf, nt_errstr(status));
		goto out;
	}

out:
	unbecome_root();
	TALLOC_FREE(frame);
	return status;
}

/*
 * Mount id of a directory named relative to the share root, or 0 if it cannot
 * be stat'd. Every stat fills st_ex_mnt_id (statx STATX_MNT_ID_UNIQUE).
 */
static uint64_t recycle_path_mnt_id(vfs_handle_struct *handle,
				    const char *relpath)
{
	struct smb_filename smb_fname = {
		.base_name = discard_const_p(char, relpath),
	};

	if (SMB_VFS_STAT(handle->conn, &smb_fname) != 0) {
		return 0;
	}
	return smb_fname.st.st_ex_mnt_id;
}

/*
 * Resolve, relative to the share root, the mountpoint of the dataset a file
 * lives on -- "" for the share's own mount, or e.g. "child" for a nested child
 * dataset. The file is on mount mnt_id, in directory path_name. We compare
 * mount ids up the path rather than mapping the id to a path (the unique mount
 * id is not in /proc/self/mountinfo). Cached per connection, keyed by mnt_id.
 */
static const char *recycle_mount_root(vfs_handle_struct *handle,
				      struct recycle_config_data *config,
				      const char *path_name,
				      uint64_t mnt_id)
{
	TALLOC_CTX *frame = NULL;
	const char *found = NULL;
	const char *result = NULL;
	char *accum = NULL, *copy = NULL, *tok = NULL, *saveptr = NULL;
	struct recycle_mount *tmp = NULL;
	size_t i;

	for (i = 0; i < config->num_mounts; i++) {
		if (config->mounts[i].mnt_id == mnt_id) {
			return config->mounts[i].root;
		}
	}

	frame = talloc_stackframe();

	if (recycle_path_mnt_id(handle, ".") == mnt_id) {
		found = "";
	} else {
		/*
		 * Walk the file's directory components from the share root
		 * down; the shallowest prefix on the file's mount is its
		 * dataset mountpoint.
		 */
		copy = talloc_strdup(frame, path_name);
		if (copy == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
		for (tok = strtok_r(copy, "/", &saveptr);
		     tok != NULL;
		     tok = strtok_r(NULL, "/", &saveptr)) {
			accum = (accum == NULL) ?
				talloc_strdup(frame, tok) :
				talloc_asprintf(frame, "%s/%s", accum, tok);
			if (accum == NULL) {
				TALLOC_FREE(frame);
				return NULL;
			}
			if (recycle_path_mnt_id(handle, accum) == mnt_id) {
				found = accum;
				break;
			}
		}
	}

	if (found == NULL) {
		/* The file's own directory is on its mount, so this is a bug. */
		DBG_WARNING("recycle: no mountpoint for mnt_id %"PRIu64
			    " under '%s'\n", mnt_id, path_name);
		TALLOC_FREE(frame);
		return NULL;
	}

	/* Copy onto config so it survives the frame, then cache it. */
	result = (found[0] == '\0') ? "" : talloc_strdup(config, found);
	TALLOC_FREE(frame);
	if (result == NULL) {
		return NULL;
	}

	tmp = talloc_realloc(config, config->mounts, struct recycle_mount,
			     config->num_mounts + 1);
	if (tmp != NULL) {
		config->mounts = tmp;
		config->mounts[config->num_mounts].mnt_id = mnt_id;
		config->mounts[config->num_mounts].root = result;
		config->num_mounts++;
	}
	return result;
}

/**
 * Check if file should be recycled
 **/
static int recycle_unlink_internal(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				int flags)
{
	TALLOC_CTX *frame = NULL;
	struct smb_filename *full_fname = NULL;
	char *path_name = NULL;
	const char *temp_name = NULL;
	const char *final_name = NULL;
	const char *repository = NULL;
	const char *mroot = NULL;
	const char *keep_path = NULL;
	struct smb_filename *smb_fname_final = NULL;
	const char *base = NULL;
	uint64_t mnt_id;
	int i;
	bool exist;
	int rc = -1;
	struct recycle_config_data *config = NULL;
	struct vfs_rename_how rhow = { .flags = 0, };
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct recycle_config_data,
				return -1);

	frame = talloc_stackframe();

	if (config->repository[0] == '\0') {
		DBG_INFO("recycle: repository path not set, purging %s...\n",
		         smb_fname_str_dbg(smb_fname));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	full_fname = full_path_from_dirfsp_atname(frame,
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		rc = -1;
		errno = ENOMEM;
		goto done;
	}

	/* extract filename and path */
	if (!parent_dirname(frame, full_fname->base_name, &path_name, &base)) {
		rc = -1;
		errno = ENOMEM;
		goto done;
	}

	/* original filename with path */
	DBG_DEBUG("recycle: fname = %s\n", smb_fname_str_dbg(full_fname));
	/* original path */
	DBG_DEBUG("recycle: fpath = %s\n", path_name);
	/* filename without path */
	DBG_DEBUG("recycle: base = %s\n", base);

	/*
	 * Put the bin on the same mount (dataset) as the file, so the rename
	 * into it stays on-device instead of EXDEV-purging a file on a nested
	 * child dataset. We identify the mount by the file's unique mount id;
	 * on a supported kernel it is never zero.
	 */
	if (VALID_STAT(smb_fname->st)) {
		mnt_id = smb_fname->st.st_ex_mnt_id;
	} else {
		struct smb_filename *tmp = cp_smb_filename(frame, smb_fname);
		if (tmp == NULL) {
			rc = -1;
			errno = ENOMEM;
			goto done;
		}
		if (SMB_VFS_STAT(handle->conn, tmp) != 0) {
			/* vanished/inaccessible; let the real unlink report it */
			rc = SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname,
						  flags);
			goto done;
		}
		mnt_id = tmp->st.st_ex_mnt_id;
	}
	SMB_ASSERT(mnt_id != 0);

	mroot = recycle_mount_root(handle, config, path_name, mnt_id);
	if (mroot == NULL) {
		/* Resolution failed; fall back to the share root. */
		mroot = "";
	}
	if (mroot[0] != '\0') {
		repository = talloc_asprintf(frame, "%s/%s", mroot,
					     config->repository);
		if (repository == NULL) {
			rc = -1;
			errno = ENOMEM;
			goto done;
		}
		/* keeptree mirrors the path within the mount root */
		if (strcmp(path_name, mroot) == 0) {
			keep_path = ".";
		} else {
			keep_path = path_name + strlen(mroot) + 1;
		}
	} else {
		repository = config->repository;
		keep_path = path_name;
	}

	/* we don't recycle the recycle bin... */
	if (strncmp(full_fname->base_name, repository,
		    strlen(repository)) == 0) {
		DBG_INFO("recycle: File is within recycling bin, unlinking ...\n");
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	if (config->keeptree && !ISDOT(keep_path)) {
		temp_name = talloc_asprintf(frame, "%s/%s",
					    repository,
					    keep_path);
		if (temp_name == NULL) {
			rc = -1;
			goto done;
		}
	} else {
		temp_name = repository;
	}

	/*
	 * Provision the per-user recycle bin (and its shared parent) with the
	 * correct ACLs, under privilege, the first time it is needed. Done
	 * before any keeptree subdirectories are created so those inherit the
	 * bin ACL.
	 */
	if (!recycle_bin_is_users(handle, repository,
				  handle->conn->session_info->unix_token->uid)) {
		status = recycle_provision_bin(handle, config, mroot);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_INFO("recycle: could not provision bin '%s' (%s), "
			         "purging %s...\n",
			         repository, nt_errstr(status),
			         smb_fname_str_dbg(full_fname));
			rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
			goto done;
		}
	}

	exist = recycle_directory_exist(handle, temp_name);
	if (exist) {
		DBG_DEBUG("recycle: Directory already exists\n");
	} else {
		DBG_DEBUG("recycle: Creating directory %s\n", temp_name);
		if (recycle_create_dir(handle,
				       temp_name,
				       config->subdir_mode,
				       config->subdir_mode) == False)
		{
			DBG_INFO("recycle: Could not create directory, "
			         "purging %s...\n",
			         smb_fname_str_dbg(full_fname));
			rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
			goto done;
		}
	}

	final_name = talloc_asprintf(frame, "%s/%s",
				     temp_name, base);
	if (final_name == NULL) {
		rc = -1;
		goto done;
	}

	/* Create smb_fname with final base name and orig stream name. */
	smb_fname_final = synthetic_smb_fname(frame,
					final_name,
					full_fname->stream_name,
					NULL,
					full_fname->twrp,
					full_fname->flags);
	if (smb_fname_final == NULL) {
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	/* new filename with path */
	DBG_DEBUG("recycle: recycled file name: %s\n",
	          smb_fname_str_dbg(smb_fname_final));

	/* check if we should delete file from recycle bin */
	if (recycle_file_exist(handle, smb_fname_final)) {
		if (config->versions == False) {
			DBG_INFO("recycle: Removing old file %s from recycle "
			         "bin\n", smb_fname_str_dbg(smb_fname_final));
			if (SMB_VFS_NEXT_UNLINKAT(handle,
						dirfsp->conn->cwd_fsp,
						smb_fname_final,
						flags) != 0) {
				DBG_WARNING("recycle: Error deleting old file: %s\n", strerror(errno));
			}
		}
	}

	/* rename file we move to recycle bin */
	i = 1;
	while (recycle_file_exist(handle, smb_fname_final)) {
		char *copy = NULL;

		TALLOC_FREE(smb_fname_final->base_name);
		copy = talloc_asprintf(smb_fname_final, "%s/Copy #%d of %s",
				       temp_name, i++, base);
		if (copy == NULL) {
			rc = -1;
			goto done;
		}
		smb_fname_final->base_name = copy;
	}

	DBG_DEBUG("recycle: Moving %s to %s\n", smb_fname_str_dbg(full_fname),
	          smb_fname_str_dbg(smb_fname_final));
	rc = SMB_VFS_NEXT_RENAMEAT(handle,
			dirfsp,
			smb_fname,
			handle->conn->cwd_fsp,
			smb_fname_final,
			&rhow);
	if (rc != 0) {
		DBG_INFO("recycle: Move error %d (%s), purging file %s "
		         "(%s)\n", errno, strerror(errno),
		         smb_fname_str_dbg(full_fname),
		         smb_fname_str_dbg(smb_fname_final));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				smb_fname,
				flags);
		goto done;
	}

	/* touch access date of moved file */
	if (config->touch)
		recycle_do_touch(handle, smb_fname_final);

done:
	TALLOC_FREE(frame);
	return rc;
}

static int recycle_unlinkat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		int flags)
{
	int ret;

	if (flags & AT_REMOVEDIR) {
		ret = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
	} else {
		ret = recycle_unlink_internal(handle,
					dirfsp,
					smb_fname,
					flags);
	}
	return ret;
}

static struct vfs_fn_pointers vfs_truenas_recycle_fns = {
	.connect_fn = vfs_truenas_recycle_connect,
	.unlinkat_fn = recycle_unlinkat,
};

static_decl_vfs;
NTSTATUS vfs_truenas_recycle_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "truenas_recycle",
					&vfs_truenas_recycle_fns);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_truenas_recycle_debug_level = debug_add_class("truenas_recycle");
	if (vfs_truenas_recycle_debug_level == -1) {
		vfs_truenas_recycle_debug_level = DBGC_VFS;
		DBG_ERR("vfs_truenas_recycle: Couldn't register custom debugging class!\n");
	} else {
		DBG_DEBUG("vfs_truenas_recycle: Debug class number of 'truenas_recycle': %d\n", vfs_truenas_recycle_debug_level);
	}

	return ret;
}
