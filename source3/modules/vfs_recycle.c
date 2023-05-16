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
#include "system/filesys.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "auth.h"
#include "source3/lib/substitute.h"

#define ALLOC_CHECK(ptr, label) do { if ((ptr) == NULL) { DEBUG(0, ("recycle.bin: out of memory!\n")); errno = ENOMEM; goto label; } } while(0)

static int vfs_recycle_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_recycle_debug_level

#define BIN_INCREMENT 10
#define BIN2FSP(bin)	(bin->mnt_path_ref->fsp)

struct recycle_bin {
	struct smb_filename *mnt_path_ref; // O_PATH open for directory where recycle bin located
	char *recycle_path; // path for recycle bin relative to connectpath
	size_t mp_len;
};
typedef struct recycle_bin recycle_bin;

struct recycle_config_data {
	recycle_bin **bins;
	size_t bin_array_len;
	size_t next_entry;
	bool preserve_acl;
	bool busy;
	char *repository;
	mode_t mode;
};

static bool recycle_create_dir(vfs_handle_struct *handle, const files_struct *dirfsp, const char *dname);

static bool make_new_bin(vfs_handle_struct *handle,
			 struct recycle_config_data *config,
                         const files_struct *dirfsp,
			 const char *mntpath)
{
	int ret;
	NTSTATUS status;
	bool ok, is_connectpath;
	struct smb_filename *smb_fname = NULL;
	char fname[PATH_MAX];
	struct recycle_bin *to_add = NULL;

	if (config->next_entry == config->bin_array_len) {
		struct recycle_bin **tmp = NULL;
		tmp = talloc_realloc(
			config, config->bins, struct recycle_bin *, config->bin_array_len + BIN_INCREMENT
		);
		if (tmp == NULL) {
			return false;
		}
		config->bins = tmp;
		config->bin_array_len += BIN_INCREMENT;
	}

	switch(mntpath[strlen(handle->conn->connectpath)]) {
	case '\0':
		snprintf(fname, sizeof(fname), "%c", '.');
		break;
	case '/':
		snprintf(fname, sizeof(fname), "%s", mntpath + strlen(handle->conn->connectpath) + 1);
		break;
	default:
		smb_panic("Mountpath is incorrect");	
	}

	status = synthetic_pathref(config,
				   dirfsp,
				   fname,
				   NULL,
				   NULL,
				   0,
				   0,
				   &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("%s: synthetic_pathref() failed: %s\n",
			fname, nt_errstr(status));
		return false;
	}

	to_add = talloc_zero(config, struct recycle_bin);
	if (to_add == NULL) {
		errno = ENOMEM;
		DBG_ERR("talloc failure\n");
		TALLOC_FREE(smb_fname);
		return false;
	}

	if (strcmp(handle->conn->connectpath, mntpath) == 0) {
		to_add->mp_len = 0;
		to_add->recycle_path = talloc_strdup(config, config->repository);
	} else {
		to_add->mp_len = strlen(fname) + 1;
		to_add->recycle_path = talloc_asprintf(config, "%s/%s",
						       fname, config->repository);
	}
	to_add->mnt_path_ref = smb_fname;
	config->bins[config->next_entry] = to_add;
	config->next_entry++;

	ok = recycle_create_dir(handle, smb_fname->fsp, config->repository);
	if (!ok) {
		return false;
	}
	return true;
}

#ifdef FREEBSD
static bool get_mountpoint(TALLOC_CTX *mem_ctx,
			   const struct smb_filename *smb_fname,
			   char **fname_out)
{
	struct statfs sfs;
	int err;
	char *mp_fname = NULL;

	if (smb_fname->fsp) {
		err = fstatfs(fsp_get_pathref_fd(smb_fname->fsp), &sfs);
	} else {
		err = statfs(smb_fname->base_name, &sfs);
	}
	if (err) {
		DBG_ERR("%s: statfs() failed: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
		return false;
	}

	mp_fname = talloc_strdup(mem_ctx, sfs.f_mntonname);
	if (mp_fname == NULL) {
		errno = ENOMEM;
		return false;
	}
	*fname_out = mp_fname;
	return true;
}
#else

#define MNT_LINE_MAX 4108
#define BUFLEN (MNT_LINE_MAX + 2)

static bool get_mountpoint(TALLOC_CTX *mem_ctx,
			   const struct smb_filename *smb_fname,
			   char **fname_out)
{
	bool ok = true;
	FILE *fp = NULL;
	char buf[BUFLEN];
	char *found = NULL;
	struct mntent m, *entry = NULL;

	fp = setmntent("/etc/mtab", "re");
	if (fp == NULL) {
		DBG_ERR("Failed to open mnttab: %s\n", strerror(errno));
		return false;
	}

	while ((entry = getmntent_r(fp, &m, buf, BUFLEN))) {
		struct stat st;
		int rv;

		rv = stat(entry->mnt_dir, &st);
		if (rv != 0) {
			continue;
		}

		if (st.st_dev == smb_fname->st.st_ex_dev) {
			found = talloc_strdup(mem_ctx, entry->mnt_dir);
			if (found == NULL) {
				errno = ENOMEM;
				ok = false;
			}
			break;
		}
	}
	endmntent(fp);

	if (entry == NULL) {
		DBG_ERR("getmntent_r() failed:\n");
		return false;
	}

	if (ok && found == NULL) {
		ok = false;
		errno = ENOENT;
	}
	else if (found != NULL) {
		*fname_out = found;
	}

	return ok;
}
#endif

static bool make_bin_from_mount(vfs_handle_struct *handle,
				const files_struct *dirfsp,
				const struct smb_filename *smb_fname_in,
				struct recycle_config_data *config)
{
	char *mp = NULL;
	bool ok;

	ok = get_mountpoint(config, smb_fname_in, &mp);
	if (!ok) {
		DBG_ERR("%s: failed to get mountpoint: %s\n",
			smb_fname_str_dbg(smb_fname_in), strerror(errno));
		return ok;
	}

	ok = make_new_bin(handle, config, dirfsp, mp);
	if (!ok) {
		DBG_ERR("%s: add to pathrefs failed\n", mp);
	}

	TALLOC_FREE(mp);

	return ok;
}

static recycle_bin *get_recycle_bin(vfs_handle_struct *handle,
				    const struct smb_filename *smb_fname)
{
	recycle_bin *out = NULL, *thebin = NULL;
	struct recycle_config_data *config;
	bool ok;
	int i = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct recycle_config_data,
				return NULL);

	for (thebin = config->bins[i]; thebin; thebin = config->bins[i++]) {
		SMB_STRUCT_STAT sbuf = thebin->mnt_path_ref->st;
		if (sbuf.st_ex_dev == smb_fname->st.st_ex_dev) {
			out = thebin;
			break;
		}
	}

	if (out == NULL) {
		size_t new_entry = config->next_entry;
		ok = make_bin_from_mount(handle, BIN2FSP(config->bins[0]), smb_fname, config);
		if (ok) {
			out = config->bins[new_entry];
		}
	}

	return out;
}
 
static const char *recycle_repository(vfs_handle_struct *handle)
{
	const char *tmp_str = NULL;

	tmp_str = lp_parm_const_string(SNUM(handle->conn), "recycle", "repository",".recycle");

	DEBUG(10, ("recycle: repository = %s\n", tmp_str));

	return tmp_str;
}

static bool recycle_keep_dir_tree(vfs_handle_struct *handle)
{
	bool ret;

	ret = lp_parm_bool(SNUM(handle->conn), "recycle", "keeptree", False);

	DEBUG(10, ("recycle_bin: keeptree = %s\n", ret?"True":"False"));

	return ret;
}

static bool recycle_versions(vfs_handle_struct *handle)
{
	bool ret;

	ret = lp_parm_bool(SNUM(handle->conn), "recycle", "versions", False);

	DEBUG(10, ("recycle: versions = %s\n", ret?"True":"False"));

	return ret;
}

static bool recycle_touch(vfs_handle_struct *handle)
{
	bool ret;

	ret = lp_parm_bool(SNUM(handle->conn), "recycle", "touch", False);

	DEBUG(10, ("recycle: touch = %s\n", ret?"True":"False"));

	return ret;
}

static bool recycle_touch_mtime(vfs_handle_struct *handle)
{
	bool ret;

	ret = lp_parm_bool(SNUM(handle->conn), "recycle", "touch_mtime", False);

	DEBUG(10, ("recycle: touch_mtime = %s\n", ret?"True":"False"));

	return ret;
}

static const char **recycle_exclude(vfs_handle_struct *handle)
{
	const char **tmp_lp;

	tmp_lp = lp_parm_string_list(SNUM(handle->conn), "recycle", "exclude", NULL);

	DEBUG(10, ("recycle: exclude = %s ...\n", tmp_lp?*tmp_lp:""));

	return tmp_lp;
}

static const char **recycle_exclude_dir(vfs_handle_struct *handle)
{
	const char **tmp_lp;

	tmp_lp = lp_parm_string_list(SNUM(handle->conn), "recycle", "exclude_dir", NULL);

	DEBUG(10, ("recycle: exclude_dir = %s ...\n", tmp_lp?*tmp_lp:""));

	return tmp_lp;
}

static const char **recycle_noversions(vfs_handle_struct *handle)
{
	const char **tmp_lp;

	tmp_lp = lp_parm_string_list(SNUM(handle->conn), "recycle", "noversions", NULL);

	DEBUG(10, ("recycle: noversions = %s\n", tmp_lp?*tmp_lp:""));

	return tmp_lp;
}

static mode_t recycle_directory_mode(vfs_handle_struct *handle)
{
	int dirmode;
	const char *buff;

	buff = lp_parm_const_string(SNUM(handle->conn), "recycle", "directory_mode", NULL);

	if (buff != NULL ) {
		sscanf(buff, "%o", &dirmode);
	} else {
		dirmode=S_IRUSR | S_IWUSR | S_IXUSR;
	}

	DEBUG(10, ("recycle: directory_mode = %o\n", dirmode));
	return (mode_t)dirmode;
}

static mode_t recycle_subdir_mode(vfs_handle_struct *handle)
{
	int dirmode;
	const char *buff;

	buff = lp_parm_const_string(SNUM(handle->conn), "recycle", "subdir_mode", NULL);

	if (buff != NULL ) {
		sscanf(buff, "%o", &dirmode);
	} else {
		dirmode=recycle_directory_mode(handle);
	}

	DEBUG(10, ("recycle: subdir_mode = %o\n", dirmode));
	return (mode_t)dirmode;
}

static bool recycle_directory_exist(vfs_handle_struct *handle, const files_struct *dirfsp, const char *dname)
{

	int err;
	SMB_STRUCT_STAT st;

	err = sys_fstatat(fsp_get_pathref_fd(dirfsp),
			  dname,
			  &st,
			  AT_SYMLINK_NOFOLLOW,
			  lp_fake_directory_create_times(SNUM(handle->conn)));

	if (err == 0) {
		return S_ISDIR(st.st_ex_mode) ? true : false;
	}

	return false;
}

static bool recycle_file_exist(vfs_handle_struct *handle,
			       const files_struct *dirfsp,
			       const char *fname)
{
	int err;
	SMB_STRUCT_STAT st;

	err = sys_fstatat(fsp_get_pathref_fd(dirfsp),
			  fname,
			  &st,
			  AT_SYMLINK_NOFOLLOW,
			  lp_fake_directory_create_times(SNUM(handle->conn)));

	if (err == 0) {
		return S_ISREG(st.st_ex_mode) ? true : false;
	}

	return false;
}

/**
 * Create directory tree
 * @param conn connection
 * @param dname Directory tree to be created
 * @return Returns True for success
 **/
static bool recycle_create_dir(vfs_handle_struct *handle, const files_struct *dirfsp, const char *dname)
{
	size_t len;
	mode_t mode;
	char *new_dir = NULL;
	char *tmp_str = NULL;
	char *token;
	char *tok_str;
	bool ret = False;
	char *saveptr;

	mode = recycle_directory_mode(handle);

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
		if (recycle_directory_exist(handle, dirfsp, new_dir))
			DEBUG(10, ("recycle: dir %s already exists\n", new_dir));
		else {
			struct smb_filename smb_fname = (struct smb_filename) {
				.base_name = new_dir,
			};
			int retval;

			DEBUG(5, ("recycle: creating new dir %s\n", new_dir));

			retval = SMB_VFS_NEXT_MKDIRAT(handle,
					dirfsp,
					&smb_fname,
					mode);
			if (retval != 0) {
				DBG_WARNING("recycle: mkdirat failed "
					"for %s with error: %s\n",
					new_dir,
					strerror(errno));
				ret = False;
				goto done;
			}
		}
		if (strlcat(new_dir, "/", len+1) >= len+1) {
			goto done;
		}
		mode = recycle_subdir_mode(handle);
	}

	ret = True;
done:
	SAFE_FREE(tmp_str);
	SAFE_FREE(new_dir);
	return ret;
}

/**
 * Check if any of the components of "exclude_list" are contained in path.
 * Return True if found
 **/

static bool matchdirparam(const char **dir_exclude_list, char *path)
{
	char *startp = NULL, *endp = NULL;

	if (dir_exclude_list == NULL || dir_exclude_list[0] == NULL ||
		*dir_exclude_list[0] == '\0' || path == NULL || *path == '\0') {
		return False;
	}

	/* 
	 * Walk the components of path, looking for matches with the
	 * exclude list on each component. 
	 */

	for (startp = path; startp; startp = endp) {
		int i;

		while (*startp == '/') {
			startp++;
		}
		endp = strchr(startp, '/');
		if (endp) {
			*endp = '\0';
		}

		for(i=0; dir_exclude_list[i] ; i++) {
			if(unix_wild_match(dir_exclude_list[i], startp)) {
				/* Repair path. */
				if (endp) {
					*endp = '/';
				}
				return True;
			}
		}

		/* Repair path. */
		if (endp) {
			*endp = '/';
		}
	}

	return False;
}

/**
 * Check if needle is contained in haystack, * and ? patterns are resolved
 * @param haystack list of parameters separated by delimimiter character
 * @param needle string to be matched exectly to haystack including pattern matching
 * @return True if found
 **/
static bool matchparam(const char **haystack_list, const char *needle)
{
	int i;

	if (haystack_list == NULL || haystack_list[0] == NULL ||
		*haystack_list[0] == '\0' || needle == NULL || *needle == '\0') {
		return False;
	}

	for(i=0; haystack_list[i] ; i++) {
		if(unix_wild_match(haystack_list[i], needle)) {
			return True;
		}
	}

	return False;
}

/**
 * Touch access or modify date
 **/
static void recycle_do_touch(vfs_handle_struct *handle,
			     const files_struct *dirfsp,
			     const struct smb_filename *smb_fname,
			     bool touch_mtime)
{
	struct smb_filename *smb_fname_tmp = NULL;
	struct smb_file_time ft;
	int ret, err;
	NTSTATUS status;

	init_smb_file_time(&ft);

	status = synthetic_pathref(talloc_tos(),
				   dirfsp,
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
	/* mtime */
	ft.mtime = touch_mtime ? ft.atime : smb_fname_tmp->st.st_ex_mtime;

	become_root();
	ret = SMB_VFS_NEXT_FNTIMES(handle, smb_fname_tmp->fsp, &ft);
	err = errno;
	unbecome_root();
	if (ret == -1 ) {
		DEBUG(0, ("recycle: touching %s failed, reason = %s\n",
			  smb_fname_str_dbg(smb_fname_tmp), strerror(err)));
	}

	TALLOC_FREE(smb_fname_tmp);
}

static char *full_path_fname(
	TALLOC_CTX *mem_ctx,
	vfs_handle_struct *handle,
	const struct files_struct *dirfsp,
	const struct smb_filename *atname)
{
	char *path = NULL;

	if (dirfsp == dirfsp->conn->cwd_fsp ||
	    ISDOT(dirfsp->fsp_name->base_name) ||
	    atname->base_name[0] == '/')
	{
		path = talloc_asprintf(mem_ctx, "%s/%s",
				       handle->conn->connectpath,
				       atname->base_name);
	} else {
		path = talloc_asprintf(mem_ctx, "%s/%s/%s",
				       handle->conn->connectpath,
				       dirfsp->fsp_name->base_name,
				       atname->base_name);
	}
	if (path == NULL) {
		return NULL;
	}

	return path;
}


/**
 * Check if file should be recycled
 **/
static int recycle_unlink_internal(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				int flags)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	connection_struct *conn = handle->conn;
	struct smb_filename full_fname;
	char *path_name = NULL;
	char *final_name = NULL;
	char *to_free = NULL;
	char *resolved = NULL;
	const char *base;
	char *repository = NULL;
	int i = 1;
	bool exist;
	int rc = -1;
	size_t final_name_len;
	recycle_bin *the_bin = NULL;

	if (!VALID_STAT(smb_fname->st)) {
		int err = SMB_VFS_STAT(handle->conn, smb_fname);
		if (err && (errno == ENOENT)) {
			return err;
		}
		SMB_ASSERT(err == 0);
	}

	the_bin = get_recycle_bin(handle, smb_fname);
	if (the_bin == NULL) {
		DBG_ERR("Failed to get recycle bin for file\n");
		goto done;
	}
	repository = the_bin->recycle_path;

	if (!repository || *(repository) == '\0') {
		DEBUG(3, ("recycle: repository path not set, purging %s...\n",
			  smb_fname_str_dbg(smb_fname)));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	to_free = full_path_fname(talloc_tos(), handle, dirfsp, smb_fname);
	resolved = to_free + strlen(handle->conn->connectpath) + the_bin->mp_len + 1;

	full_fname = (struct smb_filename) {
		.base_name = resolved,
		.stream_name = smb_fname->stream_name,
		.st = smb_fname->st,
		.twrp = smb_fname->twrp,
		.flags = smb_fname->flags
	};
	/* we don't recycle the recycle bin... */
	if (strncmp(to_free + strlen(handle->conn->connectpath) + 1, repository,
		    strlen(repository)) == 0) {
		DEBUG(3, ("recycle: File is within recycling bin, unlinking ...\n"));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	/* extract filename and path */
	if (!parent_dirname(talloc_tos(), full_fname.base_name, &path_name, &base)) {
		rc = -1;
		errno = ENOMEM;
		goto done;
	}

	/* original filename with path */
	DBG_DEBUG("recycle: fname = %s, fpath = %s, base = %s\n",
		  smb_fname_str_dbg(&full_fname), path_name, base);

	if (matchparam(recycle_exclude(handle), base)) {
		DEBUG(3, ("recycle: file %s is excluded \n", base));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	if (matchdirparam(recycle_exclude_dir(handle), path_name)) {
		DEBUG(3, ("recycle: directory %s is excluded \n", path_name));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	if ((recycle_keep_dir_tree(handle) == True) && (path_name[0] != '.')) {
		final_name = talloc_asprintf(talloc_tos(), "%s/%s/", repository + the_bin->mp_len, path_name);
	} else {
		final_name = talloc_asprintf(talloc_tos(), "%s/", repository + the_bin->mp_len);
	}
	ALLOC_CHECK(final_name, done);

	exist = recycle_directory_exist(handle, BIN2FSP(the_bin), final_name);
	if (exist) {
		DBG_DEBUG("%s: directory already exists\n", final_name);
	} else {
		DBG_DEBUG("recycle: Creating directory %s\n", final_name);
		if (recycle_create_dir(handle, BIN2FSP(the_bin), final_name) == False) {
			DEBUG(3, ("recycle: Could not create directory, "
				  "purging %s...\n",
				  smb_fname_str_dbg(&full_fname)));
			rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
			goto done;
		}
	}

	final_name = talloc_strdup_append(final_name, base);
	ALLOC_CHECK(final_name, done);

	/* Create smb_fname with final base name and orig stream name. */
	full_fname.base_name = final_name;

	/* new filename with path */
	DBG_DEBUG("recycle: recycled file name: %s\n",
		  smb_fname_str_dbg(&full_fname));

	/* check if we should delete file from recycle bin */
	if (recycle_file_exist(handle, BIN2FSP(the_bin), full_fname.base_name)) {
		if (recycle_versions(handle) == False || matchparam(recycle_noversions(handle), base) == True) {
			DBG_INFO("recycle: Removing old file %s from recycle "
				 "bin\n", smb_fname_str_dbg(&full_fname));
			if (SMB_VFS_NEXT_UNLINKAT(handle,
						BIN2FSP(the_bin),
						&full_fname,
						flags) != 0) {
				DBG_ERR("recycle: Error deleting old file: %s\n", strerror(errno));
			}
		}
	}

	/* rename file we move to recycle bin */
	final_name_len = strlen(final_name);
	for (i = 1; recycle_file_exist(handle, BIN2FSP(the_bin), final_name); i++) {
		char *new_suffix = NULL;
		final_name[final_name_len] = '\0';
		new_suffix = talloc_asprintf(talloc_tos(), " - Copy %d", i);
		ALLOC_CHECK(new_suffix, done);

		final_name = talloc_strdup_append(final_name, new_suffix);
		ALLOC_CHECK(final_name, done);
		TALLOC_FREE(new_suffix);
	}

	DBG_DEBUG("recycle: Moving %s to %s\n",
		  smb_fname_str_dbg(smb_fname),
		  smb_fname_str_dbg(&full_fname));
	rc = SMB_VFS_NEXT_RENAMEAT(handle,
			dirfsp,
			smb_fname,
			BIN2FSP(the_bin),
			&full_fname);
	if (rc != 0) {
		DEBUG(3, ("recycle: Move error %d (%s), purging file %s "
			  "(%s)\n", errno, strerror(errno),
			  smb_fname_str_dbg(smb_fname),
			  smb_fname_str_dbg(&full_fname)));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				smb_fname,
				flags);
		goto done;
	}

	/* touch access date of moved file */
	if (recycle_touch(handle) == True || recycle_touch_mtime(handle))
		recycle_do_touch(handle, BIN2FSP(the_bin), &full_fname,
				 recycle_touch_mtime(handle));

done:
	TALLOC_FREE(path_name);
	TALLOC_FREE(final_name);
	TALLOC_FREE(to_free);
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

static int recycle_openat(vfs_handle_struct *handle,
			  const struct files_struct *dirfsp,
			  const struct smb_filename *smb_fname,
			  files_struct *fsp,
			  int flags,
			  mode_t mode)
{
	struct recycle_config_data *config = NULL;
	int ret;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct recycle_config_data,
				return -1);

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, flags, mode);
	if ((ret == -1) ||
	    (config->bins[0] != NULL) ||
	    (config->busy) ||
	    (strcmp(smb_fname->base_name, "/") == 0)) {
		return ret;
	}

	config->busy = true;

	ok = make_new_bin(handle, config, handle->conn->connectpath_fsp, handle->conn->connectpath);
	if (!ok) {
		DBG_ERR("%s: add to pathrefs failed\n", handle->conn->connectpath);
		ret = -1;
	}

	config->busy = false;
	return ret;
}

static int recycle_connect(struct vfs_handle_struct *handle,
			   const char *service, const char *user)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	connection_struct *conn = handle->conn;
	int ret;
	const char *tmp_str = NULL;
	char *repository = NULL;
	struct recycle_config_data *config = NULL;
	bool ok;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0 || IS_IPC(handle->conn) || IS_PRINT(handle->conn)) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct recycle_config_data);
	if (!config) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	tmp_str = lp_parm_const_string(
	    SNUM(handle->conn), "recycle", "repository", ".recycle"
	);

	repository = talloc_sub_full(config,
				     lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
				     conn->session_info->unix_info->unix_name,
				     conn->connectpath,
				     conn->session_info->unix_token->gid,
				     conn->session_info->unix_info->sanitized_username,
				     conn->session_info->info->domain_name,
				     tmp_str);
	if (repository == NULL) {
		DBG_ERR("%s: talloc_sub_full() failed\n", service);
		TALLOC_FREE(config);
		return -1;
	}
	trim_char(repository, '\0', '/');

	config->repository = repository;

	config->bins = talloc_zero_array(config, struct recycle_bin *, BIN_INCREMENT);
	if (config->bins == NULL) {
		errno = ENOMEM;
		TALLOC_FREE(config);
		return -1;
	};
	config->bin_array_len = BIN_INCREMENT;
	config->mode = recycle_directory_mode(handle);

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct recycle_config_data,
				return -1);

	return 0;
}

static struct vfs_fn_pointers vfs_recycle_fns = {
	.unlinkat_fn = recycle_unlinkat,
	.openat_fn = recycle_openat,
	.connect_fn = recycle_connect
};

static_decl_vfs;
NTSTATUS vfs_recycle_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "recycle",
					&vfs_recycle_fns);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_recycle_debug_level = debug_add_class("recycle");
	if (vfs_recycle_debug_level == -1) {
		vfs_recycle_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_recycle: Couldn't register custom debugging class!\n"));
	} else {
		DEBUG(10, ("vfs_recycle: Debug class number of 'recycle': %d\n", vfs_recycle_debug_level));
	}

	return ret;
}
