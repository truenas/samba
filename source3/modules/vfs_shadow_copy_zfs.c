/* shadow_copy_zfs: a shadow copy module for ZFS
 *
 * Copyright (C) Andrew Tridgell   2007 (portions taken from shadow_copy_zfs)
 * Copyright (C) Ed Plese          2009
 * Copyright (C) Volker Lendecke   2011
 * Copyright (C) Christian Ambach  2011
 * Copyright (C) Michael Adam      2013
 * Copyright (C) XStor Systems Inc 2011
 * Copyright (C) iXsystems Inc     2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "system/filesys.h"
#include "include/ntioctl.h"
#include "modules/smb_libzfs.h"
#include "../lib/util/memcache.h"
#include "../lib/util/time.h"

#define GMT_NAME_LEN 24 /* length of a @GMT- name */

#define SHADOW_COPY_ZFS_SNAP_DIR ".zfs/snapshot"

/*
 * This module does the following:
 * 1) Determines whether file path received from client contains an "@GMT token". This is
 *    a special token that can be present as part of a file path to indicate a request to see
 *    a previous version of the file or directory. The format is "@GMT-YYYY.MM.DD-HH.MM.SS".
 *    This 16-bit Unicode string represents a time and date in UTC. If the path contains an
 *    @GMT token, then redirect to the correct .zfs/snapshot path.
 * 2) Generates snapshot list for FSCTL_SRV_ENUMERATE_SNAPSHOTS response.
 *    shadow_copy_zfs_get_shadow_copy_zfs_data()
 */

static const char *null_string = NULL;
static const char **empty_list = &null_string;
static int vfs_shadow_copy_zfs_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_shadow_copy_zfs_debug_level

struct shadow_copy_zfs_config {
	struct smblibzfshandle	*libzp;
	struct dataset_list	*ds_list;

	/* Cache parameters */
	bool 			cache_enabled;

	int			timedelta;
	/* Snapshot parameters */
	bool 			ignore_empty_snaps;
	const char 		**inclusions;
	const char 		**exclusions;
	struct snapshot_list 	*snapshots;

	char			*shadow_connectpath;
};

struct snapshot_data {
	char *mountpoint;
	char *shadow_cp;
	struct snapshot_entry *snap;
};

struct shadow_copy_fsp_ext {
	struct snapshot_data *data;
	void *fsp_name_ptr;
	struct files_struct *fsp;
	vfs_handle_struct *handle;
};

static struct zfs_dataset *shadow_path_to_dataset(struct dataset_list *dl,
						  const char *path)
{
	int ret;
	struct stat st;
	struct zfs_dataset *child = NULL;
	if (!dl->children) {
		return dl->root;
	}
	ret = stat(path, &st);
	if (ret < 0) {
		DBG_ERR("Stat of %s failed with error: %s\n",
			path, strerror(errno));
	}
	if (st.st_dev == dl->root->devid) {
		return dl->root;
	}
	for (child=dl->children; child; child=child->next) {
		if (child->devid == st.st_dev) {
			return child;
		}
	}
	/*
	 * Our current cache of datasets does not contain the path in
	 * question. Use libzfs to try to get it. Allocate under
	 * memory context of our dataset list.
	 */
	child = smb_zfs_path_get_dataset(dl->root->zhandle->lz, dl,
					 path, true, false, true);
	if (child != NULL) {
		DLIST_ADD(dl->children, child);
		return child;
	}

	DBG_ERR("No dataset found for %s with device id: %lu\n",
		path, st.st_dev);
	errno = ENOENT;
	return NULL;
}

static struct snapshot_list *get_cached_snapshot(TDB_DATA ds,
			   struct shadow_copy_zfs_config *config)
{
	return (struct snapshot_list *)memcache_lookup_talloc(
				config->libzp->zcache,
				ZFS_CACHE,
				data_blob_const(ds.dptr, ds.dsize));
}

static bool put_cached_snapshot(TDB_DATA key,
				struct snapshot_list *snaps,
				struct shadow_copy_zfs_config *config)
{
	memcache_add_talloc(config->libzp->zcache,
				ZFS_CACHE,
				data_blob_const(key.dptr, key.dsize),
				&snaps);
	return true;
}

char *get_snapshot_path(TALLOC_CTX *mem_ctx,
			char *connectpath, size_t clen,
			char *mountpoint, size_t mplen,
			char *filename, size_t flen,
			char *mpoffset,
			struct snapshot_entry *snap)
{
	DBG_DEBUG("connectpath: %s, clen: %zu, mountpoint: %s, mplen %zu "
		  "filename: %s, flen %zu, mpoffset: %s, snapshot: %s\n",
		  connectpath, clen, mountpoint, mplen, filename, flen,
		  mpoffset, snap->name);
	TALLOC_CTX *tmp_ctx = NULL;
	char *ret = NULL;
	char *tmp_name = NULL;
	bool is_child = false;
	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		DBG_ERR("Failed to init new talloc context\n");
		errno = ENOMEM;
		return NULL;
	}
	tmp_name = talloc_strdup(tmp_ctx, filename);
	if (mplen > clen) {
		/*
		 * This is not the same dataset as the one underlying the connectpath.
		 */
		is_child = true;
		if (!(flen > (mplen - clen -1)) && (strcmp(mountpoint + clen + 1, tmp_name) == 0)) {
			/* The path is a dataset mountpoint. Set last path component
			 * to NULL so that we later exclude from our returned string.
			 */
			TALLOC_FREE(tmp_name);
			tmp_name = NULL;
			DBG_DEBUG("file [%s] is a sub-dataset mountpoint\n",
				  filename);
		}
		else {
			SMB_ASSERT(flen >= (mplen - clen - 1));
			tmp_name += (mplen - clen);
			DBG_DEBUG("file [%s] is within sub-dataset [%s] base_name rewritten to [%s]\n",
				  filename, mountpoint + clen, tmp_name);
		}
	}
	/*
	 * A mountpoint offset occurs when a directory inside a dataset is shared
	 * rather than the actual dataset mountpoint. We will only adjust the path
	 * relative to the snapshot if (1) there's an offset and (2) if the
	 * the path is not a child dataset. The mountpoint offset only applies to
	 * the dataset underlying the share's connectpath (at least on TrueNAS).
	 */
	if (mpoffset && !is_child) {
		if (flen) {
			ret = talloc_asprintf(mem_ctx, "%s/.zfs/snapshot/%s/%s/%s",
					      mountpoint, snap->name, mpoffset, tmp_name);
		}
		else {
			ret = talloc_asprintf(mem_ctx, "%s/.zfs/snapshot/%s/%s",
					      mountpoint, snap->name, mpoffset);
		}
	}
	/*
	 * Path is a dataset mountpoint for child dataset or
	 * the share's connectpath.
	 */
	else if ((tmp_name == NULL) || (flen == 0)) {
		ret = talloc_asprintf(mem_ctx, "%s/.zfs/snapshot/%s",
				      mountpoint, snap->name);
	}
	/*
	 * All other cases. If needed, we have adjusted the pointer for
	 * the filename to make it relative to the snapshot mountpoint
	 * rather than the share connectpath.
	 */
	else {
		ret = talloc_asprintf(mem_ctx, "%s/.zfs/snapshot/%s/%s",
				      mountpoint, snap->name, tmp_name);
	}
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/**
 * This function will check if snaplist is updated or not. If snaplist
 * is empty then it will create a new list. Each time snaplist is updated
 * the time is recorded. If the snapshot time is greater than the snaplist
 * update time then chances are we are working on an older list. Then discard
 * the old list and fetch a new snaplist. End-users can adjust the timeout
 * period by adjusting the parameter "shadow:snap_timedelta=300"
 *
 * @param[in]	handle		VFS handle struct
 * @param[in]	mem_ctx		talloc context
 * @param[in]	path		full path in which to check snapshots
 * @param[in]	do_update	update existing snapshot list cache
 * @param[out]	snapp		snapshot list
 *
 * @return	true if the list is updated else false
 */
static bool shadow_copy_zfs_update_snaplist(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    const char *path,
					    bool do_update,
					    struct snapshot_list **snapp)
{
	bool snaplist_updated = false;
	bool is_same_dataset = false;
	double seconds = 0.0;
	time_t snap_time;
	TDB_DATA key = { .dptr = NULL, .dsize = 0 };
	struct shadow_copy_zfs_config *config = NULL;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_list *cached_snaps = NULL;
	struct zfs_dataset *ds = NULL;
	struct smbzhandle *zfsp = NULL;
	struct stat st = {0};

	time(&snap_time);
	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return NULL);
	ds = shadow_path_to_dataset(config->ds_list, path);
	if (!ds) {
		return NULL;
	}
	key.dptr = discard_const_p(uint8_t, ds->dataset_name);
	key.dsize = strlen(ds->dataset_name);
	cached_snaps = get_cached_snapshot(key, config);
	if (cached_snaps != NULL) {
		seconds = difftime(snap_time, cached_snaps->timestamp);
	}

	if (((seconds > config->timedelta) && do_update) || cached_snaps == NULL) {
		DBG_INFO("refreshing stored snaplist - current timedelta: %f "
			 "permitted timedelta: %d\n", seconds, config->timedelta);

		get_smbzhandle(config->libzp, handle->conn, ds->dataset_name, &zfsp, false);
		if (zfsp == NULL) {
			return false;
		}
		snapshots = zhandle_list_snapshots(zfsp,
						   mem_ctx,
						   config->ignore_empty_snaps,
						   config->inclusions,
						   config->exclusions, 0, 0);

		close_smbzhandle(zfsp);
		if (snapshots != NULL) {
			snaplist_updated = put_cached_snapshot(key, snapshots,
							       config);
		} else {
			DBG_ERR("Failed to get shadow copy data for %s\n", path);
		}
		*snapp = snapshots;
	}
	else {
		*snapp = cached_snaps;
	}

	return snaplist_updated;
}

static bool shadow_copy_zfs_match_name(vfs_handle_struct *handle,
				       const struct smb_filename *name)
{
	if (name->twrp == 0) {
		return false;
	}

	if (name->fsp != NULL) {
		struct shadow_copy_fsp_ext *fsp_ext = NULL;
		fsp_ext = (struct shadow_copy_fsp_ext *)
		    VFS_FETCH_FSP_EXTENSION(handle, name->fsp);

		if (fsp_ext) {
			return false;
		}
	}

	return true;
}

static char *snapshot_mp_to_dataset(TALLOC_CTX *mem_ctx,
				    vfs_handle_struct *handle,
				    const char *snapshot_mp)
{
	char *ds_path = NULL;
	size_t to_remove, new_len;
	if (strlen(snapshot_mp) < (strlen(SHADOW_COPY_ZFS_SNAP_DIR) + 2)) {
		DBG_ERR("Invalid snapshot name: %s\n", snapshot_mp);
		return NULL;
	}
	ds_path = strstr(snapshot_mp, "/.zfs/snapshot/");
	if (ds_path != NULL) {
		to_remove = strlen(ds_path);
		new_len = strlen(snapshot_mp) - to_remove;
		ds_path = talloc_strndup(mem_ctx, snapshot_mp, new_len);
	}
	return ds_path;
}

/**
 * Converts path [name] to an absolute path. The relative path
 * that client sends will be relative to the connectpath
 * rather than relative to the dataset mountpoint.
 *
 * @param[in]	mem_ctx		talloc context
 * @param[in]	handle		vfs handle
 * @param[in]	priv		config data (contains stored cwd info)
 * @param[in]	name		file name
 *
 * @return	absolute path
 */
static char *resolve_path(TALLOC_CTX *mem_ctx,
			  vfs_handle_struct *handle,
			  struct shadow_copy_zfs_config *priv,
			  const char *name,
			  bool *is_shadow_path)
{
	char *new_path = NULL;
	if (name[0] != '/') {
		char *scp = priv->shadow_connectpath;
		char *cwd = handle->conn->cwd_fsp->fsp_name->base_name;
		if (scp && (strncmp(cwd, scp, strlen(scp)) == 0)) {
			*is_shadow_path = true;
		}
		if (ISDOT(name) || name[0] == '\0') {
			new_path = talloc_strdup(mem_ctx, cwd);
		}
		else if (strncmp(name, "./", 2) == 0) {
			new_path = talloc_asprintf(mem_ctx, "%s/%s", cwd, (name + 2));
		}
		else {
			new_path = talloc_asprintf(mem_ctx, "%s/%s", cwd, name);
		}
	}
	else if (strncmp(handle->conn->connectpath,
			 name, strlen(handle->conn->connectpath)) == 0) {
		new_path = talloc_strdup(mem_ctx, name);
	}
	else {
		new_path = talloc_asprintf(mem_ctx,
					   "%s%s",
					   handle->conn->connectpath,
					   name);
	}
	return new_path;
}

static void store_connectpath(vfs_handle_struct *handle,
			      const char *connectpath)
{
	struct shadow_copy_zfs_config *priv = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy_zfs_config,
				return);

	TALLOC_FREE(priv->shadow_connectpath);
	if (connectpath) {
		DBG_INFO("shadow connectpath = %s\n", connectpath);
		priv->shadow_connectpath = talloc_strdup(handle->conn, connectpath);
		if (priv->shadow_connectpath == NULL) {
			smb_panic("talloc failed\n");
		}
	}
}


static char *snapcache_get(TALLOC_CTX *tmp_ctx,
			   vfs_handle_struct *handle,
			   struct shadow_copy_zfs_config *config,
			   TDB_DATA key)
{
	return (char *)memcache_lookup_talloc(
				config->libzp->zcache,
				ZFS_CACHE,
				data_blob_const(key.dptr, key.dsize));
}

static void snapcache_set(TALLOC_CTX *tmp_ctx,
			  struct shadow_copy_zfs_config *config,
			  TDB_DATA key,
			  char *resolved_path)
{
	memcache_add_talloc(config->libzp->zcache,
				ZFS_CACHE,
				data_blob_const(key.dptr, key.dsize),
				&resolved_path);
}

/*
 * Convert a filename containing an @GMT token to a path in the corresponding
 * .zfs/snapshot/<snap_name> directory.
 */
static char *do_convert_shadow_zfs_name(vfs_handle_struct *handle,
					const char *fname,
					NTTIME tval,
					struct snapshot_data *out,
					const bool incl_rel)
{
	TALLOC_CTX *tmp_ctx = talloc_new(handle->data);
	struct shadow_copy_zfs_config *config = NULL;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_entry *entry = NULL;
	char *mpoffset = NULL;
	size_t mplen, flen, clen;
	char *ret = NULL;
	char *normalized_fname = NULL;
	char *cache_entry = NULL;
	char *tsname = NULL;
	char *res_fname = NULL;
	bool already_converted = false;
	TDB_DATA key = { .dptr = NULL, .dsize = 0 };

	mplen = flen = clen = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
	    return NULL);

	if (config->ds_list == NULL) {
		DBG_ERR("Refusing to convert to shadow copy due to "
			"path not supporting snapshots\n");
		errno = EINVAL;
		return NULL;
	}
	if (config->cache_enabled && out == NULL && !ISDOT(fname)) {
		tsname = talloc_asprintf(tmp_ctx, "%d/%ld/%s",
					 SNUM(handle->conn),
					 tval, fname);
		key.dptr = discard_const_p(uint8_t, tsname);
		key.dsize = strlen(tsname);
		ret = snapcache_get(tmp_ctx, handle, config, key);
		if (ret != NULL) {
			DBG_DEBUG("Retrieved cache entry for %s->%s\n",
				  tsname, ret);
			cache_entry = talloc_strdup(talloc_tos(), ret);
			TALLOC_FREE(tmp_ctx);
			return cache_entry;
		}
	}

	res_fname = resolve_path(tmp_ctx, handle, config, fname, &already_converted);
	if (res_fname == NULL) {
		TALLOC_FREE(tmp_ctx);
		DBG_ERR("Failed to resolve %s to an absolute path.\n", fname);
		return NULL;
	}
	if (already_converted) {
		ret = talloc_strdup(talloc_tos(), res_fname);
		TALLOC_FREE(tmp_ctx);
		return ret;
	}

	normalized_fname = canonicalize_absolute_path(tmp_ctx, res_fname);
	if (normalized_fname == NULL) {
		DBG_ERR("Failed to canonicalize %s\n", res_fname);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	shadow_copy_zfs_update_snaplist(handle, handle->conn, normalized_fname, false, &snapshots);
	if (snapshots == NULL) {
		DBG_ERR("Failed to get snapshot list for %s\n",
			normalized_fname);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	/* get snapshot name */
	for (entry = snapshots->entries; entry; entry = entry->next) {
		if (tval == entry->nt_time) {
			break;
		}
	}

	mplen = strlen(snapshots->mountpoint);
	clen = strlen(handle->conn->connectpath);
	flen = strlen(res_fname);

	/* Strip off connectpath before rewriting path to be relative to snapshot dir*/
	if (clen == flen) {
		res_fname += clen;
	}
	else if (clen < flen) {
		res_fname += (clen + 1);
	}
	else {
		DBG_ERR("resulting fname is too short - res_fname: %s, connectpath: %s\n",
			res_fname, handle->conn->connectpath);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	flen = strlen(res_fname);
	if (clen > mplen) {
		mpoffset = talloc_strdup(tmp_ctx, handle->conn->connectpath + mplen + 1);
	}

	if (entry == NULL) {
		DBG_INFO("Failed to retrieve snapshot entry for filename: %s, ts: %ld,"
			 "with snapshot mountpoint: %s\n", fname, tval, snapshots->mountpoint);
		if (strcmp(handle->conn->connectpath, snapshots->mountpoint) == 0) {
			/*
			 * Sub datasets can have snapshots that don't exist at the root
			 * of the share. It appears that SMB clients still try to enter
			 * the root of the share using the @GMT token of the sub-dataset
			 * We need to allow access here, otherwise access to the snapshot
			 * will fail.
			 */
			ret = talloc_strdup(talloc_tos(), snapshots->mountpoint);
			TALLOC_FREE(tmp_ctx);
			return ret;
		}
		else if (mpoffset) {
			/*
			 * In this cause we need to avoid granting access to the
			 * snapshot mountpoint because share is a subdirectory inside a
			 * dataset.
			 */
			ret = talloc_strdup(talloc_tos(), handle->conn->connectpath);
			TALLOC_FREE(tmp_ctx);
			return ret;
		}
		TALLOC_FREE(tmp_ctx);
		errno = ENOENT;
		return NULL;
	}
	ret = get_snapshot_path(talloc_tos(), handle->conn->connectpath, clen,
				snapshots->mountpoint, mplen,
				res_fname, flen, mpoffset, entry);

	if (out != NULL) {
		/*
		 * This mountpoint ends up getting stored as part of CWD
		 * in the chdir() function.
		 */
		if (mpoffset) {
			out->shadow_cp = talloc_asprintf(out, "%s/%s/%s/%s",
							 snapshots->mountpoint,
							 SHADOW_COPY_ZFS_SNAP_DIR,
							 entry->name, mpoffset);
		}
		else {
			out->shadow_cp = talloc_asprintf(out, "%s/%s/%s",
							 snapshots->mountpoint,
							 SHADOW_COPY_ZFS_SNAP_DIR,
							 entry->name);
		}
		out->snap = talloc_zero(out, struct snapshot_entry);
		if (out->snap == NULL) {
			errno = ENOMEM;
			TALLOC_FREE(tmp_ctx);
			return NULL;
		}
		out->snap->nt_time = entry->nt_time;
		out->snap->cr_time = entry->cr_time;
		out->snap->name = talloc_strdup(out, entry->name);
		out->mountpoint = talloc_strdup(out, snapshots->mountpoint);
		snprintf(out->snap->label, GMT_NAME_LEN, "%s", entry->label);
	}

	if (config->cache_enabled && !ISDOT(fname)) {
		cache_entry = talloc_strdup(tmp_ctx, ret);
		talloc_set_destructor(cache_entry, NULL);
		snapcache_set(tmp_ctx, config, key, cache_entry);
		DBG_INFO("Set cache entry for %s->%s\n",
			 res_fname, ret);
	}
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static char *convert_shadow_zfs_name(vfs_handle_struct *handle,
    const char *fname, NTTIME tval,
    const bool incl_rel)
{
	return do_convert_shadow_zfs_name(handle, fname, tval, NULL, incl_rel);
}

static int shadow_copy_zfs_renameat(vfs_handle_struct *handle,
				    files_struct *srcfsp,
				    const struct smb_filename *smb_fname_src,
				    files_struct *dstfsp,
				    const struct smb_filename *smb_fname_dst)
{
	int ret_src, ret_dst;

	ret_src = shadow_copy_zfs_match_name(handle, smb_fname_src);
	ret_dst = shadow_copy_zfs_match_name(handle, smb_fname_dst);

	if (ret_src != 0) {
		errno = EXDEV;
		return -1;
	}

	if (ret_dst != 0) {
		errno = EROFS;
		return -1;
	}

	return SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, smb_fname_src, dstfsp, smb_fname_dst);
}

static int shadow_copy_zfs_symlinkat(vfs_handle_struct *handle,
				     const struct smb_filename *link_contents,
				     struct files_struct *dirfsp,
				     const struct smb_filename *new_smb_filename)
{
	int ret_old, ret_new;
	ret_old = shadow_copy_zfs_match_name(handle, link_contents);
	ret_new = shadow_copy_zfs_match_name(handle, new_smb_filename);

	if ((ret_old != 0) || (ret_new != 0)) {
		errno = EROFS;
		return -1;
	}

	return SMB_VFS_NEXT_SYMLINKAT(handle, link_contents, dirfsp, new_smb_filename);
}

static int shadow_copy_zfs_linkat(vfs_handle_struct *handle,
				  files_struct *srcfsp,
				  const struct smb_filename *oldname,
				  files_struct *dstfsp,
				  const struct smb_filename *newname,
				  int flags)
{
	int ret_old, ret_new;

	ret_old = shadow_copy_zfs_match_name(handle, oldname);
	ret_new = shadow_copy_zfs_match_name(handle, newname);

	if ((ret_old != 0) || (ret_new != 0)) {
		errno = EROFS;
		return -1;
	}

	return SMB_VFS_NEXT_LINKAT(handle, srcfsp, oldname, dstfsp, newname, flags);
}

static int shadow_copy_zfs_stat(vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	int ret;
	char *tmp = NULL;

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		tmp = smb_fname->base_name;
		smb_fname->base_name = convert_shadow_zfs_name(
		    handle, smb_fname->base_name, smb_fname->twrp, True);

		if (smb_fname->base_name == NULL) {
			smb_fname->base_name = tmp;
			return -1;
		}

		ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
		TALLOC_FREE(smb_fname->base_name);
		smb_fname->base_name = tmp;
		return ret;
	}
	return SMB_VFS_NEXT_STAT(handle, smb_fname);
}

static int shadow_copy_zfs_lstat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	int ret;
	char *tmp = NULL;

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		tmp = smb_fname->base_name;
		smb_fname->base_name = convert_shadow_zfs_name(
		    handle, smb_fname->base_name, smb_fname->twrp, True);

		if (smb_fname->base_name == NULL) {
			smb_fname->base_name = tmp;
			return -1;
		}

		ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
		TALLOC_FREE(smb_fname->base_name);
		smb_fname->base_name = tmp;
		return ret;
	}
	return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
}

static int shadow_copy_zfs_fstat(vfs_handle_struct *handle, files_struct *fsp,
			      SMB_STRUCT_STAT *sbuf)
{
	int ret;
	struct smb_filename *orig_smb_fname = NULL;
	struct smb_filename vss_smb_fname;
	struct smb_filename *orig_base_smb_fname = NULL;
	struct smb_filename vss_base_smb_fname;
	char *stripped = NULL;
	if (!shadow_copy_zfs_match_name(handle, fsp->fsp_name)) {
		ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
		if (ret == -1) {
			return ret;
		}
		return 0;
	}

	vss_smb_fname = *fsp->fsp_name;
	vss_smb_fname.base_name = convert_shadow_zfs_name(handle,
				 fsp->fsp_name->base_name, fsp->fsp_name->twrp, True);

	if (vss_smb_fname.base_name == NULL) {
		return -1;
	}

	orig_smb_fname = fsp->fsp_name;
	fsp->fsp_name = &vss_smb_fname;

	if (fsp->base_fsp != NULL) {
		vss_base_smb_fname = *fsp->base_fsp->fsp_name;
		vss_base_smb_fname.base_name = vss_smb_fname.base_name;
		orig_base_smb_fname = fsp->base_fsp->fsp_name;
		fsp->base_fsp->fsp_name = &vss_base_smb_fname;
	}

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);

	fsp->fsp_name = orig_smb_fname;
	if (fsp->base_fsp != NULL) {
		fsp->base_fsp->fsp_name = orig_base_smb_fname;
	}
	return ret;
}

static int shadow_copy_zfs_open(vfs_handle_struct *handle,
				const struct files_struct *dirfsp,
				const struct smb_filename *smb_fname_in,
				files_struct *fsp,
				int flags, mode_t mode)
{
	int ret;
	char *tmp = NULL;
	struct smb_filename *conv_smb_fname = NULL;
	struct smb_filename *smb_fname = NULL;
	struct snapshot_data *data = NULL;
	struct shadow_copy_fsp_ext *fsp_ext = NULL;

	smb_fname = full_path_from_dirfsp_atname(talloc_tos(),
						 dirfsp,
						 smb_fname_in);

	if (!shadow_copy_zfs_match_name(handle, smb_fname)) {
		TALLOC_FREE(smb_fname);
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname_in,
					   fsp, flags, mode);
	}

	/*
	 * If dirfsp is an open in a snapshot directory, then concatenate the
	 * dirfsp path with smb_fname relative path, convert into an absolute
	 * path in the relevant snapdir, and pass to openat().
	 */
	data = talloc_zero(handle, struct snapshot_data);
	if (data == NULL) {
		TALLOC_FREE(smb_fname);
		errno = ENOMEM;
		return -1;
	}
	tmp = do_convert_shadow_zfs_name(handle,
					 smb_fname->base_name,
					 smb_fname->twrp,
					 data,
					 True);
	if (tmp == NULL) {
		TALLOC_FREE(smb_fname);
		return -1;
	}

	conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					     tmp,
					     NULL,
					     &smb_fname->st,
					     smb_fname->twrp,
					     smb_fname->flags);
	if (conv_smb_fname == NULL) {
		TALLOC_FREE(smb_fname);
		TALLOC_FREE(tmp);
		return -1;
	}
	TALLOC_FREE(smb_fname);

	flags &= ~(O_WRONLY | O_RDWR | O_CREAT);

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, conv_smb_fname,
				  fsp, flags, mode);

	TALLOC_FREE(conv_smb_fname);

	if (ret != -1) {
		fsp_ext = VFS_ADD_FSP_EXTENSION(handle, fsp, struct shadow_copy_fsp_ext, NULL);
		SMB_ASSERT(fsp_ext != NULL);
		fsp_ext->data = talloc_move(VFS_MEMCTX_FSP_EXTENSION(handle, fsp), &data);
		fsp_ext->handle = handle;
		fsp_ext->fsp = fsp;
		fsp_ext->fsp_name_ptr = fsp->fsp_name;
	}

	return ret;
}

static int shadow_copy_zfs_unlinkat(vfs_handle_struct *handle,
				    struct files_struct *dirfsp,
				    const struct smb_filename *smb_fname,
				    int flags)
{
	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
}

static int shadow_copy_zfs_fchmod(vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  mode_t mode)
{
	if (shadow_copy_zfs_match_name(handle, fsp->fsp_name)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
}

static int shadow_copy_zfs_fchown(vfs_handle_struct *handle,
				  files_struct *fsp,
				  uid_t uid,
				  gid_t gid)
{
	if (shadow_copy_zfs_match_name(handle, fsp->fsp_name)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
}

static int shadow_copy_zfs_lchown(vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  uid_t uid,
				  gid_t gid)
{
	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
}

static int shadow_copy_zfs_chdir(vfs_handle_struct *handle,
				 const struct smb_filename *smb_fname)
{
	int ret;
	char *conv = NULL;
	struct snapshot_data *data = NULL;
	char *shadow_cp = NULL;
	struct smb_filename *conv_smb_fname = NULL;

	if (!shadow_copy_zfs_match_name(handle, smb_fname)) {
		ret =  SMB_VFS_NEXT_CHDIR(handle, smb_fname);
		store_connectpath(handle, NULL);
		return ret;
	}

	data = talloc_zero(handle->conn, struct snapshot_data);
	if (data == NULL) {
		errno = ENOMEM;
		return -1;
	}
	conv = do_convert_shadow_zfs_name(handle,
					smb_fname->base_name,
					smb_fname->twrp,
					data, True);
	if (conv == NULL) {
		return -1;
	}

	conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					     conv,
					     NULL,
					     NULL,
					     0,
					     smb_fname->flags);
	if (conv_smb_fname == NULL) {
		TALLOC_FREE(conv);
		return -1;
	}

	ret = SMB_VFS_NEXT_CHDIR(handle, conv_smb_fname);
	if (ret == 0) {
		store_connectpath(handle, data->shadow_cp);
	}
	TALLOC_FREE(conv);
	TALLOC_FREE(conv_smb_fname);
	return ret;
}

static int shadow_copy_zfs_fntimes(vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   struct smb_file_time *ft)
{
	if (shadow_copy_zfs_match_name(handle, fsp->fsp_name)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_FNTIMES(handle, fsp, ft);
}

static int shadow_copy_zfs_readlinkat(vfs_handle_struct *handle,
				      const struct files_struct *dirfsp,
				      const struct smb_filename *smb_fname,
				      char *buf,
				      size_t bufsiz)
{
	int ret;
	int shadow_fd = -1;
	int orig_fd = -1;
	char *shadow_name = NULL;
	struct smb_filename *conv = NULL;

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		conv = cp_smb_filename(talloc_tos(), smb_fname);
		if (conv == NULL) {
			return -1;
		}
		shadow_name = convert_shadow_zfs_name(
		    handle, smb_fname->base_name, smb_fname->twrp, True);
		if (shadow_name == NULL){
			TALLOC_FREE(conv);
			return -1;
		}
		conv->base_name = shadow_name;
		ret = SMB_VFS_NEXT_READLINKAT(handle, dirfsp, conv, buf, bufsiz);
		TALLOC_FREE(conv);
		TALLOC_FREE(shadow_name);
		return ret;
	} else {
		return SMB_VFS_NEXT_READLINKAT(handle, dirfsp, smb_fname, buf, bufsiz);
	}
}

static int shadow_copy_zfs_mknodat(vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode,
				SMB_DEV_T dev)
{
	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKNODAT(handle, dirfsp, smb_fname, mode, dev);
}

static struct smb_filename *shadow_copy_zfs_realpath(vfs_handle_struct *handle, TALLOC_CTX *ctx,
				   const struct smb_filename *smb_fname)
{
	struct smb_filename *ret = NULL;
	char *conv = NULL;
	struct smb_filename *conv_smb_fname = NULL;

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		conv = convert_shadow_zfs_name(
		    handle, smb_fname->base_name, smb_fname->twrp, True);
		if (conv == NULL) {
			errno = ENOENT;
			return NULL;
		}
		conv_smb_fname = synthetic_smb_fname(talloc_tos(),
						     conv,
						     NULL,
						     NULL,
						     0,
						     smb_fname->flags);
		if (conv_smb_fname == NULL) {
			TALLOC_FREE(conv);
			errno = ENOMEM;
			return NULL;
		}
		ret = SMB_VFS_NEXT_REALPATH(handle, ctx, conv_smb_fname);
		TALLOC_FREE(conv);
		TALLOC_FREE(conv_smb_fname);
		return ret;
	}

	return SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
}

static int shadow_copy_zfs_get_shadow_copy_zfs_data(vfs_handle_struct *handle,
						    files_struct *fsp,
						    struct shadow_copy_data
						    *shadow_copy_zfs_data,
						    bool labels)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct shadow_copy_zfs_config *config = NULL;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_entry *entry = NULL;
	SMB_STRUCT_STAT sbuf, cur_st, prev_st;
	const SMB_STRUCT_STAT *psbuf = NULL;
	uint idx = 0;
	char tmpbuf[PATH_MAX];
	char *fullpath, *to_free;
	char *tmp_file = NULL;
	char *file_name = NULL;
	char *mpoffset = NULL;
	ssize_t len, cpathlen, mplen, flen;
	int rv;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return -1);

	if (config->ds_list == NULL) {
		DBG_ERR("No dataset list present for share at path: %s\n",
			handle->conn->connectpath);
		return 0;
	}

	cpathlen = strlen(handle->conn->connectpath);

	len = full_path_tos(handle->conn->connectpath, fsp->fsp_name->base_name, tmpbuf,
			    sizeof(tmpbuf), &fullpath, &to_free);

	if (len == -1) {
		errno = ENOMEM;
		return -1;
	}

	tmp_ctx = talloc_new(config);

	if (VALID_STAT(fsp->fsp_name->st)) {
		psbuf = &fsp->fsp_name->st;
	}

	if (psbuf == NULL) {
		rv = vfs_stat_smb_basename(handle->conn, fsp->fsp_name, &sbuf);
		if (rv != 0) {
			DBG_ERR("stat [%s]failed: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			return -1;
		}
		psbuf = &sbuf;
	}
	prev_st = *psbuf;

	shadow_copy_zfs_update_snaplist(handle,
					handle->conn,
					fullpath,
					true,
					&snapshots);
	if (snapshots == NULL) {
		DBG_INFO("failed to retrieve snapshots for %s\n", fullpath);
		TALLOC_FREE(tmp_ctx);
		TALLOC_FREE(to_free);
		return -1;
	}
	shadow_copy_zfs_data->labels = NULL;
	DBG_INFO("Retrieved %zu snapshots for %s\n",
		 snapshots->num_entries, fsp_str_dbg(fsp));

	if (labels) {
		shadow_copy_zfs_data->labels =
			talloc_array(shadow_copy_zfs_data,
				     SHADOW_COPY_LABEL,
				     snapshots->num_entries);

		if (shadow_copy_zfs_data->labels == NULL) {
			DBG_ERR("shadow_copy_zfs: out of memory\n");
			TALLOC_FREE(tmp_ctx);
			TALLOC_FREE(to_free);
			return -1;
		}
	}
	mplen = strlen(snapshots->mountpoint);
	flen = strlen(fsp->fsp_name->base_name);
	if (cpathlen > mplen) {
		/*
		 * Connectpath for share is longer than the dataset mountpoint.
		 * This happens if share is directory outside of mountpoint, which
		 * most commonly occurs when share is a [homes] share.
		 */
		mpoffset = talloc_strdup(tmp_ctx, (handle->conn->connectpath + mplen + 1));
	}

	for (entry = snapshots->entries; entry; entry = entry->next) {
		/*
		 * Directories should always be added if they exist in the
		 * snapshot. Files only be added if mtime differs.
		 */
		tmp_file = get_snapshot_path(tmp_ctx, handle->conn->connectpath,
					     cpathlen, snapshots->mountpoint,
					     mplen, fsp->fsp_name->base_name,
					     flen, mpoffset, entry);

		rv = sys_stat(tmp_file, &cur_st, false);
		TALLOC_FREE(tmp_file);
		if (rv != 0) {
			DBG_INFO("stat() failed for [%s] in mp [%s] snap [%s]: %s\n",
				 fsp_str_dbg(fsp), snapshots->mountpoint, entry->name,
				 strerror(errno));
			continue;
		}
		if (config->ignore_empty_snaps && !S_ISDIR(cur_st.st_ex_mode) &&
		    (timespec_compare(&cur_st.st_ex_mtime, &prev_st.st_ex_mtime) == 0)) {
			continue;
			}
		if (labels) {
			strlcpy(shadow_copy_zfs_data->labels[idx],
				entry->label, sizeof(entry->label));
		}
		idx++;
		prev_st = cur_st;
	}

	shadow_copy_zfs_data->num_volumes = idx;
	TALLOC_FREE(to_free);
	TALLOC_FREE(tmp_ctx);
	return 0;
}

static int shadow_copy_zfs_mkdirat(vfs_handle_struct *handle,
				   struct files_struct *dirfsp,
				   const struct smb_filename *smb_fname,
				   mode_t mode)
{
	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKDIRAT(handle, dirfsp, smb_fname, mode);
}

static int shadow_copy_zfs_fchflags(vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    unsigned int flags)
{
	if (shadow_copy_zfs_match_name(handle, fsp->fsp_name)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_FCHFLAGS(handle, fsp, flags);
}

static int shadow_copy_zfs_fsetxattr(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     const char *aname,
				     const void *value,
				     size_t size,
				     int flags)
{
	if (shadow_copy_zfs_match_name(handle, fsp->fsp_name)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_FSETXATTR(handle, fsp, aname, value, size, flags);
}

static int shadow_copy_zfs_get_real_filename(struct vfs_handle_struct *handle,
					  const struct smb_filename *path,
					  const char *name,
					  TALLOC_CTX *mem_ctx,
					  char **found_name)
{
	ssize_t ret;
	char *conv = NULL;
	struct smb_filename *conv_smb_fname = NULL;

	if (shadow_copy_zfs_match_name(handle, path)) {
		conv = convert_shadow_zfs_name(handle, path->base_name,
					       path->twrp, True);
		if (conv == NULL) {
			return -1;
		}
		conv_smb_fname = synthetic_smb_fname(talloc_tos(),
						conv,
						NULL,
						NULL,
						0,
						path->flags);
		TALLOC_FREE(conv);
		if (conv_smb_fname == NULL) {
			return -1;
		}
		ret = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, conv_smb_fname, name,
						     mem_ctx, found_name);
		TALLOC_FREE(conv_smb_fname);
		return ret;
	}
	return SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name,
					      mem_ctx, found_name);
}

static const char *shadow_copy_zfs_connectpath(struct vfs_handle_struct *handle,
					    const struct smb_filename *smb_fname)
{
	const char *ret;
	char *conv = NULL;
	struct shadow_copy_zfs_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return NULL);

	if (config->shadow_connectpath != NULL) {
		DBG_INFO("cached connect path is [%s]\n",
			 config->shadow_connectpath);
		return config->shadow_connectpath;
	}

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		char *out = NULL;
		struct snapshot_data *data = NULL;
		data = talloc_zero(handle, struct snapshot_data);
		if (data == NULL) {
			errno = ENOMEM;
			return NULL;
		}
		conv = do_convert_shadow_zfs_name(handle,
					smb_fname->base_name,
					smb_fname->twrp,
					data, True);
		if (conv == NULL) {
			return handle->conn->connectpath;
		}
		TALLOC_FREE(conv);
		if (data->shadow_cp == NULL) {
			TALLOC_FREE(data);
			return SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname);
		}
		out = talloc_strdup(talloc_tos(), data->shadow_cp);

		TALLOC_FREE(data);
		return out;
	}
	return SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname);
}

static uint64_t shadow_copy_zfs_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	uint64_t ret = (uint64_t)-1;
	char *conv = NULL;
	struct smb_filename *conv_smb_fname = NULL;

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		conv = convert_shadow_zfs_name(handle, smb_fname->base_name,
					       smb_fname->twrp, True);
		if (conv == NULL) {
			return (uint64_t)-1;
		}
		conv_smb_fname = synthetic_smb_fname(talloc_tos(),
						conv,
						NULL,
						NULL,
						0,
						smb_fname->flags);
		if (conv_smb_fname == NULL) {
			TALLOC_FREE(conv);
			return -1;
		}

		ret = SMB_VFS_NEXT_DISK_FREE(handle, conv_smb_fname, bsize, dfree, dsize);
		TALLOC_FREE(conv);
		TALLOC_FREE(conv_smb_fname);
		return ret;
	}
	return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree,
				      dsize);
}

static int shadow_copy_zfs_get_quota(vfs_handle_struct *handle, const struct smb_filename *smb_fname,
				  enum SMB_QUOTA_TYPE qtype, unid_t id,
				  SMB_DISK_QUOTA *dq)
{
	int ret;
	char *conv = NULL;
	struct smb_filename *conv_smb_fname = NULL;

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		conv = convert_shadow_zfs_name(handle, smb_fname->base_name,
					       smb_fname->twrp, True);
		if (conv == NULL) {
			return -1;
		}
		conv_smb_fname = synthetic_smb_fname(talloc_tos(),
						conv,
						NULL,
						NULL,
						0,
						smb_fname->flags);
		if (conv_smb_fname == NULL) {
			TALLOC_FREE(conv);
			return -1;
		}

		ret = SMB_VFS_NEXT_GET_QUOTA(handle, conv_smb_fname, qtype, id, dq);
		TALLOC_FREE(conv);
		TALLOC_FREE(conv_smb_fname);
		return ret;
	} else {
		return SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, dq);
	}
}

static int shadow_copy_zfs_connect(struct vfs_handle_struct *handle,
				const char *service, const char *user)
{
	struct smblibzfshandle	*libzp = NULL;
	struct shadow_copy_zfs_config *config = NULL;
	int ret;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct shadow_copy_zfs_config);
	if (config == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &config->libzp,
			    &config->ds_list);

	if (ret != 0) {
		DBG_ERR("Failed to initialize zfs: %s\n", strerror(errno));
		return -1;
	}

	config->inclusions = lp_parm_string_list(SNUM(handle->conn), "shadow",
						"include", empty_list);
	config->exclusions = lp_parm_string_list(SNUM(handle->conn), "shadow",
						 "exclude", empty_list);

	config->cache_enabled = lp_parm_bool(SNUM(handle->conn), "shadow",
						"cache_enabled", true);

	config->ignore_empty_snaps = lp_parm_bool(SNUM(handle->conn), "shadow",
						"ignore_empty_snaps", true);

	config->timedelta = lp_parm_int(SNUM(handle->conn),
					"shadow", "snap_timedelta", 300);


	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct shadow_copy_zfs_config,
				return -1);

	return 0;
}

static struct vfs_fn_pointers vfs_shadow_copy_zfs_fns = {
	.connect_fn = shadow_copy_zfs_connect,
	.disk_free_fn = shadow_copy_zfs_disk_free,
	.get_quota_fn = shadow_copy_zfs_get_quota,
	.renameat_fn = shadow_copy_zfs_renameat,
	.linkat_fn = shadow_copy_zfs_linkat,
	.symlinkat_fn = shadow_copy_zfs_symlinkat,
	.stat_fn = shadow_copy_zfs_stat,
	.lstat_fn = shadow_copy_zfs_lstat,
	.fstat_fn = shadow_copy_zfs_fstat,
	.openat_fn = shadow_copy_zfs_open,
	.unlinkat_fn = shadow_copy_zfs_unlinkat,
	.fchmod_fn = shadow_copy_zfs_fchmod,
	.fchown_fn = shadow_copy_zfs_fchown,
	.lchown_fn = shadow_copy_zfs_lchown,
	.chdir_fn = shadow_copy_zfs_chdir,
	.fntimes_fn = shadow_copy_zfs_fntimes,
	.readlinkat_fn = shadow_copy_zfs_readlinkat,
	.mknodat_fn = shadow_copy_zfs_mknodat,
	.realpath_fn = shadow_copy_zfs_realpath,
	.get_shadow_copy_data_fn = shadow_copy_zfs_get_shadow_copy_zfs_data,
	.mkdirat_fn = shadow_copy_zfs_mkdirat,
	.fsetxattr_fn = shadow_copy_zfs_fsetxattr,
	.fchflags_fn = shadow_copy_zfs_fchflags,
	.get_real_filename_fn = shadow_copy_zfs_get_real_filename,
	.connectpath_fn = shadow_copy_zfs_connectpath,
};

NTSTATUS vfs_shadow_copy_zfs_init(TALLOC_CTX *);
NTSTATUS vfs_shadow_copy_zfs_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret =  smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
					 "shadow_copy_zfs", &vfs_shadow_copy_zfs_fns);
	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_shadow_copy_zfs_debug_level = debug_add_class("shadowzfs");
	if (vfs_shadow_copy_zfs_debug_level == -1) {
		vfs_shadow_copy_zfs_debug_level = DBGC_VFS;
		DBG_ERR("vfs_shadow_copy_zfs: Couldn't register custom debugging class!\n");
	} else {
		DBG_DEBUG("vfs_shadow_copy_zfs: Debug class number of 'shadowzfs': %d\n",
			  vfs_shadow_copy_zfs_debug_level);
	}

	return ret;
}
