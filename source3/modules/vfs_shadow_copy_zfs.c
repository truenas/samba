/* shadow_copy_zfs: a shadow copy module for ZFS
 *
 * Copyright (C) Andrew Tridgell   2007 (portions taken from shadow_copy_zfs)
 * Copyright (C) Ed Plese          2009
 * Copyright (C) Volker Lendecke   2011
 * Copyright (C) Christian Ambach  2011
 * Copyright (C) Michael Adam      2013
 * Copyright (C) XStor Systems Inc 2011
 * Copyright (C) iXsystems Inc     2022
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

static int vfs_shadow_copy_zfs_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_shadow_copy_zfs_debug_level

struct shadow_copy_zfs_config {
	struct zfs_dataset	*ds;
	struct zfs_dataset	*singleton;
	struct memcache		*zcache;

	int			timedelta;
	/* Snapshot parameters */
	struct snap_filter	*filter;
	struct snapshot_list 	*snapshots;
	char			*shadow_connectpath;
};

struct snapshot_data {
	char mountpoint[PATH_MAX];
	char shadow_cp[PATH_MAX];
	enum casesensitivity sens;
	struct snapshot_entry *snap;
};

struct shadow_copy_fsp_ext {
	struct snapshot_data *data;
	void *fsp_name_ptr;
	struct files_struct *fsp;
	vfs_handle_struct *handle;
};

static struct zfs_dataset *shadow_path_to_dataset(
    struct vfs_handle_struct *handle,
    struct shadow_copy_zfs_config *config,
    const char *path)
{
	int err;
	struct stat st;
	struct zfs_dataset *resolved = NULL;

	err = stat(path, &st);
	if (err && errno == ENOENT) {
		char tmp_path[PATH_MAX];
		char *slashp = NULL;
		strlcpy(tmp_path, path, sizeof(tmp_path));

		while (err && errno == ENOENT) {
			slashp = strrchr(tmp_path, '/');
			if (slashp == NULL) {
				break;
			}
			*slashp = '\0';
			err = stat(tmp_path, &st);
		}
	}
	if (err == 0) {
		if (st.st_dev == config->ds->devid) {
			return config->ds;
		}

		if (config->singleton &&
		    (config->singleton->devid == st.st_dev)) {
			return config->singleton;
		}
	}

	/*
	 * Our current cache of datasets does not contain the path in
	 * question. Use libzfs to try to get it. Allocate under
	 * memory context of our dataset list.
	 */
	resolved = smb_zfs_path_get_dataset(config, path, true, true, true);
	if (resolved != NULL) {
		TALLOC_FREE(config->singleton);
		config->singleton = resolved;
		return resolved;
	}

	DBG_ERR("No dataset found for %s with device id: %lu\n",
		path, st.st_dev);
	errno = ENOENT;
	return NULL;
}

static struct zfs_dataset *shadow_fsp_to_dataset(
    struct vfs_handle_struct *handle,
    struct shadow_copy_zfs_config *config,
    files_struct *fsp)
{
	int ret;
	dev_t devid;
	struct zfs_dataset *resolved = NULL;

	if (VALID_STAT(fsp->fsp_name->st)) {
		devid = fsp->fsp_name->st.st_ex_dev;
	} else {
		SMB_STRUCT_STAT st;
		ret = SMB_VFS_NEXT_FSTAT(handle, fsp, &st);
		if (ret != 0) {
			DBG_ERR("%s: fstat() failed: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			return NULL;
		}
		devid = st.st_ex_dev;
	}

	if (devid == config->ds->devid) {
		return config->ds;
	}

	if ((config->singleton != NULL) &&
	    (devid == config->singleton->devid)) {
		return config->singleton;
	}

	resolved = smb_zfs_fd_get_dataset(config, fsp_get_pathref_fd(fsp), true, true);
	if (resolved != NULL) {
		TALLOC_FREE(config->singleton);
		config->singleton = resolved;
		return resolved;
	}

	DBG_ERR("%s: no dataset found\n", fsp_str_dbg(fsp));
	errno = ENOENT;
	return NULL;
}

static struct snapshot_list *get_cached_snapshot(TDB_DATA ds,
			   struct shadow_copy_zfs_config *config)
{
	return (struct snapshot_list *)memcache_lookup_talloc(
				config->zcache,
				ZFS_CACHE,
				data_blob_const(ds.dptr, ds.dsize));
}

static bool put_cached_snapshot(TDB_DATA key,
				struct snapshot_list *snaps,
				struct shadow_copy_zfs_config *config)
{
	memcache_add_talloc(config->zcache,
				ZFS_CACHE,
				data_blob_const(key.dptr, key.dsize),
				&snaps);
	return true;
}

char *get_snapshot_path(TALLOC_CTX *mem_ctx,
			char *connectpath,
			char *mountpoint,
			char *filename,
			const char *mpoffset,
			struct snapshot_entry *snap,
			enum casesensitivity sens)
{
	DBG_DEBUG("connectpath: %s, mountpoint: %s, "
		  "filename: %s, mpoffset: %s, snapshot: %s\n",
		  connectpath, mountpoint, filename,
		  mpoffset, snap->name);
	char *ret = NULL;
	char buf[PATH_MAX] = {0};
	char *tmp_name = buf;
	char *child_offset = NULL;
	int (*strcmp_fn)(const char *s1, const char *s2);
	int (*strncmp_fn)(const char *s1, const char *s2, size_t len);

	switch(sens) {
	case SMBZFS_MIXED:
	case SMBZFS_SENSITIVE:
		strcmp_fn = strcmp;
		strncmp_fn = strncmp;
		break;
	case SMBZFS_INSENSITIVE:
		strcmp_fn = strcasecmp_m;
		strncmp_fn = strncasecmp_m;
		break;
	default:
		smb_panic("Unsupported case sensitivity setting");
	}


	strlcpy(buf, filename, sizeof(buf));
	if (mpoffset == NULL) {
		SMB_ASSERT(strcmp_fn(mountpoint, connectpath) >= 0);
		child_offset = mountpoint + strlen(connectpath);
	}

	if (child_offset && (*child_offset == '/')) {
		/*
		 * This is not the same dataset as the one underlying the connectpath.
		 */
		child_offset += 1;
		if (strcmp_fn(child_offset, tmp_name) == 0) {
			/* The path is a dataset mountpoint. Set last path component
			 * to NULL so that we later exclude from our returned string.
			 */
			*tmp_name = '\0';
			DBG_DEBUG("file [%s] is a sub-dataset mountpoint\n",
				  filename);
		} else {
			SMB_ASSERT(strncmp_fn(tmp_name, child_offset, strlen(child_offset)) == 0);
			tmp_name += strlen(child_offset) + 1;
			DBG_DEBUG("file [%s] is within sub-dataset [%s] base_name rewritten to [%s]\n",
				  filename, mountpoint, tmp_name);
		}
	}
	/*
	 * A mountpoint offset occurs when a directory inside a dataset is shared
	 * rather than the actual dataset mountpoint. We will only adjust the path
	 * the path is not a child dataset.
	 */
	if (mpoffset) {
		if (*filename != '\0') {
			ret = talloc_asprintf(mem_ctx, "%s/.zfs/snapshot/%s/%s/%s",
					      mountpoint, snap->name, mpoffset, tmp_name);
		} else {
			ret = talloc_asprintf(mem_ctx, "%s/.zfs/snapshot/%s/%s",
					      mountpoint, snap->name, mpoffset);
		}
	}
	/*
	 * Path is a dataset mountpoint for child dataset or
	 * the share's connectpath.
	 */
	else if ((*tmp_name == '\0') || (*filename == '\0')) {
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
					    files_struct *fsp,
					    bool do_update,
					    struct snapshot_list **snapp,
					    enum casesensitivity *psens)
{
	bool snaplist_updated = false;
	double seconds = 0.0;
	time_t snap_time;
	TDB_DATA key = { .dptr = NULL, .dsize = 0 };
	struct shadow_copy_zfs_config *config = NULL;
	struct snapshot_list *cached_snaps = NULL;
	struct zfs_dataset *ds = NULL;

	time(&snap_time);
	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return NULL);
	if (fsp == NULL) {
		ds = shadow_path_to_dataset(handle, config, path);
	} else {
		ds = shadow_fsp_to_dataset(handle, config, fsp);
	}
	if (!ds || ds->properties->snapdir_visible) {
		*snapp = NULL;
		return false;
	}
	key.dptr = discard_const_p(uint8_t, ds->dataset_name);
	key.dsize = strlen(ds->dataset_name);
	cached_snaps = get_cached_snapshot(key, config);
	if (cached_snaps != NULL) {
		seconds = difftime(snap_time, cached_snaps->timestamp);
	}
	/*
	 * If we have retrieved snapshots for this dataset before
	 * perform optimized lookup based on createtxg of last snapshot
	 * we've retrieved
	 */
	if ((seconds && seconds > config->timedelta) &&
	     cached_snaps->num_entries > 0) {
		bool ok;

		DBG_INFO("refreshing stored snaplist - current timedelta: %f "
			 "permitted timedelta: %d, dataset: %s\n",
			 seconds, config->timedelta, ds->dataset_name);

		ok = update_snapshot_list(ds->zhandle, cached_snaps, config->filter);
		if (!ok) {
			DBG_ERR("%s: Failed to update snapshot list: %s\n",
				cached_snaps->mountpoint, strerror(errno));
			*snapp = NULL;
			return false;
		}
		*snapp = cached_snaps;
		snaplist_updated = true;
	}
	/*
	 * We haven't gotten any snapshots before for this dataset.
	 * Try from scratch.
	 */
	else if (cached_snaps == NULL) {
		struct snapshot_list *snapshots = NULL;
		snapshots = zhandle_list_snapshots(ds->zhandle,
						   mem_ctx,
						   config->filter);
		if (snapshots != NULL) {
			snaplist_updated = put_cached_snapshot(key, snapshots,
							       config);
		} else {
			DBG_ERR("Failed to get shadow copy data for %s\n", path);
		}
		*snapp = snapshots;
	}
	/*
	 * We have snapshots, but timedelta hasn't been exceeded so use
	 * cached values.
	 */
	else {
		*snapp = cached_snaps;
	}
	*psens = ds->properties->casesens;
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

static bool path_in_ctldir(const char *path, bool *is_snapdir)
{
	char *p = NULL;
	struct stat st;
	char tmp[PATH_MAX];
	int err;

	p = strstr(path, ".zfs/snapshot");
	if (p == NULL) {
		*is_snapdir = false;
		return true;
	}

	strlcpy(tmp, path, sizeof(tmp));
	tmp[PTR_DIFF(p + 4, path)] = '\0';
	err = stat(tmp, &st);
	if (err) {
		DBG_ERR("%s: stat() failed: %s\n", tmp, strerror(errno));
		return false;
	}

	*is_snapdir = inode_is_ctldir(st.st_ino);
	return true;
}

static void resolve_path(vfs_handle_struct *handle,
			 struct shadow_copy_zfs_config *priv,
			 const char *name,
			 char *buf,
			 size_t bufsz,
			 bool *is_shadow_path)
{
	if (name[0] != '/') {
		char *scp = priv->shadow_connectpath;
		char *cwd = handle->conn->cwd_fsp->fsp_name->base_name;
		if (scp && (strncmp(cwd, scp, strlen(scp)) == 0)) {
			*is_shadow_path = true;
		}
		if (ISDOT(name) || name[0] == '\0') {
			strlcpy(buf, cwd, bufsz);
		}
		else if (strncmp(name, "./", 2) == 0) {
			snprintf(buf, bufsz, "%s/%s", cwd, name + 2);
		}
		else {
			snprintf(buf, bufsz, "%s/%s", cwd, name);
		}
	}
	else if (strncmp(handle->conn->connectpath,
			 name, strlen(handle->conn->connectpath)) == 0) {
		strlcpy(buf, name, bufsz);
	}
	else {
		snprintf(buf, bufsz, "%s/%s",
			 handle->conn->connectpath,
			 name);
	}
	if (!(*is_shadow_path)) {
		if (!path_in_ctldir(buf, is_shadow_path)) {
			DBG_ERR("%s: could not determine whether path is "
				"in ZFS snapdir: %s\n", buf, strerror(errno));
		}
	}
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

static void cp_snapshot_data(struct snapshot_data *in,
			     struct snapshot_data *out)
{
	strlcpy(out->mountpoint,
		in->mountpoint,
		sizeof(out->mountpoint));

	strlcpy(out->shadow_cp,
		in->shadow_cp,
		sizeof(out->shadow_cp));

	strlcpy(out->shadow_cp,
		in->shadow_cp,
		sizeof(out->shadow_cp));

	out->snap->nt_time = in->snap->nt_time;
	out->snap->cr_time = in->snap->cr_time;
	out->sens = in->sens;

	strlcpy(out->snap->name,
		in->snap->name,
		sizeof(out->snap->name));
	strlcpy(out->snap->label,
		in->snap->label,
		sizeof(out->snap->label));
}

static bool zfs_lookup_snapshot_list(vfs_handle_struct *handle,
				     const struct smb_filename *fname_in,
				     const char *res_fname,
				     struct snapshot_data *data,
				     const char *location)
{
	char *normalized_fname = NULL;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_entry *entry = NULL;
	enum casesensitivity sens;
	int err;

	if (fname_in->fsp != NULL) {
		// Linked FSP may have snapshot data in extension
		struct shadow_copy_fsp_ext *fsp_ext = NULL;
		fsp_ext = (struct shadow_copy_fsp_ext *)
		    VFS_FETCH_FSP_EXTENSION(handle, fname_in->fsp);

		if (fsp_ext) {
			DBG_ERR("[%s()] using stored snapshot data\n",
				location);
			cp_snapshot_data(fsp_ext->data, data);
			return true;
		}
	}

	normalized_fname = canonicalize_absolute_path(handle->conn, res_fname);
	if (normalized_fname == NULL) {
		DBG_ERR("[%s()]: Failed to canonicalize %s\n", location, res_fname);
		return false;
	}

	shadow_copy_zfs_update_snaplist(handle, handle->conn, normalized_fname,
					NULL, false, &snapshots, &sens);
	if (snapshots == NULL) {
		DBG_ERR("[%s()]: Failed to get snapshot list for %s\n",
			location, normalized_fname);
		TALLOC_FREE(normalized_fname);
		return false;
	}

	TALLOC_FREE(normalized_fname);

	for (entry = snapshots->entries; entry; entry = entry->next) {
		if (fname_in->twrp == entry->nt_time) {
			break;
		}
	}

	// We want mountpoint populated
	strlcpy(data->mountpoint, snapshots->mountpoint,
		sizeof(data->mountpoint));

	if (entry == NULL) {
		/*
		 * snapshot of parent dir may not exist if
		 * it is a different mountpoint.
		 */
		if (strcmp(fname_in->base_name, "..") != 0) {
			DBG_ERR("[%s()]: %s: no snapshot found\n",
				location, smb_fname_str_dbg(fname_in));
		} else {
			DBG_INFO("[%s()]: %s: no snapshot found\n",
				 location, smb_fname_str_dbg(fname_in));
		}
		errno = ENOENT;
		return false;
	}

	// shadow connecpath has not been determined yet
	data->shadow_cp[0] = '\0';
	data->sens = sens;
	data->snap->cr_time = entry->cr_time;
	data->snap->nt_time = entry->nt_time;

	strlcpy(data->snap->name, entry->name, sizeof(data->snap->name));
	strlcpy(data->snap->label, entry->label, sizeof(data->snap->label));

	return true;
}

/*
 * Convert a filename containing an @GMT token to a path in the corresponding
 * .zfs/snapshot/<snap_name> directory.
 */
static char *_do_convert_shadow_zfs_name(vfs_handle_struct *handle,
					 const struct smb_filename *fname_in,
					 struct snapshot_data *out,
					 const char *location)
{
	struct shadow_copy_zfs_config *config = NULL;
	struct snapshot_entry snap = {0};
	struct snapshot_data snapshots = (struct snapshot_data) {
		.snap = &snap,
	};
	const char *mpoffset = NULL;
	int offset;
	char *ret = NULL, *res_fname = NULL;
	char buf[PATH_MAX] = {0};
	bool found = false;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct shadow_copy_zfs_config,
				smb_panic(location));

	if (config->ds == NULL) {
		DBG_ERR("[%s()]: Refusing to convert to shadow copy due to "
			"path not supporting snapshots.\n", location);
		errno = EINVAL;
		return NULL;
	}

	resolve_path(handle, config, fname_in->base_name, buf, sizeof(buf), &found);
	if (found) {
		return talloc_strdup(talloc_tos(), buf);
	}

	found = zfs_lookup_snapshot_list(handle, fname_in, buf, &snapshots, location);
	if (!found) {
		DBG_INFO("[%s()]: failed to retrieve snapshot entry for filename: %s, ts: %ld,"
			 "with snapshot mountpoint: %s\n",
			 location, smb_fname_str_dbg(fname_in), fname_in->twrp, snapshots.mountpoint);
		return NULL;
	}

	res_fname = strstr(buf, handle->conn->connectpath);
	SMB_ASSERT(res_fname != NULL);
	res_fname += strlen(handle->conn->connectpath);
	if (*res_fname == '/') {
		res_fname++;
	}

	if (strcmp(handle->conn->connectpath, snapshots.mountpoint) > 0) {
		mpoffset = handle->conn->connectpath + strlen(snapshots.mountpoint) + 1;
	}

	ret = get_snapshot_path(talloc_tos(), handle->conn->connectpath,
				snapshots.mountpoint, res_fname,
				mpoffset, snapshots.snap, snapshots.sens);

	if (out != NULL) {
		size_t off = 0;
		out->snap = talloc_zero(out, struct snapshot_entry);
		if (out->snap == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		cp_snapshot_data(&snapshots, out);

		off = snprintf(out->shadow_cp, sizeof(out->shadow_cp),
			       "%s/%s/%s", snapshots.mountpoint,
			       SHADOW_COPY_ZFS_SNAP_DIR, snapshots.snap->name);
		/*
		 * This mountpoint ends up getting stored as part of CWD
		 * in the chdir() function.
		 */
		if (mpoffset) {
			snprintf(out->shadow_cp + off,
				 sizeof(out->shadow_cp) - off,
			         "/%s", mpoffset);
		}
	}

	return ret;
}

#define do_convert_shadow_zfs_name(handle, fname, data_out)\
	(char *)_do_convert_shadow_zfs_name(handle, fname, data_out, __func__)

#define convert_shadow_zfs_name(handle, fname)\
	(char *)_do_convert_shadow_zfs_name(handle, fname, NULL, __func__)

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
		    handle, smb_fname);

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
		    handle, smb_fname);

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

	if (!shadow_copy_zfs_match_name(handle, fsp->fsp_name)) {
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	vss_smb_fname = *fsp->fsp_name;
	vss_smb_fname.base_name = convert_shadow_zfs_name(handle, fsp->fsp_name);

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
				const struct vfs_open_how *how)
{
	int ret;
	char *conv = NULL;
	struct smb_filename *smb_fname = NULL;
	struct snapshot_data *data = NULL;
	struct shadow_copy_fsp_ext *fsp_ext = NULL;
	struct vfs_open_how tmp_how = { .flags = how->flags, .mode = how->mode};

	smb_fname = full_path_from_dirfsp_atname(talloc_tos(),
						 dirfsp,
						 smb_fname_in);

	if (!shadow_copy_zfs_match_name(handle, smb_fname)) {
		TALLOC_FREE(smb_fname);
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname_in,
					   fsp, how);
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
	conv = do_convert_shadow_zfs_name(handle,
					  smb_fname,
					  data);
	if (conv == NULL) {
		TALLOC_FREE(smb_fname);
		TALLOC_FREE(data);
		return -1;
	}


	smb_fname->base_name = conv;
	tmp_how.flags &= ~(O_WRONLY | O_RDWR | O_CREAT);

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname,
				  fsp, &tmp_how);
	TALLOC_FREE(smb_fname);
	if (ret != -1) {
		fsp_ext = VFS_ADD_FSP_EXTENSION(handle, fsp, struct shadow_copy_fsp_ext, NULL);
		SMB_ASSERT(fsp_ext != NULL);
		fsp_ext->data = talloc_move(VFS_MEMCTX_FSP_EXTENSION(handle, fsp), &data);
		fsp_ext->handle = handle;
		fsp_ext->fsp = fsp;
		fsp_ext->fsp_name_ptr = fsp->fsp_name;
	} else {
		TALLOC_FREE(data);
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
	conv = do_convert_shadow_zfs_name(handle, smb_fname, data);
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
		    handle, smb_fname);
		if (shadow_name == NULL){
			TALLOC_FREE(conv);
			return -1;
		}
		conv->base_name = shadow_name;
		ret = SMB_VFS_NEXT_READLINKAT(handle, dirfsp, conv, buf, bufsiz);
		TALLOC_FREE(conv);
		TALLOC_FREE(shadow_name);
		return ret;
	}
	return SMB_VFS_NEXT_READLINKAT(handle, dirfsp, smb_fname, buf, bufsiz);
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
	struct smb_filename conv_smb_fname;

	if (shadow_copy_zfs_match_name(handle, smb_fname)) {
		conv = convert_shadow_zfs_name(
		    handle, smb_fname);
		if (conv == NULL) {
			errno = ENOENT;
			return NULL;
		}
		conv_smb_fname = (struct smb_filename) {
			.base_name = conv,
			.flags = smb_fname->flags
		};

		ret = SMB_VFS_NEXT_REALPATH(handle, ctx, &conv_smb_fname);
		TALLOC_FREE(conv);
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
	struct shadow_copy_zfs_config *config = NULL;
	struct snapshot_list *snapshots = NULL;
	struct snapshot_entry *entry = NULL;
	SMB_STRUCT_STAT sbuf, prev_st;
	const SMB_STRUCT_STAT *psbuf = NULL;
	uint idx = 0;
	const char *mpoffset = NULL;
	ssize_t len, cpathlen, mplen, flen;
	enum casesensitivity sens;
	int rv;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return -1);

	if (config->ds == NULL) {
		DBG_ERR("No dataset present for share at path: %s\n",
			handle->conn->connectpath);
		return 0;
	}

	cpathlen = strlen(handle->conn->connectpath);

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
					NULL,
					fsp,
					true,
					&snapshots,
					&sens);
	if (snapshots == NULL) {
		DBG_INFO("failed to retrieve snapshots for %s\n", fsp_str_dbg(fsp));
		return -1;
	}

	DBG_INFO("Retrieved %zu snapshots for %s\n",
		 snapshots->num_entries, fsp_str_dbg(fsp));

	if (labels) {
		shadow_copy_zfs_data->labels =
			talloc_array(shadow_copy_zfs_data,
				     SHADOW_COPY_LABEL,
				     snapshots->num_entries);

		if (shadow_copy_zfs_data->labels == NULL) {
			DBG_ERR("shadow_copy_zfs: out of memory\n");
			return -1;
		}
	} else {
		shadow_copy_zfs_data->labels = NULL;
	}

	mplen = strlen(snapshots->mountpoint);
	flen = strlen(fsp->fsp_name->base_name);
	if (cpathlen > mplen) {
		/*
		 * Connectpath for share is longer than the dataset mountpoint.
		 * This happens if share is directory outside of mountpoint, which
		 * most commonly occurs when share is a [homes] share.
		 */
		mpoffset = handle->conn->connectpath + mplen + 1;
	}

	for (entry = snapshots->entries; entry; entry = entry->next) {
		/*
		 * Directories should always be added if they exist in the
		 * snapshot. Files only be added if mtime differs.
		 */
		SMB_STRUCT_STAT cur_st;
		char *tmp_file = NULL;
		tmp_file = get_snapshot_path(handle->conn, handle->conn->connectpath,
					     snapshots->mountpoint,
					     fsp->fsp_name->base_name,
					     mpoffset, entry, sens);

		DBG_INFO("snapshot[%d]: ts: %ld, gmt: %s, name: %s, "
			 "createtxg: %ld, path: %s\n",
			 idx, entry->cr_time, entry->label, entry->name,
			 entry->createtxg, tmp_file);

		rv = sys_stat(tmp_file, &cur_st, false);
		TALLOC_FREE(tmp_file);
		if (rv != 0) {
			DBG_INFO("%s: stat() failed for [%s] in mp [%s] snap [%s]: %s\n",
				 tmp_file, fsp_str_dbg(fsp), snapshots->mountpoint, entry->name,
				 strerror(errno));
			continue;
		}
		if (config->filter->ignore_empty_snaps && !S_ISDIR(cur_st.st_ex_mode) &&
		    (timespec_compare(&cur_st.st_ex_mtime, &prev_st.st_ex_mtime) == 0)) {
			continue;
		}
		if (labels) {
			strlcpy(shadow_copy_zfs_data->labels[idx],
				entry->label, sizeof(SHADOW_COPY_LABEL));
		}
		idx++;
		prev_st = cur_st;
	}

	shadow_copy_zfs_data->num_volumes = idx;
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

static NTSTATUS shadow_copy_zfs_get_real_filename_at(
        struct vfs_handle_struct *handle,
        struct files_struct *dirfsp,
        const char *path,
        TALLOC_CTX *mem_ctx,
        char **found_name)
{
	ssize_t ret;
	char *conv = NULL;
	NTSTATUS status;
	struct smb_filename *conv_fname = NULL;

	if (!shadow_copy_zfs_match_name(handle, dirfsp->fsp_name)) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME_AT(handle, dirfsp, path,
							 mem_ctx, found_name);
	}

	conv = convert_shadow_zfs_name(handle, dirfsp->fsp_name);
	if (conv == NULL) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("%s: convert_shadow_zfs_name() failed: %s\n",
			  fsp_str_dbg(dirfsp), strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	status = synthetic_pathref(
		talloc_tos(),
		dirfsp->conn->cwd_fsp,
		conv,
		NULL,
		NULL,
		0,
		0,
		&conv_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("%s: failed to create synthetic pathref: %s\n",
			conv, nt_errstr(status));
		TALLOC_FREE(conv);
		return status;
	}

	status = get_real_filename_full_scan_at(
		conv_fname->fsp, path, false, mem_ctx, found_name);

	TALLOC_FREE(conv_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Scan [%s] for [%s] failed\n",
			  conv, path);
		TALLOC_FREE(conv);
		return status;
	}

	DBG_DEBUG("Scan [%s] for [%s] returned [%s]\n",
		  conv, path, *found_name);

	TALLOC_FREE(conv);
	return NT_STATUS_OK;
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
		conv = do_convert_shadow_zfs_name(handle, smb_fname, data);
		if (conv == NULL) {
			return handle->conn->connectpath;
		}
		TALLOC_FREE(conv);
		if (data->shadow_cp[0] == '\0') {
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
		conv = convert_shadow_zfs_name(handle, smb_fname);
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
		conv = convert_shadow_zfs_name(handle, smb_fname);
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

static NTSTATUS zfs_parent_pathname(struct vfs_handle_struct *handle,
				    TALLOC_CTX *mem_ctx,
				    const struct smb_filename *smb_fname_in,
				    struct smb_filename **parent_dir_out,
				    struct smb_filename **atname_out)
{
	NTSTATUS status;
	char *tmp_fname = NULL;
	struct smb_filename *fname_ref = NULL;

	status = SMB_VFS_NEXT_PARENT_PATHNAME(
		handle, mem_ctx,
		smb_fname_in, parent_dir_out,
		atname_out
	);

	/*
	 * 34 is a special inode number on ZFS indicating a dataset
	 * mountpoint.
	 */
	if (!NT_STATUS_IS_OK(status) ||
            (smb_fname_in->st.st_ex_ino != 34) ||
	    !shadow_copy_zfs_match_name(handle, smb_fname_in)) {
		return status;
	}

	fname_ref = *parent_dir_out;

	tmp_fname = convert_shadow_zfs_name(handle, fname_ref);
	if (tmp_fname == NULL) {
		if (errno != ENOENT) {
			status = map_nt_error_from_unix(errno);
		}
		fname_ref->twrp = 0;
	} else {
		TALLOC_FREE(tmp_fname);
	}

	return status;
}

static int shadow_copy_zfs_connect(struct vfs_handle_struct *handle,
				const char *service, const char *user)
{
	struct shadow_copy_zfs_config *config = NULL;
	const char **exclusions = NULL;
	const char **inclusions = NULL;
	int ret, saved_errno;
	int memcache_sz;

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

	config->filter = talloc_zero(config, struct snap_filter);
	if (config->filter == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &config->ds,
			    handle->conn->tcon != NULL);

	if (ret != 0) {
		DBG_ERR("Failed to initialize zfs: %s\n", strerror(errno));
		goto disconnect_out;
	}

	inclusions = lp_parm_string_list(SNUM(handle->conn), "shadow",
					 "include", NULL);
	if (inclusions != NULL) {
		config->filter->inclusions = str_list_copy(config, inclusions);
		if (config->filter->inclusions == NULL) {
			DBG_ERR("%s: str_list_copy failed: %s\n",
				service, strerror(errno));
			goto disconnect_out;
		}
	}
	exclusions = lp_parm_string_list(SNUM(handle->conn), "shadow",
					 "exclude", NULL);
	if (exclusions != NULL) {
		config->filter->exclusions = str_list_copy(config, exclusions);
		if (config->filter->exclusions == NULL) {
			DBG_ERR("%s: str_list_copy failed: %s\n",
				service, strerror(errno));
			goto disconnect_out;
		}
	}

	config->filter->ignore_empty_snaps = lp_parm_bool(SNUM(handle->conn), "shadow",
						"ignore_empty_snaps", true);

	config->timedelta = lp_parm_int(SNUM(handle->conn),
					"shadow", "snap_timedelta", 30);

	memcache_sz = lp_parm_int(SNUM(handle->conn),
				  "shadow", "cache_size", 512);

	config->zcache = memcache_init(handle->conn, (memcache_sz * 1024));

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct shadow_copy_zfs_config,
				return -1);

	return 0;

disconnect_out:

	TALLOC_FREE(config);
	saved_errno = errno;
	SMB_VFS_NEXT_DISCONNECT(handle);
	errno = saved_errno;
	return -1;
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
	.get_real_filename_at_fn = shadow_copy_zfs_get_real_filename_at,
	.connectpath_fn = shadow_copy_zfs_connectpath,
	.parent_pathname_fn = zfs_parent_pathname,
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
