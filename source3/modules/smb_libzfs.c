/*
 * Copyright 2021 iXsystems, Inc.
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

#include <talloc.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#ifndef FREEBSD_LIBZFS
#include <mntent.h>
#ifndef mntent
struct mntent
  {
    char *mnt_fsname;           /* Device or server for filesystem.  */
    char *mnt_dir;              /* Directory mounted on.  */
    char *mnt_type;             /* Type of filesystem: ufs, nfs, etc.  */
    char *mnt_opts;             /* Comma-separated options for fs.  */
    int mnt_freq;               /* Dump frequency (in days).  */
    int mnt_passno;             /* Pass number for `fsck'.  */
  };
#endif
#endif /* FREEBSD_LIBZFS */
#include <libzfs/sys/nvpair.h>
#include <libzfs/libzfs.h>
#include <fnmatch.h>
#include "lib/util/time.h"
#include "lib/util/debug.h"
#include "lib/util/discard.h"
#include "lib/util/dlinklist.h"
#include "lib/util/fault.h"
#include "lib/util/memcache.h"
#include "lib/util/memory.h"
#include "lib/util/unix_match.h"
#include "smb_macros.h"
#include "modules/smb_libzfs.h"

#define SHADOW_COPY_ZFS_GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"
#define ZFS_PROP_SAMBA_PREFIX "org.samba"

static struct smblibzfshandle *global_libzfs_handle = NULL;

struct share_dataset_list {
	struct dataset_list *dl;
	char *connectpath;
	struct share_dataset_list *prev, *next;
};

static struct share_dataset_list *shareds = NULL;

static const struct {
	enum casesensitivity sens;
	const char *sens_str;
} sens_enum_list[] = {
	{SMBZFS_SENSITIVE, "sensitive"},
	{SMBZFS_INSENSITIVE, "insensitive"},
	{SMBZFS_MIXED, "mixed"},
};

static const char *user_quota_strings[] =  {
	"userquota",
	"userused",
#ifdef HAVE_ZFS_OBJ_QUOTA
	"userobjquota",
	"userobjused"
#endif
};

static const char *group_quota_strings[] =  {
	"groupquota",
	"groupused",
#ifdef HAVE_ZFS_OBJ_QUOTA
	"groupobjquota",
	"groupobjused"
#endif
};

struct smblibzfs_int {
	libzfs_handle_t *libzfsp;
};

struct smbzhandle_int {
	zfs_handle_t *zhandle;
};

struct iter_info
{
	bool ignore_empty_snaps;
	const char **inclusions;
	const char **exclusions;
	time_t start;
	time_t end;
};

struct snap_cb
{
	struct snapshot_list *snapshots;
	struct iter_info *iter_info;
};

struct child_cb
{
	struct dataset_list *dslist;
	bool open_zhandle;
};

static int smblibzfs_handle_destructor(struct smblibzfs_int *slibzp)
{
	if (slibzp->libzfsp == NULL) {
		DBG_ERR("Failed to retrieve libzfs handle"
			"from smblibzfs handle\n");
		return 0;
	}
	libzfs_fini(slibzp->libzfsp);
	return 0;
}

static int smbzhandle_destructor(struct smbzhandle_int *szhp)
{
	if (szhp->zhandle == NULL) {
		DBG_INFO("Failed to retrieve smb zfs dataset handle"
			"from smbzhandle\n");
		return 0;
	}
	zfs_close(szhp->zhandle);
	return 0;
}

int get_smblibzfs_handle(TALLOC_CTX *mem_ctx,
			 struct smblibzfshandle **smblibzfsp)
{
	libzfs_handle_t *libzfsp = NULL;
	struct smblibzfs_int *slibzp_int = NULL;
	struct smblibzfshandle *slibzp_ext = NULL;
	slibzp_ext = talloc_zero(mem_ctx, struct smblibzfshandle);
	if (slibzp_ext == NULL) {
		errno = ENOMEM;
		return -1;
	}
	slibzp_int = talloc_zero(slibzp_ext, struct smblibzfs_int);
	if (slibzp_int == NULL) {
		errno = ENOMEM;
		return -1;
	}
	libzfsp = libzfs_init();
	if (libzfsp == NULL) {
		DBG_ERR("Failed to init libzfs\n");
		return -1;
	}
	libzfs_print_on_error(libzfsp, B_TRUE);
	slibzp_int->libzfsp = libzfsp;
	talloc_set_destructor(slibzp_int, smblibzfs_handle_destructor);
	slibzp_ext->sli = slibzp_int;
	slibzp_ext->zcache = memcache_init(slibzp_ext, (1024 * 1024));
	*smblibzfsp = slibzp_ext;
	return 0;
}

struct smblibzfshandle *get_global_smblibzfs_handle(TALLOC_CTX *mem_ctx) {
	int ret;

	if (global_libzfs_handle == NULL) {
		ret = get_smblibzfs_handle(mem_ctx, &global_libzfs_handle);
		if (ret != 0) {
			return NULL;
		}
	}
	return global_libzfs_handle;
}

static int existing_parent_name(const char *path, char *buf, size_t buflen, int *nslashes);

static zfs_handle_t *get_zhandle(struct smblibzfshandle *smblibzfsp,
				 const char *path, bool resolve)
{
	/* "path" here can be either mountpoint or dataset name */
	zfs_handle_t *zfsp = NULL;

	if (smblibzfsp->sli == NULL) {
		DBG_ERR("Failed to retrieve smblibzfs_int handle\n");
		return zfsp;
	}

	if (path == NULL) {
		DBG_ERR("No pathname provided\n");
		return zfsp;
	}

	zfsp = zfs_path_to_zhandle(smblibzfsp->sli->libzfsp, discard_const(path),
				   ZFS_TYPE_FILESYSTEM);

	if (zfsp == NULL) {
		if (resolve && errno == ENOENT) {
			int rv, to_create;
			char parent[ZFS_MAXPROPLEN] = {0};
			rv = existing_parent_name(path, parent, sizeof(parent), &to_create);
			if (rv != 0) {
				DBG_ERR("Unable to access parent of %s\n", path);
				errno = ENOENT;
				return NULL;
			}
			DBG_INFO("Path [%s] does not exist, optaining zfs dataset handle from "
				 "path [%s]\n", path, parent);
			zfsp = zfs_path_to_zhandle(smblibzfsp->sli->libzfsp, parent,
						   ZFS_TYPE_FILESYSTEM);
			if (zfsp == NULL) {
				DBG_ERR("Failed to obtain zhandle on path: (%s)\n",
					parent);
			}
			return zfsp;
		}
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n",
			path);
	}
	return zfsp;
}

static zfs_handle_t *get_zhandle_from_smbzhandle(struct smbzhandle *smbzhandle)
{
	SMB_ASSERT(smbzhandle->is_open);
	return smbzhandle->zhp->zhandle;
}

int get_smbzhandle(struct smblibzfshandle *smblibzfsp,
		   TALLOC_CTX *mem_ctx, const char *path,
		   struct smbzhandle **smbzhandle,
		   bool resolve)
{
	zfs_handle_t *zfsp = NULL;
	struct smbzhandle_int *szhandle_int = NULL;
	struct smbzhandle *szhandle_ext = NULL;
	zfsp = get_zhandle(smblibzfsp, path, resolve);

	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: [%s]: %s\n",
			path, strerror(errno));
		return -1;
	}
	szhandle_int = talloc_zero(mem_ctx, struct smbzhandle_int);
	if (szhandle_int == NULL) {
		errno = ENOMEM;
		return -1;
	}
	szhandle_ext = talloc_zero(mem_ctx, struct smbzhandle);
	if (szhandle_ext == NULL) {
		errno = ENOMEM;
		return -1;
	}
	szhandle_int->zhandle = zfsp;
	szhandle_ext->is_open = true;
	szhandle_ext->zhp = szhandle_int;
	szhandle_ext->lz = smblibzfsp;
	*smbzhandle = szhandle_ext;
	return 0;
}

void close_smbzhandle(struct smbzhandle *zfsp_ext)
{
	if (!zfsp_ext->is_open) {
		return;
	}
	zfs_handle_t *zfsp_int = NULL;
	zfsp_int = get_zhandle_from_smbzhandle(zfsp_ext);
	if (!zfsp_int) {
		DBG_ERR("failed to get zhandle\n");
		zfsp_ext->is_open = false;
		return;
	}
	zfs_close(zfsp_int);
	zfsp_int = NULL;
	zfsp_ext->is_open = false;
	return;
}

int
smb_zfs_get_quota(struct smbzhandle *hdl,
		  uint64_t xid,
		  enum zfs_quotatype quota_type,
		  struct zfs_quota *qt)
{
	int i;
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	char req[ZFS_MAXPROPLEN] = { 0 };
	uint64_t rv[4] = { 0 };

	zfsp = get_zhandle_from_smbzhandle(hdl);
	if (zfsp == NULL) {
		return -1;
	}

	switch (quota_type) {
	case SMBZFS_USER_QUOTA:
		for (i = 0; i < ARRAY_SIZE(user_quota_strings); i++) {
			snprintf(req, sizeof(req), "%s@%lu",
				 user_quota_strings[i], xid);
			zfs_prop_get_userquota_int(zfsp, req, &rv[i]);
		}
		break;
	case SMBZFS_GROUP_QUOTA:
		for (i = 0; i < ARRAY_SIZE(group_quota_strings); i++) {
			snprintf(req, sizeof(req), "%s@%lu",
				 group_quota_strings[i], xid);
			zfs_prop_get_userquota_int(zfsp, req, &rv[i]);
		}
		break;
	case SMBZFS_DATASET_QUOTA:
		errno = EINVAL;
		DBG_ERR("Retrieving dataset quotas is not yet supported\n");
		return -1;
	default:
		DBG_ERR("Received unknown quota type (%d)\n", quota_type);
		return (-1);
	}

	qt->bytes = rv[0] / blocksize;
	qt->bytes_used = rv[1] / blocksize;
	qt->obj = rv[2];
	qt->obj_used = rv[3];
	qt->quota_type = quota_type;
	return 0;
}

int
smb_zfs_set_quota(struct smbzhandle *hdl, uint64_t xid, struct zfs_quota qt)
{
	int rv;
	zfs_handle_t *zfsp = NULL;
	char qr[ZFS_MAXPROPLEN] = { 0 };
#ifdef HAVE_ZFS_OBJ_QUOTA
	char qr_obj[ZFS_MAXPROPLEN] = { 0 };
#endif
	char quota[ZFS_MAXPROPLEN] = { 0 };

	if (xid == 0) {
		DBG_ERR("Setting quota on id 0 is not permitted\n");
		errno = EPERM;
		return -1;
	}

	zfsp = get_zhandle_from_smbzhandle(hdl);
	if (zfsp == NULL){
		DBG_ERR("Failed to retrieve ZFS dataset handle\n");
		return -1;
	}

	switch (qt.quota_type) {
	case SMBZFS_USER_QUOTA:
		snprintf(qr, sizeof(qr), "userquota@%lu", xid);
#ifdef HAVE_ZFS_OBJ_QUOTA
		snprintf(qr_obj, sizeof(qr_obj), "userobj@%lu", xid);
#endif
		break;
	case SMBZFS_GROUP_QUOTA:
		snprintf(qr, sizeof(qr), "groupquota@%lu", xid);
#ifdef HAVE_ZFS_OBJ_QUOTA
		snprintf(qr_obj, sizeof(qr_obj), "groupobj@%lu", xid);
#endif
		break;
	case SMBZFS_DATASET_QUOTA:
		errno = EINVAL;
		DBG_ERR("Setting dataset quotas is not yet supported\n");
		return -1;
	default:
		DBG_ERR("Received unknown quota type (%d)\n", qt.quota_type);
		return -1;
	}

	snprintf(quota, sizeof(quota), "%lu", qt.bytes);
	rv = zfs_prop_set(zfsp, qr, quota);
	if (rv != 0) {
		DBG_ERR("Failed to set (%s = %s)\n", qr, quota);
		return -1;
	}
#ifdef HAVE_ZFS_OBJ_QUOTA
	snprintf(quota, sizeof(quota), "%lu", qt.obj);
	rv = zfs_prop_set(zfsp, qr_obj, quota);
	if (rv != 0) {
		DBG_ERR("Failed to set (%s = %s)\n", qr_obj, quota);
		return -1;
	}
#endif
	return 0;
}

uint64_t
smb_zfs_disk_free(struct smbzhandle *hdl,
		  uint64_t *bsize, uint64_t *dfree,
		  uint64_t *dsize)
{
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	uint64_t available, usedbysnapshots, usedbydataset,
		usedbychildren, real_used, total;

	zfsp = get_zhandle_from_smbzhandle(hdl);
	if (zfsp == NULL) {
		return (-1);
	}

	available = zfs_prop_get_int(zfsp, ZFS_PROP_AVAILABLE);
	usedbysnapshots = zfs_prop_get_int(zfsp, ZFS_PROP_USEDSNAP);
	usedbydataset = zfs_prop_get_int(zfsp, ZFS_PROP_USEDDS);
	usedbychildren = zfs_prop_get_int(zfsp, ZFS_PROP_USEDCHILD);

	real_used = usedbysnapshots + usedbydataset + usedbychildren;

	total = (real_used + available) / blocksize;
	available /= blocksize;

	*bsize = blocksize;
	*dfree = available;
	*dsize = total;

	return (*dfree);
}

static int
existing_parent_name(const char *path,
		     char *buf,
		     size_t buflen,
		     int *nslashes)
{
	char *slashp = NULL;
	*nslashes = 0;
	strlcpy(buf, path, buflen);
	for (;;) {
		slashp = strrchr(buf, '/');
		if (slashp == NULL) {
			return -1;
		}
		*nslashes += 1;
		*slashp = '\0';
		if (access(buf, F_OK) == 0) {
			break;
		}
	}
	return 0;
}

static int
get_mp_offset(zfs_handle_t *zfsp, size_t *offset)
{
	int rv;
	char parent_mp[ZFS_MAXPROPLEN] = {0};
	const char *parent_dsname = NULL;

	parent_dsname = zfs_get_name(zfsp);
	rv = zfs_prop_get(zfsp, ZFS_PROP_MOUNTPOINT, parent_mp,
			  sizeof(parent_mp), NULL, NULL,
			  0, 0);
	if (rv != 0) {
		DBG_ERR("Failed to get mountpoint for %s: %s\n",
			parent_dsname, strerror(errno));
		return -1;
	}
	*offset = strlen(parent_mp) - strlen(parent_dsname);
	return rv;
}

static char *
get_target_name(TALLOC_CTX *mem_ctx, zfs_handle_t *zfsp, const char *path)
{
	int rv;
	size_t len_mp;
	char *out = NULL;
	rv = get_mp_offset(zfsp, &len_mp);
	out = talloc_strdup(mem_ctx, path);
	if (out == NULL) {
		DBG_ERR("strdup failed for %s: %s\n",
			path, strerror(errno));
		errno = ENOMEM;
		return out;
	}
	if (strlen(path) < len_mp) {
		errno = EINVAL;
		TALLOC_FREE(out);
		return NULL;
	}
	out += len_mp;
	return out;
}

static int
create_dataset_internal(struct smblibzfshandle *lz,
			char *to_create,
			const char *quota)
{
	/* Create and mount new dataset. to_create should be dataset name */
	int rv;
	zfs_handle_t *new = NULL;

	rv = zfs_create(lz->sli->libzfsp, to_create, ZFS_TYPE_FILESYSTEM, NULL);
	if (rv != 0) {
		DBG_ERR("Failed to create dataset [%s]: %s\n",
			to_create, strerror(errno));
		return -1;
	}
	new = zfs_open(lz->sli->libzfsp, to_create, ZFS_TYPE_FILESYSTEM);
	if (new == NULL) {
		DBG_ERR("Failed to open dataset [%s]: %s\n",
			to_create, strerror(errno));
		return -1;
	}
	rv = zfs_mount(new, NULL, 0);
	if (rv != 0) {
		DBG_ERR("Failed to mount dataset [%s] after dataset "
			"creation: %s\n", to_create, strerror(errno));
		goto failure;
	}
	if (quota != NULL) {
		rv = zfs_prop_set(new, "quota", quota);
		if (rv != 0) {
			DBG_ERR("Failed to set quota to (%s): %s\n",
				quota, strerror(errno));
		}
	}
failure:
	zfs_close(new);
	return rv;
}

struct dataset_list *path_to_dataset_list(TALLOC_CTX *mem_ctx,
					  struct smblibzfshandle *lz,
					  const char *path,
					  int depth)
{
	char *slashp = NULL;
	struct dataset_list *dl = NULL;
	struct zfs_dataset *ds = NULL;
	struct zfs_dataset *root = NULL;
	char tmp_path[ZFS_MAXPROPLEN] = {0};
	int rv;

	strlcpy(tmp_path, path, sizeof(tmp_path));
	dl = talloc_zero(mem_ctx, struct dataset_list);
	if (dl == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	ds = smb_zfs_path_get_dataset(lz, dl, path, true, false, false);
	if (ds == NULL) {
		TALLOC_FREE(dl);
		return NULL;
	}

	if (tmp_path[strlen(tmp_path) -1] == '/') {
		tmp_path[strlen(tmp_path) -1] = '\0';
	}

	DLIST_ADD(dl->children, ds);
	dl->nentries = 1;

	for (; dl->nentries <= depth; dl->nentries++) {
		slashp = strrchr(tmp_path, '/');
		if (slashp == NULL) {
			DBG_ERR("Exiting at depth %zu\n",
				 dl->nentries);
			break;
		}
		*slashp = '\0';
		ds = smb_zfs_path_get_dataset(lz, dl, tmp_path,
					      true, false, false);
		if (ds == NULL) {
			TALLOC_FREE(dl);
			return NULL;
		}
		DLIST_ADD_END(dl->children, ds);
	}
	root = DLIST_TAIL(dl->children);
	DLIST_REMOVE(dl->children, root);
	dl->nentries--;
	dl->root = root;
	return dl;
}

int
smb_zfs_create_dataset(TALLOC_CTX *mem_ctx,
		       struct smblibzfshandle *smblibzfsp,
		       const char *path, const char *quota,
		       struct dataset_list **created,
		       bool create_ancestors)
{
	int rv, to_create;
	zfs_handle_t *zfsp = NULL;
	char parent[ZFS_MAXPROPLEN] = {0};
	char *target_ds = NULL;
	struct dataset_list *ds_list = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (access(path, F_OK) == 0) {
		DBG_ERR("Path %s already exists.\n", path);
		errno = EEXIST;
		goto fail;
	}

	if (smblibzfsp->sli == NULL) {
		DBG_ERR("Failed to retrieve smblibzfs_int handle\n");
		errno = ENOMEM;
		goto fail;
	}

	rv = existing_parent_name(path, parent, sizeof(parent), &to_create);
	if (rv != 0) {
		DBG_ERR("Unable to access parent of %s\n", path);
		errno = ENOENT;
		goto fail;
	}
	/*
	 * This zfs dataset handle allows us to figure out the
	 * name that our new dataset should have by looking at
	 * dataset properties of parent dataset.
	 */
	zfsp = zfs_path_to_zhandle(smblibzfsp->sli->libzfsp, parent,
				   ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on %s: %s\n",
			parent, strerror(errno));
		goto fail;
	}

	target_ds = get_target_name(tmp_ctx, zfsp, path);
	if (target_ds == NULL) {
		zfs_close(zfsp);
		goto fail;
	}
	zfs_close(zfsp);

	if (to_create > 1 && create_ancestors) {
		rv = zfs_create_ancestors(smblibzfsp->sli->libzfsp, target_ds);
		if (rv != 0 ) {
			goto fail;
		}
	}
	else if (to_create > 1) {
		DBG_ERR("Unable to create dataset [%s] due to "
			"missing ancestor datasets.", target_ds);
		errno = ENOENT;
		goto fail;
	}

	rv = create_dataset_internal(smblibzfsp, target_ds, quota);
	if (rv != 0) {
		goto fail;
	}

	ds_list = path_to_dataset_list(mem_ctx, smblibzfsp, path, to_create);
	if (ds_list == NULL) {
		DBG_ERR("Failed to generate dataset list for %s\n",
			path);
		goto fail;
	}
	*created = ds_list;
	TALLOC_FREE(tmp_ctx);
	return 0;
fail:
	TALLOC_FREE(tmp_ctx);
	return -1;
}

int
smb_zfs_get_user_prop(struct smbzhandle *hdl,
		      TALLOC_CTX *mem_ctx,
		      const char *prop,
		      char **value)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	nvlist_t *userprops = NULL;
	nvlist_t *propval = NULL;
	char *propstr = NULL;
	char *prefixed_prop = NULL;

	zfsp = get_zhandle_from_smbzhandle(hdl);
	if (zfsp == NULL) {
		return -1;
	}
	userprops = zfs_get_user_props(zfsp);
	prefixed_prop = talloc_asprintf(mem_ctx, "%s:%s",
					ZFS_PROP_SAMBA_PREFIX,
					prop);
	ret = nvlist_lookup_nvlist(userprops, prefixed_prop, &propval);
	if (ret != 0) {
		DBG_INFO("Failed to look up custom user property %s on dataset [%s]: %s\n",
			 prop, zfs_get_name(zfsp), strerror(errno));
		return -1;
	}
	ret = nvlist_lookup_string(propval, ZPROP_VALUE, &propstr);
	TALLOC_FREE(prefixed_prop);
	if (ret != 0) {
		DBG_ERR("Failed to get nvlist string for property %s\n",
			prop);
		return -1;
	}
	*value = talloc_strdup(mem_ctx, propstr);
	return 0;
}

int
smb_zfs_set_user_prop(struct smbzhandle *hdl,
		      const char *prop,
		      const char *value)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	char prefixed_prop[ZFS_MAXPROPLEN] = {0};

	zfsp = get_zhandle_from_smbzhandle(hdl);
	if (zfsp == NULL) {
		return -1;
	}

	ret = snprintf(prefixed_prop, sizeof(prefixed_prop), "%s:%s",
		       ZFS_PROP_SAMBA_PREFIX, prop);
	if (ret < 0) {
		DBG_ERR("Failed to generate property name: %s",
			strerror(errno));
		return -1;
	}

	ret = zfs_prop_set(zfsp, prefixed_prop, value);
	if (ret != 0) {
		DBG_ERR("Failed to set property [%s] on dataset [%s] to [%s]\n",
			prefixed_prop, zfs_get_name(zfsp), value);
	}
	return ret;
}

static int
zhandle_get_props(struct smbzhandle *zfsp_ext,
		  TALLOC_CTX *mem_ctx,
		  struct zfs_dataset_prop **pprop)
{
	int ret, i;
	char buf[ZFS_MAXPROPLEN];
	char source[ZFS_MAX_DATASET_NAME_LEN];
	zprop_source_t sourcetype;
	zfs_handle_t *zfsp = NULL;
	struct zfs_dataset_prop *props = NULL;
	props = *pprop;

	zfsp = get_zhandle_from_smbzhandle(zfsp_ext);
	if (zfsp == NULL) {
		return -1;
	}
	if (zfs_prop_get(zfsp, ZFS_PROP_CASE,
	    buf, sizeof(buf), &sourcetype,
	    source, sizeof(source), B_FALSE) != 0) {
		DBG_ERR("Failed to look up casesensitivity property\n");
		return -1;
	}
	for (i = 0; i < ARRAY_SIZE(sens_enum_list); i++) {
		if (strcmp(buf, sens_enum_list[i].sens_str) == 0) {
			props->casesens = sens_enum_list[i].sens;
		}
	}
	props->readonly = zfs_prop_get_int(zfsp, ZFS_PROP_READONLY);
#if 0 /* properties we may wish to return in the future */
	props->exec = zfs_prop_get_int(zfsp, ZFS_PROP_EXEC);
	props->atime = zfs_prop_get_int(zfsp, ZFS_PROP_ATIME);
	props->setuid = zfs_prop_get_int(zfsp, ZFS_PROP_SETUID);
#endif
	return 0;
}

struct zfs_dataset *zhandle_get_dataset(struct smbzhandle *zfsp_ext,
					TALLOC_CTX *mem_ctx,
					bool get_props)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	struct zfs_dataset *dsout = NULL;
	struct stat ds_st;
	zfsp = get_zhandle_from_smbzhandle(zfsp_ext);
	if (zfsp == NULL) {
		return NULL;
	}
	dsout = talloc_zero(mem_ctx, struct zfs_dataset);
	if (dsout == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	dsout->mountpoint = talloc_zero_size(dsout, PATH_MAX);
	if (dsout->mountpoint == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	dsout->zhandle = zfsp_ext;
	dsout->dataset_name = talloc_strdup(dsout, zfs_get_name(zfsp));
	ret = zfs_prop_get(zfsp, ZFS_PROP_MOUNTPOINT, dsout->mountpoint,
			   talloc_get_size(dsout->mountpoint), NULL, NULL,
			   0, 0);
	if (ret != 0) {
		DBG_ERR("Failed to get mountpoint for %s: %s\n",
			dsout->dataset_name, strerror(errno));
		TALLOC_FREE(dsout);
		dsout = NULL;
	}
	if (get_props) {
		dsout->properties = talloc_zero(dsout, struct zfs_dataset_prop);
		if (dsout->properties == NULL) {
			errno = ENOMEM;
			return NULL;
		}
		ret = zhandle_get_props(zfsp_ext, mem_ctx, &dsout->properties);
		if (ret != 0) {
			DBG_ERR("Failed to get properties for dataset\n");
			dsout = NULL;
		}
	}
	ret = stat(dsout->mountpoint, &ds_st);
	if (ret < 0) {
		DBG_ERR("Failed to stat dataset mounpoint [%s] "
			"for dataset [%s]: %s\n",
			dsout->mountpoint, dsout->dataset_name,
			strerror(errno));
		return NULL;
	}
	dsout->devid = ds_st.st_dev;
	return dsout;
}

struct zfs_dataset *smb_zfs_path_get_dataset(struct smblibzfshandle *smblibzfsp,
					     TALLOC_CTX *mem_ctx,
					     const char *path,
					     bool get_props,
					     bool open_zhandle,
					     bool resolve_path)
{
	int ret;
	struct zfs_dataset *dsout = NULL;
	struct smbzhandle *zfs_ext = NULL;
	ret = get_smbzhandle(smblibzfsp, mem_ctx, path, &zfs_ext, resolve_path);
	if (ret != 0) {
		DBG_ERR("Failed to get zhandle\n");
		return NULL;
	}
	dsout = zhandle_get_dataset(zfs_ext, mem_ctx, get_props);
	if (dsout == NULL) {
		return dsout;
	}
	if (!open_zhandle) {
		close_smbzhandle(dsout->zhandle);
	}
	return dsout;
}

static bool
shadow_copy_zfs_is_snapshot_included(struct iter_info *info,
    const char *snap_name)
{
	const char **pattern;

	pattern = info->inclusions;
	while (*pattern) {
		if (unix_wild_match(*pattern, snap_name)) {
			break;
		}
		pattern++;
	}

	if (*info->inclusions && !*pattern) {
		DBG_INFO("smb_zfs_add_snapshot: snapshot %s "
			    "not in inclusion list\n", snap_name);
		return false;
	}

	pattern = info->exclusions;
	while (*pattern) {
		if (unix_wild_match(*pattern, snap_name)) {
			DBG_INFO("smb_zfs_add_snapshot: snapshot %s "
				    "in exclusion list\n", snap_name);
			return false;
		}
		pattern++;
	}

	return true;
}

static int
smb_zfs_add_snapshot(zfs_handle_t *snap, void *data)
{
	struct snap_cb *state = NULL;
	struct snapshot_entry *entry = NULL;
	const char *snap_name;
	time_t cr_time;
	struct tm timestamp;
	int rc, used;
	size_t req_mem, name_len;
	bool included;

	state = talloc_get_type_abort(data, struct snap_cb);
	if (state == NULL) {
		DBG_ERR("failed to get snap_cb private data\n");
		zfs_close(snap);
		errno = ENOMEM;
		return -1;
	}

	/* ignore excluded snapshots */
	snap_name = strchr(zfs_get_name(snap), '@') + 1;

	included = shadow_copy_zfs_is_snapshot_included(state->iter_info,
							snap_name);
	if (!included) {
		goto done;
	}

	/* ignore snapshots with zero bytes written */
	used = zfs_prop_get_int(snap, ZFS_PROP_WRITTEN);
	if (used == 0 && !state->iter_info->ignore_empty_snaps) {
		goto done;
	}

	/* ignore snapshots outside the specified time range */
	cr_time = zfs_prop_get_int(snap, ZFS_PROP_CREATION);
	if (state->iter_info->start && state->iter_info->start > cr_time) {
		goto done;
	}
	if (state->iter_info->end && state->iter_info->end < cr_time) {
		goto done;
	}

	entry = talloc_zero(state->snapshots, struct snapshot_entry);
	if (entry == NULL) {
		errno = ENOMEM;
		return -1;
	}

	name_len = strlen(snap_name);
	gmtime_r(&cr_time, &timestamp);
	strftime(entry->label, sizeof(entry->label), SHADOW_COPY_ZFS_GMT_FORMAT,
		 &timestamp);

	entry->cr_time = cr_time;
	unix_to_nt_time(&entry->nt_time, cr_time);
	entry->name = talloc_strndup(entry, snap_name, name_len +1);

	DLIST_ADD(state->snapshots->entries, entry);
	state->snapshots->num_entries++;
done:
	zfs_close(snap);
	return 0;
}

struct
snapshot_list *zhandle_list_snapshots(struct smbzhandle *zhandle_ext,
				      TALLOC_CTX *mem_ctx,
				      bool ignore_empty_snaps,
				      const char **inclusions,
				      const char **exclusions,
				      time_t start,
				      time_t end)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct snap_cb *state = NULL;
	struct snapshot_list *snapshots = NULL;
	struct iter_info iter_info;
	size_t initial_size;
	int rc;
	zfs_handle_t *zfs = NULL;

	zfs = get_zhandle_from_smbzhandle(zhandle_ext);
	if (!zfs) {
		return NULL;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		DBG_ERR("talloc() failed\n");
		return NULL;
	}

	state = talloc_zero(tmp_ctx, struct snap_cb);
	if (state == NULL) {
		DBG_ERR("smb_zfs_list_snapshots: out of memory");
		goto done;
	}

	snapshots = talloc_zero(mem_ctx, struct snapshot_list);
	if (snapshots == NULL) {
		DBG_ERR("talloc() failed\n");
		goto done;
	}

	snapshots->mountpoint = talloc_zero_size(snapshots, MAXPATHLEN);
	if (snapshots->mountpoint == NULL) {
		DBG_ERR("talloc() failed\n");
		goto error;
	}

	state->iter_info = talloc_zero(tmp_ctx, struct iter_info);
	if (state->iter_info == NULL) {
		DBG_ERR("talloc() failed\n");
		goto error;
	}

	state->snapshots = snapshots;

	/* get mountpoint */
	snapshots->dataset_name = talloc_strdup(snapshots, zfs_get_name(zfs));

	rc = zfs_prop_get(zfs, ZFS_PROP_MOUNTPOINT, snapshots->mountpoint,
			  talloc_get_size(snapshots->mountpoint), NULL, NULL,
			  0, 0);

	if (rc != 0) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"mountpoint for '%s': %s\n",
			snapshots->dataset_name,
			strerror(errno));
		goto error;
	}

	state->iter_info->inclusions = inclusions;
	state->iter_info->exclusions = exclusions;
	state->iter_info->ignore_empty_snaps = ignore_empty_snaps;
	state->iter_info->start = start;
	state->iter_info->end = end;

	if (state->iter_info->inclusions == NULL) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"shadow:include parameter\n");
		goto error;
	}

	if (state->iter_info->exclusions == NULL) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"shadow:exclude parameter\n");
		goto error;
	}

	rc = zfs_iter_snapshots_sorted(zfs, smb_zfs_add_snapshot, state, 0, 0);
	if (rc != 0) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"snapshots for '%s': %s\n",
			snapshots->dataset_name, strerror(errno));
		goto error;
	}

	time(&snapshots->timestamp);
	state->snapshots = NULL;
	goto done;

error:
	TALLOC_FREE(tmp_ctx);
	TALLOC_FREE(snapshots);
	return NULL;
done:
	TALLOC_FREE(tmp_ctx);
	return snapshots;
}

struct
snapshot_list *smb_zfs_list_snapshots(struct smblibzfshandle *smblibzfsp,
				      TALLOC_CTX *mem_ctx,
				      const char *path,
				      bool ignore_empty_snaps,
				      const char **inclusions,
				      const char **exclusions,
				      time_t start,
				      time_t end)
{
	int ret;
	struct smbzhandle *zfs_ext = NULL;
	struct snapshot_list *out = NULL;
	ret = get_smbzhandle(smblibzfsp, mem_ctx, path, &zfs_ext, false);
	if (ret != 0) {
		DBG_ERR("Failed to get zhandle\n");
		return NULL;
	}
	out = zhandle_list_snapshots(zfs_ext, mem_ctx,
				     ignore_empty_snaps,
				     inclusions,
				     exclusions,
				     start,
				     end);
	close_smbzhandle(zfs_ext);
	return out;
}

/*
 * Convert linked list to nvlist and perform delete in single
 * consolidated ioctl.
 */
int
smb_zfs_delete_snapshots(struct smblibzfshandle *smblibzfsp,
			 TALLOC_CTX *mem_ctx,
			 struct snapshot_list *snaps)
{
	int ret;
	nvlist_t *to_delete = NULL;
	struct smblibzfs_int *slibzp_int = NULL;
	struct snapshot_entry *entry = NULL;
	char *snapname = NULL;
	if (smblibzfsp->sli == NULL) {
		errno=ENOMEM;
		DBG_ERR("Unable to re-use libzfs handle\n");
		return -1;
	}
	ret = nvlist_alloc(&to_delete, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		DBG_ERR("Failed to initialize nvlist for snaps.\n");
		errno=ENOMEM;
		return -1;
	}
	for (entry = snaps->entries; entry; entry = entry->next) {
		snapname = talloc_asprintf(mem_ctx,
					   "%s@%s",
					   snaps->dataset_name,
					   entry->name);
		DBG_INFO("deleting snapshot: %s\n", snapname);
		fnvlist_add_boolean(to_delete, snapname);
		TALLOC_FREE(snapname);
	}
	ret = zfs_destroy_snaps_nvl(smblibzfsp->sli->libzfsp,
				    to_delete,
				    B_TRUE);
	if (ret !=0) {
		DBG_ERR("Failed to delete snapshots\n");
		return ret;
	}
	return 0;
}

int
smb_zfs_snapshot(struct smbzhandle *hdl,
		 const char *snapshot_name,
		 bool recursive)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	char snap[ZFS_MAXPROPLEN] = {0};
	const char *dataset_name;

	zfsp = get_zhandle_from_smbzhandle(hdl);
	if (zfsp == NULL) {
		return -1;
	}
	dataset_name = zfs_get_name(zfsp);
	zfs_close(zfsp);
	ret = snprintf(snap, sizeof(snap), "%s@%s",
		       dataset_name, snapshot_name);
	if (ret < 0) {
		DBG_ERR("Failed to format snapshot name:%s\n",
			strerror(errno));
		return -1;
	}
	ret = zfs_snapshot(hdl->lz->sli->libzfsp,
			   snap, recursive, NULL);
	if (ret != 0) {
		DBG_ERR("Failed to create snapshot %s: [%s]\n",
			snap, strerror(errno));
	}
	DBG_INFO("Successfully created snapshot: %s\n", snap);
	return ret;
}

/*
 * Roll back to specified snapshot
 */
int
smb_zfs_rollback(struct smbzhandle *hdl,
		 const char *snapshot_name,
		 bool force)
{
	int ret;
	zfs_handle_t *dataset_handle = NULL;
	zfs_handle_t *snap_handle = NULL;

	dataset_handle = get_zhandle_from_smbzhandle(hdl);
	if (dataset_handle == NULL) {
		return -1;
	}

	snap_handle = zfs_open(hdl->lz->sli->libzfsp,
			       snapshot_name,
			       ZFS_TYPE_DATASET);
	if (snap_handle == NULL) {
		DBG_ERR("Failed to obtain zhandle for snap: (%s)\n",
			snapshot_name);
		zfs_close(dataset_handle);
		return -1;
	}
	ret = zfs_rollback(dataset_handle, snap_handle, force);
	if (ret != 0) {
		DBG_ERR("Failed to roll back %s to snapshot %s\n",
			zfs_get_name(dataset_handle), snapshot_name);
	}
	zfs_close(snap_handle);
	return ret;
}

/*
 * Roll back to last snapshot
 */
int
smb_zfs_rollback_last(struct smbzhandle *hdl)
{
	int ret;
	zfs_handle_t *dataset_handle = NULL;
	const char *dataset_name;

	dataset_handle = get_zhandle_from_smbzhandle(hdl);
	if (dataset_handle == NULL) {
		return -1;
	}
	dataset_name = zfs_get_name(dataset_handle);

	ret = lzc_rollback(dataset_name, NULL, 0);
	if (ret != 0) {
		DBG_ERR("Failed to roll back snapshot on %s\n",
			zfs_get_name(dataset_handle));
	}
	return ret;
}

static int
smb_zfs_add_child(zfs_handle_t *child, void *data)
{
	int ret;
	struct child_cb *state = NULL;
	struct smbzhandle *zhandle_ext = NULL;
	struct smbzhandle_int *zhandle_int = NULL;
	struct zfs_dataset *ds_new = NULL;
	if (zfs_get_type(child) != ZFS_TYPE_FILESYSTEM) {
		return 0;
	}
	if (!zfs_is_mounted(child, NULL)) {
		DBG_INFO("Dataset [%s] is not mounted\n",
			 zfs_get_name(child));
		return 0;
	}
	state = talloc_get_type_abort(data, struct child_cb);
	if (state == NULL) {
		DBG_ERR("failed to get child_cb private data\n");
		zfs_close(child);
		errno = ENOMEM;
		return -1;
	}
	zhandle_ext = talloc_zero(state->dslist, struct smbzhandle);
	if (zhandle_ext == NULL) {
		errno = ENOMEM;
		return -1;
	}
	zhandle_int = talloc_zero(zhandle_ext, struct smbzhandle_int);
	if (zhandle_int == NULL) {
		errno = ENOMEM;
		return -1;
	}
	zhandle_ext->zhp = zhandle_int;
	zhandle_ext->is_open = true;
	zhandle_int->zhandle = child;
	ds_new = zhandle_get_dataset(zhandle_ext, state->dslist, true);
	if (ds_new == NULL) {
		close_smbzhandle(zhandle_ext);
		TALLOC_FREE(zhandle_ext);
		return 0;
	}
	DLIST_ADD(state->dslist->children, ds_new);
	state->dslist->nentries++;
	if (!state->open_zhandle) {
		close_smbzhandle(ds_new->zhandle);
	}
	return 0;
}

struct dataset_list *zhandle_list_children(TALLOC_CTX *mem_ctx,
					  struct smbzhandle *zhandle_ext,
					  bool open_zhandles)
{
	int ret ;
	TALLOC_CTX *tmp_ctx = NULL;
	struct dataset_list *dl = NULL;
	char *ds_name = NULL;
	struct child_cb *state = NULL;
	struct zfs_dataset *ds = NULL;
	zfs_handle_t *zfsp = NULL;

	zfsp = get_zhandle_from_smbzhandle(zhandle_ext);
	if (zfsp == NULL) {
		return NULL;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		DBG_ERR("talloc() failed\n");
		errno = ENOMEM;
		return NULL;
	}

	state = talloc_zero(tmp_ctx, struct child_cb);
	if (state == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	state->open_zhandle = open_zhandles;
	dl = talloc_zero(mem_ctx, struct dataset_list);
	if (dl == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	state->dslist = dl;
	dl->root = zhandle_get_dataset(zhandle_ext, mem_ctx, true);
	if (dl->root == NULL) {
		DBG_ERR("Failed to get dataset information for root "
			"of dataset list\n");
		TALLOC_FREE(tmp_ctx);
		TALLOC_FREE(dl);
		return NULL;
	}
	ret = zfs_iter_filesystems(zfsp, smb_zfs_add_child, state);
	if (ret < 0) {
		TALLOC_FREE(dl);
		return NULL;
	}
	TALLOC_FREE(tmp_ctx);
	return dl;
}

static struct dataset_list *share_lookup_dataset_list(const char *connectpath)
{
	struct dataset_list *out = NULL;
	struct share_dataset_list *to_check = NULL;
	if (shareds == NULL) {
		return out;
	}
	for (to_check=shareds; to_check; to_check = to_check->next) {
		if (strcmp(connectpath, to_check->connectpath) == 0) {
			out = to_check->dl;
			break;
		}
	}
	return out;
}

static int put_share_dataset_list(TALLOC_CTX *mem_ctx, const char *connectpath,
				  struct dataset_list *dl)
{
	struct share_dataset_list *new_shareds= NULL;
	new_shareds = talloc_zero(mem_ctx, struct share_dataset_list);
	if (new_shareds == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_shareds->dl = dl;
	new_shareds->connectpath = talloc_strdup(mem_ctx, connectpath);
	if (new_shareds->connectpath == NULL) {
		errno = ENOMEM;
		return -1;
	}
	if (shareds == NULL) {
		shareds = new_shareds;
		return 0;
	}
	DLIST_ADD(shareds, new_shareds);
	return 0;
}

int conn_zfs_init(TALLOC_CTX *mem_ctx,
		  const char *connectpath,
		  struct smblibzfshandle **plibzp,
		  struct dataset_list **pdsl)
{
	int ret = 0;
	struct smbzhandle *conn_zfsp = NULL;
	char *tmp_name = NULL;
	size_t to_remove, new_len;
	struct dataset_list *dl = NULL;

	get_global_smblibzfs_handle(mem_ctx);
	if (global_libzfs_handle == NULL) {
		/*
		 * Attempt to get libzfs handle should succeed even if share
		 * is not on ZFS. Failure here is significant error condition
		 * and therefore fatal.
		 */
		DBG_ERR("Failed to initialize global libzfs handle: %s\n",
			strerror(errno));
		errno = ENOMEM;
		return -1;
	}
	dl = share_lookup_dataset_list(connectpath);
	if (dl != NULL) {
		*plibzp = global_libzfs_handle;
		*pdsl = dl;
		return 0;
	}
	get_smbzhandle(global_libzfs_handle, mem_ctx, connectpath, &conn_zfsp, true);
	/*
	 * Attempt to get zfs dataset handle will fail if the dataset is a
	 * snapshot. This may occur if the share is one dynamically created
	 * by FSRVP when it exposes a snapshot.
	 */
	if ((conn_zfsp == NULL) && (strlen(connectpath) > 15)) {
		DBG_ERR("Failed to obtain zhandle on connectpath: %s\n",
			strerror(errno));
		tmp_name = strstr(connectpath, "/.zfs/snapshot/");
		if (tmp_name != NULL) {
			DBG_INFO("Connectpath is zfs snapshot. Opening zhandle "
				 "on parent dataset.\n");
			to_remove = strlen(tmp_name);
			new_len = strlen(connectpath) - to_remove;
			tmp_name = talloc_strndup(mem_ctx,
						  connectpath,
						  new_len);
			get_smbzhandle(global_libzfs_handle,
				       mem_ctx, tmp_name,
				       &conn_zfsp, false);
			TALLOC_FREE(tmp_name);
		}
	}
	*plibzp = global_libzfs_handle;
	if (conn_zfsp == NULL) {
		/*
		 * The filesystem is most likely not ZFS. Jailed processes
		 * on FreeBSD may not be able to obtain ZFS dataset handles.
		 */
		*pdsl = NULL;
		return 0;
	}
	dl = zhandle_list_children(mem_ctx, conn_zfsp, true);
	if (dl == NULL) {
		return 0;
	}
	ret = put_share_dataset_list(mem_ctx, connectpath, dl);
	if (ret != 0) {
		DBG_ERR("Failed to store share dataset list\n");
	}
	*pdsl = dl;
	return 0;
}
