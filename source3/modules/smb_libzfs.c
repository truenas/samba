/*
 * Copyright 2022 iXsystems, Inc.
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

#include <fcntl.h>
#include <talloc.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <mntent.h>
#ifndef hasmntopt
/* Search MNT->mnt_opts for an option matching OPT.
   Returns the address of the substring, or null if none found.  */
/* Structure describing a mount table entry.  */
struct mntent
  {
    char *mnt_fsname;           /* Device or server for filesystem.  */
    char *mnt_dir;              /* Directory mounted on.  */
    char *mnt_type;             /* Type of filesystem: ufs, nfs, etc.  */
    char *mnt_opts;             /* Comma-separated options for fs.  */
    int mnt_freq;               /* Dump frequency (in days).  */
    int mnt_passno;             /* Pass number for `fsck'.  */
  };

char *hasmntopt (const struct mntent *__mnt,
                 const char *__opt) __THROW;
#endif
#include <libzfs/sys/nvpair.h>
#include <libzfs/libzfs.h>
#include "lib/util/time.h"
#include "lib/util/debug.h"
#include "lib/util/discard.h"
#include "lib/util/dlinklist.h"
#include "lib/util/memcache.h"
#include "lib/util/memory.h"
#include "lib/util/unix_match.h"
#include "smb_macros.h"
#include "modules/smb_libzfs.h"

#define SHADOW_COPY_ZFS_GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"
#define ZFS_PROP_SAMBA_PREFIX "org.samba"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

#ifndef ZFSCTL_INO_ROOT
#define ZFSCTL_INO_ROOT     0x0000FFFFFFFFFFFFULL
#endif /* ZFSCTL_INO_ROOT */

typedef struct dataset_entry_internal {
	struct zfs_dataset *ds;
} dataset_t;

struct share_dataset_list {
	char *connectpath;
	dev_t dev_id;
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

static const struct {
	enum zfs_feature feature;
	const char *feature_str;
} zfs_feature_enum_list[] = {
	{SMBZFS_BLOCK_CLONING, "feature@block_cloning"},
};

static const char *user_quota_strings[] =  {
	"userquota",
	"userused",
	"userobjquota",
	"userobjused"
};

static const char *group_quota_strings[] =  {
	"groupquota",
	"groupused",
	"groupobjquota",
	"groupobjused"
};

static libzfs_handle_t *g_libzfs_handle;
static uint32_t g_refcount;
static struct memcache *global_zcache;

enum zhandle_zone {ZHANDLE_LOCAL, ZHANDLE_ROOT};

struct smbzhandle {
        libzfs_handle_t *lz;
	dev_t dev_id;
	zfs_handle_t *zhandle;
	int zhandle_ref;
	enum zhandle_zone zone;
	const char *location;
};

struct snap_cb
{
	struct snapshot_list *snapshots;
	struct snap_filter *iter_info;
};

struct child_cb
{
	struct dataset_list *dslist;
	bool open_zhandle;
};

static void global_handle_decref()
{
	SMB_ASSERT(g_refcount > 0);
	g_refcount--;

	if (g_refcount == 0) {
		libzfs_fini(g_libzfs_handle);
		g_libzfs_handle = NULL;
	}
}

static void global_handle_incref()
{
	if (g_refcount == 0) {
		g_libzfs_handle = libzfs_init();
		libzfs_print_on_error(g_libzfs_handle, B_TRUE);
		SMB_ASSERT(g_libzfs_handle != NULL);
	}
	g_refcount++;
}

static dataset_t *zcache_lookup_dataset(dev_t dev_id)
{
	char key[22] = {0};
	dataset_t *out = NULL;

	snprintf(key, sizeof(key), "DS_0x%16lx", dev_id);

	out = memcache_lookup_talloc(global_zcache,
				     ZFS_CACHE,
				     data_blob_const(&key, sizeof(key)));
	return out;
}

static void zcache_add_dataset(dataset_t *ds)
{
	char key[22] = {0};

	snprintf(key, sizeof(key), "DS_0x%16lx", ds->ds->devid);

	ds->ds->zhandle->zone = ZHANDLE_ROOT;
	memcache_add_talloc(global_zcache,
			    ZFS_CACHE,
			    data_blob_const(&key, sizeof(key)),
			    &ds);
}

static void zcache_remove_dataset(dev_t dev_id)
{
	char key[22] = {0};

	snprintf(key, sizeof(key), "DS_0x%16lx", dev_id);

	memcache_delete(global_zcache,
			ZFS_CACHE,
			data_blob_const(&key, sizeof(key)));
}

static void add_to_global_datasets(dataset_t *ds)
{
	zcache_add_dataset(ds);
}

static int smbzhandle_destructor(smbzhandle_t zhp)
{
	if (zhp->zhandle != NULL) {
		if (zhp->zone == ZHANDLE_LOCAL) {
			zfs_close(zhp->zhandle);
		}
		zhp->zhandle = NULL;
	}
	global_handle_decref();
	zhp->lz = NULL;
	return 0;
}

static libzfs_handle_t *get_global_smblibzfs_handle() {
	global_handle_incref();
	return g_libzfs_handle;
}

static int existing_parent_name(const char *path, char *buf, size_t buflen, int *nslashes);

static zfs_handle_t *get_zhandle(libzfs_handle_t *lz, const char *path,
				 dev_t *dev_id, bool resolve)
{
	/* "path" here can be either mountpoint or dataset name */
	int rv;
	struct stat st;
	zfs_handle_t *zfsp = NULL;

	if (path == NULL) {
		DBG_ERR("No pathname provided\n");
		errno = EINVAL;
		return zfsp;
	}

	zfsp = zfs_path_to_zhandle(lz, discard_const(path),
				   ZFS_TYPE_FILESYSTEM);

	if (zfsp == NULL) {
		if (resolve && errno == ENOENT) {
			int to_create;
			char parent[ZFS_MAXPROPLEN] = {0};

			rv = existing_parent_name(path, parent, sizeof(parent), &to_create);
			if (rv != 0) {
				DBG_ERR("Unable to access parent of %s\n", path);
				errno = ENOENT;
				return NULL;
			}
			DBG_INFO("Path [%s] does not exist, optaining zfs dataset handle from "
				 "path [%s]\n", path, parent);

			rv = stat(parent, &st);
			if (rv != 0) {
				DBG_ERR("%s: stat() failed: %s\n", parent, strerror(errno));
				*dev_id = 0;
			} else {
				*dev_id = st.st_dev;
			}
			zfsp = zfs_path_to_zhandle(lz, parent,
						   ZFS_TYPE_FILESYSTEM);
			if (zfsp == NULL) {
				DBG_ERR("%s: failed to obtain zhandle on path: %s\n",
					parent, libzfs_error_description(lz));
			}
			DBG_DEBUG("Successfully obtained ZFS dataset handle\n");
			return zfsp;
		}
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n", path);
	}

	rv = stat(path, &st);
	if (rv != 0) {
		DBG_ERR("%s: stat() failed: %s\n", path, strerror(errno));
		*dev_id = 0;
	} else {
		*dev_id = st.st_dev;
	}
	return zfsp;
}

static bool mp_to_dataset_name(const char *mp, char *name_out, size_t bufsz)
{
	/*
	 * Depending on what Samba's VFS is doing we may receive a request
	 * for snapshot enumeration on a VSS path (within snapdir). In this case
	 * we should determine whether the path is legitimately a snapdir or
	 * something a person has just named ".zfs/snapshot" and if it is
	 * one, strip off the path components within the ZFS ctldir so that
	 * we can retrieve a regular ZFS dataset handle for it.
	 */
	char buf[PATH_MAX + 1];
	char *ptr = NULL;
	size_t cnt;
	struct stat st;

	cnt = readlink(mp, buf, sizeof(buf) - 1);
	if (cnt == -1) {
		DBG_ERR("%s: readlink() failed: %s\n", mp, strerror(errno));
		return false;
	}

	// readlink() does not NULL-terminate
	buf[cnt] = '\0';
	strlcpy(name_out, buf, bufsz);

	ptr = strstr(name_out, ".zfs/snapshot");
	if (ptr == NULL) {
		return true;
	}

	/*
	 * Trim off everything after .zfs in our temporary
	 * buffer so that we can check its inode number to be
	 * extra sure this is the ZFS ctldir
	 */
	buf[PTR_DIFF(ptr + 4, name_out)] = '\0';
	if (stat(buf, &st) != 0) {
		return false;
	}

	if (!inode_is_ctldir(st.st_ino)) {
		return true;
	}

	// trim off the ctldir
	*ptr = '\0';
	return true;
}

static zfs_handle_t *fget_zhandle(libzfs_handle_t *lz, dev_t *dev_id, int fd)
{
	zfs_handle_t *zfsp = NULL;
	int err;
	struct stat st;
	char procfd_path[PATH_MAX] = {0};
	char ds_name[ZFS_MAX_DATASET_NAME_LEN];

	err = fstat(fd, &st);
	if (err) {
		DBG_ERR("fstat() failed: %s\n", strerror(errno));
		*dev_id = 0;
	} else {
		*dev_id = st.st_dev;
	}

	snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", fd);

	if (!mp_to_dataset_name(procfd_path, ds_name, ZFS_MAX_DATASET_NAME_LEN)) {
		DBG_ERR("%s: failed to convert to dataset name\n", procfd_path);
		strlcpy(ds_name, procfd_path, ZFS_MAX_DATASET_NAME_LEN);
	}

	zfsp = zfs_path_to_zhandle(lz, ds_name, ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL) {
		DBG_ERR("%s zfs_open() failed: %s\n",
			ds_name, libzfs_error_description(lz));
	}
	return zfsp;
}

bool inode_is_ctldir(ino_t ino)
{
	return ino == ZFSCTL_INO_ROOT ? true : false;
}

static zfs_handle_t *get_zhandle_from_smbzhandle(struct smbzhandle *smbzhandle)
{
	SMB_ASSERT(smbzhandle->zhandle != NULL);
	return smbzhandle->zhandle;
}

static bool zfs_get_smbzhandle(TALLOC_CTX *mem_ctx,
			       libzfs_handle_t *lz,
			       zfs_handle_t *zfsp,
			       dev_t dev_id,
			       smbzhandle_t *zh_out)
{
	smbzhandle_t zh = NULL;

	zh = talloc_zero(mem_ctx, struct smbzhandle);
	if (zh == NULL) {
		/* caller does refcounting on lz */
		errno = ENOMEM;
		return false;
	}

	zh->zhandle = zfsp;
	zh->lz = lz;
	zh->dev_id = dev_id;
	zh->zone = ZHANDLE_LOCAL;
	talloc_set_destructor(zh, smbzhandle_destructor);
	*zh_out = zh;
	return true;
}

int _get_smbzhandle(TALLOC_CTX *mem_ctx, const char *path,
		   smbzhandle_t *smbzhandle,
		   bool resolve, const char *location)
{
	zfs_handle_t *zfsp = NULL;
	smbzhandle_t zh = NULL;
	libzfs_handle_t *lz = NULL;
	dev_t devid;
	bool ok;

	lz = get_global_smblibzfs_handle();

	zfsp = get_zhandle(lz, path, &devid, resolve);
	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: [%s]: %s\n",
			path, strerror(errno));
		global_handle_decref();
		return -1;
	}

	ok = zfs_get_smbzhandle(mem_ctx, lz, zfsp, devid, &zh);
	if (!ok) {
		global_handle_decref();
		return -1;
	}

	zh->location = location;
	*smbzhandle = zh;
	return 0;
}

int _fget_smbzhandle(TALLOC_CTX *mem_ctx, int fd,
		    smbzhandle_t *smbzhandle, const char *location)
{
	zfs_handle_t *zfsp = NULL;
	smbzhandle_t zh = NULL;
	libzfs_handle_t *lz = NULL;
	dev_t devid;
	bool ok;

	lz = get_global_smblibzfs_handle();

	zfsp = fget_zhandle(lz, &devid, fd);
	if (zfsp == NULL) {
		global_handle_decref();
		return -1;
	}

	ok = zfs_get_smbzhandle(mem_ctx, lz, zfsp, devid, &zh);
	if (!ok) {
		global_handle_decref();
		return -1;
	}

	zh->location = location;
	*smbzhandle = zh;
	return 0;
}

/*
 * duplicate a smbzfs handle under different
 * TALLOC context. This also duplicates
 * underlying ZFS dataset handle so that
 * destructor doesn't close our cached one
 */
smbzhandle_t smbzhandle_dup(TALLOC_CTX *mem_ctx,
			    smbzhandle_t in_zh)
{
	libzfs_handle_t *lz = NULL;
	zfs_handle_t *new_zh = NULL;
	smbzhandle_t out = NULL;
	bool ok;

	new_zh = get_zhandle_from_smbzhandle(in_zh);
	SMB_ASSERT(new_zh);
	lz = get_global_smblibzfs_handle();
	ok = zfs_get_smbzhandle(mem_ctx, lz, new_zh,
				in_zh->dev_id,
				&out);
	SMB_ASSERT(ok);
	return out;
}

/*
 * Make a copy of the stored dataset handle from our internal
 * cache under the provided talloc context. ZFS dataset handle
 * is duped and global handle refcount increased.
 */
static struct zfs_dataset *copy_to_external(TALLOC_CTX *mem_ctx,
					    dataset_t *ds_in,
					    bool include_props,
				            bool open_zhandle)
{
	struct zfs_dataset *out = NULL;

	out = talloc_zero(mem_ctx, struct zfs_dataset);
	if (out == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	strlcpy(out->dataset_name, ds_in->ds->dataset_name,
		sizeof(out->dataset_name));
	strlcpy(out->mountpoint, ds_in->ds->mountpoint,
		sizeof(out->mountpoint));
	out->devid = ds_in->ds->devid;
	if (include_props) {
		struct zfs_dataset_prop *prop_in = ds_in->ds->properties;
		out->properties = talloc_zero(mem_ctx, struct zfs_dataset_prop);
		if (out->properties == NULL) {
			TALLOC_FREE(out);
			errno = ENOMEM;
			return NULL;
		}
		out->properties->casesens = prop_in->casesens;
		out->properties->readonly = prop_in->readonly;
		out->properties->record_size = prop_in->record_size;
		out->properties->checksum_enabled = prop_in->checksum_enabled;
		out->properties->snapdir = prop_in->snapdir;
	}
	if (open_zhandle) {
		out->zhandle = smbzhandle_dup(out, ds_in->ds->zhandle);
		out->zhandle->zone = ZHANDLE_ROOT;
		out->zhandle->location = ds_in->ds->zhandle->location;
	}
	return out;
}

struct zfs_quota_singleton_cache
{
	struct zfs_quota qt;
	dev_t dev_id;
	uint64_t xid;
	time_t ts;
	bool valid;
};

struct zfs_quota_singleton_cache cached_quota[SMBZFS_GROUP_QUOTA + 1];
#define ZFS_QUOTA_TIMEOUT 10

static bool
smb_zfs_get_cached_quota(dev_t dev_id,
			 uint64_t xid,
			 enum zfs_quotatype quota_type,
			 struct zfs_quota *qt)
{
	struct zfs_quota_singleton_cache *cache = NULL;
	double seconds;
	time_t now;

	SMB_ASSERT((quota_type == SMBZFS_USER_QUOTA) ||
		   (quota_type == SMBZFS_GROUP_QUOTA));
	cache = &cached_quota[quota_type];
	if (!cache->valid || (cache->dev_id != dev_id) ||
	    (cache->xid != xid)) {
		return false;
	}

	time(&now);

	seconds = difftime(now, cache->ts);
	if (seconds > ZFS_QUOTA_TIMEOUT) {
		return false;
	}

	memcpy(qt, &cache->qt, sizeof(struct zfs_quota));
	return true;
}

static void
smb_zfs_set_cached_quota(dev_t dev_id,
			 uint64_t xid,
			 enum zfs_quotatype quota_type,
			 struct zfs_quota *qt,
			 bool valid)
{
	struct zfs_quota_singleton_cache *cache = NULL;
	SMB_ASSERT((quota_type == SMBZFS_USER_QUOTA) ||
		   (quota_type == SMBZFS_GROUP_QUOTA));

	cache = &cached_quota[quota_type];
	*cache = (struct zfs_quota_singleton_cache) {
		.dev_id = dev_id,
		.xid = xid,
		.valid = valid
	};
	memcpy(&cache->qt, qt, sizeof(struct zfs_quota));
	time(&cache->ts);
}

int
smb_zfs_get_quota(smbzhandle_t hdl,
		  uint64_t xid,
		  enum zfs_quotatype quota_type,
		  struct zfs_quota *qt)
{
	int i;
	bool cached;
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	char req[ZFS_MAXPROPLEN] = { 0 };
	uint64_t rv[4] = { 0 };

	zfsp = get_zhandle_from_smbzhandle(hdl);
	cached = smb_zfs_get_cached_quota(hdl->dev_id, xid, quota_type, qt);
	if (cached) {
		return 0;
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
	default:
		DBG_ERR("Received unknown quota type (%d)\n", quota_type);
		return -1;
	}

	qt->bytes = rv[0] / blocksize;
	qt->bytes_used = rv[1] / blocksize;
	qt->obj = rv[2];
	qt->obj_used = rv[3];
	qt->quota_type = quota_type;
	smb_zfs_set_cached_quota(hdl->dev_id, xid, quota_type, qt, true);
	return 0;
}

int
smb_zfs_set_quota(smbzhandle_t hdl, uint64_t xid, struct zfs_quota qt)
{
	int rv;
	zfs_handle_t *zfsp = NULL;
	char qr[ZFS_MAXPROPLEN] = { 0 };
	char qr_obj[ZFS_MAXPROPLEN] = { 0 };
	char quota[ZFS_MAXPROPLEN] = { 0 };

	if (xid == 0) {
		DBG_ERR("Setting quota on id 0 is not permitted\n");
		errno = EPERM;
		return -1;
	}

	zfsp = get_zhandle_from_smbzhandle(hdl);

	switch (qt.quota_type) {
	case SMBZFS_USER_QUOTA:
		snprintf(qr, sizeof(qr), "userquota@%lu", xid);
		snprintf(qr_obj, sizeof(qr_obj), "userobj@%lu", xid);
		break;
	case SMBZFS_GROUP_QUOTA:
		snprintf(qr, sizeof(qr), "groupquota@%lu", xid);
		snprintf(qr_obj, sizeof(qr_obj), "groupobj@%lu", xid);
		break;
	default:
		DBG_ERR("Received unknown quota type (%d)\n", qt.quota_type);
		return -1;
	}

	snprintf(quota, sizeof(quota), "%lu", qt.bytes);
	smb_zfs_set_cached_quota(hdl->dev_id, xid, qt.quota_type, &qt, false);
	rv = zfs_prop_set(zfsp, qr, quota);
	if (rv != 0) {
		DBG_ERR("Failed to set (%s = %s)\n", qr, quota);
		return -1;
	}

	snprintf(quota, sizeof(quota), "%lu", qt.obj);
	rv = zfs_prop_set(zfsp, qr_obj, quota);
	if (rv != 0) {
		DBG_ERR("Failed to set (%s = %s)\n", qr_obj, quota);
		return -1;
	}

	return 0;
}

uint64_t
smb_zfs_disk_free(smbzhandle_t hdl,
		  uint64_t *bsize, uint64_t *dfree,
		  uint64_t *dsize)
{
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	uint64_t available, usedbysnapshots, usedbydataset,
		usedbychildren, real_used, total;

	zfsp = get_zhandle_from_smbzhandle(hdl);

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
create_dataset_internal(libzfs_handle_t *lz,
			char *to_create,
			const char *quota)
{
	/* Create and mount new dataset. to_create should be dataset name */
	int rv;
	zfs_handle_t *new = NULL;

	rv = zfs_create(lz, to_create, ZFS_TYPE_FILESYSTEM, NULL);
	if (rv != 0) {
		DBG_ERR("Failed to create dataset [%s]: %s\n",
			to_create, strerror(errno));
		return -1;
	}
	new = zfs_open(lz, to_create, ZFS_TYPE_FILESYSTEM);
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

#define DATASET_ARRAY_SZ 50	/* zfs_max_dataset_nesting */

static bool path_to_dataset_list(TALLOC_CTX *mem_ctx,
				 const char *path,
				 struct zfs_dataset ***_array_out,
				 size_t *_nentries,
				 int depth)
{
	char *slashp = NULL;
	struct zfs_dataset **ds_array = NULL;
	struct zfs_dataset *ds = NULL;
	char tmp_path[ZFS_MAXPROPLEN] = {0};
	size_t nentries;
	int rv;

	strlcpy(tmp_path, path, sizeof(tmp_path));

	/* allocate array of pointers to datasets */
	ds_array = talloc_zero_array(mem_ctx, struct zfs_dataset *, DATASET_ARRAY_SZ);
	if (ds_array == NULL) {
		errno = ENOMEM;
		return false;
	}

	ds = smb_zfs_path_get_dataset(ds_array, path, true, true, false);
	if (ds == NULL) {
		TALLOC_FREE(ds_array);
		return false;
	}
	ds_array[0] = ds;
	nentries = 1;

	if (tmp_path[strlen(tmp_path) -1] == '/') {
		tmp_path[strlen(tmp_path) -1] = '\0';
	}

	for (; nentries <= depth; nentries++) {
		slashp = strrchr(tmp_path, '/');
		if (slashp == NULL) {
			DBG_ERR("Exiting at depth %zu\n",
				 nentries);
			break;
		}
		*slashp = '\0';
		ds = smb_zfs_path_get_dataset(ds_array, tmp_path,
					      true, true, false);
		if (ds == NULL) {
			TALLOC_FREE(ds_array);
			return false;
		}
		ds_array[nentries] = ds;
	}
	*_nentries = nentries;
	*_array_out = ds_array;
	return true;
}

int
smb_zfs_create_dataset(TALLOC_CTX *mem_ctx,
		       const char *path, const char *quota,
		       struct zfs_dataset ***_array_out,
		       size_t *_nentries,
		       bool create_ancestors)
{
	int rv = -1, error, to_create;
	zfs_handle_t *zfsp = NULL;
	char parent[ZFS_MAXPROPLEN] = {0};
	char *target_ds = NULL;
	struct zfs_dataset **ds_array = NULL;
	struct dataset_list *ds_list = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	libzfs_handle_t *lz = NULL;
	size_t nentries;
	bool ok;

	lz = get_global_smblibzfs_handle();

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (access(path, F_OK) == 0) {
		DBG_ERR("Path %s already exists.\n", path);
		errno = EEXIST;
		goto fail;
	}

	error = existing_parent_name(path, parent, sizeof(parent), &to_create);
	if (error) {
		DBG_ERR("Unable to access parent of %s\n", path);
		errno = ENOENT;
		goto fail;
	}

	/*
	 * This zfs dataset handle allows us to figure out the
	 * name that our new dataset should have by looking at
	 * dataset properties of parent dataset.
	 */
	zfsp = zfs_path_to_zhandle(lz, parent, ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on %s: %s\n",
			parent, strerror(errno));
		goto unlock_out;
	}

	target_ds = get_target_name(tmp_ctx, zfsp, path);
	if (target_ds == NULL) {
		zfs_close(zfsp);
		goto unlock_out;
	}
	zfs_close(zfsp);

	if (to_create > 1 && create_ancestors) {
		rv = zfs_create_ancestors(lz, target_ds);
		if (rv != 0 ) {
			goto unlock_out;
		}
	}
	else if (to_create > 1) {
		DBG_ERR("Unable to create dataset [%s] due to "
			"missing ancestor datasets.", target_ds);
		errno = ENOENT;
		goto unlock_out;
	}

	error = create_dataset_internal(lz, target_ds, quota);
	if (error) {
		goto unlock_out;
	}

	ok = path_to_dataset_list(mem_ctx, path, &ds_array,
				  &nentries, to_create);
	if (!ok) {
		DBG_ERR("Failed to generate dataset list for %s\n",
			path);
		goto unlock_out;
	}

	*_array_out = ds_array;
	*_nentries = nentries;
	rv = 0;
unlock_out:
fail:
	TALLOC_FREE(tmp_ctx);
	return rv;
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
	const char *propstr = NULL;
	char prefixed_prop[ZFS_MAXPROPLEN] = {0};

	snprintf(prefixed_prop, sizeof(prefixed_prop),
		 "%s:%s", ZFS_PROP_SAMBA_PREFIX, prop);

	zfsp = get_zhandle_from_smbzhandle(hdl);

	userprops = zfs_get_user_props(zfsp);
	ret = nvlist_lookup_nvlist(userprops, prefixed_prop, &propval);
	if (ret != 0) {
		DBG_INFO("Failed to look up custom user property %s on dataset [%s]: %s\n",
			 prop, zfs_get_name(zfsp), strerror(errno));
		goto out;
	}
	ret = nvlist_lookup_string(propval, ZPROP_VALUE, &propstr);
	if (ret != 0) {
		DBG_ERR("Failed to get nvlist string for property %s\n",
			prop);
		goto out;
	}

	*value = talloc_strdup(mem_ctx, propstr);

out:
	return ret;
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

	snprintf(prefixed_prop, sizeof(prefixed_prop), "%s:%s",
		 ZFS_PROP_SAMBA_PREFIX, prop);

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
	    NULL, 0, B_FALSE) != 0) {
		DBG_ERR("Failed to look up casesensitivity property\n");
		return -1;
	}
	for (i = 0; i < ARRAY_SIZE(sens_enum_list); i++) {
		if (strcmp(buf, sens_enum_list[i].sens_str) == 0) {
			props->casesens = sens_enum_list[i].sens;
		}
	}
	if (zfs_prop_get(zfsp, ZFS_PROP_SNAPDIR,
	    buf, sizeof(buf), &sourcetype,
	    NULL, 0, B_FALSE) != 0) {
		DBG_ERR("Failed to look up snapdir property\n");
		return -1;
	}
	if (strcmp(buf, "visible") == 0) {
		props->snapdir = SMBZFS_SNAPDIR_VISIBLE;
	} else if (strcmp(buf, "disabled") == 0) {
		props->snapdir = SMBZFS_SNAPDIR_DISABLED;
	} else {
		props->snapdir = SMBZFS_SNAPDIR_HIDDEN;
	}

	if (zfs_prop_get(zfsp, ZFS_PROP_CHECKSUM,
	    buf, sizeof(buf), &sourcetype,
	    NULL, 0, B_FALSE) != 0) {
		DBG_ERR("Failed to look up checksum property\n");
		return -1;
	}

	if (strcmp(buf, "off") == 0) {
		props->checksum_enabled = false;
	} else {
		props->checksum_enabled = true;
	}

	props->readonly = zfs_prop_get_int(zfsp, ZFS_PROP_READONLY);
	props->record_size = zfs_prop_get_int(zfsp, ZFS_PROP_RECORDSIZE);
	return 0;
}

static bool find_dataset_mp(FILE *mntinfo, struct zfs_dataset *ds)
{
	const char *dsname = zfs_get_name(get_zhandle_from_smbzhandle(ds->zhandle));
	char *line = NULL;
	size_t linecap = 0;

	/*
	 * Sample line from /proc/self/mountinfo:
	 * 27 1 0:24 / / rw,relatime shared:1 - zfs boot-pool/ROOT/22.02.3 rw,xattr,noacl
	 * (0)(1)(2)(3)(4) (5)       (6)      (7)(8)(9)                    (10)
	 * 0 - mount id
	 * 1 - parent id
	 * 2 - major:minor
	 * 3 - root
	 * 4 - mount point
	 * 5 - mount options
	 * 6 - optional fields
	 * 7 - separator
	 * 8 - filesystem type
	 * 9 - mount source
	 * 10 - super_options
	 */
	while (getline(&line, &linecap, mntinfo) > 0) {
		char *saveptr = NULL, *found = NULL, *token = NULL;
		int i;

		found = strstr(line, dsname);
		if (found == NULL) {
			continue;
		}

		/* Spaces are escaped in proc mountinfo */
		if (((found + strlen(dsname))[0] != ' ') ||
		    ((found - 1)[0] != ' ')) {
			continue;
		}

		token = strtok_r(line, " ", &saveptr);
		for (i = 0; i < 4; i++) {
			token = strtok_r(NULL, " ", &saveptr);
			/*
			 * Dump core if we have invalid lines in mountinfo
			 * This would be something worth investigating.
			 */
			SMB_ASSERT(token != NULL);
		}
		strlcpy(ds->mountpoint, token, sizeof(ds->mountpoint));
		free(line);
		return true;
	}
	DBG_ERR("Failed to find dataset %s in /proc/self/mountinfo\n", dsname);
	errno = ENOENT;
	free(line);
	return false;
}

static bool resolve_legacy(struct zfs_dataset *ds)
{
	FILE *mnt = NULL;
	bool ok;
	int fd;

	fd = open("/proc/self/mountinfo", O_RDONLY);
	if (fd == -1) {
		DBG_ERR("Failed to open mountinfo %s\n", strerror(errno));
		return NULL;
	}

	mnt = fdopen(fd, "r");
	if (mnt == NULL) {
		DBG_ERR("fdopen() failed: %s\n",
			strerror(errno));
		close(fd);
		return NULL;
	}

	ok = find_dataset_mp(mnt, ds);
	fclose(mnt);
	return ok;
}

static dataset_t *lookup_dataset_by_devid(dev_t dev_id)
{
	return zcache_lookup_dataset(dev_id);
}

static struct zfs_dataset *zhandle_get_dataset(TALLOC_CTX *mem_ctx,
					struct smbzhandle *zfsp_ext,
					bool open_zhandle,
					bool get_props)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	struct zfs_dataset *ds = NULL;
	dataset_t *dsentry = NULL;
	struct stat ds_st;

	SMB_ASSERT(zfsp_ext->dev_id != 0);
	dsentry = lookup_dataset_by_devid(zfsp_ext->dev_id);
	if (dsentry != NULL) {
		return copy_to_external(mem_ctx, dsentry,
					get_props, open_zhandle);
	}

	zfsp = get_zhandle_from_smbzhandle(zfsp_ext);
	dsentry = talloc_zero(global_zcache, dataset_t);
	if (dsentry == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ds = talloc_zero(dsentry, struct zfs_dataset);
	if (ds == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	dsentry->ds = ds;

	ds->zhandle = smbzhandle_dup(ds, zfsp_ext);
	ds->zhandle->location = zfsp_ext->location;

	strlcpy(ds->dataset_name, zfs_get_name(zfsp),
		sizeof(ds->dataset_name));

	ret = zfs_prop_get(zfsp, ZFS_PROP_MOUNTPOINT, ds->mountpoint,
			   sizeof(ds->mountpoint), NULL, NULL,
			   0, 0);
	if (ret != 0) {
		DBG_ERR("Failed to get mountpoint for %s: %s\n",
			ds->dataset_name, strerror(errno));
		goto fail;
	}

	if (strcmp(ds->mountpoint, "legacy") == 0) {
		bool ok;
		ok = resolve_legacy(ds);
		if (!ok) {
			DBG_ERR("%s: Failed to resolve dataset mountpoint\n",
				ds->dataset_name);
			goto fail;
		}
	}

	ret = stat(ds->mountpoint, &ds_st);
	if (ret != 0) {
		DBG_ERR("%s: stat() failed: %s\n",
			ds->mountpoint, strerror(errno));
		goto fail;
	}

	ds->devid = ds_st.st_dev;
	ds->zhandle->dev_id = ds_st.st_dev;

	ds->properties = talloc_zero(ds, struct zfs_dataset_prop);
	if (ds->properties == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	ret = zhandle_get_props(zfsp_ext, ds, &ds->properties);
	if (ret != 0) {
		DBG_ERR("Failed to get properties for dataset\n");
		goto fail;
	}

	add_to_global_datasets(dsentry);
	/*
	 * Change zone to ROOT to prevent destructor from closing
	 * ZFS dataset handle that is now in our cache
	 */
	zfsp_ext->zone = ZHANDLE_ROOT;
	return copy_to_external(mem_ctx, dsentry,
				get_props, open_zhandle);
fail:
	TALLOC_FREE(dsentry);
	return NULL;
}

struct zfs_dataset *_smb_zfs_path_get_dataset(TALLOC_CTX *mem_ctx,
					      const char *path,
					      bool get_props,
					      bool open_zhandle,
					      bool resolve_path,
					      const char *location)
{
	int ret;
	struct zfs_dataset *dsout = NULL;
	struct smbzhandle *zfs_ext = NULL;

	ret = _get_smbzhandle(mem_ctx, path, &zfs_ext, resolve_path, location);
	if (ret != 0) {
		DBG_ERR("Failed to get zhandle\n");
		return NULL;
	}
	dsout = zhandle_get_dataset(mem_ctx, zfs_ext, get_props, open_zhandle);
	TALLOC_FREE(zfs_ext);
	if (dsout == NULL) {
		return dsout;
	}
	return dsout;
}

struct zfs_dataset *_smb_zfs_fd_get_dataset(TALLOC_CTX *mem_ctx,
					    int fd,
					    bool get_props,
					    bool open_zhandle,
					    const char *location)
{
	int ret;
	struct zfs_dataset *dsout = NULL;
	struct smbzhandle *zfs_ext = NULL;

	ret = _fget_smbzhandle(mem_ctx, fd, &zfs_ext, location);
	if (ret != 0) {
		DBG_ERR("Failed to get zhandle\n");
		return NULL;
	}
	dsout = zhandle_get_dataset(mem_ctx, zfs_ext, get_props, open_zhandle);
	TALLOC_FREE(zfs_ext);
	if (dsout == NULL) {
		return dsout;
	}
	return dsout;
}

static bool check_pattern(char **pattern, const char *snap_name)
{
	char **to_check = NULL;
	bool match = false;

	SMB_ASSERT(pattern != NULL);

	for (to_check = pattern; *to_check != NULL; to_check++) {
		match = unix_wild_match(*to_check, snap_name);
		if (match) {
			break;
		}
	}

	return match;
}

static bool
shadow_copy_zfs_is_snapshot_included(struct snap_filter *info,
    const char *snap_name)
{
	bool is_match;

	if (info->inclusions != NULL) {
		is_match = check_pattern(info->inclusions, snap_name);
		if (!is_match) {
			DBG_INFO("smb_zfs_add_snapshot: snapshot %s "
				 "not in inclusion list\n", snap_name);
			return false;
		}
	}

	if (info->exclusions != NULL) {
		is_match = check_pattern(info->exclusions, snap_name);
		if (is_match) {
			DBG_INFO("smb_zfs_add_snapshot: snapshot %s "
				 "in exclusion list\n", snap_name);
			return false;
		}
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
	uint64_t createtxg;
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

	createtxg = zfs_prop_get_int(snap, ZFS_PROP_CREATETXG);
	if (state->iter_info->start_txg == createtxg) {
		goto done;
	}

	/* ignore snapshots with zero bytes written */
	used = zfs_prop_get_int(snap, ZFS_PROP_WRITTEN);
	if (used == 0 && state->iter_info->ignore_empty_snaps) {
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

	gmtime_r(&cr_time, &timestamp);
	strftime(entry->label, sizeof(entry->label), SHADOW_COPY_ZFS_GMT_FORMAT,
		 &timestamp);

	entry->cr_time = cr_time;
	unix_to_nt_time(&entry->nt_time, cr_time);
	strlcpy(entry->name, snap_name, sizeof(entry->name));
	entry->createtxg = createtxg;

	DLIST_ADD(state->snapshots->entries, entry);
	state->snapshots->num_entries++;
	state->snapshots->last = entry;
done:
	zfs_close(snap);
	return 0;
}

struct
snapshot_list *zhandle_list_snapshots(struct smbzhandle *zhandle_ext,
				      TALLOC_CTX *mem_ctx,
				      struct snap_filter *iter_info)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct snap_cb *state = NULL;
	struct snapshot_list *snapshots = NULL;
	int rc;
	zfs_handle_t *zfs = NULL;

	zfs = get_zhandle_from_smbzhandle(zhandle_ext);

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

	state->snapshots = snapshots;

	strlcpy(snapshots->dataset_name, zfs_get_name(zfs),
		sizeof(snapshots->dataset_name));

	rc = zfs_prop_get(zfs, ZFS_PROP_MOUNTPOINT, snapshots->mountpoint,
			  sizeof(snapshots->mountpoint), NULL, NULL,
			  0, 0);
	if (rc != 0) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"mountpoint for '%s': %s\n",
			snapshots->dataset_name,
			strerror(errno));
		goto error;
	}

	state->iter_info = iter_info;

	rc = zfs_iter_snapshots_sorted(zfs, smb_zfs_add_snapshot, state,
				       iter_info->start_txg, iter_info->end_txg);

	if (rc != 0) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"snapshots for '%s': %s\n",
			snapshots->dataset_name, strerror(errno));
		goto error;
	}

	time(&snapshots->timestamp);
	state->snapshots = NULL;
done:
	TALLOC_FREE(tmp_ctx);
	return snapshots;

error:
	TALLOC_FREE(tmp_ctx);
	TALLOC_FREE(snapshots);
	return NULL;
}

bool update_snapshot_list(smbzhandle_t zh,
			  struct snapshot_list *snaps,
			  struct snap_filter *iter_info)
{
	struct snap_cb *state = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	zfs_handle_t *zfs = NULL;
	int rc;

	tmp_ctx = talloc_new(snaps);
	if (tmp_ctx == NULL) {
		errno = ENOMEM;
		return false;
	}

	state = talloc_zero(tmp_ctx, struct snap_cb);
	if (state == NULL) {
		errno = ENOMEM;
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	zfs = get_zhandle_from_smbzhandle(zh);

	state->iter_info = iter_info;
	state->snapshots = snaps;
	state->iter_info->start_txg = snaps->last->createtxg;

	rc = zfs_iter_snapshots_sorted(zfs, smb_zfs_add_snapshot,
				       state, snaps->last->createtxg, 0);

	time(&snaps->timestamp);
	TALLOC_FREE(tmp_ctx);
	return true;
}

struct
snapshot_list *smb_zfs_list_snapshots(TALLOC_CTX *mem_ctx,
				      const char *path,
				      struct snap_filter *iter_info)
{
	int ret;
	smbzhandle_t hdl = NULL;
	struct snapshot_list *out = NULL;
	ret = _get_smbzhandle(mem_ctx, path, &hdl, false, __location__);
	if (ret != 0) {
		DBG_ERR("Failed to get zhandle\n");
		return NULL;
	}
	out = zhandle_list_snapshots(hdl, mem_ctx, iter_info);
	TALLOC_FREE(hdl);
	return out;
}

/*
 * Convert linked list to nvlist and perform delete in single
 * consolidated ioctl.
 */
int
smb_zfs_delete_snapshots(struct snapshot_list *snaps)
{
	int ret;
	nvlist_t *to_delete = NULL;
	struct snapshot_entry *entry = NULL;
	char snapname[ZFSDS_NAMELEN + ZFSDS_NAMELEN + 2];
	libzfs_handle_t *lz = NULL;

	lz = get_global_smblibzfs_handle();

	ret = nvlist_alloc(&to_delete, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		DBG_ERR("Failed to initialize nvlist for snaps.\n");
		errno=ENOMEM;
		return -1;
	}
	for (entry = snaps->entries; entry; entry = entry->next) {
		snprintf(snapname, sizeof(snapname),
			 "%s@%s",
			 snaps->dataset_name,
			 entry->name);

		DBG_INFO("deleting snapshot: %s\n", snapname);
		fnvlist_add_boolean(to_delete, snapname);
	}
	ret = zfs_destroy_snaps_nvl(lz, to_delete, B_TRUE);
	if (ret !=0) {
		DBG_ERR("Failed to delete snapshots: %s\n",
			strerror(errno));
	}

	nvlist_free(to_delete);
	return ret;
}

int
smb_zfs_snapshot(smbzhandle_t hdl,
		 const char *snapshot_name,
		 bool recursive)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	char snap[ZFS_MAXPROPLEN] = {0};
	const char *dataset_name;

	zfsp = get_zhandle_from_smbzhandle(hdl);
	dataset_name = zfs_get_name(zfsp);
	ret = snprintf(snap, sizeof(snap), "%s@%s",
		       dataset_name, snapshot_name);
	if (ret < 0) {
		DBG_ERR("Failed to format snapshot name:%s\n",
			strerror(errno));
		return -1;
	}
	ret = zfs_snapshot(hdl->lz, snap, recursive, NULL);
	if (ret != 0) {
		DBG_ERR("Failed to create snapshot %s: %s\n",
			snap, strerror(errno));
	}
	return ret;
}

bool
smb_zfs_pool_feature_enabled(struct zfs_dataset *ds,
			     enum zfs_feature feature,
			     bool *enabled_out)
{
	zfs_handle_t *zfsp = NULL;
	zpool_handle_t *pool = NULL;
	char statebuf[64] = {0};
	int error, i;
	bool enabled;
	const char *feature_name = NULL;

	SMB_ASSERT(ds != NULL);

	for (i = 0; i < ARRAY_SIZE(zfs_feature_enum_list); i++) {
		if (zfs_feature_enum_list[i].feature == feature) {
			feature_name = zfs_feature_enum_list[i].feature_str;
			break;
		}
	}

	SMB_ASSERT(feature_name != NULL);

	if (ds->zhandle == NULL) {
		DBG_ERR("%s: no dataset handle.\n", ds->dataset_name);
		return false;
	}

	zfsp = get_zhandle_from_smbzhandle(ds->zhandle);

	pool = zfs_get_pool_handle(zfsp);
	if (pool == NULL) {
		DBG_ERR("%s: pool handle not initialized\n", ds->dataset_name);
		return false;
	}
	error = zpool_prop_get_feature(pool, feature_name,
				       statebuf, sizeof(statebuf));

	if (error) {
		DBG_ERR("%s: failed to retrieve status of %s: %s\n",
			ds->dataset_name, feature_name, strerror(error));
		return false;
	}

	if ((strcmp(statebuf, "enabled") == 0) ||
	    (strcmp(statebuf, "active") == 0)) {
		*enabled_out = true;

	} else {
		DBG_INFO("%s: %s on dataset [%s] is not active\n",
			 statebuf, feature_name, ds->dataset_name);

		*enabled_out = false;
	}

	return true;
}

static struct zfs_dataset *share_lookup_dataset_list(TALLOC_CTX *mem_ctx,
						     const char *connectpath)
{
	dataset_t *ds_internal;
	dev_t dev_id = 0;
	struct share_dataset_list *to_check = NULL;


	for (to_check=shareds; to_check; to_check = to_check->next) {
		if (strcmp(connectpath, to_check->connectpath) == 0) {
			dev_id = to_check->dev_id;
			break;
		}
	}

	if (dev_id == 0) {
		DBG_DEBUG("%s: path is uncached\n", connectpath);
		return NULL;
	}

	ds_internal = lookup_dataset_by_devid(dev_id);
	SMB_ASSERT(ds_internal != NULL);

	DBG_DEBUG("%s: cache entry found - dataset: %s\n",
		  connectpath, ds_internal->ds->dataset_name);

	return copy_to_external(mem_ctx, ds_internal, true, true);
}

static int put_share_dataset_list(TALLOC_CTX *mem_ctx, const char *connectpath,
				  struct zfs_dataset *ds)
{
	int ret = -1;

	struct share_dataset_list *new_shareds= NULL;
	new_shareds = talloc_zero(mem_ctx, struct share_dataset_list);
	if (new_shareds == NULL) {
		errno = ENOMEM;
		goto out;
	}

	new_shareds->dev_id = ds->devid;
	new_shareds->connectpath = talloc_strdup(mem_ctx, connectpath);
	if (new_shareds->connectpath == NULL) {
		errno = ENOMEM;
		goto out;
	}

	ret = 0;

	if (shareds == NULL) {
		shareds = new_shareds;
	} else {
		DLIST_ADD(shareds, new_shareds);
	}

out:
	return ret;
}

static void init_global_zcache()
{
	if (global_zcache == NULL) {
		global_zcache = memcache_init(NULL, 0);
		SMB_ASSERT(global_zcache != NULL);
	}
}

int conn_zfs_init(TALLOC_CTX *mem_ctx,
		  const char *connectpath,
		  struct zfs_dataset **pds,
		  bool has_tcon)
{
	int ret = 0;
	smbzhandle_t conn_zfsp = NULL;
	size_t to_remove, new_len;
	struct zfs_dataset *ds = NULL;

	if (has_tcon) {
		init_global_zcache();
		ds = share_lookup_dataset_list(mem_ctx, connectpath);
		if (ds != NULL) {
			*pds = ds;
			return 0;
		}
	}

	_get_smbzhandle(mem_ctx, connectpath, &conn_zfsp, true, __location__);
	/*
	 * Attempt to get zfs dataset handle will fail if the dataset is a
	 * snapshot. This may occur if the share is one dynamically created
	 * by FSRVP when it exposes a snapshot.
	 */
	if ((conn_zfsp == NULL) && (strlen(connectpath) > 15)) {
		char *tmp_name = NULL;
		char *ptr;

		tmp_name = talloc_strdup(mem_ctx, connectpath);
		if (tmp_name == NULL) {
			errno = ENOMEM;
			return -1;
		}

		DBG_ERR("Failed to obtain zhandle on connectpath: %s\n",
			strerror(errno));
		ptr = strstr(connectpath, "/.zfs/snapshot/");
		if (ptr != NULL) {
			*ptr = '\0';
			_get_smbzhandle(mem_ctx, tmp_name,
				        &conn_zfsp, true, __location__);
		}
		TALLOC_FREE(tmp_name);
	}

	if (conn_zfsp == NULL) {
		/*
		 * The filesystem is most likely not ZFS. Jailed processes
		 * on FreeBSD may not be able to obtain ZFS dataset handles.
		 */
		*pds = NULL;
		return 0;
	}

	ds = zhandle_get_dataset(mem_ctx, conn_zfsp, true, true);
	if (has_tcon && ds) {
		ret = put_share_dataset_list(mem_ctx, connectpath, ds);
		if (ret != 0) {
			DBG_ERR("Failed to store share dataset list\n");
		}
	}

	*pds = ds;
	return 0;
}
