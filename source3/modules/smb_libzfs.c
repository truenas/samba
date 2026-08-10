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
#include <inttypes.h>
#include <string.h>
/*
 * The ZFS include paths put libzfs/sys ahead of the system include
 * directory, so <mntent.h> resolves to ZFS's sys/mntent.h (mount option
 * name constants) rather than the libc header. libspl's sys/mnttab.h
 * compat shim (pulled in via libzfs.h) needs struct mntent and
 * hasmntopt() from the shadowed libc header, so declare them here.
 */
#include <mntent.h>
#ifndef hasmntopt
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
#include "lib/util/dlinklist.h"
#include "lib/util/fault.h"
#include "lib/util/memcache.h"
#include "lib/util/memory.h"
#include "lib/util/unix_match.h"
#include "smb_macros.h"
#include "modules/smb_libzfs.h"
#include "lib/truenas_mount.h"

#define SHADOW_COPY_ZFS_GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

#ifndef ZFSCTL_INO_ROOT
#define ZFSCTL_INO_ROOT     0x0000FFFFFFFFFFFFULL
#endif /* ZFSCTL_INO_ROOT */

/*
 * Bound for the mount ID alias cache. Entries are a pair of mount IDs, so
 * this holds several hundred snapshot automounts; evicting one costs a
 * re-resolve and nothing more.
 */
#define ZFS_ALIAS_CACHE_BYTES (64 * 1024)

/*
 * Cache keys are a one byte tag and the mount ID's raw bytes. memcache
 * orders keys with memcmp() over their length and copies them into the
 * element, so a key needs no text encoding and no terminator: building one
 * is a store and an eight byte copy rather than an snprintf() on every
 * lookup, and these sit on the per-file path through smbfname_to_ds().
 */
#define ZFS_CACHE_KEYLEN (1 + sizeof(uint64_t))
#define ZFS_CACHE_TAG_MNT 'M'
#define ZFS_CACHE_TAG_ALIAS 'A'

typedef struct dataset_entry_internal {
	struct zfs_dataset *ds;		/* published, as a const pointer */
	zfs_handle_t *zhandle;		/* never leaves this library */
} dataset_t;

/*
 * Case sensitivity as reported by ZFS via its superblock mount options
 * (statmount() mnt_opts / show_options).
 */
static const struct {
	enum casesensitivity sens;
	const char *opt;
} sens_opt_list[] = {
	{SMBZFS_SENSITIVE, "casesensitive"},
	{SMBZFS_INSENSITIVE, "caseinsensitive"},
	{SMBZFS_MIXED, "casemixed"},
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
};

static const char *group_quota_strings[] =  {
	"groupquota",
	"groupused",
};

static libzfs_handle_t *g_libzfs_handle;
static uint32_t g_refcount;
static struct memcache *global_zcache;
static struct memcache *global_alias_cache;

struct snap_cb
{
	struct snapshot_list *snapshots;
	struct snap_filter *iter_info;
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

/*
 * The dataset cache is keyed by the unique mount ID of the dataset mount.
 * Unique mount IDs are never reused within a boot, so unlike the previous
 * dev_t based scheme a cache hit can never refer to a different (since
 * remounted) filesystem.
 *
 * An entry owns the ZFS dataset handle every operation in this library
 * runs against. Handles are never handed out, so nothing outside can be
 * holding one, and the facts we publish (struct zfs_dataset) are handed
 * out as const pointers into the entry rather than copied. That is what
 * makes entries process-lifetime: a caller may hold the pointer for as
 * long as its connection lasts. The cache is bounded by the number of ZFS
 * mounts a given smbd actually serves.
 */

/*
 * The blob points into buf, so it lives exactly as long as the caller's
 * buffer -- which is all memcache needs, since it copies the key.
 */
static DATA_BLOB zfs_cache_key(uint8_t buf[ZFS_CACHE_KEYLEN],
			       uint8_t tag,
			       uint64_t mnt_id)
{
	buf[0] = tag;
	memcpy(&buf[1], &mnt_id, sizeof(mnt_id));

	return data_blob_const(buf, ZFS_CACHE_KEYLEN);
}

static dataset_t *zcache_lookup_dataset(uint64_t mnt_id)
{
	uint8_t key[ZFS_CACHE_KEYLEN];
	dataset_t *out = NULL;
	DATA_BLOB blob;

	blob = zfs_cache_key(key, ZFS_CACHE_TAG_MNT, mnt_id);

	out = memcache_lookup_talloc(global_zcache, ZFS_CACHE, blob);
	return out;
}

static void zcache_add_dataset(dataset_t *ds)
{
	uint8_t key[ZFS_CACHE_KEYLEN];
	DATA_BLOB blob;

	blob = zfs_cache_key(key, ZFS_CACHE_TAG_MNT, ds->ds->mnt_id);

	memcache_add_talloc(global_zcache, ZFS_CACHE, blob, &ds);
}

/*
 * Mount IDs that are not themselves dataset mounts -- those of snapshot
 * automounts, which resolve to the dataset the snapshot belongs to -- get
 * an entry here so that repeated operations on a path inside a snapshot
 * do not repeat the resolution (two statmount() calls and a libzfs open).
 * Values are mount IDs, so eviction costs nothing but a re-resolve.
 */
static void alias_cache_add(uint64_t queried_id, uint64_t dataset_id)
{
	uint8_t key[ZFS_CACHE_KEYLEN];
	uint64_t *value = NULL;
	DATA_BLOB blob;

	/*
	 * ZFS_CACHE is a talloc-typed memcache kind, so the value has to be
	 * a talloc pointer the cache takes over and frees on eviction.
	 */
	value = talloc(NULL, uint64_t);
	if (value == NULL) {
		/* the alias only saves work; losing it is not an error */
		return;
	}
	*value = dataset_id;

	blob = zfs_cache_key(key, ZFS_CACHE_TAG_ALIAS, queried_id);

	memcache_add_talloc(global_alias_cache, ZFS_CACHE, blob, &value);
}

static bool alias_cache_lookup(uint64_t queried_id, uint64_t *dataset_id)
{
	uint8_t key[ZFS_CACHE_KEYLEN];
	uint64_t *value = NULL;
	DATA_BLOB blob;

	blob = zfs_cache_key(key, ZFS_CACHE_TAG_ALIAS, queried_id);

	value = memcache_lookup_talloc(global_alias_cache, ZFS_CACHE, blob);
	if (value == NULL) {
		return false;
	}
	*dataset_id = *value;
	return true;
}

/*
 * A cache entry owns its dataset handle outright.
 */
static int dataset_entry_destructor(dataset_t *entry)
{
	if (entry->zhandle != NULL) {
		zfs_close(entry->zhandle);
		entry->zhandle = NULL;
	}
	global_handle_decref();
	return 0;
}

static libzfs_handle_t *get_global_smblibzfs_handle() {
	global_handle_incref();
	return g_libzfs_handle;
}

/*
 * ZFS reports the dataset name as the mount source: pool/ds for a
 * dataset, pool/ds@snap for a snapshot automount below
 * <mp>/.zfs/snapshot/<snap>.
 */
static bool entry_is_zfs(const struct tn_mount_entry *entry)
{
	if (entry->sb_magic != 0) {
		return entry->sb_magic == ZFS_SUPER_MAGIC;
	}
	return (entry->fs_type != NULL) &&
	       (strcmp(entry->fs_type, "zfs") == 0);
}

static bool entry_is_zfs_snapshot(const struct tn_mount_entry *entry)
{
	if (!entry_is_zfs(entry) || (entry->sb_source == NULL)) {
		return false;
	}
	return strchr(entry->sb_source, '@') != NULL;
}

/* The dataset name for a mount, without any @snapshot suffix. */
static char *entry_base_dataset_name(TALLOC_CTX *mem_ctx,
				     const struct tn_mount_entry *entry)
{
	const char *at = NULL;

	if (!entry_is_zfs(entry) || (entry->sb_source == NULL)) {
		errno = EINVAL;
		return NULL;
	}

	at = strchr(entry->sb_source, '@');
	if (at == NULL) {
		return talloc_strdup(mem_ctx, entry->sb_source);
	}
	return talloc_strndup(mem_ctx, entry->sb_source,
			      PTR_DIFF(at, entry->sb_source));
}

struct find_dataset_state {
	const char *dataset;
	TALLOC_CTX *mem_ctx;
	struct tn_mount_entry *found;
};

static bool find_dataset_cb(const struct tn_mount_entry *entry,
			    void *private_data)
{
	struct find_dataset_state *state = private_data;

	if (!entry_is_zfs(entry) ||
	    (entry->sb_source == NULL) ||
	    (strcmp(entry->sb_source, state->dataset) != 0)) {
		return true;
	}

	state->found = tn_mount_entry_copy(state->mem_ctx, entry);
	SMB_ASSERT(state->found != NULL);
	return false;
}

/*
 * Find the mount of a dataset by exact name. Works uniformly for datasets
 * with mountpoint=legacy.
 *
 * A dataset can be mounted more than once -- a bind mount or a second
 * legacy mount each get their own mount ID while reporting the same
 * dataset as the mount source -- so the search is scoped to the mounts
 * below parent_mnt_id whenever the caller knows which one it wants.
 * TN_MOUNT_NS_ROOT searches the whole mount namespace.
 */
static int find_zfs_dataset_mount(TALLOC_CTX *mem_ctx,
				  uint64_t parent_mnt_id,
				  const char *dataset,
				  struct tn_mount_entry **entry_out)
{
	struct find_dataset_state state = {
		.dataset = dataset,
		.mem_ctx = mem_ctx,
	};
	int ret;

	ret = tn_mount_traverse(parent_mnt_id, false, find_dataset_cb,
				&state);
	if (ret != 0) {
		return -1;
	}
	if (state.found == NULL) {
		DBG_INFO("%s: dataset is not mounted\n", dataset);
		errno = ENOENT;
		return -1;
	}

	*entry_out = state.found;
	return 0;
}

/*
 * Resolve the mount entry backing a location to the entry of the regular
 * dataset mount. For a location inside a ZFS snapshot automount this is
 * the mount of the dataset itself. This may legitimately be encountered
 * when Samba's VFS hands us a location within the ZFS ctldir, for
 * example for VSS or an FSRVP snapshot share.
 */
static int entry_resolve_base(TALLOC_CTX *mem_ctx,
			      struct tn_mount_entry **pentry)
{
	struct tn_mount_entry *entry = *pentry;
	struct tn_mount_entry *parent = NULL;
	char *base_name = NULL;
	int ret;

	if (!entry_is_zfs_snapshot(entry)) {
		return 0;
	}

	base_name = entry_base_dataset_name(mem_ctx, entry);
	if (base_name == NULL) {
		return -1;
	}

	/*
	 * Snapshot automounts appear on <mp>/.zfs/snapshot/<snap>, so the
	 * parent mount is normally the dataset mount itself. Fall back to
	 * scanning the mount namespace if it is not.
	 */
	ret = tn_mount_entry_get(mem_ctx, entry->mnt_parent_id, &parent);
	if ((ret != 0) ||
	    !entry_is_zfs(parent) ||
	    (parent->sb_source == NULL) ||
	    (strcmp(parent->sb_source, base_name) != 0)) {
		/*
		 * The dataset mount is an ancestor of the snapshot mount
		 * rather than a descendant, so there is no subtree to scope
		 * the search to.
		 */
		TALLOC_FREE(parent);
		ret = find_zfs_dataset_mount(mem_ctx, TN_MOUNT_NS_ROOT,
					     base_name, &parent);
		if (ret != 0) {
			DBG_ERR("%s: failed to locate dataset mount for "
				"snapshot mount [%s]: %s\n",
				base_name, entry->sb_source, strerror(errno));
			TALLOC_FREE(base_name);
			return -1;
		}
	}

	TALLOC_FREE(base_name);
	TALLOC_FREE(*pentry);
	*pentry = parent;
	return 0;
}

static zfs_handle_t *zhandle_from_entry(libzfs_handle_t *lz,
					const struct tn_mount_entry *entry)
{
	zfs_handle_t *zfsp = NULL;

	zfsp = zfs_open(lz, entry->sb_source, ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL) {
		DBG_ERR("%s: zfs_open() failed: %s\n",
			entry->sb_source, libzfs_error_description(lz));
	}
	return zfsp;
}

bool inode_is_ctldir(ino_t ino)
{
	return ino == ZFSCTL_INO_ROOT ? true : false;
}

/*
 * Resolve a mount ID to its cache entry, opening the dataset and filling
 * the entry in on a miss. The entry, and so the ZFS dataset handle it
 * owns, belongs to the cache: callers borrow it for the duration of an
 * operation and never free it.
 */
static dataset_t *mntid_get_entry(uint64_t mnt_id);

/*
 * The ZFS dataset handle for a mount ID. Every operation this library
 * exposes goes through here rather than taking a handle from its caller.
 */
static zfs_handle_t *mntid_get_zhandle_cached(uint64_t mnt_id)
{
	dataset_t *entry = NULL;

	entry = mntid_get_entry(mnt_id);
	if (entry == NULL) {
		return NULL;
	}
	return entry->zhandle;
}

struct zfs_quota_singleton_cache
{
	struct zfs_quota qt;
	uint64_t mnt_id;
	uint64_t xid;
	time_t ts;
	bool valid;
};

struct zfs_quota_singleton_cache cached_quota[SMBZFS_GROUP_QUOTA + 1];
#define ZFS_QUOTA_TIMEOUT 10

static bool
smb_zfs_get_cached_quota(uint64_t mnt_id,
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
	if (!cache->valid || (cache->mnt_id != mnt_id) ||
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
smb_zfs_set_cached_quota(uint64_t mnt_id,
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
		.mnt_id = mnt_id,
		.xid = xid,
		.valid = valid
	};
	memcpy(&cache->qt, qt, sizeof(struct zfs_quota));
	time(&cache->ts);
}

int
smb_zfs_get_quota(uint64_t mnt_id,
		  uint64_t xid,
		  enum zfs_quotatype quota_type,
		  struct zfs_quota *qt)
{
	int i;
	bool cached;
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	char req[ZFS_MAXPROPLEN] = { 0 };
	uint64_t rv[2] = { 0 };

	cached = smb_zfs_get_cached_quota(mnt_id, xid, quota_type, qt);
	if (cached) {
		return 0;
	}

	zfsp = mntid_get_zhandle_cached(mnt_id);
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
	default:
		DBG_ERR("Received unknown quota type (%d)\n", quota_type);
		return -1;
	}

	qt->bytes = rv[0] / blocksize;
	qt->bytes_used = rv[1] / blocksize;
	qt->quota_type = quota_type;
	smb_zfs_set_cached_quota(mnt_id, xid, quota_type, qt, true);
	return 0;
}

int
smb_zfs_set_quota(uint64_t mnt_id, uint64_t xid, struct zfs_quota qt)
{
	int rv;
	zfs_handle_t *zfsp = NULL;
	char qr[ZFS_MAXPROPLEN] = { 0 };
	char quota[ZFS_MAXPROPLEN] = { 0 };

	if (xid == 0) {
		DBG_ERR("Setting quota on id 0 is not permitted\n");
		errno = EPERM;
		return -1;
	}

	zfsp = mntid_get_zhandle_cached(mnt_id);
	if (zfsp == NULL) {
		return -1;
	}

	switch (qt.quota_type) {
	case SMBZFS_USER_QUOTA:
		snprintf(qr, sizeof(qr), "userquota@%lu", xid);
		break;
	case SMBZFS_GROUP_QUOTA:
		snprintf(qr, sizeof(qr), "groupquota@%lu", xid);
		break;
	default:
		DBG_ERR("Received unknown quota type (%d)\n", qt.quota_type);
		return -1;
	}

	snprintf(quota, sizeof(quota), "%lu", qt.bytes);
	smb_zfs_set_cached_quota(mnt_id, xid, qt.quota_type, &qt, false);
	rv = zfs_prop_set(zfsp, qr, quota);
	if (rv != 0) {
		DBG_ERR("Failed to set (%s = %s)\n", qr, quota);
		return -1;
	}

	return 0;
}

uint64_t
smb_zfs_disk_free(uint64_t mnt_id,
		  uint64_t *bsize, uint64_t *dfree,
		  uint64_t *dsize)
{
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	uint64_t available, usedbysnapshots, usedbydataset,
		usedbychildren, real_used, total;

	zfsp = mntid_get_zhandle_cached(mnt_id);
	if (zfsp == NULL) {
		/* the caller falls back to the next VFS module */
		return (uint64_t)-1;
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

/* the nearest ancestor of a path that exists, which need not be a mount */
static int
existing_parent_name(const char *path,
		     char *buf,
		     size_t buflen)
{
	char *slashp = NULL;

	strlcpy(buf, path, buflen);
	for (;;) {
		slashp = strrchr(buf, '/');
		if (slashp == NULL) {
			return -1;
		}
		*slashp = '\0';
		if (access(buf, F_OK) == 0) {
			break;
		}
	}
	return 0;
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

/*
 * Resolve a dataset by name via its mount entry below parent_mnt_id. This
 * is the name-based counterpart of smb_zfs_lookup_dataset() and
 * requires the dataset to be mounted.
 */
static const struct zfs_dataset *name_get_dataset(uint64_t parent_mnt_id,
						  const char *dsname)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct tn_mount_entry *entry = NULL;
	const struct zfs_dataset *out = NULL;
	int ret;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ret = find_zfs_dataset_mount(tmp_ctx, parent_mnt_id, dsname, &entry);
	if (ret != 0) {
		DBG_ERR("%s: failed to find dataset mount: %s\n",
			dsname, strerror(errno));
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	out = smb_zfs_lookup_dataset(entry->mnt_id);
	TALLOC_FREE(tmp_ctx);
	return out;
}

int
smb_zfs_create_dataset(TALLOC_CTX *mem_ctx,
		       const char *path, const char *quota,
		       const struct zfs_dataset ***_array_out,
		       size_t *_nentries,
		       bool create_ancestors)
{
	int rv = -1;
	int error;
	int to_create;
	int i;
	size_t mp_len;
	char parent[PATH_MAX] = {0};
	const char *relative = NULL;
	const char *p = NULL;
	char *target_ds = NULL;
	char *name = NULL;
	struct tn_mount_entry *parent_entry = NULL;
	const struct zfs_dataset **ds_array = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	libzfs_handle_t *lz = NULL;

	lz = get_global_smblibzfs_handle();

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	if (access(path, F_OK) == 0) {
		DBG_ERR("Path %s already exists.\n", path);
		errno = EEXIST;
		goto fail;
	}

	error = existing_parent_name(path, parent, sizeof(parent));
	if (error) {
		DBG_ERR("Unable to access parent of %s\n", path);
		errno = ENOENT;
		goto fail;
	}

	/*
	 * The nearest existing ancestor gives us the dataset the new
	 * datasets nest under. Its mount entry maps the path to the
	 * dataset name to create: the dataset name plus the path
	 * relative to the mountpoint.
	 */
	error = tn_mount_entry_get_path(tmp_ctx, parent, &parent_entry);
	if (error != 0) {
		DBG_ERR("%s: failed to look up mount entry: %s\n",
			parent, strerror(errno));
		goto fail;
	}
	if (!entry_is_zfs(parent_entry) ||
	    (parent_entry->sb_source == NULL) ||
	    (parent_entry->mnt_point == NULL)) {
		DBG_ERR("%s: not a ZFS filesystem\n", parent);
		errno = ENOTSUP;
		goto fail;
	}

	mp_len = strlen(parent_entry->mnt_point);
	if (strncmp(path, parent_entry->mnt_point, mp_len) != 0) {
		DBG_ERR("%s: path does not lie below mountpoint [%s]\n",
			path, parent_entry->mnt_point);
		errno = EINVAL;
		goto fail;
	}
	relative = path + mp_len;
	while (*relative == '/') {
		relative++;
	}

	target_ds = talloc_asprintf(tmp_ctx, "%s/%s",
				    parent_entry->sb_source, relative);
	if (target_ds == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	/*
	 * How many datasets have to exist below the anchor, which is what
	 * decides whether ancestors are needed -- not how many path
	 * components are missing. The nearest existing ancestor of the path
	 * may be a plain directory inside the anchor dataset, in which case
	 * a dataset has to be created for it too.
	 */
	to_create = 1;
	for (p = relative; *p != '\0'; p++) {
		if (*p == '/') {
			to_create++;
		}
	}

	if (create_ancestors) {
		/* a no-op when every ancestor dataset already exists */
		rv = zfs_create_ancestors(lz, target_ds);
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

	error = create_dataset_internal(lz, target_ds, quota);
	if (error) {
		rv = -1;
		goto fail;
	}

	/*
	 * Return the created datasets, deepest first, plus the pre-existing
	 * dataset they nest under. Every dataset we created is mounted
	 * somewhere below that one, so each is found by name in a
	 * listmount() of its subtree rather than by scanning the whole
	 * mount namespace: the same dataset mounted a second time elsewhere
	 * is a different mount and must not match here.
	 */
	ds_array = talloc_zero_array(mem_ctx, const struct zfs_dataset *,
				     to_create + 1);
	if (ds_array == NULL) {
		errno = ENOMEM;
		rv = -1;
		goto fail;
	}

	name = talloc_strdup(tmp_ctx, target_ds);
	if (name == NULL) {
		TALLOC_FREE(ds_array);
		errno = ENOMEM;
		rv = -1;
		goto fail;
	}

	for (i = 0; i < to_create; i++) {
		char *slashp = NULL;

		ds_array[i] = name_get_dataset(parent_entry->mnt_id, name);
		if (ds_array[i] == NULL) {
			DBG_ERR("Failed to generate dataset list for %s\n",
				path);
			TALLOC_FREE(ds_array);
			rv = -1;
			goto fail;
		}

		slashp = strrchr(name, '/');
		SMB_ASSERT(slashp != NULL);
		*slashp = '\0';
	}

	/*
	 * The anchor is the mount we already resolved from the nearest
	 * existing ancestor of the path. It is not necessarily named by any
	 * prefix of the new dataset name: the ancestor may be a plain
	 * directory inside the dataset, as it is for a share of a
	 * subdirectory.
	 */
	ds_array[to_create] = smb_zfs_lookup_dataset(parent_entry->mnt_id);
	if (ds_array[to_create] == NULL) {
		DBG_ERR("%s: failed to look up dataset for mount ID %" PRIx64
			": %s\n", path, parent_entry->mnt_id, strerror(errno));
		TALLOC_FREE(ds_array);
		rv = -1;
		goto fail;
	}

	*_array_out = ds_array;
	*_nentries = (size_t)to_create + 1;
	rv = 0;
fail:
	TALLOC_FREE(tmp_ctx);
	/*
	 * The datasets we resolved above hold their own references; this
	 * one was only needed for the creation itself.
	 */
	global_handle_decref();
	return rv;
}

static int
zhandle_get_props(zfs_handle_t *zfsp,
		  struct zfs_dataset_prop *props)
{
	char buf[ZFS_MAXPROPLEN];
	zprop_source_t sourcetype;

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

	props->record_size = zfs_prop_get_int(zfsp, ZFS_PROP_RECORDSIZE);
	return 0;
}

static void init_global_caches(void)
{
	if (global_zcache == NULL) {
		global_zcache = memcache_init(NULL, 0);
		SMB_ASSERT(global_zcache != NULL);
	}
	if (global_alias_cache == NULL) {
		global_alias_cache = memcache_init(NULL,
						   ZFS_ALIAS_CACHE_BYTES);
		SMB_ASSERT(global_alias_cache != NULL);
	}
}

/*
 * Build the cache entry for a dataset mount: the ZFS dataset handle the
 * entry owns, plus the facts we publish about it. The mount entry has
 * already been resolved to the dataset mount by the caller.
 *
 * The dataset handle and its reference on the global libzfs handle are
 * consumed either way -- on failure they are released here.
 */
static dataset_t *dataset_entry_create(const struct tn_mount_entry *entry,
				       zfs_handle_t *zfsp)
{
	dataset_t *dsentry = NULL;
	struct zfs_dataset *ds = NULL;
	int ret;
	int i;

	dsentry = talloc_zero(global_zcache, dataset_t);
	if (dsentry == NULL) {
		zfs_close(zfsp);
		global_handle_decref();
		errno = ENOMEM;
		return NULL;
	}
	dsentry->zhandle = zfsp;
	talloc_set_destructor(dsentry, dataset_entry_destructor);

	ds = talloc_zero(dsentry, struct zfs_dataset);
	if (ds == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	dsentry->ds = ds;

	strlcpy(ds->dataset_name, entry->sb_source,
		sizeof(ds->dataset_name));
	strlcpy(ds->mountpoint, entry->mnt_point, sizeof(ds->mountpoint));
	ds->mnt_id = entry->mnt_id;

	ds->properties = talloc_zero(ds, struct zfs_dataset_prop);
	if (ds->properties == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	/*
	 * Case sensitivity and the read-only state are reported through
	 * the mount table; only the remaining properties need libzfs.
	 */
	ds->properties->casesens = SMBZFS_SENSITIVE;
	for (i = 0; i < ARRAY_SIZE(sens_opt_list); i++) {
		if (tn_mount_has_opt(entry, sens_opt_list[i].opt)) {
			ds->properties->casesens = sens_opt_list[i].sens;
			break;
		}
	}
	ds->properties->readonly = tn_mount_is_readonly(entry);

	ret = zhandle_get_props(zfsp, ds->properties);
	if (ret != 0) {
		DBG_ERR("%s: failed to get dataset properties\n",
			ds->dataset_name);
		goto fail;
	}

	return dsentry;

fail:
	/*
	 * The entry owns the handle from the point it was attached, so
	 * unwinding here closes it exactly once.
	 */
	TALLOC_FREE(dsentry);
	return NULL;
}

static dataset_t *mntid_get_entry(uint64_t mnt_id)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct tn_mount_entry *entry = NULL;
	dataset_t *dsentry = NULL;
	zfs_handle_t *zfsp = NULL;
	libzfs_handle_t *lz = NULL;
	uint64_t dataset_id;
	bool found;
	int ret;

	if (mnt_id == 0) {
		DBG_ERR("Refusing to resolve a zero mount ID\n");
		errno = ENOTSUP;
		return NULL;
	}

	init_global_caches();

	/*
	 * A mount ID we have seen before is answered without any syscall
	 * or libzfs call at all. Mount IDs that are not dataset mounts --
	 * snapshot automounts -- reach their dataset through the alias
	 * recorded the first time they were resolved.
	 */
	dsentry = zcache_lookup_dataset(mnt_id);
	if (dsentry != NULL) {
		return dsentry;
	}

	found = alias_cache_lookup(mnt_id, &dataset_id);
	if (found) {
		dsentry = zcache_lookup_dataset(dataset_id);
		if (dsentry != NULL) {
			return dsentry;
		}
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ret = tn_mount_entry_get(tmp_ctx, mnt_id, &entry);
	if (ret != 0) {
		DBG_ERR("Failed to look up mount entry for mount ID "
			"%" PRIx64 ": %s\n", mnt_id, strerror(errno));
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	if (!entry_is_zfs(entry) || (entry->sb_source == NULL)) {
		DBG_INFO("mount ID %" PRIx64 ": not a ZFS filesystem "
			 "[%s]\n", mnt_id,
			 entry->fs_type ? entry->fs_type : "unknown");
		TALLOC_FREE(tmp_ctx);
		errno = ENOTSUP;
		return NULL;
	}

	ret = entry_resolve_base(tmp_ctx, &entry);
	if (ret != 0) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	if (entry->mnt_point == NULL) {
		DBG_ERR("Kernel did not report a mountpoint for mount ID "
			"%" PRIx64 "\n", entry->mnt_id);
		TALLOC_FREE(tmp_ctx);
		errno = EINVAL;
		return NULL;
	}

	if (entry->mnt_id != mnt_id) {
		/* a snapshot automount: remember where it resolved to */
		alias_cache_add(mnt_id, entry->mnt_id);

		dsentry = zcache_lookup_dataset(entry->mnt_id);
		if (dsentry != NULL) {
			TALLOC_FREE(tmp_ctx);
			return dsentry;
		}
	}

	lz = get_global_smblibzfs_handle();
	zfsp = zhandle_from_entry(lz, entry);
	if (zfsp == NULL) {
		global_handle_decref();
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	/* the entry takes over both the handle and its libzfs reference */
	dsentry = dataset_entry_create(entry, zfsp);
	TALLOC_FREE(tmp_ctx);
	if (dsentry == NULL) {
		return NULL;
	}

	zcache_add_dataset(dsentry);
	return dsentry;
}

const struct zfs_dataset *smb_zfs_lookup_dataset(uint64_t mnt_id)
{
	dataset_t *dsentry = NULL;

	dsentry = mntid_get_entry(mnt_id);
	if (dsentry == NULL) {
		return NULL;
	}
	return dsentry->ds;
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
snapshot_list *smb_zfs_list_snapshots(TALLOC_CTX *mem_ctx,
				      uint64_t mnt_id,
				      struct snap_filter *iter_info)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct snap_cb *state = NULL;
	struct snapshot_list *snapshots = NULL;
	int rc;
	zfs_handle_t *zfs = NULL;
	dataset_t *dsentry = NULL;

	dsentry = mntid_get_entry(mnt_id);
	if (dsentry == NULL) {
		return NULL;
	}
	zfs = dsentry->zhandle;

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

	/* name and mountpoint are already known to the cache */
	strlcpy(snapshots->dataset_name, dsentry->ds->dataset_name,
		sizeof(snapshots->dataset_name));
	strlcpy(snapshots->mountpoint, dsentry->ds->mountpoint,
		sizeof(snapshots->mountpoint));

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

bool update_snapshot_list(uint64_t mnt_id,
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

	zfs = mntid_get_zhandle_cached(mnt_id);
	if (zfs == NULL) {
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	state->iter_info = iter_info;
	state->snapshots = snaps;
	state->iter_info->start_txg = snaps->last->createtxg;

	rc = zfs_iter_snapshots_sorted(zfs, smb_zfs_add_snapshot,
				       state, snaps->last->createtxg, 0);

	time(&snaps->timestamp);
	TALLOC_FREE(tmp_ctx);
	return true;
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
smb_zfs_snapshot(uint64_t mnt_id,
		 const char *snapshot_name,
		 bool recursive)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	char snap[ZFS_MAXPROPLEN] = {0};
	const char *dataset_name;

	zfsp = mntid_get_zhandle_cached(mnt_id);
	if (zfsp == NULL) {
		return -1;
	}
	dataset_name = zfs_get_name(zfsp);
	ret = snprintf(snap, sizeof(snap), "%s@%s",
		       dataset_name, snapshot_name);
	if (ret < 0) {
		DBG_ERR("Failed to format snapshot name:%s\n",
			strerror(errno));
		return -1;
	}
	ret = zfs_snapshot(zfs_get_handle(zfsp), snap, recursive, NULL);
	if (ret != 0) {
		DBG_ERR("Failed to create snapshot %s: %s\n",
			snap, strerror(errno));
	}
	return ret;
}

bool
smb_zfs_pool_feature_enabled(uint64_t mnt_id,
			     enum zfs_feature feature,
			     bool *enabled_out)
{
	zfs_handle_t *zfsp = NULL;
	zpool_handle_t *pool = NULL;
	char statebuf[64] = {0};
	int error, i;
	bool enabled;
	const char *feature_name = NULL;

	for (i = 0; i < ARRAY_SIZE(zfs_feature_enum_list); i++) {
		if (zfs_feature_enum_list[i].feature == feature) {
			feature_name = zfs_feature_enum_list[i].feature_str;
			break;
		}
	}

	SMB_ASSERT(feature_name != NULL);

	zfsp = mntid_get_zhandle_cached(mnt_id);
	if (zfsp == NULL) {
		return false;
	}

	pool = zfs_get_pool_handle(zfsp);
	if (pool == NULL) {
		DBG_ERR("%s: pool handle not initialized\n",
			zfs_get_name(zfsp));
		return false;
	}
	error = zpool_prop_get_feature(pool, feature_name,
				       statebuf, sizeof(statebuf));

	if (error) {
		DBG_ERR("%s: failed to retrieve status of %s: %s\n",
			zfs_get_name(zfsp), feature_name, strerror(error));
		return false;
	}

	if ((strcmp(statebuf, "enabled") == 0) ||
	    (strcmp(statebuf, "active") == 0)) {
		*enabled_out = true;

	} else {
		DBG_INFO("%s: %s on dataset [%s] is not active\n",
			 statebuf, feature_name, zfs_get_name(zfsp));

		*enabled_out = false;
	}

	return true;
}

int conn_zfs_init(const char *connectpath,
		  const struct zfs_dataset **pds)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct tn_mount_entry *entry = NULL;
	const struct zfs_dataset *ds = NULL;
	uint64_t mnt_id;
	bool is_zfs;
	int ret;

	*pds = NULL;

	ret = tn_mount_path_get_mnt_id(connectpath, &mnt_id);
	if ((ret != 0) && (errno == ENOENT)) {
		char parent[PATH_MAX] = {0};

		ret = existing_parent_name(connectpath, parent,
					   sizeof(parent));
		if (ret == 0) {
			DBG_INFO("Path [%s] does not exist, resolving "
				 "dataset from path [%s]\n",
				 connectpath, parent);
			ret = tn_mount_path_get_mnt_id(parent, &mnt_id);
		}
	}
	if (ret != 0) {
		DBG_ERR("%s: failed to look up mount ID: %s\n",
			connectpath, strerror(errno));
		return -1;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ret = tn_mount_entry_get(tmp_ctx, mnt_id, &entry);
	if (ret != 0) {
		DBG_ERR("%s: failed to look up mount entry: %s\n",
			connectpath, strerror(errno));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	is_zfs = entry_is_zfs(entry);
	TALLOC_FREE(tmp_ctx);

	if (!is_zfs) {
		/*
		 * Not an error. A NULL dataset with a return value of 0
		 * tells the caller that the share is not on ZFS.
		 */
		DBG_INFO("%s: filesystem is not ZFS\n", connectpath);
		return 0;
	}

	/*
	 * A connectpath inside a ZFS snapshot automount (a share
	 * dynamically created by FSRVP to expose a snapshot) is
	 * transparently resolved to the underlying dataset.
	 */
	ds = smb_zfs_lookup_dataset(mnt_id);
	if (ds == NULL) {
		DBG_ERR("%s: failed to look up dataset for mount ID %" PRIx64
			": %s\n", connectpath, mnt_id, strerror(errno));
		return -1;
	}

	*pds = ds;
	return 0;
}
