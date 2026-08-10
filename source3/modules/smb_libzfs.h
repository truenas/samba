/*-
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

#ifndef	__SMB_LIBZFS_H
#define	__SMB_LIBZFS_H
#include <pwd.h>
#include <talloc.h>

#define SMBGMT_NAMELEN 25
#define ZFSDS_NAMELEN 256
/*
 * Maximum length dataset name is 256 characters
 */
struct snapshot_entry
{
	uint64_t createtxg;
	char label[SMBGMT_NAMELEN];	/* @GMT-prefixed label for snapshot */
	char name[ZFSDS_NAMELEN];	/* name of snapshot */
	time_t cr_time;			/* creation time of snapshot */
	NTTIME nt_time;			/* creation time as nt_time */
	struct snapshot_entry *prev, *next;
};

struct snapshot_list
{
	time_t timestamp;			/* when list generated */
	char mountpoint[PATH_MAX];		/* mountpoint of underlying ds */
	char dataset_name[ZFSDS_NAMELEN];	/* ZFS dataset name */
	size_t num_entries;			/* number of entries in snapshot list */
	struct snapshot_entry *entries;
	struct snapshot_entry *last;
};

struct snap_filter
{
	bool ignore_empty_snaps;
	char **inclusions;
	char **exclusions;
	time_t start;
	time_t end;
	uint64_t start_txg;
	uint64_t end_txg;
};

enum casesensitivity {SMBZFS_SENSITIVE, SMBZFS_INSENSITIVE, SMBZFS_MIXED};

enum zfs_quotatype {
	SMBZFS_USER_QUOTA = 0,
	SMBZFS_GROUP_QUOTA,
};

enum zfs_snapdir_type {
	SMBZFS_SNAPDIR_HIDDEN,
	SMBZFS_SNAPDIR_VISIBLE,
	SMBZFS_SNAPDIR_DISABLED
};

enum zfs_feature {SMBZFS_BLOCK_CLONING};

struct zfs_quota {
	enum zfs_quotatype quota_type;
	uint64_t bytes;
	uint64_t bytes_used;
};

struct zfs_dataset_prop
{
	enum casesensitivity casesens;
	enum zfs_snapdir_type snapdir;
	bool readonly;
	bool checksum_enabled;
	uint64_t record_size;
};

/*
 * Facts about a mounted ZFS dataset. Instances are owned by the library
 * and live for the life of the process: callers hold const pointers to
 * them and never free or modify one. The ZFS dataset handle behind an
 * instance is internal -- every operation below takes the mount ID and
 * looks the handle up, so a handle is never shared with a caller.
 */
struct zfs_dataset
{
	char dataset_name[ZFSDS_NAMELEN];
	char mountpoint[PATH_MAX];
	uint64_t mnt_id;	/* unique mount ID of the dataset mount */
	struct zfs_dataset_prop *properties;
};

/*
 * Look up the dataset backing a unique mount ID (st_ex_mnt_id in any
 * SMB_STRUCT_STAT). Mount IDs of snapshot automounts resolve to the
 * dataset the snapshot belongs to.
 *
 * @param[in]	mnt_id		unique mount ID
 *
 * @return	dataset, or NULL with errno set: ENOTSUP when the mount is
 *		not ZFS, otherwise the failure of the lookup itself
 */
const struct zfs_dataset *smb_zfs_lookup_dataset(uint64_t mnt_id);

/*
 * Get userspace quotas for a given mount, ID, and quota type.
 * @param[in]	mnt_id			mount ID of the dataset
 * @param[in]	xid		 	user id or group id.
 * @param[in]	quota_type	 	quota type
 * @param[out]	qt			zfs_quota struct with quota info
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_get_quota(uint64_t mnt_id,
		      uint64_t xid,
		      enum zfs_quotatype quota_type,
		      struct zfs_quota *qt);

/*
 * Set userspace quotas for a given mount, ID, and quota type. May
 * fail with EPERM if user lacks permissions to set quota.
 * @param[in]	mnt_id			mount ID of the dataset
 * @param[in]	xid		 	user id or group id.
 * @param[in]	qt		 	struct containing quota info
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_set_quota(uint64_t mnt_id,
		      uint64_t xid,
		      struct zfs_quota qt);

uint64_t smb_zfs_disk_free(uint64_t mnt_id,
			   uint64_t *bsize,
			   uint64_t *dfree,
			   uint64_t *dsize);

/*
 * Create a dataset with a given quota (NULL for no quota). Optionally,
 * create any intermediate datasets required to fill out the specified path.
 * For example, a dataset zroot/share exists and is mounted at /. If the
 * path "/zroot/share/foo/bar" is specified along with `create_ancestors`,
 * then the datasets zroot/share/foo and zroot/share/foo/bar will be created
 * and mounted. In this situation, the specified `quota` will only be
 * applied to "zroot/share/foo/bar", and not to the intermediate datasets.
 *
 * The datasets that have to exist are counted below the dataset the path
 * already lies in, so the nearest existing ancestor of the path being a
 * plain directory rather than a mountpoint means a dataset is created for
 * it too -- and without `create_ancestors` that is refused rather than
 * done silently.
 *
 * @param[in]	mem_ctx			memory context for the returned
 *					array itself
 * @para[in]	path			path to be created.
 * @para[in]	quota			quota to set on final dataset.
 * @para[out]	_array_out		array of the datasets created,
 *					deepest first, followed by the
 *					pre-existing dataset they nest under.
 *					The array is allocated under mem_ctx;
 *					its elements are owned by the library
 *					and must not be freed (see
 *					smb_zfs_lookup_dataset()).
 * @para[out]	_nentries		number of datasets.
 * @para[in]	create_ancestors	create intermediate datasets.
 *
 * @return	0 on success -1 on failure.
 */
int smb_zfs_create_dataset(TALLOC_CTX *mem_ctx,
			   const char *path, const char *quota,
			   const struct zfs_dataset ***_array_out,
			   size_t *_nentries,
			   bool create_ancestors);

/*
 * This function returns a list of ZFS snapshots matching the specified
 * filters, allocated under a user-provided talloc memory context. Returns
 * NULL on error.
 *
 * @param[in]	mnt_id			mount ID of the dataset.
 * @param[in]	mem_ctx			talloc memory context
 * @param[in]	ignore_empty_snaps	ignore snapshots with zero space used
 * @param[in]	inclusions		list of filters to determine whether to
 *					include a snapshot
 * @param[in]	exclusions		list of filters to determine whether to
 *					exclude a snapshot
 * @param[in]	start			snapshots with create time greater than
 *					this will be included
 * @param[in]	end			snapshots with create time less than
 *					this will be included
 *
 * @return	struct snapshot_list
 */
struct snapshot_list *smb_zfs_list_snapshots(TALLOC_CTX *mem_ctx,
					     uint64_t mnt_id,
					     struct snap_filter *filter);

bool update_snapshot_list(uint64_t mnt_id,
			  struct snapshot_list *snaps,
			  struct snap_filter *filter);

/*
 * Delete a list of ZFS snapshots. List is converted into an nvlist
 * and deletion performed in single ZFS ioctl. Required parts of
 * snapshot list are snaps->dataset_name, and entry->name for entries.
 *
 * @param[in]	snaps			list of snapshots to delete
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_delete_snapshots(struct snapshot_list *snaps);

/*
 * Take a named snapshot of a given dataset.
 * @param[in]	mnt_id			mount ID of the dataset to snapshot
 * @param[in]	snapshot_name		name to give snapshot
 * @param[in]	recursive		snapshot child datasets
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_snapshot(uint64_t mnt_id,
		     const char *snapshot_name,
		     bool recursive);

/*
 * Check whether the specified zpool feature is enabled
 *
 * @param[in] mnt_id - mount ID of a dataset in the pool
 * @param[in] feature - feature to check
 * @param[out] enabled - whether feature is enabled
 *
 * @return - bool true on success else false
 */
bool smb_zfs_pool_feature_enabled(uint64_t mnt_id,
				  enum zfs_feature feature,
				  bool *enabled_out);

/*
 * Initialize global libzfs handle if necessary and look up the
 * dataset for the connectpath. *ppds is set to NULL (with a return
 * value of 0) if the connectpath is not on ZFS.
 *
 * @param[in]	connectpath		connectpath to share.
 * @param[out]	ppds			dataset for connectpath, owned by
 *					the library.
 * @return	0 on success -1 on failure
 */
int conn_zfs_init(const char *connectpath,
		  const struct zfs_dataset **ppds);

bool inode_is_ctldir(ino_t ino);
#endif	/* !__SMB_LIBZFS_H */
