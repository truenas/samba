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

struct smbzhandle;
typedef struct smbzhandle *smbzhandle_t;

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
	SMBZFS_USER_QUOTA,
	SMBZFS_GROUP_QUOTA,
	SMBZFS_DATASET_QUOTA
};

struct zfs_quota {
	enum zfs_quotatype quota_type;
	uint64_t bytes;
	uint64_t bytes_used;
	uint64_t obj;
	uint64_t obj_used;
};

struct zfs_dataset_prop
{
	enum casesensitivity casesens;
	bool readonly;
	bool snapdir_visible;
#if 0 /* Properties we may wish to expose in the future */
	int atime;
	int exec;
	int setuid;
#endif
};

struct zfs_dataset
{
	char dataset_name[ZFSDS_NAMELEN];
	char mountpoint[PATH_MAX];
	smbzhandle_t zhandle;
	dev_t devid;
	struct zfs_dataset_prop *properties;
};

#ifdef DOXYGEN
int get_smbzhandle(TALLOC_CTX *mem_ctx, const char *path,
		   struct smbzhandle **smbzhandle,
		   bool resolve);
#else
#define	get_smbzhandle(mem_ctx, path, smbzhandle, resolve) \
	_get_smbzhandle(mem_ctx, path, smbzhandle, resolve, __location__)
#endif

#ifdef DOXYGEN
int fget_smbzhandle(TALLOC_CTX *mem_ctx, int fd,
                    smbzhandle_t *smbzhandle);
#else
#define	fget_smbzhandle(mem_ctx, fd, smbzhandle) \
	_fget_smbzhandle(mem_ctx, path, smbzhandle, __location__)
#endif

/*
 * Get userspace quotas for a given path, ID, and quota type.
 * @param[in]	hdl			ZFS dataset handle from which to get quota
 * @param[in]	xid		 	user id or group id.
 * @param[in]	quota_type	 	quota type
 * @param[out]	qt			zfs_quota struct with quota info
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_get_quota(struct smbzhandle *hdl,
		      uint64_t xid,
		      enum zfs_quotatype quota_type,
		      struct zfs_quota *qt);

/*
 * Set userspace quotas for a given path, ID, and quota type. May require
 * fail with EPERM if user lacks permissions to set quota.
 * @param[in]	hdl			ZFS dataset handle on which to get quota
 * @param[in]	xid		 	user id or group id.
 * @param[in]	qt		 	struct containing quota info
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_set_quota(struct smbzhandle *hdl,
		      uint64_t xid,
		      struct zfs_quota qt);

uint64_t smb_zfs_disk_free(struct smbzhandle *hdl,
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
 * @param[in]	mem_ctx			memory context under which to
 *					allocate the output dataset_list
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @para[in]	path			path to be created.
 * @para[in]	quota			quota to set on final dataset.
 * @para[out]	_array_out		pointer to array of datasets.
 * @para[out]	_nentries		number of datasets.
 * @para[in]	create_ancestors	create intermediate datasets.
 *
 * @return	0 on success -1 on failure.
 */
int smb_zfs_create_dataset(TALLOC_CTX *mem_ctx,
			   const char *path, const char *quota,
			   struct zfs_dataset ***_array_out,
			   size_t *_nentries,
			   bool create_ancestors);


/*
 * Retrieve the value of a user-defined ZFS dataset property
 * "org.samba:" prefix will be automatically applied.
 *
 * @param[in]	hdl			ZFS dataset from which to retrieve property
 * @param[in]	mem_ctx			talloc memory context
 * @param[in]	prop			property name
 * @param[out]	value			talloc'ed string containing
 *					value of propert.
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_get_user_prop(smbzhandle_t hdl,
			  TALLOC_CTX *mem_ctx,
			  const char *prop,
			  char **value);

/*
 * Set the value of a user-defined ZFS dataset property.
 * "org.samba:" prefix will be automatically applied.
 *
 * @param[in]	hdl			ZFS dataset on which to apply custom
 *					proprety
 * @param[in]	prop			property name
 * @param[out]	value			value to set
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_set_user_prop(smbzhandle_t hdl,
			  const char *prop,
			  const char *value);

/*
 * Returns ZFS dataset information for a given path or dataset name.
 * If get_props is set to True, then ZFS dataset properties are included
 * in the returned zfs_dataset struct.
 */
#ifdef DOXYGEN
struct zfs_dataset *smb_zfs_path_get_dataset(TALLOC_CTX *mem_ctx,
					     const char *path,
					     bool get_props,
					     bool open_zhandle,
					     bool resolve_path);
#else
#define	smb_zfs_path_get_dataset(mem_ctx, path, get_props, open, resolve)\
	(struct zfs_dataset *)_smb_zfs_path_get_dataset(\
		mem_ctx, path, get_props, open, resolve, __location__)

struct zfs_dataset *_smb_zfs_path_get_dataset(TALLOC_CTX *mem_ctx,
					      const char *path,
					      bool get_props,
					      bool open_zhandle,
					      bool resolve_path,
					      const char *location);
#endif

#ifdef DOXYGEN
struct zfs_dataset *smb_zfs_fd_get_dataset(TALLOC_CTX *mem_ctx,
					   int fd,
					   bool get_props,
					   bool open_zhandle);
#else
#define	smb_zfs_fd_get_dataset(mem_ctx, fd, get_props, open_zhandle)\
	(struct zfs_dataset *)_smb_zfs_fd_get_dataset(\
		mem_ctx, fd, get_props, open_zhandle, __location__)

struct zfs_dataset *_smb_zfs_fd_get_dataset(TALLOC_CTX *mem_ctx,
					    int fd,
					    bool get_props,
					    bool open_zhandle,
					    const char *location);
#endif

/*
 * This function returns a list of ZFS snapshots matching the specified
 * filters, allocated under a user-provided talloc memory context. Returns
 * NULL on error. It is a wrapper around zhandle_list_snapshots.
 *
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
					     const char *fs,
					     struct snap_filter *filter);

/*
 * This function returns a list of ZFS snapshots matching the specified
 * filters, allocated under a user-provided talloc memory context. Returns
 * NULL on error.
 *
 * @param[in]	smbzhandle		smbzhandle struct (typically from dataset).
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
struct snapshot_list *zhandle_list_snapshots(smbzhandle_t hdl,
					     TALLOC_CTX *mem_ctx,
					     struct snap_filter *filter);

bool update_snapshot_list(smbzhandle_t hdl,
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
 * Take a named snapshot of a given path.
 * @param[in]	hdl			ZFS dataset handle to snapshot
 * @param[in]	snapshot_name		name to give snapshot
 * @param[in]	recursive		snapshot child datasets
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_snapshot(smbzhandle_t hdl,
		     const char *snapshot_name,
		     bool recursive);

/*
 * Roll back to named snapshot. This is a destructive process.
 * Roll back specified dataset handle to specified snapshot
 * snapshot, discarding any data changes since then and making it the
 * active dataset.
 *
 * Any snapshots and bookmarks more recent than the target are
 * destroyed, along with their dependents (i.e. clones).
 *
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	snapshot_name		name to give snapshot
 * @param[in]	force			forcibly unmount cloned filesystems
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_rollback(smbzhandle_t hdl,
		     const char *snapshot_name,
		     bool force);

/*
 * Roll back to the last successful snapshot. This is a destructive process. All
 * data from after the last snapshot was taken will be destroyed.
 *
 * @param[in]	hdl			target ZFS dataset handle
 * @return	0 on success -1 on failure
 */
int smb_zfs_rollback_last(smbzhandle_t hdl);

/*
 * Initialize global libzfs handle if necessary and populate
 * dataset list for connectpath
 *
 * @param[in]	mem_ctx			talloc memory context on which to hang results.
 * @param[in]	connectpath		connectpath to share.
 * @param[out]	ppdsl			dataset for connectpath.
 * @param[in]	has_tcon		indicates whether talloc ctx is short-lived
 * @return	0 on success -1 on failure
 */
int conn_zfs_init(TALLOC_CTX *mem_ctx,
		  const char *connectpath,
		  struct zfs_dataset **ppds,
		  bool has_tcon);

bool inode_is_ctldir(ino_t ino);
#endif	/* !__SMB_LIBZFS_H */
