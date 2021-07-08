/*-
 * Copyright 2018 iXsystems, Inc.
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

struct smblibzfs_int;
struct smbzhandle_int;

struct smblibzfshandle {
	struct memcache *zcache;
	struct db_context *db;
	struct smblibzfs_int *sli;
};

struct smbzhandle {
	struct smblibzfshandle *lz;
	struct smbzhandle_int *zhp;
	bool is_open;
};

struct snapshot_entry
{
	char label[25];		/* @GMT-prefixed label for snapshot */
	char *name;		/* name of snapshot */
	time_t cr_time;		/* creation time of snapshot */
	NTTIME nt_time;		/* creation time as nt_time */
	struct snapshot_entry *prev, *next;
};

struct snapshot_list
{
	time_t timestamp;	/* when list generated */
	char *mountpoint;	/* mountpoint of ZFS dataset where list taken */
	char *dataset_name;	/* ZFS dataset name that the list is for */
	size_t num_entries;	/* number of entries in snapshot list */
	struct snapshot_entry *entries;
};

enum casesensitivity {SMBZFS_SENSITIVE, SMBZFS_INSENSITIVE, SMBZFS_MIXED};

struct zfs_dataset_prop
{
	enum casesensitivity casesens;
	int readonly;
#if 0 /* Properties we may wish to expose in the future */
	int atime;
	int exec;
	int setuid;
#endif
};

struct zfs_dataset
{
	char *dataset_name;
	char *mountpoint;
	struct smbzhandle *zhandle;
	dev_t devid;
	struct zfs_dataset_prop *properties;
	struct zfs_dataset *prev, *next;
};

struct dataset_list
{
	time_t timestamp;	/* when list generated */
	struct zfs_dataset *root;
	struct zfs_dataset *children;
	size_t nentries;
};

/*
 * Get an smblibzfshandle. This is to allow reuse of the same libzfs handle,
 * which provides performance and efficiency benefits. The libzfs handle will
 * be automatically closed in the destructor function for the smblibzfshandle.
 *
 * @param[in]	mem_ctx			talloc memory context
 * @param[out]	smblibzfsp		smblibzfs handle struct
 *
 * @return	0 on success -1 on failure
 */

int get_smblibzfs_handle(TALLOC_CTX *mem_ctx,struct smblibzfshandle **smblibzfsp);

struct smblibzfshandle *get_global_smblibzfs_handle(TALLOC_CTX *mem_ctx);

int get_smbzhandle(struct smblibzfshandle *smblibzfsp,
		   TALLOC_CTX *mem_ctx, char *path,
		   struct smbzhandle **smbzhandle,
		   bool resolve);

/*
 * Get dataset name for a given path. This is useful because there may be
 * multiple ZFS datasets within a single SMB share.
 *
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	pathname	 	full path in which to get dataset name.
 * @param[out]	dataset_name_out	name of ZFS dataset
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_path_to_dataset(struct smblibzfshandle *smblibzfsp,
			    const char *pathname,
			    const char **dataset_name_out);

/*
 * Get userspace quotas for a given path, ID, and quota type.
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	path		 	the full path in which to get quota.
 * @param[in]	xid		 	user id or group id.
 * @param[in]	quota_type	 	quota type
 * @param[out]	hardlimit	 	quota size in bytes
 * @param[out]	usedspace		space used against quota in bytes
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_get_userspace_quota(struct smblibzfshandle *smblibzfsp,
				char *path,
				int64_t xid,
				int quota_type,
				uint64_t *hardlimit,
				uint64_t *usedspace);

/*
 * Set userspace quotas for a given path, ID, and quota type. May require
 * fail with EPERM if user lacks permissions to set quota.
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	path		 	the full path in which to get quota.
 * @param[in]	xid		 	user id or group id.
 * @param[in]	quota_type	 	quota type
 * @param[in]	hardlimit	 	quota size in bytes
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_set_userspace_quota(struct smblibzfshandle *smblibzfsp,
				char *path,
				int64_t xid,
				int quota_type,
				uint64_t hardlimit,
				uint64_t blocksize);

uint64_t smb_zfs_disk_free(struct smblibzfshandle *smblibzfsp,
			   char *path,
			   uint64_t *bsize,
			   uint64_t *dfree,
			   uint64_t *dsize,
			   uid_t euid);

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
 * @para[out]	created			dataset_list with new dataset(s).
 * @para[in]	create_ancestors	create intermediate datasets.
 *
 * @return	0 on success -1 on failure.
 */
int smb_zfs_create_dataset(TALLOC_CTX *mem_ctx,
			   struct smblibzfshandle *smblibzfsp,
			   const char *path, char *quota,
			   struct dataset_list **created,
			   bool create_ancestors);

/*
 * Retrieve the value of a user-defined ZFS dataset property
 * "org.samba:" prefix will be automatically applied.
 *
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	mem_ctx			talloc memory context
 * @param[in]	path			path on which to retrieve
 *					custom user property
 * @param[in]	prop			property name
 * @param[out]	value			talloc'ed string containing
 *					value of propert.
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_get_user_prop(struct smblibzfshandle *smblibzfsp,
			  TALLOC_CTX *mem_ctx,
			  const char *path,
			  const char *prop,
			  char **value);

/*
 * Set the value of a user-defined ZFS dataset property.
 * "org.samba:" prefix will be automatically applied.
 *
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	path			path on which to set
 *					custom user property
 * @param[in]	prop			property name
 * @param[out]	value			value to set
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_set_user_prop(struct smblibzfshandle *smblibzfsp,
			  const char *path,
			  const char *prop,
			  const char *value);

/*
 * Returns ZFS dataset information for a given path or dataset name.
 * If get_props is set to True, then ZFS dataset properties are included
 * in the returned zfs_dataset struct.
 */
struct zfs_dataset *smb_zfs_path_get_dataset(struct smblibzfshandle *smblibzfsp,
                                             TALLOC_CTX *mem_ctx,
                                             const char *path,
                                             bool get_props,
					     bool open_zhandle,
					     bool resolve_path);

/*
 * This function returns a list of ZFS snapshots matching the specified
 * filters, allocated under a user-provided talloc memory context. Returns
 * NULL on error. It is a wrapper around zhandle_list_snapshots.
 *
 * @param[in]	smblibzfsp		smblibzfs handle struct
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
struct snapshot_list *smb_zfs_list_snapshots(struct smblibzfshandle *smblibzfsp,
					     TALLOC_CTX *mem_ctx,
					     const char *fs,
					     bool ignore_empty_snaps,
					     const char **inclusions,
					     const char **exclusions,
					     time_t start,
					     time_t end);

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
struct snapshot_list *zhandle_list_snapshots(struct smbzhandle *zhandle_ext,
                                      TALLOC_CTX *mem_ctx,
                                      bool ignore_empty_snaps,
                                      const char **inclusions,
                                      const char **exclusions,
                                      time_t start,
                                      time_t end);

/*
 * Delete a list of ZFS snapshots. List is converted into an nvlist
 * and deletion performed in single ZFS ioctl. Required parts of
 * snapshot list are snaps->dataset_name, and entry->name for entries.
 *
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	mem_ctx			talloc memory context
 * @param[in]	snaps			list of snapshots to delete
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_delete_snapshots(struct smblibzfshandle *smblibzfsp,
			     TALLOC_CTX *mem_ctx,
			     struct snapshot_list *snaps);

/*
 * Take a named snapshot of a given path.
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	path			path on which to take snapshot
 * @param[in]	snapshot_name		name to give snapshot
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_snapshot(struct smblibzfshandle *smblibzfsp,
		     const char *path,
		     const char *snapshot_name,
		     bool recursive);

/*
 * Roll back to named snapshot. This is a destructive process.
 * Given a path, convert path to dataset handle and rollback to a specific
 * snapshot, discarding any data changes since then and making it the
 * active dataset.
 *
 * Any snapshots and bookmarks more recent than the target are
 * destroyed, along with their dependents (i.e. clones).
 *
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	path			path on which to take snapshot
 * @param[in]	snapshot_name		name to give snapshot
 * @param[in]	force			forcibly unmount cloned filesystems
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_rollback(struct smblibzfshandle *smblibzfsp,
		     const char *path,
		     const char *snapshot_name,
		     bool force);

/*
 * Roll back to the last successful snapshot. This is a destructive process. All
 * data from after the last snapshot was taken will be destroyed.
 * @param[in]	smblibzfsp		smblibzfs handle struct
 * @param[in]	path			path on which to take snapshot
 * @param[in]	snapshot_name		name to give snapshot
 *
 * @return	0 on success -1 on failure
 */
int smb_zfs_rollback_last(struct smblibzfshandle *smblibzfsp, const char *path);

void close_smbzhandle(struct smbzhandle *zfsp_ext);

/*
 * Get a list of child datasets of a given dataset using zfs_iter_filesystems.
 *
 * @param[in]	mem_ctx			talloc memory context on which to hang results.
 * @param[in]	smbzhandle_ext		smb zfs dataset handle
 * @param[in]	open_handles		specifies whether to leave zhandles on child
 *					datasets open
 * @return	dataset_list		dataset->root->zhandle is a pointer to the
 *					same zhandle used to generate the dataset list.
 */
struct dataset_list *zhandle_list_children( TALLOC_CTX *mem_ctx,
                                          struct smbzhandle *zhandle_ext,
                                          bool open_zhandles);

/*
 * Initialize global libzfs handle if necessary and populate
 * dataset list for connectpath
 *
 * @param[in]	mem_ctx			talloc memory context on which to hang results.
 * @param[in]	connectpath		connectpath to share.
 * @param[out]	ppdsl			returned dataset list for connectpath.
 * @return	0 on success -1 on failure
 */
int conn_zfs_init(TALLOC_CTX *mem_ctx,
		  const char *connectpath,
		  struct smblibzfshandle **plibzfs,
		  struct dataset_list **ppdsl);

#endif	/* !__SMB_LIBZFS_H */
