/*
 * Thin wrapper around the Linux statmount(2) / listmount(2) system calls.
 *
 * Copyright (C) iXsystems, Inc. 2026
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

#ifndef _SOURCE3_LIB_TRUENAS_MOUNT_H_
#define _SOURCE3_LIB_TRUENAS_MOUNT_H_

#include <talloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Mount IDs here are always the 64-bit *unique* mount IDs as reported by
 * statx() with STATX_MNT_ID_UNIQUE. Every SMB_STRUCT_STAT already carries
 * one in st_ex_mnt_id. Unlike st_dev and the legacy 32-bit mount IDs in
 * /proc/self/mountinfo, unique mount IDs are never reused within a boot,
 * which makes them safe keys for long-lived caches: an unmount + remount
 * cycle yields a new ID and therefore a clean cache miss.
 */

/* Pseudo mount ID addressing the root of the mount namespace (LSMT_ROOT) */
#define TN_MOUNT_NS_ROOT (~0ULL)

struct tn_mount_entry {
	uint64_t mnt_id;	/* unique mount ID, matches st_ex_mnt_id */
	uint64_t mnt_parent_id;	/* unique mount ID of parent mount */
	uint32_t mnt_id_old;	/* mount ID as shown in /proc/self/mountinfo */
	uint64_t mnt_attr;	/* MOUNT_ATTR_* per-mount flags */
	dev_t sb_dev;		/* device number of the superblock */
	uint64_t sb_magic;	/* filesystem magic */
	uint32_t sb_flags;	/* SB_{RDONLY,SYNCHRONOUS,DIRSYNC,MANDLOCK} */
	const char *fs_type;	/* filesystem type, e.g. "zfs" */
	const char *mnt_root;	/* root of the mount within the filesystem */
	const char *mnt_point;	/* mountpoint relative to process root */
	const char *mnt_opts;	/* superblock options as shown by the
				 * filesystem. Comma-separated with special
				 * characters escaped. Does NOT include the
				 * ro/rw state -- see tn_mount_is_readonly() */
	const char *sb_source;	/* mount source as reported by the
				 * filesystem, e.g. a block device or a ZFS
				 * dataset name */
	uint64_t mask;		/* STATMOUNT_* bits the kernel actually
				 * returned. String fields above are NULL
				 * when the kernel did not report them */
};

/**
 * @brief Retrieve mount information for a unique mount ID.
 *
 * The returned entry and all strings in it are talloc'd under mem_ctx.
 * A mount ID belonging to a since-unmounted filesystem (for example an
 * expired automount) fails with ENOENT.
 *
 * @param[in]	mem_ctx		talloc memory context for the result
 * @param[in]	mnt_id		unique mount ID (st_ex_mnt_id)
 * @param[out]	entry_out	the decoded mount entry
 *
 * @return	0 on success, -1 on failure with errno set
 */
int tn_mount_entry_get(TALLOC_CTX *mem_ctx,
		       uint64_t mnt_id,
		       struct tn_mount_entry **entry_out);

/**
 * @brief Retrieve mount information for the mount a path resides on.
 *
 * Symlinks in the path are followed.
 *
 * @param[in]	mem_ctx		talloc memory context for the result
 * @param[in]	path		path to look up
 * @param[out]	entry_out	the decoded mount entry
 *
 * @return	0 on success, -1 on failure with errno set
 */
int tn_mount_entry_get_path(TALLOC_CTX *mem_ctx,
			    const char *path,
			    struct tn_mount_entry **entry_out);

/**
 * @brief Get the unique mount ID for the mount a path resides on.
 *
 * Symlinks in the path are followed.
 *
 * @param[in]	path		path to look up
 * @param[out]	mnt_id_out	unique mount ID
 *
 * @return	0 on success, -1 on failure with errno set
 */
int tn_mount_path_get_mnt_id(const char *path, uint64_t *mnt_id_out);

/**
 * @brief Duplicate a mount entry under a new talloc memory context.
 *
 * @param[in]	mem_ctx		talloc memory context for the copy
 * @param[in]	entry		entry to copy
 *
 * @return	the copy, or NULL on failure with errno set
 */
struct tn_mount_entry *tn_mount_entry_copy(TALLOC_CTX *mem_ctx,
					   const struct tn_mount_entry *entry);

/**
 * @brief Callback for tn_mount_traverse().
 *
 * The entry is only valid for the duration of the callback; use
 * tn_mount_entry_copy() to keep it.
 *
 * @return	true to continue iterating, false to stop
 */
typedef bool (*tn_mount_traverse_fn)(const struct tn_mount_entry *entry,
				     void *private_data);

/**
 * @brief Iterate over mounts in the current mount namespace.
 *
 * Mounts that disappear between enumeration and lookup (for example
 * expiring automounts) are skipped silently.
 *
 * @param[in]	parent_mnt_id	TN_MOUNT_NS_ROOT to iterate every mount in
 *				the namespace, or a unique mount ID to
 *				iterate the mounts below it -- the whole
 *				subtree, at any depth, not just its direct
 *				children. The mount itself is not visited.
 * @param[in]	reverse		iterate most-recently-mounted first
 * @param[in]	fn		callback invoked per mount
 * @param[in]	private_data	passed through to the callback
 *
 * @return	0 on success (including callback-requested stop),
 *		-1 on failure with errno set
 */
int tn_mount_traverse(uint64_t parent_mnt_id,
		      bool reverse,
		      tn_mount_traverse_fn fn,
		      void *private_data);

/**
 * @brief Check whether an option token is present in mnt_opts.
 *
 * Exact whole-token match, e.g. "casesensitive", "posixacl".
 */
bool tn_mount_has_opt(const struct tn_mount_entry *entry, const char *opt);

/**
 * @brief Whether the superblock is mounted read-only.
 *
 * statmount does not include ro/rw in mnt_opts (unlike
 * /proc/self/mountinfo); the state is carried in sb_flags.
 */
bool tn_mount_is_readonly(const struct tn_mount_entry *entry);

#endif /* _SOURCE3_LIB_TRUENAS_MOUNT_H_ */
