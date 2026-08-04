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

#include "includes.h"
#include "lib/truenas_mount.h"

#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <linux/mount.h>

/*
 * statmount(2) and listmount(2) were added in Linux 6.8 with arch-unified
 * syscall numbers, but glibc has no wrappers for them yet.
 */
#ifndef SYS_statmount
#define SYS_statmount 457
#endif
#ifndef SYS_listmount
#define SYS_listmount 458
#endif

#ifndef LISTMOUNT_REVERSE
#define LISTMOUNT_REVERSE (1 << 0)
#endif

/*
 * SB_RDONLY is not exported through uapi headers, but the sb_flags bits
 * exposed by statmount are the stable superblock flag ABI values from
 * include/linux/fs.h, which for the flags statmount reports coincide with
 * the classic MS_* mount flag values.
 */
#ifndef SB_RDONLY
#define SB_RDONLY 0x01
#endif

/*
 * All statmount fields struct tn_mount_entry models. Fields the running
 * kernel does not support are simply absent from the returned mask.
 */
#define TN_STATMOUNT_WANT (STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC | \
			   STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT | \
			   STATMOUNT_FS_TYPE | STATMOUNT_MNT_OPTS | \
			   STATMOUNT_SB_SOURCE)

#define TN_STATMOUNT_BUFSZ_INITIAL 4096
#define TN_STATMOUNT_BUFSZ_MAX (1024 * 1024)
#define TN_LISTMOUNT_BATCH 256

static int sys_statmount(const struct mnt_id_req *req,
			 struct statmount *buf,
			 size_t bufsize)
{
	return syscall(SYS_statmount, req, buf, bufsize, 0);
}

static ssize_t sys_listmount(const struct mnt_id_req *req,
			     uint64_t *mnt_ids,
			     size_t nr_mnt_ids,
			     unsigned int flags)
{
	return syscall(SYS_listmount, req, mnt_ids, nr_mnt_ids, flags);
}

static struct statmount *statmount_raw(TALLOC_CTX *mem_ctx, uint64_t mnt_id)
{
	struct mnt_id_req req = {
		.size = MNT_ID_REQ_SIZE_VER0,
		.mnt_id = mnt_id,
		.param = TN_STATMOUNT_WANT,
	};
	size_t bufsz = TN_STATMOUNT_BUFSZ_INITIAL;
	struct statmount *sm = NULL;
	struct statmount *tmp = NULL;
	int saved_errno;
	int ret;

	for (;;) {
		/*
		 * A NULL pointer makes this the initial allocation and every
		 * later pass a grow. EOVERFLOW means the kernel wrote nothing,
		 * so there are no contents to preserve -- but talloc can often
		 * extend in place, and a failed grow leaves sm to be freed.
		 */
		tmp = talloc_realloc_size(mem_ctx, sm, bufsz);
		if (tmp == NULL) {
			TALLOC_FREE(sm);
			errno = ENOMEM;
			return NULL;
		}
		sm = tmp;

		ret = sys_statmount(&req, sm, bufsz);
		if (ret == 0) {
			return sm;
		}

		if (errno != EOVERFLOW || bufsz >= TN_STATMOUNT_BUFSZ_MAX) {
			saved_errno = errno;
			TALLOC_FREE(sm);
			errno = saved_errno;
			return NULL;
		}
		bufsz *= 2;
	}
}

/*
 * Copy out one of the strings in the statmount string table. A field the
 * kernel did not report is set to NULL, which is distinct from failure:
 * callers must be able to tell "this kernel does not have the field" from
 * "we could not allocate it".
 */
static bool sm_string(TALLOC_CTX *mem_ctx,
		      const struct statmount *sm,
		      uint64_t mask_bit,
		      uint32_t offset,
		      const char **str_out)
{
	if ((sm->mask & mask_bit) == 0) {
		*str_out = NULL;
		return true;
	}
	*str_out = talloc_strdup(mem_ctx, (const char *)sm->str + offset);
	return (*str_out != NULL);
}

int tn_mount_entry_get(TALLOC_CTX *mem_ctx,
		       uint64_t mnt_id,
		       struct tn_mount_entry **entry_out)
{
	struct tn_mount_entry *entry = NULL;
	struct statmount *sm = NULL;
	int saved_errno;
	bool ok;

	entry = talloc_zero(mem_ctx, struct tn_mount_entry);
	if (entry == NULL) {
		errno = ENOMEM;
		return -1;
	}

	sm = statmount_raw(entry, mnt_id);
	if (sm == NULL) {
		saved_errno = errno;
		if (saved_errno != ENOENT) {
			DBG_ERR("statmount() failed for mount ID %" PRIx64
				": %s\n", mnt_id, strerror(saved_errno));
		}
		TALLOC_FREE(entry);
		errno = saved_errno;
		return -1;
	}

	entry->mask = sm->mask;
	if (sm->mask & STATMOUNT_MNT_BASIC) {
		entry->mnt_id = sm->mnt_id;
		entry->mnt_parent_id = sm->mnt_parent_id;
		entry->mnt_id_old = sm->mnt_id_old;
		entry->mnt_attr = sm->mnt_attr;
	}
	if (sm->mask & STATMOUNT_SB_BASIC) {
		entry->sb_dev = makedev(sm->sb_dev_major, sm->sb_dev_minor);
		entry->sb_magic = sm->sb_magic;
		entry->sb_flags = sm->sb_flags;
	}

	ok = sm_string(entry, sm, STATMOUNT_FS_TYPE, sm->fs_type,
		       &entry->fs_type) &&
	     sm_string(entry, sm, STATMOUNT_MNT_ROOT, sm->mnt_root,
		       &entry->mnt_root) &&
	     sm_string(entry, sm, STATMOUNT_MNT_POINT, sm->mnt_point,
		       &entry->mnt_point) &&
	     sm_string(entry, sm, STATMOUNT_MNT_OPTS, sm->mnt_opts,
		       &entry->mnt_opts) &&
	     sm_string(entry, sm, STATMOUNT_SB_SOURCE, sm->sb_source,
		       &entry->sb_source);
	if (!ok) {
		DBG_ERR("Failed to copy mount strings for mount ID %" PRIx64
			"\n", mnt_id);
		TALLOC_FREE(entry);
		errno = ENOMEM;
		return -1;
	}
	TALLOC_FREE(sm);

	*entry_out = entry;
	return 0;
}

int tn_mount_path_get_mnt_id(const char *path, uint64_t *mnt_id_out)
{
	struct statx stx = {};
	int ret;

	ret = statx(AT_FDCWD, path, 0, STATX_MNT_ID_UNIQUE, &stx);
	if (ret != 0) {
		DBG_INFO("statx() failed for %s: %s\n", path,
			 strerror(errno));
		return -1;
	}
	if ((stx.stx_mask & STATX_MNT_ID_UNIQUE) == 0) {
		DBG_ERR("kernel did not report a unique mount ID\n");
		errno = ENOSYS;
		return -1;
	}
	*mnt_id_out = stx.stx_mnt_id;
	return 0;
}

int tn_mount_entry_get_path(TALLOC_CTX *mem_ctx,
			    const char *path,
			    struct tn_mount_entry **entry_out)
{
	uint64_t mnt_id;
	int ret;

	ret = tn_mount_path_get_mnt_id(path, &mnt_id);
	if (ret != 0) {
		return -1;
	}
	return tn_mount_entry_get(mem_ctx, mnt_id, entry_out);
}

static bool copy_entry_string(struct tn_mount_entry *out,
			      const char **dst,
			      const char *src)
{
	if (src == NULL) {
		*dst = NULL;
		return true;
	}
	*dst = talloc_strdup(out, src);
	return (*dst != NULL);
}

struct tn_mount_entry *tn_mount_entry_copy(TALLOC_CTX *mem_ctx,
					   const struct tn_mount_entry *entry)
{
	struct tn_mount_entry *out = NULL;
	bool ok;

	out = talloc_zero(mem_ctx, struct tn_mount_entry);
	if (out == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	*out = *entry;

	ok = copy_entry_string(out, &out->fs_type, entry->fs_type) &&
	     copy_entry_string(out, &out->mnt_root, entry->mnt_root) &&
	     copy_entry_string(out, &out->mnt_point, entry->mnt_point) &&
	     copy_entry_string(out, &out->mnt_opts, entry->mnt_opts) &&
	     copy_entry_string(out, &out->sb_source, entry->sb_source);
	if (!ok) {
		TALLOC_FREE(out);
		errno = ENOMEM;
		return NULL;
	}

	return out;
}

int tn_mount_traverse(uint64_t parent_mnt_id,
		      bool reverse,
		      tn_mount_traverse_fn fn,
		      void *private_data)
{
	uint64_t mnt_ids[TN_LISTMOUNT_BATCH];
	struct mnt_id_req req = {
		.size = MNT_ID_REQ_SIZE_VER0,
		.mnt_id = parent_mnt_id,
		.param = 0,
	};
	/*
	 * The iteration direction must be passed in the flags argument on
	 * every call; req.param is strictly the continuation cursor (the
	 * last mount ID of the previous batch).
	 */
	const unsigned int flags = reverse ? LISTMOUNT_REVERSE : 0;

	for (;;) {
		ssize_t cnt;
		ssize_t i;

		cnt = sys_listmount(&req, mnt_ids, ARRAY_SIZE(mnt_ids), flags);
		if (cnt < 0) {
			DBG_ERR("listmount() failed for mount ID %" PRIx64
				": %s\n", parent_mnt_id, strerror(errno));
			return -1;
		}
		if (cnt == 0) {
			return 0;
		}

		for (i = 0; i < cnt; i++) {
			struct tn_mount_entry *entry = NULL;
			bool proceed;
			int ret;

			ret = tn_mount_entry_get(NULL, mnt_ids[i], &entry);
			if (ret != 0) {
				/*
				 * Skip mounts we cannot look at rather than
				 * abandoning the search. The mount may
				 * legitimately have gone away since it was
				 * enumerated (an expired ZFS snapshot
				 * automount, for example), and a single mount
				 * the kernel refuses to describe must not
				 * make the whole namespace unsearchable.
				 */
				continue;
			}

			proceed = fn(entry, private_data);
			TALLOC_FREE(entry);
			if (!proceed) {
				return 0;
			}
		}

		if ((size_t)cnt < ARRAY_SIZE(mnt_ids)) {
			return 0;
		}
		req.param = mnt_ids[cnt - 1];
	}
}

bool tn_mount_has_opt(const struct tn_mount_entry *entry, const char *opt)
{
	const char *p = entry->mnt_opts;
	size_t optlen = strlen(opt);

	if (p == NULL) {
		return false;
	}

	while (*p != '\0') {
		const char *end = strchrnul(p, ',');

		if (((size_t)(end - p) == optlen) &&
		    (memcmp(p, opt, optlen) == 0)) {
			return true;
		}
		p = (*end != '\0') ? end + 1 : end;
	}
	return false;
}

bool tn_mount_is_readonly(const struct tn_mount_entry *entry)
{
	return (entry->sb_flags & SB_RDONLY) != 0;
}
