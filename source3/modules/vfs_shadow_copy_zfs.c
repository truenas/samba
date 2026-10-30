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
#include "source3/lib/truenas_mount.h"
#include "../lib/util/time.h"


#define SHADOW_COPY_ZFS_SNAP_DIR ".zfs/snapshot"
#define MAX_SNAPSHOT_COUNT 512
/* snapshot lists kept per connection, one per dataset */
#define MAX_CACHED_LISTS 16

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

struct shadow_copy_zfs_config;

/*
 * A pathref fd (O_PATH) does not keep the automount of a ZFS snapshot from
 * expiring, so every file open in a snapshot holds a reference on an
 * O_DIRECTORY open of the root of the snapshot. The last reference closes
 * it, which lets the snapshot unmount and be destroyed.
 *
 * The pin is also what every access to a snapshot is checked against. It
 * is opened from the verified .zfs/snapshot directory of the dataset
 * (smb_zfs_open_snapdir()), so its fd is the root of that snapshot and its
 * device that of the snapshot mount, whatever the path of the dataset
 * names today.
 *
 * A snapshot renamed while pinned leaves its old name to a new snapshot,
 * so a pin is reused only for the same snapshot time, and the pins of a
 * dataset leave the lookup list whenever its snapshot list is read again,
 * staying only for the references they have.
 */
struct snapdir_pin {
	struct snapdir_pin *prev, *next;
	struct shadow_copy_zfs_config *config;
	uint64_t mnt_id;	/* of the dataset */
	char *name;		/* of the snapshot */
	NTTIME twrp;		/* the time of the snapshot, as in a name */
	int fd;			/* the root of the snapshot */
	dev_t dev;		/* of the snapshot mount */
	int refcnt;
	bool listed;		/* in config->pins */
};

/* Where a name with a timewarp token is, from shadow_copy_zfs_convert(). */
struct snap_target {
	const char *mountpoint;	/* of the dataset */
	uint64_t mnt_id;	/* of the dataset */
	const char *name;	/* of the snapshot */
	NTTIME twrp;		/* the time of the snapshot, as in a name */
	const char *rel;	/* below the root of the snapshot; "" for it */
};

struct cached_snaps {
	struct snapshot_list *snaps;
	struct cached_snaps *prev, *next;
};

struct shadow_copy_zfs_config {
	const struct zfs_dataset *ds;
	bool snapshot_share;	/* share root is inside a snapshot */
	struct cached_snaps	*cache;	/* most recently used first */
	size_t			ncached;

	bool			no_dataset_traversal;
	bool			ignore_empty_snaps;
	/* Snapshot parameters */
	struct snap_filter	*filter;

	struct snapdir_pin	*pins;
};

/* the extension of an fsp opened in a snapshot */
struct shadow_fsp_ext {
	struct snapdir_pin *pin;
};

/*
 * smb_libzfs reports the path of a dataset gone stale -- a directory above
 * its mountpoint renamed since it was resolved -- as ESTALE, which smbd
 * has no status for. To the client, what the name meant is not there.
 */
static int shadow_copy_zfs_errno(int err)
{
	return (err == ESTALE) ? ENOENT : err;
}

/*
 * Open the root of snapshot name of the dataset mounted at mountpoint, as
 * root: the user may not be able to open it. A single component below the
 * verified snapshot directory, and the root of a mount of its own.
 */
static int snapdir_root_open(const struct snap_target *tgt, dev_t *pdev)
{
	struct statx stx;
	int dfd, fd = -1, saved_errno;

	become_root();
	dfd = smb_zfs_open_snapdir(tgt->mountpoint, tgt->mnt_id);
	if (dfd != -1) {
		fd = openat(dfd, tgt->name,
			    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		saved_errno = errno;
		close(dfd);
	} else {
		saved_errno = errno;
	}
	unbecome_root();
	if (fd == -1) {
		errno = shadow_copy_zfs_errno(saved_errno);
		/* smb_libzfs logs a snapshot directory it cannot open */
		if (dfd != -1) {
			DBG_ERR("%s@%s: failed to open the snapshot: %s\n",
				tgt->mountpoint, tgt->name, strerror(errno));
		}
		return -1;
	}

	if (statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) != 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	if ((stx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) &&
	    !(stx.stx_attributes & STATX_ATTR_MOUNT_ROOT)) {
		DBG_ERR("%s@%s: the snapshot is not mounted\n",
			tgt->mountpoint, tgt->name);
		close(fd);
		errno = ENOENT;
		return -1;
	}
	*pdev = makedev(stx.stx_dev_major, stx.stx_dev_minor);
	return fd;
}

static struct snapdir_pin *snapdir_pin_get(struct shadow_copy_zfs_config *config,
					   const struct snap_target *tgt)
{
	struct snapdir_pin *pin = NULL;
	dev_t dev;
	int fd;

	for (pin = config->pins; pin != NULL; pin = pin->next) {
		if ((pin->mnt_id == tgt->mnt_id) &&
		    (pin->twrp == tgt->twrp) &&
		    (strcmp(pin->name, tgt->name) == 0)) {
			pin->refcnt++;
			return pin;
		}
	}

	fd = snapdir_root_open(tgt, &dev);
	if (fd == -1) {
		return NULL;
	}

	pin = talloc_zero(config, struct snapdir_pin);
	if (pin == NULL) {
		close(fd);
		errno = ENOMEM;
		return NULL;
	}
	pin->name = talloc_strdup(pin, tgt->name);
	if (pin->name == NULL) {
		close(fd);
		TALLOC_FREE(pin);
		errno = ENOMEM;
		return NULL;
	}
	pin->config = config;
	pin->mnt_id = tgt->mnt_id;
	pin->twrp = tgt->twrp;
	pin->fd = fd;
	pin->dev = dev;
	pin->refcnt = 1;
	pin->listed = true;
	DLIST_ADD(config->pins, pin);
	return pin;
}

static void snapdir_pin_put(struct snapdir_pin *pin)
{
	SMB_ASSERT(pin->refcnt > 0);
	if (--pin->refcnt > 0) {
		return;
	}
	if (pin->listed) {
		DLIST_REMOVE(pin->config->pins, pin);
	}
	close(pin->fd);
	TALLOC_FREE(pin);
}

/* Take the pins of the dataset mnt_id out of the lookup. */
static void snapdir_pins_unlist(struct shadow_copy_zfs_config *config,
				uint64_t mnt_id)
{
	struct snapdir_pin *pin = NULL;
	struct snapdir_pin *next = NULL;

	for (pin = config->pins; pin != NULL; pin = next) {
		next = pin->next;
		if (pin->mnt_id != mnt_id) {
			continue;
		}
		DLIST_REMOVE(config->pins, pin);
		pin->listed = false;
	}
}

/*
 * An O_PATH fd on rel in the snapshot of pin, resolved beneath its root
 * and through no symlink: rel names exactly what it says, inside that
 * snapshot. With nofollow a symlink at the end is opened itself.
 */
static int snapdir_open_beneath(const struct snapdir_pin *pin,
				const char *rel,
				bool nofollow)
{
	struct open_how how = {
		.flags = O_PATH | O_CLOEXEC | (nofollow ? O_NOFOLLOW : 0),
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
	};

	return openat2(pin->fd, (rel[0] == '\0') ? "." : rel, &how,
		       sizeof(how));
}

static bool fd_on_dev(int fd, dev_t dev)
{
	struct stat st;

	return (fstat(fd, &st) == 0) && (st.st_dev == dev);
}

/* Whether st, from a call by path, is the object fd was opened on. */
static bool stat_is_fd(const SMB_STRUCT_STAT *st, int fd)
{
	struct stat fst;

	return (fstat(fd, &fst) == 0) &&
	       (st->st_ex_dev == fst.st_dev) &&
	       (st->st_ex_ino == fst.st_ino);
}

/*
 * How a name is opened in a snapshot. Read-only, whatever the client asked
 * for. No symlinks, whatever smbd asked for: not inside the snapshot,
 * where smbd relies on RESOLVE_NO_SYMLINKS to see them, nor in the path
 * of the dataset, which is the one of the mount table and has none. With
 * O_PATH and O_NOFOLLOW a symlink at the end is still opened itself, as
 * smbd expects. RESOLVE_NO_XDEV goes: the path leads into the snapshot
 * mount by design.
 */
static void shadow_copy_zfs_snap_how(struct vfs_open_how *how)
{
	how->flags &= ~(O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_EXCL |
			O_APPEND);
	how->resolve &= ~VFS_OPEN_HOW_RESOLVE_NO_XDEV;
	how->resolve |= VFS_OPEN_HOW_RESOLVE_NO_SYMLINKS;
}

static void shadow_fsp_ext_destroy(void *p_data)
{
	struct shadow_fsp_ext *ext = (struct shadow_fsp_ext *)p_data;

	if (ext->pin != NULL) {
		snapdir_pin_put(ext->pin);
		ext->pin = NULL;
	}
}

/* fsp holds one reference on pin; an fsp opened again drops its old one */
static bool shadow_fsp_set_pin(vfs_handle_struct *handle,
			       files_struct *fsp,
			       struct snapdir_pin *pin)
{
	struct shadow_fsp_ext *ext = NULL;

	ext = VFS_ADD_FSP_EXTENSION(handle, fsp, struct shadow_fsp_ext,
				    shadow_fsp_ext_destroy);
	if (ext == NULL) {
		errno = ENOMEM;
		return false;
	}
	if (ext->pin != NULL) {
		snapdir_pin_put(ext->pin);
	}
	ext->pin = pin;
	return true;
}

static bool fsp_in_snapshot(vfs_handle_struct *handle,
			    const struct files_struct *fsp)
{
	return (fsp != NULL) &&
	       (VFS_FETCH_FSP_EXTENSION(handle, fsp) != NULL);
}

static const struct zfs_dataset *shadow_path_to_dataset(
    struct shadow_copy_zfs_config *config,
    const char *path)
{
	int err;
	uint64_t mnt_id = 0;
	const struct zfs_dataset *resolved = NULL;

	err = tn_mount_path_get_mnt_id(path, &mnt_id);
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
			err = tn_mount_path_get_mnt_id(tmp_path, &mnt_id);
		}
	}
	if (err != 0) {
		DBG_ERR("%s: failed to resolve mount id: %s\n",
			path, strerror(errno));
		errno = ENOENT;
		return NULL;
	}

	if (mnt_id == config->ds->mnt_id) {
		return config->ds;
	}

	resolved = smb_zfs_lookup_dataset(mnt_id);
	if (resolved != NULL) {
		return resolved;
	}

	DBG_ERR("No dataset found for %s with mount id: %" PRIu64 "\n",
		path, mnt_id);
	errno = ENOENT;
	return NULL;
}

static const struct zfs_dataset *shadow_fsp_to_dataset(
    struct vfs_handle_struct *handle,
    struct shadow_copy_zfs_config *config,
    files_struct *fsp)
{
	int ret;
	uint64_t mnt_id;
	const struct zfs_dataset *resolved = NULL;

	if (VALID_STAT(fsp->fsp_name->st)) {
		mnt_id = fsp->fsp_name->st.st_ex_mnt_id;
	} else {
		SMB_STRUCT_STAT st;
		ret = SMB_VFS_NEXT_FSTAT(handle, fsp, &st);
		if (ret != 0) {
			DBG_ERR("%s: fstat() failed: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			return NULL;
		}
		mnt_id = st.st_ex_mnt_id;
	}

	if (mnt_id == config->ds->mnt_id) {
		return config->ds;
	}

	resolved = smb_zfs_lookup_dataset(mnt_id);
	if (resolved != NULL) {
		return resolved;
	}

	DBG_ERR("%s: no dataset found\n", fsp_str_dbg(fsp));
	errno = ENOENT;
	return NULL;
}

/*
 * Whether the share root itself lies inside a snapshot automount. FSRVP
 * creates such shares to expose a shadow copy; their contents are already
 * a snapshot, so there are no previous versions of them to offer and
 * every path in them is inside the ctldir.
 */
static bool shadow_copy_zfs_in_snapshot(const char *connectpath,
					const char *mountpoint)
{
	const char *snapdir = SHADOW_COPY_ZFS_SNAP_DIR "/";
	size_t mplen = strlen(mountpoint);

	if (mplen == 1) {
		mplen = 0;
	}
	if (strncmp(connectpath, mountpoint, mplen) != 0) {
		return false;
	}
	if (connectpath[mplen] != '/') {
		return false;
	}
	return strncmp(connectpath + mplen + 1, snapdir, strlen(snapdir)) == 0;
}

/*
 * Position of the share root below the dataset mountpoint, e.g. "sub/dir"
 * when a directory inside a dataset is shared rather than the dataset
 * mountpoint itself (most commonly a [homes] share). NULL when the share is
 * rooted at the mountpoint.
 *
 * A share may also be rooted inside a snapshot automount, which is how
 * FSRVP exposes a shadow copy: the connectpath is then
 * <mountpoint>/.zfs/snapshot/<snap>[/<sub>]. That prefix identifies a
 * snapshot rather than a position within the dataset, so it is skipped --
 * previous versions of such a share are the same paths in other snapshots.
 */
static const char *shadow_copy_zfs_mp_offset(const char *connectpath,
					     const char *mountpoint)
{
	const char *snapdir = SHADOW_COPY_ZFS_SNAP_DIR "/";
	size_t snapdir_len = strlen(snapdir);
	size_t mplen = strlen(mountpoint);
	const char *offset = NULL;
	const char *slash = NULL;

	/* A dataset mounted at "/" has no path component of its own. */
	if (mplen == 1) {
		mplen = 0;
	}

	if (strncmp(connectpath, mountpoint, mplen) != 0) {
		return NULL;
	}
	if (connectpath[mplen] != '/') {
		return NULL;
	}
	offset = connectpath + mplen + 1;

	if (strncmp(offset, snapdir, snapdir_len) == 0) {
		slash = strchr(offset + snapdir_len, '/');
		if (slash == NULL) {
			return NULL;
		}
		offset = slash + 1;
	}

	if (offset[0] == '\0') {
		return NULL;
	}
	return offset;
}

/* whether path is prefix, or below it */
static bool path_is_below(const char *path, const char *prefix,
			  int (*ncmp)(const char *, const char *, size_t))
{
	size_t len = strlen(prefix);

	if ((len == 1) && (prefix[0] == '/')) {
		return path[0] == '/';
	}
	if (ncmp(path, prefix, len) != 0) {
		return false;
	}
	return (path[len] == '\0') || (path[len] == '/');
}

/*
 * The path below the root of a snapshot of the dataset mounted at
 * mountpoint for name, relative to the share root; "" for the root of the
 * snapshot. With mpoffset the share root is that directory of the dataset,
 * as for a share at /pool/ds/share of the dataset /pool/ds. Without it the
 * dataset is mounted at the share root or at a child dataset below it, and
 * name begins with the path of that child.
 *
 * name has no "." or ".." components (see shadow_copy_zfs_convert()), so
 * the result is always within the share as it was in the snapshot.
 */
static char *get_snapshot_relpath(TALLOC_CTX *mem_ctx,
				  const char *connectpath,
				  const char *mountpoint,
				  const char *name,
				  const char *mpoffset,
				  enum casesensitivity sens)
{
	int (*ncmp)(const char *s1, const char *s2, size_t len) = NULL;
	const char *rel = name;

	switch (sens) {
	case SMBZFS_MIXED:
	case SMBZFS_SENSITIVE:
		ncmp = strncmp;
		break;
	case SMBZFS_INSENSITIVE:
		ncmp = strncasecmp_m;
		break;
	default:
		smb_panic("Unsupported case sensitivity setting");
	}

	if (mpoffset != NULL) {
		if (*rel == '\0') {
			return talloc_strdup(mem_ctx, mpoffset);
		}
		return talloc_asprintf(mem_ctx, "%s/%s", mpoffset, rel);
	}

	if (!path_is_below(mountpoint, connectpath, ncmp)) {
		DBG_ERR("%s: dataset mountpoint %s is not in the share %s\n",
			name, mountpoint, connectpath);
		errno = EINVAL;
		return NULL;
	}
	{
		const char *child = mountpoint + strlen(connectpath);
		size_t len;

		if (*child == '/') {
			child++;
		}
		len = strlen(child);
		if (len > 0) {
			if ((ncmp(name, child, len) != 0) ||
			    ((name[len] != '\0') && (name[len] != '/'))) {
				DBG_ERR("%s: not within the dataset mounted at "
					"%s\n", name, mountpoint);
				errno = EINVAL;
				return NULL;
			}
			rel = name + len;
			if (*rel == '/') {
				rel++;
			}
		}
	}
	return talloc_strdup(mem_ctx, rel);
}

/* "<mountpoint>/.zfs/snapshot/<name>[/<rel>]" */
static char *snapshot_abspath(TALLOC_CTX *mem_ctx,
			      const char *mountpoint,
			      const char *snapname,
			      const char *rel)
{
	const char *mp = (strcmp(mountpoint, "/") == 0) ? "" : mountpoint;

	if (rel[0] == '\0') {
		return talloc_asprintf(mem_ctx, "%s/" SHADOW_COPY_ZFS_SNAP_DIR
				       "/%s", mp, snapname);
	}
	return talloc_asprintf(mem_ctx, "%s/" SHADOW_COPY_ZFS_SNAP_DIR "/%s/%s",
			       mp, snapname, rel);
}

/*
 * The snapshot list of the dataset of path, or of fsp when it is not NULL.
 * A cached list is used while the .zfs/snapshot directory of the dataset is
 * unchanged, and read again otherwise. The list belongs to the cache: it is
 * valid until the next call.
 */
static struct snapshot_list *shadow_copy_zfs_get_snaplist(
	struct vfs_handle_struct *handle,
	const char *path,
	files_struct *fsp,
	enum casesensitivity *psens)
{
	struct shadow_copy_zfs_config *config = NULL;
	struct cached_snaps *c = NULL;
	struct snapshot_list *snaps = NULL;
	const struct zfs_dataset *ds = NULL;
	const struct zfs_dataset_prop *props = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return NULL);
	if (fsp == NULL) {
		ds = shadow_path_to_dataset(config, path);
	} else {
		ds = shadow_fsp_to_dataset(handle, config, fsp);
	}
	if (ds == NULL) {
		return NULL;
	}
	props = smb_zfs_dataset_props(ds);
	if ((props == NULL) || (props->snapdir != SMBZFS_SNAPDIR_HIDDEN)) {
		return NULL;
	}
	*psens = ds->properties->casesens;

	for (c = config->cache; c != NULL; c = c->next) {
		if (c->snaps->mnt_id == ds->mnt_id) {
			break;
		}
	}
	if ((c != NULL) && smb_zfs_snapshot_list_current(c->snaps)) {
		DLIST_PROMOTE(config->cache, c);
		return c->snaps;
	}

	snaps = smb_zfs_list_snapshots(config, ds->mnt_id, config->filter);
	if (snaps == NULL) {
		/* the cause is logged by smb_libzfs */
		DBG_INFO("%s: failed to list snapshots: %s\n",
			 ds->dataset_name, strerror(errno));
		errno = shadow_copy_zfs_errno(errno);
		return NULL;
	}
	DBG_INFO("%s: read %zu snapshots\n",
		 ds->dataset_name, snaps->num_entries);
	snapdir_pins_unlist(config, snaps->mnt_id);

	if (c == NULL) {
		if (config->ncached == MAX_CACHED_LISTS) {
			c = DLIST_TAIL(config->cache);
			DLIST_REMOVE(config->cache, c);
			TALLOC_FREE(c);
			config->ncached--;
		}
		c = talloc_zero(config, struct cached_snaps);
		if (c == NULL) {
			TALLOC_FREE(snaps);
			errno = ENOMEM;
			return NULL;
		}
		DLIST_ADD(config->cache, c);
		config->ncached++;
	} else {
		TALLOC_FREE(c->snaps);
		DLIST_PROMOTE(config->cache, c);
	}
	c->snaps = talloc_move(c, &snaps);
	return c->snaps;
}

/*
 * Two versions of a file with the same inode, generation and change cookie
 * hold the same data: ZFS persists the cookie with every change it counts,
 * so a snapshot never has new data under an old cookie. The device is not
 * compared, as every mounted snapshot has a device of its own. Without a
 * cookie or generation, compare mtime.
 */
static bool shadow_copy_zfs_same_version(const SMB_STRUCT_STAT *a,
					 const SMB_STRUCT_STAT *b)
{
	uint32_t need = ST_EX_IFLAG_HAS_CHANGE_COOKIE | ST_EX_IFLAG_HAS_GEN;

	if (((a->st_ex_iflags & need) == need) &&
	    ((b->st_ex_iflags & need) == need)) {
		return (a->st_ex_ino == b->st_ex_ino) &&
		       (a->st_ex_gen == b->st_ex_gen) &&
		       (a->st_ex_change_cookie == b->st_ex_change_cookie);
	}

	return timespec_compare(&a->st_ex_mtime, &b->st_ex_mtime) == 0;
}

/* Path-based calls: a name with a timewarp token is a name in a snapshot. */
static bool shadow_copy_zfs_match_name(const struct smb_filename *name)
{
	return name->twrp != 0;
}

/*
 * fd-based calls: an fsp opened through this module has its fd in the
 * snapshot already, and needs no conversion.
 */
static bool shadow_copy_zfs_match_fsp(vfs_handle_struct *handle,
				      const struct files_struct *fsp)
{
	return (fsp->fsp_name->twrp != 0) && !fsp_in_snapshot(handle, fsp);
}

/* The absolute path of a name relative to the share root, or below it. */
static char *shadow_copy_zfs_abspath(TALLOC_CTX *mem_ctx,
				     const char *connectpath,
				     const char *name)
{
	if (name[0] == '/') {
		if (!path_is_below(name, connectpath, strncmp)) {
			DBG_ERR("%s: not in the share %s\n", name, connectpath);
			errno = EINVAL;
			return NULL;
		}
		return talloc_strdup(mem_ctx, name);
	}
	if ((name[0] == '\0') || ISDOT(name)) {
		return talloc_strdup(mem_ctx, connectpath);
	}
	if (strncmp(name, "./", 2) == 0) {
		name += 2;
	}
	return talloc_asprintf(mem_ctx, "%s/%s", connectpath, name);
}

/*
 * The path of a name with a timewarp token in the .zfs/snapshot directory
 * of the snapshot taken at that time, allocated under talloc_tos(). With
 * tgt, also where that is, with the strings allocated under the result.
 *
 * The name is made absolute and canonical first, so "." and ".." are gone
 * and a name that leaves the share is refused; what remains is mapped to
 * the same place below the share in the snapshot.
 */
static char *shadow_copy_zfs_convert(vfs_handle_struct *handle,
				     const struct smb_filename *fname,
				     struct snap_target *tgt)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	TALLOC_CTX *frame = NULL;
	struct shadow_copy_zfs_config *config = NULL;
	const char *connectpath = handle->conn->connectpath;
	struct snapshot_list *snaps = NULL;
	const struct snapshot_entry *entry = NULL;
	enum casesensitivity sens;
	const char *mpoffset = NULL;
	const char *rel = NULL;
	char *path = NULL;
	char *snaprel = NULL;
	char *ret = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				smb_panic(__func__));

	if (config->ds == NULL) {
		DBG_INFO("%s: the share is not on ZFS\n",
			 smb_fname_str_dbg(fname));
		errno = EINVAL;
		return NULL;
	}
	if (config->snapshot_share) {
		DBG_INFO("%s: the share is rooted inside a snapshot\n",
			 smb_fname_str_dbg(fname));
		errno = EINVAL;
		return NULL;
	}

	frame = talloc_stackframe();

	path = shadow_copy_zfs_abspath(frame, connectpath, fname->base_name);
	if (path != NULL) {
		path = canonicalize_absolute_path(frame, path);
	}
	if (path == NULL) {
		goto fail;
	}
	if (!path_is_below(path, connectpath, strncmp)) {
		DBG_ERR("%s: resolves outside the share\n",
			smb_fname_str_dbg(fname));
		errno = EINVAL;
		goto fail;
	}

	snaps = shadow_copy_zfs_get_snaplist(handle, path, NULL, &sens);
	if (snaps == NULL) {
		if (errno == 0) {
			errno = ENOENT;
		}
		goto fail;
	}
	/* as live opens with RESOLVE_NO_XDEV: no child datasets */
	if (config->no_dataset_traversal &&
	    (snaps->mnt_id != config->ds->mnt_id)) {
		DBG_INFO("%s: in the child dataset %s\n",
			 smb_fname_str_dbg(fname), snaps->dataset_name);
		errno = EXDEV;
		goto fail;
	}
	for (entry = snaps->entries; entry != NULL; entry = entry->next) {
		if (entry->nt_time == fname->twrp) {
			break;
		}
	}
	if (entry == NULL) {
		DBG_INFO("%s: no snapshot taken at that time\n",
			 smb_fname_str_dbg(fname));
		errno = ENOENT;
		goto fail;
	}

	rel = path + strlen(connectpath);
	if (*rel == '/') {
		rel++;
	}
	mpoffset = shadow_copy_zfs_mp_offset(connectpath, snaps->mountpoint);
	snaprel = get_snapshot_relpath(frame, connectpath, snaps->mountpoint,
				       rel, mpoffset, sens);
	if (snaprel == NULL) {
		goto fail;
	}
	ret = snapshot_abspath(mem_ctx, snaps->mountpoint, entry->name,
			       snaprel);
	if (ret == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	if (tgt != NULL) {
		*tgt = (struct snap_target) {
			.mountpoint = talloc_strdup(ret, snaps->mountpoint),
			.mnt_id = snaps->mnt_id,
			.name = talloc_strdup(ret, entry->name),
			.twrp = entry->nt_time,
			.rel = talloc_move(ret, &snaprel),
		};
		if ((tgt->mountpoint == NULL) || (tgt->name == NULL)) {
			TALLOC_FREE(ret);
			errno = ENOMEM;
			goto fail;
		}
	}

	TALLOC_FREE(frame);
	return ret;

fail:
	{
		int saved_errno = errno;
		TALLOC_FREE(frame);
		errno = saved_errno;
	}
	return NULL;
}

/*
 * shadow_copy_zfs_convert(), and the name resolved beneath the root of its
 * snapshot through no symlink, from the pin rather than from the path of
 * the dataset: the converted path names that object only if nothing above
 * the snapshot changed, which the caller checks against *pfd. Returns the
 * converted path with *ppin held, for snapdir_pin_put(), and *pfd, an
 * O_PATH fd on the name, for close().
 */
static char *shadow_copy_zfs_convert_checked(vfs_handle_struct *handle,
					     const struct smb_filename *fname,
					     bool nofollow,
					     struct snapdir_pin **ppin,
					     int *pfd)
{
	struct shadow_copy_zfs_config *config = NULL;
	struct snapdir_pin *pin = NULL;
	struct snap_target tgt;
	char *conv = NULL;
	int saved_errno;
	int fd;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				smb_panic(__func__));

	conv = shadow_copy_zfs_convert(handle, fname, &tgt);
	if (conv == NULL) {
		return NULL;
	}
	pin = snapdir_pin_get(config, &tgt);
	if (pin == NULL) {
		goto fail;
	}
	fd = snapdir_open_beneath(pin, tgt.rel, nofollow);
	if (fd == -1) {
		saved_errno = errno;
		DBG_INFO("%s: %s\n", conv, strerror(errno));
		snapdir_pin_put(pin);
		errno = saved_errno;
		goto fail;
	}
	*ppin = pin;
	*pfd = fd;
	return conv;

fail:
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return NULL;
}


/*
 * A snapshot is read-only. The kernel refuses changes through an fd in a
 * snapshot, so only the path-based calls need refusing here: without that
 * they would change the live file of the same name.
 */
static int shadow_copy_zfs_renameat(vfs_handle_struct *handle,
				    files_struct *srcfsp,
				    const struct smb_filename *smb_fname_src,
				    files_struct *dstfsp,
				    const struct smb_filename *smb_fname_dst,
				    const struct vfs_rename_how *rhow)
{
	if (shadow_copy_zfs_match_name(smb_fname_src)) {
		errno = EXDEV;
		return -1;
	}
	if (shadow_copy_zfs_match_name(smb_fname_dst)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, smb_fname_src, dstfsp,
				     smb_fname_dst, rhow);
}

static int shadow_copy_zfs_symlinkat(vfs_handle_struct *handle,
				     const struct smb_filename *link_contents,
				     struct files_struct *dirfsp,
				     const struct smb_filename *new_smb_filename)
{
	if (shadow_copy_zfs_match_name(link_contents) ||
	    shadow_copy_zfs_match_name(new_smb_filename)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_SYMLINKAT(handle, link_contents, dirfsp,
				      new_smb_filename);
}

static int shadow_copy_zfs_linkat(vfs_handle_struct *handle,
				  files_struct *srcfsp,
				  const struct smb_filename *oldname,
				  files_struct *dstfsp,
				  const struct smb_filename *newname,
				  int flags)
{
	if (shadow_copy_zfs_match_name(oldname) ||
	    shadow_copy_zfs_match_name(newname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_LINKAT(handle, srcfsp, oldname, dstfsp, newname,
				   flags);
}

static int shadow_copy_zfs_unlinkat(vfs_handle_struct *handle,
				    struct files_struct *dirfsp,
				    const struct smb_filename *smb_fname,
				    int flags)
{
	if (shadow_copy_zfs_match_name(smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
}

static int shadow_copy_zfs_mkdirat(vfs_handle_struct *handle,
				   struct files_struct *dirfsp,
				   const struct smb_filename *smb_fname,
				   mode_t mode)
{
	if (shadow_copy_zfs_match_name(smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKDIRAT(handle, dirfsp, smb_fname, mode);
}

static int shadow_copy_zfs_mknodat(vfs_handle_struct *handle,
				   files_struct *dirfsp,
				   const struct smb_filename *smb_fname,
				   mode_t mode,
				   SMB_DEV_T dev)
{
	if (shadow_copy_zfs_match_name(smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKNODAT(handle, dirfsp, smb_fname, mode, dev);
}

static int shadow_copy_zfs_lchown(vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  uid_t uid,
				  gid_t gid)
{
	if (shadow_copy_zfs_match_name(smb_fname)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
}

/*
 * The stat of a name with a timewarp token, by path through the modules
 * below, and only if it is what the name resolves to beneath the root of
 * its snapshot without symlinks. A symlink at the end is not followed
 * even for stat: only smbd decides where a symlink may lead.
 */
static int shadow_copy_zfs_stat_common(vfs_handle_struct *handle,
				       struct smb_filename *smb_fname,
				       bool nofollow)
{
	char *orig = smb_fname->base_name;
	struct snapdir_pin *pin = NULL;
	char *conv = NULL;
	int fd = -1;
	int saved_errno;
	int ret;

	conv = shadow_copy_zfs_convert_checked(handle, smb_fname, nofollow,
					       &pin, &fd);
	if (conv == NULL) {
		return -1;
	}
	smb_fname->base_name = conv;
	ret = nofollow ? SMB_VFS_NEXT_LSTAT(handle, smb_fname) :
			 SMB_VFS_NEXT_STAT(handle, smb_fname);
	saved_errno = errno;
	smb_fname->base_name = orig;
	if ((ret == 0) && !stat_is_fd(&smb_fname->st, fd)) {
		DBG_ERR("%s: not the file in the snapshot\n", conv);
		SET_STAT_INVALID(smb_fname->st);
		saved_errno = ENOENT;
		ret = -1;
	}
	close(fd);
	snapdir_pin_put(pin);
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy_zfs_stat(vfs_handle_struct *handle,
				struct smb_filename *smb_fname)
{
	if (!shadow_copy_zfs_match_name(smb_fname)) {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}
	return shadow_copy_zfs_stat_common(handle, smb_fname, false);
}

static int shadow_copy_zfs_lstat(vfs_handle_struct *handle,
				 struct smb_filename *smb_fname)
{
	if (!shadow_copy_zfs_match_name(smb_fname)) {
		return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}
	return shadow_copy_zfs_stat_common(handle, smb_fname, true);
}

static int shadow_copy_zfs_fstat(vfs_handle_struct *handle, files_struct *fsp,
				 SMB_STRUCT_STAT *sbuf)
{
	int ret;
	struct smb_filename *orig_smb_fname = NULL;
	struct smb_filename vss_smb_fname;
	struct smb_filename *orig_base_smb_fname = NULL;
	struct smb_filename vss_base_smb_fname;

	if (!shadow_copy_zfs_match_fsp(handle, fsp)) {
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	vss_smb_fname = *fsp->fsp_name;
	vss_smb_fname.base_name = shadow_copy_zfs_convert(handle,
							  fsp->fsp_name, NULL);
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
	TALLOC_FREE(vss_smb_fname.base_name);
	return ret;
}

/*
 * Whether the single name below dirfsp is, live, the mounted root of a
 * dataset other than mnt_id: a child dataset, whose previous versions are
 * its own snapshots, while the snapshot of the parent holds only its
 * empty mountpoint. A directory of that name put at a path of the dataset
 * gone stale is not a mount root, and a symlink there is not followed.
 */
static bool shadow_copy_zfs_live_elsewhere(vfs_handle_struct *handle,
					   const struct files_struct *dirfsp,
					   const struct smb_filename *smb_fname,
					   uint64_t mnt_id)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *rel = NULL;
	char *path = NULL;
	struct statx stx;
	bool ret = false;

	rel = full_path_from_dirfsp_at_basename(frame, dirfsp,
						smb_fname->base_name);
	if (rel != NULL) {
		path = shadow_copy_zfs_abspath(frame, handle->conn->connectpath,
					       rel);
	}
	if (path != NULL) {
		ret = (statx(AT_FDCWD, path,
			     AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW,
			     STATX_MNT_ID_UNIQUE, &stx) == 0) &&
		      (stx.stx_mask & STATX_MNT_ID_UNIQUE) &&
		      (stx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) &&
		      (stx.stx_attributes & STATX_ATTR_MOUNT_ROOT) &&
		      (stx.stx_mnt_id != mnt_id);
	}
	TALLOC_FREE(frame);
	return ret;
}

/*
 * Open a single name below a directory that is open in a snapshot, inside
 * that snapshot: one open from the fd of the directory, on its pin. A
 * snapshot holds no other mount, no symlink is followed and ".." does not
 * come here, so this cannot leave the snapshot; the device of what was
 * opened is checked all the same. A directory that is, live, the root of
 * a child dataset has previous versions of its own: it is not opened
 * here, and *child says so.
 */
static int shadow_copy_zfs_openat_in_snapshot(vfs_handle_struct *handle,
					      const struct files_struct *dirfsp,
					      struct snapdir_pin *pin,
					      const struct smb_filename *smb_fname,
					      files_struct *fsp,
					      const struct vfs_open_how *how,
					      bool *child)
{
	struct stat st;
	int fd, saved_errno;

	*child = false;

	fd = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
	if (fd == -1) {
		return -1;
	}
	if ((fstat(fd, &st) != 0) || (st.st_dev != pin->dev)) {
		DBG_ERR("%s/%s: not in the snapshot %s\n", fsp_str_dbg(dirfsp),
			smb_fname->base_name, pin->name);
		close(fd);
		errno = ENOENT;
		return -1;
	}
	if (S_ISDIR(st.st_mode) && !ISDOT(smb_fname->base_name) &&
	    shadow_copy_zfs_live_elsewhere(handle, dirfsp, smb_fname,
					   pin->mnt_id)) {
		close(fd);
		*child = true;
		return -1;
	}

	pin->refcnt++;
	if (!shadow_fsp_set_pin(handle, fsp, pin)) {
		saved_errno = errno;
		close(fd);
		snapdir_pin_put(pin);
		errno = saved_errno;
		return -1;
	}
	return fd;
}

static int shadow_copy_zfs_open(vfs_handle_struct *handle,
				const struct files_struct *dirfsp,
				const struct smb_filename *smb_fname_in,
				files_struct *fsp,
				const struct vfs_open_how *how)
{
	struct shadow_copy_zfs_config *config = NULL;
	struct smb_filename *smb_fname = NULL;
	struct shadow_fsp_ext *dir_ext = NULL;
	struct snapdir_pin *pin = NULL;
	struct vfs_open_how snap_how = *how;
	struct vfs_open_how noxdev_how;
	struct snap_target tgt;
	char *conv = NULL;
	bool child = false;
	int saved_errno;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return -1);

	if (!shadow_copy_zfs_match_name(smb_fname_in)) {
		if (!config->no_dataset_traversal ||
		    is_named_stream(smb_fname_in) ||
		    ISDOT(smb_fname_in->base_name) ||
		    strncmp(smb_fname_in->base_name,
			    "/proc/self/fd/",
			    sizeof("/proc/self/fd/") - 1) == 0) {
			return SMB_VFS_NEXT_OPENAT(handle,
						   dirfsp,
						   smb_fname_in,
						   fsp, how);
		}

		/*
		 * If we're here it means that we've configured the
		 * share to not allow traversal out of dataset boundaries.
		 * This means that if we are sharing dozer/SHARE and have
		 * dozer/SHARE/SUBDATASET, we will not allow opening the
		 * SUBDATASET. This is related to SMB share contract for
		 * tiering more than anything else.
		 */
		noxdev_how = *how;
		noxdev_how.resolve |= VFS_OPEN_HOW_RESOLVE_NO_XDEV;
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname_in,
					   fsp, &noxdev_how);
	}

	shadow_copy_zfs_snap_how(&snap_how);

	/*
	 * A single name below a directory open in a snapshot, at the time
	 * of that snapshot, is in it: smbd walks a path and lists a
	 * directory one name at a time. Not "..": at the root of the
	 * snapshot it would lead into the snapshot directory, and the full
	 * name maps it to the parent as it was at that time. Nor the root
	 * of a child dataset, which has snapshots of its own.
	 */
	if (dirfsp != NULL) {
		dir_ext = VFS_FETCH_FSP_EXTENSION(handle, dirfsp);
	}
	if ((dir_ext != NULL) && (dir_ext->pin != NULL) &&
	    (dir_ext->pin->twrp == smb_fname_in->twrp) &&
	    (strchr(smb_fname_in->base_name, '/') == NULL) &&
	    !ISDOTDOT(smb_fname_in->base_name)) {
		ret = shadow_copy_zfs_openat_in_snapshot(handle, dirfsp,
							 dir_ext->pin,
							 smb_fname_in, fsp,
							 &snap_how, &child);
		if (!child) {
			return ret;
		}
	}

	smb_fname = full_path_from_dirfsp_atname(talloc_tos(), dirfsp,
						 smb_fname_in);
	if (smb_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	conv = shadow_copy_zfs_convert(handle, smb_fname, &tgt);
	if (conv == NULL) {
		saved_errno = errno;
		TALLOC_FREE(smb_fname);
		errno = saved_errno;
		return -1;
	}
	smb_fname->base_name = conv;

	pin = snapdir_pin_get(config, &tgt);
	if (pin == NULL) {
		ret = -1;
		goto out;
	}

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, &snap_how);
	if (ret == -1) {
		saved_errno = errno;
		snapdir_pin_put(pin);
		errno = saved_errno;
		goto out;
	}

	/*
	 * The path of the dataset is the one it had when first resolved. A
	 * directory above it renamed since leaves a path that may lead into
	 * anything: what was opened must be in the snapshot of the pin, which
	 * was found from the verified snapshot directory. Below the root of
	 * the snapshot nothing can change, and there is no other mount.
	 */
	if (!fd_on_dev(ret, pin->dev)) {
		DBG_ERR("%s: not in the snapshot %s of mount ID %" PRIu64
			"\n", conv, pin->name, pin->mnt_id);
		close(ret);
		snapdir_pin_put(pin);
		errno = ENOENT;
		ret = -1;
		goto out;
	}

	if (!shadow_fsp_set_pin(handle, fsp, pin)) {
		saved_errno = errno;
		close(ret);
		snapdir_pin_put(pin);
		errno = saved_errno;
		ret = -1;
		goto out;
	}

out:
	saved_errno = errno;
	TALLOC_FREE(smb_fname);
	errno = saved_errno;
	return ret;
}

/*
 * A stat by name takes the rules of openat_fn, or the modules below would
 * answer for the name as it is in the snapshot of the directory. smbd
 * stats an entry of a listing by name when its open failed with other
 * than ENOENT, EACCES, EPERM or EXDEV (openat_pathref_fsp_lcomp()), and a
 * search for one name before any open (dptr_ReadDirName()). A single
 * name below a directory open in a snapshot is stat'ed in it from its
 * fd; the root of a child dataset has previous versions of its own, and
 * none here with shadow:no_dataset_traversal, like any name on the full
 * path.
 */
static int shadow_copy_zfs_fstatat(vfs_handle_struct *handle,
				   const struct files_struct *dirfsp,
				   const struct smb_filename *smb_fname_in,
				   SMB_STRUCT_STAT *sbuf,
				   int flags)
{
	struct shadow_fsp_ext *dir_ext = NULL;
	struct smb_filename *smb_fname = NULL;
	int saved_errno;
	int ret;

	if (!shadow_copy_zfs_match_name(smb_fname_in)) {
		return SMB_VFS_NEXT_FSTATAT(handle, dirfsp, smb_fname_in,
					    sbuf, flags);
	}

	if (dirfsp != NULL) {
		dir_ext = VFS_FETCH_FSP_EXTENSION(handle, dirfsp);
	}
	if ((dir_ext != NULL) && (dir_ext->pin != NULL) &&
	    (dir_ext->pin->twrp == smb_fname_in->twrp) &&
	    (strchr(smb_fname_in->base_name, '/') == NULL) &&
	    !ISDOTDOT(smb_fname_in->base_name)) {
		ret = SMB_VFS_NEXT_FSTATAT(handle, dirfsp, smb_fname_in,
					   sbuf, flags);
		if (ret != 0) {
			return ret;
		}
		if (sbuf->st_ex_dev != dir_ext->pin->dev) {
			DBG_ERR("%s/%s: not in the snapshot %s\n",
				fsp_str_dbg(dirfsp), smb_fname_in->base_name,
				dir_ext->pin->name);
			errno = ENOENT;
			return -1;
		}
		if (!S_ISDIR(sbuf->st_ex_mode) ||
		    ISDOT(smb_fname_in->base_name) ||
		    !shadow_copy_zfs_live_elsewhere(handle, dirfsp,
						    smb_fname_in,
						    dir_ext->pin->mnt_id)) {
			return 0;
		}
	}

	smb_fname = full_path_from_dirfsp_atname(talloc_tos(), dirfsp,
						 smb_fname_in);
	if (smb_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	ret = shadow_copy_zfs_stat_common(handle, smb_fname,
					  (flags & AT_SYMLINK_NOFOLLOW) != 0);
	if (ret == 0) {
		*sbuf = smb_fname->st;
	}
	saved_errno = errno;
	TALLOC_FREE(smb_fname);
	errno = saved_errno;
	return ret;
}

/*
 * A batch stat of entries of dirfsp goes down with the names as they
 * are. None in a snapshot, where an entry may need the conversion of
 * fstatat_fn: each is then stat'ed through it.
 */
static int shadow_copy_zfs_batch_attr_submit(vfs_handle_struct *handle,
					     const struct files_struct *dirfsp,
					     struct vfs_attr_entry *ents,
					     size_t count,
					     uint32_t want)
{
	if ((dirfsp->fsp_name->twrp != 0) || fsp_in_snapshot(handle, dirfsp)) {
		errno = ENOSYS;
		return -1;
	}
	return SMB_VFS_NEXT_BATCH_ATTR_SUBMIT(handle, dirfsp, ents, count,
					      want);
}

static int shadow_copy_zfs_readlinkat(vfs_handle_struct *handle,
				      const struct files_struct *dirfsp,
				      const struct smb_filename *smb_fname,
				      char *buf,
				      size_t bufsiz)
{
	struct smb_filename *full = NULL;
	struct snapdir_pin *pin = NULL;
	char *conv = NULL;
	int saved_errno;
	int fd = -1;
	int ret;

	/* a name relative to a directory open in a snapshot needs nothing */
	if (!shadow_copy_zfs_match_name(smb_fname) ||
	    fsp_in_snapshot(handle, dirfsp)) {
		return SMB_VFS_NEXT_READLINKAT(handle, dirfsp, smb_fname, buf,
					       bufsiz);
	}

	full = full_path_from_dirfsp_atname(talloc_tos(), dirfsp, smb_fname);
	if (full == NULL) {
		errno = ENOMEM;
		return -1;
	}
	conv = shadow_copy_zfs_convert_checked(handle, full, true, &pin, &fd);
	saved_errno = errno;
	TALLOC_FREE(full);
	if (conv == NULL) {
		errno = saved_errno;
		return -1;
	}
	/* the link the name resolved to in the snapshot, not the path */
	ret = readlinkat(fd, "", buf, bufsiz);
	saved_errno = errno;
	close(fd);
	snapdir_pin_put(pin);
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static struct smb_filename *shadow_copy_zfs_realpath(vfs_handle_struct *handle,
						     TALLOC_CTX *ctx,
						     const struct smb_filename *smb_fname)
{
	struct smb_filename *ret = NULL;
	struct smb_filename conv_smb_fname;
	struct snapdir_pin *pin = NULL;
	char *conv = NULL;
	int fd = -1;

	if (!shadow_copy_zfs_match_name(smb_fname)) {
		return SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
	}
	conv = shadow_copy_zfs_convert_checked(handle, smb_fname, false, &pin,
					       &fd);
	if (conv == NULL) {
		errno = ENOENT;
		return NULL;
	}
	close(fd);
	snapdir_pin_put(pin);

	conv_smb_fname = (struct smb_filename) {
		.base_name = conv,
		.flags = smb_fname->flags
	};
	ret = SMB_VFS_NEXT_REALPATH(handle, ctx, &conv_smb_fname);
	/*
	 * The name resolved without symlinks, so its real path is itself
	 * unless something above the snapshot changed in between.
	 */
	if ((ret != NULL) && (strcmp(ret->base_name, conv) != 0)) {
		DBG_ERR("%s: resolves to %s\n", conv, ret->base_name);
		TALLOC_FREE(ret);
		errno = ENOENT;
	}
	TALLOC_FREE(conv);
	return ret;
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
	uint32_t idx = 0;
	const char *mpoffset = NULL;
	char *rel = NULL;
	enum casesensitivity sens;
	int snapdir_fd;
	int rv;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy_zfs_config,
				return -1);

	if (config->ds == NULL) {
		DBG_INFO("No dataset present for share at path: %s\n",
			handle->conn->connectpath);
		return 0;
	}

	if (config->snapshot_share) {
		DBG_INFO("%s: share is rooted inside a snapshot\n",
			 handle->conn->connectpath);
		return 0;
	}

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

	snapshots = shadow_copy_zfs_get_snaplist(handle, NULL, fsp, &sens);
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

	mpoffset = shadow_copy_zfs_mp_offset(handle->conn->connectpath,
					     snapshots->mountpoint);
	rel = get_snapshot_relpath(talloc_tos(), handle->conn->connectpath,
				   snapshots->mountpoint,
				   fsp->fsp_name->base_name, mpoffset, sens);
	if (rel == NULL) {
		DBG_INFO("%s: no path in the snapshots of %s\n",
			 fsp_str_dbg(fsp), snapshots->dataset_name);
		shadow_copy_zfs_data->num_volumes = 0;
		return 0;
	}

	/*
	 * Each version is looked up below the verified snapshot directory,
	 * beneath it and through no symlink, not by the path of the dataset.
	 */
	snapdir_fd = smb_zfs_open_snapdir(snapshots->mountpoint,
					  snapshots->mnt_id);
	if (snapdir_fd == -1) {
		int saved_errno = shadow_copy_zfs_errno(errno);

		TALLOC_FREE(rel);
		errno = saved_errno;
		return -1;
	}

	for (entry = snapshots->entries; entry && idx < MAX_SNAPSHOT_COUNT; entry = entry->next) {
		/*
		 * Directories should always be added if they exist in the
		 * snapshot. Files only be added if mtime differs.
		 */
		struct open_how how = {
			.flags = O_PATH | O_CLOEXEC,
			.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
		};
		SMB_STRUCT_STAT cur_st;
		char *snapname = NULL;
		int fd;

		/*
		 * Snapshots taken in one second share a label, and a
		 * timewarp at that label opens the first of them: list it
		 * once, for that one.
		 */
		if ((entry != snapshots->entries) &&
		    (entry->prev->nt_time == entry->nt_time)) {
			continue;
		}

		snapname = talloc_asprintf(talloc_tos(), "%s%s%s", entry->name,
					   (rel[0] == '\0') ? "" : "/", rel);
		if (snapname == NULL) {
			break;
		}
		DBG_INFO("snapshot[%d]: ts: %ld, gmt: %s, name: %s\n",
			 idx, entry->cr_time, entry->label, snapname);

		fd = openat2(snapdir_fd, snapname, &how, sizeof(how));
		if (fd == -1) {
			DBG_INFO("%s/%s: %s\n", snapshots->mountpoint, snapname,
				 strerror(errno));
			TALLOC_FREE(snapname);
			continue;
		}
		TALLOC_FREE(snapname);
		rv = sys_fstat(fd, &cur_st, false);
		close(fd);
		if (rv != 0) {
			continue;
		}
		if (config->ignore_empty_snaps && !S_ISDIR(cur_st.st_ex_mode) &&
		    shadow_copy_zfs_same_version(&cur_st, &prev_st)) {
			continue;
		}
		if (labels) {
			strlcpy(shadow_copy_zfs_data->labels[idx],
				entry->label, sizeof(SHADOW_COPY_LABEL));
		}
		idx++;
		prev_st = cur_st;
	}
	close(snapdir_fd);
	TALLOC_FREE(rel);

	shadow_copy_zfs_data->num_volumes = idx;
	return 0;
}

static NTSTATUS shadow_copy_zfs_get_real_filename_at(
        struct vfs_handle_struct *handle,
        struct files_struct *dirfsp,
        const char *path,
        TALLOC_CTX *mem_ctx,
        char **found_name)
{
	NTSTATUS status;
	struct smb_filename *snap_fname = NULL;

	if (!shadow_copy_zfs_match_fsp(handle, dirfsp)) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME_AT(handle, dirfsp, path,
							 mem_ctx, found_name);
	}

	/*
	 * dirfsp has a timewarp token but was not opened through us: open
	 * it again by its name, which the open above checks, and scan that.
	 */
	status = synthetic_pathref(talloc_tos(),
				   dirfsp->conn->cwd_fsp,
				   dirfsp->fsp_name->base_name,
				   NULL,
				   NULL,
				   dirfsp->fsp_name->twrp,
				   dirfsp->fsp_name->flags,
				   &snap_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("%s: open in the snapshot failed: %s\n",
			  fsp_str_dbg(dirfsp), nt_errstr(status));
		return status;
	}

	status = get_real_filename_at(snap_fname->fsp, path, mem_ctx,
				      found_name);
	DBG_DEBUG("Scan [%s] for [%s]: %s\n",
		  fsp_str_dbg(dirfsp), path, nt_errstr(status));
	TALLOC_FREE(snap_fname);
	return status;
}

/*
 * A name with a timewarp token for the path-based calls that the modules
 * below answer from the stat of the name (zfs_core: its mount ID): the
 * converted path with the stat of what it resolves to in the snapshot, so
 * that nothing is looked up by path again.
 */
static struct smb_filename *shadow_copy_zfs_resolved_fname(
	vfs_handle_struct *handle,
	const struct smb_filename *smb_fname)
{
	struct smb_filename *ret = NULL;
	struct snapdir_pin *pin = NULL;
	SMB_STRUCT_STAT st;
	char *conv = NULL;
	int saved_errno;
	int fd = -1;
	int rc;

	conv = shadow_copy_zfs_convert_checked(handle, smb_fname, false, &pin,
					       &fd);
	if (conv == NULL) {
		return NULL;
	}
	rc = sys_fstat(fd, &st, false);
	saved_errno = errno;
	close(fd);
	snapdir_pin_put(pin);
	if (rc != 0) {
		TALLOC_FREE(conv);
		errno = saved_errno;
		return NULL;
	}
	ret = synthetic_smb_fname(talloc_tos(), conv, NULL, &st, 0,
				  smb_fname->flags);
	TALLOC_FREE(conv);
	if (ret == NULL) {
		errno = ENOMEM;
	}
	return ret;
}

static uint64_t shadow_copy_zfs_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	struct smb_filename *resolved = NULL;
	uint64_t ret;

	if (!shadow_copy_zfs_match_name(smb_fname)) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree,
					      dsize);
	}
	resolved = shadow_copy_zfs_resolved_fname(handle, smb_fname);
	if (resolved == NULL) {
		return (uint64_t)-1;
	}
	ret = SMB_VFS_NEXT_DISK_FREE(handle, resolved, bsize, dfree, dsize);
	TALLOC_FREE(resolved);
	return ret;
}

static int shadow_copy_zfs_get_quota(vfs_handle_struct *handle,
				     const struct smb_filename *smb_fname,
				     enum SMB_QUOTA_TYPE qtype, unid_t id,
				     SMB_DISK_QUOTA *dq)
{
	struct smb_filename *resolved = NULL;
	int ret;

	if (!shadow_copy_zfs_match_name(smb_fname)) {
		return SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, dq);
	}
	resolved = shadow_copy_zfs_resolved_fname(handle, smb_fname);
	if (resolved == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_GET_QUOTA(handle, resolved, qtype, id, dq);
	TALLOC_FREE(resolved);
	return ret;
}

/*
 * The parent of the root of a dataset is in another dataset, which may have
 * no snapshot at the time of the name: then use the live parent.
 */
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

	if (!NT_STATUS_IS_OK(status) ||
	    !VALID_STAT(smb_fname_in->st) ||
	    !(smb_fname_in->st.st_ex_flags & ST_EX_ATTR_MOUNT_ROOT) ||
	    !shadow_copy_zfs_match_name(smb_fname_in)) {
		return status;
	}

	fname_ref = *parent_dir_out;

	tmp_fname = shadow_copy_zfs_convert(handle, fname_ref, NULL);
	if (tmp_fname != NULL) {
		TALLOC_FREE(tmp_fname);
		return NT_STATUS_OK;
	}
	if (errno != ENOENT) {
		status = map_nt_error_from_unix(errno);
		/* the atname is allocated under the parent */
		TALLOC_FREE(*parent_dir_out);
		if (atname_out != NULL) {
			*atname_out = NULL;
		}
		return status;
	}
	fname_ref->twrp = 0;
	return NT_STATUS_OK;
}

static int shadow_copy_zfs_connect(struct vfs_handle_struct *handle,
				const char *service, const char *user)
{
	struct shadow_copy_zfs_config *config = NULL;
	const char **exclusions = NULL;
	const char **inclusions = NULL;
	int ret, saved_errno;

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
		goto disconnect_out;
	}

	ret = conn_zfs_init(handle->conn->connectpath, &config->ds);

	if (ret != 0) {
		DBG_ERR("Failed to initialize zfs: %s\n", strerror(errno));
		goto disconnect_out;
	}

	if (config->ds != NULL) {
		config->snapshot_share = shadow_copy_zfs_in_snapshot(
					handle->conn->connectpath,
					config->ds->mountpoint);
		if (config->snapshot_share) {
			DBG_NOTICE("%s: share is rooted inside a snapshot; "
				   "previous versions are not available for "
				   "it\n", handle->conn->connectpath);
		}
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

	/* skip file versions with the same data as the next newer one */
	config->ignore_empty_snaps = lp_parm_bool(SNUM(handle->conn), "shadow",
						  "ignore_empty_snaps", true);

	config->no_dataset_traversal = lp_parm_bool(SNUM(handle->conn), "shadow",
						     "no_dataset_traversal", false);
	if (config->no_dataset_traversal) {
		handle->conn->internal_tcon_flags |= TCON_FLAG_NOXDEV;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config, NULL,
				struct shadow_copy_zfs_config,
				return -1);

	return 0;

disconnect_out:

	saved_errno = errno;
	TALLOC_FREE(config);
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
	.fstatat_fn = shadow_copy_zfs_fstatat,
	.batch_attr_submit_fn = shadow_copy_zfs_batch_attr_submit,
	.openat_fn = shadow_copy_zfs_open,
	.unlinkat_fn = shadow_copy_zfs_unlinkat,
	.lchown_fn = shadow_copy_zfs_lchown,
	.readlinkat_fn = shadow_copy_zfs_readlinkat,
	.mknodat_fn = shadow_copy_zfs_mknodat,
	.realpath_fn = shadow_copy_zfs_realpath,
	.get_shadow_copy_data_fn = shadow_copy_zfs_get_shadow_copy_zfs_data,
	.mkdirat_fn = shadow_copy_zfs_mkdirat,
	.get_real_filename_at_fn = shadow_copy_zfs_get_real_filename_at,
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
