/*
 * Unix SMB/CIFS implementation.
 * TrueNAS: set times and DOS attributes of a ZFS file in one transaction
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

#ifndef __LIB_TRUENAS_SETATTR_H__
#define __LIB_TRUENAS_SETATTR_H__

/*
 * Setting system.truenas_setattr on a file sets what the value names in
 * one zfs_setattr(), with the checks of chmod(2) and utimensat(2) as the
 * caller. The value is the struct below, as include/sys/fs/zfs.h of
 * TrueNAS OpenZFS defines it.
 */
#define TRUENAS_SETATTR_ATIME		(1ULL << 3)
#define TRUENAS_SETATTR_MTIME		(1ULL << 4)
#define TRUENAS_SETATTR_BTIME		(1ULL << 5)
#define TRUENAS_SETATTR_DOSFLAGS	(1ULL << 6)
#define TRUENAS_SETATTR_TIMES		(TRUENAS_SETATTR_ATIME | \
					 TRUENAS_SETATTR_MTIME | \
					 TRUENAS_SETATTR_BTIME)

struct truenas_setattr_time {
	int64_t zt_sec;
	int64_t zt_nsec;
};

struct truenas_setattr {
	uint32_t zsa_version;
	uint32_t zsa_hdrsize;
	uint64_t zsa_valid;	/* TRUENAS_SETATTR_* */
	uint32_t zsa_mode;
	uint32_t zsa_mode_mask;
	uint32_t zsa_uid;
	uint32_t zsa_gid;
	struct truenas_setattr_time zsa_atime;
	struct truenas_setattr_time zsa_mtime;
	struct truenas_setattr_time zsa_btime;
	uint64_t zsa_dos_set;	/* ZFS DOS flags, ZFS_* in sys/zfs_znode.h */
	uint64_t zsa_dos_clear;
	uint32_t zsa_acl_len;
	uint32_t zsa_flags;
	uint64_t zsa_reserved[5];
};

/* A request that names nothing */
void truenas_setattr_init(struct truenas_setattr *sa);

/* Name a time, one of TRUENAS_SETATTR_TIMES. UTIME_NOW is allowed. */
void truenas_setattr_time(struct truenas_setattr *sa,
			  uint64_t which,
			  struct timespec ts);

/* Name the ZFS DOS flags to set and to clear */
void truenas_setattr_dosflags(struct truenas_setattr *sa,
			      uint64_t set,
			      uint64_t clear);

/* Apply sa to the file open as fd, or if fd is -1 to path */
int truenas_setattr(int fd, const char *path, const struct truenas_setattr *sa);

#endif /* __LIB_TRUENAS_SETATTR_H__ */
