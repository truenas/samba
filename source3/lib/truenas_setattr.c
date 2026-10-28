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

#include "replace.h"
#include "system/filesys.h"
#include "lib/truenas_setattr.h"

#define TRUENAS_XATTR_SETATTR		"system.truenas_setattr"
#define TRUENAS_XATTR_SETATTR_VERSION	1

void truenas_setattr_init(struct truenas_setattr *sa)
{
	*sa = (struct truenas_setattr) {
		.zsa_version = TRUENAS_XATTR_SETATTR_VERSION,
		.zsa_hdrsize = sizeof(*sa),
	};
}

void truenas_setattr_time(struct truenas_setattr *sa,
			  uint64_t which,
			  struct timespec ts)
{
	struct truenas_setattr_time t = {
		.zt_sec = ts.tv_sec,
		.zt_nsec = ts.tv_nsec,
	};

	switch (which) {
	case TRUENAS_SETATTR_ATIME:
		sa->zsa_atime = t;
		break;
	case TRUENAS_SETATTR_MTIME:
		sa->zsa_mtime = t;
		break;
	case TRUENAS_SETATTR_BTIME:
		sa->zsa_btime = t;
		break;
	default:
		return;
	}
	sa->zsa_valid |= which;
}

void truenas_setattr_dosflags(struct truenas_setattr *sa,
			      uint64_t set,
			      uint64_t clear)
{
	sa->zsa_dos_set = set;
	sa->zsa_dos_clear = clear;
	sa->zsa_valid |= TRUENAS_SETATTR_DOSFLAGS;
}

int truenas_setattr(int fd, const char *path, const struct truenas_setattr *sa)
{
	if (fd != -1) {
		return fsetxattr(fd, TRUENAS_XATTR_SETATTR, sa, sizeof(*sa), 0);
	}
	return setxattr(path, TRUENAS_XATTR_SETATTR, sa, sizeof(*sa), 0);
}
