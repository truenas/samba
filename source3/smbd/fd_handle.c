/*
   Unix SMB/CIFS implementation.
   fd_handle structure handling
   Copyright (C) Ralph Boehme 2020

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "fd_handle.h"

struct fd_handle {
	size_t ref_count;
	int fd;
	uint64_t position_information;
	off_t pos;
	/*
	 * NT Create options, but we only look at
	 * NTCREATEX_FLAG_DENY_DOS and
	 * NTCREATEX_FLAG_DENY_FCB.
	 */
	uint32_t private_options;
	int status_flags;  /* TrueNAS */
	uint64_t gen_id;
};

static int fd_handle_destructor(struct fd_handle *fh)
{
	SMB_ASSERT((fh->fd == -1) || (fh->fd == AT_FDCWD));
	return 0;
}

struct fd_handle *fd_handle_create(TALLOC_CTX *mem_ctx)
{
	struct fd_handle *fh = NULL;

	fh = talloc_zero(mem_ctx, struct fd_handle);
	if (fh == NULL) {
		return NULL;
	}
	fh->fd = -1;

	talloc_set_destructor(fh, fd_handle_destructor);

	return fh;
}

size_t fh_get_refcount(struct fd_handle *fh)
{
	return fh->ref_count;
}

void fh_set_refcount(struct fd_handle *fh, size_t ref_count)
{
	fh->ref_count = ref_count;
}

uint64_t fh_get_position_information(struct fd_handle *fh)
{
	return fh->position_information;
}

void fh_set_position_information(struct fd_handle *fh, uint64_t posinfo)
{
	fh->position_information = posinfo;
}

off_t fh_get_pos(struct fd_handle *fh)
{
	return fh->pos;
}

void fh_set_pos(struct fd_handle *fh, off_t pos)
{
	fh->pos = pos;
}

uint32_t fh_get_private_options(struct fd_handle *fh)
{
	return fh->private_options;
}

void fh_set_private_options(struct fd_handle *fh, uint32_t private_options)
{
	fh->private_options = private_options;
}

uint64_t fh_get_gen_id(struct fd_handle *fh)
{
	return fh->gen_id;
}

void fh_set_gen_id(struct fd_handle *fh, uint64_t gen_id)
{
	fh->gen_id = gen_id;
}

/****************************************************************************
 Helper functions for working with fsp->fh->fd
****************************************************************************/

int fsp_get_io_fd(const struct files_struct *fsp)
{
	if (fsp->fsp_flags.is_pathref) {
		DBG_ERR("fsp [%s] is a path referencing fsp\n",
			fsp_str_dbg(fsp));
#ifdef DEVELOPER
		smb_panic("fsp is a pathref");
#endif
		return -1;
	}

	return fsp->fh->fd;
}

int fsp_get_pathref_fd(const struct files_struct *fsp)
{
	return fsp->fh->fd;
}

void fsp_set_fd(struct files_struct *fsp, int fd)
{
	/*
	 * Deliberately allow setting an fd if the existing fd is the
	 * same. This happens if a VFS module assigns the fd to
	 * fsp->fh->fd in its openat VFS function. The canonical place
	 * where the assignment is done is in fd_open(), but some VFS
	 * modules do it anyway.
	 */
	bool fd_changed = fsp->fh->fd != fd;

	SMB_ASSERT(fsp->fh->fd == -1 ||
		   fsp->fh->fd == fd ||
		   fd == -1 ||
		   fd == AT_FDCWD);

	fsp->fh->fd = fd;

	/* TrueNAS changes */
	if (fd_changed || fsp->fh->status_flags == 0) {
		if (fsp->fh->fd == -1 || fsp->fh->fd == AT_FDCWD) {
			fsp->fh->status_flags = 0;
		} else {
			fsp->fh->status_flags = fcntl(fd, F_GETFL);
		}
	}
}

/* TrueNAS changes */
int fsp_get_status_flags(const struct files_struct *fsp)
{
	return fsp->fh->status_flags;
}

/*
 * There are various places where if the pathref was O_PATH we'd have
 * to make a call through procfs to perform an operation because the
 * access mode for the fd is incorrect for the syscall (for example
 * getxattr, listxattr, reading ACLs). This provides a quick check of
 * our stored status flags for the fd and replies whether the desired
 * access will require using the procfd path e.g.
 * getxattr(/proc/self/fd/<fd>). The use for this is limited in scope
 * and new usage should be carefully validated.
 */
bool fsp_must_use_procfd_path(const struct files_struct *fsp,
			      int desired_access)
{
	int status = fsp_get_status_flags(fsp);

	if (status == 0) {
		return true;
	}

	if (desired_access == O_RDONLY) {
		// Allow O_DIRECTORY to fulfill request for O_RDONLY
		return status & (O_PATH | O_RDWR | O_WRONLY) == 0;

	}

	return status & desired_access == 0;
}

/*
 * This is a check for whether the fd in the fd_handle is suitable
 * for performing fd-based syscalls that require minimally O_RDONLY
 * access mode. This is specifically to be used in places where
 * the VFS would need to perform a path-based syscall through a
 * procfd path (/proc/self/fd/<fd>) as an optimization to avoid
 * unnecessary lookups
 */
bool fsp_has_read_access(const struct files_struct *fsp)
{
	if (!fsp->fsp_flags.is_pathref) {
		/*
		 * This is not an O_PATH open and so we can
		 * use it with fgetxattr, flistxattr, and ioctl
		 * calls
		 */
		return true;
	}

	return !fsp_must_use_procfd_path(fsp, O_RDONLY);
}
