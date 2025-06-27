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

#define __NR_NAME_TO_HANDLE_AT 303
#define __NR_OPEN_BY_HANDLE_AT 304
#define INIT_HANDLE_SZ 128 // MAX_HANDLE_SZ as of 6.13 kernel
#define AT_HANDLE_FID AT_REMOVEDIR


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
	uint64_t gen_id;
	struct file_handle *kern_fh; /* kernel file handle */
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

	fh->kern_fh = talloc_zero_size(fh, INIT_HANDLE_SZ);
	if (fh->kern_fh == NULL) {
		TALLOC_FREE(fh);
		return NULL;
	}

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

	SMB_ASSERT(fsp->fh->fd == -1 ||
		   fsp->fh->fd == fd ||
		   fd == -1 ||
		   fd == AT_FDCWD);

	fsp->fh->fd = fd;

	DBG_ERR("XXX: setting %d on %s\n", fd, fsp_str_dbg(fsp));

	if (fd != -1 && fd != AT_FDCWD &&  // Need a valid fd
	    fsp->fsp_name && fsp->fsp_name->st.st_ex_mnt_id && // and some mount info 
	    fsp->conn->internal_tcon_flags & TCON_FLAG_SUPPORTS_FHANDLE) {
		int err;
		uint64_t mntid = fsp->fsp_name->st.st_ex_mnt_id; 
		err = syscall(__NR_NAME_TO_HANDLE_AT,
			      fd, "", fsp->fh->kern_fh,
			      fsp->fsp_name->st.st_ex_mnt_id, AT_EMPTY_PATH);

		DBG_ERR("XXX: %d from %s errno %d\n", err, fsp_str_dbg(fsp), errno);
	}
}

int fsp_reopen_pathref_from_kern_fh(struct files_struct *fsp, int flags)
{
	int fd;

	if (!fsp->fsp_flags.is_pathref || fsp->fh->kern_fh->handle_bytes == 0) {
		errno = EOPNOTSUPP;
		return -1;
	}

	set_effective_capability(DAC_READ_SEARCH);
	fd = syscall(__NR_OPEN_BY_HANDLE_AT, fsp->fh->fd, fsp->fh->kern_fh, flags);
	drop_effective_capability(DAC_READ_SEARCH);

	return fd;
}
