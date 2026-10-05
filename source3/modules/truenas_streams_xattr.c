/*
 * Store streams in xattrs
 *
 * Copyright (C) Volker Lendecke, 2008
 *
 * Partly based on James Peach's Darwin module, which is
 *
 * Copyright (C) James Peach 2006-2007
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
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "lib/util/tevent_unix.h"
#include "librpc/gen_ndr/ioctl.h"
#include "hash_inode.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct streams_xattr_config {
	const char *prefix;
	size_t prefix_len;
	bool store_stream_type;
	int xattr_compat_bytes;
};

struct stream_io {
	char *base;
	char *xattr_name;
	void *fsp_name_ptr;
	files_struct *fsp;
	vfs_handle_struct *handle;
};

static bool can_write_ea(files_struct *fsp)
{
	NTSTATUS status;
	status = smbd_check_access_rights_fsp(fsp->conn->cwd_fsp,
					      fsp,
					      false,
					      SEC_FILE_WRITE_EA);
	return NT_STATUS_IS_OK(status);
}

/*
 * Length of the xattr holding a stream, trailing compat byte included,
 * without reading it: a size-only getxattr makes neither the kernel nor ZFS
 * allocate or copy a value buffer. Fails on symlinks and on values over
 * "smbd max xattr size", which get_xattr_value_fsp() won't read either.
 */
static ssize_t get_xattr_len_fsp(struct files_struct *fsp,
				 const char *xattr_name)
{
	ssize_t len;

	if (refuse_symlink_fsp(fsp)) {
		errno = EACCES;
		return -1;
	}

	len = SMB_VFS_FGETXATTR(fsp, xattr_name, NULL, 0);
	if ((len != -1) && (len > lp_smbd_max_xattr_size(SNUM(fsp->conn)))) {
		errno = ERANGE;
		return -1;
	}

	return len;
}

/*
 * Size of the stream in xattr_name as clients see it: get_xattr_len_fsp()
 * minus the trailing byte xattr_compat = no stores. A zero length is an empty
 * stream with xattr_compat = yes; values too short to hold that byte fail
 * with EINVAL, as pread and pwrite do.
 */
static ssize_t get_stream_size_fsp(vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   const char *xattr_name)
{
	ssize_t len;
	struct streams_xattr_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	len = get_xattr_len_fsp(fsp, xattr_name);
	if (len == -1) {
		return -1;
	}

	if (len < config->xattr_compat_bytes) {
		errno = EINVAL;
		return -1;
	}

	return len - config->xattr_compat_bytes;
}

/*
 * Read xattr_name into a new talloc buffer of size bytes. size must not be 0:
 * a 0-byte getxattr only asks for the size. Nothing is allocated on failure.
 */
static ssize_t fgetxattr_alloc(TALLOC_CTX *mem_ctx,
			       struct files_struct *fsp,
			       const char *xattr_name,
			       size_t size,
			       uint8_t **pval)
{
	uint8_t *val = NULL;
	ssize_t len;

	val = talloc_array(mem_ctx, uint8_t, size);
	if (val == NULL) {
		errno = ENOMEM;
		return -1;
	}

	len = SMB_VFS_FGETXATTR(fsp, xattr_name, val, size);
	if (len == -1) {
		int err = errno;

		TALLOC_FREE(val);
		errno = err;
		return -1;
	}

	*pval = val;
	return len;
}

/*
 * Read an xattr too large for get_xattr_value_fsp()'s first guess at its
 * exact size, rather than at "smbd max xattr size" (2 MiB on TrueNAS), which
 * the kernel would allocate and zero in full. Only if it grows between asking
 * and reading fall back to that.
 */
static ssize_t fgetxattr_large(TALLOC_CTX *mem_ctx,
			       struct files_struct *fsp,
			       const char *xattr_name,
			       uint8_t **pval)
{
	ssize_t len = get_xattr_len_fsp(fsp, xattr_name);

	if (len == -1) {
		return -1;
	}

	/* MAX: it may have been emptied since the first guess */
	len = fgetxattr_alloc(mem_ctx, fsp, xattr_name, MAX(len, 1), pval);
	if ((len == -1) && (errno == ERANGE)) {
		len = fgetxattr_alloc(mem_ctx, fsp, xattr_name,
				      lp_smbd_max_xattr_size(SNUM(fsp->conn)),
				      pval);
	}

	return len;
}

/*
 * Read the whole xattr holding a stream into a talloc buffer. The first guess
 * of 8 KiB fits nearly every stream in one call, and costs the kernel about
 * what a tiny buffer does: up to that size its copy comes from the kmalloc
 * slab caches, beyond it from the page allocator.
 */
static int get_xattr_value_fsp(TALLOC_CTX *mem_ctx,
			       struct files_struct *fsp,
			       const char *xattr_name,
			       struct ea_struct *pea)
{
	uint8_t *val = NULL;
	ssize_t len;

	if (refuse_symlink_fsp(fsp)) {
		return EACCES;
	}

	len = fgetxattr_alloc(mem_ctx, fsp, xattr_name, 8192, &val);
	if ((len == -1) && (errno == ERANGE)) {
		len = fgetxattr_large(mem_ctx, fsp, xattr_name, &val);
	}
	if (len == -1) {
		return errno;
	}

	*pea = (struct ea_struct) {
		.value = { .data = val, .length = len },
	};
	return 0;
}

/**
 * Given a stream name, populate xattr_name with the xattr name to use for
 * accessing the stream.
 */
static int streams_xattr_get_name(vfs_handle_struct *handle,
				  TALLOC_CTX *ctx,
				  const char *stream_name,
				  char **xattr_name)
{
	size_t stream_name_len = strlen(stream_name);
	char *stype;
	struct streams_xattr_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				return EACCES);

	SMB_ASSERT(stream_name[0] == ':');
	stream_name += 1;

	/*
	 * With vfs_fruit option "fruit:encoding = native" we're
	 * already converting stream names that contain illegal NTFS
	 * characters from their on-the-wire Unicode Private Range
	 * encoding to their native ASCII representation.
	 *
	 * As as result the name of xattrs storing the streams (via
	 * vfs_streams_xattr) may contain a colon, so we have to use
	 * strrchr_m() instead of strchr_m() for matching the stream
	 * type suffix.
	 *
	 * In check_path_syntax() we've already ensured the streamname
	 * we got from the client is valid.
	 */
	stype = strrchr_m(stream_name, ':');

	if (stype) {
		/*
		 * We only support one stream type: "$DATA"
		 */
		if (strcasecmp_m(stype, ":$DATA") != 0) {
			return EINVAL;
		}

		/* Split name and type */
		stream_name_len = (stype - stream_name);
	}

	*xattr_name = talloc_asprintf(ctx, "%s%.*s%s",
				      config->prefix,
				      (int)stream_name_len,
				      stream_name,
				      config->store_stream_type ? ":$DATA" : "");
	if (*xattr_name == NULL) {
		return ENOMEM;
	}

	DBG_DEBUG("%s, stream_name: %s\n", *xattr_name, stream_name);

	return 0;
}

static bool streams_xattr_recheck(struct stream_io *sio)
{
	int ret;
	char *xattr_name = NULL;

	if (sio->fsp->fsp_name == sio->fsp_name_ptr) {
		return true;
	}

	if (sio->fsp->fsp_name->stream_name == NULL) {
		/* how can this happen */
		errno = EINVAL;
		return false;
	}

	ret = streams_xattr_get_name(sio->handle,
				     talloc_tos(),
				     sio->fsp->fsp_name->stream_name,
				     &xattr_name);
	if (ret != 0) {
		return false;
	}

	TALLOC_FREE(sio->xattr_name);
	TALLOC_FREE(sio->base);
	sio->xattr_name = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(sio->handle, sio->fsp),
					xattr_name);
	if (sio->xattr_name == NULL) {
		DBG_DEBUG("sio->xattr_name==NULL\n");
		return false;
	}
	TALLOC_FREE(xattr_name);

	sio->base = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(sio->handle, sio->fsp),
				  sio->fsp->fsp_name->base_name);
	if (sio->base == NULL) {
		DBG_DEBUG("sio->base==NULL\n");
		return false;
	}

	sio->fsp_name_ptr = sio->fsp->fsp_name;

	return true;
}

static int streams_xattr_fstat(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_STRUCT_STAT *sbuf)
{
	int ret = -1;
	struct stream_io *io = (struct stream_io *)
		VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (io == NULL || !fsp_is_alternate_stream(fsp)) {
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	DBG_DEBUG("streams_xattr_fstat called for %s\n", fsp_str_dbg(io->fsp));

	if (!streams_xattr_recheck(io)) {
		return -1;
	}

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp->base_fsp, sbuf);
	if (ret == -1) {
		return -1;
	}

	sbuf->st_ex_size = get_stream_size_fsp(handle,
					       fsp->base_fsp,
					       io->xattr_name);
	if (sbuf->st_ex_size == -1) {
		SET_STAT_INVALID(*sbuf);
		return -1;
	}

	DBG_DEBUG("sbuf->st_ex_size = %jd\n", (intmax_t)sbuf->st_ex_size);

	sbuf->st_ex_ino = hash_inode(sbuf, io->xattr_name);
	sbuf->st_ex_mode &= ~S_IFMT;
	sbuf->st_ex_mode &= ~S_IFDIR;
        sbuf->st_ex_mode |= S_IFREG;
        sbuf->st_ex_blocks = sbuf->st_ex_size / STAT_ST_BLOCKSIZE + 1;

	return 0;
}

static int streams_xattr_stat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	NTSTATUS status;
	int ret;
	int result = -1;
	char *xattr_name = NULL;
	char *tmp_stream_name = NULL;
	struct smb_filename *pathref = NULL;
	struct files_struct *fsp = smb_fname->fsp;

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	/* Note if lp_posix_paths() is true, we can never
	 * get here as is_named_stream() is
	 * always false. So we never need worry about
	 * not following links here. */

	/* Populate the stat struct with info from the base file. */
	tmp_stream_name = smb_fname->stream_name;
	smb_fname->stream_name = NULL;
	result = SMB_VFS_NEXT_STAT(handle, smb_fname);
	smb_fname->stream_name = tmp_stream_name;

	if (result == -1) {
		return -1;
	}

	/* Derive the xattr name to lookup. */
	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	/* Augment the base file's stat information before returning. */
	if (fsp == NULL) {
		status = synthetic_pathref(talloc_tos(),
					   handle->conn->cwd_fsp,
					   smb_fname->base_name,
					   NULL,
					   NULL,
					   smb_fname->twrp,
					   smb_fname->flags,
					   &pathref);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(xattr_name);
			SET_STAT_INVALID(smb_fname->st);
			errno = ENOENT;
			return -1;
		}
		fsp = pathref->fsp;
	} else {
		fsp = fsp->base_fsp;
	}

	smb_fname->st.st_ex_size = get_stream_size_fsp(handle, fsp,
							xattr_name);
	if (smb_fname->st.st_ex_size == -1) {
		TALLOC_FREE(xattr_name);
		TALLOC_FREE(pathref);
		SET_STAT_INVALID(smb_fname->st);
		errno = ENOENT;
		return -1;
	}

	smb_fname->st.st_ex_ino = hash_inode(&smb_fname->st, xattr_name);
	smb_fname->st.st_ex_mode &= ~S_IFMT;
        smb_fname->st.st_ex_mode |= S_IFREG;
        smb_fname->st.st_ex_blocks =
	    smb_fname->st.st_ex_size / STAT_ST_BLOCKSIZE + 1;

	TALLOC_FREE(xattr_name);
	TALLOC_FREE(pathref);
	return 0;
}

static int streams_xattr_lstat(vfs_handle_struct *handle,
			       struct smb_filename *smb_fname)
{
	if (is_named_stream(smb_fname)) {
		/*
		 * There can never be EA's on a symlink.
		 * Windows will never see a symlink, and
		 * in SMB_FILENAME_POSIX_PATH mode we don't
		 * allow EA's on a symlink.
		 */
		SET_STAT_INVALID(smb_fname->st);
		errno = ENOENT;
		return -1;
	}

	return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
}

static int streams_xattr_fstatat(struct vfs_handle_struct *handle,
				 const struct files_struct *dirfsp,
				 const struct smb_filename *smb_fname,
				 SMB_STRUCT_STAT *sbuf,
				 int flags)
{
	char *xattr_name = NULL;
	struct smb_filename *pathref = NULL;
	struct files_struct *fsp = smb_fname->fsp;
	ssize_t size;
	NTSTATUS status;
	int ret = -1;

	DBG_DEBUG("called for [%s/%s]\n",
		  dirfsp->fsp_name->base_name,
		  smb_fname_str_dbg(smb_fname));

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_FSTATAT(
			handle, dirfsp, smb_fname, sbuf, flags);
	}

	SET_STAT_INVALID(*sbuf);

	/* Derive the xattr name to lookup. */
	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		ret = -1;
		goto done;
	}

	if (fsp == NULL) {
		status = synthetic_pathref(talloc_tos(),
					   dirfsp,
					   smb_fname->base_name,
					   NULL,
					   NULL,
					   smb_fname->twrp,
					   smb_fname->flags,
					   &pathref);
		if (!NT_STATUS_IS_OK(status)) {
			errno = ENOENT;
			ret = -1;
			goto done;
		}
		fsp = pathref->fsp;
	} else {
		fsp = fsp->base_fsp;
	}

	*sbuf = fsp->fsp_name->st;

	size = get_stream_size_fsp(handle, fsp, xattr_name);
	if (size == -1) {
		errno = ENOENT;
		ret = -1;
		goto done;
	}
	sbuf->st_ex_size = size;
	sbuf->st_ex_ino = hash_inode(sbuf, xattr_name);
	sbuf->st_ex_mode &= ~S_IFMT;
	sbuf->st_ex_mode |= S_IFREG;
	sbuf->st_ex_blocks = sbuf->st_ex_size / STAT_ST_BLOCKSIZE + 1;

done:
	{
		int err = errno;
		TALLOC_FREE(pathref);
		TALLOC_FREE(xattr_name);
		errno = err;
	}
	return ret;
}

static int streams_xattr_openat(struct vfs_handle_struct *handle,
				const struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				files_struct *fsp,
				const struct vfs_open_how *how)
{
	struct streams_xattr_config *config = NULL;
	struct stream_io *sio = NULL;
	char *xattr_name = NULL;
	int fakefd = -1;
	bool set_empty_xattr = false;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	DBG_DEBUG("called for %s with flags 0x%x\n",
		  smb_fname_str_dbg(smb_fname),
		  how->flags);

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname,
					   fsp,
					   how);
	}

	if ((how->resolve & ~VFS_OPEN_HOW_WITH_BACKUP_INTENT) != 0) {
		errno = ENOSYS;
		return -1;
	}

	SMB_ASSERT(fsp_is_alternate_stream(fsp));
	SMB_ASSERT(dirfsp == NULL);

	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		goto fail;
	}

	/* Only whether the stream exists matters here, not its value */
	if (get_xattr_len_fsp(fsp->base_fsp, xattr_name) == -1) {
		ret = errno;
		DBG_DEBUG("get_xattr_len_fsp returned %s\n", strerror(ret));

		if (ret != ENOATTR) {
			/*
			 * The base file is not there. This is an error even if
			 * we got O_CREAT, the higher levels should have created
			 * the base file for us.
			 */
			DBG_DEBUG("base file %s not around, "
				  "returning ENOENT\n",
				  smb_fname->base_name);
			errno = ENOENT;
			goto fail;
		}

		if (!(how->flags & O_CREAT)) {
			errno = ENOENT;
			goto fail;
		}

		set_empty_xattr = true;
	}

	if (how->flags & O_TRUNC) {
		set_empty_xattr = true;
	}

	if (set_empty_xattr && (config->xattr_compat_bytes == 0)) {
		ret = SMB_VFS_FSETXATTR(fsp->base_fsp,
					xattr_name,
					NULL, 0,
					how->flags & O_EXCL ? XATTR_CREATE : 0);
		if (ret != 0) {
			goto fail;
		}
	}
	else if (set_empty_xattr) {
		/*
		 * The attribute does not exist or needs to be truncated
		 */

		/*
		 * Darn, xattrs need at least 1 byte
		 */
		char null = '\0';

		DEBUG(10, ("creating or truncating attribute %s on file %s\n",
			   xattr_name, smb_fname->base_name));

		ret = SMB_VFS_FSETXATTR(fsp->base_fsp,
				       xattr_name,
				       &null, sizeof(null),
				       how->flags & O_EXCL ? XATTR_CREATE : 0);
		if (ret != 0) {
			goto fail;
		}
	}

	fakefd = vfs_fake_fd();

        sio = VFS_ADD_FSP_EXTENSION(handle, fsp, struct stream_io, NULL);
        if (sio == NULL) {
                errno = ENOMEM;
                goto fail;
        }

        sio->xattr_name = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
					xattr_name);
	if (sio->xattr_name == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	/*
	 * so->base needs to be a copy of fsp->fsp_name->base_name,
	 * making it identical to streams_xattr_recheck(). If the
	 * open is changing directories, fsp->fsp_name->base_name
	 * will be the full path from the share root, whilst
	 * smb_fname will be relative to the $cwd.
	 */
        sio->base = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
				  fsp->fsp_name->base_name);
	if (sio->base == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	sio->fsp_name_ptr = fsp->fsp_name;
	sio->handle = handle;
	sio->fsp = fsp;

	return fakefd;

 fail:
	if (fakefd >= 0) {
		vfs_fake_fd_close(fakefd);
		fakefd = -1;
	}

	return -1;
}

static int streams_xattr_close(vfs_handle_struct *handle,
			       files_struct *fsp)
{
	int ret;
	int fd;

	fd = fsp_get_pathref_fd(fsp);

	DBG_DEBUG("called [%s] fd [%d]\n",
		  smb_fname_str_dbg(fsp->fsp_name),
		  fd);

	if (!fsp_is_alternate_stream(fsp)) {
		return SMB_VFS_NEXT_CLOSE(handle, fsp);
	}

	ret = vfs_fake_fd_close(fd);
	fsp_set_fd(fsp, -1);

	return ret;
}

static int streams_xattr_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	NTSTATUS status;
	int ret = -1;
	char *xattr_name = NULL;
	struct smb_filename *pathref = NULL;
	struct files_struct *fsp = smb_fname->fsp;

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
	}

	/* A stream can never be rmdir'ed */
	SMB_ASSERT((flags & AT_REMOVEDIR) == 0);

	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		goto fail;
	}

	if (fsp == NULL) {
		status = synthetic_pathref(talloc_tos(),
					handle->conn->cwd_fsp,
					smb_fname->base_name,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags,
					&pathref);
		if (!NT_STATUS_IS_OK(status)) {
			errno = ENOENT;
			goto fail;
		}
		fsp = pathref->fsp;
	} else {
		SMB_ASSERT(fsp_is_alternate_stream(smb_fname->fsp));
		fsp = fsp->base_fsp;
	}

	ret = SMB_VFS_FREMOVEXATTR(fsp, xattr_name);

	if ((ret == -1) && (errno == ENOATTR)) {
		errno = ENOENT;
		goto fail;
	}

	ret = 0;

 fail:
	TALLOC_FREE(xattr_name);
	TALLOC_FREE(pathref);
	return ret;
}

/*
 * Rename the stream src_fsp is open on: write its value under the new name,
 * then remove the old one. smbd only gets here for a named stream renamed to
 * another named stream.
 */
static int streams_xattr_rename_stream(struct vfs_handle_struct *handle,
				       struct files_struct *src_fsp,
				       const char *dst_name,
				       bool replace_if_exists)
{
	struct files_struct *base_fsp = src_fsp->base_fsp;
	char *src_xattr_name = NULL;
	char *dst_xattr_name = NULL;
	struct ea_struct ea = { .flags = 0, };
	int ret;

	if (!fsp_is_alternate_stream(src_fsp)) {
		errno = ENOSYS;
		return -1;
	}

	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     src_fsp->fsp_name->stream_name,
				     &src_xattr_name);
	if (ret == 0) {
		ret = streams_xattr_get_name(handle,
					     talloc_tos(),
					     dst_name,
					     &dst_xattr_name);
	}
	if (ret != 0) {
		errno = ret;
		ret = -1;
		goto out;
	}

	/*
	 * Same stream, if only in case: nothing to do. Writing the new name
	 * and removing the old would lose the stream where the two names are
	 * one xattr, as in the xattr directory of a case-insensitive dataset.
	 */
	if (strcasecmp_m(src_xattr_name, dst_xattr_name) == 0) {
		ret = 0;
		goto out;
	}

	ret = get_xattr_value_fsp(talloc_tos(), base_fsp, src_xattr_name, &ea);
	if (ret != 0) {
		errno = (ret == ENOATTR) ? ENOENT : ret;
		ret = -1;
		goto out;
	}

	ret = SMB_VFS_FSETXATTR(base_fsp,
				dst_xattr_name,
				ea.value.data,
				ea.value.length,
				replace_if_exists ? 0 : XATTR_CREATE);
	if (ret != 0) {
		goto out;
	}

	ret = SMB_VFS_FREMOVEXATTR(base_fsp, src_xattr_name);
	if ((ret != 0) && (errno == ENOATTR)) {
		errno = ENOENT;
	}

out:
	{
		int err = errno;

		TALLOC_FREE(ea.value.data);
		TALLOC_FREE(src_xattr_name);
		TALLOC_FREE(dst_xattr_name);
		errno = err;
	}
	return ret;
}

/*
 * Whether xattr_name holds a stream. samba_private_attr_name() flags every
 * name under the default stream prefix as private, so it is only asked about
 * names outside that prefix (on a share with "streams_xattr:prefix = user.",
 * for example).
 */
static bool is_stream_xattr(const struct streams_xattr_config *config,
			    const char *xattr_name)
{
	if (strncmp(xattr_name, config->prefix, config->prefix_len) != 0) {
		return false;
	}

	if (strncasecmp_m(xattr_name, SAMBA_XATTR_DOSSTREAM_PREFIX,
			  strlen(SAMBA_XATTR_DOSSTREAM_PREFIX)) == 0) {
		return true;
	}

	return !samba_private_attr_name(xattr_name);
}

/*
 * Stream name for a stream xattr, the reverse of streams_xattr_get_name():
 * ":" plus the name past the prefix, plus ":$DATA" when the type isn't
 * stored. Built by copying, without a format string.
 */
static char *stream_name_from_xattr(TALLOC_CTX *mem_ctx,
				    const struct streams_xattr_config *config,
				    const char *xattr_name)
{
	static const char stype[] = ":$DATA";
	const char *name = xattr_name + config->prefix_len;
	size_t namelen = strlen(name);
	size_t typelen = config->store_stream_type ? 0 : sizeof(stype) - 1;
	char *sname = NULL;

	sname = talloc_array(mem_ctx, char, 1 + namelen + typelen + 1);
	if (sname == NULL) {
		return NULL;
	}

	sname[0] = ':';
	memcpy(sname + 1, name, namelen);
	memcpy(sname + 1 + namelen, stype, typelen);
	sname[1 + namelen + typelen] = '\0';

	return sname;
}

/*
 * List fsp's xattr names into buf, which covers nearly every file. If it is
 * too small, list them into a talloc buffer of the kernel's list limit
 * instead, returned in *plist for the caller to free: asking for the size
 * first would cost a second full walk on ZFS. A symlink has no xattrs.
 */
static NTSTATUS list_xattrs_fsp(struct files_struct *fsp,
				char *buf,
				size_t bufsize,
				char **plist,
				size_t *plistlen)
{
	NTSTATUS status = NT_STATUS_OK;
	char *list = buf;
	ssize_t len;

	*plist = buf;
	*plistlen = 0;

	if (refuse_symlink_fsp(fsp)) {
		return NT_STATUS_OK;
	}

	len = SMB_VFS_FLISTXATTR(fsp, list, bufsize);
	if ((len == -1) && (errno == ERANGE)) {
		list = talloc_array(talloc_tos(), char, 65536);
		if (list == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		len = SMB_VFS_FLISTXATTR(fsp, list, talloc_get_size(list));
	}

	if (len == -1) {
		status = map_nt_error_from_unix(errno);
	} else if ((len > 0) && (list[len - 1] != '\0')) {
		status = NT_STATUS_INTERNAL_ERROR;
	}
	if (!NT_STATUS_IS_OK(status)) {
		if (list != buf) {
			TALLOC_FREE(list);
		}
		return status;
	}

	*plist = list;
	*plistlen = len;
	return NT_STATUS_OK;
}

static unsigned int count_stream_xattrs(
	const struct streams_xattr_config *config,
	const char *list,
	size_t listlen)
{
	const char *name = NULL;
	unsigned int num = 0;

	for (name = list; name < list + listlen; name += strlen(name) + 1) {
		if (is_stream_xattr(config, name)) {
			num += 1;
		}
	}

	return num;
}

/*
 * Append a stream for each stream xattr in list to *pstreams, with one
 * allocation for all of them. Slots of xattrs skipped below stay unused;
 * everything downstream goes by *pnum_streams.
 */
static NTSTATUS add_xattr_streams(vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  TALLOC_CTX *mem_ctx,
				  const char *list,
				  size_t listlen,
				  unsigned int *pnum_streams,
				  struct stream_struct **pstreams)
{
	struct streams_xattr_config *config = NULL;
	struct stream_struct *streams = NULL;
	unsigned int num_streams = *pnum_streams;
	unsigned int num_xattrs;
	const char *name = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return NT_STATUS_UNSUCCESSFUL);

	num_xattrs = count_stream_xattrs(config, list, listlen);
	if (num_xattrs == 0) {
		return NT_STATUS_OK;
	}
	if (num_streams + num_xattrs < num_streams) {
		/* Integer wrap. */
		return NT_STATUS_INVALID_PARAMETER;
	}

	streams = talloc_realloc(mem_ctx, *pstreams, struct stream_struct,
				 num_streams + num_xattrs);
	if (streams == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*pstreams = streams;

	for (name = list; name < list + listlen; name += strlen(name) + 1) {
		struct stream_struct *s = NULL;
		ssize_t size;

		if (!is_stream_xattr(config, name)) {
			continue;
		}

		size = get_stream_size_fsp(handle, fsp, name);
		if (size == -1) {
			/* Removed since the listxattr, or unreadable */
			DBG_DEBUG("Skipping %s on %s: %s\n",
				  name, fsp_str_dbg(fsp), strerror(errno));
			continue;
		}

		s = &streams[num_streams];
		s->name = stream_name_from_xattr(streams, config, name);
		if (s->name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		s->size = size;
		s->alloc_size = smb_roundup(handle->conn, size);
		num_streams += 1;
	}

	*pnum_streams = num_streams;
	return NT_STATUS_OK;
}

static NTSTATUS streams_xattr_fstreaminfo(vfs_handle_struct *handle,
					 struct files_struct *fsp,
					 TALLOC_CTX *mem_ctx,
					 unsigned int *pnum_streams,
					 struct stream_struct **pstreams)
{
	char smallbuf[1024];
	char *list = NULL;
	size_t listlen = 0;
	NTSTATUS status;

	status = list_xattrs_fsp(fsp, smallbuf, sizeof(smallbuf),
				 &list, &listlen);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = add_xattr_streams(handle, fsp, mem_ctx, list, listlen,
				   pnum_streams, pstreams);
	if (list != smallbuf) {
		TALLOC_FREE(list);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return SMB_VFS_NEXT_FSTREAMINFO(handle,
			fsp,
			mem_ctx,
			pnum_streams,
			pstreams);
}

static uint32_t streams_xattr_fs_capabilities(struct vfs_handle_struct *handle,
			enum timestamp_set_resolution *p_ts_res)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res) | FILE_NAMED_STREAMS;
}

static int streams_xattr_connect(vfs_handle_struct *handle,
				 const char *service, const char *user)
{
	struct streams_xattr_config *config;
	const char *default_prefix = SAMBA_XATTR_DOSSTREAM_PREFIX;
	const char *prefix;
	int rc;
	bool xattr_compat;

	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (rc != 0) {
		return rc;
	}

	handle->conn->internal_tcon_flags |= TCON_FLAG_STREAMS_XATTR;

	config = talloc_zero(handle->conn, struct streams_xattr_config);
	if (config == NULL) {
		DEBUG(1, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	prefix = lp_parm_const_string(SNUM(handle->conn),
				      "streams_xattr", "prefix",
				      default_prefix);
	config->prefix = talloc_strdup(config, prefix);
	if (config->prefix == NULL) {
		DEBUG(1, ("talloc_strdup() failed\n"));
		errno = ENOMEM;
		return -1;
	}
	config->prefix_len = strlen(config->prefix);
	DEBUG(10, ("streams_xattr using stream prefix: %s\n", config->prefix));

	config->store_stream_type = lp_parm_bool(SNUM(handle->conn),
						 "streams_xattr",
						 "store_stream_type",
						 true);

	xattr_compat = lp_parm_bool(SNUM(handle->conn),
				    "streams_xattr",
				    "xattr_compat",
				    false);

        config->xattr_compat_bytes = xattr_compat ? 0 : 1;

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct stream_xattr_config,
				return -1);

	return 0;
}

static ssize_t streams_xattr_pwrite(vfs_handle_struct *handle,
				    files_struct *fsp, const void *data,
				    size_t n, off_t offset)
{
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	struct ea_struct ea;
	int ret;
	struct streams_xattr_config *config = NULL;

	DBG_DEBUG("offset=%jd, size=%zu\n", (intmax_t)offset, n);

	if (sio == NULL) {
		return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	if ((offset + n) >= lp_smbd_max_xattr_size(SNUM(handle->conn))) {
		/*
		 * Requested write is beyond what can be read based on
		 * samba configuration.
		 * ReFS returns STATUS_FILESYSTEM_LIMITATION, which causes
		 * entire file to be skipped by File Explorer. VFAT returns
		 * NT_STATUS_OBJECT_NAME_COLLISION causes user to be prompted
		 * to skip writing metadata, but copy data.
		 */
		DBG_ERR("Write to xattr [%s] on file [%s] exceeds maximum "
			"supported extended attribute size. "
			"Depending on filesystem type and operating system "
			"(OS) specifics, this value may be increased using "
			"the value of the parameter: "
			"smbd max xattr size = <bytes>. Consult OS and "
			"filesystem manpages prior to increasing this limit.\n",
			sio->xattr_name, sio->base);
		errno = EOVERFLOW;
		return -1;
	}

	ret = get_xattr_value_fsp(talloc_tos(),
				  fsp->base_fsp,
				  sio->xattr_name,
				  &ea);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	if (ea.value.length < (size_t)config->xattr_compat_bytes) {
		/* No trailing byte: not written by this module */
		TALLOC_FREE(ea.value.data);
		errno = EINVAL;
		return -1;
	}

        if ((offset + n) > ea.value.length - config->xattr_compat_bytes) {
		uint8_t *tmp;
		size_t new_sz = offset + n + 1;

		tmp = talloc_realloc(talloc_tos(), ea.value.data, uint8_t,
					   new_sz + config->xattr_compat_bytes);

		if (tmp == NULL) {
			TALLOC_FREE(ea.value.data);
                        errno = ENOMEM;
                        return -1;
                }

		memset(tmp + ea.value.length, 0, new_sz - ea.value.length);
		ea.value.data = tmp;
		ea.value.length = offset + n + config->xattr_compat_bytes;
		if (config->xattr_compat_bytes) {
			ea.value.data[offset+n] = 0;
		}
        }

        memcpy(ea.value.data + offset, data, n);

	ret = SMB_VFS_FSETXATTR(fsp->base_fsp,
				sio->xattr_name,
				ea.value.data,
				ea.value.length,
				0);

	if ((ret == -1) && (errno == EACCES)) {
		bool ok;
		ok = can_write_ea(fsp->base_fsp);
		if (ok) {
			become_root();
			ret = SMB_VFS_FSETXATTR(fsp->base_fsp,
						sio->xattr_name,
						ea.value.data,
						ea.value.length,
						0);
			unbecome_root();
		}
	}
	TALLOC_FREE(ea.value.data);

	if (ret == -1) {
		return -1;
	}

	return n;
}

static ssize_t streams_xattr_pread(vfs_handle_struct *handle,
				   files_struct *fsp, void *data,
				   size_t n, off_t offset)
{
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	struct ea_struct ea;
	int ret;
	size_t length, overlap;
	struct smb_filename *smb_fname_base = NULL;
	struct streams_xattr_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	DBG_DEBUG("offset=%jd, size=%zu\n", (intmax_t)offset, n);

	if (sio == NULL) {
		return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	ret = get_xattr_value_fsp(talloc_tos(),
				  fsp->base_fsp,
				  sio->xattr_name,
				  &ea);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	if (ea.value.length < (size_t)config->xattr_compat_bytes) {
		/* No trailing byte: not written by this module */
		TALLOC_FREE(ea.value.data);
		errno = EINVAL;
		return -1;
	}

	length = ea.value.length - config->xattr_compat_bytes;

	DBG_DEBUG("get_xattr_value_fsp returned %zu bytes\n", length);

        /* Attempt to read past EOF. */
        if (length <= offset) {
                return 0;
        }

        overlap = (offset + n) > length ? (length - offset) : n;
        memcpy(data, ea.value.data + offset, overlap);

	TALLOC_FREE(ea.value.data);
        return overlap;
}

struct streams_xattr_pread_state {
	ssize_t nread;
	struct vfs_aio_state vfs_aio_state;
};

static void streams_xattr_pread_done(struct tevent_req *subreq);

static struct tevent_req *streams_xattr_pread_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	void *data,
	size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct streams_xattr_pread_state *state = NULL;
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct streams_xattr_pread_state);
	if (req == NULL) {
		return NULL;
	}

	if (sio == NULL) {
		subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp,
						 data, n, offset);
		if (tevent_req_nomem(req, subreq)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, streams_xattr_pread_done, req);
		return req;
	}

	state->nread = SMB_VFS_PREAD(fsp, data, n, offset);
	if (state->nread != n) {
		if (state->nread != -1) {
			errno = EIO;
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void streams_xattr_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct streams_xattr_pread_state *state = tevent_req_data(
		req, struct streams_xattr_pread_state);

	state->nread = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (tevent_req_error(req, state->vfs_aio_state.error)) {
		return;
	}
	tevent_req_done(req);
}

static ssize_t streams_xattr_pread_recv(struct tevent_req *req,
					struct vfs_aio_state *vfs_aio_state)
{
	struct streams_xattr_pread_state *state = tevent_req_data(
		req, struct streams_xattr_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->nread;
}

struct streams_xattr_pwrite_state {
	ssize_t nwritten;
	struct vfs_aio_state vfs_aio_state;
};

static void streams_xattr_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *streams_xattr_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	const void *data,
	size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct streams_xattr_pwrite_state *state = NULL;
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct streams_xattr_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	if (sio == NULL) {
		subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp,
						  data, n, offset);
		if (tevent_req_nomem(req, subreq)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, streams_xattr_pwrite_done, req);
		return req;
	}

	state->nwritten = SMB_VFS_PWRITE(fsp, data, n, offset);
	if (state->nwritten != n) {
		if (state->nwritten != -1) {
			errno = EIO;
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void streams_xattr_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct streams_xattr_pwrite_state *state = tevent_req_data(
		req, struct streams_xattr_pwrite_state);

	state->nwritten = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (tevent_req_error(req, state->vfs_aio_state.error)) {
		return;
	}
	tevent_req_done(req);
}

static ssize_t streams_xattr_pwrite_recv(struct tevent_req *req,
					 struct vfs_aio_state *vfs_aio_state)
{
	struct streams_xattr_pwrite_state *state = tevent_req_data(
		req, struct streams_xattr_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->nwritten;
}

static int streams_xattr_ftruncate(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					off_t offset)
{
	int ret;
	uint8_t *tmp;
	struct ea_struct ea;
	struct streams_xattr_config *config = NULL;
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	DBG_DEBUG("called for file %s offset %ju\n",
		  fsp_str_dbg(fsp),
		  (intmax_t)offset);

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	ret = get_xattr_value_fsp(talloc_tos(),
				  fsp->base_fsp,
				  sio->xattr_name,
				  &ea);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	tmp = talloc_realloc(talloc_tos(), ea.value.data, uint8_t,
				   offset + 1);

	if (tmp == NULL) {
		TALLOC_FREE(ea.value.data);
		errno = ENOMEM;
		return -1;
	}

	/* Did we expand ? */
	if (ea.value.length < offset + config->xattr_compat_bytes) {
		memset(&tmp[ea.value.length], '\0',
			offset + config->xattr_compat_bytes - ea.value.length);
	}

	ea.value.data = tmp;
	ea.value.length = offset + config->xattr_compat_bytes;
	if (config->xattr_compat_bytes) {
		ea.value.data[offset] = 0;
	}

	ret = SMB_VFS_FSETXATTR(fsp->base_fsp,
				sio->xattr_name,
				ea.value.data,
				ea.value.length,
				0);

	if ((ret == -1) && (errno == EACCES)) {
		bool ok;
		ok = can_write_ea(fsp->base_fsp);
		if (ok) {
			become_root();
			ret = SMB_VFS_FSETXATTR(fsp->base_fsp,
						sio->xattr_name,
						ea.value.data,
						ea.value.length,
						0);
			unbecome_root();
		}
	}

	TALLOC_FREE(ea.value.data);

	if (ret == -1) {
		return -1;
	}

	return 0;
}

static int streams_xattr_fallocate(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32_t mode,
					off_t offset,
					off_t len)
{
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	DBG_DEBUG("called for file %s offset %jd len=%jd\n",
		  fsp_str_dbg(fsp),
		  (intmax_t)offset,
		  (intmax_t)len);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	/* Let the pwrite code path handle it. */
	errno = ENOSYS;
	return -1;
}

static int streams_xattr_fchown(vfs_handle_struct *handle, files_struct *fsp,
				uid_t uid, gid_t gid)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
	}

	return 0;
}

static int streams_xattr_fchmod(vfs_handle_struct *handle,
				files_struct *fsp,
				mode_t mode)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}

	return 0;
}

static ssize_t streams_xattr_fgetxattr(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       const char *name,
				       void *value,
				       size_t size)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
	}

	errno = ENOTSUP;
	return -1;
}

static ssize_t streams_xattr_flistxattr(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					char *list,
					size_t size)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);
	}

	errno = ENOTSUP;
	return -1;
}

static int streams_xattr_fremovexattr(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      const char *name)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
	}

	errno = ENOTSUP;
	return -1;
}

static int streams_xattr_fsetxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   const char *name,
				   const void *value,
				   size_t size,
				   int flags)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value,
					      size, flags);
	}

	errno = ENOTSUP;
	return -1;
}

struct streams_xattr_fsync_state {
	int ret;
	struct vfs_aio_state vfs_aio_state;
};

static void streams_xattr_fsync_done(struct tevent_req *subreq);

static struct tevent_req *streams_xattr_fsync_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct streams_xattr_fsync_state *state = NULL;
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct streams_xattr_fsync_state);
	if (req == NULL) {
		return NULL;
	}

	if (sio == NULL) {
		subreq = SMB_VFS_NEXT_FSYNC_SEND(state, ev, handle, fsp);
		if (tevent_req_nomem(req, subreq)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, streams_xattr_fsync_done, req);
		return req;
	}

	/*
	 * There's no pathname based sync variant and we don't have access to
	 * the basefile handle, so we can't do anything here.
	 */

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void streams_xattr_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct streams_xattr_fsync_state *state = tevent_req_data(
		req, struct streams_xattr_fsync_state);

	state->ret = SMB_VFS_FSYNC_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	if (state->ret != 0) {
		tevent_req_error(req, errno);
		return;
	}

	tevent_req_done(req);
}

static int streams_xattr_fsync_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct streams_xattr_fsync_state *state = tevent_req_data(
		req, struct streams_xattr_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static bool streams_xattr_lock(vfs_handle_struct *handle,
			       files_struct *fsp,
			       int op,
			       off_t offset,
			       off_t count,
			       int type)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);
	}

	return true;
}

static bool streams_xattr_getlock(vfs_handle_struct *handle,
				  files_struct *fsp,
				  off_t *poffset,
				  off_t *pcount,
				  int *ptype,
				  pid_t *ppid)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset,
					    pcount, ptype, ppid);
	}

	errno = ENOTSUP;
	return false;
}

static int streams_xattr_filesystem_sharemode(vfs_handle_struct *handle,
					      files_struct *fsp,
					      uint32_t share_access,
					      uint32_t access_mask)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FILESYSTEM_SHAREMODE(handle,
							 fsp,
							 share_access,
							 access_mask);
	}

	return 0;
}

static int streams_xattr_linux_setlease(vfs_handle_struct *handle,
					files_struct *fsp,
					int leasetype)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);
	}

	return 0;
}

static bool streams_xattr_strict_lock_check(struct vfs_handle_struct *handle,
					    files_struct *fsp,
					    struct lock_struct *plock)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);
	}

	return true;
}

static int streams_xattr_fcntl(vfs_handle_struct *handle,
			       files_struct *fsp,
			       int cmd,
			       va_list cmd_arg)
{
	va_list dup_cmd_arg;
	void *arg;
	int ret;

	if (fsp_is_alternate_stream(fsp)) {
		switch (cmd) {
		case F_GETFL:
		case F_SETFL:
			break;
		default:
			DBG_ERR("Unsupported fcntl() cmd [%d] on [%s]\n",
				cmd, fsp_str_dbg(fsp));
			errno = EINVAL;
			return -1;
		}
	}

	va_copy(dup_cmd_arg, cmd_arg);
	arg = va_arg(dup_cmd_arg, void *);

	ret = SMB_VFS_NEXT_FCNTL(handle, fsp, cmd, arg);

	va_end(dup_cmd_arg);

	return ret;
}

static struct vfs_fn_pointers vfs_truenas_streams_xattr_fns = {
	.fs_capabilities_fn = streams_xattr_fs_capabilities,
	.connect_fn = streams_xattr_connect,
	.openat_fn = streams_xattr_openat,
	.close_fn = streams_xattr_close,
	.stat_fn = streams_xattr_stat,
	.fstat_fn = streams_xattr_fstat,
	.lstat_fn = streams_xattr_lstat,
	.fstatat_fn = streams_xattr_fstatat,
	.pread_fn = streams_xattr_pread,
	.pwrite_fn = streams_xattr_pwrite,
	.pread_send_fn = streams_xattr_pread_send,
	.pread_recv_fn = streams_xattr_pread_recv,
	.pwrite_send_fn = streams_xattr_pwrite_send,
	.pwrite_recv_fn = streams_xattr_pwrite_recv,
	.unlinkat_fn = streams_xattr_unlinkat,
	.rename_stream_fn = streams_xattr_rename_stream,
	.ftruncate_fn = streams_xattr_ftruncate,
	.fallocate_fn = streams_xattr_fallocate,
	.fstreaminfo_fn = streams_xattr_fstreaminfo,

	.fsync_send_fn = streams_xattr_fsync_send,
	.fsync_recv_fn = streams_xattr_fsync_recv,

	.lock_fn = streams_xattr_lock,
	.getlock_fn = streams_xattr_getlock,
	.filesystem_sharemode_fn = streams_xattr_filesystem_sharemode,
	.linux_setlease_fn = streams_xattr_linux_setlease,
	.strict_lock_check_fn = streams_xattr_strict_lock_check,
	.fcntl_fn = streams_xattr_fcntl,

	.fchown_fn = streams_xattr_fchown,
	.fchmod_fn = streams_xattr_fchmod,

	.fgetxattr_fn = streams_xattr_fgetxattr,
	.flistxattr_fn = streams_xattr_flistxattr,
	.fremovexattr_fn = streams_xattr_fremovexattr,
	.fsetxattr_fn = streams_xattr_fsetxattr,
};

static_decl_vfs;
NTSTATUS vfs_truenas_streams_xattr_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "truenas_streams_xattr",
				&vfs_truenas_streams_xattr_fns);
}
