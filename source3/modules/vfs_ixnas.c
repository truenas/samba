/*
 *  Unix SMB/CIFS implementation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "includes.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "passdb/lookup_sid.h"
#include "nfs4_acls.h"
#include "zfsacl.h"

static int vfs_ixnas_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_ixnas_debug_level

struct ixnas_config_data {
	struct smbacl4_vfs_params nfs4_params;
	bool posix_rename;
	bool dosattrib_xattr;
	bool zfs_acl_enabled;
	bool zfs_acl_chmod_enabled;
};

enum ixnas_dacl_type {
	IXNAS_NULL_DACL,
	IXNAS_EMPTY_DACL,
	IXNAS_NORMAL_DACL
};

#define	UF_READONLY		0x0000000100000000ull
#define	UF_HIDDEN		0x0000000200000000ull
#define	UF_SYSTEM		0x0000000400000000ull
#define	UF_ARCHIVE		0x0000000800000000ull
#define	UF_REPARSE		0x0000080000000000ull
#define	UF_OFFLINE		0x0000100000000000ull
#define	UF_SPARSE		0x0000200000000000ull

#define ACL4_XATTR "system.nfs4_acl_xdr"
#define ACL_XATTR "system.posix_acl_access"

#define ZFS_IOC_GETDOSFLAGS     _IOR(0x83, 1, uint64_t)
#define ZFS_IOC_SETDOSFLAGS     _IOW(0x83, 2, uint64_t)

static const struct {
	uint32_t dosmode;
	uint64_t flag;
} dosmode2flag[] = {
	{ FILE_ATTRIBUTE_READONLY, UF_READONLY },
	{ FILE_ATTRIBUTE_ARCHIVE, UF_ARCHIVE },
	{ FILE_ATTRIBUTE_SYSTEM, UF_SYSTEM },
	{ FILE_ATTRIBUTE_HIDDEN, UF_HIDDEN },
	{ FILE_ATTRIBUTE_SPARSE, UF_SPARSE },
	{ FILE_ATTRIBUTE_OFFLINE, UF_OFFLINE },
#ifdef DEVELOPER
	{ FILE_ATTRIBUTE_REPARSE_POINT, UF_REPARSE },
#endif
};

#define KERN_DOSMODES (UF_READONLY | UF_ARCHIVE | UF_SYSTEM | \
	UF_HIDDEN | UF_SPARSE | UF_OFFLINE | UF_REPARSE)

static void _dump_acl_info(zfsacl_t theacl, const char *fn)
{
	char *acltext = NULL;

	if (!CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		return;
	}

	acltext = zfsacl_to_text(theacl);
	if (acltext == NULL) {
		DBG_ERR("zfsacl_to_text() failed: %s\n", strerror(errno));
		return;
	}

	DBG_ERR("%s():\n%s\n", fn, acltext);
	free(acltext);
}
#define dump_acl_info(x) _dump_acl_info(x, __func__)

/*
 * This function converts a file opened via O_PATH to one opened under
 * different flags by using procfs.
 */
static int ixnas_pathref_reopen(const files_struct *fsp, int flags)
{
	int fd_out = -1;
	const char *p = NULL;
	struct sys_proc_fd_path_buf buf;

	p = sys_proc_fd_path(fsp_get_pathref_fd(fsp), &buf);
	if (p == NULL) {
		errno = EBADF;
		return fd_out;
	}
	if (S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		fd_out = open(p, O_DIRECTORY);
	} else {
		fd_out = open(p, flags);
	}
	return fd_out;
}

static bool ixnas_get_native_dosmode(struct files_struct *fsp, uint64_t *_dosmode)
{
	int err;
	if (!fsp->fsp_flags.is_pathref) {
		err = ioctl(fsp_get_io_fd(fsp), ZFS_IOC_GETDOSFLAGS, _dosmode);
	} else {
		int fd;

		fd = ixnas_pathref_reopen(fsp, O_RDONLY);
		if ((fd == -1) && (errno == EACCES)) {
			become_root();
			fd = ixnas_pathref_reopen(fsp, O_RDONLY);
			unbecome_root();
		}

		if (fd == -1) {
			DBG_WARNING("%s: open() failed: %s\n",
				    fsp_str_dbg(fsp), strerror(errno));
			return false;
		}

		err = ioctl(fd, ZFS_IOC_GETDOSFLAGS, _dosmode);
		close(fd);
	}
	if (err) {
		DBG_ERR("%s: ioctl() to get dos flags failed: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return false;
	}
	return true;
}

static bool ixnas_set_native_dosmode(struct files_struct *fsp, uint64_t dosmode)
{
	int err;
	if (!fsp->fsp_flags.is_pathref) {
		err = ioctl(fsp_get_io_fd(fsp), ZFS_IOC_SETDOSFLAGS, &dosmode);
	} else {
		int fd;
		fd = ixnas_pathref_reopen(fsp, O_RDWR);
		if (fd == -1) {
			DBG_WARNING("%s: open() failed: %s\n",
				    fsp_str_dbg(fsp), strerror(errno));
			return false;
		}
		err = ioctl(fd, ZFS_IOC_SETDOSFLAGS, &dosmode);
		close(fd);
	}

	if (err) {
		if ((errno != EACCES) && (errno != EPERM)) {
			DBG_WARNING("Setting dosmode failed for %s: %s\n",
				    fsp_str_dbg(fsp), strerror(errno));
		} else {
			DBG_DEBUG("Setting dosmode failed for %s: %s\n",
				  fsp_str_dbg(fsp), strerror(errno));
		}
		return false;
	}
	return true;
}

static NTSTATUS ixnas_fget_dos_attributes(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
				          uint32_t *dosmode)
{
	struct ixnas_config_data *config = NULL;
	int i;
	bool ok;
	uint64_t kern_dosmode = 0;
	uint32_t xattr_dosmode = 0;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	status = SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
						  fsp,
						  &xattr_dosmode);

	if (config->dosattrib_xattr) {
		return status;
	}

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			// .zfs and .zfs/snapshot do not support xattrs
			return NT_STATUS_OK;
		} else if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			return status;
		}
	}

	if (is_named_stream(fsp->fsp_name)) {
		// Streams don't have separate dos attribute metadata
		ok = ixnas_get_native_dosmode(fsp->base_fsp, &kern_dosmode);
	} else {
		ok = ixnas_get_native_dosmode(fsp, &kern_dosmode);
	}

	if (!ok) {
		return map_nt_error_from_unix(errno);
	}

	*dosmode = xattr_dosmode;

	for (i = 0; i < ARRAY_SIZE(dosmode2flag); i++) {
		if (kern_dosmode & dosmode2flag[i].flag) {
			*dosmode |= dosmode2flag[i].dosmode;
		}
	}

	/*
	 * Windows default behavior appears to be that the archive bit
	 * on a directory is only explicitly set by clients. ZFS
	 * sets this bit when the directory's contents are modified.
	 *
	 * This means that we _must_ rely on the xattr-encoded dosmode
	 * to provide guidance as to whether it is set for the file.
	 */
	if (S_ISDIR(fsp->fsp_name->st.st_ex_mode) &&
	    ((xattr_dosmode & FILE_ATTRIBUTE_ARCHIVE) == 0)) {
		*dosmode &= ~FILE_ATTRIBUTE_ARCHIVE;
	}

	return NT_STATUS_OK;
}

static NTSTATUS ixnas_fset_dos_attributes(struct vfs_handle_struct *handle,
                                            struct files_struct *fsp,
                                            uint32_t dosmode)
{
	NTSTATUS status;
	struct ixnas_config_data *config = NULL;
	uint64_t flags = 0;
	int ret, i;
	bool set_dosmode_ok = false;
	bool ok;

	if (is_named_stream(fsp->fsp_name)) {
		// Streams don't have separate dos attribute metadata
		return NT_STATUS_OK;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (config->dosattrib_xattr) {
		return SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
							fsp,
							dosmode);
	}

	DBG_INFO("ixnas:set_dos_attributes: set attribute 0x%x, on file %s\n",
		 dosmode, fsp_str_dbg(fsp));
	/*
	* Optimization. This is most likely set by file owner. First try without
	* performing additional permissions checks and using become_root().
	*/
	if (!CAN_WRITE(handle->conn)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	for (i = 0; i < ARRAY_SIZE(dosmode2flag); i++) {
		if (dosmode & dosmode2flag[i].dosmode) {
			flags |= dosmode2flag[i].flag;
		}
	}

	ok = ixnas_set_native_dosmode(fsp, flags);
	if (ok) {
		goto out;
	} else if ((errno != EACCES) && (errno != EPERM)) {
		return map_nt_error_from_unix(errno);
	}

	status = smbd_check_access_rights_fsp(handle->conn->cwd_fsp, fsp,
					      false, FILE_WRITE_ATTRIBUTES);
	if (NT_STATUS_IS_OK(status)) {
		set_dosmode_ok = true;
	}

	if (!set_dosmode_ok && lp_dos_filemode(SNUM(handle->conn))) {
		set_dosmode_ok = can_write_to_fsp(fsp);
	}

	if (!set_dosmode_ok){
		return NT_STATUS_ACCESS_DENIED;
	}

	/* becomeroot() because non-owners need to write flags */

	become_root();
	ok = ixnas_set_native_dosmode(fsp, flags);
	unbecome_root();

	if (!ok) {
		DBG_WARNING("Setting dosmode failed for %s: %s\n",
			    fsp_str_dbg(fsp), strerror(errno));
		return map_nt_error_from_unix(errno);
	}

out:
	return SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
						fsp,
						dosmode);
}

static zfsacl_t fsp_get_zfsacl(files_struct *fsp)
{
	int fd;
	const char *proc_fd_path = NULL;
	struct sys_proc_fd_path_buf buf;

	if (!fsp->fsp_flags.is_pathref) {
		return zfsacl_get_fd(fsp_get_io_fd(fsp), ZFSACL_BRAND_NFSV4);
	}

	SMB_ASSERT(fsp->fsp_flags.have_proc_fds);

	fd = fsp_get_pathref_fd(fsp);
	proc_fd_path = sys_proc_fd_path(fd, &buf);
	if (proc_fd_path == NULL) {
		return NULL;
	}

	return zfsacl_get_file(proc_fd_path, ZFSACL_BRAND_NFSV4);
}

static bool fsp_set_zfsacl(files_struct *fsp, zfsacl_t zfsacl)
{
	int fd;
	const char *proc_fd_path = NULL;
	struct sys_proc_fd_path_buf buf;

	if (!fsp->fsp_flags.is_pathref) {
		return zfsacl_set_fd(fsp_get_io_fd(fsp), zfsacl);
	}

	SMB_ASSERT(fsp->fsp_flags.have_proc_fds);

	fd = fsp_get_pathref_fd(fsp);
	proc_fd_path = sys_proc_fd_path(fd, &buf);
	if (proc_fd_path == NULL) {
		errno = EBADF;
		return -1;
	}

	return zfsacl_set_file(proc_fd_path, zfsacl);
}

/*
 * fsp_get_aclbrand() and path_get_aclbrand() both get the ACL brand on the
 * underlying filesystem. In almost all cases we rely on the ACL brand we
 * detected on the initial SMB tree connect, which is preferable to detecting
 * on a per-file basis. Unfortunately, certain types of users disregard UI
 * warnings and alerts and nest datasets with different ACL properties (or
 * mount random filesystems via the unix shell) and so we need to handle the
 * unexpected if initial attempt to read the file's ACL fails.
 */
static int fsp_get_acl_brand(files_struct *fsp)
{
	ssize_t rv;
	rv = SMB_VFS_FGETXATTR(fsp, ACL_XATTR, NULL, 0);
	if (rv == -1) {
		if (errno == ENODATA) {
			return TRUENAS_ACL_BRAND_POSIX;
		} else if (errno != EOPNOTSUPP) {
			DBG_ERR("%s: fgetxattr() for %s failed: %s\n",
				fsp_str_dbg(fsp), ACL_XATTR, strerror(errno));
			return TRUENAS_ACL_BRAND_UNKNOWN;
		}
	}

	rv = SMB_VFS_FGETXATTR(fsp, ACL4_XATTR, NULL, 0);
	if (rv == -1) {
		if (errno == ENODATA) {
			/* probably need to add disabled */
			return TRUENAS_ACL_BRAND_UNKNOWN;
		} else if (errno == EOPNOTSUPP) {
			/* Neither NFSv4 nor POSIX acls are supported */
			return TRUENAS_ACL_BRAND_NONE;
		}
		DBG_ERR("%s: fgetxattr() for %s failed: %s\n",
			fsp_str_dbg(fsp), ACL4_XATTR, strerror(errno));
		return TRUENAS_ACL_BRAND_UNKNOWN;
	}

	return TRUENAS_ACL_BRAND_NFS4;
}

static int path_get_aclbrand(const char *path)
{
	ssize_t rv;
	rv = getxattr(path, ACL_XATTR, NULL, 0);
	if (rv == -1) {
		if (errno == ENODATA) {
			return TRUENAS_ACL_BRAND_POSIX;
		} else if (errno != EOPNOTSUPP) {
			DBG_ERR("%s: getxattr() for %s failed: %s\n",
				path, ACL_XATTR, strerror(errno));
			return TRUENAS_ACL_BRAND_UNKNOWN;
		}
	}

	rv = getxattr(path, ACL4_XATTR, NULL, 0);
	if (rv == -1) {
		if (errno == ENODATA) {
			/* probably need to add disabled */
			return TRUENAS_ACL_BRAND_UNKNOWN;
		}
		DBG_ERR("%s: getxattr() for %s failed: %s\n",
			path, ACL4_XATTR, strerror(errno));
		return TRUENAS_ACL_BRAND_UNKNOWN;
	}

	return TRUENAS_ACL_BRAND_NFS4;
}

/* Convert the native ZFS ACE format to the generic Samba NFSv4 format */
static bool zfsentry2smbace(zfsacl_entry_t ae, SMB_ACE4PROP_T *aceprop)
{
	int i;
	zfsace_permset_t perms = 0;
	zfsace_flagset_t flags = 0;
	zfsace_entry_type_t entry_type = 0;
	zfsace_id_t who_id = ZFSACL_UNDEFINED_ID;
	zfsace_who_t who_type = ZFSACL_UNDEFINED_TAG;
	bool ok;

	ok = zfsace_get_permset(ae, &perms);
	if (!ok) {
		DBG_ERR("zfsace_get_permset() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_get_flagset(ae, &flags);
	if (!ok) {
		DBG_ERR("zfsace_get_flagset() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_get_who(ae, &who_type, &who_id);
	if (!ok) {
		DBG_ERR("zfsace_get_who() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_get_entry_type(ae, &entry_type);
	if (!ok) {
		DBG_ERR("zfsace_get_entry_type() failed: %s\n", strerror(errno));
		return false;
	}

	aceprop->aceMask = perms;
	aceprop->aceFlags = flags;
	aceprop->aceType = entry_type;

	switch(who_type) {
	case ZFSACL_USER_OBJ:
		aceprop->flags = SMB_ACE4_ID_SPECIAL;
		aceprop->who.special_id = SMB_ACE4_WHO_OWNER;
		break;
	case ZFSACL_GROUP_OBJ:
		aceprop->flags = SMB_ACE4_ID_SPECIAL;
		aceprop->who.special_id = SMB_ACE4_WHO_GROUP;
		break;
	case ZFSACL_EVERYONE:
		aceprop->flags = SMB_ACE4_ID_SPECIAL;
		aceprop->who.special_id = SMB_ACE4_WHO_EVERYONE;
		break;
	case ZFSACL_GROUP:
		aceprop->aceFlags |= SMB_ACE4_IDENTIFIER_GROUP;
	case ZFSACL_USER:
		aceprop->who.id = who_id;
		aceprop->flags = 0;
		break;
	default:
		smb_panic("Unsupported ace tag");
	}

	if ((aceprop->flags & SMB_ACE4_ID_SPECIAL) &&
	    (aceprop->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) &&
	    ((aceprop->aceFlags & (SMB_ACE4_DIRECTORY_INHERIT_ACE | SMB_ACE4_FILE_INHERIT_ACE)) == 0) &&
	    (aceprop->aceMask & SMB_ACE4_WRITE_DATA)) {
		aceprop->aceMask |= (SMB_ACE4_WRITE_NAMED_ATTRS | \
				     SMB_ACE4_WRITE_ATTRIBUTES | \
				     SMB_ACE4_DELETE);
	}

	if ((aceprop->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) &&
	    (aceprop->aceMask != 0)) {
		aceprop->aceMask |= SMB_ACE4_SYNCHRONIZE;
	}

	return true;
}

/* convert Samba's generic NFSv4 ACE format to the native ZFS format */
static bool smbace2zfsentry(zfsacl_t zfsacl, SMB_ACE4PROP_T *aceprop)
{
	bool ok;
	zfsacl_entry_t new_entry = NULL;
	zfsace_who_t who_type;
	zfsace_id_t who_id = ZFSACL_UNDEFINED_ID;
	zfsace_entry_type_t entry_type;

	ok = zfsacl_create_aclentry(zfsacl, ZFSACL_APPEND_ENTRY, &new_entry);
	if (!ok) {
		DBG_ERR("Failed to create new ACL entry: %s\n", strerror(errno));
		return false;
	}

	if (aceprop->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) {
		entry_type = ZFSACL_ENTRY_TYPE_ALLOW;
	} else if (aceprop->aceType == SMB_ACE4_ACCESS_DENIED_ACE_TYPE) {
		entry_type = ZFSACL_ENTRY_TYPE_DENY;
	} else {
		// Some clients may request to set ACCESS_ALLOWED_OBJECT_ACE and
		// ACCESS_DENIED_OBJECT_ACE. Reject entire ACL and present error
		// to client.
		DBG_ERR("Unsupported ACE type %d, rejecting ACL\n", aceprop->aceType);
		errno = EINVAL;
		return false;
	}

	if (aceprop->flags & SMB_ACE4_ID_SPECIAL) {
		switch(aceprop->who.special_id) {
		case SMB_ACE4_WHO_EVERYONE:
			who_type = ZFSACL_EVERYONE;
			break;
		case SMB_ACE4_WHO_OWNER:
			who_type = ZFSACL_USER_OBJ;
			break;
		case SMB_ACE4_WHO_GROUP:
			who_type = ZFSACL_GROUP_OBJ;
			break;
		default:
			smb_panic("Unsupported special id.");
		}
	} else {
		who_type = aceprop->aceFlags & SMB_ACE4_IDENTIFIER_GROUP ?
		     ZFSACL_GROUP : ZFSACL_USER;
		who_id = aceprop->who.id;
	}

	ok = zfsace_set_permset(new_entry, (zfsace_permset_t)aceprop->aceMask);
	if (!ok) {
		DBG_ERR("zfsace_set_permset() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_set_flagset(new_entry, (zfsace_flagset_t)aceprop->aceFlags);
	if (!ok) {
		DBG_ERR("zfsace_set_flagset() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_set_who(new_entry, who_type, who_id);
	if (!ok) {
		DBG_ERR("zfsace_set_who() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_set_entry_type(new_entry, entry_type);
	if (!ok) {
		DBG_ERR("zfsace_set_type() failed: %s\n", strerror(errno));
		return false;
	}

	return true;
}

/*
 * Determine the DACL type (for generating an NT security descriptor) from
 * the native ZFS ACL format. If the ZFS ACL encodes a NULL DACL then
 * dtype_out will be set to IXNAS_NULL_DACL, if it encodes an empty dacl
 * then dtype_out will be set to IXNAS_EMPTY_DACL, otherwise it will
 * be set to IXNAS_NORMAL_DACL.
 *
 * @param[in]   zfacl Native ZFS ACL
 * @param[out]  dtype_out DACL type (on success)
 * @return      boolean - true on success
 *
 * NOTE: this may fail if we get a malformed ACL from ZFS.
 */
static bool ixnas_zfsacl_get_dacl_type(zfsacl_t zfsacl,
				       enum ixnas_dacl_type *dtype_out)
{
	bool ok;
	uint cnt;
	enum ixnas_dacl_type dtype = IXNAS_NORMAL_DACL;
	zfsacl_entry_t ae = NULL;
	zfsace_permset_t perms = 0;
	zfsace_flagset_t flags = 0;
	zfsace_entry_type_t entry_type = 0;
	zfsace_id_t who_id = ZFSACL_UNDEFINED_ID;
	zfsace_who_t who_type = ZFSACL_UNDEFINED_TAG;

	ok = zfsacl_get_acecnt(zfsacl, &cnt);
	if (!ok) {
		DBG_ERR("zfsacl_get_acecnt() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsacl_get_aclentry(zfsacl, 0, &ae);
	if (!ok) {
		DBG_ERR("zfsacl_get_aclentry() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_get_permset(ae, &perms);
	if (!ok) {
		DBG_ERR("zfsace_get_permset() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_get_flagset(ae, &flags);
	if (!ok) {
		DBG_ERR("zfsace_get_flagset() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_get_who(ae, &who_type, &who_id);
	if (!ok) {
		DBG_ERR("zfsace_get_who() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_get_entry_type(ae, &entry_type);
	if (!ok) {
		DBG_ERR("zfsace_get_entry_type() failed: %s\n", strerror(errno));
		return false;
	}

	// our special DACL types have precisely one entry;
	if ((cnt == 1) &&
	    (entry_type == ZFSACL_ENTRY_TYPE_ALLOW) &&
	    (who_type == ZFSACL_EVERYONE) &&
	    (who_id == ZFSACL_UNDEFINED_ID) &&
	    (flags == 0)) {
		if (perms == ZFSACE_FULL_SET) {
			dtype = IXNAS_NULL_DACL;
		} else if (perms == 0) {
			dtype = IXNAS_EMPTY_DACL;
		}
	}

	*dtype_out = dtype;
	return true;
}

static NTSTATUS ixnas_get_nt_acl_nfs4_common(struct connection_struct *conn,
					     TALLOC_CTX *mem_ctx,
					     files_struct *fsp,
					     zfsacl_t zfsacl,
					     struct SMB4ACL_T **ppacl,
					     struct ixnas_config_data *config)
{
	uint cnt, i;
	struct SMB4ACL_T *pacl = NULL;
	bool inherited_is_present = false;
	bool ok;

	mem_ctx = talloc_tos();

	/* create SMB4ACL data */
	pacl = smb_create_smb4acl(mem_ctx);
	if (pacl == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = zfsacl_get_acecnt(zfsacl, &cnt);
	if (!ok) {
		DBG_ERR("zfsacl_get_acecnt() failed: %s\n", strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	for (i=0; i < cnt; i++) {
		SMB_ACE4PROP_T aceprop;
		ZERO_STRUCT(aceprop);
		zfsacl_entry_t ae = NULL;
		bool ok;

		ok = zfsacl_get_aclentry(zfsacl, i, &ae);
		if (!ok) {
			DBG_ERR("zfsacl_get_aclentry() failed: %s\n", strerror(errno));
			TALLOC_FREE(pacl);
			return map_nt_error_from_unix(errno);
		}

		ok = zfsentry2smbace(ae, &aceprop);
		if (!ok) {
			TALLOC_FREE(pacl);
			return map_nt_error_from_unix(errno);
		}

		if ((aceprop.aceMask == 0) &&
		    (aceprop.flags == SMB_ACE4_ID_SPECIAL) &&
		    (aceprop.who.special_id == SMB_ACE4_WHO_EVERYONE)) {
			continue;
		}

		if (aceprop.aceFlags & SMB_ACE4_INHERITED_ACE) {
			inherited_is_present = true;
		}

		if (smb_add_ace4(pacl, &aceprop) == NULL) {
			TALLOC_FREE(pacl);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (!inherited_is_present) {
		DBG_DEBUG("Setting SEC_DESC_DACL_PROTECTED on [%s]\n",
			  fsp_str_dbg(fsp));

		smbacl4_set_controlflags(pacl,
					 SEC_DESC_DACL_PROTECTED |
					 SEC_DESC_SELF_RELATIVE);

	}

	*ppacl = pacl;
	return NT_STATUS_OK;
}

/* See include/os/linux/zfs/sys/zfs_ctldir.h */
#define ZFSCTL_INO_ROOT         0x0000FFFFFFFFFFFFULL
#define ZFSCTL_INO_SHARES       0x0000FFFFFFFFFFFEULL
#define ZFSCTL_INO_SNAPDIR      0x0000FFFFFFFFFFFDULL
#define ZFSCTL_INO_SNAPDIRS     0x0000FFFFFFFFFFFCULL

#define ASSERT_CTL_INO(x) do { \
	SMB_ASSERT( \
		(x == ZFSCTL_INO_ROOT) || \
		(x == ZFSCTL_INO_SNAPDIR) || \
		(x == ZFSCTL_INO_SNAPDIRS) \
	); \
} while (0)

static int mode_to_acl(zfsacl_t *new_acl, mode_t mode);

static zfsacl_t fsp_get_zfsacl_from_mode(struct files_struct *fsp)
{
	zfsacl_t zfsacl = NULL;
	struct stat st;
	int error;

	error = fstat(fsp_get_pathref_fd(fsp), &st);
	if (error) {
		return NULL;
	}

	if (st.st_ino == ZFSCTL_INO_SHARES) {
		// There is no legitimate reason to expose this dir to SMB clients
		errno = EACCES;
		return NULL;
	}

	if ((st.st_ino != ZFSCTL_INO_ROOT) && (st.st_ino != ZFSCTL_INO_SNAPDIR)) {
		SMB_ASSERT(S_ISDIR(st.st_mode));

		struct stat parent;
		error = fstatat(fsp_get_pathref_fd(fsp), "..", &parent, 0);
		if (error) {
			DBG_ERR("%s: failed to stat parent directory", fsp_str_dbg(fsp));
			errno = EACCES;
			return NULL;
		}

		ASSERT_CTL_INO(parent.st_ino);
	}

	zfsacl = zfsacl_init(ZFSACL_MAX_ENTRIES, ZFSACL_BRAND_NFSV4);
	if (zfsacl == NULL) {
		return NULL;
	}

	error = mode_to_acl(&zfsacl, st.st_mode & ~(S_IWUSR|S_IWGRP|S_IWOTH));
	if (error) {
		DBG_ERR("%s: failed to convert permissions to acl\n", fsp_str_dbg(fsp));
		zfsacl_free(&zfsacl);
		return NULL;
	}

	return zfsacl;
}

static NTSTATUS ixnas_generate_special_dacl_sd(struct vfs_handle_struct *handle,
					       struct files_struct *fsp,
					       uint32_t security_info,
					       TALLOC_CTX *mem_ctx,
					       enum ixnas_dacl_type dtype,
					       struct security_descriptor **ppdesc)
{
	NTSTATUS status;
	struct dom_sid sid_owner, sid_group;
	size_t sd_size = 0;
	struct security_ace *nt_ace_list = NULL;
	struct security_acl *psa = NULL;
	uint16_t controlflags = SEC_DESC_SELF_RELATIVE | SEC_DESC_DACL_PROTECTED | SEC_DESC_DACL_PRESENT;

	SMB_ASSERT((dtype == IXNAS_EMPTY_DACL) || (dtype == IXNAS_NULL_DACL));

	if (!VALID_STAT(fsp->fsp_name->st)) {
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	uid_to_sid(&sid_owner, fsp->fsp_name->st.st_ex_uid);
	gid_to_sid(&sid_group, fsp->fsp_name->st.st_ex_gid);

	if (dtype == IXNAS_EMPTY_DACL) {
		psa = make_sec_acl(mem_ctx, NT4_ACL_REVISION, 0, NULL);
		if (psa == NULL) {
			DBG_ERR("make_sec_acl failed\n");
			return NT_STATUS_NO_MEMORY;
		}
	}

	*ppdesc = make_sec_desc(
		mem_ctx, SD_REVISION, controlflags,
		(security_info & SECINFO_OWNER) ? &sid_owner : NULL,
		(security_info & SECINFO_GROUP) ? &sid_group : NULL,
		NULL, psa, &sd_size);

	TALLOC_FREE(psa);

	if (*ppdesc==NULL) {
		DBG_ERR("make_sec_desc failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("smb_get_nt_acl_nfs4_common successfully exited with "
		  "sd_size %d\n", (int)ndr_size_security_descriptor(*ppdesc, 0));

	return NT_STATUS_OK;
}

static NTSTATUS ixnas_fget_nt_acl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl = NULL;
	TALLOC_CTX *frame = NULL;
	struct files_struct *to_check = NULL;
	NTSTATUS status;
	zfsacl_t zfsacl;
	bool ok;
	enum ixnas_dacl_type dtype = IXNAS_NORMAL_DACL;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->zfs_acl_enabled) {
		return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);
	}

	to_check = fsp->base_fsp ? fsp->base_fsp : fsp;
	zfsacl = fsp_get_zfsacl(to_check);
	if (zfsacl == NULL) {
		if ((errno == EINVAL) || (errno == EOPNOTSUPP)) {
			switch (fsp_get_acl_brand(fsp)) {
			case TRUENAS_ACL_BRAND_POSIX:
			case TRUENAS_ACL_BRAND_UNKNOWN:
				status = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);
				if (NT_STATUS_IS_OK(status)) {
						(*ppdesc)->type |= SEC_DESC_DACL_PROTECTED;
				}
				return status;
			case TRUENAS_ACL_BRAND_NONE:
				zfsacl = fsp_get_zfsacl_from_mode(fsp);
				if (zfsacl == NULL) {
					return map_nt_error_from_unix(errno);
				}
				break;
			default:
				smb_panic("Unknown ACL brand");
			}
		} else {
			return map_nt_error_from_unix(errno);
		}
	}
	dump_acl_info(zfsacl);

	ok = ixnas_zfsacl_get_dacl_type(zfsacl, &dtype);
	if (!ok) {
		return map_nt_error_from_unix(errno);
	}
	switch (dtype) {
	case IXNAS_NULL_DACL:
	case IXNAS_EMPTY_DACL:
		return ixnas_generate_special_dacl_sd(handle,
						      fsp,
						      security_info,
						      mem_ctx,
						      dtype,
						      ppdesc);
	case IXNAS_NORMAL_DACL:
		break;
	default:
		smb_panic("Unexpected ixnas_dacl_type");
	};

	frame = talloc_stackframe();
	status = ixnas_get_nt_acl_nfs4_common(handle->conn,
					      frame,
					      fsp,
					      zfsacl,
					      &pacl,
					      config);
	zfsacl_free(&zfsacl);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, &config->nfs4_params, security_info, mem_ctx,
				      ppdesc, pacl);
	TALLOC_FREE(frame);
	return status;
}

static bool ixnas_add_hidden_entry(zfsacl_t zfsacl,
				   bool has_inheritable,
				   files_struct *fsp)
{
	bool ok;
	uint acecnt;
	zfsacl_entry_t hidden_entry = NULL;

	if (!has_inheritable) {
		ok = zfsacl_get_acecnt(zfsacl, &acecnt);
		if (!ok) {
			DBG_ERR("Failed to get ACE count: %s\n",
				strerror(errno));
			return false;
		}
		if (acecnt != 0) {
			/*
			 * We don't want locking entry. Otherwise
			 * no aces will be inherited.
			 */
			return true;
		}
	}

	ok = zfsacl_create_aclentry(zfsacl, ZFSACL_APPEND_ENTRY, &hidden_entry);
	if (!ok) {
		DBG_ERR("zfsacl_create_aclentry() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_set_permset(hidden_entry, 0);
	if (!ok) {
		DBG_ERR("zfsacl_set_permset() failed: %s\n", strerror(errno));
		return false;
	}
	ok = zfsace_set_who(hidden_entry, ZFSACL_EVERYONE, ZFSACL_UNDEFINED_ID);
	if (!ok) {
		DBG_ERR("zfsacl_set_who() failed: %s\n", strerror(errno));
		return false;
	}

	if (S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		ok = zfsace_set_flagset(hidden_entry,
					ZFSACE_FILE_INHERIT | ZFSACE_DIRECTORY_INHERIT);
	}
	else {
		ok = zfsace_set_flagset(hidden_entry, 0);
	}

	if (!ok) {
		DBG_ERR("zfsacl_set_flagset() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_set_entry_type(hidden_entry, ZFSACL_ENTRY_TYPE_ALLOW);
	if (!ok) {
		DBG_ERR("zfsace_set_entry_type() failed: %s\n", strerror(errno));
		return false;
	}

	return true;
}

static bool ixnas_process_smbacl(vfs_handle_struct *handle,
				 files_struct *fsp,
				 struct SMB4ACL_T *smbacl)
{
	zfsacl_t zfsacl;
	struct SMB4ACE_T *smbace = NULL;
	bool has_inheritable = false;
	bool ok;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return False);

	zfsacl = zfsacl_init(ZFSACL_MAX_ENTRIES, ZFSACL_BRAND_NFSV4);
	if (zfsacl == NULL) {
		DBG_ERR("%s: acl_init failed: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return false;
	}

	for (smbace=smb_first_ace4(smbacl);
	     smbace!=NULL;
	     smbace = smb_next_ace4(smbace)) {
		bool ok;
		SMB_ACE4PROP_T *aceprop = smb_get_ace4(smbace);

		ok = smbace2zfsentry(zfsacl, aceprop);
                if (!ok) {
			DBG_ERR("%s: failed to convert ACL entry\n",
				fsp_str_dbg(fsp));
			zfsacl_free(&zfsacl);
			return false;
		}

		if ((aceprop->aceFlags & ~(SMB_ACE4_IDENTIFIER_GROUP|SMB_ACE4_INHERITED_ACE)) != 0) {
			has_inheritable = true;
		}
	}

	if (!ixnas_add_hidden_entry(zfsacl, has_inheritable, fsp)) {
		DBG_ERR("%s: failed to add locking ACL entry\n", fsp_str_dbg(fsp));
		zfsacl_free(&zfsacl);
		return false;
	}

	dump_acl_info(zfsacl);
	if (!fsp_set_zfsacl(fsp, zfsacl)) {
		DBG_ERR("%s: failed to set acl: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		zfsacl_free(&zfsacl);
		return false;
	}

	zfsacl_free(&zfsacl);
	return true;
}

static NTSTATUS ixnas_fset_special_dacl(vfs_handle_struct *handle,
					files_struct *fsp,
					enum ixnas_dacl_type dtype)
{
	/*
	 * A null DACL grants full access to any user that requests it; normal
	 * security checking is not performed with respect to the object.
	 *
	 * Example use case:
	 * Adobe applications may use these for locking files.
	 *
	 * For our purposes we indicate this special ACL type with the following
	 * characteristics:
	 * 1. A single ACL entry granting everyone@ full control
	 * 2. No additional hidden locking ACE
	 * 3. No additional ACL control flags
	 *
	 * An empty DACL grants no access to the object it is assigned to.
	 * 1. A single ACL entry granting everyone@ no access at all
	 * 2. No additional hidden locking ACE
	 * 3. No additional ACL control flags
	 *
	 * Example use case:
	 * Adobe applications may use an empty DACL on some files while in
	 * protected mode to prevent anyone other than the file owner or users
	 * with elevated system privileges that allow ignoring DACL from
	 * accessing the files.
	 *
	 * SDDL sample: O:<sid>G:<sid>D:PAI
	 * c.f https://learn.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls
	 */

	zfsacl_t zfsacl;
	struct SMB4ACE_T *smbace = NULL;
	zfsacl_entry_t placeholder_entry = NULL;
	bool ok;
	zfsace_permset_t perms;

	switch (dtype) {
	case IXNAS_NULL_DACL:
		perms = ZFSACE_FULL_SET;
		break;
	case IXNAS_EMPTY_DACL:
		perms = 0;
		break;
	default:
		smb_panic("unexpected ixnas_dacl_type");
	};

	zfsacl = zfsacl_init(1, ZFSACL_BRAND_NFSV4);
	if (zfsacl == NULL) {
		DBG_ERR("%s: acl_init failed: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return NT_STATUS_ACCESS_DENIED;
	}

	ok = zfsacl_create_aclentry(zfsacl, ZFSACL_APPEND_ENTRY, &placeholder_entry);
	if (!ok) {
		DBG_ERR("zfsacl_create_aclentry() failed: %s\n", strerror(errno));
		zfsacl_free(&zfsacl);
		return NT_STATUS_ACCESS_DENIED;
	}

	ok = zfsace_set_permset(placeholder_entry, perms);
	if (!ok) {
		DBG_ERR("zfsacl_set_permset() failed: %s\n", strerror(errno));
		zfsacl_free(&zfsacl);
		return NT_STATUS_ACCESS_DENIED;
	}

	ok = zfsace_set_who(placeholder_entry, ZFSACL_EVERYONE, ZFSACL_UNDEFINED_ID);
	if (!ok) {
		DBG_ERR("zfsacl_set_who() failed: %s\n", strerror(errno));
		zfsacl_free(&zfsacl);
		return NT_STATUS_ACCESS_DENIED;
	}

	dump_acl_info(zfsacl);
	if (!fsp_set_zfsacl(fsp, zfsacl)) {
		DBG_ERR("%s: failed to set acl: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		zfsacl_free(&zfsacl);
		return map_nt_error_from_unix(errno);
	}

	zfsacl_free(&zfsacl);
	return NT_STATUS_OK;
}

static NTSTATUS ixnas_fset_nt_acl(vfs_handle_struct *handle,
				  files_struct *fsp,
				  uint32_t security_info_sent,
				  const struct security_descriptor *psd)
{
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if ((security_info_sent & SECINFO_DACL) &&
	    (psd->dacl == NULL)) {
		return ixnas_fset_special_dacl(handle, fsp, IXNAS_NULL_DACL);
	} else if ((security_info_sent & SECINFO_DACL) &&
		   ((psd->type & SEC_DESC_DACL_PRESENT) == 0)) {
		return ixnas_fset_special_dacl(handle, fsp, IXNAS_EMPTY_DACL);
	}

	return smb_set_nt_acl_nfs4(handle,
				   fsp,
				   &config->nfs4_params,
				   security_info_sent,
				   psd,
				   ixnas_process_smbacl);
}


/*
 * Functions below are related to posix1e ACLs. Logic copied from vfs_zfsacl.
 */
static SMB_ACL_T ixnas_fail__sys_acl_get_fd(vfs_handle_struct *handle,
					     files_struct *fsp,
					     SMB_ACL_TYPE_T type,
					     TALLOC_CTX *mem_ctx)
{
	return (SMB_ACL_T)NULL;
}

static int ixnas_fail__sys_acl_set_fd(vfs_handle_struct *handle,
				       files_struct *fsp,
				       SMB_ACL_TYPE_T type,
				       SMB_ACL_T theacl)
{
	return -1;
}

static int ixnas_fail__sys_acl_blob_get_fd(vfs_handle_struct *handle,
			files_struct *fsp,
			TALLOC_CTX *mem_ctx,
			char **blob_description,
			DATA_BLOB *blob)
{
	return -1;
}

/********************************************************************
 Convert chmod() requests into an appropriate non-inheriting ACL
 entry. We don't rely on ZFS behavior in this case,
 because it strips some bits that we actually care about
 (WRITE_ATTRIBUTES, DELETE, etc.). If DELETE is stripped, then
 users will no longer be able to rename files.
********************************************************************/
static int mode_to_acl(zfsacl_t *new_acl, mode_t mode)
{
	int res = 0;
	bool ok;
	mode_t shifted_mode, other_mode, deny_mode;
	zfsacl_entry_t o_allow_entry = NULL;
	zfsacl_entry_t g_allow_entry = NULL;
	zfsacl_entry_t e_allow_entry = NULL;
	zfsacl_entry_t o_deny_entry = NULL;
	zfsacl_entry_t g_deny_entry = NULL;
	zfsace_permset_t permset;
	/*
	 * convert posix mode bits to ACLs
	 */
	if (((mode & S_IRWXU) >> 6) < (mode & S_IRWXO)) {
		permset = 0;
		shifted_mode = (mode &= S_IRWXU) >> 6;
		other_mode &= S_IRWXO;
		deny_mode = (shifted_mode ^ other_mode) << 6;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &o_deny_entry);
		if (!ok) {
			return -1;
		}
		if (deny_mode & S_IRUSR) {
			permset = ZFSACE_READ_DATA;
		}
		if (deny_mode & S_IWUSR) {
			permset |= ZFSACE_WRITE_DATA;
		}
		if (deny_mode & S_IXUSR) {
			permset |= ZFSACE_EXECUTE;
		}
		if (!zfsace_set_permset(o_deny_entry, permset))
			return -1;

		if (!zfsace_set_flagset(o_deny_entry, 0))
			return -1;

		if (!zfsace_set_entry_type(o_deny_entry, ZFSACL_ENTRY_TYPE_DENY))
			return -1;

		if (!zfsace_set_who(o_deny_entry, ZFSACL_USER_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;
	}
	if (((mode & S_IRWXG) >> 3) < (mode & S_IRWXO)) {
		permset = 0;
		shifted_mode = (mode &= S_IRWXG) >> 3;
		other_mode &= S_IRWXG;
		deny_mode = (shifted_mode ^ other_mode) << 3;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &g_deny_entry);
		if (!ok) {
			return -1;
		}

		if (deny_mode & S_IRGRP) {
			permset = ZFSACE_READ_DATA;
		}
		if (deny_mode & S_IWGRP) {
			permset |= ZFSACE_WRITE_DATA;
		}
		if (deny_mode & S_IXGRP) {
			permset |= ZFSACE_EXECUTE;
		}

		if (!zfsace_set_permset(g_deny_entry, permset))
			return -1;

		if (!zfsace_set_flagset(g_deny_entry, 0))
			return -1;

		if (!zfsace_set_entry_type(g_deny_entry, ZFSACL_ENTRY_TYPE_DENY))
			return -1;

		if (!zfsace_set_who(o_deny_entry, ZFSACL_GROUP_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;

	}
	if (mode & S_IRWXU) {
		permset = 0;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &o_allow_entry);
		if (!ok) {
			return -1;
		}

		if (mode & S_IRUSR) {
			permset = ZFSACE_READ_SET;
		}
		if (mode & S_IWUSR) {
			permset |= ZFSACE_WRITE_SET;
			permset |= ZFSACE_DELETE;
		}
		if (mode & S_IXUSR) {
			permset |= ZFSACE_EXECUTE;
		}

		if (!zfsace_set_permset(o_allow_entry, permset))
			return -1;

		if (!zfsace_set_flagset(o_allow_entry, 0))
			return -1;

		if (!zfsace_set_entry_type(o_allow_entry, ZFSACL_ENTRY_TYPE_ALLOW))
			return -1;

		if (!zfsace_set_who(o_allow_entry, ZFSACL_USER_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;
	}
	if (mode & S_IRWXG) {
		permset = 0;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &g_allow_entry);
		if (!ok) {
			return -1;
		}

		if (mode & S_IRGRP) {
			permset = ZFSACE_READ_SET;
		}
		if (mode & S_IWGRP) {
			permset |= ZFSACE_WRITE_SET;
			permset |= ZFSACE_DELETE;
		}
		if (mode & S_IXGRP) {
			permset |= ZFSACE_EXECUTE;
		}

		if (!zfsace_set_permset(g_allow_entry, permset))
			return -1;

		if (!zfsace_set_flagset(g_allow_entry, 0))
			return -1;

		if (!zfsace_set_entry_type(g_allow_entry, ZFSACL_ENTRY_TYPE_ALLOW))
			return -1;

		if (!zfsace_set_who(g_allow_entry, ZFSACL_GROUP_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;
	}
	if (mode & S_IRWXO) {
		permset = 0;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &e_allow_entry);
		if (!ok) {
			return -1;
		}

		if (mode & S_IROTH) {
			permset = ZFSACE_READ_SET;
		}
		if (mode & S_IWOTH) {
			permset |= ZFSACE_WRITE_SET;
			permset |= ZFSACE_DELETE;
		}
		if (mode & S_IXOTH) {
			permset |= ZFSACE_EXECUTE;
		}

		if (!zfsace_set_permset(e_allow_entry, permset))
			return -1;

		if (!zfsace_set_flagset(e_allow_entry, 0))
			return -1;

		if (!zfsace_set_entry_type(e_allow_entry, ZFSACL_ENTRY_TYPE_ALLOW))
			return -1;

		if (!zfsace_set_who(e_allow_entry, ZFSACL_EVERYONE, ZFSACL_UNDEFINED_ID))
			return -1;
	}

	return 0;
}

static int recalculate_flagset(zfsace_flagset_t *flagset)
{
	/* Simply replace non-inheriting entries */
	if ((*flagset & (ZFSACE_DIRECTORY_INHERIT \
		        | ZFSACE_FILE_INHERIT)) == 0){
		return -1;
	}
	/*
	 * This edge case is not easily handled. It is
	 * unclear what user expectation should be. FreeBSD
	 * kernel changes to fdin, but this causes the ACL
	 * to inherit one deeper than it should. I think safe
	 * play here is to maintain the inheritance flags
	 * as-is and end up with wonky mode so as not to
	 * break expectations regarding inheritance.
	 */
	if (((*flagset & ZFSACE_INHERIT_ONLY) == 0) &&
	     (*flagset & ZFSACE_NO_PROPAGATE_INHERIT)) {
		return 0;
	}

	*flagset |= ZFSACE_INHERIT_ONLY;
	return 0;
}

static zfsacl_t calculate_chmod_acl(zfsacl_t source_acl,
				    mode_t mode)
{
	int err, i;
	bool ok;
	uint acecnt;
	zfsacl_t new_acl = NULL;

	/* create new ACL that we will return */
	new_acl = zfsacl_init(ZFSACL_MAX_ENTRIES, ZFSACL_BRAND_NFSV4);
	if (new_acl == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	/*
	 * start by putting in entries for new mode
	 * since these are non-inheriting entries Windows clients
	 * want them at the top of the ACL
	 */
	err = mode_to_acl(&new_acl, mode);
	if (err) {
		DBG_ERR("Failed to convert mode to ACL: %s\n", strerror(errno));
		goto failure;
	}

	ok = zfsacl_get_acecnt(source_acl, &acecnt);
	if (!ok) {
		DBG_ERR("zfsacl_get_acecnt() failed: %s\n", strerror(errno));
		goto failure;
	}
	/*
	 * Iterate through ACL, remove non-inheriting special entries.
	 * Append INHERIT_ONLY to inheritng special entries
	 */
	for (i = 0; i < acecnt; i++) {
		zfsacl_entry_t src_entry = NULL, dst_entry = NULL;
		zfsace_permset_t perms = 0;
		zfsace_flagset_t flags = 0;
		zfsace_entry_type_t type;
		zfsace_who_t who_type = ZFSACL_UNDEFINED_TAG;
		zfsace_id_t who_id = ZFSACL_UNDEFINED_ID;

		ok = zfsacl_get_aclentry(source_acl, i, &src_entry);
		if (!ok) {
			DBG_ERR("zfsacl_get_aclentry() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_get_permset(src_entry, &perms);
		if (!ok) {
			DBG_ERR("zfsace_get_permset() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_get_flagset(src_entry, &flags);
		if (!ok) {
			DBG_ERR("zfsace_get_permset() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_get_who(src_entry, &who_type, &who_id);
		if (!ok) {
			DBG_ERR("zfsace_get_who() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_get_entry_type(src_entry, &type);
		if (!ok) {
			DBG_ERR("zfsace_get_entry_type() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		switch(who_type) {
		case ZFSACL_USER_OBJ:
		case ZFSACL_GROUP_OBJ:
		case ZFSACL_EVERYONE:
			err = recalculate_flagset(&flags);
			if (err) {
				continue;
			}
			break;
		default:
			break;
		};

		ok = zfsacl_create_aclentry(new_acl, ZFSACL_APPEND_ENTRY, &dst_entry);
		if (!ok) {
			DBG_ERR("zfsacl_create_aclentry() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_set_permset(dst_entry, perms);
		if (!ok) {
			DBG_ERR("zfsace_set_permset() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_set_flagset(dst_entry, flags);
		if (!ok) {
			DBG_ERR("zfsace_set_flagset() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_set_entry_type(dst_entry, type);
		if (!ok) {
			DBG_ERR("zfsace_set_entry_type() failed: %s\n",
				strerror(errno));
			goto failure;
		}

		ok = zfsace_set_who(dst_entry, who_type, who_id);
		if (!ok) {
			DBG_ERR("zfsace_set_who() failed: %s\n",
				strerror(errno));
			goto failure;
		}
	}

	return new_acl;
failure:
	zfsacl_free(&new_acl);
	return NULL;
}

static int ixnas_fchmod(vfs_handle_struct *handle,
			files_struct *fsp, mode_t mode)
{
	zfsacl_t zacl, new_acl;
	bool trivial, ok;
	struct ixnas_config_data *config = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (!config->zfs_acl_chmod_enabled) {
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}
	zacl = fsp_get_zfsacl(fsp);
	if (zacl == NULL) {
		DBG_ERR("ixnas: acl_get_fd() failed for %s: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return -1;
	}
	dump_acl_info(zacl);
	ok = zfsacl_is_trivial(zacl, &trivial);
	if (!ok) {
		DBG_ERR("zfsacl_is_trivial() failed: %s\n", strerror(errno));
		goto failure;
	}
	/*
	 * A "trivial" ACL can be expressed as a POSIX mode without
	 * losing information. In this case, pass on to normal
	 * chmod() behavior because user is probably not concerned
	 * about ACLs.
	 */
	if (trivial) {
		DBG_INFO("Trivial ACL detected on file %s, "
			 "passing to next CHMOD function\n",
			 fsp_str_dbg(fsp));
		zfsacl_free(&zacl);
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}
	new_acl = calculate_chmod_acl(zacl, mode);
	if (new_acl == NULL) {
		DBG_ERR("Failed to generate new ACL for %s",
			fsp_str_dbg(fsp));
		goto failure;
	}
	dump_acl_info(new_acl);
	ok = fsp_set_zfsacl(fsp, new_acl);
	if (!ok) {
		DBG_ERR("Failed to set new ACL on %s: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
	}
	zfsacl_free(&zacl);
	zfsacl_free(&new_acl);
	return 0;
failure:
	zfsacl_free(&zacl);
	return -1;
}

static bool set_acl_parameters(struct vfs_handle_struct *handle,
			       struct ixnas_config_data *config)
{
	int ret;
	char *chkpath = NULL;
	acl_t zacl;
	int is_trivial = 0;

	config->zfs_acl_enabled = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfs_acl_enabled", true);

	ret = access(handle->conn->connectpath, F_OK);
	if (ret != 0 && errno == ENOENT) {
		bool ok;
		ok = parent_dirname(handle->conn, handle->conn->connectpath,
				     &chkpath, NULL);
		if (!ok) {
			DBG_ERR("Failed to get parent_dirname for [%s]: %s\n",
				handle->conn->connectpath, strerror(errno));
			return false;
		}
		DBG_INFO("Connectpath doesn't exist, checking ACL info for parent: %s\n",
			 chkpath);
	}
	else if (ret != 0) {
		return false;
	}
	else {
		chkpath = talloc_strdup(handle->conn, handle->conn->connectpath);
	}
	if (chkpath == NULL) {
		errno = ENOMEM;
		return false;
	}
	/*
	 * Disable the get/set NT ACL functions here if the path lacks NFSv4 ACL support.
	 * The user may have mounted a non-ZFS filesystem and shared it via Samba. Our
	 * middleware will probably not let the user get this far, but it's better to
	 * be somewhat safer.
	 */
	handle->conn->aclbrand = path_get_aclbrand(handle->conn->connectpath);
	if (handle->conn->aclbrand != TRUENAS_ACL_BRAND_NFS4) {
		DBG_ERR("Connectpath does not support NFSv4 ACLs. Disabling ZFS ACL handling.\n");
		config->zfs_acl_enabled = false;
	}
	TALLOC_FREE(chkpath);
	config->zfs_acl_chmod_enabled = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfs_acl_chmod_enabled", false);

	ret = smbacl4_get_vfs_params(handle->conn, &config->nfs4_params);
	if (ret < 0) {
		return false;
	}
	return true;
}

/********************************************************************
 Optimization. Load parameters on connect. This allows us to enable
 and disable portions of the large vfs module on demand.
********************************************************************/
static int ixnas_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	struct ixnas_config_data *config = NULL;
	int ret;
	const char *homedir_quota = NULL;
	bool ok;
	config = talloc_zero(handle->conn, struct ixnas_config_data);
	if (!config) {
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		TALLOC_FREE(config);
		return ret;
	}

	config->posix_rename = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "posix_rename", false);

	/*
	 * Ensure other alternate methods of mapping dosmodes are disabled.
	 */
	config->dosattrib_xattr = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "dosattrib_xattr", false);

	ok = set_acl_parameters(handle, config);
	if (!ok) {
		TALLOC_FREE(config);
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct ixnas_config_data,
				return -1);

	return 0;
}

static struct vfs_fn_pointers ixnas_fns = {
	.connect_fn = ixnas_connect,
	/* dosmode_enabled */
	.fget_dos_attributes_fn = ixnas_fget_dos_attributes,
	.fset_dos_attributes_fn = ixnas_fset_dos_attributes,
	/* zfs_acl_enabled = true */
	.fchmod_fn = ixnas_fchmod,
	.fget_nt_acl_fn = ixnas_fget_nt_acl,
	.fset_nt_acl_fn = ixnas_fset_nt_acl,
	.sys_acl_get_fd_fn = ixnas_fail__sys_acl_get_fd,
	.sys_acl_blob_get_fd_fn = ixnas_fail__sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = ixnas_fail__sys_acl_set_fd,
};

NTSTATUS vfs_ixnas_init(TALLOC_CTX *);
NTSTATUS vfs_ixnas_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "ixnas",
					&ixnas_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_ixnas_debug_level = debug_add_class("ixnas");
	if (vfs_ixnas_debug_level == -1) {
		vfs_ixnas_debug_level = DBGC_VFS;
		DBG_ERR("%s: Couldn't register custom debugging class!\n",
			"vfs_ixnas_init");
	} else {
		DBG_DEBUG("%s: Debug class number of '%s': %d\n",
		"vfs_ixnas_init","ixnas",vfs_ixnas_debug_level);
	}
	return ret;
}
