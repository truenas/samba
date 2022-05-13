/*
 *  Unix SMB/CIFS implementation.
 *  A dumping ground for FreeBSD-specific VFS functions. For testing case
 *  of reducing number enabled VFS modules to bare minimum by creating
 *  single large VFS module.
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
#include "libcli/security/security.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "nfs4_acls.h"
#include "zfsacl.h"
#if 0
#include <sys/acl.h>
#endif

#if HAVE_LIBZFS
#include "modules/smb_libzfs.h"
#endif

static int vfs_ixnas_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_ixnas_debug_level

struct ixnas_config_data {
	struct smbacl4_vfs_params nfs4_params;
	struct smblibzfshandle *libzp;
	struct dataset_list *dsl;
	bool posix_rename;
	bool dosattrib_xattr;
	bool zfs_acl_enabled;
	bool zfs_acl_chmod_enabled;
	struct zfs_dataset_prop *props;
};

static const struct {
	uint32_t dosmode;
	uint32_t flag;
} dosmode2flag[] = {
	{ FILE_ATTRIBUTE_READONLY, UF_READONLY },
	{ FILE_ATTRIBUTE_ARCHIVE, UF_ARCHIVE },
	{ FILE_ATTRIBUTE_SYSTEM, UF_SYSTEM },
	{ FILE_ATTRIBUTE_HIDDEN, UF_HIDDEN },
	{ FILE_ATTRIBUTE_SPARSE, UF_SPARSE },
	{ FILE_ATTRIBUTE_OFFLINE, UF_OFFLINE },
	{ FILE_ATTRIBUTE_REPARSE_POINT, UF_REPARSE },
};

static NTSTATUS ixnas_fget_dos_attributes(struct vfs_handle_struct *handle,
                                            struct files_struct *fsp,
                                            uint32_t *dosmode)
{
	struct ixnas_config_data *config = NULL;
	int i;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (config->dosattrib_xattr) {
		return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
							fsp,
							dosmode);
	}

	for (i = 0; i < ARRAY_SIZE(dosmode2flag); i++) {
		if (fsp->fsp_name->st.st_ex_flags & dosmode2flag[i].flag) {
			*dosmode |= dosmode2flag[i].dosmode;
		}
	}

	if (S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
	/*
	 * Windows default behavior appears to be that the archive bit
	 * on a directory is only explicitly set by clients. FreeBSD
	 * sets this bit when the directory's contents are modified.
	 * This is a temporary hack until we can make OS behavior
	 * configurable
	 */
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
	uint32_t flags = 0;
	int ret, i;
	bool set_dosmode_ok = false;

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

	ret = SMB_VFS_FCHFLAGS(fsp, flags);
	if ((ret == -1) && (errno != EPERM)) {
		DBG_WARNING("Setting dosmode failed for %s: %s\n",
			    fsp_str_dbg(fsp), strerror(errno));

		return map_nt_error_from_unix(errno);
	}

	if (ret == 0) {
		return NT_STATUS_OK;
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
	ret = SMB_VFS_FCHFLAGS(fsp, flags);
	unbecome_root();

	if (ret == -1) {
		DBG_WARNING("Setting dosmode failed for %s: %s\n",
			    fsp_str_dbg(fsp), strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

static zfsacl_t fsp_get_zfsacl(files_struct *fsp)
{
	int fd;
	const char *proc_fd_path = NULL;
	char buf[PATH_MAX];

	if (!fsp->fsp_flags.is_pathref) {
		return zfsacl_get_fd(fsp_get_io_fd(fsp), ZFSACL_BRAND_NFSV4);
	}

	SMB_ASSERT(fsp->fsp_flags.have_proc_fds);

	fd = fsp_get_pathref_fd(fsp);
	proc_fd_path = sys_proc_fd_path(fd, buf, sizeof(buf));
	if (proc_fd_path == NULL) {
		return NULL;
	}

	return zfsacl_get_file(proc_fd_path, ZFSACL_BRAND_NFSV4);
}

static bool fsp_set_zfsacl(files_struct *fsp, zfsacl_t zfsacl)
{
	int fd;
	const char *proc_fd_path = NULL;
	char buf[PATH_MAX];

	if (!fsp->fsp_flags.is_pathref) {
		return zfsacl_set_fd(fsp_get_io_fd(fsp), zfsacl);
	}

	SMB_ASSERT(fsp->fsp_flags.have_proc_fds);

	fd = fsp_get_pathref_fd(fsp);
	proc_fd_path = sys_proc_fd_path(fd, buf, sizeof(buf));
	if (proc_fd_path == NULL) {
		errno = EBADF;
		return -1;
	}

	return zfsacl_set_file(proc_fd_path, zfsacl);
}

static int fsp_get_acl_brand(files_struct *fsp)
{
	long ret;
	int saved_errno;
	saved_errno = errno;

	ret = fpathconf(fsp_get_pathref_fd(fsp), _PC_ACL_NFS4);
	if (ret == -1) {
		if (saved_errno == errno) {
			return ACL_BRAND_POSIX;
		}
		DBG_ERR("%s: fpathconf failed: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		errno = saved_errno;
		return ACL_BRAND_UNKNOWN;
	}

	return ACL_BRAND_NFS4;
}

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
	    ((aceprop->flags & (SMB_ACE4_DIRECTORY_INHERIT_ACE | SMB_ACE4_FILE_INHERIT_ACE)) == 0) &&
	    (aceprop->aceMask & SMB_ACE4_WRITE_DATA)) {
		aceprop->aceMask |= (SMB_ACE4_WRITE_NAMED_ATTRS | \
				     SMB_ACE4_WRITE_ATTRIBUTES | \
				     SMB_ACE4_DELETE);
	}
	return true;
}

static bool smbace2zfsentry(zfsacl_t zfsacl, SMB_ACE4PROP_T *aceprop)
{
	bool ok;
	zfsacl_entry_t new_entry = NULL;
	zfsace_who_t who_type;
	zfsace_id_t who_id = ZFSACL_UNDEFINED_ID;
	zfsace_entry_type_t type;

	ok = zfsacl_create_aclentry(zfsacl, ZFSACL_APPEND_ENTRY, &new_entry);
	if (!ok) {
		DBG_ERR("Failed to create new ACL entry: %s\n", strerror(errno));
		return false;
	}

	if (aceprop->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) {
		type = ACL_ENTRY_TYPE_ALLOW;
	} else if (aceprop->aceType == SMB_ACE4_ACCESS_DENIED_ACE_TYPE) {
		type = ACL_ENTRY_TYPE_DENY;
	} else {
		smb_panic("Unsupported ace type.");
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

	ok = zfsace_set_who(new_entry, who_type, who_id);
	if (!ok) {
		DBG_ERR("zfsace_set_who() failed: %s\n", strerror(errno));
		return false;
	}

	ok = zfsace_set_entry_type(new_entry, type);
	if (!ok) {
		DBG_ERR("zfsace_set_type() failed: %s\n", strerror(errno));
		return false;
	}

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
		return NT_STATUS_NO_MEMORY;
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
			return NT_STATUS_NO_MEMORY;
		}

		ok = zfsentry2smbace(ae, &aceprop);
		if (!ok) {
			TALLOC_FREE(pacl);
			return NT_STATUS_NO_MEMORY;
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
		if ((errno == EINVAL) &&
		    (fsp_get_acl_brand(fsp) == ACL_BRAND_POSIX)) {
			status = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);
			if (NT_STATUS_IS_OK(status)) {
				(*ppdesc)->type |= SEC_DESC_DACL_PROTECTED;
			}
			return status;
		} else {
			return map_nt_error_from_unix(errno);
		}
	}

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

	status = smb_fget_nt_acl_nfs4(fsp, NULL, security_info, mem_ctx,
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
		if (!ok) {
			DBG_ERR("zfsacl_set_flagset() failed: %s\n", strerror(errno));
			return false;
		}
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

	if (fsp_set_zfsacl(fsp, zfsacl)) {
		DBG_ERR("%s: failed to set acl: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		zfsacl_free(&zfsacl);
		return false;
	}

	zfsacl_free(&zfsacl);
	return true;
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
 entry. We don't rely on FreeBSD kernel behavior in this case,
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

/*
 * Windows clients return NT_STATUS_OBJECT_NAME_COLLISION in case of
 * rename in case of rename in case insensitive dataset. MacOS does
 * attempts the rename. rename() in FreeBSD in this returns success, but
 * does not actually rename the file. Add new logic to rename(). If
 * a case_insensitive string comparison of the filenames returns 0, then
 * perform two renames so that the returned filename matches client
 * expectations. First rename appends a unique id generated from
 * inode and generation number to the file's name. This makes the
 * rename deterministic, while minimizing risk of name collisions.
 */
static uint64_t ixnas_fs_file_id(struct vfs_handle_struct *handle,
				 const SMB_STRUCT_STAT *psbuf);

static int ixnas_renameat(vfs_handle_struct *handle,
			  files_struct *srcfsp,
			  const struct smb_filename *smb_fname_src,
			  files_struct *dstfsp,
			  const struct smb_filename *smb_fname_dst)
{
	int result = 1;
	struct ixnas_config_data *config = NULL;
	char *tmp_base_name = NULL;
	uint64_t srcid, dstid;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (config->props->casesens != SMBZFS_INSENSITIVE) {
		return SMB_VFS_NEXT_RENAMEAT(handle,
					     srcfsp,
					     smb_fname_src,
					     dstfsp,
					     smb_fname_dst);
	}

	srcid = ixnas_fs_file_id(handle, &srcfsp->fsp_name->st);
	dstid = ixnas_fs_file_id(handle, &dstfsp->fsp_name->st);

	if (srcid == dstid) {
		result = strcasecmp_m(smb_fname_src->base_name,
				      smb_fname_dst->base_name);
	}
	if (result != 0) {
		return SMB_VFS_NEXT_RENAMEAT(handle,
					     srcfsp,
					     smb_fname_src,
					     dstfsp,
					     smb_fname_dst);
	}

	dstid = ixnas_fs_file_id(handle, &smb_fname_src->st);
	tmp_base_name = talloc_asprintf(talloc_tos(), "%s_%lu",
					smb_fname_src->base_name, dstid);
	if (tmp_base_name == NULL) {
		errno = ENOMEM;
		return -1;
	}
	result = renameat(
		fsp_get_pathref_fd(srcfsp), smb_fname_src->base_name,
		fsp_get_pathref_fd(dstfsp), tmp_base_name
        );
	if (result != 0) {
		DBG_ERR("Failed to rename %s to intermediate name %s\n",
			smb_fname_src->base_name, tmp_base_name);
		TALLOC_FREE(tmp_base_name);
		return result;
	}
	result = renameat(
		fsp_get_pathref_fd(dstfsp), tmp_base_name,
		fsp_get_pathref_fd(srcfsp), smb_fname_dst->base_name
        );
	TALLOC_FREE(tmp_base_name);
	return result;
}

static struct file_id ixnas_file_id_create(struct vfs_handle_struct *handle,
					   const SMB_STRUCT_STAT *sbuf)
{
	struct file_id key = (struct file_id) {
		.devid = sbuf->st_ex_dev,
		.inode = sbuf->st_ex_ino,
		.extid = sbuf->st_ex_gen,
	};

	return key;
}

static inline uint64_t gen_id_comp(uint64_t p) {
	uint64_t out = (p & UINT32_MAX) ^ (p >> 32);
	return out;
};

static uint64_t ixnas_fs_file_id(struct vfs_handle_struct *handle,
				 const SMB_STRUCT_STAT *psbuf)
{
	uint64_t file_id;
	if (!(psbuf->st_ex_iflags & ST_EX_IFLAG_CALCULATED_FILE_ID)) {
		return psbuf->st_ex_file_id;
	}

	file_id = gen_id_comp(psbuf->st_ex_ino);
	file_id |= gen_id_comp(psbuf->st_ex_gen) << 32;
	return file_id;
}

static int fsp_set_times(files_struct *fsp, struct timespec *times, bool set_btime)
{
	int flag = set_btime ? AT_UTIMENSAT_BTIME : 0;
	if (fsp->fsp_flags.have_proc_fds) {
		int fd = fsp_get_pathref_fd(fsp);
		const char *p = NULL;
		char buf[PATH_MAX];

		p = sys_proc_fd_path(fd, buf, sizeof(buf));
		if (p != NULL) {
			return utimensat(AT_FDCWD, p, times, flag);
                }

		return -1;
	}

	/* fallback to path-based call */
	return utimensat(AT_FDCWD, fsp->fsp_name->base_name, times, flag);
}

static int ixnas_ntimes(vfs_handle_struct *handle,
			files_struct *fsp,
			struct smb_file_time *ft)
{
	int result = -1;
	struct ixnas_config_data *config = NULL;
	struct timespec ts[3], *times = NULL;

	if (is_named_stream(fsp->fsp_name)) {
		errno = ENOENT;
		return result;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (config->dosattrib_xattr) {
		return SMB_VFS_NEXT_FNTIMES(handle, fsp, ft);
	}

	if (ft != NULL) {
		bool set_btime = !is_omit_timespec(&ft->create_time);
		if (is_omit_timespec(&ft->atime)) {
			ft->atime= fsp->fsp_name->st.st_ex_atime;
		}
		if (is_omit_timespec(&ft->mtime)) {
			ft->mtime = fsp->fsp_name->st.st_ex_mtime;
		}
		/* mtime and atime are unchanged */
		if ((timespec_compare(&ft->atime,
				      &fsp->fsp_name->st.st_ex_atime) == 0) &&
		    (timespec_compare(&ft->mtime,
				      &fsp->fsp_name->st.st_ex_mtime) == 0) &&
		    (timespec_compare(&ft->create_time,
				      &fsp->fsp_name->st.st_ex_btime) == 0)) {
			return 0;
		}
		ts[0] = ft->atime;
		ts[1] = ft->mtime;
		ts[2] = ft->create_time;
		result = fsp_set_times(fsp, ts, set_btime);
	}

	if (result != 0) {
		DBG_ERR("utimensat failed: %s \n", strerror(errno));
	}
	return result;
}

static bool set_zfs_parameters(struct vfs_handle_struct *handle,
			       const char *service, const char *user,
			       struct ixnas_config_data *config)
{
	const char *base_quota_str = NULL;
	if (config->dsl == NULL) {
		config->props = talloc_zero(handle->conn, struct zfs_dataset_prop);
		if (config->props == NULL) {
			errno = ENOMEM;
			return false;
		}
		DBG_INFO("Share connectpath is not ZFS dataset. "
			 "Skipping configuration.\n");
		config->props->casesens = SMBZFS_SENSITIVE;
		return true;
	}
	config->props = config->dsl->root->properties;

	if (config->props->casesens == SMBZFS_INSENSITIVE) {
		DBG_INFO("ixnas: case insensitive dataset detected, "
			 "automatically adjusting case sensitivity settings.\n");
		lp_do_parameter(SNUM(handle->conn),
				"case sensitive", "yes");
		handle->conn->case_sensitive = True;
	}
	return true;
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
	if (pathconf(chkpath, _PC_ACL_NFS4) < 0) {
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


#if HAVE_LIBZFS
	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &config->libzp,
			    &config->dsl, handle->conn->tcon != NULL);

	if (ret != 0) {
		TALLOC_FREE(config);
		return ret;
	}

	ok = set_zfs_parameters(handle, service, user, config);
	if (!ok) {
		TALLOC_FREE(config);
		return -1;
	}
#endif

	/* OS-X Compatibility */
	config->posix_rename = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "posix_rename", false);

	/*
	 * Ensure other alternate methods of mapping dosmodes are disabled.
	 */
	config->dosattrib_xattr = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "dosattrib_xattr", false);

	if (!config->dosattrib_xattr) {
		if ((lp_map_readonly(SNUM(handle->conn))) == MAP_READONLY_YES) {
			DBG_INFO("ixnas:dosmode to file flag mapping enabled,"
				  "disabling 'map readonly'\n");
			lp_do_parameter(SNUM(handle->conn), "map readonly",
					"no");
		}

		if (lp_map_archive(SNUM(handle->conn))) {
			DBG_INFO("ixnas:dosmode to file flag mapping enabled,"
				  "disabling 'map archive'\n");
			lp_do_parameter(SNUM(handle->conn), "map archive",
					"no");
		}

		if (lp_store_dos_attributes(SNUM(handle->conn))){
			DBG_INFO("ixnas:dosmode to file flag mapping enabled,"
				  "disabling 'store dos attributes'\n");
			lp_do_parameter(SNUM(handle->conn), "store dos attributes",
					"no");
		}
		lp_do_parameter(SNUM(handle->conn), "kernel dosmodes", "yes");
	}

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
	.fntimes_fn = ixnas_ntimes,
	.renameat_fn = ixnas_renameat,
	.file_id_create_fn = ixnas_file_id_create,
	.fs_file_id_fn = ixnas_fs_file_id,
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
