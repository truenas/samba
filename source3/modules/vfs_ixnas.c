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
#include <sys/acl.h>

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

/*
 * ACL_ENTRY_SUCCESSFUL_ACCESS and
 * ACL_ENTRY_FAILED_ACCESS are omitted because
 * they are not currently implemented in FreeBSD and Samba
 */
static const struct {
	acl_flag_t bsdflag;
	uint32_t nfs4flag;
} bsdflag2nfs4flag[] = {
	{ ACL_ENTRY_FILE_INHERIT, SMB_ACE4_FILE_INHERIT_ACE },
	{ ACL_ENTRY_DIRECTORY_INHERIT, SMB_ACE4_DIRECTORY_INHERIT_ACE },
	{ ACL_ENTRY_NO_PROPAGATE_INHERIT, SMB_ACE4_NO_PROPAGATE_INHERIT_ACE },
	{ ACL_ENTRY_INHERIT_ONLY, SMB_ACE4_INHERIT_ONLY_ACE },
	{ ACL_ENTRY_INHERITED, SMB_ACE4_INHERITED_ACE },
};

static const struct {
	acl_perm_t bsdperm;
	uint32_t nfs4perm;
} bsdperm2nfs4perm[] = {
	{ ACL_READ_DATA, SMB_ACE4_READ_DATA },
	{ ACL_WRITE_DATA, SMB_ACE4_WRITE_DATA },
	{ ACL_APPEND_DATA, SMB_ACE4_APPEND_DATA },
	{ ACL_READ_NAMED_ATTRS, SMB_ACE4_READ_NAMED_ATTRS },
	{ ACL_WRITE_NAMED_ATTRS, SMB_ACE4_WRITE_NAMED_ATTRS },
	{ ACL_EXECUTE, SMB_ACE4_EXECUTE },
	{ ACL_DELETE_CHILD, SMB_ACE4_DELETE_CHILD },
	{ ACL_READ_ATTRIBUTES, SMB_ACE4_READ_ATTRIBUTES },
	{ ACL_WRITE_ATTRIBUTES, SMB_ACE4_WRITE_ATTRIBUTES },
	{ ACL_DELETE, SMB_ACE4_DELETE },
	{ ACL_READ_ACL, SMB_ACE4_READ_ACL },
	{ ACL_WRITE_ACL, SMB_ACE4_WRITE_ACL },
	{ ACL_WRITE_OWNER, SMB_ACE4_WRITE_OWNER },
	{ ACL_SYNCHRONIZE, SMB_ACE4_SYNCHRONIZE },
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

	if (!CAN_WRITE(handle->conn)) {
		return NT_STATUS_ACCESS_DENIED;
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

static acl_t fsp_get_bsdacl(files_struct *fsp)
{
	int fd;
	const char *proc_fd_path = NULL;
	char buf[PATH_MAX];

	if (!fsp->fsp_flags.is_pathref) {
		return acl_get_fd_np(fsp_get_io_fd(fsp), ACL_TYPE_NFS4);
	}

	SMB_ASSERT(fsp->fsp_flags.have_proc_fds);

	fd = fsp_get_pathref_fd(fsp);
	proc_fd_path = sys_proc_fd_path(fd, buf, sizeof(buf));
	if (proc_fd_path == NULL) {
		return NULL;
	}

	return acl_get_file(proc_fd_path, ACL_TYPE_NFS4);
}

static int fsp_set_bsdacl(files_struct *fsp, acl_t bsdacl)
{
	int fd;
	const char *proc_fd_path = NULL;
	char buf[PATH_MAX];

	if (!fsp->fsp_flags.is_pathref) {
		return acl_set_fd_np(fsp_get_io_fd(fsp), bsdacl, ACL_TYPE_NFS4);
	}

	SMB_ASSERT(fsp->fsp_flags.have_proc_fds);

	fd = fsp_get_pathref_fd(fsp);
	proc_fd_path = sys_proc_fd_path(fd, buf, sizeof(buf));
	if (proc_fd_path == NULL) {
		errno = EBADF;
		return -1;
	}

	return acl_set_file(proc_fd_path, ACL_TYPE_NFS4, bsdacl);
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

static void bsdentry2smbace(acl_entry_t ae, SMB_ACE4PROP_T *aceprop)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(bsdperm2nfs4perm); i++) {
		if (ae->ae_perm & bsdperm2nfs4perm[i].bsdperm) {
			aceprop->aceMask |= bsdperm2nfs4perm[i].nfs4perm;
		}
	}

	for (i = 0; i < ARRAY_SIZE(bsdflag2nfs4flag); i++) {
		if (ae->ae_flags & bsdflag2nfs4flag[i].bsdflag) {
			aceprop->aceFlags |= bsdflag2nfs4flag[i].nfs4flag;
		}
	}

	if (ae->ae_entry_type == ACL_ENTRY_TYPE_ALLOW) {
		aceprop->aceType = SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE;
		aceprop->aceMask |= SMB_ACE4_SYNCHRONIZE;
	} else if (ae->ae_entry_type == ACL_ENTRY_TYPE_DENY) {
		aceprop->aceType = SMB_ACE4_ACCESS_DENIED_ACE_TYPE;
	} else {
		smb_panic("Unsupported ace type.");
	}

	switch(ae->ae_tag) {
	case ACL_USER_OBJ:
		aceprop->flags = SMB_ACE4_ID_SPECIAL;
		aceprop->who.special_id = SMB_ACE4_WHO_OWNER;
		break;
	case ACL_GROUP_OBJ:
		aceprop->flags = SMB_ACE4_ID_SPECIAL;
		aceprop->who.special_id = SMB_ACE4_WHO_GROUP;
		break;
	case ACL_EVERYONE:
		aceprop->flags = SMB_ACE4_ID_SPECIAL;
		aceprop->who.special_id = SMB_ACE4_WHO_EVERYONE;
		break;
	case ACL_GROUP:
		aceprop->aceFlags |= SMB_ACE4_IDENTIFIER_GROUP;
	case ACL_USER:
		aceprop->who.id = ae->ae_id;
		aceprop->flags = 0;
		break;
	default:
		smb_panic("Unsupported ace tag");
	}

	if ((aceprop->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) &&
	    (aceprop->flags) && (aceprop->aceMask & SMB_ACE4_WRITE_DATA)) {
		aceprop->aceMask |= (SMB_ACE4_WRITE_NAMED_ATTRS | \
				     SMB_ACE4_WRITE_ATTRIBUTES | \
				     SMB_ACE4_DELETE);
	}
}

static bool smbace2bsdentry(acl_t bsdacl, SMB_ACE4PROP_T *aceprop)
{
	acl_entry_t new_entry;
	acl_perm_t permset = 0;
	acl_entry_type_t type = 0;
	acl_flag_t flags;
	uid_t id;
	acl_tag_t tag;
	int i;

	for (i = 0; i < ARRAY_SIZE(bsdperm2nfs4perm); i++) {
		if (aceprop->aceMask & bsdperm2nfs4perm[i].nfs4perm) {
			permset |= bsdperm2nfs4perm[i].bsdperm;
		}
	}

	for (i = 0; i < ARRAY_SIZE(bsdflag2nfs4flag); i++) {
		if (aceprop->aceFlags & bsdflag2nfs4flag[i].nfs4flag) {
			flags |= bsdflag2nfs4flag[i].bsdflag;
		}
	}

	if (acl_create_entry(&bsdacl, &new_entry) < 0) {
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
			tag = ACL_EVERYONE;
			break;
		case SMB_ACE4_WHO_OWNER:
			tag = ACL_USER_OBJ;
			break;
		case SMB_ACE4_WHO_GROUP:
			tag = ACL_GROUP_OBJ;
			break;
		default:
			smb_panic("Unsupported special id.");
		}
	} else {
		tag = ACL_GROUP ? aceprop->aceFlags & SMB_ACE4_IDENTIFIER_GROUP : ACL_USER;
	}

	new_entry->ae_perm = permset;
	new_entry->ae_flags = flags;
	new_entry->ae_entry_type = type;
	new_entry->ae_tag = tag;
	new_entry->ae_id = id;

	return true;
}

static NTSTATUS ixnas_get_nt_acl_nfs4_common(struct connection_struct *conn,
					     TALLOC_CTX *mem_ctx,
					     files_struct *fsp,
					     acl_t bsdacl,
					     struct SMB4ACL_T **ppacl,
					     struct ixnas_config_data *config)
{
	int cnt, ret;
	struct SMB4ACL_T *pacl = NULL;
	bool inherited_is_present = false;
	bool is_dir;

	mem_ctx = talloc_tos();

	/* create SMB4ACL data */
	pacl = smb_create_smb4acl(mem_ctx);
	if (pacl == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (cnt=0; cnt<bsdacl->ats_acl.acl_cnt; cnt++) {
		SMB_ACE4PROP_T aceprop;
		ZERO_STRUCT(aceprop);

		bsdentry2smbace(&bsdacl->ats_acl.acl_entry[cnt], &aceprop);

		if ((aceprop.aceMask == 0) &&
		    (aceprop.flags == SMB_ACE4_ID_SPECIAL) &&
		    (aceprop.who.special_id == SMB_ACE4_WHO_EVERYONE)) {
			continue;
		}

		if (aceprop.aceFlags & SMB_ACE4_INHERITED_ACE) {
			inherited_is_present = true;
		}

		if (smb_add_ace4(pacl, &aceprop) == NULL) {
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
	NTSTATUS status;
	acl_t bsdacl;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->zfs_acl_enabled) {
		return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);
	}

	bsdacl = fsp_get_bsdacl(fsp);
	if (bsdacl == NULL) {
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
					      bsdacl,
					      &pacl,
					      config);
	acl_free(bsdacl);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, NULL, security_info, mem_ctx,
				      ppdesc, pacl);
	TALLOC_FREE(frame);
	return status;
}

static bool ixnas_process_smbacl(vfs_handle_struct *handle,
				 files_struct *fsp,
				 struct SMB4ACL_T *smbacl)
{
	acl_t bsdacl;
	struct SMB4ACE_T *smbace = NULL;
	bool has_inheritable = false;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return False);

	bsdacl = acl_init(ACL_MAX_ENTRIES);
	if (bsdacl == NULL) {
		DBG_ERR("%s: acl_init failed: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return false;
	}

	for (smbace=smb_first_ace4(smbacl);
	     smbace!=NULL;
	     smbace = smb_next_ace4(smbace)) {
		bool ok;
		SMB_ACE4PROP_T *aceprop = smb_get_ace4(smbace);

		ok = smbace2bsdentry(bsdacl, aceprop);
                if (!ok) {
			DBG_ERR("%s: failed to convert ACL entry\n",
				fsp_str_dbg(fsp));
			acl_free(bsdacl);
			return false;
		}

		if ((aceprop->aceFlags & ~(SMB_ACE4_IDENTIFIER_GROUP|SMB_ACE4_INHERITED_ACE)) != 0) {
			has_inheritable = true;
		}
	}

	if (bsdacl->ats_acl.acl_cnt == 0 || has_inheritable) {
		int rv;
		acl_entry_t hidden_entry;

		rv = acl_create_entry(&bsdacl, &hidden_entry);
		if (rv == -1) {
			DBG_ERR("%s: acl_create_entry() failed: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			acl_free(bsdacl);
			return false;
		}

		if (S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
			hidden_entry->ae_flags = ACL_ENTRY_DIRECTORY_INHERIT|ACL_ENTRY_FILE_INHERIT;
		}

		hidden_entry->ae_perm = 0;
		hidden_entry->ae_entry_type = ACL_ENTRY_TYPE_ALLOW;
		hidden_entry->ae_tag = ACL_EVERYONE;
		hidden_entry->ae_id = ACL_UNDEFINED_ID;
	}

	if (fsp_set_bsdacl(fsp, bsdacl)) {
		DBG_ERR("%s: failed to set acl: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		acl_free(bsdacl);
		return false;
	}

	acl_free(bsdacl);
	return True;
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
static int mode_to_acl(acl_t *new_acl, mode_t mode)
{
	int res = 0;
	mode_t shifted_mode, other_mode, deny_mode;
	acl_entry_t o_allow_entry = NULL;
	acl_entry_t g_allow_entry = NULL;
	acl_entry_t e_allow_entry = NULL;
	acl_entry_t o_deny_entry = NULL;
	acl_entry_t g_deny_entry = NULL;
	acl_permset_t permset;
	acl_flagset_t flagset;
	/*
	 * convert posix mode bits to ACLs
	 */
	if (((mode & S_IRWXU) >> 6) < (mode & S_IRWXO)) {
		shifted_mode = (mode &= S_IRWXU) >> 6;
		other_mode &= S_IRWXO;
		deny_mode = (shifted_mode ^ other_mode) << 6;
		res = acl_create_entry(new_acl, &o_deny_entry);
		if (res != 0) {
			return -1;
		}
		acl_get_permset(o_deny_entry, &permset);
		if (deny_mode & S_IRUSR) {
			*permset = ACL_READ_DATA;
		}
		if (deny_mode & S_IWUSR) {
			*permset |= ACL_WRITE_DATA;
		}
		if (deny_mode & S_IXUSR) {
			*permset |= ACL_EXECUTE;
		}
		acl_get_flagset_np(o_deny_entry, &flagset);
		*flagset = 0;
		acl_set_entry_type_np(o_deny_entry, ACL_ENTRY_TYPE_DENY);
		acl_set_tag_type(o_deny_entry, ACL_USER_OBJ);
	}
	if (((mode & S_IRWXG) >> 3) < (mode & S_IRWXO)) {
		shifted_mode = (mode &= S_IRWXG) >> 3;
		other_mode &= S_IRWXG;
		deny_mode = (shifted_mode ^ other_mode) << 3;

		res = acl_create_entry(new_acl, &g_deny_entry);
		if (res != 0) {
			return -1;
		}
		acl_get_permset(g_deny_entry, &permset);
		if (deny_mode & S_IRGRP) {
			*permset = ACL_READ_DATA;
		}
		if (deny_mode & S_IWGRP) {
			*permset |= ACL_WRITE_DATA;
		}
		if (deny_mode & S_IXGRP) {
			*permset |= ACL_EXECUTE;
		}
		acl_get_flagset_np(g_deny_entry, &flagset);
		*flagset = 0;
		acl_set_entry_type_np(g_deny_entry, ACL_ENTRY_TYPE_DENY);
		acl_set_tag_type(g_deny_entry, ACL_GROUP_OBJ);
	}
	if (mode & S_IRWXU) {
		res = acl_create_entry(new_acl, &o_allow_entry);
		if (res != 0) {
			return -1;
		}
		acl_get_permset(o_allow_entry, &permset);
		if (mode & S_IRUSR) {
			*permset = ACL_READ_SET;
		}
		if (mode & S_IWUSR) {
			*permset |= ACL_WRITE_SET;
			*permset |= ACL_DELETE;
		}
		if (mode & S_IXUSR) {
			*permset |= ACL_EXECUTE;
		}
		acl_get_flagset_np(o_allow_entry, &flagset);
		*flagset = 0;
		acl_set_entry_type_np(o_allow_entry, ACL_ENTRY_TYPE_ALLOW);
		acl_set_tag_type(o_allow_entry, ACL_USER_OBJ);
	}
	if (mode & S_IRWXG) {
		res = acl_create_entry(new_acl, &g_allow_entry);
		if (res != 0) {
			return -1;
		}
		acl_get_permset(g_allow_entry, &permset);
		if (mode & S_IRGRP) {
			*permset = ACL_READ_SET;
		}
		if (mode & S_IWGRP) {
			*permset |= ACL_WRITE_SET;
			*permset |= ACL_DELETE;
		}
		if (mode & S_IXGRP) {
			*permset |= ACL_EXECUTE;
		}
		acl_get_flagset_np(g_allow_entry, &flagset);
		*flagset = 0;
		acl_set_entry_type_np(g_allow_entry, ACL_ENTRY_TYPE_ALLOW);
		acl_set_tag_type(g_allow_entry, ACL_GROUP_OBJ);
	}
	if (mode & S_IRWXO) {
		res = acl_create_entry(new_acl, &e_allow_entry);
		if (res != 0) {
			return -1;
		}
		acl_get_permset(e_allow_entry, &permset);
		if (mode & S_IROTH) {
			*permset = ACL_READ_SET;
		}
		if (mode & S_IWOTH) {
			*permset |= ACL_WRITE_SET;
			*permset |= ACL_DELETE;
		}
		if (mode & S_IXOTH) {
			*permset |= ACL_EXECUTE;
		}
		acl_get_flagset_np(e_allow_entry, &flagset);
		*flagset = 0;
		acl_set_entry_type_np(e_allow_entry, ACL_ENTRY_TYPE_ALLOW);
		acl_set_tag_type(e_allow_entry, ACL_EVERYONE);
	}
	return 0;
}

static int recalculate_flagset(acl_flagset_t flagset)
{
	/* Simply replace non-inheriting entries */
	if ((*flagset & (ACL_ENTRY_DIRECTORY_INHERIT \
		        | ACL_ENTRY_FILE_INHERIT)) == 0){
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
	if (((*flagset & ACL_ENTRY_INHERIT_ONLY) == 0) &&
	     (*flagset & ACL_ENTRY_NO_PROPAGATE_INHERIT)) {
		return 0;
	}
	*flagset |= ACL_ENTRY_INHERIT_ONLY;
	return 0;
}

static acl_t calculate_chmod_acl(acl_t source_acl,
				 mode_t mode)
{
	int res = 0;
	acl_t new_acl, tmp_acl;
	int entry_id = ACL_FIRST_ENTRY;
	acl_entry_t entry, new_entry;
	acl_tag_t tag = 0;
	acl_flagset_t flagset;

	new_acl = acl_init(ACL_MAX_ENTRIES);
	tmp_acl = acl_dup(source_acl);
	res = mode_to_acl(&new_acl, mode);
	if (res != 0) {
		DBG_ERR("Failed to convert mode to ACL\n");
		goto failure;
	}
	/*
	 * Iterate through ACL, remove non-inheriting special entries.
	 * Append INHERIT_ONLY to inheritng special entries
	 */
	while (acl_get_entry(tmp_acl, entry_id, &entry) == 1) {
		entry_id = ACL_NEXT_ENTRY;
		res = acl_get_tag_type(entry, &tag);
		if (res != 0) {
			DBG_ERR("acl_get_permset() failed.\n");
			return NULL;
		}
		switch (tag) {
                        case ACL_USER_OBJ:
                        case ACL_GROUP_OBJ:
                        case ACL_EVERYONE:
				res = acl_get_flagset_np(entry, &flagset);
				if (res != 0) {
					DBG_ERR("acl_get_flagset failed\n");
					return NULL;
				}
				res = recalculate_flagset(flagset);
				if (res != 0) {
					continue;
				}
				res = acl_create_entry(&new_acl, &new_entry);
				if (res != 0) {
					DBG_ERR("acl_create_entry failed\n");
					goto failure;
				}
				res = acl_copy_entry(new_entry, entry);
				if (res != 0) {
					DBG_ERR("acl_copy_entry failed\n");
					goto failure;
				}
                                break;
                        default:
				res = acl_create_entry(&new_acl, &new_entry);
				if (res != 0) {
					DBG_ERR("acl_create_entry failed\n");
					goto failure;
				}
				res = acl_copy_entry(new_entry, entry);
				if (res != 0) {
					DBG_ERR("acl_copy_entry failed\n");
					goto failure;
				}
                                break;
		}
	}
	acl_free(tmp_acl);
	return new_acl;
failure:
	acl_free(tmp_acl);
	acl_free(new_acl);
	return NULL;
}

static int ixnas_fchmod(vfs_handle_struct *handle,
			files_struct *fsp, mode_t mode)
{
	int result;
	acl_t zacl, new_acl;
	int trivial = 0;
	struct ixnas_config_data *config = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (!config->zfs_acl_chmod_enabled) {
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}
	zacl = fsp_get_bsdacl(fsp);
	if (zacl == NULL) {
		DBG_ERR("ixnas: acl_get_fd() failed for %s: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		return -1;
	}
	result = acl_is_trivial_np(zacl, &trivial);
	if (result !=0) {
		DBG_ERR("acl_is_trivial_np() failed\n");
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
		acl_free(zacl);
		result = SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
		return result;
	}
	new_acl = calculate_chmod_acl(zacl, mode);
	if (new_acl == NULL) {
		DBG_ERR("Failed to generate new ACL for %s",
			fsp_str_dbg(fsp));
		goto failure;
	}
	result = fsp_set_bsdacl(fsp, new_acl);
	if (result != 0) {
		DBG_ERR("Failed to set new ACL on %s: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
	}
	acl_free(zacl);
	acl_free(new_acl);
	return result;
failure:
	acl_free(zacl);
	return -1;
}

/*
 * Windows clients return NT_STATUS_OBJECT_NAME_COLLISION in case of
 * rename in case of rename in case insensitive dataset. MacOS does
 * attempts the rename. rename() in FreeBSD in this returns success, but
 * does not actually rename the file. Add new logic to rename(). If
 * a case_insensitive string comparison of the filenames returns 0, then
 * perform two renames so that the returned filename matches client
 * expectations. First rename appends a jenkins hash of the full path
 * to the file to its name. This makes the rename deterministic, but
 * minimizes risk of name collisions.
 */
static int ixnas_renameat(vfs_handle_struct *handle,
			  files_struct *srcfsp,
			  const struct smb_filename *smb_fname_src,
			  files_struct *dstfsp,
			  const struct smb_filename *smb_fname_dst)
{
	int result;
	struct ixnas_config_data *config = NULL;
	char *tmp_base_name = NULL;
	uint32_t nhash;
	NTSTATUS status;
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
	result = strcasecmp_m(smb_fname_src->base_name,
			      smb_fname_dst->base_name);
	if (result != 0) {
		return SMB_VFS_NEXT_RENAMEAT(handle,
					     srcfsp,
					     smb_fname_src,
					     dstfsp,
					     smb_fname_dst);
	}
	status = file_name_hash(handle->conn, smb_fname_src->base_name, &nhash);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
		DBG_ERR("failed to generate filename hash for %s\n",
			smb_fname_src->base_name);
		errno=ENOMEM;
		return -1;
	}
	tmp_base_name = talloc_asprintf(talloc_tos(), "%s_0x%08x",
					smb_fname_src->base_name, nhash);
	result = rename(smb_fname_src->base_name, tmp_base_name);
	if (result != 0) {
		DBG_ERR("Failed to rename %s to intermediate name %s\n",
			smb_fname_src->base_name, tmp_base_name);
		TALLOC_FREE(tmp_base_name);
		return result;
	}
	result = rename(tmp_base_name, smb_fname_dst->base_name);
	TALLOC_FREE(tmp_base_name);
	return result;
}

static bool is_robocopy_init(struct smb_file_time *ft)
{
	if (!null_timespec(ft->atime) ||
	    !null_timespec(ft->create_time)) {
		return false;
	}
	if (ft->mtime.tv_sec == 315619200) {
		return true;
	}
	return false;
}

static int fsp_set_times(files_struct *fsp, struct timespec *times)
{
	if (!fsp->fsp_flags.is_pathref) {
		return futimens(fsp_get_io_fd(fsp), times);
        }

	if (fsp->fsp_flags.have_proc_fds) {
		int fd = fsp_get_pathref_fd(fsp);
		const char *p = NULL;
		char buf[PATH_MAX];

		p = sys_proc_fd_path(fd, buf, sizeof(buf));
		if (p != NULL) {
			return utimensat(AT_FDCWD, p, times, 0);
                }

		return -1;
	}

	/* fallback to path-based call */
	return utimensat(AT_FDCWD, fsp->fsp_name->base_name, times, 0);
}

static int ixnas_ntimes(vfs_handle_struct *handle,
			files_struct *fsp,
			struct smb_file_time *ft)
{
	int result = -1;
	struct ixnas_config_data *config = NULL;
	struct timespec ts[2], *times = NULL;

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

	/*
	 * man utimensat(2)
	 * If times is non-NULL, it is assumed to point to an array of two
	 * timespec structures. The access time is set to the value of the
	 * second element. For filesystems that support file birth (creation) times,
	 * the birth time will be set to the value of the second element if the
	 * second element is older than the currently set birthtime. To set both
	 * a birth time and a modification tie, two calls are required. The first
	 * to set the birth time and the second to set the (presumabley newer).
	 */
	if (ft != NULL) {
		if (is_robocopy_init(ft)) {
			return 0;
		}
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
				      &fsp->fsp_name->st.st_ex_mtime) == 0)) {
			return 0;
		}
		/*
		 * Perform two utimensat() calls if needed to set the specified
		 * timestamps.
		 */
		if (is_omit_timespec(&ft->create_time)) {
			ft->create_time = ft->mtime;
		}
		ts[0] = ft->atime;
		ts[1] = ft->create_time;
		result = fsp_set_times(fsp, ts);
		if (timespec_compare(&ft->mtime, &ft->create_time) != 0) {
			ts[1] = ft->mtime;
			result = fsp_set_times(fsp, ts);
		}
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
			    &config->dsl);

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
