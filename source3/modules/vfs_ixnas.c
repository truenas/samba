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
#include "smbd/globals.h"
#include "MacExtensions.h"
#include "smbd/smbd.h"
#include "libcli/security/security.h"
#include "auth.h"
#include "privileges.h"
#include "librpc/gen_ndr/idmap.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "../libcli/security/dom_sid.h"
#include "../libcli/security/security.h"
#include "passdb/lookup_sid.h"
#include "nfs4_acls.h"
#include "system/filesys.h"
#include <fstab.h>
#include <sys/types.h>
#include <ufs/ufs/quota.h>
#include <sys/acl.h>

#if HAVE_LIBZFS
#include "lib/util/tevent_ntstatus.h"
#include "modules/smb_libzfs.h"
#endif
#include <libutil.h>

static int vfs_ixnas_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_ixnas_debug_level

extern const struct generic_mapping file_generic_mapping;

struct ixnas_config_data {
	struct smbacl4_vfs_params nfs4_params;
	struct smblibzfshandle *libzp;
	struct dataset_list *dsl;
	bool posix_rename;
	bool dosattrib_xattr;
	bool zfs_acl_enabled;
	bool zfs_acl_sortaces;
	bool zfs_acl_map_modify;
	bool zfs_acl_ignore_empty_mode;
	bool zfs_acl_chmod_enabled;
	bool zfs_space_enabled;
	bool zfs_quota_enabled;
	bool zfs_auto_homedir;
	struct zfs_dataset_prop *props;
	const char *homedir_quota;
	uint64_t base_user_quota; 
};

static uint32_t ixnas_fs_capabilities(struct vfs_handle_struct *handle,
			enum timestamp_set_resolution *p_ts_res)
{
	struct ixnas_config_data *config = NULL;
        uint32_t fscaps;
	int rv;

	fscaps = SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);

	rv = pathconf(handle->conn->connectpath,
		      _PC_ACL_NFS4);
	if (rv == 1) {
		handle->conn->aclbrand = SMB_ACL_BRAND_NFS41;
	}
	else if (fscaps & FILE_PERSISTENT_ACLS) {
		handle->conn->aclbrand = SMB_ACL_BRAND_POSIX;
	}
	else {
		handle->conn->aclbrand = SMB_ACL_BRAND_NONE;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return fscaps);

	if (config->dosattrib_xattr) {
		return fscaps;
	}

	rv = pathconf(handle->conn->connectpath, _PC_MIN_HOLE_SIZE);
	if (rv > 0) {
		DBG_DEBUG("pathconf _PC_MIN_HOLE_SIZE on [%s] returned: %d\n",
			  handle->conn->connectpath, rv);
		fscaps |= FILE_SUPPORTS_SPARSE_FILES;
	}
	DBG_INFO("ixnas: fscaps: %08x\n", fscaps);
	return fscaps;
}

/********************************************************************
 Fuctions to store DOS attributes as File Flags.
********************************************************************/
static uint32_t fileflags_to_dosmode(uint32_t fileflags)
{
	uint32_t dosmode = 0;
	if (fileflags & UF_READONLY){
		dosmode |= FILE_ATTRIBUTE_READONLY;
	}
	if (fileflags & UF_ARCHIVE){
		dosmode |= FILE_ATTRIBUTE_ARCHIVE;
	}
	if (fileflags & UF_SYSTEM){
		dosmode |= FILE_ATTRIBUTE_SYSTEM;
	}
	if (fileflags & UF_HIDDEN){
		dosmode |= FILE_ATTRIBUTE_HIDDEN;
	}
	if (fileflags & UF_SPARSE){
		dosmode |= FILE_ATTRIBUTE_SPARSE;
	}
	if (fileflags & UF_OFFLINE){
		dosmode |= FILE_ATTRIBUTE_OFFLINE;
	}
	if (fileflags & UF_REPARSE){
		dosmode |= FILE_ATTRIBUTE_REPARSE_POINT;
	}

	return dosmode;
}

static uint32_t dosmode_to_fileflags(uint32_t dosmode)
{
	uint32_t fileflags = 0;
	if (dosmode & FILE_ATTRIBUTE_ARCHIVE) {
		fileflags |= UF_ARCHIVE;
	}
	if (dosmode & FILE_ATTRIBUTE_HIDDEN) {
		fileflags |= UF_HIDDEN;
	}
	if (dosmode & FILE_ATTRIBUTE_OFFLINE) {
		fileflags |= UF_OFFLINE;
	}
	if (dosmode & FILE_ATTRIBUTE_READONLY) {
		fileflags |= UF_READONLY;
	}
	if (dosmode & FILE_ATTRIBUTE_SYSTEM) {
		fileflags |= UF_SYSTEM;
	}
	if (dosmode & FILE_ATTRIBUTE_SPARSE) {
		fileflags |= UF_SPARSE;
	}
	if (dosmode & FILE_ATTRIBUTE_REPARSE_POINT){
		fileflags |= UF_REPARSE;
	}

	return fileflags;
}

static NTSTATUS set_dos_attributes_common(struct vfs_handle_struct *handle,
					 const struct smb_filename *smb_fname,
					 uint32_t dosmode)
{
	int ret;
	bool set_dosmode_ok = false;
	NTSTATUS status = NT_STATUS_OK;
	uint32_t fileflags = dosmode_to_fileflags(dosmode);

	DBG_INFO("ixnas:set_dos_attributes: set attribute 0x%x, on file %s\n",
		dosmode, smb_fname->base_name);
	/*
	* Optimization. This is most likely set by file owner. First try without
	* performing additional permissions checks and using become_root().
	*/

	ret = SMB_VFS_CHFLAGS(handle->conn, smb_fname, fileflags);

	if (ret ==-1 && errno == EPERM) {
	/*
	* We want DOS semantics, i.e. allow non-owner with write permission to
	* change the bits on a file.   
	*/

		if (!CAN_WRITE(handle->conn)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		status = smbd_check_access_rights(handle->conn, smb_fname, false,
						FILE_WRITE_ATTRIBUTES);
		if (NT_STATUS_IS_OK(status)) {
			set_dosmode_ok = true;
		}

		if (!set_dosmode_ok && lp_dos_filemode(SNUM(handle->conn))) {
			set_dosmode_ok = can_write_to_file(handle->conn, smb_fname);
		}

		if (!set_dosmode_ok){
			return NT_STATUS_ACCESS_DENIED;
		}

		/* becomeroot() because non-owners need to write flags */

		become_root();
		ret = SMB_VFS_CHFLAGS(handle->conn, smb_fname, fileflags);
		unbecome_root();

		if (ret == -1) {
			DBG_WARNING("Setting dosmode failed for %s: %s\n",
			smb_fname->base_name, strerror(errno));
			return map_nt_error_from_unix(errno);
		}
		return NT_STATUS_OK;
	}

	if (ret == -1) {
		DBG_WARNING("Setting dosmode failed for %s: %s\n",
			smb_fname->base_name, strerror(errno));
		return map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}

static NTSTATUS ixnas_get_dos_attributes(struct vfs_handle_struct *handle,
					 struct smb_filename *smb_fname,
					 uint32_t *dosmode)
{
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (config->dosattrib_xattr) {
		return SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle,
						       smb_fname,
						       dosmode);
	}

	*dosmode |= fileflags_to_dosmode(smb_fname->st.st_ex_flags);

	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
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

static NTSTATUS ixnas_fget_dos_attributes(struct vfs_handle_struct *handle,
                                            struct files_struct *fsp,
                                            uint32_t *dosmode)
{
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (config->dosattrib_xattr) {
		return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
							fsp,
							dosmode);
	}

        *dosmode |= fileflags_to_dosmode(fsp->fsp_name->st.st_ex_flags);

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

static NTSTATUS ixnas_set_dos_attributes(struct vfs_handle_struct *handle,
                                           const struct smb_filename *smb_fname,
                                           uint32_t dosmode)
{
	NTSTATUS ret;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->dosattrib_xattr) {
		ret = set_dos_attributes_common(handle, smb_fname, dosmode);
	}
	else {
		ret = SMB_VFS_NEXT_SET_DOS_ATTRIBUTES(handle,
						      smb_fname,
						      dosmode);
	}

	return ret;
}

static NTSTATUS ixnas_fset_dos_attributes(struct vfs_handle_struct *handle,
                                            struct files_struct *fsp,
                                            uint32_t dosmode)
{
	NTSTATUS ret;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->dosattrib_xattr) {
		ret = set_dos_attributes_common(handle, fsp->fsp_name, dosmode);
	}
	else {
		ret = SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
						       fsp,
						       dosmode);
	}

	return ret;
}

/********************************************************************
 Correctly calculate free space on ZFS 
 Per MS-FSCC, behavior for Windows 2000 -> 2008R2 is to account for
 user quotas in TotalAllocationUnits and CallerAvailableAllocationUnits  
 in FileFsFullSizeInformation.
********************************************************************/
#if HAVE_LIBZFS
static uint64_t ixnas_disk_free(vfs_handle_struct *handle, const struct smb_filename *smb_fname,
				uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	uint64_t res;
	char rp[PATH_MAX] = { 0 };
	struct ixnas_config_data *config = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (!config->zfs_space_enabled) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	}

	if (realpath(smb_fname->base_name, rp) == NULL)
		return (-1);

	DBG_DEBUG("realpath = %s\n", rp);

	res = smb_zfs_disk_free(config->libzp, rp, bsize, dfree, dsize, geteuid());
	if (res == (uint64_t)-1)
		res = SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	if (res == (uint64_t)-1)
		return (res);

	DBG_DEBUG("*bsize = %" PRIu64 "\n", *bsize);
	DBG_DEBUG("*dfree = %" PRIu64 "\n", *dfree);
	DBG_DEBUG("*dsize = %" PRIu64 "\n", *dsize);

	return (res);
}
#endif

/********************************************************************
 Functions for OSX compatibility. 
********************************************************************/
static NTSTATUS ixnas_create_file(vfs_handle_struct *handle,
				  struct smb_request *req,
				  uint16_t root_dir_fid,
				  struct smb_filename *smb_fname,
				  uint32_t access_mask,
				  uint32_t share_access,
				  uint32_t create_disposition,
				  uint32_t create_options,
				  uint32_t file_attributes,
				  uint32_t oplock_request,
				  const struct smb2_lease *lease,
				  uint64_t allocation_size,
				  uint32_t private_flags,
				  struct security_descriptor *sd,
				  struct ea_list *ea_list,
				  files_struct **result,
				  int *pinfo,
				  const struct smb2_create_blobs *in_context_blobs,
				  struct smb2_create_blobs *out_context_blobs)
{
	NTSTATUS status;
	struct ixnas_config_data *config = NULL;
	files_struct *fsp = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	status = SMB_VFS_NEXT_CREATE_FILE(
		handle, req, root_dir_fid, smb_fname,
		access_mask, share_access,
		create_disposition, create_options,
		file_attributes, oplock_request,
		lease,
		allocation_size, private_flags,
		sd, ea_list, result,
		pinfo, in_context_blobs, out_context_blobs);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp = *result;

	if (config->posix_rename && fsp->is_directory) {
		fsp->posix_flags |= FSP_POSIX_FLAGS_RENAME;
	}

	return status;
}

/********************************************************************
 Functions to use ZFS ACLs. 
********************************************************************/
/*  
 * These permissions unfortunately don't line up directly so we
 * perform bitwise operations to transform them.
 * BSD perms are defined in acl.h and Windows perms in security.idl
 * Several permissions share the same mask. The chart below shows
 * the file constants unless the permission only applies to directories.
 * (DELETE_CHILD).
 * ____________________________   ___________________________________
 * READ_DATA         0x00000008 | SEC_FILE_READ_DATA       0x00000001
 * WRITE_DATA        0x00000010 | SEC_FILE_WRITE_DATA      0x00000002
 * APPEND_DATA       0x00000020 | SEC_FILE_APPEND_DATA     0x00000004
 * READ_NAMED_ATTRS  0x00000040 | SEC_FILE_READ_EA         0x00000008
 * WRITE_NAMED_ATTRS 0x00000080 | SEC_FILE_WRITE_EA        0x00000010
 * EXECUTE               0x0001 | SEC_FILE_EXECUTE         0x00000020
 * DELETE_CHILD      0x00000100 | SEC_DIR_DELETE_CHILD     0x00000040
 * READ_ATTRIBUTES   0x00000200 | SEC_FILE_READ_ATTRIBUTE  0x00000080
 * WRITE_ATTRIBUTES  0x00000400 | SEC_FILE_WRITE_ATTRIBUTE 0x00000100
 * DELETE            0x00000800 | SEC_STD_DELETE           0x00001000
 * READ_ACL          0x00001000 | SEC_STD_READ_CONTROL     0x00002000
 * WRITE_ACL         0x00002000 | SEC_STD_WRITE_DAC        0x00004000
 * WRITE_OWNER       0x00004000 | SEC_STD_WRITE_OWNER      0x00008000
 * SYNCHRONIZE       0x00008000 | SEC_STD_SYNCHRONIZE      0x00010000
 *
 * Requests for GENERIC rights will fail if the ACE lacks synchronize.
 * this means that this bit must be added to allow ACEs but not deny
 * ACEs. See Samba bugzilla tickets #7909 and #8442. 
 */
uint32_t bsd2winperms(acl_perm_t bsd_perm)
{
	uint32_t winperms = 0;
	int l, m, h;
	l = m = h = 0;
	l = bsd_perm >> 3;
	m = bsd_perm >> 2;
	h = bsd_perm << 5;
	l &= (SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA|
	      SEC_FILE_APPEND_DATA|SEC_FILE_READ_EA|
	      SEC_FILE_WRITE_EA);
	m &= (SEC_FILE_READ_ATTRIBUTE|SEC_FILE_WRITE_ATTRIBUTE|SEC_DIR_DELETE_CHILD);
	h &= (SEC_STD_DELETE|SEC_STD_READ_CONTROL|
	      SEC_STD_WRITE_DAC|SEC_STD_WRITE_OWNER|
	      SEC_STD_SYNCHRONIZE); //remove bits lower than SMB_ACE4_DELETE
	winperms = (l|m|h);
	if (bsd_perm & ACL_EXECUTE) {
		winperms |= SEC_DIR_TRAVERSE;
	}

	return winperms;	
}

uint32_t win2bsdperms(uint32_t win_perm)
{
	uint32_t bsd_perm = 0;
	int l, m, h;
	l = m = h = 0;

	l =  win_perm << 3;
	m =  win_perm << 2;
	h =  win_perm >> 5;
	l &= (ACL_READ_DATA|ACL_WRITE_DATA|ACL_APPEND_DATA|
	      ACL_READ_NAMED_ATTRS|ACL_WRITE_NAMED_ATTRS);
	m &= (ACL_WRITE_ATTRIBUTES|ACL_READ_ATTRIBUTES|ACL_DELETE_CHILD); 
	h &= (ACL_READ_ACL|ACL_WRITE_ACL|ACL_WRITE_OWNER|ACL_DELETE); //Drop SYNCRHONIZE per#7909 
	bsd_perm = (l|m|h);
	if (win_perm & SEC_DIR_TRAVERSE) {
		bsd_perm |= ACL_EXECUTE; //0x0001 (doesn't map cleanly)
	}
	return bsd_perm;
}

/*
 * FILE_INHERIT (0x0001) through INHERIT_ONY (0x0008) map directly.
 * INHERITED (0x0080) and SEC_ACE_FLAG_INHERITED (0x10) do not.
 * SUCCESSFUL_ACCESS and FAILED_ACCESS are not implemented in FreeBSD. 
 * __________________________    ______________________________________
 * FILE_INHERIT         0x0001 | SEC_ACE_FLAG_OBJECT_INHERIT       0x01
 * DIRECTORY_INHERIT    0x0002 | SEC_ACE_FLAG_CONTAINER_INHERIT    0x02
 * NO_PROPAGATE_INHERIT 0x0004 | SEC_ACE_FLAG_NO_PROPAGATE_INHERIT 0x04
 * INHERIT_ONLY         0x0008 | SEC_ACE_FLAG_INHERIT_ONLY         0x08
 * SUCCESSFUL_ACCESS    0x0010 | SEC_ACE_FLAG_SUCCESSFUL_ACCESS    0x40
 * FAILED_ACCESS        0x0020 | SEC_ACE_FLAG_FAILED_ACCESS        0x80
 * INHERITED            0x0080 | SEC_ACE_FLAG_INHERITED_ACE        0x10
 *                             | SEC_ACE_FLAG_VALID_INHERIT        0x0f
 *
 * Invalid inheritance bits for files are stripped from windows flags before
 * returning the BSD flags.
 */

uint8_t bsd2winflags(uint16_t bsd_flags)
{
	uint8_t win_flags = 0;
	win_flags = bsd_flags & (ACL_ENTRY_FILE_INHERIT|
				 ACL_ENTRY_DIRECTORY_INHERIT|
				 ACL_ENTRY_NO_PROPAGATE_INHERIT|
				 ACL_ENTRY_INHERIT_ONLY);
	if (bsd_flags & ACL_ENTRY_INHERITED) {
		win_flags |= SEC_ACE_FLAG_INHERITED_ACE;
	}
	return win_flags;
}

uint16_t win2bsdflags(uint8_t win_flags, bool is_dir)
{
	uint16_t bsd_flags = 0;
	if (is_dir) {
		bsd_flags = win_flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
					 SEC_ACE_FLAG_CONTAINER_INHERIT|
					 SEC_ACE_FLAG_NO_PROPAGATE_INHERIT|
					 SEC_ACE_FLAG_INHERIT_ONLY);
	}
	if (win_flags & SEC_ACE_FLAG_INHERITED_ACE) {
		bsd_flags |= ACL_ENTRY_INHERITED;
	}
	return bsd_flags;
}

bool nt_ace_is_inherit(uint8_t win_flags)
{
	return win_flags & (SEC_ACE_FLAG_INHERIT_ONLY|
			    SEC_ACE_FLAG_OBJECT_INHERIT|
			    SEC_ACE_FLAG_CONTAINER_INHERIT);
}

static acl_t get_zfs_acl(const struct smb_filename *smb_fname)
{
	acl_t zacl;
	int ret, saved_errno;
	zacl = acl_get_file(smb_fname->base_name, ACL_TYPE_NFS4);
	if (zacl == NULL) {
		/*
		 * If we fail to get the ACL on the path in question,
 		 * make a pathconf() call to determine whether the path
		 * supports NFSv4 ACLs. If it does not, then it's clear that
		 * the filesystem underly the path in question is not ZFS.
		 * In this case we want to pass through to the next VFS module
		 * in the stack, which will probably treat the path as having
		 * posix ACLs. errno is set to ENOSYS in this case because
		 * neither pathconf() nor acl_get_file() set it to this value, and
		 * because this is the behavior of libsunacl / vfs_zfsacl.
		 */
		saved_errno = errno;
		ret = pathconf(smb_fname->base_name, _PC_ACL_NFS4);
		if (ret != 0) {
			/*
			 * If path does not support NFS4 ACLs, then pathconf() returns -1
			 * and errno is not modified. If pathconf() itself fails, then it
			 * returns -1 and errno is set.
			 */
			if (errno != saved_errno) {
				DBG_INFO("%s: pathconf(..., _PC_ACL_NFS4) failed. Path does not support NFS4 ACL.",
					smb_fname->base_name);
				errno = ENOSYS;
			}
			else {
				DBG_INFO("ixnas: pathconf() failed for %s: %s\n",
					smb_fname->base_name, strerror(errno));
			}
		}
	}
	return zacl;
}

static acl_t fget_zfs_acl(struct files_struct *fsp)
{
	acl_t zacl;
	int ret, saved_errno;
	if (fsp->fh->fd == -1) {
		return get_zfs_acl(fsp->fsp_name);
	}
	zacl = acl_get_fd_np(fsp->fh->fd, ACL_TYPE_NFS4);

	if (zacl == NULL) {
		/* See above note in get_zfs_acl() */
		saved_errno = errno;
		ret = fpathconf(fsp->fh->fd, _PC_ACL_NFS4);
		if (ret != 0) {
			/*
			 * If path does not support NFS4 ACLs, then pathconf() returns -1
			 * and errno is not modified. If pathconf() itself fails, then it
			 * returns -1 and errno is set.
			 */
			if (errno != saved_errno) {
				DBG_INFO("%s: pathconf(..., _PC_ACL_NFS4) failed. Path does not support NFS4 ACL.",
					 fsp->fsp_name->base_name);
				errno = ENOSYS;
			}
			else {
				DBG_INFO("ixnas: pathconf() failed for %s: %s\n",
					 fsp->fsp_name->base_name, strerror(errno));
			}
		}
	}
	return zacl;
}

static bool bsdacl4_2win(TALLOC_CTX *mem_ctx,
	struct ixnas_config_data *config,
	acl_t zacl,
	const struct smb_filename *smb_fname,
	struct dom_sid *psid_owner,
	struct dom_sid *psid_group,
	struct security_ace **ppnt_ace_list,
	int *pgood_aces,
	uint16_t *acl_control_flags)
{
	int naces, i, good_aces, saved_errno;
	bool is_dir, inherited_present;
	i = naces = saved_errno = good_aces = 0;
	is_dir = inherited_present = false;
	struct security_ace *nt_ace_list = NULL;

	naces = zacl->ats_acl.acl_cnt;
	nt_ace_list = talloc_zero_array(mem_ctx, struct security_ace,
					2 * naces);
	if (nt_ace_list==NULL)
	{
		DBG_ERR("talloc error with %d aces", naces);
		errno = ENOMEM;
		acl_free(zacl);
		return false;
	}
	for(i=0; i<naces; i++) {
		uint32_t mask = 0;
		uint8_t win_ace_flags = 0;
		uint32_t win_ace_type = 0;
		struct dom_sid sid;
		bool map_special_entry = false;
		DBG_DEBUG("ae_tag: %d, ae_id: %d, ae_perm: %x, "
			  "ae_flags: %x, ae_entry_type %x\n",
			  zacl->ats_acl.acl_entry[i].ae_tag,
			  zacl->ats_acl.acl_entry[i].ae_id,
			  zacl->ats_acl.acl_entry[i].ae_perm,
			  zacl->ats_acl.acl_entry[i].ae_flags,
			  zacl->ats_acl.acl_entry[i].ae_entry_type);

		if (!(zacl->ats_acl.acl_entry[i].ae_perm) &&
		    (zacl->ats_acl.acl_entry[i].ae_tag & ACL_EVERYONE)) {
			continue;
		}

		mask = bsd2winperms(zacl->ats_acl.acl_entry[i].ae_perm);

		win_ace_flags = bsd2winflags(zacl->ats_acl.acl_entry[i].ae_flags);

		if (win_ace_flags & SEC_ACE_FLAG_INHERITED_ACE) {
			inherited_present = true;
		}

		win_ace_type = zacl->ats_acl.acl_entry[i].ae_entry_type >> 9; 

		if (win_ace_type == SEC_ACE_TYPE_ACCESS_ALLOWED) {
			mask |= SEC_STD_SYNCHRONIZE;
		}

		switch (zacl->ats_acl.acl_entry[i].ae_tag) {
			case ACL_USER_OBJ:
				sid_copy(&sid, psid_owner);
				map_special_entry = True;
				break;
			case ACL_GROUP_OBJ:
				sid_copy(&sid, psid_group);
				map_special_entry = True;
				break;
			case ACL_EVERYONE:
				sid_copy(&sid, &global_sid_World);
				break;
			case ACL_GROUP:
				gid_to_sid(&sid, zacl->ats_acl.acl_entry[i].ae_id);
				break;
			default:
				uid_to_sid(&sid, zacl->ats_acl.acl_entry[i].ae_id);
				break;
		}
		if (map_special_entry) {
			/*
			 * Special handling for owner@, and group@ entries.
			 * These entries are split into two entries in the Windows SD.
			 * For the first entry owner@ and group@ are mapped to 
			 * S-1-3-0 and S-1-3-1 respectively. Their permset is not changed
			 * for these entries, but SEC_ACE_FLAG_INHERIT_ONLY is added 
			 * to the inheritance flags. The second entry is mapped to
			 * the SID associated with the UID or GID of the owner or group,
			 * and inheritance flags are stripped. This implements windows
			 * behavior for CREATOR-OWNER and CREATOR-GROUP.
			 */
			if ((zacl->ats_acl.acl_entry[i].ae_perm & ACL_WRITE_DATA) &&
			    (config->zfs_acl_map_modify) && (win_ace_flags == 0) &&
			    (win_ace_type == SEC_ACE_TYPE_ACCESS_ALLOWED)) {
				/*
				 * Compatibilty logic for posix modes on
				 * special ids. for group, map "rw" to "modify". 
				 * for user, map "rw" to "full control".
				 */
				mask |= (SEC_STD_DELETE|
					 SEC_FILE_WRITE_EA|
					 SEC_FILE_WRITE_ATTRIBUTE);
			}

			if (!(win_ace_flags & SEC_ACE_FLAG_INHERIT_ONLY)) {
				uint32_t win_ace_flags_current;
				win_ace_flags_current = win_ace_flags &
					~(SEC_ACE_FLAG_OBJECT_INHERIT |
					  SEC_ACE_FLAG_CONTAINER_INHERIT);
				DBG_DEBUG("map current sid:: ace_type: %x, mask: %x, flags%x\n",
					  win_ace_type, mask, win_ace_flags_current);
				init_sec_ace(&nt_ace_list[good_aces++], &sid,
					win_ace_type, mask,
					win_ace_flags_current);
			}
			if ((zacl->ats_acl.acl_entry[i].ae_tag == ACL_USER_OBJ) &&
			     win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT |
					      SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				uint32_t win_ace_flags_creator;
				win_ace_flags_creator = win_ace_flags |
					SEC_ACE_FLAG_INHERIT_ONLY;
				DBG_DEBUG("map creator owner:: ace_type: %x, mask: %x, flags%x\n",
					  win_ace_type, mask, win_ace_flags_creator);
				init_sec_ace(&nt_ace_list[good_aces++],
					&global_sid_Creator_Owner,
					win_ace_type, mask,
					win_ace_flags_creator);
			}
			if ((zacl->ats_acl.acl_entry[i].ae_tag == ACL_GROUP_OBJ) &&
			     win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT |
					      SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				uint32_t win_ace_flags_creator;
				win_ace_flags_creator = win_ace_flags |
					SEC_ACE_FLAG_INHERIT_ONLY;
				DBG_DEBUG("map creator group:: ace_type: %x, mask: %x, flags%x\n",
					  win_ace_type, mask, win_ace_flags_creator);
				init_sec_ace(&nt_ace_list[good_aces++],
					&global_sid_Creator_Group,
					win_ace_type, mask,
					win_ace_flags_creator);
			}
		} else {
			DBG_DEBUG("map normal ace:: ace_type: %x, mask: %x, flags%x\n",
				  win_ace_type, mask, win_ace_flags);
			init_sec_ace(&nt_ace_list[good_aces++], &sid,
				     win_ace_type, mask, win_ace_flags);
		}
	}
	nt_ace_list = talloc_realloc(mem_ctx, nt_ace_list, struct security_ace,
				     good_aces);

	/* returns a NULL ace list when good_aces is zero. */
	if (good_aces && nt_ace_list == NULL) {
		DBG_DEBUG("realloc error with %d aces\n", good_aces);
		errno = ENOMEM;
		acl_free(zacl);
		return false;
	}
	*ppnt_ace_list = nt_ace_list;
	*pgood_aces = good_aces;

	/*
	 * NFSv4.1 ACL control flags are not implemented in FreeBSD and so
         * we need to fake them. This is required in order for users to be
         * able to disable permissions inheritance.
	 */
	if (!inherited_present) {
		*acl_control_flags = (SEC_DESC_DACL_PROTECTED |
				      SEC_DESC_DACL_AUTO_INHERITED |
				      SEC_DESC_SELF_RELATIVE);
	}
	else {
		*acl_control_flags = (SEC_DESC_DACL_AUTO_INHERITED |
				      SEC_DESC_SELF_RELATIVE);
	}
	acl_free(zacl);
	return true;
}

static NTSTATUS ixnas_get_nt_acl_nfs4_common(struct connection_struct *conn,
					     TALLOC_CTX *mem_ctx,
					     const struct smb_filename *smb_fname,
					     acl_t bsdacl,
					     SMB_STRUCT_STAT *psbuf,
					     struct security_descriptor **ppdesc,
					     uint32_t security_info,
					     struct ixnas_config_data *config)
{
	/*
	 * Converts native NFSv4 ACL into Windows Security Descriptor (SD)
	 * ACEs in the DACL in the SD map more or less directly to ZFS ACEs,
	 * SMB clients use SIDs and so all xIDs must be converted to SIDs.
	 * FreeBSD currently does not implement NFSv4.1 ACL control flags,
	 * and so special handling of the SEC_DESC_DACL_PROTECTED flag is
	 * required.
	 */
	int good_aces = 0;
	uint16_t acl_control_flags;
	struct dom_sid sid_owner, sid_group;
	size_t sd_size = 0;
	struct security_ace *nt_ace_list = NULL;
	struct security_acl *psa = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	SMB_STRUCT_STAT sbuf;
	int ret;
	bool ok;

	sbuf = *psbuf;

	uid_to_sid(&sid_owner, sbuf.st_ex_uid);
	gid_to_sid(&sid_group, sbuf.st_ex_gid);

	ok = bsdacl4_2win(frame, config, bsdacl, smb_fname, &sid_owner, &sid_group,
                          &nt_ace_list, &good_aces, &acl_control_flags);

	if (!ok) {
		DBG_INFO("bsdacl4_2win failed\n");
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}
	psa = make_sec_acl(frame, NT4_ACL_REVISION, good_aces, nt_ace_list);
	if (psa == NULL) {
		DBG_ERR("make_sec_acl failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	*ppdesc = make_sec_desc(
		mem_ctx, SD_REVISION, acl_control_flags,
		(security_info & SECINFO_OWNER) ? &sid_owner : NULL,
		(security_info & SECINFO_GROUP) ? &sid_group : NULL,
		NULL, psa, &sd_size);
	if (*ppdesc==NULL) {
		DBG_ERR("make_sec_desc failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	/*
	 * Optionally order the ACEs per guidelines here:
	 * https://docs.microsoft.com/en-us/windows/desktop/secauthz/order-of-aces-in-a-dacl
	 *
	 * The following steps describe the preferred order:
	 * 1. All explicit ACEs are placed in a group before any inherited ACEs.
	 * 2. Within the group of explicit ACEs, access-denied ACEs are placed before access-allowed ACEs.
	 * 3. Inherited ACEs are placed in the order in which they are inherited. ACEs inherited from
	 *    the child object's parent come first, then ACEs inherited from the grandparent, and so on
	 *    up the tree of objects.
	 * 4. For each level of inherited ACEs, access-denied ACEs are placed before access-allowed ACEs.
	 *
	 * This is potentially expensive and so is disabled by default, but may be required
	 * in environments where clients (perhaps using other filesharing protocols) may write
	 * ACLs with entries outside of the preferred order.
	 */
	if ((*ppdesc)->dacl && config->zfs_acl_sortaces) {
		dacl_sort_into_canonical_order((*ppdesc)->dacl->aces, (unsigned int)(*ppdesc)->dacl->num_aces);
	}	
	DBG_DEBUG("sd size %d\n", (int)ndr_size_security_descriptor(*ppdesc, 0));
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}


static bool convert_ntace_to_bsdace(acl_t zacl,
				    const struct security_ace *ace_nt,
				    SMB_STRUCT_STAT sbuf,
				    bool is_dir,
				    bool *has_inheritable)
{
	struct dom_sid_buf buf;
	uint32_t tmp_mask = 0;
	acl_entry_t new_entry, new_entry2;
	acl_perm_t permset = 0;
	acl_entry_type_t type = 0;
	acl_flag_t flags, flags2;
	uid_t id, id2;
	acl_tag_t tag, tag2;
	bool add_ace2 = false;
	struct unixid unixid;
	bool ok = false;

	DBG_DEBUG("[dacl entry] access_mask: 0x%x, flags: 0x%x, type: 0x%x\n",
		  ace_nt->access_mask, ace_nt->flags, ace_nt->type);

	tmp_mask = ace_nt->access_mask & (SEC_STD_ALL | SEC_FILE_ALL);
	se_map_generic(&tmp_mask, &file_generic_mapping);
	if (tmp_mask != ace_nt->access_mask) {
		DBG_INFO("tmp_mask (0x%x) != access_mask(0x%x)\n",
			 tmp_mask, ace_nt->access_mask);
	}

	permset = win2bsdperms(tmp_mask);
	flags = win2bsdflags(ace_nt->flags, is_dir);
	if (flags & (ACL_ENTRY_FILE_INHERIT | ACL_ENTRY_DIRECTORY_INHERIT)) {
		*has_inheritable = true;
	}
	/* Currently ZFS only supports ALLOW and DENY entries */
	switch (ace_nt->type) {
	case SEC_ACE_TYPE_ACCESS_ALLOWED:
		type = ACL_ENTRY_TYPE_ALLOW;
		break;
	case SEC_ACE_TYPE_ACCESS_DENIED:
		type = ACL_ENTRY_TYPE_DENY;
		break;
	case SEC_ACE_TYPE_SYSTEM_AUDIT:
		DBG_ERR("AUDIT entries are not supported.\n");
		errno = EINVAL;
		return false;
	case SEC_ACE_TYPE_SYSTEM_ALARM:
		DBG_ERR("ALARM entries are not supported.\n");
		errno = EINVAL;
		return false;
	default:
		DBG_ERR("Unsupported aceType: %x\n", ace_nt->type);
		errno = EINVAL;
		return false;
	}

	if (dom_sid_equal(&ace_nt->trustee, &global_sid_World)) {
		/* Convert S-1-1-0 to everyone@ */
		tag  = ACL_EVERYONE;
		id   = ACL_UNDEFINED_ID;
	}
	else if (dom_sid_equal(&ace_nt->trustee, &global_sid_Creator_Owner)){
		/* Convert S-1-3-0 to owner@ */
		tag  = ACL_USER_OBJ;
		id   = ACL_UNDEFINED_ID;
		flags |= ACL_ENTRY_INHERIT_ONLY;
		if (flags & !(ACL_ENTRY_FILE_INHERIT|ACL_ENTRY_DIRECTORY_INHERIT)) {
			DBG_INFO("Dropping non-inheriting CREATOR_OWNER entry\n");
			return true;
		}
	}
	else if (dom_sid_equal(&ace_nt->trustee, &global_sid_Creator_Group)) {
		/* Convert S-1-3-1 to group@ */
		tag  = ACL_GROUP_OBJ;
		id   = ACL_UNDEFINED_ID;
		flags |= ACL_ENTRY_INHERIT_ONLY;
		if (flags & !(ACL_ENTRY_FILE_INHERIT|ACL_ENTRY_DIRECTORY_INHERIT)) {
			DBG_INFO("Dropping non-inheriting CREATOR_GROUP entry\n");
			return true;
		}
	}
	else {
		ok = sids_to_unixids(&ace_nt->trustee, 1, &unixid);

		if (!ok) {
			DBG_WARNING("Could not convert %s to uid or gid.\n",
				    dom_sid_str_buf(&ace_nt->trustee, &buf));
			return true;
		}
		switch (unixid.type) {
		/*
		 * The SID resolves to both a GID and a UID. In this situation,
		 * we prefer to convert to a group entry except in a few edge cases.
		 * 1) If the SID is also the Group in the Security Descriptor
		 *    _and_ it is not inheritable. In this case we convert to the special
		 *    "group@" entry. This undoes the NFSv4 "simple" conversion performed on ACL read.
		 * 2) If the SID is also the User in the Security Descriptor _and_ it is not
		 *    inheritable, then add a secondary non-inheriting "owner@" entry.
		 */
		case ID_TYPE_BOTH:
			tag  = ACL_GROUP;
			id  = unixid.id;
			if ((sbuf.st_ex_uid == id) &&
			     !nt_ace_is_inherit(ace_nt->flags)) {
				tag2 = ACL_USER_OBJ;
				id2 = ACL_UNDEFINED_ID;
				add_ace2 = true;
			}
			if ((sbuf.st_ex_gid == id) &&
			    !nt_ace_is_inherit(ace_nt->flags)) {
				tag = ACL_GROUP_OBJ;
				id = ACL_UNDEFINED_ID;
			}
			break;
		/*
		 * The SID was converted into a GID. Create a "group@" entry if it is
		 * not inheritable, otherwise create a normal group entry.
		 */
		case ID_TYPE_GID:
			if ((sbuf.st_ex_gid == unixid.id) &&
			    !nt_ace_is_inherit(ace_nt->flags)) {
				id = ACL_UNDEFINED_ID;
				tag = ACL_GROUP_OBJ;
			}
			else {
				tag = ACL_GROUP;
				id = unixid.id;
			}
			break;
		/*
		 * The SID was converted into a UID. Create a "user@" entry if it is
		 * not inheritable, otherwise create a normal user entry.
		 */
		case ID_TYPE_UID:
			if ((sbuf.st_ex_uid == unixid.id) &&
			    !nt_ace_is_inherit(ace_nt->flags)) {
				id = ACL_UNDEFINED_ID;
				tag = ACL_USER_OBJ;
			}
			else {
				tag = ACL_USER;
				id = unixid.id;
			}
			break;
		case ID_TYPE_NOT_SPECIFIED:
		default:
			DBG_WARNING("Could not convert %s to uid or gid\n",
				    dom_sid_str_buf(&ace_nt->trustee, &buf));
			return false;
		}
	}
	DBG_DEBUG("tag: 0x%08x, id: %d, perm: 0x%08x, flags: 0x%04x, type: 0x%04x\n",
		  tag, id, permset, flags, type);

	if (acl_create_entry(&zacl, &new_entry) < 0) {
		DBG_ERR("Failed to create new ACL entry: %s\n", strerror(errno));
		return false;
	}

	new_entry->ae_perm = permset;
	new_entry->ae_flags = flags;
	new_entry->ae_entry_type = type;
	new_entry->ae_tag = tag;
	new_entry->ae_id = id;
	if (add_ace2) {
		if (acl_create_entry(&zacl, &new_entry2) < 0) {
			DBG_ERR("Failed to create second new ACL entry: %s\n", strerror(errno));
			return false;
		}
		new_entry2->ae_perm = permset;
		new_entry2->ae_flags = flags;
		new_entry2->ae_tag = tag2;
		new_entry2->ae_id = id2;
		new_entry2->ae_entry_type = type;
		DBG_DEBUG("tag: 0x%08x, id: %d, perm: 0x%08x, flags: 0x%04x, type: 0x%04x\n",
			  tag, id, permset, flags, type);
	}
	return true;
}

/*
 * Convert the Security Descriptor DACL into a ZFS ACL
 * using FreeBSD nfsv4 ACL API.
 */
static NTSTATUS ixnas_set_nfs4_acl(vfs_handle_struct *handle,
				   files_struct *fsp,
				   uint32_t security_info_sent,
				   const struct security_descriptor *psd,
				   struct ixnas_config_data *config,
				   bool set_acl_as_root)
{
	int ret, naces, i, saved_errno;
	acl_t zacl;
	acl_entry_t hidden_entry;
	bool ok, is_dir;
	bool has_inheritable = false;

	zacl = acl_init(ACL_MAX_ENTRIES);
	naces = psd->dacl->num_aces;

	SMB_STRUCT_STAT sbuf;

	if (VALID_STAT(fsp->fsp_name->st)) {
		sbuf = fsp->fsp_name->st;
	}
	else {
		ZERO_STRUCT(sbuf);
		ret = vfs_stat_smb_basename(handle->conn, fsp->fsp_name, &sbuf);
		if (ret != 0) {
			DBG_DEBUG("stat [%s]failed: %s\n",
				fsp_str_dbg(fsp), strerror(errno));
			acl_free(zacl);
			return map_nt_error_from_unix(errno);
		}
	}
	is_dir = S_ISDIR(sbuf.st_ex_mode);
	for (i=0; i<psd->dacl->num_aces; i++) {
		ok = convert_ntace_to_bsdace(zacl, (psd->dacl->aces + i),
					     sbuf, is_dir, &has_inheritable);
		if (!ok) {
			acl_free(zacl);
			return map_nt_error_from_unix(errno);
		}
	}
	/*
	 * The 'hidden entry' is added to lock down ZFS behavior of appending
	 * special entries to ZFS ACL on file creation on absence of inheriting
	 * special entries in the parent directory.
	 */
	if (config->zfs_acl_ignore_empty_mode && has_inheritable) {
		if (acl_create_entry(&zacl, &hidden_entry) < 0) {
			DBG_ERR("Failed to create new ACL entry: %s\n", strerror(errno));
		}
		if (is_dir) {
			hidden_entry->ae_flags = ACL_ENTRY_DIRECTORY_INHERIT|ACL_ENTRY_FILE_INHERIT;
		}
		else {
			hidden_entry->ae_flags = 0;
		}
		hidden_entry->ae_perm = 0;
		hidden_entry->ae_entry_type = ACL_ENTRY_TYPE_ALLOW;
		hidden_entry->ae_tag = ACL_EVERYONE;
		hidden_entry->ae_id = ACL_UNDEFINED_ID;
	}

	if (set_acl_as_root) {
		become_root();
	}
	ret = acl_set_file(fsp->fsp_name->base_name, ACL_TYPE_NFS4, zacl);
	if (ret != 0 && errno == EBADF) {
		ret = acl_set_file(fsp->fsp_name->base_name, ACL_TYPE_NFS4, zacl);
	}
	if (set_acl_as_root) {
		unbecome_root();
	}

	if (ret != 0) {
		DBG_DEBUG("(acl_set_file(): %s): %s\n", fsp_str_dbg(fsp), strerror(errno));
		if (pathconf(fsp->fsp_name->base_name, _PC_ACL_NFS4) < 0) {
			DBG_INFO("%s: pathconf(..., _PC_ACL_NFS4) failed. Path does not support NFS4 ACL.",
				fsp_str_dbg(fsp));
			errno = ENOSYS; //preserve behavior from libsunacl and zfsacl
		} 
		else {
			DBG_ERR("(acl_set_file(): %s): %s ", fsp_str_dbg(fsp),
				  strerror(errno));
		}
		saved_errno = errno;
		acl_free(zacl);
		errno = saved_errno;
		return map_nt_error_from_unix(errno);
	}
	acl_free(zacl);
	return NT_STATUS_OK;	
}

static NTSTATUS ixnas_fget_nt_acl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl;
	NTSTATUS status;
	acl_t bsdacl;
	struct ixnas_config_data *config = NULL;
	SMB_STRUCT_STAT *psbuf = NULL;
	SMB_STRUCT_STAT sbuf;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->zfs_acl_enabled) {
		return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);
	}

	if (!VALID_STAT(fsp->fsp_name->st)) {
		ZERO_STRUCT(sbuf);
		if (SMB_VFS_FSTAT(fsp, &sbuf) != 0) {
			DBG_INFO("SMB_VFS_FSTAT failed with error %s\n",
				 strerror(errno));
			return map_nt_error_from_unix(errno);
		}
		psbuf = &sbuf;
	}
	else {
		psbuf = &fsp->fsp_name->st;
	}
	bsdacl = fget_zfs_acl(fsp);

	if (bsdacl == NULL) {
		if (errno == ENOSYS) {
			status = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);
			if (NT_STATUS_IS_OK(status)) {
				(*ppdesc)->type |= SEC_DESC_DACL_PROTECTED;
			}
			return status;
		}
		else {
			return map_nt_error_from_unix(errno);
		}
	}

	status = ixnas_get_nt_acl_nfs4_common(handle->conn,
					      mem_ctx,
					      fsp->fsp_name,
					      bsdacl,
					      psbuf,
					      ppdesc,
					      security_info,
					      config); 

	return status;
}

static NTSTATUS ixnas_get_nt_acl(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl;
	NTSTATUS status;
	int ret;
	acl_t bsdacl;
	struct ixnas_config_data *config = NULL;
	SMB_STRUCT_STAT *psbuf = NULL;
	SMB_STRUCT_STAT sbuf;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->zfs_acl_enabled) {
		return SMB_VFS_NEXT_GET_NT_ACL(handle, smb_fname, security_info, mem_ctx, ppdesc);
	}

	if (VALID_STAT(smb_fname->st)) {
		psbuf = &smb_fname->st;
	}
	else {
		ZERO_STRUCT(sbuf);
		ret = vfs_stat_smb_basename(handle->conn, smb_fname, &sbuf);
		if (ret != 0) {
			DBG_INFO("stat [%s]failed: %s\n",
				 smb_fname_str_dbg(smb_fname), strerror(errno));
			return map_nt_error_from_unix(errno);
		}
		psbuf = &sbuf;
	}
	bsdacl = get_zfs_acl(smb_fname);

	if (bsdacl == NULL) {
		if (errno == ENOSYS) {
			status = SMB_VFS_NEXT_GET_NT_ACL(handle, smb_fname, security_info, mem_ctx, ppdesc);
			if (NT_STATUS_IS_OK(status)) {
				(*ppdesc)->type |= SEC_DESC_DACL_PROTECTED;
			}
			return status;
		}
		else {
			return map_nt_error_from_unix(errno);
		}
	}

	status = ixnas_get_nt_acl_nfs4_common(handle->conn,
					      mem_ctx,
					      smb_fname,
					      bsdacl,
					      psbuf,
					      ppdesc,
					      security_info,
					      config); 

	return status;
}

static int ixnas_get_file_owner(files_struct *fsp, SMB_STRUCT_STAT *psbuf)
{
	ZERO_STRUCTP(psbuf);

	if (fsp->fh->fd == -1) {
		if (vfs_stat_smb_basename(fsp->conn, fsp->fsp_name, psbuf) != 0) {
			DBG_ERR("vfs_stat_smb_basename failed with error %s\n",
				strerror(errno));
			return -1;
		}
		return 0;
	}
	if (SMB_VFS_FSTAT(fsp, psbuf) != 0)
	{
		DBG_ERR("SMB_VFS_FSTAT failed with error %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static NTSTATUS ixnas_fset_nt_acl(vfs_handle_struct *handle,
			 files_struct *fsp,
			 uint32_t security_info_sent,
			 const struct security_descriptor *psd)
{
	struct ixnas_config_data *config;
	NTSTATUS status;
	uid_t newUID = (uid_t)-1;
	gid_t newGID = (gid_t)-1;
	SMB_STRUCT_STAT sbuf;
	bool set_acl_as_root = false;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->zfs_acl_enabled) {
		return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	}

	if (ixnas_get_file_owner(fsp, &sbuf)) {
		return map_nt_error_from_unix(errno);
	}

	if (config->nfs4_params.do_chown) {
		status = unpack_nt_owners(fsp->conn, &newUID, &newGID,
					  security_info_sent, psd);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_INFO("unpack_nt_owners failed\n");
			return status;
		}
		if (((newUID != (uid_t)-1) && (sbuf.st_ex_uid != newUID)) ||
		    ((newGID != (gid_t)-1) && (sbuf.st_ex_gid != newGID))) {
			status = try_chown(fsp, newUID, newGID);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_INFO("chown %s, %u, %u failed. Error = "
					 "%s.\n", fsp_str_dbg(fsp),
					 (unsigned int)newUID,
					 (unsigned int)newGID,
					 nt_errstr(status));
				return status;
			}
			DBG_DEBUG("chown %s, %u, %u succeeded.\n",
				  fsp_str_dbg(fsp), (unsigned int)newUID,
				  (unsigned int)newGID);

			status = vfs_stat_fsp(fsp);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			set_acl_as_root = true;
		}
	}

	if (!(security_info_sent & SECINFO_DACL) || psd->dacl ==NULL) {
		DBG_ERR("No dacl found: security_info_sent = 0x%x\n",
			security_info_sent);
		return NT_STATUS_OK;
 	}
	/*
	 * nfs4_acls.c in some situations will become_root() before calling this.
	 */
	status = ixnas_set_nfs4_acl(handle, fsp, security_info_sent, psd, config,
				    set_acl_as_root);
	return status;
}

/*
 * Functions below are related to posix1e ACLs. Logic copied from vfs_zfsacl.
 */
static SMB_ACL_T ixnas_fail__sys_acl_get_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx)
{
	return (SMB_ACL_T)NULL;
}

static SMB_ACL_T ixnas_fail__sys_acl_get_fd(vfs_handle_struct *handle,
					     files_struct *fsp,
					     TALLOC_CTX *mem_ctx)
{
	return (SMB_ACL_T)NULL;
}

static int ixnas_fail__sys_acl_set_file(vfs_handle_struct *handle,
					 const struct smb_filename *smb_fname,
					 SMB_ACL_TYPE_T type,
					 SMB_ACL_T theacl)
{
	return -1;
}

static int ixnas_fail__sys_acl_set_fd(vfs_handle_struct *handle,
				       files_struct *fsp,
				       SMB_ACL_T theacl)
{
	return -1;
}

static int ixnas_fail__sys_acl_delete_def_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	return -1;
}

static int ixnas_fail__sys_acl_blob_get_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			TALLOC_CTX *mem_ctx,
			char **blob_description,
			DATA_BLOB *blob)
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

#if HAVE_LIBZFS
/********************************************************************
  Expose ZFS user/group quotas 
********************************************************************/
static int ixnas_get_quota(struct vfs_handle_struct *handle,
                                const struct smb_filename *smb_fname,
                                enum SMB_QUOTA_TYPE qtype,
                                unid_t id,
                                SMB_DISK_QUOTA *qt)

{
	int ret;
	char rp[PATH_MAX] = { 0 };
	struct ixnas_config_data *config = NULL;
	uint64_t hardlimit, usedspace;
	uid_t current_user = geteuid();
	hardlimit = usedspace = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (!config->zfs_quota_enabled) {
		DBG_DEBUG("Quotas disabled in ixnas configuration.\n");
		errno = ENOSYS;
		return -1;
	}

	if (realpath(smb_fname->base_name, rp) == NULL) {
		DBG_ERR("failed to get realpath for (%s)\n", smb_fname->base_name);
		return (-1);
	}
	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		//passing -1 to quotactl means that the current UID should be used. Do the same.
		if (id.uid == -1) {
			become_root();
			ret = smb_zfs_get_userspace_quota(config->libzp,
							  rp, current_user,
							  qtype, &hardlimit, &usedspace);
			unbecome_root();
		}
		else {
			become_root();
			ret = smb_zfs_get_userspace_quota(config->libzp,
							  rp, id.uid, qtype,
							  &hardlimit, &usedspace);
			unbecome_root();
		}
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		become_root();
		ret = smb_zfs_get_userspace_quota(config->libzp,
						  rp, id.gid, qtype,
						  &hardlimit, &usedspace);
		unbecome_root();
		break;
	default:
		DBG_ERR("Unrecognized quota type.\n");
		ret = -1;
		break;
	}

	ZERO_STRUCTP(qt);
	qt->bsize = 1024;
	qt->hardlimit = hardlimit;
	qt->softlimit = hardlimit;
	qt->curblocks = usedspace;
	qt->ihardlimit = hardlimit;
	qt->isoftlimit = hardlimit;
	qt->curinodes = usedspace;
	qt->qtype = qtype;
	qt->qflags = QUOTAS_DENY_DISK|QUOTAS_ENABLED;

        DBG_INFO("ixnas_get_quota: hardlimit: (%lu), usedspace: (%lu)\n", qt->hardlimit, qt->curblocks);

        return ret;
}

static int ixnas_set_quota(struct vfs_handle_struct *handle,
			enum SMB_QUOTA_TYPE qtype, unid_t id,
			SMB_DISK_QUOTA *qt)
{
	struct ixnas_config_data *config = NULL;
	int ret;
	bool is_disk_op = false;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (!config->zfs_quota_enabled) {
		DBG_DEBUG("Quotas disabled in ixnas configuration.\n");
		errno = ENOSYS;
		return -1;
	}

	is_disk_op = security_token_has_privilege(
			handle->conn->session_info->security_token,
			SEC_PRIV_DISK_OPERATOR);

	if (!is_disk_op) {
		errno = EPERM;
		return -1;
	}

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		DBG_INFO("ixnas_set_quota: quota type: (%d), id: (%d), h-limit: (%lu), s-limit: (%lu)\n", 
			qtype, id.uid, qt->hardlimit, qt->softlimit);
		become_root();
		ret = smb_zfs_set_userspace_quota(config->libzp,
						  handle->conn->connectpath,
						  id.uid, qtype, qt->hardlimit, qt->bsize);
		unbecome_root();
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		DBG_INFO("ixnas_set_quota: quota type: (%d), id: (%d), h-limit: (%lu), s-limit: (%lu)\n", 
			qtype, id.gid, qt->hardlimit, qt->softlimit);
		become_root();
		ret = smb_zfs_set_userspace_quota(config->libzp,
						  handle->conn->connectpath,
						  id.gid, qtype, qt->hardlimit, qt->bsize);
		unbecome_root();
		break;
	default:
		DBG_ERR("Received unknown quota type.\n");
		ret = -1;
		break;
	}

	return ret;
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

static int ixnas_chmod(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       mode_t mode)
{
	int result;
	acl_t zacl, new_acl;
	int trivial = 0;
	struct ixnas_config_data *config = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (!config->zfs_acl_chmod_enabled) {
		return SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
	}
	zacl = acl_get_file(smb_fname->base_name, ACL_TYPE_NFS4);
	if (zacl == NULL) {
		DBG_ERR("ixnas: acl_get_file() failed for %s: %s\n",
			smb_fname->base_name, strerror(errno));
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
			 smb_fname->base_name);
		acl_free(zacl);
		result = SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
		return result;
	}
	new_acl = calculate_chmod_acl(zacl, mode);
	if (new_acl == NULL) {
		DBG_ERR("Failed to generate new ACL for %s: %s\n",
			smb_fname->base_name, strerror(errno));
		goto failure;
	}
	result = acl_set_file(smb_fname->base_name, ACL_TYPE_NFS4, new_acl);
	if (result != 0) {
		DBG_ERR("Failed to set new ACL on %s: %s\n",
			smb_fname->base_name, strerror(errno));
		acl_free(new_acl);
		goto failure;
	}
	acl_free(zacl);
	acl_free(new_acl);
	return result;

failure:
	acl_free(zacl);
	return -1;
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
	zacl = acl_get_fd_np(fsp->fh->fd, ACL_TYPE_NFS4);
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
	result = acl_set_fd_np(fsp->fh->fd, new_acl, ACL_TYPE_NFS4);
	if (result != 0) {
		DBG_ERR("Failed to set new ACL on %s: %s\n",
			fsp_str_dbg(fsp), strerror(errno));
		acl_free(new_acl);
		goto failure;
	}
	acl_free(zacl);
	acl_free(new_acl);
	return result;
failure:
	acl_free(zacl);
	return -1;
}
/********************************************************************
 Create datasets for home directories. We fail if the path already
 exists  
********************************************************************/

static acl_t calculate_inherited_acl(acl_t parent_acl)
{
	acl_t tmp_acl;
	acl_t new_acl = NULL;
	int trivial = 0;
	acl_entry_t entry, dir_entry;
	acl_permset_t permset;
	acl_flagset_t flagset, dir_flag;
	int entry_id, d_entry_id;
	entry_id = d_entry_id = ACL_FIRST_ENTRY;
	if (acl_is_trivial_np(parent_acl, &trivial) != 0) {
		DBG_ERR("acl_is_trivial_np() failed\n");
		return NULL;
	}
	if (trivial) {
		DBG_ERR("ACL is trivial, not calculating inherited ACL\n");
		return parent_acl;
	}
	if ((new_acl = acl_init(ACL_MAX_ENTRIES)) == NULL) {
		DBG_ERR("Failed to initialize new ACL for connectpath.\n");
		return NULL;
	}
	tmp_acl = acl_dup(parent_acl);
	while (acl_get_entry(tmp_acl, entry_id, &entry) == 1) {
		entry_id = ACL_NEXT_ENTRY;
		if (acl_get_permset(entry, &permset)) {
			DBG_ERR("acl_get_permset() failed on connectpath.\n");
			goto failure;
		}
		if (acl_get_flagset_np(entry, &flagset)) {
			DBG_ERR("acl_get_flagset_np() failed\n");
			goto failure;
		} 
		/* Entry is not inheritable at all. Skip. */
		if ((*flagset & (ACL_ENTRY_DIRECTORY_INHERIT|ACL_ENTRY_FILE_INHERIT)) == 0) {
			continue;
		}
		/* Skip if the ACE has NO_PROPAGATE flag set and does not have INHERIT_ONLY flag. */
		if ((*flagset & ACL_ENTRY_NO_PROPAGATE_INHERIT) &&
		    (*flagset & ACL_ENTRY_INHERIT_ONLY) == 0) {
			continue;
		}

		/*
		 * Skip if the ACE has NO_PROPAGATE flag set and does not have DIRECTORY INHERIT.
		 * This is acceptible in this limited case of calculating inherited ACLs on
		 * child datasets. We know that the ACL generated here will not be applied to a file.
		 */
		if ((*flagset & ACL_ENTRY_NO_PROPAGATE_INHERIT) &&
		    (*flagset & ACL_ENTRY_DIRECTORY_INHERIT) == 0) {
			continue;
		}

		/*
		 * By the time we've gotten here, we're inheriting something somewhere.
		 * Strip inherit only from the flagset and set ACL_ENTRY_INHERITED.
		 * I have mixed feelings about seting INHERITED here since the ACL applies
		 * to a dataset, and the flag may allow permissions auto-inheritance from
		 * Windows clients.
		 */
		*flagset &= ~ACL_ENTRY_INHERIT_ONLY;
		*flagset |= ACL_ENTRY_INHERITED;

		if (acl_create_entry_np(&new_acl, &dir_entry, d_entry_id) == -1) {
			DBG_ERR("acl_create_entry() failed in connectpath.\n");
			goto failure;
		}
		if (acl_copy_entry(dir_entry, entry) == -1) {
			DBG_ERR("acl_copy_entry() failed in connectpath.\n");
			goto failure;
		}
		if (acl_get_flagset_np(dir_entry, &dir_flag) == -1) {
			DBG_ERR("acl_copy_entry() failed in connectpath.\n");
			goto failure;
		}
		if (*flagset & ACL_ENTRY_NO_PROPAGATE_INHERIT) {
			*dir_flag &= ~(ACL_ENTRY_DIRECTORY_INHERIT|ACL_ENTRY_FILE_INHERIT|ACL_ENTRY_NO_PROPAGATE_INHERIT);
		}
		/*
		 * If only FILE_INHERIT is set then turn on INHERIT_ONLY
		 * on directories. This is to prevent ACE from applying to directories.
		 */
		else if ((*flagset & ACL_ENTRY_DIRECTORY_INHERIT) == 0) {
			*dir_flag |= ACL_ENTRY_INHERIT_ONLY;
		}
	}
	acl_free(tmp_acl);
	return new_acl;
failure:
	acl_free(tmp_acl);
	acl_free(new_acl);
	return NULL;
}

static int create_zfs_autohomedir(vfs_handle_struct *handle, 
				  struct ixnas_config_data *config,
				  const char *user)
{
	bool ret = 0;
	int rv;
	char *parent = NULL;
	acl_t parent_acl, new_acl;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct smblibzfshandle *libzp = NULL;
	struct dataset_list *ds_list = NULL;
	struct zfs_dataset *ds = NULL;

	if (access(handle->conn->connectpath, F_OK) == 0) {
		DBG_INFO("Home directory already exists. Skipping dataset creation\n");
		TALLOC_FREE(tmp_ctx);
		return ret;
	}

	rv = get_smblibzfs_handle(tmp_ctx, &libzp);
	if (rv != 0) {
		DBG_ERR("Failed to obtain libzfshandle on connectpath: %s\n",
			strerror(errno));
		return -1;
	}
	rv = smb_zfs_create_dataset(tmp_ctx, libzp, handle->conn->connectpath,
				    config->homedir_quota, &ds_list, true);
	if (rv !=0) {
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	for (ds = ds_list->children; ds; ds = ds->next) {
		ret = parent_dirname(tmp_ctx, ds->mountpoint, &parent, NULL);
		if (!ret)  {
			DBG_ERR("Failed to get parent directory name for %s\n",
				ds->mountpoint);
			TALLOC_FREE(tmp_ctx);
			return -1;
		}
		parent_acl = acl_get_file(parent, ACL_TYPE_NFS4);
		if (parent_acl == NULL) {
			DBG_ERR("ixnas: acl_get_file() failed for %s: %s\n",
				parent, strerror(errno));
			TALLOC_FREE(tmp_ctx);
			return -1;
		}

		new_acl = calculate_inherited_acl(parent_acl);
		if (new_acl == NULL) {
			acl_free(parent_acl);
			TALLOC_FREE(tmp_ctx);
			return -1;
		}

		acl_free(parent_acl);
		rv = acl_set_file(ds->mountpoint, ACL_TYPE_NFS4, new_acl);
		if (rv < 0) {
			DBG_ERR("ixnas: acl_set_file() failed for %s: %s\n",
				handle->conn->connectpath, strerror(errno));
			acl_free(new_acl);
			TALLOC_FREE(tmp_ctx);
			return -1;
		}
		acl_free(new_acl);
		TALLOC_FREE(parent);
	}

	if (lp_parm_bool(SNUM(handle->conn), "ixnas", "chown_homedir", true)) {
		struct passwd *current_user = Get_Pwnam_alloc(tmp_ctx, user);
		if ( !current_user ) {
			DBG_ERR("Get_Pwnam_alloc failed for (%s).\n", user);
			TALLOC_FREE(tmp_ctx);
			return -1;
		}
		rv = chown(handle->conn->connectpath,
			   current_user->pw_uid,
			   current_user->pw_gid);
		if (rv < 0) {
			DBG_ERR("Failed to chown (%s) to (%u:%u)\n",
				handle->conn->connectpath, current_user->pw_uid, getegid() );
			ret = -1;
		}
	}
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/*
 * Fake the presence of a base quota. Check if user quota already exists.
 * If it exists, then we assume that the base quota has either already been set
 * or it has been modified by the admin. In either case, do nothing.
 */

static int set_base_user_quota(vfs_handle_struct *handle,
			       struct ixnas_config_data *config,
			       const char *user)
{
	int ret;
	uint64_t existing_quota, usedspace, base_quota;
	existing_quota = usedspace = 0;
	uid_t current_user = nametouid(user);
	base_quota = config->base_user_quota / 1024;

	if ( !current_user ) {
		DBG_ERR("Failed to convert (%s) to uid.\n", user); 
		return -1;
	}

	if (smb_zfs_get_userspace_quota(config->libzp,
			      handle->conn->connectpath, 
			      current_user,
			      SMB_USER_QUOTA_TYPE,
			      &existing_quota,
			      &usedspace) < 0) {
		DBG_ERR("Failed to get base quota uid: (%u), path (%s)\n",
			current_user, handle->conn->connectpath );
		return -1;
	}

	DBG_INFO("set_base_user_quote: uid (%u), quota (%lu)\n",
		 current_user, base_quota);

	if ( !existing_quota ) {
		ret = smb_zfs_set_userspace_quota(config->libzp,
					handle->conn->connectpath,
					current_user,
					SMB_USER_QUOTA_TYPE,
					base_quota, 1024);
		if (!ret) {
			DBG_ERR("Failed to set base quota uid: (%u), path (%s), value (%lu)\n",
				current_user, handle->conn->connectpath, base_quota );
		}
	}
	return ret;
}
#endif

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

static int ixnas_ntimes(vfs_handle_struct *handle,
                                 const struct smb_filename *smb_fname,
                                 struct smb_file_time *ft)
{
	int result = -1;
	struct ixnas_config_data *config = NULL;

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	if (config->dosattrib_xattr) {
		return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
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
		struct timespec ts[2];
		if (is_omit_timespec(&ft->atime)) {
			ft->atime= smb_fname->st.st_ex_atime;
		}
		if (is_omit_timespec(&ft->mtime)) {
			ft->mtime = smb_fname->st.st_ex_mtime;
		}
		/* mtime and atime are unchanged */
		if ((timespec_compare(&ft->atime,
				      &smb_fname->st.st_ex_atime) == 0) &&
		    (timespec_compare(&ft->mtime,
				      &smb_fname->st.st_ex_mtime) == 0)) {
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
		result = utimensat(AT_FDCWD, smb_fname->base_name, ts, 0);
		if (timespec_compare(&ft->mtime, &ft->create_time) != 0) {
			ts[1] = ft->mtime;
			result = utimensat(AT_FDCWD, smb_fname->base_name, ts, 0);
		}
	} else {
		result = utimensat(AT_FDCWD, smb_fname->base_name, NULL, 0);
	}
 out:
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
		config->zfs_space_enabled = false;
		config->zfs_quota_enabled = false;
		config->props->casesens = SMBZFS_SENSITIVE;
		return true;
	}
	config->props = config->dsl->root->properties;

	base_quota_str = lp_parm_const_string(SNUM(handle->conn),
					      "ixnas", "base_user_quota", NULL);
	if (base_quota_str != NULL) {
		config->base_user_quota = conv_str_size(base_quota_str);
        }

	if (config->base_user_quota) {
		set_base_user_quota(handle, config, user);
	}
	if (config->props->casesens == SMBZFS_INSENSITIVE) {
		DBG_INFO("ixnas: case insensitive dataset detected, "
			 "automatically adjusting case sensitivity settings.\n");
		lp_do_parameter(SNUM(handle->conn),
				"case sensitive", "yes");
		handle->conn->case_sensitive = True;
	}
	config->zfs_space_enabled = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfs_space_enabled", true);

	config->zfs_quota_enabled = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfs_quota_enabled", true);

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
	if (config->zfs_acl_enabled) {
		config->zfs_acl_map_modify = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfsacl_map_modify", true);

		config->zfs_acl_ignore_empty_mode = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfsacl_ignore_empty_mode", true);

		config->zfs_acl_sortaces = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfsacl_sortaces", false);
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
	/*
	 * Check if we need to automatically create a new ZFS dataset
	 * before falling through to SMB_VFS_NEXT_CONNECT
	 */
	config->zfs_auto_homedir = lp_parm_bool(SNUM(handle->conn), 
			"ixnas", "zfs_auto_homedir", false);
	config->homedir_quota = lp_parm_const_string(SNUM(handle->conn),
			"ixnas", "homedir_quota", NULL);

	if (config->zfs_auto_homedir) {
		ret = create_zfs_autohomedir(handle, config, user);
		if (ret < 0) {
			DBG_ERR("Failed to automatically generate connectpath.\n");
			return -1;
		}
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
	.fs_capabilities_fn = ixnas_fs_capabilities,
	.connect_fn = ixnas_connect,
	.create_file_fn = ixnas_create_file,
	/* dosmode_enabled */
	.get_dos_attributes_fn = ixnas_get_dos_attributes,
	.fget_dos_attributes_fn = ixnas_fget_dos_attributes,
	.set_dos_attributes_fn = ixnas_set_dos_attributes,
	.fset_dos_attributes_fn = ixnas_fset_dos_attributes,
	/* zfs_acl_enabled = true */
	.chmod_fn = ixnas_chmod,
	.fchmod_fn = ixnas_fchmod,
	.ntimes_fn = ixnas_ntimes,
	.renameat_fn = ixnas_renameat,
	.fget_nt_acl_fn = ixnas_fget_nt_acl,
	.get_nt_acl_fn = ixnas_get_nt_acl,
	.fset_nt_acl_fn = ixnas_fset_nt_acl,
	.sys_acl_get_file_fn = ixnas_fail__sys_acl_get_file,
	.sys_acl_get_fd_fn = ixnas_fail__sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = ixnas_fail__sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = ixnas_fail__sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = ixnas_fail__sys_acl_set_file,
	.sys_acl_set_fd_fn = ixnas_fail__sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = ixnas_fail__sys_acl_delete_def_file,
	
#if HAVE_LIBZFS
	.get_quota_fn = ixnas_get_quota,
	.set_quota_fn = ixnas_set_quota,
	.disk_free_fn = ixnas_disk_free
#endif
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
