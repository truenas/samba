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
#include "auth.h"
#include "system/filesys.h"
#include "passdb/lookup_sid.h"
#include "nfs4_acls.h"
#include "zfsacl.h"
#include "smbd/truenas_mdcache.h"

static int vfs_ixnas_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_ixnas_debug_level

struct ixnas_config_data {
	struct smbacl4_vfs_params nfs4_params;
	bool dosattrib_xattr;
	bool dosattrib_create_time;
	bool advertise_enforced_acl;
};

enum ixnas_dacl_type {
	IXNAS_NULL_DACL,
	IXNAS_EMPTY_DACL,
	IXNAS_NORMAL_DACL
};

#define ACL_XATTR "system.posix_acl_access"

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

/* The create time in fsp's DOSATTRIB, UTIME_OMIT if there is none */
static bool ixnas_dosattrib_read_btime(struct files_struct *fsp,
				       struct timespec *btime)
{
	uint8_t buf[sizeof(fstring)];
	struct smb_filename tmp = *fsp->fsp_name;
	uint32_t attr = 0;
	ssize_t len;
	NTSTATUS status;

	*btime = (struct timespec) { .tv_nsec = UTIME_OMIT };

	len = SMB_VFS_FGETXATTR(fsp, SAMBA_XATTR_DOS_ATTRIB, buf, sizeof(buf));
	if ((len == -1) && ((errno == EPERM) || (errno == EACCES))) {
		become_root();
		len = SMB_VFS_FGETXATTR(fsp, SAMBA_XATTR_DOS_ATTRIB,
					buf, sizeof(buf));
		unbecome_root();
	}
	if (len == -1) {
		/* .zfs and .zfs/snapshot have no xattrs */
		return (errno == ENOATTR) || (errno == ENOTSUP);
	}

	tmp.st.st_ex_btime = *btime;
	status = parse_dos_attribute_blob(&tmp,
					  data_blob_const(buf, len),
					  &attr);
	if (NT_STATUS_IS_OK(status)) {
		*btime = tmp.st.st_ex_btime;
	}
	return true;
}

/*
 * Before Samba stored the create time natively, a create time that a
 * client set went into DOSATTRIB only, so DOSATTRIB's wins. The inode's
 * slot keeps it. A listed entry without an fd needs the slot.
 */
static NTSTATUS ixnas_dosattrib_btime(struct files_struct *fsp)
{
	SMB_STRUCT_STAT *st = &fsp->fsp_name->st;
	struct mdcache_inode *slot = NULL;
	struct timespec btime;

	if (fsp_get_pathref_fd(fsp) == -1) {
		slot = mdcache_inode_peek(&fsp->file_id,
					  st->st_ex_change_cookie);
		if ((slot == NULL) || !(slot->flags & MDCACHE_HAVE_BTIME)) {
			return NT_STATUS_RETRY;
		}
	} else {
		slot = mdcache_inode_fetch(fsp);
	}

	if ((slot != NULL) && (slot->flags & MDCACHE_HAVE_BTIME)) {
		btime = (struct timespec) {
			.tv_sec = slot->btime_sec,
			.tv_nsec = slot->btime_nsec,
		};
	} else {
		if (!ixnas_dosattrib_read_btime(fsp, &btime)) {
			return map_nt_error_from_unix(errno);
		}
		if (slot != NULL) {
			slot->btime_sec = btime.tv_sec;
			slot->btime_nsec = btime.tv_nsec;
			slot->flags |= MDCACHE_HAVE_BTIME;
		}
	}

	if (btime.tv_nsec != UTIME_OMIT) {
		update_stat_ex_create_time(st, btime);
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
		return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle, fsp, dosmode);
	}

	*dosmode = dos_mode_from_zfsflags(&fsp->fsp_name->st);
	if (!config->dosattrib_create_time) {
		return NT_STATUS_OK;
	}
	return ixnas_dosattrib_btime(fsp);
}

/*
 * A create time set now is native. A DOSATTRIB create time from before
 * would still win in ixnas_dosattrib_btime(), so DOSATTRIB goes, unless
 * the inode's slot shows that it has none.
 */
static int ixnas_fntimes(struct vfs_handle_struct *handle,
			 struct files_struct *fsp,
			 struct smb_file_time *ft)
{
	struct ixnas_config_data *config = NULL;
	struct timespec btime = fsp->fsp_name->st.st_ex_btime;
	uint64_t cookie = fsp->fsp_name->st.st_ex_change_cookie;
	struct mdcache_inode *slot = NULL;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return -1);

	ret = SMB_VFS_NEXT_FNTIMES(handle, fsp, ft);
	if ((ret != 0) || config->dosattrib_xattr ||
	    !config->dosattrib_create_time || (ft == NULL) ||
	    is_omit_timespec(&ft->create_time) ||
	    timespec_equal(&ft->create_time, &btime)) {
		return ret;
	}

	slot = mdcache_inode_peek(&fsp->file_id, cookie);
	if ((slot != NULL) && (slot->flags & MDCACHE_HAVE_BTIME) &&
	    (slot->btime_nsec == UTIME_OMIT)) {
		return 0;
	}

	ret = SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, SAMBA_XATTR_DOS_ATTRIB);
	if ((ret == -1) && ((errno == EPERM) || (errno == EACCES))) {
		/* Samba allowed the create time, which DOSATTRIB holds */
		become_root();
		ret = SMB_VFS_NEXT_FREMOVEXATTR(handle,
						fsp,
						SAMBA_XATTR_DOS_ATTRIB);
		unbecome_root();
	}
	if ((ret == -1) && (errno != ENOATTR)) {
		DBG_WARNING("%s: removing DOSATTRIB failed: %s\n",
			    fsp_str_dbg(fsp), strerror(errno));
	}
	return 0;
}

static zfsacl_t fsp_get_zfsacl(files_struct *fsp)
{
	int fd;
	const char *proc_fd_path = NULL;
	struct sys_proc_fd_path_buf buf;

	if (fsp_has_read_access(fsp)) {
		return zfsacl_get_fd(fsp_get_pathref_fd(fsp), ZFSACL_BRAND_NFSV4);
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
		return false;
	}

	return zfsacl_set_file(proc_fd_path, zfsacl);
}

/*
 * True if the ZFS ACL is a "fully open" everyone@ ACL: every entry is an
 * everyone@ ALLOW entry (no DENY, no owner@/group@/named trustee) and at least
 * one of them grants the full set of rights on the object itself (not
 * inherit-only). Such an ACL imposes no real access control -- semantically a
 * NULL DACL that ixnas materialised as everyone@ -- so it is the one state in
 * which overriding ZFS's refusal to honor everyone@ WRITE_ACL/WRITE_OWNER is
 * safe. Tolerates the hidden everyone@:empty entry ixnas adds for inheritance.
 *
 * Distinct from ixnas_zfsacl_get_dacl_type()'s strict IXNAS_NULL_DACL (single
 * entry, no inheritance flags): this also matches the multi-entry, inheritable
 * everyone@:FULL form. Observed with Avid MediaComposer, which applies an
 * Everyone:Full DACL (dropping the inherited named-user ACE) to its content
 * directories and to files created inside them via an SMB2 create-context
 * security descriptor -- the create-time apply is what fails without the retry.
 */
static bool is_open_everyone(zfsacl_t zfsacl)
{
	bool ok;
	uint cnt, i;
	bool saw_full = false;

	ok = zfsacl_get_acecnt(zfsacl, &cnt);
	if (!ok || (cnt == 0)) {
		return false;
	}

	for (i = 0; i < cnt; i++) {
		zfsacl_entry_t ae = NULL;
		zfsace_permset_t perms = 0;
		zfsace_flagset_t flags = 0;
		zfsace_who_t who_type = ZFSACL_UNDEFINED_TAG;
		zfsace_id_t who_id = ZFSACL_UNDEFINED_ID;
		zfsace_entry_type_t entry_type = 0;

		ok = zfsacl_get_aclentry(zfsacl, i, &ae);
		if (!ok) {
			return false;
		}

		ok = zfsace_get_who(ae, &who_type, &who_id);
		if (!ok) {
			return false;
		}
		if ((who_type != ZFSACL_EVERYONE) ||
		    (who_id != ZFSACL_UNDEFINED_ID)) {
			return false;
		}

		ok = zfsace_get_entry_type(ae, &entry_type);
		if (!ok || (entry_type != ZFSACL_ENTRY_TYPE_ALLOW)) {
			return false;
		}

		ok = zfsace_get_permset(ae, &perms);
		if (!ok) {
			return false;
		}

		ok = zfsace_get_flagset(ae, &flags);
		if (!ok) {
			return false;
		}

		if ((perms == ZFSACE_FULL_SET) &&
		    ((flags & ZFSACE_INHERIT_ONLY) == 0)) {
			saw_full = true;
		}
	}

	return saw_full;
}

/*
 * True if the ACL grants owner@ full control on the object itself: some owner@
 * (ZFSACL_USER_OBJ) ALLOW entry with the full permset, not inherit-only. ZFS
 * strips WRITE_ACL from owner@ and, on a non-trivial ACL, lets only CAP_FOWNER
 * write it, so the file owner cannot rewrite such an ACL without the privileged
 * retry below. Coexisting group@/everyone@/named entries are fine.
 */
static bool acl_has_owner_full(zfsacl_t zfsacl)
{
	bool ok;
	uint cnt, i;

	ok = zfsacl_get_acecnt(zfsacl, &cnt);
	if (!ok) {
		return false;
	}

	for (i = 0; i < cnt; i++) {
		zfsacl_entry_t ae = NULL;
		zfsace_permset_t perms = 0;
		zfsace_flagset_t flags = 0;
		zfsace_who_t who_type = ZFSACL_UNDEFINED_TAG;
		zfsace_id_t who_id = ZFSACL_UNDEFINED_ID;
		zfsace_entry_type_t entry_type = 0;

		ok = zfsacl_get_aclentry(zfsacl, i, &ae);
		if (!ok) {
			return false;
		}
		ok = zfsace_get_who(ae, &who_type, &who_id);
		if (!ok) {
			return false;
		}
		if (who_type != ZFSACL_USER_OBJ) {
			continue;
		}
		ok = zfsace_get_entry_type(ae, &entry_type);
		if (!ok || (entry_type != ZFSACL_ENTRY_TYPE_ALLOW)) {
			continue;
		}
		ok = zfsace_get_permset(ae, &perms);
		if (!ok) {
			return false;
		}
		ok = zfsace_get_flagset(ae, &flags);
		if (!ok) {
			return false;
		}
		if ((perms == ZFSACE_FULL_SET) &&
		    ((flags & ZFSACE_INHERIT_ONLY) == 0)) {
			return true;
		}
	}

	return false;
}

/* True if the connecting SMB user owns this file. */
static bool fsp_caller_is_owner(files_struct *fsp)
{
	if (!VALID_STAT(fsp->fsp_name->st)) {
		if (!NT_STATUS_IS_OK(vfs_stat_fsp(fsp))) {
			return false;
		}
	}
	return fsp->conn->session_info->unix_token->uid ==
	       fsp->fsp_name->st.st_ex_uid;
}

/*
 * Set the ZFS ACL, falling back to a privileged retry when SMB says the caller
 * may manage the ACL but ZFS refuses. ZFS strips WRITE_ACL/WRITE_OWNER from
 * owner@/group@/everyone@ ALLOW ACEs and, on a non-trivial ACL, grants WRITE_ACL
 * only to CAP_FOWNER (zfs_acl.c uses secpolicy_vnode_chown there, not the
 * owner-allowed secpolicy_vnode_setdac) -- so neither a fully-open everyone@
 * object nor the owner of a normal file can rewrite the ACL, and fsp_set_zfsacl
 * gets EACCES/EPERM. When @escalate is set (ixnas:zfs_acl_advertise_enforced, on
 * by default) complete the set under become_root() (CAP_FOWNER) iff the on-disk
 * ACL is a fully-open everyone@ ACL (no protection to bypass) or grants owner@
 * full control and the connecting user owns the file. Only the set is
 * privileged; the on-disk read is not. Any owner change is done separately by
 * smb_set_nt_acl_nfs4() and stays ZFS-enforced.
 */
static bool fsp_set_zfsacl_escalate(files_struct *fsp, zfsacl_t zfsacl,
				    bool escalate)
{
	int saved_errno, retry_errno;
	zfsacl_t current = NULL;
	bool may_escalate = false;
	bool ok;

	if (fsp_set_zfsacl(fsp, zfsacl)) {
		return true;
	}
	if (!escalate || ((errno != EACCES) && (errno != EPERM))) {
		return false;
	}
	saved_errno = errno;

	/*
	 * Reading the ACL needs no privilege (owner and everyone@ both hold
	 * READ_ACL); read it as the user and fail closed unless the caller may
	 * manage it: a fully-open everyone@ ACL, or an owner@ full-control ACL on
	 * a file the connecting user owns.
	 */
	current = fsp_get_zfsacl(fsp);
	if (current != NULL) {
		may_escalate = is_open_everyone(current) ||
			(acl_has_owner_full(current) &&
			 fsp_caller_is_owner(fsp));
		zfsacl_free(&current);
	}
	if (!may_escalate) {
		errno = saved_errno;
		return false;
	}

	/* Only the set needs root (CAP_FOWNER); the read above did not. */
	become_root();
	ok = fsp_set_zfsacl(fsp, zfsacl);
	retry_errno = ok ? 0 : errno;
	unbecome_root();

	errno = retry_errno;
	return ok;
}

/* Nested datasets and mounts can have a different ACL type than the share */
static enum acl_brand stat_acl_brand(const SMB_STRUCT_STAT *st)
{
	if ((st->st_ex_flags & ST_EX_ATTR_ACLTYPE) == 0) {
		return TRUENAS_ACL_BRAND_UNKNOWN;
	}
	if (st->st_ex_flags & ST_EX_ATTR_NFSV4ACL) {
		return TRUENAS_ACL_BRAND_NFS4;
	}
	if (st->st_ex_flags & ST_EX_ATTR_POSIXACL) {
		return TRUENAS_ACL_BRAND_POSIX;
	}
	return TRUENAS_ACL_BRAND_NONE;
}

static int fsp_get_acl_brand(files_struct *fsp)
{
	ssize_t rv;
	enum acl_brand brand = stat_acl_brand(&fsp->fsp_name->st);

	if (brand != TRUENAS_ACL_BRAND_UNKNOWN) {
		return brand;
	}

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

static bool fsp_acl_is_posix(files_struct *fsp)
{
	const files_struct *mfsp = metadata_fsp(fsp);
	enum acl_brand brand = stat_acl_brand(&mfsp->fsp_name->st);

	if (brand == TRUENAS_ACL_BRAND_UNKNOWN) {
		brand = fsp->conn->aclbrand;
	}
	return brand == TRUENAS_ACL_BRAND_POSIX;
}

static bool fsp_acl_is_nfs4(const files_struct *fsp)
{
	enum acl_brand brand = stat_acl_brand(&fsp->fsp_name->st);

	if (brand == TRUENAS_ACL_BRAND_UNKNOWN) {
		brand = fsp->conn->aclbrand;
	}
	return brand == TRUENAS_ACL_BRAND_NFS4;
}

static int path_get_aclbrand(const char *path)
{
	ssize_t rv;
	SMB_STRUCT_STAT st;

	if (sys_stat(path, &st, false) == 0) {
		enum acl_brand brand = stat_acl_brand(&st);

		if (brand != TRUENAS_ACL_BRAND_UNKNOWN) {
			return brand;
		}
	}

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
static bool zfsentry2smbace(zfsacl_entry_t ae, SMB_ACE4PROP_T *aceprop,
			    bool advertise_enforced)
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

	/*
	 * Advertisement-only: ZFS will not honor WRITE_ACL/WRITE_OWNER granted
	 * through group@ (a group member cannot rewrite the ACL via group@), so do
	 * not report those bits on group@. owner@ and everyone@ keep them: the file
	 * owner may manage its ACL and a fully-open everyone@ ACL has no protection,
	 * and fsp_set_zfsacl_escalate() completes those sets under privilege. This
	 * drops bits only from the SD we present, never from what we store (the set
	 * path is untouched). Named user/group entries (flags == 0) are untouched.
	 * Gated by ixnas:zfs_acl_advertise_enforced.
	 */
	if (advertise_enforced &&
	    (aceprop->flags & SMB_ACE4_ID_SPECIAL) &&
	    (aceprop->who.special_id == SMB_ACE4_WHO_GROUP) &&
	    (aceprop->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE)) {
		aceprop->aceMask &= ~(SMB_ACE4_WRITE_ACL | SMB_ACE4_WRITE_OWNER);
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

		ok = zfsentry2smbace(ae, &aceprop, config->advertise_enforced_acl);
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

static bool fsp_acl_trivial(files_struct *fsp)
{
	const SMB_STRUCT_STAT *st = &fsp->fsp_name->st;
	uint64_t epoch = mdcache_epoch(fsp->conn);

	if (!ST_EX_ACL_FROM_MODE(st)) {
		return false;
	}
	if ((epoch == 0) || (st->st_ex_epoch != epoch)) {
		if (!NT_STATUS_IS_OK(vfs_stat_fsp(fsp))) {
			return false;
		}
	}
	return ST_EX_ACL_FROM_MODE(st);
}

static bool zfsacl_add_special(zfsacl_t zfsacl,
			       zfsace_entry_type_t type,
			       zfsace_who_t who,
			       zfsace_permset_t perms)
{
	zfsacl_entry_t entry = NULL;

	return zfsacl_create_aclentry(zfsacl, ZFSACL_APPEND_ENTRY, &entry) &&
	       zfsace_set_permset(entry, perms) &&
	       zfsace_set_flagset(entry, 0) &&
	       zfsace_set_entry_type(entry, type) &&
	       zfsace_set_who(entry, who, ZFSACL_UNDEFINED_ID);
}

/* As acl_trivial_access_masks() and zfs_acl_chmod() in ZFS */
static zfsacl_t zfsacl_from_trivial_mode(mode_t mode)
{
	zfsace_permset_t r = ZFSACE_READ_DATA;
	zfsace_permset_t w = ZFSACE_WRITE_DATA | ZFSACE_APPEND_DATA;
	zfsace_permset_t x = ZFSACE_EXECUTE;
	zfsace_permset_t base = ZFSACE_READ_ACL | ZFSACE_READ_ATTRIBUTES |
				ZFSACE_READ_NAMED_ATTRS | ZFSACE_SYNCHRONIZE;
	zfsace_permset_t allow0 = 0, deny1 = 0, deny2 = 0;
	zfsace_permset_t owner, group, everyone;
	zfsacl_t zfsacl = NULL;
	bool ok;

	if (S_ISDIR(mode)) {
		w |= ZFSACE_DELETE_CHILD;
	}

	if (!(mode & S_IRUSR) && (mode & (S_IRGRP|S_IROTH))) {
		deny1 |= r;
	}
	if (!(mode & S_IWUSR) && (mode & (S_IWGRP|S_IWOTH))) {
		deny1 |= w;
	}
	if (!(mode & S_IXUSR) && (mode & (S_IXGRP|S_IXOTH))) {
		deny1 |= x;
	}

	if (!(mode & S_IRGRP) && (mode & S_IROTH)) {
		deny2 |= r;
	}
	if (!(mode & S_IWGRP) && (mode & S_IWOTH)) {
		deny2 |= w;
	}
	if (!(mode & S_IXGRP) && (mode & S_IXOTH)) {
		deny2 |= x;
	}

	if ((mode & S_IRUSR) && !(mode & S_IRGRP) && (mode & S_IROTH)) {
		allow0 |= r;
	}
	if ((mode & S_IWUSR) && !(mode & S_IWGRP) && (mode & S_IWOTH)) {
		allow0 |= w;
	}
	if ((mode & S_IXUSR) && !(mode & S_IXGRP) && (mode & S_IXOTH)) {
		allow0 |= x;
	}

	owner = base | ZFSACE_WRITE_ATTRIBUTES | ZFSACE_WRITE_OWNER |
		ZFSACE_WRITE_ACL | ZFSACE_WRITE_NAMED_ATTRS |
		((mode & S_IRUSR) ? r : 0) | ((mode & S_IWUSR) ? w : 0) |
		((mode & S_IXUSR) ? x : 0);
	group = base | ((mode & S_IRGRP) ? r : 0) |
		((mode & S_IWGRP) ? w : 0) | ((mode & S_IXGRP) ? x : 0);
	everyone = base | ((mode & S_IROTH) ? r : 0) |
		   ((mode & S_IWOTH) ? w : 0) | ((mode & S_IXOTH) ? x : 0);

	zfsacl = zfsacl_init(6, ZFSACL_BRAND_NFSV4);
	if (zfsacl == NULL) {
		return NULL;
	}
	ok = ((allow0 == 0) ||
	      zfsacl_add_special(zfsacl, ZFSACL_ENTRY_TYPE_ALLOW,
				 ZFSACL_USER_OBJ, allow0)) &&
	     ((deny1 == 0) ||
	      zfsacl_add_special(zfsacl, ZFSACL_ENTRY_TYPE_DENY,
				 ZFSACL_USER_OBJ, deny1)) &&
	     ((deny2 == 0) ||
	      zfsacl_add_special(zfsacl, ZFSACL_ENTRY_TYPE_DENY,
				 ZFSACL_GROUP_OBJ, deny2)) &&
	     zfsacl_add_special(zfsacl, ZFSACL_ENTRY_TYPE_ALLOW,
				ZFSACL_USER_OBJ, owner) &&
	     zfsacl_add_special(zfsacl, ZFSACL_ENTRY_TYPE_ALLOW,
				ZFSACL_GROUP_OBJ, group) &&
	     zfsacl_add_special(zfsacl, ZFSACL_ENTRY_TYPE_ALLOW,
				ZFSACL_EVERYONE, everyone);
	if (!ok) {
		zfsacl_free(&zfsacl);
		return NULL;
	}
	return zfsacl;
}

static NTSTATUS ixnas_fget_nt_acl_uncached(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    uint32_t security_info,
					    TALLOC_CTX *mem_ctx,
					    struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl = NULL;
	TALLOC_CTX *frame = NULL;
	struct files_struct *to_check = NULL;
	NTSTATUS status;
	zfsacl_t zfsacl = NULL;
	enum acl_brand brand;
	bool ok;
	enum ixnas_dacl_type dtype = IXNAS_NORMAL_DACL;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	to_check = metadata_fsp(fsp);
	brand = stat_acl_brand(&to_check->fsp_name->st);
	if ((brand == TRUENAS_ACL_BRAND_NFS4) && fsp_acl_trivial(to_check)) {
		zfsacl = zfsacl_from_trivial_mode(
			to_check->fsp_name->st.st_ex_mode);
		if (zfsacl == NULL) {
			return map_nt_error_from_unix(errno);
		}
	} else if ((brand == TRUENAS_ACL_BRAND_NFS4) ||
		   (brand == TRUENAS_ACL_BRAND_UNKNOWN)) {
		zfsacl = fsp_get_zfsacl(to_check);
		if (zfsacl == NULL) {
			int err = errno;

			if ((err != EINVAL) && (err != EOPNOTSUPP)) {
				return map_nt_error_from_unix(err);
			}
			if (brand == TRUENAS_ACL_BRAND_UNKNOWN) {
				brand = fsp_get_acl_brand(to_check);
			} else if (err == EOPNOTSUPP) {
				/* The .zfs directories have no ACL */
				brand = TRUENAS_ACL_BRAND_NONE;
			}
			if (brand == TRUENAS_ACL_BRAND_NFS4) {
				return map_nt_error_from_unix(err);
			}
		}
	}
	switch (brand) {
	case TRUENAS_ACL_BRAND_NFS4:
		break;
	case TRUENAS_ACL_BRAND_POSIX:
	case TRUENAS_ACL_BRAND_UNKNOWN:
		status = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
						  mem_ctx, ppdesc);
		if (NT_STATUS_IS_OK(status)) {
			(*ppdesc)->type |= SEC_DESC_DACL_PROTECTED;
		}
		return status;
	case TRUENAS_ACL_BRAND_NONE:
		zfsacl = fsp_get_zfsacl_from_mode(to_check);
		if (zfsacl == NULL) {
			return map_nt_error_from_unix(errno);
		}
		break;
	default:
		smb_panic("Unknown ACL brand");
	}
	dump_acl_info(zfsacl);

	ok = ixnas_zfsacl_get_dacl_type(zfsacl, &dtype);
	if (!ok) {
		zfsacl_free(&zfsacl);
		return map_nt_error_from_unix(errno);
	}
	switch (dtype) {
	case IXNAS_NULL_DACL:
	case IXNAS_EMPTY_DACL:
		zfsacl_free(&zfsacl);
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

static NTSTATUS ixnas_fget_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32_t security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc)
{
	uint64_t cookie, variant;
	NTSTATUS status;

	if (fsp_acl_is_posix(fsp)) {
		return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
						mem_ctx, ppdesc);
	}

	variant = mdcache_fsp_variant(fsp, &cookie);
	if ((variant != 0) &&
	    mdcache_sd_get(variant, security_info, mem_ctx, ppdesc)) {
		return NT_STATUS_OK;
	}

	status = ixnas_fget_nt_acl_uncached(handle, fsp, security_info,
					    mem_ctx, ppdesc);
	if ((variant != 0) && NT_STATUS_IS_OK(status)) {
		mdcache_sd_put(fsp, cookie, variant, security_info, *ppdesc);
	}
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
	bool ok = false;
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
	if (!fsp_set_zfsacl_escalate(fsp, zfsacl,
					 config->advertise_enforced_acl)) {
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
	zfsacl_entry_t placeholder_entry = NULL;
	bool ok;
	zfsace_permset_t perms;
	struct ixnas_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct ixnas_config_data,
				return NT_STATUS_INTERNAL_ERROR);

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
	if (!fsp_set_zfsacl_escalate(fsp, zfsacl,
					 config->advertise_enforced_acl)) {
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

	if (fsp_acl_is_posix(fsp)) {
		return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent,
						psd);
	}

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
static SMB_ACL_T ixnas_sys_acl_get_fd(vfs_handle_struct *handle,
				      files_struct *fsp,
				      SMB_ACL_TYPE_T type,
				      TALLOC_CTX *mem_ctx)
{
	if (fsp_acl_is_posix(fsp)) {
		return SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, type, mem_ctx);
	}
	return (SMB_ACL_T)NULL;
}

static int ixnas_sys_acl_set_fd(vfs_handle_struct *handle,
				files_struct *fsp,
				SMB_ACL_TYPE_T type,
				SMB_ACL_T theacl)
{
	if (fsp_acl_is_posix(fsp)) {
		return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, type, theacl);
	}
	return -1;
}

static int ixnas_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp,
				     TALLOC_CTX *mem_ctx,
				     char **blob_description,
				     DATA_BLOB *blob)
{
	if (fsp_acl_is_posix(fsp)) {
		return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx,
							blob_description,
							blob);
	}
	return -1;
}

/* nfs4_acl_*stat() retry with CAP_DAC_OVERRIDE, which only NFSv4 permits */
static int ixnas_stat(struct vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	if (handle->conn->aclbrand == TRUENAS_ACL_BRAND_NFS4) {
		return nfs4_acl_stat(handle, smb_fname);
	}
	return SMB_VFS_NEXT_STAT(handle, smb_fname);
}

static int ixnas_lstat(struct vfs_handle_struct *handle,
		       struct smb_filename *smb_fname)
{
	if (handle->conn->aclbrand == TRUENAS_ACL_BRAND_NFS4) {
		return nfs4_acl_lstat(handle, smb_fname);
	}
	return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
}

static int ixnas_fstat(struct vfs_handle_struct *handle,
		       struct files_struct *fsp,
		       SMB_STRUCT_STAT *sbuf)
{
	if (fsp_acl_is_nfs4(fsp)) {
		return nfs4_acl_fstat(handle, fsp, sbuf);
	}
	return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
}

static int ixnas_fstatat(struct vfs_handle_struct *handle,
			 const struct files_struct *dirfsp,
			 const struct smb_filename *smb_fname,
			 SMB_STRUCT_STAT *sbuf,
			 int flags)
{
	if (fsp_acl_is_nfs4(dirfsp)) {
		return nfs4_acl_fstatat(handle, dirfsp, smb_fname, sbuf,
					flags);
	}
	return SMB_VFS_NEXT_FSTATAT(handle, dirfsp, smb_fname, sbuf, flags);
}

static int mode_to_acl(zfsacl_t *new_acl, mode_t mode)
{
	int res = 0;
	bool ok;
	mode_t shifted_mode, other_mode, deny_mode;
	zfsacl_entry_t entry = NULL;
	zfsace_permset_t permset;
	shifted_mode = deny_mode = 0;
	other_mode = mode & S_IRWXO;

	/*
	 * convert posix mode bits to ACLs
	 */

	// we may have to set a deny ACE because the mode of OTHER
	// grants more permissions that user e.g. 0o557
	if (((mode & S_IRWXU) >> 6) < (mode & S_IRWXO)) {
		permset = 0;
		// shift mode over so that we can compare user bits with other
		shifted_mode = (mode & S_IRWXU) >> 6;
		deny_mode = (other_mode & ~shifted_mode) << 6;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &entry);
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
		if (!zfsace_set_permset(entry, permset))
			return -1;

		if (!zfsace_set_flagset(entry, 0))
			return -1;

		if (!zfsace_set_entry_type(entry, ZFSACL_ENTRY_TYPE_DENY))
			return -1;

		if (!zfsace_set_who(entry, ZFSACL_USER_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;
	}

	// Check if we need to add a deny entry based on group bits
	if (((mode & S_IRWXG) >> 3) < (mode & S_IRWXO)) {
		permset = 0;
		// shift mode over so that we can compare group bits with other with other
		shifted_mode = (mode & S_IRWXG) >> 3;
		deny_mode = (other_mode & ~shifted_mode) << 3;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &entry);
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

		if (!zfsace_set_permset(entry, permset))
			return -1;

		if (!zfsace_set_flagset(entry, 0))
			return -1;

		if (!zfsace_set_entry_type(entry, ZFSACL_ENTRY_TYPE_DENY))
			return -1;

		if (!zfsace_set_who(entry, ZFSACL_GROUP_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;

	}
	if (mode & S_IRWXU) {
		permset = 0;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &entry);
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

		if (!zfsace_set_permset(entry, permset))
			return -1;

		if (!zfsace_set_flagset(entry, 0))
			return -1;

		if (!zfsace_set_entry_type(entry, ZFSACL_ENTRY_TYPE_ALLOW))
			return -1;

		if (!zfsace_set_who(entry, ZFSACL_USER_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;
	}
	if (mode & S_IRWXG) {
		permset = 0;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &entry);
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

		if (!zfsace_set_permset(entry, permset))
			return -1;

		if (!zfsace_set_flagset(entry, 0))
			return -1;

		if (!zfsace_set_entry_type(entry, ZFSACL_ENTRY_TYPE_ALLOW))
			return -1;

		if (!zfsace_set_who(entry, ZFSACL_GROUP_OBJ, ZFSACL_UNDEFINED_ID))
			return -1;
	}
	if (mode & S_IRWXO) {
		permset = 0;

		ok = zfsacl_create_aclentry(*new_acl, ZFSACL_APPEND_ENTRY, &entry);
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

		if (!zfsace_set_permset(entry, permset))
			return -1;

		if (!zfsace_set_flagset(entry, 0))
			return -1;

		if (!zfsace_set_entry_type(entry, ZFSACL_ENTRY_TYPE_ALLOW))
			return -1;

		if (!zfsace_set_who(entry, ZFSACL_EVERYONE, ZFSACL_UNDEFINED_ID))
			return -1;
	}

	return 0;
}

static bool set_acl_parameters(struct vfs_handle_struct *handle,
			       struct ixnas_config_data *config)
{
	int ret;
	char *chkpath = NULL;

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
	handle->conn->aclbrand = path_get_aclbrand(chkpath);
	if (handle->conn->aclbrand != TRUENAS_ACL_BRAND_NFS4) {
		DBG_INFO("%s: no NFSv4 ACLs (brand %d)\n",
			 chkpath, handle->conn->aclbrand);
	}
	TALLOC_FREE(chkpath);

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

	/*
	 * Ensure other alternate methods of mapping dosmodes are disabled.
	 */
	config->dosattrib_xattr = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "dosattrib_xattr", false);

	if (!config->dosattrib_xattr) {
		lp_do_parameter(SNUM(handle->conn), "kernel dosmodes", "yes");
	}

	/*
	 * Create times that Samba stored only in DOSATTRIB, before it set them
	 * natively. Reading them costs an fgetxattr per file.
	 */
	config->dosattrib_create_time =
		lp_store_dos_attributes(SNUM(handle->conn)) &&
		lp_parm_bool(SNUM(handle->conn),
			     "ixnas", "dosattrib_create_time", false);

	/*
	 * Reconcile the SMB ACL view and set operations with what the ZFS backend
	 * actually enforces. On (default): strip the WRITE_ACL/WRITE_OWNER that ZFS
	 * won't honor from owner@/group@/everyone@ in the SD we report (not from
	 * what we store) -- except for a fully-open everyone@ ACL, which we
	 * advertise in full and whose DACL writes we complete under privilege (see
	 * is_open_everyone() / fsp_set_zfsacl_escalate()). Off: raw passthrough
	 * of the stored ACL, no demotion and no privileged retry.
	 */
	config->advertise_enforced_acl = lp_parm_bool(SNUM(handle->conn),
			"ixnas", "zfs_acl_advertise_enforced", true);

	ok = set_acl_parameters(handle, config);
	if (!ok) {
		TALLOC_FREE(config);
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct ixnas_config_data,
				return -1);

	handle->conn->internal_tcon_flags |= TCON_FLAG_MDCACHE_SD;

	if (lp_parm_bool(SNUM(handle->conn), "ixnas", "truenas_abe",
			 handle->conn->aclbrand == TRUENAS_ACL_BRAND_NFS4)) {
		/*
		 * The support team requested that ABE be enabled by default
		 * on NFSv4 ACL shares in order to preserve FreeBSD behavior
		 * and better align with enterprise customer expectations
		 */
		handle->conn->internal_tcon_flags |= TCON_FLAG_TRUENAS_ABE;
	}

	return 0;
}

static int ixnas_openat(vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			files_struct *fsp,
			const struct vfs_open_how *how)
{
	int fd;
	struct vfs_open_how tmp_how = {
		.flags = how->flags,
		.mode = how->mode,
		.resolve = how->resolve | VFS_OPEN_HOW_TRUENAS_ABE
	};

	if (!fsp->fsp_flags.is_pathref) {
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname,
					   fsp,
					   how);
	}

	fd = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, &tmp_how);
	if ((fd == -1) && (errno == EACCES)) {
		// attempt to open pathref fd O_RDONLY failed
		// this *should* be a relatively rare edge-case
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname,
					   fsp,
					   how);
	}

	return fd;
}


static struct vfs_fn_pointers ixnas_fns = {
	.connect_fn = ixnas_connect,
	.openat_fn = ixnas_openat,
	/* dosmode_enabled */
	.fget_dos_attributes_fn = ixnas_fget_dos_attributes,
	.fntimes_fn = ixnas_fntimes,
	.fget_nt_acl_fn = ixnas_fget_nt_acl,
	.fset_nt_acl_fn = ixnas_fset_nt_acl,
	.sys_acl_get_fd_fn = ixnas_sys_acl_get_fd,
	.sys_acl_blob_get_fd_fn = ixnas_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = ixnas_sys_acl_set_fd,
	.stat_fn = ixnas_stat,
	.fstat_fn = ixnas_fstat,
	.lstat_fn = ixnas_lstat,
	.fstatat_fn = ixnas_fstatat,
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
