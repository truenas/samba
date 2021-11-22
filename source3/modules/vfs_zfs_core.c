/*
 *  Unix SMB/CIFS implementation.
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
#include "smbd/smbd.h"
#include "libcli/security/security.h"
#include "auth.h"
#include "privileges.h"
#include "system/filesys.h"

#include "lib/util/tevent_ntstatus.h"
#include "modules/smb_libzfs.h"

static int vfs_zfs_core_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_zfs_core_debug_level

struct zfs_core_config_data {
	struct dataset_list *dl;
	struct dataset_list *created;
	bool zfs_space_enabled;
	bool zfs_quota_enabled;
	bool zfs_auto_create;
	const char *dataset_auto_quota;
	uint64_t base_user_quota;
};

static struct zfs_dataset *smbfname_to_ds(const struct connection_struct *conn,
					  struct dataset_list *dl,
					  const struct smb_filename *smb_fname)
{
	int ret;
	SMB_STRUCT_STAT sbuf;
	const SMB_STRUCT_STAT *psbuf = NULL;
	struct zfs_dataset *child = NULL;
	char *full_path = NULL;
	char *to_free = NULL;
	char path[PATH_MAX + 1];
	int len;

	if (VALID_STAT(smb_fname->st)) {
		psbuf = &smb_fname->st;
	}
	else {
		ret = vfs_stat_smb_basename(discard_const(conn),
					    smb_fname, &sbuf);
		if (ret != 0) {
			DBG_ERR("Failed to stat() %s: %s\n",
				smb_fname_str_dbg(smb_fname), strerror(errno));
			return NULL;
		}
		psbuf = &sbuf;
	}

	if (psbuf->st_ex_dev == dl->root->devid) {
		return dl->root;
	}
	for (child=dl->children; child; child=child->next) {
		if (child->devid == psbuf->st_ex_dev) {
			return child;
		}
	}

	/*
	 * Our current cache of datasets does not contain the path in
	 * question. Use libzfs to try to get it. Allocate under
	 * memory context of our dataset list.
	 */
	len = full_path_tos(discard_const(conn->cwd_fsp->fsp_name->base_name),
			    smb_fname->base_name,
			    path, sizeof(path),
			    &full_path, &to_free);
	if (len == -1) {
		DBG_ERR("Could not allocate memory in full_path_tos.\n");
		return NULL;
	}

	child = smb_zfs_path_get_dataset(dl->root->zhandle->lz,
					 dl, path, true, true, true);
	TALLOC_FREE(to_free);
	if (child != NULL) {
		DLIST_ADD(dl->children, child);
		return child;
	}

	DBG_ERR("No dataset found for %s with device id: %lu\n",
		path, psbuf->st_ex_dev);
	errno = ENOENT;
	return NULL;
}

static uint32_t zfs_core_fs_capabilities(struct vfs_handle_struct *handle,
					 enum timestamp_set_resolution *p_ts_res)
{
	struct zfs_core_config_data *config = NULL;
	uint32_t fscaps;

	fscaps = SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return fscaps);

	if (!config->zfs_quota_enabled) {
		fscaps &= ~FILE_VOLUME_QUOTAS;
	}
	return fscaps;
}

static uint64_t zfs_core_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	uint64_t res;
	struct zfs_core_config_data *config = NULL;
	struct zfs_dataset *ds = NULL;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return -1);

	if (!config->zfs_space_enabled) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	}

	ds = smbfname_to_ds(handle->conn, config->dl, smb_fname);
	if (ds == NULL) {
		DBG_ERR("Failed to retrive ZFS dataset handle on %s: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
	}

	res = smb_zfs_disk_free(ds->zhandle, bsize, dfree, dsize);
	if (res == -1) {
		res = SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	}
	return res;
}

static int zfs_core_get_quota(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      enum SMB_QUOTA_TYPE qtype,
			      unid_t id,
			      SMB_DISK_QUOTA *qt)

{
	int ret;
	struct zfs_core_config_data *config = NULL;
	struct zfs_dataset *ds = NULL;
	struct zfs_quota zfs_qt;
	uint64_t hardlimit, usedspace, xid;
	hardlimit = usedspace = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return -1);

	if (!config->zfs_quota_enabled) {
		DBG_DEBUG("Quotas disabled in zfs_core configuration.\n");
		errno = ENOSYS;
		return -1;
	}

	ds = smbfname_to_ds(handle->conn, config->dl, smb_fname);
	if (ds == NULL) {
		DBG_ERR("Failed to retrive ZFS dataset handle on %s: %s\n",
			smb_fname_str_dbg(smb_fname), strerror(errno));
		return -1;
	}
	ZERO_STRUCT(zfs_qt);
	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		xid = id.uid == -1?(uint64_t)geteuid():(uint64_t)id.uid;
		become_root();
		ret = smb_zfs_get_quota(ds->zhandle,
					xid,
					SMBZFS_USER_QUOTA,
					&zfs_qt);
		unbecome_root();
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		xid = id.gid == -1?(uint64_t)getegid():(uint64_t)id.gid;
		become_root();
		ret = smb_zfs_get_quota(ds->zhandle,
					xid,
					SMBZFS_GROUP_QUOTA,
					&zfs_qt);
		unbecome_root();
		break;
	default:
		DBG_ERR("Unrecognized quota type.\n");
		ret = -1;
		break;
	}

	ZERO_STRUCTP(qt);
	qt->bsize = 1024;
	qt->hardlimit = zfs_qt.bytes;
	qt->softlimit = zfs_qt.bytes;
	qt->curblocks = zfs_qt.bytes_used;
	qt->ihardlimit = zfs_qt.obj;
	qt->isoftlimit = zfs_qt.obj;
	qt->curinodes = zfs_qt.obj_used;
	qt->qtype = qtype;
	qt->qflags = QUOTAS_DENY_DISK|QUOTAS_ENABLED;

	DBG_INFO("zfs_core_get_quota: hardlimit: (%lu), usedspace: (%lu)\n",
		 qt->hardlimit, qt->curblocks);

	return ret;
}

static int zfs_core_set_quota(struct vfs_handle_struct *handle,
			enum SMB_QUOTA_TYPE qtype, unid_t id,
			SMB_DISK_QUOTA *qt)
{
	struct zfs_core_config_data *config = NULL;
	int ret;
	bool is_disk_op = false;
	uint64_t xid;
	struct zfs_quota zq;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return -1);

	if (!config->zfs_quota_enabled) {
		DBG_DEBUG("Quotas disabled in zfs_core configuration.\n");
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

	zq.bytes = qt->hardlimit * 1024;
	zq.obj = qt->ihardlimit;

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		DBG_INFO("zfs_core_set_quota: quota type: (%d), "
			 "id: (%d), h-limit: (%lu), s-limit: (%lu)\n",
			 SMBZFS_USER_QUOTA, id.uid, qt->hardlimit, qt->softlimit);
		xid = id.uid == -1?(uint64_t)geteuid():(uint64_t)id.uid;
		zq.quota_type = SMBZFS_USER_QUOTA;
		become_root();
		ret = smb_zfs_set_quota(config->dl->root->zhandle, xid, zq);
		unbecome_root();
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		DBG_INFO("zfs_core_set_quota: quota type: (%d), "
			 "id: (%d), h-limit: (%lu), s-limit: (%lu)\n",
			 SMBZFS_GROUP_QUOTA, id.gid, qt->hardlimit, qt->softlimit);
		xid = id.gid == -1?(uint64_t)getegid():(uint64_t)id.gid;
		zq.quota_type = SMBZFS_GROUP_QUOTA;
		become_root();
		ret = smb_zfs_set_quota(config->dl->root->zhandle, xid, zq);
		unbecome_root();
		break;
	default:
		DBG_ERR("Received unknown quota type.\n");
		ret = -1;
		break;
	}

	return ret;
}

static bool get_synthetic_fsp(vfs_handle_struct *handle,
			      const char *fname_in,
			      files_struct **out)
{
	NTSTATUS status;
	files_struct *tmp_fsp = NULL;
	struct smb_filename *tmp_fname = NULL;
	mode_t unix_mode;
	int fd;

	tmp_fname = synthetic_smb_fname(talloc_tos(),
					fname_in,
					NULL,
					NULL,
					0,
					0);
	if (tmp_fname == NULL) {
		errno = ENOMEM;
		return false;
	}

	status = create_internal_fsp(handle->conn, tmp_fname, &tmp_fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create internal FSP for %s: %s\n",
			smb_fname_str_dbg(tmp_fname), nt_errstr(status));
		return false;
	}
	TALLOC_FREE(tmp_fname);

	unix_mode = (0777 & lp_directory_mask(SNUM(handle->conn)));

	fd = open(fname_in, O_DIRECTORY, unix_mode);
	if (fd == -1) {
		DBG_ERR("Failed to open %s, mode: 0o%o: %s\n",
			smb_fname_str_dbg(tmp_fname), unix_mode,
			strerror(errno));
		return false;
	}
	tmp_fsp->fsp_flags.is_directory = true;

	fsp_set_fd(tmp_fsp, fd);

	*out = tmp_fsp;
	return true;
}

static bool zfs_inherit_acls(vfs_handle_struct *handle,
			     const char *root,
			     struct dataset_list *ds_list)
{
	struct zfs_dataset *ds = NULL;
	size_t root_len;
	struct stat st;
	int error;
	struct files_struct *pathref = NULL;
	bool ok;

	root_len = strlen(ds_list->root->mountpoint) + 1;

	error = stat(handle->conn->connectpath, &st);
	if (error) {
		DBG_ERR("%s: stat() failed: %s\n", root, strerror(errno));
		return false;
	}

	error = chdir(ds_list->root->mountpoint);
	if (error != 0) {
		DBG_ERR("failed to chdir into [%s]: %s\n",
			ds_list->root->mountpoint, strerror(errno));
		return false;
	}

	ok = get_synthetic_fsp(handle, ".", &pathref);
	if (!ok) {
		return false;
	}

	for (ds = ds_list->children; ds; ds = ds->next) {
		struct files_struct *c_fsp = NULL;
		NTSTATUS status;

		ok = get_synthetic_fsp(handle, ds->mountpoint + root_len, &c_fsp);
		if (!ok) {
			return false;
		}

		error = SMB_VFS_STAT(handle->conn, c_fsp->fsp_name);
		if (error) {
			DBG_ERR("%s: stat() failed: %s\n", fsp_str_dbg(c_fsp), strerror(errno));
			fd_close(c_fsp);
			return false;
		}

		/*
		 * ensure we have valid stat on our synthetic FSP
		 */

		status = inherit_new_acl(pathref->fsp_name, c_fsp);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("fail: %s: %s\n", ds->mountpoint, nt_errstr(status));
		}

		fd_close(pathref);
		pathref = c_fsp;
	}
	error = chdir(handle->conn->connectpath);
	if (error != 0) {
		DBG_ERR("failed to chdir into [%s]: %s\n",
			handle->conn->connectpath, strerror(errno));
		return false;
	}

	/*
	 * Restore owner after inheriting ACL from parent dataset.
	 */
	error = chown(handle->conn->connectpath, st.st_uid, st.st_gid);
	if (error) {
		DBG_ERR("%s: failed to restore ownership after "
			"forced ACL inheritance: %s\n",
			root, strerror(errno));
	}

	return true;
}

static int create_zfs_connectpath(vfs_handle_struct *handle,
				  struct zfs_core_config_data *config,
				  const char *user)
{
	bool do_chown;
	int rv;
	NTSTATUS status;
	struct smblibzfshandle *libzp = NULL;
	struct dataset_list *ds_list = NULL;

	if (access(handle->conn->connectpath, F_OK) == 0) {
		DBG_INFO("Connectpath for %s already exists. "
			 "skipping dataset creation\n",
			 handle->conn->connectpath);
		return 0;
	}

	rv = get_smblibzfs_handle(handle->conn, &libzp);
	if (rv != 0) {
		DBG_ERR("Failed to obtain libzfshandle on connectpath: %s\n",
			strerror(errno));
		return -1;
	}

	rv = smb_zfs_create_dataset(handle->conn, libzp,
				    handle->conn->connectpath,
				    config->dataset_auto_quota,
				    &config->created, true);
	if (rv !=0) {
		return -1;
	}

	do_chown = lp_parm_bool(SNUM(handle->conn), "zfs_core",
			        "chown_homedir", true);
	if (do_chown) {
		struct passwd *current_user = Get_Pwnam_alloc(handle->conn, user);
		if ( !current_user ) {
			DBG_ERR("Get_Pwnam_alloc failed for (%s).\n", user);
			return -1;
		}
		rv = chown(handle->conn->connectpath,
			   current_user->pw_uid,
			   current_user->pw_gid);
		if (rv < 0) {
			DBG_ERR("Failed to chown (%s) to (%u:%u)\n",
				handle->conn->connectpath,
				current_user->pw_uid, getegid() );
		}
		TALLOC_FREE(current_user);
	}
	TALLOC_FREE(libzp);
	return rv;
}

/*
 * Fake the presence of a base quota. Check if user quota already exists.
 * If it exists, then we assume that the base quota has either already been set
 * or it has been modified by the admin. In either case, do nothing.
 */
static int set_base_user_quota(vfs_handle_struct *handle,
			       struct zfs_core_config_data *config,
			       const char *user)
{
	int ret;
	uint64_t base_quota;
	uid_t current_user = nametouid(user);
	struct zfs_quota zq = {0};

	if (current_user == -1) {
		DBG_ERR("Failed to convert (%s) to uid.\n", user);
		return -1;
	}
	else if (current_user == 0) {
		DBG_INFO("Refusing to set user quota on uid 0.\n");
		return -1;
	}

	ret = smb_zfs_get_quota(config->dl->root->zhandle,
					  current_user,
					  SMBZFS_USER_QUOTA,
					  &zq);
	if (ret != 0) {
		DBG_ERR("Failed to get base quota uid: (%u), path (%s)\n",
			current_user, handle->conn->connectpath );
		return -1;
	}

	DBG_INFO("set_base_user_quote: uid (%u), quota (%lu)\n",
		 current_user, base_quota);

	if (zq.bytes == 0) {
		zq.bytes = config->base_user_quota;
		zq.obj = 0;
		ret = smb_zfs_set_quota(config->dl->root->zhandle,
				        current_user, zq);
		if (ret != 0) {
			DBG_ERR("Failed to set base quota uid: (%u), "
				"path (%s), value (%lu)\n", current_user,
				handle->conn->connectpath, base_quota );
		}
	}
	return ret;
}

static int zfs_core_chdir(vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname)
{
	static bool checked = false;
	struct zfs_core_config_data *config = NULL;

	if (checked) {
		return SMB_VFS_NEXT_CHDIR(handle, smb_fname);
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfs_core_config_data,
				return -1);

	if (config->created != NULL) {
		bool ok;

		become_root();
		ok = zfs_inherit_acls(handle,
				      config->created->root->mountpoint,
				      config->created);
		unbecome_root();
		if (!ok) {
			checked = true;
			return -1;
		}
	}

	checked = true;
	return SMB_VFS_NEXT_CHDIR(handle, smb_fname);
}

static int zfs_core_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	struct zfs_core_config_data *config = NULL;
	int ret;
	const char *dataset_auto_quota = NULL;
	const char *base_quota_str = NULL;
	struct smblibzfshandle *lz = NULL;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct zfs_core_config_data);
	if (!config) {
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Check if we need to automatically create a new ZFS dataset
	 * before falling through to SMB_VFS_NEXT_CONNECT.
	 */
	config->zfs_auto_create = lp_parm_bool(SNUM(handle->conn),
			"zfs_core", "zfs_auto_create", false);
	config->dataset_auto_quota = lp_parm_const_string(SNUM(handle->conn),
			"zfs_core", "dataset_auto_quota", NULL);

	if (config->zfs_auto_create) {
		ret = create_zfs_connectpath(handle, config, user);
		if (ret < 0) {
			return -1;
		}
	}

	ret = conn_zfs_init(handle->conn->sconn,
			    handle->conn->connectpath,
			    &lz,
			    &config->dl);
	if (ret != 0) {
		DBG_ERR("Failed to initialize ZFS data: %s\n",
			strerror(errno));
		return ret;
	}

	base_quota_str = lp_parm_const_string(SNUM(handle->conn),
			"zfs_core", "base_user_quota", NULL);

	if (base_quota_str != NULL) {
		config->base_user_quota = conv_str_size(base_quota_str);
		set_base_user_quota(handle, config, user);
        }

	if (config->dl->root->properties->casesens == SMBZFS_INSENSITIVE) {
		DBG_INFO("zfs_core: case insensitive dataset detected, "
			 "automatically adjusting case sensitivity settings.\n");
		lp_do_parameter(SNUM(handle->conn),
				"case sensitive", "yes");
		handle->conn->case_sensitive = True;
	}

	config->zfs_space_enabled = lp_parm_bool(SNUM(handle->conn),
			"zfs_core", "zfs_space_enabled", false);

	config->zfs_quota_enabled = lp_parm_bool(SNUM(handle->conn),
			"zfs_core", "zfs_quota_enabled", true);

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct zfs_core_config_data,
				return -1);

	return 0;
}

static struct vfs_fn_pointers zfs_core_fns = {
	.fs_capabilities_fn = zfs_core_fs_capabilities,
	.chdir_fn = zfs_core_chdir,
	.connect_fn = zfs_core_connect,
	.get_quota_fn = zfs_core_get_quota,
	.set_quota_fn = zfs_core_set_quota,
	.disk_free_fn = zfs_core_disk_free
};

NTSTATUS vfs_zfs_core_init(TALLOC_CTX *);
NTSTATUS vfs_zfs_core_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "zfs_core",
					&zfs_core_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_zfs_core_debug_level = debug_add_class("zfs_core");
	if (vfs_zfs_core_debug_level == -1) {
		vfs_zfs_core_debug_level = DBGC_VFS;
		DBG_ERR("%s: Couldn't register custom debugging class!\n",
			"vfs_zfs_core_init");
	} else {
		DBG_DEBUG("%s: Debug class number of '%s': %d\n",
		"vfs_zfs_core_init","zfs_core",vfs_zfs_core_debug_level);
	}
	return ret;
}
