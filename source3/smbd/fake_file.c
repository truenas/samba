/*
   Unix SMB/CIFS implementation.
   FAKE FILE support, for faking up special files windows want access to
   Copyright (C) Stefan (metze) Metzmacher	2003

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "fake_file.h"
#include "auth.h"
#include "privileges.h"

struct fake_file_type {
	const char *name;
	enum FAKE_FILE_TYPE type;
	void *(*init_pd)(TALLOC_CTX *mem_ctx);
};

static const struct fake_file_type fake_files[] = {
#ifdef WITH_QUOTAS
	{FAKE_FILE_NAME_QUOTA_UNIX, FAKE_FILE_TYPE_QUOTA, init_quota_handle},
#endif /* WITH_QUOTAS */
	{NULL, FAKE_FILE_TYPE_NONE, NULL}
};

/****************************************************************************
 Create a fake file handle
****************************************************************************/

static struct fake_file_handle *init_fake_file_handle(enum FAKE_FILE_TYPE type)
{
	struct fake_file_handle *fh = NULL;
	int i;

	for (i=0; fake_files[i].name!=NULL; i++) {
		if (fake_files[i].type==type) {
			break;
		}
	}

	if (fake_files[i].name == NULL) {
		return NULL;
	}

	DEBUG(5,("init_fake_file_handle: for [%s]\n",fake_files[i].name));

	fh = talloc(NULL, struct fake_file_handle);
	if (fh == NULL) {
		DEBUG(0,("TALLOC_ZERO() failed.\n"));
		return NULL;
	}

	fh->type = type;

	if (fake_files[i].init_pd) {
		fh->private_data = fake_files[i].init_pd(fh);
	}
	return fh;
}

/****************************************************************************
 Does this name match a fake filename ?
****************************************************************************/

enum FAKE_FILE_TYPE is_fake_file_path(const char *path)
{
	int i;

	if (!path) {
		return FAKE_FILE_TYPE_NONE;
	}

	for (i=0;fake_files[i].name!=NULL;i++) {
		if (strncmp(path,fake_files[i].name,strlen(fake_files[i].name))==0) {
			DEBUG(5,("is_fake_file: [%s] is a fake file\n",path));
			return fake_files[i].type;
		}
	}

	return FAKE_FILE_TYPE_NONE;
}

enum FAKE_FILE_TYPE is_fake_file(const struct smb_filename *smb_fname)
{
	char *fname = NULL;
	NTSTATUS status;
	enum FAKE_FILE_TYPE ret;

	if (!smb_fname) {
		return FAKE_FILE_TYPE_NONE;
	}

	status = get_full_smb_filename(talloc_tos(), smb_fname, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		return FAKE_FILE_TYPE_NONE;
	}

	ret = is_fake_file_path(fname);

	TALLOC_FREE(fname);

	return ret;
}

uint32_t dosmode_from_fake_filehandle(const struct fake_file_handle *ffh)
{
	if (ffh->type != FAKE_FILE_TYPE_QUOTA) {
		DBG_ERR("Unexpected fake_file_handle: %d\n", ffh->type);
		log_stack_trace();
		return FILE_ATTRIBUTE_NORMAL;
	}

	/* This is what Windows 2016 returns */
	return FILE_ATTRIBUTE_HIDDEN
		| FILE_ATTRIBUTE_SYSTEM
		| FILE_ATTRIBUTE_DIRECTORY
		| FILE_ATTRIBUTE_ARCHIVE;
}

/****************************************************************************
 Open a fake quota file with a share mode.
****************************************************************************/

NTSTATUS open_fake_file(struct smb_request *req, connection_struct *conn,
				uint64_t current_vuid,
				enum FAKE_FILE_TYPE fake_file_type,
				const struct smb_filename *smb_fname,
				uint32_t access_mask,
				files_struct **result)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	files_struct *fsp = NULL;
	NTSTATUS status;
	bool is_allowed;

	/* access check
	 * Allow access to QUOTA fake file if user has DISK_OPERATOR
	 * privileges. This is a subset of local admin rights.
	 */
	is_allowed = (geteuid() == sec_initial_uid());
	switch(fake_file_type){
	case FAKE_FILE_TYPE_QUOTA:
		if (!is_allowed) {
			is_allowed = security_token_has_privilege(
				conn->session_info->security_token,
				SEC_PRIV_DISK_OPERATOR);
		}
		if (!is_allowed) {
			DBG_NOTICE("Access denied to "
				   "service[%s] file[%s]. User [%s] "
				   "lacks SE_PRIV_DISK_OPERATOR\n",
				   lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
				   smb_fname_str_dbg(smb_fname),
				   conn->session_info->unix_info->unix_name);
			return NT_STATUS_ACCESS_DENIED;
		}
		break;
	default:
		if (!is_allowed) {
			DEBUG(3, ("open_fake_file_shared: access_denied to "
				  "service[%s] file[%s] user[%s]\n",
				  lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
				  smb_fname_str_dbg(smb_fname),
				  conn->session_info->unix_info->unix_name));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	status = file_new(req, conn, &fsp);
	if(!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DBG_INFO("fname = %s, %s, access_mask = 0x%"PRIx32"\n",
		 smb_fname_str_dbg(smb_fname),
		 fsp_fnum_dbg(fsp),
		 access_mask);

	fsp->conn = conn;
	fsp_set_fd(fsp, -1);
	fsp->vuid = current_vuid;
	fh_set_pos(fsp->fh, -1);
	fsp->fsp_flags.can_lock = false; /* Should this be true ? - No, JRA */
	fsp->access_mask = access_mask;
	status = fsp_set_smb_fname(fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(req, fsp);
		return NT_STATUS_NO_MEMORY;
	}

	fsp->fake_file_handle = init_fake_file_handle(fake_file_type);

	if (fsp->fake_file_handle==NULL) {
		file_free(req, fsp);
		return NT_STATUS_NO_MEMORY;
	}

	status = smbd_calculate_access_mask_fsp(conn->cwd_fsp,
					fsp,
					false,
					access_mask,
					&access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("smbd_calculate_access_mask_fsp "
			"on service[%s] file[%s] returned %s\n",
			lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		file_free(req, fsp);
		return status;
	}

	*result = fsp;
	return NT_STATUS_OK;
}

NTSTATUS close_fake_file(struct smb_request *req, files_struct *fsp)
{
	/*
	 * Nothing to do, fake files don't hold any resources
	 */
	return NT_STATUS_OK;
}
