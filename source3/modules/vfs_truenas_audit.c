/*
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) iXsystems, Inc			2023
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
#include "system/filesys.h"
#include "system/syslog.h"
#include "auth.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/param/loadparm.h"
#include "lib/util/tevent_unix.h"
#include "libcli/security/sddl.h"
#include "passdb/machine_sid.h"

#include <jansson.h>
#include "audit_logging.h"
#include "vfs_truenas_audit.h"

int vfs_tnaudit_debug_level = DBGC_VFS;

static int audit_syslog_priority(vfs_handle_struct *handle)
{
	static const struct enum_list enum_log_priorities[] = {
		{ LOG_EMERG, "EMERG" },
		{ LOG_ALERT, "ALERT" },
		{ LOG_CRIT, "CRIT" },
		{ LOG_ERR, "ERR" },
		{ LOG_WARNING, "WARNING" },
		{ LOG_NOTICE, "NOTICE" },
		{ LOG_INFO, "INFO" },
		{ LOG_DEBUG, "DEBUG" },
		{ -1, NULL }
	};

	int priority;

	priority = lp_parm_enum(SNUM(handle->conn), MODULE_NAME, "priority",
				enum_log_priorities, LOG_NOTICE);
	if (priority == -1) {
		priority = LOG_WARNING;
	}

	return priority;
}

enum tn_audit_filter {WATCH_LIST, IGNORE_LIST};
static bool tn_audit_check_group_list(const char *user,
				      const char **grouplist,
				      enum tn_audit_filter f)
{
	bool def = f == WATCH_LIST ? true : false;
	const char *filter_name = f == WATCH_LIST ? "watch_list" : "ignore_list";
	int i;

	if (user == NULL) {
		DBG_ERR("%s: Username is NULL. "
			"Returning default value of [%s].\n",
			filter_name, def ? "true": "false");
		return def;
	}

	if (grouplist == NULL) {
		DBG_DEBUG("%s: No grouplist specified. "
			  "Returning default value of [%s].\n",
			  filter_name, def ? "true": "false");
		return def;
	}

	for (i = 0; grouplist && grouplist[i]; i++) {
		const char *group = grouplist[i];
		if (strcmp(group, "*") == 0) {
			DBG_DEBUG("%s: wildcard filter applied\n",
				  filter_name);
			return true;
		}

		if (user_in_group(user, group)) {
			DBG_DEBUG("%s: user [%s] is in group [%s]\n",
				  filter_name, user, group);
			return true;
		}
        }

	return false;
}

static int tn_audit_connect(vfs_handle_struct *handle,
			    const char *svc,
			    const char *user)
{
	/*
	 * Sample `event_data`
	 *
	 * {
	 *   "host": "127.0.0.1",
	 *   "unix_token": {
	 *     "username": "smbuser",
	 *     "uid": 3000,
	 *     "gid": 3000
         *     "groups": [545, 3000, 90000005, 90000012, 90000017],
	 *   },
	 *   "result": {
	 *     "type": "UNIX",
	 *     "value_raw": 0,
	 *     "value_parsed": "SUCCESS"
	 *   },
	 *   "vers": {"major": 0, "minor": 1}
	 * }
	 */
	int result;
	tn_audit_conf_t *config = NULL;
	struct json_object msg, entry, js_conn;
	bool ok;
	const char **watch_list = NULL;
	const char **ignore_list = NULL;

	result = SMB_VFS_NEXT_CONNECT(handle, svc, user);
	if (result < 0) {
		return result;
	}

	config = talloc_zero(handle->conn, tn_audit_conf_t);
	if (config == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	config->do_syslog = lp_parm_bool(SNUM(handle->conn),
					 MODULE_NAME,
					 "use_syslog",
					 true);
	if (config->do_syslog) {
		config->syslog_priority = audit_syslog_priority(handle);
		openlog(SYSLOG_IDENT, 0, LOG_USER);
	}

	config->enabled = true;

	/*
	 * Prefer to err on the side of caution (auditing session)
	 * Auditing will be disabled in following situations
	 *
	 * 1) user is member of group in ignore_list and is not
	 *    a member of group in the watch list.
	 *
	 * watch_list is always given precedence.
	 */
	watch_list = lp_parm_string_list(SNUM(handle->conn),
					 MODULE_NAME,
					 "watch_list", NULL);

	ignore_list = lp_parm_string_list(SNUM(handle->conn),
					  MODULE_NAME,
					  "ignore_list", NULL);

	if (tn_audit_check_group_list(user, ignore_list, IGNORE_LIST)) {
		config->enabled = false;
	}

	if (watch_list) {
		config->enabled = tn_audit_check_group_list(user,
							    watch_list,
							    WATCH_LIST);
	}

	// If we fail to generate our connection info, then
	// TCON should be rejected since we will be unable to properly audit
	config->conn_info.sess = GUID_string(config,
	    &handle->conn->session_info->unique_session_token);

	if (config->conn_info.sess == NULL) {
		TALLOC_FREE(config);
		return -1;
	}

	config->conn_info.user = talloc_strdup(config,
	    handle->conn->session_info->unix_info->sanitized_username);
	if (config->conn_info.user == NULL) {
		TALLOC_FREE(config);
		return -1;
	}

	js_conn = json_new_object();
	if (json_is_invalid(&js_conn)) {
		TALLOC_FREE(config);
		return -1;
	}

	ok = add_connection_info_to_obj(svc, handle->conn,
					&js_conn);
	if (!ok) {
		TALLOC_FREE(config);
		return -1;
	}
	config->js_connection = json_to_string(config, &js_conn);
	json_free(&js_conn);
	if (config->js_connection == NULL) {
		TALLOC_FREE(config);
		return -1;
	}
	SMB_VFS_HANDLE_SET_DATA(handle, config, NULL,
				tn_audit_conf_t, return -1);

	// After this point, we unilaterally succeed (just log message is potentially lost)
	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		return result;
	}

	ok = add_client_info_to_obj(handle->conn->sconn, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_unix_token_to_obj(handle->conn->session_info, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_result_unix(0, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_CONNECT, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = tn_audit_do_log(config, &msg);
	if (!ok) {
		DBG_ERR("Failed to send log message\n");
	}

cleanup:
	json_free(&msg);
	json_free(&entry);

	return result;
}

static bool add_session_counters(tn_audit_conf_t *config,
				 struct json_object *jsobj)
{
	int error;
	char buf[20];

	snprintf(buf, sizeof(buf), "%zu", config->op_cnt.create);
	error = json_add_string(jsobj, "create", buf);
	if (error) {
		return false;
	}

	snprintf(buf, sizeof(buf), "%zu", config->op_cnt.close);
	error = json_add_string(jsobj, "close", buf);
	if (error) {
		return false;
	}

	snprintf(buf, sizeof(buf), "%zu", config->op_cnt.read);
	error = json_add_string(jsobj, "read", buf);
	if (error) {
		return false;
	}

	snprintf(buf, sizeof(buf), "%zu", config->op_cnt.write);
	error = json_add_string(jsobj, "write", buf);
	if (error) {
		return false;
	}

	return true;
}

static void tn_audit_disconnect(vfs_handle_struct *handle)
{
	/*
	 * Sample `event_data`
	 *
	 * {
	 *   "host": "127.0.0.1",
	 *   "unix_token": {
	 *     "username": "smbuser",
	 *     "uid": 3000,
	 *     "gid": 3000
         *     "groups": [545, 3000, 90000005, 90000012, 90000017],
	 *   },
	 *   "operations": {
	 *     "create": "0",
	 *     "close": "0",
	 *     "read": "0",
	 *     "write": "0"
	 *   },
	 *   "result": {
	 *     "type": "UNIX",
	 *     "value_raw": 0,
	 *     "value_parsed": "SUCCESS"
	 *   },
	 *   "vers": {"major": 0, "minor": 1}
	 * }
	 */
	int result, error;
	tn_audit_conf_t *config = NULL;
	struct json_object msg, entry, counters;
	bool ok;

	SMB_VFS_NEXT_DISCONNECT(handle);

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return);

	counters = json_new_object();
	if (json_is_invalid(&counters)) {
		return;
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		return;
	}

	ok = add_client_info_to_obj(handle->conn->sconn, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_unix_token_to_obj(handle->conn->session_info, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_session_counters(config, &counters);
	if (!ok) {
		goto cleanup;
	}

	error = json_add_object(&entry, "operations", &counters);
	if (error) {
		goto cleanup;
	}

	ok = add_result_unix(0, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_DISCONNECT, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	tn_audit_do_log(config, &msg);
	json_free(&msg);

cleanup:
	json_free(&msg);
	json_free(&entry);
}

static tn_audit_ext_t *init_fsp_extension(vfs_handle_struct *handle,
					  files_struct *fsp,
					  struct json_object *jsobj)
{
	/*
	 * Ensure that the file has an extension on it and
	 * add the file_id information to the JSON object
	 */
	tn_audit_ext_t *fsp_ext = NULL;

	fsp_ext = (tn_audit_ext_t *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (fsp_ext != NULL) {
		return NULL;
	}

	fsp_ext = VFS_ADD_FSP_EXTENSION(handle, fsp, tn_audit_ext_t,
					NULL);
	SMB_ASSERT(fsp_ext != NULL);
	file_id_str_buf(fsp->file_id, &fsp_ext->fid_str);
	return fsp_ext;
}

static NTSTATUS tn_audit_create_file(vfs_handle_struct *handle,
				     struct smb_request *req,
				     struct files_struct *dirfsp,
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
				     files_struct **result_fsp,
				     int *pinfo,
				     const struct smb2_create_blobs *in_context_blobs,
				     struct smb2_create_blobs *out_context_blobs)
{
	/*
	 * Sample `event_data`
	 *
	 *  {
	 *    "parameters": {
	 *      "DesiredAccess": "0x00000003",
	 *      "FileAttributes": "0x00000000",
	 *      "ShareAccess": "0x00000003",
	 *      "CreateDisposition": "OPEN",
	 *      "CreateOptions": "0x00000000"
	 *    },
	 *    "file_type": "FILE",
	 *    "file": {
	 *      "path": "kern.log",
	 *      "stream": null,
	 *      "snap": null,
	 *      "handle": {
	 *        "type": "DEV_INO",
	 *        "value": "41:14:0"
	 *      }
	 *    },
	 *    "result": {
	 *      "type": "NTSTATUS",
	 *      "value_raw": 0,
	 *      "value_parsed": "SUCCESS"
	 *    },
	 *    "vers": {"major": 0, "minor": 1}
	 *  }
	 *
	 * NOTE: above JSON object may include SDDL-formatted string if CREATE
	 * operation specifies an ACL to set concurrently with file creation.
	 */
	NTSTATUS result;
	tn_audit_conf_t *config = NULL;
	tn_audit_ext_t *fsp_ext = NULL;
	struct json_object msg, entry;
	struct smb_filename *fname = smb_fname;
	uint32_t js_flags = FILE_ADD_NAME | FILE_NAME_IS_PATH;
	bool ok;

	result = SMB_VFS_NEXT_CREATE_FILE(
		handle,
		req,
		dirfsp,
		smb_fname,
		access_mask,
		share_access,
		create_disposition,
		create_options,
		file_attributes,
		oplock_request,
		lease,
		allocation_size,
		private_flags,
		sd,
		ea_list,
		result_fsp,
		pinfo,
		in_context_blobs, out_context_blobs);

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return result);
	if (oplock_request == INTERNAL_OPEN_ONLY) {
		// This is interal op, don't log
		return result;
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		return result;
	}


	if (NT_STATUS_IS_OK(result)) {
		fsp_ext = init_fsp_extension(handle, *result_fsp, &entry);
		if (fsp_ext == NULL) {
			// We're reusing an existing handle. Reduce spam.
			goto cleanup;
		}
		fname = (*result_fsp)->fsp_name;
		js_flags |= FILE_ADD_HANDLE;
	}

	ok = add_create_payload(fname,
				fsp_ext,
				js_flags,
				access_mask,
				share_access,
				create_disposition,
				create_options,
				file_attributes,
				sd,
				&entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_result_ntstatus(result, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_CREATE, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	tn_audit_do_log(config, &msg);

cleanup:
	json_free(&msg);
	json_free(&entry);
	return result;
}

static bool add_fsp_operations(tn_audit_ext_t *fsp_ext, struct json_object *jsobj)
{
	int error;
	char buf[64];

	snprintf(buf, sizeof(buf), "%zu", fsp_ext->ops.read_cnt);
	error = json_add_string(jsobj, "read_cnt", buf);
	if (error) {
		return false;
	}

	snprintf(buf, sizeof(buf), "%zu",
		 fsp_ext->ops.read_bytes * (fsp_ext->ops.read_wrap + 1));
	error = json_add_string(jsobj, "read_bytes", buf);
	if (error) {
		return false;
	}

	snprintf(buf, sizeof(buf), "%zu", fsp_ext->ops.write_cnt);
	error = json_add_string(jsobj, "write_cnt", buf);
	if (error) {
		return false;
	}

	snprintf(buf, sizeof(buf), "%zu",
		 fsp_ext->ops.write_bytes * (fsp_ext->ops.write_wrap + 1));
	error = json_add_string(jsobj, "write_bytes", buf);
	if (error) {
		return false;
	}

	return true;
}

static int tn_audit_close(vfs_handle_struct *handle, files_struct *fsp)
{
	/*
	 * Sample `event_data`
	 *
	 *  {
	 *    "file": {
	 *      "handle": {
	 *        "type": "DEV_INO",
	 *        "value": "41:14:0"
	 *      }
	 *    },
	 *    "operations": {
	 *      "read_cnt": "0",
	 *      "read_bytes": "0",
	 *      "write_cnt": "0",
	 *      "write_bytes": "0"
	 *    },
	 *    "result": {
	 *      "type": "UNIX",
	 *      "value_raw": 0,
	 *      "value_parsed": "SUCCESS"
	 *    },
	 *    "vers": {"major": 0, "minor": 1}
	 *  }
	 */
	int result, error;
	tn_audit_conf_t *config = NULL;
	tn_audit_ext_t *fsp_ext = NULL;
	struct json_object msg, entry, counters;
	bool ok;

	result = SMB_VFS_NEXT_CLOSE(handle, fsp);

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return result);

	fsp_ext = (tn_audit_ext_t *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (fsp_ext == NULL) {
		return result;
	}

	counters = json_new_object();
	if (json_is_invalid(&counters)) {
		return result;
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		return result;
	}

	ok = add_file_to_object(fsp->fsp_name, fsp_ext, "file", FILE_ADD_HANDLE, &entry);
	if (!ok) {
		json_free(&entry);
		goto cleanup;
	}

	ok = add_fsp_operations(fsp_ext, &counters);
	if (!ok) {
		json_free(&entry);
		goto cleanup;
	}

	error = json_add_object(&entry, "operations", &counters);
	if (error) {
		json_free(&entry);
		goto cleanup;
	}

	ok = add_result_unix(result, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_CLOSE, &msg, &entry);
	if (!ok) {
		json_free(&entry);
		goto cleanup;
	}

	tn_audit_do_log(config, &msg);

cleanup:
	json_free(&msg);
	return result;
}

static int tn_audit_unlinkat(vfs_handle_struct *handle,
			     struct files_struct *dirfsp,
			     const struct smb_filename *smb_fname,
			     int flags)
{
	/*
	 * Sample `event_data`
	 *
	 *  {
	 *    "file": {
	 *      "type": "REGULAR",
	 *      "path": "kern.log",
	 *      "stream": null,
	 *      "snap": null
	 *    },
	 *    "result": {
	 *      "type": "UNIX",
	 *      "value_raw": 0,
	 *      "value_parsed": "SUCCESS"
	 *    },
	 *    "vers": {"major": 0, "minor": 1}
	 *  }
	 */
	struct smb_filename *full_fname = NULL;
	int result;
	tn_audit_conf_t *config = NULL;
	struct json_object msg, entry;
	uint32_t js_flags = FILE_ADD_NAME | FILE_NAME_IS_PATH | FILE_ADD_TYPE;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return -1);

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		TALLOC_FREE(full_fname);
		return -1;
	}

	result = SMB_VFS_NEXT_UNLINKAT(handle,
				       dirfsp,
				       smb_fname,
				       flags);

	ok = add_file_to_object(full_fname, NULL, "file", js_flags, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_result_unix(result, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_UNLINK, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	tn_audit_do_log(config, &msg);

cleanup:
	json_free(&msg);
	json_free(&entry);
	TALLOC_FREE(full_fname);
	return result;
}

static int tn_audit_renameat(vfs_handle_struct *handle,
			     files_struct *srcfsp,
			     const struct smb_filename *smb_fname_src,
			     files_struct *dstfsp,
			     const struct smb_filename *smb_fname_dst)
{
	int result;
	struct smb_filename *full_fname_src = NULL;
	struct smb_filename *full_fname_dst = NULL;
	tn_audit_conf_t *config = NULL;
	struct json_object msg, entry;
	uint32_t js_flags = FILE_ADD_NAME | FILE_NAME_IS_PATH | FILE_ADD_TYPE;
	bool ok;

	full_fname_src = full_path_from_dirfsp_atname(talloc_tos(),
						      srcfsp,
						      smb_fname_src);
	if (full_fname_src == NULL) {
		return -1;
	}
	full_fname_dst = full_path_from_dirfsp_atname(talloc_tos(),
						      dstfsp,
						      smb_fname_dst);
	if (full_fname_dst == NULL) {
		TALLOC_FREE(full_fname_src);
		return -1;
	}

	result = SMB_VFS_NEXT_RENAMEAT(handle,
				srcfsp,
				smb_fname_src,
				dstfsp,
				smb_fname_dst);

	if (result == -1) {
		TALLOC_FREE(full_fname_src);
		TALLOC_FREE(full_fname_dst);
		return -1;
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		TALLOC_FREE(full_fname_src);
		TALLOC_FREE(full_fname_dst);
		return -1;
	}

	ok = add_file_to_object(full_fname_src,
				NULL,
				"src_file",
				js_flags,
				&entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_file_to_object(full_fname_dst,
				NULL,
				"dst_file",
				js_flags,
				&entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_result_unix(result, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_RENAME, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	tn_audit_do_log(config, &msg);

cleanup:
	json_free(&msg);
	json_free(&entry);
	TALLOC_FREE(full_fname_src);
	TALLOC_FREE(full_fname_dst);
	return result;
}

static NTSTATUS tn_audit_fsctl(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       TALLOC_CTX *ctx,
			       uint32_t function,
			       uint16_t req_flags,
			       const uint8_t *_in_data,
			       uint32_t in_len,
			       uint8_t **_out_data,
			       uint32_t max_out_len,
			       uint32_t *out_len)
{
	static const struct enum_list fn_types[] = {
		{ FSCTL_SET_SPARSE,
		  "SPARSE" },
		{ FSCTL_REQUEST_OPLOCK_LEVEL_1,
		  "REQUEST_OPLOCK_LEVEL_1" },
		{ FSCTL_REQUEST_OPLOCK_LEVEL_2,
		  "REQUEST_OPLOCK_LEVEL_2" },
		{ FSCTL_REQUEST_BATCH_OPLOCK,
		  "REQUEST_BATCH_OPLOCK" },
		{ FSCTL_SET_COMPRESSION,
		  "SET_COMPRESSION" },
		{ FSCTL_SET_OBJECT_ID,
		  "SET_OBJECT_ID" },
		{ FSCTL_CREATE_OR_GET_OBJECT_ID,
		  "CREATE_OR_GET_OBJECT_ID" },
		{ FSCTL_DELETE_OBJECT_ID,
		  "DELETE_OBJECT_ID" },
		{ FSCTL_GET_REPARSE_POINT,
		  "GET_REPARSE_POINT" },
		{ FSCTL_SET_REPARSE_POINT,
		  "SET_REPARSE_POINT" },
		{ FSCTL_DELETE_REPARSE_POINT,
		  "DELETE_REPARSE_POINT" },
		{ FSCTL_SET_INTEGRITY_INFORMATION,
		 "SET_INTEGRITY_INFORMATION" },
		{ FSCTL_OFFLOAD_READ,
		 "OFFLOAD_READ" },
		{ FSCTL_OFFLOAD_WRITE,
		 "OFFLOAD_WRITE" },
		{ FSCTL_DUP_EXTENTS_TO_FILE,
		 "DUP_EXTENTS_TO_FILE" },
		{ FSCTL_GET_SHADOW_COPY_DATA,
		 "GET_SHADOW_COPY_DATA" },
		{ FSCTL_SRV_COPYCHUNK,
		 "COPYCHUNK" },
		{ FSCTL_SRV_COPYCHUNK_WRITE,
		 "COPYCHUNK_WRITE" },
	};
	NTSTATUS result;
	const char *parsed = NULL;
	int i, error;
	tn_audit_conf_t *config = NULL;
	tn_audit_ext_t *fsp_ext = NULL;
	struct json_object msg, entry, jsfn;
	bool ok;

	result = SMB_VFS_NEXT_FSCTL(handle,
				    fsp,
				    ctx,
				    function,
				    req_flags,
				    _in_data,
				    in_len,
				    _out_data,
				    max_out_len,
				    out_len);

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return result);
	fsp_ext = (tn_audit_ext_t *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (fsp_ext == NULL) {
		return result;
	}

	for (i = 0; i < ARRAY_SIZE(fn_types); i++) {
		if (fn_types[i].value == function) {
			parsed = fn_types[i].name;
		}
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		return result;
	}

	jsfn = json_new_object();
	if (json_is_invalid(&jsfn)) {
		goto cleanup;
	}

	ok = add_map_to_object(function, "raw", &jsfn);
	if (!ok) {
		json_free(&jsfn);
		goto cleanup;
	}

	error = json_add_string(&jsfn, "parsed", parsed);
	if (error) {
		json_free(&jsfn);
		goto cleanup;
	}

	error = json_add_object(&entry, "function", &jsfn);
	if (error) {
		json_free(&jsfn);
		goto cleanup;
	}

	ok = add_file_to_object(fsp->fsp_name, fsp_ext, "file", FILE_ADD_HANDLE, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = add_result_ntstatus(result, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_FSCTL, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = tn_audit_do_log(config, &msg);
	if (!ok) {
		DBG_ERR("Failed to send log message\n");
	}

cleanup:
	json_free(&msg);
	json_free(&entry);
	return result;
}

enum tn_setattr_tp { TN_SETATTR_DOSMODE, TN_SETATTR_TIME };

static void log_setattr_common(vfs_handle_struct *handle,
			       files_struct *fsp,
			       enum tn_setattr_tp attr_type,
			       tn_rval_t rv,
			       struct smb_file_time *ft,
			       uint32_t dosmode)
{
	bool ok;
	int error;
	tn_audit_conf_t *config = NULL;
	tn_audit_ext_t *fsp_ext = NULL;
	struct json_object msg, entry, jsts;
	struct timeval tval;

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return);
	fsp_ext = (tn_audit_ext_t *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (fsp_ext == NULL) {
		return;
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		return;
	}

	switch (attr_type) {
	case TN_SETATTR_DOSMODE:
		error = json_add_string(&entry, "attr_type", "DOSMODE");
		if (error) {
			goto cleanup;
		}

		ok = add_map_to_object(dosmode, "dosmode", &entry);
		if (!ok) {
			goto cleanup;
		}

		error = json_add_string(&entry, "ts", NULL);
		if (error) {
			goto cleanup;
		}
		ok = add_result_unix(rv.error ? errno : 0, &msg, &entry);
		if (!ok) {
			goto cleanup;
		}
		break;

	case TN_SETATTR_TIME:
		error = json_add_string(&entry, "attr_type", "TIMESTAMP");
		if (error) {
			goto cleanup;
		}

		error = json_add_string(&entry, "dosmode", NULL);
		if (error) {
			goto cleanup;
		}

		jsts = json_new_object();
		if (json_is_invalid(&jsts)) {
			goto cleanup;
		}

		tval = convert_timespec_to_timeval(ft->create_time);
		ok = add_timestamp(&jsts, "btime", &tval);
		if (!ok) {
			json_free(&jsts);
			goto cleanup;
		}

		tval = convert_timespec_to_timeval(ft->atime);
		ok = add_timestamp(&jsts, "atime", &tval);
		if (!ok) {
			json_free(&jsts);
			goto cleanup;
		}

		tval = convert_timespec_to_timeval(ft->mtime);
		ok = add_timestamp(&jsts, "mtime", &tval);
		if (!ok) {
			json_free(&jsts);
			goto cleanup;
		}

		tval = convert_timespec_to_timeval(ft->ctime);
		ok = add_timestamp(&jsts, "ctime", &tval);
		if (!ok) {
			json_free(&jsts);
			goto cleanup;
		}

		error = json_add_object(&entry, "ts", &jsts);
		if (error) {
			json_free(&jsts);
			goto cleanup;
		}

		ok = add_result_ntstatus(rv.status, &msg, &entry);
		if (ok) {
			goto cleanup;
		}
		break;
	default:
		smb_panic("unexpected attr_type");
	};

	ok = add_file_to_object(fsp->fsp_name, fsp_ext, "file", FILE_ADD_HANDLE, &entry);
	if (!ok) {
		goto cleanup;
	}

	ok = format_log_entry(handle, config, TN_OP_SET_ATTR, &msg, &entry);
	if (!ok) {
		goto cleanup;
	}

	tn_audit_do_log(config, &msg);

cleanup:
	json_free(&msg);
	json_free(&entry);
	return;
}

static NTSTATUS tn_audit_fset_dos_attributes(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     uint32_t dosmode)
{
	tn_rval_t rv;

	rv.status = SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle, fsp, dosmode);
	log_setattr_common(handle, fsp, TN_SETATTR_DOSMODE, rv, NULL, dosmode);
	return rv.status;
}

static int tn_audit_fntimes(vfs_handle_struct *handle,
			    files_struct *fsp,
			    struct smb_file_time *ft)
{
	tn_rval_t rv;

	rv.error = SMB_VFS_NEXT_FNTIMES(handle, fsp, ft);
	log_setattr_common(handle, fsp, TN_SETATTR_TIME, rv, ft, 0);
	return rv.error;
}

static NTSTATUS tn_audit_fset_nt_acl(vfs_handle_struct *handle,
				     files_struct *fsp,
				     uint32_t secinfo_sent,
				     const struct security_descriptor *psd)
{
	/*
	 * Sample `event_data`
	 *
	 *  {
	 *    "file": {
	 *      "handle": {
	 *        "type": "DEV_INO",
	 *        "value": "44:14:0"
	 *      }
	 *    },
	 *    "secinfo": "0x00000004",
	 *    "sd": "O:S-1-5-21-4111435917-4205493354-991704561-20065"\
	 *      "G:S-1-22-2-0"\
	 *      "D:PAI"\
	 *      "(A;;0x001301ff;;;S-1-22-2-0)"\
         *      "(A;;0x001f01ff;;;S-1-5-21-4111435917-4205493354-991704561-20)"\
         *      "(A;;0x001f01ff;;;S-1-5-21-4111435917-4205493354-991704561-205)",
	 *    "result": {
	 *      "type": "NTSTATUS",
	 *      "value_raw": 0,
	 *      "value_parsed": "SUCCESS"
	 *    },
	 *    "vers": {"major": 0, "minor": 1}
	 *  }
	 *
	 * NOTE: `sd` is SDDL-formatted string
	 */
	NTSTATUS result = NT_STATUS_AUDIT_FAILED;
	char *sd = NULL;
	bool ok;
	int error;
	tn_audit_conf_t *config = NULL;
	tn_audit_ext_t *fsp_ext = NULL;
	struct json_object msg, entry, jsts;

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return result);
	fsp_ext = (tn_audit_ext_t *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	sd = sddl_encode(talloc_tos(), psd, get_global_sam_sid());
	if (sd == NULL) {
		return result;
	}

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		DBG_ERR("Failed to generate audit message.\n");
		return result;
	}

	if (fsp_ext == NULL) {
		ok = add_file_to_object(fsp->fsp_name,
					fsp_ext,
					"file",
					FILE_ADD_NAME | FILE_ADD_TYPE,
					&entry);
	} else {
		ok = add_file_to_object(fsp->fsp_name,
					fsp_ext,
					"file",
					FILE_ADD_HANDLE,
					&entry);
	}
	if (!ok) {
		DBG_ERR("Failed to add file handle to audit message\n");
		goto cleanup;
	}

	ok = add_map_to_object(secinfo_sent, "secinfo", &entry);
	if (!ok) {
		DBG_ERR("Failed to add secinfo_sent to audit message\n");
		goto cleanup;
	}

	error = json_add_string(&entry, "sd", sd);
	if (error) {
		DBG_ERR("Failed to add sd to audit message\n");
		goto cleanup;
	}

	result = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, secinfo_sent, psd);
	SMB_ASSERT(add_result_ntstatus(result, &msg, &entry));
	SMB_ASSERT(format_log_entry(handle,
				    config,
				    TN_OP_SET_ACL,
				    &msg,
				    &entry));
	tn_audit_do_log(config, &msg);

cleanup:
	TALLOC_FREE(sd);
	json_free(&msg);
	json_free(&entry);
	return result;
}

static int tn_audit_set_quota(struct vfs_handle_struct *handle,
			      enum SMB_QUOTA_TYPE qtype, unid_t id,
			      SMB_DISK_QUOTA *qt)
{
	/*
	 * Sample `event_data`
	 *
	 *  {
	 *    "qt": {
	 *      "type": "USER",
	 *      "bsize": "1024",
	 *      "softlimit": "9",
	 *      "hardlimit": "9",
	 *      "isoftlimit": "NO_LIMIT",
	 *      "ihardlimit": "NO_LIMIT",
	 *    },
	 *    "result": {
	 *      "type": "UNIX",
	 *      "value_raw": 0,
	 *      "value_parsed": "SUCCESS"
	 *    },
	 *    "vers": {"major": 0, "minor": 1}
	 *  }
	 */
	int result = -1;
	bool ok;
	tn_audit_conf_t *config = NULL;
	struct json_object msg, entry;

	SMB_VFS_HANDLE_GET_DATA(handle, config, tn_audit_conf_t, return result);

	ok = init_json_msg(&msg, &entry);
	if (!ok) {
		return result;
	}

	result = SMB_VFS_NEXT_SET_QUOTA(handle, qtype, id, qt);

	SMB_ASSERT(add_smb_quota_to_obj(qtype, id, qt, &entry));
	SMB_ASSERT(add_result_unix(result, &msg, &entry));
	SMB_ASSERT(format_log_entry(handle,
				    config,
				    TN_OP_SET_QUOTA,
				    &msg,
				    &entry));
	tn_audit_do_log(config, &msg);

	json_free(&msg);
	json_free(&entry);
	return result;
}

static struct vfs_fn_pointers vfs_truenas_audit_fns = {
	.connect_fn = tn_audit_connect,
	.disconnect_fn = tn_audit_disconnect,
	.create_file_fn = tn_audit_create_file,
	.close_fn = tn_audit_close,
	.pread_fn = tn_audit_pread,
	.pread_send_fn = tn_audit_pread_send,
	.pread_recv_fn = tn_audit_pread_recv,
	.pwrite_fn = tn_audit_pwrite,
	.pwrite_send_fn = tn_audit_pwrite_send,
	.pwrite_recv_fn = tn_audit_pwrite_recv,
	.unlinkat_fn = tn_audit_unlinkat,
	.renameat_fn = tn_audit_renameat,
	.fsctl_fn = tn_audit_fsctl,
	.fset_dos_attributes_fn = tn_audit_fset_dos_attributes,
	.fntimes_fn = tn_audit_fntimes,
	.fset_nt_acl_fn = tn_audit_fset_nt_acl,
	.set_quota_fn = tn_audit_set_quota,
	.offload_read_send_fn = tn_audit_offload_read_send,
	.offload_read_recv_fn = tn_audit_offload_read_recv,
	.offload_write_send_fn = tn_audit_offload_write_send,
	.offload_write_recv_fn = tn_audit_offload_write_recv,
};

static_decl_vfs;
NTSTATUS vfs_truenas_audit_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, MODULE_NAME,
					&vfs_truenas_audit_fns);

	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_tnaudit_debug_level = debug_add_class("truenas_audit");
	if (vfs_tnaudit_debug_level == -1) {
		vfs_tnaudit_debug_level = DBGC_VFS;
		DBG_ERR("vfs_tn_audit: Couldn't register custom "
			"debugging class!\n");
	} else {
		DBG_DEBUG("vfs_tnaudit_init: Debug class number of '%s': %d\n",
			  "truenas_audit", vfs_tnaudit_debug_level);
	}
	return ret;
}
