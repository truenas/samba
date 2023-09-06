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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/param/loadparm.h"
#include "lib/util/tevent_unix.h"
#include "libcli/security/sddl.h"
#include "passdb/machine_sid.h"

#include <jansson.h>
#include "audit_logging.h"
#include "libsmbjson/smb_json.h"
#include "vfs_truenas_audit.h"

bool tn_init_json_msg(struct json_object *wrapper,
		      struct json_object *data)
{
	/*
	 * This initializes the JSON "msg" component of
	 * syslog message. It is called within all VFS
	 * functions in this module.
	 */
	wrapper->root = json_object();
	if (wrapper->root == NULL) {
		wrapper->valid = false;
		return false;
	}

	data->root = json_object();
	if (data->root == NULL) {
		data->valid = false;
		json_free(wrapper);
		return false;
	}

	wrapper->valid = true;
	data->valid = true;

	return true;
}

bool tn_add_connection_info_to_obj(const char *service,
				   const connection_struct *conn,
				   struct json_object *jsobj)
{
	/*
	 * The only consumer is in SMB_VFS_CONNECT. A copy of this informaiton
	 * is stored in the VFS handle struct private data so that it is
	 * available in all VFS functions in this module.
	 */
	int error;
	bool ok;
	char buf[22];

	if (json_is_invalid(jsobj)) {
		DBG_ERR("Unable to add connection info to object. "
			"Target object is invalid\n");
		return false;
	}

	ok = json_add_vers(jsobj, "vers", SVC_MAJ_VER, SVC_MIN_VER);
	if (!ok) {
		return false;
	}

	error = json_add_string(jsobj, "service", service);
	if (error) {
		return false;
	}

	snprintf(buf, sizeof(buf), "%lu", conn->vuid);
	error = json_add_string(jsobj, "session_id", buf);
	if (error) {
		return false;
	}

	// conn->tcon may be theoretically be NULL.
	// Set tcon_id to -1 in this case
	snprintf(buf, sizeof(buf), "%u",
		 conn->tcon ? conn->tcon->local_id : -1);

	error = json_add_string(jsobj, "tcon_id", buf);
	if (error) {
		return false;
	}

	return true;
}

static
bool tn_add_snapshot_to_object(struct json_object *jsobj,
			       const char *key,
			       NTTIME twrp,
			       const char *location)
{
	int error;
	time_t t;
	struct tm tm;
	struct tm *ptm = NULL;
	fstring tstr;
	ssize_t slen;

	if (twrp == 0) {
		error = json_add_string(jsobj, key, NULL);
		if (error) {
			return false;
		}
		return true;
	}
	t = nt_time_to_unix(twrp);
	ptm = gmtime_r(&t, &tm);
	if (ptm == NULL) {
		DBG_ERR("%s: failed to convert twrp to tm struct\n",
			location);
		return false;
	}

	slen = strftime(tstr, sizeof(tstr), GMT_FORMAT, &tm);
	if (slen == 0) {
		DBG_ERR("%s: strftime() failed\n", location);
		return false;
	}

	error = json_add_string(jsobj, key, tstr);

	return error ? false : true;
}

static
bool tn_add_file_type_to_object(struct json_object *jsobj,
				const char *key,
				mode_t ftype,
				const char *location)
{
	static const struct enum_list file_types[] = {
		{ S_IFBLK, "BLOCK" },
		{ S_IFCHR, "CHARACTER" },
		{ S_IFIFO, "FIFO" },
		{ S_IFREG, "REGULAR" },
		{ S_IFDIR, "DIRECTORY" },
		{ S_IFLNK, "SYMLINK" },
	};
	bool ok;

	ok = json_add_enum_list_find(jsobj, key,
				     ftype,
				     ARRAY_SIZE(file_types),
				     file_types,
				     NULL);
	if (ok) {
		return true;
	}

	if (errno == ENOENT) {
		DBG_ERR("%s: %u: unknown file type\n", location, ftype);
	} else {
		DBG_ERR("%s: %u: lookup of file type failed\n", location, ftype);
	}

	return false;
}

bool _tn_add_file_to_object(const struct smb_filename *fname,
			    const tn_audit_ext_t *fsp_ext,
			    const char *key,
			    uint32_t flags,
			    struct json_object *jsobj,
			    const char *location)
{
	int error;
	bool ok;
	struct json_object wrapper, fhandle;
	const char *namekey = flags & FILE_NAME_IS_PATH ? "path" : "name";

	if (json_is_invalid(jsobj)) {
		DBG_ERR("%s: Unable to add file information to object. "
			"Target object is invalid\n", location);
		return false;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		DBG_ERR("%s: Failed to create JSON object for file wrapper\n",
			location);
		return false;
	}

	if (flags & FILE_ADD_TYPE) {
		mode_t ftype = fname->st.st_ex_mode & S_IFMT;
		ok = tn_add_file_type_to_object(&wrapper, "type", ftype,
						location);
		if (!ok) {
			goto fail;
		}
	}

	if (flags & FILE_ADD_NAME) {
		error = json_add_string(&wrapper,
					namekey,
					fname->base_name);
		if (error) {
			DBG_ERR("%s: Failed to add name to file object\n",
				location);
			goto fail;
		}

		error = json_add_string(&wrapper,
					"stream",
					fname->stream_name);
		if (error) {
			DBG_ERR("%s: Failed to add stream to file object\n",
				location);
			goto fail;
		}

		ok = tn_add_snapshot_to_object(&wrapper,
					       "snap",
					       fname->twrp,
					       location);
		if (!ok) {
			goto fail;
		}
	}

	if (flags & FILE_ADD_HANDLE) {
		SMB_ASSERT(fsp_ext != NULL);

		fhandle = json_new_object();
		if (json_is_invalid(&fhandle)) {
			goto fail;
		}

		error = json_add_string(&fhandle, "type", "DEV_INO");
		if (error) {
			json_free(&fhandle);
			goto fail;
		}

		error = json_add_string(&fhandle,
					"value",
					fsp_ext->fid_str.buf);
		if (error) {
			json_free(&fhandle);
			goto fail;
		}

		error = json_add_object(&wrapper, "handle", &fhandle);
		if (error) {
			return false;
		}
	}

	error = json_add_object(jsobj, key, &wrapper);
	if (error) {
		return false;
	}

	return true;
fail:
	json_free(&wrapper);
	return false;
}

static bool add_quota_entry(uint64_t val,
			    const char *key,
			    struct json_object *jsobj)
{
	int error;

	switch (val) {
	case SMB_QUOTAS_NO_LIMIT:
		error = json_add_string(jsobj, key, "NO_LIMIT");
		break;
	case SMB_QUOTAS_NO_SPACE:
		error = json_add_string(jsobj, key, "NO_SPACE");
		break;
	default:
		return json_add_u64_to_object(jsobj, key, val);
	};

	return error ? false : true;
}

bool tn_add_smb_quota_to_obj(enum SMB_QUOTA_TYPE qtype,
			     unid_t id,
			     SMB_DISK_QUOTA *qt,
			     struct json_object *jsobj)
{
	bool ok = false;
	int error, xid;
	struct json_object jsqt;
	const char *qtype_str = NULL;

	if (json_is_invalid(jsobj)) {
		DBG_ERR("Unable to add quota to object. "
			"Target object is invalid\n");
		return false;
	}

	jsqt = json_new_object();
	if (json_is_invalid(&jsqt)) {
		return false;
	}

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		xid = id.uid == -1 ? geteuid() : id.uid;
		qtype_str = "USER";
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		xid = id.gid == -1 ? getegid() : id.gid;
		qtype_str = "GROUP";
		break;
	default:
		smb_panic("Unknown quota type");
	};

	error = json_add_string(&jsqt, "type", qtype_str);
	if (error) {
		goto fail;
	}

	ok = json_add_u64_to_object(&jsqt, "bsize", qt->bsize);
	if (!ok) {
		goto fail;
	}

	ok = add_quota_entry(qt->softlimit, "softlimit", &jsqt);
	if (!ok) {
		goto fail;
	}

	ok = add_quota_entry(qt->hardlimit, "hardlimit", &jsqt);
	if (!ok) {
		goto fail;
	}

	ok = add_quota_entry(qt->isoftlimit, "isoftlimit", &jsqt);
	if (!ok) {
		goto fail;
	}

	ok = add_quota_entry(qt->ihardlimit, "ihardlimit", &jsqt);
	if (!ok) {
		goto fail;
	}

	error = json_add_object(jsobj, "qt", &jsqt);
	if (error) {
		return false;
	}
	return true;

fail:
	json_free(&jsqt);
	return false;
}

bool tn_add_create_payload(struct smb_filename *smb_fname,
			   tn_audit_ext_t *fsp_ext,
			   uint32_t js_flags,
			   uint32_t access_mask,
			   uint32_t share_access,
			   uint32_t create_disposition,
			   uint32_t create_options,
			   uint32_t file_attributes,
			   struct security_descriptor *psd,
			   struct json_object *jsobj)
{
	const char *str_create_disposition;
	const char *str_file_type;
	char *sd = NULL;
	int error;
	struct json_object params;
	bool ok;

	if (json_is_invalid(jsobj)) {
		DBG_ERR("Unable to add create payload to object. "
			"Target object is invalid\n");
		return false;
	}

	switch (create_disposition) {
	case FILE_SUPERSEDE:
		str_create_disposition = "SUPERSEDE";
		break;
	case FILE_OVERWRITE_IF:
		str_create_disposition = "OVERWRITE_IF";
		break;
	case FILE_OPEN:
		str_create_disposition = "OPEN";
		break;
	case FILE_OVERWRITE:
		str_create_disposition = "OVERWRITE";
		break;
	case FILE_CREATE:
		str_create_disposition = "CREATE";
		break;
	case FILE_OPEN_IF:
		str_create_disposition = "OPEN_IF";
		break;
	default:
		str_create_disposition = "UNKNOWN";
	}

	params = json_new_object();
	if (json_is_invalid(&params)) {
		return false;
	}

	ok = json_add_map_to_object(&params, "DesiredAccess", access_mask);
	if (!ok) {
		goto fail;
	}

	ok = json_add_map_to_object(&params, "FileAttributes", file_attributes);
	if (!ok) {
		goto fail;
	}

	ok = json_add_map_to_object(&params, "ShareAccess", share_access);
	if (!ok) {
		goto fail;
	}

	error = json_add_string(&params, "CreateDisposition",
				str_create_disposition);
	if (error) {
		goto fail;
	}

	ok = json_add_map_to_object(&params, "CreateOptions", create_options);
	if (!ok) {
		goto fail;
	}

	error = json_add_object(jsobj, "parameters", &params);
	if (error) {
		TALLOC_FREE(sd);
		return false;
	}

	if (psd) {
		sd = sddl_encode(talloc_tos(), psd, get_global_sam_sid());
		if (sd) {
			error = json_add_string(jsobj, "sd", sd);
			if (error) {
				goto fail;
			}
		}
	}
	error = json_add_string(jsobj, "file_type",
				create_options & FILE_DIRECTORY_FILE?
				"DIRECTORY":
				"FILE");
	if (error) {
		goto fail;
	}

	ok = tn_add_file_to_object(smb_fname, fsp_ext, "file", js_flags, jsobj);
	if (!ok) {
		goto fail;
	}

	TALLOC_FREE(sd);
	return true;

fail:
	TALLOC_FREE(sd);
	json_free(&params);
	return false;
}

bool _tn_add_result_unix(const int err,
			 struct json_object *root,
			 struct json_object *body,
			 const char *location)
{
	bool ok;
	int error;
	struct json_object object;

	object = json_new_object();
	if (json_is_invalid(&object)) {
		DBG_ERR("%s: Failed to create new JSON object for result\n",
			location);
		return false;
	}

	ok =  _json_add_result_unix(&object, err, location);
	if (!ok) {
		json_free(&object);
		return false;
	}

	error = json_add_bool(root, "success", err == 0);
	if (error) {
		json_free(&object);
		return false;
	}

	error = json_add_object(body, "result", &object);
	if (error) {
		DBG_ERR("%s: Failed to add result object to audit message body\n",
			location);
		return false;
	}

	return ok;
}

bool _tn_add_result_ntstatus(const NTSTATUS status,
			     struct json_object *root,
			     struct json_object *body,
			     const char *location)
{
	bool ok;
	int error;
	struct json_object object;

	object = json_new_object();
	if (json_is_invalid(&object)) {
		DBG_ERR("%s: Failed to create new JSON object for result\n",
			location);
		return false;
	}

	ok =  _json_add_result_ntstatus(&object, status, location);
	if (!ok) {
		json_free(&object);
		return false;
	}

	error = json_add_bool(root, "success", NT_STATUS_IS_OK(status));
	if (error) {
		json_free(&object);
		return false;
	}

	error = json_add_object(body, "result", &object);
	if (error) {
		DBG_ERR("%s: Failed to add result object to audit message body\n",
			location);
		return false;
	}

	return ok;
}

bool _tn_format_log_entry(vfs_handle_struct *handle,
			  tn_audit_conf_t *conf,
			  tn_op_t op,
			  struct json_object *root,
			  struct json_object *entry_data,
			  const char *location)
{
	bool ok;
	int i, error;
	char buf[22], *data = NULL;
	struct GUID msgid;

	for (i = 0; i < ARRAY_SIZE(tn_ops); i++) {
		if (tn_ops[i].type != op) {
			continue;
		}

		msgid = GUID_random();

		error = json_add_guid(root, "aid", &msgid);
		if (error) {
			DBG_ERR("[%s]: failed to add audit event GUID\n",
				location);
			return false;
		}

		ok = json_add_vers(root, "vers", DEF_MAJ_VER, DEF_MIN_VER);
		if (!ok) {
			DBG_ERR("[%s]: failed to add audit event version\n",
				location);
			return false;
		}

		ok = json_add_inet_addr(root, "addr",
					handle->conn->sconn->remote_address);
		if (!ok) {
			DBG_ERR("[%s]: failed to add audit event address\n",
				location);
			return false;
		}

		error = json_add_string(root, "user", conf->conn_info.user);
		if (error) {
			DBG_ERR("[%s]: failed to add audit event user\n",
				location);
			return false;
		}

		error = json_add_string(root, "sess", conf->conn_info.sess);
		if (error) {
			DBG_ERR("[%s]: failed to add audit event session\n",
				location);
			return false;
		}

		ok = json_add_time(root, "time", NULL, 0);
		if (!ok) {
			DBG_ERR("[%s]: failed to add audit event timestamp\n",
				location);
			return false;
		}

		error = json_add_string(root, "svc", "SMB");
		if (error) {
			DBG_ERR("[%s]: failed to add audit event service "
				"identifier\n", location);
			return false;
		}

		ok = json_add_vers(entry_data, "vers", tn_ops[i].maj_ver,
				 tn_ops[i].min_ver);
		if (!ok) {
			DBG_ERR("[%s]: failed to add audit entry_data version\n",
				location);
			return false;
		}

		error = json_add_string(root, "svc_data", conf->js_connection);
		if (error) {
			DBG_ERR("[%s]: failed to add audit svc_data\n",
				location);
			return false;
		}

		error = json_add_string(root, "event", tn_ops[i].name);
		if (error) {
			DBG_ERR("[%s]: failed to add audit event name\n",
				location);
			return false;
		}

		data = json_to_string(conf, entry_data);
		if (data == NULL) {
			DBG_ERR("[%s]: failed to convert entry_data to "
				"string\n", location);
			return false;
		}

		error = json_add_string(root, "event_data", data);
		TALLOC_FREE(data);
		if (error) {
			DBG_ERR("[%s]: failed to add audit event_data\n",
				location);
			return false;
		}

		return true;
	}

	DBG_ERR("[%s]: Failed to map op 0x%08x to optable entry\n",
		location, op);
	return false;
}
