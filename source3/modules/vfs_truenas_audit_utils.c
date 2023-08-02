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
#include "vfs_truenas_audit.h"

bool dup_json_object(struct json_object *src,
		     const char *key,
		     struct json_object *dst)
{
	/*
	 * Make a deep copy of the provided `src` JSON object
	 * and add it to the specified `dst` JSON object.
	 */
	struct json_object tmp;
	int error;

	tmp = (struct json_object){
		.valid = true,
		.root = json_deep_copy(src->root)
	};

	if (tmp.root == NULL) {
		return false;
	}

	error = json_add_object(dst, key, &tmp);
	if (error) {
		json_free(&tmp);
		return false;
	}

	return true;
}

bool init_json_msg(struct json_object *wrapper,
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

bool add_json_gid_array(struct json_object *object,
			const char *key,
			uint32_t ngroups,
			gid_t *groups)
{
	uint32_t i;
	int err;
	json_t *jsarr = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add groups array to object. "
			"Target object is invalid\n");
		return false;
	}

	jsarr = json_array();
	if (jsarr == NULL) {
		return false;
	}

	for (i = 0; i < ngroups; i++) {
		json_t *jsgid = NULL;
		jsgid = json_integer(groups[i]);
		if (jsgid == NULL) {
			DBG_ERR("%u: ailed to create JSON integer for gid\n",
				groups[i]);
			json_decref(jsarr);
			return false;
		}

		err = json_array_append_new(jsarr, jsgid);
		if (err) {
			json_decref(jsarr);
			json_decref(jsgid);
			return false;
		}
	}

	err = json_object_set_new(object->root, key, jsarr);
	if (err) {
		json_decref(jsarr);
		DBG_ERR("Unable to add gid array to object.\n");
		return false;
	}

	return true;
}

static
bool add_version(struct json_object *object,
		 const char *key,
		 int vers_major,
		 int vers_minor)
{
	struct json_object vers;
	int err;

	vers = json_new_object();
	if (json_is_invalid(&vers)) {
		return false;
	}

	err = json_add_int(&vers, "major", vers_major);
	if (err) {
		json_free(&vers);
		return false;
	}

	err = json_add_int(&vers, "minor", vers_minor);
	if (err) {
		json_free(&vers);
		return false;
	}

	err = json_add_object(object, key, &vers);
	if (err) {
		json_free(&vers);
		return false;
	}

	return true;
}

bool add_timestamp(struct json_object *object,
		   const char *key,
		   struct timeval *tvp)
{
	char buffer[40];
	char ts[65];
	char tz[10];
	struct tm *tm_info, tmbuf;
	struct timeval tv;
	int r;
	int ret;

	if (json_is_invalid(object)) {
		return false;
	}

	if (tvp == NULL) {
		r = gettimeofday(&tv, NULL);
		if (r) {
			DBG_ERR("Unable to get time of day: (%d) %s\n",
				errno,
				strerror(errno));
			return false;
		}
		tvp = &tv;
	}

	tm_info = gmtime_r(&tvp->tv_sec, &tmbuf);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine UTC time\n");
		return false;
	}

	strftime(buffer, sizeof(buffer)-1, "%Y-%m-%d %T", tm_info);
	snprintf(ts, sizeof(ts), "%s.%06ldZ", buffer, tv.tv_usec);

	ret = json_add_string(object, key, ts);
	if (ret != 0) {
		DBG_ERR("Unable to add time stamp to JSON object\n");
	}
	return true;
}

bool add_inet_addr(struct json_object *object,
		   const char *key,
		   const struct tsocket_address *addr)
{
	char *addr_s = NULL;
	int error;

	if (addr == NULL) {
		error = json_add_string(object, key, NULL);
		if (error) {
			return false;
		}
		return true;
	}

	addr_s = tsocket_address_inet_addr_string(addr, talloc_tos());
	if (addr_s == NULL) {
		DBG_ERR("Out of memory adding address.\n");
		return false;
	}

	error = json_add_string(object, key, addr_s);
	TALLOC_FREE(addr_s);
	return error ? false : true;
}

bool add_connection_info_to_obj(const char *service,
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

	ok = add_version(jsobj, "vers", SVC_MAJ_VER, SVC_MIN_VER);
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

bool add_unix_token_to_obj(const struct auth_session_info *sess,
			   struct json_object *jsobj)
{
	int error;
	bool ok;
	struct json_object unix_token;

	unix_token = json_new_object();
	if (json_is_invalid(&unix_token)) {
		return false;
	}

	error = json_add_string(&unix_token,
				"username",
				sess->unix_info->sanitized_username);
	if (error) {
		goto fail;
	}

	error = json_add_int(&unix_token, "uid", sess->unix_token->uid);
	if (error) {
		goto fail;
	}

	error = json_add_int(&unix_token, "gid", sess->unix_token->gid);
	if (error) {
		goto fail;
	}

	ok = add_json_gid_array(&unix_token, "groups",
				sess->unix_token->ngroups,
				sess->unix_token->groups);
	if (!ok) {
		goto fail;
	}

	error = json_add_object(jsobj, "unix_token", &unix_token);
	if (error) {
		return false;
	}

	return true;
fail:
	json_free(&unix_token);
	return false;
}

bool add_client_info_to_obj(const struct smbd_server_connection *sconn,
			    struct json_object *jsobj)
{
	int error;

	error = json_add_string(jsobj, "host", sconn->remote_hostname);

	return error ? false : true;
}

bool add_snapshot_to_object(struct json_object *jsobj,
			    const char *key,
			    NTTIME twrp)
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
		return false;
	}

	slen = strftime(tstr, sizeof(tstr), GMT_FORMAT, &tm);
	if (slen == 0) {
		return false;
	}

	error = json_add_string(jsobj, key, tstr);

	return error ? false : true;
}

bool add_file_type_to_object(struct json_object *jsobj,
			     const char *key,
			     mode_t ftype)
{
	static const struct enum_list file_types[] = {
		{ S_IFBLK, "BLOCK" },
		{ S_IFCHR, "CHARACTER" },
		{ S_IFIFO, "FIFO" },
		{ S_IFREG, "REGULAR" },
		{ S_IFDIR, "DIRECTORY" },
		{ S_IFLNK, "SYMLINK" },
	};
	int error, i;

	for (i = 0; i < ARRAY_SIZE(file_types); i++) {
		if (file_types[i].value == ftype) {
			error = json_add_string(jsobj,
						key,
						file_types[i].name);
			return error ? false : true;
		}
	}

	DBG_ERR("%u: unknown file type\n", ftype);
	return false;
}

bool add_file_to_object(const struct smb_filename *fname,
			const tn_audit_ext_t *fsp_ext,
			const char *key,
			uint32_t flags,
			struct json_object *jsobj)
{
	int error;
	bool ok;
	struct json_object wrapper, fhandle;
	const char *namekey = flags & FILE_NAME_IS_PATH ? "path" : "name";

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		return false;
	}

	if (flags & FILE_ADD_TYPE) {
		mode_t ftype = fname->st.st_ex_mode & S_IFMT;
		ok = add_file_type_to_object(&wrapper, "type", ftype);
		if (!ok) {
			goto fail;
		}
	}

	if (flags & FILE_ADD_NAME) {
		error = json_add_string(&wrapper,
					namekey,
					fname->base_name);
		if (error) {
			goto fail;
		}

		error = json_add_string(&wrapper,
					"stream",
					fname->stream_name);
		if (error) {
			goto fail;
		}

		ok = add_snapshot_to_object(&wrapper,
					    "snap",
					    fname->twrp);
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
			json_free(&fhandle);
			goto fail;
		}
	}

	error = json_add_object(jsobj, key, &wrapper);
	if (error) {
		goto fail;
	}

	return true;
fail:
	json_free(&wrapper);
	return false;
}

static bool add_conv_to_object(uint64_t val,
			       const char *name,
			       const char *map,
			       struct json_object *jsobj)
{
	int error;
	char buf[22];

	snprintf(buf, sizeof(buf), map, val);
	error = json_add_string(jsobj, name, buf);
	if (error) {
		return false;
	}

	return true;
}

bool add_map_to_object(uint32_t attr,
		       const char *name,
		       struct json_object *jsobj)
{
	return add_conv_to_object(attr, name, "0x%08x", jsobj);
}

bool add_u64_to_object(uint64_t val,
		       const char *name,
		       struct json_object *jsobj)
{
	return add_conv_to_object(val, name, "%lu", jsobj);
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
		return add_u64_to_object(val, key, jsobj);
	};

	return error ? false : true;
}

bool add_smb_quota_to_obj(enum SMB_QUOTA_TYPE qtype,
			  unid_t id,
			  SMB_DISK_QUOTA *qt,
			  struct json_object *jsobj)
{
	bool ok = false;
	int error, xid;
	struct json_object jsqt;
	const char *qtype_str = NULL;

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

	ok = add_u64_to_object(qt->bsize, "bsize", &jsqt);
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
		goto fail;
	}
	return true;

fail:
	json_free(&jsqt);
	return false;
}

bool add_create_payload(struct smb_filename *smb_fname,
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

	ok = add_map_to_object(access_mask, "DesiredAccess", &params);
	if (!ok) {
		goto fail;
	}

	ok = add_map_to_object(file_attributes, "FileAttributes", &params);
	if (!ok) {
		goto fail;
	}

	ok = add_map_to_object(share_access, "ShareAccess", &params);
	if (!ok) {
		goto fail;
	}

	error = json_add_string(&params, "CreateDisposition",
				str_create_disposition);
	if (error) {
		goto fail;
	}

	ok = add_map_to_object(create_options, "CreateOptions", &params);
	if (!ok) {
		goto fail;
	}

	error = json_add_object(jsobj, "parameters", &params);
	if (error) {
		goto fail;
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

	ok = add_file_to_object(smb_fname, fsp_ext, "file", js_flags, jsobj);
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

static bool add_result_common(const char *res_type,
			      int err,
			      const char *err_str,
			      bool ok,
			      struct json_object *root,
			      struct json_object *body)
{
	int error;
	struct json_object result;

	result = json_new_object();
	if (json_is_invalid(&result)) {
		return false;
	}

	error = json_add_string(&result, "type", res_type);
	if (error) {
		goto fail;
	}

	error = json_add_int(&result, "value_raw", err);
	if (error) {
		goto fail;
	}

	error = json_add_string(&result, "value_parsed",
				err ? err_str : "SUCCESS");
	if (error) {
		goto fail;
	}

	error = json_add_object(body, "result", &result);
	if (error) {
		return false;
	}

	error = json_add_bool(root, "success", ok);
	if (error) {
		return false;
	}

	return true;

fail:
	json_free(&result);
	return false;
}

bool add_result_unix(const int err,
		     struct json_object *root,
		     struct json_object *body)
{
	return add_result_common("UNIX",
				 err,
				 strerror(err),
				 err == 0,
				 root,
				 body);
}

bool add_result_ntstatus(const NTSTATUS status,
			 struct json_object *root,
			 struct json_object *body)
{
	return add_result_common("NTSTATUS",
				 NT_STATUS_V(status),
				 nt_errstr(status),
				 NT_STATUS_IS_OK(status),
				 root,
				 body);
}

bool _format_log_entry(vfs_handle_struct *handle,
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

		ok = add_version(root, "vers", DEF_MAJ_VER, DEF_MIN_VER);
		if (!ok) {
			DBG_ERR("[%s]: failed to add audit event version\n",
				location);
			return false;
		}

		ok = add_inet_addr(root, "addr",
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

		ok = add_timestamp(root, "time", NULL);
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

		snprintf(buf, sizeof(buf), "%u_%u", tn_ops[i].maj_ver,
			 tn_ops[i].min_ver);

		ok = add_version(entry_data, "vers", tn_ops[i].maj_ver,
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

/* This function performs actual JSON logging */
bool _tn_audit_do_log(tn_audit_conf_t *config,
		      struct json_object *jsobj,
		      const char *location)
{
	char *msg = NULL;

	if (!config->enabled) {
		return true;
	}

	msg = json_to_string(config, jsobj);
	if (msg == NULL) {
		DBG_ERR("[%s]: Memory error generating log message\n",
			location);
		return false;
	}

	DBG_DEBUG("[%s]: %s\n", location, msg);

	if (config->do_syslog) {
		syslog(config->syslog_priority | config->syslog_facility,
		       "@cee:{\"TNAUDIT\": %s}", msg);
	} else {
		DBG_WARNING("@cee:{\"TNAUDIT\": %s}\n", msg);
	}

	TALLOC_FREE(msg);
	return true;
}
