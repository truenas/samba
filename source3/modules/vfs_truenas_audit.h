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

#ifndef __TRUENAS_AUDIT_H
#define __TRUENAS_AUDIT_H

#define DEF_MAJ_VER 0
#define DEF_MIN_VER 1
#define SVC_MAJ_VER DEF_MAJ_VER
#define SVC_MIN_VER DEF_MIN_VER

#define MODULE_NAME "truenas_audit"
#define SYSLOG_IDENT "TNAUDIT_SMB"

extern int vfs_tnaudit_debug_level;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_tnaudit_debug_level

typedef struct truenas_audit_config {
	int syslog_facility;
	int syslog_priority;
	int rw_interval;
	bool do_syslog;
	bool enabled;
	char *js_connection;
	struct {
		char *user;
		char *sess;
	} conn_info;
	struct {
		size_t read;
		size_t write;
		size_t create;
		size_t close;
	} op_cnt;
} tn_audit_conf_t;

typedef struct truenas_audit_vfs_extension {
	struct {
		size_t read_cnt;
		size_t read_bytes;
		uint32_t read_wrap;
		size_t write_cnt;
		size_t write_bytes;
		uint32_t write_wrap;
	} ops;
	struct timespec last_read;
	struct timespec last_offload_read;
	struct timespec last_write;
	struct timespec last_offload_write;
	struct file_id_buf fid_str;
} tn_audit_ext_t;

typedef enum tn_audit_op {
	TN_OP_CONNECT = 0,
	TN_OP_DISCONNECT,
	TN_OP_CREATE,
	TN_OP_CLOSE,
	TN_OP_LISTDIR,
	TN_OP_READ_DATA,
	TN_OP_OFFLOAD_READ_DATA,
	TN_OP_WRITE_DATA,
	TN_OP_OFFLOAD_WRITE_DATA,
	TN_OP_SET_ACL,
	TN_OP_RENAME,
	TN_OP_FSCTL,
	TN_OP_UNLINK,
	TN_OP_COPY,
	TN_OP_SET_ATTR,
	TN_OP_SET_QUOTA,
} tn_op_t;

typedef union tn_result_val {
	int error;
	NTSTATUS status;
} tn_rval_t;

/*
 * The following ops lookup table contains the following items that
 * are used when generating wrapper for the logged event
 * Each of the event types contains major and minor versions that
 * should be incremented with changes to JSON object returned for
 * event.
 *
 * type - internal enum for the event type
 * name - string that will be serve as key for event data
 * maj_ver - major version for the event data
 * min_ver - minor version for the event data
 */
static struct {
        tn_op_t type;
        const char *name;
	int maj_ver;
	int min_ver;
} tn_ops[] = {
	{ TN_OP_CONNECT, "CONNECT", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_DISCONNECT, "DISCONNECT", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_CREATE, "CREATE", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_CLOSE, "CLOSE", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_LISTDIR, "QUERY_DIRECTORY", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_READ_DATA, "READ", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_WRITE_DATA, "WRITE", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_OFFLOAD_READ_DATA, "OFFLOAD_READ", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_OFFLOAD_WRITE_DATA, "OFFLOAD_WRITE", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_SET_ACL, "SET_ACL", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_RENAME, "RENAME", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_UNLINK, "UNLINK", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_COPY, "COPY", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_FSCTL, "FSCTL", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_SET_ATTR, "SET_ATTR", DEF_MAJ_VER, DEF_MIN_VER },
	{ TN_OP_SET_QUOTA, "SET_QUOTA", DEF_MAJ_VER, DEF_MIN_VER },
};

/**
 * @brief Perform deep copy of JSON object and insert in specfied object
 *
 * @param[in] src     Source object that will be copied
 * @param[in] key     Key to use for newly created JSON object
 * @param[in] dst     Target for new copy
 *
 * @return            boolean True on success False on failure
 */
bool dup_json_object(struct json_object *src,
		     const char *key,
		     struct json_object *dst);

/**
 * @brief Initialize JSON objects to be used in log message
 *
 * @param[out] wrapper Wrapper for JSON objects
 * @param[out] data    JSON object for event-specific data
 *
 * @return            boolean True on success False on failure
 */
bool init_json_msg(struct json_object *wrapper,
		   struct json_object *data);

/**
 * @brief Add ISO 8601 timestamp to specified JSON object
 *
 * @param[in] object  JSON object to which to add timestamp
 * @param[in] key     Key to use to attach timestamp
 * @param[in] tvp     Timeval struct to convert into timestamp
 *
 * @return            boolean True on success False on failure
 */
bool add_timestamp(struct json_object *object,
		   const char *key,
		   struct timeval *tvp);

/**
 * @brief Add connection information to specified JSON object
 *
 * {
 *   "vers": <string>,
 *   "service": <string>,
 *   "session_guid": <GUID string>,
 *   "session_id": <string>,
 *   "tcon_id": <string>,
 * }
 *
 * @param[in] service Name of SMB share
 * @param[in] conn    Connection information to add to JSON object
 * @param[in] jsobj   JSON object to which to add connection info
 *
 * @return            boolean True on success False on failure
 */
bool add_connection_info_to_obj(const char *service,
				const connection_struct *conn,
				struct json_object *jsobj);

/**
 * @brief Add unix token to JSON object
 *
 * "unix_token": {
 *   "username": <string>,
 *   "uid": <int>,
 *   "gid": <int>,
 *   "groups": [<int>, <int>, ..]
 * }
 *
 * @param[in] sess    Session information to add to JSON object
 * @param[in] jsobj   JSON object to which to add session info
 *
 * @return            boolean True on success False on failure
 */
bool add_unix_token_to_obj(const struct auth_session_info *sess,
			   struct json_object *jsobj);

/**
 * @brief Add SMB client information to JSON object
 *
 * Currently this adds hostname string as `host` key. More
 * information may be added in future revision
 *
 * "host": <string>
 *
 * @param[in] sess    Server connection information to add to JSON object
 * @param[in] jsobj   JSON object to which to add SMB client info
 *
 * @return            boolean True on success False on failure
 */
bool add_client_info_to_obj(const struct smbd_server_connection *sconn,
			    struct json_object *jsobj);

/**
 * @brief Convert NTTIME to string and insert in object with specified key.
 *
 * @param[in] jsobj   JSON object to which to add snapshot timestamp
 * @param[in] key     Key to use to attach snapshot timestamp
 * @param[in] twrp    NTTIME-converted TWRP token
 *
 * @return            boolean True on success False on failure
 */
bool add_snapshot_to_object(struct json_object *jsobj,
			    const char *key,
			    NTTIME twrp);

/**
 * @brief Convert file type to a string and attach using specified key.
 *
 * @param[in] jsobj   JSON object to which to add file type
 * @param[in] key     Key to use to attach file type
 * @param[in] mode_t  S_IFMT c.f. stat.h
 *
 * @return            boolean True on success False on failure
 */
bool add_file_type_to_object(struct json_object *jsobj,
			     const char *key,
			     mode_t ftype);

#define FILE_ADD_HANDLE 0x00000001
#define FILE_ADD_NAME 0x00000002
#define FILE_ADD_TYPE 0x00000004
#define FILE_NAME_IS_PATH 0x00000008

/**
 * @brief Add a file object to a specified JSON object.
 *
 * The file JSON object is added to provided JSON object via keyname "file"
 * Caller can specify which information to add to the "file" object via
 * `flags` parameter.
 *
 * FILE_ADD_HANDLE - adds a JSON file handle object to the "file" object
 * example:
 * "file": {
 *   "handle": {"type": "DEV_INO", "value": "58:133:2993905"},
 * }
 *
 * FILE_ADD_TYPE - adds JSON string "type" to the "file" object
 * example:
 * "file": {
 *   "type": "DIRECTORY"
 * }
 *
 * FILE_ADD_NAME - adds rough equivalent of struct smb_filename to "file"
 * object.
 * example:
 * "file": {
 *   "name": "testfile.txt",
 *   "stream": null,
 *   "snap": null
 * }
 *
 * FILE_NAME_IS_PATH - if FILE_ADD_NAME is specified, this flag indicates
 * that the name provided is a path rather than basename of file. This changes
 * key used for the name.
 * example:
 * "file": {
 *   "path": "PATHFINDER/testfile.txt",
 *   "stream": null,
 *   "snap": null
 * }
 *
 * @param[in] fname      SMB filename from which to gather name and type info
 *
 * @param[in] fsp_ext    Internal FSP extension from which to get file id
 * 			 string
 *
 * @param[in] flags      Bitmask of desired information to add to the
 * 			 specified JSON object. The following may be used:
 * 			 FILE_ADD_HANDLE - adds a JSON file handle object
 * 			 (see below) with key "handle" to "file" object.
 * 			 FILE_ADD_NAME - adds multiple keys related to
 * 			 file name to "file" object. See below for details.
 * 			 FILE_ADD_TYPE - adds "type" key to "file" object
 * 			 indicating the type of file.
 *
 * @param[in] jsobj      JSON object to which to add the new file object.
 *
 * @return               boolean True on success False on failure
 *
 *
 * @code
 *
 * @endcode
 */
bool add_file_to_object(const struct smb_filename *fname,
			const tn_audit_ext_t *fsp_ext,
			const char *key,
			uint32_t flags,
			struct json_object *jsobj);

/**
 * @brief convert bitmask into hex string and attach as key.
 *
 * @param[in] uint32_t attribute to convert to hex string
 * @param[in] name     Key to use to attach bitmask
 * @param[in] jsobj    JSON object to which to add the bitmask.
 *
 * @return             boolean True on success False on failure
 */
bool add_map_to_object(uint32_t attr,
		       const char *name,
		       struct json_object *jsobj);

/**
 * @brief Convert uint64_t to string and attach as key.
 *
 * @param[in] uint64_t value to convert to string
 * @param[in] name     Key to use to attach integer
 * @param[in] jsobj    JSON object to which to string.
 *
 * @return             boolean True on success False on failure
 */
bool add_u64_to_object(uint64_t val,
		       const char *name,
		       struct json_object *jsobj);

bool add_smb_quota_to_obj(enum SMB_QUOTA_TYPE qtype,
			  unid_t id,
			  SMB_DISK_QUOTA *qt,
			  struct json_object *jsobj);

/*
 * Convert SMB_VFS_CREATE payload into a JSON object
 *
 * "parameters": {
 *   "DesiredAccess": <hex string>,
 *   "FileAttributes": <hex string>,
 *   "ShareAccess": <hex string>,
 *   "CreateDisposition": <string>,
 *   "CreateOptions": <hex string>
 * },
 * "file_type": <string -- c.f. add_file_type_to_object()>,
 * "file": <JSON object c.f. add_file_to_object()>,
 * "sd": <SDDL string if SD specified during file creation>
 */
bool add_create_payload(struct smb_filename *smb_fname,
			tn_audit_ext_t *fsp_ext,
		        uint32_t js_flags,
		        uint32_t access_mask,
		        uint32_t share_access,
		        uint32_t create_disposition,
		        uint32_t create_options,
		        uint32_t file_attributes,
		        struct security_descriptor *psd,
		        struct json_object *jsobj);

/**
 * @brief Add UNIX result to JSON message.
 *
 * This add boolean `success` to provided `root` of message
 * and separate JSON object `result` to event data body.
 *
 * @param[in] err      errno of error or 0 on success
 * @param[in] root     JSON object for message body.
 * @param[in] body     JSON object encapsulating event data.
 *
 * @return             boolean True on success False on failure
 */
bool add_result_unix(const int err,
		     struct json_object *root,
		     struct json_object *body);

/**
 * @brief Add NTSTATUS result to JSON message.
 *
 * This add boolean `success` to provided `root` of message
 * and separate JSON object `result` to event data body.
 *
 * @param[in] status   NTSTATUS to convert to JSON object
 * @param[in] root     JSON object for message body.
 * @param[in] body     JSON object encapsulating event data.
 *
 * @return             boolean True on success False on failure
 */
bool add_result_ntstatus(const NTSTATUS status,
			 struct json_object *root,
			 struct json_object *body);

ssize_t tn_audit_pread(vfs_handle_struct *handle, files_struct *fsp,
		       void *data, size_t n, off_t offset);

ssize_t tn_audit_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			const void *data, size_t n, off_t offset);

ssize_t tn_audit_pread_recv(struct tevent_req *req,
			    struct vfs_aio_state *vfs_aio_state);

struct tevent_req *tn_audit_pread_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	void *data, size_t n, off_t offset);

ssize_t tn_audit_pwrite_recv(struct tevent_req *req,
			     struct vfs_aio_state *vfs_aio_state);

struct tevent_req *tn_audit_pwrite_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	const void *data, size_t n, off_t offset);

struct tevent_req *tn_audit_offload_read_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct vfs_handle_struct *handle, files_struct *fsp, uint32_t fsctl,
	uint32_t ttl, off_t offset, size_t to_copy);

NTSTATUS tn_audit_offload_read_recv(
	struct tevent_req *req, struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx, uint32_t *flags, uint64_t *xferlen,
	DATA_BLOB *token);

struct tevent_req *tn_audit_offload_write_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t fsctl,
	DATA_BLOB *token,
	off_t transfer_offset,
	struct files_struct *dest_fsp,
	off_t dest_off,
	off_t to_copy);

NTSTATUS tn_audit_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied);

bool _format_log_entry(vfs_handle_struct *handle,
		      tn_audit_conf_t *conf,
		      tn_op_t op,
		      struct json_object *root,
		      struct json_object *entry_data,
		      const char *location);

#define format_log_entry(hdl, conf, op, root, entry_data)\
	_format_log_entry(hdl, conf, op, root, entry_data, __location__)

bool _tn_audit_do_log(tn_audit_conf_t *config,
		      struct json_object *jsobj,
		      const char *location);

#define tn_audit_do_log(config, jsobj)\
	_tn_audit_do_log(config, jsobj, __location__)
#endif  /* __TRUENAS_AUDIT_H */
