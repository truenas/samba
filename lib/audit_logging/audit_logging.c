/*
   common routines for audit logging

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

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

/*
 * Error handling:
 *
 */

#include "includes.h"

#include "librpc/ndr/libndr.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_token.h"
#include "lib/messaging/messaging.h"
#include "auth/common_auth.h"
#include "audit_logging.h"
#include "auth/authn_policy.h"

/*
 * @brief Get a human readable timestamp.
 *
 * Returns the current time formatted as
 *  "Tue, 14 Mar 2017 08:38:42.209028 NZDT"
 *
 * The returned string is allocated by talloc in the supplied context.
 * It is the callers responsibility to free it.
 *
 * @param mem_ctx talloc memory context that owns the returned string.
 *
 * @return a human readable time stamp, or NULL in the event of an error.
 *
 */
char* audit_get_timestamp(TALLOC_CTX *frame)
{
	char buffer[40];	/* formatted time less usec and timezone */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	struct timeval tv;	/* current system time			 */
	int ret;		/* response code			 */
	char * ts;		/* formatted time stamp			 */

	ret = gettimeofday(&tv, NULL);
	if (ret != 0) {
		DBG_ERR("Unable to get time of day: (%d) %s\n",
			errno,
			strerror(errno));
		return NULL;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine local time\n");
		return NULL;
	}

	strftime(buffer, sizeof(buffer)-1, "%a, %d %b %Y %H:%M:%S", tm_info);
	strftime(tz, sizeof(tz)-1, "%Z", tm_info);
	ts = talloc_asprintf(frame, "%s.%06ld %s", buffer, (long)tv.tv_usec, tz);
	if (ts == NULL) {
		DBG_ERR("Out of memory formatting time stamp\n");
	}
	return ts;
}

/*
 * @brief write an audit message to the audit logs.
 *
 * Write a human readable text audit message to the samba logs.
 *
 * @param prefix Text to be printed at the start of the log line
 * @param message The content of the log line.
 * @param debub_class The debug class to log the message with.
 * @param debug_level The debug level to log the message with.
 */
void audit_log_human_text(const char* prefix,
			  const char* message,
			  int debug_class,
			  int debug_level)
{
	DEBUGC(debug_class, debug_level, ("%s %s\n", prefix, message));
}

#ifdef HAVE_JANSSON
/*
 * Constant for empty json object initialisation
 */
const struct json_object json_empty_object = {.valid = false, .root = NULL};
/*
 * @brief write a json object to the samba audit logs.
 *
 * Write the json object to the audit logs as a formatted string
 *
 * @param message The content of the log line.
 * @param debub_class The debug class to log the message with.
 * @param debug_level The debug level to log the message with.
 */
void audit_log_json(struct json_object* message,
		    int debug_class,
		    int debug_level)
{
	TALLOC_CTX *frame = NULL;
	char *s = NULL;

	if (json_is_invalid(message)) {
		DBG_ERR("Invalid JSON object, unable to log\n");
		return;
	}

	frame = talloc_stackframe();
	s = json_to_string(frame, message);
	if (s == NULL) {
		DBG_ERR("json_to_string returned NULL, "
			"JSON audit message could not written\n");
		TALLOC_FREE(frame);
		return;
	}
	/*
	 * This is very strange, but we call this routine to get a log
	 * output without the header.  JSON logs all have timestamps
	 * so this only makes parsing harder.
	 *
	 * We push out the raw JSON blob without a prefix, consumers
	 * can find such lines by the leading {
	 */
	DEBUGADDC(debug_class, debug_level, ("%s\n", s));
	TALLOC_FREE(frame);
}

/*
 * @brief get a connection to the messaging event server.
 *
 * Get a connection to the messaging event server registered by server_name.
 *
 * @param msg_ctx a valid imessaging_context.
 * @param server_name name of messaging event server to connect to.
 * @param server_id The event server details to populate
 *
 * @return NTSTATUS
 */
static NTSTATUS get_event_server(
	struct imessaging_context *msg_ctx,
	const char *server_name,
	struct server_id *event_server)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned num_servers, i;
	struct server_id *servers;

	status = irpc_servers_byname(
		msg_ctx,
		frame,
		server_name,
		&num_servers,
		&servers);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Failed to find the target '%s' on the message bus "
			  "to send JSON audit events to: %s\n",
			  server_name,
			  nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * Select the first server that is listening, because we get
	 * connection refused as NT_STATUS_OBJECT_NAME_NOT_FOUND
	 * without waiting
	 */
	for (i = 0; i < num_servers; i++) {
		status = imessaging_send(
			msg_ctx,
			servers[i],
			MSG_PING,
			&data_blob_null);
		if (NT_STATUS_IS_OK(status)) {
			*event_server = servers[i];
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
	}
	DBG_NOTICE(
		"Failed to find '%s' registered on the message bus to "
		"send JSON audit events to: %s\n",
		server_name,
		nt_errstr(status));
	TALLOC_FREE(frame);
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

/*
 * @brief send an audit message to a messaging event server.
 *
 * Send the message to a registered and listening event server.
 * Note: Any errors are logged, and the message is not sent.  This is to ensure
 *       that a poorly behaved event server does not impact Samba.
 *
 *       As it is possible to lose messages, especially during server
 *       shut down, currently this function is primarily intended for use
 *       in integration tests.
 *
 * @param msg_ctx an imessaging_context, can be NULL in which case no message
 *                will be sent.
 * @param server_name the naname of the event server to send the message to.
 * @param messag_type A message type defined in librpc/idl/messaging.idl
 * @param message The message to send.
 *
 */
void audit_message_send(
	struct imessaging_context *msg_ctx,
	const char *server_name,
	uint32_t message_type,
	struct json_object *message)
{
	struct server_id event_server = {
		.pid = 0,
	};
	NTSTATUS status;

	const char *message_string = NULL;
	DATA_BLOB message_blob = data_blob_null;
	TALLOC_CTX *ctx = NULL;

	if (json_is_invalid(message)) {
		DBG_ERR("Invalid JSON object, unable to send\n");
		return;
	}
	if (msg_ctx == NULL) {
		DBG_DEBUG("No messaging context\n");
		return;
	}

	ctx = talloc_new(NULL);
	if (ctx == NULL) {
		DBG_ERR("Out of memory creating temporary context\n");
		return;
	}

	/* Need to refetch the address each time as the destination server may
	 * have disconnected and reconnected in the interim, in which case
	 * messages may get lost
	 */
	status = get_event_server(msg_ctx, server_name, &event_server);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(ctx);
		return;
	}

	message_string = json_to_string(ctx, message);
	message_blob = data_blob_string_const(message_string);
	status = imessaging_send(
		msg_ctx,
		event_server,
		message_type,
		&message_blob);

	/*
	 * If the server crashed, try to find it again
	 */
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		status = get_event_server(msg_ctx, server_name, &event_server);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(ctx);
			return;
		}
		imessaging_send(
			msg_ctx,
			event_server,
			message_type,
			&message_blob);
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief Create a new struct json_object, wrapping a JSON Object.
 *
 * Create a new json object, the json_object wraps the underlying json
 * implementations JSON Object representation.
 *
 * Free with a call to json_free_object, note that the jansson inplementation
 * allocates memory with malloc and not talloc.
 *
 * @return a struct json_object, valid will be set to false if the object
 *         could not be created.
 *
 */
struct json_object json_new_object(void) {

	struct json_object object = json_empty_object;

	object.root = json_object();
	if (object.root == NULL) {
		object.valid = false;
		DBG_ERR("Unable to create JSON object\n");
		return object;
	}
	object.valid = true;
	return object;
}

/*
 * @brief Create a new struct json_object wrapping a JSON Array.
 *
 * Create a new json object, the json_object wraps the underlying json
 * implementations JSON Array representation.
 *
 * Free with a call to json_free_object, note that the jansson inplementation
 * allocates memory with malloc and not talloc.
 *
 * @return a struct json_object, error will be set to true if the array
 *         could not be created.
 *
 */
struct json_object json_new_array(void) {

	struct json_object array = json_empty_object;

	array.root = json_array();
	if (array.root == NULL) {
		array.valid = false;
		DBG_ERR("Unable to create JSON array\n");
		return array;
	}
	array.valid = true;
	return array;
}


/*
 * @brief free and invalidate a previously created JSON object.
 *
 * Release any resources owned by a json_object, and then mark the structure
 * as invalid.  It is safe to call this multiple times on an object.
 *
 */
void json_free(struct json_object *object)
{
	if (object->root != NULL) {
		json_decref(object->root);
	}
	object->root = NULL;
	object->valid = false;
}

/*
 * @brief is the current JSON object invalid?
 *
 * Check the state of the object to determine if it is invalid.
 *
 * @return is the object valid?
 *
 */
bool json_is_invalid(const struct json_object *object)
{
	return !object->valid;
}

/*
 * @brief Add an integer value to a JSON object.
 *
 * Add an integer value named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name of the value.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_int(struct json_object *object, const char *name, const json_int_t value)
{
	int ret = 0;
	json_t *integer = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add int [%s] value [%jd], "
			"target object is invalid\n",
			name,
			(intmax_t)value);
		return JSON_ERROR;
	}

	integer = json_integer(value);
	if (integer == NULL) {
		DBG_ERR("Unable to create integer value [%s] value [%jd]\n",
			name,
			(intmax_t)value);
		return JSON_ERROR;
	}

	ret = json_object_set_new(object->root, name, integer);
	if (ret != 0) {
		json_decref(integer);
		DBG_ERR("Unable to add int [%s] value [%jd]\n",
			name,
			(intmax_t)value);
	}
	return ret;
}

/*
 * @brief Add a boolean value to a JSON object.
 *
 * Add a boolean value named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_bool(struct json_object *object,
		  const char *name,
		  const bool value)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add boolean [%s] value [%d], "
			"target object is invalid\n",
			name,
			value);
		return JSON_ERROR;
	}

	ret = json_object_set_new(object->root, name, json_boolean(value));
	if (ret != 0) {
		DBG_ERR("Unable to add boolean [%s] value [%d]\n", name, value);
	}
	return ret;
}

/*
 * @brief Add an optional boolean value to a JSON object.
 *
 * Add an optional boolean value named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_optional_bool(struct json_object *object,
			   const char *name,
			   const bool *value)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add boolean [%s] value [%d], "
			"target object is invalid\n",
			name,
			*value);
		return JSON_ERROR;
	}

	if (value != NULL) {
		ret = json_object_set_new(object->root, name, json_boolean(*value));
		if (ret != 0) {
			DBG_ERR("Unable to add boolean [%s] value [%d]\n", name, *value);
			return ret;
		}
	} else {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null boolean [%s]\n", name);
			return ret;
		}
	}

	return ret;
}

/*
 * @brief Add a string value to a JSON object.
 *
 * Add a string value named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_string(struct json_object *object,
		    const char *name,
		    const char *value)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add string [%s], target object is invalid\n",
			name);
		return JSON_ERROR;
	}
	if (value) {
		json_t *string = json_string(value);
		if (string == NULL) {
			DBG_ERR("Unable to add string [%s], "
				"could not create string object\n",
				name);
			return JSON_ERROR;
		}
		ret = json_object_set_new(object->root, name, string);
		if (ret != 0) {
			json_decref(string);
			DBG_ERR("Unable to add string [%s]\n", name);
			return ret;
		}
	} else {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null string [%s]\n", name);
			return ret;
		}
	}
	return ret;
}

/*
 * @brief Assert that the current JSON object is an array.
 *
 * Check that the current object is a JSON array, and if not
 * invalidate the object. We also log an error message as this indicates
 * bug in the calling code.
 *
 * @param object the JSON object to be validated.
 */
void json_assert_is_array(struct json_object *array) {

	if (json_is_invalid(array)) {
		return;
	}

	if (json_is_array(array->root) == false) {
		DBG_ERR("JSON object is not an array\n");
		array->valid = false;
		return;
	}
}

/*
 * @brief Add a JSON object to a JSON object.
 *
 * Add a JSON object named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_object(struct json_object *object,
		    const char *name,
		    struct json_object *value)
{
	int ret = 0;
	json_t *jv = NULL;

	if (value != NULL && json_is_invalid(value)) {
		DBG_ERR("Invalid JSON object [%s] supplied\n", name);
		return JSON_ERROR;
	}
	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add object [%s], target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	jv = value == NULL ? json_null() : value->root;

	if (json_is_array(object->root)) {
		ret = json_array_append_new(object->root, jv);
	} else if (json_is_object(object->root)) {
		ret = json_object_set_new(object->root, name, jv);
	} else {
		DBG_ERR("Invalid JSON object type\n");
		ret = JSON_ERROR;
	}
	if (ret != 0) {
		DBG_ERR("Unable to add object [%s]\n", name);
	}
	return ret;
}

/*
 * @brief Add a string to a JSON object, truncating if necessary.
 *
 *
 * Add a string value named 'name' to the json object, the string will be
 * truncated if it is more than len characters long. If len is 0 the value
 * is encoded as a JSON null.
 *
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 * @param len the maximum number of characters to be copied.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_stringn(struct json_object *object,
		     const char *name,
		     const char *value,
		     const size_t len)
{

	int ret = 0;
	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add string [%s], target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	if (value != NULL && len > 0) {
		json_t *string = json_stringn(value, len);
		if (string == NULL) {
			DBG_ERR("Unable to add string [%s], "
				"could not create string object\n",
				name);
			return JSON_ERROR;
		}
		ret = json_object_set_new(object->root, name, string);
		if (ret != 0) {
			json_decref(string);
			DBG_ERR("Unable to add string [%s]\n", name);
			return ret;
		}
	} else {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null string [%s]\n", name);
			return ret;
		}
	}
	return ret;
}

/*
 * @brief Add a version object to a JSON object
 *
 * Add a version object to the JSON object
 * 	"version":{"major":1, "minor":0}
 *
 * The version tag is intended to aid the processing of the JSON messages
 * The major version number should change when an attribute is:
 *  - renamed
 *  - removed
 *  - its meaning changes
 *  - its contents change format
 * The minor version should change whenever a new attribute is added and for
 * minor bug fixes to an attributes content.
 *
 *
 * @param object the JSON object to be updated.
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 */
int json_add_version(struct json_object *object, int major, int minor)
{
	int ret = 0;
	struct json_object version;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add version, target object is invalid\n");
		return JSON_ERROR;
	}

	version = json_new_object();
	if (json_is_invalid(&version)) {
		DBG_ERR("Unable to add version, failed to create object\n");
		return JSON_ERROR;
	}
	ret = json_add_int(&version, "major", major);
	if (ret != 0) {
		json_free(&version);
		return ret;
	}
	ret = json_add_int(&version, "minor", minor);
	if (ret != 0) {
		json_free(&version);
		return ret;
	}
	ret = json_add_object(object, "version", &version);
	if (ret != 0) {
		json_free(&version);
		return ret;
	}
	return ret;
}

/*
 * @brief add an ISO 8601 timestamp to the object.
 *
 * Add a date and time as a timestamp in ISO 8601 format to a JSON object
 *
 * "time":"2017-03-06T17:18:04.455081+1300"
 *
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param time the value to set.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 */
int json_add_time(struct json_object *object, const char *name, const struct timeval tv)
{
	char buffer[40];	/* formatted time less usec and timezone */
	char timestamp[65];	/* the formatted ISO 8601 time stamp	 */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	int ret;		/* return code from json operations	*/

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add time, target object is invalid\n");
		return JSON_ERROR;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine local time\n");
		return JSON_ERROR;
	}

	strftime(buffer, sizeof(buffer)-1, "%Y-%m-%dT%T", tm_info);
	strftime(tz, sizeof(tz)-1, "%z", tm_info);
	snprintf(
		timestamp,
		sizeof(timestamp),
		"%s.%06ld%s",
		buffer,
		tv.tv_usec,
		tz);
	ret = json_add_string(object, name, timestamp);
	if (ret != 0) {
		DBG_ERR("Unable to add time to JSON object\n");
	}
	return ret;
}

/*
 * @brief add an ISO 8601 timestamp to the object.
 *
 * Add the current date and time as a timestamp in ISO 8601 format
 * to a JSON object
 *
 * "timestamp":"2017-03-06T17:18:04.455081+1300"
 *
 *
 * @param object the JSON object to be updated.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 */
int json_add_timestamp(struct json_object *object)
{
	struct timeval tv;	/* current system time			 */
	int r;			/* response code from gettimeofday	 */

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add time stamp, target object is invalid\n");
		return JSON_ERROR;
	}

	r = gettimeofday(&tv, NULL);
	if (r) {
		DBG_ERR("Unable to get time of day: (%d) %s\n",
			errno,
			strerror(errno));
		return JSON_ERROR;
	}

	return json_add_time(object, "timestamp", tv);
}

/*
 *@brief Add a tsocket_address to a JSON object
 *
 * Add the string representation of a Samba tsocket_address to the object.
 *
 * "localAddress":"ipv6::::0"
 *
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param address the tsocket_address.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_address(struct json_object *object,
		     const char *name,
		     const struct tsocket_address *address)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add address [%s], "
			"target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	if (address == NULL) {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null address [%s]\n", name);
			return JSON_ERROR;
		}
	} else {
		TALLOC_CTX *ctx = talloc_new(NULL);
		char *s = NULL;

		if (ctx == NULL) {
			DBG_ERR("Out of memory adding address [%s]\n", name);
			return JSON_ERROR;
		}

		s = tsocket_address_string(address, ctx);
		if (s == NULL) {
			DBG_ERR("Out of memory adding address [%s]\n", name);
			TALLOC_FREE(ctx);
			return JSON_ERROR;
		}
		ret = json_add_string(object, name, s);
		if (ret != 0) {
			DBG_ERR(
			    "Unable to add address [%s] value [%s]\n", name, s);
			TALLOC_FREE(ctx);
			return JSON_ERROR;
		}
		TALLOC_FREE(ctx);
	}
	return ret;
}

/*
 * @brief Add a formatted string representation of a sid to a json object.
 *
 * Add the string representation of a Samba sid to the object.
 *
 * "sid":"S-1-5-18"
 *
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param sid the sid
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_sid(struct json_object *object,
		 const char *name,
		 const struct dom_sid *sid)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add SID [%s], "
			"target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	if (sid == NULL) {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null SID [%s]\n", name);
			return ret;
		}
	} else {
		struct dom_sid_buf sid_buf;

		ret = json_add_string(
			object, name, dom_sid_str_buf(sid, &sid_buf));
		if (ret != 0) {
			DBG_ERR("Unable to add SID [%s] value [%s]\n",
				name,
				sid_buf.buf);
			return ret;
		}
	}
	return ret;
}

/*
 * @brief Add a formatted string representation of a guid to a json object.
 *
 * Add the string representation of a Samba GUID to the object.
 *
 * "guid":"1fb9f2ee-2a4d-4bf8-af8b-cb9d4529a9ab"
 *
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param guid the guid.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 *
 */
int json_add_guid(struct json_object *object,
		  const char *name,
		  const struct GUID *guid)
{

	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add GUID [%s], "
			"target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	if (guid == NULL) {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null GUID [%s]\n", name);
			return ret;
		}
	} else {
		char *guid_str;
		struct GUID_txt_buf guid_buff;

		guid_str = GUID_buf_string(guid, &guid_buff);
		ret = json_add_string(object, name, guid_str);
		if (ret != 0) {
			DBG_ERR("Unable to add GUID [%s] value [%s]\n",
				name,
				guid_str);
			return ret;
		}
	}
	return ret;
}

/*
 * @brief Add a hex-formatted string representation of a 32-bit integer to a
 * json object.
 *
 * Add a hex-formatted string representation of a 32-bit flags integer to the
 * object.
 *
 * "accountFlags":"0x12345678"
 *
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param flags the flags.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 *
 */
int json_add_flags32(struct json_object *object,
		  const char *name,
		  const uint32_t flags)
{
	int ret = 0;
	char buf[sizeof("0x12345678")];

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add flags [%s], "
			"target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	ret = snprintf(buf, sizeof (buf), "0x%08X", flags);
	if (ret != sizeof (buf) - 1) {
		DBG_ERR("Unable to format flags [%s] value [0x%08X]\n",
			name,
			flags);
		return JSON_ERROR;
	}

	ret = json_add_string(object, name, buf);
	if (ret != 0) {
		DBG_ERR("Unable to add flags [%s] value [%s]\n",
			name,
			buf);
	}

	return ret;
}

/*
 * @brief Replaces the object for a given key with a given json object.
 *
 * If key already exists, the value will be replaced. Otherwise the given
 * value will be added under the given key.
 *
 * @param object the JSON object to be updated.
 * @param key the key which will be updated.
 * @param new_obj the new value object to be inserted.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed (e.j. if one of the parameters is invalid)
 */
int json_update_object(struct json_object *object,
		       const char *key,
		       struct json_object *new_obj)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to update key [%s], "
			"target object is invalid\n",
			key);
		return JSON_ERROR;
	}
	if (json_is_invalid(new_obj)) {
		DBG_ERR("Unable to update key [%s], "
			"new object is invalid\n",
			key);
		return JSON_ERROR;
	}

	if (key == NULL) {
		DBG_ERR("Unable to add null String as key\n");
		return JSON_ERROR;
	}

	ret = json_object_set(object->root, key, new_obj->root);
	if (ret != 0) {
		DBG_ERR("Unable to update object\n");
		return ret;
	}

	return ret;
}

/*
 * @brief Convert a JSON object into a string
 *
 * Convert the jsom object into a string suitable for printing on a log line,
 * i.e. with no embedded line breaks.
 *
 * If the object is invalid it logs an error and returns NULL.
 *
 * @param mem_ctx the talloc memory context owning the returned string
 * @param object the json object.
 *
 * @return A string representation of the object or NULL if the object
 *         is invalid.
 */
char *json_to_string(TALLOC_CTX *mem_ctx, const struct json_object *object)
{
	char *json = NULL;
	char *json_string = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object, unable to convert to string\n");
		return NULL;
	}

	if (object->root == NULL) {
		return NULL;
	}

	/*
	 * json_dumps uses malloc, so need to call free(json) to release
	 * the memory
	 */
	json = json_dumps(object->root, 0);
	if (json == NULL) {
		DBG_ERR("Unable to convert JSON object to string\n");
		return NULL;
	}

	json_string = talloc_strdup(mem_ctx, json);
	if (json_string == NULL) {
		free(json);
		DBG_ERR("Unable to copy JSON object string to talloc string\n");
		return NULL;
	}
	free(json);

	return json_string;
}

/*
 * @brief get a json array named "name" from the json object.
 *
 * Get the array attribute named name, creating it if it does not exist.
 *
 * @param object the json object.
 * @param name the name of the array attribute
 *
 * @return The array object, will be created if it did not exist.
 */
struct json_object json_get_array(struct json_object *object, const char *name)
{

	struct json_object array = json_empty_object;
	json_t *a = NULL;
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object, unable to get array [%s]\n",
			name);
		json_free(&array);
		return array;
	}

	array = json_new_array();
	if (json_is_invalid(&array)) {
		DBG_ERR("Unable to create new array for [%s]\n", name);
		return array;
	}

	a = json_object_get(object->root, name);
	if (a == NULL) {
		return array;
	}

	ret = json_array_extend(array.root, a);
	if (ret != 0) {
		DBG_ERR("Unable to get array [%s]\n", name);
		json_free(&array);
		return array;
	}

	return array;
}

/*
 * @brief get a json object named "name" from the json object.
 *
 * Get the object attribute named name, creating it if it does not exist.
 *
 * @param object the json object.
 * @param name the name of the object attribute
 *
 * @return The object, will be created if it did not exist.
 */
struct json_object json_get_object(struct json_object *object, const char *name)
{

	struct json_object o = json_new_object();
	json_t *v = NULL;
	int ret = 0;

	if (json_is_invalid(&o)) {
		DBG_ERR("Unable to get object [%s]\n", name);
		json_free(&o);
		return o;
	}

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object, unable to get object [%s]\n",
			name);
		json_free(&o);
		return o;
	}

	v = json_object_get(object->root, name);
	if (v == NULL) {
		return o;
	}
	ret = json_object_update(o.root, v);
	if (ret != 0) {
		DBG_ERR("Unable to get object [%s]\n", name);
		json_free(&o);
		return o;
	}
	return o;
}

/*
 * @brief Return the JSON null object.
 *
 * @return the JSON null object.
 */
_WARN_UNUSED_RESULT_ struct json_object json_null_object(void)
{
	struct json_object object = json_empty_object;

	object.root = json_null();
	if (object.root != NULL) {
		object.valid = true;
	}

	return object;
}

/*
 * @brief Create a JSON object from a structure containing audit information.
 *
 * @param audit_info the audit information from which to create a JSON object.
 *
 * @return the JSON object (which may be valid or not)
 *
 *
 */
struct json_object json_from_audit_info(const struct authn_audit_info *audit_info)
{
	struct json_object object = json_new_object();
	enum auth_event_id_type auth_event_id;
	const struct auth_user_info_dc *client_info = NULL;
	const char *policy_name = NULL;
	const char *silo_name = NULL;
	const bool *policy_enforced = NULL;
	NTSTATUS policy_status;
	struct authn_int64_optional tgt_lifetime_mins;
	const char *location = NULL;
	const char *audit_event = NULL;
	const char *audit_reason = NULL;
	int rc = 0;

	if (json_is_invalid(&object)) {
		goto failure;
	}

	auth_event_id = authn_audit_info_event_id(audit_info);
	rc = json_add_int(&object, "eventId", auth_event_id);
	if (rc != 0) {
		goto failure;
	}

	policy_name = authn_audit_info_policy_name(audit_info);
	rc = json_add_string(&object, "policyName", policy_name);
	if (rc != 0) {
		goto failure;
	}

	silo_name = authn_audit_info_silo_name(audit_info);
	rc = json_add_string(&object, "siloName", silo_name);
	if (rc != 0) {
		goto failure;
	}

	policy_enforced = authn_audit_info_policy_enforced(audit_info);
	rc = json_add_optional_bool(&object, "policyEnforced", policy_enforced);
	if (rc != 0) {
		goto failure;
	}

	policy_status = authn_audit_info_policy_status(audit_info);
	rc = json_add_string(&object, "status", nt_errstr(policy_status));
	if (rc != 0) {
		goto failure;
	}

	tgt_lifetime_mins = authn_audit_info_policy_tgt_lifetime_mins(audit_info);
	if (tgt_lifetime_mins.is_present) {
		rc = json_add_int(&object, "tgtLifetime", tgt_lifetime_mins.val);
		if (rc != 0) {
			goto failure;
		}
	}

	location = authn_audit_info_location(audit_info);
	rc = json_add_string(&object, "location", location);
	if (rc != 0) {
		goto failure;
	}

	audit_event = authn_audit_info_event(audit_info);
	rc = json_add_string(&object, "auditEvent", audit_event);
	if (rc != 0) {
		goto failure;
	}

	audit_reason = authn_audit_info_reason(audit_info);
	rc = json_add_string(&object, "reason", audit_reason);
	if (rc != 0) {
		goto failure;
	}

	client_info = authn_audit_info_client_info(audit_info);
	if (client_info != NULL) {
		const struct auth_user_info *client_user_info = NULL;

		client_user_info = client_info->info;
		if (client_user_info != NULL) {
			rc = json_add_string(&object, "checkedDomain", client_user_info->domain_name);
			if (rc != 0) {
				goto failure;
			}

			rc = json_add_string(&object, "checkedAccount", client_user_info->account_name);
			if (rc != 0) {
				goto failure;
			}

			rc = json_add_string(&object, "checkedLogonServer", client_user_info->logon_server);
			if (rc != 0) {
				goto failure;
			}

			rc = json_add_flags32(&object, "checkedAccountFlags", client_user_info->acct_flags);
			if (rc != 0) {
				goto failure;
			}
		}

		if (client_info->num_sids) {
			const struct dom_sid *policy_checked_sid = NULL;

			policy_checked_sid = &client_info->sids[PRIMARY_USER_SID_INDEX].sid;
			rc = json_add_sid(&object, "checkedSid", policy_checked_sid);
			if (rc != 0) {
				goto failure;
			}
		}
	}

	return object;

failure:
	json_free(&object);
	return object;
}

/*
 * @brief iterate through objects in a json array
 *
 * Iterate through elements of json array and call callback
 * function for each of them.
 *
 * @param object the json object
 * @param fn callback function
 * @param private_data private data to pass to callback function
 *
 * @return 0 on success -1 on failure
 */
int iter_json_array(struct json_object *object,
		    bool (*fn)(int index,
			       struct json_object *entry,
			       void *state),
		    void *private_data)
{
	int i;
	size_t array_size;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object.\n");
		return -1;
	}
	if (!json_is_array(object->root)) {
		DBG_ERR("JSON object is not an array\n");
		return -1;
	}

	array_size = json_array_size(object->root);
	for (i = 0; i < array_size; i++) {
		bool ok;
		json_t *entry = NULL;
		struct json_object jsobj = json_empty_object;

		entry = json_array_get(object->root, i);
		if (entry == NULL) {
			DBG_ERR("Idx [%d] in JSON array is invalid\n", i);
			return -1;
		}

		jsobj = (struct json_object) {
			.root = entry,
			.valid = true,
		};

		ok = fn(i, &jsobj, private_data);
		if (!ok) {
			return -1;
		}
	}
	return 0;
}

/*
 * @brief iterate through keys in a json object
 *
 * Iterate through keys in a json object, and call callback
 * function for each of them.
 *
 * @param object the json object
 * @param fn callback function
 * @param private_data private data to pass to callback function
 *
 * @return 0 on success -1 on failure
 */
int iter_json_object(struct json_object *object,
		     bool (*fn)(const char *key,
				struct json_object *value,
				void *state),
		     void *private_data)
{
	void *tmp = NULL;
	const char *key = NULL;
	json_t *value = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object.\n");
		return -1;
	}

	json_object_foreach_safe(object->root, tmp, key, value) {
		bool ok;
		struct json_object jsobj = json_empty_object;

		jsobj = (struct json_object) {
			.root = value,
			.valid = true,
		};

		ok = fn(key, &jsobj, private_data);
		if (!ok) {
			return -1;
		}
	}
	return 0;
}

int json_get_string_value(const struct json_object *object,
			  const char *key,
			  const char **valp)
{
	json_t *to_check = NULL;
	const char *value = NULL;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (!json_is_string(to_check)) {
		DBG_ERR("%s: Unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		return -1;
	}

	value = json_string_value(to_check);
	*valp = value;
	return 0;
}

int json_get_bool_value(const struct json_object *object,
			const char *key,
			bool *valp)
{
	json_t *to_check = NULL;
	bool value;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (!json_is_boolean(to_check)) {
		DBG_ERR("%s: unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		return -1;
	}

	value = json_boolean_value(to_check);
	*valp = value;
	return 0;
}

int json_get_int_value(const struct json_object *object,
		       const char *key,
		       int *valp)
{
	json_t *to_check = NULL;
	int value;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (!json_is_integer(to_check)) {
		DBG_ERR("%s: unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		return -1;
	}

	value = json_integer_value(to_check);
	*valp = value;
	return 0;
}

int json_get_array_value(const struct json_object *object,
			 const char *key,
			 struct json_object *valp)
{
	json_t *to_check = NULL;
	int value;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		valp->valid = false;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		valp->valid = false;
		return -1;
	}

	if (!json_is_array(to_check)) {
		DBG_ERR("%s: unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		valp->valid = false;
		return -1;
	}

	valp->root = to_check;
	valp->valid = true;
	return 0;
}

/*
 * @brief convert text into a json object
 *
 * Load json from text. This is primarily useful for adding
 * json input support for utilities. libjansson will perform
 * validation and report errors, which we print at DBG_ERR.
 *
 * @param text string to convert to struct json object
 *
 * @return a struct json_object, valid will be set to false if the object
 *         could not be created.
 */
struct json_object load_json(const char *text)
{
	struct json_object object = json_empty_object;
	json_t *root = NULL;
	json_error_t error;

	root = json_loads(text, 0, &error);
	if (root == NULL) {
		DBG_ERR("JSON error on line %d: %s\n",
			error.line, error.text);
		object.valid = false;
		return object;
	}
	object = (struct json_object) {
		.root = root,
		.valid = true,
	};
	return object;
}
#endif
