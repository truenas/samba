/*
 * Copyright (C) iXsystems, Inc                 2023
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

#ifndef ___JS_UTILS_H
#define __JS_UTILS_H

/**
 * @brief Perform deep copy of JSON object and insert in specfied object
 *
 * @param[in] src     Source object that will be copied
 * @param[in] key     Key to use for newly created JSON object
 * @param[in] dst     Target for new copy
 *
 * @return            boolean True on success False on failure
 */
bool _json_object_dup(struct json_object *src,
		      const char *key,
		      struct json_object *dst,
		      const char *location);

#define json_object_dup(src, key, dst) \
	_json_object_dup(src, key, dst, __location__)

#define SMB_JSON_TIME_LOCAL 0x01
/**
 * @brief Add ISO 8601 timestamp to specified JSON object
 *
 * @param[in] object  JSON object to which to add timestamp
 * @param[in] key     Key to use to attach timestamp
 * @param[in] tvp     Timeval struct to convert into timestamp
 *		      NULL value has special meaning that system
 *		      will retrieve current timestamp
 * @param[in] flags   special flags related to operation
 *		      SMB_JSON_TIME_LOCAL - get local time instead
 *		      of UTC
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_time(struct json_object *object,
		    const char *key,
		    struct timeval *tvp,
		    uint32_t flags,
		    const char *location);

#define json_add_time(object, key, tvp, flags) \
	_json_add_time(object, key, tvp, flags, __location__)

/**
 * @brief Add NT TIME converted to ISO 8601 timestamp to specified JSON object
 *
 * @param[in] object  JSON object to which to add timestamp
 * @param[in] key     Key to use to attach timestamp
 * @param[in] nt      Timestamp in NTTIME
 * @param[in] flags   special flags related to operation
 *		      SMB_JSON_TIME_LOCAL - get local time instead
 *		      of UTC
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_nt_time(struct json_object *object,
		       const char *key,
		       NTTIME nt,
		       uint32_t flags,
		       const char *location);
#define json_add_nt_time(object, key, nt, flags) \
	_json_add_nt_time(object, key, nt, flags, __location__)

/**
 * @brief Convert an array of GIDs to an array of JSON numbers
 *
 * @param[in] object  JSON object to which to add the array of GIDs
 * @param[in] key     Key to use to attach gids
 * @param[in] ngroups Number of groups in GID array
 * @param[in] groups  GIDs to add
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_gid_array(struct json_object *object,
			 const char *key,
			 uint32_t ngroups,
			 gid_t *groups,
			 const char *location);

#define json_add_gid_array(object, key, ngroups, groups) \
	_json_add_gid_array(object, key, ngroups, groups, __location__)

/**
 * @brief Convert an array of SIDs to an array of SID strings
 *
 * @param[in] object  JSON object to which to add the array of SIDs
 * @param[in] key     Key to use to attach SIDs
 * @param[in] nsids   Number of SIDs in SID array
 * @param[in] sids    SIDs to add
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_sid_array(struct json_object *object,
			 const char *key,
			 uint32_t nsids,
			 struct dom_sid *sids,
			 const char *location);
#define json_add_sid_array(object, key, nsids, sids) \
	_json_add_sid_array(object, key, nsids, sids, __location__)

/**
 * @brief  Use bitmap to generate attach a JSON array of strings
 * based on a specified enum list and attach to specified JSON
 * object using specified key.
 *
 * @param[in] object  JSON object to which to add the array of strings
 * @param[in] key     Key to use to attach array
 * @param[in] mask    Mask of values to map
 * @param[in] nelem   size of enum_list array
 * @param[in] list    array of enum_list structs
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_enum_list_array(struct json_object *object,
			       const char *key,
			       uint32_t mask,
			       size_t nelem,
			       const struct enum_list *list,
			       const char *location);
#define json_add_enum_list_array(object, key, mask, nelem, list) \
	_json_add_enum_list_array(object, key, mask, nelem, list, __location__)

/**
 * @brief Search specified enum_list for specified value and add string
 * name to specified JSON object using specified name. If default value
 * is specified and the value is not found in the enum_list array, then
 * the default value will be used instead. If no match is found and default
 * value is _not_ specified, then this operation will fail with errno set
 * to ENOENT.
 *
 * @param[in] object  JSON object to which to add the array of strings
 * @param[in] key     Key to use to attach array
 * @param[in] value   Value to search for in enum_list array
 * @param[in] nelem   size of enum_list array
 * @param[in] list    array of enum_list structs
 * @param[in] def     default value to supply in case of lookup failure
 *                    This may be NULL
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_enum_list_find(struct json_object *object,
			      const char *key,
			      uint32_t value,
			      size_t nelem,
			      const struct enum_list *list,
			      const char *def,
			      const char *location);
#define json_add_enum_list_find(obj, key, mask, nelem, list, def) \
	_json_add_enum_list_find(obj, key, mask, nelem, list, def, __location__)

/**
 * @brief Add version object to specified JSON object with specified
 * major and minor versions using specified key.
 *
 * @param[in] object  JSON object to which to add version
 * @param[in] key     Key to use to attach version
 * @param[in] major   Major version
 * @param[in] minor   Minor version
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_vers(struct json_object *object,
		    const char *key,
		    int vers_major,
		    int vers_minor,
		    const char *location);
#define json_add_vers(object, key, vers_major, vers_minor) \
	_json_add_vers(object, key, vers_major, vers_minor, __location__)

/**
 * @brief Add IP address based on tsocket_address to the specified
 * JSON object using specified key.
 *
 * @param[in] object  JSON object to which to add address
 * @param[in] key     Key to use to attach address
 * @param[in] addr    struct tsocket_address
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_inet_addr(struct json_object *object,
			 const char *key,
			 const struct tsocket_address *addr,
			 const char *location);
#define json_add_inet_addr(object, key, addr) \
	_json_add_inet_addr(object, key, addr, __location__)

/**
 * @brief Convert specified bitmap to hex string (0x%08x) and
 * attach to specified JSON object using specified key.
 *
 * @param[in] object  JSON object to which to add address
 * @param[in] name    Key to use to attach address
 * @param[in] attr    mask to convert
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_map_to_object(struct json_object *jsobj,
			     const char *name,
			     uint32_t attr,
			     const char *location);
#define json_add_map_to_object(jsobj, name, attr) \
	_json_add_map_to_object(jsobj, name, attr, __location__)

/**
 * @brief Convert specified 64bit unsigned integer to JSON string
 * and attach to specified JSON object using specified key. This
 * is useful for cases where there is concern about overflowing
 * maximum value of JSON number.
 *
 * @param[in] object  JSON object to which to add address
 * @param[in] name    Key to use to attach address
 * @param[in] attr    mask to convert
 *
 * @return            boolean True on success False on failure
 */
bool _json_add_u64_to_object(struct json_object *jsobj,
			     const char *name,
			     uint64_t val,
			     const char *location);
#define json_add_u64_to_object(jsobj, name, val) \
	_json_add_u64_to_object(jsobj, name, val, __location__)

/**
 * @brief Add UNIX result to JSON message.
 *
 * This adds three keys to the specified JSON message
 * based on the provided UNIX errno.
 * "type": "UNIX"
 * "value_raw": <JSON number for errno>
 * "value_parsed": <strerror output of errno>
 *
 * @param[in] object   JSON object to which to attach status.
 * @param[in] err      errno to convert to JSON
 *
 * @return             boolean True on success False on failure
 */
bool _json_add_result_unix(struct json_object *object,
			   int err,
			   const char *location);
#define json_add_result_unix(object, err) \
	_json_add_result_unix(object, err, __location__)

/**
 * @brief Add NTSTATUS result to JSON message.
 *
 * This adds three keys to the specified JSON message
 * based on the provided NTSTATUS code.
 * "type": "NTSTATUS"
 * "value_raw": <JSON number of error code>
 * "value_parsed": <nt_errstr output of status code>
 *
 * @param[in] object   JSON object to which to attach status.
 * @param[in] status   NTSTATUS to convert to JSON
 *
 * @return             boolean True on success False on failure
 */
bool _json_add_result_ntstatus(struct json_object *object,
			       NTSTATUS status,
			       const char *location);
#define json_add_result_ntstatus(object, status) \
	_json_add_result_ntstatus(object, status, __location__)
#endif /* __JS_UTILS_H */
