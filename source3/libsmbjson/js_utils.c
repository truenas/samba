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
#include "libcli/security/dom_sid.h"

#include <jansson.h>
#include "audit_logging.h"
#include "smb_json.h"

bool _json_object_dup(struct json_object *src,
		      const char *key,
		      struct json_object *dst,
		      const char *location)
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
		DBG_ERR("%s: failed to deep copy JSON object %s\n",
			location, strerror(errno));
		return false;
	}

	error = json_add_object(dst, key, &tmp);
	if (error) {
		DBG_ERR("%s: failed to add JSON object %s\n",
			location, strerror(errno));
		return false;
	}

	return true;
}

bool _json_add_gid_array(struct json_object *object,
			 const char *key,
			 uint32_t ngroups,
			 gid_t *groups,
			 const char *location)
{
	uint32_t i;
	int err;
	json_t *jsarr = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add groups array to object. "
			"Target object is invalid\n", location);
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
			DBG_ERR("%s: failed to create JSON integer "
				"for gid [%u]\n",
				location, groups[i]);
			json_decref(jsarr);
			return false;
		}

		err = json_array_append_new(jsarr, jsgid);
		if (err) {
			json_decref(jsarr);
			return false;
		}
	}

	err = json_object_set_new(object->root, key, jsarr);
	if (err) {
		DBG_ERR("%s: Unable to add gid array to object.\n",
			location);
		return false;
	}

	return true;
}

bool _json_add_sid_array(struct json_object *object,
			 const char *key,
			 uint32_t nsids,
			 struct dom_sid *sids,
			 const char *location)
{
	uint32_t i;
	int err;
	json_t *jsarr = NULL;
	struct dom_sid_buf sid_buf;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add sid array to object. "
			"Target object is invalid\n", location);
		return false;
	}

	jsarr = json_array();
	if (jsarr == NULL) {
		return false;
	}

	for (i = 0; i < nsids; i++) {
		json_t *jssid = NULL;
		jssid = json_string(dom_sid_str_buf(&sids[i], &sid_buf));
		if (jssid == NULL) {
			json_decref(jsarr);
			return false;
		}

		err = json_array_append_new(jsarr, jssid);
		if (err) {
			json_decref(jsarr);
			return false;
		}
	}

	err = json_object_set_new(object->root, key, jsarr);
	if (err) {
		DBG_ERR("Unable to add sid array to object.\n");
		return false;
	}

	return true;
}

bool _json_add_enum_list_array(struct json_object *object,
			       const char *key,
			       uint32_t mask,
			       size_t nelem,
			       const struct enum_list *list,
			       const char *location)
{
	size_t i;
	int err;
	json_t *jsarr = NULL;
	struct enum_list entry;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add enum list to object. "
			"Target object is invalid\n", location);
		return false;
	}

	jsarr = json_array();
	if (jsarr == NULL) {
		return false;
	}

	for (i = 0; i < nelem; i++) {
		json_t *jsname = NULL;
		entry = list[i];

		if ((mask & entry.value) == 0) {
			continue;
		}

		jsname = json_string(entry.name);
		if (jsname == NULL) {
			DBG_ERR("%s: failed to convert %s to string\n",
				location, entry.name);
			json_decref(jsarr);
			json_decref(jsname);
			return false;
		}

		err = json_array_append_new(jsarr, jsname);
		if (err) {
			DBG_ERR("%s: failed to append %s to array\n",
				location, entry.name);
			json_decref(jsarr);
			return false;
		}
	}

	err = json_object_set_new(object->root, key, jsarr);
	if (err) {
		DBG_ERR("%s: Unable to add enum list to object.\n", location);
		return false;
	}

	return true;
}

bool _json_add_enum_list_find(struct json_object *object,
			      const char *key,
			      uint32_t value,
			      size_t nelem,
			      const struct enum_list *list,
			      const char *default_value,
			      const char *location)
{
	size_t i;
	int err;
	const char *found = default_value;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add sid array to object. "
			"Target object is invalid\n", location);
		return false;
	}

	for (i = 0; i < nelem; i++) {
		if (value == list[i].value) {
			found = list[i].name;
			break;
		}
	}

	if (found == NULL) {
		errno = ENOENT;
		return false;
	}

	err = json_add_string(object, key, found);

	return err ? false : true;
}

bool _json_add_vers(struct json_object *object,
		    const char *key,
		    int vers_major,
		    int vers_minor,
		    const char *location)
{
	struct json_object vers;
	int err;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add version to object. "
			"Target object is invalid\n", location);
		return false;
	}

	vers = json_new_object();
	if (json_is_invalid(&vers)) {
		return false;
	}

	err = json_add_int(&vers, "major", vers_major);
	if (err) {
		DBG_ERR("%s: Failed to add major version to object\n",
			location);
		json_free(&vers);
		return false;
	}

	err = json_add_int(&vers, "minor", vers_minor);
	if (err) {
		DBG_ERR("%s: Failed to add minor version to object\n",
			location);
		json_free(&vers);
		return false;
	}

	err = json_add_object(object, key, &vers);
	if (err) {
		DBG_ERR("%s: Failed to add version object.\n",
			location);
		return false;
	}

	return true;
}

bool _json_add_time(struct json_object *object,
		    const char *key,
		    struct timeval *tvp,
		    uint32_t flags,
		    const char *location)
{
	char buffer[40];
	char ts[65];
	char tz[10];
	struct tm *tm_info, tmbuf;
	struct timeval tv;
	int r;
	int ret;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add timestamp to object. "
			"Target object is invalid\n", location);
		return false;
	}

	if (tvp == NULL) {
		r = gettimeofday(&tv, NULL);
		if (r) {
			DBG_ERR("%s: Unable to get time of day: (%d) %s\n",
				location, errno, strerror(errno));
			return false;
		}
		tvp = &tv;
	}

	if (flags & SMB_JSON_TIME_LOCAL) {
		tm_info = localtime_r(&tvp->tv_sec, &tmbuf);
	} else {
		tm_info = gmtime_r(&tvp->tv_sec, &tmbuf);
	}

	if (tm_info == NULL) {
		DBG_ERR("%s: Unable to determine time\n", location);
		return false;
	}

	strftime(buffer, sizeof(buffer)-1, "%Y-%m-%d %T", tm_info);

	if (flags & SMB_JSON_TIME_LOCAL) {
		strftime(tz, sizeof(tz)-1, "%z", tm_info);
		snprintf(ts, sizeof(ts), "%s.%06ld%s", buffer, tvp->tv_usec, tz);
	} else {
		snprintf(ts, sizeof(ts), "%s.%06ldZ", buffer, tvp->tv_usec);
	}

	ret = json_add_string(object, key, ts);
	if (ret != 0) {
		DBG_ERR("%s: Unable to add time to JSON object\n", location);
		return false;
	}

	return true;
}

bool _json_add_nt_time(struct json_object *object,
		       const char *key,
		       NTTIME nt,
		       uint32_t flags,
		       const char *location)
{
	int error;
	struct timeval tv;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add NTTIME to object. "
			"Target object is invalid\n", location);
		return false;
	}

	if ((nt == NTTIME_OMIT) || (nt == NTTIME_MIN)) {
		error = json_add_string(object, key, NULL);
		if (error) {
			DBG_ERR("%s: failed to add NTTIME to object.\n",
				location);
			return false;
		}
		return true;
	}

	nttime_to_timeval(&tv, nt);

	return _json_add_time(object, key, &tv, flags, location);
}

bool _json_add_inet_addr(struct json_object *object,
			 const char *key,
			 const struct tsocket_address *addr,
			 const char *location)
{
	char *addr_s = NULL;
	int error;

	if (json_is_invalid(object)) {
		DBG_ERR("%s: Unable to add address to object. "
			"Target object is invalid\n", location);
		return false;
	}

	if (addr == NULL) {
		error = json_add_string(object, key, NULL);
		if (error) {
			DBG_ERR("%s: failed to add null for address\n",
				location);
			return false;
		}
		return true;
	}

	addr_s = tsocket_address_inet_addr_string(addr, talloc_tos());
	if (addr_s == NULL) {
		DBG_ERR("%s: Out of memory adding address.\n", location);
		return false;
	}

	error = json_add_string(object, key, addr_s);
	TALLOC_FREE(addr_s);
	return error ? false : true;
}

static bool add_conv_to_object(uint64_t val,
			       const char *name,
			       const char *map,
			       struct json_object *jsobj,
			       const char *location)
{
	int error;
	char buf[22];

	if (json_is_invalid(jsobj)) {
		DBG_ERR("%s: Unable to add %s to object. "
			"Target object is invalid\n",
			location, name);
		return false;
	}

	snprintf(buf, sizeof(buf), map, val);
	error = json_add_string(jsobj, name, buf);
	if (error) {
		DBG_ERR("%s: failed to add %s to JSON object\n",
			location, buf);
		return false;
	}

	return true;
}

bool _json_add_map_to_object(struct json_object *jsobj,
			     const char *name,
			     uint32_t attr,
			     const char *location)
{
	return add_conv_to_object(attr, name, "0x%08x", jsobj, location);
}

bool _json_add_u64_to_object(struct json_object *jsobj,
			     const char *name,
			     uint64_t val,
			     const char *location)
{
	return add_conv_to_object(val, name, "%lu", jsobj, location);
}

static bool json_add_result_common(const char *res_type,
				   int err,
				   const char *err_str,
				   struct json_object *object,
				   const char *location)
{
        int error;

        if (json_is_invalid(object)) {
                DBG_ERR("Unable to add result. Target object is invalid\n");
                return false;
        }

        error = json_add_string(object, "type", res_type);
        if (error) {
		return false;
        }

        error = json_add_int(object, "value_raw", err);
        if (error) {
		return false;
        }

        error = json_add_string(object, "value_parsed",
                                err ? err_str : "SUCCESS");

	return error ? false : true;
}

bool _json_add_result_unix(struct json_object *object,
			   int err,
			   const char *location)
{
	return json_add_result_common("UNIX",
				      err,
				      strerror(err),
				      object,
				      location);
}

bool _json_add_result_ntstatus(struct json_object *object,
			       NTSTATUS status,
			       const char *location)
{
	return json_add_result_common("NTSTATUS",
				      NT_STATUS_V(status),
				      nt_errstr(status),
				      object,
				      location);
}
