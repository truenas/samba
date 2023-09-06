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

bool _json_add_unix_sec_token(const struct security_unix_token *token,
			      struct json_object *jsobj,
			      uint32_t flags,
			      const char *location)
{
	int error;
	bool ok;

	if (json_is_invalid(jsobj)) {
		DBG_ERR("%s: Unable to add unix sec token to object. "
			"Target object is invalid\n", location);
		return false;
	}

	if (flags & SMB_JSON_UTOK_UID_GID) {
		error = json_add_int(jsobj, "uid", token->uid);
		if (error) {
			DBG_ERR("%s: failed to add uid to JSON object\n",
				location);
			return false;
		}

		error = json_add_int(jsobj, "gid", token->gid);
		if (error) {
			DBG_ERR("%s: failed to add gid to JSON object\n",
				location);
			return false;
		}
	}

	if (flags & SMB_JSON_UTOK_GROUPS) {
		ok = json_add_gid_array(jsobj, "groups",
					token->ngroups,
					token->groups);
		if (!ok) {
			DBG_ERR("%s: failed to add groups to JSON object\n",
				location);
			return false;
		}
	}

	return true;
}

bool _json_add_sec_token(const struct security_token *token,
			 struct json_object *jsobj,
			 uint32_t flags,
			 const char *location)
{
	bool ok;

	if (json_is_invalid(jsobj)) {
		DBG_ERR("%s: Unable to add sec token to object. "
			"Target object is invalid\n", location);
		return false;
	}

	if (flags & SMB_JSON_STOK_SIDS) {
		ok = json_add_sid_array(jsobj, "sids",
					token->num_sids,
					token->sids);
		if (!ok) {
			return false;
		}
	}

	if (flags & SMB_JSON_STOK_PRIV) {
		ok = json_add_map_to_object(jsobj, "privilege_mask",
					    token->privilege_mask);
		if (!ok) {
			return false;
		}
	}

	if (flags & SMB_JSON_STOK_RIGHTS) {
		ok = json_add_map_to_object(jsobj, "rights_mask",
					    token->rights_mask);
		if (!ok) {
			return false;
		}
	}

	return true;
}

bool _json_add_auth_user_info(const struct auth_user_info *info,
			      struct json_object *jsobj,
			      uint32_t flags,
			      const char *location)
{
	int error;
	bool ok;
	uint32_t time_flags = flags & SMB_JSON_AUTH_INFO_TS_LOCAL ?
			      SMB_JSON_TIME_LOCAL : 0;

	if (json_is_invalid(jsobj)) {
		DBG_ERR("%s: Unable to add auth_user_info to object. "
			"Target object is invalid\n", location);
		return false;
	}

	if (flags & SMB_JSON_AUTH_INFO_NAME) {
		error = json_add_string(jsobj, "account_name",
					info->account_name);
		if (error) {
			DBG_ERR("%s: failed to add account name to "
				"JSON object\n", location);
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_UPN) {
		error = json_add_string(jsobj, "user_principal_name",
					info->account_name);
		if (error) {
			DBG_ERR("%s: failed to add UPN to "
				"JSON object\n", location);
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_DOM) {
		error = json_add_string(jsobj, "domain_name",
					info->domain_name);
		if (error) {
			DBG_ERR("%s: failed to add domain name to "
				"JSON object\n", location);
			return false;
		}

		error = json_add_string(jsobj, "dns_domain_name",
					info->dns_domain_name);
		if (error) {
			DBG_ERR("%s: failed to add DNS domain name to "
				"JSON object\n", location);
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_EXTRA) {
		error = json_add_string(jsobj, "full_name",
					info->full_name);
		if (error) {
			DBG_ERR("%s: failed to add full_name to "
				"JSON object\n", location);
			return false;
		}

		error = json_add_string(jsobj, "logon_script",
					info->logon_script);
		if (error) {
			DBG_ERR("%s: failed to add logon_script to "
				"JSON object\n", location);
			return false;
		}

		error = json_add_string(jsobj, "profile_path",
					info->profile_path);
		if (error) {
			DBG_ERR("%s: failed to add profile_path to "
				"JSON object\n", location);
			return false;
		}

		error = json_add_string(jsobj, "home_directory",
					info->home_directory);
		if (error) {
			DBG_ERR("%s: failed to add home_directory to "
				"JSON object\n", location);
			return false;
		}

		error = json_add_string(jsobj, "home_drive",
					info->home_drive);
		if (error) {
			DBG_ERR("%s: failed to add home_drive to "
				"JSON object\n", location);
			return false;
		}

		error = json_add_string(jsobj, "logon_server",
					info->logon_server);
		if (error) {
			DBG_ERR("%s: failed to add logon_server to "
				"JSON object\n", location);
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_TS) {
		ok = _json_add_nt_time(jsobj, "last_logon",
				       info->last_logon,
				       time_flags,
				       location);
		if (!ok) {
			DBG_ERR("%s: failed to add last_logon to "
				"JSON object\n", location);
			return false;
		}

		ok = _json_add_nt_time(jsobj, "last_logoff",
				       info->last_logoff,
				       time_flags,
				       location);
		if (!ok) {
			DBG_ERR("%s: failed to add last_logoff to "
				"JSON object\n", location);
			return false;
		}

		ok = _json_add_nt_time(jsobj, "acct_expiry",
				       info->acct_expiry,
				       time_flags,
				       location);
		if (!ok) {
			DBG_ERR("%s: failed to add acct_expiry to "
				"JSON object\n", location);
			return false;
		}

		ok = _json_add_nt_time(jsobj, "last_password_change",
				       info->last_password_change,
				       time_flags,
				       location);
		if (!ok) {
			DBG_ERR("%s: failed to add last_password_change to "
				"JSON object\n", location);
			return false;
		}

		ok = _json_add_nt_time(jsobj, "force_password_change",
				       info->force_password_change,
				       time_flags,
				       location);
		if (!ok) {
			DBG_ERR("%s: failed to add force_password_change to "
				"JSON object\n", location);
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_CNT) {
		error = json_add_int(jsobj, "logon_count", info->logon_count);
		if (error) {
			DBG_ERR("%s: failed to add logon_count to "
				"JSON object\n", location);
			return false;
		}

		error = json_add_int(jsobj, "bad_password_count",
				     info->bad_password_count);
		if (error) {
			DBG_ERR("%s: failed to add bad_password_count to "
				"JSON object\n", location);
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_FLAGS) {
		ok = json_add_map_to_object(jsobj, "acct_flags",
					       info->acct_flags);
		if (!ok) {
			DBG_ERR("%s: failed to add acct_flags to "
				"JSON object\n", location);
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_AUTHD) {
		error = json_add_bool(jsobj, "authenticated",
				      info->authenticated);
		if (error) {
			DBG_ERR("%s: failed to add authenticated to "
				"JSON object\n", location);
			return false;
		}
	}

	return true;
}

bool _json_add_auth_session_info(const struct auth_session_info *sess,
				 struct json_object *jsobj,
				 uint32_t flags,
				 const char *location)
{
	int error;
	bool ok;
	struct json_object subobj;

	if (json_is_invalid(jsobj)) {
		DBG_ERR("%s: Unable to add session information to object. "
			"Target object is invalid\n", location);
		return false;
	}

	if (flags & SMB_JSON_SESS_USERNAME) {
		error = json_add_string(jsobj,
					"username",
					sess->unix_info->sanitized_username);
		if (error) {
			return false;
		}
	}

	if (flags & SMB_JSON_UTOK_ALL) {
		subobj = json_new_object();
		if (json_is_invalid(&subobj)) {
			return false;
		}

		ok = _json_add_unix_sec_token(sess->unix_token,
					      &subobj,
					      flags & SMB_JSON_UTOK_ALL,
					      location);
		if (!ok) {
			json_free(&subobj);
			return false;
		}

		error = json_add_object(jsobj, "unix_token", &subobj);
		if (error) {
			return false;
		}
	}

	if (flags & SMB_JSON_STOK_ALL) {
		subobj = json_new_object();
		if (json_is_invalid(&subobj)) {
			return false;
		}

		ok = _json_add_sec_token(sess->security_token,
					 &subobj,
					 flags & SMB_JSON_STOK_ALL,
					 location);
		if (!ok) {
			json_free(&subobj);
			return false;
		}

		error = json_add_object(jsobj, "security_token", &subobj);
		if (error) {
			return false;
		}
	}

	if (flags & SMB_JSON_AUTH_INFO_ALL) {
		subobj = json_new_object();
		if (json_is_invalid(&subobj)) {
			return false;
		}

		ok = _json_add_auth_user_info(sess->info,
					      &subobj,
					      flags & SMB_JSON_AUTH_INFO_ALL,
					      location);
		if (!ok) {
			json_free(&subobj);
			return false;
		}

		error = json_add_object(jsobj, "info", &subobj);
		if (error) {
			return false;
		}
	}

	if (flags & SMB_JSON_SESS_UNIQUE_TOKEN) {
		error = json_add_guid(jsobj,
				      "unique_session_token",
				      &sess->unique_session_token);
		if (error) {
			return false;
		}
	}

	return true;
}
