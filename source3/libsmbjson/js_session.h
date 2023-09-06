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

#ifndef __JS_SESSION_H
#define __JS_SESSION_H

/*
 * Flags indicating which info to gather from struct unix_security_token
 * SMB_JSON_UTOK_UID_GID adds
 * "uid": <UID>
 * "gid": <GID>
 *
 * SMB_JSON_UTOK_GROUPS adds
 * "groups": [<GID 1>, <GID 2>, <GID n>, ...]
 */
#define SMB_JSON_UTOK_UID_GID		0x00000001
#define SMB_JSON_UTOK_GROUPS		0x00000002
#define SMB_JSON_UTOK_ALL (\
	SMB_JSON_UTOK_UID_GID | \
	SMB_JSON_UTOK_GROUPS)

/*
 * Flags indicating which info to gather from struct security_token
 * SMB_JSON_STOK_SIDS adds
 * "sids": [<SID STRING 1>, <SID STRING n>, ...]
 *
 * SMB_JSON_STOK_PRIV adds se_privilege mask in hex format
 * "privilege": <Hex STRING>
 * SMB_JSON_STOK_RIGHTS adds lsa_SystemAccessModeFlags mask in hex format
 * "rights": <Hex STRING>
 */
#define SMB_JSON_STOK_SIDS		0x00000004
#define SMB_JSON_STOK_PRIV		0x00000008
#define SMB_JSON_STOK_RIGHTS		0x00000010
#define SMB_JSON_STOK_ALL (\
	SMB_JSON_STOK_SIDS | \
	SMB_JSON_STOK_PRIV | \
	SMB_JSON_STOK_RIGHTS)

/*
 * Flags indicating which info to gather from struct auth_user_info
 * SMB_JSON_AUTH_INFO_NAME - account_name as "account_name"
 * SMB_JSON_AUTH_INFO_UPN - user_principal_name as "user_principal_name"
 *
 * SMB_JSON_AUTH_INFO_DOM - domain information as follows:
 * "domain_name": <info->domain_name>
 * "dns_domain_name": <info->dns_domain_name>
 *
 * SMB_JSON_AUTH_INFO_EXTRA - extra user account details as follows:
 * "full_name": <info->full_name>
 * "logon_script": <info->logon_script>
 * "profile_path": <info->profile_path>
 * "home_directory": <info->home_directory>
 * "home_drive": <info->home_drive>
 * "logon_server": <info->logon_server>
 *
 * SMB_JSON_AUTH_INFO_TS - timestamps related to the account converted
 * to ISO 8601 / UTC. Unitiialized timestamps are replaced with JSON null
 * "last_logon": <info->last_logon>
 * "last_logoff": <info->last_logoff>
 * "last_password_change": <info->last_password_change>
 * "allow_password_change: <info->allow_password_change>
 * "force_password_change: <info->force_password_change>
 * SMB_JSON_AUTH_INFO_TS_LOCAL - print timestamp in local time rather than
 * UTC
 *
 * SMB_JSON_AUTH_INFO_CNT - counters related to the account
 * "logon_count": <info->logon_count>
 * "bad_password_count": <info->bad_password_count>
 *
 * SMB_JSON_AUTH_INFO_FLAGS - info->acct_flags as hex string
 * "acct_flags": <hex STRING>
 */
#define SMB_JSON_AUTH_INFO_NAME		0x00000080
#define SMB_JSON_AUTH_INFO_UPN		0x00000100
#define SMB_JSON_AUTH_INFO_DOM		0x00000200
#define SMB_JSON_AUTH_INFO_EXTRA	0x00000400
#define SMB_JSON_AUTH_INFO_FLAGS	0x00000800
#define SMB_JSON_AUTH_INFO_CNT		0x00001000
#define SMB_JSON_AUTH_INFO_TS		0x00002000
#define SMB_JSON_AUTH_INFO_TS_LOCAL	(0x00004000 | \
	SMB_JSON_AUTH_INFO_TS)
#define SMB_JSON_AUTH_INFO_ALL (\
	SMB_JSON_AUTH_INFO_NAME | \
	SMB_JSON_AUTH_INFO_UPN | \
	SMB_JSON_AUTH_INFO_DOM | \
	SMB_JSON_AUTH_INFO_EXTRA | \
	SMB_JSON_AUTH_INFO_FLAGS | \
	SMB_JSON_AUTH_INFO_CNT | \
	SMB_JSON_AUTH_INFO_TS)

/*
 * Flags indicating which info to gather from struct auth_session_info
 * SMB_JSON_SESS_USERNAME adds sanitized username as
 * "username": <string>
 *
 * SMB_JSON_SESS_UNIQUE_TOKEN adds the session guid as
 * "unique_session_token": <GUID string>
 */
#define SMB_JSON_SESS_USERNAME		0x00000020
#define SMB_JSON_SESS_UNIQUE_TOKEN	0x00000040
#define SMB_JSON_SESS_ALL (\
	SMB_JSON_SESS_USERNAME | \
	SMB_JSON_SESS_UNIQUE_TOKEN | \
	SMB_JSON_UTOK_ALL | \
	SMB_JSON_STOK_ALL | \
	SMB_JSON_AUTH_INFO_ALL)

/**
 * @brief Add Unix security token to specified JSON object
 * Keys added may be contolled via desired_info parameter
 *
 * @param[in] token         security_unix_token to be converted to JSON
 * @param[in] jsobj         JSON object to which to insert information
 * @param[in] desired_info  Mask of info requested to be added
 *                          See SMB_JSON_UTOK_ALL above
 *
 * @return                  boolean - success
 */
bool _json_add_unix_sec_token(const struct security_unix_token *token,
			      struct json_object *jsobj,
			      uint32_t desired_info,
			      const char *location);
#define json_add_unix_sec_token(token, obj, desired_info) \
	_json_add_unix_sec_token(token, obj, desired_info, __location__)

/**
 * @brief Add security token to specified JSON object
 * Keys added may be contolled via desired_info parameter
 *
 * @param[in] token         security_token to be converted to JSON
 * @param[in] jsobj         JSON object to which to insert information
 * @param[in] desired_info  Mask of info requested to be added
 *                          See SMB_JSON_STOK_ALL above
 *
 * @return                  boolean - success
 */
bool _json_add_sec_token(const struct security_token *token,
			 struct json_object *jsobj,
			 uint32_t desired_info,
			 const char *location);
#define json_add_sec_token(token, obj, desired_info) \
	_json_add_sec_token(token, obj, desired_info, __location__)

/**
 * @brief Add auth_session_info to specified JSON object
 * Keys added may be contolled via desired_info parameter
 *
 * If desired_info includes mask for structs within auth_session_info
 * (see SMB_JSON_SESS_ALL above) then that information will be added
 * as JSON objects within the specified option as follows:
 * "info": <sess->info>
 * "unix_token": <sess->unix_token>
 * "security_token": <sess->security_token>
 *
 * @param[in] sess          auth_session_info to be converted to JSON
 * @param[in] jsobj         JSON object to which to insert information
 * @param[in] desired_info  Mask of info requested to be added
 *                          See SMB_JSON_STOK_ALL above
 *
 * @return                  boolean - success
 */
bool _json_add_auth_session_info(const struct auth_session_info *sess,
				 struct json_object *jsobj,
				 uint32_t desired_info,
				 const char *location);
#define json_add_auth_session_info(sess, obj, desired_info) \
	_json_add_auth_session_info(sess, obj, desired_info, __location__)
#endif /* __JS_SESSION_H */
