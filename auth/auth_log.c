/*

   Authentication and authorization logging

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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
 * Debug log levels for authentication logging (these both map to
 * LOG_NOTICE in syslog)
 */
#define AUTH_FAILURE_LEVEL 2
#define AUTH_SUCCESS_LEVEL 3
#define AUTHZ_SUCCESS_LEVEL 4
#define KDC_AUTHZ_FAILURE_LEVEL 2
#define KDC_AUTHZ_SUCCESS_LEVEL 3

/* 5 is used for both authentication and authorization */
#define AUTH_ANONYMOUS_LEVEL 5
#define AUTHZ_ANONYMOUS_LEVEL 5

#define AUTHZ_JSON_TYPE "Authorization"
#define AUTH_JSON_TYPE  "Authentication"
#define KDC_AUTHZ_JSON_TYPE "KDC Authorization"

/*
 * JSON message version numbers
 *
 * If adding a field increment the minor version
 * If removing or changing the format/meaning of a field
 * increment the major version.
 */
#define AUTH_MAJOR 1
#define AUTH_MINOR 3
#define AUTHZ_MAJOR 1
#define AUTHZ_MINOR 2
#define KDC_AUTHZ_MAJOR 1
#define KDC_AUTHZ_MINOR 0

#include "includes.h"
#include "../lib/tsocket/tsocket.h"
#include "common_auth.h"
#include "lib/util/util_str_escape.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_token.h"
#include "librpc/gen_ndr/server_id.h"
#include "source4/lib/messaging/messaging.h"
#include "source4/lib/messaging/irpc.h"
#include "lib/util/server_id_db.h"
#include "lib/param/param.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/windows_event_ids.h"
#include "lib/audit_logging/audit_logging.h"
#include "system/syslog.h"

/*
 * Determine the type of the password supplied for the
 * authorisation attempt.
 *
 */
static const char* get_password_type(const struct auth_usersupplied_info *ui);

#ifdef HAVE_JANSSON

#include <jansson.h>
#include "system/time.h"

/*
 * Write the json object to the debug logs.
 *
 */
static void log_json(struct imessaging_context *msg_ctx,
		     struct loadparm_context *lp_ctx,
		     struct json_object *object,
		     int debug_class,
		     int debug_level)
{
	audit_log_json(object, debug_class, debug_level);
	if (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx)) {
		audit_message_send(msg_ctx,
				   AUTH_EVENT_NAME,
				   MSG_AUTH_LOG,
				   object);
	}
}

/*
 * Determine the Windows logon type for the current authorisation attempt.
 *
 * Currently Samba only supports
 *
 * 2 Interactive      A user logged on to this computer.
 * 3 Network          A user or computer logged on to this computer from
 *                    the network.
 * 8 NetworkCleartext A user logged on to this computer from the network.
 *                    The user's password was passed to the authentication
 *                    package in its unhashed form.
 *
 */
static enum event_logon_type get_logon_type(
	const struct auth_usersupplied_info *ui)
{
	if ((ui->logon_parameters & MSV1_0_CLEARTEXT_PASSWORD_SUPPLIED)
	   || (ui->password_state == AUTH_PASSWORD_PLAIN)) {
		return EVT_LOGON_NETWORK_CLEAR_TEXT;
	} else if (ui->flags & USER_INFO_INTERACTIVE_LOGON) {
		return EVT_LOGON_INTERACTIVE;
	}
	return EVT_LOGON_NETWORK;
}

static bool authentication_event_json(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct timeval *start_time,
	const struct auth_usersupplied_info *ui,
	NTSTATUS status,
	const char *domain_name,
	const char *account_name,
	struct dom_sid *sid,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info,
	enum event_id_type event_id,
	int debug_level,
	struct json_object *authentication)
{
	struct json_object client_policy = json_null_object();
	struct json_object server_policy = json_null_object();
	char logon_id[19];
	int rc = 0;
	const char *clientDomain = ui->orig_client.domain_name ?
				   ui->orig_client.domain_name :
				   ui->client.domain_name;
	const char *clientAccount = ui->orig_client.account_name ?
				    ui->orig_client.account_name :
				    ui->client.account_name;

	if (json_is_invalid(authentication)) {
		goto failure;
	}

	rc = json_add_version(authentication, AUTH_MAJOR, AUTH_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(authentication,
			  "eventId",
			  event_id);
	if (rc != 0) {
		goto failure;
	}
	snprintf(logon_id,
		 sizeof( logon_id),
		 "%"PRIx64"",
		 ui->logon_id);
	rc = json_add_string(authentication, "logonId", logon_id);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(authentication, "logonType", get_logon_type(ui));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(authentication, "status", nt_errstr(status));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_address(authentication, "localAddress", ui->local_host);
	if (rc != 0) {
		goto failure;
	}
	rc =
	    json_add_address(authentication, "remoteAddress", ui->remote_host);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "serviceDescription", ui->service_description);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "authDescription", ui->auth_description);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "clientDomain", clientDomain);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "clientAccount", clientAccount);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "workstation", ui->workstation_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(authentication, "becameAccount", account_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(authentication, "becameDomain", domain_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_sid(authentication, "becameSid", sid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "mappedAccount", ui->mapped.account_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "mappedDomain", ui->mapped.domain_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(authentication,
			     "netlogonComputer",
			     ui->netlogon_trust_account.computer_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(authentication,
			     "netlogonTrustAccount",
			     ui->netlogon_trust_account.account_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_flags32(
	    authentication, "netlogonNegotiateFlags",
	    ui->netlogon_trust_account.negotiate_flags);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(authentication,
			  "netlogonSecureChannelType",
			  ui->netlogon_trust_account.secure_channel_type);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_sid(authentication,
			  "netlogonTrustAccountSid",
			  ui->netlogon_trust_account.sid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    authentication, "passwordType", get_password_type(ui));
	if (rc != 0) {
		goto failure;
	}

	if (client_audit_info != NULL) {
		client_policy = json_from_audit_info(client_audit_info);
		if (json_is_invalid(&client_policy)) {
			goto failure;
		}
	}

	rc = json_add_object(authentication, "clientPolicyAccessCheck", &client_policy);
	if (rc != 0) {
		goto failure;
	}

	if (server_audit_info != NULL) {
		server_policy = json_from_audit_info(server_audit_info);
		if (json_is_invalid(&server_policy)) {
			goto failure;
		}
	}

	rc = json_add_object(authentication, "serverPolicyAccessCheck", &server_policy);
	if (rc != 0) {
		goto failure;
	}

	return true;
failure:
	json_free(&server_policy);
	json_free(&client_policy);
	return false;
}

static bool truenas_audit_add_vers(struct json_object *wrapper,
				   const char *key)
{
	struct json_object vers = json_empty_object;
	int error;

	vers = json_new_object();
	if (json_is_invalid(&vers)) {
		goto failure;
	}

	error = json_add_int(&vers, "major", 0);
	if (error) {
		goto failure;
	}

	error = json_add_int(&vers, "minor", 1);
	if (error) {
		goto failure;
	}

	error = json_add_object(wrapper, key, &vers);
	if (error != 0) {
		goto failure;
	}

	return true;
failure:
	json_free(&vers);
	return false;
}

static bool truenas_audit_add_svc_data(struct json_object *wrapper)
{
	struct json_object svc_data = json_empty_object;
	int error;
	bool rv = false;
	char *msg = NULL;

	svc_data = json_new_object();
	if (json_is_invalid(&svc_data)) {
		goto failure;
	}

	if (!truenas_audit_add_vers(&svc_data, "vers")) {
		goto failure;
	}

	error = json_add_string(&svc_data, "service", NULL);
	if (error) {
		goto failure;
	}

	error = json_add_string(&svc_data, "session_id", NULL);
	if (error) {
		goto failure;
	}
	error = json_add_string(&svc_data, "tcon_id", NULL);
	if (error) {
		goto failure;
	}

	msg = json_dumps(svc_data.root, 0);
	if (msg == NULL) {
		goto failure;
	}
	error = json_add_string(wrapper, "svc_data", msg);
	free(msg);
	if (error != 0) {
		goto failure;
	}

	rv = true;
failure:
	json_free(&svc_data);
	return rv;
}

bool truenas_audit_add_time(struct json_object *object,
			    const char *key)
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

	r = gettimeofday(&tv, NULL);
	if (r) {
		return false;
        }

	tm_info = gmtime_r(&tv.tv_sec, &tmbuf);
	if (tm_info == NULL) {
		return false;
	}

	strftime(buffer, sizeof(buffer)-1, "%Y-%m-%d %T", tm_info);
	snprintf(ts, sizeof(ts), "%s.%06ldZ", buffer, tv.tv_usec);

	ret = json_add_string(object, key, ts);
	if (ret != 0) {
		return false;
	}

	return true;
}

static bool truenas_audit_add_inet_addr(struct json_object *object,
					const char *key,
					const struct tsocket_address *addr)
{
	char *addr_s = NULL;
	int error;

	if (json_is_invalid(object)) {
		return false;
        }

	if (addr == NULL) {
		error = json_add_string(object, key, NULL);
		if (error) {
			return false;
		}
		return true;
	}

	addr_s = tsocket_address_inet_addr_string(addr, talloc_tos());
	if (addr_s == NULL) {
		return false;
	}

	error = json_add_string(object, key, addr_s);
	TALLOC_FREE(addr_s);
	return error ? false : true;
}

static bool truenas_audit_add_result(struct json_object *authentication,
				     NTSTATUS status)
{
	struct json_object result = json_empty_object;
	int error;

	result = json_new_object();
	if (json_is_invalid(&result)) {
		goto failure;
	}

	error = json_add_string(&result, "type", "NTSTATUS");
	if (error) {
		goto failure;
	}

	error = json_add_int(&result, "value_raw", NT_STATUS_V(status));
	if (error) {
		goto failure;
	}

	error = json_add_string(&result, "value_parsed",
				NT_STATUS_IS_OK(status) ?
				"SUCCESS" :
				nt_errstr(status));
	if (error) {
		goto failure;
	}

	error = json_add_object(authentication, "result", &result);
	if (error != 0) {
		goto failure;
	}

	return true;
failure:
	json_free(&result);
	return false;
}

static void truenas_audit_authentication_event(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct timeval *start_time,
	const struct auth_usersupplied_info *ui,
	NTSTATUS status,
	const char *domain_name,
	const char *account_name,
	struct dom_sid *sid,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info,
	enum event_id_type event_id,
	int debug_level)
{
	struct json_object authentication = json_empty_object;
	struct json_object wrapper = json_empty_object;
	int rc = 0;
	char *msg = NULL;
	bool ok;
	static bool log_opened = false;
	struct GUID msgid = GUID_random();
	const char *clientAccount = ui->orig_client.account_name ?
				    ui->orig_client.account_name :
				    ui->client.account_name;

	if (!log_opened) {
		openlog("TNAUDIT_SMB", 0, LOG_AUTH);
		log_opened = true;
	}

	authentication = json_new_object();
	if (json_is_invalid(&authentication)) {
		goto failure;
	}

	ok = authentication_event_json(
		msg_ctx, lp_ctx, start_time, ui, status, domain_name,
		account_name, sid, client_audit_info, server_audit_info,
		event_id, debug_level, &authentication
	);
	if (!ok) {
		goto failure;
	}

	rc = json_object_del(authentication.root, "version");
	if (rc != 0) {
		goto failure;
	}

	rc = json_object_del(authentication.root, "status");
	if (rc != 0) {
		goto failure;
	}

	rc = json_object_del(authentication.root, "eventId");
	if (rc != 0) {
		goto failure;
	}

	ok = truenas_audit_add_vers(&authentication, "vers");
	if (!ok) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}

	rc = json_add_guid(&wrapper, "aid", &msgid);
	if (rc != 0) {
		goto failure;
	}

	ok = truenas_audit_add_vers(&wrapper, "vers");
	if (!ok) {
		goto failure;
	}

	ok = truenas_audit_add_inet_addr(&wrapper, "addr", ui->remote_host);
	if (!ok) {
		goto failure;
	}

	rc = json_add_string(&wrapper, "user", account_name ? account_name : clientAccount);
	if (rc != 0) {
		goto failure;
	}

	rc = json_add_string(&wrapper, "sess", NULL);
	if (rc != 0) {
		goto failure;
	}

	ok = truenas_audit_add_time(&wrapper, "time");
	if (!ok) {
		goto failure;
	}

	rc = json_add_string(&wrapper, "svc", "SMB");
	if (rc != 0) {
		goto failure;
	}

	ok = truenas_audit_add_svc_data(&wrapper);
	if (!ok) {
		goto failure;
	}

	rc = json_add_string(&wrapper, "event", "AUTHENTICATION");
	if (rc != 0) {
		goto failure;
	}

	if (!truenas_audit_add_result(&authentication, status)) {
		goto failure;
	}

	msg = json_dumps(authentication.root, 0);
	if (msg == NULL) {
		goto failure;
	}

	rc = json_add_string(&wrapper, "event_data", msg);
	free(msg);
	if (rc != 0) {
		goto failure;
	}

	rc = json_add_bool(&wrapper, "success", NT_STATUS_IS_OK(status));
	if (rc != 0) {
		goto failure;
	}

	msg = json_dumps(wrapper.root, 0);
	if (msg == NULL) {
		goto failure;
	}

	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_NOTICE),
	       "@cee:{\"TNAUDIT\": %s}", msg);

	free(msg);
	json_free(&authentication);
	json_free(&wrapper);
	return;

failure:
	/*
	 * On a failure authentication will not have been added to wrapper so it
	 * needs to be freed to avoid a leak.
	 *
	 */
	json_free(&authentication);
	json_free(&wrapper);
	DBG_ERR("Failed to generate audit event for authenticaiton\n");
}

/*
 * Write a machine parsable json formatted authentication log entry.
 *
 * IF removing or changing the format/meaning of a field please update the
 *    major version number AUTH_MAJOR
 *
 * IF adding a new field please update the minor version number AUTH_MINOR
 *
 *  To process the resulting log lines from the command line use jq to
 *  parse the json.
 *
 *  grep "^  {" log file |
 *  jq -rc '"\(.timestamp)\t\(.Authentication.status)\t
 *           \(.Authentication.clientDomain)\t
 *           \(.Authentication.clientAccount)
 *           \t\(.Authentication.workstation)
 *           \t\(.Authentication.remoteAddress)
 *           \t\(.Authentication.localAddress)"'
 */
static void log_authentication_event_json(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct timeval *start_time,
	const struct auth_usersupplied_info *ui,
	NTSTATUS status,
	const char *domain_name,
	const char *account_name,
	struct dom_sid *sid,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info,
	enum event_id_type event_id,
	int debug_level)
{
	struct json_object authentication = json_empty_object;
	struct json_object wrapper = json_empty_object;
	int rc = 0;
	bool ok;

	authentication = json_new_object();
	if (json_is_invalid(&authentication)) {
		goto failure;
	}

	ok = authentication_event_json(
		msg_ctx, lp_ctx, start_time, ui, status, domain_name,
		account_name, sid, client_audit_info, server_audit_info,
		event_id, debug_level, &authentication
	);
	if (!ok) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", AUTH_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, AUTH_JSON_TYPE, &authentication);
	if (rc != 0) {
		goto failure;
	}

	/*
	 * While not a general-purpose profiling solution this will
	 * assist some to determine how long NTLM and KDC
	 * authentication takes once this process can handle it.  This
	 * covers transactions elsewhere but not (eg) the delay while
	 * this is waiting unread on the input socket.
	 */
	if (start_time != NULL) {
		struct timeval current_time = timeval_current();
		uint64_t duration =  usec_time_diff(&current_time,
						    start_time);
		rc = json_add_int(&authentication, "duration", duration);
		if (rc != 0) {
			goto failure;
		}
	}

	log_json(msg_ctx,
		 lp_ctx,
		 &wrapper,
		 DBGC_AUTH_AUDIT_JSON,
		 debug_level);
	json_free(&wrapper);
	return;
failure:
	/*
	 * On a failure authentication will not have been added to wrapper so it
	 * needs to be freed to avoid a leak.
	 *
	 */
	json_free(&authentication);
	json_free(&wrapper);
	DBG_ERR("Failed to write authentication event JSON log message\n");
}

/*
 * Log details of a successful authorization to a service,
 * in a machine parsable json format
 *
 * IF removing or changing the format/meaning of a field please update the
 *    major version number AUTHZ_MAJOR
 *
 * IF adding a new field please update the minor version number AUTHZ_MINOR
 *
 *  To process the resulting log lines from the command line use jq to
 *  parse the json.
 *
 *  grep "^  {" log_file |\
 *  jq -rc '"\(.timestamp)\t
 *           \(.Authorization.domain)\t
 *           \(.Authorization.account)\t
 *           \(.Authorization.remoteAddress)"'
 *
 */
static void log_successful_authz_event_json(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	const char *service_description,
	const char *auth_type,
	const char *transport_protection,
	struct auth_session_info *session_info,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info,
	int debug_level)
{
	struct json_object wrapper = json_empty_object;
	struct json_object authorization = json_empty_object;
	struct json_object client_policy = json_null_object();
	struct json_object server_policy = json_null_object();
	int rc = 0;

	authorization = json_new_object();
	if (json_is_invalid(&authorization)) {
		goto failure;
	}
	rc = json_add_version(&authorization, AUTHZ_MAJOR, AUTHZ_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_address(&authorization, "localAddress", local);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_address(&authorization, "remoteAddress", remote);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    &authorization, "serviceDescription", service_description);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&authorization, "authType", auth_type);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    &authorization, "domain", session_info->info->domain_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    &authorization, "account", session_info->info->account_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_sid(
	    &authorization, "sid", &session_info->security_token->sids[PRIMARY_USER_SID_INDEX]);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(
	    &authorization, "sessionId", &session_info->unique_session_token);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    &authorization, "logonServer", session_info->info->logon_server);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    &authorization, "transportProtection", transport_protection);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_flags32(&authorization, "accountFlags", session_info->info->acct_flags);
	if (rc != 0) {
		goto failure;
	}

	if (client_audit_info != NULL) {
		client_policy = json_from_audit_info(client_audit_info);
		if (json_is_invalid(&client_policy)) {
			goto failure;
		}
	}

	rc = json_add_object(&authorization, "clientPolicyAccessCheck", &client_policy);
	if (rc != 0) {
		goto failure;
	}

	if (server_audit_info != NULL) {
		server_policy = json_from_audit_info(server_audit_info);
		if (json_is_invalid(&server_policy)) {
			goto failure;
		}
	}

	rc = json_add_object(&authorization, "serverPolicyAccessCheck", &server_policy);
	if (rc != 0) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", AUTHZ_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, AUTHZ_JSON_TYPE, &authorization);
	if (rc != 0) {
		goto failure;
	}

	log_json(msg_ctx,
		 lp_ctx,
		 &wrapper,
		 DBGC_AUTH_AUDIT_JSON,
		 debug_level);
	json_free(&wrapper);
	return;
failure:
	json_free(&server_policy);
	json_free(&client_policy);
	/*
	 * On a failure authorization will not have been added to wrapper so it
	 * needs to be freed to avoid a leak.
	 *
	 */
	json_free(&authorization);
	json_free(&wrapper);
	DBG_ERR("Unable to log Authentication event JSON audit message\n");
}

/*
 * Log details of an authorization to a service, in a machine parsable json
 * format
 *
 * IF removing or changing the format/meaning of a field please update the
 *    major version number KDC_AUTHZ_MAJOR
 *
 * IF adding a new field please update the minor version number KDC_AUTHZ_MINOR
 *
 *  To process the resulting log lines from the command line use jq to
 *  parse the json.
 *
 *  grep "^  {" log_file |\
 *  jq -rc '"\(.timestamp)\t
 *           \(."KDC Authorization".domain)\t
 *           \(."KDC Authorization".account)\t
 *           \(."KDC Authorization".remoteAddress)"'
 *
 */
static void log_authz_event_json(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	const struct authn_audit_info *server_audit_info,
	const char *service_description,
	const char *auth_type,
	const char *domain_name,
	const char *account_name,
	const struct dom_sid *sid,
	const char *logon_server,
	const struct timeval authtime,
	NTSTATUS status,
	int debug_level)
{
	struct json_object wrapper = json_empty_object;
	struct json_object authorization = json_empty_object;
	struct json_object server_policy = json_null_object();
	int rc = 0;

	authorization = json_new_object();
	if (json_is_invalid(&authorization)) {
		goto failure;
	}
	rc = json_add_version(&authorization, KDC_AUTHZ_MAJOR, KDC_AUTHZ_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&authorization, "status", nt_errstr(status));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_address(&authorization, "localAddress", local);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_address(&authorization, "remoteAddress", remote);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(
	    &authorization, "serviceDescription", service_description);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&authorization, "authType", auth_type);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&authorization, "domain", domain_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&authorization, "account", account_name);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_sid(&authorization, "sid", sid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&authorization, "logonServer", logon_server);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_time(&authorization, "authTime", authtime);
	if (rc != 0) {
		goto failure;
	}

	if (server_audit_info != NULL) {
		server_policy = json_from_audit_info(server_audit_info);
		if (json_is_invalid(&server_policy)) {
			goto failure;
		}
	}

	rc = json_add_object(&authorization, "serverPolicyAccessCheck", &server_policy);
	if (rc != 0) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", KDC_AUTHZ_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, KDC_AUTHZ_JSON_TYPE, &authorization);
	if (rc != 0) {
		goto failure;
	}

	log_json(msg_ctx,
		 lp_ctx,
		 &wrapper,
		 DBGC_AUTH_AUDIT_JSON,
		 debug_level);
	json_free(&wrapper);
	return;
failure:
	json_free(&server_policy);
	/*
	 * On a failure authorization will not have been added to wrapper so it
	 * needs to be freed to avoid a leak.
	 */
	json_free(&authorization);
	json_free(&wrapper);
	DBG_ERR("Unable to log KDC Authorization event JSON audit message\n");
}

#else

static void log_no_json(struct imessaging_context *msg_ctx,
                        struct loadparm_context *lp_ctx)
{
	if (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx)) {
		static bool auth_event_logged = false;
		if (auth_event_logged == false) {
			auth_event_logged = true;
			DBG_ERR("auth event notification = true but Samba was "
				"not compiled with jansson\n");
		}
	} else {
		static bool json_logged = false;
		if (json_logged == false) {
			json_logged = true;
			DBG_NOTICE("JSON auth logs not available unless "
				   "compiled with jansson\n");
		}
	}
}

static void log_authentication_event_json(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct timeval *start_time,
	const struct auth_usersupplied_info *ui,
	NTSTATUS status,
	const char *domain_name,
	const char *account_name,
	struct dom_sid *sid,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info,
	enum event_id_type event_id,
	int debug_level)
{
	log_no_json(msg_ctx, lp_ctx);
}

static void log_successful_authz_event_json(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	const char *service_description,
	const char *auth_type,
	const char *transport_protection,
	struct auth_session_info *session_info,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info,
	int debug_level)
{
	log_no_json(msg_ctx, lp_ctx);
}

static void log_authz_event_json(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	const struct authn_audit_info *server_audit_info,
	const char *service_description,
	const char *auth_type,
	const char *domain_name,
	const char *account_name,
	const struct dom_sid *sid,
	const char *logon_server,
	const struct timeval authtime,
	NTSTATUS status,
	int debug_level)
{
	log_no_json(msg_ctx, lp_ctx);
}

#endif

/*
 * Determine the type of the password supplied for the
 * authorisation attempt.
 *
 */
static const char* get_password_type(const struct auth_usersupplied_info *ui)
{

	const char *password_type = NULL;

	if (ui->password_type != NULL) {
		password_type = ui->password_type;
	} else if (ui->auth_description != NULL &&
		   strncmp("ServerAuthenticate", ui->auth_description, 18) == 0)
	{
		if (ui->netlogon_trust_account.negotiate_flags
		    & NETLOGON_NEG_SUPPORTS_AES) {
			password_type = "HMAC-SHA256";
		} else if (ui->netlogon_trust_account.negotiate_flags
		           & NETLOGON_NEG_STRONG_KEYS) {
			password_type = "HMAC-MD5";
		} else {
			password_type = "DES";
		}
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE &&
		   (ui->logon_parameters & MSV1_0_ALLOW_MSVCHAPV2) &&
		   ui->password.response.nt.length == 24) {
		password_type = "MSCHAPv2";
	} else if ((ui->logon_parameters & MSV1_0_CLEARTEXT_PASSWORD_SUPPLIED)
		   || (ui->password_state == AUTH_PASSWORD_PLAIN)) {
		password_type = "Plaintext";
	} else if (ui->password_state == AUTH_PASSWORD_HASH) {
		password_type = "Supplied-NT-Hash";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.nt.length > 24) {
		password_type = "NTLMv2";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.nt.length == 24) {
		password_type = "NTLMv1";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.lanman.length == 24) {
		password_type = "LANMan";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.nt.length == 0
		   && ui->password.response.lanman.length == 0) {
		password_type = "No-Password";
	}
	return password_type;
}

/*
 * Write a human readable authentication log entry.
 *
 */
static void log_authentication_event_human_readable(
	const struct auth_usersupplied_info *ui,
	NTSTATUS status,
	const char *domain_name,
	const char *account_name,
	struct dom_sid *sid,
	int debug_level)
{
	TALLOC_CTX *frame = NULL;

	const char *ts = NULL;		   /* formatted current time      */
	char *remote = NULL;		   /* formatted remote host       */
	char *local = NULL;		   /* formatted local host        */
	char *nl = NULL;		   /* NETLOGON details if present */
	char *trust_computer_name = NULL;
	char *trust_account_name = NULL;
	char *logon_line = NULL;
	const char *password_type = NULL;
	const char *clientDomain = ui->orig_client.domain_name ?
				   ui->orig_client.domain_name :
				   ui->client.domain_name;
	const char *clientAccount = ui->orig_client.account_name ?
				    ui->orig_client.account_name :
				    ui->client.account_name;

	frame = talloc_stackframe();

	password_type = get_password_type(ui);
	/* Get the current time */
        ts = audit_get_timestamp(frame);

	/* Only log the NETLOGON details if they are present */
	if (ui->netlogon_trust_account.computer_name ||
	    ui->netlogon_trust_account.account_name) {
		trust_computer_name = log_escape(frame,
			ui->netlogon_trust_account.computer_name);
		trust_account_name  = log_escape(frame,
			ui->netlogon_trust_account.account_name);
		nl = talloc_asprintf(frame,
			" NETLOGON computer [%s] trust account [%s]",
			trust_computer_name, trust_account_name);
	}

	remote = tsocket_address_string(ui->remote_host, frame);
	local = tsocket_address_string(ui->local_host, frame);

	if (NT_STATUS_IS_OK(status)) {
		struct dom_sid_buf sid_buf;

		logon_line = talloc_asprintf(frame,
					     " became [%s]\\[%s] [%s].",
					     log_escape(frame, domain_name),
					     log_escape(frame, account_name),
					     dom_sid_str_buf(sid, &sid_buf));
	} else {
		logon_line = talloc_asprintf(
				frame,
				" mapped to [%s]\\[%s].",
				log_escape(frame, ui->mapped.domain_name),
				log_escape(frame, ui->mapped.account_name));
	}

	DEBUGC(DBGC_AUTH_AUDIT, debug_level,
	       ("Auth: [%s,%s] user [%s]\\[%s]"
		" at [%s] with [%s] status [%s]"
		" workstation [%s] remote host [%s]"
		"%s local host [%s]"
		" %s\n",
		ui->service_description,
		ui->auth_description,
		log_escape(frame, clientDomain),
		log_escape(frame, clientAccount),
		ts,
		password_type,
		nt_errstr(status),
		log_escape(frame, ui->workstation_name),
		remote,
		logon_line,
		local,
		nl ? nl : ""
	));

	talloc_free(frame);
}

/*
 * Log details of an authentication attempt.
 * Successful and unsuccessful attempts are logged.
 *
 * NOTE: msg_ctx and lp_ctx is optional, but when supplied allows streaming the
 * authentication events over the message bus.
 */
void log_authentication_event(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct timeval *start_time,
	const struct auth_usersupplied_info *ui,
	NTSTATUS status,
	const char *domain_name,
	const char *account_name,
	struct dom_sid *sid,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info)
{
	/* set the log level */
	int debug_level = AUTH_FAILURE_LEVEL;
	enum event_id_type event_id = EVT_ID_UNSUCCESSFUL_LOGON;

	if (NT_STATUS_IS_OK(status)) {
		debug_level = AUTH_SUCCESS_LEVEL;
		event_id = EVT_ID_SUCCESSFUL_LOGON;
		if (dom_sid_equal(sid, &global_sid_Anonymous)) {
			debug_level = AUTH_ANONYMOUS_LEVEL;
		}
	}

	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT, debug_level)) {
		log_authentication_event_human_readable(ui,
							status,
							domain_name,
							account_name,
							sid,
							debug_level);
	}
	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT_JSON, debug_level) ||
	    (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx))) {
		log_authentication_event_json(msg_ctx,
					      lp_ctx,
					      start_time,
					      ui,
					      status,
					      domain_name,
					      account_name,
					      sid,
					      client_audit_info,
					      server_audit_info,
					      event_id,
					      debug_level);
	}

	truenas_audit_authentication_event(msg_ctx,
					      lp_ctx,
					      start_time,
					      ui,
					      status,
					      domain_name,
					      account_name,
					      sid,
					      client_audit_info,
					      server_audit_info,
					      event_id,
					      debug_level);
}

/*
 * Log details of a successful authorization to a service,
 * in a human readable format.
 *
 */
static void log_successful_authz_event_human_readable(
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	const char *service_description,
	const char *auth_type,
	struct auth_session_info *session_info,
	int debug_level)
{
	TALLOC_CTX *frame = NULL;

	const char *ts = NULL;       /* formatted current time      */
	char *remote_str = NULL;     /* formatted remote host       */
	char *local_str = NULL;      /* formatted local host        */
	struct dom_sid_buf sid_buf;

	frame = talloc_stackframe();

	/* Get the current time */
        ts = audit_get_timestamp(frame);

	remote_str = tsocket_address_string(remote, frame);
	local_str = tsocket_address_string(local, frame);

	DEBUGC(DBGC_AUTH_AUDIT, debug_level,
	       ("Successful AuthZ: [%s,%s] user [%s]\\[%s] [%s]"
		" at [%s]"
		" Remote host [%s]"
		" local host [%s]\n",
		service_description,
		auth_type,
		log_escape(frame, session_info->info->domain_name),
		log_escape(frame, session_info->info->account_name),
		dom_sid_str_buf(&session_info->security_token->sids[PRIMARY_USER_SID_INDEX],
				&sid_buf),
		ts,
		remote_str,
		local_str));

	talloc_free(frame);
}

/*
 * Log details of a successful authorization to a service.
 *
 * Only successful authorizations are logged.  For clarity:
 * - NTLM bad passwords will be recorded by log_authentication_event
 * - Kerberos decrypt failures need to be logged in gensec_gssapi et al
 *
 * The service may later refuse authorization due to an ACL.
 *
 * NOTE: msg_ctx and lp_ctx is optional, but when supplied allows streaming the
 * authentication events over the message bus.
 */
void log_successful_authz_event(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	const char *service_description,
	const char *auth_type,
	const char *transport_protection,
	struct auth_session_info *session_info,
	const struct authn_audit_info *client_audit_info,
	const struct authn_audit_info *server_audit_info)
{
	int debug_level = AUTHZ_SUCCESS_LEVEL;

	/* set the log level */
	if (security_token_is_anonymous(session_info->security_token)) {
		debug_level = AUTH_ANONYMOUS_LEVEL;
	}

	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT, debug_level)) {
		log_successful_authz_event_human_readable(remote,
							  local,
							  service_description,
							  auth_type,
							  session_info,
							  debug_level);
	}
	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT_JSON, debug_level) ||
	    (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx))) {
		log_successful_authz_event_json(msg_ctx, lp_ctx,
						remote,
						local,
						service_description,
						auth_type,
						transport_protection,
						session_info,
						client_audit_info,
						server_audit_info,
						debug_level);
	}
}

/*
 * Log details of an authorization to a service.
 *
 * NOTE: msg_ctx and lp_ctx are optional, but when supplied, allow streaming the
 * authorization events over the message bus.
 */
void log_authz_event(
	struct imessaging_context *msg_ctx,
	struct loadparm_context *lp_ctx,
	const struct tsocket_address *remote,
	const struct tsocket_address *local,
	const struct authn_audit_info *server_audit_info,
	const char *service_description,
	const char *auth_type,
	const char *domain_name,
	const char *account_name,
	const struct dom_sid *sid,
	const char *logon_server,
	const struct timeval authtime,
	NTSTATUS status)
{
	/* set the log level */
	int debug_level = KDC_AUTHZ_FAILURE_LEVEL;

	if (NT_STATUS_IS_OK(status)) {
		debug_level = KDC_AUTHZ_SUCCESS_LEVEL;
	}

	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT_JSON, debug_level) ||
	    (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx))) {
		log_authz_event_json(msg_ctx, lp_ctx,
				     remote,
				     local,
				     server_audit_info,
				     service_description,
				     auth_type,
				     domain_name,
				     account_name,
				     sid,
				     logon_server,
				     authtime,
				     status,
				     debug_level);
	}
}
