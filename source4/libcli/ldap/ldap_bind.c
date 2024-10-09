/* 
   Unix SMB/CIFS implementation.

   LDAP bind calls
   
   Copyright (C) Andrew Tridgell  2005
   Copyright (C) Volker Lendecke  2004
    
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

#include "includes.h"
#include "libcli/ldap/libcli_ldap.h"
#include "libcli/ldap/ldap_proto.h"
#include "libcli/ldap/ldap_client.h"
#include "lib/tls/tls.h"
#include "auth/gensec/gensec.h"
#include "source4/auth/gensec/gensec_tstream.h"
#include "auth/credentials/credentials.h"
#include "lib/stream/packet.h"
#include "param/param.h"
#include "param/loadparm.h"
#include "librpc/gen_ndr/ads.h"

struct ldap_simple_creds {
	const char *dn;
	const char *pw;
};

_PUBLIC_ NTSTATUS ldap_rebind(struct ldap_connection *conn)
{
	NTSTATUS status;
	struct ldap_simple_creds *creds;

	switch (conn->bind.type) {
	case LDAP_BIND_SASL:
		status = ldap_bind_sasl(conn, (struct cli_credentials *)conn->bind.creds,
					conn->lp_ctx);
		break;
		
	case LDAP_BIND_SIMPLE:
		creds = (struct ldap_simple_creds *)conn->bind.creds;

		if (creds == NULL) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		status = ldap_bind_simple(conn, creds->dn, creds->pw);
		break;

	default:
		return NT_STATUS_UNSUCCESSFUL;
	}

	return status;
}


static struct ldap_message *new_ldap_simple_bind_msg(struct ldap_connection *conn, 
						     const char *dn, const char *pw)
{
	struct ldap_message *res;

	res = new_ldap_message(conn);
	if (!res) {
		return NULL;
	}

	res->type = LDAP_TAG_BindRequest;
	res->r.BindRequest.version = 3;
	res->r.BindRequest.dn = talloc_strdup(res, dn);
	res->r.BindRequest.mechanism = LDAP_AUTH_MECH_SIMPLE;
	res->r.BindRequest.creds.password = talloc_strdup(res, pw);
	res->controls = NULL;

	return res;
}


/*
  perform a simple username/password bind
*/
_PUBLIC_ NTSTATUS ldap_bind_simple(struct ldap_connection *conn, 
			  const char *userdn, const char *password)
{
	struct ldap_request *req;
	struct ldap_message *msg;
	const char *dn, *pw;
	NTSTATUS status;

	if (conn == NULL) {
		return NT_STATUS_INVALID_CONNECTION;
	}

	if (userdn) {
		dn = userdn;
	} else {
		if (conn->auth_dn) {
			dn = conn->auth_dn;
		} else {
			dn = "";
		}
	}

	if (password) {
		pw = password;
	} else {
		if (conn->simple_pw) {
			pw = conn->simple_pw;
		} else {
			pw = "";
		}
	}

	msg = new_ldap_simple_bind_msg(conn, dn, pw);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	/* send the request */
	req = ldap_request_send(conn, msg);
	talloc_free(msg);
	NT_STATUS_HAVE_NO_MEMORY(req);

	/* wait for replies */
	status = ldap_request_wait(req);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return status;
	}

	/* check its a valid reply */
	msg = req->replies[0];
	if (msg->type != LDAP_TAG_BindResponse) {
		talloc_free(req);
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	status = ldap_check_response(conn, &msg->r.BindResponse.response);

	talloc_free(req);

	if (NT_STATUS_IS_OK(status)) {
		struct ldap_simple_creds *creds = talloc(conn, struct ldap_simple_creds);
		if (creds == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		creds->dn = talloc_strdup(creds, dn);
		creds->pw = talloc_strdup(creds, pw);
		if (creds->dn == NULL || creds->pw == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		conn->bind.type = LDAP_BIND_SIMPLE;
		conn->bind.creds = creds;
	}

	return status;
}


static struct ldap_message *new_ldap_sasl_bind_msg(struct ldap_connection *conn, 
						   const char *sasl_mechanism, 
						   DATA_BLOB *secblob)
{
	struct ldap_message *res;

	res = new_ldap_message(conn);
	if (!res) {
		return NULL;
	}

	res->type = LDAP_TAG_BindRequest;
	res->r.BindRequest.version = 3;
	res->r.BindRequest.dn = "";
	res->r.BindRequest.mechanism = LDAP_AUTH_MECH_SASL;
	res->r.BindRequest.creds.SASL.mechanism = talloc_strdup(res, sasl_mechanism);
	if (secblob) {
		res->r.BindRequest.creds.SASL.secblob = talloc(res, DATA_BLOB);
		if (!res->r.BindRequest.creds.SASL.secblob) {
			talloc_free(res);
			return NULL;
		}
		*res->r.BindRequest.creds.SASL.secblob = *secblob;
	} else {
		res->r.BindRequest.creds.SASL.secblob = NULL;
	}
	res->controls = NULL;

	return res;
}


/*
  perform a sasl bind using the given credentials
*/
_PUBLIC_ NTSTATUS ldap_bind_sasl(struct ldap_connection *conn,
			struct cli_credentials *creds,
			struct loadparm_context *lp_ctx)
{
	const char *sasl_mech = "GSS-SPNEGO";
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = NULL;
	DATA_BLOB input = data_blob(NULL, 0);
	DATA_BLOB output = data_blob(NULL, 0);
	bool first = true;
	int wrap_flags = 0;
	uint32_t old_gensec_features;
	unsigned int logon_retries = 0;
	size_t queue_length;
	const DATA_BLOB *tls_cb = NULL;
	bool use_channel_bound = lpcfg_parm_bool(lp_ctx,
						  NULL,
						  "ldap_testing",
						  "channel_bound",
						  true);
	const char *forced_channel_binding = lpcfg_parm_string(lp_ctx,
						  NULL,
						  "ldap_testing",
						  "forced_channel_binding");
	DATA_BLOB forced_cb = data_blob_string_const(forced_channel_binding);

	if (conn->sockets.active == NULL) {
		status = NT_STATUS_CONNECTION_DISCONNECTED;
		goto failed;
	}

	queue_length = tevent_queue_length(conn->sockets.send_queue);
	if (queue_length != 0) {
		status = NT_STATUS_INVALID_PARAMETER_MIX;
		DEBUG(1, ("SASL bind triggered with non empty send_queue[%zu]: %s\n",
			  queue_length, nt_errstr(status)));
		goto failed;
	}

	if (conn->pending != NULL) {
		status = NT_STATUS_INVALID_PARAMETER_MIX;
		DEBUG(1, ("SASL bind triggered with pending requests: %s\n",
			  nt_errstr(status)));
		goto failed;
	}

	tmp_ctx = talloc_new(conn);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	gensec_init();

	if (conn->sockets.active == conn->sockets.tls) {
		/*
		 * allow this for testing the old code:
		 * ldap_testing:no_tls_channel_bindings = no
		 */
		bool use_tls_cb = lpcfg_parm_bool(lp_ctx,
						  NULL,
						  "ldap_testing",
						  "tls_channel_bindings",
						  true);

		/*
		 * require Kerberos SIGN/SEAL only if we don't use SSL
		 * Windows seem not to like double encryption
		 */
		wrap_flags = 0;

		if (use_tls_cb) {
			tls_cb = tstream_tls_channel_bindings(conn->sockets.tls);
		}
	} else if (cli_credentials_is_anonymous(creds)) {
		/*
		 * anonymous isn't protected
		 */
		wrap_flags = 0;
	} else {
		wrap_flags = lpcfg_client_ldap_sasl_wrapping(lp_ctx);
	}

	if (forced_cb.length != 0) {
	       tls_cb = &forced_cb;
	}

try_logon_again:
	/*
	  we loop back here on a logon failure, and re-create the
	  gensec session. The logon_retries counter ensures we don't
	  loop forever.
	 */
	data_blob_free(&input);
	TALLOC_FREE(conn->gensec);

	status = gensec_client_start(conn, &conn->gensec,
				     lpcfg_gensec_settings(conn, lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to start GENSEC engine (%s)\n", nt_errstr(status)));
		goto failed;
	}

	old_gensec_features = cli_credentials_get_gensec_features(creds);
	if (wrap_flags == 0) {
		cli_credentials_set_gensec_features(creds,
				old_gensec_features & ~(GENSEC_FEATURE_SIGN|GENSEC_FEATURE_SEAL),
				CRED_SPECIFIED);
	}

	/* this call also sets the gensec_want_features */
	status = gensec_set_credentials(conn->gensec, creds);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set GENSEC creds: %s\n", 
			  nt_errstr(status)));
		goto failed;
	}

	/* reset the original gensec_features (on the credentials
	 * context, so we don't tattoo it ) */
	cli_credentials_set_gensec_features(creds,
					    old_gensec_features,
					    CRED_SPECIFIED);

	if (wrap_flags & ADS_AUTH_SASL_SEAL) {
		gensec_want_feature(conn->gensec, GENSEC_FEATURE_SIGN);
		gensec_want_feature(conn->gensec, GENSEC_FEATURE_SEAL);
	}
	if (wrap_flags & ADS_AUTH_SASL_SIGN) {
		gensec_want_feature(conn->gensec, GENSEC_FEATURE_SIGN);
	}

	if (!use_channel_bound) {
		gensec_want_feature(conn->gensec, GENSEC_FEATURE_CB_OPTIONAL);
	}

	/*
	 * This is an indication for the NTLMSSP backend to
	 * also encrypt when only GENSEC_FEATURE_SIGN is requested
	 * in gensec_[un]wrap().
	 */
	gensec_want_feature(conn->gensec, GENSEC_FEATURE_LDAP_STYLE);

	if (conn->host) {
		status = gensec_set_target_hostname(conn->gensec, conn->host);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to set GENSEC target hostname: %s\n", 
				  nt_errstr(status)));
			goto failed;
		}
	}

	status = gensec_set_target_service(conn->gensec, "ldap");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set GENSEC target service: %s\n", 
			  nt_errstr(status)));
		goto failed;
	}

	if (tls_cb != NULL) {
		uint32_t initiator_addrtype = 0;
		const DATA_BLOB *initiator_address = NULL;
		uint32_t acceptor_addrtype = 0;
		const DATA_BLOB *acceptor_address = NULL;
		const DATA_BLOB *application_data = tls_cb;

		status = gensec_set_channel_bindings(conn->gensec,
						     initiator_addrtype,
						     initiator_address,
						     acceptor_addrtype,
						     acceptor_address,
						     application_data);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("Failed to set GENSEC channel bindings: %s\n",
				    nt_errstr(status));
			goto failed;
		}
	}

	status = gensec_start_mech_by_sasl_name(conn->gensec, sasl_mech);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("gensec_start_mech_by_sasl_name(%s): %s\n",
			    sasl_mech, nt_errstr(status));
		goto failed;
	}

	while (1) {
		NTSTATUS gensec_status;
		struct ldap_message *response;
		struct ldap_message *msg;
		struct ldap_request *req;
		int result = LDAP_OTHER;
	
		status = gensec_update(conn->gensec, tmp_ctx,
				       input,
				       &output);
		/* The status value here, from GENSEC is vital to the security
		 * of the system.  Even if the other end accepts, if GENSEC
		 * claims 'MORE_PROCESSING_REQUIRED' then you must keep
		 * feeding it blobs, or else the remote host/attacker might
		 * avoid mutual authentication requirements.
		 *
		 * Likewise, you must not feed GENSEC too much (after the OK),
		 * it doesn't like that either.
		 *
		 * For SASL/EXTERNAL, there is no data to send, but we still
		 * must send the actual Bind request the first time around.
		 * Otherwise, a result of NT_STATUS_OK with 0 output means the
		 * end of a multi-step authentication, and no message must be
		 * sent.
		 */

		gensec_status = status;

		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) && 
		    !NT_STATUS_IS_OK(status)) {
			break;
		}
		if (NT_STATUS_IS_OK(status) && output.length == 0) {
			if (!first)
				break;
		}
		first = false;

		msg = new_ldap_sasl_bind_msg(tmp_ctx,
					     sasl_mech,
					     output.data != NULL ? &output : NULL);
		if (msg == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto failed;
		}

		req = ldap_request_send(conn, msg);
		if (req == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto failed;
		}
		talloc_reparent(conn, tmp_ctx, req);

		status = ldap_result_n(req, 0, &response);
		if (!NT_STATUS_IS_OK(status)) {
			goto failed;
		}
		
		if (response->type != LDAP_TAG_BindResponse) {
			status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
			goto failed;
		}

		result = response->r.BindResponse.response.resultcode;

		if (result == LDAP_STRONG_AUTH_REQUIRED) {
			if (wrap_flags == 0) {
				wrap_flags = ADS_AUTH_SASL_SIGN;
				goto try_logon_again;
			}
		}

		if (result == LDAP_INVALID_CREDENTIALS) {
			/*
			  try a second time on invalid credentials, to
			  give the user a chance to re-enter the
			  password and to handle the case where our
			  kerberos ticket is invalid as the server
			  password has changed
			*/
			const char *principal;

			principal = gensec_get_target_principal(conn->gensec);
			if (principal == NULL) {
				const char *hostname = gensec_get_target_hostname(conn->gensec);
				const char *service  = gensec_get_target_service(conn->gensec);
				if (hostname != NULL && service != NULL) {
					principal = talloc_asprintf(tmp_ctx, "%s/%s", service, hostname);
				}
			}

			if (cli_credentials_failed_kerberos_login(creds, principal, &logon_retries) ||
			    cli_credentials_wrong_password(creds)) {
				/*
				  destroy our gensec session and loop
				  back up to the top to retry,
				  offering the user a chance to enter
				  new credentials, or get a new ticket
				  if using kerberos
				 */
				goto try_logon_again;
			}
		}

		if (result != LDAP_SUCCESS && result != LDAP_SASL_BIND_IN_PROGRESS) {
			status = ldap_check_response(conn, 
						     &response->r.BindResponse.response);
			break;
		}

		/* This is where we check if GENSEC wanted to be fed more data */
		if (!NT_STATUS_EQUAL(gensec_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			break;
		}
		if (response->r.BindResponse.SASL.secblob) {
			input = *response->r.BindResponse.SASL.secblob;
		} else {
			input = data_blob(NULL, 0);
		}
	}

	TALLOC_FREE(tmp_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	conn->bind.type = LDAP_BIND_SASL;
	conn->bind.creds = creds;

	if (wrap_flags & ADS_AUTH_SASL_SEAL) {
		if (!gensec_have_feature(conn->gensec, GENSEC_FEATURE_SIGN)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		if (!gensec_have_feature(conn->gensec, GENSEC_FEATURE_SEAL)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	} else if (wrap_flags & ADS_AUTH_SASL_SIGN) {
		if (!gensec_have_feature(conn->gensec, GENSEC_FEATURE_SIGN)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	}

	if (!gensec_have_feature(conn->gensec, GENSEC_FEATURE_SIGN) &&
	    !gensec_have_feature(conn->gensec, GENSEC_FEATURE_SEAL)) {
		return NT_STATUS_OK;
	}

	status = gensec_create_tstream(conn->sockets.raw,
				       conn->gensec,
				       conn->sockets.raw,
				       &conn->sockets.sasl);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	conn->sockets.active = conn->sockets.sasl;

	return NT_STATUS_OK;

failed:
	talloc_free(tmp_ctx);
	talloc_free(conn->gensec);
	conn->gensec = NULL;
	return status;
}
