/*
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005
   Copyright (C) Guenther Deschner 2005,2007,2008

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
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "smb_krb5.h"
#include "libads/kerberos_proto.h"
#include "auth/common_auth.h"
#include "lib/param/param.h"
#include "librpc/crypto/gse.h"
#include "auth/gensec/gensec.h"
#include "../libcli/auth/spnego.h"
#include "lib/util/asn1.h"

#ifdef HAVE_KRB5

#include "auth/kerberos/pac_utils.h"

struct smb_krb5_context;

/*
  generate a krb5 GSS-API wrapper packet given a ticket
*/
static DATA_BLOB spnego_gen_krb5_wrap(
	TALLOC_CTX *ctx, const DATA_BLOB ticket, const uint8_t tok_id[2])
{
	ASN1_DATA *data;
	DATA_BLOB ret = data_blob_null;

	data = asn1_init(talloc_tos(), ASN1_MAX_TREE_DEPTH);
	if (data == NULL) {
		return data_blob_null;
	}

	if (!asn1_push_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_write_OID(data, OID_KERBEROS5)) goto err;

	if (!asn1_write(data, tok_id, 2)) goto err;
	if (!asn1_write(data, ticket.data, ticket.length)) goto err;
	if (!asn1_pop_tag(data)) goto err;

	if (!asn1_extract_blob(data, ctx, &ret)) {
		goto err;
	}

	asn1_free(data);
	data = NULL;

  err:

	if (data != NULL) {
		if (asn1_has_error(data)) {
			DEBUG(1, ("Failed to build krb5 wrapper at offset %d\n",
				  (int)asn1_current_ofs(data)));
		}

		asn1_free(data);
	}

	return ret;
}

/*
 * Given the username/password, do a kinit, store the ticket in
 * cache_name if specified, and return the PAC_LOGON_INFO (the
 * structure containing the important user information such as
 * groups).
 */
NTSTATUS kerberos_return_pac(TALLOC_CTX *mem_ctx,
			     const char *name,
			     const char *pass,
			     time_t time_offset,
			     time_t *expire_time,
			     time_t *renew_till_time,
			     const char *cache_name,
			     bool request_pac,
			     bool add_netbios_addr,
			     time_t renewable_time,
			     const char *impersonate_princ_s,
			     const char *local_service,
			     char **_canon_principal,
			     char **_canon_realm,
			     struct PAC_DATA_CTR **_pac_data_ctr)
{
	krb5_error_code ret;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	DATA_BLOB tkt = data_blob_null;
	DATA_BLOB tkt_wrapped = data_blob_null;
	DATA_BLOB ap_rep = data_blob_null;
	DATA_BLOB sesskey1 = data_blob_null;
	const char *auth_princ = NULL;
	const char *cc = NULL;
	struct auth_session_info *session_info;
	struct gensec_security *gensec_server_context;
	const struct gensec_security_ops **backends;
	struct gensec_settings *gensec_settings;
	size_t idx = 0;
	struct auth4_context *auth_context;
	struct loadparm_context *lp_ctx;
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	char *canon_principal = NULL;
	char *canon_realm = NULL;
	krb5_context ctx = NULL;
	krb5_ccache ccid = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	ZERO_STRUCT(tkt);
	ZERO_STRUCT(ap_rep);
	ZERO_STRUCT(sesskey1);

	if (!name || !pass) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (_canon_principal != NULL) {
		*_canon_principal = NULL;
	}

	if (_canon_realm != NULL) {
		*_canon_realm = NULL;
	}

	if (cache_name) {
		cc = cache_name;
	} else {
		char *ccname = NULL;

		ret = smb_krb5_init_context_common(&ctx);
		if (ret != 0) {
			status = krb5_to_nt_status(ret);
			goto out;
		}

		ret = smb_krb5_cc_new_unique_memory(ctx,
						    tmp_ctx,
						    &ccname,
						    &ccid);
		if (ret != 0) {
			status = krb5_to_nt_status(ret);
			goto out;
		}
		cc = ccname;
	}

	if (!strchr_m(name, '@')) {
		auth_princ = talloc_asprintf(mem_ctx, "%s@%s", name,
			lp_realm());
	} else {
		auth_princ = name;
	}
	NT_STATUS_HAVE_NO_MEMORY(auth_princ);

	ret = kerberos_kinit_password_ext(auth_princ,
					  pass,
					  time_offset,
					  expire_time,
					  renew_till_time,
					  cc,
					  request_pac,
					  add_netbios_addr,
					  renewable_time,
					  tmp_ctx,
					  &canon_principal,
					  &canon_realm,
					  &status);
	if (ret) {
		DEBUG(1,("kinit failed for '%s' with: %s (%d)\n",
			auth_princ, error_message(ret), ret));
		/* status already set */
		goto out;
	}

	DEBUG(10,("got TGT for %s in %s\n", auth_princ, cc));
	if (expire_time) {
		DEBUGADD(10,("\tvalid until: %s (%d)\n",
			http_timestring(talloc_tos(), *expire_time),
			(int)*expire_time));
	}
	if (renew_till_time) {
		DEBUGADD(10,("\trenewable till: %s (%d)\n",
			http_timestring(talloc_tos(), *renew_till_time),
			(int)*renew_till_time));
	}

	/* we cannot continue with krb5 when UF_DONT_REQUIRE_PREAUTH is set,
	 * in that case fallback to NTLM - gd */

	if (expire_time && renew_till_time &&
	    (*expire_time == 0) && (*renew_till_time == 0)) {
		status = NT_STATUS_INVALID_LOGON_TYPE;
		goto out;
	}

	ret = ads_krb5_cli_get_ticket(mem_ctx,
				      local_service,
				      time_offset,
				      &tkt,
				      &sesskey1,
				      0,
				      cc,
				      NULL,
				      impersonate_princ_s);
	if (ret) {
		DEBUG(1,("failed to get ticket for %s: %s\n",
			local_service, error_message(ret)));
		if (impersonate_princ_s) {
			DEBUGADD(1,("tried S4U2SELF impersonation as: %s\n",
				impersonate_princ_s));
		}
		status = krb5_to_nt_status(ret);
		goto out;
	}

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(tmp_ctx, tkt, TOK_ID_KRB_AP_REQ);
	if (tkt_wrapped.data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	auth_context = auth4_context_for_PAC_DATA_CTR(tmp_ctx);
	if (auth_context == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	lp_ctx = loadparm_init_s3(tmp_ctx, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		status = NT_STATUS_INVALID_SERVER_STATE;
		DEBUG(10, ("loadparm_init_s3 failed\n"));
		goto out;
	}

	gensec_settings = lpcfg_gensec_settings(tmp_ctx, lp_ctx);
	if (gensec_settings == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(10, ("lpcfg_gensec_settings failed\n"));
		goto out;
	}

	backends = talloc_zero_array(gensec_settings,
				     const struct gensec_security_ops *, 2);
	if (backends == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	gensec_settings->backends = backends;

	gensec_init();

	backends[idx++] = gensec_gse_security_by_oid(GENSEC_OID_KERBEROS5);

	status = gensec_server_start(tmp_ctx, gensec_settings,
					auth_context, &gensec_server_context);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, (__location__ "Failed to start server-side GENSEC to validate a Kerberos ticket: %s\n", nt_errstr(status)));
		goto out;
	}

	talloc_unlink(tmp_ctx, lp_ctx);
	talloc_unlink(tmp_ctx, gensec_settings);
	talloc_unlink(tmp_ctx, auth_context);

	/* Session info is not complete, do not pass to auth log */
	gensec_want_feature(gensec_server_context, GENSEC_FEATURE_NO_AUTHZ_LOG);

	status = gensec_start_mech_by_oid(gensec_server_context, GENSEC_OID_KERBEROS5);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, (__location__ "Failed to start server-side GENSEC krb5 to validate a Kerberos ticket: %s\n", nt_errstr(status)));
		goto out;
	}

	/* Do a client-server update dance */
	status = gensec_update(gensec_server_context, tmp_ctx, tkt_wrapped, &ap_rep);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("gensec_update() failed: %s\n", nt_errstr(status)));
		goto out;
	}

	/* Now return the PAC information to the callers.  We ignore
	 * the session_info and instead pick out the PAC via the
	 * private_data on the auth_context */
	status = gensec_session_info(gensec_server_context, tmp_ctx, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Unable to obtain PAC via gensec_session_info\n"));
		goto out;
	}

	pac_data_ctr = auth4_context_get_PAC_DATA_CTR(auth_context, mem_ctx);
	if (pac_data_ctr == NULL) {
		DEBUG(1,("no PAC\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	*_pac_data_ctr = talloc_move(mem_ctx, &pac_data_ctr);
	if (_canon_principal != NULL) {
		*_canon_principal = talloc_move(mem_ctx, &canon_principal);
	}
	if (_canon_realm != NULL) {
		*_canon_realm = talloc_move(mem_ctx, &canon_realm);
	}

out:
	if (ccid != NULL) {
		krb5_cc_destroy(ctx, ccid);
		ccid = NULL;
	}
	if (ctx != NULL) {
		krb5_free_context(ctx);
		ctx = NULL;
	}
	talloc_free(tmp_ctx);

	data_blob_free(&tkt);
	data_blob_free(&ap_rep);
	data_blob_free(&sesskey1);

	return status;
}

/*
 * Make an AP-REQ with the ticket in creds, with the GSS-API checksum that
 * ads_krb5_mk_req() also sends. The function calls only the Kerberos
 * library and malloc().
 */
static krb5_error_code s4u2self_mk_req(krb5_context ctx,
				       krb5_creds *creds,
				       uint8_t **_ap_req,
				       size_t *_ap_req_len)
{
	krb5_auth_context auth_ctx = NULL;
#ifdef HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE
	/* Length of the channel bindings, no channel bindings, no flags */
	uint8_t gss_cksum[4 + 16 + 4] = { 0 };
#endif
	krb5_data in_data;
	krb5_data out;
	krb5_error_code ret;

	ZERO_STRUCT(in_data);
	ZERO_STRUCT(out);

	ret = krb5_auth_con_init(ctx, &auth_ctx);
	if (ret != 0) {
		return ret;
	}

	ret = krb5_auth_con_setaddrs(ctx, auth_ctx, NULL, NULL);
	if (ret != 0) {
		goto out;
	}

#ifdef HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE
	SIVAL(gss_cksum, 0, 16);
	in_data.data = (char *)gss_cksum;
	in_data.length = sizeof(gss_cksum);

	ret = krb5_auth_con_set_req_cksumtype(ctx, auth_ctx, 0x8003);
	if (ret != 0) {
		goto out;
	}
#endif

	ret = krb5_mk_req_extended(ctx,
				   &auth_ctx,
				   AP_OPTS_USE_SUBKEY,
				   &in_data,
				   creds,
				   &out);
	if (ret != 0) {
		goto out;
	}

	*_ap_req = malloc(out.length);
	if (*_ap_req == NULL) {
		ret = ENOMEM;
		goto out;
	}
	memcpy(*_ap_req, out.data, out.length);
	*_ap_req_len = out.length;

out:
	smb_krb5_free_data_contents(ctx, &out);
	krb5_auth_con_free(ctx, auth_ctx);
	return ret;
}

/*
 * Ask the KDC if the account of a user can log on to this server.
 *
 * The machine account asks the KDC for a ticket for the user to this
 * server (S4U2Self). The user does not take part. The function does
 * network I/O and can block.
 *
 * A thread of a thread pool can call this function. For that reason the
 * function calls only the Kerberos library. talloc_tos(), DEBUG and the
 * lp_*() functions are not safe in a second thread.
 *
 * machine_princ is the principal of the machine account. machine_pass is
 * its password. user_princ is the principal of the user.
 *
 * On KERBEROS_S4U2SELF_OK, *_endtime is the end time of the ticket.
 * *_ap_req is an AP-REQ with the ticket, for kerberos_ap_req_pac(). The
 * caller frees *_ap_req with free(). *_krb5_error is the Kerberos error
 * code, or 0.
 */
enum kerberos_s4u2self_result kerberos_s4u2self_check(
	const char *machine_princ,
	const char *machine_pass,
	const char *user_princ,
	time_t *_endtime,
	uint8_t **_ap_req,
	size_t *_ap_req_len,
	int *_krb5_error)
{
	enum kerberos_s4u2self_result result = KERBEROS_S4U2SELF_UNAVAILABLE;
	krb5_context ctx = NULL;
	krb5_ccache cc = NULL;
	krb5_principal me = NULL;
	krb5_principal client = NULL;
	krb5_principal user = NULL;
	krb5_creds *creds = NULL;
	krb5_error_code ret;

	*_endtime = 0;
	*_ap_req = NULL;
	*_ap_req_len = 0;
	*_krb5_error = 0;

	ret = krb5_init_context(&ctx);
	if (ret != 0) {
		goto out;
	}

	ret = krb5_parse_name(ctx, machine_princ, &me);
	if (ret != 0) {
		goto out;
	}

	ret = krb5_parse_name(ctx, user_princ, &user);
	if (ret != 0) {
		goto out;
	}

	ret = krb5_cc_new_unique(ctx, "MEMORY", NULL, &cc);
	if (ret != 0) {
		goto out;
	}

	/* Get a TGT for the machine account. */
	ret = smb_krb5_kinit_password_ccache(
		ctx, cc, me, machine_pass, NULL, NULL, NULL, NULL);
	if (ret != 0) {
		goto out;
	}

	/* The name of the machine account as the KDC returned it */
	ret = krb5_cc_get_principal(ctx, cc, &client);
	if (ret != 0) {
		goto out;
	}

	/* The service is the machine account. */
	ret = smb_krb5_get_credentials(ctx, cc, client, client, user, &creds);
	if (ret == 0) {
		ret = s4u2self_mk_req(ctx, creds, _ap_req, _ap_req_len);
		if (ret == 0) {
			*_endtime = creds->times.endtime;
			result = KERBEROS_S4U2SELF_OK;
		}
		goto out;
	}

	switch (ret) {
	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	case KRB5KDC_ERR_CLIENT_REVOKED:
	case KRB5KDC_ERR_NAME_EXP:
	case KRB5KDC_ERR_CLIENT_NOTYET:
#if defined(KRB5KDC_ERR_KEY_EXP) /* MIT */
	case KRB5KDC_ERR_KEY_EXP:
#else /* Heimdal */
	case KRB5KDC_ERR_KEY_EXPIRED:
#endif
	case KRB5KDC_ERR_POLICY:
		/* These answers are about the account of the user. */
		result = KERBEROS_S4U2SELF_REFUSED;
		break;
	default:
		break;
	}

out:
	*_krb5_error = ret;
	if (creds != NULL) {
		krb5_free_creds(ctx, creds);
	}
	if (client != NULL) {
		krb5_free_principal(ctx, client);
	}
	if (user != NULL) {
		krb5_free_principal(ctx, user);
	}
	if (me != NULL) {
		krb5_free_principal(ctx, me);
	}
	if (cc != NULL) {
		krb5_cc_destroy(ctx, cc);
	}
	if (ctx != NULL) {
		krb5_free_context(ctx);
	}
	return result;
}

/*
 * Accept an AP-REQ from kerberos_s4u2self_check() in the same way as the
 * ticket of a session setup, and return the PAC of the ticket. The steps
 * are the same as at the end of kerberos_return_pac(). Only the main
 * thread can call this function.
 */
NTSTATUS kerberos_ap_req_pac(TALLOC_CTX *mem_ctx,
			     const uint8_t *ap_req,
			     size_t ap_req_len,
			     struct PAC_DATA_CTR **_pac_data_ctr)
{
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB ticket = data_blob_const(ap_req, ap_req_len);
	DATA_BLOB tkt_wrapped;
	DATA_BLOB ap_rep = data_blob_null;
	struct auth4_context *auth_context = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct gensec_settings *gensec_settings = NULL;
	const struct gensec_security_ops **backends = NULL;
	struct gensec_security *gensec = NULL;
	struct auth_session_info *session_info = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	tkt_wrapped = spnego_gen_krb5_wrap(frame, ticket, TOK_ID_KRB_AP_REQ);
	auth_context = auth4_context_for_PAC_DATA_CTR(frame);
	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (tkt_wrapped.data == NULL || auth_context == NULL || lp_ctx == NULL) {
		goto out;
	}
	gensec_settings = lpcfg_gensec_settings(frame, lp_ctx);
	if (gensec_settings == NULL) {
		goto out;
	}
	backends = talloc_zero_array(gensec_settings,
				     const struct gensec_security_ops *,
				     2);
	if (backends == NULL) {
		goto out;
	}
	backends[0] = gensec_gse_security_by_oid(GENSEC_OID_KERBEROS5);
	gensec_settings->backends = backends;

	gensec_init();

	status = gensec_server_start(frame,
				     gensec_settings,
				     auth_context,
				     &gensec);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	/* gensec has references to these now */
	talloc_unlink(frame, lp_ctx);
	talloc_unlink(frame, gensec_settings);
	talloc_unlink(frame, auth_context);

	gensec_want_feature(gensec, GENSEC_FEATURE_NO_AUTHZ_LOG);

	status = gensec_start_mech_by_oid(gensec, GENSEC_OID_KERBEROS5);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	status = gensec_update(gensec, frame, tkt_wrapped, &ap_rep);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* The session info is empty. The auth context keeps the PAC. */
	status = gensec_session_info(gensec, frame, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	*_pac_data_ctr = auth4_context_get_PAC_DATA_CTR(auth_context, mem_ctx);
	if (*_pac_data_ctr == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
	}
out:
	TALLOC_FREE(frame);
	return status;
}

#endif
