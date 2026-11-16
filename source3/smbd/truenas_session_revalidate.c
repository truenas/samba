/*
 *  Unix SMB/CIFS implementation.
 *  Keep Kerberos sessions valid after the end time of the ticket
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * A session that a client sets up with Kerberos expires when the ticket
 * ends. smbd then answers each request with
 * NT_STATUS_NETWORK_SESSION_EXPIRED. The macOS and Linux clients do not
 * authenticate again on the same connection. They close the connection and
 * make a new one. That stops the I/O of the client.
 *
 * With "truenas:keep kerberos sessions = yes", smbd does not let such a
 * session expire. smbd sets the expiration time of the session to
 * infinity. At the time when the ticket ends, smbd asks the KDC if the
 * account of the user can still log on. smbd uses the machine account for
 * this request (S4U2Self). The KDC answers with a new ticket. smbd accepts
 * that ticket in the same way as the ticket of a session setup, and reads
 * the PAC of the ticket. smbd asks again when the new ticket ends.
 *
 * - The PAC has the account, the names and the groups of the token of the
 *   session. The session stays valid and keeps its token.
 * - The PAC has the account of the session, but different names or groups.
 *   The session stays valid and gets a new token from the PAC, with the
 *   current groups of the user.
 * - The PAC is for a different account, because a different account now
 *   has the name of the user. The session expires immediately.
 * - The KDC refuses because of the account (disabled, deleted, expired,
 *   locked). The session expires immediately.
 * - There is no answer about the account (no KDC, an error in the
 *   request, no token). smbd asks again after REVALIDATE_RETRY_SECS. After
 *   REVALIDATE_MAX_TRIES tries without an answer, the session expires.
 *
 * A token from S4U2Self has the SID S-1-18-2 (service asserted identity)
 * in place of S-1-18-1 (authentication authority asserted identity). The
 * comparison of the PAC with the token ignores these SIDs.
 *
 * The Kerberos library blocks during network I/O. A thread of the thread
 * pool of smbd talks to the KDC. smbd continues to serve requests during
 * that time. smbd cannot stop that thread. The Kerberos library limits the
 * time of a try. With "aio max threads = 0" there is no thread and the
 * main loop of smbd talks to the KDC.
 *
 * The parameter is off by default. It has an effect only on a member of
 * an Active Directory domain (security = ads).
 *
 * "truenas:kerberos session lifetime = N" is for tests. A session that a
 * client sets up with Kerberos then expires N seconds after the session
 * setup, or earlier if the ticket ends earlier. Each new authentication
 * on the session starts a new period. Use it to examine how a client
 * authenticates again. With "truenas:keep kerberos sessions = yes", the
 * first check occurs at that time and the session does not expire.
 * The default is 0, which keeps the end time of the ticket.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "source3/smbd/smbXsrv_session.h"
#include "source3/smbd/truenas_session_revalidate.h"
#include "auth.h"
#include "auth/gensec/gensec.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "passdb.h"
#include "libcli/security/security.h"
#include "smb_krb5.h"
#include "libads/kerberos_proto.h"
#include "secrets.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"
#include "lib/util/talloc_keep_secret.h"
#include "lib/util/dlinklist.h"
#include "nsswitch/libwbclient/wbclient.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

#ifdef HAVE_KRB5

#include "auth/kerberos/pac_utils.h"

/* The time to wait before a new try when there was no answer. */
#define REVALIDATE_RETRY_SECS 60
/* The number of tries without an answer before the session expires. */
#define REVALIDATE_MAX_TRIES 10
/* The minimum time between two checks. */
#define REVALIDATE_MIN_SECS 60

struct revalidate_state;

/*
 * The data of one check. A thread of the pool uses it, so it is not a
 * child of the session. It stays valid until the thread returns.
 */
struct revalidate_job {
	/* NULL when the session went away during the check. */
	struct revalidate_state *state;
	char *machine_princ;
	char *machine_pass;
	char *user_princ;
	enum kerberos_s4u2self_result result;
	int krb5_error;
	/* The end time of the new ticket. */
	time_t endtime;
	/* An AP-REQ with the new ticket, from malloc() */
	uint8_t *ap_req;
	size_t ap_req_len;
};

struct revalidate_state {
	struct revalidate_state *prev, *next;
	struct smbXsrv_session *session;
	char *user_princ;
	/* The next check. */
	struct tevent_timer *te;
	/* The check that runs now. */
	struct revalidate_job *job;
	unsigned int failures;
};

static struct revalidate_state *revalidate_states;

static void revalidate_timer(struct tevent_context *ev,
			     struct tevent_timer *te,
			     struct timeval now,
			     void *private_data);

static int revalidate_state_destructor(struct revalidate_state *state)
{
	DLIST_REMOVE(revalidate_states, state);
	if (state->job != NULL) {
		/* The thread still runs. revalidate_job_done() frees the job. */
		state->job->state = NULL;
		state->job = NULL;
	}
	return 0;
}

static int revalidate_job_destructor(struct revalidate_job *job)
{
	SAFE_FREE(job->ap_req);
	return 0;
}

static struct revalidate_state *revalidate_state_find(
	struct smbXsrv_session *session)
{
	struct revalidate_state *state = NULL;

	for (state = revalidate_states; state != NULL; state = state->next) {
		if (state->session == session) {
			return state;
		}
	}
	return NULL;
}

/*
 * True if smbd deletes the session. After a logoff, smbd keeps the session
 * until the response is sent, but session->client is NULL.
 */
static bool revalidate_session_gone(struct revalidate_state *state)
{
	struct smbXsrv_session *session = state->session;

	return session->client == NULL ||
	       NT_STATUS_EQUAL(session->status, NT_STATUS_USER_SESSION_DELETED);
}

/*
 * Make the Kerberos principal of the user from the names in the PAC.
 */
static char *revalidate_user_principal(
	TALLOC_CTX *mem_ctx,
	const struct auth_session_info *session_info)
{
	const char *account = session_info->info->account_name;
	const char *domain = session_info->info->domain_name;
	struct wbcDomainInfo *dinfo = NULL;
	const char *realm = NULL;
	char *upper_realm = NULL;
	char *princ = NULL;

	if (account == NULL || account[0] == '\0' || domain == NULL) {
		return NULL;
	}

	if (strequal(domain, lp_workgroup())) {
		realm = lp_realm();
	} else {
		/* A user of a trusted domain. winbindd knows the realm. */
		wbcErr wbc_err = wbcDomainInfo(domain, &dinfo);
		if (!WBC_ERROR_IS_OK(wbc_err)) {
			return NULL;
		}
		realm = dinfo->dns_name;
	}

	if (realm != NULL && realm[0] != '\0') {
		upper_realm = talloc_strdup_upper(mem_ctx, realm);
	}
	if (upper_realm != NULL) {
		princ = talloc_asprintf(mem_ctx, "%s@%s", account, upper_realm);
	}
	TALLOC_FREE(upper_realm);
	wbcFreeMemory(dinfo);
	return princ;
}

static void revalidate_arm(struct revalidate_state *state,
			   struct timeval when)
{
	TALLOC_FREE(state->te);
	state->te = tevent_add_timer(state->session->client->raw_ev_ctx,
				     state,
				     when,
				     revalidate_timer,
				     state);
	if (state->te == NULL) {
		DBG_ERR("session %" PRIu64 ": no memory for the timer\n",
			state->session->global->session_wire_id);
	}
}

/*
 * Make the session expire now. The client gets
 * NT_STATUS_NETWORK_SESSION_EXPIRED for its next request.
 */
static void revalidate_expire(struct revalidate_state *state)
{
	struct smbXsrv_session *session = state->session;
	struct timeval now = timeval_current();
	NTSTATUS status;

	session->global->expiration_time = timeval_to_nttime(&now);
	status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("session %" PRIu64 ": smbXsrv_session_update() "
			"failed: %s\n",
			session->global->session_wire_id,
			nt_errstr(status));
	}
	TALLOC_FREE(state);
}

/* The account is valid. The next check is when the new ticket ends. */
static void revalidate_next(struct revalidate_state *state, time_t endtime)
{
	struct timeval now = timeval_current();
	struct timeval end = { .tv_sec = endtime };
	struct timeval earliest = timeval_add(&now, REVALIDATE_MIN_SECS, 0);
	struct timeval next = timeval_max(&end, &earliest);

	state->failures = 0;
	DBG_INFO("session %" PRIu64 ": the KDC gave a new ticket for %s. "
		 "The next check is in %.0f seconds\n",
		 state->session->global->session_wire_id,
		 state->user_princ,
		 timeval_elapsed2(&now, &next));
	revalidate_arm(state, next);
}

/* The KDC refused the account. The session expires now. */
static void revalidate_refused(struct revalidate_state *state, int krb5_error)
{
	uint64_t id = state->session->global->session_wire_id;

	DBG_WARNING("session %" PRIu64 ": the KDC refused a ticket for %s "
		    "(%s). The session expires now\n",
		    id,
		    state->user_princ,
		    error_message(krb5_error));
	if (krb5_error == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN) {
		/*
		 * This error has two possible causes. The KDC cannot tell
		 * us which one applies.
		 */
		DBG_WARNING("session %" PRIu64 ": the KDC gives this error if "
			    "the account does not exist. An Active Directory "
			    "KDC also gives this error if the machine account "
			    "of this server cannot read the attribute "
			    "tokenGroupsGlobalAndUniversal of the user. "
			    "Members of the group \"Windows Authorization "
			    "Access Group\" can read this attribute\n",
			    id);
	}
	revalidate_expire(state);
}

/*
 * There is no answer about the account. smbd tries again after
 * REVALIDATE_RETRY_SECS. After REVALIDATE_MAX_TRIES tries, the session
 * expires.
 */
static void revalidate_retry(struct revalidate_state *state,
			     const char *reason)
{
	uint64_t id = state->session->global->session_wire_id;

	state->failures += 1;
	if (state->failures >= REVALIDATE_MAX_TRIES) {
		DBG_WARNING("session %" PRIu64 ": smbd could not check %s "
			    "after %u tries (%s). The session expires now\n",
			    id,
			    state->user_princ,
			    state->failures,
			    reason);
		revalidate_expire(state);
		return;
	}

	DBG_WARNING("session %" PRIu64 ": smbd could not check %s (%s). "
		    "The next try is in %d seconds\n",
		    id,
		    state->user_princ,
		    reason,
		    REVALIDATE_RETRY_SECS);
	revalidate_arm(state, timeval_current_ofs(REVALIDATE_RETRY_SECS, 0));
}

/*
 * A thread of the pool runs this function. The function must use only
 * the data of the job. talloc_tos(), DEBUG and the lp_*() functions are
 * not safe here.
 */
static void revalidate_job_fn(void *private_data)
{
	struct revalidate_job *job = private_data;

	job->result = kerberos_s4u2self_check(job->machine_princ,
					      job->machine_pass,
					      job->user_princ,
					      &job->endtime,
					      &job->ap_req,
					      &job->ap_req_len,
					      &job->krb5_error);
}

/*
 * True if the PAC has the account, the names and the groups of the token
 * of the session. smbd then keeps the token. To make a new token takes
 * some milliseconds of the main loop.
 */
static bool revalidate_pac_unchanged(
	const struct auth_session_info *session_info,
	const struct PAC_DATA *pac)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct security_token *token = session_info->security_token;
	const struct PAC_LOGON_INFO *logon_info = NULL;
	struct netr_SamInfo3 *info3 = NULL;
	struct dom_sid *sids = NULL;
	uint32_t num_sids = 0;
	bool unchanged = false;
	NTSTATUS status;
	uint32_t i;

	if (session_info->info == NULL || token == NULL ||
	    token->num_sids <= PRIMARY_GROUP_SID_INDEX) {
		goto done;
	}

	for (i = 0; i < pac->num_buffers; i++) {
		if (pac->buffers[i].type == PAC_TYPE_LOGON_INFO &&
		    pac->buffers[i].info != NULL) {
			logon_info = pac->buffers[i].info->logon_info.info;
		}
	}
	if (logon_info == NULL) {
		goto done;
	}

	/* This adds the resource groups, as for a session setup */
	status = create_info3_from_pac_logon_info(frame, logon_info, &info3);
	if (!NT_STATUS_IS_OK(status) || info3->base.domain_sid == NULL) {
		goto done;
	}

	if (!strequal(info3->base.account_name.string,
		      session_info->info->account_name) ||
	    !strequal(info3->base.logon_domain.string,
		      session_info->info->domain_name)) {
		goto done;
	}

	/*
	 * The user and the primary group come first, as in a token. The
	 * list has no asserted identity (S-1-18-*), which is different for
	 * S4U2Self.
	 */
	status = sid_array_from_info3(frame, info3, &sids, &num_sids, true);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!security_token_is_sid(token, &sids[0]) ||
	    !dom_sid_equal(&sids[1], &token->sids[PRIMARY_GROUP_SID_INDEX])) {
		goto done;
	}

	/* The token has each SID of the PAC */
	for (i = 0; i < num_sids; i++) {
		if (!security_token_has_sid(token, &sids[i])) {
			goto done;
		}
	}

	/*
	 * The PAC has each SID of a domain account in the token, except the
	 * local SAM. smbd adds the other SIDs of a token itself.
	 */
	for (i = 0; i < token->num_sids; i++) {
		const struct dom_sid *sid = &token->sids[i];

		if (dom_sid_has_account_domain(sid) &&
		    !sid_check_is_in_our_sam(sid) &&
		    !sids_contains_sid(sids, num_sids, sid)) {
			goto done;
		}
	}

	unchanged = true;
done:
	TALLOC_FREE(frame);
	return unchanged;
}

/*
 * Accept the ticket of the check in the same way as the ticket of a
 * session setup. If the PAC of the ticket matches the token of the
 * session, *_session_info is NULL: the session keeps its token. Otherwise
 * smbd makes the new token from the PAC, as for a session setup.
 */
static NTSTATUS revalidate_new_token(TALLOC_CTX *mem_ctx,
				     struct smbXsrv_session *session,
				     const struct revalidate_job *job,
				     struct auth_session_info **_session_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smbXsrv_connection *xconn = NULL;
	struct PAC_DATA_CTR *pac = NULL;
	struct auth4_context *auth_ctx = NULL;
	NTSTATUS status;
	uint32_t i;

	*_session_info = NULL;

	for (i = 0; i < session->global->num_channels; i++) {
		xconn = session->global->channels[i].connection;
		if (xconn != NULL) {
			break;
		}
	}
	if (xconn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	/* smbd also does a session setup as root */
	become_root();

	status = kerberos_ap_req_pac(frame, job->ap_req, job->ap_req_len, &pac);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	if (revalidate_pac_unchanged(session->global->auth_session_info,
				     pac->pac_data)) {
		goto out;
	}

	status = make_auth4_context(frame, &auth_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	status = auth_ctx->generate_session_info_pac(
		auth_ctx,
		mem_ctx,
		NULL,
		&pac->pac_blob,
		job->user_princ,
		xconn->remote_address,
		AUTH_SESSION_INFO_DEFAULT_GROUPS | AUTH_SESSION_INFO_UNIX_TOKEN,
		_session_info);
out:
	unbecome_root();
	TALLOC_FREE(frame);
	return status;
}

static const struct dom_sid *revalidate_user_sid(
	const struct auth_session_info *session_info)
{
	const struct security_token *token = NULL;

	if (session_info == NULL) {
		return NULL;
	}
	token = session_info->security_token;
	if (token == NULL || token->num_sids <= PRIMARY_USER_SID_INDEX) {
		return NULL;
	}
	return &token->sids[PRIMARY_USER_SID_INDEX];
}

/*
 * Give the new token to the session. smbd_smb2_reauth_generic_return()
 * does the same for a new authentication on the session.
 */
static NTSTATUS revalidate_use_token(struct revalidate_state *state,
				     struct auth_session_info **_session_info)
{
	struct smbXsrv_session *session = state->session;
	struct auth_session_info *session_info = *_session_info;
	char *user_princ = NULL;
	NTSTATUS status;
	uint32_t i;

	data_blob_clear_free(&session_info->session_key);
	session_info->session_key = data_blob_dup_talloc_s(
		session_info, session->global->application_key_blob);
	if (session_info->session_key.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* The account can have a new name */
	user_princ = revalidate_user_principal(state, session_info);
	if (user_princ != NULL) {
		TALLOC_FREE(state->user_princ);
		state->user_princ = user_princ;
	}

	TALLOC_FREE(session->global->auth_session_info);
	session->global->auth_session_info = talloc_move(session->global,
							 _session_info);
	session->global->auth_session_info_seqnum += 1;
	for (i = 0; i < session->global->num_channels; i++) {
		session->global->channels[i].auth_session_info_seqnum =
			session->global->auth_session_info_seqnum;
	}

	status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("session %" PRIu64 ": smbXsrv_session_update() "
			"failed: %s\n",
			session->global->session_wire_id,
			nt_errstr(status));
	}

	/* The tree connects get the new token with their next request */
	conn_clear_vuid_caches(session->client->sconn,
			       session->global->session_wire_id);
	return NT_STATUS_OK;
}

/*
 * Use the result of a check: keep or replace the token of the session, try
 * again later, or let the session expire. This can free the state.
 */
static void revalidate_job_result(struct revalidate_state *state,
				  const struct revalidate_job *job,
				  int ret)
{
	uint64_t id = state->session->global->session_wire_id;
	struct auth_session_info *session_info = NULL;
	const struct dom_sid *old_sid = NULL;
	const struct dom_sid *new_sid = NULL;
	struct dom_sid_buf old_buf, new_buf;
	NTSTATUS status;

	if (revalidate_session_gone(state)) {
		TALLOC_FREE(state);
		return;
	}
	if (ret != 0) {
		revalidate_retry(state, strerror(ret));
		return;
	}

	switch (job->result) {
	case KERBEROS_S4U2SELF_OK:
		break;
	case KERBEROS_S4U2SELF_REFUSED:
		revalidate_refused(state, job->krb5_error);
		return;
	case KERBEROS_S4U2SELF_UNAVAILABLE:
		revalidate_retry(state, error_message(job->krb5_error));
		return;
	}

	status = revalidate_new_token(state, state->session, job, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		revalidate_retry(state, nt_errstr(status));
		return;
	}
	if (session_info == NULL) {
		DBG_INFO("session %" PRIu64 ": the PAC of the new ticket for "
			 "%s matches the token of the session. The session "
			 "keeps its token\n",
			 id,
			 state->user_princ);
		revalidate_next(state, job->endtime);
		return;
	}

	/* The KDC finds the account by its name. Another account can have it. */
	old_sid = revalidate_user_sid(state->session->global->auth_session_info);
	new_sid = revalidate_user_sid(session_info);
	if (old_sid == NULL || new_sid == NULL ||
	    !dom_sid_equal(old_sid, new_sid)) {
		DBG_WARNING("session %" PRIu64 ": the KDC gave a ticket for %s "
			    "that is for a different account (%s). The account "
			    "of the session is %s. The session expires now\n",
			    id,
			    state->user_princ,
			    new_sid != NULL ?
				    dom_sid_str_buf(new_sid, &new_buf) : "none",
			    old_sid != NULL ?
				    dom_sid_str_buf(old_sid, &old_buf) : "none");
		TALLOC_FREE(session_info);
		revalidate_expire(state);
		return;
	}

	status = revalidate_use_token(state, &session_info);
	TALLOC_FREE(session_info);
	if (!NT_STATUS_IS_OK(status)) {
		revalidate_retry(state, nt_errstr(status));
		return;
	}

	DBG_INFO("session %" PRIu64 ": the PAC of the new ticket for %s is "
		 "different from the token of the session. smbd replaced the "
		 "token\n",
		 id,
		 state->user_princ);
	revalidate_next(state, job->endtime);
}

static void revalidate_job_done(struct tevent_req *subreq)
{
	struct revalidate_job *job = tevent_req_callback_data(
		subreq, struct revalidate_job);
	struct revalidate_state *state = job->state;
	int ret;

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	/* state is NULL if the session went away during the check */
	if (state != NULL) {
		state->job = NULL;
		revalidate_job_result(state, job, ret);
	}
	TALLOC_FREE(job);
}

/*
 * Give the check of the account to a thread of the pool.
 */
static void revalidate_start(struct revalidate_state *state)
{
	struct smbXsrv_client *client = state->session->client;
	struct revalidate_job *job = NULL;
	struct tevent_req *subreq = NULL;
	char *pass = NULL;

	job = talloc_zero(NULL, struct revalidate_job);
	if (job == NULL) {
		goto fail;
	}
	talloc_set_destructor(job, revalidate_job_destructor);
	job->result = KERBEROS_S4U2SELF_UNAVAILABLE;

	job->machine_princ = talloc_asprintf(job,
					     "%s$@%s",
					     lp_netbios_name(),
					     lp_realm());
	job->user_princ = talloc_strdup(job, state->user_princ);
	if (job->machine_princ == NULL || job->user_princ == NULL) {
		goto fail;
	}

	become_root();
	pass = secrets_fetch_machine_password(lp_workgroup(), NULL, NULL);
	unbecome_root();
	if (pass == NULL) {
		DBG_WARNING("No password for the machine account\n");
		goto fail;
	}
	job->machine_pass = talloc_strdup(job, pass);
	BURN_FREE_STR(pass);
	if (job->machine_pass == NULL) {
		goto fail;
	}
	talloc_keep_secret(job->machine_pass);

	subreq = pthreadpool_tevent_job_send(job,
					     client->raw_ev_ctx,
					     client->sconn->pool,
					     revalidate_job_fn,
					     job);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, revalidate_job_done, job);

	job->state = state;
	state->job = job;
	return;

fail:
	TALLOC_FREE(job);
	revalidate_retry(state, "the check did not start");
}

static void revalidate_timer(struct tevent_context *ev,
			     struct tevent_timer *te,
			     struct timeval now,
			     void *private_data)
{
	struct revalidate_state *state = talloc_get_type_abort(
		private_data, struct revalidate_state);

	TALLOC_FREE(state->te);
	if (revalidate_session_gone(state)) {
		TALLOC_FREE(state);
		return;
	}
	revalidate_start(state);
}

/* Apply "truenas:kerberos session lifetime" to a Kerberos session. */
static void session_lifetime_limit(struct smbXsrv_session *session)
{
	int lifetime = lp_parm_int(GLOBAL_SECTION_SNUM,
				   "truenas",
				   "kerberos session lifetime",
				   0);
	NTTIME expiry = session->global->expiration_time;
	struct timeval now = timeval_current();
	struct timeval limit;
	struct timeval end;

	if (lifetime <= 0) {
		return;
	}
	limit = timeval_add(&now, lifetime, 0);
	if (expiry <= timeval_to_nttime(&limit)) {
		return;
	}

	nttime_to_timeval(&end, expiry);
	DBG_INFO("session %" PRIu64 ": the session expires in %d seconds "
		 "(truenas:kerberos session lifetime), not in %.0f seconds\n",
		 session->global->session_wire_id,
		 lifetime,
		 timeval_elapsed2(&now, &end));

	session->global->expiration_time = timeval_to_nttime(&limit);
}

/*
 * smbd calls this function after each successful session setup, when the
 * expiration time of the session holds the end time of the ticket.
 */
void truenas_session_revalidate_setup(struct smbXsrv_session *session)
{
	struct auth_session_info *session_info =
		session->global->auth_session_info;
	NTTIME expiry;
	struct revalidate_state *state = NULL;
	struct timeval now = timeval_current();
	struct timeval when;

	/* A new authentication replaces the state of the old one. */
	state = revalidate_state_find(session);
	TALLOC_FREE(state);

	if (session->global->expiration_time == GENSEC_EXPIRE_TIME_INFINITY) {
		/* The client did not use Kerberos. */
		return;
	}

	session_lifetime_limit(session);
	expiry = session->global->expiration_time;

	if (!lp_parm_bool(GLOBAL_SECTION_SNUM,
			  "truenas",
			  "keep kerberos sessions",
			  false)) {
		return;
	}
	if (lp_security() != SEC_ADS) {
		return;
	}
	if (session_info == NULL || session_info->info == NULL ||
	    security_session_user_level(session_info, NULL) < SECURITY_USER) {
		return;
	}

	state = talloc_zero(session, struct revalidate_state);
	if (state == NULL) {
		return;
	}
	state->session = session;
	DLIST_ADD(revalidate_states, state);
	talloc_set_destructor(state, revalidate_state_destructor);

	state->user_princ = revalidate_user_principal(state, session_info);
	if (state->user_princ == NULL) {
		DBG_NOTICE("session %" PRIu64 ": no Kerberos principal for "
			   "%s\\%s. The session expires with its ticket\n",
			   session->global->session_wire_id,
			   session_info->info->domain_name,
			   session_info->info->account_name);
		TALLOC_FREE(state);
		return;
	}

	nttime_to_timeval(&when, expiry);
	revalidate_arm(state, when);
	if (state->te == NULL) {
		TALLOC_FREE(state);
		return;
	}

	DBG_INFO("session %" PRIu64 ": the session does not expire. "
		 "The first check for %s is in %.0f seconds\n",
		 session->global->session_wire_id,
		 state->user_princ,
		 timeval_elapsed2(&now, &when));

	session->global->expiration_time = GENSEC_EXPIRE_TIME_INFINITY;
}

#else /* HAVE_KRB5 */

void truenas_session_revalidate_setup(struct smbXsrv_session *session)
{
}

#endif /* HAVE_KRB5 */
