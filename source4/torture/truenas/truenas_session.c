/*
   Unix SMB/CIFS implementation.

   TrueNAS Kerberos session torture tests.

   A session that a client sets up with Kerberos expires when the ticket
   ends. With "truenas:keep kerberos sessions = yes" on a member of an
   Active Directory domain, smbd keeps the session. At the time when the
   ticket ends, smbd asks the KDC if the account can still log on.

   The tests need a domain member and --use-kerberos=required. The client
   asks for a ticket that lasts torture:session_lifetime seconds (default
   5). smbd adds the clock skew of its Kerberos library to the end of the
   ticket. torture:session_skew must hold that clock skew in seconds
   (default 5).

   truenas.session.expire      The parameter is off, which is the default.
                               The session expires.
   truenas.session.revalidate  The parameter is on. The session stays valid
                               and I/O continues.
   truenas.session.refused     The parameter is on. The test runs the
                               command in torture:session_cmd after the
                               session setup. The command must disable the
                               account, or give its name to a different
                               account. The session expires at the time
                               when the ticket ends, not before.
   truenas.session.logoff      The parameter is on. The command in
                               torture:session_cmd must make the KDC hang
                               for some time. The client logs the session
                               off while smbd waits for the KDC. The
                               connection stays usable.
   truenas.session.groups      The parameter is on. Only the members of a
                               group can connect to the share in
                               torture:session_share. The command in
                               torture:session_cmd must add the user to
                               that group. After the end of the ticket,
                               the session can connect to that share.

   Copyright (C) iXsystems 2026

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
#include "system/wait.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "../libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"
#include "lib/cmdline/cmdline.h"
#include "auth/credentials/credentials.h"
#include "lib/param/param.h"

/* The time between two requests, in milliseconds */
#define SESSION_STEP_MSEC 200

struct session_test {
	struct smb2_tree *tree;
	struct smb2_handle root;
	int lifetime;
	/* The end of the ticket in smbd: seconds after the session setup */
	int end;
	int margin;
	/* The session setup started after "before" and ended before "after" */
	struct timeval before;
	struct timeval after;
};

static bool session_have_kerberos(void)
{
	struct cli_credentials *creds = samba_cmdline_get_creds();

	return cli_credentials_get_kerberos_state(creds) ==
	       CRED_USE_KERBEROS_REQUIRED;
}

/* Set up a session with a new, short ticket and open the share root */
static bool session_open(struct torture_context *tctx,
			 struct session_test *st)
{
	struct cli_credentials *creds = samba_cmdline_get_creds();
	struct smbcli_options options;
	const char *opt = NULL;
	NTSTATUS status;
	bool ok;

	*st = (struct session_test) {
		.lifetime = torture_setting_int(tctx, "session_lifetime", 5),
		.margin = torture_setting_int(tctx, "session_margin", 5),
	};
	st->end = st->lifetime + torture_setting_int(tctx, "session_skew", 5);

	cli_credentials_invalidate_ccache(creds, CRED_SPECIFIED);
	opt = talloc_asprintf(tctx, "gensec_gssapi:requested_life_time=%d",
			      st->lifetime);
	torture_assert(tctx, opt != NULL, "talloc");
	lpcfg_set_option(tctx->lp_ctx, opt);
	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	st->before = timeval_current();
	ok = torture_smb2_connection_ext(tctx, 0, &options, &st->tree);
	st->after = timeval_current();
	torture_assert(tctx, ok, "session setup with Kerberos");

	status = smb2_util_roothandle(st->tree, &st->root);
	torture_assert_ntstatus_ok(tctx, status, "open share root");
	return true;
}

static void session_close(struct torture_context *tctx,
			  struct session_test *st)
{
	struct cli_credentials *creds = samba_cmdline_get_creds();

	/* After the session expired, this drops the connection */
	TALLOC_FREE(st->tree);
	cli_credentials_invalidate_ccache(creds, CRED_SPECIFIED);
	lpcfg_set_option(tctx->lp_ctx, "gensec_gssapi:requested_life_time=0");
}

/* One request on the session */
static NTSTATUS session_probe(struct session_test *st)
{
	TALLOC_CTX *frame = talloc_new(st->tree);
	union smb_fileinfo q;
	NTSTATUS status;

	ZERO_STRUCT(q);
	q.basic_info.level = RAW_FILEINFO_BASIC_INFORMATION;
	q.basic_info.in.file.handle = st->root;
	status = smb2_getinfo_file(st->tree, frame, &q);
	TALLOC_FREE(frame);
	return status;
}

/*
 * Send requests until the session expires. smbd holds the end of the
 * ticket in full seconds, so each limit has some slack.
 */
static bool session_must_expire(struct torture_context *tctx,
				struct session_test *st)
{
	double earliest = st->end - 2;
	double latest = st->end + st->margin;
	NTSTATUS status = NT_STATUS_OK;

	while (timeval_elapsed(&st->after) < latest) {
		status = session_probe(st);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}
		smb_msleep(SESSION_STEP_MSEC);
	}
	torture_comment(tctx, "%s %.1f seconds after the session setup\n",
			nt_errstr(status), timeval_elapsed(&st->after));
	torture_assert_ntstatus_equal(tctx, status,
				      NT_STATUS_NETWORK_SESSION_EXPIRED,
				      "the session did not expire");
	torture_assert(tctx, timeval_elapsed(&st->before) >= earliest,
		       "the session expired before the ticket ended");
	return true;
}

/* Send requests until secs seconds after the session setup. All must work. */
static bool session_probe_until(struct torture_context *tctx,
				struct session_test *st,
				double secs)
{
	while (timeval_elapsed(&st->after) < secs) {
		NTSTATUS status = session_probe(st);

		torture_assert_ntstatus_ok(tctx, status,
			talloc_asprintf(tctx, "query %.1f seconds after the "
					"session setup",
					timeval_elapsed(&st->after)));
		smb_msleep(SESSION_STEP_MSEC);
	}
	return true;
}

/*
 * Run torture:session_cmd. With in_time, the command must end before the
 * ticket ends.
 */
static bool session_run_cmd(struct torture_context *tctx,
			    struct session_test *st,
			    const char *cmd,
			    bool in_time)
{
	int rc = system(cmd);

	torture_assert(tctx, rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0,
		       "torture:session_cmd failed");
	torture_assert(tctx,
		       !in_time || timeval_elapsed(&st->before) < st->end - 2,
		       "torture:session_cmd ended too late");
	return true;
}

/* The parameter is off: the session expires when the ticket ends */
static bool test_truenas_session_expire(struct torture_context *tctx)
{
	struct session_test st;
	bool ret = true;

	if (!session_have_kerberos()) {
		torture_skip(tctx, "the test needs --use-kerberos=required\n");
	}

	torture_assert_goto(tctx, session_open(tctx, &st), ret, done,
			    "session_open");
	torture_assert_goto(tctx, session_must_expire(tctx, &st), ret, done,
			    "session_must_expire");
done:
	session_close(tctx, &st);
	return ret;
}

/*
 * The parameter is on: writes, reads and metadata requests continue for
 * torture:session_hold seconds (default 10) after the ticket ended. The
 * test waits torture:session_step milliseconds between two rounds.
 */
static bool test_truenas_session_revalidate(struct torture_context *tctx)
{
	int hold = torture_setting_int(tctx, "session_hold", 10);
	int step = torture_setting_int(tctx, "session_step",
				       SESSION_STEP_MSEC);
	const char *fname = talloc_asprintf(tctx, "truenas_session_%s.dat",
					    generate_random_str(tctx, 8));
	struct smb2_handle h = {{0}};
	struct session_test st;
	uint8_t buf[4096];
	double limit, total = 0, slowest = 0;
	NTSTATUS status;
	bool ret = true;
	int n = 0;

	if (!session_have_kerberos()) {
		torture_skip(tctx, "the test needs --use-kerberos=required\n");
	}

	torture_assert_goto(tctx, session_open(tctx, &st), ret, done,
			    "session_open");
	status = torture_smb2_testfile(st.tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file");

	limit = st.end + hold;
	while (timeval_elapsed(&st.after) < limit) {
		struct timeval start = timeval_current();
		double at = timeval_elapsed(&st.after);
		struct smb2_read rd;
		double took;

		memset(buf, n, sizeof(buf));
		status = smb2_util_write(st.tree, h, buf, 0, sizeof(buf));
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			talloc_asprintf(tctx, "write %.1f seconds after "
					"the session setup", at));

		ZERO_STRUCT(rd);
		rd.in.file.handle = h;
		rd.in.length = sizeof(buf);
		status = smb2_read(st.tree, tctx, &rd);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			talloc_asprintf(tctx, "read %.1f seconds after "
					"the session setup", at));
		torture_assert_mem_equal_goto(tctx, rd.out.data.data, buf,
					      sizeof(buf), ret, done,
					      "the data that the read returned");
		TALLOC_FREE(rd.out.data.data);

		status = session_probe(&st);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			talloc_asprintf(tctx, "query %.1f seconds after "
					"the session setup", at));

		took = timeval_elapsed(&start);
		total += took;
		slowest = MAX(slowest, took);
		n++;
		if (step > 0) {
			smb_msleep(step);
		}
	}
	torture_comment(tctx, "%d rounds of write, read and query until %d "
			"seconds after the end of the ticket. A round took "
			"%.3f ms on average and %.3f ms at most\n",
			n, hold, total * 1000.0 / MAX(n, 1), slowest * 1000.0);

done:
	if (st.tree != NULL) {
		smb2_util_close(st.tree, h);
		smb2_util_unlink(st.tree, fname);
	}
	session_close(tctx, &st);
	return ret;
}

/*
 * The parameter is on. After the command, the account of the session
 * cannot log on. The session expires when the ticket ends, not before.
 */
static bool test_truenas_session_refused(struct torture_context *tctx)
{
	const char *cmd = torture_setting_string(tctx, "session_cmd", NULL);
	struct session_test st;
	bool ret = true;

	if (!session_have_kerberos()) {
		torture_skip(tctx, "the test needs --use-kerberos=required\n");
	}
	if (cmd == NULL) {
		torture_skip(tctx, "the test needs torture:session_cmd\n");
	}

	torture_assert_goto(tctx, session_open(tctx, &st), ret, done,
			    "session_open");
	torture_assert_goto(tctx, session_run_cmd(tctx, &st, cmd, true), ret,
			    done, "session_run_cmd");
	torture_assert_goto(tctx, session_must_expire(tctx, &st), ret, done,
			    "session_must_expire");
done:
	session_close(tctx, &st);
	return ret;
}

/*
 * The parameter is on and the KDC does not answer for some time. The
 * client logs the session off while smbd waits for the KDC. smbd must
 * handle the late answer: the connection stays usable.
 */
static bool test_truenas_session_logoff(struct torture_context *tctx)
{
	const char *cmd = torture_setting_string(tctx, "session_cmd", NULL);
	int wait_secs = torture_setting_int(tctx, "session_wait", 15);
	struct session_test st;
	NTSTATUS status;
	bool ret = true;

	if (!session_have_kerberos()) {
		torture_skip(tctx, "the test needs --use-kerberos=required\n");
	}
	if (cmd == NULL) {
		torture_skip(tctx, "the test needs torture:session_cmd\n");
	}

	torture_assert_goto(tctx, session_open(tctx, &st), ret, done,
			    "session_open");
	torture_assert_goto(tctx, session_run_cmd(tctx, &st, cmd, false), ret,
			    done, "session_run_cmd");

	/* Requests continue until smbd waits for the KDC */
	torture_assert_goto(tctx, session_probe_until(tctx, &st, st.end + 2),
			    ret, done, "requests before the logoff");

	status = smb2_logoff(st.tree->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "logoff");
	torture_comment(tctx, "logoff %.1f seconds after the session setup\n",
			timeval_elapsed(&st.after));

	smb_msleep(wait_secs * 1000);
	status = smb2_keepalive(st.tree->session->transport);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"echo after the answer of the KDC");
done:
	session_close(tctx, &st);
	return ret;
}

/* Connect the session to a second share */
static NTSTATUS session_tcon(struct torture_context *tctx,
			     struct session_test *st,
			     const char *share,
			     struct smb2_tree **_tree)
{
	struct smb2_session *session = st->tree->session;
	const char *host = torture_setting_string(tctx, "host", NULL);
	struct smb2_tree *tree = NULL;
	const char *unc = NULL;
	NTSTATUS status;

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	tree = smb2_tree_init(session, tctx, false);
	if (unc == NULL || tree == NULL) {
		TALLOC_FREE(tree);
		return NT_STATUS_NO_MEMORY;
	}

	status = smb2cli_tcon(session->transport->conn,
			      session->transport->options.request_timeout * 1000,
			      session->smbXcli,
			      tree->smbXcli,
			      0, /* flags */
			      unc);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tree);
		return status;
	}

	*_tree = tree;
	return NT_STATUS_OK;
}

/*
 * The parameter is on and the user joins a group after the session setup.
 * After the check at the end of the ticket, the session has the group.
 */
static bool test_truenas_session_groups(struct torture_context *tctx)
{
	const char *cmd = torture_setting_string(tctx, "session_cmd", NULL);
	const char *share = torture_setting_string(tctx, "session_share", NULL);
	struct smb2_tree *tree2 = NULL;
	struct session_test st;
	NTSTATUS status;
	bool ret = true;

	if (!session_have_kerberos()) {
		torture_skip(tctx, "the test needs --use-kerberos=required\n");
	}
	if (cmd == NULL || share == NULL) {
		torture_skip(tctx, "the test needs torture:session_cmd and "
			     "torture:session_share\n");
	}

	torture_assert_goto(tctx, session_open(tctx, &st), ret, done,
			    "session_open");

	status = session_tcon(tctx, &st, share, &tree2);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED, ret, done,
					   "tree connect before the user is in "
					   "the group");

	torture_assert_goto(tctx, session_run_cmd(tctx, &st, cmd, true), ret,
			    done, "session_run_cmd");

	/* Requests continue while smbd checks the account */
	torture_assert_goto(tctx,
			    session_probe_until(tctx, &st, st.end + st.margin),
			    ret, done, "requests while smbd checks the account");

	status = session_tcon(tctx, &st, share, &tree2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"tree connect after the end of the "
					"ticket");
done:
	TALLOC_FREE(tree2);
	session_close(tctx, &st);
	return ret;
}

void torture_truenas_session_suite(struct torture_suite *suite)
{
	struct torture_suite *session = torture_suite_create(suite, "session");

	torture_suite_add_simple_test(session, "expire",
				      test_truenas_session_expire);
	torture_suite_add_simple_test(session, "revalidate",
				      test_truenas_session_revalidate);
	torture_suite_add_simple_test(session, "refused",
				      test_truenas_session_refused);
	torture_suite_add_simple_test(session, "logoff",
				      test_truenas_session_logoff);
	torture_suite_add_simple_test(session, "groups",
				      test_truenas_session_groups);

	torture_suite_add_suite(suite, session);
}
