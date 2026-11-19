/*
 * TrueNAS: [MS-SMB2] 3.3.4.2 interim responses for READ, WRITE and FLUSH
 * on slow storage.
 *
 * smbd answers a READ, WRITE or FLUSH that still runs after 500
 * microseconds with an interim response (STATUS_PENDING). The interim
 * response grants the credits of the request. The final response has the
 * async flag, the AsyncId of the interim response and no credits. A
 * truenas_ros reactor does the same for the file I/O that smbd gives it.
 * Without the interim response, a Windows client drops the connection
 * after 60 seconds instead of 240.
 *
 * The share must be on storage that takes torture:pending_delay_ms or
 * longer for each read, write and flush. torture:pending_dir (default
 * "pending") must have:
 *   read.dat  at least torture:pending_io_size bytes, not in the page cache
 *   sync      write.dat and deep0.dat to deep<N-1>.dat, N being
 *             torture:pending_files, files that the kernel writes
 *             synchronously
 * Each test expects the behaviour of smbd without a reactor. The suite
 * passes against smbd with and without the reactors.
 *
 * Copyright (C) iXsystems, Inc. 2026
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"

/* The client gives up on a request after this many seconds. */
#define RP_LIMIT 60

struct rp_opts {
	const char *dir;
	uint32_t io_size;
	/* The delay of the storage in seconds, 0 for any */
	double delay;
	/* An interim response must come within this many seconds */
	double interim;
};

static struct rp_opts rp_opts(struct torture_context *tctx)
{
	return (struct rp_opts) {
		.dir = torture_setting_string(tctx, "pending_dir", "pending"),
		.io_size = torture_setting_int(tctx, "pending_io_size",
					       1024 * 1024),
		.delay = torture_setting_int(tctx, "pending_delay_ms", 0) /
			 1000.0,
		.interim = torture_setting_int(tctx, "pending_interim_ms",
					       1000) / 1000.0,
	};
}

static uint16_t rp_credits(struct smb2_tree *tree)
{
	return smb2cli_conn_get_cur_credits(tree->session->transport->conn);
}

/* Get the credits for a READ or WRITE of size bytes. */
static bool rp_get_credits(struct torture_context *tctx,
			   struct smb2_tree *tree,
			   uint32_t size)
{
	return test_smb2_bench_credits(tctx,
				       tree,
				       10000,
				       test_smb2_bench_min_credits(size, 1, 1));
}

/*
 * Check the responses to req, which the caller sent at start. An interim
 * response comes within o->interim seconds and grants credits. With
 * cancel, a CANCEL for the AsyncId follows. smbd lets a READ, WRITE or
 * FLUSH run on after a CANCEL. The final response comes after the delay
 * of the storage. It has the async flag and the AsyncId, which is the
 * MessageId, and grants no credits. The caller then receives req.
 */
static bool rp_check(struct torture_context *tctx,
		     struct smb2_tree *tree,
		     struct smb2_request *req,
		     struct timeval start,
		     const struct rp_opts *o,
		     bool cancel)
{
	uint16_t sent = rp_credits(tree);
	uint16_t interim;
	const uint8_t *hdr = NULL;
	double t;

	t = torture_ros_wait_pending(tctx, req, start, o->interim);
	torture_assert(tctx, t >= 0 && req->cancel.can_cancel,
		       "no interim response in time");
	torture_comment(tctx, "interim response after %.6f s\n", t);
	interim = rp_credits(tree);
	torture_assert(tctx, interim > sent,
		       "the interim response granted no credits");

	if (cancel) {
		smb2_cancel(req);
	}

	t = torture_ros_wait_done(tctx, req, start, RP_LIMIT);
	torture_assert(tctx, t >= 0, "no final response");
	/* A transport error also ends the wait, and leaves in.hdr NULL. */
	torture_assert(tctx, req->state == SMB2_REQUEST_DONE,
		       "the request ended in a transport error");
	torture_comment(tctx, "final response after %.3f s\n", t);
	torture_assert(tctx, t >= o->delay / 2,
		       "the I/O was faster than the storage delay");

	hdr = req->in.hdr;
	torture_assert(tctx, IVAL(hdr, SMB2_HDR_FLAGS) & SMB2_HDR_FLAG_ASYNC,
		       "the final response has no async flag");
	torture_assert_u64_equal(tctx,
				 BVAL(hdr, SMB2_HDR_ASYNC_ID),
				 BVAL(hdr, SMB2_HDR_MESSAGE_ID),
				 "the AsyncId is not the MessageId");
	torture_assert_int_equal(tctx, SVAL(hdr, SMB2_HDR_CREDIT), 0,
				 "the final response grants credits");
	torture_assert_int_equal(tctx, rp_credits(tree), interim,
				 "the credits changed with the final response");
	return true;
}

static bool test_rp_read(struct torture_context *tctx,
			 struct smb2_tree *tree)
{
	struct rp_opts o = rp_opts(tctx);
	const char *fname = talloc_asprintf(tctx, "%s\\read.dat", o.dir);
	struct smb2_handle h = {};
	struct smb2_read r = {};
	struct smb2_request *req = NULL;
	struct timeval start;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, rp_get_credits(tctx, tree, o.io_size), "credits");
	status = torture_smb2_open(tree, fname, SEC_RIGHTS_FILE_ALL, &h);
	torture_assert_ntstatus_ok(tctx, status, "open read.dat");

	r = (struct smb2_read) {
		.in.file.handle = h,
		.in.length = o.io_size,
	};
	start = timeval_current();
	req = smb2_read_send(tree, &r);
	torture_assert_goto(tctx, req != NULL, ret, done, "read send");
	ret = rp_check(tctx, tree, req, start, &o, false);
	status = smb2_read_recv(req, tctx, &r);
	req = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	torture_assert_int_equal_goto(tctx, r.out.data.length, o.io_size,
				      ret, done, "read length");
done:
	smb2_util_close(tree, h);
	return ret;
}

/* WRITE o.io_size bytes to sync\write.dat. With cancel, cancel it. */
static bool rp_write(struct torture_context *tctx,
		     struct smb2_tree *tree,
		     bool cancel)
{
	struct rp_opts o = rp_opts(tctx);
	const char *fname = talloc_asprintf(tctx, "%s\\sync\\write.dat",
					    o.dir);
	uint8_t *data = talloc_zero_array(tctx, uint8_t, o.io_size);
	struct smb2_handle h = {};
	struct smb2_write w = {};
	struct smb2_request *req = NULL;
	struct timeval start;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, data != NULL, "no memory");
	torture_assert(tctx, rp_get_credits(tctx, tree, o.io_size), "credits");
	status = torture_smb2_open(tree, fname, SEC_RIGHTS_FILE_ALL, &h);
	torture_assert_ntstatus_ok(tctx, status, "open write.dat");

	w = (struct smb2_write) {
		.in.file.handle = h,
		.in.data = data_blob_const(data, o.io_size),
	};
	start = timeval_current();
	req = smb2_write_send(tree, &w);
	torture_assert_goto(tctx, req != NULL, ret, done, "write send");
	ret = rp_check(tctx, tree, req, start, &o, cancel);
	status = smb2_write_recv(req, &w);
	req = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	torture_assert_int_equal_goto(tctx, w.out.nwritten, o.io_size,
				      ret, done, "write count");
done:
	smb2_util_close(tree, h);
	return ret;
}

static bool test_rp_write(struct torture_context *tctx,
			  struct smb2_tree *tree)
{
	return rp_write(tctx, tree, false);
}

/* A CANCEL leaves the WRITE running, as smbd does for a READ or WRITE. */
static bool test_rp_cancel(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	return rp_write(tctx, tree, true);
}

static bool test_rp_flush(struct torture_context *tctx,
			  struct smb2_tree *tree)
{
	struct rp_opts o = rp_opts(tctx);
	const char *fname = talloc_asprintf(tctx, "%s\\flush.dat", o.dir);
	uint8_t *data = talloc_zero_array(tctx, uint8_t, o.io_size);
	struct smb2_create c = {
		.in.desired_access = SEC_RIGHTS_FILE_ALL,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF,
		.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE,
		.in.fname = fname,
	};
	struct smb2_handle h = {};
	struct smb2_flush f = {};
	struct smb2_request *req = NULL;
	struct timeval start;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, data != NULL, "no memory");
	torture_assert(tctx, rp_get_credits(tctx, tree, o.io_size), "credits");
	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok(tctx, status, "create");
	h = c.out.file.handle;
	/* The data stays in the page cache until the FLUSH. */
	status = smb2_util_write(tree, h, data, 0, o.io_size);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");

	f = (struct smb2_flush) {
		.in.file.handle = h,
	};
	start = timeval_current();
	req = smb2_flush_send(tree, &f);
	torture_assert_goto(tctx, req != NULL, ret, done, "flush send");
	ret = rp_check(tctx, tree, req, start, &o, false);
	status = smb2_flush_recv(req, &f);
	req = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "flush");
done:
	smb2_util_close(tree, h);
	return ret;
}

/*
 * torture:pending_depth WRITEs of torture:pending_deep_size bytes at once,
 * spread over the deep files in sync. That is more than a reactor reads
 * at once. All of them must succeed. On slow storage, each of them also
 * gets an interim response, the WRITEs that wait unread at first too. The
 * CI script checks the memory of smbd meanwhile. The connection then stays
 * for torture:pending_hold_ms, so the script sees the peak of the smbd of
 * the connection.
 */
static bool test_rp_deep(struct torture_context *tctx,
			 struct smb2_tree *tree)
{
	struct rp_opts o = rp_opts(tctx);
	int depth = torture_setting_int(tctx, "pending_depth", 64);
	int nfiles = torture_setting_int(tctx, "pending_files", 16);
	uint32_t size = torture_setting_int(tctx, "pending_deep_size",
					    8 * 1024 * 1024);
	uint8_t *data = talloc_zero_array(tctx, uint8_t, size);
	struct smb2_handle *h = talloc_zero_array(tctx, struct smb2_handle,
						  nfiles);
	struct smb2_write *w = talloc_zero_array(tctx, struct smb2_write,
						 depth);
	struct smb2_request **req = talloc_zero_array(tctx,
						      struct smb2_request *,
						      depth);
	struct smbXcli_conn *conn = tree->session->transport->conn;
	struct timeval start = timeval_current();
	int i, opened = 0, interims = 0;
	uint32_t max = 0;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, depth > 0 && nfiles > 0, "bad options");
	torture_assert(tctx, data && h && w && req, "no memory");
	torture_assert(tctx, rp_get_credits(tctx, tree, size), "credits");
	for (opened = 0; opened < nfiles; opened++) {
		const char *fname = talloc_asprintf(tctx,
						    "%s\\sync\\deep%d.dat",
						    o.dir,
						    opened);

		status = torture_smb2_open(tree, fname, SEC_RIGHTS_FILE_ALL,
					   &h[opened]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open a deep file");
	}

	for (i = 0; i < depth; i++) {
		/* Like a client, wait for the credits of the next WRITE. */
		while (!smb2cli_conn_req_possible(conn, &max) || max < size) {
			torture_assert_goto(tctx,
					    timeval_elapsed(&start) < RP_LIMIT,
					    ret, done, "no credits");
			torture_ros_poll(tctx);
		}
		w[i] = (struct smb2_write) {
			.in.file.handle = h[i % nfiles],
			.in.offset = (uint64_t)(i / nfiles) * size,
			.in.data = data_blob_const(data, size),
		};
		req[i] = smb2_write_send(tree, &w[i]);
		torture_assert_goto(tctx, req[i] != NULL, ret, done,
				    "write send");
	}
	for (i = 0; i < depth; i++) {
		double t = torture_ros_wait_done(tctx, req[i], start,
						 2 * RP_LIMIT);

		torture_assert_goto(tctx, t >= 0, ret, done,
				    "no final response");
		interims += req[i]->cancel.can_cancel ? 1 : 0;
		status = smb2_write_recv(req[i], &w[i]);
		req[i] = NULL;
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"write");
	}
	torture_comment(tctx, "%d writes, %d with an interim response, "
			"%.3f s\n", depth, interims, timeval_elapsed(&start));
	torture_assert_goto(tctx, o.delay == 0 || interims == depth, ret, done,
			    "a slow WRITE without an interim response");
	torture_ros_sleep(
		tctx, torture_setting_int(tctx, "pending_hold_ms", 0) / 1000.0);
done:
	for (i = 0; i < depth; i++) {
		if (req[i] != NULL) {
			smb2_write_recv(req[i], &w[i]);
		}
	}
	for (i = 0; i < opened; i++) {
		smb2_util_close(tree, h[i]);
	}
	return ret;
}

struct torture_suite *torture_smb2_ros_pending_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "ros-pending");

	torture_suite_add_1smb2_test(suite, "read", test_rp_read);
	torture_suite_add_1smb2_test(suite, "write", test_rp_write);
	torture_suite_add_1smb2_test(suite, "flush", test_rp_flush);
	torture_suite_add_1smb2_test(suite, "cancel", test_rp_cancel);
	torture_suite_add_1smb2_test(suite, "deep", test_rp_deep);
	suite->description = talloc_strdup(
		suite, "Interim responses for slow READ, WRITE and FLUSH");
	return suite;
}
