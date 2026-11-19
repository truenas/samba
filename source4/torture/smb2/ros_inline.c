/*
 * TrueNAS: [MS-SMB2] checks for the inline runs of the truenas_ros
 * reactors and for the delegation of FLUSH to them.
 *
 * A reactor thread runs most PDUs through the code of smbd under a process
 * lock. The main thread of smbd runs NEGPROT, SESSION_SETUP, LOGOFF,
 * TREE_DISCONNECT, the requests on IPC$ and the events of its own loop.
 * These tests check behaviour that this split can break. They cover
 * FLUSH, timers that a PDU starts, wake-ups between requests, and the end
 * of a tree connect or a session while other requests run. Each test
 * expects the behaviour of smbd without a reactor. The suite passes
 * against smbd with and without the reactors.
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
#include "lib/util/tevent_ntstatus.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/smb2/lease_break_handler.h"
#include "libcli/security/security.h"
#include "lib/cmdline/cmdline.h"
#include "param/param.h"

#define RI_DIR "ros_inline"

/* smbd's OPLOCK_BREAK_TIMEOUT, see source3/include/local.h */
#define RI_BREAK_TIMEOUT 35

/* Run the event loop for secs seconds. */
void torture_ros_sleep(struct torture_context *tctx, double secs)
{
	struct timeval start = timeval_current();

	while (timeval_elapsed(&start) < secs) {
		torture_ros_poll(tctx);
	}
}

/*
 * Wait until req has its final reply. Return the seconds from start to
 * that reply, or -1 after limit seconds.
 */
double torture_ros_wait_done(struct torture_context *tctx,
			     struct smb2_request *req,
			     struct timeval start,
			     double limit)
{
	while (req->state <= SMB2_REQUEST_RECV) {
		if (timeval_elapsed(&start) > limit) {
			return -1;
		}
		torture_ros_poll(tctx);
	}
	return timeval_elapsed(&start);
}

/*
 * Wait until req has an interim response or its final reply. Return the
 * seconds from start to that point, or -1 after limit seconds.
 */
double torture_ros_wait_pending(struct torture_context *tctx,
				struct smb2_request *req,
				struct timeval start,
				double limit)
{
	while (!req->cancel.can_cancel && req->state <= SMB2_REQUEST_RECV) {
		if (timeval_elapsed(&start) > limit) {
			return -1;
		}
		torture_ros_poll(tctx);
	}
	return timeval_elapsed(&start);
}

static NTSTATUS ri_flush(struct smb2_tree *tree, struct smb2_handle h)
{
	struct smb2_flush f = {
		.in.file.handle = h,
	};

	return smb2_flush(tree, &f);
}

static NTSTATUS ri_write(struct smb2_tree *tree,
			 struct smb2_handle h,
			 uint64_t ofs,
			 size_t len,
			 uint8_t fill)
{
	struct smb2_write w = {
		.in.file.handle = h,
		.in.offset = ofs,
	};
	NTSTATUS status;

	w.in.data = data_blob_talloc(tree, NULL, len);
	if (w.in.data.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	memset(w.in.data.data, fill, len);
	status = smb2_write(tree, &w);
	data_blob_free(&w.in.data);
	return status;
}

/*
 * This test checks that a FLUSH of a file or a stream needs
 * FILE_WRITE_DATA or FILE_APPEND_DATA ([MS-SMB2] 3.3.5.11). smbd also
 * flushes a directory that is open with FILE_ADD_FILE or
 * FILE_ADD_SUBDIRECTORY. A FLUSH of a closed handle fails with
 * NT_STATUS_FILE_CLOSED.
 */
static bool test_ri_flush_access(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\flush_access.dat";
	const char *sname = RI_DIR "\\flush_access.dat:ri_stream";
	struct smb2_handle h = {};
	struct smb2_handle hr = {};
	struct smb2_handle ha = {};
	struct smb2_handle hd = {};
	struct smb2_handle hs = {};
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");

	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	status = ri_write(tree, h, 0, 4096, 0x5a);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	status = ri_flush(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"flush with write access");

	status = torture_smb2_testfile_access(tree,
					      fname,
					      &hr,
					      SEC_FILE_READ_DATA |
					      SEC_FILE_READ_ATTRIBUTE);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open read");
	status = ri_flush(tree, hr);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "flush with read access only");

	status = torture_smb2_testfile_access(tree,
					      fname,
					      &ha,
					      SEC_FILE_APPEND_DATA |
					      SEC_FILE_READ_ATTRIBUTE);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open append");
	status = ri_flush(tree, ha);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"flush with append access");
	smb2_util_close(tree, ha);
	status = ri_flush(tree, ha);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_FILE_CLOSED,
					   ret, done,
					   "flush of a closed handle");
	ZERO_STRUCT(ha);

	status = torture_smb2_testdir_access(tree,
					     RI_DIR,
					     &hd,
					     SEC_DIR_LIST |
					     SEC_FILE_READ_ATTRIBUTE);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open dir list");
	status = ri_flush(tree, hd);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "flush of a dir opened to list");
	smb2_util_close(tree, hd);
	ZERO_STRUCT(hd);

	status = torture_smb2_testdir_access(tree,
					     RI_DIR,
					     &hd,
					     SEC_DIR_ADD_FILE |
					     SEC_FILE_READ_ATTRIBUTE);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open dir add file");
	status = ri_flush(tree, hd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"flush of a dir opened to add files");

	status = torture_smb2_testfile(tree, sname, &hs);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create stream");
	status = ri_write(tree, hs, 0, 100, 0x33);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write stream");
	status = ri_flush(tree, hs);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"flush of a stream");

done:
	if (!smb2_util_handle_empty(hs)) {
		smb2_util_close(tree, hs);
	}
	if (!smb2_util_handle_empty(hd)) {
		smb2_util_close(tree, hd);
	}
	if (!smb2_util_handle_empty(hr)) {
		smb2_util_close(tree, hr);
	}
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

#define RI_PIPE_WRITES 8
#define RI_PIPE_SIZE (64 * 1024)

/*
 * This test sends WRITEs, a FLUSH and a CLOSE on one handle without
 * waiting for the replies. Each request must succeed. The file must then
 * contain the data of each WRITE.
 */
static bool test_ri_flush_pipeline(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\flush_pipeline.dat";
	struct smb2_request *wreq[RI_PIPE_WRITES] = {};
	struct smb2_write w[RI_PIPE_WRITES] = {};
	struct smb2_request *freq = NULL;
	struct smb2_request *creq = NULL;
	struct smb2_flush f = {};
	struct smb2_close c = {};
	struct smb2_handle h = {};
	struct smb2_read r = {};
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20);
	unsigned round;
	NTSTATUS status;
	bool ret = true;
	unsigned i;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");
	/* Get credits for the requests of one round and a few more. */
	torture_assert(tctx,
		       test_smb2_bench_credits(tctx,
					       tree,
					       10000,
					       RI_PIPE_WRITES * 2 + 8),
		       "credits");

	for (round = 0; round < rounds; round++) {
		status = torture_smb2_testfile(tree, fname, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create");

		for (i = 0; i < RI_PIPE_WRITES; i++) {
			w[i] = (struct smb2_write) {
				.in.file.handle = h,
				.in.offset = (uint64_t)i * RI_PIPE_SIZE,
			};
			w[i].in.data = data_blob_talloc(tctx,
							NULL,
							RI_PIPE_SIZE);
			torture_assert_goto(tctx, w[i].in.data.data != NULL,
					    ret, done, "data");
			memset(w[i].in.data.data, round + i,
			       RI_PIPE_SIZE);
			wreq[i] = smb2_write_send(tree, &w[i]);
			torture_assert_goto(tctx, wreq[i] != NULL,
					    ret, done, "write send");
		}
		f.in.file.handle = h;
		freq = smb2_flush_send(tree, &f);
		torture_assert_goto(tctx, freq != NULL, ret, done,
				    "flush send");
		c = (struct smb2_close) {
			.in.file.handle = h,
		};
		creq = smb2_close_send(tree, &c);
		torture_assert_goto(tctx, creq != NULL, ret, done,
				    "close send");

		for (i = 0; i < RI_PIPE_WRITES; i++) {
			status = smb2_write_recv(wreq[i], &w[i]);
			torture_assert_ntstatus_ok_goto(tctx, status,
							ret, done,
							"write");
			torture_assert_int_equal_goto(tctx,
						      w[i].out.nwritten,
						      RI_PIPE_SIZE,
						      ret, done,
						      "written");
			data_blob_free(&w[i].in.data);
		}
		status = smb2_flush_recv(freq, &f);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"flush");
		status = smb2_close_recv(creq, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"close");
		ZERO_STRUCT(h);

		status = torture_smb2_testfile(tree, fname, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"reopen");
		for (i = 0; i < RI_PIPE_WRITES; i++) {
			size_t j;

			r = (struct smb2_read) {
				.in.file.handle = h,
				.in.length = RI_PIPE_SIZE,
				.in.offset = (uint64_t)i * RI_PIPE_SIZE,
			};
			status = smb2_read(tree, tctx, &r);
			torture_assert_ntstatus_ok_goto(tctx, status,
							ret, done,
							"read back");
			torture_assert_int_equal_goto(tctx,
						      r.out.data.length,
						      RI_PIPE_SIZE,
						      ret, done,
						      "read length");
			for (j = 0; j < r.out.data.length; j++) {
				if (r.out.data.data[j] !=
				    (uint8_t)(round + i)) {
					break;
				}
			}
			torture_assert_goto(tctx,
					    j == r.out.data.length,
					    ret, done,
					    "data of a write");
			data_blob_free(&r.out.data);
		}
		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

/*
 * This test sends a FLUSH and the CLOSE of its handle without waiting.
 * The CLOSE waits for the FLUSH. Both must succeed.
 */
static bool test_ri_flush_close(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\flush_close.dat";
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20) * 5;
	struct smb2_handle h = {};
	unsigned round;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");

	for (round = 0; round < rounds; round++) {
		struct smb2_request *freq = NULL;
		struct smb2_request *creq = NULL;
		struct smb2_flush f = {};
		struct smb2_close c = {};

		status = torture_smb2_testfile(tree, fname, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create");
		status = ri_write(tree, h, round * 4096, 4096, round);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"write");

		f.in.file.handle = h;
		freq = smb2_flush_send(tree, &f);
		torture_assert_goto(tctx, freq != NULL, ret, done,
				    "flush send");
		c.in.file.handle = h;
		creq = smb2_close_send(tree, &c);
		torture_assert_goto(tctx, creq != NULL, ret, done,
				    "close send");
		status = smb2_flush_recv(freq, &f);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"flush");
		status = smb2_close_recv(creq, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"close");
		ZERO_STRUCT(h);
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

/*
 * This test sends a FLUSH and closes the connection without waiting. The
 * first connection must then open the file without sharing.
 */
static bool test_ri_flush_disconnect(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\flush_disconnect.dat";
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20);
	struct smb2_handle h = {};
	unsigned round;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");

	for (round = 0; round < rounds; round++) {
		struct smb2_tree *tree2 = NULL;
		struct smb2_handle h2 = {};
		struct smb2_flush f = {};
		struct smb2_request *freq = NULL;

		torture_assert_goto(tctx,
				    torture_smb2_connection(tctx, &tree2),
				    ret, done, "connect");
		status = torture_smb2_testfile(tree2, fname, &h2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create");
		status = ri_write(tree2, h2, 0, 256 * 1024, round);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"write");
		f.in.file.handle = h2;
		freq = smb2_flush_send(tree2, &f);
		torture_assert_goto(tctx, freq != NULL, ret, done,
				    "flush send");
		/* This closes the socket before the FLUSH reply arrives. */
		TALLOC_FREE(tree2);

		status = torture_ros_open_exclusive(tctx, tree, fname, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"exclusive open");
		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

#define RI_LEASE1 0xBEEF0001ULL
#define RI_LEASE2 0xBEEF0002ULL

/*
 * This test sends a CREATE that breaks a lease and does not acknowledge
 * the break. The server must send an interim response within 3 seconds.
 * The CREATE must succeed when the break times out. Both depend on timers
 * that the CREATE starts.
 */
static bool test_ri_lease_timeout(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\lease_timeout.dat";
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_request *req = NULL;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct timeval start;
	double t_pending;
	double t_done;
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert(tctx, caps & SMB2_CAP_LEASING, "no leases");
	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");

	smb2_lease_create(&io1, &ls1, false, fname, RI_LEASE1,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, tctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create 1");
	h1 = io1.out.file.handle;
	torture_assert_int_equal_goto(tctx,
				      io1.out.lease_response.lease_state,
				      smb2_util_lease_state("RWH"),
				      ret, done, "lease 1");

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	smb2_lease_create(&io2, &ls2, false, fname, RI_LEASE2,
			  smb2_util_lease_state("RWH"));
	start = timeval_current();
	req = smb2_create_send(tree, &io2);
	torture_assert_goto(tctx, req != NULL, ret, done, "create 2 send");

	t_pending = torture_ros_wait_pending(tctx, req, start, 10);
	torture_comment(tctx, "interim response after %.3f s\n", t_pending);
	torture_assert_goto(tctx, t_pending >= 0 && t_pending < 3,
			    ret, done, "no interim response in time");
	torture_assert_goto(tctx, req->cancel.can_cancel, ret, done,
			    "the CREATE did not go async");

	t_done = torture_ros_wait_done(tctx, req, start, RI_BREAK_TIMEOUT * 3);
	torture_comment(tctx, "CREATE done after %.3f s\n", t_done);
	torture_assert_goto(tctx,
			    t_done >= RI_BREAK_TIMEOUT - 2 &&
			    t_done <= RI_BREAK_TIMEOUT + 5,
			    ret, done,
			    "the CREATE did not end at the break timeout");
	status = smb2_create_recv(req, tctx, &io2);
	req = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create 2");
	h2 = io2.out.file.handle;
	torture_assert_int_equal_goto(tctx,
				      io2.out.lease_response.lease_state,
				      smb2_util_lease_state("RH"),
				      ret, done, "lease 2");
	torture_assert_int_equal_goto(tctx, lease_break_info.count, 1,
				      ret, done, "lease breaks");

done:
	tree->session->transport->lease.handler = NULL;
	if (req != NULL) {
		smb2_create_recv(req, tctx, &io2);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

static NTSTATUS ri_lock(struct smb2_tree *tree,
			struct smb2_handle h,
			uint32_t flags)
{
	struct smb2_lock_element el = {
		.offset = 0,
		.length = 100,
		.flags = flags,
	};
	struct smb2_lock lck = {
		.in.lock_count = 1,
		.in.file.handle = h,
		.in.locks = &el,
	};

	return smb2_lock(tree, &lck);
}

/*
 * This test checks that a blocking LOCK ([MS-SMB2] 3.3.5.14) succeeds
 * within a second after another open unlocks the range. Both opens use
 * one connection if tree2 is NULL.
 */
static bool ri_lock_wakeup(struct torture_context *tctx,
			   struct smb2_tree *tree,
			   struct smb2_tree *tree2)
{
	const char *fname = RI_DIR "\\lock_wakeup.dat";
	struct smb2_tree *t2 = (tree2 != NULL) ? tree2 : tree;
	struct smb2_lock_element el = {
		.offset = 0,
		.length = 100,
		.flags = SMB2_LOCK_FLAG_EXCLUSIVE,
	};
	struct smb2_lock lck = {};
	struct smb2_request *req = NULL;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct timeval start;
	struct timeval unlock;
	double t;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");

	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open 1");
	status = torture_smb2_testfile(t2, fname, &h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open 2");

	status = ri_lock(tree, h1,
			 SMB2_LOCK_FLAG_EXCLUSIVE |
			 SMB2_LOCK_FLAG_FAIL_IMMEDIATELY);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "lock 1");

	lck = (struct smb2_lock) {
		.in.lock_count = 1,
		.in.file.handle = h2,
		.in.locks = &el,
	};
	start = timeval_current();
	req = smb2_lock_send(t2, &lck);
	torture_assert_goto(tctx, req != NULL, ret, done, "lock 2 send");
	t = torture_ros_wait_pending(tctx, req, start, 5);
	torture_assert_goto(tctx, t >= 0 && req->cancel.can_cancel,
			    ret, done, "lock 2 did not wait");

	torture_ros_sleep(tctx, 1.0);
	torture_assert_goto(tctx, req->state <= SMB2_REQUEST_RECV,
			    ret, done, "lock 2 ended while lock 1 held");

	status = ri_lock(tree, h1, SMB2_LOCK_FLAG_UNLOCK);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "unlock 1");
	unlock = timeval_current();

	t = torture_ros_wait_done(tctx, req, unlock, 10);
	torture_comment(tctx, "lock 2 granted %.3f s after the unlock\n", t);
	torture_assert_goto(tctx, t >= 0 && t < 1.0, ret, done,
			    "lock 2 not granted at once");
	status = smb2_lock_recv(req, &lck);
	req = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "lock 2");

	status = ri_lock(t2, h2, SMB2_LOCK_FLAG_UNLOCK);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "unlock 2");

done:
	if (req != NULL) {
		smb2_cancel(req);
		smb2_lock_recv(req, &lck);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(t2, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

static bool test_ri_lock_wakeup(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	return ri_lock_wakeup(tctx, tree, NULL);
}

static bool test_ri_lock_wakeup2(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	struct smb2_tree *tree2 = NULL;
	bool ret;

	torture_assert(tctx, torture_smb2_connection(tctx, &tree2),
		       "connect 2");
	ret = ri_lock_wakeup(tctx, tree, tree2);
	TALLOC_FREE(tree2);
	return ret;
}

/*
 * This test sends a CANCEL for a waiting LOCK ([MS-SMB2] 3.3.5.14 and
 * 3.3.5.16). The LOCK must fail with NT_STATUS_CANCELLED within a second.
 */
static bool test_ri_cancel_lock(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\cancel_lock.dat";
	struct smb2_lock_element el = {
		.offset = 0,
		.length = 100,
		.flags = SMB2_LOCK_FLAG_EXCLUSIVE,
	};
	struct smb2_lock lck = {};
	struct smb2_request *req = NULL;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct timeval start;
	double t;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");

	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open 1");
	status = torture_smb2_testfile(tree, fname, &h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open 2");
	status = ri_lock(tree, h1,
			 SMB2_LOCK_FLAG_EXCLUSIVE |
			 SMB2_LOCK_FLAG_FAIL_IMMEDIATELY);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "lock 1");

	lck = (struct smb2_lock) {
		.in.lock_count = 1,
		.in.file.handle = h2,
		.in.locks = &el,
	};
	start = timeval_current();
	req = smb2_lock_send(tree, &lck);
	torture_assert_goto(tctx, req != NULL, ret, done, "lock 2 send");
	t = torture_ros_wait_pending(tctx, req, start, 5);
	torture_assert_goto(tctx, t >= 0 && req->cancel.can_cancel,
			    ret, done, "lock 2 did not wait");

	start = timeval_current();
	smb2_cancel(req);
	t = torture_ros_wait_done(tctx, req, start, 10);
	torture_comment(tctx, "cancelled after %.3f s\n", t);
	torture_assert_goto(tctx, t >= 0 && t < 1.0, ret, done,
			    "cancel not at once");
	status = smb2_lock_recv(req, &lck);
	req = NULL;
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_CANCELLED,
					   ret, done, "lock 2");

done:
	if (req != NULL) {
		smb2_lock_recv(req, &lck);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		ri_lock(tree, h1, SMB2_LOCK_FLAG_UNLOCK);
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

/*
 * This test sends a CHANGE_NOTIFY on a directory ([MS-SMB2] 3.3.5.19).
 * The same connection then creates a file in the directory. The
 * CHANGE_NOTIFY must complete within a second and name that file.
 */
static bool test_ri_notify_create(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	const char *dname = RI_DIR "\\notify";
	const char *fname = RI_DIR "\\notify\\new.dat";
	struct smb2_notify n = {};
	struct smb2_request *req = NULL;
	struct smb2_handle hd = {};
	struct smb2_handle h = {};
	struct timeval start;
	double t;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");
	status = smb2_util_mkdir(tree, dname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "mkdir");
	status = torture_smb2_testdir(tree, dname, &hd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open dir");

	n = (struct smb2_notify) {
		.in.recursive = 0,
		.in.buffer_size = 1000,
		.in.file.handle = hd,
		.in.completion_filter = FILE_NOTIFY_CHANGE_FILE_NAME,
	};
	start = timeval_current();
	req = smb2_notify_send(tree, &n);
	torture_assert_goto(tctx, req != NULL, ret, done, "notify send");
	t = torture_ros_wait_pending(tctx, req, start, 5);
	torture_assert_goto(tctx, t >= 0 && req->cancel.can_cancel,
			    ret, done, "notify did not wait");

	start = timeval_current();
	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

	t = torture_ros_wait_done(tctx, req, start, 10);
	torture_comment(tctx, "notify done %.3f s after the CREATE\n", t);
	torture_assert_goto(tctx, t >= 0 && t < 1.0, ret, done,
			    "notify not at once");
	status = smb2_notify_recv(req, tctx, &n);
	req = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "notify");
	torture_assert_goto(tctx, n.out.num_changes >= 1, ret, done,
			    "no change");
	torture_assert_int_equal_goto(tctx, n.out.changes[0].action,
				      NOTIFY_ACTION_ADDED, ret, done,
				      "action");
	torture_assert_str_equal_goto(tctx, n.out.changes[0].name.s,
				      "new.dat", ret, done, "name");

done:
	if (req != NULL) {
		smb2_cancel(req);
		smb2_notify_recv(req, tctx, &n);
	}
	if (!smb2_util_handle_empty(hd)) {
		smb2_util_close(tree, hd);
	}
	smb2_deltree(tree, RI_DIR);
	return ret;
}

/*
 * This test sends a READ on one tree connect and then a TREE_DISCONNECT of
 * a second tree connect of the same session ([MS-SMB2] 3.3.5.8). The READ
 * and a later WRITE must succeed. A FLUSH on the second tree connect must
 * fail.
 */
static bool test_ri_tdis_other(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\tdis_other.dat";
	struct smb2_tree *tree2 = NULL;
	struct smb2_request *rreq = NULL;
	struct smb2_read r = {};
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");
	torture_assert_goto(tctx,
			    torture_smb2_tree_connect(tctx,
						      tree->session,
						      tctx,
						      &tree2),
			    ret, done, "tcon 2");

	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	status = ri_write(tree, h, 0, 8192, 0x11);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	status = torture_smb2_testfile(tree2, fname, &h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open 2");

	r = (struct smb2_read) {
		.in.file.handle = h,
		.in.length = 8192,
	};
	rreq = smb2_read_send(tree, &r);
	torture_assert_goto(tctx, rreq != NULL, ret, done, "read send");
	status = smb2_tdis(tree2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "tdis 2");
	status = smb2_read_recv(rreq, tctx, &r);
	rreq = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	torture_assert_int_equal_goto(tctx, r.out.data.length, 8192,
				      ret, done, "read length");

	status = ri_write(tree, h, 8192, 8192, 0x22);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write after tdis 2");
	status = ri_flush(tree2, h2);
	torture_assert_goto(tctx, !NT_STATUS_IS_OK(status), ret, done,
			    "flush on the ended tree connect");
	ZERO_STRUCT(h2);

done:
	if (rreq != NULL) {
		smb2_read_recv(rreq, tctx, &r);
	}
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	TALLOC_FREE(tree2);
	smb2_deltree(tree, RI_DIR);
	return ret;
}

/*
 * This test sends a READ on one session and then a LOGOFF of a second
 * session on the same connection ([MS-SMB2] 3.3.5.6). The READ and a
 * later FLUSH must succeed. A FLUSH on the second session must fail with
 * NT_STATUS_USER_SESSION_DELETED.
 */
static bool test_ri_logoff_other(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	const char *fname = RI_DIR "\\logoff_other.dat";
	struct smb2_transport *transport = tree->session->transport;
	struct smb2_session *session2 = NULL;
	struct smb2_tree *tree2 = NULL;
	struct smb2_request *rreq = NULL;
	struct smb2_read r = {};
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");

	session2 = smb2_session_init(transport,
				     tctx->lp_ctx,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				     tctx);
	torture_assert(tctx, session2 != NULL, "session 2");
	status = smb2_session_setup_spnego(session2,
					   samba_cmdline_get_creds(),
					   0);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"session setup 2");
	torture_assert_goto(tctx,
			    torture_smb2_tree_connect(tctx,
						      session2,
						      tctx,
						      &tree2),
			    ret, done, "tcon 2");

	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	status = ri_write(tree, h, 0, 8192, 0x44);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	status = torture_smb2_testfile(tree2, fname, &h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open 2");

	r = (struct smb2_read) {
		.in.file.handle = h,
		.in.length = 8192,
	};
	rreq = smb2_read_send(tree, &r);
	torture_assert_goto(tctx, rreq != NULL, ret, done, "read send");
	status = smb2_logoff(session2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "logoff 2");
	status = smb2_read_recv(rreq, tctx, &r);
	rreq = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");

	status = ri_flush(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"flush after logoff 2");
	status = ri_flush(tree2, h2);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_USER_SESSION_DELETED,
					   ret, done,
					   "flush of the ended session");
	ZERO_STRUCT(h2);

done:
	if (rreq != NULL) {
		smb2_read_recv(rreq, tctx, &r);
	}
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	/*
	 * smb2_session_init() made session2 the talloc parent of the
	 * transport.
	 */
	if (session2 != NULL) {
		tree->session->transport =
			talloc_steal(tree->session, session2->transport);
	}
	TALLOC_FREE(tree2);
	TALLOC_FREE(session2);
	smb2_deltree(tree, RI_DIR);
	return ret;
}

/*
 * This test sends an ECHO with a message id that the client used before
 * ([MS-SMB2] 3.3.5.2.3). The server must close that connection. It must
 * still answer requests on new connections and on the first connection.
 */
static bool test_ri_bad_mid(struct torture_context *tctx,
			    struct smb2_tree *tree)
{
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20);
	unsigned round;
	bool ret = true;

	for (round = 0; round < rounds; round++) {
		struct smb2_tree *tree2 = NULL;
		struct smb2_transport *transport = NULL;
		struct smbXcli_conn *conn = NULL;
		NTSTATUS status;

		torture_assert(tctx, torture_smb2_connection(tctx, &tree2),
			       "connect");
		transport = tree2->session->transport;
		conn = transport->conn;

		status = smb2_keepalive(transport);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"echo");
		smb2cli_conn_set_mid(conn, smb2cli_conn_get_mid(conn) - 1);
		status = smb2_keepalive(transport);
		torture_assert_goto(tctx, !NT_STATUS_IS_OK(status),
				    ret, done, "echo with an old message id");
		torture_assert_goto(tctx, !smbXcli_conn_is_connected(conn),
				    ret, done, "connection still up");
done:
		TALLOC_FREE(tree2);
		if (!ret) {
			return false;
		}
	}

	torture_assert_ntstatus_ok(tctx,
				   smb2_keepalive(tree->session->transport),
				   "echo on the first connection");
	return true;
}

#define RI_EXISTING_SIZE (64 * 1024)

/*
 * This test sends a WRITE, a FLUSH and a READ on the existing file that
 * torture:ri_file names. The caller can set the set-user-ID bit on that
 * file and check it after the test. A write without CAP_FSETID clears the
 * bit. A write as root does not clear it.
 */
static bool test_ri_write_existing(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	const char *fname = torture_setting_string(tctx, "ri_file", NULL);
	struct smb2_create cr = {};
	struct smb2_handle h = {};
	struct smb2_read rd = {};
	NTSTATUS status;
	bool ret = true;
	size_t i;

	if (fname == NULL) {
		torture_skip(tctx, "torture:ri_file names no file\n");
	}

	cr = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
			SEC_FILE_READ_ATTRIBUTE,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = fname,
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok(tctx, status, "open of torture:ri_file");
	h = cr.out.file.handle;

	status = ri_write(tree, h, 0, RI_EXISTING_SIZE, 'w');
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	status = ri_flush(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "flush");

	rd = (struct smb2_read) {
		.in.file.handle = h,
		.in.length = RI_EXISTING_SIZE,
	};
	status = smb2_read(tree, tctx, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	torture_assert_goto(tctx, rd.out.data.length == RI_EXISTING_SIZE,
			    ret, done, "short read");
	for (i = 0; i < RI_EXISTING_SIZE; i++) {
		if (rd.out.data.data[i] != 'w') {
			break;
		}
	}
	torture_assert_goto(tctx, i == RI_EXISTING_SIZE, ret, done,
			    "data of the write");

done:
	smb2_util_close(tree, h);
	return ret;
}

static bool ri_position(struct torture_context *tctx,
			struct smb2_tree *tree,
			struct smb2_handle h,
			uint64_t want)
{
	union smb_fileinfo fi = {
		.position_information.level = RAW_FILEINFO_POSITION_INFORMATION,
		.position_information.in.file.handle = h,
	};
	NTSTATUS status;

	status = smb2_getinfo_file(tree, tctx, &fi);
	torture_assert_ntstatus_ok(tctx, status, "position");
	torture_assert_u64_equal(tctx,
				 fi.position_information.out.position,
				 want,
				 "position");
	return true;
}

/*
 * This test checks that the position of an open is the end of its last
 * READ. A reactor can run a single READ. smbd
 * runs the READs of a compound. The test sends both kinds in turn.
 */
static bool test_ri_read_position(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20);
	const char *fname = RI_DIR "\\position.dat";
	struct smb2_handle h = {};
	NTSTATUS status;
	bool ret = true;
	unsigned round;

	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");
	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok(tctx, status, "create");
	status = ri_write(tree, h, 0, 64 * 1024, 'p');
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");

	for (round = 0; round < rounds; round++) {
		struct smb2_read alone = {
			.in.file.handle = h,
			.in.offset = 1000 + round,
			.in.length = 100,
		};
		struct smb2_read first = {
			.in.file.handle = h,
			.in.offset = 5000 + round,
			.in.length = 200,
		};
		struct smb2_read second = {
			.in.file.handle = h,
			.in.offset = 9000 + round,
			.in.length = 300,
		};
		struct smb2_request *reqs[2] = {};

		status = smb2_read(tree, tctx, &alone);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"read");
		data_blob_free(&alone.out.data);

		smb2_transport_compound_start(tree->session->transport, 2);
		reqs[0] = smb2_read_send(tree, &first);
		reqs[1] = smb2_read_send(tree, &second);
		torture_assert_goto(tctx, reqs[0] != NULL && reqs[1] != NULL,
				    ret, done, "send");
		status = smb2_read_recv(reqs[0], tctx, &first);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"first read of the compound");
		status = smb2_read_recv(reqs[1], tctx, &second);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"second read of the compound");
		data_blob_free(&first.out.data);
		data_blob_free(&second.out.data);

		/* The older READ of the reactor must not set the position. */
		ret = ri_position(tctx, tree, h, 9300 + round);
		if (!ret) {
			goto done;
		}

		status = smb2_read(tree, tctx, &alone);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"read");
		data_blob_free(&alone.out.data);
		ret = ri_position(tctx, tree, h, 1100 + round);
		if (!ret) {
			goto done;
		}
	}

done:
	smb2_util_close(tree, h);
	return ret;
}

static bool ri_tree_connect(struct torture_context *tctx,
			    struct smb2_session *session,
			    const char *share,
			    struct smb2_tree **_tree)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	struct smb2_tree *t = smb2_tree_init(session, tctx, false);
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	torture_assert(tctx, unc != NULL && t != NULL, "talloc");
	subreq = smb2cli_tcon_send(
		t,
		tctx->ev,
		session->transport->conn,
		session->transport->options.request_timeout * 1000,
		session->smbXcli,
		t->smbXcli,
		0,
		unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");
	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");
	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok(tctx, status, "tree connect");
	*_tree = t;
	return true;
}

/*
 * This test checks that a tree connect expands %U at the end of the path
 * of the share that torture:ri_user_share names. An open of the user name
 * in the share root must fail with NT_STATUS_OBJECT_NAME_NOT_FOUND. If %U
 * expands to nothing, the share root is the parent directory. The open
 * then succeeds.
 */
static bool test_ri_user_share(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	const char *share = torture_setting_string(tctx, "ri_user_share", NULL);
	const char *user =
		cli_credentials_get_username(samba_cmdline_get_creds());
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20);
	unsigned round;

	if (share == NULL) {
		torture_skip(tctx, "torture:ri_user_share names no share\n");
	}

	for (round = 0; round < rounds; round++) {
		struct smb2_create cr = {
			.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.impersonation_level =
				SMB2_IMPERSONATION_IMPERSONATION,
			.in.fname = user,
		};
		struct smb2_tree *t = NULL;
		NTSTATUS status;

		/* A reactor runs the tree connect only when smbd is idle. */
		torture_ros_sleep(tctx, 0.05);
		torture_assert(tctx,
			       ri_tree_connect(tctx, tree->session, share, &t),
			       "tree connect");

		status = smb2_create(t, tctx, &cr);
		if (NT_STATUS_IS_OK(status)) {
			smb2_util_close(t, cr.out.file.handle);
		}
		smb2_tdis(t);
		TALLOC_FREE(t);
		torture_assert_ntstatus_equal(tctx,
					      status,
					      NT_STATUS_OBJECT_NAME_NOT_FOUND,
					      "the share is not the directory "
					      "of the user");
	}
	return true;
}

/*
 * This test sends a signed compound without encryption. The compound has
 * a CREATE on the tree of the test and a CREATE on the share that
 * torture:ri_enc_share names. That share has "smb encrypt = desired".
 * smbd defers the signature of the first reply. The second CREATE then
 * makes smbd encrypt the whole reply. Both CREATEs must succeed.
 */
static bool test_ri_mixed_seal(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	const char *share = torture_setting_string(tctx, "ri_enc_share", NULL);
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20);
	const char *fname1 = RI_DIR "\\mixed_seal.dat";
	const char *fname2 = "ri_mixed_seal.dat";
	struct smb2_tree *t = NULL;
	NTSTATUS status;
	bool ret = true;
	unsigned round;

	if (share == NULL) {
		torture_skip(tctx, "torture:ri_enc_share names no share\n");
	}
	torture_assert(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR), "setup");
	torture_assert(tctx,
		       ri_tree_connect(tctx, tree->session, share, &t),
		       "tree connect");
	smb2cli_tcon_should_sign(tree->smbXcli, true);
	smb2cli_tcon_should_sign(t->smbXcli, true);
	smb2cli_tcon_should_encrypt(t->smbXcli, false);

	for (round = 0; round < rounds; round++) {
		struct smb2_create cr1 = {
			.in.desired_access = SEC_RIGHTS_FILE_ALL,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
			.in.impersonation_level =
				SMB2_IMPERSONATION_IMPERSONATION,
			.in.fname = fname1,
		};
		struct smb2_create cr2 = cr1;
		struct smb2_request *reqs[2] = {};

		cr2.in.fname = fname2;
		smb2_transport_compound_start(tree->session->transport, 2);
		reqs[0] = smb2_create_send(tree, &cr1);
		reqs[1] = smb2_create_send(t, &cr2);
		torture_assert_goto(tctx, reqs[0] != NULL && reqs[1] != NULL,
				    ret, done, "send");
		status = smb2_create_recv(reqs[0], tctx, &cr1);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create on the tree of the test");
		status = smb2_create_recv(reqs[1], tctx, &cr2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create on the encrypted share");
		smb2_util_close(tree, cr1.out.file.handle);
		smb2_util_close(t, cr2.out.file.handle);
	}

done:
	smb2_util_unlink(t, fname2);
	smb2_tdis(t);
	TALLOC_FREE(t);
	smb2_deltree(tree, RI_DIR);
	return ret;
}

struct ri_break_seen {
	unsigned count;
	struct smb2_handle h;
	uint8_t level;
};

/* Record an oplock break. The test sends the acknowledgement itself. */
static bool ri_break_seen(struct smb2_transport *transport,
			  const struct smb2_handle *handle,
			  uint8_t level,
			  void *private_data)
{
	struct ri_break_seen *seen = private_data;

	seen->h = *handle;
	seen->level = level;
	seen->count += 1;
	return true;
}

/*
 * This test sends one compound with the acknowledgement of an oplock
 * break and a CHANGE_NOTIFY that waits. The acknowledgement removes the
 * break timer of smbd. The CHANGE_NOTIFY adds the timer of its interim
 * response. smbd must still send the interim response without delay.
 *
 * The compound must add no other timer. Any other new timer makes smbd
 * check its timers anyway. The smbd of a second client sends the break
 * message. In the first round, a new messaging socket to that smbd adds
 * a timer. smbd closes the socket after one idle second. Each later round
 * must therefore last less than a second.
 */
static bool test_ri_ack_notify(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	unsigned rounds = torture_setting_int(tctx, "looplimit", 5);
	const char *oname = RI_DIR "\\ack_notify.dat";
	const char *dname = RI_DIR "\\ack_notify";
	struct smb2_transport *transport = tree->session->transport;
	struct ri_break_seen seen = {};
	struct smbcli_options options;
	struct smb2_tree *tree2 = NULL;
	struct smb2_notify n = {};
	struct smb2_break br = {};
	struct smb2_create cr2 = {};
	struct smb2_request *oreq = NULL;
	struct smb2_request *breq = NULL;
	struct smb2_request *nreq = NULL;
	struct smb2_handle ho = {};
	struct smb2_handle hd = {};
	NTSTATUS status;
	bool ret = true;
	unsigned round;

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	options.client_guid = GUID_random();
	torture_assert(tctx,
		       torture_smb2_connection_ext(tctx, 0, &options, &tree2),
		       "connect of the second client");

	torture_assert_goto(tctx, smb2_util_setup_dir(tctx, tree, RI_DIR),
			    ret, done, "setup");
	status = smb2_util_mkdir(tree, dname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "mkdir");
	status = torture_smb2_testdir(tree, dname, &hd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open dir");
	transport->oplock.handler = ri_break_seen;
	transport->oplock.private_data = &seen;

	for (round = 0; round < rounds; round++) {
		struct smb2_create cr = {
			.in.desired_access = SEC_RIGHTS_FILE_ALL,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
			.in.impersonation_level =
				SMB2_IMPERSONATION_IMPERSONATION,
			.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH,
			.in.fname = oname,
		};
		struct timeval start;
		double t;

		status = smb2_create(tree, tctx, &cr);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"oplock file");
		ho = cr.out.file.handle;
		torture_assert_goto(
			tctx,
			cr.out.oplock_level == SMB2_OPLOCK_LEVEL_BATCH,
			ret, done, "no batch oplock");

		seen = (struct ri_break_seen) {};
		cr2 = cr;
		cr2.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		oreq = smb2_create_send(tree2, &cr2);
		torture_assert_goto(tctx, oreq != NULL, ret, done,
				    "create 2 send");
		start = timeval_current();
		while (seen.count == 0 && timeval_elapsed(&start) < 10) {
			torture_ros_poll(tctx);
		}
		torture_assert_goto(tctx, seen.count == 1, ret, done,
				    "no break");
		/* Let smbd wait for the acknowledgement with its timer set. */
		torture_ros_sleep(tctx, 0.1);

		br = (struct smb2_break) {
			.in.file.handle = seen.h,
			.in.oplock_level = seen.level,
		};
		n = (struct smb2_notify) {
			.in.recursive = 0,
			.in.buffer_size = 1000,
			.in.file.handle = hd,
			.in.completion_filter = FILE_NOTIFY_CHANGE_FILE_NAME,
		};
		smb2_transport_compound_start(transport, 2);
		start = timeval_current();
		breq = smb2_break_send(tree, &br);
		nreq = smb2_notify_send(tree, &n);
		torture_assert_goto(tctx, breq != NULL && nreq != NULL,
				    ret, done, "send");
		status = smb2_break_recv(breq, &br);
		breq = NULL;
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"break acknowledgement");
		t = torture_ros_wait_pending(tctx, nreq, start, 20);
		torture_comment(tctx,
				"round %u: interim response after %.3f s\n",
				round, t);
		torture_assert_goto(
			tctx,
			t >= 0 && t < 0.25 && nreq->cancel.can_cancel,
			ret, done,
			"the CHANGE_NOTIFY got no interim response at once");

		status = smb2_create_recv(oreq, tctx, &cr2);
		oreq = NULL;
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create 2");
		smb2_util_close(tree2, cr2.out.file.handle);
		smb2_cancel(nreq);
		status = smb2_notify_recv(nreq, tctx, &n);
		nreq = NULL;
		torture_assert_ntstatus_equal_goto(tctx, status,
						   NT_STATUS_CANCELLED,
						   ret, done, "notify");
		smb2_util_close(tree, ho);
		ZERO_STRUCT(ho);
	}

done:
	if (breq != NULL) {
		smb2_break_recv(breq, &br);
	}
	if (nreq != NULL) {
		smb2_cancel(nreq);
		smb2_notify_recv(nreq, tctx, &n);
	}
	if (oreq != NULL) {
		status = smb2_create_recv(oreq, tctx, &cr2);
		if (NT_STATUS_IS_OK(status)) {
			smb2_util_close(tree2, cr2.out.file.handle);
		}
	}
	transport->oplock.handler = NULL;
	transport->oplock.private_data = NULL;
	if (!smb2_util_handle_empty(hd)) {
		smb2_util_close(tree, hd);
	}
	if (!smb2_util_handle_empty(ho)) {
		smb2_util_close(tree, ho);
	}
	TALLOC_FREE(tree2);
	smb2_deltree(tree, RI_DIR);
	return ret;
}

struct torture_suite *torture_smb2_ros_inline_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "ros-inline");

	torture_suite_add_1smb2_test(suite, "flush-access",
				     test_ri_flush_access);
	torture_suite_add_1smb2_test(suite, "flush-pipeline",
				     test_ri_flush_pipeline);
	torture_suite_add_1smb2_test(suite, "flush-close",
				     test_ri_flush_close);
	torture_suite_add_1smb2_test(suite, "flush-disconnect",
				     test_ri_flush_disconnect);
	torture_suite_add_1smb2_test(suite, "lease-timeout",
				     test_ri_lease_timeout);
	torture_suite_add_1smb2_test(suite, "lock-wakeup",
				     test_ri_lock_wakeup);
	torture_suite_add_1smb2_test(suite, "lock-wakeup2",
				     test_ri_lock_wakeup2);
	torture_suite_add_1smb2_test(suite, "cancel-lock",
				     test_ri_cancel_lock);
	torture_suite_add_1smb2_test(suite, "notify-create",
				     test_ri_notify_create);
	torture_suite_add_1smb2_test(suite, "tdis-other",
				     test_ri_tdis_other);
	torture_suite_add_1smb2_test(suite, "logoff-other",
				     test_ri_logoff_other);
	torture_suite_add_1smb2_test(suite, "bad-mid", test_ri_bad_mid);
	torture_suite_add_1smb2_test(suite, "write-existing",
				     test_ri_write_existing);
	torture_suite_add_1smb2_test(suite, "read-position",
				     test_ri_read_position);
	torture_suite_add_1smb2_test(suite, "user-share", test_ri_user_share);
	torture_suite_add_1smb2_test(suite, "mixed-seal", test_ri_mixed_seal);
	torture_suite_add_1smb2_test(suite, "ack-notify", test_ri_ack_notify);
	suite->description = talloc_strdup(
		suite, "SMB2 checks for the inline reactor runs and FLUSH");
	return suite;
}
