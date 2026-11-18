/*
 * TrueNAS: abuse of the file I/O that smbd delegates to the reactors.
 *
 * With delegation, smbd builds the reply of a READ or a WRITE. A
 * truenas_ros reactor then does the file I/O. These tests send requests
 * that race with the file I/O of earlier requests. They also end
 * connections while that I/O runs. Each test expects the behaviour of
 * smbd without delegation. The suite passes against smbd with and without
 * delegation.
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
#include "librpc/ndr/libndr.h"
#include "lib/cmdline/cmdline.h"
#include "param/param.h"

#define ROS_FNAME "ros_abuse.dat"

/* Run one pass of the event loop for at most 50 ms. */
void torture_ros_poll(struct torture_context *tctx)
{
	struct tevent_req *wakeup = tevent_wakeup_send(
		tctx, tctx->ev, timeval_current_ofs_msec(50));

	tevent_loop_once(tctx->ev);
	TALLOC_FREE(wakeup);
}

/*
 * Open fname without sharing. smbd closes the files of an ended connection
 * a moment later. This function therefore retries after a sharing
 * violation for up to 10 seconds.
 */
NTSTATUS torture_ros_open_exclusive(struct torture_context *tctx,
				    struct smb2_tree *tree,
				    const char *fname,
				    struct smb2_handle *h)
{
	struct timeval start = timeval_current();
	NTSTATUS status;

	do {
		struct smb2_create io = {
			.in.fname = fname,
			.in.desired_access = SEC_RIGHTS_FILE_ALL,
			.in.share_access = 0,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.impersonation_level =
				SMB2_IMPERSONATION_IMPERSONATION,
		};

		status = smb2_create(tree, tctx, &io);
		if (NT_STATUS_IS_OK(status)) {
			*h = io.out.file.handle;
			break;
		}
		torture_ros_poll(tctx);
	} while (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION) &&
		 timeval_elapsed(&start) < 10);

	return status;
}

/* The order in which replies arrive */
struct ros_arrival {
	unsigned *count;
	unsigned pos;
};

static void ros_arrived(struct smb2_request *req)
{
	struct ros_arrival *a = req->async.private_data;

	a->pos = *a->count;
	*a->count += 1;
}

static void ros_track(struct smb2_request *req,
		      struct ros_arrival *a,
		      unsigned *count)
{
	a->count = count;
	a->pos = UINT_MAX;
	req->async.fn = ros_arrived;
	req->async.private_data = a;
}

/* Return the byte at offset ofs after a write with seed. */
static uint8_t ros_byte(uint64_t ofs, unsigned seed)
{
	return (uint8_t)((ofs * 131 + (ofs >> 11) + seed * 7 + 1) & 0xff);
}

static DATA_BLOB ros_data(TALLOC_CTX *mem_ctx,
			  uint64_t ofs,
			  size_t len,
			  unsigned seed)
{
	DATA_BLOB d = data_blob_talloc(mem_ctx, NULL, len);
	size_t i;

	if (d.data == NULL) {
		return d;
	}
	for (i = 0; i < len; i++) {
		d.data[i] = ros_byte(ofs + i, seed);
	}
	return d;
}

/* Read up to len bytes at ofs of h. At the end of the file, *out is empty. */
static bool ros_read(struct torture_context *tctx,
		     TALLOC_CTX *mem_ctx,
		     struct smb2_tree *tree,
		     struct smb2_handle h,
		     uint64_t ofs,
		     size_t len,
		     DATA_BLOB *out)
{
	struct smb2_read r = {
		.in.file.handle = h,
		.in.offset = ofs,
		.in.length = len,
	};
	NTSTATUS status;

	status = smb2_read(tree, mem_ctx, &r);
	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
		*out = data_blob_null;
		return true;
	}
	torture_assert_ntstatus_ok(tctx, status, "smb2_read");
	*out = r.out.data;
	return true;
}

/*
 * Check that the len bytes at ofs are those of a write with seed. With
 * maybe_zero, zero bytes and a short file pass too. Callers set it for a
 * write that got no success reply.
 */
static bool ros_check(struct torture_context *tctx,
		      struct smb2_tree *tree,
		      struct smb2_handle h,
		      uint64_t ofs,
		      size_t len,
		      unsigned seed,
		      bool maybe_zero)
{
	TALLOC_CTX *frame = talloc_new(tctx);
	size_t done = 0;

	/* A READ of at most 64 KiB costs one credit. */
	while (done < len) {
		size_t want_len = MIN(len - done, 65536);
		uint64_t at = ofs + done;
		DATA_BLOB d;
		size_t i;

		torture_assert(tctx,
			       ros_read(tctx, frame, tree, h, at, want_len, &d),
			       "read");
		if (d.length < want_len && !maybe_zero) {
			torture_result(tctx, TORTURE_FAIL,
				       "%zu bytes at %llu, want %zu\n",
				       d.length, (unsigned long long)at, want_len);
			TALLOC_FREE(frame);
			return false;
		}
		for (i = 0; i < d.length; i++) {
			uint8_t want = ros_byte(at + i, seed);

			if (d.data[i] == want || (maybe_zero && d.data[i] == 0)) {
				continue;
			}
			torture_result(tctx, TORTURE_FAIL,
				       "byte at %llu is 0x%02x, want 0x%02x\n",
				       (unsigned long long)(at + i), d.data[i], want);
			TALLOC_FREE(frame);
			return false;
		}
		if (d.length < want_len) {
			break;
		}
		done += want_len;
	}
	TALLOC_FREE(frame);
	return true;
}

static bool ros_open(struct torture_context *tctx,
		     struct smb2_tree *tree,
		     const char *fname,
		     uint32_t disposition,
		     uint32_t create_options,
		     struct smb2_handle *h)
{
	struct smb2_create io = {
		.in.fname = fname,
		.in.desired_access = SEC_RIGHTS_FILE_ALL,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = disposition,
		.in.create_options = create_options,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
	};
	NTSTATUS status;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok(tctx, status, "smb2_create");
	*h = io.out.file.handle;
	return true;
}

static bool ros_create(struct torture_context *tctx,
		       struct smb2_tree *tree,
		       const char *fname,
		       uint32_t create_options,
		       struct smb2_handle *h)
{
	return ros_open(tctx, tree, fname, NTCREATEX_DISP_OVERWRITE_IF,
			create_options, h);
}

/*
 * Send num WRITEs of io_size bytes. WRITE i writes at offset i * io_size.
 * If arr is not NULL, record the order of the replies in arr.
 */
static bool ros_send_writes(struct torture_context *tctx,
			    struct smb2_tree *tree,
			    struct smb2_handle h,
			    unsigned num,
			    size_t io_size,
			    unsigned seed,
			    struct smb2_write *w,
			    struct smb2_request **reqs,
			    struct ros_arrival *arr,
			    unsigned *count)
{
	unsigned i;

	for (i = 0; i < num; i++) {
		uint64_t ofs = (uint64_t)i * io_size;

		w[i] = (struct smb2_write) {
			.in.file.handle = h,
			.in.offset = ofs,
			.in.data = ros_data(w, ofs, io_size, seed),
		};
		torture_assert(tctx, w[i].in.data.data != NULL, "ros_data");
		reqs[i] = smb2_write_send(tree, &w[i]);
		torture_assert(tctx, reqs[i] != NULL, "smb2_write_send");
		if (arr != NULL) {
			ros_track(reqs[i], &arr[i], count);
		}
	}
	return true;
}

static void ros_settings(struct torture_context *tctx,
			 unsigned *num,
			 size_t *io_size,
			 unsigned *rounds)
{
	*num = torture_setting_int(tctx, "qdepth", 12);
	*io_size = torture_setting_int(tctx, "io_size", 65536);
	*rounds = torture_setting_int(tctx, "looplimit", 20);
}

/* Get the credits for num requests of io_size bytes. */
static bool ros_credits(struct torture_context *tctx,
			struct smb2_tree *tree,
			unsigned num,
			size_t io_size)
{
	return test_smb2_bench_credits(
		tctx,
		tree,
		10000,
		test_smb2_bench_min_credits(io_size, num + 4, 1));
}

/*
 * This test sends WRITEs and the CLOSE of their handle without waiting.
 * It then does the same with READs. Each CLOSE reply must arrive last.
 * The file must contain the data of each successful WRITE. With cancel,
 * the test also sends a CANCEL for each WRITE and READ. A request can then
 * also fail with NT_STATUS_CANCELLED.
 */
static bool ros_io_inflight(struct torture_context *tctx,
			    struct smb2_tree *tree,
			    bool cancel)
{
	unsigned num, rounds, round, i;
	size_t io_size;

	ros_settings(tctx, &num, &io_size, &rounds);
	torture_assert(tctx, ros_credits(tctx, tree, num, io_size), "credits");

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_read *r = talloc_zero_array(frame, struct smb2_read, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num + 1);
		struct ros_arrival *arr = talloc_zero_array(frame, struct ros_arrival, num + 1);
		bool *ok = talloc_zero_array(frame, bool, num);
		struct smb2_close cl = { .in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION };
		struct smb2_handle h;
		unsigned count = 0;
		bool all_ok = true;
		NTSTATUS status;

		torture_assert(tctx, w && r && reqs && arr && ok, "talloc");

		torture_assert(tctx, ros_create(tctx, tree, ROS_FNAME, 0, &h), "create");
		torture_assert(tctx,
			       ros_send_writes(tctx, tree, h, num, io_size, round,
					       w, reqs, arr, &count),
			       "writes");
		for (i = 0; cancel && i < num; i++) {
			(void)smb2_cancel(reqs[i]);
		}
		cl.in.file.handle = h;
		reqs[num] = smb2_close_send(tree, &cl);
		torture_assert(tctx, reqs[num] != NULL, "smb2_close_send");
		ros_track(reqs[num], &arr[num], &count);

		for (i = 0; i < num; i++) {
			status = smb2_write_recv(reqs[i], &w[i]);
			if (cancel &&
			    NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) {
				all_ok = false;
				continue;
			}
			torture_assert_ntstatus_ok(tctx, status, "write");
			torture_assert_int_equal(tctx, w[i].out.nwritten, io_size, "nwritten");
			ok[i] = true;
		}
		status = smb2_close_recv(reqs[num], &cl);
		torture_assert_ntstatus_ok(tctx, status, "close");
		torture_assert_int_equal(tctx, arr[num].pos, num,
					 "CLOSE reply before an I/O reply");
		if (all_ok) {
			torture_assert_u64_equal(tctx, cl.out.size,
						 (uint64_t)num * io_size, "size");
		}

		torture_assert(tctx,
			       ros_open(tctx, tree, ROS_FNAME, NTCREATEX_DISP_OPEN, 0, &h),
			       "open");
		for (i = 0; i < num; i++) {
			torture_assert(tctx,
				       ros_check(tctx, tree, h, (uint64_t)i * io_size,
						 io_size, round, !ok[i]),
				       "data");
		}

		count = 0;
		for (i = 0; i < num; i++) {
			r[i] = (struct smb2_read) {
				.in.file.handle = h,
				.in.offset = (uint64_t)i * io_size,
				.in.length = io_size,
				/* Without cancel, a short READ is an error. */
				.in.min_count = cancel ? 0 : io_size,
			};
			reqs[i] = smb2_read_send(tree, &r[i]);
			torture_assert(tctx, reqs[i] != NULL, "smb2_read_send");
			ros_track(reqs[i], &arr[i], &count);
			if (cancel) {
				(void)smb2_cancel(reqs[i]);
			}
		}
		cl = (struct smb2_close) { .in.file.handle = h };
		reqs[num] = smb2_close_send(tree, &cl);
		torture_assert(tctx, reqs[num] != NULL, "smb2_close_send");
		ros_track(reqs[num], &arr[num], &count);
		for (i = 0; i < num; i++) {
			uint64_t ofs = (uint64_t)i * io_size;
			size_t j;

			status = smb2_read_recv(reqs[i], frame, &r[i]);
			if ((cancel &&
			     NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) ||
			    (!ok[i] && NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE))) {
				continue;
			}
			torture_assert_ntstatus_ok(tctx, status, "read");
			if (ok[i]) {
				torture_assert_int_equal(tctx, r[i].out.data.length,
							 io_size, "read length");
			}
			for (j = 0; j < r[i].out.data.length; j++) {
				uint8_t b = r[i].out.data.data[j];

				if (b != ros_byte(ofs + j, round) && (ok[i] || b != 0)) {
					torture_fail(tctx, "read data");
				}
			}
		}
		status = smb2_close_recv(reqs[num], &cl);
		torture_assert_ntstatus_ok(tctx, status, "close");
		torture_assert_int_equal(tctx, arr[num].pos, num,
					 "CLOSE reply before an I/O reply");
		TALLOC_FREE(frame);
	}
	smb2_util_unlink(tree, ROS_FNAME);
	return true;
}

static bool test_ros_close_inflight(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	return ros_io_inflight(tctx, tree, false);
}

static bool test_ros_cancel_inflight(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	return ros_io_inflight(tctx, tree, true);
}

/*
 * This test sends WRITEs and then a TREE_DISCONNECT on a second connection
 * without waiting. With do_logoff, it sends a LOGOFF instead. The WRITEs
 * must succeed. The file must contain their data. The TREE_DISCONNECT or
 * LOGOFF reply must arrive last.
 */
static bool ros_end_inflight(struct torture_context *tctx,
			     struct smb2_tree *tree,
			     bool do_logoff)
{
	unsigned num, rounds, round, i;
	size_t io_size;

	ros_settings(tctx, &num, &io_size, &rounds);

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num + 1);
		struct ros_arrival *arr = talloc_zero_array(frame, struct ros_arrival, num + 1);
		struct smb2_tree *t = NULL;
		struct smb2_handle h;
		unsigned count = 0;
		NTSTATUS status;

		torture_assert(tctx, w && reqs && arr, "talloc");
		torture_assert(tctx, torture_smb2_connection(tctx, &t), "connection");
		torture_assert(tctx, ros_credits(tctx, t, num, io_size), "credits");

		torture_assert(tctx, ros_create(tctx, t, ROS_FNAME, 0, &h), "create");
		torture_assert(tctx,
			       ros_send_writes(tctx, t, h, num, io_size, round,
					       w, reqs, arr, &count),
			       "writes");
		if (do_logoff) {
			reqs[num] = smb2_logoff_send(t->session);
		} else {
			reqs[num] = smb2_tdis_send(t);
		}
		torture_assert(tctx, reqs[num] != NULL, "send");
		ros_track(reqs[num], &arr[num], &count);

		for (i = 0; i < num; i++) {
			status = smb2_write_recv(reqs[i], &w[i]);
			torture_assert_ntstatus_ok(tctx, status, "write");
			torture_assert_int_equal(tctx, w[i].out.nwritten, io_size, "nwritten");
		}
		if (do_logoff) {
			status = smb2_logoff_recv(reqs[num]);
		} else {
			status = smb2_tdis_recv(reqs[num]);
		}
		torture_assert_ntstatus_ok(tctx, status, do_logoff ? "logoff" : "tdis");
		torture_assert_int_equal(tctx, arr[num].pos, num,
					 "reply before an I/O reply");
		TALLOC_FREE(t);

		torture_assert(tctx,
			       ros_open(tctx, tree, ROS_FNAME, NTCREATEX_DISP_OPEN, 0, &h),
			       "open");
		for (i = 0; i < num; i++) {
			torture_assert(tctx,
				       ros_check(tctx, tree, h, (uint64_t)i * io_size,
						 io_size, round, false),
				       "data");
		}
		smb2_util_close(tree, h);
		TALLOC_FREE(frame);
	}
	smb2_util_unlink(tree, ROS_FNAME);
	return true;
}

static bool test_ros_tdis_inflight(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	return ros_end_inflight(tctx, tree, false);
}

static bool test_ros_logoff_inflight(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	return ros_end_inflight(tctx, tree, true);
}

/*
 * This test sends WRITEs on a second connection and disconnects it
 * without waiting. The first connection must then open the file without
 * sharing. Each byte must have the written value or zero.
 */
static bool test_ros_disconnect_inflight(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	unsigned num, rounds, round, i;
	size_t io_size;

	ros_settings(tctx, &num, &io_size, &rounds);

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num);
		struct smb2_tree *t = NULL;
		struct smb2_handle h;
		NTSTATUS status;

		torture_assert(tctx, w && reqs, "talloc");
		torture_assert(tctx, torture_smb2_connection(tctx, &t), "connection");
		torture_assert(tctx, ros_credits(tctx, t, num, io_size), "credits");

		torture_assert(tctx, ros_create(tctx, t, ROS_FNAME, 0, &h), "create");
		torture_assert(tctx,
			       ros_send_writes(tctx, t, h, num, io_size, round,
					       w, reqs, NULL, NULL),
			       "writes");
		/* Vary how many WRITEs reach smbd before the disconnect. */
		smb_msleep(round % 3);
		smbXcli_conn_disconnect(t->session->transport->conn,
					NT_STATUS_LOCAL_DISCONNECT);
		TALLOC_FREE(t);

		status = torture_ros_open_exclusive(tctx, tree, ROS_FNAME, &h);
		torture_assert_ntstatus_ok(tctx, status, "open after the disconnect");
		for (i = 0; i < num; i++) {
			torture_assert(tctx,
				       ros_check(tctx, tree, h,
						 (uint64_t)i * io_size, io_size,
						 round, true),
				       "data");
		}
		smb2_util_close(tree, h);
		TALLOC_FREE(frame);
	}
	smb2_util_unlink(tree, ROS_FNAME);
	return true;
}

/*
 * This test sends WRITEs to a delete-on-close handle and then its CLOSE
 * without waiting. The WRITEs must succeed. The CLOSE reply must arrive
 * last. The file must not exist after that.
 */
static bool test_ros_doc_inflight(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	unsigned num, rounds, round, i;
	size_t io_size;

	ros_settings(tctx, &num, &io_size, &rounds);
	torture_assert(tctx, ros_credits(tctx, tree, num, io_size), "credits");

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num + 1);
		struct ros_arrival *arr = talloc_zero_array(frame, struct ros_arrival, num + 1);
		struct smb2_close cl = { 0 };
		struct smb2_create io = {
			.in.fname = ROS_FNAME,
			.in.desired_access = SEC_RIGHTS_FILE_READ,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		};
		struct smb2_handle h;
		unsigned count = 0;
		NTSTATUS status;

		torture_assert(tctx, w && reqs && arr, "talloc");
		torture_assert(tctx,
			       ros_create(tctx, tree, ROS_FNAME,
					  NTCREATEX_OPTIONS_DELETE_ON_CLOSE, &h),
			       "create");
		torture_assert(tctx,
			       ros_send_writes(tctx, tree, h, num, io_size, round,
					       w, reqs, arr, &count),
			       "writes");
		cl.in.file.handle = h;
		reqs[num] = smb2_close_send(tree, &cl);
		torture_assert(tctx, reqs[num] != NULL, "smb2_close_send");
		ros_track(reqs[num], &arr[num], &count);
		for (i = 0; i < num; i++) {
			status = smb2_write_recv(reqs[i], &w[i]);
			torture_assert_ntstatus_ok(tctx, status, "write");
		}
		status = smb2_close_recv(reqs[num], &cl);
		torture_assert_ntstatus_ok(tctx, status, "close");
		torture_assert_int_equal(tctx, arr[num].pos, num,
					 "CLOSE reply before an I/O reply");

		status = smb2_create(tree, frame, &io);
		torture_assert_ntstatus_equal(tctx, status,
					      NT_STATUS_OBJECT_NAME_NOT_FOUND,
					      "delete on close");
		TALLOC_FREE(frame);
	}
	return true;
}

/*
 * This test sends WRITEs to a durable handle on a second connection and
 * disconnects it without waiting. A new connection must reconnect the
 * handle. Each byte must have the written value or zero.
 *
 * smbd records the stat of the file when the connection ends. A WRITE
 * that changes the file after that makes the reconnect fail with
 * NT_STATUS_OBJECT_NAME_NOT_FOUND. This also happens sometimes without
 * delegation. The test therefore accepts this failure in one round of ten.
 */
static bool test_ros_durable_inflight(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	unsigned num, rounds, round, i;
	unsigned lost = 0;
	size_t io_size;

	ros_settings(tctx, &num, &io_size, &rounds);

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num);
		struct GUID create_guid = GUID_random();
		struct smbcli_options options;
		struct smb2_tree *t = NULL;
		struct smb2_create io;
		struct smb2_handle h;
		NTSTATUS status;
		int tries;

		torture_assert(tctx, w && reqs, "talloc");
		torture_assert(tctx, torture_smb2_connection(tctx, &t), "connection");
		torture_assert(tctx, ros_credits(tctx, t, num, io_size), "credits");
		options = t->session->transport->options;

		smb2_util_unlink(tree, ROS_FNAME);
		smb2_oplock_create_share(&io, ROS_FNAME,
					 smb2_util_share_access("RWD"),
					 smb2_util_oplock_level("b"));
		io.in.durable_open_v2 = true;
		io.in.create_guid = create_guid;
		io.in.timeout = UINT32_MAX;
		status = smb2_create(t, frame, &io);
		torture_assert_ntstatus_ok(tctx, status, "durable create");
		if (!io.out.durable_open_v2) {
			torture_skip(tctx, "the share grants no durable handles\n");
		}
		h = io.out.file.handle;

		torture_assert(tctx,
			       ros_send_writes(tctx, t, h, num, io_size, round,
					       w, reqs, NULL, NULL),
			       "writes");
		smb_msleep(round % 3);
		smbXcli_conn_disconnect(t->session->transport->conn,
					NT_STATUS_LOCAL_DISCONNECT);
		TALLOC_FREE(t);

		torture_assert(tctx,
			       torture_smb2_connection_ext(tctx, 0, &options, &t),
			       "reconnect");
		for (tries = 0; tries < 500; tries++) {
			ZERO_STRUCT(io);
			io.in.fname = ROS_FNAME;
			io.in.durable_handle_v2 = &h;
			io.in.create_guid = create_guid;
			io.in.oplock_level = smb2_util_oplock_level("b");
			status = smb2_create(t, frame, &io);
			if (NT_STATUS_IS_OK(status)) {
				break;
			}
			smb_msleep(10);
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			lost += 1;
			TALLOC_FREE(t);
			TALLOC_FREE(frame);
			continue;
		}
		torture_assert_ntstatus_ok(tctx, status, "durable reconnect");
		h = io.out.file.handle;
		for (i = 0; i < num; i++) {
			torture_assert(tctx,
				       ros_check(tctx, t, h, (uint64_t)i * io_size,
						 io_size, round, true),
				       "data");
		}
		smb2_util_close(t, h);
		TALLOC_FREE(t);
		TALLOC_FREE(frame);
	}
	smb2_util_unlink(tree, ROS_FNAME);
	torture_comment(tctx, "durable handles lost: %u of %u\n", lost, rounds);
	torture_assert(tctx, lost * 10 <= rounds, "lost more than one handle in ten");
	return true;
}

/*
 * This test sends WRITEs of data A to offset 0 and a GETINFO with a new
 * channel sequence without waiting. It then repeats a replayed WRITE of
 * data B to offset 0 until the server accepts it. The server refuses the
 * replay with NT_STATUS_FILE_NOT_AVAILABLE while an old WRITE is
 * outstanding ([MS-SMB2] 3.3.5.2.10). The file must therefore contain data
 * B at the end.
 */
static bool test_ros_replay_order(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	struct smbXcli_conn *conn = tree->session->transport->conn;
	struct smbXcli_session *sess = tree->session->smbXcli;
	unsigned num, rounds, round, i;
	unsigned long long refused = 0;
	size_t io_size;

	if (smbXcli_conn_protocol(conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3 is needed for channel sequences\n");
	}
	ros_settings(tctx, &num, &io_size, &rounds);
	io_size = torture_setting_int(tctx, "io_size", 1048576);
	torture_assert(tctx, ros_credits(tctx, tree, num, io_size), "credits");
	smbXcli_conn_set_force_channel_sequence(conn, true);

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num);
		struct smb2_request *qreq = NULL;
		union smb_fileinfo q = {
			.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		};
		DATA_BLOB a = data_blob_talloc(frame, NULL, io_size);
		DATA_BLOB b = data_blob_talloc(frame, NULL, 65536);
		struct smb2_handle h;
		DATA_BLOB back;
		NTSTATUS status;
		int tries;

		torture_assert(tctx, w && reqs && a.data && b.data, "talloc");
		memset(a.data, 0xaa, a.length);
		memset(b.data, 0xbb, b.length);

		smb2cli_session_reset_channel_sequence(sess, 0);
		torture_assert(tctx, ros_create(tctx, tree, ROS_FNAME, 0, &h), "create");

		for (i = 0; i < num; i++) {
			w[i] = (struct smb2_write) {
				.in.file.handle = h,
				.in.offset = 0,
				.in.data = a,
			};
			reqs[i] = smb2_write_send(tree, &w[i]);
			torture_assert(tctx, reqs[i] != NULL, "smb2_write_send");
		}

		/* The new channel sequence makes the WRITEs old requests. */
		smb2cli_session_reset_channel_sequence(sess, 1);
		q.generic.in.file.handle = h;
		qreq = smb2_getinfo_file_send(tree, &q);
		torture_assert(tctx, qreq != NULL, "smb2_getinfo_file_send");

		for (tries = 0; tries < 100000; tries++) {
			struct smb2_write rw = {
				.in.file.handle = h,
				.in.offset = 0,
				.in.data = b,
			};

			smb2cli_session_start_replay(sess);
			status = smb2_write(tree, &rw);
			smb2cli_session_stop_replay(sess);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_NOT_AVAILABLE)) {
				break;
			}
			refused += 1;
		}
		torture_assert_ntstatus_ok(tctx, status, "replayed write");

		for (i = 0; i < num; i++) {
			status = smb2_write_recv(reqs[i], &w[i]);
			torture_assert_ntstatus_ok(tctx, status, "write");
		}
		status = smb2_getinfo_file_recv(qreq, frame, &q);
		torture_assert_ntstatus_ok(tctx, status, "getinfo");

		torture_assert(tctx,
			       ros_read(tctx, frame, tree, h, 0, b.length, &back),
			       "read");
		torture_assert_int_equal(tctx, back.length, b.length, "length");
		for (i = 0; i < back.length; i++) {
			if (back.data[i] != 0xbb) {
				torture_fail(tctx,
					     "an old WRITE landed after the replay\n");
			}
		}
		smb2_util_close(tree, h);
		TALLOC_FREE(frame);
	}
	smb2cli_session_reset_channel_sequence(sess, 0);
	smbXcli_conn_set_force_channel_sequence(conn, false);
	torture_comment(tctx, "replays refused while old WRITEs ran: %llu\n", refused);
	smb2_util_unlink(tree, ROS_FNAME);
	return true;
}

static bool ros_channels(struct torture_context *tctx,
			 struct smb2_tree **trees,
			 unsigned num,
			 size_t io_size)
{
	struct smbcli_options options;
	unsigned i;
	bool ok;

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	ok = test_multichannel_create_channel_array(
		tctx,
		torture_setting_string(tctx, "host", NULL),
		torture_setting_string(tctx, "share", NULL),
		samba_cmdline_get_creds(),
		&options,
		2,
		trees);
	torture_assert(tctx, ok, "channels");
	for (i = 0; i < 2; i++) {
		torture_assert(tctx, ros_credits(tctx, trees[i], num, io_size), "credits");
	}
	return true;
}

/*
 * This test binds two channels to one session. It sends WRITEs on the
 * first channel and the CLOSE on the second without waiting. A WRITE that
 * the server runs after the CLOSE fails with NT_STATUS_FILE_CLOSED. The
 * file must contain the data of the other WRITEs.
 */
static bool test_ros_mc_close(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	struct smb2_tree *trees[2] = { NULL, NULL };
	unsigned num, rounds, round, i;
	size_t io_size;

	ros_settings(tctx, &num, &io_size, &rounds);
	torture_assert(tctx, ros_channels(tctx, trees, num, io_size), "channels");

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num + 1);
		bool *ok = talloc_zero_array(frame, bool, num);
		struct smb2_close cl = { 0 };
		struct smb2_handle h;
		NTSTATUS status;

		torture_assert(tctx, w && reqs && ok, "talloc");
		torture_assert(tctx, ros_create(tctx, trees[0], ROS_FNAME, 0, &h), "create");
		torture_assert(tctx,
			       ros_send_writes(tctx, trees[0], h, num, io_size,
					       round, w, reqs, NULL, NULL),
			       "writes");
		cl.in.file.handle = h;
		reqs[num] = smb2_close_send(trees[1], &cl);
		torture_assert(tctx, reqs[num] != NULL, "smb2_close_send");
		for (i = 0; i < num; i++) {
			status = smb2_write_recv(reqs[i], &w[i]);
			if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED)) {
				continue;
			}
			torture_assert_ntstatus_ok(tctx, status, "write");
			ok[i] = true;
		}
		status = smb2_close_recv(reqs[num], &cl);
		torture_assert_ntstatus_ok(tctx, status, "close");

		torture_assert(tctx,
			       ros_open(tctx, trees[1], ROS_FNAME, NTCREATEX_DISP_OPEN, 0, &h),
			       "open");
		for (i = 0; i < num; i++) {
			torture_assert(tctx,
				       ros_check(tctx, trees[1], h, (uint64_t)i * io_size,
						 io_size, round, !ok[i]),
				       "data");
		}
		smb2_util_close(trees[1], h);
		TALLOC_FREE(frame);
	}
	smb2_util_unlink(trees[0], ROS_FNAME);
	TALLOC_FREE(trees[1]);
	TALLOC_FREE(trees[0]);
	return true;
}

/*
 * This test binds two channels to one session. It sends WRITEs on the
 * first channel and disconnects that channel without waiting. A CLOSE on
 * the second channel must succeed. Each byte must have the written value
 * or zero.
 */
static bool test_ros_mc_kill(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	unsigned num, rounds, round, i;
	size_t io_size;

	ros_settings(tctx, &num, &io_size, &rounds);

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_tree *trees[2] = { NULL, NULL };
		struct smb2_write *w = talloc_zero_array(frame, struct smb2_write, num);
		struct smb2_request **reqs = talloc_zero_array(frame, struct smb2_request *, num);
		struct smb2_close cl = { 0 };
		struct smb2_handle h;
		NTSTATUS status;

		torture_assert(tctx, w && reqs, "talloc");
		torture_assert(tctx, ros_channels(tctx, trees, num, io_size), "channels");
		torture_assert(tctx, ros_create(tctx, trees[0], ROS_FNAME, 0, &h), "create");
		torture_assert(tctx,
			       ros_send_writes(tctx, trees[0], h, num, io_size,
					       round, w, reqs, NULL, NULL),
			       "writes");
		smb_msleep(round % 3);
		smbXcli_conn_disconnect(trees[0]->session->transport->conn,
					NT_STATUS_LOCAL_DISCONNECT);

		cl.in.file.handle = h;
		status = smb2_close(trees[1], &cl);
		torture_assert_ntstatus_ok(tctx, status, "close on the other channel");

		torture_assert(tctx,
			       ros_open(tctx, trees[1], ROS_FNAME, NTCREATEX_DISP_OPEN, 0, &h),
			       "open");
		for (i = 0; i < num; i++) {
			torture_assert(tctx,
				       ros_check(tctx, trees[1], h, (uint64_t)i * io_size,
						 io_size, round, true),
				       "data");
		}
		smb2_util_close(trees[1], h);
		TALLOC_FREE(trees[0]);
		TALLOC_FREE(trees[1]);
		TALLOC_FREE(frame);
	}
	smb2_util_unlink(tree, ROS_FNAME);
	return true;
}

/*
 * This test sends READs and WRITEs at the end of the file and at the
 * limits of the offset range. It prints the status, the byte count and
 * the file position after each request in a "ros-range:" line. The caller
 * compares these lines between two servers.
 */
static bool test_ros_ranges(struct torture_context *tctx,
			    struct smb2_tree *tree)
{
	const struct {
		bool write;
		uint64_t ofs;
		uint32_t len;
		uint32_t min;
	} cases[] = {
		{ false, 0, 1, 0 },
		{ false, 0, 65536, 0 },
		{ false, 4000, 1000, 0 },
		{ false, 4000, 1000, 1000 },
		{ false, 4000, 1000, 96 },
		{ false, 4096, 1, 0 },
		{ false, 4097, 1, 0 },
		{ false, 1 << 20, 65536, 0 },
		{ false, 0, 4096, 4097 },
		{ false, 0, 10, 20 },
		{ false, 0x7fffffffffffe000ULL, 4096, 0 },
		{ false, 0x7ffffffffffff000ULL, 4096, 0 },
		{ false, 0x7fffffffffffffffULL, 1, 0 },
		{ false, 0x8000000000000000ULL, 1, 0 },
		{ false, UINT64_MAX, 1, 0 },
		{ true, 0, 1, 0 },
		{ true, 4095, 2, 0 },
		{ true, 1 << 30, 65536, 0 },
		{ true, 0x7fffffffffffe000ULL, 4096, 0 },
		{ true, 0x7ffffffffffff000ULL, 4096, 0 },
		{ true, 0x7fffffffffffffffULL, 1, 0 },
		{ true, 0x8000000000000000ULL, 1, 0 },
		{ true, UINT64_MAX - 1, 1, 0 },
		{ true, UINT64_MAX, 1, 0 },
	};
	struct smb2_handle h;
	DATA_BLOB d = data_blob_talloc_zero(tctx, 65536);
	size_t i;

	torture_assert(tctx, d.data != NULL, "talloc");
	torture_assert(tctx, ros_create(tctx, tree, ROS_FNAME, 0, &h), "create");
	torture_assert_ntstatus_ok(tctx,
				   smb2_util_write(tree, h, d.data, 0, 4096),
				   "write");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		union smb_fileinfo q = {
			.generic.level = RAW_FILEINFO_POSITION_INFORMATION,
			.generic.in.file.handle = h,
		};
		NTSTATUS status, qstatus;
		unsigned long long n = 0;

		if (cases[i].write) {
			struct smb2_write w = {
				.in.file.handle = h,
				.in.offset = cases[i].ofs,
				.in.data = data_blob_const(d.data, cases[i].len),
			};
			status = smb2_write(tree, &w);
			n = w.out.nwritten;
		} else {
			struct smb2_read r = {
				.in.file.handle = h,
				.in.offset = cases[i].ofs,
				.in.length = cases[i].len,
				.in.min_count = cases[i].min,
			};
			status = smb2_read(tree, tctx, &r);
			n = r.out.data.length;
		}
		qstatus = smb2_getinfo_file(tree, tctx, &q);
		torture_comment(tctx,
				"ros-range: %s ofs=0x%llx len=%u min=%u -> %s n=%llu"
				" pos=%s/0x%llx\n",
				cases[i].write ? "write" : "read",
				(unsigned long long)cases[i].ofs,
				cases[i].len,
				cases[i].min,
				nt_errstr(status),
				NT_STATUS_IS_OK(status) ? n : 0ULL,
				nt_errstr(qstatus),
				(unsigned long long)q.position_information.out.position);
	}
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, ROS_FNAME);
	return true;
}

/*
 * This test sends a random load. Each of torture:nprocs connections has a
 * file with 16 slots of 256 KiB. In each round, each connection sends a
 * WRITE or a READ per slot, a CANCEL for some of them, and the CLOSE
 * without waiting. A READ must return the data of earlier rounds. At the
 * end, each file must contain the data of the successful WRITEs.
 */
#define ROS_MAX_CONN 16
#define ROS_SLOTS 16
#define ROS_SLOT_SIZE (256 * 1024)

/* What the client knows about a slot */
struct ros_slot {
	/* 0 if never written, UINT_MAX if unknown after a cancelled WRITE */
	unsigned seed;
	size_t len;
};

static bool ros_storm_check(struct torture_context *tctx,
			    struct smb2_tree *tree,
			    const char *fname,
			    const struct ros_slot *model)
{
	struct smb2_handle h;
	unsigned s;

	torture_assert(tctx, ros_open(tctx, tree, fname, NTCREATEX_DISP_OPEN, 0, &h), "open");
	for (s = 0; s < ROS_SLOTS; s++) {
		if (model[s].seed == 0 || model[s].seed == UINT_MAX) {
			continue;
		}
		torture_assert(tctx,
			       ros_check(tctx, tree, h, (uint64_t)s * ROS_SLOT_SIZE,
					 model[s].len, model[s].seed, false),
			       "slot data");
	}
	smb2_util_close(tree, h);
	return true;
}

static bool test_ros_storm(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	unsigned nconn = torture_setting_int(tctx, "nprocs", 4);
	unsigned rounds = torture_setting_int(tctx, "looplimit", 50);
	struct smb2_tree *t[ROS_MAX_CONN] = { NULL };
	struct ros_slot model[ROS_MAX_CONN][ROS_SLOTS];
	const char *fname[ROS_MAX_CONN];
	unsigned round, c, s;

	torture_assert(tctx, nconn >= 1 && nconn <= ROS_MAX_CONN, "1 to 16 connections");
	srandom(torture_setting_int(tctx, "seed", 1));
	memset(model, 0, sizeof(model));

	for (c = 0; c < nconn; c++) {
		struct smb2_handle h;

		fname[c] = talloc_asprintf(tctx, "ros_storm_%u.dat", c);
		torture_assert(tctx, fname[c] != NULL, "talloc");
		torture_assert(tctx, torture_smb2_connection(tctx, &t[c]), "connection");
		torture_assert(tctx,
			       ros_credits(tctx, t[c], ROS_SLOTS, ROS_SLOT_SIZE),
			       "credits");
		torture_assert(tctx, ros_create(tctx, t[c], fname[c], 0, &h), "create");
		smb2_util_close(t[c], h);
	}

	for (round = 1; round <= rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct smb2_request *reqs[ROS_MAX_CONN][ROS_SLOTS + 1];
		struct smb2_write w[ROS_MAX_CONN][ROS_SLOTS];
		struct smb2_read r[ROS_MAX_CONN][ROS_SLOTS];
		bool is_write[ROS_MAX_CONN][ROS_SLOTS];
		struct smb2_close cl[ROS_MAX_CONN];
		struct ros_slot next[ROS_MAX_CONN][ROS_SLOTS];

		for (c = 0; c < nconn; c++) {
			struct smb2_handle h;

			torture_assert(tctx,
				       ros_open(tctx, t[c], fname[c], NTCREATEX_DISP_OPEN, 0, &h),
				       "open");
			memcpy(next[c], model[c], sizeof(next[c]));

			for (s = 0; s < ROS_SLOTS; s++) {
				uint64_t ofs = (uint64_t)s * ROS_SLOT_SIZE;

				is_write[c][s] = (random() % 2) == 0;
				if (is_write[c][s]) {
					size_t len = 1 + random() % ROS_SLOT_SIZE;

					w[c][s] = (struct smb2_write) {
						.in.file.handle = h,
						.in.offset = ofs,
						.in.data = ros_data(frame, ofs, len, round),
					};
					torture_assert(tctx, w[c][s].in.data.data != NULL, "data");
					reqs[c][s] = smb2_write_send(t[c], &w[c][s]);
				} else {
					r[c][s] = (struct smb2_read) {
						.in.file.handle = h,
						.in.offset = ofs,
						.in.length = ROS_SLOT_SIZE,
					};
					reqs[c][s] = smb2_read_send(t[c], &r[c][s]);
				}
				torture_assert(tctx, reqs[c][s] != NULL, "send");
				if (random() % 8 == 0) {
					(void)smb2_cancel(reqs[c][s]);
				}
			}
			cl[c] = (struct smb2_close) { .in.file.handle = h };
			reqs[c][ROS_SLOTS] = smb2_close_send(t[c], &cl[c]);
			torture_assert(tctx, reqs[c][ROS_SLOTS] != NULL, "close");
		}

		for (c = 0; c < nconn; c++) {
			NTSTATUS status;

			for (s = 0; s < ROS_SLOTS; s++) {
				uint64_t ofs = (uint64_t)s * ROS_SLOT_SIZE;
				size_t j;

				if (is_write[c][s]) {
					status = smb2_write_recv(reqs[c][s], &w[c][s]);
					if (NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) {
						next[c][s].seed = UINT_MAX;
						continue;
					}
					torture_assert_ntstatus_ok(tctx, status, "write");
					next[c][s].seed = round;
					next[c][s].len = w[c][s].in.data.length;
					continue;
				}
				status = smb2_read_recv(reqs[c][s], frame, &r[c][s]);
				if (NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) {
					continue;
				}
				if (model[c][s].seed == 0 &&
				    NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
					continue;
				}
				torture_assert_ntstatus_ok(tctx, status, "read");
				if (model[c][s].seed == 0 || model[c][s].seed == UINT_MAX) {
					continue;
				}
				torture_assert(tctx,
					       r[c][s].out.data.length >= model[c][s].len,
					       "short read of a written slot");
				for (j = 0; j < model[c][s].len; j++) {
					if (r[c][s].out.data.data[j] !=
					    ros_byte(ofs + j, model[c][s].seed)) {
						torture_fail(tctx, "read data");
					}
				}
			}
			status = smb2_close_recv(reqs[c][ROS_SLOTS], &cl[c]);
			torture_assert_ntstatus_ok(tctx, status, "close");
			memcpy(model[c], next[c], sizeof(next[c]));
		}
		TALLOC_FREE(frame);
	}

	for (c = 0; c < nconn; c++) {
		torture_assert(tctx, ros_storm_check(tctx, t[c], fname[c], model[c]), "final");
		smb2_util_unlink(t[c], fname[c]);
		TALLOC_FREE(t[c]);
	}
	return true;
}

/*
 * This test writes 64 KiB to the existing file ros_suid.dat and closes it.
 * The caller sets the setuid bit before the test and checks the mode after
 * it. A write with the credentials of the user clears the setuid bit.
 */
static bool test_ros_suid_write(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	struct smb2_handle h;
	DATA_BLOB d = ros_data(tctx, 0, 65536, 1);

	torture_assert(tctx, d.data != NULL, "talloc");
	torture_assert(tctx,
		       ros_open(tctx, tree, "ros_suid.dat", NTCREATEX_DISP_OPEN, 0, &h),
		       "open");
	torture_assert_ntstatus_ok(tctx,
				   smb2_util_write(tree, h, d.data, 0, d.length),
				   "write");
	torture_assert_ntstatus_ok(tctx, smb2_util_close(tree, h), "close");
	return true;
}

struct torture_suite *torture_smb2_ros_abuse_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "ros-abuse");

	torture_suite_add_1smb2_test(suite, "close-inflight", test_ros_close_inflight);
	torture_suite_add_1smb2_test(suite, "cancel-inflight", test_ros_cancel_inflight);
	torture_suite_add_1smb2_test(suite, "tdis-inflight", test_ros_tdis_inflight);
	torture_suite_add_1smb2_test(suite, "logoff-inflight", test_ros_logoff_inflight);
	torture_suite_add_1smb2_test(suite, "disconnect-inflight", test_ros_disconnect_inflight);
	torture_suite_add_1smb2_test(suite, "doc-inflight", test_ros_doc_inflight);
	torture_suite_add_1smb2_test(suite, "durable-inflight", test_ros_durable_inflight);
	torture_suite_add_1smb2_test(suite, "replay-order", test_ros_replay_order);
	torture_suite_add_1smb2_test(suite, "mc-close", test_ros_mc_close);
	torture_suite_add_1smb2_test(suite, "mc-kill", test_ros_mc_kill);
	torture_suite_add_1smb2_test(suite, "ranges", test_ros_ranges);
	torture_suite_add_1smb2_test(suite, "storm", test_ros_storm);
	torture_suite_add_1smb2_test(suite, "suid-write", test_ros_suid_write);

	suite->description = talloc_strdup(suite,
					   "Abuse of delegated file I/O");
	return suite;
}
