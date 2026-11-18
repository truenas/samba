/*
   Unix SMB/CIFS implementation.

   SMB2 bench test suite

   Copyright (C) Stefan Metzmacher 2022

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
#include "lib/param/param.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"

#include "system/filesys.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/cmdline.h"
#include "librpc/gen_ndr/security.h"
#include "lib/events/events.h"
#include "system/threads.h"

#define FNAME "test_create.dat"
#define DNAME "smb2_open"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect status %s - should be %s\n", \
			 __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	}} while (0)

#define CHECK_EQUAL(v, correct) do { \
	if (v != correct) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect value for %s 0x%08llx - " \
		        "should be 0x%08llx\n", \
			 __location__, #v, \
		        (unsigned long long)v, \
		        (unsigned long long)correct); \
		return false;					\
	}} while (0)

#define CHECK_TIME(t, field) do { \
	time_t t1, t2; \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	t1 = t & ~1; \
	t2 = nt_time_to_unix(finfo.all_info.out.field) & ~1; \
	if (abs(t1-t2) > 2) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong time for field %s  %s - %s\n", \
			__location__, #field, \
			timestring(tctx, t1), \
			timestring(tctx, t2)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_NTTIME(t, field) do { \
	NTTIME t2; \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	t2 = finfo.all_info.out.field; \
	if (llabs((int64_t)(t-t2)) > 20000) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong time for field %s  %s - %s\n", \
		       __location__, #field, \
		       nt_time_string(tctx, t), \
		       nt_time_string(tctx, t2)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_ALL_INFO(v, field) do { \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	if ((v) != (finfo.all_info.out.field)) { \
	       torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong value for field %s  0x%x - 0x%x\n", \
			__location__, #field, (int)v,\
			(int)(finfo.all_info.out.field)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong value for %s  0x%x - should be 0x%x\n", \
		       __location__, #v, (int)(v), (int)correct); \
		ret = false; \
	}} while (0)

#define SET_ATTRIB(sattrib) do { \
	union smb_setfileinfo sfinfo; \
	ZERO_STRUCT(sfinfo.basic_info.in); \
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION; \
	sfinfo.basic_info.in.file.handle = h1; \
	sfinfo.basic_info.in.attrib = sattrib; \
	status = smb2_setinfo_file(tree, &sfinfo); \
	if (!NT_STATUS_IS_OK(status)) { \
		torture_comment(tctx, \
		    "(%s) Failed to set attrib 0x%x on %s\n", \
		       __location__, (unsigned int)(sattrib), fname); \
	}} while (0)

/*
   stress testing keepalive iops
 */

struct test_smb2_bench_echo_conn;
struct test_smb2_bench_echo_loop;

struct test_smb2_bench_echo_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_echo_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_echo_loop *loops;
	size_t pending_loops;
	struct timeval starttime;
	int timecount;
	int timelimit;
	uint64_t num_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	bool ok;
	bool stop;
};

struct test_smb2_bench_echo_conn {
	struct test_smb2_bench_echo_state *state;
	int idx;
	struct smb2_tree *tree;
};

struct test_smb2_bench_echo_loop {
	struct test_smb2_bench_echo_state *state;
	struct test_smb2_bench_echo_conn *conn;
	int idx;
	struct tevent_immediate *im;
	struct tevent_req *req;
	struct timeval starttime;
	uint64_t num_started;
	uint64_t num_finished;
	uint64_t total_finished;
	uint64_t max_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	NTSTATUS error;
};

static void test_smb2_bench_echo_loop_do(
	struct test_smb2_bench_echo_loop *loop);

static void test_smb2_bench_echo_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_echo_loop *loop =
		(struct test_smb2_bench_echo_loop *)
		private_data;

	test_smb2_bench_echo_loop_do(loop);
}

static void test_smb2_bench_echo_loop_done(struct tevent_req *req);

static void test_smb2_bench_echo_loop_do(
	struct test_smb2_bench_echo_loop *loop)
{
	struct test_smb2_bench_echo_state *state = loop->state;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_echo_send(state->loops,
				      state->tctx->ev,
				      loop->conn->tree->session->transport->conn,
				      1000);
	torture_assert_goto(state->tctx, loop->req != NULL,
			    state->ok, asserted, "smb2cli_echo_send");

	tevent_req_set_callback(loop->req,
				test_smb2_bench_echo_loop_done,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_echo_loop_done(struct tevent_req *req)
{
	struct test_smb2_bench_echo_loop *loop =
		(struct test_smb2_bench_echo_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_echo_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	TALLOC_CTX *frame = talloc_stackframe();

	torture_assert_goto(state->tctx, loop->req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2cli_echo_recv(req);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->num_finished == 0) {
		/* first round */
		loop->min_latency = latency;
		loop->max_latency = latency;
	}

	loop->num_finished += 1;
	loop->total_finished += 1;
	loop->total_latency += latency;

	if (latency < loop->min_latency) {
		loop->min_latency = latency;
	}

	if (latency > loop->max_latency) {
		loop->max_latency = latency;
	}

	if (loop->total_finished >= loop->max_finished) {
		if (state->pending_loops > 0) {
			state->pending_loops -= 1;
		}
		if (state->pending_loops == 0) {
			goto asserted;
		}
	}

	TALLOC_FREE(frame);
	test_smb2_bench_echo_loop_do(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_echo_progress(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval current_time,
					  void *private_data)
{
	struct test_smb2_bench_echo_state *state =
		(struct test_smb2_bench_echo_state *)private_data;
	uint64_t num_echos = 0;
	double total_echo_latency = 0;
	double min_echo_latency = 0;
	double max_echo_latency = 0;
	double avs_echo_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_echo_loop *loop =
			&state->loops[i];

		num_echos += loop->num_finished;
		total_echo_latency += loop->total_latency;
		if (min_echo_latency == 0.0 && loop->min_latency != 0.0) {
			min_echo_latency = loop->min_latency;
		}
		if (loop->min_latency < min_echo_latency) {
			min_echo_latency = loop->min_latency;
		}
		if (max_echo_latency == 0.0) {
			max_echo_latency = loop->max_latency;
		}
		if (loop->max_latency > max_echo_latency) {
			max_echo_latency = loop->max_latency;
		}
		loop->num_finished = 0;
		loop->total_latency = 0.0;
	}

	state->num_finished += num_echos;
	state->total_latency += total_echo_latency;
	if (state->min_latency == 0.0 && min_echo_latency != 0.0) {
		state->min_latency = min_echo_latency;
	}
	if (min_echo_latency < state->min_latency) {
		state->min_latency = min_echo_latency;
	}
	if (state->max_latency == 0.0) {
		state->max_latency = max_echo_latency;
	}
	if (max_echo_latency > state->max_latency) {
		state->max_latency = max_echo_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_echo_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_echo_latency = total_echo_latency / num_echos;

		torture_comment(state->tctx,
				"%.2f second: "
				"echo[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]      \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_echos,
				avs_echo_latency,
				min_echo_latency,
				max_echo_latency);
		return;
	}

	avs_echo_latency = state->total_latency / state->num_finished;
	num_echos = state->num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"echo[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_echos,
			avs_echo_latency,
			state->min_latency,
			state->max_latency);

asserted:
	state->stop = true;
}

static bool test_smb2_bench_echo(struct torture_context *tctx,
			         struct smb2_tree *tree)
{
	struct test_smb2_bench_echo_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	size_t i;
	size_t li = 0;
	int looplimit = torture_setting_int(tctx, "looplimit", -1);
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;

	state = talloc_zero(tctx, struct test_smb2_bench_echo_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_echo_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_echo_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zu connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");

		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_echo_loop *loop = &state->loops[li];

			loop->idx = li++;
			if (looplimit != -1) {
				loop->max_finished = looplimit;
			} else {
				loop->max_finished = UINT64_MAX;
			}
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_echo_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_echo_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();
	state->pending_loops = state->num_loops;

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_echo_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	return ret;
}

/*
   stress testing path base operations
   e.g. contention on lockting.tdb records
 */

struct test_smb2_bench_path_contention_shared_conn;
struct test_smb2_bench_path_contention_shared_loop;

struct test_smb2_bench_path_contention_shared_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_path_contention_shared_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_path_contention_shared_loop *loops;
	struct timeval starttime;
	int timecount;
	int timelimit;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} opens;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} closes;
	bool ok;
	bool stop;
};

struct test_smb2_bench_path_contention_shared_conn {
	struct test_smb2_bench_path_contention_shared_state *state;
	int idx;
	struct smb2_tree *tree;
};

struct test_smb2_bench_path_contention_shared_loop {
	struct test_smb2_bench_path_contention_shared_state *state;
	struct test_smb2_bench_path_contention_shared_conn *conn;
	int idx;
	struct tevent_immediate *im;
	struct {
		struct smb2_create io;
		struct smb2_request *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} opens;
	struct {
		struct smb2_close io;
		struct smb2_request *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} closes;
	NTSTATUS error;
};

static void test_smb2_bench_path_contention_loop_open(
	struct test_smb2_bench_path_contention_shared_loop *loop);

static void test_smb2_bench_path_contention_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_path_contention_shared_loop *loop =
		(struct test_smb2_bench_path_contention_shared_loop *)
		private_data;

	test_smb2_bench_path_contention_loop_open(loop);
}

static void test_smb2_bench_path_contention_loop_opened(struct smb2_request *req);

static void test_smb2_bench_path_contention_loop_open(
	struct test_smb2_bench_path_contention_shared_loop *loop)
{
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;

	loop->opens.num_started += 1;
	loop->opens.starttime = timeval_current();
	loop->opens.req = smb2_create_send(loop->conn->tree, &loop->opens.io);
	torture_assert_goto(state->tctx, loop->opens.req != NULL,
			    state->ok, asserted, "smb2_create_send");

	loop->opens.req->async.fn = test_smb2_bench_path_contention_loop_opened;
	loop->opens.req->async.private_data = loop;
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_path_contention_loop_close(
	struct test_smb2_bench_path_contention_shared_loop *loop);

static void test_smb2_bench_path_contention_loop_opened(struct smb2_request *req)
{
	struct test_smb2_bench_path_contention_shared_loop *loop =
		(struct test_smb2_bench_path_contention_shared_loop *)
		req->async.private_data;
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->opens.starttime);
	TALLOC_CTX *frame = talloc_stackframe();

	torture_assert_goto(state->tctx, loop->opens.req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2_create_recv(req, frame, &loop->opens.io);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	ZERO_STRUCT(loop->opens.io.out.blobs);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->opens.num_finished == 0) {
		/* first round */
		loop->opens.min_latency = latency;
		loop->opens.max_latency = latency;
	}

	loop->opens.num_finished += 1;
	loop->opens.total_latency += latency;

	if (latency < loop->opens.min_latency) {
		loop->opens.min_latency = latency;
	}

	if (latency > loop->opens.max_latency) {
		loop->opens.max_latency = latency;
	}

	TALLOC_FREE(frame);
	test_smb2_bench_path_contention_loop_close(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_path_contention_loop_closed(struct smb2_request *req);

static void test_smb2_bench_path_contention_loop_close(
	struct test_smb2_bench_path_contention_shared_loop *loop)
{
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;

	loop->closes.num_started += 1;
	loop->closes.starttime = timeval_current();
	loop->closes.io.in.file = loop->opens.io.out.file;
	loop->closes.req = smb2_close_send(loop->conn->tree, &loop->closes.io);
	torture_assert_goto(state->tctx, loop->closes.req != NULL,
			    state->ok, asserted, "smb2_close_send");

	loop->closes.req->async.fn = test_smb2_bench_path_contention_loop_closed;
	loop->closes.req->async.private_data = loop;
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_path_contention_loop_closed(struct smb2_request *req)
{
	struct test_smb2_bench_path_contention_shared_loop *loop =
		(struct test_smb2_bench_path_contention_shared_loop *)
		req->async.private_data;
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->closes.starttime);

	torture_assert_goto(state->tctx, loop->closes.req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2_close_recv(req, &loop->closes.io);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);
	if (loop->closes.num_finished == 0) {
		/* first round */
		loop->closes.min_latency = latency;
		loop->closes.max_latency = latency;
	}
	loop->closes.num_finished += 1;

	loop->closes.total_latency += latency;

	if (latency < loop->closes.min_latency) {
		loop->closes.min_latency = latency;
	}

	if (latency > loop->closes.max_latency) {
		loop->closes.max_latency = latency;
	}

	test_smb2_bench_path_contention_loop_open(loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_path_contention_progress(struct tevent_context *ev,
						     struct tevent_timer *te,
						     struct timeval current_time,
						     void *private_data)
{
	struct test_smb2_bench_path_contention_shared_state *state =
		(struct test_smb2_bench_path_contention_shared_state *)private_data;
	uint64_t num_opens = 0;
	double total_open_latency = 0;
	double min_open_latency = 0;
	double max_open_latency = 0;
	double avs_open_latency = 0;
	uint64_t num_closes = 0;
	double total_close_latency = 0;
	double min_close_latency = 0;
	double max_close_latency = 0;
	double avs_close_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_path_contention_shared_loop *loop =
			&state->loops[i];

		num_opens += loop->opens.num_finished;
		total_open_latency += loop->opens.total_latency;
		if (min_open_latency == 0.0 && loop->opens.min_latency != 0.0) {
			min_open_latency = loop->opens.min_latency;
		}
		if (loop->opens.min_latency < min_open_latency) {
			min_open_latency = loop->opens.min_latency;
		}
		if (max_open_latency == 0.0) {
			max_open_latency = loop->opens.max_latency;
		}
		if (loop->opens.max_latency > max_open_latency) {
			max_open_latency = loop->opens.max_latency;
		}
		loop->opens.num_finished = 0;
		loop->opens.total_latency = 0.0;

		num_closes += loop->closes.num_finished;
		total_close_latency += loop->closes.total_latency;
		if (min_close_latency == 0.0 && loop->closes.min_latency != 0.0) {
			min_close_latency = loop->closes.min_latency;
		}
		if (loop->closes.min_latency < min_close_latency) {
			min_close_latency = loop->closes.min_latency;
		}
		if (max_close_latency == 0.0) {
			max_close_latency = loop->closes.max_latency;
		}
		if (loop->closes.max_latency > max_close_latency) {
			max_close_latency = loop->closes.max_latency;
		}
		loop->closes.num_finished = 0;
		loop->closes.total_latency = 0.0;
	}

	state->opens.num_finished += num_opens;
	state->opens.total_latency += total_open_latency;
	if (state->opens.min_latency == 0.0 && min_open_latency != 0.0) {
		state->opens.min_latency = min_open_latency;
	}
	if (min_open_latency < state->opens.min_latency) {
		state->opens.min_latency = min_open_latency;
	}
	if (state->opens.max_latency == 0.0) {
		state->opens.max_latency = max_open_latency;
	}
	if (max_open_latency > state->opens.max_latency) {
		state->opens.max_latency = max_open_latency;
	}

	state->closes.num_finished += num_closes;
	state->closes.total_latency += total_close_latency;
	if (state->closes.min_latency == 0.0 && min_close_latency != 0.0) {
		state->closes.min_latency = min_close_latency;
	}
	if (min_close_latency < state->closes.min_latency) {
		state->closes.min_latency = min_close_latency;
	}
	if (state->closes.max_latency == 0.0) {
		state->closes.max_latency = max_close_latency;
	}
	if (max_close_latency > state->closes.max_latency) {
		state->closes.max_latency = max_close_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_path_contention_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_open_latency = total_open_latency / num_opens;
		avs_close_latency = total_close_latency / num_closes;

		torture_comment(state->tctx,
				"%.2f second: "
				"open[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
				"close[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]     \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_opens,
				avs_open_latency,
				min_open_latency,
				max_open_latency,
				(unsigned long long)num_closes,
				avs_close_latency,
				min_close_latency,
				max_close_latency);
		return;
	}

	avs_open_latency = state->opens.total_latency / state->opens.num_finished;
	avs_close_latency = state->closes.total_latency / state->closes.num_finished;
	num_opens = state->opens.num_finished / state->timelimit;
	num_closes = state->closes.num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"open[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
			"close[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_opens,
			avs_open_latency,
			state->opens.min_latency,
			state->opens.max_latency,
			(unsigned long long)num_closes,
			avs_close_latency,
			state->closes.min_latency,
			state->closes.max_latency);

asserted:
	state->stop = true;
}

bool test_smb2_bench_path_contention_shared(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct test_smb2_bench_path_contention_shared_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	size_t i;
	size_t li = 0;
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	const char *path = torture_setting_string(tctx, "bench_path", "");
	struct smb2_create open_io = { .level = RAW_OPEN_SMB2, };
	struct smb2_close close_io = { .level = RAW_CLOSE_SMB2, };
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;

	state = talloc_zero(tctx, struct test_smb2_bench_path_contention_shared_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_path_contention_shared_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_path_contention_shared_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);

	open_io.in.desired_access = SEC_DIR_READ_ATTRIBUTE;
	open_io.in.alloc_size = 0;
	open_io.in.file_attributes = 0;
	open_io.in.share_access = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
	open_io.in.create_disposition = FILE_OPEN;
	open_io.in.create_options = FILE_OPEN_REPARSE_POINT;
	open_io.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	open_io.in.security_flags = 0;
	open_io.in.fname = path;
	open_io.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	open_io.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zd connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");
		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_path_contention_shared_loop *loop = &state->loops[li];

			loop->idx = li++;
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);
			loop->opens.io = open_io;
			loop->closes.io = close_io;
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_path_contention_shared_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_path_contention_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_path_contention_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	return ret;
}

/*
 * torture:threads=yes runs the loops of each channel on a separate thread
 * with its own tevent context. A single client thread for all channels is
 * busy all the time with a fast server. It then does not read some
 * channels for seconds.
 *
 * While a thread runs, only that thread uses the transport, the tree and
 * the loops of its channel. The threads share the session. All channels
 * encrypt with the keys and the nonce counter of the session. The threads
 * can race on that counter. The test therefore refuses encryption. The
 * run ends at torture:timelimit or when every loop reaches
 * torture:looplimit. Only requests that finish before the end count.
 */
#define BENCH_THREAD_TICK_MSEC 100

struct test_smb2_bench_thread {
	struct tevent_context *ev;
	struct tevent_timer *tick;
	pthread_t id;
	bool *stop;
	void **loops;
	size_t num_loops;
	void (*loop_start)(void *loop);
	bool (*loop_busy)(void *loop);
	int error;
};

static bool test_smb2_bench_stopped(bool *stop)
{
	return __atomic_load_n(stop, __ATOMIC_ACQUIRE);
}

static void test_smb2_bench_stop(bool *stop)
{
	__atomic_store_n(stop, true, __ATOMIC_RELEASE);
}

/* A loop calls this at torture:looplimit. The run ends when all loops did. */
static void test_smb2_bench_loop_limit(size_t *pending)
{
	__atomic_sub_fetch(pending, 1, __ATOMIC_ACQ_REL);
}

/*
 * A thread with no pending request waits in tevent_loop_once(). This
 * timer wakes the thread. The thread then checks the stop flag.
 */
static void test_smb2_bench_thread_tick(struct tevent_context *ev,
					struct tevent_timer *te,
					struct timeval current_time,
					void *private_data)
{
	struct test_smb2_bench_thread *t =
		(struct test_smb2_bench_thread *)private_data;

	t->tick = tevent_add_timer(ev,
				   t,
				   timeval_current_ofs_msec(BENCH_THREAD_TICK_MSEC),
				   test_smb2_bench_thread_tick,
				   t);
	if (t->tick == NULL) {
		t->error = ENOMEM;
		test_smb2_bench_stop(t->stop);
	}
}

static bool test_smb2_bench_thread_busy(struct test_smb2_bench_thread *t)
{
	size_t i;

	for (i = 0; i < t->num_loops; i++) {
		if (t->loop_busy(t->loops[i])) {
			return true;
		}
	}
	return false;
}

static void *test_smb2_bench_thread_main(void *private_data)
{
	struct test_smb2_bench_thread *t =
		(struct test_smb2_bench_thread *)private_data;
	sigset_t set;
	size_t i;

	/* The main thread of smbtorture handles the signals. */
	sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	test_smb2_bench_thread_tick(t->ev, NULL, timeval_zero(), t);

	for (i = 0; i < t->num_loops; i++) {
		t->loop_start(t->loops[i]);
	}

	while (!test_smb2_bench_stopped(t->stop) ||
	       test_smb2_bench_thread_busy(t))
	{
		if (tevent_loop_once(t->ev) != 0) {
			t->error = errno;
			test_smb2_bench_stop(t->stop);
			break;
		}
	}

	TALLOC_FREE(t->tick);
	return NULL;
}

static struct test_smb2_bench_thread *test_smb2_bench_thread_create(
	TALLOC_CTX *mem_ctx,
	bool *stop,
	size_t max_loops,
	void (*loop_start)(void *loop),
	bool (*loop_busy)(void *loop))
{
	struct test_smb2_bench_thread *t = NULL;

	t = talloc_zero(mem_ctx, struct test_smb2_bench_thread);
	if (t == NULL) {
		return NULL;
	}
	t->ev = tevent_context_init(t);
	if (t->ev == NULL) {
		TALLOC_FREE(t);
		return NULL;
	}
	t->loops = talloc_zero_array(t, void *, max_loops);
	if (t->loops == NULL) {
		TALLOC_FREE(t);
		return NULL;
	}
	t->stop = stop;
	t->loop_start = loop_start;
	t->loop_busy = loop_busy;
	return t;
}

/*
 * Make the transport of a channel tree usable from a thread. The request
 * that waits for oplock and lease breaks reads the transport on tctx->ev.
 * This function frees that request. The loops request no oplocks or
 * leases.
 */
static bool test_smb2_bench_thread_prepare(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	struct smb2_transport *transport = tree->session->transport;

	torture_assert(tctx,
		       !smb2cli_tcon_is_encryption_on(tree->smbXcli),
		       "torture:threads does not support encryption");

	transport->oplock.handler = NULL;
	transport->lease.handler = NULL;
	TALLOC_FREE(transport->break_subreq);

	torture_assert(tctx,
		       !smbXcli_conn_has_async_calls(transport->conn),
		       "a request is pending on the transport");
	return true;
}

/*
 * Run the threads until the time limit, or until each loop reaches its
 * limit. Then wait for the pending requests. This sets *elapsed to the run
 * time without that wait.
 */
static bool test_smb2_bench_threads_run(struct torture_context *tctx,
					struct test_smb2_bench_thread **threads,
					size_t num_threads,
					bool *stop,
					size_t *pending_loops,
					int timelimit,
					double *elapsed)
{
	struct timeval start = timeval_current();
	size_t started = 0;
	bool ok = true;
	size_t i;

	for (i = 0; i < num_threads; i++) {
		int rc = pthread_create(&threads[i]->id,
					NULL,
					test_smb2_bench_thread_main,
					threads[i]);
		if (rc != 0) {
			torture_comment(tctx,
					"pthread_create: %s\n",
					strerror(rc));
			ok = false;
			break;
		}
		started += 1;
	}

	while (ok &&
	       !test_smb2_bench_stopped(stop) &&
	       __atomic_load_n(pending_loops, __ATOMIC_ACQUIRE) > 0 &&
	       timeval_elapsed(&start) < timelimit)
	{
		smb_msleep(10);
	}

	*elapsed = timeval_elapsed(&start);
	test_smb2_bench_stop(stop);

	for (i = 0; i < started; i++) {
		pthread_join(threads[i]->id, NULL);
	}

	for (i = 0; i < started; i++) {
		torture_assert_int_equal(tctx,
					 threads[i]->error,
					 0,
					 "tevent_loop_once in a thread");
	}

	return ok;
}

/*
   stress testing read iops
 */

struct test_smb2_bench_read_conn;
struct test_smb2_bench_read_loop;

struct test_smb2_bench_read_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_read_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_read_loop *loops;
	size_t pending_loops;
	uint32_t io_size;
	/* Size of the shared file with torture:single_file, or 0 */
	uint64_t file_size;
	struct timeval starttime;
	int timecount;
	int timelimit;
	uint64_t num_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	bool ok;
	bool stop;
	/* torture:threads */
	bool thread_stop;
	size_t thread_pending;
};

struct test_smb2_bench_read_conn {
	struct test_smb2_bench_read_state *state;
	int idx;
	struct smb2_tree *tree;
	struct smb2_tree **trees;
	size_t num_trees;
};

struct test_smb2_bench_read_loop {
	struct test_smb2_bench_read_state *state;
	struct test_smb2_bench_read_conn *conn;
	struct test_smb2_bench_thread *thread;
	struct smb2_tree *tree;
	int idx;
	struct tevent_immediate *im;
	char *fname;
	struct smb2_handle handle;
	/* Next offset and step per request with torture:single_file */
	uint64_t offset;
	uint64_t stride;
	struct tevent_req *req;
	struct timeval starttime;
	uint64_t num_started;
	uint64_t num_finished;
	uint64_t total_finished;
	uint64_t max_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	NTSTATUS error;
};

static void test_smb2_bench_read_loop_do(
	struct test_smb2_bench_read_loop *loop);

static void test_smb2_bench_read_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_read_loop *loop =
		(struct test_smb2_bench_read_loop *)
		private_data;

	test_smb2_bench_read_loop_do(loop);
}

static void test_smb2_bench_read_loop_done(struct tevent_req *req);

static void test_smb2_bench_read_loop_do(
	struct test_smb2_bench_read_loop *loop)
{
	struct test_smb2_bench_read_state *state = loop->state;
	uint32_t timeout_msec;

	timeout_msec = loop->tree->session->transport->options.request_timeout * 1000;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_read_send(state->loops,
				      state->tctx->ev,
				      loop->tree->session->transport->conn,
				      timeout_msec,
				      loop->tree->session->smbXcli,
				      loop->tree->smbXcli,
				      state->io_size, /* length */
				      loop->offset,   /* offset */
				      loop->handle.data[0],/* fid_persistent */
				      loop->handle.data[1],/* fid_volatile */
				      state->io_size, /* minimum_count */
				      0);              /* remaining_bytes */
	torture_assert_goto(state->tctx, loop->req != NULL,
			    state->ok, asserted, "smb2cli_read_send");
	if (loop->stride != 0) {
		loop->offset = (loop->offset + loop->stride) % state->file_size;
	}

	tevent_req_set_callback(loop->req,
				test_smb2_bench_read_loop_done,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_read_loop_done(struct tevent_req *req)
{
	struct test_smb2_bench_read_loop *loop =
		(struct test_smb2_bench_read_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_read_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	TALLOC_CTX *frame = talloc_stackframe();
	uint8_t *data = NULL;
	uint32_t data_length = 0;

	torture_assert_goto(state->tctx, loop->req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2cli_read_recv(req, frame, &data, &data_length);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	torture_assert_u32_equal_goto(state->tctx, data_length, state->io_size,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->num_finished == 0) {
		/* first round */
		loop->min_latency = latency;
		loop->max_latency = latency;
	}

	loop->num_finished += 1;
	loop->total_finished += 1;
	loop->total_latency += latency;

	if (latency < loop->min_latency) {
		loop->min_latency = latency;
	}

	if (latency > loop->max_latency) {
		loop->max_latency = latency;
	}

	if (loop->total_finished >= loop->max_finished) {
		if (state->pending_loops > 0) {
			state->pending_loops -= 1;
		}
		if (state->pending_loops == 0) {
			goto asserted;
		}
	}

	TALLOC_FREE(frame);
	test_smb2_bench_read_loop_do(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_read_progress(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval current_time,
					  void *private_data)
{
	struct test_smb2_bench_read_state *state =
		(struct test_smb2_bench_read_state *)private_data;
	uint64_t num_reads = 0;
	double total_read_latency = 0;
	double min_read_latency = 0;
	double max_read_latency = 0;
	double avs_read_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_read_loop *loop =
			&state->loops[i];

		num_reads += loop->num_finished;
		total_read_latency += loop->total_latency;
		if (min_read_latency == 0.0 && loop->min_latency != 0.0) {
			min_read_latency = loop->min_latency;
		}
		if (loop->min_latency < min_read_latency) {
			min_read_latency = loop->min_latency;
		}
		if (max_read_latency == 0.0) {
			max_read_latency = loop->max_latency;
		}
		if (loop->max_latency > max_read_latency) {
			max_read_latency = loop->max_latency;
		}
		loop->num_finished = 0;
		loop->total_latency = 0.0;
	}

	state->num_finished += num_reads;
	state->total_latency += total_read_latency;
	if (state->min_latency == 0.0 && min_read_latency != 0.0) {
		state->min_latency = min_read_latency;
	}
	if (min_read_latency < state->min_latency) {
		state->min_latency = min_read_latency;
	}
	if (state->max_latency == 0.0) {
		state->max_latency = max_read_latency;
	}
	if (max_read_latency > state->max_latency) {
		state->max_latency = max_read_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_read_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_read_latency = total_read_latency / num_reads;

		torture_comment(state->tctx,
				"%.2f second: "
				"read[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]      \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_reads,
				(unsigned long long)num_reads*state->io_size,
				avs_read_latency,
				min_read_latency,
				max_read_latency);
		return;
	}

	avs_read_latency = state->total_latency / state->num_finished;
	num_reads = state->num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"read[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_reads,
			(unsigned long long)num_reads*state->io_size,
			avs_read_latency,
			state->min_latency,
			state->max_latency);

asserted:
	state->stop = true;
}

/*
 * torture:channels binds this number of channels to the session of each
 * connection. The loops of a connection send their I/O round robin over
 * the channels, like a multichannel client.
 */
static bool test_smb2_bench_channels(struct torture_context *tctx,
				     TALLOC_CTX *mem_ctx,
				     int num_channels,
				     struct smb2_tree ***_trees)
{
	struct smbcli_options options;
	struct smb2_tree **trees = NULL;
	bool ok;

	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	trees = talloc_zero_array(mem_ctx, struct smb2_tree *, num_channels);
	torture_assert(tctx, trees != NULL, __location__);

	ok = test_multichannel_create_channel_array(
		tctx,
		torture_setting_string(tctx, "host", NULL),
		torture_setting_string(tctx, "share", NULL),
		samba_cmdline_get_creds(),
		&options,
		num_channels,
		trees);
	torture_assert(tctx, ok, "test_multichannel_create_channel_array");

	*_trees = trees;
	return true;
}

/*
 * Ask the server for credits on the transport of a tree until the
 * transport has min_credits. The server grants only some credits with
 * each response. A new channel has few credits.
 */
bool test_smb2_bench_credits(struct torture_context *tctx,
			     struct smb2_tree *ct,
			     uint32_t timeout_msec,
			     uint16_t min_credits)
{
	struct smbXcli_conn *conn = ct->session->transport->conn;
	size_t i;

	smb2cli_conn_set_max_credits(conn, 8192);

	for (i = 0; i < 1000; i++) {
		struct tevent_req *subreq = NULL;

		/*
		 * The transport of a channel has a pending request for
		 * oplock breaks. The synchronous smb2cli_ioctl() fails with
		 * NT_STATUS_INVALID_PARAMETER_MIX in that case.
		 */
		subreq = smb2cli_ioctl_send(tctx,
					    tctx->ev,
					    conn,
					    timeout_msec,
					    ct->session->smbXcli,
					    ct->smbXcli,
					    UINT64_MAX, /* in_fid_persistent */
					    UINT64_MAX, /* in_fid_volatile */
					    UINT32_MAX,
					    0, /* in_max_input_length */
					    NULL, /* in_input_buffer */
					    1, /* in_max_output_length */
					    NULL, /* in_output_buffer */
					    SMB2_IOCTL_FLAG_IS_FSCTL);
		torture_assert(tctx, subreq != NULL, "smb2cli_ioctl_send");
		torture_assert(tctx,
			       tevent_req_poll(subreq, tctx->ev),
			       "tevent_req_poll");
		(void)smb2cli_ioctl_recv(subreq, tctx, NULL, NULL);
		TALLOC_FREE(subreq);
		torture_assert(tctx,
			       smbXcli_conn_is_connected(conn),
			       "smbXcli_conn_is_connected");
		if (smb2cli_conn_get_cur_credits(conn) >= min_credits) {
			break;
		}
	}
	return true;
}

/* Return the credits that the loops of one channel need. */
uint16_t test_smb2_bench_min_credits(uint32_t io_size,
				     int qdepth,
				     size_t num_trees)
{
	size_t per_io = (io_size + 65535) / 65536;
	size_t loops = (qdepth + num_trees - 1) / num_trees;

	return MIN(per_io * loops + 1, 8192);
}

/*
 * With torture:single_file, the loops of a connection share one file of
 * torture:file_size bytes. Loop n starts at offset n * io_size. It adds
 * qdepth * io_size to its offset per request. Together the loops access
 * the file in order, like one large transfer of a multichannel client.
 * With fill, test_smb2_bench_single_file() first writes the whole file.
 * The READs then do not read holes.
 */
static uint64_t test_smb2_bench_file_size(struct torture_context *tctx,
					  uint32_t io_size,
					  int qdepth)
{
	uint64_t size;

	if (!torture_setting_bool(tctx, "single_file", false)) {
		return 0;
	}
	size = (uint64_t)torture_setting_int(tctx, "file_size", 1024 * 1024 * 1024);
	size -= size % io_size;
	return MAX(size, (uint64_t)io_size * MAX(qdepth, 1));
}

static bool test_smb2_bench_single_file(struct torture_context *tctx,
					struct smb2_tree *tree,
					const char *fname,
					uint64_t file_size,
					uint32_t io_size,
					bool fill,
					struct smb2_handle *handle)
{
	struct smb2_create cr = {
		.in.create_flags = NTCREATEX_FLAGS_EXTENDED,
		.in.alloc_size = file_size,
		.in.desired_access = SEC_RIGHTS_FILE_ALL,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_NONE,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE |
				     NTCREATEX_OPTIONS_NON_DIRECTORY_FILE,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};
	union smb_setfileinfo sfinfo = {
		.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION,
		.end_of_file_info.in.size = file_size,
	};
	NTSTATUS status;
	uint8_t *buf = NULL;
	uint64_t ofs;

	status = smb2_create(tree, tctx, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	*handle = cr.out.file.handle;

	sfinfo.end_of_file_info.in.file.handle = *handle;
	status = smb2_setinfo_file(tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!fill) {
		return true;
	}
	buf = talloc_array(tctx, uint8_t, io_size);
	torture_assert(tctx, buf != NULL, __location__);
	memset(buf, 0x5a, io_size);
	for (ofs = 0; ofs < file_size; ofs += io_size) {
		status = smb2_util_write(tree, *handle, buf, ofs, io_size);
		CHECK_STATUS(status, NT_STATUS_OK);
	}
	TALLOC_FREE(buf);
	return true;
}

static void test_smb2_bench_read_tloop_do(
	struct test_smb2_bench_read_loop *loop);

/* The torture:threads version of test_smb2_bench_read_loop_done() */
static void test_smb2_bench_read_tloop_done(struct tevent_req *req)
{
	struct test_smb2_bench_read_loop *loop =
		(struct test_smb2_bench_read_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_read_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	TALLOC_CTX *frame = talloc_stackframe();
	uint8_t *data = NULL;
	uint32_t data_length = 0;
	NTSTATUS status;

	status = smb2cli_read_recv(req, frame, &data, &data_length);
	TALLOC_FREE(loop->req);
	TALLOC_FREE(frame);
	if (NT_STATUS_IS_OK(status) && data_length != state->io_size) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (!NT_STATUS_IS_OK(status)) {
		loop->error = status;
		test_smb2_bench_stop(&state->thread_stop);
		return;
	}
	if (test_smb2_bench_stopped(&state->thread_stop)) {
		/* The request finished after the end of the run. */
		return;
	}

	if (loop->total_finished == 0) {
		loop->min_latency = latency;
		loop->max_latency = latency;
	}
	loop->total_finished += 1;
	loop->total_latency += latency;
	loop->min_latency = MIN(loop->min_latency, latency);
	loop->max_latency = MAX(loop->max_latency, latency);

	if (loop->total_finished >= loop->max_finished) {
		test_smb2_bench_loop_limit(&state->thread_pending);
		return;
	}

	test_smb2_bench_read_tloop_do(loop);
}

static void test_smb2_bench_read_tloop_do(
	struct test_smb2_bench_read_loop *loop)
{
	struct test_smb2_bench_read_state *state = loop->state;
	uint32_t timeout_msec;

	timeout_msec = loop->tree->session->transport->options.request_timeout * 1000;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_read_send(loop->thread,
				      loop->thread->ev,
				      loop->tree->session->transport->conn,
				      timeout_msec,
				      loop->tree->session->smbXcli,
				      loop->tree->smbXcli,
				      state->io_size, /* length */
				      loop->offset,   /* offset */
				      loop->handle.data[0],/* fid_persistent */
				      loop->handle.data[1],/* fid_volatile */
				      state->io_size, /* minimum_count */
				      0);              /* remaining_bytes */
	if (loop->req == NULL) {
		loop->error = NT_STATUS_NO_MEMORY;
		test_smb2_bench_stop(&state->thread_stop);
		return;
	}
	if (loop->stride != 0) {
		loop->offset = (loop->offset + loop->stride) % state->file_size;
	}

	tevent_req_set_callback(loop->req,
				test_smb2_bench_read_tloop_done,
				loop);
}

static void test_smb2_bench_read_tloop_start(void *loop)
{
	test_smb2_bench_read_tloop_do(
		(struct test_smb2_bench_read_loop *)loop);
}

static bool test_smb2_bench_read_tloop_busy(void *loop)
{
	return ((struct test_smb2_bench_read_loop *)loop)->req != NULL;
}

/* Run the read loops with torture:threads and print the result. */
static bool test_smb2_bench_read_threads(
	struct torture_context *tctx,
	struct test_smb2_bench_read_state *state)
{
	struct test_smb2_bench_thread **threads = NULL;
	size_t num_threads = 0;
	uint64_t num_reads = 0;
	double total_latency = 0;
	double min_latency = 0;
	double max_latency = 0;
	double elapsed = 0;
	size_t i;
	size_t li;
	bool ok;

	for (i = 0; i < state->num_conns; i++) {
		num_threads += state->conns[i].num_trees;
	}
	threads = talloc_zero_array(state,
				    struct test_smb2_bench_thread *,
				    num_threads);
	torture_assert(tctx, threads != NULL, __location__);

	num_threads = 0;
	for (i = 0; i < state->num_conns; i++) {
		struct test_smb2_bench_read_conn *conn = &state->conns[i];
		size_t c;

		for (c = 0; c < conn->num_trees; c++) {
			struct test_smb2_bench_thread *t = NULL;

			if (!test_smb2_bench_thread_prepare(tctx,
							    conn->trees[c])) {
				return false;
			}
			t = test_smb2_bench_thread_create(
				threads,
				&state->thread_stop,
				state->num_loops,
				test_smb2_bench_read_tloop_start,
				test_smb2_bench_read_tloop_busy);
			torture_assert(tctx, t != NULL, __location__);

			for (li = 0; li < state->num_loops; li++) {
				struct test_smb2_bench_read_loop *loop =
					&state->loops[li];

				if (loop->conn != conn ||
				    loop->tree != conn->trees[c]) {
					continue;
				}
				loop->thread = t;
				t->loops[t->num_loops++] = loop;
			}
			threads[num_threads++] = t;
		}
	}
	state->thread_pending = state->num_loops;

	torture_comment(tctx, "Running for %d seconds on %zu threads\n",
			state->timelimit, num_threads);

	ok = test_smb2_bench_threads_run(tctx,
					 threads,
					 num_threads,
					 &state->thread_stop,
					 &state->thread_pending,
					 state->timelimit,
					 &elapsed);
	torture_assert(tctx, ok, "test_smb2_bench_threads_run");

	for (li = 0; li < state->num_loops; li++) {
		struct test_smb2_bench_read_loop *loop = &state->loops[li];

		torture_assert_ntstatus_ok(tctx, loop->error,
					   "read on a thread");
		if (loop->total_finished == 0) {
			continue;
		}
		num_reads += loop->total_finished;
		total_latency += loop->total_latency;
		if (min_latency == 0.0 || loop->min_latency < min_latency) {
			min_latency = loop->min_latency;
		}
		max_latency = MAX(max_latency, loop->max_latency);
	}

	torture_comment(tctx,
			"%.2f second: "
			"read[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			elapsed,
			(unsigned long long)(num_reads / elapsed),
			(unsigned long long)(num_reads * (double)state->io_size / elapsed),
			num_reads > 0 ? total_latency / num_reads : 0.0,
			min_latency,
			max_latency);
	return true;
}

static bool test_smb2_bench_read(struct torture_context *tctx,
			         struct smb2_tree *tree)
{
	struct test_smb2_bench_read_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	int torture_io_size = torture_setting_int(tctx, "io_size", 4096);
	int torture_channels = torture_setting_int(tctx, "channels", 1);
	bool torture_threads = torture_setting_bool(tctx, "threads", false);
	size_t i;
	size_t li = 0;
	int looplimit = torture_setting_int(tctx, "looplimit", -1);
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;
	const char *dname = "bench_read_dir";
	const char *unique = generate_random_str(tctx, 8);
	struct smb2_handle dh;
	NTSTATUS status;

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, dname, &dh);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, dh);
	CHECK_STATUS(status, NT_STATUS_OK);

	state = talloc_zero(tctx, struct test_smb2_bench_read_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_read_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_read_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);
	state->io_size = MAX(torture_io_size, 1);
	state->io_size = MIN(state->io_size, 16*1024*1024);
	state->file_size = test_smb2_bench_file_size(tctx, state->io_size,
						     torture_qdepth);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zu connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		size_t pcli;
		size_t c;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (torture_channels > 1) {
			if (!test_smb2_bench_channels(tctx,
						      state->conns,
						      torture_channels,
						      &state->conns[i].trees)) {
				return false;
			}
			state->conns[i].num_trees = torture_channels;
			state->conns[i].tree = ct = state->conns[i].trees[0];
		} else if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}
		if (state->conns[i].trees == NULL) {
			state->conns[i].trees = &state->conns[i].tree;
			state->conns[i].num_trees = 1;
		}

		for (c = 0; c < state->conns[i].num_trees; c++) {
			if (!test_smb2_bench_credits(tctx,
						     state->conns[i].trees[c],
						     timeout_msec,
						     test_smb2_bench_min_credits(
							state->io_size,
							torture_qdepth,
							state->conns[i].num_trees))) {
				return false;
			}
		}

		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_read_loop *loop = &state->loops[li];
			struct smb2_create cr;
			union smb_setfileinfo sfinfo;

			loop->tree = state->conns[i].trees[
					pcli % state->conns[i].num_trees];
			loop->idx = li++;
			if (looplimit != -1) {
				loop->max_finished = looplimit;
			} else {
				loop->max_finished = UINT64_MAX;
			}
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);

			loop->fname = talloc_asprintf(state->loops,
						"%s\\%s_loop_%zu_conn_%zu_loop_%zu.dat",
						dname, unique, li, i, pcli);
			torture_assert(tctx, loop->fname != NULL, __location__);

			if (state->file_size != 0) {
				loop->offset = pcli * state->io_size;
				loop->stride = (uint64_t)torture_qdepth * state->io_size;
				if (pcli > 0) {
					/* Use the handle of the first loop. */
					loop->handle = state->loops[li - 1 - pcli].handle;
					continue;
				}
				if (!test_smb2_bench_single_file(tctx,
								 state->conns[i].tree,
								 loop->fname,
								 state->file_size,
								 state->io_size,
								 true,
								 &loop->handle)) {
					return false;
				}
				continue;
			}

			/* reasonable default parameters */
			ZERO_STRUCT(cr);
			cr.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
			cr.in.alloc_size = state->io_size;
			cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
			cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
			cr.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
			cr.in.create_disposition = NTCREATEX_DISP_CREATE;
			cr.in.create_options =
				NTCREATEX_OPTIONS_DELETE_ON_CLOSE |
				NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
			cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
			cr.in.security_flags = 0;
			cr.in.fname = loop->fname;
			status = smb2_create(state->conns[i].tree, tctx, &cr);
			CHECK_STATUS(status, NT_STATUS_OK);
			loop->handle = cr.out.file.handle;

			ZERO_STRUCT(sfinfo);
			sfinfo.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
			sfinfo.end_of_file_info.in.file.handle = loop->handle;
			sfinfo.end_of_file_info.in.size = state->io_size;
			status = smb2_setinfo_file(state->conns[i].tree, &sfinfo);
			CHECK_STATUS(status, NT_STATUS_OK);
		}
	}

	if (torture_threads) {
		torture_comment(tctx, "Opened %zu connections with channels=%d qdepth=%d => %zu loops\n",
				state->num_conns, torture_channels, torture_qdepth,
				state->num_loops);
		ret = test_smb2_bench_read_threads(tctx, state);
		TALLOC_FREE(state);
		smb2_deltree(tree, dname);
		return ret;
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_read_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_read_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with channels=%d qdepth=%d => %zu loops\n",
			state->num_conns, torture_channels, torture_qdepth,
			state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();
	state->pending_loops = state->num_loops;

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_read_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	smb2_deltree(tree, dname);
	return ret;
}

/*
   stress testing write iops
 */

struct test_smb2_bench_write_conn;
struct test_smb2_bench_write_loop;

struct test_smb2_bench_write_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_write_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_write_loop *loops;
	size_t pending_loops;
	uint32_t io_size;
	/* Size of the shared file with torture:single_file, or 0 */
	uint64_t file_size;
	uint8_t *data_buffer;
	struct timeval starttime;
	int timecount;
	int timelimit;
	uint64_t num_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	bool ok;
	bool stop;
	/* torture:threads */
	bool thread_stop;
	size_t thread_pending;
};

struct test_smb2_bench_write_conn {
	struct test_smb2_bench_write_state *state;
	int idx;
	struct smb2_tree *tree;
	struct smb2_tree **trees;
	size_t num_trees;
};

struct test_smb2_bench_write_loop {
	struct test_smb2_bench_write_state *state;
	struct test_smb2_bench_write_conn *conn;
	struct test_smb2_bench_thread *thread;
	struct smb2_tree *tree;
	int idx;
	struct tevent_immediate *im;
	char *fname;
	struct smb2_handle handle;
	/* Next offset and step per request with torture:single_file */
	uint64_t offset;
	uint64_t stride;
	struct tevent_req *req;
	struct timeval starttime;
	uint64_t num_started;
	uint64_t num_finished;
	uint64_t total_finished;
	uint64_t max_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	NTSTATUS error;
};

static void test_smb2_bench_write_loop_do(
	struct test_smb2_bench_write_loop *loop);

static void test_smb2_bench_write_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_write_loop *loop =
		(struct test_smb2_bench_write_loop *)
		private_data;

	test_smb2_bench_write_loop_do(loop);
}

static void test_smb2_bench_write_loop_done(struct tevent_req *req);

static void test_smb2_bench_write_loop_do(
	struct test_smb2_bench_write_loop *loop)
{
	struct test_smb2_bench_write_state *state = loop->state;
	uint32_t timeout_msec;

	timeout_msec = loop->tree->session->transport->options.request_timeout * 1000;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_write_send(state->loops,
				       state->tctx->ev,
				       loop->tree->session->transport->conn,
				       timeout_msec,
				       loop->tree->session->smbXcli,
				       loop->tree->smbXcli,
				       state->io_size, /* length */
				       loop->offset,   /* offset */
				       loop->handle.data[0],/* fid_persistent */
				       loop->handle.data[1],/* fid_volatile */
				       0,              /* remaining_bytes */
				       0,              /* flags */
				       state->data_buffer);
	torture_assert_goto(state->tctx, loop->req != NULL,
			    state->ok, asserted, "smb2cli_write_send");
	if (loop->stride != 0) {
		loop->offset = (loop->offset + loop->stride) % state->file_size;
	}

	tevent_req_set_callback(loop->req,
				test_smb2_bench_write_loop_done,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_write_loop_done(struct tevent_req *req)
{
	struct test_smb2_bench_write_loop *loop =
		(struct test_smb2_bench_write_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_write_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	uint32_t data_length = 0;

	torture_assert_goto(state->tctx, loop->req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2cli_write_recv(req, &data_length);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	torture_assert_u32_equal_goto(state->tctx, data_length, state->io_size,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->num_finished == 0) {
		/* first round */
		loop->min_latency = latency;
		loop->max_latency = latency;
	}

	loop->num_finished += 1;
	loop->total_finished += 1;
	loop->total_latency += latency;

	if (latency < loop->min_latency) {
		loop->min_latency = latency;
	}

	if (latency > loop->max_latency) {
		loop->max_latency = latency;
	}

	if (loop->total_finished >= loop->max_finished) {
		if (state->pending_loops > 0) {
			state->pending_loops -= 1;
		}
		if (state->pending_loops == 0) {
			goto asserted;
		}
	}

	test_smb2_bench_write_loop_do(loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_write_progress(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval current_time,
					  void *private_data)
{
	struct test_smb2_bench_write_state *state =
		(struct test_smb2_bench_write_state *)private_data;
	uint64_t num_writes = 0;
	double total_write_latency = 0;
	double min_write_latency = 0;
	double max_write_latency = 0;
	double avs_write_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_write_loop *loop =
			&state->loops[i];

		num_writes += loop->num_finished;
		total_write_latency += loop->total_latency;
		if (min_write_latency == 0.0 && loop->min_latency != 0.0) {
			min_write_latency = loop->min_latency;
		}
		if (loop->min_latency < min_write_latency) {
			min_write_latency = loop->min_latency;
		}
		if (max_write_latency == 0.0) {
			max_write_latency = loop->max_latency;
		}
		if (loop->max_latency > max_write_latency) {
			max_write_latency = loop->max_latency;
		}
		loop->num_finished = 0;
		loop->total_latency = 0.0;
	}

	state->num_finished += num_writes;
	state->total_latency += total_write_latency;
	if (state->min_latency == 0.0 && min_write_latency != 0.0) {
		state->min_latency = min_write_latency;
	}
	if (min_write_latency < state->min_latency) {
		state->min_latency = min_write_latency;
	}
	if (state->max_latency == 0.0) {
		state->max_latency = max_write_latency;
	}
	if (max_write_latency > state->max_latency) {
		state->max_latency = max_write_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_write_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_write_latency = total_write_latency / num_writes;

		torture_comment(state->tctx,
				"%.2f second: "
				"write[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]      \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_writes,
				(unsigned long long)num_writes*state->io_size,
				avs_write_latency,
				min_write_latency,
				max_write_latency);
		return;
	}

	avs_write_latency = state->total_latency / state->num_finished;
	num_writes = state->num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"write[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_writes,
			(unsigned long long)num_writes*state->io_size,
			avs_write_latency,
			state->min_latency,
			state->max_latency);

asserted:
	state->stop = true;
}

static void test_smb2_bench_write_tloop_do(
	struct test_smb2_bench_write_loop *loop);

/* The torture:threads version of test_smb2_bench_write_loop_done() */
static void test_smb2_bench_write_tloop_done(struct tevent_req *req)
{
	struct test_smb2_bench_write_loop *loop =
		(struct test_smb2_bench_write_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_write_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	uint32_t data_length = 0;
	NTSTATUS status;

	status = smb2cli_write_recv(req, &data_length);
	TALLOC_FREE(loop->req);
	if (NT_STATUS_IS_OK(status) && data_length != state->io_size) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (!NT_STATUS_IS_OK(status)) {
		loop->error = status;
		test_smb2_bench_stop(&state->thread_stop);
		return;
	}
	if (test_smb2_bench_stopped(&state->thread_stop)) {
		/* The request finished after the end of the run. */
		return;
	}

	if (loop->total_finished == 0) {
		loop->min_latency = latency;
		loop->max_latency = latency;
	}
	loop->total_finished += 1;
	loop->total_latency += latency;
	loop->min_latency = MIN(loop->min_latency, latency);
	loop->max_latency = MAX(loop->max_latency, latency);

	if (loop->total_finished >= loop->max_finished) {
		test_smb2_bench_loop_limit(&state->thread_pending);
		return;
	}

	test_smb2_bench_write_tloop_do(loop);
}

static void test_smb2_bench_write_tloop_do(
	struct test_smb2_bench_write_loop *loop)
{
	struct test_smb2_bench_write_state *state = loop->state;
	uint32_t timeout_msec;

	timeout_msec = loop->tree->session->transport->options.request_timeout * 1000;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_write_send(loop->thread,
				       loop->thread->ev,
				       loop->tree->session->transport->conn,
				       timeout_msec,
				       loop->tree->session->smbXcli,
				       loop->tree->smbXcli,
				       state->io_size, /* length */
				       loop->offset,   /* offset */
				       loop->handle.data[0],/* fid_persistent */
				       loop->handle.data[1],/* fid_volatile */
				       0,              /* remaining_bytes */
				       0,              /* flags */
				       state->data_buffer);
	if (loop->req == NULL) {
		loop->error = NT_STATUS_NO_MEMORY;
		test_smb2_bench_stop(&state->thread_stop);
		return;
	}
	if (loop->stride != 0) {
		loop->offset = (loop->offset + loop->stride) % state->file_size;
	}

	tevent_req_set_callback(loop->req,
				test_smb2_bench_write_tloop_done,
				loop);
}

static void test_smb2_bench_write_tloop_start(void *loop)
{
	test_smb2_bench_write_tloop_do(
		(struct test_smb2_bench_write_loop *)loop);
}

static bool test_smb2_bench_write_tloop_busy(void *loop)
{
	return ((struct test_smb2_bench_write_loop *)loop)->req != NULL;
}

/* Run the write loops with torture:threads and print the result. */
static bool test_smb2_bench_write_threads(
	struct torture_context *tctx,
	struct test_smb2_bench_write_state *state)
{
	struct test_smb2_bench_thread **threads = NULL;
	size_t num_threads = 0;
	uint64_t num_writes = 0;
	double total_latency = 0;
	double min_latency = 0;
	double max_latency = 0;
	double elapsed = 0;
	size_t i;
	size_t li;
	bool ok;

	for (i = 0; i < state->num_conns; i++) {
		num_threads += state->conns[i].num_trees;
	}
	threads = talloc_zero_array(state,
				    struct test_smb2_bench_thread *,
				    num_threads);
	torture_assert(tctx, threads != NULL, __location__);

	num_threads = 0;
	for (i = 0; i < state->num_conns; i++) {
		struct test_smb2_bench_write_conn *conn = &state->conns[i];
		size_t c;

		for (c = 0; c < conn->num_trees; c++) {
			struct test_smb2_bench_thread *t = NULL;

			if (!test_smb2_bench_thread_prepare(tctx,
							    conn->trees[c])) {
				return false;
			}
			t = test_smb2_bench_thread_create(
				threads,
				&state->thread_stop,
				state->num_loops,
				test_smb2_bench_write_tloop_start,
				test_smb2_bench_write_tloop_busy);
			torture_assert(tctx, t != NULL, __location__);

			for (li = 0; li < state->num_loops; li++) {
				struct test_smb2_bench_write_loop *loop =
					&state->loops[li];

				if (loop->conn != conn ||
				    loop->tree != conn->trees[c]) {
					continue;
				}
				loop->thread = t;
				t->loops[t->num_loops++] = loop;
			}
			threads[num_threads++] = t;
		}
	}
	state->thread_pending = state->num_loops;

	torture_comment(tctx, "Running for %d seconds on %zu threads\n",
			state->timelimit, num_threads);

	ok = test_smb2_bench_threads_run(tctx,
					 threads,
					 num_threads,
					 &state->thread_stop,
					 &state->thread_pending,
					 state->timelimit,
					 &elapsed);
	torture_assert(tctx, ok, "test_smb2_bench_threads_run");

	for (li = 0; li < state->num_loops; li++) {
		struct test_smb2_bench_write_loop *loop = &state->loops[li];

		torture_assert_ntstatus_ok(tctx, loop->error,
					   "write on a thread");
		if (loop->total_finished == 0) {
			continue;
		}
		num_writes += loop->total_finished;
		total_latency += loop->total_latency;
		if (min_latency == 0.0 || loop->min_latency < min_latency) {
			min_latency = loop->min_latency;
		}
		max_latency = MAX(max_latency, loop->max_latency);
	}

	torture_comment(tctx,
			"%.2f second: "
			"write[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			elapsed,
			(unsigned long long)(num_writes / elapsed),
			(unsigned long long)(num_writes * (double)state->io_size / elapsed),
			num_writes > 0 ? total_latency / num_writes : 0.0,
			min_latency,
			max_latency);
	return true;
}

static bool test_smb2_bench_write(struct torture_context *tctx,
			         struct smb2_tree *tree)
{
	struct test_smb2_bench_write_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	int torture_io_size = torture_setting_int(tctx, "io_size", 4096);
	int torture_channels = torture_setting_int(tctx, "channels", 1);
	bool torture_threads = torture_setting_bool(tctx, "threads", false);
	size_t i;
	size_t li = 0;
	int looplimit = torture_setting_int(tctx, "looplimit", -1);
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;
	const char *dname = "bench_write_dir";
	const char *unique = generate_random_str(tctx, 8);
	struct smb2_handle dh;
	NTSTATUS status;

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, dname, &dh);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, dh);
	CHECK_STATUS(status, NT_STATUS_OK);

	state = talloc_zero(tctx, struct test_smb2_bench_write_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_write_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_write_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);
	state->io_size = MAX(torture_io_size, 1);
	state->io_size = MIN(state->io_size, 16*1024*1024);
	state->file_size = test_smb2_bench_file_size(tctx, state->io_size,
						     torture_qdepth);
	state->data_buffer = talloc_zero_array(state, uint8_t, state->io_size);
	torture_assert(tctx, state->data_buffer != NULL, __location__);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zu connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		size_t pcli;
		size_t c;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (torture_channels > 1) {
			if (!test_smb2_bench_channels(tctx,
						      state->conns,
						      torture_channels,
						      &state->conns[i].trees)) {
				return false;
			}
			state->conns[i].num_trees = torture_channels;
			state->conns[i].tree = ct = state->conns[i].trees[0];
		} else if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}
		if (state->conns[i].trees == NULL) {
			state->conns[i].trees = &state->conns[i].tree;
			state->conns[i].num_trees = 1;
		}

		for (c = 0; c < state->conns[i].num_trees; c++) {
			if (!test_smb2_bench_credits(tctx,
						     state->conns[i].trees[c],
						     timeout_msec,
						     test_smb2_bench_min_credits(
							state->io_size,
							torture_qdepth,
							state->conns[i].num_trees))) {
				return false;
			}
		}

		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_write_loop *loop = &state->loops[li];
			struct smb2_create cr;
			union smb_setfileinfo sfinfo;

			loop->tree = state->conns[i].trees[
					pcli % state->conns[i].num_trees];
			loop->idx = li++;
			if (looplimit != -1) {
				loop->max_finished = looplimit;
			} else {
				loop->max_finished = UINT64_MAX;
			}
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);

			loop->fname = talloc_asprintf(state->loops,
						"%s\\%s_loop_%zu_conn_%zu_loop_%zu.dat",
						dname, unique, li, i, pcli);
			torture_assert(tctx, loop->fname != NULL, __location__);

			if (state->file_size != 0) {
				loop->offset = pcli * state->io_size;
				loop->stride = (uint64_t)torture_qdepth * state->io_size;
				if (pcli > 0) {
					/* Use the handle of the first loop. */
					loop->handle = state->loops[li - 1 - pcli].handle;
					continue;
				}
				if (!test_smb2_bench_single_file(tctx,
								 state->conns[i].tree,
								 loop->fname,
								 state->file_size,
								 state->io_size,
								 false,
								 &loop->handle)) {
					return false;
				}
				continue;
			}

			/* reasonable default parameters */
			ZERO_STRUCT(cr);
			cr.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
			cr.in.alloc_size = state->io_size;
			cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
			cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
			cr.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
			cr.in.create_disposition = NTCREATEX_DISP_CREATE;
			cr.in.create_options =
				NTCREATEX_OPTIONS_DELETE_ON_CLOSE |
				NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
			cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
			cr.in.security_flags = 0;
			cr.in.fname = loop->fname;
			status = smb2_create(state->conns[i].tree, tctx, &cr);
			CHECK_STATUS(status, NT_STATUS_OK);
			loop->handle = cr.out.file.handle;

			ZERO_STRUCT(sfinfo);
			sfinfo.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
			sfinfo.end_of_file_info.in.file.handle = loop->handle;
			sfinfo.end_of_file_info.in.size = state->io_size;
			status = smb2_setinfo_file(state->conns[i].tree, &sfinfo);
			CHECK_STATUS(status, NT_STATUS_OK);
		}
	}

	if (torture_threads) {
		torture_comment(tctx, "Opened %zu connections with channels=%d qdepth=%d => %zu loops\n",
				state->num_conns, torture_channels, torture_qdepth,
				state->num_loops);
		ret = test_smb2_bench_write_threads(tctx, state);
		TALLOC_FREE(state);
		smb2_deltree(tree, dname);
		return ret;
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_write_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_write_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with channels=%d qdepth=%d => %zu loops\n",
			state->num_conns, torture_channels, torture_qdepth,
			state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();
	state->pending_loops = state->num_loops;

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_write_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	smb2_deltree(tree, dname);
	return ret;
}

/*
   stress testing session setups
 */

struct test_smb2_bench_session_setup_shared_conn;
struct test_smb2_bench_session_setup_shared_loop;

struct test_smb2_bench_session_setup_shared_state {
	struct torture_context *tctx;
	struct cli_credentials *credentials;
	struct gensec_settings *gensec_settings;
	size_t num_conns;
	struct test_smb2_bench_session_setup_shared_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_session_setup_shared_loop *loops;
	struct timeval starttime;
	int timecount;
	int timelimit;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} setups;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} logoffs;
	bool ok;
	bool stop;
};

struct test_smb2_bench_session_setup_shared_conn {
	struct test_smb2_bench_session_setup_shared_state *state;
	int idx;
	struct smb2_transport *transport;
};

struct test_smb2_bench_session_setup_shared_loop {
	struct test_smb2_bench_session_setup_shared_state *state;
	struct test_smb2_bench_session_setup_shared_conn *conn;
	int idx;
	struct smb2_session *session;
	struct tevent_immediate *im;
	struct {
		struct tevent_req *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} setups;
	struct {
		struct smb2_request *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} logoffs;
	NTSTATUS error;
};

static void test_smb2_bench_session_setup_loop_do_setup(
	struct test_smb2_bench_session_setup_shared_loop *loop);

static void test_smb2_bench_session_setup_loop_start(struct tevent_context *ctx,
						     struct tevent_immediate *im,
						     void *private_data)
{
	struct test_smb2_bench_session_setup_shared_loop *loop =
		(struct test_smb2_bench_session_setup_shared_loop *)
		private_data;

	test_smb2_bench_session_setup_loop_do_setup(loop);
}

static void test_smb2_bench_session_setup_loop_done_setup(struct tevent_req *subreq);

static void test_smb2_bench_session_setup_loop_do_setup(
	struct test_smb2_bench_session_setup_shared_loop *loop)
{
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;

	loop->session = smb2_session_init(loop->conn->transport,
					  state->tctx->lp_ctx,
					  state->gensec_settings,
					  loop->conn->transport);
	torture_assert_goto(state->tctx, loop->session != NULL,
			    state->ok, asserted, "smb2_session_init");
	talloc_steal(state->conns, loop->conn->transport);

	loop->setups.num_started += 1;
	loop->setups.starttime = timeval_current();
	loop->setups.req = smb2_session_setup_spnego_send(loop->session,
							  state->tctx->ev,
							  loop->session,
							  state->credentials,
							  0); /* previous_session_id */
	torture_assert_goto(state->tctx, loop->setups.req != NULL,
			    state->ok, asserted,
			    "smb2_session_setup_spnego_send");

	tevent_req_set_callback(loop->setups.req,
				test_smb2_bench_session_setup_loop_done_setup,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_session_setup_loop_do_logoff(
	struct test_smb2_bench_session_setup_shared_loop *loop);

static void test_smb2_bench_session_setup_loop_done_setup(struct tevent_req *subreq)
{
	struct test_smb2_bench_session_setup_shared_loop *loop =
		(struct test_smb2_bench_session_setup_shared_loop *)
		tevent_req_callback_data_void(subreq);
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->setups.starttime);
	TALLOC_CTX *frame = talloc_stackframe();

	torture_assert_goto(state->tctx, loop->setups.req == subreq,
			    state->ok, asserted, __location__);
	loop->setups.req = NULL;
	loop->error = smb2_session_setup_spnego_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->setups.num_finished == 0) {
		/* first round */
		loop->setups.min_latency = latency;
		loop->setups.max_latency = latency;
	}

	loop->setups.num_finished += 1;
	loop->setups.total_latency += latency;

	if (latency < loop->setups.min_latency) {
		loop->setups.min_latency = latency;
	}

	if (latency > loop->setups.max_latency) {
		loop->setups.max_latency = latency;
	}

	TALLOC_FREE(frame);
	test_smb2_bench_session_setup_loop_do_logoff(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_session_setup_loop_done_logoff(struct smb2_request *req);

static void test_smb2_bench_session_setup_loop_do_logoff(
	struct test_smb2_bench_session_setup_shared_loop *loop)
{
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;

	loop->logoffs.num_started += 1;
	loop->logoffs.starttime = timeval_current();
	loop->logoffs.req = smb2_logoff_send(loop->session);
	torture_assert_goto(state->tctx, loop->logoffs.req != NULL,
			    state->ok, asserted, "smb2_logoff_send");

	loop->logoffs.req->async.fn = test_smb2_bench_session_setup_loop_done_logoff;
	loop->logoffs.req->async.private_data = loop;
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_session_setup_loop_done_logoff(struct smb2_request *req)
{
	struct test_smb2_bench_session_setup_shared_loop *loop =
		(struct test_smb2_bench_session_setup_shared_loop *)
		req->async.private_data;
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->logoffs.starttime);

	torture_assert_goto(state->tctx, loop->logoffs.req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2_logoff_recv(req);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	TALLOC_FREE(loop->session);
	SMB_ASSERT(latency >= 0.000001);
	if (loop->logoffs.num_finished == 0) {
		/* first round */
		loop->logoffs.min_latency = latency;
		loop->logoffs.max_latency = latency;
	}
	loop->logoffs.num_finished += 1;

	loop->logoffs.total_latency += latency;

	if (latency < loop->logoffs.min_latency) {
		loop->logoffs.min_latency = latency;
	}

	if (latency > loop->logoffs.max_latency) {
		loop->logoffs.max_latency = latency;
	}

	test_smb2_bench_session_setup_loop_do_setup(loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_session_setup_progress(struct tevent_context *ev,
						   struct tevent_timer *te,
						   struct timeval current_time,
						   void *private_data)
{
	struct test_smb2_bench_session_setup_shared_state *state =
		(struct test_smb2_bench_session_setup_shared_state *)private_data;
	uint64_t num_setups = 0;
	double total_setup_latency = 0;
	double min_setup_latency = 0;
	double max_setup_latency = 0;
	double avs_setup_latency = 0;
	uint64_t num_logoffs = 0;
	double total_logoff_latency = 0;
	double min_logoff_latency = 0;
	double max_logoff_latency = 0;
	double avs_logoff_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_session_setup_shared_loop *loop =
			&state->loops[i];

		num_setups += loop->setups.num_finished;
		total_setup_latency += loop->setups.total_latency;
		if (min_setup_latency == 0.0 && loop->setups.min_latency != 0.0) {
			min_setup_latency = loop->setups.min_latency;
		}
		if (loop->setups.min_latency < min_setup_latency) {
			min_setup_latency = loop->setups.min_latency;
		}
		if (max_setup_latency == 0.0) {
			max_setup_latency = loop->setups.max_latency;
		}
		if (loop->setups.max_latency > max_setup_latency) {
			max_setup_latency = loop->setups.max_latency;
		}
		loop->setups.num_finished = 0;
		loop->setups.total_latency = 0.0;

		num_logoffs += loop->logoffs.num_finished;
		total_logoff_latency += loop->logoffs.total_latency;
		if (min_logoff_latency == 0.0 && loop->logoffs.min_latency != 0.0) {
			min_logoff_latency = loop->logoffs.min_latency;
		}
		if (loop->logoffs.min_latency < min_logoff_latency) {
			min_logoff_latency = loop->logoffs.min_latency;
		}
		if (max_logoff_latency == 0.0) {
			max_logoff_latency = loop->logoffs.max_latency;
		}
		if (loop->logoffs.max_latency > max_logoff_latency) {
			max_logoff_latency = loop->logoffs.max_latency;
		}
		loop->logoffs.num_finished = 0;
		loop->logoffs.total_latency = 0.0;
	}

	state->setups.num_finished += num_setups;
	state->setups.total_latency += total_setup_latency;
	if (state->setups.min_latency == 0.0 && min_setup_latency != 0.0) {
		state->setups.min_latency = min_setup_latency;
	}
	if (min_setup_latency < state->setups.min_latency) {
		state->setups.min_latency = min_setup_latency;
	}
	if (state->setups.max_latency == 0.0) {
		state->setups.max_latency = max_setup_latency;
	}
	if (max_setup_latency > state->setups.max_latency) {
		state->setups.max_latency = max_setup_latency;
	}

	state->logoffs.num_finished += num_logoffs;
	state->logoffs.total_latency += total_logoff_latency;
	if (state->logoffs.min_latency == 0.0 && min_logoff_latency != 0.0) {
		state->logoffs.min_latency = min_logoff_latency;
	}
	if (min_logoff_latency < state->logoffs.min_latency) {
		state->logoffs.min_latency = min_logoff_latency;
	}
	if (state->logoffs.max_latency == 0.0) {
		state->logoffs.max_latency = max_logoff_latency;
	}
	if (max_logoff_latency > state->logoffs.max_latency) {
		state->logoffs.max_latency = max_logoff_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_session_setup_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_setup_latency = total_setup_latency / num_setups;
		avs_logoff_latency = total_logoff_latency / num_logoffs;

		torture_comment(state->tctx,
				"%.2f second: "
				"setup[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
				"logoff[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]     \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_setups,
				avs_setup_latency,
				min_setup_latency,
				max_setup_latency,
				(unsigned long long)num_logoffs,
				avs_logoff_latency,
				min_logoff_latency,
				max_logoff_latency);
		return;
	}

	avs_setup_latency = state->setups.total_latency / state->setups.num_finished;
	avs_logoff_latency = state->logoffs.total_latency / state->logoffs.num_finished;
	num_setups = state->setups.num_finished / state->timelimit;
	num_logoffs = state->logoffs.num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"setup[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
			"logoff[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_setups,
			avs_setup_latency,
			state->setups.min_latency,
			state->setups.max_latency,
			(unsigned long long)num_logoffs,
			avs_logoff_latency,
			state->logoffs.min_latency,
			state->logoffs.max_latency);

asserted:
	state->stop = true;
}

static bool test_smb2_bench_session_setup(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	struct test_smb2_bench_session_setup_shared_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	size_t i;
	size_t li = 0;
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;

	state = talloc_zero(tctx, struct test_smb2_bench_session_setup_shared_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->credentials = samba_cmdline_get_creds();
	torture_assert(tctx, state->credentials != NULL, __location__);
	state->gensec_settings = lpcfg_gensec_settings(state, tctx->lp_ctx);
	torture_assert(tctx, state->gensec_settings != NULL, __location__);
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_session_setup_shared_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_session_setup_shared_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zd connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			talloc_steal(state->conns, ct);
		}
		state->conns[i].transport = ct->session->transport;

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");
		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_session_setup_shared_loop *loop = &state->loops[li];

			loop->idx = li++;
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_session_setup_shared_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_session_setup_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_session_setup_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	return ret;
}

struct torture_suite *torture_smb2_bench_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "bench");

	torture_suite_add_1smb2_test(suite, "oplock1", test_smb2_bench_oplock);
	torture_suite_add_1smb2_test(suite, "echo", test_smb2_bench_echo);
	torture_suite_add_1smb2_test(suite, "path-contention-shared", test_smb2_bench_path_contention_shared);
	torture_suite_add_1smb2_test(suite, "read", test_smb2_bench_read);
	torture_suite_add_1smb2_test(suite, "write", test_smb2_bench_write);
	torture_suite_add_1smb2_test(suite, "session-setup", test_smb2_bench_session_setup);

	suite->description = talloc_strdup(suite, "SMB2-BENCH tests");

	return suite;
}
