/*
 * TrueNAS: abuse of the inline runs of the reactors.
 *
 * A reactor runs most PDUs through smbd under a process lock. The main
 * thread of smbd runs the rest. These tests send random compounds, mix
 * the two kinds of work, end connections with pending requests, and start
 * many timers at the same time. Each test expects the behaviour of smbd
 * without a reactor. The suite passes against smbd with and without the
 * reactors. compound-fuzz logs each status. The caller can compare the
 * logs of two servers line by line. related-create, eof-stat-open and
 * alloc-stat-open check fixes of smbd bugs outside the reactor code.
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
#include "torture/smb2/lease_break_handler.h"
#include "libcli/security/security.h"
#include "lib/cmdline/cmdline.h"
#include "param/param.h"

#define RIA_DIR "ros_inline_abuse"
#define RIA_FILES 6
#define RIA_FILE_SIZE (16 * 1024)
#define RIA_MAX_MSGS 5

/* smbd's OPLOCK_BREAK_TIMEOUT, see source3/include/local.h */
#define RIA_BREAK_TIMEOUT 35

/* A private PRNG. One seed produces the same requests for both servers. */
static uint64_t ria_rand(uint64_t *s)
{
	uint64_t x = *s;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*s = x;
	return x;
}

static const char *ria_fname(TALLOC_CTX *mem_ctx, unsigned i)
{
	return talloc_asprintf(mem_ctx, RIA_DIR "\\f%u.dat", i);
}

/* Create the directory and RIA_FILES files of RIA_FILE_SIZE bytes. */
static bool ria_setup(struct torture_context *tctx, struct smb2_tree *tree)
{
	DATA_BLOB data = data_blob_talloc_zero(tctx, RIA_FILE_SIZE);
	NTSTATUS status;
	unsigned i;

	torture_assert(tctx,
		       smb2_util_setup_dir(tctx, tree, RIA_DIR),
		       "mkdir " RIA_DIR);

	for (i = 0; i < RIA_FILES; i++) {
		struct smb2_handle h;

		status = torture_smb2_testfile(tree, ria_fname(tctx, i), &h);
		torture_assert_ntstatus_ok(tctx, status, "create");
		memset(data.data, 'a' + i, data.length);
		status = smb2_util_write(tree, h, data.data, 0, data.length);
		torture_assert_ntstatus_ok(tctx, status, "write");
		smb2_util_close(tree, h);
	}
	data_blob_free(&data);
	return true;
}

enum ria_op {
	RIA_CREATE,
	RIA_GETINFO,
	RIA_SETINFO,
	RIA_FIND,
	RIA_READ,
	RIA_WRITE,
	RIA_FLUSH,
	RIA_CLOSE,
	RIA_NUM_OPS,
};

static const char *ria_op_names[RIA_NUM_OPS] = {
	"create", "getinfo", "setinfo", "find",
	"read", "write", "flush", "close",
};

struct ria_msg {
	enum ria_op op;
	bool related;
	struct smb2_request *req;
	struct smb2_create create;
	struct smb2_getinfo getinfo;
	union smb_setfileinfo setinfo;
	struct smb2_find find;
	struct smb2_read read;
	struct smb2_write write;
	struct smb2_flush flush;
	struct smb2_close close;
};

/* Send message m of a compound. Each op except CREATE uses handle h. */
static struct smb2_request *ria_send(TALLOC_CTX *mem_ctx,
				     struct smb2_tree *tree,
				     struct ria_msg *m,
				     struct smb2_handle h,
				     uint64_t *seed)
{
	static const struct {
		uint8_t type;
		uint8_t class;
	} getinfo_levels[] = {
		{ SMB2_0_INFO_FILE, 0x04 },		/* FileBasicInformation */
		{ SMB2_0_INFO_FILE, 0x05 },		/* FileStandardInformation */
		{ SMB2_0_INFO_FILE, 0x16 },		/* FileStreamInformation */
		{ SMB2_0_INFO_FILE, 0x12 },		/* FileAllInformation */
		{ SMB2_0_INFO_FILESYSTEM, 0x03 },	/* FileFsSizeInformation */
		{ SMB2_0_INFO_FILESYSTEM, 0x07 },	/* FileFsFullSizeInformation */
	};
	uint64_t r = ria_rand(seed);

	switch (m->op) {
	case RIA_CREATE: {
		/* A stat open, a read-only open and a full open */
		static const uint32_t access[] = {
			SEC_FILE_READ_ATTRIBUTE | SEC_STD_SYNCHRONIZE,
			SEC_FILE_READ_DATA | SEC_FILE_READ_ATTRIBUTE,
			SEC_RIGHTS_FILE_ALL,
		};
		unsigned which = r % (RIA_FILES + 2);
		const char *name = NULL;

		if (which < RIA_FILES) {
			name = ria_fname(mem_ctx, which);
		} else if (which == RIA_FILES) {
			name = RIA_DIR;
		} else {
			name = RIA_DIR "\\nosuch.dat";
		}
		m->create = (struct smb2_create) {
			.in.desired_access = access[(r >> 8) % 3],
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.impersonation_level =
				SMB2_IMPERSONATION_IMPERSONATION,
			.in.fname = name,
		};
		return smb2_create_send(tree, &m->create);
	}
	case RIA_GETINFO: {
		unsigned l = r % ARRAY_SIZE(getinfo_levels);

		m->getinfo = (struct smb2_getinfo) {
			.in.info_type = getinfo_levels[l].type,
			.in.info_class = getinfo_levels[l].class,
			.in.output_buffer_length = 4096,
			.in.file.handle = h,
		};
		return smb2_getinfo_send(tree, &m->getinfo);
	}
	case RIA_SETINFO:
		if (r & 1) {
			m->setinfo.generic.level =
				RAW_SFILEINFO_END_OF_FILE_INFORMATION;
			m->setinfo.end_of_file_info.in.file.handle = h;
			m->setinfo.end_of_file_info.in.size = RIA_FILE_SIZE;
		} else {
			m->setinfo.generic.level =
				RAW_SFILEINFO_BASIC_INFORMATION;
			m->setinfo.basic_info.in.file.handle = h;
			m->setinfo.basic_info.in.write_time =
				0x01d0000000000000ULL + (r >> 32) % 1000;
			m->setinfo.basic_info.in.attrib =
				FILE_ATTRIBUTE_NORMAL;
		}
		return smb2_setinfo_file_send(tree, &m->setinfo);
	case RIA_FIND:
		m->find = (struct smb2_find) {
			.in.file.handle = h,
			.in.level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
			.in.continue_flags = SMB2_CONTINUE_FLAG_RESTART |
				((r & 1) ? SMB2_CONTINUE_FLAG_SINGLE : 0),
			.in.max_response_size = 65536,
			.in.pattern = (r & 2) ? "*" : "f1.dat",
		};
		return smb2_find_send(tree, &m->find);
	case RIA_READ:
		m->read = (struct smb2_read) {
			.in.file.handle = h,
			.in.offset = (r >> 4) % (2 * RIA_FILE_SIZE),
			.in.length = 1 + (r >> 20) % 65536,
		};
		return smb2_read_send(tree, &m->read);
	case RIA_WRITE: {
		size_t len = 1 + (r >> 20) % RIA_FILE_SIZE;

		m->write = (struct smb2_write) {
			.in.file.handle = h,
			.in.offset = (r >> 4) % RIA_FILE_SIZE,
		};
		m->write.in.data = data_blob_talloc(mem_ctx, NULL, len);
		if (m->write.in.data.data == NULL) {
			return NULL;
		}
		memset(m->write.in.data.data, (int)(r >> 40), len);
		return smb2_write_send(tree, &m->write);
	}
	case RIA_FLUSH:
		m->flush = (struct smb2_flush) {
			.in.file.handle = h,
		};
		return smb2_flush_send(tree, &m->flush);
	case RIA_CLOSE:
		m->close = (struct smb2_close) {
			.in.file.handle = h,
		};
		return smb2_close_send(tree, &m->close);
	case RIA_NUM_OPS:
		break;
	}
	return NULL;
}

static NTSTATUS ria_recv(TALLOC_CTX *mem_ctx, struct ria_msg *m)
{
	switch (m->op) {
	case RIA_CREATE:
		return smb2_create_recv(m->req, mem_ctx, &m->create);
	case RIA_GETINFO:
		return smb2_getinfo_recv(m->req, mem_ctx, &m->getinfo);
	case RIA_SETINFO:
		return smb2_setinfo_recv(m->req);
	case RIA_FIND:
		return smb2_find_recv(m->req, mem_ctx, &m->find);
	case RIA_READ:
		return smb2_read_recv(m->req, mem_ctx, &m->read);
	case RIA_WRITE:
		return smb2_write_recv(m->req, &m->write);
	case RIA_FLUSH:
		return smb2_flush_recv(m->req, &m->flush);
	case RIA_CLOSE:
		return smb2_close_recv(m->req, &m->close);
	case RIA_NUM_OPS:
		break;
	}
	return NT_STATUS_INTERNAL_ERROR;
}

/* The fuzz test stops after this many disconnects by the server. */
#define RIA_MAX_DROPS 5

/*
 * This test sends random compounds of 2 to RIA_MAX_MSGS messages. A
 * message is related, or it uses a long-lived handle or a closed handle.
 * Each round logs the status of each message as "ria round N: op/status
 * ...". Two servers that behave the same log the same lines for one seed.
 * The test fails if the server ends a connection.
 *
 * torture:related_create=no makes each CREATE unrelated. Use it against
 * an smbd without the fix that test_ria_related_create() checks. Such an
 * smbd ends the connection on a related CREATE.
 */
static bool test_ria_compound_fuzz(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_tree *t = tree;
	struct smb2_transport *transport = tree->session->transport;
	unsigned rounds = torture_setting_int(tctx, "looplimit", 1000);
	uint64_t seed = torture_setting_int(tctx, "seed", 1) | 1;
	bool related_create = torture_setting_bool(tctx, "related_create",
						   true);
	struct smb2_handle rel = {
		.data = { UINT64_MAX, UINT64_MAX },
	};
	struct smb2_handle hk = {};
	struct smb2_handle hgone = {};
	unsigned drops = 0;
	unsigned round;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, ria_setup(tctx, tree), "setup");

	status = torture_smb2_testfile(tree, ria_fname(tctx, 1), &hgone);
	torture_assert_ntstatus_ok(tctx, status, "open closed");
	smb2_util_close(tree, hgone);

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		struct ria_msg msgs[RIA_MAX_MSGS] = {};
		unsigned n = 2 + ria_rand(&seed) % (RIA_MAX_MSGS - 1);
		char *line = talloc_asprintf(frame, "ria round %u:", round);
		unsigned i;

		/* A CLOSE in the last round can have closed this handle. */
		if (!smb2_util_handle_empty(hk)) {
			smb2_util_close(t, hk);
		}
		status = torture_smb2_testfile(t, ria_fname(tctx, 0), &hk);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open long-lived");

		status = smb2_transport_compound_start(transport, n);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"compound start");
		for (i = 0; i < n; i++) {
			uint64_t r = ria_rand(&seed);
			struct ria_msg *m = &msgs[i];
			struct smb2_handle h = hk;

			m->op = (i == 0 && (r & 3) != 0) ?
				RIA_CREATE : (enum ria_op)((r >> 2) %
							   RIA_NUM_OPS);
			m->related = (i > 0) && ((r >> 8) % 4 != 0);
			if (m->op == RIA_CREATE && !related_create) {
				m->related = false;
			}
			smb2_transport_compound_set_related(transport,
							    m->related);
			if (m->related) {
				h = rel;
			} else if ((r >> 10) % 4 == 0) {
				h = hgone;
			}
			m->req = ria_send(frame, t, m, h, &seed);
			torture_assert_goto(tctx, m->req != NULL, ret, done,
					    "send");
		}
		for (i = 0; i < n; i++) {
			struct ria_msg *m = &msgs[i];

			status = ria_recv(frame, m);
			line = talloc_asprintf_append(line, " %s%s/%s",
						      m->related ? "+" : "",
						      ria_op_names[m->op],
						      nt_errstr(status));
			if (m->op == RIA_CREATE && NT_STATUS_IS_OK(status) &&
			    smbXcli_conn_is_connected(transport->conn))
			{
				/* A related CLOSE can have closed it. */
				smb2_util_close(t, m->create.out.file.handle);
			}
		}
		torture_comment(tctx, "%s\n", line);
		TALLOC_FREE(frame);

		if (!smbXcli_conn_is_connected(transport->conn)) {
			struct smb2_tree *t2 = NULL;

			torture_comment(tctx, "ria round %u: DISCONNECTED\n",
					round);
			drops += 1;
			if (drops == RIA_MAX_DROPS) {
				break;
			}
			torture_assert_goto(tctx,
					    torture_smb2_connection(tctx, &t2),
					    ret, done, "connect again");
			if (t != tree) {
				talloc_free(t);
			}
			t = t2;
			transport = t->session->transport;
			hk = (struct smb2_handle) {};
		}
	}
	torture_assert_int_equal_goto(tctx, drops, 0, ret, done,
				      "connections the server ended");

done:
	if (smbXcli_conn_is_connected(transport->conn)) {
		if (!smb2_util_handle_empty(hk)) {
			smb2_util_close(t, hk);
		}
		smb2_deltree(t, RIA_DIR);
	}
	if (t != tree) {
		talloc_free(t);
	}
	return ret;
}

/*
 * This test sends a compound of a READ and a related CREATE of another
 * file. A CREATE has no FileId. smbd must not count it as a request on the
 * open of the READ (MS-SMB2 3.3.5.2.10). The CREATE must succeed. The
 * server must not close the connection.
 */
static bool test_ria_related_create(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	struct smb2_transport *transport = tree->session->transport;
	struct smb2_request *reqs[2] = {};
	struct smb2_handle h = {};
	struct smb2_create cr = {};
	struct smb2_read rd = {};
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, ria_setup(tctx, tree), "setup");
	status = torture_smb2_testfile(tree, ria_fname(tctx, 0), &h);
	torture_assert_ntstatus_ok(tctx, status, "open");

	status = smb2_transport_compound_start(transport, 2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"compound start");
	rd = (struct smb2_read) {
		.in.file.handle = h,
		.in.length = 1,
	};
	reqs[0] = smb2_read_send(tree, &rd);
	smb2_transport_compound_set_related(transport, true);
	cr = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
			SEC_STD_SYNCHRONIZE,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = ria_fname(tctx, 1),
	};
	reqs[1] = smb2_create_send(tree, &cr);
	torture_assert_goto(tctx, reqs[0] != NULL && reqs[1] != NULL,
			    ret, done, "send");

	status = smb2_read_recv(reqs[0], tctx, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	status = smb2_create_recv(reqs[1], tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"related create");
	smb2_util_close(tree, cr.out.file.handle);
	torture_assert_goto(tctx, smbXcli_conn_is_connected(transport->conn),
			    ret, done, "the server ended the connection");

done:
	if (smbXcli_conn_is_connected(transport->conn)) {
		smb2_util_close(tree, h);
		smb2_deltree(tree, RIA_DIR);
	}
	return ret;
}

/*
 * This test sets a new size through a stat open with the info level
 * "level". A stat open has no FILE_WRITE_DATA. The server must refuse the
 * change (MS-FSA 2.1.5.15). The handle and new connections must still
 * work after that.
 */
static bool ria_size_stat_open(struct torture_context *tctx,
			       struct smb2_tree *tree,
			       enum smb_setfileinfo_level level)
{
	struct smb2_transport *transport = tree->session->transport;
	union smb_setfileinfo sinfo = {};
	union smb_fileinfo finfo = {};
	struct smb2_create cr = {};
	struct smb2_tree *t2 = NULL;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, ria_setup(tctx, tree), "setup");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
			SEC_STD_SYNCHRONIZE,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = ria_fname(tctx, 0),
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok(tctx, status, "stat open");

	sinfo.generic.level = level;
	if (level == RAW_SFILEINFO_ALLOCATION_INFORMATION) {
		sinfo.allocation_info.in.file.handle = cr.out.file.handle;
		sinfo.allocation_info.in.alloc_size = RIA_FILE_SIZE * 4;
	} else {
		sinfo.end_of_file_info.in.file.handle = cr.out.file.handle;
		sinfo.end_of_file_info.in.size = RIA_FILE_SIZE / 2;
	}
	status = smb2_setinfo_file(tree, &sinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "size through a stat open");

	finfo.standard_info.level = RAW_FILEINFO_STANDARD_INFORMATION;
	finfo.standard_info.in.file.handle = cr.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo on the stat open");
	torture_assert_u64_equal_goto(tctx, finfo.standard_info.out.size,
				      RIA_FILE_SIZE, ret, done, "file size");

	status = smb2_util_close(tree, cr.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close of the stat open");
	torture_assert_goto(tctx, smbXcli_conn_is_connected(transport->conn),
			    ret, done, "the server ended the connection");

	torture_assert_goto(tctx, torture_smb2_connection(tctx, &t2),
			    ret, done, "the server stopped answering");
	smb2_deltree(t2, RIA_DIR);
	talloc_free(t2);
	return ret;

done:
	if (smbXcli_conn_is_connected(transport->conn)) {
		smb2_deltree(tree, RIA_DIR);
	}
	return ret;
}

static bool test_ria_eof_stat_open(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	return ria_size_stat_open(tctx, tree,
				  RAW_SFILEINFO_END_OF_FILE_INFORMATION);
}

static bool test_ria_alloc_stat_open(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	return ria_size_stat_open(tctx, tree,
				  RAW_SFILEINFO_ALLOCATION_INFORMATION);
}

/*
 * This test closes a connection with a waiting CHANGE_NOTIFY, a waiting
 * blocking LOCK, and a WRITE and a FLUSH in progress. The first connection
 * must then open the file of the WRITE without sharing. The lock range
 * must be free in the next round.
 */
static bool test_ria_disconnect_async(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	unsigned rounds = torture_setting_int(tctx, "looplimit", 20);
	const char *wname = RIA_DIR "\\w.dat";
	const char *lname = RIA_DIR "\\l.dat";
	struct smb2_handle hl = {};
	unsigned round;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, ria_setup(tctx, tree), "setup");
	status = torture_smb2_testfile(tree, lname, &hl);
	torture_assert_ntstatus_ok(tctx, status, "open lock file");

	for (round = 0; round < rounds; round++) {
		struct smb2_lock_element el = {
			.offset = 0,
			.length = 100,
			.flags = SMB2_LOCK_FLAG_EXCLUSIVE |
				 SMB2_LOCK_FLAG_FAIL_IMMEDIATELY,
		};
		struct smb2_lock lck = {
			.in.lock_count = 1,
			.in.locks = &el,
		};
		struct smb2_lock lck2 = {};
		struct smb2_lock_element el2 = el;
		struct smb2_notify n = {};
		struct smb2_write w = {};
		struct smb2_flush f = {};
		struct smb2_tree *tree2 = NULL;
		struct smb2_request *reqs[4] = {};
		struct smb2_handle hd2, hl2, hw2;
		struct timeval start;
		unsigned i;

		/* The lock of this connection makes the LOCK below wait. */
		lck.in.file.handle = hl;
		status = smb2_lock(tree, &lck);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"lock");

		torture_assert_goto(tctx,
				    torture_smb2_connection(tctx, &tree2),
				    ret, done, "connect 2");
		status = torture_smb2_testdir(tree2, RIA_DIR, &hd2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open dir 2");
		status = torture_smb2_testfile(tree2, lname, &hl2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open lock file 2");
		status = torture_smb2_testfile(tree2, wname, &hw2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open write file 2");

		n = (struct smb2_notify) {
			.in.buffer_size = 1000,
			.in.file.handle = hd2,
			.in.completion_filter = FILE_NOTIFY_CHANGE_FILE_NAME,
		};
		reqs[0] = smb2_notify_send(tree2, &n);
		el2.flags = SMB2_LOCK_FLAG_EXCLUSIVE;
		lck2 = (struct smb2_lock) {
			.in.lock_count = 1,
			.in.file.handle = hl2,
			.in.locks = &el2,
		};
		reqs[1] = smb2_lock_send(tree2, &lck2);
		w = (struct smb2_write) {
			.in.file.handle = hw2,
		};
		w.in.data = data_blob_talloc_zero(tctx, 1024 * 1024);
		reqs[2] = smb2_write_send(tree2, &w);
		f.in.file.handle = hw2;
		reqs[3] = smb2_flush_send(tree2, &f);
		for (i = 0; i < ARRAY_SIZE(reqs); i++) {
			torture_assert_goto(tctx, reqs[i] != NULL, ret, done,
					    "send");
		}

		start = timeval_current();
		while ((!reqs[0]->cancel.can_cancel ||
			!reqs[1]->cancel.can_cancel) &&
		       timeval_elapsed(&start) < 5)
		{
			torture_ros_poll(tctx);
		}
		torture_assert_goto(tctx,
				    reqs[0]->cancel.can_cancel &&
				    reqs[1]->cancel.can_cancel,
				    ret, done, "notify and lock did not wait");

		/* This closes the connection while the requests are pending. */
		TALLOC_FREE(tree2);
		data_blob_free(&w.in.data);

		status = torture_ros_open_exclusive(tctx, tree, wname, &hw2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"exclusive open of the write file");
		smb2_util_close(tree, hw2);

		el.flags = SMB2_LOCK_FLAG_UNLOCK;
		status = smb2_lock(tree, &lck);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"unlock");
	}

done:
	smb2_util_close(tree, hl);
	smb2_deltree(tree, RIA_DIR);
	return ret;
}

#define RIA_TIMERS 16
#define RIA_LEASE_BASE 0xBEEF1000ULL

/*
 * This test sends RIA_TIMERS CREATEs at the same time on one connection.
 * Each CREATE breaks the lease of another open. The client does not
 * acknowledge the breaks. Each CREATE starts timers in smbd. Each CREATE
 * must succeed when the break times out.
 */
static bool test_ria_timer_storm(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	struct smb2_create io1[RIA_TIMERS] = {};
	struct smb2_create io2[RIA_TIMERS] = {};
	struct smb2_lease ls1[RIA_TIMERS] = {};
	struct smb2_lease ls2[RIA_TIMERS] = {};
	struct smb2_request *reqs[RIA_TIMERS] = {};
	struct smb2_handle h1[RIA_TIMERS] = {};
	struct timeval start;
	unsigned done_count = 0;
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;
	unsigned i;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert(tctx, caps & SMB2_CAP_LEASING, "no leases");
	torture_assert(tctx, ria_setup(tctx, tree), "setup");

	for (i = 0; i < RIA_TIMERS; i++) {
		const char *name = talloc_asprintf(tctx,
						   RIA_DIR "\\t%u.dat", i);

		smb2_lease_create(&io1[i], &ls1[i], false, name,
				  RIA_LEASE_BASE + i,
				  smb2_util_lease_state("RWH"));
		status = smb2_create(tree, tctx, &io1[i]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create 1");
		h1[i] = io1[i].out.file.handle;
	}

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	smb2cli_conn_set_max_credits(tree->session->transport->conn, 8192);

	start = timeval_current();
	for (i = 0; i < RIA_TIMERS; i++) {
		smb2_lease_create(&io2[i], &ls2[i], false, io1[i].in.fname,
				  RIA_LEASE_BASE + 0x100 + i,
				  smb2_util_lease_state("RWH"));
		reqs[i] = smb2_create_send(tree, &io2[i]);
		torture_assert_goto(tctx, reqs[i] != NULL, ret, done,
				    "create 2 send");
	}

	while (done_count < RIA_TIMERS &&
	       timeval_elapsed(&start) < RIA_BREAK_TIMEOUT * 3)
	{
		done_count = 0;
		for (i = 0; i < RIA_TIMERS; i++) {
			if (reqs[i]->state > SMB2_REQUEST_RECV) {
				done_count++;
			}
		}
		if (done_count < RIA_TIMERS) {
			torture_ros_poll(tctx);
		}
	}
	torture_comment(tctx, "%u CREATEs done after %.3f s\n",
			done_count, timeval_elapsed(&start));
	torture_assert_goto(tctx, done_count == RIA_TIMERS, ret, done,
			    "not all CREATEs ended");
	torture_assert_goto(tctx,
			    timeval_elapsed(&start) >= RIA_BREAK_TIMEOUT - 2 &&
			    timeval_elapsed(&start) <= RIA_BREAK_TIMEOUT + 5,
			    ret, done,
			    "the CREATEs did not end at the break timeout");

	for (i = 0; i < RIA_TIMERS; i++) {
		status = smb2_create_recv(reqs[i], tctx, &io2[i]);
		reqs[i] = NULL;
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create 2");
		smb2_util_close(tree, io2[i].out.file.handle);
	}
	torture_assert_int_equal_goto(tctx, lease_break_info.count,
				      RIA_TIMERS, ret, done, "lease breaks");

done:
	tree->session->transport->lease.handler = NULL;
	for (i = 0; i < RIA_TIMERS; i++) {
		if (reqs[i] != NULL) {
			smb2_create_recv(reqs[i], tctx, &io2[i]);
		}
		if (!smb2_util_handle_empty(h1[i])) {
			smb2_util_close(tree, h1[i]);
		}
	}
	smb2_deltree(tree, RIA_DIR);
	return ret;
}

/*
 * In each round, this test adds a second tree connect and a second
 * session. It ends both while a WRITE and a FLUSH on the first tree are in
 * progress. The main thread of smbd runs the TREE_DISCONNECT and the
 * LOGOFF. A reactor runs the file requests. A READ must return the data of
 * the WRITE.
 */
static bool test_ria_churn(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	struct smb2_transport *transport = tree->session->transport;
	unsigned rounds = torture_setting_int(tctx, "looplimit", 50);
	unsigned round;
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, ria_setup(tctx, tree), "setup");

	for (round = 0; round < rounds; round++) {
		TALLOC_CTX *frame = talloc_new(tctx);
		const char *name = ria_fname(frame, round % RIA_FILES);
		struct smb2_session *session2 = NULL;
		struct smb2_tree *tree2 = NULL;
		struct smb2_tree *tree3 = NULL;
		struct smb2_request *wreq = NULL;
		struct smb2_request *freq = NULL;
		struct smb2_write w = {};
		struct smb2_flush f = {};
		struct smb2_read r = {};
		struct smb2_handle h = {};
		size_t j;

		torture_assert_goto(tctx,
				    torture_smb2_tree_connect(tctx,
							      tree->session,
							      frame,
							      &tree2),
				    ret, done, "tcon 2");
		session2 = smb2_session_init(transport,
					     tctx->lp_ctx,
					     lpcfg_gensec_settings(frame,
								   tctx->lp_ctx),
					     frame);
		torture_assert_goto(tctx, session2 != NULL, ret, done,
				    "session 2");
		status = smb2_session_setup_spnego(session2,
						   samba_cmdline_get_creds(),
						   0);
		/*
		 * smb2_session_init() made session2 the talloc parent of
		 * the transport.
		 */
		tree->session->transport =
			talloc_steal(tree->session, session2->transport);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"session setup 2");
		torture_assert_goto(tctx,
				    torture_smb2_tree_connect(tctx,
							      session2,
							      frame,
							      &tree3),
				    ret, done, "tcon 3");

		status = torture_smb2_testfile(tree, name, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open");
		w = (struct smb2_write) {
			.in.file.handle = h,
		};
		w.in.data = data_blob_talloc(frame, NULL, RIA_FILE_SIZE);
		memset(w.in.data.data, round, w.in.data.length);
		wreq = smb2_write_send(tree, &w);
		f.in.file.handle = h;
		freq = smb2_flush_send(tree, &f);
		torture_assert_goto(tctx, wreq != NULL && freq != NULL,
				    ret, done, "send");

		status = smb2_tdis(tree2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"tdis 2");
		status = smb2_logoff(session2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"logoff 2");

		status = smb2_write_recv(wreq, &w);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"write");
		status = smb2_flush_recv(freq, &f);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"flush");

		r = (struct smb2_read) {
			.in.file.handle = h,
			.in.length = RIA_FILE_SIZE,
		};
		status = smb2_read(tree, frame, &r);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"read");
		for (j = 0; j < r.out.data.length; j++) {
			if (r.out.data.data[j] != (uint8_t)round) {
				break;
			}
		}
		torture_assert_goto(tctx, j == RIA_FILE_SIZE, ret, done,
				    "data of the write");
		smb2_util_close(tree, h);
		TALLOC_FREE(frame);
	}

done:
	smb2_deltree(tree, RIA_DIR);
	return ret;
}

struct torture_suite *torture_smb2_ros_inline_abuse_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
		torture_suite_create(ctx, "ros-inline-abuse");

	torture_suite_add_1smb2_test(suite, "compound-fuzz",
				     test_ria_compound_fuzz);
	torture_suite_add_1smb2_test(suite, "disconnect-async",
				     test_ria_disconnect_async);
	torture_suite_add_1smb2_test(suite, "timer-storm",
				     test_ria_timer_storm);
	torture_suite_add_1smb2_test(suite, "churn", test_ria_churn);
	torture_suite_add_1smb2_test(suite, "related-create",
				     test_ria_related_create);
	torture_suite_add_1smb2_test(suite, "eof-stat-open",
				     test_ria_eof_stat_open);
	torture_suite_add_1smb2_test(suite, "alloc-stat-open",
				     test_ria_alloc_stat_open);
	suite->description = talloc_strdup(
		suite, "Abuse of the inline reactor runs");
	return suite;
}
