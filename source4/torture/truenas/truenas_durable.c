/*
   Unix SMB/CIFS implementation.

   TrueNAS: durable handles across a server restart, crash or failover,
   restored from truenas_smbhad (source3/truenas_hastate/restore.c).

   Copyright (C) iXsystems, Inc. 2026

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
 * The test has three phases. Each smbtorture run does one phase. The
 * caller stops, kills or reboots the server while prepare or reconnect
 * keeps the connection open.
 *
 *  --option=torture:durable_phase=prepare --option=torture:durable_state=FILE
 *	Opens the durable handles in the list below. Waits 2 s, one tick
 *	after the records are sent. Then locks C and changes J, K, M and N.
 *	Waits until torture:durable_late_lock_secs seconds after the opens,
 *	default 0. Then locks I. Writes the client state to FILE. Keeps the
 *	connection open for torture:durable_hold seconds.
 *  --option=torture:durable_phase=reconnect --option=torture:durable_state=FILE
 *	--option=torture:durable_state_out=FILE2
 *	Reconnects the handles that verify expects to be restored, except E.
 *	Does not check their state. Writes the client state to FILE2. Keeps
 *	the connection open for torture:durable_hold seconds. The caller
 *	causes a second failure during this time.
 *  --option=torture:durable_phase=verify --option=torture:durable_state=FILE
 *	Reconnects the handles with the client GUID from FILE. Checks each
 *	handle against the list below, for a failover. Only a failover
 *	restores handles.
 *
 * The handles:
 *  A  v2, RWH lease, written, flushed. Restored with its data.
 *  B  v2, RWH lease, written, not flushed. Never restored: a failover can
 *     lose the writes.
 *  C  v2, RWH lease, flushed, holds a byte range lock with a lock
 *     sequence. Restored with the lock. A replay of the lock succeeds and
 *     adds no lock.
 *  D  v1, batch oplock, flushed. Restored with its data.
 *  E  v2, RWH lease, flushed, 20 s timeout. Not reconnected before the
 *     timeout ends. Not restored after the timeout.
 *  F  v2, RWH lease, flushed, renamed while open. Restored at the new name.
 *  G  v2, RWH lease, flushed, 20 s timeout. Restored when reconnected
 *     before the timeout ends.
 *  H  v2, RH lease, flushed, holds a byte range lock. Never restored. A
 *     disconnect closes it (smb2.durable-open.lock-noW-lease).
 *  I  Same as H, but locked last, after the wait. Never restored, also
 *     when the standby received its record before the lock.
 *  J  v2, RWH lease, flushed. A second lease of the client breaks it to RH.
 *     Restored with RH.
 *  K  v2, RWH lease, flushed, then written through a second handle of the
 *     lease. Never restored, as B.
 *  L  v2, RWH lease, flushed, of a second client. That client closes L
 *     and disconnects. Never restored.
 *  M  v2, RWH lease, flushed. A second handle of the lease sets delete on
 *     close and closes. Never restored.
 *  N  v2, RWH lease, flushed. A second handle of the lease opens it with
 *     overwrite (truncates it) and closes. Never restored, as B.
 *
 * torture:durable_gone lists the letters of the handles that the caller
 * changed on disk while they were disconnected. These handles must not be
 * restored.
 *
 * The test is skipped if torture:durable_phase or torture:durable_state
 * is not set.
 */

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"
#include "lib/util/sys_rw_data.h"

#define TD_DIR		"truenas_durable"
#define TD_SIZE		65536
#define TD_LOCK_LEN	4096
#define TD_SHORT_MSEC	20000

struct td_handle {
	char tag;
	const char *name;
	int version;		/* 1: DHnQ, 2: DH2Q */
	bool lease;
	bool no_write;		/* RH instead of RWH */
	bool flush;
	bool lock;
	bool late_lock;		/* locked after durable_late_lock_secs */
	uint32_t timeout_msec;	/* v2 only, 0: the server's maximum */
	const char *rename_to;
	uint32_t lock_sequence;	/* of the lock, 0: none */
	bool break_write;	/* a second lease breaks write caching */
	bool sibling_write;	/* written through a second handle */
	bool exit_close;	/* a second client opens and closes it */
	bool sibling_delete;	/* delete on close through a second handle */
	bool sibling_truncate;	/* overwritten through a second handle */
	/* client state, saved in the state file */
	struct smb2_handle h;
	struct GUID create_guid;
	uint64_t lease_key;
	struct GUID client_guid;
};

static struct td_handle td_handles[] = {
	{ .tag = 'A', .name = TD_DIR "\\durable_a.dat", .version = 2,
	  .lease = true, .flush = true },
	{ .tag = 'B', .name = TD_DIR "\\durable_b.dat", .version = 2,
	  .lease = true, .flush = false },
	{ .tag = 'C', .name = TD_DIR "\\durable_c.dat", .version = 2,
	  .lease = true, .flush = true, .lock = true, .lock_sequence = 0x15 },
	{ .tag = 'D', .name = TD_DIR "\\durable_d.dat", .version = 1,
	  .lease = false, .flush = true },
	{ .tag = 'E', .name = TD_DIR "\\durable_e.dat", .version = 2,
	  .lease = true, .flush = true, .timeout_msec = TD_SHORT_MSEC },
	{ .tag = 'F', .name = TD_DIR "\\durable_f.dat", .version = 2,
	  .lease = true, .flush = true,
	  .rename_to = TD_DIR "\\durable_f2.dat" },
	{ .tag = 'G', .name = TD_DIR "\\durable_g.dat", .version = 2,
	  .lease = true, .flush = true, .timeout_msec = TD_SHORT_MSEC },
	{ .tag = 'H', .name = TD_DIR "\\durable_h.dat", .version = 2,
	  .lease = true, .no_write = true, .flush = true, .lock = true },
	{ .tag = 'I', .name = TD_DIR "\\durable_i.dat", .version = 2,
	  .lease = true, .no_write = true, .flush = true, .lock = true,
	  .late_lock = true },
	{ .tag = 'J', .name = TD_DIR "\\durable_j.dat", .version = 2,
	  .lease = true, .flush = true, .break_write = true },
	{ .tag = 'K', .name = TD_DIR "\\durable_k.dat", .version = 2,
	  .lease = true, .flush = true, .sibling_write = true },
	{ .tag = 'L', .name = TD_DIR "\\durable_l.dat", .version = 2,
	  .lease = true, .flush = true, .exit_close = true },
	{ .tag = 'M', .name = TD_DIR "\\durable_m.dat", .version = 2,
	  .lease = true, .flush = true, .sibling_delete = true },
	{ .tag = 'N', .name = TD_DIR "\\durable_n.dat", .version = 2,
	  .lease = true, .flush = true, .sibling_truncate = true },
};

static void td_pattern(uint8_t *buf, size_t len, char tag)
{
	size_t i;

	for (i = 0; i < len; i++) {
		buf[i] = (uint8_t)((tag * 7 + i * 31) & 0xff);
	}
}

static const char *td_final_name(const struct td_handle *t)
{
	return (t->rename_to != NULL) ? t->rename_to : t->name;
}

static void td_create(struct smb2_create *io,
		      struct smb2_lease *ls,
		      struct td_handle *t,
		      bool reconnect)
{
	if (t->lease) {
		smb2_lease_create(io, ls, false, td_final_name(t),
				  t->lease_key,
				  smb2_util_lease_state(t->no_write ? "RH" :
								      "RWH"));
	} else {
		smb2_oplock_create(io, td_final_name(t),
				   SMB2_OPLOCK_LEVEL_BATCH);
	}
	if (!reconnect) {
		io->in.fname = t->name;
		if (t->version == 2) {
			io->in.durable_open_v2 = true;
			io->in.create_guid = t->create_guid;
			io->in.timeout = (t->timeout_msec != 0) ?
				t->timeout_msec : UINT32_MAX;
		} else {
			io->in.durable_open = true;
		}
		return;
	}
	io->in.create_disposition = NTCREATEX_DISP_OPEN;
	if (t->version == 2) {
		io->in.durable_handle_v2 = &t->h;
		io->in.create_guid = t->create_guid;
	} else {
		io->in.durable_handle = &t->h;
	}
}

static bool td_save(struct torture_context *tctx,
		    const char *path,
		    const struct GUID *client_guid)
{
	char *text = NULL;
	char *tmp = NULL;
	size_t i;
	int fd;
	bool ok;

	text = talloc_asprintf(tctx, "client_guid=%s\n",
			       GUID_string(tctx, client_guid));
	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];

		talloc_asprintf_addbuf(
			&text,
			"handle=%c %"PRIu64" %"PRIu64" %s %"PRIu64" %s\n",
			t->tag,
			t->h.data[0],
			t->h.data[1],
			GUID_string(tctx, &t->create_guid),
			t->lease_key,
			GUID_string(tctx, t->exit_close ? &t->client_guid :
							  client_guid));
	}
	tmp = talloc_asprintf(tctx, "%s.tmp", path);
	if ((text == NULL) || (tmp == NULL)) {
		return false;
	}
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		return false;
	}
	ok = (write_data(fd, text, strlen(text)) == (ssize_t)strlen(text)) &&
	     (fsync(fd) == 0);
	close(fd);
	return ok && (rename(tmp, path) == 0);
}

static bool td_load(struct torture_context *tctx,
		    const char *path,
		    struct GUID *client_guid)
{
	char line[512];
	FILE *f = fopen(path, "r");
	size_t loaded = 0;

	if (f == NULL) {
		return false;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char guid[64];
		char cguid[64];
		char tag;
		uint64_t p, v, key;
		size_t i;

		if (sscanf(line, "client_guid=%63s", guid) == 1) {
			if (!NT_STATUS_IS_OK(GUID_from_string(guid,
							      client_guid))) {
				fclose(f);
				return false;
			}
			continue;
		}
		if (sscanf(line,
			   "handle=%c %"SCNu64" %"SCNu64" %63s %"SCNu64" %63s",
			   &tag, &p, &v, guid, &key, cguid) != 6) {
			continue;
		}
		for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
			struct td_handle *t = &td_handles[i];

			if (t->tag != tag) {
				continue;
			}
			t->h.data[0] = p;
			t->h.data[1] = v;
			t->lease_key = key;
			if (!NT_STATUS_IS_OK(GUID_from_string(
				    guid, &t->create_guid)) ||
			    !NT_STATUS_IS_OK(GUID_from_string(
				    cguid, &t->client_guid))) {
				fclose(f);
				return false;
			}
			loaded += 1;
		}
	}
	fclose(f);
	return loaded == ARRAY_SIZE(td_handles);
}

static NTSTATUS td_lock(struct smb2_tree *tree, struct td_handle *t)
{
	struct smb2_lock_element el = {
		.offset = 0,
		.length = TD_LOCK_LEN,
		.flags = SMB2_LOCK_FLAG_EXCLUSIVE |
			 SMB2_LOCK_FLAG_FAIL_IMMEDIATELY,
	};
	struct smb2_lock lck = {
		.in.lock_count = 1,
		.in.lock_sequence = t->lock_sequence,
		.in.file.handle = t->h,
		.in.locks = &el,
	};

	return smb2_lock(tree, &lck);
}

static void td_break_acked(struct smb2_request *req)
{
	struct smb2_lease_break_ack ack;

	(void)smb2_lease_break_ack_recv(req, &ack);
}

/* Acknowledge each lease break with the new state. */
static bool td_lease_handler(struct smb2_transport *transport,
			     const struct smb2_lease_break *lb,
			     void *private_data)
{
	struct smb2_tree *tree = private_data;
	struct smb2_lease_break_ack io = {
		.in.lease.lease_key = lb->current_lease.lease_key,
		.in.lease.lease_state = lb->new_lease_state,
	};
	struct smb2_request *req = NULL;

	if (!(lb->break_flags & SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED)) {
		return true;
	}
	req = smb2_lease_break_ack_send(tree, &io);
	if (req != NULL) {
		req->async.fn = td_break_acked;
		req->async.private_data = NULL;
	}
	return true;
}

/*
 * Open a second, not durable handle of the file of t with lease_key and
 * RWH. With t->sibling_truncate, the open overwrites the file. With
 * delete, set delete on close. With write, write the data of t. Then close
 * it.
 */
static bool td_second(struct torture_context *tctx,
		      struct smb2_tree *tree,
		      struct td_handle *t,
		      uint64_t lease_key,
		      bool write,
		      bool delete)
{
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h;
	uint8_t *buf = NULL;
	NTSTATUS status;
	bool ret = true;

	ZERO_STRUCT(io);
	smb2_lease_create(&io, &ls, false, td_final_name(t), lease_key,
			  smb2_util_lease_state("RWH"));
	if (t->sibling_truncate) {
		io.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	}
	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok(tctx, status, "second open");
	h = io.out.file.handle;
	if (write) {
		buf = talloc_array(tctx, uint8_t, TD_SIZE);
		torture_assert_goto(tctx, buf != NULL, ret, done,
				    "no memory");
		td_pattern(buf, TD_SIZE, t->tag);
		status = smb2_util_write(tree, h, buf, 0, TD_SIZE);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"second write");
	}
	if (delete) {
		union smb_setfileinfo sinfo;

		ZERO_STRUCT(sinfo);
		sinfo.disposition_info.level =
			RAW_SFILEINFO_DISPOSITION_INFORMATION;
		sinfo.disposition_info.in.file.handle = h;
		sinfo.disposition_info.in.delete_on_close = 1;
		status = smb2_setinfo_file(tree, &sinfo);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"delete on close");
	}
done:
	smb2_util_close(tree, h);
	talloc_free(buf);
	return ret;
}

/*
 * Open, write and flush t through a second client. Wait until the record
 * of t is on the standby. Then close t and disconnect the client.
 */
static bool td_exit_close(struct torture_context *tctx,
			  struct smb2_tree *tree0,
			  struct td_handle *t)
{
	struct smbcli_options options = tree0->session->transport->options;
	struct smb2_tree *tree = NULL;
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_flush f;
	uint8_t *buf = talloc_array(tctx, uint8_t, TD_SIZE);
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, buf != NULL, "no memory");
	options.client_guid = GUID_random();
	t->client_guid = options.client_guid;
	torture_assert(tctx,
		       torture_smb2_connection_ext(tctx, 0, &options, &tree),
		       "connecting the second client");
	ZERO_STRUCT(io);
	td_create(&io, &ls, t, false);
	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"durable open");
	t->h = io.out.file.handle;
	td_pattern(buf, TD_SIZE, t->tag);
	status = smb2_util_write(tree, t->h, buf, 0, TD_SIZE);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	f = (struct smb2_flush) { .in.file.handle = t->h };
	status = smb2_flush(tree, &f);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "flush");
	/* more than one tick */
	smb_msleep(3000);
	status = smb2_util_close(tree, t->h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "close");
done:
	/* The server process of the client exits. */
	talloc_free(tree);
	talloc_free(buf);
	return ret;
}

static bool td_prepare(struct torture_context *tctx,
		       struct smb2_tree *tree,
		       const char *state_path)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	uint8_t *buf = talloc_array(mem_ctx, uint8_t, TD_SIZE);
	int hold = torture_setting_int(tctx, "durable_hold", 0);
	int late = torture_setting_int(tctx, "durable_late_lock_secs", 0);
	const struct GUID *client_guid = NULL;
	struct smb2_handle dirh;
	NTSTATUS status;
	bool ret = true;
	size_t i;

	torture_assert(tctx, buf != NULL, "no memory");

	smb2_deltree(tree, TD_DIR);
	status = torture_smb2_testdir(tree, TD_DIR, &dirh);
	torture_assert_ntstatus_ok(tctx, status, "creating " TD_DIR);
	smb2_util_close(tree, dirh);
	tree->session->transport->lease.handler = td_lease_handler;
	tree->session->transport->lease.private_data = tree;

	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];
		struct smb2_create io;
		struct smb2_lease ls;

		t->create_guid = GUID_random();
		t->lease_key = random() | ((uint64_t)t->tag << 56);
		if (t->exit_close) {
			torture_assert_goto(tctx,
					    td_exit_close(tctx, tree, t),
					    ret, done, "second client");
			torture_comment(tctx, "%c: closed by a client that "
					"disconnected\n", t->tag);
			continue;
		}
		ZERO_STRUCT(io);
		td_create(&io, &ls, t, false);
		status = smb2_create(tree, mem_ctx, &io);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"durable open");
		t->h = io.out.file.handle;
		if (t->version == 2) {
			torture_assert_goto(tctx, io.out.durable_open_v2,
					    ret, done, "no durable v2 grant");
		} else {
			torture_assert_goto(tctx, io.out.durable_open,
					    ret, done, "no durable v1 grant");
		}
		if (t->lease) {
			torture_assert_int_equal_goto(
				tctx,
				io.out.lease_response.lease_state,
				smb2_util_lease_state(t->no_write ? "RH" :
								    "RWH"),
				ret, done, "lease state");
		} else {
			torture_assert_int_equal_goto(
				tctx, io.out.oplock_level,
				SMB2_OPLOCK_LEVEL_BATCH,
				ret, done, "oplock level");
		}

		td_pattern(buf, TD_SIZE, t->tag);
		status = smb2_util_write(tree, t->h, buf, 0, TD_SIZE);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"write");
		if (t->flush) {
			struct smb2_flush f = { .in.file.handle = t->h };

			status = smb2_flush(tree, &f);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "flush");
		}
		if (t->lock && !t->late_lock && (t->lock_sequence == 0)) {
			status = td_lock(tree, t);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "lock");
		}
		if (t->rename_to != NULL) {
			union smb_setfileinfo sinfo;

			ZERO_STRUCT(sinfo);
			sinfo.rename_information.level =
				RAW_SFILEINFO_RENAME_INFORMATION;
			sinfo.rename_information.in.file.handle = t->h;
			sinfo.rename_information.in.overwrite = true;
			sinfo.rename_information.in.new_name = t->rename_to;
			status = smb2_setinfo_file(tree, &sinfo);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "rename");
			if (t->flush) {
				struct smb2_flush f = {
					.in.file.handle = t->h,
				};

				status = smb2_flush(tree, &f);
				torture_assert_ntstatus_ok_goto(
					tctx, status, ret, done, "flush");
			}
		}
		torture_comment(tctx, "%c: %s open, persistent id %"PRIu64
				"\n", t->tag, td_final_name(t), t->h.data[0]);
	}

	/* These changes come after the standby has the records. */
	smb_msleep(2000);
	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];
		uint64_t key = t->break_write ? (t->lease_key ^ 1) :
						t->lease_key;

		if (t->lock_sequence != 0) {
			status = td_lock(tree, t);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "lock");
		}
		if (t->break_write || t->sibling_write || t->sibling_delete ||
		    t->sibling_truncate) {
			torture_assert_goto(tctx,
					    td_second(tctx, tree, t, key,
						      t->sibling_write,
						      t->sibling_delete),
					    ret, done, "second handle");
		}
	}
	if (late > 2) {
		smb_msleep((late - 2) * 1000);
	}
	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];

		if (!t->late_lock) {
			continue;
		}
		status = td_lock(tree, t);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"late lock");
		torture_comment(tctx, "%c: locked\n", t->tag);
	}

	client_guid = &tree->session->transport->options.client_guid;
	torture_assert_goto(tctx,
			    td_save(tctx, state_path, client_guid),
			    ret, done, "saving the client state");
	torture_comment(tctx, "state saved to %s, holding %d s\n",
			state_path, hold);
	if (hold > 0) {
		smb_msleep(hold * 1000);
	}
done:
	talloc_free(mem_ctx);
	return ret;
}

static bool td_check_data(struct torture_context *tctx,
			  struct smb2_tree *tree,
			  struct td_handle *t)
{
	struct smb2_read rd;
	uint8_t *want = talloc_array(tctx, uint8_t, TD_SIZE);
	NTSTATUS status;

	torture_assert(tctx, want != NULL, "no memory");
	td_pattern(want, TD_SIZE, t->tag);

	ZERO_STRUCT(rd);
	rd.in.file.handle = t->h;
	rd.in.length = TD_SIZE;
	rd.in.offset = 0;
	status = smb2_read(tree, tctx, &rd);
	if (t->sibling_truncate) {
		torture_assert_ntstatus_equal(tctx, status,
					      NT_STATUS_END_OF_FILE,
					      "read of the truncated file");
		return true;
	}
	torture_assert_ntstatus_ok(tctx, status, "read");
	torture_assert_int_equal(tctx, rd.out.data.length, TD_SIZE,
				 "read length");
	torture_assert_mem_equal(tctx, rd.out.data.data, want, TD_SIZE,
				 "data after reconnect");
	return true;
}

static NTSTATUS td_reconnect(struct torture_context *tctx,
			     struct smb2_tree *tree,
			     struct td_handle *t,
			     struct smb2_create *io)
{
	struct smb2_lease ls;
	NTSTATUS status;

	ZERO_STRUCTP(io);
	td_create(io, &ls, t, true);
	status = smb2_create(tree, tctx, io);
	if (NT_STATUS_IS_OK(status)) {
		t->h = io->out.file.handle;
	}
	torture_comment(tctx, "%c: reconnect %s: %s\n",
			t->tag, td_final_name(t), nt_errstr(status));
	return status;
}

/* True if verify expects t to be restored */
static bool td_wanted(const struct td_handle *t, const char *gone)
{
	if ((t->tag == 'B') || t->sibling_write || t->sibling_truncate) {
		return false;	/* unflushed writes */
	}
	if (t->exit_close || t->sibling_delete) {
		return false;	/* closed, or delete on close */
	}
	if (strchr(gone, t->tag) != NULL) {
		return false;	/* changed on disk while disconnected */
	}
	if (t->no_write && t->lock) {
		return false;	/* a disconnect closes it */
	}
	return true;
}

static bool td_rehold(struct torture_context *tctx,
		      struct smb2_tree *tree0,
		      const char *state_path)
{
	const char *out = torture_setting_string(tctx, "durable_state_out",
						 NULL);
	const char *gone = torture_setting_string(tctx, "durable_gone", "");
	int hold = torture_setting_int(tctx, "durable_hold", 0);
	struct smbcli_options options;
	struct smb2_tree *tree = NULL;
	struct GUID client_guid;
	struct smb2_create io;
	NTSTATUS status;
	bool ret = true;
	size_t i;

	torture_assert(tctx, out != NULL, "needs torture:durable_state_out");
	torture_assert(tctx, td_load(tctx, state_path, &client_guid),
		       "loading the client state");

	options = tree0->session->transport->options;
	options.client_guid = client_guid;
	torture_assert(tctx,
		       torture_smb2_connection_ext(tctx, 0, &options, &tree),
		       "connecting with the saved client GUID");

	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];

		if ((t->tag == 'E') || !td_wanted(t, gone)) {
			continue;
		}
		status = td_reconnect(tctx, tree, t, &io);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"durable reconnect");
	}
	torture_assert_goto(tctx, td_save(tctx, out, &client_guid),
			    ret, done, "saving the client state");
	torture_comment(tctx, "state saved to %s, holding %d s\n", out, hold);
	if (hold > 0) {
		smb_msleep(hold * 1000);
	}
done:
	talloc_free(tree);
	return ret;
}

static bool td_verify(struct torture_context *tctx,
		      struct smb2_tree *tree0,
		      const char *state_path)
{
	const char *gone = torture_setting_string(tctx, "durable_gone", "");
	struct smbcli_options options;
	struct smb2_tree *tree = NULL;
	struct GUID client_guid;
	struct smb2_create io;
	NTSTATUS status;
	bool ret = true;
	size_t i;

	torture_assert(tctx, td_load(tctx, state_path, &client_guid),
		       "loading the client state");

	options = tree0->session->transport->options;
	options.client_guid = client_guid;
	torture_assert(tctx,
		       torture_smb2_connection_ext(tctx, 0, &options, &tree),
		       "connecting with the saved client GUID");

	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];
		bool want = td_wanted(t, gone);

		if (t->tag == 'E') {
			continue;	/* checked below, after its timeout */
		}

		if (t->exit_close) {
			struct smb2_tree *other = NULL;

			options.client_guid = t->client_guid;
			torture_assert_goto(
				tctx,
				torture_smb2_connection_ext(tctx, 0, &options,
							    &other),
				ret, done, "connecting as the second client");
			status = td_reconnect(tctx, other, t, &io);
			talloc_free(other);
			torture_assert_ntstatus_equal_goto(
				tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ret, done, "closed handle came back");
			continue;
		}

		status = td_reconnect(tctx, tree, t, &io);
		if (!want) {
			torture_assert_ntstatus_equal_goto(
				tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ret, done, "handle came back");
			continue;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"durable reconnect");
		if (t->lease) {
			torture_assert_int_equal_goto(
				tctx, io.out.oplock_level,
				SMB2_OPLOCK_LEVEL_LEASE,
				ret, done, "lease after reconnect");
			torture_assert_int_equal_goto(
				tctx, io.out.lease_response.lease_state,
				smb2_util_lease_state(t->break_write ? "RH" :
								       "RWH"),
				ret, done, "lease state after reconnect");
		} else {
			torture_assert_int_equal_goto(
				tctx, io.out.oplock_level,
				SMB2_OPLOCK_LEVEL_BATCH,
				ret, done, "oplock after reconnect");
		}
		torture_assert_goto(tctx, td_check_data(tctx, tree, t),
				    ret, done, "data");

		if (t->lock_sequence != 0) {
			/* a replay of the lock before the failure */
			status = td_lock(tree, t);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "lock replay");
		}
		if (t->lock) {
			struct smb2_lock_element el = {
				.offset = 0,
				.length = TD_LOCK_LEN,
				.flags = SMB2_LOCK_FLAG_UNLOCK,
			};
			struct smb2_lock lck = {
				.in.lock_count = 1,
				.in.file.handle = t->h,
				.in.locks = &el,
			};

			/* the unlock succeeds only if the lock is restored */
			status = smb2_lock(tree, &lck);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done,
							"unlocking the "
							"restored lock");
			status = smb2_lock(tree, &lck);
			torture_assert_ntstatus_equal_goto(
				tctx, status, NT_STATUS_RANGE_NOT_LOCKED,
				ret, done, "second unlock");
		}
	}

	torture_comment(tctx, "waiting for the %u ms timeout of E\n",
			TD_SHORT_MSEC);
	smb_msleep(TD_SHORT_MSEC + 5000);
	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];

		if (t->tag != 'E') {
			continue;
		}
		status = td_reconnect(tctx, tree, t, &io);
		torture_assert_ntstatus_equal_goto(
			tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			ret, done, "timed out handle came back");
	}

done:
	for (i = 0; i < ARRAY_SIZE(td_handles); i++) {
		struct td_handle *t = &td_handles[i];

		smb2_util_close(tree, t->h);
	}
	smb2_deltree(tree, TD_DIR);
	talloc_free(tree);
	return ret;
}

static bool test_truenas_durable_restore(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	const char *phase = torture_setting_string(tctx, "durable_phase",
						   NULL);
	const char *state = torture_setting_string(tctx, "durable_state",
						   NULL);

	if ((phase == NULL) || (state == NULL)) {
		torture_skip(tctx, "needs torture:durable_phase and "
			     "torture:durable_state\n");
	}
	if (strcmp(phase, "prepare") == 0) {
		return td_prepare(tctx, tree, state);
	}
	if (strcmp(phase, "reconnect") == 0) {
		return td_rehold(tctx, tree, state);
	}
	if (strcmp(phase, "verify") == 0) {
		return td_verify(tctx, tree, state);
	}
	torture_fail(tctx,
		     "torture:durable_phase is prepare, reconnect or verify");
}

/*
 * truenas.durable.bench: one client of an A/B comparison of stateful
 * failover on and off. Several smbtorture processes run it against the same
 * share at the same time. Each process uses its own files.
 *
 *  torture:durable_bench=open|write|flush|lock|plain|hold
 *	open   Durable v2 open with an RWH lease, then close.
 *	write  As open, with a 64 KiB write before the close.
 *	flush  As write, with a flush after the write.
 *	lock   Lock and unlock 4 KiB of a durable handle that stays open.
 *	plain  Control: open without durability or lease, then close.
 *	hold   Open torture:durable_bench_holds durable handles. Write
 *	       "held <n>" to the out file. Keep the handles open for the
 *	       run time.
 *  torture:durable_bench_id	client number, part of the directory name
 *  torture:durable_bench_secs	run time in seconds, default 10
 *  torture:durable_bench_start	unix time when the run starts
 *  torture:durable_bench_out	file for the operation count and latencies
 *  torture:durable_bench_persistent  no, ask or require, default no
 *	ask      Request persistent handles.
 *	require  Request persistent handles. Fail if one is not granted.
 *
 * Latency buckets are 1 us wide up to 1 ms, 10 us up to 10 ms and 100 us
 * up to 100 ms. The out file has "ops <n> secs <s>" and "hist <us> <count>"
 * lines.
 */

#define TDB_FILES	16
#define TDB_WRITE	65536
#define TDB_NBUCKETS	2801

static size_t tdb_bucket(int64_t us)
{
	if (us < 1000) {
		return (us < 0) ? 0 : (size_t)us;
	}
	if (us < 10000) {
		return 1000 + (size_t)((us - 1000) / 10);
	}
	if (us < 100000) {
		return 1900 + (size_t)((us - 10000) / 100);
	}
	return TDB_NBUCKETS - 1;
}

static int64_t tdb_bucket_us(size_t b)
{
	if (b < 1000) {
		return (int64_t)b;
	}
	if (b < 1900) {
		return 1000 + (int64_t)(b - 1000) * 10;
	}
	return 10000 + (int64_t)(b - 1900) * 100;
}

struct tdb_client {
	struct smb2_tree *tree;
	const char *workload;
	char *names[TDB_FILES];
	uint64_t keys[TDB_FILES];
	uint8_t *buf;
	struct smb2_handle locked;
	int persistent;		/* 0 no, 1 ask, 2 require */
};

static NTSTATUS tdb_open(struct tdb_client *c,
			 TALLOC_CTX *mem_ctx,
			 size_t i,
			 bool durable,
			 struct smb2_handle *h)
{
	struct smb2_create io;
	struct smb2_lease ls;
	NTSTATUS status;

	ZERO_STRUCT(io);
	if (durable) {
		smb2_lease_create(&io, &ls, false, c->names[i], c->keys[i],
				  smb2_util_lease_state("RWH"));
		io.in.durable_open_v2 = true;
		io.in.persistent_open = (c->persistent != 0);
		io.in.create_guid = GUID_random();
		io.in.timeout = UINT32_MAX;
	} else {
		smb2_oplock_create(&io, c->names[i], SMB2_OPLOCK_LEVEL_NONE);
	}
	status = smb2_create(c->tree, mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (durable && (!io.out.durable_open_v2 ||
			((c->persistent == 2) && !io.out.persistent_open))) {
		smb2_util_close(c->tree, io.out.file.handle);
		return NT_STATUS_INVALID_HANDLE;
	}
	*h = io.out.file.handle;
	return NT_STATUS_OK;
}

/* One operation of the workload */
static NTSTATUS tdb_op(struct tdb_client *c, uint64_t n)
{
	TALLOC_CTX *frame = talloc_stackframe();
	size_t i = n % TDB_FILES;
	struct smb2_handle h;
	NTSTATUS status;

	if (strcmp(c->workload, "lock") == 0) {
		struct smb2_lock_element el = {
			.offset = 0,
			.length = 4096,
			.flags = SMB2_LOCK_FLAG_EXCLUSIVE |
				 SMB2_LOCK_FLAG_FAIL_IMMEDIATELY,
		};
		struct smb2_lock lck = {
			.in.lock_count = 1,
			.in.file.handle = c->locked,
			.in.locks = &el,
		};

		status = smb2_lock(c->tree, &lck);
		if (NT_STATUS_IS_OK(status)) {
			el.flags = SMB2_LOCK_FLAG_UNLOCK;
			status = smb2_lock(c->tree, &lck);
		}
		TALLOC_FREE(frame);
		return status;
	}

	status = tdb_open(c, frame, i, strcmp(c->workload, "plain") != 0, &h);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	if ((strcmp(c->workload, "write") == 0) ||
	    (strcmp(c->workload, "flush") == 0)) {
		status = smb2_util_write(c->tree, h, c->buf, 0, TDB_WRITE);
	}
	if (NT_STATUS_IS_OK(status) && (strcmp(c->workload, "flush") == 0)) {
		struct smb2_flush f = { .in.file.handle = h };

		status = smb2_flush(c->tree, &f);
	}
	if (NT_STATUS_IS_OK(status)) {
		status = smb2_util_close(c->tree, h);
	} else {
		smb2_util_close(c->tree, h);
	}
	TALLOC_FREE(frame);
	return status;
}

static bool test_truenas_durable_bench(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	const char *workload = torture_setting_string(tctx, "durable_bench",
						      NULL);
	int id = torture_setting_int(tctx, "durable_bench_id", 0);
	int secs = torture_setting_int(tctx, "durable_bench_secs", 10);
	int start = torture_setting_int(tctx, "durable_bench_start", 0);
	const char *out = torture_setting_string(tctx, "durable_bench_out",
						 NULL);
	const char *persistent = torture_setting_string(
		tctx, "durable_bench_persistent", "no");
	struct tdb_client c = {
		.tree = tree,
		.workload = workload,
		.persistent = (strcmp(persistent, "require") == 0) ? 2 :
			      (strcmp(persistent, "ask") == 0) ? 1 : 0,
	};
	uint64_t *hist = NULL;
	struct timespec t0, t1, end;
	char *dir = NULL;
	char *text = NULL;
	uint64_t ops = 0;
	NTSTATUS status;
	size_t i;
	FILE *f = NULL;

	if ((workload == NULL) || (out == NULL)) {
		torture_skip(tctx, "needs torture:durable_bench and "
			     "torture:durable_bench_out\n");
	}

	hist = talloc_zero_array(tctx, uint64_t, TDB_NBUCKETS);
	c.buf = talloc_array(tctx, uint8_t, TDB_WRITE);
	torture_assert(tctx, (hist != NULL) && (c.buf != NULL), "no memory");
	td_pattern(c.buf, TDB_WRITE, 'W');

	/* the directories can already exist */
	status = smb2_util_mkdir(tree, "truenas_durable_bench");
	dir = talloc_asprintf(tctx, "truenas_durable_bench\\c%d", id);
	status = smb2_util_mkdir(tree, dir);
	for (i = 0; i < TDB_FILES; i++) {
		struct smb2_handle h;

		c.names[i] = talloc_asprintf(tctx, "%s\\f%zu.dat", dir, i);
		c.keys[i] = ((uint64_t)id << 32) | (i + 1);
		status = tdb_open(&c, tctx, i, false, &h);
		torture_assert_ntstatus_ok(tctx, status, "creating the files");
		smb2_util_close(tree, h);
	}
	if (strcmp(workload, "lock") == 0) {
		status = tdb_open(&c, tctx, 0, true, &c.locked);
		torture_assert_ntstatus_ok(tctx, status, "durable open");
	}
	if (strcmp(workload, "hold") == 0) {
		int holds = torture_setting_int(tctx, "durable_bench_holds",
						1000);
		int n;

		for (n = 0; n < holds; n++) {
			struct smb2_handle h;

			c.names[0] = talloc_asprintf(tctx, "%s\\h%d.dat",
						     dir, n);
			c.keys[0] = ((uint64_t)id << 32) | (TDB_FILES + n);
			status = tdb_open(&c, tctx, 0, true, &h);
			torture_assert_ntstatus_ok(tctx, status, "holding");
		}
		f = fopen(out, "w");
		torture_assert(tctx, f != NULL, "opening the out file");
		fprintf(f, "held %d\n", holds);
		fclose(f);
		smb_msleep(secs * 1000);
		return true;
	}

	/* all clients start at the same time */
	while ((start != 0) && (time(NULL) < start)) {
		smb_msleep(10);
	}

	clock_gettime_mono(&t0);
	end = t0;
	end.tv_sec += secs;
	for (;;) {
		clock_gettime_mono(&t1);
		if ((t1.tv_sec > end.tv_sec) ||
		    ((t1.tv_sec == end.tv_sec) &&
		     (t1.tv_nsec >= end.tv_nsec))) {
			break;
		}
		status = tdb_op(&c, ops);
		torture_assert_ntstatus_ok(tctx, status, workload);
		clock_gettime_mono(&t0);
		hist[tdb_bucket(nsec_time_diff(&t0, &t1) / 1000)] += 1;
		ops += 1;
	}

	if (strcmp(workload, "lock") == 0) {
		smb2_util_close(tree, c.locked);
	}

	text = talloc_asprintf(tctx, "ops %"PRIu64" secs %d\n", ops, secs);
	for (i = 0; (text != NULL) && (i < TDB_NBUCKETS); i++) {
		if (hist[i] != 0) {
			talloc_asprintf_addbuf(&text,
					       "hist %"PRIi64" %"PRIu64"\n",
					       tdb_bucket_us(i),
					       hist[i]);
		}
	}
	torture_assert(tctx, text != NULL, "no memory");
	f = fopen(out, "w");
	torture_assert(tctx, f != NULL, "opening the out file");
	fputs(text, f);
	fclose(f);
	torture_comment(tctx, "%s client %d: %"PRIu64" ops in %d s\n",
			workload, id, ops, secs);
	return true;
}

/*
 * Print the file id (FileInternalInformation) of torture:fileid_path,
 * default nested\fileid.dat. The CI checks that the file id of a file in
 * a nested dataset does not change when the dataset gets another device
 * number.
 */
static bool test_truenas_durable_fileid(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	const char *path = torture_setting_string(tctx, "fileid_path",
						  "nested\\fileid.dat");
	struct smb2_create io = {
		.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = path,
	};
	union smb_fileinfo info = {
		.generic.level = RAW_FILEINFO_INTERNAL_INFORMATION,
	};
	NTSTATUS status;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok(tctx, status, "open");
	info.generic.in.file.handle = io.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &info);
	smb2_util_close(tree, io.out.file.handle);
	torture_assert_ntstatus_ok(tctx, status, "FileInternalInformation");
	torture_comment(tctx, "fileid 0x%016"PRIx64"\n",
			info.internal_information.out.file_id);
	return true;
}

void torture_truenas_durable_suite(struct torture_suite *suite)
{
	struct torture_suite *durable = torture_suite_create(
		suite, "durable");

	torture_suite_add_1smb2_test(durable, "restore",
				     test_truenas_durable_restore);
	torture_suite_add_1smb2_test(durable, "bench",
				     test_truenas_durable_bench);
	torture_suite_add_1smb2_test(durable, "fileid",
				     test_truenas_durable_fileid);
	torture_suite_add_suite(suite, durable);
}
