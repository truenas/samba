/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * TrueNAS: the HA state of durable handles. truenas_smbhad keeps it on
 * both controllers. Durable handles survive the loss of the controller
 * that granted them (an HA failover). This file has the hooks that smbd
 * calls.
 *
 * Copyright (C) iXsystems, Inc. 2026
 */

/*
 * With "truenas stateful failover", smbd sends a record of each durable
 * handle with handle caching to truenas_smbhad. The daemon keeps a copy of
 * the records in the memory of the standby controller. Each smbd process
 * connects to the local daemon on "truenas smbhad socket".
 *
 * A changed handle goes on the pending list of the process. The tick is a
 * timer that runs every 100 ms ("truenas smbhad:tick ms") while changes
 * are pending. At each tick, smbd sends the pending records and deletes.
 * smbd does not wait for a reply. smbd sends nothing for a handle that it
 * opens and closes between two ticks. A process with durable handles keeps
 * its connection. When the daemon restarts, the process sends all its
 * handles again.
 *
 * Some changes wait for the standby. smbd replies to the client only after
 * the standby has the change or after the standby's copy is fenced. These
 * changes are:
 * - the dirty flag, before the first change of the file after the open or
 *   a flush. The client can cache a change for all its handles of the
 *   file. smbd marks all handles of the file in the process. A flush
 *   clears the flag at the next tick: a failover before it drops the
 *   handle as unflushed.
 * - byte range lock changes, see tn_every_lock_promised()
 * - a lease change that adds write caching. An open makes this change
 *   under the share mode lock: the wait comes before the reply to the
 *   create, see truenas_hastate_created().
 * - the delete of the record of a handle that holds byte range locks, and
 *   of the handles of a file that gets delete on close, and the marker of
 *   the file, see tn_delete_pending()
 * This applies only to a handle whose record smbd sent before. If the wait
 * fails, smbd fences the standby's copy through the epoch file.
 *
 * A disconnect closes a handle with byte range locks and without write
 * caching. smbd deletes the record of such a handle. When a handle without
 * write caching gets a lock, the delete waits for the standby.
 *
 * When smbd starts after a failover, the parent restores the handles
 * before it accepts connections. The parent reads the whole copy from the
 * daemon in pages. It drops the records of a file that disagree, see
 * tn_check_file(). It writes each restored handle to the volatile
 * databases as a disconnected handle. It sends the records of the restored
 * handles to the daemon. Then it ends the rehydration. The daemon then
 * replaces the copy with the records that it received after the first
 * page.
 *
 * truenas_smbhad/client has the protocol, the record format, the durable
 * cookie of vfs_zfs_core and the fence through the epoch file.
 *
 * The daemon sends the origin of the copy and the node (A or B) that wrote
 * it. Only a copy of the other node, after a failover, is restored. After
 * a restart of smbd or of this node, smbd restores nothing and clears the
 * copy, see tn_restore_case(). A restart is how an administrator clears
 * the state of the handles.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "truenas_hastate/truenas_hastate.h"
#include "locking/share_mode_lock.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "lib/util/server_id.h"
#include "lib/global_contexts.h"
#include "messages.h"
#include "truenas_hastate/private.h"

static bool tn_durable_enabled(void)
{
	return lp_truenas_stateful_failover() && !lp_clustering();
}

/*
 * "every": each lock change waits for the standby.
 * "first": only the first lock change of a handle with stable locks waits
 * for the standby. The record then marks the locks as unstable. The locks
 * are stable again after one full tick without a lock change. smbd does
 * not restore a handle with unstable locks.
 */
static bool tn_every_lock_promised(void)
{
	const char *mode = lp_parm_const_string(-1,
						"truenas smbhad",
						"lock promises",
						"every");

	return strequal(mode, "every");
}

/*
 * The hooks
 */

/* The next change of the file of fsp marks its handles dirty again. */
static void tn_file_clean(struct files_struct *fsp)
{
	struct files_struct *s = NULL;

	for (s = file_find_di_first(fsp->conn->sconn, fsp->file_id, true);
	     s != NULL;
	     s = file_find_di_next(s, true)) {
		tn_set(s, TRUENAS_FSP_HA_FILE_DIRTY, false);
	}
}

/* smbd granted or reconnected a durable handle. */
NTSTATUS truenas_hastate_open(struct files_struct *fsp,
			      bool reconnect)
{
	struct truenas_zfs_durable_cookie zc = { .flags = 0 };
	struct statfs sfs;
	NTSTATUS status;

	if (!tn_durable_enabled() || !tn_fsp_survives(fsp)) {
		return NT_STATUS_OK;
	}
	if (!truenas_zfs_durable_cookie_pull(talloc_tos(),
					     &fsp->op->global->backend_cookie,
					     &zc)) {
		DBG_INFO("%s: not recorded, the share has no zfs_core\n",
			 fsp_str_dbg(fsp));
		return NT_STATUS_OK;
	}
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (fstatfs(fsp_get_pathref_fd(fsp), &sfs) != 0) {
		return map_nt_error_from_unix(errno);
	}
	fsp->hastate_fsid = tn_fsid(&sfs);
	if (reconnect && (zc.flags & TRUENAS_ZFS_DURABLE_DIRTY)) {
		/* unflushed changes before the disconnect */
		tn_set(fsp, TRUENAS_FSP_HA_DIRTY, true);
	}
	/* With sync=disabled, a flush does not write the data to disk. */
	tn_set(fsp,
	       TRUENAS_FSP_HA_NO_SYNC,
	       (zc.flags & TRUENAS_ZFS_DURABLE_NO_SYNC) != 0);
	tn_baseline(fsp);
	tn_set(fsp, TRUENAS_FSP_HA_RECORDED, true);
	if (!tn_is(fsp, TRUENAS_FSP_HA_DIRTY)) {
		tn_file_clean(fsp);
	}
	tn_this_process();
	tn_c.sconn = fsp->conn->sconn;
	tn_watch();
	/* The daemon has the record of a reconnected handle. */
	tn_set(fsp, TRUENAS_FSP_HA_SENT, reconnect);
	tn_mark(fsp);
	return NT_STATUS_OK;
}

/*
 * Delete the record of fsp. A disconnect now closes fsp, or smbd closes
 * fsp. A later change can record fsp again. True if a delete that must
 * wait for the standby waits for it: the standby has the record with
 * stable locks.
 */
static bool tn_unrecord(struct files_struct *fsp)
{
	bool sent = tn_is(fsp, TRUENAS_FSP_HA_SENT);
	bool unstable = tn_is(fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE);

	tn_unmark(fsp);
	if (sent) {
		tn_mark_delete(fsp->op->global->open_persistent_id);
	}
	tn_set(fsp, TRUENAS_FSP_HA_SENT | TRUENAS_FSP_HA_LOCKS_UNSTABLE, false);
	return sent && !unstable;
}

/*
 * The client disconnected and smbd kept the handle, see close_normal_file().
 * smbd waits until the local daemon applies the record (TN_SYNC_LOCAL).
 */
void truenas_hastate_disconnect(struct files_struct *fsp)
{
	struct files_struct *rec = fsp;

	if (!tn_recorded(fsp)) {
		return;
	}
	/* vfs_default_durable_disconnect() updated fsp->fsp_name->st. */
	tn_baseline(fsp);
	tn_unmark(fsp);
	if (!tn_fsp_survives(fsp)) {
		/* smbd keeps fsp, but the file has delete on close */
		(void)tn_unrecord(fsp);
		rec = NULL;
	}
	/* This record has the last lock change. */
	tn_set(fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE, false);
	if (!tn_connect(TN_WORKER) || !tn_submit(TN_SYNC_LOCAL, rec, true)) {
		DBG_WARNING("%s: disconnect not recorded\n", fsp_str_dbg(fsp));
	}
}

/*
 * Markers. smbd does not replicate the delete token of a file. Before smbd
 * sets the token, it breaks the handle caching of the other clients. Their
 * processes then delete the records of their handles at their next tick.
 * A failover before that tick can restore these handles. So the process
 * that sets the token also sends a marker of the file and waits for the
 * standby. The restore drops all records of a file with a marker. Each
 * second, the process deletes its markers whose file has no delete token
 * for their name. A marker has no owner: it stays when the process exits,
 * until the copy is cleared.
 */

struct tn_others_state {
	struct server_id self;
	bool found;
};

static bool tn_others_fn(struct share_mode_entry *e,
			 bool *modified,
			 void *private_data)
{
	struct tn_others_state *state = private_data;

	state->found = !server_id_equal(&e->pid, &state->self);
	return state->found;
}

/* True if another process has the file of fsp open, also disconnected */
static bool tn_others_open(struct files_struct *fsp)
{
	struct tn_others_state state = {
		.self = messaging_server_id(fsp->conn->sconn->msg_ctx),
	};
	size_t own = fsp->fsp_flags.no_share_mode_entry ? 0 : 1;
	struct share_mode_lock *lck = NULL;
	size_t n = 0;
	NTSTATUS status;
	bool ok;

	/* Most often fsp is the only open. That needs no lock. */
	status = share_mode_count_entries(fsp->file_id, &n);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND) ||
	    (NT_STATUS_IS_OK(status) && (n <= own))) {
		return false;
	}
	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		return false;
	}
	ok = share_mode_forall_entries(lck, tn_others_fn, &state);
	TALLOC_FREE(lck);
	return !ok || state.found;
}

static void tn_marker_fn(struct tevent_context *ev,
			 struct tevent_timer *te,
			 struct timeval current_time,
			 void *private_data);

static void tn_arm_marker_check(void)
{
	if (tn_c.marker_te != NULL) {
		return;
	}
	tn_c.marker_te = tevent_add_timer(global_event_context(),
					  NULL,
					  timeval_current_ofs(1, 0),
					  tn_marker_fn,
					  NULL);
}

static void tn_marker_fn(struct tevent_context *ev,
			 struct tevent_timer *te,
			 struct timeval current_time,
			 void *private_data)
{
	struct tn_marker *m = NULL, *next = NULL;

	tn_c.marker_te = NULL;
	for (m = tn_c.markers; m != NULL; m = next) {
		uint32_t access_mask, share_mode, lease_type;
		bool delete_on_close = false;
		NTSTATUS status;

		next = m->next;
		status = share_mode_peek_unlocked(m->file_id,
						  m->name_hash,
						  &access_mask,
						  &share_mode,
						  &lease_type,
						  &delete_on_close);
		if (NT_STATUS_IS_OK(status) && !delete_on_close) {
			tn_drop_marker(m);
		} else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			/* The file has no open handle. */
			tn_drop_marker(m);
		}
	}
	if (tn_c.markers != NULL) {
		tn_arm_marker_check();
	}
}

/*
 * If another process has the file of fsp open, make a marker of the file
 * and the name of fsp. True if smbd must wait for the standby.
 */
static bool tn_add_marker(struct files_struct *fsp)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct tn_marker *m = NULL;
	struct statfs sfs;

	tn_this_process();
	if ((fsp->op == NULL) || !tn_others_open(fsp)) {
		return false;
	}
	for (m = tn_c.markers; m != NULL; m = m->next) {
		if (file_id_equal(&m->file_id, &fsp->file_id) &&
		    (m->name_hash == fsp->name_hash)) {
			return false;
		}
	}
	if (fstatfs(fsp_get_pathref_fd(fsp), &sfs) != 0) {
		DBG_WARNING("%s: no marker: %s\n",
			    fsp_str_dbg(fsp),
			    strerror(errno));
		return false;
	}
	m = talloc_zero(NULL, struct tn_marker);
	if (m == NULL) {
		return false;
	}
	*m = (struct tn_marker) {
		.id = TN_MARKER_ID | fsp->op->global->open_persistent_id,
		.file_id = fsp->file_id,
		.name_hash = fsp->name_hash,
		.fsid = tn_fsid(&sfs),
		.share = lp_servicename(m, lp_sub, SNUM(fsp->conn)),
		.servicepath = talloc_strdup(m, fsp->conn->connectpath),
		.base_name = talloc_strdup(m, fsp->fsp_name->base_name),
	};
	if ((m->share == NULL) || (m->servicepath == NULL) ||
	    (m->base_name == NULL)) {
		TALLOC_FREE(m);
		return false;
	}
	DLIST_ADD(tn_c.markers, m);
	tn_mark_marker(m);
	tn_arm_marker_check();
	return true;
}

/*
 * Delete on close is set on the file of fsp, or the close of fsp sets it.
 * smbd must not restore the handles of the file. The deletes and the
 * marker wait for the standby.
 */
static void tn_delete_pending(struct files_struct *fsp)
{
	struct files_struct *s = NULL;
	bool promise = false;

	for (s = file_find_di_first(fsp->conn->sconn, fsp->file_id, true);
	     s != NULL;
	     s = file_find_di_next(s, true)) {
		tn_set(s, TRUENAS_FSP_HA_DELETE_PENDING, true);
		if (tn_recorded(s)) {
			promise |= tn_unrecord(s);
		}
	}
	promise |= tn_add_marker(fsp);
	if (promise && !NT_STATUS_IS_OK(tn_promise(NULL))) {
		DBG_ERR("%s: delete not replicated and not fenced\n",
			fsp_str_dbg(fsp));
	}
}

/* smbd closes the handle. No client can reconnect it. */
void truenas_hastate_close(struct files_struct *fsp)
{
	if (fsp->fsp_flags.initial_delete_on_close && tn_durable_enabled()) {
		/* The close sets delete on close if other handles stay open. */
		tn_delete_pending(fsp);
	}
	if (!tn_recorded(fsp)) {
		return;
	}
	tn_set(fsp, TRUENAS_FSP_HA_RECORDED | TRUENAS_FSP_HA_DIRTY, false);
	/* Another client can take the byte range locks after the close. */
	if (tn_unrecord(fsp) && (fsp->current_lock_count != 0) &&
	    !NT_STATUS_IS_OK(tn_promise(NULL))) {
		DBG_ERR("%s: delete not replicated and not fenced\n",
			fsp_str_dbg(fsp));
	}
}

/* smbd frees fsp. Remove the pointer to fsp from the pending list. */
void truenas_hastate_fsp_freed(struct files_struct *fsp)
{
	struct tn_pending *p = fsp->hastate_pending;

	if (p == NULL) {
		return;
	}
	if (tn_is(fsp, TRUENAS_FSP_HA_SENT) && (fsp->op != NULL)) {
		/* The close hook did not run. */
		tn_pending_to_delete(p);
		return;
	}
	tn_unlink_pending(p);
}

/*
 * smbd calls this before it changes the file of fsp, and again before the
 * reply. Until the next flush, a crash can lose the change. The client can
 * cache the change for all its handles of the file. Mark the recorded
 * handles of the file in this process dirty. Return an error only if the
 * standby does not get the dirty flag and smbd cannot fence the standby's
 * copy.
 */
NTSTATUS truenas_hastate_dirty(struct files_struct *fsp)
{
	struct files_struct *s = NULL;
	struct files_struct **marked = NULL;
	size_t i, n = 0;
	bool promise = false;
	NTSTATUS status = NT_STATUS_OK;

	if (!tn_durable_enabled() || tn_is(fsp, TRUENAS_FSP_HA_FILE_DIRTY)) {
		return NT_STATUS_OK;
	}
	for (s = file_find_di_first(fsp->conn->sconn, fsp->file_id, true);
	     s != NULL;
	     s = file_find_di_next(s, true)) {
		if (!tn_recorded(s) || tn_is(s, TRUENAS_FSP_HA_DIRTY)) {
			continue;
		}
		marked = talloc_realloc(talloc_tos(),
					marked,
					struct files_struct *,
					n + 1);
		if (marked == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		marked[n++] = s;
		tn_set(s, TRUENAS_FSP_HA_DIRTY, true);
		promise |= tn_is(s, TRUENAS_FSP_HA_SENT);
		tn_mark(s);
	}
	if (promise) {
		status = tn_promise(NULL);
	}
	if (NT_STATUS_IS_OK(status)) {
		tn_set(fsp, TRUENAS_FSP_HA_FILE_DIRTY, true);
	} else {
		/* The request fails. A retry waits for the standby again. */
		for (i = 0; i < n; i++) {
			tn_set(marked[i], TRUENAS_FSP_HA_DIRTY, false);
		}
	}
	TALLOC_FREE(marked);
	return status;
}

/*
 * A flush wrote the data of the file of fsp to disk. Clear the dirty flag
 * of the recorded handles of the file in this process. The change cookie
 * of a record includes a change that ended before the stat. A change that
 * ends after the stat marks the handles dirty again before its reply.
 */
void truenas_hastate_flushed(struct files_struct *fsp)
{
	struct files_struct *s = NULL;
	bool cleaned = false;

	if (!tn_durable_enabled()) {
		return;
	}
	for (s = file_find_di_first(fsp->conn->sconn, fsp->file_id, true);
	     s != NULL;
	     s = file_find_di_next(s, true)) {
		if (!tn_recorded(s) || !tn_is(s, TRUENAS_FSP_HA_DIRTY) ||
		    tn_is(s, TRUENAS_FSP_HA_NO_SYNC)) {
			continue;
		}
		if (!NT_STATUS_IS_OK(vfs_stat_fsp(s))) {
			continue;
		}
		tn_baseline(s);
		tn_set(s, TRUENAS_FSP_HA_DIRTY, false);
		tn_mark(s);
		cleaned = true;
	}
	if (cleaned) {
		tn_file_clean(fsp);
	}
}

/*
 * smbd changed and stored the byte range locks of fsp. The lock sequence
 * array has the value of the request. Return an error only if the standby
 * can restore fsp without the change and smbd cannot fence the standby's
 * copy.
 */
NTSTATUS truenas_hastate_locked(struct files_struct *fsp)
{
	NTSTATUS status;

	if (!tn_recorded(fsp) || !lp_locking(fsp->conn->params)) {
		return NT_STATUS_OK;
	}
	if (!tn_fsp_survives(fsp)) {
		/* The standby must not restore the handle without its lock. */
		status = tn_unrecord(fsp) ? tn_promise(NULL) : NT_STATUS_OK;
		goto done;
	}
	fsp->hastate_lock_tick = tn_c.tick;
	if (!tn_is(fsp, TRUENAS_FSP_HA_SENT)) {
		/* The standby has no record of this handle. */
		tn_mark(fsp);
		return NT_STATUS_OK;
	}
	if (tn_every_lock_promised()) {
		tn_unmark(fsp);
		status = tn_promise(fsp);
		goto done;
	}
	if (tn_is(fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE)) {
		tn_mark(fsp);
		return NT_STATUS_OK;
	}
	tn_set(fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE, true);
	tn_unmark(fsp);
	status = tn_promise(fsp);
	/* pending until the locks are stable */
	tn_mark(fsp);
done:
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("%s: lock change not replicated and not fenced\n",
			fsp_str_dbg(fsp));
	}
	return status;
}

/*
 * Delete the record of fsp, which no longer survives a disconnect. Returns
 * true if the delete must wait for the standby: fsp holds byte range locks
 * that the standby has.
 */
static bool tn_unrecord_locks(struct files_struct *fsp)
{
	return tn_unrecord(fsp) && (fsp->current_lock_count != 0);
}

/* The oplock of fsp changed. */
void truenas_hastate_update(struct files_struct *fsp)
{
	if (!tn_recorded(fsp)) {
		return;
	}
	if (!tn_fsp_survives(fsp)) {
		if (tn_unrecord_locks(fsp) &&
		    !NT_STATUS_IS_OK(tn_promise(NULL))) {
			DBG_ERR("%s: delete not replicated and not fenced\n",
				fsp_str_dbg(fsp));
		}
		return;
	}
	tn_mark(fsp);
}

/*
 * The lease of fsp changed from old_state. The handles of a lease in this
 * process share fsp->lease. A restored lease with less caching than the
 * client has is not safe. A change that adds write caching waits for the
 * standby. An open makes this change under the share mode lock, so the
 * reply to the create waits, see truenas_hastate_created(). The restore
 * merges the records of a lease, see tn_check_file().
 */
void truenas_hastate_lease(struct files_struct *fsp,
			   uint32_t old_state)
{
	struct files_struct *s = NULL;
	uint32_t new_state = fsp->lease->lease.lease_state;
	bool promise = false;
	bool upgrade = false;

	if (!tn_durable_enabled()) {
		return;
	}
	for (s = file_find_di_first(fsp->conn->sconn, fsp->file_id, true);
	     s != NULL;
	     s = file_find_di_next(s, true)) {
		if ((s->lease != fsp->lease) || !tn_recorded(s)) {
			continue;
		}
		if (!tn_fsp_survives(s)) {
			promise |= tn_unrecord_locks(s);
			continue;
		}
		upgrade |= tn_is(s, TRUENAS_FSP_HA_SENT) &&
			   (new_state & SMB2_LEASE_WRITE) &&
			   !(old_state & SMB2_LEASE_WRITE);
		tn_mark(s);
	}
	if (upgrade) {
		tn_set(fsp, TRUENAS_FSP_HA_LEASE_PROMISE, true);
	}
	if (promise && !NT_STATUS_IS_OK(tn_promise(NULL))) {
		DBG_ERR("%s: lease change not replicated and not fenced\n",
			fsp_str_dbg(fsp));
	}
}

/*
 * smbd opened fsp and does not hold the share mode lock. If the open added
 * write caching to a lease that the standby has, wait before the reply.
 */
void truenas_hastate_created(struct files_struct *fsp)
{
	if (!tn_is(fsp, TRUENAS_FSP_HA_LEASE_PROMISE)) {
		return;
	}
	tn_set(fsp, TRUENAS_FSP_HA_LEASE_PROMISE, false);
	if (!NT_STATUS_IS_OK(tn_promise(NULL))) {
		DBG_ERR("%s: lease change not replicated and not fenced\n",
			fsp_str_dbg(fsp));
	}
}

/*
 * Delete on close of a name of the file was cancelled. A handle of a name
 * without a delete token survives a disconnect again: it gets a record at
 * the next tick.
 */
static void tn_delete_cancelled(struct files_struct *fsp)
{
	struct share_mode_lock *lck = NULL;
	struct files_struct *s = NULL;

	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		return;
	}
	for (s = file_find_di_first(fsp->conn->sconn, fsp->file_id, true);
	     s != NULL;
	     s = file_find_di_next(s, true)) {
		if (!tn_is(s, TRUENAS_FSP_HA_DELETE_PENDING) ||
		    is_delete_on_close_set(lck, s->name_hash)) {
			continue;
		}
		tn_set(s, TRUENAS_FSP_HA_DELETE_PENDING, false);
		if (s != fsp) {
			truenas_hastate_update(s);
		}
	}
	TALLOC_FREE(lck);
}

/* Delete on close of fsp changed, see smb_set_file_disposition_info(). */
void truenas_hastate_delete_on_close(struct files_struct *fsp,
				     bool delete_on_close)
{
	if (!tn_durable_enabled()) {
		return;
	}
	if (delete_on_close) {
		tn_delete_pending(fsp);
		return;
	}
	tn_delete_cancelled(fsp);
	truenas_hastate_update(fsp);
}

/*
 * smbd renamed the file of fsp. The rename changes the change cookie. A
 * restore finds the file at the new name.
 */
void truenas_hastate_renamed(struct files_struct *fsp)
{
	SMB_STRUCT_STAT sbuf;

	if (!tn_recorded(fsp)) {
		return;
	}
	if (SMB_VFS_FSTAT(fsp, &sbuf) == 0) {
		fsp->hastate_change_cookie = sbuf.st_ex_change_cookie;
	}
	tn_mark(fsp);
}

/*
 * The scavenger tracks the disconnected durable handles. It keeps a
 * connection to the daemon and sends the disconnected handles to each new
 * instance of the daemon, see tn_resend_disconnected().
 */
void truenas_hastate_scavenger_start(void)
{
	if (!tn_durable_enabled()) {
		return;
	}
	tn_this_process();
	tn_c.scavenger = true;
	if (!tn_connect(TN_WORKER)) {
		tn_reconnect_later();
	}
}

/* The scavenger, a purge or a failed reconnect removed a handle. */
void truenas_hastate_forget(uint64_t open_persistent_id)
{
	if (!tn_durable_enabled()) {
		return;
	}
	tn_mark_delete(open_persistent_id);
}

/*
 * An smbd child exited. cleanupd knows only the pid. A child that exited
 * uncleanly did not disconnect its durable handles. Clients cannot
 * reconnect these handles.
 */
void truenas_hastate_forget_pid(pid_t pid)
{
	int ret;

	if (!tn_durable_enabled() || !tn_connect(TN_CLEANUPD)) {
		return;
	}
	/* unique_id 0: the processes with this pid that exited */
	ret = smbhad_forget(tn_c.conn, (uint32_t)pid);
	if (ret != 0) {
		tn_failed("forgetting a process", ret);
		return;
	}
	tn_c.last_used = time(NULL);
}

/*
 * The process exits after it closed or disconnected its handles. Send the
 * pending records and deletes.
 */
void truenas_hastate_exit(void)
{
	tn_this_process();
	if (tn_c.pending == NULL) {
		return;
	}
	if (!tn_connect(TN_WORKER) ||
	    !tn_submit(TN_SYNC_LOCAL, NULL, false)) {
		DBG_WARNING("durable handle changes not sent at exit\n");
	}
}
