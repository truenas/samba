/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * TrueNAS: the pending list, the tick, the promises, and the resend of
 * the handles after a reconnect and by the scavenger.
 *
 * Copyright (C) iXsystems, Inc. 2026
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "truenas_hastate/truenas_hastate.h"
#include "smbd/smbXsrv_open.h"
#include "locking/leases_db.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "lib/util/server_id.h"
#include "lib/global_contexts.h"
#include "truenas_hastate/private.h"

static int tn_tick_ms(void)
{
	return lp_parm_int(-1, "truenas smbhad", "tick ms", 100);
}

void tn_unlink_pending(struct tn_pending *p)
{
	DLIST_REMOVE(tn_c.pending, p);
	if ((p->fsp == NULL) && (p->marker == NULL)) {
		tn_c.num_deletes -= 1;
	} else if ((p->fsp != NULL) && (p->fsp->hastate_pending == p)) {
		p->fsp->hastate_pending = NULL;
	}
	TALLOC_FREE(p);
}

/* Remove the pending entry of fsp, if it has one. */
void tn_unmark(struct files_struct *fsp)
{
	if (fsp->hastate_pending != NULL) {
		tn_unlink_pending(fsp->hastate_pending);
	}
}

static void tn_tick_fn(struct tevent_context *ev,
		       struct tevent_timer *te,
		       struct timeval current_time,
		       void *private_data);

static void tn_arm_tick(void)
{
	if (tn_c.tick_te != NULL) {
		return;
	}
	tn_c.tick_te = tevent_add_timer(
		global_event_context(),
		NULL,
		timeval_current_ofs_msec(tn_tick_ms()),
		tn_tick_fn,
		NULL);
}

/* fsp changed. smbd sends its record at the next tick. */
void tn_mark(struct files_struct *fsp)
{
	struct tn_pending *p = NULL;

	tn_this_process();
	if ((fsp->hastate_pending != NULL) || !tn_fsp_survives(fsp)) {
		/* fsp is pending already, or a disconnect closes it. */
		return;
	}
	p = talloc_zero(NULL, struct tn_pending);
	if (p == NULL) {
		return;
	}
	p->id = fsp->op->global->open_persistent_id;
	p->fsp = fsp;
	fsp->hastate_pending = p;
	DLIST_ADD_END(tn_c.pending, p);
	tn_arm_tick();
}

/*
 * The daemon is unreachable and the deletes grow, mostly in the scavenger.
 * Fence the standby's copy and drop the deletes. The daemon drops a fenced
 * copy, and each process sends its handles again. If the fence fails, try
 * again after TN_MAX_DELETES more deletes.
 */
static void tn_check_deletes(void)
{
	struct tn_pending *p = NULL, *next = NULL;

	if (tn_c.drop_at == 0) {
		tn_c.drop_at = TN_MAX_DELETES;
	}
	if ((tn_c.conn != NULL) || (tn_c.num_deletes < tn_c.drop_at)) {
		return;
	}
	if (!tn_fallback_fence()) {
		tn_c.drop_at = tn_c.num_deletes + TN_MAX_DELETES;
		return;
	}
	DBG_WARNING("%zu deletes not sent: dropped, the copy is fenced\n",
		    tn_c.num_deletes);
	for (p = tn_c.pending; p != NULL; p = next) {
		next = p->next;
		if ((p->fsp == NULL) && (p->marker == NULL)) {
			tn_unlink_pending(p);
		}
	}
	tn_c.drop_at = TN_MAX_DELETES;
}

/* smbd sends a delete of the record of id at the next tick. */
void tn_mark_delete(uint64_t id)
{
	struct tn_pending *p = NULL;

	tn_this_process();
	p = talloc_zero(NULL, struct tn_pending);
	if (p == NULL) {
		return;
	}
	p->id = id;
	DLIST_ADD_END(tn_c.pending, p);
	tn_c.num_deletes += 1;
	tn_check_deletes();
	tn_arm_tick();
}

/* smbd frees the fsp of p. p becomes a delete. */
void tn_pending_to_delete(struct tn_pending *p)
{
	p->fsp->hastate_pending = NULL;
	p->fsp = NULL;
	tn_c.num_deletes += 1;
	tn_check_deletes();
}

/* smbd sends marker m at the next tick. */
void tn_mark_marker(struct tn_marker *m)
{
	struct tn_pending *p = NULL;

	tn_this_process();
	for (p = tn_c.pending; p != NULL; p = p->next) {
		if (p->marker == m) {
			return;
		}
	}
	p = talloc_zero(NULL, struct tn_pending);
	if (p == NULL) {
		return;
	}
	p->id = m->id;
	p->marker = m;
	DLIST_ADD_END(tn_c.pending, p);
	tn_arm_tick();
}

/* The file of marker m has no delete token for its name. Delete m. */
void tn_drop_marker(struct tn_marker *m)
{
	struct tn_pending *p = NULL, *next = NULL;

	for (p = tn_c.pending; p != NULL; p = next) {
		next = p->next;
		if (p->marker == m) {
			tn_unlink_pending(p);
		}
	}
	tn_mark_delete(m->id);
	DLIST_REMOVE(tn_c.markers, m);
	TALLOC_FREE(m);
}

/*
 * Send the pending records and deletes in submits of about
 * TN_BATCH_BYTES. If fsp is not NULL, the last message also has the record
 * of fsp. Only the last message has the sync level.
 * The daemon applies the messages of a connection in order. After each
 * message, mark its handles as sent and remove their entries from the
 * pending list. Keep the entries of handles with unstable locks.
 */
bool tn_submit(uint32_t sync,
	       struct files_struct *fsp,
	       bool disconnected)
{
	struct tn_pending *p = tn_c.pending;
	int fsp_put = TN_PUT_FAILED;
	bool last = false;

	while (!last) {
		struct smbhad_batch *b = smbhad_batch_new();
		struct tn_pending *q = NULL, *next = NULL;
		bool ok = true;
		int ret = 0;

		for (; (p != NULL) && (smbhad_batch_bytes(b) < TN_BATCH_BYTES);
		     p = next) {
			next = p->next;
			p->deleted = false;
			if ((fsp != NULL) && (p->fsp == fsp)) {
				/* sent at the end */
				continue;
			}
			if (p->marker != NULL) {
				(void)tn_put_marker(b, p->marker);
				continue;
			}
			if (p->fsp == NULL) {
				smbhad_batch_del(b, p->id);
				continue;
			}
			switch (tn_put_record(b, p->fsp, false)) {
			case TN_PUT_FAILED:
				/* No record. The next change queues it. */
				tn_unlink_pending(p);
				continue;
			case TN_PUT_DELETED:
				p->deleted = true;
				break;
			case TN_PUT_OK:
				break;
			}
		}
		last = (p == NULL);
		if (last && (fsp != NULL)) {
			fsp_put = tn_put_record(b, fsp, disconnected);
			/* Do not report the change of fsp as sent. */
			ok = (fsp_put != TN_PUT_FAILED);
		}
		if (ok) {
			ret = smbhad_submit(tn_c.conn,
					    b,
					    last ? sync : TN_SYNC_NONE);
		}
		smbhad_batch_free(b);
		if (ret != 0) {
			tn_failed("sending to truenas_smbhad", ret);
		}
		if (!ok || (ret != 0)) {
			return false;
		}
		tn_c.last_used = time(NULL);
		/* The entries before p are in this message or kept. */
		for (q = tn_c.pending; q != p; q = next) {
			next = q->next;
			if ((fsp != NULL) && (q->fsp == fsp)) {
				if (last) {
					tn_unlink_pending(q);
				}
				continue;
			}
			if (q->fsp == NULL) {
				tn_unlink_pending(q);
				continue;
			}
			tn_set(q->fsp, TRUENAS_FSP_HA_SENT, !q->deleted);
			if (!q->deleted &&
			    tn_is(q->fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE)) {
				/* pending until the locks are stable */
				continue;
			}
			tn_unlink_pending(q);
		}
	}
	if (fsp != NULL) {
		tn_set(fsp, TRUENAS_FSP_HA_SENT, fsp_put == TN_PUT_OK);
	}
	return true;
}

static void tn_tick_fn(struct tevent_context *ev,
		       struct tevent_timer *te,
		       struct timeval current_time,
		       void *private_data)
{
	struct tn_pending *p = NULL;

	tn_c.tick_te = NULL;
	tn_c.tick += 1;
	/* A wait that a path without truenas_hastate_settle() left */
	truenas_hastate_settle();
	if (tn_c.pending == NULL) {
		return;
	}
	/* Locks without a change for one full tick are stable again. */
	for (p = tn_c.pending; p != NULL; p = p->next) {
		if ((p->fsp != NULL) &&
		    tn_is(p->fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE) &&
		    (p->fsp->hastate_lock_tick + 1 < tn_c.tick)) {
			tn_set(p->fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE, false);
		}
	}
	if (!tn_connect(TN_WORKER) ||
	    !tn_submit(TN_SYNC_NONE, NULL, false)) {
		DBG_INFO("truenas_smbhad unreachable, retrying\n");
	}
	if (tn_c.pending != NULL) {
		tn_arm_tick();
	}
}

/*
 * Send all pending records and deletes, and the record of fsp if fsp is not
 * NULL. On success, the standby has them or the standby's copy is fenced.
 * The caller calls this before it replies to the client. A daemon restart
 * closes the cached connection. smbd then tries once on a new connection.
 */
NTSTATUS tn_promise(struct files_struct *fsp)
{
	bool fresh;
	int i;

	tn_this_process();
	for (i = 0; i < 2; i++) {
		fresh = (tn_c.conn == NULL);
		if (tn_connect(TN_WORKER) &&
		    tn_submit(TN_SYNC_REMOTE, fsp, false)) {
			/* Unprotected: the standby's copy is fenced. */
			return NT_STATUS_OK;
		}
		if (fresh || (tn_c.conn != NULL)) {
			break;
		}
	}
	if (fsp != NULL) {
		/* The daemon can lack the change. The next tick sends it. */
		tn_mark(fsp);
	}
	if (tn_fallback_fence()) {
		return NT_STATUS_OK;
	}
	return NT_STATUS_INTERNAL_DB_ERROR;
}

struct tn_resubmit_state {
	unsigned int count;
};

static struct files_struct *tn_resubmit_fn(struct files_struct *fsp,
					   void *private_data)
{
	struct tn_resubmit_state *state = private_data;

	if (tn_recorded(fsp)) {
		tn_set(fsp, TRUENAS_FSP_HA_SENT, false);
		tn_mark(fsp);
		state->count += 1;
	}
	return NULL;
}

void tn_resubmit_all(void)
{
	struct tn_resubmit_state state = { .count = 0 };
	struct tn_marker *m = NULL;

	for (m = tn_c.markers; m != NULL; m = m->next) {
		tn_mark_marker(m);
	}
	if (tn_c.sconn == NULL) {
		return;
	}
	files_forall(tn_c.sconn, tn_resubmit_fn, &state);
	DBG_NOTICE("%u durable handles to send again\n", state.count);
}

/*
 * No smbd process holds a disconnected durable handle. When the daemon has
 * a new instance, after a restart or after it dropped its copy, the
 * processes send the handles that they hold, and the scavenger sends the
 * disconnected handles. It builds each record from the databases under the
 * share mode lock of the file, and the primary has the record before the
 * lock is released: a reconnect, and the record of the reconnecting
 * process, come after it.
 */

struct tn_resend_item {
	struct tn_resend_item *prev, *next;
	struct smbXsrv_open_global0 global;
};

struct tn_resend_collect {
	TALLOC_CTX *mem_ctx;
	struct tn_resend_item *items;
};

static int tn_resend_collect_fn(struct db_record *rec,
				struct smbXsrv_open_global0 *global,
				TDB_DATA *replay_key,
				void *private_data)
{
	struct tn_resend_collect *c = private_data;
	struct tn_resend_item *item = NULL;

	if ((global == NULL) || !global->durable ||
	    !server_id_is_disconnected(&global->server_id)) {
		return 0;
	}
	item = talloc_zero(c->mem_ctx, struct tn_resend_item);
	if (item == NULL) {
		return -1;
	}
	/* The traverse frees global. backend_cookie is its only pointer. */
	item->global = *global;
	item->global.backend_cookie = data_blob_dup_talloc(
		item, global->backend_cookie);
	DLIST_ADD_END(c->items, item);
	return 0;
}

/* Send one put or delete, and wait until the primary has it. */
static bool tn_send_one(const char *share,
			uint64_t id,
			const struct truenas_durable_record *r)
{
	struct smbhad_batch *b = smbhad_batch_new();
	int ret;

	if ((r == NULL) ||
	    (smbhad_batch_put(b, share, 0, 0, r) == TN_PUT_FAILED)) {
		smbhad_batch_del(b, id);
	}
	ret = smbhad_submit(tn_c.conn, b, TN_SYNC_LOCAL);
	smbhad_batch_free(b);
	if (ret != 0) {
		tn_failed("sending a disconnected handle", ret);
	}
	return (ret == 0);
}

struct tn_resend_state {
	const struct smbXsrv_open_global0 *global;
	const struct truenas_zfs_durable_cookie *zc;
	const struct vfs_default_durable_cookie *cookie;
	const char *share;
	uint64_t fsid;
	bool have_fsid;
	bool sent;
	bool ok;
};

static void tn_resend_locked_fn(struct share_mode_lock *lck,
				void *private_data)
{
	struct tn_resend_state *st = private_data;
	const struct smbXsrv_open_global0 *global = st->global;
	TALLOC_CTX *frame = talloc_stackframe();
	struct truenas_durable_record rec = { .flags = 0 };
	struct share_mode_entry e = { .op_mid = 0 };
	struct server_id disconnected;
	struct lock_struct *locks = NULL;
	unsigned int num_locks = 0;
	bool encoded;

	st->ok = true;
	server_id_set_disconnected(&disconnected);
	if (!share_mode_entry_lookup(st->cookie->id,
				     disconnected,
				     global->open_persistent_id,
				     &e)) {
		/* A client reconnected it, or the scavenger removed it. */
		TALLOC_FREE(frame);
		return;
	}

	tn_record_from_open(&rec, global, &e, st->fsid, &st->cookie->id);
	rec.flags = TRUENAS_DURABLE_DISCONNECTED;
	if (st->zc->flags & TRUENAS_ZFS_DURABLE_DIRTY) {
		rec.flags |= TRUENAS_DURABLE_DIRTY;
	}
	rec.change_cookie = st->zc->change_cookie;
	rec.servicepath = st->cookie->servicepath;
	rec.base_name = st->cookie->base_name;
	rec.initial_allocation_size = st->cookie->initial_allocation_size;
	rec.position_information = st->cookie->position_information;
	rec.write_time_forced = st->cookie->write_time_forced;

	/* Without the fsid, a restore cannot check the file. */
	encoded = st->have_fsid;
	if (encoded && (e.op_type == LEASE_OPLOCK)) {
		uint32_t state = 0, to_requested = 0, to_required = 0;
		uint16_t version = 0, epoch = 0;
		bool breaking = false;
		NTSTATUS status;

		status = leases_db_get(&global->client_guid,
				       &e.lease_key,
				       &st->cookie->id,
				       &state,
				       &breaking,
				       &to_requested,
				       &to_required,
				       &version,
				       &epoch);
		encoded = NT_STATUS_IS_OK(status);
		rec.lease_state = state;
		rec.lease_version = version;
		rec.lease_epoch = epoch;
	}
	if (encoded &&
	    !brl_get_disconnected_locks(frame,
					st->cookie->id,
					global->open_persistent_id,
					&locks,
					&num_locks)) {
		encoded = false;
	}
	encoded = encoded &&
		  tn_record_locks(frame,
				  &rec,
				  locks,
				  num_locks,
				  global->open_persistent_id);

	/* A record that smbd cannot build becomes a delete. */
	st->ok = tn_send_one(st->share,
			     global->open_persistent_id,
			     encoded ? &rec : NULL);
	st->sent = st->ok;
	TALLOC_FREE(frame);
}

/* Send the record of one disconnected open. False if the send failed. */
static bool tn_resend_one(TALLOC_CTX *mem_ctx,
			  const struct smbXsrv_open_global0 *global,
			  unsigned int *sent)
{
	struct truenas_zfs_durable_cookie zc = { .flags = 0 };
	struct vfs_default_durable_cookie cookie = { .version = 0 };
	struct tn_resend_state st = {
		.global = global,
		.zc = &zc,
		.cookie = &cookie,
	};
	enum ndr_err_code ndr_err;
	struct statfs sfs;
	char *path = NULL;
	NTSTATUS status;

	if (!truenas_zfs_durable_cookie_pull(mem_ctx,
					     &global->backend_cookie,
					     &zc) ||
	    (zc.share[0] == '\0')) {
		/* not recorded with truenas_smbhad */
		return true;
	}
	ndr_err = ndr_pull_struct_blob_all(
		&zc.inner, mem_ctx, &cookie,
		(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err) ||
	    (cookie.servicepath == NULL) || (cookie.base_name == NULL)) {
		return true;
	}
	st.share = zc.share;
	st.ok = true;
	path = talloc_asprintf(mem_ctx,
			       "%s/%s",
			       cookie.servicepath,
			       cookie.base_name);
	if (path != NULL) {
		become_root();
		st.have_fsid = (statfs(path, &sfs) == 0);
		unbecome_root();
	}
	if (st.have_fsid) {
		st.fsid = tn_fsid(&sfs);
	}
	status = share_mode_do_locked_vfs_allowed(cookie.id,
						  tn_resend_locked_fn,
						  &st);
	if (!NT_STATUS_IS_OK(status)) {
		/* no share mode: the open is gone */
		return true;
	}
	if (st.sent) {
		*sent += 1;
	}
	return st.ok;
}

void tn_resend_disconnected(uint64_t instance)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tn_resend_collect c = { .mem_ctx = frame };
	struct tn_resend_item *item = NULL;
	unsigned int sent = 0;
	NTSTATUS status;
	bool ok = true;

	status = smbXsrv_open_global_traverse(tn_resend_collect_fn, &c);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("reading the opens failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return;
	}
	for (item = c.items; ok && (item != NULL); item = item->next) {
		ok = tn_resend_one(frame, &item->global, &sent);
	}
	if (ok) {
		/* After a failure, the next connection tries again. */
		tn_c.resent_instance = instance;
	}
	DBG_NOTICE("%u disconnected durable handles sent to truenas_smbhad\n",
		   sent);
	TALLOC_FREE(frame);
}
