/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * TrueNAS: the restore of the durable handles when smbd starts.
 *
 * Copyright (C) iXsystems, Inc. 2026
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "truenas_hastate/truenas_hastate.h"
#include "smbd/smbXsrv_open.h"
#include "smbd/scavenger.h"
#include "locking/leases_db.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "lib/util/server_id.h"
#include "auth.h"
#include "truenas_hastate/private.h"

#define TN_PAGE_BYTES (4 * 1024 * 1024)

enum tn_durable_case {
	TN_DURABLE_NONE,	/* nothing to restore */
	TN_DURABLE_RESTART,	/* this controller's records, own copy */
	TN_DURABLE_REBOOT,	/* this controller's records, from the peer */
	TN_DURABLE_FAILOVER,	/* the other controller's copy */
};

static const char *tn_case_str(enum tn_durable_case c)
{
	switch (c) {
	case TN_DURABLE_RESTART:
		return "service restart";
	case TN_DURABLE_REBOOT:
		return "reboot";
	case TN_DURABLE_FAILOVER:
		return "failover";
	case TN_DURABLE_NONE:
		break;
	}
	return "nothing to restore";
}

/* The lease type of an open, from its oplock type or lease state */
static uint32_t tn_lease_type(uint32_t op_type, uint32_t lease_state)
{
	return (op_type == LEASE_OPLOCK) ?
		lease_state : map_oplock_to_lease_type(op_type);
}

/*
 * Restore, in the parent before it accepts connections
 */

enum tn_restore_result {
	TN_RESTORED,
	TN_DROP_DIRTY,
	TN_DROP_LOCKS,
	TN_DROP_CONFLICT,
	TN_DROP_EXPIRED,
	TN_DROP_CHANGED,
	TN_DROP_FAILED,
	TN_DROP_DELETE_PENDING,
	TN_NUM_RESULTS
};

/* The results for the log */
static const char *tn_result_str[TN_NUM_RESULTS] = {
	[TN_RESTORED] = "restored",
	[TN_DROP_DIRTY] = "unflushed",
	[TN_DROP_LOCKS] = "locks",
	[TN_DROP_CONFLICT] = "caching conflict",
	[TN_DROP_EXPIRED] = "expired",
	[TN_DROP_CHANGED] = "changed",
	[TN_DROP_FAILED] = "failed",
	[TN_DROP_DELETE_PENDING] = "delete on close",
};

struct tn_restore_ctx {
	struct messaging_context *msg_ctx;
	enum tn_durable_case how;
	time_t now;
	unsigned int counts[TN_NUM_RESULTS];
};

/*
 * A record of the copy. share and body point into a page of the copy. The
 * other values come from the body. A check sets result to drop the record.
 */
struct tn_entry {
	const char *share;	/* in the page */
	DATA_BLOB body;
	char *servicepath;
	char *base_name;
	struct file_id id;	/* the devid is the fsid of the record */
	struct GUID client_guid;
	struct smb2_lease_key lease_key;
	uint32_t flags;
	uint32_t op_type;
	uint32_t lease_state;
	uint16_t lease_epoch;
	uint32_t num_locks;
	enum tn_restore_result result;
};

/* The connection of the last restored record */
struct tn_restore_conn {
	struct conn_struct_tos *c;
	const char *servicepath;	/* in the entries */
	int snum;
	/* the last share that tn_find_share() looked up */
	const char *share;
	int share_snum;
};

struct tn_restore_sm_state {
	const struct share_mode_entry *e;
	uint32_t lease_type;
	bool ok;
};

static void tn_restore_sm_fn(struct share_mode_lock *lck,
			     bool *keep_locked,
			     void *private_data)
{
	struct tn_restore_sm_state *state = private_data;

	*keep_locked = false;
	state->ok = share_mode_restore_entry(lck,
					     state->e,
					     state->lease_type);
}

/*
 * Remove the state of a partially restored open. smbd stored global. With
 * entry, smbd also stored the share mode entry.
 */
static void tn_restore_undo(const struct smbXsrv_open_global0 *global,
			    struct file_id id,
			    bool entry)
{
	NTSTATUS status;

	if (entry &&
	    !share_mode_cleanup_disconnected(id,
					     global->open_persistent_id)) {
		DBG_ERR("removing the share mode entry of open %"PRIu64
			" failed\n",
			global->open_persistent_id);
	}
	status = smbXsrv_open_global_unrestore(global);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("removing open %"PRIu64" failed: %s\n",
			global->open_persistent_id,
			nt_errstr(status));
	}
}

/*
 * Restore one record as a disconnected durable handle. Build the Samba
 * structures of this Samba version from the record. Update *rec to the
 * restored state.
 */
static enum tn_restore_result tn_restore_open(
	struct tn_restore_ctx *ctx,
	struct connection_struct *conn,
	TALLOC_CTX *mem_ctx,
	struct truenas_durable_record *rec)
{
	struct smbXsrv_open_global0 *global = NULL;
	struct vfs_default_durable_cookie cookie = { .version = 0 };
	struct truenas_zfs_durable_cookie zc = { .flags = 0 };
	const char *share_name = NULL;
	struct smb_filename *smb_fname = NULL;
	struct share_mode_entry e = { .op_mid = UINT64_MAX };
	struct share_mode_entry_prepare_state prepare_state;
	struct tn_restore_sm_state sm_state = { .e = &e };
	struct lock_struct *locks = NULL;
	const SMB_STRUCT_STAT *st = NULL;
	struct file_id file_id;
	struct statfs sfs;
	NTTIME now_nt, disconnected, until;
	uint32_t timeout_msec;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	uint32_t lease_type, i;
	bool ok;

	lease_type = tn_lease_type(rec->op_type, rec->lease_state);

	if (rec->flags & TRUENAS_DURABLE_LOCKS_UNSTABLE) {
		/* Lock changes after this record can be lost. */
		return TN_DROP_LOCKS;
	}
	if ((rec->num_locks != 0) &&
	    !tn_locks_survive(lease_type, conn->params)) {
		/* A disconnect closes such a handle. */
		return TN_DROP_LOCKS;
	}
	if ((rec->persistent_id == 0) || (rec->persistent_id > UINT32_MAX)) {
		/* The persistent id is the 32-bit global id of the open. */
		return TN_DROP_FAILED;
	}

	unix_to_nt_time(&now_nt, ctx->now);
	/* The durable timeout runs from the first disconnect. */
	disconnected = now_nt;
	if ((rec->flags & TRUENAS_DURABLE_DISCONNECTED) &&
	    (rec->disconnect_time < now_nt)) {
		disconnected = rec->disconnect_time;
	}
	/* Not longer than smbd grants: 16 minutes, for durable v1. */
	timeout_msec = MIN(rec->durable_timeout_msec, 16 * 60 * 1000);
	until = disconnected + (NTTIME)timeout_msec * 10000;
	if (until < now_nt) {
		return TN_DROP_EXPIRED;
	}

	smb_fname = synthetic_smb_fname(mem_ctx,
					rec->base_name,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		return TN_DROP_FAILED;
	}
	status = openat_pathref_fsp(conn->cwd_fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status) || !S_ISREG(smb_fname->st.st_ex_mode)) {
		return TN_DROP_CHANGED;
	}
	file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	if ((file_id.inode != rec->inode) || (file_id.extid != rec->extid) ||
	    (fstatfs(fsp_get_pathref_fd(smb_fname->fsp), &sfs) != 0) ||
	    (tn_fsid(&sfs) != rec->fsid)) {
		/* A different file has this name now. */
		return TN_DROP_CHANGED;
	}
	st = &smb_fname->fsp->fsp_name->st;
	if (!(rec->flags & TRUENAS_DURABLE_DIRTY) &&
	    (st->st_ex_change_cookie != rec->change_cookie)) {
		/* The file changed after the last tn_baseline(). */
		return TN_DROP_CHANGED;
	}

	/*
	 * The cookie for SMB_VFS_DURABLE_RECONNECT(). vfs_zfs_core reconnects
	 * the file only if its change cookie is still zc.change_cookie. Then
	 * it fills stat_info. With TRUENAS_ZFS_DURABLE_RESTORED, vfs_zfs_core
	 * sets allow_reconnect.
	 */
	cookie = (struct vfs_default_durable_cookie) {
		.id = file_id,
		.servicepath = conn->connectpath,
		.base_name = rec->base_name,
		.initial_allocation_size = rec->initial_allocation_size,
		.position_information = rec->position_information,
		.write_time_forced = rec->write_time_forced,
	};
	ndr_err = ndr_push_struct_blob(
		&zc.inner, mem_ctx, &cookie,
		(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return TN_DROP_FAILED;
	}
	zc.flags = TRUENAS_ZFS_DURABLE_RESTORED;
	if (rec->flags & TRUENAS_DURABLE_DIRTY) {
		/* The reconnect marks the handle as dirty again. */
		zc.flags |= TRUENAS_ZFS_DURABLE_DIRTY;
	}
	zc.change_cookie = st->st_ex_change_cookie;
	share_name = lp_servicename(mem_ctx,
				    loadparm_s3_global_substitution(),
				    SNUM(conn));
	if (share_name == NULL) {
		return TN_DROP_FAILED;
	}
	zc.share = share_name;

	global = talloc_zero(mem_ctx, struct smbXsrv_open_global0);
	if (global == NULL) {
		return TN_DROP_FAILED;
	}
	*global = (struct smbXsrv_open_global0) {
		.open_global_id = (uint32_t)rec->persistent_id,
		.open_persistent_id = rec->persistent_id,
		.open_volatile_id = rec->volatile_id,
		.open_owner = rec->owner,
		.open_time = rec->open_time,
		.create_guid = rec->create_guid,
		.client_guid = rec->client_guid,
		.app_instance_id = rec->app_instance_id,
		.create_action = rec->create_action,
		.disconnect_time = disconnected,
		.durable_timeout_msec = timeout_msec,
		.durable = true,
		.channel_sequence = rec->channel_sequence,
		.channel_generation = rec->channel_generation,
	};
	server_id_set_disconnected(&global->server_id);
	memcpy(global->lock_sequence_array,
	       rec->lock_sequence_array,
	       sizeof(global->lock_sequence_array));
	if (!truenas_zfs_durable_cookie_push(global,
					     &zc,
					     &global->backend_cookie)) {
		return TN_DROP_FAILED;
	}

	status = smbXsrv_open_global_restore(global);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("restoring open %"PRIu64" of %s failed: %s\n",
			    rec->persistent_id,
			    rec->base_name,
			    nt_errstr(status));
		return TN_DROP_FAILED;
	}

	e = (struct share_mode_entry) {
		.op_mid = UINT64_MAX,
		.op_type = rec->op_type,
		.client_guid = rec->client_guid,
		.lease_key = rec->lease_key,
		.access_mask = rec->access_mask,
		.share_access = rec->share_access,
		.share_file_id = rec->persistent_id,
		.uid = rec->uid,
		.flags = rec->share_flags,
		.name_hash = rec->name_hash,
	};
	nttime_to_timeval(&e.time, rec->share_time);
	server_id_set_disconnected(&e.pid);
	sm_state.lease_type = lease_type;

	status = share_mode_entry_prepare_lock_add(&prepare_state,
						   file_id,
						   conn->connectpath,
						   smb_fname,
						   tn_restore_sm_fn,
						   &sm_state);
	if (!NT_STATUS_IS_OK(status) || !sm_state.ok) {
		DBG_WARNING("restoring the share mode of open %"PRIu64
			    " of %s failed\n",
			    rec->persistent_id,
			    rec->base_name);
		tn_restore_undo(global, file_id, false);
		return TN_DROP_FAILED;
	}

	ok = true;
	if (rec->op_type == LEASE_OPLOCK) {
		status = leases_db_add(&rec->client_guid,
				       &rec->lease_key,
				       &file_id,
				       rec->lease_state,
				       rec->lease_version,
				       rec->lease_epoch,
				       conn->connectpath,
				       rec->base_name,
				       NULL);
		ok = NT_STATUS_IS_OK(status) ||
		     NT_STATUS_EQUAL(status,
				     NT_STATUS_OBJECT_NAME_COLLISION);
	}

	if (ok && (rec->num_locks != 0)) {
		locks = talloc_zero_array(mem_ctx,
					  struct lock_struct,
					  rec->num_locks);
		ok = (locks != NULL);
		for (i = 0; ok && (i < rec->num_locks); i++) {
			locks[i].start = rec->locks[i].start;
			locks[i].size = rec->locks[i].size;
			locks[i].lock_type = rec->locks[i].lock_type;
			locks[i].lock_flav = rec->locks[i].lock_flav;
		}
		if (ok) {
			ok = brl_restore_disconnected(file_id,
						      rec->persistent_id,
						      locks,
						      rec->num_locks);
		}
	}

	if (!ok) {
		DBG_WARNING("restoring the state of open %"PRIu64" of %s "
			    "failed\n",
			    rec->persistent_id,
			    rec->base_name);
		/* A client must not reconnect the open without its locks. */
		tn_restore_undo(global, file_id, true);
		return TN_DROP_FAILED;
	}

	/* The scavenger removes the handle after the durable timeout. */
	scavenger_schedule_restored(ctx->msg_ctx,
				    file_id,
				    rec->persistent_id,
				    until);

	rec->flags |= TRUENAS_DURABLE_DISCONNECTED;
	rec->updated = now_nt;
	rec->disconnect_time = disconnected;
	rec->servicepath = conn->connectpath;
	return TN_RESTORED;
}

static int tn_find_share(const char *key)
{
	int snum = lp_servicenumber(key);

	if ((snum < 0) && lp_registry_shares()) {
		process_registry_service(key);
		snum = lp_servicenumber(key);
	}
	return snum;
}

/*
 * True if this Samba version knows every value of r and a disconnect keeps
 * r. A later Samba version can give a new meaning to a new flag or value.
 * smbd drops such a record.
 */
static bool tn_record_valid(const struct truenas_durable_record *r)
{
	uint32_t lease_type;
	uint32_t i;

	/* smbhad_record_decode() checks the flags. */
	if ((r->share_flags & ~(SHARE_ENTRY_FLAG_POSIX_OPEN |
				SHARE_ENTRY_FLAG_STREAM_BASEOPEN |
				SHARE_ENTRY_FLAG_DENY_DOS |
				SHARE_ENTRY_FLAG_DENY_FCB)) ||
	    (r->lease_state & ~(SMB2_LEASE_READ |
				SMB2_LEASE_HANDLE |
				SMB2_LEASE_WRITE))) {
		return false;
	}
	switch (r->op_type) {
	case LEASE_OPLOCK:
		if ((r->lease_version != 1) && (r->lease_version != 2)) {
			return false;
		}
		break;
	case NO_OPLOCK:
	case EXCLUSIVE_OPLOCK:
	case BATCH_OPLOCK:
	case BATCH_OPLOCK|EXCLUSIVE_OPLOCK:
	case LEVEL_II_OPLOCK:
		break;
	default:
		return false;
	}
	lease_type = tn_lease_type(r->op_type, r->lease_state);
	if (!(lease_type & SMB2_LEASE_HANDLE)) {
		return false;
	}
	for (i = 0; i < r->num_locks; i++) {
		if (((r->locks[i].lock_type != READ_LOCK) &&
		     (r->locks[i].lock_type != WRITE_LOCK)) ||
		    (r->locks[i].lock_flav != WINDOWS_LOCK)) {
			return false;
		}
	}
	return true;
}

/* Read the values of e from its body. */
static void tn_entry_parse(TALLOC_CTX *mem_ctx, struct tn_entry *e)
{
	struct truenas_durable_record *r = NULL;

	e->result = TN_DROP_FAILED;
	if ((e->body.length >= 4) &&
	    (RIVAL(e->body.data, 0) != TRUENAS_DURABLE_RECORD_VERSION)) {
		DBG_WARNING("record version %u is not known\n",
			    RIVAL(e->body.data, 0));
	}
	r = smbhad_record_decode(e->body.data, e->body.length);
	if (r == NULL) {
		return;
	}
	/* A marker has no handle, see tn_check_file(). */
	if (!(r->flags & TRUENAS_DURABLE_DELETE_PENDING) &&
	    !tn_record_valid(r)) {
		DBG_WARNING("%s: the record has an unknown value\n",
			    r->base_name);
		smbhad_record_free(r);
		return;
	}
	e->servicepath = talloc_strdup(mem_ctx, r->servicepath);
	e->base_name = talloc_strdup(mem_ctx, r->base_name);
	if ((e->servicepath != NULL) && (e->base_name != NULL)) {
		e->id = (struct file_id) {
			.devid = r->fsid,
			.inode = r->inode,
			.extid = r->extid,
		};
		e->client_guid = r->client_guid;
		e->lease_key = r->lease_key;
		e->flags = r->flags;
		e->op_type = r->op_type;
		e->lease_state = r->lease_state;
		e->lease_epoch = r->lease_epoch;
		e->num_locks = r->num_locks;
		e->result = TN_RESTORED;
	}
	smbhad_record_free(r);
}

static int tn_entry_cmp_file(const struct tn_entry *x,
			     const struct tn_entry *y)
{
	if (x->id.devid != y->id.devid) {
		return NUMERIC_CMP(x->id.devid, y->id.devid);
	}
	if (x->id.inode != y->id.inode) {
		return NUMERIC_CMP(x->id.inode, y->id.inode);
	}
	return NUMERIC_CMP(x->id.extid, y->id.extid);
}

/* The records of one service path and share follow each other. */
static int tn_entry_cmp_conn(const struct tn_entry *x,
			     const struct tn_entry *y)
{
	int cmp;

	cmp = strcmp((x->servicepath != NULL) ? x->servicepath : "",
		     (y->servicepath != NULL) ? y->servicepath : "");
	if (cmp != 0) {
		return cmp;
	}
	return strcmp(x->share, y->share);
}

static bool tn_same_lease(const struct tn_entry *a, const struct tn_entry *b)
{
	return (a->op_type == LEASE_OPLOCK) && (b->op_type == LEASE_OPLOCK) &&
	       smb2_lease_equal(&a->client_guid,
				&a->lease_key,
				&b->client_guid,
				&b->lease_key);
}

/*
 * Check the records e[0..n-1] of one file. A record can be one tick older
 * than the records of other handles.
 * - A marker: the file has delete on close. Drop all records.
 * - A lease gets the states of its records with the highest epoch.
 * - After a reboot or a failover, the file can lack a change that a client
 *   cached. Drop the records of the client of a dirty record.
 * - Write caching excludes other leases and oplocks. Drop all records if
 *   one has write caching and other leases or oplocks remain.
 * - A disconnect keeps the byte range locks of one handle only. Drop the
 *   records with locks if more than one remains.
 */
static void tn_check_file(struct tn_restore_ctx *ctx,
			  struct tn_entry *e,
			  size_t n)
{
	size_t i, j, owners = 0, locked = 0;
	bool write = false;

	for (i = 0; i < n; i++) {
		if (e[i].flags & TRUENAS_DURABLE_DELETE_PENDING) {
			break;
		}
	}
	if (i < n) {
		for (i = 0; i < n; i++) {
			e[i].result = TN_DROP_DELETE_PENDING;
		}
		return;
	}

	for (i = 0; i < n; i++) {
		uint16_t epoch = e[i].lease_epoch;
		uint32_t state = 0;

		if (e[i].op_type != LEASE_OPLOCK) {
			continue;
		}
		for (j = 0; j < n; j++) {
			if (tn_same_lease(&e[i], &e[j]) &&
			    ((int16_t)(e[j].lease_epoch - epoch) > 0)) {
				epoch = e[j].lease_epoch;
			}
		}
		for (j = 0; j < n; j++) {
			if (tn_same_lease(&e[i], &e[j]) &&
			    (e[j].lease_epoch == epoch)) {
				state |= e[j].lease_state;
			}
		}
		for (j = 0; j < n; j++) {
			if (tn_same_lease(&e[i], &e[j])) {
				e[j].lease_epoch = epoch;
				e[j].lease_state = state;
			}
		}
	}

	for (i = 0; i < n; i++) {
		if (!(e[i].flags & TRUENAS_DURABLE_DIRTY)) {
			continue;
		}
		for (j = 0; j < n; j++) {
			if ((e[j].result == TN_RESTORED) &&
			    GUID_equal(&e[j].client_guid, &e[i].client_guid)) {
				e[j].result = TN_DROP_DIRTY;
			}
		}
	}

	for (i = 0; i < n; i++) {
		if (e[i].result != TN_RESTORED) {
			continue;
		}
		if (tn_lease_type(e[i].op_type, e[i].lease_state) &
		    SMB2_LEASE_WRITE) {
			write = true;
		}
		for (j = 0; j < i; j++) {
			if ((e[j].result == TN_RESTORED) &&
			    tn_same_lease(&e[i], &e[j])) {
				break;
			}
		}
		if (j == i) {
			owners += 1;
		}
		if (e[i].num_locks != 0) {
			locked += 1;
		}
	}
	for (i = 0; i < n; i++) {
		if (e[i].result != TN_RESTORED) {
			continue;
		}
		if (write && (owners > 1)) {
			e[i].result = TN_DROP_CONFLICT;
		} else if ((locked > 1) && (e[i].num_locks != 0)) {
			e[i].result = TN_DROP_LOCKS;
		}
	}
}

/* Restore the record of e. Add the restored record to base. */
static void tn_restore_entry(struct tn_restore_ctx *ctx,
			     TALLOC_CTX *mem_ctx,
			     struct tn_entry *e,
			     struct tn_restore_conn *rc,
			     struct smbhad_batch *base)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct truenas_durable_record *r = NULL;
	enum tn_restore_result res = e->result;
	const char *share = e->share;
	int snum = -1;

	if (e->flags & TRUENAS_DURABLE_DELETE_PENDING) {
		/* a marker, not a handle */
		TALLOC_FREE(frame);
		return;
	}
	if (res == TN_RESTORED) {
		/* The sort by connection groups the entries of a share. */
		if ((rc->share == NULL) || (strcmp(rc->share, share) != 0)) {
			rc->share = share;
			rc->share_snum = tn_find_share(share);
		}
		snum = rc->share_snum;
		if ((snum < 0) || !lp_durable_handles(snum) ||
		    lp_kernel_oplocks(snum) || lp_kernel_share_modes(snum)) {
			res = TN_DROP_FAILED;
		}
	}
	if ((res == TN_RESTORED) &&
	    ((rc->servicepath == NULL) || (rc->snum != snum) ||
	     (strcmp(rc->servicepath, e->servicepath) != 0))) {
		NTSTATUS status;

		TALLOC_FREE(rc->c);
		rc->snum = snum;
		rc->servicepath = e->servicepath;
		status = create_conn_struct_tos_cwd(ctx->msg_ctx,
						    snum,
						    e->servicepath,
						    get_session_info_system(),
						    &rc->c);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("connecting to %s failed: %s\n",
				    e->servicepath,
				    nt_errstr(status));
			rc->c = NULL;
		}
		/* rc->c must outlive the frame of this record. */
		talloc_steal(mem_ctx, rc->c);
	}
	if ((res == TN_RESTORED) && (rc->c == NULL)) {
		res = TN_DROP_FAILED;
	}
	if ((res == TN_RESTORED) &&
	    ((r = smbhad_record_decode(e->body.data, e->body.length)) ==
	     NULL)) {
		res = TN_DROP_FAILED;
	}
	if (res == TN_RESTORED) {
		/* the state of the lease, see tn_check_file() */
		r->lease_state = e->lease_state;
		r->lease_epoch = e->lease_epoch;
		res = tn_restore_open(ctx, rc->c->conn, frame, r);
	}

	DBG_NOTICE("[%s] %s: %s%s\n",
		   share,
		   (e->base_name != NULL) ? e->base_name : "?",
		   (res == TN_RESTORED) ? "" : "dropped, ",
		   tn_result_str[res]);

	if (res == TN_RESTORED) {
		(void)smbhad_batch_put(base, share, 0, 0, r);
	}
	ctx->counts[res] += 1;
	smbhad_record_free(r);
	TALLOC_FREE(frame);
}

/* Send the restored records of base in one submit. */
static void tn_send_baseline(struct smbhad_batch *base)
{
	int ret;

	if ((tn_c.conn == NULL) || (smbhad_batch_len(base) == 0)) {
		return;
	}
	ret = smbhad_submit(tn_c.conn, base, TN_SYNC_NONE);
	if (ret != 0) {
		tn_failed("sending the restored records", ret);
	}
}

/*
 * The case of the restore, from the writer of the copy. Only a failover
 * restores. A restart of smbd or of this node restores nothing: a restart
 * clears the state of the handles. The rehydration still ends, so the
 * daemon clears the copy and a later failover does not restore it.
 * Persistent handles, not supported, would survive a restart.
 */
static enum tn_durable_case tn_restore_case(uint32_t origin, uint32_t writer)
{
	if (origin == TN_ORIGIN_NONE) {
		return TN_DURABLE_NONE;
	}
	if (writer != tn_c.node) {
		return TN_DURABLE_FAILOVER;
	}
	if (origin != TN_ORIGIN_OWN) {
		return TN_DURABLE_REBOOT;
	}
	return TN_DURABLE_RESTART;
}

/*
 * systemd starts smbd with a start timeout, and smbd sends READY=1 after
 * the restore. A long restore asks for 30 s more every 5 s.
 */
static void tn_restore_alive(struct timespec *last,
			     const char *what,
			     size_t done,
			     size_t total)
{
	struct timespec now;
	char msg[128];

	clock_gettime_mono(&now);
	if (nsec_time_diff(&now, last) < 5 * (int64_t)1000000000) {
		return;
	}
	*last = now;
	if (total != 0) {
		snprintf(msg, sizeof(msg), "durable handles: %s %zu of %zu",
			 what, done, total);
	} else {
		snprintf(msg, sizeof(msg), "durable handles: %s", what);
	}
	daemon_extend_timeout("smbd", 30 * 1000 * 1000, msg);
}

void truenas_hastate_restore(struct messaging_context *msg_ctx)
{
	TALLOC_CTX *frame = NULL;
	struct tn_restore_ctx ctx = { .msg_ctx = msg_ctx };
	struct tn_restore_conn rc = { .snum = -1 };
	struct tn_entry *entries = NULL;
	struct smbhad_page **pages = NULL;
	size_t i, j, n = 0, alloc = 0, num_pages = 0, unreadable = 0;
	struct smbhad_batch *base = NULL;
	struct timespec t0, t1, alive;
	uint64_t cursor = 0;
	int wait_ms, waited_ms;
	bool first = true;
	bool last = false;
	unsigned int dropped = 0;

	if (!lp_truenas_stateful_failover()) {
		return;
	}
	if (lp_clustering()) {
		DBG_WARNING("durable handles are not replicated with "
			    "clustering\n");
		return;
	}

	/* The children inherit this setting through fork(). */
	share_mode_set_purged_fn(truenas_hastate_forget);
	clock_gettime_mono(&alive);

	/*
	 * smbd can start before truenas_smbhad runs as primary, for example
	 * right after a failover. If the epoch file exists (HA), wait for it.
	 */
	wait_ms = lp_parm_int(-1, "truenas smbhad", "restore wait secs", 15) *
		  1000;
	for (waited_ms = 0; !tn_connect(TN_PARENT); waited_ms += 100) {
		struct stat st;

		if ((waited_ms < wait_ms) &&
		    (stat(tn_epoch_path(), &st) == 0)) {
			tn_restore_alive(&alive,
					 "waiting for truenas_smbhad",
					 0,
					 0);
			smb_msleep(100);
			continue;
		}
		if ((stat(lp_truenas_smbhad_socket(), &st) == -1) &&
		    (errno == ENOENT)) {
			/* truenas_smbhad does not run, for example not HA. */
			DBG_NOTICE("no %s: no durable handles restored\n",
				   lp_truenas_smbhad_socket());
			return;
		}
		DBG_ERR("truenas_smbhad unreachable at %s: no durable handles "
			"restored\n",
			lp_truenas_smbhad_socket());
		return;
	}

	frame = talloc_stackframe();
	base = smbhad_batch_new();
	clock_gettime_mono(&t0);
	ctx.now = time(NULL);
	/* Read the whole copy. The entries point into the pages. */
	while (!last) {
		struct smbhad_page **tmp = NULL;
		struct smbhad_page *page = NULL;
		bool failed = false;
		int ret;

		tn_restore_alive(&alive, "reading the copy", 0, 0);
		tmp = talloc_realloc(frame,
				     pages,
				     struct smbhad_page *,
				     num_pages + 1);
		if (tmp == NULL) {
			break;
		}
		pages = tmp;
		ret = smbhad_rehydrate(tn_c.conn, cursor, TN_PAGE_BYTES, &page);
		if (ret != 0) {
			tn_failed("reading the copy", ret);
			break;
		}
		pages[num_pages++] = page;
		cursor = page->next_cursor;
		last = page->last;
		if (first) {
			ctx.how = tn_restore_case(page->origin,
						  page->writer_node);
			DBG_WARNING("durable handles: %s\n",
				    tn_case_str(ctx.how));
			first = false;
		}
		if (ctx.how != TN_DURABLE_FAILOVER) {
			break;	/* see tn_restore_case() */
		}
		for (i = 0; i < page->num_records; i++) {
			const struct smbhad_put *put = &page->records[i];

			if (n == alloc) {
				alloc = MAX(2 * alloc, 64);
				entries = talloc_realloc(frame,
							 entries,
							 struct tn_entry,
							 alloc);
				if (entries == NULL) {
					failed = true;
					break;
				}
			}
			entries[n] = (struct tn_entry) {
				.share = put->share,
				.body = data_blob_const(put->body,
							put->body_len),
			};
			tn_entry_parse(entries, &entries[n]);
			if (entries[n].result == TN_DROP_FAILED) {
				unreadable += 1;
			}
			n += 1;
		}
		if (failed) {
			DBG_ERR("reading a page of the copy failed\n");
			last = false;
			break;
		}
	}
	if (!last && (ctx.how == TN_DURABLE_FAILOVER)) {
		/* A missing record can change the checks of its file. */
		DBG_ERR("the copy is not complete: no durable handles "
			"restored\n");
		n = 0;
	}
	if (unreadable != 0) {
		/* An unreadable record has no file: it is a missing record. */
		DBG_ERR("%zu records of the copy are not readable: no durable "
			"handles restored\n",
			unreadable);
		n = 0;
	}

	TYPESAFE_QSORT(entries, n, tn_entry_cmp_file);
	for (i = 0; i < n; i = j) {
		for (j = i + 1;
		     (j < n) && file_id_equal(&entries[i].id, &entries[j].id);
		     j++) {
		}
		tn_check_file(&ctx, &entries[i], j - i);
	}
	TYPESAFE_QSORT(entries, n, tn_entry_cmp_conn);
	for (i = 0; i < n; i++) {
		tn_restore_alive(&alive, "restored", i, n);
		tn_restore_entry(&ctx, frame, &entries[i], &rc, base);
		if (smbhad_batch_bytes(base) > TN_BATCH_BYTES) {
			tn_send_baseline(base);
		}
	}
	TALLOC_FREE(rc.c);
	tn_send_baseline(base);
	smbhad_batch_free(base);
	for (i = 0; i < num_pages; i++) {
		smbhad_page_free(pages[i]);
	}

	/*
	 * Also after an error. The daemon then replaces the copy with the
	 * records that it received.
	 */
	if ((tn_c.conn != NULL) && (smbhad_done(tn_c.conn) != 0)) {
		DBG_ERR("ending the rehydration failed: %s\n",
			smbhad_last_error());
	}

	for (i = TN_DROP_DIRTY; i < TN_NUM_RESULTS; i++) {
		dropped += ctx.counts[i];
	}
	clock_gettime_mono(&t1);
	if ((ctx.how == TN_DURABLE_RESTART) || (ctx.how == TN_DURABLE_REBOOT)) {
		DBG_WARNING("durable handles after %s: none restored, the "
			    "copy is cleared\n",
			    tn_case_str(ctx.how));
	} else {
		DBG_WARNING("durable handles after %s: restored %u, dropped %u "
		    "(unflushed %u, locks %u, caching conflict %u, "
		    "expired %u, changed %u, failed %u, delete on close %u) "
		    "in %" PRIi64 " ms\n",
		    tn_case_str(ctx.how),
		    ctx.counts[TN_RESTORED],
		    dropped,
		    ctx.counts[TN_DROP_DIRTY],
		    ctx.counts[TN_DROP_LOCKS],
		    ctx.counts[TN_DROP_CONFLICT],
		    ctx.counts[TN_DROP_EXPIRED],
		    ctx.counts[TN_DROP_CHANGED],
		    ctx.counts[TN_DROP_FAILED],
		    ctx.counts[TN_DROP_DELETE_PENDING],
		    nsec_time_diff(&t1, &t0) / 1000000);
	}
	/* Each child makes its own connection. */
	tn_disconnect();
	TALLOC_FREE(frame);
}
