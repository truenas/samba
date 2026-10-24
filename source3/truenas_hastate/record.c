/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * TrueNAS: the record of a durable handle, from the open, its share
 * mode entry and its byte range locks.
 *
 * Copyright (C) iXsystems, Inc. 2026
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "truenas_hastate/truenas_hastate.h"
#include "smbd/smbXsrv_open.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "lib/util/server_id.h"
#include "messages.h"
#include "truenas_hastate/private.h"

/* The TRUENAS_FSP_* flags of fsp */
bool tn_is(const struct files_struct *fsp, uint64_t flag)
{
	return ((fsp->truenas_fsp_flags & flag) != 0);
}

void tn_set(struct files_struct *fsp, uint64_t flag, bool on)
{
	if (on) {
		fsp->truenas_fsp_flags |= flag;
	} else {
		fsp->truenas_fsp_flags &= ~flag;
	}
}

/*
 * A disconnect keeps the byte range locks of a handle only with write
 * caching and without POSIX locking (smb2.durable-open.lock-noW-lease).
 */
bool tn_locks_survive(uint32_t lease_type,
		      const struct share_params *params)
{
	return ((lease_type & SMB2_LEASE_WRITE) != 0) &&
	       !lp_posix_locking(params);
}

/*
 * True if a client can reconnect fsp after a disconnect.
 * vfs_default_durable_disconnect() uses the same rules.
 */
bool tn_fsp_survives(struct files_struct *fsp)
{
	uint32_t lease_type;

	if ((fsp->op == NULL) || !fsp->op->global->durable) {
		return false;
	}
	if (fsp->op->global->open_global_id &
	    SMBXSRV_OPEN_GLOBAL_ID_NO_RECORD) {
		return false;
	}
	lease_type = fsp_lease_type(fsp);
	if ((lease_type & SMB2_LEASE_HANDLE) == 0) {
		return false;
	}
	if ((fsp->current_lock_count != 0) &&
	    !tn_locks_survive(lease_type, fsp->conn->params)) {
		return false;
	}
	/* A disconnect closes a handle with delete on close. */
	if (fsp->fsp_flags.initial_delete_on_close ||
	    fsp->fsp_flags.delete_on_close) {
		return false;
	}
	/* smbd does not replicate the delete token of the file. */
	return !tn_is(fsp, TRUENAS_FSP_HA_DELETE_PENDING);
}

bool tn_recorded(const struct files_struct *fsp)
{
	return (fsp->op != NULL) && tn_is(fsp, TRUENAS_FSP_HA_RECORDED);
}

/*
 * The record identifies the file system of a file by f_fsid. ZFS keeps it
 * in the dataset, so an import of the pool on the other controller normally
 * keeps it. ZFS changes it when it collides with a dataset that is open in
 * that kernel. The restore then drops the records as changed. The device
 * number in a file id can change at the import.
 */
uint64_t tn_fsid(const struct statfs *sfs)
{
	return ((uint64_t)(uint32_t)sfs->f_fsid.__val[1] << 32) |
	       (uint32_t)sfs->f_fsid.__val[0];
}

/* The values of the record from the open and its share mode entry */
void tn_record_from_open(struct truenas_durable_record *r,
			 const struct smbXsrv_open_global0 *global,
			 const struct share_mode_entry *e,
			 uint64_t fsid,
			 const struct file_id *id)
{
	*r = (struct truenas_durable_record) {
		.fsid = fsid,
		.inode = id->inode,
		.extid = id->extid,
		.name_hash = e->name_hash,
		.persistent_id = global->open_persistent_id,
		.volatile_id = global->open_volatile_id,
		.owner = global->open_owner,
		.open_time = global->open_time,
		.create_guid = global->create_guid,
		.client_guid = global->client_guid,
		.app_instance_id = global->app_instance_id,
		.create_action = global->create_action,
		.disconnect_time = global->disconnect_time,
		.durable_timeout_msec = global->durable_timeout_msec,
		.channel_sequence = global->channel_sequence,
		.channel_generation = global->channel_generation,
		.op_type = e->op_type,
		.lease_key = e->lease_key,
		.access_mask = e->access_mask,
		.share_access = e->share_access,
		.share_time = timeval_to_nttime(&e->time),
		.uid = e->uid,
		.share_flags = e->flags,
	};
	memcpy(r->lock_sequence_array,
	       global->lock_sequence_array,
	       sizeof(r->lock_sequence_array));
	unix_to_nt_time(&r->updated, time(NULL));
}

/* Copy the byte range locks of the open id to r, on mem_ctx. */
bool tn_record_locks(TALLOC_CTX *mem_ctx,
		     struct truenas_durable_record *r,
		     const struct lock_struct *locks,
		     unsigned int n,
		     uint64_t id)
{
	struct truenas_durable_lock *l = NULL;
	unsigned int i;

	if (n == 0) {
		return true;
	}
	l = talloc_array(mem_ctx, struct truenas_durable_lock, n);
	if (l == NULL) {
		return false;
	}
	for (i = 0; i < n; i++) {
		if (locks[i].context.smblctx != id) {
			continue;
		}
		l[r->num_locks++] = (struct truenas_durable_lock) {
			.start = locks[i].start,
			.size = locks[i].size,
			.lock_type = locks[i].lock_type,
			.lock_flav = locks[i].lock_flav,
		};
	}
	r->locks = l;
	return true;
}

/* The record of fsp. The locks are on mem_ctx. */
static NTSTATUS tn_record_from_fsp(TALLOC_CTX *mem_ctx,
				   struct files_struct *fsp,
				   uint32_t flags,
				   struct truenas_durable_record *r)
{
	struct byte_range_lock *br_lck = NULL;
	const struct smbXsrv_open_global0 *global = fsp->op->global;
	struct server_id self = messaging_server_id(
		fsp->conn->sconn->msg_ctx);
	struct server_id disconnected = { .pid = 0 };
	struct share_mode_entry e = { .op_mid = 0 };
	bool found;

	server_id_set_disconnected(&disconnected);

	found = share_mode_entry_lookup(fsp->file_id,
					self,
					global->open_persistent_id,
					&e);
	if (!found) {
		found = share_mode_entry_lookup(fsp->file_id,
						disconnected,
						global->open_persistent_id,
						&e);
	}
	if (!found) {
		DBG_WARNING("no share mode entry for %s\n",
			    fsp_str_dbg(fsp));
		return NT_STATUS_NOT_FOUND;
	}

	tn_record_from_open(r, global, &e, fsp->hastate_fsid, &fsp->file_id);
	r->flags = flags;
	r->servicepath = fsp->conn->connectpath;
	r->base_name = fsp->fsp_name->base_name;
	r->initial_allocation_size = fsp->initial_allocation_size;
	r->position_information = fh_get_position_information(fsp->fh);
	r->write_time_forced = fsp->fsp_flags.write_time_forced;
	r->change_cookie = fsp->hastate_change_cookie;

	if ((fsp->oplock_type == LEASE_OPLOCK) && (fsp->lease != NULL)) {
		r->lease_state = fsp->lease->lease.lease_state;
		r->lease_version = fsp->lease->lease.lease_version;
		r->lease_epoch = fsp->lease->lease.lease_epoch;
	}

	br_lck = brl_get_locks_readonly(fsp);
	if ((br_lck != NULL) &&
	    !tn_record_locks(mem_ctx,
			     r,
			     brl_lock_data(br_lck),
			     brl_num_locks(br_lck),
			     global->open_persistent_id)) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/*
 * Save the change cookie of fsp from the last stat. It identifies the state
 * of the file that the client knows. The callers stat the file when the
 * handle is granted, reconnected, flushed or disconnected.
 */
void tn_baseline(struct files_struct *fsp)
{
	fsp->hastate_change_cookie = fsp->fsp_name->st.st_ex_change_cookie;
}

static uint32_t tn_fsp_flags(struct files_struct *fsp)
{
	uint32_t flags = 0;

	if (tn_is(fsp, TRUENAS_FSP_HA_DIRTY)) {
		flags |= TRUENAS_DURABLE_DIRTY;
	}
	if (tn_is(fsp, TRUENAS_FSP_HA_LOCKS_UNSTABLE)) {
		flags |= TRUENAS_DURABLE_LOCKS_UNSTABLE;
	}
	return flags;
}

/*
 * Add the put of the record of fsp to b. A record that is too large
 * becomes a delete: the standby then does not restore fsp. Returns
 * TN_PUT_OK, TN_PUT_DELETED or TN_PUT_FAILED (no record).
 */
int tn_put_record(struct smbhad_batch *b,
		  struct files_struct *fsp,
		  bool disconnected)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	uint32_t flags = tn_fsp_flags(fsp) |
			 (disconnected ? TRUENAS_DURABLE_DISCONNECTED : 0);
	struct truenas_durable_record r = { .flags = 0 };
	char *share = NULL;
	NTSTATUS status;
	int ret;

	share = lp_servicename(frame, lp_sub, SNUM(fsp->conn));
	status = tn_record_from_fsp(frame, fsp, flags, &r);
	if ((share == NULL) || !NT_STATUS_IS_OK(status)) {
		DBG_WARNING("no record for %s: %s\n",
			    fsp_str_dbg(fsp),
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return TN_PUT_FAILED;
	}
	ret = smbhad_batch_put(b,
			       share,
			       disconnected ? 0 : (uint32_t)tn_c.self.pid,
			       disconnected ? 0 : tn_c.self.unique_id,
			       &r);
	if (ret == TN_PUT_DELETED) {
		DBG_NOTICE("%s: the record is too large, not restorable\n",
			   fsp_str_dbg(fsp));
	} else if (ret != TN_PUT_OK) {
		DBG_WARNING("no record for %s: %s\n",
			    fsp_str_dbg(fsp),
			    smbhad_last_error());
	}
	TALLOC_FREE(frame);
	return ret;
}

/* Add the put of marker m to b. The marker has no owner. */
int tn_put_marker(struct smbhad_batch *b, const struct tn_marker *m)
{
	struct truenas_durable_record r = {
		.flags = TRUENAS_DURABLE_DELETE_PENDING,
		.servicepath = m->servicepath,
		.base_name = m->base_name,
		.fsid = m->fsid,
		.inode = m->file_id.inode,
		.extid = m->file_id.extid,
		.name_hash = m->name_hash,
		.persistent_id = m->id,
	};
	int ret;

	unix_to_nt_time(&r.updated, time(NULL));
	ret = smbhad_batch_put(b, m->share, 0, 0, &r);
	if (ret != TN_PUT_OK) {
		DBG_WARNING("no marker for %s: %s\n",
			    m->base_name,
			    smbhad_last_error());
	}
	return ret;
}

bool truenas_zfs_durable_cookie_push(
	TALLOC_CTX *mem_ctx,
	const struct truenas_zfs_durable_cookie *zc,
	DATA_BLOB *blob)
{
	struct smbhad_cookie c = {
		.flags = zc->flags,
		.change_cookie = zc->change_cookie,
		.inner = zc->inner.data,
		.inner_len = zc->inner.length,
	};
	size_t len;

	if (zc->share == NULL) {
		return false;
	}
	c.share = (const uint8_t *)zc->share;
	c.share_len = strlen(zc->share);
	len = smbhad_cookie_encode(&c, NULL, 0);
	if (len == 0) {
		return false;
	}
	*blob = data_blob_talloc(mem_ctx, NULL, len);
	return (blob->data != NULL) &&
	       (smbhad_cookie_encode(&c, blob->data, len) == len);
}

bool truenas_zfs_durable_cookie_pull(TALLOC_CTX *mem_ctx,
				     const DATA_BLOB *blob,
				     struct truenas_zfs_durable_cookie *zc)
{
	struct smbhad_cookie c;

	*zc = (struct truenas_zfs_durable_cookie) { .flags = 0 };
	if (!smbhad_cookie_decode(blob->data, blob->length, &c)) {
		return false;
	}
	*zc = (struct truenas_zfs_durable_cookie) {
		.flags = c.flags,
		.change_cookie = c.change_cookie,
		.share = talloc_strndup(mem_ctx,
					(const char *)c.share,
					c.share_len),
		.inner = data_blob_talloc(mem_ctx, c.inner, c.inner_len),
	};
	return (zc->share != NULL) && (zc->inner.length == c.inner_len);
}
