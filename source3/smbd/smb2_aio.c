/*
   Unix SMB/Netbios implementation.
   Version 3.0
   async_io read handling using POSIX async io.
   Copyright (C) Jeremy Allison 2005.

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/util/tevent_unix.h"
#include "lib/truenas_mempool.h"
#ifdef HAVE_LIBURING
#include "lib/truenas_uring.h"
#include "smbd/smbd_smb2_uring.h"
#include "libcli/smb/smb2_signing.h"
/* For smb2_signing_key_valid() / sign_algo_id. */

/*
 * Encrypted-PDU registered-buffer ownership: the slot must be released
 * back to the truenas_uring pool when the per-request talloc ctx is
 * torn down, regardless of whether the request completed normally or
 * was aborted.
 */
struct truenas_uring_buf_owner {
	struct truenas_uring *u;
	int slot;
};

static int truenas_uring_buf_owner_destructor(struct truenas_uring_buf_owner *o)
{
	if (o->slot >= 0) {
		truenas_uring_buf_release(o->u, o->slot);
		o->slot = -1;
	}
	return 0;
}
#endif

/****************************************************************************
 Accessor function to return write_through state.
*****************************************************************************/

bool aio_write_through_requested(struct aio_extra *aio_ex)
{
	return aio_ex->write_through;
}

/****************************************************************************
 Create the extended aio struct we must keep around for the lifetime
 of the aio call.
*****************************************************************************/

struct aio_extra *create_aio_extra(TALLOC_CTX *mem_ctx,
				   files_struct *fsp,
				   size_t buflen)
{
	struct aio_extra *aio_ex = talloc_zero(mem_ctx, struct aio_extra);

	if (!aio_ex) {
		return NULL;
	}

	/* The output buffer stored in the aio_ex is the start of
	   the smb return buffer. The buffer used in the acb
	   is the start of the reply data portion of that buffer. */

	if (buflen) {
		aio_ex->outbuf = data_blob_talloc(aio_ex, NULL, buflen);
		if (!aio_ex->outbuf.data) {
			TALLOC_FREE(aio_ex);
			return NULL;
		}
	}
	aio_ex->fsp = fsp;
	return aio_ex;
}

struct aio_req_fsp_link {
#ifdef DEVELOPER
	struct smbd_server_connection *sconn;
#endif
	files_struct *fsp;
	struct tevent_req *req;
};

static int aio_del_req_from_fsp(struct aio_req_fsp_link *lnk)
{
	unsigned i;
	files_struct *fsp = lnk->fsp;
	struct tevent_req *req = lnk->req;

#ifdef DEVELOPER
	struct files_struct *ifsp = NULL;
	bool found = false;

	/*
	 * When this is called, lnk->fsp must still exist
	 * on the files list for this connection. Panic if not.
	 */
	for (ifsp = lnk->sconn->files; ifsp; ifsp = ifsp->next) {
		if (ifsp == fsp) {
			found = true;
		}
	}
	if (!found) {
		smb_panic("orphaned lnk on fsp aio list.\n");
	}
#endif

	for (i=0; i<fsp->num_aio_requests; i++) {
		if (fsp->aio_requests[i] == req) {
			break;
		}
	}
	if (i == fsp->num_aio_requests) {
		DEBUG(1, ("req %p not found in fsp %p\n", req, fsp));
		return 0;
	}
	fsp->num_aio_requests -= 1;
	fsp->aio_requests[i] = fsp->aio_requests[fsp->num_aio_requests];

	if (fsp->num_aio_requests == 0) {
		TALLOC_FREE(fsp->aio_requests);
	}
	return 0;
}

struct aio_req_fsp_link *aio_add_req_to_fsp(files_struct *fsp, struct tevent_req *req)
{
	size_t array_len;
	struct aio_req_fsp_link *lnk;

	lnk = talloc(req, struct aio_req_fsp_link);
	if (lnk == NULL) {
		return NULL;
	}

	array_len = talloc_array_length(fsp->aio_requests);
	if (array_len <= fsp->num_aio_requests) {
		struct tevent_req **tmp;

		if (fsp->num_aio_requests + 10 < 10) {
			/* Integer wrap. */
			TALLOC_FREE(lnk);
			return NULL;
		}

		/*
		 * Allocate in blocks of 10 so we don't allocate
		 * on every aio request.
		 */
		tmp = talloc_realloc(
			fsp, fsp->aio_requests, struct tevent_req *,
			fsp->num_aio_requests+10);
		if (tmp == NULL) {
			TALLOC_FREE(lnk);
			return NULL;
		}
		fsp->aio_requests = tmp;
	}
	fsp->aio_requests[fsp->num_aio_requests] = req;
	fsp->num_aio_requests += 1;

	lnk->fsp = fsp;
	lnk->req = req;
#ifdef DEVELOPER
	lnk->sconn = fsp->conn->sconn;
#endif
	talloc_set_destructor(lnk, aio_del_req_from_fsp);

	return lnk;
}

struct pwrite_fsync_state {
	struct tevent_context *ev;
	files_struct *fsp;
	bool write_through;
	ssize_t nwritten;
};

static void pwrite_fsync_write_done(struct tevent_req *subreq);
static void pwrite_fsync_sync_done(struct tevent_req *subreq);

struct tevent_req *pwrite_fsync_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct files_struct *fsp,
				     const void *data,
				     size_t n, off_t offset,
				     bool write_through)
{
	struct tevent_req *req, *subreq;
	struct pwrite_fsync_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state, struct pwrite_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fsp = fsp;
	state->write_through = write_through;

	ok = vfs_valid_pwrite_range(fsp, offset, n);
	if (!ok) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	if (n == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_PWRITE_SEND(state, ev, fsp, data, n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, pwrite_fsync_write_done, req);
	return req;
}

static void pwrite_fsync_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct pwrite_fsync_state *state = tevent_req_data(
		req, struct pwrite_fsync_state);
	connection_struct *conn = state->fsp->conn;
	bool do_sync;
	struct vfs_aio_state vfs_aio_state;

	state->nwritten = SMB_VFS_PWRITE_RECV(subreq, &vfs_aio_state);
	TALLOC_FREE(subreq);
	if (state->nwritten == -1) {
		tevent_req_error(req, vfs_aio_state.error);
		return;
	}

	do_sync = (lp_strict_sync(SNUM(conn)) &&
		   (lp_sync_always(SNUM(conn)) || state->write_through));
	if (!do_sync) {
		tevent_req_done(req);
		return;
	}

	subreq = SMB_VFS_FSYNC_SEND(state, state->ev, state->fsp);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, pwrite_fsync_sync_done, req);
}

static void pwrite_fsync_sync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	struct vfs_aio_state vfs_aio_state;

	ret = SMB_VFS_FSYNC_RECV(subreq, &vfs_aio_state);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, vfs_aio_state.error);
		return;
	}
	tevent_req_done(req);
}

ssize_t pwrite_fsync_recv(struct tevent_req *req, int *perr)
{
	struct pwrite_fsync_state *state = tevent_req_data(
		req, struct pwrite_fsync_state);

	if (tevent_req_is_unix_error(req, perr)) {
		return -1;
	}
	return state->nwritten;
}

bool cancel_smb2_aio(struct smb_request *smbreq)
{
	struct smbd_smb2_request *smb2req = smbreq->smb2req;
	struct aio_extra *aio_ex = NULL;

	if (smb2req) {
		aio_ex = talloc_get_type(smbreq->async_priv,
					 struct aio_extra);
	}

	if (aio_ex == NULL) {
		return false;
	}

	if (aio_ex->fsp == NULL) {
		return false;
	}

	/*
	 * We let the aio request run and don't try to cancel it which means
	 * processing of the SMB2 request must continue as normal, cf MS-SMB2
	 * 3.3.5.16:
	 *
	 *   If the target request is not successfully canceled, processing of
	 *   the target request MUST continue and no response is sent to the
	 *   cancel request.
	 */

	return false;
}

static void aio_pread_smb2_done(struct tevent_req *req);

/****************************************************************************
 Set up an aio request from a SMB2 read call.
*****************************************************************************/

NTSTATUS schedule_smb2_aio_read(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				TALLOC_CTX *ctx,
				DATA_BLOB *preadbuf,
				off_t startpos,
				size_t smb_maxcnt)
{
	struct aio_extra *aio_ex;
	size_t min_aio_read_size = lp_aio_read_size(SNUM(conn));
	struct tevent_req *req;
	bool is_compound = false;
	bool is_last_in_compound = false;
	bool ok;

	ok = vfs_valid_pread_range(startpos, smb_maxcnt);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp_is_alternate_stream(fsp)) {
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return NT_STATUS_RETRY;
	}

	if (fsp->op == NULL) {
		/* No AIO on internal opens. */
		return NT_STATUS_RETRY;
	}

	if ((!min_aio_read_size || (smb_maxcnt < min_aio_read_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a read for aio request. */
		DEBUG(10,("smb2: read size (%u) too small "
			"for minimum aio_read of %u\n",
			(unsigned int)smb_maxcnt,
			(unsigned int)min_aio_read_size ));
		return NT_STATUS_RETRY;
	}

	is_compound = smbd_smb2_is_compound(smbreq->smb2req);
	is_last_in_compound = smbd_smb2_is_last_in_compound(smbreq->smb2req);

	if (is_compound && !is_last_in_compound) {
		/*
		 * Only allow going async if this is the last
		 * request in a compound.
		 */
		return NT_STATUS_RETRY;
	}

	/*
	 * Create the out buffer for the READ.
	 *
	 * All reads (plain and encrypted) are served from the reclaimable
	 * io_memory_pool: data is pread into a reused (non-pinned, swappable)
	 * pool buffer -- one copy -- and the response is sent straight from it
	 * via IORING_OP_SENDMSG_ZC. No registered/pinned RAM, so this scales to
	 * thousands of smbds; the pool is freed after an idle interval.
	 *
	 * On ZFS the registered (pinned) fixed-buffer pool buys nothing
	 * (READ_FIXED only helps DMA, not buffered ARC copies; and multi-iov
	 * SENDMSG_ZC can't use FIXED_BUF), so it is opt-in only
	 * (fixed_buffer_pool_count > 0). When enabled, encrypted reads grab a
	 * pinned slot below for in-place AEAD; otherwise -- and for the
	 * encrypted path when the pool is off/exhausted -- the mempool is used.
	 * Slot release (when used) is driven by a talloc destructor on a tiny
	 * owner parented to ctx, so it returns on normal completion or abort.
	 */
#ifdef HAVE_LIBURING
	if (smbreq->smb2req != NULL && smbreq->smb2req->do_encryption) {
		struct truenas_uring *u = truenas_uring_get(
			fsp->conn->sconn->ev_ctx);
		int slot = (u != NULL) ?
			truenas_uring_buf_acquire(u, smb_maxcnt) : -1;

		if (slot >= 0) {
			struct truenas_uring_buf_owner *owner;
			struct smbXsrv_connection *xconn =
				smbreq->smb2req->xconn;
			NTSTATUS cs;

			owner = talloc(ctx, struct truenas_uring_buf_owner);
			if (owner == NULL) {
				truenas_uring_buf_release(u, slot);
				return NT_STATUS_NO_MEMORY;
			}
			owner->u = u;
			owner->slot = slot;
			talloc_set_destructor(owner,
				truenas_uring_buf_owner_destructor);

			preadbuf->data = truenas_uring_buf_data(u, slot, NULL);
			preadbuf->length = smb_maxcnt;

			if (xconn != NULL && xconn->smb2.uring != NULL) {
				xconn->smb2.uring->counters.encrypted_recv++;
				xconn->smb2.uring->counters
					.bytes_encrypted_out += smb_maxcnt;
			}
			cs = truenas_uring_charge_recv_bytes(ctx, xconn,
							     smb_maxcnt);
			if (!NT_STATUS_IS_OK(cs)) {
				return cs;
			}
		}
	}
#endif
	if (preadbuf->data == NULL) {
		/*
		 * Default path: reclaimable io_memory_pool buffer, sent
		 * zero-copy via SENDMSG_ZC. Used by all plain reads and by
		 * encrypted reads when the opt-in registered pool is off.
		 */
		struct io_pool_link *io_lnk = NULL;

		if (!io_pool_alloc_blob(conn, ctx, smb_maxcnt, preadbuf,
					&io_lnk)) {
			return NT_STATUS_NO_MEMORY;
		}
#ifdef HAVE_LIBURING
		if (smbreq->smb2req != NULL &&
		    smbreq->smb2req->xconn != NULL &&
		    smbreq->smb2req->xconn->smb2.uring != NULL) {
			struct samba_uring_counters *cnt =
				&smbreq->smb2req->xconn->smb2.uring->counters;
			if (smbreq->smb2req->do_encryption) {
				cnt->encrypted_recv++;
				cnt->bytes_encrypted_out += smb_maxcnt;
			} else {
				cnt->unsigned_recv_mempool++;
				cnt->bytes_unsigned_mempool_out += smb_maxcnt;
			}
		}
		{
			NTSTATUS cs = truenas_uring_charge_recv_bytes(
				ctx, smbreq->smb2req->xconn, smb_maxcnt);
			if (!NT_STATUS_IS_OK(cs)) {
				return cs;
			}
		}
#endif
	}

	if (!(aio_ex = create_aio_extra(smbreq->smb2req, fsp, 0))) {
		return NT_STATUS_NO_MEMORY;
	}

	init_strict_lock_struct(fsp,
			fsp->op->global->open_persistent_id,
			(uint64_t)startpos,
			(uint64_t)smb_maxcnt,
			READ_LOCK,
			&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	aio_ex->nbyte = smb_maxcnt;
	aio_ex->offset = startpos;

	req = SMB_VFS_PREAD_SEND(aio_ex, fsp->conn->sconn->ev_ctx, fsp,
				 preadbuf->data, smb_maxcnt, startpos);
	if (req == NULL) {
		DEBUG(0, ("smb2: SMB_VFS_PREAD_SEND failed. "
			  "Error %s\n", strerror(errno)));
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}
	tevent_req_set_callback(req, aio_pread_smb2_done, aio_ex);

	if (!aio_add_req_to_fsp(fsp, req)) {
		DEBUG(1, ("Could not add req to fsp\n"));
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}

	/* We don't need talloc_move here as both aio_ex and
	 * smbreq are children of smbreq->smb2req. */
	aio_ex->smbreq = smbreq;
	smbreq->async_priv = aio_ex;

	DEBUG(10,("smb2: scheduled aio_read for file %s, "
		"offset %.0f, len = %u (mid = %u)\n",
		fsp_str_dbg(fsp), (double)startpos, (unsigned int)smb_maxcnt,
		(unsigned int)aio_ex->smbreq->mid ));

	return NT_STATUS_OK;
}

static void aio_pread_smb2_done(struct tevent_req *req)
{
	struct aio_extra *aio_ex = tevent_req_callback_data(
		req, struct aio_extra);
	struct tevent_req *subreq = aio_ex->smbreq->smb2req->subreq;
	files_struct *fsp = aio_ex->fsp;
	NTSTATUS status;
	ssize_t nread;
	struct vfs_aio_state vfs_aio_state = { 0 };

	nread = SMB_VFS_PREAD_RECV(req, &vfs_aio_state);
	TALLOC_FREE(req);

	DEBUG(10, ("pread_recv returned %d, err = %s\n", (int)nread,
		   (nread == -1) ? strerror(vfs_aio_state.error) : "no error"));

	/* Common error or success code processing for async or sync
	   read returns. */

	status = smb2_read_complete(subreq, nread, vfs_aio_state.error);

	if (nread > 0) {
		fh_set_pos(fsp->fh, aio_ex->offset + nread);
		fh_set_position_information(fsp->fh,
						fh_get_pos(fsp->fh));
	}

	DEBUG(10, ("smb2: scheduled aio_read completed "
		   "for file %s, offset %.0f, len = %u "
		   "(errcode = %d, NTSTATUS = %s)\n",
		   fsp_str_dbg(aio_ex->fsp),
		   (double)aio_ex->offset,
		   (unsigned int)nread,
		   vfs_aio_state.error, nt_errstr(status)));

	if (tevent_req_nterror(subreq, status)) {
		return;
	}
	tevent_req_done(subreq);
}

static void aio_pwrite_smb2_done(struct tevent_req *req);

#ifdef HAVE_LIBURING
/****************************************************************************
 Unsigned splice inbound WRITE (socket -> pipe -> file). Activated when
 the master knob `truenas_uring:enabled` is on AND the request arrived
 via the short-recvfile path (smbreq->unread_bytes != 0) AND the PDU
 carries no SMB2_HDR_FLAG_SIGNED (signed PDUs take the verify-before-
 write path in signed_splice_in_*). Mirrors the outbound splice flow in
 smbd_smb2_flush_with_sendmsg_uring but for the receive direction.
*****************************************************************************/

struct splice_write_state {
	/*
	 * We can't capture smb2req->subreq at schedule time -- that field is
	 * set by smbd_smb2_request_dispatch AFTER smbd_smb2_write_send
	 * returns. Defer the lookup to callback time via smbreq->smb2req->subreq.
	 */
	struct smb_request *smbreq;
	struct smbXsrv_connection *xconn;
	files_struct *fsp;
	off_t offset_orig;       /* file offset where the WRITE starts */
	size_t total_len;        /* total bytes to move from socket to file */
	size_t sock_consumed;    /* bytes already spliced socket -> pipe */
	size_t file_done;        /* bytes already spliced pipe   -> file */
	struct truenas_uring_pipe pipe;
	size_t pipe_cap;             /* usable capacity of the request's pipe */
	struct lock_struct lock;
	bool write_through;
	bool socket_released;        /* socket-reader claim already dropped? */
	struct file_modified_state modified_state;
	unsigned int zero_retries;   /* splice-returned-0 retries before EOF */
};

static void splice_write_sock_to_pipe_done(struct tevent_req *subreq);
static void splice_write_pipe_to_file_done(struct tevent_req *subreq);
static void splice_write_pump_socket(struct splice_write_state *state);
static void splice_write_drain_pipe(struct splice_write_state *state);
static void splice_write_finish(struct splice_write_state *state,
				NTSTATUS status, int err);

static void splice_write_release_pipe(struct splice_write_state *state)
{
	struct truenas_uring *u;
	if (state->pipe.slot < 0) {
		return;
	}
	u = truenas_uring_get(state->xconn->client->raw_ev_ctx);
	if (u != NULL) {
		truenas_uring_pipe_release(u, state->pipe.slot);
	}
	state->pipe.slot = -1;
}

/*
 * Drop the socket-reader claim and re-arm the recv state machine. While
 * SAMBA_URING_INFLIGHT_SPLICE_RECV is set, smbd_smb2_request_next_incoming
 * refuses to read the next PDU so it can't race the splice for this WRITE's
 * body bytes. We call this the instant the body is fully off the socket --
 * NOT at finish -- so the pipe->file drain (and the ZFS write behind it)
 * overlaps the next request's socket read. Idempotent: guarded by
 * state->socket_released so a later finish() can't clear a claim that a
 * successor request has since taken.
 */
static void splice_write_release_socket(struct splice_write_state *state)
{
	if (state->socket_released) {
		return;
	}
	state->socket_released = true;
	state->xconn->smb2.uring->inflight &= ~SAMBA_URING_INFLIGHT_SPLICE_RECV;
	(void)smbd_smb2_request_next_incoming(state->xconn);
}

NTSTATUS truenas_schedule_smb2_unsigned_splice_write(connection_struct *conn,
				    struct smb_request *smbreq,
				    files_struct *fsp,
				    uint64_t in_offset,
				    DATA_BLOB in_data,
				    bool write_through)
{
	struct smbXsrv_connection *xconn = smbreq->xconn;
	struct splice_write_state *state = NULL;
	struct truenas_uring *u = NULL;
	bool is_compound, is_last_in_compound;

	if (!xconn->smb2.uring->enabled.splice_recv) {
		return NT_STATUS_RETRY;
	}
	if (smbreq->unread_bytes == 0) {
		/* Not a short-recvfile WRITE -- normal aio handles it. */
		return NT_STATUS_RETRY;
	}
	if (smbreq->unread_bytes != in_data.length) {
		/* Inconsistent state -- legacy path's domain. */
		return NT_STATUS_RETRY;
	}
	/*
	 * Enforce the same offset/length bounds the legacy aio_write path
	 * enforces via pwrite_fsync_send -> vfs_valid_pwrite_range. The
	 * kernel splice path otherwise bypasses this check and would happily
	 * write past the configured MAXFILESIZE (samba3 fork: 64 TiB).
	 */
	if (!vfs_valid_pwrite_range(fsp, (off_t)in_offset, in_data.length)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (fsp_is_alternate_stream(fsp)) {
		return NT_STATUS_RETRY;
	}
	if (fsp->op == NULL) {
		return NT_STATUS_RETRY;
	}
	is_compound = smbd_smb2_is_compound(smbreq->smb2req);
	is_last_in_compound = smbd_smb2_is_last_in_compound(smbreq->smb2req);
	if (is_compound && !is_last_in_compound) {
		return NT_STATUS_RETRY;
	}

	u = truenas_uring_get(xconn->client->raw_ev_ctx);
	if (u == NULL) {
		return NT_STATUS_RETRY;
	}

	state = talloc_zero(smbreq->smb2req, struct splice_write_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->smbreq = smbreq;
	state->xconn = xconn;
	state->fsp = fsp;
	state->offset_orig = (off_t)in_offset;
	state->total_len = in_data.length;
	state->write_through = write_through;
	state->pipe = truenas_uring_pipe_acquire(u);
	if (state->pipe.slot < 0) {
		TALLOC_FREE(state);
		return NT_STATUS_RETRY;
	}
	state->pipe_cap = truenas_uring_pipe_capacity(u);
	if (state->pipe_cap == 0) {
		/*
		 * Pool registered (we just acquired a pipe) yet reports no
		 * capacity -- should never happen. Decline to the legacy aio
		 * path rather than drive the pump/drain loop with a zero bound.
		 */
		splice_write_release_pipe(state);
		TALLOC_FREE(state);
		return NT_STATUS_RETRY;
	}

	init_strict_lock_struct(fsp,
				fsp->op->global->open_persistent_id,
				in_offset, in_data.length,
				WRITE_LOCK, &state->lock);
	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &state->lock)) {
		splice_write_release_pipe(state);
		TALLOC_FREE(state);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	prepare_file_modified(fsp, &state->modified_state);

	/*
	 * Mark splice as owning the socket reader. While the bit is set,
	 * samba_uring_splice_reads_socket() returns true and the recv_uring
	 * path won't submit a competing RECVMSG on the same fd. Cleared in
	 * splice_write_finish.
	 */
	xconn->smb2.uring->inflight |= SAMBA_URING_INFLIGHT_SPLICE_RECV;

	xconn->smb2.uring->counters.unsigned_splice_in++;
	xconn->smb2.uring->counters.bytes_unsigned_splice_in += in_data.length;

	/*
	 * Kick off the streaming state machine: pump socket -> pipe, then
	 * drain pipe -> file, repeating until total_len bytes have moved.
	 * Both directions handle short splices via the pump/drain dance.
	 */
	splice_write_pump_socket(state);

	/*
	 * NOTE: splice_write_pump_socket may complete synchronously on
	 * failure (calling splice_write_finish which talloc_frees what
	 * it needs to). The smb2req->subreq isn't yet set, so we can't
	 * register with fsp->aio_requests here. Accepted limitation:
	 * SMB2 CLOSE during in-flight splice is rare; the alternative
	 * (registering at the first CQE) is straightforward to add later
	 * if a workload demonstrates it matters.
	 */
	return NT_STATUS_OK;
}

/*
 * Streaming state machine for socket -> pipe -> file.
 *
 * The pool sizes each pipe to the negotiated SMB2 max_write + headroom (8 MiB
 * + 64 KiB by default; see smb2_negprot.c), so the whole WRITE body fits in
 * one pipe. We therefore pump the entire body socket -> pipe first, release
 * the socket-reader claim, and only then drain pipe -> file. Filling the pipe
 * up front lets us hand the socket back to the recv state machine the instant
 * the last body byte is off it, so this request's pipe->file drain (and the
 * ZFS write behind it) overlaps the NEXT request's socket read. That
 * cross-request pipelining is what an SMB2 client's credit window expects;
 * the original code instead alternated 128 KiB socket->pipe / pipe->file ops
 * and held the socket-reader claim through the disk write, serializing every
 * connection to one in-flight WRITE with no network/disk overlap -- which is
 * what collapsed multi-stream write throughput.
 *
 * Only when the body is larger than a pipe (operator lowered
 * truenas_uring:splice_pipe_size below the negotiated max_write) do we fall
 * back to alternating pump/drain. Correctness holds; that misconfig's
 * throughput does not.
 *
 * Invariant: at most one splice op PER REQUEST is in flight at a time -- the
 * request's single pipe is its only buffer, so its socket->pipe and pipe->file
 * legs can't race on it. Concurrency now comes from OTHER requests, each with
 * its own pipe from the pool.
 */
static void splice_write_drain_pipe(struct splice_write_state *state);
static void splice_write_finish(struct splice_write_state *state,
				NTSTATUS status, int err);

static void splice_write_pump_socket(struct splice_write_state *state)
{
	struct tevent_req *subreq = NULL;
	size_t in_pipe = state->sock_consumed - state->file_done;
	size_t want;

	if (state->sock_consumed >= state->total_len) {
		/*
		 * Whole body is off the socket. Release the socket-reader
		 * claim NOW -- before the pipe->file drain -- so the recv path
		 * can pull the next PDU header while this request drains to
		 * disk, then drain what we staged.
		 */
		splice_write_release_socket(state);
		splice_write_drain_pipe(state);
		return;
	}

	if (in_pipe >= state->pipe_cap) {
		/*
		 * Pipe full but the body isn't fully staged: body > pipe size
		 * (misconfigured splice_pipe_size). Drain to make room, then
		 * resume pumping. The socket-reader claim stays held until the
		 * body is fully off the socket.
		 */
		splice_write_drain_pipe(state);
		return;
	}

	/*
	 * Pull as much of the remaining body as the pipe can still hold in one
	 * op. splice() from the socket returns whatever TCP has buffered (a
	 * short return is normal -- the next pump picks up the rest), so the
	 * old 128 KiB cap bought nothing but ~32 serialized round-trips per
	 * 4 MiB WRITE.
	 */
	want = state->total_len - state->sock_consumed;
	if (want > state->pipe_cap - in_pipe) {
		want = state->pipe_cap - in_pipe;
	}
	DBG_DEBUG("PUMP: sock_consumed=%zu file_done=%zu total=%zu want=%zu\n",
		  state->sock_consumed, state->file_done, state->total_len, want);

	subreq = truenas_uring_splice_send(state,
					   state->xconn->client->raw_ev_ctx,
					   state->xconn->transport.sock, NULL,
					   state->pipe.wfd, NULL,
					   want, SPLICE_F_MOVE);
	if (subreq == NULL) {
		splice_write_finish(state, NT_STATUS_NO_MEMORY, ENOMEM);
		return;
	}
	tevent_req_set_callback(subreq, splice_write_sock_to_pipe_done, state);
}

static void splice_write_sock_to_pipe_done(struct tevent_req *subreq)
{
	struct splice_write_state *state = tevent_req_callback_data(
		subreq, struct splice_write_state);
	ssize_t n;
	int err = 0;

	n = truenas_uring_splice_recv(subreq, &err);
	TALLOC_FREE(subreq);
	DBG_DEBUG("SOCK->PIPE done: n=%zd err=%d (retries=%u)\n",
		  n, err, state->zero_retries);

	if (n < 0) {
		splice_write_finish(state,
				    map_nt_error_from_unix_common(err), err);
		return;
	}
	if (n == 0) {
		/*
		 * Could be EOF or io_uring-level "no progress made" hiccup
		 * (saw splice-from-socket return 0 spuriously even with the
		 * socket open + client still pushing bytes). Retry a bounded
		 * number of times before giving up.
		 */
		if (state->zero_retries < 32) {
			state->zero_retries++;
			splice_write_pump_socket(state);
			return;
		}
		splice_write_finish(state, NT_STATUS_CONNECTION_RESET, EIO);
		return;
	}
	state->zero_retries = 0;
	state->sock_consumed += (size_t)n;

	/*
	 * Decrement smbreq->unread_bytes by what we just consumed off the
	 * socket. Otherwise a subsequent error path (e.g. ACCESS_DENIED on
	 * MAC mismatch in the signed splice variant; partial-write rollback
	 * in this one) would call smbd_smb2_request_error_ex, which calls
	 * drain_socket(unread_bytes) -- and the bytes are already in our
	 * pipe, not on the socket. drain_socket then fails and kills the
	 * transport.
	 */
	if (state->smbreq != NULL && state->smbreq->unread_bytes > 0) {
		size_t dec = (size_t)n;
		if (dec > state->smbreq->unread_bytes) {
			dec = state->smbreq->unread_bytes;
		}
		state->smbreq->unread_bytes -= dec;
	}

	/*
	 * Keep pumping the body into the pipe. pump_socket switches to draining
	 * once the whole body is off the socket (and releases the socket-reader
	 * claim first), or sooner if the pipe fills (oversized-body fallback).
	 * Staging the full body before draining is what lets us free the socket
	 * for the next PDU at line rate instead of alternating a 128 KiB read
	 * with a disk write.
	 */
	splice_write_pump_socket(state);
}

static void splice_write_pipe_to_file_done(struct tevent_req *subreq);

static void splice_write_drain_pipe(struct splice_write_state *state)
{
	struct tevent_req *subreq = NULL;
	int64_t out_off;
	size_t in_pipe;

	in_pipe = state->sock_consumed - state->file_done;
	DBG_DEBUG("DRAIN: sock_consumed=%zu file_done=%zu total=%zu in_pipe=%zu\n",
		  state->sock_consumed, state->file_done,
		  state->total_len, in_pipe);
	if (in_pipe == 0) {
		if (state->file_done >= state->total_len) {
			/* Done. */
			splice_write_finish(state, NT_STATUS_OK, 0);
			return;
		}
		/* Need more socket bytes. */
		splice_write_pump_socket(state);
		return;
	}

	out_off = (int64_t)state->offset_orig + (int64_t)state->file_done;
	subreq = truenas_uring_splice_send(state,
					   state->xconn->client->raw_ev_ctx,
					   state->pipe.rfd, NULL,
					   fsp_get_io_fd(state->fsp), &out_off,
					   in_pipe, SPLICE_F_MOVE);
	if (subreq == NULL) {
		splice_write_finish(state, NT_STATUS_NO_MEMORY, ENOMEM);
		return;
	}
	tevent_req_set_callback(subreq, splice_write_pipe_to_file_done, state);
}

static void splice_write_pipe_to_file_done(struct tevent_req *subreq)
{
	struct splice_write_state *state = tevent_req_callback_data(
		subreq, struct splice_write_state);
	ssize_t n;
	int err = 0;

	n = truenas_uring_splice_recv(subreq, &err);
	TALLOC_FREE(subreq);
	DBG_DEBUG("PIPE->FILE done: n=%zd err=%d\n", n, err);

	if (n < 0) {
		splice_write_finish(state,
				    map_nt_error_from_unix_common(err), err);
		return;
	}
	if (n == 0) {
		splice_write_finish(state, NT_STATUS_DISK_FULL, ENOSPC);
		return;
	}

	state->file_done += (size_t)n;
	/*
	 * drain_pipe decides correctly based on state:
	 *  - if pipe still has bytes: splice more pipe->file
	 *  - if pipe empty but socket has bytes: pump_socket
	 *  - if file_done >= total_len: finish OK
	 * Avoids the trap of pumping more socket bytes while the pipe is
	 * still partially full (which would race the pipe's capacity).
	 */
	splice_write_drain_pipe(state);
}

static void splice_write_finish(struct splice_write_state *state,
				NTSTATUS status, int err)
{
	struct tevent_req *write_req = NULL;
	files_struct *fsp = state->fsp;
	size_t written = state->file_done;

	DBG_DEBUG("FINISH: status=%s err=%d written=%zu of total=%zu "
		  "sock_consumed=%zu\n",
		  nt_errstr(status), err, written, state->total_len,
		  state->sock_consumed);

	/*
	 * On the normal path the socket-reader claim was already dropped by
	 * splice_write_release_socket() the instant the body came off the
	 * socket, so this is a guarded no-op. It only does real work when we
	 * finish early -- a socket->pipe error before the body was fully read;
	 * the SMB2 error path then drains any leftover unread_bytes and the
	 * recv state machine resumes from a clean PDU boundary.
	 */
	splice_write_release_socket(state);

	splice_write_release_pipe(state);

	if (state->smbreq != NULL &&
	    state->smbreq->smb2req != NULL) {
		write_req = state->smbreq->smb2req->subreq;
	}
	if (write_req == NULL) {
		/* Shutdown raced with us; nothing to notify. */
		return;
	}

	if (written > 0) {
		mark_file_modified(fsp, true, &state->modified_state);
	}

	if (NT_STATUS_IS_OK(status)) {
		status = smb2_write_complete_nosync(write_req,
						    (ssize_t)written, 0);
	} else {
		(void)smb2_write_complete_nosync(write_req, -1, err);
	}

	if (tevent_req_nterror(write_req, status)) {
		return;
	}
	tevent_req_done(write_req);
}

/****************************************************************************
 Signed splice inbound WRITE: streaming HMAC via splice + tee + AF_ALG.

 Verify-then-write: the signature is checked over the spliced body BEFORE any
 byte is committed to the file. Pipe contents are kernel-only; if HMAC fails
 we drain the pipe and return ACCESS_DENIED without touching the file.

 Pipe budget: the body pipe holds the entire body until HMAC verifies, then
 drains to file. The alg pipe is a tee'd copy that feeds AF_ALG. Both pipes
 need capacity >= total_len rounded to pages; the splice_pipe_size knob
 (default max(read,write)) must be sized accordingly. Operator may need to
 raise /proc/sys/fs/pipe-max-size for >1 MiB pipes.

 Algorithm name resolution from sign_algo_id:
   SMB2_SIGNING_HMAC_SHA256  -> "hmac(sha256)"  (SMB 2.x)
   SMB2_SIGNING_AES128_CMAC  -> "cmac(aes)"     (SMB 3.0+)
   SMB2_SIGNING_AES128_GMAC  -> unsupported by algif_hash; fall back

 The HMAC input mirrors smb2_signing_check_pdu in libcli/smb/smb2_signing.c:
   hdr[0:SMB2_HDR_SIGNATURE]    -- pre-signature header bytes (48 B)
   16 zero bytes                -- signature field placeholder
   body iov[1:n]                -- WRITE struct (48 B) for short-recvfile
   body data                    -- spliced from pipeB
*****************************************************************************/

struct signed_splice_in_state {
	struct smb_request *smbreq;
	struct smbXsrv_connection *xconn;
	files_struct *fsp;
	off_t offset_orig;
	size_t total_len;
	size_t sock_consumed;     /* socket -> pipeA */
	size_t alg_fed;           /* pipeB -> AF_ALG */
	size_t file_done;         /* pipeA -> file (post-verify) */
	struct truenas_uring_pipe pipeA, pipeB;
	int alg_op_fd;            /* AF_ALG operation socket (per-request) */
	int alg_bind_fd;          /* AF_ALG bind socket (per-request) */
	uint8_t client_mac[16];   /* stashed signature from inbound header */
	size_t pipe_cap;          /* usable capacity of pipeA/pipeB */
	struct lock_struct lock;
	bool write_through;
	bool socket_released;     /* socket-reader claim already dropped? */
	struct file_modified_state modified_state;
	unsigned int zero_retries;
};

static void signed_splice_in_pump_socket(struct signed_splice_in_state *state);
static void signed_splice_in_drain_to_alg(struct signed_splice_in_state *state);
static void signed_splice_in_pump_file(struct signed_splice_in_state *state);
static void signed_splice_in_finish(struct signed_splice_in_state *state,
			 NTSTATUS status, int err);

static void signed_splice_in_release_pipes(struct signed_splice_in_state *state)
{
	struct truenas_uring *u;
	if (state->xconn == NULL) {
		return;
	}
	u = truenas_uring_get(state->xconn->client->raw_ev_ctx);
	if (u == NULL) {
		return;
	}
	if (state->pipeA.slot >= 0) {
		truenas_uring_pipe_release(u, state->pipeA.slot);
		state->pipeA.slot = -1;
	}
	if (state->pipeB.slot >= 0) {
		truenas_uring_pipe_release(u, state->pipeB.slot);
		state->pipeB.slot = -1;
	}
}

static void signed_splice_in_close_alg(struct signed_splice_in_state *state)
{
	if (state->alg_op_fd >= 0) {
		close(state->alg_op_fd);
		state->alg_op_fd = -1;
	}
	if (state->alg_bind_fd >= 0) {
		truenas_uring_hmac_close(state->alg_bind_fd);
		state->alg_bind_fd = -1;
	}
}

/*
 * Release pipes + close alg fds + free state in one shot. Idempotent
 * across partial setup (each subhelper guards its own state). Use for
 * setup-time rollback only; the runtime state machine uses
 * signed_splice_in_finish.
 */
static void signed_splice_in_abort_setup(struct signed_splice_in_state *state)
{
	if (state == NULL) {
		return;
	}
	signed_splice_in_release_pipes(state);
	signed_splice_in_close_alg(state);
	TALLOC_FREE(state);
}

static const char *signed_splice_in_alg_name(uint16_t sign_algo_id)
{
	switch (sign_algo_id) {
	case SMB2_SIGNING_HMAC_SHA256: return "hmac(sha256)";
	case SMB2_SIGNING_AES128_CMAC: return "cmac(aes)";
	/*
	 * SMB3.1.1 AES-GMAC routes through algif_hash("ghash") keyed with
	 * H = AES_K(0^128). The H-derivation and key install happen inside
	 * truenas_smb2_alg_hmac_acquire; the per-message tag is finalised
	 * via splice_signed_in_compute_gmac_tag (length-block send + read
	 * + userspace AES_K(J0) XOR), paralleling the OUT path.
	 */
	case SMB2_SIGNING_AES128_GMAC: return "ghash";
	default: return NULL;
	}
}

/*
 * Per-request admissibility checks (independent of in_data sizing). Run
 * before any allocation so we can decline cheaply. NT_STATUS_OK means
 * the caller may proceed with state setup; NT_STATUS_RETRY means decline
 * and let the caller's safe-fail path return ACCESS_DENIED.
 */
static NTSTATUS signed_splice_in_eligible(struct smb_request *smbreq,
					  files_struct *fsp)
{
	struct smbd_smb2_request *smb2req = smbreq->smb2req;
	struct smb2_signing_key *sk;

	if (smb2req == NULL ||
	    smb2req->splice_in.type != SPLICE_OP_SIGNED_IN) {
		return NT_STATUS_RETRY;
	}
	if (fsp_is_alternate_stream(fsp) || fsp->op == NULL) {
		return NT_STATUS_RETRY;
	}
	if (smbd_smb2_is_compound(smb2req) &&
	    !smbd_smb2_is_last_in_compound(smb2req)) {
		return NT_STATUS_RETRY;
	}
	sk = smb2req->splice_in.signing_key;
	if (sk == NULL || !smb2_signing_key_valid(sk)) {
		return NT_STATUS_RETRY;
	}
	if (signed_splice_in_alg_name(sk->sign_algo_id) == NULL) {
		/*
		 * Should not happen: the negprot GMAC-gate filters out
		 * algorithms algif_hash cannot compute when signed splice is
		 * enabled. Defensive RETRY: caller safe-fails with
		 * ACCESS_DENIED rather than write attacker-controlled bytes.
		 */
		return NT_STATUS_RETRY;
	}
	return NT_STATUS_OK;
}

/*
 * Grab two pipes from the per-xconn pool (body pipe + tee copy for the
 * AF_ALG feed). On partial failure, releases what was acquired so the
 * caller never has to think about half-state.
 */
static NTSTATUS signed_splice_in_acquire_pipes(
	struct truenas_uring *u,
	struct signed_splice_in_state *state)
{
	state->pipeA = truenas_uring_pipe_acquire(u);
	if (state->pipeA.slot < 0) {
		return NT_STATUS_RETRY;
	}
	state->pipeB = truenas_uring_pipe_acquire(u);
	if (state->pipeB.slot < 0) {
		truenas_uring_pipe_release(u, state->pipeA.slot);
		state->pipeA.slot = -1;
		return NT_STATUS_RETRY;
	}
	return NT_STATUS_OK;
}

/*
 * Acquire the cached AF_ALG bind socket for this signing key and
 * accept4() a fresh per-request operation fd off it. alg_bind_fd
 * stays -1 in our state so signed_splice_in_close_alg does NOT close
 * the cached fd -- the cache entry's talloc destructor closes it when
 * the signing_key (= session/channel) is torn down.
 */
static NTSTATUS signed_splice_in_open_alg_fd(
	struct signed_splice_in_state *state,
	struct smb2_signing_key *sk)
{
	int cached_bind;
	int op_fd;

	cached_bind = truenas_smb2_alg_hmac_acquire(state->xconn, sk);
	if (cached_bind < 0) {
		DBG_WARNING("signed_splice: alg_acquire failed: %s\n",
			    strerror(-cached_bind));
		return NT_STATUS_RETRY;
	}
	op_fd = accept4(cached_bind, NULL, NULL, SOCK_CLOEXEC);
	if (op_fd < 0) {
		DBG_WARNING("signed_splice: accept4 on cached AF_ALG: %s\n",
			    strerror(errno));
		return NT_STATUS_RETRY;
	}
	state->alg_op_fd = op_fd;
	state->alg_bind_fd = -1;  /* shared cached fd; not owned by us */
	return NT_STATUS_OK;
}

/*
 * Feed the SMB2 header bytes that get HMACed BEFORE the body:
 *   inhdr[0:48]    -- pre-signature header
 *   16 zero bytes  -- signature field placeholder
 *   body iov bytes -- WRITE struct (small; 48 B for short-recvfile)
 * Single-call send to match the truenas_uring_hmac_compute path (verified
 * against RFC 4231). MSG_MORE keeps the hash state open for the
 * subsequent body splice from pipeB.
 */
static NTSTATUS signed_splice_in_feed_hmac_header(
	struct signed_splice_in_state *state,
	const uint8_t *inhdr,
	const struct iovec *body_iov)
{
	uint8_t hdrbuf[SMB2_HDR_SIGNATURE + sizeof(state->client_mac) + 256];
	size_t hdrlen = 0;
	ssize_t n;

	if (SMB2_HDR_SIGNATURE + sizeof(state->client_mac) +
		    body_iov->iov_len > sizeof(hdrbuf)) {
		return NT_STATUS_RETRY;
	}

	memcpy(hdrbuf + hdrlen, inhdr, SMB2_HDR_SIGNATURE);
	hdrlen += SMB2_HDR_SIGNATURE;
	memset(hdrbuf + hdrlen, 0, sizeof(state->client_mac));
	hdrlen += sizeof(state->client_mac);
	memcpy(hdrbuf + hdrlen, body_iov->iov_base, body_iov->iov_len);
	hdrlen += body_iov->iov_len;

	n = send(state->alg_op_fd, hdrbuf, hdrlen, MSG_MORE);
	if (n < 0 || (size_t)n != hdrlen) {
		int saved_errno = (n < 0) ? errno : EIO;
		DBG_WARNING("signed_splice: AF_ALG hdr send failed: %s\n",
			    strerror(saved_errno));
		return NT_STATUS_RETRY;
	}
	return NT_STATUS_OK;
}

NTSTATUS truenas_schedule_smb2_signed_splice_write(connection_struct *conn,
				   struct smb_request *smbreq,
				   files_struct *fsp,
				   uint64_t in_offset,
				   DATA_BLOB in_data,
				   bool write_through)
{
	struct smbXsrv_connection *xconn = smbreq->xconn;
	struct smbd_smb2_request *smb2req = smbreq->smb2req;
	struct signed_splice_in_state *state = NULL;
	struct truenas_uring *u;
	const uint8_t *inhdr;
	const struct iovec *body_iov;
	NTSTATUS status;

	if (!xconn->smb2.uring->enabled.splice_recv) {
		return NT_STATUS_RETRY;
	}
	status = signed_splice_in_eligible(smbreq, fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (smbreq->unread_bytes == 0 ||
	    smbreq->unread_bytes != in_data.length) {
		return NT_STATUS_RETRY;
	}
	/*
	 * Same offset bounds check as the unsigned variant -- the splice
	 * pipeline bypasses vfs_valid_pwrite_range that the legacy aio_write
	 * path enforces via pwrite_fsync_send.
	 */
	if (!vfs_valid_pwrite_range(fsp, (off_t)in_offset, in_data.length)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	u = truenas_uring_get(xconn->client->raw_ev_ctx);
	if (u == NULL) {
		return NT_STATUS_RETRY;
	}

	state = talloc_zero(smb2req, struct signed_splice_in_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->pipeA.slot = -1;
	state->pipeB.slot = -1;
	state->alg_op_fd = -1;
	state->alg_bind_fd = -1;
	state->smbreq = smbreq;
	state->xconn = xconn;
	state->fsp = fsp;
	state->offset_orig = (off_t)in_offset;
	state->total_len = in_data.length;
	state->write_through = write_through;
	state->pipe_cap = truenas_uring_pipe_capacity(u);

	/* Stash the client-supplied signature for later memcmp. */
	inhdr = SMBD_SMB2_IN_HDR_PTR(smb2req);
	body_iov = SMBD_SMB2_IN_BODY_IOV(smb2req);
	memcpy(state->client_mac, inhdr + SMB2_HDR_SIGNATURE,
	       sizeof(state->client_mac));

	status = signed_splice_in_acquire_pipes(u, state);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = signed_splice_in_open_alg_fd(
		state, smb2req->splice_in.signing_key);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = signed_splice_in_feed_hmac_header(state, inhdr, body_iov);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	init_strict_lock_struct(fsp,
				fsp->op->global->open_persistent_id,
				in_offset, in_data.length,
				WRITE_LOCK, &state->lock);
	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &state->lock)) {
		status = NT_STATUS_FILE_LOCK_CONFLICT;
		goto fail;
	}

	prepare_file_modified(fsp, &state->modified_state);

	/*
	 * Mark splice as owning the socket reader (signed variant).
	 * samba_uring_splice_reads_socket() then returns true and the
	 * recv_uring path defers until signed_splice_in_finish clears it.
	 */
	xconn->smb2.uring->inflight |= SAMBA_URING_INFLIGHT_SPLICE_RECV;

	xconn->smb2.uring->counters.signed_splice_in++;
	xconn->smb2.uring->counters.bytes_signed_splice_in += in_data.length;

	signed_splice_in_pump_socket(state);
	return NT_STATUS_OK;

fail:
	signed_splice_in_abort_setup(state);
	return status;
}

/*
 * Signed-path analogue of splice_write_release_socket(): drop the socket-reader
 * claim and re-arm the recv state machine the instant the body is off the
 * socket (tee'd into pipeB), so the HMAC verify + pipe->file drain overlap the
 * next request's socket read. Verify-then-write is unaffected -- no file byte
 * is written until the MAC is checked. Idempotent via state->socket_released.
 */
static void signed_splice_in_release_socket(struct signed_splice_in_state *state)
{
	if (state->socket_released) {
		return;
	}
	state->socket_released = true;
	state->xconn->smb2.uring->inflight &= ~SAMBA_URING_INFLIGHT_SPLICE_RECV;
	(void)smbd_smb2_request_next_incoming(state->xconn);
}

static void signed_splice_in_pump_socket_done(struct tevent_req *subreq);
static void signed_splice_in_alg_feed_done(struct tevent_req *subreq);

static void signed_splice_in_pump_socket(struct signed_splice_in_state *state)
{
	struct tevent_req *subreq;
	size_t in_pipeA = state->sock_consumed - state->file_done;
	size_t want;

	if (state->sock_consumed >= state->total_len) {
		/* All body in pipeA; drain remainder of pipeB to AF_ALG. */
		signed_splice_in_drain_to_alg(state);
		return;
	}
	/*
	 * Verify-then-write needs the whole body resident in pipeA before the
	 * MAC can be checked, and the pool sizes each pipe to max_write +
	 * headroom, so it fits. Pull as much as the pipe can still hold per op
	 * instead of the old 128 KiB cap; splice short returns are normal and
	 * the next pump picks up the rest.
	 */
	if (in_pipeA >= state->pipe_cap) {
		/*
		 * Body larger than the pipe (misconfigured splice_pipe_size):
		 * verify-then-write can't stage it, and a socket->pipe splice
		 * into a full pipe would stall. Fail cleanly.
		 */
		DBG_WARNING("signed_splice: body %zu exceeds pipe capacity "
			    "%zu; raise truenas_uring:splice_pipe_size\n",
			    state->total_len, state->pipe_cap);
		signed_splice_in_finish(state,
					NT_STATUS_INSUFFICIENT_RESOURCES, ENOBUFS);
		return;
	}
	want = state->total_len - state->sock_consumed;
	if (want > state->pipe_cap - in_pipeA) {
		want = state->pipe_cap - in_pipeA;
	}
	subreq = truenas_uring_splice_send(state,
					   state->xconn->client->raw_ev_ctx,
					   state->xconn->transport.sock, NULL,
					   state->pipeA.wfd, NULL,
					   want, SPLICE_F_MOVE);
	if (subreq == NULL) {
		signed_splice_in_finish(state, NT_STATUS_NO_MEMORY, ENOMEM);
		return;
	}
	tevent_req_set_callback(subreq, signed_splice_in_pump_socket_done, state);
}

static void signed_splice_in_pump_socket_done(struct tevent_req *subreq)
{
	struct signed_splice_in_state *state = tevent_req_callback_data(
		subreq, struct signed_splice_in_state);
	ssize_t n;
	int err = 0;

	n = truenas_uring_splice_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (n < 0) {
		signed_splice_in_finish(state, map_nt_error_from_unix_common(err), err);
		return;
	}
	if (n == 0) {
		if (state->zero_retries < 32) {
			state->zero_retries++;
			signed_splice_in_pump_socket(state);
			return;
		}
		signed_splice_in_finish(state, NT_STATUS_CONNECTION_RESET, EIO);
		return;
	}
	state->zero_retries = 0;
	state->sock_consumed += (size_t)n;

	/*
	 * Decrement smbreq->unread_bytes; the bytes are in pipeA now, not
	 * on the socket. Without this, an error response path (e.g. MAC
	 * verify failure -> ACCESS_DENIED) would call request_error_ex
	 * which calls drain_socket(unread_bytes) and kills the transport.
	 */
	if (state->smbreq != NULL && state->smbreq->unread_bytes > 0) {
		size_t dec = (size_t)n;
		if (dec > state->smbreq->unread_bytes) {
			dec = state->smbreq->unread_bytes;
		}
		state->smbreq->unread_bytes -= dec;
	}

	/*
	 * Don't tee per-chunk -- tee() reads from the head of the source
	 * pipe each call, so duplicating "the last n bytes" doesn't work
	 * when pipeA holds many chunks. Instead defer the tee until all
	 * body data is in pipeA; then a single tee duplicates the whole
	 * thing into pipeB for HMAC. Continue pumping or finalize.
	 */
	if (state->sock_consumed < state->total_len) {
		signed_splice_in_pump_socket(state);
		return;
	}
	{
		ssize_t te = tee(state->pipeA.rfd, state->pipeB.wfd,
				 state->total_len, 0);
		if (te < 0 || (size_t)te != state->total_len) {
			int saved = (te < 0) ? errno : EIO;
			DBG_WARNING("signed_splice: tee short %zd != %zu: %s\n",
				    te, state->total_len, strerror(saved));
			signed_splice_in_finish(state,
				map_nt_error_from_unix_common(saved), saved);
			return;
		}
	}
	/*
	 * Whole body is off the socket now (staged in pipeA, tee'd into pipeB).
	 * Release the socket-reader claim so the next PDU can be read while we
	 * run the streaming HMAC + verify + pipe->file drain. No file byte is
	 * written until the MAC checks out, so verify-then-write still holds.
	 */
	signed_splice_in_release_socket(state);
	signed_splice_in_drain_to_alg(state);
}

static void signed_splice_in_drain_to_alg(struct signed_splice_in_state *state)
{
	struct tevent_req *subreq;
	size_t in_pipeB;

	in_pipeB = state->sock_consumed - state->alg_fed;
	if (in_pipeB == 0) {
		/*
		 * All body bytes have been fed into AF_ALG. Read the MAC
		 * and verify against the client-supplied signature BEFORE
		 * touching the file. Verify-then-write is the only-secure
		 * design (plan Invariant 23).
		 *
		 * For HMAC-SHA256 / AES-CMAC the kernel hash output IS the
		 * tag, so we just read 16 bytes. For SMB3.1.1 AES-GMAC the
		 * ghash output needs the GMAC length-block sent first, then
		 * XOR with userspace AES_K(J0) -- factored into
		 * truenas_smb2_compute_gmac_tag for sharing with the OUT path.
		 */
		struct smbd_smb2_request *smb2req = state->smbreq->smb2req;
		struct smb2_signing_key *sk = smb2req->splice_in.signing_key;
		const uint8_t *inhdr = SMBD_SMB2_IN_HDR_PTR(smb2req);
		const struct iovec *body_iov = SMBD_SMB2_IN_BODY_IOV(smb2req);
		uint8_t mac[16] = {0};
		NTSTATUS status = NT_STATUS_OK;

		if (sk->sign_algo_id == SMB2_SIGNING_AES128_GMAC) {
			/*
			 * AAD layout matches signed_splice_in_feed_hmac_header
			 * + the body bytes splice'd into pipeB:
			 *   inhdr[0..SMB2_HDR_SIGNATURE]  = 48 bytes
			 *   zero16 (signature placeholder) = 16 bytes
			 *   body_iov[0]                    = body_iov->iov_len
			 *   body payload                   = state->total_len
			 */
			size_t aad_len = SMB2_HDR_SIGNATURE + 16
				       + body_iov->iov_len
				       + state->total_len;
			status = truenas_smb2_compute_gmac_tag(
				state->alg_op_fd,
				sk->blob.data, sk->blob.length,
				inhdr, aad_len, mac);
		} else {
			ssize_t r = read(state->alg_op_fd, mac, sizeof(mac));
			if (r != (ssize_t)sizeof(mac)) {
				int saved = (r < 0) ? errno : EIO;
				status = map_nt_error_from_unix_common(saved);
				DBG_WARNING("signed_splice: read MAC failed: "
					    "%s\n", strerror(saved));
			}
		}
		signed_splice_in_close_alg(state);
		if (!NT_STATUS_IS_OK(status)) {
			signed_splice_in_finish(state, status,
				NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)
					? ENOMEM : EIO);
			return;
		}
		{
			bool forced_fail = samba_uring_consume_force_signed_in_fail(
				state->xconn->smb2.uring);
			if (forced_fail ||
			    !mem_equal_const_time(mac, state->client_mac, 16)) {
				DBG_NOTICE("signed_splice: signature mismatch "
					   "(forced=%s) -- dropping signed "
					   "WRITE\n",
					   forced_fail ? "yes" : "no");
				state->xconn->smb2.uring->counters
					.signed_splice_in_denied++;
				signed_splice_in_finish(state,
					NT_STATUS_ACCESS_DENIED, EACCES);
				return;
			}
		}
		/* Verified. Splice pipeA -> file. */
		signed_splice_in_pump_file(state);
		return;
	}

	subreq = truenas_uring_splice_send(state,
					   state->xconn->client->raw_ev_ctx,
					   state->pipeB.rfd, NULL,
					   state->alg_op_fd, NULL,
					   in_pipeB,
					   SPLICE_F_MOVE | SPLICE_F_MORE);
	if (subreq == NULL) {
		signed_splice_in_finish(state, NT_STATUS_NO_MEMORY, ENOMEM);
		return;
	}
	tevent_req_set_callback(subreq, signed_splice_in_alg_feed_done, state);
}

static void signed_splice_in_alg_feed_done(struct tevent_req *subreq)
{
	struct signed_splice_in_state *state = tevent_req_callback_data(
		subreq, struct signed_splice_in_state);
	ssize_t n;
	int err = 0;

	n = truenas_uring_splice_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (n < 0) {
		signed_splice_in_finish(state, map_nt_error_from_unix_common(err), err);
		return;
	}
	if (n == 0) {
		signed_splice_in_finish(state, NT_STATUS_INTERNAL_ERROR, EIO);
		return;
	}
	state->alg_fed += (size_t)n;
	signed_splice_in_drain_to_alg(state);
}

static void signed_splice_in_pump_file_done(struct tevent_req *subreq);

static void signed_splice_in_pump_file(struct signed_splice_in_state *state)
{
	struct tevent_req *subreq;
	int64_t out_off;
	size_t in_pipeA;

	in_pipeA = state->sock_consumed - state->file_done;
	if (in_pipeA == 0) {
		/* Everything written. */
		signed_splice_in_finish(state, NT_STATUS_OK, 0);
		return;
	}

	out_off = (int64_t)state->offset_orig + (int64_t)state->file_done;
	subreq = truenas_uring_splice_send(state,
					   state->xconn->client->raw_ev_ctx,
					   state->pipeA.rfd, NULL,
					   fsp_get_io_fd(state->fsp), &out_off,
					   in_pipeA, SPLICE_F_MOVE);
	if (subreq == NULL) {
		signed_splice_in_finish(state, NT_STATUS_NO_MEMORY, ENOMEM);
		return;
	}
	tevent_req_set_callback(subreq, signed_splice_in_pump_file_done, state);
}

static void signed_splice_in_pump_file_done(struct tevent_req *subreq)
{
	struct signed_splice_in_state *state = tevent_req_callback_data(
		subreq, struct signed_splice_in_state);
	ssize_t n;
	int err = 0;

	n = truenas_uring_splice_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (n < 0) {
		signed_splice_in_finish(state, map_nt_error_from_unix_common(err), err);
		return;
	}
	if (n == 0) {
		signed_splice_in_finish(state, NT_STATUS_DISK_FULL, ENOSPC);
		return;
	}
	state->file_done += (size_t)n;
	signed_splice_in_pump_file(state);
}

static void signed_splice_in_finish(struct signed_splice_in_state *state,
			 NTSTATUS status, int err)
{
	struct tevent_req *write_req = NULL;
	files_struct *fsp = state->fsp;
	size_t written = state->file_done;

	/*
	 * Normally dropped already in signed_splice_in_release_socket() right
	 * after the body was tee'd off the socket; idempotent here for the
	 * early-error paths (alg setup / socket->pipe / verify) that finish
	 * before that point.
	 */
	signed_splice_in_release_socket(state);

	signed_splice_in_close_alg(state);  /* idempotent on the success path */
	signed_splice_in_release_pipes(state);

	if (state->smbreq != NULL &&
	    state->smbreq->smb2req != NULL) {
		write_req = state->smbreq->smb2req->subreq;
	}
	if (write_req == NULL) {
		return;  /* shutdown race */
	}

	if (written > 0) {
		mark_file_modified(fsp, true, &state->modified_state);
	}

	if (NT_STATUS_IS_OK(status)) {
		status = smb2_write_complete_nosync(write_req,
						    (ssize_t)written, 0);
	} else {
		(void)smb2_write_complete_nosync(write_req, -1, err);
	}

	if (tevent_req_nterror(write_req, status)) {
		return;
	}
	tevent_req_done(write_req);
}
#endif /* HAVE_LIBURING */

/****************************************************************************
 Set up an aio request from a SMB2write call.
*****************************************************************************/

NTSTATUS schedule_aio_smb2_write(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				uint64_t in_offset,
				DATA_BLOB in_data,
				bool write_through)
{
	struct aio_extra *aio_ex = NULL;
	size_t min_aio_write_size = lp_aio_write_size(SNUM(conn));
	struct tevent_req *req;
	bool is_compound = false;
	bool is_last_in_compound = false;

	if (fsp_is_alternate_stream(fsp)) {
		/* No AIO on streams yet */
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return NT_STATUS_RETRY;
	}

	if (fsp->op == NULL) {
		/* No AIO on internal opens. */
		return NT_STATUS_RETRY;
	}

	if ((!min_aio_write_size || (in_data.length < min_aio_write_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a write for aio request. */
		DEBUG(10,("smb2: write size (%u) too "
			"small for minimum aio_write of %u\n",
			(unsigned int)in_data.length,
			(unsigned int)min_aio_write_size ));
		return NT_STATUS_RETRY;
	}

	is_compound = smbd_smb2_is_compound(smbreq->smb2req);
	is_last_in_compound = smbd_smb2_is_last_in_compound(smbreq->smb2req);

	if (is_compound && !is_last_in_compound) {
		/*
		 * Only allow going async if this is the last
		 * request in a compound.
		 */
		return NT_STATUS_RETRY;
	}

	if (smbreq->unread_bytes) {
		/* Can't do async with recvfile. */
		return NT_STATUS_RETRY;
	}

	if (!(aio_ex = create_aio_extra(smbreq->smb2req, fsp, 0))) {
		return NT_STATUS_NO_MEMORY;
	}

	aio_ex->write_through = write_through;

	init_strict_lock_struct(fsp,
			fsp->op->global->open_persistent_id,
			in_offset,
			(uint64_t)in_data.length,
			WRITE_LOCK,
			&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	aio_ex->nbyte = in_data.length;
	aio_ex->offset = in_offset;
	prepare_file_modified(fsp, &aio_ex->modified_state);

	req = pwrite_fsync_send(aio_ex, fsp->conn->sconn->ev_ctx, fsp,
				in_data.data, in_data.length, in_offset,
				write_through);
	if (req == NULL) {
		DEBUG(3, ("smb2: SMB_VFS_PWRITE_SEND failed. "
			  "Error %s\n", strerror(errno)));
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}
	tevent_req_set_callback(req, aio_pwrite_smb2_done, aio_ex);

	if (!aio_add_req_to_fsp(fsp, req)) {
		DEBUG(1, ("Could not add req to fsp\n"));
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}

	/* We don't need talloc_move here as both aio_ex and
	* smbreq are children of smbreq->smb2req. */
	aio_ex->smbreq = smbreq;
	smbreq->async_priv = aio_ex;

	/* This should actually be improved to span the write. */
	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_WRITE);
	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_WRITE);

	/*
	 * We don't want to do write behind due to ownership
	 * issues of the request structs. Maybe add it if I
	 * figure those out. JRA.
	 */

	DEBUG(10,("smb2: scheduled aio_write for file "
		"%s, offset %.0f, len = %u (mid = %u)\n",
		fsp_str_dbg(fsp),
		(double)in_offset,
		(unsigned int)in_data.length,
		(unsigned int)aio_ex->smbreq->mid));

	return NT_STATUS_OK;
}

static void aio_pwrite_smb2_done(struct tevent_req *req)
{
	struct aio_extra *aio_ex = tevent_req_callback_data(
		req, struct aio_extra);
	ssize_t numtowrite = aio_ex->nbyte;
	struct tevent_req *subreq = aio_ex->smbreq->smb2req->subreq;
	files_struct *fsp = aio_ex->fsp;
	NTSTATUS status;
	ssize_t nwritten;
	int err = 0;

	nwritten = pwrite_fsync_recv(req, &err);
	TALLOC_FREE(req);

	DEBUG(10, ("pwrite_recv returned %d, err = %s\n", (int)nwritten,
		   (nwritten == -1) ? strerror(err) : "no error"));

	mark_file_modified(fsp, true, &aio_ex->modified_state);

        status = smb2_write_complete_nosync(subreq, nwritten, err);

	DEBUG(10, ("smb2: scheduled aio_write completed "
		   "for file %s, offset %.0f, requested %u, "
		   "written = %u (errcode = %d, NTSTATUS = %s)\n",
		   fsp_str_dbg(fsp),
		   (double)aio_ex->offset,
		   (unsigned int)numtowrite,
		   (unsigned int)nwritten,
		   err, nt_errstr(status)));

	if (tevent_req_nterror(subreq, status)) {
		return;
	}
	tevent_req_done(subreq);
}
