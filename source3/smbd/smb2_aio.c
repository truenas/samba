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

bool aio_add_req_to_fsp(files_struct *fsp, struct tevent_req *req)
{
	size_t array_len;
	struct aio_req_fsp_link *lnk;

	lnk = talloc(req, struct aio_req_fsp_link);
	if (lnk == NULL) {
		return false;
	}

	array_len = talloc_array_length(fsp->aio_requests);
	if (array_len <= fsp->num_aio_requests) {
		struct tevent_req **tmp;

		if (fsp->num_aio_requests + 10 < 10) {
			/* Integer wrap. */
			TALLOC_FREE(lnk);
			return false;
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
			return false;
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

	return true;
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

	ok = vfs_valid_pwrite_range(offset, n);
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

	/* Create the out buffer. */
	*preadbuf = data_blob_talloc(ctx, NULL, smb_maxcnt);
	if (preadbuf->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!(aio_ex = create_aio_extra(smbreq->smb2req, fsp, 0))) {
		return NT_STATUS_NO_MEMORY;
	}

	init_strict_lock_struct(fsp,
			fsp->op->global->open_persistent_id,
			(uint64_t)startpos,
			(uint64_t)smb_maxcnt,
			READ_LOCK,
			lp_posix_cifsu_locktype(fsp),
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
			lp_posix_cifsu_locktype(fsp),
			&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	aio_ex->nbyte = in_data.length;
	aio_ex->offset = in_offset;

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

	mark_file_modified(fsp);

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
