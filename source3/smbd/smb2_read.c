/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

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
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "libcli/security/security.h"
#include "../lib/util/tevent_ntstatus.h"
#include "rpc_server/srv_pipe_hnd.h"
#ifdef HAVE_LIBURING
#include "lib/truenas_uring.h"
#include "smbd/smbd_smb2_uring.h"
#endif
#include "lib/util/sys_rw_data.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

static struct tevent_req *smbd_smb2_read_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      struct files_struct *in_fsp,
					      uint8_t in_flags,
					      uint32_t in_length,
					      uint64_t in_offset,
					      uint32_t in_minimum,
					      uint32_t in_remaining);
static NTSTATUS smbd_smb2_read_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_data,
				    uint32_t *out_remaining);

static void smbd_smb2_request_read_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_read(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	NTSTATUS status;
	const uint8_t *inbody;
	uint8_t in_flags;
	uint32_t in_length;
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	uint32_t in_minimum_count;
	uint32_t in_remaining_bytes;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x31);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	if (xconn->protocol >= PROTOCOL_SMB3_02) {
		in_flags		= CVAL(inbody, 0x03);
	} else {
		in_flags		= 0;
	}
	in_length		= IVAL(inbody, 0x04);
	in_offset		= BVAL(inbody, 0x08);
	in_file_id_persistent	= BVAL(inbody, 0x10);
	in_file_id_volatile	= BVAL(inbody, 0x18);
	in_minimum_count	= IVAL(inbody, 0x20);
	in_remaining_bytes	= IVAL(inbody, 0x28);

	/* check the max read size */
	if (in_length > xconn->smb2.server.max_read) {
		DEBUG(2,("smbd_smb2_request_process_read: "
			 "client ignored max read: %s: 0x%08X: 0x%08X\n",
			__location__, in_length, xconn->smb2.server.max_read));
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	status = smbd_smb2_request_verify_creditcharge(req, in_length);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_read_send(req, req->sconn->ev_ctx,
				     req, in_fsp,
				     in_flags,
				     in_length,
				     in_offset,
				     in_minimum_count,
				     in_remaining_bytes);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_read_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_read_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	uint16_t body_size;
	uint8_t body_padding = req->xconn->smb2.smbtorture.read_body_padding;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint8_t out_data_offset;
	DATA_BLOB out_data_buffer = data_blob_null;
	uint32_t out_data_remaining = 0;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_read_recv(subreq,
				     req,
				     &out_data_buffer,
				     &out_data_remaining);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	/*
	 * Only FSCTL_SMBTORTURE_GLOBAL_READ_RESPONSE_BODY_PADDING8
	 * sets body_padding to a value different from 0.
	 */
	body_size = 0x10 + body_padding;
	out_data_offset = SMB2_HDR_BODY + body_size;

	outbody = smbd_smb2_generate_outbody(req, body_size);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x10 + 1);	/* struct size */
	SCVAL(outbody.data, 0x02,
	      out_data_offset);			/* data offset */
	SCVAL(outbody.data, 0x03, 0);		/* reserved */
	SIVAL(outbody.data, 0x04,
	      out_data_buffer.length);		/* data length */
	SIVAL(outbody.data, 0x08,
	      out_data_remaining);		/* data remaining */
	SIVAL(outbody.data, 0x0C, 0);		/* reserved */
	if (body_padding != 0) {
		memset(outbody.data + 0x10, 0, body_padding);
	}

	outdyn = out_data_buffer;

	error = smbd_smb2_request_done(req, outbody, &outdyn);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

struct smbd_smb2_read_state {
	struct smbd_smb2_request *smb2req;
	struct smb_request *smbreq;
	struct tevent_req *ipc_subreq;
	files_struct *fsp;
	uint8_t in_flags;
	uint32_t in_length;
	uint64_t in_offset;
	uint32_t in_minimum;
	DATA_BLOB out_headers;
	uint8_t _out_hdr_buf[NBT_HDR_SIZE + SMB2_HDR_BODY + 0x10];
	DATA_BLOB out_data;
	uint32_t out_remaining;
#ifdef HAVE_LIBURING
	/*
	 * Outbound splice selection for this READ. Picked in the scheduling
	 * phase (one of the schedule_smb2_*_read helpers); read at queue-
	 * entry stamping time to copy into queue_entry.splice.
	 *
	 *   type == SPLICE_OP_NONE          legacy aio path (or sendfile)
	 *   type == SPLICE_OP_UNSIGNED_OUT  unsigned: file -> pipe -> socket
	 *   type == SPLICE_OP_SIGNED_OUT    signed: file -> pipe + tee into
	 *                                   AF_ALG, patch MAC into header,
	 *                                   send hdr_pipe then body_pipe to
	 *                                   socket
	 *
	 * signing_key is set iff type == SPLICE_OP_SIGNED_OUT (resolved at
	 * scheduling time so the splice state machine doesn't have to look
	 * it up again).
	 */
	struct {
		enum splice_op_type      type;
		struct smb2_signing_key *signing_key;
	} splice;
#endif
};

static int smb2_smb2_read_state_deny_destructor(struct smbd_smb2_read_state *state)
{
	return -1;
}

/* struct smbd_smb2_read_state destructor. Send the SMB2_READ data. */
static int smb2_sendfile_send_data(struct smbd_smb2_read_state *state)
{
	uint32_t in_length = state->in_length;
	uint64_t in_offset = state->in_offset;
	files_struct *fsp = state->fsp;
	const DATA_BLOB *hdr = state->smb2req->queue_entry.sendfile_header;
	NTSTATUS *pstatus = state->smb2req->queue_entry.sendfile_status;
	struct smbXsrv_connection *xconn = state->smb2req->xconn;
	ssize_t nread;
	ssize_t ret;
	int saved_errno;

	nread = SMB_VFS_SENDFILE(xconn->transport.sock,
				 fsp,
				 hdr,
				 in_offset,
				 in_length);
	DBG_DEBUG("SMB_VFS_SENDFILE returned %zd on file %s\n",
		  nread,
		  fsp_str_dbg(fsp));

	if (nread == -1) {
		saved_errno = errno;

		/*
		 * Returning ENOSYS means no data at all was sent.
		   Do this as a normal read. */
		if (errno == ENOSYS) {
			goto normal_read;
		}

		if (errno == ENOTSUP) {
			set_use_sendfile(SNUM(fsp->conn), false);
			DBG_WARNING("Disabling sendfile use as sendfile is "
				    "not supported by the system\n");
			goto normal_read;
		}

		if (errno == EINTR) {
			/*
			 * Special hack for broken Linux with no working sendfile. If we
			 * return EINTR we sent the header but not the rest of the data.
			 * Fake this up by doing read/write calls.
			 */
			set_use_sendfile(SNUM(fsp->conn), false);
			nread = fake_sendfile(xconn, fsp, in_offset, in_length);
			if (nread == -1) {
				saved_errno = errno;
				DBG_ERR("fake_sendfile failed for file %s "
					"(%s) for client %s. Terminating\n",
					fsp_str_dbg(fsp),
					strerror(saved_errno),
					smbXsrv_connection_dbg(xconn));
				*pstatus = map_nt_error_from_unix_common(saved_errno);
				return 0;
			}
			goto out;
		}

		DBG_ERR("sendfile failed for file "
			"%s (%s) for client %s. Terminating\n",
			fsp_str_dbg(fsp),
			strerror(saved_errno),
			smbXsrv_connection_dbg(xconn));
		*pstatus = map_nt_error_from_unix_common(saved_errno);
		return 0;
	} else if (nread == 0) {
		/*
		 * Some sendfile implementations return 0 to indicate
		 * that there was a short read, but nothing was
		 * actually written to the socket.  In this case,
		 * fallback to the normal read path so the header gets
		 * the correct byte count.
		 */
		DBG_NOTICE("sendfile sent zero bytes "
			   "falling back to the normal read: %s\n",
			   fsp_str_dbg(fsp));
		goto normal_read;
	}

	/*
	 * We got a short read
	 */
	goto out;

normal_read:
	/* Send out the header. */
	ret = write_data(xconn->transport.sock,
			 (const char *)hdr->data, hdr->length);
	if (ret != hdr->length) {
		saved_errno = errno;
		DBG_ERR("write_data failed for file "
			"%s (%s) for client %s. Terminating\n",
			fsp_str_dbg(fsp),
			strerror(saved_errno),
			smbXsrv_connection_dbg(xconn));
		*pstatus = map_nt_error_from_unix_common(saved_errno);
		return 0;
	}
	nread = fake_sendfile(xconn, fsp, in_offset, in_length);
	if (nread == -1) {
		saved_errno = errno;
		DBG_ERR("fake_sendfile failed for file %s (%s) for client %s. "
			"Terminating\n",
			fsp_str_dbg(fsp),
			strerror(saved_errno),
			smbXsrv_connection_dbg(xconn));
		*pstatus = map_nt_error_from_unix_common(saved_errno);
		return 0;
	}

  out:

	if (nread < in_length) {
		ret = sendfile_short_send(xconn, fsp, nread,
					  hdr->length, in_length);
		if (ret == -1) {
			saved_errno = errno;
			DBG_ERR("sendfile_short_send "
				"failed for file %s (%s) for client %s. "
				"Terminating\n",
				fsp_str_dbg(fsp),
				strerror(saved_errno),
				smbXsrv_connection_dbg(xconn));
			*pstatus = map_nt_error_from_unix_common(saved_errno);
			return 0;
		}
	}

	*pstatus = NT_STATUS_OK;
	return 0;
}

static NTSTATUS schedule_smb2_sendfile_read(struct smbd_smb2_request *smb2req,
					struct smbd_smb2_read_state *state)
{
	files_struct *fsp = state->fsp;

	/*
	 * We cannot use sendfile if...
	 * We were not configured to do so OR
	 * Signing is active OR
	 * This is a compound SMB2 operation OR
	 * fsp is a STREAM file OR
	 * It's not a regular file OR
	 * Requested offset is greater than file size OR
	 * there's not enough data in the file.
	 * Phew :-). Luckily this means most
	 * reads on most normal files. JRA.
	*/

	if (!lp__use_sendfile(SNUM(fsp->conn)) ||
	    smb2req->do_signing ||
	    smb2req->do_encryption ||
	    smbd_smb2_is_compound(smb2req) ||
	    fsp_is_alternate_stream(fsp) ||
	    (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) ||
	    (state->in_offset >= fsp->fsp_name->st.st_ex_size) ||
	    (fsp->fsp_name->st.st_ex_size < state->in_offset + state->in_length))
	{
		return NT_STATUS_RETRY;
	}

	/* We've already checked there's this amount of data
	   to read. */
	state->out_data.length = state->in_length;
	state->out_remaining = 0;

	state->out_headers = data_blob_const(state->_out_hdr_buf,
					     sizeof(state->_out_hdr_buf));
	return NT_STATUS_OK;
}

#ifdef HAVE_LIBURING
/*
 * Outbound splice eligibility + state setup (file -> pipe -> socket).
 * Mirrors the sendfile gates plus the truenas_uring pipe-pool availability
 * check. On success the caller flips the state to "splice mode" --
 * smbd_smb2_read_recv later stamps the queue entry's splice fields and
 * registers a tracker against fsp->aio_requests so SMB2 CLOSE waits for
 * the splice to complete. Picks SPLICE_OP_SIGNED_OUT or
 * SPLICE_OP_UNSIGNED_OUT on state->splice.type based on whether the PDU
 * is signed.
 *
 * Filesystem-class hazard: on non-ZFS filesystems (ext4/xfs/btrfs) the
 * file -> pipe splice via filemap_splice_read has the sendfile-class
 * page-borrow corruption window (a concurrent writer can mutate the
 * in-flight bytes -- the splice-borrow regression covered by
 * source4/torture/local/truenas_uring.c). On ZFS the kernel uses
 * copy_splice_read which snapshots, so the window doesn't exist. The
 * TrueNAS fork ships only on ZFS-backed shares, so we don't probe
 * statfs here: the master knob `truenas_uring:enabled` is the opt-in.
 */
static NTSTATUS schedule_smb2_splice_read(struct smbd_smb2_request *smb2req,
					   struct smbd_smb2_read_state *state)
{
	struct smbXsrv_connection *xconn = smb2req->xconn;
	files_struct *fsp = state->fsp;
	struct truenas_uring *u;
	struct truenas_uring_pipe probe;
	struct lock_struct lock;

	if (!xconn->smb2.uring->enabled.splice_send) {
		return NT_STATUS_RETRY;
	}

	/*
	 * Plain (unsigned, unencrypted) READs: prefer the registered-buffer +
	 * SENDMSG_ZC aio path (schedule_smb2_aio_read) over splice. On ZFS the
	 * file -> pipe leg is copy_splice_read (no page borrow), so splice gains
	 * no read-side zero-copy and adds per-op pipe-page alloc/free churn on
	 * the shared page allocator -- measured ~6% slower than the legacy path.
	 * The regbuf path reads into a pinned, reused slot (READ_FIXED) and DMAs
	 * straight from it (SENDMSG_ZC) with no per-op page allocation. Decline
	 * here so dispatch falls through to it. Only divert when it is actually
	 * available (SENDMSG_ZC enabled); otherwise splice stays the best
	 * outbound option (it is the only zero-copy send when ZC is off).
	 * Signed READs keep the splice + AF_ALG patched-MAC path below.
	 */
	if (!smb2req->do_signing && !smb2req->do_encryption &&
	    xconn->smb2.uring->enabled.sendmsg_zc) {
		return NT_STATUS_RETRY;
	}

	/* Splice-incompatible request shapes (mirrors sendfile gates).
	 *
	 * Signed-but-unencrypted READs are allowed iff signed splice
	 * outbound is enabled: the state machine in smb2_server.c tees the
	 * spliced payload through AF_ALG, patches the MAC into the response
	 * header, then sends header + payload. Encrypted requests are still
	 * rejected (those belong to the registered-buffer + SEND_ZC path).
	 */
	if (smb2req->do_encryption ||
	    smbd_smb2_is_compound(smb2req) ||
	    fsp_is_alternate_stream(fsp) ||
	    !S_ISREG(fsp->fsp_name->st.st_ex_mode) ||
	    state->in_offset >= fsp->fsp_name->st.st_ex_size ||
	    fsp->fsp_name->st.st_ex_size <
		state->in_offset + state->in_length) {
		return NT_STATUS_RETRY;
	}
	if (smb2req->do_signing) {
		struct smb2_signing_key *sk;
		sk = smbd_smb2_signing_key(smb2req->session, xconn, NULL);
		if (sk == NULL || !smb2_signing_key_valid(sk)) {
			return NT_STATUS_RETRY;
		}
		/* AF_ALG must support the algorithm. SMB3.1.1 AES-GMAC is
		 * handled via algif_hash("ghash") with the GHASH subkey
		 * H = AES_K(0^128) -- see truenas_smb2_alg_hmac_acquire for
		 * the H derivation and splice_signed_compute_gmac_tag for the
		 * finalize. SMB2.x HMAC-SHA256 and SMB3.0+ AES-CMAC map
		 * directly to algif_hash bindings of the same name. */
		switch (sk->sign_algo_id) {
		case SMB2_SIGNING_HMAC_SHA256:
		case SMB2_SIGNING_AES128_CMAC:
		case SMB2_SIGNING_AES128_GMAC:
			break;
		default: return NT_STATUS_RETRY;
		}
		state->splice.type        = SPLICE_OP_SIGNED_OUT;
		state->splice.signing_key = sk;
	}

	/* Pipe pool must be registered with at least one free pipe.
	 * Probe by acquire+release; the actual acquire happens at flush
	 * time. (A "peek-free" API would avoid this microscopic dance,
	 * but probe-then-release is harmless and rare on the happy path.) */
	u = truenas_uring_get(xconn->client->raw_ev_ctx);
	if (u == NULL) {
		return NT_STATUS_RETRY;
	}
	probe = truenas_uring_pipe_acquire(u);
	if (probe.slot < 0) {
		return NT_STATUS_RETRY;
	}
	truenas_uring_pipe_release(u, probe.slot);

	/* Strict-lock check (mirrors schedule_smb2_aio_read's check). */
	init_strict_lock_struct(fsp,
				fsp->op->global->open_persistent_id,
				state->in_offset,
				state->in_length,
				READ_LOCK,
				&lock);
	if (!SMB_VFS_STRICT_LOCK_CHECK(fsp->conn, fsp, &lock)) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	/*
	 * Mark splice. out_data.length = in_length (fake -- no buffer) is
	 * the existing sendfile-hack trigger in smbd_smb2_request_reply
	 * that chops the data iov off the queue entry, leaving just the
	 * response header iovs in vector/count. The flush function's
	 * splice path then vmsplices those iovs into the pipe and appends
	 * the file payload before splicing pipe -> socket.
	 */
	state->out_data.length = state->in_length;
	state->out_remaining = 0;
	/*
	 * Only stamp the UNSIGNED variant here if the signed branch above
	 * didn't already pick SIGNED_OUT. (NONE is the talloc_zero default.)
	 */
	if (state->splice.type == SPLICE_OP_NONE) {
		state->splice.type = SPLICE_OP_UNSIGNED_OUT;
	}

	return NT_STATUS_OK;
}

struct smb2_splice_tracker_state { uint8_t dummy; };
#endif /* HAVE_LIBURING */

static void smbd_smb2_read_pipe_done(struct tevent_req *subreq);

/*******************************************************************
 Common read complete processing function for both synchronous and
 asynchronous reads.
*******************************************************************/

NTSTATUS smb2_read_complete(struct tevent_req *req, ssize_t nread, int err)
{
	struct smbd_smb2_read_state *state = tevent_req_data(req,
					struct smbd_smb2_read_state);
	files_struct *fsp = state->fsp;

	if (nread < 0) {
		NTSTATUS status = map_nt_error_from_unix(err);

		DEBUG( 3,( "smb2_read_complete: file %s nread = %d. "
			"Error = %s (NTSTATUS %s)\n",
			fsp_str_dbg(fsp),
			(int)nread,
			strerror(err),
			nt_errstr(status)));

		return status;
	}
	if (nread == 0 && state->in_length != 0) {
		DEBUG(5,("smb2_read_complete: read_file[%s] end of file\n",
			fsp_str_dbg(fsp)));
		return NT_STATUS_END_OF_FILE;
	}

	if (nread < state->in_minimum) {
		DEBUG(5,("smb2_read_complete: read_file[%s] read less %d than "
			"minimum requested %u. Returning end of file\n",
			fsp_str_dbg(fsp),
			(int)nread,
			(unsigned int)state->in_minimum));
		return NT_STATUS_END_OF_FILE;
	}

	DEBUG(3,("smbd_smb2_read: %s, file %s, length=%lu offset=%lu read=%lu\n",
		fsp_fnum_dbg(fsp),
		fsp_str_dbg(fsp),
		(unsigned long)state->in_length,
		(unsigned long)state->in_offset,
		(unsigned long)nread));

	state->out_data.length = nread;
	state->out_remaining = 0;

	return NT_STATUS_OK;
}

static bool smbd_smb2_read_ipc_cancel(struct tevent_req *req)
{
	struct smbd_smb2_read_state *state =
		tevent_req_data(req,
		struct smbd_smb2_read_state);

	TALLOC_FREE(state->ipc_subreq);
	tevent_req_defer_callback(req, state->smb2req->xconn->client->raw_ev_ctx);
	if (state->fsp->fsp_flags.closing) {
		tevent_req_nterror(req, NT_STATUS_PIPE_BROKEN);
	} else {
		tevent_req_nterror(req, NT_STATUS_CANCELLED);
	}
	return true;
}

static bool smbd_smb2_read_cancel(struct tevent_req *req)
{
	struct smbd_smb2_read_state *state =
		tevent_req_data(req,
		struct smbd_smb2_read_state);

	return cancel_smb2_aio(state->smbreq);
}

static struct tevent_req *smbd_smb2_read_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      struct files_struct *fsp,
					      uint8_t in_flags,
					      uint32_t in_length,
					      uint64_t in_offset,
					      uint32_t in_minimum,
					      uint32_t in_remaining)
{
	NTSTATUS status;
	struct tevent_req *req = NULL;
	struct smbd_smb2_read_state *state = NULL;
	struct smb_request *smbreq = NULL;
	connection_struct *conn = smb2req->tcon->compat;
	ssize_t nread = -1;
	struct lock_struct lock;
	int saved_errno;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;
	state->in_flags = in_flags;
	state->in_length = in_length;
	state->in_offset = in_offset;
	state->in_minimum = in_minimum;
	state->out_data = data_blob_null;
	state->out_remaining = 0;

	DEBUG(10,("smbd_smb2_read: %s - %s\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

	smbreq = smbd_smb2_fake_smb_request(smb2req, fsp);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}
	state->smbreq = smbreq;

	if (fsp->fsp_flags.is_directory) {
		tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		return tevent_req_post(req, ev);
	}

	state->fsp = fsp;

	if (IS_IPC(smbreq->conn)) {
		struct tevent_req *subreq = NULL;
		struct aio_req_fsp_link *aio_lnk = NULL;

		state->out_data = data_blob_talloc(state, NULL, in_length);
		if (in_length > 0 && tevent_req_nomem(state->out_data.data, req)) {
			return tevent_req_post(req, ev);
		}

		if (!fsp_is_np(fsp)) {
			tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
			return tevent_req_post(req, ev);
		}

		subreq = np_read_send(state, ev,
				      fsp->fake_file_handle,
				      state->out_data.data,
				      state->out_data.length);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smbd_smb2_read_pipe_done,
					req);

		/*
		 * Make sure we mark the fsp as having outstanding async
		 * activity so we don't crash on shutdown close.
		 */

		aio_lnk = aio_add_req_to_fsp(fsp, req);
		if (aio_lnk == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return tevent_req_post(req, ev);
		}
		talloc_move(subreq, &aio_lnk);

		state->ipc_subreq = subreq;
		tevent_req_set_cancel_fn(req, smbd_smb2_read_ipc_cancel);
		return req;
	}

	if (!CHECK_READ_SMB2(fsp)) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return tevent_req_post(req, ev);
	}

#ifdef HAVE_LIBURING
	/*
	 * Outbound splice (file -> pipe -> socket): try first for eligible
	 * requests so the payload never lands in a userspace buffer. On
	 * TrueNAS this is the only zero-copy outbound path (sendfile is
	 * forcibly disabled). schedule_smb2_splice_read picks
	 * SPLICE_OP_SIGNED_OUT or SPLICE_OP_UNSIGNED_OUT internally based
	 * on the signing posture.
	 */
	status = schedule_smb2_splice_read(smb2req, state);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
#endif

	status = schedule_smb2_aio_read(fsp->conn,
				smbreq,
				fsp,
				state,
				&state->out_data,
				(off_t)in_offset,
				(size_t)in_length);

	if (NT_STATUS_IS_OK(status)) {
		/*
		 * Doing an async read, allow this
		 * request to be canceled
		 */
		tevent_req_set_cancel_fn(req, smbd_smb2_read_cancel);
		return req;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		/* Real error in setting up aio. Fail. */
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	/* Fallback to synchronous. */

	init_strict_lock_struct(fsp,
				fsp->op->global->open_persistent_id,
				in_offset,
				in_length,
				READ_LOCK,
				&lock);

	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &lock)) {
		tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		return tevent_req_post(req, ev);
	}

	/* Try sendfile in preference. */
	status = schedule_smb2_sendfile_read(smb2req, state);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	/* Ok, read into memory. Allocate the out buffer. */
	state->out_data = data_blob_talloc(state, NULL, in_length);
	if (in_length > 0 && tevent_req_nomem(state->out_data.data, req)) {
		return tevent_req_post(req, ev);
	}

	nread = read_file(fsp,
			  (char *)state->out_data.data,
			  in_offset,
			  in_length);

	saved_errno = errno;

	DEBUG(10,("smbd_smb2_read: file %s, %s, offset=%llu "
		"len=%llu returned %lld\n",
		fsp_str_dbg(fsp),
		fsp_fnum_dbg(fsp),
		(unsigned long long)in_offset,
		(unsigned long long)in_length,
		(long long)nread));

	status = smb2_read_complete(req, nread, saved_errno);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
	} else {
		/* Success. */
		tevent_req_done(req);
	}
	return tevent_req_post(req, ev);
}

static void smbd_smb2_read_pipe_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct smbd_smb2_read_state *state = tevent_req_data(req,
					     struct smbd_smb2_read_state);
	NTSTATUS status;
	ssize_t nread = -1;
	bool is_data_outstanding;

	status = np_read_recv(subreq, &nread, &is_data_outstanding);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		NTSTATUS old = status;
		status = nt_status_np_pipe(old);
		tevent_req_nterror(req, status);
		return;
	}

	if (nread == 0 && state->out_data.length != 0) {
		tevent_req_nterror(req, NT_STATUS_END_OF_FILE);
		return;
	}

	state->out_data.length = nread;
	state->out_remaining = 0;

	/*
	 * TODO: add STATUS_BUFFER_OVERFLOW handling, once we also
	 * handle it in SMB1 pipe_read_andx_done().
	 */

	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_read_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_data,
				    uint32_t *out_remaining)
{
	NTSTATUS status;
	struct smbd_smb2_read_state *state = tevent_req_data(req,
					     struct smbd_smb2_read_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_data = state->out_data;
#ifdef HAVE_LIBURING
	{
		/*
		 * Encrypted-READ fast path uses a buffer from the truenas_uring
		 * registered fixed-pool. Those pointers are NOT talloc chunks;
		 * talloc_steal on them would dereference random memory before
		 * the pointer trying to read the TC_HDR. A lifetime-owner
		 * sentinel is already parented to the SMB2 request (smb2req)
		 * by schedule_smb2_aio_read, so the slot is released when the
		 * request is freed; no steal is necessary in that case.
		 */
		struct truenas_uring *u = truenas_uring_get(
			state->fsp->conn->sconn->ev_ctx);
		if (u != NULL && out_data->data != NULL &&
		    truenas_uring_buf_index(u, out_data->data) >= 0) {
			/* pool-backed -- skip steal */
		} else if (out_data->data != NULL) {
			talloc_steal(mem_ctx, out_data->data);
		}
	}
#else
	if (out_data->data != NULL) {
		talloc_steal(mem_ctx, out_data->data);
	}
#endif
	*out_remaining = state->out_remaining;

	if (state->out_headers.length > 0) {
		talloc_steal(mem_ctx, state);
		talloc_set_destructor(state, smb2_smb2_read_state_deny_destructor);
		tevent_req_received(req);
		state->smb2req->queue_entry.sendfile_header = &state->out_headers;
		state->smb2req->queue_entry.sendfile_body_size = state->in_length;
		talloc_set_destructor(state, smb2_sendfile_send_data);
		return NT_STATUS_OK;
	}

#ifdef HAVE_LIBURING
	if (state->splice.type != SPLICE_OP_NONE) {
		struct tevent_req *tracker;
		struct smb2_splice_tracker_state *tdummy;

		/*
		 * Stamp the queue entry with the splice descriptor. The async
		 * flush state machine (smbd_smb2_flush_with_sendmsg_uring)
		 * picks this up when the entry reaches the queue head: vmsplice
		 * the header iovs into a pipe, IORING_OP_SPLICE file->pipe,
		 * IORING_OP_SPLICE pipe->socket, advance queue.
		 */
		state->smb2req->queue_entry.splice.type        = state->splice.type;
		state->smb2req->queue_entry.splice.fsp         = state->fsp;
		state->smb2req->queue_entry.splice.offset      = state->in_offset;
		state->smb2req->queue_entry.splice.payload_len = state->in_length;
		if (state->splice.type == SPLICE_OP_SIGNED_OUT) {
			state->smb2req->queue_entry.splice.signed_out.signing_key =
				state->splice.signing_key;
			/*
			 * outhdr_ptr is stamped by the caller after the response
			 * is fully built (not available yet here -- do_signing
			 * zeroes the signature only in the final assembly step).
			 */
		}

		/*
		 * Create a tracker tevent_req parented to smb2req (which is
		 * the queue entry's mem_ctx and survives until pipe->socket
		 * CQE fires). aio_add_req_to_fsp registers a link parented
		 * to the tracker -- when the tracker is freed (with smb2req
		 * after splice completes) the link's destructor decrements
		 * fsp->num_aio_requests.
		 *
		 * SMB2 CLOSE iterates fsp->aio_requests, calls
		 * tevent_req_cancel (no-op here since we set no cancel fn),
		 * then waits on the existing tevent_queue mechanism until
		 * the array drains. So CLOSE blocks until our splice
		 * completes -- fsp stays alive throughout.
		 */
		tracker = tevent_req_create(state->smb2req, &tdummy,
					    struct smb2_splice_tracker_state);
		if (tracker == NULL) {
			tevent_req_received(req);
			return NT_STATUS_NO_MEMORY;
		}
		if (aio_add_req_to_fsp(state->fsp, tracker) == NULL) {
			TALLOC_FREE(tracker);
			tevent_req_received(req);
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_received(req);
		return NT_STATUS_OK;
	}
#endif

	tevent_req_received(req);
	return NT_STATUS_OK;
}
