/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2021

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
#include "../libcli/smb/smb_common.h"
#include "../lib/util/tevent_ntstatus.h"
#include "include/ntioctl.h"
#include "smb2_ioctl_private.h"
#include "librpc/gen_ndr/ioctl.h"
#ifdef HAVE_LIBURING
#include "smbd/smbd_smb2_uring.h"
#endif

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

struct async_sleep_state {
	struct smbd_server_connection *sconn;
	files_struct *fsp;
};

static void smbd_fsctl_torture_async_sleep_done(struct tevent_req *subreq);

static struct tevent_req *smbd_fsctl_torture_async_sleep_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				files_struct *fsp,
				uint8_t msecs)
{
	struct async_sleep_state *state = NULL;
	struct tevent_req *subreq = NULL;
	bool ok;

	subreq = tevent_req_create(mem_ctx,
				&state,
				struct async_sleep_state);
	if (!subreq) {
		return NULL;
	}

	/*
	 * Store the conn separately, as the test is to
	 * see if fsp is still a valid pointer, so we can't
	 * do anything other than test it for entry in the
	 * open files on this server connection.
	 */
	state->sconn = fsp->conn->sconn;
	state->fsp = fsp;

	/*
	 * Just wait for the specified number of micro seconds,
	 * to allow the client time to close fsp.
	 */
	ok = tevent_req_set_endtime(subreq,
				    ev,
				    timeval_current_ofs(0, msecs));
	if (!ok) {
		tevent_req_nterror(subreq, NT_STATUS_NO_MEMORY);
		return tevent_req_post(subreq, ev);
	}

	return subreq;
}

static files_struct *find_my_fsp(struct files_struct *fsp,
				 void *private_data)
{
	struct files_struct *myfsp = (struct files_struct *)private_data;

	if (fsp == myfsp) {
		return myfsp;
	}
	return NULL;
}

static bool smbd_fsctl_torture_async_sleep_recv(struct tevent_req *subreq)
{
	tevent_req_received(subreq);
	return true;
}

static void smbd_fsctl_torture_async_sleep_done(struct tevent_req *subreq)
{
	struct files_struct *found_fsp;
	struct tevent_req *req = tevent_req_callback_data(
					subreq,
					struct tevent_req);
	struct async_sleep_state *state = tevent_req_data(
					subreq,
					struct async_sleep_state);

	/* Does state->fsp still exist on state->sconn ? */
	found_fsp = files_forall(state->sconn,
				 find_my_fsp,
				 state->fsp);

	smbd_fsctl_torture_async_sleep_recv(subreq);
	TALLOC_FREE(subreq);

	if (found_fsp == NULL) {
		/*
		 * We didn't find it - return an error to the
		 * smb2 ioctl request. Use NT_STATUS_FILE_CLOSED so
		 * the client can tell the difference between
		 * a bad fsp handle and
		 *
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=14769
		 *
		 * This request should block file closure until it
		 * has completed.
		 */
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return;
	}
	tevent_req_done(req);
}

struct tevent_req *smb2_ioctl_smbtorture(uint32_t ctl_code,
					 struct tevent_context *ev,
					 struct tevent_req *req,
					 struct smbd_smb2_ioctl_state *state)
{
	NTSTATUS status;
	bool ok;

	ok = lp_parm_bool(-1, "smbd", "FSCTL_SMBTORTURE", false);
	if (!ok) {
		goto not_supported;
	}

	switch (ctl_code) {
	case FSCTL_SMBTORTURE_FORCE_UNACKED_TIMEOUT:
		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		state->smb2req->xconn->ack.force_unacked_timeout = true;
		tevent_req_done(req);
		return tevent_req_post(req, ev);

	case FSCTL_SMBTORTURE_IOCTL_RESPONSE_BODY_PADDING8:
		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		if (state->in_max_output > 0) {
			uint32_t size = state->in_max_output;

			state->out_output = data_blob_talloc(state, NULL, size);
			if (tevent_req_nomem(state->out_output.data, req)) {
				return tevent_req_post(req, ev);
			}
			memset(state->out_output.data, 8, size);
		}

		state->body_padding = 8;
		tevent_req_done(req);
		return tevent_req_post(req, ev);

	case FSCTL_SMBTORTURE_GLOBAL_READ_RESPONSE_BODY_PADDING8:
		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		state->smb2req->xconn->smb2.smbtorture.read_body_padding = 8;
		tevent_req_done(req);
		return tevent_req_post(req, ev);

#ifdef HAVE_LIBURING
	case FSCTL_SMBTORTURE_TRUENAS_URING_COUNTERS_READ: {
		struct samba_uring_xconn *u =
			state->smb2req->xconn->smb2.uring;
		uint8_t *out;
		const struct samba_uring_counters *c;
		size_t want = SAMBA_URING_COUNTERS_WIRE_BYTES;

		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (u == NULL) {
			/* xconn->smb2.uring is allocated at negprot; we
			 * shouldn't get here before that. Defensive return. */
			tevent_req_nterror(req, NT_STATUS_DEVICE_NOT_READY);
			return tevent_req_post(req, ev);
		}
		if (state->in_max_output < want) {
			tevent_req_nterror(req, NT_STATUS_BUFFER_TOO_SMALL);
			return tevent_req_post(req, ev);
		}

		state->out_output = data_blob_talloc(state, NULL, want);
		if (tevent_req_nomem(state->out_output.data, req)) {
			return tevent_req_post(req, ev);
		}
		out = state->out_output.data;
		c   = &u->counters;
		SBVAL(out,   0, c->unsigned_splice_in);
		SBVAL(out,   8, c->signed_splice_in);
		SBVAL(out,  16, c->signed_splice_in_denied);
		SBVAL(out,  24, c->unsigned_splice_out);
		SBVAL(out,  32, c->signed_splice_out);
		SBVAL(out,  40, c->encrypted_recv);
		SBVAL(out,  48, c->encrypted_send_zc);
		SBVAL(out,  56, c->legacy_recv);
		SBVAL(out,  64, c->legacy_send);
		SBVAL(out,  72, c->bytes_unsigned_splice_in);
		SBVAL(out,  80, c->bytes_signed_splice_in);
		SBVAL(out,  88, c->bytes_unsigned_splice_out);
		SBVAL(out,  96, c->bytes_signed_splice_out);
		SBVAL(out, 104, c->bytes_encrypted_in);
		SBVAL(out, 112, c->bytes_encrypted_out);
		SBVAL(out, 120, c->signed_alg_cache_hits);
		SBVAL(out, 128, c->signed_alg_cache_misses);
		SBVAL(out, 136, c->inflight_throttle_events);
		SBVAL(out, 144, c->inflight_bytes_peak);
		SBVAL(out, 152, c->unsigned_recv_mempool);
		SBVAL(out, 160, c->bytes_unsigned_mempool_out);

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	case FSCTL_SMBTORTURE_TRUENAS_URING_COUNTERS_RESET: {
		struct samba_uring_xconn *u =
			state->smb2req->xconn->smb2.uring;

		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (u == NULL) {
			tevent_req_nterror(req, NT_STATUS_DEVICE_NOT_READY);
			return tevent_req_post(req, ev);
		}
		ZERO_STRUCT(u->counters);

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	case FSCTL_SMBTORTURE_TRUENAS_URING_FORCE_NEXT_SIGNED_WRITE_FAIL: {
		struct samba_uring_xconn *u =
			state->smb2req->xconn->smb2.uring;

		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (u == NULL) {
			tevent_req_nterror(req, NT_STATUS_DEVICE_NOT_READY);
			return tevent_req_post(req, ev);
		}
		u->force_signed_in_fail = true;

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	case FSCTL_SMBTORTURE_TRUENAS_URING_FORCE_NEXT_POSIX_APPEND: {
		struct samba_uring_xconn *u =
			state->smb2req->xconn->smb2.uring;

		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (u == NULL) {
			tevent_req_nterror(req, NT_STATUS_DEVICE_NOT_READY);
			return tevent_req_post(req, ev);
		}
		u->force_next_posix_append = true;

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	case FSCTL_SMBTORTURE_TRUENAS_URING_SET_MAX_INFLIGHT_BYTES: {
		struct samba_uring_xconn *u =
			state->smb2req->xconn->smb2.uring;

		if (state->in_input.length != 8) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (u == NULL) {
			tevent_req_nterror(req, NT_STATUS_DEVICE_NOT_READY);
			return tevent_req_post(req, ev);
		}
		u->max_inflight_bytes = BVAL(state->in_input.data, 0);

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
#endif /* HAVE_LIBURING */

	case FSCTL_SMBTORTURE_FSP_ASYNC_SLEEP: {
		struct tevent_req *subreq = NULL;

		/* Data is 1 byte of CVAL stored seconds to delay for. */
		if (state->in_input.length != 1) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (state->fsp == NULL) {
			tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
			return tevent_req_post(req, ev);
		}

		subreq = smbd_fsctl_torture_async_sleep_send(
						req,
						ev,
						state->fsp,
						CVAL(state->in_input.data,0));
		if (subreq == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smbd_fsctl_torture_async_sleep_done,
					req);
		return req;
        }

	default:
		goto not_supported;
	}

not_supported:
	if (IS_IPC(state->smbreq->conn)) {
		status = NT_STATUS_FS_DRIVER_REQUIRED;
	} else {
		status = NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	tevent_req_nterror(req, status);
	return tevent_req_post(req, ev);
}
