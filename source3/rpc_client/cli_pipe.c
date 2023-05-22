/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client routines
 *  Largely rewritten by Jeremy Allison		    2005.
 *  Heavily modified by Simo Sorce		    2010.
 *  Copyright Andrew Bartlett                       2011.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "libsmb/namequery.h"
#include "../lib/util/tevent_ntstatus.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "../librpc/gen_ndr/ndr_dssetup.h"
#include "../libcli/auth/schannel.h"
#include "../libcli/auth/netlogon_creds_cli.h"
#include "auth_generic.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "librpc/gen_ndr/auth.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_util.h"
#include "rpc_dce.h"
#include "cli_pipe.h"
#include "libsmb/libsmb.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "auth/auth_util.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "librpc/gen_ndr/ndr_winreg.h"
#include "local_np.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_CLI

/********************************************************************
 Pipe description for a DEBUG
 ********************************************************************/
static const char *rpccli_pipe_txt(TALLOC_CTX *mem_ctx,
				   struct rpc_pipe_client *cli)
{
	char *result = talloc_asprintf(mem_ctx, "host %s", cli->desthost);
	if (result == NULL) {
		return "pipe";
	}
	return result;
}

/********************************************************************
 Rpc pipe call id.
 ********************************************************************/

static uint32_t get_rpc_call_id(void)
{
	static uint32_t call_id = 0;
	return ++call_id;
}

/*******************************************************************
 Use SMBreadX to get rest of one fragment's worth of rpc data.
 Reads the whole size or give an error message
 ********************************************************************/

struct rpc_read_state {
	struct tevent_context *ev;
	struct rpc_cli_transport *transport;
	uint8_t *data;
	size_t size;
	size_t num_read;
};

static void rpc_read_done(struct tevent_req *subreq);

static struct tevent_req *rpc_read_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct rpc_cli_transport *transport,
					uint8_t *data, size_t size)
{
	struct tevent_req *req, *subreq;
	struct rpc_read_state *state;

	req = tevent_req_create(mem_ctx, &state, struct rpc_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->transport = transport;
	state->data = data;
	state->size = size;
	state->num_read = 0;

	DBG_INFO("data_to_read: %zu\n", size);

	subreq = transport->read_send(state, ev, (uint8_t *)data, size,
				      transport->priv);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, rpc_read_done, req);
	return req;

 fail:
	TALLOC_FREE(req);
	return NULL;
}

static void rpc_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_read_state *state = tevent_req_data(
		req, struct rpc_read_state);
	NTSTATUS status;
	ssize_t received;

	status = state->transport->read_recv(subreq, &received);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->num_read += received;
	if (state->num_read == state->size) {
		tevent_req_done(req);
		return;
	}

	subreq = state->transport->read_send(state, state->ev,
					     state->data + state->num_read,
					     state->size - state->num_read,
					     state->transport->priv);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_read_done, req);
}

static NTSTATUS rpc_read_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct rpc_write_state {
	struct tevent_context *ev;
	struct rpc_cli_transport *transport;
	const uint8_t *data;
	size_t size;
	size_t num_written;
};

static void rpc_write_done(struct tevent_req *subreq);

static struct tevent_req *rpc_write_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct rpc_cli_transport *transport,
					 const uint8_t *data, size_t size)
{
	struct tevent_req *req, *subreq;
	struct rpc_write_state *state;

	req = tevent_req_create(mem_ctx, &state, struct rpc_write_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->transport = transport;
	state->data = data;
	state->size = size;
	state->num_written = 0;

	DBG_INFO("data_to_write: %zu\n", size);

	subreq = transport->write_send(state, ev, data, size, transport->priv);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_write_done, req);
	return req;
}

static void rpc_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_write_state *state = tevent_req_data(
		req, struct rpc_write_state);
	NTSTATUS status;
	ssize_t written;

	status = state->transport->write_recv(subreq, &written);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->num_written += written;

	if (state->num_written == state->size) {
		tevent_req_done(req);
		return;
	}

	subreq = state->transport->write_send(state, state->ev,
					      state->data + state->num_written,
					      state->size - state->num_written,
					      state->transport->priv);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_write_done, req);
}

static NTSTATUS rpc_write_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}


/****************************************************************************
 Try and get a PDU's worth of data from current_pdu. If not, then read more
 from the wire.
 ****************************************************************************/

struct get_complete_frag_state {
	struct tevent_context *ev;
	struct rpc_pipe_client *cli;
	uint16_t frag_len;
	DATA_BLOB *pdu;
};

static void get_complete_frag_got_header(struct tevent_req *subreq);
static void get_complete_frag_got_rest(struct tevent_req *subreq);

static struct tevent_req *get_complete_frag_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct rpc_pipe_client *cli,
						 DATA_BLOB *pdu)
{
	struct tevent_req *req, *subreq;
	struct get_complete_frag_state *state;
	size_t received;

	req = tevent_req_create(mem_ctx, &state,
				struct get_complete_frag_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->frag_len = RPC_HEADER_LEN;
	state->pdu = pdu;

	received = pdu->length;
	if (received < RPC_HEADER_LEN) {
		if (!data_blob_realloc(mem_ctx, pdu, RPC_HEADER_LEN)) {
			tevent_req_oom(req);
			return tevent_req_post(req, ev);
		}
		subreq = rpc_read_send(state, state->ev,
					state->cli->transport,
					pdu->data + received,
					RPC_HEADER_LEN - received);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, get_complete_frag_got_header,
					req);
		return req;
	}

	state->frag_len = dcerpc_get_frag_length(pdu);
	if (state->frag_len < RPC_HEADER_LEN) {
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return tevent_req_post(req, ev);
	}

	if (received >= state->frag_len) {
		/*
		 * Got the whole fragment
		 */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (!data_blob_realloc(NULL, pdu, state->frag_len)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	subreq = rpc_read_send(
		state,
		state->ev,
		state->cli->transport,
		pdu->data + received,
		state->frag_len - received);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, get_complete_frag_got_rest, req);
	return req;
}

static void get_complete_frag_got_header(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct get_complete_frag_state *state = tevent_req_data(
		req, struct get_complete_frag_state);
	NTSTATUS status;

	status = rpc_read_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->frag_len = dcerpc_get_frag_length(state->pdu);
	if (state->frag_len < RPC_HEADER_LEN) {
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	if (!data_blob_realloc(NULL, state->pdu, state->frag_len)) {
		tevent_req_oom(req);
		return;
	}

	/*
	 * We're here in this piece of code because we've read exactly
	 * RPC_HEADER_LEN bytes into state->pdu.
	 */

	subreq = rpc_read_send(state, state->ev, state->cli->transport,
				state->pdu->data + RPC_HEADER_LEN,
				state->frag_len - RPC_HEADER_LEN);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, get_complete_frag_got_rest, req);
}

static void get_complete_frag_got_rest(struct tevent_req *subreq)
{
	NTSTATUS status = rpc_read_recv(subreq);
	return tevent_req_simple_finish_ntstatus(subreq, status);
}

static NTSTATUS get_complete_frag_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/****************************************************************************
 Do basic authentication checks on an incoming pdu.
 ****************************************************************************/

static NTSTATUS cli_pipe_validate_current_pdu(TALLOC_CTX *mem_ctx,
						struct rpc_pipe_client *cli,
						struct ncacn_packet *pkt,
						DATA_BLOB *pdu,
						uint8_t expected_pkt_type,
						uint32_t call_id,
						DATA_BLOB *rdata,
						DATA_BLOB *reply_pdu)
{
	const struct dcerpc_response *r = NULL;
	DATA_BLOB tmp_stub = { .data = NULL };
	NTSTATUS ret;

	/*
	 * Point the return values at the real data including the RPC
	 * header. Just in case the caller wants it.
	 */
	*rdata = *pdu;

	if ((pkt->ptype == DCERPC_PKT_BIND_ACK) &&
	    !(pkt->pfc_flags & DCERPC_PFC_FLAG_LAST)) {
		/*
		 * TODO: do we still need this hack which was introduced
		 * in commit a42afcdcc7ab9aa9ed193ae36d3dbb10843447f0.
		 *
		 * I don't even know what AS/U might be...
		 */
		DEBUG(5, (__location__ ": bug in server (AS/U?), setting "
			  "fragment first/last ON.\n"));
		pkt->pfc_flags |= DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	}

	/* Ensure we have the correct type. */
	switch (pkt->ptype) {
	case DCERPC_PKT_BIND_NAK:
		DEBUG(1, (__location__ ": Bind NACK received from %s!\n",
			  rpccli_pipe_txt(talloc_tos(), cli)));

		ret = dcerpc_verify_ncacn_packet_header(pkt,
						DCERPC_PKT_BIND_NAK,
						0, /* max_auth_info */
						DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
						0); /* optional flags */
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1, (__location__ ": Connection to %s got an unexpected "
				  "RPC packet type - %u, expected %u: %s\n",
				  rpccli_pipe_txt(talloc_tos(), cli),
				  pkt->ptype, expected_pkt_type,
				  nt_errstr(ret)));
			NDR_PRINT_DEBUG(ncacn_packet, pkt);
			return ret;
		}

		/* Use this for now... */
		return NT_STATUS_NETWORK_ACCESS_DENIED;

	case DCERPC_PKT_BIND_ACK:
		ret = dcerpc_verify_ncacn_packet_header(pkt,
					expected_pkt_type,
					pkt->u.bind_ack.auth_info.length,
					DCERPC_PFC_FLAG_FIRST |
					DCERPC_PFC_FLAG_LAST,
					DCERPC_PFC_FLAG_CONC_MPX |
					DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1, (__location__ ": Connection to %s got an unexpected "
				  "RPC packet type - %u, expected %u: %s\n",
				  rpccli_pipe_txt(talloc_tos(), cli),
				  pkt->ptype, expected_pkt_type,
				  nt_errstr(ret)));
			NDR_PRINT_DEBUG(ncacn_packet, pkt);
			return ret;
		}

		break;

	case DCERPC_PKT_ALTER_RESP:
		ret = dcerpc_verify_ncacn_packet_header(pkt,
					expected_pkt_type,
					pkt->u.alter_resp.auth_info.length,
					DCERPC_PFC_FLAG_FIRST |
					DCERPC_PFC_FLAG_LAST,
					DCERPC_PFC_FLAG_CONC_MPX |
					DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1, (__location__ ": Connection to %s got an unexpected "
				  "RPC packet type - %u, expected %u: %s\n",
				  rpccli_pipe_txt(talloc_tos(), cli),
				  pkt->ptype, expected_pkt_type,
				  nt_errstr(ret)));
			NDR_PRINT_DEBUG(ncacn_packet, pkt);
			return ret;
		}

		break;

	case DCERPC_PKT_RESPONSE:

		r = &pkt->u.response;

		ret = dcerpc_verify_ncacn_packet_header(pkt,
						expected_pkt_type,
						r->stub_and_verifier.length,
						0, /* required_flags */
						DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1, (__location__ ": Connection to %s got an unexpected "
				  "RPC packet type - %u, expected %u: %s\n",
				  rpccli_pipe_txt(talloc_tos(), cli),
				  pkt->ptype, expected_pkt_type,
				  nt_errstr(ret)));
			NDR_PRINT_DEBUG(ncacn_packet, pkt);
			return ret;
		}

		tmp_stub.data = r->stub_and_verifier.data;
		tmp_stub.length = r->stub_and_verifier.length;

		/* Here's where we deal with incoming sign/seal. */
		ret = dcerpc_check_auth(cli->auth, pkt,
					&tmp_stub,
					DCERPC_RESPONSE_LENGTH,
					pdu);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1, (__location__ ": Connection to %s got an unexpected "
				  "RPC packet type - %u, expected %u: %s\n",
				  rpccli_pipe_txt(talloc_tos(), cli),
				  pkt->ptype, expected_pkt_type,
				  nt_errstr(ret)));
			NDR_PRINT_DEBUG(ncacn_packet, pkt);
			return ret;
		}

		/* Point the return values at the NDR data. */
		*rdata = tmp_stub;

		DEBUG(10, ("Got pdu len %lu, data_len %lu\n",
			   (long unsigned int)pdu->length,
			   (long unsigned int)rdata->length));

		/*
		 * If this is the first reply, and the allocation hint is
		 * reasonable, try and set up the reply_pdu DATA_BLOB to the
		 * correct size.
		 */

		if ((reply_pdu->length == 0) &&
		    r->alloc_hint && (r->alloc_hint < 15*1024*1024)) {
			if (!data_blob_realloc(mem_ctx, reply_pdu,
							r->alloc_hint)) {
				DEBUG(0, ("reply alloc hint %d too "
					  "large to allocate\n",
					  (int)r->alloc_hint));
				return NT_STATUS_NO_MEMORY;
			}
		}

		break;

	case DCERPC_PKT_FAULT:

		ret = dcerpc_verify_ncacn_packet_header(pkt,
						DCERPC_PKT_FAULT,
						0, /* max_auth_info */
						DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
						DCERPC_PFC_FLAG_DID_NOT_EXECUTE);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1, (__location__ ": Connection to %s got an unexpected "
				  "RPC packet type - %u, expected %u: %s\n",
				  rpccli_pipe_txt(talloc_tos(), cli),
				  pkt->ptype, expected_pkt_type,
				  nt_errstr(ret)));
			NDR_PRINT_DEBUG(ncacn_packet, pkt);
			return ret;
		}

		DEBUG(1, (__location__ ": RPC fault code %s received "
			  "from %s!\n",
			  dcerpc_errstr(talloc_tos(),
			  pkt->u.fault.status),
			  rpccli_pipe_txt(talloc_tos(), cli)));

		return dcerpc_fault_to_nt_status(pkt->u.fault.status);

	default:
		DEBUG(0, (__location__ "Unknown packet type %u received "
			  "from %s!\n",
			  (unsigned int)pkt->ptype,
			  rpccli_pipe_txt(talloc_tos(), cli)));
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}


	if (pkt->call_id != call_id) {
		DEBUG(3, (__location__ ": Connection to %s got an unexpected "
			  "RPC call_id - %u, not %u\n",
			  rpccli_pipe_txt(talloc_tos(), cli),
			  pkt->call_id, call_id));
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Call a remote api on an arbitrary pipe.  takes param, data and setup buffers.
****************************************************************************/

struct cli_api_pipe_state {
	struct tevent_context *ev;
	struct rpc_cli_transport *transport;
	uint8_t *rdata;
	uint32_t rdata_len;
};

static void cli_api_pipe_trans_done(struct tevent_req *subreq);
static void cli_api_pipe_write_done(struct tevent_req *subreq);
static void cli_api_pipe_read_done(struct tevent_req *subreq);

static struct tevent_req *cli_api_pipe_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct rpc_cli_transport *transport,
					    uint8_t *data, size_t data_len,
					    uint32_t max_rdata_len)
{
	struct tevent_req *req, *subreq;
	struct cli_api_pipe_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_api_pipe_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->transport = transport;

	if (max_rdata_len < RPC_HEADER_LEN) {
		/*
		 * For a RPC reply we always need at least RPC_HEADER_LEN
		 * bytes. We check this here because we will receive
		 * RPC_HEADER_LEN bytes in cli_trans_sock_send_done.
		 */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	if (transport->trans_send != NULL) {
		subreq = transport->trans_send(state, ev, data, data_len,
					       max_rdata_len, transport->priv);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_api_pipe_trans_done, req);
		return req;
	}

	/*
	 * If the transport does not provide a "trans" routine, i.e. for
	 * example the ncacn_ip_tcp transport, do the write/read step here.
	 */

	subreq = rpc_write_send(state, ev, transport, data, data_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_api_pipe_write_done, req);
	return req;
}

static void cli_api_pipe_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_api_pipe_state *state = tevent_req_data(
		req, struct cli_api_pipe_state);
	NTSTATUS status;

	status = state->transport->trans_recv(subreq, state, &state->rdata,
					      &state->rdata_len);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static void cli_api_pipe_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_api_pipe_state *state = tevent_req_data(
		req, struct cli_api_pipe_state);
	NTSTATUS status;

	status = rpc_write_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->rdata = talloc_array(state, uint8_t, RPC_HEADER_LEN);
	if (tevent_req_nomem(state->rdata, req)) {
		return;
	}

	/*
	 * We don't need to use rpc_read_send here, the upper layer will cope
	 * with a short read, transport->trans_send could also return less
	 * than state->max_rdata_len.
	 */
	subreq = state->transport->read_send(state, state->ev, state->rdata,
					     RPC_HEADER_LEN,
					     state->transport->priv);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_api_pipe_read_done, req);
}

static void cli_api_pipe_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_api_pipe_state *state = tevent_req_data(
		req, struct cli_api_pipe_state);
	NTSTATUS status;
	ssize_t received;

	status = state->transport->read_recv(subreq, &received);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->rdata_len = received;
	tevent_req_done(req);
}

static NTSTATUS cli_api_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				  uint8_t **prdata, uint32_t *prdata_len)
{
	struct cli_api_pipe_state *state = tevent_req_data(
		req, struct cli_api_pipe_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	*prdata = talloc_move(mem_ctx, &state->rdata);
	*prdata_len = state->rdata_len;
	return NT_STATUS_OK;
}

/****************************************************************************
 Send data on an rpc pipe via trans. The data must be the last
 pdu fragment of an NDR data stream.

 Receive response data from an rpc pipe, which may be large...

 Read the first fragment: unfortunately have to use SMBtrans for the first
 bit, then SMBreadX for subsequent bits.

 If first fragment received also wasn't the last fragment, continue
 getting fragments until we _do_ receive the last fragment.

 Request/Response PDU's look like the following...

 |<------------------PDU len----------------------------------------------->|
 |<-HDR_LEN-->|<--REQ LEN------>|.............|<-AUTH_HDRLEN->|<-AUTH_LEN-->|

 +------------+-----------------+-------------+---------------+-------------+
 | RPC HEADER | REQ/RESP HEADER | DATA ...... | AUTH_HDR      | AUTH DATA   |
 +------------+-----------------+-------------+---------------+-------------+

 Where the presence of the AUTH_HDR and AUTH DATA are dependent on the
 signing & sealing being negotiated.

 ****************************************************************************/

struct rpc_api_pipe_state {
	struct tevent_context *ev;
	struct rpc_pipe_client *cli;
	uint8_t expected_pkt_type;
	uint32_t call_id;

	DATA_BLOB incoming_frag;
	struct ncacn_packet *pkt;

	/* Incoming reply */
	DATA_BLOB reply_pdu;
	size_t reply_pdu_offset;
	uint8_t endianess;
};

static void rpc_api_pipe_trans_done(struct tevent_req *subreq);
static void rpc_api_pipe_got_pdu(struct tevent_req *subreq);
static void rpc_api_pipe_auth3_done(struct tevent_req *subreq);

static struct tevent_req *rpc_api_pipe_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct rpc_pipe_client *cli,
					    DATA_BLOB *data, /* Outgoing PDU */
					    uint8_t expected_pkt_type,
					    uint32_t call_id)
{
	struct tevent_req *req, *subreq;
	struct rpc_api_pipe_state *state;
	uint16_t max_recv_frag;

	req = tevent_req_create(mem_ctx, &state, struct rpc_api_pipe_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->expected_pkt_type = expected_pkt_type;
	state->call_id = call_id;
	state->endianess = DCERPC_DREP_LE;

	/*
	 * Ensure we're not sending too much.
	 */
	if (data->length > cli->max_xmit_frag) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	DEBUG(5,("rpc_api_pipe: %s\n", rpccli_pipe_txt(talloc_tos(), cli)));

	if (state->expected_pkt_type == DCERPC_PKT_AUTH3) {
		subreq = rpc_write_send(state, ev, cli->transport,
					data->data, data->length);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, rpc_api_pipe_auth3_done, req);
		return req;
	}

	/* get the header first, then fetch the rest once we have
	 * the frag_length available */
	max_recv_frag = RPC_HEADER_LEN;

	subreq = cli_api_pipe_send(state, ev, cli->transport,
				   data->data, data->length, max_recv_frag);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_api_pipe_trans_done, req);
	return req;
}

static void rpc_api_pipe_auth3_done(struct tevent_req *subreq)
{
	NTSTATUS status = rpc_write_recv(subreq);
	return tevent_req_simple_finish_ntstatus(subreq, status);
}

static void rpc_api_pipe_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_api_pipe_state *state = tevent_req_data(
		req, struct rpc_api_pipe_state);
	NTSTATUS status;
	uint8_t *rdata = NULL;
	uint32_t rdata_len = 0;

	status = cli_api_pipe_recv(subreq, state, &rdata, &rdata_len);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {;
		DEBUG(5, ("cli_api_pipe failed: %s\n", nt_errstr(status)));
		return;
	}

	if (rdata == NULL) {
		DEBUG(3,("rpc_api_pipe: %s failed to return data.\n",
			 rpccli_pipe_txt(talloc_tos(), state->cli)));
		tevent_req_done(req);
		return;
	}

	/*
	 * Move data on state->incoming_frag.
	 */
	state->incoming_frag.data = talloc_move(state, &rdata);
	state->incoming_frag.length = rdata_len;
	if (!state->incoming_frag.data) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	/* Ensure we have enough data for a pdu. */
	subreq = get_complete_frag_send(state, state->ev, state->cli,
					&state->incoming_frag);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_api_pipe_got_pdu, req);
}

static void rpc_api_pipe_got_pdu(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_api_pipe_state *state = tevent_req_data(
		req, struct rpc_api_pipe_state);
	NTSTATUS status;
	DATA_BLOB rdata = { .data = NULL };

	status = get_complete_frag_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DEBUG(5, ("get_complete_frag failed: %s\n",
			  nt_errstr(status)));
		return;
	}

	state->pkt = talloc(state, struct ncacn_packet);
	if (!state->pkt) {
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
		tevent_req_oom(req);
		return;
	}

	status = dcerpc_pull_ncacn_packet(state->pkt,
					  &state->incoming_frag,
					  state->pkt);
	if (tevent_req_nterror(req, status)) {
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
		return;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(ncacn_packet, state->pkt);
	}

	status = cli_pipe_validate_current_pdu(state,
						state->cli, state->pkt,
						&state->incoming_frag,
						state->expected_pkt_type,
						state->call_id,
						&rdata,
						&state->reply_pdu);

	DBG_DEBUG("got frag len of %zu at offset %zu: %s\n",
		  state->incoming_frag.length,
		  state->reply_pdu_offset,
		  nt_errstr(status));

	if (state->pkt->ptype != DCERPC_PKT_FAULT && !NT_STATUS_IS_OK(status)) {
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR)) {
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if ((state->pkt->pfc_flags & DCERPC_PFC_FLAG_FIRST)
	    && (state->pkt->drep[0] != DCERPC_DREP_LE)) {
		/*
		 * Set the data type correctly for big-endian data on the
		 * first packet.
		 */
		DEBUG(10,("rpc_api_pipe: On %s PDU data format is "
			  "big-endian.\n",
			  rpccli_pipe_txt(talloc_tos(), state->cli)));
		state->endianess = 0x00; /* BIG ENDIAN */
	}
	/*
	 * Check endianness on subsequent packets.
	 */
	if (state->endianess != state->pkt->drep[0]) {
		DEBUG(0,("rpc_api_pipe: Error : Endianness changed from %s to "
			 "%s\n",
			 state->endianess?"little":"big",
			 state->pkt->drep[0]?"little":"big"));
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	if (state->reply_pdu_offset + rdata.length > MAX_RPC_DATA_SIZE) {
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	/* Now copy the data portion out of the pdu into rbuf. */
	if (state->reply_pdu.length < state->reply_pdu_offset + rdata.length) {
		if (!data_blob_realloc(NULL, &state->reply_pdu,
				state->reply_pdu_offset + rdata.length)) {
			/*
			 * TODO: do a real async disconnect ...
			 *
			 * For now do it sync...
			 */
			TALLOC_FREE(state->cli->transport);
			tevent_req_oom(req);
			return;
		}
	}

	memcpy(state->reply_pdu.data + state->reply_pdu_offset,
		rdata.data, rdata.length);
	state->reply_pdu_offset += rdata.length;

	/* reset state->incoming_frag, there is no need to free it,
	 * it will be reallocated to the right size the next time
	 * it is used */
	state->incoming_frag.length = 0;

	if (state->pkt->pfc_flags & DCERPC_PFC_FLAG_LAST) {
		/* make sure the pdu length is right now that we
		 * have all the data available (alloc hint may
		 * have allocated more than was actually used) */
		state->reply_pdu.length = state->reply_pdu_offset;
		DEBUG(10,("rpc_api_pipe: %s returned %u bytes.\n",
			  rpccli_pipe_txt(talloc_tos(), state->cli),
			  (unsigned)state->reply_pdu.length));
		tevent_req_done(req);
		return;
	}

	subreq = get_complete_frag_send(state, state->ev, state->cli,
					&state->incoming_frag);
	if (subreq == NULL) {
		/*
		 * TODO: do a real async disconnect ...
		 *
		 * For now do it sync...
		 */
		TALLOC_FREE(state->cli->transport);
	}
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_api_pipe_got_pdu, req);
}

static NTSTATUS rpc_api_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				  struct ncacn_packet **pkt,
				  DATA_BLOB *reply_pdu)
{
	struct rpc_api_pipe_state *state = tevent_req_data(
		req, struct rpc_api_pipe_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	/* return data to caller and assign it ownership of memory */
	if (reply_pdu) {
		reply_pdu->data = talloc_move(mem_ctx, &state->reply_pdu.data);
		reply_pdu->length = state->reply_pdu.length;
		state->reply_pdu.length = 0;
	} else {
		data_blob_free(&state->reply_pdu);
	}

	if (pkt) {
		*pkt = talloc_steal(mem_ctx, state->pkt);
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Creates NTLMSSP auth bind.
 ********************************************************************/

static NTSTATUS create_generic_auth_rpc_bind_req(struct rpc_pipe_client *cli,
						 TALLOC_CTX *mem_ctx,
						 DATA_BLOB *auth_token,
						 bool *client_hdr_signing)
{
	struct gensec_security *gensec_security;
	DATA_BLOB null_blob = { .data = NULL };
	NTSTATUS status;

	gensec_security = cli->auth->auth_ctx;

	DEBUG(5, ("create_generic_auth_rpc_bind_req: generate first token\n"));
	status = gensec_update(gensec_security, mem_ctx, null_blob, auth_token);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED))
	{
		return status;
	}

	if (client_hdr_signing == NULL) {
		return status;
	}

	if (cli->auth->auth_level < DCERPC_AUTH_LEVEL_PACKET) {
		*client_hdr_signing = false;
		return status;
	}

	*client_hdr_signing = gensec_have_feature(gensec_security,
						GENSEC_FEATURE_SIGN_PKT_HEADER);

	return status;
}

/*******************************************************************
 Creates the internals of a DCE/RPC bind request or alter context PDU.
 ********************************************************************/

static NTSTATUS create_bind_or_alt_ctx_internal(TALLOC_CTX *mem_ctx,
						enum dcerpc_pkt_type ptype,
						uint32_t rpc_call_id,
						const struct ndr_syntax_id *abstract,
						const struct ndr_syntax_id *transfer,
						const DATA_BLOB *auth_info,
						bool client_hdr_signing,
						DATA_BLOB *blob)
{
	uint16_t auth_len = auth_info->length;
	NTSTATUS status;
	struct dcerpc_ctx_list ctx_list = {
		.context_id = 0,
		.num_transfer_syntaxes = 1,
		.abstract_syntax = *abstract,
		.transfer_syntaxes = (struct ndr_syntax_id *)discard_const(transfer),
	};
	union dcerpc_payload u = {
		.bind.max_xmit_frag	= RPC_MAX_PDU_FRAG_LEN,
		.bind.max_recv_frag	= RPC_MAX_PDU_FRAG_LEN,
		.bind.num_contexts	= 1,
		.bind.ctx_list		= &ctx_list,
		.bind.auth_info		= *auth_info,
	};
	uint8_t pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;

	if (auth_len) {
		auth_len -= DCERPC_AUTH_TRAILER_LENGTH;
	}

	if (client_hdr_signing) {
		pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
	}

	status = dcerpc_push_ncacn_packet(mem_ctx,
					  ptype, pfc_flags,
					  auth_len,
					  rpc_call_id,
					  &u,
					  blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall bind/alter ncacn_packet.\n"));
		return status;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Creates a DCE/RPC bind request.
 ********************************************************************/

static NTSTATUS create_rpc_bind_req(TALLOC_CTX *mem_ctx,
				    struct rpc_pipe_client *cli,
				    struct pipe_auth_data *auth,
				    uint32_t rpc_call_id,
				    const struct ndr_syntax_id *abstract,
				    const struct ndr_syntax_id *transfer,
				    DATA_BLOB *rpc_out)
{
	DATA_BLOB auth_token = { .data = NULL };
	DATA_BLOB auth_info = { .data = NULL };
	NTSTATUS ret;

	if (auth->auth_type != DCERPC_AUTH_TYPE_NONE) {
		ret = create_generic_auth_rpc_bind_req(
			cli, mem_ctx, &auth_token, &auth->client_hdr_signing);

		if (!NT_STATUS_IS_OK(ret) &&
		    !NT_STATUS_EQUAL(ret, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			return ret;
		}
	}

	if (auth_token.length != 0) {
		ret = dcerpc_push_dcerpc_auth(cli,
						auth->auth_type,
						auth->auth_level,
						0, /* auth_pad_length */
						auth->auth_context_id,
						&auth_token,
						&auth_info);
		if (!NT_STATUS_IS_OK(ret)) {
			return ret;
		}
		data_blob_free(&auth_token);
	}

	ret = create_bind_or_alt_ctx_internal(mem_ctx,
					      DCERPC_PKT_BIND,
					      rpc_call_id,
					      abstract,
					      transfer,
					      &auth_info,
					      auth->client_hdr_signing,
					      rpc_out);
	data_blob_free(&auth_info);

	return ret;
}

/*******************************************************************
 External interface.
 Does an rpc request on a pipe. Incoming data is NDR encoded in in_data.
 Reply is NDR encoded in out_data. Splits the data stream into RPC PDU's
 and deals with signing/sealing details.
 ********************************************************************/

struct rpc_api_pipe_req_state {
	struct tevent_context *ev;
	struct rpc_pipe_client *cli;
	uint8_t op_num;
	uint32_t call_id;
	const DATA_BLOB *req_data;
	const struct GUID *object_uuid;
	uint32_t req_data_sent;
	DATA_BLOB req_trailer;
	uint32_t req_trailer_sent;
	bool verify_bitmask1;
	bool verify_pcontext;
	DATA_BLOB rpc_out;
	DATA_BLOB reply_pdu;
};

static void rpc_api_pipe_req_write_done(struct tevent_req *subreq);
static void rpc_api_pipe_req_done(struct tevent_req *subreq);
static NTSTATUS prepare_verification_trailer(struct rpc_api_pipe_req_state *state);
static NTSTATUS prepare_next_frag(struct rpc_api_pipe_req_state *state,
				  bool *is_last_frag);

static struct tevent_req *rpc_api_pipe_req_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct rpc_pipe_client *cli,
					 uint8_t op_num,
					 const struct GUID *object_uuid,
					 const DATA_BLOB *req_data)
{
	struct tevent_req *req, *subreq;
	struct rpc_api_pipe_req_state *state;
	NTSTATUS status;
	bool is_last_frag;

	req = tevent_req_create(mem_ctx, &state,
				struct rpc_api_pipe_req_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->op_num = op_num;
	state->object_uuid = object_uuid;
	state->req_data = req_data;
	state->call_id = get_rpc_call_id();

	if (cli->max_xmit_frag < DCERPC_REQUEST_LENGTH
					+ RPC_MAX_SIGN_SIZE) {
		/* Server is screwed up ! */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	status = prepare_verification_trailer(state);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = prepare_next_frag(state, &is_last_frag);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (is_last_frag) {
		subreq = rpc_api_pipe_send(state, ev, state->cli,
					   &state->rpc_out,
					   DCERPC_PKT_RESPONSE,
					   state->call_id);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, rpc_api_pipe_req_done, req);
	} else {
		subreq = rpc_write_send(state, ev, cli->transport,
					state->rpc_out.data,
					state->rpc_out.length);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, rpc_api_pipe_req_write_done,
					req);
	}
	return req;
}

static NTSTATUS prepare_verification_trailer(struct rpc_api_pipe_req_state *state)
{
	struct pipe_auth_data *a = state->cli->auth;
	struct dcerpc_sec_verification_trailer *t;
	struct ndr_push *ndr = NULL;
	enum ndr_err_code ndr_err;
	size_t align = 0;
	size_t pad = 0;

	if (a == NULL) {
		return NT_STATUS_OK;
	}

	if (a->auth_level < DCERPC_AUTH_LEVEL_PACKET) {
		return NT_STATUS_OK;
	}

	t = talloc_zero(state, struct dcerpc_sec_verification_trailer);
	if (t == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!a->verified_bitmask1) {
		t->commands = talloc_realloc(t, t->commands,
					     struct dcerpc_sec_vt,
					     t->count.count + 1);
		if (t->commands == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		t->commands[t->count.count++] = (struct dcerpc_sec_vt) {
			.command = DCERPC_SEC_VT_COMMAND_BITMASK1,
			.u.bitmask1 = (a->client_hdr_signing) ?
				DCERPC_SEC_VT_CLIENT_SUPPORTS_HEADER_SIGNING :
				0,
		};
		state->verify_bitmask1 = true;
	}

	if (!state->cli->verified_pcontext) {
		t->commands = talloc_realloc(t, t->commands,
					     struct dcerpc_sec_vt,
					     t->count.count + 1);
		if (t->commands == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		t->commands[t->count.count++] = (struct dcerpc_sec_vt) {
			.command = DCERPC_SEC_VT_COMMAND_PCONTEXT,
			.u.pcontext.abstract_syntax =
				state->cli->abstract_syntax,
			.u.pcontext.transfer_syntax =
				state->cli->transfer_syntax,
		};
		state->verify_pcontext = true;
	}

	if (!a->hdr_signing) {
		t->commands = talloc_realloc(t, t->commands,
					     struct dcerpc_sec_vt,
					     t->count.count + 1);
		if (t->commands == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		t->commands[t->count.count++] = (struct dcerpc_sec_vt) {
			.command = DCERPC_SEC_VT_COMMAND_HEADER2,
			.u.header2.ptype = DCERPC_PKT_REQUEST,
			.u.header2.drep[0] = DCERPC_DREP_LE,
			.u.header2.call_id = state->call_id,
			.u.header2.context_id = 0,
			.u.header2.opnum = state->op_num,
		};
	}

	if (t->count.count == 0) {
		TALLOC_FREE(t);
		return NT_STATUS_OK;
	}

	t->commands[t->count.count - 1].command |= DCERPC_SEC_VT_COMMAND_END;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(dcerpc_sec_verification_trailer, t);
	}

	ndr = ndr_push_init_ctx(state);
	if (ndr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_push_dcerpc_sec_verification_trailer(ndr,
						NDR_SCALARS | NDR_BUFFERS,
						t);
	TALLOC_FREE(t);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}
	state->req_trailer = ndr_push_blob(ndr);

	align = state->req_data->length & 0x3;
	if (align > 0) {
		pad = 4 - align;
	}
	if (pad > 0) {
		bool ok;
		uint8_t *p;
		const uint8_t zeros[4] = { 0, };

		ok = data_blob_append(ndr, &state->req_trailer, zeros, pad);
		if (!ok) {
			return NT_STATUS_NO_MEMORY;
		}

		/* move the padding to the start */
		p = state->req_trailer.data;
		memmove(p + pad, p, state->req_trailer.length - pad);
		memset(p, 0, pad);
	}

	return NT_STATUS_OK;
}

static NTSTATUS prepare_next_frag(struct rpc_api_pipe_req_state *state,
				  bool *is_last_frag)
{
	size_t auth_len;
	size_t frag_len;
	uint8_t flags = 0;
	size_t pad_len;
	size_t data_left;
	size_t data_thistime;
	size_t trailer_left;
	size_t trailer_thistime = 0;
	size_t total_left;
	size_t total_thistime;
	NTSTATUS status;
	bool ok;
	union dcerpc_payload u;

	data_left = state->req_data->length - state->req_data_sent;
	trailer_left = state->req_trailer.length - state->req_trailer_sent;
	total_left = data_left + trailer_left;
	if ((total_left < data_left) || (total_left < trailer_left)) {
		/*
		 * overflow
		 */
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	status = dcerpc_guess_sizes(state->cli->auth,
				    DCERPC_REQUEST_LENGTH, total_left,
				    state->cli->max_xmit_frag,
				    &total_thistime,
				    &frag_len, &auth_len, &pad_len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (state->req_data_sent == 0) {
		flags = DCERPC_PFC_FLAG_FIRST;
	}

	if (total_thistime == total_left) {
		flags |= DCERPC_PFC_FLAG_LAST;
	}

	data_thistime = MIN(total_thistime, data_left);
	if (data_thistime < total_thistime) {
		trailer_thistime = total_thistime - data_thistime;
	}

	data_blob_free(&state->rpc_out);

	u = (union dcerpc_payload) {
		.request.alloc_hint	= total_left,
		.request.context_id	= 0,
		.request.opnum		= state->op_num,
	};

	if (state->object_uuid) {
		flags |= DCERPC_PFC_FLAG_OBJECT_UUID;
		u.request.object.object = *state->object_uuid;
		frag_len += ndr_size_GUID(state->object_uuid, 0);
	}

	status = dcerpc_push_ncacn_packet(state,
					  DCERPC_PKT_REQUEST,
					  flags,
					  auth_len,
					  state->call_id,
					  &u,
					  &state->rpc_out);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* explicitly set frag_len here as dcerpc_push_ncacn_packet() can't
	 * compute it right for requests because the auth trailer is missing
	 * at this stage */
	dcerpc_set_frag_length(&state->rpc_out, frag_len);

	if (data_thistime > 0) {
		/* Copy in the data. */
		ok = data_blob_append(NULL, &state->rpc_out,
				state->req_data->data + state->req_data_sent,
				data_thistime);
		if (!ok) {
			return NT_STATUS_NO_MEMORY;
		}
		state->req_data_sent += data_thistime;
	}

	if (trailer_thistime > 0) {
		/* Copy in the verification trailer. */
		ok = data_blob_append(NULL, &state->rpc_out,
				state->req_trailer.data + state->req_trailer_sent,
				trailer_thistime);
		if (!ok) {
			return NT_STATUS_NO_MEMORY;
		}
		state->req_trailer_sent += trailer_thistime;
	}

	switch (state->cli->auth->auth_level) {
	case DCERPC_AUTH_LEVEL_NONE:
	case DCERPC_AUTH_LEVEL_CONNECT:
		break;
	case DCERPC_AUTH_LEVEL_PACKET:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = dcerpc_add_auth_footer(state->cli->auth, pad_len,
						&state->rpc_out);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	*is_last_frag = ((flags & DCERPC_PFC_FLAG_LAST) != 0);

	return status;
}

static void rpc_api_pipe_req_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_api_pipe_req_state *state = tevent_req_data(
		req, struct rpc_api_pipe_req_state);
	NTSTATUS status;
	bool is_last_frag;

	status = rpc_write_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = prepare_next_frag(state, &is_last_frag);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (is_last_frag) {
		subreq = rpc_api_pipe_send(state, state->ev, state->cli,
					   &state->rpc_out,
					   DCERPC_PKT_RESPONSE,
					   state->call_id);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, rpc_api_pipe_req_done, req);
	} else {
		subreq = rpc_write_send(state, state->ev,
					state->cli->transport,
					state->rpc_out.data,
					state->rpc_out.length);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, rpc_api_pipe_req_write_done,
					req);
	}
}

static void rpc_api_pipe_req_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_api_pipe_req_state *state = tevent_req_data(
		req, struct rpc_api_pipe_req_state);
	NTSTATUS status;

	status = rpc_api_pipe_recv(subreq, state, NULL, &state->reply_pdu);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->cli->auth == NULL) {
		tevent_req_done(req);
		return;
	}

	if (state->verify_bitmask1) {
		state->cli->auth->verified_bitmask1 = true;
	}

	if (state->verify_pcontext) {
		state->cli->verified_pcontext = true;
	}

	tevent_req_done(req);
}

static NTSTATUS rpc_api_pipe_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       DATA_BLOB *reply_pdu)
{
	struct rpc_api_pipe_req_state *state = tevent_req_data(
		req, struct rpc_api_pipe_req_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		/*
		 * We always have to initialize to reply pdu, even if there is
		 * none. The rpccli_* caller routines expect this.
		 */
		*reply_pdu = data_blob_null;
		return status;
	}

	/* return data to caller and assign it ownership of memory */
	reply_pdu->data = talloc_move(mem_ctx, &state->reply_pdu.data);
	reply_pdu->length = state->reply_pdu.length;
	state->reply_pdu.length = 0;

	return NT_STATUS_OK;
}

/****************************************************************************
 Check the rpc bind acknowledge response.
****************************************************************************/

static bool check_bind_response(const struct dcerpc_bind_ack *r,
				const struct ndr_syntax_id *transfer)
{
	struct dcerpc_ack_ctx ctx;
	bool equal;

	if (r->secondary_address_size == 0) {
		DEBUG(4,("Ignoring length check -- ASU bug (server didn't fill in the pipe name correctly)"));
	}

	if (r->num_results < 1 || !r->ctx_list) {
		return false;
	}

	ctx = r->ctx_list[0];

	/* check the transfer syntax */
	equal = ndr_syntax_id_equal(&ctx.syntax, transfer);
	if (!equal) {
		DEBUG(2,("bind_rpc_pipe: transfer syntax differs\n"));
		return False;
	}

	if (r->num_results != 0x1 || ctx.result != 0) {
		DEBUG(2,("bind_rpc_pipe: bind denied results: %d reason: %x\n",
		          r->num_results, ctx.reason.value));
	}

	DEBUG(5,("check_bind_response: accepted!\n"));
	return True;
}

/*******************************************************************
 Creates a DCE/RPC bind authentication response.
 This is the packet that is sent back to the server once we
 have received a BIND-ACK, to finish the third leg of
 the authentication handshake.
 ********************************************************************/

static NTSTATUS create_rpc_bind_auth3(TALLOC_CTX *mem_ctx,
				struct rpc_pipe_client *cli,
				struct pipe_auth_data *auth,
				uint32_t rpc_call_id,
				DATA_BLOB *pauth_blob,
				DATA_BLOB *rpc_out)
{
	NTSTATUS status;
	union dcerpc_payload u = { .auth3._pad = 0, };

	status = dcerpc_push_dcerpc_auth(mem_ctx,
					 auth->auth_type,
					 auth->auth_level,
					 0, /* auth_pad_length */
					 auth->auth_context_id,
					 pauth_blob,
					 &u.auth3.auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_push_ncacn_packet(mem_ctx,
					  DCERPC_PKT_AUTH3,
					  DCERPC_PFC_FLAG_FIRST |
					  DCERPC_PFC_FLAG_LAST,
					  pauth_blob->length,
					  rpc_call_id,
					  &u,
					  rpc_out);
	data_blob_free(&u.auth3.auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("create_bind_or_alt_ctx_internal: failed to marshall RPC_HDR_RB.\n"));
		return status;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Creates a DCE/RPC bind alter context authentication request which
 may contain a spnego auth blob
 ********************************************************************/

static NTSTATUS create_rpc_alter_context(TALLOC_CTX *mem_ctx,
					struct pipe_auth_data *auth,
					uint32_t rpc_call_id,
					const struct ndr_syntax_id *abstract,
					const struct ndr_syntax_id *transfer,
					const DATA_BLOB *pauth_blob, /* spnego auth blob already created. */
					DATA_BLOB *rpc_out)
{
	DATA_BLOB auth_info;
	NTSTATUS status;

	status = dcerpc_push_dcerpc_auth(mem_ctx,
					 auth->auth_type,
					 auth->auth_level,
					 0, /* auth_pad_length */
					 auth->auth_context_id,
					 pauth_blob,
					 &auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = create_bind_or_alt_ctx_internal(mem_ctx,
						 DCERPC_PKT_ALTER,
						 rpc_call_id,
						 abstract,
						 transfer,
						 &auth_info,
					         false, /* client_hdr_signing */
						 rpc_out);
	data_blob_free(&auth_info);
	return status;
}

/****************************************************************************
 Do an rpc bind.
****************************************************************************/

struct rpc_pipe_bind_state {
	struct tevent_context *ev;
	struct rpc_pipe_client *cli;
	DATA_BLOB rpc_out;
	bool auth3;
	uint32_t rpc_call_id;
};

static void rpc_pipe_bind_step_one_done(struct tevent_req *subreq);
static NTSTATUS rpc_bind_next_send(struct tevent_req *req,
				   struct rpc_pipe_bind_state *state,
				   DATA_BLOB *credentials);
static NTSTATUS rpc_bind_finish_send(struct tevent_req *req,
				     struct rpc_pipe_bind_state *state,
				     DATA_BLOB *credentials);

struct tevent_req *rpc_pipe_bind_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct rpc_pipe_client *cli,
				      struct pipe_auth_data *auth)
{
	struct tevent_req *req, *subreq;
	struct rpc_pipe_bind_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct rpc_pipe_bind_state);
	if (req == NULL) {
		return NULL;
	}

	DEBUG(5,("Bind RPC Pipe: %s auth_type %u, auth_level %u\n",
		rpccli_pipe_txt(talloc_tos(), cli),
		(unsigned int)auth->auth_type,
		(unsigned int)auth->auth_level ));

	state->ev = ev;
	state->cli = cli;
	state->rpc_call_id = get_rpc_call_id();

	cli->auth = talloc_move(cli, &auth);

	/* Marshall the outgoing data. */
	status = create_rpc_bind_req(state, cli,
				     cli->auth,
				     state->rpc_call_id,
				     &cli->abstract_syntax,
				     &cli->transfer_syntax,
				     &state->rpc_out);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	subreq = rpc_api_pipe_send(state, ev, cli, &state->rpc_out,
				   DCERPC_PKT_BIND_ACK, state->rpc_call_id);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_pipe_bind_step_one_done, req);
	return req;
}

static void rpc_pipe_bind_step_one_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_pipe_bind_state *state = tevent_req_data(
		req, struct rpc_pipe_bind_state);
	struct pipe_auth_data *pauth = state->cli->auth;
	struct gensec_security *gensec_security;
	struct ncacn_packet *pkt = NULL;
	struct dcerpc_auth auth;
	DATA_BLOB auth_token = { .data = NULL };
	NTSTATUS status;

	status = rpc_api_pipe_recv(subreq, talloc_tos(), &pkt, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DEBUG(3, ("rpc_pipe_bind: %s bind request returned %s\n",
			  rpccli_pipe_txt(talloc_tos(), state->cli),
			  nt_errstr(status)));
		return;
	}

	if (state->auth3) {
		tevent_req_done(req);
		return;
	}

	if (!check_bind_response(&pkt->u.bind_ack, &state->cli->transfer_syntax)) {
		DEBUG(2, ("rpc_pipe_bind: check_bind_response failed.\n"));
		tevent_req_nterror(req, NT_STATUS_BUFFER_TOO_SMALL);
		return;
	}

	if (pkt->ptype == DCERPC_PKT_BIND_ACK) {
		if (pkt->pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN) {
			if (pauth->client_hdr_signing) {
				pauth->hdr_signing = true;
			}
		}
	}

	state->cli->max_xmit_frag = pkt->u.bind_ack.max_xmit_frag;

	if (pauth->auth_type == DCERPC_AUTH_TYPE_NONE) {
		/* Bind complete. */
		tevent_req_done(req);
		return;
	}

	if (pkt->auth_length == 0) {
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	/* get auth credentials */
	status = dcerpc_pull_auth_trailer(pkt, talloc_tos(),
					  &pkt->u.bind_ack.auth_info,
					  &auth, NULL, true);
	if (tevent_req_nterror(req, status)) {
		DEBUG(0, ("Failed to pull dcerpc auth: %s.\n",
			  nt_errstr(status)));
		return;
	}

	if (auth.auth_type != pauth->auth_type) {
		DBG_ERR("Auth type %u mismatch expected %u.\n",
			auth.auth_type, pauth->auth_type);
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	if (auth.auth_level != pauth->auth_level) {
		DBG_ERR("Auth level %u mismatch expected %u.\n",
			auth.auth_level, pauth->auth_level);
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	if (auth.auth_context_id != pauth->auth_context_id) {
		DBG_ERR("Auth context id %"PRIu32" mismatch "
			"expected %"PRIu32".\n",
			auth.auth_context_id,
			pauth->auth_context_id);
		tevent_req_nterror(req, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	/*
	 * For authenticated binds we may need to do 3 or 4 leg binds.
	 */

	if (pauth->auth_type == DCERPC_AUTH_TYPE_NONE) {
		/* Bind complete. */
		tevent_req_done(req);
		return;
	}

	gensec_security = pauth->auth_ctx;

	status = gensec_update(gensec_security, state,
			       auth.credentials, &auth_token);
	if (NT_STATUS_EQUAL(status,
			    NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = rpc_bind_next_send(req, state,
					    &auth_token);
	} else if (NT_STATUS_IS_OK(status)) {
		if (pauth->hdr_signing) {
			gensec_want_feature(gensec_security,
					    GENSEC_FEATURE_SIGN_PKT_HEADER);
		}

		if (auth_token.length == 0) {
			/* Bind complete. */
			tevent_req_done(req);
			return;
		}
		status = rpc_bind_finish_send(req, state,
					      &auth_token);
	}

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
	}
	return;
}

static NTSTATUS rpc_bind_next_send(struct tevent_req *req,
				   struct rpc_pipe_bind_state *state,
				   DATA_BLOB *auth_token)
{
	struct pipe_auth_data *auth = state->cli->auth;
	struct tevent_req *subreq;
	NTSTATUS status;

	/* Now prepare the alter context pdu. */
	data_blob_free(&state->rpc_out);

	status = create_rpc_alter_context(state, auth,
					  state->rpc_call_id,
					  &state->cli->abstract_syntax,
					  &state->cli->transfer_syntax,
					  auth_token,
					  &state->rpc_out);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	subreq = rpc_api_pipe_send(state, state->ev, state->cli,
				   &state->rpc_out, DCERPC_PKT_ALTER_RESP,
				   state->rpc_call_id);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, rpc_pipe_bind_step_one_done, req);
	return NT_STATUS_OK;
}

static NTSTATUS rpc_bind_finish_send(struct tevent_req *req,
				     struct rpc_pipe_bind_state *state,
				     DATA_BLOB *auth_token)
{
	struct pipe_auth_data *auth = state->cli->auth;
	struct tevent_req *subreq;
	NTSTATUS status;

	state->auth3 = true;

	/* Now prepare the auth3 context pdu. */
	data_blob_free(&state->rpc_out);

	status = create_rpc_bind_auth3(state, state->cli, auth,
					state->rpc_call_id,
					auth_token,
					&state->rpc_out);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	subreq = rpc_api_pipe_send(state, state->ev, state->cli,
				   &state->rpc_out, DCERPC_PKT_AUTH3,
				   state->rpc_call_id);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, rpc_pipe_bind_step_one_done, req);
	return NT_STATUS_OK;
}

NTSTATUS rpc_pipe_bind_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS rpc_pipe_bind(struct rpc_pipe_client *cli,
		       struct pipe_auth_data *auth)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = rpc_pipe_bind_send(frame, ev, cli, auth);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = rpc_pipe_bind_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

#define RPCCLI_DEFAULT_TIMEOUT 10000 /* 10 seconds. */

unsigned int rpccli_set_timeout(struct rpc_pipe_client *rpc_cli,
				unsigned int timeout)
{
	if (rpc_cli == NULL) {
		return RPCCLI_DEFAULT_TIMEOUT;
	}

	if (rpc_cli->binding_handle == NULL) {
		return RPCCLI_DEFAULT_TIMEOUT;
	}

	return dcerpc_binding_handle_set_timeout(rpc_cli->binding_handle,
						 timeout);
}

bool rpccli_is_connected(struct rpc_pipe_client *rpc_cli)
{
	if (rpc_cli == NULL) {
		return false;
	}

	if (rpc_cli->binding_handle == NULL) {
		return false;
	}

	return dcerpc_binding_handle_is_connected(rpc_cli->binding_handle);
}

struct rpccli_bh_state {
	struct rpc_pipe_client *rpc_cli;
};

static bool rpccli_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct rpccli_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpccli_bh_state);
	struct rpc_cli_transport *transport = hs->rpc_cli->transport;

	if (transport == NULL) {
		return false;
	}

	if (transport->is_connected == NULL) {
		return false;
	}

	return transport->is_connected(transport->priv);
}

static uint32_t rpccli_bh_set_timeout(struct dcerpc_binding_handle *h,
				      uint32_t timeout)
{
	struct rpccli_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpccli_bh_state);
	struct rpc_cli_transport *transport = hs->rpc_cli->transport;
	unsigned int old;

	if (transport == NULL) {
		return RPCCLI_DEFAULT_TIMEOUT;
	}

	if (transport->set_timeout == NULL) {
		return RPCCLI_DEFAULT_TIMEOUT;
	}

	old = transport->set_timeout(transport->priv, timeout);
	if (old == 0) {
		return RPCCLI_DEFAULT_TIMEOUT;
	}

	return old;
}

static void rpccli_bh_auth_info(struct dcerpc_binding_handle *h,
				enum dcerpc_AuthType *auth_type,
				enum dcerpc_AuthLevel *auth_level)
{
	struct rpccli_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpccli_bh_state);

	if (hs->rpc_cli == NULL) {
		return;
	}

	if (hs->rpc_cli->auth == NULL) {
		return;
	}

	*auth_type = hs->rpc_cli->auth->auth_type;
	*auth_level = hs->rpc_cli->auth->auth_level;
}

struct rpccli_bh_raw_call_state {
	DATA_BLOB in_data;
	DATA_BLOB out_data;
	uint32_t out_flags;
};

static void rpccli_bh_raw_call_done(struct tevent_req *subreq);

static struct tevent_req *rpccli_bh_raw_call_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct dcerpc_binding_handle *h,
						  const struct GUID *object,
						  uint32_t opnum,
						  uint32_t in_flags,
						  const uint8_t *in_data,
						  size_t in_length)
{
	struct rpccli_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpccli_bh_state);
	struct tevent_req *req;
	struct rpccli_bh_raw_call_state *state;
	bool ok;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct rpccli_bh_raw_call_state);
	if (req == NULL) {
		return NULL;
	}
	state->in_data.data = discard_const_p(uint8_t, in_data);
	state->in_data.length = in_length;

	ok = rpccli_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	subreq = rpc_api_pipe_req_send(state, ev, hs->rpc_cli,
				       opnum, object, &state->in_data);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpccli_bh_raw_call_done, req);

	return req;
}

static void rpccli_bh_raw_call_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct rpccli_bh_raw_call_state *state =
		tevent_req_data(req,
		struct rpccli_bh_raw_call_state);
	NTSTATUS status;

	state->out_flags = 0;

	/* TODO: support bigendian responses */

	status = rpc_api_pipe_req_recv(subreq, state, &state->out_data);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS rpccli_bh_raw_call_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags)
{
	struct rpccli_bh_raw_call_state *state =
		tevent_req_data(req,
		struct rpccli_bh_raw_call_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_data = talloc_move(mem_ctx, &state->out_data.data);
	*out_length = state->out_data.length;
	*out_flags = state->out_flags;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct rpccli_bh_disconnect_state {
	uint8_t _dummy;
};

static struct tevent_req *rpccli_bh_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h)
{
	struct rpccli_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rpccli_bh_state);
	struct tevent_req *req;
	struct rpccli_bh_disconnect_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct rpccli_bh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	ok = rpccli_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	/*
	 * TODO: do a real async disconnect ...
	 *
	 * For now we do it sync...
	 */
	TALLOC_FREE(hs->rpc_cli->transport);
	hs->rpc_cli = NULL;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS rpccli_bh_disconnect_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static bool rpccli_bh_ref_alloc(struct dcerpc_binding_handle *h)
{
	return true;
}

static void rpccli_bh_do_ndr_print(struct dcerpc_binding_handle *h,
				   int ndr_flags,
				   const void *_struct_ptr,
				   const struct ndr_interface_call *call)
{
	void *struct_ptr = discard_const(_struct_ptr);

	if (DEBUGLEVEL < 10) {
		return;
	}

	if (ndr_flags & NDR_IN) {
		ndr_print_function_debug(call->ndr_print,
					 call->name,
					 ndr_flags,
					 struct_ptr);
	}
	if (ndr_flags & NDR_OUT) {
		ndr_print_function_debug(call->ndr_print,
					 call->name,
					 ndr_flags,
					 struct_ptr);
	}
}

static const struct dcerpc_binding_handle_ops rpccli_bh_ops = {
	.name			= "rpccli",
	.is_connected		= rpccli_bh_is_connected,
	.set_timeout		= rpccli_bh_set_timeout,
	.auth_info		= rpccli_bh_auth_info,
	.raw_call_send		= rpccli_bh_raw_call_send,
	.raw_call_recv		= rpccli_bh_raw_call_recv,
	.disconnect_send	= rpccli_bh_disconnect_send,
	.disconnect_recv	= rpccli_bh_disconnect_recv,

	.ref_alloc		= rpccli_bh_ref_alloc,
	.do_ndr_print		= rpccli_bh_do_ndr_print,
};

/* initialise a rpc_pipe_client binding handle */
struct dcerpc_binding_handle *rpccli_bh_create(struct rpc_pipe_client *c,
					const struct GUID *object,
					const struct ndr_interface_table *table)
{
	struct dcerpc_binding_handle *h;
	struct rpccli_bh_state *hs;

	h = dcerpc_binding_handle_create(c,
					 &rpccli_bh_ops,
					 object,
					 table,
					 &hs,
					 struct rpccli_bh_state,
					 __location__);
	if (h == NULL) {
		return NULL;
	}
	hs->rpc_cli = c;

	return h;
}

NTSTATUS rpccli_anon_bind_data(TALLOC_CTX *mem_ctx,
			       struct pipe_auth_data **presult)
{
	struct pipe_auth_data *result;
	struct auth_generic_state *auth_generic_ctx;
	NTSTATUS status;

	result = talloc_zero(mem_ctx, struct pipe_auth_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->auth_type = DCERPC_AUTH_TYPE_NONE;
	result->auth_level = DCERPC_AUTH_LEVEL_NONE;
	result->auth_context_id = 0;

	status = auth_generic_client_prepare(result,
					     &auth_generic_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to create auth_generic context: %s\n",
			  nt_errstr(status)));
	}

	status = auth_generic_set_username(auth_generic_ctx, "");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set username: %s\n",
			  nt_errstr(status)));
	}

	status = auth_generic_set_domain(auth_generic_ctx, "");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set domain: %s\n",
			  nt_errstr(status)));
		return status;
	}

	status = gensec_set_credentials(auth_generic_ctx->gensec_security,
					auth_generic_ctx->credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set GENSEC credentials: %s\n",
			  nt_errstr(status)));
		return status;
	}
	talloc_unlink(auth_generic_ctx, auth_generic_ctx->credentials);
	auth_generic_ctx->credentials = NULL;

	result->auth_ctx = talloc_move(result, &auth_generic_ctx->gensec_security);
	talloc_free(auth_generic_ctx);
	*presult = result;
	return NT_STATUS_OK;
}

static NTSTATUS rpccli_generic_bind_data(TALLOC_CTX *mem_ctx,
					 enum dcerpc_AuthType auth_type,
					 enum dcerpc_AuthLevel auth_level,
					 const char *server,
					 const char *target_service,
					 const char *domain,
					 const char *username,
					 const char *password,
					 enum credentials_use_kerberos use_kerberos,
					 struct netlogon_creds_CredentialState *creds,
					 struct pipe_auth_data **presult)
{
	struct auth_generic_state *auth_generic_ctx;
	struct pipe_auth_data *result;
	NTSTATUS status;

	result = talloc_zero(mem_ctx, struct pipe_auth_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->auth_type = auth_type;
	result->auth_level = auth_level;
	result->auth_context_id = 1;

	status = auth_generic_client_prepare(result,
					     &auth_generic_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = auth_generic_set_username(auth_generic_ctx, username);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = auth_generic_set_domain(auth_generic_ctx, domain);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = auth_generic_set_password(auth_generic_ctx, password);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = gensec_set_target_service(auth_generic_ctx->gensec_security, target_service);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = gensec_set_target_hostname(auth_generic_ctx->gensec_security, server);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	cli_credentials_set_kerberos_state(auth_generic_ctx->credentials,
					   use_kerberos,
					   CRED_SPECIFIED);
	cli_credentials_set_netlogon_creds(auth_generic_ctx->credentials, creds);

	status = auth_generic_client_start_by_authtype(auth_generic_ctx, auth_type, auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	result->auth_ctx = talloc_move(result, &auth_generic_ctx->gensec_security);
	talloc_free(auth_generic_ctx);
	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return status;
}

/* This routine steals the creds pointer that is passed in */
static NTSTATUS rpccli_generic_bind_data_from_creds(TALLOC_CTX *mem_ctx,
						    enum dcerpc_AuthType auth_type,
						    enum dcerpc_AuthLevel auth_level,
						    const char *server,
						    const char *target_service,
						    struct cli_credentials *creds,
						    struct pipe_auth_data **presult)
{
	struct auth_generic_state *auth_generic_ctx;
	struct pipe_auth_data *result;
	NTSTATUS status;

	result = talloc_zero(mem_ctx, struct pipe_auth_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->auth_type = auth_type;
	result->auth_level = auth_level;
	result->auth_context_id = 1;

	status = auth_generic_client_prepare(result,
					     &auth_generic_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = auth_generic_set_creds(auth_generic_ctx, creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = gensec_set_target_service(auth_generic_ctx->gensec_security, target_service);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = gensec_set_target_hostname(auth_generic_ctx->gensec_security, server);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = auth_generic_client_start_by_authtype(auth_generic_ctx, auth_type, auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	result->auth_ctx = talloc_move(result, &auth_generic_ctx->gensec_security);
	talloc_free(auth_generic_ctx);
	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return status;
}

NTSTATUS rpccli_ncalrpc_bind_data(TALLOC_CTX *mem_ctx,
				  struct pipe_auth_data **presult)
{
	return rpccli_generic_bind_data(mem_ctx,
					DCERPC_AUTH_TYPE_NCALRPC_AS_SYSTEM,
					DCERPC_AUTH_LEVEL_CONNECT,
					NULL, /* server */
					"host", /* target_service */
					NAME_NT_AUTHORITY, /* domain */
					"SYSTEM",
					NULL, /* password */
					CRED_USE_KERBEROS_DISABLED,
					NULL, /* netlogon_creds_CredentialState */
					presult);
}

/**
 * Create an rpc pipe client struct, connecting to a tcp port.
 */
static NTSTATUS rpc_pipe_open_tcp_port(TALLOC_CTX *mem_ctx, const char *host,
				       const struct sockaddr_storage *ss_addr,
				       uint16_t port,
				       const struct ndr_interface_table *table,
				       struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct sockaddr_storage addr;
	NTSTATUS status;
	int fd;

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->abstract_syntax = table->syntax_id;
	result->transfer_syntax = ndr_transfer_syntax_ndr;

	result->desthost = talloc_strdup(result, host);
	if (result->desthost == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if (result->srv_name_slash == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;

	if (ss_addr == NULL) {
		if (!resolve_name(host, &addr, NBT_NAME_SERVER, false)) {
			status = NT_STATUS_NOT_FOUND;
			goto fail;
		}
	} else {
		addr = *ss_addr;
	}

	status = open_socket_out(&addr, port, 60*1000, &fd);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	set_socket_options(fd, lp_socket_options());

	status = rpc_transport_sock_init(result, fd, &result->transport);
	if (!NT_STATUS_IS_OK(status)) {
		close(fd);
		goto fail;
	}

	result->transport->transport = NCACN_IP_TCP;

	result->binding_handle = rpccli_bh_create(result, NULL, table);
	if (result->binding_handle == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return status;
}

static NTSTATUS rpccli_epm_map_binding(
	struct dcerpc_binding_handle *epm_connection,
	struct dcerpc_binding *binding,
	TALLOC_CTX *mem_ctx,
	char **pendpoint)
{
	TALLOC_CTX *frame = talloc_stackframe();
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(binding);
	enum dcerpc_transport_t res_transport;
	struct dcerpc_binding *res_binding = NULL;
	struct epm_twr_t *map_tower = NULL;
	struct epm_twr_p_t res_towers = { .twr = NULL };
	struct policy_handle *entry_handle = NULL;
	uint32_t num_towers = 0;
	const uint32_t max_towers = 1;
	const char *endpoint = NULL;
	char *tmp = NULL;
	uint32_t result;
	NTSTATUS status;

	map_tower = talloc_zero(frame, struct epm_twr_t);
	if (map_tower == NULL) {
		goto nomem;
	}

	status = dcerpc_binding_build_tower(
		frame, binding, &(map_tower->tower));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_binding_build_tower failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	res_towers.twr = talloc_array(frame, struct epm_twr_t, max_towers);
	if (res_towers.twr == NULL) {
		goto nomem;
	}

	entry_handle = talloc_zero(frame, struct policy_handle);
	if (entry_handle == NULL) {
		goto nomem;
	}

	status = dcerpc_epm_Map(
		epm_connection,
		frame,
		NULL,
		map_tower,
		entry_handle,
		max_towers,
		&num_towers,
		&res_towers,
		&result);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_epm_Map failed: %s\n", nt_errstr(status));
		goto done;
	}

	if (result != EPMAPPER_STATUS_OK) {
		DBG_DEBUG("dcerpc_epm_Map returned %"PRIu32"\n", result);
		status = NT_STATUS_NOT_FOUND;
		goto done;
	}

	if (num_towers != 1) {
		DBG_DEBUG("dcerpc_epm_Map returned %"PRIu32" towers\n",
			  num_towers);
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto done;
	}

	status = dcerpc_binding_from_tower(
		frame, &(res_towers.twr->tower), &res_binding);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_binding_from_tower failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	res_transport = dcerpc_binding_get_transport(res_binding);
	if (res_transport != transport) {
		DBG_DEBUG("dcerpc_epm_Map returned transport %d, "
			  "expected %d\n",
			  (int)res_transport,
			  (int)transport);
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto done;
	}

	endpoint = dcerpc_binding_get_string_option(res_binding, "endpoint");
	if (endpoint == NULL) {
		DBG_DEBUG("dcerpc_epm_Map returned no endpoint\n");
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto done;
	}

	tmp = talloc_strdup(mem_ctx, endpoint);
	if (tmp == NULL) {
		goto nomem;
	}
	*pendpoint = tmp;

	status = NT_STATUS_OK;
	goto done;

nomem:
	status = NT_STATUS_NO_MEMORY;
done:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS rpccli_epm_map_interface(
	struct dcerpc_binding_handle *epm_connection,
	enum dcerpc_transport_t transport,
	const struct ndr_syntax_id *iface,
	TALLOC_CTX *mem_ctx,
	char **pendpoint)
{
	struct dcerpc_binding *binding = NULL;
	char *endpoint = NULL;
	NTSTATUS status;

	status = dcerpc_parse_binding(mem_ctx, "", &binding);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_parse_binding failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = dcerpc_binding_set_transport(binding, transport);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_binding_set_transport failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = dcerpc_binding_set_abstract_syntax(binding, iface);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_binding_set_abstract_syntax failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = rpccli_epm_map_binding(
		epm_connection, binding, mem_ctx, &endpoint);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpccli_epm_map_binding failed: %s\n",
			  nt_errstr(status));
		goto done;
	}
	*pendpoint = endpoint;

done:
	TALLOC_FREE(binding);
	return status;
}

/**
 * Determine the tcp port on which a dcerpc interface is listening
 * for the ncacn_ip_tcp transport via the endpoint mapper of the
 * target host.
 */
static NTSTATUS rpc_pipe_get_tcp_port(const char *host,
				      const struct sockaddr_storage *addr,
				      const struct ndr_interface_table *table,
				      uint16_t *pport)
{
	NTSTATUS status;
	struct rpc_pipe_client *epm_pipe = NULL;
	struct pipe_auth_data *auth = NULL;
	char *endpoint = NULL;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if (pport == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (ndr_syntax_id_equal(&table->syntax_id,
				&ndr_table_epmapper.syntax_id)) {
		*pport = 135;
		status = NT_STATUS_OK;
		goto done;
	}

	/* open the connection to the endpoint mapper */
	status = rpc_pipe_open_tcp_port(tmp_ctx, host, addr, 135,
					&ndr_table_epmapper,
					&epm_pipe);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_anon_bind_data(tmp_ctx, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_pipe_bind(epm_pipe, auth);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_epm_map_interface(
		epm_pipe->binding_handle,
		NCACN_IP_TCP,
		&table->syntax_id,
		tmp_ctx,
		&endpoint);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpccli_epm_map_interface failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	*pport = (uint16_t)atoi(endpoint);

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/**
 * Create a rpc pipe client struct, connecting to a host via tcp.
 * The port is determined by asking the endpoint mapper on the given
 * host.
 */
static NTSTATUS rpc_pipe_open_tcp(
	TALLOC_CTX *mem_ctx,
	const char *host,
	const struct sockaddr_storage *addr,
	const struct ndr_interface_table *table,
	struct rpc_pipe_client **presult)
{
	NTSTATUS status;
	uint16_t port = 0;

	status = rpc_pipe_get_tcp_port(host, addr, table, &port);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return rpc_pipe_open_tcp_port(mem_ctx, host, addr, port,
				      table, presult);
}

static NTSTATUS rpc_pipe_get_ncalrpc_name(
	const struct ndr_syntax_id *iface,
	TALLOC_CTX *mem_ctx,
	char **psocket_name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_pipe_client *epm_pipe = NULL;
	struct pipe_auth_data *auth = NULL;
	NTSTATUS status = NT_STATUS_OK;
	bool is_epm;

	is_epm = ndr_syntax_id_equal(iface, &ndr_table_epmapper.syntax_id);
	if (is_epm) {
		char *endpoint = talloc_strdup(mem_ctx, "EPMAPPER");
		if (endpoint == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		*psocket_name = endpoint;
		goto done;
	}

	status = rpc_pipe_open_ncalrpc(
		frame, &ndr_table_epmapper, &epm_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_pipe_open_ncalrpc failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = rpccli_anon_bind_data(epm_pipe, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpccli_anon_bind_data failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = rpc_pipe_bind(epm_pipe, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_pipe_bind failed: %s\n", nt_errstr(status));
		goto done;
	}

	status = rpccli_epm_map_interface(
		epm_pipe->binding_handle,
		NCALRPC,
		iface,
		mem_ctx,
		psocket_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpccli_epm_map_interface failed: %s\n",
			  nt_errstr(status));
	}

done:
	TALLOC_FREE(frame);
	return status;
}

/********************************************************************
 Create a rpc pipe client struct, connecting to a unix domain socket
 ********************************************************************/
NTSTATUS rpc_pipe_open_ncalrpc(TALLOC_CTX *mem_ctx,
			       const struct ndr_interface_table *table,
			       struct rpc_pipe_client **presult)
{
	char *socket_name = NULL;
	struct rpc_pipe_client *result;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	socklen_t salen = sizeof(addr);
	int pathlen;
	NTSTATUS status;
	int fd = -1;

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = rpc_pipe_get_ncalrpc_name(
		&table->syntax_id, result, &socket_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_pipe_get_ncalrpc_name failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	pathlen = snprintf(
		addr.sun_path,
		sizeof(addr.sun_path),
		"%s/%s",
		lp_ncalrpc_dir(),
		socket_name);
	if ((pathlen < 0) || ((size_t)pathlen >= sizeof(addr.sun_path))) {
		DBG_DEBUG("socket_path for %s too long\n", socket_name);
		status = NT_STATUS_NAME_TOO_LONG;
		goto fail;
	}
	TALLOC_FREE(socket_name);

	result->abstract_syntax = table->syntax_id;
	result->transfer_syntax = ndr_transfer_syntax_ndr;

	result->desthost = get_myname(result);
	if (result->desthost == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if (result->srv_name_slash == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	if (connect(fd, (struct sockaddr *)(void *)&addr, salen) == -1) {
		DBG_WARNING("connect(%s) failed: %s\n",
			    addr.sun_path,
			    strerror(errno));
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = rpc_transport_sock_init(result, fd, &result->transport);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	fd = -1;

	result->transport->transport = NCALRPC;

	result->binding_handle = rpccli_bh_create(result, NULL, table);
	if (result->binding_handle == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	*presult = result;
	return NT_STATUS_OK;

 fail:
	if (fd != -1) {
		close(fd);
	}
	TALLOC_FREE(result);
	return status;
}

NTSTATUS rpc_pipe_open_local_np(
	TALLOC_CTX *mem_ctx,
	const struct ndr_interface_table *table,
	const char *remote_client_name,
	const struct tsocket_address *remote_client_addr,
	const char *local_server_name,
	const struct tsocket_address *local_server_addr,
	const struct auth_session_info *session_info,
	struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result = NULL;
	struct pipe_auth_data *auth = NULL;
	const char *pipe_name = NULL;
	struct tstream_context *npa_stream = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	int ret;

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		goto fail;
	}
	result->abstract_syntax = table->syntax_id;
	result->transfer_syntax = ndr_transfer_syntax_ndr;
	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;

	pipe_name = dcerpc_default_transport_endpoint(
		result, NCACN_NP, table);
	if (pipe_name == NULL) {
		DBG_DEBUG("dcerpc_default_transport_endpoint failed\n");
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	if (local_server_name == NULL) {
		result->desthost = get_myname(result);
	} else {
		result->desthost = talloc_strdup(result, local_server_name);
	}
	if (result->desthost == NULL) {
		goto fail;
	}
	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if (result->srv_name_slash == NULL) {
		goto fail;
	}

	ret = local_np_connect(
		pipe_name,
		NCALRPC,
		remote_client_name,
		remote_client_addr,
		local_server_name,
		local_server_addr,
		session_info,
		true,
		result,
		&npa_stream);
	if (ret != 0) {
		DBG_DEBUG("local_np_connect for %s and "
			  "user %s\\%s failed: %s\n",
			  pipe_name,
			  session_info->info->domain_name,
			  session_info->info->account_name,
			  strerror(ret));
		status = map_nt_error_from_unix(ret);
		goto fail;
	}

	status = rpc_transport_tstream_init(
		result, &npa_stream, &result->transport);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_transport_tstream_init failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	result->binding_handle = rpccli_bh_create(result, NULL, table);
	if (result->binding_handle == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DBG_DEBUG("Failed to create binding handle.\n");
		goto fail;
	}

	status = rpccli_anon_bind_data(result, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpccli_anon_bind_data failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_pipe_bind failed: %s\n", nt_errstr(status));
		goto fail;
	}

	*presult = result;
	return NT_STATUS_OK;

fail:
	TALLOC_FREE(result);
	return status;
}

struct rpc_pipe_client_np_ref {
	struct cli_state *cli;
	struct rpc_pipe_client *pipe;
};

static int rpc_pipe_client_np_ref_destructor(struct rpc_pipe_client_np_ref *np_ref)
{
	DLIST_REMOVE(np_ref->cli->pipe_list, np_ref->pipe);
	return 0;
}

/****************************************************************************
 Open a named pipe over SMB to a remote server.
 *
 * CAVEAT CALLER OF THIS FUNCTION:
 *    The returned rpc_pipe_client saves a copy of the cli_state cli pointer,
 *    so be sure that this function is called AFTER any structure (vs pointer)
 *    assignment of the cli.  In particular, libsmbclient does structure
 *    assignments of cli, which invalidates the data in the returned
 *    rpc_pipe_client if this function is called before the structure assignment
 *    of cli.
 *
 ****************************************************************************/

struct rpc_pipe_open_np_state {
	struct cli_state *cli;
	const struct ndr_interface_table *table;
	struct rpc_pipe_client *result;
};

static void rpc_pipe_open_np_done(struct tevent_req *subreq);

struct tevent_req *rpc_pipe_open_np_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const struct ndr_interface_table *table)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct rpc_pipe_open_np_state *state = NULL;
	struct rpc_pipe_client *result = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct rpc_pipe_open_np_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->table = table;

	state->result = talloc_zero(state, struct rpc_pipe_client);
	if (tevent_req_nomem(state->result, req)) {
		return tevent_req_post(req, ev);
	}
	result = state->result;

	result->abstract_syntax = table->syntax_id;
	result->transfer_syntax = ndr_transfer_syntax_ndr;

	result->desthost = talloc_strdup(
		result, smbXcli_conn_remote_name(cli->conn));
	if (tevent_req_nomem(result->desthost, req)) {
		return tevent_req_post(req, ev);
	}

	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if (tevent_req_nomem(result->srv_name_slash, req)) {
		return tevent_req_post(req, ev);
	}

	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;

	subreq = rpc_transport_np_init_send(state, ev, cli, table);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_pipe_open_np_done, req);
	return req;
}

static void rpc_pipe_open_np_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_pipe_open_np_state *state = tevent_req_data(
		req, struct rpc_pipe_open_np_state);
	struct rpc_pipe_client *result = state->result;
	struct rpc_pipe_client_np_ref *np_ref = NULL;
	NTSTATUS status;

	status = rpc_transport_np_init_recv(
		subreq, result, &result->transport);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	result->transport->transport = NCACN_NP;

	np_ref = talloc(result->transport, struct rpc_pipe_client_np_ref);
	if (tevent_req_nomem(np_ref, req)) {
		return;
	}
	np_ref->cli = state->cli;
	np_ref->pipe = result;

	DLIST_ADD(np_ref->cli->pipe_list, np_ref->pipe);
	talloc_set_destructor(np_ref, rpc_pipe_client_np_ref_destructor);

	result->binding_handle = rpccli_bh_create(result, NULL, state->table);
	if (tevent_req_nomem(result->binding_handle, req)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS rpc_pipe_open_np_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct rpc_pipe_client **_result)
{
	struct rpc_pipe_open_np_state *state = tevent_req_data(
		req, struct rpc_pipe_open_np_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*_result = talloc_move(mem_ctx, &state->result);
	return NT_STATUS_OK;
}

NTSTATUS rpc_pipe_open_np(struct cli_state *cli,
			  const struct ndr_interface_table *table,
			  struct rpc_pipe_client **presult)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(cli);
	if (ev == NULL) {
		goto fail;
	}
	req = rpc_pipe_open_np_send(ev, ev, cli, table);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = rpc_pipe_open_np_recv(req, NULL, presult);
fail:
	TALLOC_FREE(req);
	TALLOC_FREE(ev);
	return status;
}

/****************************************************************************
 Open a pipe to a remote server.
 ****************************************************************************/

static NTSTATUS cli_rpc_pipe_open(struct cli_state *cli,
				  enum dcerpc_transport_t transport,
				  const struct ndr_interface_table *table,
				  const char *remote_name,
				  const struct sockaddr_storage *remote_sockaddr,
				  struct rpc_pipe_client **presult)
{
	switch (transport) {
	case NCACN_IP_TCP:
		return rpc_pipe_open_tcp(NULL,
					 remote_name,
					 remote_sockaddr,
					 table, presult);
	case NCACN_NP:
		return rpc_pipe_open_np(cli, table, presult);
	default:
		return NT_STATUS_NOT_IMPLEMENTED;
	}
}

/****************************************************************************
 Open a named pipe to an SMB server and bind anonymously.
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_noauth_transport(struct cli_state *cli,
					    enum dcerpc_transport_t transport,
					    const struct ndr_interface_table *table,
					    const char *remote_name,
					    const struct sockaddr_storage *remote_sockaddr,
					    struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct pipe_auth_data *auth;
	NTSTATUS status;

	status = cli_rpc_pipe_open(cli,
				   transport,
				   table,
				   remote_name,
				   remote_sockaddr,
				   &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_anon_bind_data(result, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("rpccli_anon_bind_data returned %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	/*
	 * This is a bit of an abstraction violation due to the fact that an
	 * anonymous bind on an authenticated SMB inherits the user/domain
	 * from the enclosing SMB creds
	 */

	if (transport == NCACN_NP) {
		struct smbXcli_session *session;

		if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
			session = cli->smb2.session;
		} else {
			session = cli->smb1.session;
		}

		status = smbXcli_session_application_key(session, auth,
						&auth->transport_session_key);
		if (!NT_STATUS_IS_OK(status)) {
			auth->transport_session_key = data_blob_null;
		}
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		int lvl = 0;
		if (ndr_syntax_id_equal(&table->syntax_id,
					&ndr_table_dssetup.syntax_id)) {
			/* non AD domains just don't have this pipe, avoid
			 * level 0 statement in that case - gd */
			lvl = 3;
		}
		DEBUG(lvl, ("cli_rpc_pipe_open_noauth: rpc_pipe_bind for pipe "
			    "%s failed with error %s\n",
			    table->name,
			    nt_errstr(status) ));
		TALLOC_FREE(result);
		return status;
	}

	DEBUG(10,("cli_rpc_pipe_open_noauth: opened pipe %s to machine "
		  "%s and bound anonymously.\n",
		  table->name,
		  result->desthost));

	*presult = result;
	return NT_STATUS_OK;
}

/****************************************************************************
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_noauth(struct cli_state *cli,
				  const struct ndr_interface_table *table,
				  struct rpc_pipe_client **presult)
{
	const char *remote_name = smbXcli_conn_remote_name(cli->conn);
	const struct sockaddr_storage *remote_sockaddr =
		smbXcli_conn_remote_sockaddr(cli->conn);

	return cli_rpc_pipe_open_noauth_transport(cli, NCACN_NP,
						  table,
						  remote_name,
						  remote_sockaddr,
						  presult);
}

/****************************************************************************
 Open a named pipe to an SMB server and bind using the mech specified

 This routine references the creds pointer that is passed in
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_with_creds(struct cli_state *cli,
				      const struct ndr_interface_table *table,
				      enum dcerpc_transport_t transport,
				      enum dcerpc_AuthType auth_type,
				      enum dcerpc_AuthLevel auth_level,
				      const char *server,
				      const struct sockaddr_storage *remote_sockaddr,
				      struct cli_credentials *creds,
				      struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct pipe_auth_data *auth = NULL;
	const char *target_service = table->authservices->names[0];
	NTSTATUS status;

	status = cli_rpc_pipe_open(cli,
				   transport,
				   table,
				   server,
				   remote_sockaddr,
				   &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_generic_bind_data_from_creds(result,
						     auth_type, auth_level,
						     server, target_service,
						     creds,
						     &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("rpccli_generic_bind_data_from_creds returned %s\n",
			nt_errstr(status));
		goto err;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("cli_rpc_pipe_bind failed with error %s\n",
			nt_errstr(status));
		goto err;
	}

	DBG_DEBUG("opened pipe %s to machine %s and bound as user %s.\n",
		  table->name,
		  result->desthost,
		  cli_credentials_get_unparsed_name(creds, talloc_tos()));

	*presult = result;
	return NT_STATUS_OK;

  err:

	TALLOC_FREE(result);
	return status;
}

NTSTATUS cli_rpc_pipe_open_bind_schannel(
	struct cli_state *cli,
	const struct ndr_interface_table *table,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *netlogon_creds,
	const char *remote_name,
	const struct sockaddr_storage *remote_sockaddr,
	struct rpc_pipe_client **_rpccli)
{
	struct rpc_pipe_client *rpccli;
	struct pipe_auth_data *rpcauth;
	const char *target_service = table->authservices->names[0];
	struct cli_credentials *cli_creds;
	enum dcerpc_AuthLevel auth_level;
	NTSTATUS status;

	status = cli_rpc_pipe_open(cli,
				   transport,
				   table,
				   remote_name,
				   remote_sockaddr,
				   &rpccli);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auth_level = netlogon_creds_cli_auth_level(netlogon_creds);

	status = netlogon_creds_bind_cli_credentials(
		netlogon_creds, rpccli, &cli_creds);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("netlogon_creds_bind_cli_credentials failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(rpccli);
		return status;
	}

	status = rpccli_generic_bind_data_from_creds(rpccli,
						     DCERPC_AUTH_TYPE_SCHANNEL,
						     auth_level,
						     rpccli->desthost,
						     target_service,
						     cli_creds,
						     &rpcauth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("rpccli_generic_bind_data_from_creds returned %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(rpccli);
		return status;
	}

	status = rpc_pipe_bind(rpccli, rpcauth);

	/* No TALLOC_FREE, gensec takes references */
	talloc_unlink(rpccli, cli_creds);
	cli_creds = NULL;

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_pipe_bind failed with error %s\n",
			  nt_errstr(status));
		TALLOC_FREE(rpccli);
		return status;
	}

	*_rpccli = rpccli;

	return NT_STATUS_OK;
}

NTSTATUS cli_rpc_pipe_open_schannel_with_creds(struct cli_state *cli,
					       const struct ndr_interface_table *table,
					       enum dcerpc_transport_t transport,
					       struct netlogon_creds_cli_context *netlogon_creds,
					       const char *remote_name,
					       const struct sockaddr_storage *remote_sockaddr,
					       struct rpc_pipe_client **_rpccli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_pipe_client *rpccli;
	struct netlogon_creds_cli_lck *lck;
	NTSTATUS status;

	status = netlogon_creds_cli_lck(
		netlogon_creds, NETLOGON_CREDS_CLI_LCK_EXCLUSIVE,
		frame, &lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netlogon_creds_cli_lck returned %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	status = cli_rpc_pipe_open_bind_schannel(cli,
						 table,
						 transport,
						 netlogon_creds,
						 remote_name,
						 remote_sockaddr,
						 &rpccli);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED)) {
		netlogon_creds_cli_delete_lck(netlogon_creds);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("cli_rpc_pipe_open_bind_schannel failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	if (ndr_syntax_id_equal(&table->syntax_id,
				&ndr_table_netlogon.syntax_id)) {
		status = netlogon_creds_cli_check(netlogon_creds,
						  rpccli->binding_handle,
						  NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("netlogon_creds_cli_check failed with %s\n",
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}
	}

	DBG_DEBUG("opened pipe %s to machine %s with key %s "
		  "and bound using schannel.\n",
		  table->name, rpccli->desthost,
		  netlogon_creds_cli_debug_string(netlogon_creds, lck));

	TALLOC_FREE(frame);

	*_rpccli = rpccli;
	return NT_STATUS_OK;
}

NTSTATUS cli_get_session_key(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *cli,
			     DATA_BLOB *session_key)
{
	NTSTATUS status;
	struct pipe_auth_data *a;
	struct gensec_security *gensec_security;
	DATA_BLOB sk = { .data = NULL };
	bool make_dup = false;

	if (!session_key || !cli) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	a = cli->auth;

	if (a == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (cli->auth->auth_type) {
	case DCERPC_AUTH_TYPE_NONE:
		sk = data_blob_const(a->transport_session_key.data,
				     a->transport_session_key.length);
		make_dup = true;
		break;
	default:
		gensec_security = a->auth_ctx;
		status = gensec_session_key(gensec_security, mem_ctx, &sk);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		make_dup = false;
		break;
	}

	if (!sk.data) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (make_dup) {
		*session_key = data_blob_dup_talloc(mem_ctx, sk);
	} else {
		*session_key = sk;
	}

	return NT_STATUS_OK;
}
