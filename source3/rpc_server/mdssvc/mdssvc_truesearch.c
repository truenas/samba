/*
 *  Unix SMB/CIFS implementation.
 *  Main metadata server / Spotlight routines / truesearch backend
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
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Spotlight backend for truesearchd, the TrueNAS search daemon.
 *
 * The backend talks to truesearchd on a unix stream socket
 * ("truesearch:socket"). Each message is a 4-byte big-endian length, then
 * the XDR of one rix_call or rix_reply. rpcgen makes the XDR code from
 * truenas_truesearch.x.
 *
 * truesearchd does the access checks. A search sends the unix token of the
 * session, and truesearchd removes the hits that the user cannot open.
 * The backend connects as root, because truesearchd accepts this identity
 * only from a root peer. The backend does not connect to the VFS, change
 * directory or become the user. It only checks that the user can read the
 * share.
 *
 * A search identifies the share by its dataset and the path of the share
 * root in the dataset (mds_truesearch_locate()). The scope and the hits
 * are relative to the share root. The item ID of a hit is the file ID that
 * smbd gives the file. truesearchd computes it (mds_truesearch_item_id()).
 *
 * Each tree connect has one connection. It sends one call at a time.
 * Searches wait in a queue for their next call: RIX_OPEN, then RIX_FETCH
 * until a client page is full. RIX_CLOSE releases the handle of a finished
 * or closed query. A handle is valid only on its connection. When the
 * connection breaks, the searches that have a handle fail. The other
 * searches continue on a new connection.
 */

#include "includes.h"
#include "smbd/proto.h"
#include "librpc/gen_ndr/auth.h"
#include "libcli/security/security.h"
#include "libcli/security/session.h"
#include "lib/util/dlinklist.h"
#include "lib/util/tevent_unix.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util_tsock.h"
#include "lib/truenas_mount.h"
#include "mdssvc.h"
#include "mdssvc_truesearch.h"

/* <rpc/xdr.h> uses TRUE and FALSE */
#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

#ifdef HAVE_RPC_TYPES_H
#include <rpc/types.h>
#endif
#include <rpc/xdr.h>
#include "rpc_server/mdssvc/truenas_truesearch.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define MDS_TRUESEARCH_SOCKET "/run/truesearchd/mdssvc.sock"

/*
 * Maximum length of "/<share>/<path>" in a reply (MAX_SL_STRLEN).
 * marshalling.c refuses a longer string, and then the full page is lost.
 */
#define MDS_TRUESEARCH_PATH_MAX 1024

/* Time limit for one call, in seconds. Then the connection closes. */
#define MDS_TRUESEARCH_CALL_TIMEOUT 20

/* Minimum time between two logs of a connect failure, in seconds */
#define MDS_TRUESEARCH_LOG_INTERVAL 60

struct mds_truesearch_search;
struct mds_truesearch_close;

/* One per tree connect */
struct mds_truesearch_ctx {
	struct mds_ctx *mds_ctx;
	struct tevent_context *ev;

	/* "truesearch:socket" */
	const char *socket_path;
	/* The share path without a trailing slash */
	const char *root;
	/* The share root for RIX_OPEN: the dataset and the path in it */
	const char *dataset;
	const char *share;
	/* RIX_OPEN_* flags for all searches of the share */
	uint32_t flags;
	/* "truesearch:max results". 0 means the truesearchd limit. */
	uint32_t max_results;
	/* Hits per RIX_FETCH, at most the max_page of truesearchd */
	uint32_t page;
	/* The share loads vfs_zfs_core. Item IDs are its file IDs. */
	bool zfs_file_ids;

	/* The connection. ready is true after the RIX_HELLO reply. */
	struct tstream_context *stream;
	bool ready;
	/* Number of lost connections */
	uint64_t generation;
	uint32_t xid;
	time_t logged_at;

	/* The request in progress: a connect or a call */
	struct tevent_req *call;
	rix_op call_op;
	struct mds_truesearch_search *call_search;

	/* Searches that wait for their next call, and handles to release */
	struct mds_truesearch_search *searches;
	struct mds_truesearch_close *closes;

	/* The destructor runs. Queue no more calls. */
	bool dying;
};

/* One per query (slq->backend_private) */
struct mds_truesearch_search {
	struct mds_truesearch_search *prev, *next;
	struct mds_truesearch_ctx *tctx;
	/* NULL if mdssvc freed the query during its call */
	struct sl_query *slq;
	/* In tctx->searches */
	bool waiting;
	/* The search has a handle that is not released */
	bool open;
	uint64_t handle;
	uint64_t generation;
	/* RIX_OPEN was sent again after a broken connection */
	bool retried;
};

/* A handle to release */
struct mds_truesearch_close {
	struct mds_truesearch_close *prev, *next;
	uint64_t handle;
};

static void mds_truesearch_trigger(struct mds_truesearch_ctx *tctx);

static const char *rix_op_name(rix_op op)
{
	switch (op) {
	case RIX_HELLO:
		return "RIX_HELLO";
	case RIX_OPEN:
		return "RIX_OPEN";
	case RIX_FETCH:
		return "RIX_FETCH";
	case RIX_CLOSE:
		return "RIX_CLOSE";
	}
	return "RIX_?";
}

static const char *rix_status_name(rix_status status)
{
	switch (status) {
	case RIX_OK:
		return "RIX_OK";
	case RIX_BAD_VERSION:
		return "RIX_BAD_VERSION";
	case RIX_BAD_QUERY:
		return "RIX_BAD_QUERY";
	case RIX_BAD_SCOPE:
		return "RIX_BAD_SCOPE";
	case RIX_NO_INDEX:
		return "RIX_NO_INDEX";
	case RIX_DENIED:
		return "RIX_DENIED";
	case RIX_BAD_HANDLE:
		return "RIX_BAD_HANDLE";
	case RIX_BUSY:
		return "RIX_BUSY";
	case RIX_INTERNAL:
		return "RIX_INTERNAL";
	}
	return "RIX_?";
}

/* Encode a call as a record: the length, then the XDR */
static bool rix_encode(TALLOC_CTX *mem_ctx,
		       rix_call *call,
		       uint8_t **pbuf,
		       size_t *plen)
{
	unsigned long size;
	uint8_t *buf = NULL;
	XDR xdr;
	bool ok;

	size = xdr_sizeof((xdrproc_t)xdr_rix_call, call);
	if (size == 0 || size > RIX_MAX_FRAME) {
		return false;
	}

	buf = talloc_array(mem_ctx, uint8_t, size + 4);
	if (buf == NULL) {
		return false;
	}
	RSIVAL(buf, 0, size);

	xdrmem_create(&xdr, (char *)buf + 4, size, XDR_ENCODE);
	ok = xdr_rix_call(&xdr, call);
	if (ok && xdr_getpos(&xdr) != size) {
		ok = false;
	}
	xdr_destroy(&xdr);
	if (!ok) {
		TALLOC_FREE(buf);
		return false;
	}

	*pbuf = buf;
	*plen = size + 4;
	return true;
}

/* Free what xdr_rix_reply() allocated */
static int rix_reply_destructor(rix_reply *reply)
{
	xdr_free((xdrproc_t)xdr_rix_reply, (char *)reply);
	return 0;
}

/* Decode a reply. The XDR must use all bytes of the record. */
static rix_reply *rix_decode(TALLOC_CTX *mem_ctx,
			     uint8_t *buf,
			     size_t len)
{
	rix_reply *reply = NULL;
	XDR xdr;
	bool ok;

	reply = talloc_zero(mem_ctx, rix_reply);
	if (reply == NULL) {
		return NULL;
	}
	talloc_set_destructor(reply, rix_reply_destructor);

	xdrmem_create(&xdr, (char *)buf, len, XDR_DECODE);
	ok = xdr_rix_reply(&xdr, reply);
	if (ok && xdr_getpos(&xdr) != len) {
		ok = false;
	}
	xdr_destroy(&xdr);
	if (!ok) {
		TALLOC_FREE(reply);
		return NULL;
	}

	return reply;
}

/* Get the record length from the first 4 bytes */
static ssize_t rix_more(uint8_t *buf, size_t buflen, void *private_data)
{
	uint32_t len;

	if (buflen > 4) {
		return 0;
	}

	len = RIVAL(buf, 0);
	if (len == 0 || len > RIX_MAX_FRAME) {
		return -1;
	}
	return len;
}

struct rix_call_state {
	struct tevent_context *ev;
	struct tstream_context *stream;
	uint32_t xid;
	rix_op op;
	struct iovec iov;
	rix_reply *reply;
};

static void rix_call_written(struct tevent_req *subreq);
static void rix_call_read(struct tevent_req *subreq);

/* Send one encoded call and read the reply */
static struct tevent_req *rix_call_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					uint8_t *buf,
					size_t len,
					uint32_t xid,
					rix_op op)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct rix_call_state *state = NULL;
	bool ok;

	req = tevent_req_create(mem_ctx, &state, struct rix_call_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct rix_call_state) {
		.ev = ev,
		.stream = stream,
		.xid = xid,
		.op = op,
		.iov = {
			.iov_base = talloc_move(state, &buf),
			.iov_len = len,
		},
	};

	ok = tevent_req_set_endtime(
		req, ev, timeval_current_ofs(MDS_TRUESEARCH_CALL_TIMEOUT, 0));
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	subreq = tstream_writev_send(state, ev, stream, &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rix_call_written, req);
	return req;
}

static void rix_call_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rix_call_state *state = tevent_req_data(
		req, struct rix_call_state);
	int ret;
	int err;

	ret = tstream_writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	TALLOC_FREE(state->iov.iov_base);

	subreq = tstream_read_packet_send(
		state, state->ev, state->stream, 4, rix_more, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rix_call_read, req);
}

static void rix_call_read(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rix_call_state *state = tevent_req_data(
		req, struct rix_call_state);
	uint8_t *buf = NULL;
	ssize_t len;
	int err;

	len = tstream_read_packet_recv(subreq, state, &buf, &err);
	TALLOC_FREE(subreq);
	if (len == -1) {
		tevent_req_error(req, err);
		return;
	}

	state->reply = rix_decode(state, buf + 4, len - 4);
	TALLOC_FREE(buf);
	if (state->reply == NULL) {
		DBG_ERR("cannot decode the reply to %s\n",
			rix_op_name(state->op));
		tevent_req_error(req, EPROTO);
		return;
	}

	if (state->reply->vers != RIX_PROTO_VERSION ||
	    state->reply->xid != state->xid) {
		DBG_ERR("reply to %s: version %u, xid %u, expected xid %u\n",
			rix_op_name(state->op),
			state->reply->vers,
			state->reply->xid,
			state->xid);
		tevent_req_error(req, EPROTO);
		return;
	}

	if (state->reply->outcome.status == RIX_OK &&
	    state->reply->outcome.rix_outcome_u.answer.op != state->op)
	{
		DBG_ERR("reply to %s is for %s\n",
			rix_op_name(state->op),
			rix_op_name(state->reply->outcome.rix_outcome_u.answer.op));
		tevent_req_error(req, EPROTO);
		return;
	}

	tevent_req_done(req);
}

static int rix_call_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx,
			 rix_reply **preply)
{
	struct rix_call_state *state = tevent_req_data(
		req, struct rix_call_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*preply = talloc_move(mem_ctx, &state->reply);
	tevent_req_received(req);
	return 0;
}

/* Log a connect failure at level ERR at most once per minute */
static void mds_truesearch_log_unreachable(struct mds_truesearch_ctx *tctx,
					const char *what,
					int err)
{
	time_t now = time(NULL);

	if (now - tctx->logged_at >= MDS_TRUESEARCH_LOG_INTERVAL) {
		tctx->logged_at = now;
		DBG_ERR("truesearchd at %s: %s: %s\n",
			tctx->socket_path, what, strerror(err));
		return;
	}
	DBG_DEBUG("truesearchd at %s: %s: %s\n",
		  tctx->socket_path, what, strerror(err));
}

static void mds_truesearch_wait(struct mds_truesearch_search *s)
{
	if (s->waiting) {
		return;
	}
	DLIST_ADD_END(s->tctx->searches, s);
	s->waiting = true;
}

static void mds_truesearch_release(struct mds_truesearch_ctx *tctx,
				struct mds_truesearch_search *s)
{
	struct mds_truesearch_close *c = NULL;

	if (!s->open) {
		return;
	}
	s->open = false;

	if (tctx->dying || s->generation != tctx->generation) {
		/* The handle closed with its connection */
		return;
	}

	c = talloc_zero(tctx, struct mds_truesearch_close);
	if (c == NULL) {
		/* truesearchd releases the handle after an idle time */
		return;
	}
	c->handle = s->handle;
	DLIST_ADD_END(tctx->closes, c);
}

/* Set the query to the error state and release its handle */
static void mds_truesearch_fail(struct mds_truesearch_search *s)
{
	if (s->slq != NULL) {
		s->slq->state = SLQ_STATE_ERROR;
	}
	mds_truesearch_release(s->tctx, s);
}

/*
 * Close the connection. Its handles become invalid. Fail the waiting
 * searches that have a handle. If fail_all is true, fail all waiting
 * searches, because truesearchd is not available.
 */
static void mds_truesearch_disconnect(struct mds_truesearch_ctx *tctx,
				   bool fail_all)
{
	struct mds_truesearch_search *s = NULL;
	struct mds_truesearch_search *next = NULL;
	struct mds_truesearch_close *c = NULL;

	TALLOC_FREE(tctx->stream);
	tctx->ready = false;
	tctx->generation += 1;

	while ((c = tctx->closes) != NULL) {
		DLIST_REMOVE(tctx->closes, c);
		TALLOC_FREE(c);
	}

	for (s = tctx->searches; s != NULL; s = next) {
		next = s->next;
		if (!fail_all && !s->open) {
			continue;
		}
		DLIST_REMOVE(tctx->searches, s);
		s->waiting = false;
		mds_truesearch_fail(s);
	}
}

/* Return true if the error is a broken connection, not a bad reply */
static bool mds_truesearch_broken(int err)
{
	switch (err) {
	case EPIPE:
	case ECONNRESET:
	case ECONNABORTED:
	case ENOTCONN:
		return true;
	}
	return false;
}

static int mds_truesearch_search_destructor(struct mds_truesearch_search *s)
{
	struct mds_truesearch_ctx *tctx = s->tctx;

	if (tctx->call_search == s) {
		/*
		 * The call of this search is in progress. Keep the search
		 * until the reply arrives, then release its handle.
		 */
		s->slq = NULL;
		return -1;
	}

	if (s->waiting) {
		DLIST_REMOVE(tctx->searches, s);
		s->waiting = false;
	}
	mds_truesearch_release(tctx, s);
	if (!tctx->dying) {
		mds_truesearch_trigger(tctx);
	}
	return 0;
}

static int mds_truesearch_ctx_destructor(struct mds_truesearch_ctx *tctx)
{
	tctx->dying = true;

	/* Free the search of the call in progress with tctx */
	if (tctx->call_search != NULL) {
		talloc_set_destructor(tctx->call_search, NULL);
		tctx->call_search = NULL;
	}

	/* Free the request before its stream */
	TALLOC_FREE(tctx->call);
	TALLOC_FREE(tctx->stream);
	return 0;
}

static void mds_truesearch_call_done(struct tevent_req *req);

/* Send a call. s is the search of the call, or NULL. */
static bool mds_truesearch_send(struct mds_truesearch_ctx *tctx,
			     rix_call *call,
			     struct mds_truesearch_search *s)
{
	struct tevent_req *req = NULL;
	uint8_t *buf = NULL;
	size_t len;
	bool ok;

	call->vers = RIX_PROTO_VERSION;
	call->xid = ++tctx->xid;

	ok = rix_encode(tctx, call, &buf, &len);
	if (!ok) {
		DBG_ERR("cannot encode %s\n", rix_op_name(call->request.op));
		return false;
	}

	req = rix_call_send(tctx,
			    tctx->ev,
			    tctx->stream,
			    buf,
			    len,
			    call->xid,
			    call->request.op);
	if (req == NULL) {
		TALLOC_FREE(buf);
		return false;
	}
	tevent_req_set_callback(req, mds_truesearch_call_done, tctx);

	tctx->call = req;
	tctx->call_op = call->request.op;
	tctx->call_search = s;
	return true;
}

static bool mds_truesearch_send_hello(struct mds_truesearch_ctx *tctx)
{
	rix_call call = {
		.request = {
			.op = RIX_HELLO,
			.rix_request_u.hello = {
				.vers = RIX_PROTO_VERSION,
			},
		},
	};

	return mds_truesearch_send(tctx, &call, NULL);
}

static bool mds_truesearch_send_close(struct mds_truesearch_ctx *tctx,
				   uint64_t handle)
{
	rix_call call = {
		.request = {
			.op = RIX_CLOSE,
			.rix_request_u.close = {
				.handle = handle,
			},
		},
	};

	return mds_truesearch_send(tctx, &call, NULL);
}

static bool mds_truesearch_send_fetch(struct mds_truesearch_search *s)
{
	struct mds_truesearch_ctx *tctx = s->tctx;
	int queued = s->slq->query_results->num_results;
	uint32_t limit;
	rix_call call;

	/* Fill the client page, with at most the page of truesearchd */
	limit = queued < SL_PAGESIZE ? SL_PAGESIZE - queued : 1;
	limit = MIN(limit, tctx->page);

	call = (rix_call) {
		.request = {
			.op = RIX_FETCH,
			.rix_request_u.fetch = {
				.handle = s->handle,
				.limit = limit,
			},
		},
	};

	return mds_truesearch_send(tctx, &call, s);
}

/*
 * Return the item ID of a hit: the file ID that smbd gives the file. All
 * hits are on the share's dataset. With vfs_zfs_core, it is the file ID
 * that truesearchd gives: the object number and the inode generation, as
 * in zfs_core_file_id.h. Otherwise it is the inode number.
 */
static uint64_t mds_truesearch_item_id(const struct mds_truesearch_ctx *tctx,
				       const rix_stat *st)
{
	if (tctx->zfs_file_ids) {
		return st->qfid.file_id;
	}
	return st->unix_meta.ino;
}

static bool mds_truesearch_send_open(struct mds_truesearch_search *s)
{
	struct mds_truesearch_ctx *tctx = s->tctx;
	struct sl_query *slq = s->slq;
	const struct security_unix_token *ut =
		slq->mds_ctx->pipe_session_info->unix_token;
	TALLOC_CTX *frame = talloc_stackframe();
	const char *scope = NULL;
	u_int *gids = NULL;
	u_quad_t *cnids = NULL;
	uint32_t ngids;
	uint32_t ncnids = 0;
	rix_call call;
	uint32_t i;
	bool ok;

	/*
	 * Refuse a user with too many groups. Do not drop groups: with NFSv4
	 * ACLs, a dropped group can bypass a deny entry for that group.
	 */
	if (ut->ngroups > RIX_MAX_GROUPS) {
		DBG_NOTICE("uid %u has %u groups, more than %u: "
			   "search refused\n",
			   (unsigned)ut->uid,
			   (unsigned)ut->ngroups,
			   (unsigned)RIX_MAX_GROUPS);
		TALLOC_FREE(frame);
		return false;
	}
	ngids = ut->ngroups;
	gids = talloc_array(frame, u_int, ngids);
	if (gids == NULL && ngids > 0) {
		TALLOC_FREE(frame);
		return false;
	}
	for (i = 0; i < ngids; i++) {
		gids[i] = ut->groups[i];
	}

	/*
	 * Send the item IDs as the client gave them. truesearchd keeps the
	 * file whose generation an item ID holds. With more than
	 * RIX_MAX_CNIDS, do not restrict. mdssvc also compares the full item
	 * ID of each result.
	 */
	if (slq->cnids != NULL && slq->cnids_num <= RIX_MAX_CNIDS) {
		ncnids = slq->cnids_num;
		cnids = talloc_array(frame, u_quad_t, ncnids);
		if (cnids == NULL && ncnids > 0) {
			TALLOC_FREE(frame);
			return false;
		}
		for (i = 0; i < ncnids; i++) {
			cnids[i] = slq->cnids[i];
		}
	}

	/*
	 * Make the scope relative to the share root. mdssvc joins the share
	 * path and the client path. Remove the slashes at the join.
	 */
	if (!subdir_of(tctx->root, strlen(tctx->root), slq->path_scope,
		       &scope)) {
		DBG_NOTICE("scope [%s] is not under the share's path [%s]\n",
			   slq->path_scope, tctx->root);
		TALLOC_FREE(frame);
		return false;
	}
	while (*scope == '/') {
		scope++;
	}

	call = (rix_call) {
		.request = {
			.op = RIX_OPEN,
			.rix_request_u.open = {
				.dataset = discard_const_p(char, tctx->dataset),
				.share = discard_const_p(char, tctx->share),
				.scope = discard_const_p(char, scope),
				.query = slq->query_string,
				.who = {
					.uid = ut->uid,
					.gid = ut->gid,
					.gids = {
						.gids_len = ngids,
						.gids_val = gids,
					},
				},
				.flags = tctx->flags,
				.max_results = tctx->max_results,
				.cnids = {
					.cnids_len = ncnids,
					.cnids_val = cnids,
				},
			},
		},
	};

	DBG_DEBUG("RIX_OPEN dataset [%s] share [%s] scope [%s] query [%s]\n",
		  tctx->dataset, tctx->share, scope, slq->query_string);

	ok = mds_truesearch_send(tctx, &call, s);
	TALLOC_FREE(frame);
	return ok;
}

static void mds_truesearch_connect(struct mds_truesearch_ctx *tctx);

/* Send the next queued call if no call is in progress */
static void mds_truesearch_trigger(struct mds_truesearch_ctx *tctx)
{
	struct mds_truesearch_search *s = NULL;
	struct mds_truesearch_close *c = NULL;
	bool ok;

	/* Until a call is in progress or the queue is empty */
	while (!tctx->dying && tctx->call == NULL) {
		if (!tctx->ready) {
			if (tctx->searches != NULL) {
				mds_truesearch_connect(tctx);
				continue;
			}
			return;
		}

		c = tctx->closes;
		if (c != NULL) {
			DLIST_REMOVE(tctx->closes, c);
			ok = mds_truesearch_send_close(tctx, c->handle);
			TALLOC_FREE(c);
			if (!ok) {
				mds_truesearch_disconnect(tctx, true);
			}
			continue;
		}

		s = tctx->searches;
		if (s == NULL) {
			return;
		}
		DLIST_REMOVE(tctx->searches, s);
		s->waiting = false;

		if (!s->open) {
			ok = mds_truesearch_send_open(s);
			if (!ok) {
				/*
				 * The query does not encode, or the user has
				 * too many groups
				 */
				mds_truesearch_fail(s);
			}
			continue;
		}

		if (s->generation != tctx->generation) {
			/* The handle is from an earlier connection */
			mds_truesearch_fail(s);
			continue;
		}

		ok = mds_truesearch_send_fetch(s);
		if (!ok) {
			mds_truesearch_fail(s);
			mds_truesearch_disconnect(tctx, true);
		}
	}
}

static void mds_truesearch_connected(struct tevent_req *subreq);

static void mds_truesearch_connect(struct mds_truesearch_ctx *tctx)
{
	struct tsocket_address *local = NULL;
	struct tsocket_address *remote = NULL;
	struct tevent_req *subreq = NULL;
	int err = ENOMEM;
	int ret;

	ret = tsocket_address_unix_from_path(tctx, "", &local);
	if (ret != 0) {
		err = errno;
		goto fail;
	}
	ret = tsocket_address_unix_from_path(tctx, tctx->socket_path, &remote);
	if (ret != 0) {
		err = errno;
		goto fail;
	}

	/*
	 * truesearchd accepts the identity in a search only from a root peer.
	 * It reads the peer credentials at connect().
	 */
	become_root();
	subreq = tstream_unix_connect_send(tctx, tctx->ev, local, remote);
	unbecome_root();
	TALLOC_FREE(local);
	TALLOC_FREE(remote);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, mds_truesearch_connected, tctx);
	tctx->call = subreq;
	return;

fail:
	TALLOC_FREE(local);
	TALLOC_FREE(remote);
	mds_truesearch_log_unreachable(tctx, "connect", err);
	mds_truesearch_disconnect(tctx, true);
}

static void mds_truesearch_connected(struct tevent_req *subreq)
{
	struct mds_truesearch_ctx *tctx = tevent_req_callback_data(
		subreq, struct mds_truesearch_ctx);
	int ret;
	int err;
	bool ok;

	tctx->call = NULL;
	ret = tstream_unix_connect_recv(subreq, &err, tctx, &tctx->stream);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		mds_truesearch_log_unreachable(tctx, "connect", err);
		mds_truesearch_disconnect(tctx, true);
		return;
	}

	ok = mds_truesearch_send_hello(tctx);
	if (!ok) {
		mds_truesearch_disconnect(tctx, true);
	}
}

static void mds_truesearch_welcome(struct mds_truesearch_ctx *tctx,
				const rix_outcome *outcome)
{
	const rix_welcome *w = NULL;

	if (outcome->status != RIX_OK) {
		DBG_ERR("truesearchd at %s refused RIX_HELLO: %s: %s\n",
			tctx->socket_path,
			rix_status_name(outcome->status),
			outcome->rix_outcome_u.detail);
		mds_truesearch_disconnect(tctx, true);
		return;
	}

	w = &outcome->rix_outcome_u.answer.rix_answer_u.welcome;
	if (w->vers != RIX_PROTO_VERSION || w->max_page == 0) {
		DBG_ERR("truesearchd at %s: bad version %u or page %u\n",
			tctx->socket_path, w->vers, w->max_page);
		mds_truesearch_disconnect(tctx, true);
		return;
	}

	tctx->page = MIN(SL_PAGESIZE, w->max_page);
	tctx->ready = true;

	DBG_DEBUG("truesearchd at %s: max_results %u, max_page %u, idle %u s\n",
		  tctx->socket_path,
		  w->max_results,
		  w->max_page,
		  w->handle_idle_seconds);
}

/*
 * Handle a refusal. No index and a bad scope give no results. Other
 * refusals fail the query.
 */
static void mds_truesearch_refused(struct mds_truesearch_search *s,
				rix_op op,
				const rix_outcome *outcome)
{
	struct sl_query *slq = s->slq;
	const char *detail = outcome->rix_outcome_u.detail;

	switch (outcome->status) {
	case RIX_NO_INDEX:
	case RIX_BAD_SCOPE:
		DBG_NOTICE("%s: %s: %s\n",
			   rix_op_name(op),
			   rix_status_name(outcome->status),
			   detail);
		slq->state = SLQ_STATE_DONE;
		mds_truesearch_release(s->tctx, s);
		break;
	case RIX_BAD_QUERY:
		DBG_INFO("%s: %s: %s: query [%s]\n",
			 rix_op_name(op),
			 rix_status_name(outcome->status),
			 detail,
			 slq->query_string);
		mds_truesearch_fail(s);
		break;
	case RIX_BAD_HANDLE:
		/* truesearchd released the handle */
		DBG_NOTICE("%s: %s: %s\n",
			   rix_op_name(op),
			   rix_status_name(outcome->status),
			   detail);
		s->open = false;
		mds_truesearch_fail(s);
		break;
	default:
		DBG_WARNING("%s: %s: %s\n",
			    rix_op_name(op),
			    rix_status_name(outcome->status),
			    detail);
		mds_truesearch_fail(s);
		break;
	}
}

static void mds_truesearch_opened(struct mds_truesearch_search *s,
			       const rix_outcome *outcome)
{
	struct mds_truesearch_ctx *tctx = s->tctx;
	const rix_opened *opened = NULL;

	if (outcome->status != RIX_OK) {
		mds_truesearch_refused(s, RIX_OPEN, outcome);
		return;
	}

	opened = &outcome->rix_outcome_u.answer.rix_answer_u.opened;
	s->open = true;
	s->handle = opened->handle;
	s->generation = tctx->generation;

	DBG_DEBUG("RIX_OPEN: handle %"PRIu64", %u ready%s\n",
		  s->handle,
		  opened->ready,
		  opened->truncated ? ", truncated" : "");

	if (opened->ready == 0) {
		s->slq->state = SLQ_STATE_DONE;
		mds_truesearch_release(tctx, s);
		return;
	}

	mds_truesearch_wait(s);
}

/*
 * Return true if a hit path is relative to the share root and has no
 * empty, "." or ".." component. "" is the share root.
 */
static bool mds_truesearch_path_ok(const char *path)
{
	const char *p = NULL;

	if (path == NULL || path[0] == '/') {
		return false;
	}
	p = path;
	while (*p != '\0') {
		const char *end = strchr(p, '/');
		size_t len = (end != NULL) ? (size_t)(end - p) : strlen(p);

		if (len == 0) {
			return false;
		}
		if (p[0] == '.' && (len == 1 || (len == 2 && p[1] == '.'))) {
			return false;
		}
		if (end == NULL) {
			break;
		}
		p = end + 1;
	}
	return true;
}

/*
 * Convert rix_stat to stat_ex. rix_stat has no device and no change time.
 * mdssvc reads neither.
 */
static void mds_truesearch_stat(const rix_stat *st, struct stat_ex *sb)
{
	*sb = (struct stat_ex) {
		.st_ex_ino = st->unix_meta.ino,
		.st_ex_gen = st->unix_meta.gen,
		.st_ex_mode = st->unix_meta.mode,
		.st_ex_uid = st->unix_meta.uid,
		.st_ex_gid = st->unix_meta.gid,
		.st_ex_size = st->size,
		.st_ex_atime = {
			.tv_sec = st->atime_sec,
			.tv_nsec = st->atime_nsec,
		},
		.st_ex_mtime = {
			.tv_sec = st->mtime_sec,
			.tv_nsec = st->mtime_nsec,
		},
		.st_ex_btime = {
			.tv_sec = st->btime_sec,
			.tv_nsec = st->btime_nsec,
		},
	};
}

static void mds_truesearch_page(struct mds_truesearch_search *s,
			     const rix_outcome *outcome)
{
	struct mds_truesearch_ctx *tctx = s->tctx;
	struct sl_query *slq = s->slq;
	const rix_page *page = NULL;
	u_int i;
	bool ok;

	if (outcome->status != RIX_OK) {
		mds_truesearch_refused(s, RIX_FETCH, outcome);
		return;
	}

	page = &outcome->rix_outcome_u.answer.rix_answer_u.page;

	for (i = 0; i < page->hits.hits_len; i++) {
		const rix_hit *hit = &page->hits.hits_val[i];
		struct stat_ex sb;
		size_t reply_len;
		char *path = NULL;
		uint64_t id;

		if (!mds_truesearch_path_ok(hit->path)) {
			DBG_ERR("hit path [%s] is not a valid relative path\n",
				hit->path != NULL ? hit->path : "");
			mds_truesearch_fail(s);
			return;
		}
		if (hit->path[0] == '\0') {
			/*
			 * Drop the share root. mdssvc would give it the name
			 * "", and marshalling.c cannot unpack an empty string.
			 */
			DBG_DEBUG("dropped the share root as a hit\n");
			continue;
		}
		if (hit->st == NULL) {
			DBG_ERR("hit [%s] has no stat\n",
				hit->path);
			mds_truesearch_fail(s);
			return;
		}
		/* Length of "/<share>/<path>" in the reply */
		reply_len = strlen(slq->mds_ctx->sharename) +
			    strlen(hit->path) + 2;
		if (reply_len > MDS_TRUESEARCH_PATH_MAX) {
			DBG_INFO("dropped a hit with a reply path of %zu "
				 "bytes, more than %u [%.64s...]\n",
				 reply_len,
				 (unsigned)MDS_TRUESEARCH_PATH_MAX,
				 hit->path);
			continue;
		}
		mds_truesearch_stat(hit->st, &sb);
		id = mds_truesearch_item_id(tctx, hit->st);

		/* mdssvc takes the share path joined with the hit path */
		if (strcmp(tctx->root, "/") == 0) {
			path = talloc_asprintf(s, "/%s", hit->path);
		} else {
			path = talloc_asprintf(s, "%s/%s", tctx->root,
					       hit->path);
		}
		if (path == NULL) {
			mds_truesearch_fail(s);
			return;
		}
		ok = mds_add_checked_result(slq, path, id, &sb);
		TALLOC_FREE(path);
		if (!ok) {
			mds_truesearch_fail(s);
			return;
		}
	}

	DBG_DEBUG("RIX_FETCH: %u hits, %d queued%s\n",
		  page->hits.hits_len,
		  slq->query_results->num_results,
		  page->more ? ", more" : "");

	if (!page->more) {
		slq->state = SLQ_STATE_DONE;
		mds_truesearch_release(tctx, s);
		return;
	}

	if (slq->query_results->num_results >= SL_PAGESIZE) {
		/* The client page is full. search_cont() asks for more. */
		slq->state = SLQ_STATE_FULL;
		return;
	}

	slq->state = SLQ_STATE_RESULTS;
	mds_truesearch_wait(s);
}

static void mds_truesearch_call_done(struct tevent_req *req)
{
	struct mds_truesearch_ctx *tctx = tevent_req_callback_data(
		req, struct mds_truesearch_ctx);
	struct mds_truesearch_search *s = tctx->call_search;
	rix_op op = tctx->call_op;
	rix_reply *reply = NULL;
	int err;

	tctx->call = NULL;
	tctx->call_search = NULL;

	err = rix_call_recv(req, tctx, &reply);
	TALLOC_FREE(req);
	if (err != 0) {
		mds_truesearch_log_unreachable(tctx, rix_op_name(op), err);
		if (op == RIX_HELLO) {
			mds_truesearch_disconnect(tctx, true);
			goto done;
		}
		if (op == RIX_OPEN && s->slq != NULL && !s->retried &&
		    mds_truesearch_broken(err))
		{
			/* Nothing was opened. Open again on a new connection. */
			s->retried = true;
			mds_truesearch_disconnect(tctx, false);
			DLIST_ADD(tctx->searches, s);
			s->waiting = true;
			goto done;
		}
		if (s != NULL) {
			mds_truesearch_fail(s);
		}
		mds_truesearch_disconnect(tctx, false);
		goto done;
	}

	switch (op) {
	case RIX_HELLO:
		mds_truesearch_welcome(tctx, &reply->outcome);
		break;
	case RIX_OPEN:
		if (s->slq == NULL) {
			/* The query was closed. Release the new handle. */
			if (reply->outcome.status == RIX_OK) {
				s->open = true;
				s->handle = reply->outcome.rix_outcome_u.
					answer.rix_answer_u.opened.handle;
				s->generation = tctx->generation;
			}
			break;
		}
		mds_truesearch_opened(s, &reply->outcome);
		break;
	case RIX_FETCH:
		if (s->slq == NULL) {
			break;
		}
		mds_truesearch_page(s, &reply->outcome);
		break;
	case RIX_CLOSE:
		if (reply->outcome.status != RIX_OK) {
			DBG_DEBUG("RIX_CLOSE: %s\n",
				  rix_status_name(reply->outcome.status));
		}
		break;
	}
	TALLOC_FREE(reply);

done:
	if (s != NULL && s->slq == NULL) {
		/* The query was closed during the call. Free the search. */
		mds_truesearch_release(tctx, s);
		talloc_set_destructor(s, NULL);
		TALLOC_FREE(s);
	}
	mds_truesearch_trigger(tctx);
}

static bool mdssvc_truesearch_init(struct mdssvc_ctx *mdssvc_ctx)
{
	return true;
}

static bool mdssvc_truesearch_shutdown(struct mdssvc_ctx *mdssvc_ctx)
{
	return true;
}

/*
 * Check that the user can read the share, as for a tree connect: the guest
 * rules, "valid users", "invalid users" and the share security descriptor.
 * The RPC call runs as the user. Only root can read the share database.
 */
static bool mds_truesearch_share_allowed(struct mds_ctx *mds_ctx)
{
	const struct auth_session_info *si = mds_ctx->pipe_session_info;
	const char *share = lp_const_servicename(mds_ctx->snum);
	int snum = mds_ctx->snum;
	bool ok;

	if (si->unix_info == NULL || si->info == NULL) {
		DBG_ERR("share [%s]: the session has no unix info\n", share);
		return false;
	}

	/*
	 * A tree connect refuses a guest session on a share without "guest
	 * ok", and maps every user to guest on a "guest only" share. The
	 * search runs as the session user, so the backend cannot become
	 * guest: refuse a "guest only" share, and refuse a guest session on
	 * a share without "guest ok".
	 */
	if (lp_guest_only(snum)) {
		DBG_NOTICE("share [%s] is guest only: search refused\n", share);
		return false;
	}
	if (security_session_user_level(si, NULL) < SECURITY_USER &&
	    !lp_guest_ok(snum)) {
		DBG_NOTICE("guest session may not search share [%s]\n", share);
		return false;
	}

	become_root();
	ok = user_ok_token(si->unix_info->unix_name,
			   si->info->domain_name,
			   si->security_token,
			   mds_ctx->snum);
	unbecome_root();
	if (!ok) {
		DBG_NOTICE("user [%s] may not use share [%s]\n",
			   si->unix_info->unix_name, share);
		return false;
	}

	become_root();
	ok = share_access_check(si->security_token,
				share,
				FILE_READ_DATA,
				NULL);
	unbecome_root();
	if (!ok) {
		DBG_NOTICE("user [%s] may not read share [%s]\n",
			   si->unix_info->unix_name, share);
		return false;
	}

	return true;
}

/*
 * Check that the user can reach the share root. truesearchd trims from the
 * share root down, so it does not check the directories above it. A tree
 * connect changes into the share path as the user, which needs search on
 * every directory above the root. Open the share path as the user with the
 * same requirement (O_PATH does not need read on the root itself).
 */
static bool mds_truesearch_can_reach(struct mds_ctx *mds_ctx)
{
	const struct auth_session_info *si = mds_ctx->pipe_session_info;
	const char *share = lp_const_servicename(mds_ctx->snum);
	int fd;
	int err;

	if (!become_authenticated_pipe_user(mds_ctx->pipe_session_info)) {
		DBG_ERR("share [%s]: cannot become the session user\n", share);
		return false;
	}
	fd = open(mds_ctx->spath, O_PATH | O_DIRECTORY | O_CLOEXEC);
	err = errno;
	unbecome_authenticated_pipe_user();
	if (fd == -1) {
		DBG_NOTICE("user [%s] cannot reach share path [%s]: %s\n",
			   si->unix_info->unix_name,
			   mds_ctx->spath,
			   strerror(err));
		return false;
	}
	close(fd);
	return true;
}

/*
 * Find the share root for RIX_OPEN. The dataset is the source of the mount
 * of the real path. The path in the dataset is the mount root, then the
 * part of the real path under the mount point. Run as root, because the
 * user cannot always access all directories in the path.
 */
static bool mds_truesearch_locate(struct mds_truesearch_ctx *tctx,
				  const char *path)
{
	struct tn_mount_entry *entry = NULL;
	const char *in_mount = NULL;
	const char *in_root = NULL;
	const char *sep = NULL;
	char *real = NULL;
	int ret = -1;
	int err = 0;

	become_root();
	real = realpath(path, NULL);
	if (real != NULL) {
		ret = tn_mount_entry_get_path(tctx, real, &entry);
	}
	err = errno;
	unbecome_root();
	if (ret != 0) {
		DBG_ERR("cannot find the mount of share path [%s]: %s\n",
			path,
			strerror(err));
		SAFE_FREE(real);
		return false;
	}
	if (entry->sb_source == NULL || entry->mnt_point == NULL ||
	    entry->mnt_root == NULL ||
	    !subdir_of(entry->mnt_point,
		       strlen(entry->mnt_point),
		       real,
		       &in_mount)) {
		DBG_ERR("the mount of share path [%s] has no source or "
			"root\n",
			real);
		TALLOC_FREE(entry);
		SAFE_FREE(real);
		return false;
	}
	in_root = entry->mnt_root;
	while (*in_root == '/') {
		in_root++;
	}
	sep = (in_root[0] != '\0' && in_mount[0] != '\0') ? "/" : "";
	tctx->dataset = talloc_strdup(tctx, entry->sb_source);
	tctx->share = talloc_asprintf(tctx, "%s%s%s", in_root, sep, in_mount);
	TALLOC_FREE(entry);
	SAFE_FREE(real);
	return tctx->dataset != NULL && tctx->share != NULL;
}

static bool mds_truesearch_connect_ctx(struct mds_ctx *mds_ctx)
{
	struct mds_truesearch_ctx *tctx = NULL;
	const char *socket_path = NULL;
	char *root = NULL;
	size_t len;
	int max;
	bool ok;

	ok = mds_truesearch_share_allowed(mds_ctx);
	if (!ok) {
		return false;
	}

	tctx = talloc_zero(mds_ctx, struct mds_truesearch_ctx);
	if (tctx == NULL) {
		return false;
	}

	socket_path = lp_parm_const_string(mds_ctx->snum,
					   "truesearch",
					   "socket",
					   MDS_TRUESEARCH_SOCKET);

	root = talloc_strdup(tctx, mds_ctx->spath);
	if (root == NULL) {
		TALLOC_FREE(tctx);
		return false;
	}
	len = strlen(root);
	while (len > 1 && root[len - 1] == '/') {
		root[--len] = '\0';
	}

	max = lp_parm_int(mds_ctx->snum,
			  "truesearch",
			  "max results",
			  MAX_SL_RESULTS);
	if (max < 0) {
		max = MAX_SL_RESULTS;
	}

	*tctx = (struct mds_truesearch_ctx) {
		.mds_ctx = mds_ctx,
		.ev = mds_ctx->mdssvc_ctx->ev_ctx,
		.socket_path = talloc_strdup(tctx, socket_path),
		.root = root,
		/*
		 * Always hide unreadable hits, as every mdssvc backend only
		 * returns files the user can read. truesearchd also forces
		 * this for a query that matches on a value a listing does not
		 * show (content, metadata, the Finder streams, the owner).
		 */
		.flags = RIX_OPEN_TRIM_BY_IDENTITY | RIX_OPEN_WANT_STAT |
			 RIX_OPEN_HIDE_UNREADABLE,
		.max_results = MIN((uint32_t)max, (uint32_t)RIX_MAX_RESULTS),
		.page = SL_PAGESIZE,
		.zfs_file_ids = str_list_check(lp_vfs_objects(mds_ctx->snum),
					       "zfs_core"),
	};
	if (tctx->socket_path == NULL) {
		TALLOC_FREE(tctx);
		return false;
	}
	if (!mds_truesearch_locate(tctx, root)) {
		TALLOC_FREE(tctx);
		return false;
	}
	if (!mds_truesearch_can_reach(mds_ctx)) {
		TALLOC_FREE(tctx);
		return false;
	}
	talloc_set_destructor(tctx, mds_truesearch_ctx_destructor);
	mds_ctx->backend_private = tctx;

	DBG_DEBUG("share [%s] at [%s] in [%s], truesearchd at %s, flags 0x%x\n",
		  mds_ctx->sharename,
		  tctx->share,
		  tctx->dataset,
		  tctx->socket_path,
		  tctx->flags);
	return true;
}

static bool mds_truesearch_search_start(struct sl_query *slq)
{
	struct mds_truesearch_ctx *tctx = talloc_get_type_abort(
		slq->mds_ctx->backend_private, struct mds_truesearch_ctx);
	struct mds_truesearch_search *s = NULL;

	s = talloc_zero(tctx, struct mds_truesearch_search);
	if (s == NULL) {
		return false;
	}
	s->tctx = tctx;
	s->slq = slq;
	talloc_set_destructor(s, mds_truesearch_search_destructor);

	slq->backend_private = s;
	slq->state = SLQ_STATE_RUNNING;

	mds_truesearch_wait(s);
	mds_truesearch_trigger(tctx);
	return true;
}

static bool mds_truesearch_search_cont(struct sl_query *slq)
{
	struct mds_truesearch_search *s = talloc_get_type_abort(
		slq->backend_private, struct mds_truesearch_search);

	mds_truesearch_wait(s);
	mds_truesearch_trigger(s->tctx);
	return true;
}

struct mdssvc_backend mdsscv_backend_truesearch = {
	.no_vfs_conn = true,
	.init = mdssvc_truesearch_init,
	.shutdown = mdssvc_truesearch_shutdown,
	.connect = mds_truesearch_connect_ctx,
	.search_start = mds_truesearch_search_start,
	.search_cont = mds_truesearch_search_cont,
};
