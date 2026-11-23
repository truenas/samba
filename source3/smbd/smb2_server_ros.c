/*
   Unix SMB/CIFS implementation.
   TrueNAS: truenas_ros reactors as the transport of SMB2

   Copyright (C) iXsystems, Inc. 2026

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
#include "system/network.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "source3/smbd/smbXsrv_session.h"
#include "../libcli/smb/smb_common.h"
#include "smbd/smb2_server_ros.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

/*
 * TrueNAS: a truenas_ros reactor does the socket I/O of a channel. This is
 * the default. "truenas:ros transport = no" turns the reactors off. Then
 * smbd does all of the I/O, as Samba does. A reactor is a thread with its
 * own io_uring ring. It reads whole PDUs and queues them for smbd. The
 * reactors of a process share one queue and one eventfd. A reactor sends
 * the PDUs that smbd gives it. truenas_rust/mit/smbros has the reactors.
 * truenas_rust/gpl/smb-server has the SMB2 code that they run for smbd.
 */

/*
 * smbd lends vectors of this size or larger to the reactor, such as read
 * data. The reactor copies smaller vectors. Only replies have such large
 * vectors. smbd_smb2_request_destructor() does not free lent memory before
 * TN_SMBROS_SENT.
 */
#define SMBD_SMB2_ROS_LEND_MIN (64 * 1024)

/* A reactor reads at most this many PDUs ahead of smbd. */
#define SMBD_SMB2_ROS_MAX_IN_FLIGHT 16

/*
 * The default of "truenas:ros async read size" flags every READ. Without
 * the flag, one io-wq worker ran the hot reads that ZFS decompresses.
 * Forced reads then gained 27% to 56% on one channel at 1 to 8 MiB.
 */
#define SMBD_SMB2_ROS_ASYNC_READ_SIZE 1

/*
 * The default of "truenas:ros async write size" flags no WRITE. Forced
 * writes to one file on one channel gained 26% to 35% on an SSD pool when
 * the bench rewrote the same 2 GiB, and 4% to 6% on a RAM pool. On four
 * channels under sustained load on the RAM pool, they lost 6%.
 */
#define SMBD_SMB2_ROS_ASYNC_WRITE_SIZE 0

/*
 * The default of "truenas:ros zero copy size" is the default floor of
 * truenas_ros. 0 copies every reply.
 */
#define SMBD_SMB2_ROS_ZERO_COPY_SIZE (64 * 1024)

struct smbd_smb2_ros_buf {
	void *buf;
	/* The PDU after the NBT header. It points into buf. */
	const uint8_t *data;
	size_t len;
};

static int smbd_smb2_ros_buf_destructor(struct smbd_smb2_ros_buf *rb)
{
	tn_smbros_buf_free(rb->buf);
	return 0;
}

NTSTATUS smbd_smb2_ros_incoming(struct smbXsrv_connection *xconn,
				const struct tn_smbros_event *ev)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct smbd_smb2_request *req = NULL;
	struct smbd_smb2_ros_buf *rb = NULL;
	NTTIME now;
	NTSTATUS status;

	if (ev->nbt_type != 0x00) {
		DEBUG(1,("ignore NBT[0x%02X] msg\n", ev->nbt_type));
		tn_smbros_buf_free(ev->buf);
		return NT_STATUS_OK;
	}

	req = smbd_smb2_request_allocate(xconn);
	if (req == NULL) {
		tn_smbros_buf_free(ev->buf);
		return NT_STATUS_NO_MEMORY;
	}

	/* req owns the PDU buffer of the reactor. */
	rb = talloc(req, struct smbd_smb2_ros_buf);
	if (rb == NULL) {
		tn_smbros_buf_free(ev->buf);
		return NT_STATUS_NO_MEMORY;
	}
	rb->buf = ev->buf;
	rb->data = ev->data;
	rb->len = ev->len;
	talloc_set_destructor(rb, smbd_smb2_ros_buf_destructor);
	req->ros_buf = rb;
	req->ros_crypto = ev->flags;
	req->ros_crypto_status = ev->status;
	req->ros_crypto_gen = ev->tag;

	req->request_time = timeval_current();
	now = timeval_to_nttime(&req->request_time);

	status = smbd_smb2_inbuf_parse_compound(xconn,
						now,
						ev->data,
						ev->len,
						req,
						&req->in.vector,
						&req->in.vector_count);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	req->current_idx = 1;

	status = smbd_smb2_request_validate(req);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_smb2_request_setup_out(req);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sconn->num_requests++;

	if ((sconn->num_requests % 50) == 0 &&
	    need_to_check_log_size()) {
		change_to_root_user();
		check_log_size();
	}

	return NT_STATUS_OK;
}

/*
 * The reactor no longer uses the memory of e. Remove e from the send queue
 * as smbd_smb2_advance_send_queue() does.
 */
static void smbd_smb2_ros_sent(struct smbd_smb2_send_queue *e)
{
	struct smbXsrv_connection *xconn = e->ros.xconn;

	SMB_ASSERT(e->ros.lent);
	e->ros.lent = false;

	if (xconn == NULL) {
		/* smbd freed the owner of e while the reactor sent from e. */
		talloc_free(e->mem_ctx);
		return;
	}

	if (!NT_STATUS_IS_OK(xconn->transport.status)) {
		/*
		 * smbXsrv_connection_disconnect_transport() already removed e
		 * from the send queue.
		 */
		talloc_free(e->mem_ctx);
		return;
	}

	xconn->smb2.send_queue_len--;
	DLIST_REMOVE(xconn->smb2.send_queue, e);

	if (e->ack.req == NULL) {
		talloc_free(e->mem_ctx);
		return;
	}

	e->ack.required_acked_bytes = e->ros.acked_bytes;
	DLIST_ADD_END(xconn->ack.queue, e);
}

/*
 * The reactors do file I/O on the descriptor of this open file.
 * smbd_smb2_ros_file_close() waits for that I/O to end.
 */
struct smbd_smb2_ros_file {
	struct tn_smbsrv_file *file;
	/* The descriptor that file uses. */
	int fd;
	/* The parent of a wait that blocks a CLOSE until TN_SMBSRV_IDLE. */
	TALLOC_CTX *idle_wait;
};

static int smbd_smb2_ros_file_destructor(struct smbd_smb2_ros_file *rf)
{
	/* This blocks until the file I/O of the reactors ends. */
	tn_smbsrv_file_close(rf->file, NULL);
	return 0;
}

/* The reactors ended the file I/O that a CLOSE waits for. */
static void smbd_smb2_ros_idle(struct smbd_smb2_ros_file *rf)
{
	TALLOC_FREE(rf->idle_wait);
}

static void smbd_smb2_ros_handler(struct tevent_context *ev,
				  struct tevent_fd *fde,
				  uint16_t flags,
				  void *private_data)
{
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);
	struct tn_smbros_event e;

	/*
	 * A reactor wakes smbd only when it adds an event to an empty queue.
	 * So smbd clears the eventfd before it reads the whole queue.
	 */
	tn_smbros_ctx_ack(sconn->ros_ctx);

	smbd_smb2_ros_inline_terminate(sconn);
	smbd_smb2_ros_trash_empty();

	while (tn_smbros_next(sconn->ros_ctx, &e)) {
		struct smbXsrv_connection *xconn = NULL;
		NTSTATUS status;

		if (e.kind == TN_SMBROS_SENT) {
			smbd_smb2_ros_sent(
				(struct smbd_smb2_send_queue *)(uintptr_t)e.cookie);
			continue;
		}

		if (e.kind == TN_SMBSRV_IDLE) {
			smbd_smb2_ros_idle(
				(struct smbd_smb2_ros_file *)(uintptr_t)e.cookie);
			continue;
		}

		if (e.kind == TN_SMBSRV_KEY_FREE) {
			/* A key copy from smbd_smb2_ros_keys_sync(). */
			struct smb2_signing_key *key = e.buf;

			TALLOC_FREE(key);
			continue;
		}

		xconn = (struct smbXsrv_connection *)(uintptr_t)e.cookie;

		if (e.kind == TN_SMBROS_CLOSED) {
			status = NT_STATUS_END_OF_FILE;
			if (e.error != 0) {
				status = map_nt_error_from_unix_common(e.error);
			}
			smbXsrv_connection_disconnect_transport(xconn, status);
			smbd_server_connection_terminate(xconn,
							 nt_errstr(status));
			continue;
		}

		status = smbd_smb2_ros_incoming(xconn, &e);
		if (!NT_STATUS_IS_OK(status)) {
			smbd_server_connection_terminate(xconn,
							 nt_errstr(status));
		}
	}
}

/*
 * True if the reactor can do the file I/O of req. smbd does the I/O of a
 * compound itself, because the reactor sends one reply per PDU.
 */
bool smbd_smb2_ros_delegable(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;

	if (xconn->smb2.ros.conn == NULL) {
		return false;
	}
	if (req->ros_buf == NULL ||
	    !tn_smbros_buf_delegable(req->ros_buf->buf)) {
		return false;
	}
	if (smbd_smb2_is_compound(req)) {
		return false;
	}
	/* The reactor does not call the VFS modules. */
	return smbd_vfs_plain_rw(req->tcon->compat);
}

/* The reactor gets no job for req. It can read the next PDUs. */
void smbd_smb2_ros_release(struct smbd_smb2_request *req)
{
	if (req->ros_buf != NULL) {
		tn_smbros_buf_release(req->ros_buf->buf);
	}
}

/*
 * True if fsp has jobs whose file I/O did not end. A CLOSE then waits for
 * them with smbd_smb2_ros_file_block().
 */
bool smbd_smb2_ros_file_busy(struct files_struct *fsp)
{
	if (fsp->ros_file == NULL) {
		return false;
	}
	return tn_smbsrv_file_busy(fsp->ros_file->file);
}

/*
 * Block queue until the file I/O of the reactors on fsp ends. Call this
 * after smbd_smb2_ros_file_busy() returned true.
 */
bool smbd_smb2_ros_file_block(struct files_struct *fsp,
			      struct tevent_context *ev,
			      struct tevent_queue *queue)
{
	struct smbd_smb2_ros_file *rf = fsp->ros_file;
	struct tevent_req *subreq = NULL;

	if (rf->idle_wait == NULL) {
		rf->idle_wait = talloc_new(rf);
		if (rf->idle_wait == NULL) {
			return false;
		}
	}

	/*
	 * The wait has no callback. TN_SMBSRV_IDLE frees idle_wait. That free
	 * removes the wait from the queue.
	 */
	subreq = tevent_queue_wait_send(rf->idle_wait, ev, queue);
	return (subreq != NULL);
}

/*
 * After this call, the reactors do not use the descriptor of fsp. The call
 * blocks until their file I/O on fsp ends. Only a teardown blocks, because
 * a CLOSE waits for that I/O first. The reactor answers a job that it gets
 * later with NT_STATUS_FILE_CLOSED.
 */
void smbd_smb2_ros_file_close(struct files_struct *fsp)
{
	struct smbd_smb2_ros_file *rf = fsp->ros_file;
	uint64_t pos;

	if (rf == NULL) {
		return;
	}
	fh_set_position_source(fsp->fh, NULL, NULL);
	/* The last delegated read sets the position of the open. */
	if (tn_smbsrv_file_close(rf->file, &pos)) {
		fh_set_pos(fsp->fh, pos);
		fh_set_position_information(fsp->fh, pos);
	}
	talloc_set_destructor(rf, NULL);
	TALLOC_FREE(fsp->ros_file);
}

/*
 * A delegated read moves the position of the open. The fd handle calls
 * this when smbd reads or sets the position. See fh_set_position_source().
 */
static bool smbd_smb2_ros_file_take_pos(void *private_data, uint64_t *pos)
{
	struct smbd_smb2_ros_file *rf = private_data;

	return tn_smbsrv_file_take_pos(rf->file, pos);
}

/*
 * Return the number of jobs of fsp that count as outstanding requests of
 * older channel sequences. See smbd_smb2_request_dispatch_update_counts().
 */
uint32_t smbd_smb2_ros_file_seq_old(struct files_struct *fsp)
{
	if (fsp->ros_file == NULL) {
		return 0;
	}
	return tn_smbsrv_file_seq_old(fsp->ros_file->file);
}

void smbd_smb2_ros_file_seq_bump(struct files_struct *fsp)
{
	if (fsp->ros_file != NULL) {
		tn_smbsrv_file_seq_bump(fsp->ros_file->file);
	}
}

/*
 * Count the job of req as an outstanding request of the open until its
 * file I/O ends. current is true for the current channel sequence.
 */
void smbd_smb2_ros_job_keeps_count(struct smbd_smb2_request *req,
				   bool current)
{
	struct smbd_smb2_ros_job *job = req->queue_entry.ros.job;

	if (job != NULL && job->hold != NULL) {
		tn_smbsrv_hold_seq(job->hold, current);
	}
}

static struct smbd_smb2_ros_file *smbd_smb2_ros_file_get(
	struct smbd_server_connection *sconn,
	struct files_struct *fsp,
	int fd)
{
	struct smbd_smb2_ros_file *rf = fsp->ros_file;

	if (rf != NULL) {
		/* rf is for one descriptor only. */
		return (rf->fd == fd) ? rf : NULL;
	}

	rf = talloc_zero(fsp, struct smbd_smb2_ros_file);
	if (rf == NULL) {
		return NULL;
	}
	rf->file = tn_smbsrv_file_new(sconn->ros_ctx,
				      fd,
				      (uint64_t)(uintptr_t)rf);
	if (rf->file == NULL) {
		TALLOC_FREE(rf);
		return NULL;
	}
	rf->fd = fd;
	talloc_set_destructor(rf, smbd_smb2_ros_file_destructor);
	fsp->ros_file = rf;
	/* smbd_smb2_ros_file_close() removes the source. */
	fh_set_position_source(fsp->fh, smbd_smb2_ros_file_take_pos, rf);
	return rf;
}

static int smbd_smb2_ros_job_destructor(struct smbd_smb2_ros_job *job)
{
	/* A job that smbd did not give to the reactor still has these. */
	tn_smbsrv_hold_free(job->hold);
	tn_smbsrv_keys_unpin(job->keys);
	return 0;
}

/*
 * smbd's record of the keys that the reactor of a channel has for one
 * session. Each reactor gets its own copies, because a key caches GnuTLS
 * handles. smbd frees the copies on its main thread after TN_SMBSRV_KEY_FREE.
 *
 * The record has no key material. Each pointer is a key of smbd that the
 * reactor has a copy of, or NULL. smbd never changes a key after it makes
 * it. It makes the keys of a session when the session authenticates, and
 * the signing key of a channel when the channel binds. It frees them with
 * the session, after smbXsrv_session_logoff() dropped this record. So a
 * pointer identifies a key. smbd only compares these pointers. It never
 * reads a key through them.
 */
struct smbd_smb2_ros_keys {
	struct smbd_smb2_ros_keys *prev, *next;
	uint64_t session_id;
	uint64_t generation;
	const struct smb2_signing_key *sign;
	const struct smb2_signing_key *encrypt;
	const struct smb2_signing_key *decrypt;
};

static void smbd_smb2_ros_crypto_thread(void)
{
	/* Nothing in lib/util/debug.c is thread safe. */
	debug_thread_set_quiet(true);
}

static uint32_t smbd_smb2_ros_sign(void *key, struct iovec *iov, int iovcnt)
{
	return NT_STATUS_V(smb2_signing_sign_pdu(key, iov, iovcnt));
}

static uint32_t smbd_smb2_ros_check(void *key, struct iovec *iov, int iovcnt)
{
	return NT_STATUS_V(smb2_signing_check_pdu(key, iov, iovcnt));
}

static uint32_t smbd_smb2_ros_encrypt(void *key, struct iovec *iov, int iovcnt)
{
	return NT_STATUS_V(smb2_signing_encrypt_pdu(key, iov, iovcnt));
}

static uint32_t smbd_smb2_ros_decrypt(void *key, struct iovec *iov, int iovcnt)
{
	return NT_STATUS_V(smb2_signing_decrypt_pdu(key, iov, iovcnt));
}

static const struct tn_smbsrv_crypto smbd_smb2_ros_crypto = {
	.thread_init = smbd_smb2_ros_crypto_thread,
	.sign = smbd_smb2_ros_sign,
	.check = smbd_smb2_ros_check,
	.encrypt = smbd_smb2_ros_encrypt,
	.decrypt = smbd_smb2_ros_decrypt,
};

/* The pointer that a record keeps for key: key, or NULL for a missing key. */
static const struct smb2_signing_key *smbd_smb2_ros_key_ref(
	const struct smb2_signing_key *key)
{
	return smb2_signing_key_valid(key) ? key : NULL;
}

/*
 * True if the reactor has a copy of key. ref is the pointer of a record.
 * A missing key and NULL are the same.
 */
static bool smbd_smb2_ros_key_same(const struct smb2_signing_key *ref,
				   const struct smb2_signing_key *key)
{
	return ref == smbd_smb2_ros_key_ref(key);
}

/* Set *copy to a copy of key on mem_ctx, or to NULL for a missing key. */
static NTSTATUS smbd_smb2_ros_key_copy(TALLOC_CTX *mem_ctx,
				       const struct smb2_signing_key *key,
				       struct smb2_signing_key **copy)
{
	*copy = NULL;
	if (!smb2_signing_key_valid(key)) {
		return NT_STATUS_OK;
	}
	return smb2_signing_key_copy(mem_ctx, key, copy);
}

static struct smbd_smb2_ros_keys *smbd_smb2_ros_keys_find(
	struct smbXsrv_connection *xconn,
	uint64_t session_id)
{
	struct smbd_smb2_ros_keys *k = NULL;

	for (k = xconn->smb2.ros.keys; k != NULL; k = k->next) {
		if (k->session_id == session_id) {
			return k;
		}
	}
	return NULL;
}

/*
 * Free k and drop its keys in the reactor. smbd_smb2_ros_decrypted() then
 * fails a PDU that the reactor decrypted with these keys. The keys of a
 * session change only when a new session gets its id.
 */
static void smbd_smb2_ros_keys_free(struct smbXsrv_connection *xconn,
				    struct smbd_smb2_ros_keys *k)
{
	if (xconn->smb2.ros.conn != NULL) {
		tn_smbsrv_session_drop(xconn->smb2.ros.conn, k->session_id);
	}
	DLIST_REMOVE(xconn->smb2.ros.keys, k);
	TALLOC_FREE(k);
}

/*
 * Give the reactor of xconn the keys that smbd uses for session x. The
 * reactor gets copies the first time and after a change. Return the
 * record of the keys, or NULL if the reactor cannot have them.
 */
struct smbd_smb2_ros_keys *smbd_smb2_ros_keys_sync(
	struct smbXsrv_connection *xconn,
	struct smbXsrv_session *x)
{
	static uint64_t generation;
	struct smbd_server_connection *sconn = xconn->client->sconn;
	struct smbd_smb2_ros_keys *k = NULL;
	struct smb2_signing_key *sign = NULL;
	struct smb2_signing_key *encrypt = x->global->encryption_key;
	struct smb2_signing_key *decrypt = x->global->decryption_key;
	struct smb2_signing_key *rsign = NULL;
	struct smb2_signing_key *rencrypt = NULL;
	struct smb2_signing_key *rdecrypt = NULL;
	bool has_channel = false;
	NTSTATUS status;
	int ret;

	if (xconn->smb2.ros.conn == NULL) {
		return NULL;
	}
	/*
	 * This session logged off. smbXsrv_session_logoff() dropped its
	 * keys in the reactors. smbd signs its last replies itself.
	 */
	if (x->table == NULL) {
		return NULL;
	}

	/*
	 * The reactor gets the signing key of a bound channel only. That
	 * key does not change.
	 */
	sign = smbd_smb2_signing_key(x, xconn, &has_channel);
	if (!has_channel) {
		sign = NULL;
	}

	k = smbd_smb2_ros_keys_find(xconn, x->global->session_wire_id);
	if (k != NULL &&
	    smbd_smb2_ros_key_same(k->sign, sign) &&
	    smbd_smb2_ros_key_same(k->encrypt, encrypt) &&
	    smbd_smb2_ros_key_same(k->decrypt, decrypt))
	{
		return k;
	}
	if (k != NULL) {
		smbd_smb2_ros_keys_free(xconn, k);
	}
	if (!smb2_signing_key_valid(sign) &&
	    !smb2_signing_key_valid(encrypt) &&
	    !smb2_signing_key_valid(decrypt))
	{
		return NULL;
	}

	k = talloc_zero(xconn, struct smbd_smb2_ros_keys);
	if (k == NULL) {
		return NULL;
	}
	k->session_id = x->global->session_wire_id;
	k->sign = smbd_smb2_ros_key_ref(sign);
	k->encrypt = smbd_smb2_ros_key_ref(encrypt);
	k->decrypt = smbd_smb2_ros_key_ref(decrypt);
	DLIST_ADD(xconn->smb2.ros.keys, k);

	/*
	 * sconn->ros_owner owns the copies of the reactor. The reactor can
	 * use them after smbd frees xconn, until TN_SMBSRV_KEY_FREE.
	 */
	status = smbd_smb2_ros_key_copy(sconn->ros_owner, sign, &rsign);
	if (NT_STATUS_IS_OK(status)) {
		status = smbd_smb2_ros_key_copy(sconn->ros_owner, encrypt, &rencrypt);
	}
	if (NT_STATUS_IS_OK(status)) {
		status = smbd_smb2_ros_key_copy(sconn->ros_owner, decrypt, &rdecrypt);
	}
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(rsign);
		TALLOC_FREE(rencrypt);
		TALLOC_FREE(rdecrypt);
		smbd_smb2_ros_keys_free(xconn, k);
		return NULL;
	}

	generation += 1;
	ret = tn_smbsrv_session_keys(xconn->smb2.ros.conn,
				     k->session_id,
				     generation,
				     rsign,
				     rencrypt,
				     rdecrypt);
	if (ret != 0) {
		/* smbd frees the copies on TN_SMBSRV_KEY_FREE events. */
		smbd_smb2_ros_keys_free(xconn, k);
		return NULL;
	}
	k->generation = generation;
	return k;
}

/* Drop the keys of session_id in the reactors of client. */
void smbd_smb2_ros_keys_drop(struct smbXsrv_client *client,
			     uint64_t session_id)
{
	struct smbXsrv_connection *xconn = NULL;

	for (xconn = client->connections; xconn != NULL; xconn = xconn->next) {
		struct smbd_smb2_ros_keys *k =
			smbd_smb2_ros_keys_find(xconn, session_id);

		if (k != NULL) {
			smbd_smb2_ros_keys_free(xconn, k);
		}
	}
}

/*
 * Return the status of the decryption that the reactor did for the PDU of
 * req. s is the session of the PDU on req->xconn, or NULL. Return
 * NT_STATUS_ACCESS_DENIED if smbd no longer uses the keys of the reactor
 * for s.
 */
NTSTATUS smbd_smb2_ros_decrypted(struct smbd_smb2_request *req,
				 struct smbXsrv_session *s)
{
	struct smbd_smb2_ros_keys *k = NULL;

	if (s != NULL) {
		k = smbd_smb2_ros_keys_find(req->xconn,
					    s->global->session_wire_id);
	}
	if (k == NULL ||
	    k->generation != req->ros_crypto_gen ||
	    k->decrypt == NULL ||
	    !smbd_smb2_ros_key_same(k->decrypt, s->global->decryption_key))
	{
		return NT_STATUS_ACCESS_DENIED;
	}
	if (req->ros_crypto & TN_SMBSRV_DECRYPT_FAILED) {
		return NT_STATUS(req->ros_crypto_status);
	}
	return NT_STATUS_OK;
}

/*
 * True if the reactor verified the signature of the current message with
 * signing_key. The reactor checks a PDU with the keys of one session. So
 * x must be that session.
 */
bool smbd_smb2_ros_signed_ok(struct smbd_smb2_request *req,
			     struct smbXsrv_session *x,
			     struct smb2_signing_key *signing_key)
{
	struct smbd_smb2_ros_keys *k = NULL;

	if (!(req->ros_crypto & TN_SMBSRV_SIGNED_OK)) {
		return false;
	}
	k = smbd_smb2_ros_keys_find(req->xconn, x->global->session_wire_id);
	return k != NULL &&
	       k->generation == req->ros_crypto_gen &&
	       k->sign != NULL &&
	       smbd_smb2_ros_key_same(k->sign, signing_key);
}

/*
 * Return a reference to the keys of session x in the reactor of xconn.
 * The reactor signs or encrypts one PDU with it, as seal says. Return NULL
 * if the reactor does not have the key that smbd uses.
 */
static struct tn_smbsrv_keys *smbd_smb2_ros_keys_pin(
	struct smbXsrv_connection *xconn,
	struct smbXsrv_session *x,
	int seal)
{
	struct smbd_smb2_ros_keys *k = NULL;

	if (x == NULL) {
		return NULL;
	}
	k = smbd_smb2_ros_keys_sync(xconn, x);
	if (k == NULL) {
		return NULL;
	}
	if (seal == TN_SMBSRV_SEAL_SIGN && k->sign == NULL) {
		return NULL;
	}
	if (seal == TN_SMBSRV_SEAL_ENCRYPT && k->encrypt == NULL) {
		return NULL;
	}
	return tn_smbsrv_keys_pin(xconn->smb2.ros.conn,
				  k->session_id,
				  k->generation);
}

/*
 * The reactor signs or encrypts a reply of smbd with these keys before it
 * sends the reply. It encrypts the whole reply, or it signs some of its
 * messages.
 */
struct smbd_smb2_ros_reply_seal {
	struct tn_smbsrv_keys *encrypt;
	struct tn_smbsrv_sign_part *sign;
	size_t num_sign;
};

static void smbd_smb2_ros_reply_seal_unsign(
	struct smbd_smb2_ros_reply_seal *seal)
{
	size_t i;

	for (i = 0; i < seal->num_sign; i++) {
		tn_smbsrv_keys_unpin(seal->sign[i].keys);
	}
	seal->num_sign = 0;
}

static int smbd_smb2_ros_reply_seal_destructor(
	struct smbd_smb2_ros_reply_seal *seal)
{
	tn_smbsrv_keys_unpin(seal->encrypt);
	smbd_smb2_ros_reply_seal_unsign(seal);
	return 0;
}

static struct smbd_smb2_ros_reply_seal *smbd_smb2_ros_reply_seal_get(
	struct smbd_smb2_request *req)
{
	if (req->ros_seal == NULL) {
		req->ros_seal = talloc_zero(req,
					    struct smbd_smb2_ros_reply_seal);
		if (req->ros_seal == NULL) {
			return NULL;
		}
		talloc_set_destructor(req->ros_seal,
				      smbd_smb2_ros_reply_seal_destructor);
	}
	return req->ros_seal;
}

/*
 * True if the reactor can sign or encrypt the message of req at idx. smbd
 * signs and encrypts NEGOTIATE and SESSION_SETUP replies itself. These
 * replies update the preauth hash and use keys of their own.
 */
static bool smbd_smb2_ros_reply_offload(struct smbd_smb2_request *req,
					int idx)
{
	const uint8_t *outhdr = SMBD_SMB2_IDX_HDR_IOV(req, out, idx)->iov_base;
	uint16_t opcode = SVAL(outhdr, SMB2_HDR_OPCODE);

	return req->xconn->smb2.ros.conn != NULL &&
	       req->preauth == NULL &&
	       opcode != SMB2_OP_NEGPROT &&
	       opcode != SMB2_OP_SESSSETUP;
}

/*
 * Let the reactor encrypt a PDU of session x, such as an interim
 * response. The PDU already has its transform header with the nonce.
 * Return NULL if smbd must encrypt the PDU itself.
 */
struct smbd_smb2_ros_reply_seal *smbd_smb2_ros_seal_encrypt(
	TALLOC_CTX *mem_ctx,
	struct smbXsrv_connection *xconn,
	struct smbXsrv_session *x,
	uint16_t opcode)
{
	struct smbd_smb2_ros_reply_seal *seal = NULL;

	if (xconn->smb2.ros.conn == NULL ||
	    opcode == SMB2_OP_NEGPROT ||
	    opcode == SMB2_OP_SESSSETUP)
	{
		return NULL;
	}
	seal = talloc_zero(mem_ctx, struct smbd_smb2_ros_reply_seal);
	if (seal == NULL) {
		return NULL;
	}
	talloc_set_destructor(seal, smbd_smb2_ros_reply_seal_destructor);
	seal->encrypt = smbd_smb2_ros_keys_pin(xconn,
					       x,
					       TN_SMBSRV_SEAL_ENCRYPT);
	if (seal->encrypt == NULL) {
		TALLOC_FREE(seal);
	}
	return seal;
}

/*
 * Let the reactor sign the message of req at idx. It uses the signing key
 * of the session of req. False if smbd must sign the message itself.
 */
bool smbd_smb2_ros_reply_sign(struct smbd_smb2_request *req, int idx)
{
	struct smbd_smb2_ros_reply_seal *seal = NULL;
	struct tn_smbsrv_sign_part *sign = NULL;
	struct tn_smbsrv_keys *keys = NULL;

	if (!smbd_smb2_ros_reply_offload(req, idx)) {
		return false;
	}
	seal = smbd_smb2_ros_reply_seal_get(req);
	if (seal == NULL) {
		return false;
	}
	sign = talloc_realloc(seal,
			      seal->sign,
			      struct tn_smbsrv_sign_part,
			      seal->num_sign + 1);
	if (sign == NULL) {
		return false;
	}
	seal->sign = sign;
	keys = smbd_smb2_ros_keys_pin(req->xconn,
				      req->session,
				      TN_SMBSRV_SEAL_SIGN);
	if (keys == NULL) {
		return false;
	}
	/* Like smbd, the reactor signs the header, body and dynamic part. */
	seal->sign[seal->num_sign++] = (struct tn_smbsrv_sign_part) {
		.keys = keys,
		.iov = idx + SMBD_SMB2_HDR_IOV_OFS,
		.iovcnt = SMBD_SMB2_NUM_IOV_PER_REQ - 1,
	};
	return true;
}

/*
 * The reply of req now has its transform header. Let the reactor encrypt
 * the reply. A client checks no signature in an encrypted reply, so the
 * reactor signs none of its messages. A job has its own keys, so this
 * skips its reply.
 */
void smbd_smb2_ros_reply_encrypt(struct smbd_smb2_request *req)
{
	struct smbd_smb2_ros_reply_seal *seal = req->ros_seal;

	if (seal != NULL) {
		smbd_smb2_ros_reply_seal_unsign(seal);
	}
	if (req->queue_entry.ros.job != NULL ||
	    !smbd_smb2_ros_reply_offload(req, req->current_idx))
	{
		return;
	}
	seal = smbd_smb2_ros_reply_seal_get(req);
	if (seal == NULL) {
		return;
	}
	tn_smbsrv_keys_unpin(seal->encrypt);
	seal->encrypt = smbd_smb2_ros_keys_pin(req->xconn,
					       req->session,
					       TN_SMBSRV_SEAL_ENCRYPT);
}

/*
 * True if the reactor encrypts the finished reply of req. False if the
 * reply has a message that smbd must protect itself.
 */
bool smbd_smb2_ros_reply_encrypted(struct smbd_smb2_request *req)
{
	struct smbd_smb2_ros_reply_seal *seal = req->ros_seal;
	int idx;

	if (seal == NULL || seal->encrypt == NULL) {
		return false;
	}
	for (idx = 1;
	     idx < req->out.vector_count;
	     idx += SMBD_SMB2_NUM_IOV_PER_REQ)
	{
		if (!smbd_smb2_ros_reply_offload(req, idx)) {
			tn_smbsrv_keys_unpin(seal->encrypt);
			seal->encrypt = NULL;
			return false;
		}
	}
	return true;
}

/* True if the reactor signs or encrypts any part of the reply of req. */
bool smbd_smb2_ros_reply_sealed(struct smbd_smb2_request *req)
{
	return req->ros_seal != NULL &&
	       (req->ros_seal->encrypt != NULL || req->ros_seal->num_sign > 0);
}

/*
 * Give the reply of e to the reactor. The reactor signs or encrypts the
 * reply before it sends it. Return 0 or an errno.
 */
static int smbd_smb2_ros_send_sealed(struct smbXsrv_connection *xconn,
				     struct smbd_smb2_send_queue *e,
				     bool *lent)
{
	struct smbd_smb2_ros_reply_seal *seal = e->ros.seal;
	struct tn_smbsrv_keys *encrypt = seal->encrypt;
	size_t num_sign = seal->num_sign;

	e->ros.seal = NULL;
	/* The call passes the keys to the reactor in all cases. */
	seal->encrypt = NULL;
	seal->num_sign = 0;
	return tn_smbsrv_send_sealed(xconn->smb2.ros.conn,
				     e->vector,
				     e->count,
				     SMBD_SMB2_ROS_LEND_MIN,
				     (uint64_t)(uintptr_t)e,
				     lent,
				     encrypt,
				     seal->sign,
				     num_sign);
}

/* Credentials that smbd registered as an identity in a reactor ring. */
struct smbd_smb2_ros_identity {
	struct smbd_smb2_ros_identity *prev, *next;
	struct security_unix_token *ut;
	uint16_t who;
};

/*
 * Return the identity of the credentials of this thread in the ring of the
 * reactor of xconn, or 0 on failure. The reactor does the file I/O of a
 * request with this identity. smbd registers each set of credentials one
 * time per channel.
 */
static uint16_t smbd_smb2_ros_who(struct smbXsrv_connection *xconn,
				  struct connection_struct *conn)
{
	const struct security_unix_token *ut = get_current_utok(conn);
	struct smbd_smb2_ros_identity *id = NULL;
	int err = 0;

	for (id = xconn->smb2.ros.identities; id != NULL; id = id->next) {
		if (unix_token_equal(id->ut, ut)) {
			return id->who;
		}
	}

	/* The kernel registers the credentials of this thread, not ut. */
	if (geteuid() != ut->uid || getegid() != ut->gid) {
		DBG_ERR("This thread is %u:%u and not %u:%u\n",
			(unsigned)geteuid(),
			(unsigned)getegid(),
			(unsigned)ut->uid,
			(unsigned)ut->gid);
		return 0;
	}

	id = talloc_zero(xconn, struct smbd_smb2_ros_identity);
	if (id == NULL) {
		return 0;
	}
	id->ut = copy_unix_token(id, ut);
	if (id->ut == NULL) {
		TALLOC_FREE(id);
		return 0;
	}
	id->who = tn_smbros_conn_register_self(xconn->smb2.ros.conn, &err);
	if (id->who == 0) {
		DBG_WARNING("conn[%s] has no identity for uid %u: %s\n",
			    smbXsrv_connection_dbg(xconn),
			    (unsigned)ut->uid,
			    strerror(err));
		TALLOC_FREE(id);
		return 0;
	}
	DLIST_ADD(xconn->smb2.ros.identities, id);
	return id->who;
}

/*
 * Set up the file I/O of req for the reactor of the channel. The I/O is a
 * READ of count bytes, a WRITE of count bytes at data in the PDU, or a
 * FLUSH. The caller checked the request. It then builds the reply for a
 * full transfer. The reactor corrects the reply after a short transfer or
 * an error. Return NT_STATUS_RETRY if the caller must do the I/O itself.
 */
NTSTATUS smbd_smb2_ros_delegate(struct smbd_smb2_request *req,
				struct files_struct *fsp,
				uint16_t opcode,
				uint64_t offset,
				uint32_t count,
				uint32_t minimum,
				const uint8_t *data)
{
	struct smbd_smb2_ros_buf *rb = req->ros_buf;
	struct smbXsrv_session *x = req->session;
	struct smbd_smb2_ros_file *rf = NULL;
	struct smbd_smb2_ros_job *job = NULL;
	struct tn_smbsrv_keys *keys = NULL;
	struct tn_smbsrv_io io = {
		.opcode = opcode,
		.seal = TN_SMBSRV_SEAL_NONE,
		.offset = offset,
		.count = count,
		.minimum = minimum,
	};
	NTSTATUS status;
	int fd;

	/*
	 * The descriptor of a stream is a fake one, a pipe. The callers
	 * check this before their own work. This check is for a caller
	 * that does not.
	 */
	if (fsp_is_alternate_stream(fsp)) {
		return NT_STATUS_RETRY;
	}

	fd = fsp_get_io_fd(fsp);
	if (fd == -1) {
		return NT_STATUS_RETRY;
	}

	if (opcode == SMB2_OP_WRITE) {
		uintptr_t start = (uintptr_t)rb->data;
		uintptr_t at = (uintptr_t)data;

		if (data == NULL || at < start || at - start > rb->len ||
		    rb->len - (at - start) < count) {
			return NT_STATUS_RETRY;
		}
		io.data_ofs = at - start;
	}

	io.who = smbd_smb2_ros_who(req->xconn, fsp->conn);
	if (io.who == 0) {
		return NT_STATUS_RETRY;
	}

	/* Protect the reply as smbd_smb2_request_reply() does. */
	if (req->do_encryption &&
	    x != NULL &&
	    smb2_signing_key_valid(x->global->encryption_key))
	{
		io.seal = TN_SMBSRV_SEAL_ENCRYPT;
	} else if (req->do_signing) {
		io.seal = TN_SMBSRV_SEAL_SIGN;
	}
	if (io.seal != TN_SMBSRV_SEAL_NONE) {
		keys = smbd_smb2_ros_keys_pin(req->xconn, x, io.seal);
		if (keys == NULL) {
			return NT_STATUS_RETRY;
		}
	}
	if (io.seal == TN_SMBSRV_SEAL_ENCRYPT) {
		/* The interim response needs a nonce of its own. */
		status = smb2_get_new_nonce(x,
					    &io.pending_nonce_high,
					    &io.pending_nonce_low);
		if (!NT_STATUS_IS_OK(status)) {
			tn_smbsrv_keys_unpin(keys);
			return NT_STATUS_RETRY;
		}
	}

	rf = smbd_smb2_ros_file_get(req->sconn, fsp, fd);
	if (rf == NULL) {
		tn_smbsrv_keys_unpin(keys);
		return NT_STATUS_RETRY;
	}

	job = talloc_zero(req, struct smbd_smb2_ros_job);
	if (job == NULL) {
		tn_smbsrv_keys_unpin(keys);
		return NT_STATUS_NO_MEMORY;
	}
	/* From here on, a CLOSE of fsp waits for the job. */
	job->hold = tn_smbsrv_file_hold(rf->file);
	job->keys = keys;
	job->io = io;
	talloc_set_destructor(job, smbd_smb2_ros_job_destructor);
	req->queue_entry.ros.job = job;
	return NT_STATUS_OK;
}

/*
 * The reply of req is complete. True if the reactor signs or encrypts it
 * after the file I/O of its job. An error reply has no file I/O, so this
 * frees its job. Without a job, the reactor can read the next PDUs.
 */
bool smbd_smb2_ros_job_seals(struct smbd_smb2_request *req)
{
	struct smbd_smb2_ros_job *job = req->queue_entry.ros.job;

	if (job != NULL) {
		/* req is not a compound, so its reply is at index 1. */
		const uint8_t *outhdr =
			SMBD_SMB2_IDX_HDR_IOV(req, out, 1)->iov_base;

		if (IVAL(outhdr, SMB2_HDR_STATUS) == 0) {
			return job->io.seal != TN_SMBSRV_SEAL_NONE;
		}
		TALLOC_FREE(req->queue_entry.ros.job);
	}
	smbd_smb2_ros_release(req);
	return false;
}

/*
 * Give the reply in e and its file I/O to the reactor. The reactor copies
 * the reply. For a WRITE, it moves the PDU out of its buffer. So smbd
 * treats e as sent. Return 0 or an errno.
 */
static int smbd_smb2_ros_send_job(struct smbXsrv_connection *xconn,
				  struct smbd_smb2_send_queue *e)
{
	struct smbd_smb2_request *req =
		talloc_get_type_abort(e->mem_ctx, struct smbd_smb2_request);
	struct smbd_smb2_ros_job *job = e->ros.job;
	struct tn_smbsrv_hold *hold = job->hold;
	struct tn_smbsrv_keys *keys = job->keys;
	int ret;

	e->ros.job = NULL;
	/* The call passes the hold and the keys to the reactor in all cases. */
	job->hold = NULL;
	job->keys = NULL;
	ret = tn_smbsrv_delegate(xconn->smb2.ros.conn,
				 req->ros_buf->buf,
				 e->vector,
				 e->count,
				 hold,
				 keys,
				 &job->io);
	TALLOC_FREE(job);
	return ret;
}

/*
 * Give the PDU of e to the reactor of xconn. The reactor sends the PDUs in
 * the order it gets them. *lent is true if the reactor sends from the
 * memory of e. Return 0 or an errno.
 */
int smbd_smb2_ros_send(struct smbXsrv_connection *xconn,
		       struct smbd_smb2_send_queue *e,
		       bool *lent)
{
	*lent = false;
	if (e->ros.job != NULL) {
		/* The reactor sends the reply after the file I/O. */
		return smbd_smb2_ros_send_job(xconn, e);
	}
	if (e->ros.seal != NULL) {
		return smbd_smb2_ros_send_sealed(xconn, e, lent);
	}
	return tn_smbros_send(xconn->smb2.ros.conn,
			      e->vector,
			      e->count,
			      SMBD_SMB2_ROS_LEND_MIN,
			      (uint64_t)(uintptr_t)e,
			      lent);
}

bool smbd_smb2_ros_wanted(struct smbXsrv_connection *xconn)
{
	return xconn->smb2.ros.enabled;
}

/*
 * The reactor threads share the fd table of smbd. The kernel grows a
 * shared table only after an RCU grace period of 30 to 55 ms. A Mac client
 * opens hundreds of streams, and each one has a fake fd. So smbd grows the
 * table before the first reactor thread starts.
 */
#define SMBD_SMB2_ROS_FD_SLOTS 1024

static void smbd_smb2_ros_grow_fd_table(int fd)
{
	struct rlimit rl = { 0 };
	int slots = SMBD_SMB2_ROS_FD_SLOTS;
	int tmp;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < (rlim_t)slots) {
		slots = rl.rlim_cur;
	}
	tmp = fcntl(fd, F_DUPFD_CLOEXEC, slots - 1);
	if (tmp != -1) {
		close(tmp);
	}
}

NTSTATUS smbd_smb2_ros_adopt(struct smbXsrv_connection *xconn)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	size_t async_read;
	size_t async_write;
	size_t zero_copy;
	int err = 0;

	if (sconn->ros_ctx == NULL) {
		struct smbd_smb2_ros_owner *owner = NULL;
		uint32_t errmap[256];
		size_t i;

		owner = talloc_zero(sconn, struct smbd_smb2_ros_owner);
		if (owner == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		owner->sconn = sconn;
		owner->ev = xconn->client->raw_ev_ctx;

		smbd_smb2_ros_grow_fd_table(xconn->transport.sock);
		sconn->ros_ctx = tn_smbros_ctx_new();
		if (sconn->ros_ctx == NULL) {
			NTSTATUS status = map_nt_error_from_unix_common(errno);

			TALLOC_FREE(owner);
			return status;
		}
		sconn->ros_owner = owner;
		talloc_set_destructor(owner, smbd_smb2_ros_owner_destructor);
		/*
		 * The reactors answer failed file I/O with the status that
		 * smbd gives for the errno.
		 */
		for (i = 0; i < ARRAY_SIZE(errmap); i++) {
			errmap[i] = NT_STATUS_V(map_nt_error_from_unix(i));
		}
		/* The reactors sign and encrypt with libcli/smb. */
		tn_smbsrv_attach(sconn->ros_ctx,
				 &smbd_smb2_ros_crypto,
				 errmap,
				 ARRAY_SIZE(errmap));
		smbd_smb2_ros_inline_setup(owner);
		owner->fde = tevent_add_fd(owner->ev,
					   owner,
					   tn_smbros_ctx_fd(sconn->ros_ctx),
					   TEVENT_FD_READ,
					   smbd_smb2_ros_handler,
					   sconn);
		if (owner->fde == NULL) {
			TALLOC_FREE(sconn->ros_owner);
			return NT_STATUS_NO_MEMORY;
		}
	}

	smbd_smb2_ros_trash_empty();

	/*
	 * The reactor flags a delegated READ of this size or more with
	 * IOSQE_ASYNC. A hot read on ZFS does not sleep, so without the flag
	 * one io-wq worker runs all reads of the ring. 0 flags no READ.
	 */
	async_read = lp_parm_ulong(GLOBAL_SECTION_SNUM,
				   "truenas",
				   "ros async read size",
				   SMBD_SMB2_ROS_ASYNC_READ_SIZE);
	if (async_read == 0) {
		async_read = SIZE_MAX;
	}

	/*
	 * The same for WRITE. A flagged write skips the kernel's queue for
	 * its file, so the writes of one file can run at the same time.
	 */
	async_write = lp_parm_ulong(GLOBAL_SECTION_SNUM,
				    "truenas",
				    "ros async write size",
				    SMBD_SMB2_ROS_ASYNC_WRITE_SIZE);
	if (async_write == 0) {
		async_write = SIZE_MAX;
	}

	/*
	 * A reply of this size or more goes out without the kernel's copy.
	 * The reactor then keeps lent reply memory until the client
	 * acknowledges it. 0 copies every reply.
	 */
	zero_copy = lp_parm_ulong(GLOBAL_SECTION_SNUM,
				  "truenas",
				  "ros zero copy size",
				  SMBD_SMB2_ROS_ZERO_COPY_SIZE);
	if (zero_copy == 0) {
		zero_copy = SIZE_MAX;
	}

	/*
	 * The reactor thread starts with the credentials of this thread.
	 * It must start as root, not as the last user.
	 */
	become_root();
	xconn->smb2.ros.conn = tn_smbros_adopt(sconn->ros_ctx,
					       xconn->transport.sock,
					       (uint64_t)(uintptr_t)xconn,
					       SMBD_SMB2_ROS_MAX_IN_FLIGHT,
					       true,	/* delegate */
					       async_read,
					       async_write,
					       zero_copy,
					       &err);
	unbecome_root();
	if (xconn->smb2.ros.conn == NULL) {
		return map_nt_error_from_unix_common(err);
	}

	TEVENT_FD_NOT_READABLE(xconn->transport.fde);
	TEVENT_FD_NOT_WRITEABLE(xconn->transport.fde);
	TEVENT_FD_NOT_WANTERROR(xconn->transport.fde);

	DBG_INFO("conn[%s] reads and sends through a truenas_ros reactor, "
		 "root is identity %u of its ring\n",
		 smbXsrv_connection_dbg(xconn),
		 (unsigned)tn_smbros_conn_root(xconn->smb2.ros.conn));
	return NT_STATUS_OK;
}
