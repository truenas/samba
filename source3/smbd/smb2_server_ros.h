/*
   Unix SMB/CIFS implementation.
   TrueNAS: what smb2_server.c, smb2_server_ros.c and
   smb2_server_ros_inline.c share for "truenas:ros transport"

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

#ifndef _SMBD_SMB2_SERVER_ROS_H_
#define _SMBD_SMB2_SERVER_ROS_H_

#include <pthread.h>
#include "truenas_smbros.h"
#include "truenas_smb_server.h"

struct smbd_smb2_ros_keys;
struct smbd_smb2_ros_reply_seal;
struct smbd_smb2_ros_terminate;
struct smb2_signing_key;

/*
 * This struct owns sconn->ros_ctx, its fd event and the key copies of the
 * reactors. The destructor stops and joins the reactors. Then talloc frees
 * the copies.
 */
struct smbd_smb2_ros_owner {
	struct smbd_server_connection *sconn;
	struct tevent_context *ev;
	/* The fd is readable when sconn->ros_ctx has reactor events. */
	struct tevent_fd *fde;
	/*
	 * True if the lock is set up. The main thread has the lock,
	 * except while it sleeps in its event loop. A reactor that gets the
	 * lock runs a PDU through smbd on its own thread.
	 */
	bool inline_on;
	/*
	 * "truenas:ros test defer dispatch", for the tests of CI. Inline runs
	 * then also take the messages that only the main thread runs, and
	 * smbd_smb2_ros_inline_defer_dispatch() passes them to the main
	 * thread.
	 */
	bool test_defer_dispatch;
	pthread_mutex_t lock;
	/*
	 * True while the main thread sleeps without the lock. Only the main
	 * thread uses it.
	 */
	bool released;
	/*
	 * True while the main thread waits for the lock. A reactor does not
	 * try the lock then.
	 */
	bool main_waits;
	/* Connections that the reactors ask the main thread to terminate. */
	struct smbd_smb2_ros_terminate *terminate;
};

/* The file I/O of a READ, WRITE or FLUSH that a reactor does for smbd. */
struct smbd_smb2_ros_job {
	/*
	 * The hold counts the job in its file until the I/O ends. smbd gives
	 * it to the reactor with the job.
	 */
	struct tn_smbsrv_hold *hold;
	/* The keys for io.seal, or NULL. smbd gives them to the reactor. */
	struct tn_smbsrv_keys *keys;
	struct tn_smbsrv_io io;
};

/* The following definitions come from smbd/smb2_server.c  */

struct smbd_smb2_request *smbd_smb2_request_allocate(
	struct smbXsrv_connection *xconn);
NTSTATUS smbd_smb2_inbuf_parse_compound(struct smbXsrv_connection *xconn,
					NTTIME now,
					uint8_t *buf,
					size_t buflen,
					struct smbd_smb2_request *req,
					struct iovec **piov,
					int *pnum_iov);
NTSTATUS smbd_smb2_request_validate(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_setup_out(struct smbd_smb2_request *req);
struct smb2_signing_key *smbd_smb2_signing_key(
	struct smbXsrv_session *session,
	struct smbXsrv_connection *xconn,
	bool *_has_channel);
NTSTATUS smbd_smb2_request_next_incoming(struct smbXsrv_connection *xconn);
NTSTATUS smb2_get_new_nonce(struct smbXsrv_session *session,
			    uint64_t *new_nonce_high,
			    uint64_t *new_nonce_low);

/* The following definitions come from smbd/smb2_server_ros.c  */

NTSTATUS smbd_smb2_ros_incoming(struct smbXsrv_connection *xconn,
				const struct tn_smbros_event *ev);
void smbd_smb2_ros_release(struct smbd_smb2_request *req);
uint32_t smbd_smb2_ros_file_seq_old(struct files_struct *fsp);
void smbd_smb2_ros_file_seq_bump(struct files_struct *fsp);
void smbd_smb2_ros_job_keeps_count(struct smbd_smb2_request *req,
				   bool current);
struct smbd_smb2_ros_keys *smbd_smb2_ros_keys_sync(
	struct smbXsrv_connection *xconn,
	struct smbXsrv_session *x);
NTSTATUS smbd_smb2_ros_decrypted(struct smbd_smb2_request *req,
				 struct smbXsrv_session *s);
bool smbd_smb2_ros_signed_ok(struct smbd_smb2_request *req,
			     struct smbXsrv_session *x,
			     struct smb2_signing_key *signing_key);
struct smbd_smb2_ros_reply_seal *smbd_smb2_ros_seal_encrypt(
	TALLOC_CTX *mem_ctx,
	struct smbXsrv_connection *xconn,
	struct smbXsrv_session *x,
	uint16_t opcode);
bool smbd_smb2_ros_reply_sign(struct smbd_smb2_request *req, int idx);
void smbd_smb2_ros_reply_encrypt(struct smbd_smb2_request *req);
bool smbd_smb2_ros_reply_encrypted(struct smbd_smb2_request *req);
bool smbd_smb2_ros_reply_sealed(struct smbd_smb2_request *req);
bool smbd_smb2_ros_job_seals(struct smbd_smb2_request *req);
int smbd_smb2_ros_send(struct smbXsrv_connection *xconn,
		       struct smbd_smb2_send_queue *e,
		       bool *lent);
bool smbd_smb2_ros_wanted(struct smbXsrv_connection *xconn);
NTSTATUS smbd_smb2_ros_adopt(struct smbXsrv_connection *xconn);

/* The following definitions come from smbd/smb2_server_ros_inline.c  */

int smbd_smb2_ros_owner_destructor(struct smbd_smb2_ros_owner *o);
void smbd_smb2_ros_trash_empty(void);
bool smbd_smb2_ros_inline_take_next(struct smbd_smb2_request *req);
bool smbd_smb2_ros_inline_defer_dispatch(struct smbd_smb2_request *req,
					 uint16_t opcode);
bool smbd_smb2_ros_inline_defer_terminate(struct smbXsrv_connection *xconn,
					  const char *reason,
					  const char *location);
void smbd_smb2_ros_inline_terminate(struct smbd_server_connection *sconn);
void smbd_smb2_ros_inline_setup(struct smbd_smb2_ros_owner *o);

#endif /* _SMBD_SMB2_SERVER_ROS_H_ */
