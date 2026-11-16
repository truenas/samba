/*
   Unix SMB/CIFS implementation.
   TrueNAS: PDUs that a truenas_ros reactor runs through smbd on
   its own thread

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
#include "lib/param/param.h"
#include "../libcli/smb/smb_common.h"
#include "smbd/truenas_mdcache.h"
#include "smbd/smb2_server_ros.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

/* An inline run queues this to make the main thread end xconn. */
struct smbd_smb2_ros_terminate {
	struct smbd_smb2_ros_terminate *prev, *next;
	struct smbd_smb2_ros_owner *owner;
	struct smbXsrv_connection *xconn;
	char *reason;
	const char *location;
};

static int smbd_smb2_ros_terminate_destructor(struct smbd_smb2_ros_terminate *t)
{
	if (t->owner != NULL) {
		DLIST_REMOVE(t->owner->terminate, t);
	}
	return 0;
}

/*
 * Tokens of ended reactor threads. A thread ends without the lock. So it
 * must not call talloc. The main thread frees the tokens.
 */
struct smbd_smb2_ros_trash {
	struct smbd_smb2_ros_trash *next;
	struct security_token *token;
};
static pthread_mutex_t smbd_smb2_ros_trash_lock = PTHREAD_MUTEX_INITIALIZER;
static struct smbd_smb2_ros_trash *smbd_smb2_ros_trash;

/* pthread calls this when a reactor thread that ran smbd's code exits. */
static void smbd_smb2_ros_thread_end(void *private_data)
{
	struct security_token *tokens[MAX_SEC_CTX_DEPTH + 1];
	size_t num = sec_ctx_thread_end(tokens);
	size_t i;

	for (i = 0; i < num; i++) {
		struct smbd_smb2_ros_trash *t =
			SMB_MALLOC_P(struct smbd_smb2_ros_trash);

		if (t == NULL) {
			continue;
		}
		t->token = tokens[i];
		pthread_mutex_lock(&smbd_smb2_ros_trash_lock);
		t->next = smbd_smb2_ros_trash;
		__atomic_store_n(&smbd_smb2_ros_trash, t, __ATOMIC_RELEASE);
		pthread_mutex_unlock(&smbd_smb2_ros_trash_lock);
	}
}

/* The main thread calls this to free the tokens of ended reactor threads. */
void smbd_smb2_ros_trash_empty(void)
{
	struct smbd_smb2_ros_trash *t = NULL;

	if (__atomic_load_n(&smbd_smb2_ros_trash, __ATOMIC_ACQUIRE) == NULL) {
		return;
	}
	pthread_mutex_lock(&smbd_smb2_ros_trash_lock);
	t = smbd_smb2_ros_trash;
	__atomic_store_n(&smbd_smb2_ros_trash, NULL, __ATOMIC_RELEASE);
	pthread_mutex_unlock(&smbd_smb2_ros_trash_lock);

	while (t != NULL) {
		struct smbd_smb2_ros_trash *next = t->next;

		TALLOC_FREE(t->token);
		SAFE_FREE(t);
		t = next;
	}
}

int smbd_smb2_ros_owner_destructor(struct smbd_smb2_ros_owner *o)
{
	struct smbd_server_connection *sconn = o->sconn;

	TALLOC_FREE(o->fde);
	tn_smbros_ctx_free(sconn->ros_ctx);
	/* tn_smbros_ctx_free() waited for the reactor threads to end. */
	smbd_smb2_ros_trash_empty();
	sconn->ros_ctx = NULL;
	sconn->ros_owner = NULL;
	if (o->inline_on) {
		while (o->terminate != NULL) {
			struct smbd_smb2_ros_terminate *t = o->terminate;

			DLIST_REMOVE(o->terminate, t);
			t->owner = NULL;
		}
		tevent_set_trace_fd_callback(o->ev, NULL, NULL);
		tevent_set_trace_timer_callback(o->ev, NULL, NULL);
		tevent_set_trace_immediate_callback(o->ev, NULL, NULL);
		/* No reactor runs now. Only this thread can have the lock. */
		if (!o->released) {
			pthread_mutex_unlock(&o->lock);
		}
		pthread_mutex_destroy(&o->lock);
	}
	return 0;
}

/* The connection of the inline run on this thread, NULL outside a run. */
static __thread struct smbXsrv_connection *smbd_smb2_ros_inline_xconn;
/* The compound request that the inline run dispatches next. */
static __thread struct smbd_smb2_request *smbd_smb2_ros_inline_next;
/* Count of timers and immediates that this run added and did not remove. */
static __thread int smbd_smb2_ros_inline_events;
/* True if init_sec_ctx() ran on this thread. */
static __thread bool smbd_smb2_ros_inline_ready;

/*
 * The tag of a tevent timer identifies the code that added it. Timers of
 * the main thread have SMBD_SMB2_ROS_TIMER_MAIN. Timers of an inline run
 * have the number of the run. A new timer has the tag 0. Only a thread
 * that has the lock uses smbd_smb2_ros_inline_run.
 */
#define SMBD_SMB2_ROS_TIMER_MAIN 1
static uint64_t smbd_smb2_ros_inline_run = SMBD_SMB2_ROS_TIMER_MAIN;

static pthread_once_t smbd_smb2_ros_thread_once = PTHREAD_ONCE_INIT;
static pthread_key_t smbd_smb2_ros_thread_key;
static bool smbd_smb2_ros_thread_key_ok;

static void smbd_smb2_ros_thread_key_init(void)
{
	int ret = pthread_key_create(&smbd_smb2_ros_thread_key,
				     smbd_smb2_ros_thread_end);

	smbd_smb2_ros_thread_key_ok = (ret == 0);
}

/*
 * A child that fork() makes on a reactor thread gets the signal mask of
 * the reactor, which blocks nearly all signals. A program that the child
 * runs keeps that mask, for example a dfree command. So the child takes
 * the mask of the main thread, as if the main thread had made it.
 */
static sigset_t smbd_smb2_ros_main_sigmask;
static pthread_once_t smbd_smb2_ros_fork_once = PTHREAD_ONCE_INIT;

static void smbd_smb2_ros_fork_child(void)
{
	/* Only a reactor thread runs smbd_smb2_ros_thread_begin(). */
	if (smbd_smb2_ros_inline_ready) {
		pthread_sigmask(SIG_SETMASK, &smbd_smb2_ros_main_sigmask, NULL);
	}
}

static void smbd_smb2_ros_fork_init(void)
{
	pthread_atfork(NULL, NULL, smbd_smb2_ros_fork_child);
}

/* Set up a reactor thread before its first inline run. */
static void smbd_smb2_ros_thread_begin(void)
{
	/* The thread starts as root. See smbd_smb2_ros_adopt(). */
	init_sec_ctx();
	pthread_once(&smbd_smb2_ros_thread_once, smbd_smb2_ros_thread_key_init);
	if (smbd_smb2_ros_thread_key_ok) {
		/* pthread calls the destructor only for a non-NULL value. */
		pthread_setspecific(smbd_smb2_ros_thread_key,
				    &smbd_smb2_ros_inline_ready);
	}
	smbd_smb2_ros_inline_ready = true;
}

/*
 * The main thread waits in epoll_wait() without the lock. epoll_wait()
 * can return any fd event of its event context. So a reactor must not
 * free an fd event. The exception is the socket fd event of the reactor's
 * own connection. smbd_smb2_ros_adopt() cleared its flags, so epoll_wait()
 * does not return it.
 */
static void smbd_smb2_ros_inline_trace_fd(struct tevent_fd *fde,
					  enum tevent_event_trace_point point,
					  void *private_data)
{
	struct smbXsrv_connection *xconn = smbd_smb2_ros_inline_xconn;

	if (xconn == NULL || point != TEVENT_EVENT_TRACE_DETACH ||
	    fde == xconn->transport.fde) {
		return;
	}
	smb_panic("an inline reactor run freed a tevent fd event");
}

/*
 * The main thread computed its epoll_wait() timeout before this run. So
 * the reactor wakes the main thread if the run adds a timer and does not
 * remove it. The count ignores older timers. Their removal must not cancel
 * the count of a new timer. If a run removes an older timer or moves it
 * later, the main thread at worst wakes too early.
 */
static void smbd_smb2_ros_inline_trace_timer(
	struct tevent_timer *te,
	enum tevent_event_trace_point point,
	void *private_data)
{
	uint64_t tag = tevent_timer_get_tag(te);

	if (smbd_smb2_ros_inline_xconn == NULL) {
		if (point == TEVENT_EVENT_TRACE_ATTACH && tag == 0) {
			tevent_timer_set_tag(te, SMBD_SMB2_ROS_TIMER_MAIN);
		}
		return;
	}
	if (point == TEVENT_EVENT_TRACE_ATTACH) {
		if (tag == 0) {
			tag = smbd_smb2_ros_inline_run;
			tevent_timer_set_tag(te, tag);
		}
		if (tag == smbd_smb2_ros_inline_run) {
			smbd_smb2_ros_inline_events++;
		}
	} else if (point == TEVENT_EVENT_TRACE_DETACH) {
		if (tag == smbd_smb2_ros_inline_run) {
			smbd_smb2_ros_inline_events--;
		}
	}
}

/*
 * The main thread waits only when it has no immediates. So each immediate
 * here is from this run. The reactor wakes the main thread if an
 * immediate is still scheduled after the run.
 */
static void smbd_smb2_ros_inline_trace_immediate(
	struct tevent_immediate *im,
	enum tevent_event_trace_point point,
	void *private_data)
{
	if (smbd_smb2_ros_inline_xconn == NULL) {
		return;
	}
	if (point == TEVENT_EVENT_TRACE_ATTACH) {
		smbd_smb2_ros_inline_events++;
	} else if (point == TEVENT_EVENT_TRACE_DETACH) {
		smbd_smb2_ros_inline_events--;
	}
}

/*
 * True if the inline run on this thread dispatches req next. Then the
 * caller must not schedule an immediate event for req.
 */
bool smbd_smb2_ros_inline_take_next(struct smbd_smb2_request *req)
{
	if (smbd_smb2_ros_inline_xconn != req->xconn ||
	    smbd_smb2_ros_inline_next != NULL)
	{
		return false;
	}
	smbd_smb2_ros_inline_next = req;
	return true;
}

/*
 * smbd can exit when it ends a connection. Only the main thread can do
 * that. In an inline run, this queues xconn for the main thread and
 * returns true.
 */
bool smbd_smb2_ros_inline_defer_terminate(
	struct smbXsrv_connection *xconn,
	const char *reason,
	const char *location)
{
	struct smbd_smb2_ros_owner *o = NULL;
	struct smbd_smb2_ros_terminate *t = NULL;

	if (smbd_smb2_ros_inline_xconn == NULL) {
		return false;
	}
	o = xconn->client->sconn->ros_owner;

	t = talloc_zero(xconn, struct smbd_smb2_ros_terminate);
	if (t == NULL) {
		smb_panic("no memory to defer a connection end");
	}
	t->owner = o;
	t->xconn = xconn;
	t->location = location;
	t->reason = talloc_strdup(t, reason);
	if (t->reason == NULL) {
		smb_panic("no memory to defer a connection end");
	}
	DLIST_ADD_END(o->terminate, t);
	talloc_set_destructor(t, smbd_smb2_ros_terminate_destructor);
	return true;
}

/* The main thread ends the connections that inline runs queued. */
void smbd_smb2_ros_inline_terminate(struct smbd_server_connection *sconn)
{
	struct smbd_smb2_ros_owner *o = sconn->ros_owner;

	while (o != NULL && o->terminate != NULL) {
		struct smbd_smb2_ros_terminate *t = o->terminate;
		struct smbXsrv_connection *xconn = t->xconn;
		const char *location = t->location;
		char *reason = talloc_move(talloc_tos(), &t->reason);

		TALLOC_FREE(t);
		smbd_server_connection_terminate_ex(xconn, reason, location);
		TALLOC_FREE(reason);
		o = sconn->ros_owner;
	}
}

/* The main thread runs compounds with more messages than this. */
#define SMBD_SMB2_ROS_INLINE_MAX_MSGS 64

/*
 * Return the first SMB2 header in the PDU of e. In a PDU that the reactor
 * decrypted, it is after the transform header. Return NULL if e is not an
 * NBT session message, or for an encrypted PDU that the reactor did not
 * decrypt.
 */
static const uint8_t *smbd_smb2_ros_inline_first(
	const struct tn_smbros_event *e,
	size_t *_len)
{
	const uint8_t *p = e->data;
	size_t len = e->len;

	if (e->nbt_type != 0x00) {
		return NULL;
	}
	if (len >= SMB2_TF_HDR_SIZE &&
	    IVAL(p, SMB2_TF_PROTOCOL_ID) == SMB2_TF_MAGIC)
	{
		if (!(e->flags & TN_SMBSRV_DECRYPTED)) {
			return NULL;
		}
		p += SMB2_TF_HDR_SIZE;
		len -= SMB2_TF_HDR_SIZE;
	}
	*_len = len;
	return p;
}

/*
 * True if an inline run can run the PDU of e. The main thread runs each
 * NEGPROT, SESSION_SETUP, LOGOFF and TREE_DISCONNECT. LOGOFF and
 * TREE_DISCONNECT block until the reactors end their file I/O. A CLOSE
 * waits for that I/O asynchronously. The main thread also runs a
 * TREE_CONNECT with messages after it. smbd_smb2_ros_inline_main_only()
 * cannot check the new tree that those messages use.
 */
static bool smbd_smb2_ros_inline_shape(const struct tn_smbros_event *e)
{
	const uint8_t *p = NULL;
	size_t len = 0;
	size_t n;

	p = smbd_smb2_ros_inline_first(e, &len);
	if (p == NULL) {
		return false;
	}

	for (n = 0; n < SMBD_SMB2_ROS_INLINE_MAX_MSGS; n++) {
		uint32_t next;

		if (len < SMB2_HDR_BODY + 2 ||
		    IVAL(p, SMB2_HDR_PROTOCOL_ID) != SMB2_MAGIC)
		{
			return false;
		}
		next = IVAL(p, SMB2_HDR_NEXT_COMMAND);

		switch (SVAL(p, SMB2_HDR_OPCODE)) {
		case SMB2_OP_NEGPROT:
		case SMB2_OP_SESSSETUP:
		case SMB2_OP_LOGOFF:
		case SMB2_OP_TDIS:
			return false;
		case SMB2_OP_TCON:
			if (next != 0) {
				return false;
			}
			break;
		default:
			break;
		}

		if (next == 0) {
			return true;
		}
		if (next < SMB2_HDR_BODY + 2 || next > len) {
			return false;
		}
		p += next;
		len -= next;
	}
	return false;
}

/*
 * True if the main thread must run the PDU of e. The caller has the lock.
 * - A connection of the client has no reactor. The run can send a break
 *   on that connection. Only the main thread submits to its io_uring.
 * - A message is for IPC$. A named pipe frees a tevent fd event when it
 *   closes. A reactor must not free an fd event.
 */
static bool smbd_smb2_ros_inline_main_only(struct smbXsrv_connection *xconn,
					   const struct tn_smbros_event *e)
{
	struct smbXsrv_connection *x = NULL;
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);
	const uint8_t *p = NULL;
	size_t len = 0;
	uint64_t session_id = 0;
	uint32_t tree_id = 0;
	size_t n;

	for (x = xconn->client->connections; x != NULL; x = x->next) {
		if (x->smb2.ros.conn == NULL) {
			return true;
		}
	}

	p = smbd_smb2_ros_inline_first(e, &len);
	if (p == NULL) {
		return true;
	}

	for (n = 0; n < SMBD_SMB2_ROS_INLINE_MAX_MSGS; n++) {
		struct smbXsrv_session *session = NULL;
		struct smbXsrv_tcon *tcon = NULL;
		uint32_t flags;
		uint32_t next;
		NTSTATUS status;

		if (len < SMB2_HDR_BODY + 2) {
			return true;
		}
		flags = IVAL(p, SMB2_HDR_FLAGS);
		next = IVAL(p, SMB2_HDR_NEXT_COMMAND);

		/* A related message has the ids of the one before */
		if (!(flags & SMB2_HDR_FLAG_CHAINED)) {
			session_id = BVAL(p, SMB2_HDR_SESSION_ID);
			tree_id = 0;
			/* An async header has no tree id */
			if (!(flags & SMB2_HDR_FLAG_ASYNC)) {
				tree_id = IVAL(p, SMB2_HDR_TID);
			}
		}

		if (session_id != 0 && tree_id != 0) {
			status = smb2srv_session_lookup_conn(xconn,
							     session_id,
							     now,
							     &session);
			if (NT_STATUS_IS_OK(status)) {
				status = smb2srv_tcon_lookup(session,
							     tree_id,
							     now,
							     &tcon);
			}
			if (NT_STATUS_IS_OK(status) &&
			    tcon->compat != NULL &&
			    IS_IPC(tcon->compat))
			{
				return true;
			}
		}

		if (next == 0) {
			return false;
		}
		if (next < SMB2_HDR_BODY + 2 || next > len) {
			return true;
		}
		p += next;
		len -= next;
	}
	return true;
}

/*
 * A reactor calls this with each new PDU of its connection. While the main
 * thread waits for events, the reactor can get the lock. Then it runs the
 * PDU through smbd's code on its own thread. If this returns false, the
 * reactor queues the PDU for the main thread.
 */
static bool smbd_smb2_ros_inline(void *private_data,
				 struct tn_smbros_event *e)
{
	struct smbd_server_connection *sconn = private_data;
	struct smbd_smb2_ros_owner *o = sconn->ros_owner;
	struct smbXsrv_connection *xconn =
		(struct smbXsrv_connection *)(uintptr_t)e->cookie;
	struct smbd_smb2_ros_terminate *t = NULL;
	TALLOC_CTX *frame = NULL;
	bool was_quiet;
	bool wake;
	NTSTATUS status;

	if (!smbd_smb2_ros_inline_shape(e)) {
		return false;
	}
	if (__atomic_load_n(&o->main_waits, __ATOMIC_ACQUIRE)) {
		return false;
	}
	if (pthread_mutex_trylock(&o->lock) != 0) {
		return false;
	}

	/* smbd closes the reactor connection before it frees xconn. */
	if (!tn_smbros_buf_open(e->buf) ||
	    !NT_STATUS_IS_OK(xconn->transport.status))
	{
		pthread_mutex_unlock(&o->lock);
		return false;
	}
	for (t = o->terminate; t != NULL; t = t->next) {
		if (t->xconn == xconn) {
			pthread_mutex_unlock(&o->lock);
			return false;
		}
	}
	if (smbd_smb2_ros_inline_main_only(xconn, e)) {
		pthread_mutex_unlock(&o->lock);
		return false;
	}

	smbd_smb2_ros_inline_run += 1;
	smbd_smb2_ros_inline_xconn = xconn;
	smbd_smb2_ros_inline_events = 0;
	was_quiet = debug_thread_set_quiet(false);
	/* The main thread makes the same pool in each event loop iteration. */
	frame = talloc_stackframe_pool(8192);
	if (!smbd_smb2_ros_inline_ready) {
		smbd_smb2_ros_thread_begin();
	}
	/* The main thread calls this after each wait. */
	mdcache_bump_epoch(sconn);

	status = smbd_smb2_ros_incoming(xconn, e);
	while (NT_STATUS_IS_OK(status) && smbd_smb2_ros_inline_next != NULL) {
		struct smbd_smb2_request *req = smbd_smb2_ros_inline_next;

		/* smbd_smb2_request_dispatch_immediate() does the same. */
		smbd_smb2_ros_inline_next = NULL;
		status = smbd_smb2_request_dispatch(req);
		if (NT_STATUS_IS_OK(status)) {
			status = smbd_smb2_request_next_incoming(xconn);
		}
	}
	smbd_smb2_ros_inline_next = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		/* This only queues xconn for the main thread. */
		smbd_server_connection_terminate(xconn, nt_errstr(status));
	}

	TALLOC_FREE(frame);
	debug_thread_set_quiet(was_quiet);
	wake = smbd_smb2_ros_inline_events > 0 || o->terminate != NULL;
	smbd_smb2_ros_inline_xconn = NULL;
	pthread_mutex_unlock(&o->lock);

	if (wake) {
		tn_smbros_ctx_wake(sconn->ros_ctx);
	}
	return true;
}

void smbd_smb2_ros_inline_setup(struct smbd_smb2_ros_owner *o)
{
	if (pthread_mutex_init(&o->lock, NULL) != 0) {
		return;
	}
	/* The main thread runs this. See smbd_smb2_ros_fork_child(). */
	pthread_sigmask(SIG_BLOCK, NULL, &smbd_smb2_ros_main_sigmask);
	pthread_once(&smbd_smb2_ros_fork_once, smbd_smb2_ros_fork_init);
	/* The main thread has the lock except while it waits for events. */
	pthread_mutex_lock(&o->lock);
	o->inline_on = true;
	tevent_set_trace_fd_callback(o->ev,
				     smbd_smb2_ros_inline_trace_fd,
				     NULL);
	tevent_set_trace_timer_callback(o->ev,
					smbd_smb2_ros_inline_trace_timer,
					NULL);
	tevent_set_trace_immediate_callback(
		o->ev, smbd_smb2_ros_inline_trace_immediate, NULL);
	tn_smbros_ctx_inline(o->sconn->ros_ctx,
			     smbd_smb2_ros_inline,
			     o->sconn);
}

/* The main thread calls this before it waits for events. */
void smbd_smb2_ros_wait_begin(struct smbd_server_connection *sconn)
{
	struct smbd_smb2_ros_owner *o = sconn->ros_owner;

	if (o == NULL || !o->inline_on || o->released) {
		return;
	}
	o->released = true;
	pthread_mutex_unlock(&o->lock);
}

/* The main thread calls this after it waits for events. */
void smbd_smb2_ros_wait_end(struct smbd_server_connection *sconn)
{
	struct smbd_smb2_ros_owner *o = sconn->ros_owner;

	if (o == NULL || !o->inline_on || !o->released) {
		return;
	}
	__atomic_store_n(&o->main_waits, true, __ATOMIC_RELEASE);
	pthread_mutex_lock(&o->lock);
	__atomic_store_n(&o->main_waits, false, __ATOMIC_RELEASE);
	o->released = false;
}
