/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * TrueNAS: the connection of an smbd process to truenas_smbhad, and the
 * fence through the epoch file.
 *
 * Copyright (C) iXsystems, Inc. 2026
 */

#include "includes.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "lib/global_contexts.h"
#include "messages.h"
#include "truenas_hastate/private.h"

/* The longest wait for a read or a write of a call to the daemon */
#define TN_TIMEOUT_SECS 10

struct tn_client tn_c;

static int tn_idle_secs(void)
{
	return lp_parm_int(-1, "truenas smbhad", "idle secs", 30);
}

/* Reset the state that a child process inherits through fork(). */
void tn_this_process(void)
{
	if (tn_c.pid == tevent_cached_getpid()) {
		return;
	}
	/* Closes the copy of the socket. The parent keeps its connection. */
	smbhad_conn_free(tn_c.conn);
	TALLOC_FREE(tn_c.epoch_file);
	TALLOC_FREE(tn_c.tick_te);
	TALLOC_FREE(tn_c.idle_te);
	TALLOC_FREE(tn_c.fde);
	TALLOC_FREE(tn_c.reconnect_te);
	TALLOC_FREE(tn_c.marker_te);
	tn_c = (struct tn_client) { .pid = tevent_cached_getpid() };
}

void tn_disconnect(void)
{
	TALLOC_FREE(tn_c.fde);
	smbhad_conn_free(tn_c.conn);
	tn_c.conn = NULL;
	TALLOC_FREE(tn_c.idle_te);
}

/* A call failed with err. Close the connection. */
void tn_failed(const char *what, int err)
{
	char errstr[128];

	(void)strerror_r(err, errstr, sizeof(errstr));
	DBG_WARNING("%s failed: %s: %s\n", what, errstr, smbhad_last_error());
	tn_disconnect();
}

static void tn_idle_fn(struct tevent_context *ev,
		       struct tevent_timer *te,
		       struct timeval current_time,
		       void *private_data)
{
	time_t now = time(NULL);
	int idle = tn_idle_secs();

	tn_c.idle_te = NULL;
	if (tn_c.conn == NULL) {
		return;
	}
	/* A process with durable handles keeps its connection. */
	if ((tn_c.pending == NULL) && (tn_c.sconn == NULL) &&
	    !tn_c.scavenger && (tn_c.last_used + idle <= now)) {
		tn_disconnect();
		return;
	}
	tn_c.idle_te = tevent_add_timer(global_event_context(),
					NULL,
					timeval_current_ofs(idle, 0),
					tn_idle_fn,
					NULL);
}

/*
 * Connect to the daemon as root. Send the hello for this process. The
 * daemon accepts only peers with uid 0.
 */
bool tn_connect(uint32_t role)
{
	const char *path = lp_truenas_smbhad_socket();
	const struct smbhad_hello *hello = NULL;
	struct smbhad_conn *conn = NULL;
	uint64_t instance;
	bool restarted;
	int ret;

	tn_this_process();
	if ((tn_c.conn != NULL) && (tn_c.role == role)) {
		return true;
	}
	tn_disconnect();
	if (path == NULL) {
		return false;
	}
	tn_c.self = messaging_server_id(global_messaging_context());
	become_root();
	ret = smbhad_connect(path,
			     role,
			     (uint32_t)tn_c.self.pid,
			     tn_c.self.unique_id,
			     TN_TIMEOUT_SECS * 1000,
			     &conn);
	unbecome_root();
	if (ret != 0) {
		DBG_INFO("connecting to %s failed: %s\n",
			 path,
			 smbhad_last_error());
		return false;
	}
	tn_c.conn = conn;
	tn_c.role = role;
	hello = smbhad_conn_hello(conn);
	instance = hello->instance;
	TALLOC_FREE(tn_c.epoch_file);
	tn_c.epoch_file = talloc_strdup(NULL, hello->epoch_file);
	tn_c.node = hello->node;

	restarted = (tn_c.instance != 0) && (tn_c.instance != instance);
	tn_c.instance = instance;
	tn_c.last_used = time(NULL);
	if (tn_c.idle_te == NULL) {
		tn_c.idle_te = tevent_add_timer(
			global_event_context(),
			NULL,
			timeval_current_ofs(tn_idle_secs(), 0),
			tn_idle_fn,
			NULL);
	}
	tn_watch();
	if (restarted) {
		/* The daemon restarted. It has no records of this process. */
		DBG_NOTICE("truenas_smbhad restarted, sending every handle\n");
		tn_resubmit_all();
	}
	if (tn_c.scavenger && (tn_c.resent_instance != instance)) {
		tn_resend_disconnected(instance);
	}
	return (tn_c.conn != NULL);
}

static void tn_reconnect_fn(struct tevent_context *ev,
			    struct tevent_timer *te,
			    struct timeval current_time,
			    void *private_data);

/* Connect again after a delay. The delays of the processes differ. */
void tn_reconnect_later(void)
{
	uint32_t msec;

	if (tn_c.reconnect_te != NULL) {
		return;
	}
	tn_c.reconnect_secs = MIN(MAX(2 * tn_c.reconnect_secs, 1), 32);
	msec = generate_random_u64_range(tn_c.reconnect_secs * 500,
					 tn_c.reconnect_secs * 1000 + 1);
	tn_c.reconnect_te = tevent_add_timer(global_event_context(),
					     NULL,
					     timeval_current_ofs_msec(msec),
					     tn_reconnect_fn,
					     NULL);
}

static void tn_reconnect_fn(struct tevent_context *ev,
			    struct tevent_timer *te,
			    struct timeval current_time,
			    void *private_data)
{
	tn_c.reconnect_te = NULL;
	if (tn_connect(TN_WORKER)) {
		tn_c.reconnect_secs = 0;
		return;
	}
	tn_reconnect_later();
}

/* The daemon sends nothing unasked. A readable connection is closed. */
static void tn_closed_fn(struct tevent_context *ev,
			 struct tevent_fd *fde,
			 uint16_t flags,
			 void *private_data)
{
	DBG_NOTICE("truenas_smbhad closed the connection\n");
	tn_disconnect();
	tn_reconnect_later();
}

/*
 * A process with durable handles keeps its connection. The daemon closes
 * all connections when it restarts. The process then connects again. The
 * hello has the new instance, and the process sends its handles again.
 */
void tn_watch(void)
{
	if ((tn_c.fde != NULL) || (tn_c.conn == NULL) ||
	    (tn_c.role != TN_WORKER) ||
	    ((tn_c.sconn == NULL) && !tn_c.scavenger)) {
		return;
	}
	tn_c.fde = tevent_add_fd(global_event_context(),
				 NULL,
				 smbhad_conn_fd(tn_c.conn),
				 TEVENT_FD_READ,
				 tn_closed_fn,
				 NULL);
}

/* The epoch file that the daemon reported, or the configured one. */
const char *tn_epoch_path(void)
{
	if ((tn_c.epoch_file != NULL) && (tn_c.epoch_file[0] != '\0')) {
		return tn_c.epoch_file;
	}
	return lp_parm_const_string(-1,
				    "truenas smbhad",
				    "epoch file",
				    "/var/db/system/samba4/smbhad.epoch");
}

/*
 * When a wait for the standby fails, smbd fences the copy of the standby
 * through the epoch file on the pool: the standby then does not restore
 * its copy. See smbhad_epoch_fence().
 */
bool tn_fallback_fence(void)
{
	const char *path = tn_epoch_path();
	uint64_t next = 0;
	int ret;

	become_root();
	ret = smbhad_epoch_fence(path, tn_c.fenced_to, &next);
	unbecome_root();
	if (ret != 0) {
		DBG_ERR("fencing %s failed: %s\n", path, smbhad_last_error());
		return false;
	}
	if (next != 0) {
		tn_c.fenced_to = next;
		DBG_WARNING("truenas_smbhad unreachable: fenced %s to %" PRIu64
			    "\n",
			    path,
			    next);
	}
	return true;
}
