/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * TrueNAS: the internal interface of source3/truenas_hastate.
 *
 * Copyright (C) iXsystems, Inc. 2026
 */

#ifndef _TRUENAS_HASTATE_PRIVATE_H_
#define _TRUENAS_HASTATE_PRIVATE_H_

#include "truenas_smbhad_client.h"

#define TN_BATCH_BYTES (4 * 1024 * 1024)

/*
 * A process that cannot reach the daemon fences the standby's copy when
 * this many deletes are pending, and drops them, see tn_check_deletes().
 */
#define TN_MAX_DELETES 65536

/* The id of a marker: bit 63 and the persistent id of the handle */
#define TN_MARKER_ID (UINT64_C(1) << 63)

/*
 * The connection to the local truenas_smbhad
 */

struct tn_pending {
	struct tn_pending *prev, *next;
	uint64_t id;
	/* the record of fsp or of marker. Both NULL: delete the record */
	struct files_struct *fsp;
	struct tn_marker *marker;
	/* set by tn_submit(): the record was too large, smbd sent a delete */
	bool deleted;
};

/*
 * A marker: a record of a file with delete on close, not of a handle. The
 * restore drops all records of the file, see tn_delete_pending().
 */
struct tn_marker {
	struct tn_marker *prev, *next;
	uint64_t id;
	struct file_id file_id;
	uint32_t name_hash;
	uint64_t fsid;
	char *share;
	char *servicepath;
	char *base_name;
};

struct tn_client {
	pid_t pid;
	struct smbhad_conn *conn;
	uint32_t role;
	/* the client connection of this process, see tn_resubmit_all() */
	struct smbd_server_connection *sconn;
	struct server_id self;
	uint64_t instance;	/* 0: none */
	char *epoch_file;
	/* this controller, from the hello reply */
	uint32_t node;
	uint64_t fenced_to;
	struct tn_pending *pending;
	/* a wait after the share mode lock, see truenas_hastate_settle() */
	bool owed;
	size_t num_deletes;
	/* tn_check_deletes() drops at this count. 0: TN_MAX_DELETES */
	size_t drop_at;
	struct tn_marker *markers;
	struct tevent_timer *marker_te;
	struct tevent_timer *tick_te;
	struct tevent_timer *idle_te;
	struct tevent_fd *fde;
	struct tevent_timer *reconnect_te;
	unsigned int reconnect_secs;
	uint64_t tick;
	time_t last_used;
	/* the scavenger, see truenas_hastate_scavenger_start() */
	bool scavenger;
	uint64_t resent_instance;	/* 0: none */
};

_PRIVATE_ extern struct tn_client tn_c;

/* conn.c */
_PRIVATE_ void tn_this_process(void);
_PRIVATE_ void tn_disconnect(void);
_PRIVATE_ void tn_failed(const char *what, int err);
_PRIVATE_ bool tn_connect(uint32_t role);
_PRIVATE_ void tn_reconnect_later(void);
_PRIVATE_ void tn_watch(void);
_PRIVATE_ const char *tn_epoch_path(void);
_PRIVATE_ bool tn_fallback_fence(void);

/* record.c */
_PRIVATE_ bool tn_is(const struct files_struct *fsp, uint64_t flag);
_PRIVATE_ void tn_set(struct files_struct *fsp, uint64_t flag, bool on);
_PRIVATE_ bool tn_locks_survive(uint32_t lease_type,
				const struct share_params *params);
_PRIVATE_ bool tn_fsp_survives(struct files_struct *fsp);
_PRIVATE_ bool tn_recorded(const struct files_struct *fsp);
_PRIVATE_ uint64_t tn_fsid(const struct statfs *sfs);
_PRIVATE_ void tn_record_from_open(struct truenas_durable_record *r,
				   const struct smbXsrv_open_global0 *global,
				   const struct share_mode_entry *e,
				   uint64_t fsid,
				   const struct file_id *id);
_PRIVATE_ bool tn_record_locks(TALLOC_CTX *mem_ctx,
			       struct truenas_durable_record *r,
			       const struct lock_struct *locks,
			       unsigned int n,
			       uint64_t id);
_PRIVATE_ void tn_baseline(struct files_struct *fsp);
_PRIVATE_ int tn_put_record(struct smbhad_batch *b,
			    struct files_struct *fsp,
			    bool disconnected);
_PRIVATE_ int tn_put_marker(struct smbhad_batch *b,
			    const struct tn_marker *m);

/* send.c */
_PRIVATE_ void tn_unlink_pending(struct tn_pending *p);
_PRIVATE_ void tn_unmark(struct files_struct *fsp);
_PRIVATE_ void tn_mark(struct files_struct *fsp);
_PRIVATE_ void tn_mark_delete(uint64_t id);
_PRIVATE_ void tn_pending_to_delete(struct tn_pending *p);
_PRIVATE_ void tn_mark_marker(struct tn_marker *m);
_PRIVATE_ void tn_drop_marker(struct tn_marker *m);
_PRIVATE_ bool tn_submit(uint32_t sync,
			 struct files_struct *fsp,
			 bool disconnected);
_PRIVATE_ NTSTATUS tn_promise(struct files_struct *fsp);
_PRIVATE_ void tn_resubmit_all(void);
_PRIVATE_ void tn_resend_disconnected(uint64_t instance);

#endif
