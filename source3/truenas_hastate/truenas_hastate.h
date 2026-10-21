/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * TrueNAS: the HA state of durable handles. smbd sends it to
 * truenas_smbhad. Durable handles survive an HA failover.
 *
 * Copyright (C) iXsystems, Inc. 2026
 */

#ifndef _TRUENAS_HASTATE_H_
#define _TRUENAS_HASTATE_H_

struct files_struct;
struct messaging_context;

/* smbd children, see the call sites */
NTSTATUS truenas_hastate_open(struct files_struct *fsp,
			      bool reconnect);
void truenas_hastate_disconnect(struct files_struct *fsp);
void truenas_hastate_close(struct files_struct *fsp);
NTSTATUS truenas_hastate_dirty(struct files_struct *fsp);
void truenas_hastate_flushed(struct files_struct *fsp);
void truenas_hastate_update(struct files_struct *fsp);
void truenas_hastate_lease(struct files_struct *fsp,
			   uint32_t old_state);
NTSTATUS truenas_hastate_locked(struct files_struct *fsp);
void truenas_hastate_delete_on_close(struct files_struct *fsp,
				     bool delete_on_close);
void truenas_hastate_fsp_freed(struct files_struct *fsp);
void truenas_hastate_renamed(struct files_struct *fsp);
void truenas_hastate_forget(uint64_t open_persistent_id);
void truenas_hastate_forget_pid(pid_t pid);
void truenas_hastate_exit(void);

/* the scavenger */
void truenas_hastate_scavenger_start(void);

/*
 * The durable cookie of vfs_zfs_core, see smbhad_cookie_encode(). The flags
 * are TRUENAS_ZFS_DURABLE_*. inner is the vfs_default cookie.
 */
struct truenas_zfs_durable_cookie {
	uint32_t flags;
	uint64_t change_cookie;
	const char *share;
	DATA_BLOB inner;
};

/* Encode zc. blob is allocated on mem_ctx. */
bool truenas_zfs_durable_cookie_push(
	TALLOC_CTX *mem_ctx,
	const struct truenas_zfs_durable_cookie *zc,
	DATA_BLOB *blob);

/*
 * Decode blob into zc. zc->share and zc->inner are allocated on mem_ctx.
 * False if blob is not a cookie of vfs_zfs_core of this version.
 */
bool truenas_zfs_durable_cookie_pull(TALLOC_CTX *mem_ctx,
				     const DATA_BLOB *blob,
				     struct truenas_zfs_durable_cookie *zc);

/* smbd parent, before it accepts connections */
void truenas_hastate_restore(struct messaging_context *msg_ctx);

#endif /* _TRUENAS_HASTATE_H_ */
