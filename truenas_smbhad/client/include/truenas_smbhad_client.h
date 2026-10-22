/*
 * The client of truenas_smbhad in smbd, see truenas_smbhad/client.
 *
 * Copyright (C) iXsystems, Inc. 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Include the headers of Samba with struct GUID, struct dom_sid and
 * struct smb2_lease_key first.
 */

#ifndef _TRUENAS_SMBHAD_CLIENT_H_
#define _TRUENAS_SMBHAD_CLIENT_H_

/* Made by cbindgen from src/ffi.rs. Do not edit. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * smbd restored the open.
 */
#define TRUENAS_ZFS_DURABLE_RESTORED 1

/**
 * Unflushed changes from before the disconnect.
 */
#define TRUENAS_ZFS_DURABLE_DIRTY 2

/**
 * A flush does not write the data to disk: the dataset has
 * sync=disabled, or smbd cannot read its sync property.
 */
#define TRUENAS_ZFS_DURABLE_NO_SYNC 4

/**
 * The kinds of smbd process: `role` of `smbhad_connect()`.
 */
#define TN_WORKER 1

/**
 * The parent: rehydrate and done.
 */
#define TN_PARENT 2

/**
 * cleanupd: forget.
 */
#define TN_CLEANUPD 3

/**
 * No reply to the submit.
 */
#define TN_SYNC_NONE 0

/**
 * The reply comes after the daemon applied the operations.
 */
#define TN_SYNC_LOCAL 1

/**
 * The reply comes after the standby has the operations or the daemon
 * fenced the copy of the standby.
 */
#define TN_SYNC_REMOTE 2

/**
 * No copy to restore.
 */
#define TN_ORIGIN_NONE 0

/**
 * smbd on this controller wrote the copy.
 */
#define TN_ORIGIN_OWN 1

/**
 * The other controller sent the copy.
 */
#define TN_ORIGIN_REPLICA 2

/**
 * Node A of the HA pair.
 */
#define TN_NODE_A 1

/**
 * Node B of the HA pair.
 */
#define TN_NODE_B 2

/**
 * `smbhad_batch_put()` added the put.
 */
#define TN_PUT_OK 0

/**
 * The record is larger than the daemon accepts. `smbhad_batch_put()` added
 * a delete instead: the standby does not restore the handle.
 */
#define TN_PUT_DELETED 1

/**
 * The record has a value without an encoding. The batch did not change.
 */
#define TN_PUT_FAILED 2

/**
 * The record version that this version writes and reads.
 */
#define TRUENAS_DURABLE_RECORD_VERSION 1

/**
 * The handle is disconnected.
 */
#define TRUENAS_DURABLE_DISCONNECTED 1

/**
 * The handle has unflushed changes.
 */
#define TRUENAS_DURABLE_DIRTY 2

/**
 * Later lock changes can be missing from the record.
 */
#define TRUENAS_DURABLE_LOCKS_UNSTABLE 4

/**
 * Not a handle: a marker. The file has delete on close. The restore drops
 * all records of the file.
 */
#define TRUENAS_DURABLE_DELETE_PENDING 16

/**
 * The operations of one or more submits.
 */
struct smbhad_batch;

/**
 * A connection to the daemon.
 */
struct smbhad_conn;

/**
 * The reply to the hello.
 */
struct smbhad_hello {
        /**
         * A new value each time the daemon starts
         */
        uint64_t instance;
        /**
         * smbd fences through this file
         */
        const char *epoch_file;
        /**
         * This controller: `TN_NODE_A` or `TN_NODE_B`
         */
        uint32_t node;
};

/**
 * A byte range lock of the open. `struct truenas_durable_lock` in C.
 */
struct truenas_durable_lock {
        /**
         * The first byte.
         */
        uint64_t start;
        /**
         * The number of bytes.
         */
        uint64_t size;
        /**
         * Samba's `enum brl_type`.
         */
        uint32_t lock_type;
        /**
         * Samba's `enum brl_flavour`.
         */
        uint32_t lock_flav;
};

/**
 * The record of a durable handle, see `record::RecordV1`.
 */
struct truenas_durable_record {
        /**
         * `TRUENAS_DURABLE_*`
         */
        uint32_t flags;
        /**
         * NTTIME
         */
        uint64_t updated;
        /**
         * The change cookie of the file as the client knows it
         */
        uint64_t change_cookie;
        /**
         * The path of the share
         */
        const char *servicepath;
        /**
         * The path of the file in the share
         */
        const char *base_name;
        /**
         * statfs `f_fsid` of the file
         */
        uint64_t fsid;
        /**
         * The inode of the file
         */
        uint64_t inode;
        /**
         * The generation of the inode
         */
        uint64_t extid;
        /**
         * The hash of the name
         */
        uint32_t name_hash;
        /**
         * The persistent id of the open
         */
        uint64_t persistent_id;
        /**
         * The volatile id of the open
         */
        uint64_t volatile_id;
        /**
         * The owner of the open
         */
        struct dom_sid owner;
        /**
         * NTTIME
         */
        uint64_t open_time;
        /**
         * The create GUID
         */
        struct GUID create_guid;
        /**
         * The client GUID
         */
        struct GUID client_guid;
        /**
         * The app instance id
         */
        struct GUID app_instance_id;
        /**
         * The create action
         */
        uint32_t create_action;
        /**
         * NTTIME
         */
        uint64_t disconnect_time;
        /**
         * The durable timeout
         */
        uint32_t durable_timeout_msec;
        /**
         * The channel sequence
         */
        uint16_t channel_sequence;
        /**
         * The channel generation
         */
        uint64_t channel_generation;
        /**
         * The lock sequence array
         */
        uint8_t lock_sequence_array[64];
        /**
         * The values of the share mode entry
         */
        uint32_t op_type;
        /**
         * The lease key
         */
        struct smb2_lease_key lease_key;
        /**
         * The access mask
         */
        uint32_t access_mask;
        /**
         * The share access
         */
        uint32_t share_access;
        /**
         * NTTIME
         */
        uint64_t share_time;
        /**
         * The uid
         */
        uint32_t uid;
        /**
         * The flags of the share mode entry
         */
        uint32_t share_flags;
        /**
         * The state of the lease
         */
        uint32_t lease_state;
        /**
         * The version of the lease
         */
        uint16_t lease_version;
        /**
         * The epoch of the lease
         */
        uint16_t lease_epoch;
        /**
         * The values of the `vfs_default` durable cookie
         */
        uint64_t initial_allocation_size;
        /**
         * See `initial_allocation_size`
         */
        uint64_t position_information;
        /**
         * See `initial_allocation_size`
         */
        bool write_time_forced;
        /**
         * The number of locks
         */
        uint32_t num_locks;
        /**
         * The locks
         */
        const struct truenas_durable_lock *locks;
};

/**
 * A record in a page of the copy.
 */
struct smbhad_put {
        /**
         * The share
         */
        const char *share;
        /**
         * The encoded record, see `smbhad_record_decode()`
         */
        const uint8_t *body;
        /**
         * The length of `body`
         */
        size_t body_len;
};

/**
 * A page of the copy.
 */
struct smbhad_page {
        /**
         * `TN_ORIGIN_*`
         */
        uint32_t origin;
        /**
         * The node that wrote the copy: `TN_NODE_A` or `TN_NODE_B`
         */
        uint32_t writer_node;
        /**
         * The cursor of the next page
         */
        uint64_t next_cursor;
        /**
         * This is the last page
         */
        bool last;
        /**
         * The number of records
         */
        size_t num_records;
        /**
         * The records, in id order
         */
        const struct smbhad_put *records;
};

/**
 * The durable cookie of `vfs_zfs_core`. The share and the inner cookie are
 * not NUL-terminated.
 */
struct smbhad_cookie {
        /**
         * `TRUENAS_ZFS_DURABLE_*`
         */
        uint32_t flags;
        /**
         * The change cookie of the file
         */
        uint64_t change_cookie;
        /**
         * The share
         */
        const uint8_t *share;
        /**
         * The length of `share`
         */
        size_t share_len;
        /**
         * The `vfs_default` cookie
         */
        const uint8_t *inner;
        /**
         * The length of `inner`
         */
        size_t inner_len;
};

/**
 * Connects to the daemon at `path` as root and sends the hello of the
 * process `pid` with `unique_id`. A read or write that takes longer than
 * `timeout_ms` fails, also in later calls.
 *
 * # Safety
 *
 * `path` is a NUL-terminated string. `out` is valid for a write.
 */
int smbhad_connect(const char *path,
                   uint32_t role,
                   uint32_t pid,
                   uint64_t unique_id,
                   uint32_t timeout_ms,
                   struct smbhad_conn **out);

/**
 * The reply to the hello. It lives as long as `c`.
 *
 * # Safety
 *
 * `c` is a connection of `smbhad_connect()`.
 */
const struct smbhad_hello *smbhad_conn_hello(const struct smbhad_conn *c);

/**
 * The socket of `c`. The daemon sends nothing unasked: a readable socket
 * between two calls is closed.
 *
 * # Safety
 *
 * `c` is a connection of `smbhad_connect()`.
 */
int smbhad_conn_fd(const struct smbhad_conn *c);

/**
 * Closes the socket of `c` and frees `c`. A child process frees the
 * connection of its parent: the connection of the parent stays open.
 *
 * # Safety
 *
 * `c` is NULL or a connection of `smbhad_connect()`. `c` is not used
 * after the call.
 */
void smbhad_conn_free(struct smbhad_conn *c);

/**
 * The text of the last error of this thread.
 */
const char *smbhad_last_error(void);

/**
 * A new empty batch.
 */
struct smbhad_batch *smbhad_batch_new(void);

/**
 * Frees `b`.
 *
 * # Safety
 *
 * `b` is NULL or a batch of `smbhad_batch_new()`, not used after the
 * call.
 */
void smbhad_batch_free(struct smbhad_batch *b);

/**
 * Adds the put of `r` to `b`. `pid` and `unique_id` are the process that
 * holds the handle: 0 and 0 for a disconnected handle. Returns `TN_PUT_OK`,
 * `TN_PUT_DELETED` or `TN_PUT_FAILED`.
 *
 * # Safety
 *
 * `b` is a batch, `share` a NUL-terminated string, and `r` a record whose
 * strings are NUL-terminated and whose `locks` has `num_locks` locks.
 */
int smbhad_batch_put(struct smbhad_batch *b,
                     const char *share,
                     uint32_t pid,
                     uint64_t unique_id,
                     const struct truenas_durable_record *r);

/**
 * Adds a delete of the record of `id` to `b`.
 *
 * # Safety
 *
 * `b` is a batch of `smbhad_batch_new()`.
 */
void smbhad_batch_del(struct smbhad_batch *b, uint64_t id);

/**
 * The encoded size of the operations of `b`.
 *
 * # Safety
 *
 * `b` is a batch of `smbhad_batch_new()`.
 */
size_t smbhad_batch_bytes(const struct smbhad_batch *b);

/**
 * The number of operations of `b`.
 *
 * # Safety
 *
 * `b` is a batch of `smbhad_batch_new()`.
 */
size_t smbhad_batch_len(const struct smbhad_batch *b);

/**
 * Sends the operations of `b` and empties `b`. `sync` is `TN_SYNC_*`.
 * With `TN_SYNC_NONE`, the daemon does not reply. Else the call waits for
 * the reply.
 *
 * # Safety
 *
 * `c` is a connection and `b` a batch.
 */
int smbhad_submit(struct smbhad_conn *c, struct smbhad_batch *b, uint32_t sync);

/**
 * Reports that the process `pid` exited uncleanly. The daemon keeps the
 * handles of a live process with this pid.
 *
 * # Safety
 *
 * `c` is a connection of `smbhad_connect()`.
 */
int smbhad_forget(struct smbhad_conn *c, uint32_t pid);

/**
 * Reads the page of the copy at `cursor`, 0 for the first page. Free the
 * page with `smbhad_page_free()`.
 *
 * # Safety
 *
 * `c` is a connection, `out` valid for a write.
 */
int smbhad_rehydrate(struct smbhad_conn *c,
                     uint64_t cursor,
                     uint32_t max_bytes,
                     struct smbhad_page **out);

/**
 * Frees a page of `smbhad_rehydrate()`.
 *
 * # Safety
 *
 * `p` is NULL or a page of `smbhad_rehydrate()`, not used after the call.
 */
void smbhad_page_free(struct smbhad_page *p);

/**
 * Ends the rehydration.
 *
 * # Safety
 *
 * `c` is a connection of `smbhad_connect()`.
 */
int smbhad_done(struct smbhad_conn *c);

/**
 * Decodes a record. NULL if `buf` is not a record that this version can
 * restore. Free the record with `smbhad_record_free()`.
 *
 * # Safety
 *
 * `buf` has `len` bytes.
 */
struct truenas_durable_record *smbhad_record_decode(const uint8_t *buf, size_t len);

/**
 * Frees a record of `smbhad_record_decode()`.
 *
 * # Safety
 *
 * `r` is NULL or a record of `smbhad_record_decode()`, not used after the
 * call.
 */
void smbhad_record_free(struct truenas_durable_record *r);

/**
 * Encodes `c` into `buf` if `len` is large enough. Returns the length of
 * the encoded cookie, or 0 if `c` has no encoding.
 *
 * # Safety
 *
 * The pointers of `c` have their lengths. `buf` is NULL or has `len`
 * bytes.
 */
size_t smbhad_cookie_encode(const struct smbhad_cookie *c, uint8_t *buf, size_t len);

/**
 * Decodes the cookie in `buf` into `out`. The share and the inner cookie
 * of `out` point into `buf`. False if `buf` is not a cookie of
 * `vfs_zfs_core` of this version.
 *
 * # Safety
 *
 * `buf` has `len` bytes. `out` is valid for a write.
 */
bool smbhad_cookie_decode(const uint8_t *buf, size_t len, struct smbhad_cookie *out);

/**
 * The fence of smbd when it cannot reach the daemon, see
 * `EpochFile::fence()`. `fenced_to` is the epoch of the last fence of the
 * process, or 0. Writes the epoch that the fence wrote, or 0, to `next`.
 *
 * # Safety
 *
 * `path` is a NUL-terminated string. `next` is valid for a write.
 */
int smbhad_epoch_fence(const char *path, uint64_t fenced_to, uint64_t *next);

#endif  /* _TRUENAS_SMBHAD_CLIENT_H_ */
