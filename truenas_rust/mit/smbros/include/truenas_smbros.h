/*
 * Copyright (C) iXsystems, Inc. 2026
 * SPDX-License-Identifier: MIT
 *
 * truenas_smbros is a shim between an SMB server and truenas_ros. Each
 * adopted connection gets a reactor. A reactor is a
 * thread with its own io_uring ring. The reactor reads whole PDUs and
 * queues them for the thread of the caller. It sends the PDUs that the
 * caller gives it. The caller polls one eventfd per process for the queue.
 *
 * The shim knows the framing of a PDU and nothing of its content. A layer
 * above the shim can see each PDU first and give jobs to the reactors.
 * truenas_smb_server.h is that layer for smbd.
 */

#ifndef TRUENAS_SMBROS_H
#define TRUENAS_SMBROS_H

/* Made by cbindgen from src/. Do not edit. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

/**
 * The event kind for a new PDU of a connection.
 */
#define TN_SMBROS_PDU 1

/**
 * The event kind for a closed connection.
 */
#define TN_SMBROS_CLOSED 2

/**
 * The event kind for lent memory that the reactor no longer uses. See
 * `tn_smbros_send()`.
 */
#define TN_SMBROS_SENT 3

/**
 * The layer above the shim uses the event kinds from this value up.
 */
#define TN_SMBROS_UPPER 16

/**
 * One adopted connection, from `tn_smbros_adopt()`.
 */
struct tn_smbros_conn;

/**
 * The context of a process, from `tn_smbros_ctx_new()`.
 */
struct tn_smbros_ctx;

/**
 * An event for the caller, from `tn_smbros_next()`.
 */
struct tn_smbros_event {
        /**
         * The `cookie` of `tn_smbros_adopt()` in a PDU or CLOSED event. The
         * `sent_cookie` of `tn_smbros_send()` in a SENT event.
         */
        uint64_t cookie;
        /**
         * `TN_SMBROS_PDU`, `TN_SMBROS_CLOSED`, `TN_SMBROS_SENT` or a kind of
         * the layer above the shim.
         */
        int kind;
        /**
         * The first byte of the NBT header in a PDU event.
         */
        uint8_t nbt_type;
        /**
         * The message of a PDU event, without the 4-byte NBT header.
         */
        uint8_t *data;
        size_t len;
        /**
         * The buffer of a PDU event. It owns `data`. Free it with
         * `tn_smbros_buf_free()`.
         */
        void *buf;
        /**
         * The errno of a CLOSED event. 0 means that the peer closed the
         * connection.
         */
        int error;
        /**
         * In a PDU event, `flags`, `status` and `tag` are values of the layer
         * above the shim. The header of that layer describes them.
         */
        uint32_t flags;
        uint32_t status;
        uint64_t tag;
};

/**
 * A function that runs a new PDU on the reactor thread that calls it. It
 * returns true if it ran the PDU. Then it owns `ev->buf`, as with an event
 * from `tn_smbros_next()`. If it returns false, it does not keep or free
 * `ev->buf`. Then the shim queues the PDU. The arguments are the `private`
 * pointer of `tn_smbros_ctx_inline()` and the event.
 */
typedef bool (*tn_smbros_inline_fn)(void*,
                                    struct tn_smbros_event*);

/**
 * Free the buffer of a PDU event.
 *
 * # Safety
 *
 * `buf` is NULL or the `buf` of a PDU event. The caller does not use it
 * after this call.
 */
void tn_smbros_buf_free(void *buf);

/**
 * True if `tn_smbros_close()` has not run for the connection of `buf`.
 * False if `buf` is NULL.
 *
 * # Safety
 *
 * `buf` is NULL or the live `buf` of a PDU event.
 */
bool tn_smbros_buf_open(const void *buf);

/**
 * True if the PDU of `buf` can still get a job. The layer above the shim
 * selects such PDUs on a connection adopted with `delegate`. Such a PDU
 * counts against `max_in_flight` until the caller gives it a job or
 * releases it.
 *
 * # Safety
 *
 * `buf` is NULL or the live `buf` of a PDU event.
 */
bool tn_smbros_buf_delegable(const void *buf);

/**
 * Release the PDU of `buf` without a job. Call this as soon as the caller
 * knows that the PDU gets no job. Then the reactor can read more PDUs.
 * `tn_smbros_buf_free()` also releases the PDU.
 *
 * # Safety
 *
 * `buf` is NULL or the live `buf` of a PDU event.
 */
void tn_smbros_buf_release(void *buf);

/**
 * Serve the connected socket `sock` on a new reactor thread. The reactor
 * uses a duplicate of `sock`. The caller still owns `sock`.
 * `max_in_flight` bounds the PDUs in the queue, the PDUs that can still
 * get a job and the jobs that run. With `delegate`, the caller can give
 * the reactor a job for a PDU. The layer above the shim has the function
 * for that. A file read of a job of `async_read_min` bytes or more carries
 * `IOSQE_ASYNC`. A hot read on ZFS does not sleep, so without the flag one
 * io-wq worker runs all such reads of the ring. `async_write_min` does the
 * same for writes. A flagged write skips the kernel's queue for its file,
 * so the writes of one file can run at the same time. `usize::MAX` flags
 * none. `truenas_ros` has one floor, so the smaller one applies to both.
 * The reactor thread is named `smbros-<n>`, numbered from 0 in each
 * process.
 * NULL on failure, with the errno in `*err` if `err` is not NULL.
 *
 * # Safety
 *
 * `ctx` is a live context from `tn_smbros_ctx_new()`. `sock` is an open
 * descriptor. `err` is NULL or writable.
 */
struct tn_smbros_conn *tn_smbros_adopt(struct tn_smbros_ctx *ctx,
                                       int sock,
                                       uint64_t cookie,
                                       uint32_t max_in_flight,
                                       bool delegate,
                                       size_t async_read_min,
                                       size_t async_write_min,
                                       int *err);

/**
 * Stop the reactor of `conn` and free `conn`. After that,
 * `tn_smbros_next()` returns no PDU or CLOSED event of `conn`.
 *
 * # Safety
 *
 * `conn` is NULL or a connection from `tn_smbros_adopt()`. The caller does
 * not use `conn` after this call.
 */
void tn_smbros_close(struct tn_smbros_conn *conn);

/**
 * The identity of root on `conn`. An identity is an `io_uring` personality
 * in the ring of a reactor. The kernel does the file I/O of a job with the
 * credentials of one identity. An identity is a number other than 0. It is
 * valid only for its own `conn`.
 *
 * The reactor registers root with the credentials of the thread that
 * called `tn_smbros_adopt()`. So call `tn_smbros_adopt()` as root.
 *
 * # Safety
 *
 * `conn` is a live connection from `tn_smbros_adopt()`.
 */
uint16_t tn_smbros_conn_root(const struct tn_smbros_conn *conn);

/**
 * Register the current credentials of the calling thread as an identity
 * on `conn`. Any thread can call this. The identity does not change when
 * the thread changes its credentials later. 0 on failure, with the errno
 * in `*err` if `err` is not NULL.
 *
 * # Safety
 *
 * `conn` is a live connection from `tn_smbros_adopt()`. `err` is NULL or
 * writable.
 */
uint16_t tn_smbros_conn_register_self(const struct tn_smbros_conn *conn,
                                      int *err);

/**
 * Make the context of the process. Use one per process. NULL on failure,
 * with errno set.
 */
struct tn_smbros_ctx *tn_smbros_ctx_new(void);

/**
 * Stop the reactors of `ctx` and wait for their threads to end. Drop the
 * events that `tn_smbros_next()` did not return. Free `ctx`. After that,
 * no reactor uses memory of the caller. Call this on the thread of
 * `tn_smbros_next()`. The caller still closes each connection with
 * `tn_smbros_close()`. In a forked child, this call does nothing.
 *
 * # Safety
 *
 * `ctx` is NULL or a context from `tn_smbros_ctx_new()`. The caller does
 * not use `ctx` after this call.
 */
void tn_smbros_ctx_free(struct tn_smbros_ctx *ctx);

/**
 * The eventfd that becomes readable when the queue has events.
 *
 * # Safety
 *
 * `ctx` is a live context from `tn_smbros_ctx_new()`.
 */
int tn_smbros_ctx_fd(const struct tn_smbros_ctx *ctx);

/**
 * Clear the eventfd. Call this before the calls to `tn_smbros_next()` that
 * empty the queue.
 *
 * # Safety
 *
 * `ctx` is a live context from `tn_smbros_ctx_new()`.
 */
void tn_smbros_ctx_ack(struct tn_smbros_ctx *ctx);

/**
 * Make the eventfd readable, even if the queue is empty. This wakes the
 * thread of `tn_smbros_next()`.
 *
 * # Safety
 *
 * `ctx` is a live context from `tn_smbros_ctx_new()`.
 */
void tn_smbros_ctx_wake(const struct tn_smbros_ctx *ctx);

/**
 * Set the inline function of the reactors to `func`. Call this before the
 * first `tn_smbros_adopt()`. A reactor calls `func` with `private` and each
 * new PDU. It does not call `func` while its connection has a PDU in the
 * queue. False if `func` is NULL or the reactors have a function already.
 *
 * # Safety
 *
 * `ctx` is a live context from `tn_smbros_ctx_new()`. `func` with
 * `private` is safe to call on any reactor thread until
 * `tn_smbros_ctx_free()`.
 */
bool tn_smbros_ctx_inline(struct tn_smbros_ctx *ctx,
                          bool (*func)(void*,
                                       struct tn_smbros_event*),
                          void *private_);

/**
 * Move the next event of the queue to `*ev`. False if the queue is empty.
 * This call drops the PDU and CLOSED events of a closed connection. It
 * returns every SENT event.
 *
 * # Safety
 *
 * `ctx` is a live context from `tn_smbros_ctx_new()`. `ev` points to
 * writable memory for one event.
 */
bool tn_smbros_next(struct tn_smbros_ctx *ctx,
                    struct tn_smbros_event *ev);

/**
 * Queue the PDU in `iov` for sending. The shim copies the vectors shorter
 * than `lend_min`. The reactor sends the others from the caller's memory.
 * The call sets `*lent` to true if there are any. If so, the caller keeps
 * those vectors valid and unchanged until `tn_smbros_next()` returns
 * `TN_SMBROS_SENT` with `sent_cookie`. Returns 0 or an errno.
 *
 * # Safety
 *
 * `conn` is a live connection from `tn_smbros_adopt()`. `iov` points to
 * `iovcnt` vectors of readable memory. `iov` can be NULL if `iovcnt` is 0.
 * `lent` is writable. The caller keeps the vectors of `lend_min` bytes or
 * more valid and unchanged until `TN_SMBROS_SENT` with `sent_cookie`.
 */
int tn_smbros_send(struct tn_smbros_conn *conn,
                   const struct iovec *iov,
                   int iovcnt,
                   size_t lend_min,
                   uint64_t sent_cookie,
                   bool *lent);

#endif  /* TRUENAS_SMBROS_H */
