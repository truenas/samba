/*
 * Copyright (C) iXsystems, Inc. 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * truenas_smb_server is the layer of smbd on the reactors of
 * truenas_smbros.h. The reactors sign, check, encrypt and
 * decrypt PDUs with the functions and keys of the caller. They do the file
 * I/O of the SMB2 READ, WRITE and FLUSH requests that the caller gives
 * them.
 */

#ifndef TRUENAS_SMB_SERVER_H
#define TRUENAS_SMB_SERVER_H

/* Made by cbindgen from src/. Do not edit. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>
#include "truenas_smbros.h"

/**
 * An event kind of `tn_smbros_next()`. The last job of a file ended.
 * `cookie` is the cookie of `tn_smbsrv_file_new()`. See
 * `tn_smbsrv_file_busy()`.
 */
#define TN_SMBSRV_IDLE TN_SMBROS_UPPER

/**
 * An event kind of `tn_smbros_next()`. `buf` is a key that the caller gave
 * to `tn_smbsrv_session_keys()`. No reactor uses the key now. The caller
 * frees it.
 */
#define TN_SMBSRV_KEY_FREE (TN_SMBROS_UPPER + 1)

/**
 * A flag of a PDU event. The reactor decrypted the request. `data` has the
 * transform header and the decrypted message. `tag` has the generation of
 * the keys. See `tn_smbsrv_session_keys()`.
 */
#define TN_SMBSRV_DECRYPTED 1

/**
 * A flag of a PDU event. The reactor could not decrypt the request. The
 * attempt changed `data`. `status` has the NTSTATUS. `tag` has the
 * generation of the keys.
 */
#define TN_SMBSRV_DECRYPT_FAILED 2

/**
 * A flag of a PDU event. Each signature of the request is correct. `tag`
 * has the generation of the keys.
 */
#define TN_SMBSRV_SIGNED_OK 4

/**
 * The reactor sends the reply of a job as it is.
 */
#define TN_SMBSRV_SEAL_NONE 0

/**
 * The reactor signs the reply of a job.
 */
#define TN_SMBSRV_SEAL_SIGN 1

/**
 * The reactor encrypts the reply of a job.
 */
#define TN_SMBSRV_SEAL_ENCRYPT 2

/**
 * One job of a file, from `tn_smbsrv_file_hold()`. The file counts the job
 * until the hold is freed. The job is pending until the caller gives the
 * hold to `tn_smbsrv_delegate()`. Then the job is running.
 */
struct tn_smbsrv_hold;

/**
 * The keys of one session on one connection, from
 * `tn_smbsrv_session_keys()`. A `struct tn_smbsrv_keys` pointer is one
 * reference to them.
 */
struct tn_smbsrv_keys;

/**
 * An open file of the caller, from `tn_smbsrv_file_new()`. The reactors
 * do file I/O with the descriptor of the caller. The file counts each job
 * from `tn_smbsrv_file_hold()` until the hold is freed. A job is pending
 * until the caller gives its hold to `tn_smbsrv_delegate()`. Then the job
 * is running. The caller closes the descriptor only after
 * `tn_smbsrv_file_close()`. So the number cannot refer to another file
 * while a job uses it.
 */
struct tn_smbsrv_file;

/**
 * The SMB2 signing and encryption functions of the caller. The reactors
 * call them on their own threads with the keys from
 * `tn_smbsrv_session_keys()`. `iov[0]` is the SMB2 header or the transform
 * header. `iov[1]` is the rest. Each function works in place. It returns
 * an NTSTATUS. `check` does not change the PDU.
 */
struct tn_smbsrv_crypto {
        /**
         * Each reactor thread calls this first. NULL is allowed.
         */
        void (*thread_init)(void);
        uint32_t (*sign)(void*,
                         struct iovec*,
                         int);
        uint32_t (*check)(void*,
                          struct iovec*,
                          int);
        uint32_t (*encrypt)(void*,
                            struct iovec*,
                            int);
        uint32_t (*decrypt)(void*,
                            struct iovec*,
                            int);
};

/**
 * One SMB2 message of a reply that `tn_smbsrv_send_sealed()` signs.
 */
struct tn_smbsrv_sign_part {
        /**
         * Keys from `tn_smbsrv_keys_pin()`. The reactor signs the message with
         * their signing key.
         */
        struct tn_smbsrv_keys *keys;
        /**
         * The message is the `iovcnt` vectors of the reply that start at index
         * `iov`.
         */
        int iov;
        int iovcnt;
};

/**
 * The file I/O of a job, for `tn_smbsrv_delegate()`.
 */
struct tn_smbsrv_io {
        /**
         * The SMB2 opcode. READ is 8, WRITE is 9 and FLUSH is 7.
         */
        uint16_t opcode;
        /**
         * The kernel does the I/O with the credentials of this identity of
         * `conn`. See `tn_smbros_conn_register_self()`. It must not be 0.
         */
        uint16_t who;
        /**
         * A `TN_SMBSRV_SEAL_*` value for the reply.
         */
        int seal;
        /**
         * The file offset and the byte count of a READ or WRITE.
         */
        uint64_t offset;
        uint32_t count;
        /**
         * A READ of less data than this gets an error response.
         */
        uint32_t minimum;
        /**
         * The offset of the WRITE data in the `data` of the PDU event.
         */
        size_t data_ofs;
};

/**
 * Attach this layer to the reactors of `ctx`. Call this one time, before
 * the first `tn_smbros_adopt()`. `ops` is the table of crypto functions or
 * NULL. `errmap` has the NTSTATUS of each errno below `len`. The reactors
 * use it for the error responses of jobs. They use
 * `NT_STATUS_UNSUCCESSFUL` if `errmap` has 0 or no value for the errno.
 * False if `ctx` has a layer already.
 *
 * # Safety
 *
 * `ctx` is from `tn_smbros_ctx_new()`. `ops` is NULL or a table of
 * functions that any reactor thread can call. `errmap` is NULL or has
 * `len` values.
 */
bool tn_smbsrv_attach(struct tn_smbros_ctx *ctx,
                      const struct tn_smbsrv_crypto *ops,
                      const uint32_t *errmap,
                      size_t len);

/**
 * Give the reactor of `conn` the keys of `session_id`. `sign` is the
 * signing key of the channel. `encrypt` is the key for replies. `decrypt`
 * is the key for requests. The new keys replace the old keys of the
 * session on `conn`. `generation` is the caller's number for these keys.
 *
 * This function takes ownership of the keys in all cases. Later,
 * `tn_smbros_next()` returns each key in a `TN_SMBSRV_KEY_FREE` event.
 * Returns 0, or ENOTSUP if the reactors have no crypto functions.
 *
 * # Safety
 *
 * `conn` is from `tn_smbros_adopt()`. Each key is NULL or a key for the
 * crypto functions of smbd. The caller does not give the same key to
 * another connection.
 */
int tn_smbsrv_session_keys(struct tn_smbros_conn *conn,
                           uint64_t session_id,
                           uint64_t generation,
                           void *sign,
                           void *encrypt,
                           void *decrypt);

/**
 * Remove the keys of `session_id` from `conn`. References from
 * `tn_smbsrv_keys_pin()` are still valid.
 *
 * # Safety
 *
 * `conn` is from `tn_smbros_adopt()`.
 */
void tn_smbsrv_session_drop(struct tn_smbros_conn *conn,
                            uint64_t session_id);

/**
 * A reference to the keys of `session_id` on `conn`. NULL if `conn` has no
 * keys of `session_id` with this `generation`. Give the reference to
 * `tn_smbsrv_delegate()` or `tn_smbsrv_send_sealed()`, or free it with
 * `tn_smbsrv_keys_unpin()`.
 *
 * # Safety
 *
 * `conn` is from `tn_smbros_adopt()`.
 */
struct tn_smbsrv_keys *tn_smbsrv_keys_pin(struct tn_smbros_conn *conn,
                                          uint64_t session_id,
                                          uint64_t generation);

/**
 * Free a reference from `tn_smbsrv_keys_pin()`. NULL is allowed.
 *
 * # Safety
 *
 * `pin` is NULL or is from `tn_smbsrv_keys_pin()`. The caller does not use
 * it again.
 */
void tn_smbsrv_keys_unpin(struct tn_smbsrv_keys *pin);

/**
 * Queue the reply in `iov` like `tn_smbros_send()` does. The reactor signs
 * or encrypts the reply before it sends it. Pass `encrypt` or `sign`, not
 * both. With `encrypt`, the caller puts the transform header with the
 * nonce after the NBT header. The reactor then encrypts the PDU with the
 * encryption key of `encrypt`. With `sign`, the reactor signs each of the
 * `nsign` messages in `sign`. The reactor closes the connection if it
 * cannot sign or encrypt the reply.
 *
 * In all cases, this function takes ownership of `encrypt` and of the keys
 * in `sign`. Returns 0 or an errno. ENOKEY if a part has no signing key or
 * the reactors have no crypto functions.
 *
 * # Safety
 *
 * The conditions of `tn_smbros_send()` apply. `sign` is NULL or has
 * `nsign` parts. `encrypt` and the keys of each part are NULL or are from
 * `tn_smbsrv_keys_pin()`. The caller does not use them again.
 */
int tn_smbsrv_send_sealed(struct tn_smbros_conn *conn,
                          const struct iovec *iov,
                          int iovcnt,
                          size_t lend_min,
                          uint64_t sent_cookie,
                          bool *lent,
                          struct tn_smbsrv_keys *encrypt,
                          const struct tn_smbsrv_sign_part *sign,
                          size_t nsign);

/**
 * Give the file I/O of the SMB2 READ, WRITE or FLUSH in the PDU of `buf`
 * to the reactor of `conn`. `iov` has the reply that the caller built for
 * a full transfer. For a READ, the reply ends before the data. The reactor
 * does `io` on the file of `hold` and sends the reply. After a short
 * transfer, it sets the count in the reply. After an error, it sends an
 * error response. A READ that returns no data is an error. A WRITE that
 * writes none of its data is also an error.
 *
 * With `TN_SMBSRV_SEAL_SIGN`, the reactor signs the reply with the signing
 * key of `keys`. With `TN_SMBSRV_SEAL_ENCRYPT`, `iov` has the transform
 * header with its nonce after the NBT header. The reactor then encrypts
 * the reply with the encryption key of `keys`. The reactor closes the
 * connection if it cannot sign or encrypt the reply.
 *
 * In all cases, this function takes ownership of `hold` and `keys`. For a
 * WRITE, it can move the bytes of the PDU out of `buf`. So the caller must
 * not read the `data` of the PDU event after the call. The caller can free
 * `buf`. Returns 0 or an errno. ENOKEY if `keys` does not have the key for
 * the seal. ENOKEY also if the seal is not a `TN_SMBSRV_SEAL_*` value.
 *
 * # Safety
 *
 * `conn` is from `tn_smbros_adopt()`. `buf` is the live `buf` of a PDU
 * event of `conn`. `iov` has `iovcnt` vectors of readable memory. `io`
 * points to a `struct tn_smbsrv_io`. The caller does not use `hold` and
 * `keys` again.
 */
int tn_smbsrv_delegate(struct tn_smbros_conn *conn,
                       void *buf,
                       const struct iovec *iov,
                       int iovcnt,
                       struct tn_smbsrv_hold *hold,
                       struct tn_smbsrv_keys *keys,
                       const struct tn_smbsrv_io *io);

/**
 * Make the open file of `fd`. The IDLE events of the file have `cookie`.
 * Free the file with `tn_smbsrv_file_close()`. NULL if `fd` is negative.
 *
 * # Safety
 *
 * `ctx` is from `tn_smbros_ctx_new()`. The caller keeps `fd` open until
 * `tn_smbsrv_file_close()` returns.
 */
struct tn_smbsrv_file *tn_smbsrv_file_new(struct tn_smbros_ctx *ctx,
                                          int fd,
                                          uint64_t cookie);

/**
 * Count a new pending job of `file`. Returns the hold of the job. Give the
 * hold to `tn_smbsrv_delegate()`, or free it with `tn_smbsrv_hold_free()`.
 * The hold is still valid after `tn_smbsrv_file_close()`.
 *
 * # Safety
 *
 * `file` is from `tn_smbsrv_file_new()`. The caller did not call
 * `tn_smbsrv_file_close()` on it.
 */
struct tn_smbsrv_hold *tn_smbsrv_file_hold(const struct tn_smbsrv_file *file);

/**
 * Free a hold that the caller did not delegate. NULL is allowed.
 *
 * # Safety
 *
 * `hold` is NULL or is from `tn_smbsrv_file_hold()`. The caller does not
 * use it again.
 */
void tn_smbsrv_hold_free(struct tn_smbsrv_hold *hold);

/**
 * Count the job of `hold` as an outstanding request of the open. smbd uses
 * this count for the channel sequence checks of [MS-SMB2] 3.3.5.2.10.
 * `current` is true for the current channel sequence of the open. It is
 * false for an older one. The count lasts until the hold is freed. The
 * caller then does not count the request itself.
 *
 * # Safety
 *
 * `hold` is from `tn_smbsrv_file_hold()`. The caller still owns it.
 */
void tn_smbsrv_hold_seq(struct tn_smbsrv_hold *hold,
                        bool current);

/**
 * The number of jobs of `file` that count as outstanding requests of
 * older channel sequences.
 *
 * # Safety
 *
 * `file` is from `tn_smbsrv_file_new()`. The caller did not call
 * `tn_smbsrv_file_close()` on it.
 */
uint32_t tn_smbsrv_file_seq_old(const struct tn_smbsrv_file *file);

/**
 * Call this when the channel sequence of the open changes. The jobs that
 * counted as current then count as old.
 *
 * # Safety
 *
 * `file` is from `tn_smbsrv_file_new()`. The caller did not call
 * `tn_smbsrv_file_close()` on it.
 */
void tn_smbsrv_file_seq_bump(const struct tn_smbsrv_file *file);

/**
 * Write the new position of the open to `*pos`. The position is the end of
 * the last delegated read that returned data. False if no such read ended
 * after the last call.
 *
 * # Safety
 *
 * `file` is from `tn_smbsrv_file_new()`. The caller did not call
 * `tn_smbsrv_file_close()` on it. `pos` is writable.
 */
bool tn_smbsrv_file_take_pos(const struct tn_smbsrv_file *file,
                             uint64_t *pos);

/**
 * True if `file` has pending or running jobs. After this call,
 * `tn_smbros_next()` returns `TN_SMBSRV_IDLE` with the cookie of `file`
 * each time the last job of `file` ends. The reactor queues the reply of
 * each job before that event. `tn_smbros_next()` drops the IDLE events of
 * a closed file.
 *
 * # Safety
 *
 * `file` is from `tn_smbsrv_file_new()`. The caller did not call
 * `tn_smbsrv_file_close()` on it.
 */
bool tn_smbsrv_file_busy(const struct tn_smbsrv_file *file);

/**
 * Close `file`. This call blocks until the running jobs of `file` end.
 * After that, the caller can close the descriptor. A pending job that the
 * caller delegates later does no file I/O. The reactor answers it with
 * `NT_STATUS_FILE_CLOSED`. `pos` can be NULL. True if this call wrote a
 * position to `*pos`. See `tn_smbsrv_file_take_pos()`.
 *
 * # Safety
 *
 * `file` is from `tn_smbsrv_file_new()`. The caller does not use it after
 * this call. `pos` is NULL or writable.
 */
bool tn_smbsrv_file_close(const struct tn_smbsrv_file *file,
                          uint64_t *pos);

#endif  /* TRUENAS_SMB_SERVER_H */
