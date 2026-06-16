/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
   Unix SMB/CIFS implementation.

   smbd SMB2 io_uring fast-path state.

   Per-xconn bookkeeping for the truenas_uring integration: config knobs
   latched at negprot, in-flight CQE counters for socket ops, the cached
   AF_ALG bind socket used by signed PDU HMAC, and the per-PDU outbound
   splice state.

   The whole thing is reachable as xconn->smb2.uring (allocated lazily
   at negprot, talloc'd as a child of xconn). Pulled out of globals.h
   so that internal types like truenas_uring_pipe / file_modified_state
   stay out of the globals.h dependency surface.

   The xconn-side container and the send_queue->xconn back-pointer
   pattern (used by the pipelined splice state machine to find xconn
   from a queue entry) are adapted from Stefan Metzmacher's
   smbd_server_connection->uring and smbd_smb2_send_queue->xconn
   additions in upstream Samba (gitlab !4457).

   Copyright (C) Stefan Metzmacher 2020,2026
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

#ifndef SMBD_SMB2_URING_H
#define SMBD_SMB2_URING_H

#ifdef HAVE_LIBURING

#include "lib/truenas_uring.h"  /* truenas_uring_pipe */

struct files_struct;
struct smb2_signing_key;

/*
 * In-flight io_uring socket ops. At most one send and one recv may be
 * outstanding at a time, so SMB2 wire order is preserved. SEND vs SEND_ZC
 * are mutually exclusive (only one send variant outstanding at a time);
 * RECV is orthogonal to both. Stored as a bitmask on samba_uring_xconn.
 *
 * SAMBA_URING_INFLIGHT_SEND_ZC distinguishes the SENDMSG_ZC dual-CQE
 * flow (data CQE + notif CQE) so the completion callback knows what to
 * expect.
 *
 * SAMBA_URING_INFLIGHT_SPLICE_RECV is set whenever an inbound splice
 * (signed or unsigned) is consuming raw body bytes from the socket.
 * While set, the dispatcher must NOT submit a competing RECVMSG on the
 * same fd -- the two would race for TCP stream bytes and the next-PDU
 * recv would consume body bytes intended for the splice. Cleared by
 * the inbound splice's finish callback.
 */
enum samba_uring_inflight {
	SAMBA_URING_INFLIGHT_NONE        = 0,
	SAMBA_URING_INFLIGHT_SEND        = 1 << 0,
	SAMBA_URING_INFLIGHT_SEND_ZC     = 1 << 1,
	SAMBA_URING_INFLIGHT_RECV        = 1 << 2,
	SAMBA_URING_INFLIGHT_SPLICE_RECV = 1 << 3,
};

/*
 * Cap on cached SMB3 HMAC key bytes. SMB3 derives a 16-byte signing key
 * via SP800-108 KDF regardless of the underlying algorithm (HMAC-SHA256,
 * AES-128-CMAC, AES-128-GMAC), so 16 is sufficient and oversized inputs
 * are truncated on the wire too.
 */
#define SAMBA_URING_HMAC_KEY_MAX 16
#define SAMBA_URING_INFLIGHT_ANY_SEND \
	(SAMBA_URING_INFLIGHT_SEND | SAMBA_URING_INFLIGHT_SEND_ZC)

/*
 * One per (xconn, smb2_signing_key) pair. Lifetime is bound to the
 * signing_key (talloc-parented to it); destructor closes the bind fd
 * and unlinks from the xconn's signed_alg_cache list.
 *
 * bind_fd is an algif_hash socket whose backing algorithm and key are
 * chosen from sk->sign_algo_id:
 *   HMAC-SHA256 -> "hmac(sha256)" keyed with sk->blob
 *   AES-CMAC    -> "cmac(aes)"   keyed with sk->blob
 *   AES-GMAC    -> "ghash"       keyed with H = AES_K(0^128) (derived once)
 *
 * A given sk has exactly one sign_algo_id, so one bind_fd per cache
 * entry suffices.
 */
struct truenas_signed_alg_cache_entry {
	struct truenas_signed_alg_cache_entry *prev, *next;
	struct samba_uring_xconn *u;   /* back-ref for unlink-on-free */
	const struct smb2_signing_key *sk;  /* lookup key */
	int bind_fd;
};

/*
 * Splice operation type. The two outbound variants are carried per-PDU
 * on samba_uring_splice_entry; the two inbound variants live in their
 * own per-request state structs (struct splice_write_state,
 * struct signed_splice_in_state) in source3/smbd/smb2_aio.c and don't
 * use samba_uring_splice_state.
 *
 *   SPLICE_OP_NONE          idle (zero-init default; plain sendmsg)
 *   SPLICE_OP_UNSIGNED_IN   socket -> body_pipe -> file
 *   SPLICE_OP_UNSIGNED_OUT  vmsplice(hdr) + file -> body_pipe -> socket
 *   SPLICE_OP_SIGNED_IN     socket -> body_pipe, tee -> tee_pipe -> AF_ALG;
 *                           on MAC verify, body_pipe -> file
 *   SPLICE_OP_SIGNED_OUT    file -> body_pipe, tee -> tee_pipe -> AF_ALG;
 *                           patch MAC into header, write -> hdr_pipe,
 *                           send hdr_pipe then body_pipe -> socket
 *
 * Encrypted PDUs do not take any splice path -- they go through the
 * registered-buffer + SEND_ZC route inside truenas_uring directly.
 */
enum splice_op_type {
	SPLICE_OP_NONE = 0,
	SPLICE_OP_UNSIGNED_IN,
	SPLICE_OP_UNSIGNED_OUT,
	SPLICE_OP_SIGNED_IN,
	SPLICE_OP_SIGNED_OUT,
};

/*
 * In-flight outbound splice state. One per send_queue entry of type
 * SPLICE_OP_*_OUT (so multiple can be live concurrently in different
 * phases). Allocated by smbd_smb2_splice_state_start as a talloc child
 * of the queue entry's mem_ctx; the destructor returns its held pipes
 * to the per-tevent_context pool.
 *
 * Wire ordering is preserved by gating the pipe->socket phase on
 * (this entry == send_queue head) AND (no SAMBA_URING_INFLIGHT_*_SEND
 * in flight). The setup and file->pipe phases can run in parallel
 * across non-head entries.
 */
struct samba_uring_splice_state {
	/*
	 * Phase. Drives the dispatcher: only SEND_READY entries at the
	 * head of the queue start their pipe->socket SQE. Earlier phases
	 * proceed independently per-entry without touching the socket.
	 */
	enum splice_state_phase {
		SPLICE_STATE_INIT = 0,    /* nothing acquired yet */
		SPLICE_STATE_FETCHING,    /* file->pipe (and AF_ALG feed) in flight */
		SPLICE_STATE_SEND_READY,  /* hdr patched, pipes loaded, awaits socket */
		SPLICE_STATE_SENDING,     /* pipe->socket SQE in flight */
	} phase;

	/*
	 * Cached truenas_uring handle for the talloc destructor's pipe and
	 * fd cleanup. Set at state allocation time. NULL only if state was
	 * allocated but xconn died before pipes were acquired -- destructor
	 * then no-ops.
	 */
	struct truenas_uring *u;

	/*
	 * Splice variant. Mirrors e->splice.type but lives on the state so
	 * the destructor doesn't need to walk back to the entry.
	 */
	enum splice_op_type type;

	/* Body payload pipe. Held by all variants. */
	struct truenas_uring_pipe body_pipe;

	union {
		struct {            /* SPLICE_OP_UNSIGNED_OUT */
			size_t header_len;   /* vmsplice'd ahead of payload */
			size_t total_bytes;  /* header + payload */
			size_t file_done;
			size_t socket_done;
		} unsigned_out;

		struct {            /* SPLICE_OP_SIGNED_OUT */
			struct truenas_uring_pipe tee_pipe;
			struct truenas_uring_pipe hdr_pipe;
			int    alg_op_fd;
			size_t payload_len;
			size_t file_done;
			size_t alg_fed;
			size_t hdr_pipe_len;
			size_t hdr_sent;
			size_t body_sent;
			uint8_t *outhdr_ptr;  /* points into response iov[1] */
		} signed_out;
	};
};

/*
 * Splice description attached to a smbd_smb2_send_queue entry. Carries
 * the descriptor (what file region to splice, signing key, etc.) AND a
 * pointer to the per-PDU in-flight state (samba_uring_splice_state),
 * which is allocated on demand when the entry's setup phase starts.
 *
 *   type == SPLICE_OP_NONE          plain sendmsg entry (no splice)
 *   type == SPLICE_OP_UNSIGNED_OUT  unsigned READ: file -> pipe -> socket
 *   type == SPLICE_OP_SIGNED_OUT    signed READ: file -> pipe + tee into
 *                                   AF_ALG; patch MAC into header; send
 *                                   hdr_pipe then body_pipe to socket
 *
 * Only consumed by smbd_smb2_flush_with_sendmsg_uring(); the legacy sync
 * path asserts type == SPLICE_OP_NONE.
 */
struct samba_uring_splice_entry {
	enum splice_op_type type;
	struct files_struct *fsp;
	off_t  offset;
	size_t payload_len;

	/*
	 * Per-PDU in-flight state. NULL until splice_state_start allocates
	 * and seeds it (acquires pipes, opens AF_ALG fd for SIGNED_OUT,
	 * etc.). Talloc'd as child of the queue entry mem_ctx so it
	 * auto-releases its pipes/fds via destructor if the entry is
	 * freed during error/shutdown paths.
	 */
	struct samba_uring_splice_state *state;

	union {
		struct {            /* SPLICE_OP_SIGNED_OUT */
			struct smb2_signing_key *signing_key;
			uint8_t *outhdr_ptr;  /* 64-byte SMB2 hdr in vector */
		} signed_out;
	};
};

struct samba_uring_xconn {
	/* Config -- latched once at negprot, never changes. */
	struct {
		bool sendmsg;          /* IORING_OP_SENDMSG for SMB2 responses */
		bool sendmsg_zc;       /* SENDMSG_ZC above zc_min_bytes */
		size_t zc_min_bytes;
		bool recvmsg;          /* IORING_OP_RECVMSG for inbound */
		bool splice_send;        /* file->pipe->socket for outbound READ
				          * (covers both unsigned and signed
				          * variants; signing eligibility is
				          * checked per-PDU at the OUT scheduler) */
		bool splice_recv;        /* socket->pipe->file for inbound WRITE
				          * (covers both unsigned and signed
				          * variants; signing eligibility is
				          * checked per-PDU at admission time) */
	} enabled;

	unsigned inflight;          /* bitmask of enum samba_uring_inflight */

	/*
	 * AF_ALG bind-socket cache keyed by smb2_signing_key pointer.
	 *
	 * SMB2/3 derives the signing key once at SESSION_SETUP (or per
	 * channel via SMB2_SESSION_FLAG_BINDING) and never rotates it
	 * within the lifetime of that session/channel -- the only "key
	 * change" event is session expiry, which destroys the session
	 * entirely and creates a new one (MS-SMB2 3.2.5.1.6). So keying
	 * the cache on the signing_key pointer is safe: as long as the
	 * pointer is the same, the key bytes are the same.
	 *
	 * Why a list (vs single-slot): MS-SMB2 allows multiple authenticated
	 * sessions over a single TCP connection (the SessionId field
	 * distinguishes them; spec section 3.2.4.1). A single-slot cache
	 * would thrash between sessions on every signed PDU; a list lets
	 * each active session keep its bound fd warm.
	 *
	 * Each entry is talloc'd as a child of its smb2_signing_key, so
	 * session/channel teardown frees the entry via the talloc cascade,
	 * its destructor closes the fd, and the destructor unlinks the
	 * entry from this list. No explicit cleanup required at xconn
	 * teardown.
	 */
	struct truenas_signed_alg_cache_entry *signed_alg_cache;

	/*
	 * Per-mode dispatch counters, exposed via the smbtorture FSCTL pair
	 * (FSCTL_SMBTORTURE_TRUENAS_URING_COUNTERS_READ / _RESET). Lets
	 * end-to-end tests assert that a given PDU actually took the fast
	 * path rather than silently falling back to the legacy code path.
	 * Bumped at the dispatch decision points in smb2_aio.c /
	 * smb2_server.c / vfs_io_uring.c.
	 *
	 * Field order, sizes (uint64_t) and host byte order are part of the
	 * FSCTL-level ABI: the smbtorture suite reads the struct as a flat
	 * blob and PULL_LE_U64s out by offset. If you add a field, append
	 * at the end and bump the version constant in smb_constants.h.
	 */
	struct samba_uring_counters {
		uint64_t unsigned_splice_in;       /* socket -> pipe -> file */
		uint64_t signed_splice_in;         /* + AF_ALG verify-then-write */
		uint64_t signed_splice_in_denied;  /* MAC mismatch / ACCESS_DENIED */
		uint64_t unsigned_splice_out;      /* file -> pipe -> socket */
		uint64_t signed_splice_out;        /* + AF_ALG, patched-MAC hdr */
		uint64_t encrypted_recv;           /* encrypted READ served (mempool or opt-in regbuf) */
		uint64_t encrypted_send_zc;        /* SENDMSG_ZC sends (all paths) */
		uint64_t legacy_recv;              /* fell back to tstream recv */
		uint64_t legacy_send;              /* fell back to sendmsg+pktbuf */
		uint64_t bytes_unsigned_splice_in;
		uint64_t bytes_signed_splice_in;
		uint64_t bytes_unsigned_splice_out;
		uint64_t bytes_signed_splice_out;
		uint64_t bytes_encrypted_in;
		uint64_t bytes_encrypted_out;
		uint64_t signed_alg_cache_hits;    /* per-sk bind_fd reused */
		uint64_t signed_alg_cache_misses;  /* per-sk bind_fd opened */
		uint64_t inflight_throttle_events; /* recv deferred due to cap */
		uint64_t inflight_bytes_peak;      /* high-water mark */
		/*
		 * Appended (WIRE_BYTES 19 -> 21): plain (unsigned, unencrypted)
		 * READ served from the reclaimable io_memory_pool + SENDMSG_ZC
		 * (the default, non-pinned read path). Kept distinct from
		 * encrypted_recv so the read-path mix stays observable.
		 */
		uint64_t unsigned_recv_mempool;    /* plain READ via io_memory_pool */
		uint64_t bytes_unsigned_mempool_out;
	} counters;

	/* Test-only: set by FSCTL_SMBTORTURE_TRUENAS_URING_
	 * FORCE_NEXT_SIGNED_WRITE_FAIL; consumed and auto-cleared by the
	 * signed splice inbound state machine on its next MAC verify. */
	bool force_signed_in_fail;

	/* Test-only: set by FSCTL_SMBTORTURE_TRUENAS_URING_
	 * FORCE_NEXT_POSIX_APPEND; consumed and auto-cleared by the next
	 * is_smb2_recvfile_write() call, which then takes the
	 * fsp_flags.posix_append rejection branch regardless of the
	 * actual fsp flag value. Lets the torture suite exercise the
	 * O_APPEND gate without needing SMB2 POSIX-context infrastructure
	 * on the client side. */
	bool force_next_posix_append;

	/*
	 * Per-xconn recv-side back-pressure. Recreates the historical
	 * TrueNAS throttle: cap the userspace-buffer bytes that a single
	 * xconn can have in flight on the recv path. Without this, a
	 * client doing high-concurrency encrypted WRITEs can pile up
	 * unbounded talloc allocations (the registered-buffer pool falls
	 * back to talloc on exhaustion), defeating the pool's 256 MiB
	 * ceiling.
	 *
	 * Configured via `truenas_uring:max_inflight_bytes` (default
	 * 512 MiB; 0 disables). When `inflight_bytes >= max_inflight_bytes`,
	 * smbd_smb2_request_next_incoming defers requesting the next PDU
	 * until completion paths refund bytes.
	 */
	uint64_t inflight_bytes;
	uint64_t max_inflight_bytes;

	/*
	 * Once-per-smbd notification flags. Set the first time the
	 * corresponding condition fires; subsequent firings stay silent
	 * so the log doesn't fill with repeats. Counters keep counting
	 * regardless, so operators see the cumulative rate via FSCTL.
	 */
	bool notified_inflight_throttle;
	bool notified_write_splice_fallback;
};

#define TURING_MAX_INFLIGHT_BYTES_DEFAULT ((uint64_t)512 * 1024 * 1024)

/*
 * Charge / refund the per-xconn recv-side byte counter. Centralised so
 * the high-water-mark counter update stays consistent with the running
 * total. Safe to call when u == NULL (no-op) so the call sites don't
 * need to gate -- though typical callers hold xconn->smb2.uring and
 * know it is non-NULL post-negprot.
 */
static inline void samba_uring_charge_inflight(struct samba_uring_xconn *u,
					       uint64_t bytes)
{
	if (u == NULL) {
		return;
	}
	u->inflight_bytes += bytes;
	if (u->inflight_bytes > u->counters.inflight_bytes_peak) {
		u->counters.inflight_bytes_peak = u->inflight_bytes;
	}
}

static inline void samba_uring_refund_inflight(struct samba_uring_xconn *u,
					       uint64_t bytes)
{
	if (u == NULL) {
		return;
	}
	if (bytes > u->inflight_bytes) {
		/* Defensive: shouldn't happen, but never underflow. */
		u->inflight_bytes = 0;
		return;
	}
	u->inflight_bytes -= bytes;
}

/* Wire size of struct samba_uring_counters, in bytes, when serialized
 * for FSCTL_SMBTORTURE_TRUENAS_URING_COUNTERS_READ. */
#define SAMBA_URING_COUNTERS_WIRE_BYTES (21 * 8)

/* Set by FSCTL_SMBTORTURE_TRUENAS_URING_FORCE_NEXT_SIGNED_WRITE_FAIL.
 * The next signed splice inbound WRITE will force the post-HMAC verify
 * to fail (auto-clears after consumption). Test-only knob. */
static inline bool samba_uring_consume_force_signed_in_fail(
	struct samba_uring_xconn *u)
{
	bool prev = u->force_signed_in_fail;
	u->force_signed_in_fail = false;
	return prev;
}

/* Set by FSCTL_SMBTORTURE_TRUENAS_URING_FORCE_NEXT_POSIX_APPEND. The
 * next is_smb2_recvfile_write() call rejects the recvfile / splice IN
 * path as if the target fsp had fsp_flags.posix_append set (auto-clears
 * after consumption). Test-only knob. */
static inline bool samba_uring_consume_force_next_posix_append(
	struct samba_uring_xconn *u)
{
	bool prev = u->force_next_posix_append;
	u->force_next_posix_append = false;
	return prev;
}

/*
 * True iff an inbound splice currently owns the socket as a reader.
 * While true, smbd_smb2_request_next_incoming must NOT arm a recv on
 * the same fd or the two would race for socket bytes. The inbound
 * state machines (smb2_aio.c: splice_write_*, signed_splice_in_*)
 * set/clear SAMBA_URING_INFLIGHT_SPLICE_RECV around their socket
 * splice; outbound splices never reach this gate (they don't read
 * the socket).
 */
static inline bool samba_uring_splice_reads_socket(
	const struct samba_uring_xconn *u)
{
	return u != NULL &&
	       (u->inflight & SAMBA_URING_INFLIGHT_SPLICE_RECV) != 0;
}

#endif /* HAVE_LIBURING */
#endif /* SMBD_SMB2_URING_H */
