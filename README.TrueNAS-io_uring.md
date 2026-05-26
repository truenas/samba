# TrueNAS io_uring zero-copy SMB2/3

This document describes the TrueNAS-fork-local additions that move SMB2/3
READ and WRITE traffic off the userspace bounce-buffer path and onto
Linux io_uring's in-kernel zero-copy primitives (splice, registered
buffers, send_zc).

Unlike the small handful of `vfs_io_uring`-related changes in upstream
Samba, the work here spans:

  * a per-`tevent_context` io_uring abstraction layer
    (`source3/lib/truenas_uring`);
  * a per-xconn state container that hangs off `smbXsrv_connection.smb2`;
  * four SMB2 fast paths (signed/unsigned × inbound/outbound splice)
    plus an encrypted-PDU registered-buffer path;
  * a torture test suite that cross-validates the splice page-borrow
    semantic on a known-borrow substrate vs ZFS.

It is targeted at SMB shares served from ZFS datasets on TrueNAS; the
ZFS-specific `copy_splice_read` guarantee removes a class of corruption
hazard that affects the same path on page-cache filesystems
(ext4/xfs/btrfs).


## The problem: two avoidable `memcpy`s per SMB2 byte

Stock Samba moves payload bytes through userspace at least twice on
every READ/WRITE. Profiling a busy share shows
`copy_user_enhanced_fast_string()` and `copy_from_iter` / `copy_to_iter`
dominating CPU on the smbd thread.

```
       baseline SMB2 WRITE (inbound)              baseline SMB2 READ (outbound)

  client                       smbd            smbd                       client
    │                            │              │                            │
    │   header + body on TCP     │              │   readv()                  │
    │ ──────────────────────────►│              │   page cache              │
    │                            │              │   ──── memcpy #1 ────►    │
    │                            │              │   io_pool buffer          │
    │                            │              │                            │
    │   recv() into pktbuf       │              │   sendmsg()                │
    │   ◄── memcpy #1 ──         │              │   ──── memcpy #2 ────►    │
    │   pktbuf  (userspace)      │              │   socket buffer           │
    │                            │              │                            │
    │   writev()                 │              │   on the wire              │
    │   ──── memcpy #2 ────►     │              │ ◄──────────────────────── │
    │   page cache               │              │                            │
```

The TrueNAS-fork's `vfs_io_uring` builds inherit a worse baseline than
upstream Samba builds because TrueNAS forcibly disables `sendfile` (the
upstream sendfile-escape at `source3/smbd/smb2_read.c:359` always
returns false on TrueNAS). So even the unsigned/unencrypted READ path
pays both copies on stock TrueNAS Samba.

Eliminating these two memcpys is the entire point of the work below.


## Three operation modes, by security posture

Per-PDU, the SMB2 dispatcher (or the schedule_* helpers) classify the
request into one of three modes based on its signing / encryption flags
and shape. The mode determines which kernel mechanism moves the bytes.

| Mode               | Applies to                          | Inbound mechanism                              | Outbound mechanism                                     |
| ------------------ | ----------------------------------- | ---------------------------------------------- | ------------------------------------------------------ |
| Unsigned splice    | unsigned, unencrypted, regular file | `socket → pipe → file` (one `IORING_OP_SPLICE` each leg) | `file → pipe → socket` (vmsplice header into same pipe) |
| Signed splice      | signed, unencrypted                 | `socket → body_pipe; tee → alg_pipe → AF_ALG`; verify-before-write | `file → body_pipe; tee → alg_pipe → AF_ALG`; patch MAC into header; `hdr_pipe → socket`, then `body_pipe → socket` |
| Encrypted          | SMB3 transform-encrypted PDUs       | `IORING_OP_RECV` into a `IORING_REGISTER_BUFFERS`-pinned slot; in-place AEAD decrypt; `IORING_OP_WRITE_FIXED` to file | `IORING_OP_READ_FIXED` from file into pinned slot; in-place AEAD encrypt; `IORING_OP_SENDMSG_ZC` |

The discriminant lives on
`xconn->smb2.uring->splice.type ∈ {NONE, UNSIGNED_IN, UNSIGNED_OUT,
SIGNED_IN, SIGNED_OUT}`, and on per-request `splice_in.type` /
`splice.type` annotations attached to the SMB2 request and the send-queue
entry respectively.

Encrypted PDUs do not take any splice path; they use a separate
registered-buffer allocator (`truenas_uring_buf_acquire` /
`_release`).


## Component layering

```
       ┌───────────────────────────────────────────────────────────────────┐
       │                              smbd                                  │
       │                                                                    │
       │   ┌──────────────────────┐         ┌────────────────────────────┐ │
       │   │ smb2_server.c        │         │ smb2_aio.c                 │ │
       │   │  - dispatch          │         │  - signed splice WRITE     │ │
       │   │  - outbound splice   │         │  - encrypted READ (regbuf) │ │
       │   │    state machines    │         │  - splice WRITE schedule   │ │
       │   │  - send queue        │         │                            │ │
       │   │  - recv state mach.  │         │ smb2_read.c / smb2_write.c │ │
       │   │  - AF_ALG cache      │         │  - splice eligibility gate │ │
       │   └─────────┬────────────┘         └──────────────┬─────────────┘ │
       │             │                                     │               │
       │             └───────────────┬─────────────────────┘               │
       │                             │                                     │
       │              ┌──────────────▼──────────────────────┐              │
       │              │   smbd_smb2_uring.h (per xconn)     │              │
       │              │     struct samba_uring_xconn        │              │
       │              │       .enabled       (config flags) │              │
       │              │       .inflight      (CQE bitmask)  │              │
       │              │       .algif_hmac_cache (AF_ALG fd) │              │
       │              │       .splice        (op state)     │              │
       │              └──────────────┬──────────────────────┘              │
       │                             │                                     │
       │              ┌──────────────▼──────────────────────┐              │
       │              │   vfs_io_uring  (per-share VFS)     │              │
       │              │     pread/pwrite/fsync via uring    │              │
       │              └──────────────┬──────────────────────┘              │
       └─────────────────────────────┼─────────────────────────────────────┘
                                     │
                  ┌──────────────────▼──────────────────────┐
                  │       source3/lib/truenas_uring          │
                  │   per-tevent_context io_uring wrapper    │
                  │                                          │
                  │   tevent_req wrappers for:               │
                  │     pread/pwrite/fsync/splice            │
                  │     recv/send/sendmsg/recvmsg            │
                  │     send_zc/sendmsg_zc (dual CQE)        │
                  │                                          │
                  │   Resource pools:                        │
                  │     registered buffer pool (FIXED ops)   │
                  │     splice pipe pool                     │
                  │     AF_ALG HMAC open/compute/close       │
                  │                                          │
                  │   IOSQE_ASYNC threshold (per op class)   │
                  └──────────────────┬──────────────────────┘
                                     │
                              ┌──────▼──────┐
                              │   liburing  │
                              └──────┬──────┘
                                     │
                              ┌──────▼──────┐
                              │   kernel    │
                              │  io_uring   │
                              └─────────────┘
```

The principle:

  * `truenas_uring` is the only thing that talks to `liburing`. Everything
    else uses tevent_req-shaped `_send`/`_recv` wrappers.
  * `vfs_io_uring` is now a thin VFS adapter on top of `truenas_uring`;
    each share gets its own VFS handle but they all share a single
    `truenas_uring` per `tevent_context`.
  * `smbd_smb2_uring.h` declares the per-xconn state container.
  * `smb2_server.c` / `smb2_aio.c` / `smb2_read.c` / `smb2_write.c`
    implement the SMB2-layer state machines.


## Inbound paths (SMB2 WRITE)

### Unsigned splice WRITE

Eligibility: unsigned PDU, body bytes still on the socket
(`smbreq->unread_bytes > 0` from short-recvfile), regular file fd, no
alternate stream, not compounded (or last in compound).

```
  client                                       smbd
    │   WRITE PDU (signed=0, encrypted=0)        │
    │   header + body on TCP                     │
    │═══════════════════════════════════════════►│
    │                                            │
    │                          ┌─ IORING_OP_SPLICE: socket → pipe
    │                          │  (no userspace copy of body bytes)
    │                          │
    │                          ▼
    │                       ┌──────┐
    │                       │ pipe │      (kernel-resident)
    │                       └──┬───┘
    │                          │
    │                          ├─ IORING_OP_SPLICE: pipe → file
    │                          │  (kernel-side copy_from_iter into
    │                          │   page cache; this copy is fundamental
    │                          │   to buffered-write semantics)
    │                          │
    │                          ▼
    │                       ┌──────┐
    │                       │ file │
    │                       └──────┘
    │
    │   WRITE response                           │
    │◄═══════════════════════════════════════════│
```

Net win vs baseline: −1 byte-copy / payload byte. The page-cache fill
remains because buffered writes must hit the cache.

### Signed splice WRITE (verify-before-write)

Eligibility: as unsigned splice WRITE, but the PDU is signed. The SMB2
dispatcher noticed the signature can't be checked in-band (body bytes
not yet recv'd), skipped the check, and stashed the resolved signing
key on `req->splice_in.signing_key` with
`splice_in.type = SPLICE_OP_SIGNED_IN`.

```
  client                                       smbd
    │   signed WRITE PDU                          │
    │═══════════════════════════════════════════►│
    │                                             │
    │                IORING_OP_SPLICE: socket → body_pipe
    │                          │
    │                          ▼
    │                      ┌──────┐                            ┌──────────┐
    │                      │ body │ ── tee() (ref-bump) ──────►│ alg_pipe │
    │                      │ pipe │                            └────┬─────┘
    │                      └──┬───┘                                 │
    │                         │                                     │
    │                         │      IORING_OP_SPLICE: alg_pipe ───►│ AF_ALG hash op fd
    │                         │      (in-kernel feed)               │  ── reads MAC
    │                         │                                     │
    │                         │                            ┌────────▼────────┐
    │                         │                            │ compare against │
    │                         │                            │ PDU signature   │
    │                         │                            └────────┬────────┘
    │                         │                                     │
    │                         │             ┌──────────────────────►│ mismatch
    │                         │             │                       │   drain body_pipe
    │                         │             │                       │   ACCESS_DENIED
    │                         │             │                       │   (no disk write)
    │                         │             │
    │                         ▼
    │                    IORING_OP_SPLICE: body_pipe → file
    │                    (only after MAC verifies)
    │
    │   WRITE response                            │
    │◄════════════════════════════════════════════│
```

Key invariant: bytes never reach disk before the HMAC is validated. On
mismatch the body pipe is drained without touching the file and the
client gets ACCESS_DENIED. The legacy sys_recvfile path is NOT a safe
fallback if the signed splice path declines — it would write
attacker-controlled bytes before the check.

`algif_hash` lacks `MSG_SPLICE_PAGES` support, so the kernel copies the
spliced pages once into the AHASH request internally. This costs one
in-kernel pass over the bytes but no userspace round-trip. AES-NI / PMULL
runs in-kernel.

### Encrypted WRITE (registered buffer)

```
  client                                       smbd
    │   encrypted WRITE PDU                       │
    │═══════════════════════════════════════════►│
    │                                             │
    │                IORING_OP_RECV into registered buffer slot
    │                  (no malloc; slot is pre-pinned, mmap'd,
    │                   visible to both userspace and kernel)
    │                                │
    │                                ▼
    │                       ┌────────────────┐
    │                       │ regbuf slot N  │
    │                       │  (userspace)   │
    │                       └────────┬───────┘
    │                                │
    │                                │  gnutls AEAD decrypt in-place
    │                                │  (one CPU pass over the bytes;
    │                                │   AES-NI; no copy)
    │                                ▼
    │                       ┌────────────────┐
    │                       │ regbuf slot N  │  ← plaintext
    │                       └────────┬───────┘
    │                                │
    │                                │  IORING_OP_WRITE_FIXED(slot → file)
    │                                │  (kernel-side copy_from_iter)
    │                                ▼
    │                            ┌──────┐
    │                            │ file │
    │                            └──────┘
```

The bytes do visit userspace here — gnutls AEAD requires it — but the
allocation is amortized (per-xconn pool), and there is no `recv→pktbuf`
malloc churn. The slot is released back to the pool by a talloc
destructor on a tiny owner object parented to the SMB2 request, so the
slot is recovered even on abort.

Net win vs baseline encrypted: −1 byte-copy (the `recv → pktbuf` hop is
eliminated; AEAD pass is irreducible).


## Outbound paths (SMB2 READ)

### Unsigned splice READ

```
                       smbd                                     client
                         │   READ response                        │
                         │                                        │
       ┌──────┐          │   vmsplice(SPLICE_F_GIFT):             │
       │ file │ ◄────────┤   response header iov → pipe           │
       └──┬───┘          │   (the small SMB2 hdr+body bytes)      │
          │              │                                        │
          │  IORING_OP_SPLICE:                                    │
          │   file → pipe                                         │
          │   (ZFS: copy via copy_splice_read into pipe-private   │
          │    pages — snapshot semantics)                        │
          ▼                                                       │
       ┌──────┐                                                   │
       │ pipe │ ── IORING_OP_SPLICE: pipe → socket ──────────────►│
       └──────┘   (zero-copy: skb fragments point at pipe pages,  │
                   NIC DMA reads them directly)                   │
                                                                  │
                         │                                        │
                         │   on the wire                          │
                         │═══════════════════════════════════════►│
```

The vmsplice'd header IS copied (we use `write()` rather than vmsplice
without `SPLICE_F_GIFT` for signed READ — see below — but for unsigned
READ `SPLICE_F_GIFT` is safe because the iov memory is owned by the
queue entry which lives until both halves of the splice complete).

### Signed splice READ (patch MAC into header)

```
                  smbd                                                 client
                    │   signed READ response                              │
                    │                                                     │
   ┌──────┐         │   IORING_OP_SPLICE: file → body_pipe                │
   │ file │ ────────┤                                                     │
   └──────┘         │   tee(body_pipe → alg_pipe)                         │
                    │                                                     │
                    │                ┌───────────┐    ┌───────────┐       │
                    │                │ body_pipe │    │ alg_pipe  │       │
                    │                └─────┬─────┘    └─────┬─────┘       │
                    │                      │                │             │
                    │      IORING_OP_SPLICE: alg_pipe ──────┘             │
                    │      into AF_ALG hash op fd                         │
                    │                                                     │
                    │      read(hmac_op_fd, mac, 16)                      │
                    │      memcpy(response_hdr + SIG_OFS, mac, 16)        │
                    │                                                     │
                    │      write(hdr_pipe, patched_header_bytes)          │
                    │      (uses write() not vmsplice, to copy bytes      │
                    │       into pipe-private pages; the iov memory       │
                    │       gets recycled by talloc after the queue       │
                    │       entry advances, so vmsplice without GIFT      │
                    │       would race with the response talloc reset)    │
                    │                                                     │
                    │              ┌───────────┐                          │
                    │              │ hdr_pipe  │                          │
                    │              └─────┬─────┘                          │
                    │                    │                                │
                    │      IORING_OP_SPLICE: hdr_pipe → socket ──────────►│
                    │      IORING_OP_SPLICE: body_pipe → socket ─────────►│
                    │                                                     │
                    │═════════════════════════════════════════════════════►│
```

The MAC is computed over the SAME bytes the client receives because
ZFS's `copy_splice_read` snapshots into pipe-private pages — no
concurrent writer can mutate the bytes between HMAC computation and
wire transmission. On a page-cache filesystem this guarantee does not
hold (see Filesystem compatibility below).

### Encrypted READ (registered buffer + SEND_ZC)

```
                  smbd                                                 client
                    │   encrypted READ response                           │
                    │                                                     │
   ┌──────┐         │   IORING_OP_READ_FIXED: file → regbuf slot N        │
   │ file │ ────────┤   (kernel-side copy_to_iter into pinned pages)      │
   └──────┘         │                                                     │
                    │                ┌────────────────┐                   │
                    │                │ regbuf slot N  │ ← plaintext       │
                    │                └────────┬───────┘                   │
                    │                         │                           │
                    │                         │  gnutls AEAD encrypt      │
                    │                         │  in-place (AES-NI)        │
                    │                         ▼                           │
                    │                ┌────────────────┐                   │
                    │                │ regbuf slot N  │ ← ciphertext      │
                    │                └────────┬───────┘                   │
                    │                         │                           │
                    │      IORING_OP_SENDMSG_ZC(slot → socket) ──────────►│
                    │      (TCP attaches pinned pages as skb frags;       │
                    │       NIC DMA reads them; NO socket-buffer copy)    │
                    │                                                     │
                    │      data CQE arrives (advance send queue);         │
                    │      notification CQE arrives later when kernel     │
                    │      releases the pinned pages → release slot       │
                    │═════════════════════════════════════════════════════►│
```

Two CQEs per `SEND_ZC` op: the data CQE means "bytes are queued for
DMA", the notification CQE (with `IORING_CQE_F_NOTIF`) means "kernel
no longer references the buffer". The slot must not be reused until
both CQEs are in. Multi-CQE bookkeeping is handled in
`source3/lib/truenas_uring.c:truenas_uring_complete_req`.

Net win vs baseline encrypted: −1 byte-copy (the `sendmsg → socket
buffer` hop is eliminated).


## Resource pools

### Per-xconn AF_ALG bind socket cache

Opening an AF_ALG bind socket (and setting the per-session signing key)
is expensive; doing it per-PDU would dominate signed-splice cost. We
cache one bind fd per xconn, keyed by `(algo_id, key_bytes)`. Cache
invalidation: session re-key or different session on the same xconn
(rare; SMB3 multichannel uses one xconn per channel so the key is
stable).

Per-request work reduces to a single `accept4(bind_fd, ..., SOCK_CLOEXEC)`
for a fresh hash op fd.

The cache lives on `xconn->smb2.uring->algif_hmac_cache`. A tiny talloc
holder is parented to xconn so the bind fd is closed automatically at
xconn teardown.

### Per-tevent_context splice pipe pool

Pre-allocated pipe pool sized for SMB2 max-write payloads (default
`smb2 max write` = 8 MiB). Created with `pipe2(O_CLOEXEC)`, sized with
`fcntl(F_SETPIPE_SZ)`. Without `CAP_SYS_RESOURCE` the pipe size caps at
`/proc/sys/fs/pipe-max-size` (1 MiB on stock Linux); with the cap
(smbd runs as root on TrueNAS) the cap is bypassed.

Per-xconn peak demand is 3 pipes (signed READ outbound: body + tee +
patched-header). Default pool size is 4 (one slack pipe). The state
machine serializes splice ops per xconn so demand is bounded.

Pipes are blocking, not non-blocking. The kernel splice paths handle
"wait for pipe room" correctly on a kernel worker thread, and a short
splice on a full non-blocking pipe would desync our exact-byte-count
accounting from the socket position.

### Per-tevent_context registered buffer pool

For encrypted-PDU traffic. The pool is mmap'd once and registered via
`IORING_REGISTER_BUFFERS`. Slot allocator uses a 64-bit busy bitmap
(so the pool is capped at 64 slots). When a buffer pointer falls in a
registered iov, the submit helpers automatically dispatch to the
`IORING_OP_*_FIXED` variant.


## Filesystem compatibility: ZFS snapshot vs page-cache borrow

The `file → pipe` half of outbound splice has different semantics
depending on the filesystem's `splice_read` callback:

  * **`copy_splice_read`** (ZFS, NFS, FUSE): allocates fresh pages,
    calls `read_iter` to copy bytes from the FS into them, attaches the
    pages to the pipe. The pipe sees a snapshot of the file at
    splice-time; concurrent writers cannot affect bytes already in the
    pipe.

  * **`filemap_splice_read`** (ext4, xfs, btrfs): attaches page-cache
    folios to the pipe by REFERENCE. Bytes are read by the NIC's DMA
    long after the splice call returns. A concurrent writer to the
    same file offset mutates what arrives on the wire (same hazard as
    `sendfile(2)`).

This is the classic Metze reproducer: write A at offset CHUNK, splice
2*CHUNK from offset 0, pwrite B at offsets 0 AND CHUNK, drain the
pipe. On a borrow-FS the pipe yields B, B; on ZFS it yields 0, A.

Our outbound splice paths are designed assuming snapshot semantics
(ZFS) because the signed READ path's HMAC must be computed over the
exact bytes the client receives — which requires that no concurrent
writer can mutate the pipe pages between hash and transmit. The
LOCAL-TRUENAS-URING smbtorture test cross-validates this contract by
running Metze's reproducer on both a memfd (tmpfs-backed, page-cache
splice, expected to corrupt) and a tempfile in cwd (expected ZFS,
asserted snapshot-clean).

Non-ZFS shares are not currently supported by the outbound splice
path. Adding non-ZFS support would require a per-fsp filesystem-class
probe at open time and an explicit operator opt-in to acknowledge the
sendfile-class semantics on borrow-FSes. Not on the near-term roadmap.


## Configuration

A single master knob, on by default. Set to `no` for stock Samba
behavior.

```ini
[global]
    truenas_uring:enabled = yes

    # Linux clients negotiate 4-8 MiB rsize/wsize; default smb2 max
    # is already 8 MiB but the operator should confirm.
    smb2 max read  = 8388608
    smb2 max write = 8388608
```

When `truenas_uring:enabled = yes` (default), the negprot config-latch
turns on every fork-local fast path: io_uring socket I/O
(IORING_OP_SENDMSG / RECVMSG), splice paths for both signed and
unsigned READ / WRITE, the AF_ALG HMAC cache, and SENDMSG_ZC over a
registered fixed-buffer pool for encrypted responses. Per-PDU
dispatch picks the appropriate mode from the request's signing and
encryption posture; the operator doesn't choose modes individually.

### Advanced overrides (rarely needed)

```ini
[global]
    truenas_uring:splice_pipe_pool       = 4          ; pipes per xconn (peak demand: 3)
    truenas_uring:splice_pipe_size       = 0          ; 0 = lp_smb2_max_write
    truenas_uring:fixed_buffer_pool_count   = 32      ; 0 = disabled; default 32 when enabled
    truenas_uring:fixed_buffer_pool_bufsize = 0       ; 0 = lp_smb2_max_read + 8 KiB
    io_uring:send_zc_min_size            = 65536      ; SENDMSG_ZC threshold

    ; The min-receive-file-size knob is auto-engaged at 1 byte when
    ; truenas_uring:enabled = yes; an explicit non-zero value here is
    ; respected as-is.
    min receive file size                = 1
```

`smbd` must run as root for `F_SETPIPE_SZ` to exceed
`/proc/sys/fs/pipe-max-size`. TrueNAS satisfies this; on other
distros either bump the sysctl or accept the default 1 MiB pipes
(which forces chunked splice for larger PDUs).


## Code map

### New, fork-local

| Path | Purpose |
| ---- | ------- |
| `source3/lib/truenas_uring.h` / `.c` | Per-tevent_context io_uring abstraction. All `liburing` calls live here. tevent_req-shaped op wrappers, registered buffer pool, splice pipe pool, AF_ALG HMAC helpers, IOSQE_ASYNC threshold knob. |
| `source3/smbd/smbd_smb2_uring.h` | `struct samba_uring_xconn` (per-xconn config flags, CQE-in-flight bitmask, AF_ALG bind socket cache, splice op state). `struct samba_uring_splice_op` (tagged-union over UNSIGNED/SIGNED × IN/OUT). `struct samba_uring_splice_entry` (per send-queue entry splice descriptor). |
| `source4/torture/local/truenas_uring.c` | `LOCAL-TRUENAS-URING` smbtorture suite. Functional coverage of every public truenas_uring API plus the splice page-borrow cross-validation. |

### Modified upstream Samba files (fork-additive)

| Path | What we added |
| ---- | ------------- |
| `source3/modules/vfs_io_uring.c` | Drop the private `io_uring`; obtain one via `truenas_uring_get(ev)`. Submit helpers detect registered-pool pointers via `truenas_uring_buf_index` and dispatch to FIXED-variant ops. |
| `source3/smbd/globals.h` | Embedded `struct samba_uring_xconn *uring` on `smbXsrv_connection.smb2`; `struct samba_uring_splice_entry splice` on `smbd_smb2_send_queue`; `splice_in.{type,signing_key}` on `smbd_smb2_request`. |
| `source3/smbd/smb2_negprot.c` | One-shot config latch into `samba_uring_xconn.enabled.*` at negprot. GMAC-gate filters AES-128-GMAC out of the negotiated sign-algo list when signed splice is on (algif_hash cannot compute it). Registered-buffer pool registration. Splice pipe pool registration. |
| `source3/smbd/smb2_server.c` | AF_ALG cache acquire/destructor. Outbound splice state machines (unsigned + signed, file→pipe→socket). `smbd_smb2_flush_with_sendmsg_uring` dispatch. `smbd_smb2_async_recvmsg_submit` / `_done` for the async RECVMSG path. |
| `source3/smbd/smb2_aio.c` | Unsigned splice inbound WRITE state machine. Signed splice inbound WRITE state machine (verify-before-write). Encrypted-READ registered-buffer ownership. |
| `source3/smbd/smb2_read.c` | `schedule_smb2_splice_read`: eligibility gate + state stamping for outbound splice (picks SIGNED_OUT or UNSIGNED_OUT). |
| `source3/smbd/smb2_write.c` | Dispatch into signed splice or unsigned splice WRITE schedulers; fail safely if the signed splice path declines (no fallback to legacy sys_recvfile). |
| `source3/smbd/proto.h` | Externs for the three publicly-named TrueNAS helpers (`truenas_schedule_smb2_unsigned_splice_write`, `truenas_schedule_smb2_signed_splice_write`, `truenas_smb2_alg_hmac_acquire`). |


## Verification

### Build

The work is gated on `HAVE_LIBURING`. With liburing present:

```
$ ./configure
$ make smbd smbtorture
```

builds the smbd binary and the smbtorture binary that ships
`LOCAL-TRUENAS-URING`.

### Smbtorture: LOCAL-TRUENAS-URING

The unit test for the abstraction layer + the page-borrow contract.
Runs locally without a server:

```
$ cd <a ZFS dataset>
$ smbtorture //nodc/nodc -U nodc%nodc local.truenas_uring
```

Output should include:

```
splice-borrow: negative control (memfd, f_type=0x1021994) corrupted as expected -- test methodology is sound
splice-borrow: ZFS confirmed snapshot-clean (f_type=0x2fc12fc1)
success: all
```

The negative-control line proves the test methodology actually detects
corruption (without it, a kernel change to shmem semantics could
silently neuter the test). The positive line is the actual ZFS contract
assertion — if it fails, signed splice READ is unsafe and the path
must be disabled.

If the positive substrate (cwd) is not ZFS, a WARNING is logged but
the test still passes (skip is not failure). Run from a ZFS dataset
to exercise the assertion.

The full functional suite also covers: pread / pwrite / fsync via
io_uring, splice file→pipe, recv / send / sendmsg / recvmsg, send_zc /
sendmsg_zc dual-CQE, registered buffer pool (acquire/release,
size_hint boundary, FIXED-variant dispatch), AF_ALG HMAC against RFC
4231 vector 1 (header-only and header + pipe-payload), pipe pool
drain-on-release, concurrent in-flight requests, mid-flight
cancellation of recv and splice.

### End-to-end SMB testing

Separately, the SMB2 fast paths need server-side validation: a Linux
cifs client doing 4 MiB rsize/wsize reads and writes against shares
configured with each combination of
`io_uring:zero_copy_recv ∈ {no, splice, signed_splice}` and
`io_uring:zero_copy_send ∈ {no, splice, send_zc}`, with signed and
unsigned and encrypted PDUs. Plus regression suites against md5
checksums to confirm bit-for-bit integrity. (A planned addition to the
smbtorture suite.)
