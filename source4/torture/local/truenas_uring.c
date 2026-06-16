/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
   Unix SMB/CIFS implementation.

   Functional tests for source3/lib/truenas_uring (the per-tevent-context
   io_uring abstraction used by vfs_io_uring and the SMB2 zero-copy
   fast paths).

   Lives in source4/torture/local/ rather than source3/torture/ so it
   ships in the installed `smbtorture` binary (the source3 smbtorture3
   is for_selftest only and not packaged).

   Coverage:

     File I/O           IORING_OP_{READ,WRITE,FSYNC} via the
                        truenas_uring_{pread,pwrite,fsync}_send/_recv
                        wrappers. Happy path; EBADF error path; read
                        past EOF returns 0; two pread requests in
                        flight concurrently on the same ring.

     Splice             IORING_OP_SPLICE file -> pipe via
                        truenas_uring_splice_send. Mid-flight cancel
                        via TALLOC_FREE on an idle pipe (kernel ASYNC
                        cancel path); follow-up request on the same
                        ring still completes (ring health after cancel).

     Socket I/O         IORING_OP_RECV / non-zero-copy SEND / SENDMSG /
                        RECVMSG via the matching _send/_recv wrappers.
                        Full byte-count happy path; recv returns 0 on
                        peer close; recv mid-flight cancel via
                        TALLOC_FREE.

     Zero-copy send     IORING_OP_SEND_ZC / SENDMSG_ZC dual-CQE
                        completion (data CQE + IORING_CQE_F_NOTIF) over
                        TCP loopback with SO_ZEROCOPY; multi-iov form;
                        FIXED-variant dispatch when buffer is pool-
                        backed.

     Registered bufs    truenas_uring_register_buffers /
                        _unregister_buffers / _buf_index pointer-to-slot
                        lookup (in-range / out-of-range / pre- and post-
                        registration); auto-dispatch to IORING_OP_*_FIXED
                        variants when src/dst is pool-backed; the slot
                        allocator pair _buf_acquire / _buf_release /
                        _buf_data including size_hint boundary
                        (size_hint == buflen succeeds, > buflen fails);
                        register_owned_pool (the variant that mmap()s
                        and registers in one shot).

     AF_ALG HMAC        truenas_uring_hmac_open / _compute / _close,
                        which front algif_hash for SMB3 signing. RFC
                        4231 vector 1 (HMAC-SHA256) checked both
                        header-only and split as header + pipe-payload
                        (validating the splice-into-algif_hash path
                        used by the signed splice WRITE fast path).
                        Argument validation: NULL alg, overlong alg,
                        unsupported algorithm. hmac_close(-1) sentinel.

     Pipe pool          truenas_uring_register_pipe_pool plus
                        _pipe_acquire / _pipe_release: registration,
                        acquire / release ordering, exhaustion sentinel,
                        and drain-on-release (stale bytes left in a
                        pipe by the previous holder are not visible to
                        the next acquirer -- relied on by the SMB2
                        outbound splice state machine which pulls
                        pipes from a per-xconn pool one PDU at a time).

     Splice corruption  Cross-validates the file -> pipe -> socket
                        borrow-vs-snapshot question that metze
                        raised on the kernel list (page-cache splice
                        attaches the file's folio to the pipe by
                        reference, so a concurrent pwrite to the same
                        offset mutates bytes already queued for the
                        wire). The test runs metze's exact
                        reproducer on TWO substrates:

                          - negative control: a memfd (tmpfs-backed,
                            page-cache splice semantics). Expected to
                            corrupt; if it doesn't, the test
                            methodology is no longer sensitive and we
                            warn loudly.
                          - positive case: a tempfile in cwd. When
                            cwd lives on ZFS (f_type == 0x2fc12fc1)
                            the test ASSERTS no corruption -- this is
                            the snapshot contract our SMB2 outbound
                            splice path relies on (zpl_file.c uses
                            copy_splice_read).

                        Critical because the SMB2 outbound splice path
                        (file -> kernel pipe -> socket) would silently
                        corrupt wire output under concurrent writers
                        on any borrow-semantics filesystem.

   Without HAVE_LIBURING the test is a no-op SKIP so smbtorture builds
   on platforms without liburing-dev.

   Test scaffolding pattern (per-tevent_context ring fixture +
   submit/wait helpers around tevent_req-shaped ops) adapted from
   Stefan Metzmacher's `s4:torture/local: samba_io_uring_ev_register`
   in upstream Samba (gitlab !4453).

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

#include "includes.h"
#include "torture/torture.h"
#include "torture/local/proto.h"

#ifndef HAVE_LIBURING

static bool test_truenas_uring_skip(struct torture_context *tctx)
{
	torture_skip(tctx, "built without io_uring (HAVE_LIBURING unset)");
	return true;
}

struct torture_suite *torture_local_truenas_uring(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx,
							   "truenas_uring");
	torture_suite_add_simple_test(suite, "all", test_truenas_uring_skip);
	return suite;
}

#else

#include "lib/truenas_uring.h"

#include <tevent.h>
#include <talloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/vfs.h>      /* fstatfs() for ZFS detection */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define BUF_LEN 4096
#define TEST_PATTERN 0xA5

/*
 * Build a connected TCP loopback pair (server-side accepted fd in tcp[0],
 * client-side connected fd in tcp[1]). MSG_ZEROCOPY only works on TCP, and
 * SO_ZEROCOPY must be enabled on the sender side.
 */
static int tcp_pair(int tcp[2])
{
	int listen_fd = -1;
	struct sockaddr_in sa = { .sin_family = AF_INET };
	socklen_t sl = sizeof(sa);
	int one = 1;

	listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listen_fd == -1) {
		return -1;
	}
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		goto err;
	}
	if (listen(listen_fd, 1) == -1) {
		goto err;
	}
	if (getsockname(listen_fd, (struct sockaddr *)&sa, &sl) == -1) {
		goto err;
	}

	tcp[1] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (tcp[1] == -1) {
		goto err;
	}
	if (connect(tcp[1], (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		close(tcp[1]);
		tcp[1] = -1;
		goto err;
	}
	tcp[0] = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
	if (tcp[0] == -1) {
		close(tcp[1]);
		tcp[1] = -1;
		goto err;
	}
	close(listen_fd);

	if (setsockopt(tcp[1], SOL_SOCKET, SO_ZEROCOPY,
		       &one, sizeof(one)) == -1) {
		close(tcp[0]);
		close(tcp[1]);
		tcp[0] = -1;
		tcp[1] = -1;
		return -1;
	}
	return 0;
err:
	if (listen_fd >= 0) {
		close(listen_fd);
	}
	return -1;
}

/*
 * metze reported (private mail to the kernel list during the
 * io_uring/Samba zero-copy discussion) that file -> pipe splice on a
 * page-cache filesystem (ext4, xfs, btrfs -- anything using
 * filemap_splice_read) attaches the file's folio to the pipe by reference.
 * A concurrent pwrite to the same offset then mutates the bytes already
 * "queued" in the pipe -- which would corrupt SMB2 wire payloads if the
 * page gets DMA'd to the NIC AFTER another client writes to the same
 * region. ZFS uses copy_splice_read (zpl_file.c:1237) and snapshots
 * bytes from ARC into pipe-private pages at splice time, so concurrent
 * writers cannot affect data already in the pipe.
 *
 * The test runs metze's exact reproducer on TWO substrates and
 * cross-validates: a memfd (tmpfs-backed -- borrow semantics expected)
 * is the negative control, proving the test methodology actually
 * detects corruption; a regular file on cwd is the positive case,
 * asserting no corruption when cwd lives on ZFS. (cwd, not /tmp --
 * on production TrueNAS /tmp is tmpfs and would never exercise the
 * ZFS contract.)
 *
 * Reproducer sequence (per substrate):
 *   write A at offset CHUNK, splice 2*CHUNK from offset 0, pwrite B at
 *   offsets 0 AND CHUNK, drain pipe. Borrow FS yields B,B; snapshot FS
 *   yields zero,A.
 */
#define SPLICE_BORROW_CHUNK 4096   /* one page; matches metze's PIPE_BUF */
#define ZFS_MAGIC          0x2fc12fc1UL
#define TMPFS_MAGIC_NUM    0x01021994UL  /* shmem / memfd */

struct splice_borrow_outcome {
	bool          ran;        /* test sequence completed without error */
	bool          corrupted;  /* valid iff ran */
	unsigned long fs_type;    /* from fstatfs */
	char          err[160];   /* explanation when !ran */
};

/*
 * Run the metze splice-borrow sequence on `fd`. `fd` must be writable
 * and seekable; the file is truncated to zero before the test.
 */
static void splice_borrow_run(int fd, struct splice_borrow_outcome *o)
{
	struct statfs sfs;
	int pp[2] = { -1, -1 };
	char buf_zero[SPLICE_BORROW_CHUNK];
	char buf_a[SPLICE_BORROW_CHUNK];
	char buf_b[SPLICE_BORROW_CHUNK];
	char drain[SPLICE_BORROW_CHUNK];
	ssize_t sret;
	off_t ofs;

	memset(o, 0, sizeof(*o));

	if (fstatfs(fd, &sfs) == 0) {
		o->fs_type = (unsigned long)sfs.f_type;
	}

	if (ftruncate(fd, 0) != 0) {
		snprintf(o->err, sizeof(o->err),
			 "ftruncate: %s", strerror(errno));
		return;
	}

	memset(buf_zero, 0x00, sizeof(buf_zero));
	memset(buf_a,    0x1f, sizeof(buf_a));
	memset(buf_b,    0xf0, sizeof(buf_b));

	/* Write A at offset CHUNK; offset 0 stays sparse (zero on read). */
	sret = pwrite(fd, buf_a, SPLICE_BORROW_CHUNK, SPLICE_BORROW_CHUNK);
	if (sret != SPLICE_BORROW_CHUNK) {
		snprintf(o->err, sizeof(o->err),
			 "pwrite A short (%zd): %s", sret, strerror(errno));
		return;
	}

	if (pipe(pp) != 0) {
		snprintf(o->err, sizeof(o->err),
			 "pipe: %s", strerror(errno));
		return;
	}

	ofs = 0;
	sret = splice(fd, &ofs, pp[1], NULL, SPLICE_BORROW_CHUNK * 2, 0);
	if (sret != SPLICE_BORROW_CHUNK * 2) {
		snprintf(o->err, sizeof(o->err),
			 "splice short (%zd): %s", sret, strerror(errno));
		goto cleanup;
	}

	/*
	 * Mutate both offsets with pattern B. Borrow semantics => pipe pages
	 * see B; snapshot semantics => pipe pages still hold pre-pwrite state.
	 */
	if (pwrite(fd, buf_b, SPLICE_BORROW_CHUNK, 0) != SPLICE_BORROW_CHUNK ||
	    pwrite(fd, buf_b, SPLICE_BORROW_CHUNK, SPLICE_BORROW_CHUNK)
		    != SPLICE_BORROW_CHUNK) {
		snprintf(o->err, sizeof(o->err), "post-splice pwrites failed");
		goto cleanup;
	}

	/* Chunk 1 expected: zeros. Chunk 2 expected: pattern A. */
	if (read(pp[0], drain, SPLICE_BORROW_CHUNK) != SPLICE_BORROW_CHUNK) {
		snprintf(o->err, sizeof(o->err), "pipe read 1");
		goto cleanup;
	}
	if (memcmp(drain, buf_zero, SPLICE_BORROW_CHUNK) != 0) {
		o->corrupted = true;
	}

	if (read(pp[0], drain, SPLICE_BORROW_CHUNK) != SPLICE_BORROW_CHUNK) {
		snprintf(o->err, sizeof(o->err), "pipe read 2");
		goto cleanup;
	}
	if (memcmp(drain, buf_a, SPLICE_BORROW_CHUNK) != 0) {
		o->corrupted = true;
	}

	o->ran = true;

cleanup:
	if (pp[0] >= 0) {
		close(pp[0]);
	}
	if (pp[1] >= 0) {
		close(pp[1]);
	}
}

/*
 * Run the splice-borrow check on both a known-borrow substrate (memfd,
 * tmpfs-backed) and a regular file on the local FS. Reports findings
 * via the torture context. Returns false only if a real regression is
 * detected (corruption on a snapshot-semantics FS that we ASSERTED
 * should be safe -- currently just ZFS).
 */
static bool splice_borrow_cross_validate(struct torture_context *tctx)
{
	struct splice_borrow_outcome neg = { 0 };
	struct splice_borrow_outcome pos = { 0 };
	int neg_fd, pos_fd;
	/*
	 * Positive substrate is a tempfile in CWD, not /tmp. On real
	 * TrueNAS /tmp is tmpfs (the negative substrate) and would never
	 * exercise the ZFS contract -- the operator runs smbtorture from
	 * a ZFS dataset, so cwd is the FS we actually care about.
	 */
	char tmpl[] = "./truenas_uring_borrow.XXXXXX";

	/* --- Negative case: memfd (tmpfs-backed; should corrupt) --- */
	neg_fd = memfd_create("truenas_uring_borrow_neg", MFD_CLOEXEC);
	if (neg_fd >= 0) {
		splice_borrow_run(neg_fd, &neg);
		close(neg_fd);
	} else {
		snprintf(neg.err, sizeof(neg.err),
			 "memfd_create: %s", strerror(errno));
	}

	if (!neg.ran) {
		torture_warning(tctx,
			"splice-borrow: negative substrate did not run: %s",
			neg.err);
	} else if (!neg.corrupted) {
		/*
		 * memfd didn't corrupt. Either the kernel switched shmem to
		 * copy_splice_read, or some other change neutralised the
		 * borrow window. Test methodology is no longer differentiating
		 * snapshot from borrow -- log loudly but don't fail.
		 */
		torture_warning(tctx,
			"splice-borrow: NEGATIVE control (memfd, f_type=0x%lx) "
			"did NOT corrupt as expected -- kernel may have changed "
			"shmem splice semantics; the positive ZFS assertion is "
			"now less meaningful",
			neg.fs_type);
	} else {
		torture_comment(tctx,
			"splice-borrow: negative control (memfd, f_type=0x%lx) "
			"corrupted as expected -- test methodology is sound\n",
			neg.fs_type);
	}

	/* --- Positive case: regular file on local FS (ZFS on TrueNAS) --- */
	pos_fd = mkstemp(tmpl);
	if (pos_fd < 0) {
		torture_warning(tctx,
			"splice-borrow: positive substrate mkstemp failed: %s",
			strerror(errno));
		return true;  /* can't test ZFS, but no regression observed */
	}
	(void)unlink(tmpl);
	splice_borrow_run(pos_fd, &pos);
	close(pos_fd);

	if (!pos.ran) {
		torture_warning(tctx,
			"splice-borrow: positive substrate did not run: %s",
			pos.err);
		return true;
	}

	if (pos.fs_type != ZFS_MAGIC) {
		/*
		 * Positive substrate (cwd) isn't ZFS, so we don't have a
		 * known contract for snapshot semantics. Report observation
		 * but don't fail -- run smbtorture from a ZFS dataset to
		 * exercise the actual contract.
		 */
		torture_warning(tctx,
			"splice-borrow: positive substrate (cwd) is not ZFS "
			"(f_type=0x%lx, corrupted=%s); run smbtorture from a "
			"ZFS dataset to assert snapshot contract",
			pos.fs_type, pos.corrupted ? "yes" : "no");
		return true;
	}

	/*
	 * Positive substrate IS ZFS. This is the assertion that matters:
	 * concurrent pwrite must NOT leak into the spliced pipe.
	 */
	if (pos.corrupted) {
		torture_warning(tctx,
			"splice-borrow: ZFS CORRUPTION (f_type=0x%lx) -- "
			"copy_splice_read snapshot guarantee violated",
			pos.fs_type);
		return false;
	}

	torture_comment(tctx,
		"splice-borrow: ZFS confirmed snapshot-clean (f_type=0x%lx)\n",
		pos.fs_type);
	return true;
}

static bool wait_for_req(struct tevent_context *ev, struct tevent_req *req)
{
	while (tevent_req_is_in_progress(req)) {
		if (tevent_loop_once(ev) != 0) {
			return false;
		}
	}
	return true;
}

/*
 * One-shot composite test. Each subsystem (file I/O, socket I/O,
 * splice, registered buffers, HMAC, pipe pool, splice-borrow) is
 * sequenced and shares fixtures (tempfile, sockets) deliberately --
 * the coverage matters more than per-section reporting at this layer.
 * A torture failure at any point short-circuits with cleanup via the
 * talloc destructor for state.
 */

struct truenas_uring_test_state {
	int fd;
	int pipefd[2];
	int sv[2];
	int tcp[2];
};

static int truenas_uring_test_state_destructor(
	struct truenas_uring_test_state *s)
{
	if (s->fd >= 0) {
		close(s->fd);
	}
	if (s->pipefd[0] >= 0) {
		close(s->pipefd[0]);
	}
	if (s->pipefd[1] >= 0) {
		close(s->pipefd[1]);
	}
	if (s->sv[0] >= 0) {
		close(s->sv[0]);
	}
	if (s->sv[1] >= 0) {
		close(s->sv[1]);
	}
	if (s->tcp[0] >= 0) {
		close(s->tcp[0]);
	}
	if (s->tcp[1] >= 0) {
		close(s->tcp[1]);
	}
	return 0;
}

static bool test_truenas_uring(struct torture_context *tctx)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct truenas_uring *u = NULL;
	struct tevent_req *req = NULL;
	char tmpl[] = "/tmp/truenas_uring_test.XXXXXX";
	char *write_buf = NULL;
	char *read_buf = NULL;
	ssize_t n;
	int err = 0;
	int ret;
	struct truenas_uring_test_state *st = NULL;

	st = talloc_zero(frame, struct truenas_uring_test_state);
	torture_assert_goto(tctx, st != NULL, ret, out, "talloc state");
	st->fd = -1;
	st->pipefd[0] = st->pipefd[1] = -1;
	st->sv[0] = st->sv[1] = -1;
	st->tcp[0] = st->tcp[1] = -1;
	talloc_set_destructor(st, truenas_uring_test_state_destructor);

	ev = tevent_context_init(frame);
	torture_assert_goto(tctx, ev != NULL, ret, out, "tevent_context_init");

	u = truenas_uring_get(ev);
	torture_assert_goto(tctx, u != NULL, ret, out, "truenas_uring_get");
	torture_assert_goto(tctx, truenas_uring_get(ev) == u, ret, out,
			    "truenas_uring_get is not idempotent");

	truenas_uring_set_async_threshold(u, TURING_OP_READ_CLASS, 1024);
	truenas_uring_set_async_threshold(u, TURING_OP_WRITE_CLASS, 1024);
	truenas_uring_set_async_threshold(u, TURING_OP_NUM_CLASSES, 9999);

	st->fd = mkstemp(tmpl);
	torture_assert_goto(tctx, st->fd != -1, ret, out, "mkstemp");
	(void)unlink(tmpl);

	write_buf = talloc_array(frame, char, BUF_LEN);
	read_buf  = talloc_array(frame, char, BUF_LEN);
	torture_assert_goto(tctx, write_buf != NULL && read_buf != NULL, ret, out,
			    "talloc_array");
	memset(write_buf, TEST_PATTERN, BUF_LEN);
	memset(read_buf, 0, BUF_LEN);

	/* ---------- File I/O: pwrite via io_uring ---------- */
	req = truenas_uring_pwrite_send(frame, ev, st->fd,
					write_buf, BUF_LEN, 0);
	torture_assert_goto(tctx, req != NULL, ret, out, "pwrite_send");
	torture_assert_goto(tctx, wait_for_req(ev, req), ret, out,
			    "wait pwrite");
	n = truenas_uring_pwrite_recv(req, &err);
	torture_assert_int_equal_goto(tctx, n, BUF_LEN, ret, out, "pwrite_recv n");
	TALLOC_FREE(req);

	/* ---------- File I/O: fsync via io_uring ---------- */
	req = truenas_uring_fsync_send(frame, ev, st->fd, 0);
	torture_assert_goto(tctx, req != NULL, ret, out, "fsync_send");
	torture_assert_goto(tctx, wait_for_req(ev, req), ret, out, "wait fsync");
	torture_assert_int_equal_goto(tctx, truenas_uring_fsync_recv(req, &err),
				      0, ret, out, "fsync_recv");
	TALLOC_FREE(req);

	/* ---------- File I/O: pread via io_uring ---------- */
	req = truenas_uring_pread_send(frame, ev, st->fd,
				       read_buf, BUF_LEN, 0);
	torture_assert_goto(tctx, req != NULL, ret, out, "pread_send");
	torture_assert_goto(tctx, wait_for_req(ev, req), ret, out, "wait pread");
	n = truenas_uring_pread_recv(req, &err);
	torture_assert_int_equal_goto(tctx, n, BUF_LEN, ret, out, "pread_recv n");
	torture_assert_goto(tctx, memcmp(read_buf, write_buf, BUF_LEN) == 0,
			    ret, out, "pread bytes mismatch");
	TALLOC_FREE(req);

	/* PREAD past EOF returns 0 */
	memset(read_buf, 0, BUF_LEN);
	req = truenas_uring_pread_send(frame, ev, st->fd,
				       read_buf, BUF_LEN, BUF_LEN * 2);
	torture_assert_goto(tctx, wait_for_req(ev, req), ret, out, "wait pread EOF");
	n = truenas_uring_pread_recv(req, &err);
	torture_assert_int_equal_goto(tctx, n, 0, ret, out, "pread past EOF");
	TALLOC_FREE(req);

	/* PWRITE to invalid fd -> EBADF */
	req = truenas_uring_pwrite_send(frame, ev, -1,
					write_buf, BUF_LEN, 0);
	torture_assert_goto(tctx, wait_for_req(ev, req), ret, out, "wait badfd");
	n = truenas_uring_pwrite_recv(req, &err);
	torture_assert_goto(tctx, n < 0 && err == EBADF, ret, out,
			    "pwrite to bad fd should EBADF");
	TALLOC_FREE(req);

	/* ---------- Splice (file -> pipe -> read back) ---------- */
	torture_assert_goto(tctx, pipe(st->pipefd) == 0, ret, out, "pipe");
	torture_assert_goto(tctx, lseek(st->fd, 0, SEEK_SET) != (off_t)-1,
			    ret, out, "lseek");
	{
		int64_t in_off = 0;
		req = truenas_uring_splice_send(frame, ev,
						st->fd, &in_off,
						st->pipefd[1], NULL,
						BUF_LEN, 0);
		torture_assert_goto(tctx, req != NULL, ret, out, "splice_send");
		torture_assert_goto(tctx, wait_for_req(ev, req), ret, out,
				    "wait splice");
		n = truenas_uring_splice_recv(req, &err);
		torture_assert_goto(tctx, n > 0, ret, out, "splice_recv > 0");
		TALLOC_FREE(req);

		memset(read_buf, 0, BUF_LEN);
		{
			ssize_t got = read(st->pipefd[0], read_buf, n);
			torture_assert_int_equal_goto(tctx, got, n, ret, out,
						      "pipe read after splice");
		}
		torture_assert_goto(tctx,
				    memcmp(read_buf, write_buf, n) == 0,
				    ret, out, "spliced bytes mismatch");
	}
	close(st->pipefd[0]); st->pipefd[0] = -1;
	close(st->pipefd[1]); st->pipefd[1] = -1;

	/* ---------- Socket I/O: socketpair fixtures ---------- */
	torture_assert_goto(tctx,
			    socketpair(AF_UNIX, SOCK_STREAM, 0, st->sv) == 0,
			    ret, out, "socketpair");

	torture_assert_int_equal_goto(tctx, write(st->sv[0], write_buf, 128),
				      128, ret, out, "seed write socketpair");
	memset(read_buf, 0, BUF_LEN);
	req = truenas_uring_recv_send(frame, ev, st->sv[1], read_buf, 128, 0);
	torture_assert_goto(tctx, req != NULL, ret, out, "recv_send");
	torture_assert_goto(tctx, wait_for_req(ev, req), ret, out, "wait recv");
	n = truenas_uring_recv_recv(req, &err);
	torture_assert_int_equal_goto(tctx, n, 128, ret, out, "recv_recv n");
	torture_assert_goto(tctx, memcmp(read_buf, write_buf, 128) == 0,
			    ret, out, "recv bytes mismatch");
	TALLOC_FREE(req);

	/* ---------- Zero-copy send: TCP loopback pair for SEND_ZC ---------- */
	if (tcp_pair(st->tcp) == -1) {
		torture_skip_goto(tctx, out,
				  "SO_ZEROCOPY not available on this kernel");
	}

	req = truenas_uring_send_zc_send(frame, ev, st->tcp[1],
					 write_buf, 256, MSG_NOSIGNAL, 0);
	torture_assert_goto(tctx, req != NULL, ret, out, "send_zc_send");
	torture_assert_goto(tctx, wait_for_req(ev, req), ret, out, "wait send_zc");
	n = truenas_uring_send_zc_recv(req, &err);
	torture_assert_int_equal_goto(tctx, n, 256, ret, out, "send_zc_recv n");
	TALLOC_FREE(req);

	memset(read_buf, 0, BUF_LEN);
	torture_assert_int_equal_goto(tctx, read(st->tcp[0], read_buf, 256),
				      256, ret, out, "read after send_zc");
	torture_assert_goto(tctx, memcmp(read_buf, write_buf, 256) == 0,
			    ret, out, "send_zc bytes mismatch");

	{
		struct iovec iov[2] = {
			{ .iov_base = write_buf,       .iov_len = 128 },
			{ .iov_base = write_buf + 128, .iov_len = 256 },
		};
		struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };

		req = truenas_uring_sendmsg_zc_send(frame, ev, st->tcp[1],
						    &msg, MSG_NOSIGNAL);
		torture_assert_goto(tctx, req != NULL, ret, out, "sendmsg_zc_send");
		torture_assert_goto(tctx, wait_for_req(ev, req), ret, out,
				    "wait sendmsg_zc");
		n = truenas_uring_sendmsg_zc_recv(req, &err);
		torture_assert_int_equal_goto(tctx, n, 384, ret, out,
					      "sendmsg_zc_recv n");
		TALLOC_FREE(req);

		memset(read_buf, 0, BUF_LEN);
		torture_assert_int_equal_goto(tctx,
					      read(st->tcp[0], read_buf, 384),
					      384, ret, out, "read after sendmsg_zc");
		torture_assert_goto(tctx,
				    memcmp(read_buf, write_buf, 384) == 0,
				    ret, out, "sendmsg_zc bytes mismatch");
	}

	/* ---------- Registered buffer pool ---------- */
	{
		const size_t pool_buflen = 8192;
		const unsigned int pool_n = 4;
		void *pool_pages = NULL;
		struct iovec pool_iovs[4];
		unsigned int i;
		int bidx;

		pool_pages = mmap(NULL, pool_n * pool_buflen,
				  PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		torture_assert_goto(tctx, pool_pages != MAP_FAILED, ret, out,
				    "mmap pool");
		for (i = 0; i < pool_n; i++) {
			pool_iovs[i].iov_base = (char *)pool_pages + i * pool_buflen;
			pool_iovs[i].iov_len = pool_buflen;
		}

		torture_assert_int_equal_goto(tctx,
			truenas_uring_buf_index(u, pool_iovs[0].iov_base), -1,
			ret, out, "buf_index pre-registration");

		ret = truenas_uring_register_buffers(u, pool_iovs, pool_n);
		torture_assert_int_equal_goto(tctx, ret, 0, ret, out,
					      "register_buffers");
		ret = truenas_uring_register_buffers(u, pool_iovs, pool_n);
		torture_assert_int_equal_goto(tctx, ret, -EBUSY, ret, out,
					      "register_buffers double = EBUSY");

		for (i = 0; i < pool_n; i++) {
			char *base = pool_iovs[i].iov_base;
			bidx = truenas_uring_buf_index(u, base);
			torture_assert_int_equal_goto(tctx, bidx, (int)i,
				ret, out, "buf_index(base)");
			bidx = truenas_uring_buf_index(u, base + pool_buflen / 2);
			torture_assert_int_equal_goto(tctx, bidx, (int)i,
				ret, out, "buf_index(mid)");
			bidx = truenas_uring_buf_index(u, base + pool_buflen - 1);
			torture_assert_int_equal_goto(tctx, bidx, (int)i,
				ret, out, "buf_index(last)");
		}
		torture_assert_int_equal_goto(tctx,
			truenas_uring_buf_index(u, (char *)pool_pages + pool_n * pool_buflen),
			-1, ret, out, "buf_index(end+1)");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_buf_index(u, write_buf), -1,
			ret, out, "buf_index(non-pool)");

		/* pwrite -> auto-FIXED via write_fixed against slot 0. */
		memset(pool_iovs[0].iov_base, TEST_PATTERN, 1024);
		torture_assert_goto(tctx,
			lseek(st->fd, 0, SEEK_SET) != (off_t)-1,
			ret, out, "lseek for FIXED test");
		req = truenas_uring_pwrite_send(frame, ev, st->fd,
						pool_iovs[0].iov_base,
						1024, 0);
		torture_assert_goto(tctx, req != NULL && wait_for_req(ev, req),
				    ret, out, "pwrite (FIXED) send/wait");
		n = truenas_uring_pwrite_recv(req, &err);
		torture_assert_int_equal_goto(tctx, n, 1024, ret, out,
					      "pwrite FIXED n");
		TALLOC_FREE(req);

		memset(pool_iovs[1].iov_base, 0, 1024);
		req = truenas_uring_pread_send(frame, ev, st->fd,
					       pool_iovs[1].iov_base,
					       1024, 0);
		torture_assert_goto(tctx, req != NULL && wait_for_req(ev, req),
				    ret, out, "pread (FIXED) send/wait");
		n = truenas_uring_pread_recv(req, &err);
		torture_assert_int_equal_goto(tctx, n, 1024, ret, out,
					      "pread FIXED n");
		torture_assert_goto(tctx,
			memcmp(pool_iovs[1].iov_base, pool_iovs[0].iov_base,
			       1024) == 0,
			ret, out, "FIXED pread/pwrite bytes mismatch");
		TALLOC_FREE(req);

		memset(pool_iovs[2].iov_base, TEST_PATTERN, 512);
		req = truenas_uring_send_zc_send(frame, ev, st->tcp[1],
						 pool_iovs[2].iov_base,
						 512, MSG_NOSIGNAL, 0);
		torture_assert_goto(tctx, req != NULL && wait_for_req(ev, req),
				    ret, out, "send_zc (FIXED) send/wait");
		n = truenas_uring_send_zc_recv(req, &err);
		torture_assert_int_equal_goto(tctx, n, 512, ret, out,
					      "send_zc FIXED n");
		TALLOC_FREE(req);

		memset(read_buf, 0, BUF_LEN);
		torture_assert_int_equal_goto(tctx,
			read(st->tcp[0], read_buf, 512), 512, ret, out,
			"read after FIXED send_zc");
		torture_assert_goto(tctx,
			memcmp(read_buf, pool_iovs[2].iov_base, 512) == 0,
			ret, out, "FIXED send_zc bytes mismatch");

		/* Slot allocator: acquire / release / data. */
		{
			int s0, s1, s2, s3, s4;
			void *p0;
			size_t sz = 0;

			s0 = truenas_uring_buf_acquire(u, 0);
			s1 = truenas_uring_buf_acquire(u, 0);
			s2 = truenas_uring_buf_acquire(u, 0);
			s3 = truenas_uring_buf_acquire(u, 0);
			torture_assert_goto(tctx,
				s0 == 0 && s1 == 1 && s2 == 2 && s3 == 3,
				ret, out, "buf_acquire order");
			s4 = truenas_uring_buf_acquire(u, 0);
			torture_assert_int_equal_goto(tctx, s4, -1, ret, out,
				"buf_acquire on full pool");

			p0 = truenas_uring_buf_data(u, s0, &sz);
			torture_assert_goto(tctx,
				p0 == pool_iovs[0].iov_base && sz == pool_buflen,
				ret, out, "buf_data(s0)");
			torture_assert_goto(tctx,
				truenas_uring_buf_data(u, -1, NULL) == NULL &&
				truenas_uring_buf_data(u, 99, NULL) == NULL,
				ret, out, "buf_data oor");

			truenas_uring_buf_release(u, s1);
			torture_assert_int_equal_goto(tctx,
				truenas_uring_buf_acquire(u, 0), 1,
				ret, out, "buf_acquire after release");

			truenas_uring_buf_release(u, s0);
			truenas_uring_buf_release(u, 1);
			truenas_uring_buf_release(u, s2);
			truenas_uring_buf_release(u, s3);
			torture_assert_int_equal_goto(tctx,
				truenas_uring_buf_acquire(u, pool_buflen + 1),
				-1, ret, out,
				"buf_acquire with oversized hint");
			truenas_uring_buf_release(u, -1);
			truenas_uring_buf_release(u, 9999);
		}

		ret = truenas_uring_unregister_buffers(u);
		torture_assert_int_equal_goto(tctx, ret, 0, ret, out,
					      "unregister (pre-acquire test)");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_buf_acquire(u, 0), -1, ret, out,
			"buf_acquire on unregistered");

		ret = truenas_uring_register_buffers(u, pool_iovs, pool_n);
		torture_assert_int_equal_goto(tctx, ret, 0, ret, out,
					      "re-register");

		ret = truenas_uring_unregister_buffers(u);
		torture_assert_int_equal_goto(tctx, ret, 0, ret, out,
					      "unregister_buffers");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_buf_index(u, pool_iovs[0].iov_base),
			-1, ret, out, "buf_index after unregister");
		ret = truenas_uring_unregister_buffers(u);
		torture_assert_int_equal_goto(tctx, ret, -ENOENT, ret, out,
					      "double unregister = ENOENT");

		ret = truenas_uring_register_buffers(u, pool_iovs, pool_n);
		torture_assert_int_equal_goto(tctx, ret, 0, ret, out,
					      "re-register-2");
		ret = truenas_uring_unregister_buffers(u);
		torture_assert_int_equal_goto(tctx, ret, 0, ret, out,
					      "re-unregister-2");

		munmap(pool_pages, pool_n * pool_buflen);
	}

	/* ---------- Owned pool helper ---------- */
	{
		int s;
		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_owned_pool(u, 0, 4096),
			-EINVAL, ret, out, "owned_pool nr=0");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_owned_pool(u, 65, 4096),
			-EINVAL, ret, out, "owned_pool nr=65");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_owned_pool(u, 4, 0),
			-EINVAL, ret, out, "owned_pool bufsize=0");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_owned_pool(u, 4, 64 * 1024),
			0, ret, out, "owned_pool happy path");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_owned_pool(u, 4, 64 * 1024),
			-EBUSY, ret, out, "owned_pool re-call");

		s = truenas_uring_buf_acquire(u, 32 * 1024);
		torture_assert_int_equal_goto(tctx, s, 0, ret, out,
					      "owned_pool buf_acquire");
		torture_assert_goto(tctx,
			truenas_uring_buf_data(u, s, NULL) != NULL,
			ret, out, "owned_pool buf_data");
		truenas_uring_buf_release(u, s);
	}

	/* ---------- AF_ALG HMAC primitive (RFC 4231 vector 1) ---------- */
	{
		uint8_t key[20];
		const char *data = "Hi There";
		uint8_t mac[32];
		const uint8_t expected[32] = {
			0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
			0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
			0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
			0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
		};
		int hmac_fd;

		memset(key, 0x0b, sizeof(key));
		hmac_fd = truenas_uring_hmac_open("hmac(sha256)",
						  key, sizeof(key));
		if (hmac_fd == -ENOENT || hmac_fd == -EAFNOSUPPORT) {
			torture_warning(tctx,
				"SKIP AF_ALG hmac(sha256) check: not available "
				"in kernel CRYPTO_USER_API config");
		} else {
			torture_assert_goto(tctx, hmac_fd >= 0, ret, out,
					    "hmac_open");
			ret = truenas_uring_hmac_compute(
				hmac_fd, data, strlen(data),
				-1 /* no pipe */, 0,
				mac, sizeof(mac));
			if (ret != 0) {
				truenas_uring_hmac_close(hmac_fd);
				torture_fail_goto(tctx, out, "hmac_compute");
			}
			if (memcmp(mac, expected, sizeof(mac)) != 0) {
				truenas_uring_hmac_close(hmac_fd);
				torture_fail_goto(tctx, out,
					"HMAC-SHA256 mismatch vs RFC 4231");
			}
			truenas_uring_hmac_close(hmac_fd);
		}
	}

	/* ---- Pipe pool: bitmap scales past a single busy word ----
	 *
	 * The pipe pool uses a packed bitmap, so registering more slots
	 * than fit in one TURING_BUSY_BITS_PER_WORD-bit word must still
	 * deliver every requested slot, and an over-allocation must
	 * cleanly return the sentinel. POOL_N = bits-per-word + 1
	 * guarantees a slot lives in the second word of the bitmap.
	 *
	 * Uses its own tevent_context (and therefore its own
	 * truenas_uring) so it doesn't interfere with the shared `u`'s
	 * later 4-slot pool registration.
	 */
	{
		const unsigned int pool_n = TURING_BUSY_BITS_PER_WORD + 1;
		const unsigned int second_word_slot = TURING_BUSY_BITS_PER_WORD;
		struct tevent_context *ev2 = NULL;
		struct truenas_uring *u2 = NULL;
		struct truenas_uring_pipe *acq = NULL;
		struct truenas_uring_pipe overflow;
		bool saw_second_word = false;
		unsigned int i;

		ev2 = tevent_context_init(frame);
		torture_assert_goto(tctx, ev2 != NULL, ret, out,
			"tevent_context_init (wide pool)");
		u2 = truenas_uring_get(ev2);
		torture_assert_goto(tctx, u2 != NULL, ret, out,
			"truenas_uring_get (wide pool)");

		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_pipe_pool(u2, pool_n, 4096),
			0, ret, out, "register_pipe_pool (multi-word)");

		acq = talloc_array(frame, struct truenas_uring_pipe, pool_n);
		torture_assert_goto(tctx, acq != NULL, ret, out,
			"talloc acq[]");

		for (i = 0; i < pool_n; i++) {
			acq[i] = truenas_uring_pipe_acquire(u2);
			torture_assert_goto(tctx, acq[i].slot >= 0,
				ret, out,
				"acquire below pool_n must succeed");
		}
		overflow = truenas_uring_pipe_acquire(u2);
		torture_assert_goto(tctx, overflow.slot == -1,
			ret, out,
			"acquire past pool_n must return sentinel");

		for (i = 0; i < pool_n; i++) {
			if ((unsigned int)acq[i].slot == second_word_slot) {
				saw_second_word = true;
				break;
			}
		}
		torture_assert_goto(tctx, saw_second_word, ret, out,
			"first slot of bitmap word #2 was never delivered");

		for (i = 0; i < pool_n; i++) {
			truenas_uring_pipe_release(u2, acq[i].slot);
		}
		TALLOC_FREE(ev2);  /* destroys u2 + its pipes */
	}

	/* ---------- Pipe pool: register / acquire / release ---------- */
	{
		struct truenas_uring_pipe p0, p1, p2, p3, p4;
		const char *probe = "abc";
		char back[8] = {0};

		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_pipe_pool(u, 0, 0), -EINVAL,
			ret, out, "pipe_pool nr=0");

		p0 = truenas_uring_pipe_acquire(u);
		torture_assert_goto(tctx,
			p0.rfd == -1 && p0.wfd == -1 && p0.slot == -1,
			ret, out, "pipe_acquire pre-register sentinel");

		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_pipe_pool(u, 4, 4096), 0,
			ret, out, "pipe_pool happy path");
		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_pipe_pool(u, 4, 4096), -EBUSY,
			ret, out, "pipe_pool re-register = EBUSY");

		p0 = truenas_uring_pipe_acquire(u);
		p1 = truenas_uring_pipe_acquire(u);
		p2 = truenas_uring_pipe_acquire(u);
		p3 = truenas_uring_pipe_acquire(u);
		torture_assert_goto(tctx,
			p0.slot == 0 && p1.slot == 1 && p2.slot == 2 && p3.slot == 3,
			ret, out, "pipe_acquire order");
		p4 = truenas_uring_pipe_acquire(u);
		torture_assert_int_equal_goto(tctx, p4.slot, -1, ret, out,
			"pipe_acquire on exhausted pool");

		torture_assert_int_equal_goto(tctx,
			write(p0.wfd, probe, 3), 3, ret, out,
			"pipe_pool write");
		torture_assert_goto(tctx,
			read(p0.rfd, back, sizeof(back)) == 3 &&
			memcmp(back, probe, 3) == 0,
			ret, out, "pipe_pool read");

		truenas_uring_pipe_release(u, p1.slot);
		p1 = truenas_uring_pipe_acquire(u);
		torture_assert_int_equal_goto(tctx, p1.slot, 1, ret, out,
			"pipe_acquire after release");

		truenas_uring_pipe_release(u, -5);
		truenas_uring_pipe_release(u, 9999);
	}

	/* ---------- Socket I/O: non-zero-copy send / sendmsg / recvmsg ---------- */
	req = truenas_uring_send_send(frame, ev, st->sv[0],
				      write_buf, 64, MSG_NOSIGNAL);
	torture_assert_goto(tctx, req != NULL && wait_for_req(ev, req),
			    ret, out, "send (non-ZC) send/wait");
	n = truenas_uring_send_recv(req, &err);
	torture_assert_int_equal_goto(tctx, n, 64, ret, out, "send n");
	TALLOC_FREE(req);

	memset(read_buf, 0, BUF_LEN);
	torture_assert_goto(tctx,
		read(st->sv[1], read_buf, 64) == 64 &&
		memcmp(read_buf, write_buf, 64) == 0,
		ret, out, "send (non-ZC) bytes");

	{
		struct iovec iov[2] = {
			{ .iov_base = write_buf,      .iov_len = 32 },
			{ .iov_base = write_buf + 32, .iov_len = 64 },
		};
		struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };

		req = truenas_uring_sendmsg_send(frame, ev, st->sv[0],
						 &msg, MSG_NOSIGNAL);
		torture_assert_goto(tctx, req != NULL && wait_for_req(ev, req),
				    ret, out, "sendmsg send/wait");
		n = truenas_uring_sendmsg_recv(req, &err);
		torture_assert_int_equal_goto(tctx, n, 96, ret, out,
					      "sendmsg n");
		TALLOC_FREE(req);

		memset(read_buf, 0, BUF_LEN);
		torture_assert_goto(tctx,
			read(st->sv[1], read_buf, 96) == 96 &&
			memcmp(read_buf, write_buf, 96) == 0,
			ret, out, "sendmsg bytes");
	}

	torture_assert_int_equal_goto(tctx, write(st->sv[0], write_buf, 96),
				      96, ret, out, "seed for recvmsg");
	{
		char part_a[32], part_b[64];
		struct iovec iov[2] = {
			{ .iov_base = part_a, .iov_len = sizeof(part_a) },
			{ .iov_base = part_b, .iov_len = sizeof(part_b) },
		};
		struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };

		req = truenas_uring_recvmsg_send(frame, ev, st->sv[1], &msg, 0);
		torture_assert_goto(tctx, req != NULL && wait_for_req(ev, req),
				    ret, out, "recvmsg send/wait");
		n = truenas_uring_recvmsg_recv(req, &err);
		torture_assert_int_equal_goto(tctx, n, 96, ret, out, "recvmsg n");
		TALLOC_FREE(req);

		torture_assert_goto(tctx,
			memcmp(part_a, write_buf, 32) == 0 &&
			memcmp(part_b, write_buf + 32, 64) == 0,
			ret, out, "recvmsg bytes");
	}

	/* ---------- Socket I/O: mid-flight recv cancellation ---------- */
	memset(read_buf, 0, 64);
	req = truenas_uring_recv_send(frame, ev, st->sv[1], read_buf, 64, 0);
	torture_assert_goto(tctx, req != NULL, ret, out, "recv_send (cancel)");
	TALLOC_FREE(req);  /* destructor -> sync cancel */

	torture_assert_int_equal_goto(tctx, write(st->sv[0], write_buf, 32),
				      32, ret, out, "post-cancel seed");
	req = truenas_uring_recv_send(frame, ev, st->sv[1], read_buf, 32, 0);
	torture_assert_goto(tctx, req != NULL && wait_for_req(ev, req),
			    ret, out, "post-cancel recv");
	n = truenas_uring_recv_recv(req, &err);
	torture_assert_int_equal_goto(tctx, n, 32, ret, out, "post-cancel n");
	torture_assert_goto(tctx, memcmp(read_buf, write_buf, 32) == 0,
			    ret, out, "post-cancel bytes");
	TALLOC_FREE(req);

	/* ---------- Socket I/O: recv() returns 0 on peer close ---------- */
	{
		int sv2[2] = { -1, -1 };
		torture_assert_int_equal_goto(tctx,
			socketpair(AF_UNIX, SOCK_STREAM, 0, sv2), 0,
			ret, out, "socketpair (EOF test)");
		close(sv2[0]);  /* peer drops connection */
		req = truenas_uring_recv_send(frame, ev, sv2[1],
					      read_buf, 64, 0);
		torture_assert_goto(tctx,
			req != NULL && wait_for_req(ev, req),
			ret, out, "recv (EOF) send/wait");
		n = truenas_uring_recv_recv(req, &err);
		close(sv2[1]);
		torture_assert_int_equal_goto(tctx, n, 0, ret, out,
			"recv after peer close returns 0");
		TALLOC_FREE(req);
	}

	/* ---------- File I/O: two pread requests in flight at once ---------- */
	{
		struct tevent_req *req_a, *req_b;
		char *buf_a = talloc_array(frame, char, 512);
		char *buf_b = talloc_array(frame, char, 512);
		ssize_t na, nb;
		int ea = 0, eb = 0;

		torture_assert_goto(tctx, buf_a != NULL && buf_b != NULL,
			ret, out, "talloc concurrent buffers");
		memset(buf_a, 0, 512);
		memset(buf_b, 0, 512);

		req_a = truenas_uring_pread_send(frame, ev, st->fd,
						 buf_a, 512, 0);
		req_b = truenas_uring_pread_send(frame, ev, st->fd,
						 buf_b, 512, 512);
		torture_assert_goto(tctx,
			req_a != NULL && req_b != NULL,
			ret, out, "concurrent pread_send");
		while (tevent_req_is_in_progress(req_a) ||
		       tevent_req_is_in_progress(req_b)) {
			torture_assert_int_equal_goto(tctx,
				tevent_loop_once(ev), 0, ret, out,
				"concurrent wait loop");
		}
		na = truenas_uring_pread_recv(req_a, &ea);
		nb = truenas_uring_pread_recv(req_b, &eb);
		torture_assert_int_equal_goto(tctx, na, 512, ret, out,
			"concurrent pread A n");
		torture_assert_int_equal_goto(tctx, nb, 512, ret, out,
			"concurrent pread B n");
		torture_assert_goto(tctx,
			memcmp(buf_a, write_buf, 512) == 0,
			ret, out, "concurrent A bytes");
		torture_assert_goto(tctx,
			memcmp(buf_b, write_buf, 512) == 0,
			ret, out, "concurrent B bytes");
		TALLOC_FREE(req_a);
		TALLOC_FREE(req_b);
	}

	/* ---------- Splice: mid-flight cancel (idle pipe) ---------- */
	{
		int idle[2] = { -1, -1 };
		int64_t in_off = 0;
		torture_assert_int_equal_goto(tctx, pipe(idle), 0,
			ret, out, "pipe for splice cancel");
		req = truenas_uring_splice_send(frame, ev,
						idle[0], NULL,
						st->fd, &in_off,
						BUF_LEN, 0);
		torture_assert_goto(tctx, req != NULL,
			ret, out, "splice (cancel) send");
		/*
		 * Nothing on the read end of `idle`; the splice will block in
		 * the kernel waiting for input. Free the req mid-flight; the
		 * destructor must cancel cleanly so subsequent submissions on
		 * the same ring still work.
		 */
		TALLOC_FREE(req);
		close(idle[0]);
		close(idle[1]);

		/* Verify ring still healthy with a follow-up pread. */
		memset(read_buf, 0, 64);
		req = truenas_uring_pread_send(frame, ev, st->fd,
					       read_buf, 64, 0);
		torture_assert_goto(tctx,
			req != NULL && wait_for_req(ev, req),
			ret, out, "post-splice-cancel pread");
		n = truenas_uring_pread_recv(req, &err);
		torture_assert_int_equal_goto(tctx, n, 64, ret, out,
			"post-splice-cancel n");
		TALLOC_FREE(req);
	}

	/* ---------- Registered buffers: buf_acquire size_hint boundary ---------- */
	{
		const size_t pool_buflen = 4096;
		const unsigned int pool_n = 2;
		void *pool_pages = NULL;
		struct iovec pool_iovs[2];
		unsigned int i;
		int s;

		/* Owned-pool test above left a pool registered; release it
		 * so we can register our own. */
		(void)truenas_uring_unregister_buffers(u);

		pool_pages = mmap(NULL, pool_n * pool_buflen,
				  PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		torture_assert_goto(tctx, pool_pages != MAP_FAILED,
			ret, out, "mmap (size_hint test)");
		for (i = 0; i < pool_n; i++) {
			pool_iovs[i].iov_base =
				(char *)pool_pages + i * pool_buflen;
			pool_iovs[i].iov_len = pool_buflen;
		}
		torture_assert_int_equal_goto(tctx,
			truenas_uring_register_buffers(u, pool_iovs, pool_n),
			0, ret, out, "register (size_hint)");

		/* size_hint == buflen: must succeed (>= passes). */
		s = truenas_uring_buf_acquire(u, pool_buflen);
		torture_assert_int_equal_goto(tctx, s, 0, ret, out,
			"buf_acquire size_hint == buflen");
		truenas_uring_buf_release(u, s);

		/* size_hint == buflen + 1: must fail. */
		s = truenas_uring_buf_acquire(u, pool_buflen + 1);
		torture_assert_int_equal_goto(tctx, s, -1, ret, out,
			"buf_acquire size_hint == buflen + 1");

		torture_assert_int_equal_goto(tctx,
			truenas_uring_unregister_buffers(u), 0,
			ret, out, "unregister (size_hint)");
		munmap(pool_pages, pool_n * pool_buflen);
	}

	/* ---------- Pipe pool: drains stale bytes on release ---------- */
	{
		struct truenas_uring_pipe p;
		const char *stale = "OLD";
		char back[16] = {0};
		ssize_t r;
		int flags;
		int i;

		/* Earlier pipe-pool section held all 4 slots; release them. */
		for (i = 0; i < 4; i++) {
			truenas_uring_pipe_release(u, i);
		}

		p = truenas_uring_pipe_acquire(u);
		torture_assert_goto(tctx, p.slot >= 0, ret, out,
			"pipe acquire (drain test)");
		torture_assert_int_equal_goto(tctx,
			write(p.wfd, stale, 3), 3, ret, out,
			"pipe write stale");
		truenas_uring_pipe_release(u, p.slot);  /* must drain */

		p = truenas_uring_pipe_acquire(u);
		torture_assert_goto(tctx, p.slot >= 0, ret, out,
			"pipe re-acquire after drain");
		flags = fcntl(p.rfd, F_GETFL, 0);
		torture_assert_goto(tctx, flags >= 0, ret, out,
			"fcntl F_GETFL");
		torture_assert_int_equal_goto(tctx,
			fcntl(p.rfd, F_SETFL, flags | O_NONBLOCK), 0,
			ret, out, "fcntl F_SETFL O_NONBLOCK");
		r = read(p.rfd, back, sizeof(back));
		(void)fcntl(p.rfd, F_SETFL, flags);
		torture_assert_goto(tctx,
			r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
			ret, out, "stale bytes were drained on release");
		truenas_uring_pipe_release(u, p.slot);
	}

	/* ---------- AF_ALG HMAC: argument validation + payload-via-pipe ---------- */
	{
		uint8_t key[20];
		int hmac_fd;
		uint8_t mac[32];

		memset(key, 0x0b, sizeof(key));

		/* NULL alg name -> EINVAL. */
		torture_assert_int_equal_goto(tctx,
			truenas_uring_hmac_open(NULL, key, sizeof(key)),
			-EINVAL, ret, out, "hmac_open NULL alg");

		/* Overlong alg name -> EINVAL. */
		{
			char too_long[128];
			memset(too_long, 'x', sizeof(too_long));
			too_long[sizeof(too_long) - 1] = '\0';
			torture_assert_int_equal_goto(tctx,
				truenas_uring_hmac_open(too_long,
					key, sizeof(key)),
				-EINVAL, ret, out,
				"hmac_open overlong alg");
		}

		/* Unsupported algorithm -> negative errno (typically ENOENT). */
		hmac_fd = truenas_uring_hmac_open("hmac(no_such_algo_xyz)",
						  key, sizeof(key));
		if (hmac_fd == -EAFNOSUPPORT) {
			torture_warning(tctx,
				"AF_ALG not available; skipping unsupported-alg test");
		} else {
			torture_assert_goto(tctx, hmac_fd < 0, ret, out,
				"hmac_open bogus alg should fail");
		}

		/* Payload-via-pipe path: matches header-only HMAC of the same
		 * concatenated input (RFC 4231 vector 1: "Hi There"). Header
		 * carries "Hi " (3 bytes), pipe carries "There" (5 bytes). */
		hmac_fd = truenas_uring_hmac_open("hmac(sha256)",
						  key, sizeof(key));
		if (hmac_fd == -ENOENT || hmac_fd == -EAFNOSUPPORT) {
			torture_warning(tctx,
				"AF_ALG hmac(sha256) unavailable; skipping pipe-payload test");
		} else {
			int pp[2] = { -1, -1 };
			const uint8_t expected[32] = {
				0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
				0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
				0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
				0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
			};

			torture_assert_goto(tctx, hmac_fd >= 0,
				ret, out, "hmac_open (pipe test)");
			torture_assert_int_equal_goto(tctx,
				pipe(pp), 0, ret, out,
				"pipe (hmac payload)");
			torture_assert_int_equal_goto(tctx,
				write(pp[1], "There", 5), 5, ret, out,
				"pipe write payload");
			close(pp[1]);  /* signal EOF after the 5 bytes */
			ret = truenas_uring_hmac_compute(hmac_fd,
				"Hi ", 3, pp[0], 5,
				mac, sizeof(mac));
			close(pp[0]);
			if (ret != 0) {
				truenas_uring_hmac_close(hmac_fd);
				torture_fail_goto(tctx, out,
					"hmac_compute (header + pipe payload)");
			}
			if (memcmp(mac, expected, sizeof(mac)) != 0) {
				truenas_uring_hmac_close(hmac_fd);
				torture_fail_goto(tctx, out,
					"hmac pipe-payload mismatch vs RFC 4231");
			}
			truenas_uring_hmac_close(hmac_fd);
		}

		/* hmac_close on -1 is a no-op (sentinel handling). */
		truenas_uring_hmac_close(-1);
	}

	/* ---- Splice page-borrow cross-validation (memfd vs local FS) ---- */
	torture_assert_goto(tctx,
		splice_borrow_cross_validate(tctx), ret, out,
		"ZFS splice page-borrow regression -- concurrent pwrite leaked "
		"into pipe pages already queued for SMB2 wire transmit");

	TALLOC_FREE(frame);
	return true;

out:
	TALLOC_FREE(frame);
	return false;
}

struct torture_suite *torture_local_truenas_uring(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx,
							   "truenas_uring");

	torture_suite_add_simple_test(suite, "all", test_truenas_uring);
	suite->description = talloc_strdup(suite,
		"Functional tests for source3/lib/truenas_uring "
		"(io_uring abstraction layer)");
	return suite;
}

#endif /* HAVE_LIBURING */
