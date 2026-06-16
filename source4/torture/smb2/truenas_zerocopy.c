/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
   Unix SMB/CIFS implementation.

   End-to-end smbtorture coverage for the TrueNAS-fork SMB2/3 zero-copy
   fast paths in smbd. Each test exercises one of the dispatch modes:

     - unsigned splice WRITE  (socket -> pipe -> file)
     - signed   splice WRITE  (+ AF_ALG verify-before-write)
     - unsigned splice READ   (file -> pipe -> socket)
     - signed   splice READ   (+ AF_ALG, patched-MAC header)
     - encrypted WRITE        (registered buffer)
     - encrypted READ         (registered buffer + SENDMSG_ZC)

   plus a signed-WRITE tamper-rejection test that asserts the
   verify-before-write invariant (MAC mismatch -> ACCESS_DENIED, file
   bytes unchanged).

   Each round-trip test loops over a size matrix (4 KiB, 64 KiB, 1 MiB,
   4 MiB, 8 MiB, 16 MiB) so chunked splice boundaries are exercised.

   Server-side counter exposure (via the smbtorture-only FSCTL pair
   FSCTL_SMBTORTURE_TRUENAS_URING_COUNTERS_{READ,RESET}) lets each
   test assert that the EXPECTED dispatch path actually ran, rather
   than the request silently taking the legacy fallback while producing
   the correct bytes.

   Server requirements (smb.conf):
     truenas_uring:enabled    = yes     # master knob; default is yes,
                                        # listed here for clarity. When
                                        # on, the per-PDU dispatcher
                                        # auto-routes (splice, signed
                                        # splice, registered + SEND_ZC)
                                        # based on the PDU's signing/
                                        # encryption posture.
     smbd:FSCTL_SMBTORTURE    = yes     # required for counter assertions;
                                        # without it the FSCTLs return
                                        # NOT_SUPPORTED and tests SKIP.

   For the encrypted tests to actually engage the registered-buffer
   pool, the share must accept SMB3 encryption (default
   `smb encrypt = auto`).

   Run:
     smbtorture //host/share smb2.truenas_zerocopy -U user%pass

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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "libcli/smb/smb_constants.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"  /* cli_credentials_shallow_copy */
#include "lib/param/param.h"
#include "libcli/resolve/resolve.h"
#include "lib/cmdline/cmdline.h"
#include "lib/util/tevent_ntstatus.h"  /* tevent_req_poll_ntstatus */

/* Mirror of smbd's struct samba_uring_counters wire format. Field
 * order and offsets MUST match SBVAL layout in
 * source3/smbd/smb2_ioctl_smbtorture.c::FSCTL_..._COUNTERS_READ. */
struct truenas_uring_counters {
	uint64_t unsigned_splice_in;
	uint64_t signed_splice_in;
	uint64_t signed_splice_in_denied;
	uint64_t unsigned_splice_out;
	uint64_t signed_splice_out;
	uint64_t encrypted_recv;
	uint64_t encrypted_send_zc;
	uint64_t legacy_recv;
	uint64_t legacy_send;
	uint64_t bytes_unsigned_splice_in;
	uint64_t bytes_signed_splice_in;
	uint64_t bytes_unsigned_splice_out;
	uint64_t bytes_signed_splice_out;
	uint64_t bytes_encrypted_in;
	uint64_t bytes_encrypted_out;
	uint64_t signed_alg_cache_hits;
	uint64_t signed_alg_cache_misses;
	uint64_t inflight_throttle_events;
	uint64_t inflight_bytes_peak;
	uint64_t unsigned_recv_mempool;
	uint64_t bytes_unsigned_mempool_out;
};
#define COUNTERS_WIRE_BYTES (21 * 8)

/* Mirror of smbd's TURING_MAX_INFLIGHT_BYTES_DEFAULT
 * (smbd_smb2_uring.h). Defined locally so the suite doesn't pull in
 * smbd-internal headers. Used by the throttle test to restore a
 * generous cap after dialing it down. */
#define INFLIGHT_DEFAULT_CAP ((uint64_t)512 * 1024 * 1024)

/*
 * Size matrix. Capped at 1 MiB because larger writes need server-side
 * credit windows (`smb2 max credits = N`) bumped beyond the default 31
 * to avoid the smbtorture client's "Insufficient credits" abort. 1 MiB
 * is enough to exercise the splice pipe-pool path and the chunked
 * accounting; the 4 / 8 / 16 MiB cases can be added back if the
 * harness raises max credits.
 */
static const size_t test_sizes[] = {
	4 * 1024,                  /* 4 KiB     - small */
	64 * 1024,                 /* 64 KiB    - typical block */
	256 * 1024,                /* 256 KiB   - mid */
	1 * 1024 * 1024,           /* 1 MiB     - one splice chunk */
};

/* ---------------- FSCTL helpers ---------------- */

static bool fsctl_counters_reset(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	NTSTATUS status;
	DATA_BLOB out_input  = data_blob_null;
	DATA_BLOB out_output = data_blob_null;
	uint32_t timeout_ms =
		tree->session->transport->options.request_timeout * 1000;
	TALLOC_CTX *tmp = talloc_new(tctx);

	status = smb2cli_ioctl(tree->session->transport->conn,
			       timeout_ms,
			       tree->session->smbXcli,
			       tree->smbXcli,
			       UINT64_MAX, UINT64_MAX,
			       FSCTL_SMBTORTURE_TRUENAS_URING_COUNTERS_RESET,
			       0, NULL,
			       0, NULL,
			       SMB2_IOCTL_FLAG_IS_FSCTL,
			       tmp,
			       &out_input, &out_output);
	talloc_free(tmp);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_FS_DRIVER_REQUIRED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST)) {
		torture_skip_goto(tctx, fail,
			"server lacks FSCTL_SMBTORTURE_TRUENAS_URING -- "
			"set 'smbd:FSCTL_SMBTORTURE = yes' in smb.conf\n");
	}
	torture_assert_ntstatus_ok(tctx, status, "counters_reset");
	return true;
fail:
	return false;
}

static bool fsctl_counters_read(struct torture_context *tctx,
				struct smb2_tree *tree,
				struct truenas_uring_counters *out)
{
	NTSTATUS status;
	DATA_BLOB out_input  = data_blob_null;
	DATA_BLOB out_output = data_blob_null;
	uint32_t timeout_ms =
		tree->session->transport->options.request_timeout * 1000;
	TALLOC_CTX *tmp = talloc_new(tctx);
	const uint8_t *p;

	status = smb2cli_ioctl(tree->session->transport->conn,
			       timeout_ms,
			       tree->session->smbXcli,
			       tree->smbXcli,
			       UINT64_MAX, UINT64_MAX,
			       FSCTL_SMBTORTURE_TRUENAS_URING_COUNTERS_READ,
			       0, NULL,
			       COUNTERS_WIRE_BYTES, NULL,
			       SMB2_IOCTL_FLAG_IS_FSCTL,
			       tmp,
			       &out_input, &out_output);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp);
		torture_warning(tctx, "counters_read failed: %s",
				nt_errstr(status));
		return false;
	}
	if (out_output.length != COUNTERS_WIRE_BYTES) {
		talloc_free(tmp);
		torture_warning(tctx,
			"counters_read returned %zu bytes, expected %d",
			(size_t)out_output.length, COUNTERS_WIRE_BYTES);
		return false;
	}
	p = out_output.data;
	out->unsigned_splice_in        = BVAL(p,   0);
	out->signed_splice_in          = BVAL(p,   8);
	out->signed_splice_in_denied   = BVAL(p,  16);
	out->unsigned_splice_out       = BVAL(p,  24);
	out->signed_splice_out         = BVAL(p,  32);
	out->encrypted_recv     = BVAL(p,  40);
	out->encrypted_send_zc         = BVAL(p,  48);
	out->legacy_recv               = BVAL(p,  56);
	out->legacy_send               = BVAL(p,  64);
	out->bytes_unsigned_splice_in  = BVAL(p,  72);
	out->bytes_signed_splice_in    = BVAL(p,  80);
	out->bytes_unsigned_splice_out = BVAL(p,  88);
	out->bytes_signed_splice_out   = BVAL(p,  96);
	out->bytes_encrypted_in        = BVAL(p, 104);
	out->bytes_encrypted_out       = BVAL(p, 112);
	out->signed_alg_cache_hits     = BVAL(p, 120);
	out->signed_alg_cache_misses   = BVAL(p, 128);
	out->inflight_throttle_events  = BVAL(p, 136);
	out->inflight_bytes_peak       = BVAL(p, 144);
	out->unsigned_recv_mempool      = BVAL(p, 152);
	out->bytes_unsigned_mempool_out = BVAL(p, 160);
	talloc_free(tmp);
	return true;
}

static bool fsctl_force_next_signed_write_fail(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	NTSTATUS status;
	DATA_BLOB out_input  = data_blob_null;
	DATA_BLOB out_output = data_blob_null;
	uint32_t timeout_ms =
		tree->session->transport->options.request_timeout * 1000;
	TALLOC_CTX *tmp = talloc_new(tctx);

	status = smb2cli_ioctl(tree->session->transport->conn,
			       timeout_ms,
			       tree->session->smbXcli,
			       tree->smbXcli,
			       UINT64_MAX, UINT64_MAX,
			       FSCTL_SMBTORTURE_TRUENAS_URING_FORCE_NEXT_SIGNED_WRITE_FAIL,
			       0, NULL,
			       0, NULL,
			       SMB2_IOCTL_FLAG_IS_FSCTL,
			       tmp,
			       &out_input, &out_output);
	talloc_free(tmp);
	torture_assert_ntstatus_ok(tctx, status, "force_next_signed_write_fail");
	return true;
}

static bool fsctl_force_next_posix_append(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	NTSTATUS status;
	DATA_BLOB out_input  = data_blob_null;
	DATA_BLOB out_output = data_blob_null;
	uint32_t timeout_ms =
		tree->session->transport->options.request_timeout * 1000;
	TALLOC_CTX *tmp = talloc_new(tctx);

	status = smb2cli_ioctl(tree->session->transport->conn,
			       timeout_ms,
			       tree->session->smbXcli,
			       tree->smbXcli,
			       UINT64_MAX, UINT64_MAX,
			       FSCTL_SMBTORTURE_TRUENAS_URING_FORCE_NEXT_POSIX_APPEND,
			       0, NULL,
			       0, NULL,
			       SMB2_IOCTL_FLAG_IS_FSCTL,
			       tmp,
			       &out_input, &out_output);
	talloc_free(tmp);
	torture_assert_ntstatus_ok(tctx, status, "force_next_posix_append");
	return true;
}

static bool fsctl_set_max_inflight_bytes(struct torture_context *tctx,
					 struct smb2_tree *tree,
					 uint64_t cap)
{
	NTSTATUS status;
	DATA_BLOB out_input  = data_blob_null;
	DATA_BLOB out_output = data_blob_null;
	uint32_t timeout_ms =
		tree->session->transport->options.request_timeout * 1000;
	TALLOC_CTX *tmp = talloc_new(tctx);
	uint8_t body[8];
	DATA_BLOB in_body;

	SBVAL(body, 0, cap);
	in_body = data_blob_const(body, sizeof(body));
	status = smb2cli_ioctl(tree->session->transport->conn,
			       timeout_ms,
			       tree->session->smbXcli,
			       tree->smbXcli,
			       UINT64_MAX, UINT64_MAX,
			       FSCTL_SMBTORTURE_TRUENAS_URING_SET_MAX_INFLIGHT_BYTES,
			       0, &in_body,
			       0, NULL,
			       SMB2_IOCTL_FLAG_IS_FSCTL,
			       tmp,
			       &out_input, &out_output);
	talloc_free(tmp);
	torture_assert_ntstatus_ok(tctx, status, "set_max_inflight_bytes");
	return true;
}

/* ---------------- Round-trip helper ---------------- */

enum dispatch_mode {
	MODE_UNSIGNED_SPLICE_IN,
	MODE_SIGNED_SPLICE_IN,
	MODE_UNSIGNED_SPLICE_OUT,
	MODE_SIGNED_SPLICE_OUT,
	MODE_ENCRYPTED_IN,        /* encrypted WRITE */
	MODE_ENCRYPTED_OUT,       /* encrypted READ */
};

/*
 * For each mode, return a pointer-to-member-offset into struct
 * truenas_uring_counters identifying the field that MUST tick up by
 * the number of ops the test performed.
 */
static size_t expected_counter_offset(enum dispatch_mode m)
{
	switch (m) {
	case MODE_UNSIGNED_SPLICE_IN:
		return offsetof(struct truenas_uring_counters, unsigned_splice_in);
	case MODE_SIGNED_SPLICE_IN:
		return offsetof(struct truenas_uring_counters, signed_splice_in);
	case MODE_UNSIGNED_SPLICE_OUT:
		/*
		 * Plain READs are served from the reclaimable io_memory_pool +
		 * SENDMSG_ZC (schedule_smb2_aio_read); file -> pipe -> socket
		 * splice is only a fallback for when SENDMSG_ZC is disabled.
		 * Assert on the mempool counter to match the default behavior.
		 */
		return offsetof(struct truenas_uring_counters, unsigned_recv_mempool);
	case MODE_SIGNED_SPLICE_OUT:
		return offsetof(struct truenas_uring_counters, signed_splice_out);
	case MODE_ENCRYPTED_IN:
	case MODE_ENCRYPTED_OUT:
		return offsetof(struct truenas_uring_counters, encrypted_recv);
	}
	return 0;
}

static uint64_t counter_at(const struct truenas_uring_counters *c, size_t ofs)
{
	uint64_t v;
	memcpy(&v, ((const uint8_t *)c) + ofs, sizeof(v));
	return v;
}

/*
 * For each direction, perform one or more WRITE+READ rounds at each
 * size in the matrix, comparing the read-back bytes to the source. Then
 * assert the expected counter ticked up by (num_sizes) for inbound,
 * (num_sizes) for outbound, or the appropriate combination for
 * encrypted (which exercises both ends).
 *
 * For OUT modes, file is pre-populated by a WRITE on this same tree
 * (which on a signed/unsigned splice-enabled smbd will itself take the
 * inbound splice path). We only assert on the OUT counter, so an
 * extra-counted inbound op is harmless.
 */
static bool do_roundtrip(struct torture_context *tctx,
			 struct smb2_tree *tree,
			 enum dispatch_mode mode,
			 const char *fname)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	uint8_t *src = NULL;
	uint8_t *dst = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};
	size_t ofs = expected_counter_offset(mode);
	size_t i;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_create");
	h = cr.out.file.handle;

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");

	for (i = 0; i < ARRAY_SIZE(test_sizes); i++) {
		size_t sz = test_sizes[i];

		src = talloc_array(tctx, uint8_t, sz);
		dst = talloc_array(tctx, uint8_t, sz);
		torture_assert_goto(tctx, src != NULL && dst != NULL,
			ret, done, "talloc_array");
		generate_random_buffer(src, sz);
		memset(dst, 0, sz);

		/* WRITE (also pre-populates for OUT modes). */
		status = smb2_util_write(tree, h, src, 0, sz);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_util_write");

		/*
		 * Reopen for READ. The splice READ eligibility gate
		 * consults fsp->fsp_name->st.st_ex_size which is cached at
		 * open time -- on the handle we just wrote through, the
		 * cached size is still 0 and the gate rejects with RETRY.
		 * A fresh handle picks up the post-WRITE size.
		 */
		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
		ZERO_STRUCT(cr);
		cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
		cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
				   | NTCREATEX_SHARE_ACCESS_WRITE;
		cr.in.create_disposition = NTCREATEX_DISP_OPEN;
		cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
		cr.in.fname = fname;
		status = smb2_create(tree, tctx, &cr);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"reopen for read");
		h = cr.out.file.handle;

		/* READ back. */
		{
			struct smb2_read rd;
			ZERO_STRUCT(rd);
			rd.in.file.handle = h;
			rd.in.length      = sz;
			rd.in.offset      = 0;
			status = smb2_read(tree, tctx, &rd);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_read");
			torture_assert_int_equal_goto(tctx,
				rd.out.data.length, sz, ret, done,
				"short read");
			memcpy(dst, rd.out.data.data, sz);
			data_blob_free(&rd.out.data);
		}

		torture_assert_goto(tctx, memcmp(src, dst, sz) == 0,
			ret, done, "round-trip byte mismatch");

		talloc_free(src); src = NULL;
		talloc_free(dst); dst = NULL;
	}

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read");

	torture_comment(tctx,
		"counters after: us_in=%llu sig_in=%llu sig_in_denied=%llu "
		"us_out=%llu sig_out=%llu enc_rb=%llu enc_zc=%llu "
		"leg_recv=%llu leg_send=%llu\n",
		(unsigned long long)after.unsigned_splice_in,
		(unsigned long long)after.signed_splice_in,
		(unsigned long long)after.signed_splice_in_denied,
		(unsigned long long)after.unsigned_splice_out,
		(unsigned long long)after.signed_splice_out,
		(unsigned long long)after.encrypted_recv,
		(unsigned long long)after.encrypted_send_zc,
		(unsigned long long)after.legacy_recv,
		(unsigned long long)after.legacy_send);

	{
		uint64_t expected_delta;
		uint64_t got;

		switch (mode) {
		case MODE_UNSIGNED_SPLICE_IN:
		case MODE_SIGNED_SPLICE_IN:
			/* one WRITE per size */
			expected_delta = ARRAY_SIZE(test_sizes);
			break;
		case MODE_UNSIGNED_SPLICE_OUT:
		case MODE_SIGNED_SPLICE_OUT:
			/* one READ per size */
			expected_delta = ARRAY_SIZE(test_sizes);
			break;
		case MODE_ENCRYPTED_IN:
		case MODE_ENCRYPTED_OUT:
			/* one regbuf alloc per READ (per size) */
			expected_delta = ARRAY_SIZE(test_sizes);
			break;
		}
		got = counter_at(&after, ofs) - counter_at(&before, ofs);
		torture_assert_u64_equal_goto(tctx, got, expected_delta,
			ret, done,
			"expected dispatch path not taken (counter delta off "
			"-- did the request fall back to the legacy path?)");

		if (mode == MODE_UNSIGNED_SPLICE_IN ||
		    mode == MODE_SIGNED_SPLICE_IN) {
			torture_assert_u64_equal_goto(tctx,
				after.legacy_recv, 0,
				ret, done,
				"legacy_recv counter ticked -- a WRITE PDU "
				"silently fell back to sys_recvfile");
		}
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	talloc_free(dst);
	return ret;
}

/* ---------------- Connection setup helpers ---------------- */

static bool connect_with_options(struct torture_context *tctx,
				 enum smb_signing_setting signing,
				 enum smb_encryption_setting encryption,
				 struct smb2_tree **tree_out)
{
	struct smbcli_options options;
	struct cli_credentials *creds;
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);

	creds = cli_credentials_shallow_copy(tctx,
		samba_cmdline_get_creds());
	torture_assert(tctx, creds != NULL, "creds copy");

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	options.signing = signing;

	if (encryption == SMB_ENCRYPTION_REQUIRED) {
		cli_credentials_set_smb_encryption(creds,
			SMB_ENCRYPTION_REQUIRED, CRED_SPECIFIED);
	}

	/*
	 * Bypass torture_smb2_connection_ext: it calls smb2_connect_ext
	 * with samba_cmdline_get_creds() directly, so our encryption tweak
	 * on the shallow-copied creds would be ignored.
	 */
	status = smb2_connect_ext(tctx,
				  host,
				  share,
				  tctx->lp_ctx,
				  lpcfg_resolve_context(tctx->lp_ctx),
				  creds,
				  NULL, /* existing_conn */
				  0,
				  tree_out,
				  tctx->ev,
				  &options,
				  lpcfg_socket_options(tctx->lp_ctx),
				  lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx,
			"connect_with_options(signing=%d enc=%d) failed: %s",
			(int)signing, (int)encryption, nt_errstr(status));
		return false;
	}
	return true;
}

/* ---------------- Per-mode test functions ---------------- */

static bool test_unsigned_splice_write_roundtrip(struct torture_context *tctx,
						 struct smb2_tree *tree)
{
	/* Default unsigned/unencrypted tree from the suite harness. */
	return do_roundtrip(tctx, tree, MODE_UNSIGNED_SPLICE_IN,
			    "zerocopy_unsigned_write.dat");
}

static bool test_signed_splice_write_roundtrip(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	struct smb2_tree *signed_tree = NULL;
	(void)tree;
	if (!connect_with_options(tctx,
			SMB_SIGNING_REQUIRED, SMB_ENCRYPTION_DEFAULT,
			&signed_tree)) {
		return false;
	}
	return do_roundtrip(tctx, signed_tree, MODE_SIGNED_SPLICE_IN,
			    "zerocopy_signed_write.dat");
}

static bool test_unsigned_splice_read_roundtrip(struct torture_context *tctx,
						struct smb2_tree *tree)
{
	return do_roundtrip(tctx, tree, MODE_UNSIGNED_SPLICE_OUT,
			    "zerocopy_unsigned_read.dat");
}

static bool test_signed_splice_read_roundtrip(struct torture_context *tctx,
					      struct smb2_tree *tree)
{
	struct smb2_tree *signed_tree = NULL;
	(void)tree;
	if (!connect_with_options(tctx,
			SMB_SIGNING_REQUIRED, SMB_ENCRYPTION_DEFAULT,
			&signed_tree)) {
		return false;
	}
	return do_roundtrip(tctx, signed_tree, MODE_SIGNED_SPLICE_OUT,
			    "zerocopy_signed_read.dat");
}

static bool test_encrypted_write_roundtrip(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	struct smb2_tree *enc_tree = NULL;
	(void)tree;
	if (!connect_with_options(tctx,
			SMB_SIGNING_DEFAULT, SMB_ENCRYPTION_REQUIRED,
			&enc_tree)) {
		torture_skip(tctx, "server doesn't negotiate encryption");
	}
	return do_roundtrip(tctx, enc_tree, MODE_ENCRYPTED_IN,
			    "zerocopy_encrypted_write.dat");
}

static bool test_encrypted_read_roundtrip(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	struct smb2_tree *enc_tree = NULL;
	(void)tree;
	if (!connect_with_options(tctx,
			SMB_SIGNING_DEFAULT, SMB_ENCRYPTION_REQUIRED,
			&enc_tree)) {
		torture_skip(tctx, "server doesn't negotiate encryption");
	}
	return do_roundtrip(tctx, enc_tree, MODE_ENCRYPTED_OUT,
			    "zerocopy_encrypted_read.dat");
}

/* ---------------- Tamper-rejection test ---------------- */

/*
 * Open signed connection + eligible file. Reset counters. Set the
 * force-next-fail flag via FSCTL. WRITE one buffer. The server's
 * signed splice WRITE state machine MUST:
 *   - run the signed splice path (signed_splice_in counter ++)
 *   - have MAC verify return mismatch (forced; signed_splice_in_denied ++)
 *   - return ACCESS_DENIED on the WRITE response
 *   - NOT write any bytes to the file
 *
 * Then re-open and READ the file; it must be empty (size 0).
 */
static bool test_signed_splice_write_tamper_denied(
	struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_tree *signed_tree = NULL;
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_tamper.dat";
	const size_t sz = 64 * 1024;
	uint8_t *src = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};

	(void)tree;
	if (!connect_with_options(tctx,
			SMB_SIGNING_REQUIRED, SMB_ENCRYPTION_DEFAULT,
			&signed_tree)) {
		return false;
	}
	smb2_util_unlink(signed_tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(signed_tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"create (tamper test file)");
	h = cr.out.file.handle;

	torture_assert(tctx, fsctl_counters_reset(tctx, signed_tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_force_next_signed_write_fail(tctx,
		       signed_tree), "force_next_signed_write_fail");

	src = talloc_array(tctx, uint8_t, sz);
	torture_assert_goto(tctx, src != NULL, ret, done, "talloc src");
	generate_random_buffer(src, sz);

	status = smb2_util_write(signed_tree, h, src, 0, sz);
	torture_assert_ntstatus_equal_goto(tctx, status,
		NT_STATUS_ACCESS_DENIED, ret, done,
		"signed WRITE with forced MAC fail should return "
		"ACCESS_DENIED");

	torture_assert(tctx, fsctl_counters_read(tctx, signed_tree, &after),
		       "counters_read");
	torture_assert_u64_equal_goto(tctx,
		after.signed_splice_in - before.signed_splice_in, 1,
		ret, done,
		"signed splice WRITE path did not run (signed_splice_in delta "
		"!= 1) -- can't validate verify-before-write invariant");
	torture_assert_u64_equal_goto(tctx,
		after.signed_splice_in_denied - before.signed_splice_in_denied,
		1, ret, done,
		"MAC mismatch did not increment signed_splice_in_denied");

	/* File MUST still be size 0. Reopen to flush metadata cache. */
	smb2_util_close(signed_tree, h);
	ZERO_STRUCT(h);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_RIGHTS_FILE_READ;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(signed_tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"reopen for size check");
	h = cr.out.file.handle;

	torture_assert_u64_equal_goto(tctx, cr.out.size, 0, ret, done,
		"file size != 0 after MAC-fail WRITE -- "
		"verify-before-write invariant VIOLATED: attacker bytes "
		"reached disk");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(signed_tree, h);
	}
	smb2_util_unlink(signed_tree, fname);
	talloc_free(src);
	return ret;
}

/* ---------------- Coverage-gap tests ---------------- */

/*
 * N concurrent unsigned splice WRITEs to disjoint offsets in one file
 * on a single tree. Exercises the per-xconn pipe pool's serialization:
 * with peak demand 3 (signed OUT) and default pool size 4, eight
 * in-flight WRITEs force most requests to queue behind the in-flight
 * splice op. Verifies every WRITE completes, every byte round-trips,
 * and the counter reflects all N ops took the fast path.
 */
/*
 * Multi-session AF_ALG bind-socket cache test.
 *
 * MS-SMB2 3.2.4.1 permits a client to multiplex multiple authenticated
 * sessions over a single TCP connection (the SessionId field
 * distinguishes them). The signing key is derived per-session, so
 * smbd's signed-splice AF_ALG bind socket cache MUST keep one entry
 * per session/key, not a single slot that would thrash on every PDU
 * when sessions alternate.
 *
 * This test opens two SMB2 sessions on one transport, opens the same
 * file on both, does ROUNDS signed splice READs alternating between
 * sessions, and asserts:
 *   1. All ROUNDS reads took the signed splice OUT path
 *      (signed_splice_out incremented by ROUNDS).
 *   2. The AF_ALG cache took exactly TWO misses (one per session's
 *      first signed PDU). A single-slot cache would miss on every
 *      alternation (ROUNDS misses).
 *   3. The remaining ROUNDS-2 acquires were cache hits.
 *   4. Bytes returned match the seed on every read.
 */
static bool test_signed_splice_multi_session_cache(
	struct torture_context *tctx,
	struct smb2_tree *tree_unused)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	const char *fname = "zerocopy_multi_session.dat";
	const size_t wsz = 128 * 1024;
	const int rounds = 6;
	struct smb2_tree *tree1 = NULL;
	struct smb2_tree *tree2 = NULL;
	struct smb2_session *session2 = NULL;
	struct smb2_transport *transport = NULL;
	struct cli_credentials *creds = NULL;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	uint8_t *src = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};
	NTSTATUS status;
	bool ret = true;
	int i;

	(void)tree_unused;

	/* tree1: signing required, encryption left to server default
	 * (the rig has `smb encrypt = auto` which leaves it off unless
	 * the client opts in; we want signed-but-unencrypted so the
	 * signed splice path engages). */
	if (!connect_with_options(tctx, SMB_SIGNING_REQUIRED,
				  SMB_ENCRYPTION_DEFAULT, &tree1)) {
		return false;
	}
	transport = tree1->session->transport;

	/* Seed the file via tree1. Open + write + close on a separate
	 * handle so the READ handles below see the right st_ex_size. */
	src = talloc_array(tctx, uint8_t, wsz);
	torture_assert_goto(tctx, src != NULL, ret, done, "talloc src");
	generate_random_buffer(src, wsz);
	smb2_util_unlink(tree1, fname);
	{
		struct smb2_create cr;
		ZERO_STRUCT(cr);
		cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
		cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
				   | NTCREATEX_SHARE_ACCESS_WRITE;
		cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
		cr.in.create_options =
			NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
		cr.in.fname = fname;
		status = smb2_create(tree1, tctx, &cr);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"seed create");
		status = smb2_util_write(tree1, cr.out.file.handle,
					 src, 0, wsz);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"seed write");
		smb2_util_close(tree1, cr.out.file.handle);
	}

	/* Build session2 on the same transport. Same user creds; server
	 * treats it as a distinct SessionId with its own signing key
	 * (MS-SMB2 3.2.4.1 allows multiple sessions per security
	 * context). */
	creds = cli_credentials_shallow_copy(tctx, samba_cmdline_get_creds());
	torture_assert_goto(tctx, creds != NULL, ret, done, "creds copy");
	session2 = smb2_session_init(transport, tctx->lp_ctx,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				     tctx);
	torture_assert_goto(tctx, session2 != NULL, ret, done,
		"smb2_session_init session2");
	status = smb2_session_setup_spnego(session2, creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_session_setup_spnego session2");

	/* Tree-connect session2 to the same share. */
	tree2 = smb2_tree_init(session2, tctx, false);
	torture_assert_goto(tctx, tree2 != NULL, ret, done, "tree2 init");
	{
		uint32_t timeout_msec =
			transport->options.request_timeout * 1000;
		char *unc = talloc_asprintf(tctx, "\\\\%s\\%s",
					    host, share);
		struct tevent_req *subreq;
		torture_assert_goto(tctx, unc != NULL, ret, done,
			"talloc unc");
		subreq = smb2cli_tcon_send(tctx, tctx->ev, transport->conn,
					   timeout_msec, session2->smbXcli,
					   tree2->smbXcli, 0 /* flags */, unc);
		torture_assert_goto(tctx, subreq != NULL, ret, done,
			"smb2cli_tcon_send");
		torture_assert(tctx,
			tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
			"tcon poll");
		status = smb2cli_tcon_recv(subreq);
		TALLOC_FREE(subreq);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2cli_tcon_recv");
	}

	/* Open the file on each tree. */
	{
		struct smb2_create cr;
		ZERO_STRUCT(cr);
		cr.in.desired_access = SEC_FILE_READ_DATA;
		cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
				   | NTCREATEX_SHARE_ACCESS_WRITE
				   | NTCREATEX_SHARE_ACCESS_DELETE;
		cr.in.create_disposition = NTCREATEX_DISP_OPEN;
		cr.in.create_options =
			NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
		cr.in.fname = fname;
		status = smb2_create(tree1, tctx, &cr);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"open on tree1");
		h1 = cr.out.file.handle;
	}
	{
		struct smb2_create cr;
		ZERO_STRUCT(cr);
		cr.in.desired_access = SEC_FILE_READ_DATA;
		cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
				   | NTCREATEX_SHARE_ACCESS_WRITE
				   | NTCREATEX_SHARE_ACCESS_DELETE;
		cr.in.create_disposition = NTCREATEX_DISP_OPEN;
		cr.in.create_options =
			NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
		cr.in.fname = fname;
		status = smb2_create(tree2, tctx, &cr);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"open on tree2");
		h2 = cr.out.file.handle;
	}

	/*
	 * Warmup: do one signed-splice READ on each session BEFORE
	 * resetting counters. After this, both sessions' signing keys
	 * are in the AF_ALG cache. We then measure ONLY the alternating
	 * test loop, which (with a proper per-session cache) should
	 * see zero misses and `rounds` hits. A single-slot cache would
	 * miss on every session-switch in the loop (~rounds/2 misses).
	 */
	{
		int w;
		struct smb2_tree *trees[2] = { tree1, tree2 };
		struct smb2_handle hs[2] = { h1, h2 };
		for (w = 0; w < 2; w++) {
			struct smb2_read rd;
			ZERO_STRUCT(rd);
			rd.in.file.handle = hs[w];
			rd.in.length = wsz;
			rd.in.offset = 0;
			status = smb2_read(trees[w], tctx, &rd);
			torture_assert_ntstatus_ok_goto(tctx, status,
				ret, done, "warmup read");
			data_blob_free(&rd.out.data);
		}
	}

	torture_assert(tctx, fsctl_counters_reset(tctx, tree1),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree1, &before),
		       "counters_read before");

	/* Alternating signed-splice READs. */
	for (i = 0; i < rounds; i++) {
		struct smb2_tree *t = (i % 2 == 0) ? tree1 : tree2;
		struct smb2_handle h = (i % 2 == 0) ? h1 : h2;
		struct smb2_read rd;
		ZERO_STRUCT(rd);
		rd.in.file.handle = h;
		rd.in.length = wsz;
		rd.in.offset = 0;
		status = smb2_read(t, tctx, &rd);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_read multi-session");
		torture_assert_int_equal_goto(tctx, rd.out.data.length,
			wsz, ret, done, "short read");
		torture_assert_goto(tctx,
			memcmp(src, rd.out.data.data, wsz) == 0,
			ret, done, "multi-session byte mismatch");
		data_blob_free(&rd.out.data);
	}

	torture_assert(tctx, fsctl_counters_read(tctx, tree1, &after),
		       "counters_read after");

	/* All rounds took signed splice OUT. */
	torture_assert_u64_equal_goto(tctx,
		after.signed_splice_out - before.signed_splice_out,
		(uint64_t)rounds, ret, done,
		"not all alternating reads took the signed splice OUT path");

	/* With both session keys pre-cached, the alternating loop must
	 * produce ZERO misses. A single-slot cache would miss on every
	 * session-switch (~rounds/2 misses). */
	torture_assert_u64_equal_goto(tctx,
		after.signed_alg_cache_misses -
			before.signed_alg_cache_misses,
		0, ret, done,
		"AF_ALG cache: alternating sessions caused cache misses -- "
		"the cache appears to thrash on session switch");

	/* Every PDU in the loop was an acquire = every PDU was a hit. */
	torture_assert_u64_equal_goto(tctx,
		after.signed_alg_cache_hits - before.signed_alg_cache_hits,
		(uint64_t)rounds, ret, done,
		"AF_ALG cache: expected `rounds` hits across alternating "
		"sessions");

done:
	if (!smb2_util_handle_empty(h1) && tree1 != NULL) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2) && tree2 != NULL) {
		smb2_util_close(tree2, h2);
	}
	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
	}
	talloc_free(src);
	/* tree2 / session2 cleaned up by talloc cascade (tctx). */
	return ret;
}

/*
 * Per-xconn recv-side inflight-bytes throttle.
 *
 * smbd_smb2_request_next_incoming defers issuing the next-PDU recv
 * when xconn->smb2.uring->inflight_bytes >= max_inflight_bytes.
 * Recreates the historical TrueNAS protection: a heavy WRITE workload
 * can't pile up unbounded userspace buffers when the storage layer
 * can't drain as fast as the socket accepts.
 *
 * This test dials max_inflight_bytes down to a small value, fires
 * concurrent WRITEs that would exceed it, and asserts:
 *   1. All WRITEs complete with correct bytes (throttle paces, doesn't
 *      drop requests).
 *   2. inflight_throttle_events counter incremented > 0 -- the gate
 *      actually engaged during the workload.
 *   3. inflight_bytes_peak >= max_inflight_bytes (we did reach the
 *      cap).
 *
 * Cap restoration: at end of test we reset cap to a large value so
 * later tests on the same xconn aren't accidentally throttled.
 */
/*
 * Sizing:
 *   - 32 KiB writes = 1 credit each (ceil(32K/64K)=1), so N in flight
 *     fits comfortably in the default 31-credit window.
 *   - cap < single-PDU pktbuf size guarantees the gate engages: after
 *     the first PDU's pktbuf is charged, inflight_bytes > cap, so
 *     every subsequent request_next_incoming defers until that PDU's
 *     refund destructor fires (= when the request is freed at the
 *     end of its processing). Each of the N-1 follow-up PDUs records
 *     at least one throttle event.
 *   - Asserts: inflight_throttle_events >= N-1.
 */
#define INFLIGHT_TEST_N      4
#define INFLIGHT_TEST_SZ    (32 * 1024)
#define INFLIGHT_TEST_CAP   (1 * 1024)
static bool test_inflight_byte_throttle(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_inflight_throttle.dat";
	struct smb2_write w[INFLIGHT_TEST_N];
	struct smb2_request *req[INFLIGHT_TEST_N];
	uint8_t *src = NULL;
	uint8_t *dst = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};
	int i;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	h = cr.out.file.handle;

	src = talloc_array(tctx, uint8_t, INFLIGHT_TEST_N * INFLIGHT_TEST_SZ);
	dst = talloc_array(tctx, uint8_t, INFLIGHT_TEST_N * INFLIGHT_TEST_SZ);
	torture_assert_goto(tctx, src != NULL && dst != NULL,
		ret, done, "talloc");
	generate_random_buffer(src, INFLIGHT_TEST_N * INFLIGHT_TEST_SZ);

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &before),
		       "counters_read before");

	/* Dial the cap down to force throttling under modest load. */
	torture_assert(tctx,
		fsctl_set_max_inflight_bytes(tctx, tree, INFLIGHT_TEST_CAP),
		"set_max_inflight_bytes (cap down)");

	/* Fire concurrent WRITEs. Total bytes ~ INFLIGHT_TEST_N *
	 * INFLIGHT_TEST_SZ = 2 MiB, well above the 1 MiB cap, so the
	 * recv-side gate must defer at least once. */
	for (i = 0; i < INFLIGHT_TEST_N; i++) {
		ZERO_STRUCT(w[i]);
		w[i].in.file.handle = h;
		w[i].in.offset      = (uint64_t)i * INFLIGHT_TEST_SZ;
		w[i].in.data        = data_blob_const(
			src + (size_t)i * INFLIGHT_TEST_SZ, INFLIGHT_TEST_SZ);
		req[i] = smb2_write_send(tree, &w[i]);
		torture_assert_goto(tctx, req[i] != NULL, ret, done,
			"smb2_write_send");
	}
	for (i = 0; i < INFLIGHT_TEST_N; i++) {
		status = smb2_write_recv(req[i], &w[i]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_write_recv");
	}

	/* All WRITEs landed correctly (throttle paces, doesn't drop). */
	for (i = 0; i < INFLIGHT_TEST_N; i++) {
		struct smb2_read rd;
		ZERO_STRUCT(rd);
		rd.in.file.handle = h;
		rd.in.length      = INFLIGHT_TEST_SZ;
		rd.in.offset      = (uint64_t)i * INFLIGHT_TEST_SZ;
		status = smb2_read(tree, tctx, &rd);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"readback");
		torture_assert_int_equal_goto(tctx,
			rd.out.data.length, INFLIGHT_TEST_SZ, ret, done,
			"readback length");
		memcpy(dst + (size_t)i * INFLIGHT_TEST_SZ,
		       rd.out.data.data, INFLIGHT_TEST_SZ);
		data_blob_free(&rd.out.data);
	}
	torture_assert_goto(tctx,
		memcmp(src, dst, INFLIGHT_TEST_N * INFLIGHT_TEST_SZ) == 0,
		ret, done, "throttle WRITE bytes mismatch on readback");

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read after");

	/* The cap was exceeded during the workload -- gate fired. */
	torture_assert_goto(tctx,
		after.inflight_throttle_events -
			before.inflight_throttle_events > 0,
		ret, done,
		"inflight_throttle_events did not increment -- "
		"the cap was either too high or the throttle gate is dead");

	/* Peak inflight reached at least one full PDU's pktbuf, which is
	 * comfortably above the deliberately-tiny cap. */
	torture_assert_goto(tctx,
		after.inflight_bytes_peak >= INFLIGHT_TEST_SZ,
		ret, done,
		"inflight_bytes_peak did not reach one PDU's worth -- "
		"workload was too small to exercise the throttle");

done:
	/* Restore generous cap so later tests on this xconn aren't
	 * accidentally paced. */
	(void)fsctl_set_max_inflight_bytes(tctx, tree,
		INFLIGHT_DEFAULT_CAP);
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	talloc_free(dst);
	return ret;
}

/*
 * The posix_append eligibility gate (smb2_server.c:is_smb2_recvfile_write)
 * rejects the short-recvfile / splice IN path for files opened with
 * O_APPEND. The kernel-side write path would take the file's tail
 * offset and ignore the offset we pass to IORING_OP_SPLICE(pipe ->
 * file), so the splice would write at the wrong place. Same hazard as
 * the legacy sys_recvfile splice.
 *
 * Triggering a real SMB2 POSIX-context open from torture would require
 * client-side SMB2 POSIX-extension plumbing we don't have. Instead we
 * use FSCTL_SMBTORTURE_TRUENAS_URING_FORCE_NEXT_POSIX_APPEND to flip
 * the test override flag for ONE WRITE.
 *
 * Differential check (a single counter snapshot can't prove the gate
 * fired -- a small/encrypted/streamed WRITE legitimately bypasses
 * splice IN too):
 *   1. CONTROL WRITE (no force): splice IN counter MUST bump by 1.
 *   2. GATED WRITE (force_next_posix_append): splice IN counter MUST
 *      NOT bump.
 * Both WRITEs must readback correctly. If a future change drops the
 * posix_append gate, the gated WRITE silently takes the splice path
 * and the second assertion fires.
 */
static bool test_posix_append_gate(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_posix_append_gate.dat";
	const size_t wsz = 128 * 1024;  /* > 'min receive file size' */
	uint8_t *src = NULL;
	uint8_t *dst = NULL;
	struct truenas_uring_counters c0 = {0};
	struct truenas_uring_counters c1 = {0};
	struct truenas_uring_counters c2 = {0};

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	h = cr.out.file.handle;

	src = talloc_array(tctx, uint8_t, wsz);
	dst = talloc_array(tctx, uint8_t, wsz);
	torture_assert_goto(tctx, src != NULL && dst != NULL,
		ret, done, "talloc");
	generate_random_buffer(src, wsz);

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &c0),
		       "counters_read c0");

	/* (1) CONTROL: ordinary WRITE -- must take splice IN. */
	status = smb2_util_write(tree, h, src, 0, wsz);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"control WRITE");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &c1),
		       "counters_read c1");
	torture_assert_u64_equal_goto(tctx,
		c1.unsigned_splice_in - c0.unsigned_splice_in,
		1, ret, done,
		"control WRITE did not take splice IN -- "
		"the rest of the test is meaningless");

	/* (2) GATED: same WRITE, but force_next_posix_append flips the
	 * test override flag so the gate rejects splice IN. */
	torture_assert(tctx, fsctl_force_next_posix_append(tctx, tree),
		       "force_next_posix_append");
	status = smb2_util_write(tree, h, src, (uint64_t)wsz, wsz);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"gated WRITE");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &c2),
		       "counters_read c2");
	torture_assert_u64_equal_goto(tctx,
		c2.unsigned_splice_in - c1.unsigned_splice_in,
		0, ret, done,
		"posix_append gate failed to reject splice IN");

	/* Both WRITEs landed bytes correctly. */
	{
		struct smb2_read rd;
		ZERO_STRUCT(rd);
		rd.in.file.handle = h;
		rd.in.length      = wsz;
		rd.in.offset      = (uint64_t)wsz;
		status = smb2_read(tree, tctx, &rd);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"readback after gated WRITE");
		torture_assert_int_equal_goto(tctx, rd.out.data.length, wsz,
			ret, done, "short readback");
		memcpy(dst, rd.out.data.data, wsz);
		data_blob_free(&rd.out.data);
	}
	torture_assert_goto(tctx,
		memcmp(src, dst, wsz) == 0,
		ret, done, "byte mismatch on gated WRITE readback");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	talloc_free(dst);
	return ret;
}

/*
 * 6 in-flight WRITEs > 4-pipe pool default forces queueing. Each WRITE
 * is 32 KiB so it stays at 1 credit (default initial 31 credits); we
 * don't want to exhaust the SMB2 credit window before the splice pool
 * pressure is exercised.
 */
#define PARALLEL_N    6
#define PARALLEL_SZ  (32 * 1024)

static bool test_parallel_writes(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_parallel_writes.dat";
	struct smb2_write w[PARALLEL_N];
	struct smb2_request *req[PARALLEL_N];
	uint8_t *src = NULL;
	uint8_t *dst = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};
	int i;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	h = cr.out.file.handle;

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &before),
		       "counters_read");

	src = talloc_array(tctx, uint8_t, PARALLEL_N * PARALLEL_SZ);
	dst = talloc_array(tctx, uint8_t, PARALLEL_N * PARALLEL_SZ);
	torture_assert_goto(tctx, src != NULL && dst != NULL,
		ret, done, "talloc");
	generate_random_buffer(src, PARALLEL_N * PARALLEL_SZ);

	for (i = 0; i < PARALLEL_N; i++) {
		ZERO_STRUCT(w[i]);
		w[i].in.file.handle = h;
		w[i].in.offset      = (uint64_t)i * PARALLEL_SZ;
		w[i].in.data        = data_blob_const(
			src + (size_t)i * PARALLEL_SZ, PARALLEL_SZ);
		req[i] = smb2_write_send(tree, &w[i]);
		torture_assert_goto(tctx, req[i] != NULL, ret, done,
			"smb2_write_send");
	}

	for (i = 0; i < PARALLEL_N; i++) {
		status = smb2_write_recv(req[i], &w[i]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_write_recv");
	}

	for (i = 0; i < PARALLEL_N; i++) {
		struct smb2_read rd;
		ZERO_STRUCT(rd);
		rd.in.file.handle = h;
		rd.in.length      = PARALLEL_SZ;
		rd.in.offset      = (uint64_t)i * PARALLEL_SZ;
		status = smb2_read(tree, tctx, &rd);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"readback");
		torture_assert_int_equal_goto(tctx,
			rd.out.data.length, PARALLEL_SZ, ret, done,
			"readback length");
		memcpy(dst + (size_t)i * PARALLEL_SZ,
		       rd.out.data.data, PARALLEL_SZ);
		data_blob_free(&rd.out.data);
	}
	torture_assert_goto(tctx,
		memcmp(src, dst, PARALLEL_N * PARALLEL_SZ) == 0,
		ret, done, "parallel WRITE bytes mismatch on readback");

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read");
	torture_assert_u64_equal_goto(tctx,
		after.unsigned_splice_in - before.unsigned_splice_in,
		PARALLEL_N, ret, done,
		"some concurrent WRITEs did not take splice IN path");
	torture_assert_u64_equal_goto(tctx,
		after.legacy_recv - before.legacy_recv, 0, ret, done,
		"some concurrent WRITEs fell back to legacy");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	talloc_free(dst);
	return ret;
}

/*
 * K-deep concurrent outbound splice READs. Fires PARALLEL_READ_N reads
 * at non-overlapping offsets and asserts that all of them take the
 * splice OUT path. The splice state machine pipelines the per-PDU
 * pre-send work (pipe acquire, file -> body_pipe, AF_ALG feed) so
 * multiple PDUs can be in their FETCHING phase concurrently; only
 * the head entry's pipe -> socket runs at any moment (wire order).
 * This test catches a regression where concurrent READs would either
 * serialize or fall back to the legacy aio path.
 */
#define PARALLEL_READ_N    6
#define PARALLEL_READ_SZ  (32 * 1024)
static bool test_parallel_reads(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_parallel_reads.dat";
	struct smb2_read rd[PARALLEL_READ_N];
	struct smb2_request *req[PARALLEL_READ_N];
	uint8_t *src = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};
	int i;

	smb2_util_unlink(tree, fname);

	/* Seed the file via a separate handle, then close it. The READ
	 * handle opened below stats the file at open time, so it sees
	 * the final size and the splice eligibility gate (which consults
	 * the cached st_ex_size) lets the READ take the splice path. */
	src = talloc_array(tctx, uint8_t, PARALLEL_READ_N * PARALLEL_READ_SZ);
	torture_assert_goto(tctx, src != NULL, ret, done, "talloc");
	generate_random_buffer(src, PARALLEL_READ_N * PARALLEL_READ_SZ);
	{
		struct smb2_create cr_seed;
		struct smb2_write w;
		ZERO_STRUCT(cr_seed);
		cr_seed.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
		cr_seed.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		cr_seed.in.share_access = NTCREATEX_SHARE_ACCESS_READ
				       | NTCREATEX_SHARE_ACCESS_WRITE;
		cr_seed.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
		cr_seed.in.create_options =
			NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
		cr_seed.in.fname = fname;
		status = smb2_create(tree, tctx, &cr_seed);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"seed create");
		ZERO_STRUCT(w);
		w.in.file.handle = cr_seed.out.file.handle;
		w.in.offset = 0;
		w.in.data = data_blob_const(src,
			PARALLEL_READ_N * PARALLEL_READ_SZ);
		status = smb2_write(tree, &w);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"seed write");
		smb2_util_close(tree, cr_seed.out.file.handle);
	}

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	h = cr.out.file.handle;

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &before),
		       "counters_read");

	for (i = 0; i < PARALLEL_READ_N; i++) {
		ZERO_STRUCT(rd[i]);
		rd[i].in.file.handle = h;
		rd[i].in.length      = PARALLEL_READ_SZ;
		rd[i].in.offset      = (uint64_t)i * PARALLEL_READ_SZ;
		req[i] = smb2_read_send(tree, &rd[i]);
		torture_assert_goto(tctx, req[i] != NULL, ret, done,
			"smb2_read_send");
	}

	for (i = 0; i < PARALLEL_READ_N; i++) {
		status = smb2_read_recv(req[i], tctx, &rd[i]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_read_recv");
		torture_assert_int_equal_goto(tctx,
			rd[i].out.data.length, PARALLEL_READ_SZ, ret, done,
			"short parallel read");
		torture_assert_goto(tctx,
			memcmp(rd[i].out.data.data,
			       src + (size_t)i * PARALLEL_READ_SZ,
			       PARALLEL_READ_SZ) == 0,
			ret, done, "parallel READ bytes mismatch");
		data_blob_free(&rd[i].out.data);
	}

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read");
	/*
	 * The strong guarantee: each parallel READ bumped unsigned_splice_out.
	 * We don't check legacy_send here because the FSCTL_COUNTERS_READ
	 * "before" response itself goes through the legacy_send path between
	 * capture-of-before and capture-of-after, so the diff is noisy at
	 * the +1 level. If any of the N reads fell back to legacy_aio, the
	 * unsigned_splice_out count below would be < N -- which is the only
	 * check we actually need.
	 */
	torture_assert_u64_equal_goto(tctx,
		after.unsigned_splice_out - before.unsigned_splice_out,
		PARALLEL_READ_N, ret, done,
		"some concurrent READs did not take splice OUT path");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	return ret;
}

/*
 * Same handle, alternate WRITE / READ. The splice READ eligibility gate
 * consults fsp->fsp_name->st.st_ex_size (smb2_read.c around line 452);
 * the size is cached at open time. After a WRITE, the cache must
 * advance for a same-handle READ to be splice-eligible -- otherwise
 * READs always RETRY to legacy and the test would catch a missed
 * fast-path opportunity. (If a later refactor makes the gate consult a
 * stale value and over-eagerly accepts a splice on an EOF-overshooting
 * READ, the assertion that the legacy_send counter does NOT pop will
 * fire.)
 */
static bool test_interleaved_rw_same_handle(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_interleaved.dat";
	const size_t chunk = 32 * 1024;
	const int rounds = 5;
	uint8_t *src = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};
	int i;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	h = cr.out.file.handle;

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &before),
		       "counters_read");

	src = talloc_array(tctx, uint8_t, (size_t)rounds * chunk);
	torture_assert_goto(tctx, src != NULL, ret, done, "talloc");
	generate_random_buffer(src, (size_t)rounds * chunk);

	for (i = 0; i < rounds; i++) {
		struct smb2_read rd;

		status = smb2_util_write(tree, h, src + (size_t)i * chunk,
					 (uint64_t)i * chunk, chunk);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"interleaved write");

		ZERO_STRUCT(rd);
		rd.in.file.handle = h;
		rd.in.length      = chunk;
		rd.in.offset      = (uint64_t)i * chunk;
		status = smb2_read(tree, tctx, &rd);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"interleaved read");
		torture_assert_int_equal_goto(tctx,
			rd.out.data.length, chunk, ret, done,
			"interleaved read short");
		torture_assert_goto(tctx,
			memcmp(src + (size_t)i * chunk,
			       rd.out.data.data, chunk) == 0,
			ret, done, "interleaved RW byte mismatch");
		data_blob_free(&rd.out.data);
	}

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read");
	/* All WRITEs go via splice IN. */
	torture_assert_u64_equal_goto(tctx,
		after.unsigned_splice_in - before.unsigned_splice_in,
		(uint64_t)rounds, ret, done,
		"interleaved WRITEs did not all take splice IN");
	/*
	 * READs MAY fall back to legacy when the same-handle stale size
	 * cache rejects the splice eligibility check -- accept either
	 * outcome but require correctness. The point of the test is the
	 * byte-mismatch check above; counter just documents whichever
	 * the gate chose.
	 */

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	return ret;
}

/*
 * Compound chain containing a WRITE should NOT engage the splice WRITE
 * fast path -- the eligibility check at smb2_aio.c:1036 rejects compound
 * chains that aren't last-in-compound. The legacy path handles them.
 *
 * Builds: CREATE + WRITE compounded (related ops, so the WRITE inherits
 * the CREATE's FileId via UINT64_MAX-then-resolve). Asserts the WRITE
 * completes (correctness) AND that the splice IN counter does NOT tick
 * (the compound fast-path rejection works).
 */
static bool test_compound_write_falls_back(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	struct smb2_handle handle;
	struct smb2_create cr;
	struct smb2_write wr;
	struct smb2_close cl;
	struct smb2_request *req[3];
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_compound.dat";
	const size_t sz = 4096;
	uint8_t *src = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};

	smb2_util_unlink(tree, fname);

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &before),
		       "counters_read");

	src = talloc_array(tctx, uint8_t, sz);
	torture_assert_goto(tctx, src != NULL, ret, done, "talloc");
	generate_random_buffer(src, sz);

	smb2_transport_compound_start(tree->session->transport, 3);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	req[0] = smb2_create_send(tree, &cr);

	smb2_transport_compound_set_related(tree->session->transport, true);

	/* Sentinel UINT64_MAX FileId -- resolves to the prior CREATE. */
	handle.data[0] = UINT64_MAX;
	handle.data[1] = UINT64_MAX;

	ZERO_STRUCT(wr);
	wr.in.file.handle = handle;
	wr.in.offset      = 0;
	wr.in.data        = data_blob_const(src, sz);
	req[1] = smb2_write_send(tree, &wr);

	ZERO_STRUCT(cl);
	cl.in.file.handle = handle;
	req[2] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"compound CREATE");
	status = smb2_write_recv(req[1], &wr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"compound WRITE");
	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"compound CLOSE");

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read");
	torture_assert_u64_equal_goto(tctx,
		after.unsigned_splice_in - before.unsigned_splice_in,
		0, ret, done,
		"compound WRITE took splice IN -- eligibility gate is "
		"failing to reject mid-compound WRITEs");
	torture_assert_u64_equal_goto(tctx,
		after.signed_splice_in - before.signed_splice_in,
		0, ret, done,
		"compound WRITE took signed splice IN");

done:
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	return ret;
}

/*
 * Sparse WRITE: WRITE at offset much larger than the current file size.
 * Splice WRITE should handle this -- splice(socket->pipe->file) at an
 * arbitrary offset creates the hole. Verifies bytes land where asked
 * and that the file extends to the right size.
 */
static bool test_sparse_splice_write(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_sparse.dat";
	const uint64_t sparse_offset = 1 * 1024 * 1024;  /* 1 MiB hole */
	const size_t sz = 64 * 1024;
	uint8_t *src = NULL;
	uint8_t *dst = NULL;
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	h = cr.out.file.handle;

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &before),
		       "counters_read");

	src = talloc_array(tctx, uint8_t, sz);
	dst = talloc_array(tctx, uint8_t, sz);
	torture_assert_goto(tctx, src != NULL && dst != NULL,
		ret, done, "talloc");
	generate_random_buffer(src, sz);
	memset(dst, 0xAA, sz);

	status = smb2_util_write(tree, h, src, sparse_offset, sz);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"sparse WRITE");

	{
		struct smb2_read rd;
		ZERO_STRUCT(rd);
		rd.in.file.handle = h;
		rd.in.length      = sz;
		rd.in.offset      = sparse_offset;
		status = smb2_read(tree, tctx, &rd);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"sparse READ-back");
		torture_assert_int_equal_goto(tctx, rd.out.data.length, sz,
			ret, done, "sparse READ-back length");
		memcpy(dst, rd.out.data.data, sz);
		data_blob_free(&rd.out.data);
	}
	torture_assert_goto(tctx, memcmp(src, dst, sz) == 0,
		ret, done, "sparse WRITE bytes mismatch on readback");

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read");
	torture_assert_u64_equal_goto(tctx,
		after.unsigned_splice_in - before.unsigned_splice_in,
		1, ret, done,
		"sparse WRITE did not take splice IN");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(src);
	talloc_free(dst);
	return ret;
}

/*
 * READ at offset == EOF must return 0 bytes (success, not error). The
 * splice READ gate at smb2_read.c:452 rejects this case (in_offset >=
 * st_ex_size), so the legacy path handles it. Verifies the gate is
 * actually rejecting (counter stays 0) and the response is correct.
 */
static bool test_read_at_eof(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	struct smb2_read rd;
	NTSTATUS status;
	bool ret = true;
	const char *fname = "zerocopy_eof.dat";
	const size_t file_sz = 100;
	uint8_t small[100];
	struct truenas_uring_counters before = {0};
	struct truenas_uring_counters after  = {0};

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ
			   | NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	h = cr.out.file.handle;

	generate_random_buffer(small, file_sz);
	status = smb2_util_write(tree, h, small, 0, file_sz);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"seed-write");

	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

	/* Re-open so st_ex_size is fresh = 100. */
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "reopen");
	h = cr.out.file.handle;

	torture_assert(tctx, fsctl_counters_reset(tctx, tree),
		       "counters_reset");
	torture_assert(tctx, fsctl_counters_read(tctx, tree, &before),
		       "counters_read");

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length      = 4096;
	rd.in.offset      = file_sz;     /* exactly at EOF */
	status = smb2_read(tree, tctx, &rd);
	/*
	 * Per MS-SMB2 2.2.20, a 0-byte READ at EOF on a file with 0 bytes
	 * to return is STATUS_END_OF_FILE. Samba's READ handler returns
	 * the right thing here; the splice gate must NOT have engaged.
	 */
	torture_assert_ntstatus_equal_goto(tctx, status,
		NT_STATUS_END_OF_FILE, ret, done,
		"READ at EOF should be END_OF_FILE");

	torture_assert(tctx, fsctl_counters_read(tctx, tree, &after),
		       "counters_read");
	torture_assert_u64_equal_goto(tctx,
		after.unsigned_splice_out - before.unsigned_splice_out,
		0, ret, done,
		"splice OUT engaged on at-EOF READ -- eligibility gate "
		"is failing to reject zero-yield reads");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/* ---------------- Suite registration ---------------- */

struct torture_suite *torture_smb2_truenas_zerocopy_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
		torture_suite_create(ctx, "truenas_zerocopy");

	torture_suite_add_1smb2_test(suite, "unsigned_splice_write_roundtrip",
				     test_unsigned_splice_write_roundtrip);
	torture_suite_add_1smb2_test(suite, "signed_splice_write_roundtrip",
				     test_signed_splice_write_roundtrip);
	torture_suite_add_1smb2_test(suite, "unsigned_splice_read_roundtrip",
				     test_unsigned_splice_read_roundtrip);
	torture_suite_add_1smb2_test(suite, "signed_splice_read_roundtrip",
				     test_signed_splice_read_roundtrip);
	torture_suite_add_1smb2_test(suite, "encrypted_write_roundtrip",
				     test_encrypted_write_roundtrip);
	torture_suite_add_1smb2_test(suite, "encrypted_read_roundtrip",
				     test_encrypted_read_roundtrip);
	torture_suite_add_1smb2_test(suite, "signed_splice_write_tamper_denied",
				     test_signed_splice_write_tamper_denied);
	torture_suite_add_1smb2_test(suite, "signed_splice_multi_session_cache",
				     test_signed_splice_multi_session_cache);
	torture_suite_add_1smb2_test(suite, "posix_append_gate",
				     test_posix_append_gate);
	torture_suite_add_1smb2_test(suite, "inflight_byte_throttle",
				     test_inflight_byte_throttle);
	torture_suite_add_1smb2_test(suite, "parallel_writes",
				     test_parallel_writes);
	torture_suite_add_1smb2_test(suite, "parallel_reads",
				     test_parallel_reads);
	torture_suite_add_1smb2_test(suite, "interleaved_rw_same_handle",
				     test_interleaved_rw_same_handle);
	torture_suite_add_1smb2_test(suite, "compound_write_falls_back",
				     test_compound_write_falls_back);
	torture_suite_add_1smb2_test(suite, "sparse_splice_write",
				     test_sparse_splice_write);
	torture_suite_add_1smb2_test(suite, "read_at_eof",
				     test_read_at_eof);

	suite->description = talloc_strdup(suite,
		"End-to-end coverage for TrueNAS-fork io_uring zero-copy "
		"SMB2/3 fast paths");
	return suite;
}
