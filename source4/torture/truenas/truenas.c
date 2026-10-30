/*
   Unix SMB/CIFS implementation.

   TrueNAS VFS stack torture tests.

   These exercise behavior that is specific to the TrueNAS Samba VFS modules
   (zfs_core, truenas_streams_xattr, ...) rather than generic SMB protocol
   semantics already covered by the base/smb2/vfs suites. They are intended to
   run in the QEMU build+test CI against a real ZFS dataset.

   The CI harness is responsible for provisioning the share. The tests in this
   suite expect the default share to be a casesensitivity=insensitive ZFS
   dataset served with "vfs objects = zfs_core truenas_streams_xattr".

   Copyright (C) iXsystems 2026

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
#include "system/filesys.h"

#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smb2_create_ctx.h"
#include "libcli/security/security.h"
#include "MacExtensions.h"

#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smbtorture.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"
#ifdef HAVE_LIBZFS
#include "source3/modules/smb_libzfs.h"
#endif

/* Length of an SMB shadow-copy @GMT- token: "@GMT-YYYY.MM.DD-HH.MM.SS". */
#define TN_GMT_LEN 24

/*
 * Return whether the share root contains an entry whose name matches @name
 * with exact case. ZFS with casesensitivity=insensitive is case-preserving,
 * so the on-disk case is observable through directory enumeration even when
 * an open() would succeed regardless of case.
 */
static bool truenas_dir_has_name(struct torture_context *tctx,
				 struct smb2_tree *tree,
				 const char *name,
				 bool *present)
{
	struct smb2_handle dirh;
	struct smb2_find f;
	union smb_search_data *d;
	unsigned int count;
	NTSTATUS status;
	bool ret = true;

	*present = false;

	status = smb2_util_roothandle(tree, &dirh);
	torture_assert_ntstatus_ok(tctx, status,
				   "open share root for enumeration");

	ZERO_STRUCT(f);
	f.in.file.handle	= dirh;
	f.in.pattern		= "*";
	f.in.max_response_size	= 0x10000;
	f.in.level		= SMB2_FIND_BOTH_DIRECTORY_INFO;

	do {
		unsigned int i;

		status = smb2_find_level(tree, tree, &f, &count, &d);
		if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
			break;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_find_level");

		for (i = 0; i < count; i++) {
			const char *found = d[i].both_directory_info.name.s;

			if (strcmp(found, name) == 0) {
				*present = true;
			}
		}
	} while (count > 0);

done:
	smb2_util_close(tree, dirh);
	return ret;
}

static NTSTATUS truenas_rename(struct smb2_tree *tree,
			       struct smb2_handle handle,
			       const char *new_name,
			       bool overwrite)
{
	union smb_setfileinfo sinfo;

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = handle;
	sinfo.rename_information.in.overwrite = overwrite;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name = new_name;

	return smb2_setinfo_file(tree, &sinfo);
}

/*
 * Case-insensitive rename on a casesensitivity=insensitive ZFS dataset.
 *
 * Mirrors middleware test_068_case_insensitive_rename. The second rename is
 * the regression of interest: the client opens "to_rename" (which resolves
 * case-insensitively to the on-disk "To_rename") and renames it to the
 * identical request string "to_rename". That must still flip the on-disk
 * case, i.e. zfs_core_renameat() must be reached rather than smbd
 * short-circuiting it as a "no file name change".
 */
static bool test_truenas_rename_case_insensitive(struct torture_context *tctx,
						 struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	bool present = false;
	struct smb2_handle h;

	smb2_util_unlink(tree, "to_rename");
	smb2_util_unlink(tree, "To_rename");

	status = torture_smb2_testfile(tree, "to_rename", &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create to_rename");
	smb2_util_close(tree, h);

	/* to_rename -> To_rename (pure case change, differing strings) */
	status = torture_smb2_open(tree, "to_rename", SEC_STD_DELETE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open to_rename");
	status = truenas_rename(tree, h, "To_rename", false);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"rename to_rename -> To_rename");
	smb2_util_close(tree, h);

	ret = truenas_dir_has_name(tctx, tree, "To_rename", &present);
	if (!ret) {
		goto done;
	}
	torture_assert_goto(tctx, present, ret, done,
			    "To_rename must be present after rename");

	ret = truenas_dir_has_name(tctx, tree, "to_rename", &present);
	if (!ret) {
		goto done;
	}
	torture_assert_goto(tctx, !present, ret, done,
			    "to_rename must be gone after rename");

	/* to_rename -> to_rename: identical request strings, on-disk is "To_rename" */
	status = torture_smb2_open(tree, "to_rename", SEC_STD_DELETE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"reopen to_rename (case-insensitive)");
	status = truenas_rename(tree, h, "to_rename", false);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"case-only rename To_rename -> to_rename");
	smb2_util_close(tree, h);

	ret = truenas_dir_has_name(tctx, tree, "to_rename", &present);
	if (!ret) {
		goto done;
	}
	torture_assert_goto(tctx, present, ret, done,
			    "to_rename must be present after case-only rename");

	ret = truenas_dir_has_name(tctx, tree, "To_rename", &present);
	if (!ret) {
		goto done;
	}
	torture_assert_goto(tctx, !present, ret, done,
			    "To_rename must be gone after case-only rename");

done:
	smb2_util_unlink(tree, "to_rename");
	smb2_util_unlink(tree, "To_rename");
	return ret;
}

static NTSTATUS truenas_open_stream(struct smb2_tree *tree,
				    const char *sname,
				    uint32_t disposition,
				    struct smb2_handle *handle)
{
	struct smb2_create cr;
	NTSTATUS status;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = disposition;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = sname;

	status = smb2_create(tree, tree, &cr);
	if (NT_STATUS_IS_OK(status)) {
		*handle = cr.out.file.handle;
	}
	return status;
}

/*
 * Alternate data stream stored by truenas_streams_xattr.
 *
 * Mirrors middleware test_062_write_stream_large_offset_smb2, but scaled to the
 * share's configured per-stream cap (smbd max xattr size) so it runs on a stock
 * kernel. The stream lives in a single xattr, so:
 *   - a sparse write past current length zero-fills the gap,
 *   - a write whose end offset reaches the cap is rejected with
 *     NT_STATUS_FILE_SYSTEM_LIMITATION,
 *   - a write ending just below the cap (leaving room for the trailing compat
 *     byte the module stores) succeeds,
 *   - the stream is then visible via FILE_STREAM_INFORMATION.
 *
 * The cap defaults to 32768 (the CI streams share sets "smbd max xattr size =
 * 32768", comfortably under the stock 64KiB xattr limit); a TrueNAS-kernel CI
 * can raise it with --option=torture:streams_cap=<bytes>.
 */
static bool test_truenas_streams_cap_and_offset(struct torture_context *tctx,
						struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	bool found = false;
	struct smb2_handle h = {{0}};
	struct smb2_read rd;
	union smb_fileinfo finfo;
	const char *fname = "streamstest";
	const char *sname = "streamstest:smb2_stream";
	const char *value = "test2";
	const uint32_t vlen = 5;
	uint32_t cap = torture_setting_int(tctx, "streams_cap", 32768);
	uint32_t mid = cap / 4;
	uint32_t i;

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create base file");
	smb2_util_close(tree, h);

	/* sparse write past current length: the gap must read back as zeros */
	status = truenas_open_stream(tree, sname, NTCREATEX_DISP_OPEN_IF, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create stream");
	status = smb2_util_write(tree, h, value, mid, vlen);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write stream at mid offset");
	smb2_util_close(tree, h);

	status = truenas_open_stream(tree, sname, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open stream for read");
	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.offset = mid;
	rd.in.length = vlen;
	status = smb2_read(tree, tree, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"read stream at mid offset");
	torture_assert_int_equal_goto(tctx, rd.out.data.length, vlen, ret, done,
				      "short read from stream");
	torture_assert_mem_equal_goto(tctx, rd.out.data.data, value, vlen,
				      ret, done, "stream data mismatch");

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.offset = 0;
	rd.in.length = mid;
	status = smb2_read(tree, tree, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"read stream gap");
	torture_assert_int_equal_goto(tctx, rd.out.data.length, mid, ret, done,
				      "short read of stream gap");
	for (i = 0; i < rd.out.data.length; i++) {
		torture_assert_goto(tctx, rd.out.data.data[i] == 0, ret, done,
				    "stream gap not zero-filled");
	}
	smb2_util_close(tree, h);

	/* a write whose end offset reaches the cap is rejected */
	status = truenas_open_stream(tree, sname, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open stream (limit check)");
	status = smb2_util_write(tree, h, value, cap, vlen);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_FILE_SYSTEM_LIMITATION,
					   ret, done,
					   "oversized stream write must be rejected");
	smb2_util_close(tree, h);

	/* a write ending just below the cap (room for the compat NUL) succeeds */
	status = truenas_open_stream(tree, sname, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open stream (max write)");
	status = smb2_util_write(tree, h, value, cap - (vlen + 1), vlen);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write at maximum legal stream offset");
	smb2_util_close(tree, h);

	/*
	 * FILE_STREAM_INFORMATION is queried on the BASE file handle -- issuing
	 * it on a stream handle returns NT_STATUS_INVALID_PARAMETER.
	 */
	status = truenas_open_stream(tree, fname, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open base file (streaminfo)");
	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	finfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"query stream information");
	for (i = 0; i < finfo.stream_info.out.num_streams; i++) {
		const char *nm = finfo.stream_info.out.streams[i].stream_name.s;
		if (strstr(nm, "smb2_stream") != NULL) {
			found = true;
			torture_assert_int_equal_goto(tctx,
				finfo.stream_info.out.streams[i].size,
				cap - 1, ret, done, "stream size mismatch");
		}
	}
	torture_assert_goto(tctx, found, ret, done,
			    "smb2_stream not listed by streaminfo");
	smb2_util_close(tree, h);

done:
	smb2_util_unlink(tree, fname);
	return ret;
}

/* The pattern test_truenas_streams_sizes() writes, by stream offset */
static void truenas_stream_fill(uint8_t *buf, uint32_t off, uint32_t len)
{
	uint32_t k;

	for (k = 0; k < len; k++) {
		buf[k] = (uint8_t)(((off + k) * 2654435761u) >> 24);
	}
}

/*
 * Stream sizes and data with truenas_streams_xattr.
 *
 * The module takes a stream's size from the length of its xattr alone, both
 * for FILE_STREAM_INFORMATION and when a stream is stat'ed, and reads values
 * past a 256-byte first guess at their exact size. Sizes and data must match
 * what was written: for empty and one-byte streams, around 256 bytes, and up
 * to the cap. The trailing compat byte must not leak into either, so run this
 * against shares with both streams_xattr:xattr_compat settings.
 */
static bool test_truenas_streams_sizes(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	union smb_fileinfo finfo;
	const char *fname = "streamsizes";
	uint32_t cap = torture_setting_int(tctx, "streams_cap", 32768);
	uint32_t sizes[] = { 0, 1, 254, 255, 256, 257, 350, 4096, 0, 0 };
	size_t num_sizes = ARRAY_SIZE(sizes);
	/* One credit per WRITE: smbtorture may hold too few for larger ones */
	const uint32_t chunk = 65536;
	uint8_t *buf = NULL;
	size_t i, j;

	sizes[num_sizes - 2] = cap / 2;
	sizes[num_sizes - 1] = cap - 1;

	buf = talloc_zero_array(tctx, uint8_t, chunk);
	torture_assert_goto(tctx, buf != NULL, ret, done, "talloc buffer");

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create base file");
	smb2_util_close(tree, h);

	for (i = 0; i < num_sizes; i++) {
		const char *sname = talloc_asprintf(tctx, "%s:s%zu", fname, i);
		uint32_t off;

		status = truenas_open_stream(tree, sname, NTCREATEX_DISP_CREATE,
					     &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create stream");
		for (off = 0; off < sizes[i]; off += chunk) {
			uint32_t len = MIN(chunk, sizes[i] - off);

			truenas_stream_fill(buf, off, len);
			status = smb2_util_write(tree, h, buf, off, len);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				talloc_asprintf(tctx, "write %" PRIu32
						"-byte stream", sizes[i]));
		}
		smb2_util_close(tree, h);

		/* The reopened stream's size comes from stat'ing it */
		status = truenas_open_stream(tree, sname, NTCREATEX_DISP_OPEN,
					     &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"reopen stream");
		ZERO_STRUCT(finfo);
		finfo.generic.level = RAW_FILEINFO_STANDARD_INFORMATION;
		finfo.generic.in.file.handle = h;
		status = smb2_getinfo_file(tree, tctx, &finfo);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"query stream standard info");
		torture_assert_u64_equal_goto(tctx,
					      finfo.standard_info.out.size,
					      sizes[i], ret, done,
					      "stream size via stat");

		for (off = 0; off < sizes[i]; off += chunk) {
			struct smb2_read rd;
			uint32_t len = MIN(chunk, sizes[i] - off);

			ZERO_STRUCT(rd);
			rd.in.file.handle = h;
			rd.in.offset = off;
			rd.in.length = len;
			status = smb2_read(tree, tctx, &rd);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				talloc_asprintf(tctx, "read %" PRIu32
						"-byte stream", sizes[i]));
			torture_assert_int_equal_goto(tctx, rd.out.data.length,
						      len, ret, done,
						      "short stream read");
			truenas_stream_fill(buf, off, len);
			torture_assert_mem_equal_goto(tctx, rd.out.data.data,
						      buf, len, ret, done,
						      "stream data mismatch");
			TALLOC_FREE(rd.out.data.data);
		}
		smb2_util_close(tree, h);
	}

	status = truenas_open_stream(tree, fname, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open base file (streaminfo)");
	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	finfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"query stream information");
	smb2_util_close(tree, h);

	/* every stream exactly once, plus ::$DATA */
	torture_assert_int_equal_goto(tctx, finfo.stream_info.out.num_streams,
				      num_sizes + 1, ret, done,
				      "number of streams listed");

	for (i = 0; i < num_sizes; i++) {
		const char *want = talloc_asprintf(tctx, ":s%zu:$DATA", i);
		bool found = false;

		for (j = 0; j < finfo.stream_info.out.num_streams; j++) {
			struct stream_struct *s = &finfo.stream_info.out.streams[j];

			if (!strequal(s->stream_name.s, want)) {
				continue;
			}
			found = true;
			torture_assert_u64_equal_goto(tctx, s->size, sizes[i],
						      ret, done,
						      "stream size via streaminfo");
			torture_assert_goto(tctx, s->alloc_size >= s->size,
					    ret, done,
					    "allocation size below stream size");
		}
		torture_assert_goto(tctx, found, ret, done,
				    talloc_asprintf(tctx, "%s not listed", want));
	}

done:
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * Check that stream sname holds exactly len bytes of data.
 */
static bool truenas_check_stream(struct torture_context *tctx,
				 struct smb2_tree *tree,
				 const char *sname,
				 const uint8_t *data,
				 uint32_t len)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	union smb_fileinfo finfo;
	struct smb2_read rd;

	status = truenas_open_stream(tree, sname, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		talloc_asprintf(tctx, "open %s", sname));

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_STANDARD_INFORMATION;
	finfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"query stream standard info");
	torture_assert_u64_equal_goto(tctx, finfo.standard_info.out.size, len,
				      ret, done,
		talloc_asprintf(tctx, "size of %s", sname));

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.offset = 0;
	rd.in.length = len;
	status = smb2_read(tree, tctx, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		talloc_asprintf(tctx, "read %s", sname));
	torture_assert_int_equal_goto(tctx, rd.out.data.length, len, ret, done,
				      "short stream read");
	torture_assert_mem_equal_goto(tctx, rd.out.data.data, data, len,
				      ret, done,
		talloc_asprintf(tctx, "data of %s", sname));

done:
	smb2_util_close(tree, h);
	return ret;
}

/*
 * Renaming a stream ("file:old" to ":new"), which smbd hands to the module's
 * rename_stream. The data must move with the name, an existing target is
 * replaced only when asked, and renaming a stream onto its own name, in any
 * case, leaves it intact.
 */
static bool test_truenas_streams_rename(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	union smb_fileinfo finfo;
	const char *fname = "streamrename";
	const uint8_t small[] = "small";
	/* past get_xattr_value_fsp()'s first guess */
	const uint32_t biglen = 20000;
	uint8_t *big = NULL;

	big = talloc_array(tctx, uint8_t, biglen);
	torture_assert_goto(tctx, big != NULL, ret, done, "talloc buffer");
	truenas_stream_fill(big, 0, biglen);

	smb2_util_unlink(tree, fname);
	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create base file");
	smb2_util_close(tree, h);

	status = truenas_open_stream(tree, "streamrename:one",
				     NTCREATEX_DISP_CREATE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create stream one");
	status = smb2_util_write(tree, h, big, 0, biglen);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write stream one");
	smb2_util_close(tree, h);

	status = truenas_open_stream(tree, "streamrename:two",
				     NTCREATEX_DISP_CREATE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create stream two");
	status = smb2_util_write(tree, h, small, 0, sizeof(small));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write stream two");
	smb2_util_close(tree, h);

	/* one -> three: the data moves, the old name is gone */
	status = truenas_open_stream(tree, "streamrename:one",
				     NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open stream one");
	status = truenas_rename(tree, h, ":three", false);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"rename one to three");
	status = truenas_open_stream(tree, "streamrename:one",
				     NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "stream one still there");
	ret = truenas_check_stream(tctx, tree, "streamrename:three",
				   big, biglen);
	torture_assert_goto(tctx, ret, ret, done, "stream three");

	/* three -> two, an existing stream: only replaced when asked */
	status = truenas_open_stream(tree, "streamrename:three",
				     NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open stream three");
	status = truenas_rename(tree, h, ":two", false);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_COLLISION,
					   ret, done,
					   "rename onto two without overwrite");
	status = truenas_rename(tree, h, ":two", true);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"rename onto two with overwrite");
	status = truenas_open_stream(tree, "streamrename:three",
				     NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "stream three still there");
	ret = truenas_check_stream(tctx, tree, "streamrename:two", big, biglen);
	torture_assert_goto(tctx, ret, ret, done, "stream two replaced");

	/* two -> TWO: its own name in another case, which changes nothing */
	status = truenas_open_stream(tree, "streamrename:two",
				     NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open stream two");
	status = truenas_rename(tree, h, ":TWO", true);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"rename two onto itself");
	ret = truenas_check_stream(tctx, tree, "streamrename:two", big, biglen);
	torture_assert_goto(tctx, ret, ret, done, "stream two intact");

	/* left: ::$DATA and the one stream */
	status = truenas_open_stream(tree, fname, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open base file (streaminfo)");
	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	finfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"query stream information");
	torture_assert_int_equal_goto(tctx, finfo.stream_info.out.num_streams,
				      2, ret, done, "number of streams left");

done:
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * smbd only checks the streams of a file opened for delete while one of them
 * is open. A stream open without FILE_SHARE_DELETE on another connection must
 * still block the delete, and once it is closed the streams go with the file.
 */
static bool test_truenas_streams_delete_open_stream(struct torture_context *tctx,
						    struct smb2_tree *tree1,
						    struct smb2_tree *tree2)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct smb2_handle hs = {{0}};
	struct smb2_create cr;
	union smb_fileinfo finfo;
	const char *fname = "streamdelete";
	const char *sname = "streamdelete:s";
	const uint8_t data[] = "stream data";

	smb2_util_unlink(tree1, fname);

	status = torture_smb2_testfile(tree1, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create base file");
	smb2_util_close(tree1, h);

	status = truenas_open_stream(tree1, sname, NTCREATEX_DISP_CREATE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create stream");
	status = smb2_util_write(tree1, h, data, 0, sizeof(data));
	smb2_util_close(tree1, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write stream");

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			     NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.fname = sname;
	status = smb2_create(tree2, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open stream on the other connection");
	hs = cr.out.file.handle;

	status = smb2_util_unlink(tree1, fname);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_SHARING_VIOLATION,
					   ret, done,
					   "delete with the stream open");

	smb2_util_close(tree2, hs);
	ZERO_STRUCT(hs);

	status = smb2_util_unlink(tree1, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"delete after the stream was closed");

	status = torture_smb2_testfile(tree1, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"recreate base file");
	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	finfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree1, tctx, &finfo);
	smb2_util_close(tree1, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"query stream information");
	torture_assert_int_equal_goto(tctx, finfo.stream_info.out.num_streams,
				      1, ret, done,
				      "streams on the recreated file");

done:
	if (!smb2_util_handle_empty(hs)) {
		smb2_util_close(tree2, hs);
	}
	smb2_util_unlink(tree1, fname);
	return ret;
}

/*
 * Ask for Apple's SMB2 extensions with directory attributes for this session,
 * as a Mac does. *supported says whether the server offered them, which it
 * only does with vfs_fruit.
 */
/*
 * Send an AAPL server query offering client_caps. *server_caps stays 0 on
 * shares without vfs_fruit.
 */
static bool truenas_negotiate_aapl(struct torture_context *tctx,
				   struct smb2_tree *tree,
				   uint64_t client_caps,
				   uint64_t *server_caps)
{
	struct smb2_create io;
	struct smb2_create_blob *aapl = NULL;
	DATA_BLOB data;
	NTSTATUS status;
	bool ret = true;

	*server_caps = 0;

	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	io.in.fname = "";

	data = data_blob_talloc(tctx, NULL, 3 * sizeof(uint64_t));
	torture_assert_goto(tctx, data.data != NULL, ret, done, "talloc");
	SBVAL(data.data, 0, SMB2_CRTCTX_AAPL_SERVER_QUERY);
	SBVAL(data.data, 8, SMB2_CRTCTX_AAPL_SERVER_CAPS);
	SBVAL(data.data, 16, client_caps);

	status = smb2_create_blob_add(tctx, &io.in.blobs, "AAPL", data);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create_blob_add");

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open share root with AAPL context");
	smb2_util_close(tree, io.out.file.handle);

	aapl = smb2_create_blob_find(&io.out.blobs, SMB2_CREATE_TAG_AAPL);
	if ((aapl != NULL) && (aapl->data.length >= 24)) {
		*server_caps = BVAL(aapl->data.data, 16);
	}

done:
	return ret;
}

static bool truenas_enable_aapl(struct torture_context *tctx,
				struct smb2_tree *tree,
				bool *supported)
{
	uint64_t server_caps = 0;
	bool ret;

	ret = truenas_negotiate_aapl(tctx, tree,
				     SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
				     SMB2_CRTCTX_AAPL_UNIX_BASED,
				     &server_caps);
	*supported = (server_caps &
		      SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR) != 0;
	return ret;
}

/*
 * Resource fork sizes in AAPL directory listings.
 *
 * With directory attributes negotiated, each entry carries the length of its
 * resource fork in the short name field. With fruit:resource = stream,
 * vfs_fruit takes that length straight from the truenas_streams_xattr xattr,
 * so it must use the stream's xattr name and leave out the trailing byte the
 * module stores. Sizes stay under the CI share's 32 KiB stream cap. Skipped
 * on shares without vfs_fruit.
 */
static bool test_truenas_fruit_readdir_rfork_size(struct torture_context *tctx,
						  struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	bool supported = false;
	bool found[5] = { false };
	struct smb2_handle h = {{0}};
	struct smb2_handle dirh = {{0}};
	struct smb2_find f;
	union smb_search_data *d = NULL;
	const uint32_t sizes[] = { 0, 3, 300, 5000, 30000 };
	uint8_t *buf = NULL;
	unsigned int count;
	size_t i;

	ret = truenas_enable_aapl(tctx, tree, &supported);
	if (!ret) {
		return false;
	}
	if (!supported) {
		torture_skip(tctx, "share does not offer AAPL directory "
			     "attributes (no vfs_fruit)\n");
	}

	buf = talloc_zero_array(tctx, uint8_t, sizes[ARRAY_SIZE(sizes) - 1]);
	torture_assert_goto(tctx, buf != NULL, ret, done, "talloc buffer");

	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		const char *fname = talloc_asprintf(tctx, "rforksize_%zu", i);
		const char *sname = talloc_asprintf(tctx, "%s%s", fname,
						    AFPRESOURCE_STREAM_NAME);

		smb2_util_unlink(tree, fname);
		status = torture_smb2_testfile(tree, fname, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create file");
		smb2_util_close(tree, h);

		if (sizes[i] == 0) {
			continue;
		}

		status = truenas_open_stream(tree, sname,
					     NTCREATEX_DISP_OPEN_IF, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create resource fork");
		status = smb2_util_write(tree, h, buf, 0, sizes[i]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"write resource fork");
		smb2_util_close(tree, h);
	}

	status = smb2_util_roothandle(tree, &dirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open share root for enumeration");

	ZERO_STRUCT(f);
	f.in.file.handle	= dirh;
	f.in.pattern		= "rforksize_*";
	f.in.max_response_size	= 0x10000;
	f.in.level		= SMB2_FIND_ID_BOTH_DIRECTORY_INFO;

	do {
		unsigned int j;

		status = smb2_find_level(tree, tree, &f, &count, &d);
		if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
			break;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_find_level");

		for (j = 0; j < count; j++) {
			const char *name = d[j].id_both_directory_info.name.s;
			uint64_t rfork_len;
			unsigned int n;

			if ((sscanf(name, "rforksize_%u", &n) != 1) ||
			    (n >= ARRAY_SIZE(sizes))) {
				continue;
			}
			found[n] = true;

			rfork_len = BVAL(
				d[j].id_both_directory_info.short_name_buf, 0);
			torture_assert_u64_equal_goto(tctx, rfork_len,
						      sizes[n], ret, done,
				talloc_asprintf(tctx, "resource fork length "
						"of %s", name));
		}
	} while (count > 0);

	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		torture_assert_goto(tctx, found[i], ret, done,
				    "file missing from listing");
	}

done:
	smb2_util_close(tree, dirh);
	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		smb2_util_unlink(tree,
				 talloc_asprintf(tctx, "rforksize_%zu", i));
	}
	return ret;
}

/* Whether the UTF-16LE name of len bytes is the ASCII string s */
static bool truenas_utf16_is(const uint8_t *p, size_t len, const char *s)
{
	size_t i, n = strlen(s);

	if (len != 2 * n) {
		return false;
	}
	for (i = 0; i < n; i++) {
		if ((p[2 * i] != (uint8_t)s[i]) || (p[2 * i + 1] != 0)) {
			return false;
		}
	}
	return true;
}

/*
 * List the share root with SMB2_FIND_ID_BOTH_DIRECTORY_INFO and return, for
 * each of names, the 16-bit word after the EA size: the short name length and
 * reserved byte in V1, the flags in READ_DIR_ATTR_V2. Unlisted names get -1.
 */
static bool truenas_aapl_entry_words(struct torture_context *tctx,
				     struct smb2_tree *tree,
				     const char **names,
				     size_t num_names,
				     int *words)
{
	struct smb2_handle h = {{0}};
	struct smb2_find f;
	NTSTATUS status;
	bool ret = true;
	size_t i;

	for (i = 0; i < num_names; i++) {
		words[i] = -1;
	}

	status = smb2_util_roothandle(tree, &h);
	torture_assert_ntstatus_ok(tctx, status, "open share root");

	ZERO_STRUCT(f);
	f.in.file.handle	= h;
	f.in.pattern		= "rdattr*";
	f.in.max_response_size	= 0x10000;
	f.in.level		= SMB2_FIND_ID_BOTH_DIRECTORY_INFO;

	for (;;) {
		const uint8_t *b = NULL;
		size_t len, ofs = 0;

		status = smb2_find(tree, tctx, &f);
		if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
			break;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_find");
		b = f.out.blob.data;
		len = f.out.blob.length;

		while (ofs + 104 <= len) {
			uint32_t next = IVAL(b, ofs);
			uint32_t name_len = IVAL(b, ofs + 60);

			torture_assert_goto(tctx, ofs + 104 + name_len <= len,
					    ret, done, "entry overruns buffer");
			for (i = 0; i < num_names; i++) {
				if (truenas_utf16_is(b + ofs + 104, name_len,
						     names[i])) {
					words[i] = SVAL(b, ofs + 68);
				}
			}
			if (next == 0) {
				break;
			}
			ofs += next;
		}
	}

done:
	smb2_util_close(tree, h);
	return ret;
}

/*
 * A client that only offers READ_DIR_ATTR keeps the V1 layout: no V2 bit, and
 * the word after the EA size is the short name length Samba always sent.
 */
static bool test_truenas_fruit_readdir_attr_v1(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	const char *names[] = { "rdattr_v1_plain" };
	int words[ARRAY_SIZE(names)];
	struct smb2_handle h = {{0}};
	uint64_t server_caps = 0;
	NTSTATUS status;
	bool ret = true;

	ret = truenas_negotiate_aapl(tctx, tree,
				     SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
				     SMB2_CRTCTX_AAPL_UNIX_BASED,
				     &server_caps);
	if (!ret) {
		return false;
	}
	if (!(server_caps & SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR)) {
		torture_skip(tctx, "share does not offer AAPL directory "
			     "attributes (no vfs_fruit)\n");
	}
	torture_assert(tctx,
		       !(server_caps &
			 SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR_V2),
		       "V2 only when the client offers it");

	smb2_util_unlink(tree, names[0]);
	status = torture_smb2_testfile(tree, names[0], &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file");
	smb2_util_close(tree, h);

	ret = truenas_aapl_entry_words(tctx, tree, names, ARRAY_SIZE(names),
				       words);
	if (!ret) {
		goto done;
	}
	torture_assert_int_equal_goto(tctx, words[0], 24, ret, done,
				      "V1 short name length");

done:
	smb2_util_unlink(tree, names[0]);
	return ret;
}

/*
 * AAPL READ_DIR_ATTR_V2. A client offering V2 gets the V1 and V2 bits back,
 * as from macOS, and each entry's flags say whether it has no stream besides
 * its data, which lets macOS skip asking for its xattrs. The entries live in
 * the share root, as fruit:resource = file can't create resource forks in
 * subdirectories.
 * Skipped without vfs_fruit or with fruit:readdir_attr_version = 1.
 */
static bool test_truenas_fruit_readdir_attr_v2(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	struct {
		const char *name;
		bool dir;
		const char *stream;
		size_t len;
		int flags;
	} e[] = {
		{ "rdattr_v2_plain", false, NULL, 0,
		  SMB2_CRTCTX_AAPL_READ_DIR_NO_XATTR },
		{ "rdattr_v2_dir", true, NULL, 0,
		  SMB2_CRTCTX_AAPL_READ_DIR_NO_XATTR },
		{ "rdattr_v2_stream", false, ":foo", 3, 0 },
		{ "rdattr_v2_finderinfo", false, AFPINFO_STREAM_NAME,
		  AFP_INFO_SIZE, 0 },
		{ "rdattr_v2_rsrc", false, AFPRESOURCE_STREAM_NAME, 300, 0 },
		{ "rdattr_v2_dirfinderinfo", true, AFPINFO_STREAM_NAME,
		  AFP_INFO_SIZE, 0 },
	};
	const char *names[ARRAY_SIZE(e)];
	int words[ARRAY_SIZE(e)];
	uint8_t data[300] = {0};
	struct smb2_handle h = {{0}};
	uint64_t server_caps = 0;
	NTSTATUS status;
	bool ret = true;
	size_t i;

	ret = truenas_negotiate_aapl(tctx, tree,
				     SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
				     SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR_V2 |
				     SMB2_CRTCTX_AAPL_UNIX_BASED,
				     &server_caps);
	if (!ret) {
		return false;
	}
	if (!(server_caps & (SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR |
			     SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR_V2))) {
		torture_skip(tctx, "share does not offer AAPL directory "
			     "attributes (no vfs_fruit)\n");
	}
	if (!(server_caps & SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR_V2)) {
		torture_skip(tctx, "fruit:readdir_attr_version = 1\n");
	}
	torture_assert(tctx,
		       server_caps & SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR,
		       "a V2 server also sets the V1 bit");

	/* AfpInfo with a FinderInfo type and creator */
	RSIVAL(data, 0, AFP_Signature);
	RSIVAL(data, 4, AFP_Version);
	RSIVAL(data, 12, AFP_BackupTime);
	memcpy(data + AFP_OFF_FinderInfo, "TEXTttxt", 8);

	for (i = 0; i < ARRAY_SIZE(e); i++) {
		names[i] = e[i].name;
		smb2_deltree(tree, e[i].name);
	}

	for (i = 0; i < ARRAY_SIZE(e); i++) {
		const char *path = e[i].name;

		if (e[i].dir) {
			status = torture_smb2_testdir(tree, path, &h);
		} else {
			status = torture_smb2_testfile(tree, path, &h);
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						path);
		smb2_util_close(tree, h);

		if (e[i].stream == NULL) {
			continue;
		}
		path = talloc_asprintf(tctx, "%s%s", path, e[i].stream);
		status = truenas_open_stream(tree, path,
					     NTCREATEX_DISP_OPEN_IF, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						path);
		if (e[i].len > 0) {
			status = smb2_util_write(tree, h, data, 0, e[i].len);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, path);
		}
		smb2_util_close(tree, h);
	}

	ret = truenas_aapl_entry_words(tctx, tree, names, ARRAY_SIZE(e),
				       words);
	if (!ret) {
		goto done;
	}
	for (i = 0; i < ARRAY_SIZE(e); i++) {
		torture_assert_int_equal_goto(tctx, words[i], e[i].flags,
					      ret, done,
			talloc_asprintf(tctx, "READ_DIR_ATTR_V2 flags of %s",
					e[i].name));
	}

done:
	for (i = 0; i < ARRAY_SIZE(e); i++) {
		smb2_deltree(tree, e[i].name);
	}
	return ret;
}

/*
 * Enumerate snapshots over SMB (FSCTL_SRV_ENUM_SNAPS) and return the first
 * @GMT- label plus its NTTIME timewarp token. On a share without
 * shadow_copy_zfs the FSCTL is unsupported: *supported is set false and true is
 * returned (the caller should torture_skip). Returns false only on a hard
 * failure.
 */
static bool truenas_sc_first_snapshot(struct torture_context *tctx,
				      struct smb2_tree *tree,
				      bool *supported,
				      char label[TN_GMT_LEN + 1],
				      NTTIME *twrp)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h;
	union smb_ioctl io;
	uint32_t nsnaps, arr_size, i;
	const uint8_t *sp;
	struct tm tm;
	char *tp = NULL;

	*supported = true;

	status = smb2_util_roothandle(tree, &h);
	torture_assert_ntstatus_ok(tctx, status, "open share root");

	/* First call: header only, to learn the count and array size. */
	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = h;
	io.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	io.smb2.in.max_output_response = 16;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, tctx, &io.smb2);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST)) {
		smb2_util_close(tree, h);
		*supported = false;
		return true;
	}
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SRV_ENUM_SNAPS (header)");
	torture_assert_goto(tctx, io.smb2.out.out.length >= 12, ret, done,
			    "short ENUM_SNAPS header");
	nsnaps = IVAL(io.smb2.out.out.data, 0);
	arr_size = IVAL(io.smb2.out.out.data, 8);
	torture_assert_goto(tctx, nsnaps >= 1, ret, done,
			    "shadow_copy_zfs enumerated no snapshots");

	/* Second call: fetch the @GMT- label array. */
	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = h;
	io.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	io.smb2.in.max_output_response = 12 + arr_size;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, tctx, &io.smb2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SRV_ENUM_SNAPS (data)");
	torture_assert_goto(tctx,
			    io.smb2.out.out.length >= 12 + (TN_GMT_LEN * 2),
			    ret, done, "short ENUM_SNAPS data");

	/*
	 * Labels are UTF-16LE @GMT- tokens (pure ASCII). Pull the first one
	 * (TN_GMT_LEN code units at offset 12) by taking each unit's low byte.
	 */
	sp = (const uint8_t *)io.smb2.out.out.data + 12;
	for (i = 0; i < TN_GMT_LEN; i++) {
		label[i] = (char)sp[i * 2];
	}
	label[TN_GMT_LEN] = '\0';
	smb2_util_close(tree, h);
	torture_comment(tctx, "shadow_copy: enumerated label [%s]\n", label);

	/*
	 * Over SMB2 the snapshot is selected by the timewarp create context, not
	 * by an @GMT- prefix in the path: the source4 SMB2 client does not
	 * auto-parse @GMT- path prefixes (only smbclient/source3 does), and smbd
	 * only sets UCF_GMT_PATHNAME from FLAGS2_REPARSE_PATH, which the SMB2
	 * server never sets. Convert the label to an NTTIME for cr.in.timewarp.
	 */
	setenv("TZ", "GMT", 1);
	ZERO_STRUCT(tm);
	tp = strptime(label, "@GMT-%Y.%m.%d-%H.%M.%S", &tm);
	torture_assert_goto(tctx, tp != NULL && *tp == '\0', ret, done,
			    "parse enumerated @GMT- label");
	unix_to_nt_time(twrp, mktime(&tm));

done:
	return ret;
}

/*
 * Snapshot browsing via shadow_copy_zfs.
 *
 * The harness writes a file, snapshots the dataset, then overwrites the live
 * file. This test enumerates the snapshot over SMB, opens the plain file name at
 * that snapshot's timewarp token, and verifies it still holds the pre-snapshot
 * content. Skipped on shares without shadow_copy_zfs (FSCTL unsupported).
 */
static bool test_truenas_shadow_copy_browse(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	bool supported;
	struct smb2_handle h = {{0}};
	struct smb2_read rd;
	struct smb2_create cr;
	const char *file = torture_setting_string(tctx, "sc_file", "sc_canary");
	const char *expect = torture_setting_string(tctx, "sc_expect",
						    "snapshot-version");
	size_t elen = strlen(expect);
	char label[TN_GMT_LEN + 1];
	NTTIME twrp;

	if (!truenas_sc_first_snapshot(tctx, tree, &supported, label, &twrp)) {
		return false;
	}
	if (!supported) {
		torture_skip(tctx,
			     "FSCTL_SRV_ENUM_SNAPS unsupported (no shadow_copy_zfs)");
	}

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = file;
	cr.in.timewarp = twrp;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open file at snapshot timewarp");
	h = cr.out.file.handle;

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.offset = 0;
	rd.in.length = elen;
	status = smb2_read(tree, tree, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"read snapshot file");
	torture_assert_int_equal_goto(tctx, rd.out.data.length, elen, ret, done,
				      "short read from snapshot");
	torture_assert_mem_equal_goto(tctx, rd.out.data.data, expect, elen,
				      ret, done,
				      "snapshot content does not match pre-snapshot value");
	smb2_util_close(tree, h);

done:
	return ret;
}

/*
 * A snapshot is read-only: opening a file at the snapshot timewarp with write
 * access must either be denied at open or, if the handle is granted (downgraded
 * to read-only), the write that follows must fail. shadow_copy_zfs forces
 * snapshot opens read-only and returns EROFS on mutation
 * (vfs_shadow_copy_zfs.c). Skipped on shares without shadow_copy_zfs.
 */
static bool test_truenas_shadow_copy_readonly(struct torture_context *tctx,
					      struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	bool supported;
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	const char *file = torture_setting_string(tctx, "sc_file", "sc_canary");
	const char *data = "overwrite";
	char label[TN_GMT_LEN + 1];
	NTTIME twrp;

	if (!truenas_sc_first_snapshot(tctx, tree, &supported, label, &twrp)) {
		return false;
	}
	if (!supported) {
		torture_skip(tctx,
			     "FSCTL_SRV_ENUM_SNAPS unsupported (no shadow_copy_zfs)");
	}

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = file;
	cr.in.timewarp = twrp;
	status = smb2_create(tree, tctx, &cr);
	if (!NT_STATUS_IS_OK(status)) {
		/* write access denied at open time -- read-only enforced */
		torture_comment(tctx,
				"shadow_copy: write open denied (%s)\n",
				nt_errstr(status));
		return true;
	}
	h = cr.out.file.handle;

	status = smb2_util_write(tree, h, data, 0, strlen(data));
	torture_assert_goto(tctx, !NT_STATUS_IS_OK(status), ret, done,
			    "write into snapshot must fail");

done:
	smb2_util_close(tree, h);
	return ret;
}

/*
 * The snapshot directory is browsable: opening the share root at the snapshot
 * timewarp and enumerating it must list the pre-snapshot file. Skipped on
 * shares without shadow_copy_zfs.
 */
static bool test_truenas_shadow_copy_listdir(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	bool supported;
	bool present = false;
	struct smb2_handle dirh = {{0}};
	struct smb2_create cr;
	struct smb2_find f;
	union smb_search_data *d;
	unsigned int count;
	const char *file = torture_setting_string(tctx, "sc_file", "sc_canary");
	char label[TN_GMT_LEN + 1];
	NTTIME twrp;

	if (!truenas_sc_first_snapshot(tctx, tree, &supported, label, &twrp)) {
		return false;
	}
	if (!supported) {
		torture_skip(tctx,
			     "FSCTL_SRV_ENUM_SNAPS unsupported (no shadow_copy_zfs)");
	}

	/* Open the snapshot root directory via the timewarp token. */
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_DIR_LIST | SEC_DIR_READ_ATTRIBUTE;
	cr.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	cr.in.fname = "";
	cr.in.timewarp = twrp;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open snapshot root directory");
	dirh = cr.out.file.handle;

	ZERO_STRUCT(f);
	f.in.file.handle	= dirh;
	f.in.pattern		= "*";
	f.in.max_response_size	= 0x10000;
	f.in.level		= SMB2_FIND_BOTH_DIRECTORY_INFO;

	do {
		unsigned int i;

		status = smb2_find_level(tree, tree, &f, &count, &d);
		if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
			break;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_find_level in snapshot");

		for (i = 0; i < count; i++) {
			if (strcmp(d[i].both_directory_info.name.s, file) == 0) {
				present = true;
			}
		}
	} while (count > 0);

	torture_assert_goto(tctx, present, ret, done,
			    "canary file must be listed in snapshot directory");

done:
	smb2_util_close(tree, dirh);
	return ret;
}

#ifdef HAVE_LIBZFS
/*
 * The listing cache tests take and destroy snapshots of the share dataset
 * through smb_libzfs, so smbtorture has to run as root on the server, with
 * torture:sc_mp set to the mountpoint of the dataset of the share root.
 * Without it they skip.
 */
static bool truenas_sc_take(const struct zfs_dataset *zds, const char *name)
{
	return smb_zfs_snapshot(zds->mnt_id, name, false) == 0;
}

/* destroying a snapshot that does not exist is not an error in ZFS */
static bool truenas_sc_destroy(const struct zfs_dataset *zds,
			       const char *name)
{
	struct snapshot_list l = { .num_entries = 1 };
	struct snapshot_entry e = { 0 };

	strlcpy(l.dataset_name, zds->dataset_name, sizeof(l.dataset_name));
	strlcpy(e.name, name, sizeof(e.name));
	l.entries = &e;
	return smb_zfs_delete_snapshots(&l) == 0;
}

/*
 * The @GMT- label and timewarp token of a snapshot of the dataset, from
 * smb_zfs_list_snapshots() (checked against the snapshot calls by
 * local.smb_libzfs.snapshot_list). ptwrp may be NULL.
 */
static bool truenas_sc_find(struct torture_context *tctx,
			    const struct zfs_dataset *zds,
			    const char *name,
			    char label[TN_GMT_LEN + 1],
			    NTTIME *ptwrp)
{
	struct snapshot_list *l = NULL;
	const struct snapshot_entry *e = NULL;

	l = smb_zfs_list_snapshots(tctx, zds->mnt_id, NULL);
	if (l == NULL) {
		return false;
	}
	for (e = l->entries; e != NULL; e = e->next) {
		if (strcmp(e->name, name) == 0) {
			strlcpy(label, e->label, TN_GMT_LEN + 1);
			if (ptwrp != NULL) {
				*ptwrp = e->nt_time;
			}
			break;
		}
	}
	TALLOC_FREE(l);
	return e != NULL;
}

#define truenas_sc_label(tctx, zds, name, label) \
	truenas_sc_find(tctx, zds, name, label, NULL)

/* Open fname for reading at the timewarp token twrp. */
static NTSTATUS truenas_sc_open_at(struct smb2_tree *tree,
				   TALLOC_CTX *mem_ctx,
				   const char *fname,
				   NTTIME twrp,
				   struct smb2_handle *h)
{
	struct smb2_create cr;
	NTSTATUS status;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_READ_ATTRIBUTE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;
	cr.in.timewarp = twrp;
	status = smb2_create(tree, mem_ctx, &cr);
	if (NT_STATUS_IS_OK(status)) {
		*h = cr.out.file.handle;
	}
	return status;
}

/*
 * The @GMT- labels FSCTL_SRV_ENUM_SNAPS returns for fname ("" for the share
 * root), in the order of the server: newest first. Each label takes a
 * SHADOW_COPY_LABEL slot of 25 UTF-16 units after the 12 byte header.
 */
static bool truenas_sc_enum(struct torture_context *tctx,
			    struct smb2_tree *tree,
			    const char *fname,
			    char ***plabels,
			    uint32_t *pn)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct smb2_create cr;
	union smb_ioctl io;
	uint32_t nsnaps, arr_size, i, j;
	const uint8_t *sp = NULL;
	char **labels = NULL;

	*plabels = NULL;
	*pn = 0;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_READ_ATTRIBUTE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok(tctx, status, "open for ENUM_SNAPS");
	h = cr.out.file.handle;

	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = h;
	io.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	io.smb2.in.max_output_response = 16;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, tctx, &io.smb2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SRV_ENUM_SNAPS (header)");
	torture_assert_goto(tctx, io.smb2.out.out.length >= 12, ret, done,
			    "short ENUM_SNAPS header");
	nsnaps = IVAL(io.smb2.out.out.data, 0);
	arr_size = IVAL(io.smb2.out.out.data, 8);
	if (nsnaps == 0) {
		goto done;
	}

	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = h;
	io.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	io.smb2.in.max_output_response = 12 + arr_size;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, tctx, &io.smb2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SRV_ENUM_SNAPS (data)");
	/* the list may have changed between the two calls; it must not */
	torture_assert_int_equal_goto(tctx, IVAL(io.smb2.out.out.data, 4),
				      nsnaps, ret, done,
				      "labels returned");
	torture_assert_goto(tctx,
			    io.smb2.out.out.length >=
			    12 + nsnaps * (TN_GMT_LEN + 1) * 2,
			    ret, done, "short ENUM_SNAPS data");

	labels = talloc_array(tctx, char *, nsnaps);
	torture_assert_goto(tctx, labels != NULL, ret, done, "talloc");
	for (i = 0; i < nsnaps; i++) {
		labels[i] = talloc_zero_array(labels, char, TN_GMT_LEN + 1);
		torture_assert_goto(tctx, labels[i] != NULL, ret, done,
				    "talloc");
		sp = (const uint8_t *)io.smb2.out.out.data + 12 +
		     i * (TN_GMT_LEN + 1) * 2;
		/* pure ASCII: the low byte of each UTF-16LE unit */
		for (j = 0; j < TN_GMT_LEN; j++) {
			labels[i][j] = (char)sp[j * 2];
		}
	}
	*plabels = labels;
	*pn = nsnaps;

done:
	smb2_util_close(tree, h);
	return ret;
}

static bool truenas_sc_has_label(char **labels, uint32_t n,
				 const char *label)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (strcmp(labels[i], label) == 0) {
			return true;
		}
	}
	return false;
}

/*
 * The share dataset for a listing cache test, or NULL (with the test
 * marked skipped) where the test cannot run. False on a failure.
 */
static bool truenas_sc_cache_setup(struct torture_context *tctx,
				   struct smb2_tree *tree,
				   const struct zfs_dataset **pzds)
{
	const char *mp = torture_setting_string(tctx, "sc_mp", NULL);
	const struct zfs_dataset *zds = NULL;
	struct smb2_handle h;
	union smb_ioctl io;
	NTSTATUS status;

	*pzds = NULL;

	if (mp == NULL) {
		torture_result(tctx, TORTURE_SKIP,
			       "no torture:sc_mp (mountpoint of the share "
			       "dataset)");
		return true;
	}
	if (geteuid() != 0) {
		torture_result(tctx, TORTURE_SKIP,
			       "taking snapshots needs root");
		return true;
	}
	/* the share root may have no snapshot yet: probe support only */
	status = smb2_util_roothandle(tree, &h);
	torture_assert_ntstatus_ok(tctx, status, "open share root");
	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = h;
	io.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	io.smb2.in.max_output_response = 16;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, tctx, &io.smb2);
	smb2_util_close(tree, h);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST)) {
		torture_result(tctx, TORTURE_SKIP,
			       "FSCTL_SRV_ENUM_SNAPS unsupported "
			       "(no shadow_copy_zfs)");
		return true;
	}
	torture_assert_ntstatus_ok(tctx, status, "FSCTL_SRV_ENUM_SNAPS");
	torture_assert_int_equal(tctx, conn_zfs_init(mp, &zds), 0,
				 "conn_zfs_init");
	torture_assert(tctx, zds != NULL, "share dataset");

	*pzds = zds;
	return true;
}

/*
 * A snapshot taken or destroyed while a connection holds the snapshot list
 * of the dataset shows in the next enumeration on that connection: the
 * list is checked against the .zfs/snapshot directory on every use, not
 * kept for a time. The share root is a directory, which every snapshot
 * lists.
 */
static bool test_truenas_shadow_copy_cache_change(struct torture_context *tctx,
						  struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const char *snap = "tn_sc_cache";
	char **labels = NULL;
	uint32_t n0, n;
	char label[TN_GMT_LEN + 1];
	bool taken = false;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	truenas_sc_destroy(zds, snap);

	/* fill the cache of this connection */
	torture_assert(tctx, truenas_sc_enum(tctx, tree, "", &labels, &n0),
		       "enumerate");

	torture_assert(tctx, truenas_sc_take(zds, snap), "snapshot");
	taken = true;
	torture_assert_goto(tctx, truenas_sc_label(tctx, zds, snap, label),
			    ret, done, "label of the snapshot");

	torture_assert_goto(tctx, truenas_sc_enum(tctx, tree, "", &labels, &n),
			    ret, done, "enumerate after snapshot");
	torture_assert_int_equal_goto(tctx, n, n0 + 1, ret, done,
				      "new snapshot listed at once");
	torture_assert_goto(tctx, truenas_sc_has_label(labels, n, label),
			    ret, done, "label of the new snapshot");

	/* a listing that did not change is served from the cache */
	torture_assert_goto(tctx, truenas_sc_enum(tctx, tree, "", &labels, &n),
			    ret, done, "enumerate again");
	torture_assert_int_equal_goto(tctx, n, n0 + 1, ret, done,
				      "same list");

	torture_assert_goto(tctx, truenas_sc_destroy(zds, snap), ret, done,
			    "destroy");
	taken = false;

	torture_assert_goto(tctx, truenas_sc_enum(tctx, tree, "", &labels, &n),
			    ret, done, "enumerate after destroy");
	torture_assert_int_equal_goto(tctx, n, n0, ret, done,
				      "destroyed snapshot gone at once");
	torture_assert_goto(tctx, !truenas_sc_has_label(labels, n, label),
			    ret, done, "label of the destroyed snapshot");

done:
	if (taken) {
		truenas_sc_destroy(zds, snap);
	}
	return ret;
}

static bool truenas_sc_write(struct torture_context *tctx,
			     struct smb2_tree *tree,
			     const char *fname,
			     const char *data)
{
	NTSTATUS status;
	struct smb2_create cr;
	struct smb2_handle h;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_WRITE_DATA | SEC_FILE_READ_ATTRIBUTE;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok(tctx, status, "create");
	h = cr.out.file.handle;

	status = smb2_util_write(tree, h, data, 0, strlen(data));
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok(tctx, status, "write");
	return true;
}

/*
 * A file version is listed only when it differs from the next newer one:
 * the same inode, generation and change cookie mean the same data. With
 * the file written before snapshots a and b, unchanged for c, and written
 * again after c, the versions are c (b holds the same data) and a.
 */
static bool test_truenas_shadow_copy_same_version(struct torture_context *tctx,
						  struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const char *fname = "tn_sc_version";
	const char *snaps[] = { "tn_sc_va", "tn_sc_vb", "tn_sc_vc" };
	char label_a[TN_GMT_LEN + 1];
	char label_c[TN_GMT_LEN + 1];
	char **labels = NULL;
	uint32_t n;
	size_t i, taken = 0;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	for (i = 0; i < ARRAY_SIZE(snaps); i++) {
		truenas_sc_destroy(zds, snaps[i]);
	}

	/*
	 * A second between the snapshots gives each its own @GMT- label,
	 * which has a resolution of one second.
	 */
	torture_assert_goto(tctx, truenas_sc_write(tctx, tree, fname, "v1"),
			    ret, done, "write v1");
	torture_assert_goto(tctx, truenas_sc_take(zds, snaps[0]), ret, done,
			    "snapshot a");
	taken = 1;
	sleep(1);
	torture_assert_goto(tctx, truenas_sc_write(tctx, tree, fname, "v2"),
			    ret, done, "write v2");
	torture_assert_goto(tctx, truenas_sc_take(zds, snaps[1]), ret, done,
			    "snapshot b");
	taken = 2;
	sleep(1);
	torture_assert_goto(tctx, truenas_sc_take(zds, snaps[2]), ret, done,
			    "snapshot c");
	taken = 3;
	torture_assert_goto(tctx, truenas_sc_write(tctx, tree, fname, "v3"),
			    ret, done, "write v3");

	torture_assert_goto(tctx,
			    truenas_sc_label(tctx, zds, snaps[0], label_a) &&
			    truenas_sc_label(tctx, zds, snaps[2], label_c),
			    ret, done, "labels of the snapshots");

	torture_assert_goto(tctx,
			    truenas_sc_enum(tctx, tree, fname, &labels, &n),
			    ret, done, "enumerate file versions");
	for (i = 0; i < n; i++) {
		torture_comment(tctx, "version %zu: %s\n", i, labels[i]);
	}
	torture_assert_int_equal_goto(tctx, n, 2, ret, done,
				      "versions c and a only");
	torture_assert_str_equal_goto(tctx, labels[0], label_c, ret, done,
				      "newest version is snapshot c");
	torture_assert_str_equal_goto(tctx, labels[1], label_a, ret, done,
				      "older version is snapshot a");

done:
	for (i = 0; i < taken; i++) {
		truenas_sc_destroy(zds, snaps[i]);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * A symlink inside a snapshot is refused like one in the live share: the
 * open of a path through it at the timewarp token of the snapshot must not
 * reach the target outside the share. The share has "wide links = no".
 */
static bool test_truenas_shadow_copy_symlink(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const char *snap = "tn_sc_link";
	const char *mp = torture_setting_string(tctx, "sc_mp", NULL);
	char outside[] = "/tmp/tn_sc_outsideXXXXXX";
	char *secret = NULL;
	char *link = NULL;
	char label[TN_GMT_LEN + 1];
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	NTTIME twrp;
	bool taken = false;
	bool linked = false;
	int fd;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	truenas_sc_destroy(zds, snap);

	/* a readable file outside the share, and a symlink to its dir */
	torture_assert(tctx, mkdtemp(outside) != NULL, "mkdtemp");
	torture_assert_goto(tctx, chmod(outside, 0755) == 0, ret, done,
			    "chmod");
	secret = talloc_asprintf(tctx, "%s/secret", outside);
	link = talloc_asprintf(tctx, "%s/%s", mp, snap);
	torture_assert_goto(tctx, (secret != NULL) && (link != NULL), ret, done,
			    "talloc");
	fd = open(secret, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	torture_assert_goto(tctx, fd != -1, ret, done, "create secret");
	torture_assert_goto(tctx, write(fd, "secret", 6) == 6, ret, done,
			    "write secret");
	close(fd);
	unlink(link);
	torture_assert_goto(tctx, symlink(outside, link) == 0, ret, done,
			    "symlink");
	linked = true;

	torture_assert_goto(tctx, truenas_sc_take(zds, snap), ret, done,
			    "snapshot");
	taken = true;
	torture_assert_goto(tctx, truenas_sc_find(tctx, zds, snap, label, &twrp),
			    ret, done, "timewarp of the snapshot");
	/* only the snapshot has the link now */
	unlink(link);
	linked = false;

	status = truenas_sc_open_at(tree, tctx, "tn_sc_link\\secret", twrp, &h);
	torture_comment(tctx, "open through the snapshot symlink: %s\n",
			nt_errstr(status));
	if (NT_STATUS_IS_OK(status)) {
		smb2_util_close(tree, h);
	}
	torture_assert_goto(tctx, !NT_STATUS_IS_OK(status), ret, done,
			    "symlink in a snapshot followed out of the share");

done:
	if (taken) {
		truenas_sc_destroy(zds, snap);
	}
	if (linked) {
		unlink(link);
	}
	if (secret != NULL) {
		unlink(secret);
	}
	rmdir(outside);
	return ret;
}

/*
 * A timewarp token on a name that itself goes through .zfs/snapshot is an
 * ordinary name in the snapshot, not a path into the snapshot directory:
 * it may fail, but smbd must survive it.
 */
static bool test_truenas_shadow_copy_ctldir_name(struct torture_context *tctx,
						 struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const char *snap = "tn_sc_ctldir";
	char *fname = NULL;
	char label[TN_GMT_LEN + 1];
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	NTTIME twrp;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	truenas_sc_destroy(zds, snap);
	torture_assert(tctx, truenas_sc_take(zds, snap), "snapshot");
	torture_assert_goto(tctx, truenas_sc_find(tctx, zds, snap, label, &twrp),
			    ret, done, "timewarp of the snapshot");

	fname = talloc_asprintf(tctx, ".zfs\\snapshot\\%s", snap);
	torture_assert_goto(tctx, fname != NULL, ret, done, "talloc");
	status = truenas_sc_open_at(tree, tctx, fname, twrp, &h);
	torture_comment(tctx, "open %s at its own timewarp: %s\n", fname,
			nt_errstr(status));
	if (NT_STATUS_IS_OK(status)) {
		smb2_util_close(tree, h);
	}

	/* the connection is still served */
	status = smb2_util_roothandle(tree, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open the share root afterwards");
	smb2_util_close(tree, h);

done:
	truenas_sc_destroy(zds, snap);
	return ret;
}

/*
 * Files open in a snapshot hold its automount, and closing the last of
 * them lets go: after handles in two snapshots, one of them opened twice,
 * are closed, both snapshots can be destroyed (a snapshot still mounted
 * and in use cannot).
 */
static bool test_truenas_shadow_copy_pins(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const char *fname = "tn_sc_pin";
	const char *snaps[] = { "tn_sc_pa", "tn_sc_pb" };
	char label[TN_GMT_LEN + 1];
	struct smb2_handle h[3];
	NTTIME twrp[2];
	NTSTATUS status;
	size_t i, nopen = 0, taken = 0;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	for (i = 0; i < ARRAY_SIZE(snaps); i++) {
		truenas_sc_destroy(zds, snaps[i]);
	}

	torture_assert_goto(tctx, truenas_sc_write(tctx, tree, fname, "pin"),
			    ret, done, "write");
	for (i = 0; i < ARRAY_SIZE(snaps); i++) {
		if (i > 0) {
			sleep(1);	/* a label of its own */
		}
		torture_assert_goto(tctx, truenas_sc_take(zds, snaps[i]),
				    ret, done, "snapshot");
		taken = i + 1;
		torture_assert_goto(tctx,
				    truenas_sc_find(tctx, zds, snaps[i], label,
						    &twrp[i]),
				    ret, done, "timewarp of the snapshot");
	}

	/* a, b, then a again: a is no longer the newest pin */
	for (i = 0; i < ARRAY_SIZE(h); i++) {
		status = truenas_sc_open_at(tree, tctx, fname,
					    twrp[i == 1 ? 1 : 0], &h[i]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open in a snapshot");
		nopen = i + 1;
	}
	for (i = 0; i < nopen; i++) {
		smb2_util_close(tree, h[i]);
	}
	nopen = 0;

	for (i = 0; i < ARRAY_SIZE(snaps); i++) {
		torture_assert_goto(tctx, truenas_sc_destroy(zds, snaps[i]),
				    ret, done,
				    "destroy after the last close");
		torture_assert_goto(tctx,
				    !truenas_sc_label(tctx, zds, snaps[i],
						      label),
				    ret, done, "snapshot gone");
	}
	taken = 0;

done:
	for (i = 0; i < nopen; i++) {
		smb2_util_close(tree, h[i]);
	}
	for (i = 0; i < taken; i++) {
		truenas_sc_destroy(zds, snaps[i]);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * Snapshots taken in one second share an @GMT- label, and a timewarp at
 * that label opens one of them: the enumeration lists the label once.
 */
static bool test_truenas_shadow_copy_same_second(struct torture_context *tctx,
						 struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const char *snaps[] = { "tn_sc_s1", "tn_sc_s2" };
	char label1[TN_GMT_LEN + 1];
	char label2[TN_GMT_LEN + 1];
	char **labels = NULL;
	uint32_t n, i, count;
	size_t k;
	int attempt;
	bool same = false;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}

	/*
	 * Start on a second boundary and take both at once. A slow
	 * transaction sync can still push the second one into the next
	 * second, so try a few times.
	 */
	for (attempt = 0; attempt < 3; attempt++) {
		time_t t;

		for (k = 0; k < ARRAY_SIZE(snaps); k++) {
			truenas_sc_destroy(zds, snaps[k]);
		}
		t = time(NULL);
		while (time(NULL) == t) {
			usleep(10000);
		}
		torture_assert_goto(tctx, truenas_sc_take(zds, snaps[0]) &&
				    truenas_sc_take(zds, snaps[1]),
				    ret, done, "snapshots");
		torture_assert_goto(tctx,
				    truenas_sc_label(tctx, zds, snaps[0],
						     label1) &&
				    truenas_sc_label(tctx, zds, snaps[1],
						     label2),
				    ret, done, "labels of the snapshots");
		if (strcmp(label1, label2) == 0) {
			same = true;
			break;
		}
		torture_comment(tctx, "snapshots fell in two seconds, again\n");
		sleep(1);
	}
	torture_assert_goto(tctx, same, ret, done,
			    "two snapshots in one second");

	/* the share root is a directory, which every snapshot lists */
	torture_assert_goto(tctx, truenas_sc_enum(tctx, tree, "", &labels, &n),
			    ret, done, "enumerate");
	for (i = 0, count = 0; i < n; i++) {
		if (strcmp(labels[i], label1) == 0) {
			count++;
		}
	}
	torture_assert_int_equal_goto(tctx, count, 1, ret, done,
				      "label of the second listed once");

done:
	for (k = 0; k < ARRAY_SIZE(snaps); k++) {
		truenas_sc_destroy(zds, snaps[k]);
	}
	return ret;
}

/*
 * Snapshot snap of the datasets a and b in one second, so that one timewarp
 * names both. Up to three tries: a slow sync can push b into the next one.
 */
static bool truenas_sc_take_pair(struct torture_context *tctx,
				 const struct zfs_dataset *a,
				 const struct zfs_dataset *b,
				 const char *snap,
				 NTTIME *ptwrp)
{
	char label[TN_GMT_LEN + 1];
	NTTIME ta, tb;
	int attempt;

	for (attempt = 0; attempt < 3; attempt++) {
		time_t t = time(NULL);

		truenas_sc_destroy(a, snap);
		truenas_sc_destroy(b, snap);
		while (time(NULL) == t) {
			usleep(10000);
		}
		if (!truenas_sc_take(a, snap) || !truenas_sc_take(b, snap) ||
		    !truenas_sc_find(tctx, a, snap, label, &ta) ||
		    !truenas_sc_find(tctx, b, snap, label, &tb)) {
			break;
		}
		if (ta == tb) {
			*ptwrp = ta;
			return true;
		}
		torture_comment(tctx, "snapshots fell in two seconds, again\n");
	}
	truenas_sc_destroy(a, snap);
	truenas_sc_destroy(b, snap);
	return false;
}

/* Write data to the local file path, as root on the server. */
static bool truenas_sc_local_write(const char *path, const char *data)
{
	size_t len = strlen(data);
	int fd;
	bool ok;

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd == -1) {
		return false;
	}
	ok = (write(fd, data, len) == (ssize_t)len);
	close(fd);
	return ok;
}

/* Open fname at twrp and require its content to be expect. */
static bool truenas_sc_expect_at(struct torture_context *tctx,
				 struct smb2_tree *tree,
				 const char *fname,
				 NTTIME twrp,
				 const char *expect)
{
	struct smb2_handle h = {{0}};
	struct smb2_read rd;
	size_t elen = strlen(expect);
	NTSTATUS status;
	bool ret = true;

	status = truenas_sc_open_at(tree, tctx, fname, twrp, &h);
	torture_assert_ntstatus_ok(tctx, status,
				   talloc_asprintf(tctx, "open %s at its "
						   "snapshot", fname));
	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = elen + 16;
	status = smb2_read(tree, tctx, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	torture_assert_int_equal_goto(tctx, rd.out.data.length, elen, ret, done,
				      "length of the version");
	torture_assert_mem_equal_goto(tctx, rd.out.data.data, expect, elen,
				      ret, done, "content of the version");
done:
	smb2_util_close(tree, h);
	return ret;
}

/* Open the directory dname at twrp, for a listing. */
static NTSTATUS truenas_sc_open_dir_at(struct smb2_tree *tree,
				       TALLOC_CTX *mem_ctx,
				       const char *dname,
				       NTTIME twrp,
				       struct smb2_handle *h)
{
	struct smb2_create cr;
	NTSTATUS status;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_DIR_LIST | SEC_DIR_READ_ATTRIBUTE;
	cr.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	cr.in.fname = dname;
	cr.in.timewarp = twrp;
	status = smb2_create(tree, mem_ctx, &cr);
	if (NT_STATUS_IS_OK(status)) {
		*h = cr.out.file.handle;
	}
	return status;
}

/* The names one FIND of the open directory h returns. */
static bool truenas_sc_dir_names(struct torture_context *tctx,
				 struct smb2_tree *tree,
				 struct smb2_handle h,
				 char ***pnames,
				 uint32_t *pn)
{
	struct smb2_find f;
	union smb_search_data *d = NULL;
	unsigned int count, i;
	char **names = NULL;
	uint32_t n = 0;
	NTSTATUS status;

	*pnames = NULL;
	*pn = 0;
	ZERO_STRUCT(f);
	f.in.file.handle = h;
	f.in.pattern = "*";
	f.in.max_response_size = 0x10000;
	f.in.level = SMB2_FIND_BOTH_DIRECTORY_INFO;
	do {
		status = smb2_find_level(tree, tctx, &f, &count, &d);
		if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
			break;
		}
		torture_assert_ntstatus_ok(tctx, status,
					   "find in snapshot directory");
		names = talloc_realloc(tctx, names, char *, n + count);
		torture_assert(tctx, names != NULL, "talloc");
		for (i = 0; i < count; i++) {
			names[n] = talloc_strdup(
				names, d[i].both_directory_info.name.s);
			torture_assert(tctx, names[n] != NULL, "talloc");
			n++;
		}
	} while (count > 0);
	*pnames = names;
	*pn = n;
	return true;
}

/* Whether the directory dname at twrp lists name. */
static bool truenas_sc_lists(struct torture_context *tctx,
			     struct smb2_tree *tree,
			     const char *dname,
			     NTTIME twrp,
			     const char *name,
			     bool *plisted)
{
	struct smb2_handle h = {{0}};
	char **names = NULL;
	uint32_t n;
	NTSTATUS status;
	bool ret;

	*plisted = false;
	status = truenas_sc_open_dir_at(tree, tctx, dname, twrp, &h);
	torture_assert_ntstatus_ok(tctx, status, "open directory at snapshot");
	ret = truenas_sc_dir_names(tctx, tree, h, &names, &n);
	smb2_util_close(tree, h);
	if (ret) {
		*plisted = truenas_sc_has_label(names, n, name);
	}
	return ret;
}

/*
 * With shadow:no_dataset_traversal a child dataset is refused live
 * (RESOLVE_NO_XDEV), and so in snapshots: a file in a snapshot of the
 * child dataset torture:sc_child opens on a share without the option
 * and not on one with it (torture:sc_noxdev). A file in a snapshot of
 * the share dataset opens on both.
 *
 * In the snapshot of the share dataset the mountpoint of the child is an
 * empty directory. Listed at that time, the share root shows it as the
 * root of the child's own snapshot of the same time, or not at all with
 * the option, as live.
 */
static bool test_truenas_shadow_copy_child_dataset(struct torture_context *tctx,
						   struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const struct zfs_dataset *czds = NULL;
	const char *mp = torture_setting_string(tctx, "sc_mp", NULL);
	const char *child = torture_setting_string(tctx, "sc_child", NULL);
	bool noxdev = torture_setting_bool(tctx, "sc_noxdev", false);
	const char *snap = "tn_sc_child";
	const char *fname = "tn_sc_childfile";
	char *cmp = NULL;
	char *ppath = NULL;
	char *cpath = NULL;
	char *cname = NULL;
	struct smb2_handle h = {{0}};
	NTTIME twrp;
	NTSTATUS status;
	bool ptaken = false, ctaken = false;
	bool listed;
	int fd;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	if (child == NULL) {
		torture_skip(tctx, "no torture:sc_child (child dataset of the "
			     "share root)");
	}

	cmp = talloc_asprintf(tctx, "%s/%s", mp, child);
	ppath = talloc_asprintf(tctx, "%s/%s", mp, fname);
	cpath = talloc_asprintf(tctx, "%s/%s", cmp, fname);
	cname = talloc_asprintf(tctx, "%s\\%s", child, fname);
	torture_assert(tctx, (cmp != NULL) && (ppath != NULL) &&
		       (cpath != NULL) && (cname != NULL), "talloc");
	torture_assert_int_equal(tctx, conn_zfs_init(cmp, &czds), 0,
				 "conn_zfs_init of the child");
	torture_assert(tctx, (czds != NULL) && (czds->mnt_id != zds->mnt_id),
		       "sc_child is a dataset of its own");
	truenas_sc_destroy(zds, snap);
	truenas_sc_destroy(czds, snap);

	/* the live child is not reachable on a noxdev share: write locally */
	fd = open(ppath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	torture_assert_goto(tctx, fd != -1, ret, done, "create parent file");
	close(fd);
	fd = open(cpath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	torture_assert_goto(tctx, fd != -1, ret, done, "create child file");
	close(fd);

	ptaken = ctaken = true;
	torture_assert_goto(tctx,
			    truenas_sc_take_pair(tctx, zds, czds, snap, &twrp),
			    ret, done, "snapshots in one second");

	status = truenas_sc_open_at(tree, tctx, fname, twrp, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open in the share dataset snapshot");
	smb2_util_close(tree, h);

	status = truenas_sc_open_at(tree, tctx, cname, twrp, &h);
	torture_comment(tctx, "open %s in the child snapshot (noxdev %d): "
			"%s\n", cname, noxdev, nt_errstr(status));
	if (NT_STATUS_IS_OK(status)) {
		smb2_util_close(tree, h);
	}
	if (noxdev) {
		torture_assert_goto(tctx, !NT_STATUS_IS_OK(status), ret, done,
				    "child dataset opened in a snapshot "
				    "with no_dataset_traversal");
	} else {
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open in the child snapshot");
	}

	torture_assert_goto(tctx,
			    truenas_sc_lists(tctx, tree, "", twrp, child,
					     &listed),
			    ret, done, "list the share root in the snapshot");
	torture_comment(tctx, "%s in the listing (noxdev %d): %d\n", child,
			noxdev, listed);
	if (noxdev) {
		torture_assert_goto(tctx, !listed, ret, done,
				    "child dataset listed with "
				    "no_dataset_traversal");
	} else {
		torture_assert_goto(tctx, listed, ret, done,
				    "child dataset not listed as the root of "
				    "its snapshot");
		/*
		 * In its own snapshot, ".." of the root of the child is the
		 * directory above it as it was at that time: in the
		 * snapshot of the share dataset, not in the snapshot
		 * directory the mount sits in.
		 */
		torture_assert_goto(tctx,
				    truenas_sc_lists(tctx, tree, child, twrp,
						     "..", &listed),
				    ret, done,
				    "list the root of the child in its "
				    "snapshot");
		torture_assert_goto(tctx, listed, ret, done,
				    "\"..\" of the root of the child dataset");
	}

done:
	if (ctaken) {
		truenas_sc_destroy(czds, snap);
	}
	if (ptaken) {
		truenas_sc_destroy(zds, snap);
	}
	unlink(cpath);
	unlink(ppath);
	return ret;
}

/*
 * A share rooted in a directory of its dataset, as /pool/ds/share of the
 * dataset /pool/ds, maps a timewarp to that directory in the snapshot of
 * the dataset, and nothing leads above it: not "..", not a symlink inside
 * the snapshot to a sibling of the share in the same snapshot. A dataset
 * mounted below the share root still has its own snapshots.
 *
 * Run on a share whose root is torture:sc_subdir below torture:sc_mp,
 * with a child dataset mounted at <share root>/inner and the directory
 * <sc_mp>/sc_outside next to the share root.
 */
static bool test_truenas_shadow_copy_subdir_share(struct torture_context *tctx,
						  struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const struct zfs_dataset *izds = NULL;
	const char *mp = torture_setting_string(tctx, "sc_mp", NULL);
	const char *sub = torture_setting_string(tctx, "sc_subdir", NULL);
	const char *snap = "tn_sc_sub";
	char *root = NULL, *inner = NULL, *outside = NULL;
	char *subfile = NULL, *innerfile = NULL, *secret = NULL, *up = NULL;
	char label[TN_GMT_LEN + 1];
	struct smb2_handle h = {{0}};
	NTTIME twrp, itwrp;
	NTSTATUS status;
	bool listed;
	bool taken = false;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	if (sub == NULL) {
		torture_skip(tctx, "no torture:sc_subdir (share root below "
			     "sc_mp)");
	}

	root = talloc_asprintf(tctx, "%s/%s", mp, sub);
	inner = talloc_asprintf(tctx, "%s/inner", root);
	outside = talloc_asprintf(tctx, "%s/sc_outside", mp);
	subfile = talloc_asprintf(tctx, "%s/tn_sc_subfile", root);
	innerfile = talloc_asprintf(tctx, "%s/tn_sc_innerfile", inner);
	secret = talloc_asprintf(tctx, "%s/secret", outside);
	up = talloc_asprintf(tctx, "%s/tn_sc_up", root);
	torture_assert(tctx, (up != NULL) && (secret != NULL) &&
		       (innerfile != NULL) && (subfile != NULL), "talloc");
	torture_assert_int_equal(tctx, conn_zfs_init(inner, &izds), 0,
				 "conn_zfs_init of the inner dataset");
	torture_assert(tctx, (izds != NULL) && (izds->mnt_id != zds->mnt_id),
		       "inner is a dataset of its own");
	truenas_sc_destroy(izds, snap);
	truenas_sc_destroy(zds, snap);

	mkdir(outside, 0755);
	unlink(up);
	torture_assert_goto(tctx,
			    truenas_sc_local_write(subfile, "sub-version") &&
			    truenas_sc_local_write(innerfile, "inner-version") &&
			    truenas_sc_local_write(secret, "secret") &&
			    (symlink("../sc_outside", up) == 0),
			    ret, done, "files");

	taken = true;
	torture_assert_goto(tctx, truenas_sc_take(zds, snap) &&
			    truenas_sc_take(izds, snap),
			    ret, done, "snapshots");
	torture_assert_goto(tctx,
			    truenas_sc_find(tctx, zds, snap, label, &twrp) &&
			    truenas_sc_find(tctx, izds, snap, label, &itwrp),
			    ret, done, "timewarps of the snapshots");
	torture_assert_goto(tctx,
			    truenas_sc_local_write(subfile, "live") &&
			    truenas_sc_local_write(innerfile, "live"),
			    ret, done, "live versions");

	/* the share root in the snapshot is the directory of the share */
	torture_assert_goto(tctx,
			    truenas_sc_expect_at(tctx, tree, "tn_sc_subfile",
						 twrp, "sub-version"),
			    ret, done, "file of the share in the snapshot");
	torture_assert_goto(tctx,
			    truenas_sc_lists(tctx, tree, "", twrp,
					     "tn_sc_subfile", &listed) &&
			    listed,
			    ret, done, "share root lists its file");
	torture_assert_goto(tctx,
			    truenas_sc_lists(tctx, tree, "", twrp,
					     "sc_outside", &listed) &&
			    !listed,
			    ret, done, "share root is not the dataset root");

	/* nothing above the share root */
	status = truenas_sc_open_at(tree, tctx, "tn_sc_up\\secret", twrp, &h);
	torture_comment(tctx, "open through a symlink to a sibling: %s\n",
			nt_errstr(status));
	if (NT_STATUS_IS_OK(status)) {
		smb2_util_close(tree, h);
	}
	torture_assert_goto(tctx, !NT_STATUS_IS_OK(status), ret, done,
			    "symlink in the snapshot led above the share");
	status = truenas_sc_open_at(tree, tctx, "..\\sc_outside\\secret", twrp,
				    &h);
	torture_comment(tctx, "open of ..\\sc_outside: %s\n",
			nt_errstr(status));
	if (NT_STATUS_IS_OK(status)) {
		smb2_util_close(tree, h);
	}
	torture_assert_goto(tctx, !NT_STATUS_IS_OK(status), ret, done,
			    ".. led above the share");

	/* the nested dataset, in its own snapshot */
	torture_assert_goto(tctx,
			    truenas_sc_expect_at(tctx, tree,
						 "inner\\tn_sc_innerfile",
						 itwrp, "inner-version"),
			    ret, done, "file of the nested dataset");

done:
	if (taken) {
		truenas_sc_destroy(izds, snap);
		truenas_sc_destroy(zds, snap);
	}
	unlink(up);
	unlink(subfile);
	unlink(innerfile);
	unlink(secret);
	rmdir(outside);
	return ret;
}

/*
 * The path of a dataset mounted below a plain directory goes stale when a
 * user renames that directory. A symlink put in its place must not lead
 * the server into the snapshots by the old path, though it ends at the
 * same dataset: snapshots are reached only through the snapshot directory
 * of the mount itself. Uses the dataset mounted at <sc_mp>/<sc_nest>,
 * whose parent directory is not a mountpoint.
 *
 * The share dataset is snapshotted in the same second, so that the parent
 * directory exists at the timewarp too: smbd then walks the name one
 * component at a time after the first refusal, and each component must
 * be refused on its own.
 */
static bool test_truenas_shadow_copy_stale_mountpoint(
	struct torture_context *tctx,
	struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const struct zfs_dataset *nzds = NULL;
	const char *mp = torture_setting_string(tctx, "sc_mp", NULL);
	const char *nest = torture_setting_string(tctx, "sc_nest", NULL);
	const char *snap = "tn_sc_stale";
	char *nmp = NULL, *dir = NULL, *moved = NULL, *file = NULL;
	char *fname = NULL;
	char *slash = NULL;
	struct smb2_handle h = {{0}};
	NTTIME twrp;
	NTSTATUS status;
	bool taken = false, renamed = false, linked = false;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	if (nest == NULL) {
		torture_skip(tctx, "no torture:sc_nest (dataset below a plain "
			     "directory of the share)");
	}

	nmp = talloc_asprintf(tctx, "%s/%s", mp, nest);
	dir = talloc_strdup(tctx, nmp);
	torture_assert(tctx, (nmp != NULL) && (dir != NULL), "talloc");
	slash = strrchr(dir, '/');
	torture_assert(tctx, slash != NULL, "parent of sc_nest");
	*slash = '\0';
	moved = talloc_asprintf(tctx, "%s_moved", dir);
	file = talloc_asprintf(tctx, "%s/tn_sc_stalefile", nmp);
	fname = talloc_asprintf(tctx, "%s\\tn_sc_stalefile", nest);
	torture_assert(tctx, (moved != NULL) && (file != NULL) &&
		       (fname != NULL), "talloc");
	all_string_sub(fname, "/", "\\", 0);

	torture_assert_int_equal(tctx, conn_zfs_init(nmp, &nzds), 0,
				 "conn_zfs_init of the nested dataset");
	torture_assert(tctx, nzds != NULL, "nested dataset");
	torture_assert(tctx, truenas_sc_local_write(file, "stale-version"),
		       "file");
	taken = true;
	torture_assert_goto(tctx, truenas_sc_take_pair(tctx, zds, nzds, snap,
						       &twrp),
			    ret, done, "snapshots in one second");

	/* this also has the server resolve the dataset and keep its path */
	torture_assert_goto(tctx,
			    truenas_sc_expect_at(tctx, tree, fname, twrp,
						 "stale-version"),
			    ret, done, "file in the snapshot before the rename");

	torture_assert_goto(tctx, rename(dir, moved) == 0, ret, done,
			    "rename the directory above the dataset");
	renamed = true;
	torture_assert_goto(tctx, symlink(moved, dir) == 0, ret, done,
			    "symlink in its place");
	linked = true;

	status = truenas_sc_open_at(tree, tctx, fname, twrp, &h);
	torture_comment(tctx, "open by the stale path: %s\n",
			nt_errstr(status));
	if (NT_STATUS_IS_OK(status)) {
		smb2_util_close(tree, h);
	}
	torture_assert_goto(tctx, !NT_STATUS_IS_OK(status), ret, done,
			    "snapshot reached through a symlink in the path "
			    "of the dataset");

	/* with the directory back, the path is good again */
	torture_assert_goto(tctx, unlink(dir) == 0, ret, done, "unlink");
	linked = false;
	torture_assert_goto(tctx, rename(moved, dir) == 0, ret, done,
			    "rename back");
	renamed = false;
	torture_assert_goto(tctx,
			    truenas_sc_expect_at(tctx, tree, fname, twrp,
						 "stale-version"),
			    ret, done, "file in the snapshot after the rename "
			    "back");

done:
	if (linked) {
		unlink(dir);
	}
	if (renamed && (rename(moved, dir) != 0)) {
		torture_comment(tctx, "rename %s back failed: %s\n", moved,
				strerror(errno));
		ret = false;
	}
	if (taken) {
		truenas_sc_destroy(nzds, snap);
		truenas_sc_destroy(zds, snap);
	}
	unlink(file);
	return ret;
}

/* FSCTL_SRV_ENUM_SNAPS on h for the count only: its status, and *pn. */
static NTSTATUS truenas_sc_enum_status(struct smb2_tree *tree,
				       TALLOC_CTX *mem_ctx,
				       struct smb2_handle h,
				       uint32_t *pn)
{
	union smb_ioctl io;
	NTSTATUS status;

	*pn = 0;
	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = h;
	io.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	io.smb2.in.max_output_response = 16;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, mem_ctx, &io.smb2);
	if (NT_STATUS_IS_OK(status) && (io.smb2.out.out.length >= 12)) {
		*pn = IVAL(io.smb2.out.out.data, 0);
	}
	return status;
}

/*
 * The versions of an open file are found through the snapshot directory
 * of its dataset, by the path the dataset had when the server resolved
 * it. With the directory above the dataset renamed, and ordinary
 * directories named .zfs/snapshot/<snap> with a file in them put at that
 * path, the enumeration must not offer that file as a version: it fails,
 * and the client is told the name does not exist. The enumeration before
 * the rename has the server resolve the dataset, and is the control.
 */
static bool test_truenas_shadow_copy_stale_enum(struct torture_context *tctx,
						struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const struct zfs_dataset *nzds = NULL;
	const char *mp = torture_setting_string(tctx, "sc_mp", NULL);
	const char *nest = torture_setting_string(tctx, "sc_nest", NULL);
	const char *snap = "tn_sc_senum";
	const char *leaf = "tn_sc_senumfile";
	char *nmp = NULL, *dir = NULL, *moved = NULL, *file = NULL;
	char *fname = NULL, *fakefile = NULL;
	char *fake[5] = { NULL };
	char *slash = NULL;
	struct smb2_create cr;
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	uint32_t n;
	size_t i, nfake = 0;
	bool opened = false, taken = false, renamed = false;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	if (nest == NULL) {
		torture_skip(tctx, "no torture:sc_nest (dataset below a plain "
			     "directory of the share)");
	}

	nmp = talloc_asprintf(tctx, "%s/%s", mp, nest);
	dir = talloc_strdup(tctx, nmp);
	torture_assert(tctx, (nmp != NULL) && (dir != NULL), "talloc");
	slash = strrchr(dir, '/');
	torture_assert(tctx, slash != NULL, "parent of sc_nest");
	*slash = '\0';
	moved = talloc_asprintf(tctx, "%s_moved", dir);
	file = talloc_asprintf(tctx, "%s/%s", nmp, leaf);
	fname = talloc_asprintf(tctx, "%s\\%s", nest, leaf);
	fake[0] = dir;
	fake[1] = nmp;
	fake[2] = talloc_asprintf(tctx, "%s/.zfs", nmp);
	fake[3] = talloc_asprintf(tctx, "%s/.zfs/snapshot", nmp);
	fake[4] = talloc_asprintf(tctx, "%s/.zfs/snapshot/%s", nmp, snap);
	fakefile = talloc_asprintf(tctx, "%s/%s", fake[4], leaf);
	torture_assert(tctx, (moved != NULL) && (file != NULL) &&
		       (fname != NULL) && (fake[2] != NULL) &&
		       (fake[3] != NULL) && (fake[4] != NULL) &&
		       (fakefile != NULL), "talloc");
	all_string_sub(fname, "/", "\\", 0);

	torture_assert_int_equal(tctx, conn_zfs_init(nmp, &nzds), 0,
				 "conn_zfs_init of the nested dataset");
	torture_assert(tctx, nzds != NULL, "nested dataset");
	truenas_sc_destroy(nzds, snap);

	/* a version in the snapshot: the file changes after it */
	torture_assert(tctx, truenas_sc_local_write(file, "version"), "file");
	torture_assert_goto(tctx, truenas_sc_take(nzds, snap), ret, done,
			    "snapshot");
	taken = true;
	torture_assert_goto(tctx, truenas_sc_local_write(file, "live"), ret,
			    done, "live version");

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_READ_ATTRIBUTE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open the live file");
	h = cr.out.file.handle;
	opened = true;

	status = truenas_sc_enum_status(tree, tctx, h, &n);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"enumerate before the rename");
	torture_assert_goto(tctx, n >= 1, ret, done,
			    "the snapshot is a version before the rename");

	torture_assert_goto(tctx, rename(dir, moved) == 0, ret, done,
			    "rename the directory above the dataset");
	renamed = true;
	for (i = 0; i < ARRAY_SIZE(fake); i++) {
		torture_assert_goto(tctx, mkdir(fake[i], 0755) == 0, ret, done,
				    "fake snapshot directory");
		nfake = i + 1;
	}
	torture_assert_goto(tctx, truenas_sc_local_write(fakefile, "fake"),
			    ret, done, "fake version");

	status = truenas_sc_enum_status(tree, tctx, h, &n);
	torture_comment(tctx, "enumerate by the stale path: %s, %u\n",
			nt_errstr(status), n);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "fake snapshot directory refused");

done:
	if (opened) {
		smb2_util_close(tree, h);
	}
	unlink(fakefile);
	for (i = nfake; i > 0; i--) {
		rmdir(fake[i - 1]);
	}
	if (renamed && (rename(moved, dir) != 0)) {
		torture_comment(tctx, "rename %s back failed: %s\n", moved,
				strerror(errno));
		ret = false;
	}
	if (taken) {
		truenas_sc_destroy(nzds, snap);
	}
	unlink(file);
	return ret;
}

/*
 * A directory open in a snapshot lists its entries from its own fd, and
 * the listing holds up when the path of its dataset goes stale: with the
 * directory above the dataset renamed, and ordinary directories of the
 * same names put at the old path, a subdirectory in the snapshot is still
 * listed from the snapshot, not mistaken for the root of another dataset
 * because the live path of its name now leads elsewhere. The handle is
 * opened before the rename, as a client's would be.
 */
static bool test_truenas_shadow_copy_stale_listing(struct torture_context *tctx,
						   struct smb2_tree *tree)
{
	bool ret = true;
	const struct zfs_dataset *zds = NULL;
	const struct zfs_dataset *nzds = NULL;
	const char *mp = torture_setting_string(tctx, "sc_mp", NULL);
	const char *nest = torture_setting_string(tctx, "sc_nest", NULL);
	const char *snap = "tn_sc_slist";
	const char *subname = "tn_sc_slsub";
	char *nmp = NULL, *dir = NULL, *moved = NULL;
	char *sub = NULL, *subd = NULL, *subf = NULL, *dname = NULL;
	char *fake[4] = { NULL };
	char *slash = NULL;
	char **names = NULL;
	char label[TN_GMT_LEN + 1];
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	NTTIME twrp;
	uint32_t n;
	size_t i, nfake = 0;
	bool opened = false, taken = false, renamed = false;

	if (!truenas_sc_cache_setup(tctx, tree, &zds)) {
		return false;
	}
	if (zds == NULL) {
		return true;
	}
	if (nest == NULL) {
		torture_skip(tctx, "no torture:sc_nest (dataset below a plain "
			     "directory of the share)");
	}

	nmp = talloc_asprintf(tctx, "%s/%s", mp, nest);
	dir = talloc_strdup(tctx, nmp);
	torture_assert(tctx, (nmp != NULL) && (dir != NULL), "talloc");
	slash = strrchr(dir, '/');
	torture_assert(tctx, slash != NULL, "parent of sc_nest");
	*slash = '\0';
	moved = talloc_asprintf(tctx, "%s_moved", dir);
	sub = talloc_asprintf(tctx, "%s/%s", nmp, subname);
	subd = talloc_asprintf(tctx, "%s/d", sub);
	subf = talloc_asprintf(tctx, "%s/f", sub);
	dname = talloc_asprintf(tctx, "%s\\%s", nest, subname);
	torture_assert(tctx, (moved != NULL) && (sub != NULL) &&
		       (subd != NULL) && (subf != NULL) && (dname != NULL),
		       "talloc");
	all_string_sub(dname, "/", "\\", 0);
	fake[0] = dir;
	fake[1] = nmp;
	fake[2] = sub;
	fake[3] = subd;

	torture_assert_int_equal(tctx, conn_zfs_init(nmp, &nzds), 0,
				 "conn_zfs_init of the nested dataset");
	torture_assert(tctx, nzds != NULL, "nested dataset");
	truenas_sc_destroy(nzds, snap);

	torture_assert(tctx, (mkdir(sub, 0755) == 0) || (errno == EEXIST),
		       "subdirectory");
	torture_assert(tctx, (mkdir(subd, 0755) == 0) || (errno == EEXIST),
		       "directory in it");
	torture_assert(tctx, truenas_sc_local_write(subf, "version"),
		       "file in it");
	torture_assert_goto(tctx, truenas_sc_take(nzds, snap), ret, done,
			    "snapshot");
	taken = true;
	torture_assert_goto(tctx, truenas_sc_find(tctx, nzds, snap, label,
						  &twrp),
			    ret, done, "timewarp of the snapshot");

	status = truenas_sc_open_dir_at(tree, tctx, dname, twrp, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open the directory in the snapshot");
	opened = true;

	torture_assert_goto(tctx, rename(dir, moved) == 0, ret, done,
			    "rename the directory above the dataset");
	renamed = true;
	for (i = 0; i < ARRAY_SIZE(fake); i++) {
		torture_assert_goto(tctx, mkdir(fake[i], 0755) == 0, ret, done,
				    "directory at the stale path");
		nfake = i + 1;
	}

	torture_assert_goto(tctx, truenas_sc_dir_names(tctx, tree, h, &names,
						       &n),
			    ret, done, "list the open directory");
	for (i = 0; i < n; i++) {
		torture_comment(tctx, "listed: %s\n", names[i]);
	}
	torture_assert_goto(tctx, truenas_sc_has_label(names, n, "f"), ret,
			    done, "file in the snapshot listed");
	torture_assert_goto(tctx, truenas_sc_has_label(names, n, "d"), ret,
			    done, "directory in the snapshot listed");

done:
	if (opened) {
		smb2_util_close(tree, h);
	}
	for (i = nfake; i > 0; i--) {
		rmdir(fake[i - 1]);
	}
	if (renamed && (rename(moved, dir) != 0)) {
		torture_comment(tctx, "rename %s back failed: %s\n", moved,
				strerror(errno));
		ret = false;
	}
	if (taken) {
		truenas_sc_destroy(nzds, snap);
	}
	unlink(subf);
	rmdir(subd);
	rmdir(sub);
	return ret;
}

#endif /* HAVE_LIBZFS */

NTSTATUS torture_truenas_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "truenas");
	struct torture_suite *rename_suite =
		torture_suite_create(suite, "rename");
	struct torture_suite *streams_suite =
		torture_suite_create(suite, "streams");
	struct torture_suite *sc_suite =
		torture_suite_create(suite, "shadow_copy");
	struct torture_suite *fruit_suite =
		torture_suite_create(suite, "fruit");

	torture_suite_add_1smb2_test(rename_suite, "case_insensitive",
				     test_truenas_rename_case_insensitive);
	torture_suite_add_1smb2_test(streams_suite, "cap_and_offset",
				     test_truenas_streams_cap_and_offset);
	torture_suite_add_1smb2_test(streams_suite, "sizes",
				     test_truenas_streams_sizes);
	torture_suite_add_1smb2_test(streams_suite, "rename",
				     test_truenas_streams_rename);
	torture_suite_add_2smb2_test(streams_suite, "delete_open_stream",
				     test_truenas_streams_delete_open_stream);
	torture_suite_add_1smb2_test(fruit_suite, "readdir_rfork_size",
				     test_truenas_fruit_readdir_rfork_size);
	torture_suite_add_1smb2_test(fruit_suite, "readdir_attr_v1",
				     test_truenas_fruit_readdir_attr_v1);
	torture_suite_add_1smb2_test(fruit_suite, "readdir_attr_v2",
				     test_truenas_fruit_readdir_attr_v2);
	torture_suite_add_1smb2_test(sc_suite, "browse",
				     test_truenas_shadow_copy_browse);
	torture_suite_add_1smb2_test(sc_suite, "readonly",
				     test_truenas_shadow_copy_readonly);
	torture_suite_add_1smb2_test(sc_suite, "listdir",
				     test_truenas_shadow_copy_listdir);
#ifdef HAVE_LIBZFS
	torture_suite_add_1smb2_test(sc_suite, "cache_change",
				     test_truenas_shadow_copy_cache_change);
	torture_suite_add_1smb2_test(sc_suite, "same_version",
				     test_truenas_shadow_copy_same_version);
	torture_suite_add_1smb2_test(sc_suite, "symlink",
				     test_truenas_shadow_copy_symlink);
	torture_suite_add_1smb2_test(sc_suite, "ctldir_name",
				     test_truenas_shadow_copy_ctldir_name);
	torture_suite_add_1smb2_test(sc_suite, "pins",
				     test_truenas_shadow_copy_pins);
	torture_suite_add_1smb2_test(sc_suite, "child_dataset",
				     test_truenas_shadow_copy_child_dataset);
	torture_suite_add_1smb2_test(sc_suite, "same_second",
				     test_truenas_shadow_copy_same_second);
	torture_suite_add_1smb2_test(sc_suite, "subdir_share",
				     test_truenas_shadow_copy_subdir_share);
	torture_suite_add_1smb2_test(sc_suite, "stale_mountpoint",
				     test_truenas_shadow_copy_stale_mountpoint);
	torture_suite_add_1smb2_test(sc_suite, "stale_enum",
				     test_truenas_shadow_copy_stale_enum);
	torture_suite_add_1smb2_test(sc_suite, "stale_listing",
				     test_truenas_shadow_copy_stale_listing);
#endif

	torture_suite_add_suite(suite, rename_suite);
	torture_suite_add_suite(suite, streams_suite);
	torture_suite_add_suite(suite, fruit_suite);
	torture_suite_add_suite(suite, sc_suite);

	/* ACL <-> Security-Descriptor mapping subtests (truenas_acl.c) */
	torture_truenas_acl_suite(suite);

	/* SMB auditing subtests (truenas_audit.c) */
	torture_truenas_audit_suite(suite);

	/* smbd metadata cache subtests (truenas_mdcache.c) */
	torture_truenas_mdcache_suite(suite);

	/* kernel dosmodes subtests (truenas_dosmode.c) */
	torture_truenas_dosmode_suite(suite);

	/* vfs_worm subtests (truenas_worm.c) */
	torture_truenas_worm_suite(suite);

	/* durable handle subtests (truenas_durable.c) */
	torture_truenas_durable_suite(suite);

	suite->description = talloc_strdup(suite,
		"TrueNAS VFS stack tests (zfs_core, truenas_streams_xattr, "
		"shadow_copy_zfs, ixnas, truenas_audit)");

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
