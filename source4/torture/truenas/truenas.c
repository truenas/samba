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
#include "libcli/security/security.h"

#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smbtorture.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"

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
			       const char *new_name)
{
	union smb_setfileinfo sinfo;

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = handle;
	sinfo.rename_information.in.overwrite = 0;
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
	status = truenas_rename(tree, h, "To_rename");
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
	status = truenas_rename(tree, h, "to_rename");
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

NTSTATUS torture_truenas_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "truenas");
	struct torture_suite *rename_suite =
		torture_suite_create(suite, "rename");
	struct torture_suite *streams_suite =
		torture_suite_create(suite, "streams");
	struct torture_suite *sc_suite =
		torture_suite_create(suite, "shadow_copy");

	torture_suite_add_1smb2_test(rename_suite, "case_insensitive",
				     test_truenas_rename_case_insensitive);
	torture_suite_add_1smb2_test(streams_suite, "cap_and_offset",
				     test_truenas_streams_cap_and_offset);
	torture_suite_add_1smb2_test(sc_suite, "browse",
				     test_truenas_shadow_copy_browse);
	torture_suite_add_1smb2_test(sc_suite, "readonly",
				     test_truenas_shadow_copy_readonly);
	torture_suite_add_1smb2_test(sc_suite, "listdir",
				     test_truenas_shadow_copy_listdir);

	torture_suite_add_suite(suite, rename_suite);
	torture_suite_add_suite(suite, streams_suite);
	torture_suite_add_suite(suite, sc_suite);

	/* ACL <-> Security-Descriptor mapping subtests (truenas_acl.c) */
	torture_truenas_acl_suite(suite);

	suite->description = talloc_strdup(suite,
		"TrueNAS VFS stack tests (zfs_core, truenas_streams_xattr, "
		"shadow_copy_zfs, ixnas)");

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
