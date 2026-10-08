/*
   Unix SMB/CIFS implementation.

   TrueNAS smbd metadata cache (truenas_mdcache) torture tests.

   These use FSCTL_SMBTORTURE_MDCACHE to shorten the cache's idle timeout
   and read its size, so smbd needs "smbd:FSCTL_SMBTORTURE = yes". They
   self-skip on shares where nothing fills the cache (no ixnas, or a kernel
   without STATX_CHANGE_COOKIE).

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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"

#define MDC_DIR		"truenas_mdcache"
#define MDC_FILES	50
#define MDC_IDLE	2	/* seconds */

/* Set the idle timeout unless it is 0, and get the table size and entries */
static NTSTATUS mdc_fsctl(struct torture_context *tctx,
			  struct smb2_tree *tree,
			  struct smb2_handle h,
			  uint32_t idle_timeout,
			  uint32_t *slots,
			  uint32_t *count)
{
	struct smb2_ioctl ioctl;
	uint8_t buf[4];
	NTSTATUS status;

	ZERO_STRUCT(ioctl);
	ioctl.in.file.handle = h;
	ioctl.in.function = FSCTL_SMBTORTURE_MDCACHE;
	ioctl.in.max_output_response = 8;
	ioctl.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	if (idle_timeout != 0) {
		SIVAL(buf, 0, idle_timeout);
		ioctl.in.out = data_blob_const(buf, sizeof(buf));
	}

	status = smb2_ioctl(tree, tctx, &ioctl);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (ioctl.out.out.length != 8) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	*slots = IVAL(ioctl.out.out.data, 0);
	*count = IVAL(ioctl.out.out.data, 4);
	return NT_STATUS_OK;
}

/* List MDC_DIR and check it has every test file, with f0 hidden */
static bool mdc_list(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_find f;
	union smb_search_data *d = NULL;
	unsigned int count, i, nfiles = 0;
	bool hidden = false;
	NTSTATUS status;
	bool ret = true;

	status = torture_smb2_testdir(tree, MDC_DIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "open directory");

	ZERO_STRUCT(f);
	f.in.file.handle	= h;
	f.in.pattern		= "f*";
	f.in.max_response_size	= 0x10000;
	f.in.level		= SMB2_FIND_BOTH_DIRECTORY_INFO;

	do {
		status = smb2_find_level(tree, tctx, &f, &count, &d);
		if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
			break;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_find_level");

		for (i = 0; i < count; i++) {
			const char *name = d[i].both_directory_info.name.s;

			nfiles++;
			if (strcmp(name, "f0") == 0) {
				hidden = (d[i].both_directory_info.attrib &
					  FILE_ATTRIBUTE_HIDDEN) != 0;
			}
		}
	} while (count > 0);

	torture_assert_int_equal_goto(tctx, nfiles, MDC_FILES, ret, done,
				      "files listed");
	torture_assert_goto(tctx, hidden, ret, done, "f0 listed as hidden");

done:
	smb2_util_close(tree, h);
	return ret;
}

/*
 * A listing fills the cache, the idle timer frees it, and the next listing
 * fills it again with the same attributes.
 */
static bool test_truenas_mdcache_idle(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_handle fh = {{0}};
	uint32_t slots = 0, count = 0;
	NTSTATUS status;
	bool ret = true;
	int i;

	smb2_deltree(tree, MDC_DIR);
	status = torture_smb2_testdir(tree, MDC_DIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory");

	status = mdc_fsctl(tctx, tree, h, MDC_IDLE, &slots, &count);
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_FS_DRIVER_REQUIRED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		torture_skip_goto(tctx, done,
				  "smbd:FSCTL_SMBTORTURE is not enabled\n");
	}
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SMBTORTURE_MDCACHE");

	for (i = 0; i < MDC_FILES; i++) {
		const char *fname = talloc_asprintf(tctx, MDC_DIR "\\f%d", i);

		status = torture_smb2_testfile(tree, fname, &fh);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create file");
		smb2_util_close(tree, fh);
	}
	status = smb2_util_setatr(tree, MDC_DIR "\\f0", FILE_ATTRIBUTE_HIDDEN);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set FILE_ATTRIBUTE_HIDDEN");

	torture_assert_goto(tctx, mdc_list(tctx, tree), ret, done,
			    "first listing");
	status = mdc_fsctl(tctx, tree, h, 0, &slots, &count);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SMBTORTURE_MDCACHE");
	if (count == 0) {
		torture_skip_goto(tctx, done, "nothing fills the metadata "
				  "cache on this share\n");
	}
	torture_assert_goto(tctx, count >= MDC_FILES, ret, done,
			    "listed files are cached");

	/* Freed after one to two timeouts without use */
	for (i = 0; (i < 5 * MDC_IDLE) && (slots != 0); i++) {
		smb_msleep(1000);
		status = mdc_fsctl(tctx, tree, h, 0, &slots, &count);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"FSCTL_SMBTORTURE_MDCACHE");
	}
	torture_assert_int_equal_goto(tctx, slots, 0, ret, done,
				      "cache freed after idling");

	torture_assert_goto(tctx, mdc_list(tctx, tree), ret, done,
			    "listing after the cache was freed");
	status = mdc_fsctl(tctx, tree, h, 0, &slots, &count);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SMBTORTURE_MDCACHE");
	torture_assert_goto(tctx, count >= MDC_FILES, ret, done,
			    "cache filled again");

done:
	smb2_util_close(tree, h);
	smb2_deltree(tree, MDC_DIR);
	return ret;
}

void torture_truenas_mdcache_suite(struct torture_suite *suite)
{
	struct torture_suite *mdcache = torture_suite_create(suite, "mdcache");

	torture_suite_add_1smb2_test(mdcache, "idle",
				     test_truenas_mdcache_idle);

	torture_suite_add_suite(suite, mdcache);
}
