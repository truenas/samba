/*
   Unix SMB/CIFS implementation.

   TrueNAS vfs_worm torture tests.

   vfs_worm locks a file whose change time is older than worm:grace_period.
   A locked file keeps its attributes and times, also through a handle
   opened before the lock. With kernel dosmodes, SET_INFO sets both with
   one SMB_VFS_FNTIMES, which worm sees below ixnas. Run on [zworm], whose
   grace period is torture:worm_grace seconds (default 1). A locked file
   can't be removed, so each run uses a new directory.

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

/* 2001-02-03 04:05:06.7 UTC */
#define WORM_CREATE_TIME	126256467067000000ULL

/* A new file in a new directory, open in *_h */
static bool worm_new_file(struct torture_context *tctx,
			  struct smb2_tree *tree,
			  struct smb2_handle *_h)
{
	const char *dname = talloc_asprintf(tctx, "truenas_worm_%s",
					    generate_random_str(tctx, 8));
	struct smb2_handle hd = {{0}};
	NTSTATUS status;

	status = torture_smb2_testdir(tree, dname, &hd);
	torture_assert_ntstatus_ok(tctx, status, "create directory");
	smb2_util_close(tree, hd);

	status = torture_smb2_testfile(tree,
				       talloc_asprintf(tctx, "%s\\f", dname),
				       _h);
	torture_assert_ntstatus_ok(tctx, status, "create file");
	return true;
}

/* FileBasicInformation with attrib and a create time, 0: unchanged */
static NTSTATUS worm_set_basic(struct smb2_tree *tree,
			       struct smb2_handle h,
			       uint32_t attrib,
			       NTTIME create_time)
{
	union smb_setfileinfo sfinfo;

	ZERO_STRUCT(sfinfo);
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.basic_info.in.file.handle = h;
	sfinfo.basic_info.in.create_time = create_time;
	sfinfo.basic_info.in.attrib = attrib;
	return smb2_setinfo_file(tree, &sfinfo);
}

/* Before the lock, attributes and times change */
static bool test_truenas_worm_unlocked(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, worm_new_file(tctx, tree, &h), "new file");

	status = worm_set_basic(tree, h, FILE_ATTRIBUTE_HIDDEN,
				WORM_CREATE_TIME);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set attributes and the create time");

done:
	smb2_util_close(tree, h);
	return ret;
}

/* After the lock, a handle opened before it changes neither */
static bool test_truenas_worm_locked(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	int grace = torture_setting_int(tctx, "worm_grace", 1);
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	bool ret = true;

	torture_assert(tctx, worm_new_file(tctx, tree, &h), "new file");
	smb_msleep((grace + 1) * 1000);

	status = worm_set_basic(tree, h, 0, WORM_CREATE_TIME);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED, ret, done,
					   "set the create time");

	status = worm_set_basic(tree, h, FILE_ATTRIBUTE_HIDDEN, 0);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED, ret, done,
					   "set attributes");

done:
	smb2_util_close(tree, h);
	return ret;
}

void torture_truenas_worm_suite(struct torture_suite *suite)
{
	struct torture_suite *worm = torture_suite_create(suite, "worm");

	torture_suite_add_1smb2_test(worm, "unlocked",
				     test_truenas_worm_unlocked);
	torture_suite_add_1smb2_test(worm, "locked",
				     test_truenas_worm_locked);

	torture_suite_add_suite(suite, worm);
}
