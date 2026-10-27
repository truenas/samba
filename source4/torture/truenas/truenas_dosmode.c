/*
   Unix SMB/CIFS implementation.

   TrueNAS kernel dosmodes torture tests.

   With kernel dosmodes, ixnas takes the DOS attributes from the ZFS flags
   in the stat and sets them and the times with system.truenas_setattr.
   The create time is the native one. A directory never has
   FILE_ATTRIBUTE_ARCHIVE, since ZFS sets ZFS_ARCHIVE on a directory
   whenever it changes. Run on [zacl], where a listing opens each entry,
   and on [zkdos], where it lists from the stat ("ea support = no").

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

#define DM_DIR		"truenas_dosmode"
#define DM_ATTRS	(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | \
			 FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE)
/* 2001-02-03 04:05:06.7 UTC */
#define DM_CREATE_TIME	126256467067000000ULL

/* The attributes and create time of DM_DIR\name, from an open */
static bool dm_query(struct torture_context *tctx,
		     struct smb2_tree *tree,
		     const char *name,
		     uint32_t *attrib,
		     NTTIME *create_time)
{
	struct smb2_create c = {
		.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = talloc_asprintf(tctx, DM_DIR "\\%s", name),
	};
	union smb_fileinfo finfo = {
		.all_info2.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
	};
	NTSTATUS status;

	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok(tctx, status, "open");
	finfo.all_info2.in.file.handle = c.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	smb2_util_close(tree, c.out.file.handle);
	torture_assert_ntstatus_ok(tctx, status, "getinfo");

	*attrib = finfo.all_info2.out.attrib;
	*create_time = finfo.all_info2.out.create_time;
	return true;
}

/* The attributes and create time that a listing of DM_DIR gives name */
static bool dm_list(struct torture_context *tctx,
		    struct smb2_tree *tree,
		    const char *name,
		    uint32_t *attrib,
		    NTTIME *create_time)
{
	struct smb2_handle h = {{0}};
	struct smb2_find f;
	union smb_search_data *d = NULL;
	unsigned int count, i;
	bool found = false;
	NTSTATUS status;
	bool ret = true;

	status = torture_smb2_testdir(tree, DM_DIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "open directory");

	ZERO_STRUCT(f);
	f.in.file.handle	= h;
	f.in.pattern		= "*";
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
			if (strcmp(d[i].both_directory_info.name.s,
				   name) != 0) {
				continue;
			}
			*attrib = d[i].both_directory_info.attrib;
			*create_time = d[i].both_directory_info.create_time;
			found = true;
		}
	} while (count > 0);

	torture_assert_goto(tctx, found, ret, done, "entry listed");

done:
	smb2_util_close(tree, h);
	return ret;
}

/* Attributes set on a file read back from an open and from listings */
static bool test_truenas_dosmode_file(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	uint32_t want = DM_ATTRS;
	uint32_t attrib = 0;
	NTTIME ct = 0;
	NTSTATUS status;
	bool ret = true;
	int i;

	smb2_deltree(tree, DM_DIR);
	status = torture_smb2_testdir(tree, DM_DIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory");
	smb2_util_close(tree, h);
	status = torture_smb2_testfile(tree, DM_DIR "\\f", &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file");
	smb2_util_close(tree, h);

	status = smb2_util_setatr(tree, DM_DIR "\\f", want);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set attributes");
	torture_assert_goto(tctx, dm_query(tctx, tree, "f", &attrib, &ct),
			    ret, done, "query");
	torture_assert_int_equal_goto(tctx, attrib & DM_ATTRS, want,
				      ret, done, "attributes from an open");

	/* The second listing comes from the stat where it can */
	for (i = 0; i < 2; i++) {
		torture_assert_goto(tctx,
				    dm_list(tctx, tree, "f", &attrib, &ct),
				    ret, done, "list");
		torture_assert_int_equal_goto(tctx, attrib & DM_ATTRS, want,
					      ret, done,
					      "attributes from a listing");
	}

	/* ZFS may set ARCHIVE again for the change, so leave it out */
	status = smb2_util_setatr(tree, DM_DIR "\\f", FILE_ATTRIBUTE_NORMAL);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"clear attributes");
	torture_assert_goto(tctx, dm_query(tctx, tree, "f", &attrib, &ct),
			    ret, done, "query");
	torture_assert_int_equal_goto(tctx,
				      attrib & (DM_ATTRS &
						~FILE_ATTRIBUTE_ARCHIVE),
				      0, ret, done, "attributes cleared");

done:
	smb2_deltree(tree, DM_DIR);
	return ret;
}

/* A directory never has ARCHIVE, even after ZFS sets ZFS_ARCHIVE */
static bool test_truenas_dosmode_dir_archive(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	uint32_t attrib = 0;
	NTTIME ct = 0;
	NTSTATUS status;
	bool ret = true;
	int i;

	smb2_deltree(tree, DM_DIR);
	status = torture_smb2_testdir(tree, DM_DIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory");
	smb2_util_close(tree, h);
	status = torture_smb2_testdir(tree, DM_DIR "\\d", &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create subdirectory");
	smb2_util_close(tree, h);

	torture_assert_goto(tctx, dm_query(tctx, tree, "d", &attrib, &ct),
			    ret, done, "query");
	torture_assert_int_equal_goto(tctx, attrib & FILE_ATTRIBUTE_ARCHIVE,
				      0, ret, done, "new directory");

	status = smb2_util_setatr(tree, DM_DIR "\\d",
				  FILE_ATTRIBUTE_DIRECTORY |
				  FILE_ATTRIBUTE_ARCHIVE |
				  FILE_ATTRIBUTE_HIDDEN);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set attributes");

	/* A new entry changes the directory */
	status = torture_smb2_testfile(tree, DM_DIR "\\d\\f", &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file");
	smb2_util_close(tree, h);

	torture_assert_goto(tctx, dm_query(tctx, tree, "d", &attrib, &ct),
			    ret, done, "query");
	torture_assert_int_equal_goto(tctx,
				      attrib & (FILE_ATTRIBUTE_ARCHIVE |
						FILE_ATTRIBUTE_HIDDEN),
				      FILE_ATTRIBUTE_HIDDEN, ret, done,
				      "attributes from an open");

	for (i = 0; i < 2; i++) {
		torture_assert_goto(tctx,
				    dm_list(tctx, tree, "d", &attrib, &ct),
				    ret, done, "list");
		torture_assert_int_equal_goto(tctx,
					      attrib & (FILE_ATTRIBUTE_ARCHIVE |
							FILE_ATTRIBUTE_HIDDEN),
					      FILE_ATTRIBUTE_HIDDEN, ret, done,
					      "attributes from a listing");
	}

done:
	smb2_deltree(tree, DM_DIR);
	return ret;
}

/* A create time that a client sets is stored natively */
static bool test_truenas_dosmode_create_time(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	struct smb2_tree *tree2 = NULL;
	struct smb2_handle h = {{0}};
	union smb_setfileinfo sfinfo;
	uint32_t attrib = 0;
	NTTIME ct = 0;
	NTSTATUS status;
	bool ret = true;
	int i;

	smb2_deltree(tree, DM_DIR);
	status = torture_smb2_testdir(tree, DM_DIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory");
	smb2_util_close(tree, h);
	status = torture_smb2_testfile(tree, DM_DIR "\\f", &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file");

	ZERO_STRUCT(sfinfo);
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.basic_info.in.file.handle = h;
	sfinfo.basic_info.in.create_time = DM_CREATE_TIME;
	status = smb2_setinfo_file(tree, &sfinfo);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set the create time");

	torture_assert_goto(tctx, dm_query(tctx, tree, "f", &attrib, &ct),
			    ret, done, "query");
	torture_assert_u64_equal_goto(tctx, ct, DM_CREATE_TIME, ret, done,
				      "create time from an open");

	for (i = 0; i < 2; i++) {
		torture_assert_goto(tctx,
				    dm_list(tctx, tree, "f", &attrib, &ct),
				    ret, done, "list");
		torture_assert_u64_equal_goto(tctx, ct, DM_CREATE_TIME,
					      ret, done,
					      "create time from a listing");
	}

	torture_assert_goto(tctx,
			    torture_smb2_tree_connect(tctx, tree->session,
						      tctx, &tree2),
			    ret, done, "second tree connect");
	torture_assert_goto(tctx, dm_query(tctx, tree2, "f", &attrib, &ct),
			    ret, done, "query");
	torture_assert_u64_equal_goto(tctx, ct, DM_CREATE_TIME, ret, done,
				      "create time on a new tree connect");

done:
	TALLOC_FREE(tree2);
	smb2_deltree(tree, DM_DIR);
	return ret;
}

/* Attributes and times in one SET_INFO, one ZFS transaction */
static bool test_truenas_dosmode_basic_info(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	union smb_setfileinfo sfinfo;
	union smb_fileinfo finfo = {
		.all_info2.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
	};
	uint32_t want = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
	uint32_t attrib = 0;
	NTTIME ct = 0;
	NTSTATUS status;
	bool ret = true;
	int i;

	smb2_deltree(tree, DM_DIR);
	status = torture_smb2_testdir(tree, DM_DIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory");
	smb2_util_close(tree, h);
	status = torture_smb2_testfile(tree, DM_DIR "\\f", &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file");

	ZERO_STRUCT(sfinfo);
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.basic_info.in.file.handle = h;
	sfinfo.basic_info.in.create_time = DM_CREATE_TIME;
	sfinfo.basic_info.in.write_time = DM_CREATE_TIME + 10000000;
	sfinfo.basic_info.in.attrib = want;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set attributes and times");

	finfo.all_info2.in.file.handle = h;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "getinfo");
	torture_assert_int_equal_goto(tctx,
				      finfo.all_info2.out.attrib & want,
				      want, ret, done,
				      "attributes on the handle");
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.write_time,
				      DM_CREATE_TIME + 10000000, ret, done,
				      "write time on the handle");

	torture_assert_goto(tctx, dm_query(tctx, tree, "f", &attrib, &ct),
			    ret, done, "query");
	torture_assert_int_equal_goto(tctx, attrib & want, want, ret, done,
				      "attributes from an open");
	torture_assert_u64_equal_goto(tctx, ct, DM_CREATE_TIME, ret, done,
				      "create time from an open");

	for (i = 0; i < 2; i++) {
		torture_assert_goto(tctx,
				    dm_list(tctx, tree, "f", &attrib, &ct),
				    ret, done, "list");
		torture_assert_int_equal_goto(tctx, attrib & want, want,
					      ret, done,
					      "attributes from a listing");
		torture_assert_u64_equal_goto(tctx, ct, DM_CREATE_TIME,
					      ret, done,
					      "create time from a listing");
	}

done:
	smb2_deltree(tree, DM_DIR);
	return ret;
}

void torture_truenas_dosmode_suite(struct torture_suite *suite)
{
	struct torture_suite *dosmode = torture_suite_create(suite,
							     "dosmode");

	torture_suite_add_1smb2_test(dosmode, "file",
				     test_truenas_dosmode_file);
	torture_suite_add_1smb2_test(dosmode, "dir_archive",
				     test_truenas_dosmode_dir_archive);
	torture_suite_add_1smb2_test(dosmode, "create_time",
				     test_truenas_dosmode_create_time);
	torture_suite_add_1smb2_test(dosmode, "basic_info",
				     test_truenas_dosmode_basic_info);

	torture_suite_add_suite(suite, dosmode);
}
