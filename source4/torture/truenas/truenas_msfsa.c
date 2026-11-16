/*
   Unix SMB/CIFS implementation.

   This file ports MS-FSA build verification tests of the Microsoft File
   Server test suite. The Microsoft tests are in
   TestSuites/FileServer/src/FSA of
   github.com/microsoft/WindowsProtocolTestSuites, release 4.26.9.0. The
   comment of each test names the Microsoft tests that it ports. Each
   port runs the same steps and checks as those tests. The file omits
   tests that need features missing from Samba.

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

   The Microsoft tests have this notice:

   Copyright (c) Microsoft Corporation

   All rights reserved.

   MIT License

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"

#define MSFSA_DIR	"truenas_msfsa"
/* The Microsoft tests set this time, 2009-04-01 08:00:00 UTC. */
#define MSFSA_TIME	((NTTIME)128830464000000000ULL)
/* The pause makes a change of a time visible. */
#define MSFSA_DELAY_MS	100
#define MSFSA_SHARE_ALL	(NTCREATEX_SHARE_ACCESS_READ | \
			 NTCREATEX_SHARE_ACCESS_WRITE | \
			 NTCREATEX_SHARE_ACCESS_DELETE)
#define MSFSA_RW	(SEC_GENERIC_READ | SEC_GENERIC_WRITE)
/* [MS-FSCC] 2.5.1 and 2.6 define these flags. */
#define MSFSA_FS_INTEGRITY	0x04000000
#define MSFSA_ATTR_INTEGRITY	0x00008000
/* Convert a trans2 level to its SMB2 info class. */
#define MSFSA_CLASS(level)	((level) - 1000)

/* The order matches the times in FileBasicInformation. */
enum msfsa_time {
	MSFSA_CREATE,
	MSFSA_ACCESS,
	MSFSA_WRITE,
	MSFSA_CHANGE,
	MSFSA_NUM_TIMES
};

static const char *msfsa_time_names[MSFSA_NUM_TIMES] = {
	"CreationTime",
	"LastAccessTime",
	"LastWriteTime",
	"ChangeTime",
};

struct msfsa_basic {
	NTTIME t[MSFSA_NUM_TIMES];
	uint32_t attrib;
};

static NTSTATUS msfsa_create(struct smb2_tree *tree,
			     TALLOC_CTX *mem_ctx,
			     const char *name,
			     bool dir,
			     uint32_t access,
			     uint32_t share,
			     uint32_t disposition,
			     struct smb2_handle *h)
{
	struct smb2_create c = {
		.in.fname = name,
		.in.desired_access = access,
		.in.share_access = share,
		.in.create_disposition = disposition,
		.in.create_options = dir ? NTCREATEX_OPTIONS_DIRECTORY :
			NTCREATEX_OPTIONS_NON_DIRECTORY_FILE,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
	};
	NTSTATUS status;

	status = smb2_create(tree, mem_ctx, &c);
	if (NT_STATUS_IS_OK(status)) {
		*h = c.out.file.handle;
	}
	return status;
}

/* Create name as the Microsoft tests do, then close it. */
static NTSTATUS msfsa_touch(struct smb2_tree *tree,
			    TALLOC_CTX *mem_ctx,
			    const char *name)
{
	struct smb2_handle h = {};
	NTSTATUS status;

	status = msfsa_create(tree, mem_ctx, name, false, MSFSA_RW,
			      MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN_IF, &h);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return smb2_util_close(tree, h);
}

static NTSTATUS msfsa_query_basic(struct smb2_tree *tree,
				  TALLOC_CTX *mem_ctx,
				  struct smb2_handle h,
				  struct msfsa_basic *b)
{
	union smb_fileinfo q = {
		.basic_info.level = RAW_FILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h,
	};
	NTSTATUS status;

	status = smb2_getinfo_file(tree, mem_ctx, &q);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	b->t[MSFSA_CREATE] = q.basic_info.out.create_time;
	b->t[MSFSA_ACCESS] = q.basic_info.out.access_time;
	b->t[MSFSA_WRITE] = q.basic_info.out.write_time;
	b->t[MSFSA_CHANGE] = q.basic_info.out.change_time;
	b->attrib = q.basic_info.out.attrib;
	return NT_STATUS_OK;
}

/* A field of 0 means "no change". */
static NTSTATUS msfsa_set_basic(struct smb2_tree *tree,
				struct smb2_handle h,
				const struct msfsa_basic *b)
{
	union smb_setfileinfo s = {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h,
		.basic_info.in.create_time = b->t[MSFSA_CREATE],
		.basic_info.in.access_time = b->t[MSFSA_ACCESS],
		.basic_info.in.write_time = b->t[MSFSA_WRITE],
		.basic_info.in.change_time = b->t[MSFSA_CHANGE],
		.basic_info.in.attrib = b->attrib,
	};

	return smb2_setinfo_file(tree, &s);
}

/* Set the size to len, then write len bytes, as WriteNewFile() does. */
static NTSTATUS msfsa_write_new(struct smb2_tree *tree,
				struct smb2_handle h,
				size_t len,
				uint8_t fill)
{
	union smb_setfileinfo s = {
		.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION,
		.end_of_file_info.in.file.handle = h,
		.end_of_file_info.in.size = len,
	};
	uint8_t *buf = NULL;
	NTSTATUS status;

	status = smb2_setinfo_file(tree, &s);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	buf = talloc_array(tree, uint8_t, len);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	memset(buf, fill, len);
	status = smb2_util_write(tree, h, buf, 0, len);
	TALLOC_FREE(buf);
	return status;
}

static NTSTATUS msfsa_getinfo(struct smb2_tree *tree,
			      TALLOC_CTX *mem_ctx,
			      struct smb2_handle h,
			      uint8_t type,
			      uint8_t class,
			      uint32_t out_len,
			      DATA_BLOB *blob)
{
	struct smb2_getinfo g = {
		.in.info_type = type,
		.in.info_class = class,
		.in.output_buffer_length = out_len,
		.in.file.handle = h,
	};
	NTSTATUS status;

	status = smb2_getinfo(tree, mem_ctx, &g);
	*blob = g.out.blob;
	return status;
}

static NTSTATUS msfsa_fsctl(struct smb2_tree *tree,
			    TALLOC_CTX *mem_ctx,
			    struct smb2_handle h,
			    uint32_t function,
			    DATA_BLOB in,
			    uint32_t max_out,
			    DATA_BLOB *out)
{
	union smb_ioctl io = {
		.smb2.level = RAW_IOCTL_SMB2,
		.smb2.in.file.handle = h,
		.smb2.in.function = function,
		.smb2.in.max_output_response = max_out,
		.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL,
		.smb2.in.out = in,
	};
	NTSTATUS status;

	status = smb2_ioctl(tree, mem_ctx, &io.smb2);
	*out = io.smb2.out.out;
	return status;
}

static bool msfsa_setup(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;

	smb2_deltree(tree, MSFSA_DIR);
	status = smb2_util_mkdir(tree, MSFSA_DIR);
	torture_assert_ntstatus_ok(tctx, status, "mkdir " MSFSA_DIR);
	return true;
}

static bool msfsa_all_zero(const uint8_t *p, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (p[i] != 0) {
			return false;
		}
	}
	return true;
}

/*
 * The search tests check [MS-FSA] 2.1.4.4. Each search runs with each of
 * the six information classes of the Microsoft tests.
 */

static const uint8_t msfsa_levels[] = {
	SMB2_FIND_NAME_INFO,
	SMB2_FIND_DIRECTORY_INFO,
	SMB2_FIND_FULL_DIRECTORY_INFO,
	SMB2_FIND_BOTH_DIRECTORY_INFO,
	SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
	SMB2_FIND_ID_FULL_DIRECTORY_INFO,
};

static const char *msfsa_entry_name(uint8_t level, union smb_search_data *d)
{
	switch (level) {
	case SMB2_FIND_NAME_INFO:
		return d->name_info.name.s;
	case SMB2_FIND_DIRECTORY_INFO:
		return d->directory_info.name.s;
	case SMB2_FIND_FULL_DIRECTORY_INFO:
		return d->full_directory_info.name.s;
	case SMB2_FIND_BOTH_DIRECTORY_INFO:
		return d->both_directory_info.name.s;
	case SMB2_FIND_ID_BOTH_DIRECTORY_INFO:
		return d->id_both_directory_info.name.s;
	case SMB2_FIND_ID_FULL_DIRECTORY_INFO:
		return d->id_full_directory_info.name.s;
	}
	return NULL;
}

static NTTIME msfsa_entry_create_time(uint8_t level, union smb_search_data *d)
{
	switch (level) {
	case SMB2_FIND_BOTH_DIRECTORY_INFO:
		return d->both_directory_info.create_time;
	case SMB2_FIND_FULL_DIRECTORY_INFO:
		return d->full_directory_info.create_time;
	}
	return 0;
}

struct msfsa_search {
	const char *pattern;
	/*
	 * If files is empty, the test creates ten files with long names and
	 * expects every entry to match.
	 */
	const char *files[6];
	const char *match[5];
};

static bool msfsa_search_run(struct torture_context *tctx,
			     struct smb2_tree *tree,
			     const struct msfsa_search *s)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *dname = MSFSA_DIR "\\search";
	const char **files = NULL;
	const char **match = NULL;
	size_t nfiles = 0, nmatch = 0, l, i, j;
	bool all = (s->files[0] == NULL);
	struct smb2_handle dh = {};
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	status = torture_smb2_testdir(tree, dname, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "mkdir");

	if (all) {
		files = talloc_zero_array(mem_ctx, const char *, 10);
		for (i = 0; i < 10; i++) {
			/* The Microsoft tests use names of this length. */
			files[i] = talloc_asprintf(files, "searchfile_%09zu.txt",
						   i);
		}
		nfiles = 10;
		match = talloc_zero_array(mem_ctx, const char *, 12);
		match[0] = ".";
		match[1] = "..";
		memcpy(&match[2], files, 10 * sizeof(files[0]));
		nmatch = 12;
	} else {
		files = discard_const_p(const char *, s->files);
		match = discard_const_p(const char *, s->match);
		while (files[nfiles] != NULL) {
			nfiles++;
		}
		while (match[nmatch] != NULL) {
			nmatch++;
		}
	}

	for (i = 0; i < nfiles; i++) {
		const char *path = talloc_asprintf(mem_ctx, "%s\\%s", dname,
						   files[i]);

		status = msfsa_touch(tree, mem_ctx, path);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done, path);
	}

	for (l = 0; l < ARRAY_SIZE(msfsa_levels); l++) {
		struct smb2_find f = {
			.in.file.handle = dh,
			.in.level = msfsa_levels[l],
			.in.continue_flags = SMB2_CONTINUE_FLAG_RESTART,
			.in.max_response_size = 4096,
			.in.pattern = s->pattern,
		};
		union smb_search_data *d = NULL;
		unsigned int count = 0;

		torture_comment(tctx, "pattern %s, level 0x%02x\n",
				s->pattern, msfsa_levels[l]);
		status = smb2_find_level(tree, mem_ctx, &f, &count, &d);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"query directory");
		torture_assert_int_equal_goto(tctx, count, nmatch, ret, done,
					      "number of entries");
		if (all) {
			torture_assert_str_equal_goto(
				tctx, msfsa_entry_name(f.in.level, &d[0]), ".",
				ret, done, "first entry");
			torture_assert_str_equal_goto(
				tctx, msfsa_entry_name(f.in.level, &d[1]), "..",
				ret, done, "second entry");
		}
		for (i = 0; i < nmatch; i++) {
			bool found = false;

			for (j = 0; j < count; j++) {
				const char *n = msfsa_entry_name(f.in.level,
								 &d[j]);
				if (n != NULL && strcmp(n, match[i]) == 0) {
					found = true;
					break;
				}
			}
			torture_assert_goto(tctx, found, ret, done,
					    talloc_asprintf(mem_ctx,
							    "%s not found",
							    match[i]));
		}
	}

done:
	if (!smb2_util_handle_empty(dh)) {
		smb2_util_close(tree, dh);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/* BVT_QueryDirectoryBySearchPattern_*_AsteriskWildCard */
static bool test_msfsa_search_star(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	const struct msfsa_search s = { .pattern = "*" };

	return msfsa_search_run(tctx, tree, &s);
}

/* BVT_QueryDirectoryBySearchPattern_*_SpecialCase_AsteriskWildCard */
static bool test_msfsa_search_star_dot_star(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	const struct msfsa_search s = { .pattern = "*.*" };

	return msfsa_search_run(tctx, tree, &s);
}

/* BVT_QueryDirectoryBySearchPattern_*_WildCard_QuestionMark */
static bool test_msfsa_search_question_mark(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	const struct msfsa_search s = {
		.pattern = "Fi?e",
		.files = { "Fine", "File", "Bile", "Fille", "Nine" },
		.match = { "Fine", "File" },
	};

	return msfsa_search_run(tctx, tree, &s);
}

/* BVT_QueryDirectoryBySearchPattern_*_AsteriskInStringWildCard */
static bool test_msfsa_search_star_in_name(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	const struct msfsa_search s = {
		.pattern = "*ile",
		.files = { "Fine", "File", "Bile", "Fille", "Nine" },
		.match = { "File", "Bile" },
	};

	return msfsa_search_run(tctx, tree, &s);
}

/* BVT_QueryDirectoryBySearchPattern_*_DOS_STAR_WildCard. DOS_STAR is '<'. */
static bool test_msfsa_search_dos_star(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	const struct msfsa_search s = {
		.pattern = "<txt",
		.files = { "Fine.txt", "FileGrip.txt", "Bile.txt", "Tile.txt",
			   "Nine.jpg" },
		.match = { "Fine.txt", "FileGrip.txt", "Bile.txt",
			   "Tile.txt" },
	};

	return msfsa_search_run(tctx, tree, &s);
}

/* BVT_QueryDirectoryBySearchPattern_*_DOS_QM_WildCard. DOS_QM is '>'. */
static bool test_msfsa_search_dos_qm(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	const struct msfsa_search s = {
		.pattern = "Fi>e",
		.files = { "Fine", "File", "Bile", "Fille", "Nine" },
		.match = { "Fine", "File" },
	};

	return msfsa_search_run(tctx, tree, &s);
}

static int msfsa_strcmp(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

/*
 * Fs_CreateFiles_QueryDirectory_With_Single_Entry_Flag. The test creates
 * 1000 files and lists them with SMB2_RETURN_SINGLE_ENTRY, one entry per
 * query. The port also checks that the listing returns each entry one
 * time and then ends.
 */
static bool test_msfsa_search_single_entry(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *dname = MSFSA_DIR "\\single";
	const unsigned int nfiles = 1000;
	const char **want = NULL;
	const char **got = NULL;
	struct smb2_handle dh = {};
	unsigned int i;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	status = torture_smb2_testdir(tree, dname, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "mkdir");

	want = talloc_zero_array(mem_ctx, const char *, nfiles + 2);
	got = talloc_zero_array(mem_ctx, const char *, nfiles + 2);
	torture_assert_goto(tctx, want != NULL && got != NULL, ret, done,
			    "no memory");
	want[0] = ".";
	want[1] = "..";
	for (i = 0; i < nfiles; i++) {
		const char *path = NULL;

		want[i + 2] = talloc_asprintf(want, "s%07u.txt", i);
		path = talloc_asprintf(mem_ctx, "%s\\%s", dname, want[i + 2]);
		status = msfsa_touch(tree, mem_ctx, path);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done, path);
	}

	for (i = 0; i < nfiles + 3; i++) {
		struct smb2_find f = {
			.in.file.handle = dh,
			.in.level = SMB2_FIND_BOTH_DIRECTORY_INFO,
			.in.continue_flags = SMB2_CONTINUE_FLAG_SINGLE,
			.in.max_response_size = 4096,
			.in.pattern = "*",
		};
		union smb_search_data *d = NULL;
		unsigned int count = 0;

		if (i == 0) {
			f.in.continue_flags |= SMB2_CONTINUE_FLAG_RESTART;
		}
		status = smb2_find_level(tree, mem_ctx, &f, &count, &d);
		if (i == nfiles + 2) {
			torture_assert_ntstatus_equal_goto(
				tctx, status, NT_STATUS_NO_MORE_FILES, ret,
				done, "query after the last entry");
			break;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"query directory");
		torture_assert_int_equal_goto(tctx, count, 1, ret, done,
					      "entries of a single query");
		got[i] = talloc_strdup(got, d[0].both_directory_info.name.s);
		talloc_free(d);
	}

	qsort(want, nfiles + 2, sizeof(want[0]), msfsa_strcmp);
	qsort(got, nfiles + 2, sizeof(got[0]), msfsa_strcmp);
	for (i = 0; i < nfiles + 2; i++) {
		torture_assert_str_equal_goto(tctx, got[i], want[i], ret,
					      done, "entry");
	}

done:
	if (!smb2_util_handle_empty(dh)) {
		smb2_util_close(tree, dh);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * FileInfo_Set_FileBasicInformation_{File,Dir}_{CreationTime,
 * LastAccessTime,LastWriteTime}. A query returns the time that the test
 * set. The port omits ChangeTime because Linux cannot set it.
 */
static bool test_msfsa_basic_set_times(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h = {};
	int dir, t;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		for (t = MSFSA_CREATE; t <= MSFSA_WRITE; t++) {
			struct msfsa_basic set = {}, got = {};
			const char *name = talloc_asprintf(
				mem_ctx, MSFSA_DIR "\\%s_%s",
				dir ? "dir" : "file", msfsa_time_names[t]);

			torture_comment(tctx, "%s\n", name);
			status = msfsa_create(tree, mem_ctx, name, dir,
					      MSFSA_RW | SEC_FILE_WRITE_DATA |
					      SEC_FILE_WRITE_ATTRIBUTE,
					      NTCREATEX_SHARE_ACCESS_READ |
					      NTCREATEX_SHARE_ACCESS_WRITE,
					      NTCREATEX_DISP_CREATE, &h);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "create");
			set.t[t] = MSFSA_TIME;
			status = msfsa_set_basic(tree, h, &set);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "set");
			status = msfsa_query_basic(tree, mem_ctx, h, &got);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "query");
			torture_assert_u64_equal_goto(
				tctx, got.t[t], MSFSA_TIME, ret, done,
				"the object store MUST set the time");
			smb2_util_close(tree, h);
			ZERO_STRUCT(h);
		}
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * FileInfo_Set_FileBasicInformation_Timestamp_Zero_{File,Dir}_*. A time
 * of 0 changes nothing. Each of those tests sends a request with all
 * times 0. The port sends one such request for a file and one for a
 * directory.
 */
static bool test_msfsa_basic_set_zero(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h = {};
	int dir, t;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		struct msfsa_basic before = {}, zero = {}, after = {};
		const char *name = dir ? MSFSA_DIR "\\zero_dir" :
			MSFSA_DIR "\\zero_file";

		status = msfsa_create(tree, mem_ctx, name, dir,
				      MSFSA_RW | SEC_FILE_WRITE_DATA |
				      SEC_FILE_WRITE_ATTRIBUTE,
				      NTCREATEX_SHARE_ACCESS_READ |
				      NTCREATEX_SHARE_ACCESS_WRITE,
				      NTCREATEX_DISP_CREATE, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create");
		status = msfsa_query_basic(tree, mem_ctx, h, &before);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"query");
		smb_msleep(MSFSA_DELAY_MS);
		status = msfsa_set_basic(tree, h, &zero);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"set");
		status = msfsa_query_basic(tree, mem_ctx, h, &after);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"query");
		for (t = 0; t < MSFSA_NUM_TIMES; t++) {
			torture_assert_u64_equal_goto(
				tctx, after.t[t], before.t[t], ret, done,
				talloc_asprintf(mem_ctx,
						"%s %s changed after 0",
						name, msfsa_time_names[t]));
		}
		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * FileInfo_Query_FileBasicInformation_{File,Dir}_CreationTime and
 * FileInfo_Query_File{Both,Full}DirectoryInformation_Dir_CreationTime.
 * A write does not change the creation time of a file. A new file does
 * not change the creation time of its directory. The listing tests read
 * the time of the "." entry.
 */
static bool test_msfsa_create_time_io(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const uint8_t levels[] = {
		SMB2_FIND_BOTH_DIRECTORY_INFO,
		SMB2_FIND_FULL_DIRECTORY_INFO,
	};
	struct msfsa_basic before = {}, after = {};
	struct smb2_handle h = {};
	size_t l;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}

	/* The Microsoft test writes two clusters of 4 KiB. */
	status = msfsa_create(tree, mem_ctx, MSFSA_DIR "\\ctime_file", false,
			      MSFSA_RW, MSFSA_SHARE_ALL, NTCREATEX_DISP_CREATE,
			      &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	status = msfsa_query_basic(tree, mem_ctx, h, &before);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "query");
	smb_msleep(MSFSA_DELAY_MS);
	status = msfsa_write_new(tree, h, 8192, 'a');
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	smb2_util_close(tree, h);
	status = msfsa_create(tree, mem_ctx, MSFSA_DIR "\\ctime_file", false,
			      MSFSA_RW, MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN,
			      &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open");
	status = msfsa_query_basic(tree, mem_ctx, h, &after);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "query");
	torture_assert_u64_equal_goto(tctx, after.t[MSFSA_CREATE],
				      before.t[MSFSA_CREATE], ret, done,
				      "creation time of the file changed");
	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

	status = msfsa_create(tree, mem_ctx, MSFSA_DIR "\\ctime_dir", true,
			      MSFSA_RW, MSFSA_SHARE_ALL, NTCREATEX_DISP_CREATE,
			      &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "mkdir");
	status = msfsa_query_basic(tree, mem_ctx, h, &before);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "query");
	smb_msleep(MSFSA_DELAY_MS);
	status = msfsa_touch(tree, mem_ctx, MSFSA_DIR "\\ctime_dir\\inner");
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	status = msfsa_query_basic(tree, mem_ctx, h, &after);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "query");
	torture_assert_u64_equal_goto(tctx, after.t[MSFSA_CREATE],
				      before.t[MSFSA_CREATE], ret, done,
				      "creation time of the directory changed");
	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

	for (l = 0; l < ARRAY_SIZE(levels); l++) {
		const char *dname = talloc_asprintf(
			mem_ctx, MSFSA_DIR "\\ctime_list_%zu", l);
		const char *inner = talloc_asprintf(mem_ctx, "%s\\inner",
						    dname);
		NTTIME t1 = 0, t2 = 0;
		int pass;

		status = torture_smb2_testdir(tree, dname, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"mkdir");
		for (pass = 0; pass <= 1; pass++) {
			struct smb2_find f = {
				.in.file.handle = h,
				.in.level = levels[l],
				.in.continue_flags =
					SMB2_CONTINUE_FLAG_RESTART,
				.in.max_response_size = 4096,
				.in.pattern = "*",
			};
			union smb_search_data *d = NULL;
			unsigned int count = 0;

			status = smb2_find_level(tree, mem_ctx, &f, &count,
						 &d);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "list");
			torture_assert_int_equal_goto(tctx, count, 2 + pass,
						      ret, done, "entries");
			torture_assert_str_equal_goto(
				tctx, msfsa_entry_name(levels[l], &d[0]), ".",
				ret, done, "first entry");
			if (pass == 0) {
				t1 = msfsa_entry_create_time(levels[l], &d[0]);
				smb_msleep(MSFSA_DELAY_MS);
				status = msfsa_touch(tree, mem_ctx, inner);
				torture_assert_ntstatus_ok_goto(
					tctx, status, ret, done, "create");
			} else {
				t2 = msfsa_entry_create_time(levels[l], &d[0]);
				torture_assert_u64_equal_goto(
					tctx, t2, t1, ret, done,
					"creation time in the listing "
					"changed");
			}
		}
		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * FileInfo_Query_FileInternalInformation,
 * FileInfo_Query_FileAlignmentInformation,
 * FileInfo_Query_FileAccessInformation_DataSuffix and
 * FileInfo_Query_FileNormalizedNameInfo_File. The queries use the output
 * buffer sizes of the Microsoft tests.
 */
static bool test_msfsa_query_info(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *name = MSFSA_DIR "\\query.txt";
	/* [MS-FSCC] 2.4.3 defines these AlignmentRequirement values. */
	const uint32_t alignments[] = {
		0, 1, 3, 7, 15, 31, 63, 127, 255, 511,
	};
	union smb_fileinfo q = {};
	struct smb2_handle h = {};
	DATA_BLOB b = {};
	uint32_t alignment;
	bool found = false;
	size_t i;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	status = msfsa_create(tree, mem_ctx, name, false, MSFSA_RW,
			      MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN_IF, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");

	/* The file ID has 64 bits and is not 0. */
	status = msfsa_getinfo(
		tree, mem_ctx, h, SMB2_0_INFO_FILE,
		MSFSA_CLASS(SMB_QFILEINFO_INTERNAL_INFORMATION), 4 + 64 * 2, &b);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FileInternalInformation");
	torture_assert_int_equal_goto(tctx, b.length, 8, ret, done,
				      "size of FileInternalInformation");
	torture_assert_goto(tctx, BVAL(b.data, 0) != 0, ret, done,
			    "IndexNumber is 0");

	/* The alignment is a defined value in exactly 4 bytes. */
	status = msfsa_getinfo(
		tree, mem_ctx, h, SMB2_0_INFO_FILE,
		MSFSA_CLASS(SMB_QFILEINFO_ALIGNMENT_INFORMATION), 4, &b);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FileAlignmentInformation");
	torture_assert_int_equal_goto(tctx, b.length, 4, ret, done,
				      "ByteCount of FileAlignmentInformation");
	alignment = IVAL(b.data, 0);
	for (i = 0; i < ARRAY_SIZE(alignments); i++) {
		found |= (alignment == alignments[i]);
	}
	torture_assert_goto(tctx, found, ret, done,
			    "AlignmentRequirement is not a defined value");

	/* The normalized name is the created name, from the share root. */
	q.normalized_name_info.level = RAW_FILEINFO_NORMALIZED_NAME_INFORMATION;
	q.normalized_name_info.in.file.handle = h;
	status = smb2_getinfo_file(tree, mem_ctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FileNormalizedNameInformation");
	torture_assert_str_equal_goto(tctx,
				      q.normalized_name_info.out.fname.s, name,
				      ret, done, "normalized name");
	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

	/* Query FileAccessInformation of a name with the ::$DATA suffix. */
	status = msfsa_create(tree, mem_ctx, MSFSA_DIR "\\access.txt::$DATA",
			      false, MSFSA_RW, MSFSA_SHARE_ALL,
			      NTCREATEX_DISP_OPEN_IF, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create with ::$DATA");
	status = msfsa_getinfo(
		tree, mem_ctx, h, SMB2_0_INFO_FILE,
		MSFSA_CLASS(SMB_QFILEINFO_ACCESS_INFORMATION), 4, &b);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FileAccessInformation");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * The Microsoft stream tests write 1024 bytes to the unnamed stream of a
 * file. Then they add a stream of 2048 bytes and a stream of 4096 bytes.
 * A directory has only the two named streams.
 */

#define MSFSA_STREAM1	"msfsa_s1"
#define MSFSA_STREAM2	"msfsa_s2"

struct msfsa_stream_want {
	const char *name;
	uint64_t size;
};

/* Create the base and both streams. Leave the second stream open in h2. */
static bool msfsa_streams_make(struct torture_context *tctx,
			       struct smb2_tree *tree,
			       TALLOC_CTX *mem_ctx,
			       const char *base,
			       bool dir,
			       struct smb2_handle *h2)
{
	struct smb2_handle h = {};
	const char *s1 = talloc_asprintf(mem_ctx, "%s:%s:$DATA", base,
					 MSFSA_STREAM1);
	const char *s2 = talloc_asprintf(mem_ctx, "%s:%s:$DATA", base,
					 MSFSA_STREAM2);
	NTSTATUS status;

	status = msfsa_create(tree, mem_ctx, base, dir, SEC_GENERIC_ALL,
			      MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN_IF, &h);
	torture_assert_ntstatus_ok(tctx, status, "create");
	if (!dir) {
		status = msfsa_write_new(tree, h, 1024, 'u');
		torture_assert_ntstatus_ok(tctx, status, "write");
	}
	smb2_util_close(tree, h);

	status = msfsa_create(tree, mem_ctx, s1, false, SEC_GENERIC_ALL,
			      MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN_IF, &h);
	torture_assert_ntstatus_ok(tctx, status, "create stream 1");
	status = msfsa_write_new(tree, h, 2048, '1');
	torture_assert_ntstatus_ok(tctx, status, "write stream 1");
	smb2_util_close(tree, h);

	status = msfsa_create(tree, mem_ctx, s2, false, SEC_GENERIC_ALL,
			      MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN_IF, h2);
	torture_assert_ntstatus_ok(tctx, status, "create stream 2");
	status = msfsa_write_new(tree, *h2, 4096, '2');
	torture_assert_ntstatus_ok(tctx, status, "write stream 2");
	return true;
}

/* List the streams through a handle of the base. Check names and sizes. */
static bool msfsa_streams_check(struct torture_context *tctx,
				struct smb2_tree *tree,
				TALLOC_CTX *mem_ctx,
				const char *base,
				bool dir,
				const struct msfsa_stream_want *want,
				size_t nwant)
{
	union smb_fileinfo q = {};
	struct smb2_handle h = {};
	size_t i, j;
	NTSTATUS status;
	bool ret = true;

	status = msfsa_create(tree, mem_ctx, base, dir, SEC_GENERIC_ALL,
			      MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN, &h);
	torture_assert_ntstatus_ok(tctx, status, "open base");
	q.stream_info.level = RAW_FILEINFO_STREAM_INFORMATION;
	q.stream_info.in.file.handle = h;
	status = smb2_getinfo_file(tree, mem_ctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FileStreamInformation");
	torture_assert_int_equal_goto(tctx, q.stream_info.out.num_streams,
				      nwant, ret, done, "number of streams");
	for (i = 0; i < nwant; i++) {
		bool found = false;

		for (j = 0; j < q.stream_info.out.num_streams; j++) {
			struct stream_struct *s =
				&q.stream_info.out.streams[j];

			if (strcmp(s->stream_name.s, want[i].name) != 0) {
				continue;
			}
			torture_assert_u64_equal_goto(tctx, s->size,
						      want[i].size, ret, done,
						      want[i].name);
			found = true;
		}
		torture_assert_goto(tctx, found, ret, done, want[i].name);
	}
done:
	smb2_util_close(tree, h);
	return ret;
}

/* BVT_AlternateDataStream_CreateStream_{File,Dir} */
static bool test_msfsa_stream_create(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const struct msfsa_stream_want want[] = {
		{ ":" MSFSA_STREAM1 ":$DATA", 2048 },
		{ ":" MSFSA_STREAM2 ":$DATA", 4096 },
		{ "::$DATA", 1024 },
	};
	struct smb2_handle h2 = {};
	int dir;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		const char *base = dir ? MSFSA_DIR "\\sdir" :
			MSFSA_DIR "\\sfile";

		ret = msfsa_streams_make(tctx, tree, mem_ctx, base, dir, &h2);
		torture_assert_goto(tctx, ret, ret, done, "make streams");
		smb2_util_close(tree, h2);
		ZERO_STRUCT(h2);
		/* A directory has no unnamed stream. */
		ret = msfsa_streams_check(tctx, tree, mem_ctx, base, dir, want,
					  dir ? 2 : 3);
		torture_assert_goto(tctx, ret, ret, done, "streams");
	}
done:
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * BVT_AlternateDataStream_WriteAndRead_{File,Dir}. A read of each stream
 * returns the data that the test wrote to it.
 */
static bool test_msfsa_stream_write_read(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const struct {
		const char *stream;
		size_t len;
		uint8_t fill;
	} streams[] = {
		{ MSFSA_STREAM1, 2048, '1' },
		{ MSFSA_STREAM2, 4096, '2' },
	};
	struct smb2_handle h = {};
	int dir;
	size_t i, k;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		const char *base = dir ? MSFSA_DIR "\\wrdir" :
			MSFSA_DIR "\\wrfile";

		ret = msfsa_streams_make(tctx, tree, mem_ctx, base, dir, &h);
		torture_assert_goto(tctx, ret, ret, done, "make streams");
		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
		for (i = 0; i < ARRAY_SIZE(streams); i++) {
			struct smb2_read r = {};
			const char *s = talloc_asprintf(mem_ctx, "%s:%s:$DATA",
							base,
							streams[i].stream);

			status = msfsa_create(tree, mem_ctx, s, false,
					      SEC_GENERIC_ALL, MSFSA_SHARE_ALL,
					      NTCREATEX_DISP_OPEN, &h);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, s);
			r.in.file.handle = h;
			r.in.length = streams[i].len;
			status = smb2_read(tree, mem_ctx, &r);
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
							done, "read");
			torture_assert_int_equal_goto(tctx, r.out.data.length,
						      streams[i].len, ret,
						      done, "bytes read");
			for (k = 0; k < r.out.data.length; k++) {
				torture_assert_int_equal_goto(
					tctx, r.out.data.data[k],
					streams[i].fill, ret, done,
					"data read");
			}
			smb2_util_close(tree, h);
			ZERO_STRUCT(h);
		}
	}
done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * BVT_AlternateDataStream_LockAndUnlock_{File,Dir}. The test locks 5 bytes
 * at offset 3 of a stream exclusively and then unlocks them.
 */
static bool test_msfsa_stream_lock(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h2 = {};
	int dir;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		const char *base = dir ? MSFSA_DIR "\\ldir" :
			MSFSA_DIR "\\lfile";
		struct smb2_lock_element el = {
			.offset = 3,
			.length = 5,
			.flags = SMB2_LOCK_FLAG_EXCLUSIVE |
				SMB2_LOCK_FLAG_FAIL_IMMEDIATELY,
		};
		struct smb2_lock lck = {
			.in.lock_count = 1,
			.in.locks = &el,
		};

		ret = msfsa_streams_make(tctx, tree, mem_ctx, base, dir, &h2);
		torture_assert_goto(tctx, ret, ret, done, "make streams");
		lck.in.file.handle = h2;
		status = smb2_lock(tree, &lck);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"lock");
		el.flags = SMB2_LOCK_FLAG_UNLOCK;
		status = smb2_lock(tree, &lck);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"unlock");
		smb2_util_close(tree, h2);
		ZERO_STRUCT(h2);
	}
done:
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * BVT_AlternateDataStream_DeleteStream_{File,Dir}. The close of a stream
 * handle with DeletePending set deletes the stream.
 */
static bool test_msfsa_stream_delete(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const struct msfsa_stream_want want[] = {
		{ ":" MSFSA_STREAM1 ":$DATA", 2048 },
		{ "::$DATA", 1024 },
	};
	struct smb2_handle h2 = {};
	int dir;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		const char *base = dir ? MSFSA_DIR "\\ddir" :
			MSFSA_DIR "\\dfile";
		union smb_setfileinfo s = {
			.disposition_info.level =
				RAW_SFILEINFO_DISPOSITION_INFORMATION,
			.disposition_info.in.delete_on_close = true,
		};

		ret = msfsa_streams_make(tctx, tree, mem_ctx, base, dir, &h2);
		torture_assert_goto(tctx, ret, ret, done, "make streams");
		s.disposition_info.in.file.handle = h2;
		status = smb2_setinfo_file(tree, &s);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"set DeletePending");
		smb2_util_close(tree, h2);
		ZERO_STRUCT(h2);
		ret = msfsa_streams_check(tctx, tree, mem_ctx, base, dir, want,
					  dir ? 1 : 2);
		torture_assert_goto(tctx, ret, ret, done, "streams");
	}
done:
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Algorithm_NotingFileModified_File_{LastModificationTime,LastChangeTime,
 * Archive} and Algorithm_NotingFileModified_Dir_{LastModificationTime,
 * LastChangeTime} test [MS-FSA] 2.1.4.17. A write to a file, or a new
 * file in a directory, updates the write and change times. The creation
 * time does not change. A written file has FILE_ATTRIBUTE_ARCHIVE.
 */
static bool test_msfsa_noting_modified(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h = {};
	int dir;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		struct msfsa_basic before = {}, after = {};
		const char *name = dir ? MSFSA_DIR "\\mod_dir" :
			MSFSA_DIR "\\mod_file";

		status = msfsa_create(tree, mem_ctx, name, dir, MSFSA_RW,
				      MSFSA_SHARE_ALL, NTCREATEX_DISP_CREATE,
				      &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create");
		status = msfsa_query_basic(tree, mem_ctx, h, &before);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"query");
		smb_msleep(MSFSA_DELAY_MS);
		if (dir) {
			status = msfsa_touch(tree, mem_ctx,
					     MSFSA_DIR "\\mod_dir\\inner");
		} else {
			status = msfsa_write_new(tree, h, 1024, 'm');
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"modify");
		smb2_util_close(tree, h);
		status = msfsa_create(tree, mem_ctx, name, dir, MSFSA_RW,
				      MSFSA_SHARE_ALL, NTCREATEX_DISP_OPEN,
				      &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open");
		status = msfsa_query_basic(tree, mem_ctx, h, &after);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"query");
		torture_assert_u64_equal_goto(tctx, after.t[MSFSA_CREATE],
					      before.t[MSFSA_CREATE], ret,
					      done, "creation time changed");
		torture_assert_goto(tctx,
				    after.t[MSFSA_WRITE] >
				    before.t[MSFSA_WRITE],
				    ret, done, "LastWriteTime did not change");
		torture_assert_goto(tctx,
				    after.t[MSFSA_CHANGE] >
				    before.t[MSFSA_CHANGE],
				    ret, done, "ChangeTime did not change");
		if (!dir) {
			torture_assert_goto(
				tctx, after.attrib & FILE_ATTRIBUTE_ARCHIVE,
				ret, done, "no FILE_ATTRIBUTE_ARCHIVE");
		}
		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
	}
done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * FsInfo_Query_FileFsSectorSizeInformation_File_
 * OutputBufferSizeEqualToSectorSizeInfo,
 * FsInfo_Query_FileFsObjectIdInformation_File_IsObjectIdSupported,
 * FsInfo_Query_FileFsAttributeInformation_File_IsObjectIDsSupported,
 * FsInfo_Query_FileFsAttributeInformation_File_IsIntegritySupported,
 * FileInfo_Query_FileBasicInfo_File_IsIntegritySupported,
 * BVT_FsCtl_CreateOrGetObjectId_{File,Dir}_IsSupported and
 * FsCtl_{Get,Set}_IntegrityInformation_{File,Dir}_IsIntegritySupported.
 * The port runs each check on a file and on a directory. Samba supports
 * object IDs. It does not support integrity streams.
 */
static bool test_msfsa_fs_info(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	/*
	 * ChecksumAlgorithm is CHECKSUM_TYPE_CRC64. Flags is
	 * FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF. The Microsoft test
	 * sends the same buffer.
	 */
	uint8_t set_integrity[8] = { 0x02, 0, 0, 0, 0x01, 0, 0, 0 };
	struct smb2_handle h = {};
	DATA_BLOB b = {};
	int dir;
	NTSTATUS status;
	bool ret = true;

	if (!msfsa_setup(tctx, tree)) {
		return false;
	}
	for (dir = 0; dir <= 1; dir++) {
		struct msfsa_basic basic = {};
		const char *name = dir ? MSFSA_DIR "\\fs_dir" :
			MSFSA_DIR "\\fs_file";

		status = msfsa_create(tree, mem_ctx, name, dir,
				      SEC_GENERIC_ALL, MSFSA_SHARE_ALL,
				      NTCREATEX_DISP_OPEN_IF, &h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"create");

		/* FILE_FS_SECTOR_SIZE_INFORMATION is 28 bytes long. */
		status = msfsa_getinfo(
			tree, mem_ctx, h, SMB2_0_INFO_FILESYSTEM,
			MSFSA_CLASS(SMB_QFS_SECTOR_SIZE_INFORMATION), 28, &b);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"FileFsSectorSizeInformation");

		status = msfsa_getinfo(
			tree, mem_ctx, h, SMB2_0_INFO_FILESYSTEM,
			MSFSA_CLASS(SMB_QFS_OBJECTID_INFORMATION), 64, &b);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"FileFsObjectIdInformation");
		torture_assert_goto(tctx, b.length >= 16 &&
				    !msfsa_all_zero(b.data, 16),
				    ret, done, "ObjectId is empty");

		status = msfsa_getinfo(
			tree, mem_ctx, h, SMB2_0_INFO_FILESYSTEM,
			MSFSA_CLASS(SMB_QFS_ATTRIBUTE_INFORMATION), 1024, &b);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"FileFsAttributeInformation");
		torture_assert_goto(tctx, b.length >= 4, ret, done,
				    "short FileFsAttributeInformation");
		torture_assert_goto(tctx,
				    IVAL(b.data, 0) & FILE_SUPPORTS_OBJECT_IDS,
				    ret, done, "no FILE_SUPPORTS_OBJECT_IDS");
		torture_assert_goto(tctx,
				    !(IVAL(b.data, 0) & MSFSA_FS_INTEGRITY),
				    ret, done,
				    "FILE_SUPPORTS_INTEGRITY_STREAMS is set");

		status = msfsa_query_basic(tree, mem_ctx, h, &basic);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"FileBasicInformation");
		torture_assert_goto(tctx,
				    !(basic.attrib & MSFSA_ATTR_INTEGRITY),
				    ret, done,
				    "FILE_ATTRIBUTE_INTEGRITY_STREAM is set");

		/* The reply is a FILE_OBJECTID_BUFFER of type 1. */
		status = msfsa_fsctl(tree, mem_ctx, h,
				     FSCTL_CREATE_OR_GET_OBJECT_ID,
				     data_blob_null, 64, &b);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"FSCTL_CREATE_OR_GET_OBJECT_ID");
		torture_assert_int_equal_goto(tctx, b.length, 64, ret, done,
					      "size of FILE_OBJECTID_BUFFER");
		torture_assert_goto(tctx, !msfsa_all_zero(b.data, 16), ret,
				    done, "ObjectId is empty");
		torture_assert_goto(tctx, !msfsa_all_zero(b.data + 16, 16),
				    ret, done, "BirthVolumeId is empty");
		torture_assert_goto(tctx, !msfsa_all_zero(b.data + 32, 16),
				    ret, done, "BirthObjectId is empty");
		torture_assert_goto(tctx, msfsa_all_zero(b.data + 48, 16),
				    ret, done, "DomainId is not empty");

		status = msfsa_fsctl(tree, mem_ctx, h,
				     FSCTL_GET_INTEGRITY_INFORMATION,
				     data_blob_null, 16, &b);
		torture_assert_ntstatus_equal_goto(
			tctx, status, NT_STATUS_INVALID_DEVICE_REQUEST, ret,
			done, "FSCTL_GET_INTEGRITY_INFORMATION");
		status = msfsa_fsctl(tree, mem_ctx, h,
				     FSCTL_SET_INTEGRITY_INFORMATION,
				     data_blob_const(set_integrity,
						     sizeof(set_integrity)),
				     0, &b);
		torture_assert_ntstatus_equal_goto(
			tctx, status, NT_STATUS_INVALID_DEVICE_REQUEST, ret,
			done, "FSCTL_SET_INTEGRITY_INFORMATION");

		smb2_util_close(tree, h);
		ZERO_STRUCT(h);
	}
done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MSFSA_DIR);
	talloc_free(mem_ctx);
	return ret;
}

void torture_truenas_msfsa_suite(struct torture_suite *suite)
{
	struct torture_suite *msfsa = torture_suite_create(suite, "msfsa");

	msfsa->description = talloc_strdup(
		msfsa, "MS-FSA tests of the Microsoft File Server suite");

	torture_suite_add_1smb2_test(msfsa, "search_star",
				     test_msfsa_search_star);
	torture_suite_add_1smb2_test(msfsa, "search_star_dot_star",
				     test_msfsa_search_star_dot_star);
	torture_suite_add_1smb2_test(msfsa, "search_question_mark",
				     test_msfsa_search_question_mark);
	torture_suite_add_1smb2_test(msfsa, "search_star_in_name",
				     test_msfsa_search_star_in_name);
	torture_suite_add_1smb2_test(msfsa, "search_dos_star",
				     test_msfsa_search_dos_star);
	torture_suite_add_1smb2_test(msfsa, "search_dos_qm",
				     test_msfsa_search_dos_qm);
	torture_suite_add_1smb2_test(msfsa, "search_single_entry",
				     test_msfsa_search_single_entry);
	torture_suite_add_1smb2_test(msfsa, "basic_set_times",
				     test_msfsa_basic_set_times);
	torture_suite_add_1smb2_test(msfsa, "basic_set_zero",
				     test_msfsa_basic_set_zero);
	torture_suite_add_1smb2_test(msfsa, "create_time_io",
				     test_msfsa_create_time_io);
	torture_suite_add_1smb2_test(msfsa, "query_info",
				     test_msfsa_query_info);
	torture_suite_add_1smb2_test(msfsa, "stream_create",
				     test_msfsa_stream_create);
	torture_suite_add_1smb2_test(msfsa, "stream_write_read",
				     test_msfsa_stream_write_read);
	torture_suite_add_1smb2_test(msfsa, "stream_lock",
				     test_msfsa_stream_lock);
	torture_suite_add_1smb2_test(msfsa, "stream_delete",
				     test_msfsa_stream_delete);
	torture_suite_add_1smb2_test(msfsa, "noting_modified",
				     test_msfsa_noting_modified);
	torture_suite_add_1smb2_test(msfsa, "fs_info",
				     test_msfsa_fs_info);

	torture_suite_add_suite(suite, msfsa);
}
