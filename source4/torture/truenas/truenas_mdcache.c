/*
   Unix SMB/CIFS implementation.

   TrueNAS smbd metadata cache (truenas_mdcache) torture tests.

   These use FSCTL_SMBTORTURE_MDCACHE to shorten the cache's idle timeout
   and read its size, so smbd needs "smbd:FSCTL_SMBTORTURE = yes". They
   self-skip on shares where nothing fills the cache (no ixnas, or a kernel
   without STATX_CHANGE_COOKIE). A listing uses the cache only with
   "ea support = no", as middleware sets it. "abe" also needs TrueNAS ABE
   on the share (ixnas:truenas_abe, the default) and a user who is not
   root.

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
#include "libcli/security/security.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"

#define MDC_DIR		"truenas_mdcache"
#define MDC_FILES	50
#define MDC_IDLE	2	/* seconds */
#define ABE_DIR		"truenas_mdcache_abe"
#define ONE_DIR		"truenas_mdcache_one"

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

/* How mdc_fsctl() fails without "smbd:FSCTL_SMBTORTURE = yes" */
static bool mdc_no_fsctl(NTSTATUS status)
{
	return NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST) ||
	       NT_STATUS_EQUAL(status, NT_STATUS_FS_DRIVER_REQUIRED) ||
	       NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED);
}

/* Create the test files in MDC_DIR, f0 hidden */
static bool mdc_create_files(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	struct smb2_handle fh = {{0}};
	NTSTATUS status;
	int i;

	for (i = 0; i < MDC_FILES; i++) {
		const char *fname = talloc_asprintf(tctx, MDC_DIR "\\f%d", i);

		status = torture_smb2_testfile(tree, fname, &fh);
		torture_assert_ntstatus_ok(tctx, status, "create file");
		smb2_util_close(tree, fh);
	}
	status = smb2_util_setatr(tree, MDC_DIR "\\f0", FILE_ATTRIBUTE_HIDDEN);
	torture_assert_ntstatus_ok(tctx, status, "set FILE_ATTRIBUTE_HIDDEN");
	return true;
}

static bool mdc_find_all(struct torture_context *tctx,
			 struct smb2_tree *tree,
			 struct smb2_handle h,
			 const char *pattern,
			 union smb_search_data **_d,
			 unsigned int *_count)
{
	struct smb2_find f;
	union smb_search_data *all = NULL;
	unsigned int n = 0;

	ZERO_STRUCT(f);
	f.in.file.handle	= h;
	f.in.pattern		= pattern;
	f.in.max_response_size	= 0x10000;
	f.in.level		= SMB2_FIND_BOTH_DIRECTORY_INFO;
	f.in.continue_flags	= SMB2_CONTINUE_FLAG_RESTART;

	for (;;) {
		union smb_search_data *d = NULL;
		unsigned int count;
		NTSTATUS status;

		status = smb2_find_level(tree, tctx, &f, &count, &d);
		if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES) ||
		    (NT_STATUS_IS_OK(status) && (count == 0))) {
			break;
		}
		torture_assert_ntstatus_ok(tctx, status, "smb2_find_level");
		f.in.continue_flags = 0;

		all = talloc_realloc(tctx, all, union smb_search_data,
				     n + count);
		torture_assert(tctx, all != NULL, "talloc_realloc");
		memcpy(&all[n], d, count * sizeof(*d));
		n += count;
	}
	*_d = all;
	*_count = n;
	return true;
}

static const union smb_search_data *mdc_entry(const union smb_search_data *d,
					      unsigned int count,
					      const char *name)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (strcmp(d[i].both_directory_info.name.s, name) == 0) {
			return &d[i];
		}
	}
	return NULL;
}

/* Check a listing of h has every test file, with f0 hidden */
static bool mdc_find(struct torture_context *tctx,
		     struct smb2_tree *tree,
		     struct smb2_handle h)
{
	union smb_search_data *d = NULL;
	const union smb_search_data *f0 = NULL;
	unsigned int count;

	torture_assert(tctx, mdc_find_all(tctx, tree, h, "f*", &d, &count),
		       "list");
	torture_assert_int_equal(tctx, count, MDC_FILES, "files listed");
	f0 = mdc_entry(d, count, "f0");
	torture_assert(tctx,
		       (f0 != NULL) &&
		       (f0->both_directory_info.attrib & FILE_ATTRIBUTE_HIDDEN),
		       "f0 listed as hidden");
	return true;
}

static bool mdc_list(struct torture_context *tctx,
		     struct smb2_tree *tree,
		     struct smb2_handle *_h)
{
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	bool ret;

	status = torture_smb2_testdir(tree, MDC_DIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "open directory");

	ret = mdc_find(tctx, tree, h);
	if ((_h != NULL) && ret) {
		*_h = h;
	} else {
		smb2_util_close(tree, h);
	}
	return ret;
}

static bool mdc_setup(struct torture_context *tctx,
		      struct smb2_tree *tree,
		      uint32_t idle,
		      struct smb2_handle *h,
		      struct smb2_handle *_lh,
		      uint32_t *slots,
		      uint32_t *count,
		      const char **skip)
{
	NTSTATUS status;

	*skip = NULL;
	smb2_deltree(tree, MDC_DIR);
	status = torture_smb2_testdir(tree, MDC_DIR, h);
	torture_assert_ntstatus_ok(tctx, status, "create directory");

	status = mdc_fsctl(tctx, tree, *h, idle, slots, count);
	if (mdc_no_fsctl(status)) {
		*skip = "smbd:FSCTL_SMBTORTURE is not enabled\n";
		return true;
	}
	torture_assert_ntstatus_ok(tctx, status, "FSCTL_SMBTORTURE_MDCACHE");

	torture_assert(tctx, mdc_create_files(tctx, tree),
		       "create the test files");
	torture_assert(tctx, mdc_list(tctx, tree, _lh), "first listing");
	status = mdc_fsctl(tctx, tree, *h, 0, slots, count);
	torture_assert_ntstatus_ok(tctx, status, "FSCTL_SMBTORTURE_MDCACHE");
	if (*count == 0) {
		*skip = "nothing fills the metadata cache on this share\n";
	}
	return true;
}

/*
 * A listing fills the cache, the idle timer frees it, and the next listing
 * fills it again with the same attributes.
 */
static bool test_truenas_mdcache_idle(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	uint32_t slots = 0, count = 0;
	const char *skip = NULL;
	NTSTATUS status;
	bool ret = true;
	int i;

	torture_assert_goto(tctx,
			    mdc_setup(tctx, tree, MDC_IDLE, &h, NULL,
				      &slots, &count, &skip),
			    ret, done, "set up");
	if (skip != NULL) {
		torture_skip_goto(tctx, done, skip);
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

	torture_assert_goto(tctx, mdc_list(tctx, tree, NULL), ret, done,
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

/*
 * A tree disconnect closes a directory handle that listed from the cache.
 * The listing gave the handle an fsp for its entries. Only the handle
 * frees that fsp.
 */
static bool test_truenas_mdcache_tdis(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	struct smb2_tree *tree2 = NULL;
	struct smb2_handle h = {{0}};
	struct smb2_handle h2 = {{0}};
	uint32_t slots = 0, count = 0;
	const char *skip = NULL;
	NTSTATUS status;
	bool ret = true;

	torture_assert_goto(tctx,
			    mdc_setup(tctx, tree, 0, &h, NULL,
				      &slots, &count, &skip),
			    ret, done, "set up");
	if (skip != NULL) {
		torture_skip_goto(tctx, done, skip);
	}

	/*
	 * The cache keeps the ABE answers of each tree connect. The first
	 * listing on a tree stores them, the second comes from the cache.
	 */
	torture_assert_goto(tctx,
			    torture_smb2_tree_connect(tctx, tree->session,
						      tctx, &tree2),
			    ret, done, "second tree connect");
	torture_assert_goto(tctx, mdc_list(tctx, tree2, NULL), ret, done,
			    "first listing on the second tree");
	torture_assert_goto(tctx, mdc_list(tctx, tree2, &h2), ret, done,
			    "second listing on the second tree");
	status = smb2_tdis(tree2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"tree disconnect, directory open");
	torture_assert_goto(tctx, mdc_list(tctx, tree, NULL), ret, done,
			    "listing after the tree disconnect");

done:
	TALLOC_FREE(tree2);
	smb2_util_close(tree, h);
	smb2_deltree(tree, MDC_DIR);
	return ret;
}

/* Relisting an open directory from the cache keeps the idle timer off */
static bool test_truenas_mdcache_relist(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	int idle = torture_setting_int(tctx, "mdcache_idle", MDC_IDLE);
	int secs = torture_setting_int(tctx, "mdcache_relist_seconds",
				       4 * idle);
	struct smb2_handle h = {{0}};
	struct smb2_handle lh = {{0}};
	struct timeval start;
	uint32_t slots = 0, count = 0;
	const char *skip = NULL;
	unsigned int i;
	NTSTATUS status;
	bool ret = true;

	torture_assert_goto(tctx,
			    mdc_setup(tctx, tree, idle, &h, &lh,
				      &slots, &count, &skip),
			    ret, done, "set up");
	if (skip != NULL) {
		torture_skip_goto(tctx, done, skip);
	}

	/* Four listings a second, by default for four idle timeouts */
	start = timeval_current();
	for (i = 0; i < 4 * (unsigned int)secs; i++) {
		status = mdc_fsctl(tctx, tree, h, 0, &slots, &count);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"FSCTL_SMBTORTURE_MDCACHE");
		torture_assert_goto(tctx, slots != 0, ret, done,
				    talloc_asprintf(tctx, "cache freed after "
						    "%.1f s of listings",
						    timeval_elapsed(&start)));
		torture_assert_goto(tctx, mdc_find(tctx, tree, lh), ret, done,
				    "listing again");
		smb_msleep(250);
	}

done:
	smb2_util_close(tree, lh);
	smb2_util_close(tree, h);
	smb2_deltree(tree, MDC_DIR);
	return ret;
}

/* Set the DACL of h to one entry: sid is allowed access_mask */
static NTSTATUS abe_set_dacl(struct torture_context *tctx,
			     struct smb2_tree *tree,
			     struct smb2_handle h,
			     const char *sid,
			     uint32_t access_mask)
{
	struct security_descriptor *sd = NULL;

	sd = security_descriptor_dacl_create(tctx, 0, NULL, NULL,
					     sid,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     access_mask,
					     0,
					     NULL);
	if (sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	return truenas_acl_set(tree, h, sd);
}

/* TrueNAS ABE, from the open and from the cache. Needs a non-root user. */
static bool test_truenas_mdcache_abe(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	struct smb2_handle fh = {{0}};
	struct security_descriptor *sd = NULL;
	union smb_search_data *d = NULL;
	const char *owner = NULL;
	uint32_t slots = 0, count = 0;
	unsigned int n, i;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, ABE_DIR);
	status = torture_smb2_testdir(tree, ABE_DIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory");

	status = torture_smb2_testfile(tree, ABE_DIR "\\readable", &fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create readable");
	smb2_util_close(tree, fh);

	/* The owner of "hidden" may still read and change its ACL */
	status = torture_smb2_testfile(tree, ABE_DIR "\\hidden", &fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create hidden");
	status = truenas_acl_get(tree, tctx, fh, SECINFO_OWNER, &sd);
	if (NT_STATUS_IS_OK(status)) {
		owner = dom_sid_string(tctx, sd->owner_sid);
		status = abe_set_dacl(tctx, tree, fh, owner,
				      SEC_STD_READ_CONTROL |
				      SEC_STD_WRITE_DAC);
	}
	smb2_util_close(tree, fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"take read access from hidden");

	status = mdc_fsctl(tctx, tree, h, 0, &slots, &count);
	if (mdc_no_fsctl(status)) {
		torture_skip_goto(tctx, done,
				  "smbd:FSCTL_SMBTORTURE is not enabled\n");
	}
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SMBTORTURE_MDCACHE");
	if (count == 0) {
		/* Without ixnas there is no TrueNAS ABE either */
		torture_skip_goto(tctx, done, "nothing fills the metadata "
				  "cache on this share\n");
	}

	status = torture_smb2_testfile_access(tree, ABE_DIR "\\hidden", &fh,
					      SEC_FILE_READ_DATA);
	if (NT_STATUS_IS_OK(status)) {
		smb2_util_close(tree, fh);
		torture_skip_goto(tctx, done,
				  "the user can read any file (root?)\n");
	}
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED, ret, done,
					   "open hidden for reading");

	/* The first listing opens the files, the second uses the cache */
	for (i = 0; i < 2; i++) {
		const char *which = (i == 0) ? "first" : "cached";

		torture_assert_goto(tctx,
				    mdc_find_all(tctx, tree, h, "*", &d, &n),
				    ret, done, "list");
		torture_assert_goto(tctx, mdc_entry(d, n, "readable") != NULL,
				    ret, done,
				    talloc_asprintf(tctx, "%s listing: readable "
						    "file not listed", which));
		torture_assert_goto(tctx, mdc_entry(d, n, "hidden") == NULL,
				    ret, done,
				    talloc_asprintf(tctx, "%s listing: file "
						    "without read access "
						    "listed", which));
	}

done:
	if (owner != NULL) {
		/* Give the owner back full control, so the directory can go */
		status = torture_smb2_testfile_access(tree,
						      ABE_DIR "\\hidden",
						      &fh,
						      SEC_STD_WRITE_DAC);
		if (NT_STATUS_IS_OK(status)) {
			abe_set_dacl(tctx, tree, fh, owner,
				     SEC_RIGHTS_FILE_ALL);
			smb2_util_close(tree, fh);
		}
	}
	smb2_util_close(tree, h);
	smb2_deltree(tree, ABE_DIR);
	return ret;
}

/* The one entry that a search for name gives on h, from its start */
static bool one_find(struct torture_context *tctx,
		     struct smb2_tree *tree,
		     struct smb2_handle h,
		     const char *name,
		     union smb_search_data *_e)
{
	union smb_search_data *d = NULL;
	unsigned int n = 0;

	torture_assert(tctx, mdc_find_all(tctx, tree, h, name, &d, &n),
		       "search");
	torture_assert_int_equal(tctx, n, 1,
				 talloc_asprintf(tctx, "entries for %s", name));
	*_e = d[0];
	return true;
}

static bool one_equal(struct torture_context *tctx,
		      const union smb_search_data *a,
		      const union smb_search_data *b,
		      const char *name)
{
	const char *what = talloc_asprintf(tctx, "%s: search for the name "
					   "against the full listing", name);

	torture_assert_int_equal(tctx, a->both_directory_info.attrib,
				 b->both_directory_info.attrib, what);
	torture_assert_u64_equal(tctx, a->both_directory_info.size,
				 b->both_directory_info.size, what);
	torture_assert_u64_equal(tctx, a->both_directory_info.alloc_size,
				 b->both_directory_info.alloc_size, what);
	torture_assert_u64_equal(tctx, a->both_directory_info.create_time,
				 b->both_directory_info.create_time, what);
	torture_assert_u64_equal(tctx, a->both_directory_info.write_time,
				 b->both_directory_info.write_time, what);
	torture_assert_u64_equal(tctx, a->both_directory_info.change_time,
				 b->both_directory_info.change_time, what);
	return true;
}

/*
 * A search for one name (no wildcard) stats the name, and smbd lists the
 * entry from that stat. The entry must be the one of a full listing, and
 * a search from the start on the same handle must see a change.
 */
static bool test_truenas_mdcache_one_name(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	const char *names[] = { "file", "dir" };
	struct smb2_handle h = {{0}};
	struct smb2_handle sh = {{0}};
	struct smb2_handle fh = {{0}};
	union smb_search_data *all = NULL;
	union smb_search_data one;
	uint8_t buf[4096] = {0};
	unsigned int nall = 0;
	uint32_t slots = 0, count = 0;
	size_t i;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, ONE_DIR);
	status = torture_smb2_testdir(tree, ONE_DIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory");
	status = torture_smb2_testfile(tree, ONE_DIR "\\file", &fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file");
	status = smb2_util_write(tree, fh, buf, 0, 1);
	smb2_util_close(tree, fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	status = torture_smb2_testdir(tree, ONE_DIR "\\dir", &fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create subdirectory");
	smb2_util_close(tree, fh);

	torture_assert_goto(tctx, mdc_find_all(tctx, tree, h, "*", &all, &nall),
			    ret, done, "list");

	status = mdc_fsctl(tctx, tree, h, 0, &slots, &count);
	if (mdc_no_fsctl(status)) {
		torture_skip_goto(tctx, done,
				  "smbd:FSCTL_SMBTORTURE is not enabled\n");
	}
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SMBTORTURE_MDCACHE");
	if (count == 0) {
		/* Only a listing from the cache uses the stat of the search */
		torture_skip_goto(tctx, done, "nothing fills the metadata "
				  "cache on this share\n");
	}

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		const union smb_search_data *e = mdc_entry(all, nall, names[i]);

		torture_assert_goto(tctx, e != NULL, ret, done,
				    talloc_asprintf(tctx, "%s listed",
						    names[i]));
		status = torture_smb2_testdir(tree, ONE_DIR, &sh);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"open directory");
		torture_assert_goto(tctx,
				    one_find(tctx, tree, sh, names[i], &one),
				    ret, done, "search for one name");
		torture_assert_goto(tctx, one_equal(tctx, e, &one, names[i]),
				    ret, done, "entry");
		smb2_util_close(tree, sh);
		ZERO_STRUCT(sh);
	}

	status = torture_smb2_testdir(tree, ONE_DIR, &sh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open directory");
	torture_assert_goto(tctx, one_find(tctx, tree, sh, "file", &one),
			    ret, done, "search for one name");
	torture_assert_u64_equal_goto(tctx, one.both_directory_info.size, 1,
				      ret, done, "size before the write");

	status = torture_smb2_testfile(tree, ONE_DIR "\\file", &fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open file");
	status = smb2_util_write(tree, fh, buf, 1, sizeof(buf));
	smb2_util_close(tree, fh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");

	torture_assert_goto(tctx, one_find(tctx, tree, sh, "file", &one),
			    ret, done, "search for one name again");
	torture_assert_u64_equal_goto(tctx, one.both_directory_info.size,
				      1 + sizeof(buf), ret, done,
				      "size after the write");

done:
	if (!smb2_util_handle_empty(sh)) {
		smb2_util_close(tree, sh);
	}
	smb2_util_close(tree, h);
	smb2_deltree(tree, ONE_DIR);
	return ret;
}

void torture_truenas_mdcache_suite(struct torture_suite *suite)
{
	struct torture_suite *mdcache = torture_suite_create(suite, "mdcache");

	torture_suite_add_1smb2_test(mdcache, "idle",
				     test_truenas_mdcache_idle);
	torture_suite_add_1smb2_test(mdcache, "tdis",
				     test_truenas_mdcache_tdis);
	torture_suite_add_1smb2_test(mdcache, "relist",
				     test_truenas_mdcache_relist);
	torture_suite_add_1smb2_test(mdcache, "abe",
				     test_truenas_mdcache_abe);
	torture_suite_add_1smb2_test(mdcache, "one_name",
				     test_truenas_mdcache_one_name);

	torture_suite_add_suite(suite, mdcache);
}
