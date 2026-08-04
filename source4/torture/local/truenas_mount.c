/*
   Unix SMB/CIFS implementation.

   Local tests for the TrueNAS mount and dataset-resolution libraries:
   source3/lib/truenas_mount (statmount(2)/listmount(2) wrapping) and
   source3/modules/smb_libzfs (mount ID -> ZFS dataset resolution).

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

   The pure unit tests run anywhere; the syscall tests skip on kernels
   without statmount(2). The ZFS-backed tests skip unless torture options
   describe prepared datasets (provisioned by
   .github/workflows/scripts/qemu-4-test.sh):

     torture:tn_mount_ds         dataset name (casesensitivity=sensitive)
     torture:tn_mount_mp         its mountpoint
     torture:tn_mount_ci_mp      mountpoint of a casesensitivity=insensitive
                                 dataset
     torture:tn_mount_legacy_ds  dataset with mountpoint=legacy
     torture:tn_mount_legacy_mp  where the legacy dataset is mounted
     torture:tn_mount_space_ds   dataset whose name contains a space
     torture:tn_mount_space_mp   its mountpoint
     torture:tn_mount_snap_name  name of a snapshot of tn_mount_ds
     torture:tn_mount_snap_path  path inside the snapshot automount

   torture:tn_mount_require_all=yes (set by the CI invocation) turns
   every environmental skip -- unconfigured datasets, no statmount(2),
   not root, no mount namespace -- into a hard failure, so a
   provisioning or option mistake cannot silently pass as an all-skip
   green run: with it set, the suites only pass if every test really
   ran against live ZFS on a statmount-capable kernel.
*/

#include "includes.h"
#include "torture/torture.h"
#include "torture/local/proto.h"

#include <limits.h>
#include <sys/mount.h>
#include <sched.h>

#include "source3/lib/truenas_mount.h"
#include "source3/modules/smb_libzfs.h"

static bool test_has_opt(struct torture_context *tctx)
{
	struct tn_mount_entry e = {
		.mnt_opts = "xattr,posixacl,casesensitive",
	};
	bool ok;

	ok = tn_mount_has_opt(&e, "xattr");
	torture_assert(tctx, ok, "first token");
	ok = tn_mount_has_opt(&e, "posixacl");
	torture_assert(tctx, ok, "middle token");
	ok = tn_mount_has_opt(&e, "casesensitive");
	torture_assert(tctx, ok, "last token");

	/* whole-token matches only */
	ok = tn_mount_has_opt(&e, "case");
	torture_assert(tctx, !ok, "prefix");
	ok = tn_mount_has_opt(&e, "casesensitiv");
	torture_assert(tctx, !ok, "truncated token");
	ok = tn_mount_has_opt(&e, "casesensitivex");
	torture_assert(tctx, !ok, "extended token");
	ok = tn_mount_has_opt(&e, "acl");
	torture_assert(tctx, !ok, "substring");
	ok = tn_mount_has_opt(&e, "noatime");
	torture_assert(tctx, !ok, "absent token");

	e.mnt_opts = NULL;
	ok = tn_mount_has_opt(&e, "xattr");
	torture_assert(tctx, !ok, "NULL opts");

	e.mnt_opts = "";
	ok = tn_mount_has_opt(&e, "xattr");
	torture_assert(tctx, !ok, "empty opts");

	e.mnt_opts = "single";
	ok = tn_mount_has_opt(&e, "single");
	torture_assert(tctx, ok, "only token");
	ok = tn_mount_has_opt(&e, "sing");
	torture_assert(tctx, !ok, "prefix of only token");

	return true;
}

static bool test_readonly_flag(struct torture_context *tctx)
{
	struct tn_mount_entry e = {};
	bool ok;

	ok = tn_mount_is_readonly(&e);
	torture_assert(tctx, !ok, "rw");

	e.sb_flags = 0x01;	/* SB_RDONLY */
	ok = tn_mount_is_readonly(&e);
	torture_assert(tctx, ok, "ro");

	return true;
}

static bool statmount_available(void)
{
	struct tn_mount_entry *e = NULL;
	int ret;

	ret = tn_mount_entry_get_path(NULL, "/", &e);
	if (ret != 0) {
		return false;
	}
	TALLOC_FREE(e);
	return true;
}

/*
 * Skip for an environmental reason -- unless tn_mount_require_all is
 * set, in which case the missing prerequisite is a test failure.
 * Usage: return tn_skip_or_fail(tctx, "reason");
 */
static bool tn_skip_or_fail(struct torture_context *tctx,
			    const char *reason)
{
	bool require_all;

	require_all = torture_setting_bool(tctx, "tn_mount_require_all",
					   false);
	if (require_all) {
		torture_result(tctx, TORTURE_FAIL,
			       "%s, but torture:tn_mount_require_all=yes",
			       reason);
		return false;
	}
	torture_result(tctx, TORTURE_SKIP, "%s", reason);
	return true;
}

static bool test_lookup_equivalence(struct torture_context *tctx)
{
	struct tn_mount_entry *by_path = NULL;
	struct tn_mount_entry *by_id = NULL;
	struct tn_mount_entry *copy = NULL;
	uint64_t mnt_id;
	int ret;

	if (!statmount_available()) {
		return tn_skip_or_fail(tctx, "no statmount(2) on this kernel");
	}

	ret = tn_mount_entry_get_path(tctx, "/", &by_path);
	torture_assert_int_equal(tctx, ret, 0, "lookup by path");
	torture_assert(tctx, by_path->mnt_id != 0, "mnt_id set");
	torture_assert(tctx, by_path->mask != 0, "mask set");
	torture_assert(tctx, by_path->mnt_point != NULL, "mnt_point set");
	torture_assert(tctx, by_path->mnt_root != NULL, "mnt_root set");
	torture_assert(tctx, by_path->fs_type != NULL, "fs_type set");

	ret = tn_mount_path_get_mnt_id("/", &mnt_id);
	torture_assert_int_equal(tctx, ret, 0, "mnt_id by path");
	torture_assert_u64_equal(tctx, mnt_id, by_path->mnt_id,
				 "mnt_id lookups agree");

	ret = tn_mount_entry_get(tctx, mnt_id, &by_id);
	torture_assert_int_equal(tctx, ret, 0, "lookup by id");
	torture_assert_u64_equal(tctx, by_id->mnt_id, by_path->mnt_id,
				 "id/path mnt_id agree");
	torture_assert_str_equal(tctx, by_id->mnt_point, by_path->mnt_point,
				 "id/path mnt_point agree");
	torture_assert_u64_equal(tctx, by_id->sb_dev, by_path->sb_dev,
				 "sb_dev agrees");

	copy = tn_mount_entry_copy(tctx, by_id);
	torture_assert(tctx, copy != NULL, "copy");
	torture_assert_u64_equal(tctx, copy->mnt_id, by_id->mnt_id,
				 "copied mnt_id");
	torture_assert_u64_equal(tctx, copy->mask, by_id->mask,
				 "copied mask");
	torture_assert_str_equal(tctx, copy->mnt_point, by_id->mnt_point,
				 "copied mnt_point");
	torture_assert_str_equal(tctx, copy->fs_type, by_id->fs_type,
				 "copied fs_type");

	return true;
}

static bool test_stale_mnt_id(struct torture_context *tctx)
{
	struct tn_mount_entry *e = NULL;
	int ret;
	int saved_errno;

	if (!statmount_available()) {
		return tn_skip_or_fail(tctx, "no statmount(2) on this kernel");
	}

	ret = tn_mount_entry_get(tctx, 0xdeadbeefcafeULL, &e);
	saved_errno = errno;
	torture_assert_int_equal(tctx, ret, -1, "bogus id fails");
	torture_assert_int_equal(tctx, saved_errno, ENOENT,
				 "bogus id fails ENOENT");

	return true;
}

struct traverse_state {
	size_t count;
	size_t limit;		/* stop after this many, 0 = no limit */
	uint64_t *ids;		/* when non-NULL, record up to limit ids */
};

static bool traverse_cb(const struct tn_mount_entry *entry,
			void *private_data)
{
	struct traverse_state *ts = private_data;

	if (ts->ids != NULL && ts->count < ts->limit) {
		ts->ids[ts->count] = entry->mnt_id;
	}
	ts->count++;
	if (ts->limit != 0 && ts->count >= ts->limit) {
		return false;
	}
	return true;
}

static bool test_traverse(struct torture_context *tctx)
{
	struct traverse_state fwd = {};
	struct traverse_state rev = {};
	struct traverse_state one = { .limit = 1 };
	int ret;

	if (!statmount_available()) {
		return tn_skip_or_fail(tctx, "no statmount(2) on this kernel");
	}

	ret = tn_mount_traverse(TN_MOUNT_NS_ROOT, false, traverse_cb, &fwd);
	torture_assert_int_equal(tctx, ret, 0, "forward traverse");
	torture_assert(tctx, fwd.count > 0, "at least one mount");

	ret = tn_mount_traverse(TN_MOUNT_NS_ROOT, true, traverse_cb, &rev);
	torture_assert_int_equal(tctx, ret, 0, "reverse traverse");
	torture_assert_int_equal(tctx, rev.count, fwd.count,
				 "both directions see every mount");

	ret = tn_mount_traverse(TN_MOUNT_NS_ROOT, false, traverse_cb, &one);
	torture_assert_int_equal(tctx, ret, 0, "early-stop traverse");
	torture_assert_int_equal(tctx, one.count, 1,
				 "callback stop is honored");

	return true;
}

static int cmp_u64(const void *a, const void *b)
{
	const uint64_t *ua = a;
	const uint64_t *ub = b;

	if (*ua < *ub) {
		return -1;
	}
	return (*ua > *ub) ? 1 : 0;
}

/*
 * Regression test for listmount() continuation across the internal batch
 * size, in both directions: the continuation cursor and the direction
 * flag must never mix (cf. truenas_pyos NAS-141922, where reverse
 * iteration returned corrupt results past the first batch). Needs enough
 * privilege for a private mount namespace; skipped otherwise. The
 * namespace change is process-wide, so this must stay the last test of
 * the suite.
 */
#define TEST_STACK_MOUNTS 300

/*
 * A traversal rooted at a mount ID visits the mounts below that mount and
 * nothing else -- not the mount itself, and not its peers elsewhere in the
 * namespace. smb_libzfs relies on this to find a dataset by name within a
 * known subtree instead of scanning the whole namespace.
 */
static bool test_traverse_scope(struct torture_context *tctx)
{
	char tmpl[] = "/tmp/tn_mount_scope_XXXXXX";
	char *dir = NULL;
	char *child = NULL;
	char *peer = NULL;
	struct traverse_state below = {};
	struct traverse_state leaf = {};
	struct traverse_state all = {};
	uint64_t below_ids[16] = {};
	uint64_t dir_id;
	uint64_t child_id;
	uint64_t peer_id;
	int ret;

	if (!statmount_available()) {
		return tn_skip_or_fail(tctx, "no statmount(2) on this kernel");
	}
	if (geteuid() != 0) {
		return tn_skip_or_fail(tctx, "not root");
	}
	ret = unshare(CLONE_NEWNS);
	if (ret != 0) {
		return tn_skip_or_fail(tctx,
			"cannot create a private mount namespace");
	}
	ret = mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
	torture_assert_int_equal(tctx, ret, 0, "make namespace private");

	dir = mkdtemp(tmpl);
	torture_assert(tctx, dir != NULL, "mkdtemp");

	ret = mount("tn_mount_test", dir, "tmpfs", 0, "size=64k");
	torture_assert_int_equal(tctx, ret, 0, "mount parent tmpfs");

	child = talloc_asprintf(tctx, "%s/child", dir);
	peer = talloc_asprintf(tctx, "%s/peer", dir);
	torture_assert(tctx, child != NULL && peer != NULL, "alloc");

	ret = mkdir(child, 0755);
	torture_assert_int_equal(tctx, ret, 0, "mkdir child");
	ret = mkdir(peer, 0755);
	torture_assert_int_equal(tctx, ret, 0, "mkdir peer");

	ret = mount("tn_mount_test", child, "tmpfs", 0, "size=64k");
	torture_assert_int_equal(tctx, ret, 0, "mount child tmpfs");
	ret = mount("tn_mount_test", peer, "tmpfs", 0, "size=64k");
	torture_assert_int_equal(tctx, ret, 0, "mount peer tmpfs");

	ret = tn_mount_path_get_mnt_id(dir, &dir_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id of parent");
	ret = tn_mount_path_get_mnt_id(child, &child_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id of child");
	ret = tn_mount_path_get_mnt_id(peer, &peer_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id of peer");

	below.ids = below_ids;
	below.limit = ARRAY_SIZE(below_ids);
	ret = tn_mount_traverse(dir_id, false, traverse_cb, &below);
	torture_assert_int_equal(tctx, ret, 0, "traverse below parent");
	torture_assert_int_equal(tctx, below.count, 2,
				 "only the two mounts below the parent");
	torture_assert(tctx,
		       ((below_ids[0] == child_id) &&
			(below_ids[1] == peer_id)) ||
		       ((below_ids[0] == peer_id) &&
			(below_ids[1] == child_id)),
		       "the child and peer mounts, and no other");

	ret = tn_mount_traverse(child_id, false, traverse_cb, &leaf);
	torture_assert_int_equal(tctx, ret, 0, "traverse below child");
	torture_assert_int_equal(tctx, leaf.count, 0,
				 "nothing is mounted below the child");

	ret = tn_mount_traverse(TN_MOUNT_NS_ROOT, false, traverse_cb, &all);
	torture_assert_int_equal(tctx, ret, 0, "traverse namespace");
	torture_assert(tctx, all.count > below.count,
		       "the namespace holds more than that subtree");

	return true;
}

static bool test_traverse_batch_boundary(struct torture_context *tctx)
{
	char tmpl[] = "/tmp/tn_mount_test_XXXXXX";
	char *dir = NULL;
	uint64_t *fwd_ids = NULL;
	uint64_t *rev_ids = NULL;
	struct traverse_state fwd = {};
	struct traverse_state rev = {};
	size_t i;
	int ret;

	if (!statmount_available()) {
		return tn_skip_or_fail(tctx, "no statmount(2) on this kernel");
	}
	if (geteuid() != 0) {
		return tn_skip_or_fail(tctx, "not root");
	}
	ret = unshare(CLONE_NEWNS);
	if (ret != 0) {
		return tn_skip_or_fail(tctx,
			"cannot create a private mount namespace");
	}
	ret = mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
	torture_assert_int_equal(tctx, ret, 0, "make namespace private");

	dir = mkdtemp(tmpl);
	torture_assert(tctx, dir != NULL, "mkdtemp");

	/*
	 * Stack tmpfs overmounts on one directory; each is a distinct
	 * mount in the namespace, pushing the total well past the
	 * listmount batch size.
	 */
	for (i = 0; i < TEST_STACK_MOUNTS; i++) {
		ret = mount("tn_mount_test", dir, "tmpfs", 0, "size=64k");
		torture_assert_int_equal(tctx, ret, 0, "mount tmpfs");
	}

	fwd_ids = talloc_zero_array(tctx, uint64_t,
				    TEST_STACK_MOUNTS + 1024);
	rev_ids = talloc_zero_array(tctx, uint64_t,
				    TEST_STACK_MOUNTS + 1024);
	torture_assert(tctx, fwd_ids != NULL && rev_ids != NULL, "alloc");

	fwd.ids = fwd_ids;
	fwd.limit = TEST_STACK_MOUNTS + 1024;
	rev.ids = rev_ids;
	rev.limit = TEST_STACK_MOUNTS + 1024;

	ret = tn_mount_traverse(TN_MOUNT_NS_ROOT, false, traverse_cb, &fwd);
	torture_assert_int_equal(tctx, ret, 0, "forward traverse");
	ret = tn_mount_traverse(TN_MOUNT_NS_ROOT, true, traverse_cb, &rev);
	torture_assert_int_equal(tctx, ret, 0, "reverse traverse");

	torture_assert(tctx, fwd.count >= TEST_STACK_MOUNTS,
		       "sees the stacked mounts");
	torture_assert(tctx, fwd.count < fwd.limit, "did not hit the cap");
	torture_assert_int_equal(tctx, rev.count, fwd.count,
				 "same count in both directions");

	/* same id set in both directions, no duplicates */
	qsort(fwd_ids, fwd.count, sizeof(uint64_t), cmp_u64);
	qsort(rev_ids, rev.count, sizeof(uint64_t), cmp_u64);
	torture_assert_mem_equal(tctx, fwd_ids, rev_ids,
				 fwd.count * sizeof(uint64_t),
				 "same id set in both directions");
	for (i = 1; i < fwd.count; i++) {
		torture_assert(tctx, fwd_ids[i] != fwd_ids[i - 1],
			       "no duplicate ids");
	}

	/* the private namespace (and the stacked mounts) die with us */
	return true;
}

static const char *tn_mount_setting(struct torture_context *tctx,
				    const char *name)
{
	return torture_setting_string(tctx, name, NULL);
}

static bool test_zfs_dataset(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const char *mp = tn_mount_setting(tctx, "tn_mount_mp");
	struct tn_mount_entry *e = NULL;
	bool ok;
	int ret;

	if (ds == NULL || mp == NULL) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_ds/tn_mount_mp configured");
	}

	ret = tn_mount_entry_get_path(tctx, mp, &e);
	torture_assert_int_equal(tctx, ret, 0, "lookup");
	torture_assert(tctx, e->fs_type != NULL, "fs_type reported");
	torture_assert_str_equal(tctx, e->fs_type, "zfs", "fs_type");
	torture_assert(tctx, e->sb_source != NULL, "sb_source reported");
	torture_assert_str_equal(tctx, e->sb_source, ds,
				 "sb_source is the dataset name");
	torture_assert(tctx, e->mnt_point != NULL, "mnt_point reported");
	torture_assert_str_equal(tctx, e->mnt_point, mp, "mountpoint");
	ok = tn_mount_is_readonly(e);
	torture_assert(tctx, !ok, "read-write");
	ok = tn_mount_has_opt(e, "casesensitive");
	torture_assert(tctx, ok, "casesensitivity token");
	ok = tn_mount_has_opt(e, "caseinsensitive");
	torture_assert(tctx, !ok, "no caseinsensitive token");

	return true;
}

static bool test_zfs_caseinsensitive(struct torture_context *tctx)
{
	const char *ci_mp = tn_mount_setting(tctx, "tn_mount_ci_mp");
	struct tn_mount_entry *e = NULL;
	bool ok;
	int ret;

	if (ci_mp == NULL) {
		return tn_skip_or_fail(tctx, "no tn_mount_ci_mp configured");
	}

	ret = tn_mount_entry_get_path(tctx, ci_mp, &e);
	torture_assert_int_equal(tctx, ret, 0, "lookup");
	torture_assert_str_equal(tctx, e->fs_type, "zfs", "fs_type");
	ok = tn_mount_has_opt(e, "caseinsensitive");
	torture_assert(tctx, ok, "caseinsensitive token");
	ok = tn_mount_has_opt(e, "casesensitive");
	torture_assert(tctx, !ok, "no casesensitive token");

	return true;
}

/*
 * ZFS permits spaces in dataset names, and __zpl_show_devname() escapes
 * them as \040 so getmntent(3) can parse /proc/self/mounts. statmount(2)
 * undoes that escaping before it returns (statmount_sb_source() in
 * fs/namespace.c unescapes in place), and the mountpoint is never escaped
 * at all (statmount_mnt_point() passes an empty escape set, where
 * mountinfo passes " \t\n\\"). Both matter: smb_libzfs feeds sb_source
 * straight to zfs_open(), and mnt_point is prefix-matched against share
 * paths by recycle and shadow_copy. An escaped name would reach neither
 * libzfs nor a string compare intact.
 */
static bool test_zfs_space_in_name(struct torture_context *tctx)
{
	const char *space_ds = tn_mount_setting(tctx, "tn_mount_space_ds");
	const char *space_mp = tn_mount_setting(tctx, "tn_mount_space_mp");
	struct tn_mount_entry *e = NULL;
	const char *found = NULL;
	int ret;

	if (space_ds == NULL || space_mp == NULL) {
		return tn_skip_or_fail(tctx, "no tn_mount_space_* configured");
	}

	/* a mis-provisioned dataset would make this test vacuous */
	found = strchr(space_ds, ' ');
	torture_assert(tctx, found != NULL, "dataset name has a space in it");

	ret = tn_mount_entry_get_path(tctx, space_mp, &e);
	torture_assert_int_equal(tctx, ret, 0, "lookup");
	torture_assert_str_equal(tctx, e->fs_type, "zfs", "fs_type");
	torture_assert_str_equal(tctx, e->sb_source, space_ds,
				 "sb_source is the unescaped dataset name");
	found = strchr(e->sb_source, '\\');
	torture_assert(tctx, found == NULL, "no escape left in sb_source");
	torture_assert_str_equal(tctx, e->mnt_point, space_mp,
				 "mountpoint keeps its space");
	found = strchr(e->mnt_point, '\\');
	torture_assert(tctx, found == NULL, "no escape left in mnt_point");

	return true;
}

/*
 * mountpoint=legacy datasets have no ZFS_PROP_MOUNTPOINT to consult; the
 * mount table is the only source of truth. This is the replacement for
 * the removed /proc/self/mountinfo parser.
 */
static bool test_zfs_legacy_mountpoint(struct torture_context *tctx)
{
	const char *legacy_ds = tn_mount_setting(tctx, "tn_mount_legacy_ds");
	const char *legacy_mp = tn_mount_setting(tctx, "tn_mount_legacy_mp");
	struct tn_mount_entry *e = NULL;
	int ret;

	if (legacy_ds == NULL || legacy_mp == NULL) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_legacy_* configured");
	}

	ret = tn_mount_entry_get_path(tctx, legacy_mp, &e);
	torture_assert_int_equal(tctx, ret, 0, "lookup");
	torture_assert_str_equal(tctx, e->fs_type, "zfs", "fs_type");
	torture_assert_str_equal(tctx, e->sb_source, legacy_ds,
				 "dataset name");
	torture_assert_str_equal(tctx, e->mnt_point, legacy_mp,
				 "legacy mountpoint from the mount table");

	return true;
}

static bool test_zfs_snapshot_automount(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const char *snap_name = tn_mount_setting(tctx, "tn_mount_snap_name");
	const char *snap_path = tn_mount_setting(tctx, "tn_mount_snap_path");
	struct tn_mount_entry *e = NULL;
	char *expected = NULL;
	bool ok;
	int ret;

	if (ds == NULL || snap_name == NULL || snap_path == NULL) {
		return tn_skip_or_fail(tctx, "no tn_mount_snap_* configured");
	}

	expected = talloc_asprintf(tctx, "%s@%s", ds, snap_name);
	torture_assert(tctx, expected != NULL, "asprintf");

	/* the statx path walk triggers the automount */
	ret = tn_mount_entry_get_path(tctx, snap_path, &e);
	torture_assert_int_equal(tctx, ret, 0, "lookup");
	torture_assert_str_equal(tctx, e->fs_type, "zfs", "fs_type");
	torture_assert_str_equal(tctx, e->sb_source, expected,
				 "snapshot automount source is ds@snap");
	ok = tn_mount_is_readonly(e);
	torture_assert(tctx, ok, "snapshot mounts are read-only");

	return true;
}

struct torture_suite *torture_local_truenas_mount(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = NULL;

	suite = torture_suite_create(mem_ctx, "truenas_mount");

	torture_suite_add_simple_test(suite, "has_opt", test_has_opt);
	torture_suite_add_simple_test(suite, "readonly_flag",
				      test_readonly_flag);
	torture_suite_add_simple_test(suite, "lookup_equivalence",
				      test_lookup_equivalence);
	torture_suite_add_simple_test(suite, "stale_mnt_id",
				      test_stale_mnt_id);
	torture_suite_add_simple_test(suite, "traverse", test_traverse);
	torture_suite_add_simple_test(suite, "zfs_dataset",
				      test_zfs_dataset);
	torture_suite_add_simple_test(suite, "zfs_caseinsensitive",
				      test_zfs_caseinsensitive);
	torture_suite_add_simple_test(suite, "zfs_space_in_name",
				      test_zfs_space_in_name);
	torture_suite_add_simple_test(suite, "zfs_legacy_mountpoint",
				      test_zfs_legacy_mountpoint);
	torture_suite_add_simple_test(suite, "zfs_snapshot_automount",
				      test_zfs_snapshot_automount);

	/* keep last: these switch the process to a private mount namespace */
	torture_suite_add_simple_test(suite, "traverse_scope",
				      test_traverse_scope);
	torture_suite_add_simple_test(suite, "traverse_batch_boundary",
				      test_traverse_batch_boundary);

	suite->description = talloc_strdup(suite,
		"statmount(2)/listmount(2) wrapper library tests");
	return suite;
}

/*
 * smb_libzfs mount ID -> dataset resolution. All of these need live ZFS
 * (/dev/zfs) and the provisioned datasets, so everything skips unless
 * the torture options are set.
 */

static bool test_libzfs_conn_init(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const char *mp = tn_mount_setting(tctx, "tn_mount_mp");
	const struct zfs_dataset *zds = NULL;
	int ret;

	if (ds == NULL || mp == NULL) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_ds/tn_mount_mp configured");
	}

	ret = conn_zfs_init(mp, &zds);
	torture_assert_int_equal(tctx, ret, 0, "conn_zfs_init");
	torture_assert(tctx, zds != NULL, "dataset resolved");
	torture_assert_str_equal(tctx, zds->dataset_name, ds,
				 "dataset name");
	torture_assert_str_equal(tctx, zds->mountpoint, mp, "mountpoint");
	torture_assert(tctx, zds->mnt_id != 0, "mnt_id set");
	torture_assert(tctx, zds->properties != NULL, "properties");
	torture_assert_int_equal(tctx, zds->properties->casesens,
				 SMBZFS_SENSITIVE, "casesensitive");
	torture_assert(tctx, !zds->properties->readonly, "read-write");
	torture_assert(tctx, zds->properties->record_size != 0,
		       "recordsize from libzfs");

	return true;
}

static bool test_libzfs_caseinsensitive(struct torture_context *tctx)
{
	const char *ci_mp = tn_mount_setting(tctx, "tn_mount_ci_mp");
	const struct zfs_dataset *zds = NULL;
	int ret;

	if (ci_mp == NULL) {
		return tn_skip_or_fail(tctx, "no tn_mount_ci_mp configured");
	}

	ret = conn_zfs_init(ci_mp, &zds);
	torture_assert_int_equal(tctx, ret, 0, "conn_zfs_init");
	torture_assert(tctx, zds != NULL, "dataset resolved");
	torture_assert_int_equal(tctx, zds->properties->casesens,
				 SMBZFS_INSENSITIVE, "caseinsensitive");

	return true;
}

static bool test_libzfs_not_zfs(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const struct zfs_dataset *zds = NULL;
	int ret;

	if (ds == NULL) {
		return tn_skip_or_fail(tctx, "no tn_mount_ds configured");
	}

	/* not ZFS: succeeds with a NULL dataset */
	ret = conn_zfs_init("/proc", &zds);
	torture_assert_int_equal(tctx, ret, 0, "conn_zfs_init on procfs");
	torture_assert(tctx, zds == NULL, "no dataset for procfs");

	return true;
}

/*
 * conn_zfs_init() reports a failed lookup as an error and reserves a NULL
 * dataset with a return value of 0 for "this path is not on ZFS". Needs no
 * ZFS: procfs is never a dataset and the missing path never resolves.
 */
static bool test_libzfs_missing_path(struct torture_context *tctx)
{
	const struct zfs_dataset *zds = NULL;
	int ret;

	/* nearest existing ancestor is procfs: not ZFS, not an error */
	ret = conn_zfs_init("/proc/tn-torture-absent/child", &zds);
	torture_assert_int_equal(tctx, ret, 0, "conn_zfs_init below procfs");
	torture_assert(tctx, zds == NULL, "no dataset below procfs");

	/* nothing to resolve at all: an error */
	zds = NULL;
	ret = conn_zfs_init("/tn-torture-absent/child", &zds);
	torture_assert_int_equal(tctx, ret, -1,
				 "conn_zfs_init on unresolvable path");
	torture_assert(tctx, zds == NULL, "no dataset for absent path");

	return true;
}

static bool test_libzfs_mntid(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const char *mp = tn_mount_setting(tctx, "tn_mount_mp");
	const struct zfs_dataset *zds = NULL;
	char subdir[PATH_MAX];
	uint64_t mnt_id;
	int ret;

	if (ds == NULL || mp == NULL) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_ds/tn_mount_mp configured");
	}

	/* the mount-ID lookup the VFS modules use (st_ex_mnt_id) */
	ret = tn_mount_path_get_mnt_id(mp, &mnt_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id");

	zds = smb_zfs_lookup_dataset(mnt_id);
	torture_assert(tctx, zds != NULL, "resolve by mount id");
	torture_assert_str_equal(tctx, zds->dataset_name, ds,
				 "mount id maps to the dataset");
	torture_assert_str_equal(tctx, zds->mountpoint, mp, "mountpoint");
	torture_assert_u64_equal(tctx, zds->mnt_id, mnt_id,
				 "dataset carries its mount id");

	/* a location below the mountpoint resolves to the same dataset */
	snprintf(subdir, sizeof(subdir), "%s/local_smb_libzfs_subdir", mp);
	ret = mkdir(subdir, 0755);
	torture_assert(tctx, ret == 0 || errno == EEXIST, "mkdir subdir");

	ret = tn_mount_path_get_mnt_id(subdir, &mnt_id);
	torture_assert_int_equal(tctx, ret, 0, "subdir mount id");

	zds = smb_zfs_lookup_dataset(mnt_id);
	torture_assert(tctx, zds != NULL, "resolve subdir");
	torture_assert_str_equal(tctx, zds->dataset_name, ds,
				 "subdir maps to the dataset");
	torture_assert_str_equal(tctx, zds->mountpoint, mp, "mountpoint");

	return true;
}

/*
 * mountpoint=legacy datasets used to require parsing
 * /proc/self/mountinfo; resolution must now come uniformly from the
 * mount table.
 */
static bool test_libzfs_legacy_mountpoint(struct torture_context *tctx)
{
	const char *legacy_ds = tn_mount_setting(tctx, "tn_mount_legacy_ds");
	const char *legacy_mp = tn_mount_setting(tctx, "tn_mount_legacy_mp");
	const struct zfs_dataset *zds = NULL;
	uint64_t mnt_id;
	int ret;

	if (legacy_ds == NULL || legacy_mp == NULL) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_legacy_* configured");
	}

	ret = tn_mount_path_get_mnt_id(legacy_mp, &mnt_id);
	torture_assert_int_equal(tctx, ret, 0, "legacy mount id");

	zds = smb_zfs_lookup_dataset(mnt_id);
	torture_assert(tctx, zds != NULL, "resolve legacy mountpoint");
	torture_assert_str_equal(tctx, zds->dataset_name, legacy_ds,
				 "legacy dataset name");
	torture_assert_str_equal(tctx, zds->mountpoint, legacy_mp,
				 "legacy mountpoint from the mount table");
	torture_assert(tctx, zds->mnt_id != 0, "mnt_id set");

	return true;
}

/*
 * A path inside a snapshot automount resolves to the underlying dataset:
 * name without the @snapshot suffix, mountpoint of the live dataset.
 * FSRVP snapshot shares and VSS depend on this.
 */
static bool test_libzfs_snapshot_base(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const char *mp = tn_mount_setting(tctx, "tn_mount_mp");
	const char *snap_path = tn_mount_setting(tctx, "tn_mount_snap_path");
	const struct zfs_dataset *zds = NULL;
	uint64_t snap_mnt_id;
	int ret;

	if (ds == NULL || mp == NULL || snap_path == NULL) {
		return tn_skip_or_fail(tctx, "no tn_mount_snap_* configured");
	}

	/* the snapshot automount's own mount ID resolves to the base */
	ret = tn_mount_path_get_mnt_id(snap_path, &snap_mnt_id);
	torture_assert_int_equal(tctx, ret, 0, "snapshot mount id");

	zds = smb_zfs_lookup_dataset(snap_mnt_id);
	torture_assert(tctx, zds != NULL, "resolve by snapshot mount id");
	torture_assert_str_equal(tctx, zds->dataset_name, ds,
				 "snapshot resolves to base dataset");
	torture_assert(tctx, strchr(zds->dataset_name, '@') == NULL,
		       "no @snap in dataset name");
	torture_assert_str_equal(tctx, zds->mountpoint, mp,
				 "base dataset mountpoint");

	/* conn_zfs_init (the FSRVP snapshot-share path) agrees */
	zds = NULL;
	ret = conn_zfs_init(snap_path, &zds);
	torture_assert_int_equal(tctx, ret, 0,
				 "conn_zfs_init on snapshot path");
	torture_assert(tctx, zds != NULL, "dataset resolved");
	torture_assert_str_equal(tctx, zds->dataset_name, ds,
				 "base dataset name");
	torture_assert_str_equal(tctx, zds->mountpoint, mp,
				 "base dataset mountpoint");

	return true;
}

/*
 * Every dataset the library resolves is cached and handed out as the same
 * instance, so a share whose tree spans several datasets -- nested
 * children, or the snapshot automounts a previous-versions browse walks
 * through -- resolves each of them exactly once.
 */
static bool test_libzfs_ds_cache(struct torture_context *tctx)
{
	const char *mp = tn_mount_setting(tctx, "tn_mount_mp");
	const char *ci_mp = tn_mount_setting(tctx, "tn_mount_ci_mp");
	const char *legacy_mp = tn_mount_setting(tctx, "tn_mount_legacy_mp");
	const char *snap_path = tn_mount_setting(tctx, "tn_mount_snap_path");
	const struct zfs_dataset *root = NULL;
	const struct zfs_dataset *first = NULL;
	const struct zfs_dataset *second = NULL;
	const struct zfs_dataset *again = NULL;
	uint64_t root_id;
	uint64_t first_id;
	uint64_t second_id;
	uint64_t snap_id;
	int ret;

	if ((mp == NULL) || (ci_mp == NULL) || (legacy_mp == NULL) ||
	    (snap_path == NULL)) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_mp/tn_mount_ci_mp/tn_mount_legacy_mp/"
			"tn_mount_snap_path configured");
	}

	ret = conn_zfs_init(mp, &root);
	torture_assert_int_equal(tctx, ret, 0, "conn_zfs_init");
	torture_assert(tctx, root != NULL, "share dataset resolved");

	ret = tn_mount_path_get_mnt_id(mp, &root_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id of share root");
	ret = tn_mount_path_get_mnt_id(ci_mp, &first_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id of child dataset");
	ret = tn_mount_path_get_mnt_id(legacy_mp, &second_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id of legacy dataset");
	ret = tn_mount_path_get_mnt_id(snap_path, &snap_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id of snapshot mount");

	again = smb_zfs_lookup_dataset(root_id);
	torture_assert(tctx, again == root, "share root is the same instance");

	first = smb_zfs_lookup_dataset(first_id);
	torture_assert(tctx, first != NULL, "child dataset resolved");
	second = smb_zfs_lookup_dataset(second_id);
	torture_assert(tctx, second != NULL, "legacy dataset resolved");
	torture_assert(tctx, second != first, "distinct datasets");

	/* all of them stay cached: alternating does not re-resolve */
	again = smb_zfs_lookup_dataset(first_id);
	torture_assert(tctx, again == first, "child still cached");
	again = smb_zfs_lookup_dataset(second_id);
	torture_assert(tctx, again == second, "legacy still cached");

	/*
	 * A snapshot automount has its own mount ID and resolves to the
	 * dataset it belongs to: the very same instance, not a second copy
	 * describing the same dataset. (Whether the second lookup took the
	 * alias-cache shortcut or resolved again is not observable from
	 * here -- both reach the one cached instance.)
	 */
	again = smb_zfs_lookup_dataset(snap_id);
	torture_assert(tctx, again == root,
		       "snapshot mount resolves to the dataset instance");
	again = smb_zfs_lookup_dataset(snap_id);
	torture_assert(tctx, again == root, "and stays resolved");

	/* a stat with no mount ID is never resolved */
	again = smb_zfs_lookup_dataset(0);
	torture_assert(tctx, again == NULL, "zero mount ID rejected");

	return true;
}

/*
 * smb_libzfs has no dataset destroy of its own -- nothing in production
 * needs one -- so tear down what the auto-create test made with the CLI.
 */
static void tn_zfs_destroy(const char *dataset)
{
	char cmd[ZFSDS_NAMELEN + 64];
	int ret;

	/*
	 * Quote the name: ZFS permits spaces in dataset names, so an
	 * unquoted one would split into two arguments here. Single quotes
	 * are complete escaping because valid_char() (ZFS
	 * module/zcommon/zfs_namecheck.c) permits only alphanumerics and
	 * "-_.: " -- a name zfs accepted can never contain a quote.
	 */
	snprintf(cmd, sizeof(cmd), "zfs destroy -r '%s' >/dev/null 2>&1",
		 dataset);
	ret = system(cmd);
	if (ret != 0) {
		DBG_INFO("%s: dataset was not present\n", dataset);
	}
}

/*
 * Dataset auto-creation (zfs_core:zfs_auto_create), which runs at tree
 * connect for the private-datasets and time machine share purposes. The
 * returned array is the datasets created, deepest first, followed by the
 * pre-existing dataset they nest under -- vfs_zfs_core chdir()s to that
 * last entry and resolves the others relative to it to inherit ACLs.
 */
static bool test_libzfs_create_dataset(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const char *mp = tn_mount_setting(tctx, "tn_mount_mp");
	const struct zfs_dataset **created = NULL;
	char path[PATH_MAX];
	char subdir[PATH_MAX];
	char name[ZFSDS_NAMELEN];
	size_t nentries = 0;
	int ret;

	if ((ds == NULL) || (mp == NULL)) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_ds/tn_mount_mp configured");
	}
	if (geteuid() != 0) {
		return tn_skip_or_fail(tctx, "not root");
	}

	/* leftovers from an interrupted run */
	snprintf(name, sizeof(name), "%s/tn_ac_user", ds);
	tn_zfs_destroy(name);
	snprintf(name, sizeof(name), "%s/tn_ac_deep", ds);
	tn_zfs_destroy(name);
	snprintf(name, sizeof(name), "%s/tn_ac_dir/tn_ac_user", ds);
	tn_zfs_destroy(name);

	/* the share root is the dataset mountpoint */
	snprintf(path, sizeof(path), "%s/tn_ac_user", mp);
	snprintf(name, sizeof(name), "%s/tn_ac_user", ds);
	ret = smb_zfs_create_dataset(tctx, path, NULL, &created, &nentries,
				     false);
	torture_assert_int_equal(tctx, ret, 0, "create below dataset root");
	torture_assert_int_equal(tctx, nentries, 2, "created plus anchor");
	torture_assert_str_equal(tctx, created[0]->dataset_name, name,
				 "created dataset name");
	torture_assert_str_equal(tctx, created[0]->mountpoint, path,
				 "created mountpoint");
	torture_assert(tctx, created[0]->mnt_id != 0, "created mnt_id");
	torture_assert_str_equal(tctx, created[1]->dataset_name, ds,
				 "anchor dataset name");
	torture_assert_str_equal(tctx, created[1]->mountpoint, mp,
				 "anchor mountpoint");
	tn_zfs_destroy(name);

	/*
	 * The share root is a plain directory inside the dataset, as it is
	 * for a share of a subdirectory. ZFS has no dataset for that
	 * directory, so one has to be created for it as well: what decides
	 * that is the dataset depth below the anchor, not how many path
	 * components are missing. The anchor is the containing dataset,
	 * which no prefix of the created dataset name names.
	 */
	snprintf(subdir, sizeof(subdir), "%s/tn_ac_dir", mp);
	ret = mkdir(subdir, 0755);
	torture_assert(tctx, (ret == 0) || (errno == EEXIST), "mkdir subdir");

	snprintf(path, sizeof(path), "%s/tn_ac_user", subdir);

	/* the intermediate dataset is not created behind the caller's back */
	ret = smb_zfs_create_dataset(tctx, path, NULL, &created, &nentries,
				     false);
	torture_assert_int_equal(tctx, ret, -1,
				 "refuses the missing dataset level");

	ret = smb_zfs_create_dataset(tctx, path, NULL, &created, &nentries,
				     true);
	torture_assert_int_equal(tctx, ret, 0, "create below a directory");
	torture_assert_int_equal(tctx, nentries, 3, "two created plus anchor");
	snprintf(name, sizeof(name), "%s/tn_ac_dir/tn_ac_user", ds);
	torture_assert_str_equal(tctx, created[0]->dataset_name, name,
				 "created dataset name");
	torture_assert_str_equal(tctx, created[0]->mountpoint, path,
				 "created mountpoint");
	snprintf(name, sizeof(name), "%s/tn_ac_dir", ds);
	torture_assert_str_equal(tctx, created[1]->dataset_name, name,
				 "directory level created as a dataset");
	torture_assert_str_equal(tctx, created[1]->mountpoint, subdir,
				 "intermediate mountpoint");
	torture_assert_str_equal(tctx, created[2]->dataset_name, ds,
				 "anchor is the containing dataset");
	torture_assert_str_equal(tctx, created[2]->mountpoint, mp,
				 "anchor mountpoint");
	tn_zfs_destroy(name);
	ret = rmdir(subdir);
	torture_assert_int_equal(tctx, ret, 0, "rmdir subdir");

	/* intermediate datasets, deepest first */
	snprintf(path, sizeof(path), "%s/tn_ac_deep/a/b", mp);
	ret = smb_zfs_create_dataset(tctx, path, NULL, &created, &nentries,
				     true);
	torture_assert_int_equal(tctx, ret, 0, "create with ancestors");
	torture_assert_int_equal(tctx, nentries, 4,
				 "three created plus anchor");
	snprintf(name, sizeof(name), "%s/tn_ac_deep/a/b", ds);
	torture_assert_str_equal(tctx, created[0]->dataset_name, name,
				 "deepest dataset first");
	snprintf(name, sizeof(name), "%s/tn_ac_deep/a", ds);
	torture_assert_str_equal(tctx, created[1]->dataset_name, name,
				 "intermediate dataset");
	snprintf(name, sizeof(name), "%s/tn_ac_deep", ds);
	torture_assert_str_equal(tctx, created[2]->dataset_name, name,
				 "outermost created dataset");
	torture_assert_str_equal(tctx, created[3]->dataset_name, ds,
				 "anchor last");

	/* missing ancestors are refused unless asked for */
	snprintf(path, sizeof(path), "%s/tn_ac_deep/a/b/c/d", mp);
	ret = smb_zfs_create_dataset(tctx, path, NULL, &created, &nentries,
				     false);
	torture_assert_int_equal(tctx, ret, -1, "refuses missing ancestors");

	snprintf(name, sizeof(name), "%s/tn_ac_deep", ds);
	tn_zfs_destroy(name);

	/* an existing path is refused */
	ret = smb_zfs_create_dataset(tctx, mp, NULL, &created, &nentries,
				     false);
	torture_assert_int_equal(tctx, ret, -1, "refuses existing path");
	torture_assert_int_equal(tctx, errno, EEXIST, "EEXIST");

	return true;
}

/*
 * The dataset name statmount reports is exactly what smb_libzfs hands to
 * zfs_open(), so a name ZFS itself accepts has to survive the trip: the
 * lookup below succeeding at all is the proof, because mntid_get_entry()
 * returns NULL when zfs_open() rejects the name. Creating below such a
 * dataset then covers the name concatenation in smb_zfs_create_dataset(),
 * which builds the child name from sb_source.
 */
static bool test_libzfs_space_in_name(struct torture_context *tctx)
{
	const char *space_ds = tn_mount_setting(tctx, "tn_mount_space_ds");
	const char *space_mp = tn_mount_setting(tctx, "tn_mount_space_mp");
	const struct zfs_dataset **created = NULL;
	const struct zfs_dataset *zds = NULL;
	char path[PATH_MAX];
	char name[ZFSDS_NAMELEN];
	size_t nentries = 0;
	uint64_t mnt_id;
	int ret;

	if (space_ds == NULL || space_mp == NULL) {
		return tn_skip_or_fail(tctx, "no tn_mount_space_* configured");
	}
	if (geteuid() != 0) {
		return tn_skip_or_fail(tctx, "not root");
	}

	ret = tn_mount_path_get_mnt_id(space_mp, &mnt_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id");

	zds = smb_zfs_lookup_dataset(mnt_id);
	torture_assert(tctx, zds != NULL, "libzfs accepted the name");
	torture_assert_str_equal(tctx, zds->dataset_name, space_ds,
				 "dataset name keeps its space");
	torture_assert_str_equal(tctx, zds->mountpoint, space_mp,
				 "mountpoint keeps its space");

	/* leftovers from an interrupted run */
	snprintf(name, sizeof(name), "%s/tn_ac_space", space_ds);
	tn_zfs_destroy(name);

	snprintf(path, sizeof(path), "%s/tn_ac_space", space_mp);
	ret = smb_zfs_create_dataset(tctx, path, NULL, &created, &nentries,
				     false);
	torture_assert_int_equal(tctx, ret, 0, "create below a spaced name");
	torture_assert_int_equal(tctx, nentries, 2, "created plus anchor");
	torture_assert_str_equal(tctx, created[0]->dataset_name, name,
				 "child inherits the parent's space");
	torture_assert_str_equal(tctx, created[0]->mountpoint, path,
				 "created mountpoint");
	torture_assert(tctx, created[0]->mnt_id != 0, "created mnt_id");
	torture_assert_str_equal(tctx, created[1]->dataset_name, space_ds,
				 "anchor is the spaced dataset");
	tn_zfs_destroy(name);

	return true;
}

/* repeated lookups hand back the library's own cached instance */
static bool test_libzfs_lookup_stability(struct torture_context *tctx)
{
	const char *ds = tn_mount_setting(tctx, "tn_mount_ds");
	const char *mp = tn_mount_setting(tctx, "tn_mount_mp");
	const struct zfs_dataset *a = NULL;
	const struct zfs_dataset *b = NULL;
	uint64_t mnt_id;
	int ret;

	if (ds == NULL || mp == NULL) {
		return tn_skip_or_fail(tctx,
			"no tn_mount_ds/tn_mount_mp configured");
	}

	ret = tn_mount_path_get_mnt_id(mp, &mnt_id);
	torture_assert_int_equal(tctx, ret, 0, "mount id");

	a = smb_zfs_lookup_dataset(mnt_id);
	b = smb_zfs_lookup_dataset(mnt_id);
	torture_assert(tctx, a != NULL && b != NULL, "two lookups");
	torture_assert(tctx, a == b, "no copy is made");
	torture_assert_str_equal(tctx, a->dataset_name, ds, "dataset name");
	torture_assert_str_equal(tctx, a->mountpoint, mp, "mountpoint");

	return true;
}

struct torture_suite *torture_local_smb_libzfs(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = NULL;

	suite = torture_suite_create(mem_ctx, "smb_libzfs");

	torture_suite_add_simple_test(suite, "conn_init",
				      test_libzfs_conn_init);
	torture_suite_add_simple_test(suite, "caseinsensitive",
				      test_libzfs_caseinsensitive);
	torture_suite_add_simple_test(suite, "not_zfs",
				      test_libzfs_not_zfs);
	torture_suite_add_simple_test(suite, "missing_path",
				      test_libzfs_missing_path);
	torture_suite_add_simple_test(suite, "mntid",
				      test_libzfs_mntid);
	torture_suite_add_simple_test(suite, "legacy_mountpoint",
				      test_libzfs_legacy_mountpoint);
	torture_suite_add_simple_test(suite, "snapshot_base",
				      test_libzfs_snapshot_base);
	torture_suite_add_simple_test(suite, "ds_cache",
				      test_libzfs_ds_cache);
	torture_suite_add_simple_test(suite, "create_dataset",
				      test_libzfs_create_dataset);
	torture_suite_add_simple_test(suite, "space_in_name",
				      test_libzfs_space_in_name);
	torture_suite_add_simple_test(suite, "lookup_stability",
				      test_libzfs_lookup_stability);

	suite->description = talloc_strdup(suite,
		"smb_libzfs mount ID -> ZFS dataset resolution tests");
	return suite;
}
