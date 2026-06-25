/*
   Unix SMB/CIFS implementation.

   TrueNAS ACL <-> Windows Security-Descriptor mapping torture tests.

   These exercise the ixnas VFS module's translation between a ZFS/NFSv4 ACL
   (stored in the system.nfs4_acl_xdr xattr provided by the TrueNAS ZFS module)
   and the Windows Security Descriptor seen over SMB2. They assert mapping
   correctness only -- SET/GET of a security descriptor over the wire -- not the
   kernel-enforced access-check edge cases (delete behaviour, access-based
   enumeration) which depend on a TrueNAS-patched base kernel and so cannot be
   validated on a stock-kernel CI runner.

   The reference for the expected mappings is the TrueNAS middleware
   plugins/smb_/util_sd.py truth table and tests/sharing_protocols/smb/
   test_smb_null_empty_dacl.py / tests/api2/test_427_smb_acl.py.

   These require a ZFS dataset with acltype=nfsv4 served with
   "vfs objects = ixnas zfs_core"; they self-skip unless the harness asserts
   that with --option=torture:acl_nfs4=yes (set only once the ZFS module is
   confirmed to expose system.nfs4_acl_xdr).

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
#include "librpc/gen_ndr/ndr_security.h"

#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smbtorture.h"
#include "torture/smb2/proto.h"
#include "torture/truenas/proto.h"

/*
 * The ACL tests are registered into the shared "truenas" suite, which also runs
 * against non-ixnas shares (e.g. ztest). Gate every test on this option so they
 * only execute against the dedicated ixnas/NFSv4 share.
 */
static bool truenas_acl_enabled(struct torture_context *tctx)
{
	return torture_setting_bool(tctx, "acl_nfs4", false);
}

static NTSTATUS truenas_acl_open(struct smb2_tree *tree,
				 struct torture_context *tctx,
				 const char *fname,
				 struct smb2_handle *h)
{
	struct smb2_create cr;
	NTSTATUS status;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC |
			       SEC_STD_WRITE_OWNER | SEC_FILE_READ_DATA;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	if (NT_STATUS_IS_OK(status)) {
		*h = cr.out.file.handle;
	}
	return status;
}

static NTSTATUS truenas_acl_get(struct smb2_tree *tree,
				struct torture_context *tctx,
				struct smb2_handle h,
				uint32_t secinfo,
				struct security_descriptor **sd)
{
	union smb_fileinfo q;
	NTSTATUS status;

	ZERO_STRUCT(q);
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = h;
	q.query_secdesc.in.secinfo_flags = secinfo;
	status = smb2_getinfo_file(tree, tctx, &q);
	if (NT_STATUS_IS_OK(status)) {
		*sd = q.query_secdesc.out.sd;
	}
	return status;
}

static NTSTATUS truenas_acl_set(struct smb2_tree *tree,
				struct smb2_handle h,
				struct security_descriptor *sd)
{
	union smb_setfileinfo s;

	ZERO_STRUCT(s);
	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.handle = h;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = sd;
	return smb2_setinfo_file(tree, &s);
}

/*
 * Sanity: ixnas returns a well-formed NFSv4-mapped security descriptor for a
 * freshly created file (owner, group and a non-empty DACL).
 */
static bool test_truenas_acl_get_sd(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct security_descriptor *sd = NULL;
	const char *fname = "acl_get_sd";

	if (!truenas_acl_enabled(tctx)) {
		torture_skip(tctx, "requires an ixnas NFSv4-ACL share "
				   "(--option=torture:acl_nfs4=yes)");
	}

	smb2_util_unlink(tree, fname);
	status = truenas_acl_open(tree, tctx, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create file");

	status = truenas_acl_get(tree, tctx, h,
				 SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL,
				 &sd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get sd");
	torture_assert_goto(tctx, sd != NULL, ret, done, "NULL sd");
	torture_assert_goto(tctx, sd->owner_sid != NULL, ret, done,
			    "sd has no owner");
	torture_assert_goto(tctx, sd->dacl != NULL, ret, done,
			    "sd has no DACL");
	torture_assert_goto(tctx, sd->dacl->num_aces >= 1, ret, done,
			    "sd DACL is empty");

done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * Each Windows access-mask bit set on an owner ALLOW ACE must survive the round
 * trip through the ZFS NFSv4 ACL. ixnas may add bits (it forces SYNCHRONIZE on
 * ALLOW entries, and synthesises DELETE/WRITE_NAMED_ATTRS for special-id
 * entries with WRITE_DATA), so this asserts the returned owner mask is a
 * superset of what was set, never an exact match. Mirrors the per-bit walk in
 * middleware test_427_smb_acl.py::test_003_test_perms (util_sd.py ACLPerms).
 */
static bool test_truenas_acl_perm_bits(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct security_descriptor *sd0 = NULL, *sd = NULL, *got = NULL;
	struct dom_sid *owner = NULL;
	const char *owner_str = NULL;
	const char *fname = "acl_perm_bits";
	uint32_t test_mask = 0, got_mask = 0;
	unsigned int c, j;
	static const struct {
		const char *name;
		uint32_t mask;
	} cases[] = {
		{ "READ_DATA",       SEC_FILE_READ_DATA },
		{ "WRITE_DATA",      SEC_FILE_WRITE_DATA },
		{ "APPEND_DATA",     SEC_FILE_APPEND_DATA },
		{ "READ_EA",         SEC_FILE_READ_EA },
		{ "WRITE_EA",        SEC_FILE_WRITE_EA },
		{ "EXECUTE",         SEC_FILE_EXECUTE },
		{ "READ_ATTRIBUTE",  SEC_FILE_READ_ATTRIBUTE },
		{ "WRITE_ATTRIBUTE", SEC_FILE_WRITE_ATTRIBUTE },
		{ "DELETE",          SEC_STD_DELETE },
		{ "READ_CONTROL",    SEC_STD_READ_CONTROL },
		{ "WRITE_DAC",       SEC_STD_WRITE_DAC },
		{ "WRITE_OWNER",     SEC_STD_WRITE_OWNER },
	};

	if (!truenas_acl_enabled(tctx)) {
		torture_skip(tctx, "requires an ixnas NFSv4-ACL share "
				   "(--option=torture:acl_nfs4=yes)");
	}

	smb2_util_unlink(tree, fname);
	status = truenas_acl_open(tree, tctx, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create file");

	status = truenas_acl_get(tree, tctx, h, SECINFO_OWNER, &sd0);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get owner");
	torture_assert_goto(tctx, sd0->owner_sid != NULL, ret, done,
			    "no owner sid");
	owner = sd0->owner_sid;
	owner_str = dom_sid_string(tctx, owner);

	/*
	 * Set one owner ALLOW ACE carrying every bit under test at once, then
	 * verify each maps back individually. A single comprehensive ACE keeps
	 * the owner able to manage the ACL (a degenerate single-bit ACE per
	 * iteration makes ZFS reject the setacl with EPERM) and removes any
	 * cross-iteration ACL state.
	 */
	for (c = 0; c < ARRAY_SIZE(cases); c++) {
		test_mask |= cases[c].mask;
	}

	sd = security_descriptor_dacl_create(tctx, 0, owner_str, NULL,
					     owner_str,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     test_mask, 0, NULL);
	torture_assert_goto(tctx, sd != NULL, ret, done, "build dacl");

	status = truenas_acl_set(tree, h, sd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set owner ACL");

	status = truenas_acl_get(tree, tctx, h, SECINFO_OWNER | SECINFO_DACL, &got);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get owner ACL");
	torture_assert_goto(tctx, got->dacl != NULL, ret, done,
			    "unexpected NULL DACL");

	for (j = 0; j < got->dacl->num_aces; j++) {
		struct security_ace *ace = &got->dacl->aces[j];
		if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED &&
		    dom_sid_equal(&ace->trustee, owner)) {
			got_mask |= ace->access_mask;
		}
	}

	for (c = 0; c < ARRAY_SIZE(cases); c++) {
		torture_assert_goto(tctx,
				    (got_mask & cases[c].mask) == cases[c].mask,
				    ret, done, cases[c].name);
	}

done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * A Windows NULL DACL (DACL present, no ACL pointer = "grant everyone") must
 * round-trip as a NULL DACL over SMB. ixnas stores it as a single everyone@
 * full-control ACE and reports it back as a NULL DACL. Mirrors middleware
 * test_smb_null_empty_dacl.py.
 */
static bool test_truenas_acl_null_dacl(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct security_descriptor *sd = NULL, *got = NULL;
	const char *fname = "acl_null_dacl";

	if (!truenas_acl_enabled(tctx)) {
		torture_skip(tctx, "requires an ixnas NFSv4-ACL share "
				   "(--option=torture:acl_nfs4=yes)");
	}

	smb2_util_unlink(tree, fname);
	status = truenas_acl_open(tree, tctx, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create file");

	sd = security_descriptor_initialise(tctx);
	torture_assert_goto(tctx, sd != NULL, ret, done, "init sd");
	sd->type |= SEC_DESC_DACL_PRESENT;
	sd->dacl = NULL;

	status = truenas_acl_set(tree, h, sd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set NULL DACL");

	status = truenas_acl_get(tree, tctx, h, SECINFO_DACL, &got);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"get NULL DACL");
	torture_assert_goto(tctx, got->dacl == NULL, ret, done,
			    "NULL DACL did not round-trip as NULL");

done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	return ret;
}

void torture_truenas_acl_suite(struct torture_suite *suite)
{
	struct torture_suite *acl = torture_suite_create(suite, "acl");

	torture_suite_add_1smb2_test(acl, "get_sd_nfs4",
				     test_truenas_acl_get_sd);
	torture_suite_add_1smb2_test(acl, "perm_bits",
				     test_truenas_acl_perm_bits);
	torture_suite_add_1smb2_test(acl, "null_dacl",
				     test_truenas_acl_null_dacl);

	torture_suite_add_suite(suite, acl);
}
