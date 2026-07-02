/*
   Unix SMB/CIFS implementation.

   TrueNAS ACL <-> Windows Security-Descriptor mapping torture tests.

   These exercise the ixnas VFS module's translation between a ZFS/NFSv4 ACL
   (stored in the system.nfs4_acl_xdr xattr provided by the TrueNAS ZFS module)
   and the Windows Security Descriptor seen over SMB2. They assert mapping
   correctness only -- SET/GET of a security descriptor over the wire -- not the
   kernel-enforced access-check edge cases (delete behavior, access-based
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
	/*
	 * WRITE_DAC suffices to install a DACL, and the owner is granted it
	 * implicitly. Deliberately do NOT request WRITE_OWNER: ixnas demotes it
	 * out of owner@/group@/everyone@ in the advertised SD and the owner has no
	 * implicit WRITE_OWNER, so requesting it would make the open itself
	 * ACCESS_DENIED once a handle is reopened against an existing object.
	 */
	cr.in.desired_access = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC |
			       SEC_FILE_READ_DATA;
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
 * entries with WRITE_DATA), so the data/attribute bits are asserted as a
 * superset of what was set, never an exact match. Mirrors the per-bit walk in
 * middleware test_427_smb_acl.py::test_003_test_perms (util_sd.py ACLPerms).
 *
 * WRITE_DAC and WRITE_OWNER: the trustee here is the owner, so it stores as
 * owner@. ixnas demotes only group@ now, so the owner ACE keeps both bits (the
 * owner may manage its own ACL, completed under privilege by ixnas). They are
 * asserted PRESENT on the returned owner ACE -- see
 * test_truenas_acl_special_demote for the full owner@/group@/everyone@ vs
 * named-entry contract.
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
		bool present;	/* expected on the returned owner ACE? */
	} cases[] = {
		{ "READ_DATA",       SEC_FILE_READ_DATA,      true },
		{ "WRITE_DATA",      SEC_FILE_WRITE_DATA,     true },
		{ "APPEND_DATA",     SEC_FILE_APPEND_DATA,    true },
		{ "READ_EA",         SEC_FILE_READ_EA,        true },
		{ "WRITE_EA",        SEC_FILE_WRITE_EA,       true },
		{ "EXECUTE",         SEC_FILE_EXECUTE,        true },
		{ "READ_ATTRIBUTE",  SEC_FILE_READ_ATTRIBUTE, true },
		{ "WRITE_ATTRIBUTE", SEC_FILE_WRITE_ATTRIBUTE, true },
		{ "DELETE",          SEC_STD_DELETE,          true },
		{ "READ_CONTROL",    SEC_STD_READ_CONTROL,    true },
		/* owner@ keeps these now -- ixnas demotes only group@ */
		{ "WRITE_DAC",       SEC_STD_WRITE_DAC,       true },
		{ "WRITE_OWNER",     SEC_STD_WRITE_OWNER,     true },
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
		bool ok = cases[c].present ?
			((got_mask & cases[c].mask) == cases[c].mask) :
			((got_mask & cases[c].mask) == 0);
		torture_assert_goto(tctx, ok, ret, done, cases[c].name);
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

/* Open an existing file read-only (READ_CONTROL is enough to read the SD). */
static NTSTATUS truenas_acl_open_existing(struct smb2_tree *tree,
					 struct torture_context *tctx,
					 const char *fname,
					 struct smb2_handle *h)
{
	struct smb2_create cr;
	NTSTATUS status;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_STD_READ_CONTROL | SEC_FILE_READ_DATA;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;		/* must exist */
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	if (NT_STATUS_IS_OK(status)) {
		*h = cr.out.file.handle;
	}
	return status;
}

/*
 * The advertisement contract after ixnas's group@-only demote: the group@ ALLOW
 * ACE returns WITHOUT WRITE_DAC/WRITE_OWNER, while owner@ and everyone@ keep
 * them (the owner may manage its ACL; a fully-open everyone@ has no protection).
 * owner@/group@/everyone@ map back to the owner SID, the owning-group SID and
 * Everyone. With want_named, also require a named ALLOW ACE that carries both
 * bits -- proof the demote is scoped to group@ and is not a blanket strip.
 */
static bool truenas_acl_assert_demote(struct torture_context *tctx,
				      const struct security_descriptor *sd,
				      bool want_named)
{
	const uint32_t wc = SEC_STD_WRITE_DAC | SEC_STD_WRITE_OWNER;
	bool saw_owner = false, saw_group = false, saw_world = false;
	bool saw_named_full = false;
	uint32_t i;

	torture_assert(tctx, sd->dacl != NULL, "no DACL returned");

	for (i = 0; i < sd->dacl->num_aces; i++) {
		const struct security_ace *ace = &sd->dacl->aces[i];

		if (ace->type != SEC_ACE_TYPE_ACCESS_ALLOWED) {
			continue;
		}

		if (sd->group_sid != NULL &&
		    dom_sid_equal(&ace->trustee, sd->group_sid)) {
			saw_group = true;
			torture_assert(tctx, (ace->access_mask & wc) == 0,
				       "group@ still advertises "
				       "WRITE_DAC/WRITE_OWNER");
		} else if (sd->owner_sid != NULL &&
			   dom_sid_equal(&ace->trustee, sd->owner_sid)) {
			saw_owner = true;
			torture_assert(tctx, (ace->access_mask & wc) == wc,
				       "owner@ lost WRITE_DAC/WRITE_OWNER");
		} else if (dom_sid_equal(&ace->trustee, &global_sid_World)) {
			saw_world = true;
			torture_assert(tctx, (ace->access_mask & wc) == wc,
				       "everyone@ lost WRITE_DAC/WRITE_OWNER");
		} else if ((ace->access_mask & wc) == wc) {
			saw_named_full = true;
		}
	}

	torture_assert(tctx, saw_owner && saw_group && saw_world,
		       "missing owner@/group@/everyone@ ACE in returned SD");
	if (want_named) {
		torture_assert(tctx, saw_named_full,
			       "named entry lost WRITE_DAC/WRITE_OWNER");
	}
	return true;
}

/*
 * Core contract over pure SMB: set Full Control (including WRITE_DAC/WRITE_OWNER)
 * on owner@, group@ and everyone@, read the SD back, and require group@ to
 * return without those two bits while owner@ and everyone@ keep them. No fixture
 * needed.
 */
static bool test_truenas_acl_special_demote(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct security_descriptor *sd0 = NULL, *sd = NULL, *got = NULL;
	const char *owner = NULL, *group = NULL, *world = NULL;
	const char *fname = "acl_special_demote";
	const uint32_t full = SEC_STD_ALL | SEC_FILE_ALL;

	if (!truenas_acl_enabled(tctx)) {
		torture_skip(tctx, "requires an ixnas NFSv4-ACL share "
				   "(--option=torture:acl_nfs4=yes)");
	}

	smb2_util_unlink(tree, fname);
	status = truenas_acl_open(tree, tctx, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create file");

	status = truenas_acl_get(tree, tctx, h,
				 SECINFO_OWNER | SECINFO_GROUP, &sd0);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get owner/group");
	torture_assert_goto(tctx,
			    sd0->owner_sid != NULL && sd0->group_sid != NULL,
			    ret, done, "missing owner/group sid");

	owner = dom_sid_string(tctx, sd0->owner_sid);
	group = dom_sid_string(tctx, sd0->group_sid);
	world = dom_sid_string(tctx, &global_sid_World);

	/*
	 * The owner/owning-group SIDs collapse to owner@/group@ and S-1-1-0 maps
	 * to everyone@ on store, so this lands as a 3-entry special-identity ACL.
	 */
	sd = security_descriptor_dacl_create(tctx, 0, owner, NULL,
			owner, SEC_ACE_TYPE_ACCESS_ALLOWED, full, 0,
			group, SEC_ACE_TYPE_ACCESS_ALLOWED, full, 0,
			world, SEC_ACE_TYPE_ACCESS_ALLOWED, full, 0,
			NULL);
	torture_assert_goto(tctx, sd != NULL, ret, done, "build dacl");

	status = truenas_acl_set(tree, h, sd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set special ACL");

	status = truenas_acl_get(tree, tctx, h,
				 SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL,
				 &got);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get back ACL");

	ret = truenas_acl_assert_demote(tctx, got, false);

done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * Same contract against an out-of-band fixture (laid down on disk by
 * truenas_setfacl in the CI runner) that also carries a named user/group with
 * Full Control: the special identities must be demoted while the named entry
 * keeps WRITE_DAC/WRITE_OWNER. The runner brackets this with truenas_getfacl to
 * prove the on-disk ACL is left untouched (advertisement-only). Self-skips
 * unless given the fixture path.
 */
static bool test_truenas_acl_fixture_scope(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct security_descriptor *got = NULL;
	const char *fname = torture_setting_string(tctx, "acl_fixture", NULL);

	if (!truenas_acl_enabled(tctx)) {
		torture_skip(tctx, "requires an ixnas NFSv4-ACL share "
				   "(--option=torture:acl_nfs4=yes)");
	}
	if (fname == NULL) {
		torture_skip(tctx, "requires --option=torture:acl_fixture=<path> "
				   "(an on-disk fixture carrying a named entry)");
	}

	status = truenas_acl_open_existing(tree, tctx, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open fixture");

	status = truenas_acl_get(tree, tctx, h,
				 SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL,
				 &got);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get fixture ACL");

	ret = truenas_acl_assert_demote(tctx, got, true);

done:
	smb2_util_close(tree, h);
	return ret;
}

/*
 * Avid MediaComposer content-directory pattern, observed on the wire:
 *
 *   1. SMB2 SetInfo(SECURITY, DACL) on a directory installing a DACL-only SD:
 *      one ACE, Everyone (S-1-1-0) ACCESS_ALLOWED, OI|CI, mask 0x101fffff
 *      (Full), control 0x8004 (SELF_RELATIVE|DACL_PRESENT, not protected), no
 *      owner/group -- i.e. it drops the inherited owner@/group@/named ACEs.
 *   2. SMB2 Create of a file inside that directory (disposition OVERWRITE_IF,
 *      desired access 0x0012019f = read/write data + READ_CONTROL, NO WRITE_DAC
 *      or WRITE_OWNER) carrying a "SecD" (SMB2_CREATE_SD_BUFFER) create-context
 *      holding the same Everyone:Full DACL. This returned STATUS_ACCESS_DENIED.
 *
 * ixnas applies that create-time SD via SMB_VFS_FSET_NT_ACL. The child inherits
 * the parent's non-trivial everyone@:full ACL, and ZFS grants WRITE_ACL on a
 * non-trivial ACL only to CAP_FOWNER (secpolicy_vnode_chown) -- so even the
 * connecting user, as the child's owner, is refused, and without the
 * open-everyone privileged retry (fsp_set_zfsacl_open_everyone) the create rolls
 * back to ACCESS_DENIED.
 *
 * Asserts the create succeeds and the DACL round-trips. NOTE: the become_root
 * retry only fires on a TrueNAS-patched kernel that enforces the NFSv4 ACL; on a
 * stock CI runner (no enforcement) the create succeeds without the retry, so
 * this still validates the create-context SD apply path and its mapping.
 */
static bool test_truenas_acl_create_ctx_open_everyone(struct torture_context *tctx,
						      struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle dh = {{0}};
	struct smb2_handle fh = {{0}};
	struct smb2_create cr;
	struct security_descriptor *sd = NULL, *got = NULL;
	const char *world = NULL;
	const char *dname = "acl_open_everyone_dir";
	const char *fname = "acl_open_everyone_dir\\creating_ctx";
	const uint32_t full = SEC_STD_ALL | SEC_FILE_ALL;
	uint32_t i;
	bool saw_world = false;

	if (!truenas_acl_enabled(tctx)) {
		torture_skip(tctx, "requires an ixnas NFSv4-ACL share "
				   "(--option=torture:acl_nfs4=yes)");
	}

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, dname, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create dir");

	/* Everyone:Full, inheritable, DACL-only -- step 1 above. */
	world = dom_sid_string(tctx, &global_sid_World);
	sd = security_descriptor_dacl_create(tctx, 0, NULL, NULL,
			world, SEC_ACE_TYPE_ACCESS_ALLOWED, full,
			SEC_ACE_FLAG_OBJECT_INHERIT | SEC_ACE_FLAG_CONTAINER_INHERIT,
			NULL);
	torture_assert_goto(tctx, sd != NULL, ret, done, "build dacl");

	status = truenas_acl_set(tree, dh, sd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set dir DACL");

	/*
	 * Create a file inside it carrying the same Everyone:Full DACL as a
	 * "SecD" create-context SD -- step 2 above (Overwrite-If, read/write, no
	 * WRITE_DAC/WRITE_OWNER). Must NOT be ACCESS_DENIED.
	 */
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
			       SEC_STD_READ_CONTROL;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;
	cr.in.sec_desc = sd;

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file with Everyone:Full SecD SD");
	fh = cr.out.file.handle;

	/*
	 * The applied DACL round-trips as "everyone has full access". A lone
	 * everyone@:full on a file is stored as a single flags==0 ACE, which ixnas
	 * maps back to a NULL DACL (SEC_DESC_DACL_PRESENT, dacl==NULL) -- the
	 * Windows "Everyone / full control / no ACL" form (see acl.null_dacl).
	 * Accept that, or an explicit Everyone ALLOW ACE; both mean it was applied.
	 */
	status = truenas_acl_get(tree, tctx, fh,
				 SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL, &got);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get back SD");
	if (got->dacl == NULL) {
		torture_assert_goto(tctx,
			(got->type & SEC_DESC_DACL_PRESENT) != 0, ret, done,
			"no DACL present after create-context set");
	} else {
		for (i = 0; i < got->dacl->num_aces; i++) {
			const struct security_ace *ace = &got->dacl->aces[i];

			if ((ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED) &&
			    dom_sid_equal(&ace->trustee, &global_sid_World)) {
				saw_world = true;
			}
		}
		torture_assert_goto(tctx, saw_world, ret, done,
			"Everyone ACE missing after create-context set");
	}

done:
	smb2_util_close(tree, fh);
	smb2_util_close(tree, dh);
	smb2_deltree(tree, dname);
	return ret;
}

/*
 * The file owner may rewrite the ACL of their own file even once it is
 * non-trivial -- which ZFS otherwise refuses (WRITE_ACL on a non-trivial ACL
 * needs CAP_FOWNER, and owner@ does not convey it). Set [owner@:full,
 * group@:full] (trivial->non-trivial, allowed by secpolicy_vnode_setdac), then
 * rewrite it to [owner@:full, group@:read]: the second set is on a non-trivial
 * ACL, so ZFS refuses the owner's WRITE_ACL and it must complete via ixnas's
 * become_root retry (gated on owner@ full-control + caller is the owner).
 *
 * NOTE: the retry only fires on a TrueNAS-patched enforcing kernel; on a stock
 * CI runner the second set succeeds without it (still validates the mapping).
 */
static bool test_truenas_acl_owner_full_escalate(struct torture_context *tctx,
						 struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct security_descriptor *sd0 = NULL, *sd = NULL;
	const char *owner = NULL, *group = NULL;
	const char *fname = "acl_owner_full_escalate";
	const uint32_t full = SEC_STD_ALL | SEC_FILE_ALL;

	if (!truenas_acl_enabled(tctx)) {
		torture_skip(tctx, "requires an ixnas NFSv4-ACL share "
				   "(--option=torture:acl_nfs4=yes)");
	}

	smb2_util_unlink(tree, fname);
	status = truenas_acl_open(tree, tctx, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create file");

	status = truenas_acl_get(tree, tctx, h,
				 SECINFO_OWNER | SECINFO_GROUP, &sd0);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "get owner/group");
	torture_assert_goto(tctx,
			    sd0->owner_sid != NULL && sd0->group_sid != NULL,
			    ret, done, "missing owner/group sid");
	owner = dom_sid_string(tctx, sd0->owner_sid);
	group = dom_sid_string(tctx, sd0->group_sid);

	/* Establish a non-trivial ACL (allowed: the file's ACL is still trivial). */
	sd = security_descriptor_dacl_create(tctx, 0, owner, NULL,
			owner, SEC_ACE_TYPE_ACCESS_ALLOWED, full, 0,
			group, SEC_ACE_TYPE_ACCESS_ALLOWED, full, 0,
			NULL);
	torture_assert_goto(tctx, sd != NULL, ret, done, "build dacl 1");
	status = truenas_acl_set(tree, h, sd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set initial non-trivial ACL");

	/* Rewrite it -- now the on-disk ACL is non-trivial; needs the retry. */
	sd = security_descriptor_dacl_create(tctx, 0, owner, NULL,
			owner, SEC_ACE_TYPE_ACCESS_ALLOWED, full, 0,
			group, SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_FILE_READ_DATA, 0,
			NULL);
	torture_assert_goto(tctx, sd != NULL, ret, done, "build dacl 2");
	status = truenas_acl_set(tree, h, sd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"rewrite non-trivial owner ACL");

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
	torture_suite_add_1smb2_test(acl, "special_demote",
				     test_truenas_acl_special_demote);
	torture_suite_add_1smb2_test(acl, "fixture_scope",
				     test_truenas_acl_fixture_scope);
	torture_suite_add_1smb2_test(acl, "create_ctx_open_everyone",
				     test_truenas_acl_create_ctx_open_everyone);
	torture_suite_add_1smb2_test(acl, "owner_full_escalate",
				     test_truenas_acl_owner_full_escalate);

	torture_suite_add_suite(suite, acl);
}
