#include "replace.h"
#include "zfsacl.h"

#define INHERITANCE_FLAGS ZFSACE_FILE_INHERIT | ZFSACE_DIRECTORY_INHERIT | \
	ZFSACE_NO_PROPAGATE_INHERIT

static bool copy_ace(zfsacl_entry_t target,
		     zfsacl_entry_t source,
		     zfsace_flagset_t new_flags)
{
	zfsace_permset_t aeperms;
	zfsace_who_t aewho;
	zfsace_id_t aeid;
	zfsace_entry_type_t aetp;

	if (!zfsace_get_permset(source, &aeperms)) {
		return false;
	}

	if (!zfsace_get_who(source, &aewho, &aeid)) {
		return false;
	}

	if (!zfsace_get_entry_type(source, &aetp)) {
		return false;
	}

	if (!zfsace_set_permset(target, aeperms)) {
		return false;
	}

	if (!zfsace_set_who(target, aewho, aeid)) {
		return false;
	}

        if (!zfsace_set_entry_type(target, aetp)) {
		return false;
	}

        if (!zfsace_set_flagset(target, new_flags)) {
		return false;
	}

	return true;
}

static bool add_non_inherited_entries(zfsacl_t target, zfsacl_t source)
{
	uint i, cnt;

	if (!zfsacl_get_acecnt(source, &cnt)) {
		return false;
	}

	for (i = 0; i < cnt; i++) {
		zfsacl_entry_t ae = NULL;
		zfsacl_entry_t new = NULL;
		zfsace_flagset_t flags = 0;

		if (!zfsacl_get_aclentry(source, i, &ae)) {
			return false;
		}

		if (!zfsace_get_flagset(ae, &flags)) {
			return false;
		}

		if (flags & ZFSACE_INHERITED_ACE) {
			continue;
		}

		if (!zfsacl_create_aclentry(target, ZFSACL_APPEND_ENTRY, &new)) {
			return false;
		}

		if (!copy_ace(new, ae, flags)) {
			return false;
		}
	}

	return true;
}

static bool add_inherited_ace(zfsacl_t target,
			      zfsacl_entry_t ae,
			      zfsace_flagset_t flags,
			      bool isdir)
{
	zfsacl_entry_t new = NULL;

	if (!zfsacl_create_aclentry(target, ZFSACL_APPEND_ENTRY, &new)) {
		return false;
	}

	if (isdir) {
		if (flags & ZFSACE_INHERIT_ONLY) {
			flags &= ~ZFSACE_INHERIT_ONLY;
		} else if (flags & ZFSACE_NO_PROPAGATE_INHERIT) {
			flags &= ~INHERITANCE_FLAGS;
		}
	} else {
		flags &= ~(ZFSACE_INHERIT_ONLY | INHERITANCE_FLAGS);
	}

	flags |= ZFSACE_INHERITED_ACE;

	return copy_ace(new, ae, flags);
}

static bool add_inherited_entries(zfsacl_t target, zfsacl_t source, bool isdir)
{
	uint i, cnt;

	if (!zfsacl_get_acecnt(source, &cnt)) {
		return false;
	}

	for (i = 0; i < cnt; i++) {
		zfsacl_entry_t ae = NULL;
		zfsacl_entry_t new_entry = NULL;
		zfsace_flagset_t flags = 0;

		if (!zfsacl_get_aclentry(source, i, &ae)) {
			return false;
		}

		if (!zfsace_get_flagset(ae, &flags)) {
			return false;
		}

		if ((flags &
		    (ZFSACE_FILE_INHERIT | ZFSACE_DIRECTORY_INHERIT)) == 0) {
			// Not inheritable, skip
			continue;
		}

		if (((flags & ZFSACE_DIRECTORY_INHERIT) == 0) && isdir) {
			/*
			 * Inheritable only on files and this ACL is for a
			 * directory.
			 */
			continue;
		}

		if (((flags & ZFSACE_FILE_INHERIT) == 0) && !isdir) {
			/*
			 * Inheritable only on directories and this ACL is for
			 * a file.
			 */
			continue;
		}

		if (!add_inherited_ace(target, ae, flags, isdir)) {
			return false;
		}
	}

	return true;
}

/*
 * Permissions auto-inheritance is only a NFSv4 ACL feature
 */
static bool acl_may_inherit(zfsacl_t parent, zfsacl_t target)
{
	zfsacl_brand_t brand;

	if (parent == NULL) {
		errno = EINVAL;
		return false;
	}

	if (!zfsacl_get_brand(parent, &brand)) {
		return false;
	}

	if (brand != ZFSACL_BRAND_NFSV4) {
		errno = EOPNOTSUPP;
		return false;
	}

	if (target) {
		if (!zfsacl_get_brand(target, &brand)) {
			return false;
		}


		if (brand != ZFSACL_BRAND_NFSV4) {
			errno = EOPNOTSUPP;
			return false;
		}
	}

	return true;
}

zfsacl_t zfsacl_calculate_inherited_acl(zfsacl_t parent, zfsacl_t target, bool is_dir)
{
	zfsacl_t out = NULL;

	if (!acl_may_inherit(parent, target)) {
		return NULL;
	}

	out = zfsacl_init(ZFSACL_MAX_ENTRIES, ZFSACL_BRAND_NFSV4);

	if (target) {
		if (!add_non_inherited_entries(out, target)) {
			zfsacl_free(&out);
			return NULL;
		}
	}

	if (!add_inherited_entries(out, parent, is_dir)) {
		zfsacl_free(&out);
		return NULL;
	}

	return out;
}
