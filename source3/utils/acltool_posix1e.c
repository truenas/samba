#include <sys/types.h>
#include <sys/acl.h>
#include <errno.h>
#include <sys/stat.h>
#include <err.h>
#include <fts.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include "acltool.h"
#ifdef __linux__
#include <acl/libacl.h>
#endif


/* from POSIX1e setfacl in acl package */
static const struct acl_ops posix1e_acl_ops;

void posix1e_acl_ops_init(struct acl_info *w)
{
	w->ops = &posix1e_acl_ops;
	w->brand = ACL_BRAND_POSIX1E;
}

#ifdef __linux__
int
acl_get_perm_np(acl_permset_t permset_d, acl_perm_t perm)
{
	return acl_get_perm(permset_d, perm);
}
#endif

acl_entry_t
find_entry(
        acl_t acl,
        acl_tag_t type,
        id_t id)
{
        acl_entry_t ent;
        acl_tag_t e_type;
        id_t *e_id_p;

        if (acl_get_entry(acl, ACL_FIRST_ENTRY, &ent) != 1){
                return NULL;
	}

        for(;;) {
                acl_get_tag_type(ent, &e_type);
                if (type == e_type) {
                        if (id != ACL_UNDEFINED_ID) {
                                e_id_p = acl_get_qualifier(ent);
                                if (e_id_p == NULL)
                                        return NULL;
                                if (*e_id_p == id) {
                                        acl_free(e_id_p);
                                        return ent;
                                }
                                acl_free(e_id_p);
                        } else {
                                return ent;
                        }
                }
                if (acl_get_entry(acl, ACL_NEXT_ENTRY, &ent) != 1)
                        return NULL;
        }
}


static int
remove_extended_entries(
	acl_t acl)
{
	acl_entry_t ent, group_obj;
	acl_permset_t mask_permset, group_obj_permset;
	acl_tag_t tag;
	int error;

	ent = find_entry(acl, ACL_MASK, ACL_UNDEFINED_ID);
	group_obj = find_entry(acl, ACL_GROUP_OBJ, ACL_UNDEFINED_ID);
	if (ent && group_obj) {
		if (!acl_get_permset(ent, &mask_permset) &&
		    !acl_get_permset(group_obj, &group_obj_permset)) {
			if (!acl_get_perm_np(mask_permset, ACL_READ))
				acl_delete_perm(group_obj_permset, ACL_READ);
			if (!acl_get_perm_np(mask_permset, ACL_WRITE))
				acl_delete_perm(group_obj_permset, ACL_WRITE);
			if (!acl_get_perm_np(mask_permset, ACL_EXECUTE))
				acl_delete_perm(group_obj_permset, ACL_EXECUTE);
		}
	}

	error = acl_get_entry(acl, ACL_FIRST_ENTRY, &ent);
	while (error == 1) {
		acl_get_tag_type(ent, &tag);
		switch(tag) {
			case ACL_USER:
			case ACL_GROUP:
			case ACL_MASK:
				acl_delete_entry(acl, ent);
				break;
			default:
				break;
		}

		error = acl_get_entry(acl, ACL_NEXT_ENTRY, &ent);
	}
	if (error < 0)
		return -1;
	return 0;
}

int
strip_acl_posix1e(struct acl_info *w, FTSENT *fts_entry)
{
	/*
	 * Convert non-trivial ACL to trivial ACL.
	 * This function is only called when action is set
	 * to 'strip'. A trivial ACL is one that is fully
	 * represented by the posix mode. If the goal is to
	 * simply remove ACLs, it will generally be more
	 * efficient to strip the ACL using setfacl -b
	 * from the root directory and then use the 'clone'
	 * action to set the ACL recursively.
	 */
	char *path;
	int ret;
	struct acl_obj *theacl;
	acl_t facl;

	if (fts_entry == NULL)
		path = w->path;
	else
		path = fts_entry->fts_accpath;

	theacl = w->ops->get_acl_fn(w, fts_entry, true);
	if (theacl->dacl != NULL) {
		acl_free(theacl->dacl);
		theacl->dacl = NULL;
		ret = acl_delete_def_file(path);
		if (ret != 0) {
			fprintf(stdout, "Failed to remove default entries\n");
			return -1;
		}
	}
	facl = (acl_t)theacl->facl;
	ret = remove_extended_entries(facl);
	if (ret != 0) {
		fprintf(stdout, "Failed to remove extended entries\n");
		return -1;
	}
	ret = w->ops->set_acl_fn(w, fts_entry, theacl, true);
	if (ret != 0) {
		fprintf(stdout, "Failed to set new acl\n");
		return -1;
	}
	w->ops->acl_free_fn(theacl);
	if (w->uid != -1 || w->gid != -1) {
		if (chown(path, w->uid, w->gid) < 0) {
			warn("%s: chown() failed", path);
			return (-1);
		}
	}
	return (0);
}

/*
 * Iterate through linked list of parent directories until we are able
 * to find one that exists in the snapshot directory. Use this ACL
 * to calculate an inherited acl.
 */
int get_acl_parent_posix1e(struct acl_info *w, FTSENT *fts_entry)
{
	int rval;
	FTSENT *p = NULL;
	FTSENT fake_ftsent;
	char *relpath = NULL;
	char shadow_path[PATH_MAX] = {0};
	struct acl_obj *parent_acl = NULL;

	if (fts_entry->fts_parent == NULL) {
		/*
		 * No parent node indicates we're at fts root level.
		 */
		ZERO_STRUCT(fake_ftsent);
                fake_ftsent.fts_path = w->source;
                fake_ftsent.fts_statp = &w->st;

		parent_acl = w->ops->get_acl_fn(w, &fake_ftsent, true);
		if (parent_acl == NULL) {
			return -1;
		}
		rval = w->ops->calculate_inherited_acl_fn(w, parent_acl, 0);
		if (rval != 0) {
			warn("%s: acl_get_file() failed", w->source);
		}
		acl_free(parent_acl);
		return rval;
	}

	for (p=fts_entry->fts_parent; p; p=p->fts_parent) {
		rval = snprintf(shadow_path, sizeof(shadow_path),
				"%s/%s", w->source, p->fts_accpath);
		if (rval < 0) {
			warn("%s: snprintf failed", relpath);
			return -1;
		}

		parent_acl->dacl = acl_get_file(shadow_path, ACL_TYPE_DEFAULT);
		if (parent_acl->dacl == NULL) {
			if (errno == ENOENT) {
				continue;
			}
			else {
				warn("%s: acl_get_file() failed", shadow_path);
				return -1;

			}
		}
		parent_acl->facl = acl_get_file(shadow_path, ACL_TYPE_ACCESS);
		if (parent_acl->facl == NULL) {
			return -1;
		}
		rval = w->ops->calculate_inherited_acl_fn(w, parent_acl, 0);
		if (rval == 0) {
			acl_free(parent_acl);
			return 0;
		}
		warn("%s: acl_get_file() failed", shadow_path);
		acl_free(parent_acl);
	}
	return -1;
}

/*
 * Compare two acl_t structs. Return 0 on success -1 on failure.
 */
#ifdef __linux__
static int acl_cmp_internal(acl_t source, acl_t dest, int flags)
{
	return acl_cmp(source, dest);
}
#else
static int acl_cmp_internal(acl_t source, acl_t dest, int flags)
{
	acl_entry_t s_entry, p_entry;
	acl_permset_t s_perm, p_perm;
	acl_tag_t s_tag, p_tag;
	id_t *s_id, *p_id;

	int entry_id = ACL_FIRST_ENTRY;
	int rv;

	while (acl_get_entry(source, entry_id, &s_entry) == 1) {
		entry_id = ACL_NEXT_ENTRY;
		rv = acl_get_entry(dest, entry_id, &p_entry);
		if (rv != 1) {
			if (flags & WA_VERBOSE) {
				fprintf(stdout, "+ [ACL_COUNT] ");
			}
			return -1;
		}
                acl_get_tag_type(s_entry, &s_tag);
                acl_get_tag_type(p_entry, &p_tag);

		if (s_tag != p_tag) {
			if (flags & WA_VERBOSE) {
				fprintf(stdout, "+ [ACL tag 0x%08x -> 0x%08x] ",
					s_tag, p_tag);
			}
			return -1;
		}
		s_id = acl_get_qualifier(s_entry);
		p_id = acl_get_qualifier(p_entry);
		if (*s_id != *p_id) {
			if (flags & WA_VERBOSE) {
				fprintf(stdout, "+ [ACL id %d -> %d] ",
					*s_id, *p_id);
			}
			return -1;
		}

		acl_get_permset(s_entry, &s_perm);
		acl_get_permset(p_entry, &p_perm);
		if (s_perm != p_perm) {
			if (flags & WA_VERBOSE) {
				fprintf(stdout, "+ [ACL perm 0x%08x -> 0x%08x] ",
					s_perm, p_perm);
			}
			return -1;
		}
	}
	return 0;
}
#endif

int acl_cmp_posix1e(struct acl_obj source, struct acl_obj dest, int flags)
{
	int rv;
	if ((source.dacl != NULL) && (dest.dacl != NULL)) {
		rv = acl_cmp_internal(source.dacl, dest.dacl, flags);
		if (rv != 0) {
			return -1;
		}
		rv = acl_cmp_internal(source.facl, dest.facl, flags);
		if (rv != 0) {
			return -1;
		}
		return 0;
	}
	else if ((source.facl != NULL) && (dest.facl != NULL)) {
		rv = acl_cmp_internal(source.facl, dest.facl, flags);
		if (rv != 0) {
			return -1;
		}
		return 0;
	}
	return -1;
}

static bool
get_parent_path(char *dir)
{
	ptrdiff_t len;
	char *p = NULL;
	for (;;)
	{
		p = strrchr(dir, '/');
		if (p == NULL) {
			return false;
		}
		len = p-dir;
		dir[len] = '\0';
		if (access(dir, F_OK) == 0) {
			break;
		}
	}
	return true;
}

int
restore_acl_posix1e(struct acl_info *w, char *relpath, FTSENT *fts_entry, size_t slen)
{
	int rval;
	bool found_parent = false;
	struct acl_obj *acl_new = NULL;
	struct acl_obj *acl_old = NULL;
	struct acl_obj *to_set = NULL;
	FTSENT new;
	char shadow_path[PATH_MAX] = {0};
	char *tmp_name = NULL;

	if (strlen(relpath) + slen > PATH_MAX) {
		warn("%s: path in snapshot directory is too long", relpath);
		return -1;
	}

	rval = snprintf(shadow_path, sizeof(shadow_path), "%s/%s", w->source, relpath);
	if (rval < 0) {
		warn("%s: snprintf failed", relpath);
		return -1;
	}
	ZERO_STRUCT(new);
	new.fts_path = shadow_path;
	new.fts_statp = fts_entry->fts_statp; //we only care about whether this is a dir.
	acl_new = w->ops->get_acl_fn(w, &new, true);
	if (acl_new == NULL) {
		if (errno == ENOENT) {
			if (w->flags & WA_FORCE) {
				tmp_name = strdup(shadow_path);
				found_parent = get_parent_path(tmp_name);
				if (!found_parent) {
					free(tmp_name);
					fprintf(stdout, "! %s\n", shadow_path);
					return 0;
				}
				new.fts_path = tmp_name;
				acl_new = w->ops->get_acl_fn(w, &new, true);
				if (acl_new == NULL) {
					warn("%s: OP_GET_ACL() failed", shadow_path);
					free(tmp_name);
					return -1;
				}
				free(tmp_name);
				w->ops->calculate_inherited_acl_fn(w, acl_new, 0);
				to_set = &w->acls[0];
				//to_set = acl_new;
			}
			else {
				fprintf(stdout, "! %s\n", shadow_path);
				return 0;
			}
		}
		else {
			warn("%s: OP_GET_ACL() failed", shadow_path);
			return (-1);
		}
	}
	else {
		to_set = acl_new;
	}

	acl_old = w->ops->get_acl_fn(w, fts_entry, true);
	if (acl_old == NULL) {
		warn("%s: OP_GETACL() failed", fts_entry->fts_path);
		return (-1);
	}

	rval = w->ops->acl_cmp_fn(*to_set, *acl_old, w->flags);

	if (rval == 0) {
		return 0;
	}

	if (w->flags & WA_VERBOSE) {
		fprintf(stdout, "%s -> %s\n",
			shadow_path,
			fts_entry->fts_path);
	}
	if ((w->flags & WA_TRIAL) == 0) {
		rval = w->ops->set_acl_fn(w, fts_entry, to_set, true);
		if (rval < 0) {
			warn("%s: OP_SET_ACL() failed", fts_entry->fts_path);
			w->ops->acl_free_fn(acl_old);
			w->ops->acl_free_fn(acl_new);
			return -1;
		}
	}

	w->ops->acl_free_fn(acl_old);
	w->ops->acl_free_fn(acl_new);
	return 0;
}

struct acl_obj
*get_acl_posix1e(struct acl_info *w, FTSENT *ftsentry, bool quiet)
{
	struct acl_obj *ret_acl = NULL;
	ret_acl = calloc(1, sizeof(struct acl_obj));
	if (ret_acl == NULL) {
		return NULL;
	}
	ret_acl->facl = acl_get_file(ftsentry->fts_path, ACL_TYPE_ACCESS);
	if (ret_acl->facl == NULL) {
		if (!quiet) {
			fprintf(stdout, "failed to get ACL on %s\n", ftsentry->fts_path);
		}
		free(ret_acl);
		return NULL;
	}
	if (ISDIR(ftsentry)) {
		ret_acl->dacl = acl_get_file(ftsentry->fts_path, ACL_TYPE_DEFAULT);
		if (!quiet && ret_acl->dacl == NULL) {
			fprintf(stdout, "failed to get DACL on %s\n", ftsentry->fts_path);
			return NULL;
		}
	}
	else {
		ret_acl->dacl = NULL;
	}
	ret_acl->is_valid = true;
	ret_acl->is_alloc = true;
	return ret_acl;
}

int
set_acl_posix1e(struct acl_info *w, FTSENT *fts_entry, struct acl_obj *theacl, bool quiet)
{
	char *path = NULL;
	struct acl_obj *acl_new;
	int acl_depth = 0;
	if (!quiet && w->flags & WA_VERBOSE) {
		fprintf(stdout, "%s\n", fts_entry->fts_path);
	}

	if (theacl != NULL) {
		acl_new = theacl;
	}
	else if (fts_entry->fts_level == FTS_ROOTLEVEL) {
		acl_new = w->source_acl;
	}
	else {
		if ((fts_entry->fts_level -1) >= MAX_ACL_DEPTH) {
			acl_depth = MAX_ACL_DEPTH-1;
		}
		else {
			acl_depth = fts_entry->fts_level -1;
		}
		acl_new = &w->acls[acl_depth];
	}

	/* write out the acl to the file */
	if (acl_set_file(fts_entry->fts_accpath, ACL_TYPE_ACCESS, acl_new->facl) < 0) {
		warn("%s: acl_set_file() failed", path);
		return (-1);
	}
	if (ISDIR(fts_entry) && (acl_set_file(fts_entry->fts_accpath, ACL_TYPE_DEFAULT, acl_new->facl)) < 0) {
		warn("%s: acl_set_file() failed", path);
		return (-1);
	}

	if (w->uid != -1 || w->gid != -1) {
		if (chown(path, w->uid, w->gid) < 0) {
			warn("%s: chown() failed", path);
			return (-1);
		}
	}

 
	return (0);
}

int
calculate_inherited_acl_posix1e(struct acl_info *w, struct acl_obj *parent_acl, int level)
{
	if (parent_acl->dacl != NULL) {
		w->acls[level].dacl = acl_dup(parent_acl->dacl);
		if (w->acls[level].dacl == NULL) {
			warn("acl_dup() failed");
			w->acls[level].is_valid = false;
			return -1;
		}
	}
	if (parent_acl->facl != NULL) {
		w->acls[level].facl = acl_dup(parent_acl->facl);
		if (w->acls[level].facl == NULL) {
			warn("acl_dup() failed");
			w->acls[level].is_valid = false;
			return -1;
		}
	}
	w->acls[level].is_valid = true;
	return 0;
}

void
acl_free_posix1e(struct acl_obj *tofree)
{
	if (tofree == NULL || !tofree->is_valid) {
		return;
	}
	if (tofree->is_valid && tofree->dacl != NULL) {
		acl_free(tofree->dacl);
	}
	if (tofree->is_valid && tofree->facl != NULL) {
		acl_free(tofree->facl);
	}
	tofree->is_valid = false;
	if (tofree->is_alloc) {
		free(tofree);
		tofree = NULL;
	}
	return;
}

static const struct acl_ops posix1e_acl_ops = {
	.restore_acl_fn = restore_acl_posix1e,
	.calculate_inherited_acl_fn = calculate_inherited_acl_posix1e,
	.set_acl_fn = set_acl_posix1e,
	.get_acl_fn = get_acl_posix1e,
	.get_acl_parent_fn = get_acl_parent_posix1e,
	.strip_acl_fn = strip_acl_posix1e,
	.acl_cmp_fn = acl_cmp_posix1e,
	.acl_free_fn = acl_free_posix1e,
};

