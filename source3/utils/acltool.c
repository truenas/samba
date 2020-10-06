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
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include "acltool.h"


struct {
	const char *str;
	int action;
} actions[] = {
	{	"clone",	WA_CLONE	},
	{	"strip",	WA_STRIP	},
	{	"chown",	WA_CHOWN	},
	{	"restore",	WA_RESTORE	}
};

size_t actions_size = sizeof(actions) / sizeof(actions[0]);

static int
get_action(const char *str)
{
	int i;
	int action = WA_NULL;

	for (i = 0;i < actions_size;i++) {
		if (strcasecmp(actions[i].str, str) == 0) {
			action = actions[i].action;
			break;
		}
	}

	return action;
}


static struct acl_info *
new_acl_info(void)
{
	struct acl_info *w = NULL;
	w = calloc(1, sizeof(struct acl_info));
	if (w == NULL) {
		err(EX_OSERR, "calloc() failed");
	}
	w->acls = calloc(MAX_ACL_DEPTH, sizeof(struct acl_obj));
	if (w->acls == NULL) {
		err(EX_OSERR, "calloc() failed");
	}
	w->brand = ACL_BRAND_UNKNOWN;
	w->uid = -1;
	w->gid = -1;

	return w;
}


static void
free_acl_info(struct acl_info *w)
{
	if (w == NULL)
		return;
	int i;

	free(w->source);
	w->source = NULL;
	free(w->path);
	w->path = NULL;
	if (w->brand != ACL_BRAND_UNKNOWN) {
		if (w->source_acl != NULL) {
			w->ops->acl_free_fn(w->source_acl);
		}
		for (i=0; i<=MAX_ACL_DEPTH; i++){
			if (&w->acls[i].is_valid) {
				w->ops->acl_free_fn(&w->acls[i]);
			}
		}
	}
	free(w->acls);
	free(w);
}


static void
usage(char *path)
{
	if (strcmp(path, "cloneacl") == 0) {
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -s <path>                    # source for ACL. If none specified then ACL taken from -p\n"
		"    -p <path>                    # path to recursively set ACL\n"
		"    -v                           # verbose\n",
		path
	);
	} else {
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -a <clone|strip|chown|restore> # action to perform <restore is experimental!>\n"
		"    -O <owner>                     # change owner\n"
		"    -G <group>                     # change group\n"
		"    -c <path>                      # chroot path\n"
		"    -s <source>                    # source (if cloning ACL). If none specified then ACL taken from -p\n"
		"    -p <path>                      # path to set\n"
		"    -r                             # recursive\n"
		"    -v                             # verbose\n"
		"    -t                             # trial run - makes no changes\n"
		"    -x                             # traverse filesystem mountpoints\n"
		"    -f                             # force acl inheritance\n",
		path
	);
	}

	exit(0);
}

static inline char *get_relative_path(FTSENT *entry, size_t plen)
{
	char *relpath = NULL;
	relpath = entry->fts_path + plen;
	if (relpath[0] == '/') {
		relpath++;
	}
	return relpath;
}

static int
fts_compare(const FTSENT **s1, const FTSENT **s2)
{
	return (strcoll((*s1)->fts_name, (*s2)->fts_name));
}

static int
iter_acls(struct acl_info *w)
{
	FTS *tree = NULL;
	FTSENT *entry;
	int options = 0;
	char *paths[4];
	int rval;
	struct stat ftsroot_st;
	size_t slen, plen;
	char *relpath = NULL;

	if (w == NULL)
		return (-1);

	if (stat(w->path, &ftsroot_st) < 0) {
		err(EX_OSERR, "%s: stat() failed", w->path);
	}

	paths[0] = w->path;
	paths[1] = NULL;

	if ((w->flags & WA_TRAVERSE) == 0 || (w->flags & WA_RESTORE)) {
		options |= FTS_XDEV;
	}

	if ((tree = fts_open(paths, options, fts_compare)) == NULL)
		err(EX_OSERR, "fts_open");

        slen = strlen(w->source);
        plen = strlen(w->path);

	/* traverse directory hierarchy */
	for (rval = 0; (entry = fts_read(tree)) != NULL;) {
		if ((w->flags & WA_RECURSIVE) == 0) {
			if (entry->fts_level == FTS_ROOTLEVEL){
				if (w->flags & WA_STRIP) {
					rval = w->ops->strip_acl_fn(w, entry);
					break;
				}
				rval = w->ops->set_acl_fn(w, entry, w->source_acl, false);
				break;
			}
		}

		/*
		 * Recursively set permissions for the target path.
		 * In case FTS_XDEV is set, we still need to check st_dev to avoid
		 * resetting permissions on subdatasets (FTS_XDEV will only prevent us
		 * from recursing into directories inside the subdataset.
		 */

		if ( (options & FTS_XDEV) && (ftsroot_st.st_dev != entry->fts_statp->st_dev) ){
			continue;
		}

		switch (entry->fts_info) {
			case FTS_D:
			case FTS_F:
				if (w->root_dev == entry->fts_statp->st_dev) {
					warnx("%s: path resides in boot pool", entry->fts_path);
					return -1;
				}
				if (w->flags & WA_RESTORE) {
					relpath = get_relative_path(entry, plen);

					if (strlen(entry->fts_path) > PATH_MAX) {
						warnx("%s: PATH TOO LONG", entry->fts_path);
						return -1;
					}
					rval = w->ops->restore_acl_fn(w, relpath, entry, slen);
					break;
				}
				if (w->flags & WA_TRIAL) {
					fprintf(stdout, "depth: %d, name: %s, full_path: %s\n",
						entry->fts_level, entry->fts_name, entry->fts_path);
					break;
				}
				if (w->flags & WA_STRIP) {
					rval = w->ops->strip_acl_fn(w, entry);
				}
				else if (w->flags & WA_CHOWN) {
					if ((w->uid == (uid_t)-1 || w->uid == entry->fts_statp->st_uid) &&
					    (w->gid == (gid_t)-1 || w->gid == entry->fts_statp->st_gid)){
						continue;
					}
					if (chown(entry->fts_accpath, w->uid, w->gid) < 0) {
						warn("%s: chown() failed", entry->fts_accpath);
						rval = -1;
					}
					if (w->flags & WA_VERBOSE)
						fprintf(stdout, "%s\n", entry->fts_accpath);

				}
				else {
					rval = w->ops->set_acl_fn(w, entry, NULL, false);
				}
				break;

			case FTS_ERR:
				warnx("%s: %s", entry->fts_path, strerror(entry->fts_errno));
				rval = -2;
				continue;
		}
		if (rval < 0) {
			err(EX_OSERR, "%s: iter_acls() failed", entry->fts_accpath);
			continue;
		}

	} 
	fts_close(tree);

	return (rval);
}


static void
usage_check(struct acl_info *w)
{
	if (w->path == NULL)
		errx(EX_USAGE, "no path specified");

	if (!WA_OP_CHECK(w->flags, ~WA_OP_SET) &&
		w->acls[0].dacl == NULL && w->acls[0].facl == NULL)
		errx(EX_USAGE, "nothing to do");

}

static uid_t
id(const char *name, const char *type)
{
	uid_t val;
	char *ep = NULL;

	/*
	 * We know that uid_t's and gid_t's are unsigned longs.
	 */
	errno = 0;
	val = strtoul(name, &ep, 10);
	if (errno || *ep != '\0')
		errx(1, "%s: illegal %s name", name, type);
	return (val);
}

static gid_t
a_gid(const char *s)
{
	struct group *gr = NULL;
	return ((gr = getgrnam(s)) != NULL) ? gr->gr_gid : id(s, "group");
}

static uid_t
a_uid(const char *s)
{
	struct passwd *pw = NULL;
	return ((pw = getpwnam(s)) != NULL) ? pw->pw_uid : id(s, "user");
}

static void set_aclinfo_brand(struct acl_info *w) {
#if HAS_NFS4_ACLS
	if (pathconf(w->source, _PC_ACL_NFS4) < 0) {
		posix1e_acl_ops_init(w);
	}
	else {
		nfs4_acl_ops_init(w);
	}
#else
	posix1e_acl_ops_init(w);
#endif
}

int
main(int argc, char **argv)
{
	int 	ch, ret;
	ch = ret = 0;
	struct stat st;
	struct acl_info *w = NULL;
	FTSENT fake_ftsent;
	ZERO_STRUCT(fake_ftsent);
	if (argc < 2) {
		usage(argv[0]);
	}
	w = new_acl_info();

	while ((ch = getopt(argc, argv, "a:O:G:c:s:p:rftvx")) != -1) {
		switch (ch) {
			case 'a': {
				int action = get_action(optarg);
				if (action == WA_NULL)
					errx(EX_USAGE, "invalid action");
				if (WA_OP_CHECK(w->flags, action))
					errx(EX_USAGE, "only one action can be specified");
				w->flags |= action;
				break;
			}

			case 'O': {
				w->uid = a_uid(optarg);
				break;
			}

			case 'G': {
				w->gid = a_gid(optarg);
				break;
			}

			case 'c':
				w->chroot = realpath(optarg, NULL);
				break;

			case 's':
				w->source = realpath(optarg, NULL);
				break;

			case 'p':
				w->path = realpath(optarg, NULL);
				break;

			case 'r':
				w->flags |= WA_RECURSIVE;
				break;

			case 't':
				w->flags |= WA_TRIAL;
				break;

			case 'v':
				w->flags |= WA_VERBOSE;
				break;

			case 'x':
				w->flags |= WA_TRAVERSE;
				break;

			case 'f':
				w->flags |= WA_FORCE;
				break;

			case '?':
			default:
				usage(argv[0]);
			}
	}

	if (w->path == NULL) {
		errno = EINVAL;
		warn("Path [-p] must be specified");
		usage(argv[0]);
	}

	/* set the source to the destination if we lack -s */
	if (w->source == NULL) {
		if (w->flags & WA_RESTORE) {
			warn("source must be set for restore jobs");
			return (1);
		}
		w->source = strdup(w->path);
		if (w->source == NULL) {
			warn("failed to duplicate path name");
			return (1);
		}
	}

	if (stat("/", &st) < 0) {
		warn("%s: stat() failed.", "/");
		return (1);
	}
	w->root_dev = st.st_dev;
	w->st = st;

	if (w->chroot != NULL) {
		if (w->source != NULL) {
			if (strncmp(w->chroot, w->source, strlen(w->chroot)) != 0) {
				warn("%s: path does not lie in chroot path.", w->source);
				free_acl_info(w);
				return (1);
			}
			w->source += strlen(w->chroot);
		}
		if (w->path != NULL ) {
			if (strncmp(w->chroot, w->path, strlen(w->chroot)) != 0) {
				warn("%s: path does not lie in chroot path.", w->path);
				free_acl_info(w);
				return (1);
			}
			w->path += strlen(w->chroot);
		}
		ret = chdir(w->chroot);
		if (ret == -1) {
			warn("%s: chdir() failed.", w->chroot);
			free_acl_info(w);
			return (1);
		}
		ret = chroot(w->chroot);
		if (ret == -1) {
			warn("%s: chroot() failed.", w->chroot);
			free_acl_info(w);
			return (1);
		}
		if (access(w->path, F_OK) < 0) {
			warn("%s: access() failed after chroot.", w->source);
			free_acl_info(w);
			return (1);
		}
	}

	if (access(w->source, F_OK) < 0) {
		warn("%s: access() failed.", w->source);
		free_acl_info(w);
		return (1);
	}

	set_aclinfo_brand(w);

	if (w->flags & WA_CLONE){
		fake_ftsent.fts_path = w->source;
		fake_ftsent.fts_statp = &w->st;
		w->source_acl = w->ops->get_acl_fn(w, &fake_ftsent, false);
		if (w->source_acl == NULL) {
			err(EX_OSERR, "%s: acl_get_file() failed", w->source);
			free_acl_info(w);
			return (1);
		}

		ret = w->ops->calculate_inherited_acl_fn(w, w->source_acl, 0);
		if (ret != 0) {
			free_acl_info(w);
			return (1);
		}
		ret = w->ops->calculate_inherited_acl_fn(w, &w->acls[0], 1);
		if (ret != 0) {
			free_acl_info(w);
			return (1);
		}
	}

	usage_check(w);

	if (iter_acls(w) <0) {
		ret = 1;
	}

	free_acl_info(w);
	return (ret);
}
