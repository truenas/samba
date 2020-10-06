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
#ifdef __linux__
#include <linux/limits.h>
#endif


#define	WA_NULL			0x00000000	/* nothing */
#define	WA_RECURSIVE		0x00000001	/* recursive */
#define	WA_VERBOSE		0x00000002	/* print more stuff */
#define	WA_CLONE		0x00000008	/* clone an ACL */
#define	WA_TRAVERSE		0x00000010	/* traverse filesystem mountpoints */
#define	WA_PHYSICAL		0x00000020	/* do not follow symlinks */
#define	WA_STRIP		0x00000040	/* strip ACL */
#define	WA_CHOWN		0x00000080	/* only chown */
#define	WA_TRIAL		0x00000100	/* trial run */
#define	WA_RESTORE		0x00000200	/* restore ACL */
#define	WA_FORCE		0x00000400	/* force */

#define	WA_OP_SET	(WA_CLONE|WA_STRIP|WA_CHOWN|WA_RESTORE)
#define	WA_OP_CHECK(flags, bit) ((flags & ~bit) & WA_OP_SET)
#define	MAX_ACL_DEPTH		2
#define ISDIR(x)(x->fts_statp->st_mode & S_IFDIR)
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

// FreeBSD acl_type_t arguments
#define ACL_TOOL_ACCESS		0x00000002
#define ACL_TOOL_DEFAULT	0x00000003
#define ACL_TOOL_NFSV4		0x00000004

enum aclbrand { ACL_BRAND_UNKNOWN, ACL_BRAND_POSIX1E, ACL_BRAND_NFSV4 };

struct acl_obj {	
	void *dacl; /*NFSV4 directory ACL or POSIX1e DEFAULT ACL*/
	void *facl; /*NFSV4 file ACL or POSIX1e ACCESS ACL*/
	bool is_valid;
	bool is_alloc;
};

struct acl_info;

struct acl_ops {
	int (*restore_acl_fn)(struct acl_info *w, char *relpath, FTSENT *fts_entry, size_t slen);
	int (*calculate_inherited_acl_fn)(struct acl_info *w, struct acl_obj *parent_acl, int depth);
	int (*set_acl_fn)(struct acl_info *w, FTSENT *fts_entry, struct acl_obj *to_set, bool quiet);
	struct acl_obj *(*get_acl_fn)(struct acl_info *w, FTSENT *fts_entry, bool quiet);
	int (*get_acl_parent_fn)(struct acl_info *w, FTSENT *fts_entry);
	int (*strip_acl_fn)(struct acl_info *w, FTSENT *fts_entry);
	int (*acl_cmp_fn)(struct acl_obj source, struct acl_obj dest, int flags);
	void (*acl_free_fn)(struct acl_obj *tofree);
};

struct acl_info {
	char *source;
	char *path;
	char *chroot;
	long pathmax;
	struct acl_obj *source_acl;
	dev_t root_dev;
	struct stat st;
	struct acl_obj *acls;
	uid_t uid;
	gid_t gid;
	int	flags;
	const struct acl_ops *ops;
	enum aclbrand brand;
};

void nfs4_acl_ops_init(struct acl_info *w);
void posix1e_acl_ops_init(struct acl_info *w);
