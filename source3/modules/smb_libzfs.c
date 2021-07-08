/*-
 * Copyright 2018 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdbool.h>
#include <talloc.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/nvpair.h>
#include <libzfs.h>
#include <fnmatch.h>
#include "lib/util/debug.h"
#include "lib/util/dlinklist.h"
#include "lib/util/memcache.h"
#include "smb_macros.h"
#include "includes.h"
#include "modules/smb_libzfs.h"
#include "smbd/globals.h"
#include "smbd/smbd.h"

#define SHADOW_COPY_ZFS_GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"
#define ZFS_PROP_SAMBA_PREFIX "org.samba"
#define ZFSERR_EQUAL(lz, err) (libzfs_errno(lz) == err)
#define STOLZ(x) (x->sli->libzfsp)
#define STOERR(x) (libzfs_error_description(STOLZ(x)))

struct share_dataset_list {
	struct dataset_list *dl;
	char *connectpath;
	struct share_dataset_list *prev, *next;
};

static struct share_dataset_list *shareds = NULL;

static struct enum_list casesensitivity[] = {
	{SMBZFS_SENSITIVE, "sensitive"},
	{SMBZFS_INSENSITIVE, "insensitive"},
	{SMBZFS_MIXED, "mixed"},
	{ -1, NULL}
};

struct smblibzfs_int {
	libzfs_handle_t *libzfsp;
};

struct smbzhandle_int {
	zfs_handle_t *zhandle;
};

struct iter_info
{
	bool ignore_empty_snaps;
	const char **inclusions;
	const char **exclusions;
	time_t start;
	time_t end;
};

struct snap_cb
{
	struct snapshot_list *snapshots;
	struct iter_info *iter_info;
};

struct child_cb
{
	struct dataset_list *dslist;
	bool open_zhandle;
};

static int get_enum(const char *s, const struct enum_list *_enum)
{
	int i;

	if (!s || !*s || !_enum) {
		return (-1);
	}

	for (i=0; _enum[i].name; i++) {
		if (strcmp(_enum[i].name,s) == 0)
			return _enum[i].value;
	}

	DBG_ERR("get_enum(%s,enum): value is not in enum_list!\n", s);
	return (-1);
}

static int libzfserr_to_errno(int libzfs_err)
{
	int error = 0;

	switch (libzfs_err) {
	case EZFS_NOMEM:
		error = ENOMEM;
		break;
	case EZFS_BADPROP:
	case EZFS_PROPREADONLY:
	case EZFS_PROPTYPE:
	case EZFS_PROPNONINHERIT:
	case EZFS_PROPSPACE:
	case EZFS_BADTYPE:
	case EZFS_BADSTREAM:
	case EZFS_BADTARGET:
	case EZFS_BADDEV:
	case EZFS_BADVERSION:
	case EZFS_BADPATH:
	case EZFS_ISSPARE:
	case EZFS_INVALCONFIG:
	case EZFS_POOL_INVALARG:
	case EZFS_BADPERM:
	case EZFS_BADPERMSET:
	case EZFS_ISL2CACHE:
	case EZFS_DIFFDATA:
	case EZFS_WRONG_PARENT:
		error = EINVAL;
		break;
	case EZFS_BUSY:
	case EZFS_RESILVERING:
	case EZFS_ZONED:
	case EZFS_UNPLAYED_LOGS:
	case EZFS_SCRUB_PAUSED:
	case EZFS_DISCARDING_CHECKPOINT:
	case EZFS_DEVRM_IN_PROGRESS:
	case EZFS_ACTIVE_POOL:
	case EZFS_INITIALIZING:
		error = EBUSY;
		break;
	case EZFS_EXISTS:
	case EZFS_REFTAG_HOLD:
	case EZFS_CHECKPOINT_EXISTS:
		error = EEXIST;
		break;
	case EZFS_NOENT:
	case EZFS_NOREPLICAS:
	case EZFS_NOHISTORY:
	case EZFS_BADWHO:
	case EZFS_REFTAG_RELE:
	case EZFS_NO_CHECKPOINT:
		error = ENOENT;
		break;
	case EZFS_DSREADONLY:
	case EZFS_POOLREADONLY:
		error = EROFS;
		break;
	case EZFS_VOLTOOBIG:
	case EZFS_VDEV_TOO_BIG:
	case EZFS_TOOMANY:
		error = E2BIG;
		break;
	case EZFS_INVALIDNAME:
	case EZFS_NAMETOOLONG:
	case EZFS_TAGTOOLONG:
		error = ENAMETOOLONG;
		break;
	case EZFS_BADRESTORE:
	case EZFS_BADBACKUP:
	case EZFS_MOUNTFAILED:
	case EZFS_UMOUNTFAILED:
	case EZFS_UNSHARENFSFAILED:
	case EZFS_SHARENFSFAILED:
	case EZFS_UNSHARESMBFAILED:
	case EZFS_SHARESMBFAILED:
	case EZFS_FAULT:
	case EZFS_POOLPROPS:
	case EZFS_OPENFAILED:
	case EZFS_NOCAP:
	case EZFS_LABELFAILED:
	case EZFS_ACTIVE_SPARE:
	case EZFS_THREADCREATEFAILED:
	case EZFS_POSTSPLIT_ONLINE:
	case EZFS_DIFF:
		error = EFAULT;
		break;
	case EZFS_POOLUNAVAIL:
	case EZFS_BADCACHE:
	case EZFS_NO_INITIALIZE:
		error = ENXIO;
		break;
	case EZFS_DEVOVERFLOW:
		error = EOVERFLOW;
		break;
	case EZFS_CROSSTARGET:
		error = EXDEV;
		break;
	case EZFS_PERM:
	case EZFS_NODELEGATION:
		error = EPERM;
		break;
	case EZFS_NOSPC:
		error = ENOSPC;
		break;
	case EZFS_IO:
		error = EIO;
		break;
	case EZFS_INTR:
		error = EINTR;
		break;
	case EZFS_RECURSIVE:
		error = ELOOP;
		break;
	case EZFS_NOTSUP:
		error = EOPNOTSUPP;
		break;
	case EZFS_POOL_NOTSUP:
	case EZFS_VDEVNOTSUP:
		error = ENODEV;
		break;
	case EZFS_PIPEFAILED:
		error = EPIPE;
		break;
	case EZFS_SCRUBBING:
	case EZFS_NO_PENDING:
		error = EAGAIN;
		break;
	case EZFS_UNKNOWN:
		error = EFAULT;
		break;
	default:
		if (libzfs_err != 0) {
			DBG_NOTICE("%d: could not convert ZFS error to errno\n",
				   libzfs_err);
			error = EFAULT;
		}
	}

	return error;
}

static int smblibzfs_handle_destructor(struct smblibzfs_int *slibzp)
{
	if (slibzp->libzfsp == NULL) {
		DBG_ERR("Failed to retrieve libzfs handle"
			"from smblibzfs handle\n");
		return 0;
	}
	libzfs_fini(slibzp->libzfsp);
	return 0;
}

static int smbzhandle_destructor(struct smbzhandle_int *szhp)
{
	if (szhp->zhandle == NULL) {
		DBG_INFO("Failed to retrieve smb zfs dataset handle"
			"from smbzhandle\n");
		return 0;
	}
	zfs_close(szhp->zhandle);
	return 0;
}

int get_smblibzfs_handle(TALLOC_CTX *mem_ctx,
			 struct smblibzfshandle **smblibzfsp)
{
	libzfs_handle_t *libzfsp = NULL;
	struct smblibzfs_int *slibzp_int = NULL;
	struct smblibzfshandle *slibzp_ext = NULL;
	slibzp_ext = talloc_zero(mem_ctx, struct smblibzfshandle);
	if (slibzp_ext == NULL) {
		errno = ENOMEM;
		return -1;
	}
	slibzp_int = talloc_zero(slibzp_ext, struct smblibzfs_int);
	if (slibzp_int == NULL) {
		errno = ENOMEM;
		return -1;
	}
	libzfsp = libzfs_init();
	if (libzfsp == NULL) {
		DBG_ERR("Failed to init libzfs\n");
		return -1;
	}
	libzfs_print_on_error(libzfsp, B_FALSE);
	slibzp_int->libzfsp = libzfsp;
	talloc_set_destructor(slibzp_int, smblibzfs_handle_destructor);
	slibzp_ext->sli = slibzp_int;
	slibzp_ext->zcache = memcache_init(slibzp_ext, (1024 * 1024));
	*smblibzfsp = slibzp_ext;
	return 0;
}

static int existing_parent_name(const char *path, char *buf, size_t buflen, int *nslashes);

static zfs_handle_t *get_zhandle(struct smblibzfshandle *smblibzfsp,
				 const char *path, bool resolve)
{
	/* "path" here can be either mountpoint or dataset name */
	zfs_handle_t *zfsp = NULL;

	if (smblibzfsp->sli == NULL) {
		DBG_ERR("Failed to retrieve smblibzfs_int handle\n");
		return zfsp;
	}

	if (path == NULL) {
		DBG_ERR("No pathname provided\n");
		return zfsp;
	}

	zfsp = zfs_path_to_zhandle(STOLZ(smblibzfsp), discard_const(path),
				   ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL) {
		if (resolve && errno == ENOENT) {
			int rv, to_create;
			char parent[ZFS_MAXPROPLEN] = {0};

			rv = existing_parent_name(path, parent, sizeof(parent), &to_create);
			if (rv != 0) {
				DBG_ERR("Unable to access parent of %s\n", path);
				errno = ENOENT;
				return NULL;
			}
			DBG_INFO("Path [%s] does not exist, optaining zfs dataset handle from "
				 "path [%s]\n", path, parent);
			zfsp = zfs_path_to_zhandle(STOLZ(smblibzfsp), parent,
						   ZFS_TYPE_FILESYSTEM);
			if (zfsp == NULL) {
				DBG_ERR("%s: Failed to obtain zhandle on path: %s\n",
					parent, STOERR(smblibzfsp));
				errno = libzfserr_to_errno(libzfs_errno(STOLZ(smblibzfsp)));
			}
			return zfsp;
		}
		DBG_ERR("%s: zfs_path_to_zhandle() failed: %s\n",
			path, STOERR(smblibzfsp));
	}
	return zfsp;
}

static zfs_handle_t *get_zhandle_from_smbzhandle(struct smbzhandle *smbzhandle)
{
	SMB_ASSERT(smbzhandle->is_open);
	return smbzhandle->zhp->zhandle;
}

int get_smbzhandle(struct smblibzfshandle *smblibzfsp,
		   TALLOC_CTX *mem_ctx, char *path,
		   struct smbzhandle **smbzhandle,
		   bool resolve)
{
	zfs_handle_t *zfsp = NULL;
	struct smbzhandle_int *szhandle_int = NULL;
	struct smbzhandle *szhandle_ext = NULL;
	zfsp = get_zhandle(smblibzfsp, path, resolve);

	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: [%s]: %s\n",
			path, strerror(errno));
		return -1;
	}
	szhandle_int = talloc_zero(mem_ctx, struct smbzhandle_int);
	if (szhandle_int == NULL) {
		errno = ENOMEM;
		return -1;
	}
	szhandle_ext = talloc_zero(mem_ctx, struct smbzhandle);
	if (szhandle_ext == NULL) {
		errno = ENOMEM;
		return -1;
	}
	szhandle_int->zhandle = zfsp;
	szhandle_ext->is_open = true;
	szhandle_ext->zhp = szhandle_int;
	szhandle_ext->lz = smblibzfsp;
	*smbzhandle = szhandle_ext;
	return 0;
}

void close_smbzhandle(struct smbzhandle *zfsp_ext)
{
	if (!zfsp_ext->is_open) {
		return;
	}
	zfs_handle_t *zfsp_int = NULL;
	zfsp_int = get_zhandle_from_smbzhandle(zfsp_ext);
	if (!zfsp_int) {
		DBG_ERR("failed to get zhandle\n");
		zfsp_ext->is_open = false;
		return;
	}
	zfs_close(zfsp_int);
	zfsp_int = NULL;
	zfsp_ext->is_open = false;
	return;
}

int
smb_zfs_path_to_dataset(struct smblibzfshandle *smblibzfsp,
			const char *pathname,
			const char **dataset_name_out)
{
	zfs_handle_t *zfsp = NULL;
	zfsp = get_zhandle(smblibzfsp, pathname, false);

	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on parent directory: (%s)\n",
			pathname);
		return -1;
	}

	*dataset_name_out = zfs_get_name(zfsp);
	zfs_close(zfsp);
	return 0;
}

int
smb_zfs_get_userspace_quota(struct smblibzfshandle *smblibzfsp,
		  char *path, int64_t xid,
		  enum SMB_QUOTA_TYPE quota_type,
		  uint64_t *hardlimit, uint64_t *usedspace)
{
	int ret;
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	char u_req[ZFS_MAXPROPLEN] = { 0 };
	char q_req[ZFS_MAXPROPLEN] = { 0 };
	uint64_t quota, used;
	quota = used = 0;
	if (smblibzfsp->sli == NULL) {
		DBG_ERR("Failed to retrieve smblibzfs_int handle\n");
		return -1;
	}

	DBG_DEBUG("Path: (%s), xid: %lu), qtype (%u)\n",
		path, xid, quota_type);

	switch (quota_type) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		snprintf(u_req, sizeof(u_req), "userused@%lu", xid);
		snprintf(q_req, sizeof(q_req), "userquota@%lu", xid);
		DBG_DEBUG("u_req: (%s), q_req (%s)\n", u_req, q_req);
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		snprintf(u_req, sizeof(u_req), "groupused@%lu", xid);
		snprintf(q_req, sizeof(q_req), "groupquota@%lu", xid);
		DBG_DEBUG("u_req: (%s), q_req (%s)\n", u_req, q_req);
		break;
	default:
		DBG_ERR("Received unknown quota type (%d)\n", quota_type);
		return (-1);
	}

	if (path == NULL) {
		DBG_ERR("Path does not exist\n");
		return (-1);
	}

	zfsp = zfs_path_to_zhandle(smblibzfsp->sli->libzfsp, path,
		ZFS_TYPE_VOLUME|ZFS_TYPE_DATASET|ZFS_TYPE_FILESYSTEM);

	if (zfsp == NULL) {
		DBG_ERR("Failed to convert path (%s) to zhandle\n", path);
		return (-1);
	}

	zfs_prop_get_userquota_int(zfsp, q_req, &quota);
	zfs_prop_get_userquota_int(zfsp, u_req, &used);

	zfs_close(zfsp);

	quota /= blocksize;
	used /= blocksize;

	*hardlimit = quota;
	*usedspace = used;

	return 0;
}

int
smb_zfs_set_userspace_quota(struct smblibzfshandle *smblibzfsp,
		  char *path, int64_t xid,
		  enum SMB_QUOTA_TYPE quota_type,
		  uint64_t hardlimit,
		  uint64_t blocksize)
{
	zfs_handle_t *zfsp = NULL;
	char q_req[256] = { 0 };
	char quota[256] = { 0 };

	snprintf(quota, sizeof(quota), "%lu", (hardlimit * blocksize));
	SMB_ASSERT(smblibzfsp->sli != NULL);

	DBG_DEBUG("Path: (%s), xid: %lu), qtype (%u), limit (%lu)\n",
		path, xid, quota_type, hardlimit);
	switch (quota_type) {
	case SMB_USER_QUOTA_TYPE:
	case SMB_USER_FS_QUOTA_TYPE:
		snprintf(q_req, sizeof(q_req), "userquota@%lu", xid);
		DBG_DEBUG("userquota string is (%s)\n", q_req);
		break;
	case SMB_GROUP_QUOTA_TYPE:
	case SMB_GROUP_FS_QUOTA_TYPE:
		snprintf(q_req, sizeof(q_req), "groupquota@%lu", xid);
		DBG_DEBUG("groupquota string is (%s)\n", q_req);
		break;
	default:
		DBG_ERR("Received unknown quota type (%d)\n", quota_type);
		return (-1);
	}

	if (path == NULL) {
		DBG_ERR("smb_zfs_set_quota received NULL path\n");
		return (-1);
	}

	zfsp = zfs_path_to_zhandle(STOLZ(smblibzfsp), path,
				   ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL){
		DBG_ERR("%s: zfs_path_to_zhandle() failed: %s\n",
			 path, STOERR(smblibzfsp));
		errno = libzfserr_to_errno(libzfs_errno(STOLZ(smblibzfsp)));
		return (-1);
	}

	if (zfs_prop_set(zfsp, q_req, quota) != 0) {
		DBG_ERR("%s: Failed to set (%s = %s): %s\n",
			path, q_req, quota, STOERR(smblibzfsp));
		zfs_close(zfsp);
		errno = libzfserr_to_errno(libzfs_errno(STOLZ(smblibzfsp)));
		return (-1);
	}

	zfs_close(zfsp);
	DBG_INFO("%s: smb_zfs_set_quota: Set (%s = %s)\n", path, q_req, quota);
	return 0;
}

uint64_t
smb_zfs_disk_free(struct smblibzfshandle *smblibzfsp,
		  char *path, uint64_t *bsize, uint64_t *dfree,
		  uint64_t *dsize, uid_t euid)
{
	size_t blocksize = 1024;
	zfs_handle_t *zfsp = NULL;
	char uu_req[256] = { 0 };
	char uq_req[256] = { 0 };
	uint64_t available, usedbysnapshots, usedbydataset,
		usedbychildren, real_used, total,
		userquota, userused, userquotarem;

	snprintf(uu_req, sizeof(uu_req), "userused@%u", euid);
	snprintf(uq_req, sizeof(uq_req), "userquota@%u", euid);
	if (smblibzfsp->sli == NULL) {
		DBG_ERR("Failed to retrieve smblibzfs_int handle\n");
		return -1;
	}

	if (path == NULL) {
		DBG_ERR("received NULL path\n");
		return (-1);
	}

	zfsp = zfs_path_to_zhandle(STOLZ(smblibzfsp), path,
				   ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL){
		DBG_ERR("%s: zfs_path_to_zhandle() failed: %s\n",
			 path, STOERR(smblibzfsp));
		errno = libzfserr_to_errno(libzfs_errno(STOLZ(smblibzfsp)));
		return (-1);
	}

	available = zfs_prop_get_int(zfsp, ZFS_PROP_AVAILABLE);
	usedbysnapshots = zfs_prop_get_int(zfsp, ZFS_PROP_USEDSNAP);
	usedbydataset = zfs_prop_get_int(zfsp, ZFS_PROP_USEDDS);
	usedbychildren = zfs_prop_get_int(zfsp, ZFS_PROP_USEDCHILD);
	zfs_prop_get_userquota_int(zfsp, uq_req, &userquota);
	zfs_prop_get_userquota_int(zfsp, uu_req, &userused);

	zfs_close(zfsp);

	real_used = usedbysnapshots + usedbydataset + usedbychildren;

	userquotarem = (userquota - userused) / blocksize;
	userquota /= blocksize;

	total = (real_used + available) / blocksize;
	available /= blocksize;

	*bsize = blocksize;
	if ( userquota && (available > userquotarem) ) {
		*dfree = userquotarem;
	}
	else {
		*dfree = available;
	}
	if ( userquota && (total > userquota) ) {
		*dsize = userquota;
	}
	else {
		*dsize = total;
	}

	return (*dfree);
}

static int
existing_parent_name(const char *path,
		     char *buf,
		     size_t buflen,
		     int *nslashes)
{
	char *slashp = NULL;
	*nslashes = 0;
	strlcpy(buf, path, buflen);
	for (;;) {
		slashp = strrchr(buf, '/');
		if (slashp == NULL) {
			return -1;
		}
		*nslashes += 1;
		*slashp = '\0';
		if (access(buf, F_OK) == 0) {
			break;
		}
	}
	return 0;
}

static int
get_mp_offset(zfs_handle_t *zfsp, size_t *offset)
{
	int rv;
	char parent_mp[ZFS_MAXPROPLEN] = {0};
	const char *parent_dsname = NULL;

	parent_dsname = zfs_get_name(zfsp);
	rv = zfs_prop_get(zfsp, ZFS_PROP_MOUNTPOINT, parent_mp,
			  sizeof(parent_mp), NULL, NULL,
			  0, 0);
	if (rv != 0) {
		DBG_ERR("Failed to get mountpoint for %s: %s\n",
			parent_dsname, strerror(errno));
		return -1;
	}
	*offset = strlen(parent_mp) - strlen(parent_dsname);
	return rv;
}

static char *
get_target_name(TALLOC_CTX *mem_ctx, zfs_handle_t *zfsp, const char *path)
{
	int error;
	size_t len_mp;
	char *out = NULL;
	error = get_mp_offset(zfsp, &len_mp);

	if (error) {
		errno = EINVAL;
		return NULL;
	}
	if (strlen(path) < len_mp) {
		errno = EINVAL;
		return NULL;
	}

	out = talloc_strdup(mem_ctx, path + len_mp);
	if (out == NULL) {
		errno = ENOMEM;
		DBG_ERR("%s: talloc_strdup() failed.\n", path);
	}
	return out;
}

static int
create_dataset_internal(struct smblibzfshandle *lz,
			char *to_create,
			char *quota)
{
	/* Create and mount new dataset. to_create should be dataset name */
	int rv;
	zfs_handle_t *new = NULL;

	/*
	 * Dataset may already exist, but be unmounted. In this case,
	 * ignore failure to create it, and simply mount the dataset.
	 */
	rv = zfs_create(lz->sli->libzfsp, to_create, ZFS_TYPE_FILESYSTEM, NULL);
	if ((rv != 0) && !ZFSERR_EQUAL(lz->sli->libzfsp, EZFS_EXISTS)) {
		DBG_ERR("Failed to create dataset [%s]: %s\n",
			to_create, STOERR(lz));
		errno = libzfserr_to_errno(libzfs_errno(STOLZ(lz)));
		return -1;
	}

	new = zfs_open(lz->sli->libzfsp, to_create, ZFS_TYPE_FILESYSTEM);
	if (new == NULL) {
		DBG_ERR("Failed to open dataset [%s]: %s\n",
			to_create, STOERR(lz));
		errno = libzfserr_to_errno(libzfs_errno(STOLZ(lz)));
		return -1;
	}

	rv = zfs_mount(new, NULL, 0);
	if (rv != 0) {
		DBG_ERR("Failed to mount dataset [%s] after dataset "
			"creation: %s\n", to_create, STOERR(lz));
		goto failure;
	}

	if (quota != NULL) {
		rv = zfs_prop_set(new, "quota", quota);
		if (rv != 0) {
			DBG_ERR("Failed to set quota to (%s): %s\n",
				quota, STOERR(lz));
		}
	}
failure:
	zfs_close(new);
	return rv;
}

/*
 * Convert `path` to struct dataset_list. `depth`
 * indicates how many path components will be converted into datasets.
 * lowest path component will be `root` dataset in struct.
 * For example, given path "/mnt/dozer/SHARE/DOMAIN/smbuser", with
 * corresponding datasets dozer/SHARE/DOMAIN/smbuser. If path is
 * provided with depth 2, then:
 *
 * dl->root will be dozer/SHARE
 * dl->children will point to dozer/SHARE/DOMAIN,
 * dl->children->next will point to dozer/SHARE/DOMAIN/smbuser
 */
struct dataset_list *path_to_dataset_list(TALLOC_CTX *mem_ctx,
					  struct smblibzfshandle *lz,
					  const char *path,
					  int depth)
{
	struct dataset_list *dl = NULL;
	char tmp_path[ZFS_MAXPROPLEN] = {0};

	strlcpy(tmp_path, path, sizeof(tmp_path));
	dl = talloc_zero(mem_ctx, struct dataset_list);

	for (; dl->nentries < depth; dl->nentries++) {
		char *slashp = NULL;
		struct zfs_dataset *ds = NULL;

		ds = smb_zfs_path_get_dataset(lz, mem_ctx, tmp_path, true, false, false);
		if (ds == NULL) {
			TALLOC_FREE(dl);
			return NULL;
		}
		DLIST_ADD(dl->children, ds);

		slashp = strrchr(tmp_path, '/');
		if (slashp == NULL) {
			DBG_ERR("Exiting at depth %zu", dl->nentries);
			break;
		}
		*slashp = '\0';
	}

	dl->root = smb_zfs_path_get_dataset(lz, mem_ctx, tmp_path, true, false, false);
	if (dl->root == NULL) {
		TALLOC_FREE(dl);
		return NULL;
	}

	return dl;
}

int
smb_zfs_create_dataset(TALLOC_CTX *mem_ctx,
		       struct smblibzfshandle *smblibzfsp,
		       const char *path, char *quota,
		       struct dataset_list **created,
		       bool create_ancestors)
{
	int rv, to_create;
	zfs_handle_t *zfsp = NULL;
	char parent[ZFS_MAXPROPLEN] = {0};
	char *target_ds = NULL;
	struct dataset_list *ds_list = NULL;
	struct statfs sfs;

	if (access(path, F_OK) == 0) {
		DBG_ERR("Path %s already exists.\n", path);
		errno = EEXIST;
		return -1;
	}

	SMB_ASSERT(smblibzfsp->sli);

	rv = existing_parent_name(path, parent, sizeof(parent), &to_create);
	if (rv != 0) {
		DBG_ERR("Unable to access parent of %s\n", path);
		errno = ENOENT;
		return -1;
	}

	rv = statfs(parent, &sfs);
	if (rv != 0) {
		DBG_ERR("%s: statfs() failed: %s\n", parent, strerror(errno));
		return -1;
	}

	/*
	 * If intermediate path component is a directory, then error out.
	 */
	if (strcmp(parent, sfs.f_mntonname) != 0) {
		DBG_ERR("%s: path component of auto-generated dataset is not "
			"a ZFS filesystem\n", parent);
		errno = EINVAL;
		return -1;
	}

	/*
	 * This zfs dataset handle allows us to figure out the
	 * name that our new dataset should have by looking at
	 * dataset properties of parent dataset.
	 */
	zfsp = zfs_path_to_zhandle(STOLZ(smblibzfsp), parent,
				   ZFS_TYPE_FILESYSTEM);
	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on %s: %s\n",
			parent, strerror(errno));
		return -1;
	}

	target_ds = get_target_name(mem_ctx, zfsp, path);
	if (target_ds == NULL) {
		zfs_close(zfsp);
		return -1;
	}
	zfs_close(zfsp);

	if (to_create > 1 && create_ancestors) {
		rv = zfs_create_ancestors(STOLZ(smblibzfsp), target_ds);
		if (rv != 0 ) {
			DBG_ERR("%s: zfs_create_ancestors() failed: %s\n",
				target_ds, STOERR(smblibzfsp));
			errno = libzfserr_to_errno(libzfs_errno(STOLZ(smblibzfsp)));
			TALLOC_FREE(target_ds);
			return -1;
		}
	}
	else if (to_create > 1) {
		DBG_ERR("Unable to create dataset [%s] due to "
			"missing ancestor datasets.", target_ds);
		errno = ENOENT;
		TALLOC_FREE(target_ds);
		return -1;
	}

	rv = create_dataset_internal(smblibzfsp, target_ds, quota);
	if (rv != 0) {
		TALLOC_FREE(target_ds);
		return -1;
	}

	TALLOC_FREE(target_ds);
	ds_list = path_to_dataset_list(mem_ctx, smblibzfsp, path, to_create);
	if (ds_list == NULL) {
		DBG_ERR("Failed to generate dataset list for %s\n",
			path);
		return -1;
	}
	*created = ds_list;
	return 0;
}

int
smb_zfs_get_user_prop(struct smblibzfshandle *smblibzfsp,
		      TALLOC_CTX *mem_ctx,
		      const char *path,
		      const char *prop,
		      char **value)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	nvlist_t *userprops = NULL;
	nvlist_t *propval = NULL;
	char *propstr = NULL;
	char *prefixed_prop = NULL;

	zfsp = get_zhandle(smblibzfsp, path, false);
	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n", path);
		return -1;
	}
	userprops = zfs_get_user_props(zfsp);
	prefixed_prop = talloc_asprintf(mem_ctx, "%s:%s",
					ZFS_PROP_SAMBA_PREFIX,
					prop);
	ret = nvlist_lookup_nvlist(userprops, prefixed_prop, &propval);
	if (ret != 0) {
		DBG_INFO("Failed to look up custom user property %s "
			 "on path [%s]: %s\n", prop, path, strerror(errno));
		zfs_close(zfsp);
		return -1;
	}
	ret = nvlist_lookup_string(propval, ZPROP_VALUE, &propstr);
	TALLOC_FREE(prefixed_prop);
	if (ret != 0) {
		DBG_ERR("Failed to get nvlist string for property %s\n",
			prop);
		zfs_close(zfsp);
		return -1;
	}
	*value = talloc_strdup(mem_ctx, propstr);
	zfs_close(zfsp);
	return 0;
}

int
smb_zfs_set_user_prop(struct smblibzfshandle *smblibzfsp,
		      const char *path,
		      const char *prop,
		      const char *value)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	char prefixed_prop[ZFS_MAXPROPLEN] = {0};

	zfsp = get_zhandle(smblibzfsp, path, false);

	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n", path);
		return -1;
	}

	ret = snprintf(prefixed_prop, sizeof(prefixed_prop), "%s:%s",
		       ZFS_PROP_SAMBA_PREFIX, prop);
	if (ret < 0) {
		DBG_ERR("Failed to generate property name: %s",
			strerror(errno));
		zfs_close(zfsp);
		return -1;
	}

	ret = zfs_prop_set(zfsp, prefixed_prop, value);
	if (ret != 0) {
		DBG_ERR("Failed to set property [%s] on path [%s] to [%s]\n",
			prefixed_prop, path, value);
	}

	zfs_close(zfsp);
	return ret;
}

static int
zhandle_get_props(struct smbzhandle *zfsp_ext,
		  TALLOC_CTX *mem_ctx,
		  struct zfs_dataset_prop **pprop)
{
	int casesens = 0;
	int ret;
	char buf[ZFS_MAXPROPLEN];
	char source[ZFS_MAX_DATASET_NAME_LEN];
	zprop_source_t sourcetype;
	zfs_handle_t *zfsp = NULL;
	struct zfs_dataset_prop *props = NULL;
	props = *pprop;

	zfsp = get_zhandle_from_smbzhandle(zfsp_ext);
	if (zfsp == NULL) {
		return -1;
	}
	if (zfs_prop_get(zfsp, ZFS_PROP_CASE,
	    buf, sizeof(buf), &sourcetype,
	    source, sizeof(source), B_FALSE) != 0) {
		DBG_ERR("Failed to look up casesensitivity property\n");
		return -1;
	}
	props->casesens = get_enum(buf, casesensitivity);
	props->readonly = zfs_prop_get_int(zfsp, ZFS_PROP_READONLY);
#if 0 /* properties we may wish to return in the future */
	props->exec = zfs_prop_get_int(zfsp, ZFS_PROP_EXEC);
	props->atime = zfs_prop_get_int(zfsp, ZFS_PROP_ATIME);
	props->setuid = zfs_prop_get_int(zfsp, ZFS_PROP_SETUID);
#endif
	return 0;
}

static char *resolve_legacy(TALLOC_CTX *mem_ctx, char *ds_name)
{
	struct statfs *statfsbuf = NULL;
	char *resolved = NULL;
	long size;
	int nstatfs, i;

	nstatfs = getfsstat(NULL, 0, MNT_WAIT);
	if (nstatfs == -1) {
		DBG_ERR("getfsstat() failed: %s\n", strerror(errno));
		return NULL;
	}
	size = nstatfs * sizeof(struct statfs);

	statfsbuf = talloc_array(mem_ctx, struct statfs, nstatfs);
	if (statfsbuf == NULL) {
		DBG_ERR("talloc_array() failed.\n");
		errno = ENOMEM;
		return NULL;
	}

	nstatfs = getfsstat(statfsbuf, size, MNT_WAIT);
	if (nstatfs == -1) {
		DBG_ERR("getfsstat() failed to retrieve [%ld] bytes: %s\n",
		size, strerror(errno));
		TALLOC_FREE(statfsbuf);
		return NULL;
	}

	for (i = 0; i < nstatfs; i++) {
		if ((strcmp(statfsbuf[i].f_mntfromname, ds_name) == 0) &&
		    (strchr(statfsbuf[i].f_mntfromname, '@') == NULL)) {
			resolved = talloc_strdup(mem_ctx,
						 statfsbuf[i].f_mntonname);
			if (resolved == NULL) {
				DBG_ERR("talloc() failed\n");
				errno = ENOMEM;
			}
			break;
		}
	}

	TALLOC_FREE(statfsbuf);
	return resolved;
}

struct zfs_dataset *zhandle_get_dataset(struct smbzhandle *zfsp_ext,
					TALLOC_CTX *mem_ctx,
					bool get_props)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	struct zfs_dataset *dsout = NULL;
	struct stat ds_st;

	zfsp = get_zhandle_from_smbzhandle(zfsp_ext);
	if (zfsp == NULL) {
		return NULL;
	}
	dsout = talloc_zero(mem_ctx, struct zfs_dataset);
	if (dsout == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	dsout->mountpoint = talloc_zero_size(dsout, PATH_MAX);
	if (dsout->mountpoint == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	dsout->zhandle = zfsp_ext;
	dsout->dataset_name = talloc_strdup(dsout, zfs_get_name(zfsp));
	ret = zfs_prop_get(zfsp, ZFS_PROP_MOUNTPOINT, dsout->mountpoint,
			   PATH_MAX, NULL, NULL, 0, 0);
	if (ret != 0) {
		DBG_ERR("Failed to get mountpoint for %s: %s\n",
			dsout->dataset_name, strerror(errno));
		goto fail;
	}
	if (strcmp(dsout->mountpoint, "legacy") == 0) {
		TALLOC_FREE(dsout->mountpoint);
		dsout->mountpoint = resolve_legacy(dsout, dsout->dataset_name);
		if (dsout->mountpoint == NULL) {
			DBG_ERR("Dataset [%s] is an unmounted legacy dataset",
				dsout->dataset_name);
			goto fail;
		}
	}
	if (get_props) {
		dsout->properties = talloc_zero(dsout, struct zfs_dataset_prop);
		if (dsout->properties == NULL) {
			errno = ENOMEM;
			goto fail;
		}
		ret = zhandle_get_props(zfsp_ext, mem_ctx, &dsout->properties);
		if (ret != 0) {
			DBG_ERR("Failed to get properties for dataset\n");
			goto fail;
		}
	}
	ret = stat(dsout->mountpoint, &ds_st);
	if (ret < 0) {
		DBG_ERR("Failed to stat dataset mounpoint [%s] "
			"for dataset [%s]: %s\n",
			dsout->mountpoint, dsout->dataset_name,
			strerror(errno));
		goto fail;
	}
	dsout->devid = ds_st.st_dev;
	return dsout;

fail:
	TALLOC_FREE(dsout);
	return NULL;
}

struct zfs_dataset *smb_zfs_path_get_dataset(struct smblibzfshandle *smblibzfsp,
					     TALLOC_CTX *mem_ctx,
					     const char *path,
					     bool get_props,
					     bool open_zhandle,
					     bool resolve_path)
{
	int ret;
	struct zfs_dataset *dsout = NULL;
	struct smbzhandle *zfs_ext = NULL;

	ret = get_smbzhandle(smblibzfsp, mem_ctx, path, &zfs_ext, resolve_path);
	if (ret != 0) {
		DBG_ERR("Failed to get zhandle\n");
		return NULL;
	}
	dsout = zhandle_get_dataset(zfs_ext, mem_ctx, get_props);
	if (dsout == NULL) {
		return dsout;
	}
	if (!open_zhandle) {
		close_smbzhandle(dsout->zhandle);
	}
	return dsout;
}

int
smb_zfs_get_case_sensitivity(struct smblibzfshandle *smblibzfsp, char* path)
{
	int casesens = 0;
	int rv;
	char buf[ZFS_MAXPROPLEN];
	char source[ZFS_MAX_DATASET_NAME_LEN];
	zprop_source_t sourcetype;
	zfs_handle_t *zfsp = NULL;

	zfsp = get_zhandle(smblibzfsp, path, false);
	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n", path);
		return (-1);
	}
	rv = zfs_prop_get(zfsp, ZFS_PROP_CASE, buf, sizeof(buf),
			  &sourcetype, source, sizeof(source), B_FALSE);
	if (rv != 0) {
		DBG_ERR("Failed to look up casesensitivity property "
			"on path: (%s): %s\n", path, strerror(errno));
		zfs_close(zfsp);
		return (-1);
	}
	casesens = get_enum(buf, casesensitivity);
	zfs_close(zfsp);
	return casesens;
}

static bool
shadow_copy_zfs_is_snapshot_included(struct iter_info *info,
    const char *snap_name)
{
	const char **pattern;

	pattern = info->inclusions;
	while (*pattern) {
		if (unix_wild_match(*pattern, snap_name)) {
			break;
		}
		pattern++;
	}

	if (*info->inclusions && !*pattern) {
		DBG_INFO("smb_zfs_add_snapshot: snapshot %s "
			    "not in inclusion list\n", snap_name);
		return false;
	}

	pattern = info->exclusions;
	while (*pattern) {
		if (unix_wild_match(*pattern, snap_name)) {
			DBG_INFO("smb_zfs_add_snapshot: snapshot %s "
				    "in exclusion list\n", snap_name);
			return false;
		}
		pattern++;
	}

	return true;
}

static int
smb_zfs_add_snapshot(zfs_handle_t *snap, void *data)
{
	struct snap_cb *state = NULL;
	struct snapshot_entry *entry = NULL;
	const char *snap_name;
	time_t cr_time;
	struct tm timestamp;
	int rc, used;
	size_t req_mem, name_len;
	bool included;

	state = talloc_get_type_abort(data, struct snap_cb);
	if (state == NULL) {
		DBG_ERR("failed to get snap_cb private data\n");
		zfs_close(snap);
		errno = ENOMEM;
		return -1;
	}

	/* ignore excluded snapshots */
	snap_name = strchr(zfs_get_name(snap), '@') + 1;

	included = shadow_copy_zfs_is_snapshot_included(state->iter_info,
							snap_name);
	if (!included) {
		zfs_close(snap);
		return 0;
	}

	used = zfs_prop_get_int(snap, ZFS_PROP_WRITTEN);
	if (used == 0) {
		goto done;
	}

	cr_time = zfs_prop_get_int(snap, ZFS_PROP_CREATION);

	if (state->iter_info->start && state->iter_info->start > cr_time) {
		zfs_close(snap);
		return 0;
	}
	if (state->iter_info->end && state->iter_info->end < cr_time) {
		zfs_close(snap);
		return 0;
	}

	entry = talloc_zero(state->snapshots, struct snapshot_entry);
	if (entry == NULL) {
		errno = ENOMEM;
		return -1;
	}

	name_len = strlen(snap_name);
	gmtime_r(&cr_time, &timestamp);
	strftime(entry->label, sizeof(entry->label), SHADOW_COPY_ZFS_GMT_FORMAT,
		 &timestamp);

	entry->cr_time = cr_time;
	unix_to_nt_time(&entry->nt_time, cr_time);
	entry->name = talloc_strndup(entry, snap_name, name_len +1);

	DLIST_ADD(state->snapshots->entries, entry);
	state->snapshots->num_entries++;
done:
	zfs_close(snap);
	return 0;
}

struct
snapshot_list *zhandle_list_snapshots(struct smbzhandle *zhandle_ext,
				      TALLOC_CTX *mem_ctx,
				      bool ignore_empty_snaps,
				      const char **inclusions,
				      const char **exclusions,
				      time_t start,
				      time_t end)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct snap_cb *state = NULL;
	struct snapshot_list *snapshots = NULL;
	struct iter_info iter_info;
	size_t initial_size;
	int rc;
	zfs_handle_t *zfs = NULL;

	zfs = get_zhandle_from_smbzhandle(zhandle_ext);
	if (!zfs) {
		return NULL;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		DBG_ERR("talloc() failed\n");
		return NULL;
	}

	state = talloc_zero(tmp_ctx, struct snap_cb);
	if (state == NULL) {
		DBG_ERR("smb_zfs_list_snapshots: out of memory");
		goto done;
	}

	snapshots = talloc_zero(mem_ctx, struct snapshot_list);
	if (snapshots == NULL) {
		DBG_ERR("talloc() failed\n");
		goto done;
	}

	snapshots->mountpoint = talloc_zero_size(snapshots, MAXPATHLEN);
	if (snapshots->mountpoint == NULL) {
		DBG_ERR("talloc() failed\n");
		goto error;
	}

	state->iter_info = talloc_zero(tmp_ctx, struct iter_info);
	if (state->iter_info == NULL) {
		DBG_ERR("talloc() failed\n");
		goto error;
	}

	state->snapshots = snapshots;

	/* get mountpoint */
	snapshots->dataset_name = talloc_strdup(snapshots, zfs_get_name(zfs));

	rc = zfs_prop_get(zfs, ZFS_PROP_MOUNTPOINT, snapshots->mountpoint,
			  talloc_get_size(snapshots->mountpoint), NULL, NULL,
			  0, 0);

	if (rc != 0) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"mountpoint for '%s': %s\n",
			snapshots->dataset_name,
			strerror(errno));
		goto error;
	}
	if (strcmp(snapshots->mountpoint, "legacy") == 0) {
		TALLOC_FREE(snapshots->mountpoint);
		snapshots->mountpoint = resolve_legacy(snapshots, snapshots->dataset_name);
		if (snapshots->mountpoint == NULL) {
			DBG_ERR("Failed to resolve mountpoint for dataset [%s] "
				"skipping creation of snapshot list.\n",
				snapshots->dataset_name);
			errno = ENOENT;
			goto error;
		}
	}

	state->iter_info->inclusions = inclusions;
	state->iter_info->exclusions = exclusions;
	state->iter_info->ignore_empty_snaps = ignore_empty_snaps;
	state->iter_info->start = start;
	state->iter_info->end = end;

	if (state->iter_info->inclusions == NULL) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"shadow:include parameter\n");
		goto error;
	}

	if (state->iter_info->exclusions == NULL) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"shadow:exclude parameter\n");
		goto error;
	}

	rc = zfs_iter_snapshots_sorted(zfs, smb_zfs_add_snapshot, state, 0, 0);
	if (rc != 0) {
		DBG_ERR("smb_zfs_list_snapshots: error getting "
			"snapshots for '%s': %s\n",
			snapshots->dataset_name, strerror(errno));
		goto error;
	}

	time(&snapshots->timestamp);
	state->snapshots = NULL;
	goto done;

error:
	TALLOC_FREE(tmp_ctx);
	TALLOC_FREE(snapshots);
	return NULL;
done:
	TALLOC_FREE(tmp_ctx);
	return snapshots;
}

struct
snapshot_list *smb_zfs_list_snapshots(struct smblibzfshandle *smblibzfsp,
				      TALLOC_CTX *mem_ctx,
				      const char *path,
				      bool ignore_empty_snaps,
				      const char **inclusions,
				      const char **exclusions,
				      time_t start,
				      time_t end)
{
	int ret;
	struct smbzhandle *zfs_ext = NULL;
	struct snapshot_list *out = NULL;
	ret = get_smbzhandle(smblibzfsp, mem_ctx, path, &zfs_ext, false);
	if (ret != 0) {
		DBG_ERR("Failed to get zhandle\n");
		return NULL;
	}
	out = zhandle_list_snapshots(zfs_ext, mem_ctx,
				     ignore_empty_snaps,
				     inclusions,
				     exclusions,
				     start,
				     end);
	close_smbzhandle(zfs_ext);
	return out;
}

/*
 * Convert linked list to nvlist and perform delete in single
 * consolidated ioctl.
 */
int
smb_zfs_delete_snapshots(struct smblibzfshandle *smblibzfsp,
			 TALLOC_CTX *mem_ctx,
			 struct snapshot_list *snaps)
{
	int ret;
	nvlist_t *to_delete = NULL;
	struct smblibzfs_int *slibzp_int = NULL;
	struct snapshot_entry *entry = NULL;
	char *snapname = NULL;
	if (smblibzfsp->sli == NULL) {
		errno=ENOMEM;
		DBG_ERR("Unable to re-use libzfs handle\n");
		return -1;
	}
	ret = nvlist_alloc(&to_delete, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		DBG_ERR("Failed to initialize nvlist for snaps.\n");
		errno=ENOMEM;
		return -1;
	}
	for (entry = snaps->entries; entry; entry = entry->next) {
		snapname = talloc_asprintf(mem_ctx,
					   "%s@%s",
					   snaps->dataset_name,
					   entry->name);
		DBG_INFO("deleting snapshot: %s\n", snapname);
		fnvlist_add_boolean(to_delete, snapname);
		TALLOC_FREE(snapname);
	}
	ret = zfs_destroy_snaps_nvl(smblibzfsp->sli->libzfsp,
				    to_delete,
				    B_TRUE);
	if (ret !=0) {
		DBG_ERR("Failed to delete snapshots\n");
		return ret;
	}
	return 0;
}

/*
 * Create snapshot with specified name on specified dataset.
 */
int
smb_zfs_snapshot(struct smblibzfshandle *smblibzfsp,
		 const char *path,
		 const char *snapshot_name,
		 bool recursive)
{
	int ret;
	zfs_handle_t *zfsp = NULL;
	char snap[ZFS_MAXPROPLEN] = {0};
	const char *dataset_name;

	if (smblibzfsp->sli == NULL) {
		errno=ENOMEM;
		return -1;
	}

	zfsp = get_zhandle(smblibzfsp, path, false);
	if (zfsp == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n",
			path);
		return -1;
	}
	dataset_name = zfs_get_name(zfsp);
	zfs_close(zfsp);
	ret = snprintf(snap, sizeof(snap), "%s@%s",
		       dataset_name, snapshot_name);
	if (ret < 0) {
		DBG_ERR("Failed to format snapshot name:%s\n",
			strerror(errno));
		return -1;
	}
	ret = zfs_snapshot(smblibzfsp->sli->libzfsp,
			   snap, recursive, NULL);
	if (ret != 0) {
		DBG_ERR("Failed to create snapshot %s: [%s]\n",
			snap, strerror(errno));
	}
	DBG_INFO("Successfully created snapshot: %s\n", snap);
	return ret;
}

/*
 * Roll back to specified snapshot
 */
int
smb_zfs_rollback(struct smblibzfshandle *smblibzfsp,
		 const char *path,
		 const char *snapshot_name,
		 bool force)
{
	int ret;
	zfs_handle_t *dataset_handle = NULL;
	zfs_handle_t *snap_handle = NULL;

	if (smblibzfsp->sli == NULL) {
		errno=ENOMEM;
		return -1;
	}

	dataset_handle = get_zhandle(smblibzfsp, path, false);
	if (dataset_handle == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n",
			path);
		return -1;
	}

	snap_handle = zfs_open(smblibzfsp->sli->libzfsp, snapshot_name,
			       ZFS_TYPE_DATASET);
	if (snap_handle == NULL) {
		DBG_ERR("Failed to obtain zhandle for snap: (%s)\n",
			snapshot_name);
		zfs_close(dataset_handle);
		return -1;
	}
	ret = zfs_rollback(dataset_handle, snap_handle, force);
	if (ret != 0) {
		DBG_ERR("Failed to roll back %s to snapshot %s\n",
			path, snapshot_name);
	}
	zfs_close(dataset_handle);
	zfs_close(snap_handle);
	return ret;
}

/*
 * Roll back to last snapshot
 */
int
smb_zfs_rollback_last(struct smblibzfshandle *smblibzfsp,
		      const char *path)
{
	int ret;
	zfs_handle_t *dataset_handle = NULL;
	const char *dataset_name;

	dataset_handle = get_zhandle(smblibzfsp, path, false);
	if (dataset_handle == NULL) {
		DBG_ERR("Failed to obtain zhandle on path: (%s)\n",
			path);
		return -1;
	}
	dataset_name = zfs_get_name(dataset_handle);

	ret = lzc_rollback(dataset_name, NULL, 0);
	if (ret != 0) {
		DBG_ERR("Failed to roll back snapshot on %s\n", path);
	}
	zfs_close(dataset_handle);
	return ret;
}

static int
smb_zfs_add_child(zfs_handle_t *child, void *data)
{
	int ret;
	struct child_cb *state = NULL;
	struct smbzhandle *zhandle_ext = NULL;
	struct smbzhandle_int *zhandle_int = NULL;
	struct zfs_dataset *ds_new = NULL;
	if (zfs_get_type(child) != ZFS_TYPE_FILESYSTEM) {
		return 0;
	}
	if (!zfs_is_mounted(child, NULL)) {
		DBG_INFO("Dataset [%s] is not mounted\n",
			 zfs_get_name(child));
		return 0;
	}
	state = talloc_get_type_abort(data, struct child_cb);
	if (state == NULL) {
		DBG_ERR("failed to get child_cb private data\n");
		zfs_close(child);
		errno = ENOMEM;
		return -1;
	}
	zhandle_ext = talloc_zero(state->dslist, struct smbzhandle);
	if (zhandle_ext == NULL) {
		errno = ENOMEM;
		return -1;
	}
	zhandle_int = talloc_zero(zhandle_ext, struct smbzhandle_int);
	if (zhandle_int == NULL) {
		errno = ENOMEM;
		return -1;
	}
	zhandle_ext->zhp = zhandle_int;
	zhandle_ext->is_open = true;
	zhandle_int->zhandle = child;
	ds_new = zhandle_get_dataset(zhandle_ext, state->dslist, true);
	if (ds_new == NULL) {
		close_smbzhandle(zhandle_ext);
		TALLOC_FREE(zhandle_ext);
		return 0;
	}
	DLIST_ADD(state->dslist->children, ds_new);
	state->dslist->nentries++;
	if (!state->open_zhandle) {
		close_smbzhandle(ds_new->zhandle);
	}
	return 0;
}

struct dataset_list *zhandle_list_children(TALLOC_CTX *mem_ctx,
					  struct smbzhandle *zhandle_ext,
					  bool open_zhandles)
{
	int ret ;
	TALLOC_CTX *tmp_ctx = NULL;
	struct dataset_list *dl = NULL;
	char *ds_name = NULL;
	struct child_cb *state = NULL;
	struct zfs_dataset *ds = NULL;
	zfs_handle_t *zfsp = NULL;

	zfsp = get_zhandle_from_smbzhandle(zhandle_ext);
	if (zfsp == NULL) {
		return NULL;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		DBG_ERR("talloc() failed\n");
		errno = ENOMEM;
		return NULL;
	}

	state = talloc_zero(tmp_ctx, struct child_cb);
	if (state == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	state->open_zhandle = open_zhandles;
	dl = talloc_zero(mem_ctx, struct dataset_list);
	if (dl == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	state->dslist = dl;
	dl->root = zhandle_get_dataset(zhandle_ext, mem_ctx, true);
	if (dl->root == NULL) {
		DBG_ERR("Failed to get dataset information for root "
			"of dataset list\n");
		TALLOC_FREE(tmp_ctx);
		TALLOC_FREE(dl);
		return NULL;
	}
	ret = zfs_iter_filesystems(zfsp, smb_zfs_add_child, state);
	if (ret < 0) {
		TALLOC_FREE(dl);
		return NULL;
	}
	TALLOC_FREE(tmp_ctx);
	return dl;
}

static struct dataset_list *share_lookup_dataset_list(const char *connectpath)
{
	struct dataset_list *out = NULL;
	struct share_dataset_list *to_check = NULL;
	if (shareds == NULL) {
		return out;
	}
	for (to_check=shareds; to_check; to_check = to_check->next) {
		if (strcmp(connectpath, to_check->connectpath) == 0) {
			out = to_check->dl;
			break;
		}
	}
	return out;
}

static int put_share_dataset_list(TALLOC_CTX *mem_ctx, const char *connectpath,
				  struct dataset_list *dl)
{
	struct share_dataset_list *new_shareds= NULL;
	new_shareds = talloc_zero(mem_ctx, struct share_dataset_list);
	if (new_shareds == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_shareds->dl = dl;
	new_shareds->connectpath = talloc_strdup(mem_ctx, connectpath);
	if (new_shareds->connectpath == NULL) {
		errno = ENOMEM;
		return -1;
	}
	if (shareds == NULL) {
		shareds = new_shareds;
		return 0;
	}
	DLIST_ADD(shareds, new_shareds);
	return 0;
}

int conn_zfs_init(TALLOC_CTX *mem_ctx,
		  const char *connectpath,
		  struct smblibzfshandle **plibzp,
		  struct dataset_list **pdsl)
{
	static struct smblibzfshandle *gl = NULL;
	int ret = 0;
	struct smbzhandle *conn_zfsp = NULL;
	char *tmp_name = NULL;
	size_t to_remove, new_len;
	struct dataset_list *dl = NULL;

	if (!gl) {
		ret = get_smblibzfs_handle(mem_ctx, &gl);
                if (ret != 0) {
                        return -1;
                }
	}

	dl = share_lookup_dataset_list(connectpath);
	if (dl != NULL) {
		*plibzp = gl;
		*pdsl = dl;
		return 0;
	}

	get_smbzhandle(gl, mem_ctx, connectpath, &conn_zfsp, true);
	/*
	 * Attempt to get zfs dataset handle will fail if the dataset is a
	 * snapshot. This may occur if the share is one dynamically created
	 * by FSRVP when it exposes a snapshot.
	 */
	if ((conn_zfsp == NULL) && (strlen(connectpath) > 15)) {
		DBG_ERR("Failed to obtain zhandle on connectpath: %s\n",
			strerror(errno));
		tmp_name = strnstr(connectpath, "/.zfs/snapshot/", PATH_MAX);
		if (tmp_name != NULL) {
			DBG_INFO("Connectpath is zfs snapshot. Opening zhandle "
				 "on parent dataset.\n");
			to_remove = strlen(tmp_name);
			new_len = strlen(connectpath) - to_remove;
			tmp_name = talloc_strndup(mem_ctx,
						  connectpath,
						  new_len);
			get_smbzhandle(gl,
				       mem_ctx, tmp_name,
				       &conn_zfsp, false);
			TALLOC_FREE(tmp_name);
		}
	}
	*plibzp = gl;
	if (conn_zfsp == NULL) {
		/*
		 * The filesystem is most likely not ZFS. Jailed processes
		 * on FreeBSD may not be able to obtain ZFS dataset handles.
		 */
		*pdsl = NULL;
		return 0;
	}

	dl = zhandle_list_children(mem_ctx, conn_zfsp, false);
	if (dl == NULL) {
		return 0;
	}
	ret = put_share_dataset_list(mem_ctx, connectpath, dl);
	if (ret != 0) {
		DBG_ERR("Failed to store share dataset list\n");
	}

	*pdsl = dl;
	return 0;
}
