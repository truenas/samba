/*
 *  Unix SMB/CIFS implementation.
 *  Cache of file metadata derived from ZFS, keyed by change cookie
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Per-process cache of what smbd derives from ZFS metadata. A flat table
 * holds a small slot per file, keyed by its file_id: the change cookie,
 * dosmode, DOSATTRIB create time and security descriptor variant. The
 * file_id includes the inode generation, so a reused inode number gets a
 * new slot, and ZFS bumps the cookie on every change, so a slot is only
 * used while the cookie it was filled under is current.
 *
 * Security descriptors and maximum access are shared between files: a
 * converted SD is a function of the raw NFSv4 ACL, owner, group and mode,
 * so those are the key of a variant, and files in a large folder usually
 * share a handful of them. Shared entries are only stored after checking
 * that the file did not change while they were computed.
 *
 * Both are freed once the process goes MDCACHE_IDLE_TIMEOUT seconds
 * without using them.
 *
 * Finding a file's slot takes a statx of its fd, unless one was taken in
 * the current epoch. The epoch ends whenever smbd wakes up from waiting,
 * with each request and with each change smbd makes, so a change made
 * elsewhere goes unseen at most until smbd next waits.
 */

#include "includes.h"
#include "system/shmem.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbd/truenas_mdcache.h"
#include "lib/util/memcache.h"
#include "libcli/security/security.h"

#define MDCACHE_MIN_INODES	1024
#define MDCACHE_MAX_INODES	(256 * 1024)
#define MDCACHE_PROBES		16
#define MDCACHE_SIZE		(4 * 1024 * 1024)
#define MDCACHE_IDLE_TIMEOUT	300

static struct {
	struct mdcache_inode *slots;
	uint32_t mask;
	uint32_t count;
	uint32_t tick;
	uint64_t seq;
	struct memcache *mc;
	struct tevent_timer *idle_timer;
	uint32_t idle_tick;
	uint32_t idle_timeout;
} mdc = {
	.idle_timeout = MDCACHE_IDLE_TIMEOUT,
};

static uint32_t mdcache_home(const struct file_id *id)
{
	return (uint32_t)(((id->inode ^ (id->devid << 40)) *
			   0x9e3779b97f4a7c15ULL) >> 32);
}

/*
 * Slots are never freed, so a key is never stored past an empty slot of
 * its probe window. If the window is full, *pfree is its least recently
 * used slot.
 */
static struct mdcache_inode *mdcache_find(const struct file_id *id,
					  struct mdcache_inode **pfree)
{
	struct mdcache_inode *victim = NULL;
	uint32_t home, i;

	*pfree = NULL;
	if (mdc.slots == NULL) {
		return NULL;
	}

	home = mdcache_home(id);
	for (i = 0; i < MDCACHE_PROBES; i++) {
		struct mdcache_inode *s = &mdc.slots[(home + i) & mdc.mask];

		if (s->cookie == 0) {
			*pfree = s;
			return NULL;
		}
		if (file_id_equal(&s->id, id)) {
			return s;
		}
		if ((victim == NULL) || ((int32_t)(s->tick - victim->tick) < 0)) {
			victim = s;
		}
	}
	*pfree = victim;
	return NULL;
}

static bool mdcache_grow(void)
{
	struct mdcache_inode *old = mdc.slots;
	uint32_t old_size = (old == NULL) ? 0 : mdc.mask + 1;
	uint32_t size = (old == NULL) ? MDCACHE_MIN_INODES : old_size * 2;
	struct mdcache_inode *slots = NULL;
	uint32_t i;

	if (size > MDCACHE_MAX_INODES) {
		return false;
	}

	/* mmap, so freeing the table always gives it back to the kernel */
	slots = mmap(NULL, size * sizeof(struct mdcache_inode),
		     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (slots == MAP_FAILED) {
		return false;
	}

	mdc.slots = slots;
	mdc.mask = size - 1;
	mdc.count = 0;

	for (i = 0; i < old_size; i++) {
		struct mdcache_inode *s = NULL;

		if (old[i].cookie == 0) {
			continue;
		}
		if ((mdcache_find(&old[i].id, &s) == NULL) &&
		    (s != NULL) && (s->cookie == 0)) {
			*s = old[i];
			mdc.count++;
		}
	}
	if (old != NULL) {
		munmap(old, old_size * sizeof(struct mdcache_inode));
	}
	return true;
}

static struct mdcache_inode *mdcache_insert(const struct file_id *id)
{
	struct mdcache_inode *s = NULL;
	struct mdcache_inode *slot = NULL;

	for (;;) {
		s = mdcache_find(id, &slot);
		if (s != NULL) {
			return s;
		}
		if ((slot != NULL) && (slot->cookie == 0) &&
		    ((mdc.count + 1) * 8 <= (mdc.mask + 1) * 7)) {
			mdc.count++;
			break;
		}
		if (mdcache_grow()) {
			continue;
		}
		if (slot == NULL) {
			return NULL;
		}
		if (slot->cookie == 0) {
			mdc.count++;
		}
		break;
	}

	*slot = (struct mdcache_inode) {
		.id = *id,
	};
	return slot;
}

static void mdcache_idle(struct tevent_context *ev,
			 struct tevent_timer *te,
			 struct timeval now,
			 void *private_data);

static void mdcache_idle_arm(struct tevent_context *ev)
{
	mdc.idle_tick = mdc.tick;
	mdc.idle_timer = tevent_add_timer(
		ev, NULL, timeval_current_ofs(mdc.idle_timeout, 0),
		mdcache_idle, NULL);
}

/*
 * Free everything if the cache wasn't used since the last check. seq
 * keeps counting, so a variant number held across this is never given
 * to a different ACL.
 */
static void mdcache_idle(struct tevent_context *ev,
			 struct tevent_timer *te,
			 struct timeval now,
			 void *private_data)
{
	mdc.idle_timer = NULL;
	if (mdc.tick != mdc.idle_tick) {
		mdcache_idle_arm(ev);
		return;
	}

	if (mdc.slots != NULL) {
		munmap(mdc.slots,
		       (size_t)(mdc.mask + 1) * sizeof(struct mdcache_inode));
	}
	mdc.slots = NULL;
	mdc.mask = 0;
	mdc.count = 0;
	TALLOC_FREE(mdc.mc);
}

void mdcache_bump_epoch(struct smbd_server_connection *sconn)
{
	if (sconn != NULL) {
		sconn->mdcache_epoch++;
	}
}

/*
 * Moves with every SMB request (num_requests) and with every wake-up and
 * change of our own (mdcache_epoch). 0 is never current.
 */
static uint64_t mdcache_epoch(const struct files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;

	if (sconn == NULL) {
		return 0;
	}
	return sconn->num_requests + sconn->mdcache_epoch;
}

#ifdef STATX_CHANGE_COOKIE
static void mdcache_set_stat(struct files_struct *fsp, const struct statx *stx)
{
	fsp->mdcache_stat = (struct mdcache_stat) {
		.epoch = mdcache_epoch(fsp),
		.cookie = stx->stx_change_cookie,
		.gen = stx->stx_gen,
		.dev = makedev(stx->stx_dev_major, stx->stx_dev_minor),
		.ino = stx->stx_ino,
		.uid = stx->stx_uid,
		.gid = stx->stx_gid,
		.mode = stx->stx_mode,
	};
}
#endif

/* sbuf is a stat of fsp's fd */
void mdcache_stat_taken(struct files_struct *fsp, const SMB_STRUCT_STAT *sbuf)
{
#ifdef STATX_CHANGE_COOKIE
	struct statx stx = {
		.stx_change_cookie = sbuf->st_ex_change_cookie,
		.stx_gen = sbuf->st_ex_gen,
		.stx_dev_major = major(sbuf->st_ex_dev),
		.stx_dev_minor = minor(sbuf->st_ex_dev),
		.stx_ino = sbuf->st_ex_ino,
		.stx_uid = sbuf->st_ex_uid,
		.stx_gid = sbuf->st_ex_gid,
		.stx_mode = sbuf->st_ex_mode,
	};

	mdcache_set_stat(fsp, &stx);
#endif
}

/*
 * Return the slot for the current version of fsp's file, emptied if the
 * file changed since it was filled, or NULL if it can't be cached. Values
 * derived for the slot use the owner, group and mode in fsp's stat, so
 * the cache is skipped when those are out of date.
 */
struct mdcache_inode *mdcache_inode_fetch(struct files_struct *fsp)
{
#ifdef STATX_CHANGE_COOKIE
	const SMB_STRUCT_STAT *st = &fsp->fsp_name->st;
	const struct mdcache_stat *m = &fsp->mdcache_stat;
	uint64_t epoch = mdcache_epoch(fsp);
	struct mdcache_inode *s = NULL;

	if (fsp_is_alternate_stream(fsp)) {
		return NULL;
	}

	if ((epoch == 0) || (m->epoch != epoch)) {
		struct statx stx;

		if (statx(fsp_get_pathref_fd(fsp), "", AT_EMPTY_PATH,
			  STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID |
			  STATX_INO | STATX_CHANGE_COOKIE | STATX_GEN,
			  &stx) != 0) {
			return NULL;
		}
		mdcache_set_stat(fsp, &stx);
	}

	if ((m->cookie == 0) ||
	    (m->uid != st->st_ex_uid) ||
	    (m->gid != st->st_ex_gid) ||
	    (m->mode != st->st_ex_mode)) {
		// a zero cookie is the .zfs control directory
		return NULL;
	}

	if (m->gen == 0) {
		static bool logged;

		if (!logged) {
			DBG_ERR("%s: no inode generation, not caching "
				"metadata\n", fsp_str_dbg(fsp));
			logged = true;
		}
		return NULL;
	}

	/* The slot is keyed by fsp->file_id, so it must be this fd's file */
	if ((m->dev != fsp->file_id.devid) ||
	    (m->ino != fsp->file_id.inode) ||
	    (m->gen != fsp->file_id.extid)) {
		return NULL;
	}

	s = mdcache_insert(&fsp->file_id);
	if (s == NULL) {
		return NULL;
	}
	if (mdc.idle_timer == NULL) {
		mdcache_idle_arm(fsp->conn->sconn->ev_ctx);
	}

	if (s->cookie != m->cookie) {
		*s = (struct mdcache_inode) {
			.id = s->id,
			.cookie = m->cookie,
			.btime_nsec = UTIME_OMIT,
		};
	}
	s->tick = ++mdc.tick;
	return s;
#else
	return NULL;
#endif
}

struct mdcache_inode *mdcache_inode_peek(const struct file_id *id,
					 uint64_t cookie)
{
	struct mdcache_inode *s = NULL;
	struct mdcache_inode *unused = NULL;

	s = mdcache_find(id, &unused);
	if ((s == NULL) || (s->cookie != cookie)) {
		return NULL;
	}
	return s;
}

bool mdcache_inode_unchanged(struct files_struct *fsp, uint64_t cookie)
{
#ifdef STATX_CHANGE_COOKIE
	struct statx stx;

	if (statx(fsp_get_pathref_fd(fsp), "", AT_EMPTY_PATH,
		  STATX_CHANGE_COOKIE, &stx) != 0) {
		return false;
	}
	return stx.stx_change_cookie == cookie;
#else
	return false;
#endif
}

static struct memcache *mdcache_mc(void)
{
	if (mdc.mc == NULL) {
		mdc.mc = memcache_init(NULL, MDCACHE_SIZE);
	}
	return mdc.mc;
}

/* Variant number for a raw ACL, owner, group and mode */
uint64_t mdcache_sd_variant(DATA_BLOB content)
{
	struct memcache *mc = mdcache_mc();
	DATA_BLOB val;
	uint64_t seq;

	if (mc == NULL) {
		return 0;
	}

	if (memcache_lookup(mc, MDCACHE_SD_VARIANT, content, &val) &&
	    (val.length == sizeof(seq))) {
		memcpy(&seq, val.data, sizeof(seq));
		return seq;
	}

	seq = ++mdc.seq;
	memcache_add(mc, MDCACHE_SD_VARIANT, content,
		     data_blob_const(&seq, sizeof(seq)));
	return seq;
}

struct mdcache_sd_key {
	uint64_t seq;
	uint32_t security_info;
	uint32_t pad;
};

bool mdcache_sd_get(uint64_t seq, uint32_t security_info,
		    TALLOC_CTX *mem_ctx, struct security_descriptor **ppdesc)
{
	struct mdcache_sd_key key = {
		.seq = seq,
		.security_info = security_info,
	};
	DATA_BLOB val;
	NTSTATUS status;

	if ((mdc.mc == NULL) ||
	    !memcache_lookup(mdc.mc, MDCACHE_SD,
			     data_blob_const(&key, sizeof(key)), &val)) {
		return false;
	}

	status = unmarshall_sec_desc(mem_ctx, val.data, val.length, ppdesc);
	return NT_STATUS_IS_OK(status);
}

void mdcache_sd_put(uint64_t seq, uint32_t security_info,
		    const struct security_descriptor *psd)
{
	struct mdcache_sd_key key = {
		.seq = seq,
		.security_info = security_info,
	};
	uint8_t *data = NULL;
	size_t len;
	NTSTATUS status;

	if (mdcache_mc() == NULL) {
		return;
	}

	status = marshall_sec_desc(talloc_tos(), psd, &data, &len);
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	memcache_add(mdc.mc, MDCACHE_SD, data_blob_const(&key, sizeof(key)),
		     data_blob_const(data, len));
	TALLOC_FREE(data);
}

bool mdcache_access_get(const struct mdcache_access_key *key,
			uint32_t *access_mask)
{
	DATA_BLOB val;

	if ((mdc.mc == NULL) ||
	    !memcache_lookup(mdc.mc, MDCACHE_ACCESS,
			     data_blob_const(key, sizeof(*key)), &val) ||
	    (val.length != sizeof(*access_mask))) {
		return false;
	}

	memcpy(access_mask, val.data, sizeof(*access_mask));
	return true;
}

void mdcache_access_put(const struct mdcache_access_key *key,
			uint32_t access_mask)
{
	if (mdcache_mc() == NULL) {
		return;
	}

	memcache_add(mdc.mc, MDCACHE_ACCESS, data_blob_const(key, sizeof(*key)),
		     data_blob_const(&access_mask, sizeof(access_mask)));
}

/* Maximum access depends on share settings such as "read only" */
void mdcache_flush_access(void)
{
	if (mdc.mc != NULL) {
		memcache_flush(mdc.mc, MDCACHE_ACCESS);
	}
}

/*
 * FSCTL_SMBTORTURE_MDCACHE: set the idle timeout unless it is 0, and
 * report the table size and the number of slots in use
 */
void mdcache_smbtorture(struct files_struct *fsp, uint32_t idle_timeout,
			uint32_t *slots, uint32_t *count)
{
	if (idle_timeout != 0) {
		mdc.idle_timeout = idle_timeout;
		if (mdc.idle_timer != NULL) {
			TALLOC_FREE(mdc.idle_timer);
			mdcache_idle_arm(fsp->conn->sconn->ev_ctx);
		}
	}
	*slots = (mdc.slots == NULL) ? 0 : mdc.mask + 1;
	*count = mdc.count;
}
