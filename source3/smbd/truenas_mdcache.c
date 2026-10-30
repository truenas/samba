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
 * DOSATTRIB create time and security descriptor variant. The
 * file_id includes the inode generation, so a reused inode number gets a
 * new slot, and ZFS bumps the cookie on every change, so a slot is only
 * used while the cookie it was filled under is current.
 *
 * Security descriptors and maximum access are shared between files: a
 * converted SD is a function of the raw NFSv4 ACL, owner, group and mode,
 * so those are the key of a variant, and files in a large folder usually
 * share a handful of them. Shared entries are only stored after checking
 * that the file did not change while they were computed. TrueNAS ABE's
 * answer for a file, taken from the open a listing did, stays in its slot.
 *
 * Both are freed once the process goes MDCACHE_IDLE_TIMEOUT seconds
 * without using them.
 *
 * A file's slot is found from the stat in fsp->fsp_name, taken again
 * unless it came from the fd in the current epoch. The epoch ends whenever
 * smbd wakes up from waiting, with each request and with each change smbd
 * makes, so a change made elsewhere goes unseen at most until smbd next
 * waits.
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
	uint64_t last_variant;
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

/*
 * ABE's answer for a file is kept in its slot under a number standing
 * for the session, share and user. A number is not reused while slots
 * may hold it: a token change drops the contexts, the numbering goes on.
 */
struct mdcache_abe_ctx {
	uint64_t vuid;
	uint32_t cnum;
	uint32_t uid;
	uint32_t num;
};

static struct {
	struct mdcache_abe_ctx *ctxs;
	uint32_t count;
	uint32_t next;		/* number for the next context */
} abe;

#define MDCACHE_ABE_BITS	(MDCACHE_ABE_VISIBLE | \
				 (UINT32_MAX << MDCACHE_ABE_CTX_SHIFT))

static void mdcache_abe_drop_ctxs(void)
{
	TALLOC_FREE(abe.ctxs);
	abe.count = 0;
}

static void mdcache_abe_forget(void)
{
	uint32_t i;

	if (mdc.slots == NULL) {
		return;
	}
	for (i = 0; i <= mdc.mask; i++) {
		mdc.slots[i].flags &= ~MDCACHE_ABE_BITS;
	}
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
 * Free everything if the cache wasn't used since the last check.
 * last_variant keeps counting, so a variant number held across this is
 * never given to a different ACL.
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
	mdcache_abe_drop_ctxs();
	abe.next = 0;
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
uint64_t mdcache_epoch(const struct connection_struct *conn)
{
	struct smbd_server_connection *sconn = conn->sconn;

	if (sconn == NULL) {
		return 0;
	}
	return sconn->num_requests + sconn->mdcache_epoch;
}

/*
 * Return the slot for the current version of fsp's file, emptied if the
 * file changed since it was filled, or NULL if it can't be cached.
 */
struct mdcache_inode *mdcache_inode_fetch(struct files_struct *fsp)
{
	const SMB_STRUCT_STAT *st = &fsp->fsp_name->st;
	uint64_t epoch = mdcache_epoch(fsp->conn);
	struct mdcache_inode *s = NULL;

	if (fsp_is_alternate_stream(fsp) || (fsp_get_pathref_fd(fsp) == -1)) {
		return NULL;
	}

	if ((epoch == 0) || (st->st_ex_epoch != epoch)) {
		NTSTATUS status = vfs_stat_fsp(fsp);

		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}
	}

	if (st->st_ex_change_cookie == 0) {
		// a zero cookie is the .zfs control directory
		return NULL;
	}

	if (st->st_ex_gen == 0) {
		static bool logged;

		if (!logged) {
			DBG_ERR("%s: no inode generation, not caching "
				"metadata\n", fsp_str_dbg(fsp));
			logged = true;
		}
		return NULL;
	}

	/* The slot is keyed by fsp->file_id, so it must be this fd's file */
	if ((st->st_ex_dev != fsp->file_id.devid) ||
	    (st->st_ex_ino != fsp->file_id.inode) ||
	    (st->st_ex_gen != fsp->file_id.extid)) {
		return NULL;
	}

	s = mdcache_insert(&fsp->file_id);
	if (s == NULL) {
		return NULL;
	}
	if (mdc.idle_timer == NULL) {
		mdcache_idle_arm(fsp->conn->sconn->ev_ctx);
	}

	if (s->cookie != st->st_ex_change_cookie) {
		*s = (struct mdcache_inode) {
			.id = s->id,
			.cookie = st->st_ex_change_cookie,
			.btime_nsec = UTIME_OMIT,
		};
	}
	s->tick = ++mdc.tick;
	return s;
}

void mdcache_inode_prefetch(const struct file_id *id)
{
	if (mdc.slots != NULL) {
		__builtin_prefetch(&mdc.slots[mdcache_home(id) & mdc.mask]);
	}
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
	s->tick = ++mdc.tick;
	return s;
}

static bool mdcache_inode_unchanged(struct files_struct *fsp, uint64_t cookie)
{
	NTSTATUS status;

	if (fsp_get_pathref_fd(fsp) == -1) {
		return false;
	}
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	return fsp->fsp_name->st.st_ex_change_cookie == cookie;
}

static struct memcache *mdcache_mc(void)
{
	if (mdc.mc == NULL) {
		mdc.mc = memcache_init(NULL, MDCACHE_SIZE);
	}
	return mdc.mc;
}

/* Variant number for a raw ACL, owner, group and mode */
static uint64_t mdcache_sd_variant(DATA_BLOB content)
{
	struct memcache *mc = mdcache_mc();
	DATA_BLOB val;
	uint64_t variant;

	if (mc == NULL) {
		return 0;
	}

	if (memcache_lookup(mc, MDCACHE_SD_VARIANT, content, &val) &&
	    (val.length == sizeof(variant))) {
		memcpy(&variant, val.data, sizeof(variant));
		return variant;
	}

	variant = ++mdc.last_variant;
	memcache_add(mc, MDCACHE_SD_VARIANT, content,
		     data_blob_const(&variant, sizeof(variant)));
	return variant;
}

#define ACL4_XDR_MAX 20488	/* what libzfsacl reads, 1024 entries */
#define ACL4_XDR_SMALL 1008	/* 50 entries */

/* The variant of a file's SD: its raw NFSv4 ACL, owner, group and mode */
static uint64_t mdcache_sd_variant_fsp(struct files_struct *fsp)
{
	const SMB_STRUCT_STAT *st = &fsp->fsp_name->st;
	struct {
		uint32_t uid;
		uint32_t gid;
		uint32_t mode;
		uint32_t pad;
	} hdr = {
		.uid = st->st_ex_uid,
		.gid = st->st_ex_gid,
		.mode = st->st_ex_mode,
	};
	uint8_t small[sizeof(hdr) + ACL4_XDR_SMALL];
	uint8_t *buf = small;
	ssize_t len;
	uint64_t variant = 0;

	/* vfs_ixnas makes the SD of a trivial ACL from the mode */
	if (ST_EX_ACL_FROM_MODE(st)) {
		return mdcache_sd_variant(data_blob_const(&hdr, sizeof(hdr)));
	}
	if ((st->st_ex_flags & ST_EX_ATTR_ACLTYPE) &&
	    !(st->st_ex_flags & ST_EX_ATTR_NFSV4ACL)) {
		return 0;
	}

	/*
	 * Linux allocates and zeroes a buffer of the requested size on
	 * every getxattr, so try a typical ACL size first. Larger ACLs are
	 * rare and get read twice.
	 */
	len = SMB_VFS_FGETXATTR(fsp, ACL4_XATTR, buf + sizeof(hdr),
				ACL4_XDR_SMALL);
	if ((len == -1) && (errno == ERANGE)) {
		buf = talloc_array(talloc_tos(), uint8_t,
				   sizeof(hdr) + ACL4_XDR_MAX);
		if (buf == NULL) {
			return 0;
		}
		len = SMB_VFS_FGETXATTR(fsp, ACL4_XATTR, buf + sizeof(hdr),
					ACL4_XDR_MAX);
	}
	if (len > 0) {
		memcpy(buf, &hdr, sizeof(hdr));
		variant = mdcache_sd_variant(
			data_blob_const(buf, sizeof(hdr) + len));
	}
	if (buf != small) {
		TALLOC_FREE(buf);
	}
	return variant;
}

/* The SD variant of fsp's file, 0 if none, and its change cookie */
uint64_t mdcache_fsp_variant(struct files_struct *fsp, uint64_t *pcookie)
{
	struct mdcache_inode *slot = NULL;
	uint64_t variant;

	*pcookie = 0;
	if (!(fsp->conn->internal_tcon_flags & TCON_FLAG_MDCACHE_SD)) {
		return 0;
	}
	slot = mdcache_inode_fetch(fsp);
	if (slot == NULL) {
		return 0;
	}
	*pcookie = slot->cookie;
	if (slot->sd_variant != 0) {
		return slot->sd_variant;
	}

	/* Reading the ACL can move the slot */
	variant = mdcache_sd_variant_fsp(fsp);
	slot = mdcache_inode_peek(&fsp->file_id, *pcookie);
	if (slot != NULL) {
		slot->sd_variant = variant;
	}
	return variant;
}

struct mdcache_sd_key {
	uint64_t variant;
	uint32_t security_info;
	uint32_t pad;
};

bool mdcache_sd_get(uint64_t variant, uint32_t security_info,
		    TALLOC_CTX *mem_ctx, struct security_descriptor **ppdesc)
{
	struct mdcache_sd_key key = {
		.variant = variant,
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

/* Cache psd for the SD variant, unless fsp's file changed since cookie */
void mdcache_sd_put(struct files_struct *fsp,
		    uint64_t cookie,
		    uint64_t variant,
		    uint32_t security_info,
		    const struct security_descriptor *psd)
{
	struct mdcache_sd_key key = {
		.variant = variant,
		.security_info = security_info,
	};
	uint8_t *data = NULL;
	size_t len;
	NTSTATUS status;

	if ((mdcache_mc() == NULL) || !mdcache_inode_unchanged(fsp, cookie)) {
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

bool mdcache_access_key(struct connection_struct *conn,
			uint64_t sd_variant,
			uint32_t access_mask,
			uint32_t flags,
			struct mdcache_access_key *key)
{
	if (sd_variant == 0) {
		return false;
	}
	*key = (struct mdcache_access_key) {
		.sd_variant = sd_variant,
		.vuid = get_current_vuid(conn),
		.cnum = conn->cnum,
		.uid = get_current_uid(conn),
		.access_mask = access_mask,
		.flags = flags,
	};
	return true;
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

static void mdcache_access_store(const struct mdcache_access_key *key,
				 uint32_t access_mask)
{
	if (mdcache_mc() == NULL) {
		return;
	}

	memcache_add(mdc.mc, MDCACHE_ACCESS, data_blob_const(key, sizeof(*key)),
		     data_blob_const(&access_mask, sizeof(access_mask)));
}

/* Cache an access decision, unless fsp's file changed since cookie */
void mdcache_access_put(struct files_struct *fsp,
			uint64_t cookie,
			const struct mdcache_access_key *key,
			uint32_t access_mask)
{
	if (mdcache_inode_unchanged(fsp, cookie)) {
		mdcache_access_store(key, access_mask);
	}
}

/* Maximum access and ABE answers depend on share settings and the token */
void mdcache_flush_access(void)
{
	if (mdc.mc != NULL) {
		memcache_flush(mdc.mc, MDCACHE_ACCESS);
	}
	mdcache_abe_drop_ctxs();
}

static uint32_t mdcache_abe_ctx(struct connection_struct *conn)
{
	uint64_t vuid = get_current_vuid(conn);
	uint32_t uid = get_current_uid(conn);
	struct mdcache_abe_ctx *c = NULL;
	uint32_t i;

	for (i = 0; i < abe.count; i++) {
		c = &abe.ctxs[i];
		if ((c->vuid == vuid) && (c->cnum == conn->cnum) &&
		    (c->uid == uid)) {
			return c->num;
		}
	}

	if ((abe.next == 0) || (abe.next > UINT16_MAX)) {
		/* wrapped: no slot may keep an old number */
		mdcache_abe_forget();
		abe.next = 1;
	}

	c = talloc_realloc(NULL, abe.ctxs, struct mdcache_abe_ctx,
			   abe.count + 1);
	if (c == NULL) {
		return 0;
	}
	abe.ctxs = c;
	c = &abe.ctxs[abe.count++];
	*c = (struct mdcache_abe_ctx) {
		.vuid = vuid,
		.cnum = conn->cnum,
		.uid = uid,
		.num = abe.next++,
	};
	return c->num;
}

bool mdcache_abe_get(struct connection_struct *conn,
		     const struct mdcache_inode *slot,
		     bool *visible)
{
	uint32_t ctx = mdcache_abe_ctx(conn);
	struct mdcache_access_key key;
	uint32_t read_access;

	if ((ctx != 0) && ((slot->flags >> MDCACHE_ABE_CTX_SHIFT) == ctx)) {
		*visible = (slot->flags & MDCACHE_ABE_VISIBLE) != 0;
		return true;
	}
	if (!mdcache_access_key(conn, slot->sd_variant, 0,
				MDCACHE_ACCESS_ABE, &key) ||
	    !mdcache_access_get(&key, &read_access)) {
		return false;
	}
	*visible = (read_access != 0);
	return true;
}

void mdcache_abe_put(struct connection_struct *conn,
		     struct mdcache_inode *slot,
		     bool visible)
{
	uint32_t ctx = mdcache_abe_ctx(conn);
	struct mdcache_access_key key;

	if (ctx != 0) {
		slot->flags &= ~MDCACHE_ABE_BITS;
		slot->flags |= ctx << MDCACHE_ABE_CTX_SHIFT;
		if (visible) {
			slot->flags |= MDCACHE_ABE_VISIBLE;
		}
	}
	if (mdcache_access_key(conn, slot->sd_variant, 0,
			       MDCACHE_ACCESS_ABE, &key)) {
		mdcache_access_store(&key, visible ? FILE_READ_DATA : 0);
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
