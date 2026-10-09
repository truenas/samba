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

#ifndef __SMBD_TRUENAS_MDCACHE_H__
#define __SMBD_TRUENAS_MDCACHE_H__

struct smbd_server_connection;

#define MDCACHE_HAVE_DOSMODE	0x1

/*
 * What smbd derived from one version of a file, keyed by its file_id
 * (device, inode number and generation). The slot is reset whenever the
 * change cookie moves.
 */
struct mdcache_inode {
	struct file_id id;
	uint64_t cookie;
	uint64_t sd_seq;	/* security descriptor variant, 0 if unknown */
	int64_t btime_sec;	/* create time from DOSATTRIB */
	uint32_t btime_nsec;	/* UTIME_OMIT if DOSATTRIB has none */
	uint32_t dosmode;
	uint32_t flags;
	uint32_t tick;
};

struct mdcache_access_key {
	uint64_t sd_seq;
	uint64_t vuid;
	uint32_t cnum;
	uint32_t uid;
	uint32_t access_mask;
	uint32_t flags;
};

void mdcache_bump_epoch(struct smbd_server_connection *sconn);
void mdcache_stat_taken(struct files_struct *fsp, const SMB_STRUCT_STAT *sbuf);
struct mdcache_inode *mdcache_inode_fetch(struct files_struct *fsp);
struct mdcache_inode *mdcache_inode_peek(const struct file_id *id,
					 uint64_t cookie);
bool mdcache_inode_unchanged(struct files_struct *fsp, uint64_t cookie);
uint64_t mdcache_sd_variant(DATA_BLOB content);
bool mdcache_sd_get(uint64_t seq, uint32_t security_info,
		    TALLOC_CTX *mem_ctx, struct security_descriptor **ppdesc);
void mdcache_sd_put(uint64_t seq, uint32_t security_info,
		    const struct security_descriptor *psd);
bool mdcache_access_get(const struct mdcache_access_key *key,
			uint32_t *access_mask);
void mdcache_access_put(const struct mdcache_access_key *key,
			uint32_t access_mask);
void mdcache_flush_access(void);
void mdcache_smbtorture(struct files_struct *fsp, uint32_t idle_timeout,
			uint32_t *slots, uint32_t *count);

#endif /* __SMBD_TRUENAS_MDCACHE_H__ */
