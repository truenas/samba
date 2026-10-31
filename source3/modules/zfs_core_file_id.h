/*
 *  Unix SMB/CIFS implementation.
 *  File ids of ZFS files, as vfs_zfs_core gives them
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

#ifndef _ZFS_CORE_FILE_ID_H_
#define _ZFS_CORE_FILE_ID_H_

/*
 * The low 39 bits of a file id are the object number of the file. The
 * high 24 bits are:
 * - On the share's dataset, the low 24 bits of the inode generation, the
 *   txg in which ZFS created the object. Bit 39 is set. ZFS gives a freed
 *   object number to a new file only in a later txg, so the new file gets
 *   a different file id, unless the two txgs differ by a multiple of 2^24.
 * - Off the share's dataset, in the pool of the share's dataset, the
 *   objsetid of the dataset. Bits 39 and 63 are clear. An objsetid is
 *   unique in the pool, never 0, and does not change. A device minor can
 *   change at a failover.
 * - Off the share's dataset, in another pool, bit 63 and the low 23 bits
 *   of the fsid of the dataset. Bit 39 is clear. An objsetid is unique only
 *   in its pool. ZFS keeps an fsid in the pool and unique among the
 *   datasets of the host, so it does not change at a failover. Its low 23
 *   bits are unique only with high probability.
 * Without bit 39, a file on the share's dataset could have the file id of
 * a file in a child dataset. Without bit 63, a file in another pool could
 * have the file id of a file in the pool of the share's dataset.
 *
 * In ZFS both numbers can use 48 bits (DN_MAX_OBJECT_SHIFT), so no split of
 * 64 bits holds every pair. The split is 23 bits for the objsetid and 39
 * bits for the object number:
 * - An objsetid is an object number in the MOS of the pool. It grows with
 *   the history of dataset and snapshot creation. Real pools have
 *   objsetids above 2^16, for example 138,892. 2^23 is 8.4 million.
 * - The object number of a file follows the peak file count of its
 *   dataset, times the dnode slots of a file. 2^39 is 550 billion.
 * Above these limits, the file id is the default of vfs_default, which can
 * change at a failover. smbd logs a warning for such a dataset.
 *
 * vfs_zfs_core and the truesearch Spotlight backend use this layout.
 */
#define ZC_FILE_ID_OBJ_BITS 39
#define ZC_FILE_ID_SHARE_DS (1ULL << ZC_FILE_ID_OBJ_BITS)
#define ZC_FILE_ID_SET_SHIFT (ZC_FILE_ID_OBJ_BITS + 1)
#define ZC_FILE_ID_SET_BITS (64 - ZC_FILE_ID_SET_SHIFT)
#define ZC_FILE_ID_GEN_MASK ((1ULL << ZC_FILE_ID_SET_BITS) - 1)
/* The objsetid or the fsid bits of a child dataset */
#define ZC_FILE_ID_CHILD_BITS (ZC_FILE_ID_SET_BITS - 1)
#define ZC_FILE_ID_CHILD_MASK ((1ULL << ZC_FILE_ID_CHILD_BITS) - 1)
/* In the high 24 bits of a child dataset's file ids: another pool */
#define ZC_FILE_ID_OTHER_POOL (1ULL << ZC_FILE_ID_CHILD_BITS)

/* Return true if the object number fits in a file id */
static inline bool zc_file_id_fits(uint64_t ino)
{
	return (ino >> ZC_FILE_ID_OBJ_BITS) == 0;
}

/* Return the file id of a file on the share's dataset */
static inline uint64_t zc_share_file_id(uint64_t ino, uint64_t gen)
{
	return ((gen & ZC_FILE_ID_GEN_MASK) << ZC_FILE_ID_SET_SHIFT) |
	       ZC_FILE_ID_SHARE_DS |
	       ino;
}

/*
 * Return the high 24 bits of the file ids of a child dataset in the pool
 * of the share's dataset, or 0 if its objsetid does not fit.
 */
static inline uint64_t zc_child_set_same_pool(uint64_t objsetid)
{
	return ((objsetid >> ZC_FILE_ID_CHILD_BITS) == 0) ? objsetid : 0;
}

/* Return the high 24 bits of the file ids of a child dataset in another pool */
static inline uint64_t zc_child_set_other_pool(uint64_t fsid)
{
	return ZC_FILE_ID_OTHER_POOL | (fsid & ZC_FILE_ID_CHILD_MASK);
}

/* Return the file id of a file in a child dataset */
static inline uint64_t zc_child_file_id(uint64_t set, uint64_t ino)
{
	return (set << ZC_FILE_ID_SET_SHIFT) | ino;
}

/*
 * Get the object number from the file id of a file on the share's dataset.
 * Return false for other file ids.
 */
static inline bool zc_share_file_id_ino(uint64_t file_id, uint64_t *ino)
{
	if ((file_id & ZC_FILE_ID_SHARE_DS) == 0) {
		return false;
	}
	*ino = file_id & (ZC_FILE_ID_SHARE_DS - 1);
	return true;
}

#endif /* _ZFS_CORE_FILE_ID_H_ */
