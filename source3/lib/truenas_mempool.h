/*
 * Use memory pool under global server context
 *
 * Copyright (C) iXsystems, Inc. 2024
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
*/


/**
 * @brief Link the specified data blob to the specified memory context
 *	  This is done so that when the specified context is freed
 *	  the buffer associated the the specified DATA_BLOB is also
 *	  freed. This may be used in lieu of talloc_steal of the buffer,
 *	  and is required when memory pool is in use in order to ensure
 *	  that memory is released to the pool c.f. documentation for
 *	  talloc_pool(). A DATA_BLOB must be linked to no more than
 *	  one talloc context.
 *
 * @param[in]	ctx		The talloc context for the link
 * @param[in]	buf		Buffer to link to the context
 *
 * @return	true on success false on failure.
 */
bool link_io_buffer_blob(TALLOC_CTX *mem_ctx, DATA_BLOB *buf);

/**
 * @brief Allocate a DATA_BLOB with a buffer size specied by buflen
 * 	  using memory in the io_memory_pool.
 *
 * @param[in]	conn		The current tree connection
 * @param[in]	buflen		size of buffer to allocate
 * @param[buf]	out 		New DATA_BLOB with buffer
 *
 * @return	true on success false on failure.
 */
bool io_pool_alloc_blob(struct connection_struct *conn,
			size_t buflen,
			DATA_BLOB *out);

void *_io_pool_calloc_size(struct connection_struct *conn, size_t size,
			   const char *name, const char *location);

/**
 * @brief Allocate a specified amount of memory with the specified
 * 	  name using the io_memory_pool.
 *
 * @param[in]	conn		The current tree connection
 * @param[in]	size		size of allocation
 * @param[in]	name 		Name to use for new talloc chunk
 *
 * @return	Pointer to new talloc chunk, NULL on error.
 */
#define io_pool_calloc_size(conn, size, name)\
	_io_pool_calloc_size(conn, size, name, __location__)

/**
 * @brief Allocate a zero-initialized memory chunk of the  specified
 * 	  type.
 *
 * @param[in]	conn		The current tree connection
 * @param[in]	type		Type of memory to allocate
 *
 * @return	Pointer to new talloc chunk, NULL on error.
 */
#define io_pool_calloc(conn, type)\
	(type *)io_pool_calloc_size(conn, sizeof(type), #type)
