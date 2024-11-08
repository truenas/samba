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

struct io_pool_link;

/**
 * @brief Allocate a DATA_BLOB with a buffer size specified by buflen
 * 	  using memory in the io_memory_pool. The buffer will be freed
 *	  when lnk_out is freed. lnk_out is allocated under the specified
 *	  mem_ctx.
 *
 * @param[in]	conn		The current tree connection
 * @param[in]   mem_ctx		Memory context under which to free buffer.
 * @param[in]	buflen		size of buffer to allocate
 * @param[out]	buf 		New DATA_BLOB with buffer
 * @param[out]	lnk_out 	Autofree linkage for data blob buffer
 *
 * @return	true on success false on failure.
 */
bool io_pool_alloc_blob(struct connection_struct *conn,
			TALLOC_CTX *mem_ctx,
			size_t buflen,
			DATA_BLOB *out,
			struct io_pool_link **lnk_out);
