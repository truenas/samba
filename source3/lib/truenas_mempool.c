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

#include "includes.h"
#include "smbd/globals.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/util/tevent_unix.h"

/****************************************************************************
 Accessor function to return write_through state.
*****************************************************************************/
#define MEM_POOL_SZ (16 * 1024 * 1024)
#define IO_POOL_IDLE_TIMEOUT 300

static uint alloc_cnt;
static struct tevent_timer *io_buffer_timer;
static struct timespec last_alloc;

struct io_pool_link { uint8_t *to_free; };

static int io_buffer_destroy(struct io_pool_link *lnk)
{
	if (lnk->to_free) {
		TALLOC_FREE(lnk->to_free);
	}
	SMB_ASSERT(alloc_cnt > 0);
	alloc_cnt -= 1;
	return 0;
}

bool link_io_buffer_blob(TALLOC_CTX *mem_ctx, DATA_BLOB *buf)
{
	struct io_pool_link *lnk = NULL;

	SMB_ASSERT(buf->data != NULL);

	lnk = talloc_zero(mem_ctx, struct io_pool_link);
	if (lnk == NULL) {
		return false;
	}
	lnk->to_free = buf->data;
	talloc_set_destructor(lnk, io_buffer_destroy);
	return true;
}

static bool link_io_buffer(TALLOC_CTX *mem_ctx)
{
	// This linkage is used to keep count of memory allocations
	// from the pool
	struct io_pool_link *lnk = NULL;

	lnk = talloc_zero(mem_ctx, struct io_pool_link);
	if (lnk == NULL) {
		return false;
	}

	talloc_set_destructor(lnk, io_buffer_destroy);
	return true;
}

static void io_pool_time_handler(struct tevent_context *ctx,
				 struct tevent_timer *te,
				 struct timeval now,
				 void *private_data)
{
	// This is an idle timer. We want to free the io memory
	// pool if the smbd process is not using it for more than
	// five minutes.
	struct smbd_server_connection *sconn = NULL;
	struct timespec mono_now;
	int err;

	sconn = (struct smbd_server_connection *)private_data;
	SMB_ASSERT(sconn != NULL);

	clock_gettime(CLOCK_MONOTONIC_COARSE, &mono_now);

	if ((alloc_cnt == 0) &&
	    (timespec_elapsed2(&last_alloc, &mono_now) > IO_POOL_IDLE_TIMEOUT)){
		TALLOC_FREE(sconn->io_memory_pool);
		io_buffer_timer = NULL;
		return;
	}

	// now is timeval based on realtime clock (not monotonic time)
	now.tv_sec += IO_POOL_IDLE_TIMEOUT;
	io_buffer_timer = tevent_add_timer(sconn->ev_ctx, NULL,
					   now, io_pool_time_handler,
					   sconn);
}

static bool init_io_pool(struct smbd_server_connection *sconn)
{
	// Allocate the memory pool if needed and then set the idle
	// timer.
	clock_gettime(CLOCK_MONOTONIC_COARSE, &last_alloc);
	if (sconn->io_memory_pool == NULL) {
		sconn->io_memory_pool = talloc_pool(sconn, MEM_POOL_SZ);
		if (sconn->io_memory_pool == NULL) {
			return false;
		}
	}

	if (io_buffer_timer == NULL) {
		// tevent timers are based on CLOCK_REALTIME
		struct timeval interval;
		interval = timeval_current_ofs(IO_POOL_IDLE_TIMEOUT, 0);

		io_buffer_timer = tevent_add_timer(sconn->ev_ctx, NULL,
						   interval,
						   io_pool_time_handler, sconn);
	}

	return true;
}

bool io_pool_alloc_blob(struct connection_struct *conn,
			size_t buflen,
			DATA_BLOB *out)
{
	DATA_BLOB buf = { 0 };

	if (!init_io_pool(conn->sconn)) {
		return false;
	}

	buf = data_blob_talloc(conn->sconn->io_memory_pool, NULL, buflen);
	if (buf.data == NULL) {
		return false;
	}

	*out = buf;
	alloc_cnt += 1;
	return true;
}

void *_io_pool_calloc_size(struct connection_struct *conn, size_t size,
			   const char *name, const char *location)
{
	void *out = NULL;

	if (!init_io_pool(conn->sconn)) {
		return NULL;
	}

	out = talloc_zero_size(conn, size);
	if (out == NULL) {
		return NULL;
	}

	talloc_set_name_const(out, name ? name : location);
	alloc_cnt += 1;

	if (!link_io_buffer(out)) {
		TALLOC_FREE(out);
		return NULL;
	}

	return out;
}
