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
#include "lib/truenas_mempool.h"

/*
 * Defaults chosen scale-safe (thousands of smbds): a modest reusable arena
 * and a short idle reclaim, so an idle or read-light worker pays ~nothing.
 * A low-client-count "max speed" box can raise io_pool_size_kb and set
 * io_pool_idle_secs=0 to keep buffers permanently warm.
 */
#define MEM_POOL_DEFAULT_KB     (16 * 1024)   /* 16 MiB arena hint */
#define IO_POOL_DEFAULT_IDLE    60            /* seconds; 0 = never reclaim */

/* Count of allocations out of memory pool */
static uint alloc_cnt;

static struct tevent_timer *io_buffer_timer;
static struct timespec last_alloc;

struct io_pool_link { DATA_BLOB to_free; };

static size_t io_pool_size_bytes(void)
{
	int kb = lp_parm_int(GLOBAL_SECTION_SNUM, "truenas_uring",
			     "io_pool_size_kb", MEM_POOL_DEFAULT_KB);
	if (kb <= 0) {
		kb = MEM_POOL_DEFAULT_KB;
	}
	return (size_t)kb * 1024;
}

static int io_pool_idle_secs(void)
{
	int s = lp_parm_int(GLOBAL_SECTION_SNUM, "truenas_uring",
			    "io_pool_idle_secs", IO_POOL_DEFAULT_IDLE);
	return (s < 0) ? IO_POOL_DEFAULT_IDLE : s;
}

static int io_buffer_destroy(struct io_pool_link *lnk)
{
	/*
	 * This is the destructor function for linkage between
	 * between allocations out of our memory pool and is
	 * used for keeping track of how many outstanding
	 * allocations there are. In the case of data blobs,
	 * the linkage is created external to this library in order
	 * to allow a mechanism to effectively reparent the buffer under
	 * a different memory context.
	 */
	data_blob_free(&lnk->to_free);
	SMB_ASSERT(alloc_cnt > 0);
	alloc_cnt -= 1;
	return 0;
}

static struct io_pool_link *link_io_buffer_blob(TALLOC_CTX *mem_ctx, DATA_BLOB *buf)
{
	struct io_pool_link *lnk = NULL;

	SMB_ASSERT(buf->data != NULL);

	lnk = talloc_zero(mem_ctx, struct io_pool_link);
	if (lnk == NULL) {
		return lnk;
	}
	lnk->to_free = *buf;
	talloc_set_destructor(lnk, io_buffer_destroy);
	return lnk;
}

static void io_pool_time_handler(struct tevent_context *ctx,
				 struct tevent_timer *te,
				 struct timeval now,
				 void *private_data)
{
	// This is an idle timer. We want to free the io memory
	// pool if the smbd process is not using it for more than
	// the configured idle interval.
	struct smbd_server_connection *sconn = NULL;
	struct timespec mono_now;
	int idle = io_pool_idle_secs();

	sconn = (struct smbd_server_connection *)private_data;
	SMB_ASSERT(sconn != NULL);

	clock_gettime(CLOCK_MONOTONIC_COARSE, &mono_now);

	if ((alloc_cnt == 0) &&
	    (timespec_elapsed2(&last_alloc, &mono_now) > idle)){
		TALLOC_FREE(sconn->io_memory_pool);
		io_buffer_timer = NULL;
		return;
	}

	// now is timeval based on realtime clock (not monotonic time)
	now.tv_sec += idle;
	io_buffer_timer = tevent_add_timer(sconn->ev_ctx, NULL,
					   now, io_pool_time_handler,
					   sconn);
}

static bool init_io_pool(struct smbd_server_connection *sconn)
{
	int idle = io_pool_idle_secs();

	// Allocate the memory pool if needed and then set the idle
	// timer.
	clock_gettime(CLOCK_MONOTONIC_COARSE, &last_alloc);
	if (sconn->io_memory_pool == NULL) {
		sconn->io_memory_pool = talloc_pool(sconn, io_pool_size_bytes());
		if (sconn->io_memory_pool == NULL) {
			return false;
		}
		talloc_set_name(sconn->io_memory_pool, "TrueNAS Memory Pool");
	}

	// idle reclaim disabled (io_pool_idle_secs=0): keep the pool warm.
	if ((idle > 0) && (io_buffer_timer == NULL)) {
		// tevent timers are based on CLOCK_REALTIME
		struct timeval interval;
		interval = timeval_current_ofs(idle, 0);

		io_buffer_timer = tevent_add_timer(sconn->ev_ctx, NULL,
						   interval,
						   io_pool_time_handler, sconn);
	}

	return true;
}

bool io_pool_alloc_blob(struct connection_struct *conn,
			TALLOC_CTX *mem_ctx,
			size_t buflen,
			DATA_BLOB *out,
			struct io_pool_link **lnk_out)
{
	DATA_BLOB buf = { 0 };
	struct io_pool_link *lnk = NULL;

	alloc_cnt += 1;

	if (!init_io_pool(conn->sconn)) {
		alloc_cnt -= 1;
		return false;
	}

	buf = data_blob_talloc(conn->sconn->io_memory_pool, NULL, buflen);
	if (buf.data == NULL) {
		alloc_cnt -= 1;
		return false;
	}

	lnk = link_io_buffer_blob(mem_ctx, &buf);
	if (lnk == NULL) {
		data_blob_free(&buf);
		alloc_cnt -= 1;
		return false;
	}

	*out = lnk->to_free;
	*lnk_out = lnk;
	return true;
}
