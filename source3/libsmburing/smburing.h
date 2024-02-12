/*
 * NFS4 ACL handling
 *
 * Copyright (C) iXsystems, Inc, 2024
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

#ifndef __SMBURING_H__
#define __SMBURING_H__

#include <liburing.h>

struct iovec_status;
struct smburing_aiocb;

typedef struct smburing_ctx {
	int event_fd;
	struct io_uring ring;
	TALLOC_CTX *aiocb_pool;
	struct smburing_aiocb *aio_queue;
	void *fde;
} suctx_t;

enum suaiocb_state { AIO_INIT, AIO_RUNNING, AIO_COMPLETE, AIO_CANCELLED };

typedef struct smburing_aiocb {
	struct smburing_aiocb *next, *prev;
	suctx_t *ctx;
	const char *location;
	struct tevent_req *req;
	struct io_uring_sqe *sqe;
	int saved_errno;
	struct iovec *iov;
	int iov_idx;
	int rv;
	enum suaiocb_state state;
	bool (*completion_fn)(struct smburing_aiocb *cur,
			      const char *location);
	void *private_data;
} suaiocb_t;

suctx_t *init_smburing_ctx(TALLOC_CTX *mem_ctx, size_t ring_sz);

int _smburing_process_events(suctx_t *ctx, const char *location);
#define smburing_process_events(ctx)\
	_smburing_process_events(ctx, __location__)

suaiocb_t *_get_aio_cb(suctx_t *ctx, const char *location);
#define get_aio_cb(ctx)\
	(suctx_t *)_get_aio_cb(ctx, __location__)

/* Normal variants of read / write */
int _add_aio_read(suaiocb_t *aiocb, int fd, void *data, size_t n,
		  off_t offset, const char *location);
#define add_aio_read(aiocb, fd, data, n, offset)\
	(int)_add_aio_read(aiocb, fd, data, n, offset, __location__)

int _add_aio_write(suaiocb_t *aiocb, int fd, void *data, size_t n,
		   off_t offset, const char *location);
#define add_aio_write(aiocb, fd, data, n, offset)\
	(int)_add_aio_write(aiocb, fd, data, n, offset, __location__)

int _add_aio_fsync(suaiocb_t *aiocb, int fd, const char *location);
#define add_aio_fsync(aiocb, fd)\
	(int)_add_aio_fsync(aiocb, fd, __location__)

#endif /* __SMBURING_H__ */
