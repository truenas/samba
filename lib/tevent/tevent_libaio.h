/*
   Unix SMB/CIFS implementation.

   main select loop and event handling - kqueue implementation

   Copyright (C) iXsystems		2023

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include "libaio.h"

typedef struct iocb iocb_t;

struct tevent_aiocb {
	const char *location;
	struct tevent_req *req;
	struct tevent_context *ev;
	iocb_t *iocbp;
	int saved_errno;
	int rv;
};

int _tevent_add_aio_read(struct tevent_aiocb *taiocb, const char *location);
#define tevent_add_aio_read(taiocb)\
        (int)_tevent_add_aio_read(taiocb, __location__)

int _tevent_add_aio_write(struct tevent_aiocb *taiocb, const char *location);
#define tevent_add_aio_write(taiocb)\
        (int)_tevent_add_aio_write(taiocb, __location__)

int _tevent_add_aio_fsync(struct tevent_aiocb *taiocb, const char *location);
#define tevent_add_aio_fsync(taiocb)\
        (int)_tevent_add_aio_fsync(taiocb, __location__)

struct iocb *tevent_ctx_get_iocb(struct tevent_aiocb *taiocb);

#define tio_prep_pread io_prep_pread
#define tio_prep_pwrite io_prep_pwrite
#define tio_prep_fsync io_prep_fsync
