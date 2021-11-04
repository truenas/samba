/*
   Unix SMB/CIFS implementation.

   main select loop and event handling - kqueue implementation

   Copyright (C) iXsystems		2020

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
#include <aio.h>

struct tevent_aiocb {
	struct aiocb *iocbp;
	int saved_errno;
	int rv;
};

int tevent_add_aio_read(struct tevent_context *ev, struct tevent_aiocb *taiocb);
int tevent_add_aio_write(struct tevent_context *ev, struct tevent_aiocb *taiocb);
int tevent_add_aio_fsync(struct tevent_context *ev, struct tevent_aiocb *taiocb);
