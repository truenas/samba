/*
   Unix SMB/CIFS implementation.

   main select loop and event handling - kqueue implementation

   Copyright (C) Andrew Tridgell	2003-2005
   Copyright (C) Stefan Metzmacher	2005-2013
   Copyright (C) Jeremy Allison		2013
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
#include <sys/cdefs.h>
#include "replace.h"
#include <sys/event.h>
#include <search.h>
#include <aio.h>
#include "system/filesys.h"
#include "system/select.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"
#include "tevent_kqueue.h"

#define KQAIOSZ 16

typedef struct tevent_kqueue_ctx {
	int kq_fd;
	pid_t pid;
	struct tevent_context *ev;
	struct tevent_fd *kq_fde;
	struct kevent kq_array[KQAIOSZ];
	TALLOC_CTX *aio_pool;
} kqctx_t;


static void kqueue_event_loop(kqctx_t *kqctx);

static void tevent_aio_kq_handler(struct tevent_context *ev,
				  struct tevent_fd *fde,
				  uint16_t flags,
				  void *private_data)
{
	kqctx_t *kqctx = (kqctx_t *)private_data;
	kqueue_event_loop(kqctx);
}

static int kq_destructor(kqctx_t *kq)
{
	close(kq->kq_fd);
	kq->kq_fd = -1;
	kq->pid = -1;
	kq->ev = NULL;
	kq->kq_fde = NULL;
	kq->aio_pool = NULL;
	return 0;
}

static int do_kqueue(struct tevent_context *ev, kqctx_t *kq)
{
	kq->kq_fd = kqueuex(KQUEUE_CLOEXEC);
	if (kq->kq_fd == -1) {
		tevent_debug(kq->ev, TEVENT_DEBUG_FATAL,
			     "do_kqueue: Failed to create kqueue: %d\n",
			     errno);
		return -1;
	}

	talloc_set_destructor(kq, kq_destructor);

	if (kq->kq_fde != NULL) {
		/* possibly had to reinit after fork */
		TALLOC_FREE(kq->kq_fde);
	}
	kq->kq_fde = tevent_add_fd(kq->ev,
				   kq,
				   kq->kq_fd,
				   TEVENT_FD_READ,
				   tevent_aio_kq_handler,
				   kq);
	if (kq->kq_fde == NULL) {
		tevent_debug(kq->ev, TEVENT_DEBUG_FATAL,
			     "do_kqueue: Failed to set tevent fd on kqueue: %d\n",
			     errno);
		return -1;
	}

	return 0;
}

static kqctx_t *kqueue_init_ctx(struct tevent_context *ev)
{
	int ret;
	kqctx_t *kqctx = NULL;

	kqctx = talloc_zero(ev, kqctx_t);
	if (kqctx == NULL) {
		return NULL;
	}

	ret = do_kqueue(ev, kqctx);
	if (ret != 0) {
		TALLOC_FREE(kqctx);
		return NULL;
	}

	kqctx->pid = tevent_cached_getpid();
	return kqctx;
}

/*
  The kqueue queue is not inherited by a child created with fork(2).
  So we need to re-initialize if this happens.
 */
static void kqueue_check_reopen(kqctx_t *kqctx)
{
	int ret;
	pid_t pid = tevent_cached_getpid();

	if (kqctx->pid == pid) {
		return;
	}
	/*
	 * We've forked. Re-initialize.
	 */

	ret = do_kqueue(kqctx->ev, kqctx);
	if (ret != 0) {
		tevent_debug(kqctx->ev, TEVENT_DEBUG_FATAL,
			     "failed to initialize AIO kqueue.\n");
		abort();
	}

	kqctx->pid = pid;
}

static void kqueue_process_aio(kqctx_t *kqueue_ev,
			       void *udata)
{
	struct tevent_aiocb *tiocbp = NULL;

	tiocbp = talloc_get_type_abort(udata, struct tevent_aiocb);
	if (tiocbp == NULL) {
		tevent_debug(kqueue_ev->ev, TEVENT_DEBUG_FATAL,
			     "aio request was freed after being put on kevent queue. "
			     "memory may leak.\n");
		return;
	}
	if (tiocbp->iocbp == NULL) {
		tevent_debug(kqueue_ev->ev, TEVENT_DEBUG_FATAL,
			     "aiocb request is already completed.\n");
		abort();
	}

	if (!tevent_req_is_in_progress(tiocbp->req)) {
		tevent_debug(kqueue_ev->ev, TEVENT_DEBUG_FATAL,
			     "tevent request for aio event is not in progress.\n");
		abort();
	}

	tiocbp->rv = aio_return(tiocbp->iocbp);
	if (tiocbp->rv == -1) {
		tevent_debug(
			kqueue_ev->ev, TEVENT_DEBUG_WARNING,
			"%s: processing AIO [%p] - failed: %s\n",
			 tiocbp->location, tiocbp->iocbp, strerror(errno)
		);
		tiocbp->saved_errno = errno;
		TALLOC_FREE(tiocbp->iocbp);
		tevent_req_error(tiocbp->req, errno);
		return;
	}

	TALLOC_FREE(tiocbp->iocbp);
	tevent_req_done(tiocbp->req);
}

static void kqueue_process_kev(kqctx_t *kqueue_ev, struct kevent kev)
{
	switch (kev.filter) {
	case EVFILT_AIO:
		kqueue_process_aio(kqueue_ev, kev.udata);
		break;
	default:
		abort();
	}
	return;
}

static void kqueue_event_loop(kqctx_t *kqctx)
{
	/*
	 * Loop through an array of kevents. We need to retrieve multiple
	 * events at once in order to properly reconstruct the correct flags to
	 * send to the tevent fd handler.
	 */
	int i, nkevents;
	struct timespec ts = { 0 };

	/*
	 * If timeout is a non-NULL pointer, it specifies a maximum interval
	 * to wait for an event. If timeout is a NULL pointer, kevent() waits
	 * indefinetly. To effect a poll, the timeout argument should be
	 * non-NULL, pointing to a zero-valued timespec structure.
	 *
	 * If tvalp is NULL, then we pass a NULL for kevent() timeout. This is
	 * equivalent to epoll_wait() on Linux with a timeout of -1, which is
	 * what is performed in epoll tevent backend.
	 */
	nkevents = kevent(kqctx->kq_fd,
			  NULL,				/* changelist */
			  0,				/* nchanges */
			  kqctx->kq_array,		/* eventlist */
			  KQAIOSZ,			/* nevents */
			  &ts);				/* timeout */

	if (nkevents == -1) {
		if (errno != EINTR) {
			tevent_debug(kqctx->ev, TEVENT_DEBUG_FATAL,
				     "kevent() failed: %d\n", errno);
		}
		return;
	}

	for (i = 0; i < nkevents; i++) {
		kqueue_process_kev(kqctx, kqctx->kq_array[i]);
	}
}

static void tevent_aio_waitcomplete(struct tevent_context *ev, struct aiocb *iocbp)
{
	int ret;
	struct timespec timeout = {30,0};

	tevent_debug(
		ev, TEVENT_DEBUG_WARNING,
		"tevent_aio_waitcomplete(): aio op currently in progress for "
		"fd [%d], waiting for completion\n", iocbp->aio_fildes
	);

	ret = aio_waitcomplete(&iocbp, &timeout);
	if (ret == -1) {
		if (errno == ECANCELED) {
			return;
		}
		tevent_debug(
			ev, TEVENT_DEBUG_FATAL,
			"tevent_aio_waitcomplete(): aio_waitcomplete() failed: %s\n",
			strerror(errno)
		);
	} else if (ret == EINPROGRESS) {
		tevent_debug(
			ev, TEVENT_DEBUG_FATAL,
			"tevent_aio_waitcomplete(): aio_waitcomplete() "
			"failed to complete after 30 seconds\n"
		);
	}
}

static void tevent_aio_cancel(struct tevent_aiocb *taiocb)
{
	int ret;
	struct aiocb *iocbp = taiocb->iocbp;

	tevent_debug(
		taiocb->ev, TEVENT_DEBUG_WARNING,
		"tevent_aio_cancel(): "
		"taio: %p, iocbp: %p\n",
		taiocb, iocbp
	);

	if (iocbp == NULL) {
		abort();
	}

	ret = aio_cancel(iocbp->aio_fildes, iocbp);
	switch (ret) {
	case -1:
		tevent_debug(
			taiocb->ev, TEVENT_DEBUG_WARNING,
			"tevent_aio_cancel(): "
			"aio_cancel() returned -1: %s\n",
			 strerror(errno)
		);
		abort();
	case AIO_NOTCANCELED:
		ret = aio_error(iocbp);
		if ((ret == -1) &&
		    (errno != EAGAIN)) {
			tevent_debug(
				taiocb->ev, TEVENT_DEBUG_WARNING,
				"tevent_aio_cancel(): "
				"aio_error() failed: %s\n",
				 strerror(errno)
			);
			abort();
		}
		break;
	case AIO_CANCELED:
	case AIO_ALLDONE:
		break;
	default:
		tevent_debug(
			taiocb->ev, TEVENT_DEBUG_WARNING,
			"%d: unexpected aio_cancel() return.\n",
			ret
		);
		abort();
	};

	tevent_aio_waitcomplete(taiocb->ev, iocbp);
	TALLOC_FREE(taiocb->iocbp);
}

int _tevent_add_aio_read(struct tevent_aiocb *taiocb, const char *location)
{
	int err;

	taiocb->location = location;
	err = aio_read(taiocb->iocbp);
	if (err) {
		TALLOC_FREE(taiocb->iocbp);
	}

	return err;
}

int _tevent_add_aio_write(struct tevent_aiocb *taiocb, const char *location)
{
	int err;

	taiocb->location = location;
	err = aio_write(taiocb->iocbp);
	if (err) {
		TALLOC_FREE(taiocb->iocbp);
	}

	return err;
}

int _tevent_add_aio_fsync(struct tevent_aiocb *taiocb, const char *location)
{
	int err;

	taiocb->location = location;
	err = aio_fsync(O_SYNC, taiocb->iocbp);
	if (err) {
		TALLOC_FREE(taiocb->iocbp);
	}

	return err;
}

static bool aio_req_cancel(struct tevent_req *req)
{
	struct tevent_aiocb *taiocb = tevent_req_data(req, struct tevent_aiocb);
	tevent_aio_cancel(taiocb);
	return true;
}

static int aio_destructor(struct tevent_aiocb *taio)
{
	if (taio->iocbp != NULL) {
		tevent_aio_cancel(taio);
	}
	return 0;
}

struct aiocb *tevent_ctx_get_iocb(struct tevent_aiocb *taiocb)
{
	struct aiocb *iocbp = NULL;
	kqctx_t *kqctx = NULL;
	void *ctx_out = NULL;

	if (!tevent_poll_aioctx_get(taiocb->ev, &ctx_out)) {
		abort();
	}

	if (ctx_out == NULL) {
		kqctx = kqueue_init_ctx(taiocb->ev);
		if (kqctx == NULL) {
			abort();
		}
		tevent_poll_aioctx_set(taiocb->ev, (void *)kqctx);
	} else {
		kqctx = talloc_get_type_abort(ctx_out, kqctx_t);
	}

	if (kqctx->aio_pool == NULL) {
		kqctx->aio_pool = talloc_pool(taiocb->ev, 128 * sizeof(struct aiocb));
		if (kqctx->aio_pool == NULL) {
			abort();
		}
	}

	tevent_req_set_cancel_fn(taiocb->req, aio_req_cancel);
	iocbp = talloc_zero(kqctx->aio_pool, struct aiocb);
	if (iocbp == NULL) {
		abort();
	}
	iocbp->aio_sigevent.sigev_notify_kqueue = kqctx->kq_fd;
	iocbp->aio_sigevent.sigev_value.sival_ptr = taiocb;
	iocbp->aio_sigevent.sigev_notify = SIGEV_KEVENT;
	iocbp->aio_sigevent.sigev_notify_kevent_flags = EV_ONESHOT;
	taiocb->iocbp = iocbp;
	talloc_set_destructor(taiocb, aio_destructor);
	return iocbp;
}
