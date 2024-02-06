/* 
   Unix SMB/CIFS implementation.

   main select loop and event handling - libaio implementation

   Copyright (C) Andrew Tridgell	2003-2005
   Copyright (C) Stefan Metzmacher	2005-2013
   Copyright (C) Jeremy Allison		2013
   Copyright (C) Andrew Walker		2023

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

#include "replace.h"
#include "system/filesys.h"
#include "system/select.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"
#include "libaio.h"
#include "tevent_libaio.h"

#define LIBAIO_MAX_EV 256

typedef  bool libaio_fallback_t(struct tevent_context *ev, bool replay);
typedef struct libaio_event_context {
	/* a pointer back to the generic event_context */
	struct tevent_context *ev;
	io_context_t ctx;
	pid_t pid;
	bool panic_force_replay;
	bool *panic_state;
	libaio_fallback_t *panic_fallback;
        TALLOC_CTX *iocb_pool;
} libaio_ev_ctx_t;

#define LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT	(1<<0)
#define LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR	(1<<1)
#define LIBAIO_ADDITIONAL_FD_FLAG_GOT_ERROR	(1<<2)
#define LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX	(1<<3)
#define EVTOLA(x) (talloc_get_type_abort(x->additional_data, libaio_ev_ctx_t))
#define DATATOFDE(x) (talloc_get_type_abort(x, struct tevent_fd))
#define GETAIOKEY(x) (x->additional_flags >> 32)
#define SETAIOKEY(x) (
#define FLAGSTOKEY(x) (x >> 32)
#define KEYTOFLAGS(x) (x << 32)


static void libaio_panic(libaio_ev_ctx_t *libaio_ev,
			 const char *reason, bool replay)
{
	struct tevent_context *ev = libaio_ev->ev;
	libaio_fallback_t *panic_fallback = libaio_ev->panic_fallback;

	if (libaio_ev->panic_state != NULL) {
		*libaio_ev->panic_state = true;
	}

	if (libaio_ev->panic_force_replay) {
		replay = true;
	}

	TALLOC_FREE(ev->additional_data);

	if (panic_fallback == NULL) {
		tevent_debug(ev, TEVENT_DEBUG_FATAL,
			"%s (%s) replay[%u] - calling abort()\n",
			reason, strerror(errno), (unsigned)replay);
		abort();
	}

	tevent_debug(ev, TEVENT_DEBUG_ERROR,
		     "%s (%s) replay[%u] - calling panic_fallback\n",
		     reason, strerror(errno), (unsigned)replay);

	if (!panic_fallback(ev, replay)) {
		/* Fallback failed. */
		tevent_debug(ev, TEVENT_DEBUG_FATAL,
			"%s (%s) replay[%u] - calling abort()\n",
			reason, strerror(errno), (unsigned)replay);
		abort();
	}
}

static int libaio_poll(libaio_ev_ctx_t *libaio_ev,
		       struct tevent_fd *fde,
		       int events)
{
	struct iocb *iocb = talloc_zero(libaio_ev->iocb_pool, struct iocb);
	if (iocb == NULL) {
		abort();
	}
#if 0
	*iocb = (struct iocb) {
		.aio_fildes = fde->fd,
		.aio_lio_opcode = IO_CMD_POLL,
		.aio_reqprio = 0,
		.u.poll.events = events,
		.data = (void*)fde
	};
#endif
	iocb->aio_fildes = fde->fd;
	iocb->aio_lio_opcode = IO_CMD_POLL;
	iocb->aio_reqprio = 0;
	iocb->u.poll.events = events;
	iocb->data = (void *)fde;

	// io_submit returns count of submitted events or -errno
	ret = io_submit(libaio_ev->ctx, 1, &iocb);
	if (ret == 1) {

	}
}

/*
  map from TEVENT_FD_* to poll flags
*/
static uint16_t libaio_map_flags(uint16_t flags)
{
	uint16_t pollflags = 0;
        if (flags & TEVENT_FD_READ) {
		pollflags |= (POLLIN|POLLHUP);
        }
	if (flags & TEVENT_FD_WRITE) {
		pollflags |= (POLLOUT);
	}
	return pollflags;
}

static int libaio_ctx_destructor(libaio_ev_ctx_t *libaio_ev)
{
	int error;
	
	// io_queue_release() states that it _may_ cancel pending
	// iocbs. 
	error = io_queue_release(libaio_ev->ctx);
	if (error) {
		errno = -error;
	}

	libaio_ev->ctx = NULL;
	return 0;
}

_PRIVATE_ void tevent_libaio_set_panic_fallback(struct tevent_context *ev,
						libaio_fallback_t *panic_fallback)
{
	libaio_ev_ctx_t *libaio_ev = EVTOLA(ev);
	libaio_ev->panic_fallback = panic_fallback;
}

static int libaio_init_ctx(libaio_ev_ctx_t *libaio_ev)
{
	long error;

	error = io_queue_init(LIBAIO_MAX_EV, &libaio_ev->ctx);
	if (error) {
		tevent_debug(libaio_ev->ev, TEVENT_DEBUG_FATAL,
			     "Failed to create aio context (%s).\n",
			     strerror(-error));
		return -1;
	}

	libaio_ev->iocb_pool = talloc_pool(libaio_ev, LIBAIO_MAX_EV * sizeof(struct iocb));
	if (libaio_ev->iocb_pool == NULL) {
		abort();
	}

	libaio_ev->pid = tevent_cached_getpid();
	talloc_set_destructor(libaio_ev, libaio_ctx_destructor);

	return 0;
}

static void libaio_update_event(struct libaio_event_context *libaio_ev, struct tevent_fd *fde);

/*
 * Reopen io queue if pid changes
 */
static void libaio_check_reopen(libaio_ev_ctx_t *libaio_ev)
{
	struct tevent_fd *fde = NULL;
	int error;
	bool *caller_panic_state = libaio_ev->panic_state;
	bool panic_triggered = false;
	pid_t pid = tevent_cached_getpid();

	if (libaio_ev->pid == pid) {
		return;
	}

	io_destroy(libaio_ev->ctx);

	error = io_queue_init(LIBAIO_MAX_EV, &libaio_ev->ctx);
	if (error) {
		errno = -error;
		libaio_panic(libaio_ev, "io_setup() failed", false);
		return;
	}

	libaio_ev->pid = pid;
	libaio_ev->panic_state = &panic_triggered;
	for (fde=libaio_ev->ev->fd_events; fde; fde=fde->next) {
		fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	}
	for (fde=libaio_ev->ev->fd_events; fde; fde=fde->next) {
		libaio_update_event(libaio_ev, fde);

		if (panic_triggered) {
			if (caller_panic_state != NULL) {
				*caller_panic_state = true;
			}
			return;
		}
	}
	libaio_ev->panic_state = NULL;
}

/*
 libaio cannot add the same file descriptor twice, once
 with read, once with write which is allowed by the
 tevent backend. Multiplex the existing fde, flag it
 as such so we can search for the correct fde on
 event triggering.
*/

static int libaio_add_multiplex_fd(libaio_ev_ctx_t *libaio_ev,
				   struct tevent_fd *add_fde)
{
	struct iocb aiocb; // io_poll zeroes this struct
	struct tevent_fd *mpx_fde = NULL;
	int ret;
	uint16_t pollflags;

	/* Find the existing fde that caused the EEXIST error. */
	for (mpx_fde = libaio_ev->ev->fd_events; mpx_fde; mpx_fde = mpx_fde->next) {
		if (mpx_fde->fd != add_fde->fd) {
			continue;
		}

		if (mpx_fde == add_fde) {
			continue;
		}

		break;
	}
	if (mpx_fde == NULL) {
		tevent_debug(libaio_ev->ev, TEVENT_DEBUG_FATAL,
			     "can't find multiplex fde for fd[%d]",
			     add_fde->fd);
		return -1;
	}

	if (mpx_fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/* Logic error. Can't have more than 2 multiplexed fde's. */
		tevent_debug(libaio_ev->ev, TEVENT_DEBUG_FATAL,
			     "multiplex fde for fd[%d] is already multiplexed\n",
			     mpx_fde->fd);
		return -1;
	}

	/*
	 * The multiplex fde must have the same fd
	 */
	if (!(mpx_fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT)) {
		/* Logic error. Can't have more than 2 multiplexed fde's. */
		tevent_debug(libaio_ev->ev, TEVENT_DEBUG_FATAL,
			     "multiplex fde for fd[%d] has no event\n",
			     mpx_fde->fd);
		return -1;
	}

	/* Modify the mpx_fde to add in the new flags. */
	pollflags = libaio_map_flags(mpx_fde->flags | add_fde->flags);

	ret = libaio_poll(libaio_ev, mpx_fde, pollflags);
	if (ret != 0 && errno == EBADF) {
		tevent_debug(libaio_ev->ev, TEVENT_DEBUG_ERROR,
			     "io_poll() failed with EBADF for "
			     "add_fde[%p] mpx_fde[%p] fd[%d] - disabling\n",
			     add_fde, mpx_fde, add_fde->fd);
		DLIST_REMOVE(libaio_ev->ev->fd_events, mpx_fde);
		mpx_fde->wrapper = NULL;
		mpx_fde->event_ctx = NULL;
		DLIST_REMOVE(libaio_ev->ev->fd_events, add_fde);
		add_fde->wrapper = NULL;
		add_fde->event_ctx = NULL;
		return 0;
	} else if (ret < 0) {
		errno = -ret;
		return -1;
	}

	/*
	 * Make each fde->additional_data pointers point at each other
	 * so we can look them up from each other. They are now paired.
	 */
	mpx_fde->additional_data = (struct tevent_fd *)add_fde;
	add_fde->additional_data = (struct tevent_fd *)mpx_fde;

	/* Now flag both fde's as being multiplexed. */
	mpx_fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX;
	add_fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX;

	/* we need to keep the GOT_ERROR flag */
	if (mpx_fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_GOT_ERROR) {
		add_fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_GOT_ERROR;
	}

	return 0;
}

static void libaio_add_event(libaio_ev_ctx_t *libaio_ev, struct tevent_fd *fde)
{
	int ret;
	struct tevent_fd *mpx_fde = NULL;
	uint16_t pollflags;

	fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	pollflags = libaio_map_flags(fde->flags);

	if (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is a multiplexed fde, we need to include both
		 * flags in the modified event.
		 */
		mpx_fde = DATATOFDE(fde->additional_data);
		mpx_fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
		mpx_fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;
		pollflags |= libaio_map_flags(mpx_fde->flags);
	}

	ret = libaio_poll(libaio_ev, fde, pollflags);
	if (ret != 0 && errno == EBADF) {
		tevent_debug(libaio_ev->ev, TEVENT_DEBUG_ERROR,
			     "io_poll() EBADF for "
			     "fde[%p] mpx_fde[%p] fd[%d] - disabling\n",
			     fde, mpx_fde, fde->fd);
		DLIST_REMOVE(libaio_ev->ev->fd_events, fde);
		fde->wrapper = NULL;
		fde->event_ctx = NULL;
		if (mpx_fde != NULL) {
			DLIST_REMOVE(libaio_ev->ev->fd_events, mpx_fde);
			mpx_fde->wrapper = NULL;
			mpx_fde->event_ctx = NULL;
		}
		return;
	} else if (ret < 0) {
		errno = -ret;
		libaio_panic(libaio_ev, "io_poll() failed", false);
		return;
	}

	fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & TEVENT_FD_READ) {
		fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	if (mpx_fde == NULL) {
		return;
	}

	mpx_fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (mpx_fde->flags & TEVENT_FD_READ) {
		mpx_fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

static void libaio_del_event(libaio_ev_ctx_t *libaio_ev, struct tevent_fd *fde)
{
	struct iocb aiocb;
	struct io_event event;
	int ret;
	struct tevent_fd *mpx_fde = NULL;

	fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	if (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is a multiplexed fde, we need to modify both events.
		 */
		mpx_fde = DATATOFDE(fde->additional_data);
		mpx_fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
		mpx_fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	aiocb = (struct iocb) {
		.aio_fildes = fde->fd,
		.aio_lio_opcode = IO_CMD_POLL,
	};
	ret = io_cancel(libaio_ev->ctx, &aiocb, &event);
	if (ret != 0) {
		errno = ret;
		abort();
		libaio_panic(libaio_ev, "io_cancel() failed", false);
		return;
	}
}

static void libaio_mod_event(libaio_ev_ctx_t *libaio_ev, struct tevent_fd *fde)
{
	struct tevent_fd *mpx_fde = NULL;
	int ret;
	uint16_t pollflags;

	fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	if (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is a multiplexed fde, we need to include both
		 * flags in the modified event.
		 */
		mpx_fde = DATATOFDE(fde->additional_data);
		mpx_fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
		mpx_fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	pollflags = libaio_map_flags(fde->flags);
	if (mpx_fde != NULL) {
		pollflags |= libaio_map_flags(mpx_fde->flags);
	}

	ret = libaio_poll(libaio_ev, fde, pollflags);
	if (ret != 0 && errno == EBADF) {
		tevent_debug(libaio_ev->ev, TEVENT_DEBUG_ERROR,
			     "io_poll() EBADF for "
			     "fde[%p] mpx_fde[%p] fd[%d] - disabling\n",
			     fde, mpx_fde, fde->fd);
		DLIST_REMOVE(libaio_ev->ev->fd_events, fde);
		fde->wrapper = NULL;
		fde->event_ctx = NULL;
		if (mpx_fde != NULL) {
			DLIST_REMOVE(libaio_ev->ev->fd_events, mpx_fde);
			mpx_fde->wrapper = NULL;
			mpx_fde->event_ctx = NULL;
		}
		return;
	} else if (ret < 0) {
		libaio_panic(libaio_ev, "io_poll() failed", false);
		return;
	}

	fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & TEVENT_FD_READ) {
		fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	if (mpx_fde == NULL) {
		return;
	}

	mpx_fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (mpx_fde->flags & TEVENT_FD_READ) {
		mpx_fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

static void libaio_update_event(libaio_ev_ctx_t *libaio_ev, struct tevent_fd *fde)
{
	bool got_error = (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_GOT_ERROR);
	bool want_read = (fde->flags & TEVENT_FD_READ);
	bool want_write= (fde->flags & TEVENT_FD_WRITE);
	struct tevent_fd *mpx_fde = NULL;

	if (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * work out what the multiplexed fde wants.
		 */
		mpx_fde = DATATOFDE(fde->additional_data);
		if (mpx_fde->flags & TEVENT_FD_READ) {
			want_read = true;
		}

		if (mpx_fde->flags & TEVENT_FD_WRITE) {
			want_write = true;
		}
	}

	/* there's already an event */
	if (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT) {
		if (want_read || (want_write && !got_error)) {
			libaio_mod_event(libaio_ev, fde);
			return;
		}
		/* TODO: review whether this is needed for aio POLL */
		libaio_del_event(libaio_ev, fde);
		return;
	}

	if (want_read || (want_write && !got_error)) {
		libaio_add_event(libaio_ev, fde);
		return;
	}
}

static bool libaio_handle_hup_or_err(libaio_ev_ctx_t *libaio_ev,
				struct tevent_fd *fde)
{
	if (fde == NULL) {
		/* Nothing to do if no event. */
		return true;
	}

	fde->additional_flags |= LIBAIO_ADDITIONAL_FD_FLAG_GOT_ERROR;
	/*
	 * if we only wait for TEVENT_FD_WRITE, we should not tell the
	 * event handler about it, and remove the io_event,
	 * as we only report errors when waiting for read events,
	 * to match the select() behavior
	 */
	if (!(fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_REPORT_ERROR)) {
		/*
		 * Do the same as the poll backend and
		 * remove the writeable flag.
		 */
		fde->flags &= ~TEVENT_FD_WRITE;
		return true;
	}
	/* This has TEVENT_FD_READ set, we're not finished. */
	return false;
}

static int process_poll_event(libaio_ev_ctx_t *libaio_ev,
			      struct iocb *aiocb,
			      void *data)
{
	struct tevent_fd *fde = NULL, *mpx_fde = NULL;
	int pollret = aiocb->u.poll.events;
	int flags;

	fde = DATATOFDE(data);
	if (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * Save off the multiplexed event in case we need
		 * to use it to call the handler function.
		 */
		mpx_fde = DATATOFDE(fde->additional_data);
	}
	if (pollret & (POLLHUP|POLLERR)) {
		bool handled_fde = libaio_handle_hup_or_err(libaio_ev, fde);
		bool handled_mpx = libaio_handle_hup_or_err(libaio_ev, mpx_fde);
		if (handled_fde && handled_mpx) {
			libaio_update_event(libaio_ev, fde);
			TALLOC_FREE(aiocb);
			return 0;
		}

		if (!handled_mpx) {
			/*
			 * If the mpx event was the one that needs
			 * further handling, it's the TEVENT_FD_READ
			 * event so switch over and call that handler.
			 */
			fde = mpx_fde;
			mpx_fde = NULL;
		}
		flags |= TEVENT_FD_READ;
	}

	if (pollret & POLLIN) flags |= TEVENT_FD_READ;
	if (pollret & POLLOUT) flags |= TEVENT_FD_WRITE;

	if (flags & TEVENT_FD_WRITE) {
		if (fde->flags & TEVENT_FD_WRITE) {
			mpx_fde = NULL;
		}
		if (mpx_fde && mpx_fde->flags & TEVENT_FD_WRITE) {
			fde = mpx_fde;
			mpx_fde = NULL;
		}
	}

	if (mpx_fde) {
		/* Ensure we got the right fde. */
		if ((flags & fde->flags) == 0) {
			fde = mpx_fde;
			mpx_fde = NULL;
		}
	}

	/*
	 * make sure we only pass the flags
	 * the handler is expecting.
	 */
	flags &= fde->flags;
	if (flags) {
		return tevent_common_invoke_fd_handler(fde, flags, NULL);
	}

	TALLOC_FREE(aiocb);
	return 0;
}

static int handle_libaio_event(libaio_ev_ctx_t *libaio_ev,
	       		       struct iocb *iocbp,
			       void *data)
{
	switch (iocbp->aio_lio_opcode) {
	case 9:
	case IO_CMD_POLL:
		return process_poll_event(libaio_ev, iocbp, data);
	default:
		abort();
	};
}

static int libaio_event_loop(libaio_ev_ctx_t *libaio_ev, struct timeval *tvalp)
{
	int ret, i;
	struct io_event event = { 0 };
	struct timespec ts;
	struct timespec *tsp = NULL;

	if (libaio_ev == NULL)
		abort();
	if (tvalp) {
		ts = (struct timespec) {
			.tv_sec = tvalp->tv_sec,
			.tv_nsec = (tvalp->tv_usec + 999) * 1000
		};
		if (ts.tv_nsec >= 1000000000) {
			ts.tv_sec += 1;
			ts.tv_nsec -= 1000000000;
		}
		tsp = &ts;
	}

	if (libaio_ev->ev->signal_events &&
	    tevent_common_check_signal(libaio_ev->ev)) {
		return 0;
	}

	tevent_trace_point_callback(libaio_ev->ev, TEVENT_TRACE_BEFORE_WAIT);
	ret = io_getevents(libaio_ev->ctx, 0, 1, &event, tsp);
	tevent_trace_point_callback(libaio_ev->ev, TEVENT_TRACE_AFTER_WAIT);

	switch (ret) {
	case -EINTR:
		if (libaio_ev->ev->signal_events) {
			tevent_common_check_signal(libaio_ev->ev);
		}
		return 0;
	case 0:
		if (tvalp) {
			tevent_common_loop_timer_delay(libaio_ev->ev);
		}
		return 0;
	};

	if (ret < 0) {
		errno = -ret;
		libaio_panic(libaio_ev, "fuck", false);
		return -1;
	}

	return handle_libaio_event(libaio_ev, event.obj, event.data);
}

static int libaio_event_context_init(struct tevent_context *ev)
{
	int ret;
	libaio_ev_ctx_t *libaio_ev = NULL;

	/*
	 * We might be called during tevent_re_initialise()
	 * which means we need to free our old additional_data.
	 */
	TALLOC_FREE(ev->additional_data);

	libaio_ev = talloc_zero(ev, libaio_ev_ctx_t);
	if (!libaio_ev) return -1;
	libaio_ev->ev = ev;

	ret = libaio_init_ctx(libaio_ev);
	if (ret != 0) {
		talloc_free(libaio_ev);
		return ret;
	}

	ev->additional_data = libaio_ev;
	return 0;
}

static int libaio_event_fd_destructor(struct tevent_fd *fde)
{
	struct tevent_context *ev = fde->event_ctx;
	libaio_ev_ctx_t *libaio_ev = NULL;
	bool panic_triggered = false;
	struct tevent_fd *mpx_fde = NULL;
	int flags = fde->flags;

	if (ev == NULL) {
		return tevent_common_fd_destructor(fde);
	}

	libaio_ev = EVTOLA(ev);

	/*
	 * we must remove the event from the list
	 * otherwise a panic fallback handler may
	 * reuse invalid memory
	 */
	DLIST_REMOVE(ev->fd_events, fde);

	if (fde->additional_flags & LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX) {
		mpx_fde = DATATOFDE(fde->additional_data);
		fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX;
		mpx_fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_MPX;

		fde->additional_data = NULL;
		mpx_fde->additional_data = NULL;

		fde->additional_flags &= ~LIBAIO_ADDITIONAL_FD_FLAG_HAS_EVENT;
	}

	libaio_ev->panic_state = &panic_triggered;
	if (libaio_ev->pid != tevent_cached_getpid()) {
		libaio_check_reopen(libaio_ev);
		if (panic_triggered) {
			return tevent_common_fd_destructor(fde);
		}
	}

	if (mpx_fde != NULL) {
		libaio_update_event(libaio_ev, mpx_fde);
		if (panic_triggered) {
			return tevent_common_fd_destructor(fde);
		}
	}

	fde->flags = 0;
	libaio_update_event(libaio_ev, fde);
	fde->flags = flags;
	if (panic_triggered) {
		return tevent_common_fd_destructor(fde);
	}
	libaio_ev->panic_state = NULL;

	return tevent_common_fd_destructor(fde);
}

static struct tevent_fd *libaio_event_add_fd(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
					     int fd, uint16_t flags,
					     tevent_fd_handler_t handler,
					     void *private_data,
					     const char *handler_name,
					     const char *location)
{
	libaio_ev_ctx_t *libaio_ev = EVTOLA(ev);
	struct tevent_fd *fde;
	bool panic_triggered = false;
	pid_t old_pid = libaio_ev->pid;

	fde = tevent_common_add_fd(ev, mem_ctx, fd, flags,
				   handler, private_data,
				   handler_name, location);
	if (!fde) return NULL;

	talloc_set_destructor(fde, libaio_event_fd_destructor);

	if (libaio_ev->pid != tevent_cached_getpid()) {
		libaio_ev->panic_state = &panic_triggered;
		libaio_check_reopen(libaio_ev);
		if (panic_triggered) {
			return fde;
		}
		libaio_ev->panic_state = NULL;
	}

	if (libaio_ev->pid == old_pid) {
		libaio_update_event(libaio_ev, fde);
	}

	return fde;
}

static void libaio_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	struct tevent_context *ev = NULL;
	libaio_ev_ctx_t *libaio_ev = NULL;
	bool panic_triggered = false;
	pid_t old_pid;

	if (fde->flags == flags) return;

	ev = fde->event_ctx;

	libaio_ev = EVTOLA(ev);

	old_pid = libaio_ev->pid;

	fde->flags = flags;

	if (libaio_ev->pid != tevent_cached_getpid()) {
		libaio_ev->panic_state = &panic_triggered;
		libaio_check_reopen(libaio_ev);
		if (panic_triggered) {
			return;
		}
		libaio_ev->panic_state = NULL;
	}

	if (libaio_ev->pid == old_pid) {
		libaio_update_event(libaio_ev, fde);
	}
}

static int libaio_event_loop_once(struct tevent_context *ev, const char *location)
{
	libaio_ev_ctx_t *libaio_ev = EVTOLA(ev);
	struct timeval tval;
	bool panic_triggered = false;
	if (libaio_ev == NULL)
		abort();

	if (ev->signal_events &&
	    tevent_common_check_signal(ev)) {
		return 0;
	}

	if (ev->threaded_contexts != NULL) {
		tevent_common_threaded_activate_immediate(ev);
	}

	if (ev->immediate_events &&
	    tevent_common_loop_immediate(ev)) {
		return 0;
	}

	tval = tevent_common_loop_timer_delay(ev);
	if (tevent_timeval_is_zero(&tval)) {
		return 0;
	}

	if (libaio_ev->pid != tevent_cached_getpid()) {
		libaio_ev->panic_state = &panic_triggered;
		libaio_ev->panic_force_replay = true;
		libaio_check_reopen(libaio_ev);
		if (panic_triggered) {
			errno = EINVAL;
			return -1;
		}
		libaio_ev->panic_force_replay = false;
		libaio_ev->panic_state = NULL;
	}

	return libaio_event_loop(libaio_ev, &tval);
}

static void tevent_aio_cancel(struct tevent_aiocb *taiocb)
{
	int error;
	libaio_ev_ctx_t *libaio_ev = EVTOLA(taiocb->ev);
	struct iocb *iocbp = taiocb->iocbp;
	struct io_event event;

	tevent_debug(
		taiocb->ev, TEVENT_DEBUG_WARNING,
		"tevent_aio_cancel(): "
		"taio: %p, iocbp: %p\n",
		taiocb, iocbp
	);

	if (iocbp == NULL) {
		abort();
	}

	error = io_cancel(libaio_ev->ctx, iocbp, &event);
        switch (error) {
        case EFAULT:
		// EFAULT If any of the data structures pointed to are invalid.
                tevent_debug(
                        taiocb->ev, TEVENT_DEBUG_WARNING,
                        "tevent_aio_cancel(): "
                        "io_cancel() failed with EFAULT\n"
                );
                abort();
        case EINVAL:
		// EINVAL If aio_context specified by ctx is invalid.
                tevent_debug(
                        taiocb->ev, TEVENT_DEBUG_WARNING,
                        "tevent_aio_cancel(): "
                        "io_cancel() failed with EINVAL\n"
                );
                abort();
	case EAGAIN:
		// EAGAIN If the iocb specified was not cancelled.
                tevent_debug(
                        taiocb->ev, TEVENT_DEBUG_WARNING,
                        "tevent_aio_cancel(): "
                        "io_cancel() failed with EAGAIN\n"
                );
                abort();
	};
	TALLOC_FREE(taiocb->iocbp);
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

struct iocb *tevent_ctx_get_iocb(struct tevent_aiocb *taiocb)
{
	libaio_ev_ctx_t *libaio_ev = EVTOLA(taiocb->ev);
        struct iocb *iocbp = NULL;

        tevent_req_set_cancel_fn(taiocb->req, aio_req_cancel);
        iocbp = talloc_zero(libaio_ev->iocb_pool, struct iocb);
        if (iocbp == NULL) {
                abort();
        }
#if 0
        iocbp->aio_sigevent.sigev_notify_kqueue = kqueue_ev->rdwrq->kq_fd;
        iocbp->aio_sigevent.sigev_value.sival_ptr = taiocb;
        iocbp->aio_sigevent.sigev_notify = SIGEV_KEVENT;
        iocbp->aio_sigevent.sigev_notify_kevent_flags = EV_ONESHOT;
        taiocb->iocbp = iocbp;
#endif
        talloc_set_destructor(taiocb, aio_destructor);
        return iocbp;
}

static const struct tevent_ops libaio_event_ops = {
	.context_init		= libaio_event_context_init,
	.add_fd			= libaio_event_add_fd,
	.set_fd_close_fn	= tevent_common_fd_set_close_fn,
	.get_fd_flags		= tevent_common_fd_get_flags,
	.set_fd_flags		= libaio_event_set_fd_flags,
	.add_timer		= tevent_common_add_timer_v2,
	.schedule_immediate	= tevent_common_schedule_immediate,
	.add_signal		= tevent_common_add_signal,
	.loop_once		= libaio_event_loop_once,
	.loop_wait		= tevent_common_loop_wait,
};

_PRIVATE_ bool tevent_libaio_init(void)
{
	return tevent_register_backend("libaio", &libaio_event_ops);
}
