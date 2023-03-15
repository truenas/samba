/*
   Unix SMB/CIFS implementation.
   main select loop and event handling
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan Metzmacher 2009

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

/*
  PLEASE READ THIS BEFORE MODIFYING!

  This module is a general abstraction for the main select loop and
  event handling. Do not ever put any localised hacks in here, instead
  register one of the possible event types and implement that event
  somewhere else.

  There are 2 types of event handling that are handled in this module:

  1) a file descriptor becoming readable or writeable. This is mostly
     used for network sockets, but can be used for any type of file
     descriptor. You may only register one handler for each file
     descriptor/io combination or you will get unpredictable results
     (this means that you can have a handler for read events, and a
     separate handler for write events, but not two handlers that are
     both handling read events)

  2) a timed event. You can register an event that happens at a
     specific time.  You can register as many of these as you
     like. They are single shot - add a new timed event in the event
     handler to get another event.

  To setup a set of events you first need to create a event_context
  structure using the function tevent_context_init(); This returns a
  'struct tevent_context' that you use in all subsequent calls.

  After that you can add/remove events that you are interested in
  using tevent_add_*() and talloc_free()

  Finally, you call tevent_loop_wait_once() to block waiting for one of the
  events to occor or tevent_loop_wait() which will loop
  forever.

*/
#include "replace.h"
#include "system/filesys.h"
#ifdef HAVE_PTHREAD
#include "system/threads.h"
#endif
#define TEVENT_DEPRECATED 1
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"
#ifdef HAVE_EVENTFD
#include <sys/eventfd.h>
#endif

struct tevent_ops_list {
	struct tevent_ops_list *next, *prev;
	const char *name;
	const struct tevent_ops *ops;
};

/* list of registered event backends */
static struct tevent_ops_list *tevent_backends = NULL;
static char *tevent_default_backend = NULL;

/*
  register an events backend
*/
bool tevent_register_backend(const char *name, const struct tevent_ops *ops)
{
	struct tevent_ops_list *e;

	for (e = tevent_backends; e != NULL; e = e->next) {
		if (0 == strcmp(e->name, name)) {
			/* already registered, skip it */
			return true;
		}
	}

	e = talloc(NULL, struct tevent_ops_list);
	if (e == NULL) return false;

	e->name = name;
	e->ops = ops;
	DLIST_ADD(tevent_backends, e);

	return true;
}

/*
  set the default event backend
 */
void tevent_set_default_backend(const char *backend)
{
	talloc_free(tevent_default_backend);
	tevent_default_backend = talloc_strdup(NULL, backend);
}

/*
  initialise backends if not already done
*/
static void tevent_backend_init(void)
{
	static bool done;

	if (done) {
		return;
	}

	done = true;

	tevent_poll_init();
	tevent_poll_mt_init();
#if defined(HAVE_EPOLL)
	tevent_epoll_init();
#elif defined(HAVE_SOLARIS_PORTS)
	tevent_port_init();
#elif defined(HAVE_KQUEUE)
	tevent_kqueue_init();

#endif

	tevent_standard_init();
}

const struct tevent_ops *tevent_find_ops_byname(const char *name)
{
	struct tevent_ops_list *e;

	tevent_backend_init();

	if (name == NULL) {
		name = tevent_default_backend;
	}
	if (name == NULL) {
		name = "standard";
	}

	for (e = tevent_backends; e != NULL; e = e->next) {
		if (0 == strcmp(e->name, name)) {
			return e->ops;
		}
	}

	return NULL;
}

/*
  list available backends
*/
const char **tevent_backend_list(TALLOC_CTX *mem_ctx)
{
	const char **list = NULL;
	struct tevent_ops_list *e;
	size_t idx = 0;

	tevent_backend_init();

	for (e=tevent_backends;e;e=e->next) {
		idx += 1;
	}

	list = talloc_zero_array(mem_ctx, const char *, idx+1);
	if (list == NULL) {
		return NULL;
	}

	idx = 0;
	for (e=tevent_backends;e;e=e->next) {
		list[idx] = talloc_strdup(list, e->name);
		if (list[idx] == NULL) {
			TALLOC_FREE(list);
			return NULL;
		}
		idx += 1;
	}

	return list;
}

static void tevent_common_wakeup_fini(struct tevent_context *ev);

#ifdef HAVE_PTHREAD

static pthread_mutex_t tevent_contexts_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tevent_context *tevent_contexts = NULL;
static pthread_once_t tevent_atfork_initialized = PTHREAD_ONCE_INIT;
static pid_t tevent_cached_global_pid = 0;

static void tevent_atfork_prepare(void)
{
	struct tevent_context *ev;
	int ret;

	ret = pthread_mutex_lock(&tevent_contexts_mutex);
	if (ret != 0) {
		abort();
	}

	for (ev = tevent_contexts; ev != NULL; ev = ev->next) {
		struct tevent_threaded_context *tctx;

		for (tctx = ev->threaded_contexts; tctx != NULL;
		     tctx = tctx->next) {
			ret = pthread_mutex_lock(&tctx->event_ctx_mutex);
			if (ret != 0) {
				tevent_abort(ev, "pthread_mutex_lock failed");
			}
		}

		ret = pthread_mutex_lock(&ev->scheduled_mutex);
		if (ret != 0) {
			tevent_abort(ev, "pthread_mutex_lock failed");
		}
	}
}

static void tevent_atfork_parent(void)
{
	struct tevent_context *ev;
	int ret;

	for (ev = DLIST_TAIL(tevent_contexts); ev != NULL;
	     ev = DLIST_PREV(ev)) {
		struct tevent_threaded_context *tctx;

		ret = pthread_mutex_unlock(&ev->scheduled_mutex);
		if (ret != 0) {
			tevent_abort(ev, "pthread_mutex_unlock failed");
		}

		for (tctx = DLIST_TAIL(ev->threaded_contexts); tctx != NULL;
		     tctx = DLIST_PREV(tctx)) {
			ret = pthread_mutex_unlock(&tctx->event_ctx_mutex);
			if (ret != 0) {
				tevent_abort(
					ev, "pthread_mutex_unlock failed");
			}
		}
	}

	ret = pthread_mutex_unlock(&tevent_contexts_mutex);
	if (ret != 0) {
		abort();
	}
}

static void tevent_atfork_child(void)
{
	struct tevent_context *ev;
	int ret;

	tevent_cached_global_pid = getpid();

	for (ev = DLIST_TAIL(tevent_contexts); ev != NULL;
	     ev = DLIST_PREV(ev)) {
		struct tevent_threaded_context *tctx;

		for (tctx = DLIST_TAIL(ev->threaded_contexts); tctx != NULL;
		     tctx = DLIST_PREV(tctx)) {
			tctx->event_ctx = NULL;

			ret = pthread_mutex_unlock(&tctx->event_ctx_mutex);
			if (ret != 0) {
				tevent_abort(
					ev, "pthread_mutex_unlock failed");
			}
		}

		ev->threaded_contexts = NULL;

		ret = pthread_mutex_unlock(&ev->scheduled_mutex);
		if (ret != 0) {
			tevent_abort(ev, "pthread_mutex_unlock failed");
		}
	}

	ret = pthread_mutex_unlock(&tevent_contexts_mutex);
	if (ret != 0) {
		abort();
	}
}

static void tevent_prep_atfork(void)
{
	int ret;

	ret = pthread_atfork(tevent_atfork_prepare,
			     tevent_atfork_parent,
			     tevent_atfork_child);
	if (ret != 0) {
		abort();
	}

	tevent_cached_global_pid = getpid();
}

#endif

static int tevent_init_globals(void)
{
#ifdef HAVE_PTHREAD
	int ret;

	ret = pthread_once(&tevent_atfork_initialized, tevent_prep_atfork);
	if (ret != 0) {
		return ret;
	}
#endif

	return 0;
}

_PUBLIC_ pid_t tevent_cached_getpid(void)
{
#ifdef HAVE_PTHREAD
	tevent_init_globals();
#ifdef TEVENT_VERIFY_CACHED_GETPID
	if (tevent_cached_global_pid != getpid()) {
		tevent_abort(NULL, "tevent_cached_global_pid invalid");
	}
#endif
	if (tevent_cached_global_pid != 0) {
		return tevent_cached_global_pid;
	}
#endif
	return getpid();
}

int tevent_common_context_destructor(struct tevent_context *ev)
{
	struct tevent_fd *fd, *fn;
	struct tevent_timer *te, *tn;
	struct tevent_immediate *ie, *in;
	struct tevent_signal *se, *sn;
	struct tevent_wrapper_glue *gl, *gn;
#ifdef HAVE_PTHREAD
	int ret;
#endif

	if (ev->wrapper.glue != NULL) {
		tevent_abort(ev,
			"tevent_common_context_destructor() active on wrapper");
	}

#ifdef HAVE_PTHREAD
	ret = pthread_mutex_lock(&tevent_contexts_mutex);
	if (ret != 0) {
		abort();
	}

	DLIST_REMOVE(tevent_contexts, ev);

	ret = pthread_mutex_unlock(&tevent_contexts_mutex);
	if (ret != 0) {
		abort();
	}

	while (ev->threaded_contexts != NULL) {
		struct tevent_threaded_context *tctx = ev->threaded_contexts;

		ret = pthread_mutex_lock(&tctx->event_ctx_mutex);
		if (ret != 0) {
			abort();
		}

		/*
		 * Indicate to the thread that the tevent_context is
		 * gone. The counterpart of this is in
		 * _tevent_threaded_schedule_immediate, there we read
		 * this under the threaded_context's mutex.
		 */

		tctx->event_ctx = NULL;

		ret = pthread_mutex_unlock(&tctx->event_ctx_mutex);
		if (ret != 0) {
			abort();
		}

		DLIST_REMOVE(ev->threaded_contexts, tctx);
	}

	ret = pthread_mutex_destroy(&ev->scheduled_mutex);
	if (ret != 0) {
		abort();
	}
#endif

	for (gl = ev->wrapper.list; gl; gl = gn) {
		gn = gl->next;

		gl->main_ev = NULL;
		DLIST_REMOVE(ev->wrapper.list, gl);
	}

	tevent_common_wakeup_fini(ev);

	for (fd = ev->fd_events; fd; fd = fn) {
		fn = fd->next;
		tevent_trace_fd_callback(fd->event_ctx, fd, TEVENT_EVENT_TRACE_DETACH);
		fd->wrapper = NULL;
		fd->event_ctx = NULL;
		DLIST_REMOVE(ev->fd_events, fd);
	}

	ev->last_zero_timer = NULL;
	for (te = ev->timer_events; te; te = tn) {
		tn = te->next;
		tevent_trace_timer_callback(te->event_ctx, te, TEVENT_EVENT_TRACE_DETACH);
		te->wrapper = NULL;
		te->event_ctx = NULL;
		DLIST_REMOVE(ev->timer_events, te);
	}

	for (ie = ev->immediate_events; ie; ie = in) {
		in = ie->next;
		tevent_trace_immediate_callback(ie->event_ctx, ie, TEVENT_EVENT_TRACE_DETACH);
		ie->wrapper = NULL;
		ie->event_ctx = NULL;
		ie->cancel_fn = NULL;
		DLIST_REMOVE(ev->immediate_events, ie);
	}

	for (se = ev->signal_events; se; se = sn) {
		sn = se->next;
		tevent_trace_signal_callback(se->event_ctx, se, TEVENT_EVENT_TRACE_DETACH);
		se->wrapper = NULL;
		se->event_ctx = NULL;
		DLIST_REMOVE(ev->signal_events, se);
		/*
		 * This is important, Otherwise signals
		 * are handled twice in child. eg, SIGHUP.
		 * one added in parent, and another one in
		 * the child. -- BoYang
		 */
		tevent_cleanup_pending_signal_handlers(se);
	}

	/* removing nesting hook or we get an abort when nesting is
	 * not allowed. -- SSS
	 * Note that we need to leave the allowed flag at its current
	 * value, otherwise the use in tevent_re_initialise() will
	 * leave the event context with allowed forced to false, which
	 * will break users that expect nesting to be allowed
	 */
	ev->nesting.level = 0;
	ev->nesting.hook_fn = NULL;
	ev->nesting.hook_private = NULL;

	return 0;
}

static int tevent_common_context_constructor(struct tevent_context *ev)
{
	int ret;

	ret = tevent_init_globals();
	if (ret != 0) {
		return ret;
	}

#ifdef HAVE_PTHREAD

	ret = pthread_mutex_init(&ev->scheduled_mutex, NULL);
	if (ret != 0) {
		return ret;
	}

	ret = pthread_mutex_lock(&tevent_contexts_mutex);
	if (ret != 0) {
		pthread_mutex_destroy(&ev->scheduled_mutex);
		return ret;
	}

	DLIST_ADD(tevent_contexts, ev);

	ret = pthread_mutex_unlock(&tevent_contexts_mutex);
	if (ret != 0) {
		abort();
	}
#endif

	talloc_set_destructor(ev, tevent_common_context_destructor);

	return 0;
}

void tevent_common_check_double_free(TALLOC_CTX *ptr, const char *reason)
{
	void *parent_ptr = talloc_parent(ptr);
	size_t parent_blocks = talloc_total_blocks(parent_ptr);

	if (parent_ptr != NULL && parent_blocks == 0) {
		/*
		 * This is an implicit talloc free, as we still have a parent
		 * but it's already being destroyed. Note that
		 * talloc_total_blocks(ptr) also just returns 0 if a
		 * talloc_free(ptr) is still in progress of freeing all
		 * children.
		 */
		return;
	}

	tevent_abort(NULL, reason);
}

/*
  create a event_context structure for a specific implemementation.
  This must be the first events call, and all subsequent calls pass
  this event_context as the first element. Event handlers also
  receive this as their first argument.

  This function is for allowing third-party-applications to hook in gluecode
  to their own event loop code, so that they can make async usage of our client libs

  NOTE: use tevent_context_init() inside of samba!
*/
struct tevent_context *tevent_context_init_ops(TALLOC_CTX *mem_ctx,
					       const struct tevent_ops *ops,
					       void *additional_data)
{
	struct tevent_context *ev;
	int ret;

	ev = talloc_zero(mem_ctx, struct tevent_context);
	if (!ev) return NULL;

	ret = tevent_common_context_constructor(ev);
	if (ret != 0) {
		talloc_free(ev);
		return NULL;
	}

	ev->ops = ops;
	ev->additional_data = additional_data;

	ret = ev->ops->context_init(ev);
	if (ret != 0) {
		talloc_free(ev);
		return NULL;
	}

	return ev;
}

/*
  create a event_context structure. This must be the first events
  call, and all subsequent calls pass this event_context as the first
  element. Event handlers also receive this as their first argument.
*/
struct tevent_context *tevent_context_init_byname(TALLOC_CTX *mem_ctx,
						  const char *name)
{
	const struct tevent_ops *ops;

	ops = tevent_find_ops_byname(name);
	if (ops == NULL) {
		return NULL;
	}

	return tevent_context_init_ops(mem_ctx, ops, NULL);
}


/*
  create a event_context structure. This must be the first events
  call, and all subsequent calls pass this event_context as the first
  element. Event handlers also receive this as their first argument.
*/
struct tevent_context *tevent_context_init(TALLOC_CTX *mem_ctx)
{
	return tevent_context_init_byname(mem_ctx, NULL);
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
struct tevent_fd *_tevent_add_fd(struct tevent_context *ev,
				 TALLOC_CTX *mem_ctx,
				 int fd,
				 uint16_t flags,
				 tevent_fd_handler_t handler,
				 void *private_data,
				 const char *handler_name,
				 const char *location)
{
	return ev->ops->add_fd(ev, mem_ctx, fd, flags, handler, private_data,
			       handler_name, location);
}

/*
  set a close function on the fd event
*/
void tevent_fd_set_close_fn(struct tevent_fd *fde,
			    tevent_fd_close_fn_t close_fn)
{
	if (!fde) return;
	if (!fde->event_ctx) return;
	fde->event_ctx->ops->set_fd_close_fn(fde, close_fn);
}

static void tevent_fd_auto_close_fn(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    int fd,
				    void *private_data)
{
	close(fd);
}

void tevent_fd_set_auto_close(struct tevent_fd *fde)
{
	tevent_fd_set_close_fn(fde, tevent_fd_auto_close_fn);
}

/*
  return the fd event flags
*/
uint16_t tevent_fd_get_flags(struct tevent_fd *fde)
{
	if (!fde) return 0;
	if (!fde->event_ctx) return 0;
	return fde->event_ctx->ops->get_fd_flags(fde);
}

/*
  set the fd event flags
*/
void tevent_fd_set_flags(struct tevent_fd *fde, uint16_t flags)
{
	if (!fde) return;
	if (!fde->event_ctx) return;
	fde->event_ctx->ops->set_fd_flags(fde, flags);
}

bool tevent_signal_support(struct tevent_context *ev)
{
	if (ev->ops->add_signal) {
		return true;
	}
	return false;
}

static void (*tevent_abort_fn)(const char *reason);

void tevent_set_abort_fn(void (*abort_fn)(const char *reason))
{
	tevent_abort_fn = abort_fn;
}

void tevent_abort(struct tevent_context *ev, const char *reason)
{
	if (ev != NULL) {
		tevent_debug(ev, TEVENT_DEBUG_FATAL,
			     "abort: %s\n", reason);
	}

	if (!tevent_abort_fn) {
		abort();
	}

	tevent_abort_fn(reason);
}

/*
  add a timer event
  return NULL on failure
*/
struct tevent_timer *_tevent_add_timer(struct tevent_context *ev,
				       TALLOC_CTX *mem_ctx,
				       struct timeval next_event,
				       tevent_timer_handler_t handler,
				       void *private_data,
				       const char *handler_name,
				       const char *location)
{
	return ev->ops->add_timer(ev, mem_ctx, next_event, handler, private_data,
				  handler_name, location);
}

/*
  allocate an immediate event
  return NULL on failure (memory allocation error)
*/
struct tevent_immediate *_tevent_create_immediate(TALLOC_CTX *mem_ctx,
						  const char *location)
{
	struct tevent_immediate *im;

	im = talloc(mem_ctx, struct tevent_immediate);
	if (im == NULL) return NULL;

	*im = (struct tevent_immediate) { .create_location = location };

	return im;
}

/*
  schedule an immediate event
*/
void _tevent_schedule_immediate(struct tevent_immediate *im,
				struct tevent_context *ev,
				tevent_immediate_handler_t handler,
				void *private_data,
				const char *handler_name,
				const char *location)
{
	ev->ops->schedule_immediate(im, ev, handler, private_data,
				    handler_name, location);
}

/*
  add a signal event

  sa_flags are flags to sigaction(2)

  return NULL on failure
*/
struct tevent_signal *_tevent_add_signal(struct tevent_context *ev,
					 TALLOC_CTX *mem_ctx,
					 int signum,
					 int sa_flags,
					 tevent_signal_handler_t handler,
					 void *private_data,
					 const char *handler_name,
					 const char *location)
{
	return ev->ops->add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data,
				   handler_name, location);
}

void tevent_loop_allow_nesting(struct tevent_context *ev)
{
	if (ev->wrapper.glue != NULL) {
		tevent_abort(ev, "tevent_loop_allow_nesting() on wrapper");
		return;
	}

	if (ev->wrapper.list != NULL) {
		tevent_abort(ev, "tevent_loop_allow_nesting() with wrapper");
		return;
	}

	ev->nesting.allowed = true;
}

void tevent_loop_set_nesting_hook(struct tevent_context *ev,
				  tevent_nesting_hook hook,
				  void *private_data)
{
	if (ev->nesting.hook_fn &&
	    (ev->nesting.hook_fn != hook ||
	     ev->nesting.hook_private != private_data)) {
		/* the way the nesting hook code is currently written
		   we cannot support two different nesting hooks at the
		   same time. */
		tevent_abort(ev, "tevent: Violation of nesting hook rules\n");
	}
	ev->nesting.hook_fn = hook;
	ev->nesting.hook_private = private_data;
}

static void tevent_abort_nesting(struct tevent_context *ev, const char *location)
{
	const char *reason;

	reason = talloc_asprintf(NULL, "tevent_loop_once() nesting at %s",
				 location);
	if (!reason) {
		reason = "tevent_loop_once() nesting";
	}

	tevent_abort(ev, reason);
}

/*
  do a single event loop using the events defined in ev
*/
int _tevent_loop_once(struct tevent_context *ev, const char *location)
{
	int ret;
	void *nesting_stack_ptr = NULL;

	ev->nesting.level++;

	if (ev->nesting.level > 1) {
		if (!ev->nesting.allowed) {
			tevent_abort_nesting(ev, location);
			errno = ELOOP;
			return -1;
		}
	}
	if (ev->nesting.level > 0) {
		if (ev->nesting.hook_fn) {
			int ret2;
			ret2 = ev->nesting.hook_fn(ev,
						   ev->nesting.hook_private,
						   ev->nesting.level,
						   true,
						   (void *)&nesting_stack_ptr,
						   location);
			if (ret2 != 0) {
				ret = ret2;
				goto done;
			}
		}
	}

	tevent_trace_point_callback(ev, TEVENT_TRACE_BEFORE_LOOP_ONCE);
	ret = ev->ops->loop_once(ev, location);
	tevent_trace_point_callback(ev, TEVENT_TRACE_AFTER_LOOP_ONCE);

	/* New event (and request) will always start with call depth 0. */
	tevent_thread_call_depth_set(0);

	if (ev->nesting.level > 0) {
		if (ev->nesting.hook_fn) {
			int ret2;
			ret2 = ev->nesting.hook_fn(ev,
						   ev->nesting.hook_private,
						   ev->nesting.level,
						   false,
						   (void *)&nesting_stack_ptr,
						   location);
			if (ret2 != 0) {
				ret = ret2;
				goto done;
			}
		}
	}

done:
	ev->nesting.level--;
	return ret;
}

/*
  this is a performance optimization for the samba4 nested event loop problems
*/
int _tevent_loop_until(struct tevent_context *ev,
		       bool (*finished)(void *private_data),
		       void *private_data,
		       const char *location)
{
	int ret = 0;
	void *nesting_stack_ptr = NULL;

	ev->nesting.level++;

	if (ev->nesting.level > 1) {
		if (!ev->nesting.allowed) {
			tevent_abort_nesting(ev, location);
			errno = ELOOP;
			return -1;
		}
	}
	if (ev->nesting.level > 0) {
		if (ev->nesting.hook_fn) {
			int ret2;
			ret2 = ev->nesting.hook_fn(ev,
						   ev->nesting.hook_private,
						   ev->nesting.level,
						   true,
						   (void *)&nesting_stack_ptr,
						   location);
			if (ret2 != 0) {
				ret = ret2;
				goto done;
			}
		}
	}

	while (!finished(private_data)) {
		tevent_trace_point_callback(ev, TEVENT_TRACE_BEFORE_LOOP_ONCE);
		ret = ev->ops->loop_once(ev, location);
		tevent_trace_point_callback(ev, TEVENT_TRACE_AFTER_LOOP_ONCE);
		if (ret != 0) {
			break;
		}
	}

	if (ev->nesting.level > 0) {
		if (ev->nesting.hook_fn) {
			int ret2;
			ret2 = ev->nesting.hook_fn(ev,
						   ev->nesting.hook_private,
						   ev->nesting.level,
						   false,
						   (void *)&nesting_stack_ptr,
						   location);
			if (ret2 != 0) {
				ret = ret2;
				goto done;
			}
		}
	}

done:
	ev->nesting.level--;
	return ret;
}

bool tevent_common_have_events(struct tevent_context *ev)
{
	if (ev->fd_events != NULL) {
		if (ev->fd_events != ev->wakeup_fde) {
			return true;
		}
		if (ev->fd_events->next != NULL) {
			return true;
		}

		/*
		 * At this point we just have the wakeup pipe event as
		 * the only fd_event. That one does not count as a
		 * regular event, so look at the other event types.
		 */
	}

	return ((ev->timer_events != NULL) ||
		(ev->immediate_events != NULL) ||
		(ev->signal_events != NULL));
}

/*
  return on failure or (with 0) if all fd events are removed
*/
int tevent_common_loop_wait(struct tevent_context *ev,
			    const char *location)
{
	/*
	 * loop as long as we have events pending
	 */
	while (tevent_common_have_events(ev)) {
		int ret;
		ret = _tevent_loop_once(ev, location);
		if (ret != 0) {
			tevent_debug(ev, TEVENT_DEBUG_FATAL,
				     "_tevent_loop_once() failed: %d - %s\n",
				     ret, strerror(errno));
			return ret;
		}
	}

	tevent_debug(ev, TEVENT_DEBUG_WARNING,
		     "tevent_common_loop_wait() out of events\n");
	return 0;
}

/*
  return on failure or (with 0) if all fd events are removed
*/
int _tevent_loop_wait(struct tevent_context *ev, const char *location)
{
	return ev->ops->loop_wait(ev, location);
}


/*
  re-initialise a tevent context. This leaves you with the same
  event context, but all events are wiped and the structure is
  re-initialised. This is most useful after a fork()

  zero is returned on success, non-zero on failure
*/
int tevent_re_initialise(struct tevent_context *ev)
{
	tevent_common_context_destructor(ev);

	tevent_common_context_constructor(ev);

	return ev->ops->context_init(ev);
}

static void wakeup_pipe_handler(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags, void *_private)
{
	ssize_t ret;

	do {
		/*
		 * This is the boilerplate for eventfd, but it works
		 * for pipes too. And as we don't care about the data
		 * we read, we're fine.
		 */
		uint64_t val;
		ret = read(fde->fd, &val, sizeof(val));
	} while (ret == -1 && errno == EINTR);
}

/*
 * Initialize the wakeup pipe and pipe fde
 */

int tevent_common_wakeup_init(struct tevent_context *ev)
{
	int ret, read_fd;

	if (ev->wakeup_fde != NULL) {
		return 0;
	}

#ifdef HAVE_EVENTFD
	ret = eventfd(0, EFD_NONBLOCK);
	if (ret == -1) {
		return errno;
	}
	read_fd = ev->wakeup_fd = ret;
#else
	{
		int pipe_fds[2];
		ret = pipe(pipe_fds);
		if (ret == -1) {
			return errno;
		}
		ev->wakeup_fd = pipe_fds[1];
		ev->wakeup_read_fd = pipe_fds[0];

		ev_set_blocking(ev->wakeup_fd, false);
		ev_set_blocking(ev->wakeup_read_fd, false);

		read_fd = ev->wakeup_read_fd;
	}
#endif

	ev->wakeup_fde = tevent_add_fd(ev, ev, read_fd, TEVENT_FD_READ,
				     wakeup_pipe_handler, NULL);
	if (ev->wakeup_fde == NULL) {
		close(ev->wakeup_fd);
#ifndef HAVE_EVENTFD
		close(ev->wakeup_read_fd);
#endif
		return ENOMEM;
	}

	return 0;
}

int tevent_common_wakeup_fd(int fd)
{
	ssize_t ret;

	do {
#ifdef HAVE_EVENTFD
		uint64_t val = 1;
		ret = write(fd, &val, sizeof(val));
#else
		char c = '\0';
		ret = write(fd, &c, 1);
#endif
	} while ((ret == -1) && (errno == EINTR));

	return 0;
}

int tevent_common_wakeup(struct tevent_context *ev)
{
	if (ev->wakeup_fde == NULL) {
		return ENOTCONN;
	}

	return tevent_common_wakeup_fd(ev->wakeup_fd);
}

static void tevent_common_wakeup_fini(struct tevent_context *ev)
{
	if (ev->wakeup_fde == NULL) {
		return;
	}

	TALLOC_FREE(ev->wakeup_fde);

	close(ev->wakeup_fd);
#ifndef HAVE_EVENTFD
	close(ev->wakeup_read_fd);
#endif
}
