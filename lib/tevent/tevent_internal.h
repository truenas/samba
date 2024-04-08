/*
   Unix SMB/CIFS implementation.

   generalised event loop handling

   INTERNAL STRUCTS. THERE ARE NO API GUARANTEES.
   External users should only ever have to include this header when
   implementing new tevent backends.

   Copyright (C) Stefan Metzmacher 2005-2009

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

struct tevent_req {
	/**
	 * @brief What to do on completion
	 *
	 * This is used for the user of an async request, fn is called when
	 * the request completes, either successfully or with an error.
	 */
	struct {
		/**
		 * @brief Completion function
		 * Completion function, to be filled by the API user
		 */
		tevent_req_fn fn;
		/**
		 * @brief Private data for the completion function
		 */
		void *private_data;
		/**
		 * @brief  The completion function name, for flow tracing.
		 */
		const char *fn_name;
	} async;

	/**
	 * @brief Private state pointer for the actual implementation
	 *
	 * The implementation doing the work for the async request needs to
	 * keep around current data like for example a fd event. The user of
	 * an async request should not touch this.
	 */
	void *data;

	/**
	 * @brief A function to overwrite the default print function
	 *
	 * The implementation doing the work may want to implement a
	 * custom function to print the text representation of the async
	 * request.
	 */
	tevent_req_print_fn private_print;

	/**
	 * @brief A function to cancel the request
	 *
	 * The implementation might want to set a function
	 * that is called when the tevent_req_cancel() function
	 * was called.
	 */
	struct {
		tevent_req_cancel_fn fn;
		const char *fn_name;
	} private_cancel;

	/**
	 * @brief A function to cleanup the request
	 *
	 * The implementation might want to set a function
	 * that is called before the tevent_req_done() and tevent_req_error()
	 * trigger the callers callback function.
	 */
	struct {
		tevent_req_cleanup_fn fn;
		const char *fn_name;
		enum tevent_req_state state;
	} private_cleanup;

	/**
	 * @brief Internal state of the request
	 *
	 * Callers should only access this via functions and never directly.
	 */
	struct {
		/**
		 * @brief The talloc type of the data pointer
		 *
		 * This is filled by the tevent_req_create() macro.
		 *
		 * This for debugging only.
		 */
		const char *private_type;

		/**
		 * @brief The location where the request was created
		 *
		 * This uses the __location__ macro via the tevent_req_create()
		 * macro.
		 *
		 * This for debugging only.
		 */
		const char *create_location;

		/**
		 * @brief The location where the request was finished
		 *
		 * This uses the __location__ macro via the tevent_req_done(),
		 * tevent_req_error() or tevent_req_nomem() macro.
		 *
		 * This for debugging only.
		 */
		const char *finish_location;

		/**
		 * @brief The location where the request was canceled
		 *
		 * This uses the __location__ macro via the
		 * tevent_req_cancel() macro.
		 *
		 * This for debugging only.
		 */
		const char *cancel_location;

		/**
		 * @brief The external state - will be queried by the caller
		 *
		 * While the async request is being processed, state will remain in
		 * TEVENT_REQ_IN_PROGRESS. A request is finished if
		 * req->state>=TEVENT_REQ_DONE.
		 */
		enum tevent_req_state state;

		/**
		 * @brief status code when finished
		 *
		 * This status can be queried in the async completion function. It
		 * will be set to 0 when everything went fine.
		 */
		uint64_t error;

		/**
		 * @brief the immediate event used by tevent_req_post
		 *
		 */
		struct tevent_immediate *trigger;

		/**
		 * @brief An event context which will be used to
		 *        defer the _tevent_req_notify_callback().
		 */
		struct tevent_context *defer_callback_ev;

		/**
		 * @brief the timer event if tevent_req_set_endtime was used
		 *
		 */
		struct tevent_timer *timer;

		/**
		 * @brief The place where profiling data is kept
		 */
		struct tevent_req_profile *profile;

		size_t call_depth;
	} internal;
};

struct tevent_req_profile {
	struct tevent_req_profile *prev, *next;
	struct tevent_req_profile *parent;
	const char *req_name;
	pid_t pid;
	const char *start_location;
	struct timeval start_time;
	const char *stop_location;
	struct timeval stop_time;
	enum tevent_req_state state;
	uint64_t user_error;
	struct tevent_req_profile *subprofiles;
};

struct tevent_fd {
	struct tevent_fd *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	int fd;
	uint16_t flags; /* see TEVENT_FD_* flags */
	tevent_fd_handler_t handler;
	tevent_fd_close_fn_t close_fn;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *location;
	/* this is private for the events_ops implementation */
	uint64_t additional_flags;
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
};

struct tevent_timer {
	struct tevent_timer *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	struct timeval next_event;
	tevent_timer_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *location;
	/* this is private for the events_ops implementation */
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
};

struct tevent_immediate {
	struct tevent_immediate *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	struct tevent_context *detach_ev_ctx;
	tevent_immediate_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *create_location;
	const char *schedule_location;
	/* this is private for the events_ops implementation */
	void (*cancel_fn)(struct tevent_immediate *im);
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
};

struct tevent_signal {
	struct tevent_signal *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	int signum;
	int sa_flags;
	tevent_signal_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *location;
	/* this is private for the events_ops implementation */
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
};

struct tevent_threaded_context {
	struct tevent_threaded_context *next, *prev;

#ifdef HAVE_PTHREAD
	pthread_mutex_t event_ctx_mutex;
#endif
	struct tevent_context *event_ctx;
};

struct tevent_debug_ops {
	enum tevent_debug_level max_level;
	void (*debug)(void *context, enum tevent_debug_level level,
		      const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3,0);
	void *context;
};

void tevent_debug(struct tevent_context *ev, enum tevent_debug_level level,
		  const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);
#define TEVENT_DEBUG(__ev, __level, __fmt, ...) do { \
	if (unlikely((__ev) != NULL && \
		     (__level) <= (__ev)->debug_ops.max_level)) \
	{ \
		tevent_debug((__ev), (__level), (__fmt), __VA_ARGS__); \
	} \
} while(0)

void tevent_abort(struct tevent_context *ev, const char *reason);

void tevent_common_check_double_free(TALLOC_CTX *ptr, const char *reason);

struct tevent_context {
	/* the specific events implementation */
	const struct tevent_ops *ops;

	/*
	 * The following three pointers are queried on every loop_once
	 * in the order in which they appear here. Not measured, but
	 * hopefully putting them at the top together with "ops"
	 * should make tevent a *bit* more cache-friendly than before.
	 */

	/* list of signal events - used by common code */
	struct tevent_signal *signal_events;

	/* List of threaded job indicators */
	struct tevent_threaded_context *threaded_contexts;

	/* list of immediate events - used by common code */
	struct tevent_immediate *immediate_events;

	/* list of fd events - used by common code */
	struct tevent_fd *fd_events;

	/* list of timed events - used by common code */
	struct tevent_timer *timer_events;

	/* List of scheduled immediates */
	pthread_mutex_t scheduled_mutex;
	struct tevent_immediate *scheduled_immediates;

	/* this is private for the events_ops implementation */
	void *additional_data;

	/* pipe hack used with signal handlers */
	struct tevent_fd *wakeup_fde;
	int wakeup_fd;		/* fd to write into */
#ifndef HAVE_EVENT_FD
	int wakeup_read_fd;
#endif

	/* debugging operations */
	struct tevent_debug_ops debug_ops;

	/* info about the nesting status */
	struct {
		bool allowed;
		uint32_t level;
		tevent_nesting_hook hook_fn;
		void *hook_private;
	} nesting;

	struct {
		struct {
			tevent_trace_callback_t callback;
			void *private_data;
		} point;

		struct {
			tevent_trace_fd_callback_t callback;
			void *private_data;
		} fde;

		struct {
			tevent_trace_signal_callback_t callback;
			void *private_data;
		} se;

		struct {
			tevent_trace_timer_callback_t callback;
			void *private_data;
		} te;

		struct {
			tevent_trace_immediate_callback_t callback;
			void *private_data;
		} im;

		struct {
			tevent_trace_queue_callback_t callback;
			void *private_data;
		} qe;
	} tracing;

	struct {
		/*
		 * This is used on the main event context
		 */
		struct tevent_wrapper_glue *list;

		/*
		 * This is used on the wrapper event context
		 */
		struct tevent_wrapper_glue *glue;
	} wrapper;

	/*
	 * an optimization pointer into timer_events
	 * used by used by common code via
	 * tevent_common_add_timer_v2()
	 */
	struct tevent_timer *last_zero_timer;

#ifdef HAVE_PTHREAD
	struct tevent_context *prev, *next;
#endif
};

int tevent_common_context_destructor(struct tevent_context *ev);
int tevent_common_loop_wait(struct tevent_context *ev,
			    const char *location);

struct tevent_common_fd_buf {
	char buf[128];
};

const char *tevent_common_fd_str(struct tevent_common_fd_buf *buf,
				 const char *description,
				 const struct tevent_fd *fde);

int tevent_common_fd_destructor(struct tevent_fd *fde);
struct tevent_fd *tevent_common_add_fd(struct tevent_context *ev,
				       TALLOC_CTX *mem_ctx,
				       int fd,
				       uint16_t flags,
				       tevent_fd_handler_t handler,
				       void *private_data,
				       const char *handler_name,
				       const char *location);
void tevent_common_fd_set_close_fn(struct tevent_fd *fde,
				   tevent_fd_close_fn_t close_fn);
uint16_t tevent_common_fd_get_flags(struct tevent_fd *fde);
void tevent_common_fd_set_flags(struct tevent_fd *fde, uint16_t flags);
int tevent_common_invoke_fd_handler(struct tevent_fd *fde, uint16_t flags,
				    bool *removed);

struct tevent_timer *tevent_common_add_timer(struct tevent_context *ev,
					     TALLOC_CTX *mem_ctx,
					     struct timeval next_event,
					     tevent_timer_handler_t handler,
					     void *private_data,
					     const char *handler_name,
					     const char *location);
struct tevent_timer *tevent_common_add_timer_v2(struct tevent_context *ev,
						TALLOC_CTX *mem_ctx,
					        struct timeval next_event,
					        tevent_timer_handler_t handler,
					        void *private_data,
					        const char *handler_name,
					        const char *location);
struct timeval tevent_common_loop_timer_delay(struct tevent_context *);
int tevent_common_invoke_timer_handler(struct tevent_timer *te,
				       struct timeval current_time,
				       bool *removed);

void tevent_common_schedule_immediate(struct tevent_immediate *im,
				      struct tevent_context *ev,
				      tevent_immediate_handler_t handler,
				      void *private_data,
				      const char *handler_name,
				      const char *location);
int tevent_common_invoke_immediate_handler(struct tevent_immediate *im,
					   bool *removed);
bool tevent_common_loop_immediate(struct tevent_context *ev);
void tevent_common_threaded_activate_immediate(struct tevent_context *ev);

bool tevent_common_have_events(struct tevent_context *ev);
int tevent_common_wakeup_init(struct tevent_context *ev);
int tevent_common_wakeup_fd(int fd);
int tevent_common_wakeup(struct tevent_context *ev);

struct tevent_signal *tevent_common_add_signal(struct tevent_context *ev,
					       TALLOC_CTX *mem_ctx,
					       int signum,
					       int sa_flags,
					       tevent_signal_handler_t handler,
					       void *private_data,
					       const char *handler_name,
					       const char *location);
int tevent_common_check_signal(struct tevent_context *ev);
void tevent_cleanup_pending_signal_handlers(struct tevent_signal *se);
int tevent_common_invoke_signal_handler(struct tevent_signal *se,
					int signum, int count, void *siginfo,
					bool *removed);

struct tevent_context *tevent_wrapper_main_ev(struct tevent_context *ev);

struct tevent_wrapper_ops;

struct tevent_wrapper_glue {
	struct tevent_wrapper_glue *prev, *next;
	struct tevent_context *wrap_ev;
	struct tevent_context *main_ev;
	bool busy;
	bool destroyed;
	const struct tevent_wrapper_ops *ops;
	void *private_state;
};

void tevent_wrapper_push_use_internal(struct tevent_context *ev,
				      struct tevent_wrapper_glue *wrapper);
void tevent_wrapper_pop_use_internal(const struct tevent_context *__ev_ptr,
				     struct tevent_wrapper_glue *wrapper);

bool tevent_standard_init(void);
bool tevent_poll_init(void);
bool tevent_poll_event_add_fd_internal(struct tevent_context *ev,
				       struct tevent_fd *fde);
bool tevent_poll_mt_init(void);
#ifdef HAVE_EPOLL
bool tevent_epoll_init(void);
void tevent_epoll_set_panic_fallback(struct tevent_context *ev,
			bool (*panic_fallback)(struct tevent_context *ev,
					       bool replay));
#endif

bool tevent_poll_aioctx_get(struct tevent_context *ev, void **aio_ctx);
bool tevent_poll_aioctx_set(struct tevent_context *ev, void *aio_ctx);

static inline void tevent_thread_call_depth_notify(
			enum tevent_thread_call_depth_cmd cmd,
			struct tevent_req *req,
			size_t depth,
			const char *fname)
{
	if (tevent_thread_call_depth_state_g.cb != NULL) {
		tevent_thread_call_depth_state_g.cb(
			tevent_thread_call_depth_state_g.cb_private,
			cmd,
			req,
			depth,
			fname);
	}
}
void tevent_thread_call_depth_set(size_t depth);

void tevent_trace_point_callback(struct tevent_context *ev,
				 enum tevent_trace_point);

void tevent_trace_fd_callback(struct tevent_context *ev,
			      struct tevent_fd *fde,
			      enum tevent_event_trace_point);

void tevent_trace_signal_callback(struct tevent_context *ev,
				  struct tevent_signal *se,
				  enum tevent_event_trace_point);

void tevent_trace_timer_callback(struct tevent_context *ev,
				 struct tevent_timer *te,
				 enum tevent_event_trace_point);

void tevent_trace_immediate_callback(struct tevent_context *ev,
				     struct tevent_immediate *im,
				     enum tevent_event_trace_point);

void tevent_trace_queue_callback(struct tevent_context *ev,
				 struct tevent_queue_entry *qe,
				 enum tevent_event_trace_point);
