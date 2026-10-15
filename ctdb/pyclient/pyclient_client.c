/*
   CTDB python client

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/* Allow use of deprecated function tevent_loop_set_nesting_hook() */
#define TEVENT_DEPRECATED
#include "pyclient.h"
#include "pyclient_tables.h"

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#ifdef __linux__
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/tcp.h>
#endif

#define SRVID_PY_CTDB	(CTDB_SRVID_TOOL_RANGE | 0x0001000000000000LL)
#define DEFAULT_TIMEOUT 10
/*
 * Long enough for two recoveries in a row, each of which may be held off by
 * the default RerecoveryTimeout (10 seconds): one that was already due when
 * the recovery was asked for, then the forced one.
 */
#define RECOVER_DEFAULT_TIMEOUT 60
#define RECOVER_MAX_TIMEOUT 300
#define RECOVER_POLL_USEC 100000
/*
 * How long a new client waits to hear from the leader. This is the default
 * "leader timeout", which is how long the nodes themselves wait for it.
 */
#define LEADER_WAIT_SECS 5
unsigned leak_reporting_enabled;
unsigned glock_enabled;

PyMutex py_g_lock;

/*
 * Get nodemap allocated under python memory allocator. Does not require GIL,
 * but does require the client context lock being held
 */
static
int get_nodemap_internal(TALLOC_CTX *mem_ctx,
			 struct tevent_context *ev,
			 struct ctdb_client_context *client,
			 int target_node,
			 struct timeval timeout,
			 struct ctdb_node_and_flags **nodes_array,
			 uint32_t *node_cnt)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ctdb_node_map *nodemap = NULL;
	struct ctdb_node_and_flags *nodes = NULL;
	int err;

	if (tmp_ctx == NULL) {
		return -ENOMEM;
	}

	err = ctdb_ctrl_get_nodemap(tmp_ctx, ev, client, target_node,
				    timeout, &nodemap);
	if (err) {
		TALLOC_FREE(tmp_ctx);
		return err;
	}

	nodes = PyMem_RawCalloc(nodemap->num, sizeof(struct ctdb_node_and_flags));
	if (nodes == NULL) {
		TALLOC_FREE(tmp_ctx);
		return -ENOMEM;
	}

	memcpy(nodes, nodemap->node,
	       nodemap->num * sizeof( struct ctdb_node_and_flags));

	*node_cnt = nodemap->num;
	*nodes_array = nodes;
	TALLOC_FREE(tmp_ctx);
	return 0;
}

static
PyObject *py_node_flags_parse(uint32_t flags)
{
	PyObject *out = NULL;
	int i;

	out = PyList_New(0);
	if (out == NULL) {
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(node_flags_tbl); i++) {
		PyObject *pyflag;
		int rv;
		if ((flags & node_flags_tbl[i].val) == 0)
			continue;

		pyflag = PyUnicode_FromString(
			node_flags_tbl[i].name
		);
		if (pyflag == NULL) {
			Py_DECREF(out);
			return NULL;
		}
		rv = PyList_Append(out, pyflag);
		Py_DECREF(pyflag);
		if (rv == -1) {
			Py_DECREF(out);
			return NULL;
		}
	}

	return out;
}

static
PyObject *py_node(const struct ctdb_node_and_flags *node, int this_node)
{
	PyObject *out = NULL;
	PyObject *pyflags = NULL;
	char cip[128] = {0};
	int err;

	err = ctdb_sock_addr_to_buf(cip, sizeof(cip),
				    discard_const_p(ctdb_sock_addr, &node->addr),
				    true);
	if (err) {
		pyctdb_err(err, "Failed to parse ctdb socket address");
		return NULL;
	}

	pyflags = py_node_flags_parse(node->flags);
	if (pyflags == NULL)
		goto cleanup;

	out = Py_BuildValue(
		"{s:I,s:s,s:O,s:O}",
		"pnn", node->pnn,
		"address", cip,
		"flags", pyflags,
		"this_node", node->pnn == this_node ? Py_True : Py_False
	);

cleanup:
	Py_CLEAR(pyflags);
	return out;
}

static
PyObject *py_nodemap(const struct ctdb_node_map *nodemap, int this_node)
{
	PyObject *nodes_list = NULL;
	uint32_t i;

	if (nodemap->num == 0 || nodemap->node == NULL) {
		pyctdb_err(EINVAL, "nodemap not properly initialized");
		return NULL;
	}

	nodes_list = PyList_New(0);
	if (nodes_list == NULL) {
		return NULL;
	}

	for (i = 0; i < nodemap->num; i++) {
		PyObject *pynode = NULL;
		struct ctdb_node_and_flags *node = &nodemap->node[i];
		int rv;

		if (node->flags & NODE_FLAGS_DELETED)
			continue;

		pynode = py_node(node, this_node);
		if (pynode == NULL) {
			Py_DECREF(nodes_list);
			return NULL;
		}

		rv = PyList_Append(nodes_list, pynode);
		Py_DECREF(pynode);
		if (rv == -1) {
			Py_DECREF(nodes_list);
			return NULL;
		}

	}

	return nodes_list;
}

static void leader_handler(uint64_t srvid, TDB_DATA data, void *private_data)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)private_data;
	uint32_t leader_pnn;
	size_t np;
	int ret;

	ret = ctdb_uint32_pull(data.dptr, data.dsize, &leader_pnn, &np);
	if (ret != 0) {
		/* Ignore packet */
		return;
	}

	ctx->leader = leader_pnn;
}

/* What the wait for a leader in get_leader() ends on */
static bool leader_known(void *private_data)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)private_data;

	return ctx->leader != CTDB_UNKNOWN_PNN ||
	       _Py_atomic_load_uint(&ctx->disconnected);
}

/*
 * Get the leader as it was last announced to this client, CTDB_UNKNOWN_PNN
 * if it never was. Does not require GIL, but does require the client context
 * lock being held. A leader that has gone without a successor is still
 * reported: nothing announces that.
 *
 * The leader announces itself once a second and there is no other way to
 * find out who it is. Announcements are only read while a request runs the
 * client's event loop, so this has to be called after a request: the reply
 * to that came after every announcement that was waiting. A client that is
 * too new to have been sent one waits for it here.
 */
static
int get_leader(py_ctdb_client_ctx *ctx, uint32_t *leader)
{
	struct timespec now;
	double left;

	clock_gettime_mono(&now);
	left = LEADER_WAIT_SECS - timespec_elapsed2(&ctx->created, &now);
	if (ctx->leader == CTDB_UNKNOWN_PNN && left > 0) {
		/* This times out if there is no leader */
		ctdb_client_wait_func_timeout(
			ctx->ev, leader_known, ctx,
			timeval_current_ofs_msec(left * 1000 + 1));
	}

	if (_Py_atomic_load_uint(&ctx->disconnected)) {
		return ENOTCONN;
	}

	*leader = ctx->leader;
	return 0;
}

int py_ctdb_current_leader(py_ctdb_client_ctx *ctx, uint32_t *leader)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int num_clients;
	int err;

	Py_BEGIN_ALLOW_THREADS
	err = py_ctdb_client_lock(ctx);
	if (err == 0) {
		tmp_ctx = talloc_new(ctx->mem_ctx);
		if (tmp_ctx == NULL) {
			err = ENOMEM;
		}
	}

	if (err == 0) {
		/* The request that get_leader() has to follow */
		err = ctdb_ctrl_ping(tmp_ctx, ctx->ev, ctx->client, ctx->pnn,
				     TIMEOUT(ctx), &num_clients);
	}

	if (err == 0) {
		err = get_leader(ctx, leader);
	}
	TALLOC_FREE(tmp_ctx);
	py_ctdb_client_unlock(ctx);
	Py_END_ALLOW_THREADS

	if (err) {
		pyctdb_client_err(ctx, err, "Failed to get cluster leader");
	}

	return err;
}

/*
 * The connection to ctdbd has been closed or has failed. The client library
 * calls this in place of its default, which is exit().
 *
 * The library can not carry on after this. Requests that are waiting for a
 * reply never complete, and if the event loop runs once more it finds the
 * dead socket and aborts. So all that is done here is to make a note for
 * disconnected_loop_hook(), which stops the loop. The operation that was
 * running fails, and the next one connects again: see py_ctdb_client_lock().
 */
static void disconnect_handler(void *private_data)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)private_data;

	_Py_atomic_store_uint(&ctx->disconnected, 1);
}

/*
 * tevent calls this at the start and at the end of every turn of the
 * client's event loop. A failure at the start makes tevent_loop_once() fail
 * without having done anything, and that in turn makes the library give up
 * on whatever request it is waiting for and return an error.
 */
static int disconnected_loop_hook(struct tevent_context *ev,
				  void *private_data,
				  uint32_t level,
				  bool begin,
				  void *stack_ptr,
				  const char *location)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)private_data;

	if (begin && _Py_atomic_load_uint(&ctx->disconnected)) {
		return -1;
	}

	return 0;
}

/*
 * The hook is the only way that tevent has to keep a loop from running. It
 * is part of tevent's deprecated support for nested event loops, which are
 * not used here.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static void set_disconnected_loop_hook(py_ctdb_client_ctx *ctx)
{
	tevent_loop_set_nesting_hook(ctx->ev, disconnected_loop_hook, ctx);
}
#pragma GCC diagnostic pop

/*
 * Free what a client which has lost its connection still holds of it: the
 * library's client context, and with it the socket and the databases it
 * attached. Requires the client context lock being held, and nothing of
 * the client library to be in use.
 *
 * This is not only tidying up. The client has the local copies of its
 * databases open, and a ctdbd that is started again aborts when it comes to
 * attach a volatile database that another process still has open.
 */
static void drop_connection(py_ctdb_client_ctx *ctx)
{
	TALLOC_FREE(ctx->client);
}

/*
 * The watcher thread. A client only runs the library's event loop during an
 * operation, so one that is idle would not notice ctdbd going away until
 * its next operation, and would keep its databases open all that while.
 * That keeps a ctdbd that is started again from coming up: it aborts when
 * it attaches a volatile database that another process has open with
 * records in it.
 *
 * So this thread waits on a copy of the connection's socket for the other
 * end to close, and then marks the client disconnected and drops the
 * connection, unless an operation has found out first. It takes the client
 * lock for that and for picking up the socket, briefly, and nothing else:
 * no Python, and nobody waits for it with the lock held.
 */
static int poll_quietly(struct pollfd *fds, nfds_t nfds)
{
	int ret;

	do {
		ret = poll(fds, nfds, -1);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

static void *watch_connection(void *arg)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)arg;

	while (true) {
		struct pollfd fds[2];
		unsigned connection;
		uint64_t count;
		ssize_t nread;
		int fd;

		/* Wait to be given a connection, or to be told to go */
		fds[0] = (struct pollfd) {
			.fd = ctx->wake_fd, .events = POLLIN,
		};
		if (poll_quietly(fds, 1) < 0) {
			return NULL;
		}
		nread = read(ctx->wake_fd, &count, sizeof(count));
		if (nread < 0 && errno != EAGAIN) {
			return NULL;
		}
		if (_Py_atomic_load_uint(&ctx->watcher_exit)) {
			return NULL;
		}

		PYCTDB_LOCK(ctx);
		fd = ctx->watch_fd;
		ctx->watch_fd = -1;
		connection = ctx->connection;
		PYCTDB_UNLOCK(ctx);
		if (fd < 0) {
			continue;
		}

		fds[0] = (struct pollfd) { .fd = fd, .events = POLLRDHUP };
		fds[1] = (struct pollfd) {
			.fd = ctx->wake_fd, .events = POLLIN,
		};
		if (poll_quietly(fds, 2) < 0) {
			close(fd);
			return NULL;
		}
		close(fd);
		if (fds[1].revents != 0) {
			/* Something new: back to the top, which reads it */
			continue;
		}

		/* The other end has gone */
		PYCTDB_LOCK(ctx);
		if (ctx->connection == connection &&
		    !_Py_atomic_load_uint(&ctx->disconnected)) {
			_Py_atomic_store_uint(&ctx->disconnected, 1);
			drop_connection(ctx);
		}
		PYCTDB_UNLOCK(ctx);
	}
}

/* Give the watcher the connection. Requires the lock. */
static int watch_new_connection(py_ctdb_client_ctx *ctx)
{
	uint64_t one = 1;
	int fd;

	fd = fcntl(ctx->client->fd, F_DUPFD_CLOEXEC, 0);
	if (fd < 0) {
		return errno;
	}

	/* Not picked up yet: the watcher is still busy with the last one */
	if (ctx->watch_fd >= 0) {
		close(ctx->watch_fd);
	}
	ctx->watch_fd = fd;

	if (write(ctx->wake_fd, &one, sizeof(one)) < 0) {
		return errno;
	}

	return 0;
}

static int start_watcher(py_ctdb_client_ctx *ctx)
{
	sigset_t all, old;
	int err;

	/* Signals are for the interpreter's threads */
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &old);
	err = pthread_create(&ctx->watcher, NULL, watch_connection, ctx);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	if (err == 0) {
		ctx->watcher_pid = getpid();
	}

	return err;
}

/* Stop the watcher and wait for it. Not with the lock held. */
static void stop_watcher(py_ctdb_client_ctx *ctx)
{
	uint64_t one = 1;

	/* A process that forked inherited the thread's state, not the thread */
	if (ctx->watcher_pid == getpid()) {
		_Py_atomic_store_uint(&ctx->watcher_exit, 1);
		if (write(ctx->wake_fd, &one, sizeof(one)) == sizeof(one)) {
			pthread_join(ctx->watcher, NULL);
		}
	}
	ctx->watcher_pid = 0;
}

/*
 * Connect to ctdbd, on the client's event context, which is kept for the
 * life of the client. Requires the lock when the client is in use.
 */
static int connect_client(py_ctdb_client_ctx *ctx)
{
	int err;

	/* Or the loop hook keeps the connection from being made */
	_Py_atomic_store_uint(&ctx->disconnected, 0);

	err = ctdb_client_init(ctx->mem_ctx, ctx->ev, ctx->ctdb_socket,
			       &ctx->client);
	if (err != 0) {
		goto fail;
	}

	ctdb_client_set_disconnect_callback(ctx->client, disconnect_handler,
					    ctx);

	/* We want to update the client information if leader changes */
	err = ctdb_client_set_message_handler(ctx->ev, ctx->client,
					      CTDB_SRVID_LEADER, leader_handler,
					      ctx);
	if (err != 0) {
		TALLOC_FREE(ctx->client);
		goto fail;
	}

	ctx->pnn = ctdb_client_pnn(ctx->client);
	/* What is known of the cluster came over the old connection */
	ctx->leader = CTDB_UNKNOWN_PNN;
	clock_gettime_mono(&ctx->created);
	ctx->connection++;

	err = watch_new_connection(ctx);
	if (err != 0) {
		TALLOC_FREE(ctx->client);
		goto fail;
	}

	return 0;

fail:
	_Py_atomic_store_uint(&ctx->disconnected, 1);
	return err;
}

int py_ctdb_client_lock(py_ctdb_client_ctx *ctx)
{
	int err = 0;

	PYCTDB_LOCK(ctx);
	if (_Py_atomic_load_uint(&ctx->disconnected)) {
		drop_connection(ctx);
		err = connect_client(ctx);
		if (err != 0) {
			err = ENOTCONN;
		}
	}

	return err;
}

void py_ctdb_client_unlock(py_ctdb_client_ctx *ctx)
{
	/* The operation that is ending may be the one that found out */
	if (_Py_atomic_load_uint(&ctx->disconnected)) {
		drop_connection(ctx);
	}
	PYCTDB_UNLOCK(ctx);
}

/* CTDB client object functions */
static int py_ctdb_client_init(py_ctdb_client_ctx *self,
			       PyObject *args_unused,
			       PyObject *kwargs_unused)
{
	int err = 0;
	uint64_t srvid_offset;
	const char *errmsg = NULL;
	bool glocked;

	/*
	 * Create a new talloc context. Since there are no other talloc chunks
	 * using this we are safe to do without GIL and only taking lock if
	 * required for talloc leak check.
	 */
	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LEAK_LOCK(glocked);
	self->mem_ctx = talloc_new(NULL);
	if (self->mem_ctx == NULL) {
		errmsg = "talloc_new() failed";
		errno = ENOMEM;
	} else {
		self->ev = tevent_context_init(self->mem_ctx);
		if (self->ev == NULL) {
			errmsg = "tevent_context_init() failed";
			TALLOC_FREE(self->mem_ctx);
		} else {
			self->ctdb_socket = path_socket(self->mem_ctx, "ctdbd");
			if (self->ctdb_socket == NULL) {
				errmsg = "path_socket() for ctdb socket failed";
				TALLOC_FREE(self->mem_ctx);
			}
		}
	}

	if (errmsg == NULL) {
		self->wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (self->wake_fd < 0) {
			errmsg = "eventfd() failed";
			err = errno;
		}
	}

	/* We should have all required info set up to create the ctdb client connection */
	if (errmsg == NULL) {
		set_disconnected_loop_hook(self);
		err = connect_client(self);
		if (err) {
			errmsg = "ctdb_client_init() failed";
			errno = err;
		}
	}

	if (errmsg == NULL) {
		err = start_watcher(self);
		if (err) {
			errmsg = "Failed to start the connection watcher";
			errno = err;
		}
	}

	if (errmsg == NULL) {
		self->target_pnn = self->pnn;
		srvid_offset = getpid() & 0xFFFF;
		self->srvid = SRVID_PY_CTDB | (srvid_offset << 16);
		self->timeout = DEFAULT_TIMEOUT;
	} else {
		if (self->watch_fd >= 0) {
			close(self->watch_fd);
			self->watch_fd = -1;
		}
		if (self->wake_fd >= 0) {
			close(self->wake_fd);
			self->wake_fd = -1;
		}
		TALLOC_FREE(self->mem_ctx);
	}

	PYCTDB_LEAK_UNLOCK(glocked);
	Py_END_ALLOW_THREADS

	/*
	 * At this point we've reacquired the GIL and so it's safe to generate python
	 * errors
	 */

	if (err) {
		pyctdb_err(errno, errmsg);
		return -1;
	}

	return 0;
}

static PyObject *py_ctdb_client_new(PyTypeObject *type, PyObject *args,
				    PyObject *kwargs)
{
	py_ctdb_client_ctx *self;

	self = (py_ctdb_client_ctx *)type->tp_alloc(type, 0);
	if (self == NULL) {
		return NULL;
	}

	/* So that dealloc() knows them for not open before init() */
	self->wake_fd = -1;
	self->watch_fd = -1;

	return (PyObject *)self;
}

static
void py_ctdb_client_dealloc(py_ctdb_client_ctx *self)
{
	/*
	 * We'll drop GIL for TALLOC_FREE since the destructors involved may
	 * be involved and long-running.
	 */
	Py_BEGIN_ALLOW_THREADS
	/* Before taking the lock: the watcher may be waiting for it */
	stop_watcher(self);

	PYCTDB_LOCK(self);

	TALLOC_FREE(self->mem_ctx);

	PYCTDB_UNLOCK(self);

	if (self->watch_fd >= 0) {
		close(self->watch_fd);
	}
	if (self->wake_fd >= 0) {
		close(self->wake_fd);
	}
	PyMem_RawFree(self->nodemap_cached.node);
	Py_END_ALLOW_THREADS

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static
PyObject *py_ctdb_get_pnn(PyObject *self, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	return Py_BuildValue("I", ctx->pnn);
}

static
PyObject *py_ctdb_get_leader(PyObject *self, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	uint32_t leader;

	if (py_ctdb_current_leader(ctx, &leader) != 0) {
		return NULL;
	}

	return Py_BuildValue("I", leader);
}

static
PyObject *py_ctdb_get_timeout(PyObject *self, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	return Py_BuildValue("I", ctx->timeout);
}

static
int py_ctdb_set_timeout(py_ctdb_client_ctx *self,
			PyObject *value, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	long val;

	if (!PyLong_Check(value)) {
		PyErr_SetString(PyExc_TypeError,
				"Timeout must be an integer between 1 and 300");
		return -1;
	}

	val = PyLong_AsLong(value);
	if (val > 300 || val < 1) {
		if (PyErr_Occurred()) {
			return -1;
		}

		PyErr_SetString(PyExc_ValueError,
				"Timeout must be between 1 and 300");
		return -1;
	}

	ctx->timeout = val;
	return 0;
}

/* CTDB client definitions */
PyDoc_STRVAR(py_ctdb_pnn__doc__,
"pnn -> int\n"
"----------\n"
"The physical node number (PNN) of this CTDB client.\n"
);

PyDoc_STRVAR(py_ctdb_leader__doc__,
"leader -> int\n"
"-------------\n"
"The PNN of the current cluster leader node, 4294967295 if there is none.\n"
"\n"
"This is the node that last announced itself as the leader. Reading it\n"
"makes a request to the daemon, and a client that is less than 5 seconds\n"
"old waits for the first announcement if it has not had one yet.\n"
);

PyDoc_STRVAR(py_ctdb_timeout__doc__,
"timeout -> int\n"
"--------------\n"
"Timeout in seconds for CTDB operations (1-300).\n"
);

static PyGetSetDef ctdb_client_getsetters[] = {
	{
		.name = discard_const_p(char, "pnn"),
		.get = (getter)py_ctdb_get_pnn,
		.doc = py_ctdb_pnn__doc__,
	},
	{
		.name = discard_const_p(char, "leader"),
		.get = (getter)py_ctdb_get_leader,
		.doc = py_ctdb_leader__doc__,
	},
	{
		.name = discard_const_p(char, "timeout"),
		.get = (getter)py_ctdb_get_timeout,
		.set = (setter)py_ctdb_set_timeout,
		.doc = py_ctdb_timeout__doc__,
	},
	{ .name = NULL }
};

PyObject *py_ctdb_get_nodemap(py_ctdb_client_ctx *ctx, bool refresh)
{
	struct ctdb_node_and_flags *nodes = NULL;
	uint32_t num = 0;
	int err;

	if (ctx->nodemap_cached.node == NULL) {
		/* We've never initialized a nodemap and so need a fresh one */
		refresh = true;
	}

	if (refresh) {
		Py_BEGIN_ALLOW_THREADS
		err = py_ctdb_client_lock(ctx);
		if (err == 0) {
			err = get_nodemap_internal(ctx->mem_ctx,
						   ctx->ev,
						   ctx->client,
						   ctx->pnn,
						   TIMEOUT(ctx),
						   &nodes,
						   &num);
		}
		py_ctdb_client_unlock(ctx);
		Py_END_ALLOW_THREADS
		if (err) {
			pyctdb_client_err(ctx, err,
					  "Failed to refresh nodemap");
			return NULL;
		}

		/*
		 * The cached nodemap is only used with the GIL held, so it
		 * is replaced here rather than above.
		 */
		PyMem_RawFree(ctx->nodemap_cached.node);
		ctx->nodemap_cached.node = nodes;
		ctx->nodemap_cached.num = num;
	}

	return py_nodemap(&ctx->nodemap_cached, ctx->pnn);
}

static
PyObject *py_ctdb_nodemap(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	bool refresh = false;
	static char *kwlist[] = {"refresh", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|b", kwlist, &refresh)) {
		return NULL;
	}

	return py_ctdb_get_nodemap(ctx, refresh);
}

static
PyObject *py_ctdb_status(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	PyObject *pynodemap = NULL;
	PyObject *out = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	enum ctdb_runstate runstate;
	uint32_t leader = CTDB_UNKNOWN_PNN;
	int err, recmode;
	const char *errmsg = NULL;

	pynodemap = py_ctdb_get_nodemap(ctx, true);
	if (pynodemap == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	err = py_ctdb_client_lock(ctx);
	if (err == 0) {
		tmp_ctx = talloc_new(ctx->mem_ctx);
		if (tmp_ctx == NULL) {
			err = ENOMEM;
			errmsg = "Failed to allocate new memory context";
		}
	}

	if (err == 0) {
		err = ctdb_ctrl_get_recmode(tmp_ctx, ctx->ev, ctx->client,
					    ctx->target_pnn, TIMEOUT(ctx),
					    &recmode);
		if (err)
			errmsg = "Failed to get recovery mode";
	}

	if (err == 0) {
		err = ctdb_ctrl_get_runstate(tmp_ctx, ctx->ev, ctx->client,
					     ctx->target_pnn, TIMEOUT(ctx),
					     &runstate);
		if (err)
			errmsg = "Failed to get runstate";
	}

	if (err == 0) {
		err = get_leader(ctx, &leader);
	}
	TALLOC_FREE(tmp_ctx);
	py_ctdb_client_unlock(ctx);
	Py_END_ALLOW_THREADS

	if (err) {
		pyctdb_client_err(ctx, err, errmsg);
		Py_DECREF(pynodemap);
		return NULL;
	}

	out = Py_BuildValue(
		"{s:O,s:s,s:s,s:I}",
		"nodemap", pynodemap,
		"recovery_mode", recmode == CTDB_RECOVERY_NORMAL ? "NORMAL" : "RECOVERY",
		"state", ctdb_runstate_to_string(runstate),
		"leader_pnn", leader
	);
	Py_DECREF(pynodemap);
	return out;
}

PyDoc_STRVAR(py_ctdb_status__doc__,
"status() -> dict\n"
"----------------\n"
"Retrieve the current status of the CTDB cluster.\n"
"\n"
"Returns:\n"
"    A dictionary containing:\n"
"        nodemap: list of node information dictionaries\n"
"        recovery_mode: 'NORMAL' or 'RECOVERY'\n"
"        state: the cluster's run state\n"
"        leader_pnn: PNN of the cluster leader\n"
);

PyDoc_STRVAR(py_ctdb_nodemap__doc__,
"nodemap(refresh=False) -> list\n"
"-------------------------------\n"
"Retrieve the node map of the CTDB cluster.\n"
"\n"
"Args:\n"
"    refresh: If True, fetch fresh nodemap from cluster.\n"
"             If False, use cached nodemap (default).\n"
"\n"
"Returns:\n"
"    A list of dictionaries, each containing:\n"
"        pnn: physical node number\n"
"        address: node's network address\n"
"        flags: list of node flag strings\n"
"        this_node: boolean indicating if this is the local node\n"
);

static
PyObject *py_ctdb_get_db(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	const char *db_name = NULL;
	uint8_t db_flags = 0;
	int persistent = 1;
	int readonly = 0;
	int replicated = 0;
	int create_ok = 0;
	static char *kwlist[] = {
		"db_name", "persistent", "readonly", "replicated",
		"create_ok", NULL
	};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|pppp", kwlist,
					 &db_name, &persistent, &readonly,
					 &replicated, &create_ok)) {
		return NULL;
	}

	/* Build db_flags from boolean arguments */
	if (persistent) {
		db_flags |= CTDB_DB_FLAGS_PERSISTENT;
	}
	if (readonly) {
		db_flags |= CTDB_DB_FLAGS_READONLY;
	}
	if (replicated) {
		db_flags |= CTDB_DB_FLAGS_REPLICATED;
	}

	return py_get_or_create_db(ctx, db_name, db_flags, (bool)create_ok);
}

PyDoc_STRVAR(py_ctdb_get_db__doc__,
"get_db(db_name, persistent=True, readonly=False, replicated=False,\n"
"       create_ok=False) -> CtdbDB\n"
"-----------------------------------------------------------------------\n"
"Open or create a CTDB database.\n"
"\n"
"Args:\n"
"    db_name: Name of the database to open\n"
"    persistent: Database is persistent (default: True)\n"
"    readonly: Database is read-only (default: False)\n"
"    replicated: Database is replicated (default: False)\n"
"    create_ok: If True, create database if it doesn't exist (default: False)\n"
"\n"
"Returns:\n"
"    A CtdbDB object representing the opened database\n"
);

/*
 * Get the timeout for the next control of a recovery wait that began at
 * `start` and may take `timeout` seconds in total: the client timeout, or
 * the time left to wait if that is shorter. Returns false once the wait
 * has timed out.
 */
static
bool recover_ctl_timeout(py_ctdb_client_ctx *ctx,
			 const struct timespec *start,
			 uint32_t timeout,
			 struct timeval *ctl_timeout)
{
	struct timespec now;
	double left;
	uint32_t msecs;

	clock_gettime_mono(&now);
	left = (double)timeout - timespec_elapsed2(start, &now);
	if (left <= 0) {
		return false;
	}

	/* Rounded up, so that the wait is never cut short */
	msecs = MIN(left, (double)ctx->timeout) * 1000 + 1;
	*ctl_timeout = timeval_current_ofs_msec(msecs);
	return true;
}

/*
 * Read the generation and the recovery mode of the connected node. Does not
 * require GIL, but does require the client context lock being held.
 *
 * The generation is read first. A recovery makes the node ACTIVE before it
 * changes the generation, so if the mode is then NORMAL the generation is
 * not that of a recovery still in progress.
 */
static
int get_generation_and_recmode(py_ctdb_client_ctx *ctx,
			       TALLOC_CTX *mem_ctx,
			       struct timeval timeout,
			       uint32_t *generation,
			       int *recmode,
			       const char **errmsg)
{
	struct ctdb_vnn_map *vnnmap = NULL;
	int err;

	err = ctdb_ctrl_getvnnmap(mem_ctx, ctx->ev, ctx->client,
				  ctx->target_pnn, timeout, &vnnmap);
	if (err) {
		*errmsg = "Failed to get generation";
		return err;
	}
	*generation = vnnmap->generation;

	err = ctdb_ctrl_get_recmode(mem_ctx, ctx->ev, ctx->client,
				    ctx->target_pnn, timeout, recmode);
	if (err) {
		*errmsg = "Failed to get recovery mode";
	}

	return err;
}

/*
 * Force a recovery and wait for it to complete. Must be called without the
 * GIL and without the client context lock. The lock is only held while the
 * node is queried, so other threads can use the client during the wait.
 *
 * The node is settled when it is in NORMAL recovery mode with a valid
 * generation. The recovery is only requested from a settled node, because
 * one that is already running may have collected this node's records
 * before the caller's last changes to them. It is complete when the node
 * has settled again on a different generation.
 */
static
int py_ctdb_do_recover(py_ctdb_client_ctx *ctx, uint32_t timeout,
		       const char **errmsg)
{
	struct timespec start;
	uint32_t old_generation = INVALID_GENERATION;
	bool forced = false;

	clock_gettime_mono(&start);

	while (true) {
		TALLOC_CTX *tmp_ctx = NULL;
		struct timeval ctl_timeout;
		uint32_t generation = INVALID_GENERATION;
		int recmode = CTDB_RECOVERY_ACTIVE;
		bool settled = false;
		int err;

		if (!recover_ctl_timeout(ctx, &start, timeout, &ctl_timeout)) {
			*errmsg = forced ?
				"Timed out waiting for recovery to complete" :
				"Timed out waiting for node to leave recovery";
			return ETIMEDOUT;
		}

		err = py_ctdb_client_lock(ctx);
		if (err == 0) {
			tmp_ctx = talloc_new(ctx->mem_ctx);
			if (tmp_ctx == NULL) {
				err = ENOMEM;
				*errmsg = "Failed to allocate new memory "
					  "context";
			}
		}

		if (err == 0) {
			err = get_generation_and_recmode(ctx, tmp_ctx,
							 ctl_timeout,
							 &generation,
							 &recmode, errmsg);
		}

		if (err == 0) {
			settled = (recmode == CTDB_RECOVERY_NORMAL &&
				   generation != INVALID_GENERATION &&
				   generation != old_generation);
		}

		if (settled && !forced) {
			err = ctdb_ctrl_set_recmode(tmp_ctx, ctx->ev,
						    ctx->client,
						    ctx->target_pnn,
						    ctl_timeout,
						    CTDB_RECOVERY_ACTIVE);
			if (err) {
				*errmsg = "Failed to set recovery mode active";
			}
		}
		TALLOC_FREE(tmp_ctx);
		py_ctdb_client_unlock(ctx);

		if (err) {
			return err;
		}

		if (settled) {
			if (forced) {
				return 0;
			}
			old_generation = generation;
			forced = true;
		}

		usleep(RECOVER_POLL_USEC);
	}
}

static
PyObject *py_ctdb_recover(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	long timeout = RECOVER_DEFAULT_TIMEOUT;
	const char *errmsg = NULL;
	int err;
	static char *kwlist[] = {"timeout", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|l", kwlist,
					 &timeout)) {
		return NULL;
	}

	if (timeout < 1 || timeout > RECOVER_MAX_TIMEOUT) {
		PyErr_Format(PyExc_ValueError,
			     "Timeout must be between 1 and %d",
			     RECOVER_MAX_TIMEOUT);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	err = py_ctdb_do_recover(ctx, timeout, &errmsg);
	Py_END_ALLOW_THREADS

	if (err) {
		pyctdb_client_err(ctx, err, errmsg);
		return NULL;
	}

	Py_RETURN_NONE;
}

/*
 * This host's TCP connections with another node, found and destroyed through
 * the kernel's socket diagnostics interface, which is how `ss -K` does it.
 * ctdbd then finds its sockets gone and treats the node as disconnected at
 * once, instead of after its keepalives time out.
 *
 * A node is connected to another twice, once in each direction, and binds the
 * connection it makes to its own address. So from here the links with the
 * node are the established sockets whose remote address is the node's: the
 * one to its port, and the one from it to ours.
 */
#ifdef __linux__

#define NODE_LINKS_MAX 8

struct node_links {
	struct inet_diag_sockid id[NODE_LINKS_MAX];
	unsigned int num;
};

static int diag_request(int fd, uint16_t type, uint16_t flags,
			const struct inet_diag_req_v2 *req)
{
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 req;
	} msg = {
		.nlh = {
			.nlmsg_len = sizeof(msg),
			.nlmsg_type = type,
			.nlmsg_flags = flags,
		},
		.req = *req,
	};
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	ssize_t n;

	n = sendto(fd, &msg, sizeof(msg), 0, (struct sockaddr *)&kernel,
		   sizeof(kernel));
	if (n < 0) {
		return errno;
	}

	return 0;
}

static bool is_link_with(const struct inet_diag_msg *m,
			 const ctdb_sock_addr *addr,
			 unsigned int port, unsigned int own_port)
{
	const void *node_ip;
	size_t len;

	if (addr->sa.sa_family == AF_INET) {
		node_ip = &addr->ip.sin_addr;
		len = sizeof(addr->ip.sin_addr);
	} else {
		node_ip = &addr->ip6.sin6_addr;
		len = sizeof(addr->ip6.sin6_addr);
	}

	if (memcmp(m->id.idiag_dst, node_ip, len) != 0) {
		return false;
	}

	return ntohs(m->id.idiag_dport) == port ||
	       ntohs(m->id.idiag_sport) == own_port;
}

/* Find the links. The dump answers in as many messages as it takes. */
static int find_node_links(int fd, const ctdb_sock_addr *addr,
			   unsigned int port, unsigned int own_port,
			   struct node_links *links)
{
	struct inet_diag_req_v2 req = {
		.sdiag_family = addr->sa.sa_family,
		.sdiag_protocol = IPPROTO_TCP,
		.idiag_states = 1 << TCP_ESTABLISHED,
	};
	char buf[16384];
	int err;

	err = diag_request(fd, SOCK_DIAG_BY_FAMILY,
			   NLM_F_REQUEST | NLM_F_DUMP, &req);
	if (err != 0) {
		return err;
	}

	links->num = 0;
	while (true) {
		struct nlmsghdr *h;
		ssize_t n;

		n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			return errno;
		}
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, n);
		     h = NLMSG_NEXT(h, n)) {
			const struct inet_diag_msg *m;

			if (h->nlmsg_type == NLMSG_DONE) {
				return 0;
			}
			if (h->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *e = NLMSG_DATA(h);
				return e->error < 0 ? -e->error : EIO;
			}
			m = NLMSG_DATA(h);
			if (!is_link_with(m, addr, port, own_port)) {
				continue;
			}
			if (links->num == NODE_LINKS_MAX) {
				return E2BIG;
			}
			links->id[links->num++] = m->id;
		}
	}
}

/* Destroy one link. ENOENT when it is already gone. */
static int destroy_link(int fd, uint8_t family,
			const struct inet_diag_sockid *id)
{
	struct inet_diag_req_v2 req = {
		.sdiag_family = family,
		.sdiag_protocol = IPPROTO_TCP,
		.idiag_states = ~0U,
		.id = *id,
	};
	char buf[256];
	struct nlmsghdr *h;
	ssize_t n;
	int err;

	err = diag_request(fd, SOCK_DESTROY, NLM_F_REQUEST | NLM_F_ACK, &req);
	if (err != 0) {
		return err;
	}

	n = recv(fd, buf, sizeof(buf), 0);
	if (n < 0) {
		return errno;
	}
	h = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(h, n) || h->nlmsg_type != NLMSG_ERROR) {
		return EIO;
	}
	{
		const struct nlmsgerr *e = NLMSG_DATA(h);
		return -e->error;
	}
}

/* Destroy this host's links with the node. *count is how many were. */
static int destroy_node_links(const ctdb_sock_addr *addr, unsigned int port,
			      unsigned int own_port, int *count)
{
	struct node_links links;
	unsigned int i;
	int fd, err;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
	if (fd < 0) {
		return errno;
	}

	err = find_node_links(fd, addr, port, own_port, &links);
	if (err != 0) {
		close(fd);
		return err;
	}

	*count = 0;
	for (i = 0; i < links.num; i++) {
		err = destroy_link(fd, addr->sa.sa_family, &links.id[i]);
		if (err == 0) {
			(*count)++;
		} else if (err != ENOENT) {
			/* ctdbd may have closed it on seeing the first go */
			close(fd);
			return err;
		}
	}
	close(fd);

	return 0;
}

#else /* __linux__ */

static int destroy_node_links(const ctdb_sock_addr *addr, unsigned int port,
			      unsigned int own_port, int *count)
{
	return ENOSYS;
}

#endif /* __linux__ */

PyDoc_STRVAR(py_ctdb_disconnect_node__doc__,
"disconnect_node(pnn) -> int\n"
"---------------------------\n"
"Make this node's ctdbd treat node pnn as disconnected now.\n"
"\n"
"Destroys this host's TCP connections with that node, the way `ss -K`\n"
"does, through the kernel's socket diagnostics interface. ctdbd finds\n"
"its sockets gone, marks the node DISCONNECTED and recovers without\n"
"it, instead of waiting for its keepalives to time out. It reconnects\n"
"by itself, so a node that is in fact alive costs a reconnect and two\n"
"recoveries, nothing more. Returns the number of connections destroyed.\n"
"\n"
"Requires CAP_NET_ADMIN. Linux only.\n"
"\n"
"Args:\n"
"    pnn: The node, which may not be this one\n"
"\n"
"Raises:\n"
"    ValueError: pnn is this node, or there is no such node\n"
"    CTDBError: The node map could not be read, or the connections\n"
"        could not be destroyed. errno is EPERM without CAP_NET_ADMIN.\n"
);
static PyObject *py_ctdb_disconnect_node(PyObject *self, PyObject *args,
					 PyObject *kwargs)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	struct ctdb_node_map *nodemap = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	ctdb_sock_addr addr;
	unsigned int pnn, port = 0, own_port = 0;
	bool found = false;
	const char *errmsg = NULL;
	int count = 0;
	int err;
	static char *kwlist[] = {"pnn", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "I", kwlist, &pnn)) {
		return NULL;
	}

	if (pnn == ctx->pnn) {
		PyErr_SetString(PyExc_ValueError, "That is this node");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	err = py_ctdb_client_lock(ctx);
	if (err == 0) {
		tmp_ctx = talloc_new(ctx->mem_ctx);
		if (tmp_ctx == NULL) {
			err = ENOMEM;
			errmsg = "Failed to allocate new memory context";
		}
	}

	if (err == 0) {
		err = ctdb_ctrl_get_nodemap(tmp_ctx, ctx->ev, ctx->client,
					    ctx->pnn, TIMEOUT(ctx), &nodemap);
		if (err) {
			errmsg = "Failed to get nodemap";
		}
	}

	if (err == 0) {
		unsigned int i;

		for (i = 0; i < nodemap->num; i++) {
			struct ctdb_node_and_flags *node = &nodemap->node[i];

			if (node->pnn == pnn) {
				addr = node->addr;
				port = ctdb_sock_addr_port(&node->addr);
				found = true;
			} else if (node->pnn == ctx->pnn) {
				own_port = ctdb_sock_addr_port(&node->addr);
			}
		}
	}
	TALLOC_FREE(tmp_ctx);
	py_ctdb_client_unlock(ctx);

	/* Not under the lock: this is between us and the kernel */
	if (err == 0 && found) {
		err = destroy_node_links(&addr, port, own_port, &count);
		if (err) {
			errmsg = "Failed to destroy the connections with "
				 "the node";
		}
	}
	Py_END_ALLOW_THREADS

	if (err) {
		pyctdb_client_err(ctx, err, errmsg);
		return NULL;
	}

	if (!found) {
		PyErr_Format(PyExc_ValueError, "There is no node %u", pnn);
		return NULL;
	}

	return PyLong_FromLong(count);
}

PyDoc_STRVAR(py_ctdb_recover__doc__,
"recover(timeout=60) -> None\n"
"---------------------------\n"
"Force a database recovery and wait for it to complete.\n"
"\n"
"The recovery is requested through this node, as `ctdb recover` does.\n"
"If a recovery is already in progress then that one is waited for first,\n"
"so the recovery this method waits for always starts after the call.\n"
"On return this node is back in normal recovery mode with a new database\n"
"generation.\n"
"\n"
"Args:\n"
"    timeout: Maximum time to wait in seconds (1-300, default: 60)\n"
"\n"
"Raises:\n"
"    ValueError: If timeout is out of range\n"
"    CTDBError: If the operation fails. errno is ETIMEDOUT if the\n"
"        recovery did not complete in time. It may then still be\n"
"        pending or in progress.\n"
);

static PyMethodDef ctdb_client_methods[] = {
	{
		.ml_name = "status",
		.ml_meth = py_ctdb_status,
		.ml_flags = METH_NOARGS,
		.ml_doc = py_ctdb_status__doc__,
	},
	{
		.ml_name = "nodemap",
		.ml_meth = (PyCFunction)py_ctdb_nodemap,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_nodemap__doc__,
	},
	{
		.ml_name = "get_db",
		.ml_meth = (PyCFunction)py_ctdb_get_db,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_get_db__doc__,
	},
	{
		.ml_name = "recover",
		.ml_meth = (PyCFunction)py_ctdb_recover,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_recover__doc__,
	},
	{
		.ml_name = "disconnect_node",
		.ml_meth = (PyCFunction)py_ctdb_disconnect_node,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_disconnect_node__doc__,
	},
	{ NULL, NULL, 0, NULL }
};

PyTypeObject PyCtdbClient = {
	.tp_name = PYMODULE_NAME ".Client",
	.tp_basicsize = sizeof(py_ctdb_client_ctx),
	.tp_methods = ctdb_client_methods,
	.tp_getset = ctdb_client_getsetters,
	.tp_doc = "A CTDB client",
	.tp_new = py_ctdb_client_new,
	.tp_init = (initproc)py_ctdb_client_init,
	.tp_dealloc = (destructor)py_ctdb_client_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};
