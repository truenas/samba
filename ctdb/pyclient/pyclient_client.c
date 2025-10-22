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

#include "pyclient.h"

#if 0
typedef struct {
	PyObject_HEAD;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_node_map *nodemap;
	const char *ctdb_socket;
	uint32_t pnn;
	uint32_t target_pnn;
	uint32_t leader_pnn;
	uint64_t srvid;
	int timeout;
} py_ctdb_client_ctx;

#endif

#define SRVID_PY_CTDB	(CTDB_SRVID_TOOL_RANGE | 0x0001000000000000LL)

/* CTDB client getsetter functions */
static PyObject *py_ctdb_get_pnn(PyObject *self, void *closure);
static PyObject *py_ctdb_get_timeout(PyObject *self, void *closure);
static int py_ctdb_set_timeout(py_ctdb_client_ctx *self, PyObject *value, void *closure);
static PyObject *py_ctdb_get_target(PyObject *self, void *closure);
static int py_ctdb_set_target(py_ctdb_client_ctx *self, PyObject *value, void *closure);

/* CTDB client methods */
static PyObject *py_ctdb_status(PyObject *self, PyObject *args);
static PyObject *py_ctdb_recmaster(PyObject *self, PyObject *args);
static PyObject *py_ctdb_listnodes(PyObject *self, PyObject *args);
static PyObject *py_ctdb_dbmap(PyObject *self, PyObject *args);
static PyObject *py_ctdb_get_ips(PyObject *self, PyObject *args);
static PyObject *py_ctdb_getpid(PyObject *self, PyObject *args);
static PyObject *py_ctdb_getcaps(PyObject *self, PyObject *args);
static PyObject *py_ctdb_get_runstate(PyObject *self, PyObject *args);

/* CTDB client object functions */
static PyObject *py_ctdb_client_init(py_ctdb_client_ctx *self,
				     PyObject *args_unused,
				     PyObject *kwargs_unused)
{
	int err = 0;
	uint64_t srvid_offset;
	const char *errmsg = NULL;

	/*
	 * Create a new talloc context. Since there are no other talloc chunks
	 * using this we are safe to do without GIL and only taking lock if
	 * required for talloc leak check.
	 */
	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LEAK_LOCK()
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

	/* We should have all required info set up to create the ctdb client connection */
	if (errmsg == NULL) {
		err = ctdb_client_init(
			self->mem_ctx, self->ev, self->ctdb_socket, &self->client
        	);
		if (err) {
			errmsg = "ctdb_client_init() failed";
			errno = err;
		} else {
			self->pnn = ctdb_client_pnn(self->client);
			self->target_pnn = self->pnn;
			srvid_offset = getpid() & 0xFFFF;
			self->srvid = SRVID_PY_CTDB | (srvid_offset << 16);
			self->timeout = DEFAULT_TIMEOUT;
			self->leader_pnn = CTDB_UNKNOWN_PNN;
		}
	}

	if (err == 0) {
		/* We want to update the client information if leader changes */
		err = ctdb_client_set_message_handler(self->ev,
						      self->client,
						      CTDB_SRVID_LEADER,
						      leader_handler,
						      self);
		if (err) {
			errmsg = "ctdb_client_set_message_handler() failed";
			errno = err;
		} else {
			pthread_mutex_init(&self->client_lock);
		}
	}

	if (err) {
		TALLOC_FREE(self->mem_ctx);
	}

	PYCTDB_LEAK_UNLOCK()
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

static void py_ctdb_client_dealloc(py_ctdb_client_ctx *self)
{
	/*
	 * We'll drop GIL for TALLOC_FREE since the destructors involved may
	 * be involved and long-running.
	 */ 
	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(self)

	TALLOC_FREE(self->mem_ctx);

	PYCTDB_UNLOCK(self)
	Py_END_ALLOW_THREADS

	pthread_mutex_destroy(&self->client_lock);

	Py_TYPE(self)->tp_free((PyObject *)self);
}

/* CTDB client definitions */
static PyGetSetDef ctdb_client_getsetters[] = {
	{
		.name = discard_const_p(char, "pnn"),
		.get = (getter)py_ctdb_get_pnn,
	},
	{
		.name = discard_const_p(char, "timeout"),
		.get = (getter)py_ctdb_get_timeout,
		.set = (setter)py_ctdb_set_timeout,
	},
	{
		.name = discard_const_p(char, "target"),
		.get = (getter)py_ctdb_get_target,
		.set = (setter)py_ctdb_set_target,
	},
	{ .name = NULL }
};

static PyMethodDef ctdb_client_methods[] = {
	{
		.ml_name = "status",
		.ml_meth = py_ctdb_status,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Show node status"
	},
	{
		.ml_name = "listnodes",
		.ml_meth = py_ctdb_listnodes,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Show node list"
	},
	{
		.ml_name = "dbmap",
		.ml_meth = py_ctdb_dbmap,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Show attached databases"
	},
	{
		.ml_name = "ips",
		.ml_meth = py_ctdb_get_ips,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Show public ips"
	},
	{
		.ml_name = "pid",
		.ml_meth = py_ctdb_getpid,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Get CTDB process ID for node"
	},
	{
		.ml_name = "capabilities",
		.ml_meth = py_ctdb_getcaps,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Get CTDB node capabilities"
	},
	{
		.ml_name = "recmaster",
		.ml_meth = py_ctdb_recmaster,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Get CTDB cluster recovery master (deprecated)"
	},
	{
		.ml_name = "leader",
		.ml_meth = py_ctdb_recmaster,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Get CTDB cluster leader"
	},
	{
		.ml_name = "runstate",
		.ml_meth = py_ctdb_get_runstate,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Get CTDB node runstate"
	},
	{ NULL, NULL, 0, NULL }
};

PyTypeObject PyCtdbClient = {
	.tp_name = PYMODULE_NAME ".Client",
	.tp_basicsize = sizeof(py_ctdb_client_ctx),
	.tp_methods = ctdb_client_methods,
	.tp_getset = ctdb_client_getsetters,
	.tp_doc = "A CTDB client",
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_ctdb_client_init,
	.tp_dealloc = (destructor)py_ctdb_client_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};
