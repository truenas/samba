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
#include "pyclient_tables.h"

#define SRVID_PY_CTDB	(CTDB_SRVID_TOOL_RANGE | 0x0001000000000000LL)
#define DEFAULT_TIMEOUT 10
unsigned leak_reporting_enabled;
unsigned glock_enabled;

/* There's only ever one leader and so we'll store this as a global */
uint32_t cluster_leader = CTDB_UNKNOWN_PNN;

pthread_mutex_t py_g_lock = PTHREAD_MUTEX_INITIALIZER;

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
	uint32_t leader_pnn;
	size_t np;
	int ret;

	ret = ctdb_uint32_pull(data.dptr, data.dsize, &leader_pnn, &np);
	if (ret != 0) {
		/* Ignore packet */
		return;
	}

	_Py_atomic_store_uint32(&cluster_leader, leader_pnn);
}

/* CTDB client object functions */
static int py_ctdb_client_init(py_ctdb_client_ctx *self,
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
	PYCTDB_LEAK_LOCK();
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
		}
	}

	if (err == 0) {
		/* We want to update the client information if leader changes */
		err = ctdb_client_set_message_handler(self->ev,
						      self->client,
						      CTDB_SRVID_LEADER,
						      leader_handler,
						      NULL);
		if (err) {
			errmsg = "ctdb_client_set_message_handler() failed";
			errno = err;
		} else {
			pthread_mutex_init(&self->client_lock, NULL);
		}
	}

	if (err) {
		TALLOC_FREE(self->mem_ctx);
	}

	PYCTDB_LEAK_UNLOCK();
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

static
void py_ctdb_client_dealloc(py_ctdb_client_ctx *self)
{
	/*
	 * We'll drop GIL for TALLOC_FREE since the destructors involved may
	 * be involved and long-running.
	 */
	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(self);

	TALLOC_FREE(self->mem_ctx);

	PYCTDB_UNLOCK(self);

	PyMem_RawFree(self->nodemap_cached.node);
	Py_END_ALLOW_THREADS

	pthread_mutex_destroy(&self->client_lock);

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
	uint32_t leader = _Py_atomic_load_uint32(&cluster_leader);
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
"The PNN of the current cluster leader node.\n"
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
	int err;

	if (ctx->nodemap_cached.node == NULL) {
		/* We've never initialized a nodemap and so need a fresh one */
		refresh = true;
	}

	if (refresh) {
		Py_BEGIN_ALLOW_THREADS
		PYCTDB_LOCK(ctx);
		err = get_nodemap_internal(ctx->mem_ctx,
					   ctx->ev,
					   ctx->client,
					   ctx->pnn,
					   TIMEOUT(ctx),
					   &ctx->nodemap_cached.node,
					   &ctx->nodemap_cached.num);
		PYCTDB_UNLOCK(ctx);
		Py_END_ALLOW_THREADS
		if (err) {
			pyctdb_err(err, "Failed to refresh nodemap");
			return NULL;
		}
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
	enum ctdb_runstate runstate;
	int err, recmode;
	const char *errmsg;

	pynodemap = py_ctdb_get_nodemap(ctx, true);
	if (pynodemap == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(ctx);
	err = ctdb_ctrl_get_recmode(ctx->mem_ctx, ctx->ev, ctx->client,
				    ctx->target_pnn, TIMEOUT(ctx), &recmode);
	if (err == 0) {
		err = ctdb_ctrl_get_runstate(ctx->mem_ctx, ctx->ev, ctx->client,
					     ctx->target_pnn, TIMEOUT(ctx), &runstate);
		if (err)
			errmsg = "Failed to get runstate";
	} else {
		errmsg = "Failed to get recovery mode";
	}
	PYCTDB_UNLOCK(ctx);
	Py_END_ALLOW_THREADS

	if (err) {
		pyctdb_err(err, errmsg);
		Py_DECREF(pynodemap);
		return NULL;
	}

	out = Py_BuildValue(
		"{s:O,s:s,s:s,s:I}",
		"nodemap", pynodemap,
		"recovery_mode", recmode == CTDB_RECOVERY_NORMAL ? "NORMAL" : "RECOVERY",
		"state", ctdb_runstate_to_string(runstate),
		"leader_pnn", _Py_atomic_load_uint32(&cluster_leader)
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
