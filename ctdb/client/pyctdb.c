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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/time.h"
#include "system/wait.h"
#include "system/dir.h"

#include <ctype.h>
#include <popt.h>
#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "version.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/smb_strtox.h"

#include <Python.h>
#include "python/py3compat.h"
#include "python/modules.h"
#include "common/db_hash.h"
#include "common/logging.h"
#include "common/path.h"
#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "protocol/protocol_util.h"
#include "common/system_socket.h"
#include "client/client.h"
#include "client/client_sync.h"
#include "common/tunable.h"


#ifndef PY_CHECK_TYPE
#define PY_CHECK_TYPE(type, var, fail) \
        if (!PyObject_TypeCheck(var, type)) {\
                PyErr_Format(PyExc_TypeError, __location__ ": Expected type '%s' for '%s' of type '%s'", (type)->tp_name, #var, Py_TYPE(var)->tp_name); \
                fail; \
        }
#endif

#define SRVID_PY_CTDB	(CTDB_SRVID_TOOL_RANGE | 0x0001000000000000LL)
#define TIMEOUT(ctx)	timeval_current_ofs(ctx->timeout, 0)
#define DEFAULT_TIMEOUT	10
#define DBFLAGS_ALL	0x0F

typedef struct {
	PyObject_HEAD;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_node_map *nodemap;
	const char *ctdb_socket;
	uint32_t pnn;
	uint32_t target_pnn;
	uint64_t srvid;
	int timeout;
} py_ctdb_client_ctx;

typedef struct {
	PyObject_HEAD;
	py_ctdb_client_ctx *client;
	struct ctdb_db_context *db;
	struct ctdb_transaction_handle *txh;
	bool txh_ro;
	char *db_name;
	uint32_t db_id;
	uint8_t db_flags;
	bool db_exists;
} py_ctdb_db_ctx;

typedef struct {
	PyObject_HEAD;
	PyObject *key;
	PyObject *val;
	struct ctdb_record_handle *hdl;
	py_ctdb_db_ctx *ctx; //back-pointer to our db-context
} py_ctdb_db_entry;

typedef struct {
	PyObject_HEAD;
	py_ctdb_client_ctx *client;
	uint32_t pnn;
	uint32_t flags;
	PyObject *sockaddr;
	PyObject *py_flags;
} py_ctdb_node;

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
static PyObject *py_ctdb_client_new(PyTypeObject *obj,
				    PyObject *args_unused,
				    PyObject *kwargs_unused);

static void py_ctdb_client_dealloc(py_ctdb_client_ctx *self);

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
		.ml_flags = METH_NOARGS,
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
		.ml_doc = "Get CTDB cluster recovery master"
	},
	{
		.ml_name = "runstate",
		.ml_meth = py_ctdb_get_runstate,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Get CTDB node runstate"
	},
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject PyCtdbClient = {
	.tp_name = "ctdb.Client",
	.tp_basicsize = sizeof(py_ctdb_client_ctx),
	.tp_methods = ctdb_client_methods,
	.tp_getset = ctdb_client_getsetters,
	.tp_doc = "A CTDB client",
	.tp_new = py_ctdb_client_new,
	.tp_dealloc = (destructor)py_ctdb_client_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

/* CTDB database object getsetter functions */
static PyObject *py_ctdb_db_exists(PyObject *self, void *closure);
static PyObject *py_ctdb_db_opened(PyObject *self, void *closure);
static PyObject *py_ctdb_db_txh(PyObject *self, void *closure);
static PyObject *py_ctdb_db_ro(PyObject *self, void *closure);
static PyObject *py_ctdb_db_dbid(PyObject *self, void *closure);
static PyObject *py_ctdb_db_flags(PyObject *self, void *closure);
static PyObject *py_ctdb_db_name(PyObject *self, void *closure);
static PyObject *py_ctdb_db_seqnum(PyObject *self, void *closure);

/* CTDB database object methods */
static PyObject *py_ctdb_attach(PyObject *self, PyObject *args);
static PyObject *py_ctdb_detach(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_fetch(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_store(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_delete(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_close(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_tx_start(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_tx_commit(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_tx_cancel(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_status(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_traverse(PyObject *self, PyObject *args);


/* CTDB database object functions */
static PyObject *py_ctdb_db_new(PyTypeObject *obj,
				PyObject *args_unused,
				PyObject *kwargs_unused);

static int py_ctdb_db_init(py_ctdb_db_ctx *self,
			   PyObject *args,
			   PyObject *kwargs_unused);

static void py_ctdb_db_dealloc(py_ctdb_db_ctx *self);

/* CTDB database definitions */
static PyGetSetDef ctdb_db_getsetters[] = {
	{
		.name = discard_const_p(char, "exists"),
		.get = (getter)py_ctdb_db_exists,
	},
	{
		.name = discard_const_p(char, "opened"),
		.get = (getter)py_ctdb_db_opened,
	},
	{
		.name = discard_const_p(char, "transaction"),
		.get = (getter)py_ctdb_db_txh,
	},
	{
		.name = discard_const_p(char, "readonly"),
		.get = (getter)py_ctdb_db_ro,
	},
	{
		.name = discard_const_p(char, "db_id"),
		.get = (getter)py_ctdb_db_dbid,
	},
	{
		.name = discard_const_p(char, "db_flags"),
		.get = (getter)py_ctdb_db_flags,
	},
	{
		.name = discard_const_p(char, "db_name"),
		.get = (getter)py_ctdb_db_name,
	},
	{
		.name = discard_const_p(char, "sequence_number"),
		.get = (getter)py_ctdb_db_seqnum,
	},
	{ .name = NULL }
};

static PyMethodDef ctdb_db_methods[] = {
	{
		.ml_name = "attach",
		.ml_meth = py_ctdb_attach,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Attach a database with specified flag."
	},
	{
		.ml_name = "detach",
		.ml_meth = py_ctdb_detach,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Detach a database."
	},
	{
		.ml_name = "close",
		.ml_meth = py_ctdb_db_close,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Close DB context"
	},
	{
		.ml_name = "fetch",
		.ml_meth = py_ctdb_db_fetch,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Fetch a databse entry by key. Returns entry object"
	},
	{
		.ml_name = "store",
		.ml_meth = py_ctdb_db_store,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Write data to specified key."
	},
	{
		.ml_name = "delete",
		.ml_meth = py_ctdb_db_delete,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Delete specified key."
	},
	{
		.ml_name = "start_transaction",
		.ml_meth = py_ctdb_db_tx_start,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Start a new database transaction."
	},
	{
		.ml_name = "commit_transaction",
		.ml_meth = py_ctdb_db_tx_commit,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Commit the currently active transaction"
	},
	{
		.ml_name = "cancel_transaction",
		.ml_meth = py_ctdb_db_tx_cancel,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Cancel the currently active transaction"
	},
	{
		.ml_name = "status",
		.ml_meth = py_ctdb_db_status,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Show database status."
	},
	{
		.ml_name = "traverse",
		.ml_meth = py_ctdb_db_traverse,
		.ml_flags = METH_VARARGS,
		.ml_doc = "traverse entries in database. "
			"Takes a callable and private state object "
			"Callable will be called for each entry and passed "
			"a ctdb.DBEntry object and the state object. "
			"Traversal may be stopped by returning Py_False from "
			"callable."
	},
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject PyCtdbDB = {
	.tp_name = "ctdb.Ctdb",
	.tp_basicsize = sizeof(py_ctdb_db_ctx),
	.tp_methods = ctdb_db_methods,
	.tp_getset = ctdb_db_getsetters,
	.tp_doc = "A CTDB database",
	.tp_new = py_ctdb_db_new,
	.tp_init = (initproc)py_ctdb_db_init,
	.tp_dealloc = (destructor)py_ctdb_db_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

/* CTDB database entry getsetters functions */
static PyObject *py_ctdb_db_entry_locked(PyObject *self, void *closure);
static PyObject *py_ctdb_db_entry_key(PyObject *self, void *closure);
static PyObject *py_ctdb_db_entry_val(PyObject *self, void *closure);

/* CTDB database entry methods */
static PyObject *py_ctdb_db_entry_unlock(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_entry_fetch(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_entry_store(PyObject *self, PyObject *args);
static PyObject *py_ctdb_db_entry_delete(PyObject *self, PyObject *args);

/* CTDB database entry object functions */
static PyObject *py_ctdb_db_entry_new(PyTypeObject *obj,
				      PyObject *args_unused,
				      PyObject *kwargs_unused);

static int py_ctdb_db_entry_init(py_ctdb_db_entry *self,
			         PyObject *args,
			         PyObject *kwargs_unused);

static void py_ctdb_db_entry_dealloc(py_ctdb_db_entry *self);


static PyGetSetDef ctdb_db_entry_getsetters[] = {
	{
		.name = discard_const_p(char, "locked"),
		.get = (getter)py_ctdb_db_entry_locked,
	},
	{
		.name = discard_const_p(char, "key"),
		.get = (getter)py_ctdb_db_entry_key,
	},
	{
		.name = discard_const_p(char, "value"),
		.get = (getter)py_ctdb_db_entry_val,
	},
	{ .name = NULL }
};

static PyMethodDef ctdb_db_entry_methods[] = {
	{
		.ml_name = "unlock",
		.ml_meth = py_ctdb_db_entry_unlock,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Unlock locked entry."
	},
	{
		.ml_name = "fetch",
		.ml_meth = py_ctdb_db_entry_fetch,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Write fetch current value of entry."
	},
	{
		.ml_name = "store",
		.ml_meth = py_ctdb_db_entry_store,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Write data to entry (replaces existing)."
	},
	{
		.ml_name = "delete",
		.ml_meth = py_ctdb_db_entry_delete,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Delete the entry."
	},
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject PyCtdbDBEntry = {
	.tp_name = "ctdb.CtdbDBEntry",
	.tp_basicsize = sizeof(py_ctdb_db_entry),
	.tp_methods = ctdb_db_entry_methods,
	.tp_getset = ctdb_db_entry_getsetters,
	.tp_doc = "CTDB database entry",
	.tp_new = py_ctdb_db_entry_new,
	.tp_init = (initproc)py_ctdb_db_entry_init,
	.tp_dealloc = (destructor)py_ctdb_db_entry_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

/* CTDB node getsetter functions */
static PyObject *py_ctdb_node_is_current(PyObject *self, void *closure);
static PyObject *py_ctdb_node_pnn(PyObject *self, void *closure);
static PyObject *py_ctdb_node_flags(PyObject *self, void *closure);
static PyObject *py_ctdb_node_addr(PyObject *self, void *closure);


/* CTDB node methods */
static PyObject *py_ctdb_node_ban(PyObject *self, PyObject *args);
static PyObject *py_ctdb_node_unban(PyObject *self, PyObject *args);
static PyObject *py_ctdb_node_enable(PyObject *self, PyObject *args);
static PyObject *py_ctdb_node_disable(PyObject *self, PyObject *args);
static PyObject *py_ctdb_node_rebalance(PyObject *self, PyObject *args);

/* CTDB database entry object functions */
static PyObject *py_ctdb_node_new(PyTypeObject *obj,
				  PyObject *args_unused,
				  PyObject *kwargs_unused);

static int py_ctdb_node_init(py_ctdb_node *self,
			     PyObject *args,
			     PyObject *kwargs_unused);

static void py_ctdb_node_dealloc(py_ctdb_node *self);

static PyGetSetDef ctdb_db_node_getsetters[] = {
	{
		.name = discard_const_p(char, "pnn"),
		.get = (getter)py_ctdb_node_pnn,
	},
	{
		.name = discard_const_p(char, "current_node"),
		.get = (getter)py_ctdb_node_is_current,
	},
	{
		.name = discard_const_p(char, "flags"),
		.get = (getter)py_ctdb_node_flags,
	},
	{
		.name = discard_const_p(char, "private_address"),
		.get = (getter)py_ctdb_node_addr,
	},
	{ .name = NULL }
};

static PyMethodDef ctdb_db_node_methods[] = {
	{
		.ml_name = "rebalance",
		.ml_meth = py_ctdb_node_rebalance,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Rebalance the node."
	},
	{
		.ml_name = "ban",
		.ml_meth = py_ctdb_node_ban,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Ban the node."
	},
	{
		.ml_name = "unban",
		.ml_meth = py_ctdb_node_unban,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Unban the node."
	},
	{
		.ml_name = "enable",
		.ml_meth = py_ctdb_node_enable,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Enable the node."
	},
	{
		.ml_name = "disable",
		.ml_meth = py_ctdb_node_disable,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Disable the node."
	},
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject PyCtdbNode = {
	.tp_name = "ctdb.CtdbNode",
	.tp_basicsize = sizeof(py_ctdb_db_entry),
	.tp_methods = ctdb_db_node_methods,
	.tp_getset = ctdb_db_node_getsetters,
	.tp_doc = "CTDB node",
	.tp_new = py_ctdb_node_new,
	.tp_init = (initproc)py_ctdb_node_init,
	.tp_dealloc = (destructor)py_ctdb_node_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static PyObject *py_ctdb_client_new(PyTypeObject *obj,
				    PyObject *args_unused,
				    PyObject *kwargs_unused)
{
	int err;
	uint64_t srvid_offset;
	py_ctdb_client_ctx *self = NULL;

	self = (py_ctdb_client_ctx *)obj->tp_alloc(obj, 0);
	if (self == NULL) {
		return NULL;
	}

	self->mem_ctx = talloc_new(NULL);
	if (self->mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	self->ev = tevent_context_init(self->mem_ctx);
	if (self->ev == NULL) {
		goto nomem;
	}

	self->ctdb_socket = path_socket(self->mem_ctx, "ctdbd");
	if (self->ctdb_socket == NULL) {
		goto nomem;
	}

	err = ctdb_client_init(
		self->mem_ctx, self->ev, self->ctdb_socket, &self->client
        );

	if (err) {
		TALLOC_FREE(self->mem_ctx);
		PyErr_Format(
			PyExc_RuntimeError,
			"%s: ctdb_client_init() failed: %s\n",
			self->ctdb_socket, strerror(abs(err))
		);
		return NULL;
	}

	self->pnn = ctdb_client_pnn(self->client);
	self->target_pnn = self->pnn;
	srvid_offset = getpid() & 0xFFFF;
	self->srvid = SRVID_PY_CTDB | (srvid_offset << 16);
	self->timeout = DEFAULT_TIMEOUT;

	return (PyObject *)self;

nomem:
	PyErr_NoMemory();
	TALLOC_FREE(self->mem_ctx);
	return NULL;
}

static void py_ctdb_client_dealloc(py_ctdb_client_ctx *self)
{
	TALLOC_FREE(self->mem_ctx);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static bool ctdb_get_tunables(TALLOC_CTX *mem_ctx,
			      py_ctdb_client_ctx *ctx,
			      struct ctdb_tunable_list **tun_list)
{
	int err;

	err = ctdb_ctrl_get_all_tunables(
		mem_ctx, ctx->ev, ctx->client, ctx->target_pnn,
		TIMEOUT(ctx), tun_list);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_ctrl_get_all_tunables() failed: %s\n",
			strerror(abs(err))
		);
		return false;
	}

	return true;
}

static bool ctdb_get_tunable(TALLOC_CTX *mem_ctx,
			     py_ctdb_client_ctx *ctx,
			     const char *tun,
			     uint32_t *value_out)
{
	int err;
	uint32_t tunval;

	err = ctdb_ctrl_get_tunable(
		mem_ctx, ctx->ev, ctx->client, ctx->target_pnn,
		TIMEOUT(ctx), tun, &tunval);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_ctrl_get_tunable() failed: %s\n",
			strerror(abs(err))
		);
		return false;
	}

	*value_out = tunval;
	return true;
}

static struct ctdb_node_and_flags *get_node_by_pnn(
					struct ctdb_node_map *nodemap,
					uint32_t pnn)
{
	unsigned int i;

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].pnn == pnn) {
			return &nodemap->node[i];
		}
	}
	return NULL;
}

/* Append a node to a node map with given address and flags */
static bool node_map_add(struct ctdb_node_map *nodemap,
			 const char *nstr, uint32_t flags)
{
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_node_and_flags *n = NULL;
	int ret;

	ret = ctdb_sock_addr_from_string(nstr, &addr, false);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", nstr);
		return false;
	}

	num = nodemap->num;
	nodemap->node = talloc_realloc(nodemap, nodemap->node,
				       struct ctdb_node_and_flags, num+1);
	if (nodemap->node == NULL) {
		return false;
	}

	n = &nodemap->node[num];
	n->addr = addr;
	n->pnn = num;
	n->flags = flags;

	nodemap->num = num+1;
	return true;
}

/* Read a nodes file into a node map */
static struct ctdb_node_map *ctdb_read_nodes_file(TALLOC_CTX *mem_ctx,
						  const char *nlist)
{
	char **lines;
	int nlines;
	int i;
	struct ctdb_node_map *nodemap;

	nodemap = talloc_zero(mem_ctx, struct ctdb_node_map);
	if (nodemap == NULL) {
		return NULL;
	}

	lines = file_lines_load(nlist, &nlines, 0, mem_ctx);
	if (lines == NULL) {
		return NULL;
	}

	while (nlines > 0 && strcmp(lines[nlines-1], "") == 0) {
		nlines--;
	}

	for (i=0; i<nlines; i++) {
		char *node = NULL;
		uint32_t flags;
		size_t len;

		node = lines[i];
		/* strip leading spaces */
		while((*node == ' ') || (*node == '\t')) {
			node++;
		}

		len = strlen(node);

		/* strip trailing spaces */
		while ((len > 1) &&
		       ((node[len-1] == ' ') || (node[len-1] == '\t')))
		{
			node[len-1] = '\0';
			len--;
		}

		if (len == 0) {
			continue;
		}
		if (*node == '#') {
			/* A "deleted" node is a node that is
			   commented out in the nodes file.  This is
			   used instead of removing a line, which
			   would cause subsequent nodes to change
			   their PNN. */
			flags = NODE_FLAGS_DELETED;
			node = discard_const("0.0.0.0");
		} else {
			flags = 0;
		}
		if (! node_map_add(nodemap, node, flags)) {
			talloc_free(lines);
			TALLOC_FREE(nodemap);
			return NULL;
		}
	}

	talloc_free(lines);
	return nodemap;
}

static struct ctdb_node_map *read_nodes_file(TALLOC_CTX *mem_ctx, uint32_t pnn)
{
	struct ctdb_node_map *nodemap;
	char nodes_list[PATH_MAX];

	const char *basedir = getenv("CTDB_BASE");
	if (basedir == NULL) {
		basedir = CTDB_ETCDIR;
	}
	snprintf(nodes_list, sizeof(nodes_list), "%s/nodes", basedir);
	nodemap = ctdb_read_nodes_file(mem_ctx, nodes_list);
	if (nodemap == NULL) {
		fprintf(stderr, "Failed to read nodes file \"%s\"\n",
			nodes_list);
		return NULL;
	}

	return nodemap;
}

/*
 * Get consistent nodemap information.
 *
 * If nodemap is already cached, use that. If not get it.
 * If the current node is BANNED, then get nodemap from "better" node.
 */
static struct ctdb_node_map *get_nodemap(py_ctdb_client_ctx *self, bool force)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct ctdb_node_map *nodemap = NULL;
	struct ctdb_node_and_flags *node =NULL;
	uint32_t current_node;
	int err;

	if (force) {
		TALLOC_FREE(self->nodemap);
	}

	tmp_ctx = talloc_new(self->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	current_node = self->pnn;

again:
	err = ctdb_ctrl_get_nodemap(tmp_ctx, self->ev, self->client,
				    current_node, TIMEOUT(self), &nodemap);

	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get nodemap from node: %u\n",
			current_node
		);
		goto failed;
	}

	node = get_node_by_pnn(nodemap, current_node);
	if (node->flags & NODE_FLAGS_BANNED) {
		/* Pick next node */
		do {
			current_node = (current_node + 1) % nodemap->num;
			node = get_node_by_pnn(nodemap, current_node);
			if (! (node->flags &
			      (NODE_FLAGS_DELETED|NODE_FLAGS_DISCONNECTED))) {
				break;
			}
		} while (current_node != self->pnn);

		if (current_node == self->pnn) {
			PyErr_Format(
				PyExc_RuntimeError,
				"All nodes are banned.\n"
			);
			goto failed;
		}

		goto again;
	}

	self->nodemap = talloc_steal(self->mem_ctx, nodemap);
	TALLOC_FREE(tmp_ctx);
	return nodemap;

failed:
	TALLOC_FREE(tmp_ctx);
	return NULL;
}

static PyObject *node_flags_to_list(uint32_t flags)
{
	static const struct {
		uint32_t flag;
		const char *name;
	} flag_names[] = {
		{ NODE_FLAGS_DISCONNECTED,	    "DISCONNECTED" },
		{ NODE_FLAGS_PERMANENTLY_DISABLED,  "DISABLED" },
		{ NODE_FLAGS_BANNED,		    "BANNED" },
		{ NODE_FLAGS_UNHEALTHY,		    "UNHEALTHY" },
		{ NODE_FLAGS_DELETED,		    "DELETED" },
		{ NODE_FLAGS_STOPPED,		    "STOPPED" },
		{ NODE_FLAGS_INACTIVE,		    "INACTIVE" },
	};

        PyObject *out = NULL;
	size_t i;
	int rv;

        out = Py_BuildValue("[]");
        if (out == NULL) {
                PyErr_NoMemory();
                return NULL;
        }

	for (i=0; i<ARRAY_SIZE(flag_names); i++) {
		PyObject *py_flag = NULL;

		if ((flags & flag_names[i].flag) == 0) {
			continue;
		}

		py_flag = Py_BuildValue("s", flag_names[i].name);
		if (py_flag == NULL) {
			Py_DECREF(out);
			PyErr_NoMemory();
			return NULL;
		}
		rv = PyList_Append(out, py_flag);
		Py_DECREF(py_flag);
		if (rv == -1) {
			Py_DECREF(out);
			PyErr_NoMemory();
			return NULL;
		}
	}

	return out;
}

static const char *pretty_print_flags(TALLOC_CTX *mem_ctx, uint32_t flags)
{
	static const struct {
		uint32_t flag;
		const char *name;
	} flag_names[] = {
		{ NODE_FLAGS_DISCONNECTED,	    "DISCONNECTED" },
		{ NODE_FLAGS_PERMANENTLY_DISABLED,  "DISABLED" },
		{ NODE_FLAGS_BANNED,		    "BANNED" },
		{ NODE_FLAGS_UNHEALTHY,		    "UNHEALTHY" },
		{ NODE_FLAGS_DELETED,		    "DELETED" },
		{ NODE_FLAGS_STOPPED,		    "STOPPED" },
		{ NODE_FLAGS_INACTIVE,		    "INACTIVE" },
	};
	char *flags_str = NULL;
	size_t i;

	for (i=0; i<ARRAY_SIZE(flag_names); i++) {
		if (flags & flag_names[i].flag) {
			if (flags_str == NULL) {
				flags_str = talloc_asprintf(mem_ctx,
						"%s", flag_names[i].name);
			} else {
				flags_str = talloc_asprintf_append(flags_str,
						"|%s", flag_names[i].name);
			}
			if (flags_str == NULL) {
				return "OUT-OF-MEMORY";
			}
		}
	}
	if (flags_str == NULL) {
		return "OK";
	}

	return flags_str;
}

static PyObject *partially_online(py_ctdb_client_ctx *ctdb,
				  struct ctdb_node_and_flags *node)
{
	struct ctdb_iface_list *iface_list;
	unsigned int i;
	int ret;
	bool status = false;

	if (node->flags != 0) {
		Py_RETURN_FALSE;
	}

	ret = ctdb_ctrl_get_ifaces(ctdb->mem_ctx, ctdb->ev, ctdb->client,
				   node->pnn, TIMEOUT(ctdb), &iface_list);
	if (ret != 0) {
		Py_RETURN_FALSE;
	}

	status = false;
	for (i=0; i < iface_list->num; i++) {
		if (iface_list->iface[i].link_state == 0) {
			status = true;
			break;
		}
	}

	TALLOC_FREE(iface_list);

	if (status) {
		Py_RETURN_TRUE;
	}

	Py_RETURN_FALSE;
}

static PyObject *py_ctdb_sock_addr(ctdb_sock_addr *addr,
				   bool with_port)
{
	PyObject *out = NULL;
	const char *addr_str = NULL;
	const char *addr_typ = NULL;
	char buf[INET6_ADDRSTRLEN+1];

	switch (addr->sa.sa_family) {
	case AF_INET:
		addr_str = inet_ntop(addr->ip.sin_family,
				     &addr->ip.sin_addr,
				     buf,
				     INET_ADDRSTRLEN);
		break;
	case AF_INET6:
		addr_str = inet_ntop(addr->ip6.sin6_family,
				     &addr->ip6.sin6_addr,
				     buf,
				     INET6_ADDRSTRLEN);
		break;
	default:
		errno = EAFNOSUPPORT;
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	if (addr_str == NULL) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	addr_typ = (addr->sa.sa_family == AF_INET) ? "INET" : "INET6";
	if (with_port) {

	} else {
		out = Py_BuildValue(
			"{s:s,s:s}",
			"type", addr_typ,
			"address", addr_str
		);
	}
	return out;
}

static PyObject *node_to_python(py_ctdb_client_ctx *ctx,
				struct ctdb_node_and_flags *node,
				bool to_dict)
{
	PyObject *py_node = NULL;
	PyObject *alias = NULL;
	PyObject *flags = NULL;
	PyObject *p_online = NULL;
	PyObject *this_node = NULL;


	alias = py_ctdb_sock_addr(&node->addr, false);
	if (alias == NULL) {
		return NULL;
	}

	flags = node_flags_to_list(node->flags);
	if (flags == NULL) {
		Py_DECREF(alias);
		return NULL;
	}

	if (!to_dict) {
		py_ctdb_node *entry = NULL;
		py_node = PyObject_CallFunction(
			(PyObject *)&PyCtdbNode, "O", ctx
		);
		if (py_node == NULL) {
			Py_DECREF(alias);
			Py_DECREF(flags);
			return NULL;
		}
		entry = (py_ctdb_node *)py_node;
		entry->pnn = node->pnn,
		entry->flags = node->flags,
		entry->py_flags = flags;
		entry->sockaddr = alias;
		return (PyObject *)entry;
	}

	this_node = (node->pnn == ctx->pnn) ? Py_True : Py_False;
	p_online =  partially_online(ctx, node);
	py_node = Py_BuildValue(
		"{s:I,s:O,s:O,s:I,s:O,s:O}",
		"pnn", node->pnn,
		"address", alias,
		"flags", flags,
		"flags_raw", node->flags,
		"partially_online", p_online,
		"this_node", this_node
	);

	Py_XDECREF(flags);
	Py_XDECREF(p_online);
	Py_XDECREF(alias);
	if (py_node == NULL) {
		return NULL;
	}
	Py_INCREF(this_node);
	return py_node;
}

static PyObject *nodemap_to_python(py_ctdb_client_ctx *ctx,
				   struct ctdb_node_map *nodemap,
				   bool to_dict)
{
	PyObject *out = NULL;
	PyObject *nodes = NULL;
	struct ctdb_node_and_flags *node = NULL;
	int num_deleted_nodes = 0;
	unsigned int i, rv;

	nodes = Py_BuildValue("[]");
	if (nodes == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < nodemap->num; i++) {
		PyObject *py_node = NULL;

		node = &nodemap->node[i];
		if (node->flags & NODE_FLAGS_DELETED) {
			num_deleted_nodes++;
			continue;
		}

		py_node = node_to_python(ctx, node, to_dict);
		if (py_node == NULL) {
			Py_DECREF(nodes);
			return NULL;
		}

		rv = PyList_Append(nodes, py_node);
		Py_DECREF(py_node);
		if (rv == -1) {
			Py_DECREF(nodes);
			PyErr_NoMemory();
			return NULL;
		}
	}

	out = Py_BuildValue(
		"{s:I,s:I,s:O}",
		"node_count", nodemap->num,
		"deleted_node_count", num_deleted_nodes,
		"nodes", nodes
	);
	Py_XDECREF(nodes);
	if (out == NULL) {
		Py_DECREF(nodes);
		PyErr_NoMemory();
		return NULL;
	}
	return out;
}

static PyObject *vnnmap_to_python(TALLOC_CTX *mem_ctx,
				  struct ctdb_vnn_map *vnnmap)
{
	PyObject *vnns = NULL;
	PyObject *out = NULL;
	int i, rv;

	vnns = PyList_New(vnnmap->size);
	if (vnns == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < vnnmap->size; i++) {
		PyObject *entry = NULL;
		entry = Py_BuildValue(
			"{s:I,s:I}",
			"hash", i,
			"lmaster", vnnmap->map[i]
		);

		if (entry == NULL) {
			Py_DECREF(vnns);
			PyErr_NoMemory();
			return NULL;
		}

		rv = PyList_SetItem(vnns, i, entry);
		if (rv == -1) {
			Py_DECREF(vnns);
			PyErr_NoMemory();
			return NULL;
		}
	}

	out = Py_BuildValue(
		"{s:I,s:I,s:O}",
		"size", vnnmap->size,
		"generation", vnnmap->generation,
		"entries", vnns
	);

	Py_XDECREF(vnns);
	if (out == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	return out;
}

static PyObject *py_ctdb_status(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	struct ctdb_node_map *nodemap = NULL;
	struct ctdb_vnn_map *vnnmap = NULL;
	PyObject *pynodes = NULL;
	PyObject *pyvnn = NULL;
	PyObject *out = NULL;
	int recmode;
	uint32_t recmaster;
	char *recmode_str;
	int err;

	nodemap = get_nodemap(ctx, false);
	if (nodemap == NULL) {
		return NULL;
	}

	pynodes = nodemap_to_python(ctx, nodemap, true);
	TALLOC_FREE(nodemap);
	if (pynodes == NULL) {
		return NULL;
	}

	err = ctdb_ctrl_getvnnmap(ctx->mem_ctx, ctx->ev, ctx->client,
				  ctx->target_pnn, TIMEOUT(ctx), &vnnmap);
	if (err) {
		Py_DECREF(pynodes);
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get vnnmap: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	pyvnn = vnnmap_to_python(ctx->mem_ctx, vnnmap);
	TALLOC_FREE(vnnmap);
	if (pyvnn == NULL) {
		Py_DECREF(pynodes);
		return NULL;
	}

	err = ctdb_ctrl_get_recmode(ctx->mem_ctx, ctx->ev, ctx->client,
				    ctx->target_pnn, TIMEOUT(ctx), &recmode);
	if (err != 0) {
		Py_DECREF(pynodes);
		Py_DECREF(pyvnn);
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get recmode: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	err = ctdb_ctrl_get_recmaster(ctx->mem_ctx, ctx->ev, ctx->client,
				      ctx->target_pnn, TIMEOUT(ctx), &recmaster);
	if (err != 0) {
		Py_DECREF(pynodes);
		Py_DECREF(pyvnn);
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get recmode: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	out = Py_BuildValue(
		"{s:O,s:O,s:i,s:s,s:I}",
		"nodemap", pynodes,
		"vnnmap", pyvnn,
		"recovery_mode_raw", recmode,
		"recovery_mode_str", recmode == CTDB_RECOVERY_NORMAL ? "NORMAL" : "RECOVERY",
		"recovery_master", recmaster
	);
	Py_XDECREF(pynodes);
	Py_XDECREF(pyvnn);
	if (out == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	return out;
}

static PyObject *py_ctdb_listnodes(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	PyObject *pynodes = NULL;
	struct ctdb_node_map *nodemap = NULL;

	nodemap = read_nodes_file(ctx->mem_ctx, CTDB_UNKNOWN_PNN);

	if (nodemap == NULL) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to read nodes file: %s\n",
			strerror(errno)
		);
		goto done;
	}

	pynodes = nodemap_to_python(ctx, nodemap, false);
	TALLOC_FREE(nodemap);
done:
	return pynodes;
}

static PyObject *py_dbmap_entry(TALLOC_CTX *mem_ctx,
				py_ctdb_client_ctx *ctdb,
				struct ctdb_dbid db)
{
	PyObject *out = NULL;
	const char *name = NULL;
	const char *path = NULL;
	const char *health = NULL;
	char dbid_str[12] = {0};
	int err;
	uint32_t db_id = db.db_id;
	uint8_t flags = db.flags;

	snprintf(dbid_str, sizeof(dbid_str), "0x%08x", db_id);
	err = ctdb_ctrl_get_dbname(mem_ctx, ctdb->ev, ctdb->client,
				   ctdb->target_pnn, TIMEOUT(ctdb), db_id,
				   &name);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_ctrl_get_dbname() failed: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	err = ctdb_ctrl_getdbpath(mem_ctx, ctdb->ev, ctdb->client,
				  ctdb->target_pnn, TIMEOUT(ctdb), db_id,
				  &path);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_ctrl_get_dbpath() failed: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	err = ctdb_ctrl_db_get_health(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->target_pnn, TIMEOUT(ctdb), db_id,
				      &health);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_ctrl_get_health() failed: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	out = Py_BuildValue(
		"{s:s,s:I,s:s,s:s,s:O,s:O,s:O,s:O,s:H,s:s}",
		"dbid", dbid_str,
		"dbid_raw", db_id,
		"name", name,
		"path", path,
		"persistent", (flags & CTDB_DB_FLAGS_PERSISTENT) ? Py_True : Py_False,
		"replicated", (flags & CTDB_DB_FLAGS_REPLICATED) ? Py_True : Py_False,
		"sticky", (flags & CTDB_DB_FLAGS_STICKY) ? Py_True : Py_False,
		"readonly", (flags & CTDB_DB_FLAGS_READONLY) ? Py_True : Py_False,
		"flags_raw", flags,
		"health", health ? health : "OK"
	);
	return out;
}

static PyObject *py_ctdb_dbmap(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	PyObject *out = NULL;
	PyObject *pydbmap = NULL;
	struct ctdb_dbid_map *dbmap = NULL;
	int err, i;
	TALLOC_CTX *tmp_ctx = NULL;

	tmp_ctx = talloc_new(ctx->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	err = ctdb_ctrl_get_dbmap(tmp_ctx, ctx->ev, ctx->client,
				  ctx->target_pnn, TIMEOUT(ctx), &dbmap);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get recmode: %s\n",
			strerror(abs(err))
		);
		goto done;
	}

	pydbmap = PyList_New(dbmap->num);
	if (pydbmap == NULL) {
		PyErr_NoMemory();
		goto done;
	}

	for (i = 0; i < dbmap->num; i++) {
		PyObject *entry = NULL;
		entry = py_dbmap_entry(tmp_ctx, ctx, dbmap->dbs[i]);
		if (entry == NULL) {
			Py_DECREF(dbmap);
			goto done;
		}

		err = PyList_SetItem(pydbmap, i, entry);
		if (err == -1) {
			Py_DECREF(entry);
			PyErr_NoMemory();
			goto done;
		}
	}

	out = Py_BuildValue(
		"{s:I,s:O}",
		"database_cnt", dbmap->num,
		"dbmap", pydbmap
	);

	Py_XDECREF(pydbmap);
done:
	TALLOC_FREE(tmp_ctx);
	return out;
}

static PyObject *py_ctdb_getpid(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;

	pid_t pid;
	int err;

	err = ctdb_ctrl_get_pid(ctx->mem_ctx, ctx->ev, ctx->client,
				ctx->target_pnn, TIMEOUT(ctx), &pid);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get CTDB PID: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	return Py_BuildValue("I", pid);
}

static PyObject *py_ctdb_getcaps(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	PyObject *out = NULL;
        uint32_t caps;
        int err;

        err = ctdb_ctrl_get_capabilities(ctx->mem_ctx, ctx->ev, ctx->client,
                                         ctx->target_pnn, TIMEOUT(ctx), &caps);
        if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get CTDB node capabilities: %s\n",
			strerror(abs(err))
		);
		return NULL;
        }

	out = Py_BuildValue(
		"{s:O,s:O,s:I}",
		"recmaster", (caps & CTDB_CAP_RECMASTER) ? Py_True : Py_False,
		"lmaster", (caps & CTDB_CAP_LMASTER) ? Py_True : Py_False,
		"raw", caps
	);
	if (out == NULL) {
		PyErr_NoMemory();
	}

	return out;
}

static PyObject *py_ctdb_recmaster(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	uint32_t recmaster = 0;
	int err;

	err = ctdb_ctrl_get_recmaster(ctx->mem_ctx, ctx->ev, ctx->client,
				      ctx->target_pnn, TIMEOUT(ctx), &recmaster);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get recmode: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}
	return Py_BuildValue("I", recmaster);
}

static PyObject *py_ctdb_get_runstate(PyObject *self, PyObject *args_unused)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	PyObject *out = NULL;
	enum ctdb_runstate runstate;
	int err;

	err = ctdb_ctrl_get_runstate(ctx->mem_ctx, ctx->ev, ctx->client,
				     ctx->target_pnn, TIMEOUT(ctx), &runstate);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get CTDB node runstate: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}

	out = Py_BuildValue(
		"{s:s,s:i}",
		"state", ctdb_runstate_to_string(runstate),
		"raw", runstate
	);
	if (out == NULL) {
		PyErr_NoMemory();
	}
	return out;
}

static int ctdb_public_ip_cmp(const void *a, const void *b)
{
	const struct ctdb_public_ip *ip_a = a;
	const struct ctdb_public_ip *ip_b = b;

	return ctdb_sock_addr_cmp(&ip_a->addr, &ip_b->addr);
}

static int collect_ips(uint8_t *keybuf, size_t keylen, uint8_t *databuf,
		       size_t datalen, void *private_data)
{
	struct ctdb_public_ip_list *ips = talloc_get_type_abort(
		private_data, struct ctdb_public_ip_list);
	struct ctdb_public_ip *ip;

	ip = (struct ctdb_public_ip *)databuf;
	ips->ip[ips->num] = *ip;
	ips->num += 1;

	return 0;
}

static int get_all_public_ips(py_ctdb_client_ctx *ctdb, TALLOC_CTX *mem_ctx,
			      struct ctdb_public_ip_list **out)
{
	struct ctdb_node_map *nodemap;
	struct ctdb_public_ip_list *ips;
	struct db_hash_context *ipdb;
	uint32_t *pnn_list;
	unsigned int j;
	int ret, count, i;

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	ret = db_hash_init(mem_ctx, "ips", 101, DB_HASH_COMPLEX, &ipdb);
	if (ret != 0) {
		ret = -EFAULT;
		goto failed;
	}

	count = list_of_active_nodes(nodemap, CTDB_UNKNOWN_PNN, mem_ctx,
				     &pnn_list);
	if (count <= 0) {
		ret = -EFAULT;
		goto failed;
	}

	for (i=0; i<count; i++) {
		ret = ctdb_ctrl_get_public_ips(mem_ctx, ctdb->ev, ctdb->client,
					       pnn_list[i], TIMEOUT(ctdb),
					       false, &ips);
		if (ret != 0) {
			goto failed;
		}

		for (j=0; j<ips->num; j++) {
			struct ctdb_public_ip ip;

			ip.pnn = ips->ip[j].pnn;
			ip.addr = ips->ip[j].addr;

			if (pnn_list[i] == ip.pnn) {
				/* Node claims IP is hosted on it, so
				 * save that information
				 */
				ret = db_hash_add(ipdb, (uint8_t *)&ip.addr,
						  sizeof(ip.addr),
						  (uint8_t *)&ip, sizeof(ip));
				if (ret != 0) {
					goto failed;
				}
			} else {
				/* Node thinks IP is hosted elsewhere,
				 * so overwrite with CTDB_UNKNOWN_PNN
				 * if there's no existing entry
				 */
				ret = db_hash_exists(ipdb, (uint8_t *)&ip.addr,
						     sizeof(ip.addr));
				if (ret == ENOENT) {
					ip.pnn = CTDB_UNKNOWN_PNN;
					ret = db_hash_add(ipdb,
							  (uint8_t *)&ip.addr,
							  sizeof(ip.addr),
							  (uint8_t *)&ip,
							  sizeof(ip));
					if (ret != 0) {
						goto failed;
					}
				}
			}
		}

		TALLOC_FREE(ips);
	}

	talloc_free(pnn_list);

	ret = db_hash_traverse(ipdb, NULL, NULL, &count);
	if (ret != 0) {
		ret = -ENOMEM;
		goto failed;
	}

	ips = talloc_zero(mem_ctx, struct ctdb_public_ip_list);
	if (ips == NULL) {
		ret = -ENOMEM;
		goto failed;
	}

	ips->ip = talloc_array(ips, struct ctdb_public_ip, count);
	if (ips->ip == NULL) {
		ret = -ENOMEM;
		goto failed;
	}

	ret = db_hash_traverse(ipdb, collect_ips, ips, &count);
	if (ret != 0) {
		ret = -ENOMEM;
		goto failed;
	}

	if ((unsigned int)count != ips->num) {
		ret = -ERANGE;
		goto failed;
	}

	*out = ips;

failed:
	TALLOC_FREE(nodemap);
	talloc_free(ipdb);
	return ret;
}

static PyObject *ipinfo_to_py(struct ctdb_public_ip_info *ipinfo)
{
	PyObject *interfaces = NULL;
	uint i;
	int err;

	if (ipinfo == NULL) {
		return PyList_New(0);
	}

	interfaces = PyList_New(ipinfo->ifaces->num);
	if (interfaces == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < ipinfo->ifaces->num; i++) {
		PyObject *entry = NULL;
		struct ctdb_iface *iface = &ipinfo->ifaces->iface[i];
		bool active, available;

		active = (ipinfo->active_idx == i) ? true : false;
		available = (iface->link_state == 0) ? false : true;

		entry = Py_BuildValue(
			"{s:s,s:O,s:O}",
			"name", iface->name,
			"active", active ? Py_True : Py_False,
			"available", available ? Py_True : Py_False
		);

		err = PyList_SetItem(interfaces, i, entry);
		if (err == -1) {
			Py_DECREF(entry);
			Py_DECREF(interfaces);
			PyErr_NoMemory();
			return NULL;
		}
	}

	return interfaces;
}

static PyObject *ips_to_py(TALLOC_CTX *mem_ctx,
			   py_ctdb_client_ctx *ctx,
			   struct ctdb_public_ip_list *ips,
			   struct ctdb_public_ip_info **ipinfo)
{
	PyObject *nodes = NULL;
	int err;
	unsigned int i;

	nodes = PyList_New(ips->num);
	if (nodes == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < ips->num; i++) {
		PyObject *entry = NULL;
		PyObject *py_ifaces = NULL;
		PyObject *alias = NULL;
		char *a = NULL;

		a = ctdb_sock_addr_to_string(mem_ctx, &ips->ip[i].addr, false);

		py_ifaces = ipinfo_to_py(ipinfo[i]);
		if (py_ifaces == NULL) {
			Py_DECREF(nodes);
			return NULL;
		}

		alias = py_ctdb_sock_addr(&ips->ip->addr, false);
		if (alias == NULL) {
			return NULL;
		}

		entry = Py_BuildValue(
			"{s:s,s:O,s:I,s:O}",
			"public_ip", a,
			"alias", alias,
			"pnn", ips->ip[i].pnn,
			"interfaces", py_ifaces
		);

		Py_XDECREF(alias);
		Py_XDECREF(py_ifaces);

		if (entry == NULL) {
			Py_DECREF(nodes);
			Py_DECREF(py_ifaces);
			PyErr_NoMemory();
			return NULL;
		}

		err = PyList_SetItem(nodes, i, entry);
		if (err == -1) {
			Py_DECREF(nodes);
			PyErr_NoMemory();
			return NULL;
		}
	}

	return nodes;
}

static PyObject *py_ctdb_get_ips(PyObject *self, PyObject *args)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	struct ctdb_public_ip_list *ips = NULL;
	struct ctdb_public_ip_info **ipinfo;
	PyObject *out = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	bool all = false;
	int err;
	uint32_t i;

	if (!PyArg_ParseTuple(args, "|b", &all)) {
		return NULL;
	}

	tmp_ctx = talloc_new(ctx->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (all) {
		err = get_all_public_ips(ctx, tmp_ctx, &ips);
	} else {
		err = ctdb_ctrl_get_public_ips(tmp_ctx, ctx->ev, ctx->client,
					       ctx->target_pnn, TIMEOUT(ctx),
					       false, &ips);
	}
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to get CTDB public ip information: %s\n",
			strerror(abs(err))
		);
		goto done;
	}

	ipinfo = talloc_array(tmp_ctx, struct ctdb_public_ip_info *, ips->num);
	if (ipinfo == NULL) {
		PyErr_NoMemory();
		goto done;
	}

	for (i = 0; i < ips->num; i++) {
		uint32_t pnn;
		if (all) {
			pnn = ips->ip[i].pnn;
		} else {
			pnn = ctx->target_pnn;
		}
		if (pnn == CTDB_UNKNOWN_PNN) {
			ipinfo[i] = NULL;
			continue;
		}
		err = ctdb_ctrl_get_public_ip_info(tmp_ctx, ctx->ev,
						   ctx->client, pnn,
						   TIMEOUT(ctx), &ips->ip[i].addr,
						   &ipinfo[i]);
		if (err != 0) {
			PyErr_Format(
				PyExc_RuntimeError,
				"%d: ctrl_get_public_ip_info() failed: %s\n",
				pnn, strerror(abs(err))
			);
			goto done;
		}
	}

	out = ips_to_py(tmp_ctx, ctx, ips, ipinfo);
done:
	TALLOC_FREE(tmp_ctx);
	return out;
}

static PyObject *py_ctdb_get_pnn(PyObject *self, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	return Py_BuildValue("I", ctx->pnn);
}

static PyObject *py_ctdb_get_timeout(PyObject *self, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	return Py_BuildValue("I", ctx->timeout);
}

static int py_ctdb_set_timeout(py_ctdb_client_ctx *self, PyObject *value, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	long val;

	PY_CHECK_TYPE(&PyLong_Type, value, return -1);

	val = PyLong_AsLong(value);
	if (val > 300 || val < 1) {
		PyErr_Format(
			PyExc_ValueError,
			"Timeout must be between 1 second and 300 seconds\n"
		);
		return -1;
	}

	ctx->timeout = val;
	return 0;
}

static PyObject *py_ctdb_get_target(PyObject *self, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	return Py_BuildValue("I", ctx->target_pnn);
}

static int py_ctdb_set_target(py_ctdb_client_ctx *self, PyObject *value, void *closure)
{
	py_ctdb_client_ctx *ctx = (py_ctdb_client_ctx *)self;
	struct ctdb_node_map *nodemap = NULL;
	bool found = false;
	long val;
	uint32_t i;

	PY_CHECK_TYPE(&PyLong_Type, value, return -1);

	val = PyLong_AsLong(value);
	if (val >= CTDB_UNKNOWN_PNN || val < 0) {
		PyErr_Format(
			PyExc_ValueError,
			"Target PNN is invalid\n"
		);
		return -1;
	}

	nodemap = get_nodemap(ctx, false);
	if (nodemap == NULL) {
		return -1;
	}

	for (i = 0; i < nodemap->num; i++) {
		if (nodemap->node[i].pnn == (uint32_t)val) {
			found = true;
			break;
		}
	}

	if (!found) {
		PyErr_Format(
			PyExc_ValueError,
			"%ld: Target PNN does not exist\n",
			val
		);
		TALLOC_FREE(nodemap);
		return -1;
	}

	if (nodemap->node[i].flags &
	    (NODE_FLAGS_DISCONNECTED | NODE_FLAGS_DELETED)) {
		PyErr_Format(
			PyExc_ValueError,
			"%ld: Target PNN has status: 0x%08x\n",
			val, nodemap->node[i].flags
		);
		TALLOC_FREE(nodemap);
		return -1;
	}

	TALLOC_FREE(nodemap);
	ctx->target_pnn = val;
	return 0;
}

/*
 * TDB Entry python handling
 */
static TDB_DATA PyBytes_AsTDB_DATA(PyObject *data)
{
	/*
	 * returned TDB_DATA points to same buffer
	 * as python object. Python will handle frees
	 */
	TDB_DATA ret = {
		.dptr = (unsigned char *)PyBytes_AsString(data),
		.dsize = PyBytes_Size(data)
	};
	return ret;
}

static PyObject *PyBytes_FromTDB_DATA(TDB_DATA data)
{
	/*
	 * Python allocates memory for copy of data.
	 * It is responsibility of caller here to free
	 * original data.dptr (if needed)
	 */
	if (data.dptr == NULL && data.dsize == 0) {
		Py_RETURN_NONE;
	}

	PyObject *out = PyBytes_FromStringAndSize(
		(const char *)data.dptr,
		data.dsize
	);

	return out;
}

static PyObject *pytdb_copy(PyObject *pytdb)
{
	TDB_DATA data;
	if (pytdb == Py_None) {
		Py_RETURN_NONE;
	}

	data = PyBytes_AsTDB_DATA(pytdb);
	return PyBytes_FromTDB_DATA(data);
}

static bool validate_op(py_ctdb_db_ctx *ctx, bool is_volatile, bool is_rw)
{
	if (ctx->db == NULL) {
		PyErr_SetString(
			PyExc_ValueError,
			"CTDB database handle is closed. "
			"DB must be reattached prior to "
			"starting a transaction"
		);
		return false;
	}

	if ((ctx->txh == NULL) && !is_volatile) {
		PyErr_SetString(
			PyExc_ValueError,
			"CTDB transaction must be started prior. "
			"to operation on non-volatile database "
			"starting a transaction"
		);
		return false;
	}

	if (is_rw && ctx->txh_ro) {
		PyErr_SetString(
			PyExc_PermissionError,
			"Cannot write to readonly CTDB database handle."
		);
		return false;
	}

	return true;
}

static bool ctdb_db_fetch(TALLOC_CTX *mem_ctx,
			  py_ctdb_db_ctx *ctx,
			  TDB_DATA key_in,
			  TDB_DATA *out,
			  struct ctdb_record_handle **pphdl)
{
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	TDB_DATA val;
	bool is_volatile = false;
	int err;


	if ((ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) == 0) {
		is_volatile = true;
	}

	if (!validate_op(ctx, is_volatile, false)) {
		return false;
	}

	if (is_volatile) {
		err = ctdb_fetch_lock(mem_ctx, cl_ctx->ev, cl_ctx->client,
				      ctx->db, key_in, ctx->txh_ro, pphdl,
				      NULL, &val);
		if (err) {
			PyErr_Format(
				PyExc_RuntimeError,
				"ctdb_fetch_lock() failed: %s",
				strerror(abs(err))
			);
			return false;
		}
	} else {
		err = ctdb_transaction_fetch_record(ctx->txh, key_in, mem_ctx, &val);
		if (err) {
			PyErr_Format(
				PyExc_RuntimeError,
				"ctdb_transaction_fetch_record() failed: %s. "
				"Cancelled transaction.",
				strerror(abs(err))
			);
			ctdb_transaction_cancel(ctx->txh);
			ctx->txh = NULL;
			return false;
		}
	}
	out->dptr = val.dptr;
	out->dsize = val.dsize;
	return true;
}

static bool ctdb_db_store(py_ctdb_db_ctx *ctx,
			  TDB_DATA key,
			  TDB_DATA data,
			  struct ctdb_record_handle *hdl)
{
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	TDB_DATA val;
	bool is_volatile = false;
	int err;

	if ((ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) == 0) {
		is_volatile = true;
	}

	if (!validate_op(ctx, is_volatile, true)) {
		return false;
	}

	if (is_volatile) {
		if (hdl == NULL) {
			PyErr_SetString(
				PyExc_ValueError,
				"CTDB record handle required."
			);
			return false;
		}
		err = ctdb_store_record(hdl, data);
		if (err) {
			PyErr_Format(
				PyExc_RuntimeError,
				"ctdb_store_record() failed: %s. "
				"Released record handle.",
				strerror(abs(err))
			);
			TALLOC_FREE(hdl);
			return false;
		}
	} else {
		err = ctdb_transaction_store_record(ctx->txh, key, data);
		if (err) {
			PyErr_Format(
				PyExc_RuntimeError,
				"ctdb_transaction_store_record() failed: %s. "
				"Cancelled transaction.",
				strerror(abs(err))
			);
			ctdb_transaction_cancel(ctx->txh);
			ctx->txh = NULL;
			return false;
		}
	}

	return true;
}

static bool ctdb_db_delete(py_ctdb_db_ctx *ctx, TDB_DATA key,
			   struct ctdb_record_handle *hdl)
{
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	TDB_DATA val;
	bool is_volatile = false;
	int err;

	if ((ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) == 0) {
		is_volatile = true;
	}

	if (!validate_op(ctx, is_volatile, true)) {
		return false;
	}

	if (is_volatile) {
		if (hdl == NULL) {
			PyErr_SetString(
				PyExc_ValueError,
				"CTDB record handle required."
			);
			return false;
		}
		err = ctdb_delete_record(hdl);
		if (err) {
			PyErr_Format(
				PyExc_RuntimeError,
				"ctdb_delete_record() failed: %s. "
				"Released record handle.",
				strerror(abs(err))
			);
			TALLOC_FREE(hdl);
			return false;
		}
	} else {
		err = ctdb_transaction_delete_record(ctx->txh, key);
		if (err) {
			PyErr_Format(
				PyExc_RuntimeError,
				"ctdb_transaction_delete_record() failed: %s. "
				"Cancelled transaction.",
				strerror(abs(err))
			);
			ctdb_transaction_cancel(ctx->txh);
			ctx->txh = NULL;
			return false;
		}
	}

	return true;
}

/*
 * Not all backend types will have a tdb_record_handle
 */

static PyObject *py_ctdb_db_entry_locked(PyObject *self, void *closure)
{
	py_ctdb_db_entry *entry = (py_ctdb_db_entry *)self;
	if (entry->hdl == NULL) {
		Py_RETURN_FALSE;
	}
	Py_RETURN_TRUE;
}

/*
 * getters for key and value return copy of the key so
 * that it is de-facto immutable
 */
static PyObject *py_ctdb_db_entry_key(PyObject *self, void *closure)
{
	py_ctdb_db_entry *entry = (py_ctdb_db_entry *)self;
	TDB_DATA data;

	data = PyBytes_AsTDB_DATA(entry->key);
	return PyBytes_FromTDB_DATA(data);
}

static PyObject *py_ctdb_db_entry_val(PyObject *self, void *closure)
{
	py_ctdb_db_entry *entry = (py_ctdb_db_entry *)self;
	TDB_DATA data;

	if (entry->val == Py_None) {
		Py_RETURN_NONE;
	}

	data = PyBytes_AsTDB_DATA(entry->val);
	return PyBytes_FromTDB_DATA(data);
}

static PyObject *py_ctdb_db_entry_new(PyTypeObject *obj,
				      PyObject *args_unused,
				      PyObject *kwargs_unused)
{
	py_ctdb_db_entry *self = NULL;

	self = (py_ctdb_db_entry *)obj->tp_alloc(obj, 0);
	if (self == NULL) {
		return NULL;
	}
	self->key = NULL;
	self->val = NULL;
	self->hdl = NULL;
	self->ctx = NULL;
	return (PyObject *)self;
}

static int py_ctdb_db_entry_init(py_ctdb_db_entry *self,
				 PyObject *args,
				 PyObject *kwargs_unused)
{
	PyObject *key = NULL;
	PyObject *db_ctx = NULL;
	uint32_t dbid;
	uint8_t dbflags;
	long init_flags=0;
	TALLOC_CTX *tmp_ctx = NULL;
	bool exists;

	if (!PyArg_ParseTuple(args, "OO", &db_ctx, &key)) {
		return -1;
	}

	if (PyObject_IsInstance(db_ctx, (PyObject *)&PyCtdbDB) == 0) {
		PyErr_SetString(
			PyExc_TypeError,
			"First argument must be ctdb.Ctdb type"
		);
		return -1;
	}
	if (!PyBytes_Check(key)) {
		PyErr_SetString(
			PyExc_TypeError,
			"Second argument (key) must by bytestring"
		);
		return -1;
	}

	self->key = pytdb_copy(key);
	self->ctx = (py_ctdb_db_ctx *)db_ctx;
	Py_INCREF(db_ctx);
	self->val = Py_None;
	Py_INCREF(self->val);
	return 0;
}

static PyObject *py_ctdb_db_entry_unlock(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_entry *entry = (py_ctdb_db_entry *)self;
	if (entry->ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		PyErr_SetString(
			PyExc_ValueError,
			"Unlock operation is only permitted on volatile "
			"database."
		);
		return NULL;
	}
	if (entry->hdl) {
		TALLOC_FREE(entry->hdl);
	}
	Py_RETURN_TRUE;
}

/*
 * Init function does not increment refcount for `key`, but instead
 * allocates new object. This means caller of this should `decref`
 * `key` if appropriate.
 */
static py_ctdb_db_entry *entry_from_tdb_data(py_ctdb_db_ctx *db_ctx,
					     PyObject *key,
					     PyObject *data)
{
	py_ctdb_db_entry *entry = NULL;

	entry = PyObject_CallFunction(
		(PyObject *)&PyCtdbDBEntry,
		"OO", db_ctx, key
	);

	if (entry == NULL) {
		return NULL;
	}

	if (data != NULL) {
		Py_DECREF(entry->val);
		entry->val = pytdb_copy(data);
	}

	return entry;
}

/*
 * returns new ctdb.CtdbDBEntry object
 */
static PyObject *py_ctdb_db_entry_fetch(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_entry *entry = (py_ctdb_db_entry *)self;
	bool ok;
	TDB_DATA key, data;
	struct ctdb_record_handle *hdl = NULL;
	PyObject *pydata = NULL;
	py_ctdb_db_entry *out = NULL;

	key = PyBytes_AsTDB_DATA(entry->key);
	ok = ctdb_db_fetch(entry->ctx->client->mem_ctx, entry->ctx, key, &data, &hdl);
	if (!ok) {
		goto finished;
	}

	pydata = PyBytes_FromTDB_DATA(data);
	if (data.dptr) {
		TALLOC_FREE(data.dptr);
	}
	out = entry_from_tdb_data(entry->ctx, entry->key, pydata);
	if (out == NULL) {
		goto finished;
	}

	if (hdl != NULL) {
		out->hdl = hdl;
	}

finished:
	Py_XDECREF(pydata);
	if (out == NULL) {
		return NULL;
	}
	return (PyObject *)out;
}

/*
 * returns new ctdb.CtdbDBEntry object
 * with reference to original database key
 * if database is volatile.
 */
static PyObject *py_ctdb_db_entry_store(PyObject *self, PyObject *args)
{
	PyObject *payload = NULL;
	py_ctdb_db_entry *entry = (py_ctdb_db_entry *)self;
	TDB_DATA key, data;
	bool ok;

	if (!PyArg_ParseTuple(args, "O", &payload)) {
		return NULL;
	}

	if (!PyBytes_Check(payload)) {
		PyErr_SetString(
			PyExc_TypeError,
			"data must be bytestring"
		);
		return NULL;
	}

	key = PyBytes_AsTDB_DATA(entry->key);
	data = PyBytes_AsTDB_DATA(payload);

	ok = ctdb_db_store(entry->ctx, key, data, entry->hdl);
	if (!ok) {
		return NULL;
	}

	Py_CLEAR(entry->val);
	entry->val = pytdb_copy(payload);
	Py_INCREF(self);
	return (PyObject *)self;
}

static PyObject *py_ctdb_db_entry_delete(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_entry *entry = (py_ctdb_db_entry *)self;
	TDB_DATA key = PyBytes_AsTDB_DATA(entry->key);
	bool ok;

	ok = ctdb_db_delete(entry->ctx, key, entry->hdl);
	if (!ok) {
		return NULL;
	}
	Py_CLEAR(entry->val);

	entry->val = Py_None;
	Py_INCREF(entry->val);
	Py_RETURN_NONE;
}

static void py_ctdb_db_entry_dealloc(py_ctdb_db_entry *self)
{
	/*
	 * Handle for volatile database entry is generated on
	 * fetch. We increment refcount on store ops
	 * where we return updated entry.
	 */
	if (self->hdl != NULL) {
		TALLOC_FREE(self->hdl);
	}
	Py_XDECREF(self->ctx);
	Py_XDECREF(self->key);
	Py_XDECREF(self->val);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

/*
 * DB Operations
 */
static bool db_exists(TALLOC_CTX *mem_ctx, py_ctdb_client_ctx *ctx,
		      const char *db_arg, uint32_t *db_id,
		      const char **db_name, uint8_t *db_flags);
static bool attach_db(py_ctdb_db_ctx *ctx)
{
	int err;
	py_ctdb_client_ctx *ctdb = ctx->client;
	struct ctdb_db_context *db = NULL;

	if (ctx->db != NULL) {
		return true;
	}

	err = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(ctdb), ctx->db_name,
			  ctx->db_flags, &db);

	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_attach() failed: %s\n",
			strerror(abs(err))
		);
		return false;
	}

	if (!ctx->db_exists) {
		const char *new = NULL;
		bool exists;
		uint32_t dbid;
		uint8_t dbflags;

		exists = db_exists(ctdb->mem_ctx, ctdb, ctx->db_name, &dbid, &new, &dbflags);
		if (!exists) {
			PyErr_SetString(
				PyExc_RuntimeError,
				"Failed to find database after creation."
			);
			return false;
		}

		ctx->db_id = dbid;
		ctx->db_flags = dbflags;
		TALLOC_FREE(new);
	}

	ctx->db = db;
	ctx->db_exists = true;
	return true;
}

static PyObject *py_ctdb_attach(PyObject *self, PyObject *args)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	int err;
	long flag = 0;

	if (!PyArg_ParseTuple(args, "|I", &flag)) {
		return NULL;
	}

	if (flag > CTDB_DB_FLAGS_REPLICATED || flag < 0) {
		PyErr_Format(
			PyExc_ValueError,
			"Invalid DB flags\n"
		);
		return NULL;
	}

	if (ctx->db_flags && ctx->db_flags != flag) {
		PyErr_Format(
			PyExc_ValueError,
			"Specified flags (%d) do not match existing flags (%d)\n",
			flag, ctx->db_flags
		);
		return NULL;
	}

	ctx->db_flags = flag;
	if (!attach_db(ctx)) {
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_ctdb_detach(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	int err, recmode;
	TALLOC_CTX *tmp_ctx = NULL;
	unsigned int i;
	struct ctdb_node_map *nodemap = NULL;

	if (ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		PyErr_SetString(
			PyExc_TypeError,
			"Non-volatile databases may not be detached."
		);
		return NULL;
	}

	tmp_ctx = talloc_new(cl_ctx->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	err = ctdb_ctrl_get_recmode(tmp_ctx, cl_ctx->ev, cl_ctx->client,
				    cl_ctx->target_pnn, TIMEOUT(cl_ctx), &recmode);
	if (err != 0) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_ctrl_get_recmode() failed: %s",
			strerror(abs(err))
		);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	if (recmode == CTDB_RECOVERY_ACTIVE) {
		PyErr_SetString(
			PyExc_RuntimeError,
			"Database may not be detached while recovery is active."
		);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	nodemap = get_nodemap(cl_ctx, false);
	if (nodemap == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	for (i = 0; i < nodemap->num; i++) {
		uint32_t value;
		if (nodemap->node[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}
		if (nodemap->node[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (nodemap->node[i].flags & NODE_FLAGS_INACTIVE) {
			PyErr_Format(
				PyExc_RuntimeError,
				"Database may not be detached on "
				"inactive (stopped or banned) node %u",
				nodemap->node[i].pnn
			);
			TALLOC_FREE(tmp_ctx);
			TALLOC_FREE(nodemap);
			return NULL;
		}
		err = ctdb_ctrl_get_tunable(tmp_ctx, cl_ctx->ev, cl_ctx->client,
					    nodemap->node[i].pnn, TIMEOUT(cl_ctx),
					    "AllowClientDBAttach", &value);
		if (err) {
			PyErr_Format(
				PyExc_RuntimeError,
				"Unable to get tunable AllowClientDBAttach "
				"from node %u: %s",
				nodemap->node[i].pnn, strerror(abs(err))
			);
			TALLOC_FREE(tmp_ctx);
			TALLOC_FREE(nodemap);
			return NULL;
		}

		if (value == 1) {
			PyErr_Format(
				PyExc_RuntimeError,
				"Database access is still active on node %u. "
			        "Set AllowclientDBAttach=0 on all nodes.",
				nodemap->node[i].pnn
			);
			TALLOC_FREE(tmp_ctx);
			TALLOC_FREE(nodemap);
			return NULL;
		}
	}

	TALLOC_FREE(tmp_ctx);
	TALLOC_FREE(nodemap);

	err = ctdb_detach(cl_ctx->ev, cl_ctx->client, TIMEOUT(cl_ctx), ctx->db_id);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_detach() failed: %s",
			strerror(abs(err))
		);
		return NULL;
	}

	Py_RETURN_NONE;
}

/*
 * returns new ctdb.CtdbDBEntry object
 */
static PyObject *py_ctdb_db_fetch(PyObject *self, PyObject *args)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	PyObject *pykey = NULL, *pydata = NULL;
	py_ctdb_db_entry *out = NULL;
	TDB_DATA key, data;
	struct ctdb_record_handle *hdl = NULL;
	bool ok;

	if (!PyArg_ParseTuple(args, "O", &pykey)) {
		goto finished;
	}

	if (!PyBytes_Check(pykey)) {
		PyErr_SetString(
			PyExc_TypeError,
			"Key must be bytestring"
		);
		goto finished;
	}

	key = PyBytes_AsTDB_DATA(pykey);
	ok = ctdb_db_fetch(ctx->client->mem_ctx, ctx, key, &data, &hdl);
	if (!ok) {
		goto finished;
	}

	/*
	 * create new bytestring objects for TDB key / data
	 * memory for TDB_DATA data is allocated under temporary
	 * TALLOC context and freed in TALLOC_FREE()
	 */
	pydata = PyBytes_FromTDB_DATA(data);
	out = entry_from_tdb_data(ctx, pykey, pydata);

	Py_XDECREF(pydata);
	if (data.dptr) {
		TALLOC_FREE(data.dptr);
	}

	if (out == NULL) {
		goto finished;
	}

	if (hdl != NULL) {
		out->hdl = hdl;
	}

finished:
	if (out == NULL) {
		return NULL;
	}
	return (PyObject *)out;
}

static PyObject *py_ctdb_db_store(PyObject *self, PyObject *args)
{
	PyObject *payload = NULL, *pykey = NULL;
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	TDB_DATA key, data;
	bool ok;

	if ((ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) == 0) {
		PyErr_SetString(
			PyExc_ValueError,
			"Writes to volatile database must be made "
			"through an open DB entry object and not the "
			"database object. Fetch the entry, then operate "
			"on it."
		);
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "OO", &pykey, &payload)) {
		return NULL;
	}

	if (!PyBytes_Check(payload)) {
		PyErr_SetString(
			PyExc_TypeError,
			"data must be bytestring"
		);
		return NULL;
	}

	if (!PyBytes_Check(pykey)) {
		PyErr_SetString(
			PyExc_TypeError,
			"key must be bytestring"
		);
		return NULL;
	}

	key = PyBytes_AsTDB_DATA(pykey);
	data = PyBytes_AsTDB_DATA(payload);

	ok = ctdb_db_store(ctx, key, data, NULL);
	if (!ok) {
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ctdb_db_delete(PyObject *self, PyObject *args)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	PyObject *pykey = NULL;
	bool ok;
	TDB_DATA key;

	if ((ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) == 0) {
		PyErr_SetString(
			PyExc_ValueError,
			"Writes to volatile database must be made "
			"through an open DB entry object and not the "
			"database object. Fetch the entry, then operate "
			"on it."
		);
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "O", &pykey)) {
		return NULL;
	}

	key = PyBytes_AsTDB_DATA(pykey);
	ok = ctdb_db_delete(ctx, key, NULL);
	if (!ok) {
		return NULL;
	}

	Py_RETURN_NONE;
}

/*
 * Transactions should be cancelled prior to closing the database handle
 */
static PyObject *py_ctdb_db_close(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;

	if (ctx->txh != NULL) {
		return Py_False;
	}

	if (ctx->db == NULL) {
		return Py_True;
	}

	TALLOC_FREE(ctx->db);
	return Py_True;
}

/*
 * Transaction control functions
 */

/*
 * Start a transaction. Optionally can set transaction handle as
 * readonly by setting Py_True as first arg.
 */
static PyObject *py_ctdb_db_tx_start(PyObject *self, PyObject *args)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	PyObject *ro = NULL;
	struct ctdb_transaction_handle *h = NULL;
	bool readonly = false;
	int err;

	if (ctx->db == NULL) {
		PyErr_SetString(
			PyExc_ValueError,
			"CTDB database handle is closed. "
			"DB must be reattached prior to "
			"starting a transaction"
		);
		return NULL;
	}

	if ((ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) == 0) {
		PyErr_SetString(
			PyExc_ValueError,
			"Transactions are not supported on this database type"
		);
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "O", &ro))
		return NULL;

	if ((ro != NULL) && !PyBool_Check(ro)) {
		PyErr_SetString(
			PyExc_TypeError,
			"Expected boolean for ro"
		);
		return NULL;
	}

	if (ro == Py_True) {
		readonly = true;
	}

	err = ctdb_transaction_start(cl_ctx->mem_ctx, cl_ctx->ev, cl_ctx->client,
				     TIMEOUT(cl_ctx), ctx->db, readonly, &h);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_transaction_start() failed: %s\n",
			strerror(abs(err))
		);
		return NULL;
	}
	ctx->txh_ro = readonly;
	ctx->txh = h;

	Py_RETURN_TRUE;
}

static PyObject *py_ctdb_db_tx_commit(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	int err;

	if (ctx->txh == NULL) {
		PyErr_SetString(
			PyExc_ValueError,
			"Object does not have an database transaction handle."
		);
		return NULL;
	}

	if (ctx->txh_ro) {
		PyErr_SetString(
			PyExc_TypeError,
			"Cannot commit on readonly transaction handle."
		);
		return NULL;
	}

	err = ctdb_transaction_commit(ctx->txh);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_transaction_commit() failed: %s. "
			"database transaction has been cancelled.",
			strerror(abs(err))
		);
		ctdb_transaction_cancel(ctx->txh);
		ctx->txh = NULL;
		return NULL;
	}
	ctx->txh = NULL;
	Py_RETURN_TRUE;
}

static PyObject *py_ctdb_db_tx_cancel(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	int err;

	if (ctx->txh == NULL) {
		PyErr_SetString(
			PyExc_ValueError,
			"Object does not have an database transaction handle."
		);
		return NULL;
	}

	ctdb_transaction_cancel(ctx->txh);
	ctx->txh = NULL;

	Py_RETURN_TRUE;
}

typedef  struct {
	PyObject *private;
	PyObject *fn;
	py_ctdb_db_ctx *db_ctx;
	bool incl_ltdb_hdr;
	size_t cnt;
} traverse_cb_state;

/*
 * Thin wrapper around python callback function.
 * Creates the python_ctdb_db_entry object and
 * passes it with pointer to python object for
 * private data to python callback function.
 * ctdb traversal stops on non-zero return. Use
 * EFAULT to indicate a python exception is being
 * passed back to caller (which also stops traversal).
 *
 * Py_False return means traversal should stop.
 */
static PyObject *cb_do_call(PyObject *fn,
			    PyObject *cb_data,
			    PyObject *private)
{
	PyObject *rv = NULL;
	PyObject *arglist = NULL;

	arglist = Py_BuildValue("OO", cb_data, private);
	if (arglist == NULL) {
		return NULL;
	}

	rv = PyObject_Call(fn, arglist, NULL);
	Py_DECREF(arglist);
	return rv;
}

static py_ctdb_db_entry *cb_mk_tdb_entry(py_ctdb_db_ctx *ctx,
					 TDB_DATA key,
					 TDB_DATA data)
{
	py_ctdb_db_entry *entry = NULL;
	PyObject *pykey = NULL;
	PyObject *pydata = NULL;

	pykey = PyBytes_FromTDB_DATA(key);
	pydata = PyBytes_FromTDB_DATA(data);
	entry = entry_from_tdb_data(ctx, pykey, pydata);

	Py_DECREF(pykey);
	Py_DECREF(pydata);

	return entry;
}

static int db_traverse_cb(uint32_t reqid,
			  struct ctdb_ltdb_header *header,
			  TDB_DATA key,
			  TDB_DATA data,
			  void *private_data)
{
	traverse_cb_state *state = NULL;
	py_ctdb_db_entry *entry = NULL;
	PyObject *result = NULL;
	PyObject *pykey = NULL, *pydata = NULL;
	PyObject *cb_data = NULL;
	PyObject *ltdb_header = NULL;
	int rv;

	state = (traverse_cb_state *)private_data;

	/* skip sequence number key */
	if ((key.dsize == 23) &&
	    (strncmp(key.dptr, "__db_sequence_number__", 22) == 0)) {
		return 0;
	}

	entry = cb_mk_tdb_entry(state->db_ctx, key, data);
	if (entry == NULL) {
		return EFAULT;
	}

	if (state->incl_ltdb_hdr) {
		ltdb_header = Py_BuildValue(
			"{s:I,s:I,s:I}",
			"dmaster", header->dmaster,
			"rsn", header->rsn,
			"flags", header->flags
		);

		if (ltdb_header == NULL) {
			Py_DECREF(entry);
			return EFAULT;
		}

		cb_data = Py_BuildValue(
			"{s:O,s:O}",
			"ltdb_header", ltdb_header,
			"entry", entry
		);
		Py_CLEAR(ltdb_header);
	} else {
		cb_data = (PyObject *)entry;
	}

	result = cb_do_call(state->fn, cb_data, state->private);
	if (result == NULL) {
		goto error;
	}
	else if (result != Py_True && result != Py_False) {
		PyErr_SetString(
			PyExc_TypeError,
			"Callable must return True, False, or "
			"raise exception."
		);
		goto error;
	}
	rv = (result == Py_True) ? 0 : 1;
	Py_DECREF(result);
	if (ltdb_header) {
		Py_DECREF(ltdb_header);
		Py_DECREF(entry);
	}
	Py_DECREF(cb_data);
	state->cnt++;
	return rv;

error:
	if (ltdb_header) {
		Py_DECREF(ltdb_header);
		Py_DECREF(cb_data);
	}
	if (result) {
		Py_DECREF(result);
	}
	Py_DECREF(entry);
	return EFAULT;
}

/*
 * Traverse all database entries in CTDB database and call
 * specified python callback function. Returns python integer
 * containing count of entries iterated through.
 * Callback may stop traversal by returning Py_False.
 *
 * Depending on whether local tdb header info is desired
 * callback object will either be ctdb.CtdbDBEntry type or dict:
 * {"ltdb_header": {<header>}, "entry": ctdb.CtdbDBEntry}
 */
static PyObject *py_ctdb_db_traverse(PyObject *self, PyObject *args)
{
	TALLOC_CTX *tmp_ctx = NULL;
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	PyObject *fn = NULL;
	PyObject *private = NULL;
	PyObject *ltdb_header = NULL;
	traverse_cb_state state;
	int err;
	bool incl_ltdb_hdr;

	if (!ctx->db_exists) {
		PyErr_Format(
			PyExc_FileNotFoundError,
			"%s: database does not exist",
			ctx->db_name
		);
		return NULL;
	}

	if (ctx->txh != NULL) {
		PyObject *pyerr = Py_BuildValue(
			"is", EBUSY,
			"Traverse is not permitted with transaction in "
			"progress."
		);
		if (pyerr == NULL) {
			return NULL;

		}
		PyErr_SetObject(
			PyExc_OSError,
			pyerr
		);
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "OO|O", &fn, &private, &ltdb_header))
		return NULL;

	if (!PyCallable_Check(fn)) {
		PyErr_SetString(
			PyExc_TypeError,
			"First argument must be callable type. "
			"Callable will be called with two arguments: "
			"a DB entry object, and the private data passed into "
			"this traverse function."
		);
		return NULL;
	}

	if (ltdb_header && !PyBool_Check(ltdb_header)) {
		PyErr_SetString(
			PyExc_TypeError,
			"Second argument (whether to include ltdb headers "
			" must be boolean type."
		);
		return NULL;
	}

	incl_ltdb_hdr = (ltdb_header && ltdb_header == Py_False) ? false : true;

	state = (traverse_cb_state) {
		.fn = fn,
		.private = private,
		.db_ctx = ctx,
		.incl_ltdb_hdr = incl_ltdb_hdr,
	};

	tmp_ctx = talloc_new(cl_ctx->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	err = ctdb_db_traverse(tmp_ctx, cl_ctx->ev, cl_ctx->client,
			       ctx->db, cl_ctx->target_pnn, TIMEOUT(cl_ctx),
			       db_traverse_cb, &state);
	TALLOC_FREE(tmp_ctx);
	if (err == EFAULT) {
		return NULL;
	}
	return Py_BuildValue("k", state.cnt);
}

#if 0
static PyObject *py_ctdb_db_wipe(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	PyObject *out = NULL;
	struct ctdb_dbid_map dbmap = {self->db_id, self->db_flags};
	PyObject *db_status = NULL;
	TALLOC_CTX *tmp_ctx == NULL;
	uint32_t db_id;
	uint8_t db_flags;
	struct ctdb_node_map *nodemap;
	struct ctdb_req_control request;
	struct ctdb_transdb wipedb;
	uint32_t generation;
	uint32_t *pnn_list;
	int count, ret;

	if (!self.db_exists) {
		PyErr_Format(
			PyExc_FileNotFoundError,
			"%s: database does not exist"
			self->db_name
		);
		return NULL;
	}

	tmp_ctx = talloc_new(self->client->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (db == NULL) {
		bool ok;
		ok = attach_db(ctx);
		if (!ok) {
			return NULL;
		}
	}
	nodemap = get_nodemap(ctdb, false);

	out = Py_None;
done:
	TALLOC_FREE(tmp_ctx);
	return out;
}
#endif


static PyObject *py_ctdb_db_status(PyObject *self, PyObject *args_unused)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	struct ctdb_dbid dbmap = {ctx->db_id, ctx->db_flags};
	PyObject *db_status = NULL;
	TALLOC_CTX *tmp_ctx = NULL;

	if (!ctx->db_exists) {
		PyErr_Format(
			PyExc_FileNotFoundError,
			"%s: database does not exist",
			ctx->db_name
		);
		return NULL;
	}

	tmp_ctx = talloc_new(ctx->client->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	db_status = py_dbmap_entry(tmp_ctx, ctx->client, dbmap);

	TALLOC_FREE(tmp_ctx);

	return db_status;
}

static struct ctdb_dbid *db_find(TALLOC_CTX *mem_ctx,
				 py_ctdb_client_ctx *ctdb,
				 struct ctdb_dbid_map *dbmap,
				 const char *db_name)
{
	struct ctdb_dbid *db = NULL;
	const char *name;
	unsigned int i;
	int ret;

	for (i=0; i<dbmap->num; i++) {
		ret = ctdb_ctrl_get_dbname(mem_ctx, ctdb->ev, ctdb->client,
					   ctdb->pnn, TIMEOUT(ctdb),
					   dbmap->dbs[i].db_id, &name);
		if (ret != 0) {
			return false;
		}

		if (strcmp(db_name, name) == 0) {
			talloc_free(discard_const(name));
			db = &dbmap->dbs[i];
			break;
		}
	}

	return db;
}

static bool db_exists(TALLOC_CTX *mem_ctx, py_ctdb_client_ctx *ctx,
		      const char *db_arg, uint32_t *db_id,
		      const char **db_name, uint8_t *db_flags)
{
	struct ctdb_dbid_map *dbmap;
	struct ctdb_dbid *db = NULL;
	uint32_t id = 0;
	const char *name = NULL;
	unsigned int i;
	int ret = 0;

	ret = ctdb_ctrl_get_dbmap(mem_ctx, ctx->ev, ctx->client,
				  ctx->pnn, TIMEOUT(ctx), &dbmap);
	if (ret != 0) {
		return false;
	}

	if (strncmp(db_arg, "0x", 2) == 0) {
		id = smb_strtoul(db_arg, NULL, 0, &ret, SMB_STR_STANDARD);
		if (ret != 0) {
			return false;
		}
		for (i=0; i<dbmap->num; i++) {
			if (id == dbmap->dbs[i].db_id) {
				db = &dbmap->dbs[i];
				break;
			}
		}
	} else {
		name = db_arg;
		db = db_find(mem_ctx, ctx, dbmap, name);
	}

	if (db == NULL) {
		return false;
	}

	if (name == NULL) {
		ret = ctdb_ctrl_get_dbname(mem_ctx, ctx->ev, ctx->client,
					   ctx->pnn, TIMEOUT(ctx), id, &name);
		if (ret != 0) {
			return false;
		}
	}

	if (db_id != NULL) {
		*db_id = db->db_id;
	}
	if (db_name != NULL) {
		*db_name = talloc_strdup(mem_ctx, name);
	}
	if (db_flags != NULL) {
		*db_flags = db->flags;
	}
	return true;
}

static PyObject *py_ctdb_db_new(PyTypeObject *obj,
				PyObject *args_unused,
				PyObject *kwargs_unused)
{
	int err;
	uint64_t srvid_offset;
	py_ctdb_db_ctx *self = NULL;

	self = (py_ctdb_db_ctx *)obj->tp_alloc(obj, 0);
	if (self == NULL) {
		return NULL;
	}

	self->client = NULL;
	self->db_exists = false;
	self->db = NULL;
	self->txh = NULL;
	return (PyObject *)self;
}

static int py_ctdb_db_init(py_ctdb_db_ctx *self,
			   PyObject *args,
			   PyObject *kwargs_unused)
{
	const char *dbname = NULL;
	const char *new = NULL;
	PyObject *cl_ctx = NULL;
	uint32_t dbid;
	uint8_t dbflags;
	long init_flags=0;
	TALLOC_CTX *tmp_ctx = NULL;
	bool exists;

	if (!PyArg_ParseTuple(args, "Os|I", &cl_ctx, &dbname, &init_flags)) {
		return -1;
	}

	if (PyObject_IsInstance(cl_ctx, (PyObject *)&PyCtdbClient) == 0) {
		PyErr_Format(
			PyExc_ValueError,
			"First argument must be ctdb.Client type\n"
		);
		return -1;
	}
	self->client = (py_ctdb_client_ctx *)cl_ctx;
	Py_INCREF(self->client);

	tmp_ctx = talloc_new(self->client->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return -1;
	}

	exists = db_exists(tmp_ctx, self->client, dbname, &dbid, &new, &dbflags);
	if (exists) {
		self->db_exists = true;
		self->db_id = dbid;
		self->db_flags = dbflags;
		self->db_name = talloc_strdup(self->client->mem_ctx, new);
	} else if ((init_flags & O_CREAT) == 0) {
		TALLOC_FREE(tmp_ctx);
		PyErr_Format(
			PyExc_FileNotFoundError,
			"%s: database does not exist. If os.O_CREAT is specified "
			"in flags, then new database will be created on Ctdb.attach().",
			dbname
		);
		return -1;
	} else {
		self->db_name = talloc_strdup(self->client->mem_ctx, dbname);
		self->db_exists = false;
	}
	TALLOC_FREE(tmp_ctx);

	return 0;
}

static void py_ctdb_db_dealloc(py_ctdb_db_ctx *self)
{
	if (self->txh != NULL) {
		ctdb_transaction_cancel(self->txh);
		self->txh = NULL;
	}
	if (self->db != NULL) {
		TALLOC_FREE(self->db);
	}
	Py_CLEAR(self->client);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *py_ctdb_db_exists(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;

	if (ctx->db_exists) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *py_ctdb_db_opened(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;

	if (ctx->db == NULL) {
		Py_RETURN_FALSE;
	}
	Py_RETURN_TRUE;
}

static PyObject *py_ctdb_db_flags(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	return Py_BuildValue("H", ctx->db_flags);
}

static PyObject *py_ctdb_db_dbid(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	return Py_BuildValue("I", ctx->db_id);
}

static PyObject *py_ctdb_db_txh(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;

	if (ctx->txh == NULL) {
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

static PyObject *py_ctdb_db_ro(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;

	if (ctx->db == NULL) {
		Py_RETURN_TRUE;
	}

	if ((ctx->db_flags &
	    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED) == 0)) {
		if (ctx->txh_ro) {
			Py_RETURN_TRUE;

		}
		Py_RETURN_FALSE;
	}

	if (ctx->txh == NULL || !ctx->txh_ro) {
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

static PyObject *py_ctdb_db_seqnum(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	py_ctdb_client_ctx *cl_ctx = ctx->client;
	PyObject *out;
	int err;
	uint64_t seqnum;

	if (ctx->db == NULL || !ctx->db_exists) {
		Py_RETURN_NONE;
	}

	err = ctdb_ctrl_get_db_seqnum(cl_ctx->mem_ctx, cl_ctx->ev, cl_ctx->client,
				      cl_ctx->target_pnn, TIMEOUT(cl_ctx), ctx->db_id,
				      &seqnum);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"ctdb_ctrl_get_db_seqnum() failed: %s",
			strerror(abs(err))
		);
	}

	out = Py_BuildValue("k", seqnum);
	return out;
}


static PyObject *py_ctdb_db_name(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	return Py_BuildValue("s", ctx->db_name);
}

static PyMethodDef ctdb_module_methods[] = {
#if 0
	{
		.ml_name = "Client",
		.ml_meth = (PyCFunction)py_ctdb_client_new,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Client()\nCreate new ctdb client.",
	},
#endif
	{ NULL, NULL, 0, NULL }
};

static bool check_flags(TALLOC_CTX *mem_ctx,
			py_ctdb_node *ctx,
			uint32_t flag,
			bool set_flag,
		        bool *out)
{
	struct ctdb_node_map *nodemap;
	struct ctdb_node_and_flags *node = NULL;
	bool flag_is_set;

	nodemap = get_nodemap(ctx->client, false);
	if (nodemap == NULL) {
		/* python error set in called function */
		TALLOC_FREE(nodemap);
		return false;
	}

	node = get_node_by_pnn(nodemap, ctx->pnn);
	if (node == NULL) {
		PyErr_Format(
			PyExc_RuntimeError,
			"%u: node not found in current nodemap.",
			ctx->pnn
		);
		TALLOC_FREE(nodemap);
		return false;
	}

	flag_is_set = node->flags & flag;
	*out = (set_flag == flag_is_set) ? false : true;
	TALLOC_FREE(nodemap);
	return true;
}

static bool py_ctdb_set_ban_state(py_ctdb_node *node, struct ctdb_ban_state ban)
{
	TALLOC_CTX *tmp_ctx = NULL;
	bool ok, flag_is_correct, set_flag;
	int err;
	uint32_t tunval;
	py_ctdb_client_ctx *ctx = node->client;
	struct ctdb_tunable_list *tun_list = NULL;

	tmp_ctx = talloc_new(ctx->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return false;
	}

	ok = ctdb_get_tunables(tmp_ctx, ctx, &tun_list);
	if (!ok) {
		/* python error set in called function */
		goto out;
	}

	ok = ctdb_tunable_get_value(tun_list, "enable_bans", &tunval);
	if (!ok) {
		PyErr_SetString(
			PyExc_RuntimeError,
			"ctdb_get_tunable() failed"
		);
		goto out;
	}

	if ((ban.time != 0) && (tunval == 0)) {
		PyErr_SetString(
			PyExc_PermissionError,
			"Bans are disabled by tunable."
		);
		ok = false;
		goto out;
	}

	set_flag = (ban.time == 0) ? false : true;

	ok = check_flags(tmp_ctx, node, NODE_FLAGS_BANNED, set_flag,
			 &flag_is_correct);
	if (!ok || flag_is_correct) {
		goto out;
	}

	err = ctdb_ctrl_set_ban_state(tmp_ctx, ctx->ev, ctx->client,
				      node->pnn, TIMEOUT(ctx), &ban);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"%u: ctdb_ctrl_set_ban_state() failed: %s",
			node->pnn, strerror(abs(err))
		);
		ok = false;
	}

out:
	TALLOC_FREE(tmp_ctx);
	return ok;
}

static PyObject *py_ctdb_node_unban(PyObject *self,
				    PyObject *args_unused)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	bool ok;

	struct ctdb_ban_state ban_state = {
		.pnn = node->pnn,
		.time = 0
	};

	ok = py_ctdb_set_ban_state(node, ban_state);
	if (!ok) {
		return NULL;
	}

	Py_RETURN_NONE;
}


static PyObject *py_ctdb_node_ban(PyObject *self,
				  PyObject *args)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	bool ok;
	uint ban_time;
	struct ctdb_ban_state ban_state = { .pnn = node->pnn };

	if (!PyArg_ParseTuple(args, "I", &ban_time)) {
		return NULL;
	}

	if (ban_time > 86400) {
		PyErr_SetString(
			PyExc_ValueError,
			"Bans of more than 24 hours are not permitted."
		);
		return NULL;
	}

	ok = py_ctdb_set_ban_state(node, ban_state);
	if (!ok) {
		return NULL;
	}

	Py_RETURN_NONE;
}

static bool node_change_disabled(py_ctdb_node *node, bool disabled)
{
	TALLOC_CTX *tmp_ctx = NULL;
	py_ctdb_client_ctx *ctx = node->client;
	bool ok, flag_is_correct;
	int err;

	tmp_ctx = talloc_new(ctx->mem_ctx);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return false;
	}

	ok = check_flags(tmp_ctx, node, NODE_FLAGS_PERMANENTLY_DISABLED, disabled,
			 &flag_is_correct);
	if (!ok || flag_is_correct) {
		goto out;
	}

	if (disabled) {
		err = ctdb_ctrl_disable_node(tmp_ctx,
					     ctx->ev,
					     ctx->client,
					     node->pnn,
					     TIMEOUT(ctx));
	} else {
		err = ctdb_ctrl_enable_node(tmp_ctx,
					    ctx->ev,
					    ctx->client,
					    node->pnn,
					    TIMEOUT(ctx));
	}

	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"%u: %s failed: %s",
			node->pnn,
			(disabled ?
			 "ctdb_ctrl_disable_node()" :
			 "ctdb_ctrl_enable_node()"),
			strerror(abs(err))
		);
		ok = false;
		goto out;
	}

out:
	TALLOC_FREE(tmp_ctx);
	return ok;
}

static PyObject *py_ctdb_node_enable(PyObject *self,
				     PyObject *args_unused)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	bool ok;

	ok = node_change_disabled(node, false);
	if (!ok) {
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ctdb_node_disable(PyObject *self,
				      PyObject *args_unused)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	bool ok;

	ok = node_change_disabled(node, true);
	if (!ok) {
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ctdb_node_rebalance(PyObject *self,
					PyObject *args_unused)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	py_ctdb_client_ctx *ctx = node->client;
	int err;

	err = ctdb_message_rebalance_node(ctx->mem_ctx, ctx->ev, ctx->client,
					  CTDB_BROADCAST_CONNECTED, node->pnn);
	if (err) {
		PyErr_Format(
			PyExc_RuntimeError,
			"Failed to ask recovery master to distribute IPs: %s",
			strerror(abs(err))
		);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ctdb_node_is_current(PyObject *self, void *closure)
{
	py_ctdb_node *node = (py_ctdb_node *)self;

	if (node->pnn == node->client->pnn) {
		Py_RETURN_TRUE;
	}

	Py_RETURN_FALSE;
}

static PyObject *py_ctdb_node_pnn(PyObject *self, void *closure)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	return Py_BuildValue("I", node->pnn);
}

static PyObject *py_ctdb_node_flags(PyObject *self, void *closure)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	PyObject *flags = NULL;
	PyObject *out = NULL;
	struct ctdb_node_and_flags *this_node = NULL;
	struct ctdb_node_map *nodemap = NULL;

	nodemap = get_nodemap(node->client, false);
	if (nodemap == NULL) {
		/* python error set in called function */
		return NULL;
	}

	this_node = get_node_by_pnn(nodemap, node->pnn);
	if (this_node == NULL) {
		PyErr_Format(
			PyExc_RuntimeError,
			"%u: node not found in current nodemap.",
			node->pnn
		);
		goto done;
	}

	flags = node_flags_to_list(this_node->flags);
	if (flags == NULL) {
		goto done;
	}

	out = Py_BuildValue(
		"{s:O,s:I}",
		"parsed", flags,
		"raw", this_node->flags
	);
	Py_XDECREF(flags);
done:
	TALLOC_FREE(nodemap);
	return out;
}

static PyObject *py_ctdb_node_addr(PyObject *self, void *closure)
{
	py_ctdb_node *node = (py_ctdb_node *)self;
	PyObject *out = NULL;
	struct ctdb_node_and_flags *this_node = NULL;
	struct ctdb_node_map *nodemap = NULL;

	nodemap = get_nodemap(node->client, false);
	if (nodemap == NULL) {
		/* python error set in called function */
		return NULL;
	}

	this_node = get_node_by_pnn(nodemap, node->pnn);
	if (this_node == NULL) {
		PyErr_Format(
			PyExc_RuntimeError,
			"%u: node not found in current nodemap.",
			node->pnn
		);
		goto done;
	}

	out = py_ctdb_sock_addr(&this_node->addr, false);
done:
	TALLOC_FREE(nodemap);
	return out;
}

static PyObject *py_ctdb_node_new(PyTypeObject *obj,
				  PyObject *args_unused,
				  PyObject *kwargs_unused)
{
	py_ctdb_node *self = NULL;

	self = (py_ctdb_node *)obj->tp_alloc(obj, 0);
	if (self == NULL) {
		return NULL;
	}
	self->pnn = CTDB_UNKNOWN_PNN;
	return (PyObject *)self;
}

static int py_ctdb_node_init(py_ctdb_node *self,
			     PyObject *args,
			     PyObject *kwargs_unused)
{
	PyObject *client_ctx = NULL;

	if (!PyArg_ParseTuple(args, "O", &client_ctx)) {
		return -1;
	}
	if (PyObject_IsInstance(client_ctx, (PyObject *)&PyCtdbClient) == 0) {
		PyErr_Format(
			PyExc_ValueError,
			"First argument must be ctdb.Client type\n"
		);
		return -1;
	}
	self->client = (py_ctdb_client_ctx *)client_ctx;
	Py_INCREF(self->client);

	return 0;
}

static void py_ctdb_node_dealloc(py_ctdb_node *self)
{
	Py_CLEAR(self->client);
	Py_CLEAR(self->sockaddr);
	Py_CLEAR(self->py_flags);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

#define MODULE_DOC "Clustered TDB client python bindings."

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "ctdb",
    .m_doc = MODULE_DOC,
    .m_size = -1,
    .m_methods = ctdb_module_methods,
};

PyObject* module_init(void);
PyObject* module_init(void)
{
	PyObject *m = NULL;

	talloc_stackframe();

	if (PyType_Ready(&PyCtdbClient) < 0)
		return NULL;

	if (PyType_Ready(&PyCtdbDB) < 0)
		return NULL;

	if (PyType_Ready(&PyCtdbDBEntry) < 0)
		return NULL;

	if (PyType_Ready(&PyCtdbNode) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		fprintf(stderr, "Failed to initialize module\n");
		return NULL;
	}

	/* Node flags */
	PyModule_AddIntConstant(m, "NODE_DISCONNECTED", NODE_FLAGS_DISCONNECTED);
	PyModule_AddIntConstant(m, "NODE_UNHEALTHY", NODE_FLAGS_UNHEALTHY);
	PyModule_AddIntConstant(m, "NODE_PERMANENTLY_DISABLED", NODE_FLAGS_PERMANENTLY_DISABLED);
	PyModule_AddIntConstant(m, "NODE_BANNED", NODE_FLAGS_BANNED);
	PyModule_AddIntConstant(m, "NODE_DELETED", NODE_FLAGS_DELETED);
	PyModule_AddIntConstant(m, "NODE_STOPPED", NODE_FLAGS_STOPPED);
	PyModule_AddIntConstant(m, "NODE_DISABLED", NODE_FLAGS_DISABLED);
	PyModule_AddIntConstant(m, "NODE_INACTIVE", NODE_FLAGS_INACTIVE);

	/* CTDB DB flags */
	PyModule_AddIntConstant(m, "DB_PERSISTENT", CTDB_DB_FLAGS_PERSISTENT);
	PyModule_AddIntConstant(m, "DB_READONLY", CTDB_DB_FLAGS_READONLY);
	PyModule_AddIntConstant(m, "DB_STICKY", CTDB_DB_FLAGS_STICKY);
	PyModule_AddIntConstant(m, "DB_REPLICATED", CTDB_DB_FLAGS_REPLICATED);

	/* CTDB Node Capabilities */
	PyModule_AddIntConstant(m, "CAP_RECMASTER", CTDB_CAP_RECMASTER);
	PyModule_AddIntConstant(m, "CAP_LMASTER", CTDB_CAP_LMASTER);

	/* CTDB runstate */
	PyModule_AddIntConstant(m, "RUNSTATE_UNKNOWN", CTDB_RUNSTATE_UNKNOWN);
	PyModule_AddIntConstant(m, "RUNSTATE_INIT", CTDB_RUNSTATE_INIT);
	PyModule_AddIntConstant(m, "RUNSTATE_SETUP", CTDB_RUNSTATE_SETUP);
	PyModule_AddIntConstant(m, "RUNSTATE_FIRST_RECOVERY", CTDB_RUNSTATE_FIRST_RECOVERY);
	PyModule_AddIntConstant(m, "RUNSTATE_STARTUP", CTDB_RUNSTATE_STARTUP);
	PyModule_AddIntConstant(m, "RUNSTATE_RUNNING", CTDB_RUNSTATE_RUNNING);
	PyModule_AddIntConstant(m, "RUNSTATE_SHUTDOWN", CTDB_RUNSTATE_SHUTDOWN);

	PyModule_AddIntConstant(m, "UNKNOWN_PNN", CTDB_UNKNOWN_PNN);

	PyModule_AddIntConstant(m, "REPLACE", TDB_REPLACE);
	PyModule_AddIntConstant(m, "INSERT", TDB_INSERT);
	PyModule_AddIntConstant(m, "MODIFY", TDB_MODIFY);

	PyModule_AddIntConstant(m, "DEFAULT", TDB_DEFAULT);
	PyModule_AddIntConstant(m, "CLEAR_IF_FIRST", TDB_CLEAR_IF_FIRST);
	PyModule_AddIntConstant(m, "INTERNAL", TDB_INTERNAL);
	PyModule_AddIntConstant(m, "NOLOCK", TDB_NOLOCK);
	PyModule_AddIntConstant(m, "NOMMAP", TDB_NOMMAP);
	PyModule_AddIntConstant(m, "CONVERT", TDB_CONVERT);
	PyModule_AddIntConstant(m, "BIGENDIAN", TDB_BIGENDIAN);
	PyModule_AddIntConstant(m, "NOSYNC", TDB_NOSYNC);
	PyModule_AddIntConstant(m, "SEQNUM", TDB_SEQNUM);
	PyModule_AddIntConstant(m, "VOLATILE", TDB_VOLATILE);
	PyModule_AddIntConstant(m, "ALLOW_NESTING", TDB_ALLOW_NESTING);
	PyModule_AddIntConstant(m, "DISALLOW_NESTING", TDB_DISALLOW_NESTING);
	PyModule_AddIntConstant(m, "INCOMPATIBLE_HASH", TDB_INCOMPATIBLE_HASH);

	PyModule_AddStringConstant(m, "__docformat__", "restructuredText");
	PyModule_AddStringConstant(m, "version", SAMBA_VERSION_STRING);

	Py_INCREF(&PyCtdbClient);
	PyModule_AddObject(m, "Client", (PyObject *)&PyCtdbClient);

	Py_INCREF(&PyCtdbDB);
	PyModule_AddObject(m, "Ctdb", (PyObject *)&PyCtdbDB);

	return m;
}

PyMODINIT_FUNC PyInit_ctdb(void)
{
    return module_init();
}
