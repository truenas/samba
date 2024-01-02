/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright © Jelmer Vernooij <jelmer@samba.org> 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "lib/replace/system/python.h"
#include "includes.h"
#include "python/py3compat.h"
#include "libcli/util/pyerrors.h"
#include "python/modules.h"
#include "../libcli/nbt/libnbt.h"
#include "lib/events/events.h"

void initnetbios(void);

extern PyTypeObject nbt_node_Type;

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct nbt_name_socket *socket;
} nbt_node_Object;

static void py_nbt_node_dealloc(nbt_node_Object *self)
{
	talloc_free(self->mem_ctx);
	Py_TYPE(self)->tp_free(self);
}

static PyObject *py_nbt_node_init(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	struct tevent_context *ev;
	nbt_node_Object *ret = PyObject_New(nbt_node_Object, &nbt_node_Type);

	ret->mem_ctx = talloc_new(NULL);
	if (ret->mem_ctx == NULL)
		return NULL;

	ev = s4_event_context_init(ret->mem_ctx);
	ret->socket = nbt_name_socket_init(ret->mem_ctx, ev);
	return (PyObject *)ret;
}

static bool PyObject_AsDestinationTuple(PyObject *obj, const char **dest_addr, uint16_t *dest_port)
{
	if (PyUnicode_Check(obj)) {
		*dest_addr = PyUnicode_AsUTF8(obj);
		*dest_port = NBT_NAME_SERVICE_PORT;
		return true;
	}

	if (PyTuple_Check(obj)) {
		if (PyTuple_Size(obj) < 1) {
			PyErr_SetString(PyExc_TypeError, "Destination tuple size invalid");
			return false;
		}

		if (!PyUnicode_Check(PyTuple_GetItem(obj, 0))) {
			PyErr_SetString(PyExc_TypeError, "Destination tuple first element not string");
			return false;
		}

		*dest_addr = PyUnicode_AsUTF8(obj);

		if (PyTuple_Size(obj) == 1) {
			*dest_port = NBT_NAME_SERVICE_PORT;
			return true;
		} else if (PyLong_Check(PyTuple_GetItem(obj, 1))) {
			*dest_port = PyLong_AsLong(PyTuple_GetItem(obj, 1));
			return true;
		} else {
			PyErr_SetString(PyExc_TypeError, "Destination tuple second element not a port");
			return false;
		}
	}

	PyErr_SetString(PyExc_TypeError, "Destination tuple second element not a port");
	return false;
}

static bool PyObject_AsNBTName(PyObject *obj, struct nbt_name_socket *name_socket, struct nbt_name *name)
{
	if (PyTuple_Check(obj)) {
		if (PyTuple_Size(obj) == 2) {
			name->name = PyUnicode_AsUTF8(PyTuple_GetItem(obj, 0));
			if (name->name == NULL) {
				goto err;
			}
			name->type = PyLong_AsLong(PyTuple_GetItem(obj, 1));
			if (name->type == -1 && PyErr_Occurred()) {
				goto err;
			}
			name->scope = NULL;
			return true;
		} else if (PyTuple_Size(obj) == 3) {
			name->name = PyUnicode_AsUTF8(PyTuple_GetItem(obj, 0));
			if (name->name == NULL) {
				goto err;
			}
			name->scope = PyUnicode_AsUTF8(PyTuple_GetItem(obj, 1));
			if (name->scope == NULL) {
				goto err;
			}
			name->type = PyLong_AsLong(PyTuple_GetItem(obj, 2));
			if (name->type == -1 && PyErr_Occurred()) {
				goto err;
			}
			return true;
		} else {
			PyErr_SetString(PyExc_TypeError, "Invalid tuple size");
			return false;
		}
	}

	if (PyUnicode_Check(obj)) {
		/* FIXME: Parse string to be able to interpret things like RHONWYN<02> ? */
		name->name = PyUnicode_AsUTF8(obj);
		if (name->name == NULL) {
			goto err;
		}
		name->scope = NULL;
		name->type = 0;
		return true;
	}
err:
	PyErr_SetString(PyExc_TypeError, "Invalid type for object");
	return false;
}

static PyObject *PyObject_FromNBTName(struct nbt_name_socket *name_socket, 
				      struct nbt_name *name)
{
	if (name->scope) {
		return Py_BuildValue("(ssi)", name->name, name->scope, name->type);
	} else {
		return Py_BuildValue("(si)", name->name, name->type);
	}
}

static PyObject *py_nbt_name_query(PyObject *self, PyObject *args, PyObject *kwargs)
{
	nbt_node_Object *node = (nbt_node_Object *)self;
	PyObject *ret, *reply_addrs, *py_dest, *py_name;
	struct nbt_name_query io;
	NTSTATUS status;
	int i;

	const char *kwnames[] = { "name", "dest", "broadcast", "wins", "timeout",
				  "retries", NULL };
	io.in.broadcast = true;
	io.in.wins_lookup = false;
	io.in.timeout = 0;
	io.in.retries = 3;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|bbii:query_name",
					 discard_const_p(char *, kwnames),
					 &py_name, &py_dest,
					 &io.in.broadcast, &io.in.wins_lookup,
					 &io.in.timeout, &io.in.retries)) {
		return NULL;
	}

	if (!PyObject_AsDestinationTuple(py_dest, &io.in.dest_addr, &io.in.dest_port))
		return NULL;

	if (!PyObject_AsNBTName(py_name, node->socket, &io.in.name))
		return NULL;

	status = nbt_name_query(node->socket, NULL, &io);

	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	ret = PyTuple_New(3);
	if (ret == NULL)
		return NULL;
	PyTuple_SetItem(ret, 0, PyUnicode_FromString(io.out.reply_from));

	py_name = PyObject_FromNBTName(node->socket, &io.out.name);
	if (py_name == NULL)
		return NULL;

	PyTuple_SetItem(ret, 1, py_name);

	reply_addrs = PyList_New(io.out.num_addrs);
	if (reply_addrs == NULL) {
		Py_DECREF(ret);
		return NULL;
	}

	for (i = 0; i < io.out.num_addrs; i++) {
		PyList_SetItem(reply_addrs, i, PyUnicode_FromString(io.out.reply_addrs[i]));
	}

	PyTuple_SetItem(ret, 2, reply_addrs);
	return ret;
}

static PyObject *py_nbt_name_status(PyObject *self, PyObject *args, PyObject *kwargs)
{
	nbt_node_Object *node = (nbt_node_Object *)self;
	PyObject *ret, *py_dest, *py_name, *py_names;
	struct nbt_name_status io;
	int i;
	NTSTATUS status;

	const char *kwnames[] = { "name", "dest", "timeout", "retries", NULL };

	io.in.timeout = 0;
	io.in.retries = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|ii:name_status",
					 discard_const_p(char *, kwnames),
					 &py_name, &py_dest,
					 &io.in.timeout, &io.in.retries)) {
		return NULL;
	}

	if (!PyObject_AsDestinationTuple(py_dest, &io.in.dest_addr, &io.in.dest_port))
		return NULL;

	if (!PyObject_AsNBTName(py_name, node->socket, &io.in.name))
		return NULL;

	status = nbt_name_status(node->socket, NULL, &io);

	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	ret = PyTuple_New(3);
	if (ret == NULL)
		return NULL;
	PyTuple_SetItem(ret, 0, PyUnicode_FromString(io.out.reply_from));

	py_name = PyObject_FromNBTName(node->socket, &io.out.name);
	if (py_name == NULL)
		return NULL;

	PyTuple_SetItem(ret, 1, py_name);

	py_names = PyList_New(io.out.status.num_names);

	for (i = 0; i < io.out.status.num_names; i++) {
		PyList_SetItem(py_names, i, Py_BuildValue("(sii)",
				io.out.status.names[i].name,
				io.out.status.names[i].nb_flags,
				io.out.status.names[i].type));
	}

	PyTuple_SetItem(ret, 2, py_names);

	return ret;
}

static PyObject *py_nbt_name_register(PyObject *self, PyObject *args, PyObject *kwargs)
{
	nbt_node_Object *node = (nbt_node_Object *)self;
	PyObject *ret, *py_dest, *py_name;
	struct nbt_name_register io;
	NTSTATUS status;

	const char *kwnames[] = { "name", "address", "dest", "register_demand", "broadcast",
		                  "multi_homed", "ttl", "timeout", "retries", NULL };

	io.in.broadcast = true;
	io.in.multi_homed = true;
	io.in.register_demand = true;
	io.in.ttl = 0;
	io.in.timeout = 0;
	io.in.retries = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OsO|bbbiii:query_name",
					 discard_const_p(char *, kwnames),
					 &py_name, &io.in.address, &py_dest,
					 &io.in.register_demand,
					 &io.in.broadcast, &io.in.multi_homed,
					 &io.in.ttl, &io.in.timeout, &io.in.retries)) {
		return NULL;
	}

	if (!PyObject_AsDestinationTuple(py_dest, &io.in.dest_addr, &io.in.dest_port))
		return NULL;

	if (!PyObject_AsNBTName(py_name, node->socket, &io.in.name))
		return NULL;

	status = nbt_name_register(node->socket, NULL, &io);

	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	ret = PyTuple_New(4);
	if (ret == NULL)
		return NULL;
	PyTuple_SetItem(ret, 0, PyUnicode_FromString(io.out.reply_from));

	py_name = PyObject_FromNBTName(node->socket, &io.out.name);
	if (py_name == NULL)
		return NULL;

	PyTuple_SetItem(ret, 1, py_name);

	PyTuple_SetItem(ret, 2, PyUnicode_FromString(io.out.reply_addr));

	PyTuple_SetItem(ret, 3, PyLong_FromLong(io.out.rcode));

	return ret;
}

static PyObject *py_nbt_name_refresh(PyObject *self, PyObject *args, PyObject *kwargs)
{
	nbt_node_Object *node = (nbt_node_Object *)self;
	PyObject *ret, *py_dest, *py_name;
	struct nbt_name_refresh io;
	NTSTATUS status;

	const char *kwnames[] = { "name", "address", "dest", "nb_flags", "broadcast",
		                  "ttl", "timeout", "retries", NULL };

	io.in.broadcast = true;
	io.in.nb_flags = 0;
	io.in.ttl = 0;
	io.in.timeout = 0;
	io.in.retries = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OsO|ibiii:query_name",
					 discard_const_p(char *, kwnames),
					 &py_name, &io.in.address, &py_dest,
					 &io.in.nb_flags,
					 &io.in.broadcast,
					 &io.in.ttl, &io.in.timeout, &io.in.retries)) {
		return NULL;
	}

	if (!PyObject_AsDestinationTuple(py_dest, &io.in.dest_addr, &io.in.dest_port))
		return NULL;

	if (!PyObject_AsNBTName(py_name, node->socket, &io.in.name))
		return NULL;

	status = nbt_name_refresh(node->socket, NULL, &io);

	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	ret = PyTuple_New(3);
	if (ret == NULL)
		return NULL;
	PyTuple_SetItem(ret, 0, PyUnicode_FromString(io.out.reply_from));

	py_name = PyObject_FromNBTName(node->socket, &io.out.name);
	if (py_name == NULL)
		return NULL;

	PyTuple_SetItem(ret, 1, py_name);

	PyTuple_SetItem(ret, 2, PyUnicode_FromString(io.out.reply_addr));

	PyTuple_SetItem(ret, 3, PyLong_FromLong(io.out.rcode));

	return ret;
}

static PyObject *py_nbt_name_release(PyObject *self, PyObject *args, PyObject *kwargs)
{
	Py_RETURN_NONE; /* FIXME */
}

static PyMethodDef py_nbt_methods[] = {
	{ "query_name", PY_DISCARD_FUNC_SIG(PyCFunction, py_nbt_name_query),
		METH_VARARGS|METH_KEYWORDS,
		"S.query_name(name, dest, broadcast=True, wins=False, timeout=0, retries=3) -> (reply_from, name, reply_addr)\n"
		"Query for a NetBIOS name" },
	{ "register_name", PY_DISCARD_FUNC_SIG(PyCFunction,
					       py_nbt_name_register),
		METH_VARARGS|METH_KEYWORDS,
		"S.register_name(name, address, dest, register_demand=True, broadcast=True, multi_homed=True, ttl=0, timeout=0, retries=0) -> (reply_from, name, reply_addr, rcode)\n"
		"Register a new name" },
	{ "release_name", PY_DISCARD_FUNC_SIG(PyCFunction, py_nbt_name_release),
		METH_VARARGS|METH_KEYWORDS, "S.release_name(name, address, dest, nb_flags=0, broadcast=true, timeout=0, retries=3) -> (reply_from, name, reply_addr, rcode)\n"
		"release a previously registered name" },
	{ "refresh_name", PY_DISCARD_FUNC_SIG(PyCFunction, py_nbt_name_refresh),
		METH_VARARGS|METH_KEYWORDS, "S.refresh_name(name, address, dest, nb_flags=0, broadcast=True, ttl=0, timeout=0, retries=0) -> (reply_from, name, reply_addr, rcode)\n"
		"release a previously registered name" },
	{ "name_status", PY_DISCARD_FUNC_SIG(PyCFunction, py_nbt_name_status),
		METH_VARARGS|METH_KEYWORDS,
		"S.name_status(name, dest, timeout=0, retries=0) -> (reply_from, name, status)\n"
		"Find the status of a name" },

	{0}
};

PyTypeObject nbt_node_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "netbios.Node",
	.tp_basicsize = sizeof(nbt_node_Object),
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
	.tp_new = py_nbt_node_init,
	.tp_dealloc = (destructor)py_nbt_node_dealloc,
	.tp_methods = py_nbt_methods,
	.tp_doc = "Node()\n"
		  "Create a new NetBIOS node\n"
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "netbios",
    .m_doc = "NetBIOS over TCP/IP support",
    .m_size = -1,
    .m_methods = NULL,
};

MODULE_INIT_FUNC(netbios)
{
	PyObject *mod = NULL;
	if (PyType_Ready(&nbt_node_Type) < 0)
		return mod;

	mod = PyModule_Create(&moduledef);


	Py_INCREF((PyObject *)&nbt_node_Type);
	PyModule_AddObject(mod, "Node", (PyObject *)&nbt_node_Type);
	return mod;
}
