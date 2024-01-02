/*
 *  Unix SMB/CIFS implementation.
 *  Python bindings for libpolicy
 *  Copyright (C) Jelmer Vernooij 2010
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "lib/replace/system/python.h"
#include "includes.h"
#include "python/py3compat.h"
#include "policy.h"
#include "libcli/util/pyerrors.h"

void initpolicy(void);

static PyObject *py_get_gpo_flags(PyObject *self, PyObject *args)
{
	int flags;
	PyObject *py_ret;
	const char **ret;
	TALLOC_CTX *mem_ctx;
	int i;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "i", &flags))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = gp_get_gpo_flags(mem_ctx, flags, &ret);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}

	py_ret = PyList_New(0);
	for (i = 0; ret[i]; i++) {
		int res = 0;
		PyObject *item = PyUnicode_FromString(ret[i]);
		if (item == NULL) {
			talloc_free(mem_ctx);
			Py_DECREF(py_ret);
			PyErr_NoMemory();
			return NULL;
		}
		res = PyList_Append(py_ret, item);
		Py_CLEAR(item);
		if (res == -1) {
			Py_DECREF(py_ret);
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	talloc_free(mem_ctx);

	return py_ret;
}

static PyObject *py_get_gplink_options(PyObject *self, PyObject *args)
{
	int flags;
	PyObject *py_ret;
	const char **ret;
	TALLOC_CTX *mem_ctx;
	int i;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "i", &flags))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = gp_get_gplink_options(mem_ctx, flags, &ret);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}

	py_ret = PyList_New(0);
	for (i = 0; ret[i]; i++) {
		int res = 0;
		PyObject *item = PyUnicode_FromString(ret[i]);
		if (item == NULL) {
			talloc_free(mem_ctx);
			Py_DECREF(py_ret);
			PyErr_NoMemory();
			return NULL;
		}
		res = PyList_Append(py_ret, item);
		Py_CLEAR(item);
		if (res == -1) {
			Py_DECREF(py_ret);
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	talloc_free(mem_ctx);

	return py_ret;
}

static PyObject *py_ads_to_dir_access_mask(PyObject *self, PyObject *args)
{
	uint32_t access_mask, dir_mask;

	if (! PyArg_ParseTuple(args, "I", &access_mask))
		return NULL;

	dir_mask = gp_ads_to_dir_access_mask(access_mask);

	return Py_BuildValue("I", dir_mask);
}


static PyMethodDef py_policy_methods[] = {
	{ "get_gpo_flags", (PyCFunction)py_get_gpo_flags, METH_VARARGS,
		"get_gpo_flags(flags) -> list" },
	{ "get_gplink_options", (PyCFunction)py_get_gplink_options, METH_VARARGS,
		"get_gplink_options(options) -> list" },
	{ "ads_to_dir_access_mask", (PyCFunction)py_ads_to_dir_access_mask, METH_VARARGS,
		"ads_to_dir_access_mask(access_mask) -> dir_mask" },
	{0}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "policy",
    .m_doc = "(Group) Policy manipulation",
    .m_size = -1,
    .m_methods = py_policy_methods,
};

MODULE_INIT_FUNC(policy)
{
	PyObject *m = NULL;

	m = PyModule_Create(&moduledef);
	if (!m)
		return m;

	PyModule_AddObject(m, "GPO_FLAG_USER_DISABLE",
					   PyLong_FromLong(GPO_FLAG_USER_DISABLE));
	PyModule_AddObject(m, "GPO_MACHINE_USER_DISABLE",
					   PyLong_FromLong(GPO_FLAG_MACHINE_DISABLE));
	PyModule_AddObject(m, "GPLINK_OPT_DISABLE",
					   PyLong_FromLong(GPLINK_OPT_DISABLE ));
	PyModule_AddObject(m, "GPLINK_OPT_ENFORCE ",
					   PyLong_FromLong(GPLINK_OPT_ENFORCE ));
	return m;
}
