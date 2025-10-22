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

static int
pyctbd_clear(PyObject *m)
{
	pyctdb_mod_state_t *state = NULL;

	if (m == NULL) {
		return 0;
	}

	state = pycdb_get_state(m);
	PYCLEAR_MOD_STATE(state);
	return 0;
}

static void
pyctdb_free(void *m)
{
	pyctdb_clear((PyObject *)m);
}

PyDoc_STRVAR(pyctdb_get_global_locking__doc__,
"get_global_locking() -> bool\n"
"----------------------------\n"
"Get the current global locking state for the pyctdb module.\n"
"When global locking is enabled, then each ctdb client operation will be\n"
"serialized behind a global pthread mutex for the module. The primary\n"
"reason why global locking would be enabled is that the user has enabled\n"
"the talloc library feature to generate a leak report on close.\n"
);
static PyObject *pyctdb_get_global_locking(PyObject *self, PyObject *unused)
{
	if (glock_enabled) {
		Py_RETURN_TRUE;
	} else {
		Py_RETURN_FALSE;
	}
}

PyDoc_STRVAR(pyctdb_get_global_locking__doc__,
"set_global_locking(value: bool) -> bool\n"
"---------------------------------------\n"
"Set the global locking behavior for ctdb client operations. \n"
"See discussion in `get_global_locking()` for explanation of feature.\n"
"\n"
"Once leak reporting has been enabled, this feature may no longer be\n"
"disabled for the module.\n"
);
static PyObject *pyctdb_set_global_locking(PyObject *self, PyObject *args)
{
	bool enable = false;

	if (PyArg_ParseTuple(args, "p", &enable) < 0) {
		return NULL;
	}

	if (leak_reporting_enabled) {
		PyErr_SetString(PyExc_ValueError,
				"value may not be changed once "
				"leak reporting has been enabled.");
		return NULL;
	}

	glock_enabled = enable;

	if (enable) {
		Py_RETURN_TRUE;
	} else {
		Py_RETURN_FALSE;
	}
}

PyDoc_STRVAR(pyctdb_get_leakreporting__doc__,
"get_leak_reporting() -> bool\n"
"----------------------------\n"
"Return boolean indicating whether leak reporting for the python module\n"
"is enabled. This is a developer-oriented module feature to aid in tracking\n"
"talloc library memory usage at program exit.\n"
);
static PyObject *pyctdb_get_leakreporting(PyObject *self, PyObject *unused)
{
	if (leak_reporting_enabled) {
		Py_RETURN_TRUE;
	} else {
		Py_RETURN_FALSE;
	}
}

PyDoc_STRVAR(pyctdb_enable_leakreporting__doc__,
"enable_leak_reporting() -> None\n"
"-------------------------------\n"
"Enable talloc leak report for this module on program exit. This is a\n"
"developer-oriented feature that should not be used in production scripts.\n"
);
static PyObject *pyctdb_enable_leakreporting(PyObject *self, PyObject *args)
{
	leak_reporting_enabled = true;
	glock_enabled = true;
	talloc_enable_leak_report_full();
	Py_RETURN_NONE;
}

static PyMethodDef pyctdb_module_methods[] = {
	{
		.ml_name = "get_global_locking",
		.ml_meth = (PyCFunction)pyctdb_get_global_locking,
		.ml_flags = METH_NOARGS,
		.ml_doc = pyctdb_get_global_locking__doc__,
	},
	{
		.ml_name = "set_global_locking",
		.ml_meth = (PyCFunction)pyctdb_set_global_locking,
		.ml_flags = METH_VARARGS,
		.ml_doc = pyctdb_set_global_locking__doc__,
	},
	{
		.ml_name = "get_leak_reporting",
		.ml_meth = (PyCFunction)pyctdb_get_leakreporting,
		.ml_flags = METH_NOARGS,
		.ml_doc = pyctdb_get_leakreporting__doc__,
	},
	{
		.ml_name = "enable_leak_reporting",
		.ml_meth = (PyCFunction)pyctdb_enable_leakreporting,
		.ml_flags = METH_NOARGS,
		.ml_doc = pyctdb_enable_leakreporting__doc__,
	},
	{ NULL, NULL, 0, NULL }
};

PyDoc_STRVAR(pyctdb_module_doc,
"CTDB client cpython extension. \n"
"\n"
"This provides basic functionality to view the status of CTDB nodes and\n"
"databases as well as perform basic administrative actions on the CTDB\n"
"cluster.\n"
);

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = PYMODULE_NAME,
    .m_doc = pyctdb_module_doc,
    .m_size = sizeof(pyctdb_mod_state_t),
    .m_clear = pyctdb_clear,
    .m_free = pyctdb_free,
    .m_methods = pyctdb_module_methods,
};

/* Get the module state. NULL for module_in is OK, but less efficient */
pyctdb_state_t *pyctdb_get_state(PyObject *module_in)
{
	PyObject *modref = module_in;
	pyctdb_state_t *state = NULL;

	if (modref == NULL) {
		modref = PyState_FindModule(&moduledef);
		PYCTDB_ASSERT((modref != NULL), "Failed to get module");
	}

	state = (pyctdb_state_t *)PyModule_GetState(modref);
	PYCTDB_ASSERT((state != NULL), "Failed to get module state");
	return state;
}

PyObject* module_init(void);
PyObject* module_init(void)
{
	PyObject *m = NULL;

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

	Py_INCREF(&PyCtdbClient);
	PyModule_AddObject(m, "Client", (PyObject *)&PyCtdbClient);

	Py_INCREF(&PyCtdbDB);
	PyModule_AddObject(m, "Ctdb", (PyObject *)&PyCtdbDB);

	return m;
}

PyMODINIT_FUNC PyInit_pyctdb(void)
{
    return module_init();
}
