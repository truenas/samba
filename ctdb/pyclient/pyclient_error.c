// SPDX-License-Identifier: LGPL-3.0-or-later
#include <string.h>
#include "pyclient.h"

PyDoc_STRVAR(py_ctdb_exception__doc__,
"CTDBError(Exception)\n"
"-----------------------\n\n"
"Python wrapper around an unexpected CTDB response.\n\n"
"attributes:\n"
"-----------\n"
"errno: int\n"
"    Errno returned by the CTDB client\n"
"err_str: str\n"
"    strerror() of the errno\n"
"message: str\n"
"    verbose message describing the error\n"
"location: str\n"
"    line of file in uncompiled source of this module\n\n"
);
bool setup_ctdb_exception(PyObject *module_ref)
{
	pyctdb_mod_state_t *state = NULL;
	PyObject *ctdb_error = NULL;
	PyObject *dict = NULL;
	bool success = false;

	// Set up spec for the new exception type
	dict = Py_BuildValue("{s:i,s:s,s:s,s:s}",
			     "code", 0,
			     "err_str", "",
			     "message", "",
			     "location", "");
	if (dict == NULL) {
		goto cleanup;
	}

	ctdb_error = PyErr_NewExceptionWithDoc(PYMODULE_NAME
					       ".CTDBError",
					       py_ctdb_exception__doc__,
					       PyExc_RuntimeError,
					       dict);
	if (ctdb_error == NULL) {
		goto cleanup;
	}

	state = pyctdb_get_state(module_ref);
	if (state == NULL) {
		goto cleanup;
	}

	// Add reference to our module state so that it's available generally
	// for implementation in this extension
	state->py_ctdb_error = Py_NewRef(ctdb_error);

	// Add exception reference to root of module so that it's available
	// to library consumers
	if (PyModule_AddObjectRef(module_ref, "CTDBError", ctdb_error) < 0) {
		goto cleanup;
	}

	success = true;

cleanup:
	Py_CLEAR(dict);
	Py_CLEAR(ctdb_error);
	return success;
}

void
_set_ctdb_exc(int code, const char *additional_info, const char *location)
{
	pyctdb_mod_state_t *state = NULL;
	PyObject *obj = NULL;
	PyObject *exc = NULL;
	PyObject *message = NULL;
	const char *err_str = strerror(code);

	state = pyctdb_get_state(NULL);

	// first set up str() for exception
	message = PyUnicode_FromFormat("[%d]: %s", code, additional_info);
	if (message == NULL) {
		return;
	}

	PYCTDB_ASSERT((state->py_ctdb_error != NULL), "Error not initialized");
	exc = PyObject_CallOneArg(state->py_ctdb_error, message);
	Py_CLEAR(message);
	if (exc == NULL) {
		return;
	}

	// Create integer object for the code value
	obj = PyLong_FromLong(code);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "errno", obj);
	Py_CLEAR(obj);

	/* set err_str */
	obj = PyUnicode_FromString(err_str);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "err_str", obj);
	Py_CLEAR(obj);

	/* set message */
	obj = PyUnicode_FromString(additional_info);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "message", obj);
	Py_CLEAR(obj);

	/* set location */
	obj = PyUnicode_FromString(location);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "location", obj);
	Py_CLEAR(obj);

	PyErr_SetObject(state->py_ctdb_error, exc);
	Py_DECREF(exc);
}

void
_pyctdb_set_error(pyctdb_error_t *error, int error_code, const char *fmt,
		  const char *location, ...)
{
        va_list args;
        int offset = 0;

        if (!error || !fmt) {
		abort();
        }

        va_start(args, location);
        offset = vsnprintf(error->message, sizeof(error->message), fmt, args);
        va_end(args);

        if (offset > 0 && (size_t)offset < sizeof(error->message) - 1) {
                snprintf(error->message + offset, sizeof(error->message) - offset,
                        " [%s]", location);
        }

	error->code = error_code;
}
