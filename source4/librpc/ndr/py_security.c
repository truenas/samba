/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008-2010
   
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
#include <Python.h>
#include "py3compat.h"
#include "libcli/security/sddl.h"
#include "libcli/security/security.h"

static void PyType_AddMethods(PyTypeObject *type, PyMethodDef *methods)
{
	PyObject *dict;
	int i;
	if (type->tp_dict == NULL)
		type->tp_dict = PyDict_New();
	dict = type->tp_dict;
	for (i = 0; methods[i].ml_name; i++) {
		PyObject *descr;
		if (methods[i].ml_flags & METH_CLASS) 
			descr = PyCFunction_New(&methods[i], (PyObject *)type);
		else 
			descr = PyDescr_NewMethod(type, &methods[i]);
		PyDict_SetItemString(dict, methods[i].ml_name, 
				     descr);
		Py_CLEAR(descr);
	}
}

static PyObject *py_dom_sid_split(PyObject *py_self, PyObject *args)
{
	struct dom_sid *self = pytalloc_get_ptr(py_self);
	struct dom_sid *domain_sid;
	TALLOC_CTX *mem_ctx;
	uint32_t rid;
	NTSTATUS status;
	PyObject *py_domain_sid;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = dom_sid_split_rid(mem_ctx, self, &domain_sid, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetString(PyExc_RuntimeError, "dom_sid_split_rid failed");
		talloc_free(mem_ctx);
		return NULL;
	}

	py_domain_sid = pytalloc_steal(&dom_sid_Type, domain_sid);
	talloc_free(mem_ctx);
	return Py_BuildValue("(OI)", py_domain_sid, rid);
}

#if PY_MAJOR_VERSION >= 3
static PyObject *py_dom_sid_richcmp(PyObject *py_self, PyObject *py_other, int op)
{
	struct dom_sid *self = pytalloc_get_ptr(py_self), *other;
	int val;

	other = pytalloc_get_ptr(py_other);
	if (other == NULL) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}

	val =  dom_sid_compare(self, other);

	switch (op) {
			case Py_EQ: if (val == 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
			case Py_NE: if (val != 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
			case Py_LT: if (val <  0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
			case Py_GT: if (val >  0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
			case Py_LE: if (val <= 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
			case Py_GE: if (val >= 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
	}
	Py_INCREF(Py_NotImplemented);
	return Py_NotImplemented;
}
#else
static int py_dom_sid_cmp(PyObject *py_self, PyObject *py_other)
{
	struct dom_sid *self = pytalloc_get_ptr(py_self), *other;
	int val;

	other = pytalloc_get_ptr(py_other);
	if (other == NULL)
		return -1;

	val =  dom_sid_compare(self, other);
	if (val > 0) {
		return 1;
	} else if (val < 0) {
		return -1;
	}
	return 0;
}
#endif

static PyObject *py_dom_sid_str(PyObject *py_self)
{
	struct dom_sid *self = pytalloc_get_ptr(py_self);
	struct dom_sid_buf buf;
	PyObject *ret = PyUnicode_FromString(dom_sid_str_buf(self, &buf));
	return ret;
}

static PyObject *py_dom_sid_repr(PyObject *py_self)
{
	struct dom_sid *self = pytalloc_get_ptr(py_self);
	struct dom_sid_buf buf;
	PyObject *ret = PyUnicode_FromFormat(
		"dom_sid('%s')", dom_sid_str_buf(self, &buf));
	return ret;
}

static int py_dom_sid_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *str = NULL;
	struct dom_sid *sid = pytalloc_get_ptr(self);
	const char *kwnames[] = { "str", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", discard_const_p(char *, kwnames), &str))
		return -1;

	if (str != NULL && !dom_sid_parse(str, sid)) {
		PyErr_SetString(PyExc_TypeError, "Unable to parse string");
		return -1;
	}

	return 0;
}

static PyMethodDef py_dom_sid_extra_methods[] = {
	{ "split", (PyCFunction)py_dom_sid_split, METH_NOARGS,
		"S.split() -> (domain_sid, rid)\n"
		"Split a domain sid" },
	{0}
};


static void py_dom_sid_patch(PyTypeObject *type)
{
	type->tp_init = py_dom_sid_init;
	type->tp_str = py_dom_sid_str;
	type->tp_repr = py_dom_sid_repr;
#if PY_MAJOR_VERSION >= 3
	type->tp_richcompare = py_dom_sid_richcmp;
#else
	type->tp_compare = py_dom_sid_cmp;
#endif
	PyType_AddMethods(type, py_dom_sid_extra_methods);
}

#define PY_DOM_SID_PATCH py_dom_sid_patch

static PyObject *py_descriptor_sacl_add(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = pytalloc_get_ptr(self);
	NTSTATUS status;
	struct security_ace *ace;
	PyObject *py_ace;
	Py_ssize_t idx = -1;

	if (!PyArg_ParseTuple(args, "O|n", &py_ace, &idx))
		return NULL;

	ace = pytalloc_get_ptr(py_ace);
	status = security_descriptor_sacl_insert(desc, ace, idx);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	Py_RETURN_NONE;
}

static PyObject *py_descriptor_dacl_add(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = pytalloc_get_ptr(self);
	NTSTATUS status;
	struct security_ace *ace;
	PyObject *py_ace;
	Py_ssize_t idx = -1;

	if (!PyArg_ParseTuple(args, "O|n", &py_ace, &idx))
		return NULL;

	ace = pytalloc_get_ptr(py_ace);

	status = security_descriptor_dacl_insert(desc, ace, idx);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	Py_RETURN_NONE;
}

static PyObject *py_descriptor_dacl_del(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = pytalloc_get_ptr(self);
	NTSTATUS status;
	struct dom_sid *sid;
	PyObject *py_sid;

	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = pytalloc_get_ptr(py_sid);
	status = security_descriptor_dacl_del(desc, sid);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	Py_RETURN_NONE;
}

static PyObject *py_descriptor_sacl_del(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = pytalloc_get_ptr(self);
	NTSTATUS status;
	struct dom_sid *sid;
	PyObject *py_sid;

	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = pytalloc_get_ptr(py_sid);
	status = security_descriptor_sacl_del(desc, sid);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	Py_RETURN_NONE;
}

static PyObject *py_descriptor_dacl_del_ace(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = pytalloc_get_ptr(self);
	NTSTATUS status;
	struct security_ace *ace = NULL;
	PyObject *py_ace = Py_None;

	if (!PyArg_ParseTuple(args, "O!", &security_ace_Type, &py_ace))
		return NULL;

	if (!PyObject_TypeCheck(py_ace, &security_ace_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"expected security.security_ace "
				"for first argument to .dacl_del_ace");
		return NULL;
	}

	ace = pytalloc_get_ptr(py_ace);
	status = security_descriptor_dacl_del_ace(desc, ace);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	Py_RETURN_NONE;
}

static PyObject *py_descriptor_sacl_del_ace(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = pytalloc_get_ptr(self);
	NTSTATUS status;
	struct security_ace *ace = NULL;
	PyObject *py_ace = Py_None;

	if (!PyArg_ParseTuple(args, "O!", &security_ace_Type, &py_ace))
		return NULL;

	if (!PyObject_TypeCheck(py_ace, &security_ace_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"expected security.security_ace "
				"for first argument to .sacl_del_ace");
		return NULL;
	}

	ace = pytalloc_get_ptr(py_ace);
	status = security_descriptor_sacl_del_ace(desc, ace);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	Py_RETURN_NONE;
}

static PyObject *py_descriptor_new(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	return pytalloc_steal(self, security_descriptor_initialise(NULL));
}

static PyObject *py_descriptor_from_sddl(PyObject *self, PyObject *args)
{
	struct security_descriptor *secdesc;
	char *sddl;
	PyObject *py_sid;
	struct dom_sid *sid;

	if (!PyArg_ParseTuple(args, "sO!", &sddl, &dom_sid_Type, &py_sid))
		return NULL;

	if (!PyObject_TypeCheck(py_sid, &dom_sid_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"expected security.dom_sid "
				"for second argument to .from_sddl");
		return NULL;
	}

	sid = pytalloc_get_ptr(py_sid);

	secdesc = sddl_decode(NULL, sddl, sid);
	if (secdesc == NULL) {
		PyErr_SetString(PyExc_TypeError, "Unable to parse SDDL");
		return NULL;
	}

	return pytalloc_steal((PyTypeObject *)self, secdesc);
}

static PyObject *py_descriptor_as_sddl(PyObject *self, PyObject *args)
{
	struct dom_sid *sid;
	PyObject *py_sid = Py_None;
	struct security_descriptor *desc = pytalloc_get_ptr(self);
	char *text;
	PyObject *ret;

	if (!PyArg_ParseTuple(args, "|O!", &dom_sid_Type, &py_sid))
		return NULL;

	if (py_sid != Py_None)
		sid = pytalloc_get_ptr(py_sid);
	else
		sid = NULL;

	text = sddl_encode(NULL, desc, sid);

	ret = PyUnicode_FromString(text);

	talloc_free(text);

	return ret;
}

static PyMethodDef py_descriptor_extra_methods[] = {
	{ "sacl_add", (PyCFunction)py_descriptor_sacl_add, METH_VARARGS,
		"S.sacl_add(ace) -> None\n"
		"Add a security ace to this security descriptor" },
	{ "dacl_add", (PyCFunction)py_descriptor_dacl_add, METH_VARARGS,
		NULL },
	{ "dacl_del", (PyCFunction)py_descriptor_dacl_del, METH_VARARGS,
		NULL },
	{ "sacl_del", (PyCFunction)py_descriptor_sacl_del, METH_VARARGS,
		NULL },
	{ "dacl_del_ace", (PyCFunction)py_descriptor_dacl_del_ace, METH_VARARGS,
		NULL },
	{ "sacl_del_ace", (PyCFunction)py_descriptor_sacl_del_ace, METH_VARARGS,
		NULL },
	{ "from_sddl", (PyCFunction)py_descriptor_from_sddl, METH_VARARGS|METH_CLASS,
		NULL },
	{ "as_sddl", (PyCFunction)py_descriptor_as_sddl, METH_VARARGS,
		NULL },
	{0}
};

static PyObject *py_descriptor_richcmp(
	PyObject *py_self, PyObject *py_other, int op)
{
	struct security_descriptor *self = pytalloc_get_ptr(py_self);
	struct security_descriptor *other = pytalloc_get_ptr(py_other);
	bool eq;

	if (other == NULL) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}

	eq = security_descriptor_equal(self, other);

	switch(op) {
	case Py_EQ:
		if (eq) {
			Py_RETURN_TRUE;
		} else {
			Py_RETURN_FALSE;
		}
		break;
	case Py_NE:
		if (eq) {
			Py_RETURN_FALSE;
		} else {
			Py_RETURN_TRUE;
		}
		break;
	default:
		break;
	}

	Py_RETURN_NOTIMPLEMENTED;
}

static void py_descriptor_patch(PyTypeObject *type)
{
	type->tp_new = py_descriptor_new;
	type->tp_richcompare = py_descriptor_richcmp;
	PyType_AddMethods(type, py_descriptor_extra_methods);
}

#define PY_DESCRIPTOR_PATCH py_descriptor_patch

static PyObject *py_token_is_sid(PyObject *self, PyObject *args)
{
	PyObject *py_sid;
	struct dom_sid *sid;
	struct security_token *token = pytalloc_get_ptr(self);
	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = pytalloc_get_ptr(py_sid);

	return PyBool_FromLong(security_token_is_sid(token, sid));
}

static PyObject *py_token_has_sid(PyObject *self, PyObject *args)
{
	PyObject *py_sid;
	struct dom_sid *sid;
	struct security_token *token = pytalloc_get_ptr(self);
	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = pytalloc_get_ptr(py_sid);

	return PyBool_FromLong(security_token_has_sid(token, sid));
}

static PyObject *py_token_is_anonymous(PyObject *self,
	PyObject *Py_UNUSED(ignored))
{
	struct security_token *token = pytalloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_is_anonymous(token));
}

static PyObject *py_token_is_system(PyObject *self,
	PyObject *Py_UNUSED(ignored))
{
	struct security_token *token = pytalloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_is_system(token));
}

static PyObject *py_token_has_builtin_administrators(PyObject *self,
	PyObject *Py_UNUSED(ignored))
{
	struct security_token *token = pytalloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_has_builtin_administrators(token));
}

static PyObject *py_token_has_nt_authenticated_users(PyObject *self,
	PyObject *Py_UNUSED(ignored))
{
	struct security_token *token = pytalloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_has_nt_authenticated_users(token));
}

static PyObject *py_token_has_privilege(PyObject *self, PyObject *args)
{
	int priv;
	struct security_token *token = pytalloc_get_ptr(self);

	if (!PyArg_ParseTuple(args, "i", &priv))
		return NULL;

	return PyBool_FromLong(security_token_has_privilege(token, priv));
}

static PyObject *py_token_set_privilege(PyObject *self, PyObject *args)
{
	int priv;
	struct security_token *token = pytalloc_get_ptr(self);

	if (!PyArg_ParseTuple(args, "i", &priv))
		return NULL;

	security_token_set_privilege(token, priv);
	Py_RETURN_NONE;
}

static PyObject *py_token_new(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	return pytalloc_steal(self, security_token_initialise(NULL));
}	

static PyMethodDef py_token_extra_methods[] = {
	{ "is_sid", (PyCFunction)py_token_is_sid, METH_VARARGS,
		"S.is_sid(sid) -> bool\n"
		"Check whether this token is of the specified SID." },
	{ "has_sid", (PyCFunction)py_token_has_sid, METH_VARARGS,
		NULL },
	{ "is_anonymous", (PyCFunction)py_token_is_anonymous, METH_NOARGS,
		"S.is_anonymous() -> bool\n"
		"Check whether this is an anonymous token." },
	{ "is_system", (PyCFunction)py_token_is_system, METH_NOARGS,
		NULL },
	{ "has_builtin_administrators", (PyCFunction)py_token_has_builtin_administrators, METH_NOARGS,
		NULL },
	{ "has_nt_authenticated_users", (PyCFunction)py_token_has_nt_authenticated_users, METH_NOARGS,
		NULL },
	{ "has_privilege", (PyCFunction)py_token_has_privilege, METH_VARARGS,
		NULL },
	{ "set_privilege", (PyCFunction)py_token_set_privilege, METH_VARARGS,
		NULL },
	{0}
};

#define PY_TOKEN_PATCH py_token_patch
static void py_token_patch(PyTypeObject *type)
{
	type->tp_new = py_token_new;
	PyType_AddMethods(type, py_token_extra_methods);
}

static PyObject *py_privilege_name(PyObject *self, PyObject *args)
{
	int priv;
	const char *name = NULL;
	if (!PyArg_ParseTuple(args, "i", &priv)) {
		return NULL;
	}
	name = sec_privilege_name(priv);
	if (name == NULL) {
		PyErr_Format(PyExc_ValueError,
			     "Invalid privilege LUID: %d", priv);
		return NULL;
	}

	return PyUnicode_FromString(name);
}

static PyObject *py_privilege_id(PyObject *self, PyObject *args)
{
	char *name;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	return PyLong_FromLong(sec_privilege_id(name));
}

static PyObject *py_random_sid(PyObject *self,
	PyObject *Py_UNUSED(ignored))
{
	struct dom_sid *sid;
	PyObject *ret;
	char *str = talloc_asprintf(
		NULL,
		"S-1-5-21-%"PRIu32"-%"PRIu32"-%"PRIu32,
		generate_random(),
		generate_random(),
		generate_random());

        sid = dom_sid_parse_talloc(NULL, str);
	talloc_free(str);
	ret = pytalloc_steal(&dom_sid_Type, sid);
	return ret;
}

static PyMethodDef py_mod_security_extra_methods[] = {
	{ "random_sid", (PyCFunction)py_random_sid, METH_NOARGS, NULL },
	{ "privilege_id", (PyCFunction)py_privilege_id, METH_VARARGS, NULL },
	{ "privilege_name", (PyCFunction)py_privilege_name, METH_VARARGS, NULL },
	{0}
};

static void py_mod_security_patch(PyObject *m)
{
	int i;
	for (i = 0; py_mod_security_extra_methods[i].ml_name; i++) {
		PyObject *descr = PyCFunction_New(&py_mod_security_extra_methods[i], NULL);
		PyModule_AddObject(m, py_mod_security_extra_methods[i].ml_name,
				   descr);
	}
}

#define PY_MOD_SECURITY_PATCH py_mod_security_patch

static PyObject *py_security_ace_equal(PyObject *py_self, PyObject *py_other, int op)
{
	struct security_ace *self = pytalloc_get_ptr(py_self);
	struct security_ace *other = NULL;
	bool eq;

	if (!PyObject_TypeCheck(py_other, &security_ace_Type)) {
		eq = false;
	} else {
		other = pytalloc_get_ptr(py_other);
		eq = security_ace_equal(self, other);
	}

	switch(op) {
	case Py_EQ:
		if (eq) {
			Py_RETURN_TRUE;
		} else {
			Py_RETURN_FALSE;
		}
		break;
	case Py_NE:
		if (eq) {
			Py_RETURN_FALSE;
		} else {
			Py_RETURN_TRUE;
		}
		break;
	default:
		break;
	}

	Py_RETURN_NOTIMPLEMENTED;
}

static PyObject *py_security_ace_as_sddl(PyObject *self, PyObject *args)
{
	struct security_ace *ace = pytalloc_get_ptr(self);
	PyObject *py_sid = Py_None;
	struct dom_sid *sid = NULL;
	char *text = NULL;
	PyObject *ret = Py_None;

	if (!PyArg_ParseTuple(args, "O!", &dom_sid_Type, &py_sid))
		return NULL;

	if (!PyObject_TypeCheck(py_sid, &dom_sid_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"expected security.dom_sid "
				"for second argument to .sddl_encode_ace");
		return NULL;
	}

	sid = pytalloc_get_ptr(py_sid);

	text = sddl_encode_ace(NULL, ace, sid);
	if (text == NULL) {
		return NULL;
	}
	ret = PyUnicode_FromString(text);
	talloc_free(text);

	return ret;
}

static PyMethodDef py_security_ace_extra_methods[] = {
	{ "as_sddl", (PyCFunction)py_security_ace_as_sddl, METH_VARARGS, NULL },
	{0}
};

#define PY_ACE_PATCH py_security_ace_patch

static void py_security_ace_patch(PyTypeObject *type)
{
	type->tp_richcompare = py_security_ace_equal;
	PyType_AddMethods(type, py_security_ace_extra_methods);
}
