/*
   Unix SMB/CIFS implementation.
   Copyright (C) Luke Morrison <luc785@hotmail.com> 2013

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
#include "version.h"
#include "param/pyparam.h"
#include "gpo.h"
#include "ads.h"
#include "secrets.h"
#include "../libds/common/flags.h"
#include "librpc/rpc/pyrpc_util.h"
#include "auth/credentials/pycredentials.h"
#include "libcli/util/pyerrors.h"
#include "python/py3compat.h"
#include "python/modules.h"
#include <pytalloc.h>
#include "../libcli/security/security.h"

/* A Python C API module to use LIBGPO */

#define GPO_getter(ATTR) \
static PyObject* GPO_get_##ATTR(PyObject *self, void *closure) \
{ \
	struct GROUP_POLICY_OBJECT *gpo_ptr \
		= pytalloc_get_ptr(self); \
	\
	if (gpo_ptr->ATTR) \
		return PyUnicode_FromString(gpo_ptr->ATTR); \
	else \
		Py_RETURN_NONE; \
}
GPO_getter(ds_path)
GPO_getter(file_sys_path)
GPO_getter(display_name)
GPO_getter(name)
GPO_getter(link)
GPO_getter(user_extensions)
GPO_getter(machine_extensions)
#define GPO_setter(ATTR) \
static int GPO_set_##ATTR(PyObject *self, PyObject *val, void *closure) \
{ \
	struct GROUP_POLICY_OBJECT *gpo_ptr \
		= pytalloc_get_ptr(self); \
	\
	if (!PyUnicode_Check(val)) { \
		PyErr_Format(PyExc_TypeError, \
			     "Cannot convert input to string"); \
		return -1; \
	} \
	if (val != Py_None) { \
		gpo_ptr->ATTR = talloc_strdup(gpo_ptr, \
					      _PyUnicode_AsString(val)); \
	} else { \
		gpo_ptr->ATTR = NULL; \
	} \
	return 0; \
}
GPO_setter(ds_path)
GPO_setter(file_sys_path)
GPO_setter(display_name)
GPO_setter(name)
GPO_setter(link)
GPO_setter(user_extensions)
GPO_setter(machine_extensions)
#define GPO_int_getter(ATTR) \
static PyObject* GPO_get_##ATTR(PyObject *self, void *closure) \
{ \
	struct GROUP_POLICY_OBJECT *gpo_ptr \
		= pytalloc_get_ptr(self); \
	\
	return PyLong_FromLong(gpo_ptr->ATTR); \
}
GPO_int_getter(options)
GPO_int_getter(version)
GPO_int_getter(link_type)
#define GPO_int_setter(ATTR) \
static int GPO_set_##ATTR(PyObject *self, PyObject *val, void *closure) \
{ \
        struct GROUP_POLICY_OBJECT *gpo_ptr \
                = pytalloc_get_ptr(self); \
        \
	if (!PyLong_Check(val)) { \
		PyErr_Format(PyExc_TypeError, \
			     "Cannot convert input to int"); \
		return -1; \
	} else { \
		gpo_ptr->ATTR = PyLong_AsLong(val); \
	} \
	return 0; \
}
GPO_int_setter(options)
GPO_int_setter(version)
GPO_int_setter(link_type)

static PyObject *GPO_marshall_get_sec_desc_buf(PyObject *self, PyObject *args,
					       PyObject *kwds)
{
	struct GROUP_POLICY_OBJECT *gpo_ptr = pytalloc_get_ptr(self);
	NTSTATUS status;
	uint8_t *data = NULL;
	size_t len = 0;

	status = marshall_sec_desc(gpo_ptr, gpo_ptr->security_descriptor,
				   &data, &len);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(PyExc_BufferError,
			     "marshall_sec_desc_buf failed: %s",
			     nt_errstr(status));
		return NULL;
	}

	return PyBytes_FromStringAndSize((char *)data, len);
}

static PyObject *GPO_unmarshall_set_sec_desc(PyObject *self, PyObject *args,
					     PyObject *kwds)
{
	struct GROUP_POLICY_OBJECT *gpo_ptr = pytalloc_get_ptr(self);
	char *bytes = NULL;
	size_t length = 0;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "s#", &bytes, &length)) {
		PyErr_Format(PyExc_TypeError,
			     "Cannot convert input to bytes");
		return NULL;
	}

	gpo_ptr->security_descriptor = talloc_zero(gpo_ptr,
						   struct security_descriptor);
	status = unmarshall_sec_desc(gpo_ptr, (uint8_t *)bytes, length,
				     &gpo_ptr->security_descriptor);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(PyExc_BufferError,
			     "unmarshall_sec_desc failed: %s",
			     nt_errstr(status));
		return NULL;
	}

	return Py_None;
}

static PyGetSetDef GPO_setters[] = {
	{discard_const_p(char, "options"), (getter)GPO_get_options,
		(setter)GPO_set_options, NULL, NULL},
	{discard_const_p(char, "version"), (getter)GPO_get_version,
		(setter)GPO_set_version, NULL, NULL},
	{discard_const_p(char, "ds_path"), (getter)GPO_get_ds_path,
		(setter)GPO_set_ds_path, NULL, NULL},
	{discard_const_p(char, "file_sys_path"), (getter)GPO_get_file_sys_path,
		(setter)GPO_set_file_sys_path, NULL, NULL},
	{discard_const_p(char, "display_name"), (getter)GPO_get_display_name,
		(setter)GPO_set_display_name, NULL, NULL},
	{discard_const_p(char, "name"), (getter)GPO_get_name,
		(setter)GPO_set_name, NULL, NULL},
	{discard_const_p(char, "link"), (getter)GPO_get_link,
		(setter)GPO_set_link, NULL, NULL},
	{discard_const_p(char, "link_type"), (getter)GPO_get_link_type,
		(setter)GPO_set_link_type, NULL, NULL},
	{discard_const_p(char, "user_extensions"),
		(getter)GPO_get_user_extensions,
		(setter)GPO_set_user_extensions, NULL, NULL},
	{discard_const_p(char, "machine_extensions"),
		(getter)GPO_get_machine_extensions,
		(setter)GPO_set_machine_extensions, NULL, NULL},
	{0}
};

static PyObject *py_gpo_get_unix_path(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
	NTSTATUS status;
	const char *cache_dir = NULL;
	PyObject *ret = NULL;
	char *unix_path = NULL;
	TALLOC_CTX *frame = NULL;
	static const char *kwlist[] = {"cache_dir", NULL};
	struct GROUP_POLICY_OBJECT *gpo_ptr \
		= (struct GROUP_POLICY_OBJECT *)pytalloc_get_ptr(self);

	frame = talloc_stackframe();

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s",
					 discard_const_p(char *, kwlist),
					 &cache_dir)) {
		goto out;
	}

	if (!cache_dir) {
		cache_dir = cache_path(talloc_tos(), GPO_CACHE_DIR);
		if (!cache_dir) {
			PyErr_SetString(PyExc_MemoryError,
					"Failed to determine gpo cache dir");
			goto out;
		}
	}

	status = gpo_get_unix_path(frame, cache_dir, gpo_ptr, &unix_path);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(PyExc_RuntimeError,
				"Failed to determine gpo unix path: %s",
				get_friendly_nt_error_msg(status));
		goto out;
	}

	ret = PyUnicode_FromString(unix_path);

out:
	TALLOC_FREE(frame);
	return ret;
}

static PyMethodDef GPO_methods[] = {
	{"get_unix_path", PY_DISCARD_FUNC_SIG(PyCFunction,
					      py_gpo_get_unix_path),
		METH_VARARGS | METH_KEYWORDS,
		NULL },
	{"set_sec_desc", PY_DISCARD_FUNC_SIG(PyCFunction,
					     GPO_unmarshall_set_sec_desc),
		METH_VARARGS, NULL },
	{"get_sec_desc_buf", PY_DISCARD_FUNC_SIG(PyCFunction,
						 GPO_marshall_get_sec_desc_buf),
		METH_NOARGS, NULL },
	{0}
};

static int py_gpo_init(PyObject *self, PyObject *args, PyObject *kwds)
{
	struct GROUP_POLICY_OBJECT *gpo_ptr = pytalloc_get_ptr(self);
	const char *name = NULL;
	const char *display_name = NULL;
	enum GPO_LINK_TYPE link_type = GP_LINK_UNKOWN;
	const char *file_sys_path = NULL;

	static const char *kwlist[] = {
		"name", "display_name", "link_type", "file_sys_path", NULL
	};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ssIs",
					 discard_const_p(char *, kwlist),
					 &name, &display_name, &link_type,
					 &file_sys_path)) {
		return -1;
	}

	if (name) {
		gpo_ptr->name = talloc_strdup(gpo_ptr, name);
	}
	if (display_name) {
		gpo_ptr->display_name = talloc_strdup(gpo_ptr, display_name);
	}
	gpo_ptr->link_type = link_type;
	if (file_sys_path) {
		gpo_ptr->file_sys_path = talloc_strdup(gpo_ptr, file_sys_path);
	}

	return 0;
}

static PyObject *py_gpo_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return pytalloc_new(struct GROUP_POLICY_OBJECT, type);
}

static PyTypeObject GPOType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "gpo.GROUP_POLICY_OBJECT",
	.tp_doc = "GROUP_POLICY_OBJECT",
	.tp_getset = GPO_setters,
	.tp_methods = GPO_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_gpo_new,
	.tp_init = (initproc)py_gpo_init,
};

typedef struct {
	PyObject_HEAD
	ADS_STRUCT *ads_ptr;
	PyObject *py_creds;
	struct cli_credentials *cli_creds;
} ADS;

static void py_ads_dealloc(ADS* self)
{
	TALLOC_FREE(self->ads_ptr);
	Py_CLEAR(self->py_creds);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* py_ads_connect(ADS *self, PyObject *Py_UNUSED(ignored));
static int py_ads_init(ADS *self, PyObject *args, PyObject *kwds)
{
	const char *realm = NULL;
	const char *workgroup = NULL;
	const char *ldap_server = NULL;
	PyObject *lp_obj = NULL;
	PyObject *py_creds = NULL;
	struct loadparm_context *lp_ctx = NULL;
	bool ok = false;

	static const char *kwlist[] = {
		"ldap_server", "loadparm_context", "credentials", NULL
	};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "sO|O",
					 discard_const_p(char *, kwlist),
					 &ldap_server, &lp_obj, &py_creds)) {
		return -1;
	}
	/* keep reference to the credentials. Clear any earlier ones */
	Py_CLEAR(self->py_creds);
	self->cli_creds = NULL;
	self->py_creds = py_creds;
	Py_XINCREF(self->py_creds);

	if (self->py_creds) {
		ok = py_check_dcerpc_type(self->py_creds, "samba.credentials",
					  "Credentials");
		if (!ok) {
			return -1;
		}
		self->cli_creds
			= PyCredentials_AsCliCredentials(self->py_creds);
	}

	ok = py_check_dcerpc_type(lp_obj, "samba.param", "LoadParm");
	if (!ok) {
		return -1;
	}
	lp_ctx = pytalloc_get_type(lp_obj, struct loadparm_context);
	if (lp_ctx == NULL) {
		return -1;
	}
	ok = lp_load_initial_only(lp_ctx->szConfigFile);
	if (!ok) {
		PyErr_Format(PyExc_RuntimeError, "Could not load config file '%s'",
				lp_ctx->szConfigFile);
		return -1;
	}

	if (self->cli_creds) {
		realm = cli_credentials_get_realm(self->cli_creds);
		workgroup = cli_credentials_get_domain(self->cli_creds);
	} else {
		realm = lp_realm();
		workgroup = lp_workgroup();
	}

	/* in case __init__ is called more than once */
	if (self->ads_ptr) {
		TALLOC_FREE(self->ads_ptr);
	}
	/* always succeeds or crashes */
	self->ads_ptr = ads_init(pytalloc_get_mem_ctx(args),
				 realm,
				 workgroup,
				 ldap_server,
				 ADS_SASL_PLAIN);
	
	return 0;
}

/* connect.  Failure to connect results in an Exception */
static PyObject* py_ads_connect(ADS *self,
		PyObject *Py_UNUSED(ignored))
{
	ADS_STATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	if (!self->ads_ptr) {
		PyErr_SetString(PyExc_RuntimeError, "Uninitialized");
		return NULL;
	}
	ADS_TALLOC_CONST_FREE(self->ads_ptr->auth.user_name);
	ADS_TALLOC_CONST_FREE(self->ads_ptr->auth.password);
	ADS_TALLOC_CONST_FREE(self->ads_ptr->auth.realm);
	if (self->cli_creds) {
		self->ads_ptr->auth.user_name = talloc_strdup(self->ads_ptr,
			cli_credentials_get_username(self->cli_creds));
		if (self->ads_ptr->auth.user_name == NULL) {
			PyErr_NoMemory();
			goto err;
		}
		self->ads_ptr->auth.password = talloc_strdup(self->ads_ptr,
			cli_credentials_get_password(self->cli_creds));
		if (self->ads_ptr->auth.password == NULL) {
			PyErr_NoMemory();
			goto err;
		}
		self->ads_ptr->auth.realm = talloc_strdup(self->ads_ptr,
			cli_credentials_get_realm(self->cli_creds));
		if (self->ads_ptr->auth.realm == NULL) {
			PyErr_NoMemory();
			goto err;
		}
		self->ads_ptr->auth.flags |= ADS_AUTH_USER_CREDS;
		status = ads_connect_user_creds(self->ads_ptr);
	} else {
		char *passwd = NULL;

		if (!secrets_init()) {
			PyErr_SetString(PyExc_RuntimeError,
					"secrets_init() failed");
			goto err;
		}

		self->ads_ptr->auth.user_name = talloc_asprintf(self->ads_ptr,
							"%s$",
							lp_netbios_name());
		if (self->ads_ptr->auth.user_name == NULL) {
			PyErr_NoMemory();
			goto err;
		}

		passwd = secrets_fetch_machine_password(
			self->ads_ptr->server.workgroup, NULL, NULL);
		if (passwd == NULL) {
			PyErr_SetString(PyExc_RuntimeError,
					"Failed to fetch the machine account "
					"password");
			goto err;
		}

		self->ads_ptr->auth.password = talloc_strdup(self->ads_ptr,
							     passwd);
		SAFE_FREE(passwd);
		if (self->ads_ptr->auth.password == NULL) {
			PyErr_NoMemory();
			goto err;
		}
		self->ads_ptr->auth.realm = talloc_asprintf_strupper_m(
			self->ads_ptr, "%s", self->ads_ptr->server.realm);
		if (self->ads_ptr->auth.realm == NULL) {
			PyErr_NoMemory();
			goto err;
		}
		self->ads_ptr->auth.flags |= ADS_AUTH_USER_CREDS;
		status = ads_connect(self->ads_ptr);
	}
	if (!ADS_ERR_OK(status)) {
		PyErr_Format(PyExc_RuntimeError,
				"ads_connect() failed: %s",
				ads_errstr(status));
		goto err;
	}

	TALLOC_FREE(frame);
	Py_RETURN_TRUE;

err:
	TALLOC_FREE(frame);
	return NULL;
}

/* Parameter mapping and functions for the GP_EXT struct */
void initgpo(void);

/* Global methods aka do not need a special pyobject type */
static PyObject *py_gpo_get_sysvol_gpt_version(PyObject * self,
					       PyObject * args)
{
	TALLOC_CTX *tmp_ctx = NULL;
	char *unix_path;
	char *display_name = NULL;
	uint32_t sysvol_version = 0;
	PyObject *result;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "s", &unix_path)) {
		return NULL;
	}
	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		return PyErr_NoMemory();
	}
	status = gpo_get_sysvol_gpt_version(tmp_ctx, unix_path,
					    &sysvol_version,
					    &display_name);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	result = Py_BuildValue("[s,i]", display_name, sysvol_version);
	talloc_free(tmp_ctx);
	return result;
}

#ifdef HAVE_ADS
static ADS_STATUS find_samaccount(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
				  const char *samaccountname,
				  uint32_t *uac_ret, const char **dn_ret)
{
	ADS_STATUS status;
	const char *attrs[] = { "userAccountControl", NULL };
	const char *filter;
	LDAPMessage *res = NULL;
	char *dn = NULL;
	uint32_t uac = 0;

	filter = talloc_asprintf(mem_ctx, "(sAMAccountName=%s)",
				 samaccountname);
	if (filter == NULL) {
		status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto out;
	}

	status = ads_do_search_all(ads, ads->config.bind_path,
				   LDAP_SCOPE_SUBTREE, filter, attrs, &res);

	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (ads_count_replies(ads, res) != 1) {
		status = ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
		goto out;
	}

	dn = ads_get_dn(ads, talloc_tos(), res);
	if (dn == NULL) {
		status = ADS_ERROR(LDAP_NO_MEMORY);
		goto out;
	}

	if (!ads_pull_uint32(ads, res, "userAccountControl", &uac)) {
		status = ADS_ERROR(LDAP_NO_SUCH_ATTRIBUTE);
		goto out;
	}

	if (uac_ret) {
		*uac_ret = uac;
	}

	if (dn_ret) {
		*dn_ret = talloc_strdup(mem_ctx, dn);
		if (*dn_ret == NULL) {
			status = ADS_ERROR(LDAP_NO_MEMORY);
			goto out;
		}
	}
out:
	TALLOC_FREE(dn);
	ads_msgfree(ads, res);

	return status;
}

static PyObject *py_ads_get_gpo_list(ADS *self, PyObject *args, PyObject *kwds)
{
	TALLOC_CTX *frame = NULL;
	struct GROUP_POLICY_OBJECT *gpo = NULL, *gpo_list = NULL;
	ADS_STATUS status;
	const char *samaccountname = NULL;
	const char *dn = NULL;
	uint32_t uac = 0;
	uint32_t flags = 0;
	struct security_token *token = NULL;
	PyObject *ret = NULL;
	TALLOC_CTX *gpo_ctx = NULL;
	size_t list_size;
	size_t i;

	static const char *kwlist[] = {"samaccountname", NULL};

	PyErr_WarnEx(PyExc_DeprecationWarning, "The get_gpo_list function"
				" is deprecated as of Samba 4.19. Please use "
				"the samba.gp module instead.", 2);

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s",
					 discard_const_p(char *, kwlist),
					 &samaccountname)) {
		return NULL;
	}
	if (!self->ads_ptr) {
		PyErr_SetString(PyExc_RuntimeError, "Uninitialized");
		return NULL;
	}

	frame = talloc_stackframe();

	status = find_samaccount(self->ads_ptr, frame,
				 samaccountname, &uac, &dn);
	if (!ADS_ERR_OK(status)) {
		PyErr_Format(PyExc_RuntimeError,
				"Failed to find samAccountName '%s': %s",
				samaccountname, ads_errstr(status));
		goto out;
	}

	if (uac & UF_WORKSTATION_TRUST_ACCOUNT ||
	    uac & UF_SERVER_TRUST_ACCOUNT) {
		flags |= GPO_LIST_FLAG_MACHINE;
		status = gp_get_machine_token(self->ads_ptr, frame, dn,
					      &token);
		if (!ADS_ERR_OK(status)) {
			PyErr_Format(PyExc_RuntimeError,
				"Failed to get machine token for '%s'(%s): %s",
				samaccountname, dn, ads_errstr(status));
			goto out;
		}
	} else {
		status = ads_get_sid_token(self->ads_ptr, frame, dn, &token);
		if (!ADS_ERR_OK(status)) {
			PyErr_Format(PyExc_RuntimeError,
				"Failed to get sid token for '%s'(%s): %s",
				samaccountname, dn, ads_errstr(status));
			goto out;
		}
	}

	gpo_ctx = talloc_new(frame);
	if (!gpo_ctx) {
		PyErr_NoMemory();
		goto out;
	}
	status = ads_get_gpo_list(self->ads_ptr, gpo_ctx, dn, flags, token,
				  &gpo_list);
	if (!ADS_ERR_OK(status)) {
		PyErr_Format(PyExc_RuntimeError,
			"Failed to fetch GPO list: %s",
			ads_errstr(status));
		goto out;
	}

	/* Convert the C linked list into a python list */
	list_size = 0;
	for (gpo = gpo_list; gpo != NULL; gpo = gpo->next) {
		list_size++;
	}

	i = 0;
	ret = PyList_New(list_size);
	if (ret == NULL) {
		goto out;
	}

	for (gpo = gpo_list; gpo != NULL; gpo = gpo->next) {
		PyObject *obj = pytalloc_reference_ex(&GPOType,
						      gpo_ctx, gpo);
		if (obj == NULL) {
			Py_CLEAR(ret);
			goto out;
		}

		PyList_SetItem(ret, i, obj);
		i++;
	}

out:
	TALLOC_FREE(frame);
	return ret;
}

#endif

static PyMethodDef ADS_methods[] = {
	{ "connect", (PyCFunction)py_ads_connect, METH_NOARGS,
		"Connect to the LDAP server" },
#ifdef HAVE_ADS
	{ "get_gpo_list", PY_DISCARD_FUNC_SIG(PyCFunction, py_ads_get_gpo_list),
		METH_VARARGS | METH_KEYWORDS,
		NULL },
#endif
	{0}
};

static PyTypeObject ads_ADSType = {
	.tp_name = "gpo.ADS_STRUCT",
	.tp_basicsize = sizeof(ADS),
	.tp_new = PyType_GenericNew,
	.tp_dealloc = (destructor)py_ads_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "ADS struct",
	.tp_methods = ADS_methods,
	.tp_init = (initproc)py_ads_init,
};

static PyMethodDef py_gpo_methods[] = {
	{"gpo_get_sysvol_gpt_version",
		(PyCFunction)py_gpo_get_sysvol_gpt_version,
		METH_VARARGS, NULL},
	{0}
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "gpo",
	.m_doc = "libgpo python bindings",
	.m_size = -1,
	.m_methods = py_gpo_methods,
};

/* Will be called by python when loading this module */
void initgpo(void);

MODULE_INIT_FUNC(gpo)
{
	PyObject *m;

	debug_setup_talloc_log();

	/* Instantiate the types */
	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		goto err;
	}

	if (PyModule_AddObject(m, "version",
			   PyUnicode_FromString(SAMBA_VERSION_STRING)) ) {
		goto err;
	}

	if (pytalloc_BaseObject_PyType_Ready(&ads_ADSType) < 0) {
		goto err;
	}

	Py_INCREF(&ads_ADSType);
	if (PyModule_AddObject(m, "ADS_STRUCT", (PyObject *)&ads_ADSType)) {
		goto err;
	}

	if (pytalloc_BaseObject_PyType_Ready(&GPOType) < 0) {
		goto err;
	}

	Py_INCREF((PyObject *)(void *)&GPOType);
	if (PyModule_AddObject(m, "GROUP_POLICY_OBJECT",
			   (PyObject *)&GPOType)) {
		goto err;
	}

#define ADD_FLAGS(val)  PyModule_AddObject(m, #val, PyLong_FromLong(val))

	ADD_FLAGS(GP_LINK_UNKOWN);
	ADD_FLAGS(GP_LINK_MACHINE);
	ADD_FLAGS(GP_LINK_SITE);
	ADD_FLAGS(GP_LINK_DOMAIN);
	ADD_FLAGS(GP_LINK_OU);
	ADD_FLAGS(GP_LINK_LOCAL);

	return m;

err:
	Py_CLEAR(m);
	return NULL;
}
