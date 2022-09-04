/*
 *  Unix SMB/CIFS implementation.
 *  libwbclient - Python bindings
 *
 *  Copyright (C) Andrew Walker 2022
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

#include <Python.h>
#include "includes.h"
#include "libwbclient/wbclient.h"
#include "winbind_struct_protocol.h"
#include "libwbclient/wbclient_internal.h"

static PyObject *PyExc_WBCError;

typedef struct {
	PyObject_HEAD
	struct wbcInterfaceDetails *iface_details;
	struct wbcContext *ctx;
} py_wbclient;

typedef struct {
	PyObject_HEAD
	py_wbclient *wbclient;
	char domain[16];
	char dns_domain[256];
	char sid_str[WBC_SID_STRING_BUFLEN];
	uint32_t trust_flags;
	uint32_t trust_type;
	char trust_routing[280];
} py_wbdomain;

typedef struct {
	PyObject_HEAD
	py_wbclient *wbclient;
	char sid[WBC_SID_STRING_BUFLEN];
	uid_t id;
	uint32_t idtype;
	char idtype_str[5];
	char name[256];
	char domain[256];
	enum wbcSidType sidtype;
	PyObject *(*id_info_fn)(PyObject *obj, PyObject *args);
} py_uid_gid;

static void _set_exc_from_wbcerrno(wbcErr wbc_status,
				   const char *additional_info,
				   const char *location)
{
	PyObject *v = NULL;
	PyObject *args = NULL;
	PyObject *errstr = NULL;
	int err;

	if (additional_info) {
		errstr = PyUnicode_FromFormat(
			"%s: %s",
			wbcErrorString(wbc_status),
			additional_info
		);
	} else {
		errstr = Py_BuildValue("s", wbcErrorString(wbc_status));
	}
	if (errstr == NULL) {
		goto simple_err;
	}

	args = Py_BuildValue("(iNs)", wbc_status, errstr, location);
	if (args == NULL) {
		Py_XDECREF(errstr);
		goto simple_err;
	}

	v = PyObject_Call(PyExc_WBCError, args, NULL);
	if (v == NULL) {
		Py_CLEAR(args);
		return;
	}

	err = PyObject_SetAttrString(v, "error_code", PyTuple_GetItem(args, 0));
	if (err == -1) {
		Py_CLEAR(args);
		Py_CLEAR(v);
		return;
	}

	err = PyObject_SetAttrString(v, "location", PyTuple_GetItem(args, 2));
	Py_CLEAR(args);
	if (err == -1) {
		Py_CLEAR(v);
		return;
	}

	PyErr_SetObject((PyObject *) Py_TYPE(v), v);
	Py_DECREF(v);
	return;

simple_err:
	PyErr_Format(PyExc_WBCError, "[%d]: %s",
		     wbc_status, wbcErrorString(wbc_status));
	return;

}

#define set_exc_from_wbcerrno(wbc_status, additional_info) \
	_set_exc_from_wbcerrno(wbc_status, additional_info, __location__)

static PyObject *py_wbc_getpwuid(PyObject *obj, PyObject *args)
{
	wbcErr wbc_status;
	py_uid_gid *self = (py_uid_gid *)obj;
	struct passwd *pwd = NULL;
	PyObject *py_pwd = NULL;
	wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	wbc_status = wbcCtxGetpwuid(self->wbclient->ctx, self->id, &pwd);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcCtxGetpwuid failed");
		return NULL;
	}

	py_pwd = Py_BuildValue(
		"{s:s, s:s, s:I, s:I, s:s, s:s}",
		"pw_name", pwd->pw_name,
		"pw_passwd", pwd->pw_passwd,
		"pw_uid", pwd->pw_uid,
		"pw_gid", pwd->pw_gid,
		"pw_gecos", pwd->pw_gecos,
		"pw_shell", pwd->pw_shell
	);
	wbcFreeMemory(pwd);
	return py_pwd;
}

static PyObject *py_wbc_getgrgid(PyObject *obj, PyObject *args)
{
	wbcErr wbc_status;
	py_uid_gid *self = (py_uid_gid *)obj;
	struct group *grp = NULL;
	PyObject *py_grp = NULL;
	wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	wbc_status = wbcCtxGetgrgid(self->wbclient->ctx, self->id, &grp);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcCtxGetgrgid failed");
		return NULL;
	}

	py_grp = Py_BuildValue(
		"{s:s, s:s, s:I}",
		"gr_name", grp->gr_name,
		"gr_passwd", grp->gr_passwd,
		"gr_gid", grp->gr_gid
	);
	wbcFreeMemory(grp);
	return py_grp;
}

static PyObject *py_wbc_getboth(PyObject *obj, PyObject *args)
{
	PyObject *py_pwd = NULL;
	PyObject *py_grp = NULL;
	int err;

	py_pwd = py_wbc_getpwuid(obj, args);
	if (py_pwd == NULL) {
		return NULL;
	}

	py_grp = py_wbc_getgrgid(obj, args);
	if (py_grp == NULL) {
		Py_DECREF(py_pwd);
		return NULL;
	}

	err = PyDict_Merge(py_pwd, py_grp, false);
	if (err == -1) {
		Py_DECREF(py_pwd);
		Py_DECREF(py_grp);
		return NULL;
	}
	Py_DECREF(py_grp);
	return py_pwd;
}

static PyObject *py_id_info(PyObject *obj, PyObject *args)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	return self->id_info_fn(obj, args);
}

static PyObject *py_uid_gid_new(PyTypeObject *obj,
			        PyObject *args_unused,
			        PyObject *kwargs_unused)
{
	py_uid_gid *self = NULL;
	self = (py_uid_gid *)obj->tp_alloc(obj, 0);
	if (self == NULL) {
		return NULL;
	}
	return (PyObject *)self;
}

static bool parse_sid_info(py_uid_gid *self)
{
	wbcErr wbc_status;
	struct wbcDomainSid sid;
	char *domain = NULL;
	char *name = NULL;
	enum wbcSidType stype;

	if (strcmp(self->sid, "S-0-0") == 0) {
		return true;
	}

	wbc_status = wbcStringToSid(self->sid, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcStringToSid failed");
		return false;
	}

	wbc_status = wbcCtxLookupSid(
		self->wbclient->ctx,
		&sid, &domain, &name, &stype
	);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcCtxLookupSid failed");
		return false;
	}

	self->sidtype = stype;
	strlcpy(self->domain, domain, sizeof(self->domain));
	if (stype != WBC_SID_NAME_DOMAIN) {
		strlcpy(self->name, name, sizeof(self->name));
	}
	return true;
}

static int py_uid_gid_init(PyObject *obj,
			   PyObject *args,
			   PyObject *kwargs)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	PyObject *pyclient = NULL;
	const char *sid = NULL;
	uid_t id = -1;
	uint32_t id_type;

	if (!PyArg_ParseTuple(args, "OIIs", &pyclient, &id, &id_type, &sid)) {
		return -1;
	}

	switch(id_type) {
	case WBC_ID_TYPE_UID:
		strlcpy(self->idtype_str, "UID", sizeof(self->idtype_str));
		self->id_info_fn = py_wbc_getpwuid;
		break;
	case WBC_ID_TYPE_GID:
		strlcpy(self->idtype_str, "GID", sizeof(self->idtype_str));
		self->id_info_fn = py_wbc_getgrgid;
		break;
	case WBC_ID_TYPE_BOTH:
		strlcpy(self->idtype_str, "BOTH", sizeof(self->idtype_str));
		self->id_info_fn = py_wbc_getboth;
		break;
	default:
		PyErr_Format(
			PyExc_TypeError,
			"0x%08x: Invalid id_type",
			id_type
		);
		return -1;
	}

	strlcpy(self->sid, sid, sizeof(self->sid));
	self->id = id;

	self->wbclient = (py_wbclient *)pyclient;

	if (!parse_sid_info(self)) {
		return -1;
	}

	Py_INCREF(self->wbclient);

	return 0;
}

static void py_uid_gid_dealloc(py_uid_gid *self)
{
	Py_XDECREF(self->wbclient);
        Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *py_uid_gid_repr(PyObject *obj)
{
	py_uid_gid *self = (py_uid_gid *)obj;

	return PyUnicode_FromFormat(
		"wbclient.UidGid(id_type=%s, "
		"id=%u, sid=%s)",
		self->idtype_str, self->id,
		self->sid
	);
}

static PyObject *uid_gid_get_id_type(PyObject *obj, void *closure)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	return Py_BuildValue("I", self->idtype);
}

static PyObject *uid_gid_get_id(PyObject *obj, void *closure)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	return Py_BuildValue("I", self->id);
}

static PyObject *uid_gid_get_domain(PyObject *obj, void *closure)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	return Py_BuildValue("s", self->domain);
}

static PyObject *uid_gid_get_name(PyObject *obj, void *closure)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	return Py_BuildValue("s", self->name);
}

static PyObject *uid_gid_get_sid(PyObject *obj, void *closure)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	if (strcmp(self->sid, "S-0-0") == 0) {
		Py_RETURN_NONE;
	}
	return Py_BuildValue("s", self->sid);
}

static PyObject *uid_gid_get_sid_type(PyObject *obj, void *closure)
{
	py_uid_gid *self = (py_uid_gid *)obj;
	if (strcmp(self->sid, "S-0-0") == 0) {
		Py_RETURN_NONE;
	}

	return Py_BuildValue(
		"{s:I, s:s}",
		"raw", self->sidtype,
		"parsed", wbcSidTypeString(self->sidtype)
	);
}

static PyMethodDef uid_gid_object_methods[] = {
	{
		.ml_name = "id_info",
		.ml_meth = (PyCFunction)py_id_info,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Return passwd or group info for id."
	},
	{ NULL, NULL, 0, NULL }
};

static PyGetSetDef uid_gid_getsetters[] = {
	{
		.name	= discard_const_p(char, "id_type"),
		.get	= (getter)uid_gid_get_id_type,
	},
	{
		.name	= discard_const_p(char, "id"),
		.get	= (getter)uid_gid_get_id,
	},
	{
		.name	= discard_const_p(char, "sid"),
		.get	= (getter)uid_gid_get_sid,
	},
	{
		.name	= discard_const_p(char, "sid_type"),
		.get	= (getter)uid_gid_get_sid_type,
	},
	{
		.name	= discard_const_p(char, "domain"),
		.get	= (getter)uid_gid_get_domain,
	},
	{
		.name	= discard_const_p(char, "name"),
		.get	= (getter)uid_gid_get_name,
	},
	{ .name = NULL }
};

static PyTypeObject PyUidGid = {
	.tp_name = "wbclient.UidGid",
	.tp_basicsize = sizeof(py_uid_gid),
	.tp_methods = uid_gid_object_methods,
	.tp_getset = uid_gid_getsetters,
	.tp_new = py_uid_gid_new,
	.tp_init = py_uid_gid_init,
	.tp_repr = py_uid_gid_repr,
	.tp_doc = "User or group entry",
	.tp_dealloc = (destructor)py_uid_gid_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static PyObject *py_list_from_array(const char **_array, uint32_t sz)
{
	uint32_t i;
	PyObject *list_out = NULL;

	list_out = PyList_New(sz);
	if (list_out == NULL) {
		return NULL;
	}

	for (i = 0; i < sz; i ++) {
		PyObject *entry = NULL;
		int err;

		entry = Py_BuildValue("s", _array[i]);
		if (entry == NULL) {
			Py_DECREF(list_out);
			return NULL;
		}

		err = PyList_SetItem(list_out, i, entry);
		if (err) {
			Py_XDECREF(entry);
			Py_XDECREF(list_out);
			return NULL;
		}
	}

	return list_out;
}

static PyObject *wbclient_domain_users(PyObject *obj, PyObject *args)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t num_users = 0;
	const char **users = NULL;
	PyObject *pyusers = NULL;
	py_wbdomain *self = (py_wbdomain *)obj;

	wbc_status = wbcCtxListUsers(
		self->wbclient->ctx, self->domain, &num_users, &users
	);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcListUsers failed");
		return NULL;
	}

	pyusers = py_list_from_array(users, num_users);
	wbcFreeMemory(users);
	return pyusers;
}

static PyObject *wbclient_domain_groups(PyObject *obj, PyObject *args)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t num_groups = 0;
	const char **groups = NULL;
	PyObject *pygroups = NULL;
	py_wbdomain *self = (py_wbdomain *)obj;

	wbc_status = wbcCtxListGroups(
		self->wbclient->ctx, self->domain, &num_groups, &groups
	);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcListGroups failed");
		return NULL;
	}

	pygroups = py_list_from_array(groups, num_groups);
	wbcFreeMemory(groups);
	return pygroups;
}

static PyObject *wbclient_check_secret(PyObject *obj, PyObject *args)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcAuthErrorInfo *error = NULL;
	py_wbdomain *self = (py_wbdomain *)obj;

	wbc_status = wbcCtxCheckTrustCredentials(
		self->wbclient->ctx, self->domain, &error);
	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		char *errstr = NULL;
		if (asprintf(&errstr,
		    "wbcCheckTrustCredentials(%s): "
		    "error code was %s (0x%08x)",
		    self->domain, error->nt_string, error->nt_status) == -1) {
			goto generic_error;
		}
		set_exc_from_wbcerrno(wbc_status, errstr);
		free(errstr);
		return NULL;
	}
	wbcFreeMemory(error);

	if (!WBC_ERROR_IS_OK(wbc_status)) {
		goto generic_error;
	}

	Py_RETURN_NONE;

generic_error:
	set_exc_from_wbcerrno(wbc_status, "wbcCheckTrustCredentials failed");
	return NULL;
}

static PyObject *wbclient_ping_dc(PyObject *obj, PyObject *args)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcAuthErrorInfo *error = NULL;
	char *errstr = NULL;
	char *dc_name = NULL;
	py_wbdomain *self = (py_wbdomain *)obj;
	PyObject *out = NULL;

	wbc_status = wbcCtxPingDc2(
		self->wbclient->ctx, self->domain, &error, &dc_name
	);
	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		wbcFreeMemory(dc_name);
		if (asprintf(&errstr,
		    "wbcCheckTrustCredentials(%s): "
		    "error code was %s (0x%08x)",
		    self->domain, error->nt_string, error->nt_status) == -1) {
			set_exc_from_wbcerrno(wbc_status, "wbcPingDc2 failed");
			return NULL;
		}
		set_exc_from_wbcerrno(wbc_status, errstr);
		free(errstr);
		return NULL;
	}
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		wbcFreeMemory(dc_name);
		wbcFreeMemory(error);
		set_exc_from_wbcerrno(wbc_status, "wbcPingDc2 failed");
		return NULL;
	}
	out = Py_BuildValue("s", dc_name);
	wbcFreeMemory(dc_name);
	wbcFreeMemory(error);
	return out;
}

struct flag2str {
	uint32_t flag;
	const char *str;
};

struct flag2str dom_status[] = {
	{ WBC_DOMINFO_DOMAIN_AD, "ACTIVE_DIRECTORY" },
	{ WBC_DOMINFO_DOMAIN_NATIVE, "NATIVE" },
	{ WBC_DOMINFO_DOMAIN_PRIMARY, "PRIMARY" },
	{ WBC_DOMINFO_DOMAIN_OFFLINE, "OFFLINE" },
	{ 0, NULL}
};

struct flag2str dom_trust[] = {
	{ WBC_DOMINFO_TRUST_TRANSITIVE, "TRANSITIVE" },
	{ WBC_DOMINFO_TRUST_INCOMING, "INCOMING" },
	{ WBC_DOMINFO_TRUST_OUTGOING, "OUTGOING" },
	{ 0, NULL}
};

static PyObject *parse_flags(struct flag2str *table, uint32_t flags)
{
	PyObject *parsed = NULL;
	const struct flag2str *tmp = NULL;
	int err;

	parsed = Py_BuildValue("[]");
	if (parsed == NULL) {
		return NULL;
	}

	for (tmp = table; tmp->str != NULL; tmp++) {
		PyObject *val = NULL;

		if ((flags & tmp->flag) == 0) {
			continue;
		}

		val = Py_BuildValue("s", tmp->str);
		if (val == NULL) {
			Py_CLEAR(parsed);
			return NULL;
		}

		err = PyList_Append(parsed, val);
		Py_XDECREF(val);
		if (err) {
			Py_CLEAR(parsed);
			return NULL;
		}
	}

	return Py_BuildValue("{s:I, s:N}", "raw", flags, "parsed", parsed);
}

static PyObject *get_trust_type(uint32_t trust_type,
				uint32_t trust_flags,
				char *trust_routing)
{
	PyObject *flags = NULL;
	const char *trust = NULL;

	switch(trust_type) {
	case WBC_DOMINFO_TRUSTTYPE_NONE:
		if (trust_routing[0] != '\0') {
			trust = trust_routing;
		}
		break;
	case WBC_DOMINFO_TRUSTTYPE_LOCAL:
		trust = "LOCAL";
		break;
	case WBC_DOMINFO_TRUSTTYPE_RODC:
		trust = "RODC";
		break;
	case WBC_DOMINFO_TRUSTTYPE_PDC:
		trust = "PDC";
		break;
	case WBC_DOMINFO_TRUSTTYPE_WKSTA:
		trust = "WORKSTATION";
		break;
	case WBC_DOMINFO_TRUSTTYPE_FOREST:
		trust = "FOREST";
		break;
	case WBC_DOMINFO_TRUSTTYPE_EXTERNAL:
		trust = "EXTERNAL";
		break;
	case WBC_DOMINFO_TRUSTTYPE_IN_FOREST:
		trust = "IN-FOREST";
		break;
	}

	flags = parse_flags(dom_trust, trust_flags);
	if (flags == NULL) {
		return NULL;
	}

	if (trust == NULL) {
		return Py_BuildValue(
			"{s:O, s:I, s:N}",
			"type", Py_None,
			"type_raw", trust_type,
			"flags", flags
		);
	}

	return Py_BuildValue(
		"{s:s, s:I, s:N}",
		"type", trust,
		"type_raw", trust_type,
		"flags", flags
	);
}

static void populate_domain_info(py_wbdomain *dom,
				 const struct wbcDomainInfo *dinfo,
				 bool has_trust_info)
{
	strlcpy(dom->dns_domain, dinfo->dns_name, sizeof(dom->dns_domain));
	wbcSidToStringBuf(&dinfo->sid, dom->sid_str, sizeof(dom->sid_str));
	if (has_trust_info) {
		dom->trust_flags = dinfo->trust_flags;
		dom->trust_type = dinfo->trust_type;
		if (dinfo->trust_routing) {
			strlcpy(dom->trust_routing, dinfo->trust_routing,
				sizeof(dom->trust_routing));
		}
	}
}

static PyObject *py_domain_info(struct wbcDomainInfo *dinfo)
{
	char sid_str[WBC_SID_STRING_BUFLEN];
	PyObject *domain_flags = NULL;

	wbcSidToStringBuf(&dinfo->sid, sid_str, sizeof(sid_str));

	domain_flags = parse_flags(dom_status, dinfo->domain_flags);
	if (domain_flags == NULL) {
		return NULL;
	}

	return Py_BuildValue(
		"{s:s, s:s, s:s, s:N, s:O}",
		"netbios_domain", dinfo->short_name,
		"dns_name", dinfo->dns_name,
		"sid", sid_str,
		"domain_flags", domain_flags,
		"online", dinfo->domain_flags &
		WBC_DOMINFO_DOMAIN_OFFLINE ? Py_False : Py_True
	);
}

static PyObject *wbclient_domain_info(PyObject *obj, PyObject *argsunused)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	py_wbdomain *self = (py_wbdomain *)obj;
	PyObject *out = NULL;
	struct wbcDomainInfo *dinfo = NULL;

	wbc_status = wbcCtxDomainInfo(
		self->wbclient->ctx, self->domain, &dinfo
	);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcDomainInfo failed");
		return NULL;
	}

	if (self->sid_str[0] == '\0') {
		populate_domain_info(self, dinfo, false);
	}
	out = py_domain_info(dinfo);
	wbcFreeMemory(dinfo);

	if (out && (self->trust_type != -1)) {
		PyObject *trust_info = NULL;
		int err;

		trust_info = get_trust_type(
			self->trust_type,
			self->trust_flags,
			self->trust_routing[0] != '\0' ?
			self->trust_routing : NULL
		);
		if (trust_info == NULL) {
			Py_DECREF(out);
			return NULL;
		}
		err = PyDict_SetItemString(
			out, "trust_information", trust_info
		);
		Py_XDECREF(trust_info);
		if (err) {
			Py_DECREF(out);
			return NULL;
		}
	}

	return out;
}

static PyObject *wbclient_dc_name(PyObject *obj, PyObject *argsunused)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	py_wbdomain *self = (py_wbdomain *)obj;
	PyObject *out = NULL;
	const char **dc_names, **dc_ips;
	size_t num_dcs;

	/*
	 * NOTE: wbcCtxDcInfo retieves current DC from gencache
	 * and so there will be at most one DC in the response.
	 */
	wbc_status = wbcCtxDcInfo(
		self->wbclient->ctx, self->domain,
		&num_dcs, &dc_names, &dc_ips
	);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcCtxDcInfo failed");
		return NULL;
	}

	if (num_dcs == 0) {
		wbcFreeMemory(dc_names);
		wbcFreeMemory(dc_ips);
		Py_RETURN_NONE;
	}

	out = Py_BuildValue(
		"{s:s, s:s}",
		"name", dc_names[0],
		"address", dc_ips[0]
	);

	wbcFreeMemory(dc_names);
	wbcFreeMemory(dc_ips);
	return out;
}

static PyObject *py_wbdomain_new(PyTypeObject *obj,
			       PyObject *args_unused,
			       PyObject *kwargs_unused)
{
	py_wbdomain *self = NULL;
	self = (py_wbdomain *)obj->tp_alloc(obj, 0);
	if (self == NULL) {
		return NULL;
	}
	return (PyObject *)self;
}

static int py_wbdomain_init(PyObject *obj,
			  PyObject *args,
			  PyObject *kwargs)
{
	py_wbdomain *self = (py_wbdomain *)obj;
	PyObject *tmp_domain_info = NULL;
	PyObject *pyclient = NULL;
	const char *dom = NULL;

	if (!PyArg_ParseTuple(args, "Os", &pyclient, &dom)) {
		return -1;
	}

	strlcpy(self->domain, dom, sizeof(self->domain));
	self->trust_type = -1;

	self->wbclient = (py_wbclient *)pyclient;
	Py_INCREF(self->wbclient);

	/* attempt to pre-populate domain information */
	tmp_domain_info = wbclient_domain_info(obj, NULL);
	Py_XDECREF(tmp_domain_info);

	return 0;
}

static void py_wbdomain_dealloc(py_wbdomain *self)
{
	Py_XDECREF(self->wbclient);
        Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *domain_get_name(PyObject *obj, void *closure)
{
	py_wbdomain *self = (py_wbdomain *)obj;
	return Py_BuildValue("s", self->domain);
}

static PyObject *domain_get_dns_name(PyObject *obj, void *closure)
{
	py_wbdomain *self = (py_wbdomain *)obj;
	return Py_BuildValue("s", self->dns_domain);
}

static PyObject *domain_get_sid(PyObject *obj, void *closure)
{
	py_wbdomain *self = (py_wbdomain *)obj;
	return Py_BuildValue("s", self->sid_str);
}

static PyObject *py_wbdomain_repr(PyObject *obj)
{
	py_wbdomain *self = (py_wbdomain *)obj;

	return PyUnicode_FromFormat(
		"wbclient.Domain(netbios_domain=%s, "
		"dns_domain=%s, sid=%s)",
		self->domain, self->dns_domain,
		self->sid_str
	);
}

static PyGetSetDef domain_object_getsetters[] = {
	{
		.name	= discard_const_p(char, "name"),
		.get	= (getter)domain_get_name,
	},
	{
		.name	= discard_const_p(char, "dns_name"),
		.get	= (getter)domain_get_dns_name,
	},
	{
		.name	= discard_const_p(char, "sid"),
		.get	= (getter)domain_get_sid,
	},
	{ .name = NULL }
};

static PyMethodDef domain_object_methods[] = {
	{
		.ml_name = "current_domain_controller",
		.ml_meth = (PyCFunction)wbclient_dc_name,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Name and IP address of active DC"
	},
	{
		.ml_name = "check_secret",
		.ml_meth = (PyCFunction)wbclient_check_secret,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Verify workstation trust account is working"
	},
	{
		.ml_name = "ping_dc",
		.ml_meth = (PyCFunction)wbclient_ping_dc,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Issue no-effect command to our DC. Returns DC name."
	},
	{
		.ml_name = "domain_info",
		.ml_meth = (PyCFunction)wbclient_domain_info,
		.ml_flags = METH_NOARGS,
		.ml_doc = "Returns dictionary containing information about domain."
	},
	{
		.ml_name = "users",
		.ml_meth = (PyCFunction)wbclient_domain_users,
		.ml_flags = METH_NOARGS,
		.ml_doc = "List of names of users in domain"
	},
	{
		.ml_name = "groups",
		.ml_meth = (PyCFunction)wbclient_domain_groups,
		.ml_flags = METH_NOARGS,
		.ml_doc = "List of names of groups in domain"
	},
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject PyDomain = {
	.tp_name = "wbclient.Domain",
	.tp_basicsize = sizeof(py_wbdomain),
	.tp_methods = domain_object_methods,
	.tp_getset = domain_object_getsetters,
	.tp_new = py_wbdomain_new,
	.tp_init = py_wbdomain_init,
	.tp_repr = py_wbdomain_repr,
	.tp_doc = "winbind domain",
	.tp_dealloc = (destructor)py_wbdomain_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

struct domain_iter_info {
	const char *restrict_domain;
	py_wbclient *client;
	PyObject *(*fn)(py_wbclient *ctx, const struct wbcDomainInfo domain);
};

static PyObject *wbclient_iter_domains(struct domain_iter_info *iter_info)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	size_t i, num_domains;
	struct wbcDomainInfo *domain_list = NULL;
	PyObject *out = NULL;

	wbc_status = wbcCtxListTrusts(
		iter_info->client->ctx, &domain_list, &num_domains
	);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcListTrusts failed");
		return NULL;
	}

	out = Py_BuildValue("[]");
	if (out == NULL) {
		wbcFreeMemory(domain_list);
		return NULL;
	}

	for (i=0; i<num_domains; i++) {
		PyObject *pydomain = NULL;
		int err;

		if (iter_info->restrict_domain &&
		    !strequal(domain_list[i].short_name,
			      iter_info->restrict_domain)) {
			continue;
		}

		pydomain = iter_info->fn(iter_info->client, domain_list[i]);
		if (pydomain == NULL) {
				wbcFreeMemory(domain_list);
			return NULL;
		}

		err = PyList_Append(out, pydomain);
		Py_DECREF(pydomain);
		if (err == -1) {
			Py_DECREF(out);
			wbcFreeMemory(domain_list);
			return NULL;
		}
	}
	wbcFreeMemory(domain_list);
	return out;
}

static PyObject *domain_list_cb(py_wbclient *ctx,
				const struct wbcDomainInfo domain)
{
	py_wbdomain *dom = NULL;
	dom = (py_wbdomain *)PyObject_CallFunction(
		(PyObject *)&PyDomain, "Os", ctx, domain.short_name
	);
	if (dom == NULL) {
		return NULL;
	}
	populate_domain_info(dom, &domain, true);
	return (PyObject *)dom;
}

static PyObject *wbclient_trusted_domains(PyObject *obj, PyObject *args_unused)
{
	py_wbclient *self = (py_wbclient *)obj;
	struct domain_iter_info iter_info = (struct domain_iter_info){
		.fn = domain_list_cb,
		.client = self
	};

	return wbclient_iter_domains(&iter_info);
}

static PyObject *wbclient_get_domain(PyObject *obj, PyObject *args)
{
	py_wbclient *self = (py_wbclient *)obj;
	const char *domain = NULL;

	if (!PyArg_ParseTuple(args, "|s", &domain)) {
		return NULL;
	}
	if (domain == NULL) {
		domain = self->iface_details->netbios_domain;
	}

	return PyObject_CallFunction((PyObject *)&PyDomain, "Os", self, domain);
}

static bool pysidlist_to_sids(PyObject *sidlist,
			      struct wbcDomainSid **_sid,
			      int *_num_sids)
{
	wbcErr wbc_status;
	struct wbcDomainSid *sids = NULL;
	int num_sids = 0;
	Py_ssize_t list_sz = PyList_Size(sidlist);
	size_t i;

	sids = calloc((size_t)list_sz, sizeof(struct wbcDomainSid));
	if (sids == NULL) {
		PyErr_NoMemory();
		return false;
	}

	for (i = 0; i < list_sz; i++, num_sids++) {
		PyObject *entry = NULL;
		const char *decoded_sid = NULL;
		Py_ssize_t sid_str_sz = 0;

		entry = PyList_GetItem(sidlist, i);
		if (entry == NULL) {
			free(sids);
			return false;
		}
		if (!PyUnicode_Check(entry)) {
			PyErr_SetString(
				PyExc_TypeError,
				"Item is not a unicode string"
			);
			free(sids);
			Py_XDECREF(entry);
			return false;
		}

		decoded_sid = PyUnicode_AsUTF8AndSize(entry, &sid_str_sz);
		if (decoded_sid == NULL) {
			free(sids);
			return false;
		}

		wbc_status = wbcStringToSid(decoded_sid, &sids[num_sids]);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			free(sids);
			set_exc_from_wbcerrno(wbc_status, "wbcStringToSid failed");
			return false;
		}
	}

	*_sid = sids;
	*_num_sids = num_sids;
	return true;
}

static PyObject *unixid_to_py(py_wbclient *ctx,
			      const struct wbcUnixId *xid,
			      const char *sid)
{
	PyObject *entry = NULL;
	uid_t id = -1;

	switch(xid->type) {
	case WBC_ID_TYPE_UID:
		id = xid->id.uid;
		break;
	case WBC_ID_TYPE_GID:
		id = xid->id.gid;
		break;
	case WBC_ID_TYPE_BOTH:
		id = xid->id.uid;
		break;
	default:
		/* Error will be set when trying to create entry */
		break;
	}

	entry = PyObject_CallFunction(
		(PyObject *)&PyUidGid, "OIIs",
		ctx, id, xid->type, sid);

	return entry;
}

static PyObject *py_sids_to_xids(py_wbclient *client,
				 struct wbcDomainSid *sids,
				 int num_sids)
{
	char sidstr[WBC_SID_STRING_BUFLEN] = { 0 };
	struct wbcUnixId *unix_ids = NULL;
	wbcErr wbc_status;
	PyObject *mapped = NULL;
	PyObject *unmapped = NULL;
	int i;

	unix_ids = calloc(num_sids, sizeof(struct wbcUnixId));
	if (unix_ids == NULL) {
		return PyErr_NoMemory();
	}

	wbc_status = wbcCtxSidsToUnixIds(client->ctx, sids, num_sids, unix_ids);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		free(unix_ids);
		set_exc_from_wbcerrno(wbc_status, "wbcSidsToUnixIds failed");
		return NULL;
	}

	mapped = Py_BuildValue("{}");
	if (mapped == NULL) {
		free(unix_ids);
		return NULL;
	}

	unmapped = Py_BuildValue("{}");
	if (unmapped == NULL) {
		free(unix_ids);
		Py_XDECREF(mapped);
		return NULL;
	}

	for (i = 0; i < num_sids; i++) {
		int err;
		PyObject *py_xid = NULL;
		PyObject *target = mapped;

		wbcSidToStringBuf(&sids[i], sidstr, sizeof(sidstr));

		py_xid = unixid_to_py(client, &unix_ids[i], sidstr);
		if (py_xid == NULL) {
			PyErr_Clear();
			py_xid = Py_BuildValue("s", sidstr);
			if (py_xid == NULL) {
				free(unix_ids);
				return NULL;
			}
			target = unmapped;
		}

		err = PyDict_SetItemString(target, sidstr, py_xid);
		Py_XDECREF(py_xid);
		if (err) {
			Py_XDECREF(mapped);
			Py_XDECREF(unmapped);
			free(unix_ids);
			return NULL;
		}
	}
	free(unix_ids);
	return Py_BuildValue(
		"{s:N, s:N}",
		"mapped", mapped,
		"unmapped", unmapped
	);
}

static PyObject *wbclient_sids_to_xids(PyObject *obj, PyObject *args)
{
	py_wbclient *self = (py_wbclient *)obj;
	PyObject *pysidlist = NULL;
	PyObject *out = NULL;
	int num_sids = 0;
	struct wbcDomainSid *sids = NULL;
	bool ok;

	if (!PyArg_ParseTuple(args, "O", &pysidlist)) {
		return NULL;
	}

	if (!PyList_Check(pysidlist)) {
		PyErr_SetString(
			PyExc_TypeError,
			"argument is not a list of SIDS"
		);
		return NULL;
	}

	if (PyList_Size(pysidlist) == 0) {
		return Py_BuildValue("[]");
	}

	ok = pysidlist_to_sids(pysidlist, &sids, &num_sids);
	if (!ok) {
		return NULL;
	}

	out = py_sids_to_xids(self, sids, num_sids);
	free(sids);
	return out;
}

static bool entry_to_unixid(PyObject *entry, struct wbcUnixId *unixid)
{
	PyObject *idtype = NULL;
	PyObject *xid = NULL;
	Py_ssize_t idtype_len;
	const char *idtype_str = NULL;
	size_t xid_val;

	idtype = PyDict_GetItemString(entry, "id_type");
	if (idtype == NULL) {
		PyErr_SetString(
			PyExc_KeyError,
			"id_type is required for entry"
		);
		return false;
	}

	xid = PyDict_GetItemString(entry, "id");
	if (xid == NULL) {
		PyErr_SetString(
			PyExc_KeyError,
			"id is required for entry"
		);
		return false;
	}

	if (!PyUnicode_Check(idtype)) {
		PyErr_SetString(
			PyExc_TypeError,
			"idtype must be string"
		);
		return false;
	}

	idtype_str = PyUnicode_AsUTF8AndSize(idtype, &idtype_len);
	if (idtype_str == NULL) {
		return false;
	}

	if (!PyLong_Check(xid)) {
		PyErr_SetString(
			PyExc_TypeError,
			"id must be integer"
		);
		return false;
	}

	xid_val = PyLong_AsSize_t(xid);
	if (xid_val == -1) {
		if (PyErr_Occurred()) {
			return false;
		}

		PyErr_SetString(
			PyExc_ValueError,
			"id may not be -1"
		);
		return false;
	}

	if (xid_val >= UINT32_MAX) {
		PyErr_SetString(
			PyExc_ValueError,
			"id is invalid"
		);
		return false;
	}

	if (strcmp(idtype_str, "UID") == 0) {
		unixid->type = WBC_ID_TYPE_UID;
		unixid->id.uid = (uid_t)xid_val;
	} else if (strcmp(idtype_str, "GID") == 0) {
		unixid->type = WBC_ID_TYPE_GID;
		unixid->id.gid = (uid_t)xid_val;
	} else {
		PyErr_SetString(
			PyExc_ValueError,
			"idtype must be UID or GID"
		);
		return false;
	}

	return true;
}

static bool pyxidlist_to_sids(PyObject *pyxidlist,
			      struct wbcUnixId **_xids,
			      Py_ssize_t list_cnt)
{
	struct wbcUnixId *xids = NULL;
	PyObject *entry = NULL;
	bool ok;
	size_t i;

	xids = calloc((size_t)list_cnt, sizeof(struct wbcUnixId));
	if (xids == NULL) {
		return PyErr_NoMemory();
	}

	for (i = 0; i < list_cnt; i++) {
		entry = PyList_GetItem(pyxidlist, i);
		if (entry == NULL) {
			free(xids);
			return false;
		}
		if (!PyDict_Check(entry)) {
			free(xids);
			PyErr_SetString(
				PyExc_TypeError,
				"expected dictionary "
				"with following keys and values: "
				"string \"idtype\", permitted values: "
				"UID and GID, integer \"id\" for uid or "
				"gid in question."
			);
			return false;
		}
		ok = entry_to_unixid(entry, &xids[i]);
		if (!ok) {
			free(xids);
			return false;
		}
	}
	*_xids = xids;
	return true;
}

static PyObject *xidlist_to_pysids(py_wbclient *client,
				   struct wbcUnixId *xids,
				   Py_ssize_t cnt)
{
	static struct wbcDomainSid null_sid = { 0 };
	wbcErr wbc_status;
	struct wbcDomainSid *sids = NULL;
	int i;
	PyObject *mapped = NULL;
	PyObject *unmapped = NULL;

	sids = calloc((size_t)cnt, sizeof(struct wbcDomainSid));
	if (sids == NULL) {
		return NULL;
	}

	wbc_status = wbcCtxUnixIdsToSids(client->ctx, xids, cnt, sids);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		free(sids);
		set_exc_from_wbcerrno(wbc_status, "wbcUnixIdsToSids failed");
		return NULL;
	}

	mapped = Py_BuildValue("{}");
	if (mapped == NULL) {
		free(sids);
		return NULL;
	}

	unmapped = Py_BuildValue("{}");
	if (unmapped == NULL) {
		free(sids);
		Py_DECREF(mapped);
		return NULL;
	}

	for (i = 0; i < cnt; i++) {
		int err;
		char sidstr[WBC_SID_STRING_BUFLEN];
		char key[16];
		PyObject *target = mapped;
		py_uid_gid *entry = NULL;

		wbcSidToStringBuf(&sids[i], sidstr, sizeof(sidstr));
		if (memcmp(&null_sid, &sids[i], sizeof(struct wbcDomainSid)) == 0) {
			target = unmapped;
		}

		entry = (py_uid_gid *)unixid_to_py(client, &xids[i], sidstr);
		if (entry == NULL) {
			free(sids);
			Py_DECREF(mapped);
			Py_DECREF(unmapped);
			return NULL;
		}

		snprintf(key, sizeof(key), "%s:%u", entry->idtype_str, entry->id);
		err = PyDict_SetItemString(target, key, (PyObject *)entry);
		Py_XDECREF(entry);
		if (err) {
			free(sids);
			Py_DECREF(mapped);
			Py_DECREF(unmapped);
			return NULL;
		}
	}

	free(sids);
	return Py_BuildValue(
		"{s:N, s:N}",
		"mapped", mapped,
		"unmapped", unmapped
	);
}

static PyObject *wbclient_xids_to_sids(PyObject *obj, PyObject *args)
{
	py_wbclient *self = (py_wbclient *)obj;
	PyObject *pyxidlist = NULL;
	PyObject *out = NULL;
	Py_ssize_t xid_cnt;
	struct wbcUnixId *xids = NULL;
	bool ok;

	if (!PyArg_ParseTuple(args, "O", &pyxidlist)) {
		return NULL;
	}

	if (!PyList_Check(pyxidlist)) {
		PyErr_SetString(
			PyExc_TypeError,
			"expected list of dictionaries "
			"with following keys and values: "
			"string \"idtype\", permitted values: "
			"UID and GID, integer \"id\" for uid or "
			"gid in question."
		);
		return NULL;
	}

	xid_cnt = PyList_Size(pyxidlist);
	if (xid_cnt == 0) {
		return Py_BuildValue("[]");
	}

	ok = pyxidlist_to_sids(pyxidlist, &xids, xid_cnt);
	if (!ok) {
		return NULL;
	}

	out = xidlist_to_pysids(self, xids, xid_cnt);
	free(xids);
	return out;
}

static bool name_to_unixid_and_sid(py_wbclient *self,
				   const char *full_name,
				   struct wbcUnixId **xid_out,
				   char *sid_out,
				   size_t sidbufsz)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	struct wbcUnixId *xid = NULL;
	enum wbcSidType type;
	char user[256] = { 0 };
	char domain[256] = { 0 };
	char *p = NULL;

	p = strchr(full_name, self->iface_details->winbind_separator);
	if (p == NULL) {
		/*
		 * If this is UPN then leave domain empty
		 * otherwise copy the netbios_domain from
		 * our winbind interface details
		 */
		strlcpy(user, full_name, sizeof(user));
		p = strchr(full_name, '@');
		if (p == NULL) {
			strlcpy(domain,
				self->iface_details->netbios_domain,
				sizeof(user)
			);
		}
	} else {
		strlcpy(user, p + 1, sizeof(user));
		strlcpy(domain, full_name, sizeof(domain));
		domain[PTR_DIFF(p, full_name)] = '\0';
	}

	wbc_status = wbcCtxLookupName(self->ctx, domain, user, &sid, &type);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcCtxLookupName failed");
		return false;
	}

	xid = calloc(1, sizeof(struct wbcUnixId));
	if (!xid) {
		PyErr_NoMemory();
		return false;
	}

	wbc_status = wbcCtxSidsToUnixIds(self->ctx, &sid, 1, xid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcCtxSidsToUnixIds failed");
		return false;
	}

	*xid_out = xid;
	wbcSidToStringBuf(&sid, sid_out, sidbufsz);
	return true;
}

static PyObject *wbclient_lookup_name(PyObject *obj, PyObject *args)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	py_wbclient *self = (py_wbclient *)obj;
	const char *full_name = NULL;
	PyObject *out = NULL;
	struct wbcUnixId *xid = NULL;
	char sidstr[WBC_SID_STRING_BUFLEN] = { 0 };

	if (!PyArg_ParseTuple(args, "s", &full_name)) {
		return NULL;
	}

	if (!name_to_unixid_and_sid(self, full_name,
	    &xid, sidstr, sizeof(sidstr))) {
		return NULL;
	}

	out = unixid_to_py(self, xid, sidstr);
	free(xid);
	return out;
}

static PyMethodDef wbclient_object_methods[] = {
	{
		.ml_name = "all_domains",
		.ml_meth = (PyCFunction)wbclient_trusted_domains,
		.ml_flags = METH_NOARGS,
		.ml_doc = "List all known trusted domains (including own domain)"
	},
	{
		.ml_name = "uid_gid_objects_from_sids",
		.ml_meth = (PyCFunction)wbclient_sids_to_xids,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Convert list of SIDs UidGid objects"
	},
	{
		.ml_name = "uid_gid_objects_from_unix_ids",
		.ml_meth = (PyCFunction)wbclient_xids_to_sids,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Convert list of Unix IDs to UidGid objects"
	},
        {
		.ml_name = "uid_gid_object_from_name",
		.ml_meth = (PyCFunction)wbclient_lookup_name,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Convert user or group name to UidGid object"
        },
	{
		.ml_name = "domain",
		.ml_meth = (PyCFunction)wbclient_get_domain,
		.ml_flags = METH_VARARGS,
		.ml_doc = "Get specified domain (defaults to own domain)"
	},
	{ NULL, NULL, 0, NULL }
};

static PyObject *wbclient_get_separator(PyObject *obj, void *closure)
{
	py_wbclient *self = (py_wbclient *)obj;

	if (!self->iface_details->winbind_separator) {
		Py_RETURN_NONE;
	}

	return Py_BuildValue("c", self->iface_details->winbind_separator);
}

static PyObject *wbclient_get_netbios_name(PyObject *obj, void *closure)
{
	py_wbclient *self = (py_wbclient *)obj;
	return Py_BuildValue("s", self->iface_details->netbios_name);
}

static PyObject *wbclient_get_netbios_domain(PyObject *obj, void *closure)
{
	py_wbclient *self = (py_wbclient *)obj;
	return Py_BuildValue("s", self->iface_details->netbios_domain);
}

static PyObject *wbclient_get_dns_domain(PyObject *obj, void *closure)
{
	py_wbclient *self = (py_wbclient *)obj;
	return Py_BuildValue("s", self->iface_details->dns_domain);
}

static PyObject *wbclient_get_version(PyObject *obj, void *closure)
{
	py_wbclient *self = (py_wbclient *)obj;
	return Py_BuildValue("s", self->iface_details->winbind_version);
}

static PyGetSetDef wbclient_object_getsetters[] = {
	{
		.name	= discard_const_p(char, "separator"),
		.get	= (getter)wbclient_get_separator,
	},
	{
		.name	= discard_const_p(char, "netbios_name"),
		.get	= (getter)wbclient_get_netbios_name,
	},
	{
		.name	= discard_const_p(char, "netbios_domain"),
		.get	= (getter)wbclient_get_netbios_domain,
	},
	{
		.name	= discard_const_p(char, "dns_domain"),
		.get	= (getter)wbclient_get_dns_domain,
	},
	{
		.name	= discard_const_p(char, "version"),
		.get	= (getter)wbclient_get_version,
	},
	{ .name = NULL }
};

static PyObject *py_wbclient_new(PyTypeObject *obj,
			       PyObject *args_unused,
			       PyObject *kwargs_unused)
{
	py_wbclient *self = NULL;

	self = (py_wbclient *)obj->tp_alloc(obj, 0);
	if (self == NULL) {
		return NULL;
	}

	self->iface_details = NULL;
	return (PyObject *)self;
}

static int py_wbclient_init(PyObject *obj,
			  PyObject *args,
			  PyObject *kwargs)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcInterfaceDetails *details = NULL;
	py_wbclient *self = (py_wbclient *)obj;

	self->ctx = wbcCtxCreate();
	if (self->ctx == NULL) {
		PyErr_Format(
			PyExc_RuntimeError,
			"wbcCtxCreate() failed: %s",
			strerror(errno)
		);
		return -1;
	}

	wbc_status = wbcCtxInterfaceDetails(self->ctx, &details);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		set_exc_from_wbcerrno(wbc_status, "wbcInterfaceDetails failed");
		return -1;
	}

	self->iface_details = details;

	return 0;
}

static void py_wbclient_dealloc(py_wbclient *self)
{
	wbcFreeMemory(self->iface_details);
	self->iface_details = NULL;

	wbcCtxFree(self->ctx);
	self->ctx = NULL;
        Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyTypeObject PyWbclient = {
	.tp_name = "wbclient.Ctx",
	.tp_basicsize = sizeof(py_wbclient),
	.tp_methods = wbclient_object_methods,
	.tp_getset = wbclient_object_getsetters,
	.tp_new = py_wbclient_new,
	.tp_init = py_wbclient_init,
	.tp_doc = "winbind client",
	.tp_dealloc = (destructor)py_wbclient_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static PyMethodDef wbclient_module_methods[] = {
	{ .ml_name = NULL }
};
#define MODULE_DOC "Winbind client python bindings."

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "wbclient",
	.m_doc = MODULE_DOC,
	.m_size = -1,
	.m_methods = wbclient_module_methods,
};

PyObject* module_init(void)
{
	PyObject *m = NULL;
	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return NULL;
	}

	if (PyType_Ready(&PyWbclient) < 0) {
		Py_XDECREF(m);
		return NULL;
	}

	Py_INCREF(&PyWbclient);

	if (PyType_Ready(&PyDomain) < 0) {
		Py_XDECREF(m);
		return NULL;
	}

	Py_INCREF(&PyDomain);

	if (PyType_Ready(&PyUidGid) < 0) {
		Py_XDECREF(m);
		return NULL;
	}

	Py_INCREF(&PyUidGid);

	PyExc_WBCError =
		PyErr_NewException("wbclient.WBCError",
				   PyExc_RuntimeError,
				   NULL);

	if (PyExc_WBCError == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	if (PyModule_AddObject(m, "WBCError", PyExc_WBCError) < 0) {
		Py_DECREF(m);
		Py_DECREF(&PyExc_WBCError);
		return NULL;
	}

	if (PyModule_AddObject(m, "Ctx", (PyObject *)&PyWbclient) < 0) {
		Py_DECREF(m);
		Py_DECREF(&PyWbclient);
		return NULL;
	};


	PyModule_AddIntConstant(m, "ID_TYPE_UID", WBC_ID_TYPE_UID);
	PyModule_AddIntConstant(m, "ID_TYPE_GID", WBC_ID_TYPE_GID);
	PyModule_AddIntConstant(m, "ID_TYPE_BOTH", WBC_ID_TYPE_BOTH);

	PyModule_AddIntConstant(m, "SID_TYPE_NAME_USE_NONE", WBC_SID_NAME_USE_NONE);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_USER", WBC_SID_NAME_USER);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_DOM_GRP", WBC_SID_NAME_DOM_GRP);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_DOMAIN", WBC_SID_NAME_DOMAIN);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_ALIAS", WBC_SID_NAME_ALIAS);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_WKN_GRP", WBC_SID_NAME_WKN_GRP);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_DELETED", WBC_SID_NAME_DELETED);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_INVALID", WBC_SID_NAME_INVALID);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_UNKNOWN", WBC_SID_NAME_UNKNOWN);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_COMPUTER", WBC_SID_NAME_COMPUTER);
	PyModule_AddIntConstant(m, "SID_TYPE_NAME_LABEL", WBC_SID_NAME_LABEL);

	PyModule_AddIntConstant(m, "WBC_ERR_SUCCESS", WBC_ERR_SUCCESS);
	PyModule_AddIntConstant(m, "WBC_ERR_NOT_IMPLEMENTED", WBC_ERR_NOT_IMPLEMENTED);
	PyModule_AddIntConstant(m, "WBC_ERR_UNKNOWN_FAILURE", WBC_ERR_UNKNOWN_FAILURE);
	PyModule_AddIntConstant(m, "WBC_ERR_NO_MEMORY", WBC_ERR_NO_MEMORY);
	PyModule_AddIntConstant(m, "WBC_ERR_INVALID_SID", WBC_ERR_INVALID_SID);
	PyModule_AddIntConstant(m, "WBC_ERR_WINBIND_NOT_AVAILABLE", WBC_ERR_WINBIND_NOT_AVAILABLE);
	PyModule_AddIntConstant(m, "WBC_ERR_DOMAIN_NOT_FOUND", WBC_ERR_DOMAIN_NOT_FOUND);
	PyModule_AddIntConstant(m, "WBC_ERR_INVALID_RESPONSE", WBC_ERR_INVALID_RESPONSE);
	PyModule_AddIntConstant(m, "WBC_ERR_NSS_ERROR", WBC_ERR_NSS_ERROR);
	PyModule_AddIntConstant(m, "WBC_ERR_AUTH_ERROR", WBC_ERR_AUTH_ERROR);
	PyModule_AddIntConstant(m, "WBC_ERR_UNKNOWN_USER", WBC_ERR_UNKNOWN_USER);
	PyModule_AddIntConstant(m, "WBC_ERR_UNKNOWN_GROUP", WBC_ERR_UNKNOWN_GROUP);
	PyModule_AddIntConstant(m, "WBC_ERR_PWD_CHANGE_FAILED", WBC_ERR_PWD_CHANGE_FAILED);
	return m;
}

PyMODINIT_FUNC PyInit_wbclient(void)
{
	return module_init();
}
