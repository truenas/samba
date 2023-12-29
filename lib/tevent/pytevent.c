/*
   Unix SMB/CIFS implementation.
   Python bindings for tevent

   Copyright (C) Jelmer Vernooij 2010

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "lib/replace/system/python.h"
#include "replace.h"
#include <tevent.h>


/* discard signature of 'func' in favour of 'target_sig' */
#define PY_DISCARD_FUNC_SIG(target_sig, func) (target_sig)(void(*)(void))func

void init_tevent(void);

typedef struct {
	PyObject_HEAD
	struct tevent_context *ev;
} TeventContext_Object;

typedef struct {
	PyObject_HEAD
	struct tevent_queue *queue;
} TeventQueue_Object;

typedef struct {
	PyObject_HEAD
	struct tevent_req *req;
} TeventReq_Object;

typedef struct {
	PyObject_HEAD
	struct tevent_signal *signal;
} TeventSignal_Object;

typedef struct {
	PyObject_HEAD
	struct tevent_timer *timer;
	PyObject *callback;
} TeventTimer_Object;

typedef struct {
	PyObject_HEAD
	struct tevent_fd *fd;
} TeventFd_Object;

static PyTypeObject TeventContext_Type;
static PyTypeObject TeventReq_Type;
static PyTypeObject TeventQueue_Type;
static PyTypeObject TeventSignal_Type;
static PyTypeObject TeventTimer_Type;
static PyTypeObject TeventFd_Type;

static PyObject *py_tevent_context_reinitialise(TeventContext_Object *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret = tevent_re_initialise(self->ev);
	if (ret != 0) {
		PyErr_SetNone(PyExc_RuntimeError);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_tevent_queue_stop(TeventQueue_Object *self,
		PyObject *Py_UNUSED(ignored))
{
	tevent_queue_stop(self->queue);
	Py_RETURN_NONE;
}

static PyObject *py_tevent_queue_start(TeventQueue_Object *self,
		PyObject *Py_UNUSED(ignored))
{
	tevent_queue_start(self->queue);
	Py_RETURN_NONE;
}

static void py_queue_trigger(struct tevent_req *req, void *private_data)
{
	PyObject *callback = private_data, *ret;

	ret = PyObject_CallFunction(callback, discard_const_p(char, ""));
	Py_XDECREF(ret);
}

static PyObject *py_tevent_queue_add(TeventQueue_Object *self, PyObject *args)
{
	TeventContext_Object *py_ev;
	TeventReq_Object *py_req;
	PyObject *trigger;
	bool ret;

	if (!PyArg_ParseTuple(args, "O!O!O", 
						  &TeventContext_Type, &py_ev,
						  &TeventReq_Type, &py_req,
						  &trigger))
		return NULL;

	Py_INCREF(trigger);

	ret = tevent_queue_add(self->queue, py_ev->ev, py_req->req,
						   py_queue_trigger, trigger);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "queue add failed");
		Py_DECREF(trigger);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMethodDef py_tevent_queue_methods[] = {
	{ "stop", (PyCFunction)py_tevent_queue_stop,
		METH_NOARGS,
		"S.stop()" },
	{ "start", (PyCFunction)py_tevent_queue_start,
		METH_NOARGS,
		"S.start()" },
	{ "add", (PyCFunction)py_tevent_queue_add, METH_VARARGS,
		"S.add(ctx, req, trigger, baton)" },
	{0},
};

static PyObject *py_tevent_context_wakeup_send(PyObject *self, PyObject *args)
{
	/* FIXME */

	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_loop_wait(TeventContext_Object *self,
		PyObject *Py_UNUSED(ignored))
{
	if (tevent_loop_wait(self->ev) != 0) {
		PyErr_SetNone(PyExc_RuntimeError);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_loop_once(TeventContext_Object *self,
		PyObject *Py_UNUSED(ignored))
{
	if (tevent_loop_once(self->ev) != 0) {
		PyErr_SetNone(PyExc_RuntimeError);
		return NULL;
	}
	Py_RETURN_NONE;
}

static void py_tevent_signal_handler(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data)
{
	PyObject *callback = (PyObject *)private_data, *ret;

	ret = PyObject_CallFunction(callback, discard_const_p(char, "ii"), signum, count);
	Py_XDECREF(ret);
}

static void py_tevent_signal_dealloc(TeventSignal_Object *self)
{
	talloc_free(self->signal);
	PyObject_Del(self);
}

static PyTypeObject TeventSignal_Type = {
	.tp_name = "tevent.Signal",
	.tp_basicsize = sizeof(TeventSignal_Object),
	.tp_dealloc = (destructor)py_tevent_signal_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject *py_tevent_context_add_signal(TeventContext_Object *self, PyObject *args)
{
	int signum, sa_flags;
	PyObject *handler;
	struct tevent_signal *sig;
	TeventSignal_Object *ret;

	if (!PyArg_ParseTuple(args, "iiO", &signum, &sa_flags, &handler))
		return NULL;

	Py_INCREF(handler);
	sig = tevent_add_signal(self->ev, NULL, signum, sa_flags,
							py_tevent_signal_handler, handler);

	ret = PyObject_New(TeventSignal_Object, &TeventSignal_Type);
	if (ret == NULL) {
		PyErr_NoMemory();
		talloc_free(sig);
		return NULL;
	}

	ret->signal = sig;

	return (PyObject *)ret;
}

static void py_timer_handler(struct tevent_context *ev,
				       struct tevent_timer *te,
				       struct timeval current_time,
				       void *private_data)
{
	TeventTimer_Object *self = private_data;
	PyObject *ret;

	ret = PyObject_CallFunction(self->callback, discard_const_p(char, "l"), te);
	if (ret == NULL) {
		/* No Python stack to propagate exception to; just print traceback */
		PyErr_PrintEx(0);
	}
	Py_XDECREF(ret);
}

static void py_tevent_timer_dealloc(TeventTimer_Object *self)
{
	if (self->timer) {
		talloc_free(self->timer);
	}
	Py_CLEAR(self->callback);
	PyObject_Del(self);
}

static int py_tevent_timer_traverse(TeventTimer_Object *self, visitproc visit, void *arg)
{
	Py_VISIT(self->callback);
	return 0;
}

static PyObject* py_tevent_timer_get_active(TeventTimer_Object *self,
			PyObject *Py_UNUSED(ignored))
{
	return PyBool_FromLong(self->timer != NULL);
}

struct PyGetSetDef py_tevent_timer_getset[] = {
	{
		.name = discard_const_p(char, "active"),
		.get = (getter)py_tevent_timer_get_active,
		.doc = discard_const_p(char, "true if the timer is scheduled to run"),
	},
	{0},
};

static PyTypeObject TeventTimer_Type = {
	.tp_name = "tevent.Timer",
	.tp_basicsize = sizeof(TeventTimer_Object),
	.tp_dealloc = (destructor)py_tevent_timer_dealloc,
	.tp_traverse = (traverseproc)py_tevent_timer_traverse,
	.tp_getset = py_tevent_timer_getset,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

struct TeventTimer_Object_ref {
	TeventTimer_Object *obj;
};

static int TeventTimer_Object_ref_destructor(struct TeventTimer_Object_ref *ref)
{
	ref->obj->timer = NULL;
	Py_CLEAR(ref->obj);
	return 0;
}

static PyObject *py_tevent_context_add_timer_internal(TeventContext_Object *self,
                                                      struct timeval next_event,
                                                      PyObject *callback)
{
	/* Ownership notes:
	 *
	 * There are 5 pieces in play; two tevent contexts and 3 Python objects:
	 * - The tevent timer
	 * - The tevent context
	 * - The Python context -- "self"
	 * - The Python timer (TeventTimer_Object) -- "ret"
	 * - The Python callback function -- "callback"
	 *
	 * We only use the Python context for getting the tevent context,
	 * afterwards it can be destroyed.
	 *
	 * The tevent context owns the tevent timer.
	 *
	 * The tevent timer holds a reference to the Python timer, so the Python
	 * timer must always outlive the tevent timer.
	 * The Python timer has a pointer to the tevent timer; a destructor is
	 * used to set this to NULL when the tevent timer is deallocated.
	 *
	 * The tevent timer can be deallocated in these cases:
	 *  1) when the context is destroyed
	 *  2) after the event fires
	 *  Posssibly, API might be added to cancel (free the tevent timer).
	 *
	 * The Python timer holds a reference to the callback.
	 */
	TeventTimer_Object *ret;
	struct TeventTimer_Object_ref *ref;

	ret = PyObject_New(TeventTimer_Object, &TeventTimer_Type);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	Py_INCREF(callback);
	ret->callback = callback;
	ret->timer = tevent_add_timer(self->ev, NULL, next_event, py_timer_handler,
	                              ret);
	if (ret->timer == NULL) {
		Py_DECREF(ret);
		PyErr_SetString(PyExc_RuntimeError, "Could not initialize timer");
		return NULL;
	}
	ref = talloc(ret->timer, struct TeventTimer_Object_ref);
	if (ref == NULL) {
		talloc_free(ret->timer);
		Py_DECREF(ret);
		PyErr_SetString(PyExc_RuntimeError, "Could not initialize timer");
		return NULL;
	}
	Py_INCREF(ret);
	ref->obj = ret;

	talloc_set_destructor(ref, TeventTimer_Object_ref_destructor);

	return (PyObject *)ret;
}

static PyObject *py_tevent_context_add_timer(TeventContext_Object *self, PyObject *args)
{
	struct timeval next_event;
	PyObject *callback;
	double secs, usecs;
	if (!PyArg_ParseTuple(args, "dO", &secs, &callback)){
		return NULL;
	}
	next_event.tv_sec = secs;
	usecs = (secs - next_event.tv_sec) * 1000000.0;
	next_event.tv_usec = usecs;
	return py_tevent_context_add_timer_internal(self, next_event, callback);
}

static PyObject *py_tevent_context_add_timer_offset(TeventContext_Object *self, PyObject *args)
{
	struct timeval next_event;
	double offset;
	int seconds;
	PyObject *callback;
	if (!PyArg_ParseTuple(args, "dO", &offset, &callback))
		return NULL;

	seconds = offset;
	offset -= seconds;
	next_event = tevent_timeval_current_ofs(seconds, (int)(offset*1000000));
	return py_tevent_context_add_timer_internal(self, next_event, callback);
}

static void py_fd_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data)
{
	PyObject *callback = private_data, *ret;

	ret = PyObject_CallFunction(callback, discard_const_p(char, "i"), flags);
	Py_XDECREF(ret);
}

static void py_tevent_fp_dealloc(TeventFd_Object *self)
{
	talloc_free(self->fd);
	PyObject_Del(self);
}

static PyTypeObject TeventFd_Type = {
	.tp_name = "tevent.Fd",
	.tp_basicsize = sizeof(TeventFd_Object),
	.tp_dealloc = (destructor)py_tevent_fp_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject *py_tevent_context_add_fd(TeventContext_Object *self, PyObject *args)
{
	int fd, flags;
	PyObject *handler;
	struct tevent_fd *tfd;
	TeventFd_Object *ret;

	if (!PyArg_ParseTuple(args, "iiO", &fd, &flags, &handler))
		return NULL;

	tfd = tevent_add_fd(self->ev, NULL, fd, flags, py_fd_handler, handler);
	if (tfd == NULL) {
		PyErr_SetNone(PyExc_RuntimeError);
		return NULL;
	}

	ret = PyObject_New(TeventFd_Object, &TeventFd_Type);
	if (ret == NULL) {
		talloc_free(tfd);
		return NULL;
	}
	ret->fd = tfd;

	return (PyObject *)ret;
}

static PyMethodDef py_tevent_context_methods[] = {
	{ "reinitialise", (PyCFunction)py_tevent_context_reinitialise,
		METH_NOARGS,
		"S.reinitialise()" },
	{ "wakeup_send", (PyCFunction)py_tevent_context_wakeup_send, 
		METH_VARARGS, "S.wakeup_send(wakeup_time) -> req" },
	{ "loop_wait", (PyCFunction)py_tevent_context_loop_wait,
		METH_NOARGS, "S.loop_wait()" },
	{ "loop_once", (PyCFunction)py_tevent_context_loop_once,
		METH_NOARGS, "S.loop_once()" },
	{ "add_signal", (PyCFunction)py_tevent_context_add_signal,
		METH_VARARGS, "S.add_signal(signum, sa_flags, handler) -> signal" },
	{ "add_timer", (PyCFunction)py_tevent_context_add_timer,
		METH_VARARGS, "S.add_timer(next_event, handler) -> timer" },
	{ "add_timer_offset", (PyCFunction)py_tevent_context_add_timer_offset,
		METH_VARARGS, "S.add_timer_offset(offset_seconds, handler) -> timer" },
	{ "add_fd", (PyCFunction)py_tevent_context_add_fd, 
		METH_VARARGS, "S.add_fd(fd, flags, handler) -> fd" },
	{0},
};

static PyObject *py_tevent_req_wakeup_recv(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_received(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_is_error(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_poll(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_is_in_progress(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyGetSetDef py_tevent_req_getsetters[] = {
	{
		.name = discard_const_p(char, "in_progress"),
		.get = (getter)py_tevent_req_is_in_progress,
		.doc = discard_const_p(char, "Whether the request is in progress"),
	},
	{0}
};

static PyObject *py_tevent_req_post(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_set_error(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_done(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_notify_callback(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_set_endtime(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_cancel(TeventReq_Object *self,
		PyObject *Py_UNUSED(ignored))
{
	if (!tevent_req_cancel(self->req)) {
		PyErr_SetNone(PyExc_RuntimeError);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyMethodDef py_tevent_req_methods[] = {
	{ "wakeup_recv", (PyCFunction)py_tevent_req_wakeup_recv,
		METH_NOARGS,
		"Wakeup received" },
	{ "received", (PyCFunction)py_tevent_req_received,
		METH_NOARGS,
		"Receive finished" },
	{ "is_error", (PyCFunction)py_tevent_req_is_error, METH_NOARGS,
		"is_error() -> (error, state)" },
	{ "poll", (PyCFunction)py_tevent_req_poll, METH_VARARGS,
		"poll(ctx)" },
	{ "post", (PyCFunction)py_tevent_req_post, METH_VARARGS,
		"post(ctx) -> req" },
	{ "set_error", (PyCFunction)py_tevent_req_set_error, METH_VARARGS,
		"set_error(error)" },
	{ "done", (PyCFunction)py_tevent_req_done, METH_NOARGS,
		"done()" },
	{ "notify_callback", (PyCFunction)py_tevent_req_notify_callback,
		METH_NOARGS, "notify_callback()" },
	{ "set_endtime", (PyCFunction)py_tevent_req_set_endtime,
		METH_VARARGS, "set_endtime(ctx, endtime)" },
	{ "cancel", (PyCFunction)py_tevent_req_cancel,
		METH_NOARGS, "cancel()" },
	{0}
};

static void py_tevent_req_dealloc(TeventReq_Object *self)
{
	talloc_free(self->req);
	PyObject_DEL(self);
}

static PyTypeObject TeventReq_Type = {
	.tp_name = "tevent.Request",
	.tp_basicsize = sizeof(TeventReq_Object),
	.tp_methods = py_tevent_req_methods,
	.tp_dealloc = (destructor)py_tevent_req_dealloc,
	.tp_getset = py_tevent_req_getsetters,
	/* FIXME: .tp_new = py_tevent_req_new, */
};

static PyObject *py_tevent_queue_get_length(TeventQueue_Object *self,
			PyObject *Py_UNUSED(ignored))
{
	return PyLong_FromLong(tevent_queue_length(self->queue));
}

static PyGetSetDef py_tevent_queue_getsetters[] = {
	{
		.name = discard_const_p(char, "length"),
		.get = (getter)py_tevent_queue_get_length,
		.doc = discard_const_p(char, "The number of elements in the queue."),
	},
	{0},
};

static void py_tevent_queue_dealloc(TeventQueue_Object *self)
{
	talloc_free(self->queue);
	PyObject_Del(self);
}

static PyTypeObject TeventQueue_Type = {
	.tp_name = "tevent.Queue",
	.tp_basicsize = sizeof(TeventQueue_Object),
	.tp_dealloc = (destructor)py_tevent_queue_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_getset = py_tevent_queue_getsetters,
	.tp_methods = py_tevent_queue_methods,
};

static PyObject *py_tevent_context_signal_support(PyObject *_self,
		PyObject *Py_UNUSED(ignored))
{
	TeventContext_Object *self = (TeventContext_Object *)_self;
	return PyBool_FromLong(tevent_signal_support(self->ev));
}

static PyGetSetDef py_tevent_context_getsetters[] = {
	{
		.name = discard_const_p(char, "signal_support"),
		.get = PY_DISCARD_FUNC_SIG(getter,
					   py_tevent_context_signal_support),
		.doc = discard_const_p(char, "if this platform and tevent context support signal handling"),
	},
	{0}
};

static void py_tevent_context_dealloc(TeventContext_Object *self)
{
	talloc_free(self->ev);
	PyObject_Del(self);
}

static PyObject *py_tevent_context_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "name", NULL };
	char *name = NULL;
	struct tevent_context *ev;
	TeventContext_Object *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", discard_const_p(char *, kwnames), &name))
		return NULL;

	if (name == NULL) {
		ev = tevent_context_init(NULL);
	} else {
		ev = tevent_context_init_byname(NULL, name);
	}

	if (ev == NULL) {
		PyErr_SetNone(PyExc_RuntimeError);
		return NULL;
	}

	ret = PyObject_New(TeventContext_Object, type);
	if (ret == NULL) {
		PyErr_NoMemory();
		talloc_free(ev);
		return NULL;
	}

	ret->ev = ev;
	return (PyObject *)ret;
}

static PyTypeObject TeventContext_Type = {
	.tp_name = "tevent.Context",
	.tp_new = py_tevent_context_new,
	.tp_basicsize = sizeof(TeventContext_Object),
	.tp_dealloc = (destructor)py_tevent_context_dealloc,
	.tp_methods = py_tevent_context_methods,
	.tp_getset = py_tevent_context_getsetters,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject *py_set_default_backend(PyObject *self, PyObject *args)
{
	char *backend_name;
	if (!PyArg_ParseTuple(args, "s", &backend_name))
		return NULL;

	tevent_set_default_backend(backend_name);

	Py_RETURN_NONE;
}

static PyObject *py_backend_list(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	PyObject *ret = NULL;
	PyObject *string = NULL;
	int i, result;
	const char **backends = NULL;

	ret = PyList_New(0);
	if (ret == NULL) {
		return NULL;
	}

	backends = tevent_backend_list(NULL);
	if (backends == NULL) {
		PyErr_SetNone(PyExc_RuntimeError);
		goto err;
	}
	for (i = 0; backends[i]; i++) {
		string = PyUnicode_FromString(backends[i]);
		if (!string) {
			goto err;
		}
		result = PyList_Append(ret, string);
		if (result) {
			goto err;
		}
		Py_DECREF(string);
		string = NULL;
	}

	talloc_free(backends);

	return ret;

err:
	Py_XDECREF(ret);
	Py_XDECREF(string);
	talloc_free(backends);
	return NULL;
}

static PyMethodDef tevent_methods[] = {
	{ "set_default_backend", (PyCFunction)py_set_default_backend, 
		METH_VARARGS, "set_default_backend(backend)" },
	{ "backend_list", (PyCFunction)py_backend_list, 
		METH_NOARGS, "backend_list() -> list" },
	{0},
};

#define MODULE_DOC PyDoc_STR("Python wrapping of talloc-maintained objects.")

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "_tevent",
	.m_doc = MODULE_DOC,
	.m_size = -1,
	.m_methods = tevent_methods,
};

PyObject * module_init(void);
PyObject * module_init(void)
{
	PyObject *m;

	if (PyType_Ready(&TeventContext_Type) < 0)
		return NULL;

	if (PyType_Ready(&TeventQueue_Type) < 0)
		return NULL;

	if (PyType_Ready(&TeventReq_Type) < 0)
		return NULL;

	if (PyType_Ready(&TeventSignal_Type) < 0)
		return NULL;

	if (PyType_Ready(&TeventTimer_Type) < 0)
		return NULL;

	if (PyType_Ready(&TeventFd_Type) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	Py_INCREF(&TeventContext_Type);
	PyModule_AddObject(m, "Context", (PyObject *)&TeventContext_Type);

	Py_INCREF(&TeventQueue_Type);
	PyModule_AddObject(m, "Queue", (PyObject *)&TeventQueue_Type);

	Py_INCREF(&TeventReq_Type);
	PyModule_AddObject(m, "Request", (PyObject *)&TeventReq_Type);

	Py_INCREF(&TeventSignal_Type);
	PyModule_AddObject(m, "Signal", (PyObject *)&TeventSignal_Type);

	Py_INCREF(&TeventTimer_Type);
	PyModule_AddObject(m, "Timer", (PyObject *)&TeventTimer_Type);

	Py_INCREF(&TeventFd_Type);
	PyModule_AddObject(m, "Fd", (PyObject *)&TeventFd_Type);

	PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION);

	return m;
}

PyMODINIT_FUNC PyInit__tevent(void);
PyMODINIT_FUNC PyInit__tevent(void)
{
	return module_init();
}
