/*
   CTDB python client - Database Iterator

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

/*
 * Iterator state structure for database iteration
 */
typedef struct {
	PyObject_HEAD;
	py_ctdb_db_ctx *db_ctx;
	TDB_DATA *keys;
	size_t num_keys;
	size_t current_index;
} py_ctdb_db_iter_ctx;

/*
 * Callback for traverse - collects keys into a list
 */
struct key_collection_state {
	TDB_DATA *keys;
	size_t num_keys;
	size_t capacity;
	bool error_occurred;
};

static int collect_keys_callback(uint32_t reqid,
				  struct ctdb_ltdb_header *header,
				  TDB_DATA key,
				  TDB_DATA data,
				  void *private_data)
{
	struct key_collection_state *state =
		(struct key_collection_state *)private_data;

	/* Skip empty or deleted records */
	if (key.dsize == 0 || data.dptr == NULL) {
		return 0;
	}

	/* Skip the sequence number key for persistent databases */
	if (key.dsize == (strlen(CTDB_DB_SEQNUM_KEY) + 1) &&
	    memcmp(key.dptr, CTDB_DB_SEQNUM_KEY, key.dsize) == 0) {
		return 0;
	}

	/* Expand capacity if needed */
	if (state->num_keys >= state->capacity) {
		size_t new_capacity = state->capacity * 2;
		if (new_capacity == 0) {
			new_capacity = 64;
		}

		TDB_DATA *new_keys = PyMem_RawRealloc(state->keys,
						      new_capacity * sizeof(TDB_DATA));
		if (new_keys == NULL) {
			state->error_occurred = true;
			return ENOMEM;
		}

		/* Zero out the newly allocated portion for security */
		memset(&new_keys[state->capacity], 0,
		       (new_capacity - state->capacity) * sizeof(TDB_DATA));

		state->keys = new_keys;
		state->capacity = new_capacity;
	}

	/* Copy the key */
	state->keys[state->num_keys].dptr = PyMem_RawMalloc(key.dsize);
	if (state->keys[state->num_keys].dptr == NULL) {
		state->error_occurred = true;
		return ENOMEM;
	}

	memcpy(state->keys[state->num_keys].dptr, key.dptr, key.dsize);
	state->keys[state->num_keys].dsize = key.dsize;
	state->num_keys++;

	return 0;
}

/*
 * Create iterator for a database
 */
PyObject *py_ctdb_db_iter_new(py_ctdb_db_ctx *db_ctx)
{
	py_ctdb_db_iter_ctx *iter_ctx = NULL;
	struct key_collection_state state = {0};
	int err;

	if (db_ctx->db == NULL) {
		PyErr_SetString(PyExc_ValueError, "Database context not initialized");
		return NULL;
	}

	/* Collect all keys via traverse */
	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(db_ctx->client);
	err = ctdb_db_traverse_local(db_ctx->db, true, false,
				     collect_keys_callback, &state);
	PYCTDB_UNLOCK(db_ctx->client);
	Py_END_ALLOW_THREADS

	if (err != 0 || state.error_occurred) {
		/* Clean up any allocated keys */
		size_t i;
		for (i = 0; i < state.num_keys; i++) {
			PyMem_RawFree(state.keys[i].dptr);
		}
		PyMem_RawFree(state.keys);

		if (state.error_occurred) {
			PyErr_NoMemory();
		} else {
			pyctdb_err(err, "Failed to traverse database");
		}
		return NULL;
	}

	/* Create the iterator object */
	iter_ctx = PyObject_New(py_ctdb_db_iter_ctx, &PyCtdbDBIter);
	if (iter_ctx == NULL) {
		size_t i;
		for (i = 0; i < state.num_keys; i++) {
			PyMem_RawFree(state.keys[i].dptr);
		}
		PyMem_RawFree(state.keys);
		return NULL;
	}

	iter_ctx->db_ctx = (py_ctdb_db_ctx *)Py_NewRef(db_ctx);
	iter_ctx->keys = state.keys;
	iter_ctx->num_keys = state.num_keys;
	iter_ctx->current_index = 0;

	return (PyObject *)iter_ctx;
}

static void py_ctdb_db_iter_dealloc(py_ctdb_db_iter_ctx *self)
{
	size_t i;

	/* Free all collected keys */
	for (i = 0; i < self->num_keys; i++) {
		PyMem_RawFree(self->keys[i].dptr);
	}
	PyMem_RawFree(self->keys);

	Py_CLEAR(self->db_ctx);
	PyObject_Del(self);
}

static PyObject *py_ctdb_db_iter_iter(PyObject *self)
{
	Py_INCREF(self);
	return self;
}

static PyObject *py_ctdb_db_iter_next(PyObject *self)
{
	py_ctdb_db_iter_ctx *iter_ctx = (py_ctdb_db_iter_ctx *)self;
	TDB_DATA key, data = {0};
	PyObject *py_key = NULL;
	PyObject *py_value = NULL;
	PyObject *result = NULL;
	pyctdb_error_t pyerr;
	int err;

	/* Check if we've exhausted all keys */
	if (iter_ctx->current_index >= iter_ctx->num_keys) {
		PyErr_SetNone(PyExc_StopIteration);
		return NULL;
	}

	key = iter_ctx->keys[iter_ctx->current_index];
	iter_ctx->current_index++;

	/* Fetch the value for this key */
	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(iter_ctx->db_ctx->client);
	err = py_ctdb_fetchrecord(iter_ctx->db_ctx, key, &data, &pyerr);
	PYCTDB_UNLOCK(iter_ctx->db_ctx->client);
	Py_END_ALLOW_THREADS

	if (err != 0) {
		if (err == ENOENT) {
			/* Key was deleted between traverse and fetch - skip it */
			return py_ctdb_db_iter_next(self);
		}
		pyctdb_err(err, pyerr.message);
		return NULL;
	}

	/* Build Python key and value */
	py_key = PyBytes_FromStringAndSize((const char *)key.dptr, key.dsize);
	if (py_key == NULL) {
		PyMem_RawFree(data.dptr);
		return NULL;
	}

	py_value = PyBytes_FromStringAndSize((const char *)data.dptr, data.dsize);
	PyMem_RawFree(data.dptr);

	if (py_value == NULL) {
		Py_DECREF(py_key);
		return NULL;
	}

	/* Return tuple of (key, value) */
	result = PyTuple_Pack(2, py_key, py_value);
	Py_DECREF(py_key);
	Py_DECREF(py_value);

	return result;
}

PyDoc_STRVAR(py_ctdb_db_iter__doc__,
"Iterator for CTDB database records.\n"
"\n"
"Yields tuples of (key, value) for each record in the database.\n"
"The iterator snapshot is taken at creation time, so records added\n"
"after iteration begins will not be included.\n"
);

PyTypeObject PyCtdbDBIter = {
	.tp_name = PYMODULE_NAME ".CtdbDBIterator",
	.tp_basicsize = sizeof(py_ctdb_db_iter_ctx),
	.tp_doc = py_ctdb_db_iter__doc__,
	.tp_dealloc = (destructor)py_ctdb_db_iter_dealloc,
	.tp_iter = py_ctdb_db_iter_iter,
	.tp_iternext = py_ctdb_db_iter_next,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};
