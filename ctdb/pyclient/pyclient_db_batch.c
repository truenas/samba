/*
   CTDB python client - Database Batch Operations

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

static PyStructSequence_Field batch_op_fields[] = {
	{
		.name = "action",
		.doc = "Operation action: 'GET', 'SET', or 'DEL'",
	},
	{
		.name = "key",
		.doc = "Record key as bytes",
	},
	{
		.name = "value",
		.doc = "Record value as bytes (required for SET, ignored for GET/DEL)",
	},
	{ .name = NULL }
};

static PyStructSequence_Desc batch_op_desc = {
	.name = PYMODULE_NAME ".BatchOp",
	.doc = "Batch operation tuple (action, key, value)",
	.fields = batch_op_fields,
	.n_in_sequence = 3,
};

bool setup_batch_op_type(PyObject *module_ref)
{
	pyctdb_mod_state_t *state = pyctdb_get_state(module_ref);
	PyTypeObject *batch_op_type;

	batch_op_type = PyStructSequence_NewType(&batch_op_desc);
        PYCTDB_ASSERT(batch_op_type, "Failed to allocate batch_op_type");

	state->py_batch_op_type = batch_op_type;

	if (PyModule_AddObjectRef(module_ref, "BatchOp", (PyObject *)batch_op_type) < 0) {
		return false;
	}

	return true;
}

void free_batch_state(struct batch_state *state)
{
	size_t i;

	if (state->ops != NULL) {
		for (i = 0; i < state->num_ops; i++) {
			PyMem_RawFree(state->ops[i].key.dptr);
			if (state->ops[i].value.dptr != NULL) {
				PyMem_RawFree(state->ops[i].value.dptr);
			}
		}
		PyMem_RawFree(state->ops);
		state->ops = NULL;
	}

	if (state->results != NULL) {
		for (i = 0; i < state->num_ops; i++) {
			if (state->results[i] != NULL) {
				TDB_DATA *result_data = (TDB_DATA *)state->results[i];
				PyMem_RawFree(result_data->dptr);
				PyMem_RawFree(result_data);
				state->results[i] = NULL;
			}
		}
		PyMem_RawFree(state->results);
		state->results = NULL;
	}

	state->num_ops = 0;
	state->capacity = 0;
}

int parse_batch_operations(PyObject *operations, struct batch_state *state)
{
	PyObject *iterator = NULL;
	PyObject *item = NULL;
	int ret = -1;

	state->capacity = 16;
	state->num_ops = 0;

	/* Allocate initial arrays */
	state->ops = PyMem_RawMalloc(state->capacity * sizeof(struct batch_operation));
	state->results = PyMem_RawMalloc(state->capacity * sizeof(PyObject *));
	if (state->ops == NULL || state->results == NULL) {
		PyErr_NoMemory();
		goto cleanup;
	}
	memset(state->results, 0, state->capacity * sizeof(PyObject *));

	/* Get iterator for the operations */
	iterator = PyObject_GetIter(operations);
	if (iterator == NULL) {
		PyErr_SetString(PyExc_TypeError, "operations must be iterable");
		goto cleanup;
	}

	/* Parse operations from Python objects */
	while ((item = PyIter_Next(iterator)) != NULL) {
		const char *action_str;
		Py_ssize_t key_len, val_len = 0;
		uint8_t *key_data, *val_data = NULL;
		struct batch_operation *op;
		PyObject *action_obj, *key_obj, *value_obj;
		pyctdb_mod_state_t *mod_state = pyctdb_get_state(NULL);

		/* Expand capacity if needed */
		if (state->num_ops >= state->capacity) {
			size_t new_capacity = state->capacity * 2;
			struct batch_operation *new_ops;
			PyObject **new_results;

			new_ops = PyMem_RawRealloc(state->ops,
						   new_capacity * sizeof(struct batch_operation));
			new_results = PyMem_RawRealloc(state->results,
						       new_capacity * sizeof(PyObject *));

			if (new_ops == NULL || new_results == NULL) {
				PyMem_RawFree(new_ops);
				PyMem_RawFree(new_results);
				PyErr_NoMemory();
				Py_DECREF(item);
				goto cleanup;
			}

			memset(&new_results[state->capacity], 0,
			       (new_capacity - state->capacity) * sizeof(PyObject *));

			state->ops = new_ops;
			state->results = new_results;
			state->capacity = new_capacity;
		}

		/* Check if it's our BatchOp struct sequence type */
		if (!PyObject_IsInstance(item, (PyObject *)mod_state->py_batch_op_type)) {
			Py_DECREF(item);
			PyErr_SetString(PyExc_TypeError,
					"Each operation must be a BatchOp instance");
			goto cleanup;
		}

		/* Access struct sequence fields directly */
		action_obj = PyStructSequence_GET_ITEM(item, 0);
		key_obj = PyStructSequence_GET_ITEM(item, 1);
		value_obj = PyStructSequence_GET_ITEM(item, 2);

		/* Extract action string */
		if (!PyUnicode_Check(action_obj)) {
			Py_DECREF(item);
			PyErr_SetString(PyExc_TypeError, "action must be a string");
			goto cleanup;
		}
		action_str = PyUnicode_AsUTF8(action_obj);
		if (action_str == NULL) {
			Py_DECREF(item);
			goto cleanup;
		}

		/* Extract key bytes */
		if (PyBytes_AsStringAndSize(key_obj, (char **)&key_data, &key_len) < 0) {
			Py_DECREF(item);
			goto cleanup;
		}

		/* Extract value bytes (may be None) */
		if (value_obj != Py_None) {
			if (PyBytes_AsStringAndSize(value_obj, (char **)&val_data, &val_len) < 0) {
				Py_DECREF(item);
				goto cleanup;
			}
		} else {
			val_data = NULL;
			val_len = 0;
		}

		op = &state->ops[state->num_ops];

		/* Parse action */
		if (strcmp(action_str, "GET") == 0) {
			op->action = BATCH_ACTION_GET;
		} else if (strcmp(action_str, "SET") == 0) {
			op->action = BATCH_ACTION_SET;
		} else if (strcmp(action_str, "DEL") == 0) {
			op->action = BATCH_ACTION_DEL;
		} else {
			Py_DECREF(item);
			PyErr_Format(PyExc_ValueError,
				     "Invalid action '%s', must be GET, SET, or DEL",
				     action_str);
			goto cleanup;
		}

		/* Copy key */
		op->key.dptr = PyMem_RawMalloc(key_len);
		if (op->key.dptr == NULL) {
			Py_DECREF(item);
			PyErr_NoMemory();
			goto cleanup;
		}
		memcpy(op->key.dptr, key_data, key_len);
		op->key.dsize = key_len;

		/* Copy value for SET operations */
		if (op->action == BATCH_ACTION_SET) {
			if (val_data == NULL || val_len == 0) {
				Py_DECREF(item);
				PyErr_SetString(PyExc_ValueError,
						"SET operation requires non-empty value");
				PyMem_RawFree(op->key.dptr);
				op->key.dptr = NULL;
				goto cleanup;
			}
			op->value.dptr = PyMem_RawMalloc(val_len);
			if (op->value.dptr == NULL) {
				PyMem_RawFree(op->key.dptr);
				op->key.dptr = NULL;
				Py_DECREF(item);
				PyErr_NoMemory();
				goto cleanup;
			}
			memcpy(op->value.dptr, val_data, val_len);
			op->value.dsize = val_len;
		} else {
			op->value.dptr = NULL;
			op->value.dsize = 0;
		}

		state->num_ops++;
		Py_DECREF(item);
	}

	if (PyErr_Occurred()) {
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (iterator != NULL) {
		Py_DECREF(iterator);
	}

	if (ret != 0) {
		free_batch_state(state);
	}

	return ret;
}

int execute_batch_operations(py_ctdb_db_ctx *pydb,
			      struct batch_state *state)
{
	struct ctdb_transaction_handle *h = NULL;
	TALLOC_CTX *tmp_ctx;
	int err = 0;
	size_t i;

	tmp_ctx = talloc_new(pydb->client->mem_ctx);
	if (tmp_ctx == NULL) {
		pyctdb_set_error(&state->error, ENOMEM,
				 "Failed to allocate memory context");
		return ENOMEM;
	}

	err = ctdb_transaction_start(tmp_ctx, pydb->client->ev,
				     pydb->client->client,
				     TIMEOUT(pydb->client),
				     pydb->db, false, &h);
	if (err != 0) {
		pyctdb_set_error(&state->error, err, "Failed to start transaction");
		goto done;
	}

	for (i = 0; i < state->num_ops; i++) {
		struct batch_operation *op = &state->ops[i];

		switch (op->action) {
		case BATCH_ACTION_GET:
		{
			TDB_DATA result = {0};
			err = ctdb_transaction_fetch_record(h, op->key,
							    tmp_ctx, &result);
			if (err != 0) {
				pyctdb_set_error(&state->error, err,
						 "Failed to fetch record in batch operation %zu", i);
				goto cancel;
			}

			if (result.dptr == NULL) {
				pyctdb_set_error(&state->error, ENOENT,
						 "Record not found in batch operation %zu", i);
				err = ENOENT;
				goto cancel;
			}

			/* Allocate result using PyMem for Python */
			if (result.dsize > 0) {
				TDB_DATA *result_copy = PyMem_RawMalloc(sizeof(TDB_DATA));
				if (result_copy == NULL) {
					err = ENOMEM;
					pyctdb_set_error(&state->error, ENOMEM,
							 "Failed to allocate memory for result");
					goto cancel;
				}

				result_copy->dptr = PyMem_RawMalloc(result.dsize);
				if (result_copy->dptr == NULL) {
					PyMem_RawFree(result_copy);
					err = ENOMEM;
					pyctdb_set_error(&state->error, ENOMEM,
							 "Failed to allocate memory for result data");
					goto cancel;
				}

				memcpy(result_copy->dptr, result.dptr, result.dsize);
				result_copy->dsize = result.dsize;
				state->results[i] = (PyObject *)result_copy;
			}
			break;
		}
		case BATCH_ACTION_SET:
			err = ctdb_transaction_store_record(h, op->key, op->value);
			if (err != 0) {
				pyctdb_set_error(&state->error, err,
						 "Failed to store record in batch operation %zu", i);
				goto cancel;
			}
			break;

		case BATCH_ACTION_DEL:
			err = ctdb_transaction_delete_record(h, op->key);
			if (err != 0) {
				pyctdb_set_error(&state->error, err,
						 "Failed to delete record in batch operation %zu", i);
				goto cancel;
			}
			break;

		default:
			pyctdb_set_error(&state->error, EINVAL,
					 "Unknown batch action %d in operation %zu",
					 op->action, i);
			err = EINVAL;
			goto cancel;
		}
	}

	err = ctdb_transaction_commit(h);
	if (err != 0) {
		pyctdb_set_error(&state->error, err, "Failed to commit transaction");
		goto cancel;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;

cancel:
	ctdb_transaction_cancel(h);
done:
	TALLOC_FREE(tmp_ctx);
	return err;
}

PyObject *build_batch_result_dict(struct batch_state *state)
{
	PyObject *result_dict;
	size_t i;

	result_dict = PyDict_New();
	if (result_dict == NULL) {
		return NULL;
	}

	for (i = 0; i < state->num_ops; i++) {
		if (state->ops[i].action == BATCH_ACTION_GET && state->results[i] != NULL) {
			TDB_DATA *result_data = (TDB_DATA *)state->results[i];
			PyObject *py_value;
			PyObject *py_index;

			py_value = PyBytes_FromStringAndSize(
				(const char *)result_data->dptr,
				result_data->dsize
			);
			PyMem_RawFree(result_data->dptr);
			PyMem_RawFree(result_data);
			state->results[i] = NULL;

			if (py_value == NULL) {
				Py_DECREF(result_dict);
				return NULL;
			}

			py_index = PyLong_FromSize_t(i);
			if (py_index == NULL) {
				Py_DECREF(py_value);
				Py_DECREF(result_dict);
				return NULL;
			}

			if (PyDict_SetItem(result_dict, py_index, py_value) < 0) {
				Py_DECREF(py_index);
				Py_DECREF(py_value);
				Py_DECREF(result_dict);
				return NULL;
			}

			Py_DECREF(py_index);
			Py_DECREF(py_value);
		}
	}

	return result_dict;
}
