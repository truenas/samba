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
#include "pyclient_tables.h"
#include "lib/util/dlinklist.h"

static int py_ctdb_db_init(py_ctdb_db_ctx *self,
			   PyObject *args,
			   PyObject *kwargs)
{
	return 0;
}

static
void py_ctdb_db_dealloc(py_ctdb_db_ctx *self)
{
	if (self->client == NULL) {
		Py_TYPE(self)->tp_free((PyObject *)self);
		return;
	}

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(self->client);

	/*
	 * Do not free self->db - it is owned by the client context
	 * and will be freed when the client is freed. The db context
	 * may also be shared by multiple Python DB objects (attach
	 * reuses existing db handles), so freeing it here would cause
	 * use-after-free bugs.
	 */
	self->db = NULL;

	PYCTDB_UNLOCK(self->client);
	Py_END_ALLOW_THREADS
	Py_CLEAR(self->client);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static
int get_generation(py_ctdb_client_ctx *pyclient, uint32_t *generation)
{
	uint32_t leader = _Py_atomic_load_uint32(&cluster_leader);
	int recmode;
	struct ctdb_vnn_map *vnnmap;
	TALLOC_CTX *tmp_ctx = NULL;
	int err;
	const char *errmsg;

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(pyclient);
	tmp_ctx = talloc_new(pyclient->mem_ctx);
	if (tmp_ctx == NULL) {
		err = ENOMEM;
		errmsg = "Failed to allocate new memory context";
	} else {
		err = ctdb_ctrl_get_recmode(tmp_ctx,
					    pyclient->ev,
					    pyclient->client,
					    leader,
					    TIMEOUT(pyclient),
					    &recmode);
		if (err) {
			errmsg = "Failed to get recovery mode";
		}
	}

	if (!err && (recmode == CTDB_RECOVERY_ACTIVE)) {
		err = EBUSY;
		errmsg = "Ctdb cluster is currently in recovery mode";
	} else if (!err) {
		err = ctdb_ctrl_getvnnmap(tmp_ctx,
					  pyclient->ev,
					  pyclient->client,
					  leader,
					  TIMEOUT(pyclient),
					  &vnnmap);
		if (err) {
			errmsg = "Failed to get generation from node";
		} else {
			*generation = vnnmap->generation;
		}
	}
	TALLOC_FREE(tmp_ctx);
	PYCTDB_UNLOCK(pyclient);
	Py_END_ALLOW_THREADS

	if (err) {
		// Set python exception
		pyctdb_err(err, errmsg);
	}

	return err;
}

static
int py_ctdb_wipedb(py_ctdb_db_ctx *dbctx)
{
	uint32_t leader = _Py_atomic_load_uint32(&cluster_leader);
	int count, err;
	bool frozen = false;
	uint32_t *pnn_list;
	uint32_t generation;
	struct ctdb_req_control request;
	struct ctdb_transdb wipedb;
	const char *errmsg = NULL;
	TALLOC_CTX *tmp_ctx = NULL;

	PYCTDB_ASSERT((dbctx != NULL), "uninitialized db context");

	if (leader != dbctx->client->pnn) {
		PyErr_SetString(PyExc_ValueError,
				"DB wipe operations must be initiated by "
				"the cluster leader.");
		return EINVAL;
	}

	if (dbctx->client->nodemap_cached.node == NULL) {
		/*
		 * This function requires an initialized nodemap
		 * we'll use the python function because it's readily
		 * available and having a cached nodemap is OK.
		 */
		PyObject *tmp = py_ctdb_get_nodemap(dbctx->client, true);
		if (tmp == NULL) {
			return EINVAL;
		}

		Py_DECREF(tmp);
	}

	err = get_generation(dbctx->client, &generation);
	if (err)
		return err;

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(dbctx->client);
	tmp_ctx = talloc_new(dbctx->client->mem_ctx);
	if (tmp_ctx == NULL) {
		err = ENOMEM;
		errmsg = "Failed to allocate new memory context";
	} else {
		count = list_of_active_nodes(&dbctx->client->nodemap_cached,
					     CTDB_UNKNOWN_PNN,
					     tmp_ctx,
					     &pnn_list);
		if (count < 0) {
			err = ENOMEM;
			errmsg = "Failed to list active nodes";
		}
	}

	if (!err) {
		ctdb_req_control_db_freeze(&request, dbctx->db_id);
		err = ctdb_client_control_multi(tmp_ctx, dbctx->client->ev,
						dbctx->client->client,
						pnn_list, count,
						TIMEOUT(dbctx->client),
						&request, NULL, NULL);
		if (err) {
			errmsg = "Failed to issue freeze";
		} else {
			frozen = true;
		}
	}

	if (frozen) {
		wipedb.db_id = dbctx->db_id;
		wipedb.tid = generation;
		ctdb_req_control_db_transaction_start(&request, &wipedb);
		err = ctdb_client_control_multi(tmp_ctx, dbctx->client->ev,
						dbctx->client->client,
						pnn_list, count,
						TIMEOUT(dbctx->client),
						&request, NULL, NULL);
		if (err) {
			errmsg = "Failed to wipe database";
		} else {
			ctdb_req_control_db_set_healthy(&request, dbctx->db_id);
			err = ctdb_client_control_multi(tmp_ctx, dbctx->client->ev,
							 dbctx->client->client,
							 pnn_list, count,
							 TIMEOUT(dbctx->client),
							 &request, NULL, NULL);
			if (err) {
				errmsg = "Failed to set healthy";
			}
		}

		/* commit the transaction */
		if (!err) {
			ctdb_req_control_db_transaction_commit(&request, &wipedb);
			err = ctdb_client_control_multi(tmp_ctx, dbctx->client->ev,
							 dbctx->client->client,
							 pnn_list, count,
							 TIMEOUT(dbctx->client),
							 &request, NULL, NULL);
			if (err) {
				errmsg = "Failed to commit transaction";
			}
		}

		/* unfreeze */
		if (!err) {
			ctdb_req_control_db_thaw(&request, dbctx->db_id);
			err = ctdb_client_control_multi(tmp_ctx, dbctx->client->ev,
							 dbctx->client->client,
							 pnn_list, count,
							 TIMEOUT(dbctx->client),
							 &request, NULL, NULL);
			if (err) {
				errmsg = "Failed to unfreeze DB";
			}
		}

	}

	if (err) {
		ctdb_ctrl_set_recmode(tmp_ctx, dbctx->client->ev,
				      dbctx->client->client,
				      dbctx->client->pnn,
				      TIMEOUT(dbctx->client),
				      CTDB_RECOVERY_ACTIVE);
	}

	TALLOC_FREE(tmp_ctx);
	PYCTDB_UNLOCK(dbctx->client);
	Py_END_ALLOW_THREADS

	if (err)
		pyctdb_err(err, errmsg);

	return err;
}

typedef struct ctdb_rec_del_entry {
	TDB_DATA key;
	struct ctdb_rec_del_entry *next, *prev;
} del_entry_t;

struct ctdb_tdb_sync_state {
	del_entry_t *del_list;
	TDB_CONTEXT *tctx;
	TALLOC_CTX *mem_ctx;
};

static
int gen_del_list(TDB_DATA key, TDB_DATA data, struct ctdb_tdb_sync_state *state)
{
	TDB_DATA val;
	del_entry_t *d = NULL;

	/*
	 * Never delete the __db_sequence_number__ entry during sync.
	 * This entry is managed by CTDB for persistent databases.
	 */
	if (key.dsize == (strlen(CTDB_DB_SEQNUM_KEY) + 1) &&
	    memcmp(key.dptr, CTDB_DB_SEQNUM_KEY, key.dsize) == 0) {
		return 0;
	}

	val = tdb_fetch(state->tctx, key);
	if ((val.dptr == NULL) || (val.dsize != data.dsize)) {
		goto copy_out;
	} else if (memcmp(val.dptr, data.dptr, data.dsize) != 0) {
		goto copy_out;
	}

	free(val.dptr);
	return 0;
copy_out:
	// copy the key into our destroy list
	d = talloc_zero(state->mem_ctx, del_entry_t);
	if (d == NULL) {
		free(val.dptr);
		return ENOMEM;
	}

	d->key.dptr = talloc_memdup(state->mem_ctx,
				    key.dptr,
				    key.dsize);
	if (d->key.dptr == NULL) {
		free(val.dptr);
		return ENOMEM;
	}

	d->key.dsize = key.dsize;
	DLIST_ADD(state->del_list, d);
	free(val.dptr);
	return 0;
}

static
int traverse_gen_del_list_cb(uint32_t reqid, struct ctdb_ltdb_header *header,
			     TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct ctdb_tdb_sync_state *state = NULL;
	state = (struct ctdb_tdb_sync_state *)private_data;

	return gen_del_list(key, data, state);
}

static
int traverse_ctdb_local_for_del_list(struct ctdb_db_context *db,
				     TALLOC_CTX *mem_ctx,
				     TDB_CONTEXT *tctx,
				     del_entry_t *del_list)
{
	int err;
	struct ctdb_tdb_sync_state state = (struct ctdb_tdb_sync_state) {
		.del_list = del_list,
		.tctx = tctx,
		.mem_ctx = mem_ctx
	};

	return ctdb_db_traverse_local(db, true, false,
				      traverse_gen_del_list_cb, &state);
}

struct store_tdb_in_ctdb_state {
	bool error_occurred;
	pyctdb_error_t *error;
	struct ctdb_transaction_handle *h;
};

static
int store_tdb_record(TDB_CONTEXT *tctx, TDB_DATA key, TDB_DATA val,
		     void *private_data)
{
	struct store_tdb_in_ctdb_state *state;
	state = (struct store_tdb_in_ctdb_state *)private_data;
	int err;

	err = ctdb_transaction_store_record(state->h, key, val);
	if (err) {
		state->error_occurred = true;
		pyctdb_set_error(state->error, err, "Failed to store tdb record.");
	}

	return err;
}

static
int store_tdb_in_ctdb(struct ctdb_transaction_handle *h, TDB_CONTEXT *tctx, pyctdb_error_t *error)
{
	struct store_tdb_in_ctdb_state state = {.error = error, .h = h};
	int rv;

	rv = tdb_traverse(tctx, store_tdb_record, &state);
	if (rv < 0) {
		/* tdb error occurred */
		pyctdb_set_error(error, errno, "TDB traversal failed");
		return -1;
	} else if (state.error_occurred) {
		return -1;
	}

	return 0;
}

static
int sync_ctdb_and_tdb(py_ctdb_db_ctx *pydb, TDB_CONTEXT *tctx,
		      pyctdb_error_t *error)
{
	int err;
	TALLOC_CTX *tmp_ctx = NULL;
	del_entry_t del_list = {0};
	del_entry_t *de, *next;
	struct ctdb_transaction_handle *h;

	tmp_ctx = talloc_new(pydb->client->mem_ctx);
	if (tmp_ctx == NULL) {
		pyctdb_set_error(error, ENOMEM, "Failed to create talloc context");
		return ENOMEM;
	}

	err = traverse_ctdb_local_for_del_list(pydb->db, tmp_ctx, tctx, &del_list);
	if (err) {
		pyctdb_set_error(error, err, "Failed to traverse and create delete list");
		TALLOC_FREE(tmp_ctx);
		return err;
	}

	/* perform changes under transaction lock */
	err = ctdb_transaction_start(tmp_ctx, pydb->client->ev,
				     pydb->client->client, TIMEOUT(pydb->client),
				     pydb->db, false, &h);
	if (err) {
		pyctdb_set_error(error, err, "Failed to start transaction.");
		TALLOC_FREE(tmp_ctx);
		return err;
	}

	/* first delete any records in the ctdb db that don't need to be there */
	for (de = &del_list; de; de = next) {
		next = de->next;
		if (de->key.dptr == NULL)
			continue;

		err = ctdb_transaction_delete_record(h, de->key);
		if (err) {
			pyctdb_set_error(error, err, "Failed to delete record");
			goto cancel_transaction;
		}
	}

	/* now write all entries from the tdb file into transaction */
	err = store_tdb_in_ctdb(h, tctx, error);
	if (err) {
		/* We already filled error buffer in store_tdb_in_ctdb() */
		goto cancel_transaction;
	}

	/* now commit our transaction to ctdb db */
	err = ctdb_transaction_commit(h);
	if (err) {
		pyctdb_set_error(error, err, "Failed to commit transaction");
		goto cancel_transaction;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;

cancel_transaction:
	ctdb_transaction_cancel(h);
	TALLOC_FREE(tmp_ctx);
	return err;
}

static
int py_ctdb_db_synchronize(py_ctdb_db_ctx *pydb, const char *tdb_path, int tdb_flags,
			   int open_flags, mode_t mode)
{
	int err;
	pyctdb_error_t pyerr;
	TDB_CONTEXT *tctx;
	uint32_t leader = _Py_atomic_load_uint32(&cluster_leader);

	PYCTDB_ASSERT((pydb->client != NULL), "uninitialized db context");

	if (pydb->client->pnn != leader) {
		PyErr_SetString(PyExc_ValueError,
				"This operation may only be performed on the "
				"cluster leader.");
		return EINVAL;
	}

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(pydb->client);
	tctx = tdb_open(tdb_path, 0, tdb_flags, open_flags, mode);
	if (tctx == NULL) {
		err = errno;
		pyctdb_set_error(&pyerr, err, "%s: failed to open tdb file", tdb_path);
	} else {
		err = sync_ctdb_and_tdb(pydb, tctx, &pyerr);
		tdb_close(tctx);
	}
	PYCTDB_UNLOCK(pydb->client);
	Py_END_ALLOW_THREADS

	if (err) {
		pyctdb_err(err, pyerr.message);
	}

	return err;
}

int py_ctdb_fetchrecord(py_ctdb_db_ctx *pydb, TDB_DATA key,
			TDB_DATA *data, pyctdb_error_t *pyerr)
{
	struct ctdb_transaction_handle *h = NULL;
	TALLOC_CTX *tmp_ctx;
	TDB_DATA result = { .dptr = NULL, .dsize = 0 };
	int err = 0;

	PYCTDB_ASSERT((pydb->client != NULL), "uninitialized db context");

	tmp_ctx = talloc_new(pydb->client->mem_ctx);
	if (tmp_ctx == NULL) {
		pyctdb_set_error(pyerr, ENOMEM,
				 "Failed to allocate memory context");
		return ENOMEM;
	}

	err = ctdb_transaction_start(tmp_ctx, pydb->client->ev,
				     pydb->client->client,
				     TIMEOUT(pydb->client),
				     pydb->db, true, &h);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to start transaction");
		goto done;
	}

	err = ctdb_transaction_fetch_record(h, key, tmp_ctx, &result);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to fetch record");
		ctdb_transaction_cancel(h);
		goto done;
	}

	/* Check if record exists - NULL dptr indicates non-existent key */
	if (result.dptr == NULL) {
		pyctdb_set_error(pyerr, ENOENT, "Record not found");
		err = ENOENT;
		ctdb_transaction_cancel(h);
		goto done;
	}

	/* Copy data to PyMem allocated memory so it survives tmp_ctx free */
	if (result.dsize > 0) {
		data->dptr = PyMem_RawCalloc(1, result.dsize);
		if (data->dptr == NULL) {
			pyctdb_set_error(pyerr, ENOMEM,
					 "Failed to allocate memory for data");
			err = ENOMEM;
			ctdb_transaction_cancel(h);
			goto done;
		}
		memcpy(data->dptr, result.dptr, result.dsize);
		data->dsize = result.dsize;
	}

	ctdb_transaction_cancel(h);

done:
	TALLOC_FREE(tmp_ctx);
	return err;
}

PyDoc_STRVAR(py_ctdb_db_fetch__doc__,
"fetch(key) -> bytes\n"
"--------------------\n"
"Fetch a record from the CTDB database.\n"
"\n"
"Args:\n"
"    key: Record key as bytes\n"
"\n"
"Returns:\n"
"    bytes: The record value\n"
"\n"
"Raises:\n"
"    FileNotFoundError: If the record does not exist\n"
"    CtdbError: If the operation fails\n"
);
static PyObject *py_ctdb_db_fetch(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_db_ctx *dbctx = (py_ctdb_db_ctx *)self;
	TDB_DATA key, data = { .dptr = NULL, .dsize = 0 };
	PyObject *result = NULL;
	int err;
	pyctdb_error_t pyerr;
	static char *kwlist[] = {"key", NULL};

	PYCTDB_ASSERT((dbctx->client != NULL), "uninitialized db context");

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#", kwlist,
					 &key.dptr, &key.dsize)) {
		return NULL;
	}

	if (!(dbctx->db_flags &
	      (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		PyErr_Format(PyExc_ValueError,
			     "Database '%s' is not persistent or replicated",
			     dbctx->db_name);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(dbctx->client);
	err = py_ctdb_fetchrecord(dbctx, key, &data, &pyerr);
	PYCTDB_UNLOCK(dbctx->client);
	Py_END_ALLOW_THREADS

	if (err == 0) {
		result = PyBytes_FromStringAndSize((const char *)data.dptr,
						   data.dsize);
		PyMem_RawFree(data.dptr);
	} else if (err == ENOENT) {
		PyErr_SetString(PyExc_FileNotFoundError,
				"Record not found");
	} else {
		pyctdb_err(err, pyerr.message);
	}

	return result;
}

static int py_ctdb_storerecord(py_ctdb_db_ctx *pydb, TDB_DATA key,
			       TDB_DATA value, pyctdb_error_t *pyerr)
{
	struct ctdb_transaction_handle *h = NULL;
	TALLOC_CTX *tmp_ctx;
	int err = 0;

	PYCTDB_ASSERT((pydb->client != NULL), "uninitialized db context");

	tmp_ctx = talloc_new(pydb->client->mem_ctx);
	if (tmp_ctx == NULL) {
		pyctdb_set_error(pyerr, ENOMEM,
				 "Failed to allocate memory context");
		return ENOMEM;
	}

	err = ctdb_transaction_start(tmp_ctx, pydb->client->ev,
				     pydb->client->client,
				     TIMEOUT(pydb->client),
				     pydb->db, false, &h);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to start transaction");
		goto done;
	}

	err = ctdb_transaction_store_record(h, key, value);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to store record");
		ctdb_transaction_cancel(h);
		goto done;
	}

	err = ctdb_transaction_commit(h);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to commit transaction");
		ctdb_transaction_cancel(h);
		goto done;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return err;
}

PyDoc_STRVAR(py_ctdb_db_store__doc__,
"store(key, value) -> None\n"
"-------------------------\n"
"Store a record in the CTDB database.\n"
"\n"
"Args:\n"
"    key: Record key as bytes\n"
"    value: Record value as bytes\n"
"\n"
"Returns:\n"
"    None\n"
"\n"
"Raises:\n"
"    CtdbError: If the operation fails\n"
);
static PyObject *py_ctdb_db_store(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_db_ctx *dbctx = (py_ctdb_db_ctx *)self;
	TDB_DATA key, value;
	int err;
	pyctdb_error_t pyerr;
	static char *kwlist[] = {"key", "value", NULL};

	PYCTDB_ASSERT((dbctx->client != NULL), "uninitialized db context");

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#", kwlist,
					 &key.dptr, &key.dsize,
					 &value.dptr, &value.dsize)) {
		return NULL;
	}

	if (!(dbctx->db_flags &
	      (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		PyErr_Format(PyExc_ValueError,
			     "Database '%s' is not persistent or replicated",
			     dbctx->db_name);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(dbctx->client);
	err = py_ctdb_storerecord(dbctx, key, value, &pyerr);
	PYCTDB_UNLOCK(dbctx->client);
	Py_END_ALLOW_THREADS

	if (err != 0) {
		pyctdb_err(err, pyerr.message);
		return NULL;
	}

	Py_RETURN_NONE;
}

static int py_ctdb_deleterecord(py_ctdb_db_ctx *pydb, TDB_DATA key,
				pyctdb_error_t *pyerr)
{
	struct ctdb_transaction_handle *h = NULL;
	TALLOC_CTX *tmp_ctx;
	int err = 0;

	PYCTDB_ASSERT((pydb->client != NULL), "uninitialized db context");

	tmp_ctx = talloc_new(pydb->client->mem_ctx);
	if (tmp_ctx == NULL) {
		pyctdb_set_error(pyerr, ENOMEM,
				 "Failed to allocate memory context");
		return ENOMEM;
	}

	err = ctdb_transaction_start(tmp_ctx, pydb->client->ev,
				     pydb->client->client,
				     TIMEOUT(pydb->client),
				     pydb->db, false, &h);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to start transaction");
		goto done;
	}

	err = ctdb_transaction_delete_record(h, key);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to delete record");
		ctdb_transaction_cancel(h);
		goto done;
	}

	err = ctdb_transaction_commit(h);
	if (err != 0) {
		pyctdb_set_error(pyerr, err, "Failed to commit transaction");
		ctdb_transaction_cancel(h);
		goto done;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return err;
}

PyDoc_STRVAR(py_ctdb_db_delete__doc__,
"delete(key) -> None\n"
"-------------------\n"
"Delete a record from the CTDB database.\n"
"\n"
"Args:\n"
"    key: Record key as bytes\n"
"\n"
"Returns:\n"
"    None\n"
"\n"
"Raises:\n"
"    CtdbError: If the operation fails\n"
);
static PyObject *py_ctdb_db_delete(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_db_ctx *dbctx = (py_ctdb_db_ctx *)self;
	TDB_DATA key;
	int err;
	pyctdb_error_t pyerr;
	static char *kwlist[] = {"key", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#", kwlist,
					 &key.dptr, &key.dsize)) {
		return NULL;
	}

	if (!(dbctx->db_flags &
	      (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		PyErr_Format(PyExc_ValueError,
			     "Database '%s' is not persistent or replicated",
			     dbctx->db_name);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(dbctx->client);
	err = py_ctdb_deleterecord(dbctx, key, &pyerr);
	PYCTDB_UNLOCK(dbctx->client);
	Py_END_ALLOW_THREADS

	if (err != 0) {
		pyctdb_err(err, pyerr.message);
		return NULL;
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(py_ctdb_db_wipe_db__doc__,
"wipe_db() -> None\n"
"------------------\n"
"Wipe the CTDB database, removing all records. This operation must be\n"
"initiated by the cluster leader and will freeze the database, wipe its\n"
"contents across all nodes, and then unfreeze it.\n"
"\n"
"Raises:\n"
"    CtdbError: If the operation fails or if not called on cluster leader.\n"
);
static PyObject *py_ctdb_db_wipe_db(PyObject *self, PyObject *unused)
{
	py_ctdb_db_ctx *dbctx = (py_ctdb_db_ctx *)self;
	int err;

	err = py_ctdb_wipedb(dbctx);
	if (err) {
		return NULL;
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(py_ctdb_db_sync_with_tdb_file__doc__,
"sync_with_tdb_file(tdb_path, tdb_flags=0, open_flags=0, mode=0644) -> None\n"
"--------------------------------------------------------------------------\n"
"Synchronize the CTDB database with a local TDB file. This operation reads\n"
"the specified TDB file and ensures the CTDB database matches its contents.\n"
"Records present in CTDB but not in the TDB file will be deleted. Records\n"
"in the TDB file will be written to CTDB. This operation must be initiated\n"
"by the cluster leader.\n"
"\n"
"Args:\n"
"    tdb_path: Path to the TDB file to synchronize with\n"
"    tdb_flags: TDB flags for opening the file (default: 0)\n"
"    open_flags: File open flags (default: 0)\n"
"    mode: File mode permissions (default: 0644)\n"
"\n"
"Raises:\n"
"    CtdbError: If the operation fails, file cannot be opened, or if not\n"
"               called on cluster leader.\n"
);
static PyObject *py_ctdb_db_sync_with_tdb_file(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_db_ctx *dbctx = (py_ctdb_db_ctx *)self;
	const char *tdb_path = NULL;
	int tdb_flags = 0;
	int open_flags = 0;
	int mode = 0644;
	int err;
	static char *kwlist[] = {"tdb_path", "tdb_flags", "open_flags", "mode", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|iii", kwlist,
					 &tdb_path, &tdb_flags, &open_flags, &mode)) {
		return NULL;
	}

	err = py_ctdb_db_synchronize(dbctx, tdb_path, tdb_flags, open_flags, mode);
	if (err) {
		return NULL;
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(py_ctdb_db_iter__doc__,
"iter() -> CtdbDBIterator\n"
"------------------------\n"
"Create an iterator for this database.\n"
"\n"
"Returns:\n"
"    An iterator that yields (key, value) tuples for all records\n"
"\n"
"Raises:\n"
"    ValueError: If the database is not persistent or replicated\n"
"    CtdbError: If the iteration setup fails\n"
);
static PyObject *py_ctdb_db_iter(PyObject *self, PyObject *unused)
{
	py_ctdb_db_ctx *dbctx = (py_ctdb_db_ctx *)self;

	if (!(dbctx->db_flags &
	      (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		PyErr_Format(PyExc_ValueError,
			     "Database '%s' is not persistent or replicated",
			     dbctx->db_name);
		return NULL;
	}

	return py_ctdb_db_iter_new(dbctx);
}

PyDoc_STRVAR(py_ctdb_db_batch_op__doc__,
"batch_op(operations) -> dict\n"
"----------------------------\n"
"Perform a batch of operations under a single transaction.\n"
"\n"
"Args:\n"
"    operations: Iterable of BatchOp instances where each BatchOp contains:\n"
"        action: str - 'GET', 'SET', or 'DEL'\n"
"        key: bytes - The record key\n"
"        value: bytes - The record value (required for SET, None for GET/DEL)\n"
"\n"
"Returns:\n"
"    dict: Dictionary mapping operation index to value for all GET operations\n"
"\n"
"Raises:\n"
"    TypeError: If operations are not BatchOp instances\n"
"    ValueError: If the database is not persistent/replicated or invalid operation\n"
"    CtdbError: If any operation fails (transaction is rolled back)\n"
"\n"
"Example:\n"
"    from pyctdb import BatchOp\n"
"    ops = [\n"
"        BatchOp('SET', b'key1', b'value1'),\n"
"        BatchOp('GET', b'key2', None),\n"
"        BatchOp('DEL', b'key3', None),\n"
"    ]\n"
"    results = db.batch_op(ops)\n"
);
static PyObject *py_ctdb_db_batch_op(PyObject *self, PyObject *args, PyObject *kwargs)
{
	py_ctdb_db_ctx *dbctx = (py_ctdb_db_ctx *)self;
	PyObject *operations = NULL;
	PyObject *result_dict = NULL;
	struct batch_state state = {0};
	int err;
	static char *kwlist[] = {"operations", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O", kwlist, &operations)) {
		return NULL;
	}

	if (!(dbctx->db_flags &
	      (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		PyErr_Format(PyExc_ValueError,
			     "Database '%s' is not persistent or replicated",
			     dbctx->db_name);
		return NULL;
	}

	/* Parse Python operations into C structures */
	if (parse_batch_operations(operations, &state) != 0) {
		return NULL;
	}

	if (state.num_ops == 0) {
		/* Empty operation list - return empty dict */
		free_batch_state(&state);
		return PyDict_New();
	}

	/* Execute operations with GIL dropped */
	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(dbctx->client);
	err = execute_batch_operations(dbctx, &state);
	PYCTDB_UNLOCK(dbctx->client);
	Py_END_ALLOW_THREADS

	if (err != 0) {
		pyctdb_err(err, state.error.message);
		free_batch_state(&state);
		return NULL;
	}

	/* Build result dictionary from GET operations */
	result_dict = build_batch_result_dict(&state);

	/* Free allocated memory */
	free_batch_state(&state);

	return result_dict;
}

PyDoc_STRVAR(py_ctdb_db_name__doc__,
"db_name -> str\n"
"--------------\n"
"The name of this CTDB database.\n"
);

static PyObject *py_ctdb_db_get_name(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	return Py_BuildValue("s", ctx->db_name);
}

PyDoc_STRVAR(py_ctdb_db_id__doc__,
"db_id -> int\n"
"------------\n"
"The database ID of this CTDB database.\n"
);

static PyObject *py_ctdb_db_get_id(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	return Py_BuildValue("I", ctx->db_id);
}

PyDoc_STRVAR(py_ctdb_db_flags__doc__,
"db_flags -> tuple[str, ...]\n"
"---------------------------\n"
"A tuple of flag names associated with this CTDB database.\n"
);

static PyObject *py_ctdb_db_get_flags(PyObject *self, void *closure)
{
	py_ctdb_db_ctx *ctx = (py_ctdb_db_ctx *)self;
	PyObject *result = NULL;
	PyObject *flag_list = NULL;
	size_t i;

	flag_list = PyList_New(0);
	if (flag_list == NULL) {
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(db_flags_tbl); i++) {
		if (ctx->db_flags & db_flags_tbl[i].val) {
			PyObject *flag_str = PyUnicode_FromString(db_flags_tbl[i].name);
			if (flag_str == NULL) {
				Py_DECREF(flag_list);
				return NULL;
			}
			if (PyList_Append(flag_list, flag_str) < 0) {
				Py_DECREF(flag_str);
				Py_DECREF(flag_list);
				return NULL;
			}
			Py_DECREF(flag_str);
		}
	}

	result = PyList_AsTuple(flag_list);
	Py_DECREF(flag_list);
	return result;
}

static PyGetSetDef ctdb_db_getsetters[] = {
	{
		.name = discard_const_p(char, "db_name"),
		.get = (getter)py_ctdb_db_get_name,
		.doc = py_ctdb_db_name__doc__,
	},
	{
		.name = discard_const_p(char, "db_id"),
		.get = (getter)py_ctdb_db_get_id,
		.doc = py_ctdb_db_id__doc__,
	},
	{
		.name = discard_const_p(char, "db_flags"),
		.get = (getter)py_ctdb_db_get_flags,
		.doc = py_ctdb_db_flags__doc__,
	},
	{ .name = NULL }
};

static PyMethodDef ctdb_db_methods[] = {
	{
		.ml_name = "fetch",
		.ml_meth = (PyCFunction)py_ctdb_db_fetch,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_db_fetch__doc__,
	},
	{
		.ml_name = "store",
		.ml_meth = (PyCFunction)py_ctdb_db_store,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_db_store__doc__,
	},
	{
		.ml_name = "delete",
		.ml_meth = (PyCFunction)py_ctdb_db_delete,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_db_delete__doc__,
	},
	{
		.ml_name = "wipe_db",
		.ml_meth = (PyCFunction)py_ctdb_db_wipe_db,
		.ml_flags = METH_NOARGS,
		.ml_doc = py_ctdb_db_wipe_db__doc__,
	},
	{
		.ml_name = "sync_with_tdb_file",
		.ml_meth = (PyCFunction)py_ctdb_db_sync_with_tdb_file,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_db_sync_with_tdb_file__doc__,
	},
	{
		.ml_name = "iter",
		.ml_meth = (PyCFunction)py_ctdb_db_iter,
		.ml_flags = METH_NOARGS,
		.ml_doc = py_ctdb_db_iter__doc__,
	},
	{
		.ml_name = "batch_op",
		.ml_meth = (PyCFunction)py_ctdb_db_batch_op,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_ctdb_db_batch_op__doc__,
	},
	{ NULL, NULL, 0, NULL }
};

PyTypeObject PyCtdbDB = {
	.tp_name = PYMODULE_NAME ".CtdbDB",
	.tp_basicsize = sizeof(py_ctdb_db_ctx),
	.tp_methods = ctdb_db_methods,
	.tp_getset = ctdb_db_getsetters,
	.tp_doc = "A CTDB database",
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_ctdb_db_init,
	.tp_dealloc = (destructor)py_ctdb_db_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

PyObject *py_get_or_create_db(py_ctdb_client_ctx *client,
			      const char *db_name,
			      uint8_t db_flags_in,
			      bool create_ok)
{
	struct ctdb_dbid_map *dbmap;
	uint32_t db_id;
	uint8_t db_flags = db_flags_in;
	int err;
	const char *errmsg;
	TALLOC_CTX *tmp_ctx = NULL;
	py_ctdb_db_ctx *pydb = NULL;

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(client);
	tmp_ctx = talloc_new(client->mem_ctx);
	if (tmp_ctx == NULL) {
		err = ENOMEM;
		errmsg = "Memory allocation failure";
	} else {
		err = ctdb_ctrl_get_dbmap(tmp_ctx, client->ev, client->client,
					  client->pnn, TIMEOUT(client), &dbmap);
		if (err) {
			errmsg = "Failed to get ctdb dbmap";
		}
	}

	if (!err) {
		/* check that this DB actually exists */
		int i;
		bool found = false;
		const char *name;
		for (i = 0; i < dbmap->num; i++) {
			err = ctdb_ctrl_get_dbname(tmp_ctx,
						   client->ev,
						   client->client,
						   client->pnn,
						   TIMEOUT(client),
						   dbmap->dbs[i].db_id,
						   &name);
			if (err) {
				errmsg = "Failed to get dbname";
				break;
			}

			if (strcmp(db_name, name) == 0) {
				/*
				 * If database already exists, use those flags
				 * rather than user-supplied ones
				 */
				db_flags = dbmap->dbs[i].flags;
				found = true;
				break;
			}
		}

		if (!found && !create_ok) {
			err = ENOENT;
			errmsg = "Database not found and create_ok not set";
		}
	}

	TALLOC_FREE(tmp_ctx);
	PYCTDB_UNLOCK(client);
	Py_END_ALLOW_THREADS

	if (err) {
		pyctdb_err(err, errmsg);
		return NULL;
	}

	pydb =  (py_ctdb_db_ctx *)PyObject_CallFunction((PyObject *)&PyCtdbDB, NULL);
	if (pydb == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	PYCTDB_LOCK(client);
	err = ctdb_attach(client->ev, client->client, TIMEOUT(client),
			  db_name, db_flags, &pydb->db);
	PYCTDB_UNLOCK(client);
	Py_END_ALLOW_THREADS

	if (err) {
		Py_DECREF(pydb);
		pyctdb_err(err, errmsg);
		return NULL;
	}

	pydb->client = (py_ctdb_client_ctx *)Py_NewRef(client);
	strlcpy(pydb->db_name, db_name, sizeof(pydb->db_name));
	pydb->db_id = pydb->db->db_id;
	pydb->db_flags = pydb->db->db_flags;
	return (PyObject *)pydb;
}
