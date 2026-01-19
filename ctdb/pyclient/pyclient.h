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

#ifndef PYCLIENT_H
#define PYCLIENT_H

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/time.h"
#include "system/dir.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/util/samba_util.h"

#include <Python.h>
#include "python/py3compat.h"
#include "common/path.h"
#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "protocol/protocol_util.h"
#include "protocol/protocol_basic.h"
#include "common/system_socket.h"
#include "client/client.h"
#include "client/client_private.h"
#include "client/client_sync.h"


#define PYMODULE_NAME	"pyctdb"

/*
 * Module state definition. This holds references to various enums that we use
 * to construct python getattr responses for ctdb objects as well as module
 * exception types for error handling.
 */
typedef struct {
	/* See pyclient_tables.h */
	PyObject *py_node_status_enum;
	PyObject *py_db_flags_enum;
	PyObject *py_ctdb_caps_enum;
	/* See pyclient_error.c */
	PyObject *py_ctdb_error;
	/* See pyclient_db_batch.c */
	PyTypeObject *py_batch_op_type;
} pyctdb_mod_state_t;

/*
 * WARNING: this should only be consumed in module method to free module.
 * It is present here *merely* to help keep in sync with what needs to be
 * freed from the module state
 */
#define PYCLEAR_MOD_STATE(state) do { \
       Py_CLEAR(state->py_node_status_enum); \
       Py_CLEAR(state->py_db_flags_enum); \
       Py_CLEAR(state->py_ctdb_caps_enum); \
       Py_CLEAR(state->py_ctdb_error); \
       Py_CLEAR(state->py_batch_op_type); \
} while (0);

/*
 * From pyclient_module.c
 * retrieve a pointer to the pyctdb module state structure. This takes an
 * optional argument to provide a reference to the current module object
 * (if available) as an optimization. If NULL then we'll look it up.
 *
 * NOTE: this function cannot fail / return NULL (will abort on failure)
 *
 * WARNING: this returns a borrowed reference to the state. Caller should
 * not free / clear it.
 */
extern pyctdb_mod_state_t *pyctdb_get_state(PyObject *module_ref);

typedef struct {
	PyObject_HEAD;
	TALLOC_CTX *mem_ctx;
	pthread_mutex_t client_lock;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	const char *ctdb_socket;
	uint32_t pnn;
	uint32_t target_pnn;
	uint64_t srvid;
	uint32_t timeout;
	struct ctdb_node_map nodemap_cached;
} py_ctdb_client_ctx;

typedef struct {
	PyObject_HEAD;
	char db_name[MAXNAMLEN];
	py_ctdb_client_ctx *client;
	struct ctdb_db_context *db;
	uint32_t db_id;
	uint8_t db_flags;
} py_ctdb_db_ctx;

/*
 * This macros specifically handle global locking when talloc leak reporting is
 * enabled. This is because the NULL context with leak reporting enabled is
 * actually a talloc chunk and so the talloc API as used here is not thread-safe.
 *
 * leak_reporting_enabled will only ever be changed while GIL is held and so we
 * shouldn't have to worry about toctou here. This is mostly a debugging feature
 * to generate a talloc leak report on script exit.
 */
extern unsigned leak_reporting_enabled;
extern unsigned glock_enabled;
extern uint32_t cluster_leader;
extern pthread_mutex_t py_g_lock;

#define TIMEOUT(client)    timeval_current_ofs(client->timeout, 0)

#define PYCTDB_LEAK_LOCK() do { \
	if (_Py_atomic_load_uint(&glock_enabled)) { \
		pthread_mutex_lock(&py_g_lock); \
	} \
} while (0);

#define PYCTDB_LEAK_UNLOCK() do { \
	if (_Py_atomic_load_uint(&glock_enabled)) { \
		pthread_mutex_unlock(&py_g_lock); \
	} \
} while (0);

/*
 * The following macros are to simplify code that performs ctdb client
 * operations. Locks should be taken when python methods perform operations to
 * help protect python users from having multiple threads performing operations
 * concurrently on talloc-ed memory
 */
#define PYCTDB_LOCK(obj) do { \
	PYCTDB_LEAK_LOCK(); \
	pthread_mutex_lock(&obj->client_lock); \
} while (0);

#define PYCTDB_UNLOCK(obj) do { \
	pthread_mutex_unlock(&obj->client_lock); \
	PYCTDB_LEAK_UNLOCK(); \
} while (0);

/*
 * Print a fatal error message and kill the process. No cleanup is performed.
 * This should only be invoked for conditions that make it dangerous to
 * continue using the module. For example apparent state corruption. This will
 * call abort() and attempt to produce a corefile.
 */
#define PYCTDB_ASSERT_IMPL(test, message, location) do {\
	if (!test) { \
		Py_FatalError(message " [" location "]"); \
	} \
} while (0);

#define PYCTDB_ASSERT(test, message)\
	PYCTDB_ASSERT_IMPL(test, message, __location__)

extern PyTypeObject PyCtdbClient;
extern PyTypeObject PyCtdbDB;
extern PyTypeObject PyCtdbDBIter;

extern PyObject *py_get_or_create_db(py_ctdb_client_ctx *client,
				     const char *db_name,
				     uint8_t db_flags,
				     bool create_ok);

extern PyObject *py_ctdb_get_nodemap(py_ctdb_client_ctx *ctx, bool refresh);

/* python exception */
extern bool setup_ctdb_exception(PyObject *module_ref);
extern void _set_ctdb_exc(int code, const char *additional_info,
			  const char *location);
#define pyctdb_err(code, info) \
	_set_ctdb_exc(code, info, __location__)

/* error structures for when GIL not held */
typedef struct {
	int code;
        char message[1024];
} pyctdb_error_t;

/* Database iterator */
extern PyObject *py_ctdb_db_iter_new(py_ctdb_db_ctx *db_ctx);

/* Internal fetch function used by iterator */
extern int py_ctdb_fetchrecord(py_ctdb_db_ctx *pydb, TDB_DATA key,
			       TDB_DATA *data, pyctdb_error_t *pyerr);

/* Internal error setting function */
extern void _pyctdb_set_error(pyctdb_error_t *error, int error_code,
			      const char *fmt, const char *location, ...);
#define pyctdb_set_error(error, code, fmt, ...) \
	_pyctdb_set_error(error, code, fmt, __location__, ##__VA_ARGS__)

/* Batch operations - see pyclient_db_batch.c */
enum batch_action {
	BATCH_ACTION_GET = 0,
	BATCH_ACTION_SET,
	BATCH_ACTION_DEL,
};

struct batch_operation {
	enum batch_action action;
	TDB_DATA key;
	TDB_DATA value;
};

struct batch_state {
	struct batch_operation *ops;
	size_t num_ops;
	size_t capacity;
	PyObject **results;
	pyctdb_error_t error;
};

extern bool setup_batch_op_type(PyObject *module_ref);
extern int parse_batch_operations(PyObject *operations, struct batch_state *state);
extern int execute_batch_operations(py_ctdb_db_ctx *pydb, struct batch_state *state);
extern PyObject *build_batch_result_dict(struct batch_state *state);
extern void free_batch_state(struct batch_state *state);

#endif /* PYCLIENT_H */
