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
#include "system/wait.h"
#include "system/dir.h"

#include <ctype.h>
#include <popt.h>
#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "version.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/smb_strtox.h"

#include <Python.h>
#include "python/py3compat.h"
#include "python/modules.h"
#include "common/db_hash.h"
#include "common/logging.h"
#include "common/path.h"
#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "protocol/protocol_basic.h"
#include "protocol/protocol_util.h"
#include "common/system_socket.h"
#include "client/client.h"
#include "client/client_sync.h"
#include "common/tunable.h"


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
} pyctdb_mod_state_t;

/*
 * WARNING: this should only be consumed in module method to free module.
 * It is present here *merely* to help keep in sync with what needs to be
 * freed from the module state
 */
#define PYCLEAR_MOD_STATE(state) do { \
       PY_CLEAR(state->py_node_status_enum); \
       PY_CLEAR(state->py_db_flags_enum); \
       PY_CLEAR(state->py_ctdb_caps_enum); \
       PY_CLEAR(state->py_ctdb_error); \
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
extern pycdb_mod_state_t *get_module_state(PyObject *module_ref); 

typedef struct {
	PyObject_HEAD;
	TALLOC_CTX *mem_ctx;
	pthread_mutex_t client_lock;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_node_map *nodemap;
	const char *ctdb_socket;
	uint32_t pnn;
	uint32_t target_pnn;
	uint32_t leader_pnn;
	uint64_t srvid;
	int timeout;
} py_ctdb_client_ctx;


/*
 * This macros specifically handle global locking when talloc leak reporting is
 * enabled. This is because the NULL context with leak reporting enabled is
 * actually a talloc chunk and so the talloc API as used here is not thread-safe.
 *
 * leak_reporting_enabled will only ever be changed while GIL is held and so we
 * shouldn't have to worry about toctou here. This is mostly a debugging feature
 * to generate a talloc leak report on script exit.
 */ 
volatile bool leak_reporting_enabled;
volatile bool glock_enabled;

#define PYCTDB_LEAK_LOCK() do { \
	if (glock_enabled) { \
		pthread_mutex_lock(&py_g_lock); \
	} \
} while (0);

#define PYCTDB_LEAK_UNLOCK() do { \
	if (glock_enabled) { \
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

typedef struct {
	PyObject_HEAD;
	py_ctdb_client_ctx *client;
	struct ctdb_db_context *db;
	struct ctdb_transaction_handle *txh;
	bool txh_ro;
	char *db_name;
	uint32_t db_id;
	uint8_t db_flags;
	bool db_exists;
} py_ctdb_db_ctx;

typedef struct {
	PyObject_HEAD;
	PyObject *key;
	PyObject *val;
	struct ctdb_record_handle *hdl;
	py_ctdb_db_ctx *ctx; //back-pointer to our db-context
} py_ctdb_db_entry;

typedef struct {
	PyObject_HEAD;
	py_ctdb_client_ctx *client;
	uint32_t pnn;
	uint32_t flags;
	PyObject *sockaddr;
	PyObject *py_flags;
} py_ctdb_node;

extern PyTypeObject PyCtdbClient;
extern PyTypeObject PyCtdbDB;
extern PyTypeObject PyCtdbDBEntry;
extern PyTypeObject PyCtdbNode;

#endif /* PYCLIENT_H */
