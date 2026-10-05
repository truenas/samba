# pyctdb - Python CTDB Client Extension

A CPython extension module providing a high-performance interface to CTDB (Cluster Trivial Database) for Python applications.

## Overview

`pyctdb` is a native Python extension written in C that provides direct access to CTDB's client library. It enables Python applications to interact with clustered TDB databases with full support for transactions, batch operations, and cluster management.

### Key Features

- **Native Performance**: Direct C API bindings with minimal overhead
- **Thread-Safe**: Built-in locking mechanisms for concurrent access
- **Transaction Support**: Atomic operations with automatic rollback on failure
- **Batch Operations**: Execute multiple operations under a single transaction
- **Iterator Support**: Memory-efficient iteration over database records
- **Cluster Management**: Access to node status, recovery mode, and cluster state

## Architecture

The extension is organized into several components:

- **pyclient_module.c**: Module initialization and global state management
- **pyclient_client.c**: CTDB client connection and cluster operations
- **pyclient_db.c**: Database handle management and record operations
- **pyclient_db_batch.c**: Batch operation support with struct sequence types
- **pyclient_db_iter.c**: Database iteration implementation
- **pyclient_error.c**: Exception handling and error reporting

### Module State

The module maintains state for:
- Custom exception types (`CTDBError`)
- Struct sequence types (`BatchOp`)
- Enumeration objects for node status, database flags, and capabilities
- Global locking state for talloc leak reporting

## Installation

The module is built as part of the Samba build system:

```bash
cd /path/to/samba
./configure
make
```

The compiled module will be available as `pyctdb.so` in the build output.

## API Reference

### Client Class

The main entry point for CTDB operations.

```python
from pyctdb import Client

# Create a client connection
client = Client()

# Access cluster information
pnn = client.pnn                    # Physical Node Number
leader = client.leader              # Current cluster leader PNN
timeout = client.timeout            # Operation timeout (default: 10s)
client.timeout = 30                 # Set timeout to 30 seconds

# Get cluster status
status = client.status()
# Returns: {
#     'nodemap': [...],
#     'recovery_mode': 'NORMAL' | 'RECOVERY',
#     'state': <runstate>,
#     'leader_pnn': <pnn>
# }

# Get node map
nodemap = client.nodemap(refresh=False)
# Returns list of nodes: [{
#     'pnn': <int>,
#     'address': '<ip>:<port>',
#     'flags': [<flag_strings>],
#     'this_node': <bool>
# }, ...]

# Open a database
db = client.get_db(
    db_name="mydb",
    persistent=True,      # Persistent database (default)
    readonly=False,       # Read-write access (default)
    replicated=False,     # Not replicated (default)
    create_ok=False       # Don't create if doesn't exist (default)
)

# Force a database recovery and wait for it to complete
client.recover(timeout=60)
```

#### Client Properties

- `pnn` (int, read-only): Physical node number of this client
- `leader` (int, read-only): PNN of the current cluster leader, 4294967295 if there is none. This is the node that last announced itself as the leader. Reading it makes a request to the daemon, and a client that is less than 5 seconds old waits for the first announcement if it has not had one yet
- `timeout` (int, read/write): Timeout in seconds for operations (1-300)

#### Client Methods

##### `status() -> dict`
Retrieve comprehensive cluster status including nodemap, recovery mode, run state, and leader. `leader_pnn` is found in the same way as the `leader` property.

##### `nodemap(refresh=False) -> list`
Get the cluster node map. If `refresh=True`, fetches fresh data from the cluster; otherwise returns cached data.

##### `get_db(db_name, persistent=True, readonly=False, replicated=False, create_ok=False) -> CtdbDB`
Open or create a CTDB database with specified flags.

##### `recover(timeout=60) -> None`
Force a database recovery and wait for it to complete, as `ctdb recover` does. The recovery is requested through the node the client is connected to, which does not have to be the leader. On return that node is back in normal recovery mode with a new database generation.

A recovery leaves all active nodes with a full copy of every database. Until then the data of a volatile record is only on the node that last wrote it.

If a recovery is already in progress then that one is waited for first and another is forced, so the recovery this method waits for always starts after the call. CTDB holds off a new recovery for `RerecoveryTimeout` seconds (10 by default) after one has finished, and the wait includes that.

`timeout` is the maximum time to wait in seconds (1-300). The client is not locked during the wait, so other threads can keep using it.

**Raises:**
- `ValueError`: `timeout` is out of range
- `CTDBError`: Operation failed. `errno` is `ETIMEDOUT` if the recovery did not complete in time, in which case it may still be pending or in progress and the node may still be in recovery mode.

### CtdbDB Class

Represents an open CTDB database handle.

```python
# Database properties
name = db.db_name                   # Database name
db_id = db.db_id                    # Database ID
flags = db.db_flags                 # Tuple of flag strings

# Single record operations
value = db.fetch(key=b'mykey')      # Fetch a record
db.store(key=b'mykey', value=b'myvalue')  # Store a record
db.delete(key=b'mykey')             # Delete a record

# Bulk operations
db.wipe_db()                        # Wipe all records (leader only)
db.sync_with_tdb_file(
    tdb_path="/path/to/file.tdb",
    tdb_flags=0,
    open_flags=0,
    mode=0o644
)  # Synchronize with a TDB file (leader only)

# Iteration
for key, value in db.iter():
    print(f"Key: {key}, Value: {value}")

# Batch operations
from pyctdb import BatchOp

results = db.batch_op([
    BatchOp('SET', b'key1', b'value1'),
    BatchOp('SET', b'key2', b'value2'),
    BatchOp('GET', b'key1', None),
    BatchOp('DEL', b'key2', None),
])
# results = {2: b'value1'}  # Index 2 was the GET operation
```

#### Database Properties

- `db_name` (str, read-only): Name of the database
- `db_id` (int, read-only): Unique database identifier
- `db_flags` (tuple, read-only): Database flags as strings (e.g., `('PERSISTENT', 'REPLICATED')`)

#### Database Methods

##### `fetch(key) -> bytes`
Fetch a record from the database.

**Raises:**
- `FileNotFoundError`: Record does not exist, or has been deleted
- `CtdbError`: Operation failed

##### `store(key, value) -> None`
Store a record in the database. CTDB has no empty records: storing an empty value deletes the record.

**Raises:**
- `CtdbError`: Operation failed

##### `delete(key) -> None`
Delete a record from the database.

**Raises:**
- `CtdbError`: Operation failed

##### `wipe_db() -> None`
Wipe all records from the database. Must be called on the cluster leader.

**Raises:**
- `ValueError`: Not called on leader
- `CtdbError`: Operation failed

##### `sync_with_tdb_file(tdb_path, tdb_flags=0, open_flags=0, mode=0o644) -> None`
Synchronize the CTDB database with a local TDB file. Records in CTDB but not in the file are deleted; records in the file are written to CTDB. Must be called on the cluster leader.

**Raises:**
- `ValueError`: Not called on leader
- `CtdbError`: Operation failed or file cannot be opened

##### `iter() -> CtdbDBIterator`
Create an iterator for the database that yields `(key, value)` tuples. Deleted records are left out, including ones that are deleted while the iteration is under way.

**Raises:**
- `ValueError`: Database is not persistent or replicated
- `CtdbError`: Iteration setup failed

##### `batch_op(operations) -> dict`
Execute multiple operations atomically under a single transaction. All operations succeed or all fail (rollback).

**Parameters:**
- `operations`: Iterable of `BatchOp` instances

**Returns:**
- Dictionary mapping operation index to value for all GET operations

**Raises:**
- `TypeError`: Operations are not BatchOp instances
- `ValueError`: Database is not persistent/replicated or invalid operation
- `CtdbError`: Any operation failed (transaction rolled back). A GET of a record that does not exist, or has been deleted, is such a failure, with `errno` set to `ENOENT`

### BatchOp Type

A struct sequence representing a batch operation.

```python
from pyctdb import BatchOp

# Create batch operations
op_set = BatchOp('SET', b'mykey', b'myvalue')
op_get = BatchOp('GET', b'mykey', None)
op_del = BatchOp('DEL', b'mykey', None)

# Access fields
action = op_set.action      # 'SET'
key = op_set.key           # b'mykey'
value = op_set.value       # b'myvalue'
```

#### Fields

- `action` (str): Operation type - `'GET'`, `'SET'`, or `'DEL'`
- `key` (bytes): Record key
- `value` (bytes | None): Record value (required for SET, None for GET/DEL)

## Usage Examples

### Basic Database Operations

```python
from pyctdb import Client

# Connect to CTDB
client = Client()

# Open a persistent database
db = client.get_db("myapp", persistent=True, create_ok=True)

# Store some data
db.store(b'user:1', b'{"name": "Alice", "age": 30}')
db.store(b'user:2', b'{"name": "Bob", "age": 25}')

# Fetch data
user1 = db.fetch(b'user:1')
print(user1)  # b'{"name": "Alice", "age": 30}'

# Delete a record
db.delete(b'user:2')

# Iterate over all records
for key, value in db.iter():
    print(f"{key}: {value}")
```

### Batch Operations

```python
from pyctdb import Client, BatchOp

client = Client()
db = client.get_db("myapp", persistent=True)

# Prepare batch operations
operations = [
    BatchOp('SET', b'counter:a', b'1'),
    BatchOp('SET', b'counter:b', b'2'),
    BatchOp('SET', b'counter:c', b'3'),
    BatchOp('GET', b'counter:a', None),
    BatchOp('GET', b'counter:b', None),
    BatchOp('DEL', b'counter:c', None),
]

# Execute atomically
results = db.batch_op(operations)

# Results contains values from GET operations
print(results[3])  # b'1' (counter:a)
print(results[4])  # b'2' (counter:b)
```

### Cluster Management

```python
from pyctdb import Client

client = Client()

# Check if this node is the leader
if client.pnn == client.leader:
    print("This node is the cluster leader")

# Get cluster status
status = client.status()
print(f"Recovery mode: {status['recovery_mode']}")
print(f"Cluster state: {status['state']}")

# Get node information
nodemap = client.nodemap(refresh=True)
leader = client.leader
for node in nodemap:
    status_str = "LEADER" if node['pnn'] == leader else "MEMBER"
    flags_str = ", ".join(node['flags']) if node['flags'] else "NONE"
    print(f"Node {node['pnn']}: {node['address']} [{status_str}] flags: {flags_str}")
```

### Database Synchronization

```python
from pyctdb import Client

client = Client()
db = client.get_db("secrets", persistent=True)

# Synchronize CTDB database with a TDB file
# (must be run on the cluster leader)
if client.pnn == client.leader:
    db.sync_with_tdb_file("/var/lib/samba/private/secrets.tdb")
    print("Database synchronized")
else:
    print("Must run on leader node")
```

## Error Handling

The module raises custom exceptions for CTDB errors:

```python
from pyctdb import Client, CTDBError

client = Client()
db = client.get_db("mydb", persistent=True)

try:
    value = db.fetch(b'nonexistent')
except FileNotFoundError:
    print("Record not found")
except CTDBError as e:
    print(f"CTDB error: {e}")
```

### Losing the connection to ctdbd

If ctdbd stops or restarts, the client that was connected to it is of no further use. Every call on it, and on the databases opened through it, raises `CTDBError` with `errno` set to `ENOTCONN`. That includes a call that is in progress when the connection goes. Calls that need nothing from the daemon, such as `nodemap()` without `refresh`, still work.

A client only finds out that the connection has gone when it is next used. Until then it keeps the local copies of its databases open, and a ctdbd that is started again aborts if another process still has one of its volatile databases open with records in it. A client that has run a transaction, which every `fetch`, `store`, `delete` and `batch_op` does, has `g_lock.tdb` open. So before ctdbd is restarted on purpose, drop the client and the databases opened through it.

A client does not reconnect. Create a new `Client` and open the databases again:

```python
import errno

try:
    value = db.fetch(b'key')
except CTDBError as e:
    if e.errno != errno.ENOTCONN:
        raise

    client = Client()
    db = client.get_db("mydb")
    value = db.fetch(b'key')
```

## Thread Safety

The extension is designed to be thread-safe:

- Each client context has its own mutex lock
- Database operations acquire locks before accessing CTDB
- The GIL is released during long-running operations
- Global locking can be enabled for talloc leak reporting

```python
import threading
from pyctdb import Client

def worker(thread_id):
    client = Client()
    db = client.get_db("shared", persistent=True, create_ok=True)
    db.store(f'thread:{thread_id}'.encode(), b'data')

threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

## Performance Considerations

### Iterator vs. Manual Iteration

The `iter()` method creates a snapshot of keys at iteration start, then fetches values on-demand:

```python
# Memory-efficient - fetches values as needed
for key, value in db.iter():
    process(key, value)
```

### Batch Operations

Use batch operations for atomic multi-record updates:

```python
# All operations succeed or all fail
results = db.batch_op([
    BatchOp('SET', b'key1', b'val1'),
    BatchOp('SET', b'key2', b'val2'),
    # ... many more operations
])
```

### Transaction Overhead

Single operations (`fetch`, `store`, `delete`) each run in their own transaction. For multiple operations, use `batch_op` to reduce transaction overhead.

## Module Configuration

### Global Locking

Enable global locking for talloc leak reporting (debugging only):

```python
import pyctdb

# Enable leak reporting (also enables global locking)
pyctdb.enable_leak_reporting()

# Check if enabled
if pyctdb.get_leak_reporting():
    print("Leak reporting is active")

# Query/set global locking independently
is_locked = pyctdb.get_global_locking()
pyctdb.set_global_locking(True)
```

**Note:** Once leak reporting is enabled, it cannot be disabled for the module.

## Database Types

CTDB supports different database types:

- **Persistent**: Data survives cluster recovery (`persistent=True`)
- **Volatile**: Data is lost on recovery (`persistent=False`)
- **Replicated**: Database is replicated across all nodes (`replicated=True`)
- **Read-only**: Database is read-only (`readonly=True`)

Only persistent and replicated databases support the `fetch`, `store`, `delete`, `iter`, and `batch_op` operations.

## Building from Source

The extension is built using the Samba build system (waf):

```bash
# Configure
./configure --enable-debug

# Build
make

# The module will be in bin/default/ctdb/
ls -l bin/default/ctdb/pyctdb*.so
```

## Development

### Source Files

- `pyclient.h` - Main header with type definitions and function declarations
- `pyclient_module.c` - Module initialization
- `pyclient_client.c` - Client class implementation
- `pyclient_db.c` - Database class implementation
- `pyclient_db_batch.c` - Batch operations support
- `pyclient_db_iter.c` - Database iterator implementation
- `pyclient_error.c` - Exception handling
- `pyclient_tables.h` - Enumeration tables for node flags and capabilities

### Adding New Features

When adding new functionality:

1. Update the appropriate source file
2. Add function declarations to `pyclient.h`
3. Update module state if adding new types
4. Add proper error handling
5. Release GIL for long-running operations
6. Update this README with documentation

## Testing

`tests/` holds tests that run against a real CTDB cluster, which they start themselves: `tests/local_cluster.py` runs a few `ctdbd` daemons on loopback addresses in CTDB's test mode, with all of their files in one directory.

```bash
# Against the installed packages
python3 ctdb/pyclient/tests/test_pyctdb.py -v
```

`PYCTDB_TEST_NODES` sets the number of daemons (default: 2). Tests that need a second node are skipped with one. `PYCTDB_TEST_DIR` names a directory for the cluster's files and logs, which is then kept; the default is a temporary directory.

To test a build tree (configured `--with-cluster-support`), put its binaries, module and helpers in place of the installed ones:

```bash
B=$PWD/bin
export PATH=$B:$PATH PYTHONPATH=$PWD/bin/python
export CTDB_EVENTD=$B/ctdb-eventd CTDB_LOCK_HELPER=$B/ctdb_lock_helper
export CTDB_RECOVERY_HELPER=$B/ctdb_recovery_helper
export CTDB_TAKEOVER_HELPER=$B/ctdb_takeover_helper
export CTDB_CLUSTER_MUTEX_HELPER=$B/ctdb_mutex_fcntl_helper
python3 ctdb/pyclient/tests/test_pyctdb.py -v
```

The GitHub workflow runs these tests in its VM after the smoke tests (`.github/workflows/scripts/qemu-4-test.sh`).

## License

This code is part of the Samba project and is licensed under the GNU General Public License version 3 or later.
