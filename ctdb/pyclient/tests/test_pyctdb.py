#!/usr/bin/env python3
# Tests for the pyctdb module.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Tests for the pyctdb module, run against a local ctdb cluster.

    python3 ctdb/pyclient/tests/test_pyctdb.py -v

Environment:
    PYCTDB_TEST_NODES  number of ctdb daemons to run (default: 2)
    PYCTDB_TEST_DIR    directory for the cluster's files, logs included,
                       which is then kept (default: a temporary directory)

See local_cluster.py for how the cluster is run and what it needs.
"""

import ctypes
import errno
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest

import pyctdb

from local_cluster import LocalCluster

NUM_NODES = int(os.environ.get('PYCTDB_TEST_NODES', '2'))

cluster = None


def setUpModule():
    global cluster

    directory = os.environ.get('PYCTDB_TEST_DIR')
    if directory is None:
        tmpdir = tempfile.TemporaryDirectory(prefix='pyctdb-')
        unittest.addModuleCleanup(tmpdir.cleanup)
        directory = tmpdir.name

    cluster = LocalCluster(directory, NUM_NODES)
    unittest.addModuleCleanup(cluster.stop)
    cluster.start()


def heap_in_use():
    """The number of bytes that malloc() has handed out and not got back."""

    class MallInfo2(ctypes.Structure):
        _fields_ = [(name, ctypes.c_size_t) for name in (
            'arena', 'ordblks', 'smblks', 'hblks', 'hblkhd', 'usmblks',
            'fsmblks', 'uordblks', 'fordblks', 'keepcost',
        )]

    mallinfo2 = ctypes.CDLL(None).mallinfo2
    mallinfo2.restype = MallInfo2
    info = mallinfo2()
    return info.uordblks + info.hblkhd


class ClusterTestCase(unittest.TestCase):
    def setUp(self):
        # A test may leave a recovery behind, so let the cluster settle
        cluster.wait_ready()

    def stop_node(self, node):
        """Take a node out of the cluster until the end of the test."""
        cluster.ctdb(node, 'stop')
        self.addCleanup(cluster.ctdb, node, 'continue')

    def node_to_take_down(self):
        """A node whose daemon the test stops, restarted when the test ends.

        Not the leader if that can be avoided, which saves an election.
        """
        leader = cluster.status(0)['leader']
        node = next((n for n in range(NUM_NODES) if n != leader), leader)
        self.addCleanup(cluster.start_daemon, node)
        return node


class LeaderTest(ClusterTestCase):
    def test_new_client_knows_leader(self):
        for node in range(NUM_NODES):
            with self.subTest(node=node):
                leader = cluster.status(node)['leader']
                self.assertEqual(cluster.client(node).leader, leader)
                self.assertEqual(cluster.client(node).status()['leader_pnn'],
                                 leader)

    def test_wipe_db_on_new_client(self):
        leader = cluster.status(0)['leader']
        db_name = 'pyctdb_wipe.tdb'
        db = cluster.client(leader).get_db(db_name, create_ok=True)
        db.store(b'key', b'value')

        for node in range(NUM_NODES):
            if node != leader:
                db = cluster.client(node).get_db(db_name)
                with self.assertRaises(ValueError):
                    db.wipe_db()
                self.assertEqual(db.fetch(b'key'), b'value')

        cluster.client(leader).get_db(db_name).wipe_db()

        for node in range(NUM_NODES):
            db = cluster.client(node).get_db(db_name)
            with self.assertRaises(FileNotFoundError):
                db.fetch(b'key')

    def test_sync_with_tdb_file_on_new_client(self):
        leader = cluster.status(0)['leader']
        db_name = 'pyctdb_sync.tdb'
        db = cluster.client(leader).get_db(db_name, create_ok=True)
        db.store(b'same', b'value')
        db.store(b'changed', b'old value')
        db.store(b'removed', b'value')

        with tempfile.TemporaryDirectory() as tmpdir:
            tdb_path = os.path.join(tmpdir, 'file.tdb')
            subprocess.run(
                ['tdbrestore', tdb_path], check=True, text=True,
                input='{\nkey(4) = "same"\ndata(5) = "value"\n}\n'
                      '{\nkey(7) = "changed"\ndata(9) = "new value"\n}\n'
                      '{\nkey(5) = "added"\ndata(5) = "value"\n}\n',
            )

            for node in range(NUM_NODES):
                if node != leader:
                    db = cluster.client(node).get_db(db_name)
                    with self.assertRaises(ValueError):
                        db.sync_with_tdb_file(tdb_path)
                    self.assertEqual(db.fetch(b'changed'), b'old value')

            cluster.client(leader).get_db(db_name).sync_with_tdb_file(tdb_path)

        for node in range(NUM_NODES):
            db = cluster.client(node).get_db(db_name)
            self.assertEqual(dict(db.iter()), {
                b'same': b'value',
                b'changed': b'new value',
                b'added': b'value',
            })
            with self.assertRaises(FileNotFoundError):
                db.fetch(b'removed')

    @unittest.skipIf(NUM_NODES < 2, 'needs a second node')
    def test_idle_client_after_leader_change(self):
        old_leader = cluster.status(0)['leader']
        clients = {
            node: cluster.client(node) for node in range(NUM_NODES)
            if node != old_leader
        }
        dbs = {}
        for node, client in clients.items():
            self.assertEqual(client.leader, old_leader)
            dbs[node] = client.get_db('pyctdb_leader_change.tdb',
                                      create_ok=True)
            dbs[node].store(b'key', b'value')

        # The clients make no request while another node takes over
        self.stop_node(old_leader)
        node = next(iter(clients))

        def leader_changed():
            status = cluster.status(node)
            return (status['leader'] not in (None, old_leader)
                    and status['recovery_mode'] == 'NORMAL')

        cluster.wait_until(leader_changed)
        leader = cluster.status(node)['leader']

        dbs[leader].wipe_db()
        with self.assertRaises(FileNotFoundError):
            dbs[leader].fetch(b'key')
        self.assertEqual(clients[leader].leader, leader)

    @unittest.skipIf(NUM_NODES < 2, 'needs a second node')
    def test_wipe_db_reaches_node_that_rejoined(self):
        leader = cluster.status(0)['leader']
        node = next(n for n in range(NUM_NODES) if n != leader)
        client = cluster.client(leader)
        db = client.get_db('pyctdb_wipe_rejoin.tdb', create_ok=True)
        db.store(b'key', b'value')

        # The last that the client hears of the node is that it is stopped
        self.stop_node(node)
        flags = {n['pnn']: n['flags'] for n in client.nodemap(refresh=True)}
        self.assertIn('STOPPED', flags[node])
        cluster.ctdb(node, 'continue')
        cluster.wait_ready()
        self.assertEqual(cluster.status(leader)['leader'], leader)

        db.wipe_db()

        rejoined = cluster.client(node).get_db('pyctdb_wipe_rejoin.tdb')
        with self.assertRaises(FileNotFoundError):
            rejoined.fetch(b'key')


class DatabaseTest(ClusterTestCase):
    def test_deleted_record_does_not_exist(self):
        db_name = 'pyctdb_delete.tdb'
        db = cluster.client(0).get_db(db_name, create_ok=True)
        db.store(b'kept', b'value')
        db.store(b'deleted', b'value')
        db.store(b'emptied', b'value')

        started_before = db.iter()
        db.delete(b'deleted')
        # ctdb has no empty records: a record without data is a deleted one
        db.store(b'emptied', b'')

        for node in range(NUM_NODES):
            with self.subTest(node=node):
                db = cluster.client(node).get_db(db_name)
                for key in (b'deleted', b'emptied'):
                    with self.assertRaises(FileNotFoundError):
                        db.fetch(key)
                    with self.assertRaises(pyctdb.CTDBError) as cm:
                        db.batch_op([pyctdb.BatchOp(('GET', key, None))])
                    self.assertEqual(cm.exception.errno, errno.ENOENT)
                self.assertEqual(dict(db.iter()), {b'kept': b'value'})

        self.assertEqual(dict(started_before), {b'kept': b'value'})

        db.store(b'deleted', b'new value')
        self.assertEqual(db.fetch(b'deleted'), b'new value')


class DisconnectTest(ClusterTestCase):
    def test_calls_fail_after_daemon_has_gone(self):
        node = self.node_to_take_down()
        db_name = 'pyctdb_disconnect.tdb'
        client = cluster.client(node)
        db = client.get_db(db_name, create_ok=True)
        db.store(b'key', b'value')
        nodemap = client.nodemap()

        cluster.stop_daemon(node)

        calls = {
            'status()': client.status,
            'leader': lambda: client.leader,
            'nodemap(refresh=True)': lambda: client.nodemap(refresh=True),
            'get_db()': lambda: client.get_db(db_name),
            'recover()': client.recover,
            'fetch()': lambda: db.fetch(b'key'),
            'store()': lambda: db.store(b'key', b'value'),
            'delete()': lambda: db.delete(b'key'),
            'batch_op()': lambda: db.batch_op(
                [pyctdb.BatchOp(('SET', b'key', b'value'))]
            ),
            'iter()': lambda: list(db.iter()),
            'wipe_db()': db.wipe_db,
            'sync_with_tdb_file()': lambda: db.sync_with_tdb_file('/nonexistent'),
        }
        for name, call in calls.items():
            with self.subTest(call=name):
                start = time.monotonic()
                with self.assertRaises(pyctdb.CTDBError) as cm:
                    call()
                self.assertEqual(cm.exception.errno, errno.ENOTCONN)
                # At once, not when some timeout expires
                self.assertLess(time.monotonic() - start, 2)

        # What needs no daemon still works
        self.assertEqual(client.nodemap(), nodemap)

        # The daemon can only come back because the client has let go of
        # its databases: ctdbd aborts over a volatile one that is still open
        # elsewhere. Once it is back, the client and the database connect
        # again on their own.
        cluster.start_daemon(node)
        cluster.wait_ready()
        client.status()
        self.assertEqual(db.fetch(b'key'), b'value')

    def test_call_fails_when_daemon_dies_during_it(self):
        node = self.node_to_take_down()
        client = cluster.client(node)
        client.status()
        errors = []

        def status():
            try:
                client.status()
            except Exception as e:
                errors.append(e)

        # A stopped process does not reply, so the request stays in flight
        os.kill(cluster.daemon_pid(node), signal.SIGSTOP)
        thread = threading.Thread(target=status, daemon=True)
        thread.start()
        try:
            time.sleep(1)
            self.assertTrue(thread.is_alive(), errors)
        finally:
            cluster.stop_daemon(node, kill=True)

        # Well before the request would have timed out, after 10 seconds
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([type(e) for e in errors], [pyctdb.CTDBError])
        self.assertEqual(errors[0].errno, errno.ENOTCONN)

        cluster.start_daemon(node)
        cluster.wait_ready()
        client.status()

    def test_leader_wait_ends_when_daemon_dies(self):
        leader = cluster.status(0)['leader']
        self.addCleanup(cluster.start_daemon, leader)
        results = []

        def lookup():
            try:
                results.append(client.leader)
            except Exception as e:
                results.append(e)

        # The leader announces itself from its recovery daemon. With that
        # stopped, a client that is created now does not hear of a leader
        # and waits for one.
        os.kill(cluster.recoverd_pid(leader), signal.SIGSTOP)
        try:
            client = cluster.client(leader)
            thread = threading.Thread(target=lookup, daemon=True)
            thread.start()
            time.sleep(1)
            self.assertTrue(thread.is_alive(), results)
        finally:
            cluster.stop_daemon(leader, kill=True)

        # Left alone, the wait would have gone on for another 4 seconds
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual([type(r) for r in results], [pyctdb.CTDBError])
        self.assertEqual(results[0].errno, errno.ENOTCONN)

    def test_threads_using_client_when_daemon_dies(self):
        node = self.node_to_take_down()
        client = cluster.client(node)
        db = client.get_db('pyctdb_disconnect_threads.tdb', create_ok=True)
        db.store(b'key', b'value')
        errors = []

        def use(call):
            try:
                while True:
                    call()
            except Exception as e:
                errors.append(e)

        calls = [
            client.status,
            lambda: client.leader,
            lambda: db.fetch(b'key'),
            lambda: db.store(b'key', b'value'),
        ]
        threads = [
            threading.Thread(target=use, args=(call,), daemon=True)
            for call in calls
        ]
        for thread in threads:
            thread.start()
        time.sleep(0.5)
        self.assertEqual(errors, [])

        cluster.stop_daemon(node, kill=True)
        for thread in threads:
            thread.join(5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([(type(e), e.errno) for e in errors],
                         [(pyctdb.CTDBError, errno.ENOTCONN)] * len(calls))

        cluster.start_daemon(node)
        cluster.wait_ready()
        errors.clear()

        def use_a_while(call):
            try:
                for _ in range(20):
                    call()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=use_a_while, args=(call,), daemon=True)
            for call in calls
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])


def open_databases():
    """The ctdb database files this process has open."""
    files = set()
    for fd in os.listdir('/proc/self/fd'):
        try:
            path = os.readlink(f'/proc/self/fd/{fd}')
        except OSError:
            continue
        if '/db/' in path and '.tdb' in path:
            files.add(path)

    return files


class ReconnectTest(ClusterTestCase):
    """A client connects again when ctdbd has been restarted."""

    def restart_daemon(self, node):
        cluster.stop_daemon(node)
        cluster.start_daemon(node)
        cluster.wait_ready()

    def test_idle_client_lets_go_of_its_databases(self):
        node = self.node_to_take_down()
        client = cluster.client(node)
        db = client.get_db('pyctdb_reconnect_idle.tdb', create_ok=True)
        # A transaction attaches g_lock.tdb, which is volatile
        db.store(b'key', b'value')
        ours = {f for f in open_databases() if f'/node.{node}/' in f}
        self.assertTrue(any('g_lock.tdb' in f for f in ours), ours)
        self.assertTrue(any('pyctdb_reconnect_idle.tdb' in f for f in ours),
                        ours)

        # Without being used, the client notices and lets go, which is
        # what lets ctdbd start again
        cluster.stop_daemon(node)
        deadline = time.monotonic() + 5
        while ours & open_databases() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(ours & open_databases(), set())

        cluster.start_daemon(node)
        cluster.wait_ready()
        self.assertEqual(db.fetch(b'key'), b'value')
        self.assertTrue(any('g_lock.tdb' in f for f in open_databases()))

    def test_idle_client_after_daemon_restart(self):
        node = self.node_to_take_down()
        client = cluster.client(node)
        db = client.get_db('pyctdb_reconnect.tdb', create_ok=True)
        db.store(b'before', b'restart')
        iterator = db.iter()
        pnn = client.pnn

        self.restart_daemon(node)

        # The client has not been told. Its first call finds out, connects
        # again and is carried out all the same.
        self.assertEqual(client.status()['leader_pnn'],
                         cluster.status(node)['leader'])
        self.assertEqual(client.pnn, pnn)

        # So is a database opened before, and an iterator made before
        self.assertEqual(db.fetch(b'before'), b'restart')
        db.store(b'after', b'restart')
        self.assertEqual(dict(iterator), {b'before': b'restart'})
        self.assertEqual(dict(db.iter()),
                         {b'before': b'restart', b'after': b'restart'})
        self.assertEqual(
            db.batch_op([pyctdb.BatchOp(('GET', b'after', None))]),
            {0: b'restart'},
        )

        # And what the restart did not touch
        self.assertEqual(cluster.client(node).get_db('pyctdb_reconnect.tdb')
                         .fetch(b'after'), b'restart')
        client.recover()
        self.assertEqual(db.fetch(b'after'), b'restart')

    def test_client_after_two_restarts(self):
        node = self.node_to_take_down()
        client = cluster.client(node)
        db = client.get_db('pyctdb_reconnect_twice.tdb', create_ok=True)
        for n in range(2):
            db.store(b'key', b'value %d' % n)
            self.restart_daemon(node)
            self.assertEqual(db.fetch(b'key'), b'value %d' % n)
            self.assertEqual(client.leader, cluster.status(node)['leader'])

    def test_database_opened_while_daemon_is_down(self):
        node = self.node_to_take_down()
        client = cluster.client(node)
        client.status()
        cluster.stop_daemon(node)
        with self.assertRaises(pyctdb.CTDBError) as cm:
            client.get_db('pyctdb_reconnect_down.tdb', create_ok=True)
        self.assertEqual(cm.exception.errno, errno.ENOTCONN)

        cluster.start_daemon(node)
        cluster.wait_ready()
        db = client.get_db('pyctdb_reconnect_down.tdb', create_ok=True)
        db.store(b'key', b'value')
        self.assertEqual(db.fetch(b'key'), b'value')


class GlobalLockingTest(ClusterTestCase):
    """The lock that all clients of a process share, if it is turned on.

    The setting is for the whole process, and leak reporting can not be
    turned off again. So each test does its part in a process of its own,
    which also keeps a crash there from ending the test run.
    """

    def run_python(self, code, *args, node=0):
        """Run code in a process whose clients use a node of the cluster."""
        result = subprocess.run(
            [sys.executable, '-c', textwrap.dedent(code), *map(str, args)],
            env=cluster.env(node),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_set_global_locking(self):
        self.run_python('''
            import concurrent.futures

            import pyctdb

            assert pyctdb.get_global_locking() is False
            for value, setting in ((True, True), (1, True), ('x', True),
                                   (False, False), (0, False), ('', False)):
                assert pyctdb.set_global_locking(value) is setting, value
                assert pyctdb.get_global_locking() is setting, value

            for args in ((), (True, True)):
                try:
                    pyctdb.set_global_locking(*args)
                except TypeError:
                    pass
                else:
                    raise AssertionError(args)

            assert pyctdb.set_global_locking(value=True) is True
            assert pyctdb.get_global_locking() is True

            def use_database(number):
                key = b'key %d' % number
                db = pyctdb.Client().get_db('pyctdb_global_locking.tdb',
                                            create_ok=True)
                for n in range(20):
                    db.store(key, b'value %d' % n)
                    assert db.fetch(key) == b'value %d' % n

            # Two clients, each of which now waits for the other
            with concurrent.futures.ThreadPoolExecutor(2) as executor:
                for future in [executor.submit(use_database, number)
                               for number in range(2)]:
                    future.result()
        ''')

    def test_leak_reporting_keeps_global_locking_on(self):
        self.run_python('''
            import pyctdb

            assert pyctdb.get_leak_reporting() is False
            pyctdb.enable_leak_reporting()
            assert pyctdb.get_leak_reporting() is True
            assert pyctdb.get_global_locking() is True
            for value in (False, True):
                try:
                    pyctdb.set_global_locking(value)
                except ValueError:
                    pass
                else:
                    raise AssertionError(value)

            assert pyctdb.get_global_locking() is True
            pyctdb.Client().status()
        ''')

    def test_setting_changes_during_a_call(self):
        node = NUM_NODES - 1
        daemon = cluster.daemon_pid(node)
        # In case the other process does not get to it
        self.addCleanup(os.kill, daemon, signal.SIGCONT)
        self.run_python('''
            import os
            import signal
            import sys
            import threading
            import time

            import pyctdb

            daemon = int(sys.argv[1])
            client = pyctdb.Client()
            client.status()

            def call(during=None):
                """Make a call, and do something while it waits for a reply."""
                errors = []

                def status():
                    try:
                        client.status()
                    except Exception as e:
                        errors.append(e)

                thread = threading.Thread(target=status, daemon=True)
                if during is None:
                    thread.start()
                else:
                    # A stopped process does not reply
                    os.kill(daemon, signal.SIGSTOP)
                    try:
                        thread.start()
                        time.sleep(1)
                        assert thread.is_alive(), errors
                        during()
                    finally:
                        os.kill(daemon, signal.SIGCONT)

                thread.join(30)
                assert not thread.is_alive(), 'the call does not return'
                assert not errors, errors

            # The call that is waiting has not taken the global lock
            call(lambda: pyctdb.set_global_locking(True))
            call()
            # This one has taken it, and still has to release it
            call(lambda: pyctdb.set_global_locking(False))
            pyctdb.set_global_locking(True)
            call()
        ''', daemon, node=node)


class StatusTest(ClusterTestCase):
    def test_status_does_not_leak(self):
        try:
            heap_in_use()
        except AttributeError:
            self.skipTest('needs mallinfo2(), which glibc has')

        client = cluster.client(0)
        calls = {
            'status()': client.status,
            'nodemap(refresh=True)': lambda: client.nodemap(refresh=True),
        }
        for name, call in calls.items():
            with self.subTest(call=name):
                for _ in range(100):
                    call()

                before = heap_in_use()
                for _ in range(1000):
                    call()
                self.assertLess(heap_in_use() - before, 16384)

    def test_nodemap_from_threads(self):
        client = cluster.client(0)
        errors = []

        def nodemaps():
            try:
                for i in range(400):
                    nodemap = client.nodemap(refresh=i % 2 == 0)
                    self.assertEqual(len(nodemap), NUM_NODES)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=nodemaps) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])


class RecoverTest(ClusterTestCase):
    def test_recover(self):
        client = cluster.client(0)
        before = cluster.status(0)['generation']

        client.recover()

        # No waiting here: the recovery has to be over when recover() returns
        after = cluster.status(0)
        self.assertEqual(after['recovery_mode'], 'NORMAL')
        self.assertIsNotNone(after['generation'])
        self.assertNotEqual(after['generation'], before)
        self.assertEqual(client.status()['recovery_mode'], 'NORMAL')

    def test_invalid_timeout(self):
        client = cluster.client(0)
        before = cluster.statistics(0)['num_recoveries']

        for timeout in (0, -1, 301):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    client.recover(timeout=timeout)

        for timeout in ('1', 1.5, None):
            with self.subTest(timeout=timeout):
                with self.assertRaises(TypeError):
                    client.recover(timeout=timeout)

        self.assertEqual(cluster.status(0)['recovery_mode'], 'NORMAL')
        self.assertEqual(cluster.statistics(0)['num_recoveries'], before)

    def test_persistent_database_usable_after_recover(self):
        client = cluster.client(0)
        db = client.get_db('pyctdb_recover.tdb', create_ok=True)
        db.store(b'key', b'value')

        client.recover()

        self.assertEqual(db.fetch(b'key'), b'value')
        db.store(b'key', b'new value')
        peer = cluster.client(NUM_NODES - 1).get_db('pyctdb_recover.tdb')
        self.assertEqual(peer.fetch(b'key'), b'new value')

    @unittest.skipIf(NUM_NODES < 2, 'needs a second node')
    def test_recover_copies_volatile_records_to_other_nodes(self):
        """A recovery leaves every node with all the volatile records.

        Until then a record's data is only on the node that last wrote it,
        and so would be lost with that node.
        """
        db_name = 'pyctdb_recover_volatile.tdb'
        cluster.ctdb(0, 'attach', db_name)

        # Once from each node, so that the leader is both the node that
        # the records come from and a node that they have to be sent to
        for node in range(NUM_NODES):
            with self.subTest(node=node):
                records = {
                    f'key-{node}-{i}': f'value-{node}-{i}' for i in range(8)
                }
                for key, value in records.items():
                    cluster.ctdb(node, 'writekey', db_name, key, value)

                others = [n for n in range(NUM_NODES) if n != node]
                for other in others:
                    local = cluster.local_records(other, db_name)
                    for key in records:
                        self.assertFalse(local.get(key), (other, key))

                cluster.client(node).recover()

                for other in others:
                    local = cluster.local_records(other, db_name)
                    for key, value in records.items():
                        self.assertEqual(local.get(key), value, (other, key))

    def test_client_usable_during_recover(self):
        client = cluster.client(0)
        # Held off by the recovery before it, so the second one takes a
        # while
        client.recover()
        errors = []

        def recover():
            try:
                client.recover()
            except Exception as e:
                errors.append(e)

        thread = threading.Thread(target=recover)
        thread.start()
        # Calls that returned while recover() was still running
        calls = 0
        while thread.is_alive():
            client.status()
            calls += thread.is_alive()
            time.sleep(0.05)
        thread.join()

        self.assertEqual(errors, [])
        self.assertGreater(calls, 2)

    def test_timeout(self):
        client = cluster.client(0)
        # ctdb holds off the next recovery for RerecoveryTimeout seconds, 10
        # by default, so one that is forced right after another can not be
        # over within a second
        client.recover()

        start = time.monotonic()
        with self.assertRaises(pyctdb.CTDBError) as cm:
            client.recover(timeout=1)
        elapsed = time.monotonic() - start

        self.assertEqual(cm.exception.errno, errno.ETIMEDOUT)
        self.assertGreaterEqual(elapsed, 1)
        # The recovery was asked for and is still due
        self.assertEqual(cluster.status(0)['recovery_mode'], 'RECOVERY')

    def test_recover_follows_pending_recovery(self):
        """A recovery that was already due is not taken for the forced one.

        recover() has to wait for that one and then force another, which
        with the default tunables has to fit into the default timeout.
        """
        client = cluster.client(0)
        client.recover()
        before = cluster.statistics(0)['num_recoveries']
        with self.assertRaises(pyctdb.CTDBError):
            client.recover(timeout=1)

        client.recover()

        self.assertEqual(cluster.status(0)['recovery_mode'], 'NORMAL')
        recoveries = cluster.statistics(0)['num_recoveries'] - before
        self.assertGreaterEqual(recoveries, 2)

    @unittest.skipIf(NUM_NODES < 2, 'needs a second node')
    def test_timeout_on_stopped_node(self):
        # `ctdb stop` takes a node out of the cluster and leaves it in
        # recovery mode, so there is nothing that recover() could wait for.
        # Stop a node other than the leader, which saves an election.
        leader = cluster.status(0)['leader']
        node = next(n for n in range(NUM_NODES) if n != leader)
        self.stop_node(node)
        client = cluster.client(node)

        start = time.monotonic()
        with self.assertRaises(pyctdb.CTDBError) as cm:
            client.recover(timeout=2)
        elapsed = time.monotonic() - start

        self.assertEqual(cm.exception.errno, errno.ETIMEDOUT)
        self.assertGreaterEqual(elapsed, 2)
        # Far below the default timeout
        self.assertLess(elapsed, 15)


if __name__ == '__main__':
    unittest.main()
