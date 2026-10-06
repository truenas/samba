# Run a small ctdb cluster on loopback addresses, for tests.
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

"""A ctdb cluster made of daemons that all run on this host.

ctdb's test mode (CTDB_TEST_MODE) makes ctdbd, the ctdb tool and pyctdb take
every path from the environment, so each node gets a directory of its own
below the cluster directory and nothing else on the host is touched. Node n
listens on 127.0.0.<n + 1>, which Linux routes to the loopback interface
without any setup. The addresses and the ctdb port are fixed, so only one
such cluster can run on a host at a time.

The ctdb binaries are taken from PATH. To use a build tree instead, put its
bin directory on PATH and point CTDB_EVENTD, CTDB_LOCK_HELPER,
CTDB_RECOVERY_HELPER, CTDB_TAKEOVER_HELPER and CTDB_CLUSTER_MUTEX_HELPER at
the helpers in it.
"""

import os
import re
import shutil
import signal
import subprocess
import time

import pyctdb

CTDB_CONF = """\
[logging]
	location = file:{base}/log.ctdb

[cluster]
	cluster lock = {lock}
	node address = {address}

[database]
	volatile database directory = {base}/db/volatile
	persistent database directory = {base}/db/persistent
	state database directory = {base}/db/state
"""


class LocalCluster:
    def __init__(self, directory, num_nodes=2):
        if num_nodes < 1:
            raise ValueError('a cluster needs at least one node')

        self.directory = os.path.abspath(directory)
        self.num_nodes = num_nodes
        # ctdbd shuts down when its stdin is closed, so the daemons can not
        # outlive this process
        self._stdin = {}

    def __enter__(self):
        try:
            self.start()
        except BaseException:
            self.stop()
            raise

        return self

    def __exit__(self, *exc_info):
        self.stop()

    def node_dir(self, node):
        return os.path.join(self.directory, f'node.{node}')

    def socket(self, node):
        return os.path.join(self.node_dir(node), 'run', 'ctdbd.socket')

    def env(self, node):
        """The environment that makes ctdb programs use a node."""
        return dict(os.environ,
                    CTDB_TEST_MODE='yes',
                    CTDB_BASE=self.node_dir(node),
                    CTDB_SOCKET=self.socket(node))

    @staticmethod
    def _program(name):
        path = os.pathsep.join((os.environ.get('PATH', os.defpath),
                                '/usr/sbin', '/sbin'))
        program = shutil.which(name, path=path)
        if program is None:
            raise FileNotFoundError(f'{name} not found in {path}')

        return program

    def _configure(self, node):
        base = self.node_dir(node)
        for subdir in ('run', 'var', 'events/legacy', 'db/volatile',
                       'db/persistent', 'db/state'):
            os.makedirs(os.path.join(base, subdir))

        with open(os.path.join(base, 'nodes'), 'w') as f:
            for n in range(self.num_nodes):
                f.write(f'127.0.0.{n + 1}\n')

        with open(os.path.join(base, 'ctdb.conf'), 'w') as f:
            f.write(CTDB_CONF.format(
                base=base,
                lock=os.path.join(self.directory, 'cluster.lock'),
                address=f'127.0.0.{node + 1}',
            ))

    def start(self, timeout=60):
        """Start every daemon and wait for the cluster to be ready."""
        os.makedirs(self.directory, exist_ok=True)
        if os.listdir(self.directory):
            raise RuntimeError(f'{self.directory} is not empty')

        for node in range(self.num_nodes):
            self._configure(node)

        for node in range(self.num_nodes):
            self.start_daemon(node)

        self.wait_ready(timeout)

    def stop(self):
        """Shut every daemon down and wait for them to exit."""
        for node in list(self._stdin):
            self.stop_daemon(node)

    def start_daemon(self, node):
        """Start the daemon of a node, which then has to join the cluster."""
        if node in self._stdin:
            return

        stderr = os.path.join(self.node_dir(node), 'ctdbd.stderr')
        with open(stderr, 'w') as f:
            # ctdbd forks and the process started here exits at once
            proc = subprocess.Popen([self._program('ctdbd')],
                                    env=self.env(node),
                                    stdin=subprocess.PIPE,
                                    stdout=f, stderr=f)
        self._stdin[node] = proc.stdin
        if proc.wait(timeout=30) != 0:
            with open(stderr) as f:
                raise RuntimeError(
                    f'ctdbd failed to start on node {node}: {f.read()}'
                )

    def stop_daemon(self, node, kill=False, timeout=30):
        """Shut the daemon of a node down, or kill it, and wait for it."""
        if node not in self._stdin:
            return

        # The daemons that ctdbd runs are waited for as well. When ctdbd is
        # killed, its event daemon outlives it by a few seconds, and a new
        # ctdbd can not start by its side.
        processes = [
            (self.daemon_pid(node), 'ctdbd'),
            (self._pid(node, 'eventd.pid'), 'ctdb-eventd'),
            (self.recoverd_pid(node), 'ctdb_recoverd'),
        ]
        if kill:
            self._kill(processes)
        self._stdin.pop(node).close()

        deadline = time.monotonic() + timeout
        while any(self._stat(pid, name) for pid, name in processes):
            if time.monotonic() >= deadline:
                self._kill(processes)
                break
            time.sleep(0.1)

    def daemon_pid(self, node):
        """The process ID of the daemon of a node, if it has been started."""
        return self._pid(node, 'ctdbd.pid')

    def recoverd_pid(self, node):
        """The process ID of the recovery daemon that a node's daemon runs."""
        daemon = self.daemon_pid(node)
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                stat = self._stat(int(entry), 'ctdb_recoverd')
                if stat is not None and stat['ppid'] == daemon:
                    return int(entry)

        return None

    def _pid(self, node, pidfile):
        try:
            with open(os.path.join(self.node_dir(node), 'run', pidfile)) as f:
                return int(f.read())
        except (OSError, ValueError):
            return None

    @staticmethod
    def _stat(pid, name):
        """What /proc knows of a process, if it is running the named program.

        None if it is not, which includes a process that has exited but has
        not been waited for yet.
        """
        try:
            with open(f'/proc/{pid}/stat') as f:
                comm, state, ppid = re.fullmatch(
                    r'\d+ \((.*)\) (\S) (\d+) .*', f.read(), re.S
                ).groups()
        except OSError:
            return None

        if comm != name or state == 'Z':
            return None

        return {'state': state, 'ppid': int(ppid)}

    @classmethod
    def _kill(cls, processes):
        for pid, name in processes:
            if cls._stat(pid, name):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def ctdb(self, node, *args):
        """Run the ctdb tool on a node and return its output."""
        result = subprocess.run([self._program('ctdb'), *args],
                                env=self.env(node),
                                stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            raise RuntimeError(
                f'"ctdb {" ".join(args)}" failed on node {node} '
                f'({result.returncode}): {result.stderr or result.stdout}'
            )

        return result.stdout

    def client(self, node):
        """A pyctdb client that is connected to a node."""
        # pyctdb looks these up whenever a client is created
        os.environ.update(CTDB_TEST_MODE='yes',
                          CTDB_BASE=self.directory,
                          CTDB_SOCKET=self.socket(node))
        return pyctdb.Client()

    def status(self, node):
        """What `ctdb status` reports on a node.

        `nodes` maps each PNN to its flags, "OK" for a healthy node. The
        generation is None while it is invalid and the leader is None while
        there is none.
        """
        out = self.ctdb(node, 'status')
        generation = re.search(r'^Generation:(\d+)$', out, re.M)
        leader = re.search(r'^Leader:(\d+)$', out, re.M)
        return {
            'nodes': {
                int(pnn): flags for pnn, flags in
                re.findall(r'^pnn:(\d+)\s+\S+\s+(\S+)', out, re.M)
            },
            'generation': int(generation.group(1)) if generation else None,
            'recovery_mode': re.search(r'^Recovery mode:(\w+)', out,
                                       re.M).group(1),
            'leader': int(leader.group(1)) if leader else None,
        }

    def ready(self):
        """Whether every node is healthy and they all agree on that."""
        generations = set()
        for node in range(self.num_nodes):
            try:
                status = self.status(node)
            except (RuntimeError, subprocess.TimeoutExpired):
                return False

            if (
                status['recovery_mode'] != 'NORMAL'
                or status['generation'] is None
                or status['leader'] is None
                or len(status['nodes']) != self.num_nodes
                or any(flags != 'OK' for flags in status['nodes'].values())
            ):
                return False

            generations.add(status['generation'])

        return len(generations) == 1

    def wait_until(self, condition, timeout=60):
        """Wait until a condition, a function without arguments, holds."""
        deadline = time.monotonic() + timeout
        while not condition():
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f'gave up waiting on the ctdb cluster in {self.directory}'
                    f'\n{self.log_tail()}'
                )
            time.sleep(0.2)

    def wait_ready(self, timeout=60):
        self.wait_until(self.ready, timeout)

    def log_tail(self, lines=20):
        """The end of every node's log, for error messages."""
        tail = []
        for node in range(self.num_nodes):
            path = os.path.join(self.node_dir(node), 'log.ctdb')
            try:
                with open(path, errors='replace') as f:
                    tail += [f'==> {path} <==\n', *f.readlines()[-lines:]]
            except OSError as e:
                tail.append(f'{e}\n')

        return ''.join(tail)

    def statistics(self, node):
        """The counters that `ctdb statistics` reports on a node."""
        out = self.ctdb(node, 'statistics')
        return {
            name: int(value) for name, value in
            re.findall(r'^\s+(\w+)\s+(\d+)$', out, re.M)
        }

    def local_records(self, node, db_name):
        """The records in a node's own copy of a database.

        This is what the node holds itself, as opposed to what it could
        fetch from the rest of the cluster. A record whose data lives on
        another node shows up with empty data, or not at all.
        """
        records = {}
        key = None
        for line in self.ctdb(node, 'cattdb', db_name).splitlines():
            match = re.fullmatch(r'(key|data)\(\d+\) = "(.*)"', line)
            if match is None:
                continue
            if match.group(1) == 'key':
                key = match.group(2)
            else:
                records[key] = match.group(2)

        return records
