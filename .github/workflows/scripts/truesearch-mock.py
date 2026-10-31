#!/usr/bin/env python3
"""
Mock truesearchd for the CI test of the truesearch Spotlight backend.

The mock uses the protocol of source3/rpc_server/mdssvc/truenas_truesearch.x
on a unix stream socket. It finds the share directory from the dataset and
the share path in /proc/self/mountinfo. A hit is a file or directory under
the scope whose name matches the first kMDItemFSName glob of the query
("c" ignores case). The search does not follow links or cross mounts. The
mock applies max_results, the cnids (item IDs) and the fetch limit. A
handle is valid only on its connection. The mock does not filter by
identity.

The mock writes each call to the record file as a JSON line. A pattern
"mockfault-KIND-REST" injects a fault. REST is the pattern for the other
hits.
  badquery, busy, noindex  refuse the open with this status
  absolute, dotdot, empty  add a hit with a bad path
  root                     add the share root ("") as a hit
  longpath                 add a hit longer than 1024 bytes
  nostat                   send the hits without a stat
  garbage                  reply to the open with data that is not XDR
  xid                      reply to the open with another xid
  op                       reply to the open with a RIX_FETCH answer
  huge                     reply to the open with a length > RIX_MAX_FRAME
  drop                     close the connection at the first open of the
                           query
  dropfetch                close the connection at the first fetch of a
                           handle
  badhandle                reply RIX_BAD_HANDLE to the first fetch of a
                           handle
  slow                     reply to the open after 2 s
  stall                    reply to the open after 25 s (Samba waits 20 s)
--hello-faults applies to the first RIX_HELLOs, one fault each, in order:
  refuse                   reply RIX_BAD_VERSION
  version                  reply with version 2
  drop                     close the connection

The stat of a hit comes from truenas_os.statx, with the inode generation
of the TrueNAS kernel (stx_gen). Its item ID is the FileId of zfs_core for
the share's dataset, and its volume id the fsid of the share directory.
The python3-truenas-pyos deb supplies truenas_os.

  truesearch-mock.py --socket PATH --record FILE
                     [--max-results N] [--max-page N] [--hello-faults F,...]
"""

import argparse
import fnmatch
import json
import os
import re
import socket
import socketserver
import struct
import sys
import threading
import time

import truenas_os

RIX_PROTO_VERSION = 1
HELLO, OPEN, FETCH, CLOSE = range(4)
(OK, BAD_VERSION, BAD_QUERY, BAD_SCOPE, NO_INDEX, DENIED, BAD_HANDLE, BUSY,
 INTERNAL) = range(9)
RIX_MAX_FRAME = 16 * 1024 * 1024
RIX_OPEN_WANT_STAT = 2
STATUS_NAMES = ['OK', 'BAD_VERSION', 'BAD_QUERY', 'BAD_SCOPE', 'NO_INDEX',
                'DENIED', 'BAD_HANDLE', 'BUSY', 'INTERNAL']
REFUSED = {'badquery': BAD_QUERY, 'busy': BUSY, 'noindex': NO_INDEX}
DELAYED = {'slow': 2, 'stall': 25}

STATX_MASK = (truenas_os.STATX_BASIC_STATS | truenas_os.STATX_BTIME |
              truenas_os.STATX_GEN)
# The item ID: the object number in bits 0-38, bit 39 set, the low 24 bits
# of the generation in bits 40-63 (zfs_core_file_id.h)
OBJ_BITS = 39
WITH_GEN = 1 << OBJ_BITS
GEN_MASK = 0xffffff

PATTERN = re.compile(r'kMDItemFSName\s*==\s*"((?:[^"\\]|\\.)*)"([a-z]*)')
FAULT = re.compile(r'^mockfault-([a-z]+)-(.*)$')


class Dropped(Exception):
    """Close the connection without a reply."""


class Huge(Exception):
    """Reply with a record length larger than RIX_MAX_FRAME."""


class Conn:
    """A connection: the peer uid and its handles."""

    def __init__(self, peer_uid):
        self.peer_uid = peer_uid
        self.handles = set()


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError('record too short')
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self):
        return struct.unpack('>I', self.take(4))[0]

    def u64(self):
        return struct.unpack('>Q', self.take(8))[0]

    def string(self):
        n = self.u32()
        out = self.take(n)
        self.take(-n % 4)
        return out.decode('utf-8', 'surrogateescape')

    def array(self, item):
        return [item() for _ in range(self.u32())]


class Writer:
    def __init__(self):
        self.parts = []

    def u32(self, v):
        self.parts.append(struct.pack('>I', v))
        return self

    def i64(self, v):
        self.parts.append(struct.pack('>q', v))
        return self

    def u64(self, v):
        self.parts.append(struct.pack('>Q', v))
        return self

    def string(self, s):
        b = s.encode('utf-8', 'surrogateescape')
        self.u32(len(b))
        self.parts.append(b + b'\0' * (-len(b) % 4))
        return self

    def data(self):
        return b''.join(self.parts)


def statx(path):
    """Return the rix_stat of path. Do not follow a link."""
    st = truenas_os.statx(path, flags=truenas_os.AT_SYMLINK_NOFOLLOW,
                          mask=STATX_MASK)

    def time_of(ns):
        return divmod(ns, 1000000000)

    got = st.stx_mask
    return {
        'ino': st.stx_ino,
        'gen': st.stx_gen & 0xffffffff if got & truenas_os.STATX_GEN else 0,
        'size': st.stx_size,
        'mtime': time_of(st.stx_mtime_ns),
        'btime': (time_of(st.stx_btime_ns)
                  if got & truenas_os.STATX_BTIME else (0, 0)),
        'atime': time_of(st.stx_atime_ns),
        'uid': st.stx_uid,
        'gid': st.stx_gid,
        'mode': st.stx_mode,
    }


def file_id(ino, gen):
    """Return the item ID of object ino with generation gen."""
    if gen == 0 or ino >> OBJ_BITS:
        return ino
    return (gen & GEN_MASK) << (OBJ_BITS + 1) | WITH_GEN | ino


def item_parts(item):
    """Return the object number of an item ID and its generation bits,
    or None."""
    if item & WITH_GEN:
        return item & (WITH_GEN - 1), item >> (OBJ_BITS + 1)
    return item, None


def put_stat(w, st):
    w.u64(file_id(st['ino'], st['gen'])).u64(st['volume_id'])
    w.u64(st['ino']).u32(st['gen']).u32(st['uid']).u32(st['gid'])
    w.u32(st['mode']).u64(st['size'])
    for t in ('mtime', 'btime', 'atime'):
        w.i64(st[t][0]).u32(st[t][1])


def read_call(data):
    r = Reader(data)
    vers, xid, op = r.u32(), r.u32(), r.u32()
    if op == HELLO:
        body = {'vers': r.u32()}
    elif op == OPEN:
        body = {'dataset': r.string(), 'share': r.string(),
                'scope': r.string(),
                'query': r.string(), 'uid': r.u32(), 'gid': r.u32(),
                'gids': r.array(r.u32), 'flags': r.u32(),
                'max_results': r.u32(), 'cnids': r.array(r.u64)}
    elif op == FETCH:
        body = {'handle': r.u64(), 'limit': r.u32()}
    elif op == CLOSE:
        body = {'handle': r.u64()}
    else:
        raise ValueError(f'unknown op {op}')
    return vers, xid, op, body


def refusal(xid, status, detail):
    return Writer().u32(RIX_PROTO_VERSION).u32(xid).u32(status).string(
        detail).data()


def answer(xid, op):
    return Writer().u32(RIX_PROTO_VERSION).u32(xid).u32(OK).u32(op)


def relative(path):
    """Return path if it is a valid relative path, else None."""
    if path.startswith('/'):
        return None
    path = path.rstrip('/')
    if path and any(p in ('', '.', '..') for p in path.split('/')):
        return None
    return path


def unescape(field):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), field)


def share_dir(dataset, share):
    """Return the directory of the share path in the dataset, or None."""
    want = '/' + share if share else '/'
    with open('/proc/self/mountinfo') as f:
        for line in f:
            left, right = line.rstrip('\n').split(' - ', 1)
            fields = left.split(' ')
            root, point = unescape(fields[3]), unescape(fields[4])
            if unescape(right.split(' ')[1]) != dataset:
                continue
            if root == '/':
                rest = want[1:]
            elif want == root or want.startswith(root + '/'):
                rest = want[len(root) + 1:]
            else:
                continue
            path = os.path.join(point, rest) if rest else point
            if os.path.isdir(path) and not os.path.islink(path):
                return path
    return None


def matches(top, pattern, fold):
    """Return the paths under top whose name matches pattern. Do not
    follow links or cross mounts."""
    if fold:
        pattern = pattern.lower()
    dev = os.lstat(top).st_dev
    found = []
    for path, dirs, files in os.walk(top):
        dirs[:] = [d for d in dirs
                   if os.lstat(os.path.join(path, d)).st_dev == dev]
        for name in dirs + files:
            if fnmatch.fnmatchcase(name.lower() if fold else name, pattern):
                found.append(os.path.join(path, name))
    return sorted(found)


class Mock:
    def __init__(self, record, max_results, max_page, hello_faults):
        self.record_file = open(record, 'a', buffering=1)
        self.max_results = max_results
        self.max_page = max_page
        self.hello_faults = list(hello_faults)
        self.lock = threading.Lock()
        # Unique also after a restart with the same record file
        self.next_handle = time.time_ns()
        # handle: {'hits': [(path, stat)], 'fault': str, 'fetched': bool}
        self.handles = {}
        self.dropped = set()

    def record(self, **fields):
        with self.lock:
            self.record_file.write(json.dumps(fields, sort_keys=True) + '\n')

    def open(self, xid, body, conn):
        query = body['query']
        fields = dict(op='open', peer_uid=conn.peer_uid, **body)
        share = relative(body['share'])
        root = share_dir(body['dataset'], share) if share is not None \
            else None
        if root is None:
            self.record(status='NO_INDEX', **fields)
            return refusal(xid, NO_INDEX,
                           f'{body["dataset"]}:/{body["share"]} is not served')
        scope = relative(body['scope'])
        top = os.path.join(root, scope) if scope else root
        if scope is None or not os.path.isdir(top):
            self.record(status='BAD_SCOPE', **fields)
            return refusal(xid, BAD_SCOPE,
                           f'{body["scope"]} is not under the share')
        m = PATTERN.search(query)
        pattern, mods = (m.group(1), m.group(2)) if m else (None, '')
        fault, rest = None, pattern
        f = FAULT.match(pattern or '')
        if f:
            fault, rest = f.group(1), f.group(2)
        extra = []
        if fault in REFUSED:
            self.record(status=STATUS_NAMES[REFUSED[fault]], **fields)
            return refusal(xid, REFUSED[fault], 'the mock refuses this query')
        if fault == 'garbage':
            self.record(status='GARBAGE', **fields)
            return b'\xff\xff\xff'
        if fault == 'op':
            self.record(status='OP', **fields)
            return answer(xid, FETCH).u32(0).u32(0).data()
        if fault == 'huge':
            self.record(status='HUGE', **fields)
            raise Huge()
        if fault == 'drop':
            with self.lock:
                first = query not in self.dropped
                self.dropped.add(query)
            if first:
                self.record(status='DROPPED', **fields)
                raise Dropped()
        if fault == 'absolute':
            extra = [root + '/absolute.txt']
        elif fault == 'dotdot':
            extra = ['a/../escape.txt']
        elif fault == 'empty':
            extra = ['a//empty.txt']
        elif fault == 'longpath':
            extra = ['l' * 1100]
        elif fault == 'root':
            extra = ['']
        found = matches(top, rest, 'c' in mods) if rest else []
        paths = extra + [os.path.relpath(p, root) for p in found]
        if body['cnids']:
            want = [item_parts(item) for item in body['cnids']]

            def named(p):
                full = os.path.join(root, p)
                if not os.path.lexists(full):
                    return False
                st = statx(full)
                return any(st['ino'] == ino and
                           (gen is None or st['gen'] & GEN_MASK == gen)
                           for ino, gen in want)
            paths = [p for p in paths if named(p)]
        cap = min(body['max_results'] or self.max_results,
                  self.max_results)
        stat_of_root = statx(root)
        volume_id = os.statvfs(root).f_fsid
        hits = []
        for p in paths[:cap]:
            st = None
            if body['flags'] & RIX_OPEN_WANT_STAT and fault != 'nostat':
                full = os.path.join(root, p)
                st = statx(full) if os.path.lexists(full) else stat_of_root
                st = dict(st, volume_id=volume_id)
            hits.append((p, st))
        with self.lock:
            handle = self.next_handle
            self.next_handle += 1
            self.handles[handle] = {'hits': hits, 'fault': fault,
                                    'fetched': False}
            conn.handles.add(handle)
        self.record(status='OK', handle=handle, ready=len(hits),
                    truncated=len(paths) > cap, **fields)
        out = answer(xid, OPEN).u64(handle).u32(len(hits)).u32(
            1 if len(paths) > cap else 0).data()
        if fault == 'xid':
            out = out[:4] + struct.pack('>I', (xid + 1) & 0xffffffff) + \
                out[8:]
        time.sleep(DELAYED.get(fault, 0))
        return out

    def fetch(self, xid, body, conn):
        handle = body['handle']
        with self.lock:
            h = self.handles.get(handle) if handle in conn.handles else None
            first = h is not None and not h['fetched']
            if h is not None:
                h['fetched'] = True
            if first and h['fault'] == 'badhandle':
                del self.handles[handle]
                conn.handles.discard(handle)
                h = None
            if h is not None and not (first and h['fault'] == 'dropfetch'):
                limit = min(body['limit'] or self.max_page, self.max_page)
                page, h['hits'] = h['hits'][:limit], h['hits'][limit:]
                more = bool(h['hits'])
        if h is None:
            self.record(op='fetch', status='BAD_HANDLE', **body)
            return refusal(xid, BAD_HANDLE, f'no handle {handle}')
        if first and h['fault'] == 'dropfetch':
            self.record(op='fetch', status='DROPPED', **body)
            raise Dropped()
        self.record(op='fetch', status='OK', returned=len(page), more=more,
                    **body)
        w = answer(xid, FETCH).u32(len(page))
        for path, st in page:
            w.string(path)
            if st is None:
                w.u32(0)
            else:
                w.u32(1)
                put_stat(w, st)
        return w.u32(1 if more else 0).data()

    def close(self, xid, body, conn):
        with self.lock:
            known = body['handle'] in conn.handles and \
                self.handles.pop(body['handle'], None) is not None
            conn.handles.discard(body['handle'])
        self.record(op='close', status='OK' if known else 'BAD_HANDLE',
                    **body)
        if not known:
            return refusal(xid, BAD_HANDLE, f'no handle {body["handle"]}')
        return answer(xid, CLOSE).data()

    def call(self, data, conn):
        vers, xid, op, body = read_call(data)
        if vers != RIX_PROTO_VERSION:
            self.record(op='call', status='BAD_VERSION', vers=vers)
            return refusal(xid, BAD_VERSION, f'version {vers}')
        if op == HELLO:
            with self.lock:
                fault = self.hello_faults.pop(0) if self.hello_faults \
                    else None
            self.record(op='hello', peer_uid=conn.peer_uid, fault=fault,
                        **body)
            if fault == 'refuse':
                return refusal(xid, BAD_VERSION, 'the mock refuses hello')
            if fault == 'drop':
                raise Dropped()
            vers = 2 if fault == 'version' else RIX_PROTO_VERSION
            return answer(xid, HELLO).u32(vers).u32(self.max_results).u32(
                self.max_page).u32(60).data()
        if op == OPEN:
            return self.open(xid, body, conn)
        if op == FETCH:
            return self.fetch(xid, body, conn)
        return self.close(xid, body, conn)

    def forget(self, conn):
        """Forget the handles of a closed connection."""
        with self.lock:
            for handle in conn.handles:
                self.handles.pop(handle, None)
            conn.handles.clear()


def read_exactly(sock, n):
    out = b''
    while len(out) < n:
        try:
            chunk = sock.recv(n - len(out))
        except OSError:
            return None
        if not chunk:
            return None
        out += chunk
    return out


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize('3i'))
        conn = Conn(struct.unpack('3i', creds)[1])
        try:
            self.serve(sock, conn, self.server.mock)
        finally:
            self.server.mock.forget(conn)

    def serve(self, sock, conn, mock):
        while True:
            head = read_exactly(sock, 4)
            if head is None:
                return
            n = struct.unpack('>I', head)[0]
            if n > RIX_MAX_FRAME:
                return
            data = read_exactly(sock, n)
            if data is None:
                return
            try:
                out = mock.call(data, conn)
                record = struct.pack('>I', len(out)) + out
            except Dropped:
                return
            except Huge:
                record = struct.pack('>I', RIX_MAX_FRAME + 1)
            except Exception as e:
                mock.record(op='error', error=repr(e))
                return
            try:
                sock.sendall(record)
            except OSError:
                return


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--socket', required=True)
    ap.add_argument('--record', required=True)
    ap.add_argument('--max-results', type=int, default=1000)
    ap.add_argument('--max-page', type=int, default=1000)
    ap.add_argument('--hello-faults', default='')
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.socket) or '.', exist_ok=True)
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    with Server(args.socket, Handler) as server:
        server.mock = Mock(args.record, args.max_results, args.max_page,
                           [f for f in args.hello_faults.split(',') if f])
        print(f'truesearch-mock: serving on {args.socket}', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    sys.exit(main())
