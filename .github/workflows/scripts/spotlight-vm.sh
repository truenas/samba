#!/usr/bin/env bash

######################################################################
# Test the truesearch Spotlight backend in the VM, as root. truesearchd
# is closed source, so truesearch-mock.py replaces it. The mock reads the
# files of the share, records the calls of Samba and injects faults (see
# its docstring). It needs truenas_os (python3-truenas-pyos).
# qemu-4.7-spotlight.sh installs it and runs this script.
#
# The checks:
#   * The backend loads. Results are relative to the share.
#   * RIX_OPEN: the dataset and share path, the relative scope, the query,
#     the session identity, the flags (hide unreadable is always set), max
#     results, a root peer.
#   * Paging, "truesearch:max results", a daemon page of 7.
#   * The share check runs first: "invalid users", the share ACL, the
#     guest rules, that the user can reach the share root, and the share's
#     "hosts allow"/"hosts deny".
#   * Share paths: a subdirectory, "//", ".", "..", a trailing slash, a
#     link, a path that does not exist.
#   * Hit paths that Samba must refuse or drop.
#   * No results and no error: no match, an unknown scope, no index.
#   * Daemon faults: refusals, bad replies, dropped connections, a lost
#     handle, a timeout, RIX_HELLO faults, a restart. The search fails
#     and the next search works.
#   * Item IDs are the SMB FileIds and restrict a search
#     (kMDQueryItemArray, mdsearch --item-ids). truesearchd gets them as
#     the client sent them.
#   * The volume UUID of a share holds the fsid of the share path.
#   * With ZFS: the FileIds of a child dataset in the share's pool and in
#     another pool.
#   * One mdssvc context (Python mdscli): queries closed during a call
#     or in the queue, a context closed during a call, five queries at
#     the same time, a broken connection during an open query.
#
# To run outside the VM, set SPOTLIGHT_DATASET (empty: no ZFS),
# SPOTLIGHT_DIR, SPOTLIGHT_WORK, SPOTLIGHT_SOCKET, SPOTLIGHT_CREDS,
# SPOTLIGHT_PORT, SPOTLIGHT_LOGDIR, SPOTLIGHT_INCLUDE (included at the end
# of [global]), SMBD, MDSEARCH, TESTPARM, SHARESEC, SMBCLIENT_CFLAGS (for
# the FileId reader) and PYTHONPATH (for samba.samba3.mdscli).
######################################################################

set -eu

DATASET="${SPOTLIGHT_DATASET-tank/spotlight}"
# A second pool, on a file, for section 14
OTHER_POOL=spotlight-other
DIR="${SPOTLIGHT_DIR:-/tank/spotlight}"
WORK="${SPOTLIGHT_WORK:-/var/tmp/spotlight}"
SOCKET="${SPOTLIGHT_SOCKET:-/run/truesearchd/mdssvc.sock}"
CREDS="${SPOTLIGHT_CREDS:-smbtest%testpass123}"
PORT="${SPOTLIGHT_PORT:-445}"
LOGDIR="${SPOTLIGHT_LOGDIR:-/var/log/samba4}"
SMBD="${SMBD:-/usr/sbin/smbd}"
MDSEARCH="${MDSEARCH:-/usr/bin/mdsearch}"
TESTPARM="${TESTPARM:-/usr/bin/testparm}"
SHARESEC="${SHARESEC:-/usr/bin/sharesec}"
SMBCLIENT_CFLAGS="${SMBCLIENT_CFLAGS:--I/usr/include/samba-4.0 -lsmbclient}"
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${CREDS%%%*}"
CONF="$WORK/smb.conf"
RECORD="$WORK/record.jsonl"
# A second mock with RIX_HELLO faults and a page of 7
SMALL="$WORK/small.sock"
SMALL_RECORD="$WORK/record-small.jsonl"
RPCLOG="$LOGDIR/log.rpcd_mdssvc"
Q='kMDItemFSName=="*report*"cd'
PASS=0
FAILED=0

# Number of RIX_OPEN records the mock has seen so far.
opens_seen() { records "r['op'] == 'open'" | wc -l; }

ok() { PASS=$((PASS + 1)); echo "PASS  $1: $2"; }
bad() { FAILED=$((FAILED + 1)); echo "FAIL  $1: $2"; }

# Search. Print the sorted paths or the error. $1 share, $2 query, then
# mdsearch options.
search() {
	local share=$1 query=$2
	shift 2
	timeout 120 "$MDSEARCH" -s "$CONF" -U "$CREDS" "$@" \
		127.0.0.1 "$share" "$query" 2>&1 | sort
}

# Print the mock records for which the Python condition $1 on r is true.
records() {
	python3 -c '
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line)
    if eval(sys.argv[2]):
        print(json.dumps(r, sort_keys=True))
' "$RECORD" "$1"
}

# Print field $2 of the last record that matches condition $1.
last() {
	records "$1" | tail -1 | python3 -c '
import json, sys
line = sys.stdin.read().strip()
print(json.loads(line).get(sys.argv[1]) if line else "")' "$2"
}

# Print "path 0xid" for the item IDs in the rpcd_mdssvc log (the inode
# map at rpc_srv:10). $1 share, $2 log offset.
item_ids() {
	tail -c +$(($2 + 1)) "$RPCLOG" |
		sed -n "s#.*deleted \[0x\([0-9a-f]*\)\] \[/$1/#[\1] [#p" |
		sed -n 's#^\[\([^]]*\)\] \[\(.*\)\].*#\2 0x\1#p' |
		sort -u
}

# Print the dataset of directory $1 and its path in the dataset, as Samba
# finds them. The path of the dataset root is "".
place_of() {
	local real src fsroot target rest
	real=$(realpath "$1")
	src=$(findmnt -n --nofsroot -o SOURCE -T "$real")
	fsroot=$(findmnt -n -o FSROOT -T "$real")
	target=$(findmnt -n -o TARGET -T "$real")
	rest=${real#"$target"}
	rest=${rest#/}
	fsroot=${fsroot#/}
	echo "$src ${fsroot}${fsroot:+${rest:+/}}$rest"
}

# Print "path 0xid" for the SMB FileIds of the entries of a directory.
# $1 share, $2 directory.
file_ids() {
	SMB_USER="$USER_NAME" SMB_PASS="${CREDS#*%}" HOME="$WORK" \
		"$WORK/smb-fileid" "smb://127.0.0.1:$PORT/$1${2:+/$2}" |
		sed "s#^smb://127.0.0.1:$PORT/$1/##" | sort
}

# Start a mock. $1 socket, $2 record file, then mock options.
start_mock() {
	local sock=$1 record=$2
	shift 2
	(setsid python3 -I "$HERE/truesearch-mock.py" --socket "$sock" \
		--record "$record" "$@" >> "$WORK/mock.log" 2>&1 < /dev/null &
	 echo $! > "$WORK/$(basename "$sock").pid")
	for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done
	[ -S "$sock" ] || { cat "$WORK/mock.log"; echo "ERROR: no mock"; exit 1; }
}

stop_mock() {
	local pidfile
	pidfile="$WORK/$(basename "$1").pid"
	if [ -f "$pidfile" ]; then
		kill -TERM "$(cat "$pidfile")" 2> /dev/null || true
		rm -f "$pidfile" "$1"
	fi
}

stop() {
	local pid
	pid="$(cat "$WORK/run/smbd.pid" 2> /dev/null || true)"
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2> /dev/null || true
		for _ in $(seq 1 50); do
			kill -0 "$pid" 2> /dev/null || break
			sleep 0.2
		done
	fi
	# samba-dcerpcd and its rpcd_* processes for this configuration
	pkill -TERM -f -- "$CONF" 2> /dev/null || true
	stop_mock "$SOCKET"
	stop_mock "$SMALL"
}

# Print the rpcd_mdssvc log from offset $1.
log_from() {
	tail -c +$(($1 + 1)) "$RPCLOG"
}

echo "=========================================="
echo "Spotlight truesearch backend: setup"
echo "=========================================="
stop
rm -rf "$WORK"
mkdir -p "$WORK/run" "$LOGDIR"
if [ -n "$DATASET" ]; then
	# Left by an earlier run of section 14
	zpool destroy "$OTHER_POOL" 2> /dev/null || true
	zfs destroy "$DATASET/child" 2> /dev/null || true
	zfs list "$DATASET" > /dev/null 2>&1 ||
		zfs create -o mountpoint="$DIR" "$DATASET"
fi
rm -rf "${DIR:?}"/*
mkdir -p "$DIR/notes" "$DIR/deep/er" "$DIR/bulk"
echo pdf > "$DIR/report-2024.pdf"
echo draft > "$DIR/notes/report-draft.txt"
echo minutes > "$DIR/notes/minutes.txt"
echo final > "$DIR/deep/er/report-final.txt"
for i in $(seq -w 0 259); do echo "$i" > "$DIR/bulk/bulk-file-$i.txt"; done
chmod -R a+rX "$DIR"
# A share root under a directory the user cannot traverse
mkdir -p "$WORK/locked/inside"
echo locked > "$WORK/locked/inside/report-locked.txt"
chmod 700 "$WORK/locked"
# The path of IPC$, for mdsearch
mkdir -p /var/empty

# In the VM: stop the smbd of the earlier steps and its RPC daemons. They
# must not answer the pipes of this smbd with their configuration.
if [ -n "$DATASET" ]; then
	systemctl stop smbd nmbd 2> /dev/null || true
	DAEMONS='smbd|samba-dcerpcd|rpcd_[a-z_]+'
	pkill -TERM -x "$DAEMONS" 2> /dev/null || true
	for _ in $(seq 1 50); do
		pgrep -x "$DAEMONS" > /dev/null || break
		sleep 0.2
	done
	pkill -KILL -x "$DAEMONS" 2> /dev/null || true
fi

SOCKET_OPT=""
[ "$SOCKET" = /run/truesearchd/mdssvc.sock ] ||
	SOCKET_OPT="truesearch:socket = $SOCKET"
cat > "$CONF" <<CONF
[global]
    workgroup = WORKGROUP
    netbios name = SPOTLIGHTCI
    security = user
    passdb backend = tdbsam
    load printers = no
    printing = bsd
    disable spoolss = yes
    smb ports = $PORT
    pid directory = $WORK/run
    log level = 1 rpc_srv:10
    max log size = 0
    spotlight = yes
    spotlight backend = truesearch
    $SOCKET_OPT
    ${SPOTLIGHT_INCLUDE:+include = $SPOTLIGHT_INCLUDE}
    # After the include: an unknown user becomes guest (section 12)
    map to guest = Bad User
# A share on a dataset, as middleware writes it
[ts]
    path = $DIR
    read only = yes
    vfs objects = ixnas zfs_core
[ts-plain]
    path = $DIR
    read only = yes
[ts-sub]
    path = $DIR/notes
    read only = yes
    vfs objects = ixnas zfs_core
[ts-hide]
    path = $DIR/deep
    read only = yes
    hide unreadable = yes
[ts-max]
    path = $DIR/bulk
    read only = yes
    truesearch:max results = 7
[ts-all]
    path = $DIR/bulk
    read only = yes
    truesearch:max results = 0
[ts-denied]
    path = $DIR/deep/er
    read only = yes
    invalid users = $USER_NAME
# The share ACL allows only BUILTIN\Administrators
[ts-acl]
    path = $DIR/deep/er
    read only = yes
[ts-gone]
    path = $WORK/gone
    read only = yes
# The second mock
[ts-small]
    path = $DIR/bulk
    read only = yes
    truesearch:socket = $SMALL
# Other spellings of a share path
[ts-dslash]
    path = $DIR//notes
    read only = yes
[ts-dot]
    path = $DIR/./notes
    read only = yes
[ts-dotdot]
    path = $DIR/deep/../notes
    read only = yes
[ts-link]
    path = $WORK/link-notes
    read only = yes
[ts-slash]
    path = $DIR/
    read only = yes
# Guests allowed, and guests forced
[ts-guest]
    path = $DIR/notes
    read only = yes
    guest ok = yes
[ts-guestonly]
    path = $DIR/notes
    read only = yes
    guest only = yes
    guest ok = yes
# The share root is under a directory the user cannot traverse
[ts-unreach]
    path = $WORK/locked/inside
    read only = yes
# This host is denied
[ts-hostdeny]
    path = $DIR/notes
    read only = yes
    hosts deny = 127.0.0.1
CONF
ln -sfn "$DIR/notes" "$WORK/link-notes"
"$SHARESEC" -s "$CONF" ts-acl --replace 'S-1-5-32-544:ALLOWED/0x0/FULL' \
	> /dev/null

cat > "$WORK/smb-fileid.c" <<'C'
/* Print the FileId of each entry: st_ino from smbc_readdirplus2(),
 * which comes from FileIdBothDirectoryInformation. */
#include <libsmbclient.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void auth(const char *srv, const char *shr, char *wg, int wglen,
		 char *un, int unlen, char *pw, int pwlen)
{
	snprintf(un, unlen, "%s", getenv("SMB_USER"));
	snprintf(pw, pwlen, "%s", getenv("SMB_PASS"));
}

int main(int argc, char **argv)
{
	const struct libsmb_file_info *fi;
	struct stat st;
	int i, dh;

	if (smbc_init(auth, 0) < 0) {
		perror("smbc_init");
		return 1;
	}
	for (i = 1; i < argc; i++) {
		dh = smbc_opendir(argv[i]);
		if (dh < 0) {
			perror(argv[i]);
			return 1;
		}
		while ((fi = smbc_readdirplus2(dh, &st)) != NULL) {
			if (strcmp(fi->name, ".") == 0 ||
			    strcmp(fi->name, "..") == 0) {
				continue;
			}
			printf("%s/%s 0x%llx\n", argv[i], fi->name,
			       (unsigned long long)st.st_ino);
		}
		smbc_closedir(dh);
	}
	return 0;
}
C
# shellcheck disable=SC2086 # the flags are words
cc -Wno-deprecated-declarations -o "$WORK/smb-fileid" \
	"$WORK/smb-fileid.c" $SMBCLIENT_CFLAGS

start_mock "$SOCKET" "$RECORD"
start_mock "$SMALL" "$SMALL_RECORD" --max-page 7 \
	--hello-faults refuse,version,drop

RPC_START=$(stat -c %s "$RPCLOG" 2> /dev/null || echo 0)
SMBD_START=$(stat -c %s "$LOGDIR/log.smbd" 2> /dev/null || echo 0)
"$SMBD" -D -s "$CONF"
for _ in $(seq 1 150); do
	ss -ltn | grep -q ":$PORT " && break
	sleep 0.2
done
ss -ltn | grep -q ":$PORT " || { echo "ERROR: smbd does not listen"; exit 1; }
trap stop EXIT

echo "=========================================="
echo "Spotlight truesearch backend: checks"
echo "=========================================="

# 1: The backend loads. Results are relative to the share.
"$TESTPARM" -s "$CONF" 2> /dev/null |
	grep -q 'spotlight backend = truesearch' &&
	ok S1a "testparm takes the truesearch backend" ||
	bad S1a "testparm: no truesearch backend"
got=$(search ts "$Q")
want=$(printf '%s\n' deep/er/report-final.txt notes/report-draft.txt \
	report-2024.pdf)
[ "$got" = "$want" ] && ok S1b "a search answers share-relative paths" ||
	bad S1b "$(echo $got)"

# 2: The RIX_OPEN request
read -r DS SH <<< "$(place_of "$DIR")"
# Condition: an open of the share at directory $1 of the tree
at() { echo "r['op'] == 'open' and r['status'] == 'OK' and \
r['dataset'] == '$DS' and r['share'] == '$SH${SH:+${1:+/}}$1'"; }
C=$(at "")
uid=$(id -u "$USER_NAME"); gid=$(id -g "$USER_NAME")
[ -n "$(records "$C")" ] && [ "$(last "$C" scope)" = "" ] &&
	[ "$(last "$C" query)" = "$Q" ] &&
	ok S2a "RIX_OPEN: the share as $DS:/$SH, scope \"\", the query" ||
	bad S2a "dataset/share/scope/query: $(records "r['op'] == 'open'" |
		tail -1)"
[ "$(last "$C" uid)" = "$uid" ] && [ "$(last "$C" gid)" = "$gid" ] &&
	[ "$(last "$C" peer_uid)" = 0 ] &&
	ok S2b "RIX_OPEN: uid $uid gid $gid of the session, from a root peer" ||
	bad S2b "identity: $(records "$C" | tail -1)"
[ "$(last "$C" flags)" = 7 ] && [ "$(last "$C" max_results)" = 100 ] &&
	ok S2c "RIX_OPEN: trim by identity, want stat, hide unreadable; 100" ||
	bad S2c "flags/max: $(records "$C" | tail -1)"
search ts-hide "$Q" > /dev/null
H=$(at deep)
[ "$(last "$H" flags)" = 7 ] &&
	ok S2d "a share that hides unreadable files still asks for it" ||
	bad S2d "flags: $(records "$H" | tail -1)"
got=$(search ts "$Q" -p notes)
[ "$got" = notes/report-draft.txt ] &&
	[ "$(last "$C" scope)" = notes ] &&
	ok S2e "a scope is passed relative to the share's root" ||
	bad S2e "$(echo $got); $(records "$C" | tail -1)"

# 3: Paging and result limits
n=$(search ts-all 'kMDItemFSName=="bulk-file-*"' | grep -c '^bulk-file-')
pages=$(records "r['op'] == 'fetch'" | python3 -c '
import json, sys
print(max(json.loads(l)["limit"] for l in sys.stdin))')
[ "$n" = 260 ] && [ "$pages" -le 50 ] &&
	ok S3a "max results 0: all 260, fetched at most 50 at a time" ||
	bad S3a "$n hits, largest fetch $pages"
n=$(search ts-max 'kMDItemFSName=="bulk-file-*"' | grep -c '^bulk-file-')
[ "$n" = 7 ] && ok S3b "truesearch:max results = 7: 7 hits" || bad S3b "$n hits"
n=$(search ts 'kMDItemFSName=="bulk-file-*"' | grep -c 'bulk-file-')
[ "$n" = 100 ] && ok S3c "by default exactly 100" || bad S3c "$n hits"

# 4: The share check runs before truesearchd
got=$(search ts-denied "$Q")
asked=$(records "$(at deep/er | sed "s/r\['status'\] == 'OK' and //")" |
	wc -l)
! echo "$got" | grep -q report && [ "$asked" = 0 ] &&
	ok S4 "invalid users: refused before truesearchd is asked" ||
	bad S4 "$(echo $got); $asked opens"
start=$(stat -c %s "$RPCLOG")
got=$(search ts-acl "$Q")
asked=$(records "$(at deep/er | sed "s/r\['status'\] == 'OK' and //")" |
	wc -l)
! echo "$got" | grep -q report && [ "$asked" = 0 ] &&
	log_from "$start" | grep -q 'may not read share \[ts-acl\]' &&
	ok S4b "a share ACL that denies the user: refused before truesearchd" ||
	bad S4b "$(echo $got); $asked opens"

# 5: Share paths
got=$(search ts-sub "$Q")
[ "$got" = report-draft.txt ] && [ -n "$(records "$(at notes)")" ] &&
	ok S5 "a share on a subdirectory: its own place, share-relative hits" ||
	bad S5 "$(echo $got)"

# 5b: Other spellings of the same path
before=$(records "$(at notes)" | wc -l)
for share in ts-dslash ts-dot ts-dotdot ts-link; do
	got=$(search $share "$Q")
	[ "$got" = report-draft.txt ] &&
		ok S5b-$share "names the share on notes: $got" ||
		bad S5b-$share "$(echo $got)"
done
after=$(records "$(at notes)" | wc -l)
[ $((after - before)) = 4 ] &&
	ok S5c "each sent as $DS:/$SH${SH:+/}notes" ||
	bad S5c "$((after - before)) of 4 opens named the share by its place"
got=$(search ts-slash "$Q" -p notes)
[ "$got" = notes/report-draft.txt ] && [ "$(last "$C" scope)" = notes ] &&
	ok S5d "a share path ending in a slash: the share, the scope relative" ||
	bad S5d "$(echo $got); $(records "$C" | tail -1)"

# 5e: A share path that does not exist
start=$(stat -c %s "$RPCLOG")
got=$(search ts-gone "$Q")
! echo "$got" | grep -q report &&
	log_from "$start" | grep -q "reach share path \[$WORK/gone\]: No such" &&
	ok S5e "a share whose path is gone: refused, logged" ||
	bad S5e "$(echo $got)"

# 6: Bad hits, a refused query, a dropped connection
got=$(search ts 'kMDItemFSName=="mockfault-absolute-*report*"cd')
! echo "$got" | grep -q 'absolute\|report' &&
	ok S6a "an absolute hit path fails the search" || bad S6a "$(echo $got)"
got=$(search ts 'kMDItemFSName=="mockfault-dotdot-*report*"cd')
! echo "$got" | grep -q 'escape\|report' &&
	ok S6b "a hit path with .. fails the search" || bad S6b "$(echo $got)"
got=$(search ts 'kMDItemFSName=="mockfault-empty-*report*"cd')
! echo "$got" | grep -q 'empty\|report' &&
	ok S6c "a hit path with an empty component fails the search" ||
	bad S6c "$(echo $got)"
got=$(search ts 'kMDItemFSName=="mockfault-longpath-*report*"cd')
[ "$got" = "$want" ] &&
	ok S6d "a hit path past 1,024 bytes is dropped, its page served" ||
	bad S6d "$(echo $got | head -c 200)"
got=$(search ts 'kMDItemFSName=="mockfault-badquery-*"')
! echo "$got" | grep -q report && ok S6e "RIX_BAD_QUERY fails the search" ||
	bad S6e "$(echo $got)"
got=$(search ts 'kMDItemFSName=="mockfault-drop-*report*"cd')
opens=$(records "r['op'] == 'open' and 'mockfault-drop-' in r['query']" |
	wc -l)
[ "$got" = "$want" ] && [ "$opens" = 2 ] &&
	ok S6f "a connection dropped under RIX_OPEN: opened again, answered" ||
	bad S6f "$(echo $got); $opens opens"
got=$(search ts 'kMDItemFSName=="mockfault-root-*report*"cd')
[ "$got" = "$want" ] &&
	ok S6g "the share's root as a hit is dropped, its page served" ||
	bad S6g "$(echo $got)"

# 6h: No results is not an error
got=$(search ts 'kMDItemFSName=="nothing-is-named-so"')
[ -z "$got" ] && [ "$(last "r['op'] == 'open'" ready)" = 0 ] &&
	ok S6h-none "a search that matches nothing: no hit, no error" ||
	bad S6h-none "$(echo $got)"
got=$(search ts "$Q" -p no-such-dir)
[ -z "$got" ] && [ "$(last "r['op'] == 'open'" status)" = BAD_SCOPE ] &&
	ok S6h-scope "a scope truesearchd does not know: no hit, no error" ||
	bad S6h-scope "$(echo $got)"
got=$(search ts 'kMDItemFSName=="mockfault-noindex-*"')
[ -z "$got" ] && [ "$(last "r['op'] == 'open'" status)" = NO_INDEX ] &&
	ok S6h-noindex "RIX_NO_INDEX: no hit, no error" ||
	bad S6h-noindex "$(echo $got)"

# 6i: Refusals and bad replies fail the search
while read -r fault what; do
	got=$(search ts "kMDItemFSName==\"mockfault-$fault-*report*\"cd")
	asked=$(records "r['op'] == 'open' and 'mockfault-$fault-' in r['query']" |
		wc -l)
	! echo "$got" | grep -q report && [ "$asked" -ge 1 ] &&
		ok "S6i-$fault" "$what fails the search" ||
		bad "S6i-$fault" "$asked opens; $(echo $got)"
done <<'FAULTS'
busy RIX_BUSY
garbage a reply that is not XDR
xid a reply with another xid
op a reply that answers another op
huge a reply longer than a record may be
nostat a hit without the stat asked for
badhandle RIX_BAD_HANDLE for a fetch
dropfetch a connection dropped under RIX_FETCH
FAULTS

# 6j: A call without a reply for 20 s
start=$(stat -c %s "$RPCLOG")
got=$(search ts 'kMDItemFSName=="mockfault-stall-*report*"cd')
! echo "$got" | grep -q report &&
	log_from "$start" | grep -q 'RIX_OPEN: Connection timed out' &&
	ok S6j "a call unanswered for 20 seconds fails the search" ||
	bad S6j "$(echo $got)"
[ "$(search ts "$Q")" = "$want" ] &&
	ok S6k "the next search is answered" ||
	bad S6k "no answer after the faults"

# 7: Item IDs are the SMB FileIds
for share in ts ts-plain; do
	start=$(stat -c %s "$RPCLOG")
	search "$share" "$Q" > /dev/null
	sleep 1
	ids=$(item_ids "$share" "$start")
	fids=$( (file_ids "$share"; file_ids "$share" notes;
		file_ids "$share" deep/er) | grep -F -f <(echo "$want") | sort)
	[ -n "$ids" ] && [ "$ids" = "$fids" ] &&
		ok S7-$share "item IDs equal the SMB FileIds: $(echo $ids)" ||
		bad S7-$share "item IDs [$(echo $ids)] FileIds [$(echo $fids)]"
done

# 7b: Item IDs from the client restrict the search. truesearchd gets them
# as the client sent them.
for share in ts ts-plain; do
	id=$(file_ids "$share" | sed -n 's#^report-2024.pdf ##p')
	got=$(search "$share" "$Q" --item-ids "$id")
	cnids=$(last "r['op'] == 'open' and r['cnids']" cnids)
	[ "$got" = report-2024.pdf ] && [ "$cnids" = "[$(printf '%u' "$id")]" ] &&
		ok S7b-$share "item ID $id: report-2024.pdf only, sent unchanged" ||
		bad S7b-$share "$(echo $got); cnids $cnids"
done
# On a zfs_core share, the item ID includes the generation. truesearchd
# finds no file for the ID under another generation.
id=$(file_ids ts | sed -n 's#^report-2024.pdf ##p')
other=$(printf '0x%x' $((id ^ (1 << 40))))
got=$(search ts "$Q" --item-ids "$other")
ready=$(last "r['op'] == 'open'" ready)
[ -z "$got" ] && [ "$ready" = 0 ] &&
	ok S7c "the item ID of the file under another generation: no hit" ||
	bad S7c "$other: $(echo $got); ready $ready"

# 8: truesearchd stops, then starts again
stop_mock "$SOCKET"
start=$(stat -c %s "$RPCLOG")
got=$(search ts "$Q")
! echo "$got" | grep -q report &&
	log_from "$start" | grep -q "truesearchd at $SOCKET: connect: " &&
	ok S8a "truesearchd gone: the search fails, logged" ||
	bad S8a "$(echo $got)"
start_mock "$SOCKET" "$RECORD"
[ "$(search ts "$Q")" = "$want" ] &&
	ok S8b "truesearchd back: the next search is answered" ||
	bad S8b "no answer"

# 9: RIX_HELLO faults, then pages of 7
B='kMDItemFSName=="bulk-file-*"'
start=$(stat -c %s "$RPCLOG")
got=$(search ts-small "$B")
! echo "$got" | grep -q bulk-file &&
	log_from "$start" | grep -q 'refused RIX_HELLO: RIX_BAD_VERSION' &&
	ok S9a "a refused RIX_HELLO fails the search" || bad S9a "$(echo $got)"
start=$(stat -c %s "$RPCLOG")
got=$(search ts-small "$B")
! echo "$got" | grep -q bulk-file &&
	log_from "$start" | grep -q "at $SMALL: bad version 2 or page 7" &&
	ok S9b "a welcome of another version fails the search" ||
	bad S9b "$(echo $got)"
start=$(stat -c %s "$RPCLOG")
got=$(search ts-small "$B")
! echo "$got" | grep -q bulk-file &&
	log_from "$start" | grep -q "at $SMALL: RIX_HELLO: " &&
	ok S9c "a connection dropped under RIX_HELLO fails the search" ||
	bad S9c "$(echo $got)"
n=$(search ts-small "$B" | grep -c '^bulk-file-')
pages=$(RECORD=$SMALL_RECORD records "r['op'] == 'fetch'" | python3 -c '
import json, sys
print(max(json.loads(l)["limit"] for l in sys.stdin))')
[ "$n" = 100 ] && [ "$pages" = 7 ] &&
	ok S9d "a daemon page of 7: all 100, fetched 7 at a time" ||
	bad S9d "$n hits, largest fetch $pages"

# 10: One mdssvc context (samba.samba3.mdscli)
cat > "$WORK/mdscli-checks.py" <<'PY'
"""Checks on one mdssvc context. Print "ok|bad ID text" lines, then
"done"."""
import json
import sys
import time

from samba import param
from samba.credentials import Credentials
from samba.dcerpc import mdssvc
from samba.samba3 import mdscli

conf, user_pass, record = sys.argv[1:4]
lp = param.LoadParm()
lp.load(conf)
creds = Credentials()
creds.guess(lp)
user, _, password = user_pass.partition('%')
creds.set_username(user)
creds.set_password(password)
REPORTS = ['deep/er/report-final.txt', 'notes/report-draft.txt',
           'report-2024.pdf']


def check(good, name, text, why):
    print(f'{"ok" if good else "bad"} {name} {text}' +
          ('' if good else f': {why}'), flush=True)


def records(**want):
    with open(record) as f:
        rs = [json.loads(line) for line in f]
    return [r for r in rs if all(r.get(k) == v for k, v in want.items())]


def released(query):
    """Return true if Samba closed all handles of the opens of query."""
    handles = {r['handle'] for r in records(op='open', query=query,
                                            status='OK')}
    closed = {r['handle'] for r in records(op='close', status='OK')}
    return bool(handles) and handles <= closed


class Context:
    """An mdssvc context on the share ts."""

    def __init__(self):
        self.pipe = mdssvc.mdssvc('ncacn_np:127.0.0.1[/pipe/mdssvc]', lp,
                                  creds)
        self.conn = mdscli.conn(self.pipe, 'ts', '/foo')
        self.path = self.conn.sharepath()

    def open(self, query):
        return self.conn.search(self.pipe, query, self.path)

    def drain(self, s):
        out = []
        while True:
            got = s.get_results(self.pipe)
            if not got:
                return sorted(out)
            out += got

    def search(self, query):
        s = self.open(query)
        out = self.drain(s)
        s.close(self.pipe)
        return out

    def ready(self):
        """Connect to truesearchd and wait until no call is in progress."""
        got = self.search('kMDItemFSName=="*minutes*"cd')
        time.sleep(0.5)
        return got == ['notes/minutes.txt']


# 10a: Close a query during its RIX_OPEN. Samba must release the handle.
# 10b: Close a query in the queue. Samba must not send it.
ctx = Context()
ready = ctx.ready()
slow = 'kMDItemFSName=="mockfault-slow-*report*"cd'
waits = 'kMDItemFSName=="minutes*"'
a = ctx.open(slow)
b = ctx.open(waits)
b.close(ctx.pipe)
a.close(ctx.pipe)
time.sleep(4)
check(ready and released(slow), 'S10a',
      'a query closed while its RIX_OPEN is out: its handle is released',
      f'opens {records(op="open", query=slow)}')
check(ready and not records(op='open', query=waits), 'S10b',
      'a query closed while it waits in line is never sent',
      f'opens {records(op="open", query=waits)}')
ctx.conn.disconnect(ctx.pipe)

# 10c: Close the context during a RIX_OPEN
ctx = Context()
ready = ctx.ready()
ctx.open('kMDItemFSName=="mockfault-slow-*draft*"cd')
ctx.conn.disconnect(ctx.pipe)
got = Context().search('kMDItemFSName=="*report*"cd')
check(ready and got == REPORTS, 'S10c',
      'a context closed while its RIX_OPEN is out; the next one answers',
      f'{got}')

# 10d: Five queries at the same time, as Finder opens them while the user
# types. Fetch the newest first.
ctx = Context()
queries = ['kMDItemFSName=="r*"', 'kMDItemFSName=="re*"',
           'kMDItemFSName=="rep*"', 'kMDItemFSName=="bulk-file-0*"',
           'kMDItemFSName=="report*"']
searches = [ctx.open(q) for q in queries]
got = {q: ctx.drain(s) for q, s in reversed(list(zip(queries, searches)))}
for s in searches:
    s.close(ctx.pipe)
time.sleep(1)
check(all(got[q] == REPORTS for q in queries[:3] + queries[4:]) and
      len(got[queries[3]]) == 100 and all(released(q) for q in queries),
      'S10d', 'five queries at once: each answered, every handle released',
      f'{ {q: len(v) for q, v in got.items()} }')
ctx.conn.disconnect(ctx.pipe)

# 10e: The connection breaks while a query has a full page. Samba must
# not use the old handle again. The next search uses a new connection.
ctx = Context()
held = 'kMDItemFSName=="bulk-file-1*"'
a = ctx.open(held)
time.sleep(1)
ctx.open('kMDItemFSName=="mockfault-dropfetch-*report*"cd')
time.sleep(1)
first = a.get_results(ctx.pipe)
try:
    rest = ctx.drain(a)
except Exception as e:
    rest = e
opened = records(op='open', query=held, status='OK')
fetches = records(op='fetch', handle=opened[0]['handle']) if opened else []
got = ctx.search('kMDItemFSName=="*report*"cd')
check(len(first) == 50 and len(fetches) == 1 and got == REPORTS, 'S10e',
      'a connection lost under an open query: its handle is not used '
      'again, the context answers',
      f'{len(first)} hits first, then {rest!r:.60}; {len(fetches)} '
      f'fetches; then {got}')
ctx.conn.disconnect(ctx.pipe)
print('done', flush=True)
PY
out=$(python3 "$WORK/mdscli-checks.py" "$CONF" "$CREDS" "$RECORD" 2>&1) ||
	true
while read -r verdict name text; do
	case $verdict in
	ok|bad) "$verdict" "$name" "$text" ;;
	"done") ;;
	*) echo "      $verdict $name $text" ;;
	esac
done <<< "$out"
[ "$(echo "$out" | tail -1)" = "done" ] ||
	bad S10 "the checks stopped: $(echo "$out" | tail -1)"

# 12: Access checks
# A guest session, refused unless the share allows guests.
GUEST='%'  # an anonymous null session: guest-level, unsigned
start=$(stat -c %s "$RPCLOG")
before=$(opens_seen)
got=$(search ts "$Q" -U "$GUEST")
asked=$(($(opens_seen) - before))
! echo "$got" | grep -q report && [ "$asked" = 0 ] &&
	log_from "$start" | grep -q 'guest session may not search share \[ts\]' &&
	ok S12a "a guest session is refused on a share without guest ok" ||
	bad S12a "$(echo $got); $asked opens"
got=$(search ts-guest "$Q" -U "$GUEST")
[ "$got" = report-draft.txt ] &&
	ok S12b "a guest session is served on a share with guest ok" ||
	bad S12b "$(echo $got)"
start=$(stat -c %s "$RPCLOG")
before=$(opens_seen)
got=$(search ts-guestonly "$Q")
asked=$(($(opens_seen) - before))
! echo "$got" | grep -q report && [ "$asked" = 0 ] &&
	log_from "$start" | grep -q 'share \[ts-guestonly\] is guest only' &&
	ok S12c "a guest only share is refused: the search cannot become guest" ||
	bad S12c "$(echo $got); $asked opens"

# The user cannot traverse the directory above the share root.
start=$(stat -c %s "$RPCLOG")
before=$(opens_seen)
got=$(search ts-unreach "$Q")
asked=$(($(opens_seen) - before))
! echo "$got" | grep -q report && [ "$asked" = 0 ] &&
	log_from "$start" | grep -q 'cannot reach share path' &&
	ok S12d "a share root the user cannot reach: refused before truesearchd" ||
	bad S12d "$(echo $got); $asked opens"

# "hosts deny" names this host.
start=$(stat -c %s "$RPCLOG")
before=$(opens_seen)
got=$(search ts-hostdeny "$Q")
asked=$(($(opens_seen) - before))
! echo "$got" | grep -q report && [ "$asked" = 0 ] &&
	log_from "$start" | grep -q 'hosts allow/deny' &&
	ok S12e "hosts deny: the search is refused before truesearchd" ||
	bad S12e "$(echo $got); $asked opens"

# 13: The volume UUID of a share is a UUID version 8 that holds the fsid of
# the share path. The shares on one file system have one UUID.
volume_uuid() {
	log_from "$2" |
		sed -n "s#.*share \[$1\] volume uuid \([0-9a-f-]*\).*#\1#p" |
		tail -1
}
want_uuid=$(python3 -c '
import os, sys
b = bytearray(b"TNMDSV\x80\x00")
b += os.statvfs(sys.argv[1]).f_fsid.to_bytes(8, "big")
b[8] = b[8] & 0x3f | 0x80
h = b.hex()
print("-".join((h[:8], h[8:12], h[12:16], h[16:20], h[20:])))' "$DIR")
uuids=
for share in ts ts-sub ts-link; do
	start=$(stat -c %s "$RPCLOG")
	search "$share" "$Q" > /dev/null
	uuids="$uuids $(volume_uuid "$share" "$start")"
done
[ "$uuids" = " $want_uuid $want_uuid $want_uuid" ] &&
	ok S13 "ts, ts-sub, ts-link: volume UUID $want_uuid" ||
	bad S13 "want $want_uuid, got$uuids"

# 14: With ZFS, the FileIds of a child dataset: objsetid << 40 | ino in
# the share's pool. An objsetid is unique only in its pool, so in another
# pool: 1 << 63 | (fsid & 0x7fffff) << 40 | ino.
if [ -n "$DATASET" ]; then
	if zfs create "$DATASET/child" &&
	   truncate -s 128M "$WORK/other-pool.img" &&
	   zpool create -m none "$OTHER_POOL" "$WORK/other-pool.img" &&
	   zfs create -o mountpoint="$DIR/other" "$OTHER_POOL/data"; then
		echo child > "$DIR/child/report-child.txt"
		echo other > "$DIR/other/report-other.txt"
		chmod -R a+rX "$DIR/child" "$DIR/other"
		objset=$(zfs get -Hp -o value objsetid "$DATASET/child" || true)
		ino=$(stat -c %i "$DIR/child/report-child.txt")
		want=$(printf '0x%x' $(((${objset:-0} << 40) | ino)))
		got=$(file_ids ts child |
			sed -n 's#^child/report-child.txt ##p')
		[ -n "$objset" ] && [ "$got" = "$want" ] &&
			ok S14a "a child in the share's pool: objsetid << 40 | ino" ||
			bad S14a "FileId $got, want $want"
		fsid=$(python3 -c 'import os, sys
print(os.statvfs(sys.argv[1]).f_fsid)' "$DIR/other")
		ino=$(stat -c %i "$DIR/other/report-other.txt")
		want=$(printf '0x%x' \
			$(((1 << 63) | ((fsid & 0x7fffff) << 40) | ino)))
		got=$(file_ids ts other |
			sed -n 's#^other/report-other.txt ##p')
		[ "$got" = "$want" ] &&
			ok S14b "a child in another pool: bit 63, fsid bits, ino" ||
			bad S14b "FileId $got, want $want"
	else
		bad S14 "cannot make the child datasets"
	fi
	zpool destroy "$OTHER_POOL" 2> /dev/null || true
	zfs destroy "$DATASET/child" 2> /dev/null || true
	rm -f "$WORK/other-pool.img"
	rmdir "$DIR/other" "$DIR/child" 2> /dev/null || true
fi

# 11: No crash
if tail -c +$((RPC_START + 1)) "$RPCLOG" | grep -q 'PANIC\|INTERNAL ERROR' ||
   tail -c +$((SMBD_START + 1)) "$LOGDIR/log.smbd" 2> /dev/null |
	grep -q 'PANIC\|INTERNAL ERROR'; then
	bad S11 "a panic in the logs"
else
	ok S11 "no panic in smbd or rpcd_mdssvc"
fi

echo "=========================================="
echo "Spotlight truesearch backend: $PASS passed, $FAILED failed"
echo "=========================================="
[ "$FAILED" = 0 ]
