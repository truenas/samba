#!/usr/bin/env bash

######################################################################
# Durable handle tests inside the VM, as root. qemu-4.6-durable.sh runs
# one command of this script for each step:
#   setup          the dataset, the configurations, the link secret
#   unit           the packaged unit on a system that is not HA
#   case NAME      one failure case, see run_case()
#   regress        upstream suites with the option off and on
#   crash-prepare  durable handles open before the crash of the VM
#   crash-verify   after the crash: smbd starts, nothing is restored
# Two truenas_smbhad from the package stand in for the controllers. A is
# node A, primary on 127.0.0.1. B is node B, standby on 127.0.0.2. The
# epoch file is on the pool. Each case runs
# truenas.durable.restore: "prepare" opens durable handles and holds the
# connection while the server goes away, "verify" reconnects them with
# the saved client state.
#
# For a run outside the VM, the environment can set DURABLE_SHARE,
# DURABLE_DATASET (empty: no ZFS), DURABLE_EPOCH, DURABLE_WORK,
# DURABLE_PORT, DURABLE_CREDS, DURABLE_INCLUDE (a file that [global]
# includes last), SMBD, WINBINDD, WBINFO, SMBTORTURE, TESTPARM and SMBHAD.
######################################################################

set -eu

SHARE="${DURABLE_SHARE:-/tank/durable}"
DATASET="${DURABLE_DATASET-tank/durable}"
EPOCH="${DURABLE_EPOCH:-/tank/.smbhad/smbhad.epoch}"
WORK="${DURABLE_WORK:-/var/tmp/durable}"
PORT="${DURABLE_PORT:-445}"
CREDS="${DURABLE_CREDS:-smbtest%testpass123}"
SMBD="${SMBD:-/usr/sbin/smbd}"
WINBINDD="${WINBINDD:-/usr/sbin/winbindd}"
WBINFO="${WBINFO:-/usr/bin/wbinfo}"
SMBTORTURE="${SMBTORTURE:-/usr/bin/smbtorture}"
TESTPARM="${TESTPARM:-/usr/bin/testparm}"
SMBHAD="${SMBHAD:-/usr/sbin/truenas_smbhad}"
OUT="$WORK/out"
HD="$WORK/hd"
# The upstream suites that use the hooks of the option.
SUITES="smb2.durable-open smb2.durable-v2-open smb2.durable-open-disconnect
	smb2.durable-v2-delay smb2.lease smb2.oplock smb2.lock smb2.replay"
NOHA_SUITES="smb2.durable-open smb2.durable-v2-open"
ALL=ABCDEFGHIJKLMN
CASE=setup
LOG="$OUT/setup.smbd.log"
STATE="$WORK/state.txt"
PREP=""
mkdir -p "$OUT" "$HD"

fail() {
	echo "ERROR: $CASE: $*"
	exit 1
}

# smb.conf. $2: on (daemon A), off, or noha (the packaged unit).
# $3: one more [global] line.
write_conf() {
	local opt
	case $2 in
	on)
		opt="truenas stateful failover = yes
    truenas smbhad socket = $HD/a/smbd.sock
    truenas smbhad:epoch file = $EPOCH";;
	off)
		opt="truenas stateful failover = no";;
	noha)
		opt="truenas stateful failover = yes";;
	esac
	cat > "$1" <<CONF
[global]
    workgroup = WORKGROUP
    netbios name = SMBCITEST
    security = user
    passdb backend = tdbsam
    load printers = no
    printing = bsd
    disable spoolss = yes
    smbd: backgroundqueue = no
    log level = 1
    $opt
    ${3:-}
    ${DURABLE_INCLUDE:+include = $DURABLE_INCLUDE}

[zdurable]
    path = $SHARE
    read only = no
    vfs objects = truenas_streams_xattr zfs_core
    streams_xattr:xattr_compat = no
    # as middleware sets it with durable handles
    posix locking = no
CONF
}

wait_port() {
	local i
	for i in $(seq 1 150); do
		ss -ltn | grep -q ":$PORT " && return 0
		sleep 0.2
	done
	tail -40 "$LOG"
	fail "smbd does not listen"
}

wait_file() { # $1: file, $2: output of the client that writes it
	local i
	for i in $(seq 1 150); do
		[ -f "$1" ] && return 0
		sleep 0.2
	done
	cat "$2"
	fail "no $1"
}

winbindd_up() {
	local i
	if ! pgrep -x winbindd > /dev/null; then
		(setsid "$WINBINDD" -F --no-process-group \
			-s "$WORK/smb-off.conf" --debug-stdout -d1 \
			>> "$OUT/winbindd.log" 2>&1 < /dev/null &)
	fi
	for i in $(seq 1 100); do
		"$WBINFO" -p > /dev/null 2>&1 && return 0
		sleep 0.2
	done
	tail -40 "$OUT/winbindd.log"
	fail "winbindd does not answer"
}

# $1: smb.conf. $2: a or b (b: the socket of B).
# $3: nowait: do not wait until smbd listens.
smbd_up() {
	local cmd="exec $SMBD -F --no-process-group -s $1 --debug-stdout -d1"

	winbindd_up
	if [ "$2" = b ]; then
		cmd="$cmd '--option=truenas smbhad socket=$HD/b/smbd.sock'"
	fi
	(setsid sh -c "$cmd" >> "$LOG" 2>&1 < /dev/null &)
	[ "${3:-}" = nowait ] || wait_port
}

smbd_down() { # $1: TERM or KILL
	local p i
	if [ "$1" = KILL ]; then
		# A child stops when its parent dies (reinit_after_fork) and
		# then disconnects its handles cleanly. Stop the parent, kill
		# the children, then kill the parent.
		for p in $(pgrep -x smbd); do
			kill -STOP "$p" 2> /dev/null || true
			pkill -KILL -P "$p" || true
			kill -KILL "$p" 2> /dev/null || true
		done
	fi
	pkill -"$1" -x smbd 2>/dev/null || true
	for i in $(seq 1 100); do
		pgrep -x smbd > /dev/null || return 0
		sleep 0.2
	done
	pkill -KILL -x smbd || true
	sleep 1
}

# The configuration of daemon $1 (a or b) with role $2
hd_conf() {
	local addr=127.0.0.1 peer=127.0.0.2 node=A
	if [ "$1" = b ]; then
		addr=127.0.0.2; peer=127.0.0.1; node=B
	fi
	cat > "$HD/$1.conf" <<CONF
[smbhad]
role = $2
local_address = $addr
peer_address = $peer
port = 4390
socket_dir = $HD/$1
epoch_file = $EPOCH
secret_file = $HD/secret
node = $node
CONF
}

hd_log() { echo "$OUT/$CASE.hd-$1.log"; }

# Wait until daemon $1 logs $2 after line $3 of its log
hd_wait() {
	local i
	for i in $(seq 1 200); do
		tail -n +"$(($3 + 1))" "$(hd_log "$1")" 2> /dev/null |
			grep -q "$2" && return 0
		sleep 0.05
	done
	tail -20 "$(hd_log "$1")"
	fail "daemon $1 did not log '$2'"
}

hd_lines() { cat "$(hd_log "$1")" 2> /dev/null | wc -l; }

hd_up() { # $1: a or b
	(setsid "$SMBHAD" --config "$HD/$1.conf" >> "$(hd_log "$1")" 2>&1 \
		< /dev/null & echo $! > "$HD/$1.pid")
}

hd_down() { # $1: a or b, $2: signal
	local pid i
	[ -f "$HD/$1.pid" ] || return 0
	pid=$(cat "$HD/$1.pid")
	rm -f "$HD/$1.pid"
	# After a reboot, the pid can belong to another process.
	[ "$(cat "/proc/$pid/comm" 2> /dev/null)" = truenas_smbhad ] ||
		return 0
	kill -"$2" "$pid" 2> /dev/null || true
	for i in $(seq 1 100); do
		kill -0 "$pid" 2> /dev/null || return 0
		sleep 0.05
	done
	fail "daemon $1 did not stop"
}

hd_stop() { hd_down a TERM; hd_down b TERM; }

# A primary, B standby, A protected
hd_start() {
	local n
	hd_down a KILL
	hd_down b KILL
	hd_conf a primary
	hd_conf b standby
	n=$(hd_lines a)
	hd_up a
	hd_up b
	hd_wait a "protected:" "$n"
}

# A restarts with an empty copy and a new instance
hd_restart_a() {
	local n
	n=$(hd_lines a)
	hd_down a KILL
	hd_up a
	hd_wait a "protected:" "$n"
}

hd_promote_b() { # $1: nowait
	local n
	n=$(hd_lines b)
	hd_conf b primary
	kill -HUP "$(cat "$HD/b.pid")"
	[ "${1:-}" = nowait ] || hd_wait b "primary: epoch" "$n"
}

torture() { # $1: output, then the smbtorture arguments
	local out=$1
	shift
	"$SMBTORTURE" //127.0.0.1/zdurable -p "$PORT" -U "$CREDS" "$@" \
		> "$out" 2>&1
}

# Open the handles. A client in the background holds the connection.
prepare() { # $@: more smbtorture options
	rm -f "$STATE" "$STATE.2"
	setsid "$SMBTORTURE" //127.0.0.1/zdurable -p "$PORT" -U "$CREDS" \
		--option=torture:durable_phase=prepare \
		--option=torture:durable_state="$STATE" \
		--option=torture:durable_hold=600 "$@" \
		truenas.durable.restore > "$OUT/$CASE.prep.txt" 2>&1 \
		< /dev/null &
	PREP=$!
	wait_file "$STATE" "$OUT/$CASE.prep.txt"
}

stop_client() {
	[ -n "$PREP" ] || return 0
	kill "$PREP" 2> /dev/null || true
	wait "$PREP" 2> /dev/null || true
	PREP=""
}

# Reconnect the restored handles, write $STATE.2, hold the connection
reconnect() {
	setsid "$SMBTORTURE" //127.0.0.1/zdurable -p "$PORT" -U "$CREDS" \
		--option=torture:durable_phase=reconnect \
		--option=torture:durable_state="$STATE" \
		--option=torture:durable_state_out="$STATE.2" \
		--option=torture:durable_hold=600 \
		truenas.durable.restore > "$OUT/$CASE.reconnect.txt" 2>&1 \
		< /dev/null &
	PREP=$!
	wait_file "$STATE.2" "$OUT/$CASE.reconnect.txt"
}

# $1: the handles that must not come back. $2: the state file.
verify() {
	local out="$OUT/$CASE.verify.txt"

	stop_client
	if ! torture "$out" \
		--option=torture:durable_phase=verify \
		--option=torture:durable_state="$2" \
		--option=torture:durable_gone="$1" \
		truenas.durable.restore; then
		cat "$out"
		tail -60 "$LOG"
		fail "verify failed"
	fi
	echo "$CASE: PASSED (gone '${1}')"
	grep -h 'durable handles after' "$LOG" | tail -1 |
		sed 's/^.*durable handles/  durable handles/'
	grep '^[A-N]: reconnect' "$out" | sort |
		sed -E -e 's/^([A-N]): reconnect [^:]*: NT_STATUS_/\1 /' \
			-e 's/ OK$/ ok/' -e 's/ OBJECT_NAME_NOT_FOUND$/ gone/' |
		tr '\n' ' ' | sed 's/^/  /'
	echo
}

tamper() { # change a file in place, keep its size and mtime
	local f="$SHARE/truenas_durable/$1"
	touch -r "$f" "$WORK/ref"
	printf 'X' | dd of="$f" bs=1 seek=100 conv=notrunc 2> /dev/null
	touch -r "$WORK/ref" "$f"
}

# Mount the dataset and its nested dataset again until both have other
# device numbers. The record has the filesystem id (statfs f_fsid) of the
# file, which does not change.
devmove() {
	local before after nbefore nafter i=0 d
	before=$(stat -c %d "$SHARE")
	nbefore=$(stat -c %d "$SHARE/nested")
	zfs unmount "$DATASET/nested"
	zfs unmount "$DATASET"
	after=$before
	nafter=$nbefore
	while { [ "$after" = "$before" ] || [ "$nafter" = "$nbefore" ]; } &&
	    [ $i -lt 20 ]; do
		i=$((i + 1))
		mkdir -p "$WORK/devgrab$i"
		mount -t tmpfs none "$WORK/devgrab$i"
		zfs mount "$DATASET"
		zfs mount "$DATASET/nested"
		after=$(stat -c %d "$SHARE")
		nafter=$(stat -c %d "$SHARE/nested")
		if [ "$after" = "$before" ] || [ "$nafter" = "$nbefore" ]; then
			zfs unmount "$DATASET/nested"
			zfs unmount "$DATASET"
		fi
	done
	for d in "$WORK"/devgrab*; do
		umount "$d" 2> /dev/null || true
	done
	[ "$after" != "$before" ] || fail "the device number did not change"
	[ "$nafter" != "$nbefore" ] ||
		fail "the device number of the nested dataset did not change"
	echo "devmove: dataset device $before -> $after," \
		"nested $nbefore -> $nafter"
}

# The file id of the file in the nested dataset, from smbd. Empty if the
# read fails, see $OUT/$CASE.fileid.txt.
nested_fileid() {
	local out="$OUT/$CASE.fileid.txt"

	torture "$out" truenas.durable.fileid || true
	sed -n 's/^fileid //p' "$out"
}

check_panic() {
	if grep -l -E 'PANIC|smb_panic' "$OUT"/*.smbd.log 2> /dev/null; then
		fail "smbd panicked"
	fi
}

setup() {
	# The smoke test left smbd and maybe winbindd running.
	smbd_down TERM
	pkill -TERM -x winbindd 2> /dev/null || true
	hd_stop
	if [ -n "$DATASET" ] && ! zfs list "$DATASET" > /dev/null 2>&1; then
		zfs create -o casesensitivity=insensitive -o atime=off \
			"$DATASET"
	fi
	if [ -n "$DATASET" ] &&
	    ! zfs list "$DATASET/nested" > /dev/null 2>&1; then
		zfs create "$DATASET/nested"
	fi
	mkdir -p "$SHARE" "$(dirname "$EPOCH")"
	chmod 0777 "$SHARE"
	if [ -n "$DATASET" ]; then
		chmod 0777 "$SHARE/nested"
		echo nested > "$SHARE/nested/fileid.dat"
		chmod 0666 "$SHARE/nested/fileid.dat"
	fi
	rm -f "$EPOCH"
	mkdir -p -m 0700 "$HD/a" "$HD/b"
	head -c 64 /dev/urandom > "$HD/secret"
	chmod 0600 "$HD/secret"
	write_conf "$WORK/smb-on.conf" on
	write_conf "$WORK/smb-off.conf" off
	write_conf "$WORK/smb-noha.conf" noha
	write_conf "$WORK/smb-tick5.conf" on "truenas smbhad:tick ms = 5000"
	for c in on off noha tick5; do
		"$TESTPARM" -s "$WORK/smb-$c.conf" > /dev/null 2>&1 ||
			fail "testparm $WORK/smb-$c.conf"
	done
	echo "testparm: OK"
}

# Not HA: the package enables the unit. Its role is Idle. smbd does not
# wait for it and restores nothing.
unit() {
	local t0 t
	CASE=unit
	LOG="$OUT/unit.smbd.log"
	STATE="$WORK/state-unit.txt"
	[ "$(systemctl is-enabled truenas-smbhad)" = enabled ] ||
		fail "truenas-smbhad.service is not enabled"
	# Type=notify: the restart returns after READY=1.
	systemctl restart truenas-smbhad ||
		fail "truenas-smbhad.service did not start"
	[ "$(systemctl is-active truenas-smbhad)" = active ] ||
		fail "truenas-smbhad.service is not active"
	journalctl -u truenas-smbhad -b -o cat | tail -5
	journalctl -u truenas-smbhad -b -o cat | grep -q 'role Idle' ||
		fail "the role is not Idle"
	[ ! -e /var/db/system/samba4/smbhad.epoch ] ||
		fail "an epoch file on a system that is not HA"
	smbd_down KILL
	hd_stop
	t0=$(date +%s)
	smbd_up "$WORK/smb-noha.conf" a
	t=$(($(date +%s) - t0))
	echo "smbd listens after $t s"
	[ "$t" -lt 10 ] || fail "smbd waited for truenas_smbhad"
	prepare
	sleep 3
	smbd_down TERM
	smbd_up "$WORK/smb-noha.conf" a
	verify "$ALL" "$STATE"
	smbd_down TERM
	check_panic
}

run_case() { # $1: the case
	local conf="$WORK/smb-on.conf" opt="" settle=3 gone="" state fid
	CASE=$1
	LOG="$OUT/$CASE.smbd.log"
	STATE="$WORK/state-$CASE.txt"
	state=$STATE
	smbd_down KILL
	if [ "$CASE" = lockfail ]; then
		# The first tick (5 s) sends I. The client locks I at 7 s.
		# A queued delete waits for the next tick. The failover comes
		# first.
		conf="$WORK/smb-tick5.conf"
		opt="--option=torture:durable_late_lock_secs=7"
		settle=0
	fi
	hd_start
	smbd_up "$conf" a
	prepare $opt
	# A tick sends the records. A quiet tick makes the locks stable.
	sleep "$settle"
	case $CASE in
	restart)
		# A restart restores nothing and clears the copy.
		smbd_down TERM; smbd_up "$conf" a; gone=$ALL;;
	crash)
		smbd_down KILL; smbd_up "$conf" a; gone=$ALL;;
	failover|lockfail)
		smbd_down KILL; hd_down a KILL; hd_promote_b
		smbd_up "$conf" b;;
	restartfail)
		# The restart cleared the copy: the failover restores
		# nothing.
		smbd_down TERM; smbd_up "$conf" a
		sleep 3
		smbd_down KILL; hd_down a KILL; hd_promote_b
		smbd_up "$conf" b; gone=$ALL;;
	blipfail)
		# The client reconnects and holds its handles, then a
		# failover. B, not flushed, must not come back.
		stop_client; sleep 1
		stop_client
		reconnect
		# a tick sends the reconnected records
		sleep 3
		smbd_down KILL; hd_down a KILL; hd_promote_b
		smbd_up "$conf" b
		state="$STATE.2";;
	daemonrestart)
		# No process holds the handles when daemon A restarts. The
		# scavenger sends them again to the new instance.
		stop_client; sleep 1
		hd_restart_a
		sleep 3
		smbd_down KILL; hd_down a KILL; hd_promote_b
		smbd_up "$conf" b;;
	smbdfirst)
		# smbd starts before B is primary. The restore waits.
		smbd_down KILL; hd_down a KILL
		smbd_up "$conf" b nowait; sleep 2
		hd_promote_b nowait; wait_port;;
	tamper)
		# A changed before the failover, C after the restore.
		smbd_down KILL; tamper durable_a.dat
		hd_down a KILL; hd_promote_b
		smbd_up "$conf" b; gone=A;;
	tamper2)
		smbd_down KILL; hd_down a KILL; hd_promote_b
		smbd_up "$conf" b; tamper durable_c.dat; gone=C;;
	devmove)
		if [ -z "$DATASET" ]; then
			echo "devmove: SKIPPED, no ZFS"
			return 0
		fi
		# The file id of a file in a nested dataset does not change.
		fid=$(nested_fileid)
		[ -n "$fid" ] || fail "no file id, see $OUT/$CASE.fileid.txt"
		smbd_down KILL; devmove; hd_down a KILL; hd_promote_b
		smbd_up "$conf" b
		[ "$(nested_fileid)" = "$fid" ] ||
			fail "nested file id $fid -> $(nested_fileid)"
		echo "devmove: nested file id $fid";;
	*)
		fail "unknown case";;
	esac
	verify "$gone" "$state"
	smbd_down TERM
	# A daemon left running holds its address and port.
	hd_stop
	check_panic
}

# smbd and the daemons for mode $1: off, on, or noha
smbd_mode() {
	smbd_down TERM
	LOG="$OUT/regress-$1.smbd.log"
	case $1 in
	on) hd_start;;
	*) hd_stop;;
	esac
	smbd_up "$WORK/smb-$1.conf" a
}

suite() { # $1: mode, $2: suite
	local out="$OUT/regress-$1-$2.txt"
	torture "$out" "$2" || true
	grep -q -E '^(success|failure|error|skip): ' "$out" || {
		tail -20 "$out"
		fail "$2 ran no test ($1)"
	}
	sed -n -E 's/^(failure|error): ([^ ]+).*/\2/p' "$out" | sort -u \
		> "$OUT/regress-$1-$2.failed"
}

same() { # $1, $2: modes, $3: suite
	cmp -s "$OUT/regress-$1-$3.failed" "$OUT/regress-$2-$3.failed"
}

# The upstream suites must have the same failures with the option off and
# on. A suite with other failures runs again once, to rule out flaky
# tests.
regress() {
	local s again="" bad=0
	CASE=regress
	smbd_mode off
	for s in $SUITES; do suite off "$s"; done
	smbd_mode on
	for s in $SUITES; do suite on "$s"; done
	for s in $SUITES; do
		same off on "$s" || again="$again $s"
	done
	if [ -n "$again" ]; then
		echo "again:$again"
		smbd_mode off
		for s in $again; do suite off "$s"; done
		smbd_mode on
		for s in $again; do suite on "$s"; done
	fi
	smbd_mode noha
	for s in $NOHA_SUITES; do suite noha "$s"; done
	smbd_down TERM
	hd_stop
	for s in $SUITES; do
		if same off on "$s"; then
			echo "  same $s: $(grep -c '^success: ' \
				"$OUT/regress-on-$s.txt") passed, $(wc -l < \
				"$OUT/regress-on-$s.failed") failed"
		else
			echo "  DIFFERENT $s (< off, > on):"
			diff "$OUT/regress-off-$s.failed" \
				"$OUT/regress-on-$s.failed" | grep '^[<>]' |
				sed 's/^/    /'
			bad=1
		fi
	done
	for s in $NOHA_SUITES; do
		if same off noha "$s"; then
			echo "  same $s, not HA"
		else
			echo "  DIFFERENT $s, not HA (< off, > not HA):"
			diff "$OUT/regress-off-$s.failed" \
				"$OUT/regress-noha-$s.failed" | grep '^[<>]' |
				sed 's/^/    /'
			bad=1
		fi
	done
	check_panic
	[ "$bad" -eq 0 ] || fail "the option changed the results"
}

crash_prepare() {
	CASE=vmcrash
	LOG="$OUT/vmcrash.smbd.log"
	STATE="$WORK/state-vmcrash.txt"
	smbd_down KILL
	hd_start
	smbd_up "$WORK/smb-on.conf" a
	prepare
	sleep 3
	cat /proc/sys/kernel/random/boot_id > "$WORK/boot-before"
	sync
}

# Both daemons lost their copy with the VM. The epoch file on the pool
# remains. smbd waits for the new primary and restores nothing.
crash_verify() {
	local before
	CASE=vmcrash
	LOG="$OUT/vmcrash.smbd.log"
	STATE="$WORK/state-vmcrash.txt"
	before=$(cat "$WORK/boot-before")
	[ "$(cat /proc/sys/kernel/random/boot_id)" != "$before" ] ||
		fail "the VM did not reboot"
	# Only the smbd and winbindd of this script may run.
	systemctl stop smbd nmbd winbind 2> /dev/null || true
	smbd_down TERM
	pkill -TERM -x winbindd 2> /dev/null || true
	hd_stop
	modprobe zfs
	zpool list tank > /dev/null 2>&1 || zpool import -d /var/tmp tank
	zfs mount -a
	[ -f "$EPOCH" ] || fail "no epoch file after the crash"
	hd_start
	smbd_up "$WORK/smb-on.conf" a
	verify "$ALL" "$STATE"
	grep -q 'durable handles: nothing to restore' "$LOG" ||
		fail "smbd restored a copy"
	smbd_down TERM
	hd_stop
	check_panic
}

case ${1:-} in
setup) setup;;
unit) unit;;
case) run_case "${2:?case name}";;
regress) regress;;
crash-prepare) crash_prepare;;
crash-verify) crash_verify;;
*)
	echo "usage: durable-vm.sh setup | unit | case NAME | regress |"
	echo "       crash-prepare | crash-verify"
	exit 2;;
esac
