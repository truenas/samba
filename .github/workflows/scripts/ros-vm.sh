#!/usr/bin/env bash

######################################################################
# Test the interim responses of READ, WRITE and FLUSH on slow storage, in
# the VM, as root. qemu-4.10-ros.sh runs this script.
#
# smbd answers a READ, WRITE or FLUSH that still runs after 500
# microseconds with an interim response ([MS-SMB2] 3.3.4.2). A Windows
# client then waits 4 times longer before it drops the connection. The
# truenas_ros reactors must do the same for the file I/O that smbd gives
# them. The share is a ZFS pool on a file. zinject delays each I/O of the
# pool by DELAY_MS, because the TrueNAS kernel has no device mapper. The
# pool caches no file data, so a READ goes to the file. pending/sync is a
# dataset that writes synchronously.
#
# The checks:
#   P1 smb2.ros-pending read, write, flush and cancel pass with the
#      reactors on (the default) and off, plain, signed and encrypted.
#   P2 smb2.ros-pending.deep passes with the reactors on and off. With the
#      reactors on, plain and encrypted, the memory of smbd stays within
#      the limit of a reactor, 16 requests in flight per connection. An
#      interim response must not give up the place of its request.
#   P3 The READs and WRITEs of a share with truenas_audit go through the
#      VFS, with the reactors on and off. The reactors do not call VFS
#      modules, so smbd must not give them this I/O. The CLOSE audit
#      records must count the bytes.
#   P4 The reactors do the READ, WRITE and FLUSH of the shares that
#      middleware makes by default, with and without the Apple extensions.
#      These shares are on ZFS. With the reactors on, the profile counts of
#      the I/O of vfs_io_uring do not grow. With the reactors off, they
#      grow.
#   P5 A logoff and a tree disconnect end a CHANGE_NOTIFY that waits, with
#      the reactors on and off, plain, signed and encrypted. smbd waits
#      until it frees the request.
#   P6 An encrypted session re-authenticates, with the reactors on and
#      off, also with wrong credentials and a bad NTLMSSP message. Until it
#      is done, smbd finds the session of a PDU in the global record. With
#      the reactors on, smbd must accept the decryption of the reactor,
#      which used the keys of the session of the connection.
#
# To run outside the VM, set ROS_POOL empty (no pool and no stop of other
# daemons) and ROS_DIR to a directory on slow storage. Set ROS_TN_DIR to
# a directory on ZFS with NFSv4 ACLs. ROS_TN_VFS can leave out the
# modules that need libzfs. ROS_WORK, ROS_USER,
# ROS_DELAY_MS (0: any delay), ROS_IO_SIZE, SMBD, SMBPASSWD, SMBSTATUS and
# SMBTORTURE can also change.
######################################################################

set -eu

POOL="${ROS_POOL-rosslow}"
DIR="${ROS_DIR:-/mnt/rosslow}"
WORK="${ROS_WORK:-/var/tmp/ros}"
DELAY_MS="${ROS_DELAY_MS:-100}"
IO_SIZE="${ROS_IO_SIZE:-1048576}"
USER_NAME="${ROS_USER:-rosuser}"
USER_PASS='Passw0rd.3'
SMBD="${SMBD:-/usr/sbin/smbd}"
SMBPASSWD="${SMBPASSWD:-/usr/bin/smbpasswd}"
SMBSTATUS="${SMBSTATUS:-/usr/bin/smbstatus}"
SMBTORTURE="${SMBTORTURE:-/usr/bin/smbtorture}"
# P4: the VFS modules of a share of the default purpose on a dataset with
# ACLs, in the order of middleware (plugins/smb_/util_smbconf.py). The
# Apple extensions and name mangling add catia and fruit.
TN_DIR="${ROS_TN_DIR:-/rosz/share}"
TN_VFS="truenas_streams_xattr shadow_copy_zfs ixnas zfs_core io_uring"
TN_VFS="${ROS_TN_VFS:-$TN_VFS}"
TN_APPLE_VFS="catia fruit $TN_VFS"
CONF="$WORK/smb.conf"
# [global] includes this file. It turns the reactors off, or is empty.
SWITCH="$WORK/transport.conf"
OUT="$WORK/out"
# smb2.ros-pending.deep: DEPTH WRITEs of DEEP_SIZE bytes to FILES files
DEPTH=64
DEEP_SIZE=8388608
FILES=16
# A reactor reads at most 16 requests of a connection at once
# (SMBD_SMB2_ROS_MAX_IN_FLIGHT). The rest of smbd fits in 128 MiB.
MEM_LIMIT_KB=$(((16 * DEEP_SIZE + 128 * 1048576) / 1024))
# With a storage delay, a reactor holds 16 WRITEs at once. Then a peak
# under half of them means that the check measured no load. Without a
# delay, the check needs only a measured peak.
MEM_FLOOR_KB=1
[ "$DELAY_MS" -eq 0 ] || MEM_FLOOR_KB=$((8 * DEEP_SIZE / 1024))
PASS=0
FAILED=0

ok() { PASS=$((PASS + 1)); echo "PASS  $1: $2"; }
bad() { FAILED=$((FAILED + 1)); echo "FAIL  $1: $2"; }

step() {
	echo "=========================================="
	echo "Interim responses: $*"
	echo "=========================================="
}

stop_smbd() {
	local pid
	pid=$(cat "$WORK/run/smbd.pid" 2> /dev/null) || return 0
	kill -TERM "$pid" 2> /dev/null || return 0
	for _ in $(seq 1 50); do
		kill -0 "$pid" 2> /dev/null || return 0
		sleep 0.2
	done
	kill -KILL "$pid" 2> /dev/null || true
}

stop() {
	stop_smbd
	[ -n "$POOL" ] || return 0
	zinject -c all > /dev/null 2>&1 || true
	zpool destroy "$POOL" 2> /dev/null || true
	rm -f "$WORK/slow.img"
	zpool destroy rosz 2> /dev/null || true
	rm -f "$WORK/rosz.img"
}

# (Re)start smbd with the reactors on or off
start_smbd() { # $1: on or off
	stop_smbd
	case "$1" in
	off) echo "truenas:ros transport = no" > "$SWITCH" ;;
	*) : > "$SWITCH" ;;
	esac
	"$SMBD" -D -s "$CONF"
	for _ in $(seq 1 150); do
		ss -ltn | grep -q ':445 ' && return 0
		sleep 0.2
	done
	echo "ERROR: smbd does not listen"
	return 1
}

# The files of a run: read.dat is not in memory, and the kernel writes the
# files in sync synchronously. sync can be the mountpoint of a dataset, so
# this empties the directories and does not remove them.
prepare() {
	local f
	mkdir -p "$DIR/pending/sync"
	find "$DIR/pending" -mindepth 1 -maxdepth 1 ! -name sync -exec rm -rf {} +
	find "$DIR/pending/sync" -mindepth 1 -delete
	head -c "$IO_SIZE" /dev/urandom > "$DIR/pending/read.dat"
	for f in write $(seq -f 'deep%g' 0 $((FILES - 1))); do
		touch "$DIR/pending/sync/$f.dat"
	done
	chown -R "$USER_NAME" "$DIR/pending"
	# The tests open these files with all rights. Without an inherited ACL,
	# smbd gives an owner full control only for rwx.
	chmod -R u+rwx "$DIR/pending"
	sync -f "$DIR/pending/read.dat"
	# The pool frees the dirty data of read.dat only when its txg syncs.
	[ -z "$POOL" ] || zpool sync "$POOL"
}

# smbtorture as the test user, on the share SHARE (default slow). A skipped
# test fails the run.
torture() { # $1: name of the output, then arguments
	local out="$OUT/$1.txt" rc=0
	shift
	"$SMBTORTURE" "//127.0.0.1/${SHARE:-slow}" --configfile="$CONF" \
		-U "$USER_NAME%$USER_PASS" \
		--option="torture:pending_delay_ms=$DELAY_MS" \
		--option="torture:pending_io_size=$IO_SIZE" \
		--option="torture:pending_depth=$DEPTH" \
		--option="torture:pending_deep_size=$DEEP_SIZE" \
		--option="torture:pending_files=$FILES" "$@" > "$out" 2>&1 || rc=$?
	cat "$out"
	if [ "$rc" -eq 0 ] && grep -q '^skip:' "$out"; then
		rc=1
	fi
	return "$rc"
}

# Run torture "$@" and record the largest VmHWM of smbd and its children
# in PEAK_KB, in kB. The child of a connection has a name of its own.
torture_peak() {
	local main pid rc=0 kb c
	main=$(cat "$WORK/run/smbd.pid")
	PEAK_KB=0
	torture "$@" &
	pid=$!
	while kill -0 "$pid" 2> /dev/null; do
		for c in $(pgrep -P "$main") "$main"; do
			kb=$(awk '/^VmHWM:/ {print $2}' "/proc/$c/status" \
				2> /dev/null || true)
			[ "${kb:-0}" -le "$PEAK_KB" ] || PEAK_KB=$kb
		done
		sleep 0.2
	done
	wait "$pid" || rc=$?
	return "$rc"
}

# The number of truenas_audit CLOSE records in the logs that count
# IO_SIZE bytes of $1 (read or write). The counters are in a JSON string
# of the record, with escaped quotes.
audited() {
	cat "$WORK"/log/log.* 2> /dev/null |
		grep -cE "${1}_bytes[^0-9]+${IO_SIZE}[^0-9]" || true
}

# Save the profile counts of smbd in the file $1
profile() {
	"$SMBSTATUS" -s "$CONF" --profile > "$1" 2> /dev/null || : > "$1"
}

# The growth of the count $1, such as smb2_read, from the profile $2 to the
# profile $3
grown() {
	awk -v n="$1_count:" '
	{
		for (i = 1; i < NF; i++)
			if ($i == n)
				v[FILENAME] = $(i + 1)
	}
	END { print v[ARGV[2]] - v[ARGV[1]] }' "$2" "$3"
}

mkdir -p "$WORK" "$OUT" "$DIR"
for d in run log private lock state cache ncalrpc; do
	mkdir -p "$WORK/$d"
done
id "$USER_NAME" > /dev/null 2>&1 || useradd -M "$USER_NAME"

trap stop EXIT
if [ -n "$POOL" ]; then
	# Stop the smbd of the earlier steps and its RPC daemons
	systemctl stop smbd nmbd winbind 2> /dev/null || true
	DAEMONS='smbd|nmbd|winbindd|samba-dcerpcd|rpcd_[a-z_]+'
	pkill -TERM -x "$DAEMONS" 2> /dev/null || true
	for _ in $(seq 1 50); do
		pgrep -x "$DAEMONS" > /dev/null || break
		sleep 0.2
	done
	pkill -KILL -x "$DAEMONS" 2> /dev/null || true

	# zinject delays each I/O of the file of the pool. With a lane for each
	# I/O in flight, the delay adds latency and does not limit the rate.
	step "a ZFS pool whose I/O takes $DELAY_MS ms"
	modprobe zfs
	zinject -c all > /dev/null 2>&1 || true
	zpool destroy "$POOL" 2> /dev/null || true
	truncate -s 1G "$WORK/slow.img"
	zpool create -f -m "$DIR" -O primarycache=metadata -O compression=off \
		"$POOL" "$WORK/slow.img"
	zfs create -o sync=always -o mountpoint="$DIR/pending/sync" \
		"$POOL/sync"
	zinject -d "$WORK/slow.img" -D "$DELAY_MS:256" "$POOL"

	step "a ZFS dataset for the shares of P4"
	zpool destroy rosz 2> /dev/null || true
	truncate -s 1G "$WORK/rosz.img"
	zpool create -f -m /rosz rosz "$WORK/rosz.img"
	zfs create -o acltype=nfsv4 -o aclmode=passthrough \
		-o aclinherit=passthrough -o casesensitivity=insensitive \
		-o xattr=sa rosz/share
	TN_DIR=/rosz/share
fi
mkdir -p "$TN_DIR"
# P5 and P6 create files at the root of [tn].
chown "$USER_NAME" "$TN_DIR"

cat > "$CONF" <<CONF
[global]
    workgroup = WORKGROUP
    netbios name = ROSCI
    security = user
    passdb backend = tdbsam
    load printers = no
    printing = bsd
    disable spoolss = yes
    pid directory = $WORK/run
    private dir = $WORK/private
    lock directory = $WORK/lock
    state directory = $WORK/state
    cache directory = $WORK/cache
    ncalrpc dir = $WORK/ncalrpc
    log file = $WORK/log/log.%m
    log level = 1
    max log size = 0
    smbd profiling level = count
    fruit:nfs_aces = no
    fruit:zero_file_id = no
    include = $SWITCH
[slow]
    path = $DIR
    read only = no
    vfs objects = io_uring
[audited]
    path = $DIR
    read only = no
    vfs objects = truenas_audit io_uring
    truenas_audit:backend = debug
[tn]
    path = $TN_DIR
    read only = no
    vfs objects = $TN_VFS
    posix locking = no
    smbd max xattr size = 2097152
    fruit:metadata = stream
    fruit:resource = stream
    fruit:convert_adouble = no
    ea support = no
    smb3 unix extensions = no
[tnapple]
    path = $TN_DIR
    read only = no
    vfs objects = $TN_APPLE_VFS
    posix locking = no
    smbd max xattr size = 2097152
    fruit:metadata = stream
    fruit:resource = stream
    fruit:convert_adouble = no
    fruit:encoding = native
    mangled names = no
    ea support = no
    smb3 unix extensions = no
CONF
: > "$SWITCH"
printf '%s\n%s\n' "$USER_PASS" "$USER_PASS" |
	"$SMBPASSWD" -c "$CONF" -s -a "$USER_NAME" > /dev/null

for transport in on off; do
	start_smbd "$transport"
	for seal in plain signed encrypted; do
		step "P1: reactors $transport, $seal"
		case "$seal" in
		signed) set -- --option=clientsigning=required ;;
		encrypted) set -- --option=clientsmbencrypt=required ;;
		*) set -- ;;
		esac
		prepare
		torture "p1-$transport-$seal" "$@" smb2.ros-pending.read \
			smb2.ros-pending.write smb2.ros-pending.flush \
			smb2.ros-pending.cancel &&
			ok P1 "reactors $transport, $seal" ||
			bad P1 "reactors $transport, $seal"
	done

	# With encryption, a reactor decrypts each WRITE in the buffer that it
	# read the WRITE into. The same limits apply.
	seals=plain
	[ "$transport" = off ] || seals="plain encrypted"
	for seal in $seals; do
		name="reactors $transport, $seal"
		step "P2: $name, $DEPTH WRITEs of $DEEP_SIZE bytes"
		case "$seal" in
		encrypted) set -- --option=clientsmbencrypt=required ;;
		*) set -- ;;
		esac
		prepare
		torture_peak "p2-$transport-$seal" "$@" \
			--option=torture:pending_hold_ms=500 \
			smb2.ros-pending.deep &&
			ok P2a "$name: all WRITEs succeeded" ||
			bad P2a "$name: smb2.ros-pending.deep failed"
		echo "smbd VmHWM: $PEAK_KB kB"
		[ "$transport" = on ] || continue
		used="$seal: smbd used $PEAK_KB kB"
		if [ "$PEAK_KB" -lt "$MEM_FLOOR_KB" ]; then
			bad P2b "$used, under the lower limit $MEM_FLOOR_KB kB"
		elif [ "$PEAK_KB" -le "$MEM_LIMIT_KB" ]; then
			ok P2b "$used, $MEM_FLOOR_KB to $MEM_LIMIT_KB kB allowed"
		else
			bad P2b "$used, over the limit $MEM_LIMIT_KB kB"
		fi
	done

	step "P3: reactors $transport, a share with truenas_audit"
	prepare
	reads=$(audited read)
	writes=$(audited write)
	SHARE=audited torture "p3-$transport" smb2.ros-pending.read \
		smb2.ros-pending.write &&
		ok P3a "reactors $transport: READ and WRITE passed" ||
		bad P3a "reactors $transport: READ or WRITE failed"
	[ "$(audited read)" -gt "$reads" ] &&
		[ "$(audited write)" -gt "$writes" ] &&
		ok P3b "reactors $transport: the audit counted the bytes" ||
		bad P3b "reactors $transport: the audit did not count the bytes"

	for share in tn tnapple; do
		name="reactors $transport, [$share]"
		modules=$TN_VFS
		[ "$share" = tn ] || modules=$TN_APPLE_VFS
		step "P4: $name, vfs objects = $modules"
		head -c 65536 /dev/zero > "$TN_DIR/p4.dat"
		chown "$USER_NAME" "$TN_DIR/p4.dat"
		before="$OUT/p4-$transport-$share-before.txt"
		after="$OUT/p4-$transport-$share-after.txt"
		profile "$before"
		SHARE=$share torture "p4-$transport-$share" \
			--option=torture:ri_file=p4.dat \
			smb2.ros-inline.write-existing &&
			ok P4a "$name: WRITE, FLUSH and READ passed" ||
			bad P4a "$name: WRITE, FLUSH or READ failed"
		# The process of a connection adds its counts when it exits.
		for _ in $(seq 1 50); do
			profile "$after"
			[ "$(grown smb2_read "$before" "$after")" -le 0 ] || break
			sleep 0.2
		done
		# smbd counts each request. vfs_io_uring counts its own I/O.
		counted=yes
		for c in smb2_read smb2_write smb2_flush; do
			[ "$(grown "$c" "$before" "$after")" -gt 0 ] || counted=no
		done
		vfs="" none=yes all=yes
		for c in pread pwrite fsync; do
			n=$(grown "syscall_asys_$c" "$before" "$after")
			vfs="$vfs $c+$n"
			[ "$n" -eq 0 ] || none=no
			[ "$n" -gt 0 ] || all=no
		done
		echo "SMB2 requests counted: $counted, I/O of vfs_io_uring:$vfs"
		if [ "$counted" != yes ]; then
			bad P4b "$name: smbd did not count the requests"
		elif [ "$transport" = on ]; then
			[ "$none" = yes ] &&
				ok P4b "$name: the reactors did the I/O" ||
				bad P4b "$name: smbd did I/O for the reactors"
		else
			[ "$all" = yes ] &&
				ok P4b "$name: smbd did the I/O" ||
				bad P4b "$name: vfs_io_uring did not count the I/O"
		fi
	done

	for seal in plain signed encrypted; do
		name="reactors $transport, $seal"
		step "P5: $name, a logoff and a tree disconnect"
		case "$seal" in
		signed) set -- --option=clientsigning=required ;;
		encrypted) set -- --option=clientsmbencrypt=required ;;
		*) set -- ;;
		esac
		SHARE=tn torture "p5-$transport-$seal" "$@" smb2.notify.logoff \
			smb2.notify.tdis &&
			ok P5 "$name: the waiting requests ended" ||
			bad P5 "$name: a logoff or a tree disconnect failed"
	done

	name="reactors $transport, encrypted"
	step "P6: $name, a re-authentication"
	SHARE=tn torture "p6-$transport" --option=clientsmbencrypt=required \
		smb2.session.reauth1 smb2.session.reauth6 \
		smb2.session.bind_invalid_auth smb2.session.ntlmssp_bug14932 &&
		ok P6 "$name: smbd answered each re-authentication" ||
		bad P6 "$name: a re-authentication failed"
done
stop_smbd

step "$PASS passed, $FAILED failed"
if [ "$FAILED" -ne 0 ]; then
	tail -60 "$WORK/log/log.smbd" 2> /dev/null || true
	exit 1
fi
