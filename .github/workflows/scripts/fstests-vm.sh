#!/usr/bin/env bash

######################################################################
# Run the fstests of fstests-cifs.list through the kernel SMB client
# (cifs.ko) against smbd. The script runs in the VM as root.
# qemu-4.9-fstests.sh installs the packages that fstests needs and runs
# this script.
#
# The script builds fstests at a fixed commit. It creates the test and the
# scratch datasets. It starts its own smbd. The shares have the settings
# that middleware writes for the default purpose. fstests mounts both
# shares with SMB 3.1.1. The datasets are case-sensitive because fstests
# expects POSIX names. The step fails when a test fails or does not run.
# A test that the list marks "known" does not fail the step. The script
# writes the results to WORK.
#
# To run outside the VM, set FSTESTS_DATASET, FSTESTS_DIR, FSTESTS_WORK,
# FSTESTS_SRC, FSTESTS_VFS, SMBD and SMBPASSWD. FSTESTS_VFS sets the VFS
# objects of the shares. With an empty FSTESTS_DATASET, the script does
# not use ZFS, systemctl or pkill.
######################################################################

set -eu

DATASET="${FSTESTS_DATASET-tank/fstests}"
DIR="${FSTESTS_DIR:-/tank/fstests}"
WORK="${FSTESTS_WORK:-/var/tmp/fstests}"
SRC="${FSTESTS_SRC:-/var/tmp/xfstests-dev}"
VFS="${FSTESTS_VFS:-truenas_streams_xattr shadow_copy_zfs ixnas zfs_core io_uring}"
SMBD="${SMBD:-/usr/sbin/smbd}"
SMBPASSWD="${SMBPASSWD:-/usr/bin/smbpasswd}"
HERE="$(cd "$(dirname "$0")" && pwd)"
LIST="$HERE/fstests-cifs.list"
FSTESTS_URL=https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git
FSTESTS_TAG=v2026.11.10
FSTESTS_COMMIT=71641219a506ac62bfa231592394265ca812670e
USER_NAME=fstest
USER_PASS=Fstest-Pass-1
CONF="$WORK/smb.conf"
OPTS="-ousername=$USER_NAME,password=$USER_PASS,vers=3.1.1,noperm,mfsymlinks,actimeo=0"

stop() {
	local pid
	umount /mnt/fstest /mnt/fscratch 2> /dev/null || true
	pid="$(cat "$WORK/run/smbd.pid" 2> /dev/null || true)"
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2> /dev/null || true
		for _ in $(seq 1 50); do
			kill -0 "$pid" 2> /dev/null || break
			sleep 0.2
		done
	fi
}

# Print the tests of the list. With "known" as $1, print the known tests.
tests_of() {
	sed -e 's/#.*//' "$LIST" | awk -v known="$1" \
		'NF && (known == "" || $2 == "known") { print $1 }'
}

echo "=========================================="
echo "fstests through cifs.ko: setup"
echo "=========================================="
modprobe cifs || { echo "ERROR: no cifs.ko for $(uname -r)"; exit 1; }
stop
rm -rf "$WORK"
mkdir -p "$WORK/run" "$WORK/private" "$WORK/lock" "$WORK/state" \
	"$WORK/cache" "$WORK/ncalrpc" /mnt/fstest /mnt/fscratch

if [ ! -x "$SRC/check" ]; then
	rm -rf "$SRC"
	git clone --quiet --depth 1 --branch "$FSTESTS_TAG" "$FSTESTS_URL" \
		"$SRC"
fi
got="$(git -C "$SRC" rev-parse HEAD)"
[ "$got" = "$FSTESTS_COMMIT" ] ||
	{ echo "ERROR: $FSTESTS_TAG is $got, not $FSTESTS_COMMIT"; exit 1; }
make -C "$SRC" -j"$(nproc)" > "$WORK/build.log" 2>&1 ||
	{ tail -40 "$WORK/build.log"; echo "ERROR: fstests build"; exit 1; }

# Create the users of the fstests README and the user of the mounts.
id fsgqa > /dev/null 2>&1 || useradd -m fsgqa
id fsgqa2 > /dev/null 2>&1 || useradd fsgqa2
id 123456-fsgqa > /dev/null 2>&1 || useradd --badname 123456-fsgqa ||
	echo "WARNING: no user 123456-fsgqa; tests that need it do not run"
getent group fsgqa > /dev/null || groupadd fsgqa
id "$USER_NAME" > /dev/null 2>&1 || useradd -M "$USER_NAME"

if [ -n "$DATASET" ]; then
	zfs destroy -r "$DATASET" 2> /dev/null || true
	zfs create -o mountpoint="$DIR" -o acltype=nfsv4 \
		-o aclmode=passthrough -o aclinherit=passthrough \
		-o casesensitivity=sensitive -o atime=off "$DATASET"
	zfs create "$DATASET/test"
	zfs create "$DATASET/scratch"
fi
mkdir -p "$DIR/test" "$DIR/scratch"
chmod 0777 "$DIR/test" "$DIR/scratch"

# In the VM, stop the smbd of the earlier steps and its RPC daemons.
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

cat > "$CONF" <<CONF
[global]
    workgroup = WORKGROUP
    netbios name = FSTESTCI
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
    log file = $WORK/log.%m
    log level = 1
    max log size = 0
# Middleware writes these settings for the default purpose.
[fstest]
    path = $DIR/test
    read only = no
    vfs objects = $VFS
    smbd max xattr size = 2097152
    ea support = no
    posix locking = no
    smb3 unix extensions = no
    nfs4:mode = simple
    nfs4:acedup = merge
[fscratch]
    copy = fstest
    path = $DIR/scratch
CONF
printf '%s\n%s\n' "$USER_PASS" "$USER_PASS" |
	"$SMBPASSWD" -c "$CONF" -s -a "$USER_NAME" > /dev/null
"$SMBD" -D -s "$CONF"
for _ in $(seq 1 150); do
	ss -ltn | grep -q ':445 ' && break
	sleep 0.2
done
ss -ltn | grep -q ':445 ' || { echo "ERROR: smbd does not listen"; exit 1; }
trap stop EXIT

cat > "$SRC/local.config" <<CONF
export FSTYP=cifs
export TEST_DEV=//127.0.0.1/fstest
export TEST_DIR=/mnt/fstest
export SCRATCH_DEV=//127.0.0.1/fscratch
export SCRATCH_MNT=/mnt/fscratch
export CIFS_MOUNT_OPTIONS='$OPTS'
export TEST_FS_MOUNT_OPTS='$OPTS'
export RESULT_BASE=$WORK/results
CONF

echo "=========================================="
echo "fstests through cifs.ko: run"
echo "=========================================="
# shellcheck disable=SC2046 # one word per test
(cd "$SRC" && ./check $(tests_of "")) 2>&1 | tee "$WORK/check.out" || true

ran="$(sed -n 's/^Ran: //p' "$WORK/check.out")"
bad="$(sed -n 's/^Failures: //p; s/^Not run: //p' "$WORK/check.out")"
known="$(tests_of known)"
[ -n "$ran" ] || { echo "ERROR: fstests ran no test"; exit 1; }
FAILED=0
for t in $bad; do
	if echo "$known" | grep -qx "$t"; then
		echo "known  $t"
	else
		echo "FAIL   $t"
		FAILED=1
	fi
done
for t in $known; do
	echo "$bad" | tr ' ' '\n' | grep -qx "$t" ||
		echo "NOTE   $t passes now: remove \"known\" from fstests-cifs.list"
done
if grep -q 'PANIC\|INTERNAL ERROR' "$WORK"/log.* 2> /dev/null; then
	echo "FAIL   a panic in the smbd logs"
	FAILED=1
fi
echo "=========================================="
echo "fstests through cifs.ko: $(echo "$ran" | wc -w) ran, failed or" \
	"not run: ${bad:-none}"
echo "=========================================="
[ "$FAILED" = 0 ]
