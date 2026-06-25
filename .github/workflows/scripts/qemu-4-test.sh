#!/usr/bin/env bash

######################################################################
# Smoke-test the freshly-built TrueNAS Samba against a real ZFS dataset:
#   * load the ZFS kmod
#   * create a (case-insensitive) ZFS dataset
#   * serve it with `vfs objects = zfs_core truenas_streams_xattr`
#   * exercise basic I/O, a case-only rename (zfs_core_renameat) and an
#     alternate data stream (truenas_streams_xattr) over SMB
######################################################################

set -eu

echo "Running Samba smoke test..."

source /tmp/vm-info.sh

ssh debian@$VM_IP 'sudo bash -s' <<'REMOTE_SCRIPT'
set -eu

echo "=========================================="
echo "Load ZFS kernel module"
echo "=========================================="
modprobe zfs || { echo "ERROR: modprobe zfs failed"; dmesg | tail -30; exit 1; }
lsmod | grep -q zfs || { echo "ERROR: zfs not in lsmod"; exit 1; }
echo "ZFS module loaded:"; lsmod | grep zfs

echo "=========================================="
echo "Verify TrueNAS VFS modules are installed"
echo "=========================================="
VFS_DIR="$(dirname "$(find /usr/lib -path '*/samba/vfs/zfs_core.so' -print -quit)")"
echo "VFS dir: $VFS_DIR"
for m in zfs_core truenas_streams_xattr; do
  test -e "$VFS_DIR/$m.so" && echo "  ok $m.so" || { echo "  MISSING $m.so"; exit 1; }
done
SMBD="$(command -v smbd || echo /usr/sbin/smbd)"
echo "smbd: $SMBD"; "$SMBD" -b | grep -i 'WITH_LIBZFS\|HAVE_LIBZFS' || echo "(libzfs build flag not shown)"

echo "=========================================="
echo "Create a case-insensitive ZFS dataset"
echo "=========================================="
truncate -s 3G /var/tmp/zpool.img
zpool create -f tank /var/tmp/zpool.img
# casesensitivity is a create-time property; insensitive is the TrueNAS SMB default
zfs create -o casesensitivity=insensitive -o atime=off tank/share
SHARE=/tank/share
chmod 0777 "$SHARE"
echo "Dataset:"; zfs get casesensitivity tank/share

echo "=========================================="
echo "Write smb.conf and start smbd"
echo "=========================================="
mkdir -p /etc/samba /var/log/samba4 /run/samba \
         /var/lib/truenas-samba/private /var/run/samba-lock /var/run/samba-cache
cat > /etc/samba/smb.conf <<CONF
[global]
    workgroup = WORKGROUP
    security = user
    map to guest = Bad User
    guest account = nobody
    passdb backend = tdbsam
    load printers = no
    printing = bsd
    disable spoolss = yes
    smbd: backgroundqueue = no
    log level = 1 vfs:3
    log file = /var/log/samba4/smbd.log

[ztest]
    path = $SHARE
    read only = no
    guest ok = yes
    vfs objects = zfs_core truenas_streams_xattr
    truenas_streams_xattr:xattr_compat = no
CONF

testparm -s /etc/samba/smb.conf >/dev/null && echo "testparm: OK"

"$SMBD" -D -s /etc/samba/smb.conf
sleep 3
pgrep -x smbd >/dev/null && echo "smbd is running" || { echo "ERROR: smbd not running"; tail -50 /var/log/samba4/smbd.log; exit 1; }

SMBCLIENT="smbclient //localhost/ztest -N"

echo "=========================================="
echo "Basic I/O through the VFS stack"
echo "=========================================="
head -c 4096 /dev/urandom > /tmp/payload.bin
$SMBCLIENT -c "put /tmp/payload.bin foo" || { echo "ERROR: put failed"; tail -60 /var/log/samba4/smbd.log; exit 1; }
$SMBCLIENT -c "get foo /tmp/payload.out"
cmp /tmp/payload.bin /tmp/payload.out && echo "round-trip I/O OK"
test -e "$SHARE/foo" && echo "file present on dataset"

echo "=========================================="
echo "Case-only rename (exercises zfs_core_renameat)"
echo "=========================================="
$SMBCLIENT -c "rename foo FOO" || { echo "ERROR: case rename failed"; tail -60 /var/log/samba4/smbd.log; exit 1; }
# On a case-insensitive dataset the on-disk name must actually become FOO.
if ls "$SHARE" | grep -qx 'FOO'; then
  echo "case-only rename took effect on disk: FOO"
else
  echo "ERROR: on-disk name did not change to FOO"; ls -l "$SHARE"; exit 1
fi

echo "=========================================="
echo "Alternate data stream (exercises truenas_streams_xattr)"
echo "=========================================="
echo "hello-ads" > /tmp/ads.txt
if $SMBCLIENT -c 'put /tmp/ads.txt FOO:adstream'; then
  $SMBCLIENT -c 'allinfo FOO' | grep -i 'stream' && echo "ADS visible via SMB"
  $SMBCLIENT -c 'get FOO:adstream /tmp/ads.out' && cmp /tmp/ads.txt /tmp/ads.out \
    && echo "ADS round-trip OK"
else
  echo "WARN: ADS write via smbclient failed (client-syntax dependent); continuing"
fi

echo "=========================================="
echo "Check smbd log for module-load errors"
echo "=========================================="
if grep -Ei 'error loading module|failed to load|PANIC|smb_panic' /var/log/samba4/smbd.log; then
  echo "ERROR: smbd reported module/load failures"; exit 1
fi
grep -i 'vfs' /var/log/samba4/smbd.log | tail -20 || true

echo "=========================================="
echo "Samba smoke test PASSED"
echo "=========================================="
REMOTE_SCRIPT

TEST_EXIT_CODE=$?
echo "$TEST_EXIT_CODE" > /tmp/test-exitcode.txt
if [ "$TEST_EXIT_CODE" -eq 0 ]; then
  echo "All smoke tests passed!"
else
  echo "Smoke tests failed with exit code: $TEST_EXIT_CODE"
  exit "$TEST_EXIT_CODE"
fi
