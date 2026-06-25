#!/usr/bin/env bash

######################################################################
# Smoke-test the freshly-built TrueNAS Samba against a real ZFS dataset:
#   * load the ZFS kmod
#   * create a (case-insensitive) ZFS dataset
#   * serve it with `vfs objects = truenas_streams_xattr zfs_core`
#   * exercise basic I/O, a case-only rename (zfs_core_renameat) and an
#     alternate data stream (truenas_streams_xattr) over SMB
#   * run the `truenas` smbtorture suite (rename, streams cap/offset,
#     shadow_copy browse/readonly/listdir) against the share
#   * verify per-user ZFS dataset auto-creation (zfs_core:zfs_auto_create),
#     including on-disk ownership
#   * snapshot browsing via shadow_copy_zfs and Time Machine auto-snapshot
#     via tmprotect
#   * ACL<->Security-Descriptor mapping via ixnas on an NFSv4-ACL dataset
#   * a curated set of upstream smb2.* protocol regression suites against a
#     case-sensitive vanilla share
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
truncate -s 8G /var/tmp/zpool.img
zpool create -f tank /var/tmp/zpool.img
# casesensitivity is a create-time property; insensitive is the TrueNAS SMB default
zfs create -o casesensitivity=insensitive -o atime=off tank/share
SHARE=/tank/share
chmod 0777 "$SHARE"
# Separate dataset for the tmprotect (Time Machine) snapshot test.
zfs create -o atime=off tank/tm
chmod 0777 /tank/tm
# NFSv4-ACL dataset for the ixnas ACL<->Security-Descriptor mapping tests. The
# system.nfs4_acl_xdr xattr ixnas reads/writes is provided by the TrueNAS ZFS
# module (built here), so the mapping is testable; aclmode=passthrough lets the
# client install arbitrary ACLs.
zfs create -o acltype=nfsv4 -o aclmode=passthrough \
           -o casesensitivity=insensitive -o atime=off tank/acl
chmod 0777 /tank/acl
# Case-SENSITIVE plain dataset for upstream smb2.* protocol regression, so the
# generic suites aren't tripped by ZFS case-insensitivity.
zfs create -o casesensitivity=sensitive -o atime=off tank/vanilla
chmod 0777 /tank/vanilla
echo "Dataset:"; zfs get casesensitivity tank/share

echo "=========================================="
echo "Write smb.conf and start smbd"
echo "=========================================="
mkdir -p /etc/samba /var/log/samba4 /run/samba \
         /var/lib/truenas-samba/private /var/run/samba-lock /var/run/samba-cache
# Write to the build's default config path (/etc/smb4.conf) so the client
# tools (smbclient/smbpasswd/smbtorture) load it without an explicit -s; some,
# like smbpasswd, treat a missing default config as a fatal error.
cat > /etc/smb4.conf <<CONF
[global]
    workgroup = WORKGROUP
    # Without this the source4 smbtorture client gets a NULL workstation name,
    # which surfaces as a (misleading) NT_STATUS_NO_MEMORY at connect time.
    netbios name = SMBCITEST
    security = user
    map to guest = Bad User
    guest account = nobody
    passdb backend = tdbsam
    load printers = no
    printing = bsd
    disable spoolss = yes
    smbd: backgroundqueue = no
    # Cap per-stream xattr size below the stock 64KiB kernel limit so the
    # truenas.streams.cap_and_offset test hits the module's cap deterministically
    # (matches --option=torture:streams_cap=32768).
    smbd max xattr size = 32768
    log level = 1
    log file = /var/log/samba4/smbd.log

[ztest]
    path = $SHARE
    read only = no
    guest ok = yes
    vfs objects = truenas_streams_xattr zfs_core
    truenas_streams_xattr:xattr_compat = no

[zauto]
    # zfs_core auto-creates the per-user %U dataset via libzfs on connect.
    path = $SHARE/%U
    read only = no
    vfs objects = zfs_core
    zfs_core:zfs_auto_create = yes
    zfs_core:dataset_auto_quota = 1G

[zsc]
    # snapshot browsing via shadow_copy_zfs (@GMT- previous versions)
    path = $SHARE
    read only = no
    vfs objects = shadow_copy_zfs zfs_core

[ztm]
    # Time Machine auto-snapshot via tmprotect (triggered by the history plist)
    path = /tank/tm
    read only = no
    vfs objects = zfs_core tmprotect
    tmprotect:deferred_seconds = 1

[zacl]
    # ACL<->Security-Descriptor mapping via ixnas on an NFSv4-ACL dataset.
    # Object order follows middleware util_smbconf.py (ixnas before zfs_core).
    path = /tank/acl
    read only = no
    vfs objects = ixnas zfs_core
    nfs4:mode = simple
    nfs4:acedup = merge

[zvanilla]
    # Case-sensitive plain share (no fork VFS objects) for upstream smb2.*
    # protocol regression -- isolates protocol semantics from module quirks.
    path = /tank/vanilla
    read only = no
CONF

testparm -s /etc/smb4.conf >/dev/null && echo "testparm: OK"

# Run at the config's "log level = 1": at d10 the per-connection root-user
# sec-ctx spam buries the actual smbtorture failures in the on-error log tails
# (and is unmanageable across the full suite set). Raise -d selectively if a
# specific VFS path needs tracing again.
"$SMBD" -D -s /etc/smb4.conf
sleep 3
pgrep -x smbd >/dev/null && echo "smbd is running" || { echo "ERROR: smbd not running"; tail -50 /var/log/samba4/smbd.log; exit 1; }

SMBCLIENT="smbclient //127.0.0.1/ztest -N"

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
# Smoke check only -- the gating stream coverage is the truenas.streams torture
# test. Keep it non-fatal so an smbclient/allinfo quirk can't abort the run, and
# print what allinfo returns for diagnosis.
if $SMBCLIENT -c 'put /tmp/ads.txt FOO:adstream'; then
  ads_info="$($SMBCLIENT -c 'allinfo FOO' 2>&1 || true)"
  echo "$ads_info"
  if echo "$ads_info" | grep -qi 'adstream'; then
    echo "ADS visible via SMB"
    if $SMBCLIENT -c 'get FOO:adstream /tmp/ads.out' && cmp -s /tmp/ads.txt /tmp/ads.out; then
      echo "ADS round-trip OK"
    else
      echo "WARN: ADS read-back failed/mismatch; continuing"
    fi
  else
    echo "WARN: adstream not listed by allinfo; continuing"
  fi
else
  echo "WARN: ADS write via smbclient failed; continuing"
fi

echo "=========================================="
echo "Run the truenas smbtorture suite"
echo "=========================================="
# smbtorture needs an authenticated user (the smbclient checks above used guest).
useradd -M -s /usr/sbin/nologin smbtest 2>/dev/null || true
printf 'testpass123\ntestpass123\n' | smbpasswd -a -s smbtest
# Grant SeDiskOperatorPrivilege: smbd/fake_file.c gates the $Extend\$Quota fake
# file (and quota get/set) on SEC_PRIV_DISK_OPERATOR, so without it the upstream
# quota tests fail with ACCESS_DENIED. net writes it to the local tdbsam; smbd
# picks it up at session setup.
net sam rights grant smbtest SeDiskOperatorPrivilege \
  && echo "granted SeDiskOperatorPrivilege to smbtest" \
  || echo "WARN: could not grant SeDiskOperatorPrivilege (quota tests may ACCESS_DENIED)"
SMBTORTURE="$(command -v smbtorture || echo /usr/bin/smbtorture)"
test -x "$SMBTORTURE" || { echo "ERROR: smbtorture not found (expected in truenas-samba)"; exit 1; }
echo "smbtorture: $SMBTORTURE"
# ztest is casesensitivity=insensitive with zfs_core + truenas_streams_xattr, so
# truenas.rename.case_insensitive and truenas.streams.cap_and_offset run here.
# truenas.shadow_copy.* and truenas.acl.* self-skip on this share (no
# shadow_copy_zfs; not an ixnas NFSv4 share) -- they run against zsc/zacl below.
# The streams cap matches the global "smbd max xattr size"; a TrueNAS-kernel CI
# can raise both to exercise multi-MiB streams.
if "$SMBTORTURE" //127.0.0.1/ztest -U 'smbtest%testpass123' \
     --option='torture:streams_cap=32768' truenas; then
  echo "truenas smbtorture suite PASSED"
else
  echo "ERROR: truenas smbtorture suite FAILED"; tail -80 /var/log/samba4/smbd.log; exit 1
fi

echo "=========================================="
echo "Per-user dataset auto-creation (zfs_core:zfs_auto_create)"
echo "=========================================="
# Connecting to the %U share makes zfs_core create tank/share/smbtest via
# libzfs during connect (no middleware). The assertion is ZFS-level, so it is
# verified here rather than in client-side smbtorture.
zfs destroy -r tank/share/smbtest 2>/dev/null || true
smbclient //127.0.0.1/zauto -U 'smbtest%testpass123' -c 'ls' \
  || { echo "ERROR: connect to auto-create share failed"; tail -60 /var/log/samba4/smbd.log; exit 1; }
if zfs list -H -o name tank/share/smbtest >/dev/null 2>&1; then
  echo "zfs_core auto-created dataset: tank/share/smbtest"
  zfs list -j tank/share/smbtest 2>/dev/null || zfs list -o name,used,mountpoint tank/share/smbtest
else
  echo "ERROR: zfs_core did not create tank/share/smbtest"; zfs list -r tank; exit 1
fi
# zfs_core chowns the auto-created dataset to the connecting user (chown_homedir,
# default on). Assert the on-disk owner is smbtest, not root.
auto_owner="$(stat -c %U /tank/share/smbtest 2>/dev/null || echo '?')"
if [ "$auto_owner" = "smbtest" ]; then
  echo "auto-created dataset owned by connecting user: smbtest"
else
  echo "ERROR: tank/share/smbtest owner is [$auto_owner], expected smbtest"; exit 1
fi

echo "=========================================="
echo "Snapshot browsing via shadow_copy_zfs"
echo "=========================================="
# Write old content, snapshot, then overwrite the live file. The test
# enumerates the snapshot over SMB (FSCTL_SRV_ENUM_SNAPS) and opens the file at
# the server's own @GMT- label, so nothing is computed here.
printf 'snapshot-version' > "$SHARE/sc_canary"
zfs snapshot tank/share@sc1
printf 'live-version' > "$SHARE/sc_canary"
# Probe the snapshot at the FS level first -- this isolates a ZFS snapshot
# automount problem (.zfs/snapshot/<snap> not accessible) from an SMB-layer
# bug. shadow_copy_zfs resolves to /tank/share/.zfs/snapshot/sc1/<file>.
echo "--- FS-level snapshot access ---"
ls -la /tank/share/.zfs/snapshot/ 2>&1 || echo "  (.zfs/snapshot listing failed)"
if out=$(cat /tank/share/.zfs/snapshot/sc1/sc_canary 2>&1); then
  echo "  FS-level snapshot read OK: [$out]"
else
  echo "  FS-level snapshot read FAILED ($out) -> ZFS automount issue, not SMB"
fi
if "$SMBTORTURE" //127.0.0.1/zsc -U 'smbtest%testpass123' \
     --option='torture:sc_file=sc_canary' \
     --option='torture:sc_expect=snapshot-version' \
     truenas.shadow_copy; then
  echo "shadow_copy browse PASSED"
else
  echo "ERROR: shadow_copy browse FAILED"
  echo "--- smbd debug: shadow_copy open path ---"
  grep -iE "shadowzfs|get_snapshot_path|do_convert|\.zfs/snapshot|sc_canary|snapdir|open_snapdir|openat.*zfs|No such|OBJECT_PATH|EXDEV|NOT_SAME" /var/log/samba4/smbd.log | tail -50
  exit 1
fi

echo "=========================================="
echo "Time Machine auto-snapshot via tmprotect"
echo "=========================================="
# Writing the TM SnapshotHistory.plist (with a backup-completion date) then
# disconnecting makes tmprotect take a zfs snapshot (aapltm-*) inline via its
# disconnect-time fallback -- no need to wait on the deferred timer.
TM_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > /tmp/tmhist.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Snapshots</key>
  <array>
    <dict>
      <key>com.apple.backupd.SnapshotCompletionDate</key>
      <date>$TM_TS</date>
      <key>com.apple.backupd.SnapshotName</key>
      <string>ci.backup</string>
    </dict>
  </array>
</dict>
</plist>
PLIST
smbclient //127.0.0.1/ztm -U 'smbtest%testpass123' \
  -c 'put /tmp/tmhist.plist com.apple.TimeMachine.SnapshotHistory.plist' \
  || { echo "ERROR: TM plist put failed"; tail -60 /var/log/samba4/smbd.log; exit 1; }
sleep 3
if zfs list -t snapshot -H -o name | grep -q '^tank/tm@aapltm-'; then
  echo "tmprotect created a snapshot:"; zfs list -t snapshot -H -o name | grep '^tank/tm@'
else
  echo "ERROR: tmprotect did not create a snapshot"; zfs list -t snapshot -r tank/tm; exit 1
fi

echo "=========================================="
echo "ACL <-> Security-Descriptor mapping (ixnas)"
echo "=========================================="
# ixnas maps the ZFS NFSv4 ACL to a Windows SD over SMB. Gate on the ZFS module
# actually exposing system.nfs4_acl_xdr -- a stock OpenZFS build would lack it
# and ixnas self-disables. Mapping only; kernel access-check edge cases (delete,
# ABE) need the patched base kernel and are not asserted here.
if python3 -c "import os; os.getxattr('/tank/acl', 'system.nfs4_acl_xdr')" 2>/dev/null; then
  if "$SMBTORTURE" //127.0.0.1/zacl -U 'smbtest%testpass123' \
       --option='torture:acl_nfs4=yes' truenas.acl; then
    echo "truenas.acl mapping suite PASSED"
  else
    echo "ERROR: truenas.acl mapping suite FAILED"; tail -80 /var/log/samba4/smbd.log; exit 1
  fi
else
  echo "WARN: ZFS does not expose system.nfs4_acl_xdr on /tank/acl; skipping ACL suite"
fi

echo "=========================================="
echo "Upstream SMB2 protocol regression (vanilla share)"
echo "=========================================="
# Upstream suites that pass cleanly against this plain ZFS share. The broader
# smb2.* set (create/rename/dir/lock/read/rw/getinfo/setinfo/compound/
# compound_async/notify/fileid/name-mangling/charset) is deferred: those assume
# Samba's selftest reference share (streams + EAs + an ACL backend) and an
# extensive per-test knownfail list, which is out of scope for this smoke test.
# Each suite runs independently; the step fails if any regress.
SMB2_SUITES="smb2.compound_find smb2.sharemode smb2.deny \
smb2.ioctl.copy_chunk_simple smb2.ioctl.copy_chunk_multi smb2.ioctl.copy_chunk_tiny"
smb2_fail=0
set +e
for s in $SMB2_SUITES; do
  if "$SMBTORTURE" //127.0.0.1/zvanilla -U 'smbtest%testpass123' "$s" \
       >"/tmp/tort-$s.log" 2>&1; then
    echo "  PASS $s"
  else
    echo "  FAIL $s"; smb2_fail=$((smb2_fail + 1))
    # Surface every failing subtest (a blind tail misses failures that scroll
    # off when later subtests in the same suite pass).
    grep -A2 -E '^(failure|error):' "/tmp/tort-$s.log" | head -60
  fi
done
set -e
if [ "$smb2_fail" -ne 0 ]; then
  echo "ERROR: $smb2_fail upstream smb2 suite(s) failed"; exit 1
fi
echo "all upstream smb2 suites passed"

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
