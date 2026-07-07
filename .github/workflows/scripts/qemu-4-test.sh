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
#   * verify per-user auto-creation with vfs_fruit + ixnas in the stack
#     inherits the parent dataset's NFSv4 ACL into the new dataset -- the
#     regression where zfs_inherit_acls' connect-time stat routed through
#     fruit's cwd_fsp-relative stat and failed EBADF -> ACCESS_DENIED
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
for m in zfs_core truenas_streams_xattr truenas_recycle; do
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
# module (built here), so the mapping is testable. aclmode=passthrough lets the
# client install arbitrary ACLs; aclinherit=passthrough matches the TrueNAS SMB
# default so inherited ACEs keep WRITE_ACL/WRITE_OWNER and no mode-derived
# owner@/group@ is synthesised -- a child of an everyone@:full dir inherits the
# full set (as production does), not the restricted-default stripped form.
zfs create -o acltype=nfsv4 -o aclmode=passthrough -o aclinherit=passthrough \
           -o casesensitivity=insensitive -o atime=off tank/acl
chmod 0777 /tank/acl
# NFSv4-ACL dataset for the per-user auto-creation + ACL-inheritance test
# ([zhome]). Same NFSv4/passthrough setup as tank/acl so an inheritable ACL
# seeded here propagates into the dataset zfs_core auto-creates on connect.
zfs create -o acltype=nfsv4 -o aclmode=passthrough -o aclinherit=passthrough \
           -o casesensitivity=insensitive -o atime=off tank/home
chmod 0777 /tank/home
# Case-SENSITIVE plain dataset for upstream smb2.* protocol regression, so the
# generic suites aren't tripped by ZFS case-insensitivity.
zfs create -o casesensitivity=sensitive -o atime=off tank/vanilla
chmod 0777 /tank/vanilla
# Per-user recycle bin (vfs_truenas_recycle) validation datasets, one per ACL
# flavour. The NFSv4 one is aclmode=restricted on purpose: that is the case
# where a chmod of an inherited ACL fails EPERM, so recycle must set the bin
# descriptor via an ACL set. aclinherit=passthrough matches the SMB default.
zfs create -o acltype=posix -o casesensitivity=insensitive -o atime=off tank/recp
chmod 0777 /tank/recp
zfs create -o acltype=nfsv4 -o aclmode=restricted -o aclinherit=passthrough \
           -o casesensitivity=insensitive -o atime=off tank/recn
chmod 0777 /tank/recn
# Nested child dataset mounted inside the [zrecn] share: proves a delete on a
# child dataset recycles into that dataset's own bin (same mount, no EXDEV purge).
zfs create -o acltype=nfsv4 -o aclmode=restricted -o aclinherit=passthrough \
           -o casesensitivity=insensitive -o atime=off tank/recn/child
chmod 0777 /tank/recn/child
# POSIX dataset for the AD-layout recycle test (recycle:repository=.recycle/%D/%U),
# exercising the two-level shared parent chain (.recycle and .recycle/<domain>).
zfs create -o acltype=posix -o casesensitivity=insensitive -o atime=off tank/recad
chmod 0777 /tank/recad
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

[zhome]
    # Per-user dataset auto-creation with the *full* production-shaped stack:
    # vfs_fruit (whose cwd_fsp-relative stat triggered the regression) + the
    # ixnas ACL mapping, so zfs_core's connect-time ACL inheritance runs and is
    # observable on disk. Object order follows middleware util_smbconf.py
    # (fruit, streams, ixnas, then zfs_core). fruit:nfs_aces=no keeps fruit out
    # of the ACL it would otherwise synthesise, leaving the ixnas/ZFS view clean.
    path = /tank/home/%U
    read only = no
    vfs objects = fruit truenas_streams_xattr ixnas zfs_core
    zfs_core:zfs_auto_create = yes
    zfs_core:dataset_auto_quota = 1G
    fruit:nfs_aces = no
    nfs4:mode = simple
    nfs4:acedup = merge

[zvanilla]
    # Case-sensitive plain share (no fork VFS objects) for upstream smb2.*
    # protocol regression -- isolates protocol semantics from module quirks.
    path = /tank/vanilla
    read only = no

[zrecp]
    # Per-user recycle bin on a POSIX-ACL dataset.
    path = /tank/recp
    read only = no
    vfs objects = truenas_recycle zfs_core
    recycle:repository = .recycle/%U
    recycle:keeptree = yes
    recycle:subdir_mode = 0700

[zrecn]
    # Per-user recycle bin on an NFSv4-ACL dataset (aclmode=restricted). Object
    # order follows middleware util_smbconf.py: ixnas, recycle, zfs_core.
    path = /tank/recn
    read only = no
    vfs objects = ixnas truenas_recycle zfs_core
    nfs4:mode = simple
    nfs4:acedup = merge
    recycle:repository = .recycle/%U
    recycle:keeptree = yes
    recycle:subdir_mode = 0700

[zrecad]
    # AD repository layout: two shared parents (.recycle and .recycle/%D) above
    # the per-user leaf. %D resolves to the workgroup for the standalone user.
    path = /tank/recad
    read only = no
    vfs objects = truenas_recycle zfs_core
    recycle:repository = .recycle/%D/%U
    recycle:keeptree = yes
    recycle:subdir_mode = 0700
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

  # ---- Advertisement-only proof: SMB demotes group@, on-disk (NFS view) ACL is
  # left untouched. ixnas strips WRITE_ACL/WRITE_OWNER from group@ in the SD it
  # reports (a group member cannot convey them there), while owner@, everyone@
  # and named entries keep them. truenas_setfacl lays down a fixture carrying
  # them on disk; truenas.acl.fixture_scope checks the SMB view; and
  # truenas_getfacl before/after proves the GET never rewrote the stored ACL.
  # Best-effort: truenas_pyos builds a C extension (needs gcc + libbsd-dev), so
  # skip without failing the run if it cannot be installed.
  echo "--- ixnas demote: on-disk ACL untouched (truenas_pyos) ---"
  # truenas_pyos builds a C extension and is pip-installed from git, so it needs
  # pip + Python headers + libbsd-dev (gcc/git are already present from the
  # ZFS/Samba build). Trixie ships no pip by default -- without python3-pip the
  # install fails "No module named pip" and fixture_scope silently self-skips.
  apt-get install -y --no-install-recommends \
    python3-pip python3-dev libbsd-dev >/dev/null 2>&1 || true
  if python3 -m pip install --break-system-packages --quiet \
       "git+https://github.com/truenas/truenas_pyos" >/tmp/pyos-install.log 2>&1 \
     && command -v truenas_setfacl >/dev/null 2>&1; then
    assert_ondisk_owner_full() {
      truenas_getfacl -j -n "$1" | python3 -c '
import sys, json
acl = json.loads(sys.stdin.read())
o = next((set(e["perms"]) for e in acl["aces"] if e["who"] == "owner@"), None)
assert o is not None, "no owner@ entry on disk"
assert "WRITE_ACL" in o and "WRITE_OWNER" in o, \
    "owner@ lacks WRITE_ACL/WRITE_OWNER on disk"
'
    }
    FIX=/tank/acl/pyfix
    : > "$FIX"; chown smbtest:smbtest "$FIX"
    # owner@/group@/everyone@ + a named user (root) all Full Control, so the
    # stored ACL carries WRITE_ACL(C)+WRITE_OWNER(o) on every entry.
    truenas_setfacl -m 'owner@:full_set::allow,group@:full_set::allow,everyone@:full_set::allow,user:0:full_set::allow' "$FIX"
    echo "on-disk ACL (before SMB GET):"; truenas_getfacl -n "$FIX" || true
    assert_ondisk_owner_full "$FIX" \
      || { echo "ERROR: fixture setup -- owner@ lacks WRITE_ACL/WRITE_OWNER on disk"; exit 1; }
    if "$SMBTORTURE" //127.0.0.1/zacl -U 'smbtest%testpass123' \
         --option='torture:acl_nfs4=yes' --option='torture:acl_fixture=pyfix' \
         truenas.acl.fixture_scope; then
      echo "truenas.acl.fixture_scope PASSED (SMB demotes group@, keeps owner@/everyone@/named)"
    else
      echo "ERROR: truenas.acl.fixture_scope FAILED"; tail -80 /var/log/samba4/smbd.log; exit 1
    fi
    assert_ondisk_owner_full "$FIX" \
      || { echo "ERROR: SMB GET mutated the on-disk ACL (owner@ lost WRITE_ACL/WRITE_OWNER)"; exit 1; }
    echo "on-disk ACL unchanged by SMB GET -- advertisement-only confirmed"
    rm -f "$FIX"
  else
    echo "WARN: truenas_pyos unavailable; skipping on-disk advertisement-only check"
    tail -3 /tmp/pyos-install.log 2>/dev/null || true
  fi
else
  echo "WARN: ZFS does not expose system.nfs4_acl_xdr on /tank/acl; skipping ACL suite"
fi

echo "=========================================="
echo "Per-user dataset auto-creation + ACL inheritance (fruit + ixnas stack)"
echo "=========================================="
# Regression guard for zfs_core's connect-time ACL inheritance with vfs_fruit in
# the stack. Connecting to [zhome] makes zfs_core create tank/home/smbtest via
# libzfs and run zfs_inherit_acls(parent=tank/home, child=smbtest). That helper
# stats the just-created child; with fruit's cwd_fsp-relative stat and the
# connection's not-yet-valid cwd_fsp that failed EBADF -> ACCESS_DENIED, so a
# successful connect + dataset creation here already gates the fix.
zfs destroy -r tank/home/smbtest 2>/dev/null || true

# Seed the parent dataset with a DISTINCTIVE inheritable ACE (named user root,
# file+dir inherit) so the inheritance check proves the child got *this* entry,
# not merely that it has some non-trivial ACL. owner@/group@/everyone@ are made
# inheritable too so the auto-created child stays traversable by its owner.
# truenas_setfacl/getfacl come from truenas_pyos, installed best-effort by the
# ixnas section above; if absent, the connect+create assertions still run.
MARKER_SET=0
if command -v truenas_setfacl >/dev/null 2>&1; then
  if truenas_setfacl -m 'owner@:full_set:fd:allow,group@:modify_set:fd:allow,everyone@:modify_set:fd:allow,user:0:modify_set:fd:allow' /tank/home; then
    MARKER_SET=1
    echo "seeded inheritable ACL on /tank/home:"; truenas_getfacl -n /tank/home || true
  else
    echo "WARN: could not seed inheritable ACL on /tank/home"
  fi
fi

smbclient //127.0.0.1/zhome -U 'smbtest%testpass123' -c 'ls' \
  || { echo "ERROR: connect to [zhome] failed -- zfs_inherit_acls EBADF regression under fruit?"; tail -80 /var/log/samba4/smbd.log; exit 1; }

if zfs list -H -o name tank/home/smbtest >/dev/null 2>&1; then
  echo "zfs_core auto-created tank/home/smbtest (fruit + ixnas in stack)"
else
  echo "ERROR: zfs_core did not create tank/home/smbtest"; zfs list -r tank/home; exit 1
fi
home_owner="$(stat -c %U /tank/home/smbtest 2>/dev/null || echo '?')"
if [ "$home_owner" = "smbtest" ]; then
  echo "auto-created dataset owned by connecting user: smbtest"
else
  echo "ERROR: tank/home/smbtest owner is [$home_owner], expected smbtest"; exit 1
fi

# Explicit ACL inheritance check: the auto-created child dataset must carry the
# parent's distinctive inheritable named ACE (user:0). truenas_getfacl -j emits
# per-ACE {who, perms[], flags[], type} using truenas_os NFS4Flag names, so we
# look for who=user:0 still flagged inheritable (FILE_INHERIT/DIRECTORY_INHERIT).
# A freshly created ZFS dataset has only a trivial owner@/group@/everyone@ ACL,
# so a named user:0 entry can only be there because it was inherited from the
# parent -- that presence is the proof of inheritance. We deliberately do NOT
# require the per-ACE INHERITED flag: the ixnas backend maps the parent ACL into
# a security descriptor without SEC_DESC_DACL_AUTO_INHERITED, so Samba's
# se_create_child_secdesc() never stamps SEC_ACE_FLAG_INHERITED_ACE onto the
# propagated ACEs (that round-trip lives only in the nfs4acl_xattr backend).
if [ "$MARKER_SET" = 1 ]; then
  echo "on-disk ACL of auto-created dataset:"; truenas_getfacl -n /tank/home/smbtest || true
  if truenas_getfacl -j -n /tank/home/smbtest | python3 -c '
import sys, json
acl = json.loads(sys.stdin.read())
inh = [a for a in acl["aces"] if a["who"] == "user:0"
       and ({"FILE_INHERIT", "DIRECTORY_INHERIT"} & set(a["flags"]))]
assert not acl["trivial"], "child dataset ACL is trivial; nothing was inherited"
assert inh, "parent inheritable ACE absent on child: " + json.dumps(acl["aces"])
print("inherited ACE present on child:", inh[0])
'; then
    echo "explicit ACL inheritance verified on auto-created dataset"
  else
    echo "ERROR: auto-created dataset did not inherit parent ACL"; tail -80 /var/log/samba4/smbd.log; exit 1
  fi
else
  echo "WARN: truenas_pyos/truenas_setfacl unavailable; skipped explicit ACL-inheritance assertion (connect+create still gated above)"
fi

echo "=========================================="
echo "Per-user recycle bin (truenas_recycle): POSIX + NFSv4"
echo "=========================================="
# Delete a file over SMB and prove truenas_recycle moved it into the per-user
# bin <share>/.recycle/<user>/; that the bin was created (under become_root)
# owned by the connecting user while the shared .recycle parent stays root-owned;
# and that recycle:keeptree preserved the sub-path. Run on both ACL flavours.
# The NFSv4 dataset is aclmode=restricted, where a chmod of the inherited ACL
# would EPERM -- a correctly ACL'd bin there proves recycle set the descriptor
# via an ACL set, not a chmod.
recycle_smoke() {
  local share="$1" root="$2" flavour="$3"
  local bin="$root/.recycle/smbtest"
  echo "--- [$share] $flavour ($root) ---"
  rm -rf "$root/.recycle" "$root/sub" 2>/dev/null || true

  echo "recycle-me" > /tmp/rec.txt
  smbclient "//127.0.0.1/$share" -U 'smbtest%testpass123' \
    -c 'put /tmp/rec.txt top.txt; rm top.txt' \
    || { echo "ERROR: [$share] top-level put/rm failed"; tail -60 /var/log/samba4/smbd.log; exit 1; }
  test -f "$bin/top.txt" \
    || { echo "ERROR: [$share] top.txt not recycled to $bin/"; ls -laR "$root/.recycle" 2>/dev/null; tail -40 /var/log/samba4/smbd.log; exit 1; }

  smbclient "//127.0.0.1/$share" -U 'smbtest%testpass123' \
    -c 'mkdir sub; put /tmp/rec.txt sub\deep.txt; rm sub\deep.txt' \
    || { echo "ERROR: [$share] keeptree put/rm failed"; exit 1; }
  test -f "$bin/sub/deep.txt" \
    || { echo "ERROR: [$share] keeptree file not recycled to $bin/sub/"; ls -laR "$root/.recycle"; exit 1; }

  local bin_owner parent_owner
  bin_owner="$(stat -c %U "$bin")"
  parent_owner="$(stat -c %U "$root/.recycle")"
  [ "$bin_owner" = "smbtest" ] \
    || { echo "ERROR: [$share] bin owner [$bin_owner] != smbtest"; exit 1; }
  [ "$parent_owner" = "root" ] \
    || { echo "ERROR: [$share] .recycle parent owner [$parent_owner] != root"; exit 1; }
  echo "  [$share] recycled top-level + keeptree; bin owned by smbtest, parent by root"
}

recycle_smoke zrecp /tank/recp POSIX

# Seed the NFSv4 share root with a distinctive inheritable ACL so the shared
# .recycle parent inherits it (recycle no longer hardcodes a grant). everyone@
# is made inheritable so the connecting user can traverse to its bin; user:0 is
# the distinctive marker asserted on .recycle afterwards. Best-effort:
# truenas_setfacl comes from truenas_pyos (installed by the ixnas section).
REC_INHERIT=0
if command -v truenas_setfacl >/dev/null 2>&1; then
  if truenas_setfacl -m 'owner@:full_set:fd:allow,group@:modify_set:fd:allow,everyone@:modify_set:fd:allow,user:0:modify_set:fd:allow' /tank/recn; then
    REC_INHERIT=1
    echo "seeded inheritable ACL on /tank/recn:"; truenas_getfacl -n /tank/recn || true
  fi
fi

recycle_smoke zrecn /tank/recn NFSv4-restricted

# The shared .recycle parent must carry the share root's inherited ACL (proof
# recycle inherits rather than granting world): look for the distinctive user:0
# marker still flagged inheritable on .recycle itself.
if [ "$REC_INHERIT" = 1 ]; then
  echo "--- [zrecn] .recycle inherited from share root ---"
  truenas_getfacl -n /tank/recn/.recycle || true
  if truenas_getfacl -j -n /tank/recn/.recycle | python3 -c '
import sys, json
acl = json.loads(sys.stdin.read())
inh = [a for a in acl["aces"] if a["who"] == "user:0"
       and ({"FILE_INHERIT", "DIRECTORY_INHERIT"} & set(a["flags"]))]
assert inh, "shared .recycle did not inherit share-root ACE: " + json.dumps(acl["aces"])
# A: the seed put everyone@/group@/user:0 :modify (write) here; the parent
# lockdown must have stripped every non-owner ALLOW ACE to read+traverse.
WRITE = {"WRITE_DATA", "APPEND_DATA", "WRITE_NAMED_ATTRS", "WRITE_ATTRIBUTES",
         "DELETE_CHILD", "WRITE_ACL", "WRITE_OWNER"}
writable = [a for a in acl["aces"]
            if a["type"] == "allow" and a["who"] != "owner@"
            and (WRITE & set(a["perms"]))]
assert not writable, "shared .recycle grants write to a non-owner: " + json.dumps(writable)
print("inherited ACE on .recycle:", inh[0]["who"], "| non-owner write stripped: ok")
'; then
    echo "  [zrecn] .recycle inherited the share-root ACL"
  else
    echo "ERROR: [zrecn] .recycle did not inherit the share-root ACL"; exit 1
  fi
fi

# NFSv4: the per-user bin must carry an inheritable ALLOW entry for the user
# (best-effort; truenas_getfacl comes from truenas_pyos, installed by the ixnas
# section). A non-trivial ACL with an inheritable user ACE proves the descriptor
# was set through the stack under aclmode=restricted.
if command -v truenas_getfacl >/dev/null 2>&1; then
  echo "--- [zrecn] per-user bin ACL (NFSv4) ---"
  truenas_getfacl -n /tank/recn/.recycle/smbtest || true
  if truenas_getfacl -j -n /tank/recn/.recycle/smbtest | python3 -c '
import sys, json
acl = json.loads(sys.stdin.read())
assert not acl["trivial"], "bin ACL is trivial; ACL set did not take"
uinh = [a for a in acl["aces"]
        if (a["who"] == "owner@" or a["who"].startswith("user:"))
        and a["type"] == "allow"
        and {"FILE_INHERIT", "DIRECTORY_INHERIT"} <= set(a["flags"])]
assert uinh, "no inheritable user ALLOW ACE on bin: " + json.dumps(acl["aces"])
ginh = [a for a in acl["aces"] if a["who"].startswith("group:")
        and a["type"] == "allow"
        and {"FILE_INHERIT", "DIRECTORY_INHERIT"} <= set(a["flags"])]
print("inheritable user ACE:", uinh[0]["who"],
      "| inheritable group (admins) ACE:", ginh[0]["who"] if ginh else "(none)")
'; then
    echo "  [zrecn] bin ACL verified under aclmode=restricted"
  else
    echo "ERROR: [zrecn] bin ACL missing inheritable user entry"; exit 1
  fi
else
  echo "WARN: truenas_getfacl unavailable; skipped NFSv4 bin-ACL assertion (recycle behaviour still gated above)"
fi

# Nested child dataset: a delete on tank/recn/child is on a *different mount*
# than the share root, so a single share-root bin would EXDEV-purge it. It must
# instead recycle into the child dataset's own bin, and must not touch the
# child dataset root (the mountpoint) itself.
echo "--- [zrecn] nested child dataset (cross-dataset recycle) ---"
rm -rf /tank/recn/child/.recycle 2>/dev/null || true
echo recycle-me > /tmp/rec.txt
smbclient //127.0.0.1/zrecn -U 'smbtest%testpass123' \
  -c 'put /tmp/rec.txt child\nested.txt; rm child\nested.txt' \
  || { echo "ERROR: [zrecn] child-dataset put/rm failed"; tail -40 /var/log/samba4/smbd.log; exit 1; }
test -f /tank/recn/child/.recycle/smbtest/nested.txt \
  || { echo "ERROR: [zrecn] child-dataset file not recycled to its own bin (EXDEV purge?)"; ls -laR /tank/recn/child/.recycle 2>/dev/null; ls -la /tank/recn/child; exit 1; }
test ! -e /tank/recn/.recycle/smbtest/nested.txt \
  || { echo "ERROR: [zrecn] child-dataset file wrongly targeted the share-root bin"; exit 1; }
# the child dataset root (mountpoint) must be left untouched, not relocked read-only
cm="$(stat -c %A /tank/recn/child)"
[ "${cm:8:1}" = "w" ] \
  || { echo "ERROR: [zrecn] child dataset root relocked read-only ($cm) -- recycle touched the mountpoint!"; exit 1; }
echo "  [zrecn] child-dataset file recycled to /tank/recn/child/.recycle/smbtest/ (own mount); mountpoint untouched"

# POSIX: the bin should carry a default (inheritable) ACL, so keeptree subdirs
# and the files moved in inherit the owner's access.
echo "--- [zrecp] per-user bin ACL (POSIX) ---"
getfacl -p /tank/recp/.recycle/smbtest 2>/dev/null || true
if getfacl -p /tank/recp/.recycle/smbtest 2>/dev/null | grep -qE '^default:'; then
  echo "  [zrecp] bin has an inheritable (default) POSIX ACL"
else
  echo "ERROR: [zrecp] bin lacks a default (inheritable) POSIX ACL"; exit 1
fi

# AD layout (.recycle/%D/%U): two shared parents above the per-user leaf. On a
# POSIX share root with nothing to inherit, both shared parents must land at the
# read-only floor (no group/other write) and stay root-owned, while the leaf is
# owned by the connecting user. %D resolves to the workgroup, so discover the
# recycled path by search rather than hardcoding it.
echo "--- [zrecad] AD layout (.recycle/%D/%U), POSIX ---"
rm -rf /tank/recad/.recycle 2>/dev/null || true
echo recycle-me > /tmp/rec.txt
smbclient //127.0.0.1/zrecad -U 'smbtest%testpass123' \
  -c 'put /tmp/rec.txt top.txt; rm top.txt' \
  || { echo "ERROR: [zrecad] put/rm failed"; tail -60 /var/log/samba4/smbd.log; exit 1; }
found="$(find /tank/recad/.recycle -type f -name top.txt 2>/dev/null | head -1)"
[ -n "$found" ] \
  || { echo "ERROR: [zrecad] file not recycled under .recycle/<domain>/<user>/"; ls -laR /tank/recad/.recycle 2>/dev/null; exit 1; }
leaf_dir="$(dirname "$found")"           # .recycle/<dom>/smbtest
dom_dir="$(dirname "$leaf_dir")"         # .recycle/<dom>
rec_dir="$(dirname "$dom_dir")"          # .recycle
[ "$rec_dir" = /tank/recad/.recycle ] \
  || { echo "ERROR: [zrecad] unexpected recycle depth for $found"; exit 1; }
for d in "$rec_dir" "$dom_dir"; do
  m="$(stat -c %A "$d")"; o="$(stat -c %U "$d")"
  # "other" (index 8 of e.g. "drwxrwxr-x") is the class regular users fall into
  # for a root:root dir, so no other-write == no regular user can write the
  # shared parent. The group bits (index 5) are the POSIX ACL *mask*, not the
  # real group perm, so they are not a reliable signal here -- the NFSv4 test
  # checks the full ACL for non-owner writes.
  [ "${m:8:1}" = "-" ] || { echo "ERROR: [zrecad] shared parent $d is other-writable ($m)"; exit 1; }
  [ "$o" = root ] || { echo "ERROR: [zrecad] shared parent $d not root-owned ($o)"; exit 1; }
done
[ "$(stat -c %U "$leaf_dir")" = smbtest ] \
  || { echo "ERROR: [zrecad] leaf $leaf_dir not owned by smbtest"; exit 1; }
echo "  [zrecad] recycled to $found; both shared parents read-only+root, leaf owned by smbtest"

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
