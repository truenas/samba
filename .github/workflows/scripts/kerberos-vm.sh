#!/usr/bin/env bash

######################################################################
# Test "truenas:keep kerberos sessions" in the VM, as root.
# qemu-4.8-kerberos.sh runs this script.
#
# The parameter needs a member of an Active Directory domain. The domain
# controller is the Samba AD DC of Debian. It runs in a chroot, because
# the truenas-samba package conflicts with the samba package. The DC
# listens on DC_IP. The smbd and winbindd of this step listen on NAS_IP
# and keep their Samba state under WORK. Both addresses are loopback
# addresses.
#
# The checks:
#   K1 The parameter is off, which is the default. A session with a
#      short ticket expires (truenas.session.expire). smbd starts no
#      check of the account.
#   K2 The parameter is on. I/O continues after the ticket ended
#      (truenas.session.revalidate). smbd asked the KDC. The account did
#      not change, so the session kept its token.
#   K3 The parameter is on and the account is disabled after the session
#      setup. The session expires when the ticket ends, not before
#      (truenas.session.refused). smbd logs the refusal of the KDC.
#   K4 The parameter is on. smbd starts no check for an NTLM session.
#   K5 Upstream smb2.session tests have the same failures with the
#      parameter on and off.
#   K6 The parameter is on and the KDC hangs. The client logs the session
#      off while smbd waits for the KDC (truenas.session.logoff). The
#      connection stays usable and smbd has no internal error.
#   K7 The parameter is on. After the session setup, the account is
#      deleted and a new account gets its name. The session expires when
#      the ticket ends (truenas.session.refused). smbd logs that the
#      ticket is for a different account.
#   K8 The parameter is on. After the session setup, the user joins the
#      group that can use the share GROUP_SHARE. After the end of the
#      ticket, smbd replaced the token, and the session can connect to
#      that share (truenas.session.groups).
#
# "kerberos-vm.sh bootstrap" only installs the DC into the chroot. This
# is the only part that needs the network. "kerberos-vm.sh hang N" stops
# the processes of the DC for N seconds. K6 uses it.
#
# To run outside the VM, set KRB_DATASET (empty: no ZFS), KRB_DIR,
# KRB_WORK, KRB_DC_ROOT, KRB_DC_IP, KRB_NAS_IP, DEBOOTSTRAP, SMBD,
# WINBINDD, NET, WBINFO and SMBTORTURE.
######################################################################

set -eu

DATASET="${KRB_DATASET-tank/kerberos}"
DIR="${KRB_DIR:-/tank/kerberos}"
WORK="${KRB_WORK:-/var/tmp/kerberos}"
DC_ROOT="${KRB_DC_ROOT:-$WORK/dc}"
DC_IP="${KRB_DC_IP:-127.0.10.1}"
NAS_IP="${KRB_NAS_IP:-127.0.10.2}"
DEBOOTSTRAP="${DEBOOTSTRAP:-debootstrap}"
SMBD="${SMBD:-/usr/sbin/smbd}"
WINBINDD="${WINBINDD:-/usr/sbin/winbindd}"
NET="${NET:-/usr/bin/net}"
WBINFO="${WBINFO:-/usr/bin/wbinfo}"
SMBTORTURE="${SMBTORTURE:-/usr/bin/smbtorture}"
REALM=KRBCI.TEST
DNS=krbci.test
DOMAIN=KRBCI
ADMIN_PASS='Passw0rd.1'
USER_NAME=kruser
USER_PASS='Passw0rd.2'
# K7 deletes this account and makes a new one with the same name
TEMP_USER=krtemp
# Only the members of GROUP can connect to GROUP_SHARE
GROUP=krgroup
GROUP_SHARE=krgroup
# The lifetime of a test ticket and the clock skew of smbd, in seconds.
# smbd adds the clock skew to the end of a ticket.
LIFETIME=5
SKEW=5
# The upstream tests of K5
UPSTREAM="smb2.session.reconnect1 smb2.session.reconnect2
	smb2.session.reauth1 smb2.session.reauth2 smb2.session.reauth3
	smb2.session.reauth4 smb2.session.reauth5 smb2.session.reauth6"
NAS="$WORK/nas"
LOGDIR="$WORK/log"
OUT="$WORK/out"
CONF="$WORK/smb.conf"
# [global] includes this file. It holds the parameter, or nothing.
SWITCH="$WORK/revalidate.conf"
SMBD_LOG="$LOGDIR/log.smbd"
PASS=0
FAILED=0
ofs=0

ok() { PASS=$((PASS + 1)); echo "PASS  $1: $2"; }
bad() { FAILED=$((FAILED + 1)); echo "FAIL  $1: $2"; }

step() {
	echo "=========================================="
	echo "Kerberos session revalidation: $*"
	echo "=========================================="
}

# The DC must not get the Samba and Kerberos configuration of the caller
DC_ENV="env -u KRB5_CONFIG -u SMB_CONF_PATH -u LD_LIBRARY_PATH"

# Run a command of the DC in its chroot
dc() {
	$DC_ENV chroot "$DC_ROOT" "$@"
}

# Send a signal to each process that runs in the chroot of the DC
dc_signal() { # $1: signal
	local root p pids=""
	root=$(readlink -f "$DC_ROOT" 2> /dev/null) || return 0
	for p in /proc/[0-9]*; do
		if [ "$(readlink "$p/root" 2> /dev/null)" = "$root" ]; then
			pids="$pids ${p##*/}"
		fi
	done
	if [ -n "$pids" ]; then
		# shellcheck disable=SC2086
		kill "-$1" $pids 2> /dev/null || true
	fi
}

dc_mount() {
	mountpoint -q "$DC_ROOT/proc" || mount -t proc proc "$DC_ROOT/proc"
	mountpoint -q "$DC_ROOT/dev" || mount --bind /dev "$DC_ROOT/dev"
}

dc_umount() {
	umount "$DC_ROOT/dev" 2> /dev/null || true
	umount "$DC_ROOT/proc" 2> /dev/null || true
}

# Install the Samba AD DC of Debian into the chroot
dc_bootstrap() {
	[ -x "$DC_ROOT/usr/sbin/samba" ] && return 0
	command -v "${DEBOOTSTRAP%% *}" > /dev/null || {
		apt-get update
		DEBIAN_FRONTEND=noninteractive apt-get install -y debootstrap
	}
	mkdir -p "$DC_ROOT"
	$DEBOOTSTRAP --variant=minbase trixie "$DC_ROOT" \
		http://deb.debian.org/debian
	# The packages must not start their services
	printf '#!/bin/sh\nexit 101\n' > "$DC_ROOT/usr/sbin/policy-rc.d"
	chmod +x "$DC_ROOT/usr/sbin/policy-rc.d"
	dc_mount
	dc env DEBIAN_FRONTEND=noninteractive apt-get install -y \
		-o Dpkg::Use-Pty=0 --no-install-recommends samba-ad-dc \
		samba-ad-provision
}

dc_provision() {
	local done="$DC_ROOT/var/lib/samba/provisioned"
	[ -e "$done" ] && return 0
	# The configuration of the package, or of an incomplete provision
	rm -rf "$DC_ROOT/etc/samba/smb.conf" "$DC_ROOT/var/lib/samba/private"
	grep -q "dc1.$DNS" "$DC_ROOT/etc/hosts" 2> /dev/null ||
		echo "$DC_IP dc1.$DNS dc1" >> "$DC_ROOT/etc/hosts"
	dc samba-tool domain provision --realm="$REALM" --domain="$DOMAIN" \
		--server-role=dc --dns-backend=SAMBA_INTERNAL \
		--adminpass="$ADMIN_PASS" --host-name=dc1 --host-ip="$DC_IP" \
		--option="netbios name = DC1" \
		--option="interfaces = $DC_IP/8" \
		--option="bind interfaces only = yes" > "$OUT/provision.txt" 2>&1 || {
		tail -30 "$OUT/provision.txt"
		return 1
	}
	touch "$done"
}

listens() { # $1: address, $2: port
	ss -ltn | grep -q "$1:$2 "
}

# Run a command until it succeeds
retry() { # $1: tries, $2: seconds between tries, then the command
	local tries="$1" secs="$2"
	shift 2
	while [ "$tries" -gt 0 ]; do
		"$@" && return 0
		tries=$((tries - 1))
		sleep "$secs"
	done
	return 1
}

dc_listens() {
	listens "$DC_IP" 88 && listens "$DC_IP" 389 && listens "$DC_IP" 445
}

dc_start() {
	dc samba -D
	retry 120 0.5 dc_listens && return 0
	echo "ERROR: the DC does not listen"
	return 1
}

ended() { # $1: pid
	! kill -0 "$1" 2> /dev/null
}

stop_pid() { # $1: pid file
	local pid
	pid=$(cat "$1" 2> /dev/null) || return 0
	kill -TERM "$pid" 2> /dev/null || return 0
	retry 50 0.2 ended "$pid" || kill -KILL "$pid" 2> /dev/null || true
}

# Put back a file that the setup changed
restore() { # $1: saved copy, $2: file
	if [ -f "$1" ]; then
		cat "$1" > "$2"
		rm -f "$1"
	fi
}

stop() {
	stop_pid "$NAS/run/smbd.pid"
	stop_pid "$NAS/run/winbindd.pid"
	dc_signal CONT
	stop_pid "$DC_ROOT/run/samba/samba.pid"
	dc_umount
	restore "$WORK/hosts.orig" /etc/hosts
	restore "$WORK/nsswitch.orig" /etc/nsswitch.conf
}

# (Re)start smbd with the parameter on or off. "off" sets nothing: the
# default.
nas_start() { # $1: on or off
	stop_pid "$NAS/run/smbd.pid"
	case "$1" in
	on) echo "truenas:keep kerberos sessions = yes" > "$SWITCH" ;;
	*) : > "$SWITCH" ;;
	esac
	"$SMBD" -D -s "$CONF" -l "$LOGDIR"
	retry 50 0.2 listens "$NAS_IP" 445 && return 0
	echo "ERROR: smbd does not listen"
	return 1
}

log_size() {
	stat -c %s "$SMBD_LOG" 2> /dev/null || echo 0
}

# The smbd log after offset $1
log_from() {
	tail -c +$(($1 + 1)) "$SMBD_LOG"
}

# True if smbd logged $1 during the last test
logged() {
	log_from "$ofs" | grep -q "$1"
}

# smbtorture as the test user, or as TORTURE_USER. A skipped test fails
# the run. ofs is the size of the smbd log before the test.
torture() { # $1: name of the output, $2: ticket lifetime, then arguments
	local out="$OUT/$1.txt" life="$2" rc=0
	shift 2
	ofs=$(log_size)
	"$SMBTORTURE" "//nas1.$DNS/share" --configfile="$CONF" \
		-U "${TORTURE_USER:-$USER_NAME}%$USER_PASS" --realm="$REALM" \
		--option="torture:session_lifetime=$life" \
		--option="torture:session_skew=$SKEW" "$@" > "$out" 2>&1 || rc=$?
	cat "$out"
	if [ "$rc" -eq 0 ] && grep -q '^skip:' "$out"; then
		rc=1
	fi
	return "$rc"
}

# The upstream tests that failed in run $1
failed() {
	sed -n -E 's/^(failure|error): ([^ ]+).*/\2/p' "$OUT/$1.txt" | sort -u
}

if [ "${1:-}" = bootstrap ]; then
	dc_bootstrap
	dc_umount
	exit 0
fi

if [ "${1:-}" = hang ]; then
	dc_signal STOP
	(sleep "$2"; dc_signal CONT) > /dev/null 2>&1 &
	exit 0
fi

step setup
stop
rm -rf "$NAS" "$LOGDIR" "$OUT"
mkdir -p "$NAS/run" "$NAS/private" "$NAS/lock" "$NAS/state" "$NAS/cache" \
	"$NAS/ncalrpc" "$LOGDIR" "$OUT"
if [ -n "$DATASET" ]; then
	zfs list "$DATASET" > /dev/null 2>&1 ||
		zfs create -o mountpoint="$DIR" "$DATASET"
fi
mkdir -p "$DIR"
chmod 1777 "$DIR"
# The path of IPC$
mkdir -p /var/empty

# In the VM: stop the daemons of the earlier steps. They hold the SMB port
# and the winbindd pipe.
if [ -n "$DATASET" ]; then
	systemctl stop smbd nmbd winbind 2> /dev/null || true
	DAEMONS='smbd|nmbd|winbindd|samba-dcerpcd|rpcd_[a-z_]+'
	pkill -TERM -x "$DAEMONS" 2> /dev/null || true
	for _ in $(seq 1 50); do
		pgrep -x "$DAEMONS" > /dev/null || break
		sleep 0.2
	done
	pkill -KILL -x "$DAEMONS" 2> /dev/null || true
	# The directory of the winbindd pipe
	mkdir -p /run/samba
fi
trap stop EXIT

dc_bootstrap
dc_mount
dc_provision
dc_start
dc samba-tool user show "$USER_NAME" > /dev/null 2>&1 ||
	dc samba-tool user create "$USER_NAME" "$USER_PASS" > /dev/null
dc samba-tool user enable "$USER_NAME" > /dev/null

# The names of the DC and of the server under test
if ! grep -q "nas1.$DNS" /etc/hosts; then
	cp /etc/hosts "$WORK/hosts.orig"
	printf '%s dc1.%s dc1\n%s nas1.%s nas1\n' \
		"$DC_IP" "$DNS" "$NAS_IP" "$DNS" >> /etc/hosts
fi
# smbd gets the UNIX accounts of domain users from winbindd
if ! grep -q '^passwd:.*winbind' /etc/nsswitch.conf; then
	cp /etc/nsswitch.conf "$WORK/nsswitch.orig"
	sed -i -E 's/^(passwd|group):(.*)$/\1:\2 winbind/' /etc/nsswitch.conf
fi

export KRB5_CONFIG="$WORK/krb5.conf"
cat > "$KRB5_CONFIG" <<EOF
[libdefaults]
	default_realm = $REALM
	dns_lookup_realm = false
	dns_lookup_kdc = false
	rdns = false
	dns_canonicalize_hostname = false
	clockskew = $SKEW

[realms]
	$REALM = {
		kdc = $DC_IP
	}

[domain_realm]
	.$DNS = $REALM
	$DNS = $REALM
EOF

: > "$SWITCH"
cat > "$CONF" <<EOF
[global]
    netbios name = NAS1
    workgroup = $DOMAIN
    realm = $REALM
    security = ads
    kerberos method = secrets only
    password server = dc1.$DNS
    create krb5 conf = no
    interfaces = $NAS_IP/8
    bind interfaces only = yes
    idmap config * : backend = tdb
    idmap config * : range = 90000001-100000000
    idmap config $DOMAIN : backend = rid
    idmap config $DOMAIN : range = 100000001-200000000
    template shell = /bin/sh
    template homedir = /tmp
    load printers = no
    printing = bsd
    disable spoolss = yes
    pid directory = $NAS/run
    private dir = $NAS/private
    lock directory = $NAS/lock
    state directory = $NAS/state
    cache directory = $NAS/cache
    ncalrpc dir = $NAS/ncalrpc
    log level = 1 smb2:5
    max log size = 0
    include = $SWITCH
[share]
    path = $DIR
    read only = no
[$GROUP_SHARE]
    path = $DIR
    read only = no
    valid users = +$DOMAIN\\$GROUP
EOF

"$NET" ads join -s "$CONF" -U "Administrator%$ADMIN_PASS" -S "dc1.$DNS" \
	--no-dns-updates > "$OUT/join.txt" 2>&1 || {
	cat "$OUT/join.txt"
	echo "ERROR: the join failed"
	exit 1
}
"$WINBINDD" -D -s "$CONF" -l "$LOGDIR"
retry 60 0.5 "$WBINFO" -t > /dev/null 2>&1 || true
"$WBINFO" -t
getent passwd "$DOMAIN\\$USER_NAME"

step "K1: the default"
nas_start off
torture k1 "$LIFETIME" --use-kerberos=required truenas.session.expire &&
	ok K1a "a session expires when its ticket ends" ||
	bad K1a "truenas.session.expire failed"
logged "does not expire" &&
	bad K1b "smbd kept a session with the parameter off" ||
	ok K1b "smbd started no check"

step "K2: the parameter is on"
nas_start on
torture k2 "$LIFETIME" --use-kerberos=required truenas.session.revalidate &&
	ok K2a "I/O continues after the ticket ended" ||
	bad K2a "truenas.session.revalidate failed"
logged "the KDC gave a new ticket for $USER_NAME@$REALM" &&
	ok K2b "smbd asked the KDC" ||
	bad K2b "no check in the smbd log"
logged "for $USER_NAME@$REALM matches the token" &&
	ok K2c "the session kept its token" ||
	bad K2c "smbd did not keep the token of the session"

step "K3: the account is disabled"
# The test runs this command after the session setup. A longer ticket
# gives the command the time to disable the account.
DISABLE="$DC_ENV chroot $DC_ROOT samba-tool user disable $USER_NAME"
torture k3 10 --use-kerberos=required \
	--option="torture:session_cmd=$DISABLE" truenas.session.refused &&
	ok K3a "the session expires when its ticket ends" ||
	bad K3a "truenas.session.refused failed"
logged "the KDC refused a ticket for $USER_NAME@$REALM" &&
	ok K3b "smbd logged the refusal" ||
	bad K3b "no refusal in the smbd log"
dc samba-tool user enable "$USER_NAME" > /dev/null

step "K4: an NTLM session"
torture k4 "$LIFETIME" --use-kerberos=off smb2.connect &&
	ok K4a "an NTLM session works" ||
	bad K4a "smb2.connect with NTLM failed"
logged "does not expire" &&
	bad K4b "smbd started a check for an NTLM session" ||
	ok K4b "smbd started no check"

step "K5: upstream tests with the parameter on and off"
upstream() { # $1: on or off
	nas_start "$1"
	# shellcheck disable=SC2086
	torture "k5-$1" "$LIFETIME" --use-kerberos=required $UPSTREAM || true
	grep -q '^success: ' "$OUT/k5-$1.txt"
}
same_failures() {
	upstream on && upstream off &&
		[ "$(failed k5-on)" = "$(failed k5-off)" ]
}
# A second run rules out a flaky test
if same_failures || same_failures; then
	ok K5 "the same failures: $(failed k5-on | tr '\n' ' ')"
else
	bad K5 "on: $(failed k5-on | tr '\n' ' ') off: $(failed k5-off | tr '\n' ' ')"
fi

step "K6: a logoff while smbd waits for the KDC"
nas_start on
# The test runs this command after the session setup. The KDC then does
# not answer for 20 seconds. The check of the account starts in that time.
SELF=$(readlink -f "$0")
torture k6 "$LIFETIME" --use-kerberos=required \
	--option="torture:session_cmd=bash $SELF hang 20" \
	truenas.session.logoff &&
	ok K6a "the connection stays usable" ||
	bad K6a "truenas.session.logoff failed"
grep -q "PANIC\|INTERNAL ERROR" "$SMBD_LOG" &&
	bad K6b "smbd had an internal error" ||
	ok K6b "no internal error in the smbd log"

step "K7: a different account gets the name of the user"
dc samba-tool user delete "$TEMP_USER" > /dev/null 2>&1 || true
dc samba-tool user create "$TEMP_USER" "$USER_PASS" > /dev/null
# The test runs this command after the session setup
REPLACE="samba-tool user delete $TEMP_USER && samba-tool user create"
REPLACE="$DC_ENV chroot $DC_ROOT sh -c '$REPLACE $TEMP_USER $USER_PASS'"
TORTURE_USER=$TEMP_USER torture k7 10 --use-kerberos=required \
	--option="torture:session_cmd=$REPLACE" truenas.session.refused &&
	ok K7a "the session expires when its ticket ends" ||
	bad K7a "truenas.session.refused failed"
logged "ticket for $TEMP_USER@$REALM that is for a different" &&
	ok K7b "smbd logged the different account" ||
	bad K7b "no different account in the smbd log"
dc samba-tool user delete "$TEMP_USER" > /dev/null

step "K8: the user joins a group"
dc samba-tool group show "$GROUP" > /dev/null 2>&1 ||
	dc samba-tool group add "$GROUP" > /dev/null
dc samba-tool group removemembers "$GROUP" "$USER_NAME" > /dev/null 2>&1 || true
# The test runs this command after the session setup
JOIN="$DC_ENV chroot $DC_ROOT samba-tool group addmembers $GROUP $USER_NAME"
torture k8 10 --use-kerberos=required \
	--option="torture:session_cmd=$JOIN" \
	--option="torture:session_share=$GROUP_SHARE" truenas.session.groups &&
	ok K8a "the session gets the new group of the user" ||
	bad K8a "truenas.session.groups failed"
logged "for $USER_NAME@$REALM is different from the token" &&
	ok K8b "smbd replaced the token" ||
	bad K8b "no new token in the smbd log"
dc samba-tool group removemembers "$GROUP" "$USER_NAME" > /dev/null

step "$PASS passed, $FAILED failed"
if [ "$FAILED" -ne 0 ]; then
	tail -60 "$SMBD_LOG"
	exit 1
fi
