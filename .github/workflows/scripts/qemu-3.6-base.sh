#!/usr/bin/env bash

######################################################################
# In the VM of a test job without the smoke test, create what the tests
# take from the smoke test (qemu-4-test.sh): the pool tank, the default
# configuration /etc/smb4.conf and the user smbtest with the password
# testpass123 in the default passdb.
######################################################################

set -eu

source /tmp/vm-info.sh

ssh debian@$VM_IP 'sudo bash -s' <<'REMOTE_SCRIPT'
set -eu
modprobe zfs
truncate -s 8G /var/tmp/zpool.img
zpool create -f tank /var/tmp/zpool.img
mkdir -p /etc/samba /var/log/samba4 /run/samba \
         /var/lib/truenas-samba/private /var/run/samba-lock /var/run/samba-cache
# smbpasswd needs the default configuration. Without the netbios name, the
# smbtorture client fails to connect with NT_STATUS_NO_MEMORY.
cat > /etc/smb4.conf <<CONF
[global]
    workgroup = WORKGROUP
    netbios name = SMBCITEST
    security = user
    passdb backend = tdbsam
    load printers = no
    printing = bsd
    disable spoolss = yes
CONF
useradd -M -s /usr/sbin/nologin smbtest
printf 'testpass123\ntestpass123\n' | smbpasswd -a -s smbtest
echo "The pool tank, /etc/smb4.conf and the user smbtest are ready"
REMOTE_SCRIPT
