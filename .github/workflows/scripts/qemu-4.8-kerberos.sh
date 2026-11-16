#!/usr/bin/env bash

######################################################################
# Test "truenas:keep kerberos sessions" in the VM of the smoke test.
# kerberos-vm.sh runs in the VM as root. It installs the Samba AD DC of
# Debian into a chroot, joins an smbd of its own to that domain and runs
# the truenas.session tests. The install needs the network.
# Run this step before the durable handle tests, which crash the VM.
######################################################################

set -eu

source /tmp/vm-info.sh
VMSSH="ssh -o ConnectTimeout=5 -o ServerAliveInterval=5"
VMSSH="$VMSSH -o ServerAliveCountMax=3 debian@$VM_IP"
# qemu-3-build.sh copied the source tree into the VM.
$VMSSH "sudo bash /home/debian/samba/.github/workflows/scripts/kerberos-vm.sh"

echo "Kerberos session revalidation tests PASSED"
