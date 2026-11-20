#!/usr/bin/env bash

######################################################################
# Test the interim responses of READ, WRITE and FLUSH on slow storage,
# with the truenas_ros reactors on and off, in the VM of a test job.
# ros-vm.sh runs in the VM as root. It puts the share on a ZFS pool whose
# I/O zinject delays.
######################################################################

set -eu

source /tmp/vm-info.sh
VMSSH="ssh -o ConnectTimeout=5 -o ServerAliveInterval=5"
VMSSH="$VMSSH -o ServerAliveCountMax=3 debian@$VM_IP"
# qemu-3-install.sh copied the source tree into the VM.
$VMSSH "sudo bash /home/debian/samba/.github/workflows/scripts/ros-vm.sh"

echo "Interim response tests PASSED"
