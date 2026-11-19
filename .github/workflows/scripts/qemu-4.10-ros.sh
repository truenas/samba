#!/usr/bin/env bash

######################################################################
# Test the interim responses of READ, WRITE and FLUSH on slow storage,
# with the truenas_ros reactors on and off, in the VM of the smoke test.
# ros-vm.sh runs in the VM as root. It puts the share on a dm-delay
# device. It installs dmsetup if the VM has none, which needs the network.
# Run this step before the durable handle tests, which crash the VM.
######################################################################

set -eu

source /tmp/vm-info.sh
VMSSH="ssh -o ConnectTimeout=5 -o ServerAliveInterval=5"
VMSSH="$VMSSH -o ServerAliveCountMax=3 debian@$VM_IP"
# qemu-3-build.sh copied the source tree into the VM.
$VMSSH "sudo bash /home/debian/samba/.github/workflows/scripts/ros-vm.sh"

echo "Interim response tests PASSED"
