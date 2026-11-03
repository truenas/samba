#!/usr/bin/env bash

######################################################################
# Test the truesearch Spotlight backend in the VM of the smoke test.
# truesearchd is closed source. truesearch-mock.py replaces it.
# spotlight-vm.sh runs in the VM as root, with its own dataset and smbd.
# Run this step before the durable handle tests, which crash the VM.
#
# Invoked with the TrueNAS train in the TRAIN environment variable. The
# mock needs truenas_os. The step installs it from the python3-truenas-pyos
# deb of the truenas/truenas_pyos <TRAIN>-nightly release.
######################################################################

set -eu

TRAIN="${TRAIN:?TRAIN must be set}"

source /tmp/vm-info.sh
VMSSH="ssh -o ConnectTimeout=5 -o ServerAliveInterval=5"
VMSSH="$VMSSH -o ServerAliveCountMax=3 debian@$VM_IP"
# qemu-3-build.sh copied the source tree into the VM.
$VMSSH bash -s "$TRAIN" <<'REMOTE_SCRIPT'
set -eu
cd ~/samba
.github/workflows/scripts/tn-fetch-debs.sh \
  truenas/truenas_pyos "$1" /tmp/pyos-debs 'python3-truenas-pyos_*' > /dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  /tmp/pyos-debs/python3-truenas-pyos_*.deb
REMOTE_SCRIPT
$VMSSH "sudo bash /home/debian/samba/.github/workflows/scripts/spotlight-vm.sh"

echo "Spotlight truesearch backend tests PASSED"
