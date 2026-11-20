#!/usr/bin/env bash

######################################################################
# Run fstests through the kernel SMB client (cifs.ko) in the VM of a test
# job (qemu-3.6-base.sh). fstests-vm.sh runs in the VM as root, with its
# own datasets and smbd. The step installs the packages that fstests needs.
# It does not install Debian's liburing-dev. fstests works without it.
# The Samba build links only the vendored liburing of debian/build-liburing.sh.
######################################################################

set -eu

source /tmp/vm-info.sh
VMSSH="ssh -o ConnectTimeout=5 -o ServerAliveInterval=5"
VMSSH="$VMSSH -o ServerAliveCountMax=3 debian@$VM_IP"
$VMSSH "sudo apt-get update -q > /dev/null"
$VMSSH "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
  acl attr automake bc cifs-utils dbench dump e2fsprogs fio gawk gcc git \
  indent libacl1-dev libaio-dev libcap-dev libgdbm-compat-dev libgdbm-dev \
  libtool libtool-bin libuuid1 make pkgconf psmisc python3 quota sed sqlite3 \
  uuid-dev uuid-runtime xfsprogs xfslibs-dev > /dev/null"
# qemu-3-install.sh copied the source tree into the VM.
$VMSSH "sudo bash /home/debian/samba/.github/workflows/scripts/fstests-vm.sh"

echo "fstests through cifs.ko PASSED"
