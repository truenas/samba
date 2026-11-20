#!/usr/bin/env bash

######################################################################
# Install the debs of the build job in the VM of a test job: the TrueNAS
# kernel, OpenZFS and truenas-samba. The workflow downloads them to
# /tmp/ci-debs. Then power off the VM, so that qemu-3.5-restart.sh boots
# it on the TrueNAS kernel.
######################################################################

set -eu

source /tmp/vm-info.sh

echo "Waiting for cloud-init to complete..."
ssh debian@$VM_IP "cloud-init status --wait" || true

echo "Installing rsync in VM..."
ssh debian@$VM_IP "sudo apt-get update && sudo apt-get install -y rsync"

# The tests use the scripts and some test files of the source tree.
echo "Copying Samba source to VM..."
ssh debian@$VM_IP "mkdir -p ~/samba"
rsync -az --delete \
  --exclude='.git' \
  --exclude='/bin/' \
  --exclude='*.o' --exclude='*.lo' \
  "$GITHUB_WORKSPACE/" debian@$VM_IP:~/samba/
rsync -a /tmp/ci-debs/ debian@$VM_IP:/tmp/ci-debs/

echo "Installing the debs of the build job in VM..."
ssh debian@$VM_IP bash -s <<'REMOTE_SCRIPT'
set -eu
export DEBIAN_FRONTEND=noninteractive
cd ~/samba
# The tools of the build VM that the tests use: gcc and git for the
# truenas_pyos install of the smoke test, curl and jq for
# tn-fetch-debs.sh.
sudo -E apt-get install -y build-essential git curl jq ca-certificates
.github/workflows/scripts/tn-install-debs.sh kernel \
  /tmp/ci-debs/kernel /tmp/ci-debs/zfs
.github/workflows/scripts/tn-install-debs.sh samba /tmp/ci-debs/samba/*.deb
.github/workflows/scripts/tn-install-debs.sh only-truenas-kernel /tmp/ci-debs/kernel
REMOTE_SCRIPT

echo "Cleaning cloud-init and powering off VM..."
ssh debian@$VM_IP 'sudo cloud-init clean --logs && sync && sleep 2 && sudo poweroff' &

echo "Install complete; VM shutting down for restart"
