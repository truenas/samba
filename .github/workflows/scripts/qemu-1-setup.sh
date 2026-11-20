#!/usr/bin/env bash

######################################################################
# Setup QEMU environment on the GitHub Actions runner.
# (Host side — installs libvirt/QEMU and prepares SSH access.)
######################################################################

set -eu

echo "Setting up QEMU environment..."

export DEBIAN_FRONTEND="noninteractive"
sudo apt-get -y update
# Only what the scripts use. The recommended packages of these bring the
# desktop and libguestfs stacks, about 100 MB that made this step time out
# on slow mirrors. qemu-utils has qemu-img, libvirt-clients has virsh and
# virtinst has virt-install. virt-install boots the VM with the UEFI
# firmware of ovmf and needs the OS names of osinfo-db. The default
# network of libvirt gives the VM its address with dnsmasq-base.
sudo apt-get install -y --no-install-recommends \
  qemu-system-x86 \
  qemu-utils \
  ovmf \
  ipxe-qemu-256k-compat-efi-roms \
  libvirt-daemon-system \
  libvirt-clients \
  dnsmasq-base \
  virtinst \
  osinfo-db \
  rsync \
  wget

# Generate an ssh key the host uses to reach the VM.
rm -f ~/.ssh/id_ed25519
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -q -N ""

# Free up runner resources.
sudo systemctl stop docker.socket || true
sudo systemctl stop multipathd.socket || true

# SSH client: no host-key prompts, short connect timeout.
mkdir -p "$HOME/.ssh"
cat <<EOF >> "$HOME/.ssh/config"
StrictHostKeyChecking no
ConnectTimeout 10
EOF

sudo systemctl start libvirtd
sudo systemctl enable libvirtd
sudo usermod -a -G libvirt "$USER"

echo "QEMU setup complete"
