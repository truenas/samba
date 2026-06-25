#!/usr/bin/env bash

######################################################################
# Setup QEMU environment on the GitHub Actions runner.
# (Host side — installs libvirt/QEMU and prepares SSH access.)
######################################################################

set -eu

echo "Setting up QEMU environment..."

export DEBIAN_FRONTEND="noninteractive"
sudo apt-get -y update
sudo apt-get install -y \
  cloud-image-utils \
  guestfs-tools \
  virt-manager \
  qemu-system-x86 \
  qemu-utils \
  libvirt-daemon-system \
  libvirt-clients \
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
