#!/usr/bin/env bash

######################################################################
# Download and start a Debian Trixie VM (UEFI cloud image).
# Sized for a full Samba build: bigger disk + RAM than the pylibzfs VM.
######################################################################

set -eu

echo "Starting Debian Trixie VM..."

OS="debian-trixie"
URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2"
VM_NAME="truenas-samba-test"
VM_IP="192.168.122.10"
VM_MAC="52:54:00:83:79:10"

WORK_DIR="/tmp/qemu-work"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "Downloading Debian Trixie cloud image..."
if [ ! -f "debian-trixie.qcow2" ]; then
  wget -q --show-progress "$URL" -O debian-trixie.qcow2
fi

# Overlay disk. 50G headroom: ZFS debs + a full Samba source build tree.
echo "Creating VM disk..."
qemu-img create -f qcow2 -F qcow2 -b "$WORK_DIR/debian-trixie.qcow2" "$WORK_DIR/vm-disk.qcow2" 50G

PUBKEY=$(cat ~/.ssh/id_ed25519.pub)

cat <<EOF > /tmp/user-data
#cloud-config

hostname: $OS

users:
- name: debian
  sudo: ALL=(ALL) NOPASSWD:ALL
  shell: /bin/bash
  ssh_authorized_keys:
    - $PUBKEY

packages:
  - python3

runcmd:
  - echo "VM initialization complete"

growpart:
  mode: auto
  devices: ['/']
  ignore_growroot_disabled: false
EOF

sudo virsh net-update default add ip-dhcp-host \
  "<host mac='$VM_MAC' ip='$VM_IP'/>" --live --config || true

# ubuntu-24.04 runner: 4 vCPU / 16 GB RAM. Give the VM 4 vCPU and 12 GB,
# leaving headroom for the host. Debian Trixie needs UEFI boot.
echo "Starting VM..."
sudo virt-install \
  --name "$VM_NAME" \
  --os-variant debian12 \
  --cpu host-passthrough \
  --virt-type=kvm \
  --vcpus=4 \
  --memory 12288 \
  --graphics none \
  --network bridge=virbr0,model=virtio,mac="$VM_MAC" \
  --cloud-init user-data=/tmp/user-data \
  --disk path="$WORK_DIR/vm-disk.qcow2",format=qcow2,bus=virtio \
  --boot uefi=on,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
  --import \
  --noautoconsole >/dev/null

echo "Waiting for VM to be ready..."
for i in {1..60}; do
  if ssh -o ConnectTimeout=2 debian@$VM_IP "echo 'VM ready'" 2>/dev/null; then
    echo "VM is accessible via SSH"
    break
  fi
  echo "Waiting for VM... ($i/60)"
  sleep 5
done

if ! ssh debian@$VM_IP "uname -a"; then
  echo "ERROR: VM is not accessible"
  exit 1
fi

echo "Waiting for VM to fully initialize..."
sleep 10

echo "$VM_IP vm-test" | sudo tee -a /etc/hosts

cat <<EOF > /tmp/vm-info.sh
export VM_IP="$VM_IP"
export VM_NAME="$VM_NAME"
export WORK_DIR="$WORK_DIR"
EOF

echo "VM started successfully at $VM_IP"
