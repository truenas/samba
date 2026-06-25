#!/usr/bin/env bash

######################################################################
# Wait for VM poweroff and restart it (so the ZFS kmod loads on boot).
######################################################################

set -eu

echo "Waiting for VM shutdown and restarting..."

source /tmp/vm-info.sh

echo "Waiting for VM to shut down..."
for i in {1..60}; do
  if sudo virsh list --all | grep "$VM_NAME" | grep -q "shut off"; then
    echo "VM has shut down"
    break
  fi
  echo "Waiting for shutdown... ($i/60)"
  sleep 2
done

if ! sudo virsh list --all | grep "$VM_NAME" | grep -q "shut off"; then
  echo "VM did not shut down gracefully, forcing shutdown..."
  sudo virsh destroy "$VM_NAME" || true
  sleep 3
fi

echo "Starting VM..."
sudo virsh start "$VM_NAME"
sleep 5

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
  echo "ERROR: VM is not accessible after restart"
  exit 1
fi

echo "VM restarted successfully at $VM_IP"
