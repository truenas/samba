#!/usr/bin/env bash

######################################################################
# Collect logs from the VM for the uploaded artifact.
######################################################################

set -eu

echo "Collecting logs..."

source /tmp/vm-info.sh 2>/dev/null || true
: "${VM_IP:=192.168.122.10}"

LOG_DIR="/tmp/test-logs"
mkdir -p "$LOG_DIR"

cp /tmp/test-exitcode.txt "$LOG_DIR/" 2>/dev/null || true

# Samba logs + system logs (best-effort; VM may be down).
ssh debian@$VM_IP "sudo cat /var/log/samba4/smbd.log"     > "$LOG_DIR/smbd.log"      2>/dev/null || true
ssh debian@$VM_IP "sudo ls -lR /var/log/samba4"           > "$LOG_DIR/samba-logdir.txt" 2>/dev/null || true
ssh debian@$VM_IP "sudo testparm -s /etc/smb4.conf"       > "$LOG_DIR/testparm.txt"  2>/dev/null || true
ssh debian@$VM_IP "sudo journalctl -n 2000 --no-pager"    > "$LOG_DIR/journalctl.log" 2>/dev/null || true
ssh debian@$VM_IP "sudo dmesg"                            > "$LOG_DIR/dmesg.log"     2>/dev/null || true
ssh debian@$VM_IP "zpool status; zfs list"               > "$LOG_DIR/zfs-status.txt" 2>/dev/null || true
# Listing of the built debs (handy when a build/packaging step failed).
ssh debian@$VM_IP "ls -l ~/*.deb /tmp/*.deb 2>/dev/null" > "$LOG_DIR/built-debs.txt" 2>/dev/null || true

cd /tmp
tar czf qemu-logs.tar.gz test-logs/

echo "Logs collected at /tmp/qemu-logs.tar.gz"
