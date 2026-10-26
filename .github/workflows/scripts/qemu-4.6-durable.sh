#!/usr/bin/env bash

######################################################################
# Durable handles across HA failovers ("truenas stateful failover"), on
# the VM that the smoke test left behind. A restart of smbd restores
# nothing.
# durable-vm.sh does the steps in the VM, as root:
#   * the packaged truenas-smbhad.service on a system that is not HA
#   * the failure cases, each with one truenas.durable.restore run
#   * upstream smb2 suites with the option off and on: the same failures
#   * a crash of the VM through sysrq. Both daemons lose their copy. smbd
#     starts and restores nothing.
# Runs last against the VM: it ends with the crash of the VM.
######################################################################

set -eu

source /tmp/vm-info.sh
VMSSH="ssh -o ConnectTimeout=5 -o ServerAliveInterval=5"
VMSSH="$VMSSH -o ServerAliveCountMax=3 debian@$VM_IP"
# qemu-3-build.sh copied the source tree into the VM.
DVM="sudo bash /home/debian/samba/.github/workflows/scripts/durable-vm.sh"
CASES="restart crash failover tamper tamper2 devmove lockfail restartfail
	blipfail smbdfirst daemonrestart"

step() {
	echo "=========================================="
	echo "Durable handles: $*"
	echo "=========================================="
}

step setup
$VMSSH "$DVM setup"

step "the packaged unit, not HA"
$VMSSH "$DVM unit"

for c in $CASES; do
	step "$c"
	$VMSSH "$DVM case $c"
done

step "upstream suites with the option off and on"
$VMSSH "$DVM regress"

step "crash of the VM (sysrq)"
$VMSSH "$DVM crash-prepare"
# No shutdown, no unmount, no pool export.
SYSRQ='echo 1 > /proc/sys/kernel/sysrq; echo b > /proc/sysrq-trigger'
$VMSSH "sudo sh -c '$SYSRQ'" || true
sleep 5
for i in $(seq 1 60); do
	if $VMSSH true 2> /dev/null; then
		break
	fi
	echo "Waiting for the VM after the crash... ($i/60)"
	sleep 5
done
$VMSSH "$DVM crash-verify"

echo "Durable handle tests PASSED"
