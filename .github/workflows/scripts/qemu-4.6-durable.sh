#!/usr/bin/env bash

######################################################################
# Durable handles across HA failovers ("truenas stateful failover"), in
# the VM of a test job (qemu-3.6-base.sh). A restart of smbd restores
# nothing.
#
#   qemu-4.6-durable.sh cases
#   qemu-4.6-durable.sh regress [N/M]
#
# durable-vm.sh does the steps in the VM, as root:
#   * cases: the packaged truenas-smbhad.service on a system that is not
#     HA, the failure cases, each with one truenas.durable.restore run,
#     then a crash of the VM through sysrq. Both daemons lose their copy.
#     smbd starts and restores nothing. The crash ends the use of the VM.
#   * regress: upstream smb2 suites with the option off and on: the same
#     failures. N/M selects the suites N, N + M, N + 2M... of the list in
#     durable-vm.sh (default: all).
######################################################################

set -eu

source /tmp/vm-info.sh
VMSSH="ssh -o ConnectTimeout=5 -o ServerAliveInterval=5"
VMSSH="$VMSSH -o ServerAliveCountMax=3 debian@$VM_IP"
# qemu-3-install.sh copied the source tree into the VM.
DVM="sudo bash /home/debian/samba/.github/workflows/scripts/durable-vm.sh"
CASES="restart crash failover tamper tamper2 devmove lockfail restartfail
	blipfail smbdfirst daemonrestart"
MODE="${1:-}"
[ $# -gt 0 ] && shift

step() {
	echo "=========================================="
	echo "Durable handles: $*"
	echo "=========================================="
}

case $MODE in
cases|regress) ;;
*)
	echo "usage: qemu-4.6-durable.sh cases | regress [N/M]"
	exit 2;;
esac

step setup
$VMSSH "$DVM setup"

if [ "$MODE" = regress ]; then
	step "upstream suites with the option off and on: ${1:-all}"
	$VMSSH "$DVM regress ${1:-}"
	echo "Durable handle tests PASSED"
	exit 0
fi

step "the packaged unit, not HA"
$VMSSH "$DVM unit"

for c in $CASES; do
	step "$c"
	$VMSSH "$DVM case $c"
done

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
