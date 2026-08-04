#!/usr/bin/env bash

######################################################################
# Print a one-line build/test summary.
######################################################################

set -eu

echo "=========================================="
echo "Build & Test Summary"
echo "=========================================="

if [ -f /tmp/test-exitcode.txt ]; then
  EXIT_CODE=$(cat /tmp/test-exitcode.txt)
  if [ "$EXIT_CODE" -eq 0 ]; then
    echo "Status: SUCCESS"
    echo "Built Samba against the TrueNAS kernel + OpenZFS and smoke-tested the VFS stack on ZFS (Debian Trixie QEMU VM)."
  else
    echo "Status: FAILURE"
    echo "Smoke test failed with exit code: $EXIT_CODE"
  fi
else
  echo "Status: FAILURE"
  echo "No test exit code recorded — build likely failed before the test stage."
  echo "See the 'Build Samba against the TrueNAS kernel + OpenZFS' step and the uploaded logs artifact."
fi

echo "=========================================="
