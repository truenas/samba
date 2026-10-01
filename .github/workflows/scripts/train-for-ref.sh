#!/usr/bin/env bash

######################################################################
# Map a git ref (branch name) to the TrueNAS train whose rolling
# <train>-nightly kernel and OpenZFS deb releases this Samba is built and
# tested against.
#
#   train-for-ref.sh REF
#
# REF - branch name, e.g. truenas/v4-24-stable, stable/26, or a pull
#       request base ref.
#
# Prints REF's train from .github/trains.json, or default_train if REF
# is not listed.
######################################################################

set -eu

resolve="$(dirname "$0")/resolve-train.py"
rc=0
entry=$("$resolve" branch "${1:-}") || rc=$?
case $rc in
  0) ;;
  3) entry=$("$resolve" default) ;;  # not listed
  *) exit "$rc" ;;                   # invalid config
esac
jq -r '.train' <<< "$entry"
