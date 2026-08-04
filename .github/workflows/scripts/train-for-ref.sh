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
# Prints the train name (master or 26) on stdout.  This is the single
# source of truth for the branch -> train mapping, mirroring the mapping
# truenas/zfs and truenas/linux use for their own branches (stable/26 ->
# 26, everything else -> master): this repo's stable/26 tracks the SCALE
# 26 release, while the truenas/v4-* development branches track master.
######################################################################

set -eu

REF="${1:-}"

case "$REF" in
  stable/26) echo "26" ;;
  *)         echo "master" ;;
esac
