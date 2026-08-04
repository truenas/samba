#!/usr/bin/env bash

######################################################################
# Download and verify the deb assets of a truenas rolling
# <train>-nightly GitHub release.
#
#   tn-fetch-debs.sh REPO TRAIN DESTDIR GLOB [GLOB...]
#
# REPO    - GitHub slug, e.g. truenas/zfs or truenas/linux
# TRAIN   - TrueNAS train, e.g. master or 26.  The release tag is
#           <TRAIN>-nightly.
# DESTDIR - directory to download into (created if absent)
# GLOB    - one or more shell globs selecting which debs from the manifest
#           to fetch, e.g. 'openzfs-*', or 'linux-image-*' 'linux-*libc-dev_*'
#           to pull two disjoint sets.  A deb is fetched if it matches any
#           glob.  Debug-symbol packages (*-dbg_*) are always skipped.
#
# Fetches manifest.json and SHA256SUMS, downloads the matching debs, and
# verifies them against SHA256SUMS.  These rolling releases replace all
# assets on every publish, so consumers must fetch manifest.json to learn
# the current file names rather than hard-coding them.
#
# Prints the path to the downloaded manifest.json on stdout; all progress
# goes to stderr so callers can capture the path cleanly.
######################################################################

set -eu

REPO="$1"
TRAIN="$2"
DESTDIR="$3"
shift 3
# Remaining positional args are the globs to match ("$@").

URL="https://github.com/${REPO}/releases/download/${TRAIN}-nightly"

mkdir -p "$DESTDIR"
cd "$DESTDIR"

if ! curl --fail -LSs -O "$URL/manifest.json" ; then
  echo "ERROR: no ${TRAIN}-nightly release published for ${REPO} at $URL yet" >&2
  exit 1
fi
curl --fail -LSs -O "$URL/SHA256SUMS"

for deb in $(jq -r '.debs[]' manifest.json); do
  case "$deb" in
    *-dbg_*) continue ;;
  esac
  for glob in "$@"; do
    # glob is intentionally unquoted so the shell treats it as a pattern.
    # shellcheck disable=SC2254
    case "$deb" in
      $glob)
        echo "Downloading $deb" >&2
        curl --fail -LSs -O "$URL/$deb"
        break
        ;;
    esac
  done
done

# --ignore-missing: SHA256SUMS covers every asset in the release, but we
# only downloaded the subset matching the globs.
sha256sum -c --ignore-missing SHA256SUMS >&2

echo "$DESTDIR/manifest.json"
