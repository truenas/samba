#!/usr/bin/env bash
# Copyright (C) iXsystems, Inc. 2026
# SPDX-License-Identifier: GPL-3.0-or-later

######################################################################
# Build the TrueNAS Rust workspace for the Debian package.
#
# truenas_rust is a Cargo workspace in the Samba tree.  It has the daemon
# truenas_smbhad and the client library that smbd links
# (target/release/libtruenas_smbhad_client.a, see source3/wscript).
# debian/rules runs this script before configure, and again with DESTDIR to
# install the daemon.  The build uses exactly the Rust version that
# rust-toolchain.toml names.  Debian packages an older Rust.  Build-Depends
# cannot supply the compiler.  A rustup on PATH first installs that
# version.  The script then uses `cargo` from PATH if it has that version.
# If not, the script installs that version with its own rustup.
# debian/build-liburing.sh uses the same method: a pinned version,
# downloaded at build time, with retries.
#
# Usage: truenas_rust/build.sh [DESTDIR]
#   Builds with --release --locked.  With DESTDIR, also installs
#   DESTDIR/usr/sbin/truenas_smbhad and
#   DESTDIR/lib/systemd/system/truenas-smbhad.service.
#
# Environment:
#   SMBHAD_OFFLINE=1  no network access.  The script does not install a
#                     toolchain.  The CARGO_HOME of the cargo that it uses
#                     must hold every crate (`cargo fetch --locked` on a
#                     host with network access).
#
# The script installs its toolchain in target/debian/.
# `rm -rf truenas_rust/target` removes all build output.  The script does
# not change the environment for a cargo from PATH.  A rustup proxy needs
# that environment to find its toolchains.
######################################################################

set -eu

RUSTUP_URL="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
RETRIES=3

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/target/debian"

# Create DESTDIR and make it absolute before the cd below.
DESTDIR=""
if [ $# -ge 1 ]; then
    mkdir -p "$1"
    DESTDIR="$(cd "$1" && pwd)"
fi

# rustup uses rust-toolchain.toml for each cargo command in this directory.
cd "$HERE"
RUST_VERSION="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
if [ -z "$RUST_VERSION" ]; then
    echo "FATAL: rust-toolchain.toml names no channel" >&2
    exit 1
fi

# Use the toolchain that this script installs in $WORK.
use_local_toolchain() {
    export CARGO_HOME="$WORK/cargo-home"
    export RUSTUP_HOME="$WORK/rustup-home"
    CARGO="$CARGO_HOME/bin/cargo"
}

# Return true if cargo binary $1 is version RUST_VERSION.
version_ok() {
    local v
    v="$("$1" --version 2>/dev/null | awk '{print $2}')" || return 1
    [ "$v" = "$RUST_VERSION" ]
}

# Run "$@" until it succeeds, at most RETRIES times.
retry() {
    local attempt=1
    until "$@"; do
        if [ "$attempt" -ge "$RETRIES" ]; then
            return 1
        fi
        echo "'$*' failed (attempt $attempt/$RETRIES), retrying..." >&2
        sleep $((2 * attempt))
        attempt=$((attempt + 1))
    done
}

if [ "$(uname -m)" != x86_64 ]; then
    echo "FATAL: only x86_64 is supported" >&2
    exit 1
fi

if [ "${SMBHAD_OFFLINE:-0}" != 1 ] && command -v rustup >/dev/null 2>&1; then
    # The cargo proxy of this rustup then uses RUST_VERSION in this directory.
    retry rustup toolchain install "$RUST_VERSION" --profile minimal
fi

CARGO=""
if command -v cargo >/dev/null 2>&1 && version_ok "$(command -v cargo)"; then
    CARGO="$(command -v cargo)"
elif [ -x "$WORK/cargo-home/bin/cargo" ] &&
     (use_local_toolchain && version_ok "$CARGO"); then
    use_local_toolchain
elif [ "${SMBHAD_OFFLINE:-0}" = 1 ]; then
    echo "FATAL: no cargo $RUST_VERSION on PATH and SMBHAD_OFFLINE=1" >&2
    exit 1
else
    mkdir -p "$WORK"
    retry curl --proto '=https' --tlsv1.2 -fsSL -o "$WORK/rustup-init" "$RUSTUP_URL"
    retry curl --proto '=https' --tlsv1.2 -fsSL -o "$WORK/rustup-init.sha256" "$RUSTUP_URL.sha256"
    want="$(awk '{print $1}' "$WORK/rustup-init.sha256")"
    have="$(sha256sum "$WORK/rustup-init" | awk '{print $1}')"
    if [ "$want" != "$have" ]; then
        echo "FATAL: rustup-init checksum $have, expected $want" >&2
        exit 1
    fi
    chmod +x "$WORK/rustup-init"
    use_local_toolchain
    # Skip the rustup-init check for other Rust installations.  An older
    # Rust on PATH stays installed.
    retry env RUSTUP_INIT_SKIP_PATH_CHECK=yes "$WORK/rustup-init" -y \
        --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION"
    if ! version_ok "$CARGO"; then
        echo "FATAL: rustup did not install cargo $RUST_VERSION" >&2
        exit 1
    fi
fi
echo "Using $("$CARGO" --version) from $CARGO"

MANIFEST="$HERE/Cargo.toml"
if [ "${SMBHAD_OFFLINE:-0}" = 1 ]; then
    "$CARGO" build --release --locked --offline --manifest-path "$MANIFEST"
else
    retry "$CARGO" fetch --locked --manifest-path "$MANIFEST"
    "$CARGO" build --release --locked --manifest-path "$MANIFEST"
fi

BIN="$HERE/target/release/truenas_smbhad"
"$BIN" --version

if [ -n "$DESTDIR" ]; then
    install -D -m 0755 "$BIN" "$DESTDIR/usr/sbin/truenas_smbhad"
    install -D -m 0644 "$HERE/smbhad/truenas-smbhad.service" \
        "$DESTDIR/lib/systemd/system/truenas-smbhad.service"
    echo "Installed truenas_smbhad into $DESTDIR"
fi
