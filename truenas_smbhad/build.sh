#!/usr/bin/env bash
# Copyright (C) iXsystems, Inc. 2026
# SPDX-License-Identifier: GPL-3.0-or-later

######################################################################
# Build truenas_smbhad for the Debian package.
#
# truenas_smbhad is a Cargo workspace in the Samba tree: the daemon, and the
# client library that smbd links (target/release/libtruenas_smbhad_client.a,
# see source3/wscript).  debian/rules runs this script before configure, and
# again with DESTDIR to install the daemon.  The truenas_ros crates need Rust 1.98.1 or newer.  Debian packages an
# older Rust.  Build-Depends cannot supply the compiler.  The script uses
# `cargo` from PATH if it is new enough.  If not, the script installs Rust
# 1.98.1 with rustup.  debian/build-liburing.sh uses the same method: a
# pinned version, downloaded at build time, with retries.
#
# Usage: truenas_smbhad/build.sh [DESTDIR]
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
# `rm -rf truenas_smbhad/target` removes all build output.  The script does
# not change the environment for a cargo from PATH.  A rustup proxy needs
# that environment to find its toolchains.
######################################################################

set -eu

RUST_VERSION="1.98.1"
RUSTUP_URL="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
RETRIES=3

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/target/debian"

# Use the toolchain that this script installs in $WORK.
use_local_toolchain() {
    export CARGO_HOME="$WORK/cargo-home"
    export RUSTUP_HOME="$WORK/rustup-home"
    CARGO="$CARGO_HOME/bin/cargo"
}

# Return true if cargo binary $1 is version RUST_VERSION or newer.
version_ok() {
    local v
    v="$("$1" --version 2>/dev/null | awk '{print $2}')" || return 1
    [ -n "$v" ] &&
        [ "$(printf '%s\n%s\n' "$RUST_VERSION" "$v" | sort -V | head -1)" = "$RUST_VERSION" ]
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

CARGO=""
if command -v cargo >/dev/null 2>&1 && version_ok "$(command -v cargo)"; then
    CARGO="$(command -v cargo)"
elif [ -x "$WORK/cargo-home/bin/cargo" ] &&
     (use_local_toolchain && version_ok "$CARGO"); then
    use_local_toolchain
elif [ "${SMBHAD_OFFLINE:-0}" = 1 ]; then
    echo "FATAL: no cargo >= $RUST_VERSION on PATH and SMBHAD_OFFLINE=1" >&2
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

if [ $# -ge 1 ]; then
    install -D -m 0755 "$BIN" "$1/usr/sbin/truenas_smbhad"
    install -D -m 0644 "$HERE/truenas-smbhad.service" \
        "$1/lib/systemd/system/truenas-smbhad.service"
    echo "Installed truenas_smbhad into $1"
fi
