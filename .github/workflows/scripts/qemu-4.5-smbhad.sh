#!/usr/bin/env bash

######################################################################
# The tests of truenas_smbhad in the VM, after the restart into the
# TrueNAS kernel: unit tests, the model test, the integration tests with
# two daemons on loopback, the tests of the client of smbd, rustfmt and
# clippy. The package build
# (truenas_smbhad/build.sh) left the workspace's build tree and, if Debian's
# Rust is too old, its own Rust toolchain in ~/samba.
######################################################################

set -eu

source /tmp/vm-info.sh

ssh debian@$VM_IP bash -s <<'REMOTE_SCRIPT'
set -eu
cd ~/samba/truenas_smbhad
WORK="$PWD/target/debian"
if [ -x "$WORK/cargo-home/bin/cargo" ]; then
	export CARGO_HOME="$WORK/cargo-home"
	export RUSTUP_HOME="$WORK/rustup-home"
	export PATH="$CARGO_HOME/bin:$PATH"
	# build.sh installs the minimal profile.
	rustup component add rustfmt clippy
fi
cargo --version
echo "=========================================="
echo "truenas_smbhad: rustfmt"
echo "=========================================="
cargo fmt --check
echo "=========================================="
echo "truenas_smbhad: clippy"
echo "=========================================="
cargo clippy --locked --all-targets -- -D warnings
echo "=========================================="
echo "truenas_smbhad: tests"
echo "=========================================="
# The test header_is_current compares the C header of the client with the
# output of cbindgen.
cargo install --locked cbindgen --version 0.29.4
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
# Each HA test starts daemons with io_uring rings, which take locked
# memory. More test threads than RLIMIT_MEMLOCK allows fail with ENOMEM.
cargo test --locked -- --test-threads=8
echo "truenas_smbhad tests PASSED"
REMOTE_SCRIPT
