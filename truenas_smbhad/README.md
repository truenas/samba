# truenas_smbhad

truenas_smbhad keeps a copy of the durable SMB handles that smbd holds on the
active controller of a TrueNAS HA pair. It replicates the copy to the memory
of the standby controller. After a failover, smbd restores the handles from
the copy. A restart of smbd or of the controller restores nothing and clears
the copy.

smbd uses the daemon if smb.conf has `truenas stateful failover = yes`. The
smbd side is in source3/truenas_hastate/.

## Layout

A Cargo workspace:

- `proto`: the messages of smbd and the daemon, and the epoch file.
- `daemon`: the daemon.
- `client`: the client in smbd, with the record of a durable handle and the
  durable cookie of vfs_zfs_core. smbd links the static library
  `libtruenas_smbhad_client.a` and includes
  `client/include/truenas_smbhad_client.h`. cbindgen makes the header from
  `client/src/ffi.rs`, see `client/cbindgen.toml`. The header is in git.

## Building

The workspace needs Rust 1.98.1 or newer. waf does not build it. The static
library must exist before Samba's configure, see source3/wscript.

```sh
cargo build --release --locked
```

`build.sh [DESTDIR]` builds the workspace for the Debian package. debian/rules
runs it before configure, and again with DESTDIR to install the binary and
`truenas-smbhad.service`. If PATH has no `cargo` 1.98.1 or newer, the script
installs Rust 1.98.1 with rustup. With `SMBHAD_OFFLINE=1`, the script does
not use the network. `CARGO_HOME` must then hold all crates.

## Testing

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`cargo test` runs the unit tests of the primary and standby state machines, a
randomized model test, integration tests with two daemons on loopback, and
tests of the client against the daemon. With cbindgen on PATH, it also checks
that the header is current.

## License

GPL-3.0-or-later, the license of Samba. Each source file has an
`SPDX-License-Identifier` line.
