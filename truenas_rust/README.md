# truenas_rust

This Cargo workspace has the TrueNAS Rust code in the Samba tree.

## Layout

- `smbhad`: the daemon truenas_smbhad and its client in smbd. See
  `smbhad/README.md`.

## Building

The workspace needs Rust 1.98.1 or newer. waf does not build it. The static
library that smbd links must exist before Samba's configure, see
source3/wscript.

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

`cargo test` runs the tests of all crates. With cbindgen on PATH, it also checks
that the C headers are current.

## License

GPL-3.0-or-later, the license of Samba. Each source file has an
`SPDX-License-Identifier` line.
