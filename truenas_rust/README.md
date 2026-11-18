# truenas_rust

This Cargo workspace has the TrueNAS Rust code in the Samba tree.

## Layout

- `smbhad`: the daemon truenas_smbhad and its client in smbd. See
  `smbhad/README.md`.
- `mit/`: crates with the MIT license. A crate here does not link Samba
  code, copy Samba code or use a crate from `gpl/`. Because of this, a
  server other than Samba can use it.
  - `mit/smbros`: a shim between an SMB server and truenas_ros. Each
    connection has a reactor thread with its own ring. The
    reactor reads and sends the PDUs of the connection. The shim parses
    the framing of a PDU, but not its content. A layer above the shim
    receives each PDU first. That layer submits jobs to the reactors.
- `gpl/`: crates with the GPL-3.0-or-later license. They are for code that
  links Samba code or copies Samba logic. A crate here can use the crates
  in `mit/`.
  - `gpl/smb-server`: the layer of smbd above the shim. The reactors sign
    and encrypt with smbd's functions and keys. They do the file I/O of the
    READ, WRITE and FLUSH requests that smbd delegates to them. smbd uses
    the reactors by default. "truenas:ros transport = no" turns them off.
    Then smbd does all of the I/O, as Samba does.
  - `gpl/smb-vfs`: a stub for the file system work of smbd on the reactor
    rings.

smbd links all of these through the static library of `smbhad/client`.

## Building

The workspace uses the Rust version in `rust-toolchain.toml`. rustup selects
it for each cargo command in this directory. waf does not build the
workspace. The static library that smbd links must exist before Samba's
configure, see source3/wscript.

```sh
cargo build --release --locked
```

`build.sh [DESTDIR]` builds the workspace for the Debian package. debian/rules
runs it before configure, and again with DESTDIR to install the binary and
`truenas-smbhad.service`. The script uses exactly the version in
`rust-toolchain.toml`. If PATH has no `cargo` of that version, the script
installs it with rustup. With `SMBHAD_OFFLINE=1`, the script does not use
the network. `CARGO_HOME` must then hold all crates.

To use a newer Rust, change the version in `rust-toolchain.toml` and
`rust-version` in `Cargo.toml` together, after CI passes with it.

## Testing

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`cargo test` runs the tests of all crates. cbindgen makes the C headers of
`smbhad/client`, `mit/smbros` and `gpl/smb-server` from the Rust code. Each
crate has its `cbindgen.toml`. The headers are in git. With cbindgen 0.29.4
on PATH, `cargo test` also checks that each header is current. CI installs
that version. After a change to the C interface or its docs, run cbindgen
as `cbindgen.toml` says.

`deny.toml` has the cargo-deny rules for RustSec advisories, crate sources,
versions and licenses. `.github/workflows/rust-deps.yml` runs cargo-deny in
CI on each change of a manifest or of `Cargo.lock`. It also runs every
night. To run cargo-deny locally, run `cargo deny check` in this directory.

## License

GPL-3.0-or-later, the license of Samba. The crates in `mit/` have the MIT
license instead. Each source file has an `SPDX-License-Identifier` line.
