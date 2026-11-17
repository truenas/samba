# truenas_smbhad

truenas_smbhad keeps a copy of the durable SMB handles that smbd holds on the
active controller of a TrueNAS HA pair. It replicates the copy to the memory
of the standby controller. After a failover, smbd restores the handles from
the copy. A restart of smbd or of the controller restores nothing and clears
the copy.

smbd uses the daemon if smb.conf has `truenas stateful failover = yes`. The
smbd side is in source3/truenas_hastate/.

A failover drops each handle that has changes the client did not flush,
unless it is a planned failover. Before middleware resets the active
controller, it blocks SMB traffic both ways, syncs the pools and runs
`truenas_smbhad mark-synced`. The daemon marks the standby's copy as
synced and exits with 0 once the standby has the mark. The standby voids
the mark on any later change to the copy, or if the primary still runs
10 s after it.

## Layout

- `proto`: the messages of smbd and the daemon, and the epoch file.
- `daemon`: the daemon.
- `client`: the client in smbd, with the record of a durable handle and the
  durable cookie of vfs_zfs_core. smbd links the static library
  `libtruenas_smbhad_client.a` and includes
  `client/include/truenas_smbhad_client.h`. cbindgen makes the header from
  `client/src/ffi.rs`, see `client/cbindgen.toml`. The header is in git.

## Testing

`cargo test` in `truenas_rust` runs the unit tests of the primary and standby
state machines, a randomized model test, integration tests with two daemons on
loopback, and tests of the client against the daemon. See `../README.md` for the
build and the other checks.
