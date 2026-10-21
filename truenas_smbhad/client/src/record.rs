// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The record of a durable handle in XDR (RFC 4506). smbd sends it in a put
//! to the daemon. The daemon keeps it as opaque data. The record contains no
//! Samba structure: at restore, each Samba version builds its own structures
//! from it. A controller can restore the records of a controller with
//! another Samba version. Every version writes record version 1. A reader
//! drops a record with another version, a value out of range or data after
//! the end.
//!
//! Later changes without a new version:
//! - A new flag in bits 0-15 is critical: a reader that does not know it
//!   drops the record. A new flag in bits 16-31 is ignorable: a reader that
//!   does not know it restores the record as if the flag were not set.
//! - A new extension is critical if bit 31 of its type is set, with the same
//!   rule. A reader skips an ignorable extension that it does not know.
//! - A change that a reader can neither ignore nor detect needs a new
//!   version. A reader drops all records of a version that it does not
//!   know, for example the records of the other controller during an
//!   upgrade.

use serde::{Deserialize, Serialize};
use truenas_xdr::{Bounded, FixedOpaque, VarOpaque, XdrUnion};

/// The record version that this version writes and reads.
pub const TRUENAS_DURABLE_RECORD_VERSION: u32 = 1;

/// The handle is disconnected.
pub const TRUENAS_DURABLE_DISCONNECTED: u32 = 0x1;
/// The handle has unflushed changes.
pub const TRUENAS_DURABLE_DIRTY: u32 = 0x2;
/// Later lock changes can be missing from the record.
pub const TRUENAS_DURABLE_LOCKS_UNSTABLE: u32 = 0x4;
/// A persistent handle. Reserved: no reader restores it yet, and a reader
/// that does not know it must not restore it as a durable handle.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const PERSISTENT: u32 = 0x0000_0008;
/// An unknown flag in these bits makes a reader drop the record.
pub(crate) const CRITICAL_FLAGS: u32 = 0x0000_ffff;
/// The critical flags that this version knows.
pub(crate) const KNOWN_FLAGS: u32 = TRUENAS_DURABLE_DISCONNECTED
    | TRUENAS_DURABLE_DIRTY
    | TRUENAS_DURABLE_LOCKS_UNSTABLE;
/// An unknown extension with this bit makes a reader drop the record.
pub(crate) const EXT_CRITICAL: u32 = 0x8000_0000;

/// A SID: the revision, the 48-bit identifier authority and at most 15 sub
/// authorities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sid {
    /// 0 to 255.
    pub revision: u8,
    /// Below 2^48.
    pub authority: u64,
    /// The sub authorities.
    pub sub_auths: Bounded<Vec<u32>, 15>,
}

/// A byte range lock of the open. `struct truenas_durable_lock` in C.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    /// The first byte.
    pub start: u64,
    /// The number of bytes.
    pub size: u64,
    /// Samba's `enum brl_type`.
    pub lock_type: u32,
    /// Samba's `enum brl_flavour`.
    pub lock_flav: u32,
}

/// An extension of a later version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext {
    /// Bit 31: critical, see `EXT_CRITICAL`.
    pub kind: u32,
    /// The data of the extension.
    pub data: VarOpaque,
}

/// Version 1 of the record. `struct truenas_durable_record` in the C
/// interface has the meaning of each field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordV1 {
    pub flags: u32,
    pub updated: u64,
    pub change_cookie: u64,
    /// The path of the share. On the wire this is an XDR string.
    pub servicepath: VarOpaque,
    /// The path of the file in the share. An XDR string.
    pub base_name: VarOpaque,
    /// The file system of the file: statfs `f_fsid`. ZFS keeps it in the
    /// dataset, so an import of the pool on the other controller keeps it.
    pub fsid: u64,
    pub inode: u64,
    pub extid: u64,
    pub name_hash: u32,
    pub persistent_id: u64,
    pub volatile_id: u64,
    pub owner: Sid,
    pub open_time: u64,
    /// GUIDs in RFC 4122 byte order.
    pub create_guid: FixedOpaque<16>,
    pub client_guid: FixedOpaque<16>,
    pub app_instance_id: FixedOpaque<16>,
    pub app_instance_vhigh: u64,
    pub app_instance_vlow: u64,
    pub create_action: u32,
    pub disconnect_time: u64,
    pub durable_timeout_msec: u32,
    /// 0 to 65535 on the wire, an XDR unsigned int.
    pub channel_sequence: u16,
    pub channel_generation: u64,
    pub lock_sequence_array: FixedOpaque<64>,
    pub op_type: u32,
    pub lease_key: [u64; 2],
    pub access_mask: u32,
    pub share_access: u32,
    pub share_time: u64,
    pub uid: u32,
    pub share_flags: u32,
    pub lease_state: u32,
    /// 0 to 65535.
    pub lease_version: u16,
    /// 0 to 65535.
    pub lease_epoch: u16,
    pub initial_allocation_size: u64,
    pub position_information: u64,
    pub write_time_forced: bool,
    pub locks: Vec<Lock>,
    /// None in version 1.
    pub exts: Vec<Ext>,
}

/// The record, by version.
#[derive(XdrUnion, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Record {
    /// See `RecordV1`.
    V1(RecordV1) = 1,
}

/// Encodes `r` as a version 1 record.
///
/// # Errors
///
/// A value has no XDR encoding, for example more than 15 sub authorities.
pub fn encode(r: &RecordV1) -> truenas_xdr::Result<Vec<u8>> {
    truenas_xdr::to_bytes(&Record::V1(r.clone()))
}

/// Decodes a record. `None` if `bytes` is not a record that this version
/// can restore: another version, a value out of range, an unknown critical
/// flag or extension, or data after the end.
pub fn decode(bytes: &[u8]) -> Option<RecordV1> {
    let Record::V1(r) = truenas_xdr::from_bytes(bytes).ok()?;
    if (r.flags & CRITICAL_FLAGS & !KNOWN_FLAGS) != 0
        || (r.owner.authority >> 48) != 0
        || r.exts.iter().any(|e| (e.kind & EXT_CRITICAL) != 0)
    {
        return None;
    }
    Some(r)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The record of the pinned bytes, see `PINNED`.
    pub(crate) fn sample() -> RecordV1 {
        let mut lock_sequence_array = [0u8; 64];
        for (i, b) in lock_sequence_array.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        RecordV1 {
            flags: TRUENAS_DURABLE_DISCONNECTED,
            updated: 0x0102_0304_0506_0708,
            change_cookie: 0x1112_1314_1516_1718,
            servicepath: VarOpaque(b"/mnt/tank/share".to_vec()),
            base_name: VarOpaque(b"dir/file.txt".to_vec()),
            fsid: 0x21,
            inode: 0x22,
            extid: 0x23,
            name_hash: 0x2425_2627,
            persistent_id: 0x31,
            volatile_id: 0x32,
            owner: Sid {
                revision: 1,
                authority: 5,
                sub_auths: Bounded(vec![21, 1, 2, 3, 1000]),
            },
            open_time: 0x33,
            create_guid: FixedOpaque([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
                0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            ]),
            client_guid: FixedOpaque([
                0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
                0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            ]),
            app_instance_id: FixedOpaque([
                0x66, 0x66, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            ]),
            app_instance_vhigh: 0x38,
            app_instance_vlow: 0x39,
            create_action: 2,
            disconnect_time: 0x34,
            durable_timeout_msec: 60000,
            channel_sequence: 7,
            channel_generation: 8,
            lock_sequence_array: FixedOpaque(lock_sequence_array),
            op_type: 0x100,
            lease_key: [0x41, 0x42],
            access_mask: 0x0012_019f,
            share_access: 7,
            share_time: 0x35,
            uid: 1000,
            share_flags: 0,
            lease_state: 7,
            lease_version: 2,
            lease_epoch: 3,
            initial_allocation_size: 0x36,
            position_information: 0x37,
            write_time_forced: true,
            locks: vec![Lock {
                start: 4096,
                size: 512,
                lock_type: 1,
                lock_flav: 0,
            }],
            exts: Vec::new(),
        }
    }

    /// The pinned bytes of `sample()`: the bytes of every earlier version. The
    /// controllers of a pair can run different versions during an upgrade.
    pub(crate) const PINNED: &str = concat!(
        "0000000100000001010203040506070811121314151617180000000F2F6D6E74",
        "2F74616E6B2F7368617265000000000C6469722F66696C652E74787400000000",
        "0000002100000000000000220000000000000023242526270000000000000031",
        "0000000000000032000000010000000000000005000000050000001500000001",
        "0000000200000003000003E800000000000000330123456789ABCDEF01234567",
        "89ABCDEF1111111122223333444455555555555566666666777788889999AAAA",
        "AAAAAAAA00000000000000380000000000000039000000020000000000000034",
        "0000EA60000000070000000000000008000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
        "303132333435363738393A3B3C3D3E3F00000100000000000000004100000000",
        "000000420012019F000000070000000000000035000003E80000000000000007",
        "0000000200000003000000000000003600000000000000370000000100000001",
        "00000000000010000000000000000200000000010000000000000000",
    );

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn set_u32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }

    /// `pinned` with one extension of type `kind`
    fn with_ext(pinned: &[u8], kind: u32) -> Vec<u8> {
        let mut b = pinned[..pinned.len() - 4].to_vec();
        for v in [1, kind, 4, 0x0102_0304] {
            b.extend_from_slice(&u32::to_be_bytes(v));
        }
        b
    }

    #[test]
    fn a_record_has_the_pinned_bytes() {
        let pinned = unhex(PINNED);
        assert_eq!(encode(&sample()).unwrap(), pinned);
        assert_eq!(decode(&pinned), Some(sample()));
    }

    #[test]
    fn a_reader_drops_what_it_cannot_restore() {
        let pinned = unhex(PINNED);
        let mut bad = pinned.clone();
        set_u32(&mut bad, 0, TRUENAS_DURABLE_RECORD_VERSION + 1);
        assert_eq!(decode(&bad), None, "another version");
        for n in 0..pinned.len() {
            assert_eq!(decode(&pinned[..n]), None, "{n} bytes");
        }
        let mut longer = pinned.clone();
        longer.extend_from_slice(&[0; 4]);
        assert_eq!(decode(&longer), None, "data after the end");
        // lease_epoch, before two hypers, a bool, a lock and two counts
        let mut bad = pinned.clone();
        let at = bad.len() - 56;
        set_u32(&mut bad, at, 0x10000);
        assert_eq!(decode(&bad), None, "a 16-bit value over 65535");
    }

    #[test]
    fn unknown_critical_flags_and_extensions_drop_the_record() {
        let pinned = unhex(PINNED);
        let mut bad = pinned.clone();
        set_u32(&mut bad, 4, TRUENAS_DURABLE_DISCONNECTED | PERSISTENT);
        assert_eq!(decode(&bad), None, "a persistent handle");
        set_u32(&mut bad, 4, TRUENAS_DURABLE_DISCONNECTED | 0x0001_0000);
        assert_eq!(
            decode(&bad).unwrap().flags,
            TRUENAS_DURABLE_DISCONNECTED | 0x0001_0000
        );
        assert_eq!(decode(&with_ext(&pinned, EXT_CRITICAL | 1)), None);
        assert_eq!(decode(&with_ext(&pinned, 1)).unwrap().exts.len(), 1);
    }

    #[test]
    fn an_authority_of_48_bits_or_more_is_out_of_range() {
        let mut r = sample();
        r.owner.authority = 1 << 48;
        assert_eq!(decode(&encode(&r).unwrap()), None);
        r.owner.sub_auths = Bounded(vec![0; 16]);
        assert!(encode(&r).is_err(), "16 sub authorities");
    }
}
