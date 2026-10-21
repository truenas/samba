// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The durable cookie of `vfs_zfs_core`, in XDR. smbd keeps it in the backend
//! cookie of `smbXsrv_open_global`. ZFS changes the change cookie of a file
//! on every data or metadata change. A reconnect fails if the file has a
//! different change cookie. `share` is the name of the share of the open:
//! the scavenger sends the records of the disconnected handles again. smbd
//! builds the cookie again at restore, so only one Samba version reads it.

use serde::{Deserialize, Serialize};
use truenas_xdr::{VarOpaqueRef, XdrUnion};

/// The first 4 bytes of the cookie: "tzck" as a big-endian number.
pub(crate) const MAGIC: u32 = 0x6b63_7a74;
/// smbd restored the open.
pub const TRUENAS_ZFS_DURABLE_RESTORED: u32 = 0x1;
/// Unflushed changes from before the disconnect.
pub const TRUENAS_ZFS_DURABLE_DIRTY: u32 = 0x2;
/// A flush does not write the data to disk: the dataset has
/// sync=disabled, or smbd cannot read its sync property.
pub const TRUENAS_ZFS_DURABLE_NO_SYNC: u32 = 0x4;

/// Version 1 of the cookie. The data is in the encoded cookie.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieV1<'a> {
    /// `RESTORED` and the other flags.
    pub flags: u32,
    /// The change cookie of the file at the disconnect.
    pub change_cookie: u64,
    /// The share of the open. An XDR string.
    #[serde(borrow)]
    pub share: VarOpaqueRef<'a>,
    /// The `vfs_default` cookie.
    #[serde(borrow)]
    pub inner: VarOpaqueRef<'a>,
}

/// The body of the cookie, by version.
#[derive(XdrUnion, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Body<'a> {
    /// See `CookieV1`.
    V1(CookieV1<'a>) = 1,
}

/// The cookie.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cookie<'a> {
    /// `MAGIC`.
    pub magic: u32,
    /// The body.
    #[serde(borrow)]
    pub body: Body<'a>,
}

/// Encodes a version 1 cookie.
///
/// # Errors
///
/// A value has no XDR encoding.
pub fn encode(c: &CookieV1<'_>) -> truenas_xdr::Result<Vec<u8>> {
    truenas_xdr::to_bytes(&Cookie {
        magic: MAGIC,
        body: Body::V1(c.clone()),
    })
}

/// Decodes a cookie. `None` if `bytes` is not a cookie of `vfs_zfs_core` of
/// this version, for example a `vfs_default` cookie.
pub fn decode(bytes: &[u8]) -> Option<CookieV1<'_>> {
    let c: Cookie<'_> = truenas_xdr::from_bytes(bytes).ok()?;
    if c.magic != MAGIC {
        return None;
    }
    let Body::V1(v) = c.body;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::unhex;

    fn sample() -> CookieV1<'static> {
        CookieV1 {
            flags: TRUENAS_ZFS_DURABLE_RESTORED | TRUENAS_ZFS_DURABLE_DIRTY,
            change_cookie: 0x0102_0304_0506_0708,
            share: VarOpaqueRef(b"share"),
            inner: VarOpaqueRef(b"VFS_\x01\x02\x03"),
        }
    }

    #[test]
    fn a_cookie_has_the_pinned_bytes() {
        let pinned = unhex(concat!(
            "6B637A740000000100000003010203040506070800000005",
            "7368617265000000000000075646535F01020300",
        ));
        assert_eq!(encode(&sample()).unwrap(), pinned);
        assert_eq!(decode(&pinned), Some(sample()));
        assert_eq!(decode(sample().inner.0), None, "a vfs_default cookie");
        let mut other = pinned.clone();
        // version 2
        other[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(decode(&other), None, "another version");
        assert_eq!(decode(&pinned[..pinned.len() - 4]), None, "short");
    }
}
