// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The boot id, and random values for nonces and instance ids.

use crate::proto::BootId;
use std::io;
use std::path::Path;
use truenas_xdr::FixedOpaque;

/// Reads the kernel boot id from `path`, for example
/// `/proc/sys/kernel/random/boot_id`. The file holds a UUID with dashes.
///
/// # Errors
///
/// The file is not readable or does not hold a UUID.
pub fn boot_id(path: &Path) -> io::Result<BootId> {
    let text = std::fs::read_to_string(path)?;
    parse_hex16(&text.replace('-', ""), path)
}

fn parse_hex16(text: &str, path: &Path) -> io::Result<FixedOpaque<16>> {
    let hex = text.trim();
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: not 16 bytes of hex", path.display()),
        )
    };
    if hex.len() != 32 || !hex.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| bad())?;
    }
    Ok(FixedOpaque(out))
}

/// Fills `buf` with random bytes from OpenSSL (`RAND_bytes`).
///
/// # Panics
///
/// OpenSSL has no random bytes.
pub fn random_fill(buf: &mut [u8]) {
    openssl::rand::rand_bytes(buf).expect("OpenSSL gives random bytes");
}

/// Returns a random 64-bit value.
pub fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    random_fill(&mut b);
    u64::from_ne_bytes(b)
}

/// Returns a boot id as hex digits, for the log.
pub fn hex(id: &FixedOpaque<16>) -> String {
    use std::fmt::Write;
    id.0.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::single_match_else
)]
mod tests {
    use super::*;

    #[test]
    fn boot_ids_parse() {
        let dir = truenas_ros::tempdir().unwrap();
        let b = dir.path().join("boot_id");
        std::fs::write(&b, "01234567-89ab-cdef-0123-456789abcdef\n").unwrap();
        assert_eq!(
            hex(&boot_id(&b).unwrap()),
            "0123456789abcdef0123456789abcdef"
        );
        std::fs::write(&b, "nothex").unwrap();
        assert!(boot_id(&b).is_err());
    }
}
