// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The link handshake.
//!
//! Both controllers have the same pwenc secret. The secret also encrypts the
//! passwords that middleware stores. The daemons derive the link key from
//! the secret. Each side proves that it has the link key. The proof is an
//! HMAC over a label for the side and the values of the hello and the
//! challenge: both versions, both nodes and both nonces. A proof from one
//! side does not verify for the other side. A version that changes on the
//! link makes the proofs fail. The link has no encryption and no
//! per-message MAC. The link does not leave the chassis.
//!
//! OpenSSL (libcrypto) does the HKDF, the HMAC and the comparison. In FIPS
//! mode, the FIPS provider of OpenSSL does this work.

use crate::proto::Node;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::pkey::{Id, PKey};
use openssl::pkey_ctx::PkeyCtx;
use openssl::sign::Signer;
use std::fmt;
use truenas_xdr::FixedOpaque;

/// A handshake nonce, random per connection.
pub type Nonce = FixedOpaque<32>;

/// An HMAC-SHA256 proof of the link key.
pub type Proof = FixedOpaque<32>;

/// The key that both daemons derive from the pwenc secret.
pub struct LinkKey([u8; 32]);

impl fmt::Debug for LinkKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkKey(..)")
    }
}

impl LinkKey {
    /// Derives the key from `secret` with HKDF-SHA256, salt `truenas_smbhad`
    /// and info `replication key v1`. The bytes are used as read: a newline
    /// at the end is part of the key. An empty secret also gives a key;
    /// `read_key()` refuses an empty file.
    ///
    /// # Errors
    ///
    /// OpenSSL fails.
    pub fn derive(secret: &[u8]) -> Result<LinkKey, ErrorStack> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
        ctx.derive_init()?;
        ctx.set_hkdf_md(Md::sha256())?;
        ctx.set_hkdf_salt(b"truenas_smbhad")?;
        ctx.set_hkdf_key(secret)?;
        ctx.add_hkdf_info(b"replication key v1")?;
        let mut okm = [0u8; 32];
        ctx.derive(Some(&mut okm))?;
        Ok(LinkKey(okm))
    }
}

/// The side of the link that sends a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The controller that has the pool and sends the copy.
    Primary,
    /// The controller that receives the copy.
    Standby,
}

impl Side {
    fn label(self) -> &'static [u8] {
        match self {
            Side::Primary => b"truenas_smbhad v1 primary",
            Side::Standby => b"truenas_smbhad v1 standby",
        }
    }
}

/// The handshake values in the HMAC input of both proofs.
#[derive(Clone, Copy, Debug)]
pub struct Transcript<'a> {
    /// From the standby's hello: the highest version that it speaks.
    pub standby_version: u32,
    /// From the standby's hello.
    pub standby_node: Node,
    /// From the standby's hello.
    pub standby_nonce: &'a Nonce,
    /// From the primary's challenge: the version of the session.
    pub version: u32,
    /// From the primary's challenge.
    pub primary_node: Node,
    /// From the primary's challenge.
    pub primary_nonce: &'a Nonce,
}

fn mac(
    key: &LinkKey,
    side: Side,
    t: &Transcript<'_>,
) -> Result<[u8; 32], ErrorStack> {
    let pkey = PKey::hmac(&key.0)?;
    let mut m = Signer::new(MessageDigest::sha256(), &pkey)?;
    m.update(side.label())?;
    m.update(&t.standby_version.to_be_bytes())?;
    m.update(&(t.standby_node as i32).to_be_bytes())?;
    m.update(&t.standby_nonce.0)?;
    m.update(&t.version.to_be_bytes())?;
    m.update(&(t.primary_node as i32).to_be_bytes())?;
    m.update(&t.primary_nonce.0)?;
    let mut out = [0u8; 32];
    m.sign(&mut out)?;
    Ok(out)
}

/// Returns the proof that `side` sends.
///
/// # Errors
///
/// OpenSSL fails.
pub fn proof(
    key: &LinkKey,
    side: Side,
    t: &Transcript<'_>,
) -> Result<Proof, ErrorStack> {
    mac(key, side, t).map(FixedOpaque)
}

/// Checks a proof that `side` sent. The comparison takes constant time. If
/// OpenSSL fails, the proof does not verify.
pub fn verify(
    key: &LinkKey,
    side: Side,
    t: &Transcript<'_>,
    proof: &Proof,
) -> bool {
    mac(key, side, t).is_ok_and(|m| openssl::memcmp::eq(&m, &proof.0))
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

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    const SNODE: Node = Node::B;
    const SN: Nonce = FixedOpaque([2; 32]);
    const PNODE: Node = Node::A;
    const PN: Nonce = FixedOpaque([4; 32]);

    // A newer standby and a session of version 1: the two versions differ.
    fn transcript() -> Transcript<'static> {
        Transcript {
            standby_version: 3,
            standby_node: SNODE,
            standby_nonce: &SN,
            version: 1,
            primary_node: PNODE,
            primary_nonce: &PN,
        }
    }

    fn secret() -> Vec<u8> {
        (0u8..64).collect()
    }

    // Python's hmac and hashlib computed the expected values, with a manual
    // HKDF (RFC 5869). Daemons that compute different values cannot
    // authenticate to each other.
    #[test]
    fn key_and_proofs_match_known_answers() {
        let key = LinkKey::derive(&secret()).unwrap();
        assert_eq!(
            hex(&key.0),
            "015a892b5dc747ff5a87a06ab12e93677a83dd5db4a9f1c5a20ce4d82bf179f2"
        );
        assert_eq!(
            hex(&proof(&key, Side::Primary, &transcript()).unwrap().0),
            "7e94ccdfc89316137ddc97c126151e5ad4d188e6f64a538fac39d6a5cead2bed"
        );
        assert_eq!(
            hex(&proof(&key, Side::Standby, &transcript()).unwrap().0),
            "4488012ca3f1fa49629aed7d617343aa104fd1949f436d5a114e4897d133abef"
        );
    }

    #[test]
    fn a_proof_verifies_only_for_its_own_side_key_and_nonces() {
        let key = LinkKey::derive(&secret()).unwrap();
        let t = transcript();
        let p = proof(&key, Side::Standby, &t).unwrap();
        assert!(verify(&key, Side::Standby, &t, &p));
        assert!(!verify(&key, Side::Primary, &t, &p), "reflected");
        let other = LinkKey::derive(b"another secret").unwrap();
        assert!(!verify(&other, Side::Standby, &t, &p), "wrong key");
        let replayed = FixedOpaque([5; 32]);
        let t2 = Transcript {
            primary_nonce: &replayed,
            ..t
        };
        assert!(
            !verify(&key, Side::Standby, &t2, &p),
            "replayed into a new handshake"
        );
    }

    // A change that trims the secret would change the key of every system.
    #[test]
    fn the_secret_bytes_are_used_as_read() {
        assert_eq!(
            hex(&LinkKey::derive(b"\n").unwrap().0),
            "65688b58f6f52107433d2af3f64ee314b0ea281c8ba9fe0eb2c8207297911b1d"
        );
        assert!(LinkKey::derive(b"").is_ok());
    }

    #[test]
    fn a_proof_does_not_verify_for_other_versions() {
        let key = LinkKey::derive(&secret()).unwrap();
        let t = transcript();
        let p = proof(&key, Side::Primary, &t).unwrap();
        let hello = Transcript {
            standby_version: 2,
            ..t
        };
        assert!(!verify(&key, Side::Primary, &hello, &p), "hello version");
        let session = Transcript { version: 2, ..t };
        assert!(!verify(&key, Side::Primary, &session, &p), "session");
    }
}
