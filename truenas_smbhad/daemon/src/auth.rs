// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The link handshake.
//!
//! Both controllers have the same pwenc secret. The secret also encrypts the
//! passwords that middleware stores. The daemons derive the link key from
//! the secret. Each side proves that it has the link key. The proof is an
//! HMAC over a label for the side, both nodes and both nonces. A proof
//! from one side does not verify for the other side. The link has no
//! encryption and no per-message MAC. The link does not leave the chassis.

use crate::proto::Node;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
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
    /// and info `replication key v1`.
    ///
    /// # Panics
    ///
    /// Never. HKDF-SHA256 can output up to 8160 bytes. The key has 32 bytes.
    pub fn derive(secret: &[u8]) -> LinkKey {
        let hk = Hkdf::<Sha256>::new(Some(b"truenas_smbhad"), secret);
        let mut okm = [0u8; 32];
        hk.expand(b"replication key v1", &mut okm)
            .expect("32 bytes is within HKDF-SHA256's output limit");
        LinkKey(okm)
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
    /// From the standby's hello.
    pub standby_node: Node,
    /// From the standby's hello.
    pub standby_nonce: &'a Nonce,
    /// From the primary's challenge.
    pub primary_node: Node,
    /// From the primary's challenge.
    pub primary_nonce: &'a Nonce,
}

fn mac(key: &LinkKey, side: Side, t: &Transcript<'_>) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key.0)
        .expect("HMAC accepts a key of any length");
    m.update(side.label());
    m.update(&(t.standby_node as i32).to_be_bytes());
    m.update(&t.standby_nonce.0);
    m.update(&(t.primary_node as i32).to_be_bytes());
    m.update(&t.primary_nonce.0);
    m
}

/// Returns the proof that `side` sends.
pub fn proof(key: &LinkKey, side: Side, t: &Transcript<'_>) -> Proof {
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac(key, side, t).finalize().into_bytes());
    FixedOpaque(out)
}

/// Checks a proof that `side` sent. The comparison takes constant time.
pub fn verify(
    key: &LinkKey,
    side: Side,
    t: &Transcript<'_>,
    proof: &Proof,
) -> bool {
    mac(key, side, t).verify_slice(&proof.0).is_ok()
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

    fn transcript() -> Transcript<'static> {
        Transcript {
            standby_node: SNODE,
            standby_nonce: &SN,
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
        let key = LinkKey::derive(&secret());
        assert_eq!(
            hex(&key.0),
            "015a892b5dc747ff5a87a06ab12e93677a83dd5db4a9f1c5a20ce4d82bf179f2"
        );
        assert_eq!(
            hex(&proof(&key, Side::Primary, &transcript()).0),
            "e0aa788334de8cf5342c83d2bf7828b8673bb27b05d767e7c687aa725af15761"
        );
        assert_eq!(
            hex(&proof(&key, Side::Standby, &transcript()).0),
            "0a7d9150cf118ee557939b7ccc17c524a70222745a2d846a8729669aaea2d59c"
        );
    }

    #[test]
    fn a_proof_verifies_only_for_its_own_side_key_and_nonces() {
        let key = LinkKey::derive(&secret());
        let t = transcript();
        let p = proof(&key, Side::Standby, &t);
        assert!(verify(&key, Side::Standby, &t, &p));
        assert!(!verify(&key, Side::Primary, &t, &p), "reflected");
        let other = LinkKey::derive(b"another secret");
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
}
