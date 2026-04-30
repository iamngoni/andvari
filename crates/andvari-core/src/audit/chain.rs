//! HMAC chain construction + verification.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::RootKey;

/// HKDF-`info` parameter used to derive the audit HMAC key from the Root Key.
/// Bumping this byte-string rotates the entire chain — older rows would no
/// longer verify, so leave it stable across versions.
pub const AUDIT_HMAC_INFO: &[u8] = b"andvari-audit-hmac-v1";

/// Length of every chain link.
pub const CHAIN_LEN: usize = 32;

/// "Genesis" prev-chain — all zeroes, used as the input for the first row.
pub const GENESIS_CHAIN: [u8; CHAIN_LEN] = [0u8; CHAIN_LEN];

/// Symmetric key used to chain audit rows. Derived from the Root Key via
/// HKDF-SHA256 and zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuditHmacKey([u8; CHAIN_LEN]);

impl AuditHmacKey {
    /// Derive from the current Root Key. Cheap (one HKDF expand); call from
    /// the audit hot path is fine.
    pub fn derive_from_rk(rk: &RootKey) -> Self {
        let hk = Hkdf::<Sha256>::new(None, rk.as_bytes());
        let mut key = [0u8; CHAIN_LEN];
        hk.expand(AUDIT_HMAC_INFO, &mut key)
            .expect("HKDF expand of 32 bytes from 32-byte IKM never fails");
        Self(key)
    }

    /// For testing / known-answer vectors.
    pub fn from_bytes(bytes: [u8; CHAIN_LEN]) -> Self {
        Self(bytes)
    }
}

/// Compute the chain link for a single row.
///
/// `prev_chain` is the previous row's `hmac_chain` (or [`GENESIS_CHAIN`] for
/// the very first row). `row_canonical_bytes` is the deterministic
/// serialization produced by [`super::AuditRow::canonical_bytes`].
pub fn compute_chain(
    key: &AuditHmacKey,
    prev_chain: &[u8],
    row_canonical_bytes: &[u8],
) -> [u8; CHAIN_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.0)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(prev_chain);
    mac.update(row_canonical_bytes);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; CHAIN_LEN];
    out.copy_from_slice(&bytes);
    out
}

/// Constant-time chain verification — recompute and compare against `expected`.
pub fn verify_chain(
    key: &AuditHmacKey,
    prev_chain: &[u8],
    row_canonical_bytes: &[u8],
    expected: &[u8],
) -> bool {
    let computed = compute_chain(key, prev_chain, row_canonical_bytes);
    if expected.len() != computed.len() {
        // Even though ct_eq exists for slices, length mismatch is structural,
        // not a secret — short-circuit to false.
        let mut tmp = computed;
        tmp.zeroize();
        return false;
    }
    let eq: bool = computed.ct_eq(expected).into();
    let mut tmp = computed;
    tmp.zeroize();
    eq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_from_same_rk_is_deterministic() {
        let rk = RootKey::from_bytes([42u8; 32]);
        let a = AuditHmacKey::derive_from_rk(&rk);
        let b = AuditHmacKey::derive_from_rk(&rk);
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn derive_from_different_rk_is_different() {
        let a = AuditHmacKey::derive_from_rk(&RootKey::from_bytes([1u8; 32]));
        let b = AuditHmacKey::derive_from_rk(&RootKey::from_bytes([2u8; 32]));
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn chain_is_deterministic() {
        let key = AuditHmacKey::from_bytes([7u8; 32]);
        let a = compute_chain(&key, &GENESIS_CHAIN, b"row-1");
        let b = compute_chain(&key, &GENESIS_CHAIN, b"row-1");
        assert_eq!(a, b);
    }

    #[test]
    fn chain_changes_when_row_changes() {
        let key = AuditHmacKey::from_bytes([7u8; 32]);
        let a = compute_chain(&key, &GENESIS_CHAIN, b"row-1");
        let b = compute_chain(&key, &GENESIS_CHAIN, b"row-2");
        assert_ne!(a, b);
    }

    #[test]
    fn chain_changes_when_prev_changes() {
        let key = AuditHmacKey::from_bytes([7u8; 32]);
        let a = compute_chain(&key, &GENESIS_CHAIN, b"row");
        let b = compute_chain(&key, &[0xffu8; 32], b"row");
        assert_ne!(a, b);
    }

    #[test]
    fn chain_changes_when_key_changes() {
        let k1 = AuditHmacKey::from_bytes([1u8; 32]);
        let k2 = AuditHmacKey::from_bytes([2u8; 32]);
        let a = compute_chain(&k1, &GENESIS_CHAIN, b"row");
        let b = compute_chain(&k2, &GENESIS_CHAIN, b"row");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_accepts_valid_chain() {
        let key = AuditHmacKey::from_bytes([3u8; 32]);
        let computed = compute_chain(&key, &GENESIS_CHAIN, b"row");
        assert!(verify_chain(&key, &GENESIS_CHAIN, b"row", &computed));
    }

    #[test]
    fn verify_rejects_tampered_chain() {
        let key = AuditHmacKey::from_bytes([3u8; 32]);
        let mut chain = compute_chain(&key, &GENESIS_CHAIN, b"row");
        chain[0] ^= 1;
        assert!(!verify_chain(&key, &GENESIS_CHAIN, b"row", &chain));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let key = AuditHmacKey::from_bytes([3u8; 32]);
        // 16 bytes — wrong size, can't match a 32-byte expected.
        assert!(!verify_chain(&key, &GENESIS_CHAIN, b"row", &[0u8; 16]));
    }

    #[test]
    fn full_chain_walk_round_trips() {
        // Simulate three rows; recompute each chain and verify all three.
        let key = AuditHmacKey::from_bytes([0x55u8; 32]);
        let r1 = b"row-1";
        let r2 = b"row-2";
        let r3 = b"row-3";

        let c1 = compute_chain(&key, &GENESIS_CHAIN, r1);
        let c2 = compute_chain(&key, &c1, r2);
        let c3 = compute_chain(&key, &c2, r3);

        assert!(verify_chain(&key, &GENESIS_CHAIN, r1, &c1));
        assert!(verify_chain(&key, &c1, r2, &c2));
        assert!(verify_chain(&key, &c2, r3, &c3));
    }

    #[test]
    fn tampering_a_middle_row_breaks_only_from_that_row_forward() {
        let key = AuditHmacKey::from_bytes([0x55u8; 32]);
        let c1 = compute_chain(&key, &GENESIS_CHAIN, b"r1");
        let c2 = compute_chain(&key, &c1, b"r2");
        let _c3 = compute_chain(&key, &c2, b"r3");

        // r1 still verifies (untampered).
        assert!(verify_chain(&key, &GENESIS_CHAIN, b"r1", &c1));
        // r2 row body is changed by attacker — verification of c2 against the
        // new body fails.
        assert!(!verify_chain(&key, &c1, b"r2-tampered", &c2));
    }
}
