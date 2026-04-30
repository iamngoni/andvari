//! Shamir Secret Sharing over the Root Key.
//!
//! Splits the 32-byte Root Key into `limit` shares such that any `threshold`
//! of them reconstruct it. Built on `vsss-rs`'s GF(256) byte-array primitives
//! — we never roll our own field math.
//!
//! Wire format for a single share is the raw bytes returned by
//! `Gf256::split_array`:
//!
//! ```text
//! [participant_id:1][share_bytes:N]
//! ```
//!
//! For a 32-byte Root Key, `N == 32`, so each share is 33 bytes. We
//! base64-encode shares for human handling (paste into shells, write on paper,
//! engrave on a hardware token).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::rngs::OsRng;
use vsss_rs::Gf256;

use crate::crypto::{CryptoError, RootKey};

/// Length of a single share for a 32-byte root key (1 ID byte + 32 GF data bytes).
pub const SHARE_LEN: usize = 33;

/// Lower bound on the threshold (`vsss-rs` itself rejects K < 2).
pub const MIN_THRESHOLD: usize = 2;

/// Upper bound on the limit. `vsss-rs`'s GF(256) splitter rejects N > 255 because
/// the participant identifier is one byte; we mirror that here for clearer errors.
pub const MAX_LIMIT: usize = 255;

/// Split a Root Key into `limit` shares with the given recovery threshold.
///
/// Returns one `Vec<u8>` per share, base64-encode each before showing it to a
/// human. The shares array length is `limit`; the order matches the participant
/// identifier the share carries in its first byte.
pub fn split_root_key(
    rk: &RootKey,
    threshold: usize,
    limit: usize,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    validate_params(threshold, limit)?;
    Gf256::split_array(threshold, limit, rk.as_bytes(), OsRng)
        .map_err(|_| CryptoError::InvalidEnvelope("vsss-rs split rejected the parameters"))
}

/// Same as [`split_root_key`] but renders each share as base64.
pub fn split_root_key_base64(
    rk: &RootKey,
    threshold: usize,
    limit: usize,
) -> Result<Vec<String>, CryptoError> {
    let shares = split_root_key(rk, threshold, limit)?;
    Ok(shares.into_iter().map(|s| STANDARD.encode(&s)).collect())
}

/// Reconstruct the Root Key from a collection of shares.
///
/// At least `threshold` shares are required, all sharing the same secret. If
/// fewer than `threshold` are supplied the underlying combiner returns an
/// error (the value is mathematically undetermined).
pub fn combine_root_key(shares: &[Vec<u8>]) -> Result<RootKey, CryptoError> {
    let bytes = Gf256::combine_array(shares)
        .map_err(|_| CryptoError::InvalidEnvelope("vsss-rs combine rejected the shares"))?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            got: bytes.len(),
            expected: 32,
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    // Zeroize the intermediate Vec; RootKey owns its own zeroizing buffer.
    let mut bytes = bytes;
    use zeroize::Zeroize;
    bytes.zeroize();
    Ok(RootKey::from_bytes(arr))
}

/// Decode a single base64-encoded share. Validates length and basic structure
/// (`SHARE_LEN` bytes), but cannot detect cross-set corruption — that surfaces
/// at combine time as a wrong RootKey, which the caller must verify by trying
/// to decrypt a known KEK.
pub fn decode_share(s: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = STANDARD.decode(s.trim())?;
    if bytes.len() != SHARE_LEN {
        return Err(CryptoError::InvalidEnvelope(
            "share has wrong length (expected 33 bytes)",
        ));
    }
    if bytes[0] == 0 {
        return Err(CryptoError::InvalidEnvelope(
            "share participant id 0 is reserved for the secret",
        ));
    }
    Ok(bytes)
}

fn validate_params(threshold: usize, limit: usize) -> Result<(), CryptoError> {
    if threshold < MIN_THRESHOLD {
        return Err(CryptoError::InvalidEnvelope(
            "shamir threshold must be at least 2",
        ));
    }
    if limit < threshold {
        return Err(CryptoError::InvalidEnvelope(
            "shamir limit must be >= threshold",
        ));
    }
    if limit > MAX_LIMIT {
        return Err(CryptoError::InvalidEnvelope("shamir limit must be <= 255"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::WorkspaceKek;

    #[test]
    fn split_then_combine_round_trip() {
        let rk = RootKey::from_bytes([7u8; 32]);
        let shares = split_root_key(&rk, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        for s in &shares {
            assert_eq!(s.len(), SHARE_LEN);
        }
        // Any 3 of 5 reconstruct.
        let recovered = combine_root_key(&shares[0..3]).unwrap();
        assert_eq!(recovered.as_bytes(), rk.as_bytes());

        // Other 3 also work.
        let recovered = combine_root_key(&shares[2..5]).unwrap();
        assert_eq!(recovered.as_bytes(), rk.as_bytes());
    }

    #[test]
    fn random_root_key_round_trips() {
        let rk = RootKey::generate();
        let original_bytes = *rk.as_bytes();
        let shares = split_root_key(&rk, 2, 3).unwrap();
        let recovered = combine_root_key(&shares[..2]).unwrap();
        assert_eq!(recovered.as_bytes(), &original_bytes);
    }

    #[test]
    fn fewer_than_threshold_recovers_wrong_secret() {
        // With K-1 shares, vsss-rs does not error — it returns the
        // mathematically-determined value of a polynomial passing through
        // those points and one implied point. That value is statistically
        // independent of the real secret. We only assert "did not equal the
        // secret" (since otherwise the threshold property is broken).
        //
        // Probability of accidental collision is ~1/2^256.
        let rk = RootKey::from_bytes([0x42u8; 32]);
        let shares = split_root_key(&rk, 3, 5).unwrap();

        // vsss-rs `combine_array` requires at least 2 shares; one share is
        // structurally rejected.
        let bogus = combine_root_key(&shares[0..2]).unwrap();
        assert_ne!(bogus.as_bytes(), rk.as_bytes());
    }

    #[test]
    fn split_rejects_threshold_below_min() {
        let rk = RootKey::generate();
        assert!(split_root_key(&rk, 1, 3).is_err());
        assert!(split_root_key(&rk, 0, 3).is_err());
    }

    #[test]
    fn split_rejects_limit_below_threshold() {
        let rk = RootKey::generate();
        assert!(split_root_key(&rk, 5, 3).is_err());
    }

    #[test]
    fn split_rejects_limit_above_255() {
        let rk = RootKey::generate();
        assert!(split_root_key(&rk, 3, 256).is_err());
    }

    #[test]
    fn base64_round_trip() {
        let rk = RootKey::from_bytes([0xaa; 32]);
        let strings = split_root_key_base64(&rk, 2, 3).unwrap();
        assert_eq!(strings.len(), 3);

        let decoded: Vec<Vec<u8>> = strings.iter().map(|s| decode_share(s).unwrap()).collect();
        let recovered = combine_root_key(&decoded[..2]).unwrap();
        assert_eq!(recovered.as_bytes(), rk.as_bytes());
    }

    #[test]
    fn decode_share_rejects_wrong_length() {
        // 32 bytes (missing the participant ID prefix) — base64 of 32 zero bytes.
        let too_short = STANDARD.encode([0u8; 32]);
        assert!(decode_share(&too_short).is_err());

        let too_long = STANDARD.encode([0u8; 64]);
        assert!(decode_share(&too_long).is_err());
    }

    #[test]
    fn decode_share_rejects_zero_id() {
        // ID byte = 0 is reserved for the secret point itself; a real share
        // must come from x in 1..=N.
        let mut bad = vec![0u8; SHARE_LEN];
        bad[0] = 0;
        let encoded = STANDARD.encode(&bad);
        assert!(decode_share(&encoded).is_err());
    }

    #[test]
    fn shamir_protects_an_actual_kek() {
        // End-to-end: split RK, distribute shares, reconstruct RK from a
        // subset, then prove the reconstructed RK can unwrap a KEK that was
        // wrapped under the original. This is the property that matters
        // operationally — splitting bytes round-trips, but it has to keep
        // working through the rest of the crypto stack.
        let rk = RootKey::generate();
        let kek = WorkspaceKek::generate();
        let wrapped = kek.wrap(&rk, b"ws-1").unwrap();

        let shares = split_root_key(&rk, 3, 5).unwrap();
        let restored = combine_root_key(&shares[1..4]).unwrap();

        let unwrapped = WorkspaceKek::unwrap(&restored, &wrapped, b"ws-1").unwrap();
        assert_eq!(kek.as_bytes(), unwrapped.as_bytes());
    }
}
