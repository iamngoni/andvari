//! On-disk envelope format for an encrypted secret version.
//!
//! Layout (all big-endian, no length prefix needed since DEK length is fixed):
//!
//! ```text
//! 0       1                       25                                   73   97   97+N+16
//! +-------+-----------------------+------------------------------------+----+--------+
//! | ver=1 | kek_nonce (24 bytes)  | wrapped_dek (32B DEK + 16B tag)    |dek_| ct + 16|
//! |       |                       |                                    |non | tag    |
//! +-------+-----------------------+------------------------------------+----+--------+
//! ```
//!
//! The `aad` passed to [`SecretEnvelope::seal`] / [`SecretEnvelope::open`] is
//! bound into the ciphertext authentication tag (and only the ciphertext —
//! the wrapped DEK uses no AAD because the per-workspace KEK is itself the
//! workspace binding).
//!
//! Every encryption uses fresh OS-RNG random nonces and a fresh DEK.

use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::aead::{CryptoError, KEY_LEN, NONCE_LEN, TAG_LEN, xchacha_open, xchacha_seal};
use super::keys::WorkspaceKek;

/// Current envelope format version. Bump if the on-disk layout or primitives change.
pub const ENVELOPE_VERSION: u8 = 1;

/// Length of the wrapped DEK on the wire (32-byte DEK + 16-byte AEAD tag).
const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;

/// Minimum envelope size: header (1 + 24 + 48 + 24 = 97 bytes) plus the AEAD
/// tag on the (possibly empty) ciphertext.
const HEADER_LEN: usize = 1 + NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN;
const MIN_ENVELOPE_LEN: usize = HEADER_LEN + TAG_LEN;

/// A sealed secret version, ready to be persisted to `secret_versions.ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEnvelope {
    pub version: u8,
    pub kek_nonce: [u8; NONCE_LEN],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub dek_nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl SecretEnvelope {
    /// Encrypt `plaintext` under a fresh per-version DEK that is itself wrapped
    /// under `kek`. `aad` is bound to the ciphertext (not the DEK wrap) and
    /// must be supplied verbatim to [`Self::open`].
    ///
    /// Callers should construct `aad` from stable, non-secret context — typically
    /// canonical bytes of `(workspace_id, project_id, environment_id, secret_id, version_id)`
    /// — so an attacker cannot move ciphertext between rows.
    pub fn seal(plaintext: &[u8], kek: &WorkspaceKek, aad: &[u8]) -> Result<Self, CryptoError> {
        // 1. Generate a fresh DEK for this version.
        let mut dek = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut dek);

        // 2. Wrap the DEK under the KEK.
        let mut kek_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut kek_nonce);
        let wrapped_dek_vec = xchacha_seal(kek.as_bytes(), &kek_nonce, &dek, &[])?;
        debug_assert_eq!(wrapped_dek_vec.len(), WRAPPED_DEK_LEN);
        let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
        wrapped_dek.copy_from_slice(&wrapped_dek_vec);

        // 3. Encrypt the plaintext under the DEK.
        let mut dek_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut dek_nonce);
        let ciphertext = xchacha_seal(&dek, &dek_nonce, plaintext, aad)?;

        // 4. Zeroize the DEK now that the wrapped form is captured.
        dek.zeroize();

        Ok(Self {
            version: ENVELOPE_VERSION,
            kek_nonce,
            wrapped_dek,
            dek_nonce,
            ciphertext,
        })
    }

    /// Decrypt and return the plaintext. AAD must equal what was passed at seal time.
    pub fn open(&self, kek: &WorkspaceKek, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.version != ENVELOPE_VERSION {
            return Err(CryptoError::InvalidEnvelope("unsupported version"));
        }

        // 1. Unwrap the DEK.
        let mut dek_vec = xchacha_open(kek.as_bytes(), &self.kek_nonce, &self.wrapped_dek, &[])?;
        if dek_vec.len() != KEY_LEN {
            dek_vec.zeroize();
            return Err(CryptoError::InvalidEnvelope("wrapped DEK has wrong length"));
        }
        let mut dek = [0u8; KEY_LEN];
        dek.copy_from_slice(&dek_vec);
        dek_vec.zeroize();

        // 2. Decrypt the ciphertext.
        let plaintext = xchacha_open(&dek, &self.dek_nonce, &self.ciphertext, aad);

        // 3. Zeroize the DEK regardless of decrypt outcome.
        dek.zeroize();

        plaintext
    }

    /// Serialize to the on-disk byte format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(&self.kek_nonce);
        out.extend_from_slice(&self.wrapped_dek);
        out.extend_from_slice(&self.dek_nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse from the on-disk byte format. Does not decrypt.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < MIN_ENVELOPE_LEN {
            return Err(CryptoError::InvalidEnvelope("envelope too short"));
        }
        let version = data[0];
        if version != ENVELOPE_VERSION {
            return Err(CryptoError::InvalidEnvelope("unsupported version"));
        }

        let mut cursor = 1;
        let mut kek_nonce = [0u8; NONCE_LEN];
        kek_nonce.copy_from_slice(&data[cursor..cursor + NONCE_LEN]);
        cursor += NONCE_LEN;

        let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
        wrapped_dek.copy_from_slice(&data[cursor..cursor + WRAPPED_DEK_LEN]);
        cursor += WRAPPED_DEK_LEN;

        let mut dek_nonce = [0u8; NONCE_LEN];
        dek_nonce.copy_from_slice(&data[cursor..cursor + NONCE_LEN]);
        cursor += NONCE_LEN;

        let ciphertext = data[cursor..].to_vec();

        Ok(Self {
            version,
            kek_nonce,
            wrapped_dek,
            dek_nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::RootKey;

    fn fresh_kek() -> WorkspaceKek {
        let rk = RootKey::generate();
        let kek = WorkspaceKek::generate();
        // Sanity: round-trip through wrap/unwrap so we know the KEK works under
        // a real RK before we use it for envelope tests.
        let wrapped = kek.wrap(&rk, b"ws").unwrap();
        WorkspaceKek::unwrap(&rk, &wrapped, b"ws").unwrap()
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let kek = fresh_kek();
        let env = SecretEnvelope::seal(b"", &kek, b"aad").unwrap();
        assert_eq!(env.open(&kek, b"aad").unwrap(), b"");
    }

    #[test]
    fn round_trip_ascii() {
        let kek = fresh_kek();
        let plaintext = b"sk_live_abcdef123456".as_slice();
        let env = SecretEnvelope::seal(plaintext, &kek, b"secret-id-7").unwrap();
        assert_eq!(env.open(&kek, b"secret-id-7").unwrap(), plaintext);
    }

    #[test]
    fn round_trip_large_binary() {
        let kek = fresh_kek();
        let plaintext: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let env = SecretEnvelope::seal(&plaintext, &kek, b"").unwrap();
        assert_eq!(env.open(&kek, b"").unwrap(), plaintext);
    }

    #[test]
    fn each_seal_uses_fresh_nonces_and_dek() {
        let kek = fresh_kek();
        let pt = b"identical plaintext";
        let a = SecretEnvelope::seal(pt, &kek, b"aad").unwrap();
        let b = SecretEnvelope::seal(pt, &kek, b"aad").unwrap();
        assert_ne!(a.kek_nonce, b.kek_nonce);
        assert_ne!(a.dek_nonce, b.dek_nonce);
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
        assert_ne!(a.ciphertext, b.ciphertext);
        // But both must still decrypt back to the same plaintext.
        assert_eq!(a.open(&kek, b"aad").unwrap(), pt);
        assert_eq!(b.open(&kek, b"aad").unwrap(), pt);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek = fresh_kek();
        let other = fresh_kek();
        let env = SecretEnvelope::seal(b"x", &kek, b"").unwrap();
        assert!(matches!(
            env.open(&other, b""),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let kek = fresh_kek();
        let env = SecretEnvelope::seal(b"x", &kek, b"aad-1").unwrap();
        assert!(matches!(
            env.open(&kek, b"aad-2"),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn tamper_kek_nonce_fails() {
        let kek = fresh_kek();
        let mut env = SecretEnvelope::seal(b"hello", &kek, b"").unwrap();
        env.kek_nonce[0] ^= 1;
        assert!(env.open(&kek, b"").is_err());
    }

    #[test]
    fn tamper_wrapped_dek_fails() {
        let kek = fresh_kek();
        let mut env = SecretEnvelope::seal(b"hello", &kek, b"").unwrap();
        env.wrapped_dek[0] ^= 1;
        assert!(env.open(&kek, b"").is_err());
    }

    #[test]
    fn tamper_dek_nonce_fails() {
        let kek = fresh_kek();
        let mut env = SecretEnvelope::seal(b"hello", &kek, b"").unwrap();
        env.dek_nonce[0] ^= 1;
        assert!(env.open(&kek, b"").is_err());
    }

    #[test]
    fn tamper_ciphertext_fails() {
        let kek = fresh_kek();
        let mut env = SecretEnvelope::seal(b"hello", &kek, b"").unwrap();
        env.ciphertext[0] ^= 1;
        assert!(env.open(&kek, b"").is_err());
    }

    #[test]
    fn wire_format_round_trip() {
        let kek = fresh_kek();
        let env = SecretEnvelope::seal(b"sk_live_xyz", &kek, b"aad").unwrap();
        let bytes = env.to_bytes();
        let back = SecretEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, back);
        assert_eq!(back.open(&kek, b"aad").unwrap(), b"sk_live_xyz");
    }

    #[test]
    fn wire_format_layout_is_stable() {
        // 1 (version) + 24 (kek_nonce) + 48 (wrapped_dek) + 24 (dek_nonce) + N + 16 (tag)
        let kek = fresh_kek();
        let env = SecretEnvelope::seal(b"abcde", &kek, b"").unwrap();
        let bytes = env.to_bytes();
        assert_eq!(bytes[0], ENVELOPE_VERSION);
        assert_eq!(bytes.len(), 1 + 24 + 48 + 24 + 5 + 16);
    }

    #[test]
    fn truncated_envelope_rejected() {
        let kek = fresh_kek();
        let env = SecretEnvelope::seal(b"x", &kek, b"").unwrap();
        let bytes = env.to_bytes();

        // Lop off everything after the header — any chunk shorter than
        // HEADER_LEN + TAG_LEN is structurally invalid.
        let truncated = &bytes[..bytes.len() - 20];
        assert!(matches!(
            SecretEnvelope::from_bytes(truncated),
            Err(CryptoError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn unknown_version_rejected() {
        let kek = fresh_kek();
        let env = SecretEnvelope::seal(b"x", &kek, b"").unwrap();
        let mut bytes = env.to_bytes();
        bytes[0] = 0xff;
        assert!(matches!(
            SecretEnvelope::from_bytes(&bytes),
            Err(CryptoError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn open_rejects_unknown_version_in_struct() {
        let kek = fresh_kek();
        let mut env = SecretEnvelope::seal(b"x", &kek, b"").unwrap();
        env.version = 0xff;
        assert!(matches!(
            env.open(&kek, b""),
            Err(CryptoError::InvalidEnvelope(_))
        ));
    }
}
