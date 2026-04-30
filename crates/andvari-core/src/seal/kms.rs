//! KMS-backed seal mode.
//!
//! At init time the operator generates a fresh Root Key and encrypts it
//! ("wraps it") under a key held by an external KMS — HashiCorp Vault's
//! Transit engine, AWS KMS, GCP KMS, etc. The resulting ciphertext
//! ("wrapped RK") is persisted alongside the deployment; an attacker who
//! steals only the persisted blob has nothing actionable without KMS access.
//!
//! At boot time the server hands the wrapped blob back to the KMS, which
//! returns the plaintext Root Key. Andvari constructs a [`RootKey`] from
//! those bytes and transitions to [`crate::seal::VaultState::Unsealed`].
//!
//! This module hosts only the **trait** — concrete implementations live in
//! `andvari-server::kms` so that crates which don't talk HTTP (the SDK,
//! the CLI when it's not orchestrating init) don't pull in `reqwest` or
//! cloud SDKs.

use thiserror::Error;
use zeroize::Zeroize;

use crate::crypto::{CryptoError, RootKey};

/// 32-byte plaintext payload that KMS providers wrap and unwrap.
pub const RK_PLAINTEXT_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("kms transport: {0}")]
    Transport(String),

    #[error("kms provider returned error: {0}")]
    Provider(String),

    #[error("kms response did not match the expected shape: {0}")]
    Shape(&'static str),

    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("kms returned plaintext of wrong length: got {got}, expected {expected}")]
    BadPlaintextLength { got: usize, expected: usize },

    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
}

/// Provider-agnostic interface for wrapping/unwrapping the Root Key.
///
/// Implementations are expected to be cheap to clone (typically holding only
/// a configured HTTP client + endpoint + auth token + key id), so callers
/// can hand the backend off to async tasks.
#[async_trait::async_trait]
pub trait KmsBackend: Send + Sync {
    /// Wrap a 32-byte Root Key. The returned blob is opaque and persisted
    /// verbatim; provider-specific framing (e.g. `"vault:v1:..."`) is
    /// embedded inside the bytes.
    async fn wrap(&self, plaintext: &[u8; RK_PLAINTEXT_LEN]) -> Result<Vec<u8>, KmsError>;

    /// Unwrap a previously-wrapped blob back to the plaintext Root Key.
    /// Errors if the blob does not match a value produced by this backend.
    async fn unwrap(&self, wrapped: &[u8]) -> Result<RootKey, KmsError>;
}

/// Helper used by every backend's `unwrap` impl: convert raw plaintext bytes
/// into a [`RootKey`], zeroizing any intermediate buffer on error.
pub fn root_key_from_plaintext(mut plaintext: Vec<u8>) -> Result<RootKey, KmsError> {
    if plaintext.len() != RK_PLAINTEXT_LEN {
        let got = plaintext.len();
        plaintext.zeroize();
        return Err(KmsError::BadPlaintextLength {
            got,
            expected: RK_PLAINTEXT_LEN,
        });
    }
    let mut bytes = [0u8; RK_PLAINTEXT_LEN];
    bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(RootKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    //! Trait-level tests are kept here. Each concrete provider has its own
    //! tests next to the implementation.

    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// In-memory backend used to prove the trait contract: wrap then unwrap
    /// must round-trip the bytes.
    struct InMemoryKms {
        /// Pretend "encryption key" — XOR for testing only.
        xor_key: [u8; 32],
        /// Track wrap calls so we can assert behaviour.
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait::async_trait]
    impl KmsBackend for InMemoryKms {
        async fn wrap(&self, plaintext: &[u8; RK_PLAINTEXT_LEN]) -> Result<Vec<u8>, KmsError> {
            self.calls.lock().await.push("wrap");
            let mut buf = plaintext.to_vec();
            for (b, k) in buf.iter_mut().zip(self.xor_key.iter()) {
                *b ^= k;
            }
            Ok(buf)
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<RootKey, KmsError> {
            self.calls.lock().await.push("unwrap");
            let mut buf = wrapped.to_vec();
            for (b, k) in buf.iter_mut().zip(self.xor_key.iter()) {
                *b ^= k;
            }
            root_key_from_plaintext(buf)
        }
    }

    #[tokio::test]
    async fn trait_round_trips_a_root_key() {
        let kms = InMemoryKms {
            xor_key: [0x5au8; 32],
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let plaintext = [0x77u8; 32];
        let wrapped = kms.wrap(&plaintext).await.unwrap();
        assert_ne!(wrapped, plaintext);
        let _rk = kms.unwrap(&wrapped).await.unwrap();
        let calls = kms.calls.lock().await.clone();
        assert_eq!(calls, vec!["wrap", "unwrap"]);
    }

    #[tokio::test]
    async fn unwrap_rejects_wrong_length() {
        let bytes = vec![1u8; 16]; // not 32
        assert!(matches!(
            root_key_from_plaintext(bytes),
            Err(KmsError::BadPlaintextLength {
                got: 16,
                expected: 32
            })
        ));
    }
}
