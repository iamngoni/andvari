//! Key types for Andvari's three-layer envelope.
//!
//! All key structs zeroize their backing memory on drop. None of them are
//! `Clone` — sharing a key requires deliberate `Arc` wrapping, which keeps the
//! number of in-memory copies auditable.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::aead::{CryptoError, KEY_LEN, NONCE_LEN, xchacha_open, xchacha_seal};

/// 32-byte symmetric Root Key. Lives only in memory after the vault is
/// unsealed; never written to disk.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; KEY_LEN]);

impl RootKey {
    /// Construct from raw 32 bytes (testing, programmatic init, KMS unwrap path).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh root key via the OS CSPRNG. Used at vault initialization.
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// Load a root key from a base64-encoded environment variable.
    ///
    /// The standard base64 alphabet is used. The decoded payload must be
    /// exactly 32 bytes; anything else is a config error.
    pub fn from_base64_env(var_name: &str) -> Result<Self, CryptoError> {
        let raw = std::env::var(var_name)
            .map_err(|_| CryptoError::MissingEnv(var_name.to_string()))?;
        Self::from_base64(&raw)
    }

    /// Decode a base64 string into a root key.
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        let mut bytes = STANDARD.decode(s.trim())?;
        if bytes.len() != KEY_LEN {
            // zeroize the wrong-length buffer before bailing.
            bytes.zeroize();
            return Err(CryptoError::InvalidRootKey(
                "root key must be exactly 32 bytes",
            ));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(arr))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Per-workspace Key Encryption Key. Stored in Postgres wrapped under [`RootKey`];
/// loaded into memory only while the workspace is in active use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WorkspaceKek([u8; KEY_LEN]);

impl WorkspaceKek {
    /// Generate a fresh workspace KEK via the OS CSPRNG.
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// Construct from raw bytes (used after unwrap).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Wrap this KEK under the given root key, producing the storable
    /// ciphertext + nonce that can be persisted in the `workspaces.kek_wrapped`
    /// column.
    ///
    /// `aad` should be a stable, non-secret context binding (typically
    /// canonical bytes of the workspace ID) so that wrapped KEKs cannot be
    /// transplanted between workspaces.
    pub fn wrap(&self, rk: &RootKey, aad: &[u8]) -> Result<WrappedKek, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = xchacha_seal(rk.as_bytes(), &nonce, &self.0, aad)?;
        Ok(WrappedKek { nonce, ciphertext })
    }

    /// Unwrap a stored wrapped KEK using the root key.
    pub fn unwrap(
        rk: &RootKey,
        wrapped: &WrappedKek,
        aad: &[u8],
    ) -> Result<Self, CryptoError> {
        let mut plaintext = xchacha_open(rk.as_bytes(), &wrapped.nonce, &wrapped.ciphertext, aad)?;
        if plaintext.len() != KEY_LEN {
            plaintext.zeroize();
            return Err(CryptoError::InvalidKeyLength {
                got: plaintext.len(),
                expected: KEY_LEN,
            });
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// A workspace KEK wrapped under the root key. Persisted in
/// `workspaces.kek_wrapped` (ciphertext) and `workspaces.kek_nonce` (nonce).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedKek {
    /// 24-byte nonce used to encrypt the KEK.
    #[serde(with = "serde_nonce")]
    pub nonce: [u8; NONCE_LEN],

    /// AEAD ciphertext: 32-byte KEK + 16-byte Poly1305 tag = 48 bytes.
    pub ciphertext: Vec<u8>,
}

mod serde_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::NONCE_LEN;

    pub fn serialize<S: Serializer>(n: &[u8; NONCE_LEN], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(n)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; NONCE_LEN], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("nonce must be 24 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_key_from_base64_round_trip() {
        let bytes = [42u8; KEY_LEN];
        let b64 = STANDARD.encode(bytes);
        let rk = RootKey::from_base64(&b64).unwrap();
        assert_eq!(rk.as_bytes(), &bytes);
    }

    #[test]
    fn root_key_wrong_length_rejected() {
        let too_short = STANDARD.encode([0u8; 16]);
        assert!(matches!(
            RootKey::from_base64(&too_short),
            Err(CryptoError::InvalidRootKey(_))
        ));
        let too_long = STANDARD.encode([0u8; 64]);
        assert!(matches!(
            RootKey::from_base64(&too_long),
            Err(CryptoError::InvalidRootKey(_))
        ));
    }

    #[test]
    fn root_key_invalid_base64_rejected() {
        assert!(matches!(
            RootKey::from_base64("not!valid!base64!"),
            Err(CryptoError::Base64(_))
        ));
    }

    #[test]
    fn kek_wrap_round_trip() {
        let rk = RootKey::generate();
        let kek = WorkspaceKek::generate();
        let wrapped = kek.wrap(&rk, b"ws:abc").unwrap();
        let unwrapped = WorkspaceKek::unwrap(&rk, &wrapped, b"ws:abc").unwrap();
        assert_eq!(kek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn kek_unwrap_with_wrong_rk_fails() {
        let rk = RootKey::generate();
        let kek = WorkspaceKek::generate();
        let wrapped = kek.wrap(&rk, b"ws:abc").unwrap();

        let other_rk = RootKey::generate();
        assert!(matches!(
            WorkspaceKek::unwrap(&other_rk, &wrapped, b"ws:abc"),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn kek_unwrap_with_wrong_aad_fails() {
        let rk = RootKey::generate();
        let kek = WorkspaceKek::generate();
        let wrapped = kek.wrap(&rk, b"ws:abc").unwrap();

        assert!(matches!(
            WorkspaceKek::unwrap(&rk, &wrapped, b"ws:xyz"),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn kek_wrap_uses_fresh_nonce_each_call() {
        // Two wraps of the same KEK with the same RK + AAD must produce
        // distinct nonces (and therefore distinct ciphertexts), or our nonce
        // generation is broken.
        let rk = RootKey::generate();
        let kek = WorkspaceKek::from_bytes([7u8; KEY_LEN]);
        let a = kek.wrap(&rk, b"ws").unwrap();
        let b = kek.wrap(&rk, b"ws").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn from_env_round_trip() {
        // Use a process-wide unique env var name so concurrent tests don't collide.
        let var = "ANDVARI_TEST_RK_FROM_ENV";
        let bytes = [9u8; KEY_LEN];
        // SAFETY: tests in this module run in-process; we set then read once.
        unsafe { std::env::set_var(var, STANDARD.encode(bytes)) };
        let rk = RootKey::from_base64_env(var).unwrap();
        assert_eq!(rk.as_bytes(), &bytes);
        unsafe { std::env::remove_var(var) };
    }
}
