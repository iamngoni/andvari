//! XChaCha20-Poly1305 AEAD wrapper.
//!
//! Thin layer over the `chacha20poly1305` crate so callers don't need to
//! think about cipher state, nonce types, or AAD payload structs.

use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use thiserror::Error;

/// 16-byte authentication tag length appended to every AEAD ciphertext.
pub(crate) const TAG_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length (192 bits — random nonces are safe at scale).
pub(crate) const NONCE_LEN: usize = 24;

/// Symmetric key length for every layer of the envelope.
pub(crate) const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD encryption failed")]
    EncryptFailed,

    #[error("AEAD decryption failed (wrong key, wrong AAD, or tampered ciphertext)")]
    DecryptFailed,

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(&'static str),

    #[error("invalid key length: got {got}, expected {expected}")]
    InvalidKeyLength { got: usize, expected: usize },

    #[error("invalid root key: {0}")]
    InvalidRootKey(&'static str),

    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("missing env var: {0}")]
    MissingEnv(String),
}

/// Encrypt `plaintext` with the given 32-byte key and 24-byte nonce, binding `aad`
/// into the authentication tag.
pub(crate) fn xchacha_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)
}

/// Decrypt `ciphertext` (which includes the 16-byte tag at its tail) with the
/// given key, nonce, and AAD. Returns the original plaintext on success.
pub(crate) fn xchacha_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn fixed_nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        for (i, b) in n.iter_mut().enumerate() {
            *b = (0x80 + i) as u8;
        }
        n
    }

    #[test]
    fn round_trip() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let pt = b"hello andvari";
        let ct = xchacha_seal(&key, &nonce, pt, b"aad-1").unwrap();
        assert_ne!(&ct[..pt.len()], pt, "ciphertext must not equal plaintext");
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let recovered = xchacha_open(&key, &nonce, &ct, b"aad-1").unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let ct = xchacha_seal(&key, &nonce, b"x", b"aad-1").unwrap();
        let err = xchacha_open(&key, &nonce, &ct, b"aad-2").unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed));
    }

    #[test]
    fn wrong_key_fails() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let ct = xchacha_seal(&key, &nonce, b"x", b"").unwrap();

        let mut bad = key;
        bad[0] ^= 1;
        let err = xchacha_open(&bad, &nonce, &ct, b"").unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let mut ct = xchacha_seal(&key, &nonce, b"hello", b"").unwrap();
        ct[0] ^= 1;
        let err = xchacha_open(&key, &nonce, &ct, b"").unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_tag_fails() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let mut ct = xchacha_seal(&key, &nonce, b"hello", b"").unwrap();
        let tag_idx = ct.len() - 1;
        ct[tag_idx] ^= 1;
        let err = xchacha_open(&key, &nonce, &ct, b"").unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed));
    }
}
