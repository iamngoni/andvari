//! Crypto primitives for Andvari.
//!
//! Three-layer envelope encryption:
//!
//! - [`RootKey`] — 32 bytes, lives only in memory after the vault is unsealed.
//!   Loaded from env / Shamir / KMS. Never written to disk in plaintext.
//! - [`WorkspaceKek`] — 32-byte random key per workspace. Stored in Postgres,
//!   wrapped by RK. Loaded into a per-workspace cache during use; evicted and
//!   zeroized otherwise.
//! - Per-secret-version DEK — 32-byte random key per write, generated inside
//!   [`SecretEnvelope::seal`], wrapped by the workspace KEK, and stored
//!   alongside the ciphertext.
//!
//! AEAD primitive: **XChaCha20-Poly1305** (24-byte nonce, 16-byte tag).
//!
//! On-disk envelope format (see [`SecretEnvelope::to_bytes`]):
//!
//! ```text
//! [version:1][kek_nonce:24][wrapped_dek:48][dek_nonce:24][ciphertext+tag:N+16]
//! ```

mod aead;
mod envelope;
mod keys;

pub use aead::CryptoError;
pub use envelope::{ENVELOPE_VERSION, SecretEnvelope};
pub use keys::{RootKey, WorkspaceKek, WrappedKek};
