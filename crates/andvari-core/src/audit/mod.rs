//! Append-only, tamper-evident audit log primitives.
//!
//! Each row is chained to its predecessor via
//! `hmac_chain = HMAC-SHA256(prev_chain || canonical_bytes_of_this_row)`,
//! keyed by [`AuditHmacKey`] which is HKDF-derived from the [`RootKey`].
//!
//! - The very first row uses 32 zero bytes as `prev_chain`.
//! - Tampering with any historical row breaks the chain at that row and
//!   forwards. A verifier walks the table, recomputes each chain, and
//!   reports the first divergence.
//!
//! This module owns only the *primitives* (key derivation + chain math + a
//! deterministic row encoder). Persistence lives in `andvari-server::audit`
//! because it talks to Postgres.

pub mod chain;
pub mod row;

pub use chain::{AUDIT_HMAC_INFO, AuditHmacKey, GENESIS_CHAIN, compute_chain, verify_chain};
pub use row::{ActorKind, AuditRow};
