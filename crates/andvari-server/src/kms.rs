//! KMS provider implementations.
//!
//! Currently: HashiCorp Vault Transit. AWS KMS and GCP KMS land in follow-up
//! slices.

pub mod vault_transit;

pub use vault_transit::VaultTransit;
