//! KMS provider implementations: HashiCorp Vault Transit + AWS KMS.
//!
//! GCP KMS is not yet wired up in this crate; users on GCP can either
//! stand up a Vault Transit instance or implement a [`KmsBackend`] in
//! out-of-tree code.

pub mod aws_kms;
pub mod vault_transit;

pub use aws_kms::AwsKms;
pub use vault_transit::VaultTransit;
