//! Core types, errors, and crypto primitives shared across Andvari crates.

pub mod crypto;
pub mod error;
pub mod seal;

pub use error::{Error, Result};
pub use seal::VaultState;
