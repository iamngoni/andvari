//! Andvari Rust SDK — public client.
//!
//! Real client (caching, background refresh, retries) lands with the SDK slice.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not implemented")]
    NotImplemented,
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Client {
    _server: String,
}

impl Client {
    pub fn from_env() -> Result<Self> {
        Err(Error::NotImplemented)
    }
}
