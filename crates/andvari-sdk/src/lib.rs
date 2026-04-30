//! Andvari Rust SDK — public client + layered configuration resolution.
//!
//! Use [`Client`] from a Rust service to fetch secrets:
//!
//! ```no_run
//! # async fn run() -> Result<(), andvari_sdk::Error> {
//! let client = andvari_sdk::Client::from_env()?;
//! let db_url = client.get("DATABASE_URL").await?;
//! # Ok(()) }
//! ```
//!
//! The client caches values in memory with a TTL, deduplicates concurrent
//! `get()` calls for the same key, and retries transient HTTP failures.

pub mod client;
pub mod config;

pub use client::{CacheStats, Client, ClientBuilder};
pub use config::{Config, ConfigError, EnvOverride, ResolveOptions};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(#[from] ConfigError),

    #[error("missing setting: {0}")]
    MissingSetting(&'static str),

    #[error("http: {0}")]
    Http(String),

    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },

    #[error("decode: {0}")]
    Decode(String),

    #[error("secret not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;
