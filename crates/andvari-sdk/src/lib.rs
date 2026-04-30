//! Andvari Rust SDK — public client + layered configuration resolution.
//!
//! The configuration model is shared between the CLI (`andvari ...`) and any
//! Rust service that uses [`Client`] directly. See [`Config::resolve`] for
//! the precedence order.

pub mod config;

pub use config::{Config, ConfigError, EnvOverride, ResolveOptions};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(#[from] ConfigError),

    #[error("not implemented")]
    NotImplemented,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Public Andvari client. The full version (in-memory cache, background
/// refresh, retries) lands in the SDK slice; this stub exists so the CLI can
/// already depend on a real type.
pub struct Client {
    pub config: Config,
}

impl Client {
    pub fn from_env() -> Result<Self> {
        let config = Config::resolve(ResolveOptions::default())?;
        Ok(Self { config })
    }
}
