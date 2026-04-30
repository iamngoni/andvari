use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("vault is sealed")]
    Sealed,

    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("config: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
