//! Dynamic secrets engine trait — short-lived credentials minted on demand.
//!
//! Concrete implementations live in `andvari-server` because they typically
//! need network/SDK access (Postgres connection, AWS SDK, etc.). This crate
//! only defines the shape they all share.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DynamicError {
    #[error("engine: {0}")]
    Engine(String),

    #[error("not configured: {0}")]
    NotConfigured(&'static str),

    #[error("invalid scope: {0}")]
    InvalidScope(String),
}

/// Inputs to a lease request — what the operator wants the credential to do.
/// The shape is intentionally JSON-flexible so each engine can interpret
/// it however it needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub workspace_id: Uuid,
    pub engine: String,
    /// Human-meaningful identifier for what this lease applies to (a database
    /// name, an IAM role ARN, a hostname). Free-form string the engine parses.
    pub scope: String,
    pub ttl_seconds: i64,
    /// Engine-specific extras (e.g. extra grants, IAM policy ARN, …).
    #[serde(default)]
    pub params: serde_json::Value,
}

/// What the engine returns after minting a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedLease {
    pub lease_id: Uuid,
    pub engine: String,
    pub credentials: serde_json::Value,
    pub expires_at: OffsetDateTime,
}

/// Async trait for dynamic engines.
#[async_trait::async_trait]
pub trait DynamicEngine: Send + Sync {
    /// Engine identifier — `"postgres"`, `"mysql"`, `"aws-sts"`, `"ssh-otp"`.
    fn name(&self) -> &'static str;

    /// Mint a new credential.
    async fn issue_lease(&self, req: &LeaseRequest) -> Result<IssuedLease, DynamicError>;

    /// Tear down a previously-issued credential. Should be idempotent —
    /// "already gone" is success.
    async fn revoke_lease(&self, lease_id: Uuid, scope: &str) -> Result<(), DynamicError>;
}
