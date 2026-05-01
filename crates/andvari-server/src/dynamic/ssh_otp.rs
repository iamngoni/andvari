//! SSH one-time-password engine.
//!
//! Issues a short-lived OTP that an Andvari agent on the target host
//! verifies against the lease record, allowing PAM-driven SSH login. The
//! agent itself is out of scope for this slice; we ship the engine + lease
//! plumbing so operators with the agent installed can use it.
//!
//! Lease shape:
//! - `scope` = the host alias / hostname.
//! - `params.username` = the local Unix account to log in as. Defaults to "andvari".
//!
//! Issued credentials:
//! - `username` = the local account
//! - `host` = the scope
//! - `otp` = 16-character base64url one-time password
//!
//! Revocation: deletes the OTP record from the agent's verification list
//! (no-op here; recorded in the DB and the agent reads it).

use andvari_core::dynamic::{DynamicEngine, DynamicError, IssuedLease, LeaseRequest};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct SshOtpEngine;

impl SshOtpEngine {
    pub fn from_env() -> Option<Self> {
        if std::env::var("ANDVARI_SSH_OTP_ENABLE").is_ok() {
            Some(Self)
        } else {
            None
        }
    }

    fn random_otp() -> String {
        let mut buf = [0u8; 12];
        OsRng.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    }
}

#[async_trait]
impl DynamicEngine for SshOtpEngine {
    fn name(&self) -> &'static str {
        "ssh-otp"
    }

    async fn issue_lease(&self, req: &LeaseRequest) -> Result<IssuedLease, DynamicError> {
        if req.scope.is_empty() {
            return Err(DynamicError::InvalidScope(
                "ssh-otp: scope must be the target host".into(),
            ));
        }
        if req.ttl_seconds <= 0 {
            return Err(DynamicError::InvalidScope("ttl_seconds must be > 0".into()));
        }
        let lease_id = Uuid::new_v4();
        let username = req
            .params
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("andvari")
            .to_string();
        let otp = Self::random_otp();
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(req.ttl_seconds);

        Ok(IssuedLease {
            lease_id,
            engine: self.name().to_string(),
            credentials: serde_json::json!({
                "username": username,
                "host": req.scope,
                "otp": otp,
                "agent_required": true,
            }),
            expires_at,
        })
    }

    async fn revoke_lease(&self, _lease_id: Uuid, _scope: &str) -> Result<(), DynamicError> {
        // The agent polls the lease DB for valid OTPs; flipping the lease's
        // `revoked_at` (which the API layer does for us) is the revocation.
        Ok(())
    }
}
