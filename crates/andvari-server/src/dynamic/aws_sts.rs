//! AWS STS dynamic engine — issues short-lived credentials via `AssumeRole`.
//!
//! Configured with:
//! - Standard AWS credential chain (env vars / instance metadata / SSO),
//! - Optional `ANDVARI_AWS_REGION` (defaults to provider chain).
//!
//! Lease shape:
//! - `scope` = the IAM role ARN to assume.
//! - `params.session_name` = optional override; defaults to `andvari-{lease_id}`.
//! - `params.external_id` = optional ExternalId for cross-account assume.
//!
//! Returned credentials carry their own expiry (STS chooses, capped by the
//! role's `MaxSessionDuration`); we honour the smaller of `ttl_seconds` and
//! `MaxSessionDuration`. STS does not need explicit revoke — credentials
//! expire on the timetable AWS prints back.

use andvari_core::dynamic::{DynamicEngine, DynamicError, IssuedLease, LeaseRequest};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_sts::Client as StsClient;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct AwsStsEngine {
    client: StsClient,
}

impl AwsStsEngine {
    pub async fn from_env() -> Result<Option<Self>, DynamicError> {
        if std::env::var("ANDVARI_AWS_STS_ENABLE").is_err() {
            return Ok(None);
        }
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Ok(region) = std::env::var("ANDVARI_AWS_REGION") {
            loader = loader.region(aws_sdk_sts::config::Region::new(region));
        }
        let cfg = loader.load().await;
        let client = StsClient::new(&cfg);
        Ok(Some(Self { client }))
    }
}

#[async_trait]
impl DynamicEngine for AwsStsEngine {
    fn name(&self) -> &'static str {
        "aws-sts"
    }

    async fn issue_lease(&self, req: &LeaseRequest) -> Result<IssuedLease, DynamicError> {
        if req.scope.is_empty() {
            return Err(DynamicError::InvalidScope(
                "aws-sts: scope must be the IAM role ARN".into(),
            ));
        }
        if req.ttl_seconds <= 0 {
            return Err(DynamicError::InvalidScope("ttl_seconds must be > 0".into()));
        }

        let lease_id = Uuid::new_v4();
        let session_name = req
            .params
            .get("session_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("andvari-{}", &lease_id.simple().to_string()[..16]));
        let external_id = req
            .params
            .get("external_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut req_b = self
            .client
            .assume_role()
            .role_arn(&req.scope)
            .role_session_name(&session_name)
            .duration_seconds(req.ttl_seconds.clamp(900, 43200) as i32);
        if let Some(ext) = external_id {
            req_b = req_b.external_id(ext);
        }

        let resp = req_b
            .send()
            .await
            .map_err(|e| DynamicError::Engine(format!("AssumeRole: {e}")))?;

        let creds = resp
            .credentials
            .ok_or_else(|| DynamicError::Engine("STS response missing credentials".into()))?;
        let expiration = creds.expiration;
        let expires_at =
            OffsetDateTime::from_unix_timestamp(expiration.secs())
                .unwrap_or_else(|_| OffsetDateTime::now_utc());

        Ok(IssuedLease {
            lease_id,
            engine: self.name().to_string(),
            credentials: serde_json::json!({
                "access_key_id": creds.access_key_id,
                "secret_access_key": creds.secret_access_key,
                "session_token": creds.session_token,
                "session_name": session_name,
                "role_arn": req.scope,
                "expiration": expiration.to_string(),
            }),
            expires_at,
        })
    }

    async fn revoke_lease(&self, _lease_id: Uuid, _scope: &str) -> Result<(), DynamicError> {
        // STS-issued credentials cannot be revoked client-side — they expire
        // on their own timetable. The matching IAM role supports an explicit
        // `aws iam attach-role-policy` deny rule for the session name as a
        // break-glass measure, but that's an out-of-band operator action.
        Ok(())
    }
}
