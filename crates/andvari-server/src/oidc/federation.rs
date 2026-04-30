//! Workload identity federation for CI systems.
//!
//! `POST /v1/auth/oidc/exchange` accepts a runner-issued OIDC JWT, validates
//! it against the issuer JWKS and a matching `oidc_trust` row, then mints a
//! short-lived Andvari service token.

use actix_web::{HttpResponse, Responder, post, web};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::{Duration, OffsetDateTime};
use tracing::warn;
use uuid::Uuid;

use crate::auth::scope::{Op, Scopes};
use crate::auth::token;
use crate::state::AppState;

const MAX_FEDERATED_TTL_SECONDS: i32 = 900;

#[derive(Deserialize)]
pub struct ExchangeRequest {
    /// Workspace slug whose `oidc_trust` entries should be consulted.
    #[serde(alias = "workspace_slug")]
    pub workspace: String,
    /// The CI/IdP-issued OIDC JWT.
    pub token: String,
}

#[derive(Serialize)]
pub struct ExchangeResponse {
    pub token: String,
    pub token_type: &'static str,
    pub expires_at: OffsetDateTime,
    pub expires_in: i32,
}

#[derive(Debug, Deserialize, Clone)]
struct WorkloadClaims {
    iss: String,
    sub: String,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

#[derive(Debug, FromRow)]
struct TrustRow {
    id: Uuid,
    workspace_id: Uuid,
    workspace_slug: String,
    issuer: String,
    audience: String,
    subject_pattern: String,
    role: String,
    ttl_seconds: i32,
}

#[post("/v1/auth/oidc/exchange")]
pub async fn exchange(
    state: web::Data<AppState>,
    body: web::Json<ExchangeRequest>,
) -> impl Responder {
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };

    let header = match decode_header(&body.token) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error":"invalid jwt header"}));
        }
    };
    if !is_asymmetric_alg(header.alg) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":"unsupported jwt signing algorithm"}));
    }

    let unverified = match decode_unverified(&body.token, header.alg) {
        Ok(c) => c,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error":"invalid jwt claims"}));
        }
    };

    let trusts = match load_trusts(pool, &body.workspace, &unverified.iss).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "load oidc trust");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    if trusts.is_empty() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error":"no matching trust"}));
    }

    let jwks = match fetch_jwks(&unverified.iss).await {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, issuer = %unverified.iss, "fetch oidc jwks");
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error":"issuer jwks unavailable"}));
        }
    };
    let Some(jwk) = select_jwk(&jwks, header.kid.as_deref()) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error":"jwt key not found"}));
    };
    let key = match DecodingKey::from_jwk(jwk) {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "decode jwk");
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error":"jwt key unsupported"}));
        }
    };

    let mut matched: Option<(TrustRow, WorkloadClaims)> = None;
    for trust in trusts {
        let claims = match decode_verified(&body.token, &key, header.alg, &trust) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if subject_matches(&trust.subject_pattern, &claims.sub) {
            matched = Some((trust, claims));
            break;
        }
    }

    let Some((trust, claims)) = matched else {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error":"token did not satisfy oidc trust"}));
    };

    let ttl = trust.ttl_seconds.clamp(1, MAX_FEDERATED_TTL_SECONDS);
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(ttl as i64);
    let scopes = scopes_for_role(&trust.role);
    let name = format!("oidc-fed:{}:{}", trust.issuer, claims.sub);

    let created = match token::create(
        pool,
        trust.workspace_id,
        &trust.workspace_slug,
        &name,
        &scopes,
        Some(expires_at),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, trust_id = %trust.id, "mint federated token");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"token mint failed"}));
        }
    };

    HttpResponse::Ok().json(ExchangeResponse {
        token: created.raw,
        token_type: "Bearer",
        expires_at,
        expires_in: ttl,
    })
}

fn decode_unverified(
    token: &str,
    alg: Algorithm,
) -> Result<WorkloadClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(alg);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    decode::<WorkloadClaims>(token, &DecodingKey::from_secret(&[]), &validation)
        .map(|data| data.claims)
}

fn decode_verified(
    token: &str,
    key: &DecodingKey,
    alg: Algorithm,
    trust: &TrustRow,
) -> Result<WorkloadClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[trust.issuer.as_str()]);
    validation.set_audience(&[trust.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    decode::<WorkloadClaims>(token, key, &validation).map(|data| data.claims)
}

async fn load_trusts(
    pool: &sqlx::PgPool,
    workspace_slug: &str,
    issuer: &str,
) -> Result<Vec<TrustRow>, sqlx::Error> {
    sqlx::query_as::<_, TrustRow>(
        r#"
        SELECT
            t.id,
            t.workspace_id,
            w.slug AS workspace_slug,
            t.issuer,
            t.audience,
            t.subject_pattern,
            t.role,
            t.ttl_seconds
        FROM oidc_trust t
        JOIN workspaces w ON t.workspace_id = w.id
        WHERE w.slug = $1 AND t.issuer = $2
        ORDER BY t.id DESC
        "#,
    )
    .bind(workspace_slug)
    .bind(issuer)
    .fetch_all(pool)
    .await
}

async fn fetch_jwks(issuer: &str) -> Result<JwkSet, String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let discovery: DiscoveryDocument = reqwest::get(&discovery_url)
        .await
        .map_err(|e| format!("fetch discovery: {e}"))?
        .error_for_status()
        .map_err(|e| format!("discovery status: {e}"))?
        .json()
        .await
        .map_err(|e| format!("parse discovery: {e}"))?;

    reqwest::get(&discovery.jwks_uri)
        .await
        .map_err(|e| format!("fetch jwks: {e}"))?
        .error_for_status()
        .map_err(|e| format!("jwks status: {e}"))?
        .json()
        .await
        .map_err(|e| format!("parse jwks: {e}"))
}

fn select_jwk<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Option<&'a Jwk> {
    match kid {
        Some(kid) => jwks.find(kid),
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }
}

fn is_asymmetric_alg(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

fn scopes_for_role(role: &str) -> Scopes {
    let ops = match role {
        "owner" | "admin" => vec![Op::Read, Op::Write, Op::Lease],
        "writer" => vec![Op::Read, Op::Write],
        "reader" | "auditor" => vec![Op::Read],
        _ => vec![Op::Read],
    };
    Scopes {
        projects: vec!["*".to_string()],
        envs: vec!["*".to_string()],
        ops,
    }
}

fn subject_matches(pattern: &str, subject: &str) -> bool {
    wildcard_matches(pattern.as_bytes(), subject.as_bytes())
}

fn wildcard_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut match_after_star = 0usize;

    while t < text.len() {
        if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            match_after_star = t;
            p += 1;
        } else if let Some(star_idx) = star {
            p = star_idx + 1;
            match_after_star += 1;
            t = match_after_star;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::{scopes_for_role, subject_matches};
    use crate::auth::scope::Op;

    #[test]
    fn subject_globs_match_github_refs() {
        assert!(subject_matches(
            "repo:iamngoni/spirit-finder:ref:refs/heads/*",
            "repo:iamngoni/spirit-finder:ref:refs/heads/main"
        ));
        assert!(!subject_matches(
            "repo:iamngoni/spirit-finder:ref:refs/heads/main",
            "repo:iamngoni/spirit-finder:pull_request"
        ));
    }

    #[test]
    fn role_maps_to_expected_ops() {
        let writer = scopes_for_role("writer");
        assert!(writer.ops.contains(&Op::Read));
        assert!(writer.ops.contains(&Op::Write));
        assert!(!writer.ops.contains(&Op::Lease));

        let admin = scopes_for_role("admin");
        assert!(admin.ops.contains(&Op::Lease));
    }
}
