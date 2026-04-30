//! Service tokens.
//!
//! Wire format: `andv_{workspace_slug}_{32-char base64url}`.
//!
//! - 24 random bytes → 32 chars base64url (no padding)
//! - Argon2id over the raw token, hash stored in `service_tokens.token_hash`
//! - First 8 chars of the random portion are the `token_prefix`, indexed for
//!   O(1) lookup.
//!
//! Verification flow:
//! 1. Parse the token into `(slug, random)`.
//! 2. SELECT rows whose workspace matches and prefix matches.
//! 3. For each match, Argon2id::verify against the stored hash.
//! 4. Reject expired or revoked tokens.
//! 5. Update `last_used_at`.

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng as Argon2Rng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::scope::Scopes;

const TOKEN_RANDOM_BYTES: usize = 24;
const TOKEN_PREFIX_LEN: usize = 8;
const TOKEN_LITERAL_PREFIX: &str = "andv_";

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token format invalid")]
    FormatInvalid,

    #[error("token not found")]
    NotFound,

    #[error("token revoked")]
    Revoked,

    #[error("token expired")]
    Expired,

    #[error("argon2: {0}")]
    Argon2(String),

    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

/// Returned at creation time — the only point at which the raw token is
/// visible. Operators copy it once and store it; the server only keeps the
/// Argon2id hash.
#[derive(Debug, Clone, Serialize)]
pub struct CreatedToken {
    pub id: Uuid,
    pub raw: String,
    pub prefix: String,
}

/// What every authenticated service-token-bearing request carries.
#[derive(Debug, Clone)]
pub struct TokenContext {
    pub token_id: Uuid,
    pub workspace_id: Uuid,
    pub workspace_slug: String,
    pub name: String,
    pub scopes: Scopes,
}

/// Generate, hash, and persist a new token.
pub async fn create(
    pool: &PgPool,
    workspace_id: Uuid,
    workspace_slug: &str,
    name: &str,
    scopes: &Scopes,
    expires_at: Option<OffsetDateTime>,
) -> Result<CreatedToken, TokenError> {
    let mut random = [0u8; TOKEN_RANDOM_BYTES];
    OsRng.fill_bytes(&mut random);
    let random_b64 = URL_SAFE_NO_PAD.encode(random);

    let raw = format!("{TOKEN_LITERAL_PREFIX}{workspace_slug}_{random_b64}");
    let prefix = random_b64.get(..TOKEN_PREFIX_LEN).unwrap_or(&random_b64).to_string();

    let salt = SaltString::generate(&mut Argon2Rng);
    let hash = Argon2::default()
        .hash_password(raw.as_bytes(), &salt)
        .map_err(|e| TokenError::Argon2(e.to_string()))?
        .to_string();

    let scopes_json = serde_json::to_value(scopes)
        .map_err(|e| TokenError::Argon2(format!("scope encode: {e}")))?;

    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO service_tokens
            (workspace_id, name, token_prefix, token_hash, scopes, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(workspace_id)
    .bind(name)
    .bind(&prefix)
    .bind(&hash)
    .bind(&scopes_json)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;

    Ok(CreatedToken { id, raw, prefix })
}

/// Validate a raw token against the database. On success returns the
/// authenticated [`TokenContext`] and updates `last_used_at`.
pub async fn validate(pool: &PgPool, raw: &str) -> Result<TokenContext, TokenError> {
    let (slug, random_part) = parse_format(raw)?;
    let prefix = random_part
        .get(..TOKEN_PREFIX_LEN)
        .ok_or(TokenError::FormatInvalid)?;

    let candidates = sqlx::query_as::<_, StoredToken>(
        r#"
        SELECT
            t.id, t.workspace_id, t.name, t.token_hash, t.scopes,
            t.expires_at, t.revoked_at, w.slug AS workspace_slug
        FROM service_tokens t
        JOIN workspaces w ON t.workspace_id = w.id
        WHERE w.slug = $1 AND t.token_prefix = $2
        "#,
    )
    .bind(slug)
    .bind(prefix)
    .fetch_all(pool)
    .await?;

    if candidates.is_empty() {
        return Err(TokenError::NotFound);
    }

    let now = OffsetDateTime::now_utc();
    for cand in &candidates {
        if cand.revoked_at.is_some() {
            continue;
        }
        if let Some(exp) = cand.expires_at {
            if exp < now {
                continue;
            }
        }
        let parsed = match PasswordHash::new(&cand.token_hash) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if Argon2::default()
            .verify_password(raw.as_bytes(), &parsed)
            .is_ok()
        {
            // Best-effort touch of last_used_at; ignore failures.
            let _ = sqlx::query(
                "UPDATE service_tokens SET last_used_at = now() WHERE id = $1",
            )
            .bind(cand.id)
            .execute(pool)
            .await;

            let scopes: Scopes = serde_json::from_value(cand.scopes.clone())
                .map_err(|e| TokenError::Argon2(format!("scope decode: {e}")))?;
            return Ok(TokenContext {
                token_id: cand.id,
                workspace_id: cand.workspace_id,
                workspace_slug: cand.workspace_slug.clone(),
                name: cand.name.clone(),
                scopes,
            });
        }
    }

    // None of the candidate hashes matched — could be an expired/revoked token
    // or a forged prefix. Don't leak which.
    Err(TokenError::NotFound)
}

/// Mark a token revoked by id. Idempotent.
pub async fn revoke(pool: &PgPool, token_id: Uuid) -> Result<(), TokenError> {
    sqlx::query("UPDATE service_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(token_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Parse the wire format. Returns `(workspace_slug, random_b64)`.
fn parse_format(raw: &str) -> Result<(&str, &str), TokenError> {
    let body = raw
        .strip_prefix(TOKEN_LITERAL_PREFIX)
        .ok_or(TokenError::FormatInvalid)?;
    // body = "{slug}_{random}"
    let underscore_idx = body.find('_').ok_or(TokenError::FormatInvalid)?;
    let slug = &body[..underscore_idx];
    let random = &body[underscore_idx + 1..];
    if slug.is_empty() || random.len() < TOKEN_PREFIX_LEN {
        return Err(TokenError::FormatInvalid);
    }
    Ok((slug, random))
}

#[derive(sqlx::FromRow)]
struct StoredToken {
    id: Uuid,
    workspace_id: Uuid,
    workspace_slug: String,
    name: String,
    token_hash: String,
    scopes: serde_json::Value,
    expires_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_well_formed_token() {
        let raw = "andv_spirit-finder_abcdEFGHijkl1234mnop5678qrst";
        let (slug, rand) = parse_format(raw).unwrap();
        assert_eq!(slug, "spirit-finder");
        assert_eq!(rand, "abcdEFGHijkl1234mnop5678qrst");
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        assert!(matches!(
            parse_format("foo_bar_random"),
            Err(TokenError::FormatInvalid)
        ));
    }

    #[test]
    fn parse_rejects_missing_underscore() {
        assert!(matches!(
            parse_format("andv_noseparator"),
            Err(TokenError::FormatInvalid)
        ));
    }

    #[test]
    fn parse_rejects_empty_slug() {
        assert!(matches!(
            parse_format("andv__random123"),
            Err(TokenError::FormatInvalid)
        ));
    }

    #[test]
    fn parse_rejects_short_random() {
        // Shorter than the 8-byte prefix.
        assert!(matches!(
            parse_format("andv_slug_abc"),
            Err(TokenError::FormatInvalid)
        ));
    }
}
