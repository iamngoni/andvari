//! Server-side sessions backed by the `sessions` table.
//!
//! Cookie format: a single cookie `andvari_session` whose value is a UUIDv4
//! (the `sessions.id`). Tampering yields a session-not-found lookup, which
//! the middleware translates to "no identity attached"; routes that require
//! identity then return 401.

use actix_web::body::MessageBody;
use actix_web::cookie::Cookie;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{Error, HttpMessage, web};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tracing::warn;
use uuid::Uuid;

use crate::state::AppState;

pub const SESSION_COOKIE: &str = "andvari_session";
pub const SESSION_TTL_HOURS: i64 = 24 * 7; // 1 week

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// Generate a CSRF token. Used as the `csrf_token` column on the session row
/// for any future state-changing endpoints that want CSRF defense beyond the
/// SameSite=strict cookie.
fn random_csrf() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(Uuid, OffsetDateTime), SessionError> {
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(SESSION_TTL_HOURS);
    let csrf = random_csrf();
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO sessions (user_id, expires_at, csrf_token)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(user_id)
    .bind(expires_at)
    .bind(csrf)
    .fetch_one(pool)
    .await?;
    Ok((id, expires_at))
}

pub async fn lookup_session(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Option<SessionContext>, SessionError> {
    let row: Option<(Uuid, Uuid, Option<String>, Option<String>, OffsetDateTime)> = sqlx::query_as(
        r#"
        SELECT s.id, s.user_id, u.email, u.display_name, s.expires_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.id = $1
          AND s.expires_at > now()
        "#,
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(session_id, user_id, email, display_name, expires_at)| SessionContext {
            session_id,
            user_id,
            email,
            display_name,
            expires_at,
        },
    ))
}

pub async fn delete_session(pool: &PgPool, session_id: Uuid) -> Result<(), SessionError> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Build the `Set-Cookie` header for a fresh session.
pub fn session_cookie<'a>(session_id: Uuid) -> Cookie<'a> {
    Cookie::build(SESSION_COOKIE, session_id.to_string())
        .path("/")
        .http_only(true)
        .secure(false) // dev: true behind TLS in prod
        .same_site(actix_web::cookie::SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::hours(SESSION_TTL_HOURS))
        .finish()
}

/// Build a cookie that immediately expires the session cookie.
pub fn clear_session_cookie<'a>() -> Cookie<'a> {
    let mut c = Cookie::build(SESSION_COOKIE, "")
        .path("/")
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();
    c.make_removal();
    c
}

/// Middleware: parse the session cookie, look up the session row, attach
/// [`SessionContext`] to the request extensions on success.
pub async fn resolve_session<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    if let Some(cookie) = req.cookie(SESSION_COOKIE) {
        if let Ok(session_id) = Uuid::parse_str(cookie.value()) {
            if let Some(state) = req.app_data::<web::Data<AppState>>().cloned() {
                if let Some(pool) = state.db.as_ref() {
                    match lookup_session(pool, session_id).await {
                        Ok(Some(ctx)) => {
                            req.extensions_mut().insert(ctx);
                        }
                        Ok(None) => {
                            // expired or unknown — leave clean
                        }
                        Err(e) => {
                            warn!(error = %e, "session lookup");
                        }
                    }
                }
            }
        }
    }
    next.call(req).await
}
