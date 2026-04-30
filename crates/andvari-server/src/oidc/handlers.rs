//! HTTP handlers for the OIDC flow + session lifecycle endpoints.

use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, http, post, web};
use openidconnect::{
    AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge, Scope, TokenResponse,
    core::CoreAuthenticationFlow, reqwest::async_http_client,
};
use serde::Deserialize;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::oidc::provider::PendingLogin;
use crate::oidc::sessions::{
    SessionContext, clear_session_cookie, create_session, delete_session, session_cookie,
};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[get("/v1/auth/oidc/login")]
pub async fn login(state: web::Data<AppState>) -> impl Responder {
    let Some(provider) = state.oidc.clone() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"oidc not configured"}));
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = provider
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    provider
        .record_pending(
            csrf_token.secret().to_string(),
            PendingLogin {
                pkce_verifier,
                nonce,
                created_at: std::time::Instant::now(),
            },
        )
        .await;

    HttpResponse::Found()
        .append_header((http::header::LOCATION, auth_url.to_string()))
        .finish()
}

#[get("/v1/auth/oidc/callback")]
pub async fn callback(
    state: web::Data<AppState>,
    query: web::Query<CallbackQuery>,
) -> impl Responder {
    let Some(provider) = state.oidc.clone() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"oidc not configured"}));
    };
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };

    if let Some(err) = &query.error {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": err,
            "description": query.error_description.clone().unwrap_or_default(),
        }));
    }

    let code = match query.code.clone() {
        Some(c) => c,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error":"missing code parameter"}));
        }
    };
    let state_param = match query.state.clone() {
        Some(s) => s,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error":"missing state parameter"}));
        }
    };

    let pending = match provider.take_pending(&state_param).await {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error":"unknown or expired state"}));
        }
    };

    // Exchange the auth code.
    let token_response = match provider
        .client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pending.pkce_verifier)
        .request_async(async_http_client)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "oidc code exchange");
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error":"token exchange failed"}));
        }
    };

    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error":"id_token missing from token response"}));
        }
    };

    let claims = match id_token.claims(&provider.client.id_token_verifier(), &pending.nonce) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "id_token validation");
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error":"id_token validation failed"}));
        }
    };

    let issuer_str = claims.issuer().to_string();
    let subject_str = claims.subject().to_string();
    let email = claims.email().map(|e| e.to_string());
    let display_name = claims
        .name()
        .and_then(|locales| locales.iter().next().map(|(_, n)| n.to_string()));

    let user_id = match upsert_user(
        pool,
        &issuer_str,
        &subject_str,
        email.as_deref(),
        display_name.as_deref(),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "upsert user");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"user create failed"}));
        }
    };

    if let Some(workspace_slug) = provider.default_workspace.as_deref() {
        if let Err(e) =
            upsert_default_membership(pool, workspace_slug, user_id, &provider.default_role).await
        {
            warn!(error = %e, workspace_slug, "upsert default oidc membership");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"membership create failed"}));
        }
    }

    let (session_id, _expires_at) = match create_session(pool, user_id).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "create session");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"session create failed"}));
        }
    };

    HttpResponse::Found()
        .cookie(session_cookie(session_id))
        .append_header((http::header::LOCATION, "/"))
        .finish()
}

#[post("/v1/auth/logout")]
pub async fn logout(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };

    if let Some(ctx) = req.extensions().get::<SessionContext>().cloned() {
        if let Err(e) = delete_session(pool, ctx.session_id).await {
            warn!(error = %e, "delete session");
        }
    }
    HttpResponse::Ok()
        .cookie(clear_session_cookie())
        .json(serde_json::json!({"logged_out": true}))
}

#[get("/v1/auth/me")]
pub async fn me(req: HttpRequest) -> impl Responder {
    let session = req.extensions().get::<SessionContext>().cloned();
    let token = req
        .extensions()
        .get::<crate::auth::token::TokenContext>()
        .cloned();

    HttpResponse::Ok().json(serde_json::json!({
        "session": session.map(|s| serde_json::json!({
            "user_id": s.user_id,
            "email": s.email,
            "display_name": s.display_name,
            "expires_at": s.expires_at,
        })),
        "token": token.map(|t| serde_json::json!({
            "token_id": t.token_id,
            "workspace_slug": t.workspace_slug,
            "name": t.name,
        })),
    }))
}

async fn upsert_user(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
    email: Option<&str>,
    display_name: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (oidc_issuer, oidc_subject, email, display_name, last_login_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE SET
            email = COALESCE(EXCLUDED.email, users.email),
            display_name = COALESCE(EXCLUDED.display_name, users.display_name),
            last_login_at = now()
        RETURNING id
        "#,
    )
    .bind(issuer)
    .bind(subject)
    .bind(email)
    .bind(display_name)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

async fn upsert_default_membership(
    pool: &PgPool,
    workspace_slug: &str,
    user_id: Uuid,
    role: &str,
) -> Result<(), sqlx::Error> {
    let role = if is_membership_role(role) {
        role
    } else {
        "reader"
    };
    let result = sqlx::query(
        r#"
        INSERT INTO memberships (workspace_id, user_id, role)
        SELECT id, $2, $3
        FROM workspaces
        WHERE slug = $1
        ON CONFLICT (workspace_id, user_id) DO UPDATE SET
            role = memberships.role
        "#,
    )
    .bind(workspace_slug)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

fn is_membership_role(role: &str) -> bool {
    matches!(role, "owner" | "admin" | "writer" | "reader" | "auditor")
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(login)
        .service(callback)
        .service(crate::oidc::federation::exchange)
        .service(logout)
        .service(me);
}
