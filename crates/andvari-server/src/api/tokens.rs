//! Service token CRUD per workspace.

use actix_web::{HttpResponse, Responder, delete, get, post, web};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::auth::middleware::RequireToken;
use crate::auth::scope::Scopes;
use crate::auth::token;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateTokenReq {
    pub name: String,
    pub scopes: Scopes,
    /// Optional RFC 3339 timestamp.
    #[serde(default)]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
pub struct CreateTokenResp {
    pub id: Uuid,
    pub raw: String,
    pub prefix: String,
    pub name: String,
}

#[post("/v1/ws/{ws_slug}/tokens")]
pub async fn create(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
    body: web::Json<CreateTokenReq>,
) -> impl Responder {
    let ws_slug = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({"error":"db unavailable"}));
    };

    let created = match token::create(
        pool,
        auth.0.workspace_id,
        &auth.0.workspace_slug,
        &body.name,
        &body.scopes,
        body.expires_at,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "token create");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"token creation failed"}));
        }
    };

    HttpResponse::Created().json(CreateTokenResp {
        id: created.id,
        raw: created.raw,
        prefix: created.prefix,
        name: body.name.clone(),
    })
}

#[derive(Serialize, FromRow)]
struct TokenSummary {
    id: Uuid,
    name: String,
    token_prefix: String,
    scopes: serde_json::Value,
    expires_at: Option<OffsetDateTime>,
    last_used_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

#[get("/v1/ws/{ws_slug}/tokens")]
pub async fn list(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
) -> impl Responder {
    let ws_slug = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({"error":"db unavailable"}));
    };

    let rows = match sqlx::query_as::<_, TokenSummary>(
        r#"
        SELECT id, name, token_prefix, scopes, expires_at, last_used_at, revoked_at, created_at
        FROM service_tokens
        WHERE workspace_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(auth.0.workspace_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list tokens");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({ "tokens": rows }))
}

#[delete("/v1/ws/{ws_slug}/tokens/{token_id}")]
pub async fn revoke(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, Uuid)>,
) -> impl Responder {
    let (ws_slug, token_id) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    if token_id == auth.0.token_id {
        // Don't let a token revoke itself in the same call (would race a
        // 200 response against the now-invalid auth context). Operators can
        // hit DELETE with another token.
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":"cannot revoke the token used for this request"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({"error":"db unavailable"}));
    };

    // Verify the target token belongs to the same workspace before revoking.
    let belongs: Option<Uuid> = match sqlx::query_scalar(
        "SELECT id FROM service_tokens WHERE id = $1 AND workspace_id = $2",
    )
    .bind(token_id)
    .bind(auth.0.workspace_id)
    .fetch_optional(pool)
    .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "lookup token to revoke");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    if belongs.is_none() {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error":"token not found in this workspace"}));
    }

    if let Err(e) = token::revoke(pool, token_id).await {
        warn!(error = %e, "revoke token");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"revoke failed"}));
    }
    HttpResponse::Ok().json(serde_json::json!({"revoked": true}))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create).service(list).service(revoke);
}
