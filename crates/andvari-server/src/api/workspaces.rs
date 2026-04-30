//! Workspace listing + lookup. Creation past the bootstrap goes through
//! `/v1/workspaces` (auth required); the very first one comes from
//! `/v1/init`.

use actix_web::{HttpResponse, Responder, get, web};
use serde::Serialize;
use sqlx::FromRow;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::auth::middleware::RequireToken;
use crate::state::AppState;

#[derive(Serialize, FromRow)]
struct WorkspaceRow {
    id: Uuid,
    slug: String,
    name: String,
    created_at: OffsetDateTime,
}

#[get("/v1/workspaces")]
pub async fn list(state: web::Data<AppState>, auth: RequireToken) -> impl Responder {
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };

    // For now: tokens are scoped to one workspace; list returns just that one.
    // When OIDC/users land, this will return every workspace the user belongs to.
    let row = match sqlx::query_as::<_, WorkspaceRow>(
        "SELECT id, slug, name, created_at FROM workspaces WHERE id = $1",
    )
    .bind(auth.0.workspace_id)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list workspaces");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({
        "workspaces": row.into_iter().collect::<Vec<_>>(),
    }))
}

#[get("/v1/workspaces/{slug}")]
pub async fn get_one(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
) -> impl Responder {
    let slug = path.into_inner();
    if auth.0.workspace_slug != slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };
    let row = match sqlx::query_as::<_, WorkspaceRow>(
        "SELECT id, slug, name, created_at FROM workspaces WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"workspace not found"}));
        }
        Err(e) => {
            warn!(error = %e, "get workspace");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(row)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list).service(get_one);
}
