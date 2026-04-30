//! Project CRUD within a workspace.

use actix_web::{HttpResponse, Responder, get, post, web};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::auth::middleware::RequireToken;
use crate::state::AppState;

#[derive(Serialize, FromRow)]
struct ProjectRow {
    id: Uuid,
    workspace_id: Uuid,
    slug: String,
    name: String,
    created_at: OffsetDateTime,
}

#[derive(Deserialize)]
pub struct CreateProject {
    pub slug: String,
    pub name: String,
}

#[post("/v1/ws/{ws_slug}/projects")]
pub async fn create(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
    body: web::Json<CreateProject>,
) -> impl Responder {
    let ws_slug = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({"error":"db unavailable"}));
    };

    let row = match sqlx::query_as::<_, ProjectRow>(
        r#"
        INSERT INTO projects (workspace_id, slug, name)
        VALUES ($1, $2, $3)
        RETURNING id, workspace_id, slug, name, created_at
        "#,
    )
    .bind(auth.0.workspace_id)
    .bind(&body.slug)
    .bind(&body.name)
    .fetch_one(pool)
    .await
    {
        Ok(r) => r,
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            return HttpResponse::Conflict()
                .json(serde_json::json!({"error":"project slug already exists in this workspace"}));
        }
        Err(e) => {
            warn!(error = %e, "project create");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    HttpResponse::Created().json(row)
}

#[get("/v1/ws/{ws_slug}/projects")]
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

    let rows = match sqlx::query_as::<_, ProjectRow>(
        r#"
        SELECT id, workspace_id, slug, name, created_at
        FROM projects WHERE workspace_id = $1
        ORDER BY slug
        "#,
    )
    .bind(auth.0.workspace_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list projects");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({ "projects": rows }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create).service(list);
}
