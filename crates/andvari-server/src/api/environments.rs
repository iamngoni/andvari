//! Environment CRUD within a project.

use actix_web::{HttpResponse, Responder, get, post, web};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::auth::middleware::RequireToken;
use crate::state::AppState;

#[derive(Serialize, FromRow)]
struct EnvRow {
    id: Uuid,
    project_id: Uuid,
    name: String,
    requires_approval: bool,
    approver_count: i32,
    created_at: OffsetDateTime,
}

#[derive(Deserialize)]
pub struct CreateEnv {
    pub name: String,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default = "default_approver_count")]
    pub approver_count: i32,
}

fn default_approver_count() -> i32 {
    1
}

async fn project_id_for(
    pool: &sqlx::PgPool,
    workspace_id: Uuid,
    project_slug: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM projects WHERE workspace_id = $1 AND slug = $2",
    )
    .bind(workspace_id)
    .bind(project_slug)
    .fetch_optional(pool)
    .await
}

#[post("/v1/ws/{ws_slug}/projects/{proj_slug}/envs")]
pub async fn create(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String)>,
    body: web::Json<CreateEnv>,
) -> impl Responder {
    let (ws_slug, proj_slug) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({"error":"db unavailable"}));
    };

    let project_id = match project_id_for(pool, auth.0.workspace_id, &proj_slug).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"project not found"}));
        }
        Err(e) => {
            warn!(error = %e, "lookup project");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let row = match sqlx::query_as::<_, EnvRow>(
        r#"
        INSERT INTO environments (project_id, name, requires_approval, approver_count)
        VALUES ($1, $2, $3, $4)
        RETURNING id, project_id, name, requires_approval, approver_count, created_at
        "#,
    )
    .bind(project_id)
    .bind(&body.name)
    .bind(body.requires_approval)
    .bind(body.approver_count)
    .fetch_one(pool)
    .await
    {
        Ok(r) => r,
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            return HttpResponse::Conflict()
                .json(serde_json::json!({"error":"env name already exists in this project"}));
        }
        Err(e) => {
            warn!(error = %e, "env create");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Created().json(row)
}

#[get("/v1/ws/{ws_slug}/projects/{proj_slug}/envs")]
pub async fn list(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (ws_slug, proj_slug) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({"error":"db unavailable"}));
    };

    let project_id = match project_id_for(pool, auth.0.workspace_id, &proj_slug).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"project not found"}));
        }
        Err(e) => {
            warn!(error = %e, "lookup project");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let rows = match sqlx::query_as::<_, EnvRow>(
        r#"
        SELECT id, project_id, name, requires_approval, approver_count, created_at
        FROM environments WHERE project_id = $1
        ORDER BY name
        "#,
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list envs");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({ "environments": rows }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create).service(list);
}
