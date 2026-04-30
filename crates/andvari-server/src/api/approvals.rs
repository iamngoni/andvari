//! Approval requests and signoffs for sensitive operations.

use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use andvari_core::audit::{ActorKind, AuditHmacKey, AuditRow};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::audit;
use crate::auth::middleware::RequireUser;
use crate::state::AppState;

#[derive(Debug, FromRow)]
struct WorkspaceMember {
    workspace_id: Uuid,
    role: String,
}

#[derive(Debug, Serialize, FromRow)]
pub struct ApprovalRow {
    id: Uuid,
    workspace_id: Uuid,
    requested_by: Uuid,
    action: String,
    target: serde_json::Value,
    required_count: i32,
    status: String,
    created_at: OffsetDateTime,
    executed_at: Option<OffsetDateTime>,
}

#[derive(Deserialize)]
pub struct ApprovalQuery {
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateApproval {
    pub action: String,
    pub target: serde_json::Value,
    #[serde(default)]
    pub required_count: Option<i32>,
}

#[derive(Serialize)]
pub struct ApprovalMutation {
    pub approval: ApprovalRow,
    pub signoffs: i64,
}

#[get("/v1/ws/{ws_slug}/approvals")]
pub async fn list(
    state: web::Data<AppState>,
    user: RequireUser,
    path: web::Path<String>,
    query: web::Query<ApprovalQuery>,
) -> impl Responder {
    let ws_slug = path.into_inner();
    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };
    let member = match require_member(pool, &ws_slug, user.0.user_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return forbidden("user is not a member of this workspace"),
        Err(e) => {
            warn!(error = %e, "approval list membership");
            return db_error();
        }
    };

    let rows = match sqlx::query_as::<_, ApprovalRow>(
        r#"
        SELECT id, workspace_id, requested_by, action, target, required_count,
               status, created_at, executed_at
        FROM approvals
        WHERE workspace_id = $1
          AND ($2::text IS NULL OR status = $2)
        ORDER BY created_at DESC
        "#,
    )
    .bind(member.workspace_id)
    .bind(query.status.as_deref())
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "approval list");
            return db_error();
        }
    };

    HttpResponse::Ok().json(serde_json::json!({ "approvals": rows }))
}

#[post("/v1/ws/{ws_slug}/approvals")]
pub async fn create(
    state: web::Data<AppState>,
    user: RequireUser,
    path: web::Path<String>,
    body: web::Json<CreateApproval>,
    req: HttpRequest,
) -> impl Responder {
    let ws_slug = path.into_inner();
    if body.action.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error":"action is required"}));
    }
    let required_count = body.required_count.unwrap_or(1);
    if required_count < 1 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":"required_count must be >= 1"}));
    }

    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };
    let member = match require_member(pool, &ws_slug, user.0.user_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return forbidden("user is not a member of this workspace"),
        Err(e) => {
            warn!(error = %e, "approval create membership");
            return db_error();
        }
    };

    let row = match sqlx::query_as::<_, ApprovalRow>(
        r#"
        INSERT INTO approvals (workspace_id, requested_by, action, target, required_count)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, workspace_id, requested_by, action, target, required_count,
                  status, created_at, executed_at
        "#,
    )
    .bind(member.workspace_id)
    .bind(user.0.user_id)
    .bind(&body.action)
    .bind(&body.target)
    .bind(required_count)
    .fetch_one(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "approval create");
            return db_error();
        }
    };

    audit_approval(
        &state,
        pool,
        "approval.request",
        user.0.user_id,
        row.id,
        &req,
    )
    .await;
    HttpResponse::Created().json(row)
}

#[post("/v1/ws/{ws_slug}/approvals/{approval_id}/approve")]
pub async fn approve(
    state: web::Data<AppState>,
    user: RequireUser,
    path: web::Path<(String, Uuid)>,
    req: HttpRequest,
) -> impl Responder {
    mutate_signoff(state, user, path, true, req).await
}

#[post("/v1/ws/{ws_slug}/approvals/{approval_id}/reject")]
pub async fn reject(
    state: web::Data<AppState>,
    user: RequireUser,
    path: web::Path<(String, Uuid)>,
    req: HttpRequest,
) -> impl Responder {
    mutate_signoff(state, user, path, false, req).await
}

async fn mutate_signoff(
    state: web::Data<AppState>,
    user: RequireUser,
    path: web::Path<(String, Uuid)>,
    approve_it: bool,
    req: HttpRequest,
) -> HttpResponse {
    let (ws_slug, approval_id) = path.into_inner();
    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };
    let member = match require_member(pool, &ws_slug, user.0.user_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return forbidden("user is not a member of this workspace"),
        Err(e) => {
            warn!(error = %e, "approval mutate membership");
            return db_error();
        }
    };
    if !can_approve(&member.role) {
        return forbidden("workspace role cannot approve requests");
    }

    let current = match load_approval(pool, member.workspace_id, approval_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"approval not found"}));
        }
        Err(e) => {
            warn!(error = %e, "approval lookup");
            return db_error();
        }
    };
    if current.requested_by == user.0.user_id {
        return HttpResponse::Forbidden().json(
            serde_json::json!({"error":"requesters cannot approve or reject their own approval"}),
        );
    }
    if current.status != "pending" {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error":"approval is not pending"}));
    }

    if !approve_it {
        let row = match set_status(pool, approval_id, "rejected").await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "approval reject");
                return db_error();
            }
        };
        audit_approval(
            &state,
            pool,
            "approval.reject",
            user.0.user_id,
            row.id,
            &req,
        )
        .await;
        return HttpResponse::Ok().json(ApprovalMutation {
            approval: row,
            signoffs: 0,
        });
    }

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO approval_signoffs (approval_id, approver_id)
        VALUES ($1, $2)
        ON CONFLICT (approval_id, approver_id) DO NOTHING
        "#,
    )
    .bind(approval_id)
    .bind(user.0.user_id)
    .execute(pool)
    .await
    {
        warn!(error = %e, "approval signoff");
        return db_error();
    }

    let signoffs = match signoff_count(pool, approval_id).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "approval signoff count");
            return db_error();
        }
    };

    let row = if signoffs >= i64::from(current.required_count) {
        match set_status(pool, approval_id, "approved").await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "approval approve");
                return db_error();
            }
        }
    } else {
        match load_approval(pool, member.workspace_id, approval_id).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                return HttpResponse::NotFound()
                    .json(serde_json::json!({"error":"approval not found"}));
            }
            Err(e) => {
                warn!(error = %e, "approval reload");
                return db_error();
            }
        }
    };

    audit_approval(
        &state,
        pool,
        "approval.approve",
        user.0.user_id,
        row.id,
        &req,
    )
    .await;
    HttpResponse::Ok().json(ApprovalMutation {
        approval: row,
        signoffs,
    })
}

pub async fn validate_approved(
    pool: &PgPool,
    workspace_id: Uuid,
    approval_id: Uuid,
    action: &str,
    target: &serde_json::Value,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT status, target
        FROM approvals
        WHERE id = $1
          AND workspace_id = $2
          AND action = $3
        "#,
    )
    .bind(approval_id)
    .bind(workspace_id)
    .bind(action)
    .fetch_optional(pool)
    .await?;

    Ok(
        matches!(row, Some((status, stored_target)) if status == "approved" && stored_target == *target),
    )
}

pub async fn mark_executed(pool: &PgPool, approval_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE approvals
        SET status = 'executed', executed_at = now()
        WHERE id = $1 AND status = 'approved'
        "#,
    )
    .bind(approval_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn require_member(
    pool: &PgPool,
    workspace_slug: &str,
    user_id: Uuid,
) -> Result<Option<WorkspaceMember>, sqlx::Error> {
    sqlx::query_as::<_, WorkspaceMember>(
        r#"
        SELECT w.id AS workspace_id, m.role
        FROM workspaces w
        JOIN memberships m ON m.workspace_id = w.id
        WHERE w.slug = $1 AND m.user_id = $2
        "#,
    )
    .bind(workspace_slug)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

async fn load_approval(
    pool: &PgPool,
    workspace_id: Uuid,
    approval_id: Uuid,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRow>(
        r#"
        SELECT id, workspace_id, requested_by, action, target, required_count,
               status, created_at, executed_at
        FROM approvals
        WHERE id = $1 AND workspace_id = $2
        "#,
    )
    .bind(approval_id)
    .bind(workspace_id)
    .fetch_optional(pool)
    .await
}

async fn set_status(
    pool: &PgPool,
    approval_id: Uuid,
    status: &str,
) -> Result<ApprovalRow, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRow>(
        r#"
        UPDATE approvals
        SET status = $2
        WHERE id = $1
        RETURNING id, workspace_id, requested_by, action, target, required_count,
                  status, created_at, executed_at
        "#,
    )
    .bind(approval_id)
    .bind(status)
    .fetch_one(pool)
    .await
}

async fn signoff_count(pool: &PgPool, approval_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM approval_signoffs WHERE approval_id = $1")
        .bind(approval_id)
        .fetch_one(pool)
        .await
}

async fn audit_approval(
    state: &AppState,
    pool: &PgPool,
    action: &str,
    actor_id: Uuid,
    approval_id: Uuid,
    req: &HttpRequest,
) {
    let audit_key = {
        let vault = state.vault.read().await;
        vault.root_key().map(|rk| AuditHmacKey::derive_from_rk(rk))
    };
    let Some(audit_key) = audit_key else {
        return;
    };
    let row = AuditRow {
        ts: OffsetDateTime::now_utc(),
        workspace_id: None,
        actor_id: Some(actor_id),
        actor_kind: ActorKind::User,
        action,
        target_kind: Some("approval"),
        target_id: Some(approval_id),
        ip: req.peer_addr().map(|sa| sa.ip()),
        user_agent: req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok()),
        request_id: None,
    };
    if let Err(e) = audit::append(pool, &audit_key, row).await {
        warn!(error = %e, action, "approval audit append failed");
    }
}

fn can_approve(role: &str) -> bool {
    matches!(role, "owner" | "admin" | "writer")
}

fn forbidden(reason: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({ "error": reason }))
}

fn db_error() -> HttpResponse {
    HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}))
}

fn db_unavailable() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(serde_json::json!({"error":"db unavailable"}))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list)
        .service(create)
        .service(approve)
        .service(reject);
}
