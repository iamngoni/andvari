//! REST endpoints for issuing / revoking / listing dynamic-secret leases.

use actix_web::{HttpResponse, Responder, delete, get, post, web};
use andvari_core::dynamic::LeaseRequest;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::types::Json;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::auth::middleware::RequireToken;
use crate::auth::scope::Op;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct IssueLease {
    pub engine: String,
    /// Engine-specific scope (e.g. database name for postgres).
    #[serde(default)]
    pub scope: String,
    pub ttl_seconds: i64,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Serialize)]
pub struct IssueLeaseResp {
    pub lease_id: Uuid,
    pub engine: String,
    pub credentials: serde_json::Value,
    pub expires_at: OffsetDateTime,
}

#[derive(Serialize, FromRow)]
struct LeaseSummary {
    id: Uuid,
    engine: String,
    scope: String,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    params: Json<serde_json::Value>,
}

#[post("/v1/ws/{ws_slug}/leases")]
pub async fn issue(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
    body: web::Json<IssueLease>,
) -> impl Responder {
    let ws_slug = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    // Lease ops are gated on the `lease` op. We don't have project/env
    // context here, so apply a workspace-wide check by allowing any
    // (project, env) match in the scopes — pick one that the token has.
    let allowed = !auth.0.scopes.ops.iter().any(|op| matches!(op, Op::Lease)).then_some(()).is_none();
    if !allowed {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"scope does not permit lease ops"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };
    let Some(engine) = state.engines.get(&body.engine) else {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("engine '{}' not configured", body.engine),
        }));
    };

    let req = LeaseRequest {
        workspace_id: auth.0.workspace_id,
        engine: body.engine.clone(),
        scope: body.scope.clone(),
        ttl_seconds: body.ttl_seconds,
        params: body.params.clone(),
    };

    let issued = match engine.issue_lease(&req).await {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, engine = %body.engine, "issue lease");
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": e.to_string()}));
        }
    };

    // Persist lease metadata. Credentials are NOT stored — they live only
    // in the response. Revocation works from the lease_id alone.
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO leases
            (id, workspace_id, engine, scope, params, issued_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, now(), $6)
        "#,
    )
    .bind(issued.lease_id)
    .bind(auth.0.workspace_id)
    .bind(&issued.engine)
    .bind(&body.scope)
    .bind(&body.params)
    .bind(issued.expires_at)
    .execute(pool)
    .await
    {
        warn!(error = %e, "persist lease");
        // Try to clean up the just-created credential.
        let _ = engine.revoke_lease(issued.lease_id, &body.scope).await;
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }

    HttpResponse::Created().json(IssueLeaseResp {
        lease_id: issued.lease_id,
        engine: issued.engine,
        credentials: issued.credentials,
        expires_at: issued.expires_at,
    })
}

#[get("/v1/ws/{ws_slug}/leases")]
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
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };
    let rows = match sqlx::query_as::<_, LeaseSummary>(
        r#"
        SELECT id, engine, scope, issued_at, expires_at, revoked_at, params
        FROM leases WHERE workspace_id = $1
        ORDER BY issued_at DESC
        LIMIT 200
        "#,
    )
    .bind(auth.0.workspace_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list leases");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({"leases": rows}))
}

#[delete("/v1/ws/{ws_slug}/leases/{id}")]
pub async fn revoke(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, Uuid)>,
) -> impl Responder {
    let (ws_slug, id) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };
    let row: Option<(String, String)> = match sqlx::query_as(
        "SELECT engine, scope FROM leases WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(auth.0.workspace_id)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "lookup lease");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let Some((engine_name, scope)) = row else {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error":"lease not found or already revoked"}));
    };
    let Some(engine) = state.engines.get(&engine_name) else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"engine no longer configured"}));
    };

    if let Err(e) = engine.revoke_lease(id, &scope).await {
        warn!(error = %e, "engine revoke");
        // Still mark as revoked so we don't keep retrying a broken backend.
    }
    let _ = sqlx::query("UPDATE leases SET revoked_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await;
    HttpResponse::Ok().json(serde_json::json!({"revoked": true}))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(issue).service(list).service(revoke);
}
