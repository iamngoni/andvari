//! REST endpoints for managing webhook subscriptions.

use actix_web::{HttpResponse, Responder, delete, get, post, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::types::Json;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::auth::middleware::RequireToken;
use crate::state::AppState;
use crate::webhooks::dispatcher::generate_signing_secret;

#[derive(Deserialize)]
pub struct CreateWebhook {
    pub url: String,
    pub events: Vec<String>,
}

#[derive(Serialize)]
pub struct CreateWebhookResp {
    pub id: Uuid,
    pub url: String,
    pub events: Vec<String>,
    /// Base64-encoded HMAC signing secret. Returned ONCE; the server stores
    /// raw bytes and won't re-show it on subsequent reads.
    pub secret_b64: String,
}

#[derive(Serialize, FromRow)]
struct WebhookRow {
    id: Uuid,
    url: String,
    events: Json<serde_json::Value>,
    created_at: OffsetDateTime,
    disabled_at: Option<OffsetDateTime>,
}

#[post("/v1/ws/{ws_slug}/webhooks")]
pub async fn create(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
    body: web::Json<CreateWebhook>,
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

    if body.events.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error":"events list cannot be empty"}));
    }

    let secret = generate_signing_secret();
    let events_json = serde_json::to_value(&body.events).unwrap_or(serde_json::json!([]));

    let id: Uuid = match sqlx::query_scalar(
        r#"
        INSERT INTO webhooks (workspace_id, url, events, secret)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(auth.0.workspace_id)
    .bind(&body.url)
    .bind(&events_json)
    .bind(&secret)
    .fetch_one(pool)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "webhook create");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    HttpResponse::Created().json(CreateWebhookResp {
        id,
        url: body.url.clone(),
        events: body.events.clone(),
        secret_b64: STANDARD.encode(&secret),
    })
}

#[get("/v1/ws/{ws_slug}/webhooks")]
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

    let rows = match sqlx::query_as::<_, WebhookRow>(
        r#"
        SELECT id, url, events, created_at, disabled_at
        FROM webhooks WHERE workspace_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(auth.0.workspace_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list webhooks");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({ "webhooks": rows }))
}

#[delete("/v1/ws/{ws_slug}/webhooks/{id}")]
pub async fn disable(
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

    let result = sqlx::query(
        r#"UPDATE webhooks
           SET disabled_at = now()
           WHERE id = $1 AND workspace_id = $2 AND disabled_at IS NULL"#,
    )
    .bind(id)
    .bind(auth.0.workspace_id)
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => HttpResponse::NotFound()
            .json(serde_json::json!({"error":"webhook not found or already disabled"})),
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"disabled": true})),
        Err(e) => {
            warn!(error = %e, "disable webhook");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}))
        }
    }
}

#[get("/v1/ws/{ws_slug}/webhooks/{id}/deliveries")]
pub async fn list_deliveries(
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

    #[derive(Serialize, FromRow)]
    struct DeliveryRow {
        id: Uuid,
        event_type: String,
        attempt: i32,
        status: String,
        last_attempted_at: Option<OffsetDateTime>,
        next_attempt_at: OffsetDateTime,
        succeeded_at: Option<OffsetDateTime>,
        response_status: Option<i32>,
    }

    let rows = match sqlx::query_as::<_, DeliveryRow>(
        r#"
        SELECT wd.id, wd.event_type, wd.attempt, wd.status,
               wd.last_attempted_at, wd.next_attempt_at, wd.succeeded_at, wd.response_status
        FROM webhook_deliveries wd
        JOIN webhooks w ON wd.webhook_id = w.id
        WHERE w.id = $1 AND w.workspace_id = $2
        ORDER BY wd.next_attempt_at DESC
        LIMIT 100
        "#,
    )
    .bind(id)
    .bind(auth.0.workspace_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list deliveries");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({ "deliveries": rows }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create)
        .service(list)
        .service(disable)
        .service(list_deliveries);
}
