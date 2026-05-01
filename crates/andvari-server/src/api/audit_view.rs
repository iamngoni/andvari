//! Read-only audit log endpoints — list + SSE stream.
//!
//! `GET /v1/ws/{slug}/audit` returns the most recent rows (paginated by id).
//! `GET /v1/ws/{slug}/audit/stream` is a Server-Sent Events stream that emits
//! new rows as they land. The web UI's audit-log page consumes the SSE
//! stream via HTMX's `sse` extension.

use std::time::Duration;

use actix_web::web;
use actix_web::{HttpResponse, Responder, get};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::PgPool;
use time::OffsetDateTime;
use tokio_stream::wrappers::IntervalStream;
use tracing::warn;
use uuid::Uuid;

use crate::auth::middleware::RequireToken;
use crate::state::AppState;

#[derive(Serialize, FromRow)]
struct AuditRowOut {
    id: i64,
    ts: OffsetDateTime,
    actor_id: Option<Uuid>,
    actor_kind: String,
    action: String,
    target_kind: Option<String>,
    target_id: Option<Uuid>,
    ip: Option<IpNetwork>,
    user_agent: Option<String>,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    /// Return rows with id < this. Used for backwards pagination.
    pub before_id: Option<i64>,
    pub limit: Option<i64>,
}

#[get("/v1/ws/{ws_slug}/audit")]
pub async fn list(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
    query: web::Query<AuditQuery>,
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

    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let before = query.before_id.unwrap_or(i64::MAX);

    let rows = match sqlx::query_as::<_, AuditRowOut>(
        r#"
        SELECT id, ts, actor_id, actor_kind, action, target_kind, target_id, ip, user_agent
        FROM audit_log
        WHERE workspace_id = $1 AND id < $2
        ORDER BY id DESC
        LIMIT $3
        "#,
    )
    .bind(auth.0.workspace_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "audit list");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({"rows": rows}))
}

#[get("/v1/ws/{ws_slug}/audit/stream")]
pub async fn stream(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<String>,
) -> impl Responder {
    let ws_slug = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error":"token does not belong to this workspace"}));
    }
    let Some(pool) = state.db.as_ref().cloned() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error":"db unavailable"}));
    };

    let workspace_id = auth.0.workspace_id;
    let body_stream = sse_stream(pool, workspace_id);

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming::<_, std::io::Error>(body_stream)
}

fn sse_stream(
    pool: PgPool,
    workspace_id: Uuid,
) -> impl futures_util::Stream<Item = Result<actix_web::web::Bytes, std::io::Error>> {
    use futures_util::StreamExt;
    let interval = tokio::time::interval(Duration::from_secs(2));
    let ticks = IntervalStream::new(interval);
    let last_id_state = std::sync::Arc::new(tokio::sync::Mutex::new(0i64));

    ticks.then(move |_| {
        let pool = pool.clone();
        let last_id_state = last_id_state.clone();
        async move {
            let mut last = last_id_state.lock().await;
            let rows = sqlx::query_as::<_, AuditRowOut>(
                r#"
                SELECT id, ts, actor_id, actor_kind, action, target_kind, target_id, ip, user_agent
                FROM audit_log
                WHERE workspace_id = $1 AND id > $2
                ORDER BY id ASC
                LIMIT 100
                "#,
            )
            .bind(workspace_id)
            .bind(*last)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

            if rows.is_empty() {
                // Heartbeat to keep proxies happy.
                return Ok(actix_web::web::Bytes::from_static(b": keepalive\n\n"));
            }

            *last = rows.last().expect("non-empty checked").id;
            let mut buf = String::new();
            for r in rows {
                let json = serde_json::to_string(&r).unwrap_or_else(|_| "{}".to_string());
                buf.push_str("event: audit\n");
                buf.push_str("data: ");
                buf.push_str(&json);
                buf.push_str("\n\n");
            }
            Ok(actix_web::web::Bytes::from(buf))
        }
    })
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list).service(stream);
}
