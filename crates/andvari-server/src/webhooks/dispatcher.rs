//! Event dispatcher — turns a domain event into one row per subscribed
//! webhook in `webhook_deliveries`. The HTTP-side worker picks them up.

use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Json;
use tracing::warn;
use uuid::Uuid;

/// Generate a random HMAC signing secret for a new webhook (32 bytes).
pub fn generate_signing_secret() -> Vec<u8> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.to_vec()
}

/// Insert a delivery row for every webhook in `workspace_id` that subscribes
/// to `event_type`. Best-effort; logs and continues on failure so audit/main
/// flow is never blocked by webhook fan-out.
pub async fn fire(pool: &PgPool, workspace_id: Uuid, event_type: &str, payload: Value) {
    let webhooks: Vec<(Uuid, Json<Value>)> = match sqlx::query_as(
        r#"
        SELECT id, events
        FROM webhooks
        WHERE workspace_id = $1
          AND disabled_at IS NULL
        "#,
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "webhook dispatch: lookup failed");
            return;
        }
    };

    for (webhook_id, events) in webhooks {
        let subscribed = events
            .0
            .as_array()
            .map(|arr| arr.iter().any(|v| v.as_str() == Some(event_type)))
            .unwrap_or(false);
        if !subscribed {
            continue;
        }
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO webhook_deliveries
                (webhook_id, event_type, payload, status, next_attempt_at)
            VALUES ($1, $2, $3, 'pending', now())
            "#,
        )
        .bind(webhook_id)
        .bind(event_type)
        .bind(&payload)
        .execute(pool)
        .await
        {
            warn!(error = %e, %webhook_id, "webhook dispatch: enqueue failed");
        }
    }
}
