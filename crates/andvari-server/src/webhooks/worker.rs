//! Background webhook delivery worker.
//!
//! Polls `webhook_deliveries` with `status='pending'` and `next_attempt_at <= now()`,
//! POSTs the payload with an HMAC-SHA256 signature, and either marks them
//! `success` or backs off and retries.
//!
//! Signature header: `X-Andvari-Signature: t=<unix_ts>,v1=<hex_hmac>`,
//! computed over `"<unix_ts>.<canonical_json_body>"`.

use std::time::Duration;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::types::Json;
use time::OffsetDateTime;
use tracing::{debug, warn};
use uuid::Uuid;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const DEAD_LETTER_AFTER: Duration = Duration::from_secs(60 * 60 * 24); // 24h

/// Spawn the worker on the current Tokio runtime. Returns a handle the
/// caller can drop (the task survives as long as the runtime).
pub fn spawn(pool: PgPool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("andvari/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("build webhook http client");
        loop {
            if let Err(e) = process_batch(&pool, &http).await {
                warn!(error = %e, "webhook worker: batch failed");
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
}

#[derive(sqlx::FromRow)]
struct DueDelivery {
    id: Uuid,
    webhook_id: Uuid,
    event_type: String,
    payload: Json<Value>,
    attempt: i32,
    created_at_age_secs: i64,
    url: String,
    secret: Vec<u8>,
}

async fn process_batch(pool: &PgPool, http: &reqwest::Client) -> Result<(), sqlx::Error> {
    let due: Vec<DueDelivery> = sqlx::query_as(
        r#"
        SELECT
            wd.id, wd.webhook_id, wd.event_type, wd.payload, wd.attempt,
            EXTRACT(EPOCH FROM (now() - wd.next_attempt_at))::BIGINT AS created_at_age_secs,
            w.url, w.secret
        FROM webhook_deliveries wd
        JOIN webhooks w ON wd.webhook_id = w.id
        WHERE wd.status = 'pending'
          AND wd.next_attempt_at <= now()
          AND w.disabled_at IS NULL
        ORDER BY wd.next_attempt_at ASC
        LIMIT 32
        "#,
    )
    .fetch_all(pool)
    .await?;

    for delivery in due {
        deliver_one(pool, http, delivery).await;
    }
    Ok(())
}

async fn deliver_one(pool: &PgPool, http: &reqwest::Client, d: DueDelivery) {
    let body_json = serde_json::to_string(&d.payload.0).unwrap_or_else(|_| "{}".to_string());
    let ts = OffsetDateTime::now_utc().unix_timestamp();
    let signature = sign_payload(&d.secret, ts, &body_json);
    let header = format!("t={ts},v1={signature}");

    let result = http
        .post(&d.url)
        .header("X-Andvari-Signature", &header)
        .header("X-Andvari-Event", &d.event_type)
        .header("Content-Type", "application/json")
        .body(body_json)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success() {
                let _ = sqlx::query(
                    r#"UPDATE webhook_deliveries
                       SET status='success',
                           attempt=attempt+1,
                           last_attempted_at=now(),
                           succeeded_at=now(),
                           response_status=$1,
                           response_body=$2
                       WHERE id=$3"#,
                )
                .bind(status.as_u16() as i32)
                .bind(truncate(&body, 4096))
                .bind(d.id)
                .execute(pool)
                .await;
                debug!(delivery_id = %d.id, "webhook delivered");
            } else {
                schedule_retry(pool, d, Some(status.as_u16()), Some(body)).await;
            }
        }
        Err(e) => {
            schedule_retry(pool, d, None, Some(e.to_string())).await;
        }
    }
}

async fn schedule_retry(
    pool: &PgPool,
    d: DueDelivery,
    status: Option<u16>,
    body: Option<String>,
) {
    let next_attempt = d.attempt + 1;
    let elapsed = std::time::Duration::from_secs(d.created_at_age_secs.max(0) as u64);

    if elapsed > DEAD_LETTER_AFTER {
        let _ = sqlx::query(
            r#"UPDATE webhook_deliveries
               SET status='dead-letter',
                   attempt=$1,
                   last_attempted_at=now(),
                   response_status=$2,
                   response_body=$3
               WHERE id=$4"#,
        )
        .bind(next_attempt)
        .bind(status.map(|s| s as i32))
        .bind(body.as_deref().map(|b| truncate(b, 4096)))
        .bind(d.id)
        .execute(pool)
        .await;
        warn!(delivery_id = %d.id, "webhook dead-lettered after 24h of retries");
        return;
    }

    let backoff = backoff_for_attempt(next_attempt);
    let _ = sqlx::query(
        r#"UPDATE webhook_deliveries
           SET status='pending',
               attempt=$1,
               last_attempted_at=now(),
               next_attempt_at=now() + ($2 || ' seconds')::interval,
               response_status=$3,
               response_body=$4
           WHERE id=$5"#,
    )
    .bind(next_attempt)
    .bind(backoff.as_secs() as i64)
    .bind(status.map(|s| s as i32))
    .bind(body.as_deref().map(|b| truncate(b, 4096)))
    .bind(d.id)
    .execute(pool)
    .await;
}

fn backoff_for_attempt(attempt: i32) -> Duration {
    // 2^attempt seconds, capped at 30 minutes.
    let secs = 2u64.saturating_pow(attempt as u32).min(1800);
    Duration::from_secs(secs)
}

fn sign_payload(secret: &[u8], ts: i64, body: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key");
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    let bytes = mac.finalize().into_bytes();
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_deterministic() {
        let a = sign_payload(b"key", 1700000000, "{}");
        let b = sign_payload(b"key", 1700000000, "{}");
        assert_eq!(a, b);
    }

    #[test]
    fn signature_changes_with_body() {
        let a = sign_payload(b"key", 1700000000, "{\"x\":1}");
        let b = sign_payload(b"key", 1700000000, "{\"x\":2}");
        assert_ne!(a, b);
    }

    #[test]
    fn signature_changes_with_timestamp() {
        let a = sign_payload(b"key", 1700000000, "body");
        let b = sign_payload(b"key", 1700000001, "body");
        assert_ne!(a, b);
    }

    #[test]
    fn signature_changes_with_secret() {
        let a = sign_payload(b"k1", 1, "b");
        let b = sign_payload(b"k2", 1, "b");
        assert_ne!(a, b);
    }

    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(backoff_for_attempt(1), Duration::from_secs(2));
        assert_eq!(backoff_for_attempt(2), Duration::from_secs(4));
        assert_eq!(backoff_for_attempt(8), Duration::from_secs(256));
        assert_eq!(backoff_for_attempt(20), Duration::from_secs(1800));
    }
}
