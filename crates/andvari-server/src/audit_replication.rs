//! External audit-log replication to S3-compatible object storage.
//!
//! Configured via:
//!
//! - `ANDVARI_AUDIT_S3_BUCKET` — bucket name (required to enable).
//! - `ANDVARI_AUDIT_S3_PREFIX` — optional key prefix (default: `andvari-audit/`).
//! - `ANDVARI_AUDIT_S3_REGION` — optional; defaults to AWS provider chain.
//! - `ANDVARI_AUDIT_S3_ENDPOINT` — optional (set for MinIO / Backblaze B2).
//!
//! Operators should enable Object Lock on the bucket so an attacker who
//! compromises the running server can't retroactively edit historical
//! audit entries that have already been flushed.

use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use ipnetwork::IpNetwork;
use sqlx::FromRow;
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};
use uuid::Uuid;

const SINK_NAME: &str = "s3-primary";
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct S3Config {
    pub bucket: String,
    pub prefix: String,
    pub region: Option<String>,
    pub endpoint: Option<String>,
}

impl S3Config {
    pub fn from_env() -> Option<Self> {
        let bucket = std::env::var("ANDVARI_AUDIT_S3_BUCKET").ok()?;
        let prefix = std::env::var("ANDVARI_AUDIT_S3_PREFIX")
            .unwrap_or_else(|_| "andvari-audit/".to_string());
        let region = std::env::var("ANDVARI_AUDIT_S3_REGION").ok();
        let endpoint = std::env::var("ANDVARI_AUDIT_S3_ENDPOINT").ok();
        Some(Self {
            bucket,
            prefix,
            region,
            endpoint,
        })
    }
}

#[derive(Debug, FromRow)]
struct AuditRowOut {
    id: i64,
    ts: OffsetDateTime,
    workspace_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    actor_kind: String,
    action: String,
    target_kind: Option<String>,
    target_id: Option<Uuid>,
    ip: Option<IpNetwork>,
    user_agent: Option<String>,
    request_id: Option<Uuid>,
    hmac_chain: Vec<u8>,
}

/// Spawn the replication loop. Returns immediately; runs until the runtime exits.
pub fn spawn(pool: PgPool, cfg: S3Config) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = build_client(&cfg).await;
        loop {
            if let Err(e) = flush_once(&pool, &client, &cfg).await {
                warn!(error = %e, "audit replication: flush failed");
            }
            tokio::time::sleep(FLUSH_INTERVAL).await;
        }
    })
}

async fn build_client(cfg: &S3Config) -> S3Client {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(region) = cfg.region.clone() {
        loader = loader.region(aws_sdk_s3::config::Region::new(region));
    }
    let shared = loader.load().await;
    let mut s3_cfg = aws_sdk_s3::config::Builder::from(&shared);
    if let Some(endpoint) = cfg.endpoint.clone() {
        s3_cfg = s3_cfg.endpoint_url(endpoint).force_path_style(true);
    }
    S3Client::from_conf(s3_cfg.build())
}

async fn flush_once(pool: &PgPool, client: &S3Client, cfg: &S3Config) -> Result<(), sqlx::Error> {
    // Fetch the last replicated id, defaulting to 0.
    let last_id: i64 = sqlx::query_scalar(
        "SELECT last_id FROM audit_replication_state WHERE sink = $1",
    )
    .bind(SINK_NAME)
    .fetch_optional(pool)
    .await?
    .unwrap_or(0);

    let rows: Vec<AuditRowOut> = sqlx::query_as(
        r#"
        SELECT id, ts, workspace_id, actor_id, actor_kind, action,
               target_kind, target_id, ip, user_agent, request_id, hmac_chain
        FROM audit_log
        WHERE id > $1
        ORDER BY id ASC
        LIMIT 1000
        "#,
    )
    .bind(last_id)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    let mut buf = String::with_capacity(rows.len() * 256);
    for r in &rows {
        let line = serde_json::json!({
            "id": r.id,
            "ts": r.ts.format(&Rfc3339).unwrap_or_default(),
            "workspace_id": r.workspace_id,
            "actor_id": r.actor_id,
            "actor_kind": r.actor_kind,
            "action": r.action,
            "target_kind": r.target_kind,
            "target_id": r.target_id,
            "ip": r.ip.map(|n| n.ip().to_string()),
            "user_agent": r.user_agent,
            "request_id": r.request_id,
            // Hex-encoded chain — JSON binary support varies, hex is universal.
            "hmac_chain": hex_encode(&r.hmac_chain),
        });
        buf.push_str(&line.to_string());
        buf.push('\n');
    }

    let last_in_batch = rows.last().expect("non-empty checked").id;
    let now = OffsetDateTime::now_utc();
    let key = format!(
        "{}{}/{}-{}.jsonl",
        cfg.prefix,
        now.year(),
        last_in_batch,
        now.unix_timestamp_nanos()
    );

    if let Err(e) = client
        .put_object()
        .bucket(&cfg.bucket)
        .key(&key)
        .body(ByteStream::from(buf.into_bytes()))
        .content_type("application/x-ndjson")
        .send()
        .await
    {
        warn!(error = %e, key, "audit replication: PUT failed");
        return Ok(()); // try again next tick
    }

    sqlx::query(
        r#"
        INSERT INTO audit_replication_state (sink, last_id, last_flushed_at)
        VALUES ($1, $2, now())
        ON CONFLICT (sink) DO UPDATE
            SET last_id = EXCLUDED.last_id,
                last_flushed_at = EXCLUDED.last_flushed_at
        "#,
    )
    .bind(SINK_NAME)
    .bind(last_in_batch)
    .execute(pool)
    .await?;

    info!(
        rows = rows.len(),
        last_id = last_in_batch,
        "audit replication: flushed"
    );
    Ok(())
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
