//! Postgres-backed append-only audit log.
//!
//! On every write we:
//! 1. Take a global advisory transaction lock so the chain stays linear under
//!    concurrent inserts.
//! 2. Read the most recent row's `hmac_chain` (or the genesis chain).
//! 3. Compute `chain = HMAC-SHA256(prev_chain || canonical_bytes(row))`.
//! 4. INSERT the row with the computed chain.
//!
//! Verification walks the table in `id` order, recomputing each chain and
//! comparing constant-time. The first divergence is reported as the tamper
//! point — any row whose chain disagrees, or whose canonical bytes no longer
//! match what its chain was computed over, breaks the chain at that row.

#![allow(dead_code)] // wired into request handlers by later slices

use andvari_core::audit::{
    ActorKind, AuditHmacKey, AuditRow, GENESIS_CHAIN, compute_chain, verify_chain,
};
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Postgres advisory-lock key reserved for the audit chain. Arbitrary u64;
/// chosen high enough to avoid collisions with any future locks.
const AUDIT_CHAIN_LOCK: i64 = 0x4144564152495f41; // "ADVARI_A"

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),

    #[error("audit chain corrupted at row {row_id}")]
    ChainBroken { row_id: i64 },
}

/// Append a single audit row, returning the assigned `id`.
pub async fn append(
    pool: &PgPool,
    key: &AuditHmacKey,
    row: AuditRow<'_>,
) -> Result<i64, AuditError> {
    let mut tx = pool.begin().await?;

    // Serialize against any other audit-chain writer in this database.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_CHAIN_LOCK)
        .execute(&mut *tx)
        .await?;

    let prev_chain: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hmac_chain FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;

    let prev: &[u8] = prev_chain.as_deref().unwrap_or(&GENESIS_CHAIN);
    let canonical = row.canonical_bytes();
    let chain = compute_chain(key, prev, &canonical);

    let ip_for_db: Option<IpNetwork> = row.ip.map(IpNetwork::from);

    let id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO audit_log
            (ts, workspace_id, actor_id, actor_kind, action,
             target_kind, target_id, ip, user_agent, request_id, hmac_chain)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
        "#,
    )
    .bind(row.ts)
    .bind(row.workspace_id)
    .bind(row.actor_id)
    .bind(row.actor_kind.as_str())
    .bind(row.action)
    .bind(row.target_kind)
    .bind(row.target_id)
    .bind(ip_for_db)
    .bind(row.user_agent)
    .bind(row.request_id)
    .bind(chain.as_slice())
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(id)
}

/// Verifier report. `tamper_point` is the `id` of the first row whose chain
/// fails to verify, or `None` if the entire log is intact.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub rows_checked: usize,
    pub tamper_point: Option<i64>,
}

/// Walk the audit log in order, recomputing each chain link.
pub async fn verify(pool: &PgPool, key: &AuditHmacKey) -> Result<VerifyReport, AuditError> {
    let rows = sqlx::query_as::<_, StoredAuditRow>(
        r#"
        SELECT id, ts, workspace_id, actor_id, actor_kind, action,
               target_kind, target_id, ip, user_agent, request_id, hmac_chain
        FROM audit_log
        ORDER BY id ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut prev: Vec<u8> = GENESIS_CHAIN.to_vec();
    let mut rows_checked = 0;

    for stored in &rows {
        let actor_kind = parse_actor_kind(&stored.actor_kind);
        let row = AuditRow {
            ts: stored.ts,
            workspace_id: stored.workspace_id,
            actor_id: stored.actor_id,
            actor_kind,
            action: &stored.action,
            target_kind: stored.target_kind.as_deref(),
            target_id: stored.target_id,
            ip: stored.ip.map(|n| n.ip()),
            user_agent: stored.user_agent.as_deref(),
            request_id: stored.request_id,
        };
        let canonical = row.canonical_bytes();
        if !verify_chain(key, &prev, &canonical, &stored.hmac_chain) {
            return Ok(VerifyReport {
                rows_checked,
                tamper_point: Some(stored.id),
            });
        }
        prev = stored.hmac_chain.clone();
        rows_checked += 1;
    }

    Ok(VerifyReport {
        rows_checked,
        tamper_point: None,
    })
}

#[derive(sqlx::FromRow)]
struct StoredAuditRow {
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

fn parse_actor_kind(s: &str) -> ActorKind {
    match s {
        "user" => ActorKind::User,
        "token" => ActorKind::Token,
        "oidc-fed" => ActorKind::OidcFed,
        _ => ActorKind::System,
    }
}
