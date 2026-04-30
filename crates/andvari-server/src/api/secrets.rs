//! Secrets CRUD with per-version envelope encryption.
//!
//! - On `PUT`, generate a fresh envelope (new DEK + new nonces) and persist
//!   the wire bytes in `secret_versions.ciphertext`. The current pointer
//!   advances to the new version.
//! - On `GET`, load the current version's envelope, unwrap the workspace's
//!   KEK with the in-memory Root Key, and decrypt.
//! - On `DELETE`, nullify the current pointer. Historical versions are
//!   preserved for audit and `rollback`.
//! - `rollback` flips the current pointer to a previously-existing version
//!   without re-encrypting.
//!
//! Scope enforcement: every endpoint requires `read` or `write` ops in the
//! token's [`Scopes`] for the matched (project, env). Wrong workspace = 403.
//!
//! Audit: every read, write, and delete writes one row to `audit_log` with a
//! chained HMAC link.

use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, put, web};
use andvari_core::audit::{ActorKind, AuditHmacKey, AuditRow};
use andvari_core::crypto::{SecretEnvelope, WorkspaceKek, WrappedKek};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::audit;
use crate::auth::middleware::RequireToken;
use crate::auth::scope::Op;
use crate::state::AppState;

const NONCE_LEN: usize = 24;

#[derive(Deserialize)]
pub struct PutBody {
    /// Plaintext value as a UTF-8 string. Binary is allowed via base64-encoded
    /// JSON `value_b64` field instead.
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub value_b64: Option<String>,
    /// Required when the target environment has `requires_approval = true`.
    /// The approval target must match this secret write; plaintext is never
    /// stored in the approval record.
    #[serde(default)]
    pub approval_id: Option<Uuid>,
}

#[derive(Serialize)]
pub struct PutResponse {
    pub secret_id: Uuid,
    pub version_id: Uuid,
}

#[derive(Serialize, FromRow)]
struct SecretRow {
    id: Uuid,
    key: String,
    current_version_id: Option<Uuid>,
    updated_at: OffsetDateTime,
}

#[derive(Serialize, FromRow)]
struct VersionRow {
    id: Uuid,
    secret_id: Uuid,
    created_by: Option<Uuid>,
    created_at: OffsetDateTime,
}

struct EnvPolicy {
    id: Uuid,
    requires_approval: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn resolve_env_id(
    pool: &sqlx::PgPool,
    workspace_id: Uuid,
    project_slug: &str,
    env_name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        SELECT e.id
        FROM environments e
        JOIN projects p ON e.project_id = p.id
        WHERE p.workspace_id = $1 AND p.slug = $2 AND e.name = $3
        "#,
    )
    .bind(workspace_id)
    .bind(project_slug)
    .bind(env_name)
    .fetch_optional(pool)
    .await
}

async fn resolve_env_policy(
    pool: &sqlx::PgPool,
    workspace_id: Uuid,
    project_slug: &str,
    env_name: &str,
) -> Result<Option<EnvPolicy>, sqlx::Error> {
    let row: Option<(Uuid, bool)> = sqlx::query_as(
        r#"
        SELECT e.id, e.requires_approval
        FROM environments e
        JOIN projects p ON e.project_id = p.id
        WHERE p.workspace_id = $1 AND p.slug = $2 AND e.name = $3
        "#,
    )
    .bind(workspace_id)
    .bind(project_slug)
    .bind(env_name)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, requires_approval)| EnvPolicy {
        id,
        requires_approval,
    }))
}

fn secret_write_approval_target(
    project_slug: &str,
    env_name: &str,
    key: &str,
) -> serde_json::Value {
    serde_json::json!({
        "project": project_slug,
        "env": env_name,
        "secret": key,
    })
}

async fn load_workspace_kek(
    pool: &sqlx::PgPool,
    workspace_id: Uuid,
    workspace_slug: &str,
    rk: &andvari_core::crypto::RootKey,
) -> Result<WorkspaceKek, String> {
    let row: (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT kek_wrapped, kek_nonce FROM workspaces WHERE id = $1")
            .bind(workspace_id)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("kek lookup: {e}"))?;
    if row.1.len() != NONCE_LEN {
        return Err("stored kek nonce has wrong length".into());
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&row.1);
    let wrapped = WrappedKek {
        nonce,
        ciphertext: row.0,
    };
    let aad = format!("ws:{workspace_slug}");
    WorkspaceKek::unwrap(rk, &wrapped, aad.as_bytes()).map_err(|e| format!("kek unwrap: {e}"))
}

fn env_aad(workspace_id: Uuid, env_id: Uuid, key: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 16 + key.len() + 1);
    buf.extend_from_slice(workspace_id.as_bytes());
    buf.extend_from_slice(env_id.as_bytes());
    buf.push(b':');
    buf.extend_from_slice(key.as_bytes());
    buf
}

fn deny_response(reason: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({ "error": reason }))
}

fn db_unavailable() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(serde_json::json!({ "error": "database unavailable" }))
}

fn extract_remote_ip(req: &HttpRequest) -> Option<std::net::IpAddr> {
    req.peer_addr().map(|sa| sa.ip())
}

async fn audit_action(
    pool: &sqlx::PgPool,
    key: &AuditHmacKey,
    action: &str,
    workspace_id: Uuid,
    actor_id: Option<Uuid>,
    target_id: Option<Uuid>,
    req: &HttpRequest,
) {
    let row = AuditRow {
        ts: OffsetDateTime::now_utc(),
        workspace_id: Some(workspace_id),
        actor_id,
        actor_kind: ActorKind::Token,
        action,
        target_kind: Some("secret"),
        target_id,
        ip: extract_remote_ip(req),
        user_agent: req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok()),
        request_id: None,
    };
    if let Err(e) = audit::append(pool, key, row).await {
        warn!(error = %e, action, "audit append failed");
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

#[put("/v1/ws/{ws_slug}/projects/{proj_slug}/envs/{env_name}/secrets/{key}")]
pub async fn put_secret(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String, String, String)>,
    body: web::Json<PutBody>,
    req: HttpRequest,
) -> impl Responder {
    let (ws_slug, proj_slug, env_name, key) = path.into_inner();

    if auth.0.workspace_slug != ws_slug {
        return deny_response("token does not belong to this workspace");
    }
    if !auth.0.scopes.allows(&proj_slug, &env_name, Op::Write) {
        return deny_response("scope does not permit write on this (project, env)");
    }

    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };

    let env_policy =
        match resolve_env_policy(pool, auth.0.workspace_id, &proj_slug, &env_name).await {
            Ok(Some(policy)) => policy,
            Ok(None) => {
                return HttpResponse::NotFound()
                    .json(serde_json::json!({"error":"environment not found"}));
            }
            Err(e) => {
                warn!(error = %e, "resolve env");
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"database error"}));
            }
        };
    let env_id = env_policy.id;

    let approval_target = secret_write_approval_target(&proj_slug, &env_name, &key);
    if env_policy.requires_approval {
        let Some(approval_id) = body.approval_id else {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "approval required",
                "action": "secret.write",
                "target": approval_target,
            }));
        };
        match crate::api::approvals::validate_approved(
            pool,
            auth.0.workspace_id,
            approval_id,
            "secret.write",
            &approval_target,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return HttpResponse::Forbidden()
                    .json(serde_json::json!({"error":"approval is missing, not approved, or target does not match"}));
            }
            Err(e) => {
                warn!(error = %e, "validate approval");
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"database error"}));
            }
        }
    }

    let plaintext = match (body.value.as_ref(), body.value_b64.as_ref()) {
        (Some(v), None) => v.as_bytes().to_vec(),
        (None, Some(b)) => {
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    return HttpResponse::BadRequest()
                        .json(serde_json::json!({"error":"value_b64 is not valid base64"}));
                }
            }
        }
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "exactly one of `value` or `value_b64` must be provided",
            }));
        }
    };

    // Get/derive Root Key + audit HMAC key while holding the read lock briefly.
    let (rk, audit_key) = {
        let vault = state.vault.read().await;
        let Some(rk) = vault.root_key().cloned() else {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error":"vault is sealed"}));
        };
        let audit_key = AuditHmacKey::derive_from_rk(&rk);
        (rk, audit_key)
    };

    let kek = match load_workspace_kek(pool, auth.0.workspace_id, &auth.0.workspace_slug, &rk).await
    {
        Ok(k) => k,
        Err(e) => {
            warn!(error = e, "load kek");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"crypto error"}));
        }
    };

    // Upsert the secret row, getting its id.
    let secret_id: Uuid = match sqlx::query_scalar(
        r#"
        INSERT INTO secrets (environment_id, key)
        VALUES ($1, $2)
        ON CONFLICT (environment_id, key) DO UPDATE SET updated_at = now()
        RETURNING id
        "#,
    )
    .bind(env_id)
    .bind(&key)
    .fetch_one(pool)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "upsert secret");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let aad = env_aad(auth.0.workspace_id, env_id, &key);
    let envelope = match SecretEnvelope::seal(&plaintext, &kek, &aad) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "envelope seal");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"crypto error"}));
        }
    };
    let bytes = envelope.to_bytes();

    let version_id: Uuid = match sqlx::query_scalar(
        r#"
        INSERT INTO secret_versions (secret_id, ciphertext)
        VALUES ($1, $2)
        RETURNING id
        "#,
    )
    .bind(secret_id)
    .bind(&bytes)
    .fetch_one(pool)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "insert version");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    if let Err(e) =
        sqlx::query("UPDATE secrets SET current_version_id = $1, updated_at = now() WHERE id = $2")
            .bind(version_id)
            .bind(secret_id)
            .execute(pool)
            .await
    {
        warn!(error = %e, "update current_version_id");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }

    audit_action(
        pool,
        &audit_key,
        "secret.write",
        auth.0.workspace_id,
        Some(auth.0.token_id),
        Some(secret_id),
        &req,
    )
    .await;

    if let Some(approval_id) = body.approval_id {
        if let Err(e) = crate::api::approvals::mark_executed(pool, approval_id).await {
            warn!(error = %e, approval_id = %approval_id, "mark approval executed");
        }
    }

    HttpResponse::Created().json(PutResponse {
        secret_id,
        version_id,
    })
}

#[get("/v1/ws/{ws_slug}/projects/{proj_slug}/envs/{env_name}/secrets/{key}")]
pub async fn get_secret(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String, String, String)>,
    req: HttpRequest,
) -> impl Responder {
    let (ws_slug, proj_slug, env_name, key) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return deny_response("token does not belong to this workspace");
    }
    if !auth.0.scopes.allows(&proj_slug, &env_name, Op::Read) {
        return deny_response("scope does not permit read on this (project, env)");
    }
    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };

    let env_id = match resolve_env_id(pool, auth.0.workspace_id, &proj_slug, &env_name).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"environment not found"}));
        }
        Err(e) => {
            warn!(error = %e, "resolve env");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let row: Option<(Uuid, Option<Vec<u8>>)> = match sqlx::query_as(
        r#"
        SELECT s.id, sv.ciphertext
        FROM secrets s
        LEFT JOIN secret_versions sv ON s.current_version_id = sv.id
        WHERE s.environment_id = $1 AND s.key = $2
        "#,
    )
    .bind(env_id)
    .bind(&key)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "fetch secret");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let (secret_id, ciphertext) = match row {
        Some((id, Some(ct))) => (id, ct),
        _ => {
            return HttpResponse::NotFound().json(serde_json::json!({"error":"secret not found"}));
        }
    };

    let (rk, audit_key) = {
        let vault = state.vault.read().await;
        let Some(rk) = vault.root_key().cloned() else {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error":"vault is sealed"}));
        };
        let audit_key = AuditHmacKey::derive_from_rk(&rk);
        (rk, audit_key)
    };

    let kek = match load_workspace_kek(pool, auth.0.workspace_id, &auth.0.workspace_slug, &rk).await
    {
        Ok(k) => k,
        Err(e) => {
            warn!(error = e, "load kek");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"crypto error"}));
        }
    };

    let envelope = match SecretEnvelope::from_bytes(&ciphertext) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "envelope parse");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"corrupt envelope"}));
        }
    };

    let aad = env_aad(auth.0.workspace_id, env_id, &key);
    let plaintext = match envelope.open(&kek, &aad) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "envelope open");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"decrypt failed"}));
        }
    };

    audit_action(
        pool,
        &audit_key,
        "secret.read",
        auth.0.workspace_id,
        Some(auth.0.token_id),
        Some(secret_id),
        &req,
    )
    .await;

    // Try to return as UTF-8 string when possible; otherwise base64.
    match std::str::from_utf8(&plaintext) {
        Ok(s) => HttpResponse::Ok().json(serde_json::json!({
            "key": key, "value": s,
        })),
        Err(_) => HttpResponse::Ok().json(serde_json::json!({
            "key": key,
            "value_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &plaintext,
            ),
        })),
    }
}

#[get("/v1/ws/{ws_slug}/projects/{proj_slug}/envs/{env_name}/secrets")]
pub async fn list_secrets(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    let (ws_slug, proj_slug, env_name) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return deny_response("token does not belong to this workspace");
    }
    if !auth.0.scopes.allows(&proj_slug, &env_name, Op::Read) {
        return deny_response("scope does not permit read on this (project, env)");
    }
    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };

    let env_id = match resolve_env_id(pool, auth.0.workspace_id, &proj_slug, &env_name).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"environment not found"}));
        }
        Err(e) => {
            warn!(error = %e, "resolve env");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let rows = match sqlx::query_as::<_, SecretRow>(
        r#"
        SELECT id, key, current_version_id, updated_at
        FROM secrets
        WHERE environment_id = $1 AND current_version_id IS NOT NULL
        ORDER BY key
        "#,
    )
    .bind(env_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list secrets");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({ "secrets": rows }))
}

#[delete("/v1/ws/{ws_slug}/projects/{proj_slug}/envs/{env_name}/secrets/{key}")]
pub async fn delete_secret(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String, String, String)>,
    req: HttpRequest,
) -> impl Responder {
    let (ws_slug, proj_slug, env_name, key) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return deny_response("token does not belong to this workspace");
    }
    if !auth.0.scopes.allows(&proj_slug, &env_name, Op::Write) {
        return deny_response("scope does not permit write on this (project, env)");
    }
    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };

    let env_id = match resolve_env_id(pool, auth.0.workspace_id, &proj_slug, &env_name).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"environment not found"}));
        }
        Err(e) => {
            warn!(error = %e, "resolve env");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let secret_id: Option<Uuid> =
        match sqlx::query_scalar("SELECT id FROM secrets WHERE environment_id = $1 AND key = $2")
            .bind(env_id)
            .bind(&key)
            .fetch_optional(pool)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "delete secret lookup");
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"database error"}));
            }
        };
    let Some(secret_id) = secret_id else {
        return HttpResponse::NotFound().json(serde_json::json!({"error":"secret not found"}));
    };

    if let Err(e) = sqlx::query(
        "UPDATE secrets SET current_version_id = NULL, updated_at = now() WHERE id = $1",
    )
    .bind(secret_id)
    .execute(pool)
    .await
    {
        warn!(error = %e, "delete (nullify current_version)");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }

    let audit_key = {
        let vault = state.vault.read().await;
        match vault.root_key() {
            Some(rk) => AuditHmacKey::derive_from_rk(rk),
            None => {
                return HttpResponse::Ok().json(serde_json::json!({"deleted": true}));
            }
        }
    };
    audit_action(
        pool,
        &audit_key,
        "secret.delete",
        auth.0.workspace_id,
        Some(auth.0.token_id),
        Some(secret_id),
        &req,
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({"deleted": true}))
}

#[get("/v1/ws/{ws_slug}/projects/{proj_slug}/envs/{env_name}/secrets/{key}/versions")]
pub async fn list_versions(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String, String, String)>,
) -> impl Responder {
    let (ws_slug, proj_slug, env_name, key) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return deny_response("token does not belong to this workspace");
    }
    if !auth.0.scopes.allows(&proj_slug, &env_name, Op::Read) {
        return deny_response("scope does not permit read on this (project, env)");
    }
    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };

    let env_id = match resolve_env_id(pool, auth.0.workspace_id, &proj_slug, &env_name).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"environment not found"}));
        }
        Err(e) => {
            warn!(error = %e, "resolve env");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let secret_id: Option<Uuid> =
        match sqlx::query_scalar("SELECT id FROM secrets WHERE environment_id = $1 AND key = $2")
            .bind(env_id)
            .bind(&key)
            .fetch_optional(pool)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "secret lookup");
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"database error"}));
            }
        };
    let Some(secret_id) = secret_id else {
        return HttpResponse::NotFound().json(serde_json::json!({"error":"secret not found"}));
    };

    let rows = match sqlx::query_as::<_, VersionRow>(
        r#"
        SELECT id, secret_id, created_by, created_at
        FROM secret_versions
        WHERE secret_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(secret_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list versions");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({ "versions": rows }))
}

#[derive(Deserialize)]
pub struct RollbackBody {
    pub version_id: Uuid,
}

#[post("/v1/ws/{ws_slug}/projects/{proj_slug}/envs/{env_name}/secrets/{key}/rollback")]
pub async fn rollback(
    state: web::Data<AppState>,
    auth: RequireToken,
    path: web::Path<(String, String, String, String)>,
    body: web::Json<RollbackBody>,
    req: HttpRequest,
) -> impl Responder {
    let (ws_slug, proj_slug, env_name, key) = path.into_inner();
    if auth.0.workspace_slug != ws_slug {
        return deny_response("token does not belong to this workspace");
    }
    if !auth.0.scopes.allows(&proj_slug, &env_name, Op::Write) {
        return deny_response("scope does not permit write on this (project, env)");
    }
    let Some(pool) = state.db.as_ref() else {
        return db_unavailable();
    };

    let env_id = match resolve_env_id(pool, auth.0.workspace_id, &proj_slug, &env_name).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"environment not found"}));
        }
        Err(e) => {
            warn!(error = %e, "resolve env");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let secret_id: Option<Uuid> =
        match sqlx::query_scalar("SELECT id FROM secrets WHERE environment_id = $1 AND key = $2")
            .bind(env_id)
            .bind(&key)
            .fetch_optional(pool)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "rollback lookup");
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"database error"}));
            }
        };
    let Some(secret_id) = secret_id else {
        return HttpResponse::NotFound().json(serde_json::json!({"error":"secret not found"}));
    };

    // Confirm the target version belongs to this secret.
    let target_belongs: Option<Uuid> =
        match sqlx::query_scalar("SELECT id FROM secret_versions WHERE id = $1 AND secret_id = $2")
            .bind(body.version_id)
            .bind(secret_id)
            .fetch_optional(pool)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "rollback target lookup");
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"database error"}));
            }
        };
    if target_belongs.is_none() {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error":"version not found for this secret"}));
    }

    if let Err(e) =
        sqlx::query("UPDATE secrets SET current_version_id = $1, updated_at = now() WHERE id = $2")
            .bind(body.version_id)
            .bind(secret_id)
            .execute(pool)
            .await
    {
        warn!(error = %e, "rollback update");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }

    let audit_key = {
        let vault = state.vault.read().await;
        match vault.root_key() {
            Some(rk) => AuditHmacKey::derive_from_rk(rk),
            None => {
                return HttpResponse::Ok().json(serde_json::json!({"rolled_back": true}));
            }
        }
    };
    audit_action(
        pool,
        &audit_key,
        "secret.rollback",
        auth.0.workspace_id,
        Some(auth.0.token_id),
        Some(secret_id),
        &req,
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({"rolled_back": true}))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(put_secret)
        .service(get_secret)
        .service(list_secrets)
        .service(delete_secret)
        .service(list_versions)
        .service(rollback);
}
