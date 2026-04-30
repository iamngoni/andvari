//! `POST /v1/init` — bootstrap the very first workspace.
//!
//! Reject if any workspace already exists. Generates a fresh per-workspace
//! KEK (wrapped under the Root Key), persists the workspace, and mints a
//! single service token with full scope so the operator has somewhere to
//! authenticate from. The raw token is returned exactly once.

use actix_web::{HttpResponse, Responder, post, web};
use andvari_core::crypto::WorkspaceKek;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::auth::scope::{Op, Scopes};
use crate::auth::token;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct InitRequest {
    pub slug: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct InitResponse {
    pub workspace_id: uuid::Uuid,
    pub workspace_slug: String,
    pub token: String,
}

#[post("/v1/init")]
pub async fn init(state: web::Data<AppState>, body: web::Json<InitRequest>) -> impl Responder {
    let Some(pool) = state.db.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "database unavailable",
        }));
    };

    // Reject if any workspace exists.
    let count: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(pool)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "init: count workspaces failed");
            return HttpResponse::InternalServerError().json(error_json("database error"));
        }
    };
    if count > 0 {
        return HttpResponse::Conflict()
            .json(error_json("vault already initialized; /v1/init is closed"));
    }

    // Need an unsealed Root Key to wrap the new workspace KEK.
    let vault = state.vault.read().await;
    let Some(rk) = vault.root_key().cloned() else {
        return HttpResponse::ServiceUnavailable().json(error_json("vault is sealed"));
    };
    drop(vault);

    if !is_valid_slug(&body.slug) {
        return HttpResponse::BadRequest().json(error_json(
            "slug must be lowercase alphanumeric + hyphens, 2-64 chars",
        ));
    }

    let kek = WorkspaceKek::generate();
    let aad = format!("ws:{}", body.slug);
    let wrapped = match kek.wrap(&rk, aad.as_bytes()) {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "init: KEK wrap failed");
            return HttpResponse::InternalServerError().json(error_json("crypto error"));
        }
    };

    // Persist the workspace.
    let workspace_id: uuid::Uuid = match sqlx::query_scalar(
        r#"
        INSERT INTO workspaces (slug, name, kek_wrapped, kek_nonce)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(&body.slug)
    .bind(&body.name)
    .bind(&wrapped.ciphertext)
    .bind(&wrapped.nonce[..])
    .fetch_one(pool)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "init: workspace insert failed");
            return HttpResponse::InternalServerError().json(error_json("database error"));
        }
    };

    // Mint a fully-scoped bootstrap token.
    let scopes = Scopes {
        projects: vec!["*".into()],
        envs: vec!["*".into()],
        ops: vec![Op::Read, Op::Write, Op::Lease],
    };
    let created = match token::create(pool, workspace_id, &body.slug, "bootstrap", &scopes, None)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "init: token creation failed");
            return HttpResponse::InternalServerError().json(error_json("token creation error"));
        }
    };

    HttpResponse::Created().json(InitResponse {
        workspace_id,
        workspace_slug: body.slug.clone(),
        token: created.raw,
    })
}

fn error_json(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": msg })
}

fn is_valid_slug(s: &str) -> bool {
    let len_ok = (2..=64).contains(&s.len());
    let chars_ok = s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    len_ok && chars_ok && !s.starts_with('-') && !s.ends_with('-')
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(init);
}

#[cfg(test)]
mod tests {
    use super::is_valid_slug;

    #[test]
    fn slug_validation() {
        assert!(is_valid_slug("spirit-finder"));
        assert!(is_valid_slug("ab"));
        assert!(is_valid_slug("ws-2026"));
        assert!(!is_valid_slug("a"));
        assert!(!is_valid_slug("-leading"));
        assert!(!is_valid_slug("trailing-"));
        assert!(!is_valid_slug("UPPER"));
        assert!(!is_valid_slug("under_score"));
        assert!(!is_valid_slug(""));
    }
}
