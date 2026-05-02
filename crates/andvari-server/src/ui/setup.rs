//! First-run bootstrap UI: `/setup`.
//!
//! Mirrors `/v1/init` but server-rendered. GET shows a form when no workspaces
//! exist (otherwise redirects to `/login`). POST creates the first workspace +
//! a fully-scoped bootstrap token, then renders the token exactly once.

use actix_web::http::header;
use actix_web::{HttpResponse, Responder, get, post, web};
use askama::Template;
use serde::Deserialize;
use tracing::warn;

use andvari_core::crypto::WorkspaceKek;

use crate::auth::scope::{Op, Scopes};
use crate::auth::token;
use crate::state::AppState;
use crate::ui::render::render_html;

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupTemplate<'a> {
    error: Option<&'a str>,
    sealed: bool,
}

#[derive(Template)]
#[template(path = "setup_done.html")]
struct SetupDoneTemplate<'a> {
    workspace_slug: &'a str,
    workspace_name: &'a str,
    token: &'a str,
}

#[derive(Deserialize)]
pub struct SetupForm {
    pub slug: String,
    pub name: String,
}

#[get("/setup")]
async fn setup_get(state: web::Data<AppState>) -> impl Responder {
    if !crate::ui::session::needs_setup(&state).await {
        return HttpResponse::Found()
            .append_header((header::LOCATION, "/login"))
            .finish();
    }
    let sealed = state.vault.read().await.is_sealed();
    render_html(SetupTemplate {
        error: None,
        sealed,
    })
}

#[post("/setup")]
async fn setup_post(state: web::Data<AppState>, form: web::Form<SetupForm>) -> impl Responder {
    if !crate::ui::session::needs_setup(&state).await {
        return HttpResponse::Found()
            .append_header((header::LOCATION, "/login"))
            .finish();
    }

    let Some(pool) = state.db.as_ref() else {
        return render_html(SetupTemplate {
            error: Some("database unavailable"),
            sealed: false,
        });
    };

    let vault = state.vault.read().await;
    let Some(rk) = vault.root_key().cloned() else {
        return render_html(SetupTemplate {
            error: Some("vault is sealed — unseal first"),
            sealed: true,
        });
    };
    drop(vault);

    let slug = form.slug.trim().to_lowercase();
    let name = form.name.trim().to_string();

    if !is_valid_slug(&slug) {
        return render_html(SetupTemplate {
            error: Some("slug must be 2–64 chars: lowercase letters, digits, hyphens"),
            sealed: false,
        });
    }
    if name.is_empty() {
        return render_html(SetupTemplate {
            error: Some("workspace name is required"),
            sealed: false,
        });
    }

    let kek = WorkspaceKek::generate();
    let aad = format!("ws:{slug}");
    let wrapped = match kek.wrap(&rk, aad.as_bytes()) {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "setup: KEK wrap failed");
            return render_html(SetupTemplate {
                error: Some("internal crypto error"),
                sealed: false,
            });
        }
    };

    let workspace_id: uuid::Uuid = match sqlx::query_scalar(
        r#"
        INSERT INTO workspaces (slug, name, kek_wrapped, kek_nonce)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(&slug)
    .bind(&name)
    .bind(&wrapped.ciphertext)
    .bind(&wrapped.nonce[..])
    .fetch_one(pool)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "setup: workspace insert failed");
            return render_html(SetupTemplate {
                error: Some("database error creating workspace"),
                sealed: false,
            });
        }
    };

    let scopes = Scopes {
        projects: vec!["*".into()],
        envs: vec!["*".into()],
        ops: vec![Op::Read, Op::Write, Op::Lease],
    };
    let created = match token::create(pool, workspace_id, &slug, "bootstrap", &scopes, None).await {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "setup: token creation failed");
            return render_html(SetupTemplate {
                error: Some("could not mint bootstrap token"),
                sealed: false,
            });
        }
    };

    render_html(SetupDoneTemplate {
        workspace_slug: &slug,
        workspace_name: &name,
        token: &created.raw,
    })
}

fn is_valid_slug(s: &str) -> bool {
    let len_ok = (2..=64).contains(&s.len());
    let chars_ok = s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    len_ok && chars_ok && !s.starts_with('-') && !s.ends_with('-')
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(setup_get).service(setup_post);
}
