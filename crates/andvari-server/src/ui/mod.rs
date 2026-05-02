//! Server-rendered web UI.
//!
//! UI handlers either render a template for an authenticated session, or
//! redirect via [`session::gate`] to `/login` (have-workspaces) or `/setup`
//! (no-workspaces, first run).

use actix_web::{HttpRequest, HttpResponse, Responder, get, http::header, web};
use askama::Template;

use crate::oidc::SessionContext;
use crate::state::AppState;

pub mod render;
pub mod session;
pub mod setup;

use render::render_html;

const CSS: &str = include_str!("assets/andvari.css");

/// Subset of session data exposed to templates — display name + initials +
/// the email used for the avatar fallback.
struct UserView<'a> {
    display_name: String,
    initials: String,
    email: &'a str,
}

impl<'a> UserView<'a> {
    fn from(ctx: &'a SessionContext) -> Self {
        let display_name = ctx
            .display_name
            .clone()
            .or_else(|| ctx.email.clone())
            .unwrap_or_else(|| "Operator".into());
        let initials = initials_from(&display_name);
        let email = ctx.email.as_deref().unwrap_or("");
        Self {
            display_name,
            initials,
            email,
        }
    }
}

fn initials_from(name: &str) -> String {
    let mut out = String::new();
    for part in name.split_whitespace().take(2) {
        if let Some(c) = part.chars().next() {
            out.push(c.to_ascii_uppercase());
        }
    }
    if out.is_empty() {
        out.push('A');
    }
    out
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate<'a> {
    active: &'a str,
    user_name: &'a str,
    user_initials: &'a str,
    user_email: &'a str,
    workspace_name: String,
    workspace_slug: String,
    vault_state: &'a str,
    vault_state_label: &'a str,
    secret_count: i64,
    token_count: i64,
    pending_approvals: i64,
}

#[derive(Template)]
#[template(path = "secrets.html")]
struct SecretsTemplate<'a> {
    active: &'a str,
    user_name: &'a str,
    user_initials: &'a str,
    workspace_name: String,
    workspace_slug: String,
}

#[derive(Template)]
#[template(path = "secret_detail.html")]
struct SecretDetailTemplate<'a> {
    active: &'a str,
    user_name: &'a str,
    user_initials: &'a str,
    workspace_name: String,
    workspace_slug: String,
    secret_key: String,
}

#[derive(Template)]
#[template(path = "tokens.html")]
struct TokensTemplate<'a> {
    active: &'a str,
    user_name: &'a str,
    user_initials: &'a str,
    workspace_name: String,
    workspace_slug: String,
}

#[derive(Template)]
#[template(path = "approvals.html")]
struct ApprovalsTemplate<'a> {
    active: &'a str,
    user_name: &'a str,
    user_initials: &'a str,
    workspace_name: String,
    workspace_slug: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTemplate<'a> {
    active: &'a str,
    user_name: &'a str,
    user_initials: &'a str,
    workspace_name: String,
    workspace_slug: String,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    oidc_enabled: bool,
    error: Option<&'a str>,
}

#[get("/assets/andvari.css")]
async fn css() -> impl Responder {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/css; charset=utf-8"))
        .body(CSS)
}

#[get("/login")]
async fn login(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    use actix_web::HttpMessage;

    if req.extensions().get::<SessionContext>().is_some() {
        return HttpResponse::Found()
            .append_header((header::LOCATION, "/"))
            .finish();
    }
    if session::needs_setup(&state).await {
        return HttpResponse::Found()
            .append_header((header::LOCATION, "/setup"))
            .finish();
    }
    render_html(LoginTemplate {
        oidc_enabled: state.oidc.is_some(),
        error: None,
    })
}

#[get("/")]
async fn dashboard(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let ctx = match session::gate(&state, &req).await {
        Ok(c) => c,
        Err(redirect) => return redirect,
    };
    let user = UserView::from(&ctx);
    let (workspace_name, workspace_slug) = first_workspace(&state).await;
    let secret_count = count(&state, "SELECT COUNT(*) FROM secret_versions").await;
    let token_count =
        count(&state, "SELECT COUNT(*) FROM service_tokens WHERE revoked_at IS NULL").await;
    let pending_approvals = count(
        &state,
        "SELECT COUNT(*) FROM approval_requests WHERE state = 'pending'",
    )
    .await;
    let sealed = state.vault.read().await.is_sealed();
    let (vault_state, vault_state_label) = if sealed {
        ("sealed", "Sealed")
    } else {
        ("unsealed", "Unsealed")
    };

    render_html(DashboardTemplate {
        active: "home",
        user_name: &user.display_name,
        user_initials: &user.initials,
        user_email: user.email,
        workspace_name,
        workspace_slug,
        vault_state,
        vault_state_label,
        secret_count,
        token_count,
        pending_approvals,
    })
}

#[get("/secrets")]
async fn secrets(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let ctx = match session::gate(&state, &req).await {
        Ok(c) => c,
        Err(redirect) => return redirect,
    };
    let user = UserView::from(&ctx);
    let (workspace_name, workspace_slug) = first_workspace(&state).await;
    render_html(SecretsTemplate {
        active: "secrets",
        user_name: &user.display_name,
        user_initials: &user.initials,
        workspace_name,
        workspace_slug,
    })
}

#[get("/secrets/{key}")]
async fn secret_detail(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let ctx = match session::gate(&state, &req).await {
        Ok(c) => c,
        Err(redirect) => return redirect,
    };
    let user = UserView::from(&ctx);
    let (workspace_name, workspace_slug) = first_workspace(&state).await;
    render_html(SecretDetailTemplate {
        active: "secrets",
        user_name: &user.display_name,
        user_initials: &user.initials,
        workspace_name,
        workspace_slug,
        secret_key: path.into_inner(),
    })
}

#[get("/tokens")]
async fn tokens(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let ctx = match session::gate(&state, &req).await {
        Ok(c) => c,
        Err(redirect) => return redirect,
    };
    let user = UserView::from(&ctx);
    let (workspace_name, workspace_slug) = first_workspace(&state).await;
    render_html(TokensTemplate {
        active: "tokens",
        user_name: &user.display_name,
        user_initials: &user.initials,
        workspace_name,
        workspace_slug,
    })
}

#[get("/approvals")]
async fn approvals(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let ctx = match session::gate(&state, &req).await {
        Ok(c) => c,
        Err(redirect) => return redirect,
    };
    let user = UserView::from(&ctx);
    let (workspace_name, workspace_slug) = first_workspace(&state).await;
    render_html(ApprovalsTemplate {
        active: "approvals",
        user_name: &user.display_name,
        user_initials: &user.initials,
        workspace_name,
        workspace_slug,
    })
}

#[get("/audit")]
async fn audit(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let ctx = match session::gate(&state, &req).await {
        Ok(c) => c,
        Err(redirect) => return redirect,
    };
    let user = UserView::from(&ctx);
    let (workspace_name, workspace_slug) = first_workspace(&state).await;
    render_html(AuditTemplate {
        active: "audit",
        user_name: &user.display_name,
        user_initials: &user.initials,
        workspace_name,
        workspace_slug,
    })
}

async fn first_workspace(state: &AppState) -> (String, String) {
    let Some(pool) = state.db.as_ref() else {
        return ("Andvari".into(), "default".into());
    };
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, slug FROM workspaces ORDER BY created_at ASC LIMIT 1")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    row.unwrap_or_else(|| ("Andvari".into(), "default".into()))
}

async fn count(state: &AppState, sql: &str) -> i64 {
    let Some(pool) = state.db.as_ref() else {
        return 0;
    };
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap_or(0)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(css)
        .service(login)
        .service(dashboard)
        .service(secrets)
        .service(secret_detail)
        .service(tokens)
        .service(approvals)
        .service(audit)
        .configure(setup::configure);
}
