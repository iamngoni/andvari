//! Server-rendered web UI.

use actix_web::{HttpResponse, Responder, get, http::header, web};
use askama::Template;

const CSS: &str = include_str!("assets/andvari.css");

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate<'a> {
    active: &'a str,
}

#[derive(Template)]
#[template(path = "secrets.html")]
struct SecretsTemplate<'a> {
    active: &'a str,
}

#[derive(Template)]
#[template(path = "secret_detail.html")]
struct SecretDetailTemplate<'a> {
    active: &'a str,
    secret_key: String,
}

#[derive(Template)]
#[template(path = "tokens.html")]
struct TokensTemplate<'a> {
    active: &'a str,
}

#[derive(Template)]
#[template(path = "approvals.html")]
struct ApprovalsTemplate<'a> {
    active: &'a str,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

#[get("/assets/andvari.css")]
async fn css() -> impl Responder {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/css; charset=utf-8"))
        .body(CSS)
}

#[get("/login")]
async fn login() -> impl Responder {
    render(LoginTemplate)
}

#[get("/")]
async fn dashboard() -> impl Responder {
    render(DashboardTemplate { active: "home" })
}

#[get("/secrets")]
async fn secrets() -> impl Responder {
    render(SecretsTemplate { active: "secrets" })
}

#[get("/secrets/{key}")]
async fn secret_detail(path: web::Path<String>) -> impl Responder {
    render(SecretDetailTemplate {
        active: "secrets",
        secret_key: path.into_inner(),
    })
}

#[get("/tokens")]
async fn tokens() -> impl Responder {
    render(TokensTemplate { active: "tokens" })
}

#[get("/approvals")]
async fn approvals() -> impl Responder {
    render(ApprovalsTemplate {
        active: "approvals",
    })
}

fn render<T: Template>(template: T) -> HttpResponse {
    match template.render() {
        Ok(html) => HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
            .body(html),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("template render failed: {e}"),
        })),
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(css)
        .service(login)
        .service(dashboard)
        .service(secrets)
        .service(secret_detail)
        .service(tokens)
        .service(approvals);
}
