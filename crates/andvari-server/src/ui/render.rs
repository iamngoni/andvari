//! Tiny shared helper: render an Askama template into an `HttpResponse`.

use actix_web::{HttpResponse, http::header};
use askama::Template;

#[derive(Debug)]
pub struct HtmlError(pub String);

pub fn render_html<T: Template>(template: T) -> HttpResponse {
    match template.render() {
        Ok(html) => HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
            .body(html),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("template render failed: {e}"),
        })),
    }
}
