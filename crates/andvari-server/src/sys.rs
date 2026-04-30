//! `/v1/sys/*` endpoints — the small set of routes that work even when the
//! vault is sealed.

use actix_web::{HttpResponse, Responder, get, post, web};

use crate::state::SharedVaultState;

#[get("/v1/sys/health")]
pub async fn health(state: web::Data<SharedVaultState>) -> impl Responder {
    let guard = state.read().await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "sealed": guard.is_sealed(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[post("/v1/sys/seal")]
pub async fn seal(state: web::Data<SharedVaultState>) -> impl Responder {
    // TODO: require an admin/owner identity. Auth lands in a later slice.
    let mut guard = state.write().await;
    guard.seal();
    HttpResponse::Ok().json(serde_json::json!({ "sealed": true }))
}

#[post("/v1/sys/unseal")]
pub async fn unseal() -> impl Responder {
    // Env-var unseal happens at startup; Shamir/KMS unseal modes land in
    // follow-up slices. Until then, this endpoint is a polite no-op so the
    // route exists in the API surface.
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": "unseal-via-API not yet supported",
        "hint": "set ANDVARI_ROOT_KEY at boot for env-var unseal",
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(health).service(seal).service(unseal);
}
