//! Cross-cutting request middleware.

use actix_web::body::{BoxBody, EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{Error, HttpResponse, web};

use crate::state::AppState;

/// Reject every non-sys request with `503 Service Unavailable` while the
/// vault is sealed. `/v1/sys/*` always passes through so operators can
/// interact with health and unseal endpoints.
pub async fn require_unsealed<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    B: MessageBody + 'static,
{
    if req.path().starts_with("/v1/sys/") {
        return next.call(req).await.map(|r| r.map_into_left_body());
    }

    let state = req.app_data::<web::Data<AppState>>().cloned();
    if let Some(state) = state {
        let sealed = state.vault.read().await.is_sealed();
        if sealed {
            let resp = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "vault is sealed",
            }));
            return Ok(req.into_response(resp).map_into_right_body());
        }
    }

    next.call(req).await.map(|r| r.map_into_left_body())
}
