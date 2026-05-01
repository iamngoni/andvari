//! Authentication middleware.
//!
//! Resolves an `Authorization: Bearer andv_...` header to a [`TokenContext`]
//! and places it in `req.extensions()`. Does **not** enforce auth presence —
//! that is the route's responsibility (so `/v1/sys/*` and OIDC bootstrap
//! routes can stay open). Routes that require auth use the
//! [`RequireToken`] extractor.

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, web};
use std::future::{Ready, ready};

use crate::auth::token::{self, TokenContext};
use crate::oidc::SessionContext;
use crate::state::AppState;

/// Try to authenticate the request. Sets [`TokenContext`] in extensions on
/// success; on failure the request continues (the route decides what to do).
pub async fn resolve_identity<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    if let Some(raw) = bearer_token(&req) {
        if let Some(state) = req.app_data::<web::Data<AppState>>().cloned() {
            if let Some(pool) = state.db.as_ref() {
                match token::validate(pool, raw).await {
                    Ok(ctx) => {
                        crate::metrics::record_auth_event("token", "ok");
                        req.extensions_mut().insert(ctx);
                    }
                    Err(_) => {
                        crate::metrics::record_auth_event("token", "rejected");
                    }
                }
            }
        }
    }
    next.call(req).await
}

fn bearer_token(req: &ServiceRequest) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim())
}

/// Extractor for routes that **require** an authenticated token. Returns
/// `401 Unauthorized` if no [`TokenContext`] is present.
pub struct RequireToken(pub TokenContext);

impl FromRequest for RequireToken {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let ctx = req.extensions().get::<TokenContext>().cloned();
        ready(match ctx {
            Some(ctx) => Ok(RequireToken(ctx)),
            None => Err(actix_web::error::InternalError::from_response(
                "no token",
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "authentication required",
                })),
            )
            .into()),
        })
    }
}

/// Extractor for routes that require an authenticated human session.
pub struct RequireUser(pub SessionContext);

impl FromRequest for RequireUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let ctx = req.extensions().get::<SessionContext>().cloned();
        ready(match ctx {
            Some(ctx) => Ok(RequireUser(ctx)),
            None => Err(actix_web::error::InternalError::from_response(
                "no session",
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "human login required",
                })),
            )
            .into()),
        })
    }
}
