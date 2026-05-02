//! UI session helpers.
//!
//! Web pages that require an authenticated browser session use [`gate`] to
//! short-circuit to the right place when no session is present:
//!
//! - **No workspaces yet** → `/setup` (first-run bootstrap)
//! - **Workspaces exist, no session** → `/login`
//!
//! Returning `Err(HttpResponse)` from [`gate`] is the redirect; `Ok` is the
//! authenticated [`SessionContext`].

use actix_web::http::header;
use actix_web::{HttpMessage, HttpRequest, HttpResponse};

use crate::oidc::SessionContext;
use crate::state::AppState;

/// Resolve a session for a UI handler. Redirects to `/setup` if uninitialized,
/// `/login` otherwise.
pub async fn gate(state: &AppState, req: &HttpRequest) -> Result<SessionContext, HttpResponse> {
    if let Some(ctx) = req.extensions().get::<SessionContext>().cloned() {
        return Ok(ctx);
    }
    let target = if needs_setup(state).await {
        "/setup"
    } else {
        "/login"
    };
    Err(HttpResponse::Found()
        .append_header((header::LOCATION, target))
        .finish())
}

/// True when no workspaces exist in the database (or the DB is unreachable —
/// in which case the operator clearly has bigger problems and `/setup` is
/// the right destination).
pub async fn needs_setup(state: &AppState) -> bool {
    let Some(pool) = state.db.as_ref() else {
        return true;
    };
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    count == 0
}
