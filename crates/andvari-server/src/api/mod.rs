//! HTTP API endpoints (everything outside `/v1/sys/*`).

pub mod approvals;
pub mod audit_view;
pub mod environments;
pub mod init;
pub mod projects;
pub mod secrets;
pub mod tokens;
pub mod workspaces;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    init::configure(cfg);
    workspaces::configure(cfg);
    projects::configure(cfg);
    environments::configure(cfg);
    approvals::configure(cfg);
    tokens::configure(cfg);
    secrets::configure(cfg);
    audit_view::configure(cfg);
    crate::webhooks::configure(cfg);
    crate::dynamic::api::configure(cfg);
}
