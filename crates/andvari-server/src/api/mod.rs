//! HTTP API endpoints (everything outside `/v1/sys/*`).

pub mod environments;
pub mod init;
pub mod projects;
pub mod tokens;
pub mod workspaces;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    init::configure(cfg);
    workspaces::configure(cfg);
    projects::configure(cfg);
    environments::configure(cfg);
    tokens::configure(cfg);
}
