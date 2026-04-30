//! Authentication: service tokens, OIDC sessions, and the Identity that
//! every authenticated request carries through `req.extensions()`.
//!
//! Service tokens are the primary auth mechanism for non-human callers
//! (services, CLIs, the Rust SDK). Web sessions land later when OIDC ships.

#![allow(dead_code)] // wired into route handlers in the workspaces/secrets slices

pub mod middleware;
pub mod scope;
pub mod token;

pub use middleware::{RequireToken, resolve_identity};
pub use scope::{Op, Scopes};
pub use token::{TokenContext, TokenError};
