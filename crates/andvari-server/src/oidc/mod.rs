//! Generic OIDC for human login.
//!
//! Configured server-side via environment variables and exposed via
//! `/v1/auth/oidc/login` + `/v1/auth/oidc/callback`. Pocket ID is the
//! canonical example IdP — anything OIDC-compliant works (Authentik,
//! Keycloak, ZITADEL, Google, GitHub).
//!
//! The flow:
//!
//! ```text
//! 1.  Browser  → GET  /v1/auth/oidc/login
//! 2.  Server   → 302  to {IdP authorize endpoint} (with PKCE + state + nonce)
//! 3.  Browser  → IdP login screen
//! 4.  IdP      → 302  to /v1/auth/oidc/callback?code=...&state=...
//! 5.  Server   → POST {IdP token endpoint} (with code + PKCE verifier)
//! 6.  IdP      → id_token + access_token
//! 7.  Server   → validate id_token (signature + iss + aud + nonce + exp)
//! 8.  Server   → upsert user, create session row, set session cookie
//! 9.  Browser  → 302 to home
//! ```

pub mod federation;
pub mod handlers;
pub mod provider;
pub mod sessions;

pub use provider::{OidcConfig, Provider, SharedProvider};
pub use sessions::SessionContext;
