//! OIDC provider — discovery + per-request login state.
//!
//! Loaded once at server startup from `ANDVARI_OIDC_*` env vars. Discovery
//! (the `/.well-known/openid-configuration` fetch) happens at boot; JWKS
//! caching is handled by the `openidconnect` crate.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("oidc transport: {0}")]
    Transport(String),

    #[error("oidc bad config: {0}")]
    BadConfig(&'static str),
}

/// OIDC server-side configuration. All four fields must be set, or the
/// server boots without OIDC enabled.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_url: String,
    pub default_workspace: Option<String>,
    pub default_role: String,
}

impl OidcConfig {
    pub fn from_env() -> Option<Self> {
        // Treat empty strings as unset — docker-compose default-expansion
        // (`${VAR:-}`) populates env vars with empty strings, and we don't
        // want that to count as "OIDC configured".
        let issuer = non_empty("ANDVARI_OIDC_ISSUER")?;
        let client_id = non_empty("ANDVARI_OIDC_CLIENT_ID")?;
        let redirect_url = non_empty("ANDVARI_OIDC_REDIRECT_URL")?;
        let client_secret = non_empty("ANDVARI_OIDC_CLIENT_SECRET");
        let default_workspace = non_empty("ANDVARI_OIDC_DEFAULT_WORKSPACE");
        let default_role =
            non_empty("ANDVARI_OIDC_DEFAULT_ROLE").unwrap_or_else(|| "reader".to_string());
        Some(Self {
            issuer,
            client_id,
            client_secret,
            redirect_url,
            default_workspace,
            default_role,
        })
    }
}

fn non_empty(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// Pre-callback state — what the server needs to remember between issuing
/// the redirect and receiving the callback. Keyed by the random state
/// string we placed in the redirect URL.
pub struct PendingLogin {
    pub pkce_verifier: PkceCodeVerifier,
    pub nonce: Nonce,
    pub created_at: Instant,
}

/// OIDC provider — wraps the openidconnect client + a small in-memory
/// pending-login cache for the auth-code flow's transient state.
pub struct Provider {
    pub client: CoreClient,
    pub default_workspace: Option<String>,
    pub default_role: String,
    pending: Mutex<HashMap<String, PendingLogin>>,
}

impl Provider {
    /// Discover the OIDC metadata and build a client.
    pub async fn discover(config: &OidcConfig) -> Result<Self, OidcError> {
        let issuer = IssuerUrl::new(config.issuer.clone())
            .map_err(|_| OidcError::BadConfig("invalid issuer URL"))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, async_http_client)
            .await
            .map_err(|e| OidcError::Transport(e.to_string()))?;

        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(config.client_id.clone()),
            config.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_url.clone())
                .map_err(|_| OidcError::BadConfig("invalid redirect URL"))?,
        );

        Ok(Self {
            client,
            default_workspace: config.default_workspace.clone(),
            default_role: config.default_role.clone(),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Stash a pending-login record. Called from `/v1/auth/oidc/login`.
    pub async fn record_pending(&self, state: String, login: PendingLogin) {
        let mut guard = self.pending.lock().await;
        // Cheap GC — drop entries older than 10 minutes.
        guard.retain(|_, v| v.created_at.elapsed() < Duration::from_secs(600));
        guard.insert(state, login);
    }

    /// Take a pending-login record. Called from `/v1/auth/oidc/callback`.
    pub async fn take_pending(&self, state: &str) -> Option<PendingLogin> {
        self.pending.lock().await.remove(state)
    }
}

pub type SharedProvider = Arc<Provider>;
