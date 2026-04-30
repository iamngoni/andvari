//! Process-wide vault state and unseal-handshake bookkeeping.

use std::sync::Arc;

use andvari_core::VaultState;
use andvari_core::crypto::{CryptoError, RootKey};
use andvari_core::seal::UnsealProgress;
use andvari_core::seal::kms::{KmsBackend, KmsError};
use tokio::sync::RwLock;

use crate::kms::VaultTransit;

pub type SharedVaultState = Arc<RwLock<VaultState>>;
pub type SharedUnseal = Arc<RwLock<Option<UnsealProgress>>>;

/// Bundle of mutable state held in `app_data` for every request.
#[derive(Clone)]
pub struct AppState {
    pub vault: SharedVaultState,
    pub unseal: SharedUnseal,
    pub db: Option<sqlx::PgPool>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(RwLock::new(VaultState::sealed())),
            unseal: Arc::new(RwLock::new(None)),
            db: None,
        }
    }

    pub fn with_db(mut self, db: sqlx::PgPool) -> Self {
        self.db = Some(db);
        self
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to unseal from `ANDVARI_ROOT_KEY` if set. Returns `true` if we
/// transitioned to unsealed.
pub async fn unseal_from_env(vault: &SharedVaultState) -> Result<bool, CryptoError> {
    const VAR: &str = "ANDVARI_ROOT_KEY";
    if std::env::var(VAR).is_err() {
        return Ok(false);
    }
    let rk = RootKey::from_base64_env(VAR)?;
    let mut guard = vault.write().await;
    *guard = VaultState::unsealed(rk);
    Ok(true)
}

/// Read `ANDVARI_SHAMIR_THRESHOLD` from the environment, validating shape.
/// Returns `None` if unset, an error if malformed.
pub fn shamir_threshold_from_env() -> Result<Option<usize>, CryptoError> {
    const VAR: &str = "ANDVARI_SHAMIR_THRESHOLD";
    let raw = match std::env::var(VAR) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let threshold: usize = raw
        .parse()
        .map_err(|_| CryptoError::InvalidEnvelope("ANDVARI_SHAMIR_THRESHOLD must be an integer"))?;
    if threshold < 2 {
        return Err(CryptoError::InvalidEnvelope(
            "ANDVARI_SHAMIR_THRESHOLD must be >= 2",
        ));
    }
    Ok(Some(threshold))
}

/// Install a fresh [`UnsealProgress`] keyed off `threshold` if the vault is
/// still sealed. Pass `None` to skip; pass `Some(threshold)` to enable
/// Shamir-mode unseal.
pub async fn init_shamir_progress(
    state: &AppState,
    threshold: Option<usize>,
) -> Result<(), CryptoError> {
    let Some(threshold) = threshold else {
        return Ok(());
    };
    if threshold < 2 {
        return Err(CryptoError::InvalidEnvelope(
            "shamir threshold must be >= 2",
        ));
    }
    if !state.vault.read().await.is_sealed() {
        return Ok(());
    }
    *state.unseal.write().await = Some(UnsealProgress::new(threshold));
    Ok(())
}

/// Configuration for KMS-backed unseal, parsed once at startup from env.
#[derive(Debug, Clone)]
pub struct KmsUnsealConfig {
    pub provider: String,
    pub vault_addr: Option<String>,
    pub vault_token: Option<String>,
    pub vault_key: Option<String>,
    /// Either the wrapped RK bytes inline, or a path to read them from.
    pub wrapped_rk_path: Option<String>,
}

impl KmsUnsealConfig {
    /// Read `ANDVARI_KMS_*` from the environment. Returns `None` if no
    /// provider is configured.
    pub fn from_env() -> Option<Self> {
        let provider = std::env::var("ANDVARI_KMS_PROVIDER").ok()?;
        Some(Self {
            provider,
            vault_addr: std::env::var("ANDVARI_KMS_VAULT_ADDR").ok(),
            vault_token: std::env::var("ANDVARI_KMS_VAULT_TOKEN").ok(),
            vault_key: std::env::var("ANDVARI_KMS_VAULT_KEY").ok(),
            wrapped_rk_path: std::env::var("ANDVARI_KMS_WRAPPED_RK_PATH").ok(),
        })
    }
}

/// Attempt to unseal the vault from a KMS-managed wrapped Root Key.
pub async fn unseal_from_kms(
    vault: &SharedVaultState,
    cfg: &KmsUnsealConfig,
) -> Result<bool, KmsError> {
    let backend: Box<dyn KmsBackend> = match cfg.provider.as_str() {
        "vault-transit" => {
            let addr = cfg.vault_addr.as_deref().ok_or_else(|| {
                KmsError::Transport("ANDVARI_KMS_VAULT_ADDR is required for vault-transit".into())
            })?;
            let token = cfg.vault_token.as_deref().ok_or_else(|| {
                KmsError::Transport("ANDVARI_KMS_VAULT_TOKEN is required for vault-transit".into())
            })?;
            let key = cfg.vault_key.as_deref().ok_or_else(|| {
                KmsError::Transport("ANDVARI_KMS_VAULT_KEY is required for vault-transit".into())
            })?;
            Box::new(VaultTransit::new(addr, token, key)?)
        }
        other => {
            return Err(KmsError::Transport(format!(
                "unknown ANDVARI_KMS_PROVIDER: {other}"
            )));
        }
    };

    let path = cfg
        .wrapped_rk_path
        .as_deref()
        .ok_or_else(|| KmsError::Transport("ANDVARI_KMS_WRAPPED_RK_PATH is required".into()))?;
    let wrapped = std::fs::read(path)
        .map_err(|e| KmsError::Transport(format!("read wrapped RK from {path}: {e}")))?;

    let rk = backend.unwrap(&wrapped).await?;
    let mut guard = vault.write().await;
    *guard = VaultState::unsealed(rk);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_env_var_keeps_state_sealed() {
        unsafe { std::env::remove_var("ANDVARI_ROOT_KEY") };
        let app = AppState::new();
        assert!(!unseal_from_env(&app.vault).await.unwrap());
        assert!(app.vault.read().await.is_sealed());
    }

    #[tokio::test]
    async fn env_var_unseals() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let var = "ANDVARI_ROOT_KEY";
        let key_b64 = STANDARD.encode([7u8; 32]);
        unsafe { std::env::set_var(var, key_b64) };

        let app = AppState::new();
        assert!(unseal_from_env(&app.vault).await.unwrap());
        assert!(!app.vault.read().await.is_sealed());

        unsafe { std::env::remove_var(var) };
    }

    #[tokio::test]
    async fn shamir_progress_initialized_when_threshold_set() {
        let app = AppState::new();
        init_shamir_progress(&app, Some(3)).await.unwrap();
        let progress = app.unseal.read().await;
        assert!(progress.is_some());
        assert_eq!(progress.as_ref().unwrap().threshold(), 3);
    }

    #[tokio::test]
    async fn shamir_progress_not_initialized_without_threshold() {
        let app = AppState::new();
        init_shamir_progress(&app, None).await.unwrap();
        assert!(app.unseal.read().await.is_none());
    }

    #[tokio::test]
    async fn shamir_progress_skipped_when_already_unsealed() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let app = AppState::new();
        // Manually unseal first.
        let rk = andvari_core::crypto::RootKey::from_base64(&STANDARD.encode([5u8; 32])).unwrap();
        *app.vault.write().await = andvari_core::VaultState::unsealed(rk);
        init_shamir_progress(&app, Some(3)).await.unwrap();
        // Should NOT have created a progress because the vault is already unsealed.
        assert!(app.unseal.read().await.is_none());
    }
}
