//! Process-wide vault state and unseal-handshake bookkeeping.

use std::sync::Arc;

use andvari_core::VaultState;
use andvari_core::crypto::{CryptoError, RootKey};
use andvari_core::seal::UnsealProgress;
use tokio::sync::RwLock;

pub type SharedVaultState = Arc<RwLock<VaultState>>;
pub type SharedUnseal = Arc<RwLock<Option<UnsealProgress>>>;

/// Bundle of mutable state held in `app_data` for every request.
#[derive(Clone)]
pub struct AppState {
    pub vault: SharedVaultState,
    pub unseal: SharedUnseal,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(RwLock::new(VaultState::sealed())),
            unseal: Arc::new(RwLock::new(None)),
        }
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
