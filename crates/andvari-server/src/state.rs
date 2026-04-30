//! Process-wide vault state (sealed / unsealed) with env-var bootstrap.

use std::sync::Arc;

use andvari_core::VaultState;
use andvari_core::crypto::{CryptoError, RootKey};
use tokio::sync::RwLock;

pub type SharedVaultState = Arc<RwLock<VaultState>>;

/// Build a fresh shared state, sealed by default.
pub fn shared() -> SharedVaultState {
    Arc::new(RwLock::new(VaultState::sealed()))
}

/// Whether the env-var unseal mode is configured (env var present and decodes).
///
/// If `ANDVARI_ROOT_KEY` is set, attempt to decode it and unseal `state`
/// in place. Returns `true` if we transitioned the vault to unsealed,
/// `false` if the env var was absent. Decode/length errors propagate so
/// misconfiguration fails loud.
pub async fn unseal_from_env(state: &SharedVaultState) -> Result<bool, CryptoError> {
    const VAR: &str = "ANDVARI_ROOT_KEY";

    if std::env::var(VAR).is_err() {
        return Ok(false);
    }
    let rk = RootKey::from_base64_env(VAR)?;
    let mut guard = state.write().await;
    *guard = VaultState::unsealed(rk);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_env_var_keeps_state_sealed() {
        let var = "ANDVARI_ROOT_KEY";
        // SAFETY: tests touching env vars must serialize; we explicitly clear here.
        unsafe { std::env::remove_var(var) };
        let state = shared();
        assert!(!unseal_from_env(&state).await.unwrap());
        assert!(state.read().await.is_sealed());
    }

    #[tokio::test]
    async fn env_var_unseals() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let var = "ANDVARI_ROOT_KEY";
        let key_b64 = STANDARD.encode([7u8; 32]);
        unsafe { std::env::set_var(var, key_b64) };

        let state = shared();
        assert!(unseal_from_env(&state).await.unwrap());
        assert!(!state.read().await.is_sealed());

        unsafe { std::env::remove_var(var) };
    }
}
