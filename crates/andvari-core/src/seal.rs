//! Seal/unseal state machine.
//!
//! The vault boots in [`VaultState::Sealed`] — no Root Key in memory. Every
//! non-sys endpoint must reject requests until the vault transitions to
//! [`VaultState::Unsealed`]. Restarting the process re-seals.
//!
//! The only thing this module owns is the `Sealed | Unsealed(Arc<RootKey>)`
//! enum and its lifecycle. Each unseal *mode* (env, Shamir, KMS) is
//! implemented separately; they all converge on this enum once the RK has
//! been reconstructed.

use std::sync::Arc;

use crate::crypto::RootKey;

/// Current seal state of the vault.
pub enum VaultState {
    /// No Root Key in memory. The API rejects everything except a small set
    /// of system endpoints (health, unseal).
    Sealed,
    /// Root Key reconstructed and held in memory. Workspaces can be loaded,
    /// secrets can be read and written.
    Unsealed(Arc<RootKey>),
}

impl VaultState {
    /// Construct a fresh sealed state. The vault always starts here.
    pub const fn sealed() -> Self {
        Self::Sealed
    }

    /// Transition into the unsealed state with the supplied Root Key.
    pub fn unsealed(rk: RootKey) -> Self {
        Self::Unsealed(Arc::new(rk))
    }

    /// Whether the vault is currently sealed.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed)
    }

    /// Borrow the Root Key when unsealed. Returns `None` while sealed.
    pub fn root_key(&self) -> Option<&Arc<RootKey>> {
        match self {
            Self::Unsealed(rk) => Some(rk),
            Self::Sealed => None,
        }
    }

    /// Re-seal in place. Drops the [`Arc<RootKey>`] held by this state; the
    /// underlying [`RootKey`] zeroizes itself when the last reference drops
    /// (in practice, when in-flight requests using it return).
    pub fn seal(&mut self) {
        *self = Self::Sealed;
    }
}

impl Default for VaultState {
    fn default() -> Self {
        Self::sealed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_sealed() {
        let v = VaultState::sealed();
        assert!(v.is_sealed());
        assert!(v.root_key().is_none());
    }

    #[test]
    fn unseal_transition() {
        let v = VaultState::unsealed(RootKey::generate());
        assert!(!v.is_sealed());
        assert!(v.root_key().is_some());
    }

    #[test]
    fn re_seal_drops_root_key() {
        let mut v = VaultState::unsealed(RootKey::generate());
        let weak = Arc::downgrade(v.root_key().unwrap());
        assert_eq!(weak.strong_count(), 1);
        v.seal();
        assert!(v.is_sealed());
        // After seal(), the strong count goes to 0 — the RootKey was dropped
        // (and ZeroizeOnDrop ran). A weak ref upgrade now returns None.
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn default_is_sealed() {
        let v = VaultState::default();
        assert!(v.is_sealed());
    }
}
