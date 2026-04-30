//! Stateful Shamir share collector used during the unseal handshake.
//!
//! Each operator's `POST /v1/sys/unseal` submits one share. We accumulate
//! distinct shares (deduplicated by participant ID) until we have at least
//! `threshold`, at which point [`UnsealProgress::reconstruct`] returns the
//! Root Key.

use crate::crypto::{CryptoError, RootKey};
use crate::seal::shamir::{self, SHARE_LEN};

/// In-memory share accumulator.
#[derive(Debug)]
pub struct UnsealProgress {
    threshold: usize,
    shares: Vec<Vec<u8>>,
}

/// Result of submitting a single share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Share accepted. `received` distinct shares so far, threshold unchanged.
    Accepted { received: usize, threshold: usize },
    /// Share accepted and threshold has been met. Caller should call
    /// [`UnsealProgress::reconstruct`] now.
    Threshold { received: usize, threshold: usize },
    /// Share with this participant ID had already been submitted; ignored.
    Duplicate { received: usize, threshold: usize },
}

impl UnsealProgress {
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold,
            shares: Vec::with_capacity(threshold),
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn received(&self) -> usize {
        self.shares.len()
    }

    pub fn is_ready(&self) -> bool {
        self.shares.len() >= self.threshold
    }

    /// Submit a single share (raw bytes, not base64). Returns whether we now
    /// have enough material to reconstruct.
    pub fn submit(&mut self, share: Vec<u8>) -> Result<SubmitOutcome, CryptoError> {
        if share.len() != SHARE_LEN {
            return Err(CryptoError::InvalidEnvelope(
                "share has wrong length (expected 33 bytes)",
            ));
        }
        let pid = share[0];
        if pid == 0 {
            return Err(CryptoError::InvalidEnvelope(
                "share participant id 0 is reserved for the secret",
            ));
        }
        if self.shares.iter().any(|s| s[0] == pid) {
            return Ok(SubmitOutcome::Duplicate {
                received: self.shares.len(),
                threshold: self.threshold,
            });
        }
        self.shares.push(share);
        let received = self.shares.len();
        if received >= self.threshold {
            Ok(SubmitOutcome::Threshold {
                received,
                threshold: self.threshold,
            })
        } else {
            Ok(SubmitOutcome::Accepted {
                received,
                threshold: self.threshold,
            })
        }
    }

    /// Reconstruct the Root Key. Requires `received() >= threshold()`.
    pub fn reconstruct(&self) -> Result<RootKey, CryptoError> {
        if !self.is_ready() {
            return Err(CryptoError::InvalidEnvelope(
                "not enough shares to reconstruct root key",
            ));
        }
        shamir::combine_root_key(&self.shares[..self.threshold])
    }

    /// Drop all collected shares (e.g. after a successful unseal, or to abort).
    pub fn clear(&mut self) {
        // Zeroize each share's bytes before dropping the vec.
        use zeroize::Zeroize;
        for share in &mut self.shares {
            share.zeroize();
        }
        self.shares.clear();
    }
}

impl Drop for UnsealProgress {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::shamir::split_root_key;

    #[test]
    fn collects_then_reconstructs() {
        let rk = RootKey::from_bytes([3u8; 32]);
        let shares = split_root_key(&rk, 3, 5).unwrap();

        let mut progress = UnsealProgress::new(3);
        assert!(matches!(
            progress.submit(shares[0].clone()).unwrap(),
            SubmitOutcome::Accepted {
                received: 1,
                threshold: 3
            }
        ));
        assert!(matches!(
            progress.submit(shares[1].clone()).unwrap(),
            SubmitOutcome::Accepted {
                received: 2,
                threshold: 3
            }
        ));
        assert!(matches!(
            progress.submit(shares[2].clone()).unwrap(),
            SubmitOutcome::Threshold {
                received: 3,
                threshold: 3
            }
        ));
        assert!(progress.is_ready());

        let recovered = progress.reconstruct().unwrap();
        assert_eq!(recovered.as_bytes(), rk.as_bytes());
    }

    #[test]
    fn duplicate_share_ignored() {
        let rk = RootKey::generate();
        let shares = split_root_key(&rk, 3, 5).unwrap();
        let mut progress = UnsealProgress::new(3);

        progress.submit(shares[0].clone()).unwrap();
        let dup = progress.submit(shares[0].clone()).unwrap();
        assert!(matches!(dup, SubmitOutcome::Duplicate { received: 1, .. }));
        assert_eq!(progress.received(), 1);
    }

    #[test]
    fn structurally_invalid_share_rejected() {
        let mut progress = UnsealProgress::new(3);
        // Wrong length.
        assert!(progress.submit(vec![1u8; 10]).is_err());
        // Zero pid.
        assert!(progress.submit(vec![0u8; SHARE_LEN]).is_err());
    }

    #[test]
    fn reconstruct_before_threshold_errors() {
        let rk = RootKey::generate();
        let shares = split_root_key(&rk, 3, 5).unwrap();
        let mut progress = UnsealProgress::new(3);
        progress.submit(shares[0].clone()).unwrap();
        progress.submit(shares[1].clone()).unwrap();
        assert!(progress.reconstruct().is_err());
    }

    #[test]
    fn clear_drops_shares() {
        let rk = RootKey::generate();
        let shares = split_root_key(&rk, 2, 3).unwrap();
        let mut progress = UnsealProgress::new(2);
        progress.submit(shares[0].clone()).unwrap();
        progress.clear();
        assert_eq!(progress.received(), 0);
    }
}
