//! Certificate pin matching shared by every platform's `PinnedServerVerifier`
//! (Linux, Windows, Android), so the multi-pin comparison logic that backs
//! the dual-pin certificate-rotation workflow exists in exactly one place.

use constant_time_eq::constant_time_eq;
use sha2::{Digest, Sha256};

/// Returns `true` if `cert_der`'s SHA-256 digest matches any entry in
/// `expected_hashes`. During a manual cert rotation an admin configures both
/// the old and new pin so already-deployed clients keep trusting the old
/// cert while newly-configured clients pick up the new one.
#[must_use]
pub fn matches_any_pin(cert_der: &[u8], expected_hashes: &[Vec<u8>]) -> bool {
    let cert_hash = Sha256::digest(cert_der);
    expected_hashes
        .iter()
        .any(|expected| constant_time_eq(cert_hash.as_slice(), expected.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_any_pin_single_pin_match() {
        let cert = b"dummy certificate";
        let hash = Sha256::digest(cert).to_vec();
        assert!(matches_any_pin(cert, &[hash]));
    }

    #[test]
    fn matches_any_pin_single_pin_mismatch() {
        let cert = b"dummy certificate";
        let wrong_hash = vec![0u8; 32];
        assert!(!matches_any_pin(cert, &[wrong_hash]));
    }

    #[test]
    fn matches_any_pin_second_of_two_pins_matches() {
        let cert = b"dummy certificate";
        let hash = Sha256::digest(cert).to_vec();
        let wrong_hash = vec![0u8; 32];
        assert!(matches_any_pin(cert, &[wrong_hash, hash]));
    }

    #[test]
    fn matches_any_pin_neither_of_two_pins_matches() {
        let cert = b"dummy certificate";
        let wrong_a = vec![0u8; 32];
        let wrong_b = vec![1u8; 32];
        assert!(!matches_any_pin(cert, &[wrong_a, wrong_b]));
    }

    #[test]
    fn matches_any_pin_empty_list_never_matches() {
        let cert = b"dummy certificate";
        assert!(!matches_any_pin(cert, &[]));
    }
}
