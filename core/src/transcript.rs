//! Fiat-Shamir Transcript implementation for Non-Interactive Proofs.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// A trait extending `merlin::Transcript` with domain-specific ZKPRust bindings.
pub trait TranscriptProtocol {
    /// Initialize a new transcript with a domain separator.
    fn zkprust_domain_sep(&mut self, label: &'static [u8]);

    /// Append a public curve point (e.g. commitment `R` or public key `X`) to the transcript.
    fn append_point(&mut self, label: &'static [u8], point: &[u8; 32]);

    /// Generate the challenge scalar `c` from the current transcript state.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn zkprust_domain_sep(&mut self, label: &'static [u8]) {
        self.append_message(b"dom-sep", label);
    }

    fn append_point(&mut self, label: &'static [u8], point: &[u8; 32]) {
        self.append_message(label, point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}
