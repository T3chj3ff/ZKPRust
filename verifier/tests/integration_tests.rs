//! Integration tests for ZKPRust — Schnorr Proof of Knowledge over Ristretto255.
//!
//! These tests cover the full prover→verifier round-trip and critical security
//! properties (tampered proof rejection, wrong key rejection).
//!
//! Run with: `cargo test -p zkprust-verifier`

use sha2::{Digest, Sha256};
use zkprust_prover::authenticator::Authenticator;
use zkprust_verifier::validation_engine::ValidationEngine;

// ─── helpers ────────────────────────────────────────────────────────────────

/// Hash a raw password string into the 32-byte secret the SDK expects.
fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

// ─── Test 1: Valid proof verifies ───────────────────────────────────────────

#[test]
fn test_valid_proof_round_trip() {
    let secret = hash_password("hunter2");

    let payload    = Authenticator::generate_payload(secret);
    let public_key = Authenticator::derive_public_key(secret);

    let result = ValidationEngine::verify_payload(&payload, &public_key);

    assert!(result.is_ok(), "A valid ZKP payload must verify successfully");
}

// ─── Test 2: Different password ↔ proof mismatch is rejected ────────────────

#[test]
fn test_wrong_password_is_rejected() {
    let secret_a = hash_password("correct_password");
    let secret_b = hash_password("wrong_password");

    // Proof generated with secret_a
    let payload    = Authenticator::generate_payload(secret_a);
    // Public key derived from secret_b — deliberately mismatched
    let public_key = Authenticator::derive_public_key(secret_b);

    let result = ValidationEngine::verify_payload(&payload, &public_key);

    assert!(result.is_err(), "Proof from a different secret must be rejected");
}

// ─── Test 3: Tampered payload byte is rejected ──────────────────────────────

#[test]
fn test_tampered_payload_is_rejected() {
    let secret     = hash_password("tamper_target");
    let mut payload = Authenticator::generate_payload(secret);
    let public_key  = Authenticator::derive_public_key(secret);

    // Flip a single bit in the commitment portion of the 64-byte payload.
    payload[0] ^= 0xFF;

    let result = ValidationEngine::verify_payload(&payload, &public_key);

    assert!(result.is_err(), "A tampered payload byte must be rejected");
}

// ─── Test 4: Zero payload is rejected (malformed input) ─────────────────────

#[test]
fn test_zero_payload_is_rejected() {
    let secret     = hash_password("zero_test");
    let public_key = Authenticator::derive_public_key(secret);
    let zero_payload = [0u8; 64];

    let result = ValidationEngine::verify_payload(&zero_payload, &public_key);

    assert!(result.is_err(), "An all-zero payload must not verify");
}

// ─── Test 5: Public key is deterministic per secret ─────────────────────────

#[test]
fn test_public_key_is_deterministic() {
    let secret = hash_password("determinism_check");

    let pk1 = Authenticator::derive_public_key(secret);
    let pk2 = Authenticator::derive_public_key(secret);

    assert_eq!(
        pk1, pk2,
        "Public key derivation must be deterministic for the same secret"
    );
}

// ─── Test 6 (bonus): Each proof is unique (non-deterministic commitment) ─────

#[test]
fn test_proofs_are_non_deterministic() {
    let secret = hash_password("uniqueness_check");

    let proof1 = Authenticator::generate_payload(secret);
    let proof2 = Authenticator::generate_payload(secret);

    // The commitment R is randomised per proof — two proofs from the same secret
    // must differ (this is a core security property of Schnorr signatures).
    assert_ne!(
        proof1, proof2,
        "Each proof must use a fresh random commitment — proofs must not repeat"
    );
}
