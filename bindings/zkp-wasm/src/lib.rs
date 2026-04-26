// WASM browser bindings for ZKPRust.
//
// SAFETY: The FFI layer (wasm-bindgen) requires extern interactions,
// but all core cryptographic operations remain in #![forbid(unsafe_code)] crates.

use wasm_bindgen::prelude::*;

/// Generate a Zero-Knowledge Proof from a raw 32-byte secret (SHA-256 of password).
///
/// Returns the 64-byte proof as a hex string ready for network transmission.
/// The secret is immediately dropped from WASM memory after proof generation.
///
/// # Arguments
/// * `secret_hex` — 64-character hex string (32 bytes = SHA-256(password))
#[wasm_bindgen]
pub fn generate_proof(secret_hex: &str) -> Result<String, JsValue> {
    let bytes = hex_to_bytes(secret_hex)
        .ok_or_else(|| JsValue::from_str("secret_hex must be a valid 64-character hex string"))?;

    if bytes.len() != 32 {
        return Err(JsValue::from_str("secret_hex must decode to exactly 32 bytes"));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);

    let payload = zkprust_prover::authenticator::Authenticator::generate_payload(secret);

    Ok(bytes_to_hex(&payload))
}

/// Derive the persistent 32-byte public key from a 32-byte secret.
///
/// This is computed once during registration and stored server-side.
/// The public key is safe to store — it reveals nothing about the password.
///
/// # Arguments
/// * `secret_hex` — 64-character hex string (32 bytes = SHA-256(password))
#[wasm_bindgen]
pub fn derive_public_key(secret_hex: &str) -> Result<String, JsValue> {
    let bytes = hex_to_bytes(secret_hex)
        .ok_or_else(|| JsValue::from_str("secret_hex must be a valid 64-character hex string"))?;

    if bytes.len() != 32 {
        return Err(JsValue::from_str("secret_hex must decode to exactly 32 bytes"));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);

    let pk = zkprust_prover::authenticator::Authenticator::derive_public_key(secret);

    Ok(bytes_to_hex(&pk))
}

/// Verify a ZKP proof against a public key — runs fully client-side.
///
/// In production this runs on the server. Exposed here for demo transparency.
///
/// # Arguments
/// * `proof_hex`      — 128-character hex string (64 bytes)
/// * `public_key_hex` — 64-character hex string (32 bytes)
#[wasm_bindgen]
pub fn verify_proof(proof_hex: &str, public_key_hex: &str) -> Result<bool, JsValue> {
    let proof_bytes = hex_to_bytes(proof_hex)
        .ok_or_else(|| JsValue::from_str("proof_hex must be a valid 128-character hex string"))?;
    let pk_bytes = hex_to_bytes(public_key_hex)
        .ok_or_else(|| JsValue::from_str("public_key_hex must be a valid 64-character hex string"))?;

    if proof_bytes.len() != 64 {
        return Err(JsValue::from_str("proof must decode to exactly 64 bytes"));
    }
    if pk_bytes.len() != 32 {
        return Err(JsValue::from_str("public_key must decode to exactly 32 bytes"));
    }

    let mut proof_arr = [0u8; 64];
    proof_arr.copy_from_slice(&proof_bytes);

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);

    let result = zkprust_verifier::validation_engine::ValidationEngine::verify_payload(
        &proof_arr,
        &pk_arr,
    );

    Ok(result.is_ok())
}

// ─── Private helpers ─────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
