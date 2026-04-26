use wasm_bindgen::prelude::*;

// SAFETY: WASM FFI layer requires some unsafe bindings, however, our core cryptography
// remains #![forbid(unsafe_code)] to guarantee math security.

#[wasm_bindgen]
pub fn generate_zkp() -> String {
    // Note: Temporary dummy integration test payload
    let _payload = zkprust_prover::authenticator::Authenticator::generate_payload([0u8; 32]);
    "PROOF_GENERATED_64_BYTES".into()
}
