#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
/// The primary Express Middleware API for verifying the non-interactive ZKP token payload.
/// 
/// `payload`: The raw 64-byte Buffer extracted from the user's client proof request over the network.
/// `public_key`: The raw 32-byte Buffer associated with the user's database entry.
/// 
/// Returns true if mathematical validation succeeds.
pub fn verify_zkp(payload: Buffer, public_key: Buffer) -> Result<bool> {
    if payload.len() != 64 {
        return Err(Error::new(Status::InvalidArg, "Payload must be exactly 64 bytes"));
    }
    if public_key.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "Public Key must be exactly 32 bytes"));
    }

    let mut payload_arr = [0u8; 64];
    payload_arr.copy_from_slice(&payload);

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&public_key);

    Ok(zkprust_verifier::validation_engine::ValidationEngine::verify_payload(&payload_arr, &key_arr).is_ok())
}

#[napi]
/// A high-performance mock validation function generating a full ZKP dynamically.
/// Provided to Node.js backend engineers purely for standing up Test suites without
/// requiring a full WASM frontend interface to generate the proof on their behalf.
/// 
/// `secret`: The 32-byte secret Hash Buffer.
/// 
/// Returns the resulting 64-byte Payload Buffer to feed into `verify_zkp`.
pub fn generate_mock_proof(secret: Buffer) -> Result<Buffer> {
    if secret.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "Secret must be exactly 32 bytes"));
    }

    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret);

    let payload = zkprust_prover::authenticator::Authenticator::generate_payload(secret_arr);
    
    Ok(payload.to_vec().into())
}

#[napi]
/// Derive the user's persistent 32-byte Public Key equivalent needed for database storage. 
/// In reality, the WASM client generates this during registration and submits it. But for Node
/// testing, we supply this utility.
pub fn derive_public_key(secret: Buffer) -> Result<Buffer> {
    if secret.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "Secret must be exactly 32 bytes"));
    }

    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret);

    let pk = zkprust_prover::authenticator::Authenticator::derive_public_key(secret_arr);
    
    Ok(pk.to_vec().into())
}
