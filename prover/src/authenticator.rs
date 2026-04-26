//! # Authenticator (Client-Side Prover Engine)
//! 
//! Wraps the core ZKP mathematics to generate Non-Interactive Schnorr Proofs.
//! Intended to be compiled to WebAssembly or native mobile layers to securely convert
//! a user's password/secret into a dynamic 64-byte network payload.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;

use zkprust_core::sigma::{Proof, ProvingKey};

pub struct Authenticator;

impl Authenticator {
    /// Consumes a raw 32-byte secret (e.g. SHA256(password)), securely generates a 
    /// zero-knowledge payload, and immediately drops (zeroizes) the intermediate secret.
    /// 
    /// Returns the raw 64-byte `[u8; 64]` transmission payload representing the mathematical proof.
    pub fn generate_payload(raw_secret: [u8; 32]) -> [u8; 64] {
        let mut transcript = Transcript::new(b"gabanode_auth_protocol");
        
        // Safety: We restrict to strictly canonical scalars.
        // If the hash is unconstrained, from_bytes_mod_order masks it.
        let scalar_secret = Scalar::from_bytes_mod_order(raw_secret);
        
        // This ProvingKey enforces `zeroize` traits.
        let proving_key = ProvingKey::new(scalar_secret);

        let mut rng = OsRng;
        
        // Generate the 3-step proof mathematically.
        let proof = Proof::generate(&mut transcript, &proving_key, &mut rng);

        // Serialize directly into the 64-byte wire format.
        proof.to_bytes()
    }

    /// Development utility: safely computes the deterministic VerifyingKey (Public Key) 
    /// from a raw 32-byte secret and instantly drops the secret from RAM.
    /// Returns the 32-byte Ristretto point.
    pub fn derive_public_key(raw_secret: [u8; 32]) -> [u8; 32] {
        use zkprust_core::sigma::VerifyingKey;
        
        let scalar_secret = Scalar::from_bytes_mod_order(raw_secret);
        let proving_key = ProvingKey::new(scalar_secret);
        let verifying_key = VerifyingKey::from_proving_key(&proving_key);
        
        verifying_key.to_bytes()
    }
}
