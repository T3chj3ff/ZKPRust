#![no_std]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

//! # ZKPRust Core
//! 
//! The `zkprust-core` crate contains the foundational, zero-allocation,
//! memory-safe cryptography primitives for the GABAnode Engine.
//! 
//! ## T3chnexus Cryptographic Standards
//! - Completely `#![no_std]` compatible for zero-allocation performance.
//! - Outright `#![forbid(unsafe_code)]` for absolute memory safety guarantee.
//! - Uses `zeroize` for strict secret clearing from memory.
//! - Uses `subtle` for timing-attack resistance via constant-time math.

pub mod sigma;
pub mod transcript;

pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ZKPError {
        #[error("Cryptographic protocol error: {0}")]
        ProtocolError(&'static str),
        #[error("Invalid proof format")]
        InvalidProof,
        #[error("Verification failed")]
        VerificationFailed,
    }
}
