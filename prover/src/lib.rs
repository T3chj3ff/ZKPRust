#![no_std]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

//! # ZKPRust Prover
//! 
//! The `zkprust-prover` crate handles the client-side (e.g., in-browser)
//! generation of zero-knowledge proofs (e.g., Schnorr Proofs of Knowledge).

pub mod authenticator;
