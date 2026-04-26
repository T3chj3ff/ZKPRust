#![no_std]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

//! # ZKPRust Verifier
//! 
//! The `zkprust-verifier` crate manages backend, high-speed validation
//! of proofs originating from clients. Designed for multi-threaded server environments.

pub mod validation_engine;
