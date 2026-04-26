# ZKPRust Core Authentication Engine

**A GABAnode Lab LLC Project**  
*Creator & Lead Architect: J. Fryer*

## Vision
ZKPRust is a Next-Generation, Zero-Knowledge Proof (ZKP) authentication SDK. Building on standard Web2 middleware patterns (Node.js/Express and Python/FastAPI), ZKPRust provides enterprise-grade privacy and verification capabilities, enabling systems to authenticate users without storing or transmitting sensitive credentials like passwords.

This codebase is governed by the specialized `t3chnexus` skill stack, applying Big Tech R&D lab engineering methodologies, specifically prioritizing memory safety, zero-allocation cryptography paths, and developer-friendly cross-language bindings.

## Repository Architecture (Cargo Workspace)
- `core/`: The isolated cryptographic foundational types (`#![no_std]`, `#![forbid(unsafe_code)]`).
- `prover/`: Client-side (in-browser) proof generation.
- `verifier/`: Server-side (backend) proof verification logic.
- `bindings/zkp-wasm/`: Browser WebAssembly target using `wasm-bindgen`.
- `bindings/zkp-node/`: Node.js N-API target using `napi-rs` for Express middleware.
- `bindings/zkp-python/`: Native Python module target using `PyO3` for FastAPI middleware.

## Security Guarantees
- Zero allocations in core cryptographic algorithms ensuring consistent latency.
- Strict clearing of secrets from memory utilizing the `zeroize` crate.
- Protection against timing attacks via constant-time operations powered by the `subtle` crate.
- Complete ban on the `unsafe` keyword in all core cryptographic logic.
