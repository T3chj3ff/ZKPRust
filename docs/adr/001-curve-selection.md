# ADR-001: Cryptographic Curve and Protocol Selection

**Date:** 2026-01-22  
**Status:** Accepted  
**Deciders:** J. Fryer (GABAnode Lab LLC)

---

## Context

ZKPRust requires a non-interactive Zero-Knowledge Proof system for user authentication.
The proof must be:

1. Secure against passive and active adversaries
2. Efficient enough for browser WASM execution (<200ms on mid-tier hardware)
3. Compact enough for standard HTTP request payloads (≤128 bytes)
4. Free of patent encumbrances for enterprise adoption

Three candidate constructions were evaluated:

| Construction | Curve | Proof Size | Patent Risk | WASM Perf |
|---|---|---|---|---|
| Schnorr PoK (selected) | Ristretto255 | 64 bytes | None | ~8ms |
| ECDSA-based proof | secp256k1 | ~72 bytes | None | ~12ms |
| Groth16 (zk-SNARK) | BN254 | 128 bytes | Some | ~400ms |
| PLONK | Various | ~800 bytes | Some | ~600ms |

## Decision

**Use Schnorr Proof of Knowledge over the Ristretto255 group.**

### Why Schnorr PoK over zk-SNARKs

Groth16 and PLONK are correct for general computation proofs (e.g. proving a hash preimage
without revealing it in a circuit). For our use case — proving knowledge of a discrete
logarithm (the user's secret) — Schnorr is mathematically equivalent at a fraction of the
complexity and WASM binary size.

Schnorr PoK proves: *"I know `x` such that `x·G = PK`"* — which is exactly the statement
"I know the secret behind this public key." No trusted setup. No ceremony. No circuit.

### Why Ristretto255 over secp256k1

secp256k1 (Bitcoin's curve) has cofactor 8, meaning the group contains small subgroups.
A careless implementation can be attacked by sending points in a small subgroup, allowing
proof forgery without knowing the secret.

Ristretto255 is a construction over Curve25519 that presents a prime-order group with
**cofactor 1**. Small-subgroup attacks are impossible by construction — the group
arithmetic itself prevents them. This eliminates an entire class of implementation
errors without requiring explicit subgroup membership checks.

Additionally, `curve25519-dalek` is the most audited Rust elliptic curve library in
production, used in Signal, Tor, and the TLS ecosystem.

### Why Merlin for the transcript

A naive Fiat-Shamir transform (hashing commitments directly) is vulnerable to
cross-protocol attacks where the same hash appears in multiple protocol contexts.
Merlin provides domain-separated transcripts with a strobe-based construction that
prevents these attacks by ensuring challenge values are bound to the specific protocol
and session context.

## Consequences

- Proof wire format: 64 bytes (`commitment_R: [u8; 32]` + `response_z: [u8; 32]`)
- Public key format: 32 bytes (compressed Ristretto255 point)
- WASM binary: ~118KB optimized — acceptable for one-time load
- No trusted setup, no ceremony, no external dependencies beyond the library
- Proofs are non-deterministic (fresh `OsRng` per proof) — replay attacks impossible
