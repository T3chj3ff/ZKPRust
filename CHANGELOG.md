# Changelog

All notable changes to ZKPRust are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- WASM npm package publish (`@gabanode/zkp-wasm`)
- Managed REST API deployment (`zkp.gabanodelab.com/v1/verify`)
- API key dashboard (self-serve signup + free tier)
- Batch verification endpoint
- FIPS 140-3 alignment statement

---

## [0.1.0] — 2026-04-26

### Added
- **`verifier/tests/integration_tests.rs`** — 6 integration tests covering the full
  prover → verifier round-trip and critical security properties:
  - `test_valid_proof_round_trip`
  - `test_wrong_password_is_rejected`
  - `test_tampered_payload_is_rejected`
  - `test_zero_payload_is_rejected`
  - `test_public_key_is_deterministic`
  - `test_proofs_are_non_deterministic` (validates fresh commitment per login)
- **`bindings/zkp-python/build.rs`** — macOS arm64 PyO3 linker fix using
  `-undefined dynamic_lookup`. Resolves `__Py_TrueStruct` symbol error on
  Apple Silicon without requiring a Python framework path.
- **`bindings/zkp-python/pyproject.toml`** — maturin build backend configuration
  for PyPI publishing (`gabanode-zkp`).
- **`bindings/zkp-wasm/src/lib.rs`** — Full WASM browser API:
  - `generate_proof(secret_hex)` → 64-byte proof hex
  - `derive_public_key(secret_hex)` → 32-byte public key hex
  - `verify_proof(proof_hex, public_key_hex)` → bool
- **`demo/index.html`** — Interactive browser demo. Fully client-side — zero
  network requests. Shows password → SHA-256 → WASM proof → verification loop
  with tamper test.
- **`api/worker/src/index.js`** — Cloudflare Worker for managed verification API.
  Implements API key auth, KV-backed usage tracking, free tier rate limiting
  (500 calls/month), and Stripe metered billing for Pro tier.
- **`.github/workflows/ci.yml`** — Full CI/CD pipeline: Rust tests + Clippy on
  every push, auto-publish to npm and PyPI on `v*.*.*` release tags.
- **`@gabanode/zkp@0.1.0`** — Published to npm with pre-built macOS arm64 native
  binary. Includes Express middleware quickstart and TypeScript types.

### Fixed
- **`bindings/zkp-node/test.js`** — Replaced hardcoded password literal
  `"secure_user_password_123"` with `process.env.TEST_USER_PASSWORD` fallback
  to `crypto.randomBytes(8)`. Prevents false positives in credential scanners.
- **`getrandom`** — Enabled `js` feature for WASM target to support browser
  entropy source (`crypto.getRandomValues`).

### Security
- All cryptographic operations remain in `#![forbid(unsafe_code)]` crates.
- Schnorr commitment randomness sourced from `OsRng` (native) / `crypto.getRandomValues` (WASM).
- CRON secret endpoint hardened: removed `?token=` query param fallback —
  secrets must never travel via URL (server logs, CDN cache, browser history).

---

## [0.0.3] — 2026-03-14

### Added
- **`bindings/zkp-node/`** — Node.js N-API binding via `napi-rs`. Exposes
  `verifyZkp`, `generateMockProof`, and `derivePublicKey` as native functions
  callable from Express middleware without FFI overhead.
- **`bindings/zkp-node/index.d.ts`** — TypeScript type declarations auto-generated
  by napi-rs for full IDE autocomplete support.
- **`bindings/zkp-python/src/lib.rs`** — PyO3 binding exposing `verify_zkp` as
  a native Python function for FastAPI integration.
- **`.cargo/config.toml`** — napi-rs cross-compilation config for Node.js targets.

### Changed
- `Authenticator::generate_payload` now accepts `[u8; 32]` directly rather than
  taking ownership of a `Scalar`. Reduces one unnecessary clone on the hot path.

---

## [0.0.2] — 2026-02-18

### Added
- **`bindings/zkp-wasm/`** — Initial WebAssembly target skeleton using
  `wasm-bindgen`. Establishes crate structure for browser proof generation.
- **`prover/src/authenticator.rs`** — `Authenticator` struct wrapping core proof
  generation. Public API: `generate_payload([u8; 32]) → [u8; 64]` and
  `derive_public_key([u8; 32]) → [u8; 32]`.
- **`verifier/src/validation_engine.rs`** — `ValidationEngine` struct wrapping
  core proof verification. Public API: `verify_payload(&[u8; 64], &[u8; 32]) → Result<(), ZKPError>`.
- **`core/src/sigma.rs`** — `Proof::to_bytes()` and `Proof::from_bytes()` for
  64-byte wire format serialization. Commitment `R` (32 bytes) + response `z`
  (32 bytes) packed in canonical order.

### Changed
- Migrated from `rand` to `rand_core::OsRng` directly. Removes a transitive
  dependency and tightens the RNG supply chain.

### Security
- Added `zeroize` derive on `ProvingKey`. Secret scalar is now wiped from memory
  on drop automatically via the `ZeroizeOnDrop` trait.
- Adopted `subtle::ConstantTimeEq` for all byte-level comparisons in the
  verification path. Eliminates early-exit timing variance.

---

## [0.0.1] — 2026-01-22

### Added
- **Cargo workspace** — `resolver = "2"` workspace with 5 member crates:
  `core`, `prover`, `verifier`, `bindings/zkp-wasm`, (node/python stubs).
- **`core/src/sigma.rs`** — Schnorr Proof of Knowledge (PoK) implementation
  over the Ristretto255 group:
  - `ProvingKey` — secret scalar with `Zeroize + ZeroizeOnDrop`
  - `VerifyingKey` — public Ristretto255 point
  - `Proof::generate()` — non-interactive via Fiat-Shamir with Merlin transcript
  - `Proof::verify()` — constant-time check: `z·G == R + c·PK`
- **`core/src/transcript.rs`** — `TranscriptProtocol` trait extending Merlin
  for domain-separated challenge generation (`append_point`, `challenge_scalar`).
- **`core/src/lib.rs`** — `#![no_std]` compatible, `#![forbid(unsafe_code)]`
  enforced. Re-exports `sigma`, `transcript`, `error` modules.
- **Dependency selection** (see [ADR-001](docs/adr/001-curve-selection.md)):
  - `curve25519-dalek 4.x` — Ristretto255 group operations
  - `merlin 3.x` — Fiat-Shamir transcript (domain separation)
  - `subtle 2.x` — Constant-time operations
  - `zeroize 1.8` — Deterministic secret erasure
- **`.clippy.toml`** — Clippy configuration enforcing `cognitive_complexity`,
  `unwrap_used`, and `expect_used` lints across the workspace.
- **`FOUNDERS_LOG.md`** — Origin documentation and remediation history.

### Architecture Decisions
- Chose Ristretto255 over secp256k1 for cofactor-1 group structure,
  eliminating small-subgroup attacks without explicit checks. (ADR-001)
- Chose Merlin over ad-hoc transcript for built-in domain separation
  and resistance to cross-protocol attacks. (ADR-001)
- Chose Apache 2.0 over MIT for patent grant clause, protecting enterprise
  adopters from patent litigation risk. (ADR-003)

---

[Unreleased]: https://github.com/T3chj3ff/ZKPRust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/T3chj3ff/ZKPRust/compare/v0.0.3...v0.1.0
[0.0.3]: https://github.com/T3chj3ff/ZKPRust/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/T3chj3ff/ZKPRust/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/T3chj3ff/ZKPRust/releases/tag/v0.0.1
