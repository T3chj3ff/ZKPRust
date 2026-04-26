# ADR-002: Multi-Language Binding Strategy

**Date:** 2026-02-01  
**Status:** Accepted  
**Deciders:** J. Fryer (GABAnode Lab LLC)

---

## Context

The core cryptographic engine is in Rust. To achieve enterprise adoption, it must be
callable from the dominant backend languages: Node.js (Express), Python (FastAPI),
and the browser (WASM). Three binding strategies were evaluated:

| Strategy | Approach | Overhead | Maintenance |
|---|---|---|---|
| REST microservice | HTTP between services | ~5ms network latency | Low (one binary) |
| WASM (all targets) | wasm-bindgen everywhere | ~1ms, 118KB load | Medium |
| Native bindings (selected) | napi-rs + PyO3 + wasm-bindgen | ~0.1ms, no load | Higher |

## Decision

**Use platform-native bindings for each target:**

- **Browser:** `wasm-bindgen` (WebAssembly, runs in-browser)
- **Node.js:** `napi-rs` (N-API native `.node` binary)
- **Python:** `PyO3` (native `.so`/`.dylib` Python extension module)

### Rationale

A REST microservice approach requires customers to run and maintain a separate
process. This adds operational complexity, a network hop, and a new attack surface
(the microservice endpoint). For authentication — a critical hot path — the additional
latency is also unacceptable.

WASM-everywhere (running WASM in Node.js via a runtime) is viable but adds 1-3MB of
WASM runtime overhead and inconsistent startup time. Node.js already has a first-class
native extension mechanism (N-API) that is ABI-stable across Node versions.

Native bindings give customers a `require('@gabanode/zkp')` one-liner with zero
additional runtime dependencies and sub-millisecond verification latency.

### Trade-off accepted

Each binding target requires separate CI build matrix entries (macOS arm64, Linux x64,
Linux arm64, Windows x64). This is managed via napi-rs optionalDependencies and
maturin's platform wheel system — standard practice in the ecosystem (e.g., `esbuild`,
`@swc/core`, `lightningcss` all use this pattern).

## Consequences

- npm package uses `optionalDependencies` for platform-specific `.node` files
- CI matrix must build on 3+ OS/arch combinations per release
- PyPI package uses `maturin` with `manylinux` for broad Linux compatibility
- Browser package published separately as `@gabanode/zkp-wasm`
