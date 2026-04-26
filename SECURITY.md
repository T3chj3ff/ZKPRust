# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Active |
| < 0.1.0 | ❌ No longer supported |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities directly to:

**Email:** fryer@gabanodelab.com  
**Subject line:** `[ZKPRust SECURITY] <brief description>`  
**PGP:** Available on request

You will receive an acknowledgment within 48 hours and a resolution timeline
within 7 days. Critical vulnerabilities will be patched within 72 hours.

## Scope

The following are in scope for security reports:

- Cryptographic implementation errors in `core/src/sigma.rs`
- Timing side-channels in verification logic
- Memory safety issues in binding layers (`zkp-node`, `zkp-python`, `zkp-wasm`)
- Proof forgery under any adversarial model
- Denial-of-service via malformed proof payloads

## Security Design Principles

ZKPRust is built on four explicit security guarantees:

**1. No unsafe Rust in cryptographic code**  
`#![forbid(unsafe_code)]` is enforced at the compiler level in `core/`, `prover/`,
and `verifier/`. The FFI boundary layers (`zkp-node`, `zkp-python`, `zkp-wasm`) use
minimal unsafe surface required by their respective FFI mechanisms.

**2. Deterministic secret erasure**  
`ProvingKey` derives `Zeroize + ZeroizeOnDrop`. The secret scalar is wiped from
memory automatically on drop via the `zeroize` crate. This prevents secrets from
persisting in process memory after use.

**3. Constant-time operations**  
All byte-level comparisons in the verification path use `subtle::ConstantTimeEq`.
Early-exit comparisons that could leak timing information via cache or branch
prediction are forbidden in this codebase.

**4. Fresh randomness per proof**  
`Proof::generate()` calls `OsRng` for each invocation. Proofs are non-deterministic —
the same secret produces different proofs each time. This makes replay attacks and
proof correlation attacks impossible.

## Known Limitations

- This library has **not yet undergone a formal third-party cryptographic audit**.
  Enterprise customers requiring an audit letter should contact fryer@gabanodelab.com.
- The `zkp-python` binding has limited test coverage on Windows. Production use
  on Windows Python is not currently recommended.

## Hall of Fame

Responsible disclosures that lead to a fix will be credited here.
