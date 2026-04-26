# @gabanode/zkp

**Zero-Knowledge Proof authentication SDK for Node.js.**  
Verify users without storing or transmitting passwords — powered by Schnorr PoK over Ristretto255.

[![npm](https://img.shields.io/npm/v/@gabanode/zkp)](https://www.npmjs.com/package/@gabanode/zkp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Security: ZKP](https://img.shields.io/badge/security-zero--knowledge-brightgreen)]()

---

## Why ZKP Authentication?

Traditional auth stores a password hash in your database. If your DB leaks, attackers can crack those hashes.

ZKP auth stores a **public key** — a point on an elliptic curve. Even with full DB access, there is no password to recover. Each login generates a fresh cryptographic proof that is mathematically unforgeeable without knowing the original secret.

---

## Install

```bash
npm install @gabanode/zkp
```

> Native binaries are pre-built for macOS (arm64/x64), Linux (x64/arm64), and Windows (x64).  
> No compilation required.

---

## Quick Start — Express Middleware

```js
const { verifyZkp } = require('@gabanode/zkp');
const crypto = require('crypto');

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { proof, publicKey } = req.body;

  const payloadBuf   = Buffer.from(proof,     'hex'); // 64-byte proof from client
  const publicKeyBuf = Buffer.from(publicKey, 'hex'); // 32-byte key from your DB

  const valid = verifyZkp(payloadBuf, publicKeyBuf);

  if (!valid) return res.status(401).json({ error: 'Proof invalid' });

  // Issue your JWT / session here
  res.json({ token: issueToken(req.body.userId) });
});
```

---

## API

### `verifyZkp(payload: Buffer, publicKey: Buffer): boolean`

Verifies a 64-byte ZKP payload against a 32-byte stored public key.  
Returns `true` if the proof is valid. **O(1) constant-time.** Timing-attack resistant.

### `generateMockProof(secret: Buffer): Buffer`

Development utility — generates a 64-byte proof from a 32-byte secret hash.  
Use in test suites without a WASM frontend.

### `derivePublicKey(secret: Buffer): Buffer`

Derives the 32-byte public key from a 32-byte secret hash.  
Use during user registration to compute the value stored in your database.

---

## Registration Flow

```js
const { derivePublicKey } = require('@gabanode/zkp');
const crypto = require('crypto');

// POST /auth/register
app.post('/auth/register', async (req, res) => {
  const secretHash   = crypto.createHash('sha256').update(req.body.password).digest();
  const publicKey    = derivePublicKey(secretHash); // 32 bytes — store this, not the password

  await db.users.create({
    email:     req.body.email,
    publicKey: publicKey.toString('hex'), // safe to store and expose
  });

  res.json({ ok: true });
});
```

---

## Test Suite Integration

```js
const { generateMockProof, derivePublicKey, verifyZkp } = require('@gabanode/zkp');
const crypto = require('crypto');

test('valid proof verifies', () => {
  const secret    = crypto.createHash('sha256').update('test_password').digest();
  const proof     = generateMockProof(secret);
  const publicKey = derivePublicKey(secret);

  expect(verifyZkp(proof, publicKey)).toBe(true);
});

test('wrong key is rejected', () => {
  const secretA   = crypto.createHash('sha256').update('password_a').digest();
  const secretB   = crypto.createHash('sha256').update('password_b').digest();
  const proof     = generateMockProof(secretA);
  const publicKey = derivePublicKey(secretB);

  expect(verifyZkp(proof, publicKey)).toBe(false);
});
```

---

## Security Architecture

| Property | Guarantee |
|---|---|
| No password storage | Only a Ristretto255 public key is persisted |
| Timing-attack resistant | Constant-time ops via `subtle` crate |
| Memory safety | `zeroize` crate — secrets wiped from RAM immediately |
| No unsafe Rust | `#![forbid(unsafe_code)]` enforced at compile time |
| Fresh commitment per login | Non-deterministic Schnorr proof — each login unique |

---

## GovTech / Enterprise

Need a managed REST verification API, compliance documentation (FIPS, WCAG, VPAT), or a custom integration?  
Contact: **admin@gabanodelab.com** | [gabanodelab.com](https://gabanodelab.com)

---

## License

Apache 2.0 — GABAnode Lab LLC
