/**
 * ZKPRust Managed Verification API — Cloudflare Worker
 *
 * Endpoint: POST https://zkp.gabanodelab.com/v1/verify
 *
 * Revenue model: metered per verification call.
 *   - Free tier:  500 verifications/month
 *   - Pro tier:   $0.002 per verification (billed via Stripe)
 *   - Enterprise: flat-rate contract
 *
 * Auth: Bearer token (API key) issued at dashboard.gabanodelab.com
 *
 * Request body (JSON):
 *   { "proof": "<hex 64-byte>", "publicKey": "<hex 32-byte>" }
 *
 * Response:
 *   { "valid": true|false, "verifiedAt": "<ISO 8601>" }
 *   or
 *   { "error": "<message>", "code": "<ERROR_CODE>" }
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const JSON_HEADERS = {
  ...CORS_HEADERS,
  'Content-Type': 'application/json',
};

// ─── Rate limits ──────────────────────────────────────────────────────────────

const FREE_TIER_MONTHLY_LIMIT = 500;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function errorResponse(message, code, status) {
  return jsonResponse({ error: message, code }, status);
}

/** Decode a hex string into a Uint8Array. Returns null on invalid input. */
function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = Number.parseInt(hex.slice(i, i + 2), 16);
    if (Number.isNaN(byte)) return null;
    bytes[i / 2] = byte;
  }
  return bytes;
}

/** Pull the API key from the Authorization: Bearer <key> header. */
function extractApiKey(request) {
  const auth = request.headers.get('Authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(auth.trim());
  return match?.[1] ?? null;
}

// ─── Core ZKP Verification (Schnorr PoK over Ristretto255) ───────────────────
//
// The Cloudflare Worker calls the lightweight WASM build of zkp-wasm.
// The WASM module is bundled at deploy time via wrangler.
//
// For initial deployment (before WASM bundling is wired up), we call the
// origin verification service running on a Fly.io instance.
//
async function verifyProofViaOrigin(proof, publicKey, env) {
  const res = await fetch(env.ORIGIN_VERIFY_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Worker-Secret': env.WORKER_SECRET,
    },
    body: JSON.stringify({ proof, publicKey }),
  });

  if (!res.ok) throw new Error(`Origin verifier returned ${res.status}`);
  const data = await res.json();
  return data.valid === true;
}

// ─── KV Usage Tracking ───────────────────────────────────────────────────────

async function getMonthlyUsage(apiKey, env) {
  const month = new Date().toISOString().slice(0, 7); // e.g. "2026-04"
  const key   = `usage:${apiKey}:${month}`;
  const raw   = await env.ZKP_USAGE.get(key);
  return raw ? Number.parseInt(raw, 10) : 0;
}

async function incrementUsage(apiKey, env) {
  const month = new Date().toISOString().slice(0, 7);
  const key   = `usage:${apiKey}:${month}`;
  const current = await getMonthlyUsage(apiKey, env);
  // TTL: 35 days so KV auto-cleans old months
  await env.ZKP_USAGE.put(key, String(current + 1), { expirationTtl: 35 * 24 * 60 * 60 });
  return current + 1;
}

// ─── API Key Lookup ───────────────────────────────────────────────────────────

async function lookupApiKey(apiKey, env) {
  const raw = await env.ZKP_KEYS.get(`key:${apiKey}`);
  if (!raw) return null;
  return JSON.parse(raw);
  // Shape: { tenantId, plan: 'free'|'pro'|'enterprise', stripeCustomerId }
}

// ─── Billing: record usage for Stripe metered subscription ───────────────────

async function recordStripeUsage(stripeCustomerId, env) {
  if (!env.STRIPE_SECRET_KEY || !stripeCustomerId) return;

  // Retrieve the subscription item id for metered usage
  const siRes = await fetch(
    `https://api.stripe.com/v1/subscription_items?customer=${stripeCustomerId}&limit=1`,
    { headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` } }
  );
  const siData = await siRes.json();
  const siId = siData.data?.[0]?.id;
  if (!siId) return;

  // Report 1 unit of usage
  const params = new URLSearchParams({
    quantity: '1',
    timestamp: String(Math.floor(Date.now() / 1000)),
    action: 'increment',
  });

  await fetch(`https://api.stripe.com/v1/subscription_items/${siId}/usage_records`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });
}

// ─── Request Handler ─────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Only POST /v1/verify
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/v1/verify') {
      return errorResponse('Not found', 'NOT_FOUND', 404);
    }

    // ── 1. Authentication ─────────────────────────────────────────────────
    const apiKey = extractApiKey(request);
    if (!apiKey) {
      return errorResponse('Missing Authorization: Bearer <api-key>', 'UNAUTHORIZED', 401);
    }

    const tenant = await lookupApiKey(apiKey, env);
    if (!tenant) {
      return errorResponse('Invalid API key', 'UNAUTHORIZED', 401);
    }

    // ── 2. Rate limiting (free tier) ──────────────────────────────────────
    const usage = await getMonthlyUsage(apiKey, env);
    if (tenant.plan === 'free' && usage >= FREE_TIER_MONTHLY_LIMIT) {
      return errorResponse(
        `Free tier limit of ${FREE_TIER_MONTHLY_LIMIT} verifications/month reached. Upgrade at dashboard.gabanodelab.com`,
        'RATE_LIMIT_EXCEEDED',
        429
      );
    }

    // ── 3. Parse and validate request body ────────────────────────────────
    let body;
    try {
      body = await request.json();
    } catch {
      return errorResponse('Invalid JSON body', 'BAD_REQUEST', 400);
    }

    const { proof, publicKey } = body;

    if (typeof proof !== 'string' || proof.length !== 128) {
      return errorResponse('proof must be a 128-character hex string (64 bytes)', 'BAD_REQUEST', 400);
    }
    if (typeof publicKey !== 'string' || publicKey.length !== 64) {
      return errorResponse('publicKey must be a 64-character hex string (32 bytes)', 'BAD_REQUEST', 400);
    }

    const proofBytes     = hexToBytes(proof);
    const publicKeyBytes = hexToBytes(publicKey);

    if (!proofBytes || !publicKeyBytes) {
      return errorResponse('proof or publicKey contains invalid hex characters', 'BAD_REQUEST', 400);
    }

    // ── 4. Verify the ZKP ─────────────────────────────────────────────────
    let valid;
    try {
      valid = await verifyProofViaOrigin(proof, publicKey, env);
    } catch (err) {
      console.error('[verify] origin error:', err.message);
      return errorResponse('Verification service temporarily unavailable', 'SERVICE_ERROR', 503);
    }

    // ── 5. Track usage + bill ─────────────────────────────────────────────
    await incrementUsage(apiKey, env);

    if (tenant.plan === 'pro' && tenant.stripeCustomerId) {
      // Fire-and-forget — don't block the response on Stripe
      env.ctx?.waitUntil(recordStripeUsage(tenant.stripeCustomerId, env));
    }

    // ── 6. Respond ────────────────────────────────────────────────────────
    return jsonResponse({
      valid,
      verifiedAt: new Date().toISOString(),
    });
  },
};
