const crypto = require('crypto');
const zkpNative = require('./index.js'); // The generated N-API bridge

console.log("=========================================");
console.log("⚡ GABAnode Labs: ZKPRust Node.js Engine Verification");
console.log("=========================================\n");

// 1. Simulate a user creating a password/secret
// In a real application this would be a user-provided password, never hardcoded.
const rawPassword = process.env.TEST_USER_PASSWORD || 'test_' + crypto.randomBytes(8).toString('hex');
const secretHash = crypto.createHash('sha256').update(rawPassword).digest();

console.log(`[CLIENT] User registers with password hash: ${secretHash.toString('hex').substring(0, 16)}...`);

// 2. Derive the 32-byte Ristretto Public Key (this goes into the Database)
const publicKey = zkpNative.derivePublicKey(secretHash);
console.log(`[SERVER] Saved 32-byte Public Key to DB:  ${publicKey.toString('hex')}\n`);

// 3. User attempts to login (Generates a 64-byte proof on their device)
console.log(`[CLIENT] Generating 64-byte Zero-Knowledge Proof...`);
const startGen = performance.now();
const proofPayload = zkpNative.generateMockProof(secretHash);
const endGen = performance.now();

console.log(`[CLIENT] Transmitting Payload: ${proofPayload.toString('hex').substring(0, 32)}...`);
console.log(`[STAT]   Proof Generated in ${(endGen - startGen).toFixed(3)}ms\n`);

// 4. Server receives the proof (Express Middleware)
console.log(`[SERVER] Express Router Received Proof. Verifying against Database Public Key...`);
const startVerify = performance.now();

// Native Rust Execution over V8 Buffer slices!
const isValid = zkpNative.verifyZkp(proofPayload, publicKey);
const endVerify = performance.now();

if (isValid) {
    console.log(`✅ [SERVER] Authentication SUCCESSFUL. Math verified natively in ${(endVerify - startVerify).toFixed(3)}ms.`);
} else {
    console.error(`❌ [SERVER] Authentication FAILED.`);
    process.exit(1);
}

console.log("\n=========================================");
console.log("The Native N-API bindings are fully functional.");
console.log("=========================================");
