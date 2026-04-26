/* tslint:disable */
/* eslint-disable */

/**
 * Derive the persistent 32-byte public key from a 32-byte secret.
 *
 * This is computed once during registration and stored server-side.
 * The public key is safe to store — it reveals nothing about the password.
 *
 * # Arguments
 * * `secret_hex` — 64-character hex string (32 bytes = SHA-256(password))
 */
export function derive_public_key(secret_hex: string): string;

/**
 * Generate a Zero-Knowledge Proof from a raw 32-byte secret (SHA-256 of password).
 *
 * Returns the 64-byte proof as a hex string ready for network transmission.
 * The secret is immediately dropped from WASM memory after proof generation.
 *
 * # Arguments
 * * `secret_hex` — 64-character hex string (32 bytes = SHA-256(password))
 */
export function generate_proof(secret_hex: string): string;

/**
 * Verify a ZKP proof against a public key — runs fully client-side.
 *
 * In production this runs on the server. Exposed here for demo transparency.
 *
 * # Arguments
 * * `proof_hex`      — 128-character hex string (64 bytes)
 * * `public_key_hex` — 64-character hex string (32 bytes)
 */
export function verify_proof(proof_hex: string, public_key_hex: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly derive_public_key: (a: number, b: number) => [number, number, number, number];
    readonly generate_proof: (a: number, b: number) => [number, number, number, number];
    readonly verify_proof: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
