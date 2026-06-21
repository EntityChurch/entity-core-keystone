/**
 * The codec layer of `entity-core-protocol-typescript` — the browser-portable,
 * zero-runtime-dependency-on-`node:*` core. ECF canonical CBOR, content hashing,
 * peer-id, and Ed25519 sign/verify (crypto via the swappable provider seam).
 * This subtree lifts into a browser/Deno/Bun bundle untouched.
 */

export * from "./bytes.js";
export * from "./ecf-value.js";
export * from "./canonical-cbor.js";
export * from "./float.js";
export * from "./leb128.js";
export * from "./base58.js";
export * from "./peer-id.js";
export * from "./entity-codec.js";
