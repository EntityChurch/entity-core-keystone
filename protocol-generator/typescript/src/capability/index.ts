/**
 * L3 Capability — the `system/capability/token` shape, the deterministic Layer-1
 * chain verdict (N8 / §5.10), attenuation (§5.6/§5.7), two-level permission
 * checks (§5.2/§6.3), and URI/pattern matching (§5.4).
 */

export * as Paths from "./paths.js";
export * from "./scope.js";
export * from "./grant-entry.js";
export * from "./capability-token.js";
export * from "./seed-policy.js";
export * as Attenuation from "./attenuation.js";
export * as Permissions from "./permissions.js";
export * as ChainVerifier from "./chain-verifier.js";
