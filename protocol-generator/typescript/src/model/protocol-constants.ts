/**
 * Entity type-paths, status codes, and well-known protocol strings for the core
 * protocol (V7 §3, §4, §8). Frozen const objects — the TS analogue of the C#
 * reference's `TypeNames` / `Status` / `Protocols` static classes.
 */

/** Entity type-path constants for the core protocol (V7 §3). */
export const TypeNames = {
  Execute: "system/protocol/execute",
  ExecuteResponse: "system/protocol/execute/response",
  Error: "system/protocol/error",
  ResourceTarget: "system/protocol/resource-target",
  Peer: "system/peer",
  Signature: "system/signature",
  CapabilityToken: "system/capability/token",
  CapabilityGrant: "system/capability/grant",
  CapabilityRequest: "system/capability/request",
  CapabilityPolicyEntry: "system/capability/policy-entry",
  CapabilityRevocation: "system/capability/revocation",
  DeletionMarker: "system/deletion-marker",
  Handler: "system/handler",
  HandlerInterface: "system/handler/interface",
  HandlerRegisterRequest: "system/handler/register-request",
  HandlerRegisterResult: "system/handler/register-result",
  HandlerUnregisterRequest: "system/handler/unregister-request",
  Type: "system/type",
  Hello: "system/protocol/connect/hello",
  Authenticate: "system/protocol/connect/authenticate",
  PrimitiveAny: "primitive/any",
  // Entity-native body-binding seam (v7.74 §6.13(a)/§10.1 register round-trip).
  // compute-extension type LABELS the core peer reads/emits to honour the §10.1
  // round-trip — NOT part of the §9.5 core type floor (not published). See A-011.
  ComputeLiteral: "compute/literal",
  ComputeResult: "compute/result",
} as const;

/** EXECUTE_RESPONSE status codes (V7 §3.3, §8.3). */
export const Status = {
  Ok: 200,
  BadRequest: 400,
  Unauthorized: 401,
  Forbidden: 403,
  NotFound: 404,
  Conflict: 409,
  RateLimited: 429,
  InternalError: 500,
  NotSupported: 501,
  ServiceUnavailable: 503,
} as const;

/** Well-known protocol strings (V7 §8.4, §4.1). */
export const Protocols = {
  Version: "entity-core/1.0",
  ConnectPath: "system/protocol/connect",
  DefaultHashFormat: "ecfv1-sha256",
  DefaultKeyType: "ed25519",
} as const;
