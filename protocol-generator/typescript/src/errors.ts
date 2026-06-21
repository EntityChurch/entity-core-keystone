/**
 * Error hierarchy (profile `[error_model]`, JS idiom: throw `Error` subclasses).
 * Mirrors the C# reference peer's exception tree.
 *
 * ```
 * EntityCoreError
 *   EntityCodecError                  (S2 — codec / canonical-CBOR faults)
 *   EntityProtocolError               (wire-contract faults; carries a §3.3 status)
 *     HelloFailedError
 *     AuthenticationError
 *   EntityTransportError              (per-request transport faults; §6.12 code/status)
 *     RecvTimeoutError                (recv_timeout / 503)
 *     ConnectionBrokenError           (connection_broken / 503)
 *     WireProtocolError               (protocol_error / 502 — A-003 rename)
 * ```
 *
 * NOTE: `class X extends Error` needs `Object.setPrototypeOf(this, X.prototype)`
 * in the constructor for `instanceof` to work reliably across the transpiled
 * `extends` (profile [error_model] note). Applied in every subclass.
 */

/** Root of every Entity Core error. */
export class EntityCoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EntityCoreError";
    Object.setPrototypeOf(this, EntityCoreError.prototype);
  }
}

/**
 * A codec-layer failure: malformed CBOR, a forbidden tag, a non-canonical
 * encoding, a bad peer-id, a varint overflow. The decode-reject path that the
 * protocol surfaces as `400 non_canonical_ecf` (ENTITY-CBOR-ENCODING §6.3)
 * originates here.
 */
export class EntityCodecError extends EntityCoreError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EntityCodecError";
    Object.setPrototypeOf(this, EntityCodecError.prototype);
  }
}

/**
 * A protocol-layer fault: a malformed envelope, a failed integrity check, a
 * handshake-sequence violation, or any other deviation from the V7 wire contract
 * above the codec. Carries the EXECUTE_RESPONSE status code (§3.3, §8.3) so the
 * dispatcher can surface the right numeric category to the caller. Defaults to
 * `400` (bad request) when the call site does not specify one.
 */
export class EntityProtocolError extends EntityCoreError {
  /** The EXECUTE_RESPONSE status code this fault maps to (§3.3, §8.3). */
  readonly status: number;

  constructor(message: string, status = 400, options?: ErrorOptions) {
    super(message, options);
    this.name = "EntityProtocolError";
    this.status = status;
    Object.setPrototypeOf(this, EntityProtocolError.prototype);
  }
}

/** The connection handshake's `hello` leg failed (§4.1, §4.5). */
export class HelloFailedError extends EntityProtocolError {
  constructor(message: string, status = 400, options?: ErrorOptions) {
    super(message, status, options);
    this.name = "HelloFailedError";
    Object.setPrototypeOf(this, HelloFailedError.prototype);
  }
}

/** Proof-of-possession / identity verification failed at `authenticate` (§4.6, §4.7). */
export class AuthenticationError extends EntityProtocolError {
  constructor(message: string, status = 401, options?: ErrorOptions) {
    super(message, status, options);
    this.name = "AuthenticationError";
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * A per-request transport fault: no usable EXECUTE_RESPONSE arrived for an
 * outbound EXECUTE (V7 §6.12). The three concrete codes carry the canonical
 * `code`/`status` pairs so downstream consumers record the right marker.
 */
export class EntityTransportError extends EntityCoreError {
  /** The §6.12 transport error code (e.g. `"recv_timeout"`). */
  readonly code: string;
  /** The status the transport surfaces for this fault (§6.12). */
  readonly status: number;

  constructor(code: string, status: number, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EntityTransportError";
    this.code = code;
    this.status = status;
    Object.setPrototypeOf(this, EntityTransportError.prototype);
  }
}

/** No response arrived within the per-request deadline → `recv_timeout` / 503 (§6.12). */
export class RecvTimeoutError extends EntityTransportError {
  constructor(message: string, options?: ErrorOptions) {
    super("recv_timeout", 503, message, options);
    this.name = "RecvTimeoutError";
    Object.setPrototypeOf(this, RecvTimeoutError.prototype);
  }
}

/** The connection dropped before a response arrived → `connection_broken` / 503 (§6.12). */
export class ConnectionBrokenError extends EntityTransportError {
  constructor(message: string, options?: ErrorOptions) {
    super("connection_broken", 503, message, options);
    this.name = "ConnectionBrokenError";
    Object.setPrototypeOf(this, ConnectionBrokenError.prototype);
  }
}

/**
 * A response arrived but was malformed — a decode failure on the wire envelope,
 * a missing required field, or an error response (`status >= 400`) lacking the
 * required `code` field. Surfaced as `protocol_error` / 502 (V7 §6.12).
 *
 * (A-003: the naive C# `ProtocolErrorException` → TS port stuttered to
 * `ProtocolErrorError`; renamed `WireProtocolError` per the profile note.)
 */
export class WireProtocolError extends EntityTransportError {
  constructor(message: string, options?: ErrorOptions) {
    super("protocol_error", 502, message, options);
    this.name = "WireProtocolError";
    Object.setPrototypeOf(this, WireProtocolError.prototype);
  }
}
