import { type EcfValue } from "../codec/ecf-value.js";
import { EntityCoreError } from "../errors.js";
import { type GrantEntry } from "../capability/index.js";
import type { DispatchContext } from "../dispatch/dispatch-context.js";
import { type HandlerOperations, type HandlerResult } from "./handler-abstractions.js";

/**
 * What `Peer.registerHandler(spec, body)` installs (`SDK-OPERATIONS` §11.6; keystone
 * peer contract `install.handler`).
 */
export interface HandlerSpec {
  /**
   * Peer-relative, concrete pattern (`app/notes`). Not absolute, no empty / `.` / `..` /
   * wildcard segment. `system/*` is NOT refused here (`SDK-OPERATIONS` v1.13 §11.6 —
   * that is how a standard extension installs in-process).
   */
  readonly pattern: string;
  /** Human-readable handler name, published on the interface entity (§3.7). */
  readonly name: string;
  /** At least one operation; the mapped form publishes each op's §3.7 `input_type` / `output_type`. */
  readonly operations: HandlerOperations;
  /**
   * The scope the handler's own self-issued grant is minted with (§11.6, §11.6.3).
   * `null` / absent mints a grant covering NOTHING — never a wildcard.
   */
  readonly internalScope?: readonly GrantEntry[] | null;
  /**
   * Types bound at `system/type/{name}` as `system/type` entities (§11.6.1). They
   * outlive the handle's close (§11.6.2): another handler may share them.
   */
  readonly types?: Readonly<Record<string, EcfValue>>;
}

/**
 * A handler body. It receives a {@link DispatchContext}, which only the peer's
 * dispatcher can construct — the body can trust that `callerCapability` was verified
 * and that `check_permission` allowed this request.
 */
export type HandlerBody = (ctx: DispatchContext) => Promise<HandlerResult> | HandlerResult;

/**
 * Why `Peer.registerHandler(spec, body)` refused an installation — `SDK-OPERATIONS`
 * §12.5's status and code, reported before anything was written.
 *
 * - `400 invalid_handler_spec` — the pattern is not a concrete peer-relative path, or
 *   the spec declares no operations, or a type name is empty.
 * - `409 pattern_collision` — a handler (bootstrap, in-process or wire-registered) is
 *   already bound at the pattern. Close its handle first; silent replacement is not an
 *   install.
 */
export class RegisterError extends EntityCoreError {
  constructor(
    readonly status: 400 | 409,
    readonly code: "invalid_handler_spec" | "pattern_collision",
    message: string,
  ) {
    super(`${status} ${code}: ${message}`);
    this.name = "RegisterError";
    Object.setPrototypeOf(this, RegisterError.prototype);
  }
}

/**
 * The handle `Peer.registerHandler(spec, body)` returns (`SDK-OPERATIONS` §11.6.2;
 * keystone peer contract `install.remove`).
 *
 * {@link close} removes the dispatch index entry FIRST, then the handler, interface,
 * grant and grant-signature tree entries; types stay. It is idempotent: `true` for the
 * call that removed the registration, `false` for any later call — and `false` if the
 * pattern has since been re-registered by someone else, whose registration it leaves
 * alone. A JS handle is not closed by garbage collection; keep it for as long as the
 * handler should stay installed.
 */
export class HandlerHandle {
  readonly #close: () => boolean;
  #closed = false;

  /** @internal Built by the handler registry; a handle built elsewhere closes nothing. */
  constructor(
    /** The pattern this handle installed. */
    readonly pattern: string,
    close: () => boolean,
  ) {
    this.#close = close;
  }

  /** Whether {@link close} has already been called on this handle. */
  get closed(): boolean {
    return this.#closed;
  }

  close(): boolean {
    if (this.#closed) {
      return false;
    }
    this.#closed = true;
    return this.#close();
  }
}

/** The §12.5 `invalid_handler_spec` validation. Returns the reason, or `null` for a valid spec. */
export function handlerSpecProblem(spec: HandlerSpec): string | null {
  const pattern = spec.pattern;
  if (typeof pattern !== "string" || pattern.length === 0) {
    return "pattern is empty";
  }
  if (pattern.startsWith("/") || pattern.startsWith("entity://")) {
    return `pattern '${pattern}' is not peer-relative`;
  }
  for (const segment of pattern.split("/")) {
    if (segment.length === 0 || segment === "." || segment === ".." || segment.includes("*")) {
      return `pattern '${pattern}' is not a concrete path (empty, '.', '..' or wildcard segment)`;
    }
    for (const ch of segment) {
      const code = ch.charCodeAt(0);
      if (code < 0x20 || code === 0x7f) {
        return `pattern '${pattern}' carries a control character`;
      }
    }
  }
  const ops = spec.operations;
  const opCount = Array.isArray(ops) ? ops.length : Object.keys(ops as object).length;
  if (opCount === 0) {
    return `'${pattern}' declares no operations`;
  }
  for (const name of Object.keys(spec.types ?? {})) {
    if (name.length === 0) {
      return `'${pattern}' declares a type with an empty name`;
    }
  }
  return null;
}
