import { parsePeerId } from "../codec/peer-id.js";
import { peerEntityId } from "../identity/peer-entities.js";
import { isSupportedKeyType } from "../codec/key-types.js";
import { EntityCodecError } from "../errors.js";
import { Entity, Ecf, Status, TypeNames, hashHex, isZeroHash } from "../model/index.js";
import { Attenuation, CapabilityToken, GrantEntry, Paths } from "../capability/index.js";
import { type Handler, type HandlerContext, HandlerResult } from "./handler-abstractions.js";
import { errorResult } from "./errors.js";

/**
 * The capability handler at `system/capability` (V7 §6.2). Runtime capability
 * management: `request` (issue a token bounded by the caller's authority, §6.2 /
 * §5.6), `configure` (bind a policy-entry, v7.62 §4), `revoke` (write a revocation
 * marker, v7.62 §5/§6). `delegate` is same-peer-only in v1 (closeout F1 / F13) → a
 * remote caller receives 501 `unsupported_operation`.
 */
export class CapabilityHandler implements Handler {
  readonly pattern = "system/capability";
  readonly name = "capability";
  readonly operations: readonly string[] = ["request", "delegate", "revoke", "configure"];

  async handle(ctx: HandlerContext): Promise<HandlerResult> {
    switch (ctx.operation) {
      case "request":
        return this.#request(ctx);
      case "configure":
        return this.#configure(ctx);
      case "revoke":
        return this.#revoke(ctx);
      case "delegate":
        // §6.2 closeout F1: delegate is same-peer-only in v1 — a remote caller (every
        // validate-peer client) receives 501, not 403. Input shape under-specified (F13).
        return errorResult(
          Status.NotSupported,
          "unsupported_operation",
          "delegate is same-peer-only in v1 (closeout F1); input shape under-specified (F13)",
        );
      default:
        return errorResult(Status.NotSupported, "unsupported_operation", `unknown capability operation '${ctx.operation}'`);
    }
  }

  #request(ctx: HandlerContext): HandlerResult {
    if (ctx.author === null) {
      return errorResult(Status.Forbidden, "missing_authorization", "capability request requires an author");
    }
    const granteePeer = ctx.envelope.find(ctx.author);
    if (granteePeer === undefined) {
      return errorResult(Status.BadRequest, "unresolvable_grantee", "author identity not in included");
    }

    // Parse the requested scope (§3.6 system/capability/request).
    const requested = Ecf.asArray(Ecf.require(ctx.params.data, "grants")).map((g) => GrantEntry.fromEcf(g));

    // §6.2 / §5.6 attenuation-on-issue: the issued grant MUST NOT exceed the
    // caller's presented authority → 403 scope_exceeds_authority.
    if (
      ctx.callerCapability !== null &&
      !Attenuation.grantsWithinAuthority(requested, ctx.callerCapability.grants, ctx.localPeerId)
    ) {
      return errorResult(
        Status.Forbidden,
        "scope_exceeds_authority",
        "requested grant exceeds the caller's presented authority (section 6.2 / section 5.6)",
      );
    }

    // §6.2 CAP-5 / §5.6 MIN_DEFINED: the minted token is bounded by EVERY applicable
    // ceiling, not just the requester's own ttl_ms. `request` mints a ROOT token
    // (parent: null), so §5.6's parent-child attenuation rule never reaches it —
    // without this bound, temporal attenuation is the one dimension a requester can
    // escape. createdAt is sampled ONCE and threaded through both the emitted
    // created_at and every duration term, so the two cannot skew.
    const createdAt = ctx.peer.nowMs;
    const expiresAt = mintExpiry(ctx, createdAt);

    // The core peer grants the requested (now-bounded) scope from its own root
    // authority (the peer is the sole root for caps it issues, §5.5).
    const { token, signature } = CapabilityToken.createRoot(
      ctx.peer.localIdentity,
      granteePeer.contentHash,
      requested,
      createdAt,
      expiresAt,
    );

    const grant = Entity.create(TypeNames.CapabilityGrant, Ecf.map(["token", Ecf.bytes(token.contentHash)]));
    const included = [token.entity, ctx.peer.localIdentity.peerEntity, granteePeer, signature];
    return HandlerResult.ok(grant, included);
  }

  #configure(ctx: HandlerContext): HandlerResult {
    if (ctx.params.type !== TypeNames.CapabilityPolicyEntry) {
      return errorResult(
        Status.BadRequest,
        "invalid_params",
        `configure expects a ${TypeNames.CapabilityPolicyEntry} (got '${ctx.params.type}')`,
      );
    }
    const peerPattern = Ecf.requireText(ctx.params.data, "peer_pattern");
    if (!isValidPolicyPattern(peerPattern)) {
      return errorResult(
        Status.BadRequest,
        "invalid_params",
        'peer_pattern MUST be "default", a 66/98-char hex content hash, or a Base58 peer_id; partial prefixes are rejected (v7.62 section 4)',
      );
    }
    // §6.2 CAP-2: an EMPTY grants array is valid and meaningful — `configure` MUST
    // accept `grants: []` and MUST write it. It is the WITHDRAWAL form: because an
    // exact-match entry suppresses the `default` fallback simply by existing, an empty
    // entry means "this peer matches, and is granted nothing." Rejecting it (as this
    // handler did, per the retired v7.62 §4 "at least one grant" reading) leaves an
    // operator only the more permissive spelling — removal, which RESTORES the default
    // fallback (CAP-3) and is a different operation, not a synonym.
    Ecf.asArray(Ecf.require(ctx.params.data, "grants")); // shape check only; length 0 is legal

    const path = Paths.canonicalize("system/capability/policy/" + peerPattern, ctx.localPeerId);
    ctx.peer.tree.put(path, ctx.params);
    return HandlerResult.ok(ack());
  }

  #revoke(ctx: HandlerContext): HandlerResult {
    const token = Ecf.optBytes(ctx.params.data, "token");
    if (token === null || isZeroHash(token)) {
      return errorResult(Status.BadRequest, "invalid_params", "revoke-request.token must be non-zero (v7.62 section 10)");
    }
    const reason = Ecf.optText(ctx.params.data, "reason");

    const marker = Entity.create(
      TypeNames.CapabilityRevocation,
      Ecf.map(
        ["token", Ecf.bytes(token)],
        ["reason", reason === null ? null : Ecf.text(reason)],
        ["revoked_at", Ecf.uint(ctx.peer.nowMs)],
      ),
    );

    const path = Paths.canonicalize("system/capability/revocations/" + hashHex(token), ctx.localPeerId);
    ctx.peer.tree.put(path, marker);
    return HandlerResult.ok(ack());
  }
}

/** The inclusive maximum of `primitive/uint` — the representability bound for a term. */
const UINT64_MAX = (1n << 64n) - 1n;

/**
 * Convert a DURATION term (`ttl_ms`) to an absolute timestamp, reporting whether it
 * contributes a ceiling at all (§5.6 MIN_DEFINED rule 1 + rule 3).
 *
 * Overflow DROPS the term — it is treated as absent, exactly as a null term is. It
 * MUST NOT wrap and MUST NOT saturate: saturation encodes differently from absence and
 * manufactures `expires_at == 2^64-1`, a finite bound no reader can distinguish from a
 * deliberate one. JS bigints do not wrap, so the check here is representability against
 * `primitive/uint`, not machine overflow — the same rule, reached from the other side of
 * the numeric-model split (a fixed-width peer detects the wrap; a bignum peer must
 * range-check deliberately, or the rule silently never fires).
 *
 * `ttl === 0` is NOT special-cased, deliberately: rule 2 makes 0 a DEFINED value
 * yielding `createdAt` (expire immediately). Letting it fall out of the arithmetic is
 * what keeps it from collapsing into the absent/null "no bound" spelling.
 */
function durationTerm(createdAt: bigint, ttl: bigint | null): bigint | null {
  if (ttl === null) {
    return null; // absent → no term
  }
  const sum = createdAt + ttl;
  return sum > UINT64_MAX ? null : sum;
}

/** §5.6 MIN_DEFINED: the minimum over the DEFINED terms only; null when none is. */
function minDefined(...terms: readonly (bigint | null)[]): bigint | null {
  let out: bigint | null = null;
  for (const t of terms) {
    if (t !== null && (out === null || t < out)) {
      out = t;
    }
  }
  return out;
}

/**
 * §6.2 CAP-5's mint ceiling, in the §5.6 MIN_DEFINED construction:
 *
 *     expires_at = MIN_DEFINED(
 *         caller_capability.expires_at,      ; ABSOLUTE — enters directly
 *         created_at + policy_entry.ttl_ms,  ; DURATION — converted first
 *         created_at + request.ttl_ms)       ; DURATION — converted first
 *
 * Term SHAPE is the trap: mixing a duration in unconverted yields a timestamp near the
 * epoch and silently clamps every token to already-expired. If no term is defined the
 * result is null (no expiry) — which is why an unauthenticated caller asking for no ttl
 * still gets an unbounded token, and why the caller-cap term carries the ceiling on the
 * `request` path (parent is null there, so §5.6's parent term does not exist).
 *
 * The disposition is a CLAMP, never a rejection: an over-long request from a bounded
 * caller mints at 200 with the clamped value. Rejecting it is explicitly non-conformant.
 */
function mintExpiry(ctx: HandlerContext, createdAt: bigint): bigint | null {
  const callerExpiry = ctx.callerCapability === null ? null : ctx.callerCapability.expiresAt;
  return minDefined(
    callerExpiry,
    durationTerm(createdAt, policyTtlMs(ctx)),
    durationTerm(createdAt, Ecf.optUint(ctx.params.data, "ttl_ms")),
  );
}

/**
 * The `ttl_ms` of the policy entry that ceilings THIS caller, via the same v7.64
 * dual-form lookup the §4.4 authenticate path uses (hex → Base58 → `default`). This is
 * the term that makes policy withdrawal bounded on the `request` path: the entry's
 * `ttl_ms` is the withdrawal latency for tokens already issued.
 */
function policyTtlMs(ctx: HandlerContext): bigint | null {
  if (ctx.author === null) {
    return null;
  }
  const caller = ctx.envelope.find(ctx.author);
  if (caller === undefined) {
    return null;
  }
  const base = "/" + ctx.localPeerId + "/system/capability/policy/";
  let entry = ctx.peer.tree.get(base + hashHex(caller.contentHash));
  if (entry === undefined) {
    try {
      entry = ctx.peer.tree.get(base + peerEntityId(caller));
    } catch {
      // present identity with no usable key → no Base58 form; fall through to `default`
    }
  }
  entry = entry ?? ctx.peer.tree.get(base + "default");
  return entry === undefined ? null : Ecf.optUint(entry.data, "ttl_ms");
}

/**
 * A valid policy `peer_pattern` is one of three shapes (v7.62 §4 + v7.65 §3.6 rule
 * 3): the literal `"default"` fallback; a canonical hex content hash (66 chars
 * SHA-256 / 98 chars SHA-384); or a decodable Base58 wire-form peer_id.
 * Glob/partial-prefix patterns (e.g. `00abc*`) are rejected.
 */
function isValidPolicyPattern(pattern: string): boolean {
  if (pattern === "default") {
    return true;
  }
  if (pattern.includes("*")) {
    return false;
  }
  if (pattern.length === 66 || pattern.length === 98) {
    for (const c of pattern) {
      const hex = (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
      if (!hex) {
        return false;
      }
    }
    return true;
  }
  try {
    const pid = parsePeerId(pattern);
    return isSupportedKeyType(pid.keyType) && pid.digest.length > 0;
  } catch (e) {
    if (e instanceof EntityCodecError) {
      return false;
    }
    throw e;
  }
}

function ack(): Entity {
  return Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap());
}
