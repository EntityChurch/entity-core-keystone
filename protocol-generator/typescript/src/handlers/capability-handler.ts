import { parsePeerId } from "../codec/peer-id.js";
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
        "requested grant exceeds the caller's presented authority (§6.2 / §5.6)",
      );
    }

    const ttlMs = Ecf.optUint(ctx.params.data, "ttl_ms");
    const expiresAt = ttlMs === null ? null : ctx.peer.nowMs + ttlMs;

    // The core peer grants the requested (now-bounded) scope from its own root
    // authority (the peer is the sole root for caps it issues, §5.5).
    const { token, signature } = CapabilityToken.createRoot(
      ctx.peer.localIdentity,
      granteePeer.contentHash,
      requested,
      ctx.peer.nowMs,
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
        'peer_pattern MUST be "default", a 66/98-char hex content hash, or a Base58 peer_id; partial prefixes are rejected (v7.62 §4)',
      );
    }
    // v7.62 §4: a policy entry MUST carry at least one grant.
    if (Ecf.asArray(Ecf.require(ctx.params.data, "grants")).length === 0) {
      return errorResult(Status.BadRequest, "invalid_params", "policy-entry MUST specify at least one grant (v7.62 §4)");
    }

    const path = Paths.canonicalize("system/capability/policy/" + peerPattern, ctx.localPeerId);
    ctx.peer.tree.put(path, ctx.params);
    return HandlerResult.ok(ack());
  }

  #revoke(ctx: HandlerContext): HandlerResult {
    const token = Ecf.optBytes(ctx.params.data, "token");
    if (token === null || isZeroHash(token)) {
      return errorResult(Status.BadRequest, "invalid_params", "revoke-request.token must be non-zero (v7.62 §10)");
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
