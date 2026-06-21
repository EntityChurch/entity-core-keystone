import { EntityProtocolError } from "../errors.js";
import {
  Ecf,
  Entity,
  Envelope,
  Execute,
  ExecuteResponse,
  Protocols,
  Status,
  TypeNames,
  hashEqual,
  hashHex,
} from "../model/index.js";
import { peerEntityId, signatureSigner, signatureTarget, verifySignature } from "../identity/index.js";
import { CapabilityToken, ChainVerifier, Paths, Permissions } from "../capability/index.js";
import {
  type ConnectionState,
  type Handler,
  HandlerContext,
  type HandlerRegistry,
  type PeerServices,
} from "../handlers/index.js";
import { type ReentrantSender } from "../transport/reentrant-sender.js";
import { OutboundDispatchImpl } from "./outbound-dispatch.js";

/**
 * The dispatch chain (V7 §6.5): decode → integrity verify → handler resolution →
 * permission check → handler execution, producing an EXECUTE_RESPONSE envelope.
 * Connection pre-authorization (§4.2) is the sole special case. Composes the
 * deterministic Layer-1 capability verdict ({@link ChainVerifier}) with the local
 * checks here; no Layer-1 hook reads local policy (§5.10 / N8).
 */
export class Dispatcher {
  readonly #peer: PeerServices;
  readonly #registry: HandlerRegistry;

  constructor(peer: PeerServices, registry: HandlerRegistry) {
    this.#peer = peer;
    this.#registry = registry;
  }

  /**
   * Dispatch an inbound EXECUTE envelope and return the response envelope. The
   * caller (connection reader) has already routed EXECUTE_RESPONSE roots to their
   * awaiting callers; only EXECUTE roots reach here.
   */
  async dispatch(request: Envelope, conn: ConnectionState, sender: ReentrantSender | null = null): Promise<Envelope> {
    let execute: Execute;
    try {
      execute = new Execute(request.root);
    } catch (e) {
      if (e instanceof EntityProtocolError) {
        return errorEnvelope("", Status.BadRequest, "invalid_request", e.message);
      }
      throw e;
    }

    let requestId: string;
    try {
      requestId = execute.requestId;
    } catch (e) {
      if (e instanceof EntityProtocolError) {
        return errorEnvelope("", Status.BadRequest, "invalid_request", e.message);
      }
      throw e;
    }

    // §6.5 robustness (Finding 1): verification/dispatch faults become an error
    // response — an inbound EXECUTE MUST never hang the peer.
    try {
      return await this.#dispatchCore(execute, request, requestId, conn, sender);
    } catch (e) {
      if (e instanceof EntityProtocolError) {
        return errorEnvelope(requestId, e.status, "request_error", e.message);
      }
      return errorEnvelope(requestId, Status.InternalError, "internal_error", errorMessage(e));
    }
  }

  async #dispatchCore(
    execute: Execute,
    request: Envelope,
    requestId: string,
    conn: ConnectionState,
    sender: ReentrantSender | null,
  ): Promise<Envelope> {
    let path: string;
    try {
      path = Paths.dispatchPath(execute.uri, this.#peer.localPeerId);
    } catch (e) {
      if (e instanceof EntityProtocolError) {
        return errorEnvelope(requestId, Status.BadRequest, "invalid_request", e.message);
      }
      throw e;
    }

    // Inbound dispatch MUST target the local peer (§1.4).
    if (Paths.extractPeer(path, this.#peer.localPeerId) !== this.#peer.localPeerId) {
      return errorEnvelope(requestId, Status.BadRequest, "invalid_request", "request does not target local peer");
    }

    // Connection pre-authorization (§4.2, §6.5) — the sole no-auth special case.
    const connectPath = "/" + this.#peer.localPeerId + "/" + Protocols.ConnectPath;
    if (path === connectPath && !conn.established) {
      const connect = this.#registry.get(Protocols.ConnectPath);
      if (connect === null) {
        return errorEnvelope(requestId, Status.InternalError, "no_connect_handler", "connect handler missing");
      }
      return this.#runHandler(connect, execute, request, conn, null, null, Protocols.ConnectPath, "", sender);
    }

    // Authenticated path. Every EXECUTE MUST carry author + capability (§5.1). A
    // missing author is authentication-class → 401; a missing capability is
    // authorization-class → 403 (§3.3 two-level model).
    if (execute.author === null) {
      return errorEnvelope(requestId, Status.Unauthorized, "missing_author", "author required");
    }
    if (execute.capability === null) {
      return errorEnvelope(requestId, Status.Forbidden, "missing_authorization", "capability required");
    }

    // Ingest envelope signatures to their invariant pointer paths (§6.5).
    this.#ingestSignatures(request);

    // Integrity + capability verification (§5.2 verify_request).
    const verify = this.#verifyRequest(execute, request);
    if (verify.status !== Status.Ok) {
      return errorEnvelope(requestId, verify.status, verify.code!, verify.message);
    }

    // Resolve handler by tree walk (§6.6). No match → 404.
    const res = this.#registry.resolve(path);
    if (res === null) {
      return errorEnvelope(requestId, Status.NotFound, "not_found", `no handler resolves ${path}`);
    }

    // Dispatch permission check (§5.2 check_permission). §PR-8: resolve the cap's granter
    // once here; its grant resource patterns canonicalize against that frame. Register/
    // unregister ride this same boundary (B1 / V2.0/L1) — the EXECUTE.resource install
    // path is the authorization target.
    const capability = verify.capability!;
    const granterPeerId = Permissions.resolveGranterPeerId(capability, request, this.#peer.localPeerId);
    if (!Permissions.checkPermission(execute, capability, res.pattern, this.#peer.localPeerId, granterPeerId)) {
      return errorEnvelope(requestId, Status.Forbidden, "capability_denied", "capability does not grant the operation");
    }

    // Resolve + validate the handler grant (§6.8 dispatch-time grant validation). A
    // dynamically-registered handler's grant was written by register.
    const handlerGrant = this.#registry.resolveGrant(res.pattern);
    if (handlerGrant === null || !this.#validateHandlerGrant(handlerGrant)) {
      return errorEnvelope(requestId, Status.Forbidden, "permission_denied", "handler grant missing or invalid");
    }

    // Bootstrap handler (in-process body) vs dynamically-registered handler (entity-native
    // body at expression_path, v7.74 §6.13(a)).
    if (res.native !== null) {
      return this.#runHandler(res.native, execute, request, conn, capability, handlerGrant, res.pattern, res.suffix, sender);
    }
    return this.#runEntityNative(res.handlerEntity, execute);
  }

  /**
   * Dispatch a dynamically-registered (entity-native) handler by evaluating the body at
   * its `expression_path` (v7.74 §6.13(a)). The core peer's body-binding seam (impl-private
   * per §9.4) evaluates the minimal `compute/literal` shape and returns a `compute/result`,
   * which is what the §10.1 register round-trip exercises. Richer bodies need the compute
   * extension (501). See A-011.
   */
  #runEntityNative(handlerEntity: Entity, execute: Execute): Envelope {
    const exprPath = Ecf.optText(handlerEntity.data, "expression_path");
    if (exprPath === null) {
      return errorEnvelope(execute.requestId, Status.NotSupported, "no_handler_body", "registered handler has neither a native body nor an expression_path");
    }

    const absExpr = Paths.canonicalize(exprPath, this.#peer.localPeerId);
    const expr = this.#peer.tree.get(absExpr);
    if (expr === undefined) {
      return errorEnvelope(execute.requestId, Status.NotFound, "expression_not_found", `no entity bound at the handler's expression_path ${absExpr}`);
    }

    if (expr.type === TypeNames.ComputeLiteral) {
      const value = Ecf.require(expr.data, "value");
      const result = Entity.create(TypeNames.ComputeResult, Ecf.map(["value", value], ["expression", Ecf.bytes(expr.contentHash)]));
      const response = ExecuteResponse.build(execute.requestId, Status.Ok, result);
      return new Envelope(response.entity, []);
    }

    return errorEnvelope(execute.requestId, Status.NotSupported, "unsupported_expression", "core peer evaluates only compute/literal bodies (the entity-native seam); richer bodies need the compute extension");
  }

  async #runHandler(
    handler: Handler,
    execute: Execute,
    request: Envelope,
    conn: ConnectionState,
    callerCapability: CapabilityToken | null,
    handlerGrant: CapabilityToken | null,
    pattern: string,
    suffix: string,
    sender: ReentrantSender | null,
  ): Promise<Envelope> {
    const context = new HandlerContext({
      peer: this.#peer,
      execute,
      envelope: request,
      pattern,
      suffix,
      callerCapability,
      handlerGrant,
      author: execute.author,
      connection: conn,
      // §6.13(b) handler-facing outbound seam — routes through §6.11 reentry on the
      // serving connection. Present whenever a reentrant sender is available.
      outbound: sender === null ? null : new OutboundDispatchImpl(this.#peer.localIdentity, sender),
    });

    try {
      const result = await handler.handle(context);
      const response = ExecuteResponse.build(execute.requestId, result.status, result.result);
      return new Envelope(response.entity, result.included);
    } catch (e) {
      if (e instanceof EntityProtocolError) {
        return errorEnvelope(execute.requestId, e.status, "handler_error", e.message);
      }
      return errorEnvelope(execute.requestId, Status.InternalError, "internal_error", errorMessage(e));
    }
  }

  /** Request integrity + capability verification (§5.2). Revocation skipped (supports_revocation=false). */
  #verifyRequest(execute: Execute, envelope: Envelope): VerifyResult {
    const authorHash = execute.author!;
    const capabilityHash = execute.capability!;

    // Signature (target-matching) over the EXECUTE.
    const signature = ChainVerifier.findSignature(envelope, execute.entity.contentHash);
    if (signature === null) {
      return deny(Status.Unauthorized, "invalid_signature", "no signature for EXECUTE");
    }
    if (!hashEqual(signatureSigner(signature), authorHash)) {
      return deny(Status.Unauthorized, "invalid_signature", "signature signer is not the author");
    }
    const author = envelope.find(authorHash);
    if (author === undefined) {
      return deny(Status.Unauthorized, "unresolvable_author", "author identity not in included");
    }
    if (!verifySignature(signature, author)) {
      return deny(Status.Unauthorized, "invalid_signature", "EXECUTE signature does not verify");
    }

    // Capability integrity.
    const capabilityEntity = envelope.find(capabilityHash);
    if (capabilityEntity === undefined) {
      return deny(Status.Forbidden, "capability_denied", "capability not in included");
    }
    const capability = new CapabilityToken(capabilityEntity);

    // §5.2 / §3.6 PR-3 single-401 carve-out: the leaf cap's grantee MUST resolve to
    // a present system/peer entity. An unresolvable grantee is authentication-class
    // — 401 unresolvable_grantee — pinned to fire BEFORE the structural
    // grantee==author check (which keeps its 403).
    const granteeEntity = envelope.find(capability.grantee);
    if (granteeEntity === undefined || granteeEntity.type !== TypeNames.Peer) {
      return deny(Status.Unauthorized, "unresolvable_grantee", "leaf cap grantee does not resolve to a system/peer entity");
    }
    if (!hashEqual(capability.grantee, authorHash)) {
      return deny(Status.Forbidden, "capability_denied", "capability grantee is not the author");
    }
    // §4.10(b) resource bound: a chain exceeding the peer's max depth is rejected as
    // 400 chain_depth_exceeded (structural excess) BEFORE the per-link authz walk —
    // distinct from 403 capability_denied. Arch v7.75 ruling: 400 lets the caller
    // distinguish "shorten your chain" from "you lack the capability".
    if (ChainVerifier.exceedsMaxDepth(capability, envelope)) {
      return deny(Status.BadRequest, "chain_depth_exceeded", "capability chain exceeds max depth (§4.10b)");
    }
    if (!ChainVerifier.verifyCapabilityChain(capability, envelope, this.#peer.localPeerId, this.#peer.nowMs)) {
      return deny(Status.Forbidden, "capability_denied", "capability chain verification failed");
    }

    // §5.2 step 4: revocation. A revoked link anywhere in the chain denies with the
    // specific code 403 capability_revoked (Class C ruling 2026-06-11).
    if (this.#isChainRevoked(capability, envelope)) {
      return deny(Status.Forbidden, "capability_revoked", "capability is revoked (§5.1)");
    }

    return ok(capability);
  }

  /**
   * §5.1 `is_revoked` over the full authority chain: true if any link's content
   * hash has a revocation marker bound at
   * `/{local}/system/capability/revocations/{hash_hex}`. Walks leaf → root via
   * parent pointers in `included`; the chain has already verified.
   */
  #isChainRevoked(leaf: CapabilityToken, envelope: Envelope): boolean {
    let current: CapabilityToken | null = leaf;
    let depth = 0;
    while (current !== null && depth <= 64) {
      const path = "/" + this.#peer.localPeerId + "/system/capability/revocations/" + current.contentHashHex;
      if (this.#peer.tree.get(path) !== undefined) {
        return true;
      }
      if (current.parent === null) {
        break;
      }
      const parent = envelope.find(current.parent);
      if (parent === undefined) {
        break;
      }
      current = new CapabilityToken(parent);
      depth++;
    }
    return false;
  }

  /** Dispatch-time handler-grant validation (§6.8): self-issued by the local peer, signed, temporal. */
  #validateHandlerGrant(grant: CapabilityToken): boolean {
    if (grant.granter === null || !hashEqual(grant.granter, this.#peer.localIdentity.identityHash)) {
      return false; // handler grants are self-issued single-sig
    }
    // Signature at the §3.5 invariant pointer path.
    const sig = this.#peer.tree.get("/" + this.#peer.localPeerId + "/system/signature/" + grant.contentHashHex);
    if (sig === undefined || !verifySignature(sig, this.#peer.localIdentity.peerEntity)) {
      return false;
    }
    if (grant.notBefore !== null && this.#peer.nowMs < grant.notBefore) {
      return false;
    }
    if (grant.expiresAt !== null && grant.expiresAt < this.#peer.nowMs) {
      return false;
    }
    return true;
  }

  /**
   * Bind `system/signature` entities from `included` at their invariant pointer
   * paths (§6.5 ingest_envelope_signatures), so handler validation can find them by
   * tree lookup. Idempotent on content hash.
   */
  #ingestSignatures(envelope: Envelope): void {
    for (const entity of envelope.included.values()) {
      if (entity.type !== TypeNames.Signature) {
        continue;
      }
      this.#peer.contentStore.put(entity);

      const signerHash = signatureSigner(entity);
      const signerPeer = envelope.find(signerHash) ?? this.#peer.contentStore.get(signerHash);
      if (signerPeer === undefined) {
        continue; // cannot recover signer peer id; skip binding
      }
      this.#peer.contentStore.put(signerPeer);

      const path = "/" + peerEntityId(signerPeer) + "/system/signature/" + hashHex(signatureTarget(entity));
      if (this.#peer.tree.get(path) === undefined) {
        this.#peer.tree.put(path, entity);
      }
    }
  }
}

/** The outcome of {@link Dispatcher.verifyRequest}: a status (+ deny code/message) or an allowed capability. */
interface VerifyResult {
  readonly status: number;
  readonly code: string | null;
  readonly message: string | null;
  readonly capability: CapabilityToken | null;
}

function ok(capability: CapabilityToken): VerifyResult {
  return { status: Status.Ok, code: null, message: null, capability };
}

function deny(status: number, code: string, message: string): VerifyResult {
  return { status, code, message, capability: null };
}

function errorEnvelope(requestId: string, status: number, code: string, message: string | null): Envelope {
  const response = ExecuteResponse.error(requestId, status, code, message);
  return new Envelope(response.entity, []);
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
