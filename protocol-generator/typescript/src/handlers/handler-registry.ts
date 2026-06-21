import { type EcfValue } from "../codec/ecf-value.js";
import { Entity, Ecf, TypeNames } from "../model/index.js";
import { CapabilityToken } from "../capability/index.js";
import { type Handler, type PeerServices } from "./handler-abstractions.js";

/**
 * A resolved dispatch target (§6.6): the peer-relative pattern, the URI suffix, and the
 * `system/handler` tree entity. `native` is the in-process executable for a bootstrap
 * handler, or null for a dynamically-registered (entity-native) handler whose body lives
 * at the entity's `expression_path`.
 */
export interface Resolution {
  readonly pattern: string;
  readonly suffix: string;
  readonly handlerEntity: Entity;
  readonly native: Handler | null;
}

/**
 * The in-memory dispatch index (V7 §6.1, §6.6): maps a handler pattern to its
 * executable {@link Handler}, and keeps the tree the source of truth by installing
 * the matching `system/handler` (dispatch target), `system/handler/interface`
 * (discovery), and `system/capability/grants/{pattern}` (authorization) entities.
 * The tree walk in {@link HandlerRegistry.resolve} produces results equivalent to a
 * pure §6.6 walk.
 */
export class HandlerRegistry {
  readonly #handlers = new Map<string, Handler>();
  readonly #peer: PeerServices;

  constructor(peer: PeerServices) {
    this.#peer = peer;
  }

  /**
   * Register a handler: index it by pattern and install its three tree entities.
   * Bootstrap handlers (§6.9) are installed this way during peer initialization.
   */
  register(handler: Handler): void {
    this.#handlers.set(handler.pattern, handler);

    // Peer-relative interface path (§6.2 N5): the `interface` field is a
    // system/tree/path, published peer-relative (no {peer_id} segment) — what a
    // remote resolves and what validate-peer's interface_ref check expects. The
    // tree *binding* below is still absolute.
    const interfaceRelPath = "system/handler/" + handler.pattern;
    const interfacePath = this.#absolutePath(interfaceRelPath);

    const ifaceEntity = Entity.create(
      TypeNames.HandlerInterface,
      Ecf.map(
        ["pattern", Ecf.text(handler.pattern)],
        ["name", Ecf.text(handler.name)],
        ["operations", operationsMap(handler.operations)],
      ),
    );

    const handlerEntity = Entity.create(TypeNames.Handler, Ecf.map(["interface", Ecf.text(interfaceRelPath)]));

    // Self-issued, signed, empty-scope grant (§6.8: empty grants are valid for
    // pure-functional handlers; bootstrap handlers authorize caller-specified tree
    // writes via the caller capability, not their own grant).
    const { token: grant, signature: grantSig } = CapabilityToken.createRoot(
      this.#peer.localIdentity,
      this.#peer.localIdentity.identityHash,
      [],
      this.#peer.nowMs,
    );

    this.#peer.tree.put(this.#absolutePath(handler.pattern), handlerEntity);
    this.#peer.tree.put(interfacePath, ifaceEntity);
    this.#peer.tree.put(this.#absolutePath("system/capability/grants/" + handler.pattern), grant.entity);
    // Bind the grant's signature at the §3.5 invariant pointer so dispatch-time
    // grant validation (§6.8 step 3) can find and verify it by tree lookup.
    this.#peer.tree.put(this.#absolutePath("system/signature/" + grant.contentHashHex), grantSig);
  }

  get(pattern: string): Handler | null {
    return this.#handlers.get(pattern) ?? null;
  }

  /**
   * Resolve a handler by walking backward from `canonicalPath` for the longest
   * `system/handler`-typed prefix (§6.6). A registered handler with no in-process
   * executable still resolves — its body is entity-native (the v7.74 §6.13(a)
   * dynamic-register surface), dispatched via its `expression_path`. `native` is null
   * for such a handler.
   */
  resolve(canonicalPath: string): Resolution | null {
    const segments = canonicalPath.replace(/^\/+/, "").split("/");
    for (let i = segments.length; i >= 1; i--) {
      const absPrefix = "/" + segments.slice(0, i).join("/");
      const entity = this.#peer.tree.get(absPrefix);
      if (entity !== undefined && entity.type === TypeNames.Handler) {
        const pattern = this.#stripPeer(absPrefix);
        const suffix = canonicalPath.slice(absPrefix.length);
        return { pattern, suffix, handlerEntity: entity, native: this.get(pattern) };
      }
    }
    return null;
  }

  /** Resolve a handler's grant from `system/capability/grants/{pattern}` (§6.8). */
  resolveGrant(pattern: string): CapabilityToken | null {
    const grant = this.#peer.tree.get(this.#absolutePath("system/capability/grants/" + pattern));
    return grant === undefined ? null : new CapabilityToken(grant);
  }

  #absolutePath(peerRelative: string): string {
    return "/" + this.#peer.localPeerId + "/" + peerRelative;
  }

  #stripPeer(absolutePath: string): string {
    const prefix = "/" + this.#peer.localPeerId + "/";
    return absolutePath.startsWith(prefix) ? absolutePath.slice(prefix.length) : absolutePath;
  }
}

function operationsMap(operations: readonly string[]): EcfValue {
  return Ecf.map(...operations.map((op) => [op, Ecf.emptyMap()] as [string, EcfValue]));
}
