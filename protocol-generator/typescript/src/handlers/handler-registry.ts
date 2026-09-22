import { type EcfValue } from "../codec/ecf-value.js";
import { Entity, Ecf, TypeNames } from "../model/index.js";
import { CapabilityToken } from "../capability/index.js";
import {
  type Handler,
  type HandlerOperations,
  type OperationSpec,
  type PeerServices,
} from "./handler-abstractions.js";
import { type HandlerBody, HandlerHandle, type HandlerSpec, RegisterError, handlerSpecProblem } from "./handler-install.js";
import { SpecRegistration } from "./spec-registration.js";

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
  #nextGeneration = 1;

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

  /**
   * `SDK-OPERATIONS` §11.6 / §11.6.1 — install a language-native body behind a spec and
   * return its handle (keystone peer contract `install.handler`, `install.grant`,
   * `install.types`). `Peer.registerHandler(spec, body)` is the public spelling.
   *
   * Refuses with {@link RegisterError} BEFORE writing anything: `400
   * invalid_handler_spec` for an invalid spec, `409 pattern_collision` when a handler is
   * already registered in this index (bootstrap or in-process) or a wire-registered
   * `system/handler` entity is bound at the pattern. `system/*` is not refused.
   *
   * Then: the dispatch index entry, and the five core §6.13(a) writes in the wire
   * register op's order — the `system/handler` entity at the pattern, the spec's types
   * at `system/type/{name}`, the handler's self-issued grant minted with
   * `internalScope` (EMPTY scope when null: a grant covering nothing), that grant's
   * signature at the §3.5 pointer, and the interface entity.
   */
  install(spec: HandlerSpec, body: HandlerBody): HandlerHandle {
    const problem = handlerSpecProblem(spec);
    if (problem !== null) {
      throw new RegisterError(400, "invalid_handler_spec", problem);
    }
    const pattern = spec.pattern;
    const bound = this.#peer.tree.get(this.#absolutePath(pattern));
    if (this.#handlers.has(pattern) || (bound !== undefined && bound.type === TypeNames.Handler)) {
      throw new RegisterError(409, "pattern_collision", `a handler is already registered at '${pattern}'`);
    }

    const generation = this.#nextGeneration++;
    this.#handlers.set(pattern, new SpecRegistration(spec, body, generation));

    const internalScope = spec.internalScope ?? null;
    const interfaceRelPath = "system/handler/" + pattern;
    // (1) handler entity (dispatch target) at the pattern.
    this.#peer.tree.put(
      this.#absolutePath(pattern),
      Entity.create(
        TypeNames.Handler,
        Ecf.map(
          ["interface", Ecf.text(interfaceRelPath)],
          ["internal_scope", internalScope === null ? null : Ecf.array(internalScope.map((g) => g.toEcf()))],
        ),
      ),
    );
    // (2) types.
    for (const [typeName, definition] of Object.entries(spec.types ?? {})) {
      this.#peer.tree.put(this.#absolutePath("system/type/" + typeName), Entity.create(TypeNames.Type, definition));
    }
    // (3)+(4) self-issued signed grant, scope = internal_scope (empty when null).
    const { token: grant, signature: grantSig } = CapabilityToken.createRoot(
      this.#peer.localIdentity,
      this.#peer.localIdentity.identityHash,
      internalScope ?? [],
      this.#peer.nowMs,
    );
    this.#peer.tree.put(this.#absolutePath("system/capability/grants/" + pattern), grant.entity);
    this.#peer.tree.put(this.#absolutePath("system/signature/" + grant.contentHashHex), grantSig);
    // (5) interface (discovery index).
    this.#peer.tree.put(
      this.#absolutePath(interfaceRelPath),
      Entity.create(
        TypeNames.HandlerInterface,
        Ecf.map(["pattern", Ecf.text(pattern)], ["name", Ecf.text(spec.name)], ["operations", operationsMap(spec.operations)]),
      ),
    );
    return new HandlerHandle(pattern, () => this.#closeRegistration(pattern, generation));
  }

  /**
   * §11.6.2 close: the dispatch index entry first, then the tree entries — only when the
   * live registration at `pattern` is still the one `generation` names. Types stay.
   */
  #closeRegistration(pattern: string, generation: number): boolean {
    const live = this.#handlers.get(pattern);
    if (!(live instanceof SpecRegistration) || live.generation !== generation) {
      return false;
    }
    this.#handlers.delete(pattern);
    const grantPath = this.#absolutePath("system/capability/grants/" + pattern);
    const grant = this.#peer.tree.get(grantPath);
    if (grant !== undefined) {
      this.#peer.tree.remove(this.#absolutePath("system/signature/" + grant.contentHashHex));
      this.#peer.tree.remove(grantPath);
    }
    this.#peer.tree.remove(this.#absolutePath(pattern));
    this.#peer.tree.remove(this.#absolutePath("system/handler/" + pattern));
    return true;
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

/**
 * Render §3.7's `operations` map: operation name -> `system/handler/operation-spec`.
 *
 * The bare-name form yields an empty spec per operation — both spec fields are
 * optional, so that is well-formed, and it is what every bootstrap handler produces
 * (byte-unchanged by the mapped form's introduction). The mapped form publishes the
 * `input_type` / `output_type` a handler declares, which is the half a code generator
 * needs and the half this surface could not express.
 */
function operationsMap(operations: HandlerOperations): EcfValue {
  if (Array.isArray(operations)) {
    return Ecf.map(...(operations as readonly string[]).map((op) => [op, Ecf.emptyMap()] as [string, EcfValue]));
  }
  const specs = operations as Readonly<Record<string, OperationSpec>>;
  return Ecf.map(
    ...Object.entries(specs).map(([op, spec]) => {
      const fields: [string, EcfValue][] = [];
      if (spec.inputType !== undefined) fields.push(["input_type", Ecf.text(spec.inputType)]);
      if (spec.outputType !== undefined) fields.push(["output_type", Ecf.text(spec.outputType)]);
      return [op, Ecf.map(...fields)] as [string, EcfValue];
    }),
  );
}
