import { readFileSync } from "node:fs";
import * as net from "node:net";
import { PeerIdentity } from "./identity/index.js";
import { ContentStore, EntityTree } from "./store/index.js";
import {
  CapabilityHandler,
  ConnectHandler,
  ConnectionState,
  type ExpressionEvaluator,
  type Handler,
  type HandlerBody,
  type HandlerHandle,
  HandlerRegistry,
  type HandlerSpec,
  HandlersHandler,
  type PeerServices,
  TreeHandler,
  ValidateEchoHandler,
  ValidateDispatchOutboundHandler,
} from "./handlers/index.js";
import { CapabilityToken, type GrantEntry, SeedPolicy, SeedPolicyError } from "./capability/index.js";
import { EmitBus } from "./emit/index.js";
import { Entity, Ecf, TypeNames, hashHex } from "./model/index.js";
import { Dispatcher } from "./dispatch/index.js";
import { seedCoreTypes } from "./types/index.js";
import { DEFAULT_MAX_FRAME_BYTES, PeerConnection, type PeerSession, initiate } from "./transport/index.js";

const HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * An Entity Core protocol peer (V7 Layers 0–4): identity, the codec, the entity
 * tree + content store, the bootstrap system handlers, the dispatch chain, and TCP
 * transport. Listens for inbound connections and dials outbound ones; both
 * directions complete the §4.1 handshake. No standard extensions are bundled —
 * community handlers register above the dispatcher boundary.
 */
export class Peer implements PeerServices {
  readonly #identity: PeerIdentity;
  readonly #emit: EmitBus;
  readonly #tree: EntityTree;
  readonly #store: ContentStore;
  readonly #registry: HandlerRegistry;
  readonly #dispatcher: Dispatcher;
  readonly #connections = new Set<PeerConnection>();
  readonly #seedPolicy: SeedPolicy;
  readonly #maxFrameBytes: number;
  #server: net.Server | null = null;
  #port = 0;

  /**
   * @param options.identity Peer identity; a fresh Ed25519 keypair is generated when omitted.
   * @param options.seedPolicy The §6.9a identity → capability seed policy materialized at
   * L0 and consulted at §4.6 authenticate (the `withSeedPolicy` builder affordance).
   * Defaults to the conformant {@link SeedPolicy.standard} (default → §4.4 discovery floor),
   * or — when `debugOpenGrants` is set — {@link SeedPolicy.debugOpen} (default → `*`).
   * @param options.debugOpenGrants Debug-only: select the degenerate `default → *` seed
   * policy (the retired `--debug-open-grants` behaviour, now routed through the real §6.9a
   * mechanism). Deprecated in v7.74, removed in v7.75. Ignored when `seedPolicy` is supplied.
   */
  constructor(
    options: {
      identity?: PeerIdentity;
      seedPolicy?: SeedPolicy;
      debugOpenGrants?: boolean;
      /**
       * Conformance-build opt-in (GUIDE-CONFORMANCE §7a): register the `system/validate/*`
       * test-handlers (`echo` + `dispatch-outbound`) so a black-box validator can drive the
       * §6.13(a)/(b) extensibility hooks. Conformance scaffolding, **not core protocol**, and
       * **off by default** — `dispatch-outbound` is an outbound originator that must never be
       * live in production. Surfaced as the host `--validate` switch.
       */
      conformanceHandlers?: boolean;
      /**
       * The frame budget (§1.6) applied to connections this peer opens or accepts, in
       * bytes. Defaults to {@link DEFAULT_MAX_FRAME_BYTES}. Surfaced to handler bodies
       * through `HandlerContext.frameBudget()` so a body sizes its response against the
       * limit its response is actually measured against.
       */
      maxFrameBytes?: number;
    } = {},
  ) {
    this.#identity = options.identity ?? PeerIdentity.generate();
    this.#maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
    this.#seedPolicy = options.seedPolicy ?? (options.debugOpenGrants ? SeedPolicy.debugOpen() : SeedPolicy.standard());
    this.#emit = new EmitBus();
    this.#store = new ContentStore(this.#emit);
    this.#tree = new EntityTree(this.#store, this.#emit);
    this.#registry = new HandlerRegistry(this);
    this.#dispatcher = new Dispatcher(this, this.#registry);
    this.#bootstrap();
    if (options.conformanceHandlers) {
      // §7a.2: registered only on the conformance opt-in; never in a default/production peer.
      this.registerHandler(new ValidateEchoHandler());
      this.registerHandler(new ValidateDispatchOutboundHandler());
    }
  }

  // ----- PeerServices ---------------------------------------------------

  get localPeerId(): string {
    return this.#identity.peerId;
  }

  get localIdentity(): PeerIdentity {
    return this.#identity;
  }

  get tree(): EntityTree {
    return this.#tree;
  }

  get contentStore(): ContentStore {
    return this.#store;
  }

  get emit(): EmitBus {
    return this.#emit;
  }

  get nowMs(): bigint {
    return BigInt(Date.now());
  }

  /** The peer's configured default frame budget (§1.6), in bytes. */
  get maxFrameBytes(): number {
    return this.#maxFrameBytes;
  }

  /** The port the listener is bound to (valid after {@link listen}). */
  get port(): number {
    return this.#port;
  }

  // ----- lifecycle ------------------------------------------------------

  #bootstrap(): void {
    // Bootstrap handlers (§6.9): tree + connect + handlers + capability are MUST. The
    // handlers handler (§6.2 / §6.13(a)) executes register/unregister behaviorally — a 501
    // stub is non-conformant. (Types handler SHOULD remains A-007.)
    this.#registry.register(new ConnectHandler());
    this.#registry.register(new TreeHandler());
    this.#registry.register(new HandlersHandler());
    this.#registry.register(new CapabilityHandler());

    // Local peer entity at system/peer/self (§3.13), tree-walkable.
    this.#tree.put("/" + this.localPeerId + "/system/peer/self", this.#identity.peerEntity);

    // Core type registry → system/type/* (TYPE-SYSTEM §8–§10). Core + operational +
    // type-system bootstrap only (53 types; refined G4 / F17).
    seedCoreTypes(this.#tree, this.localPeerId);

    // §6.9a Peer Authority Bootstrap: materialize the seed capability entities into the
    // tree at L0 — the self-owner cap plus the seed-policy entries authenticate reads back.
    this.#seedAuthorityBootstrap();
  }

  /**
   * §6.9a Bootstrap L0 write-set (item 4): materialize the seed capability entities — the
   * `self`-owner capability (a root cap, full scope over `/{peer_id}/*`, grantee = the
   * peer's own identity, in the §6.9a.0 detached-signature shape: the cap token at the hex
   * policy path, its self-signature at the §3.5 invariant pointer), the `default` scope
   * template at the sentinel path, and any explicitly-named entries (§6.9a.1). Read back by
   * {@link ConnectHandler} at §4.6 authenticate via the v7.64 dual-form lookup.
   */
  #seedAuthorityBootstrap(): void {
    const policyBase = "/" + this.localPeerId + "/system/capability/policy/";

    // (1) self-owner capability (§6.9a.0 shape 1 — detached-signature).
    const { token: ownerCap, signature: ownerSig } = CapabilityToken.createRoot(
      this.#identity,
      this.#identity.identityHash,
      SeedPolicy.ownerGrants(this.localPeerId),
      this.nowMs,
    );
    this.#tree.put(policyBase + hashHex(this.#identity.identityHash), ownerCap.entity);
    this.#tree.put("/" + this.localPeerId + "/system/signature/" + ownerCap.contentHashHex, ownerSig);

    // (2) default seed entry — the fallback scope for any other authenticated identity.
    this.#tree.put(policyBase + "default", policyEntryEntity("default", this.#seedPolicy.defaultGrants));

    // (3) explicitly-named operator/admin/reader entries.
    for (const entry of this.#seedPolicy.namedEntries) {
      this.#tree.put(policyBase + entry.key, policyEntryEntity(entry.key, entry.grants));
    }
  }

  /**
   * `SDK-OPERATIONS` §11.6 — install a language-native body behind a {@link HandlerSpec}
   * and return its {@link HandlerHandle} (keystone peer contract `install.handler`,
   * `install.remove`, `install.grant`, `install.types`). This is the certified
   * registration surface.
   *
   * Performs the core §6.13(a) writes (types, `system/handler` entity, the handler's
   * grant minted with `spec.internalScope` — a grant covering nothing when null — its
   * signature, the interface) and binds the body in the dispatch index. Throws
   * {@link RegisterError} before writing anything: `409 pattern_collision` for a bound
   * pattern (including a bootstrap one), `400 invalid_handler_spec` for an invalid spec.
   * Does not refuse `system/*`. The body receives a {@link DispatchContext}, which only
   * the dispatcher constructs.
   */
  registerHandler(spec: HandlerSpec, body: HandlerBody): HandlerHandle;
  /**
   * Install a native (in-process) handler post-bootstrap — the seam an SDK / native
   * extension uses to add a handler with a compiled body (complementing the wire
   * `register` of §6.13(a), which installs entity-native bodies).
   *
   * The pre-contract surface, kept as it was: it replaces whatever is installed at the
   * pattern, refuses nothing, writes an empty-scope grant, and hands the body a
   * {@link HandlerContext} anyone can construct. **Not a keystone peer contract binding,
   * and not certified** — build on `registerHandler(spec, body)`.
   */
  registerHandler(handler: Handler): void;
  registerHandler(handlerOrSpec: Handler | HandlerSpec, body?: HandlerBody): HandlerHandle | void {
    if (typeof body === "function") {
      return this.#registry.install(handlerOrSpec as HandlerSpec, body);
    }
    this.#registry.register(handlerOrSpec as Handler);
  }

  /**
   * Install (or clear, with `null`) the evaluator for §6.13(a) entity-native handler
   * bodies — the seam a compute extension occupies.
   *
   * The built-in `compute/literal` fast path is unaffected and still answers first; an
   * installed evaluator receives only the bodies the core peer would otherwise refuse
   * with `501 unsupported_expression`, and may itself decline (`null`) to leave that
   * `501` in place. A peer with no evaluator installed behaves exactly as before.
   */
  setExpressionEvaluator(evaluator: ExpressionEvaluator | null): void {
    this.#dispatcher.setExpressionEvaluator(evaluator);
  }

  /** The installed §6.13(a) body evaluator, or `null` when none is installed. */
  get expressionEvaluator(): ExpressionEvaluator | null {
    return this.#dispatcher.expressionEvaluator;
  }

  /**
   * Begin listening at `host:port` (0 = auto-assign; `host` defaults to loopback).
   * Resolves with the bound port.
   */
  listen(port = 0, host = "127.0.0.1"): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      const server = net.createServer((socket) => this.#onInbound(socket));
      server.once("error", reject);
      server.listen(port, host, () => {
        const address = server.address();
        this.#port = typeof address === "object" && address !== null ? address.port : port;
        this.#server = server;
        resolve(this.#port);
      });
    });
  }

  #onInbound(socket: net.Socket): void {
    socket.setNoDelay(true);
    const state = new ConnectionState();
    const conn = new PeerConnection(socket, this.#dispatcher, state, this.#maxFrameBytes);
    this.#connections.add(conn);
    conn.start();

    // No reverse-direction handshake here (§4.1 leg 3). The spec pins leg 3 as
    // OPTIONAL and reachability-gated, deferred until a signaling mechanism (a
    // `hello` "accepts-inbound" capability or similar) is designed: "A responder
    // MUST NOT proactively send a leg-3 authenticate to an initiator that has
    // not indicated it accepts inbound dispatch... An unsolicited inbound
    // authenticate corrupts a client-style initiator's next read." (§4.1; "no
    // reference impl currently sends leg 3"). This peer previously fired it
    // unconditionally on every inbound connection — a real conformance bug, not
    // a cosmetic one: it is the confirmed root cause of the
    // connectivity/handshake_nonce_single_use (RT-6) failure, where this eager
    // leg-3 EXECUTE reliably outraced a same-connection follow-up request (the
    // RT-6 replay probe) and got read by the peer on the other end as if it
    // were that request's response, desyncing the exchange and causing it to
    // disconnect before the real response was written.
  }

  /** Dial a peer at `host:port` and complete the handshake, returning the session. */
  connect(host: string, port: number, timeoutMs = HANDSHAKE_TIMEOUT_MS): Promise<PeerSession> {
    return new Promise<PeerSession>((resolve, reject) => {
      const socket = net.connect({ host, port }, () => {
        socket.setNoDelay(true);
        const state = new ConnectionState();
        const conn = new PeerConnection(socket, this.#dispatcher, state, this.#maxFrameBytes);
        this.#connections.add(conn);
        conn.start();
        initiate(conn, this.#identity, state, timeoutMs).then(resolve, reject);
      });
      socket.once("error", reject);
    });
  }

  /**
   * Stop listening and close every connection. The listening socket is released FIRST
   * and synchronously: `server.close` stops accepting at once, but its callback waits for
   * open connections to end, so awaiting it before destroying them could hold the process
   * (and never release the peer) for as long as a client keeps a connection open.
   */
  async dispose(): Promise<void> {
    let closed: Promise<void> = Promise.resolve();
    if (this.#server !== null) {
      const server = this.#server;
      this.#server = null;
      closed = new Promise<void>((resolve) => server.close(() => resolve()));
    }
    for (const conn of this.#connections) {
      await conn.dispose();
    }
    this.#connections.clear();
    await closed;
  }
}

/**
 * Load a keystone seed-policy file (`--seed-policy <path>`; convention README §5
 * `with_seed_policy_from_file`) and return it as a {@link Peer} options fragment:
 *
 *     new Peer({ identity, ...withSeedPolicyFromFile("policy.json") })
 *
 * Parsing and every refusal are {@link SeedPolicy.fromJson}'s; this adds only the read,
 * and prefixes any error with the path. Lives in the Node layer (beside `node:net`) so
 * `capability/` stays free of `node:*` imports for the browser bundle.
 */
export function withSeedPolicyFromFile(path: string): { seedPolicy: SeedPolicy } {
  let text: string;
  try {
    // Fatal decode: invalid UTF-8 is refused, not replaced with U+FFFD.
    text = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path));
  } catch (err) {
    throw new SeedPolicyError(`${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    return { seedPolicy: SeedPolicy.fromJson(text) };
  } catch (err) {
    throw new SeedPolicyError(`${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Build a `system/capability/policy-entry` carrying a scope template (§6.9a.0 shape 2 / v7.62 §4). */
function policyEntryEntity(peerPattern: string, grants: readonly GrantEntry[]): Entity {
  return Entity.create(
    TypeNames.CapabilityPolicyEntry,
    Ecf.map(["peer_pattern", Ecf.text(peerPattern)], ["grants", Ecf.array(grants.map((g) => g.toEcf()))]),
  );
}
