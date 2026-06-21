import * as net from "node:net";
import { PeerIdentity } from "./identity/index.js";
import { ContentStore, EntityTree } from "./store/index.js";
import {
  CapabilityHandler,
  ConnectHandler,
  ConnectionState,
  type Handler,
  HandlerRegistry,
  HandlersHandler,
  type PeerServices,
  TreeHandler,
  ValidateEchoHandler,
  ValidateDispatchOutboundHandler,
} from "./handlers/index.js";
import { CapabilityToken, type GrantEntry, SeedPolicy } from "./capability/index.js";
import { EmitBus } from "./emit/index.js";
import { Entity, Ecf, TypeNames, hashHex } from "./model/index.js";
import { Dispatcher } from "./dispatch/index.js";
import { seedCoreTypes } from "./types/index.js";
import { PeerConnection, type PeerSession, initiate, respond } from "./transport/index.js";

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
    } = {},
  ) {
    this.#identity = options.identity ?? PeerIdentity.generate();
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
   * Install a native (in-process) handler post-bootstrap — the seam an SDK / native
   * extension uses to add a handler with a compiled body (complementing the wire
   * `register` of §6.13(a), which installs entity-native bodies).
   */
  registerHandler(handler: Handler): void {
    this.#registry.register(handler);
  }

  /** Begin listening on loopback at `port` (0 = auto-assign). Resolves with the bound port. */
  listen(port = 0): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      const server = net.createServer((socket) => this.#onInbound(socket));
      server.once("error", reject);
      server.listen(port, "127.0.0.1", () => {
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
    const conn = new PeerConnection(socket, this.#dispatcher, state);
    this.#connections.add(conn);
    conn.start();

    // Reverse-direction handshake (§4.1 E3): the responder sends its own
    // authenticate once it has the initiator's hello. Fire-and-forget — it
    // completes the mutual handshake; its session is not needed here.
    void this.#respondInBackground(conn, state);
  }

  async #respondInBackground(conn: PeerConnection, state: ConnectionState): Promise<void> {
    try {
      await respond(conn, this.#identity, state, HANDSHAKE_TIMEOUT_MS);
    } catch {
      // The reverse handshake is best-effort; failures don't affect the
      // initiator's already-established session.
    }
  }

  /** Dial a peer at `host:port` and complete the handshake, returning the session. */
  connect(host: string, port: number, timeoutMs = HANDSHAKE_TIMEOUT_MS): Promise<PeerSession> {
    return new Promise<PeerSession>((resolve, reject) => {
      const socket = net.connect({ host, port }, () => {
        socket.setNoDelay(true);
        const state = new ConnectionState();
        const conn = new PeerConnection(socket, this.#dispatcher, state);
        this.#connections.add(conn);
        conn.start();
        initiate(conn, this.#identity, state, timeoutMs).then(resolve, reject);
      });
      socket.once("error", reject);
    });
  }

  async dispose(): Promise<void> {
    if (this.#server !== null) {
      const server = this.#server;
      this.#server = null;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    for (const conn of this.#connections) {
      await conn.dispose();
    }
    this.#connections.clear();
  }
}

/** Build a `system/capability/policy-entry` carrying a scope template (§6.9a.0 shape 2 / v7.62 §4). */
function policyEntryEntity(peerPattern: string, grants: readonly GrantEntry[]): Entity {
  return Entity.create(
    TypeNames.CapabilityPolicyEntry,
    Ecf.map(["peer_pattern", Ecf.text(peerPattern)], ["grants", Ecf.array(grants.map((g) => g.toEcf()))]),
  );
}
