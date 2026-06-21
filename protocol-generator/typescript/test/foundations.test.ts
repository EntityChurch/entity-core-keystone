import { test } from "node:test";
import assert from "node:assert/strict";
import { ecfPreEncoded } from "../src/codec/ecf-value.js";
import {
  type ContentStoreEvent,
  Ecf,
  EmitBus,
  type EmitConsumer,
  Entity,
  GrantEntry,
  OutboundDispatchImpl,
  type OutboundAuthority,
  Peer,
  PeerIdentity,
  PeerSession,
  CapabilityToken,
  type ReentrantSender,
  ResourceTarget,
  Scope,
  SeedPolicy,
  Status,
  TreeChangeKind,
  type TreeChangeEvent,
  ContentStore,
  EntityTree,
  Envelope,
  Execute,
  ExecuteResponse,
  TypeNames,
  ChainVerifier,
  signatureSigner,
  verifySignature,
  type Handler,
  type HandlerContext,
  HandlerResult,
} from "../src/index.js";

const TIMEOUT = 10_000;
const PATTERN = "app/validate/core-register/echo";
const EXPR_PATH = PATTERN + "/expr";
const INSTALL_TARGET = "system/handler/" + PATTERN;

function treePut(session: PeerSession, path: string, entity: Entity): Promise<ExecuteResponse> {
  const putReq = Entity.create("system/tree/put-request", Ecf.map(["entity", ecfPreEncoded(entity.wireBytes)]));
  return session.execute("system/tree", "put", putReq, new ResourceTarget([path], null), TIMEOUT);
}

function treeGet(session: PeerSession, path: string): Promise<ExecuteResponse> {
  return session.execute(
    "system/tree",
    "get",
    Entity.create("system/tree/get-request", Ecf.emptyMap()),
    new ResourceTarget([path], null),
    TIMEOUT,
  );
}

// F1 — register/unregister round-trip mirroring entity-core-go core_register_gate.go.
test("F1: register (5 writes) → entity-native dispatch (42) → unregister (sig removed)", async () => {
  const responder = new Peer({ seedPolicy: SeedPolicy.debugOpen() });
  const initiator = new Peer();
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);

    // Step 1 — body-binding seam: put a compute/literal(42) at the expression path.
    const literal = Entity.create(TypeNames.ComputeLiteral, Ecf.map(["value", Ecf.uint(42n)]));
    assert.equal((await treePut(session, EXPR_PATH, literal)).statusCode, Status.Ok);

    // Step 2 — wire register.
    const reg = await session.execute("system/handler", "register", buildRegisterRequest(), new ResourceTarget([INSTALL_TARGET], null), TIMEOUT);
    assert.equal(reg.statusCode, Status.Ok);
    assert.equal(reg.result.type, TypeNames.HandlerRegisterResult);
    assert.equal(Ecf.requireText(reg.result.data, "pattern"), PATTERN);

    // Step 3 — the five normative writes landed.
    assert.equal((await treeGet(session, INSTALL_TARGET)).result.type, TypeNames.HandlerInterface); // 5. interface
    assert.equal((await treeGet(session, PATTERN)).result.type, TypeNames.Handler); // 1. manifest
    const grantGet = await treeGet(session, "system/capability/grants/" + PATTERN); // 3. grant
    assert.equal(grantGet.result.type, TypeNames.CapabilityToken);
    const grantHashHex = grantGet.result.contentHashHex;
    assert.equal((await treeGet(session, "system/signature/" + grantHashHex)).result.type, TypeNames.Signature); // 4.

    // Step 4 — dispatch round-trip: the entity-native body returns the literal 42.
    const dispatch = await session.execute(PATTERN, "compute", PeerSession.emptyParams(), null, TIMEOUT);
    assert.equal(dispatch.statusCode, Status.Ok);
    assert.equal(dispatch.result.type, TypeNames.ComputeResult);
    assert.equal(Ecf.requireUint(dispatch.result.data, "value"), 42n);

    // Step 5 — unregister, and the grant-signature is removed too.
    const unreg = await session.execute("system/handler", "unregister", PeerSession.emptyParams(), new ResourceTarget([INSTALL_TARGET], null), TIMEOUT);
    assert.equal(unreg.statusCode, Status.Ok);
    assert.equal((await treeGet(session, "system/signature/" + grantHashHex)).statusCode, Status.NotFound);
    assert.equal((await treeGet(session, PATTERN)).statusCode, Status.NotFound);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
});

function buildRegisterRequest(): Entity {
  const wildcard = new GrantEntry(new Scope(["*"], null), new Scope(["*", "/*/*"], null), new Scope(["*"], null), null, null, null);
  const manifest = Ecf.map(
    ["pattern", Ecf.text(PATTERN)],
    ["name", Ecf.text("echo")],
    ["operations", Ecf.map(["compute", Ecf.map(["input_type", Ecf.text("primitive/any")], ["output_type", Ecf.text("primitive/any")])])],
    ["expression_path", Ecf.text(EXPR_PATH)],
    ["internal_scope", Ecf.array([wildcard.toEcf()])],
  );
  return Entity.create(TypeNames.HandlerRegisterRequest, Ecf.map(["manifest", manifest], ["requested_scope", Ecf.array([wildcard.toEcf()])]));
}

// F3 — emit pathway: event-type derivation, no-op suppression, marker → modified.
test("F3: emit event-type derivation + no-op suppression + marker→modified", () => {
  const bus = new EmitBus();
  const changes: TreeChangeEvent[] = [];
  const stores: ContentStoreEvent[] = [];
  const consumer: EmitConsumer = {
    name: "rec",
    onContentStore: (ev) => stores.push(ev),
    onTreeChange: (ev) => changes.push(ev),
  };
  bus.registerConsumer(consumer);
  const tree = new EntityTree(new ContentStore(bus), bus);
  const e = (b: string): Entity => Entity.create(TypeNames.PrimitiveAny, Ecf.map(["v", Ecf.text(b)]));
  const P = "/peer/app/x";

  tree.put(P, e("one")); // created
  tree.put(P, e("two")); // modified
  tree.put(P, e("two")); // no-op re-bind to current hash → suppressed
  tree.remove(P); // deleted

  assert.deepEqual(changes.map((c) => c.eventType), [TreeChangeKind.Created, TreeChangeKind.Modified, TreeChangeKind.Deleted]);
  assert.equal(changes[0]!.previousHash, null);
  assert.equal(changes[2]!.newHash, null);
  assert.equal(stores.length, 2); // two distinct entities

  // Deletion-marker bind fires `modified`, NOT `deleted` (keys on null new_hash only).
  const marker: TreeChangeEvent[] = [];
  const bus2 = new EmitBus();
  bus2.registerConsumer({ name: "m", onContentStore: () => {}, onTreeChange: (ev) => marker.push(ev) });
  const tree2 = new EntityTree(new ContentStore(bus2), bus2);
  tree2.put("/peer/app/z", e("live"));
  tree2.put("/peer/app/z", Entity.create(TypeNames.DeletionMarker, Ecf.emptyMap()));
  assert.equal(marker[1]!.eventType, TreeChangeKind.Modified);
  assert.notEqual(marker[1]!.newHash, null);
});

// F2 — outbound closure: signed reentrant EXECUTE + end-to-end seam reachability.
test("F2: outbound dispatch builds a signed reentrant EXECUTE", async () => {
  const local = PeerIdentity.generate();
  const target = PeerIdentity.generate();
  const { token: cap, signature: capSig } = CapabilityToken.createRoot(target, local.identityHash, SeedPolicy.openGrants(), 1000n);
  const authority: OutboundAuthority = { capability: cap, granterPeer: target.peerEntity, capabilitySignature: capSig };

  let sent: Envelope | null = null;
  let counter = 0;
  const sender: ReentrantSender = {
    nextRequestId: () => "out-" + ++counter,
    sendRequest: (request: Envelope) => {
      sent = request;
      const rid = new Execute(request.root).requestId;
      return Promise.resolve(new Envelope(ExecuteResponse.build(rid, Status.Ok, PeerSession.emptyParams()).entity, []));
    },
  };

  const outbound = new OutboundDispatchImpl(local, sender);
  const resp = await outbound.execute("system/tree", "get", PeerSession.emptyParams(), new ResourceTarget(["system/handler/system/tree"], null), authority, TIMEOUT);
  assert.equal(resp.statusCode, Status.Ok);
  assert.notEqual(sent, null);

  const sentExecute = new Execute(sent!.root);
  assert.equal(sentExecute.operation, "get");
  assert.deepEqual(sentExecute.author, local.identityHash);
  assert.deepEqual(sentExecute.capability, cap.contentHash);
  const sig = ChainVerifier.findSignature(sent!, sentExecute.entity.contentHash);
  assert.notEqual(sig, null);
  assert.ok(verifySignature(sig!, local.peerEntity));
  assert.deepEqual(signatureSigner(sig!), local.identityHash);
});

test("F2: a handler dispatched over a connection receives a live ctx.outbound", async () => {
  const probe: Handler = {
    pattern: "app/probe/outbound",
    name: "outbound-probe",
    operations: ["check"],
    handle: (ctx: HandlerContext): Promise<HandlerResult> =>
      Promise.resolve(HandlerResult.ok(Entity.create(TypeNames.PrimitiveAny, Ecf.map(["has_outbound", Ecf.bool(ctx.outbound !== null)])))),
  };
  const responder = new Peer({ seedPolicy: SeedPolicy.debugOpen() });
  responder.registerHandler(probe);
  const initiator = new Peer();
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    const resp = await session.execute("app/probe/outbound", "check", PeerSession.emptyParams(), null, TIMEOUT);
    assert.equal(resp.statusCode, Status.Ok);
    assert.equal(Ecf.asBool(Ecf.require(resp.result.data, "has_outbound")), true);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
});
