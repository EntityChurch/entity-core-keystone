/**
 * Keystone peer contract — the requirements the shared wire driver cannot observe, as local
 * tests. Test names carry the requirement prefix (`embed_create__`, `context_unforgeable__`,
 * `context_authority_chain__`); `tools/peer-contract/report.py` counts them by that prefix
 * (run-contract.sh converts node:test's TAP to the libtest lines it reads), so a renamed
 * test stops counting rather than silently counting for something else.
 *
 * Everything here goes through the package surface (`../src/index.js`, which is what the
 * package's `exports` map publishes) — never a deep import — except where a test says
 * otherwise and why.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import * as pkg from "../src/index.js";
import {
  ChainVerifier,
  ContextForgeryError,
  DispatchContext,
  Ecf,
  Entity,
  HandlerResult,
  Peer,
  PeerIdentity,
  PeerSession,
  SeedPolicy,
  Status,
} from "../src/index.js";

const TIMEOUT = 10_000;

function any(): Entity {
  return Entity.create("primitive/any", Ecf.emptyMap());
}

function peer(seed: number): Peer {
  return new Peer({ identity: PeerIdentity.fromSeed(new Uint8Array(32).fill(seed)), seedPolicy: SeedPolicy.debugOpen() });
}

// ----- embed.create --------------------------------------------------------------------

test("embed_create__two_peers_in_one_process_and_a_listenerless_peer", async () => {
  // SDK-OPERATIONS §8.1: multi-peer in one process (MUST) and a peer with no listener
  // (MUST). Neither peer below ever binds a socket.
  const a = peer(0x51);
  const b = peer(0x52);
  assert.notEqual(a.localPeerId, b.localPeerId, "independent identities");
  assert.equal(a.port, 0, "a never listened");
  const ha = a.registerHandler({ pattern: "app/only-on-a", name: "a", operations: ["go"] }, () => HandlerResult.ok(any()));
  const on = (p: Peer): string => `/${p.localPeerId}/app/only-on-a`;
  assert.ok(a.tree.get(on(a)) !== undefined, "installed on a");
  assert.equal(b.tree.get(on(b)), undefined, "b has its own tree and handlers");
  assert.equal(b.tree.get(on(a)), undefined, "b's tree holds nothing a installed, under any path");
  // Stores are separate: an entity put into a is not in b.
  const e = Entity.create("app/marker", Ecf.map(["on", Ecf.text("a")]));
  assert.equal(a.contentStore.put(e), true);
  assert.ok(a.contentStore.get(e.contentHash) !== undefined);
  assert.equal(b.contentStore.get(e.contentHash), undefined, "b has its own content store");
  // b can install at the same pattern: registrations are per peer.
  const hb = b.registerHandler({ pattern: "app/only-on-a", name: "b", operations: ["go"] }, () => HandlerResult.ok(any()));
  // Closing a's handle touches a only.
  assert.equal(ha.close(), true);
  assert.equal(a.tree.get(on(a)), undefined);
  assert.ok(b.tree.get(on(b)) !== undefined, "b's registration survives a's close");
  assert.equal(hb.close(), true);
  await a.dispose();
  await b.dispose();
});

// ----- context.unforgeable -------------------------------------------------------------

test("context_unforgeable__construction_outside_the_peer_is_refused", () => {
  // The refusal, pinned to its stated reason (ContextForgeryError), so it cannot pass on an
  // unrelated TypeError. Every construction path a program holding the package has:
  const state = {} as never;
  const Ctor = DispatchContext as unknown as new (token: symbol, state: never) => DispatchContext;
  // (1) the constructor, with any token the caller can make — including one spelled like the real one.
  for (const token of [Symbol("DispatchContext construction token"), Symbol.for("DispatchContext construction token")]) {
    assert.throws(() => new Ctor(token, state), ContextForgeryError);
  }
  assert.throws(() => new Ctor(undefined as never, state), ContextForgeryError);
  // (2) Reflect.construct is the same call.
  assert.throws(() => Reflect.construct(DispatchContext, [Symbol("t"), state]), ContextForgeryError);
  // (3) a subclass cannot reach the parent constructor without the token.
  class Sub extends Ctor {
    constructor() {
      super(Symbol("t"), state);
    }
  }
  assert.throws(() => new Sub(), ContextForgeryError);
  // (4) the factory is not on the package surface.
  assert.equal("claimDispatchContextFactory" in pkg, false, "the constructing function is not exported");
  // (5) a prototype clone carries no state: every accessor refuses.
  const clone = Object.create(DispatchContext.prototype) as DispatchContext;
  assert.throws(() => clone.operation, TypeError);
  assert.throws(() => clone.callerCapability, TypeError);
  assert.throws(() => clone.frameBudget(), TypeError);
});

test("context_unforgeable__control_the_type_is_usable_outside_the_peer", async () => {
  // The control: the type IS nameable and a genuine instance is fully usable by code outside
  // the peer, so what refuses above is the constructor — not an import, a typo or a class
  // that cannot be used at all.
  const responder = peer(0x55);
  const initiator = peer(0x56);
  let seen: { isContext: boolean; operation: string; pattern: string; author: boolean; budget: number } | null = null;
  responder.registerHandler({ pattern: "app/ctx", name: "ctx", operations: ["look"] }, (ctx) => {
    seen = {
      isContext: ctx instanceof DispatchContext,
      operation: ctx.operation,
      pattern: ctx.pattern,
      author: ctx.author !== null,
      budget: ctx.frameBudget(),
    };
    return HandlerResult.ok(any());
  });
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    const r = await session.execute("app/ctx", "look", PeerSession.emptyParams(), null, TIMEOUT);
    assert.equal(r.statusCode, Status.Ok);
    assert.deepEqual(seen, { isContext: true, operation: "look", pattern: "app/ctx", author: true, budget: responder.maxFrameBytes });
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
});

// ----- context.authority_chain ---------------------------------------------------------

test("context_authority_chain__in_chain_accepts_and_not_in_chain_denies", async () => {
  // SDK-OPERATIONS §11.3 SEC-3. The caller's session capability is granted BY the responder
  // TO the caller: the responder is in its authority chain, the caller (as granter) is not.
  const responder = peer(0x53);
  const initiator = peer(0x54);
  let seen: { authorIn: boolean; localIn: boolean; bogusIn: boolean } | null = null;
  responder.registerHandler({ pattern: "app/chain", name: "chain", operations: ["ask"] }, (ctx) => {
    const cap = ctx.callerCapability;
    assert.ok(cap !== null, "a verified capability");
    seen = {
      // deny: the author is not a granter anywhere in this chain.
      authorIn: ctx.identityInAuthorityChain(cap.contentHash),
      // accept: the responder granted it.
      localIn: ChainVerifier.identityInAuthorityChain(
        ctx.envelope,
        ctx.peer.contentStore,
        ctx.localPeerId,
        cap.contentHash,
        responder.localIdentity.identityHash,
        ctx.peer.nowMs,
      ),
      // an unresolvable hash is never "in chain", for anyone.
      bogusIn: ChainVerifier.identityInAuthorityChain(
        ctx.envelope,
        ctx.peer.contentStore,
        ctx.localPeerId,
        new Uint8Array(33),
        responder.localIdentity.identityHash,
        ctx.peer.nowMs,
      ),
    };
    return HandlerResult.ok(any());
  });
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    const r = await session.execute("app/chain", "ask", PeerSession.emptyParams(), null, TIMEOUT);
    assert.equal(r.statusCode, Status.Ok);
    assert.deepEqual(seen, { authorIn: false, localIn: true, bogusIn: false });
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
});
