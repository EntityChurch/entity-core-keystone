import { test } from "node:test";
import assert from "node:assert/strict";
import { ecfPreEncoded } from "../src/codec/ecf-value.js";
import {
  DEFAULT_MAX_FRAME_BYTES,
  Ecf,
  Entity,
  type ExpressionEvaluator,
  type ExpressionRequest,
  GrantEntry,
  type Handler,
  HandlerContext,
  type HandlerResult as HandlerResultType,
  HandlerResult,
  type PeerServices,
  Peer,
  PeerSession,
  ResourceTarget,
  Scope,
  SeedPolicy,
  Status,
  TypeNames,
  type ExecuteResponse,
} from "../src/index.js";

/**
 * The keystone HOST-SEAM obligations — the things an extension host needs that core
 * protocol conformance does not ask for, and that `validate-peer` therefore cannot
 * measure. Two requirements, both routed from `entity-system-generator` after they
 * were measured ABSENT here by execution:
 *
 *   H6 — the connection's frame budget is readable by a handler body.
 *   H7 — the entity-native (§6.13(a)) evaluator is delegable to installed code.
 *
 * Every check below carries its own control, because the failure mode this family has
 * is a seam that exists and is never consulted: an exported symbol writing a container
 * nothing reads passes a source read, a type check, and a doc review. The controls are
 * what separate "installed" from "asked".
 */

const TIMEOUT = 10_000;

// A budget that is NOT the default. Every H6 assertion below is against this number,
// so an implementation that answers with a hardcoded 16 MiB literal — the exact thing
// CONTENT §6.2 Amendment 1 forbids — fails rather than passes by coincidence.
const ODD_BUDGET = 3_145_728;

const PATTERN = "app/hostseam/en";
const EXPR_PATH = PATTERN + "/expr";
const INSTALL_TARGET = "system/handler/" + PATTERN;

function treePut(session: PeerSession, path: string, entity: Entity): Promise<ExecuteResponse> {
  const putReq = Entity.create("system/tree/put-request", Ecf.map(["entity", ecfPreEncoded(entity.wireBytes)]));
  return session.execute("system/tree", "put", putReq, new ResourceTarget([path], null), TIMEOUT);
}

/** Register an entity-native handler whose body is the entity at {@link EXPR_PATH}. */
function buildRegisterRequest(): Entity {
  const wildcard = new GrantEntry(new Scope(["*"], null), new Scope(["*", "/*/*"], null), new Scope(["*"], null), null, null, null);
  const manifest = Ecf.map(
    ["pattern", Ecf.text(PATTERN)],
    ["name", Ecf.text("host-seam-probe")],
    ["operations", Ecf.map(["compute", Ecf.map(["input_type", Ecf.text("primitive/any")], ["output_type", Ecf.text("primitive/any")])])],
    ["expression_path", Ecf.text(EXPR_PATH)],
    ["internal_scope", Ecf.array([wildcard.toEcf()])],
  );
  return Entity.create(TypeNames.HandlerRegisterRequest, Ecf.map(["manifest", manifest], ["requested_scope", Ecf.array([wildcard.toEcf()])]));
}

/**
 * Stand up responder + initiator, bind `body` at the expression path, and register an
 * entity-native handler over the WIRE against it. Returns the dispatch response.
 *
 * Deliberately the wire install rather than an in-process one: a §6.13(a) body is what
 * `expression_path` resolves to, and driving it over the wire is what makes the result
 * attributable to dispatch rather than to a direct call.
 */
async function dispatchEntityNative(
  body: Entity,
  configure: (peer: Peer) => void = () => {},
): Promise<ExecuteResponse> {
  const responder = new Peer({ seedPolicy: SeedPolicy.debugOpen() });
  configure(responder);
  const initiator = new Peer();
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    assert.equal((await treePut(session, EXPR_PATH, body)).statusCode, Status.Ok);
    const reg = await session.execute("system/handler", "register", buildRegisterRequest(), new ResourceTarget([INSTALL_TARGET], null), TIMEOUT);
    // If the register did not take, nothing below is attributable to the seam.
    assert.equal(reg.statusCode, Status.Ok);
    return await session.execute(PATTERN, "compute", PeerSession.emptyParams(), null, TIMEOUT);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
}

// ----- H6 — the frame budget is reachable from a handler body -------------------

test("H6: a handler body reads the CONNECTION's frame budget, not a hardcoded literal", async () => {
  let seen: number | null = null;
  const probe: Handler = {
    pattern: "app/hostseam/budget",
    name: "budget-probe",
    operations: ["check"],
    handle: (ctx): Promise<HandlerResultType> => {
      seen = ctx.frameBudget();
      return Promise.resolve(HandlerResult.ok(Entity.create(TypeNames.PrimitiveAny, Ecf.map(["budget", Ecf.uint(BigInt(ctx.frameBudget()))]))));
    },
  };
  const responder = new Peer({ seedPolicy: SeedPolicy.debugOpen(), maxFrameBytes: ODD_BUDGET });
  responder.registerHandler(probe);
  const initiator = new Peer();
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    const resp = await session.execute("app/hostseam/budget", "check", PeerSession.emptyParams(), null, TIMEOUT);
    assert.equal(resp.statusCode, Status.Ok);
    // The control: ODD_BUDGET, never DEFAULT_MAX_FRAME_BYTES. A body that answers with
    // the default is exactly the defect this requirement exists to prevent.
    assert.equal(Ecf.requireUint(resp.result.data, "budget"), BigInt(ODD_BUDGET));
    assert.equal(seen, ODD_BUDGET);
    assert.notEqual(seen, DEFAULT_MAX_FRAME_BYTES);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
});

test("H6: the connection state carries the budget its own transport enforces", async () => {
  const responder = new Peer({ seedPolicy: SeedPolicy.debugOpen(), maxFrameBytes: ODD_BUDGET });
  let onConnection: number | null = null;
  responder.registerHandler({
    pattern: "app/hostseam/budget2",
    name: "budget-probe-2",
    operations: ["check"],
    handle: (ctx): Promise<HandlerResultType> => {
      // The per-connection value is the normative one (§6.2 says *the connection's*
      // budget); the peer default is only the fallback for a dispatch with no
      // connection. Assert they are wired to the same source, not defaulted apart.
      onConnection = ctx.connection === null ? -1 : ctx.connection.maxFrameBytes;
      return Promise.resolve(HandlerResult.ok(Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap())));
    },
  });
  const initiator = new Peer();
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    assert.equal((await session.execute("app/hostseam/budget2", "check", PeerSession.emptyParams(), null, TIMEOUT)).statusCode, Status.Ok);
    assert.equal(onConnection, ODD_BUDGET);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
});

test("H6: an off-connection dispatch still has a defined budget (the peer default)", () => {
  const peer = new Peer({ maxFrameBytes: ODD_BUDGET });
  const services: PeerServices = peer;
  assert.equal(services.maxFrameBytes, ODD_BUDGET);
  const ctx = new HandlerContext({
    peer: services,
    // The execute/envelope are unused by frameBudget(); this exercises the null-connection
    // arm, which no wire test can reach.
    execute: null as never,
    envelope: null as never,
    pattern: "app/x",
    suffix: "",
    callerCapability: null,
    handlerGrant: null,
    author: null,
    connection: null,
  });
  assert.equal(ctx.frameBudget(), ODD_BUDGET);
});

// ----- H7 — the entity-native evaluator is delegable ----------------------------

/** A body the built-in `compute/literal` path cannot evaluate. */
function arithmeticBody(): Entity {
  return Entity.create("compute/arithmetic", Ecf.map(["op", Ecf.text("add")], ["a", Ecf.uint(2n)], ["b", Ecf.uint(3n)]));
}

/**
 * An evaluator whose witness cannot be produced by any `compute/literal` body: it is
 * derived from REGISTRATION-TIME state (a token minted before the peer listened) plus
 * a value read out of the dispatched EXPRESSION. A peer that merely fell through to the
 * built-in path, or that returned a canned entity, cannot answer this.
 */
function witnessEvaluator(token: string, calls: string[]): ExpressionEvaluator {
  return {
    evaluate(req: ExpressionRequest): HandlerResultType | null {
      calls.push(req.expression.type);
      if (req.expression.type !== "compute/arithmetic") {
        return null; // decline — the peer's own 501 must stand
      }
      const a = Ecf.requireUint(req.expression.data, "a");
      const b = Ecf.requireUint(req.expression.data, "b");
      return HandlerResult.ok(
        Entity.create(
          TypeNames.ComputeResult,
          Ecf.map(["value", Ecf.uint(a + b)], ["witness", Ecf.text(token + ":" + req.expressionPath)]),
        ),
      );
    },
  };
}

test("H7 control: with NO evaluator installed, a richer body is still 501", async () => {
  const resp = await dispatchEntityNative(arithmeticBody());
  assert.equal(resp.statusCode, Status.NotSupported);
  assert.equal(resp.result.type, TypeNames.Error);
  assert.equal(Ecf.requireText(resp.result.data, "code"), "unsupported_expression");
});

test("H7: dispatch DELEGATES an entity-native body to the installed evaluator", async () => {
  const calls: string[] = [];
  const token = "reg-time-" + Math.random().toString(36).slice(2);
  const resp = await dispatchEntityNative(arithmeticBody(), (peer) => peer.setExpressionEvaluator(witnessEvaluator(token, calls)));

  assert.equal(resp.statusCode, Status.Ok);
  assert.equal(resp.result.type, TypeNames.ComputeResult);
  assert.equal(Ecf.requireUint(resp.result.data, "value"), 5n);
  // The witness is the attributability control: registration-time state + a field of the
  // dispatched expression. Nothing on the built-in path can produce this string.
  const witness = Ecf.requireText(resp.result.data, "witness");
  assert.ok(witness.startsWith(token + ":/"), witness);
  // The evaluator is handed the CANONICALIZED absolute path (`/{peer_id}/…`), not the
  // peer-relative form the manifest carried — it resolves entities against the tree, so
  // a relative path would be unusable to it.
  assert.ok(witness.endsWith("/" + EXPR_PATH), witness);
  // ...and the evaluator was reached BY DISPATCH, not merely installed.
  assert.deepEqual(calls, ["compute/arithmetic"]);
});

test("H7: an evaluator that DECLINES (null) leaves the peer's own 501 in place", async () => {
  const calls: string[] = [];
  const declines: ExpressionEvaluator = {
    evaluate(req: ExpressionRequest) {
      calls.push(req.expression.type);
      return null;
    },
  };
  const resp = await dispatchEntityNative(arithmeticBody(), (peer) => peer.setExpressionEvaluator(declines));
  assert.equal(resp.statusCode, Status.NotSupported);
  assert.equal(resp.result.type, TypeNames.Error);
  assert.equal(Ecf.requireText(resp.result.data, "code"), "unsupported_expression");
  assert.deepEqual(calls, ["compute/arithmetic"]); // it WAS asked, and it declined
});

test("H7: the built-in compute/literal fast path is untouched by an installed evaluator", async () => {
  const calls: string[] = [];
  const literal = Entity.create(TypeNames.ComputeLiteral, Ecf.map(["value", Ecf.uint(42n)]));
  const resp = await dispatchEntityNative(literal, (peer) => peer.setExpressionEvaluator(witnessEvaluator("unused", calls)));

  // This is the check that protects `core_register_body_binding` across all 46 peers:
  // the literal path answers FIRST and the evaluator is never consulted for it, so
  // installing one cannot move a conformance result.
  assert.equal(resp.statusCode, Status.Ok);
  assert.equal(resp.result.type, TypeNames.ComputeResult);
  assert.equal(Ecf.requireUint(resp.result.data, "value"), 42n);
  assert.deepEqual(calls, []);
});

test("H7: a throwing evaluator becomes a status, never a hung request", async () => {
  const boom: ExpressionEvaluator = {
    evaluate(): HandlerResultType {
      throw new Error("evaluator exploded");
    },
  };
  const resp = await dispatchEntityNative(arithmeticBody(), (peer) => peer.setExpressionEvaluator(boom));
  // §4.9(c) deliver-or-signal: third-party code on the dispatch path must not be able
  // to make the peer answer nothing.
  assert.equal(resp.statusCode, Status.InternalError);
  assert.equal(resp.result.type, TypeNames.Error);
  assert.equal(Ecf.requireText(resp.result.data, "code"), "internal_error");
});

test("H7: the evaluator seam is reachable and clearable through the public surface", () => {
  const peer = new Peer();
  assert.equal(peer.expressionEvaluator, null);
  const evaluator = witnessEvaluator("t", []);
  peer.setExpressionEvaluator(evaluator);
  assert.equal(peer.expressionEvaluator, evaluator);
  peer.setExpressionEvaluator(null);
  assert.equal(peer.expressionEvaluator, null);
});
