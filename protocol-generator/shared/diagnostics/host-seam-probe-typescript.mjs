/**
 * HOST-SEAM PROBE — `typescript`. H6 (the frame budget) and H7 (the evaluator seam),
 * driven the way a third party would drive them.
 *
 * WHY THIS EXISTS ALONGSIDE THE PEER'S OWN TEST SUITE, which already covers both with
 * planted-defect controls: `test/host-seam.test.ts` imports `../src/index.js`. That
 * proves the BEHAVIOUR and says nothing about REACHABILITY, and reachability is the
 * half this ecosystem has been wrong about four times. `cpp` exports a symbol behind
 * `private:`; `csharp` a `public` member of an `internal sealed class`; `julia` a live
 * exported entry point onto a container nothing reads. Every one of those passes a
 * source read, and two of them were ours.
 *
 * So this probe imports the peer from its built `dist/` through the path
 * `package.json`'s `exports` map publishes at `.` — the module specifier an external
 * npm consumer actually resolves — and touches nothing else. A type that is exported
 * from `src/` but not re-exported to the package root is invisible here, which is the
 * point.
 *
 * FOUR CHECKS, EACH WITH ITS CONTROL. A check that cannot go RED measures nothing.
 *
 *   H6.  a handler body reads the CONNECTION's budget      control: a NON-default budget,
 *                                                          so a hardcoded 16 MiB fails
 *   H6c. the budget the body sees is the one the transport enforces
 *   H7.  dispatch DELEGATES to an installed evaluator      control: a witness derived from
 *                                                          registration-time state + a field
 *                                                          of the dispatched expression, which
 *                                                          no compute/literal body can produce
 *   H7c. with NO evaluator installed, the same body is still 501
 *
 * H7c is H7's negative control and the reason H7 is attributable: without it, a 200
 * could be the built-in path answering rather than the evaluator being asked.
 *
 * Read-only. Nothing is written to the tree; two peers are stood up on loopback and
 * disposed. Run after `npm run build` in `protocol-generator/typescript`:
 *
 *   node protocol-generator/shared/diagnostics/host-seam-probe-typescript.mjs \
 *     [--dist <path to typescript/dist/src/index.js>]
 *
 * Exit 0 = every check passed. Exit 1 = at least one failed (the peer does not satisfy
 * the requirement). Exit 2 = the probe could not run, which is NOT a verdict about the
 * peer — a probe that cannot execute reports `unknown`, never `fail`.
 */

import { readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PEER_ROOT = resolvePath(HERE, "../../typescript");

function argValue(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

/**
 * Resolve the peer the way a consumer does: read `exports["."]` out of its manifest
 * rather than guessing `dist/src/index.js`. If the map moves, this moves with it — and
 * if the map stops publishing an entry point at all, that is a REAL H4 failure and the
 * probe must say so rather than reaching around it into `src/`.
 */
function resolveEntryPoint() {
  const override = argValue("--dist", null);
  if (override !== null) {
    return resolvePath(override);
  }
  const require = createRequire(import.meta.url);
  const manifest = require(resolvePath(PEER_ROOT, "package.json"));
  const dot = manifest.exports?.["."];
  const entry = typeof dot === "string" ? dot : (dot?.import ?? dot?.default);
  if (typeof entry !== "string") {
    throw new Error("package.json declares no `exports[\".\"]` entry point — H4 fails at the manifest");
  }
  return resolvePath(PEER_ROOT, entry);
}

/**
 * A probe that imports a build artifact is a gate on the past unless it checks the
 * artifact's age. This one caught itself: after a planted-defect run left a mutated
 * `dist/` on disk, the probe reported H7 unsatisfied against source that satisfied it —
 * i.e. it measured a build nobody had asked for. Newest `src/**` mtime vs newest
 * `dist/**` mtime; a stale build is `unknown` (exit 2), never a verdict about the peer.
 */
function newestMtime(dir) {
  let newest = 0;
  const walk = (d) => {
    for (const ent of readdirSync(d, { withFileTypes: true })) {
      const full = resolvePath(d, ent.name);
      if (ent.isDirectory()) {
        walk(full);
      } else {
        newest = Math.max(newest, statSync(full).mtimeMs);
      }
    }
  };
  walk(dir);
  return newest;
}

let entryPoint;
let pkg;
try {
  entryPoint = resolveEntryPoint();
  const srcAt = newestMtime(resolvePath(PEER_ROOT, "src"));
  const distAt = newestMtime(resolvePath(PEER_ROOT, "dist"));
  if (distAt < srcAt) {
    throw new Error(
      `dist/ is OLDER than src/ (${new Date(distAt).toISOString()} < ${new Date(srcAt).toISOString()}) — ` +
        "this probe would measure a stale build",
    );
  }
  pkg = await import(entryPoint);
} catch (e) {
  console.error("PROBE CANNOT RUN (this is `unknown`, not `fail`):", e.message);
  console.error("  build the peer first:  cd protocol-generator/typescript && npm run build");
  process.exit(2);
}

const { Peer, Entity, Ecf, HandlerResult, PeerSession, ResourceTarget, Scope, GrantEntry, SeedPolicy, TypeNames } = pkg;
// Binding an entity INTO the tree over the wire needs the pre-encoded-bytes node, which
// crosses the boundary under the `codec` namespace rather than at the root. Worth naming
// for a composition program: `Ecf.bytes(entity.wireBytes)` type-checks, encodes a byte
// STRING instead of an embedded entity, and the peer then answers `404
// expression_not_found` at dispatch — a failure that points at the handler, not the put.
const ecfPreEncoded = pkg.codec?.ecfPreEncoded;

// Every name the probe needs must come across the boundary. A missing one is an H1/H4
// finding about the export surface, not a probe bug — say which before running anything.
const MISSING = Object.entries({ Peer, Entity, Ecf, HandlerResult, PeerSession, ResourceTarget, Scope, GrantEntry, SeedPolicy, TypeNames, ecfPreEncoded })
  .filter(([, v]) => v === undefined)
  .map(([k]) => k);
if (MISSING.length > 0) {
  console.error(`H4 FAIL — not exported across the packaging boundary: ${MISSING.join(", ")}`);
  process.exit(1);
}

const TIMEOUT = 10_000;
// Deliberately not the 16 MiB default: an implementation answering with a hardcoded
// literal must FAIL here rather than coincide with the right answer.
const ODD_BUDGET = 7_340_032;
const EN_PATTERN = "app/probe/hostseam/en";
const EN_EXPR = EN_PATTERN + "/expr";
const EN_TARGET = "system/handler/" + EN_PATTERN;

const results = [];
function record(id, ok, detail) {
  results.push({ id, ok, detail });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${id.padEnd(5)} ${detail}`);
}

function wildcardGrant() {
  return new GrantEntry(new Scope(["*"], null), new Scope(["*", "/*/*"], null), new Scope(["*"], null), null, null, null);
}

function treePut(session, path, entity) {
  const req = Entity.create("system/tree/put-request", Ecf.map(["entity", ecfPreEncoded(entity.wireBytes)]));
  return session.execute("system/tree", "put", req, new ResourceTarget([path], null), TIMEOUT);
}

function registerEntityNative(session) {
  const g = wildcardGrant();
  const manifest = Ecf.map(
    ["pattern", Ecf.text(EN_PATTERN)],
    ["name", Ecf.text("host-seam-probe")],
    ["operations", Ecf.map(["compute", Ecf.map(["input_type", Ecf.text("primitive/any")], ["output_type", Ecf.text("primitive/any")])])],
    ["expression_path", Ecf.text(EN_EXPR)],
    ["internal_scope", Ecf.array([g.toEcf()])],
  );
  const req = Entity.create(TypeNames.HandlerRegisterRequest, Ecf.map(["manifest", manifest], ["requested_scope", Ecf.array([g.toEcf()])]));
  return session.execute("system/handler", "register", req, new ResourceTarget([EN_TARGET], null), TIMEOUT);
}

async function bindExpression(session, body) {
  const put = await treePut(session, EN_EXPR, body);
  if (put.statusCode !== 200) {
    throw new Error(`tree put of the expression body failed with ${put.statusCode} — the probe cannot attribute anything below it`);
  }
}

async function withPeers(configure, body) {
  const responder = new Peer({ seedPolicy: SeedPolicy.debugOpen(), maxFrameBytes: ODD_BUDGET });
  configure(responder);
  const initiator = new Peer();
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    return await body(session, responder);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
}

console.log(`peer package: ${entryPoint}`);
console.log(`node: ${process.version}\n`);

// ----- H6 -------------------------------------------------------------------
console.log("=== H6 — the connection's frame budget is readable by a handler body ===");
await withPeers(
  (peer) =>
    peer.registerHandler({
      pattern: "app/probe/hostseam/budget",
      name: "budget-probe",
      operations: ["check"],
      handle: (ctx) =>
        Promise.resolve(
          HandlerResult.ok(
            Entity.create(
              TypeNames.PrimitiveAny,
              Ecf.map(
                ["budget", Ecf.uint(BigInt(ctx.frameBudget()))],
                ["on_connection", Ecf.uint(BigInt(ctx.connection === null ? 0 : ctx.connection.maxFrameBytes))],
              ),
            ),
          ),
        ),
    }),
  async (session) => {
    const resp = await session.execute("app/probe/hostseam/budget", "check", PeerSession.emptyParams(), null, TIMEOUT);
    const budget = resp.statusCode === 200 ? Ecf.requireUint(resp.result.data, "budget") : -1n;
    const onConn = resp.statusCode === 200 ? Ecf.requireUint(resp.result.data, "on_connection") : -1n;
    record("H6", budget === BigInt(ODD_BUDGET), `body saw ${budget} (configured ${ODD_BUDGET}; a hardcoded default would read 16777216)`);
    record("H6c", onConn === BigInt(ODD_BUDGET), `connection state carries ${onConn} — the value its own transport enforces`);
  },
);

// ----- H7 -------------------------------------------------------------------
console.log("\n=== H7 — the entity-native evaluator is delegable ===");

/** A body the built-in `compute/literal` path cannot evaluate. */
const arithmetic = () =>
  Entity.create("compute/arithmetic", Ecf.map(["op", Ecf.text("add")], ["a", Ecf.uint(2n)], ["b", Ecf.uint(3n)]));

// Negative control FIRST: without it a 200 below could be the built-in path answering.
await withPeers(
  () => {},
  async (session) => {
    await bindExpression(session, arithmetic());
    const reg = await registerEntityNative(session);
    if (reg.statusCode !== 200) {
      record("H7c", false, `register did not take (status ${reg.statusCode}) — nothing below is attributable`);
      return;
    }
    const resp = await session.execute(EN_PATTERN, "compute", PeerSession.emptyParams(), null, TIMEOUT);
    const code = resp.statusCode === 200 ? "(200)" : Ecf.requireText(resp.result.data, "code");
    record("H7c", resp.statusCode === 501 && code === "unsupported_expression", `no evaluator installed → ${resp.statusCode} ${code}`);
  },
);

// The witness: registration-time state (a token minted before the peer listened) plus a
// field read out of the dispatched expression. No compute/literal body can produce it,
// and neither can a canned response.
const TOKEN = "regtime-" + Math.random().toString(36).slice(2, 10);
const asked = [];
await withPeers(
  (peer) =>
    peer.setExpressionEvaluator({
      evaluate(req) {
        asked.push(req.expression.type);
        if (req.expression.type !== "compute/arithmetic") {
          return null; // decline — the peer's own 501 must stand
        }
        const a = Ecf.requireUint(req.expression.data, "a");
        const b = Ecf.requireUint(req.expression.data, "b");
        return HandlerResult.ok(
          Entity.create(TypeNames.ComputeResult, Ecf.map(["value", Ecf.uint(a + b)], ["witness", Ecf.text(TOKEN + "@" + req.expressionPath)])),
        );
      },
    }),
  async (session) => {
    await bindExpression(session, arithmetic());
    const reg = await registerEntityNative(session);
    if (reg.statusCode !== 200) {
      record("H7", false, `register did not take (status ${reg.statusCode}) — nothing is attributable`);
      return;
    }
    const resp = await session.execute(EN_PATTERN, "compute", PeerSession.emptyParams(), null, TIMEOUT);
    const ok =
      resp.statusCode === 200 &&
      resp.result.type === TypeNames.ComputeResult &&
      Ecf.requireUint(resp.result.data, "value") === 5n &&
      Ecf.requireText(resp.result.data, "witness").startsWith(TOKEN + "@/") &&
      asked.length === 1;
    record("H7", ok, ok ? `dispatch asked the evaluator and returned its witness (${asked.join(",")})` : `status ${resp.statusCode}, evaluator asked ${asked.length}×`);
  },
);

// ----- H2 -------------------------------------------------------------------
// SYSTEM-COMPOSITION §1.2/§2.2 makes consumer INVOCATION ORDER normative -- §2.2's
// ordering constraints are load-bearing (auto-version MUST precede subscription, or a
// subscriber sees a change with no version entry). No `validate-peer` category tests it,
// so a generated composition would be relying on an unmeasured property. Three consumers,
// registered in a known order, one tree write, and the order they fire in is the answer.
console.log("\n=== H2 — emit consumers fire in registration order ===");
const fired = [];
await withPeers(
  (peer) => {
    for (const name of ["first", "second", "third"]) {
      peer.emit.registerConsumer({
        name,
        onTreeChange: () => fired.push(name),
        onContentStore: () => {},
      });
    }
  },
  async (session) => {
    await bindExpression(session, arithmetic()); // any tree write will do
    // The control that matters is not "did they fire" but "in what order" -- a peer that
    // fires none is as wrong as one that fires them backwards, and both are invisible to
    // a check that only asserts the set.
    // One write produces several tree-change events, so the log is N repetitions of the
    // consumer list. Check EVERY repetition: asserting only the first would pass a peer
    // that ordered the opening event correctly and every later one backwards.
    const EXPECTED = ["first", "second", "third"];
    const groups = [];
    for (let i = 0; i < fired.length; i += EXPECTED.length) {
      groups.push(fired.slice(i, i + EXPECTED.length).join(","));
    }
    const want = EXPECTED.join(",");
    const allOrdered = groups.length > 0 && groups.every((g) => g === want);
    record("H2", fired.length >= EXPECTED.length, `consumers invoked ${fired.length}× across ${groups.length} event(s)`);
    record("H2o", allOrdered, allOrdered ? `every event fired [${want}]` : `out of order: ${groups.join(" | ") || "(none fired)"}`);
  },
);

// ----- verdict ---------------------------------------------------------------
const failed = results.filter((r) => !r.ok);
console.log("\nVERDICT");
console.log(`  entry point resolved through package exports:   yes`);
console.log(`  H6 — frame budget reachable from a body:        ${results.find((r) => r.id === "H6")?.ok ? "MEASURED yes" : "NO"}`);
console.log(`  H7 — evaluator reached BY DISPATCH:             ${results.find((r) => r.id === "H7")?.ok ? "MEASURED yes" : "NO"}`);
console.log(`  H2 — consumers fire in REGISTRATION ORDER:      ${results.find((r) => r.id === "H2o")?.ok ? "MEASURED yes" : "NO"}`);
console.log(`  ${failed.length === 0 ? "all checks passed" : `${failed.length} of ${results.length} checks FAILED`}`);
process.exit(failed.length === 0 ? 0 : 1);
