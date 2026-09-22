import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Envelope,
  HandlerContext,
  TreeHandler,
  Ecf,
  Entity,
  type ExecuteResponse,
  Peer,
  type PeerSession,
  ResourceTarget,
  Scope,
  GrantEntry,
  SeedPolicy,
  CapabilityToken,
} from "../src/index.js";
import { checkPathPermission, effectiveTargets } from "../src/capability/permissions.js";
import { type EcfValue, ecfPreEncoded } from "../src/codec/ecf-value.js";
import { Execute } from "../src/model/execute.js";

/**
 * §3.3's effective-targets ladder (0.8.2.20, refined at .24/.25) and §6.3's
 * `check_path_permission`.
 *
 * The ladder runs on the EFFECTIVE list, never on `resource.targets`: a handler that
 * counts the effective list and then indexes `targets[0]` has implemented the arithmetic
 * completely and is still reading a path no authorization covered. Before this, every row
 * below answered `400 handler_error` — a refusal for a reason §6.3 does not name, which is
 * not the selection mechanism and reads as conformance on any check that only asks whether
 * something uncovered was served.
 */

const TIMEOUT = 10_000;
const LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA";

async function withSession(fn: (s: PeerSession, peerId: string) => Promise<void>): Promise<void> {
  const responder = new Peer({ seedPolicy: SeedPolicy.debugOpen() });
  const initiator = new Peer();
  try {
    const port = await responder.listen(0);
    const session = await initiator.connect("127.0.0.1", port, TIMEOUT);
    await fn(session, responder.localPeerId);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }
}

const emptyParams = (): Entity => Entity.create("primitive/any", Ecf.emptyMap());

function codeOf(r: ExecuteResponse): string {
  return Ecf.optText(r.result.data, "code") ?? "";
}

const get = (s: PeerSession, r: ResourceTarget | null): Promise<ExecuteResponse> =>
  s.execute("system/tree", "get", emptyParams(), r, TIMEOUT);
const put = (s: PeerSession, r: ResourceTarget | null): Promise<ExecuteResponse> =>
  s.execute("system/tree", "put", emptyParams(), r, TIMEOUT);

test("§3.3 — the ladder answers each row with its own code", async () => {
  await withSession(async (s) => {
    // `get`, ABSENT resource -> the root listing. EXTENSION-TREE §2.2a (v4.11) declares
    // `get` resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root listing".
    // This used to be a `targets.length !== 1` THROW -> 400 handler_error.
    const absent = await get(s, null);
    assert.equal(absent.statusCode, 200, "an absent resource is the root listing, not a refusal");
    assert.equal(absent.result.type, "system/tree/listing");

    // `get`, PRESENT and self-excluded -> 400 path_required. THE TWO EMPTIES ARE DISTINCT
    // for a resource-OPTIONAL operation (0.8.2.24 N7 / 0.8.2.25 N10): serving this the
    // absent case "answers a request for one excluded path with a listing of the tree".
    const selfExcluded = await get(s, new ResourceTarget(["app/a"], ["app/a"]));
    assert.equal(selfExcluded.statusCode, 400);
    assert.equal(codeOf(selfExcluded), "path_required");

    // Two survivors -> 400 ambiguous_resource. A peer indexing targets[0] answers 200 and
    // cannot tell the caller it ignored the second.
    const ambiguous = await get(s, new ResourceTarget(["app/a", "app/b"], null));
    assert.equal(ambiguous.statusCode, 400);
    assert.equal(codeOf(ambiguous), "ambiguous_resource");

    // A PATTERN subject -> 400 malformed_resource. A resource-requiring operation takes a
    // CONCRETE path; without this the pattern is looked up as a literal and answers 404,
    // which names the wrong fault.
    const pattern = await get(s, new ResourceTarget(["system/type/*"], null));
    assert.equal(pattern.statusCode, 400);
    assert.equal(codeOf(pattern), "malformed_resource");

    // An unmatchable CALLER exclude carves out NOTHING — the fail-OPEN direction of §5.4's
    // sentinel, and the correct one here (§5.4's table rules the caller arm separately
    // from the grant arm). A 400 would mean the peer raised on a path it cannot
    // canonicalize, i.e. the error return 0.8.2.20 removed.
    const unmatchable = await get(s, new ResourceTarget(["system/type/"], ["../nope"]));
    assert.equal(unmatchable.statusCode, 200, "an unmatchable caller exclude must not refuse the request");

    // `put` collapses the two empties: §2.2a declares it resource-REQUIRED, so both answer
    // `path_required`. Note the code 0.8.2.20 forces — a MISSING target is NOT
    // `ambiguous_resource`; *supply a resource* is not *disambiguate your request*.
    for (const r of [null, new ResourceTarget(["app/a"], ["app/a"])]) {
      const res = await put(s, r);
      assert.equal(res.statusCode, 400);
      assert.equal(codeOf(res), "path_required", `put with ${r === null ? "no resource" : "a self-excluded target"}`);
    }
    const putAmbiguous = await put(s, new ResourceTarget(["app/a", "app/b"], null));
    assert.equal(codeOf(putAmbiguous), "ambiguous_resource");

    // RULE G control: the OPERATION resolves FIRST. An unknown op with no resource answers
    // the OPERATION fault, never the resource one — a handler that validates the resource
    // first answers `path_required`/`ambiguous_resource` here and names the wrong fault for
    // every unknown operation.
    const bogus = await s.execute("system/tree", "bogusop", emptyParams(), null, TIMEOUT);
    assert.equal(bogus.statusCode, 501);
    assert.equal(codeOf(bogus), "unsupported_operation");
  });
});

test("§3.3 — the subject is SELECTED from the effective set, never targets[0]", async () => {
  await withSession(async (s, peerId) => {
    const a = Entity.create("test/a", Ecf.emptyMap());
    const b = Entity.create("test/b", Ecf.emptyMap());
    for (const [path, e] of [["app/sel/a", a], ["app/sel/b", b]] as const) {
      const req = Entity.create("system/tree/put-request", Ecf.map(["entity", ecfPreEncoded(e.wireBytes)]));
      const ok = await s.execute("system/tree", "put", req, new ResourceTarget([path], null), TIMEOUT);
      assert.equal(ok.statusCode, 200, `seeding ${path}`);
    }
    // targets:[a,b] exclude:[a]. The effective set is {b}, size 1, so the COUNT rule says
    // proceed — and a raw targets[0] selector proceeds on `a`. Both are bound, so a 200
    // naming `a` is a selection defect and nothing else.
    const res = await get(s, new ResourceTarget(["app/sel/a", "app/sel/b"], ["app/sel/a"]));
    assert.equal(res.statusCode, 200);
    assert.equal(res.result.type, "test/b", "targets[0] would have answered test/a");
    assert.equal(peerId.length > 0, true);
  });
});

// ── the projection itself (0.8.2.25 N11) ─────────────────────────────────────

function execWith(resource: EcfValue | null): Execute {
  const fields: [string, unknown][] = [
    ["request_id", Ecf.text("t1")],
    ["uri", Ecf.text("system/tree")],
    ["operation", Ecf.text("get")],
  ];
  if (resource !== null) {
    fields.push(["resource", resource]);
  }
  return new Execute(Entity.create("system/protocol/execute", Ecf.map(...(fields as [string, never][]))));
}

test("N11 — the projection is not lossy about its own emptiness", () => {
  const res = (targets: unknown, exclude?: string[]): EcfValue =>
    exclude === undefined
      ? Ecf.map(["targets", targets as never])
      : Ecf.map(["targets", targets as never], ["exclude", Ecf.array(exclude.map((e) => Ecf.text(e)))]);

  // ABSENT: nothing was asked for.
  assert.deepEqual(effectiveTargets(execWith(null), LOCAL), { survivors: [], hasResource: false });

  // PRESENT with a survivor, in the CALLER'S OWN SPELLING (0.8.2.21 yields RAW survivors).
  assert.deepEqual(effectiveTargets(execWith(res(Ecf.array([Ecf.text("app/a")]))), LOCAL), {
    survivors: ["app/a"],
    hasResource: true,
  });

  // PRESENT and SELF-EXCLUDED: the discriminator N11 makes a MUST. A function returning
  // only a list collapses this into the absent case and the handler's refusal arm becomes
  // dead code that only a WIRE drive can detect.
  assert.deepEqual(effectiveTargets(execWith(res(Ecf.array([Ecf.text("app/a")]), ["app/a"])), LOCAL), {
    survivors: [],
    hasResource: true,
  });

  // A `resource` map with NO `targets` key is ABSENT.
  assert.deepEqual(
    effectiveTargets(execWith(Ecf.map(["exclude", Ecf.array([Ecf.text("app/a")])])), LOCAL).hasResource,
    false,
  );

  // A PRESENT-BUT-ILL-TYPED `targets` is PRESENT with an EMPTY survivor list, never
  // absent. Reporting it absent serves the WIDER absent-case answer to a request that
  // named a resource — N11's own defect one field over, and the cell the two vanguard
  // peers initially disagreed on.
  assert.deepEqual(effectiveTargets(execWith(res(Ecf.uint(42n))), LOCAL), { survivors: [], hasResource: true });

  // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules the caller
  // arm separately from the grant arm), and that is INHERITED from the matcher, not
  // restated: `../nope` canonicalizes to NEVER_MATCH and matches nothing.
  assert.deepEqual(effectiveTargets(execWith(res(Ecf.array([Ecf.text("app/a")]), ["../nope"])), LOCAL).survivors, [
    "app/a",
  ]);
});

// ── §6.3's handler-level path check ──────────────────────────────────────────

test("§6.3 — check_path_permission accepts what a grant covers and denies each dimension", () => {
  const token = (handlers: string[], operations: string[], resources: string[]): CapabilityToken =>
    new CapabilityToken(
      Entity.create(
        "system/capability/token",
        Ecf.map(
          [
            "grants",
            Ecf.array([
              new GrantEntry(
                new Scope(handlers, null),
                new Scope(resources, null),
                new Scope(operations, null),
                null,
                null,
                null,
              ).toEcf(),
            ]),
          ],
          // `granter`/`grantee`/`created_at` are REQUIRED by the §3.6 parser and are not
          // read by `check_path_permission` — it answers about the token's GRANTS only.
          // The chain, signature, temporal bounds and revocation are `verifyRequest`'s and
          // must already have held.
          ["granter", Ecf.bytes(new Uint8Array(33))],
          ["grantee", Ecf.bytes(new Uint8Array(33))],
          ["created_at", Ecf.uint(0n)],
        ),
      ),
    );

  // THE ACCEPT CASE, and it is the one that validates the FIXTURE: with only deny cases a
  // broken fixture (every scope parsing empty) makes all of them pass for free.
  assert.equal(
    checkPathPermission("get", "app/a", token(["system/tree"], ["get"], ["app/a"]), "system/tree", LOCAL),
    true,
  );
  // One deny per DIMENSION: a single deny cannot distinguish "the predicate checks the
  // dimension I care about" from "the predicate denies".
  assert.equal(
    checkPathPermission("put", "app/a", token(["system/tree"], ["get"], ["app/a"]), "system/tree", LOCAL),
    false,
    "operations",
  );
  assert.equal(
    checkPathPermission("get", "app/b", token(["system/tree"], ["get"], ["app/a"]), "system/tree", LOCAL),
    false,
    "resources",
  );
  assert.equal(
    checkPathPermission("get", "app/a", token(["system/other"], ["get"], ["app/a"]), "system/tree", LOCAL),
    false,
    "handlers",
  );
  // An EMPTY `resources.include` is a legal grant shape (§5.2: handlers that touch no tree
  // paths) and denies every path here — `covered` over an empty include list is false.
  assert.equal(
    checkPathPermission("get", "app/a", token(["system/tree"], ["get"], []), "system/tree", LOCAL),
    false,
    "an empty resources.include denies every path",
  );
  // A malformed path canonicalizes to NEVER_MATCH, which matches no grant, so it falls
  // through to DENY rather than escaping as a throw.
  assert.equal(
    checkPathPermission("get", "../nope", token(["system/tree"], ["get"], ["*"]), "system/tree", LOCAL),
    false,
    "a malformed path denies rather than throwing",
  );
});

// ── §6.3's listing filter (0.8.2.21/.22) ─────────────────────────────────────

// "When any handler returns a multi-entry result whose entries are tree paths, each entry
// MUST be individually checked using check_path_permission. Entries for which
// check_path_permission returns DENY MUST be omitted. The result's `count` field MUST
// reflect the filtered entry count, not the source tree's total count."
//
// THIS TEST EXISTS BECAUSE ITS PLANT RAN GREEN WITHOUT IT. Removing the per-entry check
// from the handler left all 140 other cases passing: the filter is measured on the wire by
// `tools/arc-probe` G4, which needs a MINTED narrow capability, and the peer's own gate
// carried nothing. An inert control is not a control.
//
// Driven through a hand-built HandlerContext rather than a session, because the narrow
// grant is the whole input and minting one over the wire would put three more moving parts
// between the assertion and the thing asserted.
test("§6.3 — a listing omits entries the caller's own capability excludes", async () => {
  const peer = new Peer({ seedPolicy: SeedPolicy.debugOpen() });
  try {
    const base = "/" + peer.localPeerId + "/app/list";
    const e = Entity.create("test/leaf", Ecf.emptyMap());
    peer.tree.put(base + "/a", e);
    peer.tree.put(base + "/b", e);

    const narrowToken = (resources: string[]): CapabilityToken =>
      new CapabilityToken(
        Entity.create(
          "system/capability/token",
          Ecf.map(
            [
              "grants",
              Ecf.array([
                new GrantEntry(
                  new Scope(["system/tree"], null),
                  new Scope(resources, null),
                  new Scope(["get"], null),
                  null,
                  null,
                  null,
                ).toEcf(),
              ]),
            ],
            ["granter", Ecf.bytes(new Uint8Array(33))],
            ["grantee", Ecf.bytes(new Uint8Array(33))],
            ["created_at", Ecf.uint(0n)],
          ),
        ),
      );

    const listUnder = async (cap: CapabilityToken | null): Promise<{ names: string[]; count: number }> => {
      const execute = new Execute(
        Entity.create(
          "system/protocol/execute",
          Ecf.map(
            ["request_id", Ecf.text("l1")],
            ["uri", Ecf.text("system/tree")],
            ["operation", Ecf.text("get")],
            ["params", ecfPreEncoded(emptyParams().wireBytes)],
            ["resource", new ResourceTarget(["app/list/"], null).toEcf()],
          ),
        ),
      );
      const ctx = new HandlerContext({
        peer,
        execute,
        envelope: new Envelope(execute.entity, []),
        pattern: "system/tree",
        suffix: "",
        callerCapability: cap,
        handlerGrant: null,
        author: null,
        connection: null,
      });
      const result = await new TreeHandler().handle(ctx);
      assert.equal(result.status, 200);
      const entries = Ecf.require(result.result.data, "entries");
      const names = entries.kind === "map" ? entries.pairs.map(([k]) => (k.kind === "text" ? k.value : "")) : [];
      return { names, count: Number(Ecf.requireUint(result.result.data, "count")) };
    };

    // THE CONTROL, and it is what makes the assertion below falsifiable: with a grant
    // covering BOTH, the listing names both. "b is absent" under a narrower grant is the
    // trivial truth if the directory read does not work at all.
    const wide = await listUnder(narrowToken(["app/list/*"]));
    assert.deepEqual(wide.names.sort(), ["a", "b"], "control: an unfiltered listing names both entries");
    assert.equal(wide.count, 2);

    const narrow = await listUnder(narrowToken(["app/list/a"]));
    assert.deepEqual(narrow.names, ["a"], "an entry the caller's capability excludes MUST be omitted");
    assert.equal(narrow.count, 1, "`count` MUST follow the FILTERED total, not the source tree's");

    // An UNAUTHENTICATED context is not filtered — the filter's subject is "the caller's
    // verified capability", and where there is none there is no caller to narrow. This is
    // the bootstrap path, and it matches both vanguard peers.
    const bootstrap = await listUnder(null);
    assert.deepEqual(bootstrap.names.sort(), ["a", "b"], "an unauthenticated context is not filtered");
  } finally {
    await peer.dispose();
  }
});
