import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Scope } from "../src/capability/scope.js";

// §5.2 typed scope matching (0.8.1, F40) — ACCEPT-path unit checks.
//
// The oracle carried no F40 vector when this was written, and a rejection-only probe
// would let a uniformly-canonicalizing peer pass anyway, so the accept direction is the
// peer's own to cover. Drives the real Scope.matches against the cohort-shared case set
// in protocol-generator/shared/scope-matching/id-scope-vectors.json, so every peer is
// measured against one reading of §5.2 rather than 43.
//
// The load-bearing case is id.exclude.pathform: an `exclude` written in path form inside
// an `operations` scope DENIES on the pre-F40 canonicalizing reading and ALLOWS on the
// conformant one — it cannot be passed by accident.

const LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA";
const REMOTE = "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB";

// Compiled to dist/test/, so three levels up is protocol-generator/.
const VECTORS = fileURLToPath(
  new URL("../../../shared/scope-matching/id-scope-vectors.json", import.meta.url),
);

interface F40Case {
  id: string;
  scope_type: "id-scope" | "path-scope";
  value: string;
  include: string[];
  exclude?: string[];
  expect: boolean;
}

const sub = (s: string): string => s.replaceAll("{local}", LOCAL).replaceAll("{remote}", REMOTE);

test("F40 — typed scope matching agrees with the cohort-shared case set", () => {
  const doc = JSON.parse(readFileSync(VECTORS, "utf8")) as { cases: F40Case[] };
  assert.ok(doc.cases.length > 0, "shared F40 vector file carries no cases");

  for (const c of doc.cases) {
    const scope = new Scope(c.include.map(sub), (c.exclude ?? []).map(sub));
    const kind = c.scope_type === "id-scope" ? "id" : "path";
    assert.equal(scope.matches(sub(c.value), LOCAL, kind), c.expect, c.id);
  }
});

test("F40 — the exclude inversion is the discriminator", () => {
  // Same path-form exclude: ALLOWs on an id dimension, DENIEs on a path dimension.
  assert.equal(new Scope(["*"], ["/*/get"]).matches("get", LOCAL, "id"), true);
  assert.equal(
    new Scope(["*"], ["/*/system/tree"]).matches("system/tree", LOCAL, "path"),
    false,
  );
});

test("F40 — id-scope wildcards survive (bootstrap depends on them)", () => {
  assert.equal(new Scope(["*"], []).matches("get", LOCAL, "id"), true);
  assert.equal(new Scope(["compute/*"], []).matches("compute/apply", LOCAL, "id"), true);
  assert.equal(new Scope(["compute/*"], []).matches("compute", LOCAL, "id"), false);
  assert.equal(new Scope([REMOTE], []).matches(REMOTE, LOCAL, "id"), true);
});

// ── 0.8.2.24 N2/N3 — the §5.4 sentinel is scoped to PATH-SCOPE ────────────────

// "A capability carrying an unmatchable PATH-SCOPE pattern is INVALID [MUST] ... It does
// NOT reach `operations` or `peers` [MUST]." NEVER_MATCH is a §5.4 path-canonicalization
// sentinel; an id-scope pattern is a literal identifier that §5.2's id-scope arm forbids
// putting through the §5.4 transforms at all.
//
// The id-scope case cannot be passed by accident: `*/apply` is an ordinary namespaced
// operation name that PATH-canonicalizes to the sentinel, so on the pre-.24 unscoped
// reading it DENIED THE WHOLE DIMENSION — `get`, included by a bare `*`, came back false.
// The path-scope cases are the other half and prove this is a scope SPLIT rather than a
// removal: the sentinel's own arm still bites where the dimension is a path.
test("0.8.2.24 — the unmatchable-exclude sentinel is consulted on PATH scopes only", () => {
  assert.equal(
    new Scope(["*"], ["*/apply"]).matches("get", LOCAL, "id"),
    true,
    "id-scope: a path-unmatchable exclude must not deny the dimension (0.8.2.24)",
  );
  // The same holds for `peers`, the other id-scope dimension.
  assert.equal(
    new Scope(["*"], ["../nope"]).matches(REMOTE, LOCAL, "id"),
    true,
    "id-scope peers: a path-unmatchable exclude must not deny the dimension (0.8.2.24)",
  );
  // path-scope: UNCHANGED. An unmatchable exclude still denies, because there it would
  // otherwise carve out nothing and leave the grant silently wider than its author
  // wrote (0.8.2.21).
  assert.equal(
    new Scope(["*"], ["../nope"]).matches("system/tree", LOCAL, "path"),
    false,
    "path-scope: an unmatchable exclude must still deny (0.8.2.21)",
  );
  // And an ordinary path-scope exclude still carves out only its own target — the
  // sentinel arm must not have swallowed the ordinary case.
  assert.equal(
    new Scope(["*"], ["system/secret"]).matches("system/tree", LOCAL, "path"),
    true,
    "path-scope: an ordinary exclude must not deny an unrelated value",
  );
});
