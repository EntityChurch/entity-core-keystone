import { test } from "node:test";
import assert from "node:assert/strict";
import { Scope } from "../src/capability/scope.js";
import { GrantEntry } from "../src/capability/grant-entry.js";
import { grantsWithinAuthority } from "../src/capability/attenuation.js";

// F50, ruled YES at 0.8.2.16: F40's id-scope typing reaches `scope_subset` too, with
// delegation-chain WIDENING named as the reason. §3.6's grammar binds the scope TYPE, not
// one function — "An implementation on the canonicalizing reading is non-conformant and
// MUST adopt the literal matcher".
//
// `entity-core-formalization` (K-7) found the discriminating pairs by differential on
// `lean`: 2 of 64 include pairs and 2 of 64 exclude pairs disagree between the two
// readings, fail-closed, and a 16-pair control alphabet reports 0 — which is why every
// hand-tried example missed it.
//
// `scopeSubset` is module-private, so these drive it through `grantsWithinAuthority`,
// which is the §6.2 mint-time surface a wire `system/capability:request` reaches. Each
// case moves exactly ONE dimension and leaves the rest at `*` / `*`, so a verdict is
// attributable to the dimension under test.

const LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA";

const star = (): Scope => new Scope(["*"], null);
const grant = (o: { handlers?: Scope; resources?: Scope; operations?: Scope }): GrantEntry =>
  new GrantEntry(
    o.handlers ?? star(),
    o.resources ?? star(),
    o.operations ?? star(),
    null,
    null,
    null,
  );

const within = (child: GrantEntry, parent: GrantEntry): boolean =>
  grantsWithinAuthority([child], [parent], LOCAL);

test("F50 — scope_subset matches by SCOPE KIND, not uniformly by path", () => {
  // THE DISCRIMINATOR, include direction. On the id arm `/*/get` is a LITERAL and does
  // not cover the bare `get`; on the path arm it canonicalizes to a peer wildcard and
  // does. Same pair, opposite answers — which is exactly what says the kind selects the
  // matcher rather than decorating it. The untyped function answered `true` for both,
  // over-accepting on the id dimension, which is the chain widening F50 names.
  assert.equal(
    within(grant({ operations: new Scope(["get"], null) }), grant({ operations: new Scope(["/*/get"], null) })),
    false,
    "operations is ID scope: a path-form parent include does not cover the bare identifier",
  );
  assert.equal(
    within(grant({ handlers: new Scope(["get"], null) }), grant({ handlers: new Scope(["/*/get"], null) })),
    true,
    "handlers is PATH scope: the same pair IS a subset once both sides canonicalize",
  );

  // The exclude direction. `*/apply` is an ordinary namespaced operation name: on the id
  // arm it is a literal and inherits itself; on the path arm it canonicalizes to
  // NEVER_MATCH on BOTH sides, and NEVER_MATCH matches nothing in either operand (§5.4),
  // so the parent exclude is not inherited and the check fails closed.
  const opsExcl = new Scope(["*"], ["*/apply"]);
  assert.equal(
    within(grant({ operations: opsExcl }), grant({ operations: opsExcl })),
    true,
    "operations is ID scope: a literal parent exclude is inherited by the identical child exclude",
  );
  assert.equal(
    within(grant({ resources: opsExcl }), grant({ resources: opsExcl })),
    false,
    "resources is PATH scope: an unmatchable pattern is not inherited by itself (§5.4)",
  );

  // THE CONTROL that validates the fixture: an identical all-`*` grant IS within its own
  // authority. Without it every `false` above is satisfied by a function that denies
  // everything, and every `true` by one that accepts everything.
  assert.equal(within(grant({}), grant({})), true, "control: a grant is within itself");
  assert.equal(
    within(grant({ operations: new Scope(["get"], null) }), grant({ operations: new Scope(["put"], null) })),
    false,
    "control: an unrelated operation include is NOT within the parent's",
  );
});
