# F68 on the wire — a self-excluded target is read on three of five generator backends, and the two that refuse are saved by a guard the ruling is not about

**Date:** 2026-09-10
**Instrument:** `tools/f68-probe` (probe; measures, does not gate, never appears in a conformance number)
**Setup:** `tools/f68-probe/run.sh <peer>` — the peer's OWN `run-s4.sh` with exactly one flag removed
**Answering:** `entity-system-architecture`'s
`ROUTING-2026-09-10-f-entity-core-keystone-your-generators-have-both-halves-of-F68-and-the-install-path-is-the-sharp-one`

---

## The result

| backend | C — `targets:[P] exclude:[P]` | what came back | D — `targets:[P,Q] exclude:[P]` | second authorization site |
|---|---|---|---|---|
| **python** | **200** | `system/capability/policy-entry` | **200 — P** | defined, **called from nowhere** |
| **ocaml** | **200** | `system/capability/policy-entry` | **200 — P** | none |
| **go** (generated) | **200** | `system/capability/policy-entry` | **200 — P** | none |
| **csharp** | 403 `capability_denied` | — | 400 `handler_error` | `TreeHandler.cs:96` — live |
| **typescript** | 403 `capability_denied` | — | 400 `handler_error` | `tree-handler.ts:90` — live |

`P` = `system/capability/policy/default`, outside the caller's grant and bound at peer init.
`Q` = `system/type/primitive/any`, inside it.

**Three of five peers hand an unauthorized caller the peer's own seed-policy entity** — the object
that enumerates the grants the peer issues — in answer to a request whose authorization check
returned ALLOW *because the caller excluded the very path it asked for*.

`entity-core-go` the **seat** is not in this table. The `go` row is the keystone-**generated** go
peer, a fifth backend arch's read did not cover; it implements caller excludes at
`protocol-generator/go/src/peer/capability.go:283` (*"excluded by caller — admitted"*) and behaves
like `python` and `ocaml`, not like the ground-up seat.

## Controls, and why the middle one decides whether any of this is readable

Three per peer, all three green on all five:

- **Positive** (case A) — an in-grant `get` MUST NOT be 403. All five: 200, result type
  `system/type`. A peer failing this is reported `trusted: false` and suppressed.
- **Antecedent** (case B) — **the same out-of-grant target, with no `exclude`, MUST be 403.** All
  five: `403 capability_denied`. Without this arm a 403 in case C is unfalsifiable — any unrelated
  fault produces one — and a 200 means nothing, because the grant may have covered `P` all along.
  *A deny-only check on this surface measures nothing*, which is the same objection this seat filed
  against `dispatch_outbound_multisig_root_refused` (F70) the day before writing this, and it would
  have been indefensible to repeat it here.
- **Witness** (the field, not the status) — `P` and `Q` both answer 200, so status alone cannot say
  **which** target the handler acted on. The probe records the **type of the returned entity**:
  `system/capability/policy-entry` can only have come from `P`; `system/type/*` only from `Q`. Case
  D is entirely decided by this field and is unreadable without it.

## The setup detail that decides the whole measurement

**Every `run-s4.sh` in the cohort launches its peer with `--debug-open-grants`** — the degenerate
`default -> *` seed policy. Under it the caller's grant covers every path, nothing is outside it,
and the F68 composition **has nothing to bypass**. A probe run against the census configuration
reports the guard holding on all 46 peers for a reason that has nothing to do with the guard.

`run.sh` therefore takes each peer's own harness and removes exactly that flag, changing nothing
else. The peer then falls back to the **§6.9a discovery floor**, which is a real, shipped,
conformant grant rather than a synthetic one authored for the probe:

```
handlers system/tree        resources system/type/*, system/handler/*   operations get
handlers system/capability  resources (none)                           operations request
```

So this is a statement about the peers as they ship, under a grant they ship.

## What actually separates the safe peers from the unsafe ones — and it is not §5.2

**All five skip the caller-excluded target identically.** The composition arch describes is present
in every backend: `Permissions.cs:94`, `capability.ml:213`, `capability.py:606`,
`permissions.ts:109`, `capability.go:283` — five spellings of *"caller excluded it — admitted"*.

`csharp` and `typescript` refuse case C at a **second, independent authorization site**: the tree
handler re-authorizes the path it is about to act on (`AuthorizePath` -> `CheckPathPermission`,
`authorizePath` -> `checkPathPermission`) and that function does not consult the request's
`exclude`. The messages prove the two rungs are distinct — case B is refused at
`Dispatcher.cs:164` (*"capability does not grant the operation"*, the generic §5.2 denial) and case
C at `TreeHandler.cs:96` (*"capability does not cover path"*).

That second site **is** arch's general rule — *a handler MUST NOT act on a target the authorization
check SKIPPED* — already implemented, by peers that were not aiming at this.

> **`python` has that function, it is unit-tested, and the peer never calls it.**
> `check_path_permission` is defined at `capability.py:638` and its only callers in the entire tree
> are four assertions in `tests/peer/test_exec_context.py`. It is the H5 dead-map shape exactly: a
> real guard, with a real test, off the dispatch path — and it is the single difference between
> `python` reproducing F68 and `typescript` not.

## The ruling's arithmetic does not close this, and on two peers it opens it

Case D is `targets: [P, Q]`, `exclude: [P]`, where `Q` **is** in the grant. The **effective** set is
`{Q}`, size 1, so the ruled arithmetic — *count on the effective set; 0 -> `path_required`, >1 ->
`ambiguous_resource`, 1 -> proceed* — says **proceed**.

**On all three reproducing peers the response is `P`.** A handler that counts the effective set and
then selects `targets[0]` reads the excluded path with the count rule fully implemented.

And the direction nobody would look for: **on `csharp` and `typescript` case D is currently refused
by the RAW arity check** (`Targets.Count != 1` -> `400`). Replacing that raw count with an
effective-set count makes it 1 and lets the request **proceed** — so the ruling, taken as an
arithmetic, removes the refusal that currently stops D on the two safest peers, leaving their
safety resting entirely on the second site.

**So the load-bearing half of the ruling is the general rule, not the count**, and it wants stating
as a *selection* rather than a cardinality: the target a handler acts on is drawn **from the
effective set**, and `targets[0]` is not that. Implementers will code the arithmetic — it is
concrete, it is three branches, and it is what a pseudocode block can express.

## The `register` install path — what actually bounds it

All five peers: `403 capability_denied`, refused at the **dispatcher**, on **Dimension 1**. Under
the shipped discovery floor the caller has no grant on handler `system/handler` at all, so the
`targets[0]` install derivation is **unreachable** — and it cannot be reached by minting either,
since a §6.2 mint is a subset of the caller's own capability.

**F68 neutralizes Dimension 3 only.** The install path therefore needs an independent
handlers+`register` grant, and the ceiling question is *how wide Dimension 1 is in the deployment*,
not how wide the resources grant is. The dangerous deployment is the plausible one and is a design
claim rather than a measured one: **a host granted `register` and narrowed on resources to its own
subtree** — exactly the extension-host shape — loses the subtree bound entirely, because the
dimension that was doing the narrowing is the one F68 switches off.

Under `--debug-open-grants` the derivation is reachable and the composition adds nothing, since
everything is granted anyway. There is no configuration in the tree today where the install path is
both reachable and bounded by resources.

## Two things found alongside, independent of F68

- **CORRECTED 2026-09-11 — it is THREE backends, not two, and the one this sentence missed is in the
  reproducing set.** As first published this read *"`ocaml` and `python` have no arity check at all …
  `csharp`, `typescript` count"*, which named four of five and left `go` to be inferred into the
  counting half. **The generated `go` has the identical defect**: `execResourceTarget`
  (`handlers.go:231-243`) tests `len(targets) == 0` and then returns `targets[0]`, so
  `registerPattern` (`:622`) takes the head of a list of any length exactly as `ocaml` and `python`
  do. **`ocaml`, `python` and the generated `go` have no arity check**; `csharp`
  (`HandlersHandler.cs:165`, `Targets.Count != 1`) and `typescript`
  (`handlers-handler.ts:153`, `targets.length !== 1`) count. The three with no arity check are
  precisely the three that reproduce `F68` — the same three, not a coincidence, since it is the head
  selection that makes case D reach `targets[0]`.
  **The undercount is the lesson: a claim of the form *"A and B do X, C and D do Y"* over a
  five-member cohort names four and leaves the fifth to be inferred, and the inference is invisible
  in the sentence.** This one was relayed verbatim into a normative proposal
  (`entity-core-protocol` `564055f` §6) and into two architecture packets before it was re-derived.
  **Enumerate every member of a cohort by name, including the ones the claim is not about.**
  This is the defect `entity-core-go` reverted at `e030bcd` and was asked to restore, sitting
  unremarked in three generator backends.
- **All five emit the WRONG CODE for the absent case, and §3.3 names that non-conformant in the
  sentence that creates the rule.** §3.3's 400 row and §6.13 both pin *zero targets →
  `400 path_required`, more than one → `400 ambiguous_resource`*, and the row adds: *"A handler
  specification that collapses them into one code is non-conformant on the absent case."*
  **Every one of the five answers `ambiguous_resource` when the resource is absent** — the >1 code
  for the =0 condition, i.e. not merely collapsed but inverted. `csharp` and `typescript` carry the
  arity check and still collapse, so having the count does not imply having the codes. This is
  independent of `F68`, is against landed core text, and is owed by all five.
- **Arch's exculpatory claim about the oracle holds, verified independently.** *"The oracle has
  never sent a caller-side resource exclude in its life"* — every `ResourceTarget{...}` in
  `entity-core-go`'s `cmd/internal/validate` sets `Targets` and nothing else; the one live `Exclude`
  in `authz.go:922` is the **grant-side operations** exclude of the F40 row, not a request-side
  resource exclude. Recorded with the same weight as a catch.

## Reproducing

```
tools/build-probes.sh f68-probe
tools/f68-probe/run.sh python ocaml go csharp typescript
```

Reports land in `output/scratch/f68/<peer>.json`. The probe always exits 0.

**Not measured:** the remaining 41 peers. The five here are the four backends arch named plus the
generated `go`. Five executed beats forty-six surveyed, which is the standard arch asked for and the
one this seat applied when it declined the H4 packaging table.
