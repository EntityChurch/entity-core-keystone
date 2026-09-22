# The scope algebra is a decision table nobody has enumerated — a cell census

**Date:** 2026-09-12
**Seat:** `entity-core-keystone`
**Measured against:** `entity-core-protocol` `80c4d06` (spec `0.8.2.21`) · `entity-system-architecture` `98f2946` · keystone cohort at executed check set `7aa6f3de…` (778 checks, oracle `78db4a9`)
**Instrument:** `tools/scope-cell-table.py` (committed; `--summary`, `--gaps`)

---

## 0. What this is, and why it is not another finding

Twenty-one point revisions of `0.8.2.x` landed in twelve days. This document does **not**
report a defect in any of them. It reports what they have in common.

Every finding in that arc — ours, arch's, `entity-core-go`'s, `entity-core-formalization`'s —
has one of three shapes:

- *this cell says A here and B there* (F49, F68, `0.8.2.21` §1.1, arch's §6.8 authority table)
- *this cell is unreachable / its guard is skipped* (R11, the `NEVER_MATCH` fail-open)
- *the sweep covered 3 of 7 sites* (G4, F68's §9.1 miss, twice)

Those are not N defects. They are **one** defect — *the cells are nowhere enumerated* —
reported N times. This is the enumeration.

**The load-bearing claim is falsifiable and is stated first:** the algebra has **146 live
decision cells**, **37 carry a named vector**, and **every finding of the last twelve days
landed in a zero-coverage region.** If that correlation is wrong, this document is wrong.

---

## 1. The axes, derived rather than chosen

Read off the normative pseudocode, not invented. The single most important result is a
*reduction*: the space is far smaller than the naive product, and three of the four
reductions are facts about the design that are worth knowing on their own.

```
   640  naive product (scope type as a free axis)
  -320  type is FIXED by the dimension (§3.6 grant-entry lines 1010-1013)
   -32  id-scope has no /*/ and no NEVER_MATCH (§5.2 — it never canonicalizes)
   -16  L2 consults 3 dimensions, not 4 (check_path_permission)
  -126  only (L1, resources) has 4 arms; every other pair has 2
  ----
   146  live cells
```

The arithmetic is staged and self-checking — each stage is derived from the one above and
the script asserts closure, so a reduction that stops removing anything fails loudly
rather than sitting there reading as load-bearing.

**Axis 1 — layer.** The four call sites that answer an authorization question:

| | function | § | dimensions consulted | subject | frame |
|---|---|---|---|---|---|
| **L1** | `check_permission` / `check_grant_covers` | §5.2 | 4 | value (resources: a **set**) | local |
| **L2** | `check_path_permission` | §6.8/§6.3 | **3** — no `peers` | value | local |
| **L3** | `scope_subset` via `is_attenuated` | §5.5a | 4 | pattern | **per-link granter** |
| **L4** | `scope_subset` at the §6.2 mint | §6.2 | 4 | pattern | local (both sides) |

**Axis 2 — dimension.** Four. **Scope type is not an independent axis** — it is fixed per
dimension by `system/capability/grant-entry`. This halves the space and is the reason a
naive reading over-counts. It is also where §3 finds a hole.

**Axis 3 — polarity.** Which arm decides. Ordinary pairs have two (include, grant-exclude);
`scope_subset` has two (include-coverage, exclude-inheritance); **`(L1, resources)` has
four**, because it is the only pair whose subject is a set carrying its own exclusions.

**Axis 4 — operand form.** `concrete · trailing/* · /*/interior · bare * · NEVER_MATCH` on
the path side; `literal · trailing/* · bare * · path-form string` on the id side. The last
is the F40 trap and is a distinct cell precisely because the wrong answer is invisible on
every other operand.

### 1a. The generator, in one sentence

**`resources` is the only dimension whose subject is a set-with-exclusions rather than a
value, and it is matched by two different functions depending on which layer asks.**

F68, F71, G1, G3, `effective_targets`, `0.8.2.20` and `0.8.2.21` are all consequences of
that one asymmetry. It is not a defect — a caller must be able to say *"this subtree
except that leaf"* — but it is the whole cost centre, and naming it is what lets the next
revision predict where it will need to look.

---

## 2. Coverage — and four structural zeros

Mapped conservatively from the 778-check executed set by check **name**. **This column is
a source read and is `unknown` until a harness drives it**; a name is evidence about
intent, not about what a check sends. Cells marked uncovered are the honest state, not an
accusation.

```
enumerated cells   146        BY LAYER                     BY DIMENSION
  with a vector     37          L1  18/46                    handlers    5/40
  UNMEASURED       109          L2   0/28  <-- ZERO          operations 12/32
  known DEFECT       1          L3  14/36                    peers       0/24  <-- ZERO
  ruled but UNGATED 32          L4   5/36                    resources  20/50

BY POLARITY
  include            14/32      grant-exclude          4/27
  include-coverage   10/36      grant-exclude/concrete 0/5   <-- ZERO
  exclude-inheritance 9/36      grant-exclude/pattern  0/5   <-- ZERO
                                caller-exclude         0/5   <-- ZERO
```

**Z1 — `check_path_permission` has no vectors at all, 0 of 28.** `0.8.2.20`/`.21` made this
layer *"not a secondary check `[MUST]`"*, **the sole enforcement** for requests that omit
`resource`, and the non-vacuous enforcement for the F68 case. It is the layer the last two
revisions are about, and nothing in the check set drives it.

**Z2 — `peers`, 0 of 24.** Known and long-standing (PD-1/PD-2); recorded here with its
denominator for the first time.

**Z3 — the caller-exclude arm, 0 of 5.** Arch's exculpatory claim that the oracle has never
driven a caller-side resource exclude is **verified and correct**. `tools/f68-probe` is the
only instrument in the ecosystem that reaches these five cells, which is exactly why F68
had to be routed to this seat to be answered.

**Z4 — both grant-exclude arms at `(L1, resources)`, 0 of 10** — the region containing the
fail-open arch found at `0.8.2.21`.

### 2a. The correlation, which is the actual argument

| landed in | region | coverage |
|---|---|---|
| F68 / F71 (`0.8.2.18`→`.20`) | caller-exclude | **0/5** |
| `0.8.2.21` §1.1 fail-open | grant-exclude/pattern × `NEVER_MATCH` | **0/5** |
| G1 / G3 — the subject at both layers | L2 | **0/28** |
| arch `98f2946` — §6.8 flattened an intersection | L2 authority selector | **0/28** |
| F50 — the id/path split reaching `scope_subset` | L3/L4 id dims | ruled, **ungated** |
| **F40 — the id/path split at `matches_scope`** | **L1 operations** | **covered (`f40_*`) — and CLOSED, once** |

**F40 is the control.** It is the one cell family in this arc that got vectors, and it is
the one that closed and stayed closed. Everything without vectors has re-opened at least
once. That is not a metaphor for the process; it is the process, measured.

### 2b. What this predicts, and it is cheap to falsify

**The next finding will land in L2, the `peers` dimension, or an exclude arm.** If the next
two land somewhere else, this census is measuring the wrong thing and should be said so.

---

## 3. F72 — the scope type is specified as a wire value and implemented as a call-site argument

**Surfaced by the enumeration; not previously reported by any seat.**

The spec pins the dimension→type binding as a `type_ref` in `system/capability/grant-entry`
(§3.6, lines 1010-1013) and §5.2 states the consequence in the strongest available terms:
*"The two MUST NOT be interchanged — a path dimension matched literally, or an id dimension
canonicalized, is a conformance defect,"* and *"an implementation on the canonicalizing
reading is non-conformant."*

**But the matcher is specified to read the type off the received entity.** `matches_scope`
(§5.2) carries, in its own comment: *"The scope entity carries its own type, so no call
site needs to supply it,"* and dispatches on `scope.type`. `scope_subset` (§5.6) goes
further — it compares `child_scope.type != parent_scope.type`, which is only meaningful if
both are runtime values off the wire.

**And nothing validates that value against the dimension, anywhere in the pipeline:**

| | what it checks |
|---|---|
| §3.6 `grant-entry` | declares the binding as a `type_ref` — a type definition, not a gate |
| §6.3 `put` | states outright it *"does not validate `data` against the type named by `type`"* |
| M3 (§5.5) — *"checked at chain-walk entry … for every entity in the chain"* | multi-granter shape only |
| `verify_capability_chain` | signatures · linkage · attenuation · caveats · TTL · revocation |
| `scope_subset` §5.6 line 3187 | child.type **vs parent.type** — relative, never against the dimension; and a **root** cap (`parent: null`) never reaches this function at all |

So under the spec as written, a capability carrying
`operations: {type: "…/path-scope", include: ["/*/get"]}` gets the canonicalizing matcher on
an id dimension. §5.2 says what that does: *"over-grants on `include` path-form patterns and
inverts the intent on `exclude`."* On a foreign-granted chain those bytes are entirely
caller-supplied.

**The cohort does not implement it that way. All of them.** Every peer supplies the kind
from the call site, derived from the dimension:

| peer | site |
|---|---|
| `python` | `capability.py:162` — *"`kind` … has no default — every call site names its dimension, so a new one cannot silently inherit the wrong matcher (that is the F40 defect)"* |
| `java` | `Capability.java:152` `matchesScope(…, ScopeKind kind)`, call sites `:261-265` |
| `csharp` | `Permissions.cs:47-49` — `ScopeKind.Id` / `ScopeKind.Path` literal per dimension |
| `typescript` | `scope.ts:64` `matches(value, localPeerId, kind: ScopeKind)` |
| `haskell` | `Capability.hs:223` `matchesScope :: Text -> Text -> Scope -> ScopeKind -> Bool` |
| `ocaml` | `capability.ml:166` `~(kind : scope_kind)` |
| `go`, `rust` | `kindID`/`kindPath`, `ScopeKind::Id`/`::Path` as parameters |

**This is not cohort drift — it is the safer reading, arrived at independently, and the
spec's version is the one with the hole.** The two agree on every well-typed grant, which
is why twelve days of review by four seats never saw it: the divergence is observable only
on a **mistyped** grant, which the type system nominally forbids and nothing validates.

**Ask (one sentence, plus a disposition):** state that the scope type is a property of the
**dimension**, supplied by the call site and never read from a received entity; and give a
received scope whose declared type contradicts its dimension the M3 treatment — malformed,
`403 capability_denied` under M3's own error-code normalization. `scope_subset`'s
type-equality check then becomes a dimension-supplied parameter, matching the signature all
46 peers already have.

**Cohort cost: zero.** Every peer already does this. The change makes the spec match the
implementations rather than the reverse — which is worth saying plainly, because it is the
first item in this arc with that shape.

---

## 4. F73 — the layer the last two revisions are about has no vectors

`check_path_permission` is **0 of 28 cells**. `0.8.2.20` promoted it from *"secondary
check"* to a `[MUST]` that is the sole enforcement for resource-absent requests; `0.8.2.21`
rewrote its `authority` parameter after two seats filled it from the propagated caller
capability; arch's `98f2946` has just found that §6.8's authority table *"flattened an
intersection"* at the same call site.

Three consecutive revisions of a function that nothing executes.

**Ask:** vectors on the L2 arms, and the first four are cheap because they need no new
fixture — a request with **no `resource`** whose path is outside the grant (the sole-
enforcement arm), the same with the path inside (its positive control), a listing whose
entries straddle the grant boundary (`filter_listing` — the count MUST reflect the filtered
set), and one `handlers`-dimension denial at L2 to prove the layer consults three
dimensions and not one.

---

## 5. What we are asking for, and what we are not

**We are not asking for a redesign.** The design is holding. Every defect found in this arc
has been a bookkeeping defect — two layers deriving one set, a rule landing in the prose and
not the block, a guard whose call site skips it. None has been a semantic defect in the
authority model.

**We are asking for the table to become a shared artifact**, in whatever home arch and
`entity-system-conformance` prefer:

1. **A fold lands when its cells are filled and their vectors are green.** That replaces the
   current exit condition — *nobody objected in this review round* — which is the
   unfalsifiable-negative shape both trees have ratified against, and which is why rounds
   end when reviewers tire rather than when a stated set closes.
2. **The N-homes sweep becomes mechanical.** A cell names its sites; §9.1's floor stops
   being the site a manual sweep reaches last, which it has been twice in one arc.
3. **It is the `requirements/` seed the new conformance seat needs.** Arch ruled
   `requirements/` neutral and requirement-keyed with the generator's TOML as the start
   point. This is that input for §5, and its exit condition — *a new suite that finds
   nothing* — is a real predicate over a stated denominator.

### 5a. ⛔ The frame question — asked, and the answer is NO. Withdrawn 2026-09-12.

~~One design question, asked once rather than discovered cell by cell: the largest single
multiplier in the space is frame-relative canonicalization at match time. Could
canonicalization move to mint time — a grant storing patterns already resolved against the
granter's frame, every matcher then a pure pattern operation with no frame argument?~~

**Struck rather than deleted, because the case table is worth more to the next reader than
silence.** The operator's objection on the day it was floated: *the granter is always known
at grant creation, so both readings freeze the same value and the result cannot differ.*
Checked case by case rather than conceded on plausibility — **it holds, and it is stronger
than the objection claimed**:

| case | match-time frame | mint-time frame | differ? |
|---|---|---|---|
| self-issued cap, local granter | local | local | no |
| handler grant (§6.8) | local — line 4028 **MUST-rejects** a non-local granter | local | no |
| cap minted by A, evaluated anywhere | A (per-link, §5.5a) | A | no |
| B delegates its `/{A}/*` onward as `*` | `/{B}/*`, refused by subset | `/{B}/*`, refused | no |
| already-absolute and `/*/interior` | pass through | pass through | no |
| `peers`, `operations` (id-scope) | never canonicalized | never canonicalized | no |
| **K-of-N multi-granter root** | **local** (§5.5 *"subsequent use is locally rooted"*; M6 puts the verifier in the signer set) | **no single granter exists to freeze** | **YES — and mint-time is strictly worse** |

Extensionally equivalent in every single-granter case, which is every case that occurs; the
one place they differ is the one place mint-time would need a special case it does not have.
The ergonomic benefit — a human not typing a peer id — is authoring-time and survives either way.

**And the bug class it was meant to delete is already gated.** Frame appears at four layers
and **only L3 takes a non-local frame**; §5.5a pins it and ships three vectors
(`authz_attenuation_foreign_granter_{1,deep,wildcard_leaf}`), which is what caught `swift` and
`sql`. So the residual value is an algorithm simplification bought with a wire-affecting
migration across 46 peers and three ground-up implementations, to remove a degree of freedom
with one non-obvious answer and three vectors on it.

**The durable half is about the recommendation, not the frame.** This repo's standing rule is
that *the exculpation most likely to be wrong is the one WE wrote, because nothing routes it
back for review* — and **a recommendation is an exculpation about future work**: it says which
effort is unnecessary, is read once, acted on, and never re-derived. This one was a day old,
was hedged as unverified, and was still wrong. **Measure the question before proposing the
migration**; the case table above took twenty minutes and reversed it.

---

## 6. Method, and its limits — stated so the next reader can attack it

- **The axes are read off the pseudocode**, not chosen. Anyone can re-derive them from
  §5.2/§5.4/§5.6/§6.8 and disagree with the layer list; that disagreement is the useful kind.
- **The reduction arithmetic self-checks.** Staged, with a closure assertion and a non-zero
  assertion per stage. An earlier cut reported `structurally dead 0` from two classifier
  branches that could never fire — the examined-zero-things class, in the instrument, caught
  only because the script prints its counts.
- **Two vector assignments were wrong in an earlier cut** and are corrected in place:
  `chain_parent_exclude_drop_denied` and `chain_operation_exclude_denied` were filed under L1
  caller-exclude when they drive the L3 delegation link. That single mis-assignment reported
  a false ZERO on exclude-inheritance *and* a false cover on the F68 arm — wrong in both
  directions at once, which is what a coverage table does when its mapping is by name.
- **The coverage column is `unknown` until driven.** It is the weakest part of this document
  and it is the part a probe run would replace. The four zeros are robust to the mapping
  being wrong in either direction, because no check in the 778-check set names L2, `peers`,
  or a caller exclude at all.
- **The prediction in §2b is the falsifier.** If the next two findings land outside L2, the
  `peers` dimension, and the exclude arms, this census is measuring the wrong thing.

**Reproduce:** `python3 tools/scope-cell-table.py --summary` · `--gaps` for the 109
uncovered cells.
