# HANDOFF-TO-ARCH — 2026-07-27 — F40 asymmetry audit: the vector input arch asked for

**Date:** 2026-07-27 · **Owner:** `arch` (F40 vector authoring) · **Severity:** informs the bucket-B vector
**Companion to:** `0.8.1-ratify-preconditions.md` §8 (the audit this discharges)
**Read at pins:** keystone `e44b6bd` · `entity-core-protocol` `85e8738` · `entity-core-go` `352364e`
**Reproduce:** `python3 protocol-generator/shared/diagnostics/f40-scope-typing-differential.py` (run from repo root)

> Arch's response asked for the asymmetry audit before authoring the F40 vector: *which peers
> canonicalize id-scope asymmetrically (a live ALLOW bug) vs benign-symmetric.* This is that answer.

---

## 0. Headline — the finding is stronger than "latent"

**The cohort is already split on F40, and we can demonstrate the divergence today.**

- **SQL is F40-conformant.** It matches id-scope dimensions RAW and canonicalizes only path-scope. It
  is also **the peer that discovered F40** (`A-SQL-008`) — after hitting a *real ALLOW bug*.
- **The other 42 canonicalize all four dimensions uniformly** — non-conformant to F40, but
  **symmetric**, therefore no live ALLOW bug in those peers.

So the "two impls guessing the typing diverge on ALLOW across a peer boundary" scenario 0.8.1 warns
about is **not hypothetical and not future** — we have both guesses in-house, in one cohort, right
now. That is the strongest possible argument for the vector, and it is available immediately.

**But the default deployment is safe:** the shipped seed policy uses only bare identifiers, where the
two readings agree. The divergence is reachable through an *authored* seed policy or a *foreign*
capability, not through anything the cohort ships. This is a conformance/interop defect, **not a live
production vulnerability**, and we recommend arch describe it that way.

---

## 1. Cohort classification

| Class | Peers | Behaviour |
|---|---|---|
| **F40-conformant** | **`sql`** (1) | `scope_match.sql`: `CASE WHEN :dim IN ('handlers','resources') AND pattern NOT LIKE '/%'` → canonicalize; id-scope dims match RAW. |
| **Uniform canonicalization — directly verified** | `python`, `go`, `rust`, `haskell`, `datalog` (5) | One shared `matches_scope`/`covered` helper applied to all four dimensions; both value and pattern canonicalized. |
| **Uniform canonicalization — type-declared but not acted on** | `apl`, `asm-arm64`, `asm-x86_64`, `csharp`, `forth`, `fortran`, `pd`, `rexx`, `riscv64`, `smalltalk`, `tcl`, `typescript`, `wasm-wat` (13) | `system/capability/{id,path}-scope` appears **only** in the type registry / coretypes; no match-time branch on scope kind. |
| **Not individually verified** | remainder | Same generation lineage and same helper shape; no contrary evidence found. |

**Method for the negative claim** (per the prove-a-negative rule): a cohort-wide search for any
match-time reference to `id-scope` / `id_scope` / `idscope`, excluding type-registry and type_ref
sites, returns **`sql` alone**. Every other hit is a `coretypes` / `typestore` / `TypeDefs`
declaration or a doc comment.

### Why the mainstream peers are benign

They canonicalize **both sides against the same frame**. Rust states it explicitly:

> `granter_peer` is the §PR-8 canonicalization frame for the cap's grant **resource** patterns; every
> other dimension stays on the **local** frame.

So for `operations` / `peers`, value and pattern both transform under `local_peer` → the transform
cancels → the comparison lands correctly. It is, in A-SQL-008's words, *"symmetric-but-meaningless —
it only works because both sides get the same transform."*

### Why SQL hit a real bug

Its relational encoding canonicalized **patterns against the granter frame** while comparing a **raw
value** — an asymmetry. Per `A-SQL-008`: *"Discovered as a real bug first — canonicalizing operations
against the granter frame while comparing a raw value broke the ALLOW path; the fix IS the split."*

**This is the "real ALLOW bug" the 0.8.1 §5.2 text cites.** Worth recording precisely: the bug arose
from *frame asymmetry*, and the typed split is what makes the whole class unreachable. The uniform-
symmetric peers avoid the bug by accident, not by construction — which is exactly why F40 is worth
pinning normatively.

---

## 2. The measured divergence — vector candidates

Produced by `protocol-generator/shared/diagnostics/f40-scope-typing-differential.py`, which imports the **real** keystone
Python peer's `_canon` / `matches_pattern` for the cohort column (measured, not modelled) and models
the 0.8.1 reading as `matches_pattern(value, pattern)` with no canonicalization.

**Agreement cases — the shipped seed policy (no divergence, good control group):**

| dim | value | patterns | cohort | 0.8.1 |
|---|---|---|---|---|
| operations | `get` | `["get"]` | ALLOW | ALLOW |
| operations | `request` | `["request"]` | ALLOW | ALLOW |
| operations | `put` | `["get"]` | deny | deny |
| operations | `get` | `["*"]` | ALLOW | ALLOW |
| peers | `{remote}` | `["{remote}"]` | ALLOW | ALLOW |
| peers | `{remote}` | `["*"]` | ALLOW | ALLOW |
| operations | `read/x` | `["read/*"]` | ALLOW | ALLOW |
| operations | `get` | `["/get"]` | deny | deny |

**Divergence — include path (4 classes). Cohort OVER-GRANTS:**

| dim | value | patterns | cohort | 0.8.1 |
|---|---|---|---|---|
| operations | `get` | `["/*/get"]` | **ALLOW** | **deny** |
| operations | `get` | `["/{local}/get"]` | **ALLOW** | **deny** |
| peers | `{remote}` | `["/*/*"]` | **ALLOW** | **deny** |
| peers | `{remote}` | `["/*/{remote}"]` | **ALLOW** | **deny** |

**Divergence — exclude path (2 classes). Conformant peer UNDER-DENIES — the security-relevant direction:**

Scope = `{include: ["*"], exclude: [P]}`; matches iff covered-by-include AND NOT covered-by-exclude.

| dim | value | exclude | cohort | 0.8.1 |
|---|---|---|---|---|
| operations | `get` | `["/*/get"]` | deny | **ALLOW** |
| peers | `{remote}` | `["/*/*"]` | deny | **ALLOW** |
| operations | `get` | `["get"]` | deny | deny (control) |

**Read this carefully — the direction inverts between include and exclude.** An operator who writes
`exclude: ["/*/get"]` into an operations scope gets the denial they intended on all 42 canonicalizing
peers and **no denial at all** on a spec-conformant peer. That is the case the vector most needs to
cover, and it is the one a naive rejection-only probe would miss entirely.

**Characterization:** divergence occurs exactly when an id-scope pattern is written in **path form** —
i.e. begins with `/` and uses the `/*/` universal prefix or an absolute `/{peer}/` prefix. Bare
identifiers, bare `*`, and trailing-`/*` forms agree under both readings.

---

## 3. Sub-finding for the vector author — "literal identifiers" is under-specified

0.8.1 §5.2 says id-scope values "are compared as **literal identifiers**." It does not say **which
wildcard forms survive** in an id-scope dimension. This must be pinned before a vector can be written,
because the vector's expected results depend on it:

- **`*` must survive** — `operations: ["*"]` is in the shipped open-grants policy and the §4.4
  discovery floor's vocabulary; a strict string-equality reading would break it.
- **Trailing `/*`** — does `operations: ["read/*"]` cover operation `read/x`? Our model says yes
  (retained); a strict reading says no. Both peers currently agree here only because we retained it.
- **The `/*/` universal prefix** — presumably meaningless for id-scope (that is the divergence class
  above), but the text should say so rather than leave it inferred.

Our differential assumes: **`*` and trailing `/*` retained; path canonicalization dropped.** If arch
intends something different, the divergence table changes and we will re-run.

Recommend 0.8.1 add one sentence to §5.2 pinning the id-scope wildcard grammar explicitly.

---

## 4. What the F40 vector needs to cover

1. **An accept-path vector** (already arch's stated requirement) — a rejection-only probe lets a
   canonicalizing peer pass. Use the include-path divergences: a cap whose `operations.include` is
   `["/*/get"]` must **not** authorize operation `get`.
2. **An exclude-path vector** — the inverted direction of §2, which we believe is the higher-value
   half and which is easy to omit. A cap with `operations: {include: ["*"], exclude: ["/*/get"]}` must
   **still authorize** `get` on a conformant peer.
3. **A `peers`-dimension vector** — the divergence is not operations-only; `peers` shows the same
   split (`/*/*`, `/*/{peer}`).
4. **A path-scope control** — `handlers` / `resources` with `/*/`-form patterns must **still**
   canonicalize and match, so the vector proves the *split*, not a blanket removal of canonicalization.
5. **Bare-identifier controls** — must pass on both readings, so a peer cannot satisfy the vector by
   breaking the common case.

Items 1–3 come with concrete inputs from §2; we can supply them in whatever fixture format the
`authz` category prefers.

---

## 5. Position on remediation

Unchanged from the preconditions handoff: **we hold the fix.** The remediation is small (branch the
scope-match helper on dimension kind — SQL shows the shape) but we would rather it be *measured by the
vector* than *asserted by us*, and the §3 wildcard-grammar question must be settled first or 42 peers
get fixed to the wrong reading.

One thing worth arch's attention: because SQL is already conformant and the other 42 are not, **the
cohort currently cannot be internally consistent under either reading.** Whichever way §3 resolves,
one side of the cohort changes. That is a normal consequence of pinning a real ambiguity — noting it
so the vector's arrival is not a surprise on the board.

---

## 6. Evidence appendix

| Claim | Evidence |
|---|---|
| SQL is F40-conformant | `CASE WHEN :dim IN ('handlers','resources') AND pattern NOT LIKE '/%'`, `sql/src/sql/scope_match.sql` @ `e44b6bd` |
| F40 originated in the SQL peer | `A-SQL-008`, `sql/status/SPEC-AMBIGUITY-LOG.md` — "the fix IS the split", status OPEN→escalated to arch |
| The cited ALLOW bug was frame asymmetry | `A-SQL-008`: "canonicalizing operations against the granter frame while comparing a raw value broke the ALLOW path" |
| Mainstream peers are symmetric | `check_permission` doc + call sites, `rust/src/peer/capability.rs` — "every other dimension stays on the local frame" |
| Uniform shape (python/go/rust/haskell/datalog) | `_matches_scope`/`matchesScope`/`matches_scope` single helper over all four dims; `datalog/src/dispatch.rs` projects via the same `matches_scope` |
| No other peer splits at match time | cohort-wide search for match-time `id-scope`/`id_scope`/`idscope` excluding type-registry sites → `sql` only |
| Seed policy uses bare identifiers only | `_discovery_floor` → `operations: ["get"]`, `["request"]`; `_open_grants_scope` → `["*"]`, `peers: ["*"]`, `python/src/entity_core/peer/peer.py` |
| Divergence table | `protocol-generator/shared/diagnostics/f40-scope-typing-differential.py`, run against the real peer functions @ `e44b6bd` |
