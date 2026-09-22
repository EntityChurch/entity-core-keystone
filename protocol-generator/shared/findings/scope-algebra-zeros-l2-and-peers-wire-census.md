# The cell census had four zeros. All four are now driven — and the biggest one is a layer, not a cell

**Date:** 2026-09-14
**Seat:** `entity-core-keystone`
**Instrument:** `tools/arc-probe` families **F** and **G** (added this pass; probe, runners and
summarizer committed beside this file)
**Measured against:** `entity-core-protocol` `7937347` (spec `0.8.2.23`), cohort pinned at spec
snapshot `v0.8.2.11`, all 46 peers `778 · 0F` on executed check set `7aa6f3de…` (oracle `78db4a9`)
**Measured:** 45 of 46 — `turbowarp` is structurally out of reach, as in every prior arc run.

---

> ## ✅ UPDATE 2026-09-16 — **`F84` AND `F85` ARE REPAIRED; THE EMPTY CELL IS NOW POPULATED AT 44**
>
> Everything below is the measurement **as taken on 2026-09-14** and is left standing — a dated
> measurement that gets back-edited stops being evidence of anything. This box says what has moved.
>
> Re-measured on a **single-age** roster run of `tools/arc-probe` (**46 of 46** reported, report-age
> span **0.04 h**) plus `run-mint-floor.sh` for the five peers the §6.9a discovery floor voids.
> Controls green on every counted row.
>
> | row | as taken (2026-09-14) | 2026-09-16 |
> |---|---|---|
> | `G2` — dispatch vacated by a caller exclude | 33 of 43 served an uncovered path | **44 of 46 conform** |
> | `G4` — listing filter | 35 of 40 named an excluded entry | **44 of 46 conform** |
> | `A3` — selection from the effective set | **`no` on 45 of 45** | **44 of 46 conform** |
> | `F1` — Dimension 4 inbound (**`F85`**) | 4 do not evaluate it | **45 of 46** — `sql` alone |
> | `E2` — matchable grant exclude (**`F83`**) | 4 never read the field | **46 of 46 conform** |
>
> ⭐ **The cross-tabulation is the part that matters, because the count never was.** This document's
> §3 argued that the finding is *a layer with zero working instances* rather than *33 peers with a
> bug*, on the evidence that the cell *`A3` conforms × `G2` conforms* was **EMPTY** — nobody had a
> wrong selection caught by the path check. **That cell now holds 44 peers.**
>
> ⛔ **The residual is two peers and it is a different finding: `fortran` and `unison` were never
> swept at all.** They are the whole of the `no` column on `A1`–`A4`, `G2` and `G4`, and they owe
> **5 of 6 §4.11 arms** besides. No `sweep tranche` or vanguard commit touches either — verified as
> a set difference, **44 swept against a 46-peer roster**. `CONFORMANCE-MATRIX.md` footnote ¹³ and
> `docs/STATUS.md` carry it; the two rows published `0.8.2.25` for one day and now publish
> `0.8.2.21`.
>
> **And the reading that is NOT licensed: none of this moved a conformance number.** The 46 tracked
> reports were re-measured across the sweep and **3 of 35 788 severities** differed. The check set
> cannot distinguish the cohort described below from the cohort described in this box — which is
> `F73` stated as a measurement rather than an argument, and it is why the `arc-probe` families
> retire on a vector and not on a green row.

---

## 0. Why this was taken

`scope-algebra-cell-census.md` enumerated the §5 scope algebra as **146 live decision cells, 37
with a named vector**, named **four structural zeros**, and published a falsifier:

> **The next finding will land in L2, the `peers` dimension, or an exclude arm.** If the next two
> land somewhere else, this census is measuring the wrong thing and should be said so.

Two of the four zeros had been driven by the time that was written, and both produced a
cohort-scale finding: the **caller-exclude** arm gave `F68`/`F71`, and the **grant-exclude** arm
gave `F83` — four peers reading no grant exclude at dispatch at all. The remaining two had never
been driven by anything: **`peers`, 0 of 24** and **`check_path_permission` (L2), 0 of 28**.

**A prediction with two of four quadrants unexamined is not a closed argument in either
direction.** This is those two quadrants.

---

## 1. What the two families drive, and their controls

Every row runs under a capability the probe MINTS during the run, so the subject is that token's
own scope rather than the peer's shipped floor. Both families carry a positive control and family
G additionally carries an antecedent.

| row | asks | control that makes it readable |
|---|---|---|
| **F0** | a grant whose `peers` names this peer authorizes here | — (it IS the control) |
| **F1** | a grant whose `peers` **excludes this peer** must not | F0, and the peer id is derived from the handshake |
| **F2** | a grant scoped to **another** peer must not | F0 |
| **F3** | a grant with **no** `peers` scope must still work | differential: value vs mere presence |
| **G0** | a narrow capability works for what it covers | — (it IS the control) |
| **G1** | **antecedent**: the narrow capability genuinely refuses `qB` | without it, a 200 in G2 is explained by a wide grant |
| **G2** | a caller exclude that vacates the dispatch check must not yield the uncovered path | G0 + G1 |
| **G3** | **control**: the unfiltered listing NAMES `qB` | without it, `qB`'s absence in G4 is the trivial truth |
| **G4** | a listing under a capability excluding `qB` must omit it, and `count` must follow | G3 |

**The peer id is derived from the wire, not from the harness** — the session capability's granter
IS the responder, and §5.2 requires that granter's `system/peer` to be resolvable, so it is in the
`authenticate` response's `included` map. Our own entry is skipped **by public key, not by content
hash**: the hash is precisely the value family B forges, and a helper that trusted it would inherit
the defect that family exists to find. Zero or more-than-one candidate is an error, never a guess.

**Eight peers refuse `system/capability:request` under the §6.9a discovery floor** and are measured
through `run-mint-floor.sh` instead, whose header now states which families may be read out of it
and **which row changes meaning** (`F2` is refused at MINT under the floor and on USE under open
grants — two different gates, graded separately, never pooled).

---

## 2. `peers` (Z2) — largely CLEAN, and saying so is half the value

| row | conform | do not | VOID | not measured |
|---|---:|---:|---:|---:|
| **F1** — grant excludes this peer | **39** | **4** | 2 | 1 |
| **F2** — grant scoped to another peer | **43** | **0** | 2 | 1 |

**The four that do not evaluate Dimension 4 on the inbound path: `asm-arm64`, `asm-x86_64`,
`riscv64`, `sql`.** A capability whose own `peers` scope excludes this peer authorizes an ordinary
local request on them. §1.4 names this exact reasoning as forbidden:

> Implementations MUST NOT conclude from the inbound path's invariant that the dimension is inert
> and MUST NOT skip the check on an absent `peers` field.

**Two dispositions are both conformant and are reported apart, not pooled.** `c` and `cpp` refuse
to MINT a grant excluding this peer (`403 scope_exceeds_authority`) — nothing is authorized, and it
is recorded that refusing a *narrowing* is a stricter reading than §6.2 requires, because an
exclude only ever shrinks a grant. `forth` and `smalltalk` are VOID for a peer reason already on
record: they mint a capability and then deny it on use, including the control that carries no
exclude at all.

**Say the surface this ranges over.** §1.4 puts Dimension 4's *working* surface on OUTBOUND
sub-dispatch — which peers a grant may be spent against — and that needs a second peer and is
PD-2's territory. **A green family F is not a green `peers` dimension**; it is the inbound half,
which §1.4 rules unreachable-but-mandatory.

**This partially falsifies the cell census's prediction and that is recorded as such.** Three of
the four zeros produced findings; `peers` largely did not. The census said it should be said so.

---

## 3. L2 (Z1) — the finding, and it is a LAYER rather than a cell

### 3a. `G2` — 33 of 43 serve a path no authorization covered

`targets:[qB,qA] exclude:[qB]`, under a capability covering `qA` and **not** `qB`. The caller's own
exclude removes `qB` from `check_permission`'s view — §5.2 evaluates the effective set — so the one
path the grant does not cover is the one path dispatch no longer looks at. A handler that then
indexes `targets[0]` serves it.

| answer | reading | peers |
|---|---|---:|
| served `qA` or refused | nothing uncovered was served | **10** |
| **served `qB`** | **a path outside the caller's capability was disclosed** | **33** |
| VOID (control failed) | — | 2 |

### 3b. The decisive cross-tabulation: **no peer has the backstop at all**

`A3` (selection among two IN-GRANT targets) and `G2` (the same shape with the grant made the
variable) were tabulated against each other across all 45:

| | `G2` conforms | `G2` serves `qB` |
|---|---:|---:|
| **`A3` conforms** | **0** | **0** |
| **`A3` does not** | 10 | 33 |

**`A3` is `no` on 45 of 45. Not one peer in the cohort selects from the effective set.** And the
empty top row is the finding: **there is no peer where the selection is wrong and `check_path_
permission` catches it.** The 10 that do not disclose are not protected by L2 — they refuse for
reasons §6.3 does not ask for:

- `csharp`, `typescript`, `node-red` — a **raw arity check** (`400 handler_error`), which `F71`
  already warns refuses a legitimate single-entry effective set;
- `nim` — `400 ambiguous_resource`, counting raw targets rather than effective ones;
- `pd` — `403`;
- `asm-arm64`, `asm-x86_64`, `riscv64`, `sql`, `wasm-wat` — `403`.

So the honest statement is not *"33 peers have a bug"*. It is: **§6.3 designates
`check_path_permission` as "not a secondary check — the sole enforcement wherever the subject is
derived after dispatch", and the cohort contains zero instances of it doing that job.** Where the
disclosure does not happen, it is prevented by an unrelated refusal.

### 3c. `G4` — the listing filter, 35 of 40

§6.3 (0.8.2.21/.22): every entry of a multi-entry result MUST be individually checked, DENY entries
MUST be omitted, and `count` MUST reflect the filtered total.

| answer | peers |
|---|---:|
| `qB` omitted and `count` agrees | **5** — `csharp` `typescript` `nim` `pd` `node-red` |
| **listing names an entry the caller's own capability excludes** | **35** |
| VOID (nothing enumerable at that path, or control failed) | 5 |

**This one is independent of `A3`** — a different code path, and five peers do implement it — so
unlike `G2` it is not the selection defect wearing a security consequence. It is the read path at
its highest volume, which is precisely the reason `0.8.2.21` refused to carve reads out.

---

## 4. The vanguard: two peers brought to `0.8.2.23`, and what it cost

`go` and `python` — one static and one dynamic substrate, both generator backends — were taken
from the measured state to full conformance on every row this instrument drives.

**The work, identical in both:** an `effective_targets` derivation; §3.3's ladder
(`path_required` / `ambiguous_resource` / `malformed_resource` / proceed **on that entry**) in
`get` and `put`; `check_path_permission` called on the resolved path; and the listing filter with
`count` following. Roughly 90 lines each.

| | before | after |
|---|---|---|
| family A (§3.3 ladder) | 0 of 5 | **5 of 5** |
| family G (§6.3) | 0 of 2 | **2 of 2** |
| family F (§1.4 D4) | 2 of 2 | 2 of 2 |
| remaining | — | **C1/C2 only — `J4` clause 2, which `F78` asks to withdraw** |

### ⛔ 4a. The measurement that matters: **0 of 778 severities moved, on each**

Both peers were re-censused check-by-check against their committed reports. **`0 of 778` moved on
`go`, `0 of 778` on `python`**, no `budget_exhausted`, identical summaries. `make lint`, `run-s2.sh`
and the S3 axis are green on both.

**So the pinned check set cannot distinguish a peer that violates three landed MUSTs from one that
does not.** That is the same shape as `F62` and the H1 census, and it is the argument for `F73`'s
cell table more directly than any count of cells.

### 4b. The vanguard corrected an error a source read had made — ours

Our first `go` implementation threaded the **per-link granter frame** into `check_path_permission`
by analogy with §5.5a. **§6.3's own block settles it:**

```
matches_scope(canonical_path, grant.resources, "system/capability/path-scope", local_peer_id)
```

There is no granter parameter to pass. §5.5a governs chain **attenuation**, where the subject is a
pattern compared against a parent's pattern; this call site compares a **concrete local path**. The
sibling `python` peer had it right and said so at the definition — *"do not add a granter frame to
it"* — which is what caught it. **This is the standing rule that when a scope question has 45
existing answers in the tree, ask them, reached from the side where the tree was right and we were
not.**

### 4c. What the vanguard did NOT implement, stated rather than left to inference

- **§6.8's intersection.** `check_path_permission`'s `authority` is, for a caller-serving access,
  `ctx.caller_capability` **AND** `ctx.handler_grant` as a ceiling — *"BOTH must pass"*. Both peers
  implement the **caller** side only. The handler-grant ceiling needs a handler whose own grant is
  narrower than the caller's, which no core peer ships, so it is neither implemented nor driven.
- **`registerPattern`** still derives its install pattern from `targets[0]`. `register` is bounded
  by Dimension 1 rather than resources and is unreachable under the shipped floor, so it is left
  alone deliberately rather than swept.

---

## 5. ⛔ One spec question the vanguard surfaced, and it is not rhetorical

**§3.3 says an empty effective list IS the absent case. The two peers' absent case is a root
listing, and their empty-effective case is now `path_required`. Those cannot both be right.**

> **An empty effective list IS the absent case** — a request naming one target and excluding it
> asks for nothing. […] `path_required` is raised when an operation **whose own specification
> requires a `resource`** is invoked without one.

For `put` there is no difficulty: it requires a resource, so both are `path_required`, and both
peers now answer that (correcting a prior `ambiguous_resource` for a *missing* target, which
0.8.2.20 names as the exact inversion it forbids).

For `get` it is genuinely undetermined. §6.3's grammar makes the LISTING route a **trailing-slash
target** (`Trailing "/" or empty string on resource: return listing`), not an omitted resource — so
`get` arguably requires a resource and an absent one should be `path_required`. But every peer in
the cohort answers an absent resource with a root listing, and nothing in the 778-check set
objects.

**We did NOT resolve this unilaterally.** Both vanguards keep the root-listing behaviour for a
genuinely absent `resource` and answer `path_required` only for an empty effective list, with the
reasoning at the branch. **Ask: does `get` require a `resource`?** A one-sentence answer either
confirms the shipped behaviour or makes it a cohort-wide change, and it is cheap now and expensive
after 45 peers have been swept.

---

## 6. What is owed

**Arch — two, and the first is one sentence:**

1. **§3.3 / §6.3: does `system/tree:get` require a `resource`?** §5 above. Either answer is
   implementable; the ambiguity is what is not.
2. **`F84` and `F85` need vectors, and that is `F73`'s ask with a denominator.** `check_path_
   permission` is 0 of 28 cells and the cohort has zero working instances of it; `peers` is 0 of 24
   and four peers skip it. Both were invisible to 778 checks and to four seats reviewing §5 for
   twelve days.

**Ours, and it is the larger half:**

3. **The §6.3 layer on the remaining 43 peers** — `check_path_permission` plus the listing filter.
   Two reference implementations exist, the shape did not vary between them, and `arc-probe`
   families A and G grade every row with controls. **This one is NOT sequenced behind vectors:**
   the standing test is *"is there something that can tell me I got it wrong"*, and there is — the
   same argument that justified sweeping the §5.4 sentinel and not the §3.3 ladder.
4. **The §3.3 ladder on the remaining 43** — it comes with (3) rather than after it; the selection
   rule and the path check are one edit at one call site, and landing either alone leaves the
   other's arm untested.
5. **Dimension 4 on `asm-arm64`, `asm-x86_64`, `riscv64`, `sql`.**
6. **`forth` and `smalltalk`** mint a capability and then deny it — unchanged, still its own
   question, still unmeasurable here.

---

## 7. Limits of this measurement

- **45 of 46.** `turbowarp` is out of reach for families A/B/F/G.
- **One generation lineage.** 45 peers agreeing is cohort-consistent, not independent convergence.
  The three ground-up implementations are not measured here.
- **G3/G4 use a MINTED grant**, which the discovery floor cannot produce (its resources are whole
  subtrees). That is a deliberate departure from floor-only measurement, made because the
  alternative was leaving a landed MUST at zero coverage — but it means those two rows are a
  reading about the peer's FILTER, not about the peer as an adopter finds it configured.
- **The `peers` dimension's outbound half is not driven**, and it is where §1.4 says the dimension
  does its work.
- **§6.8's handler/caller intersection is not driven** and not implemented.
