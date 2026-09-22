# Seven peers do not resolve a handler they just registered — and §6.6 makes that a MUST

**Date:** 2026-09-09 · **Seat:** `entity-core-keystone` · **Register:** F62
**Measured against:** oracle `78db4a9`, executed check set `7aa6f3de…` (778 checks), spec snapshot
`v0.8.2.11` (`c97e1860…`). All 46 peers are `778 · 0F` and **no number moves** — that is the point.

**This corrects our own finding.** `host-seam-dispatch-wire-census.md` says of all three failure
shapes: *"None of it is a conformance failure — §6.13(a) is an extension surface."* That is right
for two of the three and **wrong for `NOT-RESOLVED`**. §6.13(a) is an extension surface; **§6.6 is
core**, and these seven peers fail it.

> **REPAIR IN PROGRESS — 1 of 7 closed, 2026-09-09. `smalltalk` is now
> `BOUND-NOT-EVALUATED`.** Its `resolveHandler:` consults the entity tree as well as the
> in-image `handlers` map, so the index and the walk are equivalent **by construction** rather
> than by keeping two containers in step — nothing has to remember to mirror a write, and
> unregister, which unbinds the path, needs no second teardown. `runHandler:` separates the two
> misses that were collapsed into one 404: no entity is a resolution miss (**404**), an entity
> with no bound block is a handler the peer resolved and cannot run (**501 `no_handler_body`**,
> the spelling `datalog`/`nim`/`oz` and the reference peer already use — and one this finding
> does not invent around, because F60 is exactly that vocabulary gap).
>
> **Measured three ways, and the third is the one that had to be built.** `host-seam-probe`:
> `NOT-RESOLVED` → `BOUND-NOT-EVALUATED`, with the **negative control still answering 404** —
> an unregistered path must not start resolving, which is the control that matters for a change
> that makes resolution look in a second place. `--profile core`: `778 · 333P/338W/0F/107S`,
> executed digest equal to the pin, **exactly 0 of 740 severities moved** — additive, as this
> finding predicted. And `protocol-generator/smalltalk/tests/handler-resolution.st`, 6 of 6, in
> the peer's `make s3` gate: **the repair had to ship with an executable gate because no
> conformance check can hold it**, which is this finding's own argument turned into a file.
>
> **Retiring the defect exposed that three of that peer's sibling gates could not go red.**
> `pharo eval` exits 0 whatever a driver prints; the `sunit` target carries a comment saying so
> and was fixed for `sunit` alone on 2026-09-02. `conformance`, `int-boundary` and
> `crypto-accept` each END by printing their own verdict and nothing read it — measured by
> planting a bad SHA-256 KAT, at which the driver printed `FAILED (1)` and `make crypto-accept`
> exited **0**. All three now assert their green verdict positively. That is not incidental to
> F62: **a repair whose only possible gate is a peer-local unit test is worth exactly as much as
> that peer's unit-test plumbing**, and here the plumbing was decorative.
>
> **CLOSED — 7 of 7, 2026-09-09. All seven are `BOUND-NOT-EVALUATED`, every negative control
> still 404, and `0 of 778` severities moved on every peer.**
>
> **This finding mis-scoped three of its own six, and the correction is the more useful half.**
> The paragraph that stood here read: *"they need a container the wire register can write before
> they can have an index at all."* That is true of the ISA trio and **false of `cobol`,
> `fortran` and `forth`, which were already walking the entity tree at §6.6.** The 404 came from
> the rung *below* resolution. The error was inherited from this finding's own evidence table,
> which recorded each peer's `dispatch_read_site` — and on those three that field named the
> **body-selection ladder**, not the resolution site. **A census field that names the wrong line
> produces a scope estimate that is wrong in the expensive direction**, and the field H5 exists
> for is exactly the one that misled it. All six are corrected in `profile.toml`.
>
> | peer | what was actually wrong | repair |
> |---|---|---|
> | `cobol` `fortran` | **two sites for one refusal.** `resolve-handler` / `resolve_handler` already walked the store; its miss took the 404. The ladder below it is body selection and its fall-through was spelled `404 handler_not_found` | one arm each → `501 no_handler_body` |
> | `forth` | the walk was real and **querying a key space nothing else wrote**: `register-handler` bound the bootstrap entity at the BARE pattern while `publish-handler-dispatch`, the wire register op and every validator `TreeGet` use `/<local>/<pattern>` | both sides on the canonical key; `hnd-lookup`'s miss moved below the authz gate and became 501 |
> | `asm-x86_64` `asm-arm64` `riscv64` | **genuinely no walk.** `uri_handler_known` is a compile-time list of natively-routed patterns, which a run-time install cannot reach | added `uri_handler_in_tree` (§6.6 walk over `canon_path` + `store_get` + type test), consulted AFTER the native index; walk-only hit → 501 |
>
> **`forth`'s is the one worth carrying past this finding.** A peer can hold *two key spaces for
> one fact* — the walk read one, every write used the other — so §6.6 equivalence had nothing to
> be equivalent TO. That is invisible to a source read of the walk, which looks correct, and it
> is why the single-sided mutation control below produced a *broken peer* rather than the defect.
>
> **Controls: three plants, one per repair shape, each asserted present before its run.**
> Reverting `cobol`'s verdict, `forth`'s key space (both halves) and `asm-x86_64`'s walk each
> returned `NOT-RESOLVED` with the positive control still 200. The **failed** fourth is recorded
> because it is the informative one: reverting only `forth`'s *walk* while its bootstrap still
> bound canonically made every built-in unresolvable — positive control `404`, verdict
> `UNTRUSTED`. A plant that breaks the peer has not demonstrated the defect; it has demonstrated
> that the two halves are one change.
>
> **Residual, named rather than folded into the win.** On the ISA trio the index and the walk are
> equivalent in **one direction only**: `system/type` and `system/handler` sit in the native index
> and carry no dispatch entity in the store, so a strict walk would not find them. That is a §6.2
> *publication* gap on paths the peer does route — not a §6.6 resolution defect — and bundling it
> into this repair would have coupled two changes with different evidence.
>
> **The gate is still owed and is deliberately not six unit tests.** `smalltalk` shipped with a
> peer-local unit test; the same shape across COBOL, Forth, Fortran and three assembly languages
> would be six divergent gates over one rule, and the ISA units cannot reach the dispatch path at
> all. The right artifact is **one Kind C independent check** for §6.6 index/walk equivalence —
> which covers all 46 peers, retroactively gates `smalltalk`, and is this finding's own Ask 1 in
> the form this repo is permitted to author. Until it exists, `tools/host-seam-probe` is the
> evidence and it does not gate.

---

## The rule

§6.6 `resolve_handler` walks backward through path segments and returns the first prefix carrying a
`system/handler` entity. The pseudocode ends with the clause this finding turns on:

> ```
> ; Implementations MAY use a pre-built dispatch index for performance.
> ; The index MUST produce equivalent results to the tree walk.
> ```

An index is optional. Equivalence is not.

## The evidence chain

Each link is measured, and the two independent instruments agree.

1. **A `system/handler` entity provably exists at the registered pattern, on all 46 peers.** The
   oracle's `core_register_handler_at_path` registers at `app/validate/core-register/echo`, then
   `TreeGet`s that pattern and **asserts `ent.Type == types.TypeHandler`**, failing with
   `type=%q (expected %q)` otherwise (`cmd/internal/validate/core_register_gate.go:204`). It is
   **PASS on 46 of 46** — read per-check across every committed report, not inferred from the
   category.
2. **`tools/host-seam-probe` reproduces the precondition independently**, at its own pattern
   `app/validate/core-register/hostseam`: register answers 200, and step 3 retrieves the handler
   entity at that pattern (200, carrying `expression_path`).
3. **Seven peers then answer `404 handler_not_found` when dispatched at that same pattern** —
   `asm-arm64` `asm-x86_64` `cobol` `forth` `fortran` `riscv64` `smalltalk`. §6.6's walk, run at
   `i = len(segments)`, finds the entity from link 1 on its first probe.
4. **The other 39 resolve, and that is what makes this a resolution finding rather than an
   evaluation one.** 26 evaluate the body (200); 3 answer `501` with the body bound and no evaluator;
   9 answer `501` having dropped the body reference at register. **All twelve 501s prove resolution
   SUCCEEDED and the body could not run** — the exact distinction between a §6.6 defect and a
   §6.13(a) gap, and it is visible only because the cohort splits.
5. **Their dispatch layers are static by construction**, from each peer's own hand-traced
   `dispatch_read_site` (`profile.toml`, `[extension_host]`):

   | peer | what dispatch reads |
   |---|---|
   | `asm-x86_64` `asm-arm64` `riscv64` | `derive_handler` then a length-then-bytes **op ladder**; anything unmatched → 404 |
   | `cobol` | a `when splen = N and spat(1:N) = "…"` **pattern ladder**, else 404 |
   | `forth` | `hnd-lookup` reads the **bootstrap table** |
   | `fortran` | a routine id from a table `reg_handler` fills **only at bootstrap** |
   | `smalltalk` | `handlers at: aHandlerPath ifAbsent: [404]` — a real Dictionary, **written only at bootstrap**; the wire register op never reaches it |

   Six have no container the wire register can write. `smalltalk` has one, dispatch reads it, and
   only the wire path is unwired — a different repair, and the cheapest of the seven.

**None of these peers mentions `expression_path` anywhere in its source** (`git grep -il` → 0 files
on six of seven; `smalltalk` only in its register handler's persistence and its type declarations).
The manifest is forwarded verbatim, which is why the field lands correctly on a peer that cannot use
it.

## What the checks that exist do and do not ask

`core_register_*` is nine checks that **prove every write** — op status, op result, manifest at path,
handler at path, grant at path, grant-signature at the invariant path, and the unregister teardown.
**Not one of them then dispatches at the pattern it just proved exists.** The neighbouring checks
that look like they would are pointed elsewhere, verified rather than assumed:
`unsupported_operation_on_registered_handler`'s target is **`system/tree`**, a *bootstrap* handler,
and `validate_echo_dispatch` drives the built-in `system/validate/echo`.

So a peer can bind all four §11.6.1 writes, score `778 · 0F`, and be unable to route a request to
what it just wrote. **This is FM-1g's shape — a MUST with no gate — and the fix is one line at the
end of a gate that already holds everything it needs.**

## Asks

1. **One vector** (`entity-core-go`): after `core_register_handler_at_path` passes, EXECUTE at
   `coreRegisterTestPattern`. Any answer other than 404 satisfies §6.6 — **the check must not assert
   200**, because a peer with no evaluator correctly answers 501 and that is conformant. It is a
   resolution check, not a body check, and drawing that line in the check's own message is what
   stops it being read as a §6.13(a) requirement.
2. **Confirm the reading** (arch): is *"the index MUST produce equivalent results to the tree walk"*
   binding on a peer whose dispatch is a static ladder — i.e. does a peer that never builds an index
   at all still owe the tree walk? We read it as yes: the walk is the definition and the index is the
   optimisation, so a peer with neither resolves nothing and fails the definition. If that reading is
   wrong the finding collapses, which is why it is asked rather than assumed.

## Our half

**The seven are ours to fix and they are not one repair.** `smalltalk` needs the wire register to
reach the container dispatch already reads. The other six need a container first — for the ISA trio,
`cobol`, `forth` and `fortran`, dispatch resolution is authored as a static ladder and making it
consult the store is real work, not a wiring change. The §6.13(a) evaluator is a **separate**
item after that; none of the seven has one, and it is the honest 501 rather than a defect.

**Disclosed** in `CONFORMANCE-MATRIX.md` §1 rather than left behind seven green rows.

## The instrument caveat, stated because it is the weak link

`host-seam-probe` asserts `expression_path` on the landed entity and, **until this finding, did not
assert its `type`** — so link 1 rested on the oracle's `core_register_handler_at_path` rather than on
the probe's own observation. That is an independent implementation asserting exactly the right
proposition on the same peers, which is a strong cross-check and is **not** the same measurement.
The probe now records `register_landed_type`, so the next roster run makes each row self-contained.
Reported this way rather than quietly: a control that asserts the field a claim depends on is the
rule this repo already ratified, and this claim leaned on someone else's control for one link.
