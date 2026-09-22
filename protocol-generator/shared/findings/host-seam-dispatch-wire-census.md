# H1 on the wire — 26 of 46 peers can dispatch an installed handler body

**Date:** 2026-09-09 · **From:** `entity-core-keystone` · **Instrument:** `tools/host-seam-probe`
(Kind A probe — `docs/VERIFICATION-ARCHITECTURE.md`)

**Surface:** `docs/spec/SPEC-KEYSTONE-PEER.md` **H1** v1.0 @ `62e1a1dd…` — *a handler installed after
construction is reachable by dispatch* — in the **entity-native (model 3)** shape.
Wire mechanics: `ENTITY-CORE-PROTOCOL` §6.13(a) + §11.6.1, snapshot `v0.8.2.11`.
**Measured against** oracle `78db4a9`, executed check set `7aa6f3de…`, all 46 peers at `778 · 0F`.

---

## The number

**46 of 46 measured. 0 untrusted. 26 can dispatch an installed body; 20 cannot.**

| verdict | n | peers |
|---|---:|---|
| **`EVALUATES`** | **26** | `common-lisp crystal csharp dart elixir go haskell io java julia kotlin lean node-red ocaml odin php python rexx ruby rust rust-wasm rust-wasm-wasmtime tcl turbowarp typescript zig` |
| `REGISTER-DROPPED-EXPRESSION-PATH` | 9 | `ada apl c cpp pd prolog sql swift unison` |
| `NOT-RESOLVED` | 7 | `asm-arm64 asm-x86_64 cobol forth fortran riscv64 smalltalk` |
| `BOUND-NOT-EVALUATED` | 3 | `datalog nim oz` |
| `CONTROL-FAILED` | 1 | `wasm-wat` |

`EVALUATES` means the peer answered **200 carrying the planted literal** — the expression ran, not
merely resolved. The 26 include `rust-wasm` and `rust-wasm-wasmtime`, which inherit `rust`.

**None of this is a conformance failure.** §6.13(a) is an extension surface; a core peer that binds
correctly and has no evaluator is honest and conformant. The finding is about **H1**, which is
keystone's own contract, and about what an extension host may assume.

## Why it needed measuring — nothing in the check set asks

Verified against the pinned oracle rather than assumed:

- **`core_register_body_binding`** asserts the §11.6.1 entities were **bound**. Its PASS message is
  *"entity-native echo body bound at …"*. It never dispatches. All 46 peers PASS it.
- **`unsupported_operation_on_registered_handler`** reads as if it dispatches an installed handler.
  Its `registeredURI` is **`system/tree`** — a *bootstrap* handler. "Registered" means present.
- **`validate_echo_dispatch`** dispatches `system/validate/echo`, also a built-in. The oracle's own
  declaration records the dispatch half was deliberately *"moved off compute/literal"*.

So a peer can bind all four §11.6.1 writes, score `778 · 0F`, and have nowhere for a body to run.
That is the state 20 of 46 peers are in, and no published number says so.

> ⚠️ **CORRECTED 2026-09-09 — the sentence below about none of this being a conformance failure is
> WRONG for the seven `NOT-RESOLVED` peers, and the correction makes our own reading worse.**
> §6.13(a) is an extension surface and that framing holds for `BOUND-NOT-EVALUATED` and
> `REGISTER-DROPPED-EXPRESSION-PATH`. It does not hold for `NOT-RESOLVED`: those peers 404 at a
> pattern where a `system/handler` entity provably exists, and **§6.6 makes index-equivalence with
> the tree walk a MUST** — a CORE requirement, not an extension one. The discriminator is that the
> other twelve non-evaluating peers answer **501**, which proves resolution succeeded. Routed as
> **F62**; chain in [`handler-resolution-index-equivalence.md`](handler-resolution-index-equivalence.md).
> The verdict names and the measurement in this document are unchanged and correct — what was wrong
> is the conformance framing laid over them.
>
> **All seven are repaired as of 2026-09-09 and the `NOT-RESOLVED` group is empty.** The counts
> below are the measurement as taken and stay that way; F62 carries the current state. One detail
> from the repair belongs here rather than there, because it is about **this document's own
> method**: the per-peer `dispatch_read_site` values this census reasoned from named the
> **body-selection ladder** rather than the §6.6 resolution site on three of the seven, which made
> F62 size their repair as *"needs a container first"* when they were already walking the tree.
> **A census keyed on a hand-traced source field inherits that field's errors** — the field is
> corrected on all six, and the durable form of the lesson is in `AGENTS.md`.

## The three ways to fail are different problems

The split is the part a source read could not have produced, and each row is a different repair:

- **`REGISTER-DROPPED-EXPRESSION-PATH` (9).** `system/handler:register` answers **200** and binds a
  handler entity carrying **no `expression_path`** — the body reference is accepted and silently
  discarded. The caller is told it succeeded.
- **`NOT-RESOLVED` (7 as measured; **0 as of 2026-09-09** — all seven repaired, see F62).** The
  handler entity is bound *with* its `expression_path`, and dispatch answers **404
  `handler_not_found`**. §6.6 resolution does not see what register wrote. **The seven are now
  `BOUND-NOT-EVALUATED`**, which moves them into the third row below and leaves this row empty; the
  census figures in this document are the 2026-09-09 measurement and are deliberately not
  back-edited, since the split is what the finding is evidence OF.
- **`BOUND-NOT-EVALUATED` (3).** Bound correctly, dispatch answers **501** — the honest shape. The
  peer stores an installed body and has no evaluator. This is the only one of the three that is
  merely a missing feature rather than a broken promise.

**`REGISTER-DROPPED-…` and `NOT-RESOLVED` are the ones worth attention**, because in both the peer
reports success for a registration that can never be dispatched.

### `wasm-wat` is excluded, not scored

Its never-registered sibling answers `501 unsupported_operation` rather than 404, so it does not
discriminate a registered pattern from an absent one and **no dispatch row on it is attributable to
the registration**. Reported as `CONTROL-FAILED` rather than folded into a bucket.

## Two spec questions this raised (routable, not asserted)

1. **The "registered handler, no body" failure has no pinned disposition.** `no_handler_body` — what
   `go` emits and 8 peers copy — **does not appear in `v0.8.2.11` at all**. The cohort spells this
   failure four ways: `no_handler_body`, `unsupported_operation`, `handler_not_found`,
   `not_implemented`.
2. **`pd` answers `501 not_implemented`**, which §3.3 (0.8.2.7) names as one of four *non-conformant
   spellings* of the 501 row. Whether that blacklist reaches **this** failure is genuinely unclear:
   0.8.2.8 carves out *"a domain code defined for a different failure"*, and "no body bound" is
   arguably a different failure from "operation absent from the manifest". Recorded as a question.

## Calibration — the source read was exactly right, and measuring was still necessary

Recorded with the same weight as a catch, because a verification rule only ever exercised on the miss
becomes *"never trust a source read"*.

A source trace of all 46 peers' dispatch was made **before** the probe existed and predicted the
binary question — *does this peer evaluate an installed entity-native body* — for **46 of 46
correctly**. The predicted `EVALUATES` set and the measured one are **identical, peer for peer**.

What the source read could **not** produce, and what makes the probe worth its cost:

- the **three-way split** among the 20 — the difference between a peer that drops the reference, one
  that cannot resolve it, and one that has no evaluator is invisible in a read of the dispatch site,
  and they are three different repairs;
- the **status and code** each peer actually emits, which is where both spec questions above came
  from;
- a result that satisfies the standing rule — *a capability claim reads `unknown` until a harness
  executes it* — which a read, however careful, never can.

## What the instrument cost, and the control that paid for it

**The probe's first run reported `go` as `BOUND-NOT-EVALUATED`.** `go` demonstrably has an evaluator.
The probe had encoded the register-request's `manifest` as a full **entity**
(`{type, data, content_hash}`) rather than a bare map — the oracle's `RegisterRequestData` has
`Manifest HandlerManifestData` as a plain struct field, and `ToEntity` is called on the *request*,
never on the manifest. The peer's `MapField(manifest, "expression_path")` therefore read the entity's
top level, found nothing, and bound a handler with **no body reference while still answering 200**.

Left unfixed, this run would have published **all 46 peers as non-hosts.**

What found it in one step was extending the LANDED control from *"was something bound"* to ***"does
what was bound carry the field the measurement depends on"***. That is the standing rule in a new
shape: **a control must assert the precondition the measurement rests on, not merely that the step
completed.** A probe's first two runs are about the probe — budget them.

## Reproducing

```
tools/build-probes.sh host-seam-probe
tools/run-cohort-census.sh --probe host-seam-probe    # 46 → output/scratch/host-seam-probe/
```

Per-peer JSON is gitignored: re-run rather than cite a copy, and scope any cohort read to the peers
a single run measured — a mixed-age probe directory reads as a measurement and is not one.

**Retirement:** no oracle check drives this surface today. If one ships, this probe stops being cited
as evidence on that check set; the measurement above keeps its date.
