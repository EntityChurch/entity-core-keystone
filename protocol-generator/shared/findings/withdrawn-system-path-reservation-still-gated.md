# The `system/*` registration reservation is withdrawn from the protocol and still gated by the oracle

**Date:** 2026-09-09 · **Seat:** `entity-core-keystone` · **Register:** F61
**Measured against:** oracle `78db4a9`, executed check set `7aa6f3de…` (778 checks), vendored spec
snapshot `v0.8.2.11` (`c97e1860…`), and `entity-core-protocol` HEAD **`52237bf` = 0.8.2.14**.
**No conformance number moves.** All 46 peers pass both checks named below and continue to.

---

## What changed upstream

`ENTITY-CORE-PROTOCOL` **0.8.2.13** (`02ad9a6`, 2026-09-08) **withdrew** §6.2's

> Implementations MUST NOT allow user-installed handlers to register at `system/*` paths.

and replaced it with the check that was always underneath it:

> Installation at a `system/*` path is authorized by the same mechanism as any other
> registration. `register` derives its pattern from `EXECUTE.resource.targets[0]`, and the
> standard dispatch capability check on `resource` (§6.13) decides whether the caller may install
> a handler at that path. **The protocol places no additional constraint on the `system/*` prefix.**

The same revision struck the matching bullet from §9.0's conformance-profile list, in terms that
settle the conformance question outright: *"A peer that refuses `system/*` registrations is applying
deployment policy and remains conformant; so does one that permits them."*

## What the oracle still requires

The pinned oracle predates the withdrawal by two days and carries **two hard checks in the core
`handlers` category**:

| check | message | severity, 46 peers |
|---|---|---|
| `core_register_reserved_refused` | *"register at a reserved `system/*` pattern refused with 403 (V7 §6.6)"* | **PASS × 46** |
| `core_register_reserved_publishes_nothing` | *"refused register left no manifest, no handler entity and no grant"* | **PASS × 46** |

Both are in the executed 778-check set — verified per-check across all 46 committed reports, not
inferred from the category name. The first check's own message cites **`V7 §6.6`**, a section
reference retired before the `0.8.2.x` series began.

**So an implementation that adopts the current §6.2 fails two core checks.** The gate now requires a
refusal the protocol does not require, and rewards the mechanism 0.8.2.13 removed — *"a hardcoded
prefix match ahead of authorization rather than … the capability system, so it overrode the grant a
deployment had deliberately issued."*

## The refusal code is F60's seventh undefined code

38 of 46 peers answer this refusal `403 forbidden_pattern`. **`forbidden_pattern` is defined in no
normative document.** Corpus searched by name, per the standing rule that an absence claim records
what it read: 0 occurrences in the `v0.8.2.11` snapshot, 0 in `ENTITY-CORE-PROTOCOL` at `52237bf`,
and the only hits anywhere in `entity-system-architecture/specs/` are **two in `SDK-OPERATIONS`
v1.12 that mention it solely to forbid copying it into the SDK primitive** — *"that refusal belongs
to the dispatch operation, and copying it into `register_handler` makes standard-extension
installation impossible."*

That is a code no document defines, for a refusal the protocol has withdrawn, described in the one
document that names it as belonging to a different operation. It joins the six in F60.

## Our half, stated rather than left to be found

**Our guard is exactly the shape 0.8.2.13 objected to.** In the `go` peer —
`src/peer/handlers.go:632`, and the same shape propagated to 37 more:

```go
// isReservedSystemPattern reports whether pattern falls under the reserved
// system/* namespace (§6.2: user-installed handlers MUST NOT register there).
...
if isReservedSystemPattern(pattern) {
    return errOutcome(403, "forbidden_pattern", "§6.2: user-installed handlers MUST NOT ...")
}
```

It is a prefix match evaluated **before** `paramsEntity` and before any capability check, and its
comment quotes the withdrawn sentence. Under 0.8.2.13 this is *permitted* — it is deployment policy
— but it is not the mechanism the spec now names, and a deployment that issues a grant covering a
`system/*` install path is overridden by it.

**We are holding the behaviour, deliberately, and this is why:** changing it moves 38 peers off a
check the pinned oracle still gates at 46 of 46. The cohort cannot follow the current spec text and
the current check set at the same time. That is the finding.

**It also touches the host track.** The §6.13(a) wire probe measured 26 of 46 peers able to
dispatch a wire-registered entity-native body (`host-seam-dispatch-wire-census.md`; filed as H1
until 2026-09-12, which it is not — see that finding's correction). Every standard extension owns a
`system/{ext}/…` namespace, so under the old rule a conformant peer could not host one at its own
path by the wire route at all — which is the interaction `SDK-OPERATIONS` v1.12 is describing from
the other side.

## Asks

1. **Retire or re-scope `core_register_reserved_refused` and
   `core_register_reserved_publishes_nothing`** (`entity-core-go`). If refusing is deployment
   policy, a core check cannot require it. If the checks are meant to survive as *"a peer that
   refuses does so with a coherent disposition"*, they need a control that permits the other
   answer — and the message's `V7 §6.6` citation wants correcting either way.
2. **Rule the refusal's disposition, if a peer chooses to refuse** (`arch`). The natural answer
   under 0.8.2.13 is the ordinary authorization outcome — `403 capability_denied` — since the
   refusal is now a policy decision expressed through the capability system. Saying so retires
   `forbidden_pattern` on 38 peers and folds this into F60's ask (c).
3. **Sequence it with the next oracle re-pin.** The vendored spec and the pinned oracle are on
   opposite sides of this change right now. If the checks are retired at a pin flip and the peer
   sweep rides along, the cohort is swept once; landing them separately sweeps it twice.

## Sequencing note for us

Nothing here is actionable in this repo until (1) is answered, because our peers currently satisfy
both the old rule and the gate. **We are not asking for relief and no number moves.** The reason to
route it now rather than at the re-pin is that the next seat to build against 0.8.2.14 will read two
red core checks as their own defect.
