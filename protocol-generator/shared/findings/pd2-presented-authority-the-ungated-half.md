# PD-2 landed on a ruling we proposed, and the half that makes it safe has no vector

**Date:** 2026-09-10 · **Seat:** `entity-core-keystone` · **Register:** F63–F67
**Measured against:** spec `0.8.2.18` (`entity-core-protocol` `a528d2e`), oracle pin `78db4a9` /
executed check set `7aa6f3de…` (778 checks), candidate oracle `entity-core-go` `29740e4`, cohort
snapshot `v0.8.2.11` (`c97e1860…`). All 46 peers are `778 · 0F` and **no number moves** — every
item below is invisible to the check set on both sides of the re-pin.

**This audits our own proposal.** `0.8.2.17`'s PD-2 gate-1a ruling is γ, which this seat authored:
*Dimension 4 binds ambient authority; a capability minted by the target naming this peer as
`grantee` authorizes on its own four dimensions.* We still think γ is right and we are not
withdrawing it. What follows is the part we did not state when we proposed it, found by building
the audit rather than by re-reading the argument. The standing rule here is that the exculpation
most likely to be wrong is the one **we** wrote, because nothing routes it back for review.

---

## 0. What the delta is, measured before anything was read into it

`v0.8.2.11 → 0.8.2.18` is **146 diff lines, `ENTITY-CORE-PROTOCOL.md` only**.
`ENTITY-CBOR-ENCODING.md` (`433e094e…`) and `ENTITY-NATIVE-TYPE-SYSTEM.md` (`043fc80d…`) are
**byte-identical** to our pin — verified by hash, not assumed from a changelog.

It carries **five new cohort-wide MUSTs**. Their gating, at the candidate oracle:

| # | New obligation | Landed | Vector at `29740e4` |
|---|---|---|---|
| 1 | PD-2 **ambient** arm — refuse an outbound sub-dispatch at a foreign peer on handler authority | .17 | `dispatch_outbound_ambient_refused` — **non-discriminating**, §1 |
| 2 | PD-2 **presented** arm — four verifications, *"or it is forgeable"* | .17/.18 | **none**, §1 |
| 3 | `register` with **zero** resource targets → `400 path_required` | .18 D5 | **none**, §4 |
| 4 | Signature ingestion over the **connect/authenticate response** | .18 D7 | **none**, §2 |
| 5 | `scope_subset` **dispatches on scope type** (F50 ruled in) | .16 | **none**, §4 |

**One of five is gated, and that one does not discriminate.** This is arch's own **FM-1g** —
*§4.7 declares ten MUST-emit rows and roughly one is gated* — recurring on a different surface
eleven days later, which is the argument for treating FM-1g as systemic rather than as a §4.7
accident.

---

## 1. F63 — both PD-2 arms are gated by checks a peer passes without implementing either

§1.4 is explicit about what a check set owes here. On the presented arm: *"**The
presented-authority arm MUST verify all of the following, or it is forgeable**"* — chain **root**
`granter` resolves to the target, **leaf** `grantee` to the local peer, valid/chain-verified, and
its own four dimensions cover the request. On the frame: *"an arm that **looks implemented and
denies everything** … **which is why a check set MUST discriminate both (§9.1)**."*

**What the candidate oracle adds is the refusal direction only.** `origination.go` at `29740e4`
declares exactly one new check —

```
dispatch_outbound_ambient_refused — "PD-2 (0.8.2.17) negative arm — an outbound sub-dispatch
to a foreign peer on ambient handler authority (no target-minted capability presented)
MUST be refused"
```

— beside the pre-existing `dispatch_outbound_reentry`, which presents a target-minted capability
and expects success. Read as a pair those look like the two arms. They are not, in two separate
ways, and each is enough on its own.

**(a) Nothing drives a presented capability that FAILS a verification.** Searched by name across
`cmd/internal/validate/` at `29740e4`: no check supplies a presented capability whose root
`granter` is not the target, whose leaf `grantee` is not the local peer, which is expired or
revoked, or whose dimensions do not cover the request. So the four MUSTs that the spec says are
the difference between the arm and a forgery are asserted by nothing. A peer that forwards any
presented capability unverified passes `dispatch_outbound_reentry` and
`dispatch_outbound_ambient_refused` both.

**All 46 of our peers are that peer today.** Verified in source rather than inferred:
`go/src/peer/handlers.go:752` reads `reentry_capability`, `reentry_granter` and
`reentry_cap_signature` out of `params`, checks only that they are **present**, and hands them
to `outboundDispatch`. No granter check, no grantee check, no coverage check. The remaining 45
pass the same check by the same mechanism.

**(b) The ambient check passes vacuously on a peer whose handler grants are empty.** Our
bootstrap grant is minted at `go/src/peer/bootstrap.go:96` as

```go
token, _ := p.mintToken(p.identity.IdentityHash(), cbor.Value{Kind: cbor.KindArray}, nil, nil)
```

— arg 2 is `grants`, and it is an **empty array**. §5.2 requires all four dimensions to match
**from a single grant entry**; with zero entries nothing matches, so an ambient arm implemented
literally denies *every* ambient sub-dispatch, foreign and local alike. That peer passes
`dispatch_outbound_ambient_refused` — correctly refusing the foreign case — while having
implemented a blanket refusal rather than Dimension 4. It is the standing vacuous-green shape:
*a rejection-only category lets a fail-closed peer pass without implementing the primitive.*

**Ask (a):** one presented-arm refusal vector. The cheapest discriminating input is **root
`granter` ≠ the target peer** — a capability the *dispatcher* minted to itself, correctly signed
and covering the request, which a peer doing no verification will happily present and a
conformant one must refuse to the ambient arm. `leaf grantee ≠ local peer` is the natural second.
**Ask (b):** rule whether a peer with no ambient outbound capability at all *satisfies* the
ambient arm or must SKIP it — as written, "refuses everything" and "implements Dimension 4" are
the same observation, and the second control is what separates them.

---

## 2. F64 — D7 named one carrier of a target-minted capability; the deliberate one is the other

D7 is right and its reasoning is right. It is **incomplete**, and the surface it misses is the one
PD-2's presented arm actually consumes.

§6.5's ingestion is scoped to *"the dispatcher's envelope-unwrap step, before any handler is
selected"* — an inbound EXECUTE — plus, as of .18, the **connect/authenticate response**. An
`EXECUTE_RESPONSE` is neither.

**§6.2 requires the same three entities in the `request`/`delegate` result envelope**, in terms,
and says so citing the very precedent D7 extends:

> The result envelope's `included` map MUST carry: 1. The issued token entity … **2. Its
> signature entity (`system/signature` at the §3.5 invariant-pointer path)** … 3. The granter
> identity entity. … *(Mirrors the §4.4 authenticate-response precedent.)*

So D7's whole argument — a handshake-minted capability whose signature is held in memory rather
than bound leaves *"every chain rooted at that grant unverifiable locally"* — transfers verbatim
to a capability obtained through `system/capability:request`. And §6.2 says which of the two is
the deliberate path: *"the handler is **the runtime entry point for in-band capability
management**, while §4.4 covers **initial-grant delivery**."* A peer that goes and *gets* a
target-minted credential in order to make a presented-authority sub-dispatch gets it here.
**D7 fixed the incidental carrier and left the deliberate one.**

There is a second, older instance of the same mistake, and it is what made this findable: §5.1's
v7.44 paragraph asserts the receive case is already handled — *"rather than receiving it via
envelope ingest, **which §2656 already binds correctly**"*. That sentence was **already false for
the connect response**, which is exactly what D7 proved. It is still false for `EXECUTE_RESPONSE`.

**Ask:** state the rule over **any envelope carrying an `included` map that a peer receives and
accepts**, rather than enumerating surfaces. Two surfaces have now been enumerated, one at a time,
each after a failure; the third is `EXECUTE_RESPONSE` and there is no reason to think it is last
(async delivery and subscription-notification envelopes are the same shape). The idempotency and
`signature_path_conflict` semantics already generalize without change.

---

## 3. F65 — D4's criterion is temporal; the edge it names is not

D4 states the test as dynamic extent — *"every outbound dispatch originated **while a handler body
is executing**"* — and then names the in-scope edge as three things for which **no handler body is
executing**:

> Handler-autonomous origination is IN SCOPE and is the edge an implementation misses: a
> subscription delivering a notification, **a timer firing**, a continuation advancing …

A timer callback is not a handler body in dynamic extent, and dynamic extent is the obvious
implementation — a thread-local or context-carried *current handler grant*, which is precisely
what does not survive the registration boundary. So an implementer transcribing the criterion
gets the caller-directed case right and the named edge wrong, **which is the edge the paragraph
says implementations miss**. The clause immediately above warns against the caller-derived
reading for under-covering; the substitute offered has the same defect one step over.

The invariant that is actually meant is **authority provenance**, not timing: *does this dispatch
spend a handler's grant, or the peer's own root authority?* A timer registered by handler `H`
spends `H`'s grant whenever it fires, because the peer set it up on `H`'s behalf. That
reformulation also makes the top-level carve-out fall out for free — a top-level origination
spends no handler grant — instead of needing its own sentence.

**Say the cohort cost plainly, because it cuts both ways:** all three named cases are
**extension** surfaces (SUBSCRIPTION, CLOCK, CONTINUATION). A `--profile core` peer cannot reach
any of them, so the cost to our 46 is **nil** — and for the same reason **no core check set can
ever discriminate D4's edge**, so the under-covering reading ships, passes, and is found by
whoever first builds an extension on top of it.

**Ask:** restate the criterion as provenance (*"spends a handler's grant"*) with the temporal
phrasing as the common case rather than the test.

---

## 4. F66 — the ambient arm's canonicalization frame is unstated, and D2 made that load-bearing

D3 pins the frame for one arm: *"**The presented capability** is evaluated end to end in the
granter's — the target's — frame."* Correctly scoped.

D2 is unconditional about **both**: *"On an outbound sub-dispatch, Dimension 1's handler pattern
is the peer-relative path component of the target uri."* That newly makes the Dimension 1 input a
**peer-relative string**, and `handlers` is path-scope, so `canonicalize` qualifies it with *some*
peer id. On the ambient arm nothing says which.

An implementer who generalizes D3 canonicalizes the value in the **target's** frame
(`/{T}/system/tree`) and the local handler grant's pattern in the **local** frame
(`/{me}/system/tree`). Dimension 1 then never matches for any foreign target — so the ambient arm
refuses even a handler legitimately scoped `peers: {include: [T]}`, and Dimension 4 is never
reached. That is D3's own *"looks implemented and denies everything"*, in the other arm, produced
by generalizing D3.

The intended reading is clearly the local frame — §6.3's own paragraph says *"the network bound is
carried entirely by `peers`"*, i.e. Dimension 1 asks *which handler by name* and Dimension 4 asks
*which peer*. **It is one clause to say so**, and it is worth the clause: wrong-frame
canonicalization has produced four separate measured defects in this cohort (`swift` and `sql`
over-applying §5.5a's granter frames, `datalog` under-applying them, `cobol` canonicalizing an
id dimension), and it fails silently in one direction and loudly in the other.

**Ask:** one sentence — on the ambient arm both sides canonicalize in the **local** frame, because
the grant is local; the target is carried by Dimension 4 alone.

**Sub-item, fails closed so it is low priority but should be named:** *"the chain's ROOT `granter`
resolves to the target peer's identity"* is undefined when the root `granter` is a §3.6
`system/capability/multi-granter`, and M3 makes multi-sig caps **root-only**, so that is exactly
where one lands. A K-of-N-rooted credential cannot be classified as presented authority and falls
back to the ambient arm — an under-acceptance, not a hole. This seat has the analogous rule
already: *a K-of-N root has no granter frame; the local peer is the correct one, not a fallback.*

---

## 5. F67 — γ relocates the handler-grant ceiling, and in the shape it was written for the credential is caller-supplied

This is the design question, it is against our own ruling, and it is the one item here we think
could change the text rather than add to it.

§1.4 describes the handler's bootstrap grant as *"a **ceiling** a caller must not be able to steer
past."* On the presented arm that ceiling is explicitly set aside: *"the dispatching handler's
`peers` scope is not consulted."*

The defense §1.4 gives is: *"a caller can steer the handler only toward peers that have already
granted this peer something, and only within what they granted."* **That is a bound on the
target's exposure, not on the handler's authority.** It answers *which peers* — and says nothing
about *which of this peer's credentials* get spent, or *which handler* gets to spend them.

And in the one shape the ruling was written for, **the credential is caller-supplied**: the §7a
scaffold reads `reentry_capability` out of `params` (`go/src/peer/handlers.go:762`). Capabilities
travel on the wire in `included` maps. So a caller who can obtain a copy of any `T → P` credential
can direct `P` to spend it, through a handler whose own grant never contemplated `T`, bounded only
by that credential's own dimensions. The caller cannot use the credential itself — the leaf
`grantee` is `P` — which is precisely the confused-deputy shape, with the ceiling that was
supposed to bound it removed by name.

**We are not calling γ wrong.** The reasoning that produced it holds: the target is the party that
decides what may be done at the target, and it has decided. What γ actually does is **relocate**
the ceiling from the handler's grant to the presented credential's own dimensions. That is correct
when the *handler* chooses which credential to present, and weaker than intended when the *caller*
supplies it.

**Ask:** rule whether the presented arm additionally requires the **handler's own grant to cover
Dimensions 1–3** (handler, operation, resources), with only **Dimension 4** exempted. That keeps
γ's entire motivation — the target answers *where* — while restoring the handler's ceiling on
*what*.

**State the cost honestly, which is why this is an ask and not a proposal.** Our bootstrap handler
grants carry **no grant entries at all** (§1(b)), so a Dimensions-1–3 intersection would refuse the
conformance scaffold on all 46 peers until those grants are given real dimensions. That is
probably work worth doing for its own sake — an empty grant is not a ceiling either — but it is
cohort-wide, it is ours, and the ruling should be made knowing it rather than discovering it.

---

## What this costs `entity-core-keystone`, measured

**Zero cost, confirmed rather than accepted:**

- **F54 / 0.8.2.15** (`system/peer` basis is `{public_key, key_type}`). Arch's exculpation —
  every implementation was already right — **holds for our 46.** The three-field form appears in
  our tree only in `system/peer` **type-registry declarations** (the wire form legitimately
  declares `peer_id`) and in the `system/protocol/connect/authenticate` entity, which §4.6's note
  now says carries it correctly. Our own ratchet is the corroborating evidence: the pre-v7.65
  three-field basis bit our **probe**, never our peers, and it was the probe that was fixed.
- **F61 / 0.8.2.13** (`system/*` reservation withdrawn). Refusing is now deployment policy, so no
  peer changes. The candidate oracle re-bases the two withdrawn checks into three
  (`core_register_capability_positive_control`, `core_register_capability_refused`,
  `core_register_refused_publishes_nothing`) — worth noting the middle one is the shape this seat
  asked for, a capability refusal rather than a prefix match.

**New implementation on all 46, four of five ungated** — §0's table. Two are measurable now:

- **`path_required` appears in 0 of 46 peer sources.** 35 carry `ambiguous_resource`, which .18
  now calls *"non-conformant on the absent case"* when it answers both.
- **`scope_subset` takes no scope-type argument in 20 of 20 peers** where the function is
  identifiable by name — `go rust python java haskell typescript c rexx zig php ada cobol crystal
  csharp datalog fortran julia lean nim ocaml tcl turbowarp`. Read at the call sites on ten of
  them: every one calls the same untyped function on `operations` and `peers`, both **id-scope**.
  This is 0.8.2.16's own stated defect — *"canonicalizing an id dimension here widens authority
  down a delegation chain, which is where nobody re-checks"* — live, cohort-wide, and driven by
  nothing (`f40_id_scope_*` drive `check_permission`, i.e. dispatch; **F50's surface is
  delegation**).

**Method note, recorded because the first answer was wrong in the flattering direction.** A grep
asking *"does this peer's capability file mention `id-scope`?"* returned 40 typed / 6 untyped. It
is a **false negative**: the file mentions id-scope for `matches_scope`, which landed with F40,
while `scope_subset` next to it is untyped. The discriminator that works is the **function
signature** — a `scope_subset` with no scope-type parameter cannot dispatch on one, whatever its
file says. Sixth occurrence of the false-negative class in this repo, and the first where the
wrong answer was the reassuring one.
