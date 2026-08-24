# HANDOFF-TO-ARCH — §6.11 T2.1 absolute-throughput floor + a cap-signature coverage gap

**Date:** 2026-07-15 · **Findings:** F33, F34 (`research/stewardship/SPEC-FINDINGS-LOG.md`)
**Owner:** `arch` (spec-body + GUIDE-CONFORMANCE / validate-peer probe design) · **Severity:**
F33 = probe-vs-spec-intent tension (non-blocking; a spec-conformant slow peer can fail a probe the
spec text says it should pass) · F34 = oracle coverage gap (a real security bug class has zero
adversarial coverage) · **Blocks:** nothing (the wasm-wat peer is GREEN — see below)
**Surfaced by:** the hand-authored WASM peer (`protocol-generator/wasm-wat/`) reaching `--profile
core` green; the §6.11 concurrency probes were the last hard-FAIL and forced a deep look at *why*.
**Spec surface:** ENTITY-CORE-PROTOCOL.md §4.9 / §6.11(c) @ `spec-data/v0.8.0`; GUIDE-CONFORMANCE
§7b T2.1/T2.2; validate-peer `cmd/internal/validate/{concurrency.go,client.go,security*.go}`.

> Keystone cannot edit `spec-data/**` or the oracle (both boundary/immutable). This is a request
> for arch to consider on its own schedule. Derived from the **spec** + the **oracle's observable
> behavior** (not by matching the oracle's Go verdict logic to make a number go green — the peer is
> already green via a legitimate lever; these are forward-looking clarity findings).

---

## Context: how this surfaced

The WASM peer processes an authenticated EXECUTE with the §5.2 verify ladder — **two Ed25519
verifies per request** (author-sig over the per-request root `content_hash`; granter-sig over the
capability's `content_hash`). On WasmEdge's **default interpreter**, one Ed25519 verify measures
**~9.2 ms** (micro-benchmarked, 200-verify loop). So an authenticated request costs ~18 ms of pure
signature verification, single-threaded.

`§6.11 T2.1` fires `t21Workers=16 × t21TotalReq=10_000` requests (`concurrency.go:89-90`). At
~18 ms/req serial that is ~180 s of crypto — and the peer dropped **7002/10000** with
`read response: i/o timeout`. Enabling WasmEdge's JIT (`wasmedge --enable-jit`) drops one verify
to **~84 µs (109×)**; the same probe then passes with margin (concurrency category 58 s → 1.5 s).
That fix is legitimate and shipped (it's the "compile with optimization" knob for a wasm peer;
`AOT` — `wasmedge compile` — embeds native code but the 0.17 runner does not use it, so JIT is the
working lever). **The peer is green.** But two things the investigation turned up are worth arch's
attention, independent of our peer.

---

## F33 — §6.11 T2.1's "zero drops" completeness assertion is a de-facto absolute throughput floor

### The spec intent (normative, unambiguous)

ENTITY-CORE-PROTOCOL.md §4.9 (`:1854`, `:1860`):

> **(c) Deliver or signal — never silently drop.** For every request the peer admits, it MUST
> either complete it and respond, or emit an explicit failure signal … Admitting a request and
> discarding it with no response and no error is non-conformant.

> **This is an outcome contract, not a performance bar.** It says nothing about absolute throughput
> or latency, which are language- and deployment-dependent. A slow peer that degrades gracefully —
> slows down, sheds with a coded refusal, recovers when load drops — is conformant … Conformance is
> verified by ratio/invariant probes … **per-language-fair, not by cross-language absolute
> numbers.**

§4.9 also explicitly sanctions **back-pressure** as a conformant mechanism: *"apply back-pressure
(block or slow the producer)"* (`:1858`).

### What the probe actually enforces

The **latency** assertions honor this faithfully — they are ratio-based and self-relative:
T2.1's degradation gate is `lastP50/firstP50 > 4.0` (`concurrency.go:460-462`), T1.3 is
`busyP50/soloP50 > 4.0` (`:399-401`), T1.1 is downgraded to WARN (`:217-221`). No absolute ms
threshold anywhere. Good.

The **completeness** assertion does not. `runT21` fails on *any* worker request that returns an
error (`concurrency.go:445-453`), and that bucket includes the validator's **own client-side**
`read response: i/o timeout`. That timeout comes from two arms of `ioDeadline` (`client.go:209-215`),
whichever binds first:

1. a flat **`perRequestTimeout = 20 s`** per `TreeGet` (`client.go:198`, fresh timer per request at
   `client.go:432`), and
2. the shared run-wide **`-timeout` (default 60 s)** context deadline (`cmd/validate-peer/main.go:36,88`)
   — `ioDeadline` returns `d.Before(capped)` so as the run budget nears exhaustion, per-request
   deadlines shrink toward zero.

For a slow serial peer, **arm (2) binds**: 10 000 requests × ~18 ms ≫ the 60 s run budget, so the
shared deadline is hit partway through T2.1 and every remaining request instant-times-out — the
7002/10000 we saw. This makes the completeness assertion a **fixed aggregate-throughput floor**:
the peer must clear ~10 000 authenticated requests (plus all prior categories) inside a fixed 60 s
wall-clock, single-run, cross-language.

### The tension

The probe conflates two outcomes §4.9 deliberately separates:

| Outcome | §4.9 disposition | T2.1 disposition |
|---|---|---|
| Peer **silently discards** an admitted request (no response ever) | non-conformant (§4.9(c)) | FAIL (correct) |
| Peer is **still working** on the request when the client's fixed deadline elapses | **conformant** — "slow peer that degrades gracefully" / lawful back-pressure (`:1860,:1858`) | FAIL (**over-strict**) |

Our peer never violates §4.9(c) — it *would* respond to every admitted request, just slower than
the client's fixed deadline. The probe can't observe "late" vs "dropped" — both land in the same
`dropped++` bucket (`concurrency.go:446-449`). A peer that lawfully **sheds** under §4.9 (coded
refusal before admitting) would *also* surface as `err != nil` and FAIL. So the offered load
(`16 × 10_000`, no shedding path exercised) plus the fixed deadline is an absolute floor of the
*client's* making, in direct tension with "not a performance bar / per-language-fair."

Note §6.11(c) (`:3718`) does mandate *per-request* deadlines at the request layer — so the client
using a per-request timer is correct; the tension is purely in the **value** being a fixed absolute
constant rather than adaptive/graceful.

### Honest counter-argument (for completeness)

One can read §4.9 as: a peer that can't serve promptly SHOULD shed/refuse before admitting, rather
than admit-everything-and-be-slow. Our peer admits everything. But §4.9 lists "block or slow the
producer" as an *equally valid* mechanism to shedding, and a serial peer inherently back-pressures
via TCP flow control — the probe just doesn't model a back-pressurable producer.

### Recommendation (arch's call)

One or more of:
1. **Distinguish late from lost.** Drain T2.1 to completion under a generous/adaptive deadline and
   assert *every admitted request eventually gets a response or coded signal* (the actual §4.9(c)
   property), keeping the *separate* ratio gate for latency-runaway. "No silent loss" ≠ "answered
   within a fixed absolute window."
2. **Model a back-pressurable producer.** Let the client slow when the peer slows (§4.9's sanctioned
   "slow the producer"), rather than firing a fixed deadline and scoring a drop.
3. **Document the pragmatic floor.** If a fixed floor is intended as a deployment proxy, say so in
   GUIDE-CONFORMANCE §7b and note that slow substrates must run in a compiled execution mode —
   making "compiled execution mode + its launch flags" an explicit, documented element of the
   §6.11 conformance contract (see the substrate lesson below).
4. **Harness robustness (orthogonal):** the shared 60 s `-timeout` with **no per-category
   sub-budget** (`suite.go:185-214`, the `budget_exhausted` skip) makes T2.1's pass/fail sensitive
   to run-order and upstream budget consumption — a slow-but-passing category silently starves
   later categories into `budget_exhausted` skips. A per-category budget (or excluding the sustained
   -load category from the shared clock) would de-flake this.

---

## F34 — no adversarial vector for a tampered *granter/capability* signature on a warm connection

### The asymmetry

`security.tampered_signature` (`security.go:569-597`) flips 4 bytes of the **EXECUTE author**
signature (`sigData.Signature` where `sigData.Target == execEntity.ContentHash`), on the **warm
authenticated connection**, and requires **401**. This is the guardrail that makes per-request
author-signature verification non-negotiable — it correctly kills the "authenticate once, trust
the connection" shortcut. (It caught exactly that bug in our peer during development — a
per-connection author-verdict cache — which is why we ship full per-request verification.)

There is **no symmetric probe for the granter/capability signature.** An exhaustive audit of the
tampering probes:

| Probe | Mutates | cap `content_hash`? | Conn |
|---|---|---|---|
| `tampered_signature` (`security.go:580-586`) | **author** sig detached bytes | n/a (author sig) | warm → 401 |
| `grantee_author_mismatch` (`security.go:600-670`) | EXECUTE `Author` field; cap reused verbatim | unchanged | warm → 403 |
| `forged_root_capability` (`security.go:672-736`) | builds a **new** cap (granter=client), validly signed | **new** hash | warm → 403 |
| `content_hash_substitution` / F6 (`security_chain.go:461-462`) | cap **DATA** (`CreatedAt++`) post-sign | **recomputed differs** | fresh conn |

Every path that would exercise a *stale granter-sig verdict* either changes the cap `content_hash`
(F6, forged_root — a hash-keyed cache legitimately misses) or tampers a *different* signature
(author). **No probe flips the detached bytes of the granter's signature over an *unchanged* cap
`content_hash` on a warm connection and expects rejection.**

### Why it matters

A peer that memoizes "granter signature over cap-hash `H` is valid" keyed on `H` **alone** would
pass `tampered_signature` (author sig, re-verified), `forged_root_capability` (different `H`),
`grantee_author_mismatch` (cap untouched), and F6 (different recomputed `H`) — i.e. **every**
existing security/authz check — while harboring a real bug: a later request on the same connection
re-presenting cap-hash `H` with **garbage granter-signature bytes** would be wrongly admitted
(the verifier recomputes `H`, hits the cached "valid" verdict, and skips the byte check). This is
the *exact* class `tampered_signature` exists to prevent for the author sig, with **zero coverage**
for the cap sig.

### Recommendation

Add a `tampered_capability_signature` (or `tampered_granter_signature`) vector, symmetric to
`tampered_signature`: on the warm authenticated connection, present the same valid cap but with the
detached **granter** signature bytes corrupted, and require **403 capability_denied**.

### Bonus — the *sound* optimization this clarifies (a §4.10(b) headroom lever)

§4.10(b) (`:1867`) explicitly acknowledges "capability-chain verification costs O(depth) signature
verifications." On a slow-crypto substrate that per-request cost dominates (F33). The granter-sig
verify **is** memoizable *soundly* — but the cache key must be **(cap-content-hash, detached-
signature-bytes)**, NOT the hash alone: then a tampered signature misses → re-verifies → rejects
(closing the F34 hole), while an honest repeated presentation of the same cap (the T2.1 hot-cap
workload) hits. This is `memoize-verify-by-(message, signature)` — a pure-function cache, sound by
construction. It halves per-request crypto for repeated-cap loads. (The *author* sig is over a
per-request-unique message, so its (message,signature) is unique → never a cache hit → no help; it
must stay per-request, which F34's guardrail correctly enforces.) Arch may wish to note this as a
**sanctioned** optimization in the spec/GUIDE so slow-substrate peers have documented ~2× headroom
without any weakening of §5.2 — and it composes with, not replaces, a compiled execution mode.

---

## Not a finding — the design is right

The per-request signed-envelope model (§5.2 verifies each EXECUTE independently) is **correct and
deliberate**: it buys forwardability, content-addressed cacheability, and cross-peer verifiability,
and it is stateless-per-request by design. It is not the source of the performance issue and should
not change. The cost is inherent asymmetric crypto per request — negligible (~µs) on any *compiled*
substrate, painful (~ms) only on an *interpreted* one. The resolution is a compiled execution mode
(+ optionally the F34 memoization), not a protocol change. On that axis we have **converged**.
