# HANDOFF-TO-ARCH — §4.7's address-before-authentication row has no vector, and 37 of 46 peers do not implement it

**Date:** 2026-09-07 · **From:** `entity-core-keystone` · **Spec:** `v0.8.2.11`
(`protocol-generator/shared/spec-data/v0.8.2.11/`, SHA-256-pinned in that snapshot's `MANIFEST.md`)

**How this was found is part of the finding.** It is the first result from a **Kind C independent
check** (`docs/VERIFICATION-ARCHITECTURE.md`) — a keystone-authored check aimed at the same normative
target as the oracle, **authored from the spec text and not from the oracle's source**, whose whole
purpose is to be wrong in different places than the oracle is. It found this on its first roster run.

**What it is not.** It is not a conformance verdict and it does not change one. An official
full-green pass requires the independent test suite — `validate-peer`, which this repo does not
author — and nothing here supplements or overrides it. Every peer named below is `756 · 0F` at the
current pin and stays so; this is a claim about **coverage**, and the peer work it implies is ours.

---

## 1. The finding: the intersection of two covered halves is uncovered

§4.7's **0.8.2.6** note — *"Address is evaluated before authentication"* — states a two-row table for
a **pre-establishment** EXECUTE:

| Pre-establishment EXECUTE | `result.data.code` | Status |
|---|---|---|
| `system/protocol/connect` | §4.7's rows | — |
| Own namespace, non-connect | `authentication_failed` | 401 |
| **Foreign namespace** | **`invalid_request`** | **400** |

and gives the reason in the same paragraph: *"A `401` directs the caller to authenticate and retry,
and for a foreign-namespace address that retry cannot succeed at any authentication state — so the
`401` names a remedy that does not exist."* §1.4 supplies the MUST (*"If the peer ID does not match
the local peer, the peer MUST reject with status 400 (`invalid_request`)"*), and §6.5 step 3 calls it
*"a gate, not an ordering preference."*

**The oracle covers each half and neither covers the pair.** At the candidate check set (go
`78db4a9`, 778 executed) there are two neighbouring checks:

- `execute_before_established_refused` — pre-establishment, **own** namespace → 401.
- `dispatch_inbound_foreign_namespace_refused` — **foreign** namespace, established → 400.

A peer that evaluates authentication first passes both, because on the own-namespace input 401 is
the right answer and on the foreign input it is already authenticated. **The bottom row of the table
is the one input neither check supplies**, and it is the row the note was written to pin.

## 2. Measured, with the differential that makes it a peer statement and not an instrument one

**46 of 46 peers measured and trusted** — every positive control passed, so no result is suppressed.
(`odin` and `apl` first failed with `Permission denied` writing their own output, which is this
repo's documented container-contention signature rather than a peer fault; both were re-run alone
and both are included.)

| `preestablish_foreign_namespace` | peers |
|---|---:|
| **PASS** — `400 invalid_request` | **9** |
| **FAIL** — `401 authentication_failed` | **36** |
| **FAIL** — `403 capability_denied` | **1** (`sql`) |

**All 37 failures carry the differential's confirmation, and without it none of them would be
reportable.** The check sends the *same* foreign URI a second time on a fully **established,
authenticated** connection. All 37 answer `400 invalid_request` there. So the address **is**
recognised as foreign, the URI form is not the problem, and what differs is purely the evaluation
order — which is the thing 0.8.2.6 forbids.

That control was wrong on its first cut and the way it was wrong is worth stating, because it is the
failure mode this kind of check exists under: sent **unsigned**, it answered `401
authentication_failed` — the same status as the case it was meant to disambiguate — because an
EXECUTE with no verified signer is auth-class by §5.2a whatever its address. It varied **two** things
at once (connection state *and* signature) and therefore discriminated nothing.

**The 9 passing peers are what makes this a defect rather than a reading.** `csharp`, `typescript`,
`nim`, `node-red`, `turbowarp`, `asm-arm64`, `asm-x86_64`, `riscv64`, `wasm-wat` answer `400
invalid_request` pre-establishment. The row is implementable, it has been implemented, and the
spec's reading is not in doubt.

**Ask arch / `entity-core-go`:** a vector on the intersection — a pre-establishment EXECUTE naming a
foreign namespace, asserting `400 invalid_request`. One check, in `catConnectivity`, beside the two
that already exist.

**Ours regardless of the answer:** 37 peers to fix. It is a seventh item on the §4.7 propagation
already in flight and is tracked with it.

## 3. Two code-spelling divergences that are CORROBORATION, not an ask — and saying so is the point

**This section was drafted as a second routed finding and the measurement withdrew it before it
left the tree.** The check found two minted codes on the §4.7 surface and, reasoning from the
*pinned* oracle (where the covering checks do not exist), it read as a coverage gap. It is not: the
**candidate** oracle catches both, by name, asserting the code and not merely the status.

| Observed by the Kind C check | Peers | Candidate oracle's verdict on the same peers |
|---|---|---|
| `501 operation_not_supported` for an unknown op at a registered handler | `csharp` `typescript` `node-red` `turbowarp` | `unsupported_operation_on_registered_handler` **FAILs**: *"answered 501/`operation_not_supported`, want 501/`unsupported_operation`"* |
| `401 missing_author` on a pre-establishment own-namespace EXECUTE | `csharp` `typescript` `nim` `node-red` `turbowarp` | `execute_before_established_refused` **FAILs** |

Both are peer defects, both are already gated by the check set the cohort is converging on, and
**neither is owed to arch.** They are recorded here because two independently authored readings
landing on the same two defects, by different routes, is the outcome this structure is built to
produce — and because the standing rule is that a routed claim gets verified *especially* when it is
the accusatory half. The candidate oracle is also catching a third of the same class we did not
drive (`handler_not_found_on_unregistered_path`: `404/not_found` where §3.3's 0.8.2.7 row pins
`handler_not_found`), which is the cheapest possible evidence that the gap in §1 is a real hole in a
surface that is otherwise well covered, rather than a general thinness we happened to notice.

**The one generalizable question the pattern still raises**, asked as a question and not as a
finding: `incompatible_key_type`, `invalid_signature`, `unknown_operation`, `connection_required`,
`handshake_failed`, `not_implemented`, `not_supported`, `not_available` have each been retired **by
name** after being observed in the wild. `operation_not_supported`, `missing_author` and `not_found`
are three more, none of them on a list. **Is a code the spec does not define non-conformant by
default, or only once it is enumerated?** 0.8.2.7's *"The code slot at 501 carries no synonym of this
row"* reads as the former and every blacklist reads as the latter; an implementer has to choose, and
the supply of plausible synonyms is unbounded. One sentence would close the class rather than its
instances. **The oracle already behaves as though the answer is "by default"** — which is a strong
hint and is not the spec.

### 3b. One place our check and the oracle disagree, and the oracle is the measurement

On `prolog` alone, our `prehello_authenticate` case observed **`401 authentication_failed`** where
§4.7 row 6 pins `invalid_nonce`. The candidate oracle's `connect_prehello_authenticate` **PASSes**
`prolog` on the same rule — *"an authenticate sent as the first frame, before any hello rejected with
401 invalid_nonce."*

**So the two readings disagree about one peer, and the oracle is the measurement.** This is not
reported as a peer defect and must not be cited as one. The two frames differ — ours carries a full
valid signature plus the `system/peer` and `system/signature` entities in `included`; a peer with
more than one refusal branch can take a different one — and *when one peer of a cohort diverges from
an authority that says it is fine, the prior belongs on the instrument.* `prolog` independently fails
`connect_authenticate_peer_id_mismatch_hello` by answering `invalid_nonce` too early, which says its
nonce gate is order-sensitive in a way our frame may be tripping around.

**It is named rather than dropped, and it has an owner:** the next work on this artifact is to
bisect our authenticate frame against the oracle's for that check and either fix our case or produce
a real finding. *"We noticed and moved on"* is not an outcome for a Kind C divergence — that is the
rule the whole kind exists under, and it applies to the divergences that make us look wrong exactly
as much as to the ones that make a peer look wrong.

### 3c. A WARN is not a pass, and 8 peers are unmeasured behind one — predicted, then confirmed

The two readings agree on every overlapping row **except one**, and running that disagreement to
ground produced the most immediately useful result of the exercise.

`connect_unknown_operation_established` FAILs on **37** peers at the candidate oracle. Our
equivalent case FAILs on **45**. The 8-peer gap is exact and it is not a disagreement about the
rule: the oracle's check **chains a control** — it first sends a hello on the established connection
expecting `409 connection_already_established` — and when that control does not hold it scores
**WARN**: *"control did not hold — a hello on the established connection returned (200 ""), want
(409 connection_already_established)"*. Our case does not chain that control, so it drives the
surface directly.

**All 8 WARN peers genuinely fail the underlying rule.** `asm-arm64` `asm-x86_64` `prolog` `riscv64`
answer `501 unsupported_operation`, `csharp` `400 connection_sequence_error`, `pd` `wasm-wat` `401
authentication_failed`, `nim` `401 missing_author` — none of them the `400 invalid_request` §4.7 row
10 pins. They are the same 8 that fail `connect_second_hello_after_established`, which is exactly
why: the failing control **is** that defect.

**The oracle is not wrong to do this** — suppressing a result whose prerequisite failed is correct,
and reporting it as a FAIL would be reporting an unmeasurable. The consequence is what matters for
the work in flight: **those 8 peers carry a hidden failure that will appear the moment they fix the
second-hello item, and it will read as a regression caused by that fix.** It is not. It was there
all along and the oracle could not see it.

This is the standing *"a fix to one surface converts the next surface's vacuous pass into a true
failure"* pattern — and for once it is **predicted rather than discovered**, with the peers named in
advance. That is a plain, concrete argument for a second reading that does not inherit the first
one's control chain: it can measure what the authority has correctly declined to measure.

## 4. One split recorded and deliberately NOT scored, because the spec permits both

The initiator's own `key_type` rides in its `peer_id`, not in `key_types`, so a hello may advertise a
perfectly good accept-set and still name an identity the responder cannot verify. §1.5 pins the
answer (*"Impls receiving a `key_type` they do not support MUST return `400 unsupported_key_type`"*),
but §4.5's v7.66 clarification makes the **surface** optional: hello-time is *"the canonical earliest
reject point"* and *"Implementations MAY ALSO reject … later in the handshake … AS A FALLBACK"*.

Measured with an unallocated code (`0x40`, inside §1.5's `0x0B–0xEF` *"Reserved (future real
algorithms)"* range, so no peer can legitimately accept it): **13 peers reject at hello, 33 defer.**
Both conform, and the check scores the 32 `DEFERRED`, not `FAIL`.

**It is recorded because the split is about to stop being free.** §4.5's `protocols` intersection is
being enforced across the cohort right now. On a peer that checks `protocols` before `key_type`, a
hello that is disjoint in both is refused `incompatible_protocol` and **never reaches `authenticate`**
— so the fallback surface those 32 peers rely on becomes unreachable for exactly the input the
agility vector supplies. §4.5 states **no precedence** among the three negotiated fields; the
reference peer refuses `key_types` first. That is the same unruled precedence already routed as
**F56**, and this measurement sizes it: **33 of 46 peers** depend on the ordering, not a handful.

## 5. Corroboration, which is the other half of what this structure is for

Reporting only the divergences would misrepresent the run. Two rows of the table came back
**46 of 46 PASS** on the first attempt, cohort-wide, with no prior work aimed at them:

- `hello_hash_formats_disjoint` → `400 incompatible_hash_format` — **46 of 46**
- `hello_key_types_excludes_responder` → `400 unsupported_key_type` (the §4.5 mutual-verifiability
  MUST, responder-side gate) — **46 of 46**

And the four §4.7 rows currently being propagated were found at exactly the counts the propagation
predicted from `go`'s diff, which is independent confirmation that the propagation is scoped right:
unknown connect operation **45 of 46** owing, second hello on half-open **45**, `protocols`
absent/empty **45**, `protocols` disjoint **40**. Where our case and an oracle check name the same
input the two counts are **identical** — 45/45, 45/45, 45/45, 40/40, 8/8, 6/6 — which is the
corroboration this structure is for. The single exception is §3c, and it is the useful one.

## 6. What was searched, by name

A finding that asserts an absence in someone else's corpus is unfalsifiable unless it records where
it looked. This one asserts the absence of an oracle vector.

- `output/s4-oracles/validate-peer-cand` (go `78db4a9`), full declared-check inventory, and the
  778-check executed set from `go`'s own candidate report — searched for every check whose name
  contains `foreign_namespace`, `prehello`, `preestablish`, `establish`, and every `connect_*`.
  Found: `dispatch_inbound_foreign_namespace_refused`, `execute_before_established_refused`,
  `foreign_namespace_invisible_under_local`, `foreign_namespace_listing_at_*`,
  `foreign_namespace_publish_lands_at_absolute_path`, and 13 `connect_*`. **None supplies a
  pre-establishment EXECUTE naming a foreign namespace.**
- `ENTITY-CORE-PROTOCOL.md` `v0.8.2.11` §1.4, §1.5, §3.3, §4.2, §4.5, §4.5a, §4.6, §4.7, §5.2a,
  §6.2, §6.5 — read for this, by number.

## 7. Reproduce

```
cd tools/kind-c/connect-errors && CGO_ENABLED=0 GOWORK=off go build -o ../../../output/s4-oracles/kind-c-connect-errors .
tools/run-cohort-census.sh --probe kind-c-connect-errors        # -> output/scratch/kind-c-connect-errors/
output/s4-oracles/kind-c-connect-errors -dump                   # the case table and its citations
```

The check declares 12 MUST cases, 1 ADVISORY, and 3 controls; it prints `cases N/N executed` and
exits non-zero if those disagree. `tools/kind-c-gate.py` (in `make lint`) holds the publication
boundary: the binary refuses to write any `status/CONFORMANCE-REPORT` path, and no committed report
may carry its marker.
