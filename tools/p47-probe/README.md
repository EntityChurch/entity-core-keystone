# `p47-probe` — §4.7 pre-hello `authenticate` census · **Kind A (probe)** · **RETIRED**

Kind and obligations: `docs/VERIFICATION-ARCHITECTURE.md`. A probe measures; it does not judge, it
does not gate, and it never appears in a published conformance number.

## Status: RETIRED — superseded by oracle vectors

`connect_prehello_authenticate` (FM-1) is in the **currently pinned** oracle, category
`catConnectivity` (**core**), and the surrounding sequence surface has since been extended by the
`connectivity_conn_errors.go` family (`connect_ping_before_hello`,
`connect_second_hello_mid_handshake`, `connect_second_hello_after_established`,
`execute_before_established_refused`, …).

The probe therefore **stops being cited as evidence**. Source and controls stay for provenance and
for reuse. The measurement keeps its date.

**The finding:** `protocol-generator/shared/findings/prehello-authenticate-wire-census.md`.

## What it measured

§4.7's status table contradicting itself on one input: an `authenticate` arriving before any `hello`.
Row 6 says `401 invalid_nonce`; row 10, four rows later in the same table, says
`400 connection_sequence_error`. `entity-core-formalization` censused the cohort **by reading source**
and said plainly that no probe existed to measure it. This was that measurement.

## Controls — and this probe is why the control rules exist

Three separate probe faults surfaced in one afternoon of building it, **none visible in the output**,
each of which would have produced a confident, publishable, wrong finding:

- A placeholder `content_hash` (33 zero bytes) is refused under §1.8 validate-before-trust, and the
  reference peer reports that refusal as a bare `400 non_canonical_ecf` — which reads exactly like
  the row-10 answer under measurement. The frame was structurally perfect.
- `key_type` sent as the numeric §1.5 registry code where the wire field is **text** produced
  `400 unsupported_key_type` on four peers — a plausible *fifth behaviour class*, concentrated in the
  hand-authored group, which is precisely where a real one would appear.
- A `hello` with no `nonce` field is accepted by 38 peers and refused by three with
  `400 connection_sequence_error` — the exact status *and code* under measurement.

**Two controls, and the second is the one nobody thinks to build:**

- **Positive** — a plain `hello` on a fresh connection MUST answer 200. If it does not, the peer's
  result is `trusted: false` and suppressed: a probe fault, not a finding.
- **Differential** — the same input supplied in a state where the answer *should* differ (`hello`
  *then* the same `authenticate`). A positive control catches a malformed frame; only a differential
  catches a well-formed frame **asking the wrong question**, which is how the `key_type` class was
  killed.

**The differential paid for itself twice, because it turned out to be the finding.** 38 peers answer
`401 invalid_nonce` pre-hello **and the same thing post-hello** — they never model the pre-hello case
at all, they reach the nonce check and find nothing to match. So a 38–6 "majority" is six peers that
*decided* and 38 that got one reading for free. **When a census counts implementations agreeing,
check whether the agreeing ones decided; an answer reached by fall-through is not a vote.**

## RETIRED 2026-09-09 — the question it measured is ruled and gated

Arch folded **FM-1** on 2026-08-31 (0.8.2.1): a pre-hello `authenticate` is **401
`invalid_nonce`**, and §4.7's out-of-order row stops naming it. The cohort was swept at
`5a53b75c`, and the pinned oracle carries **`connect_prehello_authenticate`**, PASS on all 46. A
re-measurement on 2026-09-09 found the 38/6/1 split gone: **46 of 46 `401 invalid_nonce`**, agreeing
with the gate peer-for-peer.

So this probe is a **second source of truth for a settled question** and is no longer maintained.
It is kept because its controls are the worked example the census rule cites, not because its
number is needed. Full closure:
`protocol-generator/shared/findings/prehello-authenticate-wire-census.md`.

## Running it

```
tools/build-probes.sh p47-probe                        # → output/s4-oracles/p47-probe
tools/run-cohort-census.sh --probe p47-probe           # all 46 → output/scratch/p47-probe/
tools/run-cohort-census.sh --probe p47-probe go swift  # named peers
```

**`tools/p47-run.sh` is deleted (2026-09-09) and nothing replaces it.** It installed this probe
*over* `output/s4-oracles/validate-peer` — a binary `entity-system-generator` invokes **by path**
from its own tree — to defeat harnesses that dropped an `ORACLE` override at their container
boundary. Those eight harnesses were fixed at source on 2026-09-06, so the plain `--probe` route
above reaches all 46; measured, not assumed, by running the whole roster through it. Its
documented per-peer form (`p47-run.sh go swift`) had also never worked: `--probe` takes an
optional NAME, so the first peer was consumed as the probe name.

Per-peer JSON is gitignored: re-run rather than cite a copy. A conformance report appearing in
`output/scratch/p47-probe/` means the `ORACLE` override was **dropped** at a container boundary and
the peer ran the real validator — classify by output *shape*, never by trusting the harness.
