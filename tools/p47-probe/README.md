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

## Running it

```
tools/build-probes.sh p47-probe                  # → output/s4-oracles/p47-probe
tools/p47-run.sh                                 # single peer
tools/run-cohort-census.sh --probe p47-probe     # all 46 → output/scratch/p47-probe/
```

Per-peer JSON is gitignored: re-run rather than cite a copy. A conformance report appearing in
`output/scratch/p47-probe/` means the `ORACLE` override was **dropped** at a container boundary and
the peer ran the real validator — classify by output *shape*, never by trusting the harness.
