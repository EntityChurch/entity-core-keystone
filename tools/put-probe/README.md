# `put-probe` — §6.3 put-admission census · **Kind A (probe)** · **RETIRED**

Kind and obligations: `docs/VERIFICATION-ARCHITECTURE.md`. A probe measures; it does not judge, it
does not gate, and it never appears in a published conformance number.

## Status: RETIRED — superseded by oracle vectors

The oracle now ships **six vectors on this exact surface**, in
`cmd/internal/validate/tree_put_error_codes.go`, category `catTreeOps` (**core**):

```
put_absent_content_hash_400_invalid_request
put_hash_mismatch_400_hash_mismatch
put_undecodable_400_invalid_request
put_unsupported_content_hash_format_400
put_cas_race_409_hash_mismatch
put_error_control_valid_200          (the accept-path control)
```

Per the expiry rule, this probe **stops being cited as evidence** from that check set onward. The
source stays for provenance and for the controls, which are reusable. The measurement it produced
stands and keeps its date.

**The finding it produced:** `protocol-generator/shared/findings/put-admission-wire-census.md` — 0 of
46 peers implemented any row; 36 accepted and stored a two-key `{type, data}` submission; 10 bound a
path to content that did not hash to the supplied hash.

**Corroboration at retirement, and it is the reason to keep this file rather than delete it.** The
ladder was authored from the spec on 46 peers *before* any vector existed. Measured against the
superseding oracle, our peers pass 5 of the 6 rows on all three probed lineages and 6 of 6 on two of
them. An independently authored check agreed with our reading of the amendment. That is the
strongest available evidence that implementing an accept-side rule ahead of the vectors was
consumption of a landed amendment and not de-facto specification.

## What it measured

§6.3's put admission ladder as introduced by `ENTITY-CORE-PROTOCOL.md` **0.8.2.11**
(`protocol-generator/shared/spec-data/v0.8.2.11/`, `c97e1860…`), with the `put` error codes cited by
reference to `EXTENSION-TREE.md` Appendix A v4.5 (deliberately not vendored — read it in the sibling).

## Controls — both required, both executed

- **Positive.** A valid `put` on a fresh connection MUST answer 200. A peer whose positive control
  fails is reported `trusted: false` and **its result is suppressed**, not published. This caught two
  probe faults before either could become a cohort finding: a stray decode call that left the
  forwarded capability material silently empty (`403 capability_denied` cohort-wide), and a
  `system/peer` entity carrying `peer_id` in its hashable basis (`401 unresolvable_grantee` on all
  46). The second became **F54** — §4.6's pseudocode contradicts §3.5's normative `MUST NOT`, and the
  probe had been written against the pseudocode.
- **Forwarded-material self-check.** Handshake capability material is replayed as raw byte spans, so
  every forwarded entry is re-decoded and re-hashed against the map key it is filed under (§3.1
  requires them equal).

  **Scope, stated because it was once overstated:** this licenses *agreement between an entry and its
  key* and says nothing about the keys being **unique**. The fault it missed was a duplicate map key
  — the probe unioned its own peer entity into an `included` map that already contained it — which
  made five peers read as refusing valid input. The encoder now deduplicates by construction and
  reports the dropped count per peer. *An invariant check licenses exactly the invariant it checks.*

## Running it

```
tools/build-probes.sh put-probe                  # → output/s4-oracles/put-probe
tools/run-cohort-census.sh --probe put-probe     # all 46 → output/scratch/put-probe/
```

Per-peer JSON is gitignored: re-run rather than cite a copy. A conformance report appearing in
`output/scratch/put-probe/` means the `ORACLE` override was **dropped** at a container boundary and
the peer ran the real validator — classify by output *shape*, never by trusting the harness.
