# entity-core-protocol-datalog — Phase S4 (Conformance)

**Deductive-logic / query-native spec-discovery probe · probe tier (‡, seam-hybrid)**
· S4 completed 2026-07-16 · **Verdict: GATE GREEN — `Result: PASS`, `682·0F @ cc1970f`**
(P/W/F/S = 292 / 294 / 0 / 96) + origination-core 3/3 + live 2-of-3 multisig accept + the
71-vector wire corpus re-confirmed 71/71. All in-container / capped / offline.

## The headline

`validate-peer --profile core` reports **`Result: PASS` with 0 fail** against the peer —
the cohort constant `682·0F @ cc1970f` (`core_gate_fingerprint 8261a033…`, the overseer's
fresh oracle, NOT rebuilt here). The **wrapper-guard held through S4**: completing the
handler surface added no imperative allow/deny to `dispatch.rs`; the §5.2 verdict still
derives end-to-end from the `ascent!` rules in `src/authority.rs`.

## Iteration count: 2 substantive iterations

The seam split predicted at S1/S3 meant almost every S4 FAIL was a HANDLER-BODY or
STRUCTURAL-VALIDATION gap on the host side — never an authority-rule gap. The Ascent
interior was already complete and correct at S3.

- **Baseline (iteration 0):** 135 fail / 682. Buckets: `type_system` 107 (type floor
  unpublished, 501-stubbed), `tree_operations` 11, `handlers` 8, `capability` 2, `multisig`
  1, `concurrency` 1, `peer_canonicalization` 2, `format_agility` 1, `negotiation` 2.
- **Iteration 1 — the type floor.** Seeded the 53-type §9.5 Core Type Floor at
  `system/type/<name>`, rendered NATIVELY (`src/types.rs`, mirroring the reference registry's
  field shapes; the FFI codec owns the bytes) — the durable "render natively, don't ingest
  bytes" lesson. Fetch reaches the floor via the `system/tree` handler + a `system/type/*`
  resource target (confirmed: the fetch returned 404 not 501 at baseline → it was a tree
  get, not the `system/type` handler). Result: **type_system 107→0 fail** (the WARN'd
  non-floor extension types are matched-if-present).
- **Iteration 2 — the remaining host surface** (one edit pass, all in `dispatch.rs`):
  handler register/unregister (the five §6.2 writes + reversal), capability `configure`
  (policy-entry bind) + `revoke` zero-token reject, tree CAS (§3.9 compare-and-put) +
  §1.4 path validity (`//`/`./`/`../`/NUL/leading-slash → 400) + deletion-marker listing
  filter, the §6.11 `dispatch-outbound` reentry body, §4.5 negotiation (disjoint
  hash_formats/key_types → 400), and the §4.7 unsupported-key_type reject at authenticate.
  Result: **0 fail**.

## What each FAIL taught

- **`type_system` (107):** a core peer MUST serve the 53-type floor as fetchable
  `system/type` entities. The fetch is a tree get (resource-targeted), so seeding the store
  is sufficient — no `system/type` GET handler needed. Rendering natively (not echoing the
  Go vector bytes) keeps a single source of truth; the vector set is the drift target.
- **`tree_operations` (11):** three sub-lessons — (a) §1.4 path validity is HOST structural
  validation returning **400 invalid_path** (NOT an authz 403); (b) §3.9 CAS is
  create-only-on-zero-hash / equal-on-nonzero → **409 hash_mismatch**; (c) a
  `system/deletion-marker` binds normally but the LISTING omits the marked leaf
  (CORE-TREE-DELETE-1) — behavioral, in `build_listing`.
- **`handlers` (8):** register/unregister are a v7.74 §6.13(a) MUST — a 501 from a core peer
  is non-conformant. The five writes install path is `EXECUTE.resource.targets[0]`.
- **`capability` (2):** `configure` is a v7.62 §6.2 MUST op (policy-entry bind); revoke MUST
  reject a zero token. Both are handler bodies, not authz.
- **`multisig` (1):** the live 2-of-3 accept returned 404 at baseline — authz ALLOWed
  (the Ascent K-of-N already worked) and the target simply hadn't the handler/floor; it went
  green once the surface was complete. Confirms the accept path runs through the aggregate.
- **`concurrency` (1):** the §6.11 reentry (`dispatch-outbound`) needs a live handler body;
  the seam (`conn.outbound`) was already present in `host.rs`.
- **`peer_canonicalization` (2) + `format_agility` (1) + `negotiation` (2):** all host-side —
  policy `configure` accepting canonical-hex/Base58 peer patterns; the §4.7 key_type reject;
  the §4.5 disjoint-advertisement rejects. None touch the rule layer.

## Did completing the handlers surface a NEW expressibility finding?

**No new authority-interior finding — and that itself is the datum.** Every S4 FAIL was a
host-seam gap (handler bodies + structural 4xx + connection state); the §5/§6.6 rule interior
authored at S3 needed ZERO additions to pass the full core gate. This CONFIRMS the A-DL-013
seam split at the higher (live-peer) bar: the deductive half was already complete; only the
stateful-sequential half (which the profile correctly locates host-side) grew at S4. The one
new *implementation* note is A-DL-015 (the type floor is a host RENDER + tree-seed, never a
rule concern — the type registry is data the peer publishes, not authority logic). Logged,
not escalated.

## Deliverables

- Completed peer surface: `src/types.rs` (NEW — 53-type floor) + `src/dispatch.rs`
  (register/unregister, configure, revoke-zero, tree CAS + path-validity + deletion-marker,
  dispatch-outbound reentry, negotiation, key_type reject); `src/lib.rs` (module).
- `run-s4.sh` (NEW — the core gate), `run-origination-core.sh` (NEW — the reentry probe).
- `status/CONFORMANCE-REPORT.md` + `status/CONFORMANCE-REPORT.json` (raw oracle output).
- `status/SPEC-AMBIGUITY-LOG.md` — A-DL-015 added; A-DL-013 reinforced at the live bar.
- 29 lib unit tests + loopback + interop GREEN; clippy `-D warnings` + fmt clean.

## S5 handoff

1. **The gate is GREEN at `cc1970f`** — do not re-pin to go HEAD (moved past on NETWORK
   work; re-pinning is policy-§4, not S5). S5 is the retrospective + publish (0.1.0-pre).
2. **The co-equal deliverable to synthesize** (`research/evaluations/authority-as-query.md`,
   authored at S5): the seam split held at the LIVE bar. §5.2/§5.5/§3.6/§5.5a/§6.6 stayed
   deductive rules driving the verdict; the entire S4 growth was host-seam (protocol
   sequencing + I/O + handler bodies). The candidate `HANDOFF-TO-ARCH` (authority-as-query
   appendix — verdict as a DERIVATION, making fail-closed + within-grant conjunction
   structural invariants) is now backed by a full-gate green, not just unit tests.
3. **The type floor is host-side render** (A-DL-015) — note it in the retrospective as a
   clean example of "not everything the peer serves is authority logic"; the type registry is
   published DATA, orthogonal to the rule interior.
4. Nothing committed — files left for the overseer to stage + commit.
