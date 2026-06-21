# entity-core-protocol-zig — Phase S4 (Conformance) Summary

**Status: COMPLETE — `validate-peer --profile core` PASS, 0 FAIL**

Peer #4 (Zig, distant-idiom systems peer). S4 drove the live Go oracle from the
S3 baseline **568 total · 94 fail** to the core verdict **568 total · 284 pass ·
195 warn · 0 fail · 89 skip → PASS**, machine-verified (`summary.failed == 0`).
Same fixed point as C# (#1) / TS (#2) / OCaml (#3), reached **spec-first**. The
full scoreboard + per-category table lives in `CONFORMANCE-REPORT.md`; the raw
JSON in `CONFORMANCE-REPORT.json`.

## Oracle + harness

- **Oracle:** Go `validate-peer` built from `entity-core-go` HEAD (v7.74 §10.1
  core-register gate + §9.5a CORE-TREE vectors) in `containers/go`, vendored to
  `output/s4-oracles/validate-peer`. This build is 16 checks larger than the
  C#/TS-era 552-check oracle (the v7.74 register round-trip + CORE-TREE
  delete/listing/cas additions) — hence 568 total.
- **Run model:** `protocol-generator/zig/run-s4.sh` (authored this phase) runs
  the peer + the Go ELF oracle **together inside `zig-toolchain:latest`**, sealed
  offline (`--network=none`), sharing one loopback — the TS/OCaml model. The host
  binds `--debug-open-grants` so the grant-gated categories activate; the oracle's
  `--profile core` is the gate (auto-allowlists §9.0 extension carve-out skips).

## Iteration: the 94→0 fix set (5 load-bearing changes, all spec-grounded)

1. **§9.5 53-type registry (A-ZIG-008 carry-in) — type_system 87→0.**
   `src/type_defs.zig` rewritten as a native render-from-model FSpec/TypeDef
   builder (the cross-blessed C#/TS/OCaml design), publishing the 53 core types
   as `system/type/<name>` entities. A build-time byte-diff
   (`A-ZIG-008` test) renders all 53 and compares each `content_hash` digest
   against the Go-rendered `type-registry-vectors-v1.cbor` → **53/53
   byte-identical on the first run** (the codec being byte-green at S2 meant the
   only risk was field-shape data, which the vector diff catches per-type). The
   non-§9.5-floor types the oracle also probes WARN (matched-if-present); a core
   peer publishes only the floor (refined G4 / F17).

2. **Bootstrap interface operation-sets — handlers `*_operations_match` 3→0.**
   The four MUST handlers now publish their §6.2 `operations` maps in their
   `system/handler/interface` entities (connect={hello,authenticate},
   tree-core={get,put}, capability={request,delegate,revoke}). The op-set value
   is the operation-spec DATA map (the oracle decodes it as HandlerOperationSpec,
   not a wrapped entity).

3. **Entity-native dispatch floor — handlers `core_register_dispatch_roundtrip`
   1→0.** The v7.74 §10.1 gate registers a handler with an `expression_path`
   pointing at a bound `compute/literal {value:42}`, then dispatches and asserts
   the value round-trips. Implemented the minimal §6.13(a) seam: a
   dynamically-registered handler with an `expression_path` evaluates a
   `compute/literal` → returns `compute/result {value, expression}`. Body-binding
   stays the spec's impl-private mechanism (§9.4); richer expression evaluation is
   extension surface (the full entity-native category, out of `--profile core`).

4. **Peer-root listing — tree `path_root_listing` + uas
   `foreign_namespace_listing_at_peer_root` 2→0.** `pathFlexOk` now accepts a
   bare peer-root listing target `/{peer_id}/` (empty body after the leading
   peer-id segment) — the §1.4 universal-tree-root walk. The foreign-root case
   falls out of the same fix (the put already lands at the foreign absolute path;
   the listing now resolves).

5. **Deletion-marker listing-omit — tree `core_tree_delete_1` 1→0.** `buildListing`
   now omits a leaf bound to a `system/deletion-marker` (§6.3 / §9.5a
   CORE-TREE-DELETE-1) — the tombstoned path drops, siblings stay, `count`
   reflects the emitted entries. GET-after-delete returns the marker (the
   pass-shape).

## Spec-first findings — validated live against the oracle (none new)

- **A-ZIG-001 (canonical identity-multihash peer_id, `hash_type=0x00`):**
  validated by connectivity 22/22 (handshake identity binding) + authz
  `authz_grantee_1` (grantee resolution). The §1.5-canonical construction is
  correct against the oracle; the stale §7.4/§1.5-line-436 SHA-256-form would
  fail handshake. Corroborates OCaml A-OC-007. → arch (unchanged escalation).
- **A-ZIG-005 (corpus peer_id coverage gap):** unchanged — codec stays
  construction-agnostic; the live handshake exercises the canonical form the S2
  corpus does not discriminate. → arch.
- **A-ZIG-006 (§5.2 401/403 authn/authz split):** validated by authz + security
  all green (403 deny-default, 403 scope-exceeds, 401 unresolvable-grantee). The
  3-way verdict matches the oracle exactly. Fourth distant-idiom peer to
  corroborate OCaml A-OC-008 / arch F20. → arch.
- **A-ZIG-008 (53-type registry deferral):** **RESOLVED** — the full registry
  landed and byte-diffs clean; the §7a handler bodies landed behind `--validate`.

**No new spec ambiguities surfaced at S4.** The 5 fixes were all
spec-grounded behaviors my S3 machinery simply hadn't yet implemented (the
registry + the v7.74 §10.1 + §9.5a vectors that postdate the older cohort
verdict), not spec contradictions.

## §7a conformance handlers (cohort parity, off by default)

`system/validate/{echo,dispatch-outbound}` (GUIDE-CONFORMANCE §7a) are
bootstrapped only when the peer is built `conformance=true` (host `--validate`).
`echo` is the §6.13(a) A-011 closure (returns params verbatim, unit-tested);
`dispatch-outbound` originates one outbound EXECUTE over the §6.11 reentry seam
(`transport.outboundShim` binds `conn.outbound` per-dispatch), carrying the
caller-minted authority in-band — the A-013 closure. The current oracle build
does **not** gate `--profile core` on these (no `system/validate/echo` symbol in
its check set), so they are parity surface, not on the core gate. The `--validate`
host serves cleanly with no core-profile regression.

## Idiom seams (Zig-specific, vs C#/TS/OCaml)

- **No GC** — the type registry renders through a scratch arena (each entity
  duped into the store, scratch freed); the entity-native evaluator and the §7a
  handlers allocate from the per-request dispatch arena; the reentry shim
  deep-clones the io.gpa-owned reply into the handler arena so ownership stays
  single-allocator. Every test + the smoke is leak-checked.
- **Build-time conformance** — the A-ZIG-008 53-type byte-diff is a `zig build
  test` unit test (loads the vector .cbor, renders, diffs digests), so the
  registry is gated offline before the live type_system run de-risks it.

## Regression / gates held

- `zig build test` — **28/28** leak-clean (S2 codec 69/69 unbroken + the new
  A-ZIG-008 byte-diff + deletion-marker + §7a echo tests).
- `zig build conformance` — **69/69** wire-conformance (no codec regression).
- `zig build smoke` — **SMOKE: PASS (7/7)** over two-peer loopback, leak-clean.
- `validate-peer --profile core` — **568 · 284P · 195W · 0F · 89skip → PASS.**

## Exit criteria

`--profile core` PASS with 0 FAIL · warns/skips are the documented non-floor /
§9.0-carve-out classes · in-container reproducible (`run-s4.sh`, `--network=none`,
std-only) · no codec/smoke regression · no new spec ambiguity. **S4 PASS.**

## S5 readiness

The peer is at the publishable verdict (green report, the S5 "green report or no
publish" gate is met). Remaining for S5: README + LICENSE + a pinned
`build.zig.zon` (std-only, no fetched deps — supply-chain trivial), CI wiring of
the in-container `zig build test` + `run-s4.sh`, and the version pin
(spec-data v7.72/v7.74, oracle HEAD recorded in this report). The agility
higher-bar (Ed448, A-ZIG-002) remains the one deferred surface — a hybrid
native-Ed25519 + FFI-Ed448 path when agility enters scope, outside the v0.1 core
floor.

---

## ADDENDUM — §7a oracle re-verification (keystone steward)

**Why:** the S4 run above was driven by a **pre-§7a oracle** (the parallel-harness
worktree's local `validate-peer`), which still carried `core_register_dispatch_roundtrip`
and had **no `validate_echo_dispatch` / `dispatch_outbound_reentry`** in its check set —
hence the §7a section's belief that the handlers were "parity surface, not on the core
gate." That oracle predates `entity-core-go@9c624aa` (the unified A-011/A-013 §7a
resolution), so Zig was green against a stale validator while the rest of the cohort
(C#/TS/OCaml/Elixir/CL) was on `9c624aa`.

**Re-run against the current `9c624aa` oracle, with `--validate`:**
- `validate-peer --profile core` → **568 / 284P / 195W / 0F / 89skip PASS** (unchanged
  scoreboard; `core_register_dispatch_roundtrip` retired → **`validate_echo_dispatch` PASS**;
  register gate now **10/10** on the §7a shape). `status/CONFORMANCE-REPORT.json` refreshed.
- `run-origination-core.sh` (new, mirrors the cohort) → **origination 3/3 PASS** incl.
  **`dispatch_outbound_reentry`** over real two-peer TCP (Zig target A-role, Go `entity-peer`
  reference B-role). The `transport.zig` §6.11 reentry shim is now **wire-proven**, not just
  unit-tested — and it passed first try, so the harness shipped the *code* correct; only the
  *verification* was against the wrong oracle.

**Net:** no Zig code bug — a verification-provenance gap, now closed. Zig is on par with the
cohort on the current §7a oracle. `run-s4.sh` default flipped to `--validate` on
(`CONFORMANCE=1` default) to prevent recurrence.
