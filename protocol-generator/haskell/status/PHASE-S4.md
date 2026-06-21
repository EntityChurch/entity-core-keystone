# entity-core-protocol-haskell — Phase S4 (Conformance) Summary

**Peer:** #8 (Haskell) · **Phase:** S4 (live-peer conformance) ·
**Spec basis:** v7.74 · **Status:** COMPLETE — **`validate-peer --profile core`
PASS, 0 FAIL**; §10.1 register 10/10; §10.2 origination-core 3/3; §7b concurrency
5/5; type_system 53/53 byte-identical; agility fully native (Ed448 included).

## Headline

S4 reached the cohort fixed point — `573 total / 289 passed / 195 warned / 0 failed
/ 89 skipped → Result: PASS` — on the **first oracle run, with zero
peer-correctness fixes**. The S3 machinery (the four MUST handlers, §6.5 dispatch,
§6.9a bootstrap, §6.13a register, §6.13b outbound, §6.11 reentry, the STM store)
was already wire-correct against the live oracle. The only S4 build was the
deferred-from-S3 work item: the full §9.5 53-type registry render (A-HS-009).

## Iteration count

**1 oracle iteration to PASS.** No FAIL→fix→re-run loop was needed: the first
`run-s4.sh` against the live oracle reported 0 failed. (Contrast the spec-first
distant-idiom peers that drove a 90+→0 loop — Haskell's S3 was built tightly enough
against v7.74 that the live oracle found nothing to fix beyond the registry it
explicitly deferred.)

## What S4 built — the §9.5 53-type registry (A-HS-009)

`src/EntityCore/TypeDefs.hs` rewritten from the S3 minimal seed into the full
render-from-model registry: an `FSpec` (field spec — `type_ref` / `array_of` /
`map_of` / `union_of` / `key_type` / `byte_size`, omit-empty) + `TypeDef` (`name` /
`extends` / `fields` / `layout`) builder, with the 53 core types declared in code
(faithful port of the cross-blessed C#/TS/OCaml/Zig enumeration). `publish` renders
each as a `system/type` entity through the byte-green S2 codec and binds it at
`/{peer}/system/type/{name}`.

**Byte-diff test** (`test/TypeRegistrySpec.hs`, wired into the conformance suite):
renders all 53 and compares each entity's `content_hash` digest against the
canonical Go-rendered `type-registry-vectors-v1.cbor` set → **53/53 byte-identical
on the first run**. The codec being byte-green at S2 meant the only residual risk
was field-shape data; the per-type digest diff catches it, and it was correct
first try (the omit-empty + canonical-key-sort semantics matched the Go encoder).

Design follows the cross-peer ruling (memory: type-registry-render-design): render
from an in-code model (single source of truth), NOT ingest-from-bytes. A core peer
publishes exactly the 53-type floor; the oracle's non-floor probes WARN
(matched-if-present).

## Fixes — peer-correctness vs GHC-mechanics

**Peer-correctness fixes: 0.** No protocol behavior was wrong against the oracle.

**GHC-mechanics fixes: 2** (both in the new render code, neither protocol-shaped):
1. **Infix builder arg-order.** `withFields` / `withExtends` / `withLayout` are
   used infix (`td \`withFields\` fields`) so the `TypeDef` must be the LEFT
   operand — initial draft had `[(Text,FSpec)] -> TypeDef -> TypeDef` (combinator
   order), which mis-typed the chain. Flipped to `TypeDef -> arg -> TypeDef`.
2. **`MonadFail`-free test parse.** The byte-diff test used a failable
   `VArray items <- decode raw` pattern in the `Either` monad (no `MonadFail`
   instance); rewrote as an explicit `case`.

## §10.1 core-register gate — 10/10 PASS

All ten register checks green, incl. `core_register_grant_signature_at_invariant_path`
(§3.4 grant-sig at `system/signature/{grant_hash}`, presence + target binding both
ways), `core_register_unregister_signature_removed` (unregister symmetry), and the
§7a `validate_echo_dispatch` (the A-011 resolution — the register→dispatch
round-trip runs through `system/validate/echo`, so the `compute/literal` body
evaluator (A-HS-010) is no longer gate-exercised; kept harmless until Go drops it).

## §7b concurrency gate — 5/5 PASS (the structural win)

The STM-`TVar` store + GHC `-threaded` RTS cleared the full §7b gate with **no
per-check fix**. t1_2 (concurrent reentry) and t2_1 (C=16×K=10000 sustained load,
zero drops) — the legs that RED'd the rest of the cohort in the §7b sweep (memory:
concurrency-gate-7b-results: Zig 65% / CL 32% drops, TS single-thread t1_1) — pass
here by construction:
- store mutations commit inside `atomically` → no lost update, no manual lock;
- the IO manager parks a blocking `recv` on epoll and yields its capability →
  no scheduler starvation (the Swift cooperative-pool trap GHC sidesteps);
- `TCP_NODELAY` on every socket (the Zig/Swift Nagle-churn lesson, set from S3).

This is the §7b data point Haskell was selected to provide: a 3rd data-race-free
store shape (transactional STM, after the Elixir actor / Swift actor) that meets the
gate structurally rather than by discipline.

## §10.2 origination-core / dispatch_outbound_reentry — 3/3 PASS

Authored `run-origination-core.sh` (modeled on the CL/Zig harness): Haskell A-role
+ Go `entity-peer --open-access` B-role over real two-peer TCP, sealed-offline.
`reference_connect` / `reference_ready` / **`dispatch_outbound_reentry`** all PASS
first run. The §6.11 reentry seam is now wire-proven cross-impl: the target
originates an outbound EXECUTE back to the validator-as-B over the SAME inbound
connection (not a fresh dial). The single-peer `run-s4.sh` honest-SKIPs origination
(reference-peer-gated).

## Agility — fully native, Ed448 in the core gate (A-HS-007)

`crypto_agility` 4/4 + `format_agility` 10/10 PASS, incl. `key_type_ed448_1` live
(not SKIP). Haskell is the first peer with native full agility — Ed448 + SHA-384
from crypton (same audited C-backed lib as Ed25519), **no FFI, no opt-in agility
sub-library**, and the shipped core peer stays self-contained. OCaml/Zig/Swift defer
Ed448 to an FFI path. Honest caveat: the *oracle's* `crypto_agility` category is also
satisfiable by the FFI-deferred peers (it exercises peer-id/key-type string handling
at the protocol surface, not a live core-gate Ed448 signature) — the native-vs-FFI
distinction lives at the test-corpus / library-availability layer, where the
cross-peer agility ledger tracks it. The data point: Haskell needs no agility
sub-library at all.

## New spec findings — none

No new `⚑` spec-text-tension item surfaced at S4 — expected for a coverage peer.
The peer-id §7.4→§1.5 reconciliation, the §4.6 401/403 boundary (the `authz_revoked`
ROLE carve-out passing via `authz_revoked_core_1`), and the §PR-8/§5.5a granter
frame all landed consistently with the cohort against the live oracle — an 8th
independent corroboration, not a discovery. The carried recorded-decision items
(A-HS-010 compute/literal, A-HS-011 seed-policy file parse) are unchanged and
non-blocking; A-HS-009 is RESOLVED this phase.

## Regression / gates held

- `cabal test conformance` — **160 examples, 0 failures** (S2 69/69 + agility 25/25
  + the new 53-type byte-diff + property + selftest).
- `cabal test smoke` — **7/7 green** over two-peer loopback TCP.
- `validate-peer --profile core` — **573 / 289P / 195W / 0F / 89skip → PASS.**
- in-container reproducible (`run-s4.sh`, `--network=none`, warm `.cabal-home`).

## Exit criteria

`--profile core` PASS with 0 FAIL · §10.1 10/10 · §10.2 3/3 · §7b 5/5 ·
type_system 53/53 byte-identical · agility native incl. Ed448 · no codec/smoke
regression · no new spec ambiguity · A-HS-009 resolved. **S4 PASS.**

## S5 readiness

The peer is at the publishable verdict (the S5 "green report or no publish" gate is
met). Remaining for S5: README + CHANGELOG + LICENSE (Apache-2.0 default), the
Hackage/cabal packaging metadata (`.cabal` is already shaped), `.cabal-home` warm
store + committed freeze pin confirmation (A-HS-012 `network 3.2.8.0` 30-day floor
re-pin audit), and the version pin (spec-data v7.74, oracle go HEAD `749e57e`
recorded here).
