> **v7.75 re-run (oracle `entity-core-go @ 62044c5`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 291 pass · 196 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-haskell — Conformance Report (S4)

**Peer:** #8 (Haskell) · **Spec basis:** v7.74 ·
**Oracle:** Go `validate-peer` @ go HEAD `749e57e` (§7a
`validate_echo_dispatch` + §7b concurrency gates present).

> The S2 codec self-conformance report (69/69 byte-identical + agility corpus) is
> preserved at `status/CODEC-CONFORMANCE-S2.md`. This file is the live-peer S4
> (`validate-peer`) conformance report.

## Verdict

**`validate-peer --profile core` → `Result: PASS` — 0 FAIL.** Reached the cohort
fixed point on the **first oracle run, zero peer-correctness fixes** — the S3
machinery was already wire-correct; S4 only had to land the full §9.5 53-type
registry render (A-HS-009), which byte-matched the Go vectors on the first try.

```
Summary: 573 total, 289 passed, 195 warned, 0 failed, 89 skipped (elapsed 21.71s)
         89 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out
Result: PASS (with warnings)
```

`failed == 0` is the binary gate (S5 no-doctoring). Warns are non-§9.5-floor type
vocabulary (matched-if-present) + one tree_operations matched-if-present probe;
skips are the §9.0 extension-category carve-outs.

## Per-category scoreboard

| Category | Pass | Warn | Fail | Skip | Total |
|---|---:|---:|---:|---:|---:|
| connectivity | 22 | 0 | 0 | 0 | 22 |
| encoding | 6 | 0 | 0 | 0 | 6 |
| type_system | 108 | 194 | 0 | 0 | 302 |
| handlers | 35 | 0 | 0 | 32 | 67 |
| capability | 12 | 0 | 0 | 0 | 12 |
| tree_operations | 24 | 1 | 0 | 31 | 56 |
| security | 28 | 0 | 0 | 1 | 29 |
| multisig | 10 | 0 | 0 | 0 | 10 |
| concurrency | 5 | 0 | 0 | 0 | 5 |
| universal_address_space | 8 | 0 | 0 | 0 | 8 |
| peer_canonicalization | 7 | 0 | 0 | 0 | 7 |
| format_agility | 10 | 0 | 0 | 0 | 10 |
| crypto_agility | 4 | 0 | 0 | 0 | 4 |
| negotiation | 4 | 0 | 0 | 0 | 4 |
| authz | 6 | 0 | 0 | 2 | 8 |
| (extension categories, each) | 0 | 0 | 0 | 1 | 1 |
| **Total** | **289** | **195** | **0** | **89** | **573** |

## type_system — the §9.5 53-type floor (A-HS-009 RESOLVED)

`type_system` is **108 PASS / 194 WARN / 0 FAIL**. The 53 core `system/type/<name>`
entities render **from the in-code model** (`src/EntityCore/TypeDefs.hs` — the
render-from-model cross-peer ruling, NOT ingest-from-bytes) through the byte-green
S2 codec. A build-time byte-diff (`test/TypeRegistrySpec.hs`, A-HS-009) renders all
53 and compares each `content_hash` digest against the canonical Go-rendered
`type-registry-vectors-v1.cbor` set → **53/53 byte-identical on the first run**.
The non-floor types the oracle also probes (validate/constraint/compute/content/…)
WARN (matched-if-present); a core peer publishes only the floor (refined G4 / F17).

## §10.1 core-register gate — 10/10 PASS

All ten register checks green (handlers category): `core_register_body_binding`,
`core_register_op_status`, `core_register_op_result`,
`core_register_manifest_at_path`, `core_register_handler_at_path`,
`core_register_grant_at_path`,
`core_register_grant_signature_at_invariant_path` (§3.4 grant-sig enforced at
`system/signature/{grant_hash}` — presence + target binding),
`core_register_unregister_status`, `core_register_unregister_signature_removed`
(unregister symmetry), and the §7a `validate_echo_dispatch` (the A-011 resolution —
register→dispatch round-trip exercised through `system/validate/echo`, not the
`compute/literal` body).

## §7b concurrency gate — 5/5 PASS

The STM-`TVar` store + GHC `-threaded` RTS make the concurrency floor structural:

| Check | Result | Detail |
|---|---|---|
| t1_1_concurrent_demux | PASS | N=16 concurrent gets all demuxed correctly, sequenced |
| t1_2_concurrent_reentry | PASS | M=8 concurrent reentrant dispatch-outbound calls round-tripped |
| t1_3_no_head_of_line | PASS | fast.get p50 stable under contention (solo≈373µs) |
| t2_1_sustained_load | PASS | C=16 × K=10000 sustained load: zero drops, p50 stable |
| t2_2_connection_churn | PASS | 100 connect→handshake→req→close cycles all succeeded |

t1_2 (concurrent reentry) and t2_1 (sustained load) — the legs that RED'd the whole
cohort in the earlier §7b-gate sweep (memory: concurrency-gate-7b-results) — pass
here **by construction**: the store serializes at the STM commit point (no manual
locking, no lost update), and GHC's IO manager multiplexes blocking socket reads
over epoll so a parked `recv` yields its capability rather than starving the
scheduler (the Swift cooperative-pool trap GHC sidesteps). `TCP_NODELAY` on every
socket. **Haskell is the first peer to clear the full §7b gate with no per-check
fix** — the STM/green-thread shape was already correct at S3.

## §10.2 origination-core / dispatch_outbound_reentry — 3/3 PASS

`run-origination-core.sh` (Haskell A-role + Go `entity-peer --open-access` B-role,
real two-peer TCP, sealed-offline): `reference_connect`, `reference_ready`,
**`dispatch_outbound_reentry`** all PASS, first run. The §6.11 reentry seam
(`Transport.hs` forkIO reader-demux + `TVar` request_id↔reply correlation +
`Peer.outboundDispatch`) is now **wire-proven cross-impl**, not just unit-tested:
the target originates an outbound EXECUTE back to the validator-as-B over the SAME
inbound connection (not a fresh dial), N6 holding under the `-threaded` RTS.

```
[origination]
  PASS reference_connect
  PASS reference_ready
  PASS dispatch_outbound_reentry   GUIDE-CONFORMANCE §7a.1 + §7a.2a; PROPOSAL v7.74 §10.2
Summary: 3 total, 3 passed, 0 warned, 0 failed, 0 skipped → Result: PASS
```

(Origination is reference-peer-gated; the single-peer `run-s4.sh` honest-SKIPs it
under core — `origination 0/0/0/1`. The probe runs via `run-origination-core.sh`.)

## Agility — fully native, Ed448 included (A-HS-007 data point)

`crypto_agility` (4/4) + `format_agility` (10/10) pass clean in the core gate, incl.
**`key_type_ed448_1` PASS live, not SKIP**. The distinguishing Haskell fact: the
agility surface is **fully native, zero FFI** — Ed448 (`key_type 0x02`) is sourced
from crypton `Crypto.PubKey.Ed448` (the SAME audited C-backed library as Ed25519),
SHA-384 from crypton too. OCaml hit the native Ed448 gap (→ hybrid FFI sub-library),
Zig/Swift deferred Ed448 to an FFI path; Haskell is the first peer where the full
agility corpus — incl. the deeper Ed448 sign/verify KATs in `test/AgilitySpec.hs`
(25/25 at S2, unregressed) — runs in-process with no FFI detour and no opt-in
agility sub-library. The shipped core peer is self-contained (`cabal install` pulls
no system packages) AND fully agility-capable.

> Honest scope note: the *validate-peer* `crypto_agility` category is also satisfied
> by the FFI-deferred peers (Zig's report shows `key_type_ed448_1` PASS too) — that
> check exercises peer-id / key-type string handling at the protocol surface, not a
> live Ed448 signature in the core gate. The native-vs-FFI distinction is at the
> test-corpus / library-availability layer, which is where the cross-peer agility
> ledger tracks it. Haskell's data point: native full agility with no sub-library.

## Regression gates held

- `cabal test conformance` — **160 examples, 0 failures** (S2 codec 69/69 +
  AgilitySpec 25/25 + Property + Selftest + the new A-HS-009 53-type byte-diff).
- `cabal test smoke` — **7/7 green** over two-peer loopback TCP, deterministic.
- No codec / smoke / agility regression.

## Honest SKIPs / WARNs (all justified)

- **89 skips** — whole §9.0 extension categories (subscriptions, continuations,
  role, identity, compute, entity_native, attestation, quorum, …) + the handler/
  tree extension-op subsets, auto-allowlisted by `--profile core`.
- **195 warns** — non-§9.5-floor type vocabulary (matched-if-present) + 1
  tree_operations matched-if-present probe.
- **`authz` 2 skips, `security` 1 skip** — ROLE §5.5 / SUBSCRIPTION extension
  carve-outs (`authz_revoked_1` expects ROLE 401 capability_revoked; the core
  peer's 403 capability_denied passes via `authz_revoked_core_1`). F18/F19.
- **`origination` 1 skip under run-s4** — reference-peer-gated; PASSes 3/3 via
  `run-origination-core.sh`.

## Iteration count

**1 oracle iteration to PASS, 0 peer-correctness fixes.** Two GHC-mechanics fixes
in the new render code (infix builder arg-order; a `MonadFail`-free test parse).
Spec-first machinery from S3 was already correct against the live oracle.
