<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-08) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 333 pass · 338 warn · 0 FAIL · 107 skip** (elapsed 112487 ms).
>
> That digest is the pinned `core_executed_check_set_digest`, so this number is
> comparable to every other row in `CONFORMANCE-MATRIX.md` §1 — and it is a CONTENT
> anchor, which is the only kind that survives the release boundary ([ADR-0012] Am. 1).
> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative
> artifact; `tools/check-set-gate.py --tracked` gates it, and this banner is generated
> from it by `tools/status-banner.py` rather than typed.
>
> **Everything below this line predates this measurement and is retained as build
> history.** Where it disagrees with the figures above, the figures above win;
> `CONFORMANCE-MATRIX.md` §1 is authoritative for the cohort.

---

# entity-core-protocol-smalltalk — Conformance Report (S4)

**Peer:** #26 — Pharo Smalltalk (the FIRST pure-object / live-image / message-passing peer).
**Gate:** `validate-peer --profile core` (V7 v7.72 §9.0 core-profile).
**Oracle:** `validate-peer` @ **`cc1970f`** (`cc1970f448e01b0eea8d8032e076f50b571359ed`),
core-gate fingerprint `8261a033fe1af56b1973fefb07ba8fcbdfd0867c17707275dbbd453bdc9bf745` —
matches `tools/oracle-pin.env`. Not rebuilt (overseer-prepared, fingerprint-verified current).
**Peer identity:** `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (seed `0x11`×32 / PEM `ERER…`).
**Date:** 2026-07-12.

## Headline — `Result: PASS`

**`682 total · 291 pass · 295 warn · 0 FAIL · 96 skip` @ `cc1970f`**

`validate-peer --profile core` → **`Result: PASS (with warnings)`**, **0 FAIL, 0 fail-counting
skips**. All 96 skips are §9.0 auto-allowlisted extension carve-outs (exempt from the FAIL gate);
all 295 warns are non-§9.5-floor type vocabulary (matched-if-present). Raw per-check JSON is
`status/CONFORMANCE-REPORT.json`. Reproduce with `./run-s4.sh`.

This is **exact cohort parity with Rexx (#24) and Forth (#25)** — both `682·0F @ cc1970f`,
291/295/96 — a **cohort-consistent** convergence (the keystone-generated peers share a generation
lineage), NOT independent convergence. The ground-up impls (go/rust/py) are the independent bases.

## Per-category status (0 FAIL everywhere)

| Category | Pass | Warn | Fail | Skip | Notes |
|---|---|---|---|---|---|
| `connectivity` | 22 | 0 | 0 | 0 | incl. `handshake_replay_cross_connection` (per-connection nonce bug fixed, A-ST-014) |
| `encoding` | 6 | 0 | 0 | 0 | hash wire form / key ordering / signature signer |
| `type_system` | 108 | 292 | 0 | 0 | render-from-model 53-type §9.5 floor (all PASS) + non-floor vocab WARN |
| `handlers` | 35 | 0 | 0 | 32 | connect/tree/capability manifests + N2 dispatch + `core_register_*` (register/unregister); extension handlers auto-skip |
| `tree_operations` | 23 | 2 | 0 | 31 | get/put/CAS/listing; deletion-marker = spec-allowed WARN; EXTENSION-TREE ops auto-skip |
| `capability` | 12 | 0 | 0 | 0 | request (mint-bounded) / configure / revoke / delegate-501 / scope |
| `authz` | 6 | 0 | 0 | 2 | grantee-401 / no-catchall-403 / deny-default / expiry / revoked (ROLE/SUBSCRIPTION legs skip) |
| `multisig` | 11 | 0 | 0 | 0 | **incl. the genuine 2-of-3 peer-co-signed ACCEPT path** (the keystone payoff) |
| `security` | 28 | 0 | 0 | 1 | chain sig/attenuation/caveats/temporal/revocation + foreign-granter; 1 auto-allowlisted skip |
| `negotiation` | 4 | 0 | 0 | 0 | hash-format / key-type disjoint reject + AGILITY-UNKNOWN-1 |
| `crypto_agility` | 4 | 0 | 0 | 0 | |
| `format_agility` | 10 | 0 | 0 | 0 | |
| `peer_canonicalization` | 7 | 0 | 0 | 0 | |
| `universal_address_space` | 8 | 0 | 0 | 0 | open-grants seed `/*/*` covers the foreign namespace |
| `concurrency` | 5 | 0 | 0 | 0 | t1_1 demux (parallel speedup) / t1_2 reentry / t1_3 no-HoL / t2_1 16×10000 / t2_2 churn |
| `resource_bounds` | 2 | 1 | 0 | 0 | r1 payload→413 (PASS) / r2 chain-depth→400 (PASS) / r3 conn-flood→WARN (§4.10(c) SHOULD) |
| extension categories (subscriptions, continuations, role, origination, relay, …) | — | — | — | 96 | whole extension categories — §9.0 auto-allowlisted |

### Origination-core §10.2 — 3/3 (reference-peer-gated; `./run-origination-core.sh`)

Under `--profile core` a single-peer run **honest-SKIPs** the origination category (extension-only,
§9.0 auto-allowlisted). Exercised separately against a Go `entity-peer` as B-role:

- **`reference_connect` PASS**, **`reference_ready` PASS**, **`dispatch_outbound_reentry` PASS** —
  the §6.11 reentry pump (`EcPeer>>dispatchOutbound:...` + the `EcPending` request_id demux), wired
  to the live `system/validate/dispatch-outbound` handler under `--validate`, genuinely originates
  ONE outbound EXECUTE back to the validator-as-B over the SAME inbound connection and round-trips
  the value. **3/3**, cohort parity.

## The multisig ACCEPT-path unit test (the keystone payoff — the direction the oracle can't cover)

`multisig` is a **rejection-only** oracle category (every vector is a malformed 2-of-3 → 403), so a
fail-closed peer passes it VACUOUSLY. `tests/multisig-accept.st` (`make multisig-accept`) builds a
GENUINE 2-of-3 root cap in-image, co-signs it as two of three signers (one the local peer), and
asserts the §5.5 verifier **ACCEPTS** (M3 structure + M4 threshold + M6 local-signer) — then flips
each rule and asserts it REJECTS. **MULTISIG-ACCEPT 4/4.** This proves the chain verifier isn't
vacuously fail-closed. The oracle's own `valid_2of3_peer_signed_accepted` also PASSES (the peer
loads its on-disk keypair and co-signs as the peer).

## Regression status (all still green after the S4 changes)

- S2 codec: **69/69** corpus + int-boundary (bignum uint64 head-form) + crypto-accept.
- S3: **selftest 25/25 + smoke 6/6** (the new dispatch/authz/serve-loop changes are compatible).
- Origination-core §10.2: **3/3** (`dispatch_outbound_reentry` PASS, Go peer as B).

## Honesty notes

- Every skip is §9.0 auto-allowlisted (extension carve-out) — none count as FAIL; none hand-marked.
- The oracle was never doctored. Every FAIL surfaced during S4 was a PEER bug fixed in code (see
  `PHASE-S4.md` + `SPEC-AMBIGUITY-LOG.md` A-ST-014…017). The one deletion-marker WARN and the r3
  WARN are spec-allowed SHOULD outcomes (cohort-identical), not masked failures.
- `682·0F @ cc1970f` is cohort-consistent (shared generation lineage), stated precisely — not
  independent convergence.
