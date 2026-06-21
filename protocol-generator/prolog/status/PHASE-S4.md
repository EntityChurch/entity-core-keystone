# Prolog peer — PHASE S4 report (conformance vs the Go oracle)

**Phase:** S4 — conformance against the Go `validate-peer` oracle, `--profile core`
**Oracle pin:** **`entity-core-go @75c532e`** (vendored fedora ELF, BuildID
`482ee7547265ed0838f34dabf2975af65e2f9c45` — the same oracle Ruby + Go scored 653·0F·94S
against; verified by `readelf -n`).
**Verdict line:** **`S4: GREEN — 653·0F @ 75c532e`**

---

## 1. Headline gate result (machine-verified)

| Gate | Result |
|---|---|
| **`validate-peer --profile core`** | **653 total · 291 P · 269 W · 0 F · 93 S → `Result: PASS`** |
| **machine-check** | `summary.failed == 0` read straight from `CONFORMANCE-REPORT.json` (`True`); 0 FAIL entries in the `checks` array |
| **origination-core** (`./run-origination-core.sh`, Go-reference-gated) | **3/3 PASS** incl `dispatch_outbound_reentry` over real 2-peer TCP |
| **S2 regression** | `run-s2.sh` → 69/69 ECF + 10/10 crypto KAT → **GREEN** |
| **S3 regression** | `run-s3.sh` → 53/53 type-registry + 11/11 loopback smoke → **GREEN** |

Raw `summary` block from the JSON (the gate evidence):

```json
{"total": 653, "passed": 291, "warned": 269, "failed": 0, "skipped": 93, "elapsed_ms": 74468}
```

The in-container command (sealed-offline, oracle + peer share one loopback):

```
podman run --rm --network=none -v "$PWD":/work:Z -w /work -e ORACLE_TIMEOUT=300s \
  entity-core-keystone/prolog-toolchain:latest \
  protocol-generator/prolog/run-s4.sh
#  → Result: PASS (with warnings) ; validate-peer exit rc=0
```

`run-s4.sh` builds the C-ABI codec + SWI shim (S2 floor), provisions the peer keypair
at `~/.entity/peers/conformance/keypair` (seed `0x11×32`, base64 `ERER…` — so the
multisig accept-path probe can co-sign AS the peer), boots `prolog/ec_host.pl
--port 7777 --name conformance --debug-open-grants --validate`, waits for its
`LISTENING …` line, then runs `validate-peer -addr 127.0.0.1:7777 -profile core
-timeout 180s -json-out status/CONFORMANCE-REPORT.json`. (`-timeout` bumped from the
1-minute default because `security` ≈ 20 s + `concurrency` ≈ 50 s blow it, which
budget-SKIPped the late categories on the first runs.)

## 2. Per-category breakdown (JSON-backed)

| Category | P | W | F | S | Note |
|---|---|---|---|---|---|
| connectivity | 22 | 0 | 0 | 0 | handshake, nonce, peer_id, replay |
| encoding | 6 | 0 | 0 | 0 | |
| type_system | 108 | 266 | 0 | 0 | 53/53 §9.5 floor PASS; 266 WARN = non-floor `compute/*`/`clock/*` matched-if-present |
| handlers | 35 | 0 | 0 | 32 | the 32 SKIP = extension handler sub-pins (cohort parity) |
| capability | 12 | 0 | 0 | 0 | request/revoke/configure/**delegate** |
| tree_operations | 24 | 1 | 0 | 31 | CAS, path-flex, delete-marker omission; 1 WARN = oracle's own `cleanup` teardown |
| security | 28 | 0 | 0 | 1 | incl. expired/not-before/temporal-chain DENY (see temporal_ok §4) |
| multisig | 11 | 0 | 0 | 0 | §3.6 K-of-N incl. the keypair-provisioned accept path |
| concurrency | 4 | 1 | 0 | 0 | t1_2/t1_3/t2_1/t2_2 PASS; 1 WARN = `t1_1` no-parallel-speedup (informational) |
| resource_bounds | 2 | 1 | 0 | 0 | 1 WARN = `r3_connection_flood` admission-is-external (cohort parity) |
| universal_address_space | 8 | 0 | 0 | 0 | absolute/peer-relative/foreign-namespace addressing |
| peer_canonicalization | 7 | 0 | 0 | 0 | |
| format_agility | 10 | 0 | 0 | 0 | incl. AGILITY-UNKNOWN-1 (key_type 0xfd → 400) |
| crypto_agility | 4 | 0 | 0 | 0 | |
| negotiation | 4 | 0 | 0 | 0 | disjoint hash_formats/key_types → 400 |
| authz | 6 | 0 | 0 | 2 | |
| (extension cats: subscriptions, clock, query, compute, …) | — | — | — | 1 each | auto-allowlisted by the §9.0 `--profile core` carve-out (exempt from the FAIL gate) |

**The only three non-`type_system` WARNs (all benign, all recorded honestly):**

```
tree_operations cleanup          WARN :: failed to remove test entity (non-critical)  [oracle's own teardown]
concurrency      t1_1_concurrent_demux WARN :: demux + completeness OK, but no parallel speedup observed
                                              (N=16 ≈ 72ms vs seq ≈ 85ms; informational, not a §6.11 violation)
resource_bounds  r3_connection_flood   WARN :: opened all 256 connections without refusal — admission delegated externally
```

These three are the SAME WARNs the Ruby peer recorded (whole-cohort behaviour); none
is a core MUST and none counts toward the FAIL gate.

## 3. What the oracle caught and what was fixed (the iteration loop)

The S3 peer was spec-first-correct on the relational core but had a handful of
genuine bugs the cross-impl oracle surfaced. Every fix is a real peer change — no
hardcoded outputs, no stubbed handlers, no special-casing.

**Run 1 → the showstopper: `key_type 0x00`.** The very first handshake check failed:
`hello_peerid_valid FAIL: unsupported key type 0x00`. The §1.5 key registry codes
Ed25519 as **0x01** (Ed448 = 0x02); only `hash_type` is 0x00. The peer shipped 0x00 —
the A-PL-010 bake-in was wrong on the key_type byte. Fixed
`ec_identity.pl:peer_id_of_pubkey/2` → `ec_peerid_format(1, 0, Digest, _)`. (See
A-PL-010a in the ambiguity log — this is exactly the "passes S2, blows up at the S4
handshake" cycle that entry warned about; the opaque-digest corpus let S2/S3 stay GREEN
with the wrong byte because both loopback peers shared the same wrong derivation.)

**Run 2 → handlers + capability + tree.** Once the handshake landed, the substantive
categories surfaced 14 more FAILs, all fixed in `ec_peer.pl`:

- **handler operations (3 FAIL):** the bootstrap interface entities had empty
  `operations` maps. Now each MUST handler declares its operations (`core_handler_spec/3`):
  connect→hello/authenticate, tree→get/put, handler→register/unregister,
  type→validate, capability→request/revoke/configure/**delegate**.
- **`delegate` capability op (was 501):** added the §6.2/v7.62 §9 delegate clause —
  parent required + non-zero (else 400), same-peer-only in v1 (remote author → 501),
  mints a bounded child under the parent.
- **`configure` partial-prefix (was 200):** added `peer_pattern_ok/1` — accept only
  the literal `default`, a 66-char hex hash, or a full Base58 peer_id; partial prefix → 400.
- **register/unregister symmetry (1 FAIL):** unregister now removes EVERY entity
  register wrote — the handler, interface, grant token, AND its detached §3.5 signature.
- **CAS (5 FAIL):** `cas_ok/3` in tree put — absent `expected_hash` admits; a 33-byte
  zero hash is create-only (admit iff path unbound); a non-zero hash must equal the
  current binding hash (else 409 `hash_mismatch`).
- **path-flex validation (path_flex_ok/1):** reject null byte, leading-slash whose
  first segment is not a peer_id, `.`/`..`, and interior empty segments (`//`); allow
  the trailing-`/` listing marker and the bare local-root (`""`, `/`).
- **deletion-marker listing omission (CORE-TREE-DELETE-1):** `build_listing` now drops
  leaf entries bound to a `system/deletion-marker`.

**Run 3 → negotiation + agility + reentry (4 FAIL):**

- **§4.5 negotiation (2 FAIL):** the hello handler now rejects an explicit
  `hash_formats` list disjoint from `ecfv1-sha256` (→ 400 `incompatible_hash_format`)
  and an explicit `key_types` list disjoint from `ed25519` (→ 400 `unsupported_key_type`).
- **AGILITY-UNKNOWN-1 (1 FAIL):** authenticate now returns **400 `unsupported_key_type`**
  (not 401) when the key_type field ≠ ed25519, the public_key ≠ 32 bytes, OR the
  claimed peer_id's leading key_type byte ≠ 0x01 (the 0xfd case — parsed via
  `ec_peerid_parse`).
- **§6.11 reentry / dispatch-outbound (1 FAIL):** implemented the §7a
  `system/validate/dispatch-outbound` handler — originate exactly one outbound EXECUTE
  back over the SAME inbound connection (the reentry seam), relay the downstream
  `{status, result}`. This needed TWO transport fixes: (a) **A-PL-017** — switch
  per-connection mutexes from named-alias to ANONYMOUS + destroy on teardown (named
  globals leaked under the churn probe and killed serve threads); (b) **A-PL-018** —
  hand the seam as the MODULE-QUALIFIED term `ec_transport:outbound_via(IO)` so the
  dispatcher's `call/3` resolves it (an unqualified term hit
  `existence_error(ec_peer:outbound_via/3)` → 503).

## 4. `temporal_ok/1` disposition — LIT UP (the S3 stub is gone)

The oracle **does** exercise temporal/expiry capabilities under `--profile core`
(`security.expired_capability_denied`, `not_before_denied`,
`chain_per_link_temporal_denied`, `chain_mid_link_expiry_denied`). Per the S4 mandate,
`ec_capability.pl:temporal_ok/1` is now implemented properly (no longer `:- true`):

```prolog
temporal_ok(Cap) :-
    cap_now_ms(Now),
    ( ent_uint(Cap, "not_before", NB) -> Now >= NB ; true ),
    ( ent_uint(Cap, "expires_at", EX) -> Now <  EX ; true ).
```

A cap is temporally valid iff (`not_before` absent OR now ≥ not_before) AND
(`expires_at` absent OR now < expires_at). Failure folds into the §5.5 chain-walk
failure → 403 (same channel as any link inconsistency). With it live, all 5 temporal
`security` checks PASS and the non-expiring-cap paths (53/53 registry, 11/11 loopback)
stay GREEN.

## 5. origination-core (the reference-peer-gated §10.2 probe)

`./run-origination-core.sh` (Prolog target A-role :7777 + Go `entity-peer` reference
B-role :7778 `-open-access`, both in one `--network=none` container):

```
[origination]
  PASS reference_connect
  PASS reference_ready
  PASS dispatch_outbound_reentry      GUIDE-CONFORMANCE §7a.1 + §7a.2a; PROPOSAL v7.74 §10.2
Summary: 3 total, 3 passed, 0 warned, 0 failed, 0 skipped → Result: PASS
```

`dispatch_outbound_reentry` is the cross-impl wire proof of the §6.11 reentry seam:
the validator mints a reentry cap, EXECUTEs `system/validate/dispatch-outbound` on the
Prolog peer, and the peer originates an outbound EXECUTE back to the validator-as-B
over the same inbound connection. **3/3.**

## 6. S2 / S3 still GREEN (no regression from the S4 fixes)

The `key_type 0x00 → 0x01` change moves every peer_id, but: (a) the 53 §9.5 type
entities are content-addressed by their `data` (peer_id never enters the basis) → the
type-registry diff stayed **53/53 byte-identical**; (b) both loopback peers derive
peer_ids the same way → the **11/11** smoke is unbroken.

```
run-s2.sh → conformance rc=0   kat rc=0   →   S2-FFI GATE: GREEN   (69/69 + 10/10 KAT)
run-s3.sh → type-registry rc=0  smoke rc=0  →  S3 GATE: GREEN       (53/53 + 11/11)
```

## 7. New spec findings (appended to SPEC-AMBIGUITY-LOG.md)

- **A-PL-010a** — Ed25519 `key_type = 0x01` (NOT 0x00); the A-PL-010 bake-in was wrong
  on the key_type byte and only the cross-impl oracle caught it.
- **A-PL-017** — SWI named-alias mutexes leak under connection churn; use anonymous
  mutexes + destroy on teardown.
- **A-PL-018** — the §6.11 reentry seam must be a module-qualified closure term
  (`ec_transport:outbound_via(IO)`), else `call/3` hits `existence_error` in the caller's
  module.

## 8. Things stubbed / simplified / uncertain (honesty section)

- **Nothing faked.** No hardcoded oracle outputs, no stubbed handlers-to-pass. Every
  green check is a real peer behaviour; the 3 WARNs are reported as WARNs.
- **`concurrency.t1_1_concurrent_demux` WARN** is genuine: SWI's per-connection threads
  do correctly demux (completeness 16/16) but show no wall-clock parallel speedup on
  this fast in-memory peer — the oracle itself classifies it informational ("not a
  §6.11 violation"; the real no-serialization MUST is `t1_3_no_head_of_line`, which
  PASSes). Recorded honestly; functionality-over-performance per the peer's goal.
- **`resource_bounds.r3_connection_flood` WARN** — the peer served all 256 connections
  without refusal; §4.10(c) connection-admission is a SHOULD / external-layer carve-out
  (whole-cohort behaviour), not a core MUST.
- **Debug aid left in:** `chain_error_outcome/2` prints the caught chain error to
  `user_error` ONLY when `EC_DEBUG` is set (off in the gate) — a harmless diagnostic.
- **`test/dispatch_outbound_probe.pl`** — an in-process (no-TCP) probe of the
  dispatch-outbound handler with a mock seam, the analogue of the existing
  `dispatch_probe.pl`; a debugging/regression aid, not part of the gate.

## 9. Verdict

`validate-peer --profile core` = `Result: PASS`, `summary.failed == 0`
machine-verified from `CONFORMANCE-REPORT.json` · all core categories 0-FAIL ·
origination-core 3/3 · S2 (69/69 + 10/10) and S3 (53/53 + 11/11) unbroken · oracle
pinned `@75c532e` (binaries gitignored, not committed).

**S4: GREEN — 653·0F·93S @ 75c532e**
