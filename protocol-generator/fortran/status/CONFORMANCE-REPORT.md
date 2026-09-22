<!-- current-pin-banner:d30c3dd0d4a1 -->
> **CURRENT (2026-09-01) — spec snapshot `v0.8.2.3`, executed check set `d30c3dd0d4a1…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **756 total · 313 pass · 337 warn · 0 FAIL · 106 skip** (elapsed 61883 ms).
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

# entity-core-protocol-fortran — Conformance Report

**Peer #25** — fixed-width SIGNED-ONLY numeric-model alien-substrate probe.
**Container:** `entity-core-keystone/fortran-toolchain:latest` (gfortran 15.2, fedora:43).

---

## S4 — live peer (`validate-peer --profile core`) — GREEN

**Gate:** `validate-peer --profile core` against the standing Fortran peer.
**Oracle:** `output/s4-oracles/validate-peer`, ref **`cc1970f`**
(core-gate fingerprint `8261a033…`, authoritative).
**Reproduce:** `./protocol-generator/fortran/run-s4.sh` (container-bound, `--network=none`;
oracle + peer share one intra-container loopback → sealed-offline).

```
Summary: 682 total, 292 passed, 294 warned, 0 failed, 96 skipped (elapsed 2.2s)
         96 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out
Result: PASS (with warnings)
```

### Score: **682·0F @ cc1970f** — 292 P / 294 W / **0 F** / 96 S

The 294 warns are all non-gating: **292** `type_system` render-native informational WARNs
(non-§9.5-floor vocabulary, matched-if-present), **1** `tree_operations/cleanup`
(informational), **1** `resource_bounds/r3_connection_flood` (SHOULD — see below). The 96
skips are the V7 v7.72 §9.0 extension carve-outs, **auto-allowlisted by the profile** (no
skip counts as a FAIL). peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (seed 0x11).

### Core-gate categories — all green

| Category | P / W / F / S | Notes |
|---|---|---|
| `connectivity` | 22/0/0/0 | handshake, hello/authenticate, framing |
| `encoding` | 6/0/0/0 | canonical ECF on the wire |
| `type_system` | 108/292/0/0 | 53-type §9.5 floor rendered native; 292 non-floor WARNs (matched-if-present) |
| `handlers` | 35/0/0/32 | core get/put/list/connect/capability + register/dispatch; extension handlers auto-skip |
| `capability` | 12/0/0/0 | §5 verify_request / chain-walk / attenuation / caveats / revocation |
| `tree_operations` | 24/1/0/31 | core get/put/list; EXTENSION-TREE §9 ops auto-skip |
| `security` | 28/0/0/1 | §5.4 handler-scope; the 1 skip targets `system/subscription` (extension) |
| `multisig` | 11/0/0/0 | §3.6 M3 K-of-N — **incl. the genuine accept path** (below) |
| `concurrency` | 5/0/0/0 | §6.11 / §7b / §4.9 — reentry + sustained load + churn (below) |
| `resource_bounds` | 2/1/0/0 | r1 413 + r2 chain-depth 400 PASS; r3 flood WARN (SHOULD) |
| `universal_address_space` | 8/0/0/0 | §1.4 peer-relative ≡ absolute; foreign-namespace isolation |
| `peer_canonicalization` | 7/0/0/0 | §3.6 v7.65 canonical peer-pattern + lazy-canon mint |
| `format_agility` | 10/0/0/0 | §4.4/§7.1 incl. AGILITY-UNKNOWN-1 (0xFD → 400 unsupported_key_type) |
| `crypto_agility` | 4/0/0/0 | §4.5 crypto-format agility |
| `negotiation` | 4/0/0/0 | §4.5 disjoint hash_formats / key_types → 400 reject |
| `authz` | 6/0/0/2 | §A4-AUTHZ deny/scope/grantee/expired/no-catchall; 2 skips = ROLE-ext carve-outs |

### Genuine, not vacuous

- **Multisig accept path is real K-of-N.** `valid_2of3_peer_signed_accepted` **PASS** — the
  harness provisions the peer's Ed25519 identity at `~/.entity/peers/conformance/keypair`
  (seed 0x11×32, base64 `ERER…`, so peer_id is unchanged), and the peer co-signs **AS** that
  keypair to authorize a real 2-of-3 (M4 quorum + M6 root-at-local). The oracle covers the
  ACCEPT direction here, so the "rejection-only category → vacuous pass" trap does not apply.
- **§6.11 concurrency is live, not structural-only.** `t1_2_concurrent_reentry` **PASS** (8
  concurrent reentrant `dispatch-outbound` calls all round-tripped — see A-FTN-018);
  `t1_3_no_head_of_line` **PASS** (fast.get p50 stable while a slow request is outstanding);
  `t2_1_sustained_load` **PASS** (C=16 × K=10000 = **160 000** gets, **zero drops**, p50
  stable across windows); `t2_2_connection_churn` **PASS** (100 connect→handshake→req→close
  cycles). `t1_1` demux is single-thread (no parallel speedup) but the §6.11(a) MUST is
  proven by `t1_3`.

### Non-gating WARN explained

- **`resource_bounds/r3_connection_flood` (SHOULD).** The net-shim admission cap is
  `EC_MAXCONN = 512`, above the probe's 256-connection burst — so the peer accepts all 256
  and **keeps serving** rather than refusing. A conformant SHOULD outcome (bound present,
  never falls over), reported as a WARN by design, not a FAIL.

### Auto-allowlisted skips (V7 v7.72 §9.0 extension carve-outs)

96 skips, all whole extension categories or extension-vocabulary legs outside `--profile
core`: `origination` (extension-only; reference-peer-gated — honest-SKIP in single-peer mode),
`subscriptions`, `continuations`, `role`, `attestation`, `quorum`, `identity`, `registry`,
`relay`, `local_files`, `compute`, `query`, EXTENSION-TREE §9 tree ops, extension handler
manifests, and the 2 `authz` legs that expect ROLE §5.5 vocabulary (`authz_delegate_grant_1`,
`authz_revoked_1`). None gate. **`dispatch-outbound` is NOT among these** — its core reentry
leg runs live under `concurrency.t1_2` (PASS); only the deeper `origination` category skips.

---

## S2 — codec (wire conformance) — GREEN

**Gate:** pinned v0.8.0 ECF corpus (`shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`),
**69 vectors — 69 pass / 0 fail / 0 skip.** **Reproduce:** `./run-s2.sh` → `make test`.
Codec compiles clean under `-std=f2018 -O2 -Wall -fimplicit-none -fcheck=bounds` (zero warns).

| Category | n | Result | Category | n | Result |
|---|---:|---|---|---:|---|
| float | 14 | ✅ | tag_reject | 5 | ✅ |
| int | 14 | ✅ | content_hash | 4 | ✅ |
| map_keys | 6 | ✅ | peer_id | 3 | ✅ |
| length | 8 | ✅ | signature | 3 | ✅ |
| primitive | 6 | ✅ | envelope | 2 | ✅ |
| nested | 4 | ✅ | **Total** | **69** | **✅ 69/0/0** |

The fixed-width SIGNED-ONLY probe closes as **corroboration**: `{0, 2⁶³-1, 2⁶³, 2⁶⁴-2,
2⁶⁴-1}` round-trip byte-exact — the unsigned tower carried as an explicit bit pattern in a
signed `integer(int64)` with the `ult()` bias compare, no side channel. FFI (`libentitycore_codec`)
bound **directly** via `iso_c_binding` (no C wrapper) for SHA-256/Ed25519/base58/content_hash.

---

## Regression floors (re-verified at S4 close)

- **S2 codec:** 69/69 (`./run-s2.sh`) — unaffected.
- **S3 peer:** offline self-test **18/18** + two-peer loopback smoke **5/5** (`./run-s3.sh`) —
  intact after the S4 net-shim (SIGPIPE), serve-loop, dispatch-outbound, and handshake-
  negotiation changes.

**Pins at S4:** oracle ref `cc1970f`, core-gate fingerprint `8261a033…` (matches
`tools/oracle-pin.env`); spec-data v0.8.0 SHA-256 pins unchanged from S2.
