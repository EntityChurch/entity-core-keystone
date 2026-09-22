<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-08) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 334 pass · 337 warn · 0 FAIL · 107 skip** (elapsed 186342 ms).
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

# entity-core-protocol-rexx — Conformance Report

## S2 — codec (wire conformance)

**Gate:** pinned v0.8.0 ECF corpus (`protocol-generator/shared/test-vectors/ecf-conformance/
conformance-vectors.cbor`), **69 vectors — 69 pass / 0 fail / 0 skip.**
**Reproduce:** `./run-s2.sh` (container-bound, `--network=none`) → `make test`.
**Container:** `entity-core-keystone/rexx-toolchain:latest` (Regina Rexx 3.9.6, fedora:43).
**Crypto provenance (`Crypto_ImplInfo` → `ec_impl_info`):**
`c 0.1.0 / ecf-c-abi 1.1 / libsodium 1.0.22` — SHA-256/384 + Ed25519 cross the C-ABI
via the `eccrypto` helper binary over a hex stem-pipe; everything else is pure Rexx.

| Category | Vectors | Result | Path |
|---|---:|---|---|
| float (shortest-float ladder f16/f32/f64) | 14 | ✅ | pure Rexx — **fully hand-rolled IEEE bits in decimal** |
| int (minimal head, uint64 boundary) | 14 | ✅ | pure Rexx (D2C/C2D big-endian, decimal bignum) |
| length (array/str/bytes boundaries) | 8 | ✅ | pure Rexx |
| map_keys (length-then-lex on encoded key bytes) | 6 | ✅ | pure Rexx |
| primitive (null/bool/empty) | 6 | ✅ | pure Rexx |
| nested (deep maps, entity carrier) | 4 | ✅ | pure Rexx |
| tag_reject (major-type-6 → reject) | 5 | ✅ | pure Rexx (N2) |
| envelope (root + included) | 2 | ✅ | pure Rexx |
| peer_id (base58 ‖ multi-byte varint) | 3 | ✅ | pure Rexx (N1) |
| content_hash (varint(fmt) ‖ SHA-256(ECF)) | 4 | ✅ | helper (SHA) |
| signature (Ed25519 of ECF bytes) | 3 | ✅ | helper (Ed25519) |
| **Total** | **69** | **✅ 69/0/0** | |

**Notable:** the FLOAT tower is the deepest hand-roll in the cohort — Rexx has no IEEE
float type and no built-in to read/write IEEE bits, so every f16/f32/f64 encode/decode
and every shortest-form decision is computed in decimal arithmetic (`%`/`//`/`*2**k`
+ `D2C`). `content_hash.4` (synthetic `format_code = 128`, a two-byte LEB128 prefix)
**passes** (COBOL honest-skipped it). The decimal-number-model probe (A-RX-002) closes
as **corroboration, no spec defect** — the spec is tight enough to force even a
substrate with no binary numeric type to carry the binary int + IEEE float towers
exactly.

### Codec-invariant coverage
- **N1** (varint framing, not fixed bytes): peer_id.3 + content_hash.4 (multi-byte codes).
- **N2** (recursive major-type-6 tag rejection): tag_reject.1–5.
- **N3** (empty map/params = single byte `0xA0`): length + primitive.
- Full-consume (no trailing data) + minimal-head re-validation enforced on decode.

## S3 — live peer

✅ **COMPLETE — two-peer loopback smoke 8/8 + foundation self-test 31/31 (0 fail).**
Reproduce `./run-s3.sh`. Peer machinery (single-thread select-pump over the `ecnet`
co-process daemon; §6.5 dispatch, §5 capability, store) — a port of the language-agnostic
protocol layers. Details in `PHASE-S3.md`.

## S4 — validate-peer `--profile core`

✅ **COMPLETE — Result: PASS, 0 FAIL.** Oracle `validate-peer` @ **`cc1970f`** (core-gate
fingerprint `8261a033…`; `valid_2of3_peer_signed_accepted` accept-path vector verified).
Reproduce `./run-s4.sh` (container-bound, `--network=none`).

**`--profile core`: 682 total · 291 pass · 295 warn · 0 FAIL · 96 skip** — all 96 skips
auto-allowlisted by the V7 v7.72 §9.0 carve-out (**0 fail-counting skips**). peer_id
`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`.

| Gate leg | Result |
|---|---|
| Every gated core category | ✅ 0 FAIL |
| §6.11 concurrency (`t2_1` 10k-req sustained, `t2_2` churn, `t1_2/t1_3`) | ✅ PASS (`t1_1` single-thread WARN) |
| Multisig accept path (`valid_2of3_peer_signed_accepted`) | ✅ genuine (peer co-signs) |
| §4.10(a) 413 / §4.10(b) chain-depth 400 | ✅ PASS + keeps serving |
| §4.10(c) connection flood (`r3`) | ⚠️ external-delegation WARN (SHOULD, not gated) |
| Origination-core §10.2 (`run-origination-core.sh`, Go peer as B) | ✅ 3/3 — `dispatch_outbound_reentry` live |

The 295 warns are non-gating (292 `type_system` render-native informational). Two genuine
§4.9/§4.10 resilience findings surfaced + fixed at S4 (A-RX-014 unbounded signature ingest;
§4.10(c) admission cap) — see `PHASE-S4.md` + `SPEC-AMBIGUITY-LOG.md`.
