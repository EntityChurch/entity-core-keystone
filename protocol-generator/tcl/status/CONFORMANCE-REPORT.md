<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-08) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 335 pass · 336 warn · 0 FAIL · 107 skip** (elapsed 13074 ms).
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

# entity-core-protocol-tcl — Conformance Report

## S2 — codec (wire conformance)

**Gate:** pinned v0.8.0 ECF corpus (`protocol-generator/shared/test-vectors/ecf-conformance/
conformance-vectors.cbor`), **69 vectors — 69 pass / 0 fail / 0 skip.**
**Reproduce:** `./run-s2.sh` (container-bound, `--network=none`) → `make test`.
**Container:** `entity-core-keystone/tcl-toolchain:latest` (Tcl 9.0.2, fedora:43).
**Crypto provenance (`ec_impl_info`):** `c 0.1.0 / ecf-c-abi 1.1 / libsodium 1.0.22`
(the codec C-ABI; SHA-256/384 + Ed25519 cross the shim, everything else is pure Tcl).

| Category | Vectors | Result | Path |
|---|---:|---|---|
| float (shortest-float ladder f16/f32/f64) | 14 | ✅ | pure Tcl |
| int (minimal head, uint64 boundary) | 14 | ✅ | pure Tcl (native bignum) |
| length (array/str/bytes boundaries) | 8 | ✅ | pure Tcl |
| map_keys (length-then-lex on encoded key bytes) | 6 | ✅ | pure Tcl |
| primitive (null/bool/empty) | 6 | ✅ | pure Tcl |
| nested (deep maps, entity carrier) | 4 | ✅ | pure Tcl |
| tag_reject (major-type-6 → reject) | 5 | ✅ | pure Tcl (N2) |
| envelope (root + included) | 2 | ✅ | pure Tcl |
| peer_id (base58 ‖ multi-byte varint) | 3 | ✅ | pure Tcl (N1) |
| content_hash (varint(fmt) ‖ SHA-256(ECF)) | 4 | ✅ | shim (SHA) |
| signature (Ed25519 of ECF bytes) | 3 | ✅ | shim (Ed25519) |
| **Total** | **69** | **✅ 69/0/0** | |

**Notable:** `content_hash.4` (synthetic `format_code = 128`, a two-byte LEB128 prefix)
**passes** — the pure-Tcl varint handles arbitrary codes, so no skip was needed
(COBOL honest-skipped this one). The byte-vs-text seam under EIAS (`map_keys.5`, a
byte-string key sorted against a text key) is byte-correct: the explicit tagged-value
representation carries the major type, resolving A-TCL-001 with no spec ambiguity.

### Codec-invariant coverage
- **N1** (varint framing, not fixed bytes): peer_id.3 + content_hash.4 (multi-byte codes).
- **N2** (recursive major-type-6 tag rejection): tag_reject.1–5 (incl. deep-nested).
- **N3** (empty map/params = single byte `0xA0`): length.2 + primitive.6.
- Full-consume (no trailing data) + minimal-head re-validation enforced on decode.

## S3 — live peer (two-peer loopback smoke)

**Gate:** the peer-layer foundation self-test (**26/26**) + the two-peer loopback
smoke (**12/12**) — full §6.5 dispatch chain over real loopback TCP on ONE
`chan event`/`vwait` event loop. **Reproduce:** `./run-s3.sh` (`--network=none`).
Covers: §4.1 handshake · 404 · authority-gated tree get · capability request ·
8-way `request_id` demux (N7/§6.11) · register live-hook (§6.13(a)) · emit hook
(§6.13(c)) · §7a echo · §6.11 dispatch-outbound reentry (nested `vwait`).
See `PHASE-S3.md`.

## S4 — validate-peer `--profile core`

**Gate:** `validate-peer --profile core` against oracle **`cc1970f`** — measured
**natively** in-container, sealed-offline (`--network=none`; oracle + peer share one
loopback). **Result: PASS — `682 · 0F`** (292 P / 294 W / 0 **F** / 96 S).
**Reproduce:** `./run-s4.sh` (peer launched via `bin/peer.tcl --name conformance
--debug-open-grants --validate`). Report: `status/CONFORMANCE-REPORT.json`.

| Category | P | W | F | S | Note |
|---|---:|---:|---:|---:|---|
| connectivity | 22 | 0 | 0 | 0 | handshake, framing, hello/authenticate |
| encoding | 6 | 0 | 0 | 0 | wire canonicality |
| type_system | 108 | 292 | 0 | 0 | 53-type floor byte-exact; **all 292 W = extension types absent** (not-a-FAIL-if-absent), **0 mismatch** |
| handlers | 35 | 0 | 0 | 32 | core handler gates; extension ops SKIP |
| capability | 12 | 0 | 0 | 0 | §5 verdicts |
| tree_operations | 24 | 1 | 0 | 31 | 1 W = non-critical cleanup |
| security | 28 | 0 | 0 | 1 | |
| **multisig** | **11** | 0 | 0 | 0 | **genuine K-of-N — `valid_2of3_peer_signed_accepted` PASSED** (peer co-signed) |
| concurrency | 5 | 0 | 0 | 0 | §7b structural (single event thread) |
| resource_bounds | 2 | 1 | 0 | 0 | 1 W = §4.10(c) connection admission delegated externally (SHOULD) |
| authz | 6 | 0 | 0 | 2 | |
| universal_address_space / peer_canonicalization / format_agility / crypto_agility / negotiation | 33 | 0 | 0 | 0 | agility + addressing |
| (extension categories) | 0 | 0 | 0 | ~62 | §9.0 carve-out — auto-allowlisted skips |
| **Total** | **292** | **294** | **0** | **96** | **0-FAIL gate MET** |

**Reading the number:** the `682` total is a **fresh** `cc1970f` measurement (COBOL
is the other natively-measured peer; the 21 others carry `665` from the retired
`e8524ed` build — totals are non-gating and vary by oracle build, see
`CONFORMANCE-MATRIX.md`). What is certified is the **`--profile core` 0-FAIL gate**.
The 294 warnings are all non-gating: **292** are the oracle probing for
extension/`compute/*` types a core peer intentionally does NOT publish
("matched-if-present … not-a-FAIL-if-absent") — **zero** are byte-mismatch, so every
published floor type renders byte-identical to the oracle (render-from-model, 0
drift); **2** are SHOULD-level notes (connection admission delegated externally; a
non-critical tree cleanup).

**EIAS probe verdict:** no spec-precision finding — clean corroboration end to end.
