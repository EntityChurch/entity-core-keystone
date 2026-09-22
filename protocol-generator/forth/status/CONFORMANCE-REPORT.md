<!-- current-pin-banner:95edd774f4a2 -->
> **CURRENT (2026-08-28) — spec snapshot `v0.8.2`, executed check set `95edd774f4a2…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **755 total · 312 pass · 337 warn · 0 FAIL · 106 skip** (elapsed 13689 ms).
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

# entity-core-protocol-forth — Conformance Report

## S2 — codec (wire conformance)

**Gate:** pinned v0.8.0 ECF corpus (`protocol-generator/shared/test-vectors/v0.8.0/
conformance-vectors-v1.cbor`), **69 vectors — 69 pass / 0 fail / 0 skip.**
**Reproduce:** `./run-s2.sh` (container-bound, `--network=none`) → `make test` (corpus) +
`make int-boundary` (uint64 boundary self-test) + `make crypto-accept` (crypto accept-path).
**Container:** `entity-core-keystone/forth-toolchain:latest` (gforth 0.7.3, fedora:43).
**Crypto provenance (`crypto-impl-info` → `ec_impl_info`):**
`c 0.1.0 / ecf-c-abi 1.1 / libsodium 1.0.22` — SHA-256/384 + Ed25519 cross the C-ABI via
gforth's IN-PROCESS libcc `c-function` (a genuine libffi binding — no subprocess / FIFO /
co-process); everything else is pure Forth.

| Category | Vectors | Result | Path |
|---|---:|---|---|
| float (shortest-float ladder f16/f32/f64) | 14 | PASS | pure Forth — **f32/f64 from native IEEE bits (`SF!`/`DF!`); f16 leg + ladder hand-rolled bit arithmetic** |
| int (minimal head, uint64 boundary) | 14 | PASS | pure Forth (fixed-width 64-bit cell; mt0/mt1 magnitude as an UNSIGNED cell) |
| length (array/str/bytes boundaries) | 8 | PASS | pure Forth |
| map_keys (length-then-lex on encoded key bytes) | 6 | PASS | pure Forth |
| primitive (null/bool/empty) | 6 | PASS | pure Forth |
| nested (deep maps, entity carrier) | 4 | PASS | pure Forth |
| tag_reject (major-type-6 → reject at any depth) | 5 | PASS | pure Forth (N2, recursive scanner) |
| envelope (root + included) | 2 | PASS | pure Forth |
| peer_id (base58 ‖ multi-byte varint) | 3 | PASS | pure Forth (N1, base58 byte-array long division) |
| content_hash (varint(fmt) ‖ SHA-256/384(ECF)) | 4 | PASS | FFI (SHA) + pure-Forth ECF |
| signature (Ed25519 of ECF bytes) | 3 | PASS | FFI (Ed25519) + pure-Forth ECF |
| **Total** | **69** | **PASS 69/0/0** | |

**Notable:** the FLOAT tower is materially easier than Rexx's (which computed every IEEE
bit in decimal): gforth's FP wordset yields real IEEE-754 f64/f32 bits via `DF!`/`SF!`, so
f32/f64 assembly is native; only the f16 half-float leg + the shortest-form ladder are
hand-rolled bit arithmetic, operating on those real bits. `content_hash.4` (synthetic
`format_code = 128`, a two-byte LEB128 prefix) **passes** (COBOL honest-skipped it). The
crypto binding is the cleanest in the FFI-hybrid family — an in-process libffi call, no
process boundary.

### Codec-invariant coverage (N1–N4)
- **N1** (varint framing, not fixed bytes): `peer_id.3` (key_type 128) + `content_hash.4`
  (format_code 128) both carry a real 2-byte LEB128 code; `varint-encode`/`varint-decode`
  are the primitives (`src/varint.fs`). Direct proof: `varint(128) = 80 01` in
  `test/crypto-accept.fs`'s provenance probe / harness.
- **N2** (recursive major-type-6 tag rejection): `tag_reject.1–5` — the decoder checks
  `major == 6` at **every** node (`dec-node-impl`), so a tag nested inside an included
  entity's data (`tag_reject.5`) and the wire self-describe tag `d9d9f7` (`tag_reject.4`)
  are both rejected. Never stripped / interpreted.
- **N3** (empty map/params = single byte `0xA0`): `length.2` encodes `{}` → `A0`;
  `content_hash.1` (empty-data entity `{type,data:{}}`) hashes to the pinned
  `005f3139…0ca396b`. Both green.
- **N4** (entity fidelity — forward original bytes, never re-serialize): satisfied at the
  codec surface — `cbor-decode` reads from a caller-held wire span (`din-addr`/`din-len`
  never mutate the input) and produces a separate TV, so the caller retains the exact
  original bytes to forward. The S3 peer forwards those, never a re-encode.
- Full-consume (trailing data rejected) + minimal-head re-validation enforced on decode.

### The stack-machine idiom verdict (A-FT-000)
The recursive canonical-CBOR encoder/decoder reads as **native Forth**, not translated —
see `PHASE-S2.md` for the verdict and the two idioms that made it work (an arena/HERE-style
byte builder returning `(c-addr u)` spans, and locals as the escape hatch where a stack
effect would exceed ~3 items). Two genuine Forth-substrate gotchas surfaced and were fixed
(the `>r`/`?do`/`r@` return-stack collision; the `1 0 ?do` counted-loop wrap on empty
maps) — banked in `SPEC-AMBIGUITY-LOG.md` as A-FT-010/011.

## S3 — live peer

✅ **COMPLETE — foundation self-test 20/20 + two-peer loopback smoke 6/6 (0 fail).**
Reproduce `./run-s3.sh`. Single-thread select-pump peer, IN-PROCESS sockets + crypto (no
co-process daemon — the COBOL/Tcl native shape, A-FT-008); §6.5 dispatch, §5 capability
scaffold, §4.10(a)/(b) floor, §6.11 reentry pump. Details in `PHASE-S3.md`.

## S4 — validate-peer `--profile core`  ✅ **COMPLETE — Result: PASS**

✅ **`Result: PASS` — 0 FAIL, 0 fail-counting skips.** Oracle `validate-peer` @ **`cc1970f`**
(core-gate fingerprint `8261a033…`; vectors confirmed compiled). Reproduce `./run-s4.sh`
(container-bound, `--network=none`).

**`--profile core`: `682 total · 291 pass · 295 warn · 0 FAIL · 96 skip`** @ `cc1970f`
(peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`; all 96 skips are §9.0 auto-allowlisted
extension carve-outs — none count as FAIL). This is **exact cohort parity with the Rexx peer**
(#24: `682·0F`, 291 pass / 295 warn / 96 skip @ `cc1970f`). Full per-check JSON:
`CONFORMANCE-REPORT.json`.

| Gate leg | Result |
|---|---|
| connectivity / encoding / negotiation / crypto_agility / format_agility | ✅ all PASS |
| type_system (render-from-model 53-type §9.5 floor + listing) | ✅ 108 pass / 0 FAIL |
| multisig — genuine 2-of-3 peer-co-signed accept (`valid_2of3_peer_signed_accepted`) | ✅ 11/11 (M3+M4+M6) |
| authz (grantee-401 / no-catchall-403 / deny-default / expiry / revoked) | ✅ all PASS |
| security (author + signer==author + tamper + resource-scope + caveats + xpeer) | ✅ all PASS |
| capability (request / configure / revoke / scope-widening-403 / revoked-denied) | ✅ all PASS |
| **handlers `core_register_*`** (register/unregister 5-write protocol + teardown) | ✅ 8/8 (A-FT-024) |
| **handler dispatch entities** (connect/tree/capability `_dispatch_type`/`_interface_ref`) | ✅ PASS |
| **revoked-cap-denied** (authz + capability) | ✅ PASS (A-FT-023 re-enabled + fixed) |
| tree_operations (`path_root_listing`, `core_tree_path_flex_1` NUL + leading-slash) | ✅ PASS (A-FT-027) |
| universal_address_space (foreign-namespace `/*/*` grants) | ✅ 8/8 (A-FT-026 seed) |
| **concurrency `t1_2_concurrent_reentry`** (§6.11(b) demux, no cross-talk) | ✅ PASS (A-FT-025) |
| concurrency `t1_3`/`t2_1`/`t2_2` (head-of-line / sustained load / churn) | ✅ PASS |
| resource_bounds `r3` (§4.10(c) admission) | ✅ WARN (A-FT-028) |
| Origination-core §10.2 `dispatch_outbound_reentry` (Go peer as B) | ✅ **3/3** |
| §4.10(a) 413 / §4.10(b) chain-depth 400 | ✅ PASS |

The oracle was never doctored, no vector relaxed, no category marked-skipped to dodge a red — the
one disabled check the prior agent left (`cap-revoked?`, A-FT-023) was **RE-ENABLED and its root
cause fixed** (a `created_at:0` token-hash collision), not left off. Every finding is a CODE bug in
the generated peer, fixed here (no spec-vs-oracle divergence surfaced). The S4 findings:
A-FT-017–022 (prior legs), **A-FT-023** (revocation `created_at:0` collision — re-enabled+fixed),
**A-FT-024** (handlers register/unregister 5-write protocol), **A-FT-025** (the concurrency payoff —
a latent `pend-new` missing-return that only concurrent reentry exposed, + the codec depth-cap +
enlarged-stack + 8-MiB-arena robustness fixes), **A-FT-026** (§5.2 resource-scope + §5.7 caveats +
mint-attenuation), **A-FT-027** (§1.4 NUL/leading-slash path-flex), **A-FT-028** (§4.10(c) conn-table
sizing) — see `PHASE-S4.md` + `SPEC-AMBIGUITY-LOG.md`.
