# entity-core-protocol-cpp — Conformance Report

**Phase S4 (full peer)** · **Status: 🟢 GREEN — `validate-peer --profile core` → 665 total · 0 FAIL ·
Result: PASS** on the v7.77 oracle. **Phase S2 (codec)** · 🟢 GREEN — 69/69 wire-conformance,
byte-identical, ASan/LSan/UBSan-clean on g++ AND clang++ (below).

---

## S4 — full peer · `validate-peer --profile core` (v7.77 oracle `e8524ed`)

| Metric | Value |
|---|---|
| Oracle | `validate-peer` from `entity-core-go @ e8524ed` (pinned by `tools/oracle-pin.env`) |
| core_gate_sha256 | `e09a865ffea690ce207149eb68851f7afbc2fa3a9ba522a0ca9d9c72f9923308` — **matches the committed pin** |
| **Summary** | **665 total · 292 passed · 278 warned · 0 FAIL · 95 skipped** |
| **Result** | **PASS** (with warnings) |

Raw output: `status/CONFORMANCE-REPORT.json`. 665 / 0 FAIL is the current cohort floor on v7.77.

### Named gate checks (RELEASE-READINESS §4)

| Gate | Result |
|---|---|
| §10.1 core-register gate | **10/10** (9 `core_register_*` + `validate_echo_dispatch`, all PASS) |
| §10.2 origination-core (`run-origination-core.sh`, Go `entity-peer` reference) | **3/3** — `reference_connect` · `reference_ready` · **`dispatch_outbound_reentry`** PASS over real two-peer TCP |
| multisig | **11/11, 0 skip** — incl **`valid_2of3_peer_signed_accepted` PASS** (genuine K-of-N: `--name conformance` persistent identity → the validator co-signs as the peer → 200) |
| concurrency (§7b) | **5/5** PASS |
| resource_bounds (§4.10) | r1 `413` PASS · r2 `400 chain_depth_exceeded` PASS · r3 conn-flood WARN (SHOULD, external admission) |

### The one peer bug S4 found + fixed (A-CPP-014)

First run had **1 FAIL** (`core_tree_path_flex_1`): an embedded NUL in a resource target was
accepted (200) instead of rejected (`400 invalid_path`). `path_flex_ok()`'s length-comparison NUL
guard was a no-op (the wire target is length-prefixed text → the NUL survives into the `std::string`,
so `target.size()` already counts it). Fixed to scan bytes directly and reject any control byte
(`< 0x20` incl. NUL, plus `0x7f`) per §1.4 R1. Re-run → 0 FAIL, no regression on g++ or clang++.

### S4 scaffolding (no protocol logic)

`test/host.cpp` (the standalone host: `--port` / `--name` / `--debug-open-grants` / `--validate`),
`run-s4.sh` (the gate harness), `run-origination-core.sh` (the §10.2 probe) — all `--network=none`,
sealed offline. The reentry transport + §7a conformance handlers were already built at S3.

---

## S2 — codec layer · `wire-conformance` corpus

| Corpus | Vendored version | Result |
|---|---|---|
| ECF codec conformance (`conformance-vectors-v1.cbor`) | v7.71 (sha `41d68d2d…`) | **69/69 PASS, 0 FAIL** (64 encode_equal + 5 decode_reject; byte-identical) |
| S2 spike (float + map_keys), run FIRST | v7.71 | **20/20 PASS** (14 float + 6 map_keys), first run |
| Uncovered-range + crypto self-tests | n/a (in-repo) | **15/15 PASS** (u64/-2^64 range, float ladder, N1/N2, base58 RT, peer_id §1.5, Ed25519 RFC-8032) |
| **Harness total** | | **84 PASS / 0 FAIL** |

Built + run under `-fsanitize=address,undefined` (ASan/LSan/UBSan) via CTest — a leak / UAF /
overflow / UB is a test failure. Clean. Compiler flags: `-std=c++23 -Wall -Wextra -Werror
-pedantic` (zero warnings).

### Cross-compiler hygiene

| Compiler (over libstdc++ 15.2.1) | conformance | selftests |
|---|---|---|
| g++ 15.2.1 | 69/69 | 84/84 |
| clang++ 21.1.8 | 69/69 | 84/84 |

Both ASan/LSan/UBSan-clean. (The clang pass caught A-CPP-010 — a g++-only recursive-variant
portability slip — before it could ship.)

## Oracle / fixture provenance (what `wire-conformance` is here)

`wire-conformance` (Go, `cmd/internal/wire-conformance/`) is a fixture **producer + cross-blesser**:
its `build-fixture` subcommand translates the human `.diag` → the canonical-ECF `.cbor` the impls
load, and every `encode_equal` `canonical` field is the 3-way **Go × Rust × Python byte-equality
lock** (71/71, arch `specs/test-vectors/ecf-conformance/`, recorded in the v7.71 MANIFEST). This
peer decodes the fixture with its OWN decoder, runs each vector through the codec, and byte-compares
against the embedded `canonical`. **Byte-identity == oracle PASS.**

**Go oracle rebuilt + fixture regenerated (ground-truth provenance, S2 mandate).** Per the runbook
isolation rule, `git archive <go HEAD 71b6ba8> | tar -x` into a temp dir **OUTSIDE** the go repo,
built `wire-conformance` there (`GOWORK=off`, `CGO_ENABLED=0`, go-toolchain image), ran
`build-fixture` on the vendored `.diag` → the regenerated `.cbor` is **byte-identical** to the
vendored one (sha `41d68d2d…` match). So the 69/69 is against the live Go oracle's own canonical
emission. The go repo was untouched (clean, same HEAD — read-only confinement honored).

**Free cross-check (independent of the fixture).** Built the sibling C-ABI codec
`libentitycore_codec.so` (`entity-core-codec-ffi-c`) and ran a differential probe
(`test/ffi_xcheck.cpp`): **28/28 PASS** (14 entity-encode + 14 content_hash) over a battery
including the uncovered `[2^63, 2^64-1]` band and the float-ladder edges — two independent codecs
agree byte-for-byte. The C-ABI `ec_encode_ecf` takes `type` as raw UTF-8 + `data` as a pre-encoded
ECF value slice; the probe mirrors that exactly.

## The four hard ECF requirements (profile `[codec]`)

| Requirement | Where | Verified |
|---|---|---|
| (a) shortest-float / f16 minimization + 4 specials | `src/ecf.cpp` `enc_float` / `double_to_f16` | float.1–14 + f16_max/f32_not_f16/f64 selftests + spike |
| (b) length-first-then-bytewise (CTAP2) map ordering | `src/ecf.cpp` `key_order` (`std::sort`) | map_keys.1–6 (incl. mixed text/byte map_keys.5) |
| (c) recursive major-type-6 tag rejection (any depth) | `src/ecf.cpp` decode `case 6` | tag_reject.1–5 + bare-tag-55799 selftest |
| (d) byte-exact raw-slice RT + full uint64/nint head-form | `src/ecf.cpp` `Int` + native u64 | int.1–14 + u64_max/u63/nint_min selftests + FFI xcheck |

Plus N1 (varint format-codes via real LEB128, content_hash.4 fc=128 / peer_id.3 kt=128), N2 (tag
scanner, not library defaults), N3 (empty map = single byte `0xA0`, falls out of the generic
encoder), N4 (entity `data` = general value, not re-serialized).

## Container

`containers/cpp-toolchain/Containerfile` — fedora:43; clang/libcxx 21.1.8-4.fc43, ninja
1.13.1-4.fc43, gcc-c++/libstdc++ 15.2.1-7.fc43, cmake 3.31.11-1.fc43, libsodium 1.0.22-1.fc43, all
exact-pinned (S11 reviewed-distro-channel tier). Built with podman; all S2 builds/tests run
`--network=none` (fully offline — libsodium pre-installed, everything else hand-rolled in-repo).

## Verdict

S2 codec layer is **GREEN**: 69/69 wire-conformance byte-identical, confirmed against the live Go
oracle's own fixture emission and cross-checked against the sibling C-ABI codec, ASan/LSan/UBSan-
clean on two compilers. No blocking ambiguity. **Ready to gate S2 → S3.**
