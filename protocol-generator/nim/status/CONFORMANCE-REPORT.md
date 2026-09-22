<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-16) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 336 pass · 335 warn · 0 FAIL · 107 skip** (elapsed 2537 ms).
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

# entity-core-protocol-nim — Conformance Report

## S4 — live peer · `validate-peer --profile core` → **PASS (293·0F, 0 FAIL)**

**Score:** **293·0F @ cc1970f** — **293 P / 293 W / 0 F / 96 S** (682 total, ~27s).
**Oracle:** `output/s4-oracles/validate-peer` from `entity-core-go` HEAD **`cc1970f`**,
core-gate fingerprint **`8261a033…`** (cohort-certified; not rebuilt, not doctored).
**Host:** `--port 7788 --name conformance --debug-open-grants --validate` (§7a ON),
peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (fixed seed `0x11×32`).

### `--profile core` scoreboard (VALIDATE=1)

| Category | P / W / F / S |
|---|---|
| connectivity | 22 / 0 / 0 / 0 ✅ |
| encoding | 6 / 0 / 0 / 0 ✅ |
| type_system | 108 / 292 / 0 / 0 ✅ |
| handlers | 35 / 0 / 0 / 32 ✅ |
| capability | 12 / 0 / 0 / 0 ✅ |
| tree_operations | 25 / 0 / 0 / 31 ✅ |
| security | 28 / 0 / 0 / 1 ✅ |
| multisig | 11 / 0 / 0 / 0 ✅ |
| concurrency | 5 / 0 / 0 / 0 ✅ |
| resource_bounds | 2 / 1 / 0 / 0 ✅ (r1 413, r2 400, r3 flood WARN) |
| universal_address_space | 8 / 0 / 0 / 0 ✅ |
| peer_canonicalization | 7 / 0 / 0 / 0 ✅ |
| format_agility | 10 / 0 / 0 / 0 ✅ |
| crypto_agility | 4 / 0 / 0 / 0 ✅ |
| negotiation | 4 / 0 / 0 / 0 ✅ |
| authz | 6 / 0 / 0 / 2 ✅ |
| *(24 extension-only categories)* | 0 / 0 / 0 / 1 each — auto-skipped |

**Total: 293 PASS · 293 WARN · 0 FAIL · 96 SKIP.**

### The 293 WARN are non-gating
292 are `type_system` non-floor type vocabulary — the `compute/*` extension types the
validator probes but a **core** peer does not publish (`matched-if-present`, WARN by
design). 1 is `resource_bounds.r3_connection_flood` (§4.10(c) **SHOULD** admission bound;
the peer survives 256 conns and serves the follow-up probe — WARN, not FAIL).

### The 96 SKIP are all §9.0 extension carve-outs — 0 need manual allow-listing
The oracle auto-allowlists every skip under `--profile core` (`96 skip(s) auto-allowlisted
by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate`; there is **no** `N skip(s)
count as FAIL` line). They are whole extension categories (subscriptions, continuations,
revision, clock, history, query, local_files, compute, entity_native, origination,
attestation, quorum, identity, role, durability, content, session, relay, registry,
discovery, encryption, …) plus the EXTENSION-TREE §9 ops inside `tree_operations` (snapshot
/ diff / extract / merge / roundtrip / tracked → `501` → skip) and the extension checks in
`handlers` / `security` / `authz`. **None masks a missing core primitive.**

### Multisig accept-path (the "conformance-green can be vacuous" guard)
- **Live:** `multisig.valid_2of3_peer_signed_accepted` **PASS** — the oracle co-signs AS
  the peer (keypair at `~/.entity/peers/conformance/keypair`) and a genuine 2-of-3 quorum
  capability is **ACCEPTED** (§5.5 M4/M6), not env-skipped. All 11 `multisig` checks pass.
- **Unit (oracle-free):** `tests/tmultisig.nim` — 4/4 OK: 2-of-3 ACCEPTED; 1-of-3 REJECTED;
  `threshold<2` REJECTED (M3); local peer not in quorum REJECTED (M6). Drives the accept
  direction the rejection-heavy oracle category cannot.

### Origination-core (`run-origination-core.sh`, Go reference B-role)
**3 / 3 PASS** with the Go `entity-peer` reference on `:7789`: `reference_connect` ·
`reference_ready` · **`dispatch_outbound_reentry`** — the Nim target originates an outbound
EXECUTE back to the validator-as-B over the SAME inbound connection (§6.11 reentry: the
transport `io.pending` request_id demux + the `OutboundSender` closure into
`peer.validateDispatchOutbound`). A single-peer `run-s4` honest-SKIPs these.

### §7a conformance handlers (--validate)
`handlers.validate_echo_dispatch` **PASS** (§7a.1 verbatim echo);
`concurrency.t1_2_concurrent_reentry` **PASS** (8 concurrent reentrant dispatch-outbound,
per-call value-matched — a genuine accept path).

### Reproduce
```
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/nim-toolchain:latest sh /work/protocol-generator/nim/run-s4.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/nim-toolchain:latest sh /work/protocol-generator/nim/run-origination-core.sh
```

---

## S2 — codec layer · `wire-conformance` → **PASS (71/71)**

**Corpus:** `conformance-vectors` (v0.8.0 / V8; sha256
`9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc`, the F29/F30
re-vendor, 71 vectors). **Result: 71 / 71 PASS, 0 FAIL.** **First compile-run, 0
codec fixes.**

Run in-container, sealed offline (`--network=none`; the core floor is libsodium +
hand-rolled Nim only — no nimble registry deps):

```
sh protocol-generator/nim/run-wire-conformance.sh
# = podman run $PODMAN_RUN_CAPS --rm --network=none -v $PWD:/work:Z \
#     -w /work/protocol-generator/nim entity-core-keystone/nim-toolchain:latest \
#     nim c -r --mm:orc --overflowChecks:on -d:release --hints:off \
#       -o:/tmp/tconformance tests/tconformance.nim \
#       /work/protocol-generator/shared/test-vectors/ecf-conformance/conformance-vectors.cbor
```

## Scoreboard (byte-identity vs the cross-blessed fixture)

| Category | Pass | Kind |
|---|---|---|
| float        | 14/14 | encode_equal (f16/f32/f64 shortest-float + specials) |
| int          | 14/14 | encode_equal (uint/nint minimisation to 2^63-1) |
| map_keys     |  6/6  | encode_equal (length-then-lex on encoded key bytes) |
| length       |  8/8  | encode_equal (definite-length only) |
| primitive    |  6/6  | encode_equal (bool/null/empty; N3 empty-map = 0xA0) |
| nested       |  6/6  | encode_equal (entity + envelope shapes + F29 text-head boundary) |
| tag_reject   |  5/5  | decode_reject (recursive major-type-6 rejection, N2) |
| content_hash |  4/4  | encode_equal (varint(fc) ‖ SHA256(ECF); multi-byte fc 128) |
| peer_id      |  3/3  | encode_equal (Base58(varint‖varint‖digest); multi-byte key_type) |
| signature    |  3/3  | encode_equal (deterministic Ed25519 over canonical ECF) |
| envelope     |  2/2  | encode_equal (root + hash-keyed included map) |
| **TOTAL**    | **71/71** | |

## Mandatory fixed-width head-form self-test (A-NIM-002)

`[2^63, 2^64-1]` round-trip — **PASS**. Carrier is native **`uint64`** (NOT a
signed int64, which would silently overflow this band). Proven twice:

- **compile time** — a `static:` block in `src/ecf.nim` executes the encoder in
  the Nim VM over `2^63`, `2^64-1`, and `nint(2^64-1) = -(2^64)`; a build is only
  possible if those compile-time asserts hold (the profile's
  compile-time-metaprogramming axis, doubling as the fixed-width proof).
- **run time** — `tests/tconformance.nim` encodes + decodes + re-encodes `2^63`,
  `2^64-2`, `2^64-1`, and `nint(2^64-1)`, asserting byte-identity each way.

Build flags `--overflowChecks:on` are on for conformance; every decoder length
read is explicitly bound-checked before the read (unsigned wraps silently).

## Notes

- **Native codec, no FFI for the canonical layer** — hand-rolled ECF in
  `src/ecf.nim` (A-NIM-001 confirmed; the `ffi` fallback was NOT needed). The
  head emission + major-type selection are `template`s the compiler inlines
  (zero runtime reflection).
- **Crypto floor via native libsodium `{.importc.}` interop** (A-NIM-003
  confirmed) — `crypto_hash_sha256` (content_hash) and
  `crypto_sign_seed_keypair` + `crypto_sign_detached` (deterministic Ed25519,
  signature vectors) link statically against fedora's libsodium in-container. Nim
  compiles to C, so this is in-process, not a foreign bridge.
- **Ed448 / SHA-384 NOT covered** — agility higher-bar only (A-NIM-004, deferred).
  The 71-vector ECF floor (Ed25519 + SHA-256) is complete; content_hash.4's
  format_code 128 still hashes SHA-256, so libsodium's lack of high-level SHA-384
  does not gate S2.
- **Cohort-consistent, not independent convergence** (ADR-0012): a Nim peer
  passing the author's vectors shares the keystone generation lineage; this is a
  corroboration / generator-robustness result, not a clean-room second source.

## Reproduce

Container image (built + verified at S2, A-NIM-005):

```
. tools/podman-caps.sh
podman build $PODMAN_BUILD_CAPS -t entity-core-keystone/nim-toolchain:latest \
  -f containers/nim-toolchain/Containerfile .
# Nim 2.2.2 tarball sha256 pinned + verified against nim-lang.org/download AND
# its published .sha256 sidecar: 7fcc9b87…8a1f
```

Gate:

```
sh protocol-generator/nim/run-wire-conformance.sh   # -> 71/71, exit 0
```
