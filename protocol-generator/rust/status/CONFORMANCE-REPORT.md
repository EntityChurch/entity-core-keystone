# entity-core-protocol-rust — S4 Conformance Report

**Result: `validate-peer --profile core` = PASS — `665 total · 0 FAIL @ e8524ed`,
machine-verified `summary.failed == 0`.** All 16 core-profile categories 0-FAIL.
multisig **11/11, 0 skip** (accept-path PASS). origination-core **3/3** over real
two-peer TCP. The peer code was not changed at S4 (S3 already published the §9.5 floor
+ wired the full surface) — and the oracle was never doctored (S5 line held).

| Field | Value |
|---|---|
| Gate | `validate-peer --profile core` → **PASS**, `failed == 0` (JSON-verified) |
| Total at this oracle | **665 · 0 FAIL @ e8524ed** (292 pass · 268 warn · 93 skip) — counts are oracle-version-specific; record as `N·0F @ <commit>` |
| Oracle | go `validate-peer` + `entity-peer`, entity-core-go commit **`e8524ed`** ("validate: multisig accept-path check") |
| Peer addr / id | `127.0.0.1:7777` · `--name conformance` → peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (deterministic seed `0x11`×32) |
| Toolchain | `entity-core-keystone/rust-toolchain:latest` — fedora:43, rust/cargo 1.96.0-1.fc43; each run `--network=none` (netns-isolated) |
| Harness | `run-s4.sh` (single-peer gate) · `run-origination-core.sh` (reference-peer-gated) |
| Iteration count | **0 peer-code changes** — green on first oracle run (the S3 §9.5 registry + full surface carried it) |

## The 16 core-profile categories — all 0-FAIL

| Category | Pass | Warn | Fail | Skip | Notes |
|---|---|---|---|---|---|
| connectivity | 22 | 0 | **0** | 0 | |
| encoding | 6 | 0 | **0** | 0 | |
| type_system | 108 | 262 | **0** | 0 | 53-type §9.5 floor PASS; non-floor type vocab WARN (matched-if-present) |
| handlers | 35 | 0 | **0** | 32 | incl. **§10.1 register 13/13 PASS** (register req/result match + body-binding + manifest/handler/grant-at-path + unregister); ext handler checks auto-skip |
| capability | 12 | 0 | **0** | 0 | §5 chain-walk + attenuation + verdict trichotomy + §4.10(a)/(b) bounds |
| tree_operations | 24 | 1 | **0** | 31 | core get/put/list/connect; EXTENSION-TREE §9 ops auto-skip |
| security | 28 | 0 | **0** | 1 | (1 skip = ext-routed cross-peer cap path, §9.0 carve-out) |
| **multisig** | **11** | 0 | **0** | **0** | §3.6 K-of-N — incl. `valid_2of3_peer_signed_accepted` PASS (oracle co-signs AS the peer) |
| negotiation | 4 | 0 | **0** | 0 | §4.5 keytype accept-set |
| crypto_agility | 4 | 0 | **0** | 0 | |
| format_agility | 10 | 0 | **0** | 0 | |
| peer_canonicalization | 7 | 0 | **0** | 0 | §1.4 |
| universal_address_space | 8 | 0 | **0** | 0 | |
| authz | 6 | 0 | **0** | 2 | (2 skip = ROLE/SUBSCRIPTION-ext-routed, §9.0 carve-out; core `authz_*_core_1` PASS) |
| **concurrency** | **5** | 0 | **0** | 0 | §7b store-safety + resilience (T2.1/T2.2) under sustained load |
| **resource_bounds** | **2** | **1** | **0** | 0 | r1 payload→`413` MUST PASS · r2 chain-depth→`400 chain_depth_exceeded` MUST PASS · r3 conn-flood→WARN (SHOULD) |

16 core-active categories; **0 FAIL across every one.** The 93 skips are the §9.0
extension-carve-out categories the oracle auto-allowlists under `--profile core`
(published_root / registry / discovery / relay / subscriptions / continuations /
role / quorum / attestation / local_files / … — whole extension categories, exempt
from the FAIL gate). 268 warns are the non-§9.5-floor type vocabulary (matched-if-present)
+ 1 tree_operations + 1 resource_bounds SHOULD — all non-blocking.

## multisig — 11/11, 0 skip (the accept-path is the hard part)

```
PASS valid_2of3_peer_signed_accepted   peer authorized a valid 2-of-3 multi-sig cap it co-signed (M4 quorum + M6 root)
PASS non_null_parent_rejected          PASS threshold_zero_rejected        PASS threshold_one_rejected
PASS threshold_exceeds_n_rejected      PASS duplicate_signers_rejected     PASS n_equals_one_rejected
PASS local_not_in_signers_rejected     PASS below_threshold_rejected
PASS precedence_m3_beats_missing_sigs  PASS precedence_m3_beats_invalid_sigs
```

The positive accept-path is **not env-skipped**: `run-s4.sh` provisions the peer's
persistent keypair at `~/.entity/peers/conformance/keypair` (entity-core PEM = base64 of
the 32-byte seed `0x11`×32) and starts the host `--name conformance`, so the oracle's
`crypto.LookupKeypairByPeerID` finds the peer's key and co-signs a genuine 2-of-3 quorum
AS the peer (deterministic peer_id `2KHoAk…`). The peer's §3.6 root then verifies M3
structure → M6 local-in-quorum → M4 distinct-signer threshold and ALLOWs. A skip would
**not** have been a pass.

## origination-core — 3/3 over real two-peer TCP

```
PASS reference_connect          PASS reference_ready
PASS dispatch_outbound_reentry  GUIDE-CONFORMANCE §7a.1 + §7a.2a; PROPOSAL v7.74 §10.2
Summary: 3 total, 3 passed, 0 warned, 0 failed, 0 skipped — Result: PASS
```

`run-origination-core.sh`: Rust target (A-role, `--validate`) on :7777 + a Go `entity-peer
--open-access` reference (B-role) on :7778, both in the rust-toolchain container,
sealed-offline (`--network=none`). The oracle mints a reentry capability, EXECUTEs
`system/validate/dispatch-outbound` on the Rust target, and the target originates an
outbound EXECUTE **back to the validator-as-B over the SAME inbound connection** (§6.11
reentry via the transport.rs reader-demux + §6.13(b) OutboundFn seam — NOT a fresh dial to
the reference). Without `--validate` this probe honest-SKIPs (which is why the single-peer
`run-s4.sh` reports `origination` as SKIP); under `run-origination-core.sh` it runs live.

## Oracle build isolation (hard rule, followed)

Vendored the committed snapshot **`e8524ed`** via
`git -C ~/projects/[internal]/[internal]/entity-core-go archive e8524ed
| tar -x -C $(mktemp -d /tmp/oracle-vendor-rust.XXXXXX)` into a temp dir **OUTSIDE**
`entity-core-go`; removed the vendored `mise.toml` (host go shim trips on it); built
`validate-peer` + `entity-peer` from that temp tree (multi-module go.work — cmd/core/ext)
with `GOWORK=<temp>/go.work`, `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, and
`GOCACHE`/`GOPATH`/`-o` on temp/output mounts → statically-linked ELFs in the gitignored
`output/s4-oracles/`. The oracle tree's `git status -s` was **empty before AND after** the
build — no binary, cache, or artifact leaked into `entity-core-go`. Required symbols
verified present in the built `validate-peer`: `resource_bounds`, `concurrency`,
`valid_2of3_peer_signed_accepted`, `dispatch_outbound_reentry`, `reference_{connect,ready}`,
`payload_too_large`, `chain_depth_exceeded`.

## Exit criteria

`validate-peer --profile core` = PASS (0 FAIL, JSON-`summary.failed==0`-verified) · all 16
core categories 0-FAIL (incl. resource_bounds, concurrency, §10.1 register 13/13) · multisig
11/11, 0 skip, accept-path PASS · origination-core 3/3 incl. dispatch_outbound_reentry over
real TCP · oracle build isolated (tree clean before+after) · ambiguity log updated
(A-RUST-008). **S4 PASS — nothing blocking S5 (publish).**

---

# entity-core-protocol-rust — S2 Conformance Report

**Result: 69 / 69 PASS, 0 FAIL.** Byte-identical against the Go `wire-conformance`
oracle over the full v1 ECF conformance corpus.

| Field | Value |
|---|---|
| Impl | `core-rust` (`entity-core-protocol-rust` 0.1.0-pre) |
| Corpus | `shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor` (v1, 69 vectors, LOCKED) |
| Spec version | 1.5 (ENTITY-CBOR-ENCODING; spec-data v7.75) |
| Encode vectors | 64 / 64 byte-identical |
| Decode-reject vectors | 5 / 5 rejected (code `non_canonical_ecf`) |
| Errors | 0 |
| Oracle | go `wire-conformance` @ entity-core-go commit `e8524ed` |
| Toolchain | `entity-core-keystone/rust-toolchain:latest` — fedora:43, rust/cargo 1.96.0-1.fc43 |
| Lint gate | `cargo fmt --check` clean + `cargo clippy --all-targets -- -D warnings` clean |
| Unit tests | 13 / 13 pass (`cargo test --release`) |

## The conformance mechanism (how 69/69 is proven)

The go oracle's `wire-conformance` does not run a peer's source directly. The model
(GUIDE-CONFORMANCE §3.1) is **comparable emission files**:

1. `build-fixture --diag conformance-vectors-v1.diag --out conformance-vectors-v1.cbor`
   produces the canonical-ECF corpus every impl loads (already shipped in the corpus dir;
   its `canonical` fields are the 3-way-locked golden bytes).
2. Each impl's harness runs `emit-canonical`-equivalent over that corpus, producing an
   **emission** = `{impl, impl_version, corpus_version, spec_version, encode_results,
   decode_results, decode_codes, errors}`.
3. Conformance = the impl's emission is byte-identical to go's for `encode_results`
   (id → emitted bytes) and agrees on `decode_results` / `decode_codes`.

This peer's harness is `src/bin/wire_conformance.rs` (the Rust analogue of go's
`emit-canonical`). It additionally self-checks each produced byte string against the
corpus's own locked `canonical` field, so a green run is checked **twice**: against the
corpus golden bytes AND against the live go-oracle emission.

### Vector classes (all green)

- **Class A — canonical encoding (re-encode through the hand-rolled encoder):**
  `float.*` (14: Rule 4/4a shortest-float ladder f64→f32→f16 + specials),
  `int.*` (14: Rule 1 minimization, full i64/uint64 + nint boundaries),
  `map_keys.*` (6: Rule 2 ordering incl. mixed bstr/text + the len-23/24 boundary),
  `length.*` (8: definite-length only, Rule 3), `primitive.*` (6: bool/null/empties),
  `nested.*` (4: deep maps + entity/envelope carrier shapes).
- **Class A — decode_reject (`tag_reject.*`, 5):** §6.3 recursive major-type-6 tag
  rejection at every depth (bare, nested-in-data, deep-in-included-entity, and the
  55799 self-describe magic) → `non_canonical_ecf`.
- **Class B — protocol surface:** `content_hash.*` (4: `varint(format_code) ||
  SHA-256(ECF({type,data}))`, incl. the multi-byte-varint `format_code=128` case),
  `peer_id.*` (3: `Base58(varint(kt)||varint(ht)||digest)` as an ECF text string, incl.
  multi-byte `key_type=128`), `signature.*` (3: deterministic Ed25519 over canonical-ECF
  entity bytes), `envelope.*` (2: full carrier shape with hash-keyed included map).

## Oracle build isolation (lesson-learned discipline)

The go oracle tree at `entity-core-go` was **never used as cwd or build-output dir**. It
was confirmed clean (`git status -s` empty) and stayed clean throughout. Procedure:

```
git -C <oracle> archive e8524ed | tar -x -C $(mktemp -d /tmp/wire-conformance-vendor.XXXXXX)
```

The go binary was then built **inside a throwaway container** (fedora:43 +
golang-1.25.11-2.fc43) with `GOCACHE`/`GOPATH`/`-o` all pointed at a separate
`mktemp -d /tmp/go-build-out.XXXXXX` mount — no artifact landed in the oracle tree. The
oracle's `golang-1.25.10` pin had drifted out of fedora:43; 1.25.11 is the current
available patch (oracle-build image only, NOT a committed deliverable). Oracle tree
re-verified clean after the run.

## Emission artifact

`status/emit-rust.cbor` (2134 bytes) is this peer's emission file, byte-comparable to
go's `emit-go.cbor` (2137 bytes; the 3-byte delta is solely the differing `impl` /
`impl_version` strings — the `encode_results`/`decode_results`/`decode_codes` maps are
byte-identical, verified by decoding both and diffing per-key).

---

# entity-core-protocol-rust — S3 Peer Machinery Report

**S3 gate: GREEN.** The live peer machinery is built on top of the S2 codec and both
S3 gate legs pass.

| Gate leg | Result |
|---|---|
| **Two-peer loopback over real TCP** | **6 / 6 checks PASS, 0 fail** (`tests/loopback.rs`) |
| **Type-registry conformance** | **53 / 53 byte-identical** to the v7.71 Go vector set (`type_defs::tests`) |
| **§3.6 multisig accept-path** | **PASS** — 2-of-3 → ALLOW + all M3/M4/M6 deny flips + single-sig superset |
| Peer unit tests (lib) | 33 / 33 pass |
| S2 codec (no regression) | still 69 / 69, 0 fail |
| Lint gate | `cargo fmt --check` clean + `cargo clippy --all-targets -- -D warnings` clean |
| Toolchain | `entity-core-keystone/rust-toolchain:latest` — fedora:43, rust/cargo 1.96.0-1.fc43 |

## Loopback gate detail (`tests/loopback.rs`)

Two `entity-core-protocol-rust` peers talk over a real `127.0.0.1` socket through the
full §6.6 dispatch chain:

```
Handshake:
  [PASS] remote peer_id matches responder
Dispatch:
  [PASS] unregistered path -> 404
  [PASS] granted tree get -> 200
  [PASS] tree get returns a system/type entity
  [PASS] capability request -> 200
Concurrency (request_id demux):
  [PASS] 8 interleaved requests each correlated -> 8/8
Teardown clean.   ->   LOOPBACK: 6 pass, 0 fail
```

This covers: the §4.1 three-EXECUTE handshake (hello → authenticate, both legs answered
over real frames by the responder's reader-demux), a 404 for an unregistered path, an
authority-gated `system/tree` get returning a `system/type` entity (proving the §4.4/§6.9a
seed-policy grant flows end-to-end), a `system/capability` request, and N7 `request_id`
demux of 8 concurrently-issued requests each correctly correlated to its reply.

## Type-registry gate detail

`type_defs::publish` renders the **53-type core floor** natively through the S2 codec.
The conformance test diffs each type's content_hash digest against the v7.71 vector set
(`shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor`, the cohort drift target — the
vector file carries 150 types; the 53 core types are matched as a subset). All 53 are
byte-identical — the same render-from-model design the whole cohort follows.

## What S4 (`validate-peer --profile core`) inherits

The peer surface is wired for the live oracle: `--name`/`--port`/`--validate` host CLI,
the four MUST handlers + §6.6 routing, §5 capability verification (chain-walk +
attenuation + verdict trichotomy + §4.10(a)/(b) bounds), §6.13 register-live, handler
outbound (§6.11 reentry), emit (§6.10), peer-owner cap + seed-policy read, §7a
`system/validate/{echo,dispatch-outbound}` (opt-in `--validate`), and genuine §3.6 K-of-N
multisig. No oracle test was doctored.

---

## S5 re-stamp — gates re-verified at packaging

The S5 packaging phase re-ran the supporting gates in the `rust-toolchain:latest` container
(`--network=none`, against the gitignored `output/vendor` mirror) — **all green, no
regression, no peer source touched**:

- `cargo fmt --check` — clean.
- `cargo clippy --all-targets --offline -- -D warnings` — clean (0 warnings).
- `cargo test --offline --lib` — **33/33 pass** (codec units + §9.5 byte-diff + round-trip).
- `wire-conformance --input conformance-vectors-v1.cbor` (v7.71) — **69 / 69 PASS, 0 FAIL**
  byte-identical (codec unregressed).
- `cargo package --locked --offline` — **succeeds**; verify-build compiles the packaged crate
  clean (29 files, src-only; `output/`/`status/`/`arch/`/`profile.toml`/`run-*.sh` excluded).

The live `validate-peer --profile core` result above (**665·0F @ e8524ed**, `summary.failed
== 0`) is the S4 record and is carried forward unchanged — S5 added no peer code. Final
version line: **`0.1.0-pre`**, license **Apache-2.0**, MSRV **rust 1.96**, two direct deps
(`ed25519-dalek =2.2.0` + `sha2 =0.10.9`). `cargo publish` is **DEFERRED per S10** (no
upload run). See [`PHASE-S5.md`](PHASE-S5.md).
