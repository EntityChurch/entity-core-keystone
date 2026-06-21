> **v7.75 re-run (oracle `entity-core-go @ 62044c5`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 290 pass · 197 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-common-lisp — Conformance Report (S2 codec)

**Peer #5** (Common Lisp) · **Phase S2 (codec)** · **Status: GREEN**

## Result

| Corpus | Vendored version | Result |
|---|---|---|
| **ECF codec** (`conformance-vectors-v1.cbor`) | v7.71 (byte-identical to v7.56/v7.70); sha256 `41d68d2d…6a052` | **69/69 PASS, byte-identical, first full run, 0 fixes** |
| **Ed448 RFC-8032 KAT** (agility gate, A-CL-005) | v7.71 `KEY-TYPE-ED448-1` pins | **PASS — pubkey + 114-B signature + §1.5 peer_id all byte-equal** |

Run in-container, sealed-offline (`--network=none`) via `./run-s2.sh` (full gate:
ASDF `entity-core/test:run-all`) or `./run-s2.sh conform` (corpus counts).
Image `entity-core-keystone/common-lisp-toolchain:latest` (SBCL 2.6.4 + ASDF 3.3.1
+ ironclad 0.61, all source/dist-pinned).

## How conformance works here

The `conformance-vectors-v1.cbor` fixture carries its own cross-blessed `canonical`
bytes per vector — it is the Go `wire-conformance` oracle's output
(`build-fixture` / `emit-canonical`, 3-way Go × Rust × Python byte-lock).
The hand-rolled harness (`test/conformance.lisp`) **decodes the
fixture with THIS peer's own decoder** (a decoder bug is itself a conformance
failure per ENTITY-CBOR-ENCODING.md §E.3), runs every vector through the codec,
and byte-compares against the embedded `canonical`. Byte-identity to the fixture
== oracle PASS. (Same self-contained mechanism the C#/TS/OCaml/Elixir peers used;
the Go binary is the fixture producer/cross-blesser, not a runtime checker — its
subcommands are `build-fixture`, `emit-canonical`, `legacy-envelope`.)

## ECF corpus (lower bar) — 69/69

Fifth independent native ECF codec to reach 69/69 byte-identical on the first full
run with zero fixes (after C#, TS, OCaml, Elixir — S8 convergence holds). Hand-rolled
canonical encoder (octet-vector builder) + index-walk decoder (`src/cbor.lisp`),
plus LEB128 varint, Base58, content-hash, peer-id, and Ed25519 signing (ironclad).

| Category | n | Notes |
|---|---|---|
| `float` | 14 | shortest-float ladder (f16/f32/f64) + Rule-4a specials. Pure-integer f16 conversion (exact, no FFI): normalized via low-42-bits-zero check, subnormal via the `value·2^24 ∈ [1,1023]` integer test; f32 via `sb-kernel:single-float-bits` round-trip-exact gate; f64 fallback. NaN/±Inf/-0.0 carried as keyword sentinels so the wire bytes are the canonical Rule-4a forms |
| `int` | 14 | major-0/1 minimization to 2^63-1. **No native-int trap** — CL integers are native bignums; the head-form carrier is just an integer (contrast OCaml int63 / C# ulong / TS bigint; matches Elixir) |
| `map_keys` | 6 | length-first then byte-lexicographic on encoded key bytes (ECF Rule 2 / §3.5); mixed text/byte keys |
| `length` | 8 | definite-length only; **N3** empty-map = `0xA0` |
| `primitive` | 6 | bool/null/empty containers (sentinels `:true`/`:false`/`:null` keep absent ≠ null ≠ false) |
| `nested` | 4 | entity + envelope carrier shapes |
| `tag_reject` | 5 | **N2** — recursive major-type-6 rejection at any depth, incl. nested in `included` entity data and the bare tag-55799 wire frame; signals `tag-rejected` (a `non-canonical-ecf` subtype) with NO restart (hard reject) |
| `content_hash` | 4 | `varint(format_code) ‖ SHA-256(ECF({type,data}))`; **N1** multi-byte varint prefix (synthetic 0x80 → `80 01`, content_hash.4) |
| `peer_id` | 3 | `CBOR-text(Base58(varint(kt) ‖ varint(ht) ‖ digest))`; N1 multi-byte key_type (128) |
| `signature` | 3 | deterministic Ed25519 over canonical ECF, native ironclad |
| `envelope` | 2 | full `{root, included}` ECF under the map-key rules |

## Conformance invariants (N1–N4) — enforced + covered

| Invariant | How (file) | Covering vectors |
|---|---|---|
| **N1** LEB128 varints | `src/varint.lisp` — every format-code/key-type/hash-type prefix routed through it | `content_hash.4` (fc 128), `peer_id.3` (kt 128), selftest multibyte round-trip |
| **N2** tag rejection | `src/cbor.lisp` `%dec` major-6 → `(error 'tag-rejected …)` at any depth | `tag_reject.1–5` (incl. nested-in-included + bare 55799), selftest bare-tag |
| **N3** empty-map `0xA0` | `%enc-head 5 0` | `length.2` (`{}` → `a0`), `content_hash.1` (empty-data boundary `005f3139…396b`) |
| **N4** entity fidelity | decoder is structural; byte strings carried as a `bytes` struct (major 2 ≠ major 3); decode→encode is identity for canonical input | round-trip selftests; original-byte forwarding wired at S3 (peer surface) |

## Ed448 / agility — native pure-Lisp, RFC-8032 KAT GATED (A-CL-005)

The S1 plan gated trusting pure-Lisp Ed448 on RFC-8032 byte-equality BEFORE using
it for the agility corpus. **The gate passes** (`test/selftest.lisp`
`run-ed448-kat`, pins from v7.71 `agility-SEEDS.md` §1.1):

- Ed448 seed `0x42×57` → **57-byte public key byte-equal** to the locked pin
  (`2601850d…3b0e00`).
- Ed448 **114-byte signature** over the §1.1 fixture message **byte-equal** to the
  locked RFC-8032 pin (`0aff7a36…b33400`) — deterministic EdDSA.
- `ed-verify` of that signature passes; `peer-id-from-public-key` yields the **§1.5
  SHA-256-form** peer_id `3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4`
  (Ed448 pubkey > 32 B → `hash_type=0x01`, digest = SHA-256(pubkey)).

This is the **third native-Ed448 peer** (after Elixir; OCaml needed FFI) and the
**second pure-Lisp/native-runtime path** — first via a pure-Lisp crypto library
(ironclad) rather than an OpenSSL-backed runtime. No FFI, no opt-in sub-library, no
hybrid. The documented fallback (hybrid-FFI, OCaml A-OC-002 route) is NOT needed.

ironclad 0.61 API confirmed in-container: `make-private-key :ed448 :x seed`
computes the public key Y; `destructure-private-key` returns a plist `(:x :y)`;
`sign-message` / `verify-signature` / `make-public-key :y` as expected.

## Uncovered-range self-tests (codec-review heuristic) — `test/selftest.lisp`, all PASS

A green corpus proves the math vs the corpus, not the ranges it doesn't cover:

- **uint64 = 2^64-1 and 2^63** (above signed-i64 max — the native-bignum win):
  encode (`1bffffffffffffffff`) + round-trip correct.
- **nint min -2^64** (`3bffffffffffffffff`).
- float ladder boundaries (1.5→f16, 65503→f32, 1.1→f64, f16 65504 round-trip);
  NaN/±Inf/-0.0 sentinel round-trips.
- peer-id format→parse round-trip (incl. multi-byte key_type 128).
- base58 decode∘encode with leading-zero preservation.
- Ed25519 sign/verify + tamper-reject.
- N2 bare-tag (55799) rejection.

## Notes

- **Native codec, no FFI.** No `dlopen`/C-ABI boundary to exercise (the
  codec-review-heuristic's FFI caveat is N/A for a native peer).
- **Clean compile.** No errors, no style-warnings from peer code under SBCL 2.6.4
  (one harmless "deleting unreachable code" note in the float path; the
  `WARNING: redefining IRONCLAD:BLOCK-LENGTH` is ironclad's own load-time warning).
- **Agility matrix beyond the KAT** (MATRIX-M2/M3/M6 full 7-gate tuples, cap-token
  content_hash) is S3 peer-layer work (needs the §3.6 cap-token shape + key
  registry) — same deferral the Elixir peer made.

## Exit criteria

ECF corpus byte-identical (69/69) · Ed448 KAT byte-equal (A-CL-005 gate passes) ·
selftests PASS · report written · compiles clean · ambiguity log has no blocking
codec items · container reproducible (SHA filled, dist pinned). **S2 PASS.**

---

## S4 — Live-peer conformance (`validate-peer --profile core`)

**Peer #5** (Common Lisp) · **Oracle:**
`output/s4-oracles/validate-peer`, rebuilt from `entity-core-go` HEAD `d39aaf2`
(§7a wire-gate compiled in: `validate_echo_dispatch` + `dispatch_outbound_reentry`
present, the pre-§7a `core_register_dispatch_roundtrip` GONE) · **Result:**

```
568 total · 284 passed · 195 warned · 0 FAILED · 89 skipped → Result: PASS
```

The **same conformance fixed-point** as OCaml (#3, 284P/195W/0F/89S), reached
spec-first in the most distant idiom (CLOS multiple-dispatch + sb-thread + the
condition system). 0 FAIL is the gate. Run sealed-offline in the
`common-lisp-toolchain` container (`--network=none`); the Go `validate-peer` ELF
and the SBCL host share one loopback. Harness: `run-s4.sh`.

```
./protocol-generator/common-lisp/run-s4.sh          # the --profile core gate
./protocol-generator/common-lisp/run-origination-core.sh   # §10.2 reentry probe (3/3)
```

### Per-category scoreboard

| Category | Pass | Warn | Fail | Skip | Notes |
|---|---:|---:|---:|---:|---|
| connectivity | 22 | 0 | 0 | 0 | |
| encoding | 6 | 0 | 0 | 0 | |
| type_system | 108 | 194 | 0 | 0 | 53-type §9.5 floor PASS byte-exact; 194 non-floor ext vocab WARN |
| handlers | 35 | 0 | 0 | 32 | core register/unregister/dispatch; ext handlers auto-skip |
| capability | 12 | 0 | 0 | 0 | request/revoke/configure/delegate |
| tree_operations | 24 | 1 | 0 | 31 | EXTENSION-TREE §9 ops auto-skip; 1 non-critical cleanup warn |
| security | 28 | 0 | 0 | 1 | §5.5 chain + §5.7 caveats + §PR-8 V2(a) cross-peer |
| multisig | 10 | 0 | 0 | 0 | |
| universal_address_space | 8 | 0 | 0 | 0 | |
| peer_canonicalization | 7 | 0 | 0 | 0 | |
| format_agility | 10 | 0 | 0 | 0 | |
| crypto_agility | 4 | 0 | 0 | 0 | |
| negotiation | 4 | 0 | 0 | 0 | §4.5 disjoint hash/key reject |
| authz | 6 | 0 | 0 | 2 | 2 ext-vocabulary carve-out skips (role / ROLE §5.5) |
| (extension categories) | — | — | — | 23 | whole-category §9.0 auto-allowlist skips |

`origination` is an extension-only category under §9.0 (auto-skipped in the gate);
its core legs (`reference_connect`/`reference_ready`) + the `dispatch_outbound_reentry`
probe run **3/3 PASS** via `run-origination-core.sh` with a Go `entity-peer` reference
(the §7a reentry: the CL target originates an outbound EXECUTE back to the
validator-as-B over the SAME inbound §6.11 connection — native sb-thread seam,
cross-impl wire-proven).

### The grind: 7 → 0 FAIL

All 7 first-run FAILs were CL **code bugs** (fixed by deriving from V7 + the cohort,
never by doctoring the oracle); details + escalations in `SPEC-AMBIGUITY-LOG.md`
(S4 closeout):

| Fix | Spec | Unblocked |
|---|---|---|
| `hex` uppercase → **lowercase** (address-space path convention, A-CL-009 ⚑) | §3.4 / §3.5 / §5.1 | `core_register_grant_signature_at_invariant_path` (+ unregister symmetry); `revoke_happy_path_writes_marker` (+ `revoked_cap_denied_on_use`) |
| §PR-8 / V2(a): grant resource patterns canonicalize against the **granter** frame | §3.6 / §5.2 PR-8 / §5.5 | `captok_form_dispatch_minted_pl_presented_xpeer` |
| §5.7 `delegation_caveats` enforced per-link (no_delegation / max_delegation_ttl) + §5.5a per-link granter frames | §5.7 / §5.5a | `chain_no_delegation_denied`, `chain_max_delegation_ttl_denied` |

### Type-registry publish (§9.5 floor) — 53/53 byte-identical

Render-from-model (NOT ingest-bytes): the 53 core type *models* live in-code
(`src/type-defs-data.lisp`, generated by `tools/gen-typedefs.py` from the shared
`type-registry-shapes.json`); `src/type-defs.lisp` renders each to a `system/type`
entity (content_hash via our own S2 codec) and publishes it at
`/{peer}/system/type/{name}` at bootstrap. The peer-side dual of the S2 corpus
(`test/type-registry.lisp`) diffs each content_hash against the canonical
`type-registry-vectors-v1.diag` — **53/53 byte-identical on the first run, 0 fixes**.
Live `type_system` went 0 → 108 PASS, 0 core FAIL (the 194 WARN = non-floor extension
vocabulary, matched-if-present — refined G4, the same WARN class the cohort carries).

### WARNs + SKIPs — all cohort-known, none disguised

- **195 WARN:** 194 `type_system` non-§9.5-floor type vocabulary (the Go reference
  peer publishes its entire ~131-type registry incl. extension type *definitions*; a
  core peer publishes only the 53-type floor → the rest WARN, never FAIL). 1
  `tree_operations.cleanup` ("failed to remove test entity (non-critical)"),
  oracle-marked non-critical — the same 1-warn delta OCaml carries.
- **89 SKIP:** all auto-allowlisted by the V7 v7.72 §9.0 profile carve-out (the oracle
  marks them SKIP, exempt from the FAIL gate): whole extension categories, the
  in-category EXTENSION-TREE §9 ops + extension handler probes, and 3 extension-
  vocabulary carve-outs (`security.handler_scope_denied` → `system/subscription`;
  `authz_delegate_grant_1` → `system/role`; `authz_revoked_1` → ROLE §5.5 401 vocab,
  while the core surface `authz_revoked_core_1` PASSES). No SKIP is a disguised FAIL.

### Standards honored
- **S1** — all in `common-lisp-toolchain`, sealed offline (`--network=none`); oracle
  built from a disposable copy of the READ-ONLY go source (never modified upstream).
- **S5/S7** — raw oracle verdict; the one warn is oracle-marked non-critical, not
  hidden; lower bar (codec 69/69) + higher bar (`--profile core` 0 FAIL) both green.
- **S8** — convergence: a spec-first peer in the most distant idiom (CLOS + sb-thread)
  reaches the same conformance fixed-point.

**S4 PASS.**
