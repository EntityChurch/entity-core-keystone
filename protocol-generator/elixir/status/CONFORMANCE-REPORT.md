<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-08) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 335 pass · 336 warn · 0 FAIL · 107 skip** (elapsed 2330 ms).
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

> **v7.75 re-run (oracle `entity-core-go @ b30a589`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 291 pass · 196 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-elixir — S2 Codec + S3 Peer + S4 Conformance Report

**Peer #4** (Elixir) · **Phases S2 (codec) + S3 (peer) + S4 (validate-peer)** · **Status: GREEN — `--profile core` PASS, first run, 0 fixes**

## Result

| Corpus / suite | Vendored version | Result |
|---|---|---|
| **ECF codec** (`conformance-vectors.cbor`) | v7.71 (byte-identical to v7.56/v7.70) | **69/69 PASS, byte-identical, first run, 0 fixes** |
| **Crypto-agility** (`agility-vectors.cbor`) | v7.71 (v7.67 corpus) | **35/35 byte-pins PASS** (0 deferred — the 4 S2-deferred gates picked up at S3) |
| **Type registry** (`type-registry-vectors`) | v7.71 | **53/53 core types byte-identical** (render-from-model, A-OC-006) |
| **Peer machinery** (`mix test`) | v7.73/v7.74 folded surface | **20/0** — F1/F3/§7a + live-wire smoke + §6.11 reentry |

Run in-container, sealed-offline (`--network=none`), via `./run-s3.sh`
(`mix test` + escript build) / `./run-s2.sh`. Image
`entity-core-keystone/beam:latest` (OTP 27.3.4 + Elixir 1.18.4).

## ECF corpus (lower bar) — 69/69

Fourth independent native ECF codec to reach 69/69 byte-identical on the **first
run with zero fixes** (after C#, TS, OCaml — S8 convergence). Hand-rolled
canonical encoder/decoder (`lib/entity_core/cbor.ex`) via **binary
pattern-matching** (`<<major::3, info::5, rest::binary>>`), plus LEB128 varint,
Base58, content-hash, peer-id, and Ed25519 signing (OTP `:crypto`).

Coverage (Class A 52 encode + 5 decode-reject + Class B 12 encode):

| Category | n | Notes |
|---|---|---|
| `float` | 14 | shortest-float ladder (f16/f32/f64) + Rule 4a specials. BEAM `::float-16` bit syntax, with an exponent guard against silent overflow-to-Inf and explicit NaN/Inf/-0.0 bit-pattern handling on decode |
| `int` | 14 | major-0/1 minimization to max signed i64. **No native-int trap** — BEAM integers are arbitrary-precision (contrast OCaml int63 / C# ulong / TS bigint) |
| `map_keys` | 6 | length-first then lexicographic on encoded key bytes; mixed text/byte keys |
| `length` | 8 | definite-length only; N3 empty-map = `0xA0` |
| `primitive` | 6 | bool/null/empty containers |
| `nested` | 4 | entity + envelope carrier shapes |
| `tag_reject` | 5 | **N2** — recursive major-type-6 rejection at any depth, incl. nested in `included` entity data and the tag-55799 wire frame |
| `content_hash` | 4 | `varint(format_code) ‖ SHA256(ECF({type,data}))`; **N1** multi-byte varint prefix (synthetic 0x80 code) |
| `peer_id` | 3 | `CBOR-text(Base58(varint(kt) ‖ varint(ht) ‖ digest))`; N1 multi-byte key_type |
| `signature` | 3 | deterministic Ed25519 over canonical ECF, native `:crypto` |
| `envelope` | 2 | full `{root, included}` ECF under the map-key rules |

## Crypto-agility corpus (higher bar) — 28/28 crypto byte-pins, native

**The headline of peer #4.** Unlike OCaml (A-OC-002 — no native Ed448, sourced
over the C-ABI in an opt-in sub-library), Elixir reaches the **entire** agility
higher bar **natively** from the default build: Ed448 and SHA-384 both come from
OTP `:crypto` (OpenSSL). No FFI, no opt-in sub-library, no hybrid split.

| Vector group | Gates | What's proven |
|---|---|---|
| `KEY-TYPE-ED448-1` | 5 | Ed448 seed→pubkey (57 B), peer-id (§1.5 SHA-256-form), system/peer data CBOR + content_hash, **Ed448 signature (114 B) byte-identical to the locked RFC-8032 pin** |
| `HASH-FORMAT-SHA-384-1` | 2 | SHA-256 inherited pin + SHA-384 rehash (49 B wire) |
| `VARINT-* / FORMAT-CODE` | 3 | **N1** — multi-byte LEB128 format-code decode fires before the registry check; unallocated codes (128, 255, 0x42) → `unsupported_content_hash_format` |
| `MATRIX-M2/M3/M6` | 18 | per-peer identity gates (pubkey / peer-id / content_hash@home) across the cross-key (Ed448↔Ed25519) and cross-hash (SHA-256↔SHA-384) matrix |

**Identity-derivation rule confirmed (§1.5 size-cutoff):** a key ≤ 32 B is an
identity-multihash (`hash_type=0x00`, digest = key) → Ed25519 = `(0x01, 0x00,
pubkey)`; a larger key is SHA-256-form (`hash_type=0x01`, digest = SHA-256(key))
→ Ed448 = `(0x02, 0x01, sha256(pubkey))`.

**S2-deferred gates picked up at S3 — now green (A-ELX-005):**
- `varint-reserved-ff.1.key_type` — key_type 255 mint refusal via the §1.5 key
  registry (`PeerId.resolve_key_type/1`).
- `matrix.{M2,M3,M6}.root_cap` — capability-token content_hash + A's signature
  over it, built per SEEDS.md §2.3-§2.5. **Byte-identical on the first attempt
  across both the key axis (Ed448 granter) and the hash axis (SHA-384 home
  identity hash under a SHA-256 active cap)** — the first independent keystone
  verification of these pins (every prior peer deferred them).

## S3 peer machinery (§5/§6 surface) — `mix test` 20/0

| Suite | n | What's proven |
|---|---|---|
| `peer_test` (F3 emit) | 1 | §6.10 event-type derivation, no-op suppression, deletion-marker → modified |
| `peer_test` (F1 register) | 1 | §6.13(a)/§6.2 five normative writes + entity-native dispatch + unregister symmetry |
| `peer_test` (§7a) | 3 | echo verbatim (A-011), dispatch-outbound reentry round-trip (A-013), OFF-by-default |
| `peer_test` (§6.9a) | 1 | self-owner cap + signature at L0; default seed policy present |
| `smoke_test` | 1 | **live wire**: §4.1/§4.6 handshake → authorized §6.5 listing (200) → unregistered path (404) → request_id echo |
| `reentry_test` | 1 | §6.11 outbound demux over a real socket pair (the §6.13(b) machinery) |

The S3 peer layer is built on the BEAM **actor model** (A-ELX-006): a GenServer
content store/tree (serialized, atomic CAS), one process per connection (single
writer, §4.8 per-request dispatch, §6.11 `request_id` demux + outbound reentry).
No NEW spec ambiguity surfaced — Elixir corroborates the inherited A-OC-007 /
A-OC-008 / A-011 / A-013 findings from a fourth, distant-idiom peer.

## Conformance invariants (N1–N4) — all covered at design time

| Invariant | How |
|---|---|
| **N1** varint LEB128 | `EntityCore.Varint` primitive routes every format-code/key-type/hash-type prefix; exercised by `content_hash.4`, `peer_id.3`, and the agility `VARINT-*` rejects (multi-byte 128/255 decode before registry check) |
| **N2** tag rejection | recursive major-type-6 scan in the decoder (`do_decode` major 6 → reject), at any depth; `tag_reject.1–5` |
| **N3** empty-map `0xA0` | `length.2` + `content_hash.1` (empty-data boundary `005f3139…`) |
| **N4** entity fidelity | decoder preserves byte strings as `{:bytes, _}` and never re-serializes received bytes on the forward path (decode→encode is identity for canonical input; selftest round-trip) |

## Gates

- `mix test` — **20 tests, 0 failures** (ECF 69/69 + agility 35 + type-registry
  53 + 8 peer/smoke/reentry).
- `mix compile --warnings-as-errors` clean (22 files); `mix escript.build` →
  standalone host.
- **Zero runtime Hex dependencies** — `:crypto` is OTP stdlib; CBOR/base58/varint
  + the peer layer hand-rolled (GenServer/process-based, no deps); ExUnit stdlib.
  `mix deps.get` pulls nothing.

## S4 conformance (live peer, higher bar) — `--profile core` PASS

Run in-container, sealed-offline, against the escript host
(`./entity_core_protocol --debug-open-grants --validate`) driven by the Go
`validate-peer` oracle rebuilt from go HEAD (`9c624aa`, the §7a unified
A-011/A-013 resolution; oracle + reference `entity-peer`).
Harness: `./run-s4.sh` (profile core) + `./run-origination-core.sh` (§10.2).

**Fourth peer to PASS `--profile core` on the first run with zero fixes** (after
C#, TS, OCaml). Scoreboard **identical to OCaml** — Elixir is the predicted
corroboration peer (it shares the BEAM `:crypto` + arbitrary-precision-int +
process model, so codec/crypto/concurrency findings *replicate* rather than
surface; the only-new-info is generator-robustness, not spec discovery).

| Gate | Result |
|---|---|
| `validate-peer --profile core` | **568 total · 284 PASS · 195 WARN · 0 FAIL · 89 SKIP → PASS** |
| §10.1 core-register gate | **10/10 PASS** (9 `core_register_*` + `validate_echo_dispatch`) |
| §10.2 origination-core (reentry) | **3/3 PASS** incl. `dispatch_outbound_reentry` over real two-peer TCP |
| §10.3 drift | oracle-side self-check (validator category-list vs sibling V7 §9.0); verified once at keystone signoff — not a per-peer check |

Category scoreboard (matches OCaml exactly): `connectivity` 22/0/0/0,
`encoding` 6/0/0/0, `type_system` 108/194/0/0, `handlers` 35/0/0/32,
`tree_operations` 24/1/0/31, `security` 28/0/0/1, `multisig` 10/0/0/0,
`universal_address_space` 8/0/0/0, `peer_canonicalization` 7/0/0/0,
`format_agility` 10/0/0/0, `crypto_agility` 4/0/0/0, `negotiation` 4/0/0/0,
`authz` 6/0/0/2. The 89 SKIPs are all V7 v7.72 §9.0 extension-profile carve-outs
(auto-allowlisted, exempt from the FAIL gate); the 195 WARNs are the type_system
extension-vocab advertisements (S6 profile-local, not core MUSTs).

**§10.1 register gate (the v7.74 Phase B core surface) — all 10 green:**
`core_register_{op_status,op_result,manifest_at_path,handler_at_path,grant_at_path,grant_signature_at_invariant_path,body_binding,unregister_status,unregister_signature_removed}`
+ `validate_echo_dispatch`. The §3.4 grant-signature lands at the invariant
pointer `system/signature/{grant_hash}` (presence + `sig.Target ==
grant.content_hash` both enforced), unregister symmetry tested. The compute-half
`core_register_dispatch_roundtrip` is gone (A-011 closed by §7a); `body_binding`
exercises the minimal `compute/literal` seam still shipped (deferred cleanup,
no longer gate-exercised, ledgered repo-wide).

**§10.2 origination-core — `dispatch_outbound_reentry` PASS over real TCP.** The
validator mints a reentry capability, EXECUTEs `system/validate/dispatch-outbound`
on the Elixir target, and the target originates an outbound EXECUTE back to the
validator-as-B over the **same inbound connection** (§6.11 reentry; NOT a fresh
dial). This is the cross-impl wire proof of the BEAM process-per-connection
reader-demux + `request_id` correlation seam (F2). The Go `entity-peer`
reference (B-role) is connected only to satisfy the `-reference-peer` input shape;
unused under core. Without `--validate` the probe honest-SKIPs (verified via
`VALIDATE=0`).

No spec ambiguity surfaced at S4 — Elixir corroborates the inherited core verdict
(A-OC-007 §7.4/§1.5 peer-id, A-OC-008 401/403, A-011/A-013 §7a) from a fourth,
distant-idiom peer. **No oracle doctoring (S5):** every SKIP is a §9.0 carve-out
or honest setup-absence; every PASS is against the real go-HEAD oracle.

## S5 packaging — DONE (publish-ready, parked `0.1.0-pre`)

Documented + packaged, not published (`status/PHASE-S5.md`). `mix.exs` carries Hex
metadata (`entity_core_protocol`, Apache-2.0, files allow-list, links);
README/CHANGELOG/LICENSE present; `mix hex.build` green **sealed-offline, zero
deps** (`deps.get` pulls nothing). API surface tiered in PHASE-S5 §3.
`@moduledoc false` hide + ex_doc HexDocs render deferred to publish-prep (keeps
the build dep-free + offline). This completes the S1→S5 lifecycle for peer #4.
