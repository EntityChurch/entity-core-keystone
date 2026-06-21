> **v7.75 re-run (oracle `entity-core-go @ 62044c5`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 291 pass · 196 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-zig — Conformance Report

Two gates (S7): the **lower bar** (codec byte-identical to the cross-blessed
fixture, `wire-conformance`) and the **higher bar** (full peer under
`validate-peer --profile core`). Both green.

---

## S4 — live peer · `validate-peer --profile core` → **PASS**

**Oracle:** `entity-core-go` HEAD (v7.74 §10.1 core-register gate + §9.5a
CORE-TREE vectors; built `CGO_ENABLED=0` in `containers/go`, run as a fedora ELF
**inside** the zig-toolchain container). **Spec-data:** v7.72/v7.74. **Peer:**
`./zig-out/bin/host --port 7777 --debug-open-grants`, run in
`entity-core-keystone/zig-toolchain:latest` (Zig 0.15.1), sealed offline
(`--network=none`) — oracle + peer share one loopback.

```
Summary: 568 total, 284 passed, 195 warned, 0 failed, 89 skipped (elapsed ~46s)
         89 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out
Result: PASS (with warnings)
```

**Zero failures on `--profile core`.** Machine-verified `summary.failed == 0`
(`status/CONFORMANCE-REPORT.json`). Same fixed point as C# (#1) / TS (#2) /
OCaml (#3) — reached **spec-first** in the distant Zig idiom (no GC, explicit
allocators, error unions, `std.Thread`). The 568 total (vs the C#/TS 552) is the
v7.74 oracle's 16 extra checks (the §10.1 core-register round-trip gate + the
§9.5a CORE-TREE delete/listing/cas vectors).

| Category | P / W / F / S | Notes |
|---|---|---|
| connectivity | 22 / 0 / 0 / 0 | TCP, hello→authenticate (incl. reverse leg), EXECUTE, request_id echo |
| encoding | 6 / 0 / 0 / 0 | hash wire format / ECF key ordering / signature shape on the wire |
| type_system | 108 / 194 / 0 / 0 | **53-type §9.5 floor byte-identical (A-ZIG-008)**; 194 warn = non-floor types (matched-if-present) |
| handlers | 35 / 0 / 0 / 32 | connect/tree/capability ops + §10.1 core-register dispatch round-trip; 32 skip = extension handler ops |
| capability | 12 / 0 / 0 / 0 | request / delegate / revoke / configure / is_revoked |
| tree_operations | 24 / 1 / 0 / 31 | get/put/CAS + §9.5a delete (deletion-marker listing-omit) + root listing; 31 skip = EXTENSION-TREE §9 ops |
| security | 28 / 0 / 0 / 1 | §5.x chain verify, handler-scope, status-code carve-outs |
| multisig | 10 / 0 / 0 / 0 | §3.6 / §5.5 multi-granter |
| universal_address_space | 8 / 0 / 0 / 0 | §1.4 foreign-namespace addressing incl. foreign-root listing |
| peer_canonicalization | 7 / 0 / 0 / 0 | §3.6 v7.65 patterns |
| format_agility | 10 / 0 / 0 / 0 | §4.7 unsupported_key_type at hello |
| crypto_agility | 4 / 0 / 0 / 0 | §1.5 key-type / §1.2 hash-format seam |
| negotiation | 4 / 0 / 0 / 0 | §4.5 hello advertisements + disjoint-reject |
| authz | 6 / 0 / 0 / 2 | deny-default 403 / scope-exceeds 403 / unresolvable-grantee 401 (A-ZIG-006); 2 skip = ROLE §5.5 ext |
| (whole extension categories) | — / — / — / 24 | subscriptions, continuations, revision, clock, compute, origination, … auto-skipped |

**Warns (195, all type_system):** the matched-if-present non-§9.5-floor type
vocabulary (compute/*, content/*, subscription/*, …) the oracle also probes —
non-blocking by §9.5 design. A core peer publishes only the 53-type floor.

**Skips (89, all auto-allowlisted):** §9.0 extension carve-outs — extension
handler ops (32), EXTENSION-TREE §9 ops (31), ROLE authz (2), and the whole
extension categories (1 each).

### Load-bearing S4 work (190 fail → 0)

The S3 baseline run was **568 total · 94 fail**. The fixes:

1. **type_system (87→0):** landed the full **§9.5 53-type registry**
   (`src/type_defs.zig`) — a native render-from-model FSpec/TypeDef builder
   (the cross-blessed C#/TS/OCaml design), seeded at `system/type/<name>`. A
   build-time byte-diff test (`A-ZIG-008`) renders all 53 and compares each
   `content_hash` digest against the Go-rendered `type-registry-vectors-v1.cbor`
   → **53/53 byte-identical, first run.** Resolves the A-ZIG-008 S4 carry-in.
2. **handlers — operations_match (3→0):** populated the bootstrap interface
   `operations` maps (connect={hello,authenticate}, tree-core={get,put},
   capability={request,delegate,revoke}) — the §6.2 op-set the oracle reads.
3. **handlers — core_register_dispatch_roundtrip (1→0):** implemented the
   minimal **§6.13(a) entity-native dispatch floor** — a dynamically-registered
   handler with an `expression_path` evaluates a bound `compute/literal {value}`
   → `compute/result {value, expression}` on dispatch (the v7.74 §10.1
   register-then-dispatch round-trip). Richer expression evaluation stays
   extension surface.
4. **tree_operations — path_root_listing (1→0)** + **uas
   foreign_namespace_listing_at_peer_root (1→0):** `pathFlexOk` now accepts a
   bare peer-root listing `/{peer_id}/` (§1.4 universal-tree-root walk).
5. **tree_operations — core_tree_delete_1 (1→0):** listings now **omit
   deletion-marker-bound leaves** (§6.3 / §9.5a CORE-TREE-DELETE-1) — the
   sibling stays, the tombstoned path drops; `count` reflects emitted entries.

### Spec-first findings validated live against the oracle

- **A-ZIG-001 (identity-multihash peer_id, `hash_type=0x00`):** validated by
  connectivity 22/22 + authz `authz_grantee_1` — the handshake's identity
  binding and grantee resolution both match the oracle, confirming the
  §1.5-canonical construction (NOT the stale §7.4/§1.5-line-436 SHA-256-form).
  Corroborates OCaml A-OC-007.
- **A-ZIG-005 (corpus peer_id coverage gap):** unchanged — the codec stays
  construction-agnostic; the live handshake exercises the canonical form the S2
  corpus does not discriminate.
- **A-ZIG-006 (401/403 authn/authz split):** validated by authz/security all
  green — `authz_deny_default_1` → 403 `capability_denied`,
  `authz_scope_exceeds_1` → 403 `scope_exceeds_authority`, `authz_grantee_1` →
  401 `unresolvable_grantee`. The 3-way verdict matches the oracle exactly.
  Corroborates OCaml A-OC-008 / arch F20 from a fourth, distant-idiom peer.

**No new spec ambiguities at S4.**

### §7a conformance handlers (`--validate`, off by default)

The `system/validate/{echo,dispatch-outbound}` scaffolding (GUIDE-CONFORMANCE
§7a) is bootstrapped only under the host `--validate` switch (peer
`conformance=true`) — `echo` is the §6.13(a) A-011 closure (returns params
verbatim); `dispatch-outbound` originates one outbound EXECUTE via the §6.11
reentry seam (A-013). The current oracle build does **not** gate `--profile core`
on these (verified: no `system/validate/echo` symbol in its check set), so they
are cohort-parity surface, not on the core gate; `echo` is unit-tested and the
`--validate` host serves cleanly with no core-profile regression.

### Reproduce

```sh
# 1. build the oracle ELF (once, or when entity-core-go moves):
podman run --rm -v $REPO/entity-core-go:/go-src:Z \
  -v $REPO/entity-core-keystone/output/s4-oracles:/out:Z \
  -v $HOME/go/pkg/mod:/root/go/pkg/mod:Z \
  -e GOWORK=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local \
  localhost/entity-core-keystone/go:latest \
  bash -c 'cd /go-src/cmd && go build -o /out/validate-peer ./validate-peer'

# 2. drive the peer (sealed offline, oracle ELF in the zig container):
podman run --rm --network=none -v $PWD:/work:Z \
  entity-core-keystone/zig-toolchain:latest \
  sh /work/protocol-generator/zig/run-s4.sh
```

Raw JSON: `status/CONFORMANCE-REPORT.json` (`summary.failed == 0`).

---

## S2 — codec layer · `wire-conformance` → **PASS** (69/69)

**Corpus:** `conformance-vectors-v1` (v7.71; sha256
`41d68d2d…6a052`) · **Result: 69 / 69 PASS, 0 FAIL** · **First run, 0 codec fixes.**

Run in-container, sealed offline:

```
podman run --rm --network=none -v $PWD:/work:Z -w /work/protocol-generator/zig \
  entity-core-keystone/zig-toolchain:latest \
  zig build conformance -- \
    /work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor
```

## Scoreboard (byte-identity vs the cross-blessed fixture)

| Category | Pass | Kind |
|---|---|---|
| float        | 14/14 | encode_equal (f16/f32/f64 shortest-float + R4a specials) |
| int          | 14/14 | encode_equal (uint/nint minimisation to 2^63-1) |
| map_keys     |  6/6  | encode_equal (length-then-lex on encoded key bytes) |
| length       |  8/8  | encode_equal (definite-length only) |
| primitive    |  6/6  | encode_equal (bool/null/empty) |
| nested       |  4/4  | encode_equal (entity + envelope-included shapes) |
| tag_reject   |  5/5  | decode_reject (recursive major-type-6 rejection, N2) |
| content_hash |  4/4  | encode_equal (varint(fc) ‖ SHA256(ECF); multi-byte fc) |
| peer_id      |  3/3  | encode_equal (Base58(varint‖varint‖digest); multi-byte key_type) |
| signature    |  3/3  | encode_equal (deterministic Ed25519 over canonical ECF) |
| envelope     |  2/2  | encode_equal (root + hash-keyed included map) |
| **TOTAL**    | **69/69** | |

Same fixed point as C# (#1), TS (#2), OCaml (#3) — reached spec-first, native,
no FFI, std-only.

## Notes
- **Native codec, no FFI** — no `dlopen`/C-ABI boundary to exercise.
- **Ed448 not covered** — agility higher-bar only (A-ZIG-002). The 69-vector ECF
  floor (Ed25519) is complete.
- **S7 lower bar: MET** (codec byte-identical); **higher bar: MET** (S4 above).

---

## ADDENDUM — §7a oracle re-verification

The original S4 run used a **pre-§7a oracle** (`core_register_dispatch_roundtrip`, no
`validate_echo_dispatch`). Re-run against the current `entity-core-go@9c624aa` oracle with
`--validate`: **568 / 284P / 195W / 0F / 89skip PASS**, `validate_echo_dispatch` **PASS**
(register gate 10/10, old roundtrip retired). `run-origination-core.sh` → **origination 3/3
PASS** incl. `dispatch_outbound_reentry` over real two-peer TCP (the `transport.zig` §6.11
reentry seam, wire-proven). No code change required; verification provenance corrected.
