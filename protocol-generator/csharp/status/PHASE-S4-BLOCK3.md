# entity-core-protocol-csharp — Phase S4 / Block 3 (in progress)

**Phase:** S4 resync — crypto-agility seam + peer canonicalization (v7.56 → v7.71/v7.72)
**Spec-data:** `v7.71` (PROTOCOL 7.71 · CBOR 1.5 · TYPE-SYSTEM 4.2.1); v7.72 §9.0/§9.5/§9.5a applied
**Status:** 🟢 **Part 1 DONE + byte-verified.** Crypto-agility seam proven against the
v7.67 corpus. **Part 2 (S4 validate-peer core verdict) — DONE: every
core-real check is GREEN.**

## ✅ Machine verdict — `validate-peer --profile core` → **PASS**

**Final run (oracle `entity-core-go` head `cb54f5b`, post-F21/F22 fix):**
`552 total · 269 pass · 194 warn · 0 FAIL · 89 skip (all auto-allowlisted)` → **`Result: PASS`.**
The hand-maintained scoreboard is now replaced by a machine-checkable PASS. All 14 core-profile
categories green, including **universal_address_space 8/8** (V7 §1.4 foreign-namespace
addressing/isolation). The 194 warns are the type_system non-§9.5-floor types (matched-if-present,
non-blocking by design); the 89 skips are the §9.0 extension carve-outs.

### How we got there (three layers, all resolved)

**First run** (oracle `64fa06f`) reported `263P/97W/126F` → FAIL, but **0 of the 126 fails were
peer bugs** — they were oracle-side `--profile core` carve-out gaps that only a *true* core peer
(53-type floor, no EXTENSION-TREE) could expose; the full-peer cohort (Go/Rust/Py, 150 types)
structurally could not. Routed to the oracle owners as a report on the Go core-profile oracle gaps:
- **[F21]** oracle bug — typesystem `_match` hard-failed absent non-floor types → **fixed by Go** (`cb54f5b`).
- **[F22]** oracle bug — EXTENSION-TREE §9 ops not skipped under core → **fixed by Go** (`cb54f5b`).
- **[F20]** ruling↔oracle contradiction (F14 "fix 401→403" vs oracle's auth-class 401) — **not applied**; routed to arch.

**Genuine peer fix** beyond the day-one set: the **universal grant** — `--debug-open-grants` now
advertises both peer-local (`*`) and cross-peer universal (`/*/*`) resource forms (V7 §5.2/PR-8:
bare `*` is local-only), so the oracle can reach the §1.4 foreign-namespace surface.
universal_address_space went 0/8→8/8 — the peer's universal addressing was already correct; the
debug grant just hadn't advertised universal coverage.

**This cycle's peer changes (all green under the oracle):**
- **Root-listing bug fixed** — `system/tree:get` on the empty/root prefix returned 400
  (`//` empty-segment from the trailing-slash peer-root prefix); now joins without the
  double slash. `path_root_listing` PASS. (The one genuine peer gap the machine run found.)
- **CORE-TREE-DELETE-1** — listing omits direct children bound to `system/deletion-marker`. PASS.
- **CORE-TREE-PATH-FLEX-1** — `tree:put` rejects control bytes + malformed leading-slash
  paths → 400 `invalid_path`. PASS.
- **Class C** — revoked-cap-on-use emits `403 capability_revoked` (known-revocation better
  default) instead of `capability_denied`. PASS (oracle's widened `authz_revoked_core_1`).
- **F14 NOT applied** — the reply's "fix 401→403" contradicts the oracle (auth-class → 401);
  C# retains the spec-and-oracle-correct 401. See **[F20]**.

xUnit 25/25; build clean (0 warnings). See the §"Core verdict reached" section below for
the prior per-category hand read.

## Core verdict reached

Per-category core read (the hand-maintained scoreboard until arch ships `--profile core`,
F18). **All core-real checks pass:**

| Category | Result | Core status |
|---|---|---|
| connectivity | 22/22 | ✅ green |
| encoding | 6/6 | ✅ green |
| multisig | 10/10 | ✅ green |
| crypto_agility | 4/4 | ✅ green |
| negotiation | 4/4 | ✅ green |
| **format_agility** | **10/10** | ✅ green (NEW — §4.7 unsupported_key_type at the hello boundary) |
| **peer_canonicalization** | **7/7** | ✅ green (NEW — PEER-PATTERN-1/2 via `:configure` + Base58 lazy-canon pattern) |
| **capability** | **12/12** | ✅ green (NEW — `request` scope-widening, `configure`, `revoke`, `is_revoked`) |
| **authz** | **5/7** | ✅ core-green (2 fail = EXTENSION-ROLE F18: `authz_delegate_grant_1` 404 on `system/role`; `authz_revoked_1` wants ROLE §5.5 `capability_revoked`/401) |
| type_system | 107/302 | ✅ core-green (191 fail = F17 extension types; 4 warn = provisional substitute) |
| handlers | 24/57 | ✅ core-green (21 fail + 8 skip = F18 extension handlers + EXTENSION-TREE op) |
| tree_operations | 20/50 | ✅ core-green (30 fail = F18 EXTENSION-TREE §9 ops) |
| security | 21/22 | ✅ core-green (1 fail = `handler_scope_denied` → `system/subscription`, F18/F19 over-demand) |
| origination | 1 skip | needs `-reference-peer` (not single-peer testable) |

**What landed this session (all spec-first, derived from V7):**
- **format_agility** — `ConnectHandler.Hello` decodes the inbound `peer_id` key_type prefix
  at the earliest boundary (`KeyTypes.IsHandshakeSupported`) and rejects non-Ed25519/Ed448
  with `400 unsupported_key_type` *before* protocol-version negotiation (v7.66 §4.4 surface
  6 / V7 §4.7; matches Go/Rust "earliest natural surface").
- **capability body** — `CapabilityHandler` now implements `request` (§6.2/§5.6 scope-widening
  reject → `403 scope_exceeds_authority` via `Attenuation.GrantsWithinAuthority`), `configure`
  (writes `system/capability/policy-entry` at `system/capability/policy/{peer_pattern}`;
  `peer_pattern` ∈ {`"default"`, 66/98-hex, Base58 peer_id}, globs rejected `400`), `revoke`
  (writes `system/capability/revocation` marker at `…/revocations/{cap_hash_hex}` with
  handler-set `revoked_at`); `delegate` stays `501` (same-peer-only, F1/F13).
- **is_revoked wiring** — `Dispatcher.IsChainRevoked` walks the full authority chain (§5.2
  step 4) and denies a revoked link with `403 capability_denied`.
- **§5.2 PR-3 carve-out** — `Dispatcher.VerifyRequest` checks the leaf cap's grantee resolves
  to a `system/peer` *before* the `grantee==author` check; an unresolvable grantee →
  `401 unresolvable_grantee` (the single-401 carve-out), matching Go `auth.go`.
- **peer_canonicalization** — PEER-PATTERN-1/2 fall out of `:configure` (canonical-hex pattern
  accepted + stored; Base58 lazy-canon pattern accepted in pending-canonicalization).

**Findings:** §5.4 dispatch-ordering resolved (V7 §6.5 pins resolution-first → 404 before
403) and the residual security/authz fails classified as F18 extension over-demands — logged
**F19** in `research/stewardship/SPEC-FINDINGS-LOG.md`.

## What landed (Part 1: resync + agility seam)

The peer was paused at the v7.56 S3 line ("WIP waiting on spec hardening"). v7.57→v7.71
turned the open S4 doubts into core spec (crypto-agility, multi-sig, the §3.3 authz
contract). This block absorbed the crypto-agility half.

### Gates (all green, container-bound, 0 warnings)

| Gate | Result |
|---|---|
| S2 codec conformance (v0.8.0 corpus) | **69/69** byte-identical (unchanged — corpus didn't move) |
| Crypto-agility byte verification (NEW) | **24/24** byte-identical to the v7.67 cohort pins |
| xUnit | 24/24 |
| S3 smoke (loopback, re-derived peer_ids) | PASS |

### The seam (contained to Codec/ + Identity/, no dispatch/transport/store changes)

- **`Codec/HashFormats.cs`** — `content_hash_format` registry (§1.2). `0x00` SHA-256
  (floor) + `0x01` SHA-384, both in-box; unknown/reserved → `unsupported_content_hash_format`.
- **`Codec/KeyTypes.cs`** — `key_type` registry (§1.5). `0x01` Ed25519 (NSec/libsodium)
  + `0x02` Ed448 (BouncyCastle 2.4.0, A-009) + `0xFE` experimental-test stub; dispatch
  by wire code **or** entity-data name (the two surfaces, v7.66). Canonical peer_id by
  the §1.5 **size-cutoff** rule (≤32B → identity-multihash `hash_type=0x00`; >32B →
  SHA-256-form `hash_type=0x01`).
- **Peer canonicalization (v7.65)** — `system/peer.data` is now `{key_type, public_key}`
  (2 fields, peer_id dropped from the hashable basis); `content_hash(system/peer)` is a
  pure fn of the keypair. **The legacy Ed25519 SHA-256-form peer_id `(1,1,SHA256)` is
  corrected to identity-multihash `(1,0,raw-pubkey)`** — the v7.66 cohort removal.
- **Format-aware decode** — `Entity.Decode` recomputes under the format the entity
  declares (wire-acceptance carve-out).
- Two independent crypto sources behind one seam (NSec Ed25519 + BouncyCastle Ed448);
  BouncyCastle Ed448 is **byte-identical** to the Go/Rust/Py cohort (and transitively to
  the Block-1 FFI Ed448) on seed `0x42` — RFC 8032 determinism, a hard equality.

### Byte-verified (agility harness, `test/EntityCore.Protocol.Agility/`)

`KEY-TYPE-ED448-1` (pubkey/peer_id/content_hash/114-B sig/verify) · `HASH-FORMAT-SHA-384-1`
(SHA-256 + SHA-384 content_hash on the 0xFE stub) · `MATRIX-M2/M3/M6` peer A&B (peer_id +
home-format content_hash, incl. SHA-384-home M3.A/M6.A) · reject paths (255 reserved,
0x42 unallocated, multi-byte-128, unknown name). **24/24.**

### Logged

- **A-009** — Ed448 = BouncyCastle (profile had no Ed448 lib); native-first + independent
  source; FFI-codec path noted as the documented alternative. → research + arch G2.
- **A-010** — codec-primitive content hash (opaque prefix + SHA-256, corpus mechanics) vs
  agility content_hash_format dispatch (family-selecting, reject-unknown) are two surfaces.
- Profile re-pinned `v7_version_pinned = 7.71`; `ed448_library` added.

## Part 2: S4 validate-peer core gate — IN PROGRESS (4 of 6 core categories green)

Oracles built fresh from go HEAD `9d97a5d` (v7.71-era, circl Ed448) →
`output/s4-oracles/{validate-peer,entity-peer}`. Run: build the Host project
**directly** (`dotnet build samples/.../Host.csproj`) before `--no-build` — the .sln
build does NOT refresh the Host's dependency dll (cost real time; see memory).

| Category | Baseline | Now | What was done |
|---|---|---|---|
| **encoding** | 6/6 | ✅ 6/6 | codec holds on the wire |
| **connectivity** | 20/22 | ✅ **22/22** | nonce-echo PoP enforcement (§4.6/F12): retain per-connection challenge nonce, reject non-echoing authenticate (401 invalid_nonce). Defeats cross-connection replay. |
| **security** | 21/22 | ✅ **22/22** | §3.3 split: missing author = auth-class → 401 `missing_author`; missing capability = authz-class → 403 |
| **multisig** | 1/9 (9-min HANG) | ✅ **10/10** (2ms) | total granter parsing ({signers,threshold}) + VerifyMultiSigRoot (§3.6 M3/§5.5 M4/M6) + dispatcher guaranteed-response wrapper |
| **type_system** | 1/302 | ✅ **107/302 (core green)** | 53/53 core types render byte-identical to the Go oracle (xUnit + live); the 191 fails are 100% the F17 extension over-demand (missing list == the 93 classified extension types + 4 provisional `substitute/*`). 0 core failures. Native render (reflection-style declarations + override table); seeded at `Bootstrap()`. |
| **handlers** | 15/57 | ✅ **24/57 (core green)** | connect 8/8, capability 8/8, tree 7/8; the lone core fail is `handler_tree_operations_match` (EXTENSION-TREE §9 ops over-demand, F18). Fix: `system/handler` dispatch entity's `interface` field is now **peer-relative** (`system/handler/{pattern}`, not absolute) → `*_interface_ref` pass. Other 20 fails + 8 skips = the 4 extension handlers (inbox/continuation/subscription/revision), excluded. |
| **negotiation** | (n/a) | ✅ **4/4 (NEW, green)** | §4.5: hello now advertises `hash_formats` (ecfv1-sha256/384) + `key_types` (ed25519/448); disjoint advertisements rejected 400 `incompatible_hash_format` / `unsupported_key_type`. Flexes the crypto-agility seam. |

Committed: nonce-echo+401/403 (`f2ca03e`), multisig (`3ced506`).

### Remaining work (the two big bodies)

1. **type_system — core type registry. ✅ DONE (core verdict green).**
   `src/EntityCore.Protocol/Types/{TypeDefinition,CoreTypeRegistry}.cs` declare the 53
   core types natively (FSpec builder + override table; single source of truth in code);
   `Bootstrap()` seeds them at `system/type/*`. `CoreTypeRegistryTests` diffs all 53
   `content_hash`es against the vector set → **53/53 byte-identical first run**. Live
   `validate-peer -category type_system`: **107 pass** (53×2 + listing), **191 fail =
   100% F17 extension over-demand** (0 core failures), report
   `output/s4-oracles/type_system.json`. Remaining work below is historical context for
   how it was reached.
   The v7.71 oracle (`runTypeSystem`) demands a byte-exact
   `system/type/<name>` for **all 150** of `RegisterCoreTypes` + connect/tree — match is
   `content_hash`-first (byte-identical → PASS, structural-only → WARN).
   - **Scope resolved → 53 core / 97 extension** (refined `status/S4-TYPE-SCOPE.txt`;
     supersedes the prior 131→106/25 guess). Core peer publishes core + operational +
     the type-system **bootstrap** (`system/type`, `field-spec`, `name`) only. The 97
     extension/type-extension demands are **G4 over-demand → excluded from the core
     verdict** (escalated **F17**, `research/stewardship/SPEC-FINDINGS-LOG.md`). Earlier
     "type defs are all core, G4 dissolves" read was itself corrected by the user: a core
     peer must NOT pre-publish extension vocab (extensions ship their own types+handlers).
   - **Design (cross-peer ruling, user):** render natively from the peer's own
     model (reflection + override table — single source of truth in code), NOT ingest
     bytes. Memory: `type-registry-render-design`, `type-registry-core-vs-extension`.
   - **Verification corpus generated:** `test-vectors/v0.8.0/type-registry-vectors-v1.{cbor,diag}`
     (all 150 rendered, byte-exact `content_hash` + ECF data) via
     `protocol-generator/shared/tools/dump-type-registry` (go container). The C# render
     diffs against this (S8 drift target).
   - **NEXT (renderer build):** C# `TypeDefinition`/`FieldSpec` model → `Entity.Create`
     ("system/type", data) using the byte-green `CanonicalCbor`; declare the 53 core types
     (mirror Go `core.go`, omitempty FieldSpec, semantic `type_ref` overrides); seed at
     `Bootstrap()` into `system/type/*` + the listing; xUnit diff of the 53 `content_hash`
     vs the vector set; then re-run `type_system` for the core-subset verdict.
2. **handlers — ✅ DONE (core green).** `HandlerRegistry` already seeded the
   N5 interface + dispatch entities and routes via a §6.6 tree-walk (`Resolve`); the only
   core gap was the dispatch entity's `interface` field being absolute — fixed to
   peer-relative. connect 8/8, capability 8/8, tree 7/8 (1 = EXTENSION-TREE-op over-demand,
   F18). The §6.1 native-binding / handlers-handler register op (A-007) is NOT gated by
   the handlers category (no register check) — it's extension-installation machinery,
   deferred. Extension handlers (inbox/continuation/subscription/revision) excluded.

## Full-suite triage — remaining CORE reds

Full run: **271 pass / 771 fail / 113 skip** across 38 categories — but the vast majority
of fails are extension categories/demands (see **F18**, the core-test-suite escalation).
Core categories now green: connectivity 22/22, encoding 6/6, type_system (core), handlers
(core), **negotiation 4/4 (new)**, multisig 10/10, crypto_agility 4/4. Remaining genuinely-
**core** reds, triaged:

3. **capability — 7/12 (4 fail, 1 warn). Biggest remaining core body.** Real features
   absent: `request_rejects_scope_widening` (§6.2 attenuation enforcement on request),
   `configure_writes_policy_entry` (v7.62 `:configure` → `system/capability/policy/{peer_pattern}`),
   `revoke_happy_path_writes_marker` (revoke → marker at `system/capability/revocations/{cap_hash}`),
   `revoked_cap_denied_on_use` (§5.1 `is_revoked`). Couples to F13 (`:delegate` input).
4. **authz — 3/7 (4 fail).** Mostly status-code carve-outs: `scope_exceeds_authority`
   (200→403, couples to cap attenuation), `unresolvable_grantee` (403→401, PR-3 carve-out),
   plus 2 that couple to EXTENSION-ROLE (`system/role:delegate`, in-flight revocation
   cascade) → partly F18 extension-coupled.
5. **peer_canonicalization — 5/7 (2 fail).** PEER-PATTERN-1/2 (§3.6 v7.65): cap pattern
   match against canonical runtime peer_id + lazy-canon Base58 mint for unknown peers.
6. **security — 21/22 (1 fail).** `handler_scope_denied` (§5.4 handler max_scope/
   internal_scope enforcement). Confirm not a regression from this session's changes
   (unlikely — touched type seeding + handler interface field, not scope checks).
7. **format_agility — 9/10 (1 fail).** `agility_unknown_1`: handshake with unsupported
   key_type `0xFD` returns `incompatible_protocol`; want 400 `unsupported_key_type`
   (different path than the negotiation key_types accept-set; a small targeted fix).
8. **tree_operations — ✅ core green.** `path_reject_empty_segment` (§1.4 R1) FIXED
   (`Paths.Canonicalize` rejects interior `//`). Core get/put/delete pass; the remaining
   ~29 fails are all EXTENSION-TREE §9 ops (snapshot/diff/merge/extract/tracked, F18).
   User wants explicit tree put/delete/flex tests folded into the core profile (F18).
9. **Matrix `root_cap` byte-match** (M2/M3/M6) — cap-token content_hash + signature;
   couples to the Capability model (item 3). Deferred from the agility harness.
10. **Final**: with F18 core profile (or the hand-maintained core scoreboard), drive the
    core verdict green.
