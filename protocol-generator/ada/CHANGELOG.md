# Changelog — entity-core-protocol-ada

All notable changes to this peer. Spec-version tracked literally per the keystone
lifecycle (S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version-line note (Alire / SemVer).** Alire's crate `version` accepts a SemVer-style
> pre-release qualifier directly, so the `0.1.0-pre` line is carried in `alire.toml`
> `version` idiomatically — unlike Common Lisp, where ASDF's dotted-integer-only `:version`
> forced the `-pre` marker into the CHANGELOG/README only (A-CL-010). Ada needs no such split.

## [0.1.0-pre]

**Tracks ENTITY-CORE-PROTOCOL-V7 v7.75** (spec-data/v7.75 — the current-state surface:
peer_id §1.5 / hex-case / §5.2 401/403 trichotomy / A-JAVA-010 data-model / §4.10(b) 400
chain-depth / `resource_bounds` / `concurrency`, all verified directly in spec-data/v7.75 at
S1); codec corpus v0.8.0 (ENTITY-CBOR-ENCODING.md is byte-stable v7.71→v7.75, SHA-verified by
the cohort — no wire-format change in the v7.72–v7.75 folds).

First release line. **Peer #10** (Ada 2012/2022, GNAT — the cohort's safety-critical /
strong-typing member; sibling of the C peer in the parallel batch), the **10th byte-compatible
core impl**, derived **spec-first** (no sibling-language source) in two idiom axes no prior peer
exercised: **tasks + protected objects + rendezvous** concurrency, and **design-by-contract**
(Pre/Post/Type_Invariant aspects). Not yet published — parked at `-pre` pending architecture
v0.1 sign-off + a first external Ada consumer (the S5 promotion gate); the `alr publish`
crate-index submission is a deferred operator step (A-ADA-005).

### Idiom summary
- **Native hand-rolled canonical codec** — ECF (canonical-CBOR) encoder/decoder owned in-code
  (`Entity_Core.Codec.Cbor`): length-then-lex map-key sort on encoded key bytes, shortest-float
  ladder (f16 ⊂ f32 ⊂ f64), recursive major-type-6 tag rejection, definite lengths, full
  0..2⁶⁴−1 head-form range. Base58 + the multicodec LEB128 varint hand-rolled (no Ada CBOR
  library gives ECF's canonical guarantees; the Ada ecosystem has none).
- **libsodium via Interfaces.C** — Ed25519 sign/verify + SHA-256 over a thin, well-typed
  `pragma Import, Convention => C` binding (`Entity_Core.Crypto`); the sole runtime dependency,
  a system shared library. libsodium returns the raw 32-byte public key directly, so the §1.5
  identity-multihash peer_id needs no point-extraction step (contrast the JDK EdEC wrinkle).
- **Tasks + protected objects + rendezvous** — Ada's first-class in-language concurrency. The
  §4.8 store + tree index live inside a **protected object** (language-enforced mutual exclusion);
  one **task per connection** (GNAT maps tasks to OS threads, so a blocking read never stalls
  other connections); the §6.11/N7 request_id↔continuation demux and the shared-stream write
  serialization are themselves protected objects.
- **Design-by-contract** — Pre/Post/Type_Invariant aspects (Ada 2012+) guard internal invariants
  (a Content_Hash is exactly 32 bytes; a canonical buffer is well-formed; a peer_id is a valid
  multihash) — runtime-checked under `-gnata`, the static-rigor seam no prior peer had. SPARK
  formal proof is out of scope for v0.1 (the aspects are runtime guards, not discharged proofs).

### Conformance
- `validate-peer --profile core`: **PASS** — **576 total · 292P · 195W · 0 FAIL · 89 skip**
  at the v7.75 cohort baseline oracle `b30a589` (machine-verified `summary.failed == 0`,
  `status/CONFORMANCE-REPORT.json`). `resource_bounds` is an ACTIVE core category at `b30a589`
  (r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood
  WARN, SHOULD/external admission). `concurrency` is **5/5** — genuinely concurrent (no-head-of-
  line + sustained 10000-req load both PASS, not accidentally serialized).
- Codec (S2): **69/69** byte-identical to `conformance-vectors-v1`, first run, 0 codec fixes,
  plus 37/37 self-tests (Ed25519/SHAKE256 KATs).
- origination-core: **3/3** over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam cross-impl wire-proven).
- §9.5 53-type registry: **53/53** byte-identical (`type_system_match`, content_hash equality).
- S3 two-direction loopback smoke: GREEN (Scenario A 5/5, Scenario B 2/2) against the Go reference.

### Added
- Hand-rolled canonical-CBOR (ECF) codec (`Entity_Core.Codec.Cbor` / `.Value`): shortest-float
  minimization, length-then-lex map-key sort on encoded key bytes, recursive major-type-6 tag
  rejection, full uint64 head-form range. **Ada advantage — no unsigned trap:** Ada has native
  modular integer types (`Interfaces.Unsigned_64`), so the full uint64 range is native (unlike the
  C# `ulong` / Java `long` no-native-unsigned workaround). Hand-rolled Base58 + LEB128 varint.
- Ed25519 sign/verify + SHA-256 native via the libsodium Interfaces.C binding
  (`crypto_sign_seed_keypair` / `crypto_sign_detached` / `crypto_sign_verify_detached` /
  `crypto_hash_sha256`). Deterministic RFC-8032 signing → cross-impl signature byte-equality.
- §1.5 canonical-form peer_id construction (Ed25519 → `hash_type=0x00` identity-multihash, digest
  = the raw public key; **not** the stale §7.4 `SHA256(pubkey)` form, A-ADA-001). Lowercase
  `a-f` hex everywhere via a custom nibble→char table (Ada hex builtins default UPPERCASE; the
  case-sensitive §3.4/§3.5/§6.9a tree-path keys would 404 against the lowercase oracle otherwise
  — the A-CL-009 trap, pinned proactively as A-ADA-003).
- §1.1 entity `data` modeled as a **discriminated-record variant** over the full ECF value space
  (uint/nint/bytes/text/array/map/bool/null/float/simple; tag rejected), NOT an `Ada.Containers`
  map (A-ADA-009 / A-JAVA-010 — a map-only model passes S2/S3 then 500s on the first scalar-data
  entity at the live gate; Ada's strong typing makes this a load-bearing type-level decision).
- §4.1 handshake (incl. F12 per-connection nonce uniqueness / cross-connection replay reject),
  the §6.5/§6.6 single-dispatch handler ladder, capability authorization with chain attenuation,
  §6.2 capability request/configure/revoke + scope-widening reject, §10.1 dynamic register gate,
  §3.9 tree CAS (expected_hash → 409) + §6.3 delete + §1.4 path-flex + deletion-marker listing
  filter, §4.5 negotiation disjoint-set reject + §4.7 unknown-key-type reject.
- §9.5 53-type registry published from a generated canonical table
  (`Entity_Core.Protocol.Type_Registry`, generated by `tools/gen_type_registry.py` from the
  oracle's `types.RegisterCoreTypes`); 53/53 byte-identical content_hash.
- §6.11 dispatch-outbound reentry over the SAME inbound connection as a **generic relay**
  (forwards the `{value: X}` params bytes verbatim, returns the downstream result entity verbatim
  — RULINGS-CONCURRENCY-GATE-7b-MATRIX #2). A reentry-only child task avoids a per-request task
  storm under the §7b load gates.
- §4.10 resource bounds: r1 over-payload → `413 payload_too_large` (default 16 MiB) + keeps
  serving; r2 over-deep chain → `400 chain_depth_exceeded` (default 64) via the ~15-line §4.10(b)
  STRUCTURAL pre-check (walk parents, no signature work, BEFORE the authz walk) — MUST be 400, NOT
  403 (A-ADA-007); r3 connection flood → honest WARN (SHOULD / external admission).
- §5.2 request verdict trichotomy (401 authn / 403 authz / 401 unresolvable, A-ADA-008) mapped
  from the Ada exception lattice (`Authentication_Error`→401, `Authorization_Error`→403,
  `Chain_Depth_Exceeded_Error`→400, `Payload_Too_Large_Error`→413) at the dispatcher boundary.
- Concurrency: **tasks + protected objects + rendezvous** — the §4.8 protected-object store makes
  the store-race **structurally unrepresentable** (the cleanest §4.8 story in the 11-peer cohort;
  the C sibling's live heap race A-C-009 and the Zig/CL manual store-safety cannot occur here by
  construction); one task per connection (A-ADA-006); TCP_NODELAY on accepted sockets. All 5 §7b
  concurrency checks PASS, genuinely concurrent (5/5 under 10000-req sustained load, not serialized).

### Known limitations
- **Alire crate publish deferred** — `alr publish` requires an Alire community crate-index
  submission (the `repository_url` is TBD until first publish), the same shape as Java's Maven
  Central namespace gate (A-JAVA-005). The crate manifest (`alire.toml`) is publish-ready; the
  submission is a one-time operator action (A-ADA-005). The core build does NOT depend on Alire —
  gprbuild builds fully offline against the committed `.gpr`; Alire is the distribution channel only.
- **Ed448 / SHA-384 (crypto-agility higher bar) deferred** — libsodium has no Ed448 and ships
  SHA-256 + SHA-512 only (no SHA-384), the same gap OCaml (A-OC-002) and Zig (A-ZIG-002) hit. The
  §9.1 core floor needs only Ed25519 + SHA-256 (both in libsodium), so the defer is non-blocking;
  when taken the agility overlay comes via the libentitycore_codec C-ABI surface or an OpenSSL
  curve448 binding (`openssl-devel` is in the base image), NOT libsodium (A-ADA-002).
- Public API surface is documented (README §Use, the `Entity_Core.*` package tiers) but not yet
  frozen with an explicit visibility lock — deferred to publish-prep / first external consumer (the
  honest `0.1.0-pre` state; mirrors the Java public-surface / OCaml `.mli` deferral).

### Toolchain pins (S11)
- **GNAT (FSF GCC-Ada) `gcc-gnat-15.2.1-7.fc43`** + **`gprbuild-25.0.0-5.fc43`** + GCC
  `gcc-15.2.1-7.fc43` — the Fedora 43 distro channel (a reviewed vendor channel; exact NVR pins
  captured by `rpm -q` inside the built image). GCC 15.2 (~10 months
  old at authoring) — clears the ≥30-day cool-down. Full Ada 2012/2022 + contract-aspect support.
- **libsodium `1.0.22-1.fc43`** (+ `libsodium-devel-1.0.22-1.fc43`) — the ONLY runtime dep;
  system shared library via the Interfaces.C binding. Fedora 43 ships only 1.0.22; conformance-
  neutral vs the S1-draft 1.0.20 (high-level `crypto_sign_*`/`crypto_hash_sha256` byte-identical).
- **openssl-devel `3.5.4-3.fc43`** — present for the DEFERRED agility overlay only (A-ADA-002),
  not used by the core floor.
- **No Alire crates.** No CBOR/base58/varint/test-framework packages — all hand-rolled in-repo.

### Spec items surfaced (routed to architecture)
- **A-ADA-013** (RESOLVED, ⚑ mainline/arch) — the cohort scorecard's `62044c5` oracle label is
  off-by-one-commit; the true v7.75 oracle is the immediate child `b30a589`, which folds
  `resource_bounds` into `coreProfileCategories` → the real **576·0F·89S** (a clean `62044c5`
  build auto-skips `resource_bounds` under `--profile core` → 574·0F·90S). Independently
  corroborated read-only from oracle source + the live re-run; no doctoring, peer not rebuilt.
- **A-ADA-011** (implementation note) — EXECUTE `params` is an ENTITY wire-form
  (`params.data.entity`, not `params.entity`); a first cut reading `key_type`/`nonce`/`public_key`
  off the params-map top level got `nonce-not-found → 401`. The biggest S4 fix cluster; not a spec
  defect (§3.2 does say params is entity-shaped), but a sharp wire-altitude trap.
- **A-ADA-010** (implementation note, conformance-neutral) — GNAT `-gnatVa` flags IEEE float
  specials (NaN/±Inf) as invalid data on perfectly canonical wire bytes; validity checks scoped-
  suppressed in the two float-bit codec bodies only (the design-by-contract aspects stay live).
- Pre-resolved inherited-settled corroborations: **A-ADA-001** (§7.4-vs-§1.5 peer_id, ⚑ arch),
  **A-ADA-003** (hex-case, ⚑ arch), **A-ADA-007** (resource_bounds 413/400/WARN), **A-ADA-008**
  (§5.2 401/403 trichotomy), **A-ADA-009** (§1.1 scalar `data`). No NEW blocking spec defect — the
  discovery well held DRY, as the honest S1 framing predicted.
- **A-ADA-002** (Ed448/SHA-384 agility defer — operator), **A-ADA-004** (gprbuild + hand-rolled
  runner, no Alire deps — operator), **A-ADA-005** (Alire publish — operator), **A-ADA-006**
  (RESOLVED — one task per connection), **A-ADA-012** (cosmetic grant-list duplication, cohort-
  consistent, non-blocking).
