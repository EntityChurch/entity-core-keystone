# entity-core-protocol-ada — Phase S1 (Profile) Summary

**Peer #10** (Ada — safety-critical / strong-typing; the
distant-idiom probe: tasks + protected objects + rendezvous concurrency, design-by-
contract; parallel cohort with the C peer) · **Status: COMPLETE (authoring) — container
NOT built (S1 boundary)**

## Preconditions resolved at session start
- **Spec version.** Read `spec-data/v7.75` (the latest snapshot). The current-state-menu
  items were verified **directly in spec-data/v7.75** (see "verified-in-spec" below).
  Codec corpus = `test-vectors/v0.8.0` (the latest test-vectors snapshot);
  `ENTITY-CBOR-ENCODING.md` is byte-stable v7.71→v7.75 (the v7.72–75 folds are peer-layer
  resilience/resource-bounds, no wire-format change; the cohort SHA-verified this), so the
  v0.8.0 corpus is valid at v7.75.
- **Verified in spec-data/v7.75 (not assumed):**
  - **peer_id** — `ENTITY-CORE-PROTOCOL-V7.md` **line 459** (§1.5 canonical-form table):
    `0x01 Ed25519 → 0x00 identity-multihash … The digest IS the public_key (v7.64)`. §7.4
    reconciled to defer to §1.5 (v7.73 §E1). (A-ADA-001.)
  - **resource_bounds** — lines 1933–1935 (the (a)/(b) MUSTs + (c) SHOULD), 1950–1951 (the
    status table: `payload_too_large` 413, `chain_depth_exceeded` **400** "non-authz by
    design"), 4036 + 4092 (§9.1 floor + the `resource_bounds` category). (A-ADA-007.)
  - **§4.8 store-safety / §4.9 resilience** — lines 1909, 1915, 1927, 4036, 4091 (the
    v7.75 non-functional floor; the §7b `concurrency` category gates it). (A-ADA-006.)
  - **§5.2 verdict trichotomy** — §E2 (the v7.73 three-way verdict + §5.2a status
    enumeration). (A-ADA-008.)
- **No-peek discipline.** Derived from V7 + Ada/GNAT ecosystem research. Read the cohort
  `{csharp, java, haskell, zig, common-lisp}` profile.toml + rationale/status for the field
  *schema and exemplar shape* only (endorsed by PHASE-S1) — config structure, not spec
  interpretation. Java is the closest precedent for the data-model + crypto-binding shape;
  Zig/CL are the store-race / hex-case precedents.
- **S1 boundary honored.** No podman run, no container build, no toolchain install, no
  compile. Authoring only. (Toolchain/library release dates were read from upstream
  release announcements + Fedora package metadata — a metadata lookup, not a build/fetch.)

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| GNAT | **gcc-gnat 15.2.1-2.fc43** (Fedora 43 distro) | GCC 15.2 upstream (~10mo); Fedora pkg built (~9mo) — ≥30-day-clean. Full Ada 2012/2022 + contract aspects. Distro = reviewed channel; matches fedora:43 base exactly |
| Codec strategy | **native** | A-005 pattern; libsodium C binding for crypto + hand-rolled canonical CBOR → ONE runtime dep (system libsodium); lightest tier with Zig/Elixir/Java |
| CBOR | **hand-rolled** (Entity_Core.Codec.Cbor) | no Ada lib gives ECF (RFC-7049 length-first ≠ RFC-8949 bytewise); float ladder + tag-reject owned regardless. Ada modular ints → NO uint64 unsigned trap (advantage) |
| Ed25519 + SHA-256 | **libsodium via Interfaces.C** | `crypto_sign_seed_keypair`/`_detached`/`_verify_detached`, `crypto_hash_sha256`. Raw 32-byte pubkey returned directly (NO point-extraction — contrast Java EdEC). RFC-8032 deterministic. The §9.1 floor needs ONLY these |
| Ed448 + SHA-384 | **DEFERRED to the agility overlay** | libsodium has NO Ed448 and NO SHA-384 (SHA-256+512 only) — same gap as OCaml(C-ABI)/Zig(flat). Core floor unaffected. Agility via C-ABI or OpenSSL curve448 when taken. A-ADA-002 |
| base58 / varint | hand-rolled | dep-minimization |
| Data model | **discriminated-record variant** for the ECF value; `data` is an arbitrary ECF value, NOT a map | A-JAVA-010 inherited + made pointed by Ada strong typing — the decision most likely to bite at S4. A-ADA-009 |
| Error model | **exceptions + design-by-contract aspects** (`Entity_Core_Error`) | exceptions per failure class + Pre/Post/Type_Invariant/Predicate runtime-checked guards — the static-rigor seam no prior peer had. SPARK out-of-scope v0.1 |
| **Concurrency** | **tasks + protected objects + rendezvous**; §4.8 store behind a **protected object** | THE standout axis — no prior peer's shape. Language-enforced mutual exclusion = cleanest §4.8 story in the cohort (Zig/CL store-races structurally unrepresentable). TCP_NODELAY set. Task topology → S3. A-ADA-006 |
| Naming | Mixed_Case_With_Underscores (all kinds); lowercase-dotted files | Ada-native (case-insensitive; no screaming-snake idiom) |
| **Hex-case** | **LOWERCASE pinned** (custom nibble→char table) | Ada hex builtins (`Integer'Image`, `16#..#`, `Integer_IO Base=>16`) default UPPERCASE → A-CL-009 trap; CL log explicitly names Ada. Pinned proactively. A-ADA-003 |
| Build / test / pkg | gprbuild + .gpr + hand-rolled runner; Alire (optional S5) | no Alire deps for core → fully offline `--network=none`. AUnit avoided (extra dep). A-ADA-004/005 |
| License | Apache-2.0 | S9 default; GNAT compiler GPL-w/-exception does not bind the generated output |

## Crypto + GNAT pins with release dates
- **GNAT: gcc-gnat 15.2.1-2.fc43** — GCC 15.2 upstream (~10mo); Fedora 43
  package `gcc-15.2.1-2.fc43` built (~9mo). ≥30-day-clean. Exact NVR pin.
- **libsodium 1.0.20** — ~24mo old. ≥30-day-clean. System shared lib
  (`libsodium-devel`, already in `containers/base`), consumed via Interfaces.C binding.
- **Fedora 43** — base image OS / toolchain channel (matches `containers/base`).
- **No Alire crates, no CBOR/base58/varint/test-framework packages** — all hand-rolled.

## Container
`containers/ada-toolchain/Containerfile` **authored, NOT built** (S1 boundary).
`fedora:43` base → `dnf install gcc-gnat gprbuild libsodium-devel` (+ the
download/build basics) — all pinned to the Fedora 43 distro versions (the NVRs are
recorded as the dnf-metadata pins; the exact `gcc-gnat` NVR `15.2.1-2.fc43` is asserted
and re-confirmed at the S2 build from the image's `dnf` metadata, the distro-channel
analogue of the Java/Temurin sha pin). Chosen over an AdaCore Alire `gnat_native` toolchain
or a from-source GNAT because the distro package **matches the fedora:43 base exactly**,
needs no tarball/sha juggling, and keeps the toolchain consistent with the base image's
existing `gcc`/`libsodium-devel`. The core build is fully offline (`--network=none`): no
Alire registry resolve (no crate deps). Mirrors the structure of
`containers/base/Containerfile` + the distro-install pattern.

## Ambiguity log
9 entries (A-ADA-001..009), **none blocking** the codec floor:
- **A-ADA-001 (PRE-RESOLVED, settled ⚑):** peer_id from §1.5 canonical-form table (raw
  pubkey, hash_type 0x00), NOT the stale §7.4 SHA-256 form. Verified spec-data/v7.75 line
  459. 5+-peer corroboration — arch escalation re-stated, non-new.
- **A-ADA-002:** Ed448 + SHA-384 deferred to the agility overlay (libsodium has neither);
  §9.1 core floor unaffected. Operator/agility decision, non-blocking.
- **A-ADA-003 (PRE-RESOLVED):** hex-case LOWERCASE pinned — Ada hex builtins default
  UPPERCASE (the A-CL-009 trap; CL log names Ada). Local fix = lowercase helper.
- **A-ADA-004:** build = gprbuild + hand-rolled runner (no Alire deps, no AUnit). Operator.
- **A-ADA-005:** Alire crate publish needs crate-index submission; deferred to S5. Operator.
- **A-ADA-006:** concurrency — protected-object store FIXED now; task topology → S3. Operator.
- **A-ADA-007 (PRE-RESOLVED):** resource_bounds — 413 payload / **400** chain-depth / 503
  conn-flood-SHOULD. Verified spec-data/v7.75 lines 1933-1951/4036/4092. Settled v7.75.
- **A-ADA-008 (PRE-RESOLVED):** §5.2 verdict trichotomy 401/403/401-unresolvable. Settled.
- **A-ADA-009 (PRE-RESOLVED, load-bearing):** entity `data` is an arbitrary ECF value, NOT
  a map (A-JAVA-010) → discriminated-record variant. The decision most likely to bite at S4.

**No new spec defect surfaced at S1** — consistent with the dry well (8+ prior peers, no
new v7.75 defect). The Ada idiom axes (protected-object store, contract aspects) map
cleanly onto V7 — a spec-tightness signal, not a finding.

## Exit criteria
profile.toml fully populated (no TBD) · rationale written (one paragraph per major choice:
CBOR, crypto+pin+date via C-interop, error model, tasking/protected-object concurrency,
design-by-contract, codec_strategy, container) · `containers/ada-toolchain/Containerfile`
authored (build deferred to S2 per the S1 boundary) · ambiguity log initialized, no
blocking-severity items (A-ADA-002 Ed448 is the agility higher bar, non-blocking for the
core floor; peer_id/hex-case/data-model/400-chain-depth/401-403 all pre-resolved).
**S1 PASS (authoring).**

## Time spent
~1 session (single S1 authoring pass): spec-data verification of the current-state menu,
Ada/GNAT ecosystem + pin-date research (GNAT/GCC 15.2, libsodium 1.0.20, gprbuild, Alire),
and authoring of profile.toml + PROFILE-RATIONALE.md + SPEC-AMBIGUITY-LOG.md + PHASE-S1.md
+ the ada-toolchain Containerfile.

## What S2 should tackle first
1. **Build the ada-toolchain image** (the deferred S1 build): `dnf install gcc-gnat
   gprbuild libsodium-devel`; confirm the exact `gcc-gnat` NVR from the image's dnf
   metadata and re-pin it (the distro-channel analogue of verifying the Temurin sha).
   Smoke: `gnatmake --version`, `gprbuild --version`, link a trivial libsodium binding.
2. Run the **codec spike** before the full build: hand-roll `Entity_Core.Codec.Cbor` enough
   to push the `map_keys` + `float` v7.71 vectors through the ECF encoder and assert
   byte-identity (the load-bearing canonical risk — shortest-float f16 + length-then-lex
   ordering on encoded key bytes). Watch the Ada seams: use `Interfaces.Unsigned_*` for
   wire scalars (modular ints → full uint64 range, NO C#/Java unsigned trap); render all
   address-space hex with the **lowercase** nibble→char helper (NEVER `Integer'Image` /
   `Integer_IO Base=>16` — A-ADA-003); model the ECF value as a **discriminated record**
   (entity `data` is an arbitrary ECF value, NOT a map — A-ADA-009).
3. Stand up the **libsodium Interfaces.C binding** (Ed25519 + SHA-256): KAT-verify
   `crypto_sign_seed_keypair` / `_detached` / `_verify_detached` / `crypto_hash_sha256`.
   Construct the peer_id per **§1.5** (raw pubkey, hash_type 0x00 — A-ADA-001), NOT §7.4;
   libsodium returns the raw pubkey directly so no point extraction is needed. The corpus
   won't catch a wrong peer_id construction (opaque digests) — it only blows up at the S4
   handshake.
4. (S3) Build the §4.8 store behind a **protected object** and the ~15-line §4.10(b)
   chain-depth structural pre-check (max 64, before the authz walk — A-ADA-007); decide the
   task topology (one-task-per-conn vs bounded pool — A-ADA-006); set TCP_NODELAY.
