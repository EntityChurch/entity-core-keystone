# Changelog — entity-core-protocol-java

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note (contrast with A-CL-010):** Maven's version grammar accepts a SemVer-style
> qualifier directly, so the `0.1.0-pre` release line is carried in `pom.xml` `<version>`
> idiomatically — unlike Common Lisp, where ASDF's dotted-integer-only `:version` forced the
> `-pre` marker into the CHANGELOG/README only (A-CL-010). Java needs no such split.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.72 + the v7.73/v7.74 peer-surface closeout**
(register / outbound-dispatch / emit live-hooks §6.13 + §PR-8 granter frame + §6.9a owner-cap
bootstrap + §7a conformance handlers); codec corpus v0.8.0 (byte-identical v7.71→v7.72, no wire
change).

First release line. Peer #7 (Java / JVM), the **9th byte-compatible core impl**, derived
**spec-first** in the cohort's mainstream static-OO idiom (records, sealed interfaces,
pattern-matching switch, checked exceptions, JDK-21 virtual threads). Not yet published — parked
at `-pre` pending architecture v0.1 sign-off + first external consumer (S5 promotion gate) AND
the Maven Central namespace-verification operator step (A-JAVA-005).

### Conformance
- `validate-peer --profile core`: **PASS** — 573 / 289P / 195W / **0F** / 89skip
  (machine-verified `summary.failed == 0`). A clean **superset** of the OCaml/CL 568 fixed
  point: the +5 is the §7b concurrency category, which at oracle HEAD `749e57e` runs and gates
  under `--profile core` (was a §9.0 drift carve-out at the older oracle); all 5 PASS.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first run, 0 codec fixes.
- origination-core: 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam cross-impl wire-proven).
- §9.5 53-type registry: 53/53 byte-identical (`TypeRegistryTest` + live oracle `type_system_match`).
- `mvn -o -B test`: 15 tests, 0 failures (codec corpus + Ed25519/Ed448/SHAKE256 KATs +
  type-registry byte-diff + two-peer loopback smoke 11/11).

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16⊂f32⊂f64 float minimization, length-then-lex
  map-key sort on encoded key bytes, recursive major-type-6 tag rejection, hand-rolled LEB128 +
  Base58 (neither in the JDK). CBOR head-form integer carrier via `BigInteger`, full 0..2⁶⁴−1
  (Java's `long` has no native unsigned).
- **Ed25519 AND Ed448 sign/verify native via the JDK SunEC provider** — zero-dependency core,
  no FFI, no BouncyCastle. SHA-256/384 via `MessageDigest`. Deterministic RFC-8032 signing →
  cross-impl signature byte-equality.
- **Hand-rolled FIPS-202 SHAKE256 + RFC-8032 raw-pubkey derivation** (A-JAVA-007) to close the
  JDK's two raw-public-key gaps (no SHAKE256 XOF, no seed→public-key API). KAT-verified byte-equal
  to the Ed25519 RFC-8032 TEST-1 pubkey, the agility `KEY-TYPE-ED448-1` pin, and BouncyCastle.
- §1.5 canonical-form peer_id construction (Ed25519 → `hash_type=0x00` raw-pubkey
  identity-multihash; Ed448 → `hash_type=0x01` SHA-256-of-pubkey), following the §1.5 v7.65 table,
  NOT the stale §7.4 pseudocode (A-JAVA-004). Seed-`0x11` peer_id byte-identical to the CL peer.
- §1.1 entity `data` generalized to an arbitrary ECF value (A-JAVA-010) — was map-only; scalar
  (`primitive/string`) data now stores/relays correctly (the §7b concurrency staging case).
- §4.1 handshake, §6.5/§6.6 single-dispatch handler ladder, capability authorization with chain
  attenuation + §5.7 delegation caveats, type registry (render-from-model, 53/53), in-memory
  address-space store with CAS, §9.5a CORE-TREE get/put/CAS/delete + listing-omit deletion markers.
- v7.73/v7.74 peer surface: §6.13 register's five normative writes, §PR-8 granter frame (V2(a)),
  §6.9a owner-cap bootstrap, §7a conformance handlers (`--validate`, off by default).
- §5.2 request verification as a three-way verdict (ALLOW / AUTHN_FAIL→401 / AUTHZ_DENY→403) +
  the §5.5 unresolvable-grantee→401 carve-out (A-JAVA-009).
- §7a `system/validate/dispatch-outbound` as a **generic relay** — forwards the `{value: X}`
  params verbatim and returns the downstream result entity verbatim (no re-wrap), per the
  §7b matrix ruling #2 (A-JAVA-011).
- Concurrency: JDK-21 **virtual threads** (Loom, JEP 444) — one reader vthread per connection +
  one vthread per inbound EXECUTE; `ConcurrentHashMap` rendezvous demux; per-connection write
  lock; transport-agnostic dispatch brain (A-JAVA-003). All 5 §7b concurrency checks PASS.

### Known limitations
- **Maven Central publishing deferred** — requires a verified `org.entitycore` reverse-DNS
  namespace (DNS TXT / hosting proof) before the first `mvn deploy` (A-JAVA-005). The artifact
  is publish-ready (`0.1.0-pre` coordinates, license metadata, zero-dep runtime); the deploy is
  an operator action.
- Crypto-agility **full MATRIX** (the M2/M3/M6 cross-product corpus) is a cohort-wide deferral;
  the primitives (Ed448 + SHA-384) are S2-proven byte-equal and the connect-path slice is
  exercised, but the full agility matrix harness is not wired.
- Public API surface is documented (README §Use, package tiers), not yet frozen with an explicit
  `module-info` / semver lock — deferred to publish-prep / first external consumer.
- The v7.73/v7.74 peer-surface behavior is cohort+oracle-sourced, not from a SHA-pinned
  v7.73/v7.74 spec-data snapshot (which remains absent locally) — a byte-provenance gap (A-JAVA-001).
- The S4 oracle is built from in-flight Go HEAD `749e57e` (14 ahead of origin/main); the 573·0F
  superset (with §7b gating core) must be re-confirmed once that HEAD lands upstream (A-JAVA-011).

### Toolchain pins (S11)
- **Temurin JDK 21 LTS** (SHA-256-pinned from the Adoptium release; LTS, virtual threads GA).
- **Apache Maven 3.9.9** (SHA-512-pinned, verified on both downloads.apache.org and
  archive.apache.org/dist; reviewed-channel build tool, bundled into the toolchain image).
- **JUnit 5 (Jupiter) 5.11.4** + maven-surefire 3.5.2 — TEST-scope only (never shipped).
- **BouncyCastle `bcprov-jdk18on` 1.80** — `provided`-scope, OPT-IN agility cross-check ONLY;
  the core build is BouncyCastle-free. (BC 1.84 is under the ≥30-day floor — deliberately not picked.)

### Spec items surfaced (routed to architecture)
- **A-JAVA-004 ⚑** §7.4 NORMATIVE `derive_peer_id` (SHA-256-form) contradicts the §1.5 v7.65
  canonical-form table (identity-multihash, `hash_type=0x00`). A literal §7.4 reader fails every
  handshake. **FOURTH spec-first peer to corroborate** (after Zig A-ZIG-001, OCaml A-OC-007, CL
  A-CL-002).
- **A-JAVA-009 ⚑** §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403)
  request-time boundary. **FIFTH peer to hit this** (OCaml A-OC-008 / arch F20, Zig A-ZIG-006).
- **A-JAVA-010 ⚑** §1.1 entity `data` is an arbitrary ECF value (not necessarily a map); the
  map-only assumption passes S2/S3 then silently 500s on the first scalar-data entity (the §7b
  gate). NEW — recommend a scalar-data conformance vector.
- **A-JAVA-007 ⚑** the JDK leaves a raw-public-key gap (no SHAKE256 XOF, no seed→public API) for
  native Ed448, requiring a hand-rolled KAT-verified SHAKE256. NEW crypto-ledger data point.
- **A-JAVA-011 ⚑** §7b concurrency now gates `--profile core` at oracle HEAD `749e57e` (568→573);
  §7a dispatch-outbound is a generic verbatim relay. Re-confirm when `749e57e` lands upstream.
- **A-JAVA-001** v7.73/v7.74 spec-data snapshot missing — byte-provenance gap (corroborates
  A-CL-001).
- **A-JAVA-005** Maven Central namespace verification — packaging note (operator).
- **A-JAVA-008** (CLOSED) full 53-type registry + real type-validate body landed; 53/53.
- **A-JAVA-002 / -003 / -006** (RESOLVED) crypto sourcing / concurrency / Maven sha512.
