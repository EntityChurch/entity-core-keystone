# entity-core-protocol-swift — Phase S1 Summary

**Peer:** #7 (Swift) · **Spec basis:** v7.74 (`spec-data/v7.74/`, freshly stamped) ·
**Phase:** S1 (research + profile authoring + container provisioning) ·
**Status:** COMPLETE — no blocking ambiguity items.

Swift is a *genuinely-spec-first* peer chosen to probe the two unsaturated discovery
axes from the six-peer synthesis: the **`String` grapheme/non-Int-indexable model**
(highest fresh yield) and **ARC** (3rd memory discipline). Protocol meaning was read
directly from `spec-data/v7.74/`; sibling *profiles* consulted for structure only.

---

## What I researched

- **spec-data/v7.74 (directly, spec-first):** §1.5 Identity / peer_id construction +
  canonical-form-per-key_type table; §7.3 signature computation (sign over full
  content_hash bytes; multicodec LEB128 varint framing); §7.4 peer_id derivation
  (`base58(varint(key_type) || varint(hash_type) || digest)`, Ed25519 = identity-form
  `0x01 0x00 || pubkey`); §8.1/§8.2 key-type + hash-format tables; ENTITY-CBOR-ENCODING
  §2.1 (text string length = UTF-8 bytes) + §2.2 (map keys sorted by encoded length
  then lexicographic over encoded bytes) + §4 (tags not part of ECF) + line 823
  (lowercase hex digest). MANIFEST: v7.71→v7.74 CBOR is byte-stable except the v7.73 E3
  decode-side erratum (no wire change) → v0.8.0 corpus valid at v7.74.
- **Swift toolchain:** release history + dates; Swift.org Linux tarball distribution
  (per-distro builds + detached GPG sig); Fedora-on-fedora:43 glibc compatibility.
- **Crypto:** swift-crypto (the Linux CryptoKit-API impl) API surface + release dates;
  Ed448 availability in BoringSSL/CryptoKit (gap); BoringSSL vendoring.
- **CBOR / base58 / varint:** Swift std + community libs vs ECF canonical requirements.
- **Build / test / packaging / error / async / memory / naming idioms** per Swift norms.

## Decisions + pinned versions (S11: each ≥30 days old)

| Surface | Decision | Pin | Age | S11 |
|---|---|---|---|---|
| Codec strategy | **native** (A-005: own the canonical layer; crypto native) | — | — | — |
| CBOR | **hand-rolled** ECF (zero CBOR dep) | in-repo | — | — |
| Toolchain | Swift **6.2-RELEASE**, fedora39 tarball | `6.2` | ~9 mo | ✅ |
| Ed25519 + SHA-2 | **swift-crypto** `Curve25519.Signing` + `SHA256/384/512` | `3.14.0` | ~10 mo | ✅ |
| swift-asn1 (transitive) | **explicit older pin** (auto-resolve = 1.7.1 @ 6 days = S11 breach) | `1.7.0` | ~59 d | ✅ |
| Ed448 | **DEFERRED** (native gap; hybrid-FFI later) | none | — | — | n/a (A-SW-001) |
| base58 / varint | hand-rolled | in-repo | — | — | — |
| Error model | typed **`throws`** + `CodecError` enum | — | — | — | — |
| Memory | **ARC**, value-type-default (struct/enum) | — | — | — | — |
| Async | **async/await + actors** (S3; codec sync) | — | — | — | — |
| Naming | Swift API Design Guidelines (UpperCamelCase / lowerCamelCase; `PeerID`) | — | — | — | — |
| Build / Test | **SwiftPM** / **XCTest** (bundled) | toolchain | — | — | ✅ |
| Publishing | SwiftPM git-tag (no central binary registry) | — | — | — | — |
| License | **Apache-2.0** (S9 default + ecosystem-norm) | — | — | — | — |

## Container build result — PASS (built + spike-verified, not just authored)

Per the S1 task contract for this peer (Swift-on-Fedora is the long pole), the
container was BUILT and PROVEN this phase.

- `podman build … containers/swift-toolchain/Containerfile` → **SUCCESS**.
- Verification fail-closed: detached **GPG signature** verified (Swift 6.x Release
  Signing Key, fingerprint `52BB 7E3D … EF80 A866 B47A 981F`) **AND** exact **sha256**
  pin matched (`4bcec3ee…4508`).
- `swift --version` → `Swift version 6.2 (swift-6.2-RELEASE)`, `Target:
  x86_64-unknown-linux-gnu` — the **fedora39** tarball runs on the **fedora:43** base
  (newer-glibc forward-compat confirmed empirically).
- **swift-crypto spike PASS** (throwaway SwiftPM package, pinned swift-crypto 3.14.0):
  `swift build -c release` compiled BoringSSL from source + linked; `swift run`:
    - `sha256("hello") = 2cf24dba…9824` ✅ (matches known digest)
    - `sha384(empty)` → 48-byte digest ✅
    - Ed25519 (`Curve25519.Signing`): pubkey 32 B, sig 64 B, **verify = true** ✅
    - **String-model probe:** `"café".count == 4` (graphemes) vs `.utf8.count == 5`
      (bytes) ✅ — the A-SW-002 trap confirmed live in-container.
- **Offline-after-resolve PASS:** with `Package.resolved` committed + `.build`
  populated, `swift build` runs under `--network=none` (green). Network is needed
  only for the toolchain pull + the one-time swift-crypto/swift-asn1 resolve.
- **S11 transitive-dep finding (A-SW-005):** SwiftPM auto-resolved swift-asn1 to 1.7.1
  (6 days old — breaches the 30-day floor); explicit 1.7.0 pin verified to satisfy
  swift-crypto 3.14.0 and resolve cleanly. This is the keystone payoff in miniature.

## Ambiguity-log entries opened (6, none blocking)

- **A-SW-001** — Ed448 native gap → DEFERRED (hybrid-FFI later); §9.1 floor unaffected. → research/agility.
- **A-SW-002** — Swift String grapheme/non-Int-index → wire ops use `String.utf8`/[UInt8]; map-key sort over encoded bytes. → operator (headline discipline).
- **A-SW-003** — CryptoKit Apple-only on Linux → swift-crypto is correct source. → operator (settled at S1).
- **A-SW-004** — XCTest over swift-testing → operator (revisitable at S2).
- **A-SW-005** — swift-asn1 transitive auto-resolve breaches S11 cool-down → explicit 1.7.0 pin. → operator/research (SwiftPM generator pattern).
- **A-SW-006** — §7a/§7b conformance scaffolding is GUIDE-carried, not spec-data → pick up at S3/S4. → research (track arch open-item).

## Spec-first observations (no NEW spec defects found at S1)

Reading v7.74 directly for profile-relevant facts surfaced no new spec contradiction
beyond the already-ledgered ones (peer-id §7.4-vs-§1.5 A-OC-007 neighborhood, hex-case
A-CL-009) — those are codec/peer-build-time findings, not S1-profile-visible. The §1.5
canonical-form table, §7.3 varint framing, and §7.4 derivation read cleanly and
unambiguously for the Ed25519 floor. The one Swift-specific spec-mapping judgment
(byte-vs-grapheme, A-SW-002) is a generation-discipline call, not a spec ambiguity — the
spec is explicit that lengths/ordering are byte/UTF-8-oriented.

---

## S2 entry checklist

1. **Container:** `entity-core-keystone/swift-toolchain:latest` — BUILT + verified. Dev
   loop: `podman run --rm -v $PWD:/work:Z -w /work/protocol-generator/swift
   entity-core-keystone/swift-toolchain:latest swift test`.
2. **Codec strategy:** `native` — hand-rolled canonical ECF CBOR + swift-crypto
   (Ed25519/SHA-256). Zero CBOR/base58/varint deps; those are in-repo.
3. **First spike (the S2 gate, cheap insurance per PHASE-S1-PROFILE):** push the
   `map_keys` + `float` ECF test-vectors (v0.8.0 corpus) through the hand-rolled encoder
   BEFORE the full build — confirm length-then-lex map-key ordering (over encoded UTF-8
   bytes), shortest-float incl. f16, and recursive major-type-6 tag rejection. If the
   spike fails, `ffi` is the documented fallback (not expected). The crypto+toolchain
   spike already passed at S1.
4. **String discipline (A-SW-002 — carry into every codec line):** text-string CBOR
   length = `String.utf8.count`; map-key sort over encoded `[UInt8]` (never `String`
   ordering); peer_id/digest hex display lowercase (§7.4, line 823). `String` is a
   UTF-8 carrier only — never `String.count`, never `Int` subscripting on wire data.
5. **Memory/idiom:** value types (struct/enum) for all codec data; `Sendable`-clean for
   Swift 6 strict concurrency; typed `throws(CodecError)` preferred (fall back to
   untyped if it fights). No force-unwrap (`!`) on wire data.
6. **Deps to pin in Package.swift + commit Package.resolved:** swift-crypto **3.14.0**,
   swift-asn1 **1.7.0** (explicit — do NOT let SwiftPM float it to 1.7.1, A-SW-005).
7. **Corpus:** v7.71 ECF test-vectors (valid at v7.74; CBOR byte-stable). Agility
   (Ed448/SHA-384) corpus gated on A-SW-001 (Ed448 deferred; SHA-384 IS native via
   swift-crypto and can be cross-checked).
8. **Oracle:** wire-conformance (pure codec) is the S2 ground truth — byte-identical to
   `entity-core-codec-ffi`. S2 is done when it says so (S5/S7).
9. **NOT in S2:** §7a/§7b conformance scaffolding (S3/S4, GUIDE-carried — A-SW-006); the
   peer machinery (S3); async/actor concurrency (S3, codec is synchronous).
