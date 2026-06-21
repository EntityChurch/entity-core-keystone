# entity-core-protocol-ocaml — Phase S1 (Profile) Summary

**Peer #3** (OCaml, spec-first / distant-idiom) · **Status: COMPLETE**

## Preconditions resolved at session start
- **Spec version.** Arch is still at v7.72 (the F12/v7.73 nonce-echo fold has NOT
  landed). Verified `ENTITY-CBOR-ENCODING.md` + `ENTITY-NATIVE-TYPE-SYSTEM.md` are
  byte-identical v7.71→v7.72 (SHA-256 match) → the v7.71 codec corpus is valid at
  v7.72, and F12 is a peer-layer concern. Operator confirmed "specs are clean" for
  the codec scope. Profile reads `spec-data/v7.72`; codec corpus `test-vectors/v0.8.0`.
- **No-peek discipline.** Derived from V7 + OCaml ecosystem only; did NOT open
  `protocol-generator/{csharp,typescript}/src/`. (Read `csharp/profile.toml` for the
  field *schema* only — explicitly endorsed by PHASE-S1; that is config structure,
  not spec interpretation.)

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** (overturns LANDSCAPE ffi-default) | spike → 69/69 first run |
| CBOR | **hand-rolled** | no opam lib gives ECF (A-005) |
| Ed25519 | mirage-crypto-ec 2.1.0 | audited, no libsodium |
| Ed448 | **deferred** (native gap) | mirage#112; A-OC-002 |
| SHA | digestif 1.3.0 | SHA-256 + SHA-384 |
| base58 / varint | hand-rolled | dep-minimization |
| Error model | **result** (poly-variant) | deliberate divergence from C#/TS exceptions |
| Async | **eio** | S6 decision, validated at S3; A-OC-003 |
| Naming | snake_case / Upper_snake modules | OCaml-native |
| Build / pkg | dune + opam; hand-rolled test harness | |
| License | Apache-2.0 | S9 default |

## Container
`containers/ocaml-toolchain/Containerfile` authored + built (fedora:43 → opam →
pinned OCaml 5.2.1 switch → pinned libs). All pins ≥30 days old (S11):
ocaml 5.2.1, dune 3.23.1, digestif 1.3.0, mirage-crypto{,-ec,-rng} 2.1.0
(~86d). Reproducible: clean rebuild from the pinned Containerfile
re-passes 69/69 + selftest.

## Ambiguity log
4 entries (A-OC-001..004). The payoff entry: **A-OC-004** — `format_code = 128` is
*emitted* on construction (`content_hash.4`) but *rejected* on receive
(`VARINT-MULTIBYTE-1`); the asymmetry is unstated in §4.3/§4.7. A genuine new probe
the spec-first OCaml pass surfaced — escalate to arch as a proposal candidate.

## Exit criteria
profile.toml fully populated (no TBD-blocking) · rationale written · container built +
reproducible · ambiguity log has no blocking-severity items (A-OC-002 Ed448 is
higher-bar, non-blocking for the codec floor). **S1 PASS.**
