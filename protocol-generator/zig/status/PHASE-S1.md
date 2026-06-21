# entity-core-protocol-zig — Phase S1 (Profile) Summary

**Peer #4** (Zig, spec-first / distant-idiom systems language) · **Status: COMPLETE (authoring) — container NOT built (S1 boundary)**

## Preconditions resolved at session start
- **Spec version.** Read `spec-data/v7.72` (latest available). Per the OCaml S1
  finding, `ENTITY-CBOR-ENCODING.md` + `ENTITY-NATIVE-TYPE-SYSTEM.md` are byte-identical
  v7.71→v7.72 (no wire-format change), so the v7.71 codec corpus is valid at v7.72.
  Profile reads `spec-data/v7.72`; codec corpus `test-vectors/v0.8.0`.
- **No-peek discipline.** Derived from V7 + Zig ecosystem only; did NOT open prior
  peers' `src/`. Read `{csharp,ocaml}/profile.toml` + the OCaml rationale/status for
  the field *schema and exemplar shape* only (explicitly endorsed by PHASE-S1) — that
  is config structure, not spec interpretation. OCaml is the closest precedent
  (native, distant idiom) and the deliberate model.
- **S1 boundary honored.** No podman run, no build, no toolchain install, no container
  executed. Authoring only.

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Zig version | **0.15.1** (pinned) | settled release; ~10mo old (S11-clean); over 0.16.0 beta. 0.15.x = "Writergate" std.Io rework — an S3 seam, not codec |
| Codec strategy | **native** | A-005 pattern; and std.crypto makes the peer std-ONLY (lighter than OCaml) |
| CBOR | **hand-rolled** (src/cbor.zig) | no std CBOR; no Zig lib gives ECF; comptime dispatch |
| Ed25519 | **std.crypto.sign.Ed25519** | in std, audited, RFC-8032 deterministic; pinned by toolchain |
| Ed448 | **deferred** (native gap) | same gap as OCaml A-OC-002; no pure-Zig/BouncyCastle equiv; A-ZIG-002 |
| SHA | std.crypto.hash.sha2 (256 + 384/512) | in std |
| base58 / varint | hand-rolled | std-only / dep-minimization |
| Error model | **error unions** (`!T`, `CodecError`) | deliberate divergence from C#/TS exceptions AND OCaml result; OOM is a first-class error member |
| Memory | **no GC, explicit std.mem.Allocator** | the headline Zig seam; leak-checked tests |
| Async | **threaded** (std.Thread) | not exercised by codec; validated at S3; Zig async in flux; A-ZIG-003 |
| Naming | PascalCase types / camelCase fns / snake_case values | Zig-native |
| Build / test / pkg | zig build + in-language tests + build.zig.zon (decentralized) | no external framework |
| License | Apache-2.0 | S9 default |

## Container
`containers/zig-toolchain/Containerfile` **authored, NOT built** (S1 boundary).
fedora:43 base → official ziglang.org 0.15.1 tarball, **minisign-verified** against
the pinned Zig project pubkey + sha256-pinned (sentinel sha256 placeholder; the
build fails closed until the real digest is filled at S2 — chosen over `dnf install
zig` because Fedora 43 carries 0.16.0 in updates-testing, not the pinned 0.15.1).
Single toolchain pin; no third-party packages (std-only peer).

## Ambiguity log
3 entries (A-ZIG-001..003), none blocking the codec floor:
- **A-ZIG-001 (NEW PROBE, escalate to arch):** §7.4 NORMATIVE `derive_peer_id`
  pseudocode (SHA-256-form, `hash_type=0x01`, digest = SHA256(pubkey)) **contradicts**
  the §1.5 canonical-form table (Ed25519 → `hash_type=0x00` identity-multihash, digest
  IS the raw pubkey). Independently re-surfaced by deriving from V7 fresh —
  corroborates OCaml A-OC-007 from a second spec-first peer. §7.4 is stale.
- **A-ZIG-002:** no native Ed448 in Zig std; agility higher-bar gap (mirrors A-OC-002).
- **A-ZIG-003:** async = threaded (Zig's colorless async removed; std.Io model in flux);
  S3 decision, recorded so S3 doesn't re-litigate silently.

## Exit criteria
profile.toml fully populated (no TBD-blocking) · rationale written · container
specified+authored (build deferred to S2 per the S1 boundary) · ambiguity log has no
blocking-severity items (A-ZIG-002 Ed448 is higher-bar, non-blocking for the codec
floor). **S1 PASS (authoring).**

## What S2 should tackle first
1. Fill `ZIG_SHA256` in the Containerfile from ziglang.org/download/0.15.1/ and build
   + smoke-test the toolchain image (the deferred S1 build).
2. Run the **codec spike** before the full build: hand-roll `src/cbor.zig` enough to
   push the `map_keys` + `float` v7.71 vectors through `encodeEcf` and assert
   byte-identity (the load-bearing canonical risk — shortest-float f16 + length-then-lex
   ordering). Green spike → proceed to the full encoder/decoder + base58 + varint +
   content_hash + signature, with `std.testing.allocator` leak-checking on from line one.
