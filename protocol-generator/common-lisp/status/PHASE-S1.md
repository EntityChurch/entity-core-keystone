# entity-core-protocol-common-lisp — Phase S1 (Profile) Summary

**Peer #5** (Common Lisp, spec-first / most-distant-idiom)
· **Status: COMPLETE (authored; container NOT built — S1 boundary)**

## Preconditions resolved at session start
- **Spec version.** Latest `spec-data` snapshot is **v7.72**; spec HEAD is v7.74
  (folded as proposal text). `ENTITY-CBOR-ENCODING.md` + `ENTITY-NATIVE-TYPE-SYSTEM.md`
  are byte-identical v7.71→v7.72 (SHA-verified upstream) → the v7.71 codec corpus is
  valid at v7.72. Profile reads `spec-data/v7.72`; codec corpus `test-vectors/v0.8.0`.
  The v7.73/v7.74 peer-layer folds are S3+ and do not affect S1/S2 (A-CL-001).
- **No-peek discipline.** Derived from V7 + Common Lisp / SBCL ecosystem only.
  Read the C#/TS/OCaml/Elixir `profile.toml` for the field *schema* (config
  structure, explicitly endorsed by PHASE-S1) and prior `SPEC-AMBIGUITY-LOG`s /
  agent-memory for cross-peer findings to corroborate — NOT for spec interpretation.
- **peer_id heads-up baked in early** — the §7.4-vs-§1.5 contradiction (A-ZIG-001 /
  A-OC-007) is pre-resolved in the profile so the S4 handshake cycle is not burned a
  third time (A-CL-002).

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** (fully native, incl. agility) | LANDSCAPE had no committed strategy; research lands native |
| CBOR | **hand-rolled** | no CL lib gives ECF (A-005, 5th time) |
| Ed25519 | **ironclad 0.61** | pure-Lisp, no libsodium/OpenSSL |
| **Ed448** | **NATIVE via ironclad** | NO FFI — headline contrast w/ OCaml (A-OC-002); matches Elixir but pure-Lisp |
| SHA-256/384 | ironclad digests | floor + agility hashing |
| base58 / varint | hand-rolled | dep-minimization |
| Integers | **native bignum** | NO uint64 head-form trap (matches Elixir; vs OCaml int63 / C# ulong / TS bigint) |
| Error model | **conditions + restarts** | most expressive of the 5; diverges from exceptions/result/tagged-tuple |
| Concurrency | **native SBCL threads** (sb-thread) | one-thread-per-conn; A-CL-003; validated S3 |
| Dispatch | **CLOS multiple dispatch** | the distant-idiom probe; S3 |
| Naming | lisp-case / earmuffs | CL-native; case-insensitive reader caveat noted |
| Build / pkg | ASDF + Quicklisp; hand-rolled harness | ASDF ships in SBCL |
| License | Apache-2.0 | S9 default |

## Container
`containers/common-lisp-toolchain/Containerfile` **authored, NOT built** (S1
boundary). fedora:43 → source-build **SBCL 2.6.4** (bootstrapped by stock fedora
sbcl, then bootstrap removed) → pull **ironclad 0.61** via the pinned **Quicklisp
2026-01 dist** at build time into an offline-resolvable on-disk registry. Build
asserts: SBCL 2.6.4 on PATH, ASDF bundled, ironclad ed25519+ed448+sha256+sha384
present (fails loudly otherwise). Pins (S11): SBCL 2.6.4 (~45d —
2.6.5 at ~15d is under the floor); ironclad 0.61 (2024-08, ~22mo); QL dist 2026-01.
SBCL source-tarball SHA-256 is a placeholder to verify at first build (A-CL-006,
phase-boundary-correct).

## Ambiguity log
7 entries (A-CL-001..007). Headline:
- **A-CL-002** — §7.4 stale peer-id pseudocode vs §1.5 canonical-form table;
  **third spec-first peer** to corroborate A-ZIG-001 / A-OC-007. Pre-resolved in the
  profile (use §1.5 `hash_type=0x00` identity-multihash, raw pubkey).
- **A-CL-005** — pure-Lisp Ed448 trust surface; gate on RFC-8032 KAT byte-equality
  at S2 before trusting the agility corpus (verification note, not a gap).
- **A-CL-007** — carries forward A-OC-004's `format_code=128` construct-vs-receive
  asymmetry to re-confirm from the CL side at S2.

## Crypto-agility / Ed448 verdict for Common Lisp
**Fully native, no FFI.** ironclad implements Ed448 + SHA-384 in pure Lisp, so
unlike OCaml (which had to source Ed448 over the C-ABI, A-OC-002) the agility higher
bar is reachable from the default build. This is the **second peer (after Elixir) to
reach the agility bar natively** — and the first to do so via a pure-Lisp crypto
library rather than an OpenSSL-backed runtime. The only attached caveat is the
larger trust surface of pure-Lisp curve math → RFC-8032 KAT gate at S2 (A-CL-005);
hybrid-FFI (the OCaml route) is the documented fallback if the KAT ever fails.

## Exit criteria
profile.toml fully populated (no TBD-blocking — only `repository_url` empty, which is
TBD-on-first-publish, the same as OCaml/Elixir) · rationale written · container
**authored** (build deferred to S2 per the S1 boundary) · ambiguity log has no
blocking-severity items (A-CL-005 Ed448 KAT and A-CL-006 SBCL checksum are S2
verification tasks, non-blocking for S1). **S1 PASS.**

## What S2 (codec) needs to know going in
1. **Build the container first** and fill the SBCL source-tarball SHA-256 (A-CL-006)
   — the build fails closed until then. Confirm the exact Quicklisp dist tag that
   ships ironclad 0.61 (A-CL-004); the build assertion catches a mismatch.
2. **Hand-roll the ECF codec** (`src/cbor.lisp`) — octet-vector encoder + index-walk
   decoder; length-then-lex map ordering, shortest-float ladder (incl. f16),
   recursive tag-6 reject. Spike the `map_keys` + `float` vectors first.
3. **Carry CBOR integers as native bignums** — no width special-casing (the CL
   advantage; corpus `int.10` = 2^63-1 and the full uint64 range are free).
4. **peer_id = §1.5 canonical form** (`hash_type=0x00`, raw pubkey) — A-CL-002. Do
   NOT implement the §7.4 SHA-256-form as the construction path.
5. **Gate Ed448 on RFC-8032 KAT byte-equality** before trusting it for the agility
   corpus (A-CL-005). Ed25519 + SHA-256/384 are the floor; verify symbol/signatures
   of `ironclad:{make-private-key,sign-message,verify-signature,digest-sequence}`
   against the in-container 0.61 (the spelling in the profile is the expected API).
6. **Keep external string/byte data case-EXACT** — never round-trip wire data
   through CL symbols (the case-insensitive-reader footgun).
7. **Re-confirm A-CL-007** (`format_code=128` construct-vs-receive) from the fresh CL
   derivation; if it lands on the same A-OC-004 resolution independently, that is
   additional corroboration for the arch proposal.
