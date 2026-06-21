# entity-core-protocol-ocaml — Profile Rationale

Audit trail for every major S1 profile choice. OCaml is **peer #3**, the
spec-tightness "distant idiom": each choice below was derived from the V7 spec +
OCaml-ecosystem research, **not** ported from the C#/TS profiles. Where a value
matches a prior peer it is by independent arrival; the idiom seams deliberately
differ.

## Codec strategy: native (not the LANDSCAPE-default ffi)

`research/LANDSCAPE.md` had OCaml as T5/ffi. The S1 spike overturned that on
evidence: a hand-rolled canonical encoder reached **69/69 byte-identical** against
the v1 ECF corpus on the first run. This is the A-005 pattern both prior native
peers hit — a faithful ECF codec must own the canonical layer (length-then-lex map
ordering, shortest-float incl. f16, recursive tag rejection, full uint64 range)
regardless of what library sits underneath, so a CBOR library buys almost nothing.
Going native also keeps the peer dependency-light (two opam libs: digestif +
mirage-crypto-ec). `ffi` remains the documented fallback, and a **hybrid** (native
Ed25519 + FFI Ed448) is the likely shape if/when crypto-agility is in scope (see
Ed448 below).

## CBOR: hand-rolled (no opam library)

Surveyed: `cbor` (0.5 — old, no canonical mode), `cborl`, `orsetto`,
`decoders-cbor`. None offers ECF's deterministic guarantees. ECF needs an explicit
float node (shortest-float f16/f32/f64 minimisation), length-then-lex map-key
ordering on encoded key bytes, recursive major-type-6 tag rejection on decode, and
full uint64/nint range — all of which a general CBOR library either omits or
actively fights. Hand-rolling (`src/cbor.ml`) is both the faithful and the simpler
path. Spike-confirmed against the `map_keys` + `float` vectors before committing
(the kickoff's load-bearing codec risk) — they pass.

## Crypto: mirage-crypto-ec 2.1.0 (Ed25519)

`mirage-crypto-ec` is the audited, maintained OCaml EC library (pure OCaml over
fiat-crypto C; no libsodium dependency). It provides the Ed25519 floor with a clean
string-based API (`priv_of_octets` / `sign` / `verify`). Version **2.1.0**
(~86 days old — clears the S11 30-day cool-down). Pinned vs
the live opam registry per the F10 lesson (no phantom versions — verified resolvable
in-container).

## Ed448: deferred — native gap (A-OC-002)

mirage-crypto-ec **does not implement Ed448** (mirage/mirage-crypto#112, open since
2021), and OCaml has no mature pure-OCaml Ed448 nor a BouncyCastle-equivalent (the
route C# took). The 69-vector ECF floor is Ed25519-only and unaffected; only the
agility higher-bar Ed448 vectors are blocked. Deferred with a documented escalation
rather than a silent gap or an unaudited hand-roll.

## Hash: digestif 1.3.0

The standard OCaml hash toolbox; provides SHA-256 (content_hash floor) and SHA-384
(agility hashing) with a uniform API. Pinned 1.3.0 (Apr 2025, S11-clean).

## Base58 + varint: hand-rolled

Both are small and dependency-free. Base58 (Bitcoin alphabet, encode+decode,
`src/base58.ml`) for peer-id; LEB128 varints (`src/varint.ml`) for the N1 format-code
/ key-type / hash-type framing. Hand-rolling dodges two opam pins and matches the
dependency-minimization stance.

## Error model: result (deliberate divergence from C#/TS exceptions)

OCaml-native is `('a, error) result` with a polymorphic-variant error type — not
exceptions-by-default. This is exactly the idiom seam that *should* differ from the
two prior peers (both `exceptions`). The one internal exception
(`Cbor.Decode_error`, raised on tag/structure violations) is caught at the module
boundary and mapped to a result; exceptions never escape a public surface as control
flow. (S2 codec is mostly total functions; the result surface lands fully at S3.)

## Async: eio (deliberate S6 decision; validated at S3)

The OCaml analogue of C#-`Task` / TS-`Promise`. Chose **eio** (OCaml 5 effects-based,
direct-style structured concurrency) over Lwt/Async: the N6/N7 reentrancy invariants
(inbound processing concurrent with outbound dispatch; reentrant request_id demux)
map onto eio fibers + switches in direct style without monadic plumbing. Not
exercised by the codec (pure/synchronous) — validated at S3, with Lwt as the
conservative fallback. Logged A-OC-003.

## Naming: OCaml-native snake_case / Upper_snake modules

`lower_snake_case` for types and values, `Upper_snake_case` for modules and variant
constructors, one module per file. Differs from C# PascalCase and TS camelCase — the
correct OCaml idiom.

## Build / test / packaging: dune + hand-rolled harness + opam

`dune` is the universal OCaml build system (3.23.1, S11-clean). Tests are a
hand-rolled harness (`test/conformance.ml` + `test/selftest.ml`) — no test-framework
dependency, honoring the minimization stance; `alcotest` can be layered for a richer
S5 report later. Packaging targets opam.

## License: Apache-2.0 (S9 default)

OCaml's ecosystem is license-mixed (ISC/BSD/MIT common in the mirage sphere) but does
not strongly mandate one, so the repo's Apache-2.0 default (explicit patent grant)
stands.

## Spec version: read v7.72, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.72` (latest). The codec uses the
`test-vectors/v0.8.0` corpus because `ENTITY-CBOR-ENCODING.md` and
`ENTITY-NATIVE-TYPE-SYSTEM.md` are **byte-identical** v7.71→v7.72 (SHA-256 verified)
— no wire-format change — so the v0.8.0 corpus is valid at v7.72. The F12/v7.73
nonce-echo fold is a peer-layer (§4.6 authenticate) concern, not a codec one, and is
resynced at S3.
