# entity-core-protocol-elixir — Profile Rationale

Audit trail for every major S1 profile choice. Elixir is **peer #4**, the second
"distant idiom" in the spec-tightness program (after OCaml). Each choice below
was derived from the V7 spec + Elixir/BEAM-ecosystem research, **not** ported
from the C#/TS/OCaml profiles. Where a value matches a prior peer it is by
independent arrival; the idiom seams deliberately differ.

## Codec strategy: native (overturns the LANDSCAPE-default ffi/enacl)

`research/LANDSCAPE.md` had Elixir as T2 with `cbor` (BEAM hex) + `enacl`
(libsodium) over an **ffi** codec. Research overturned **both halves** of that
default:

1. **Crypto is fully native and stdlib.** Erlang/OTP's `:crypto` module exposes
   EdDSA — **both Ed25519 and Ed448** — and SHA-256/384 directly, backed by the
   system OpenSSL (1.1.1+; fedora:43 ships OpenSSL 3.x). No `enacl`, no
   libsodium, no Hex dependency. Availability is queryable at runtime
   (`:crypto.supports(:public_keys)` lists `eddsa`). This is a *stronger* crypto
   position than any prior peer — including the agility higher bar (see Ed448
   below).
2. **No BEAM CBOR library gives ECF canonicality.** This is the A-005 pattern all
   three prior native peers hit: a faithful ECF codec must own the canonical
   layer (length-then-lex map ordering, shortest-float incl. f16, recursive
   major-type-6 tag rejection, full uint64/nint range) regardless of what library
   sits underneath. The `cbor` Hex package (and its `excbor` ancestor) does not
   offer these guarantees, and where it has a "deterministic" mode it targets RFC
   8949 §4.2 ordering — which is **not** ECF's RFC-7049 length-first ordering. A
   library buys almost nothing and actively fights the length-first rule.

Net result: a **core peer with zero runtime Hex dependencies** — leaner than
OCaml (2 opam libs). `:crypto` is stdlib; CBOR, base58, and varint are
hand-rolled; ExUnit (tests) is stdlib. `ffi` stays the documented fallback but is
not expected to be needed at any tier of this peer.

## CBOR: hand-rolled (no Hex library)

Surveyed: `cbor` (1.x and the 2.0.0-rc, a modernized `excbor` fork), `excbor`.
None offers ECF's deterministic guarantees. ECF needs an explicit float node
(shortest-float f16/f32/f64 minimization), **length-first** map-key ordering on
encoded key bytes (RFC 7049 order, which RFC 8949 renamed and de-emphasized),
recursive major-type-6 tag rejection on decode, and full uint64/nint range.
Hand-rolling (`lib/entity_core/cbor.ex`) is both the faithful and the simpler
path. The decoder is **binary pattern-matching**
(`<<major::3, info::5, rest::binary>>`) — the BEAM's single strongest idiom for a
wire parser, and a genuine ergonomic win over the prior peers' byte-index loops.
Spike the `map_keys` + `float` vectors at S2 before committing the full build
(the load-bearing codec risk), per the kickoff discipline.

## Crypto: OTP `:crypto` — Ed25519 (native, stdlib)

`:crypto` provides Ed25519 sign/verify/keygen over OpenSSL. The seed->pubkey
derivation V7 needs (§1.5 identity) is `crypto:generate_key(eddsa, ed25519,
Seed)`; signing is `crypto:sign(eddsa, none, Msg, [Seed, ed25519])`; verification
is `crypto:verify(eddsa, none, Msg, Sig, [Pub, ed25519])`. Deterministic by
construction (an Ed25519 property — no RNG in the signing path). Exact arity and
atom spelling are confirmed against the in-container OTP at S2 (the `:crypto` API
has several historical arities; pin the one the pinned OTP exposes). Audited via
OpenSSL; no third-party crypto in the trust base.

## Ed448: NATIVE via OTP `:crypto` — the headline contrast with OCaml

This is the standout result of peer #4. OCaml (peer #3) had **no** conformant
native Ed448 (`mirage-crypto-ec` issue #112) and no BouncyCastle-equivalent, so
it sourced `key_type 0x02` over the C-ABI in an opt-in `entitycore_agility`
sub-library (A-OC-002, resolved as hybrid FFI). Elixir needs **none** of that:
the same OpenSSL backend that serves Ed25519 serves Ed448
(`crypto:sign(eddsa, none, Msg, [Seed, ed448])`, 57-byte seeds, 114-byte
signatures). The crypto-agility higher bar (KEY-TYPE-ED448-*,
HASH-FORMAT-SHA-384-*) is reachable **from the default build** with no FFI, no
opt-in sub-library, and no hybrid split. The shipped peer stays self-contained
*and* fully agility-capable — a position no prior peer held.

## Hash: OTP `:crypto` — SHA-256 + SHA-384 (native, stdlib)

`crypto:hash(sha256, Data)` for the content_hash floor; `crypto:hash(sha384,
Data)` for agility hashing. Both stdlib via OpenSSL; no Hex dep.

## Base58 + varint: hand-rolled

Both are small and dependency-free. Base58 (Bitcoin alphabet, encode+decode,
`lib/entity_core/base58.ex`) for peer-id; LEB128 varints
(`lib/entity_core/varint.ex`) for the N1 format-code / key-type / hash-type
framing. Hand-rolling keeps the zero-runtime-dependency story intact.

## Error model: tagged tuples (deliberate divergence from all three prior peers)

Elixir-native is `{:ok, value}` / `{:error, reason}` tagged tuples on every
fallible public surface, paired with a `!`-suffixed raising variant (`encode!`,
`decode!`) for let-it-crash callers. This is a distinct seam from C#/TS
`exceptions` and even from OCaml's `result`: the tuple+bang **pair** and the
atom/struct reason vocabulary (`%EntityCore.Error{kind: :non_canonical_ecf, ...}`)
are idiomatically Elixir. Decode-path violations surface as `{:error, reason}`;
an internal raise inside the binary matcher (`EntityCore.Cbor.DecodeError`) is
caught at the module boundary and mapped to a tagged tuple — raises never escape
a non-bang public function as control flow.

## Concurrency: the BEAM actor model (the most distant idiom of the four)

Where C# used `Task`, TS used `Promise`, and OCaml used `eio` fibers, Elixir uses
**processes + message passing** — the BEAM actor model. This is the most distant
concurrency model in the program, and it maps onto the protocol's reentrancy
invariants more naturally than any prior peer:

- **N6** (inbound processing concurrent with outbound dispatch) — separate
  processes, scheduled by the runtime; no manual interleaving.
- **N7 / §6.11 reentry** (reentrant request_id demux; outbound EXECUTE back to the
  caller over the inbound connection) — one process per connection, a GenServer
  owning peer state, and request_id->caller correlation held in process state (or
  a `Registry`), with selective `receive` for response demux.

There is no explicit event loop and no monadic plumbing — the scheduler *is* the
runtime. `Task.async`/`await` exist but the peer architecture is
process/GenServer-based, not Task-based. Synchronous consumers go through
`GenServer.call`. Validated at S3 (the codec is pure/synchronous and
process-free); this is the §6.11-reentry-shaped seam that the §7a
`dispatch-outbound` conformance handler will exercise.

## Native arbitrary-precision integers: no head-form trap

A notable convergence-contrast worth recording for the eventual arch review: the
three-peer review's "integer head-form carrier re-derived through 3 different
native-int traps" (OCaml 63-bit int -> unsigned int64, C# `ulong`, TS `bigint`)
**does not occur on the BEAM**. Elixir/Erlang integers are arbitrary-precision
natively, so the CBOR uint64/int64 head-form is just an integer — no wrapping,
no widening, no bigint bridge. The 4th peer is the first to carry the full
integer range with no special-casing. (Flagged as an observation, not an
ambiguity — it is a language fact, not a spec gap.)

## Naming: Elixir-native PascalCase modules / snake_case everything else

`PascalCase` module names under the `EntityCore` namespace (`EntityCore.Cbor`,
`EntityCore.PeerId`, `EntityCore.Peer`); `snake_case` for functions, variables,
atoms, and files (`cbor.ex`, `peer_id.ex`). Differs from C# PascalCase-throughout,
TS camelCase, and OCaml lower_snake-types/Upper_snake-modules — the correct Elixir
idiom.

## Build / test / packaging: mix + ExUnit + Hex

`mix` is the universal Elixir build tool. Tests use **ExUnit**, which is *built
into Elixir* — so it is simultaneously the ecosystem standard AND a zero-added-
dependency choice. (This is a happier position than OCaml, where the
ecosystem-standard `alcotest` is an extra opam dep we declined for minimization;
here there is no tension.) The conformance harness is an ExUnit suite asserting
byte-identity against the normative fixtures; a thin `escript` runner is added at
S4 if the oracle loop needs a non-ExUnit entry point. Packaging targets Hex.

## Naming the package: peer id vs Hex id

The peer id under keystone naming is `entity-core-protocol-elixir`. Hex package
ids are idiomatic snake_case and a Hex package is implicitly a BEAM package, so
the registry id is `entity_core_protocol` (no redundant `_elixir` suffix). The
OTP application atom is `:entity_core_protocol`. Squatting/availability is checked
at S5 before first publish; if `entity_core_protocol` is taken, fall back to
`entity_core_protocol_elixir`.

## License: Apache-2.0 (S9 default)

Elixir core itself is Apache-2.0; the ecosystem is Apache-2.0/MIT-mixed with no
strong mandate, so the repo's Apache-2.0 default (explicit patent grant) stands.

## Container: source-built OTP 27.3.4 + precompiled Elixir 1.18.4

fedora:43's stock `erlang` package is OTP 26.x and lags the modern ecosystem, and
distro exact-NVR pins get garbage-collected from the stable repo (the
reproducibility problem node24 hit with distro Node). So `containers/beam`
**source-builds OTP from a pinned tarball** (OTP **27.3.4**, ~13
months old) configured against the system OpenSSL 3.x — which is also what
provides Ed25519 + Ed448 + SHA-2 to `:crypto` — and drops in the **precompiled
Elixir** release (**1.18.4**, ~10 months old, the precompiled-for-OTP-
27 build; Elixir is BEAM bytecode, so the precompiled zip is reproducible and
needs no compile). Both pins clear the S11 30-day floor comfortably. The
source-build is the heavy step (~10-15 min); it is the price of a reproducible,
S11-pure, Ed448-capable toolchain. Verified at first build (S2).

## Spec version: read v7.72 snapshot, codec corpus v0.8.0, peer resync to v7.74 at S3

Profile + codec derive from `spec-data/v7.72` (the latest available **snapshot**).
The codec uses the `test-vectors/v0.8.0` corpus because `ENTITY-CBOR-ENCODING.md`
and `ENTITY-NATIVE-TYPE-SYSTEM.md` are byte-identical v7.71->v7.72 — no wire
change. **Spec skew (A-ELX-001):** spec HEAD is v7.74 (folded), but snapshots stop
at v7.72; peers #1-3 reached v7.74 conformance against folded *proposal text*. The
v7.73 (nonce-echo §4.6) and v7.74 (register/outbound/emit/owner-cap §6.13/§6.9a +
§7a conformance handlers) folds are peer-layer (S3+), not codec, so S1/S2 are
unaffected. The peer layer resyncs to the v7.74 surface at S3 (mirroring the
C#/TS/OCaml build), and the missing v7.73/v7.74 spec-data snapshot is escalated to
arch as an S2-ownership item.
