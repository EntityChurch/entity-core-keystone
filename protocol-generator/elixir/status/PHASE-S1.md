# entity-core-protocol-elixir — Phase S1 (Profile) Summary

**Peer #4** (Elixir, spec-first / distant-idiom) · **Status: COMPLETE**

## Preconditions resolved at session start
- **Spec version.** Spec HEAD is **v7.74** (folded: extensibility boundary + peer
  authority bootstrap + §7a conformance handlers), but spec-data **snapshots stop at
  v7.72**. The codec specs (`ENTITY-CBOR-ENCODING.md`, `ENTITY-NATIVE-TYPE-SYSTEM.md`)
  are byte-identical v7.71→v7.72, so the v7.71 codec corpus is valid at v7.72 and
  S1/S2 are wire-unaffected. The v7.73 (nonce-echo) + v7.74 (register/outbound/emit/
  owner-cap + §7a) folds are **peer-layer** (S3+). Profile reads `spec-data/v7.72`;
  codec corpus `test-vectors/v0.8.0`. Logged **A-ELX-001** (need a v7.73/v7.74 snapshot
  for documented parity; peer layer resyncs to v7.74 at S3 against folded proposal
  text, as peers #1-3 did).
- **No-peek discipline.** Derived from V7 + Elixir/BEAM ecosystem only; did **not**
  open `protocol-generator/{csharp,typescript,ocaml}/src/`. (Read `ocaml/profile.toml`
  for the field *schema* only — config structure, not spec interpretation.)

## Decisions (all in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** (overturns LANDSCAPE ffi/enacl default) | strongest native story of the 4 peers |
| CBOR | **hand-rolled** | no BEAM lib gives ECF (A-005); decoder = binary pattern-match |
| Ed25519 | **OTP `:crypto`** (OpenSSL) | native, stdlib, no Hex dep |
| Ed448 | **NATIVE via OTP `:crypto`** | A-ELX-002 — headline: no FFI (contrast OCaml A-OC-002) |
| SHA-256 / SHA-384 | OTP `:crypto` | native, stdlib |
| base58 / varint | hand-rolled | dep-minimization (zero runtime Hex deps) |
| Error model | **tagged tuples** `{:ok,_}`/`{:error,_}` + bang variants | distinct from C#/TS exceptions AND OCaml result |
| Concurrency | **BEAM actor model** (processes/GenServer) | most distant of the 4; maps onto N6/N7/§6.11 reentry |
| Naming | PascalCase modules / snake_case else | Elixir-native |
| Build / test / pkg | mix + **ExUnit (stdlib)** + Hex | ExUnit = zero added dep |
| License | Apache-2.0 | S9 default (Elixir core is Apache-2.0) |

## The standout result: fully-native crypto agility, zero runtime deps
Elixir is the first peer to carry the **entire crypto-agility higher bar natively**.
OTP `:crypto` (OpenSSL 3.x backend) provides Ed25519, **Ed448**, SHA-256, and
SHA-384 — so the agility corpus (KEY-TYPE-ED448-*, HASH-FORMAT-SHA-384-*) is
reachable from the **default build** with no FFI, no opt-in sub-library, no hybrid
split. OCaml (peer #3) had to source Ed448 over the C-ABI (A-OC-002); Elixir needs
none of that. Combined with hand-rolled CBOR/base58/varint and stdlib ExUnit, the
core peer ships with **zero runtime Hex dependencies** — leaner than every prior
peer.

## Idiom observations worth recording (not ambiguities — language facts)
- **No integer head-form trap.** BEAM integers are arbitrary-precision, so the
  uint64/int64 head-form carrier that bit all three prior peers (OCaml int63→Int64,
  C# `ulong`, TS `bigint`) is **just an integer** here. Peer #4 is the first to carry
  the full range with no special-casing. (Datapoint for the eventual arch review.)
- **Binary pattern-matching decoder.** `<<major::3, info::5, rest::binary>>` is the
  BEAM's strongest parser idiom — an ergonomic win over the prior peers' byte-index
  loops, and a natural fit for ECF's tag/length framing.

## Container — BUILT + VERIFIED
`containers/beam/Containerfile` authored, **built, and verified in-session**.
fedora:43 → **source-built OTP 27.3.4** (against system OpenSSL 3.x, the EdDSA+SHA-2
backend; slim configure, no wx/observer/java/odbc) → **precompiled Elixir 1.18.4**
(precompiled-for-OTP-27 zip) → C.UTF-8 locale (+fnu) → shared `/opt`-rooted
MIX_HOME/HEX_HOME (Hex+rebar pre-installed at build time for offline
`--network=none` dev loops). Both pins ≥30 days old (S11): OTP 27.3.4 (~13mo),
Elixir 1.18.4 (~10mo). Image: 938 MB.

**Verification (in-container):**
- Build-time `crypto:supports` assertion passed: `crypto EdDSA OK: ed25519+ed448 present`.
- `erl`/`elixir` report OTP 27 (erts 15.2.7) + Elixir 1.18.4; locale clean (no latin1 warning).
- **Functional crypto round-trip** (closes A-ELX-002 + A-ELX-003): ed25519 (pub 32B,
  sig 64B) and ed448 (pub 57B, sig 114B) both sign/verify, tamper rejects,
  `crypto:generate_key(eddsa, Curve, Seed)` derives `{Pub, Seed}`, ed25519 re-sign
  deterministic. SHA-256=32B, SHA-384=48B. **The entire crypto layer's API is
  verified before S2 writes a line of codec.**

Source build is the heavy step (~10-15 min on 12 cores) — the price of a
reproducible, S11-pure, Ed448-capable toolchain.

## Ambiguity log
4 entries (A-ELX-001..004), none blocking:
- **A-ELX-001** — spec-data snapshot (v7.72) lags HEAD (v7.74); peer-layer resync at
  S3, escalate snapshot to arch. Non-blocking for S1/S2 (codec wire-unaffected).
- **A-ELX-002** — Ed448 native via `:crypto` (overturns LANDSCAPE ffi default,
  diverges from OCaml's hybrid-FFI resolution); operator decision, byte-verify at S2.
- **A-ELX-003** — exact `:crypto` EdDSA arity/atom spelling confirmed in-container at
  S2 (assumed the option-list `crypto:sign(eddsa, none, Msg, [Key, ed25519])` form).
- **A-ELX-004** — Hex package id `entity_core_protocol` (snake_case); availability
  checked at S5.

## Exit criteria
profile.toml fully populated (no TBD-blocking) · rationale written · container
authored + specified (build verified at S2) · ambiguity log has no blocking-severity
items (A-ELX-002 Ed448 is native, not a gap). **S1 PASS.**

## Next
S2 codec (`--phase codec`): build `EntityCore.Cbor` (hand-rolled canonical ECF via
binary pattern-matching) + base58 + varint + `:crypto` crypto shim; spike the
`map_keys` + `float` vectors first, then run the full v0.8.0 corpus to byte-identity.
Because Ed448 is native, the agility slot (`run-agility`-equivalent) can run from the
default build at S2 rather than being deferred. Build the container first and
confirm the `:crypto` EdDSA arity (A-ELX-003).
