# entity-core-protocol-elixir — Phase S2 (Codec) Summary

**Peer #4** (Elixir) · **Status: COMPLETE (GREEN)**

## Result

- **ECF codec corpus 69/69 byte-identical — first run, 0 fixes.** Fourth
  independent native codec to converge on the first attempt (C#/TS/OCaml → S8).
- **Crypto-agility corpus: 28/28 crypto byte-pins, NATIVE** (Ed448 + SHA-384 from
  OTP `:crypto`; no FFI). 4 gates deferred to S3 (cap-token + key registry).
- `mix test` 11/0; `mix compile` clean under `warnings_as_errors`; **zero runtime
  Hex deps**.

Full detail: `CONFORMANCE-REPORT.md`.

## What was built (`lib/entity_core/`)

| Module | Role |
|---|---|
| `cbor.ex` | Canonical ECF encode/decode via binary pattern-matching — the heart |
| `varint.ex` | LEB128 multicodec varints (N1) |
| `base58.ex` | Bitcoin-alphabet encode/decode (peer-id) |
| `hash.ex` | content_hash construction + format registry (SHA-256/384) |
| `peer_id.ex` | format/parse + §1.5 identity derivation (size-cutoff) |
| `signature.ex` | Ed25519/Ed448 sign/verify/derive via `:crypto` |
| `error.ex` | `%EntityCore.Error{}` tagged-tuple error surface |
| `conformance.ex` / `agility.ex` | corpus runners (pure; file-IO-free) |

## Design decisions / notes

- **Value representation.** Native Elixir terms; text=binary vs bytes=`{:bytes,_}`;
  finite floats native (distinct from ints); non-finite specials = `:nan`/`:inf`/
  `:neg_inf`. Maps native (re-sorted on encode), keys binary or `{:bytes,_}`.
- **Float ladder.** BEAM `::float-16` bit syntax works (OTP 27), but f16 overflow
  silently yields Inf (probed), so the candidate is accepted only if its exponent
  isn't all-ones **and** it round-trips exactly. NaN/Inf/-0.0 are matched by raw
  bit pattern on decode (the BEAM refuses to materialize a NaN float).
- **No native-int trap.** BEAM integers are arbitrary-precision → the uint64
  head-form is just an integer (the trap that bit OCaml int63 / C# ulong / TS
  bigint simply doesn't exist; first peer with no special-casing). Datapoint for
  the arch review.
- **Binary pattern-match decoder** (`<<major::3, info::5, rest::binary>>`) — the
  BEAM's strongest parser idiom; an ergonomic win over the prior peers' index loops.

## Ambiguity log

- **A-ELX-002** (Ed448 native) → **RESOLVED**: byte-verified end-to-end (114-B
  signature byte-identical to the locked RFC-8032 pin; pubkey/peer_id/content_hash
  all match). No FFI — the headline contrast with OCaml A-OC-002.
- **A-ELX-003** (`:crypto` EdDSA arity) → **RESOLVED**: the option-list form
  (`crypto:sign(eddsa, none, Msg, [Seed, curve])`) confirmed for both curves.
- No new ambiguities surfaced at S2 (the codec derived cleanly from
  ENTITY-CBOR-ENCODING.md v1.5 + the vendored corpus).

## Exit criteria

ECF corpus byte-identical (69/69) · agility crypto byte-pins green (28/28) ·
report written · compiles clean under linter settings · ambiguity log has no
blocking items. **S2 PASS.**

## Next (S3)

Peer machinery (connection / dispatch / capability / store / processor / handler)
on the BEAM actor model, resynced to v7.74 (register / outbound / emit / owner-cap
/ §7a conformance handlers) per A-ELX-001. The 4 deferred agility gates (cap-token
§3.6 shape + key_type registry) land at S3.
