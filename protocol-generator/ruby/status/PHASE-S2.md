# entity-core-protocol-ruby — Phase S2 (Codec) Summary

**Peer #12 (Ruby)** — first dynamic / duck-typed /
scripting peer · **Status: COMPLETE (GREEN)**

## Result

- **ECF wire-conformance corpus 69/69 byte-identical.** One fix on the road to
  green — an `EntityCore::Hash` (the content-hash module) shadowing `::Hash` in
  `case/when` and `is_a?` checks; resolved with `::`-qualified core-class refs.
  No spec disagreement, no fudged vector.
- **Crypto-agility 25 byte-pins PASS, NATIVE — Ed448 + SHA-384 from stdlib
  `openssl`, no FFI.** This replicates the Elixir/Haskell native-full-agility
  headline on a 3rd native-crypto substrate (Ruby stdlib openssl), the contrast
  with OCaml's hybrid-FFI Ed448 (A-OC-002). 7 gates deferred to S3 (cap-token
  §3.6 + registry interpretation).
- `ruby -w` clean (zero warnings); offline `bundle exec rake test` green; zero
  runtime gem deps.

## Container build

`containers/ruby-toolchain` (`ruby:3.4.4-slim-bookworm`, OpenSSL 3.x) **built
successfully** — the build-time Ed25519/Ed448/SHA-384 assertion passed:

```
crypto ED25519 OK (sig 64B)
crypto ED448 OK (sig 114B)
crypto EdDSA OK: ed25519+ed448 present; SHA-384 present
```

**The bundled OpenSSL delivers Ed448 natively** — the one real crypto risk
flagged at S1 (A-RUBY-002) is closed. Added a build-time `bundle install` of the
peer's (dependency-free) bundle so the offline `bundle exec rake test` dev-loop
is reproducible across ephemeral `--rm` runs (default-gem Minitest/Rake pinned in
the Gemfile).

## What was built (`lib/entity_core/`)

| Module | Role |
|---|---|
| `cbor.rb` | Canonical ECF encode/decode — the heart. Byte-cursor decoder over an ASCII-8BIT String; minimal-int + length-then-lex map sort + shortest-float on encode; recursive tag-6 / indefinite / non-minimal / dup-key / trailing-byte rejection on decode |
| `varint.rb` | Multicodec LEB128 varints (N1) |
| `base58.rb` | Bitcoin-alphabet encode/decode (peer-id), leading-zero → `1` |
| `hash.rb` | content_hash construction + SHA-256/384 format registry |
| `peer_id.rb` | format/parse + §1.5 size-cutoff identity derivation |
| `signature.rb` | Ed25519/Ed448 sign/verify/derive via stdlib `openssl` raw keys |
| `error.rb` | `EntityCore::Error < StandardError` hierarchy (CodecError, …) |
| `conformance.rb` / `agility.rb` | corpus runners (pure; file-IO-free) |
| `exe/wire-conformance` | standalone gate driver (the S4 oracle entry shape) |

## Design decisions / notes

- **Value representation — the Ruby seam.** Text string (CBOR major 3) vs byte
  string (major 2) is carried by the `String` ENCODING: `Encoding::BINARY`
  (ASCII-8BIT) = bytes, UTF-8 = text. This is the `byte_strings_ascii_8bit`
  profile idiom and needs no wrapper type (cf. Elixir's `{:bytes, _}` tuple).
  Float specials are native `Float::NAN` / `±Float::INFINITY`; entity `data` is
  modelled as an arbitrary ECF value, NOT a Hash (A-JAVA-010 / `duck_typing` —
  made explicit, though the codec never assumes a top-level shape).
- **No native-int trap.** Ruby `Integer` is arbitrary-precision, so the uint64
  head-form is just an Integer — the trap that bit OCaml int63 / C# ulong / TS
  bigint simply doesn't exist (the BEAM result, replicated; a datapoint for the
  arch review).
- **Shortest-float / f16 ladder via `pack`/`unpack`.** Ruby's `Array#pack` has
  **no half-float code** (`g`/`G` are f32/f64 only). f16 is therefore
  hand-encoded from the binary64 bits (`pack("G").unpack1("Q>")`): pull
  sign/exp/mant, reject if the unbiased exponent is outside `[-14, 15]` (the
  silent-overflow-to-Inf guard) or if the low 42 mantissa bits aren't zero
  (exactness), then assemble the 16-bit half. f32 uses `pack("g")` with an
  exact-round-trip + all-ones-exponent guard. Specials take their fixed Rule 4a
  bytes (`f97e00` / `f97c00` / `f9fc00` / `f98000`). On decode, f16 is rebuilt
  with `Math.ldexp` (normals + subnormals) and specials surface as the native
  Float constants. All 14 `float` vectors pass, incl. the
  `65503 → f32 / 65504 → f16` boundary and 2^15 large-f16 cases that broke
  cbor2's C extension.

## Ambiguity log

- **A-RUBY-002** (Ed448 native) → **RESOLVED**: byte-verified end-to-end — the
  114-byte Ed448 signature, 57-byte pubkey, peer_id, and SHA-256-form
  content_hash all byte-identical to the locked RFC-8032 / v7.67 pins. The
  bundled Debian-bookworm OpenSSL 3.x ships Ed448; no FFI.
- **A-RUBY-003** (openssl EdDSA API / raw-key methods) → **RESOLVED**:
  `OpenSSL::PKey.new_raw_private_key(alg, seed)` / `new_raw_public_key`,
  `sign(nil, msg)` / `verify(nil, sig, msg)` (digest `nil` = PureEdDSA), and
  `raw_private_key` / `raw_public_key` all confirmed in-container against Ruby
  3.4.4 / OpenSSL 3.x. (The S1 profile's `PKey.generate_key`/`.sign(nil,..)`
  spelling was right; `new_raw_private_key` is the seed-import method.)

No NEW spec-level ambiguity surfaced; no blocking items. See SPEC-AMBIGUITY-LOG.md.
