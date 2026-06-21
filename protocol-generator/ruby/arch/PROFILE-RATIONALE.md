# entity-core-protocol-ruby — Profile Rationale

Audit trail for every major S1 profile choice. Ruby is **peer #12**, the first
**dynamic / duck-typed / scripting** peer in the program. (Elixir is dynamic but
on the BEAM; Ruby's blocks, mixins, open classes, metaprogramming, and the MRI
**GVL** are a distinct idiom axis.) Each choice below was derived from V7
(pinned `spec-data/v7.75`) + Ruby-ecosystem research, **not** ported from a
sibling peer. Where a value matches a prior peer it is by independent arrival;
the idiom seams deliberately differ.

## Spec version: full v7.75 snapshot (no snapshot-lag caveat)

Peers #1–8 built against a `spec-data` snapshot that lagged spec HEAD (v7.72/
v7.74) and reconstructed the newer peer-surface from folded proposal text
(A-ELX-001 and siblings). Ruby is luckier: **`spec-data/v7.75` is a complete,
SHA-pinned snapshot** with the full `ENTITY-CORE-PROTOCOL-V7.md` body. So Ruby
derives S1/S2/S3 entirely against ratified spec text — the register/outbound/
emit/owner-cap/§7a peer surface AND the v7.75 §4.8 store-safety / §4.9
resilience / §4.10 resource-bounds substrate floor are all present. The codec
specs (`ENTITY-CBOR-ENCODING.md` label 1.5, `ENTITY-NATIVE-TYPE-SYSTEM.md`
4.2.1) are byte-identical v7.73→v7.75 per the MANIFEST, so the wire is stable
and the codec corpus is valid. No A-ELX-001-style escalation is needed.

## Codec strategy: native

The A-005 pattern holds for a 12th language: **no Ruby CBOR gem gives ECF's
canonical guarantees out of the box**, so the canonical layer is hand-rolled
regardless of what sits underneath; meanwhile **crypto is fully native via
stdlib `openssl`** (OpenSSL 3.x backend), which reaches Ed25519, **Ed448**, and
the SHA-2 family. So `native` is correct on both halves. `ffi` (the C-ABI codec)
stays the documented fallback but is not expected to be needed at any tier.

## CBOR: hand-rolled (no gem)

Surveyed the Ruby CBOR landscape:

- **`cbor`** (cabo/cbor-ruby, C extension): fast and widely used, but emits maps
  in **insertion order**, does **no** shortest-float minimization, and **accepts
  tags** — none of the ECF canonical contract.
- **`cbor-canonical`** (cabo): adds `to_canonical_cbor` implementing **RFC-7049
  §3.9 length-first map ordering** — which is *exactly* ECF's ordering (the right
  axis, unlike RFC-8949 bytewise). But it is **encode-only**, does **not**
  minimize floats (Rule 4), does **not** recursively reject major-type-6 tags on
  **decode**, and layers on the `cbor` C ext. It buys the map-order half and
  fights nothing — but leaves float-min, tag-reject, decode-canonicality, and
  raw-byte `data` fidelity (N4) to us anyway.
- **`cbor-deterministic`** (cabo): targets **RFC-8949 §4.2 bytewise** ordering —
  the **wrong** order for ECF (length-first ≠ bytewise). Actively misleading.

The full ECF contract — length-then-lex map order on **encoded key bytes**,
shortest-float incl. f16, recursive tag-6 rejection on **decode**, full
uint64/nint range, and verbatim raw-byte `data` (N4) — is not delivered by any
single gem. Hand-rolling `lib/entity_core/cbor.rb` is both faithful and *simpler*
than gluing `cbor-canonical` (encode) + a custom decoder + a custom float pass
together. Ruby makes this pleasant: **arbitrary-precision `Integer`** (no
uint64 head-form trap), and **ASCII-8BIT (BINARY) `String`** byte buffers via
`String#b` / `force_encoding` give clean byte-level cursor work. The decoder is
a byte-cursor over an ASCII-8BIT string (Ruby's natural parser shape — there is
no binary-pattern-match like the BEAM, but `String#unpack`/`getbyte`/slicing are
idiomatic and fast). **Spike the `map_keys` + `float` vectors at S2** before
committing the full build — the load-bearing codec risk.

## Crypto: stdlib `openssl` — Ed25519 (native, no gem)

MRI bundles the `openssl` gem (an stdlib default gem; Ruby 3.4 bundles openssl
3.x), which on a modern OpenSSL 3.x backend exposes EdDSA through the generic
`OpenSSL::PKey` surface:

```ruby
priv = OpenSSL::PKey.generate_key("ED25519")  # or OpenSSL::PKey.new_raw_private_key("ED25519", seed)
sig  = priv.sign(nil, msg)                     # PureEdDSA → digest MUST be nil
ok   = pub.verify(nil, sig, msg)
seed = priv.raw_private_key                    # 32-byte seed
pk   = priv.raw_public_key                     # 32-byte pubkey
```

`sign(nil, …)`/`verify(nil, …)` (no external digest — PureEdDSA hashes
internally per RFC-8032) and `raw_private_key`/`raw_public_key` /
`generate_key("ED25519")` require **openssl gem ≥ 3.0**, which Ruby 3.4 bundles.
Ed25519 is **deterministic by construction** (no RNG in the signing path), so
the crypto-library version is conformance-neutral (the C# F10 lesson). Audited
via OpenSSL; no third-party crypto gem (no RbNaCl/libsodium, no `ed25519` gem) in
the trust base. The exact spelling + raw-key-method availability is confirmed
in-container at S2 (A-RUBY-003).

> **Candidate considered and declined:** RbNaCl (libsodium binding) and the pure
> `ed25519` gem. Both work, but each adds a gem dependency (and RbNaCl pulls a
> native libsodium). stdlib `openssl` is native, audited, zero-dep, AND — unlike
> libsodium — reaches **Ed448** for the agility bar from the same surface. So
> stdlib `openssl` dominates: fewer deps and a strictly larger crypto reach.

## Ed448: NATIVE via the same stdlib `openssl` — the Elixir/Haskell result

The standout. OpenSSL 3.x provides **Ed448** (57-byte seed, 114-byte signature,
PureEdDSA) through the *identical* generic `OpenSSL::PKey` path
(`generate_key("ED448")`, `sign(nil,…)`/`verify(nil,…)`,
`raw_private_key`/`raw_public_key`). So §1.5 `key_type 0x02` is reachable with
**no FFI, no opt-in sub-library, no second crypto source** — the Elixir headline
(contrast OCaml A-OC-002, which had to source Ed448 over the C-ABI) and the
Haskell native-full-agility result, now replicated on a **third** native-crypto
substrate (Ruby stdlib openssl). The agility corpus (KEY-TYPE-ED448-*,
HASH-FORMAT-SHA-384-*) is reachable from the default build. **Caveat to verify at
S2 (A-RUBY-002):** the *bundled OpenSSL build* must actually enable Ed448 —
fedora/debian OpenSSL 3.x ships it, but a `crypto:supports`-equivalent assertion
goes in the container build (see [container]) and the byte-pin is verified at S2.

## Hash: stdlib `digest` + `openssl` — SHA-256 + SHA-384/512 (native, no gem)

`Digest::SHA256` for the content_hash floor; `Digest::SHA384`/`SHA512` (and the
equivalent `OpenSSL::Digest`) for the agility hashing family. All stdlib, no gem.
Note Ed448's *internal* hash is SHAKE256 (OpenSSL handles it inside PureEdDSA —
not a separately-invoked digest); the §HASH-FORMAT SHA-384 agility path is the
content-hash family, independent of the signature curve.

## Base58 + varint: hand-rolled

Both small and dependency-free. Base58 (Bitcoin alphabet, encode+decode,
`lib/entity_core/base58.rb`) for peer-id; LEB128 varints
(`lib/entity_core/varint.rb`) for the N1 format-code / key-type / hash-type
framing. Hand-rolling keeps the **zero-runtime-gem-dependency** story intact —
the core peer ships with no runtime gems (crypto + hashing are stdlib; CBOR/
base58/varint hand-rolled; Minitest is stdlib).

## Error model: exceptions (the Ruby idiom)

`raise`/`rescue` with a `StandardError`-rooted hierarchy under
`EntityCore::Error` — the canonical Ruby fallible surface. The tree mirrors the
C#/TS exception hierarchies in *shape* (Codec / Protocol / Transport families)
but reads as Ruby (PascalCase classes, `raise EntityCore::CodecError, "…"`).
Rooting at `StandardError` (not `Exception`) keeps faults catchable by a bare
`rescue` — the Ruby convention (rooting at `Exception` would escape normal
rescue and is reserved for system-exit-class signals). `WireProtocolError`
avoids the TS `ProtocolErrorError` stutter (A-003 precedent). Decode-path
violations raise `CodecError` subclasses; the peer rescue-maps protocol faults to
the §5.2a / §6.12 status codes at the dispatch boundary. This is distinct from
Elixir's tagged tuples, OCaml's `result`, and Zig's error unions — the
dynamic-language exception seam.

## Concurrency: thread-per-connection, with an honest GVL accounting

This is the *point* of the Ruby concurrency axis, and the profile is deliberately
candid about MRI's **Global VM Lock (GVL)**:

- MRI has **native OS threads** (`Thread`) with a **preemptive** scheduler, but
  only **one thread executes Ruby bytecode at a time** (the GVL serializes the
  interpreter). So Ruby code does **not** run in parallel across cores.
- **Crucially, the GVL is RELEASED during blocking IO** — `recv`/`send`/`accept`
  on sockets, and OpenSSL C calls. So a **thread-per-connection** peer is
  *genuinely* concurrent for an **IO-bound** workload (§4.8/§4.9): while one
  thread blocks in `recv`, others run. The entity-core peer is IO-bound (frame
  shuffling + occasional crypto), **not** CPU-bound, so the GVL is **adequate**
  for the §7b concurrency gate. We do not need worker pools or fibers to clear it.
- **Data-race safety (§4.8) still needs explicit locking.** The GVL prevents two
  threads from running bytecode simultaneously, but it does **not** make a
  compound *read-then-write* atomic (a thread can be preempted between the read
  and the write). So the shared store is **Mutex/Monitor-guarded**, and the §3.9
  CAS put is a single critical section. (Misconception to avoid: "the GVL makes
  Ruby thread-safe" is false for compound operations.)
- **§7b TCP_NODELAY** is set on every socket. The Zig lesson (Nagle/delayed-ACK
  is the small-frame req/resp throughput killer; 343 ms/cycle churn is the Nagle
  signature) applies regardless of language — recorded in the profile so S3 wires
  it from the start.
- **Ractors** (Ruby 3.x) are the **true-parallel** alternative — no shared GVL
  between Ractors — but they impose a **share-nothing** object model that fights
  the shared-store design (every object crossing a Ractor boundary must be
  shareable/frozen or copied), and Ractors are still flagged **experimental**.
  Noted as the parallelism escape hatch; **not used at core**. If a future
  CPU-bound extension needs real parallelism, Ractors (or process forking) is the
  documented path.

This maps the N6/N7/§6.11 reentrancy invariants onto: one reader **thread** per
connection (the single writer for that socket), a `pending {request_id =>
waiter}` map plus a `ConditionVariable` for the §6.11 reentrant EXECUTE_RESPONSE
demux (the threaded-peer shape, same as OCaml's reader-thread + Hashtbl +
condvar). The §6.13(b) outbound await runs on a spawned thread so it never stalls
the reader.

## Native arbitrary-precision integers: no head-form trap

Like the BEAM (Elixir peer #4), **Ruby `Integer` is arbitrary-precision**, so the
CBOR uint64/int64 head-form carrier that bit OCaml (int63→Int64), C# (`ulong`),
and TS (`bigint`) is **just an `Integer`** here — no wrapping, no widening, no
bigint bridge. Recorded as a language fact, not an ambiguity. (The second peer to
carry the full integer range with no special-casing.)

## Byte handling: ASCII-8BIT strings

Wire bytes are **ASCII-8BIT (BINARY)** `String`s via `String#b` /
`force_encoding(Encoding::BINARY)` — **never** UTF-8 in the codec core. This is
the standard Ruby distinction between text and bytes; getting it right is the
Ruby analogue of the TS `Uint8Array`-not-`Buffer` discipline and the C# byte-span
discipline. `frozen_string_literal: true` in every file (perf + immutability
hygiene); `Data.define(...)` (Ruby 3.2+ immutable value objects) for value-shaped
types (envelope, cap-token); `Struct` only where mutation is needed.

## Duck typing + §1.1 `data` is an arbitrary ECF value (A-JAVA-010)

The §1.1 entity `data` field is an **arbitrary ECF value, NOT necessarily a map**
(A-JAVA-010). Ruby's duck typing makes this natural — `data` is "whatever ECF
value decodes," modeled as a general ECF value, not assumed to be a `Hash`. This
is recorded now so the S2 codec model is right from the start (the codec carries
`data` as pre-encoded bytes / a general decoded value, never forcing a map).

## Build / test / packaging: Bundler + Rake + Minitest + RubyGems

`bundler` + `rake` is the universal idiomatic Ruby build/task setup, gemspec-
driven. Tests use **Minitest**, which **ships with Ruby** (stdlib) — so it is
simultaneously a reasonable ecosystem choice AND a zero-added-dependency one
(the Elixir/ExUnit + TS/node:test happy position; RSpec is more popular but is a
heavyweight gem dependency, declined at core and logged if ever wanted). The
conformance harness is a Minitest suite asserting byte-identity against the
normative fixtures; a thin `exe/` script is the standalone oracle driver for
validate-peer / wire-conformance at S4. **RuboCop** (lint) is the ecosystem
standard but a dev-only gem — deferred to S5, not pulled silently.

## Naming the gem: peer id vs RubyGems id

Peer id under keystone naming is `entity-core-protocol-ruby`. RubyGems ids are
idiomatic snake_case and a gem is implicitly Ruby, so the registry id is
`entity_core_protocol` (no redundant `_ruby` suffix) — mirroring the Elixir
Hex-id reasoning. The `require` path is `entity_core`; the top namespace is
`EntityCore`. Availability/squatting checked at S5; fall back to
`entity_core_protocol_ruby` if `entity_core_protocol` is taken.

## License: Apache-2.0 (S9 default)

Ruby itself is Ruby-license/BSD-2 and the gem ecosystem is MIT-heavy with no
strong mandate, so the repo's Apache-2.0 default (explicit patent grant) stands.

## Container: official `ruby:3.4.x-slim-bookworm`

Per the S1 prompt, the toolchain image pins an **official `ruby:3.x` release
image ≥30 days old**. **`ruby:3.4.4-slim-bookworm`** (Ruby 3.4.4,
~13 months old — well clear of the S11 30-day floor) is
the pin. Rationale for choosing the upstream official image over the
fedora-base-plus-toolchain pattern the other peers use: the prompt directs an
official `ruby:3.x` image specifically, and the official image is a
**reviewed-vendor channel** (Docker Official Images, built from
docker-library/ruby) — so per the S11 scope clarification the strict 30-day
*registry* discipline relaxes to "pin exactly for reproducibility" (which a
patch-pinned `3.4.4` tag does). `slim-bookworm` (Debian 12) ships **OpenSSL 3.0.x**,
which provides Ed25519 + Ed448 + SHA-2 to stdlib `openssl` — the native-crypto
backend. A build-time assertion verifies Ed25519 **and Ed448** are reachable
(`OpenSSL::PKey.generate_key("ED25519"/"ED448")` round-trip) so the image fails
loudly if the bundled OpenSSL lacks Ed448 (closes the A-RUBY-002 risk at
container-build time). Core peer has **zero runtime gem dependencies**, so there
are no gem pins to mirror in the image; Bundler + Rake + Minitest are stdlib/
bundled. (Digesting Ruby 3.4.4's exact image digest is an S2 lock-step — pin the
tag now, pin the digest when the image is first pulled in-container.)
