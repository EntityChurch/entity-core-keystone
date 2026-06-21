# entity-core-protocol-zig — Phase S2 (Codec) Summary

**Peer #4** (Zig, distant-idiom systems language) ·
**Status: COMPLETE — 69/69 wire-conformance, first conformance run, 0 codec fixes**

## Container (the deferred S1 build)

`containers/zig-toolchain/Containerfile` built clean:
`podman build -t entity-core-keystone/zig-toolchain:latest -f containers/zig-toolchain/Containerfile .`
- minisign-verified the pinned tarball against the Zig project pubkey, sha256
  pin `c61c5da6…fafe05` OK, `zig version` → **0.15.1**. Reproduces on a clean
  rebuild; runs fully offline (`--network=none`) thereafter.
- **One Containerfile fix was load-bearing:** the S1 draft wrote the minisign
  pubkey to a file and used `minisign -V -p FILE`. Fedora-43 minisign 0.12
  rejects a bare-base64 pubkey file ("Error while loading the public key file")
  — its `-p` file form requires a 2-line `untrusted comment:` header + key.
  Switched to the inline **`minisign -V -P "<base64>"`** form (no file format to
  get wrong; verified identical signature acceptance). The sha256 + tarball
  naming (`zig-x86_64-linux-…`, arch-before-os) were already corrected at the
  pin-fill step before this session.

## What was built (`src/`, library `entitycore_codec`)

| Module | Responsibility |
|---|---|
| `cbor.zig`    | Canonical ECF encode/decode; f16/f32/f64 shortest-float ladder; length-then-lex map ordering on encoded key bytes; recursive major-type-6 tag rejection (N2); `uint`/`nint` as `u64` (full 0..2^64-1 / -1..-2^64 range); owned `Value` tree with `deinit` (caller-frees) |
| `varint.zig`  | LEB128 encode/decode (N1) — multi-byte path proven by content_hash.4 + peer_id.3 |
| `base58.zig`  | Bitcoin-alphabet encode + decode, leading-zero preserving (byte long-division, no bignum) |
| `hash.zig`    | `content_hash = varint(fc) ‖ HASH(ECF{type,data})`; SHA-256 floor + SHA-384 (agility) via `std.crypto.hash.sha2` |
| `sign.zig`    | Deterministic Ed25519 sign/verify/pub via `std.crypto.sign.Ed25519` (`generateDeterministic` + `sign(msg, null)`) |
| `peer_id.zig` | `Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)` + parse (owned round-trip) |
| `root.zig`    | Public module surface (re-exports + `refAllDeclsRecursive` test pull-in) |
| `conformance.zig` | Wire-conformance harness exe (loads the fixture, byte-checks every vector) |
| `build.zig` / `build.zig.zon` | `zig build` (static lib), `zig build test` (leak-checked), `zig build conformance -- <fixture>` |

**std-only, zero third-party packages.** No GC: every allocating API threads an
explicit `std.mem.Allocator`; `errdefer`/`defer` free on every path. Error model
is error unions throughout (`cbor.Error`, `CodecError`-shaped), no exceptions.

## Conformance

**69 / 69 byte-identical** against `conformance-vectors-v1.cbor` (v7.71,
sha256 `41d68d2d…6a052`), first run, **zero codec-logic fixes**. Same scoreboard
as the C# (#1), TS (#2), and OCaml (#3) peers — converged spec-first.

| Category | Pass | Category | Pass |
|---|---|---|---|
| float | 14/14 | tag_reject | 5/5 |
| int | 14/14 | content_hash | 4/4 |
| map_keys | 6/6 | peer_id | 3/3 |
| length | 8/8 | signature | 3/3 |
| primitive | 6/6 | envelope | 2/2 |
| nested | 4/4 | **TOTAL** | **69/69** |

The fixture `.cbor` artifact holds exactly **69 vectors** (64 `encode_equal` +
5 `decode_reject`); the harness runs and passes all 69. (The MANIFEST's "71"
is the arch-side authoring count incl. 2 `.diag`-only meta entries — they are
not in the binary artifact.) The Go `wire-conformance` binary is the fixture
*producer/cross-blesser* (Go × Rust × Python 3-way lock), not a runtime checker,
so S2 is self-contained — no live oracle needed, matching the OCaml model.

### Build fixes (all Zig-API mechanics, NOT codec correctness)
1. `ArrayList.appendNTimes` does not exist in 0.15.1 → `addManyAsSlice` + `@memset`.
2. Decoder method named `u8` shadows the primitive type → renamed `readByte`.
3. `build.zig.zon` requires the compiler-suggested `fingerprint` u64.
4. `build.zig` used `.preferred_optimize_mode` (drops `-Doptimize`) → switched to
   plain `standardOptimizeOption(.{})` so `-Doptimize=ReleaseSafe` works.

None of these touched the encoder/decoder/hash/sign math — the float ladder, the
length-then-lex map ordering, and the full-u64 int range were correct on the
first compile that ran.

## Invariants N1–N4 — enforced + covered
- **N1 (LEB128 varints):** `varint.zig`; format-code/key-type/hash-type all routed
  through it. Multi-byte path proven by content_hash.4 (fc 128) + peer_id.3
  (key_type 128) + a round-trip selftest.
- **N2 (tag rejection):** decoder returns `error.TagRejected` on any major-type-6
  item at any depth; tag_reject.1–5 (incl. nested-in-included + bare 55799) pass,
  plus a local nested-tag selftest.
- **N3 (empty-params 0xA0):** length.2 (`{}` → `a0`) + content_hash.1 pass; local
  selftest pins `{}`→`a0` and `[]`→`80`.
- **N4 (entity fidelity):** decoder is structural and round-trips byte-identically
  (decode∘encode == identity selftest). Original-byte forwarding is wired at the
  S3 peer surface (not a codec-level concern).

## Uncovered-range selftests (codec-review heuristic) — `zig build test`, all PASS, leak-checked
- uint64 = 2^64-1 and 2^63 (above i64-max — the exact spot a signed decode would
  overflow); nint min (-2^64) → `3bffffffffffffffff`.
- base58 decode∘encode with leading-zero preservation.
- Ed25519 deterministic sign + verify + tamper-reject; determinism (identical
  inputs → identical sig); bare-tag + nested-tag rejection; duplicate-key reject.
- peer-id format→parse round-trip incl. multi-byte key_type.

`std.testing.allocator` backs every test → any leak fails the build. The
conformance exe uses a leak-checking `GeneralPurposeAllocator` + a per-vector
arena. Clean (no `.zig-cache`) Debug and ReleaseSafe builds both reproduce green.

## Exit criteria
All 69 vectors PASS · selftests PASS, no leaks · `zig build` clean in Debug +
ReleaseSafe · ambiguity log has no blocking codec items · container reproducible.
**S2 PASS.**

## Not in this phase (S3+)
- Peer machinery (connection, dispatch, capability, store, processor) — needs the
  threaded-async decision (A-ZIG-003) validated and the entity/envelope model
  lifted onto `Value` with the documented ownership contract (A-ZIG-004).
- Agility corpus (Ed448 + SHA-384 matrix) — Ed448 gated on A-ZIG-002 (FFI-the-
  Ed448-family-only is the recommended shape; the SHA-384 leg is already wired in
  `hash.zig`).
