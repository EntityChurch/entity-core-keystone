# entity-core-protocol-c — Phase S2 (Codec) Summary

**Peer #10** (C / C11 / POSIX, procedural / manual-memory /
return-code idiom) · **Status: COMPLETE — 69/69 wire-conformance, 0 FAIL;
ASan/LSan/UBSan-clean; c-toolchain image rebuilt (one package added).**

## Result

- **ECF codec corpus 69/69 byte-identical** — **tenth** independent native codec
  to converge (C# / TS / OCaml / Elixir / Zig / Common-Lisp / Swift / Haskell /
  Java → S8/S9). 13/13 self-tests pass (uint64 range, float ladder, N1/N2,
  base58 round-trip, peer_id §1.5, Ed25519 RFC-8032 TEST-1 + sign/verify/tamper).
- **Spike PASSED first** (profile mandate) — see below.
- **ASan/LSan/UBSan-clean** — the manual-memory conformance bonus: a leak / UAF /
  overflow / UB would be a test failure; the full run is clean.
- **Container rebuilt** — `containers/c-toolchain/Containerfile` gains
  `libasan-15.2.1-7.fc43` + `libubsan-15.2.1-7.fc43` (the one S2 add the PHASE-S1
  "to add at S2" note predicted). No other change.

Full detail: `CONFORMANCE-REPORT.md`.

## The spike (PHASE-S1 mandate) — DONE FIRST, PASSED

Before the full build, the **float + map_keys v7.71 vectors** were pushed through
the hand-rolled encoder (`test/spike.c`, `make spike`). Per ffi-c.md, float
minimization (double→f16 re-decode-and-compare) is the highest bug-density code in
the whole peer, and length-then-lex (CTAP2) map ordering is the other load-bearing
canonical risk.

**Spike result: 20/20 byte-identical (14 float + 6 map_keys), ASan/UBSan-clean,
zero `-Werror` warnings — on the first run.** The native canonical layer is
confirmed: the f16 pure-integer representability test reproduces the whole
float ladder (incl. the f32-not-f16 boundary 65503.0 → `fa477fdf00` and 1.1 →
`fb3ff199999999999a`), and the length-first qsort comparator reproduces all six
map-ordering vectors incl. the mixed text/byte map_keys.5. **No `ffi` fallback
needed** — the documented fallback (link the sibling `libentitycore_codec.a`) was
not triggered; native hand-roll stands, as A-C-005 bet.

## Decisions / idiom seams (the C-native shapes)

- **Value model = tagged union over ECF major types** (`ec_value` in
  `include/entity_core/protocol.h`): `EC_INT / EC_BYTES / EC_TEXT / EC_ARRAY /
  EC_MAP / EC_BOOL / EC_NULL / EC_FLOAT` + four float-special kinds
  (`EC_FLOAT_NAN / POS_INF / NEG_INF / NEG_ZERO`). **A-JAVA-010 (P4) honored from
  the start:** the entity `data` field is a GENERAL ECF value (any major type),
  never a map-typed field — a scalar-data entity round-trips, so the silent-500
  trap cannot fire at S4.
- **Integers in NATIVE `uint64_t`** — `ec_int = { bool negative; uint64_t u; }`
  maps the CBOR major-0/1 head argument directly (no `ulong`/int63 special-casing
  like C#/OCaml; the cleanest int story alongside Zig). uint64-max and -2^64 both
  encode/decode exactly (selftests `u64_max` / `nint_min`). Float bit-twiddling
  uses `memcpy` not type-punning (no strict-aliasing UB; UBSan-clean).
- **Return-code + out-param error model** — every fallible function returns an
  `ec_status` int (`EC_OK==0`, negative == a specific failure enum) and writes
  through an out-pointer; the caller checks before use. Codec failures are
  `EC_ERR_TRUNCATED / NON_CANONICAL_ECF / TAG_REJECTED / DUPLICATE_KEY / OOM`;
  crypto failures are `EC_ERR_BAD_SEED / VERIFY_FAILED / CRYPTO`. No
  setjmp/longjmp, no errno-smuggling.
- **Manual memory, documented caller-frees** — every allocating API documents
  ownership; the whole node tree frees via one recursive `ec_value_free`; encode/
  base58/content_hash return malloc'd buffers the caller `free()`s. Error paths
  use goto-cleanup-style reverse-order frees (the C analogue of defer/errdefer).
  The decoder **copies** byte/text payloads into owned nodes (so the input buffer
  need not outlive the tree); the zero-copy borrow variant is an S3 peer-layer
  refinement, not needed for the codec gate.
- **Hand-rolled everything but crypto** — CBOR (`ecf.c`), base58 (`base58.c`),
  varint (`varint.c`), and the test harness are all in-repo; libsodium is the one
  runtime dep (Ed25519 + SHA-256). Simplest supply chain in the cohort.
- **Symbol hygiene** — `-fvisibility=hidden` + the `EC_API` export macro; only
  `ec_*` symbols are exported from the `.so` (nm-verified). Lowercase `%02x` hex
  pinned in `ec_hex_lower` (P2 / A-CL-009 — C is lowercase by default, pinned
  explicitly).

## The grind: two real defects (both fixed; vectors/oracle never doctored)

1. **UBSan: `qsort(NULL, 0, …)`** — passing NULL to a nonnull-declared arg when a
   map had 0 entries (and a latent 0-length-key `memcmp`). Fixed: guard `qsort`
   for n≤1 and the comparator for 0-length keys. (`src/ecf.c`.)
2. **base58 long-division bug** — the original `high`/early-break digit tracking
   truncated the digit stream; peer_id.1–3 produced wrong Base58 (66/69). Fixed by
   the standard backward-walk multiply/divide with an explicit running `length`
   (both encode and decode). After the fix: 69/69, peer_id selftest green.

All fixes were spec/oracle-first — the fixture, its byte-locked `canonical`
fields, and the harness were never modified.

## Container (one package added — the predicted S2 add)

`containers/c-toolchain/Containerfile` was **REUSED** (built originally for the
FFI codec) and **rebuilt** this phase. PHASE-S1 predicted the ASan/UBSan test pass
might need `libasan`/`libubsan`; verified at S2 that gcc-15.2.1 references but the
image did **not** install them (`/usr/lib64/libasan.so.8.0.0` missing → link
failure). **Added `libasan-15.2.1-7.fc43` + `libubsan-15.2.1-7.fc43`** (same NVR
family as gcc; reviewed distro channel, exact-pinned). Rebuilt image
`entity-core-keystone/c-toolchain:latest`. No other change; the build stays fully
offline (`--network=none`) — libsodium is pre-installed and everything else is
hand-rolled.

## What was built (`protocol-generator/c/`)

| File | Responsibility |
|---|---|
| `include/entity_core/protocol.h` | the single umbrella public header — `ec_status` enum, `ec_value` tagged union, codec/varint/base58/content_hash/peer_id/crypto ABI, ownership docs |
| `src/ecf.c` | **the heart** — value model + canonical encoder (float ladder, length-then-lex map sort, minimal heads) + index-walk decoder (minimality checks, recursive tag-6 reject N2, duplicate-key detect, depth bound, trailing-byte reject) |
| `src/varint.c` | multicodec LEB128 (N1) encode/decode with non-minimal rejection |
| `src/base58.c` | Bitcoin-alphabet encode/decode (leading-zero preserving, byte-wise long division) |
| `src/content_hash.c` | `varint(fc) ‖ SHA-256(ECF({type,data}))` + lowercase hex; construct/receive format-code asymmetry |
| `src/peer_id.c` | `Base58(varint(kt) ‖ varint(ht) ‖ digest)` + parse + §1.5 canonical-form `from_pubkey` (P1) |
| `src/crypto.c` | libsodium Ed25519 (`crypto_sign_*`) + SHA-256 (`crypto_hash_sha256`) + sign-entity |
| `test/conformance.c` | the gate — decodes the fixture with this peer's decoder, byte-checks all 69, runs 13 self-tests; hand-rolled assert/count, no framework |
| `test/spike.c` | the S2 spike (float + map_keys) |
| `Makefile` | `make` (libs + harness), `make test` (ASan/LSan/UBSan), `make spike`, `make dist` (packaging stub) |
| `run-s2.sh` | the offline container dev loop (mirrors Java's) |

## Dev loop

```sh
# full gate (container-bound, sealed offline):
./run-s2.sh            # make clean && make test (ECF 69/69 + 13 self-tests, ASan/LSan/UBSan)
./run-s2.sh spike      # the float + map_keys spike only
./run-s2.sh all        # also builds libentity_core_protocol.{a,so}

# or directly:
podman run --rm --network=none -v $PWD/../..:/work:Z \
  -w /work/protocol-generator/c \
  entity-core-keystone/c-toolchain:latest \
  bash -lc 'make clean && make test'
```

## Exit criteria

All 69 vectors PASS · 13/13 self-tests (incl. Ed25519 RFC-8032 KAT) byte-equal ·
`make` compiles clean (no `-Werror` warnings) · ASan/LSan/UBSan clean · `.a` +
`.so` + harness build · only `ec_*` exported · ambiguity log has no blocking
codec items · container reproducible + offline (one package added, pinned).
**S2 PASS.**

## Not in this phase (S3+, next session)

- Peer machinery (connection, dispatch, capability, store, processor, handlers) on
  POSIX pthreads (A-C-004 — one reader thread per connection, `pthread_rwlock_t`
  store, TCP_NODELAY); the §7a `--validate` handlers + §7b concurrency gate
  (A-C-003, GUIDE-carried).
- The resource_bounds §4.10 surface (413 / **400 chain_depth_exceeded** / 503) —
  the ~15-line structural pre-check (P5).
- Ed448 / SHA-384 agility (A-C-001) — libsodium has no Ed448; route (b) (link the
  sibling FFI agility `.a`) is the deferred dependency-lightest path. The Ed25519 +
  SHA-256 floor is fully proven at S2.
- The zero-copy decode borrow (forward original bytes, N4 peer surface) — an S3
  refinement; the S2 decoder is owning-copy, which is byte-correct for the gate.
