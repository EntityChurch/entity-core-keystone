# entity-core-protocol-common-lisp — Phase S2 (Codec) Summary

**Peer #5** (Common Lisp) · **Status: COMPLETE — 69/69 wire-conformance, 0 FAIL; container built clean**

## Result

- **ECF codec corpus 69/69 byte-identical** — fifth independent native codec to
  converge (C#/TS/OCaml/Elixir → S8). 0 fixes after the codec compiled.
- **Ed448 RFC-8032 KAT byte-equality gate (A-CL-005): PASS** — native pure-Lisp
  Ed448 (ironclad) produces byte-identical pubkey/signature/peer_id. Agility corpus
  now trusted; no FFI.
- **Container built clean** — SBCL 2.6.4 (source, verified SHA), ASDF 3.3.1,
  ironclad 0.61 (pinned Quicklisp dist), all crypto primitives confirmed
  in-container.

Full detail: `CONFORMANCE-REPORT.md`.

## Container (carry-ins A-CL-006 + A-CL-004 resolved)

`containers/common-lisp-toolchain/Containerfile` BUILT (S1 authored it; S2 builds).
fedora:43 → source-build SBCL 2.6.4 (bootstrapped by the stock fedora SBCL 2.6.5,
then bootstrap removed) → ironclad 0.61 via the pinned Quicklisp dist
into an offline ASDF registry under `/opt`. Image `692 MB`.

- **A-CL-006 RESOLVED** — SBCL 2.6.4 source-tarball SHA-256 filled:
  `3ba53e654b60feb7c4f50466199d6d5260f2661c711ba22d4b770b655400d57b`. Verified by
  direct download of the official SourceForge release tarball (SBCL's canonical
  channel; release is GPG-signed at `…/sbcl-2.6.4-crhodes.asc`), bz2-integrity
  checked, unpacks to `sbcl-2.6.4/`. The build fails closed on mismatch.
- **A-CL-004 RESOLVED** — the **pinned Quicklisp dist DOES carry ironclad
  v0.61** (the dist's ironclad archive resolves to `ironclad-v0.61.tgz`). The build
  asserts on the archive URL containing `ironclad-v0.61`. Transitive deps the dist
  pulls: `alexandria`, `bordeaux-threads`, `global-vars` (and ironclad's
  `nibbles`) — slightly more than the S1 nibbles+alexandria estimate; all resolved
  offline at build time, none are codec runtime deps.

### Build gotchas hit + fixed (all in the Containerfile)
1. **`zstd.h` missing** — SBCL 2.6.4 `--fancy` builds with core compression
   (`coreparse.c` `#include <zstd.h>`); the runtime link needs `libzstd-devel`, not
   just the `zstd` CLI. Added `libzstd-devel`.
2. **Read-time package resolution** — `(require :asdf)` (and any package load) must
   be its OWN `--eval` before any form NAMING that package, because SBCL's reader
   resolves `asdf:…` / `ironclad:…` symbols at read time, before a preceding form in
   the SAME `--eval` string executes. Split the version-check eval; this is also
   baked into `run-s2.sh`.
3. **ironclad version accessor** — `ql-dist:version` / `ql-dist:name` don't give the
   release version string in 0.61's QL; used `ql-dist:archive-url` (contains
   `ironclad-v0.61`).
4. **ironclad sanity check** — `list-all-key-pair-descriptors` does not exist in
   0.61; replaced the curve-presence assert with a real ed25519/ed448
   sign→verify round-trip + sha256/sha384 digest in the build.

## What was built (`src/`, ASDF system `entity-core`, package `EC`)

| File | Responsibility |
|---|---|
| `package.lisp` | package `entity-core` (nickname `EC`); lisp-case exports |
| `error.lisp`   | the **condition hierarchy** (profile error model = conditions): root `entity-core-error`; leaves `non-canonical-ecf`, `truncated-input`, `tag-rejected`, `bad-seed`, `unsupported-content-hash-format`, `unsupported-key-type`, `duplicate-map-key`. Decode-path rejects signal with no restart (N2/N3 hard reject) |
| `varint.lisp`  | LEB128 multicodec varints (N1) — `varint-encode`/`varint-decode` |
| `base58.lisp`  | Bitcoin-alphabet encode/decode (leading-zero preserving) |
| `cbor.lisp`    | **the heart** — canonical ECF octet-vector encoder + index-walk decoder; map-key length-then-lex sort; shortest-float ladder incl. pure-integer exact f16; recursive tag rejection; native-bignum integers |
| `hash.lisp`    | `content_hash = varint(fc) ‖ HASH(ECF({type,data}))`; SHA-256/384 via ironclad; construct-vs-receive format-code asymmetry (A-CL-007) |
| `peer-id.lisp` | `Base58(varint(kt) ‖ varint(ht) ‖ digest)` + parse + §1.5 canonical-form derivation (A-CL-002 size-cutoff) |
| `sign.lisp`    | Ed25519/Ed448 sign/verify/derive via ironclad (native, no FFI) |

Tests (`test/`, hand-rolled — no FiveAM/rove dep, per the dependency-min stance):
`conformance.lisp` (loads the normative fixture, byte-checks all 69) +
`selftest.lisp` (uncovered-range probes + the Ed448 KAT gate). Entry point
`entity-core/test:run-all` exits non-zero on any failure (CI gate). Convenience
runner `run-s2.sh` (`./run-s2.sh` | `conform` | `self`).

## Value representation (the distinct-idiom decisions)

- **Maps** are an explicit `cbor-map` struct wrapping an alist, NOT a CL list — so a
  map is never confused with an array (a list) or with null; re-sorted on encode.
- **Byte strings** are a `bytes` struct wrapping an octet-vector, distinct from text
  strings — preserves major-type 2 vs 3 and keeps wire data **case-EXACT** (never
  routed through CL symbols; the case-insensitive-reader footgun).
- **Booleans / null** are keyword sentinels `:true`/`:false`/`:null`, and the float
  specials `+nan+`/`+inf+`/`+neg-inf+`/`+neg-zero+` are keywords too — so absent ≠
  null ≠ false ≠ zero on the wire (ECF §1.3), and a NaN/Inf never has to be
  materialized as a CL float.
- **Integers** are native bignums — no uint64/width special-casing anywhere.

## Key implementation notes (the ECF traps, CL-specific)

- **Shortest-float ladder (the classic trap).** Pure-integer, exact, no FFI:
  - f16: extract IEEE fields via `integer-decode-float`; a normalized value fits f16
    iff its low 42 mantissa bits are 0 and the half exponent ∈ [1,30]; a subnormal
    fits iff `value·2^24` is an integer in [1,1023]. -0.0 is the Rule-4a f16
    `f98000`.
  - f32: `sb-kernel:single-float-bits` of `(coerce f 'single-float)`, accepted only
    if it round-trips to the exact double AND the exponent isn't all-ones.
  - f64: `sb-kernel:double-float-bits` fallback.
  - Hit the f16/f32 boundary vectors (65472/65503/65504) and 1.1→f64 exactly.
- **Map ordering.** Sort entries by the ENCODED key bytes, length-first then
  bytewise-lex (ECF Rule 2 / §3.5) — covers text-key, byte-key, and mixed-key
  vectors. (The spec rule is length-then-lex; the Go corpus-builder happens to use
  plain bytewise but the corpus keys agree under both — length-then-lex is the
  normative rule and is what's implemented.)
- **Recursive tag-6 reject (N2).** `%dec` signals `tag-rejected` on ANY major-type-6
  item at any depth — not trusting a library default (there is no library). Bare
  55799 (`d9d9f7…`) and tags nested inside `included` entity data both reject.
- **content_hash format_code (A-CL-007).** Construct side serializes the
  caller-supplied `format_code` verbatim (so content_hash.4 with code 128 passes);
  receive-side `resolve-content-hash-format` rejects unallocated codes with
  `unsupported-content-hash-format`. **Independently reached the same A-OC-004
  resolution** — corroboration (see SPEC-AMBIGUITY-LOG A-CL-007).
- **peer_id = §1.5 canonical form (A-CL-002).** `peer-id-from-public-key` derives
  from the §1.5 size-cutoff table (Ed25519 ≤32B → `hash_type=0x00` identity-multihash,
  raw pubkey; Ed448 >32B → `hash_type=0x01`, SHA-256(pubkey)). The stale §7.4
  SHA-256-form is NOT implemented as a construction path. Verified by the Ed448 KAT
  peer_id matching the locked SHA-256-form pin.

## Dev loop

```
# full gate (container-bound, sealed offline):
./run-s2.sh            # ECF 69/69 + selftest + Ed448 KAT; exits non-zero on FAIL
./run-s2.sh conform    # ECF corpus PASS/FAIL counts only
./run-s2.sh self       # uncovered-range + Ed448 KAT selftest only

# or directly:
podman run --rm --network=none -v $PWD:/work:Z \
  -w /work/protocol-generator/common-lisp \
  entity-core-keystone/common-lisp-toolchain:latest \
  sbcl --non-interactive \
    --eval '(require :asdf)' \
    --eval '(load #p"/opt/quicklisp/setup.lisp")' \
    --eval '(push (truename ".") asdf:*central-registry*)' \
    --eval '(asdf:load-system :entity-core/test)' \
    --eval '(entity-core/test:run-all)'
```

## Exit criteria

All 69 vectors PASS · selftests PASS · Ed448 KAT byte-equal · SBCL/ironclad load
clean (no peer-code warnings) · ambiguity log has no blocking codec items ·
container reproducible (SHA filled, dist pinned). **S2 PASS.**

## Not in this phase (S3+, next session)

- Peer machinery (connection, dispatch via CLOS multiple dispatch, capability,
  store, processor, handlers) on native SBCL threads (A-CL-003) — resynced to the
  v7.74 peer surface (register/outbound/emit/owner-cap + §7a conformance handlers)
  per A-CL-001.
- The v7.73/v7.74 spec-data snapshot is still missing (A-CL-001 escalation to arch);
  S3 mirrors the C#/TS/OCaml/Elixir folded-proposal build.
- Full agility matrix (MATRIX-M2/M3/M6 7-gate tuples, cap-token content_hash, key_type
  registry refusals) — peer-layer, needs the §3.6 cap-token shape (same deferral as
  Elixir). The Ed448+SHA-384 crypto primitives are proven at S2.
