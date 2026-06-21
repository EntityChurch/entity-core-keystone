# Prolog peer — PHASE S2-FFI report

**Phase:** S2-FFI (FFI codec + crypto binding — the de-risking phase)
**Verdict line:** **`S2-FFI: GREEN`**

The byte-floor (canonical CBOR encode/decode, content_hash, peer_id, Ed25519/Ed448
sign+verify, SHA-256/384) is sourced over the entity-codec C-ABI
(`libentitycore_codec`, ABI v1.1) through a SWI foreign-predicate shim. The full
69-vector wire-conformance corpus round-trips byte-identically, and the crypto KAT
pins (Ed25519 / Ed448 / SHA-256 / SHA-384) all match the cohort ground truth. S3
(peer/transport/relational core) is NOT started — S2-only, per scope.

---

## 1. Gate result

| Gate | Result | How verified |
|---|---|---|
| Wire-conformance corpus | **69 / 69 byte-identical** | each vector driven end-to-end through the foreign codec inside the prolog-toolchain container (`swipl … run_conformance.pl`) |
| Crypto KAT | **10 / 10** | `agility_kat.pl` asserts pins transcribed from the cohort-blessed `.diag`/SEEDS |

### 69/69 by category (raw harness output)
```
── by category ──
  content_hash  4/4
  envelope      2/2
  float         14/14
  int           14/14
  length        8/8
  map_keys      6/6
  nested        4/4
  peer_id       3/3
  primitive     6/6
  signature     3/3
  tag_reject    5/5

TOTAL: 69 passed, 0 failed (of 69; corpus carried 69 vectors)
# RESULT: PASS (69/69)
```
Corpus = `protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`,
sha256 `41d68d2d717f84e195d46ec002fce6b8729742026256e72dc7a3a8b6c0c6a052`
(byte-identical to the v7.71 MANIFEST pin; ECF corpus unchanged v7.56→v7.71). The
69 runnable vectors = 64 `encode_equal` + 5 `decode_reject` (the same "69/69" gate
C# / Rust-FFI / C-FFI passed; the corpus array holds exactly 69 elements).

### 10/10 crypto KAT (raw harness output)
```
SHA-256 KAT:
  [PASS] sha256("abc")
SHA-384 KAT:
  [PASS] sha384("abc")
Ed25519 floor (keygen + deterministic KAT):
  [PASS] Ed25519 keygen→sign produces a 64-byte signature
  [PASS] Ed25519 sign(seed=0x00*32, ECF{test/v1,{x:1}}) [signature.1]
  [PASS] Ed25519 verify(pub, ECF, signature.1)
  [PASS] Ed25519 verify rejects a flipped signature
Ed448 agility (KEY-TYPE-ED448-1 pins):
  [PASS] Ed448 seed(0x42*57) → pubkey (57B)
  [PASS] Ed448 sign(seed, fixture msg) (114B, RFC 8032)
  [PASS] Ed448 sign→verify round-trip
  [PASS] Ed448 peer_id (key_type=0x02, hash_type=0x01)
# RESULT: PASS (10/10)
```
KAT pins are transcribed from `shared/test-vectors/v0.8.0/agility-vectors-v1.diag` +
`agility-SEEDS.md` and the conformance `signature.1` vector (the same pins the OCaml
agility harness asserts). The Ed25519 `signature.1` KAT is the corpus signature
vector re-derived independently here (deterministic RFC-8032 sign over
ECF({type:test/v1, data:{x:1}}) under the all-zero seed). SHA-256/384 KATs are the
RFC-style `"abc"` digests.

### Run command (in-container, network-isolated)
```
podman run --rm --network=none -v "$PWD":/work:Z -w /work \
  entity-core-keystone/prolog-toolchain:latest \
  protocol-generator/prolog/run-s2.sh
…
 conformance rc=0   kat rc=0
 S2-FFI GATE: GREEN
```
`run-s2.sh` (a) builds `libentitycore_codec.so` from the C-ABI CMake, (b) compiles
the shim with `swipl-ld -shared`, (c) runs the 69-vector corpus, (d) runs the KAT.
A clean from-scratch run reproduces GREEN.

## 2. What was built (files)

| File | Role |
|---|---|
| `containers/prolog-toolchain/Containerfile` | **modified** — added `libsodium-static libsodium-devel pkgconfig` (the C-ABI CMake statically+privately links libsodium; the shim needs the discovery). swipl-ld + SWI-Prolog.h already ship in the `swi-prolog` package. The pre-existing locale (`C.UTF-8`) + crypto-assertion fixes from the spike are retained. |
| `protocol-generator/prolog/c/ec_codec_pl.c` | the C foreign-predicate shim: wraps the `ec_*` C-ABI symbols (transcribed verbatim, no header on the include path — the OCaml-seam model) as 18 SWI foreign predicates registered via `PL_register_foreign`. Bytes cross as SWI strings (`REP_ISO_LATIN_1`, 1 byte = 1 code, NUL-safe, length-carried). |
| `protocol-generator/prolog/prolog/ec_codec.pl` | the **deterministic** Prolog codec surface (module `ec_codec`). Loads the shim (`use_foreign_library/1`), wraps every foreign call in `once/1` (A-PL-005), plus `ec_content_hash_prefixed/4` (the forward-compat composition, A-PL-011) and byte/hex helpers. |
| `protocol-generator/prolog/test/cbor_fixture.pl` | a minimal CBOR *reader* (HARNESS-ONLY) that navigates the conformance fixture (a CBOR array of vector-maps), extracting per-vector `id`/`kind`/`canonical` + the `input` value's structured term AND its raw byte span. NOT the peer's codec — a meta-layer corpus navigator. |
| `protocol-generator/prolog/test/run_conformance.pl` | the 69-vector wire-conformance harness; dispatches by category exactly like the C-ABI `conformance_harness.c`. |
| `protocol-generator/prolog/test/agility_kat.pl` | the crypto KAT harness (Ed25519/Ed448/SHA-256/384 pins). |
| `protocol-generator/prolog/run-s2.sh` | the in-container build+gate orchestrator. |
| `protocol-generator/prolog/.gitignore` | ignores `build/` + the byte-built `.so` (sources committed, artifacts regenerated). |
| `protocol-generator/prolog/status/SPEC-AMBIGUITY-LOG.md` | **appended** S2-FFI results (A-PL-005/009 resolved) + two new findings A-PL-011, A-PL-012. |

`spike-s2/cbor.pl` is UNTOUCHED (durable evidence artifact, per scope).

## 3. Pins (container / SWI / libsodium / corpus)

- **SWI-Prolog 9.2.9** — fedora:43 distro `swi-prolog` package; version flag 90209,
  confirmed on the 9.2.x STABLE line (A-PL-008, resolved positive at the spike, re-
  confirmed). swipl-ld at `/usr/bin/swipl-ld`, header at
  `/usr/lib64/swipl/include/SWI-Prolog.h` (ship in the package; no `-devel` needed).
- **fedora:43**, **OpenSSL 3.5.4** (image-provided; `library(crypto)` SHA path; the
  signature floor does NOT use it — see below).
- **libsodium 1.0.22** (static archive, privately linked into `libentitycore_codec`
  by the C-ABI CMake; reported in `ec_impl_info`).
- **C-ABI codec impl:** `c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 / libsodium
  1.0.22 (+ hand-rolled sha384; ed448 via vendored openssl-3.3.2 curve448 +
  shake256)` — built from `ffi-generator/c-abi/entity-core-codec-ffi-c` (its own
  CMake). ABI version `1.1`.
- **Conformance corpus:** v7.71 `conformance-vectors-v1.cbor`, sha256 `41d68d2d…a052`.

## 4. Determinism notes (A-PL-005)

Every public codec predicate is `det`/`semidet`: a `findall/3` over each
(`ec_encode_ecf`, `ec_sha256`, `ec_content_hash_prefixed`, `ec_ed25519_keygen`, …)
yields EXACTLY ONE solution — the wire is a function, no choice point leaks across
the boundary. The foreign predicates register with flag `0` (= deterministic; SWI
has no separate "deterministic" flag, only `PL_FA_NONDETERMINISTIC` to opt INTO
retry), and `ec_codec.pl` wraps each in `once/1` as the explicit public-surface
guard. One nuance: `deterministic/1` called right after a foreign call inside an
`(If->Then)` can report `false` even when the single-solution invariant holds — a
SWI foreign-frame-teardown reporting artifact, not a real CP; the single-solution
findall is authoritative. (Logged under A-PL-005 RESOLVED in the ambiguity log.)

## 5. New / resolved spec-ambiguity findings

- **A-PL-002 (signature floor → FFI)** — re-confirmed: the entire Ed25519+Ed448
  signature surface is sourced over the C-ABI; `library(crypto)` 9.2.9 has no
  ed25519/ed448 predicates. SHA-256/384 ALSO go through the C-ABI (`ec_sha256`,
  `ec_sha384`) for uniformity (rather than `crypto_data_hash/3`) — implementer's
  call, documented: one crypto provider, byte-checked against the cohort KATs.
- **A-PL-009 RESOLVED** — corpus provenance confirmed by sha256 (matches MANIFEST).
- **A-PL-005 RESOLVED** — determinism discipline holds (see §4).
- **A-PL-011 (NEW)** — the public `ec_content_hash_with_format` REJECTS forward-
  compat format codes (e.g. 0x80) that the corpus still pins with real bytes
  (`content_hash.4`). The peer composes the prefixed hash from public symbols
  (`ec_content_hash` digest + `ec_hash_format_code_encode` prefix) →
  `ec_content_hash_prefixed/4`. An ABI-surface seam worth surfacing to arch; affects
  any FFI peer driving content_hash.4 through the public ABI.
- **A-PL-012 (NEW)** — Ed448's 57-byte pubkey exceeds the §1.5 identity-multihash
  32-byte cutoff, so its peer_id digest is `SHA-256(pubkey)` (hash_type 0x01
  "SHA-256-form"), NOT the raw key. A-PL-010's "digest = raw pubkey" rule is the
  ≤32B (Ed25519) branch only. Baked into the agility KAT so S3 identity does not
  regress it.

## 6. Rabbit holes / things to double-check

- **The harness needs a CBOR reader to navigate the fixture.** The conformance
  fixture is itself a CBOR array of vector-maps, so the harness hand-rolls a minimal
  CBOR *decoder* (`cbor_fixture.pl`) just to extract the per-vector fields + raw
  spans. This is HARNESS-ONLY meta-layer code (it never re-encodes; the C-ABI owns
  all wire bytes), but it is non-trivial Prolog and is the one place a subtle bug
  could make a vector "pass" by mis-parsing. Mitigation: the float decode in the
  reader is only used to count/inspect — the actual encode_equal check feeds the
  input's RAW byte span to `ec_encode_bare_value` (decode→canonical-re-encode in C),
  so the harness's float math never gates a result. Still worth a skeptical glance.
- **Class-A vectors are driven via `ec_encode_bare_value`** (decode-then-canonical-
  re-encode), matching the OCaml/C harness's "re-encode the decoded input". Since
  the fixture stores `input` already-canonical, this is the meaningful encoder
  exercise (it forces the C encoder's minimization/ordering) rather than a trivial
  identity — verify you agree that's the right semantics (it is what the C-ABI's own
  harness does for the non-special categories).
- **content_hash.4 / A-PL-011** is the one place I deviate from a naive "call the
  obvious public symbol" approach. If arch later makes `ec_content_hash_with_format`
  accept arbitrary codes, `ec_content_hash_prefixed` can collapse to it; until then
  the composition is the only public-ABI path to the pinned bytes. Flag this one.
- **Corpus version is v7.71, oracle is v7.75-class.** S2 gates against the v7.71
  codec corpus (the latest vendored; ECF unchanged v7.56→v7.71). S4 must confirm the
  v7.75 Go oracle agrees on these exact 69 wire bytes — expected (no wire-format
  change), but verify rather than assume.

---

**Verdict:** **`S2-FFI: GREEN`** — 69/69 wire-conformance byte-identical + 10/10
crypto KAT, verified end-to-end through swipl + the foreign codec, in-container,
network-isolated, reproducible from a clean build. Ready for S3 on operator GO.
