# entity-core-protocol-unison — Phase S1 Summary

**Peer:** #43 (Unison, operator-directed) · **Spec basis:** v0.8.0 / V8 (`spec-data/v0.8.0/`) ·
**Phase:** S1 (research + profile authoring + container provisioning + de-risk spike) ·
**Status:** COMPLETE — no blocking ambiguity items. Container BUILT + spike-verified.

Unison is a **coverage / generator-robustness** peer (the wire-discovery well is dry on the
current surface). Its value is three non-wire data points: (1) generator robustness on a
**content-addressed codebase, headless-transcript** build model; (2) a **no-C-FFI
crypto-spectrum** datum (native Ed25519+SHA-256, no Ed448/SHA-384, no FFI escape hatch); (3) an
**abilities / algebraic-effects concurrency** taxonomy datum for §7b. Protocol meaning was read
from `spec-data/v0.8.0`; sibling *profiles* (haskell, common-lisp) consulted for structure only.

---

## THE de-risk: headless UCM in a container — PROVEN

The critical risk (per the S1 task contract): Unison source lives in a content-addressed
**SQLite codebase** managed by **UCM**, which is interactive by design, while our pipeline is
container-bound + non-interactive. If UCM could not drive a `.u` file headlessly in a
container, the whole build was a dead-end. **It can.** Two headless entry points, both proven:

- `ucm transcript <file.md>` — executes a markdown transcript (fenced ```unison / ```ucm
  blocks), emits a diffable `<file>.output.md`. **This is the build/test interface.**
- `ucm run.file <file.u> <symbol>` — headless single-run of a definition from a `.u` file.

### Spike command + observed output (all under the resource caps, in `unison-toolchain`)

Container build (`podman build $PODMAN_BUILD_CAPS -f containers/unison-toolchain/Containerfile .`):
```
STEP … ucm --version
unison version: release/1.3.0 (built on 2026-05-13)
Successfully tagged localhost/entity-core-keystone/unison-toolchain:latest
```

**Native crypto proof** — transcript (`builtins.mergeio`, then RFC-8032 §7.1 Test-1 keypair +
watch-expressions), run via
`podman run --rm $PODMAN_RUN_CAPS -v …:/spike -w /spike unison-toolchain ucm transcript crypto-proof.md`:
```
22 | > crypto.hashBytes crypto.HashAlgorithm.Sha2_256 (Bytes.fromList [104, 101, 108, 108, 111])
       ⧩
       0xs2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824   ← exact SHA-256("hello") KAT

23 | > edSignMatchesVector      (crypto.Ed25519.sign.impl seed pubkey "" == RFC-8032 Test-1 signature)
       ⧩
       true

24 | > edVerifyVector           (crypto.Ed25519.verify.impl pubkey "" signature)
       ⧩
       true
```

**Crypto surface** (`find crypto` after `builtins.mergeio`): `crypto.hashBytes`,
`crypto.hash`, `crypto.hmac(Bytes)`, HashAlgorithms **Sha2_256 / Sha2_512 / Sha3_256 /
Sha3_512 / Blake2b_256/512 / Blake2s_256 / Md5 / Sha1**, `crypto.Ed25519.sign.impl` /
`verify.impl`, `crypto.P256.*`, `crypto.Rsa.*`, `crypto.argon2.*`. **NO Ed448. NO Sha2_384.**
Signatures:
- `crypto.Ed25519.sign.impl   : Bytes -> Bytes -> Bytes -> Either Failure Bytes`   (secretKey, publicKey, message)
- `crypto.Ed25519.verify.impl : Bytes -> Bytes -> Bytes -> Either Failure Boolean` (publicKey, message, signature)
- `crypto.hashBytes : HashAlgorithm -> Bytes -> Bytes`

**Numeric model proof** (transcript watches):
```
Nat.increment 18446744073709551615  (2^64-1)  ⧩ 0                       ← Nat = 64-bit unsigned, wraps mod 2^64
Int.increment +9223372036854775807  (2^63-1)  ⧩ -9223372036854775808   ← Int = 64-bit signed two's-complement wrap
Float.toRepresentation 1.0                     ⧩ 4607182418800017408    ← = 0x3FF0000000000000, raw IEEE-754 double bits
```

**Networking** (`find.all serverSocket` / `find.all socketSend` after `builtins.mergeio`):
`builtin.io2.IO.serverSocket.impl`, `builtin.io2.IO.socketSend.impl` (+ the io2.IO.* TCP
family) are **runtime builtins** — no base pull needed for S3 sockets.

---

## Container build result — PASS (built + spike-verified, not just authored)

- `podman build … containers/unison-toolchain/Containerfile` (under caps) → **SUCCESS**
  (~37 s). Base `fedora:43` + runtime libs (gmp, zlib, glibc via `ldd`) + pinned UCM tarball.
- **Toolchain pin fail-closed:** UCM `release/1.3.0` `ucm-linux-x64.tar.gz` **exact sha256**
  matched (`0c52e223…d433b`); `ucm --version` → `release/1.3.0 (built on 2026-05-13)`.
- **Offline story:** UCM builtins (crypto, hashing, Bytes, io2.IO sockets) are baked into the
  binary — the **builtins-only core floor builds/runs fully `--network=none`** after the
  one-time toolchain pull. The only networked step is the container build's toolchain download.

## Decisions + pins (S11: pin ≥30 days old)

| Surface | Decision | Pin | Age | S11 |
|---|---|---|---|---|
| Codec strategy | **native**, **builtins-only floor** (A-005 confirm; crypto+sockets builtin, CBOR hand-rolled) | — | — | — |
| CBOR | **hand-rolled** ECF (zero CBOR dep; Float.toRepresentation for the float ladder) | in-repo | — | — |
| Toolchain | **UCM `release/1.3.0`** linux-x64 tarball, sha256-pinned fail-closed | `release/1.3.0` | ~60 d | ✅ |
| Ed25519 + SHA-256 | **NATIVE UCM builtins** (`crypto.Ed25519.*`, `crypto.hashBytes Sha2_256`); KAT-proven | ucm-1.3.0 | — | ✅ |
| **Ed448 + SHA-384** | **DEFERRED** — not builtins; **no C FFI escape hatch** (managed runtime); WARN not gating | n/a | — | (A-UN-001) |
| Numeric | **fixed-width 64-bit** Nat(unsigned)/Int(signed); NO bignum; head-form + [2^63,2^64-1] self-test | — | — | (A-UN-003) |
| base58 / varint | hand-rolled | in-repo | — | — |
| Error model | pure **`Either CodecError a`**; Exception/Abort abilities at the IO edge | — | — | (A-UN-005) |
| Concurrency | **abilities (algebraic effects) over IO** — fork + MVar-serialized store (new §7b shape) | — | — | (A-UN-004) |
| Naming | Unison (UpperCamelCase types/ctors/abilities; lowerCamelCase terms/fields) | — | — | — |
| Build / Test | **UCM headless transcripts** (`ucm transcript`); no test-framework dep | — | — | ✅ |
| Publishing | **Unison Share** (`ucm push …/releases/<semver>`); deferred like the cohort | — | — | — |
| License | **Apache-2.0** (S9 default; Unison is MIT-lean, not mandated) | — | — | — |
| Third-party deps | **ZERO at the core floor** (`@unison/base` optional; pin deferred to S2-first-pull if adopted) | — | — | (A-UN-002/007) |

## What I researched

- **spec-data/v0.8.0 (directly, spec-first):** §1.5 identity canonical-form (Ed25519 → key_type
  0x01, hash_type 0x00 identity-multihash, digest = raw 32-byte pubkey); §7.3 signature/varint
  framing; §7.4 peer_id (defers to §1.5); ENTITY-CBOR-ENCODING §2.2 (map-key length-then-lex over
  encoded bytes, shortest-float incl. f16), §6.3 (Option B tag-reject); §8.1 key/hash tables.
  MANIFEST: core wire byte-unchanged V7→V8.
- **UCM toolchain:** GitHub release history + dates (via the releases API); `release/1.3.0`
  (2026-05-20) is the newest tagged release before the 30-day floor; `trunk-build` is rolling
  (not used). Asset `ucm-linux-x64.tar.gz` downloaded, sha256 computed, contents + `ldd` inspected.
- **Crypto / numeric / networking:** discovered live in-container (spike above) — the
  authoritative source, not docs.
- **Build model:** UCM subcommands (`transcript`, `transcript.fork`, `run`, `run.file`,
  `run.compiled`, `compile`); content-addressed SQLite codebase; `builtins.mergeio` seeds the
  builtin namespace into a fresh codebase.
- **Packaging / license / naming idioms** per Unison norms (Unison Share, MIT-lean, camelCase).

## Ambiguity-log entries opened (8, none blocking)

- **A-UN-001** — Ed448 + SHA-384 not native; **no C FFI escape hatch** → agility DEFERRED (WARN not gating). → research (crypto ledger).
- **A-UN-002** — codec native, **builtins-only floor** (zero third-party dep); @unison/base optional. → operator + research.
- **A-UN-003** — numeric **fixed-width 64-bit** (Nat/Int); carry head form + [2^63,2^64-1] self-test; no bignum. → operator (durable lesson).
- **A-UN-004** — concurrency = **abilities/algebraic-effects over IO**; MVar-serialized store = new §7b taxonomy shape. → research.
- **A-UN-005** — error model = pure `Either CodecError a` + Exception/Abort abilities at the IO edge. → operator (idiom).
- **A-UN-006** — build = content-addressed codebase, **headless `ucm transcript`** (generator-robustness datum). → operator + research.
- **A-UN-007** — @unison/base version pin deferred to S2-first-pull (optional, non-blocking). → research.
- **A-UN-008** — peer_id from the §1.5 canonical-form table (corroboration, not a finding). → research.

## Spec-first observations (no NEW spec defects found at S1)

Reading v0.8.0 directly surfaced no new spec contradiction. The peer-id §7.4-vs-§1.5 tension is
reconciled in-body (§7.4 defers to §1.5); Unison corroborates it (A-UN-008). CBOR canonical
rules read unambiguously. The Unison-specific mapping judgments (fixed-width head form,
Text-byte-vs-codepoint via `Text.toUtf8`, builtins-only floor, abilities concurrency) are
generation-discipline calls, not spec ambiguities. As expected for a coverage peer on a dry
wire surface, the value is the three non-wire data points above, not new wire findings.

---

## S2 entry checklist

1. **Container:** `entity-core-keystone/unison-toolchain:latest` — BUILT + verified. Dev loop:
   `podman run --rm --network=none -v $PWD:/work:Z -w /work/protocol-generator/unison
   entity-core-keystone/unison-toolchain:latest ucm transcript transcripts/conformance.md`.
2. **Codec strategy:** `native`, **builtins-only floor** — hand-rolled canonical ECF CBOR over
   Bytes/Nat/Float builtins + `crypto.*` builtins (Ed25519/SHA-256). Zero CBOR/base58/varint
   deps; those + the needed list/text helpers are hand-rolled in-repo. `ffi` is structurally
   unavailable (no C FFI) — do NOT reach for it.
3. **First spike (the S2 gate, cheap insurance per PHASE-S1-PROFILE):** push the `map_keys` +
   `float` ECF test-vectors (v0.8.0 corpus) through the hand-rolled encoder BEFORE the full
   build — confirm length-then-lex map-key ordering (over encoded bytes), shortest-float incl.
   f16 (via `Float.toRepresentation`), recursive major-type-6 tag rejection (§6.3 Option B).
   The crypto+toolchain+headless spikes already passed at S1.
4. **FIXED-WIDTH discipline (A-UN-003 — carry into every codec line):** `Nat` = 64-bit unsigned
   (major-type-0 carrier, full range); `Int` = 64-bit signed (do NOT use for the largest nint
   magnitudes — decode nint as `-(n+1)` with `n : Nat`); carry the integer HEAD FORM explicitly;
   self-test [2^63, 2^64-1]. Float via `Float.toRepresentation : Float -> Nat` for the f16/f32/f64
   shortest ladder.
5. **Text/bytes:** wire byte length of a text string = `Text.toUtf8 |> Bytes.size` (UTF-8 bytes),
   NOT `Text` codepoint length. Map-key sort over encoded key bytes. No unchecked `Bytes.at`/
   `List.at` on decoded/untrusted data (`no_partial_on_wire`) — every wire access total + checked.
6. **Error/idiom:** pure codec = `Either CodecError a` (no abilities in the codec); Exception/Abort
   abilities only at the S3 transport edge.
7. **Corpus:** v0.8.0 ECF corpus (71 vectors after F29/F30 re-vendor). **Agility (Ed448/SHA-384)
   corpus is OUT OF SCOPE** — Ed448 deferred (A-UN-001), no A-SW-001-style gate needed but the
   agility vectors are skipped/WARN, not failed.
8. **Oracle:** `wire-conformance` (pure codec) is the S2 ground truth — byte-identical to
   `entity-core-codec-ffi`. S2 is done when it says so.
9. **Offline:** the builtins-only floor builds/runs `--network=none` (no per-build pull). Only if
   `@unison/base` is later adopted does a one-time networked `pull` appear at setup (A-UN-002/007).
10. **NOT in S2:** §7a/§7b conformance scaffolding (S3/S4, GUIDE-carried); the peer machinery (S3);
    the abilities/fork concurrency (S3, codec is pure/synchronous); Ed448/SHA-384 agility (deferred).

## Time spent

~1 session. The bulk was the front-loaded container + headless-UCM + crypto/numeric/networking
spike (the mandated de-risk), which settled cleanly on the first real transcript once builtins
were merged. Profile authoring + rationale + logs followed from the proven facts.
