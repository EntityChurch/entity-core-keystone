# entity-core-protocol-python — Profile Rationale

Audit trail for every major S1 profile choice for the **Python** peer. This is the
document a future operator reads to answer "why did we pick X for Python?".

## ⚠️ Clean-room constraint (the defining property of this peer)

**Python has a hand-written sibling reference impl, `entity-core-py`.** This peer —
`entity-core-protocol-python` — is a **clean-room reimplementation from the
specification**, deliberately *distinct from* and *independent of* `entity-core-py`.
This is exactly the **Go** situation: the Go peer is a clean-room clone for a
language that ALSO has a hand-written sibling (`entity-core-go`, which is moreover
the oracle). The whole value of a same-as-sibling peer is independence.

How I honored it while authoring S1:

- I read **only**: `spec-data/v7.75` (the SHA-pinned verbatim V7 snapshot:
  `ENTITY-CORE-PROTOCOL-V7.md`, `ENTITY-CBOR-ENCODING.md`,
  `ENTITY-NATIVE-TYPE-SYSTEM.md` + `MANIFEST.md`), the keystone `shared/lifecycle`
  contracts (`PROMPT-CONSTANTS.md`, `PHASE-S1-PROFILE.md`), the
  `shared/seed-policy/` convention, the cohort's **language-neutral** sibling
  profiles (`go/`, `ruby/`, `csharp/`, `typescript/` — for FIELD-SCHEMA and idiom-
  cross-reference only, not spec interpretation), an existing toolchain Containerfile
  (`ruby-toolchain`, `prolog-toolchain`, `base`) for the container shape, and the
  seeded cohort memory.
- I did **NOT** open, read, `cat`, `grep`, `find`, or otherwise reference any file
  under any `entity-core-py` checkout — not its codec, not its crypto, not its peer
  loop, not its `pyproject.toml`/`setup.py`. Every protocol-shaped decision below
  grounds in a **V7 §-pointer** from the spec snapshot, never in sibling source.
- The Python *language idioms* recorded here (`cryptography` for Ed25519/Ed448,
  hand-rolled canonical CBOR, threading + GIL accounting, `Lock`-guarded store,
  exceptions, PEP-8 snake_case, pyproject/hatchling/PyPI) are derived from **general
  Python ecosystem knowledge** and the spec's requirements — what *any* competent
  Python engineer would reach for, not what I observed the sibling doing.

The clean-room rule is about **build-time source isolation**. It does **not** forbid
the S4 step of validating this peer's *output bytes* against the oracle — that
byte-comparison is how conformance is proven and is allowed (the oracle commit
`e8524ed`, target `--profile core`, is recorded in the profile `[spec]` block for
that S4 leg).

### Adoption value + independence-check framing (the honest signal caveat)

Per the cohort's same-as-sibling honesty caveat (the Go rationale, the 8-peer
synthesis: **the spec-discovery well is dry**), the value proposition of this peer
is stated narrowly and honestly. It is **NOT** banked on as a fresh source of spec
findings — the productive discovery axes (integer / float / crypto / string /
dispatch) are saturated across the existing cohort, and Python's idioms (arbitrary-
precision int, exceptions, native-full-agility crypto) duplicate axes already
stressed by Ruby/Elixir/Haskell. Instead:

1. **Adoption** — a `pip install`-able, spec-derived core peer for the **largest
   dynamic-language community**. This is the headline value: Python's reach makes a
   conformant peer broadly useful regardless of novel spec discovery.
2. **Independence check on the generator** — a from-scratch Python impl that lands
   `--profile core` GREEN and byte-identical on the corpus is genuine corroboration
   that the *spec*, not some sibling-private convention, determines the behavior
   (the same-language independence accounting). It exercises the generator's Python
   output end-to-end rather than assuming it.

If it surfaces a net-new spec finding, that is a bonus; the plan does not bank on it.
(Cohort precedent: genuine discoveries came from distant-idiom seams — OCaml's
63-bit int, Zig's no-GC, Lean's proofs, CL's hex-case — not from same-as-sibling
arrivals.)

## Spec version: full v7.75 snapshot (no snapshot-lag caveat)

Like the Ruby and Go peers (and **unlike** peers #1–8, which built against a
`spec-data` snapshot lagging spec HEAD and reconstructed the newer peer-surface from
folded proposal text — A-ELX-001 and siblings), Python derives S1/S2/S3 entirely
against ratified spec text: **`spec-data/v7.75` is a complete, SHA-pinned snapshot**
with the full `ENTITY-CORE-PROTOCOL-V7.md` body. The register/outbound/emit/owner-
cap/§7a peer surface AND the v7.75 §4.8 store-safety / §4.9 resilience / §4.10
resource-bounds substrate floor are all present. The codec specs
(`ENTITY-CBOR-ENCODING.md` label 1.5, `ENTITY-NATIVE-TYPE-SYSTEM.md` 4.2.1) are
byte-identical v7.73→v7.75 per the MANIFEST, so the wire is stable and the codec
corpus is valid. No A-ELX-001-style escalation is needed.

## Codec strategy: native

The A-005 pattern holds for a 13th language: **no Python CBOR library gives ECF's
canonical guarantees out of the box**, so the canonical layer is hand-rolled
regardless of what sits underneath; meanwhile **crypto is native-full-agility via
the `cryptography` library** (OpenSSL backend), which reaches Ed25519, **Ed448**,
and the SHA-2 family. So `native` is correct on both halves. `ffi` (consume
`libentitycore_codec`) stays the documented fallback but is not expected to be
needed at any tier.

## CBOR: hand-rolled (cbor2 considered and rejected)

Surveyed the Python CBOR landscape:

- **`cbor2`** (agronholm, C-accelerated, the de-facto Python CBOR library): mature,
  widely used, and it *does* offer a `dumps(obj, canonical=True)` mode — the nearest
  any Python library gets. It is **rejected for the core codec** (logged A-PY-001)
  because its "canonical" mode targets **RFC-8949 §4.2 bytewise** key ordering,
  which is the **WRONG order for ECF** — ECF requires **length-then-lexicographic on
  the ENCODED key bytes** (RFC-7049 length-first ≠ RFC-8949 bytewise; the exact trap
  every prior native peer flagged). Beyond the wrong encode-side order, cbor2 does
  **not**:
  - minimize floats on **decode** (Rule 4 must be enforced on receive, not just
    emit — a received non-minimal float is non-canonical),
  - recursively **reject major-type-6 tags** on decode returning the specific
    `400 non_canonical_ecf` (§6.3) — it *decodes* tags into Python objects instead,
  - guarantee raw-byte fidelity for the arbitrary-ECF `data` field (N4),
  - carry the full uint64/nint range in a single canonical head-form path.

  So cbor2 gives **none** of the ECF decode-side contract and the **wrong** encode-
  side map order — every one of those would have to be hand-written *on top of* the
  library anyway, at which point the library is doing what the hand-roll already
  does. The other Python CBOR options (`cbor` pure-Python is abandoned; `cbor-diag`
  is diagnostic-only) are not candidates.

Hand-rolling `entity_core/_cbor.py` is both faithful and *simpler* than bending
cbor2 (which fights the length-first rule). Python makes this pleasant: **arbitrary-
precision `int`** (no uint64 head-form trap — see below) and `bytes` / `bytearray` /
`memoryview` byte buffers make the byte-level cursor clean (the decoder is a byte
cursor over a `bytes`/`memoryview` — `struct.unpack` / slicing / `int.from_bytes`
are idiomatic). The bar for a future maintainer to swap cbor2 in is explicit:
prove it reproduces `map_keys.*` / `float.*` / `tag_reject.*` byte-for-byte AND
enforces decode-side rejection — at which point it equals the hand-roll. **Spike the
`map_keys` + `float` vectors at S2** before committing the full build (the load-
bearing codec risk).

## Crypto: `cryptography` — native-full-agility (Ed25519 + Ed448, the Haskell/Ruby result)

The standout, and the reason Python lands in the **native-full-agility** class
(Haskell #8, Ruby #12) rather than the hybrid-FFI class (OCaml/Zig/Go, which had no
native Ed448). The **`cryptography`** library (pyca/cryptography — the de-facto
Python crypto library, OpenSSL-backed and audited) provides, through `hazmat`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448   import Ed448PrivateKey

sk  = Ed25519PrivateKey.from_private_bytes(seed32)   # entity-core PEM = b64(32B seed)
sig = sk.sign(msg)                                    # 64-byte, deterministic (RFC-8032)
sk.public_key().verify(sig, msg)                      # raises InvalidSignature on fail
seed = sk.private_bytes_raw(); pub = sk.public_key().public_bytes_raw()  # raw 32-byte keys
```

and the **identical surface for Ed448** (`Ed448PrivateKey.from_private_bytes(seed57)`,
57-byte seed, 114-byte signature, PureEdDSA). So §1.5 `key_type 0x02` (the crypto-
agility higher bar) is reachable with **no FFI, no opt-in sub-library, no second
crypto source** — the Haskell/Ruby native-full-agility headline, replicated on a
**fourth** native-crypto substrate (Python + OpenSSL via `cryptography`). The agility
corpus (KEY-TYPE-ED448-*, HASH-FORMAT-SHA-384-*) is reachable from the default build.

- **Ed25519 is deterministic by construction** (RFC-8032 — no RNG in the signing
  path), so the crypto-library version is **conformance-neutral** (the C# F10
  lesson). The version pin matters for supply-chain hygiene (S11), not for wire
  output.
- `private_bytes_raw` / `public_bytes_raw` / `from_private_bytes` require
  `cryptography >= 35`; we pin **48.0.0** (see [deps] below). Exact spelling +
  raw-key availability confirmed in-container at S2 (A-PY-003).

> **Candidate considered and declined: PyNaCl** (libsodium binding). PyNaCl works
> for Ed25519 + SHA-512 and is audited (libsodium), but it is **Ed25519-only** — it
> has **no Ed448**, so it cannot reach the agility higher bar without a second crypto
> source (the exact hybrid-FFI position OCaml/Zig/Go were forced into). `cryptography`
> dominates it: same audited pedigree, a single dependency, AND a strictly larger
> crypto reach (Ed25519 + Ed448 + the full SHA-2 family). PyNaCl also pulls a native
> libsodium build; `cryptography`'s manylinux wheels bundle OpenSSL. So
> `cryptography` is the single-dep, native-full-agility choice.

**Caveat to verify at S2 (A-PY-002):** the bundled OpenSSL build must actually enable
Ed448 — `cryptography`'s manylinux wheels (and the fedora system OpenSSL 3.x) ship
it, but a `crypto:supports`-equivalent round-trip assertion goes in the container
build (see [container]) and the byte-pin is verified against the agility corpus at
S2.

## Hash: stdlib `hashlib` — SHA-256 + SHA-384/512 (native, no dependency)

`hashlib.sha256` for the `content_hash` floor; `hashlib.sha384` / `sha512` for the
agility hashing family. All **stdlib**, OpenSSL-backed in CPython, **no dependency**.
Note Ed448's *internal* hash is SHAKE256 (OpenSSL handles it inside PureEdDSA — not a
separately-invoked digest); the §HASH-FORMAT SHA-384 agility path is the content-hash
family, independent of the signature curve.

## Base58 + varint: hand-rolled

Both are small and absent from the stdlib. Base58 (Bitcoin alphabet, encode + decode,
`entity_core/_base58.py`) for `peer_id`; multicodec-style LEB128 varints
(`entity_core/_varint.py`) for the §1.5 / §7.3 `key_type` / `hash_type` / format-code
framing (own the non-minimal-varint rejection). Hand-rolling keeps the **single-
runtime-dependency** story intact — the core peer ships exactly one runtime dep
(`cryptography`); hashing is stdlib, and CBOR/base58/varint are hand-rolled.

## Error model: exceptions (the Python idiom)

`raise` / `except` with an `Exception`-rooted hierarchy under `EntityCoreError` — the
canonical Python fallible surface. The tree mirrors the C#/TS/Ruby exception
hierarchies in *shape* (Codec / Protocol / Transport families) but reads as Python
(PascalCase `...Error` class names, `raise CodecError("…")`). Rooting at `Exception`
(not `BaseException`) keeps faults catchable by a normal `except Exception` — the
Python convention (rooting at `BaseException` would escape normal handling and is
reserved for `KeyboardInterrupt`/`SystemExit`-class signals, the analogue of Ruby's
`StandardError`-not-`Exception` choice). `WireProtocolError` avoids the TS
`ProtocolErrorError` stutter (A-003 precedent). Decode-path violations raise
`CodecError` subclasses (`NonCanonicalEcfError`, `TruncatedError`); the peer
except-maps protocol faults to the §5.2a / §6.12 status codes at the dispatch
boundary. This is distinct from Elixir's tagged tuples, OCaml's `result`, Zig's
error unions, and Go's `(T, error)` — the dynamic-language exception seam (shared
with Ruby).

## Concurrency: thread-per-connection, with an honest GIL accounting

This mirrors the Ruby GVL accounting (CPython's GIL is the direct analogue), and the
profile is deliberately candid:

- CPython has **native OS threads** (`threading.Thread`) with a **preemptive**
  scheduler, but the **GIL** means only **one thread executes Python bytecode at a
  time** — Python code does not run in parallel across cores.
- **Crucially, the GIL is RELEASED during blocking IO** — socket `recv`/`send`/
  `accept` — **and inside the `cryptography` / `hashlib` C extensions**. So a
  **thread-per-connection** peer is *genuinely* concurrent for an **IO-bound**
  workload (§4.8/§4.9): while one thread blocks in `recv`, others run. The
  entity-core peer is IO-bound (frame shuffling + occasional crypto), **not**
  CPU-bound, so the GIL is **adequate** for the §7b concurrency gate. We do not need
  asyncio, worker pools, or the free-threaded build to clear it.
- **Data-race safety (§4.8) still needs explicit locking.** The GIL prevents two
  threads running bytecode simultaneously, but it does **not** make a compound
  *read-then-write* atomic (a thread can be preempted between the read and the write
  — and on the free-threaded build there is no GIL at all). So the shared store is
  **`threading.Lock`/`RLock`-guarded**, and the §3.9 CAS put is a single critical
  section. (Misconception to avoid: "the GIL makes Python thread-safe" is false for
  compound operations — the same trap the Ruby rationale calls out for the GVL.)
- **§7b TCP_NODELAY** is set on every socket (`socket.setsockopt(IPPROTO_TCP,
  TCP_NODELAY, 1)`). The Zig lesson (Nagle/delayed-ACK is the small-frame req/resp
  throughput killer; 62s→1.9s; 343 ms/cycle churn is the Nagle signature) applies
  regardless of language — recorded so S3 wires it from the start.
- **asyncio** is the popular Python alternative and a clean fit for the §6.11
  reentrant demux, but it would (a) async-color the public codec/crypto APIs that are
  pure-CPU/sync, and (b) diverge the peer-loop idiom from the threaded cohort shape
  (Ruby/OCaml reader-thread + condvar). Threading keeps the codec **sync** and
  matches the cohort's reentrancy pattern. Noted as the alternative idiom; **not used
  at core**.
- The **CPython 3.13+ free-threaded (no-GIL) build** is the true-parallel escape
  hatch — but it is still experimental and would *require* the explicit locking
  above (no GIL to lean on), which the profile already mandates. Noted; **not used at
  core**.

This maps the N6/N7/§6.11 reentrancy invariants onto: one reader **thread** per
connection (the single writer for that socket), a `pending {request_id => waiter}`
map plus a `threading.Condition` for the §6.11 reentrant EXECUTE_RESPONSE demux (the
threaded-peer shape, same as OCaml/Ruby reader-thread + condvar). The §6.13(b)
outbound await runs on a spawned thread so it never stalls the reader.

## Native arbitrary-precision integers: no head-form trap

Like the BEAM (Elixir #4) and Ruby (#12), **Python `int` is arbitrary-precision**,
so the CBOR uint64/int64 head-form carrier that bit OCaml (int63→Int64), C#
(`ulong`), and TS (`bigint`) is **just an `int`** here — no wrapping, no widening, no
bigint bridge. This is the **third** arbitrary-precision peer to carry the full
integer range with no special-casing. The one discipline to keep (recorded
`explicit_head_form = true`): Python's `int` is *unbounded*, but the CBOR **head
form** is *fixed-width per the major-type head* — so the encoder must select the
**shortest head** (0/1/2/4/8 extra bytes) per Rule 1 on encode, and **reject
non-shortest** on decode (Rule 1 enforced on receive). The arbitrary-precision int
removes the *carrier* trap, not the *head-form-width* obligation; the `[2^63, 2^64-1]`
band (corpus `int.10/15/16/17`) and the `nint = -1-n` negative form both map cleanly
onto `int` + explicit width selection.

## Byte handling: bytes, not str

Wire bytes are **`bytes` / `bytearray` / `memoryview`** — **never** `str` in the
codec core. This is the standard Python text/bytes distinction (`str` is text, UTF-8
only at the entity-string boundary per the native type system); getting it right is
the Python analogue of the Ruby ASCII-8BIT discipline, the TS `Uint8Array`-not-
`Buffer` discipline, and the C# byte-span discipline. `@dataclass(frozen=True,
slots=True)` for value-shaped types (envelope, cap-token — immutability + slots for
memory and attribute-typo safety); `NamedTuple` where a tuple shape is natural.

## Duck typing + §1.1 `data` is an arbitrary ECF value (A-JAVA-010)

The §1.1 entity `data` field is an **arbitrary ECF value, NOT necessarily a dict**
(A-JAVA-010). Python's duck typing makes this natural — `data` is "whatever ECF value
decodes," modeled as a general ECF value, not assumed to be a `dict`. Recorded now so
the S2 codec model is right from the start (the codec carries `data` as pre-encoded
bytes / a general decoded value, never forcing a dict).

## Build / test / packaging: pyproject + hatchling + pytest + PyPI

Modern **src-layout** with a single **`pyproject.toml`** manifest (PEP 517/518),
**no `setup.py`**. Build backend = **hatchling** (the modern, near-stdlib-default
PEP-517 backend; `python -m build` is the frontend). Tests use **pytest** — the
de-facto Python test ecosystem standard; stdlib `unittest` exists but pytest is so
dominant it is the idiomatic choice, and it is a **dev-only** dependency (not in the
wheel's runtime deps), so the runtime-dep story stays minimal: the core peer ships
**one** runtime dep (`cryptography`); CBOR/base58/varint hand-rolled, hashlib/
threading/socket/struct stdlib. The conformance harness is a pytest suite asserting
byte-identity against the normative fixtures; a thin `python -m entity_core.host`
entry point is the standalone oracle driver for validate-peer / wire-conformance at
S4. **ruff** (lint/format) + **mypy** (PEP-484 type-check) are dev-only tools,
deferred to S5 — not pulled silently at core. src-layout is chosen deliberately to
avoid the import-shadowing footgun (tests import the *installed* package, not the
repo cwd).

## Packaging version: PEP 440 `0.1.0` (final, not a pre-release tag)

The cohort parks first publishes at "0.1.0-pre"-style markers (OCaml/Elixir
`0.1.0-pre`). But **PEP 440's pre-release spelling is `0.1.0rc1` / `0.1.0a1` /
`0.1.0b1` / `.devN`** — and a pre-release has a **resolution footgun**: `pip install
entity-core-protocol-python` **excludes pre-releases by default**, so a `0.1.0rc1`
upload would **not** install without `--pre`. That directly undercuts the **adoption**
goal (the headline value of this peer). Meanwhile a bare **`0.1.0`** already signals
"early, unstable, pre-1.0" under SemVer (a `0.x` major makes no API-stability
promise) **without** the installer surprise. So the PEP-440-correct spelling of
"0.x early peer, installable by default, honestly pre-stable" is the **final
`0.1.0`**, carried by the `0`-major rather than a pre-release suffix. (If a genuine
release-candidate gate is ever wanted before `0.1.0`, `0.1.0rc1` is the spelling —
but the default and the recommendation is the final `0.1.0`.)

## Naming the package: PyPI dist name vs import package

Keystone peer id = `entity-core-protocol-python`. **PyPI normalizes dist names**
(PEP 503: case-folded, `-`/`_`/`.` runs collapsed to `-`), so the dist name is kept
as **`entity-core-protocol-python`** (matching the keystone id directly — unlike
Ruby/Elixir, which dropped the redundant `-ruby`/`_elixir` because a gem/hex package
is language-implicit; here the *import package* `entity_core` already carries that
implicitness, so the full keystone id on the dist name is unambiguous and useful).
The **import package** is **`entity_core`** (`import entity_core`, snake_case per
PEP 8). Availability/squatting checked at S5 before first publish.

## License: Apache-2.0 (S9 default)

Python itself is PSF-licensed and the package ecosystem is MIT/BSD/Apache-mixed with
no strong mandate, so the repo's Apache-2.0 default (explicit patent grant) stands.

## Bootstrap conventions baked in (planned S3 surface)

Per the S1 brief, the latest cohort conventions are recorded in the profile
`[bootstrap]` block so later phases inherit them (NOT built in S1 — profile-only):

- **`--name NAME` persistent identity** — loads the peer's Ed25519 identity from
  `~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed),
  matching the Go entity-peer / peer-manager convention and the cohort-wide `--name`
  standardization. This is what lets the multisig accept-path
  (`valid_2of3_peer_signed_accepted`) *run* against the oracle rather than env-skip.
- **Genuine §3.6 K-of-N multisig** — real k-of-n at the root: granter union
  (`system/hash` | `{signers, threshold}` map, root-only) → `verify_multisig_root` =
  §3.6 M3 structure check (root-only, n≥2, 2≤threshold≤n, **distinct** signers)
  **before** signature counting (precedence 25), then §5.5 M6 (local ∈ signers) + M4
  (**distinct**-signer valid-sig count ≥ threshold — the K-of-N replay defense).
  Multi-sig is root-only (off-root denies); the single-sig path is a byte-identical
  strict superset. An **accept-path unit test** is required (the rejection-only
  oracle category can't cover genuine k-of-n; the per-peer unit test is the genuine
  cross-impl exercise).
- **§6.9a seed-policy bootstrap** — self owner-cap (detached-signature shape) +
  `default` discovery floor at L0, per `protocol-generator/shared/seed-policy/`;
  `--owner-identity` / `--seed-policy` CLI + `with_owner_identity` / `with_seed_policy`
  builder. `--debug-open-grants` = the degenerate `default → *` policy (removed
  v7.75).

## Container: AUTHORED `containers/python-toolchain/Containerfile` (fedora:43 base)

No existing `containers/python*/` image, so I **authored** a new Containerfile
(`containers/python-toolchain/Containerfile`) per the S1 brief — **AUTHORED, not
built** (S1 boundary: no podman, no build, no toolchain run). It is **`fedora:43`**
base (per S1, like every cohort toolchain except Ruby's official-image exception),
adds the system Python (`python3` = CPython 3.13.x from the fedora:43 distro channel)
+ minimal build deps + the one pinned runtime dep (`cryptography==48.0.0` installed
in a single network-on image-build step into a venv), and includes a **build-time
EdDSA assertion** that round-trips sign/verify on **both Ed25519 AND Ed448** plus a
SHA-384 presence check — so the image fails loudly if the bundled OpenSSL lacks Ed448
(closes the A-PY-002 risk at container-build time). Pin notes:

- **`cryptography==48.0.0`** — **44 days old** at authoring → clears the **S11 ≥30-day
  cool-down**. It is the **newest** version that clears the floor:
  **48.0.1** and **49.0.0** are both **< 30 days old** →
  too new to pin per S11. 48.0.0 carries the **CVE-2026-39892** fix (buffer overflow,
  fixed in 46.0.7) and the **CVE-2026-34073** fix (name-constraints, fixed in 46.0.6)
  forward — both predate 48.0.0. Its wheels bundle **OpenSSL 3.5.x** → Ed25519 +
  Ed448 + SHA-2 all native; minimum Python 3.9 (we run 3.13). The wheel hash pin
  (committed lockfile) is an S2 lock-step.
- **CPython `3.13.14`** — the fedora:43 distro `python3`. This
  patch is **< 30 days old** at authoring (A-PY-004), but the **3.13.x series** is
  long-stable (3.13.0 = 2024-10) and the toolchain arrives via the **fedora:43 distro
  channel — a reviewed channel** → per the supply-chain memo the S11 age floor
  *relaxes* to "pin exactly for reproducibility" (exactly as for Go's
  `golang-1.25.10`). If fedora:43 ships an older 3.13.x patch, that patch is
  acceptable (any 3.13.x stable patch). Flagged A-PY-004.
