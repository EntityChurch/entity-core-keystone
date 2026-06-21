# entity-core-protocol-common-lisp — Profile Rationale

Audit trail for every major S1 profile choice. Common Lisp is **peer #5**, and the
**most distant idiom built so far**: each choice below was derived from the V7 spec
+ Common Lisp / SBCL ecosystem research, **not** ported from the
C#/TS/OCaml/Elixir profiles. Where a value matches a prior peer it is by
independent arrival; the idiom seams (condition system, CLOS dispatch, lisp-case,
image-based build) deliberately differ.

## Why Common Lisp is a worthwhile probe

The four prior peers spanned static-OO (C#), gradual-structural (TS),
functional-static (OCaml), and actor-dynamic-functional (Elixir). Common Lisp
adds axes none of them exercise:

- **Code-as-data / macros** — the reader and `defmacro`/compiler-macros mean the
  type-registry and dispatch tables can be *generated at read/compile time* from
  the spec shapes, a derivation path no prior peer had.
- **CLOS multiple dispatch + the MOP** — the dispatcher (§6) is the natural home
  for generic functions specialised on operation + resource class, vs the
  single-dispatch / pattern-match dispatchers of the prior peers. This re-probes
  whether the spec's dispatch contract assumes single dispatch anywhere.
- **The condition system** — conditions + handlers + restarts is a strict
  superset of exceptions; it tests whether any spec error-path actually wants
  *recoverable* signalling (restarts) vs the flat throw/catch the prior peers used.
- **Dynamic typing + image-based interactive development** — there is no compile
  gate forcing total coverage; correctness rests on the conformance corpus, which
  stresses the corpus's completeness in a way the statically-checked peers did not.

## Codec strategy: native (fully native, including the agility higher bar)

`research/LANDSCAPE.md` had Common Lisp in the LOW-MED backlog with no committed
strategy. Research lands it as **native** — and, like Elixir (peer #4), as a
**fully-native** story that reaches the crypto-agility higher bar with **no FFI**:

1. **Crypto is native and pure-Lisp via ironclad.** ironclad (sharplispers fork,
   the maintained line) implements Ed25519 **and Ed448**, plus SHA-256 and
   SHA-384 — all in pure Common Lisp, with no libsodium/OpenSSL dependency. So the
   agility higher bar (Ed448 + SHA-384) is reachable from the default build with
   zero FFI. This is the **headline contrast with OCaml** (A-OC-002, which had to
   source Ed448 over the C-ABI because mirage-crypto-ec lacks it and OCaml has no
   BouncyCastle-equivalent). It **matches Elixir's** native-Ed448 position, but by
   a different mechanism: Elixir gets Ed448 from the OpenSSL NIF; CL gets it from a
   pure-Lisp implementation. The trade is auditability surface — a pure-Lisp Ed448
   is more code to trust than an OpenSSL primitive, so RFC-8032 KAT byte-equality
   is the S2 acceptance gate before the 114-byte signature / peer-id agility
   vectors are trusted (see A-CL-005).

2. **No CL CBOR library gives ECF canonicality** — the A-005 pattern all four
   prior native peers hit. The CL CBOR options (`cl-cbor`, `cbor`) are sparse,
   largely unmaintained, and target *general* CBOR, not ECF's length-then-lex map
   ordering, shortest-float ladder (incl. f16), recursive major-type-6 tag
   rejection, or full uint64/nint range. A faithful ECF codec must own the
   canonical layer regardless, so a library buys almost nothing. Hand-rolling
   `src/cbor.lisp` is both the faithful and the simpler path.

Net: a core peer whose **only third-party runtime dependency is ironclad**; CBOR,
base58, and varint are hand-rolled in-repo. `ffi` remains the documented fallback
but is not expected for any tier.

## CBOR: hand-rolled (no CL library)

Surveyed `cl-cbor` and `cbor` — neither offers ECF's deterministic guarantees, and
both are thin/unmaintained. ECF needs an explicit float node (shortest-float
f16/f32/f64 minimisation), length-then-lex map-key ordering on *encoded* key bytes,
recursive major-type-6 tag rejection on decode, and full uint64/nint range. The
encoder builds an `(unsigned-byte 8)` octet vector (the CL idiom for binary data);
the decoder is index-walking over the octet vector with `(declaim (optimize ...))`
on the hot path and `(safety 3)` on the reject paths. **CL native bignums** carry
the full uint64 range with **no special-casing** — the advantage Elixir noted, and
the inverse of the integer-width traps that bit OCaml (int63), C# (ulong), and TS
(BigInt). Spike at S2 against the `map_keys` + `float` vectors before committing the
full build (the kickoff's load-bearing codec risk).

## Crypto: ironclad 0.61 (Ed25519, Ed448, SHA-256, SHA-384)

ironclad is the de-facto Common Lisp crypto toolkit. The **sharplispers** fork is
the maintained line (the original froydnj repo is the historical one). Version
**0.61** (~22 months old — far over the S11 30-day floor)
provides everything the protocol needs: Ed25519 (added 0.35, 2017) and Ed448 (0.42,
2018, with optimizations for both), SHA-256 and SHA-384 (the SHA-2 family, 0.27,
2009). Pure Common Lisp — no libsodium/OpenSSL system dependency, which keeps the
peer self-contained inside SBCL (the OCaml "no system deps" virtue, achieved here
without an FFI). ironclad's own runtime deps are `nibbles` + `alexandria` (both
small, mature, BSD/MIT), resolved by the pinned Quicklisp dist at build time.

## Ed448: NATIVE via ironclad (no FFI — the OCaml gap does not recur)

The crypto-agility higher bar (v7.67: key_type Ed448 `0x02` validated; SHA-384
content_hash_format `0x01` validated) is reachable from the default build, because
ironclad implements Ed448 in pure Lisp. No opt-in sub-library (OCaml's
`entitycore_agility`), no C-ABI consumption, no hybrid. The §9.1 conformance floor
(Ed25519 + SHA-256) is unaffected either way. The one caveat: a pure-Lisp Ed448 is
a larger trust surface than an OpenSSL primitive, so the S2 plan is to gate it on
**RFC-8032 §7.4 known-answer-test byte-equality** (the same ground-truth check the
C FFI used for its vendored curve448) before trusting it for the agility corpus
(`KEY-TYPE-ED448-1`, 114-byte signature, `MATRIX-M2/M3/M6` peer identities). Logged
as A-CL-005 (a verification note, not a gap).

## Hash: ironclad digests (SHA-256 floor + SHA-384 agility)

`ironclad:digest-sequence :sha256` for the content_hash floor and `:sha384` for the
agility hashing, both pure-Lisp, same library as the signatures — no extra
dependency.

## Base58 + varint: hand-rolled

Both are small and dependency-free. Base58 (Bitcoin alphabet, encode+decode,
`src/base58.lisp`) for peer-id; LEB128 varints (`src/varint.lisp`) for the N1
format-code / key-type / hash-type framing. Hand-rolling dodges two more deps and
matches the dependency-minimization stance (the OCaml/Elixir precedent).

## Error model: conditions (deliberate divergence from every prior peer)

Common Lisp's **condition system** (conditions + handlers + restarts) is a strict
superset of exceptions — the richest error model of the five peers, and the correct
idiom seam to differ from C#/TS `exceptions`, OCaml `result`, and Elixir
`tagged_tuple`. Design: a `define-condition` hierarchy rooted at
`entity-core-error` (a subtype of `cl:error` with a `:report`), leaf conditions
(`non-canonical-ecf`, `truncated-input`, `tag-rejected`, `bad-seed`,
`unsupported-content-hash-format`, `unsupported-key-type`). Public codec entry
points **signal** these (idiomatic CL — errors are signalled, not value-returned).
Restarts are offered where the spec genuinely permits recovery; decode-path
violations (N2/N3 — non-canonical, truncated, tag-6) signal with **no restart**
(hard reject). A `*-safe`/`ignore-errors`-wrapped convenience surface gives
value-return callers the CL analogue of the bang-vs-tuple split. The probe: does
any V7 error path actually want a *restart* (recoverable), or are they all
terminal? (Expectation: all terminal at the codec floor; restarts may earn their
keep at the peer/dispatch layer in S3.)

## Async: native SBCL threads (deliberate S6 decision; validated at S3)

The CL analogue of C#-`Task` / TS-`Promise` / OCaml-`eio` / Elixir-processes.
Common Lisp's ANSI standard is single-threaded; the de-facto portability layer is
`bordeaux-threads` over the implementation's native threads (SBCL's `sb-thread`).
For a `--profile core` peer the N6/N7 reentrancy invariants (inbound concurrent
with outbound dispatch; reentrant request_id demux; §6.11 reentry) are satisfied by
**one native thread per connection** (`sb-thread`) plus a `request_id ->
condition-variable` correlation table guarded by a mutex — exactly the shape OCaml
arrived at when it revised its S1 eio decision to stdlib threads at S3
(A-OC-003-revised). SBCL native threads need **no third-party dependency**;
`bordeaux-threads` is only required if cross-implementation portability (ECL, CCL,
ABCL) is later desired — deferred. Not exercised by the codec (pure/synchronous) —
validated at S3. Logged A-CL-003.

## Dispatch: CLOS generic functions (the distant-idiom probe)

The §6 dispatcher is authored as CLOS generic functions specialised on operation +
resource class (multiple dispatch), vs the single-dispatch switch / pattern-match
dispatchers of the prior peers. This is the heart of why CL is worth building: it
re-probes whether the spec's dispatch contract silently assumes single dispatch
anywhere, and whether multiple-dispatch + method combination expresses the
capability-check → handler-invoke → response flow more directly. S3 work; flagged
here so S3 does not re-litigate it.

## Naming: Common-Lisp-native lisp-case / earmuffs

`lisp-case` (hyphenated) for functions, variables, classes, and packages;
`+plus-earmuffs+` for constants; `*star-earmuffs*` for dynamic/special variables;
`-p`/`p` suffix for predicates; `:lisp-case` keywords for keyword arguments. CL is
case-**insensitive** by default (the reader upcases), so source is written lower and
read upper — with the load-bearing caveat that **external string/byte data must be
kept case-EXACT** and never round-tripped through symbols (a CL-specific footgun the
codec must respect; noted in `[idiom]`). Differs from every prior peer's casing.

## Build / test / packaging: ASDF + hand-rolled harness + Quicklisp

`asdf` (with `defsystem`) is the universal CL build/system-definition tool and
**ships inside SBCL** — no separate pin. Build/load via `sbcl --non-interactive
--eval '(asdf:load-system :entity-core)'`. Tests are a **hand-rolled harness**
(`test/run-conformance.lisp` + `test/selftest.lisp`) loaded via `sbcl --load` — no
test-framework dependency, honoring the minimization stance (the OCaml precedent
declining alcotest for the same reason). The CL standards FiveAM/rove can be layered
for a richer S5 report without touching the codec. Distribution is the de-facto
Quicklisp (or Ultralisp) community dist — both index a git repo carrying the `.asd`;
submission is the optional S5 registry step.

## Image-based development note (an S1 caveat for later phases)

SBCL is **image-based**: development is interactive against a running Lisp image,
and `save-lisp-and-die` can dump a standalone executable. This is a strength for the
dev loop but a **reproducibility caveat** the Containerfile must respect — the
build/test must run from a **clean image** each time (`sbcl --non-interactive` from
the pinned base, never a long-lived saved image carrying accumulated state), or two
runs can diverge. The Containerfile pre-builds ironclad into the image at build
time (network available) so the dev loop runs fully offline (`--network=none`); the
per-run process starts from that clean, deterministic image. Flagged here so S2–S5
do not introduce image-state nondeterminism.

## License: Apache-2.0 (S9 default)

The CL ecosystem is license-mixed (MIT/BSD/LLGPL common; ironclad itself is BSD-3)
with no strong mandate, so the repo's Apache-2.0 default (explicit patent grant)
stands.

## Toolchain pins (S11)

- **SBCL 2.6.4** (~45 days old — clears the
  30-day floor). SBCL is a reviewed source channel (sbcl.org / SourceForge source
  tarball), so per the supply-chain scope clarification the 30-day age relaxes for
  the *toolchain* itself, but the exact version pin stands for reproducibility. The
  newer 2.6.5 is only ~15 days old — under the floor — so 2.6.4 is the
  correct pick. **Source-built in-container** (the BEAM/OTP precedent) for
  reproducibility, against a pinned source tarball + verified checksum.
- **ironclad 0.61** (~22 months) — far over the floor; the only
  third-party runtime dep. Pulled at container *build* time via a pinned Quicklisp
  dist, then run fully offline. ironclad is a registry-channel package, so the
  ≥30-day floor applies with full force — comfortably met.
- **Quicklisp dist 2026-01** (~5 months) — used **only** at build time to resolve
  ironclad 0.61 + its deps (`nibbles`, `alexandria`); pinned for reproducibility,
  not a runtime dependency. See A-CL-004 for the dist-pinning mechanics.

## Spec version: read v7.72, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.72` (latest snapshot). The codec
uses the `test-vectors/v0.8.0` corpus because `ENTITY-CBOR-ENCODING.md` and
`ENTITY-NATIVE-TYPE-SYSTEM.md` are **byte-identical** v7.71→v7.72 (SHA-256 verified
upstream) — no wire-format change — so the v0.8.0 corpus is valid at v7.72. The
v7.73 nonce-echo (§4.6) and v7.74 (register/outbound/emit/owner-cap/§7a) folds are
peer-layer concerns (S3+), not codec, and are resynced at S3. The spec-data
snapshot stopping at v7.72 while HEAD is v7.74 is logged A-CL-001 (escalate to
arch — non-blocking for S1/S2).

## peer_id construction: §1.5 canonical-form table, NOT §7.4 (A-CL-002)

The profile **mandates** deriving the Ed25519 peer_id from the **§1.5 v7.65
canonical-form table** — `hash_type = 0x00` identity-multihash, digest = the **raw
public key bytes** (no hash) — and **ignoring the stale §7.4 pseudocode** and the
§1.5-line-436 skeleton, both of which still show the pre-v7.65 `SHA256(public_key)`
form (`hash_type = 0x01`). Confirmed in `spec-data/v7.72`: §1.5 line 448 of
`ENTITY-CORE-PROTOCOL-V7.md` declares Ed25519 → `0x00` identity-multihash, "the
digest IS the public_key (v7.64)"; §7.4 (line ~3599) still shows `digest =
SHA256(public_key)`. Baking the correct form into the profile **proactively** avoids
the handshake-failure debug cycle that A-ZIG-001 (Zig) and A-OC-007 (OCaml) both
burned — and which S2's conformance corpus would NOT catch, because it uses opaque
digests, so a wrong construction passes S2 and only blows up at the S4 handshake.
This is the third spec-first peer to corroborate the §7.4/§1.5 contradiction; logged
A-CL-002.
