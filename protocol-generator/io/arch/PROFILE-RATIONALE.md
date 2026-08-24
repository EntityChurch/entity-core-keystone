# entity-core-protocol-io — Profile Rationale (S1)

Why each major profile choice was made. Companion to `../profile.toml`; the live
S1 evidence is `research/evaluations/oz-io-viability.md` §S1 (2026-07-15, GO).

## Why Io at all — the paradigm axis

Io is the cohort's one unprobed **object model**: pure prototype-based OO (no
classes; `clone` + differential inheritance; every operation a message send). The
§6.6 handler resolution — a longest-prefix delegation walk over a tree — is
structurally the same shape as Io's own message dispatch (a delegation walk up the
proto chain). The probe question: does authoring the protocol in a language whose
*native* dispatch is the protocol's dispatch shape surface a mismatch, or
corroborate that §6.6 is substrate-neutral? Wire-axis discovery is NOT expected
(the C peer + C-ABI saturate it); the finding channel is the object model plus two
secondary axes (double-typed numbers on a dynamic language; coroutine+libevent
single-thread concurrency).

## The frozen-native-line pin

Upstream IoLanguage/io master is now a WASM/WASI port; the native line
(DynLib/AddonLoader/addons — everything this peer stands on) is permanently frozen
at tag `2026.04.20-native-final`. Decision (settled in the S1 session, recorded in
the 2026-07-15 handoff): build on the **native line**. The paradigm payoff is
identical in both lines, and the WASM port removes the addon system (no Socket, no
C-addon FFI), which would compound two experimental substrates while losing both
proven seams. The pins are permanent by construction — the native line will never
move again. `deps/parson` is a git submodule the GitHub tag tarball ships empty;
the Containerfile fetches the exact submodule commit (`4f3eaa68…`) separately,
SHA-pinned (found at first container build — the S1 probe used a recursive clone).

## Codec strategy: ffi-addon-hybrid

- **No Io CBOR library exists** (the ecosystem is tiny and archived), and even if
  one did, no platform CBOR lib gives ECF canonicality (7/7 cohort precedent).
- **IoNumber is a C double.** Exact integers stop at 2^53; the uint64 head-form
  tower `[2^63, 2^64−1]` is unrepresentable. A pure-Io codec would need a bignum
  carrier *and* hand-rolled IEEE bit surgery (f16 ladder) on a substrate whose
  bitwise operators are 32-bit-truncating — high risk, zero discovery value (the
  wire axis is saturated).
- **The C addon IS the substrate idiom.** Io's extension story is C addons over
  the iovm API; the S1 hand-build of the Socket addon proved the exact compile +
  init-convention shape. The EntityCodec addon is the same artifact class, and is
  the in-process FFI seam to `libentitycore_codec` for crypto/hash/peer-id
  (Ed25519 + SHA-2 never hand-rolled, per the ecosystem standard).

So: byte-level canonical CBOR + crypto in the **EntityCodec addon (C)**; the
protocol — framing, envelopes, §5 capability algebra, §6.5/§6.6 dispatch, store,
handlers — **in Io**. The seam is drawn at what the substrate genuinely can't do
(bytes/crypto), exactly the durable-lesson line.

## The value model (EcMap/EcBytes/EcBig/EcFloat/EcNull)

CBOR's type distinctions (bytes-vs-text, int-vs-float, absent-vs-null) do not
survive Io's value model uninstructed:

- A Sequence doesn't reliably distinguish text from raw bytes → wire byte strings
  are always `EcBytes` wrappers (the Tcl EIAS lesson, one notch milder).
- A Number is a double → `Number` always means *integer* (guarded |x| ≤ 2^53);
  floats ride `EcFloat`; ints beyond the double range ride `EcBig` (sign +
  8-byte magnitude). Decode never lossy-folds a big int into a double.
- Io Map cannot key by raw bytes (and iterates unordered) → CBOR maps are
  `EcMap`, an insertion-ordered entry list; canonical sort happens in the addon
  at encode time. Envelope `included` (byte-string keys) needs exactly this.
- Io's `nil` is the *absent* sentinel; CBOR null decodes to an `EcNull`
  singleton, preserving the §1.3 absent ≠ null distinction.

## Concurrency: coroutines + libevent

Io's coroutines are cooperative on one OS thread, scheduled by the Socket addon's
libevent loop — a *real* scheduler (socket waits park the coroutine; the loop
keeps running), unlike the Pd/Scratch substrates where cooperative yielding had to
be retrofitted. Design commitments made at S1, from the cohort lessons:

- coroutine-per-request dispatch (reader never blocks on a handler) → §4.8;
- per-connection `request_id` → waiter map, reader resumes by id → §6.11;
- **per-connection FIFO write queue** — a frame write can yield mid-frame
  (`bytesPerWrite` chunking), so unserialized concurrent writers would interleave
  frame bytes on the wire (A-IO-002). This is the coroutine twin of Pd's
  single-owner-seam-global rule;
- store safety is structural (no yield inside store mutation on one thread);
- the S1 **half-close quirk** (peer-FIN tears down before pending writes flush)
  is a design rule: never answer after FIN — request/response flows unaffected;
- watch t2_2-class churn early (the single-thread cohort's known cliff); the
  libevent scheduler should make it a non-event, but it is measured, not assumed.

## Error model / naming / build / testing

Io has genuine exceptions — the codec boundary raises (hard reject on
canonicality violations); protocol outcomes are ordinary objects (status/result),
so a 4xx is a value, not an exception. Naming follows the Io stdlib
(UpperCamelCase protos, lowerCamelCase slots). Build is `make` over gcc (addon) +
cmake (C-ABI codec), container-bound; eerie is unusable from the frozen tree so
the addon installs by the hand-layout the S1 probe proved. Tests are plain `io`
harness scripts (the corpus + oracle are the real gates), stdlib UnitTest for
offline KATs.
