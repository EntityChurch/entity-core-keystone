# entity-core-protocol-php — Spec Ambiguity Log

Every guess the agent makes goes here (S3 discipline). Items escalate to
architecture as proposal candidates via `research/stewardship/`. **No silent
guesses.** Prefix `A-PHP-NNN` (PHP reach peer, slate row 2).

Note: prior peers already surfaced and (mostly) resolved a large set of
*spec-level* ambiguities (peer-id §7.4/§1.5, 401/403 §5.2a, format_code, hex-case
§3.4/§3.5, §4.10 403→400 chain-depth, A-JAVA-010 `data`-shape, …). Those are spec
facts now folded into v7.75 (the snapshot this peer reads), not re-litigated per
language. PHP is a **corroboration-only reach peer** (the discovery well is dry;
the dynamic/scripting axis was exercised by Ruby #12), so this log records
**PHP-specific** guesses — the slate decisions made concrete + idiomatic — plus
any **new** spec gap this peer surfaces (none expected). Cross-references to shared
findings use their original ids.

---

## A-PHP-001: codec strategy = native; CBOR hand-rolled (no PHP library does ECF)

**V7 section:** ENTITY-CBOR-ENCODING.md (ECF canonical form), §4.7 (construct-vs-decode)
**Profile field:** `[codec].strategy`, `[codec].cbor_library`
**Your guess:** `native` strategy with a **hand-rolled** canonical CBOR
encoder/decoder (`src/Cbor.php`). The de-facto PHP CBOR library
`spomky-labs/cbor-php` is a general **RFC-8949** impl: no ECF length-FIRST map
ordering, no shortest-float minimization, accepts tags — not ECF-exact (the
slate's "cbor-php not ECF-exact" note). Smaller libs (`2tvenom/CBOREncode`,
`lukasoppermann/php-cbor`) have the same gaps. Hand-roll the canonical layer
(length-then-lex on encoded key bytes, shortest-float incl. f16, recursive
major-type-6 rejection, full uint64/nint range, verbatim raw-byte `data` N4).
**Rationale:** The A-005 pattern, holding for an Nth language: a faithful ECF
codec owns the canonical layer regardless of library. Hand-rolling is simpler than
bending a general library that fights the length-first rule, and keeps the
zero-runtime-Composer-dependency story. The decoder is a byte-cursor over a
binary PHP `string` (binary-safe; `strlen`/`substr`/`ord`/`unpack` primitives).
**Escalation:** **operator** — design decision (ratifies the slate), no spec
impact. Spike the `map_keys` + `float` + uint64-band vectors at S2 before the full
build (the load-bearing risk).

---

## A-PHP-002: Ed448 = GAP → DEFER for v0.1 (ext-sodium has no Ed448); hybrid-FFI when agility lands

**V7 section:** §1.5 / §7.3 multikey (key_type 0x02 = Ed448); crypto-agility higher bar (v7.67)
**Profile field:** `[codec].ed448_library`
**Your guess:** **DEFER** Ed448 for v0.1. ext-sodium (libsodium, the floor crypto)
has **no Ed448** — libsodium ships Ed25519 + the SHA-2 family + ML-KEM/SHA-3 but
not Ed448/Ed448-Goldilocks (the same gap C / C++ / Zig hit). PHP's stdlib has no
other EdDSA source (ext-openssl exposes no Ed448 binding). The v0.1 core is
**Ed25519 + SHA-256 only** (the §9.1 floor), fully covered by ext-sodium, so the
gap does **not** touch the conformance floor. When/if agility enters scope, the
documented PHP route is **hybrid FFI** (the slate's "FFI" half): **ext-ffi**
(bundled in PHP 7.4+) binds the sibling `libentitycore_codec` C-ABI v1.1 Ed448
family (`ec_ed448_seed_to_pubkey` / `ec_ed448_sign` / `ec_ed448_verify`) — the
OCaml hybrid-FFI shape (A-OC-002), scoped to an **opt-in agility surface** so the
shipped floor peer stays FFI-free. The agility **hashing** half (SHA-384) is
**native** via stdlib `hash('sha384', …)` — only the Ed448 **signature** primitive
is the FFI piece.
**Rationale:** The slate fixes "gap → FFI/defer"; defer is the correct v0.1 call
(matches OCaml/C#/C++/Zig/Swift's deferred-higher-bar posture). PHP is in the
*Ed448-gap* camp, NOT Ruby's native-full-agility camp (Ruby gets Ed448 from stdlib
openssl) — a deliberate divergence from the closest analog.
**Escalation:** **operator** — design decision, no spec impact; the v0.1 floor is
complete without Ed448.

---

## A-PHP-003: uint64 head-form carrier = GMP (PHP int is 64-bit SIGNED, overflows to float past 2^63)

**V7 section:** ENTITY-CBOR-ENCODING.md / ENTITY-NATIVE-TYPE-SYSTEM.md (integer head-form, the [2^63, 2^64-1] uint64 band; §1.5/§7.3 framing varints)
**Profile field:** `[idiom].uint64_carrier`, `[idiom].no_float_for_ints`, `[idiom].pack_unpack_be`
**Your guess:** Carry CBOR integer head-form values as **GMP objects** (ext-gmp,
bundled in the toolchain image) **uniformly across the whole integer range** —
ONE path, no int/GMP branching. PHP `int` is 64-bit SIGNED (`PHP_INT_MAX =
2^63-1`) with NO native arbitrary-precision integer; a literal/operation beyond
`PHP_INT_MAX` silently becomes a **float** (lossy past 2^53). So the
[2^63, 2^64-1] band CANNOT be carried in a native int and must NEVER round-trip
through a float. Wire: `pack('J')`/`unpack('J')` (64-bit BE) for the <2^63 path;
the >=2^63 band assembles its 8 bytes from the GMP value (`gmp_export` / explicit
byte extraction), NEVER an int cast. Encode-side shortest-head-form + decode-side
range checks are GMP arithmetic.
**Rationale:** This is the **single most important codec-correctness decision**
for PHP — the OCaml A-OC-001/F7 trap re-derived on a 3rd signed-int substrate
(after OCaml int63→Int64, C# ulong, TS bigint). GMP gives exact arbitrary-precision
math; a uniform GMP path avoids the int↔carrier branching bug surface. (Alternative
considered + rejected: native int for <2^63 + decimal `string` for the high band —
the JSON-bigint shape; rejected for the two-path bug surface.) ext-gmp is in the
image (and the container build-time assertion proves a >2^63 GMP value round-trips).
**Escalation:** **operator** — impl detail (a hard codec-correctness constraint, no
spec impact: the spec's integer range is fixed; this is how PHP carries it). Spike
the `int.10/15/16/17` [2^63, 2^64-1] vectors at S2.

---

## A-PHP-004: shortest-float / f16 — PHP pack/unpack has no half-float code

**V7 section:** ENTITY-CBOR-ENCODING.md Rule 4 / Rule 4a (float minimization + special floats)
**Profile field:** `[idiom].f16_handroll`
**Your guess:** Hand-assemble f16 from the IEEE-754 binary64 bits — PHP
`pack`/`unpack` offer only `g`/`e` (f32) and `G`/`E` (f64); there is **no
half-float directive**. So `encFloat` decomposes via `unpack('J', pack('G', $f))`,
checks the unbiased exponent is in `[-14, 15]` (silent overflow-to-Inf guard) AND
the low 42 mantissa bits are zero (exactness), then assembles the 16-bit half
(`pack('n', …)`). f32 uses `pack('G')`-derived bits with an exact-round-trip +
all-ones-exponent guard. NaN/+Inf/-Inf/-0.0 take their fixed Rule 4a f16 bytes
(F9 7E00 / F9 7C00 / F9 FC00 / F9 8000). Decode rebuilds f16 (normals + subnormals)
and surfaces specials as native `NAN` / `±INF`.
**Rationale:** Same ladder shape as the native siblings (the Ruby A-RUBY-006 spike:
Ruby `Array#pack` likewise has no half-float code), implemented against PHP's
available primitives. The highest-bug-density code in any peer's codec — guard f16
overflow → Inf, match NaN/Inf by raw bits.
**Escalation:** **operator** — impl detail, no spec impact. Spike the `float`
vectors at S2.

---

## A-PHP-005: concurrency = single-thread `stream_select` event loop (no native threads in std PHP)

**V7 section:** §4.8 (store-safety / data-race = crash), §4.9 (resilience under load), §6.11 (reentrant request_id demux), §7b concurrency gate
**Profile field:** `[async]` (`event-loop` / `single-thread stream_select` / `single-thread store-safety`)
**Your guess:** Meet §4.8/§4.9/§6.11/§7b with a **single-thread non-blocking event
loop** over `stream_select()` and non-blocking stream sockets
(`stream_socket_server`/`stream_socket_accept`/`stream_set_blocking(false)`).
Store-safety (§4.8) is **trivial** — one handler runs at a time, no data races by
construction, the §3.9 CAS put is a sequential read-then-write needing NO lock (the
structural-safety route in the §7b taxonomy). §6.11 demux is a `pending
{request_id => waiter}` map resolved by the reader callback (no thread/condvar).
§4.9: every socket is non-blocking + multiplexed, so a blocking recv is impossible
and one slow connection cannot block others; a per-handler exception is caught at
the loop boundary (no-crash floor). Set **TCP_NODELAY** on every socket (§7b; the
Zig Nagle lesson) via `stream_context 'socket'=>['tcp_nodelay'=>true]` (or a
`setsockopt` on the fd via ext-sockets if the stream context proves insufficient —
verify at S3).
**Rationale + honest accounting:** Standard PHP (php-cli SAPI) has **no native
userland threads** (ext-pthreads dead; ext-parallel = ZTS-only non-core dep), so
the dependency-free idiomatic concurrency primitive is the stream_select event
loop (what ReactPHP/Amp abstract over). This is a genuinely **distinct** shape from
every prior peer — Ruby's thread-per-connection + GVL + Mutex-store becomes PHP's
single-thread loop + no-lock store. The honest caveat: a single thread is NOT
parallel (CPU-bound signature bursts serialize), but the peer is IO-bound, so it is
§7b-adequate (the same honesty as Ruby's GVL note, but simpler — no GVL subtlety).
True-parallel escape hatches (pcntl_fork process-per-connection / ext-parallel on a
ZTS build / ext-ev) are NOTED, NOT used at core.
**Escalation:** **operator** — design decision, flagged for review (the
no-native-threads single-thread-loop call is the PHP-specific concurrency seam).
No spec impact; no dependency (all stdlib `stream_*` + ext-sockets if needed for
TCP_NODELAY). Validate end-to-end (incl. the §6.11 multi-request_id demux + the
§4.8 sequential-CAS proof) at S3.

---

## A-PHP-006: Packagist coordinate `entity-core/protocol` (drop the redundant `-php` suffix)

**V7 section:** n/a (packaging)
**Profile field:** `[publishing].package_id`, `[layout].package_name`
**Your guess:** Composer `vendor/package` coordinate **`entity-core/protocol`**
(peer id `entity-core-protocol-php` is keystone naming; a Composer package is
implicitly PHP, so the redundant `-php` suffix is dropped — mirrors the
Ruby/Elixir registry-id reasoning). PSR-4 root namespace `EntityCore` → `src/`.
The parked pre-release version is the SemVer-dash `0.1.0-pre`, which Composer/SemVer
accepts **natively** (no RubyGems-style `0.1.0.pre.pre` mangling / no ASDF
dotted-integer rejection) — with `"minimum-stability": "dev"` + `"prefer-stable":
true` in composer.json so the unpromoted pre-release installs only under an
explicit stability flag.
**Rationale:** Composer coordinates are lowercase `vendor/package`; the `<lang>`
suffix in the keystone peer id is a multi-repo disambiguator a single-ecosystem
registry doesn't need. The SemVer-dash positive note is the inverse of the
RubyGems A-RUBY-010 / CL A-CL-010 grammar surprises — PHP is in the
suffix-accepting majority.
**Escalation:** **operator** — confirm `entity-core` vendor-namespace
availability/non-squatting at S5 before first publish; fall back to a different
vendor namespace if taken. No spec impact.

---

## A-PHP-007: value model — explicit ByteString + EcfMap wrappers (PHP can't tag string-encoding / byte-keys)

**V7 section:** ENTITY-CBOR-ENCODING.md (major-2 byte vs major-3 text; map keys)
**Profile field:** `[idiom].binary_strings`, `[idiom].data_is_arbitrary_ecf`
**Your guess (S2 impl):** A bare PHP `string` encodes as a CBOR **text** string
(major 3); a CBOR **byte** string (major 2) is the `EntityCore\ByteString`
wrapper. CBOR **maps** decode to `EntityCore\EcfMap` (ordered `[key,value]`
entries) rather than a native PHP associative array, because (a) the corpus
carries **byte-string-keyed maps** (`map_keys.5`, the envelope `included` map keyed
by content-hash bytes) which a native PHP array CANNOT hold, and (b) PHP coerces
numeric-string array keys to int, which would conflate text "1" with int 1. The
encoder accepts BOTH an `EcfMap` and a native associative array (the idiomatic
public API for the common text-keyed case). This is the PHP form of the same
distinction every native peer drew — Ruby's String#encoding (ASCII-8BIT vs UTF-8),
TS's Uint8Array-vs-string, cpp's explicit `EcfValue::Map`. PHP's `string` carries
no encoding tag, so the wrapper is required, not optional.
**Rationale:** Faithful round-trip of the corpus byte-keyed maps is impossible with
native PHP arrays alone. The cpp explicit-Map model is the proven shape; mirrored
here. Finite floats use native PHP `float` (is_float separates 1.0 from int 1 at
the top level, so no float wrapper is needed for the common case — `Float64` exists
only as an explicit-construction helper).
**Escalation:** **operator** — impl detail, no spec impact (the wire shapes are
fixed; this is how PHP carries them faithfully).

---

## A-PHP-008: PHP has no `ldexp()`; -0.0 detect via bit pattern (PHP 8 throws on 1.0/0.0)

**V7 section:** ENTITY-CBOR-ENCODING.md Rule 4 / 4a (float decode of f16 subnormals; -0.0)
**Profile field:** `[idiom].f16_handroll`
**Your guess (S2 impl):** Two PHP-runtime facts surfaced building the f16 ladder,
both impl-local, no spec impact. (1) PHP has **no `ldexp()`** in its standard
library (unlike Ruby's `Math.ldexp` referenced in the A-PHP-004 ladder sketch), so
f16-subnormal/normal decode reconstructs the value as `mantissa * (2.0 ** exp)` —
`2.0 ** e` is an exact power-of-two double for the f16 exponent range, so the
result is bit-exact. (2) PHP 8 **throws `DivisionByZeroError` on `1.0 / 0.0`**, so
-0.0 cannot be detected by the `1.0/f` sign trick used elsewhere; it is detected by
the raw 64-bit pattern instead (`-0.0 == 0.0` is true, but the sign bit differs).
**Rationale:** Both are faithful substitutes that preserve byte-identity (the f16
specials + neg-zero + the full ladder all pass the corpus + spike). Recorded so the
next PHP-family peer doesn't re-trip them.
**Escalation:** **operator** — impl detail, no spec impact.

---

_No blocking-severity items. S1 exit criteria met: profile fully populated (no
TBD-blocking), rationale written, container authored + specified (build
verification deferred to first build / S2 per the S1 no-build boundary). The two
items that touch the next phase are **A-PHP-003** (the GMP uint64 carrier — the
load-bearing codec-correctness constraint, spike at S2) and **A-PHP-001/A-PHP-004**
(hand-rolled CBOR + f16 ladder, spike at S2); neither blocks S1. **A-PHP-002**
(Ed448 deferred) is a scoped gap, not a blocker — the Ed25519+SHA-256 floor is
complete. **No NEW spec-level ambiguity surfaced** — PHP is a corroboration-only
reach peer reading the complete v7.75 snapshot, corroborating the inherited cohort
findings (peer-id §1.5, 401/403 §5.2a, §4.10 resource_bounds, A-JAVA-010
`data`-shape, lowercase address-space hex) rather than re-litigating them. The
contribution is idiom breadth + convergence evidence (the 2nd dynamic/scripting
peer; a genuinely distinct concurrency axis = single-thread event loop with
no-lock store-safety; the signed-int uint64 trap re-derived on a 3rd substrate via
GMP; ext-sodium native floor crypto with an Ed448 gap), not a new finding._

---

# Phase S3 (peer machinery) — added entries

S3 is corroboration-only: every protocol-shaped decision below matches the freshest
reference peers (cpp, kotlin, ruby) and the inherited cohort findings. **No NEW
spec-level ambiguity surfaced.** The three entries are PHP-impl notes (the
concurrency idiom + two small encoding seams), all `operator`-scoped.

## A-PHP-009: single-thread `stream_select` event loop as the concurrency idiom

**V7 section:** §4.8 (store-safety) / §4.9 (resilience) / §6.11 (reentrant demux) / §7b
**Profile field:** `[async].concurrency_model` = "single-thread stream_select event loop"
**Your guess:** Built the transport as ONE non-blocking event loop multiplexing the
listen socket + every connection (`EventLoop` + `Io`). An inbound EXECUTE is
dispatched inline; a handler originating an outbound EXECUTE (§6.13(b)/§6.11
reentry) calls `$conn->outbound`, which PUMPS the same loop until the reply
correlates by request_id (no thread, no condvar — cooperative re-entry). §4.8
store-safety is therefore STRUCTURAL (one handler runs to completion before the
next is dispatched — no concurrent store access, no lock). The 8-way demux fires 8
requests in flight on one connection, resolved out of order by the loop.
**Rationale:** PHP-CLI has no userland threads (ext-pthreads dead, ext-parallel
ZTS-only non-core). This is the dependency-free, idiomatic PHP primitive and was
the settled S1 profile decision. It is a genuinely distinct concurrency axis from
the cohort (kotlin coroutines+reader-threads, ruby thread-per-conn-under-GVL,
cpp threads) and gives the cleanest store-safety story (no race by construction).
**Escalation:** **operator** — profile-authorized idiom, no spec impact.

## A-PHP-010: TCP_NODELAY is best-effort (ext-sockets may be absent)

**V7 section:** §7b (transport menu — set TCP_NODELAY on raw-socket peers)
**Profile field:** `[async]` (concurrency/resilience notes)
**Your guess:** Set TCP_NODELAY via `socket_import_stream` + `socket_set_option`
guarded by `function_exists('socket_import_stream')` — a best-effort no-op when
ext-sockets is not loaded (it is NOT in the current php-toolchain image). The
stream-socket transport itself needs only core stream functions; NODELAY is a
latency optimization, not a correctness requirement, and loopback is unaffected.
**Rationale:** §7b NODELAY is a SHOULD-class throughput tuning (the Zig lesson was
about sustained small-frame churn, not loopback correctness). If S4 throughput
gating ever needs it, add `ext-sockets` to the image (a one-line Containerfile
change) — flagged here so it is a known knob, not a surprise.
**Escalation:** **operator** — image/tuning decision, no spec impact.

## A-PHP-011: handler classes are separate PSR-4 files (no inner classes in PHP)

**V7 section:** §6.13(a) (HandlerContext / handler interface contract)
**Profile field:** `[idiom]` (PSR-4 autoload)
**Your guess:** Kotlin/cpp model the MUST handlers as inner classes of the peer;
PHP has no inner classes and Composer PSR-4 requires one class per file, so each
handler is its own `final class ...Handler implements Handler` file constructed
with a `Peer` reference (the shared helpers — `mintToken`, `deriveSeedGrants`,
`abs`, etc. — are public methods on `Peer`). Stateless companion-object statics
became a `PeerHelpers` class.
**Rationale:** The idiomatic PHP shape for the same structure; behavior is
identical, the `Handler` interface contract is preserved, and the code reads as
PHP, not transpiled Kotlin.
**Escalation:** **operator** — language-structure idiom, no spec impact.

---

# Phase S5 (publish/packaging) — added entry

S5 is packaging-only (corroboration-only reach peer; no spec-shaped decisions). One
**new** packaging ambiguity surfaced — a version-grammar surprise — overturning the
S1 A-PHP-006 prediction.

## A-PHP-012: Composer rejects `0.1.0-pre` (`pre` is not a Composer stability keyword) — omit `version`, tag-infer

**V7 section:** n/a (packaging)
**Profile field:** `[publishing].prerelease_version` (`"0.1.0-pre"`), `[idiom].minimum_stability`
**Your guess:** Carry **no `version` field** in `composer.json`; let Packagist infer
the version from the VCS git tag at publish time (`0.1.0-pre` / `v0.1.0`), with
`minimum-stability: dev` + `prefer-stable: true` retained so an unpromoted
pre-release installs only under an explicit stability flag. The cohort `0.1.0-pre`
label lives in README/CHANGELOG/PHASE-S5 prose; the git tag is the registry
coordinate on promotion.
**Rationale:** **This corrects the S1 A-PHP-006 prediction** that "Composer accepts
`0.1.0-pre` natively." It does **not**: Composer's version grammar only recognizes
the stability keywords `alpha`/`beta`/`RC`/`dev` (+ their `a`/`b`/numeric forms);
`pre` is **not** among them, so `composer validate` rejects a literal
`"version": "0.1.0-pre"` with `Invalid version string "0.1.0-pre"` (verified
in-container, Composer 2.7 / PHP 8.3 — `0.1.0-pre` REJECT vs `0.1.0-alpha1` /
`0.1.0-dev` / `0.1.0-RC1` / `0.1.0` all OK). Rather than mangle the cohort label to
`0.1.0-alpha1`, the Composer-idiomatic fix is to omit `version` entirely — Composer's
own guidance is that VCS-distributed packages should NOT hard-code `version` (the
registry reads the git tag), and a tag-less manifest passes `composer validate
--strict` clean ("could not detect … version, defaulting to 1.0.0" is an informational
notice, not an error; the publish-time tag supplies the real coordinate). This is the
PHP analogue of the RubyGems `-pre`→`.pre.pre` surprise (A-RUBY-010) and the CL ASDF
dotted-integer rejection (A-CL-010) — the **third** cohort ecosystem whose version
grammar disagrees with the SemVer-dash, and notably the *inverse* of A-PHP-006's
suffix-accepting-majority claim (PHP is NOT in that majority for the `-pre` suffix
specifically). Logged so a future promotion re-confirms the tag spelling.
**Escalation:** **operator** — packaging decision, no spec impact; supersedes the
A-PHP-006 "SemVer-dash native" sub-claim (the coordinate name `entity-core/protocol`
and the `minimum-stability` posture from A-PHP-006 stand; only the version-string
prediction is corrected here).
