# entity-core-protocol-smalltalk — Spec Ambiguity Log

Per PROMPT-CONSTANTS: every guess is logged here, no silent guesses. `A-ST-NNN`.
Severity: **blocking** (stops a phase) / **non-blocking** (proceed with a flagged
best-guess) / **finding** (candidate spec-precision issue → arch).

Status at end of S1: **no blocking items.** This is a corroboration/robustness probe
(pure-object / live-image / message-passing — the generator-stress axis, A-ST-000); a
fresh spec finding is the upside, not the expectation. Library + substrate confirmations
(A-ST-001/002/004/005/006) were resolved at the S1 container build. Only publish URLs are
TBD-on-first-publish (non-blocking, as across the cohort).

**Status at end of S5 (FINAL — CLOSED):** all **18 items A-ST-000..017** are RESOLVED at
their stage or **research-owned** (generator-robustness / build-gate probes). **No item is
open and none is arch-escalated** — the pure-object / live-image / message-passing probe
surfaced **no fresh spec-precision finding** on the current saturated wire surface (clean
corroboration, the answer the profile was built to get). The durable value banked here is
the pure-object substrate lessons — A-ST-000 (the codec IS an idiomatic `encodeOn:`
double-dispatch, not a translated procedure), A-ST-012 (a distinguished-object absent
sentinel needs `isAbsent` answered polymorphically on the `EcValue` supertype, else the
"never nil-conflate absent" discipline still faults a DNU), A-ST-016 (the resilience frame
must catch the language's ROOT `Error` on a no-static-check substrate, or one DNU on an
unexercised path fells the whole peer) — plus the live-image toolchain lessons
(A-ST-010/011/013) and the four S4 code-bug findings in the *generated peer*
(A-ST-014/015/016/017), every one a code fix with no vector relaxed and no spec divergence.
The two low-likelihood finding-candidates carried from S1 (A-ST-002 float determinism,
A-ST-003 explicit value-tagging) both resolved TIGHT at S2 (native IEEE bits reproduce the
spec's shortest-form/canonical-NaN determinism; every core field's kind is spec-fixed). Only
the publish URLs (`repository_url`/`registry_url`, TBD on first publish) remain
non-blocking-open, as across the cohort. Owner tally: **operator/research on all 18; zero
outstanding to architecture.**

---

## A-ST-000: pure-object / message-passing generator-stress (THE probe)

**V8 section:** absent — a generator-robustness axis, not a wire axis
**Profile field:** `[idiom] pure_object`, `message_passing`, `live_image`
**Your guess:** The recursive canonical-CBOR encoder + the §5 capability chain-walk are
expressible IDIOMATICALLY as message-sends over an object graph — a value is a tagged
`Ec*Value` object, the codec is a polymorphic `encodeOn:` / double-dispatch per value
class, control flow is message-sends (`ifTrue:`, `do:`, `inject:into:`), NOT free functions
+ control keywords. The risk this probe exists to surface: the generator emitting procedural
"Smalltalk-flavored C" (a giant type-switch method / primitive obsession) that reads as
translated, not native.
**Escalation:** **operator / research — the probe itself.** The verdict (idiomatic
double-dispatch vs translated procedural) is a review judgment at S2/S3, carried forward.
Corroboration-first; a fresh wire finding is the upside.

## A-ST-001: integer tower on an arbitrary-precision bignum substrate (uint64 FREE)

**V8 section:** ENTITY-CBOR-ENCODING §major-types 0/1 (int), §head minimal-argument
**Profile field:** `[codec] numeric_model = "bignum"`, `[idiom] bignum_integers`
**Your guess (CONFIRMED at S1):** `SmallInteger` promotes to `LargePositiveInteger`
transparently; `(2 raisedTo: 64) - 1` is exact and classes as `LargePositiveInteger`
(verified in-container). So the full uint64 range `[0, 2^64-1]` is carried FREE — the
BIGNUM class (Rexx/Python/CL/Elixir/Haskell), NOT the fixed-width-int class
(Forth/Zig/C#/OCaml). The CBOR head form is still emitted explicitly (minimal-argument), but
there is NO `[2^63, 2^64-1]` signed/unsigned boundary hazard and NO fixed-width self-test tax
— a concrete contrast with the immediately-prior Forth probe's 64-bit cells.
**Escalation:** **operator — RESOLVED at S1.** No spec question; a clean native mapping.

## A-ST-002: native IEEE float bits (f32/f64 native; only f16 + shortest-ladder hand-rolled)

**V8 section:** ENTITY-CBOR-ENCODING §float shortest-form ladder (f16/f32/f64), §mt7
**Profile field:** `[codec] cbor_library`, `[idiom] native_float_bits`
**Your guess (CONFIRMED at S1):** Pharo's `Float` has `asIEEE64BitWord` /
`asIEEE32BitWord` (→ the raw IEEE-754 bits as an Integer) + inverses `Float fromIEEE64Bit:`
/ `fromIEEE32Bit:` (verified: `1.0 asIEEE64BitWord = 16r3FF0000000000000`,
`1.0 asIEEE32BitWord = 16r3F800000`, inverse round-trips). So f32/f64 encode/decode read the
true IEEE bits NATIVELY (like Forth, far easier than Rexx's all-decimal hand-roll). Only the
f16 half-float leg + the shortest-float ladder (does the value round-trip through f16/f32
exactly?) stay hand-rolled bit arithmetic — but operate on real float bits.
**Escalation:** **finding-candidate (low likelihood)** — S2 proves whether the spec's float
determinism (shortest-form selection, canonical NaN 0x7e00, ±Inf, ±0) is exactly
reproducible from `asIEEE*BitWord`. Expected: tight (native bits, like Forth). Carried to S2.

## A-ST-003: int-vs-float / bytes-vs-text intent via value-object class (double dispatch)

**V8 section:** ENTITY-CBOR-ENCODING §mt0/1 (int) vs §mt7 (float); §mt2 (bytes) vs §mt3 (text)
**Profile field:** `[idiom] explicit_value_tagging`
**Your guess:** Because dispatch is by object class, int-vs-float and bytes-vs-text intent
lives in the value object's CLASS (`EcInt` vs `EcFloat`, `EcByteString` vs `EcTextString`)
and the codec double-dispatches on it. The peer NEVER infers a CBOR major type from a raw
Smalltalk value (a `1` could be int-or-float intent; a `String` vs a `ByteArray` is not the
protocol's byte-vs-text distinction). Same root as A-TCL-003 / A-RX-003 / A-FT-003, expressed
here as class polymorphism rather than a tagged record.
**Escalation:** **finding-candidate (low likelihood)** — S2 confirms every numeric/string
core field's kind is spec-fixed (a field property, not a value property). Expected: tight.

## A-ST-004: byte-string-native — take the BYTE length (no char-vs-byte trap)

**V8 section:** ENTITY-CBOR-ENCODING §byte (mt2) / text (mt3) strings
**Profile field:** `[idiom] byte_string_native`, `addr_len` (N/A — objects)
**Your guess (CONFIRMED at S1 for the mechanism):** a `ByteArray` is a first-class
byte-vector; text is a UTF-8-aware `String`. The codec works over `ByteArray` throughout;
the wire byte count is `String>>utf8Encoded size` / `asByteArray size`, NOT the character
count (Pharo `String` is character-oriented, so — unlike Forth/Tcl's byte-oriented strings —
the peer MUST convert text to UTF-8 bytes and take the BYTE length; the A-TCL-002 char-vs-byte
trap is avoided by always encoding to `ByteArray` first). byte-vs-text intent carried
explicitly per A-ST-003.
**Escalation:** **operator — RESOLVED at S1** (mechanism), carried to S2 for the encode path
(always `utf8Encoded` before length). Non-blocking.

## A-ST-005: in-process UFFI crypto binding (the KEY differentiator, like Forth)

**V8 section:** §9.1 signature floor; C-ABI ENTITY-CODEC-C-ABI-V1 (ec_ed25519_*, ec_sha256/384)
**Profile field:** `[codec] ed25519_library`, `[idiom] in_process_ffi`
**Your guess (CONFIRMED at S1):** Pharo's Unified FFI (`ffiCall: #(...) module:`) is a
genuine in-process libffi binding (the VM dlopen's the `.so`, marshals via libffi). Verified
in-container: an external `libecfake.so` exporting an `ec_*`-shaped symbol
`(void*, uint64, void*) -> int32` was bound with exactly `ffiCall:module:` (class defined via
`Object << #Name` → `install` → `compile:`) and called correctly in-process (status 0,
xor-fold 0x0F). So — like Forth's libcc c-function — crypto is a direct in-process call; NO
subprocess/FIFO/co-process daemon (Rexx's A-RX-011 transport pain does NOT arise). The
production crypto class is `EcLibEntityCoreCodec` with one `ffiCall:module:` method per ec_*
symbol.
**Escalation:** **operator — RESOLVED at S1.** Carried to S2 (bind the real
libentitycore_codec ec_* symbols; placement on LD_LIBRARY_PATH is the verified mechanism).

## A-ST-006: headless launch requires `--headless` before the image (banked gotcha)

**V8 section:** absent — a toolchain-operational fact
**Profile field:** `[container]`, `[build]`
**Your guess (CONFIRMED at S1):** the Pharo 13 launcher must be invoked
`pharo --headless <image> eval "…"` — the `--headless` flag BEFORE the image path.
Without it the launcher tries to open the Morphic World and FATALs with "Invalid window
handle" under a no-display container. This bit the first S1 container build; the Containerfile
now launches `--headless` throughout.
**Escalation:** **operator — RESOLVED at S1.** S2/S3/S4 run scripts MUST use `--headless`.

## A-ST-007: absent sentinel is a distinguished object, NOT nil and NOT empty ByteArray

**V8 section:** §4 (entity fields), general canonical-value handling
**Profile field:** `[error_model] absent_sentinel`
**Your guess:** absent/"not found" is an `EntityAbsent` singleton object — deliberately NOT
`nil` (which is itself an object and would collide with a legitimately-nil field) and NOT the
empty `ByteArray` (the empty byte/text string is a legitimate wire value). The whole cohort
applies this discipline; here it is expressed in the pure-object idiom (a singleton object,
not a tagged marker or an RC flag).
**Escalation:** **operator — local decision, RESOLVED.** Non-blocking; carried to S2.

## A-ST-008: Ec-prefixed globally-unique class names (the Smalltalk word-prefix analogue)

**V8 section:** absent — an idiom/naming decision
**Profile field:** `[naming] namespace_scheme`
**Your guess:** Smalltalk has no namespace keyword and class names are globally unique in a
shared image, so the profile prefixes classes `Ec` (`EcCborEncoder`, `EcEntity`,
`EcCapability`) grouped in `EntityCore-*` Tonel packages — the Smalltalk analogue of Forth's
word-prefix, to guarantee global-name uniqueness when the peer is loaded into a user's image
alongside other code.
**Escalation:** **operator — local decision, RESOLVED.** Non-blocking.

## A-ST-009: crypto unified on the C-ABI even though SHA-256 could be native

**V8 section:** §9.1; C-ABI (ec_sha256)
**Profile field:** `[codec] sha256_source`
**Your guess:** the pure-Smalltalk `Cryptography` package HAS SHA-256, so SHA-256 COULD be
native — but Ed25519 has no audited native lib, so the whole crypto surface (SHA-256/384,
Ed25519, Ed448) is unified on the ONE audited C-ABI source (libsodium via UFFI) for a single
provenance. This mirrors the cohort's "one audited crypto source" preference (C#/Prolog/
Forth). An accept-path unit test in S2 cross-checks a known SHA-256 vector against the
C-ABI (the keystone "add an accept-path test the oracle can't cover" lesson).
**Escalation:** **operator — local decision, RESOLVED.** Non-blocking; if a reviewer prefers
native SHA-256 for an FFI-free-SHA sub-mode, that is a research note, not a blocker.

## A-ST-010: live-image single-doit class-visibility constraint (S2 finding)

**V8 section:** absent — a live-image toolchain / generator-robustness fact
**Profile field:** `[build]`, `[idiom] live_image`, `no_compile_gate`
**Your finding (S2):** a single doit (one `eval` / `compiler evaluate:` unit) compiles
ENTIRELY before it runs, so it **cannot both install a class and reference that class by its
global name later in the same doit** — the compiler raises "Undeclared variable". The idiom:
capture every newly-installed class in a TEMP and subclass / `compile:` off the temp;
cross-*file* references by global name are fine (the class is globally registered once the
doit completes). Consequence for the test harness: the driver must run against a SNAPSHOTTED
peer image (classes compile-time visible), not the same `eval` that loads them — hence the
`make image` (load + `Smalltalk snapshot`) step. This is the Smalltalk analogue of a
forward-declaration / two-pass load; it shaped every `src/*.st` and the Makefile flow.
**Escalation:** **operator — RESOLVED at S2, banked for S3.** Non-blocking; a generator
lesson for the live-image substrate, not a spec question. Carry to S3 (add S3 files to
`load.st` srcFiles; honor temp-capture per doit).

## A-ST-011: Pharo 13 class-builder API is a fluent cascade, not `package:slots:` (S2 finding)

**V8 section:** absent — a Pharo 13 API fact
**Profile field:** `[build]`, `[naming]`
**Your finding (S2):** `Object << #Name package: pkg slots: {…}` DNUs: `<<` (binary) yields a
`ShiftClassBuilder`, then `package: pkg slots: {…}` parses as ONE keyword message
`#package:slots:` (which the builder does not understand). The working form is the cascade
`((Object << #Name) slots: {…}; package: pkg; install)` (separate fluent setters, whose value
is the `install` result = the class). A no-slots class is fine as
`(Object << #Name package: pkg) install` (the binary `<<` binds before the keyword). Confirms
+ extends the S1 A-ST-006 note (`Object << #Name` → `install`).
**Escalation:** **operator — RESOLVED at S2.** Non-blocking; API mechanism, banked for S3.

## A-ST-012: an in-band absent sentinel must answer its predicate POLYMORPHICALLY (S3 finding)

**V8 section:** §4 (entity fields) / general canonical-value handling — a generator-robustness
axis on the pure-object substrate, not a wire axis
**Profile field:** `[error_model] absent_sentinel`, `[idiom] pure_object`
**Your finding (S3):** the profile's "absent = a distinguished object, NOT nil" discipline
(A-ST-007) is only SAFE on a pure-object substrate if the sentinel predicate (`isAbsent`) is
answered by the ENTIRE value hierarchy, not just the sentinel. The generator first defined
`isAbsent` on `EcAbsent` (→ true) + `EcEntity` (→ false) only; `EcEntity>>field:` returns the
sentinel on a missing key or the raw `EcValue` (e.g. an `EcMap`) otherwise, and a caller that
tested `v isAbsent` hit a live `doesNotUnderstand: #isAbsent` on the first present `EcMap`
(dropped every handshake reply — SMOKE 0/6). The fix is idiomatic Smalltalk: add
`isAbsent ^ false` to the `EcValue` BASE so every value answers the predicate; the sentinel
overrides to true. This is the pure-object analogue of the whole cohort's "absent is a
distinguished value, never nil-conflated" lesson — but with a SHARP edge unique to a
message-passing substrate: a distinguished-object sentinel only works if the predicate is a
polymorphic message on the common supertype, else the "not nil" discipline still faults (a DNU)
at the first non-sentinel it meets. A pure additive method, no wire change (S2 corpus
re-verified 69/69·0F).
**Escalation:** **operator — RESOLVED at S3.** Non-blocking; a generator-robustness lesson for
the pure-object / message-passing substrate (the A-ST-000 axis), banked for the cohort — carry
to any future pure-OO / dynamic-dispatch peer.

## A-ST-013: headless-driver hygiene — top-level temps hoisted + no `#show:` (S3, re-confirm)

**V8 section:** absent — a live-image toolchain / driver-hygiene fact
**Profile field:** `[build]`, `[testing]`, `[idiom] live_image`
**Your finding (S3):** the S2 gotchas A-ST-010 (a single doit compiles as one method → a temp
decl cannot follow a statement at the TOP level; block-local `| x |` inside `[...]` stays fine)
and A-ST-006 (the non-interactive transcript has no `#show:`/`#showln:` → a driver builds a
result String and returns it / emits via `Stdio stdout`) BOTH bit the S3 peer DRIVERS
(`s3-selftest.st`, `smoke.st`) exactly as they bit the S2 codec drivers. Resolution: hoist ALL
top-level temporaries to the leading declaration; accumulate output in a `WriteStream on: String`
and `Stdio stdout nextPutAll: ... ; flush` + return the value, raising an `Error` (→ nonzero
exit) only AFTER emitting the summary. The peer bin (`bin/peer.st`) reads its options from ENV
vars for the same reason (a headless `eval` appends argv to the source, not to the doit's args).
**Escalation:** **operator — RESOLVED at S3.** Non-blocking; banked toolchain hygiene for S4
(every conformance driver + the peer entry follow this shape).

## A-ST-014: per-connection nonce counter → cross-connection handshake replay (S4 finding, FIXED)

**V8 section:** §4.6 (nonce issuance / handshake integrity), F12
**Profile field:** `[async]` single-event-loop, `request_demux`
**Your finding (S4):** `mintNonceFor:` derived the §4.6 nonce as `SHA256(counter ‖ id_hash)` where
`counter` was the PER-CONNECTION out-counter (`aConn nextOut`). That counter resets to 0 on every
fresh connection, so every connection's first nonce is the IDENTICAL `SHA256(1 ‖ id_hash)` — a
captured `authenticate` from connection A replays byte-for-byte on connection B (the oracle's
`connectivity/handshake_replay_cross_connection` FAIL, F12). The fix: a PEER-GLOBAL monotonic
`nonceCounter` (EcPeer ivar, `nextNonceCounter`) so every issued nonce is unique across
connections. A generator-robustness lesson: a "unique per issuance" nonce MUST use a peer-global
(not per-connection) counter on a substrate where a fresh connection resets its own counters.
**Escalation:** **operator — RESOLVED at S4.** Real peer bug, caught by the oracle, fixed in code.

## A-ST-015: uppercase hex on revocation/signature tree paths (S4 finding, FIXED)

**V8 section:** §3.4/§3.5 tree-path hex convention (A-CL-009 cohort-settled), §5.1 revocation
**Profile field:** `[naming] file_names` (tree paths)
**Your finding (S4):** `EcPeer>>hexOf:` / `EcCapAuthz>>hexOf:` used `b printPaddedWith: $0 to: 2
base: 16`, which yields UPPERCASE hex. The oracle (and the §3.4/§3.5 lowercase tree-path
convention) uses LOWERCASE. So `handleCapRevoke:` bound a revocation marker at
`.../revocations/00537D46…` (uppercase) but the oracle's subsequent `tree.get` canonicalized to
`.../revocations/00537d46…` (lowercase) → the marker was never found → `revoke_happy_path` +
`revoked_cap_denied_on_use` FAIL (a 404 after a 200 revoke). The fix: force `asLowercase` on the
hex. Same trap as the cohort's lowercase-`%02x` path rule; here it surfaced because Pharo's
`printPaddedWith:to:base:` defaults to uppercase digits.
**Escalation:** **operator — RESOLVED at S4.** Real peer bug, caught by the oracle, fixed in code.

## A-ST-016: dispatch must catch ANY Error, not just EntityCoreError (S4 finding, FIXED)

**V8 section:** §4.9 deliver-or-signal (resilience) — a generator-robustness axis on the
dynamic/live-image substrate
**Profile field:** `[error_model] style=exceptions`, `[idiom] no_compile_gate`
**Your finding (S4):** the S3 `handleExecute:` / `serveConn:` caught only `EntityCoreError`. On a
dynamic substrate with NO compile-time type check (A-ST no_compile_gate), an unanticipated request
shape can raise a live `MessageNotUnderstood` (DNU) DEEP inside a handler/authz — which escaped
the `on: EntityCoreError do:` frame and CRASHED the single-event-loop `serveForever` (a Pharo
debugger stack dumped to stderr; every subsequent request got a broken pipe). The first oracle run
died on `ByteString >> #tokenize:` (a non-existent selector; Pharo uses `findTokens:`), taking the
whole peer down and cascading 229 FAILs. The fix: `handleExecute:` catches `Error` (→ 500 coded
response) and `serveConn:`/`onFrame:` catch `Error` (→ swallow + keep serving). This is the §4.9
"deliver-or-signal, never silently drop" rule, but with a SHARP edge unique to a no-static-check
substrate: the resilience frame MUST be the language's ROOT error class, not just the protocol
error subtree, or one DNU on an unexercised path fells the whole peer. Carried to any future
dynamic/live-image peer. (Also banked: `findTokens:` not `tokenize:`; `printPaddedWith:` is
uppercase; `waitForAcceptFor: 0` is a non-blocking accept poll.)
**Escalation:** **operator — RESOLVED at S4.** Generator-robustness lesson for the pure-object /
dynamic-dispatch substrate (the A-ST-000 axis).

## A-ST-017: single-event-loop accept-poll timeout starves throughput (S4 finding, FIXED)

**V8 section:** §7b readiness discipline / §4.8 single-event-loop; resource_bounds r3, tree/concurrency
**Profile field:** `[async]` single-event-loop, `blocking_discipline`
**Your finding (S4):** the S3 serve loop ran `serveTick: 1` — a 1-SECOND blocking `waitForAcceptFor:`
per tick. With pipelined tree.put/get traffic, every tick blocked up to 1s inside the accept-wait
even while EXISTING connections had data ready → the oracle's per-request 20s budget expired
(`tree_operations` core_tree_listing_1 / core_tree_delete_1 / path_flex i/o timeout; ~47s per
category). The fix: a NON-BLOCKING accept poll (`waitForAcceptFor: 0`), drain EVERY ready
connection of ALL available frames each tick, and only a bounded 2ms `Delay` when a tick did zero
work (so no CPU busy-spin). Throughput went from ~47s/category to sub-second. A single-event-loop
peer MUST poll accept non-blocking and serve ready connections first — the accept-wait is NOT the
place to block. Also §4.10(c) admission for r3: accept the whole flood into a bounded working set
(ExternalSemaphoreTable grows dynamically; `tryAccept:` is error-safe against a transient socket-
registration race so 256+ live sockets don't fell the peer) and keep serving the post-flood probe
(the SHOULD → WARN outcome).
**Escalation:** **operator — RESOLVED at S4.** Generator-robustness lesson for any cooperative
single-event-loop peer.

## A-ST-018: Pharo cannot write a half-closed socket, so §4.11's TRUNCATION refusal is undeliverable (S4 finding, DISCLOSED GAP)

**V8 section:** §4.11 pre-admission refusal (0.8.2.25), framing arm
**Profile field:** `[async]` single-event-loop; the `Socket` abstraction
**Finding:** §4.11 makes a coded `EXECUTE_RESPONSE` mandatory for every pre-admission refusal,
including *"a length prefix that never completes"*. A truncated frame is only KNOWABLE at
end-of-stream — the sender writes a prefix, writes part of the body, and sends FIN — so answering
it requires writing to a socket whose far end has half-closed.

**Pharo refuses that write at every API level available to the image, and it was traced rather
than inferred.** From this peer's own stderr:

```
sendData:      -> ConnectionClosed: connection closed while sending data
sendSomeData:  -> ConnectionClosed          (the lower primitive, past the liveness guard)
```

`Socket>>isConnected` answers false the moment the far end sends FIN, and both write paths gate
on it. There is no `allowHalfOpen` here: Pharo's `Socket` has no half-open support to enable.

**This is the third runtime in the cohort to decide, by its stream layer, whether a refusal
reaches the wire — and the first with no knob.** Node needs `allowHalfOpen: true`; the BEAM needs
`exit_on_close: false`; go's `TCPConn` has the behaviour by default, which is why neither
`0.8.2.25` vanguard needed the line and neither would have predicted any of the three.

**What is implemented anyway, and why it stays:** `readFrame` distinguishes a clean close at a
frame boundary (`#eof`, owed nothing) from a stream that ended mid-frame (`#truncated`), the
truncation arm is reached — verified by trace — and it composes `400 invalid_request`. Only the
delivery fails, and it says so on stderr once rather than silently. A peer that DETECTS the
condition and reports that it cannot answer is a different artifact from one that never looked,
and the arm becomes deliverable the day the socket layer supports a half-open write.

**Not affected:** the OVERSIZE arm delivers normally (`413 payload_too_large`, measured), because
the far end has not closed there — which is exactly why §4.10(a)'s SHOULD became a MUST at N14:
the condition is knowable from four bytes with the connection intact.

**Measured:** `tools/pa-probe` — 5 of 6 arms owed → 1, both controls green. The remaining one is
this.
**Escalation:** **operator / substrate.** Not a spec ambiguity and not routed to architecture: the
rule is clear and this peer cannot meet one clause of it on this runtime.
