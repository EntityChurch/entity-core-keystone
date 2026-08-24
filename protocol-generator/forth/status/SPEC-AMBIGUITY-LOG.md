# entity-core-protocol-forth — Spec Ambiguity Log

Per PROMPT-CONSTANTS: every guess is logged here, no silent guesses. `A-FT-NNN`.
Severity: **blocking** (stops a phase) / **non-blocking** (proceed with a flagged
best-guess) / **finding** (candidate spec-precision issue → arch).

Status at end of S1: **no blocking items.** The stack-machine generator-stress probe
(A-FT-000) is the reason this peer exists — carried into S2/S3 as the thing to prove.
Library + substrate confirmations (A-FT-001/002/004/005/008) were resolved at the S1
container build. No fresh spec finding expected on the current (saturated) wire surface;
the probe's payoff is generator robustness.

**Status at end of S5 (FINAL — CLOSED):** all **29 items A-FT-000..028** are RESOLVED at
their stage or **research-owned** (generator-robustness / build-gate probes: A-FT-000, 005,
008 — all confirmed at their stage). **No item is open and none is arch-escalated** — the
stack-machine probe surfaced **no fresh spec-precision finding** on the current saturated wire
surface (clean corroboration, the answer the profile was built to get). The durable value
banked here is cross-Forth substrate lessons (A-FT-010/011/012/013/014) and the seven S4
code-bug findings in the *generated peer* (A-FT-017–028, chief among them the concurrency
payoff A-FT-025), every one a code fix with no vector relaxed and no spec divergence. Owner
tally: **operator/research on all 29; zero outstanding to architecture.**

---

## A-FT-000: stack-machine / typeless generator-stress probe (THE probe)

**V8 section:** n/a — a generator-robustness axis, not a wire-spec axis (LANDSCAPE:
"Forth — stack machine / no types — generator stress").
**Profile field:** `[idiom] stack_machine`, `typeless_values`
**Your guess:** The recursive canonical-CBOR encoder + the §5 capability chain-walk are
expressible idiomatically on a stack substrate using offset-word "structs" over ALLOTed
buffers + explicitly-tagged values, WITHOUT deep dup/roll/pick choreography that reads as
translated. The state the other peers keep in named locals / typed records lives on the
data + return stacks + a tagged buffer representation.
**Escalation:** **research — generator-robustness probe.** S2/S3 prove whether the
language-agnostic phase prompts assume named-variable / typed-record structure the
generator must work around on a stack machine. Expected: expressible; the probe closes as
corroboration (generator robust down to a typeless stack machine).

## A-FT-001: integer tower on a fixed-width 64-bit cell (head form + boundary)

**V8 section:** ENTITY-CBOR-ENCODING §3.2 integer encoding, §4.1 Rule 1 (minimal ints)
**Profile field:** `[codec] numeric_model`, `[idiom] fixed_width_cell`
**Your guess (CONFIRMED at S1):** gforth cells are 64-bit (`1 cells` = 8 bytes,
confirmed in-container). uint64 fits ONE unsigned cell; int64 the same cell signed. This
is the fixed-width-int CLASS (Zig/C#/OCaml/C) — the codec carries the CBOR head form + a
self-test on `[2^63, 2^64-1]`, and the signed/unsigned seam at the top of the u64 range
is handled with UNSIGNED comparisons (`U<`), not signed. ECF's int tower tops at 2^64-1 /
-2^64 so a single unsigned cell covers core; CBOR bignum tags 2/3 are out of core scope.
**Escalation:** **operator — RESOLVED at S1.** No spec question; a clean fixed-width
mapping with the documented boundary discipline.

## A-FT-002: IEEE float tower reachable NATIVELY (SF!/DF! bits; f16+ladder hand-rolled)

**V8 section:** ENTITY-CBOR-ENCODING §3.6 / §4.1 Rule 4 + 4a (shortest float, specials)
**Profile field:** `[idiom] native_float_bits`, `[codec] cbor_library`
**Your guess (CONFIRMED at S1):** gforth has a REAL IEEE f64 float type + `DF!`/`SF!`
(f64/f32) and `DF@`/`SF@` MEMORY words. Writing a float then reading its 8/4 bytes yields
the true IEEE-754 bits (confirmed: `1.0e0 fbuf df!` → `0x3F` at the MSB offset; `sf!`
likewise for f32). So f32/f64 encode reads native bits (assemble big-endian from the
SF!/DF! image); this is MUCH less hand-roll than Rexx (which computed every IEEE bit in
decimal — A-RX-002). The f16 half-float leg (no gforth format for it) and the
shortest-float ladder (does the value round-trip through f16/f32 exactly?) remain
hand-rolled bit arithmetic — but operate on real float bits. The canonical specials (NaN
`F9 7E00`, ±Inf `F9 7C00`/`FC00`, -0.0 `F9 8000`) are fixed bytes per §4.1 Rule 4a.
**Escalation:** **operator — local decision (native bits confirmed).** S2 proves the
f16 leg + ladder against the `float` vectors (14+); expected tight (the specials are
fixed bytes; native f32/f64 bits remove Rexx's decimal-rounding risk).

## A-FT-003: typeless cells — int-vs-float / bytes-vs-text intent carried explicitly

**V8 section:** ENTITY-CBOR-ENCODING §3.1 major types; §7.6.1 (strict int/float type check)
**Profile field:** `[idiom] typeless_values`
**Your guess:** A stack cell is untyped (an int, an address, a flag — all cells); a float
lives on the separate FP stack. The codec's value representation TAGS int-vs-float and
bytes-vs-text EXPLICITLY (a type-tag cell + payload in the tagged record), and NEVER
infers a CBOR major type from a cell's value. Same root as A-TCL-003 / A-RX-003, sharpest
here (a cell has literally no type). §7.6.1's strict "integer types reject floats, float
types reject integers" is honored because the tag, not the bit pattern, decides.
**Escalation:** **operator — local decision.** Corroborates the Tcl/Rexx explicit-intent
resolution on a third typeless substrate.

## A-FT-004: byte-native strings — (addr,len); count IS byte length (no char trap)

**V8 section:** ENTITY-CBOR-ENCODING §3.3 byte (mt2) / text (mt3) strings
**Profile field:** `[idiom] byte_string_native`, `addr_len_strings`
**Your guess (CONFIRMED at S1):** A gforth string is an `(addr, len)` byte pair; gforth
is byte-oriented with no Unicode string type, so the count is already the wire BYTE count
— the A-TCL-002 char-vs-byte-length trap does NOT arise (as with Rexx A-RX-004). UTF-8
text is just its bytes. byte-vs-text (mt2 vs mt3) intent is still carried EXPLICITLY in
the tagged record (an `(addr,len)` alone cannot say which major type).
**Escalation:** **operator — RESOLVED at S1** on the length seam; the byte-vs-text tag is
the same explicit-tag discipline as Tcl/Rexx (no side-channel).

## A-FT-005: crypto via gforth's in-process libcc C FFI (the KEY differentiator)

**V8 section:** §9.1 crypto floor (Ed25519 + SHA-256)
**Profile field:** `[codec] ed25519_library`, `[layout] ffi_binding`, `[idiom] in_process_ffi`
**Your guess (CONFIRMED at S1):** gforth has no crypto. Bind `libentitycore_codec` via
gforth's libffi-based C interface (`libcc.fs`: `c-library` / `c-function` / `add-lib`),
exposing `ec_sha256/384` + `ec_ed25519_{seed_to_pubkey,sign,verify}` as Forth words.
This is a GENUINE IN-PROCESS FFI — `libcc.fs` uses libtool+gcc to compile a wrapper `.so`
and dlopen it; `s" entitycore_codec" add-lib` links `-lentitycore_codec`. CONFIRMED
in-container: an external `libecfake.so` exporting an `ec_*`-shaped symbol
`(const uint8_t*, size_t, uint8_t*) -> int32` was bound and called correctly, returning
status 0 and the expected out byte. Placed on `LIBRARY_PATH` (link) + `LD_LIBRARY_PATH`
(dlopen) — the mechanism S2 uses for the real lib.
**CRITICAL CONTRAST:** Rexx's `rxfuncadd` C-extension mechanism was NON-FUNCTIONAL
(A-RX-005), forcing a subprocess crypto helper + then a co-process daemon with a FIFO
transport (A-RX-011). gforth's `c-function` is in-process → the crypto surface is a direct
call and Rexx's entire S3 transport pain does NOT arise.
**GOTCHA (banked):** gforth caches the compiled wrapper `.so` in `~/.gforth/libcc-named`
keyed by the `c-library` NAME. A stale cache silently binds an OLD `.so` missing new
symbols (this bit the S1 probe: reusing library name `ffiprobe` after adding a symbol
loaded the old `.so` → `undefined symbol`). Clear `~/.gforth/libcc-named` +
`~/.gforth/libcc-tmp` on any symbol-set change (or use a fresh library name).
**Escalation:** **research — S2 build gate.** The libcc binding of the REAL
libentitycore_codec `ec_*` symbols + a KAT is the S2 confirm; the mechanism is proven at
S1.

## A-FT-006: f16 half-float leg (hand-rolled from real float bits)

**V8 section:** ENTITY-CBOR-ENCODING §3.6 / §4.1 Rule 4 (shortest float f16/f32/f64)
**Profile field:** `[idiom] native_float_bits`
**Your guess:** gforth has no f16 type/format; the f16 leg is hand-rolled bit arithmetic
(sign / 5-bit biased exponent / 10-bit mantissa, subnormals, round-to-nearest-even) — but
DERIVED FROM the real f32/f64 bits (SF!/DF!), not from a decimal value (contrast Rexx
A-RX-006, which hand-rolled ALL widths). The shortest-form minimization (try f16, then
f32, then f64, pick the shortest that round-trips exactly) uses exact bit comparisons on
the native float image.
**Escalation:** **operator — local decision.** Verified by the `float` vectors at S2;
easier than Rexx (real bits available), harder than Tcl only on the f16 leg (Tcl had
`binary format R/Q` for f32/f64; gforth has SF!/DF! — equivalent).

## A-FT-007: empty string cannot be the "absent" sentinel

**V8 section:** n/a (representation)
**Profile field:** `[error_model] absent_sentinel`, `[idiom] byte_string_native`
**Your guess:** Absence is a tagged marker in the value rep; a present value is always a
non-empty tagged record. The empty `(addr, 0)` string is a legitimate wire value (empty
mt2/mt3), so it cannot double as absent (same resolution as Tcl A-TCL-007 / Rexx
A-RX-007 — the tag carries presence).
**Escalation:** **operator — local decision.**

## A-FT-008: native BSD sockets via unix/socket.fs (no co-process daemon)

**V8 section:** §8 transport (TCP), §4.8 concurrency
**Profile field:** `[async] socket_source`, `[deps] gforth`
**Your guess (CONFIRMED loadable at S1):** gforth ships `unix/socket.fs`, a BSD-socket
wordset over the libc socket syscalls (in-process). CONFIRMED: `require unix/socket.fs`
loads cleanly in-container. So the peer's TCP substrate is native + in-process — NO
co-process daemon (contrast Rexx A-RX-008, which had to fold sockets into a C co-process
because fedora Regina shipped no RxSock). The peer is a single-threaded select loop over
the listen socket + per-connection sockets → structural §7b store-safety.
**Escalation:** **research — RESOLVED loadable at S1.** The full listen/accept/recv/send/
select socket path (and TCP_NODELAY via socket.fs or a libc `c-function`) is confirmed at
S3 (a two-peer loopback). If socket.fs lacks a needed primitive (e.g. TCP_NODELAY /
select), fall back to binding the libc syscall directly via a libcc `c-function` (the
same in-process mechanism as crypto) — a clean fallback, not a co-process.

## A-FT-009: no named locals by idiom — codec state on the stacks + offset-word structs

**V8 section:** n/a (idiom)
**Profile field:** `[naming] aggregate_unit`, `[idiom] stack_machine`
**Your guess:** Idiomatic Forth composes on the data + return stacks with no named
locals (gforth HAS `locals|` / `{: :}` and they are available as an escape hatch for a
genuinely stack-hostile word, but the default is stack composition). A "struct" (entity,
envelope, capability) is a set of named field-OFFSET words over an ALLOTed buffer
(`>type` `>data` `>hash` return `addr + offset`). This is the idiomatic Forth record and
keeps the codec reading as native Forth, not translated. Where a word's stack effect
would exceed ~3-4 items in flight, use a local or a scratch buffer rather than roll/pick
gymnastics (readability guard for the A-FT-000 probe).
**Escalation:** **operator — local decision (idiom).** The S2/S3 review judges whether the
result reads as native Forth (the generator-stress verdict).

## A-FT-010: `>r`/`?do`/`r@` return-stack collision (Forth substrate gotcha; S2)

**V8 section:** n/a — a gforth/ANS-Forth implementation hazard, not a spec issue.
**Profile field:** `[idiom] stack_machine`, `aggregate_unit`
**Finding (S2, banked):** A counted `?do…loop` pushes its loop-control parameters onto the
**return stack**. So `>r`-ing a value before a loop and reading it with `r@` INSIDE the loop
returns the loop index, not the stashed value. The first drafts of `tv-node-len` and
`enc-map` used `>r addr … ?do … r@ …` and read garbage addresses → `Invalid memory address`.
**Resolution:** carry per-word state in **locals** (`{ … }`) and use `recurse` for
self-reference in a locals word (the `: … recursive` marker + the bare word name does not
resolve once locals are declared). The idiomatic fix (A-FT-009 predicted locals as the
escape hatch) and it keeps the recursive codec readable.
**Escalation:** **operator — RESOLVED at S2.** Durable cross-Forth lesson; no spec bearing.

## A-FT-011: `1 0 ?do` wraps on empty containers (Forth substrate gotcha; S2)

**V8 section:** ENTITY-CBOR-ENCODING §3.2 (empty map = `0xA0`, N3) — surfaced by, not caused
by, the spec.
**Profile field:** `[idiom] stack_machine`
**Finding (S2, banked):** gforth's counted `?do` with start > limit does NOT run zero times —
it counts up and wraps around 2^64. The map insertion-sort's `n 1 ?do` with n = 0 (an empty
map `{}`) ran ~2^64 iterations with a garbage index → an out-of-bounds store. `0 0 ?do`
(equal bounds) is safe; only start > limit wraps.
**Resolution:** guard any counted loop whose start can exceed its limit — `n 2 >= if … then`
around the sort. Empty-map `A0` (N3, `length.2`) is the trigger vector.
**Escalation:** **operator — RESOLVED at S2.** Durable Forth lesson; no spec bearing.

## A-FT-012: gforth two-name locals `{ a b }` bind in STACK order, not top-first (S3)

**V8 section:** n/a — a gforth locals-syntax hazard, not a spec issue.
**Profile field:** `[idiom] stack_machine`, `[async] request_demux`
**Finding (S3, banked):** For a word returning `( addr len )` (top = len), the local
declaration `{ a b }` binds **a = the deeper item (addr), b = the top (len)** — i.e. in
stack order, NOT "top → first name." Writing `net-read-frame { flen faddr }` therefore put
the LENGTH in `flen`… no: it put `addr` in `flen` and `len` in `faddr` (swapped), so the
de-framer passed `(payaddr=len, payu=addr)` to the decoder → a decode walk off a bogus base
→ `Invalid memory address`, caught, no reply, the smoke hung. The multi-name single-brace
form is the trap; the **separate single-brace** form `{ len } { addr }` (each pops the
current top) reads top-first and is unambiguous.
**Resolution:** for a 2-value return, either bind in stack order (`{ addr len }` for
`( addr len )`) or use separate single-name braces. Audited every `{ a b }` after a 2-value
word; only the two `net-read-frame` consumers were wrong.
**Escalation:** **operator — RESOLVED at S3.** Durable gforth lesson; no spec bearing.

## A-FT-013: a bump-heap `store-dup` that forgets to advance its pointer aliases every copy (S3)

**V8 section:** §1.1 (content store immutability) / §4.8 (store) — surfaced by, not caused by.
**Profile field:** `[async] store_model` (ALLOTed durable heap)
**Finding (S3, banked):** the durable-heap copier `store-dup` (copies an arena span out to a
heap the per-op arena reset can't clobber) originally did the `move` but **never bumped the
heap pointer**. So all three `store-dup`s in `id-init` (peer entity, id_hash, peer_id) wrote
to the SAME address, each overwriting the last — `id-peer` then returned bytes starting `'2'`
(a Base58 peer_id char), not `'E'` (an entity), and `ent-len`/`ent-hash` walked off. The
single-thread structural-store-safety idiom (§4.8) makes a bump heap the right shape, but the
pointer advance is load-bearing.
**Resolution:** `store-dup` advances `store-hp` by the copied length and returns `(dst, len)`.
**Escalation:** **operator — RESOLVED at S3.** Durable Forth lesson; no spec bearing.

## A-FT-014: append-word output must not be re-`bytes,`'d (double-write) into a canonical map (S3)

**V8 section:** ENTITY-CBOR-ENCODING §4.2.1 (canonical map ordering) — surfaced by.
**Profile field:** `[codec] canonical_mode` (arena string-builder)
**Finding (S3, banked):** words like `ent->wire` / `inc->map-tv` BOTH append their result to
the arena AND return its `(addr,len)` span (the arena string-builder idiom). Following such a
word with `bytes,` (which copies a span into the arena) DOUBLE-writes: the value lands once
from the append and again from the copy. At the top of a map this is harmless (the canonical
re-encoder bounds each value by `tv-node-len` and ignores the trailing copy), but INSIDE the
`included` map's pair sequence the duplicate entity-map desynchronised pair parsing → the
decoded envelope was missing its `root` key (E-MISSING-ROOT) whenever `included` was non-empty
— so the handshake's hello (empty included) worked but authenticate (signature + peer entity)
silently failed. The fix is `2drop` (discard the returned span; the bytes are already in
place), never `bytes,`, after an append-word.
**Resolution:** all four `ent->wire bytes,` → `ent->wire 2drop`. Rule banked: a word that
appends-and-returns is consumed with `2drop`; only a word that returns a NON-arena span is
consumed with `bytes,`.
**Escalation:** **operator — RESOLVED at S3.** Durable Forth codec-idiom lesson; no spec bearing.

## A-FT-015: single-thread select loop + in-process crypto obviates the Rexx co-process daemon (S3)

**V8 section:** §4.8 (store-safety) / §7b (transport) / §6.11 (reentry).
**Profile field:** `[async] style=single-thread-select`, `socket_source`, `in_process_ffi`
**Finding (S3, banked — the transport verdict):** the Rexx precedent (#24) needed an `ecnet`
C co-process daemon over two FIFOs because Regina's `rxfuncadd` was dead AND its FIFO reads
corrupt under a concurrent subprocess (A-RX-008/011). gforth has NONE of that friction:
`unix/socket.fs`-class raw BSD-socket syscalls bound via `libcc` give a genuine in-process
select loop, and `libcc c-function` gives genuine in-process libffi crypto (A-FT-005). So the
Forth peer owns the sockets, the select() loop, the §1.6 de-framing, the §4.10(a) 16-MiB cap,
TCP_NODELAY, AND the crypto all in ONE process — the COBOL/Tcl native-socket shape, not the
Rexx daemon shape. §4.8 store-safety is structural by construction (one interp, one frame to
completion per select wake). §6.11 reentry is a manual correlation pump (`dispatch-outbound` +
`await-reply` re-enter the same select pump, matching by request_id) — the correlation-map tax
the non-actor/non-CSP peers pay, but with no IPC layer. GOTCHA banked: a `c-library` NAME
becomes part of the generated wrapper's C symbol names, so it MUST be a valid C identifier —
a hyphen (`ecnet-sock`) made gcc reject the wrapper; use `ecnetsock`.
**Escalation:** **operator — RESOLVED at S3.** Durable cross-language transport lesson.

## A-FT-016: §6.6 resolution-first — 404 must beat 403 on an unregistered path (S3)

**V8 section:** §6.5 (dispatch chain order) + §6.6 informative (resolution-first).
**Profile field:** n/a — a spec-ordering requirement, correctly followed.
**Finding (S3, banked — NOT a spec defect):** the §6.5 chain runs integrity/authn → resolve
handler (404) → check permission (403). A first draft ran the COMPOSITE `cap-verify-request`
(authn AND authz together) BEFORE resolution, so a signed request to an unregistered path whose
seed grant didn't cover it returned **403 capability_denied** instead of **404 handler_not_found**
— violating §6.6's "resolution-first: an unauthorized request to a handler that is not
registered returns 404, not 403." Splitting the verdict into `cap-verify-authn` (signature
only, before resolution) + `cap-verify-authz` (chain/depth/grantee, after resolution) restores
the spec order. The §4.10(b) chain-depth pre-check stays inside the authz leg (a structural 400,
before the per-link walk). Confirms the spec is precise here — the finding is the *ordering
discipline*, not an ambiguity.
**Escalation:** **operator — RESOLVED at S3.** No spec change; a conformance-ordering note.

---

## S1 exit checklist

- [x] `profile.toml` authored fresh from V8 spec-data + gforth research; every field
      populated; no `TBD` blocking S2 (only publish `registry_url`/`repository_url`
      TBD-on-first-publish, non-blocking as across the cohort).
- [x] `arch/PROFILE-RATIONALE.md` written (one paragraph per major choice).
- [x] `containers/forth-toolchain/Containerfile` authored AND built this session;
      every substrate probe passed at build time.
- [x] This ambiguity log initialized; no blocking-severity items.
- [x] `status/PHASE-S1.md` written.

---

## S4 conformance findings (all operator-RESOLVED code bugs; no spec defects surfaced)

The S4 conformance loop is a code-vs-oracle iteration, not a spec-discovery channel on the
saturated wire surface (A-FT-000). Every finding below is a **CODE bug in the generated peer**,
fixed here (the oracle is never doctored). No spec-vs-oracle divergence surfaced — the spec is
precise; the peer had to catch up to it. The durable, cross-language-relevant ones:

## A-FT-017: S2 codec `emit-head` +1-byte case dropped a stack cell (a real S2 defect)
**V8 section:** §4.2 (CBOR head form).  **Profile field:** n/a.
**Finding:** `emit-head` (`src/cbor.fs`) used `over` instead of `swap` in the "+1 byte" branch
(CBOR argument in [24,255], where the head grows 1→2 bytes). The word's contract is
`( major arg -- )` — it must consume both; the tiny + 2/4/8-byte branches `swap` the precomputed
`major*32`, but the +1 branch `over`'d it, leaving a stray cell. A single top-level map tolerated
it (discarded at word exit); an ARRAY-of-maps whose element crossed the len-24 boundary desynced
the source pointer the array loop carried on the stack → `-9` invalid-memory. **The 69-vector S2
corpus never exercised a ≥24-byte string INSIDE an array of maps**, so it stayed latent until the
53-type registry's `system/capability/token` granter union (`{union_of:[{type_ref:"system/hash"},
{type_ref:"system/capability/multi-granter"}]}`, a 31-char ref) hit it at S4. Fixed `over`→`swap`;
69/69 + int-boundary + crypto-accept still green. **Durable lesson:** a rejection-shaped corpus
can leave an encode path untested; the type-registry render (a big, deeply-nested encode) is a
strong differential fuzz of the codec's own encoder.
**Escalation:** operator — RESOLVED (code fix in the generated codec; the vectors were right).

## A-FT-018: `inc-get` not-found path underflowed (latent until an unresolvable lookup)
**V8 section:** §3.1 (envelope included lookup).  **Profile field:** n/a.
**Finding:** `inc-get` (`src/envelope.fs`) ended with `... loop drop 0` — but the `?do` body
already `drop`ped each non-matching candidate, so on a NOT-FOUND scan the trailing `drop`
underflowed. Every S3 lookup HIT (handshake entities are always present), so it stayed latent
until an S4 authz probe (AUTHZ-GRANTEE-1) presented a cap whose grantee is deliberately
unresolvable → the first not-found `inc-get` → `-4`. Fixed `drop 0`→`0`. **Durable lesson:** a
collection lookup's not-found branch is a distinct code path a happy-path smoke never exercises;
the adversarial-input categories (a deliberately-absent hash) are what flush it.

## A-FT-019: gforth locals-in-loop-body and divergent-branch `{ }` groups are a hazard
**V8 section:** n/a (implementation idiom).  **Profile field:** [error_model] / [layout].
**Finding:** Declaring locals `{ x }` inside a `?do … loop` body, or two separate `{ a } { b }`
groups across divergent `if…else…then` branches, corrupted the gforth locals frame → `-4`/`-9`
under specific inputs (the multisig quorum count, the tree listing, the URI normalizer, the
attenuation subset walk all hit it). **Fix pattern:** extract the loop BODY into its own colon
word (its locals are then per-CALL, not per-iteration) and bind a whole tuple in ONE
stack-order group `{ a b c }` (A-FT-012). This is the single most common S4 defect class on this
substrate. **Durable lesson (Forth family):** never declare locals inside a counted loop; keep
one locals group per word; delegate loop bodies to helpers.

## A-FT-020: URI normalization must NOT strip the first segment of a BARE handler path
**V8 section:** §6.6 (handler resolution) / §1.4 (addressing).  **Profile field:** n/a.
**Finding:** the §6.6 tree-walk resolves handlers registered under bare paths (`system/tree`),
but the validator addresses them as `entity://<peer>/system/tree` OR bare `system/protocol/
connect` (connect is bare). A normalizer that unconditionally drops the first `/`-segment (assuming
a peer prefix) turned `system/protocol/connect` into `protocol/connect` → no handler → the whole
handshake 500'd. **Fix:** only drop the leading peer segment when the URI carried the `entity://`
scheme or a leading `/` (the *addressed* forms); a bare path is already a handler path.
**Escalation:** operator — RESOLVED. (The spec is precise; §1.4 flexible-addressing just needs the
normalizer to respect the bare vs addressed distinction.)

## A-FT-021: §5.6 validity comparisons are direction-sensitive (expiry inversion)
**V8 section:** §5.6 (cap validity window).  **Profile field:** n/a.
**Finding:** a first draft compared `expires_at now-ms >` (= `expires_at > now` → "valid future
expiry" was treated as EXPIRED) — rejecting the multisig accept-path's 5-minute-future cap. The
correct reject predicate is `expires_at < now` (expired) and `not_before > now` (not yet valid).
Trivial once seen, but it fail-CLOSED silently (a 403 that looks like a legitimate denial), so it
took the multisig accept-path (the one check that must ACCEPT) to surface it — corroborating the
keystone lesson that a rejection-only category hides an accept-path bug.
**Escalation:** operator — RESOLVED.

## A-FT-022 (the keystone payoff): genuine 2-of-3 multisig accept-path
**V8 section:** §3.6 (M3) / §5.5 (M4/M6).  **Profile field:** n/a.
**Finding (payoff, not defect):** the `multisig` category is otherwise rejection-shaped (every
malformed cap → 403), which lets a fail-closed peer pass 8/8 without any K-of-N. The oracle's ONE
accept-path vector (`valid_2of3_peer_signed_accepted`, gated on the peer's on-disk keypair via
`crypto.LookupKeypairByPeerID`) forces a genuine implementation: M3 structure (N≥2, K∈[2,N],
distinct signers), M6 (local ∈ signers), M4 (≥K DISTINCT valid signatures over the cap hash from
`included`). Building it flushed A-FT-019 (loop-body locals in the quorum count), A-FT-021 (expiry
inversion), and the arg-order bug in `signer-is-local`. The peer now genuinely counts K-of-N.
This is the accept-path the oracle's rejection vectors can't cover — the keystone value.
**Escalation:** operator — RESOLVED. Multisig 11/11.

## A-FT-023: leaf revocation false-positive was a `created_at:0` token-hash COLLISION (RESOLVED)
**V8 section:** §5.1 (is_revoked) / §2a (handler-set timestamps).  **Profile field:** n/a.
**Finding (RESOLVED — a CODE bug, not a spec issue):** the §5.1 revoked-cap gate (`cap-revoked?`
in capauthz.fs) was DISABLED by the prior S4 agent because it false-positived across the oracle's
single long-lived conformance connection (many caps flagged revoked after one revoke → a −19
cascade). **Root cause isolated this session:** `mint-grant-token`/`mint-seed-token` stamped
`created_at: 0` (a fixed constant), so a `capability:request` child cap whose grantee (= the
authenticated author), granter (= us), and grants (= `grants[:1]` = the seed's own grant) all
coincide with the SEED cap was BYTE-IDENTICAL to the seed → same `content_hash`. The oracle's
revoke probe revokes THAT child (= the seed) → every subsequent request on the connection presents
the seed → flagged revoked → cascade. **Fix:** stamp a real wall-clock `created_at` (`hnd-now-ms`,
§2a) on every minted token (Rexx parity: `Peer_MintToken` stamps `Cap_NowMs()`), so a requested/
delegated child is never hash-identical to the seed. Re-enabled `cap-revoked?` (now checks the leaf
cap hash OR the chain-root hash, Rexx `Cap_IsRevoked` parity); no cascade. `revoked_cap_denied_on_use`
+ `authz_revoked_core_1` now PASS (403 capability_denied). **Durable lesson:** a fixed `created_at`
makes attenuated caps collide; the timestamp is load-bearing content, not cosmetic — it's what
makes each mint a distinct entity. **Escalation:** operator — RESOLVED, re-enabled + fixed.

## A-FT-024: `handlers:register`/`unregister` full protocol implemented (RESOLVED)
**V8 section:** §6.2 / v7.74 §10.1.  **Profile field:** [layout].
**Finding (RESOLVED — feature built):** the core-gated `core_register_*` checks (8) drive the full
§6.2 five-write `system/handler:register` protocol + `unregister` teardown symmetry, previously
stubbed 501. Implemented (Rexx `_handlers_register`/`_handlers_unregister` parity): (1) the
`system/handler {interface, expression_path?}` dispatch entity at `<pattern>`; (2) associated
`system/type` entities at `system/type/<name>` (from `register-request.types`); (3) the handler
grant token at `system/capability/grants/<pattern>` (grantee=us, grants=requested_scope|
internal_scope); (4) the §3.5 grant signature at `system/signature/<hex(grant_hash)>`; (5) the
`system/handler/interface {name, operations, pattern}` at `system/handler/<pattern>`. Result =
`system/handler/register-result {grant, pattern}`; unregister reverses all five (removing the
signature via the grant's current hash). **Key detail:** register-request `manifest`/`types`/
`requested_scope` are INLINE CBOR maps/arrays (`cbor:"manifest"`), NOT nested `{type,data,hash}`
wire entities — read them with raw-map accessors (`mtv-text`/`mtv-field`), never `ent<-wire`
(which threw E-MISSING-TYPE → 500). Also published the §6.2 N2 dispatch entities at
`/<peer>/<pattern>` for the core handlers (connect/tree/capability) so `handler_*_dispatch_type`/
`_interface_ref` resolve (`publish-handler-dispatch`). All 8 `core_register_*` + the 6 dispatch
skips now PASS. **Escalation:** operator — RESOLVED.

## A-FT-025 (the concurrency payoff): reentry demux cross-talk was a missing `pend-new` return (RESOLVED)
**V8 section:** §6.11(b) (request_id demux, no cross-talk on a multiplexed connection).  **Profile field:** n/a.
**Finding (RESOLVED — a latent S3 CODE bug the concurrent-reentry check flushed):** `t1_2_concurrent_reentry`
(8 concurrent dispatch-outbound EXECUTEs multiplexed on ONE connection) reported every downstream
`result.value` as the SAME value (all replies correlated to `o1`). EC_TRACE showed all 8 outbounds
sent DISTINCT correct values + parked under distinct request_ids `o1..o8`, but every
`dispatch-outbound` awaited pending-table slot **0** → all read `o1`'s reply. Root cause: `pend-new`
(dispatch.fs) computed the new slot index `i`, stored it, bumped `pend-count`, but **never left `i`
on the stack** — its `( … -- idx )` contract was unmet, so the caller `{ idx }` bound a stale-stack
`0`. Latent at S3 because a SINGLE reentry's stale value happened to be 0 (the correct first slot);
only CONCURRENT reentry (distinct non-zero slots) exposed it. **Fix:** `pend-new` ends with `i`.
t1_2 now PASSES. **Two supporting robustness fixes the concurrency category also forced:**
(a) `tv-node-len` (cbor.fs) grew a §4.9 recursion depth-cap + child-count sanity cap so a walk that
lands on a garbage address (from any state-corruption or hostile frame) THROWs-and-recovers instead
of overflowing the data stack; (b) the §6.11 reentry pump recurses on a single-thread substrate, so
the peer runs with enlarged gforth stacks (`-d/-r/-l`, run-s4.sh) — the correlation-map/reentry tax
the non-actor peers pay, made explicit. The 1 MiB arena was also raised to 8 MiB (off the OS heap,
not the dictionary) so a 256-KiB tree.put (t1_3's slow entity) decodes without arena overflow →
`t1_3_no_head_of_line`, `t2_1_sustained_load`, `t2_2_connection_churn` all PASS. **Durable lesson:**
a stack-effect contract that "happens to work" for the degenerate (single, index-0) case is a latent
concurrency bug; a concurrent-reentry vector is exactly the differential that flushes it — the
keystone payoff. **Escalation:** operator — RESOLVED.

## A-FT-026: §5.2 resource-scope + §5.7 delegation caveats were unenforced (RESOLVED)
**V8 section:** §5.2 (permission scope) / §5.4 (§PR-8 granter frame) / §5.7 (delegation caveats).
**Profile field:** n/a.
**Finding (RESOLVED):** `check-permission` verified operation + handler scope but IGNORED the
resource dimension, and the chain walk ignored a parent's `delegation_caveats`. Surfaced when the
seed grant gained the §9.0 open-grants `resources:[*, /*/*]` (needed for `universal_address_space`'s
foreign-namespace probe) — with resources unchecked, `authz_deny_default_1`,
`security.resource_scope_denied`, `security.captok_form_dispatch_minted_pl_presented_xpeer`,
`security.chain_no_delegation_denied`, and `security.chain_max_delegation_ttl_denied` all wrongly
ACCEPTED (200) requests that MUST 403. **Fix (Rexx `Cap_CheckResourceScope`/`_check_delegation_caveats`
parity):** `grant-covers-resource?` canonicalizes each `exec.resource.targets[i]` and checks it is
covered by the grant's `resources` include (framed by the §PR-8 granter peer) and not excluded; a
peer-local `*` (→ `/<granter>/*`) therefore does NOT cover a cross-peer `/<other>/…` target
(`captok_…_xpeer` denies), and an out-of-scope path denies (`authz_deny_default`). `caveats-ok?`
honors `no_delegation` / `max_delegation_depth` / `max_delegation_ttl` on each parent link. Also
the `request`/`delegate` handler now enforces mint-attenuation (`req-grants-bounded?` — each
requested grant ⊆ the presented cap's grants), so a narrow cap asking to WIDEN is refused 403
`scope_exceeds_authority` (`request_rejects_scope_widening` — the accept-path keystone value the
rejection-only vectors can't cover). **Escalation:** operator — RESOLVED.

## A-FT-027: §1.4 path-flex — NUL byte + leading-slash-non-peer-id rejection (RESOLVED)
**V8 section:** §1.4 (path validity).  **Profile field:** n/a.
**Finding (RESOLVED):** `path-flex-ok?` rejected empty/./.. segments but ACCEPTED a NUL byte and
accepted a leading `/` unconditionally. `core_tree_path_flex_1` requires rejecting
`system/validate/core-tree/path-flex/with\x00null` (NUL) and `/system/validate/…/bad` (a leading
`/` whose first segment is NOT a valid peer_id — an absolute path's first segment MUST be a
Base58 peer_id ≥46 chars, Rexx `Hnd_PathFlexOk`/`Cap_IsPeerId` parity). Added `has-nul?` +
`seg-is-peerid?`. Also the tree get with an EMPTY resource target (`{targets:[""]}`, the listing
form) now lists the peer root instead of 400-ing `invalid_path` (`path_root_listing`).
**Escalation:** operator — RESOLVED.

## A-FT-028: §4.10(c) admission — conn table sized for the r3 flood (RESOLVED)
**V8 section:** §4.10(c) (admission bound).  **Profile field:** [async].
**Finding (RESOLVED):** the 64-slot connection table let the `resource_bounds.r3` flood (256
concurrent connects) fill every slot, so the post-flood keep-serving probe could not get a slot →
the peer "fell over" (§4.10(c) FAIL shape) instead of accepting-all-and-keeping-serving (the
spec-allowed WARN). Raised MAX-CONNS to 320 (256 flood + headroom; select()'s static fd_set holds
1024). r3 now WARNs (Rexx parity). **Escalation:** operator — RESOLVED.
