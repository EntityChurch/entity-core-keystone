# entity-core-protocol-fortran — Spec / Profile Ambiguity Log

Peer #25. Every non-obvious S1 guess is recorded here in the required format. None
of these are **blocking** for S2 (each has a resolved best-guess). Items tagged
`arch` / `research` are escalation candidates; `operator` items are local decisions.

---

## A-FTN-001: Fortran 2023 UNSIGNED type exists (gfortran 15) but is declined

**V8 section:** absent (substrate fact; relates to ENTITY-CBOR-ENCODING §2 integer tower)
**Profile field:** `[numeric] unsigned_type_declined`, `[idiom] no_portable_unsigned`
**Your guess:** Represent the uint64 tower `[2^63, 2^64-1]` as a 64-bit BIT PATTERN in a
signed `integer(int64)` carrier; do NOT use `-funsigned` / the Fortran 2023 `UNSIGNED`
type.
**Rationale:** The task framing ("Fortran has no unsigned integer at all") is slightly
outdated — Fortran 2023 adds `UNSIGNED`, and gfortran 15 implements it under `-funsigned`
with `uint64` in `ISO_FORTRAN_ENV` (J3/24-116). But it is experimental, flag-gated, and
the unsigned type cannot index arrays or be a `DO` variable and needs explicit conversion
for mixed arithmetic — hostile to a codec, and non-portable across other/older compilers.
The signed bit-carrier is portable, keeps the fixed-width-signed probe pure, and is the
honest representation of the substrate the peer-selection compass wanted to stress.
**Escalation:** operator — local decision (recorded so S2 doesn't re-open it). A minor
finding for arch: the spec forces even a nominally-unsigned-capable substrate to carry
the uint tower as an explicit bit pattern.

## A-FTN-002: uint64 boundary via signed carrier — byte-emit + compare discipline

**V8 section:** ENTITY-CBOR-ENCODING §2 (integer encoding), Rule 1 (minimal int head)
**Profile field:** `[numeric] uint64_byte_emit`, `uint64_compare`, `head_form_selftest`
**Your guess:** Byte emission of a uint uses sign-agnostic bit extraction
`iand(ishft(v, -8*k), 255_int64)`, never signed arithmetic. Unsigned comparison (needed
for the minimal-head decision and any range check) uses a bias trick
(`ieor(v, min_int64)` compared as biased) or top-byte-first comparison — never a bare
signed `<` on the carrier. A mandatory head-form self-test round-trips every value in
`{0, 2^63-1, 2^63, 2^64-2, 2^64-1}` byte-exact.
**Rationale:** A value in `[2^63, 2^64-1]` stored in signed `integer(int64)` is negative;
signed comparison and signed shifts would corrupt the head-form/minimal-int decision. Bit
intrinsics operate on the pattern regardless of sign, so the octets come out correct. The
self-test is the AGENTS.md durable "carry the head form + self-test `[2^63, 2^64-1]`"
requirement for fixed-width-int languages.
**Escalation:** operator — local decision (implementation discipline, spec is clear).

## A-FTN-003: no native sum type — tagged-union derived type carries major-type intent

**V8 section:** ENTITY-CBOR-ENCODING §1–§2 (major types); §5 (type checking int-vs-float)
**Profile field:** `[naming] aggregate_unit`, `[idiom] tagged_union_value`, `byte_vs_text_explicit`
**Your guess:** The value model is a derived type `ecf_value_t` with an integer
major-type discriminant that carries int-vs-float (mt0/1 vs mt7) AND byte-vs-text (mt2 vs
mt3) intent explicitly; the encoder never infers the CBOR major type from the Fortran
storage kind.
**Rationale:** Fortran has no native sum/union type. The spec (§5) requires strict
int-vs-float major-type discrimination and (§1) distinct byte/text majors; the storage
kind (`integer(int64)` / `real(real64)` / `character` / `integer(int8)` array) does not
uniquely determine the intended major type (e.g. a text vs byte string are both byte
sequences). Carrying intent explicitly is the same resolution Tcl/Rexx reached for their
untyped values, here forced by the absence of sum types rather than by EIAS.
**Escalation:** operator — local decision (idiom, spec is unambiguous).

## A-FTN-004: integer(int8) byte buffers are SIGNED — mask when treating as octet

**V8 section:** ENTITY-CBOR-ENCODING (byte-string mt2, wire octets)
**Profile field:** `[numeric] byte_buffer`, `[idiom] signed_byte_trap`
**Your guess:** CBOR byte buffers are `integer(int8), allocatable(:)`; when a byte is used
as an unsigned octet value (0..255) the codec masks `iand(b, 255)`; when emitting, values
128..255 are stored as their signed int8 image.
**Rationale:** `integer(int8)` is signed (-128..127), so octet 0xFF reads as -1 — the
classic Fortran/C signed-char-on-the-wire trap. Masking to the 0..255 range at every
octet-value use avoids sign contamination in length/head arithmetic. (Default-kind
`character` is an alternative byte carrier; int8 arrays are chosen for uniform bit ops.)
**Escalation:** operator — local decision (implementation discipline).

## A-FTN-005: transfer() is native-endian — explicit big-endian byte-swap on every head

**V8 section:** ENTITY-CBOR-ENCODING §2 (network byte order), §3 (float heads F9/FA/FB)
**Profile field:** `[numeric] float_bits_path`, `endianness`, `float16_handling`
**Your guess:** `transfer(x, 0_int64/0_int32)` reads f64/f32 bits in NATIVE endianness;
the codec byte-swaps to big-endian (network order) explicitly on every integer and float
head. f16 (binary16) has no guaranteed native real kind, so its bits are hand-rolled
(sign / biased-exp / 10-bit mantissa) and the shortest-float ladder (Rule 4: does the
value round-trip through f16 then f32 exactly?) is hand-decided.
**Rationale:** ECF is big-endian; gfortran on x86-64 is little-endian, so `transfer`
output must be reversed. f16 lacks a portable native kind, so it cannot rely on
`transfer` and is computed. The shortest ladder is spec policy (Rule 4), hand-rolled in
every peer regardless of float support.
**Escalation:** operator — local decision (implementation discipline, spec is clear).

## A-FTN-006: base58 rides the C-ABI (no Fortran bignum)

**V8 section:** ENTITY-CORE-PROTOCOL §4.2 / §1.5 (peer-id base58 canonical form)
**Profile field:** `[codec] base58_library`
**Your guess:** peer-id base58 encode/decode rides `ec_peerid_{parse,format}` over the
C-ABI rather than a hand-rolled Fortran base58.
**Rationale:** base58 is base-256 → base-58 long division, which needs arbitrary-precision
integer arithmetic. Fortran has NO bignum type. Byte-array schoolbook long-division is
possible but error-prone; a clean C-ABI primitive exists and COBOL made the same choice.
Keeps the peer-id path byte-exact against the oracle without a bignum hand-roll. (varint
LEB128 format codes stay native — they are 1-byte and trivial.)
**Escalation:** operator — local decision (mirrors COBOL A-CBL pattern).

## A-FTN-007: absent sentinel is a discriminant flag, not an empty string

**V8 section:** absent (data-model convention; empty byte/text string is a valid value)
**Profile field:** `[error_model] absent_sentinel`
**Your guess:** "absent"/"not found" is a `present = .false.` discriminant in the value
derived type, NOT an empty `character`/`int8` array.
**Rationale:** The empty byte string (mt2 len 0) and empty text string (mt3 len 0) are
legitimate wire values, so an empty buffer cannot double as the absent sentinel — the
same empty-string-is-a-value trap Tcl/Rexx flagged, resolved here with a boolean
discriminant on the tagged value.
**Escalation:** operator — local decision.

## A-FTN-008: build = gfortran + make (fpm not in fedora dnf); fpm.toml shipped

**V8 section:** absent (build/packaging)
**Profile field:** `[build] build_tool`, `fpm_manifest`, `[deps] fpm`
**Your guess:** The container build is `gfortran + make`; an `fpm.toml` is shipped as the
idiomatic manifest for fpm users but fpm is NOT installed in the toolchain image.
**Rationale:** fpm (0.12.0, 2025-05-18) is the modern idiomatic Fortran build+package
tool, but it is not in fedora:43 dnf (snap/conda-forge/pypi/binary-download only). Pulling
it into the container adds network/supply-chain friction against the "system toolchains,
minimal dependencies" standard. make is self-contained and handles module dependency
order; the fpm.toml keeps the peer idiomatic + fpm-installable for downstream users.
**Escalation:** operator — local decision.

## A-FTN-009: test-drive vendored (not fpm-fetched)

**V8 section:** absent (test tooling)
**Profile field:** `[testing] framework`, `framework_version`
**Your guess:** Unit tests use test-drive 0.6.1 vendored as the single redistributable
`testdrive.F90`; the conformance corpus walk is a hand-rolled driver structured with
test-drive asserts.
**Rationale:** test-drive is the dominant fortran-lang community framework, pure standard
Fortran, explicitly redistributable as one file. Unlike COBOL/Rexx (no framework →
hand-rolled), Fortran has a real standard, so the profile follows research and uses it
(the Tcl/tcltest reasoning); vendoring keeps the make/gfortran container self-contained
(no fpm fetch). Release 2025-06-13 is S11-clean (>30 days old at 2026-07-11).
**Escalation:** operator — local decision.

---

# S2 additions (codec layer, 2026-07-11)

## A-FTN-010: test-drive not yet vendored offline — S2 unit suite is plain-Fortran

**V8 section:** absent (test tooling)
**Profile field:** `[testing] framework` = "test-drive" (A-FTN-009)
**Your guess:** The S2 unit suite (`test/unit_tests.f90`) is written as plain-Fortran
assertions (a `check(cond,name)` helper + `stop 1` on failure), NOT yet structured with
test-drive. The conformance corpus driver (`test/conformance.f90`) is hand-rolled as the
profile always intended.
**Rationale:** the container runs `--network=none` and `testdrive.F90` is not yet in the
tree, so it cannot be fetched at S2. The profile's intent (a real framework) is honored
by vendoring the single redistributable `testdrive.F90` when it can be brought in offline
(a source drop, not a build-time fetch) and re-expressing these same assertions in it —
an S3 hygiene task. The assertions themselves already give a covering test for each of
N1–N4 + the accept-path directions, which is the substance; the framing is cosmetic.
**Escalation:** operator — local decision (deferred vendoring; no coverage lost).

## A-FTN-011: recursive value model uses a POINTER component, not allocatable

**V8 section:** absent (Fortran codegen substrate fact)
**Profile field:** `[naming] aggregate_unit` (the tagged-union derived type)
**Your guess:** `ecf_value_t`'s self-referential `items(:)` aggregate is a `pointer`
component (default `=> null()`), NOT `allocatable`. The decoded tree is arena-like: never
explicitly freed, reclaimed at process exit (the codec is one-shot per message; S3's store
owns lifetime). Byte payloads stay `allocatable` (not self-referential → safe).
**Rationale:** gfortran 15.2's compiler-generated RECURSIVE auto-deallocator for a derived
type with an ALLOCATABLE component of its OWN type DOUBLE-FREES on deep/aliased nesting —
reproduced deterministically decoding the corpus (SIGABRT `free(): double free detected`,
backtrace in `__deallocate_..Ecf_value_t` recursing into itself). A pointer component is
never auto-deallocated and never followed by a dtor, so the bug cannot fire. This is a
real fixed-substrate lesson: the "obvious" recursive-allocatable value model is a gfortran
landmine; the pointer/arena model is the robust idiom (and aligns with the profile's
`[async] store_model` "module-level allocatable arrays in the one image").
**Escalation:** research — a durable cross-language lesson for any future gfortran-family
peer (banked here so S3/S4 don't rediscover it); NOT a spec issue.

## A-FTN-012: corpus tag_reject.1/2/3/5 do not contain the tags their descriptions claim (FINDING)

**V8 section:** ENTITY-CBOR-ENCODING §6.3 (tag rejection, N2); the ECF conformance corpus
`conformance-vectors-v1.cbor` (v0.8.0, SHA-256 `41d68d2d…`, pin verified at S2 entry)
**Profile field:** absent (test-vector coverage)
**Your guess / finding:** The `.cbor` bytes for `tag_reject.1/2/3/5` do NOT contain a
CBOR major-type-6 (tag) item anywhere — contrary to their `.diag` descriptions ("tag 0
datetime", "tag 1 epoch ts", "tag 37 UUID", "tag 0 nested in included"). Decoded, each is
a leading `{type:"test/v1", data:"1"}` (the intended `a1` map byte reads as `61` text-1)
followed by 8–40 bytes of TRAILING garbage. A conforming decoder therefore rejects them
via the **full-consumption / trailing-data** rule (confirmed in the reference C codec:
`ecf.c:471 if (r.pos != len) return NULL; /* trailing bytes */`), **NOT** via the §6.3
tag scanner. Only `tag_reject.4` (`d9d9f7a0`, tag 55799) actually exercises N2. So a
decoder that rejects trailing data but has NO tag scanner still passes 5/5 tag_reject
vectors — the "conformance-green can be vacuous" trap. Our decoder implements BOTH (the
recursive mt6 reject AND full-consumption), and `test/unit_tests.f90 t_n2_tag_reject`
adds the REAL nested-tag coverage the corpus lacks (tag 0 top-level, tag 55799, tag
nested in a map value — all rejected).
**Escalation:** arch — the ECF conformance corpus's `decode_reject` tag vectors 1/2/3/5
appear byte-defective (same class as the F16 agility-corpus regen: `.diag`↔`.cbor`
inconsistency). They should be regenerated to actually carry the described tags so N2 is
corpus-covered, not only unit-covered. (A `HANDOFF-TO-ARCH-*` candidate for
`research/stewardship/`.) Does not block S2: the vectors still MUST-reject and our peer
rejects all five.

## A-FTN-013: built response-value `items(:)` heap-allocated, not arena — leaks per dispatch (S4 hardening)

**V8 section:** §4.9 (resilience under sustained load)
**Profile field:** `[async]` store_model / memory discipline
**Your guess / finding:** The A-FTN-011 pointer-based `ecf_value_t%items(:)` forced by the
gfortran recursive-dtor bug means every RESPONSE value the peer BUILDS (map/array builders
in `val.f90`) heap-allocates a fresh `items` array that is never freed — the decoded tree
is arena-like (reclaimed at process exit), but the build side leaks one value tree per
inbound dispatch. For the S3 gate and a bounded validate-peer run this is well within the
4 GiB cap; under a §4.9 SUSTAINED flood (concurrency T2.1 streams ~10k requests) it grows
unbounded. **S3 default:** heap-allocate + document (the smoke + selftest are short). S4
hardening path: a bump-arena of `ecf_value_t` nodes reset at the top of each top-level
frame dispatch (built values encode to bytes BEFORE reset; decoded heap trees are
unaffected). Deferred to S4 because the reentry (§6.11) case shares the arena across an
outstanding dispatch and needs care.
**Escalation:** research — a durable cross-peer note for the gfortran/Fortran family (any
pointer-items value model has this shape); an S4 implementation item, not a spec gap.
**S4 RESOLUTION (2026-07-11): no arena needed — measured within cap.** The `concurrency`
gate ran the full §4.9 sustained flood live: `t2_1` streamed **C=16 × K=10000 = 160 000**
tree.gets (plus `t1_2`'s 8 nested reentrant dispatch-outbounds and `t2_2`'s 100
connect/churn cycles) at the committed **4 GiB `PODMAN_RUN_CAPS`** ceiling — **PASS, zero
drops, p50 stable, no OOM-kill.** The build-side leak's constant factor is small enough that
160k dispatches stay well under 4 GiB, so the bump-arena is **not** required for the core
gate and was NOT implemented (keeping the reentry-shared-arena hazard off the table). Left
as a documented durable note: a much longer-lived production peer would still want the arena.
Status: **deferred hardening, not a gate blocker** (confirmed by measurement, not asserted).

## A-FTN-014: §4.10 413 payload_too_large carries an EMPTY request_id (body never buffered)

**V8 section:** §4.10(a) (finite max inbound payload)
**Profile field:** absent (transport floor)
**Your guess / finding:** The §4.10(a) MUST is "reject over-limit with 413 BEFORE buffering
the body (check the length prefix)". But the request_id lives INSIDE the body that is, by
construction, never read — so the 413 EXECUTE_RESPONSE the peer emits carries an EMPTY
`request_id` (`send_413` in peer.f90). The net-shim signals `EC_EV_OVERSIZE` on a length
prefix > 16 MiB, having drained (not buffered) the body and KEPT the connection; the
Fortran side answers 413 and keeps serving. This matches the floor's intent (bound the
resource, deliver-or-signal, never silently drop) and the cohort's keep-serving behavior;
the only wrinkle is that the reply cannot correlate by request_id (there was none to read).
**Your guess:** emit 413 with `request_id=""`; keep serving. Flag for S4 to confirm the
`resource_bounds` oracle checks the status code (not request_id correlation) on the
oversize probe.
**Escalation:** arch — confirm the §4.10(a) reply's request_id expectation when the body is
unbuffered (a correlation-vs-status question the resource_bounds category settles); local
default is empty request_id.
**S4 RESOLUTION (2026-07-11): confirmed status-only.** `resource_bounds.r1_payload_over_limit`
**PASS** against oracle cc1970f — the probe wrote a 16778240-byte length prefix and checks
for **413 `payload_too_large` + keep-serving**, NOT request_id correlation. The empty
request_id is accepted. No arch action needed; closing as confirmed-conformant.

## A-FTN-015: gfortran `.and.`/`.or.` do NOT short-circuit — guard every `i<=n .and. s(i:i)` (durable lesson)

**V8 section:** absent (language)
**Profile field:** absent
**Your guess / finding:** Fortran's `.and.`/`.or.` are NOT guaranteed to short-circuit (the
standard leaves operand evaluation order/extent unspecified), and gfortran with
`-fcheck=bounds` evaluates BOTH operands — so the idiomatic `do while (i <= n .and.
s(i:i) /= ' ')` reads `s(i:i)` at `i = n+1` and aborts with "Substring out of bounds". Every
bounds-guarded substring/array access must be a NESTED conditional, not a compound `.and.`:
`if (i <= n) then; if (s(i:i) == ...) ...`. Fixed across `val.f90` (word splitters),
`capability.f90` (`starts_with`/`ends_with`), and `peer.f90` (`path_flex_ok`, the nonce
`all()` compare). A durable trap for any Fortran-family peer (surfaced at S3 runtime, not
compile time — the compiler accepts it).
**Escalation:** research — a Fortran-family durable lesson (belongs beside the A-FTN-011
gfortran dtor note); not a spec gap.

## A-FTN-016: unhandled SIGPIPE silently terminated the peer under connection churn (S4 crash, durable lesson)

**V8 section:** §4.9 (deliver-or-signal; a broken socket must surface, not kill the process)
**Profile field:** absent (transport substrate)
**Your guess / finding:** The C net-shim wrote responses with `write(2)` and never installed
a SIGPIPE disposition. When a conformance probe closed its socket mid-exchange (the
`concurrency` reentry `t1_2` and churn `t2_2` legs both do), the peer's next `write()` to the
half-closed socket raised **SIGPIPE**, whose default action **terminates the process** — with
NO stderr output. Symptom at S4: the whole run cascaded to `connection refused` after the
first churn/reentry category, because the listener process was gone. **Fix:** `signal(SIGPIPE,
SIG_IGN)` at listen init + switch the flush write to `send(..., MSG_NOSIGNAL)` so a broken
pipe surfaces as `EPIPE` (retry-next-writable / drop-on-close) instead of a signal. A
long-running TCP server in C (or any FFI net-shim) MUST neutralize SIGPIPE — the classic
"server dies silently under load" trap.
**Escalation:** research — durable cross-peer lesson for every raw-socket / FFI-net-shim peer
(the compiled cohort: cobol, zig, …); not a spec gap.

## A-FTN-017: persistent serve loop must not treat EV_NONE (EINTR/spurious poll) as a stop

**V8 section:** §4.9 (the serve loop is the peer's liveness)
**Profile field:** `[async]` = single-thread-select
**Your guess / finding:** `peer_serve` had `case default; exit` for a poll result that wasn't
ACCEPT/FRAME/CLOSED/OVERSIZE, on the theory that `EV_NONE` "with no fds" means a clean stop.
But with a blocking (`timeout = -1`) poll, `EV_NONE` also arises from an interrupted
`select()` (`EINTR`) — and the listener fd is never closed while serving — so an `EV_NONE`
must simply **re-poll**, never terminate the listener. Changed the default arm to `cycle`.
Belt-and-suspenders alongside A-FTN-016: even with SIGPIPE handled, a spurious wakeup must
not drop the server. **Durable rule:** a persistent single-thread select-pump exits only on
explicit shutdown, never on an empty poll.
**Escalation:** research — durable substrate lesson for single-thread-select peers; not a spec gap.

## A-FTN-018: §6.13(b) dispatch-outbound reentry — wired live at S4 (was an S3 stub)

**V8 section:** §6.11 transport reentry + §6.13(b) handler-initiated outbound dispatch; §7a.2a
**Profile field:** `[async]` single-thread-select (the §6.11 correlation-map "tax")
**Your guess / finding:** S3 shipped `hnd_dispatch_outbound` as an honest `503 no_outbound_seam`
stub (the reentry primitives `sess_send`/`pump_until` existed but weren't wired to the
handler). The `--validate`-gated `concurrency.t1_2_concurrent_reentry` core probe exercises it
(NOT origination — that's the separate reference-peer-gated category), so the stub was a real
CORE-gate FAIL, not a skip. S4 wired it: the handler reads `{target, operation, value,
reentry_capability, reentry_granter, reentry_cap_signature}` from params, builds+signs an
outbound EXECUTE to `system/handler/{target}` (author = local id, cap = reentry cap), sends it
on the **same inbound connection** (`c_io(slot)`), and **reentrant-pumps** the single serve
loop (`pump_until`) until the reply correlates by request_id — returning `{status, result}`.
Nested reentry (8 concurrent) recurses safely on the one pump because each level awaits its own
unique `out-N` rid in the per-connection pending table. **Result: t1_2 PASS.** The §6.11
contract is satisfied structurally by the single-thread pump (no per-connection serialization
lock to deadlock on). Mirrors the rexx peer's `Peer_OutboundDispatch` shape.
**Escalation:** none — this is the §6.13(b) behavioral-presence MUST implemented from spec;
the params shape is the §7a validate-handler test-scaffolding contract (GUIDE-CONFORMANCE), a
legitimate byte-exact target per the keystone's type-registry-shapes carve-out.

---

# S5 finalization (2026-07-11) — every item owner-tagged + escalation state

Closing sweep at packaging (PHASE-S5). No item is **blocking**; every one carries a resolved
best-guess or a measured resolution. Final disposition of all 18 entries:

| ID | Escalation owner | State at S5 |
|---|---|---|
| A-FTN-001 | operator (+ minor arch note) | Closed — signed bit-carrier chosen; Fortran-2023 `UNSIGNED` declined. The "even a nominally-unsigned-capable substrate must carry the uint tower as an explicit bit pattern" note stands as a small arch observation, folded into A-FTN-012's handoff context. |
| A-FTN-002 | operator | Closed — head-form self-test `{0, 2⁶³−1, 2⁶³, 2⁶⁴−2, 2⁶⁴−1}` byte-exact (S2 69/69). |
| A-FTN-003 | operator | Closed — tagged-union `ecf_value_t` discriminant; int-vs-float + byte-vs-text explicit. |
| A-FTN-004 | operator | Closed — `iand(b,255)` octet mask discipline. |
| A-FTN-005 | operator | Closed — explicit big-endian byte-swap on every head; f16 + shortest ladder hand-rolled. |
| A-FTN-006 | operator | Closed — base58 rides `ec_peerid_{parse,format}` (no Fortran bignum). |
| A-FTN-007 | operator | Closed — `present=.false.` discriminant, not empty string. |
| A-FTN-008 | operator | Closed — `make` is the container build; `fpm.toml` shipped for fpm users (S5 artifact). |
| A-FTN-009 | operator | Open-cosmetic — test-drive is the intended framework; vendoring `testdrive.F90` offline deferred (see A-FTN-010). No coverage lost. |
| A-FTN-010 | operator | Open-cosmetic — S2/S4 unit suite is plain-Fortran assertions; re-expressing in vendored test-drive is deferred hygiene, no coverage impact. |
| A-FTN-011 | research | Closed (durable lesson) — pointer-component value model avoids the gfortran recursive-dtor double-free. Banked for the Fortran family. |
| **A-FTN-012** | **arch** | **ESCALATED — `research/stewardship/HANDOFF-TO-ARCH-2026-07-11-ftn-tag-reject-corpus.md` + SPEC-FINDINGS-LOG F30** (F29 at authoring; renumbered at the 2026-07-12 two-branch merge). Corpus `tag_reject.1/2/3/5` reject via trailing-data, not the §6.3 tag scanner; only `.4` exercises N2. Real N2 coverage added in `test/unit_tests.f90`; does not block the gate. |
| A-FTN-013 | research | Closed — measured within the 4 GiB cap under the §4.9 flood (160k gets); bump-arena is documented deferred hardening, not a gate blocker. |
| A-FTN-014 | arch | Closed — confirmed status-only: `resource_bounds.r1` checks 413 + keep-serving, not request_id correlation. No arch action needed. |
| A-FTN-015 | research | Closed (durable lesson) — gfortran `.and.`/`.or.` non-short-circuit; nested-conditional guard discipline. |
| A-FTN-016 | research | Closed (durable lesson) — SIGPIPE `SIG_IGN` + `MSG_NOSIGNAL` in the net-shim; every raw-socket/FFI-net-shim peer MUST neutralize SIGPIPE. |
| A-FTN-017 | research | Closed (durable lesson) — single-thread select-pump re-polls on `EV_NONE`, never terminates on an empty poll. |
| A-FTN-018 | none | Closed — §6.13(b) dispatch-outbound reentry wired live (`concurrency.t1_2` PASS). |

**Arch-routed at S5:** A-FTN-012 (corpus defect → F30, F29 at authoring; renumbered at the 2026-07-12 merge). **Research-banked durable lessons
(no arch action):** A-FTN-011 / A-FTN-015 / A-FTN-016 / A-FTN-017 (gfortran/Fortran-family +
raw-socket traps). **All other items are operator-local, resolved.** No spec-vs-oracle
divergence surfaced at S4 (every S4 fix was a peer bug derived from the spec).
