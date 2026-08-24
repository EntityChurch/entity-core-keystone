# entity-core-protocol-apl — Spec / Profile Ambiguity Log

Format per PROMPT-CONSTANTS. Every S1 guess is logged here. **No blocking-severity
items** — all are operator-level local decisions or research-level profile fields with
resolved best-guesses. `A-APL-NNN`.

Escalation legend: `arch` = spec needs clarification · `research` = profile/landscape
needs a field · `operator` = local build decision.

---

## A-APL-001: Interpreter selection — GNU APL (not J / Dyalog / dzaima / kap)

**V8 section:** absent (toolchain choice)
**Profile field:** `[language].interpreter`
**Your guess:** **GNU APL 1.9**, built from the SHA-256-pinned GNU source tarball.
**Rationale:** The decision hinges on (a) Free + reproducibly installable in the
fedora:43 container, (b) a working C-ABI FFI path, (c) numeric width. **No** APL-family
interpreter is in the fedora:43 dnf repos (fedora + updates — verified 2026-07-12: `dnf
list apl / apl* / gnu-apl / provides */bin/apl` all empty; J and Dyalog likewise absent).
So every candidate needs a source build or a bindist fetch (the GHC precedent). Runners-up
declined: **Dyalog APL** — proprietary, cannot ship in an Apache-2.0 keystone container
(licensing) → excluded outright. **J (ijconsole)** — best FFI (`cd`/`15!:0` direct C call)
and native extended-precision integers, BUT not in dnf and distributed as an external
binary bindist / finicky jsource build → more supply-chain friction than GNU APL's clean
GNU autotools source build; and J is an APL-*family* ASCII dialect, not APL proper.
**dzaima/APL** (JVM) / **kap** (JVM) — pull in a whole JVM, heavier + less canonical.
GNU APL wins: it is THE GNU-project free APL (ISO/IEC 13751), builds cleanly from a pinned
GNU source tarball with only dnf deps (gcc-c++/make/readline-devel — verified: configures
+ `make -j` + installs + runs on fedora:43/GCC 15), has a native-function (⎕FX) C++ FFI
path (verified — see A below), and provides **native Berkeley sockets via ⎕FIO** (no C
net-shim needed). Its signed-int64 numeric ceiling is the honest array-model corroboration
of the Fortran finding.
**Escalation:** operator — local toolchain decision (recorded for audit).

## A-APL-002: uint64 tower [2^63, 2^64-1] carried as an OCTET ARRAY, never a scalar

**V8 section:** ENTITY-CBOR-ENCODING §mt0 (unsigned integer head); N-invariants
**Profile field:** `[numeric].uint64_representation`, `[codec].cbor_library`
**Your guess:** Represent CBOR unsigned integers whose magnitude ≥ 2^63 as an 8-element
big-endian OCTET VECTOR (int64 cells 0..255), assembled/consumed by array ops that never
form the >2^63 scalar (no `256⊥` into a scalar); `256⊤` used only for values provably
< 2^63. Mandatory head-form self-test on `{0, 2^63-1, 2^63, 2^64-2, 2^64-1}`.
**Rationale:** GNU APL's exact integer is signed int64 (ceiling 2^63-1); at/above 2^63 it
promotes to lossy IEEE double (A-APL-003). The array IS the fixed-width carrier — the
natural array-model expression of the "integer head-form is a fixed-width artifact, not a
protocol property" durable lesson.
**Escalation:** research — profile field recorded; the self-test is the guard.

## A-APL-003: silent int64 → IEEE-double promotion at 2^63 (verified in-container)

**V8 section:** absent (substrate property)
**Profile field:** `[numeric].overflow_behavior`, `[idiom].silent_double_promotion`
**Your guess:** Treat 2^63 as a hard exactness boundary; never rely on APL scalar
arithmetic for values ≥ 2^63. Verified in the apl-toolchain probe: `2*62` prints
`4611686018427387904` (exact int64); `(2*63)-1` prints `9.223372037E18` (float form) — the
overflow escapes to double with NO error. Sharper than Fortran, whose signed int64 at
least holds the 64-bit pattern in a controllable carrier.
**Escalation:** operator — recorded; drives the octet-array carrier (A-APL-002).

## A-APL-004: apl-2.0 declined (too new) → pin 1.9 (S11 supply-chain cool-down)

**V8 section:** absent (S11 pin discipline)
**Profile field:** `[deps].gnu_apl`
**Your guess:** Pin **GNU APL 1.9** (2024-06-29, ~24 months old). apl-2.0 EXISTS
(2026-06-24) but is only ~18 days old at authoring (2026-07-12) → violates the S11 ≥30-day
floor. 1.9 is S11-clean AND builds clean on GCC 15 (verified).
**Rationale:** the supply-chain cool-down is non-negotiable; 1.9 is the newest compliant
release. Re-evaluate 2.0 on the next rebuild once it clears 30 days.
**Escalation:** operator — S11 pin decision (recorded).

## A-APL-005: no native float-bits reinterpret (no `transfer`) → hand-rolled f64/f32 bits

**V8 section:** ENTITY-CBOR-ENCODING §mt7 (float head), Rule 4 (shortest float)
**Profile field:** `[numeric].float_bits_path`, `[idiom].no_native_float_bits`
**Your guess:** APL has native IEEE binary64 (double) but NO bit-reinterpret primitive
(no C `transfer`, no bits-of-float). IEEE bit access for f64/f32 is hand-rolled arithmetic
decomposition (sign/biased-exp/mantissa via ⌊, |, ×/÷ powers of two — the Rexx-family float
path), OR an `ec_*` native-fn helper. f16 + the shortest-float ladder hand-rolled
regardless.
**Rationale:** floats appear mainly in the ECF conformance corpus, rarely in peer data
payloads; the arithmetic decomposition is well-trodden (Rexx did it fully). If it proves
error-prone in S2, route float bit-packing through an `ec_*` native-fn helper.
**Escalation:** arch (only if a corpus float vector exposes an ambiguity) / operator.

## A-APL-006: sockets via native ⎕FIO (no C net-shim) — verify --safe gating at S3

**V8 section:** §7b (transport), §4.8 (concurrency)
**Profile field:** `[async].socket_source`, `[idiom].qfio_native_sockets`
**Your guess:** Use GNU APL's ⎕FIO Berkeley-socket family (⎕FIO[32] socket, [34] listen,
[35] accept, [36] connect, [37] recv, [38/39] send, [40] select — confirmed present in the
apl-1.9 source `Quad_FIO.cc`) — NO C net-shim (a difference from COBOL/Fortran). The peer
runs WITHOUT `--safe` (⎕FIO socket ops are gated behind the safety flag). TCP_NODELAY via
⎕FIO setsockopt/fcntl — confirm the exact ⎕FIO sub-function code at S3.
**Rationale:** eliminates the C net-shim the thread/poll siblings needed; the byte-per-cell
recv/send matches the array byte model exactly.
**Escalation:** operator — verify the `--safe` requirement + the TCP_NODELAY ⎕FIO code at
S3 (not blocking S2).

## A-APL-007: naming convention (case-sensitive; dfn vs tradfn; PascalCase)

**V8 section:** absent (idiom)
**Profile field:** `[naming].*`
**Your guess:** PascalCase functions / camelCase variables / UPPERCASE constants; dfns
`{ }` for pure codec transforms, tradfns `∇` for the stateful ⎕FIO dispatch loop; the
WORKSPACE is the namespace unit (no module system), grouped by name prefix.
**Rationale:** APL is case-sensitive with glyph primitives; there is no single ecosystem
mandate, so the profile picks the modern APL-Wiki/Dyalog-influenced convention and records
it (profile decides, agent doesn't).
**Escalation:** operator — local convention decision.

## A-APL-008: license entanglement — Apache-2.0 shim source combines into a GPLv3 binary

**V8 section:** absent (S9 licensing)
**Profile field:** `[license].generated_outputs`
**Your guess:** Keep the S9 Apache-2.0 default for all peer source. NOTE that the native-fn
shim (`src/ext/ec_native.cc`) #includes GNU APL's GPLv3 source-tree headers and is dlopen'd
into the GPLv3 apl process, so the COMPILED shim+apl combination is a GPLv3 work. Apache-2.0
is ONE-WAY compatible into GPLv3, so shipping the shim SOURCE as Apache-2.0 is fine and it
combines into a GPLv3 binary at build. The `.apl` source is interpreted (no linking) → no
entanglement. A stronger entanglement than gfortran's runtime-exception — worth the
operator's explicit awareness.
**Rationale:** GPLv3 compatibility is one-way and satisfied; no relicensing needed. Flagged
for transparency, not because it blocks.
**Escalation:** operator — license-posture awareness (recorded).

## A-APL-009: native-fn shims need the RETAINED apl source tree (headers not installed)

**V8 section:** absent (build)
**Profile field:** `[build].compile_flags`, `[idiom].retained_apl_source`
**Your guess:** The toolchain image RETAINS `/opt/apl-1.9` (configured + built) because GNU
APL native functions must compile against apl's INTERNAL headers (`Native_interface.hh`,
`Value.hh`, `Cell.hh`, …) plus the configure-generated `config.h` at the build root; `make
install` ships only `libapl.h` + `Error.def`. The shim compiles with `g++ -shared -fPIC
-std=gnu++17 -I/opt/apl-1.9 -I/opt/apl-1.9/src`; apl is linked `-export-dynamic` so the
dlopen'd `.so` resolves apl's symbols at ⎕FX load (verified in-container — the strlen shim
loaded + returned via ⎕FX; the ec_* variant links libentitycore_codec).
**Rationale:** documented, honest arrangement — the source tree is a build-time header
dependency, not a runtime one.
**Escalation:** operator — build arrangement (recorded).

## A-APL-010: base58 / peer-id ride the C-ABI (no APL exact bignum)

**V8 section:** §4.2 (peer-id), §1.5 (canonical form)
**Profile field:** `[codec].base58_library`
**Your guess:** peer-id base58 base-256→base-58 long-division rides `ec_peerid_
{parse,format}` over the C-ABI (the COBOL/Fortran choice). APL has no exact integer past
2^63, so a native base-58 long-division over the full digest would be lossy.
**Rationale:** the C-ABI already carries base58; re-deriving it in APL adds zero independent
signal and would hit the int64 ceiling.
**Escalation:** operator — recorded.

## A-APL-011: value model — nested array + explicit major-type discriminant

**V8 section:** ENTITY-CBOR-ENCODING (major types), ENTITY-NATIVE-TYPE-SYSTEM
**Profile field:** `[naming].value_model`, `[idiom].tagged_array_value`
**Your guess:** An ECF value is a nested APL array (⊂ enclose / ⊃ disclose) carrying an
explicit integer major-type discriminant cell. APL arrays do NOT carry the CBOR major type,
so int-vs-float (mt0/1 vs mt7) AND byte-vs-text (mt2 vs mt3) intent are represented
EXPLICITLY, never inferred from APL storage. The absent/"not present" sentinel is a tagged
`present=0` discriminant, NOT an empty vector (the empty byte/text string is a real wire
value).
**Rationale:** the array/EIAS-adjacent trap — like Tcl/Fortran, storage kind ≠ wire intent.
**Escalation:** operator — recorded.

---

## A-APL-012: GNU APL 1.9 --script has NO control-structure extension AND no dfn `:` guard

**V8 section:** absent (interpreter/build property, found at S2)
**Profile field:** `[naming].dfn_vs_tradfn`, `[idiom].interpreted_no_static_gate`
**Your guess (S2, verified in-container):** GNU APL 1.9's `--script -f` line reader
**rejects the `:If`/`:For`/`:Select`/`:While` control-structure extension entirely** (each
control word → "SYNTAX ERROR in function" at definition, silently mis-defining the function),
AND it **rejects the dfn `:` GUARD** as "Illegal : in immediate execution" — for single-line
dfns loaded from a file, and even via `⍎'...'` or `⎕FX`. Only `∇...∇` tradfn bodies using
**classic `→(cond)/label` branch flow control + `label:` targets** load and run correctly
(labels inside a `∇` body are fine; the `:` ban is immediate-execution-only). So S2 authors
the codec as: **branch-free single-line dfns** for pure transforms (Oct8, MkText, F64Octets,
F64Fields — honoring the profile's dfn intent) and **`→`-branch tradfns** for every
dispatch / stateful / looping path (CborEncode, EmitHead, EncMap, KeySort, EncFloat, the
whole decoder, VarintEncode/Decode, the self-test, the drivers). The profile's
"dfns for pure transforms, tradfns for the stateful loop" split still holds in spirit; the
mechanism is `→`-branch, not `:If`.
**Rationale:** this is a **GNU-APL-specific generator lesson** (Dyalog has the `:If`
extension; GNU APL 1.9 does not) — the array-model probe still lands, but the control-flow
idiom is 1970s-APL `→`, not modern structured APL. No spec impact.
**Escalation:** research — a durable "GNU APL codec idiom" note for any future GNU APL peer /
generator run; operator — local implementation decision (recorded).

## A-APL-013: GNU APL does not exit when stdout is a PIPE (hangs after )OFF)

**V8 section:** absent (interpreter/harness property, found at S2)
**Profile field:** `[testing].runner`, `[build].test_command`
**Your guess (S2, verified in-container):** `apl --script ... </dev/null | tee log`
prints all output but then **HANGS** — GNU APL 1.9 does not terminate at `)OFF` when its
stdout is a pipe. A **file redirect** (`apl ... >log 2>&1`) exits cleanly (exit 0). So the
Makefile `conf`/`unit` recipes REDIRECT apl output to `build-{conf,unit}.log`, then `cat` +
`grep` the greppable `CONFORMANCE: ALL PASS` / `UNIT: ALL PASS` marker (the gate), never
`apl | tee`.
**Rationale:** a harness gotcha, not a codec property; recorded so the pattern isn't
reintroduced. Note also that a per-container `--cpus`-capped image plus a stray hung
interactive apl (from ad-hoc probing) can starve the gate — always run one capped container
at a time.
**Escalation:** operator — build/harness decision (recorded).

## A-APL-014: native-fn FFI must read args with get_near_int (APL `÷` yields FLOAT cells)

**V8 section:** absent (GNU APL FFI property, found at S2)
**Profile field:** `[codec].ed25519_library` / `[build].ffi_shim`
**Your guess (S2, verified):** APL's `÷` (divide) produces a **FloatCell even for exact
integer division** (e.g. `(≢p)÷2` → `2.0`), so a "byte" octet vector built through any `÷`
carries float cells whose value is an exact integer but whose Cell type is float. The GNU
APL native-fn shim MUST read argument cells with **`get_near_int()`**, NOT `get_int_value()`
— the latter throws `DOMAIN_ERROR` on a FloatCell, surfacing in APL as a `DOMAIN ERROR` at
the `EcNative` call. `get_near_int()` accepts both IntCell and near-integer FloatCell. (The
APL-side byte compare `≡` already tolerates `162.0 ≡ 162`, so only the FFI boundary is
affected.) Equivalently one could `⌊`-normalize before the FFI, but `get_near_int()` at the
boundary is the robust fix.
**Rationale:** a reusable GNU-APL-native-fn gotcha (any `entity-core` GNU APL peer binding a
C-ABI hits it). No spec impact.
**Escalation:** research — GNU APL native-fn lesson; operator — recorded.

## A-APL-015: ⎕FIO socket ABI + two GNU-APL-1.9 `select` bugs (found at S3)

**V8 section:** §7b (transport), §4.8 (concurrency)
**Profile field:** `[async].socket_source` / `[async].event_primitive` / `[async].tcp_nodelay`
**Your guess (S3, verified in-container):** GNU APL's native `⎕FIO` Berkeley-socket family
is the transport (no C net-shim — A-APL-006 confirmed). The verified ABI: an **IPv4 address
is a SINGLE INTEGER** in the `(AF ip port)` triple (127.0.0.1 = `2130706433`), NOT a 4-octet
vector; `⎕FIO[35]` accept returns `(handle AF ip port)` so the new fd is item `[1]`;
`⎕FIO[37]` recv on a closed socket yields an **empty vector** (EOF); byte cells cross as
integers 0..255. TCP_NODELAY = `(6 1 1)⎕FIO[47] fd` (IPPROTO_TCP=6, TCP_NODELAY=1). Peer
runs WITHOUT `--safe` (confirmed). **Two real `⎕FIO[40]` select bugs** (read the apl-1.9
`Quad_FIO.cc` source): **(1)** the timeout arg is parsed but the `timeval*` is never assigned
`&timeout` → select **always blocks until an fd is ready** (the timeout is inoperative). We
use the 3-element (no-timeout) form as a clean "block until readable" primitive; a broken
peer still wakes it (a closed socket becomes read-ready + EOF). **(2)** `fds_to_val` loops
`m < max_fd` (off-by-one) → it **drops the highest ready fd** from the returned read list.
Recovered in `NetSelectRead`: if `count > ≢reported`, the dropped fd is `⌈/readset`.
**Also:** the vector form `1 ⎕FIO[60] Bi` (random bytes) **crashes the interpreter** (an
`Incomplete value` assertion) — randomness rides `/dev/urandom` via `⎕FIO[3]`+`⎕FIO[6]`
instead; `⎕FIO[50] 1000` gives ms wall-clock.
**Rationale:** a durable GNU-APL-socket cookbook for any future GNU APL peer / generator run.
No spec impact — the peer is spec-conformant; these are substrate ABI facts + two upstream
interpreter bugs worked around cleanly.
**Escalation:** research — GNU APL socket-idiom note; operator — recorded (the two select
bugs are candidates to report upstream to the GNU APL maintainer, out of scope here).

## A-APL-016: GNU APL 1.9 evaluates NILADIC dfns at definition; `{}X` errors (found at S3)

**V8 section:** absent (interpreter/build property, found at S3)
**Profile field:** `[naming].dfn_vs_tradfn` / `[idiom].interpreted_no_static_gate`
**Your guess (S3, verified in-container):** two GNU-APL-1.9 dfn quirks beyond A-APL-012.
**(1)** A **niladic dfn** `Name←{body}` (a body with NO `⍺`/`⍵`) is **EVALUATED at definition
time** under `--script`, not stored as a deferred function — so a niladic "function" runs
once at load (e.g. `CapNowMs←{⎕FIO[50]1000}` would freeze the clock; `NetSocket←{⎕FIO[32]…}`
would open a socket at load and return a constant fd). Every niladic *function* is therefore
authored as a **tradfn** (`∇Z←Name … ∇`); niladic dfns are reserved for genuine constants
(`VMapEmpty←EV_MAP ⍬`). **(2)** The **empty-dfn-for-effect idiom `{}expr`** (discard a
result) **throws VALUE ERROR** — replaced everywhere by a throwaway assignment `zz←expr`.
(Monadic/dyadic dfns with `⍵`/`⍺` are deferred and fine, per A-APL-012.)
**Rationale:** a reusable GNU-APL codec/peer idiom lesson (Dyalog defers niladic dfns; GNU
APL 1.9 --script does not). No spec impact.
**Escalation:** research — durable GNU APL idiom note; operator — recorded.

## A-APL-017: GNU APL array-idiom traps + reentry serialization (found at S4)

**V8 section:** none — all are GNU-APL substrate/idiom facts and peer-code bugs surfaced by
the `validate-peer --profile core` oracle. **No spec-vs-oracle divergence** (keystone rule:
the oracle is ground truth; every S4 FAIL was the *peer* being wrong, fixed in the peer —
NOT the spec). APL was authored as a *corroboration* probe; this confirms the prediction —
zero fresh wire findings, but a durable crop of GNU-APL array-idiom traps for any future run.

**The traps (each cost one debug cycle; all are reusable GNU-APL-1.9 lessons):**

1. **Monadic `⊃` is DISCLOSE, not FIRST.** `⊃⌽v` on a *simple* char vector returns the
   reversed vector UNCHANGED (disclose is identity on a non-nested array) — NOT the last
   element. `'/'=⊃⌽path` then element-wise-compares the whole string → a bit vector that
   `→(…)/label` treats as truthy whenever ANY `/` is present. This made EVERY get with a
   slash resolve as a trailing-slash *listing* (a 77-FAIL cross-category blowup: gets
   returned `system/tree/listing`, put/get returned the wrong entity, concurrency demux
   "cross-talk"). **Fix:** use the existing `EndsWith` idiom (`path EndsWith '/'`), or dyadic
   pick `(≢v)⊃v` for a scalar last element. Never `⊃` for "first" in GNU APL.

2. **`≡` compares RANK — a 1-element vector never matches a scalar.** `(¯1↑v)≡'/'` is
   ALWAYS 0 (1-elem char vector vs scalar char). Same trap: in `CapMatchesPattern`, the
   recursion `3↓pattern` yields the 1-elem vector `,'*'`, so `pattern≡'*'` was false and the
   trailing-`*` wildcard never matched → `/*/*` failed to cover a foreign `/{peer_id}/…`
   absolute path (universal-address-space 403). **Fix:** ravel both sides — `(,x)≡,y`.

3. **`⍺∘≡¨⍵` (bind-compose ≡ with each) throws DOMAIN ERROR in GNU APL 1.9** — even on a
   non-empty right arg. `SlHas` used this and was latent (never reached until the multisig
   accept-path ran). **Fix:** `{∨/(⊂⍺)≡¨⍵}` (enclose ⍺, dyadic-≡-each broadcast).

4. **A name that is BOTH a `label:` and an assignment target `name←…` → SYNTAX ERROR** on the
   assignment (you cannot assign to a label constant). `HndDispatchOutbound` had an `ok:`
   label AND `ok←PumpUntil rid`; latent because the `--validate` dispatch-outbound reentry
   was never exercised before S4. The error surfaces AT the assignment and corrupts the
   parser (subsequent statements also SYNTAX-ERROR). **Fix:** rename the variable (`pumped`).

**Reentry serialization (design note, §6.11 concurrent-reentry / `t1_2`).** GNU APL's
single-image select-pump plus trap #4 turned the §6.13(b) handler-outbound reentry pump into
a crash under the concurrent-reentry flood: pumping the WHOLE read set inside
`HndDispatchOutbound`'s wait re-entered a *pendent* `HndDispatchOutbound` for a second
connection's inbound dispatch-outbound. Redesign (durable for any single-thread peer): the
reentry pump (`fd PumpUntil rid`) services ONLY the reentry connection's fd; inbound EXECUTEs
that arrive on other fds while a reentry is pendent are DEFERRED to a queue (`gDefer`, gated
by `gReentryDepth`) that `PeerServe` drains at depth 0 — so each dispatch-outbound completes
(send outbound → await its correlated reply on the same connection → send final response)
before the next is serviced, and `HndDispatchOutbound` is never pendent more than once. This
is the single-thread event-loop serialization the §6.11(a) no-serialization MUST permits
(`t1_1` is informational for non-parallel runtimes); `t1_2`/`t1_3`/`t2_1`/`t2_2` all PASS.

**Peer-code bugs fixed (all "peer was wrong", from-spec):** (a) multisig threshold parsed via
`(2⊃p)⊃(0)(1⊃p)` picked index=present(1)→the `0` element, so threshold was always 0 →
`(1⊃p)×2⊃p`; (b) §1.4 path validation was absent — added null-byte + empty-segment (`//`) +
leading-`/`-must-be-`/{peer_id}/…` rejection (→ 400 `invalid_path`), scoped to the
`invalid` flag of `CapCanonicalize` (pattern canon via `Canon` ignores it, so `/*/…` grant
patterns are unaffected); (c) the trailing-slash *listing* was never detected (trap #1) so
`system/type/` + `system/handler/` + tree listings 404'd.

**Rationale:** a reusable GNU-APL array-idiom checklist (`⊃`=disclose, `≡`=rank-sensitive,
`∘≡¨`=DOMAIN, label∥variable=SYNTAX) + a single-thread reentry-serialization pattern. No
spec impact; no arch handoff.
**Escalation:** research — durable GNU APL idiom + single-thread-reentry note; operator —
recorded (trap #3 `⍺∘≡¨⍵` DOMAIN ERROR is a candidate upstream GNU-APL report, out of scope).

---

# S5 finalization (2026-07-12) — every item owner-tagged + escalation state

Closing sweep at packaging (PHASE-S5). No item is **blocking**; every one carries a resolved
best-guess or a measured resolution. **No item escalated to arch** — APL was authored as a
*corroboration* probe and the prediction held: zero fresh wire findings, no spec-vs-oracle
divergence at S4 (every S4 fix was a peer bug derived from the spec — A-APL-017). Final
disposition of all 17 entries:

| ID | Escalation owner | State at S5 |
|---|---|---|
| A-APL-001 | operator | Closed — GNU APL 1.9 source-built from the SHA-256-pinned GNU tarball (not in fedora dnf); Dyalog/J/dzaima/kap declined. |
| A-APL-002 | research | Closed (durable lesson) — `uint64` tower `[2⁶³,2⁶⁴−1]` carried as an 8-octet big-endian array, never `256⊥`'d into a scalar; head-form self-test byte-exact (S2 69/69). The array-model expression of the fixed-width-artifact lesson. |
| A-APL-003 | operator | Closed — silent int64→IEEE-double promotion at 2⁶³ verified in-container; drives the A-APL-002 octet-array carrier. |
| A-APL-004 | operator | Closed — GNU APL 1.9 pinned (S11 30-day floor); apl-2.0 (~18d) declined, re-evaluate on next rebuild once it clears 30 days. |
| A-APL-005 | operator | Closed — f64/f32 IEEE bits hand-rolled by arithmetic decomposition (no APL bit-reinterpret); f16 + shortest ladder hand-rolled. No corpus float vector exposed an ambiguity (the conditional arch-escalation never triggered), so closed operator-local. |
| A-APL-006 | operator | Closed — native `⎕FIO` Berkeley sockets, no C net-shim; peer runs without `--safe`; TCP_NODELAY code confirmed at S3 (A-APL-015). |
| A-APL-007 | operator | Closed — PascalCase fns / camelCase vars / UPPERCASE consts; `→`-branch tradfns + branch-free dfns (mechanism updated by A-APL-012). |
| A-APL-008 | operator | Closed (license posture) — Apache-2.0 shim source is one-way compatible into the GPLv3 shim+apl binary; surfaced in README + PHASE-S5 operator handoff. No relicense needed. |
| A-APL-009 | operator | Closed — toolchain image retains `/opt/apl-1.9` source tree (native-fn shim compiles against apl's internal headers); `make install` ships only `libapl.h`. |
| A-APL-010 | operator | Closed — base58 / peer-id ride `ec_peerid_{parse,format}` over the C-ABI (no APL exact bignum past 2⁶³). |
| A-APL-011 | operator | Closed — nested-array value model with an explicit integer major-type discriminant cell; int-vs-float + byte-vs-text intent explicit, never inferred from APL storage. |
| A-APL-012 | research (+ operator) | Closed (durable lesson) — GNU APL 1.9 `--script` rejects the `:If`/`:For` control-structure extension AND the dfn `:` guard; codec authored as `→`-branch tradfns + branch-free dfns. Reusable "GNU APL codec idiom" note. |
| A-APL-013 | operator | Closed (durable lesson) — GNU APL hangs after `)OFF` when stdout is a pipe; the harness file-redirects then greps the marker. Never `apl | tee`. |
| A-APL-014 | research (+ operator) | Closed (durable lesson) — native-fn shims MUST read arg cells with `get_near_int()` (APL `÷` yields FloatCell even for exact division); reusable GNU-APL native-fn gotcha. |
| A-APL-015 | research (+ operator) | Closed (durable lesson) — `⎕FIO` socket ABI cookbook (IPv4 addr = single int; accept fd at `[1]`; recv-on-closed = empty vector; TCP_NODELAY `(6 1 1)⎕FIO[47]`) + two worked-around GNU-APL-1.9 `⎕FIO[40]` select bugs (inoperative timeout; off-by-one drops the highest fd) + `⎕FIO[60]` vector-form crash. Two select bugs are candidate upstream reports (out of scope). |
| A-APL-016 | research (+ operator) | Closed (durable lesson) — GNU APL 1.9 evaluates niladic dfns at definition (author them as tradfns); `{}expr` throws VALUE ERROR (use a throwaway assignment). |
| A-APL-017 | research (+ operator) | Closed (durable lesson) — four GNU-APL array-idiom traps (`⊃`=disclose-not-first · `≡`=rank-sensitive · `⍺∘≡¨⍵`=DOMAIN · label∥variable=SYNTAX) + the single-thread reentry-serialization pattern surfaced by S4. No spec impact; trap #3 is a candidate upstream report. |

**Arch-routed at S5:** none — no spec-vs-oracle divergence surfaced (every S4 fix was a peer
bug derived from the spec). **Research-banked durable lessons (no arch action):**
A-APL-002 / A-APL-012 / A-APL-013 / A-APL-014 / A-APL-015 / A-APL-016 / A-APL-017 (the
GNU-APL-1.9 array-idiom + socket + native-fn cookbook for any future GNU APL peer / generator
run). **All other items are operator-local, resolved.** The two `⎕FIO[40]` select bugs
(A-APL-015) and the `⍺∘≡¨⍵` DOMAIN ERROR (A-APL-017 trap #3) are candidate upstream GNU APL
reports, out of scope for this peer.
