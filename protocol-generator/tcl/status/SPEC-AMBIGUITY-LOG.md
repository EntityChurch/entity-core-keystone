# entity-core-protocol-tcl — Spec Ambiguity Log

Per PROMPT-CONSTANTS: every guess is logged here, no silent guesses. Format per
entry below. `A-TCL-NNN`. Severity: **blocking** (stops a phase) / **non-blocking**
(proceed with a flagged best-guess) / **finding** (candidate spec-precision issue →
`research/stewardship/SPEC-FINDINGS-LOG.md` for arch).

Status at end of S1: **no blocking items.** Three probe entries (A-TCL-001/002/003)
are the reason this peer exists — carried into S2 as the things to prove, not
blockers. Library-availability confirmations (A-TCL-004/005) are S2 build gates.

---

## A-TCL-001: CBOR byte-string (mt2) vs text-string (mt3) under EIAS

**V8 section:** ENTITY-CBOR-ENCODING §major-types 2 & 3; §byte/text distinction
**Profile field:** `[idiom] byte_vs_text_seam`, `[codec] cbor_library`
**Your guess:** The data model tags every string value as *bytes* or *text* at
construction (a 2-element `{kind bytes|text  value ...}` representation or the
`bytearray` internal type for bytes vs a plain text value for text). Encode maps a
bytes value → mt2 of its raw bytes and a text value → mt3 of `encoding convertto
utf-8`. The peer NEVER infers the major type from the Tcl value alone (EIAS makes
that impossible: `"abc"` is both a valid text and a valid 3-byte string).
**Rationale:** ECF requires a definite major type; EIAS supplies none at the value
level, so the type must live in the peer's representation, sourced from the spec's
field definitions (which field is bytes vs text is normative). This is the
type-registry "render natively from the model, don't infer" lesson applied where
there is no native type to reflect.
**Escalation:** **finding-candidate** — S2 verifies whether every wire field's
bytes-vs-text kind is unambiguously fixed by the spec's type definitions. If any
core field's kind is under-specified (a value that could canonically be either),
that is a genuine A-LEAN-class spec-precision finding → arch. Expected outcome:
spec is tight, peer carries the tag explicitly, no defect — but this is THE probe.

## A-TCL-002: text-string length is UTF-8 byte length, not `string length`

**V8 section:** ENTITY-CBOR-ENCODING §text-string head (length = byte count)
**Profile field:** `[idiom] string_length_is_chars`, `utf8_explicit`
**Your guess:** Text-string CBOR length is `string length [encoding convertto
utf-8 $s]` (UTF-8 byte count), NEVER `string length $s` (which counts Tcl code
points). All text→wire goes through `encoding convertto utf-8`; all wire→text
through `encoding convertfrom utf-8`; the interp's system encoding is never trusted
for wire data.
**Rationale:** A classic EIAS/Tcl trap — `string length` is a character count, and
a multi-byte-UTF-8 string would emit a wrong CBOR length header if used directly.
The spec's length is unambiguously the encoded byte count; only the Tcl idiom is a
hazard here, not the spec.
**Escalation:** **operator — local decision** (a known Tcl correctness rule, not a
spec question). Enforced by a S2 unit test on a non-ASCII text vector.

## A-TCL-003: numeric shimmer — int (mt0/1) vs float (mt7) intent

**V8 section:** ENTITY-CBOR-ENCODING §major-types 0/1 (int) & 7 (float)
**Profile field:** `[idiom] numeric_shimmer_risk`, `native_bignum`
**Your guess:** The peer marks int-vs-float intent EXPLICITLY at value construction
(a tagged numeric representation), and NEVER derives the major type from `string is
integer`/`string is double` on the string form. Rationale: `"1"` satisfies `string
is double` too, and `"1.0"` is a double but numerically integral — EIAS gives no
reliable int-vs-float discriminator at the value level.
**Rationale:** Same root as A-TCL-001 (no intrinsic type) applied to the numeric
tower. The spec fixes which fields are ints vs floats; the peer sources intent from
the field definition, not the value's current string form.
**Escalation:** **finding-candidate** — as A-TCL-001, S2 confirms every numeric core
field's int-vs-float kind is spec-fixed. Expected: tight; peer carries intent.

## A-TCL-004: pinned Tcl major version (9.0 vs 8.6) on fedora:43

**V8 section:** n/a (toolchain)
**Profile field:** `[deps] tcl`, `tcl_fallback`, `[idiom] tcl_version`
**Your guess:** Target Tcl 9.0.1 (full-Unicode internals sharpen A-TCL-001/002);
fall back to 8.6.15 iff fedora:43 packages 8.6 not 9.0, or the pinned `cffi` only
builds on 8.6. Codec logic is version-agnostic (all wire encoding is explicit
`encoding convertto/convertfrom utf-8`), so the fallback is a build detail, not a
redesign.
**Rationale:** Cannot run tclsh under the S1 no-build boundary (same constraint
Prolog A-PL-008 noted for swipl); the exact fedora:43 Tcl package is confirmed at
first container build.
**Escalation:** **research — S2 build gate.** Assert the resolved version and record
it; either major is acceptable.

## A-TCL-005: cffi binding to libentitycore_codec (build + Ed25519 confirm)

**V8 section:** §9.1 crypto floor (Ed25519 + SHA-256)
**Profile field:** `[codec] ed25519_library`, `[deps] cffi`, `[idiom] ffi_via_cffi`
**Your guess:** Bind `libentitycore_codec` via `cffi` 1.2.x, declaring the verbatim
`entitycore_codec.h` entry points (`ec_ed25519_seed_to_pubkey`, `ec_ed25519_sign`,
`ec_ed25519_verify`, `ec_sha256`, `ec_sha384`, and `ec_ed448_*` for the opt-in
agility package). Provenance via `ec_impl_info()`.
**Rationale:** No native Tcl Ed25519 exists; `cffi` is the maintained, idiomatic
libffi FFI. The exact `cffi` patch that builds against the chosen Tcl major and the
prebuilt `.so` is a build fact, confirmed at S2 (mirrors COBOL's C-ABI dependence).
**Escalation:** **research — S2 build gate.** If the pinned `cffi` cannot bind the
header cleanly, `critcl` (inline-C) is the documented alternative FFI route.

## A-TCL-006: f16 (half-float) shortest-float leg has no `binary` format code

**V8 section:** ENTITY-CBOR-ENCODING §float shortest-form ladder (f16/f32/f64)
**Profile field:** `[codec] cbor_library` (`f16 leg hand-rolled`), `binary_command_codec`
**Your guess:** `binary format`/`scan` cover f32 (`R`) and f64 (`Q`) natively; the
16-bit half-float has no format code, so the f16 encode/decode + the shortest-form
minimization decision (does this f64 round-trip through f16/f32 exactly?) is
hand-rolled bit arithmetic on the native bignum integers — the same f16 hand-roll
every peer wrote.
**Rationale:** Universal ECF requirement; not Tcl-specific beyond the missing format
code. Straightforward with native bignums.
**Escalation:** **operator — local decision.** Verified by the `float` test-vectors
at S2 (the shortest-float ladder is the highest-value S2 spike).

## A-TCL-007: empty string cannot be the "absent" sentinel

**V8 section:** n/a (representation)
**Profile field:** `[error_model] absent_sentinel`, `[idiom] empty_string_trap`
**Your guess:** Absence/None is a tagged dict `{present 0}`, never `""`. The empty
string is a legitimate wire value (empty mt2 byte string or empty mt3 text string),
so overloading it as "absent" would collide with a real value.
**Rationale:** Classic Tcl EIAS trap; a correctness rule, not a spec question.
**Escalation:** **operator — local decision.**

## A-TCL-008: `Thread` package (actor substrate) out of scope for core

**V8 section:** §7b store-safety / §6.11 reentry
**Profile field:** `[async] style = event-loop`
**Your guess:** Use the single-threaded event loop (structural store-safety) for the
core peer; the `Thread` package (share-nothing OS threads + `thread::send`) is a
genuine actor alternative but is NOT used for `--profile core`.
**Rationale:** The event loop is more idiomatic for a network peer and needs no `tsv`
shared-var discipline; structural safety is achieved either way. Documented so the
choice is explicit, not accidental.
**Escalation:** **operator — local decision.** (A `Thread`-based variant is a
possible future robustness probe, not a core requirement.)

---

## S2 resolutions (2026-07-10)

Recorded as the S2 codec spike ran (container `tcl-toolchain:latest`, Tcl 9.0.2).

- **A-TCL-004 — RESOLVED.** fedora:43 ships **Tcl 9.0.2** (the preferred modern
  major); the container version-probe asserts 9.0.x/8.6.x and passed. Full-Unicode
  internals confirmed: `"héllo"` → `string length` 5 but UTF-8 byte length 6.
- **A-TCL-005 — RESOLVED (pivot).** `tcl-cffi` is **NOT packaged** in fedora:43
  (`can't find package cffi`). Pivoted to a self-contained **C-extension shim** via
  the Tcl stubs C API (`Tcl_InitStubs`/`Tcl_CreateObjCommand`, compiled with the
  image's `gcc` + `tcl-devel`) — de-risked in-container: a trivial extension
  compiles + loads + runs. This is cleaner than cffi (no external package, no
  network), and is the crypto binding for `libentitycore_codec` at the Class-B step.
  *Profile note:* the `[codec] ed25519_library` mechanism changes cffi → C-shim; the
  FFI-hybrid strategy itself is unchanged.
- **A-TCL-001 / 002 / 003 — CONFIRMED working (no spec defect surfaced yet).** The
  explicit tagged-value representation carries byte-vs-text (map_keys.5 mixes a byte
  key and a text key → correct mt2/mt3), int-vs-float intent, and UTF-8 byte length
  correctly: **codec spike 46/46**. The expected outcome held — the spec's major-type
  discipline cleanly obliges the peer to carry an explicit type tag; EIAS did not force
  any side-channel. The full-corpus + Class-B confirm is the remaining S2 check before
  this is closed as "corroboration, no finding" (or a finding filed if a core field's
  kind proves under-specified).

---

## S3 resolutions (2026-07-11)

Recorded as the S3 peer machinery was built + the two-peer loopback smoke ran green
(12/12; container `tcl-toolchain:latest`, Tcl 9.0.2). No new blocking items; no new
spec defect surfaced — S3 is corroboration across the peer layer.

- **A-TCL-001 / 002 / 003 — CLOSED as corroboration (no finding).** The full v0.8.0
  corpus was already 69/69 at S2; S3 carried the same tagged-value rep up through the
  entity / envelope / capability / handler layers (peer_id derivation, content-hash
  signing, the byte-keyed `included` map, the §5 chain-walk) with the byte-vs-text /
  int-vs-float / UTF-8-byte-length seams all fixed by the spec's field definitions.
  Every wire field's major-type kind was unambiguously determined by the spec — EIAS
  forced **no** side-channel anywhere in the peer. The experimental question the
  profile posed is answered: **the spec is already precise enough to oblige an EIAS
  peer to carry the type explicitly, with no leak into ad-hoc convention.**
- **A-TCL-007 — RESOLVED at the value-model layer (cleaner than the S1 guess).** The
  S1 guess was a tagged `{present 0}` dict for absence. In practice the ecf layer
  (`src/ecf.tcl`) makes this unnecessary: a PRESENT tagged value is *always* a
  non-empty Tcl list (≥1 element — the tag), so the bare empty string `""` is a safe
  absent sentinel at that layer (a field read returns `""` iff the key is truly
  absent; a present empty text/bytes value is `{text {}}` / `{bytes {}}`, non-empty).
  The one place that must tell present-empty-array from absent (§4.5 hello
  negotiation) uses an explicit `ecf::has` presence check. No `{present 0}` dict was
  needed — the tag *is* the presence bit.
- **A-TCL-008 — CORROBORATED.** The single-threaded `chan event` + `vwait` event loop
  (no `Thread` package) gives structural §4.8 store-safety (one handler runs to
  completion before the next readable event — no lock) AND makes the §6.11
  handler-initiated outbound-dispatch reentry a **nested `vwait`** — the natural
  event-loop turn, no cross-thread demux. The smoke's `dispatch-outbound` probe
  (B originates an EXECUTE back to A over the inbound connection, mid-dispatch) round-
  trips with the outer 200. This is the PHP/Dart §6.11 "reentry is ~free on an
  event-loop substrate" result, corroborated on a **fourth** event-loop peer.

**S3 verdict:** no spec-precision finding. The EIAS probe is clean corroboration end
to end — the highest-value thing S3 could have surfaced (an under-specified core
field kind) did not appear, which is itself the answer the profile was built to get.
