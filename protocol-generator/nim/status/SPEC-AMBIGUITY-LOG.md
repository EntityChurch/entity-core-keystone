# entity-core-protocol-nim — Spec Ambiguity Log

Per PROMPT-CONSTANTS: every guess is logged here, no silent guesses. `A-NIM-NNN`.
Severity: **blocking** (stops a phase) / **non-blocking** (proceed with a flagged
best-guess) / **finding** (candidate spec-precision issue → arch via
`research/stewardship/SPEC-FINDINGS-LOG.md`, overseer-owned).

Status at end of S1: **NO BLOCKING ITEMS.** Nim is a corroboration / generator-
robustness peer, not a discovery bet — no entry is a spec finding-candidate; the
substrate axes it exercises (compile-time metaprogramming codec; native-C-interop
crypto; fixed-width uint64; ARC/ORC memory) are generator-robustness, not new wire
surface. A-NIM-001/003/005 are S2 confirm items with documented fallbacks; the rest
are pre-resolved local decisions.

**S2 UPDATE (2026-07-12): all S2 confirm-items RESOLVED, still no blocking items,
no new findings.** wire-conformance = **71/71 PASS, 0 FAIL** (first compile-run).
- **A-NIM-001 — CONFIRMED native.** The hand-rolled canonical spike passed 71/71
  first-run; the documented `ffi` fallback was NOT needed.
- **A-NIM-003 — CONFIRMED.** libsodium `{.importc, header:"sodium.h".}` binding
  links + runs in-container; deterministic Ed25519 (signature 3/3) + SHA-256
  (content_hash 4/4) green.
- **A-NIM-005 — RESOLVED.** Nim 2.2.2 tarball sha256
  `7fcc9b87…8a1f` filled + verified (download AND official `.sha256` sidecar both
  matched); `nim-toolchain:latest` image built.
- **A-NIM-002 — ENFORCED + PASSING.** `[2^63, 2^64-1]` head-form self-test green
  at compile time (`static:` block in `src/ecf.nim`) AND run time; uint64 carrier.

---

## A-NIM-001: codec strategy — native hand-roll vs LANDSCAPE's "ffi" guess

**V8 section:** ENTITY-CBOR-ENCODING (canonical ECF, N1–N4); PHASE-S1-PROFILE codec-strategy
**Profile field:** `[codec] strategy`, `cbor_library`
**Your guess:** `strategy = "native"` — hand-rolled canonical ECF encoder/decoder in Nim
(compile-time macro/template major-type dispatch), overriding `research/LANDSCAPE.md`'s
first-pass `ffi`. `ffi` (consume `libentitycore_codec`) is the documented fallback if the
S2 canonical spike fails.
**Rationale:** No CBOR library (incl. Nim's `cbor` package) gives ECF's guarantees
(shortest-float f16, length-then-lex CTAP2 map ordering, recursive mt6 tag reject,
raw-byte fidelity, full uint64/nint range) — the A-005 pattern every native peer hit, so
a library buys ~nothing. Native is the only choice that yields an INDEPENDENT codec to
cross-check the oracle (the C-ABI codec is the C impl — consuming it adds zero signal)
AND exercises Nim's headline generator-stress axis (compile-time metaprogramming).
**Escalation:** **research — LANDSCAPE first-pass superseded by the profile** (PHASE-S1:
"the profile decides"). Non-blocking. S2 spike (`map_keys` + `float` vectors) confirms
the hand-rolled canonical layer before the full build; fallback to `ffi` documented.

## A-NIM-002: fixed-width uint64 head form + mandatory [2^63, 2^64-1] self-test

**V8 section:** §1.5 canonical-form table; §7.3 head form; ENTITY-CBOR-ENCODING mt0/mt1
**Profile field:** `[integer]` (whole section), `[idiom] fixed_width_uint64`
**Your guess:** Carry the head form in native `uint64` (magnitude for mt1 negatives,
tagged); build the codec with `--overflowChecks:on`; make a round-trip self-test across
`[2^63, 2^64-1]` a MANDATORY S2 codec gate.
**Rationale:** Nim is fixed-width (no bignum). `uint64` maps directly to the head form
(like C uint64_t / Zig u64 / C# ulong), but a signed int64 carrier silently overflows in
the `[2^63, 2^64-1]` band — the AGENTS.md fixed-width head-form lesson. Unsigned wraps
silently, so every decoder length read is explicitly bound-checked.
**Escalation:** **operator — local decision** (a known cohort trap, pre-resolved). Not a
spec question. Enforced by the S2 self-test.

## A-NIM-003: crypto floor — libsodium via native {.importc.} C interop

**V8 section:** §9.1 signature floor (Ed25519); SHA-256 content-hash
**Profile field:** `[codec] ed25519_library`, `sha256_source`, `[idiom] compiles_to_c`
**Your guess:** Ed25519 + SHA-256 via libsodium bound with native Nim `{.importc.}`
(+ static link). "native" in the C peer's sense — primitives+crypto native, canonical
layer hand-rolled.
**Rationale:** Nim compiles to C, so libsodium `{.importc.}` is idiomatic in-process
interop (the C peer's exact choice), NOT a foreign bridge. No audited pure-Nim Ed25519
exists (nimcrypto has SHA-2/HMAC, no EdDSA). libsodium is audited, statically linkable,
one source of Ed25519 + SHA-256. As a system crypto lib (not the entity C-ABI) it keeps
the default peer self-contained.
**Escalation:** **operator — local decision**; **S2 confirm** the `{.importc.}` binding +
static link against fedora's libsodium in-container (trivial). Non-blocking. nimcrypto
SHA-256 is the documented FFI-free SHA fallback.

## A-NIM-004: Ed448 / SHA-384 agility deferred — opt-in hybrid-FFI sub-library

**V8 section:** crypto-agility (v7.67 Ed448 / SHA-384) — the higher bar, NOT the §9.1 floor
**Profile field:** `[codec] ed448_library`
**Your guess:** DEFER Ed448 + SHA-384 from the v0.1 core. When agility lands, an opt-in
sub-library via either the sibling `libentitycore_codec` `ec_ed448_*`/`ec_sha384`
(hybrid-FFI) or OpenSSL `EVP_PKEY_ED448`.
**Rationale:** libsodium has no Ed448-Goldilocks (same gap as C/Zig/OCaml). Agility is
not the conformance floor; deferring keeps the default peer's crypto surface one library
(libsodium) + FFI-free of the entity C-ABI. Does not touch the Ed25519 + SHA-256 floor.
**Escalation:** **operator — local decision** (deferred; floor ships first). Non-blocking.

## A-NIM-005: Nim toolchain version pin + verified install

**V8 section:** n/a (S11 supply-chain)
**Profile field:** `[deps] nim`, `nim_fallback`; `[language] runtime`
**Your guess:** Pin Nim `2.2.2` (fallback line `2.0.14`); install via the official
source tarball with a fail-closed sha256 sentinel (the zig-toolchain pattern); `dnf
install nim` documented as the distro-reviewed fallback.
**Rationale:** Pin the exact release the codec is designed against + verify by sha256
rather than take whatever fedora's channel drifts to across the 2.0/2.2 line. Nim 2.x is
ARC/ORC-default with stable macros; the codec logic is 2.0/2.2-agnostic. 2.2.x is
>18 months old — clears the >=30-day floor.
**Escalation:** **operator — S2 build gate.** Confirm the exact patch + fill/verify the
tarball sha256 against nim-lang.org/install at S2. Non-blocking (fallback documented).

## A-NIM-006: async model — asyncdispatch single-threaded event loop

**V8 section:** §4.8/§4.9 concurrency; §6.11 handler-initiated outbound reentry; §7b store-safety
**Profile field:** `[async]` (whole section)
**Your guess:** `style = "event-loop"` — stdlib `asyncdispatch`/`asyncnet` on a single-
threaded cooperative event loop; plain `Table` store (no lock); request_id pending table
for §6.11 reentry. Nim OS threads noted as the out-of-scope alternative.
**Rationale:** asyncdispatch is Nim's idiomatic network model and makes §7b store-safety
STRUCTURAL (one event thread serializes mutations) and §6.11 reentry ~free (another loop
turn) — the PHP/Tcl/Dart event-loop result on a fourth substrate. `chronos` rejected as a
dependency; stdlib is dependency-minimal.
**Escalation:** **operator — local decision.** Non-blocking. Exercised at S3/S4 (the §7b
concurrency gate + §6.11 origination-core reentry).

## A-NIM-007: string byte-vs-text — static type distinction (clean)

**V8 section:** ENTITY-CBOR-ENCODING major types 2 (byte) & 3 (text); text length = byte count
**Profile field:** `[string]` (whole section), `[idiom] string_is_byte_buffer`
**Your guess:** CBOR mt2 = `seq[byte]`, mt3 = `string`; the major type is a static type
distinction sourced from the spec's field definitions and carried in the typed model,
never inferred from a value. Nim `string` len is already a BYTE count.
**Rationale:** Unlike Tcl EIAS, Nim's byte-vs-text is free at the type level and string
length is bytes (no `encoding convertto` dance — contrast A-TCL-002). The type-registry
"render from the model, don't infer" lesson costs nothing here.
**Escalation:** **operator — local decision** (no spec question). Non-blocking. mt3 text
validated as UTF-8 on decode where the spec requires text.

## A-NIM-008: error model — exceptions + {.raises.} effects; Option[T] absent

**V8 section:** protocol status codes (400/401/403/413); N2/N3 canonicality rejects
**Profile field:** `[error_model]` (whole section)
**Your guess:** stdlib exceptions with `{.raises: [...].}` effect annotations; codec
throws hard on canonicality violations; exception type → wire status at the dispatcher
boundary; in-band absent = `Option[T]`. `results` package rejected.
**Rationale:** Exceptions are Nim's idiom; `{.raises.}` gives compiler-enforced exception
sets (a lightweight checked-exceptions seam). stdlib-only keeps dependencies minimal.
**Escalation:** **operator — local decision.** Non-blocking.

## A-NIM-009: §4.2 pre-auth reject status (403) vs §5.2a author-absent (401)

**V8 section:** §4.2 (Pre-Authorization Rules) vs §5.2a (Verdict-to-status enumeration, v7.73)
**Profile field:** absent (protocol-status decision, S3 dispatch)
**Your guess:** On a non-`system/protocol/connect` EXECUTE that carries NO `author`/
`capability` fields, return **401 `authentication_failed`** (the §5.2a "Author absent →
401, auth-class" row), NOT the **403** that §4.2 bullet 3 states ("EXECUTE targeting any
other path without auth fields MUST be rejected (status 403)").
**Rationale:** §4.2 predates the v7.73 §5.2a auth-class/authz-class split. The §6.5
dispatch chain runs `verify_request` (§5.2) for every non-connect EXECUTE, and §5.2a is the
**load-bearing extension** that pins each `verify_request` DENY surface to a (status, code)
tuple — "Author absent" and "Signature absent" are **auth-class → 401**. An unauthenticated
request has no verified signer, so it is an authentication failure (401), not an
authorization denial (403). This is also exactly the F31 auth-before-resolve invariant
(unauthenticated unknown-handler → 401, never 404). Following the newer, more specific
§5.2a (401) — confirmed live by the smoke's F31 leg. §4.2's "403" reads as stale wording
relative to §5.2a.
**Escalation:** **arch — spec needs clarification.** §4.2 bullet 3 should be reconciled
with the §5.2a table: an EXECUTE with no auth fields on a non-connect path is auth-class
(401 `authentication_failed`), not 403. (A capability that is *present but does not
authorize* is the 403/authz-class case — a different surface.) Non-blocking for the peer
(§5.2a is authoritative on the tuple, per its own text); flagged so the two sections stop
disagreeing on the number a fresh reader would emit.

## A-NIM-010: revoked-capability status — `403 capability_revoked` (oracle/§5.2a) vs the vendor MANIFEST's "401"

**V8 section:** §5.1 revocation; §5.2a verdict-to-status
**Profile field:** absent (protocol-status decision, S4 dispatch)
**Your guess:** A capability revoked anywhere in its chain denies with **403
`capability_revoked`** (the §5.2a authz-class row + the cohort reference dispatcher). The
peer follows this; the live oracle's `capability.revoked_cap_denied_on_use` +
`authz` checks PASS against 403.
**Rationale:** Revocation is an authorization-class denial (the signer/author IS
authenticated; the grant is simply no longer valid) → 403, not 401. The single §5.2 **401**
carve-out is `unresolvable_grantee` only.
**Escalation:** **research — doc note only (non-blocking).** The keystone-vendored
`shared/test-vectors/v0.8.0/type-registry-vendor MANIFEST.md` AUTHZ-* table annotates
`AUTHZ-REVOKED-1` as **401 capability_revoked**, which disagrees with both §5.2a and the
`cc1970f` oracle (403). The peer conforms to the oracle/§5.2a (403) and passes; logged so a
future reader does not mistake the stale doc annotation for a peer bug. No spec change
needed — the normative surface (§5.2a) and the oracle already agree on 403.

---

## S5 finalization (2026-07-12)

**All A-NIM-001..010 are resolved or owner/escalation-tagged; NO blocking item remains; the
peer is packaged (`0.1.0-pre`).** Disposition at S5 close:

- **A-NIM-001 / 002 / 003 / 005** — RESOLVED at S2 (native codec confirmed 71/71 first-run;
  `[2⁶³,2⁶⁴−1]` head-form self-test green compile-time + run-time; libsodium `{.importc.}`
  links; Nim 2.2.2 tarball sha256 verified). No further action.
- **A-NIM-004** — DEFERRED (Ed448 / SHA-384 agility; opt-in sub-library over C-ABI
  `ec_ed448_*` or OpenSSL when an adopter scopes it). Operator-owned; does not touch the
  Ed25519 + SHA-256 floor. Not a spec question.
- **A-NIM-006 / 007 / 008** — local idiom decisions (asyncdispatch event loop; static
  byte-vs-text; exceptions + `{.raises.}` + `Option[T]`), all exercised green through S4.
  Operator-owned, closed.
- **A-NIM-009** — **arch finding, OPEN (non-blocking).** §4.2 bullet-3 "403" vs §5.2a "401"
  for an unauthenticated non-connect EXECUTE. The peer follows the newer, more specific §5.2a
  (401) and passes; flagged for arch to reconcile the two sections' wording. Overseer routes to
  `research/stewardship/SPEC-FINDINGS-LOG.md` if it chooses to escalate.
- **A-NIM-010** — **doc-note only (non-blocking).** A vendored MANIFEST's stale "401
  capability_revoked" annotation vs the oracle/§5.2a `403`; the peer follows the oracle and
  passes. No spec change needed; logged so a future reader does not read the doc note as a peer
  bug.

No fresh arch escalation is created by this sub-agent (boundary: findings log is
overseer-owned). Nim closed as a **corroboration / generator-robustness** peer — no entry is a
spec finding-candidate beyond the pre-existing A-NIM-009 wording reconciliation.
