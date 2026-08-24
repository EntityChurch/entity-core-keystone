# entity-core-protocol-julia — Spec / Profile Ambiguity Log

Per PROMPT-CONSTANTS: every guess is logged here. **No blocking-severity item** — S1 exit
criteria are met. Severities: `blocking` (halts the dependent phase) · `non-blocking`
(a best-guess flagged, phase proceeds) · `settled` (pre-resolved from cohort, recorded for
provenance). Escalation targets: `arch` (spec) · `research` (profile field) · `operator`
(local decision) · `S2/S4` (confirm-at-phase).

---

## A-JULIA-001: Julia version + tarball sha256 pinned but not yet verified

**V8 section:** absent (toolchain provisioning)
**Profile field:** `[language].julia_version`, `[deps].julia`, container `JULIA_SHA256`
**Your guess:** pin Julia 1.11.5 (the 1.11.x stable line, >>30-day cool-down at 2026-07-12);
container `JULIA_SHA256` left as an S1 sentinel that fails the build closed.
**Rationale:** S1 is authoring-only; the exact patch + tarball sha256 are verified against
julialang.org checksums at S2, exactly as the zig-toolchain image defers its `ZIG_SHA256`.
**Escalation:** S2 — confirm exact patch + fill/verify sha256. **Severity: non-blocking.**

## A-JULIA-002: CBOR.jl declined in favor of a hand-rolled canonical codec

**V8 section:** ENTITY-CBOR-ENCODING (canonical ECF: N1–N4)
**Profile field:** `[codec].cbor_library`
**Your guess:** hand-roll the canonical CBOR encoder/decoder in pure Julia; do not use
`CBOR.jl`.
**Rationale:** the A-005 pattern every native peer hit — no Julia CBOR library offers ECF's
guarantees (shortest-float incl. f16, length-then-lex map-key order, recursive mt6 tag
reject, raw byte-string fidelity, full uint64/nint range). `CBOR.jl` is a round-trip
serializer without these, so it buys nothing; hand-rolling is faithful *and* simpler.
**Escalation:** operator (settled cohort pattern). **Severity: non-blocking** (confirm at
S2 via the map_keys + float spike before the full build).

## A-JULIA-003: Ed25519 via system libsodium `ccall`, not Sodium.jl

**V8 section:** §9.x signature floor
**Profile field:** `[codec].ed25519_library`
**Your guess:** bind system libsodium (`crypto_sign_*`) directly via Julia `ccall`; decline
the Sodium.jl wrapper.
**Rationale:** libsodium is the audited reference crypto lib and is image-provided; ccall is
first-class Julia C interop used throughout Base. Direct ccall keeps the floor peer
self-contained and Pkg-fetch-free (the container builds `--network=none`); Sodium.jl would
add a registered-package network fetch for a thin need. This is the native-audited-lib
crypto tier (Elixir `:crypto` / Haskell `crypton` class), NOT the keystone C-ABI FFI-hybrid.
**Escalation:** research (profile field, recorded). **Severity: non-blocking** (confirm the
libsodium symbol/ABI at S2).

## A-JULIA-004: Ed448 agility deferred to an opt-in hybrid-FFI sub-package

**V8 section:** crypto-agility (Ed448 family)
**Profile field:** `[codec].ed448_library`
**Your guess:** DEFER Ed448; when in scope, provide it as an opt-in hybrid-FFI sub-package
over the C-ABI (`libentitycore_codec` `ec_ed448_*`), not in the floor peer.
**Rationale:** libsodium has Ed25519 only — no Ed448. The native audited library cannot
cover the agility higher bar, so it routes to the same Ed448-only-FFI shape OCaml/Zig/Swift
reached (native floor + FFI-Ed448), scoped opt-in so the floor peer stays native +
self-contained. Does not affect the ECF/Ed25519 conformance floor.
**Escalation:** operator/arch (agility roadmap). **Severity: non-blocking** (out of scope
for `--profile core`).

## A-JULIA-005: single-threaded Task scheduler chosen for the core peer (Threads out of scope)

**V8 section:** §4.8 / §7b store-safety; §6.11 outbound reentry
**Profile field:** `[async]`
**Your guess:** run the core peer on the single-threaded Task scheduler (cooperative
coroutines over libuv); do not use `Threads.@spawn` multithreading for `--profile core`.
**Rationale:** cooperative Tasks yield only at I/O, so store-safety is structural (no lock,
no race) and §6.11 reentry is a plain `Channel` handoff (no cross-thread demux) — the
PHP/Dart/Tcl event-loop result on a fourth substrate. Julia's real multithreading is a
genuine shared-memory model needing locks; more idiomatic to use the Task scheduler for a
network peer. Noted as the alternative substrate.
**Escalation:** research (profile field). **Severity: non-blocking.**

## A-JULIA-006: multiple-dispatch major-type selection — verify no value shimmers across branches

**V8 section:** ENTITY-CBOR-ENCODING (major-type distinctions mt0/1 vs mt7, mt2 vs mt3)
**Profile field:** `[idiom].multiple_dispatch_codec`
**Your guess:** dispatch `encode`/`decode` by multiple dispatch on the Julia value type
(`Vector{UInt8}`→mt2, `String`→mt3, `Integer`→mt0/1, `AbstractFloat`→mt7).
**Rationale:** Julia's type system makes major-type selection natural — the opposite of the
Tcl EIAS problem, where byte-vs-text and int-vs-float must be tagged explicitly. Verify at
S2 that no value satisfies two dispatch branches (`String` is not an `AbstractVector`; a
`UInt8` vector is not a `String`), so there is no shimmer.
**Escalation:** S2 — confirm dispatch coverage/exclusivity. **Severity: non-blocking.**

## A-JULIA-007: text length must be byte length (ncodeunits), not character length (length)

**V8 section:** ENTITY-CBOR-ENCODING (text string mt3 length = UTF-8 byte length)
**Profile field:** `[idiom].utf8_native_string`
**Your guess:** compute CBOR text-string length via `ncodeunits(s)` / `sizeof(s)` and emit
`codeunits(s)`; never `length(s)`.
**Rationale:** Julia `String` is UTF-8 internally; `length(s)` counts code points, which is
NOT the wire length. The Tcl A-TCL-002 char-vs-byte trap — avoided by construction here
because UTF-8 is the native storage (no encoding-conversion step). Logged so the generator
carries the discipline explicitly rather than by luck.
**Escalation:** operator (settled). **Severity: non-blocking.**

## A-JULIA-008: fixed-width UInt64 wire carrier → [2^63, 2^64-1] head-form self-test mandatory

**V8 section:** ENTITY-CBOR-ENCODING (uint64 argument tower, minimal-int head)
**Profile field:** `[numeric]`
**Your guess:** carry the CBOR uint64 argument in a native `UInt64` (exact for
[0, 2^64-1]); carry the mandatory `[2^63, 2^64-1]` head-form self-test; widen only
*reconstructed application values* to `Int128`/`BigInt`.
**Rationale:** `UInt64` is fixed-width → the durable "integer head-form is a fixed-width
artifact" lesson applies (the C# `ulong` / Zig `u64` class), so the boundary self-test is
mandatory even though `BigInt` makes application-level full range free. This corroborates
C#/Zig; it does not break new ground on the numeric axis.
**Escalation:** operator (settled cohort lesson). **Severity: non-blocking.**

## A-JULIA-009: `Pkg.test()` fetches the General registry → fails under `--network=none`

**V8 section:** absent (Julia tooling)
**Profile field:** `[build].test_command`, `[container].dev_loop`
**Your guess:** run the suite via `julia --project=. test/runtests.jl` (and the gate via
`julia --project=. test/conformance.jl <fixture>`) DIRECTLY, not through `Pkg.test()`.
**Rationale:** `Pkg.test()` spins up an isolated test env and calls
`download_default_registries`, which git-clones the General registry — this hits the network
even for a stdlib-only package with zero registered deps, so it dies under the (correct)
`--network=none` build. `using EntityCore` + the stdlib deps (`SHA`/`Sockets`/`Test`) resolve
fully offline from `Project.toml` alone (proven: 71/71 corpus + 62/62 self-tests run offline),
so the direct-file invocation is the offline-correct path. `run-conformance.sh` wraps it. The
profile's `test_command` (`Pkg.test()`) is the *registered/online* form; the offline gate form
is the direct `julia … test/*.jl`. Not a spec issue; a tooling note.
**Escalation:** research — profile `[build].test_command` should carry the offline direct-file
variant alongside the `Pkg.test()` published form. **Severity: non-blocking** (gate runs green
via the direct form; `run-conformance.sh` is the reproducible entry).

## A-JULIA-010: S3 capability-verification scope — single-link root cap only

**V8 section:** §5.2 verify_request; §6.5 dispatch (verify → resolve → checkPermission)
**Profile field:** absent (phase-scope decision, not a profile field)
**Your guess:** at S3 the dispatcher implements request-time AUTH-class verification (§5.2 step 2
→ 401) fully, plus a single-link **root**-capability AUTHZ check (parent==null, granter
self-signature verifies, grantee==author → else 403). Multi-link attenuation chain-walk, TTL /
`not_before`, the §4.10(b) chain-depth pre-check → 400, and the §5.2 `checkPermission` SCOPE test
against the *resolved handler pattern* are deferred to S4.
**Rationale:** the S3 gate is the smoke (handshake + auth-before-resolve 401/404 + demux); it does
not exercise attenuation or scope. The root-cap check is the minimal HONEST authz layer that makes
the 401-vs-403-vs-404 trichotomy real (a request with no valid cap gets 403, not a faked 200) —
faking a fuller chain-walk with no vectors driving it would add zero signal (durable lesson:
"conformance-green can be vacuous"). S4's validate-peer `capability` category drives the rest.
**Escalation:** S4 — build out multi-link chain-walk + checkPermission + chain-depth pre-check.
**Severity: non-blocking — RESOLVED at S4.** `capability.jl` now implements the full §5.5
multi-link chain-walk, §5.6 attenuation, §5.7 delegation caveats, §5.1 revocation, the §5.2
`check_permission` scope test against the resolved handler pattern, and the §4.10(b)
chain-depth pre-check → `400 chain_depth_exceeded`. Oracle `capability` 12/12, `authz` 6/6
(2 extension skips), `security` 28/28, `multisig` 11/11 all green.

## A-JULIA-011: §4.10 413-before-buffering vs request_id correlation on a length-prefixed stream

**V8 section:** §4.10 resource bounds (finite max inbound payload → 413 before buffering the body);
§3.6 / §4.1 "every EXECUTE receives an EXECUTE_RESPONSE"; §4.9 "keep serving after every rejection"
**Profile field:** `[async].blocking_discipline`; `Wire.MAX_FRAME`
**Your guess:** `read_frame` checks the 4-byte length prefix and, if it exceeds `MAX_FRAME`
(16 MiB), raises `FrameTooLarge` **without reading the body** (honoring "before buffering"), and the
reader loop then **closes the connection** rather than emit a correlated 413.
**Rationale:** these three MUSTs are in tension on a length-prefixed framing: to keep the connection
serving you must consume the oversize body to resync the stream — but that is exactly the buffering
§4.10 forbids; and the `request_id` needed to correlate a 413 response lives *inside* that unread
body, so a correlated 413 is impossible without buffering. Closing is the only choice that honors
"before buffering". Possibly already cohort-settled (Zig has the same `max_frame` → `FrameTooLarge`
seam) — flagged for confirmation, not asserted as a novel defect.
**Escalation:** arch — clarify whether an over-large-frame rejection must carry a correlated
`request_id` / whether the connection is expected to survive it on a length-prefixed transport;
if "close is conformant," record it. **Severity: non-blocking — RESOLVED at S4 (cohort-settled,
no arch escalation needed).** The oracle's `resource_bounds.r1` probe PASSES on
close-without-response: *"declared_max_payload=16777216 → wrote 16778240-byte length prefix;
connection closed without a response frame"* → PASS. So **close is conformant** on a
length-prefixed transport (a correlated 413 is impossible without buffering the request_id that
lives inside the unread oversize body) — exactly as flagged. Recorded, not a defect.

## A-JULIA-012: AGILITY-UNKNOWN-1 — unsupported key_type at authenticate → 400, not 401

**V8 section:** §4.6 authenticate / v7.66 §4.4 surface-6 (AGILITY-UNKNOWN-1)
**Profile field:** absent (dispatch-boundary status mapping)
**Your guess:** at `authenticate`, parse the claimed `peer_id` and, if its key_type varint
prefix ≠ `0x01` (Ed25519), return `400 unsupported_key_type` BEFORE the identity-binding
check. An unsupported key_type is a negotiation-class 400, not a `401 identity_mismatch`.
**Rationale:** the AGILITY-UNKNOWN-1 probe sends `key_type=0xFD`; the peer_id it presents
encodes that prefix, so `peerid_of_pubkey(pubkey)` (key_type 0x01) never matches → the naive
path returns 401. The spec wants the peer to reject the *unsupported key type* explicitly
(400) so a client can distinguish "unknown algorithm" from "wrong identity". Matches the
cohort (Zig peer.zig authenticate hardening).
**Escalation:** operator (settled cohort behavior; corroborated, not novel). **Severity:
non-blocking — RESOLVED at S4** (format_agility 10/10 green including AGILITY-UNKNOWN-1).

## Confirmed at S2 (S1 confirm-at-phase items — closed)

- **A-JULIA-001** (Julia version + tarball sha256): CLOSED. `julia-1.11.5-linux-x86_64.tar.gz`
  sha256 `723e878c642220cc0251a0e13758c059a389cadc7f01376feaf1ea7388fe8f9c` filled into
  `containers/julia-toolchain/Containerfile` and verified against the official
  `julialang-s3.julialang.org/bin/checksums/julia-1.11.5.sha256`. Image builds clean,
  `julia --version` → 1.11.5, runs `--network=none` thereafter.
- **A-JULIA-002** (hand-rolled canonical CBOR): CONFIRMED. The map_keys + float spike and the
  full 71-vector corpus pass byte-identical on the first run, zero codec-logic fixes.
- **A-JULIA-003** (Ed25519 via system libsodium `ccall`): CONFIRMED. `crypto_sign_seed_keypair`
  / `crypto_sign_detached` / `crypto_sign_verify_detached` bound via `ccall((:sym,"libsodium"),
  …)` reproduce the deterministic RFC-8032 corpus signatures byte-exactly (signature.1–3, 3/3),
  and sign→verify→tamper-reject + determinism self-tests pass. `sodium_init()` called once
  (idempotent). No Sodium.jl, no network fetch.
- **A-JULIA-006** (multiple-dispatch branch exclusivity): CONFIRMED. `Vector{UInt8}`→mt2 vs
  `String`→mt3 and `Bool` (≺ `Integer`)→mt7 vs `Integer`→mt0/1 dispatch cleanly with no
  shimmer; arrays built as `Vector{Any}`→mt4 never collide with byte-strings.
- **A-JULIA-007** (byte-length text) & **A-JULIA-008** (fixed-width UInt64 head-form self-test):
  CONFIRMED — the mandatory `[2^63, 2^64-1]` boundary self-test passes (`1b8000000000000000` …
  `1bffffffffffffffff`, nint-min `3bffffffffffffffff`), and a 2-byte-UTF-8 string encodes with
  a byte-length (not code-point) prefix.

---

### Settled cohort traps pre-resolved (provenance only — do NOT re-burn)

- **peer_id** derives from the §1.5 canonical-form table: `hash_type = 0x00`
  identity-multihash, digest = the RAW 32-byte Ed25519 public key (no `SHA256(pubkey)`
  skeleton). Wire form = `Base58(key_type || hash_type || digest)`. §7.4 defers to §1.5 on
  the v0.8.0 snapshot. (corroborates A-ZIG-001 / A-OC-007 / A-CL-002 / Tcl / Fortran.)
- lowercase `%02x` hex for §3.4/§3.5 tree-paths (A-CL-009).
- §5.2 authz trichotomy 401 / 403 / 401-unresolvable.
- entity `data` is an arbitrary ECF value, NOT necessarily a map (A-JAVA-010).
- §4.10 chain-depth pre-check → 400 chain_depth_exceeded (depth 64); 16 MiB payload → 413
  payload_too_large.
- §7b store-race-safety (structural here) + TCP_NODELAY + no blocking on the scheduler.

---

## S5 finalization (2026-07-12)

All A-JULIA items are resolved or owner/escalation-tagged; **none blocks publish**.

- **A-JULIA-001/002/006/007/008** — CLOSED at S2 (confirm-at-phase items).
- **A-JULIA-003** — CONFIRMED at S2 (Ed25519 via system libsodium `ccall`, RFC-8032 corpus
  byte-exact). No arch escalation.
- **A-JULIA-004** (Ed448/SHA-384 agility) — **deferred by design** (floor is Ed25519 +
  SHA-256; opt-in C-ABI `ec_ed448_*` sub-package when an adopter scopes it). Owner: operator.
- **A-JULIA-005** (real multithreading substrate) — out of scope for `--profile core`;
  documented alternative. Owner: operator.
- **A-JULIA-009** (`Pkg.test()` vs `--network=none`) — RESOLVED via the direct-file offline
  gate form (`julia --project=. test/*.jl`); routed to **research** as a profile
  `[build].test_command` note (carry the offline variant alongside the published `Pkg.test()`
  form). Non-blocking; the reproducible gate runs green via `run-conformance.sh`.
- **A-JULIA-010/011/012** — RESOLVED at S4 (multi-link chain-walk + scope check;
  close-without-413 confirmed cohort-settled; unsupported key_type → 400). No arch escalation.

No new blocking items. No fresh spec finding surfaced (corroboration outcome, as expected).
