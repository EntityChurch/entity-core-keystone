# entity-core-protocol-tcl — Phase S1 summary

**Phase:** S1 (profile research + authoring)
**Date:** 2026-07-10
**Peer #:** 23 (first alien-substrate probe past the release cohort)
**Spec surface:** v0.8.0 / V8 (`protocol-generator/shared/spec-data/v0.8.0/`)
**Oracle target (S4):** `entity-core-go` public HEAD `cc1970f` (core-gate fingerprint
`8261a033…`); `--profile core` target = **0 FAIL**.
**Exit status:** ✅ S1 complete — profile fully populated (no `TBD`), rationale +
ambiguity log + container authored. No blocking ambiguity items.

## What Tcl is here for

The **first Everything-Is-A-String (EIAS)** peer. It probes the least-saturated
wire-touching axis — the **string/encoding model** — from the extreme end: a value
model with *no intrinsic type*. A canonical wire format needs one unambiguous CBOR
major type per value; EIAS supplies none. The bet is that this forces the byte-vs-
text (A-TCL-001), length-in-bytes (A-TCL-002), and int-vs-float-intent (A-TCL-003)
seams into the open and either surfaces a spec-precision finding or confirms the
spec is tight enough to oblige an explicit tagged value model (the expected result,
corroborating the type-registry "render from the model, don't infer" lesson on a
substrate with no types to reflect).

## Decisions (see `arch/PROFILE-RATIONALE.md` for the why)

| Surface | Decision |
|---|---|
| Codec strategy | **ffi-hybrid** — hand-rolled canonical CBOR in pure Tcl; crypto over the C-ABI (`libentitycore_codec`) via `cffi`. COBOL's shape. |
| CBOR | hand-rolled (A-005, 7th peer); engine = `binary format`/`binary scan`; f16 leg hand-rolled (A-TCL-006) |
| Ed25519 / SHA | C-ABI FFI via `cffi` (no native Tcl EdDSA exists); Tcllib `sha256` = FFI-free SHA-floor fallback only |
| Ed448 | C-ABI FFI, opt-in agility package, deferred (floor ships first) |
| Integer model | **native bignum** (libtommath) — free full uint64/nint range, no fixed-width trap (CL/Elixir/Python/Ruby/Prolog class) |
| Concurrency | **single-threaded event loop** (`chan event`+`vwait`) — structural §7b store-safety; §6.11 reentry free (PHP/Dart class, 3rd event-loop substrate) |
| Error model | Tcl 8.6 `try`/`throw`/`trap` with structured `-errorcode`; absent = tagged `{present 0}` (A-TCL-007) |
| Naming | lowercase `snake_case` procs, `::entity::core::*` namespaces, ensemble public surface |
| Build / test | interpreted (no compile gate); `pkgIndex.tcl`; **tcltest** (bundled, standard) |
| Packaging | git + `pkgIndex.tcl`; Tcllib inclusion later (git-indexed model) |
| Tcl version | 9.0.1 preferred (full-Unicode sharpens the probes); 8.6.15 fallback (A-TCL-004) |
| Container | `containers/tcl-toolchain/Containerfile` authored (fedora:43 + tcl + tcllib + cffi + libsodium C-ABI deps) |

## Ambiguity log state

`status/SPEC-AMBIGUITY-LOG.md` — 8 entries, **no blocking items**:
- **A-TCL-001 / 002 / 003** — the EIAS probes (byte-vs-text, length-in-bytes,
  int-vs-float intent). Two are **finding-candidates**: S2 confirms every core
  field's kind is spec-fixed; any under-specified kind is a real spec-precision
  finding → `research/stewardship/SPEC-FINDINGS-LOG.md`. Not blockers — the reason
  the peer exists.
- **A-TCL-004 / 005** — S2 build gates (Tcl major on fedora:43; cffi binding to the
  C-ABI header). Fallbacks documented in the Containerfile.
- **A-TCL-006 / 007 / 008** — local decisions (f16 hand-roll; empty-string sentinel;
  Thread-package out of scope).

## What S2 does next

1. Build `containers/tcl-toolchain:latest`; resolve A-TCL-004 (Tcl major) +
   A-TCL-005 (cffi binds `libentitycore_codec`).
2. Hand-roll `src/cbor.tcl` (+ base58, varint). **First spike: the `float` and
   `map_keys` test-vectors** (`protocol-generator/shared/test-vectors/ecf-conformance/`) —
   the shortest-float ladder + length-then-lex ordering are the highest-risk legs.
3. Drive the EIAS probes to ground: prove byte-vs-text (A-TCL-001) and int-vs-float
   (A-TCL-003) are spec-fixed for every core field, or file the finding.
4. Byte-identity vs the `wire-conformance` oracle → green before S3.

**Codec-strategy note carried to S2:** authored as `ffi-hybrid` on the assumption
the pure-Tcl canonical CBOR spike passes (Tcl's `binary` command makes this very
likely — unlike Prolog, the engine is a clean fit). If the spike unexpectedly fails,
the documented fallback is `ffi` (whole codec over the C-ABI), but that would forfeit
the paradigm probe, so it is a last resort, not the default.

## Time / scope

S1 = research + authoring only (no build; S1 no-toolchain boundary). Container is
authored, not built. Profile has every field populated. Ready for S2.
