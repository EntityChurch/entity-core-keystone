# entity-core-protocol-nim — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/nim-toolchain:latest` (Nim 2.2.2, fedora:43, system libsodium)
**Status:** ✅ **Packaging COMPLETE** — the peer is a native, stdlib-only Nim package
(`entity_core_protocol.nimble` + `src/` tree) that compiles (`nim c`, Nim → C → gcc) and boots
to `LISTENING` in-container, sealed-offline. Registry (nimble) publish **deferred**
(`0.1.0-pre`), matching the cohort convention.

> **Honest framing (ADR-0012):** Nim is a Tier-3 **corroboration / generator-robustness** peer
> sharing the cohort's generation lineage — the 682·0F pass is **cohort-consistent, not
> independent convergence**. No fresh spec finding surfaced. All conformance numbers are
> oracle-pinned (`682·0F @ cc1970f`, P 293 / W 293 / F 0 / S 96); every skip is bisected in
> `CONFORMANCE-REPORT.md`.

## Release-readiness checklist

| Artifact | State | Notes |
|---|:---:|---|
| `README.md` | ✅ | What the peer is (compile-time macro/template canonical CBOR, fixed-width `uint64` head-form + mandatory `[2⁶³,2⁶⁴−1]` self-test, native `{.importc.}` libsodium crypto floor), build/test/run (offline in-container run scripts), conformance badge **682·0F @ cc1970f**, Ed448-deferred note, ADR-0012 honest framing |
| `CHANGELOG.md` | ✅ | `0.1.0-pre` entry; spec pinned "tracks ENTITY-CORE-PROTOCOL v0.8.0 (V8)"; honest-framing note |
| `LICENSE` | ✅ | Apache-2.0 (byte-identical copy of the repo-root Apache-2.0 text; per `profile.toml [license]`; libsodium ISC is Apache-compatible) |
| `entity_core_protocol.nimble` | ✅ | Package metadata: `version = "0.1.0-pre"` (**was `0.1.0` — corrected to carry the `-pre`**, and documented in-file that this is the PACKAGE version, NOT the spec version v0.8.0), `license = "Apache-2.0"`, `bin = @["host"]`, `requires "nim >= 2.0.0"`, in-repo `conformance`/`smoke` tasks. **No third-party nimble deps** (crypto is system libsodium via `{.importc.}`; codec/base58/varint hand-rolled; asyncdispatch/tables/options/unittest are stdlib) |
| CI (`.github/workflows/nim.yml`) | ✅ | Podman offline three-gate: S2 codec 71/71 → S3 loopback smoke → S4 `validate-peer --profile core` (asserts `summary.failed == 0`). Mirrors the cohort pattern (zig/haskell/swift/fortran/julia); read-only permissions, no CD, no publish |
| Version-pin | ✅ | Library `0.1.0-pre`; spec `v0.8.0 (V8)`; oracle `cc1970f`; Nim toolchain `2.2.2` (tarball sha256 verified, A-NIM-005) |
| Ambiguity log finalized | ✅ | All A-NIM-001..010 owner/escalation-tagged; S5 finalization footer added (`SPEC-AMBIGUITY-LOG.md`) |
| Conformance badge | ✅ | README links `status/CONFORMANCE-REPORT.md` (682·0F @ cc1970f) |
| S2/S3/S4 floors | ✅ | S2 codec 71/71 · type registry 53/53 · S3 smoke 7/7 · S4 682·0F — unregressed |

## Version-pin decision

- **Version:** `0.1.0-pre`. The pre-existing `.nimble` had `version = "0.1.0"` — **missing the
  `-pre`** the whole cohort carries (and the same field-hygiene trap the Julia peer hit, where
  the *spec* `0.8.0` had leaked in; here it was merely a promoted-too-early `0.1.0`). Corrected
  to `0.1.0-pre` (the spec version v0.8.0 is tracked in CHANGELOG/README, not in the package
  `version` field — a comment now says so in the manifest). Promote to `0.1.0` when S4 stays
  green **and** an external consumer confirms — same deferred state as OCaml / Elixir / Zig /
  Fortran / Julia.
- **Confirmed:** the `.nimble` `version` reads `0.1.0-pre`, **not** `0.8.0` and not `0.1.0`.
- **Spec / oracle:** tracks **v0.8.0 (V8)** at oracle **`cc1970f`** (core-gate fingerprint
  `8261a033…`); Nim toolchain pinned `2.2.2` (fallback line `2.0.14`).

## Publishing (deferred — matches the cohort)

Per `profile.toml [publishing]`: Nim's registry is **nimble** — a git-indexed directory
(`packages.json` in `nim-lang/packages`), NOT a binary registry. "Publishing" = tag a git
release carrying this tree with a working `.nimble` and open a PR to the packages index (the
SWI-pack / Quicklisp-git model). A package need not be registered to be installed by git URL.
`repository_url` / `registry_url` are TBD on first publish — the same deferred `0.1.0-pre` state
as the rest of the cohort. **Registry upload is an operator decision after review;
`/entity-rosetta` never publishes.**

## Operator handoff (deferred registry publish)

1. Review this tree (`README.md` / `CHANGELOG.md` / `LICENSE` / `entity_core_protocol.nimble` / CI).
2. When a community pull exists: set `profile.toml [publishing] repository_url`, tag a git
   release (`0.1.0-pre` → `0.1.0` once an external consumer confirms + S4 stays green), open the
   `nim-lang/packages` PR.
3. Ed448 / SHA-384 agility is deferred (floor is Ed25519 + SHA-256); wire the opt-in agility
   sub-library over the C-ABI `ec_ed448_*` / `ec_sha384` (hybrid-FFI) or OpenSSL
   `EVP_PKEY_ED448` when an adopter scopes it. The floor peer ships one crypto library
   (libsodium) + entity-C-ABI-free.

## The peer is complete through the conformance gate

S1 (profile — Tier-3 corroboration/robustness; compile-time-metaprogramming codec + fixed-width
`uint64` head-form) → S2 (codec **71/71**, `[2⁶³,2⁶⁴−1]` head-form self-test byte-exact at
compile time + run time; native crypto via `{.importc.}` libsodium; first compile-run, 0 codec
fixes) → S3 (peer machinery: two-peer loopback smoke 7/7; asyncdispatch single event loop,
structural §7b) → S4 (`--profile core` **682·0F** @ `cc1970f`, genuine 2-of-3 multisig
accept-path + 4/4 unit, §6.11 reentry live via `io.pending`, type registry 53/53,
origination-core 3/3) → **S5 (packaged)**.

The peer closed as **corroboration** — the spec's determinism constraints (canonical CBOR, the
fixed-width head-form trap, byte-vs-text as a static type distinction) are carried cleanly by a
compile-time-metaprogrammed codec on a GC'd, native-C-backend substrate, and §7b store-safety is
structural on the single-threaded event loop. Steady-state value is now the Tier-tracked re-run
on future amendments.

---

## Ready-to-lift blocks for the OVERSEER (do NOT let the sub-agent edit the shared files)

The overseer integrates these into `CONFORMANCE-MATRIX.md` and `research/LANDSCAPE.md`. The
sub-agent wrote ONLY under `protocol-generator/nim/`.

### Proposed `CONFORMANCE-MATRIX.md` — §1 Primary status table row

> Tier note: Nim's `profile.toml` classes it **tier-3** (LANDSCAPE Tier 3,
> corroboration/generator-robustness). Unlike the recent **probe**-tier rows
> (Tcl/Rexx/Fortran/Forth/Smalltalk/APL, which are all **FFI-hybrid**), Nim's floor is **fully
> native** (hand-rolled codec + libsodium via native `{.importc.}` in-process interop, the C
> peer's crypto story) — so it sits with the native T3 rows (Zig/C/C++). Suggested Tier cell
> `3`; overseer may prefer `probe` for post-release-track grouping (as with Julia).

```
| **Nim** | 3 | v0.8.0 | `cc1970f` | 682 · **0F** | native hand-rolled (**compile-time macro/template** canonical CBOR) | native — libsodium (native `{.importc.}` C interop) | deferred (libsodium has no Ed448) | nimble (git-indexed), `0.1.0-pre` |
```

### Proposed `CONFORMANCE-MATRIX.md` — §2 Capability & parity table row

```
| Nim | 3 | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + 4/4 unit | **single-thread asyncdispatch event loop (structural) + §6.11 `io.pending` reentry** | **compiles-to-C / ARC-ORC deterministic GC / compile-time-metaprogramming codec / fixed-width uint64** |
```

### Proposed `CONFORMANCE-MATRIX.md` — intro-paragraph sentence (cohort count + recap)

> The intro currently says "Cohort: 28 peers (incl. … APL …)". Add Nim to the count and a
> recap clause in the same style (and, if Julia was added by the parallel session, sequence Nim
> after it):

```
**Nim** (the compiles-to-C corroboration/generator-robustness peer) was measured **natively** at `cc1970f` (**682·0F Result: PASS**, 293P/293W/0F/96S, 0 fail-counting skips; genuine 2-of-3 accept-path passed + a 4/4 in-peer unit; type registry 53/53; origination-core `dispatch_outbound_reentry` 3/3) — reached with a **fully NATIVE floor** (no entity C-ABI): a hand-rolled canonical CBOR codec whose CBOR major-type dispatch is resolved at **compile time** via `macro`/`template`/`static:` (the Zig `comptime` result on a GC'd, native-C-backend substrate; the `[2⁶³,2⁶⁴−1]` fixed-width `uint64` head-form self-test runs in the Nim VM at compile time AND at run time), and Ed25519 + SHA-256 via **system libsodium through native `{.importc.}` C interop** (in-process, the C peer's crypto story — not the keystone C-ABI FFI-hybrid the probe rows use). Structural §7b store-safety from the single-threaded `asyncdispatch` event loop; ARC/ORC deterministic GC is a third memory idiom between the tracing-GC and manual-free peers. No fresh spec finding (corroboration outcome).
```

### Proposed `research/LANDSCAPE.md` — Tier-3 table row (replace the `not-started`/`ffi` Nim row at line 43)

```
| **Nim** | T3 | **hand-rolled ECF, compile-time macro/template dispatch** (A-NIM-001; `cbor` package gives no ECF canonical guarantees — declined) | **libsodium via native `{.importc.}` C interop** (Ed25519 + SHA-256; the C peer's crypto story, in-process not the entity C-ABI; **Ed448 gap** — libsodium has no Ed448 → opt-in agility sub-library deferred A-NIM-004) | **native floor** (hand-rolled codec + system libsodium; ZERO nimble registry deps, stdlib asyncdispatch/tables/options; `--network=none`) — **ffi default overturned** (A-NIM-001) | **✅ S1→S5 green** — 682·0F @ `cc1970f` (293P/293W/0F/96S); corroboration/generator-robustness peer on the **compile-time-metaprogramming codec** + **fixed-width uint64 head-form** + **ARC/ORC deterministic-GC** axes; genuine 2-of-3 accept-path + 4/4 unit; origination-core `dispatch_outbound_reentry` 3/3; publish-ready `0.1.0-pre`. See `protocol-generator/nim/status/`. |
```

### Proposed `research/LANDSCAPE.md` — post-release-track / probe table row (optional)

> If the overseer keeps Nim in a "Post-release" / native-corroboration table alongside Julia:

```
| **Nim** | **compiles-to-C substrate** — compile-time macro/template canonical CBOR codec (Zig `comptime` on a GC'd C-backend) + fixed-width `uint64` head-form + ARC/ORC deterministic GC | **native** (hand-rolled canonical CBOR + Ed25519/SHA-256 via system libsodium native `{.importc.}` interop; NO entity C-ABI) | **✅ S1→S5 green** — 682·0F @ `cc1970f`; corroboration (no fresh finding). `protocol-generator/nim/`. |
```
