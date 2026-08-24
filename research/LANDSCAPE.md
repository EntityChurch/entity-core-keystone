# Language Landscape — `entity-core-keystone`

**Status:** Seeded from architecture's top-40 cross-language matrix. Research stewards update as
evaluations complete and ecosystems mature.

> Source: architecture's entity-core peer-generator exploration (§3, in `entity-core-architecture`).

> ## ⚠ Read this before trusting a "Profile status" cell
>
> **This file's per-language status columns are a partial historical build log, not the current
> roster.** They were written as peers were selected and have not been mechanically refreshed since
> the cohort passed roughly 22 peers. Several rows below still read `not-started` for languages that
> are built and gate-green (`Python`, `Java`, `C`, `C++`, `Kotlin`, `PHP`, `Dart`, `Ruby`, `Prolog`,
> and others), and the "candidate follow-ons" list names peers that have since shipped.
>
> **For current state, use these instead:**
>
> | Question | Authoritative source |
> |---|---|
> | Is peer X built, and what did it score? | **`CONFORMANCE-MATRIX.md`** §1 |
> | What is peer X *for*? What axis does it probe? | **`research/PEER-ATLAS.md`** |
> | How often does peer X get re-measured? | `tools/peer-tiers.tsv` · `tools/tier-status.py` |
> | What's left to build? | `research/COMPLETENESS-ROADMAP.md` |
>
> **What this file is still good for, and it is genuinely useful:** the per-language *library and
> codec-strategy research* — which CBOR library was evaluated and why it was rejected, which crypto
> provider was chosen, which predictions the S1 spike overturned. That reasoning is durable and is
> not recorded anywhere else at this depth. The runtime-shared-family analysis (§Runtime-shared
> families) and the BEAM-family corroboration note are likewise still current and load-bearing.

> **Forward-looking build queue** (what's left to build + priority — the completeness phase):
> `research/COMPLETENESS-ROADMAP.md`. This file is the current-state roster; that one is the tracker.
> The whole-territory paradigm cartography (every family + viability filter): `research/PARADIGM-MAP.md`.

> ## ⚠ These tiers are NOT the maintenance tiers
>
> **This file's Tier 1–5 classify the *language landscape*** — major platform → functional/niche —
> and answer *"what is worth building, and what codec strategy will it need."* They are a
> **selection** instrument.
>
> **How often a built peer gets re-measured is a different axis entirely**, and lives in
> `CONFORMANCE-MATRIX.md` §4 as **maintenance tiers `M1`/`M2`/`M3`/`probe`/`exploratory`**, defined
> per-peer in `tools/peer-tiers.tsv`. **The two genuinely do not correlate** — verified 2026-08-17:
>
> | Peer | This file's tier | Maintenance tier | Why they differ |
> |---|---|---|---|
> | **OCaml** | Tier 5 — functional/niche | **M1** — lockstep | Low landscape pull, highest discovery yield: the proven headline finder (A-OC-007) |
> | **Rust**, **Python** | Tier 1 — major platform | **M2** | Large ecosystems, but the discovery well is dry there — they corroborate rather than find |
> | **Lean** | *not in this file at all* | **M1** — lockstep | Built as the proof vector, not selected off the language landscape |
>
> Both were previously written as bare `1`/`2`/`3` and were routinely confused; the maintenance side
> now carries an `M` prefix for exactly that reason. **If you are deciding what to re-run, you want
> `tools/tier-status.py`, not this file.**

## Tier 1 — Major platforms, native codec viable (first release wave)

| Language | Tier | CBOR library | Ed25519 library | Codec strategy | Profile status | Codec | Peer | Conformance |
|---|---|---|---|---|---|---|---|---|
| **C# / .NET** | T1 | `System.Formats.Cbor` (in-box ≥ .NET 5; CTAP2 canonical) | `NSec.Cryptography` (libsodium) or BouncyCastle.NET | native | drafted + eval ✓ (`evaluations/csharp.md`) | ⏳ | ⏳ | ⏳ |
| **JavaScript / TypeScript** | T1 | **`cborg` (deterministic-first; length-first map sort, tag-reject default)** | **`@noble/curves` (Ed25519+Ed448, browser-portable)** + `@noble/hashes`; `node:crypto` Node-only alt | native | **drafted + eval ✓ (`evaluations/typescript.md`)** — peer #2 | ⏳ | ⏳ | ⏳ |
| **Python** | T1 | `cbor2` (canonical) | `cryptography` (Ed25519 ≥ 2.6) or PyNaCl | native | not-started | — | — | — |
| **Java** | T1 | `cbor-java`, `jackson-dataformat-cbor` (canonical needs care) | BouncyCastle, or JDK 15+ native Ed25519 | native | not-started | — | — | — |
| **C++** | T1 | `tinycbor` (Intel/AOSP), `cppcodec`, jsoncons | libsodium | native | not-started | — | — | — |
| **C** | T1 | `tinycbor`, `libcbor` | libsodium, monocypher | native | not-started | — | — | — |
| **Scala** | T1 | `sirthias/borer` (mature) | BouncyCastle (JVM) | native | not-started | — | — | — |
| **Haskell** | T1 | **hand-rolled ECF** (A-005 8th confirm — `cborg` is deterministic-first but NOT ECF-exact: float ladder / encoded-key-bytes map order / §6.3 recursive tag-reject are ECF policy, not a cborg mode) | **`crypton`** (the maintained fork of the *deprecated* `cryptonite`) — Ed25519 + **NATIVE Ed448** + SHA-256/384/512, audited C-backed | native | **✅ S1→S5 green — peer #8** (`protocol-generator/haskell/`, publish-ready 0.1.0-pre) | ✅ | ✅ | ✅ 573/0F PASS |

**Haskell S1 highlights:** the **coverage/robustness** peer — biggest unrepresented idiom family (pure-functional, **lazy-by-default**, monadic-IO; OCaml is strict+impure ML). Probes: idiomatic pure/monadic-IO translation; **lazy-eval correctness in a byte-exact codec** (the one *implementation*-finding bet — strict ByteString/Text + force-at-folds, A-HS-002, QuickCheck-backed); STM/green-threads for §7b (3rd data-race-free store shape). **Crypto headline: Haskell is the FIRST native-FULL-agility peer incl. Ed448** (crypton `Crypto.PubKey.Ed448`, build-proven 57B/114B/verify=True at S1 — distinct from OCaml/Zig/Swift's Ed448 gap→FFI/defer and CL's pure-Lisp ironclad; A-HS-007). Toolchain: GHC **9.8.4** + cabal **3.14.2.0** (fedora33 bindists, sha256-pinned, fail-closed, run on fedora:43); deps pinned via a committed `cabal.project.freeze` **derived from Stackage LTS 23.27** (one dated snapshot pins the whole transitive closure ≥30d old — the clean answer to Swift's A-SW-005 transitive-age trap). Container `entity-core-keystone/ghc-toolchain:latest` BUILT + crypton SHA-256/384 + Ed25519 + Ed448 verified in-container. No new spec defects (peer-id §7.4-vs-§1.5 found already reconciled in v7.74 §7.4 body — 5th corroboration of the reconciliation).
| **F# / .NET** | T1 | shares `System.Formats.Cbor` | shares NSec / BouncyCastle | native | (free with C#) | — | — | — |
| **Rust** | T1 | `ciborium`, `minicbor` | `ed25519-dalek` | native | (covered by `entity-core-rust`) | ✅ | ✅ | ✅ |
| **Go** | T1 | `fxamacker/cbor` | `crypto/ed25519` (std) | native | (covered by `entity-core-go`) | ✅ | ✅ | ✅ |

## Tier 2 — Common ecosystem languages, mixed native/FFI

| Language | Tier | CBOR library | Ed25519 library | Codec strategy | Profile status |
|---|---|---|---|---|---|
| **Kotlin** | T2 | `kotlinx.serialization` CBOR (canonical less mature) | BouncyCastle (JVM); could share Java path via interop | interop OR ffi (profile decides) | not-started |
| **Swift** | **peer #7** | **hand-rolled ECF** (A-005 7th confirm; `SwiftCBOR` won't give ECF canonical) | **`swift-crypto`** (BoringSSL-backed CryptoKit API on Linux; CryptoKit itself is Apple-only) — Ed25519+SHA-2 native; **Ed448 gap → hybrid-FFI deferred** (A-SW-001) | native | **✅ S1→S5 green** — first genuinely spec-first peer on the stamped v7.74 surface; 573/0F PASS; probed grapheme-String/UTF-8-byte (A-SW-002, converged-null) + ARC/actor; **§7b finding: structured-concurrency bounded pool hostile to blocking syscalls → dedicated OS threads**; publish-ready 0.1.0-pre. See `protocol-generator/swift/status/`. |
| **PHP** | T2 | `spomky-labs/cbor-php` | libsodium (in-box ≥ 7.2) | native (with audit) | not-started |
| **Ruby** | T2 | `cbor-ruby`, `cbor-pure` | RbNaCl (libsodium) | ffi | not-started |
| **Dart / Flutter** | T2 | `cbor` package | `cryptography` package, `pinenacl` | ffi | not-started |
| **Elixir** | **peer #4** | hand-rolled ECF (no BEAM lib does ECF — A-005) | OTP `:crypto` (OpenSSL; Ed25519 **+ Ed448** + SHA-2) | **native** (ffi default overturned) | **✅ S1→S5 done** — `--profile core` PASS first run 0 fixes (568/0F = OCaml fixed point); BEAM actor model; zero Hex deps; publish-ready 0.1.0-pre |
| **Erlang** | T2 | hand-rolled ECF (shares Elixir's BEAM substrate) | OTP `:crypto` (same backend as Elixir) | native | not-started (corroboration peer — see BEAM-family note) |

## Tier 3 — Newcomers / systems languages, FFI codec preferred

| Language | Tier | CBOR library | Ed25519 library | Codec strategy | Profile status |
|---|---|---|---|---|---|
| **Zig** | **peer #5** (parallel harness, spec-first) | **hand-rolled ECF, comptime dispatch** (A-005; `std`-only, no zig-cbor/libsodium) | **`std.crypto`** (Ed25519+SHA-2 in-tree); **Ed448 gap** (A-ZIG-002 — no native, no BouncyCastle-equiv → hybrid-FFI deferred) | **native floor, std-only ZERO-dep** (ffi default overturned) | **✅ S1→S5 green** 568/0F spec-first; no-GC/error-union/comptime; lightest supply-chain in cohort; native u64+overflow-trap; only memory-ownership+leak-correctness dimension. See `protocol-generator/zig/status/`. |
| **Odin** | T3 | **hand-rolled ECF** (`core:encoding/cbor` is canonical-*aware* but bytewise map-sort + no decode tag-reject → insufficient) | **native pure-Odin `core:crypto`** (Ed25519+SHA-2, FFI-free; Ed448 deferred) | **native floor, core-only ZERO-dep** (ffi prediction overturned) | **✅ S1→S5 green** — 71/71 codec · **292·0F @ cc1970f**; no-GC `context` allocators / no-exceptions `or_return` / no-package-manager; native RFC-8032 §7.1 KAT. See `protocol-generator/odin/status/`. |
| **Nim** | T3 | **hand-rolled ECF** (compile-time `macro`/`template` major-type dispatch; `cbor` pkg declined — A-NIM-001, A-005 pattern) | **libsodium via native `{.importc.}` C interop** (Ed25519 + SHA-256; **Ed448 gap** → opt-in FFI deferred) | **native floor** (ffi first-pass overturned — Nim compiles to C, so `{.importc.}` is in-process, not a foreign bridge) | **✅ S1→S5 green** — 682·0F @ `cc1970f` (293P/293W/0F/96S); corroboration / generator-robustness peer on the **compile-time-metaprogramming codec** + fixed-width-uint64 axes; native codec **71/71 first-run** (0 fixes), genuine 2-of-3 accept-path + `tests/tmultisig.nim` 4/4, origination-core 3/3; publish-ready `0.1.0-pre`. **Surfaced F32** (A-NIM-009 §4.2/§4.4-vs-§5.2a author-absent status → arch). |
| **Crystal** | T3 | **hand-rolled ECF** (no shard does length-first + f16 + recursive tag-reject) | **libsodium direct `lib`/`fun` binding** (stdlib `openssl` has no PKey; Ed448 deferred) | **native floor** (ffi prediction overturned) | **✅ S1→S5 green** — 71/71 codec · **292·0F @ cc1970f**; the **Ruby-overfit check** (compiled/typed/fixed-width/CSP-fiber); graceful-shutdown hardening on the 1.20 preview scheduler (A-CRY-011). See `protocol-generator/crystal/status/`. |
| **D** | T3 | `dcbor` (smaller) | libsodium via Deimos bindings | ffi | not-started |
| **Julia** | T3 | **hand-rolled ECF** (**multiple-dispatch** canonical CBOR; `CBOR.jl` declined — A-JULIA-002, no ECF guarantees) | **system libsodium via `ccall`** + `SHA` stdlib (native-audited-lib tier, NOT the C-ABI; **Ed448 gap** → opt-in FFI deferred A-JULIA-004) | **native floor** (ffi first-pass overturned; zero registered packages → `--network=none`) | **✅ S1→S5 green** — 682·0F @ `cc1970f` (292P/294W/0F/96S); corroboration / generator-robustness peer on the **multiple-dispatch codec** + **UInt64/BigInt hybrid-numeric** axes; native codec **71/71 first-run** (0 fixes), genuine 2-of-3 accept-path + `test/multisig_accept.jl` 8/8, origination-core 3/3; publish-ready `0.1.0-pre`. **Corroborated F32.** Tooling note A-JULIA-009 (`Pkg.test()` needs net even stdlib-only → offline path is direct `julia --project`). |
| **COBOL** (GnuCOBOL) | T3 | **FFI** (no COBOL CBOR lib) | **FFI** (C-ABI, no COBOL crypto) | **ffi everything** | **queued — pre-release slate #6 (discovery bet, spike-first)**; alien substrate: PIC fixed-width records vs CBOR var-length, COMP-3 decimal vs binary int head-form, recursion support is the go/no-go |

## Tier 4 — Lisp family

| Language | Tier | CBOR library | Ed25519 library | Codec strategy | Profile status |
|---|---|---|---|---|---|
| **Clojure** | T4 | `clj-cbor`, OR BouncyCastle via JVM interop | BouncyCastle via JVM interop, or libsodium via FFI | interop (JVM) or ffi — profile decides | not-started |
| **Common Lisp (SBCL)** | **peer #6** (parallel harness, spec-first) | **hand-rolled ECF** (A-005; not cl-cbor/cl-conspack) | **`ironclad`** — agility-COMPLETE native pure-Lisp (Ed25519 **+ Ed448** + SHA-256/384), KAT-gated (larger trust surface than an audited primitive) | **native, no FFI** (1 dep, BSD-3) | **✅ S1→S5 green** 568/0F = OCaml fixed point; CLOS **multiple** dispatch (idiom-neutrality probe A-CL-008) + condition system; **found NEW spec defect A-CL-009 hex-case**. See `protocol-generator/common-lisp/status/`. |
| **Scheme (Racket)** | T4 | smaller landscape | libsodium via FFI | ffi | not-started |
| **Racket** | T4 | smaller direct CBOR | libsodium via FFI | ffi | not-started |

## Tier 5 — Functional / niche

| Language | Tier | CBOR library | Ed25519 library | Codec strategy | Profile status |
|---|---|---|---|---|---|
| **OCaml** | **peer #3** (elevated from T5 — arch pick as the spec-tightness "distant idiom") | **hand-rolled** (decided: no opam lib gives ECF; A-005 confirmed by spike) | **mirage-crypto-ec 2.1.0** (Ed25519 ✓; **Ed448 native gap** — mirage#112, A-OC-002) + digestif 1.3.0 | **native** (S1 spike overturned the ffi-default: hand-rolled canonical CBOR → 69/69 first run) | **✅ S1+S2 done** — native codec 69/69 byte-identical; result-not-exn + eio idioms; new probe A-OC-004. S3 next (needs F12/v7.73). See `protocol-generator/ocaml/status/`. |
| **Lua** | T5 | `lua-cbor` (light) | libsodium via FFI | ffi | not-started |
| **Elm** | T5 | browser-only, narrow use | browser crypto APIs | (defer) | not-started |

## Runtime-shared families (codec sharing reduces work)

| Family | Languages | Implication |
|---|---|---|
| **JVM** | Java, Kotlin, Scala, Clojure | Once a JVM codec is built (likely from Java first), siblings can interop into it as a profile choice |
| **.NET** | C#, F#, VB.NET | C# work makes F# nearly free; VB.NET is low-priority follow-on |
| **BEAM** | Erlang, Elixir | **CONFIRMED post-Elixir-S3:** the family shares one substrate — same BEAM, same OTP `:crypto` (native Ed25519+Ed448+SHA-2, no FFI/`enacl` needed), same process model, same bit-pattern decoder, same bignums. The original "one binding serves both" prediction holds *and is stronger than expected* (native, not ffi). **Implication for Erlang peer selection:** it would be a **corroboration / generator-robustness peer, not a discovery peer** — codec/crypto/concurrency findings (S8 convergence, no-uint64-trap, the actor-model seam [[A-ELX-006]], the emit-delivery fork [[A-ELX-007]]) are BEAM facts and would *replicate*, not independently surface. Only-new-info from Erlang: proving the generator isn't Elixir-template-overfit on the BEAM (macros/structs→records/no-pipe) + rebar3 packaging. Higher marginal spec value lives in a *distinct* substrate (JVM/Swift/Zig/Haskell/Lisp — different crypto+numeric+type-system traps). The full **peer-selection compass** (discovery yield is *substrate*-bound, not idiom-bound; prioritize novelty on a wire-touching axis — integer width / float model / crypto availability / string model — over concurrency/error-idiom/packaging novelty) is formalized in the four-peer architecture milestone review (§3+§7) and **refined post-Zig/CL** in the six-peer synthesis (§2.3) — empirically, the productive axes are crypto-availability + integer-model (now saturated) + memory-model + **string/encoding-model (unsaturated, highest fresh yield)** + dispatch/error (shown idiom-neutral, low yield). Next peer Swift targets the unsaturated string/encoding + ARC-memory axes. |
| **C-interop** | Zig, Odin, Nim, D, Lua, OCaml, Crystal, … | All consume `entity-core-codec-ffi` via C ABI; new language ≈ shim work |

**Implication:** top-40 coverage doesn't require 40 independent implementations — about 15–18 distinct codec builds + shim work for the runtime-shared cases.

## Reading the matrix

- **~11 languages can do native codec credibly today** — first release wave (minus Rust/Go which are already done by reference impls)
- **~7 languages cleanly want hybrid** (FFI codec, native peer)
- **~8 languages clearly want FFI codec**

## Pre-release slate (shipped)

The pre-release slate added five peers before the release tag, in build order
**Kotlin → PHP → C++ → Dart → COBOL** — reach-first (Kotlin/C++/PHP/Dart) then the
one curiosity pick (**COBOL the one genuine discovery bet**, spike-first). All reach peers
are corroboration-only (the discovery well is dry on language axes). Per-peer codec/crypto
strategy and conformance results are recorded in each peer's
`protocol-generator/<lang>/status/` and summarized in `CONFORMANCE-MATRIX.md`.

> **Correction (2026-08-20).** This section previously stated that Odin was scoped but *not* built and
> that the cohort was "Odin-free." That was accurate when written against the 22-peer cohort; it is
> now wrong. **Odin was built** — it is maintenance tier M3, `--profile core` 0-FAIL, and notable as
> one of the few peers with **pure-language crypto** (`core:crypto`, Ed25519 + SHA-2, FFI-free). Its
> Tier-3 row above carries the correct build detail; only this paragraph was stale.

## Post-release: alien-substrate track (in progress)

With the 22-peer cohort shipped and the maintenance loop solid, the ongoing work is
a deliberate sweep of **alien substrates** — languages whose *paradigm* is distant
enough to stress the generator and, where possible, probe the least-saturated
wire-touching axis (string/encoding model). These are corroboration/robustness first;
a fresh spec finding is the upside, not the expectation.

| Peer | Substrate axis probed | Codec | Status |
|---|---|---|---|
| **Tcl** (#23) | **Everything-Is-A-String (EIAS)** — no intrinsic value type; the string/encoding axis from its extreme end (byte-vs-text, length-in-bytes, int-vs-float intent) | ffi-hybrid (hand-rolled pure-Tcl CBOR + C-ABI crypto via `cffi`) | **S1 done** — profile + rationale + ambiguity log + container authored (`protocol-generator/tcl/`). S2 (codec) next. |
| **x86-64 assembly** | **The bare machine** — the extreme end of the substrate axis: no runtime, no allocator, no types, no error model, no strings; only registers, memory, and `syscall`. Isolates "what is protocol" from "what is machine." Template for an ISA family (ARM64 + RISC-V ports) **and the concurrency template for WebAssembly** (see the session note). | FFI-hybrid (L1: entire entity codec + crypto + peer-id via `libentitycore_codec`; envelope/data-map CBOR + the whole authority interior hand-rolled in asm); L2 asm-codec + L3 pure are documented stretches | **✅ S4 — `--profile core` = Result: PASS.** Hand-written GAS peer (`protocol-generator/asm-x86_64/`), measured natively at oracle `cc1970f`: **682 · 583P · 3W · 0F · 96S**, deterministic from a clean `make clean && make host`, **matching the reference `entity-peer` on every check it passes**. Full write-op surface (tree put/get/CAS/listing/delete, register/unregister, configure, revoke), genuine §5.5 K-of-N multisig accept, §6.2 dispatch-entity normalization, AND §7a.2a **concurrent reentrant dispatch-outbound** — all in hand-written asm. The 3 WARNs are benign (`r3_connection_flood` matches the reference's WARN). Three durable findings this build: **A-ASM-010** (an over-cap frame must be drained+413'd, never close a multiplexed connection — the 64 KiB→16 MiB fix + a 17 MiB `send_get_ok` buffer, both fork-crash cascades), **A-ASM-011** (per-fork `.bss` suffices for the core gate — no MAP_SHARED/epoll — because `--profile core` multiplexes stateful probes onto one connection = one fork), **A-ASM-014** (correcting an earlier "concurrent reentry is architecturally impossible for a blocking fork peer" claim — it is NOT: the reentry is one-socket, validator-as-B, handled by a single-threaded request/response frame router + a `pending_tab` demux). Not published (`0.1.0-pre`). Detail: `protocol-generator/asm-x86_64/status/`; session lessons: `research/stewardship/SESSION-2026-07-13-asm-s3-core-conformance.md`. |
| **Oz / Mozart** | **Dataflow-variable concurrency** — the 4th structural §7b store-safety shape (declarative concurrency: read-blocks-until-bound), distinct from actor/STM/CSP/thread+lock. The concurrency axis, not a wire-touching one. | FFI-hybrid (pure-Oz canonical CBOR value codec; crypto/peer-id via the `entity-codec-daemon` `Open.pipe` co-process over `libentitycore_codec` — the RPM ships zero headers, so native-functor FFI is out). Native `Open.socket` transport. | **✅ S4 — `--profile core` = Result: PASS.** `682 · 285P/301W/0F/96S @ cc1970f`; origination-core 3/3 + genuine 2-of-3 multisig accept. **Payoff (A-OZ-006):** the §6.11 demux collapses to one single-assignment dataflow variable per pending request — the variable *is* the correlation map, no side table, no yield discipline; the cleanest §6.11 substrate in the cohort. **Durable finding A-OZ-005:** on a substrate where `"" == nil`, never use `== nil` as a string sentinel, and a dispatcher MUST catch the ROOT error class → 500 (two crash-class S3 bugs). Mozart2 v2.0.1 RPM on fedora:43 (no source build). `0.1.0-pre`. Detail: `protocol-generator/oz/status/`. |
| **Io** | **Pure prototype-based OO** — the one object model unprobed (no classes; differential inheritance via `clone`; everything a message send). §6.6 resolution renders as a proto-chain delegation walk. Off-wire (object-model) axis — generator robustness, not a wire finding. | FFI-hybrid (pure-Io canonical CBOR with an `EcBig` sign+magnitude carrier for the uint64 tower — IoNumber is a C double; crypto/peer-id via the in-process `EntityCodec` C addon over `libentitycore_codec`). Native Socket transport. | **✅ S4 — `--profile core` = Result: PASS.** `682 · 291P/295W/0F/96S @ cc1970f`; origination-core 3/3 + genuine 2-of-3 multisig accept; concurrency incl. (t2_1 0/10000 dropped, t2_2 PASS). Built on the permanently-frozen `2026.04.20-native-final` tag (upstream master pivoted to WASM). **Durable findings:** A-IO-025/026 (single-event-loop non-blocking discipline — a "throughput ceiling" claim retracted after the Oz sibling passed the same checks with slower crypto → two fixable loop-blocking bugs), A-IO-004/007 (prototype-OO: fence dynamic dispatch with the declared-op set). `0.1.0-pre`. Detail: `protocol-generator/io/status/`. |

**Candidate follow-ons — all four have since shipped** (this list was written when they were queued;
kept because the *rationale* for each pick is the useful part): **Rexx** (EIAS + native decimal),
**Forth** (stack machine / no types — generator stress), **Fortran** (fixed-width signed-only integer
model), **APL** (array value-model). All four are built and carry `probe` maintenance tier; APL is
upstream-blocked and currently unmeasured. The selection heuristic that picked them — the
peer-selection compass, novelty on a wire-touching axis over idiom/packaging novelty — is stated in
full in `PEER-ATLAS.md` §1 and remains the rule.

The alien-substrate track above is likewise a partial log: **Smalltalk, Io, Oz, Pure Data, SQL,
Datalog, Unison, the three ISAs, and the three WebAssembly variants** all landed after these rows were
written. `PEER-ATLAS.md` §2 is the complete, current map.

## Sequencing (historical — first wave, all shipped)

1. **C#/.NET** — first language. Avalonia pulls; mature ecosystem; native codec; F# nearly free downstream.
2. **TypeScript** — after CDN-corridor closure (avoid narrative collision).
3. **C** — both a target and the FFI bridge for everyone else. Doing C native first may unlock the FFI fallback faster.
4. **Java/Kotlin** — enterprise + Android reach.
5. **Swift** — Apple ecosystem (FFI codec).
6. **Python/Rust/Go regeneration** — long horizon; once generator is reliable, regenerate the core machinery of `entity-core-{py,rust,go}` and let hand-written code retreat to the extension layer.
7. **Tiers 3–5** — sweep as community interest surfaces.

## Update protocol

- Research stewards update the per-language status columns as profiles get authored, codec/peer/conformance phases pass
- Tier moves (e.g. Kotlin native-codec-viable when kotlinx.serialization canonical hardens) require evaluation in `evaluations/<lang>.md`
- New language additions: add row, link to `evaluations/<lang>.md`, sequence into roadmap above
