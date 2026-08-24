# entity-core-keystone — Conformance & Status Matrix

**The transparency contract for adopters.** Before you pull a generated peer, check its row here. A peer being a spec-version behind, or lacking Ed448 agility, or carrying a known gap, is a **documented, tracked state** — not a surprise. "This peer doesn't do X yet" lives here, in the open, with a tier that tells you when it'll be caught up.

**Cohort:** 23 peers (incl. **Tcl** — the alien-substrate EIAS probe, newly S1→S5 with `pkgIndex.tcl` packaging + registry-publish deferred like the cohort), `--profile core` **0-FAIL** — the whole cohort now normalized onto the reproducible public-HEAD oracle **`cc1970f`** (2026-07-10 re-normalization; §3). The `--profile core` gate at `cc1970f` is **provably the same gate** the cohort converged against: its normalized core-gate fingerprint — the 16-category set + 53-type floor, comment/format-invariant — is `8261a03…`, and the now-retired pin `e8524ed`'s `profile.go` differs only by a V8 release-prep comment reword (raw `74e04e3` vs `e09a865`), a change that leaves that fingerprint untouched. So every peer's `--profile core` **0-FAIL** verdict carries forward to `cc1970f` unchanged. COBOL was measured **natively** at `cc1970f` (**291·0F Result: PASS**, one honest `t1_3_no_head_of_line` skip allow-listed). **Tcl** (the 23rd — the alien-substrate EIAS probe) was likewise measured **natively** at `cc1970f` (**682·0F Result: PASS**; the fresh total differs from the carried `665` because it was re-measured on `cc1970f`, not carried from `e8524ed` — totals are non-gating and vary by build, see the reading note; genuine 2-of-3 multisig accept-path `valid_2of3_peer_signed_accepted` passed). The other 21 peers' full-suite totals (**665**, extension-inflated + non-gating — see the reading note) were measured against the now-retired `e8524ed` build and are **carried, not re-measured**, on `cc1970f`; what `cc1970f` certifies for every row is the **core-profile 0-FAIL gate**, proven-identical via that fingerprint.² (Build order: the original 15-peer cohort, then the two large-ecosystem adoption peers Rust + Python — the 16th + 17th generated — then the reach peers C++, Kotlin, PHP, Dart; COBOL the 22nd, closing the §6.11 handler-outbound-dispatch seam.) The re-normalization + the anchor hardening it required are **CLOSED** in §3.
**Spec surface:** Entity Core **v0.8.0 (V8)** core protocol (standard extensions are out of scope — every peer below is a *core* peer). Spec-data stamp is **v0.8.0** (`protocol-generator/shared/spec-data/v0.8.0/`). The **core wire contract is byte-unchanged across the V7→V8 cutover**: the folded 0.7.76/0.7.77 increments + the V8 de-versioning were verdict-timestamp determinism, extension-side type-path renames, and release-prep only — no core map-key or wire change (see `spec-data/v0.8.0/MANIFEST.md`) — so each peer's certification carries forward unchanged. The oracle is `entity-core-go` at the reproducible public HEAD (`cc1970f`), whose core category set + type floor (`cmd/internal/validate/profile.go`) gates `--profile core`; its committed, comment-invariant anchor is the core-gate fingerprint in `tools/oracle-pin.env`.
**Conformance gate:** `validate-peer --profile core` — the extension-free categories (`connectivity`, `encoding`, `type_system`, `origination`, `resource_bounds`, `concurrency`, + the §10.1 register / §7a conformance-handler gates). **All 22 peers are 0-FAIL on this gate.**

> **Reading the conformance numbers.** Every peer's **gate** verdict is certified on the same oracle (`cc1970f`, re-normalized 2026-07-10): **0 FAIL** on `--profile core`, 0 core-floor gap — the number that matters, and it is proven-uniform via the core-gate fingerprint. The full-suite **total** (665; `passed` 291–293, `skip` 95–96) is the extension-inflated, **non-gating** count: it was measured @ the retired `e8524ed` build for the original 21 peers and @ `cc1970f` for COBOL, and varies purely from extension *matched-if-present* WARN/PASS and auto-allowlisted skips. It is carried, not re-measured, at `cc1970f` (a comment-only `profile.go` reword cannot move the core verdict; extension totals are neither gating nor re-run here). (Historical per-oracle totals — 576 @ `b30a589`, 653 @ `75c532e`/`33f35fd` — are superseded; see the oracle-vendoring policy in `research/diagnostics/oracle-vendoring-policy.md` for why totals move without any verdict changing.)

---

## 1. Primary status table

| Peer | Tier | Spec | Oracle commit | `--profile core`² | Codec | Crypto floor (Ed25519 + SHA-256) | Ed448 / SHA-384 agility | Publish |
|------|:----:|:----:|---------------|:----------------:|-------|----------------------------------|-------------------------|---------|
| **OCaml** | **1** | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — mirage-crypto-ec + digestif | **FFI-hybrid** (opt-in `entitycore_agility`) | opam, `0.1.0-pre` |
| **Swift** | **1** | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — swift-crypto | deferred (→ FFI when scoped) | SPM, `0.1.0-pre` |
| **Haskell** | **1** | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — crypton | **native** — crypton (Ed448) | Cabal, `0.1.0-pre` |
| **Go** (clean-room) | **1** | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — stdlib `crypto/ed25519` | deferred (→ FFI when scoped) | Go module, `0.1.0-pre` |
| **Lean** | **1** | v0.8.0 | `cc1970f` | 665 · **0F** | **pure-Lean proven core** + FFI crypto | **FFI** — C-ABI `ec_ed25519_*` | FFI (deferred) | Lake, `0.1.0-pre` |
| **C#** | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native (Cbor Ctap2 + handroll) | native — NSec | managed — BouncyCastle | NuGet, `0.1.0-pre` |
| **TypeScript** | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native (cborg + handroll) | native — @noble | managed — @noble | npm, `0.1.0-pre` |
| **Java** | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — JDK SunEC | JDK / BouncyCastle | Maven, `0.1.0-pre` |
| **Kotlin** | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — JDK SunEC | deferred (→ JDK SunEC / BouncyCastle) | Gradle→Maven Central, `0.1.0-pre` |
| **Elixir** | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — OTP `:crypto` | **native** — OTP `:crypto` | Hex, `0.1.0-pre` |
| **Common Lisp** | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — ironclad (pure-Lisp) | **native** — ironclad (pure-Lisp) | ASDF/Quicklisp, `0.1.0` |
| **Rust** (clean-room) | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — ed25519-dalek + sha2 | deferred (→ FFI when scoped) | crates.io, `0.1.0-pre` |
| **Python** (clean-room) | 2 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — `cryptography` (OpenSSL) | **native** — `cryptography` (Ed448) | PyPI, `0.1.0` |
| **Zig** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native (std-only) | native — `std.crypto` | deferred | source, `0.1.0-pre` |
| **C** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — libsodium | deferred (libsodium has no Ed448) | `make dist` + pkg-config |
| **C++** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — libsodium | deferred (libsodium has no Ed448) | CMake pkg + vcpkg + conan, `0.1.0-pre` |
| **Ada** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — libsodium (C binding) | deferred (libsodium has no Ed448) | Alire (optional), `0.1.0-pre` |
| **Ruby** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — stdlib `openssl` | **native** — stdlib `openssl` | RubyGems, `0.1.0.pre` |
| **Prolog** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | **FFI** (C-ABI) | **FFI** — C-ABI (library(crypto) has no Ed25519) | FFI | SWI pack, `0.1.0` |
| **PHP** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — ext-sodium (libsodium) | deferred (ext-sodium has no Ed448; → FFI) | Composer, `0.1.0-pre` |
| **Dart** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — cryptography_plus (pure-Dart) | deferred (→ FFI when scoped) | pub.dev, `0.1.0-pre` |
| **COBOL** | 3 | v0.8.0 | `cc1970f` | 291 · **0F** | **FFI-hybrid** (COBOL value-codec + C-ABI) | **FFI** — `libentitycore_codec` (libsodium) | deferred (libsodium has no Ed448) | `make dist`, `0.1.0-pre` |
| **Tcl** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **FFI-hybrid** (pure-Tcl canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` (C-shim, libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | git + `pkgIndex.tcl`, `0.1.0-pre` |

² **Oracle commit `cc1970f` certifies the `--profile core` 0-FAIL gate for every row.** For the 21 non-COBOL peers the `665` full-suite total was *measured* against the now-retired `e8524ed` build (extension-inflated + non-gating) and is **carried, not re-measured**, at `cc1970f`: the two builds' `profile.go` differ only by a comment reword, which leaves the core-gate fingerprint (`8261a03…`, the 16-category set + 53-type floor) untouched, so the core verdict is provably identical. COBOL's `291` was measured natively at `cc1970f`. A fresh full-suite re-run of the 21 on `cc1970f` is optional (non-gating) — see §3.

**Crypto-availability tiers** (the per-ecosystem story an adopter most needs): `native` = ships with runtime/stdlib or an in-language audited lib, no FFI; `managed` = a managed-code crypto package on the language's package manager; `FFI-hybrid` = native floor, Ed448 via `libentitycore_codec`; `FFI` = whole crypto surface via C-ABI; `deferred` = Ed25519+SHA-256 floor only, Ed448 not yet wired.

---

## 2. Capability & parity table

Feature parity is **not** uniform — the 5 T2 peers (C, Ada, Ruby, Prolog, Go) were built on a separate track and folded in later, so some normalization is still outstanding. This table makes the gaps visible; the catch-up items are in §3.

| Peer | Tier | Persistent identity CLI | `--validate` (§7a) | Genuine §3.6 K-of-N multisig¹ | Concurrency (§7b) | Idiom / discovery axis |
|------|:----:|------------------------|:------------------:|:------------------------------:|-------------------|------------------------|
| OCaml | 1 | `--name` | ✅ | ✅ genuine + selftest | OS-threads + mutex | strict-ML / result |
| Swift | 1 | `--name` (+`--owner-identity`, `--seed-policy`) | ✅ | ✅ genuine + test | actor-isolation (structural) | ARC / **grapheme-string** |
| Haskell | 1 | `--name` | ✅ | ✅ genuine + test | **STM (structural)** + GHC RTS | lazy / pure / monadic |
| Go | 1 | `--name` + `-seed` (Go-idiom single-dash flags) | ✅ (`-validate`) | present (5 files) — ✅ verify genuine | goroutines + mutex | static / clean-room |
| Lean | 1 | (host shell) | ✅ | ✅ genuine + **proven** (`multiSigRootOk_quorum`) | pure core (no shared store) | dependent-type / **proof** |
| C# | 2 | `--name` | ✅ | ✅ genuine (reference impl) | threads + lock | OO / exceptions |
| TypeScript | 2 | `--name` | ✅ | ✅ genuine (reference impl) | event-loop + promise-mutex | structural JS / bigint |
| Java | 2 | `--name` | ✅ | ✅ genuine + test | threads + lock | JVM / OO |
| Kotlin | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** | coroutines + concurrent-collections (atomic-per-key) | JVM / **sealed-Result + coroutines** |
| Elixir | 2 | `--name` | ✅ | ✅ genuine + test | actor-isolation (structural) | BEAM actor |
| Common Lisp | 2 | `--name` | ✅ | ✅ genuine + test | raw threads + manual | CLOS multiple-dispatch |
| Zig | 3 | `--name` | ✅ | ✅ genuine + test | threads + mutex (raced before fix) | no-GC / comptime |
| C | 3 | `-seed` (**no `--name` yet**) | ✅ | present (3 files) — ✅ verify genuine | **raw pthreads** (A-C-009 atomic fix) | **manual malloc/free** |
| Ada | 3 | `-seed` (**no `--name` yet**) | ✅ | present (2 files) — ✅ verify genuine | **protected objects (structural)** | safety-critical / contracts |
| Ruby | 3 | `--name` + `-seed` | ✅ | present (3 files) — ✅ verify genuine | GVL (released on IO) + mutex | dynamic / duck-typed |
| Prolog | 3 | `--name` | ✅ | present (11 files) — ✅ verify genuine | OS-threads + clause-DB RMW | **logic / SLD-resolution** |
| Rust (clean-room) | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** (oracle `33f35fd`) | std::thread + RwLock — **compile-enforced** | static / Result / `#![forbid(unsafe)]` |
| Python (clean-room) | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** (oracle `33f35fd`) | threads + explicit Lock (GIL-aware) | dynamic / duck-typed |
| PHP | 3 | `--name` | ✅ | ✅ genuine + accept-path **ran** | **single-thread `stream_select` event loop (structural)** | dynamic / **event-loop store-safety** |
| Dart | 3 | `--name` | ✅ | ✅ genuine + accept-path **ran** | event-loop confinement per isolate (structural) | **sealed-Result + Future / BigInt-web** |
| COBOL | 3 | `--name` | ✅ | present (11/0 pass) — ✅verify genuine | **single-threaded `poll()` loop + §6.11 reentry pump** | **FFI-hybrid / GnuCOBOL PIC records / COMP-3** |
| Tcl | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread `chan event`/`vwait` event loop (structural)** | **EIAS / everything-is-a-string / event-loop** |

¹ "Genuine" = real §3.6 M3 (structure) + M4 (distinct-signer threshold) + M6 (local ∈ signers) with a positive accept-path test, per the multisig cohort closeout. The original 10-peer cohort was verified genuine + accept-path-GREEN against oracle `33f35fd`. The 5 T2 peers carry multisig code but their genuine-vs-frame-only status was **not** independently re-verified in this consolidation — flagged ✅verify in §3. (Multisig is not in `--profile core`, so this does not affect any peer's 0-FAIL.)

**Standard host CLI surface** (the cohort convention): `--name NAME` (load Ed25519 identity from `~/.entity/peers/NAME/keypair`) · `--port N` · `--validate` (bootstrap §7a `system/validate/*` conformance handlers, OFF by default) · `--debug-open-grants` (deprecated; degenerate `default→*` seed policy) · `--help`. Go uses the same surface with Go-idiom single-dash flags. C/Ada currently expose identity via `-seed` only.

---

## 3. Maintenance state & catch-up backlog

**Standing maintenance loop (the steady state):** when a spec amendment lands and Go ships the corresponding `validate-peer` update, re-vendor the oracle, re-run **Tier-1** immediately and converge to 0-FAIL, then catch up Tier-2/Tier-3 as capacity allows. This is the engine of spec refinement now — not new languages (see the fifteen-peer architecture milestone review, §5).

| Item | Scope | Priority | Notes |
|------|-------|----------|-------|
| ~~**Oracle normalization**~~ ✅ DONE | whole cohort | — | **CLOSED.** All 17 peers re-run on one oracle `entity-core-go @e8524ed` (go HEAD) → uniform **665·0F**. Procedure + the when/why rule now live in `research/diagnostics/oracle-vendoring-policy.md`. (The 649-vs-653 phantom-build lesson is captured there as provenance hygiene: build once into repo-root, never per-peer.) |
| ~~**run-s4 oracle-path defaults**~~ ✅ DONE | C, Ada, Ruby, Prolog (+ Rust, Python) | — | **CLOSED.** All `run-s4.sh` + `run-origination-core.sh` defaults normalized to the repo-root `/work/output/s4-oracles/…` convention; they now run with no `ORACLE` override. (Lean keeps `/repo/output/…` by its distinct `-v "$PWD":/repo` mount convention — correct as-is.) |
| ~~**Re-normalize cohort onto public-HEAD oracle**~~ ✅ DONE | whole cohort | — | **CLOSED (2026-07-10).** The public `entity-core-go` mirror rewrote history — the pinned `e8524ed` no longer resolves. Re-pinned `tools/oracle-pin.env` (+ `protocol-generator/cpp/tools/oracle-pin.env`) to the reproducible public HEAD `cc1970f`, and **hardened the core-gate anchor**: `oracle-bootstrap.sh` now fingerprints the *normalized category set + 53-type floor* (`core_gate_fingerprint = 8261a03…`), comment/format-invariant, instead of the raw `profile.go` sha256 — so the V8 comment reword that flipped `e09a865`→`74e04e3` no longer false-alarms "core gate moved" (regression-tested: comment reword → fingerprint unchanged; category drop → fingerprint moves). The `cc1970f` core gate is thereby **provably** the gate the cohort converged against, so every peer's `--profile core` 0-FAIL carries. Cohort table + reading note re-normalized to `cc1970f`. *Optional remaining (non-gating):* a fresh full-suite re-run of the 21 non-COBOL peers on `cc1970f` to re-measure their extension-inflated `665` totals natively (COBOL already runs natively at `cc1970f`); deferred, as core is the gate and it carries. |
| **Scorecard label fix** `62044c5 → b30a589` | provenance | Low | A-C-008 / A-ADA-013: `62044c5` is off-by-one; `b30a589` is the true v7.75 baseline where `resource_bounds` activates under `--profile core`. |
| **CLI normalization** (`--name` on C, Ada) | T2 | Medium | C/Ada expose identity via `-seed` only; standardize on `--name` persistent-identity to match the cohort + enable the multisig accept-path. |
| **Verify genuine multisig** on later-folded peers | C, Ada, Ruby, Prolog, Go, COBOL | Medium | Confirm §3.6 K-of-N is genuine (not frame-only) + add accept-path tests, matching the original-10 closeout. |
| **Ed448 agility** for deferred peers | Swift, Zig, C, Ada, Go | Demand-driven | Floor (Ed25519+SHA-256) ships; Ed448 via the OCaml FFI-hybrid pattern or native lib when an adopter needs it. |
| **Publish** (registry uploads) | all | Demand-driven | All parked at `0.1.0-pre`; per-ecosystem publish is an operator step gated on a community pull. |

---

## 4. Tier policy — the workflow contract

The cohort is too large to keep every peer in lockstep on every spec amendment at current resourcing. The tiers bound the work without abandoning any peer or losing the consolidated learning.

### Tier-1 — the spec cross-check core (lockstep)
**OCaml · Swift · Haskell · Go · Lean**

Re-run on **every** spec amendment / `validate-peer` update; converged to 0-FAIL before the change is considered landed. Chosen for spec-discovery capability + axis coverage + ecosystem value:
- **OCaml** — the proven headline finder (A-OC-007 §7.4/§1.5 peer-id contradiction); strict-ML / native codec.
- **Swift** — the sharpest string/grapheme instrument + a major ecosystem (the adoption anchor); spec-first on the stamped v7.74 surface.
- **Haskell** — STM/pure substrate, native full-agility crypto, the cleanest conformance record; strong spec-first reader.
- **Go** — clean-room, static-binary, CLI-friendly; the predictable adoption starting point and an independence check on the generator (a generated peer in a language that already has a hand-written reference sibling).
- **Lean** — the **proof vector**: re-establishing the proofs against an amendment surfaces unstated preconditions that no running peer can reach. The keystone's only formal-methods discovery channel; kept in Tier-1 deliberately despite higher upkeep.

*Tier-1 is a default, not a cage — pull any peer up temporarily when an amendment touches its specific axis (e.g. a memory-model change → add C; a CLOS/dispatch change → add Common Lisp).*

### Tier-2 — priority catch-up (big ecosystems + strong substrates)
**C# · TypeScript · Java · Elixir · Common Lisp · Rust · Python**

*(Rust + Python = the clean-room large-ecosystem adoption peers; tier placement provisional — a steward may promote them to Tier-1 alongside the clean-room Go peer as same-language generator-independence checks.)*

Caught up promptly after Tier-1 converges. The mainstream adoption peers (C#/TS/Java — the largest pull) plus two high-value substrates (Elixir = production BEAM + native agility; Common Lisp = a proven finder, A-CL-009 hex-case, with pure-language full crypto).

### Tier-3 — on-demand catch-up (specialist / lower-pull)
**Zig · C · Ada · Ruby · Prolog**

Synced with excess capacity or on a concrete adopter request. Each is genuinely valuable (Zig = lightest supply chain; C = ubiquitous + found A-C-009; Ada = structural store-safety; Ruby = dynamic + native agility; Prolog = logic-fit + A-PL-006) but lower routine-pull, so they catch up when an amendment is stable or a community asks.

### Backlog (demand-driven new peers)
Clean-room **Rust** and **Python** peers — **BUILT + merged** (the 16th + 17th generated peers), full S1→S5: `validate-peer --profile core` **653·0F @ 33f35fd**, genuine §3.6 multisig (accept-path ran 11/11) + origination-core 3/3, both publish-ready (Rust `0.1.0-pre`/crates.io, Python `0.1.0`/PyPI, package-registry upload deferred until stabilization). Built in the spirit of the clean-room Go peer — adoption value (fresh keystone-generated peers for the two large ecosystems, vs the hand-written siblings `entity-core-{rust,py}`) plus a generator-independence cross-check; both clean-room (siblings never opened), and both independently landed the identical 653·0F total — no new spec defect (well dry, as expected). Per-peer detail: `protocol-generator/{rust,python}/status/`. No new-language peer is queued as a *discovery* instrument; the discovery well is dry on the current surface (15-peer review §5).

---

*Companion evidence: the per-peer `protocol-generator/<lang>/status/` records (CONFORMANCE-REPORT, ARCHITECTURE-REVIEW, SPEC-AMBIGUITY-LOG) and the cross-language findings register `research/stewardship/SPEC-FINDINGS-LOG.md`.*
