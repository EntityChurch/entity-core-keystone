# Completeness Roadmap — remaining peer/paradigm targets

**Purpose.** A forward-looking work tracker for the *ecosystem-completeness* phase. Distinct from
its two siblings: `LANDSCAPE.md` is the **current-state roster + tier policy**;
`protocol-generator/shared/evaluations/visual-paradigms.md` is the **visual-paradigm field survey**. This doc is the **queue**
— what's left to build and in what priority — so work has a guide.

**Framing (read first).** The spec-discovery well is dry on the current wire surface (see
`SUBSTRATE-TAKEAWAYS.md` + the LANDSCAPE "discovery is substrate-bound" note). Everything below is
**catalog completeness + generator-robustness, explicitly NOT a spec-discovery bet.** We add these to
round out the language/runtime landscape, not because we expect new findings.

**This is not an "obligation."** Peers are classified at **support tiers** (LANDSCAPE §Tier policy):
new completeness peers land at **low tiers** (on-demand catch-up), so adding to the list does not
commit us to lockstep re-runs. Core protocol churn has been near-zero for a long while; *if* an
amendment lands, low-tier peers catch up as capacity allows — the tier system exists precisely so the
list can grow without the maintenance cost growing linearly.

Status legend: ☐ queued · ◐ in progress · ☑ done · ⛔ blocked (accessibility) · ? research-needed

---

## 1. Conventional languages — the completeness queue

Roughly in intended build order. "Novelty" = does it exercise a genuinely distinct substrate/idiom,
or is it a catalog row over an already-covered substrate.

| # | Language | Status | Novelty | Notes |
|---|----------|:--:|---------|-------|
| — | **Pure Data** | ☑ done *(2026-07-15)* | Distinct paradigm (reactive patch) | **Closed the visual track at full gate: 682·0F Result: PASS @ `cc1970f`** on the real Pd runtime over real TCP — the only visual probe to clear it (matrix row #33; retrospective in `protocol-generator/shared/evaluations/visual-paradigms.md` §5a). Surfaced F34/F35 (mint-timestamp precision; open-seed resource form) → arch handoff drafted. |
| 1 | **Scala** | ☐ | **High** — JVM functional/OO hybrid, large ecosystem | Distinct from Java/Kotlin (implicits, HKT, pattern-matching); already T1 not-started in LANDSCAPE. Highest-value conventional gap. |
| 2 | **Objective-C** | ☐ | **Medium-high** — dynamic message-passing dispatch (`objc_msgSend`), Apple heritage | A genuinely distinct dispatch model + the pre-Swift Apple substrate. |
| 3 | **Lua** | ☐ | **Low** (ubiquity pick) | "Everywhere" (embedded/games/config). Caveat noted: Lua is C-hosted, so the substrate is close to our C peer — completeness/reach value, not a new axis. |
| 4 | **Pascal** (Free Pascal / Object Pascal) | ☐ | Medium — older structured-systems substrate | Distinct heritage (Delphi lineage), fixed-width, native-compiled. |
| 5 | **Rebol / Red** | ☐ | **High** — homoiconic *dialecting* language | Unusual message-dialect / block-as-code model; Red is the maintained successor. Genuinely distinct idiom. |
| 6 | **Haxe** | ☐ | **Medium-high** — cross-compile-to-everything toolkit | *(Corrected from "Hack" — Haxe, not the HHVM dialect.)* Distinct *build* model: one source → many targets (JS/C++/HL/JVM/…). Interesting for the codec-portability axis. |

### Lower priority / maybe

| Language | Status | Why lower |
|----------|:--:|-----------|
| **F#** | ☐ maybe | ML-family on .NET, but the .NET substrate is already covered by C# ("nearly free"). Wanted, not urgent. |
| **Scheme / Racket** | ☐ maybe | Would be **ports of Common Lisp** — same Lisp substrate, not fundamentally different. Low marginal value; do only if completeness itch persists. |
| **Erlang** | ☐ maybe | BEAM substrate already covered by Elixir → corroboration-only (LANDSCAPE BEAM-family note). |
| **D**, **Perl**, **Groovy**, **VB.NET** | ☐ backlog | Pure catalog completeness, low signal. Add on request. |

### Frontier probes — declarative query + logic (the conceptually rich corner)

The one remaining region that might teach us about the *protocol*, not just the substrate: authorization
is historically a database/logic problem, so these may express the authority interior more naturally
than imperative code. See `PARADIGM-MAP.md` §declarative for the full argument.

> **CLOSED (2026-07-16).** Both frontier probes landed gate-green and produced the spec-shaped findings
> the region was expected to yield (F40 typed scope matching; F41 authority-as-derivation). The
> declarative-query/logic corner is **exhausted** — SQL is the relational representative, Datalog the
> deductive one and closest to the trust-management literature. Nothing high-signal remains on this
> axis; steady-state value is **re-running these two authority interiors against each §5 amendment**
> (a §5 change shows up here as a diff to the *derivation*). What's left below is
> esoteric/substrate-limit curiosity only. Synthesis: `protocol-generator/shared/evaluations/authority-as-query.md`.

| Target | Status | Why |
|--------|:--:|-----|
| **SQL** (SQLite) | ☑ **done** *(2026-07-16)* | **Authority-as-query — LANDED.** SQLite + C seam; §5.2 ladder / §5.5 chain-walk (recursive CTE) / K-of-N (`HAVING count DISTINCT`) / §6.6 (`ORDER BY length DESC`) authored as real SQL. `682·0F Result: PASS @ cc1970f`. Finding: authorization is a query, the protocol around it is a state machine → F40 (typed scope matching). Retrospective: `protocol-generator/shared/evaluations/authority-as-query.md`. |
| **Datalog** | ☑ **done** *(2026-07-16)* | **Authority-as-query, deductive half — LANDED.** Embedded Ascent (bottom-up, terminating; distinct from the Prolog peer) + Rust seam; §5.5 delegation as recursive rules to least fixpoint (SecPAL/Binder shape), verdict as a derived `allow` fact. `682·0F Result: PASS @ cc1970f`. Finding: the §5/§6.6 decision surface IS a monotone deductive system → F41 (authority-as-derivation appendix). |

### Curiosity / substrate-limit probes (do *not* graduate to the extension layer)

Worth one probe each for the boundary characterization — "where does authoring stop being possible."

| Target | Status | Why |
|--------|:--:|-----|
| **Brainfuck** | ☐ curiosity | Canonical minimal Turing-tarpit; the clean *start* if we probe esolangs. Honest limit: only `,`/`.` byte I/O (no syscalls) → I/O+CBOR+crypto via a host bridge; interior is Turing-complete but machine-generated in practice. The substrate-minimalism data point (one notch below asm). |
| **Io** | ☑ **done** *(2026-07-15)* | The one distinct object model, now probed (pure prototype-based, delegation-only): §6.6 resolution rendered as a proto-chain delegation walk. **Full gate `682·0F Result: PASS @ cc1970f`** (native Socket + in-process `EntityCodec` C addon; frozen `2026.04.20-native-final` tag). Its S4 flushed out A-IO-025/026 (single-event-loop non-blocking discipline; a "throughput ceiling" claim retracted after cross-peer reconciliation). Matrix row + `protocol-generator/io/status/`. |
| **Oz / Mozart** | ☑ **done** *(2026-07-15)* | Dataflow-variable concurrency = the **4th structural §7b shape**, now built and validated: the demux collapses to one dataflow variable per pending request (A-OZ-006). **Full gate `682·0F Result: PASS @ cc1970f`** (Mozart2 v2.0.1 RPM; native `Open.socket` + the `entity-codec-daemon` `Open.pipe` co-process seam). Matrix row + `protocol-generator/oz/status/`. |
| **Term rewriting** (Pure / Wolfram / Maude) | ☐ medium-low | The one distinct *computational model* we don't represent (equational rewriting). Pure (open/LLVM) or the free Wolfram Engine are the runnable probes. |
| **Befunge** | ☐ curiosity | Only esolang adding a real axis beyond Brainfuck (2D tape). |
| **R** | ☐ low | Stats-array; distinct community, modest catalog value. |

---

## 2. WebAssembly — both flavors (coordinate with the assembly team)

The assembly team continues through hand-written asm → WebAssembly. On our side, out of curiosity we
want to see **both** WASM authoring styles side by side:

| Target | Status | Notes |
|--------|:--:|-------|
| **Natively-authored WASM (WAT)** | ☑ **done** *(2026-07-15)* | Hand-authored `.wat`, the WASM analog of the asm peer (`protocol-generator/wasm-wat/`). **Full gate `682·0F Result: PASS @ cc1970f`** (matrix row `wasm-wat`). Host model = **stock runtime** (WasmEdge flat sockets + Rust codec→wasm `wasm-merge`'d, no native host); §6.11 passes under `--enable-jit` (interpreter crypto too slow — the execution-mode-is-conformance lesson). Surfaced F33/F34/F35 (T2.1 absolute-floor tension; tampered-cap-sig coverage gap; §7a reentry-echo skips §5.2). |
| **Rust → WASM (cross-compiler)** | ☑ **done** *(2026-07-15)* | The "compile an existing peer to WASM" path — the `../rust` peer cross-compiled **unmodified** to `wasm32-wasip1` behind a `poll_oneoff` transport seam. **Full gate `682·0F Result: PASS @ cc1970f`** (matrix rows `rust-wasm`, WasmEdge/JIT; + `rust-wasm-wasmtime`, the SAME module under **wasmtime AOT**, compile-once-run-native). Codegen + runtime/AOT head-to-head: `protocol-generator/shared/evaluations/wasm-codegen-comparison.md`. |

**Coordination:** both flavors shipped, deliberately split across the two host models for coverage —
the WAT-native peer proved **stock-runtime, no-native-host** (WasmEdge sockets + `wasm-merge`'d codec),
the Rust→WASM sibling(s) the **compiled-peer / WASI** route (WasmEdge JIT + wasmtime AOT). The asm
concurrency template (A-ASM-014, single-thread frame-router + `pending_tab` reentry) ported to all
three (concurrency is substrate-forced there — no fork/threads). **The WASM track is closed;** the
substrate is covered end-to-end (author/compile portable + deploy AOT native — SUBSTRATE-TAKEAWAYS §4).

---

## 3. Visual & dataflow paradigms — status of the class

**Pure Data closes the *visual* track.** Our field survey (`protocol-generator/shared/evaluations/visual-paradigms.md`) mapped
the whole visual space:

- **Imperative block** (Scratch) → PROBED (#32 TurboWarp).
- **Flow-based / message-passing** (Node-RED) → PROBED (#31).
- **Reactive patch / signal-graph** (Pd, Max/MSP, vvvv, LabVIEW, Simulink) → **PROBED (#33 Pure Data,
  2026-07-15 — full gate `Result: PASS` on the real runtime)**. Pd was the ONLY cleanly probeable
  member (open, headless `pd -nogui`, raw TCP in-patch); one probe exhausts the accessible surface
  of this class. **All three visual paradigms are now probed — the visual track is closed** (the
  well-is-dry verdict stands three-of-three; see `protocol-generator/shared/evaluations/visual-paradigms.md` §5a).

### Inaccessible / stunt (captured for honesty, not queued)

| Target | Status | Why |
|--------|:--:|-----|
| **Simulink** | ⛔ interest-noted | Proprietary (MathWorks), no free headless runner, no raw socket from the diagram. Same wall as LabVIEW. *Wanted, but wrapper-only at best — revisit only if an accessible headless path appears.* |
| **Spreadsheets** (Excel/Sheets/Calc) | ⛔ stunt | Genuinely distinct *reactive-cell* paradigm, but socket I/O must route through Basic/Python macros = a wrapper → violates author-in-the-paradigm. A stunt row, not a clean probe. |
| **Blueprints / Bolt / other game-engine visual** | ⛔ | Engine-bound, no listening socket from the graph. |

### The "are we missing dataflow languages?" question — answered

Yes — there's a **textual dataflow** family *distinct* from the visual patches above. Most are
dead/academic or inaccessible, but a couple are real research candidates:

| Language | Class | Verdict |
|----------|-------|---------|
| **Oz / Mozart** | Declarative dataflow-variable concurrency | **☑ done (2026-07-15)** — built to full gate (`682·0F Result: PASS @ cc1970f`); the 4th §7b concurrency shape validated (the dataflow variable *is* the §6.11 demux, A-OZ-006). The textual-dataflow class is now represented. See `protocol-generator/shared/evaluations/oz-io-viability.md` + `protocol-generator/oz/status/`. |
| **Ballerina** | Modern network-integration dataflow | **? candidate** — network-native primitives, but JVM substrate (partial overlap). |
| **Lustre / Esterel / Signal / SCADE** | Synchronous dataflow (avionics/reactive) | ⛔ likely wrapper — compile-to-C, no socket-from-language; SCADE is commercial. |
| **Lucid, SISAL** | Seminal / HPC dataflow | ⛔ dead — no runnable modern tooling. |
| **Datalog** | Deductive logic / query ("data lang"?) | Substrate-adjacent to **Prolog** (already built) — logic, not dataflow. Low novelty. |

**Recommendation:** ~~after Pd, if the dataflow itch persists, **Oz/Mozart** is the one
genuinely-distinct *textual* dataflow probe worth a feasibility look~~ — **DONE (2026-07-15, full
gate).** Oz closed the textual-dataflow class; everything else in it is same-family, inaccessible, or
dead. The dataflow itch is scratched.

---

## 4. At-a-glance: coverage, not completion

**We do not claim this set is complete, and we are not trying to close it.** "Complete" was the wrong
frame and this section used to use it; what we actually have is **broad coverage of substrate forms**,
which is a different and more honest claim.

What the sweep established: every distinct **integer model, float model, string model, byte/map model,
crypto tier, concurrency shape, object model, and execution mode** we could identify has been probed at
least once. That is why the queue above looks slim — the *mechanical* axes are well covered, so a new
conventional language tends to reproduce a neighbour's results rather than surface anything new.

What it did **not** establish is that there is nothing left to find:

- **Conceptual distance was still paying when mechanical distance stopped.** SQL and Datalog produced
  F40 and F41 long after the language axes went quiet. A substrate that expresses the protocol's *ideas*
  differently remains the best bet, and term rewriting is the clearest unrepresented computational model.
- **Runtimes and platforms are under-explored relative to languages.** The wasm and ISA tracks varied the
  *execution environment* while holding the language fixed, and that is where
  execution-mode-is-a-conformance-contract came from. Embedded targets, unusual schedulers, and
  constrained runtimes have barely been touched.
- **Substrates that *lack* something we assume are worth more than unfamiliar ones.** Unison earned its
  place by having no C-FFI hatch; TurboWarp by having no per-request variable scope. Those absences
  produced findings that no amount of syntactic novelty would have.

**New peers are welcome — including plain reach picks.** If someone wants a peer in their language
because it's their language, that is a good reason and the generator exists for it. The only thing we
ask is honesty about which kind of contribution it is: a corroboration peer is genuinely useful and
should not be dressed up as a discovery peer.

`PEER-ATLAS.md` §6 carries the standing invitation and how to propose a target.

## Cross-references

- **The built cohort mapped by substrate form + the selection principle: `research/PEER-ATLAS.md`**
- **Whole-territory paradigm cartography + viability filter: `research/PARADIGM-MAP.md`**
- Current-state roster + tier policy: `research/LANDSCAPE.md`
- Visual-paradigm field survey + when-to-stop verdict: `protocol-generator/shared/evaluations/visual-paradigms.md`
- What translates / needs a seam / doesn't, across substrates: `research/SUBSTRATE-TAKEAWAYS.md`
