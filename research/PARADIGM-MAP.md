# Paradigm Map — the whole computing-substrate territory

**Purpose.** The "map of everything" — a cartography of the major programming-language and
computing-substrate *families* across ~80 years, each classified by (a) **our coverage** and (b)
**viability** for carrying the entity-core protocol. Companion to `COMPLETENESS-ROADMAP.md` (the build
queue) and `LANDSCAPE.md` (the roster). This is the wide-angle view: not "what to build next" but
"what is the shape of the territory, and which regions are viable at all."

**Why this exists.** Two goals beyond conformance:
1. *Understand the protocol* — what is intrinsic vs substrate-imposed (see `SUBSTRATE-TAKEAWAYS.md`).
2. *Understand the substrate* — what has 80 years of language design actually produced, and which of
   those substrates can host a real peer vs only a wrapper.

This directly feeds the **long-term goal**: the entity-system generator that continues into the
**extension** layer. Not every substrate here graduates to that layer — a peer that can only *wrap*
the protocol tells us the substrate is unsuitable for authoring extensions in. The viability column is
that filter.

---

## Viability classes (the filter)

- **NATIVE** — authors the full dispatch/authority interior in-language; codec/crypto may be a seam.
  Graduates to the extension layer.
- **HYBRID-FFI** — interior authored in-language; canonical-CBOR + Ed448 (and sometimes all crypto) via
  `libentitycore_codec`. Still graduates (the interior is real).
- **QUERY-NATIVE** — the authority *logic* (grant matching, chain walk, K-of-N) is *naturally* expressed
  in the paradigm (relational/deductive); I/O needs a host. **The conceptually richest region.**
- **WRAPPER-ONLY** — the substrate cannot author the interior or reach a socket without delegating to a
  host language; the "peer" is a façade. Does *not* graduate — but may still be worth one probe for the
  *characterization* (where/why it fails to fit).
- **STUNT** — technically possible, practically absurd; academic/curiosity only.
- **SAME-FAMILY** — a covered substrate already answers this; a new member adds a catalog row, no signal.

---

## The families

### Imperative / procedural
Algol · **C** · **Pascal** · **Fortran** · **COBOL** · **Ada** · BASIC · **assembly**
**Coverage: saturated.** C, Fortran, COBOL, Ada, asm-x86_64 built; Pascal queued. Algol/BASIC are
ancestral/dead. **NATIVE.**

### Object-oriented — class-based
**Java · C++ · C# · Kotlin · Swift · Ruby · Python · Dart · Crystal**
**Coverage: saturated. NATIVE.**

### Object-oriented — pure message-passing
**Smalltalk** (built #26) · **Objective-C** (queued)
Distinct dynamic-dispatch substrate (`objc_msgSend` / `doesNotUnderstand:`). **NATIVE.**

### Object-oriented — **prototype-based** ← CLOSED
**Self · Io**(built #34) · NewtonScript · JavaScript(prototype core, but we cover it as TS)
**Coverage: closed (2026-07-15).** **Io** — pure prototype-based, delegation-only, no classes — landed
full gate-green; §6.6 resolution renders as a proto-chain delegation walk. The distinct object model is
probed; Self/NewtonScript are **SAME-FAMILY**. **NATIVE.**

### Functional — ML / typed
**Haskell · OCaml** (built) · **Scala · F#** (queued) · Standard ML · Elm · PureScript · ReasonML
**Coverage: strong. NATIVE.** Scala also = the JVM-functional big-ecosystem pick.

### Functional — Lisp
**Common Lisp** (built #6) · Clojure · Scheme · Racket · Emacs Lisp · Fennel
**Coverage: substrate covered by CL. SAME-FAMILY** — Scheme/Racket/Clojure are ports, low signal.

### Functional — concatenative / stack
**Forth** (built #25) · Factor · Joy · Cat · PostScript
**Coverage: paradigm covered by Forth. SAME-FAMILY.**

### Array / vector
**APL** (built #30) · **J · K/kdb+/q · BQN** · Nial · MATLAB · **R** · **Julia**(built) · NumPy
**Coverage: paradigm covered by APL (+ Julia's numeric).** J/K/BQN are tacit-array successors —
**SAME-FAMILY**. **R** (stats-array) is the one with a distinct-enough community to be a modest catalog
pick. **NATIVE** where built.

### Logic — top-down (SLD resolution)
**Prolog** (built) · Mercury · miniKanren
**Coverage: covered. NATIVE.**

### Logic — **bottom-up deductive (Datalog)** ← CLOSED, and it paid
**Datalog**(built #40, embedded Ascent) · SecPAL · Binder · DKAL · Soutei · Cassandra
**Coverage: closed (2026-07-16). QUERY-NATIVE — the highest-yield probe in the cohort.** Datalog is
*distinct* from Prolog (bottom-up, guaranteed-terminating, set-oriented), and
**authorization/trust-management logics are historically Datalog-based** (Binder, SecPAL, DKAL are
literally Datalog dialects for delegation). The bet paid: §5.5 delegation authored as recursive rules to
least fixpoint, the §5.2 verdict as a derived `allow` fact, K-of-N as a counting aggregate. Produced
**F41** (the decision surface is a monotone deductive system). Detail: `evaluations/authority-as-query.md`.

### Declarative — **relational query (SQL)** ← CLOSED, and it paid
**SQL**(built #39, SQLite) · Postgres PL/pgSQL · SPARQL · DAX
**Coverage: closed (2026-07-16). QUERY-NATIVE.** Grant-scope matching, the delegation-chain walk
(recursive CTE), and K-of-N (`HAVING count(DISTINCT)`) are *relational/set* operations — exactly what SQL
was built for, and the peer authored all of them as real SQL against grant/token tables with a thin C
host for I/O. The viability question the probe existed to answer — *how much interior stays in the query
language vs leaks to the host* — is answered: **everything that is a pure function of the projected
request facts stays; everything stateful-sequential leaks.** Produced **F40** (§3.6 scope matching is
typed), surfaced as a real ALLOW bug. Detail: `evaluations/authority-as-query.md`.

### Term rewriting / equational ← genuine gap (headline miss)
**Wolfram/Mathematica · Maude** (rewriting logic) · **Pure** · Refal · OBJ/CafeOBJ
**GAP — a distinct computational model we don't represent.** Not imperative/functional/logic:
computation *is* rule-directed rewriting of terms to normal form. **Wolfram Language** is the
huge-community member (the free **Wolfram Engine** even has native `SocketListen` → a peer is
conceivable, but proprietary runtime). **Pure** (open, LLVM-based, small) and **Maude** (open,
rewriting-logic, academic, runnable) are the clean open representatives. Viability: NATIVE-ish where a
socket exists (Wolfram/Maude have I/O), crypto/CBOR seam. Worth cataloguing as a real paradigm gap;
**Pure** or the Wolfram Engine are the runnable probes. Medium-low, but genuinely a *new model*.

### Constraint / dataflow-variable concurrency ← CLOSED
**Oz / Mozart**(built #35) · MiniZinc · **Answer-Set Programming (clingo)**
**Coverage: closed (2026-07-15). NATIVE.** Oz (Mozart2, native sockets) landed full gate-green and
validated the thesis: dataflow variables are a **4th structural §7b concurrency shape**, and the §6.11
demux collapses to one single-assignment variable per pending request — the variable *is* the
correlation map (A-OZ-006), the cleanest §6.11 substrate in the cohort. The one distinct *textual*
dataflow probe (visual dataflow = Pd, §visual). **ASP (clingo)** remains an adjacent distinct logic
(stable-model semantics) — a possible catalog note, not a gap. Deep-dive:
`evaluations/oz-io-viability.md`.

### Resource-typed / smart-contract ← distinct domain, mostly not-a-peer
**Solidity/EVM** · **Move** (linear resources) · Michelson · Vyper · Clarity
**Mostly WRAPPER/NA for a network peer** (on-chain VMs — gas-metered, deterministic, *no sockets from
inside the VM*), but catalogued for two reasons: sizable community, and **Move's linear resource types
are conceptually adjacent to capability tokens** (a non-copyable resource ≈ a single-use capability). A
buildable peer would be host-driven (the contract can't listen); the *conceptual* note — capabilities as
linear resources — is the takeaway, not a peer.

### Configuration / total-functional
Nix · Dhall · CUE · Jsonnet · HCL
**NA — not peer substrates.** Dhall/CUE are **total** (non-Turing-complete → can't express the dispatch
loop); Nix is TC-lazy-functional but deliberately sandboxed (no sockets). Catalogued as deliberately
out — they're config languages, not general runtimes.

### Concurrency — actor / CSP
**Erlang/Elixir**(built, actor) · **Go**(built, CSP) · Pony · Occam
**Coverage: covered. NATIVE.**

### Reactive dataflow — visual & textual ← CLOSED
Visual patch: **Pure Data**(built #33) — the one clean visual probe, and **the only visual peer to clear
the full core gate on its real runtime over real TCP**. Textual synchronous: Lustre · Esterel · Signal ·
SCADE — **WRAPPER-ONLY** (compile-to-C, no socket-from-language; SCADE commercial). Seminal: Lucid ·
SISAL — **STUNT** (dead tooling). See `evaluations/visual-paradigms.md`.

### Visual — block & flow
**TurboWarp/Scratch**(#32) · **Node-RED**(#31) — **PROBED.** Rest of class same-family or inaccessible.

### Scripting / glue
**Tcl**(built) · **Rexx**(built) · Perl · AWK · Bash/shell · PowerShell · Raku · **Lua**(queued)
**Coverage: covered (Tcl/Rexx).** Lua = ubiquity pick (C-hosted → close to our C substrate, low novelty).
Perl/shell = **SAME-FAMILY / STUNT** for shell.

### Esoteric / Turing tarpit ← curiosity region
**Brainfuck** · Befunge(2D) · INTERCAL · Malbolge · Whitespace · Piet(image) · Unlambda(combinator)
**STUNT — academic curiosity.** Brainfuck is the canonical clean one (8 ops, Turing-complete) and the
sensible *start* if we probe here. Honest limits: standard BF's **only I/O is `,`/`.` (one byte
stdin/stdout)** — no `socket`/`open`/`syscall` in the language — so I/O + CBOR + crypto are host-side via
a bridge (either memory-mapped-I/O cells in a custom interpreter, or the clean stdin/stdout pipe where
the host feeds framed bytes and BF computes the verdict on the tape). BF *is* Turing-complete, so it
*can* author the authority interior — but nobody hand-writes CBOR-parsing + authority logic in raw BF;
you'd machine-generate it, which defeats "author *in* the paradigm." So: the *substrate-minimalism* data
point ("least machine that can compute an authority verdict" — one notch below asm, which has `syscall`),
**largest seam of any substrate, does not graduate.** Befunge (2D tape) is the only one adding a
*distinct* axis beyond BF. *Accidentally-Turing-complete non-languages (TeX, Make, sed, C++ templates)
are the same class — Turing-tarpit curiosities, no socket, machine-generated interior.*

### Hardware ISA / bespoke architectures
**x86-64**(built asm) · **ARM64**(planned) · **RISC-V**(planned) · **WebAssembly**(planned, both flavors)
· MIPS · POWER/PowerPC · SPARC · z/Arch · 6502/Z80/AVR(retro)
**Coverage: the live families are planned.** x86/ARM/RISC-V/WASM span the register-machine + stack-VM
space. MIPS/POWER/SPARC/z are **SAME-FAMILY** (register machines, no new axis). Retro chips (6502/Z80) =
curiosity. HDL (Verilog/VHDL) = **STUNT** (hardware description, not a software peer). *Hand-authored
**bytecode/IR** (JVM bytecode via jasmin, CIL via ilasm, LLVM IR, WAT) is the VM-level analog of the asm
peer — WAT is already planned; JVM-bytecode/CIL/LLVM-IR would be curiosities, same class.*

### Spreadsheet / reactive-cell
Excel · Sheets · Calc — **STUNT** (socket I/O = macro wrapper). See `evaluations/visual-paradigms.md`.

---

## What this map says

**Regions that graduate to the extension layer (NATIVE/HYBRID):** all the imperative, OO, functional,
logic, array, concurrency families — i.e. the vast bulk of the cohort. This is the "normal" territory
and it is essentially **saturated**; remaining picks (Scala, Objective-C, Pascal, Rebol/Red, Haxe, R,
Io) are completeness/robustness, not new axes.

**The declarative/logic corner was the genuinely interesting frontier — and it is now closed, having
paid.** **SQL** and **Datalog** were built (2026-07-16) on the argument that **authorization is
historically a database/logic problem**, so they might express the authority interior *more naturally
than imperative code does*. They did, and they were the only region that kept producing **protocol**
findings after the mechanical axes went quiet — F40 (typed §3.6 scope matching) and F41
(authority-as-derivation). The generalizable lesson for future selection: **conceptual distance keeps
paying after mechanical distance stops.** See `PEER-ATLAS.md` §5.

**The curiosity/limit regions** — Oz (dataflow variables) and Pure Data (visual reactive) are **built and
closed**; Brainfuck (minimal Turing tarpit) and Befunge (2D) remain unprobed curiosities. Each is worth
*one probe* for the substrate-limit characterization: they map the boundary of "where does authoring stop
being possible." They mostly do *not* graduate, but they complete the understanding of the territory's
edges.

**The closed regions** — Simulink/LabVIEW (proprietary), spreadsheets (macro I/O), synchronous-reactive
(compile-to-C), dead esolangs, HDLs, same-family ISAs/Lisps/arrays — are catalogued so we know they're
*deliberately* skipped, not missed.

## Open research candidates

Five of the eight candidates this map originally named have since been **built and closed** — SQL,
Datalog, Io, Oz, and Pure Data (see their family entries above). What remains:

| Target | Class | Why | Priority |
|--------|-------|-----|:--:|
| **Term rewriting** (Pure / Wolfram / Maude) | Equational rewriting | **The one distinct *computational model* we don't represent** — computation as rule-directed rewriting to normal form, neither imperative nor functional nor resolution-based. The clearest remaining paradigm gap. | **Medium** |
| **Brainfuck** | Esoteric tarpit | Canonical minimal-substrate curiosity; start of the esolang probe. Honest limit: only `,`/`.` byte I/O, so the interior is machine-generated in practice — which defeats *author-in-the-paradigm*. | Curiosity |
| **Befunge** | 2D esoteric | Only esolang adding a real axis beyond Brainfuck (2D tape) | Curiosity |
| **R** | Stats-array | Distinct community; modest catalog value | Low |
| **ASP** (clingo) | Stable-model logic | Adjacent to the closed Datalog probe; catalog note rather than a gap | Low |

Conventional-language reach picks (Scala, Objective-C, Lua, Pascal, Rebol/Red, Haxe, F#, Erlang) live in
`COMPLETENESS-ROADMAP.md` §1 — they are catalog completeness, not paradigm gaps, and this map classifies
their families as already saturated.

**This list is not a closed set.** New paradigm candidates are welcome; `PEER-ATLAS.md` §6 describes what
kind of substrate is most worth proposing and how to do it.

## Cross-references
- **The built cohort mapped by substrate form + the selection principle: `research/PEER-ATLAS.md`**
- **SQL/Datalog deep-dive (runtime model + what the code looks like): `research/evaluations/declarative-query-viability.md`**
- Authority-as-query synthesis (what the closed frontier produced): `research/evaluations/authority-as-query.md`
- **Oz/Mozart & Io deep-dive (dataflow-variable concurrency + prototype OO): `research/evaluations/oz-io-viability.md`**
- Build queue + priorities: `research/COMPLETENESS-ROADMAP.md`
- Current-state roster + tiers: `research/LANDSCAPE.md`
- Visual-paradigm survey: `research/evaluations/visual-paradigms.md`
- What translates across substrates: `research/SUBSTRATE-TAKEAWAYS.md`
