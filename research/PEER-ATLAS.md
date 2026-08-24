# The Peer Atlas — 46 substrates, and what each one was for

**What this is.** A single map of every peer in the cohort: what substrate it represents, what
*property* of the protocol it was built to stress, and what it actually taught us. If you want to know
"what does the Prolog peer exist for?" or "why is there a peer written in SQL?", this is the document.

**What this is not.** It is not a status board — `CONFORMANCE-MATRIX.md` owns per-peer conformance
numbers and is the authoritative source for any figure. It is not a build queue — that's
`COMPLETENESS-ROADMAP.md`. And it explicitly does **not** claim the set is finished; see §6.

---

## 1. The selection principle: we are collecting *forms*, not languages

The cohort is not an attempt to support the top-46 languages by popularity. If it were, it would be a
strange list — it contains APL, Forth, Oz, and a peer written in Pure Data patches, while omitting
Scala, Lua, and Objective-C.

The organizing idea is different, and it is the single most useful thing to understand about this repo:

> **A peer is worth building when its substrate forces the protocol through a shape no existing peer
> forced it through.**

Not a new *language* — a new **form**. Two languages that differ in syntax, package manager, and error
idiom but agree on how they represent an integer, a byte string, and a concurrent request will produce
the same peer twice. Two languages that disagree on any of those will produce genuinely different
peers, and the difference is where spec ambiguities surface.

Experience across the sweep sharpened this into a rule we now apply before starting any new peer:

**Discovery yield is substrate-bound, not idiom-bound.** Spec findings come from *wire-touching* axes —
how the substrate represents integers, floats, strings, and bytes, and what crypto it can reach. A peer
that is novel only *off* the wire — a different concurrency style, a different error model, a different
packaging story — buys **generator robustness**, which is worth something, but it does not surface spec
defects. We have measured this repeatedly and it has held every time.

The honest consequence: **the spec-discovery well has been dry on the current wire surface since around
peer 15, and it stayed dry through peer 46.** Every distinct integer model, float model, string model,
byte/map model, crypto tier, concurrency shape, object model, and execution mode we could find has now
been probed. That is a *result*, not a disappointment — it is the evidence that the wire surface is
unambiguous where it has been tested. It is also why the steady-state value of this cohort is now
**re-running it against each spec amendment**, rather than adding language #47 for its own sake.

The exception that proves the rule is §5 below: one region *did* keep producing findings, and it was
the region that was conceptually rather than mechanically distant.

---

## 2. The map

Every peer, grouped by the family whose *form* it represents. **Maint.** is the maintenance tier from
`tools/peer-tiers.tsv` (how often it gets re-measured — not a quality rank). "Probes" is the axis the
peer was selected for.

### Systems / imperative-compiled — 10 peers

The reference shape of the protocol, and the substrates the FFI codec is written for.

| Peer | Maint. | Probes |
|---|:--:|---|
| `c` | M3 | the ubiquitous substrate; also the FFI bridge every tier-5 peer consumes. Found A-C-009 |
| `cpp` | M3 | reach |
| `rust` (clean-room) | M2 | compile-enforced store safety |
| `ada` | M3 | **structural store-safety via protected objects** — safety by language construct, not discipline |
| `zig` | M3 | lightest supply chain in the cohort; std-only, zero dependencies |
| `odin` | M3 | no-GC + **pure-language crypto**, no C at all |
| `nim` | M3 | **compile-time macro/template codec** — the metaprogramming axis; compiles to C |
| `crystal` | M3 | the Ruby-overfit check: same syntax family, compiled + typed + fixed-width + CSP fibers |
| `fortran` | probe | **fixed-width signed-only integer model** — no unsigned type at all |
| `cobol` | M3 | alien data model: PIC fixed-width records vs CBOR variable-length; COMP-3 decimal |

### Managed / large-ecosystem — 4 peers

| Peer | Maint. | Probes |
|---|:--:|---|
| `go` (clean-room) | **M1** | independence check on the generator; also the oracle's own language |
| `java` | M2 | major ecosystem; JVM |
| `kotlin` | M2 | JVM with sealed-`Result` + coroutines |
| `csharp` | M2 | major ecosystem; the first peer ever built |

### Dynamic / scripting — 6 peers

| Peer | Maint. | Probes |
|---|:--:|---|
| `python` (clean-room) | M2 | large-ecosystem adoption; bignum integers free |
| `ruby` | M3 | dynamic; native crypto agility via stdlib OpenSSL |
| `php` | M3 | event-loop store-safety |
| `typescript` | M2 | major ecosystem; BigInt number model |
| `tcl` | probe | **Everything-Is-A-String** — the string/encoding axis from its most extreme end |
| `rexx` | probe | **native decimal number model** — arithmetic is decimal, not binary |

### Functional / typed — 6 peers

| Peer | Maint. | Probes |
|---|:--:|---|
| `haskell` | **M1** | lazy-by-default purity; **STM** as a structural store-safety shape; cleanest conformance record |
| `ocaml` | **M1** | strict impure ML; the proven headline finder (A-OC-007); int63 integer model |
| `swift` | **M1** | **grapheme-cluster strings** — the sharpest string instrument in the cohort; actor isolation |
| `lean` | **M1** | **the proof vector** — the only formal-methods discovery channel (see §4) |
| `elixir` | M2 | production BEAM; actor model; native full crypto agility |
| `dart` | M3 | sealed-`Result` + `Future`; pure-Dart crypto |

### Lisp / homoiconic — 1 peer

| Peer | Maint. | Probes |
|---|:--:|---|
| `common-lisp` | M2 | CLOS **multiple dispatch** + the condition system; **pure-Lisp full crypto**. Found A-CL-009 |

### Logic & query — the conceptually distant corner — 4 peers

The region that kept producing findings. See §5.

| Peer | Maint. | Probes |
|---|:--:|---|
| `prolog` | M3 | top-down SLD resolution. Found A-PL-006 |
| `datalog` | probe | **bottom-up deductive** (embedded Ascent) — the SecPAL/Binder trust-management shape |
| `sql` | probe | **relational query** (SQLite) — authority as recursive CTE |
| `apl` | probe | **array value-model** — the whole codec as array operations |

### Stack, array & pure-object — 4 peers

| Peer | Maint. | Probes |
|---|:--:|---|
| `forth` | probe | **stack machine, typeless** — maximum generator stress; native-float-bits codec |
| `julia` | M3 | **multiple-dispatch codec**; JIT; UInt64/BigInt hybrid numerics |
| `smalltalk` | probe | pure-object live-image message passing. Found A-ST-016 (root-error-class rule) |
| `io` | probe | **pure prototype-based OO** — delegation only, no classes; single-thread event loop |

### Concurrency & dataflow — 2 peers

| Peer | Maint. | Probes |
|---|:--:|---|
| `oz` | probe | **dataflow-variable concurrency** — the 4th structural store-safety shape (A-OZ-006) |
| `pd` | probe | Pure Data reactive patch — **the only visual probe to clear the full core gate** |

### Visual / block — 2 peers *(exploratory — not deployable)*

Kept in the cohort deliberately, labelled exploratory, because their value is pedagogical and
methodological rather than operational.

| Peer | Maint. | Probes |
|---|:--:|---|
| `node-red` | exploratory | flow-graph visualization; delegates the TS engine |
| `turbowarp` | exploratory | Scratch blocks; **thread-local-free concurrency** — the sharpest limit finding |

### The bare machine — 3 peers

| Peer | Maint. | Probes |
|---|:--:|---|
| `asm-x86_64` | probe | **the lowest-level substrate** — no runtime, allocator, types, or error model |
| `asm-arm64` | probe | first ISA port — is the interior a mechanical register/syscall swap? |
| `riscv64` | probe | second ISA port, off the arm64 template via the shared generic syscall table |

### VM & bytecode — 3 peers

| Peer | Maint. | Probes |
|---|:--:|---|
| `wasm-wat` | probe | **hand-authored WebAssembly text** — the WASM analog of the asm peer |
| `rust-wasm` | probe | compile-an-existing-peer: `wasm32-wasip1` under WasmEdge JIT |
| `rust-wasm-wasmtime` | probe | the same module under wasmtime AOT — isolates runtime + execution mode |

### Content-addressed — 1 peer

| Peer | Maint. | Probes |
|---|:--:|---|
| `unison` | probe | content-addressed code; **managed runtime with no C-FFI hatch** — the escape valve every other tier-5 peer used is structurally unavailable (see `CRYPTO-LANDSCAPE.md` §4) |

---

## 3. What the axes taught — the short version

The full treatment is `SUBSTRATE-TAKEAWAYS.md`; this is the index into it.

- **The wire contract and dispatch logic are substrate-neutral.** The §6.5 sequence, the §5.2 verify
  ladder, status codes, and §6.6 handler resolution are pure control flow and expressed cleanly in all
  46 — *including two visual block languages*. That portability, demonstrated rather than asserted, is
  itself the headline result.
- **Canonical CBOR is the universal non-freebie.** No platform library suffices anywhere. Every peer
  hand-rolls it. See `CRYPTO-LANDSCAPE.md` §5.
- **Integer head-form is a fixed-width artifact, not a protocol property.** Bignum languages carry the
  full range free; fixed-width languages must carry the head form and self-test `[2⁶³, 2⁶⁴−1]`. Branch
  the profile by language class; never treat it as a protocol requirement.
- **There are four structurally distinct concurrency shapes**, and the §6.11 handler-outbound demux is
  the discriminator: actor-isolation and STM and CSP get it ~free; thread/async peers pay a
  correlation-map tax; single-thread event loops pay a cooperative-yield tax; and **dataflow variables
  get it free in the most elegant way in the cohort** — the variable *is* the demux.
- **The honest limit: thread-local-free concurrency.** Scratch has no per-request variable scope at all,
  so a peer there *structurally cannot* process requests concurrently without clobbering its own state.
  It can satisfy §6.11 only by cooperative scheduling, never by true concurrency. This is the clearest
  case of the protocol assuming something (per-request isolation) that a substrate cannot cleanly give.
- **Crypto availability is a five-tier spectrum** and Ed448 is the fault line — drawn by C library scope
  decisions, not language capability. `CRYPTO-LANDSCAPE.md` is the whole story.

## 4. Two peers that are not like the others

**`lean` — the proof vector.** The only peer whose purpose is not conformance. The method: build the
conformant peer first, *then* prove selected invariants in Lean. A proof that needs an unstated
hypothesis is an under-specified precondition in the spec; a counterexample is a spec defect. This is a
qualitatively different discovery channel from running vectors — conformance tests tell you a peer
agrees with an oracle on the cases someone thought to write, and a proof tells you something holds for
all inputs in a stated domain. It is deliberately scoped: the proof covers the authority *logic
interior*; crypto, the IO/concurrency shell, and the adversarial-input parser stay owned by KATs, race
tests, and fuzzing. Every theorem distinguishes **soundness from completeness**, because conformance
vectors never flag that gap.

**`turbowarp` and `node-red` — the exploratory pair.** Neither is deployable and both say so in the
matrix. They are kept for three reasons: the **decomposition findings** (folding §5.2 into one boolean
masked three real conformance bugs, recovered only by making the ladder visible on the canvas — *a
folded verdict is a hiding place*, which generalizes to every peer); a **reusable technique** (running
the real authored artifact against the oracle via an interpreter, rather than mocking it); and
**community reference value** — a Scratch or Node-RED author can read the protocol in their own idiom.

## 5. The one region that kept paying: authority-as-query

Worth calling out because it is the counterexample to §1's "the well is dry."

Where mechanical distance (a weird integer model, a strange object system) stopped producing spec
findings around peer 15, **conceptual distance kept producing them.** SQL and Datalog were built on the
observation that *authorization is historically a database and logic problem* — trust-management logics
like SecPAL, Binder, and DKAL are literally Datalog dialects for delegation. So expressing the §5.2
ladder and §5.5 delegation chain as queries and rules was a natural fit, not a stunt.

Both cleared the full core gate authoring the authority interior *in the query language*: the §5.2
ladder, the §5.5 delegation closure (recursive CTE / recursive rule to least fixpoint), K-of-N
(`HAVING count(DISTINCT)` / a counting aggregate), and §6.6 resolution (`ORDER BY length DESC` /
stratified negation).

**The finding: authority is a query; the protocol around it is a state machine.** Everything that is a
pure function of the projected request facts expresses cleanly — often *more legibly* than the prose
spec. Everything stateful-sequential (dispatch, handshake, framing, crypto, store) leaks to the host.
And the boundary held: completing the full handler surface added **zero** imperative allow/deny logic.
That absence is itself the datum.

It produced two spec-shaped findings — **F40** (§3.6 scope matching is *typed*: id dimensions match
literally, path dimensions canonicalize — surfaced by SQL as a real ALLOW bug) and **F41** (the
decision surface is a monotone deductive system, which means fail-closed and the §5.5a within-grant
conjunction could be *structural invariants* rather than silently-violable MUSTs).

The lesson for peer selection: **when looking for the next high-yield peer, ask which substrate would
express the protocol's *ideas* differently — not which one represents bytes differently.**

## 6. What is not here — and what we would love to see

**We are not claiming this set is complete, and we do not want to.** The map is wide, but "wide" is not
"finished," and the useful frontier has moved rather than closed. New peers are genuinely welcome —
especially ones that stress the protocol in a way nothing above does.

**What we would most like to see:**

- **A substrate that expresses the protocol's ideas in a new way**, in the sense of §5. That is the axis
  that was still paying when the mechanical axes went quiet. Term rewriting (Maude, Pure, Wolfram) is
  the clearest unrepresented *computational model* — computation as rule-directed rewriting to normal
  form is neither imperative, functional, nor logic-resolution.
- **Runtimes and platforms, not just languages.** The wasm and ISA tracks were high-value precisely
  because they varied the *execution environment* while holding the language fixed — and that is where
  the execution-mode-is-a-conformance-contract finding came from. Embedded targets, unusual schedulers,
  and constrained runtimes are under-represented.
- **Substrates that lack something we have assumed.** Unison earned its place by lacking a C-FFI hatch.
  TurboWarp earned its by lacking per-request variable scope. **A substrate that is missing a primitive
  everything else has is worth more than a substrate that is merely unfamiliar.**
- **Conventional languages with real communities**, for reach rather than discovery — Scala,
  Objective-C, Lua, Pascal, F#, Erlang, R. These are honest catalog additions and we would take them
  happily; just know going in that they are corroboration peers, and that is fine.

**What we would gently push back on:** a peer whose novelty is purely syntactic, or purely a different
error-handling idiom or package manager, over a substrate already represented. It will almost certainly
reproduce its neighbour's results. If you want to build it anyway because you want a peer in your
language — genuinely, please do, that is a good reason and the generator exists for exactly that. Just
don't expect it to find a spec bug, and don't let anyone tell you it should have.

**How to propose one.** Open an issue describing the substrate and — most usefully — *which axis you
think it varies*. If you are not sure, `PARADIGM-MAP.md` classifies the whole territory by family and
viability, and `COMPLETENESS-ROADMAP.md` carries the current queue. The generator does the rest:
`/entity-rosetta <lang>` runs S1 (research + author a profile) through S5.

## See also

| For | Read |
|---|---|
| Per-peer conformance numbers, oracle pin, codec/crypto strategy | **`CONFORMANCE-MATRIX.md`** (authoritative) |
| What translates / needs a seam / doesn't, in operational detail | `research/SUBSTRATE-TAKEAWAYS.md` |
| The cryptography survey | `research/CRYPTO-LANDSCAPE.md` |
| Whole-territory cartography + viability filter | `research/PARADIGM-MAP.md` |
| Build queue and priorities | `research/COMPLETENESS-ROADMAP.md` |
| The narrative capstone — how we got here | `research/PROJECT-RETROSPECTIVE.md` |
| Authority-as-query deep dive | `research/evaluations/authority-as-query.md` |
| Visual-paradigm field survey | `research/evaluations/visual-paradigms.md` |
| Maintenance tiers — who gets re-measured when | `CONFORMANCE-MATRIX.md` §4 · `tools/peer-tiers.tsv` |
