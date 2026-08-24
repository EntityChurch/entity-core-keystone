# What translates across substrates — and what doesn't

The pull-it-together synthesis of the substrate sweep: entity-core has now been generated onto
**46 substrates** spanning compiled/interpreted, static/dynamic, array/stack/pure-object/decimal,
**dataflow-variable** and **pure-prototype** object models, the bare machine (three ISAs) and the
stack VM (three WebAssembly variants), the **declarative query/logic** corner (SQL, Datalog), and — the
exploratory end — **visual** paradigms (Node-RED flow-graph, TurboWarp/Scratch blocks, Pure Data
reactive patch).

> **Per-peer map.** For *which* peer probes *which* axis, and the selection principle behind the set,
> see `research/PEER-ATLAS.md`. This document is the cross-cutting synthesis; that one is the roster.
This doc answers the one question that outlives any individual peer: *given the core protocol and an
arbitrary programming substrate, what carries over cleanly, what needs a bridge, and what genuinely
doesn't fit?* It organizes lessons that live operationally in `AGENTS.md` ("Durable cross-language
lessons") and `protocol-generator/shared/evaluations/visual-paradigms.md`; read those for the per-case detail.

> **2026-07-15 — the last two axes closed.** Oz/Mozart (dataflow-variable concurrency) and Io (pure
> prototype-based OO) were built to full gate-green (`682·0F @ cc1970f`). They close the last
> genuinely-distinct **concurrency shape** (§4 below, now four) and the last unprobed **object model**
> (§1). Both reinforced — did not overturn — the meta-takeaway: the protocol fit both, the seam sat
> exactly where predicted, and neither produced a new *spec* finding (both wells: dry). Their durable
> yield is one new concurrency data point + three build-discipline lessons folded in below.

## The one-line answer

**The wire contract and the dispatch *logic* are substrate-neutral; the friction is concentrated in
a small, predictable set of wire-touching axes.** The substrate mostly determines *how much seam* you
need (canonical CBOR + crypto + byte/map types), not *whether* the protocol fits. It fit everywhere
we tried — including two visual paradigms. The places it genuinely *strains* a substrate are exactly
two, both small and now mapped: bignum-free integer width, and thread-local-free concurrency.

## 1. Translates cleanly — the protocol is genuinely neutral here

- **The dispatch sequence (§6.5), the verify ladder (§5.2), status codes, and the authority logic**
  are pure control flow. Expressible in any Turing-complete substrate — *including visual block/flow
  graphs*. TurboWarp proved the *logic itself* (not a wrapper) authors as Scratch blocks: guard
  ladders, the op-switch, the exact pinned status codes.
- **§6.6 handler resolution** is a tree walk — a `repeat until` loop that drops path segments
  longest-prefix-first. A loop works anywhere; even Scratch authors it on the canvas. And it renders
  *natively* in each substrate's own idiom: Io (pure prototype-OO) expresses it as **delegation up a
  proto chain** — a `DispatchNode` proto network where longest-prefix resolution *is* the proto-chain
  lookup, not a loop bolted on. The logic is the same walk; the substrate picks the spelling.
- **Op-switches and guard ladders** are trivial in every substrate.

Takeaway: *nothing in the protocol's decision logic assumes a particular language.* That portability,
demonstrated concretely across the whole 46-substrate cohort, is itself a result — a strong signal the
spec isn't accidentally baked to one runtime model.

## 2. Needs a seam — substrate-dependent, but always bridgeable

- **Canonical CBOR is the single most universal "doesn't come for free."** *No* platform library
  suffices — not Rust `ciborium`, not .NET `System.Formats.Cbor`. Every peer hand-rolls the
  shortest-float ladder + recursive major-type-6 tag-reject + length-then-lex key sort on top. This
  is precisely why the language-agnostic **C-ABI FFI codec** (`libentitycore_codec`) exists as a
  fallback, and why a from-spec C codec was reasonable.
- **Crypto is a spectrum**, and the S1 profile must classify each peer onto it: native-stdlib →
  native-audited-lib incl. Ed448 (Haskell crypton, Elixir OTP `:crypto`) → native-pure-lang (Common
  Lisp) → **gap → hybrid-FFI** (OCaml/Zig/Swift). Ed25519 + SHA are broadly native; **Ed448 is the
  fault line** — the one primitive that most often forces the FFI seam (scoped to an opt-in
  sub-library so the shipped default peer stays self-contained).
- **Byte and map types**: substrates without them (visual: Scratch has neither) carry protocol values
  — envelopes, entities, hashes — as **opaque handles** (short string ids into a side table). Only the
  *readable* fields (uri, request_id, author-present) surface as plain values. This is the general
  pattern for "the substrate can't hold the value but must route it."
- **Sockets**: a universal seam for *sandboxed* substrates. The browser and Scratch have no raw TCP →
  a WS↔TCP bridge. Native and Pure Data (`[netreceive]`) have raw TCP → no bridge.
- **The FFI seam has a hidden cross-ISA cost — the load-bearing finding for the asm/ISA arc
  (asm-x86_64, 2026-07-13/14).** The hand-written x86-64 peer is **green** (`--profile core`
  682·0F, concurrency 5/5 incl. `t1_3_no_head_of_line` which COBOL had to skip, §7a
  `validate_echo_dispatch` PASS) at **Level-1 (FFI-all)**: it hand-rolls transport + envelope/data-map
  CBOR + dispatch + the §9.1 floor in asm, but FFIs the *entire* entity codec + Ed25519 + SHA-256 to
  `libentitycore_codec.so`. That seam is what makes x86-64 *easy* — and what makes an **ISA port
  heavier**: the `.so` is x86-64-only, so an ARM64/RISC-V L1 port must cross-build the C codec **and
  libsodium** for that arch (or run it under qemu). This **inverts intuition**: a **pure-asm codec
  (L2/L3) is MORE portable across ISAs than the FFI-hybrid**, because pure asm carries *no*
  foreign-arch library dependency — only the register file + syscall table change. The asm shell
  itself ports near-mechanically: ARM64 and RISC-V share the kernel *generic* syscall table and put
  the syscall args in the *same* registers as the call args, so arm64→riscv is ~a register-rename and
  x86-64→either is ~a table swap (write the x86-64 template pre-adapted — `openat`, `epoll_pwait` — and
  the port is mechanical). So Axes ISA×hand-roll-level are **coupled**: "protocol on three ISAs" pays
  for pushing toward pure; "protocol on the bare machine, fastest" keeps L1 x86-64. Full design map:
  `protocol-generator/asm-x86_64/arch/OPTIONS-AND-ISA-MAP.md`.
  **Arc CLOSED (arm64 2026-07-15, riscv64 2026-07-16) — both L1 green, `--profile core` 682·0F
  byte-identical to x86-64.** Two corrections to the prediction above: (a) **the FFI×ISA cost is
  bounded, not prohibitive** — you do NOT need to go pure (L2/L3) to reach a third ISA. The "pure is
  more portable" thesis holds in principle, but in practice the foreign-arch libc+libsodium is just
  *sourced from a first-class distro*: arm64 via Fedora `--forcearch`, riscv64 (a Fedora *secondary*
  arch with no forcearch path) via **Debian trixie `.debs`** extracted into a cross-sysroot — no
  foreign-arch execution, no host binfmt, the Go oracle stays native (A-RISCV-002; retired an earlier
  "riscv BLOCKED" call). (b) **The fan-out/transliteration risk is proportional to how far the register
  map is from a bijection.** x86→arm64 has register-pressure divergence → a per-function arg-register
  seam bug (A-ARM64-003: a revoked cap accepted, an unregister that didn't delete — 3 FAILs the oracle
  caught). arm64→riscv64 is a **clean bijection** (same register class + arg model), so a 9-way parallel
  fan-out where no agent saw another slice landed **0-FAIL on the first full run** (A-RISCV-004). Lesson:
  same-register-class ISA ports are near-free; cross-class ports need the oracle to catch the seam + an
  explicit per-call-site arg-register audit. (Honesty: corroboration, not independent convergence — one
  generation lineage across all three ISAs + the same FFI codec `.so`; the wire axes are saturated,
  ADR-0012.)

## 3. Fixed-width artifact, not a protocol property

- **Integer head-form.** Only fixed-width-int languages (OCaml int63 / C# ulong / TS bigint / Zig u64)
  must carry the CBOR integer head-form + the `[2⁶³, 2⁶⁴−1]` self-test. **Bignum languages**
  (Elixir / Python / Ruby / Lisp / Haskell / Smalltalk) carry the full range **free**. The protocol
  doesn't care about integer width — the *substrate* does. Branch the profile by language class; never
  treat the head-form as a protocol requirement.

## 4. The substrate's concurrency model dictates the shape (§7b / §6.11)

There are now **four** structurally-distinct ways a substrate satisfies §7b store-safety + the §6.11
handler-outbound demux. The demux is the discriminator — how a peer correlates an out-of-order
`EXECUTE_RESPONSE` back to the handler that originated the outbound EXECUTE:

| Concurrency model | Peers | §6.11 demux mechanism | Cost |
|---|---|---|---|
| Actor-isolation | Swift, Elixir | mailbox / reply-ref | ~free |
| STM transactions | Haskell | transactional retry | ~free |
| CSP channels | Go | per-request reply channel | ~free |
| threads + lock / async | C, Zig, Java, Rust, … | **correlation map** (request_id → waiter) | a tax |
| single-thread event loop | Pd, TurboWarp, **Io** | **cooperative yield** + one in-flight slot | a yield tax |
| **dataflow variables** | **Oz/Mozart** | **the variable *is* the demux** | ~free |

- **§7b store-safety**: actor-isolation (Swift/Elixir) *or* STM (Haskell) satisfy it **structurally**;
  raw-thread/image runtimes (Zig/CL) enforce it **manually**.
- **The fourth shape — dataflow variables (Oz/Mozart, 2026-07-15).** A single-assignment dataflow
  variable collapses the demux to nothing extra: the connection's reader thread reads *all* frames and
  routes them (a response frame **binds** the pending request's variable; each inbound request frame
  dispatches in its own worker thread), so a handler that originates an outbound EXECUTE just sends
  then `{Wait Var}` — the reader binds `Var` when the correlated response arrives, and *never blocks on
  dispatch*, so reentry cannot deadlock. **The variable is the correlation map** — no side table, no
  yield discipline. This is the cleanest §6.11 substrate in the cohort, and the distinct data point Oz
  was built to produce (A-OZ-006). It sits opposite the single-thread event loop, which pays the demux
  as a *cooperative-yield* tax (next bullet + §Io below).
- **§6.11 handler-outbound demux**: ~free on actor/CSP/dataflow substrates, a correlation-map **tax**
  on thread/async peers, a **cooperative-yield** tax on single-thread event loops. Factor this into
  effort estimates.
- **Single-thread event loop, revisited (Io, 2026-07-15).** Io (coroutine + libevent, one event loop)
  lands in the same class as Pd/Scratch: it can't parallelize, so it must not block the loop. Its S4
  concurrency failures were **not** a throughput ceiling — they were two loop-blocking bugs (a
  per-request `try` that leaked a coroutine's retain stack, and a *blocking* send that stalled every
  connection when one client read slowly). Fixed → clean sustained-load + churn (0/10000 dropped). The
  lesson is the Pd/Scratch lesson restated for a coroutine runtime: **on a single event loop, every
  per-request primitive must be non-blocking (buffered writes, no synchronous retry-sleep) and must not
  accumulate** — the loop is the one resource all connections share.
- **The substrate's crypto *execution mode* is load-bearing for §6.11 (wasm-wat, 2026-07-15).**
  §5.2 verifies **every** request (2 Ed25519 verifies: author-sig over the per-request root hash +
  granter-sig over the cap hash) — correct and deliberate (forwardability, content-addressed
  caching, cross-peer verification), negligible (~µs) on any *compiled* substrate. But on an
  **interpreted** one it's ~ms and dominates: WasmEdge's default interpreter runs one verify at
  **~9 ms**; its JIT (`--enable-jit`) at **~84 µs (109×)**. At interpreter speed the §6.11 T2.1
  10k-request probe times out (the ~60 s aggregate run budget can't absorb 10 000×~18 ms serial);
  under JIT it passes with margin. So for a crypto-heavy per-request protocol on an interpreted
  host, **the compiled execution mode + its launch flag become part of the peer's conformance
  contract** (documented in `run-s4.sh`) — the §6.11 analog of "no platform CBOR lib suffices."
  On this runtime that mode is **JIT specifically**: WasmEdge 0.17 AOT (`wasmedge compile`) embeds
  native code (347 KB → 1.05 MB) but the 0.17 *runner does not execute it* — confirmed empirically
  2026-07-15: the AOT artifact run with no JIT flag **FAILs `t2_1` at 22.9 s** (crypto still ~9 ms),
  identical to the pure interpreter, while JIT **PASSes at 1.3 s**. So JIT is the only lever and it
  pays a per-boot compile cost. The wasm portability boundary is the **transport ABI, not the
  protocol logic**: the dispatch interior (codec, §5.2, handlers, the reentrant dialer) is
  ABI-neutral, but `host.wat`'s ~15 socket imports bind to WasmEdge's non-standard `sock_*`
  extension — a Wasmtime/WAMR port (which have working AOT) needs a wasi-sockets/preview2 shim for
  just that layer. Three spec findings fell out of this substrate (F33 T2.1 absolute-floor tension,
  F34 tampered-cap-sig coverage gap, F35 §7a reentry-echo skips §5.2 → outbound-authz untested) —
  see `protocol-generator/shared/findings/concurrency-latency-floor-and-cap-sig-coverage.md`
  (F33/F34) and `protocol-generator/shared/findings/wasm-dialer-parity-F35-and-execution-mode.md` (F35). **Do NOT** paper over slow crypto
  with a per-connection auth-verdict cache: `security.tampered_signature` proves per-request
  verification is mandatory (it flips the author sig on a warm connection and expects 401).
- **§7a same-connection reentry needs no true peer-side concurrency (wasm-wat, 2026-07-15).** The
  §6.11 reentrant outbound seam (dispatch-outbound dialing B back mid-request) reuses the *inbound*
  connection, so on a single-threaded poll loop the whole suspend/pump/resume collapses to
  *"dispatch returns one frame; the send-loop is unchanged"* + a `pending[echo_rid → dispatch_rid]`
  table on one fd. M=8 concurrent reentries pass deterministically (~44 ms). Correlation-by-request_id
  on a single fd is the entire cost — the reentry contract does not force a threaded pump when reentry
  is same-connection.
- **Compiling a whole peer to wasm costs ~1% over native; the codegen choice is size-vs-throughput
  (rust-wasm, 2026-07-15).** The generated Rust peer's library cross-compiled to `wasm32-wasip1`
  **unmodified** (~4,000 lines: codec, §5 authz, §6 dispatch, §9.5 floor, ed25519-dalek + sha2 — zero
  source changes; even `random_nonce`'s `/dev/urandom` fallback covers the WASI sandbox free), behind a
  336-line single-threaded `poll_oneoff` transport seam that ports the *same* single-fd reentry-demux as
  wasm-wat/asm — `Peer::dispatch` is byte-identical to native, the seam absorbs the whole thread→poll
  difference. It reaches the SAME `--profile core` 0-FAIL as the hand-authored WAT peer (291P/294W/0F).
  Head-to-head on ONE runtime (WasmEdge 0.17.1 JIT) isolates codegen: **compiled Rust wins size (−29%:
  242 KB vs 340 KB — LLVM DCE/LTO + a natively-carried codec vs a merged codec.wasm's duplicated data),
  JIT warmup (−28%: smaller module → less to JIT), and effort (reuse a whole peer + one host file vs
  ~559 hand-authored WAT functions); hand-authored WAT wins per-request throughput (~1.8× on the 10k
  sustained-load probe — the WAT loop has no allocator/abstraction tax; the Rust hot path pays a Vec +
  HashMap + socket-crate copy per request).** The decisive control: the **same Rust peer as native ELF
  vs as wasm runs within ~1%** (22.82 s vs 23.06 s full-core — both dominated by Ed25519 under JIT + one
  20 s interior settle-check present in *both* native and wasm, absent in wasm-wat's different interior).
  So **portable compute is nearly free at the compute layer; the whole per-substrate cost is the
  transport-ABI seam** — the deployable-layer implication for the NAD-native / computational-genome arc:
  default to *compiling* an existing peer (small, fast to instantiate, ~free to produce), and reserve
  hand-authoring for the hot loop only when steady-state throughput dominates. The two transport lessons
  are runtime properties, not codegen artifacts, and bit exactly as they did for wasm-wat: **single-send
  framing** (ship `[len][payload]` in ONE write — two sends let Nagle stall the body ~40–200 ms on cold
  round trips → §6.11 churn timeout) and **JIT as the crypto execution-mode contract**. Full head-to-head:
  `protocol-generator/shared/evaluations/wasm-codegen-comparison.md`.
- **Mature-AOT (wasmtime) gives compile-once-run-native — and wasip1 sufficed, correcting the earlier
  wasip2 prediction (rust-wasm-wasmtime, 2026-07-15).** The SAME `rust-wasm` wasip1 module, run under
  **wasmtime** and precompiled (`wasmtime compile` → `.cwasm`), reaches the SAME `--profile core` 0-FAIL
  (291P/294W/0F/97S) with §6.11 churn passing at native speed. This is the production story WasmEdge
  0.17's *inert* AOT couldn't give. Two durable lessons: **(1)** the seam boundary above (line ~83)
  guessed a wasmtime port would need a **wasi-sockets/preview2** shim; it did **not** — wasip1 works, via
  a **host-preopened listener** (`wasmtime run -S preview2=n -S tcplisten=ADDR`) + the *standard* wasip1
  `sock_accept`/`poll_oneoff` (the `wasi` crate), replacing WasmEdge's non-standard self-bind `sock_*`.
  So the port cost was **only the accept-model swap** (self-bind → preopened-fd) — framing, the §7a pump,
  dispatch all ported verbatim; wasip2 is a *deferred forward-ABI probe*, not a prerequisite, and avoiding
  it keeps the toolchain distro-pure (fedora ships no wasip2 std → rustup, which S11 forbids). **(2)** the
  headline warmup win (~3 s → ~ms) is a **runtime** property (WasmEdge→wasmtime; Cranelift JIT is already
  ~ms), NOT an AOT property — AOT's real payoff is removing the *residual* per-boot compile (~68 ms →
  ~5.7 ms) and yielding a **deploy-time native artifact** that boots with zero compile. Cost: the `.cwasm`
  is **wasmtime-version-pinned** (a deploy-time recompile, not portable). Net for the NAD-native arc: the
  substrate is now covered end to end — *author/compile* the compute (~free, portable), *deploy* it AOT on
  a mature runtime (native boot). Third column of `protocol-generator/shared/evaluations/wasm-codegen-comparison.md`.- **The sharpest finding — thread-local-free concurrency.** Scratch has *no* per-thread/per-request
  variable scope (all vars are sprite/global). A request-handling peer therefore **structurally
  cannot** process requests concurrently without clobbering its working state → it *must* serialize,
  or cooperatively yield between requests. §6.11's no-serialization / no-head-of-line MUST meets its
  match here: the substrate can pass it only via **cooperative scheduling** (yield between hats — the
  fix that took TurboWarp's connection-churn from flaky to solid), never true concurrency. This is the
  clearest instance of *the protocol assuming something (per-request isolation) a substrate can't
  cleanly provide.*

## 5. Genuinely fights the substrate — the honest limits

- **Reactive dataflow vs request/response.** A peer is request/response; a reactive-patch substrate
  (Pure Data, Max) is continuous pull/push. Expressing a stateful handshake + guard ladder in a signal
  graph is a real paradigm *mismatch* — and characterizing that mismatch is the entire value a **Pure
  Data** probe would add (it has raw TCP → *full control*, no bridge — the one remaining probe that
  would be more than a repeat). Worth it for the mismatch story, **not** for spec discovery.
- **No dynamic dispatch.** Scratch can't call a procedure by a dynamic name, so the
  resolved-handler → body step is a literal switch. (The resolution *itself* is a real authored tree
  walk; only the final routing is substrate-limited — label it honestly as body-selection.)

## 6. Does NOT produce findings — the honest ceiling

- **Off-wire novelty** (idiom / error-model / packaging / concurrency-style) buys **generator
  robustness**, not spec findings. Spec discovery is **substrate-bound to the wire-touching axes**:
  integer width, float model, crypto availability, string model, byte/map primitives. With 15+ peers
  the well is **dry** on the current wire surface; steady state is re-running the cohort against each
  amendment, not adding language #N.
- **The findings that *did* land came from *how* we built, not *which* language.** The visual peers'
  payoff was **decomposition**: folding §5.2 into one boolean masked three real conformance bugs
  (single-401 grantee carve-out, chain-depth-before-authz, unchecked revocation), recovered only by
  making the ladder visible. *A folded verdict is a hiding place* — that generalizes to every peer,
  and it's a build-discipline lesson, not a language lesson.
- **Guard dynamic dispatch with the declared-op set (prototype/delegation substrates).** Where §6.2
  operation dispatch is rendered as a real dynamic message-send (Io: `handler perform(op)`), *every
  inherited slot becomes wire-reachable* — `clone`, `print`, `type` are suddenly callable
  "operations." Dispatch must check the op against the handler's **declared** operation set (the
  manifest's `operations` map) *before* the send, and name the methods out of the wire namespace
  (`op_get`, not `get`). Delegation makes everything reachable unless you scope it (A-IO-004/007). The
  dual of the visual peers' "author the logic, don't wrap it": here you must *fence* the logic the
  paradigm makes too reachable.
- **List-substrate sentinels + the dispatcher catch-all (Oz, A-OZ-005).** On a substrate where the
  empty string *is* the empty list *is* `nil` (Oz), `== nil` is a broken "first-iteration / no-value"
  sentinel over string data — it silently swallowed the leading `/` of every absolute path and
  404'd **every authenticated dispatch**. Two rules generalize to any list/nil-conflating substrate:
  (a) never test string data for `== nil` as a loop sentinel; (b) **a request dispatcher MUST catch
  the host language's *root* exception class, not just its codec's condition family, and map to 500** —
  an uncaught per-request exception is indistinguishable from a hang and violates deliver-or-signal
  (§4.9(c)). This is the *same* lesson Smalltalk's A-ST-016 landed (one live `doesNotUnderstand:`
  cascaded 229 FAILs): **on any no-static-check substrate, the resilience frame catches the root error
  class.** Two independent peers finding it makes it a cohort rule.
- **A sibling that clears the bar with a *costlier* seam disproves a ceiling claim (a diagnostic).**
  Io's first S4 verdict was "single-threaded throughput ceiling — the substrate can't clear sustained
  load." The Oz sibling passed the identical checks while paying a *slower* crypto seam (a co-process
  pipe per op vs Io's in-process addon). A slower peer clearing a bar a faster one can't is a
  contradiction that a ceiling can't explain — it forced re-measurement, which showed latency
  *collapsing* (accumulation, not a flat wall) and found two fixable bugs. **Cross-peer differentials
  are a first-class debugging tool**: a "my substrate just can't" claim is only credible once no
  sibling with a heavier seam has already done it. (Corollary to the honesty doctrine: an unreconciled
  ceiling contradicted by the cohort is an overclaim in the pessimistic direction — as much a
  misreport as a false green.)

## 7. Where the visual peers land (honest status)

**Not real peers — exploratory / illustrative** (flagged as such in `CONFORMANCE-MATRIX.md`), and
distinct from the alien-substrate *language* probes (Tcl/Rexx/Forth/Smalltalk/APL) which are full
gate-green peers. Node-RED delegates the entire §6.5 engine (a flow-graph wrapper). TurboWarp authors
the dispatch + all handler bodies as Scratch blocks but delegates crypto to a bundled seam, runs
sandboxed (needs a bridge), and is measured by a faithful block-*interpreter* pending a real-VM run.
Their value is threefold: (1) the decomposition findings; (2) **reusable techniques** — author-in-the-
paradigm not wrap-it, the opaque-handle seam, and *the oracle-driven interpreter of the actual authored
artifact* (the single most reusable trick — run the real graph against the oracle); (3) a **readable
reference for those communities** — a Node-RED or Scratch author can study the protocol in their own
idiom. That community-reference value is why they're kept in the matrix, clearly labeled exploratory.

## 8. Authority-as-query — the last frontier, now closed

**The one region that taught us about the *protocol*, not the substrate.** SQL (SQLite + C seam) and
Datalog (embedded Ascent + Rust seam) authored the §5/§6.6 authority interior *in the query/logic
language* and both cleared the full core gate (`682·0F Result: PASS @ cc1970f`). The finding: **authority
is a query; the protocol around it is a state machine.** Everything that is a pure function of the
projected request facts — the §5.2 verdict, the §5.5 delegation closure, §5.5a scope-match, §3.6 K-of-N,
§6.6 resolution — expresses cleanly and often *more legibly* than the imperative prose; everything
stateful-sequential (§6.5 dispatch, §4 handshake, framing/crypto/store) leaks to the host. Unlike the
substrate probes (whose spec-discovery well is dry), this one **produced findings**: F40 (§3.6 scope
matching is typed — id dims literal, path dims canonicalized — surfaced by SQL as a real ALLOW bug) and
F41 (the decision surface is a monotone deductive system, so an authority-as-derivation appendix could
make fail-closed + the within-grant conjunction structural invariants rather than silently-violable
MUSTs). The wrapper-guard held through S4 on both — completing the handler surface added zero imperative
allow/deny — and *that absence is itself the datum*. Full synthesis:
`protocol-generator/shared/evaluations/authority-as-query.md`; arch routing:
`protocol-generator/shared/evaluations/authority-as-query.md`.

## The meta-takeaway

The core protocol is **more portable than the per-substrate friction suggests.** It landed on
compiled, interpreted, array, stack, pure-object, decimal, and visual substrates; the substrate
decided how much seam (CBOR + crypto + byte/map) — not whether the protocol fit. The two points where
it truly strains a substrate — bignum-free integer width and thread-local-free concurrency — are small
and now precisely mapped. So the honest bottom line of the whole exercise: **we did not discover much
*new spec* (the well is dry on this wire surface), but we proved something durable — that entity-core's
wire and dispatch logic are substrate-neutral to an unusual degree, and we mapped the exact, short list
of places a substrate has to work to meet it.**

With Oz (dataflow-variable concurrency) and Io (pure prototype-OO) closing the last distinct
concurrency shape and the last unprobed object model, the axes that were ever going to strain the
protocol are now all mapped: **four §7b concurrency shapes** (actor/STM/CSP, thread+lock, single-thread
event-loop, dataflow-variable), every mainstream object model, the full integer/float/string/byte-model
spread. The remaining named targets (`COMPLETENESS-ROADMAP.md`) are catalog completeness or
same-substrate corroboration — **breadth, not new axes**.

The one region that *did* still teach us about the **protocol** rather than the substrate was
**authority-as-query** (SQL / Datalog) — and it has since been built and closed (§8 above), producing
F40 and F41 exactly as predicted. That closure carries the most transferable selection lesson of the
whole sweep: **mechanical distance stopped paying around peer 15; conceptual distance kept paying.** A
substrate that represents *bytes* differently had nothing left to tell us. A substrate that expressed
the protocol's *ideas* differently still did. When weighing a future peer, that is the question to
ask — see `PEER-ATLAS.md` §5–§6.

Otherwise the steady state is maintenance: re-run the cohort against each amendment, tier-gated.

## See also

- `research/PEER-ATLAS.md` (which peer probes which axis + the selection principle)
- `research/CRYPTO-LANDSCAPE.md` (the cross-language cryptography survey — §2's crypto spectrum in full)
- `AGENTS.md` → "Durable cross-language lessons" (the operational, per-case version)
- `protocol-generator/shared/evaluations/visual-paradigms.md` (the visual-track deep dive + field survey)
- `research/LANDSCAPE.md` (tier roster, alien-substrate track, "discovery is substrate-bound")
- `CONFORMANCE-MATRIX.md` (per-peer transparency + the ‡ exploratory-probe framing)
