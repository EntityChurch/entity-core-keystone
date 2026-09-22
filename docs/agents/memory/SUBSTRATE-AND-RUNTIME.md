# Substrate and runtime — keystone memory

What a target language's runtime does to a peer: crypto availability, concurrency shape, lifetimes and leaks, source-format hazards, and the visual and query paradigms.

**Arrive here when:** the peer crashes, hangs, leaks, or a source file will not compile for a reason particular to the language.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- Profile decides; the agent doesn't
- Crypto availability is a spectrum
- Concurrency taxonomy (§7b store-safety) — now FOUR structural shapes:
- Prototype/delegation substrates: fence dynamic dispatch with the declared-op set
- UNSEQUENCED ARGUMENT EVALUATION IS THE C HAZARD THIS WORK KEEPS RE-CREATING, and it compiles clean under `-std=c11 -pedantic -Wall -Wextra -Werror`
- A RULE EXPRESSED IN TERMS OF A CPU FLAG IS NOT PORTABLE — restate it as a value comparison before porting it
- On any no-static-check substrate, the resilience frame catches the host's ROOT error class → 500
- A TRANSIENT `accept()` ERROR MUST NOT END THE ACCEPT LOOP — a peer that stops LISTENING while the process stays alive and healthy reads as a crash and is invisible to every liveness check
- Memory-primary peers: scope §6.5 signature ingestion to *handler-discoverable* signatures
- A RESOURCE BOUND MUST RELEASE ON THE SAME PATH IT IS TESTED ON — and a bound that never releases presents as a DEAD PEER, not as an over-permissive one
- ON A MANAGED RUNTIME, WHETHER A REFUSAL REACHES THE WIRE IS DECIDED BY THE STREAM LAYER'S DEFAULTS, NOT BY THE CODE THAT WRITES IT — and every throw site reads correctly while it fails
- A HANDLER'S SCOPE IS A PROPERTY OF THE LANGUAGE, NOT OF WHERE THE TEXT SITS — IN ADA AN EXCEPTION RAISED WHILE ELABORATING A BLOCK'S *DECLARATIVE PART* IS NOT HANDLED BY THAT BLOCK'S OWN HANDLER (LRM 11.4), AND THE ARM THAT NAMES THE EXCEPTION BY NAME SITS RIGHT THERE LOOKING CORRECT
- RATIFIED, SECOND AND THIRD OCCURRENCE — A RELEASE MUST BE DISARMED WHEN OWNERSHIP TRANSFERS, AND THE DANGEROUS FORM IS A CONSTRUCTOR THAT TAKES OWNERSHIP *ON SUCCESS ONLY*
- RATIFIED, THIRD FORMAT — A COMMENT DELIMITER IS CODE, AND THE RULE'S OWN CANONICAL WITNESS IS WHAT BREAKS IT
- Peer-selection: discovery yield is substrate-bound, not idiom-bound
- RATIFIED — SECOND OCCURRENCE, DIFFERENT LANGUAGE, DIFFERENT ALLOCATOR: A DETACHED WORKER MUST NOT OUTLIVE THE STATE IT BORROWS
- `detach()` IS THE HAZARD, EVEN WHEN THE BORROWED STATE IS SAFE — the victim can be the RUNTIME'S OWN bookkeeping
- A COMMENT THAT NAMES A LIFECYCLE STEP IS NOT EVIDENCE THE STEP EXISTS — count the resource at two points in time instead of reading the code that manages it
- AN INLINE `{ type X }` IMPORT IS STILL A VALUE IMPORT OF THE MODULE, AND THE EMITTED NO-OP CAN BLOCK A WHOLE BUILD TARGET
- PROSE IN A COMMENT IS CODE, IN ANY FORMAT WHERE PUNCTUATION TERMINATES A RECORD — and the errors it produces are invisible if the peer logs to a file that dies with the container
- Lean proof vector
- Visual/dataflow paradigms: author the protocol IN the language, don't wrap it
- Authority IS a query; the protocol around it is a state machine (the declarative-query/logic frontier, now closed)
- Oz: a non-ASCII byte baked into a compiled string constant can crash the peer at runtime, not at compile time
- RATIFIED (second occurrence, different shape — promoted off the candidate ladder): a non-ASCII byte in a WIRE-VISIBLE string can crash a peer's own encode path, independent of language/substrate

---

- **Profile decides; the agent doesn't.** Library, error-model, async-style, naming, and
  packaging choices are all driven by `profile.toml` + `templates/`. Unauthorized decisions
  go to the ambiguity log — no picking "the popular logger." No language-specific syntax
  (Go tags, C# attributes, Rust derives) ever leaks into `shared/`.

- **Crypto availability is a spectrum** that the S1 profile must classify: native-stdlib /
  native-audited-lib-incl-Ed448 (Haskell crypton, Elixir OTP `:crypto`) / native-pure-lang
  (Common Lisp) / gap → **hybrid-FFI** via `libentitycore_codec` (OCaml/Zig/Swift; Ed448
  only, Ed25519+SHA stay native). Hybrid-FFI is scoped to an **opt-in sub-library** so the
  shipped default core peer stays self-contained + FFI-free.
  **Fifth tier — managed-runtime-NO-C-FFI (Unison #43):** the hybrid-FFI hatch is
  *structurally unavailable*, so agility can only be pure-language or **deferred** (deferral is
  fine — Ed448/SHA-384 WARN, they don't gate `--profile core`). Classify this at S1, since it
  removes the cohort's standard fallback. Sub-case worth its own probe: **a runtime can ship
  sign/verify and still ship no KEY DERIVATION.** UCM exposes `crypto.Ed25519.sign.impl` /
  `verify.impl` — and `sign.impl` takes the pubkey as an *argument* — but no keygen, forcing a
  hand-written GF(2²⁵⁵−19) implementation (base-2¹⁶ limb arithmetic + twisted-Edwards scalar
  mult + point compression). So at S1 probe for **keygen specifically**, not just "is Ed25519
  present". And on such a substrate treat the pubkey as *part of the identity* — derived once
  and carried; exposing `sign(seed, msg)` silently makes every signature pay a full keygen.

- **Concurrency taxonomy (§7b store-safety) — now FOUR structural shapes:** actor-isolation
  (Swift/Elixir) *or* STM-transactions (Haskell) satisfy store-safety structurally; raw-thread/image
  runtimes (Zig/CL) enforce it manually; single-thread event loops (Pd/TurboWarp/**Io**) serialize +
  cooperatively yield; **dataflow-variable (Oz/Mozart)** is the fourth — a single-assignment variable
  per pending request, no shared mutable state to guard. The §6.11 handler-outbound demux is ~free on
  actor/CSP **and dataflow** substrates (the dataflow variable *is* the demux — reader binds it, the
  handler `{Wait}`s, dispatch never blocks — A-OZ-006), a correlation-map tax on thread/async peers,
  and a **cooperative-yield** tax on single-thread event loops — factor into effort estimates. On a
  single event loop every per-request primitive must be non-blocking + non-accumulating (Io's S4 fail
  was a blocking send + a per-request `try`-coroutine leak, NOT a throughput ceiling — A-IO-025/026).
  **Algebraic-effects/abilities (Unison #43) is a fifth ROUTE, not a fifth shape** — worth stating
  precisely rather than inflating: `fork` green threads + a single `MVar` store (`take → pure fn →
  put`) lands on the *actor* guarantee (one owner, serialized mutation) but reaches it through the
  effect system rather than a mailbox. §6.11 demux is a per-request `Promise` — the dataflow-variable
  pattern in a different dress, so it sits with the ~free column, not the correlation-map tax (A-UN-004).

- **Prototype/delegation substrates: fence dynamic dispatch with the declared-op set.** Where §6.2
  op-dispatch is a real dynamic message-send (Io `perform`), every inherited slot (`clone`, `type`,
  `print`) becomes wire-reachable — check the op against the handler's manifest `operations` map
  *before* sending, and name methods out of the wire namespace (`op_get`, not `get`) (A-IO-004/007).

- **UNSEQUENCED ARGUMENT EVALUATION IS THE C HAZARD THIS WORK KEEPS RE-CREATING, and it compiles
  clean under `-std=c11 -pedantic -Wall -Wextra -Werror`.** Candidate — but it happened TWICE in one
  session, once avoided at authoring time (`c`) and once reintroduced five commits later (`sql`),
  which is the shape that earns a note. Folding a computed term into a MIN accumulator invites
  `min_defined(add_ttl(created, ttl, &t), t, &acc, &have)` — which READS and WRITES `t` in one
  unsequenced argument list. In `sql` it folded a garbage term, so `ttl_ms:0` minted the caller
  cap's expiry instead of `created_at`, and the oracle reported it as a CAP-6 rule-2 failure with no
  hint of undefined behaviour. **Rule: a term computed by an out-parameter lands in its own local
  BEFORE the call that consumes it.**

- **A RULE EXPRESSED IN TERMS OF A CPU FLAG IS NOT PORTABLE — restate it as a value comparison
  before porting it.** Candidate (`riscv64` 2026-08-30). §5.6 rule 3's "the term is DROPPED if it
  does not fit" is an overflow test; x86-64 reads the carry flag after `add`, aarch64 after `adds`,
  and **RISC-V has no condition-flags register at all**, so the port has to detect the wrap the way
  the ISA intends — the sum wrapped iff it is less than either operand. Getting this wrong compiles
  clean and passes every check that does not overflow; it silently saturates instead of dropping,
  which is exactly the CAP-6 defect the rule exists to prevent. The same shape appears on any
  bignum substrate from the other direction (§5.6 rule 3 is a DELIBERATE range check there, not an
  overflow trap) — the invariant is the value, never the mechanism.

- **On any no-static-check substrate, the resilience frame catches the host's ROOT error class →
  500**, not just the codec's condition family — an uncaught per-request exception is a hang and
  violates deliver-or-signal (§4.9(c)). Two peers landed this independently: Oz (`""` IS `nil` → a
  raise escaped a narrow catch, hung the request; also never use `== nil` as a string sentinel —
  A-OZ-005) and Smalltalk (one `doesNotUnderstand:` cascaded 229 FAILs — A-ST-016). Cohort rule.

- **A TRANSIENT `accept()` ERROR MUST NOT END THE ACCEPT LOOP — a peer that stops LISTENING while
  the process stays alive and healthy reads as a crash and is invisible to every liveness check.**
  Candidate, two shapes found in one sweep (2026-09-01). `zig` had `server.accept() catch break`,
  fatal on its entire `AcceptError` set; `c` had `if (errno == EINTR) continue; break;` under a
  comment saying *"socket closed → stop"* — the intent is right, the code stops on `ECONNABORTED`,
  `EMFILE`, `ENFILE`, `ENOBUFS` and `EAGAIN` too, all recoverable. `ECONNABORTED` is the routine one:
  the client sends SYN then closes before the server accepts, which rapid churn manufactures. So one
  aborted connection can permanently kill the listener. **Say honestly what this was NOT: fixing
  both accept loops did not fix zig's churn failure** (the two entries above did) — it is a real
  defect in its own right, and conflating it with the bug found alongside it would have been the
  easy overclaim. Enforcement: `git grep -nE "accept\(\)? *(catch|orelse) *(break|return)"` plus a
  read of every `accept()` call site's error arm; the rest of the cohort (`cobol` `fortran` `rexx`
  `pd` `sql`) already skips a failed accept and keeps looping.

- **Memory-primary peers: scope §6.5 signature ingestion to *handler-discoverable* signatures.** The
  EXECUTE's own request signature (target == the root EXECUTE hash) is consumed inline by
  `verify_request` and never looked up post-dispatch — binding one per request grows an in-memory store
  by a unique entity per request → GC thrash → later-category timeouts under load. Ingest cap /
  identity / handshake signatures (reused → idempotent), skip the transient request sig. Two peers hit
  this independently (Io A-IO-022, Rexx A-RX-014) — an implementation discipline, not a spec gap (spec
  §6.5 is fine); pair it with a §4.10 connection-admission cap for the full resilience story.
  **RATIFIED, THIRD OCCURRENCE (`ocaml`, 2026-09-16) — AND THE CONSEQUENCE IS NOT ALWAYS A TIMEOUT.
  ON A THREAD-PER-REQUEST PEER OVER AN UNSYNCHRONIZED HASH TABLE IT IS A WRONG ANSWER: A `tree get`
  RETURNING 404 FOR AN ENTITY THE PEER HOLDS.** Both prior instances present as *slowness* (GC thrash,
  timeouts), so the class reads as a performance discipline and gets deprioritised. It is not.
  `ocaml`'s `Store` is two plain `Hashtbl`s with no mutex and `transport.ml` spawns a thread per
  connection and another per inbound EXECUTE. **OCaml 5.2.1's `Hashtbl.resize` assigns the new, EMPTY
  bucket array into `h.data` BEFORE repopulating it, and `insert_all_buckets` opens with another large
  allocation — a poll point, i.e. a preemption opportunity at the instant the table is observable as
  empty.** A concurrent `find_opt` there misses a present key. Unscoped ingestion is what drove the
  table across those thresholds: `t2_1_sustained_load` inserts 10 000 unique keys in one check.
  **THE MEASUREMENT IS THE METHOD, AND ITS MIDDLE ROW IS THE LESSON AGAIN:** `baseline 2 of 40 ·
  scoping the ingestion 0 of 80 · + a store mutex 0 of 40`. **Stopping at the middle row ships a peer
  whose store is still racy** — the scoping removes the DRIVER, not the defect, and any concurrent
  `tree.put` can still grow the table while `listing` iterates it. That is the `zig` pattern
  (`3/5 → 1/6 → 0/22`) in a second language: one fix masked the remaining exposure, and only naming
  what each one addresses tells them apart.
  **Two implementation notes for the mutex, because both are ways to turn a race into a deadlock.**
  §6.10 delivery is sync-inline and a consumer is third-party code that may call back into the store,
  so **events are computed under the lock and fired after it is released**; and `bind` must hold ONE
  critical section across the Store step and the Bind step, or a reader sees a path bound to an entity
  the content store does not hold yet (which needs an internal `*_locked` helper, since a non-recursive
  mutex cannot re-enter `put_entity`).
  **Enforcement, and it is the cheap direction: for every peer, name the store's concurrency model and
  the thing that enforces it.** `git grep -n 'Thread.create\|pthread_create\|spawn' <peer>/src` against
  a store with no lock, no actor and no single-thread guarantee is the defect — and note the standing
  §7b taxonomy already answers it for most of the cohort (actor-isolation, STM, single-thread event
  loop, dataflow), so the peers to check are the raw-thread ones. **Verified per-check after both
  changes: 0 of 778 severities moved** — a fix to a data race should be invisible in the verdicts, and
  when it is not, the race was not what you fixed.

- **A RESOURCE BOUND MUST RELEASE ON THE SAME PATH IT IS TESTED ON — and a bound that never
  releases presents as a DEAD PEER, not as an over-permissive one.** Candidate (first occurrence
  here was `asm-x86_64`'s §4.10(c) admission cap, 2026-08-29; ported to `asm-arm64` and `riscv64`
  2026-08-30, where the same double-reap was required and the failure mode would have been
  identical). A fork-per-connection parent that counts admissions must reap **twice** — once before
  the blocking `accept4` and **again after it returns** — because the first reap runs before the
  parent parks, so every child that exits while it is parked is still counted as live when it wakes.
  At an idle peer that is invisible; at the bound it is fatal. Measured: the peer correctly refused
  194 of 256 flood connections and then refused **the one probe that followed**, with every child
  already gone and the count still reading 64. The oracle named it outright — *"admission slots
  leaked; the bound must release when connections close."* **Generalize past sockets: for any
  counter that gates admission, the release path must be reachable from the same loop that reads the
  counter, and it must run AFTER the blocking call, not only before it.**
  Two sub-lessons from the port, both cheap: **§4.10(a)'s "reject BEFORE fully buffering" forbids the
  drain that looks more polite** — draining a declared body to keep the stream framed *is* the
  fully-buffering the section forbids, done one buffer at a time, and a sender declaring 4 GiB and
  sending 1 KiB parks the peer forever while no 413 is ever emitted. And **a connection-wide socket
  idle deadline is NOT the §6.11(c) per-request deadline** — §6.11 separately forbids implementing
  that one as a connection-wide primitive; the two are only compatible because a forked child owns
  its connection exclusively and serves one frame at a time. Say which one you built.

- **ON A MANAGED RUNTIME, WHETHER A REFUSAL REACHES THE WIRE IS DECIDED BY THE STREAM LAYER'S
  DEFAULTS, NOT BY THE CODE THAT WRITES IT — and every throw site reads correctly while it fails.**
  RATIFIED 2026-09-14 (`typescript`, two independent mechanisms in one peer, landing §4.11). Both
  were found by INSTRUMENTING THE CATCH, not by reading the emission path, and neither would have
  been predicted from the vanguards because `go`'s `TCPConn` happens to default the other way:
  - **`for await (const chunk of socket)` destroys the stream when the loop body throws AND
    replaces the thrown error.** Node's async-iterator cleanup is `destroyOnReturn: true` by
    default, so BOTH halves of §4.11 — *put a coded frame on the wire* and *the code belongs to the
    cause* — were lost to one defaulted option. The catch received
    `ERR_STREAM_PREMATURE_CLOSE` with `socket.destroyed === true`. Fixed with
    `socket.iterator({ destroyOnReturn: false })`.
  - **`allowHalfOpen: true` is a §4.11 REQUIREMENT on Node, not a tuning knob.** A truncated frame
    is only knowable at end-of-stream, and Node's default ENDS the server's write side on the
    client's FIN — so the runtime refuses the mandatory coded response with *"This socket has been
    ended by the other party."*
  **RATIFIED THE SAME DAY BY A SECOND RUNTIME, AND THE PARAMETER HAS A DIFFERENT NAME EVERY TIME:
  on the BEAM it is `exit_on_close: false`.** Under `:gen_tcp`'s default, the VM closes our write
  side on the client's FIN, so a truncated frame **cannot** be answered — §4.11 is defeated by the
  runtime with no line of the connection module being wrong. `elixir` needed it; `go`'s `TCPConn`
  has the behaviour by default, which is exactly why neither vanguard would have predicted either
  one. Two runtimes, two spellings, one rule — so **look for the knob rather than waiting to be
  bitten by it**: Node `allowHalfOpen`, BEAM `exit_on_close`, and ask the equivalent question of
  any managed substrate whose socket layer owns the FIN.
  **Enforcement: for any peer on a managed runtime, drive the refusal arms OVER A SOCKET and assert
  the frame ARRIVES.** A unit test that calls the refusal function passes in both worlds. Generalize
  past Node: ask what the stream layer does on (a) an exception inside the read loop and (b) the
  peer's FIN, before claiming a refusal path works.

- **A HANDLER'S SCOPE IS A PROPERTY OF THE LANGUAGE, NOT OF WHERE THE TEXT SITS — IN ADA AN
  EXCEPTION RAISED WHILE ELABORATING A BLOCK'S *DECLARATIVE PART* IS NOT HANDLED BY THAT BLOCK'S OWN
  HANDLER (LRM 11.4), AND THE ARM THAT NAMES THE EXCEPTION BY NAME SITS RIGHT THERE LOOKING
  CORRECT.** RATIFIED 2026-09-16 (`ada`, **three instances in one peer**, found on the wire and by
  nothing else). It is the standing *"a refusal that exists but cannot be reached is a §4.9(c) silent
  drop"* class with a **new mechanism**: every prior instance was a refusal at the wrong *layer* or
  behind an unreachable *branch*; this one is a correct refusal in a handler that **does not govern
  the call that raises**, for a reason nothing in the file's shape shows.
  - `Reader_Task`'s loop read the frame as `Payload : constant Byte_Array := Wire.Read_Frame (…)` in
    the **declarative part** of the very block whose `when Framing : others` arm calls
    `Refuse_Pre_Admission`, and whose 15-line comment says *"an OVERSIZE prefix and a TRUNCATED frame
    are REFUSALS owed a coded frame."* `Payload_Too_Large` and `Truncated_Input` propagated **past
    it**, killed the task, and left the socket open with nothing on the wire.
  - `Salvage_Request_Id` — **a function whose entire purpose is to be total** — called
    `Decode_Salvage (Payload)` in its own declarative part, above its own `when others => return ""`.
    So hostile bytes the salvage decoder itself refuses escaped to the CALLER, out through the
    handler that had just caught the decode failure. **This is `io`'s tranche-6 defect in a second
    language reached by a different mechanism** — there the salvage walk was unguarded, here the
    guard is present and **out of scope**.
  **Measured, and the ladder is the evidence: `pa-probe` 3 of 6 arms owed → 1 → 0**, each step
  attributable to one named mechanism, with **0 of 778 conformance severities moved** at every step
  (denominator asserted non-zero, digest matched, no `budget_exhausted`). A fix to an ungated surface
  should be invisible in the verdicts, and when it is not, the surface was not what you fixed.
  **Enforcement, and it is a grep this time:** in any Ada peer, an initialization in a `declare`'s or
  subprogram's declarative part that can raise is unprotected by that unit's own handler — search for
  `:=` initializers calling `Read_*`, `Decode_*`, `*_Of_Frame` or any codec entry point above a
  `begin`, and move the call into the statement part. **Generalise past Ada, because the question is
  what transfers:** for every language a peer is written in, know *what its handler does NOT cover* —
  initializers, destructors, `defer`/`ensure` blocks, `finally`, and static/field initialization are
  the usual answers — and never read a `try`/`exception` arm as governing a call merely because the
  call appears above it. **A source read clears the peer completely in all three instances here**,
  which is why this was found by driving the wire and could not have been found otherwise.
  **AND THE COVERAGE LESSON IS THE SHARPER HALF: A SWEEP THAT LANDS SEVERAL RULES CAN TOUCH A PEER FOR
  ONE RULE AND NOT ANOTHER, AND PER-PEER COVERAGE IS NOT PER-RULE COVERAGE.** `ada` is *not* the
  `fortran`/`unison` shape — a tranche **did** touch it (`sweep tranche 4`), it was measured `0 of 15`
  on `arc-probe`, it published `0.8.2.25` honestly, and its own row was true. That tranche's message
  says §4.11 went *"0 of 7 → 7 of 7 on odin, php and prolog"* — **three of the six peers it names** —
  so `ada` received the §5 rules and not the §4.11 one, and **nothing anywhere tracked which rule had
  reached which peer.** The set-difference control ratified the day before (*diff the roster against
  the peers the sweep's commits touched*) **reports `ada` as swept and is right**: it is keyed on the
  peer, and the gap is one axis finer. **Enforcement: a multi-rule sweep records a rule × peer
  matrix, and the closing claim is per cell, not per peer** — `tools/pa-probe` over the whole roster
  is what produced this, and it is the instrument that answers the §4.11 column.

- **RATIFIED, SECOND AND THIRD OCCURRENCE — A RELEASE MUST BE DISARMED WHEN OWNERSHIP TRANSFERS,
  AND THE DANGEROUS FORM IS A CONSTRUCTOR THAT TAKES OWNERSHIP *ON SUCCESS ONLY*.** First
  occurrence was `zig`'s `model.ofCbor` (2026-09-14, routed to us as a SYMPTOM by
  `entity-system-conformance` X14/F60 — *"panic: switch on corrupt value"* — and root-caused here):
  `errdefer data.deinit(gpa)` stayed armed after `Entity.make` took ownership, so
  `error.ContentHashMismatch` unwound through BOTH releases and freed one tree twice. A double free
  of a tagged union leaves a corrupt tag, and the abort surfaces LATER in an unrelated `deinit`,
  which reads as a codec fault and is a lifetime fault. **It is remotely reachable and needs no
  valid request** — §1.8 validate-on-receipt runs on every inbound entity.
  **Second and third: `zig`'s `wire.makeResponse`/`makeExecute`, found the same week one module
  over, and they are the subtler shape — the contract was CONDITIONAL.** `try f.params.toCbor(gpa)`
  consumed its argument on success and leaked it on OOM, so *whether the caller still owns the value
  depended on which branch ran*. A conditional ownership contract cannot be reasoned about at the
  call site at all. Both now consume on every path, which is why the new refusal paths need no
  release of their own.
  **Enforcement, and it is a question rather than a grep: for every constructor that takes
  ownership, say IN ITS DOC whether it does so unconditionally or only on success — and at each
  call site, release with a `catch` on the call, never an `errdefer` above it.** An `errdefer` above
  the transfer is correct until the transfer happens and wrong forever after. The tell that it went
  unnoticed: the test beside it drove only the ACCEPT direction, so nothing ever unwound.

- **RATIFIED, THIRD FORMAT — A COMMENT DELIMITER IS CODE, AND THE RULE'S OWN CANONICAL WITNESS IS
  WHAT BREAKS IT.** After Pd (`,`/`;` terminate a record inside a `#X text` comment) and Smalltalk
  (a `'` terminates the chunk-format outer string), the third is the plainest: **a C block comment
  cannot contain `*/`** — and the canonical witness for the §5.4 sentinel rule *is* `*/apply`.
  Writing the rule's own example into a `/* … */` comment in `c` terminated the comment early and
  produced eight cascading errors, including a bogus *"missing terminating `'`"* from the next
  line's apostrophe — i.e. the diagnostic points at the WRONG LINE and at the wrong defect.
  **Enforcement: before pasting a protocol literal into a comment, ask whether the literal contains
  the comment's own terminator.** `*/` `;` `,` `'` `"""` are the ones this cohort has hit. Spell it
  in prose (*"a bare star, a slash, then apply"*) or escape it; `//` comments are unaffected, and
  preferring them for anything quoting a pattern is cheap insurance.
  **AND THE SMALLTALK CASE NOW HAS AN INSTRUMENT, because the obvious check is useless there.**
  2026-09-15: four comments added to `smalltalk` carried ordinary English apostrophes (*"the
  caller's own exclude"*) inside `compile: '…'` bodies, which terminates the method literal
  mid-sentence. **A per-line quote-parity scan cannot find it** — every `compile: '` opener is
  legitimately odd, so the file reports 86 "suspect" lines and the four real ones are invisible in
  the noise. What works is to walk each `compile: '` literal under the `''`-escape rule and assert
  the character after its close is `.`:
  `re.finditer(r"compile: '")` → scan forward, `''` consumes two, first lone `'` closes → check the
  next char. **44 and 57 sites examined across two files, 4 suspect, all four mine, 0 after; 428
  across the peer.** Print the SITE COUNT and assert it non-zero, because a scanner that matched no
  sites reports exactly the same word as one that matched a hundred. Kept at
  `protocol-generator/shared/diagnostics/st-compile-string-check.py`.
  **AND THE ASSERT BELONGS TO THE RUN, NOT TO EACH FILE — the per-file form made the instrument exit
  1 on a CLEAN tree, which is how a check gets switched off.** Corrected 2026-09-16, before the
  instrument's first commit. A chunk-format tree legitimately contains files with no `compile:` at
  all — scripts (`load.st`, `bin/peer.st`, the test drivers) and class-definition-only files
  (`EcErrors.st`, `EcPeerErrors.st`) — so asserting per file reddens **seven of 40** on a tree with
  nothing wrong with it, and the real signal sits under a wall of ERRORs that are all false. Zero
  across the WHOLE invocation is the case that means the idiom moved; per-file zero means a script.
  **The general rule: an examined-zero-things assert is scoped to the unit the SCANNER ranges over,
  never to a member of it** — the same distinction as a census gate that must not fail a peer for
  having no report when the roster is what it ranges over. Three arms exercised before the commit
  (clean → 0 · zero-sites-only → 1 · a planted `caller's` inside a body → 1, naming the site, the
  closing line and the offending next character), because a gate with no regression suite is a
  script that has not been wrong yet.

- **Peer-selection: discovery yield is substrate-bound, not idiom-bound.** Spec gaps come
  from wire-touching axes (integer width / float model / crypto availability / string model);
  a peer novel only off-wire (concurrency / error-idiom / packaging) adds generator
  robustness, not new findings. The spec-discovery well has been dry on the current wire
  surface since ~15 peers and stays dry at 40 (every distinct integer/float/string/byte,
  crypto, concurrency, object-model, and execution-mode axis now probed) — steady-state
  value is **re-running the existing cohort against each amendment**,
  not adding language #N.

- **RATIFIED — SECOND OCCURRENCE, DIFFERENT LANGUAGE, DIFFERENT ALLOCATOR: A DETACHED WORKER MUST NOT
  OUTLIVE THE STATE IT BORROWS.** `c`, 2026-09-02, found by the stderr capture above on its first
  cohort run: a 46-peer census in which 45 peers were 0F and `c` was **756 · 288P/335W/27F**, and the
  peer's own dying words were `free(): chunks in smallbin corrupted`. `reader_loop` dispatches each
  inbound EXECUTE on a **detached** thread whose job borrows `conn` and `io`, both living inside the
  connection's `serve_state`; the reader returns the moment the client closes and `serve_reaper`
  joined **only the reader** before freeing that state. `ec_io_free()` also `close()`s the fd, so a
  late write can land on a descriptor **already recycled by a later `accept()`** — a cross-connection
  write, not merely a lost response.
  **The ordering IS the fix and every clause is load-bearing:** reserve BEFORE the spawn (the worker
  can finish before `pthread_create` returns), release LAST in the worker (the owner may free
  everything the instant the count reaches zero), drain before the owner frees. `ec_session_close`
  carried the identical defect with a different owner and was fixed the same day — the standing
  *"harden one anchor, check its siblings"* rule, which this repo has now failed twice.
  **THE CATEGORY RUN DOES NOT REPRODUCE IT, AND THAT IS THE MEASUREMENT LESSON.** `-category
  concurrency` alone: **0 of 20** on the unfixed binary. Heap corruption is layout-sensitive and the
  crash needs the full suite, ~680 checks deep. On `--profile core`: **baseline 1 of 10 · fixed 0 of
  20**. State the resolution rather than implying proof — against a ~10% base rate, 20 clean runs is
  roughly 88% confidence. **Corollary to the standing "drive the starved category directly" advice:
  that is right for COVERAGE and wrong for a RACE — an isolated category is a different heap.**

- **`detach()` IS THE HAZARD, EVEN WHEN THE BORROWED STATE IS SAFE — the victim can be the RUNTIME'S
  OWN bookkeeping.** RATIFIED 2026-09-02 (`zig`, second occurrence in the same peer, and the entry
  above's structural half). The 2026-09-01 fix made the detached dispatch threads safe *for our
  memory* with an in-flight counter, and left the abort: Zig's `entryFn` ends in
  `switch (completion.swap(.completed))` whose `.completed => unreachable` arm can only be reached if
  an `Instance` mapping was reused while a previous thread was still finishing with it — which only
  the detached path can produce, because `freeAndExit` munmaps the thread's own stack+TLS from INSIDE
  the dying thread and the kernel's `CLONE_CHILD_CLEARTID` write lands afterwards. **Own the handle
  and the whole shape goes away**: `join()` frees the mapping from the owner, after the kernel is
  finished. Enforcement, cohort-wide and one line: `git grep -n 'detach()\|pthread_detach' -- '*/src/*'`
  and, for each hit, name what keeps the borrowed state alive. Answers found: `zig` none (fixed),
  `c` an in-flight count + drain (fixed 2026-09-02), `cpp` `shared_ptr` copies captured by the lambda
  (correct by construction — refcounting IS the discipline on that substrate), `python` daemon threads
  over refcounted state (no manual free, so no such class).
  **Sub-lesson worth its own line, because it was measured rather than reasoned: a SPIN is not a
  cheap `join`.** The counter it replaced was drained with a `std.Thread.yield()` busy-wait, and on a
  4-core container a reader spinning in that loop can starve the very dispatch thread it is waiting
  for — 7 of 100 runs paid a full 20-second request deadline for it. A futex wait cannot do that.
  Prefer the primitive that blocks; a yield-spin is a scheduler bet, not a synchronisation.

- **A COMMENT THAT NAMES A LIFECYCLE STEP IS NOT EVIDENCE THE STEP EXISTS — count the resource at two
  points in time instead of reading the code that manages it.** Candidate (`cpp` 2026-09-02, found by
  asking the `zig` question of its siblings the same day, which is the standing sibling-check rule
  paying out for the third time). `Listener::Impl::conns` was **push_back-only** — no `erase` anywhere
  in the file — under a struct comment reading *"keep its Io + Connection + reader thread alive until
  reaped."* Nothing reaped. `close_io()` only `shutdown()`s; `~Io` is what calls `::close(fd_)`, and it
  could not run while the list held the `shared_ptr`. **Measured on the running peer: 4 fds idle →
  1419 after one `--profile core` suite → 2834 after two**, linear, unbounded, and triggerable by
  anyone who can open a connection. It had never failed a run because the toolchain container's soft
  limit is **524288** — under the conventional 1024 the peer exhausts descriptors partway through a
  single suite and `accept()` starts returning `EMFILE`. **The generalisation is about which question
  finds it:** reading `transport.cpp` for a use-after-free (what the sibling sweep was looking for)
  clears this peer completely, because the `shared_ptr`s make the lifetimes correct — the defect is
  that they are *too* correct, held by a list with no other end. `ls /proc/<pid>/fd | wc -l` at idle,
  after one suite and after two is the whole diagnostic, and a leak is a CURVE where a high-water mark
  is a plateau.

- **AN INLINE `{ type X }` IMPORT IS STILL A VALUE IMPORT OF THE MODULE, AND THE EMITTED NO-OP CAN
  BLOCK A WHOLE BUILD TARGET.** Candidate (`typescript` → `turbowarp`, 2026-09-07).
  `import { type Socket } from "node:net"` leaves the STATEMENT a value import, so `tsc` emits
  `import {} from "node:net"` into `dist/` — harmless under Node, and fatal to an esbuild
  **browser** bundle that cannot resolve a Node builtin. That single emitted line is the entire
  content of `turbowarp`'s `ERROR: bundle build failed`, the reason **the one peer nobody could
  measure** carried that status for weeks. `import type { … }` elides the statement completely.
  **Bisected before being called pre-existing** — it reproduces with the parent's source restored
  to before the arc — which is the standing rule about never labelling a failure "pre-existing"
  without bisecting, and it is also what made the fix safe to make here rather than route.
  Enforcement: `grep -rn "import { type " <peer>/src` on any peer whose output is bundled for a
  non-Node platform.

- **PROSE IN A COMMENT IS CODE, IN ANY FORMAT WHERE PUNCTUATION TERMINATES A RECORD — and the errors
  it produces are invisible if the peer logs to a file that dies with the container.** Candidate
  (first occurrence, but the enforcement point is exact). `pd` had been printing three errors on every
  load for months: `canvas: no method for 'not'` and two `established_ok: no such object`. A Pd record
  ends at an **unescaped `,` or `;` including inside a `#X text` comment**, so the RT-6 anti-replay
  note's ordinary English punctuation — *"must be REJECTED, not re-processed"*, *"auth_decode;
  established_ok 0 -> 401"* — broke out of the comment and Pd **dispatched the remainder as messages**.
  **Severity, in both directions, because both matter:** it moved **no check** (`pd` is `756 · 0F`
  before and after; a per-check severity diff against `go` shows its only deficit is 7 `type_system`
  entries, nowhere near the handshake ladder). But it was harmless **only because the words after the
  separators named nothing** — the same defect one word over sends a live message to a live receiver
  (`; net_listen`, `; buf_reset`) at load, and nothing would have reported that either.
  **Enforcement: `protocol-generator/pd/tools/patchlint.py`, a prerequisite of `make external`**, so
  every conformance run of that peer checks it; regression-tested by planting. It is a FILE and not an
  inline recipe because the first cut was inline and Make+shell+python quoting mangled the backslash
  class into one that flagged already-escaped separators — **it reported 6 findings where the truth
  was 1, and a gate that returns the wrong answer is worse than no gate.** Generalize: **before
  trusting a load-time-clean claim, confirm the loader's diagnostics are being kept**, and treat any
  format where comments share a terminator with code (Pd, CSV-ish DSLs, some `.ini`) as executable.
  **RATIFIED 2026-09-08 — THIRD FORMAT, AND THE RULE IS NOW ABOUT THE ENCLOSING CONSTRUCT RATHER
  THAN ABOUT PUNCTUATION.** Pd's terminator is `,`/`;`; a Tcl `switch` body is a LIST so `#`
  between pairs is not a comment (both already recorded); and **a Smalltalk chunk-format `.st`
  embeds every method body in an OUTER string literal, so a single APOSTROPHE anywhere in a
  comment terminates it mid-sentence.** Writing *"§4.7's own reason"* into `EcPeer.st` would have
  done it. **The tell is cheap and it is a MEASUREMENT, not a memory: `HEAD` of that file contains
  zero apostrophes in 700 lines and exactly 38 odd-single-quote lines** — a file whose existing
  prose scrupulously avoids a common English character is telling you the character is fatal.
  Count before and after any edit and require the number to be unchanged. The prohibition is now
  written into the comment that nearly broke it, which is the only place a future editor will be
  looking. *(Second half of the same near-miss, and it is about the EDITOR rather than the format:
  the replacement also lost its doubled `''` string quotes to Python's own quoting and produced
  `code: invalid_request` — syntactically plausible, silently wrong. Both defects were caught by
  READING the written result; the scripted assertion succeeded on both.)*

- **Lean proof vector** (the highest-signal channel): build the conformant peer first, then
  prove selected invariants in Lean — a proof needing an unstated hypothesis is an
  under-specified precondition (→ `A-LEAN-*` finding), a counterexample is a spec defect.
  Prove what's feasible; an unprovable-here-but-spec-sound invariant is a documented scope
  boundary, not a failure. Distinguish **soundness from completeness** in every theorem
  (conformance vectors never flag that gap); the proof covers the authority *logic interior*
  — crypto, the IO/concurrency shell, and the adversarial-input parser stay owned by KATs,
  race tests, and fuzzing. Ship the peer mathlib-free; proofs live in a `proofs/` target.

- **Visual/dataflow paradigms: author the protocol IN the language, don't wrap it.** A peer whose
  §6.5 collapses to one delegated `dispatch(frame)` call with a few façade blocks is a *wrapper*,
  not a paradigm probe — the logic must be visible on the canvas/graph (FLOW-DESIGN's wrapper-guard).
  **Foreground the *actual algorithm*, not a cosmetic proxy for it:** a §6.6 handler resolution belongs
  on the canvas as the visible *tree walk* (repeat-until, longest-prefix-first), not hidden in a seam
  `resolve()` call behind a literal `if pattern == "system/tree"` ladder — the switch reads as naive
  name-matching and buries the real mechanism (the remaining pattern→body switch is a genuine Scratch
  limit — no call-proc-by-dynamic-name — so label it as body-selection, not resolution).
  Draw the FFI seam at what the substrate *genuinely* can't do (bytes/maps/sockets/crypto/store), and
  author the rest (the §6.5/§5.2 *sequence*, status codes, op-switch, guard ladders). Values the
  substrate can't hold ride as **opaque handles**; readable fields are plain reporters. **Decomposing
  the folded logic surfaces bugs** (both Node-RED #31 and TurboWarp #32: a single collapsed dispatch
  hid real conformance defects — e.g. a folded §5.2 verdict masked the single-401 grantee carve-out,
  chain-depth-before-authz, and unchecked revocation). **Verify without the real runtime** via an
  **oracle-driven interpreter of the actual authored artifact** (TurboWarp: `run-blocks.mjs` runs the
  real `project.json` block graph vs `validate-peer`) — faithful, low-risk, a real number each
  iteration; the real-VM run is the final confirmation caveat. Frame-cap (§1.6) is load-bearing on a
  single-threaded substrate: an oversize frame stalls the peer and cascades into downstream timeouts.
  **Legibility needs decomposition into *named units*, not just "on the canvas"** — one 400-block
  tower is as unreadable as the code it replaced; split into a short dispatch *spine* + one
  procedure/subgraph per handler (Scratch `define …`; `stop this script` in a proc is the
  early-return, the spine's `stop` after the call ends dispatch). **Cooperative yielding between
  requests is load-bearing for connection-churn (§6.11 t2_2) on a single-threaded interpreter** — a
  serial queue-drain flushes no responses until it finishes, so under rapid open→handshake→close the
  oracle tears connections down before their response lands → *dropped requests* → a cascade of
  downstream failures. Yield to the event loop between hats (`await setImmediate`; the model real
  Scratch already uses — one script-step per tick) and it's solid. Diagnostic discipline: heavier
  per-request work (authoring a hot handler) only *exposes* this latent scheduling bug, it isn't the
  cause — prove it by reverting the suspected handler and re-measuring (delegated-connect *also*
  failed t2_2; the serial drain was the real root). The full **field survey + when-to-stop verdict**
  lives in `protocol-generator/shared/evaluations/visual-paradigms.md` (all THREE paradigms now probed — **Pure Data
  (#33) closed the reactive-patch track at full-gate `Result: PASS` on the real runtime**, the only
  visual probe to do so). Pd's adds: **the transport belongs in the seam when the runtime's own
  primitive is disqualified at source level** (`[netreceive]` broadcasts every reply, no per-conn
  id — structural, not inconvenient; the dispatch/verdict logic stays on canvas); **§6.11 reentry on
  a single-threaded canvas is a bounded synchronous send+wait on the SAME fd** (non-response frames
  hand back to the connection's assembler — behavioral presence, not architecture, is the contract);
  and per-request transient state as single-owner seam globals is safe ONLY under one-frame-fully-
  dispatched-before-the-next serialization (the reactive twin of Scratch's no-thread-locals).

- **Authority IS a query; the protocol around it is a state machine (the declarative-query/logic
  frontier, now closed).** SQL (SQLite) + Datalog (embedded Ascent, bottom-up/terminating) both land
  `682·0F Result: PASS @ cc1970f` authoring the §5/§6.6 interior *in the query language*: §5.2 ladder,
  §5.5 delegation closure (recursive CTE / recursive rule to least fixpoint — the SecPAL/Binder shape),
  K-of-N (`HAVING count(DISTINCT)` / counting aggregate), §6.6 (`ORDER BY length DESC` / stratified
  negation). Everything *pure-function-of-the-projected-facts* fits — often more legibly than the prose;
  everything *stateful-sequential* (§6.5 dispatch, §4 handshake, framing/crypto/store) leaks to the
  host. The wrapper-guard is what makes it a probe not a wrapper, and it held **through S4** on both:
  completing the S4 handler surface added **zero** imperative allow/deny — the verdict never migrated out
  of the authored interior (that absence is itself the datum). Two spec-shaped findings (F40 typed
  §3.6 scope matching, surfaced by SQL as a real ALLOW bug; F41 the §5/§6.6 decision surface is a
  monotone deductive system → an authority-as-derivation appendix makes fail-closed + the §5.5a
  within-grant conjunction *structural invariants* not silently-violable MUSTs). Logic-substrate impl
  trap: **a bottom-up engine dedups DERIVED tuples but not pre-seeded EDB**, so K-of-N distinctness needs
  an explicit IDB copy-rule before the count — silent if missed, and only the accept path exposes it
  (pairs with the rejection-only-oracle vacuous-green lesson) (A-DL-012). Full synthesis:
  `protocol-generator/shared/evaluations/authority-as-query.md`.

- **Oz: a non-ASCII byte baked into a compiled string constant can crash the peer at
  runtime, not at compile time.** `ozc` accepts a literal containing U+00A7 (`§`) inside a
  `"..."` string with zero warning, but concatenating it into a live error message via `#`
  (e.g. `"§6.2: ..."#Pattern`) made the register-reserved-pattern fix (2026-08-17,
  register-guard session) crash the request handler with an internal `Tell: 403 = 500`
  unification failure inside the shared `OutErr` helper — which kills the connection and
  cascades into ~100 unrelated FAILs across every later category in the same run (broken
  pipe / i/o timeout), reading as a huge regression rather than the one bad string it was.
  Isolated by A/B: the identical `OutErr`/`#`-concat call shape with an ASCII-only literal
  is clean every time; only the `§`-bearing literal reproduces the crash. No prior OutErr
  call site in this peer had ever put a non-ASCII literal into a runtime string (grep-
  verified), so this was never hit before. Root cause not fully traced past "a U+00A7 byte
  inside a compiled Oz string constant" — worth a real trace if a second peer or a second
  non-ASCII literal hits the same class; until then, treat any non-ASCII byte in an Oz
  runtime string constant as suspect and keep the citation ASCII (`"section 6.2: ..."`) in
  wire-visible text, reserving `§`-style citations for source comments (never compiled to
  a runtime value, confirmed safe) (A-OZ-008).

- **RATIFIED (second occurrence, different shape — promoted off the candidate ladder):
  a non-ASCII byte in a WIRE-VISIBLE string can crash a peer's own encode path,
  independent of language/substrate.** Io hit this independently on the same
  register-guard work (2026-08-17): a `"§6.2: ..." .. pattern` error message crashed
  `EntityCodec encode` with `ec: encode_error: text Sequence is not valid UTF-8 (bytes
  must ride EcBytes)` inside the hand-rolled `utf8_valid()` C validator
  (`protocol-generator/io/src/entitycodec/IoEntityCodec.c`) — even though the emitted
  bytes (`0xC2 0xA7`, confirmed via `od -c` on the source file) ARE valid UTF-8 by
  manual trace of that exact validator's own logic, and the oracle's reserved-pattern
  vector (`system/validate/core-register-forbidden`, `entity-core-go`
  `cmd/internal/validate/core_register_gate.go`) is plain ASCII, ruling out the dynamic
  `pattern` operand as the source. Root cause not traced further than that (same
  standard as A-OZ-008 — flag, don't over-invest); the peer is single-threaded, so the
  uncaught exception killed the whole process and cascaded `connection refused` across
  every later category (104 FAILs from ONE bad string, `Result: FAIL` on the first
  run). Isolated by the same A/B this class always uses: swap `§6.2` for ASCII
  `section 6.2` in the wire string only (keep `§` in source comments, which are never
  encoded) → `Result: PASS`, `0 failed`, both target checks PASS, no other line
  touched. **Discipline, cohort-wide, effective now:** treat any wire-VISIBLE string
  literal (an error `message`, any field the codec will CBOR-text-encode and send) as
  ASCII-only until a peer has a *proven* non-ASCII wire round-trip test; `§`-style
  spec citations stay confined to comments in every peer regardless of language,
  authoring convenience or the sink language's own claimed encoding correctness — Oz's
  string constant was independently corrupted at compile-time, Io's own UTF-8
  validator rejected byte-correct UTF-8, two peers, two unrelated compilers/encoders,
  same failure shape. No enforcement grep yet (both instances were caught by the
  peer's own `run-s4.sh`, not by static analysis) — a candidate lint would be
  `grep -RP '"[^"]*[\x80-\xff]' protocol-generator/*/src` scoped to fail()/err()/
  Out_Err()-style wire-message call sites specifically, not comments.
