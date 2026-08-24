# entity-core-keystone — Conformance & Status Matrix

**The transparency contract for adopters.** Before you pull a generated peer, check its row here. A peer being a spec-version behind, or lacking Ed448 agility, or carrying a known gap, is a **documented, tracked state** — not a surprise. "This peer doesn't do X yet" lives here, in the open, with a tier that tells you when it'll be caught up.

**Cohort:** 43 gate-green peers (**incl. the two authority-as-query declarative frontier probes — `SQL`
(SQLite + C seam) + `Datalog` (embedded Ascent + Rust seam), both `682·0F Result: PASS` @ `cc1970f`
(2026-07-16), authoring the §5/§6.6 authority interior *in the query/logic language* — see the 2026-07-16
note + rows in §1; this CLOSES the declarative-query/logic frontier, findings F40/F41** — and **incl. the first two ISA ports `asm-arm64` (2026-07-15) + `riscv64` (2026-07-16) — the x86-64 asm peer transliterated to aarch64 (GAS native syntax, run under `qemu-aarch64-static`) and to riscv64 (GAS RV64GC, run under `qemu-riscv64-static`, ported off arm64 via the shared generic syscall table), each `--profile core` **682·0F (Result: PASS**, 583P/3W/0F/96S) @ `cc1970f`, **byte-identical to the x86-64 sibling**; corroboration not independent convergence — same generation lineage + same FFI codec `.so`; note blocks in §1**) (the alien-substrate + mainstream-corroboration sweep through APL/Julia/Nim, **plus Crystal + Odin + the hand-written asm-x86_64 probe folded in at the 2026-07-14 branch merge, plus the three WebAssembly siblings (2026-07-15): the hand-authored `wasm-wat` probe, the COMPILED `rust-wasm` (Rust→`wasm32-wasip1`, WasmEdge/JIT), and `rust-wasm-wasmtime` (the SAME module under wasmtime AOT, compile-once-run-native), all full §7a `--validate` parity — their codegen + runtime/AOT head-to-head is `research/evaluations/wasm-codegen-comparison.md`**, **plus the Oz/Mozart dataflow-variable-concurrency + Io pure-prototype-OO paradigm probes added 2026-07-15 (both `682·0F Result: PASS` @ `cc1970f`; Oz 285P/301W, Io 291P/295W — see the 2026-07-15 note + rows in §1)** — see the note blocks in §1) (+ 3 visual-paradigm probes: **Node-RED** #31 (249·2F, delegates the whole §6.5 engine) and **TurboWarp/Scratch** #32 (291·0F, dispatch + all handler bodies authored in Scratch blocks) — both **exploratory, non-deployable, NOT real peers** — and **Pure Data** #33 (reactive-patch), **the first visual probe to clear the full core gate**: **682·0F Result: PASS** measured natively @ `cc1970f` (287P/299W/0F/96S, 0 fail-counting skips), genuine 2-of-3 multisig accept-path + origination-core `dispatch_outbound_reentry` 3/3, on the real Pd runtime over real TCP; see the ‡ rows + the 2026-07-15 note in §1) (incl. **Tcl** — the alien-substrate EIAS probe, newly S1→S5 with `pkgIndex.tcl` packaging + registry-publish deferred like the cohort — **Rexx**, the native-decimal number-model probe, newly S1→S5 with `make dist` source-tarball packaging + registry-publish deferred like the cohort — **Forth**, the stack-machine/typeless generator-stress probe, newly S1→S5 with `make dist` source-tarball packaging + registry-publish deferred like the cohort — **Smalltalk**, the pure-object/live-image/message-passing generator-stress probe, newly S1→S5 with `make dist` source-tarball + Metacello/Tonel packaging + registry-publish deferred like the cohort — **Fortran**, the fixed-width signed-only integer-model probe, newly S1→S5 with `make dist` source-tarball packaging + registry-publish deferred like the cohort — and **APL**, the array/value-model probe, newly S1→S5 with `make dist` (git source) packaging + registry-publish deferred like the cohort — **plus the two newest peers, native-codec corroboration / generator-robustness on the *mainstream* track (post-alien-sweep, NOT alien-substrate probes): Julia** (JIT / **multiple-dispatch** canonical-CBOR + UInt64/BigInt hybrid numeric) and **Nim** (compiles-to-C / **compile-time macro/template** dispatch codec + fixed-width uint64), both newly S1→S5 measured **natively** at `cc1970f` **682·0F Result: PASS** (Julia 292P/294W/0F/96S; Nim 293P/293W/0F/96S), each with a **genuine 2-of-3 accept-path** (`valid_2of3_peer_signed_accepted` + a peer-side unit) + origination-core `dispatch_outbound_reentry` 3/3, both native (no FFI fallback — overturning LANDSCAPE's `ffi` first-pass guess), publish-ready `0.1.0-pre`; their build surfaced **F32** (§4.2/§4.4-vs-§5.2a author-absent status conflict, → arch)), `--profile core` **0-FAIL** — the whole cohort now normalized onto the reproducible public-HEAD oracle **`cc1970f`** (2026-07-10 re-normalization; §3). The `--profile core` gate at `cc1970f` is **provably the same gate** the cohort converged against: its normalized core-gate fingerprint — the 16-category set + 53-type floor, comment/format-invariant — is `8261a03…`, and the now-retired pin `e8524ed`'s `profile.go` differs only by a V8 release-prep comment reword (raw `74e04e3` vs `e09a865`), a change that leaves that fingerprint untouched. So every peer's `--profile core` **0-FAIL** verdict carries forward to `cc1970f` unchanged. COBOL was measured **natively** at `cc1970f` (**291·0F Result: PASS**, one honest `t1_3_no_head_of_line` skip allow-listed). **Tcl** (the 23rd — the alien-substrate EIAS probe) was likewise measured **natively** at `cc1970f` (**682·0F Result: PASS**; the fresh total differs from the carried `665` because it was re-measured on `cc1970f`, not carried from `e8524ed` — totals are non-gating and vary by build, see the reading note; genuine 2-of-3 multisig accept-path `valid_2of3_peer_signed_accepted` passed). **Rexx** (the 24th — the native-decimal number-model probe) was likewise measured **natively** at `cc1970f` (**682·0F Result: PASS**, 291P/295W/0F/96S, 0 fail-counting skips; genuine 2-of-3 accept-path passed; origination-core `dispatch_outbound_reentry` 3/3); its S4 surfaced two §4.9/§4.10 resilience findings, both fixed — unbounded per-request signature ingest (A-RX-014) and the §4.10(c) connection-admission cap. **Forth** (the 25th — the stack-machine/typeless generator-stress probe) was likewise measured **natively** at `cc1970f` (**682·0F Result: PASS**, 291P/295W/0F/96S, 0 fail-counting skips; genuine 2-of-3 accept-path passed; origination-core `dispatch_outbound_reentry` 3/3) — **exact Rexx parity**, reached with a **native-float-bits** codec (gforth's `SF!`/`DF!` yield real IEEE bits, so only the f16 leg + shortest-form ladder are hand-rolled — materially easier than Rexx's decimal model) and the **cleanest FFI binding in the family**: an **in-process `libcc` `c-function`** (a genuine libffi call) with **native BSD sockets** — no co-process daemon. Its S4 surfaced no fresh spec finding but flushed out **seven code bugs in the generated peer**, all fixed (chief the concurrency payoff A-FT-025, a latent `pend-new` missing-return only concurrent §6.11 reentry exposed). **Smalltalk** (the 26th — the pure-object/live-image/message-passing generator-stress probe) was likewise measured **natively** at `cc1970f` (**682·0F Result: PASS**, 291P/295W/0F/96S, 0 fail-counting skips; genuine 2-of-3 accept-path passed + a 4/4 in-image accept-path unit; origination-core `dispatch_outbound_reentry` 3/3) — **exact Rexx/Forth parity**, reached with the codec expressed idiomatically as a **polymorphic `encodeOn:` double-dispatch** over tagged `EcValue` objects (not a translated type-switch — the A-ST-000 answer), an in-process **UFFI `ffiCall:module:`** crypto binding (no co-process) and native Sockets, and the bignum uint64 range carried FREE (arbitrary-precision integers, no fixed-width self-test tax). Its S4 surfaced no fresh spec finding but flushed out **four code bugs in the generated peer**, all fixed — chief the **A-ST-016** headline (dispatch caught only `EntityCoreError`, so one live `doesNotUnderstand:` on an unexercised path cascaded 229 FAILs from one bug: the resilience frame must catch the language's ROOT `Error` on a no-static-check substrate) — plus the durable **A-ST-012 pure-object polymorphic-absent-sentinel finding** (a distinguished-object absent sentinel is only safe if `isAbsent` is answered polymorphically on the common `EcValue` supertype). The other 21 peers' full-suite totals (**665**, extension-inflated + non-gating — see the reading note) were measured against the now-retired `e8524ed` build and are **carried, not re-measured**, on `cc1970f`; what `cc1970f` certifies for every row is the **core-profile 0-FAIL gate**, proven-identical via that fingerprint.² (Build order: the original 15-peer cohort, then the two large-ecosystem adoption peers Rust + Python — the 16th + 17th generated — then the reach peers C++, Kotlin, PHP, Dart; COBOL the 22nd, closing the §6.11 handler-outbound-dispatch seam.) The re-normalization + the anchor hardening it required are **CLOSED** in §3.
**Spec surface:** Entity Core **v0.8.0 (V8)** core protocol (standard extensions are out of scope — every peer below is a *core* peer). Spec-data stamp is **v0.8.0** (`protocol-generator/shared/spec-data/v0.8.0/`). The **core wire contract is byte-unchanged across the V7→V8 cutover**: the folded 0.7.76/0.7.77 increments + the V8 de-versioning were verdict-timestamp determinism, extension-side type-path renames, and release-prep only — no core map-key or wire change (see `spec-data/v0.8.0/MANIFEST.md`) — so each peer's certification carries forward unchanged. The oracle is `entity-core-go` at the reproducible public HEAD (`cc1970f`), whose core category set + type floor (`cmd/internal/validate/profile.go`) gates `--profile core`; its committed, comment-invariant anchor is the core-gate fingerprint in `tools/oracle-pin.env`.
**Conformance gate:** `validate-peer --profile core` — the extension-free categories (`connectivity`, `encoding`, `type_system`, `origination`, `resource_bounds`, `concurrency`, + the §10.1 register / §7a conformance-handler gates). **Was: all 43 peers 0-FAIL at `cc1970f`. The 2026-07-28 `af8a582`/`fceb61f` re-measurement dropped that to 6 of 45. A same-day remediation pass (F40 canonicalization on `forth`/`smalltalk` + RT-6 nonce single-use cohort-wide) brought it to 40 of 44 measured peers 0-FAIL — see the banner below.**

> ## ⛔ SUPERSEDED (2026-08-17) — oracle re-pinned to `de8f807`; §6.2 register-reserved-pattern gate CLOSED cohort-wide
>
> **Read this before pulling any peer — it supersedes the 2026-07-28 banner below.** `tools/oracle-pin.env` re-pinned `fceb61f` → `de8f807` (2026-08-16; arch's `SIGNOFF-2026-08-16-vector-set-final.md` — **the vector set is final, no further arch-side vector work is queued**). `core_gate_fingerprint` stayed byte-identical (same 16 core categories) but `check_set_digest` moved, which per standing policy re-triggered a full census regardless of the unchanged fingerprint — see `tools/oracle-pin.env`'s de8f807 entry for the full accounting.
>
> **Finding, universal at first census (2026-08-16): `core_register_reserved_refused` / `core_register_reserved_publishes_nothing` FAILed on all 45 measured peers.** `ENTITY-CORE-PROTOCOL.md` §6.2 (normative, pre-existing text — not a new rule) requires a handler register at a reserved `system/*` pattern to be refused with `403`; no peer enforced it because the oracle's negative-half check for this rule didn't exist until Go's 2026-08-11 commit. Full finding + reference fix shape:
> `research/stewardship/SESSION-HANDOFF-2026-08-17-oracle-repin-de8f807-and-reserved-pattern-gap.md` (the original finding) and
> `research/stewardship/SESSION-HANDOFF-2026-08-17-w-register-guard-partial-remediation.md` (the 31-peer first pass).
> (Note: the reference oracle's own citation for this rule, `"V7 §6.6"`, is stale under the de-versioned v0.8.0 spec — the rule is actually at §6.2. Filed to arch as `HANDOFF-TO-ARCH-2026-08-17-v7-section-citation-drift.md`; every keystone peer fix below uses the corrected `§6.2` citation, not the stale one.)
>
> **Closed 2026-08-17: 44 of 45 measured peers now enforce the guard, confirmed by a fresh centralized `tools/run-cohort-census.sh` run.** `apl` remains unmeasurable (unchanged, upstream-blocked, excluded per standing policy). `turbowarp` — the exploratory, non-deployable, "delegates the whole §6.5 engine" probe (§1, never a real peer, never in scope for this fix) — still FAILs both checks, unchanged, out of scope by design.
>
> **Of the 44 fixed, 40 are fully `--profile core` 0-FAIL.** The other 4 carry a separate, pre-existing, already-documented, unrelated FAIL — confirmed byte-identical by check name before/after in each fix's own commit, not touched or made worse by this pass: `cobol` (standing liveness-crash cascade, 27 FAILs) and `asm-arm64`/`asm-x86_64`/`riscv64` (standing `t2_2_connection_churn` peer-latency flake, 1 FAIL each).
>
> **Process finding worth reading if you're about to trust a census run right after a worktree-based fix:** the *first* full census after all 45 fixes landed showed 3 false FAILs (`rust-wasm`, `rust-wasm-wasmtime`, `node-red`) — not a fix regression, but `tools/run-cohort-census.sh`'s deliberate `NOBUILD=1` / build-only-if-missing reuse of on-disk build artifacts silently testing **stale, pre-session binaries** left over in the primary tree, because the actual fixes were verified inside isolated `git worktree`s with their own separate gitignored build caches that a source-only `git merge` never touches. Root-caused via build-artifact `mtime` vs. fix-commit-time comparison (not assumed), fixed by forcing a rebuild in the primary tree, re-verified 0 FAIL on all three. Ratcheted in `AGENTS.md`.
>
> **Fixed peers (44):** `go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` `typescript` · `elixir` `prolog` `common-lisp` `lean` `unison` `datalog` · `crystal` `nim` `odin` `php` `forth` `rexx` `tcl` · `smalltalk` `oz` `io` `julia` `sql` `pd` `wasm-wat` · `dart` `ruby` `node-red` · `ada` `cobol` `fortran` `haskell` `ocaml` `swift` · `c` `cpp` `csharp` `java` `kotlin` `zig` · `asm-x86_64` `asm-arm64` `riscv64`.
>
> **The per-peer rows in §1 below have NOT been mechanically updated to reflect this** (that pass is separate, unstarted follow-up work) — for the register-guard finding specifically, this banner is now the authoritative source; for anything else about a given peer, its own `protocol-generator/<lang>/status/CONFORMANCE-REPORT.json` remains the primary reference.

> ## ⛔ SUPERSEDED (2026-07-28) — every `682·0F @ cc1970f` verdict below is HISTORICAL
>
> **Read this before pulling any peer.** The cohort has been **re-measured three times** since
> `cc1970f`: `af8a582` (bucket-B: RT-6 hard-FAIL + the F40 exclude/include rows), `fceb61f`
> (arch's F40 control-row + RT-6 class-split response), then a **same-day remediation pass**
> fixing every peer the `fceb61f` measurement found non-compliant, every peer inside its own
> pinned `containers/<toolchain>/` image under podman. Current result, post-remediation:
>
> **44 of 45 measured peers (`turbowarp` untouched this pass) · 40 pass `--profile core` · 4 FAIL
> · 1 not measurable (`apl`, unchanged).** Passing (new, beyond the `fceb61f` 6):
> `ada` `c` `common-lisp` `cpp` `crystal` `csharp` `dart` `datalog` `elixir` `forth` `fortran`
> `haskell` `io` `java` `julia` `kotlin` `lean` `node-red` `ocaml` `odin` `oz` `pd` `php` `prolog`
> `rexx` `ruby` `smalltalk` `sql` `swift` `tcl` `typescript` `unison` `wasm-wat` `zig`, plus the
> unchanged `go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` `nim`. `nim` still carries a
> non-gating RT-6 WARN (401, wrong code); `rust-wasm`/`rust-wasm-wasmtime` are still thin
> transport seams over `rust`.
>
> **F40 (§5.2 typed scope matching): CLOSED cohort-wide.** `forth` and `smalltalk` — the only 2
> peers left with a real, attributable canonicalization defect — converted to the id-scope literal
> matcher (`shared/scope-matching/`), same shape as the other 34 peers. All three oracle vectors
> now PASS on both. `scope_subset` (§5.5a, F50) deliberately left unconverted in both, pending the
> still-open arch ruling. **New, unrelated finding surfaced by both fix agents independently**:
> neither peer's `check_permission` evaluates the `peers` grant dimension at all — not touched,
> needs its own investigation (session doc §5).
>
> **RT-6 (§4.6 nonce single-use): CLOSED cohort-wide — `handshake_nonce_single_use` now PASSES on
> every one of the 44 measured peers.** 31 "wrong-status" peers fixed with the pinned-status
> mechanical fix (401 invalid_nonce, matching each peer's own existing idiom for that status); the
> 7 "replay-accepted" peers (the actual anti-replay security hole — a replayed authenticate was
> silently re-verified and re-accepted with 200) got a real missing established-state check added.
> The `af8a582`/`fceb61f` census's standing "status=0" mystery on `csharp`/`node-red`/`typescript`
> was NOT a decode-outcome ambiguity as suspected — it was an **unsolicited §4.1 "leg 3" reverse-
> authenticate**, independently implemented (and independently buggy) in all three, sent
> proactively to every accepted connection in violation of the spec's explicit MUST NOT for a
> client-style initiator. Root-caused live (not from a source read) and fixed in all three, plus a
> second, distinct connect-path routing bug found alongside it in the same three. A fourth bug —
> unrelated to RT-6/F40 — was found and fixed along the way: a Pd `route`-object outlet-shift wiring
> defect in `pd`'s canvas that had silently starved its entire authz/dispatch stage. Full detail,
> including the batch-run-flakiness methodology note (isolate before trusting a mid-batch FAIL),
> in the session doc below.
>
> **Remaining 4 FAILs are pre-existing, unrelated to RT-6/F40** (confirmed via their own
> `handshake_nonce_single_use` now reading PASS): `asm-arm64`/`asm-x86_64`/`riscv64` (the standing,
> already-documented `t2_2_connection_churn` peer-latency class) and `cobol` (the standing,
> already-documented liveness-crash class). Neither touched this pass.
>
> **The `682·0F @ cc1970f` figures below are retained as a historical record of what that pin
> certified. They are not a claim about this tree.** `cc1970f`/`af8a582`/`fceb61f` all share an
> *identical* `core_gate_fingerprint` — the fingerprint tracks which categories run, not what they
> assert, so "the verdict carries forward at the same fingerprint" is **withdrawn** (established at
> the `af8a582` cutover). `tools/oracle-pin.env` carries a `check_set_digest` for exactly this
> reason.
>
> Per-peer table, per-vector breakdown, the leg-3/Pd root-cause writeups, and the still-open punch
> list: `research/stewardship/SESSION-2026-07-28-fceb61f-RT6-F40-remediation.md` (successor to
> `research/stewardship/HANDOFF-TO-ARCH-2026-07-28-fceb61f-cohort-remeasurement.md`, itself
> successor to `research/stewardship/HANDOFF-TO-ARCH-2026-07-27-af8a582-cohort-remeasurement.md`).

> **Reading the conformance numbers.** Every peer's **gate** verdict is certified on the same oracle (`cc1970f`, re-normalized 2026-07-10): **0 FAIL** on `--profile core`, 0 core-floor gap — the number that matters, and it is proven-uniform via the core-gate fingerprint. The full-suite **total** (665; `passed` 291–293, `skip` 95–96) is the extension-inflated, **non-gating** count: it was measured @ the retired `e8524ed` build for the original 21 peers and @ `cc1970f` for COBOL, and varies purely from extension *matched-if-present* WARN/PASS and auto-allowlisted skips. It is carried, not re-measured, at `cc1970f` (a comment-only `profile.go` reword cannot move the core verdict; extension totals are neither gating nor re-run here). (Historical per-oracle totals — 576 @ `b30a589`, 653 @ `75c532e`/`33f35fd` — are superseded; see the oracle-vendoring policy in `research/diagnostics/oracle-vendoring-policy.md` for why totals move without any verdict changing.)

> **Wire-conformance corpus — F29/F30 re-vendor (2026-07-12).** The ECF codec corpus (the *lower-bar* `wire-conformance` axis, distinct from the `validate-peer --profile core` gate above) advanced **69 → 71 vectors**: arch added F29's `nested.5`/`nested.6` (array-of-maps ≥24/≥256-byte inner-text head boundary) and regenerated F30's `tag_reject.1/2/3/5` (now canonical-except-the-mt6-tag, genuinely gating the §6.3 tag scanner). Vendored from `entity-core-protocol` @ `be54baf` as `9695b1f1…` (supersedes `41d68d2d…`), artifact decode-verified per the F16 lesson (71 vectors, all canonical bytes matched `.diag`, nested pins exact). **Cohort codec re-run: 71/71 (0 FAIL) across all 27 codec peers** (cobol: 70 pass / 1 documented C-ABI carve-out skip on `content_hash.4`; go independently tallied 66 encode_equal + 5 decode_reject). **F29 + F30 CLOSED** (`SPEC-FINDINGS-LOG.md`). This **closes the alien-substrate discovery sweep** (Tcl/Rexx/Fortran/Forth/Smalltalk/APL): F29/F30 were the last corpus asks it produced; the spec-discovery well is dry on the current wire surface — steady state is re-running this cohort against each amendment, not adding language #N. *(**F31 CLOSED** the same day: 4 peers (elixir/csharp/cobol/typescript) had a peer-layer unit test fail while codec-green + S4-conformant. Bisected to two **stale-test** causes, both test-side — no handler/peer code was wrong: (A) the §7a dispatch-outbound reentry tests sent the `value` field as a bare scalar instead of the `{value:X}` echo-shape entity-data map the §7a.1 contract requires (per the Go oracle + the passing kotlin test); (B) cobol's dispatch skeleton test expected 404 for an **unauthenticated** unknown-handler EXECUTE, but §6.5 authenticates before resolving → correct status is 401. All four now green; details in `SPEC-FINDINGS-LOG.md` F31.)*

---

## 1. Primary status table

> **New peer — asm-x86_64 (2026-07-13, hand-written).** The lowest-level substrate probe: a
> **hand-authored x86-64 assembly** peer (GAS/AT&T), not `/entity-rosetta`-generated — the
> ultimate "can the wire+authority interior be built in the barest language" stress test.
> Transport + the envelope/data-map CBOR + the entire dispatch/authority interior are hand-written
> asm; entity codec + Ed25519/SHA + peer-id are **FFI** via `libentitycore_codec`. Measured
> **natively at `cc1970f`** → **682·0F (Result: PASS**, 583P/3W/0F/96S, deterministic), matching
> the reference `entity-peer` on every check it passes. Notable: it implements the full write-op
> surface (tree put/get/CAS/listing/delete, register/unregister, configure, revoke), genuine §5.5
> K-of-N multisig accept, §6.2 dispatch-entity normalization, AND **§7a.2a concurrent reentrant
> dispatch-outbound** — the last via a single-threaded fork + request/response frame router +
> `pending_tab` demux (no threads/epoll; the reentry is one-socket, validator-as-B). The 3 WARNs
> are benign (`r3_connection_flood` matches the reference's WARN). **Cohort counts reconciled at
> the 2026-07-14 branch merge — headline was 33 gate-green peers then** (this row included; **40 now** — see the top Cohort line). Per-peer detail:
> `protocol-generator/asm-x86_64/status/`. (Honesty: FFI-hybrid, oracle-pinned `--profile core`,
> cohort-pinned to one author's vectors — not full-profile, not independent convergence.)
>
> > **L2 update (2026-07-15) — native canonical codec.** The peer's **canonical ECF codec is now
> > hand-written x86-64 asm** (`src/codec.s`): the shortest-float ladder, integer/length
> > minimization, definite-length + recursive tag-reject, length-then-lex key sort, `ec_content_hash`,
> > and peer-id `format`/`parse` (native base58 + LEB128) — only **Ed25519 + SHA-256 remain FFI**
> > (the L2 boundary). Cross-checked differentially against the 3-way-locked corpus (`make diff` →
> > 71 corpus + 4 synthetic, 0 FAIL) and integrated into the live peer: `run-s4.sh --profile core`
> > → **682·0F (Result: PASS**, 583P/3W/0F/96S) @ `cc1970f`, **identical pass set to L1** — only the
> > codec *provider* changed (FFI→native). Symbol-verified (`nm bin/host`): codec symbols `T` (ours),
> > `ec_sha256`/`ec_ed25519_*` `U` (FFI). Parse accept-path (oracle-invisible) covered by
> > `make parse-test` (11·0F). Detail: `status/PHASE-L2.md`. **The asm probe's discovery arc is
> > complete at L2** — L3 (hand-written asm crypto) is **deferred indefinitely** (per-ISA, high-risk
> > crypto boundary, ~zero discovery value; crypto stays linked-compiled — ISA-MAP point 5). The one
> > remaining optional item — a **RISC-V L1** port — is now **DONE (2026-07-16, `riscv64`)**: a
> > first-class-riscv64 distro (Debian trixie) sysroot under `qemu-riscv64-static` confirmed the
> > earlier "block" was a Fedora-secondary-arch packaging gap, not a riscv problem. See its note below.

> **New peer — asm-arm64 (2026-07-15), the first ISA port.** The x86-64 asm peer transliterated
> to **aarch64** (GAS native ARM syntax) — the first port off the hand-written asm template, and
> the test of the ISA-MAP Axis-A thesis: *with the codec/crypto/peer-id behind the FFI, is the
> protocol interior a mechanical register/syscall swap?* Answer: **yes, end-to-end.** All 75
> dispatch functions + the 4 shell modules ported by the codified register/ABI/syscall map
> (`rdi..r9`→`x0..x5`, cursor `r15`→`x24`, `svc #0`, `bswap`→`rev`, logical-immediate workaround,
> `push/pop`→`stp/ldp` frames) with **zero protocol-logic change**. Runs under
> `qemu-aarch64-static`; the native Go oracle runs beside it. Codec `.so` **cross-built for
> aarch64** (FFI×ISA cost: cross-libsodium via `--forcearch`). Measured `--profile core` at
> `cc1970f` → **682·0F (Result: PASS**, 583P/3W/0F/96S) — **byte-identical to the x86-64 sibling's
> verdict**, same 3 benign WARNs; §7a `validate_echo_dispatch` + concurrency 5/5 + §5.5 multisig
> accept all pass. Substrate findings: `fork`→`clone(SIGCHLD)` (no `fork` in the aarch64 generic
> table; A-ARM64-001), cross-sysroot shape (A-ARM64-002), and one porting-discipline bug —
> per-function store-helper length-register ABI (A-ARM64-003). Per-peer detail:
> `protocol-generator/asm-arm64/status/`. (Honesty: **corroboration, not independent
> convergence** — shares the x86-64 peer's generation lineage + FFIs the same codec; the real
> signal is the substrate mechanics. FFI-hybrid, oracle-pinned `--profile core`, cohort-pinned.)

> **New peer — riscv64 (2026-07-16), the third ISA (second port).** The asm peer transliterated
> to **riscv64** (GAS, RV64GC) — ported off **`asm-arm64`**, NOT x86-64, because aarch64 and riscv64
> share the kernel's *generic* syscall table (so arm64 pre-adapted every generic-table quirk). All
> 75 dispatch functions + the 4 shell modules ported by the codified aarch64→riscv64 map
> (`x0-x5`→`a0-a5`, cursor `x24`→`s6`, `svc`→`ecall` nr-in-a7, `rev`→hand-rolled `bswap*`, flag-less
> fused compare-branches, `stp/ldp`→`addi sp`+`sd/ld`) with **zero protocol-logic change** — the
> dispatch port ran as a **9-way parallel fan-out** along function boundaries. Runs under
> `qemu-riscv64-static`; the native Go oracle runs beside it. Codec `.so` **cross-built for riscv64**
> against a **Debian trixie riscv64 sysroot** (the FFI×ISA cost — riscv64 is a Fedora *secondary*
> arch with no forcearch path, so glibc+libsodium come from Debian's first-class riscv64 port,
> assembled from `.debs` with no foreign-arch execution / no host binfmt; A-RISCV-002, retiring the
> "BLOCKED" finding). Measured `--profile core` at `cc1970f` → **682·0F (Result: PASS**, 583P/3W/0F/96S)
> — **byte-identical to the x86-64/arm64 siblings**, same 3 benign WARNs; §7a `validate_echo_dispatch`
> + concurrency 5/5 + §5.5 multisig 11/11 accept all pass. Landed **0-FAIL on the first full run** —
> the A-ARM64-003 inter-function seam bug did NOT recur, because the arm64→riscv64 map is a clean
> **bijection** (no register-pressure divergence; A-RISCV-004). Other findings: hand-rolled byte-swap
> (no base-ISA `rev8`; A-RISCV-001), Debian libsodium 1.0.18 vs fedora 1.0.22 (A-RISCV-003). Per-peer
> detail: `protocol-generator/riscv64/status/`. (Honesty: **corroboration, not independent
> convergence** — shares the x86-64/arm64 generation lineage + FFIs the same codec. FFI-hybrid,
> oracle-pinned `--profile core`, cohort-pinned.)

> **New peer — wasm-wat (2026-07-15), the interpreted-substrate probe.** The peer is **hand-authored
> WebAssembly text** (`host.wat` transport + poll loop, `wire.wat`/`dispatch.wat` envelope + §5.2 +
> handlers); the Rust codec is compiled to `wasm32-wasip1` and **wasm-merged** as the seam
> (canonical CBOR + Ed25519/SHA). Measured under WasmEdge 0.17 → **682·0F (Result: PASS**, 291P/294W/
> 0F/97S @ `cc1970f`), **full §7a `--validate` parity, no `-allow-skip`** — including the
> **reentrant `dispatch-outbound` dialer** (t1_2 M=8 concurrent + `validate_echo_dispatch`), authored
> as a **same-connection** §6.11 reentry (outbound echo rides the inbound fd; a `pending[echo_rid →
> dispatch_rid]` table on one socket, no client dialer/threads). **The crypto execution mode is
> load-bearing:** WasmEdge's interpreter runs one Ed25519 verify at ~9 ms so §6.11 T2.1 times out;
> `--enable-jit` (~84 µs, 109×) is the working lever and part of this peer's conformance contract.
> AOT is inert on 0.17 (the `wasmedge compile` artifact runs without engaging its native code — t2_1
> FAILs at 22.9 s, confirmed 2026-07-15). Multisig accept-path + `--name` keypair load deferred
> (local-env). Detail: `protocol-generator/wasm-wat/status/`; findings F33/F34/F35 + execution-mode
> analysis in `research/stewardship/HANDOFF-TO-ARCH-2026-07-15-*.md`. (Honesty: seam-hybrid,
> oracle-pinned `--profile core`, cohort-pinned to one author's vectors — not independent convergence.)

> **New peer — rust-wasm (2026-07-15), the COMPILED-wasm sibling of wasm-wat.** The generated Rust
> peer's library (`../rust`) cross-compiled **unmodified** to `wasm32-wasip1` (LLVM), behind a
> 336-line single-threaded `poll_oneoff` transport seam (`src/main.rs`) — the whole ~4,000-line
> interior (codec, §5 authz, §6 dispatch, §9.5 floor, ed25519-dalek + sha2) compiles with **zero
> source changes**; `Peer::dispatch` is byte-identical to native, the seam ports the same single-fd
> §7a reentry-demux as wasm-wat/asm. Measured under WasmEdge 0.17.1 `--run-mode=jit` → **682·0F
> (Result: PASS**, 291P/294W/0F/97S @ `cc1970f`), **full §7a `--validate` parity, no `-allow-skip`** —
> byte-for-byte the same P/W/F/S as wasm-wat, same runtime. Same-runtime codegen head-to-head vs the
> hand-authored WAT peer: compiled Rust is **−29% module size** (242 KB vs 340 KB) and **−28% JIT
> warmup**, at a fraction of the authoring cost (reuse a whole peer + one host file); hand-authored WAT
> is **~1.8× faster per request** (10k sustained-load) — the abstraction-tax vs hand-tuned-loop
> trade. The decisive control: **the same Rust peer as native ELF vs wasm runs within ~1%** — portable
> compute is nearly free; the per-substrate cost is the transport-ABI seam. Full analysis:
> `research/evaluations/wasm-codegen-comparison.md`; folded into SUBSTRATE-TAKEAWAYS §4. Two transport
> lessons bit as on wasm-wat: **single-send framing** (Nagle/delayed-ACK churn stall) + **JIT crypto
> execution mode**. Multisig accept-path + `--name` keypair deferred (local-env), as wasm-wat. (Honesty:
> shares the native Rust peer's generation lineage AND crypto crates — NOT independent convergence; the
> independent datapoints are the unmodified-interior-cross-compiles result + the codegen comparison.)

> **New peer — rust-wasm-wasmtime (2026-07-15), the wasmtime-AOT production sibling.** The SAME
> `rust-wasm` `wasm32-wasip1` module, run under **wasmtime** and precompiled to native Cranelift
> code (`wasmtime compile` → `.cwasm`, run `--allow-precompiled`) — the compile-once-run-native
> production story WasmEdge 0.17's **inert** AOT couldn't give. Deliberately wasip1 (not wasip2):
> `wasmtime compile` is WASI-version-agnostic, so this isolates ONE variable (runtime + exec-mode)
> against the WasmEdge column; wasip2 would add a second (a different socket ABI) and cost the
> no-rustup rule (fedora ships no wasip2 std) — a deferred forward-ABI probe. Interior byte-identical
> to rust-wasm; only the socket seam changed — WasmEdge self-bind (`sock_open/bind/listen`) → a
> **host-preopened listener** (`-S tcplisten`) + standard wasip1 `sock_accept`/`poll_oneoff` (the
> `wasi` crate); framing + §7a reentry pump port verbatim. Measured running the AOT `.cwasm` →
> **682·0F (Result: PASS**, 291P/294W/0F/97S @ `cc1970f`), **full §7a `--validate` parity, no
> `-allow-skip`** — byte-for-byte the same P/W/F/S as rust-wasm/wasm-wat, §6.11 t2_1/t2_2 churn
> passing at native speed (the "experimental" `-S tcplisten` held). **AOT warmup ~5.7 ms** (native
> engages) vs WasmEdge JIT's ~3 s — but honestly the big win is WasmEdge→wasmtime (Cranelift JIT is
> already ~ms); AOT removes the residual per-boot compile AND yields a deploy-time native artifact.
> Sizes: `.wasm` 242 KB (portable) / `.cwasm` 904 KB (native, **wasmtime-46.0.1-pinned** — a
> deploy-time recompile artifact, not portable across wasmtime versions). wasmtime v46.0.1 is a
> **checksum-pinned upstream release** (not in fedora; S11). Full analysis:
> `research/evaluations/wasm-codegen-comparison.md` (third column); SUBSTRATE-TAKEAWAYS §4. (Honesty:
> shares rust-wasm's generation lineage + crypto crates — cohort-consistent, NOT independent
> convergence; the independent datapoint is the AOT-native-engages + warmup result.)

> **New peers — Crystal + Odin (2026-07-12, provisional).** Two T3 corroboration /
> generator-robustness peers added this session, both **native-codec** (the LANDSCAPE "ffi"
> predictions were overturned: Crystal binds libsodium directly for Ed25519; Odin's crypto is
> **native pure-Odin `core:crypto`**), both measured **natively at `cc1970f`** → **682·0F**
> (`--profile core`, 292P/294W/96S). Crystal is the **Ruby-overfit check** (compiled/typed/
> fixed-width/CSP-fiber Ruby-like); Odin is the **no-exceptions / no-GC / no-package-manager**
> systems probe. **Reconciled at the 2026-07-14 branch merge** (A-CRY-006 / A-ODIN-005): the
> Julia + Nim parallel branch merged with this one, and the headline cohort count reached **33
> gate-green peers** at that 2026-07-14 merge (Crystal + Odin + asm-x86_64 folded into the alien/mainstream sweep; **40 now** — see the top Cohort line). No spec finding surfaced (well is dry); the
> only net-new code was a shared NUL-byte path check and a Crystal graceful-shutdown hardening.

> **New peers — Oz/Mozart + Io (2026-07-15).** Two paradigm probes, each closing one open
> substrate axis, both **NATIVE-transport + FFI-hybrid-crypto** and both **`682·0F Result: PASS`
> @ `cc1970f`** (`--profile core`, incl. origination-core 3/3 + a genuine 2-of-3 multisig
> accept-path unit). **Oz / Mozart** (285P/301W/0F/96S) is the **4th §7b structural-concurrency
> shape — dataflow variables**: the §6.11 handler-outbound demux collapses to one single-assignment
> dataflow variable per pending request (reader routes frames, never blocks on dispatch — no
> correlation map, no locks; A-OZ-006). Installs from the 2018 Mozart 2.0.1 RPM (no source build);
> crypto/CBOR seam is the `entity-codec-daemon` `Open.pipe` co-process (RPM ships zero headers →
> native-functor FFI out; the Rexx `ecnet` precedent). **Io** (291P/295W/0F/96S) is the **pure
> prototype-based object model** — §6.6 handler resolution rendered as Io's own delegation (a
> `DispatchNode` proto network where longest-prefix resolution *is* the proto-chain lookup);
> native Socket + an in-process `EntityCodec` C addon, built on the permanently-frozen
> `2026.04.20-native-final` tag (upstream master pivoted to WASM). Io's S4 initially FAILed
> `concurrency` t2_1/t2_2 and was misdiagnosed as a single-threaded throughput ceiling; the Oz
> sibling passing the same checks with *slower* co-process crypto ruled that out — bisection found
> two fixable bugs (A-IO-025 per-request `try`-coroutine leak; A-IO-026 blocking send stalling the
> single event loop under slow readers), and the ceiling claim was **retracted** → clean 0-FAIL,
> t2_1 0/10000 dropped. Honesty: both FFI-hybrid, oracle-pinned `--profile core`, cohort-pinned to
> one author's vectors — not full-profile, not independent convergence. Per-peer detail:
> `protocol-generator/{oz,io}/status/`.

> **New peers — SQL + Datalog (2026-07-16), the authority-as-query frontier probes — CLOSING the
> declarative-query/logic corner.** Two *spec-discovery* probes (not substrate probes) built in parallel
> S1→S5, both **NATIVE-transport-via-host + FFI-hybrid-codec** and both **`682·0F Result: PASS` @
> `cc1970f`** (SQL 291P/295W/0F/96S; Datalog 292P/294W/0F/96S), origination-core `dispatch_outbound_reentry`
> 3/3, genuine live 2-of-3 multisig accept, 71/71 wire corpus. The whole point is the **authored authority
> interior**: the §5.2 verify ladder, §5.5 delegation chain-walk, §3.6 K-of-N, and §6.6 resolution are
> authored *in the query/logic language* (SQL: recursive CTE + `HAVING count DISTINCT` + `ORDER BY length
> DESC`; Datalog: recursive Ascent rules to least fixpoint + counting aggregate + stratified negation),
> with a thin host (C / Rust) owning only what the substrate genuinely can't do (sockets/CBOR/crypto/store).
> The **wrapper-guard held through S4** on both — completing the S4 handler surface added **zero** imperative
> allow/deny; the verdict never left the authored interior. **Finding (co-equal with the gate):** authority
> IS a query, the protocol around it is a state machine — everything pure-function-of-the-projected-facts
> fits (often more legibly than the prose), everything stateful-sequential leaks to the host. Two spec-shaped
> results routed to arch: **F40** (§3.6 scope matching is typed — id dims literal, path dims canonicalized —
> surfaced by SQL as a real ALLOW bug) and **F41** (the §5/§6.6 decision surface is a monotone deductive
> system → an authority-as-derivation appendix makes fail-closed + the §5.5a within-grant conjunction
> *structural invariants*). Honesty: both seam-hybrid, cohort-consistent (shared C-ABI codec lineage) NOT
> independent convergence (ADR-0012), probe-tier — genuine gate-green peers, not visual/illustrative (no ‡).
> Synthesis: `research/evaluations/authority-as-query.md`; arch routing:
> `research/stewardship/HANDOFF-TO-ARCH-2026-07-16-authority-as-query.md`; per-peer:
> `protocol-generator/{sql,datalog}/status/`.

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
| **Crystal** | 3 | v0.8.0 | `cc1970f` | 682 · **0F** | native hand-rolled | native — libsodium (direct `lib`/`fun` C binding) | deferred (libsodium has no Ed448; → FFI) | source, `0.1.0-pre` |
| **Odin** | 3 | v0.8.0 | `cc1970f` | 682 · **0F** | native hand-rolled | **native — pure-Odin `core:crypto`** (Ed25519 + SHA-2, FFI-free) | deferred (`core:crypto` has no Ed448; → FFI-hybrid) | source (`make dist`), `0.1.0-pre` |
| **Prolog** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | **FFI** (C-ABI) | **FFI** — C-ABI (library(crypto) has no Ed25519) | FFI | SWI pack, `0.1.0` |
| **PHP** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — ext-sodium (libsodium) | deferred (ext-sodium has no Ed448; → FFI) | Composer, `0.1.0-pre` |
| **Dart** | 3 | v0.8.0 | `cc1970f` | 665 · **0F** | native hand-rolled | native — cryptography_plus (pure-Dart) | deferred (→ FFI when scoped) | pub.dev, `0.1.0-pre` |
| **COBOL** | 3 | v0.8.0 | `cc1970f` | 291 · **0F** | **FFI-hybrid** (COBOL value-codec + C-ABI) | **FFI** — `libentitycore_codec` (libsodium) | deferred (libsodium has no Ed448) | `make dist`, `0.1.0-pre` |
| **Tcl** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **FFI-hybrid** (pure-Tcl canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` (C-shim, libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | git + `pkgIndex.tcl`, `0.1.0-pre` |
| **Rexx** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **FFI-hybrid** (pure-Rexx **decimal-model** canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via the `ecnet` co-process daemon (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Fortran** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **FFI-hybrid** (pure-Fortran **signed-carrier uint64** canonical CBOR value codec + C-ABI) | **FFI** — `libentitycore_codec` bound direct via `iso_c_binding`, no C wrapper (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Forth** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **FFI-hybrid** (pure-Forth **native-float-bits** canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via in-process `libcc` `c-function` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Smalltalk** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **FFI-hybrid** (pure-Smalltalk canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via in-process UFFI `ffiCall:module:` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | git + Metacello/Tonel, `0.1.0-pre` |
| **APL** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **FFI-hybrid** (pure-APL **array value-model** canonical CBOR codec + C-ABI) | **FFI** — `libentitycore_codec` via a GNU APL `⎕FX` native fn (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git source), `0.1.0-pre` |
| **asm-x86_64** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **native (L2)** hand-written x86-64 asm — envelope/data-map CBOR **+ canonical ECF codec** (shortest-float ladder, key-sort, `ec_content_hash`, peer-id format/parse); only crypto is FFI | **FFI** — Ed25519 + SHA-256 via `libentitycore_codec` (libsodium); the canonical codec is native asm (L2 boundary) | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make host`), `0.1.0-pre` |
| **wasm-wat** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **seam-hybrid** (hand-authored WAT peer + wire codec; Rust codec compiled to `wasm32-wasip1`, wasm-merged as the seam) | **seam** — `entitycore_codec.wasm` (Rust→wasm, Ed25519 + SHA-256) | deferred (→ codec seam `ec_ed448_*`) | source (`make peer`), `0.1.0-pre` |
| **rust-wasm** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **native (inherited)** — the `../rust` peer's hand-rolled ECF codec cross-compiled UNMODIFIED to `wasm32-wasip1`; only a 336-line `poll_oneoff` transport seam is wasm-specific | **native** — ed25519-dalek + sha2 (compile to wasm cleanly, no seam) | deferred (→ codec seam `ec_ed448_*`) | source (`make peer`), `0.1.0-pre` |
| **rust-wasm-wasmtime** | probe | v0.8.0 | `cc1970f` | 682 · **0F** | **native (inherited)** — the SAME `rust-wasm` `wasm32-wasip1` module, run under **wasmtime AOT** (`wasmtime compile` → `.cwasm`); only the socket seam differs (host-preopened `-S tcplisten` + standard wasip1 `sock_accept`/`poll_oneoff`, the `wasi` crate) | **native** — ed25519-dalek + sha2 (compile to wasm cleanly, no seam) | deferred (→ codec seam `ec_ed448_*`) | source (`make aot`), `0.1.0-pre` |
| **Julia** | 3 | v0.8.0 | `cc1970f` | 682 · **0F** | **native** hand-rolled (**multiple-dispatch** canonical CBOR) | **native** — system libsodium via `ccall` + `SHA` stdlib (Ed25519 + SHA-256; native-audited-lib tier, NOT the C-ABI) | deferred (→ opt-in FFI, C-ABI `ec_ed448_*`; libsodium has no Ed448) | Pkg (Project.toml + git), `0.1.0-pre` |
| **Nim** | 3 | v0.8.0 | `cc1970f` | 682 · **0F** | **native** hand-rolled (**compile-time macro/template** canonical CBOR) | **native** — libsodium via `{.importc.}` C interop (Ed25519 + SHA-256) | deferred (libsodium has no Ed448) | nimble (git-indexed), `0.1.0-pre` |
| **Oz / Mozart** | probe | v0.8.0 | `cc1970f` | 682 · **0F** (**Result: PASS**, 285P/301W/0F/96S) | **FFI-hybrid** (pure-Oz canonical CBOR value codec + C-ABI; bignum ints, IEEE floats as exact bit-patterns) | **FFI** — `libentitycore_codec` via the `entity-codec-daemon` `Open.pipe` co-process (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist`, `0.1.0-pre` |
| **Io** | probe | v0.8.0 | `cc1970f` | 682 · **0F** (**Result: PASS**, 291P/295W/0F/96S; concurrency incl. — t2_1 0/10000 dropped, t2_2 PASS) | **FFI-hybrid** (pure-Io canonical CBOR + C-ABI; `EcBig` uint64 carrier for the double number model) | **FFI** — `libentitycore_codec` via the in-process `EntityCodec` C addon (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist`, `0.1.0-pre` |
| **SQL** (authority-as-query) | probe | v0.8.0 | `cc1970f` | 682 · **0F** (**Result: PASS**, 291P/295W/0F/96S) | **seam-hybrid** — §5.2 ladder / §5.5 chain-walk (recursive CTE) / §3.6 K-of-N (`HAVING count DISTINCT`) / §6.6 (`ORDER BY length DESC`) **authored as real SQL** (`src/sql/`); thin C host owns sockets/CBOR/crypto/store over the C-ABI | **FFI** — `libentitycore_codec` (libsodium); crypto callable *from* SQL via `sqlite3_create_function` | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make dist`), `0.1.0-pre` |
| **Datalog** (authority-as-query) | probe | v0.8.0 | `cc1970f` | 682 · **0F** (**Result: PASS**, 292P/294W/0F/96S) | **seam-hybrid** — §5.5 delegation as recursive **Ascent rules** to least fixpoint (SecPAL/Binder shape), §5.2 verdict as a derived `allow` fact, K-of-N counting aggregate, §6.6 stratified negation; pure-Rust host asserts `verified_signer` facts over the C-ABI | **FFI** — `libentitycore_codec` (libsodium); Ascent never touches a byte | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`cargo build --release`), `0.1.0-pre` |
| **Node-RED**‡ | exploratory | v0.8.0 | `cc1970f` | 249 · **2F**‡ | **interop** (delegates the TS peer's canonical CBOR + §6.5 engine) | **interop** — TS peer `@noble` (Ed25519 + SHA-256) | deferred (→ TS `@noble` seam) | not a peer (illustrative) |
| **TurboWarp**‡ | exploratory | v0.8.0 | `cc1970f` | 291 · **0F**‡ (interp.; full marathon solid 5/5 incl. §6.11 t2_1+t2_2) | **ALL FIVE handler bodies (§4 connect / echo / §6.3 tree / §6.2 handlers / §6.2 capability) + §6.5 dispatch + §5.2 verify AUTHORED in Scratch** — a dispatch spine routing to one `define dispatch-<handler>` custom block each; only socket/CBOR/crypto/store via the `ecutils` seam | **seam** — bundled `@noble` (Ed25519 + SHA-256) | deferred (→ bundled `@noble`) | not a peer (illustrative; real-VM confirmation pending) |
| **Pure Data**‡ | probe | v0.8.0 | `cc1970f` | 682 · **0F** (**Result: PASS**, 287P/299W/0F/96S, 0 fail-counting skips) | **§6.5 dispatch spine + §5.2 verify ladder + §4.6 auth ladder + §6.6 walk AUTHORED on the canvas** (pattern-first spine, one named unit per handler); bytes/CBOR/crypto/store/**TCP transport** in the `[ecodec]` C external (stock `[netreceive]` broadcasts replies — A-PD-002) | **FFI** — `libentitycore_codec` (libsodium) via `[ecodec]` | deferred (→ FFI, C-ABI `ec_ed448_*`) | not packaged (visual-paradigm probe on the real Pd runtime) |
| **Unison** | probe | v0.8.0 | `cc1970f` | 682 · **0F** (**Result: PASS**, 292P/294W/0F/96S) | **native** hand-rolled canonical ECF on **UCM runtime builtins — ZERO third-party dependencies** (CBOR/base58/LEB128 hand-rolled; `Float.toRepresentation` gives raw IEEE bits for the shortest-float ladder) | **native** — builtin `crypto.Ed25519.sign/verify.impl` + `crypto.hashBytes Sha2_256`; **key derivation HAND-WRITTEN in pure Unison** (GF(2²⁵⁵−19) base-2¹⁶ limb arithmetic + twisted-Edwards scalar mult — UCM ships sign/verify but NO keygen, A-UN-009) | deferred — **no C-FFI hatch** (managed runtime; Ed448/SHA-384 are not builtins, so the `libentitycore_codec` path other peers used is *structurally* unavailable) | Unison Share deferred, `0.1.0-pre` |

‡ **Node-RED (#31) + TurboWarp (#32) are exploratory visual-paradigm probes — NOT real, deployable peers, and distinct from the alien-substrate *language* probes (Tcl/Rexx/Forth/…) which are full gate-green peers.** **Pure Data (#33) is the third visual probe (reactive-patch, the paradigm's lone open representative) and the exception on measurement: it runs on the REAL Pd runtime over REAL TCP and clears the full core gate (682·0F Result: PASS @ `cc1970f`, genuine 2-of-3 multisig accept + origination 3/3) — a real conformant peer by the gate's standard, kept in the probe class because its purpose is paradigm-visualization (cohort-consistent lineage, shared C-ABI codec, ADR-0012).** They exist to answer "can the protocol be *authored in* a visual paradigm?" and to serve as **readable references for those communities** (a Node-RED or Scratch author can study the dispatch logic in their own idiom), **not** as something you would deploy. Node-RED delegates the entire §6.5 engine to the TS peer (a flow-graph wrapper); TurboWarp authors the dispatch + all handler bodies as Scratch blocks but delegates crypto to a bundled `@noble` seam, runs sandboxed (no raw TCP → oracle-reachable only via a WS↔TCP bridge, the browser-Rust/WASM pattern), and is measured by a faithful **block-interpreter** of the real `project.json` pending a real-TurboWarp-VM run. Neither is independent convergence (shared TS/`@noble` lineage, ADR-0012). Full synthesis of what the substrate sweep taught — **what translates, what needs a seam, what doesn't** — is in `research/SUBSTRATE-TAKEAWAYS.md`.

> **Update 2026-07-15 — Pure Data (#33) close-out: the first visual-paradigm probe to clear the FULL core gate.** `validate-peer --profile core` @ `cc1970f`: **682 · 287P/299W/0F/96S — Result: PASS**, every remaining skip a §9.0 extension carve-out (0 fail-counting), measured **natively on the real Pd runtime over real TCP** (no interpreter harness, no bridge). Genuine **2-of-3 multisig accept-path** (§3.6/§5.5 M3/M4/M6 K-of-N verification in the chain walk, persistent `EC_NAME` identity) + **origination-core `dispatch_outbound_reentry` 3/3** over real two-peer TCP (`run-origination-core.sh`). Authored on the canvas: the §6.5 **pattern-first dispatch spine** (one named unit per handler, per-handler op-switch), the §5.2 verify ladder, the §4.6 auth ladder, and the §6.6 longest-prefix walk; `[ecodec]` (a Pd C external on the C-ABI codec) owns bytes/CBOR/crypto/store **and the TCP transport** — stock `[netreceive]` broadcasts every reply to all sockets with no per-connection id (A-PD-002, proven at Pd source level), so transport is a legitimate seam on this substrate. The §6.11 reentry on a single-threaded canvas is a **bounded synchronous send+wait on the one inbound fd** (non-response frames hand back to the connection's assembler). Cohort-consistent (shared C-ABI codec + generation lineage), not independent convergence (ADR-0012). Per-peer detail: `protocol-generator/pd/status/`; survey verdict updated in `research/evaluations/visual-paradigms.md`.

> **Update 2026-07-13 — both peers reworked to author the protocol IN the paradigm, not wrap it (supersedes the "both delegate the §6.5 engine / both 249·2F" description below).** Node-RED's §6.5 is now the visible **16-node flow-graph** (still 249·2F — leaf crypto delegated + the throughput boundary). **TurboWarp was rebuilt, then completed:** the §6.5 dispatch, the full §5.2 verify sequence, and **ALL FIVE handler bodies** (§4 connect / echo / §6.3 tree / §6.2 handlers / §6.2 capability) are now authored as **Scratch blocks** (502 blocks) — reorganized from one 400-block tower into a short **dispatch spine + one `define dispatch-<handler>` custom-block procedure per handler** for legibility — with only the socket / canonical-CBOR / Ed25519-SHA / chain-verdict / token-mint / seed-cap / store mechanics behind the `ecutils` **seam** (deliberately no `dispatch` block). The **§6.6 handler resolution is authored as the actual tree WALK** (a `repeat until` that walks the dispatch path longest-prefix-first for the matching `system/handler` registration == `HandlerRegistry#resolve`) — not a hardcoded pattern list; the per-prefix store lookup + path slice are the only seam bits, and the final pattern→body match is just body-selection (Scratch can't call a procedure by dynamic name; resolved-but-un-authored handlers delegate). Measured **291 P / 294 W / 0 F / 97 S — Result: PASS @ `cc1970f`**, **solid 5/5 full-marathon runs** including both §6.11 robustness tests (`t2_1_sustained_load` + `t2_2_connection_churn`), via the headless **block-interpreter harness** (`turbowarp/src/harness/run-blocks.mjs`, which runs the *real* `project.json` block graph against the oracle). **The earlier flakiness was a harness-scheduling bug, now fixed** (not the old `A-TW-throughput` label, and not the connect authoring): the interpreter drained the inbound queue in one serial burst without yielding, so under §6.11 connection *churn* (t2_2) responses didn't flush before the oracle tore connections down → dropped requests → a downstream cascade. Yielding to the event loop between hats (`await setImmediate` — the cooperative per-tick model real Scratch already uses) resolved it; verified by reverting connect to delegated (which *also* failed t2_2 → proved the serial drain, not the authoring, was the root). A real-TurboWarp-VM run is the remaining confirmation. Still cohort-consistent (shared bundled `@noble` + generation lineage), not independent convergence (ADR-0012). Consolidated survey + when-to-stop verdict: `research/evaluations/visual-paradigms.md`. See `docs/status/HANDOFF-2026-07-13-turbowarp-closeout.md`.

The historical description below (both 249·2F, both delegating the §6.5 engine) is retained for the Node-RED throughput finding. Both delegate codec/crypto to the TS peer (Node-RED require()'d, TurboWarp esbuild-bundled), so a green result would be cohort-consistent, not independent (ADR-0012). `validate-peer --profile core` @ `cc1970f` for BOTH: **249 P / 293 W / 2 F / 101 S** — all correctness categories green (connectivity 22/22, type_system 108P, multisig 11 w/ genuine 2-of-3 accept-path, security 28, capability 12, §6.11 concurrency *correctness* t1_2/t1_3). The **2 identical FAILs are §6.11 sustained-load/churn robustness** (`t2_1`/`t2_2`) — a documented **throughput boundary** (`A-NR-throughput` / `A-TW-throughput`): they **pass standalone** and fail only under the full ~640-test marathon. That the LEAN TurboWarp harness hits the SAME boundary as Node-RED shows it is **engine-level** (the shared delegated §6.5 engine's full-suite sustained-load behavior on pure-JS crypto), not a per-runtime artifact — not a correctness defect, not memory-bound. Per "no green → no publish," unpublished. Value is visualization + generator-robustness, not a conformance claim. See `protocol-generator/{node-red,turbowarp}/`. The peer is authored as a Node-RED *flow-graph* (§6.6 dispatch ↔ wire routing); codec/crypto/§6.5-engine are delegated (interop) to the TypeScript peer, so a green result would be cohort-consistent, not independent (ADR-0012). `validate-peer --profile core` @ `cc1970f`: **249 P / 293 W / 2 F / 101 S** — **all correctness categories green** (connectivity 22/22, type_system 108P, multisig 11 w/ genuine 2-of-3 accept-path, security 28, capability 12, §6.11 concurrency *correctness* t1_2/t1_3). The **2 FAILs are §6.11 sustained-load/churn robustness** (`t2_1`/`t2_2`) — a documented **Node-RED-substrate throughput boundary** (`A-NR-throughput`): they **pass standalone** and fail only under the full ~640-test marathon (event-loop saturation + visual-runtime per-request overhead on pure-JS crypto), not a correctness defect, not memory-bound. Per "no green → no publish," unpublished. Value is visualization + generator-robustness, not a conformance claim. See `protocol-generator/node-red/`.
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
| Go | 1 | `--name` + `-seed` (Go-idiom single-dash flags) | ✅ (`-validate`) | ✅ genuine + test — **was frame-only, FIXED 2026-07-12** (accept-path PASS) | goroutines + mutex | static / clean-room |
| Lean | 1 | (host shell) | ✅ | ✅ genuine + **proven** (`multiSigRootOk_quorum`) | pure core (no shared store) | dependent-type / **proof** |
| C# | 2 | `--name` | ✅ | ✅ genuine (reference impl) | threads + lock | OO / exceptions |
| TypeScript | 2 | `--name` | ✅ | ✅ genuine (reference impl) | event-loop + promise-mutex | structural JS / bigint |
| Java | 2 | `--name` | ✅ | ✅ genuine + test | threads + lock | JVM / OO |
| Kotlin | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** | coroutines + concurrent-collections (atomic-per-key) | JVM / **sealed-Result + coroutines** |
| Elixir | 2 | `--name` | ✅ | ✅ genuine + test | actor-isolation (structural) | BEAM actor |
| Common Lisp | 2 | `--name` | ✅ | ✅ genuine + test | raw threads + manual | CLOS multiple-dispatch |
| Zig | 3 | `--name` | ✅ | ✅ genuine + test | threads + mutex (raced before fix) | no-GC / comptime |
| C | 3 | `--name` + `--seed` (**added 2026-07-12**) | ✅ | ✅ genuine — **was frame-only, FIXED 2026-07-12** (accept-path PASS) | **raw pthreads** (A-C-009; A-C-011 churn flake) | **manual malloc/free** |
| Ada | 3 | `--name` + `--seed` (**added 2026-07-12**) | ✅ | ✅ genuine — **was frame-only, FIXED 2026-07-12** (accept-path PASS; exposed A-ADA-014) | **protected objects (structural)** | safety-critical / contracts |
| Ruby | 3 | `--name` + `--seed` | ✅ | ✅ genuine + test — **was frame-only, FIXED 2026-07-12** (accept-path PASS) | GVL (released on IO) + mutex | dynamic / duck-typed |
| Crystal | 3 | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + in-image unit | **CSP fibers + Channels, single OS thread (structural store-safety, no mutex; graceful SIGTERM — A-CRY-011, 20/20 crash-free)** | **compiled/typed Ruby-like / fixed-width int / libsodium `lib`/`fun`** |
| Odin | 3 | `--name` | ✅ | ✅ **genuine + accept-path** (multisig K-of-N Allow + M3/M4/M6 deny flips) + 53-type byte-diff drift target | **raw OS threads + `sync.Mutex` (manual §4.8; A-ODIN-009 store carries pinned allocator)** | **data-oriented / no-GC `context` alloc / no-exceptions `or_return` / native pure-Odin crypto** |
| Prolog | 3 | `--name` (real load, **fixed 2026-07-12**) | ✅ | ✅ genuine (`verify_multisig_root/4`; accept-path PASS) | OS-threads + clause-DB RMW | **logic / SLD-resolution** |
| Rust (clean-room) | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** (oracle `33f35fd`) | std::thread + RwLock — **compile-enforced** | static / Result / `#![forbid(unsafe)]` |
| Python (clean-room) | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** (oracle `33f35fd`) | threads + explicit Lock (GIL-aware) | dynamic / duck-typed |
| PHP | 3 | `--name` | ✅ | ✅ genuine + accept-path **ran** | **single-thread `stream_select` event loop (structural)** | dynamic / **event-loop store-safety** |
| Dart | 3 | `--name` | ✅ | ✅ genuine + accept-path **ran** | event-loop confinement per isolate (structural) | **sealed-Result + Future / BigInt-web** |
| COBOL | 3 | `--name` | ✅ | present (11/0 pass) — ✅verify genuine | **single-threaded `poll()` loop + §6.11 reentry pump** | **FFI-hybrid / GnuCOBOL PIC records / COMP-3** |
| Tcl | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread `chan event`/`vwait` event loop (structural)** | **EIAS / everything-is-a-string / event-loop** |
| Rexx | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread select-pump over the `ecnet` co-process daemon (structural)** | **native-decimal number model / EIAS byte-string / RC-flag errors** |
| Fortran | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread select-loop over the linked C net-shim (structural)** | **fixed-width signed-only integer / IEEE-native / iso_c_binding-direct** |
| Forth | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread select-pump, IN-PROCESS sockets + crypto (no co-process; structural)** | **stack-machine / typeless cells / RPN — no native records** |
| Smalltalk | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + 4/4 in-image unit | **single green-process event loop on one OS thread, IN-PROCESS Sockets + UFFI crypto (no co-process; structural)** | **pure-object / live-image / message-passing — polymorphic `encodeOn:` double-dispatch** |
| APL | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread `⎕FIO` select-pump (structural) + §6.11 reentry pump** | **array / value model / `⎕FIO`-native sockets / `→`-branch tradfns** |
| asm-x86_64 | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **fork-per-connection (blocking) + §7a.2a reentry demux via request/response frame router + `pending_tab` (structural)** | **hand-written x86-64 asm (GAS/AT&T) — the lowest-level substrate; FFI codec/crypto** |
| wasm-wat | probe | hardcoded conformance seed (`--name` deferred) | ✅ **echo + reentrant dispatch-outbound dialer** | deferred (local-env; needs `--name` keypair) | **single-thread `poll_oneoff` over non-blocking sockets + §7a.2a SAME-connection reentry demux via `pending` table; JIT crypto-execution-mode load-bearing (§6.11)** | **hand-authored WebAssembly text (WAT) — interpreted-substrate / crypto-execution-mode probe** |
| rust-wasm | probe | hardcoded conformance seed (`--name` deferred) | ✅ **echo + reentrant dispatch-outbound dialer** | deferred (local-env; needs `--name` keypair) | **single-thread `poll_oneoff` + §7a.2a SAME-connection reentry demux via single-threaded reentrant pump; single-send framing (Nagle fix) + JIT crypto-execution-mode load-bearing (§6.11)** | **Rust compiled to `wasm32-wasip1` — the COMPILED-wasm codegen sibling of wasm-wat (unmodified interior + 336-line transport seam)** |
| Julia | 3 | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + 8/8 unit | **single-thread Task scheduler (cooperative, structural) + §6.11 Channel reentry** | **native multiple-dispatch codec / UInt64+BigInt hybrid numeric / JIT** |
| Nim | 3 | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + 4/4 unit | **single-thread asyncdispatch event loop (structural) + §6.11 pending-table reentry** | **compiles-to-C / ARC-ORC deterministic GC / compile-time-macro codec / fixed-width uint64** |
| Unison | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted` — a hard FAIL before K-of-N landed, so the category is NOT vacuously green here); supplementary peer-side unit authored but **UNVERIFIED** | **abilities (algebraic effects) over IO — `fork` green threads + a single `MVar` store (`take → pure fn → put` serializes every mutation through one cell; actor-like BY CONSTRUCTION) + per-request `Promise` §6.11 demux** | **content-addressed codebase / headless `ucm transcript` build / fixed-width 64-bit Nat+Int / NO C FFI — pure-Unison Ed25519 keygen** |
¹ "Genuine" = real §3.6 M3 (structure) + M4 (distinct-signer threshold) + M6 (local ∈ signers) with a positive accept-path test, per the multisig cohort closeout. The original 10-peer cohort was verified genuine + accept-path-GREEN against oracle `33f35fd`. **The later-folded peers were re-verified 2026-07-12 by making the oracle's `valid_2of3_peer_signed_accepted` accept-path RUN (provision the peer keypair + boot `--name conformance`) — and 4 of 5 were FRAME-ONLY: Ruby/Go/C/Ada rejected a valid co-signed 2-of-3 (a masked defect, since the reject-dominated `multisig` category passes vacuously for a fail-closed peer). All four were fixed (genuine M3/M4/M6, accept-path PASS @ `cc1970f`); Prolog + COBOL were already genuine. See the 2026-07-12 finding note in `research/stewardship/`.** (The accept-path FAIL *does* gate — a SKIP is auto-allowlisted, a FAIL is not — so this was a real 0-FAIL risk once exercised.)

**Standard host CLI surface** (the cohort convention): `--name NAME` (load Ed25519 identity from `~/.entity/peers/NAME/keypair`) · `--port N` · `--validate` (bootstrap §7a `system/validate/*` conformance handlers, OFF by default) · `--debug-open-grants` (deprecated; degenerate `default→*` seed policy) · `--help`. Go uses the same surface with Go-idiom single-dash flags. C/Ada currently expose identity via `-seed` only.

---

## 3. Maintenance state & catch-up backlog

**Standing maintenance loop (the steady state):** when a spec amendment lands and Go ships the corresponding `validate-peer` update, re-vendor the oracle, re-run **Tier-1** immediately and converge to 0-FAIL, then catch up Tier-2/Tier-3 as capacity allows. This is the engine of spec refinement now — not new languages (see the fifteen-peer architecture milestone review, §5).

| Item | Scope | Priority | Notes |
|------|-------|----------|-------|
| ~~**Oracle normalization**~~ ✅ DONE | whole cohort | — | **CLOSED.** All 17 peers re-run on one oracle `entity-core-go @e8524ed` (go HEAD) → uniform **665·0F**. Procedure + the when/why rule now live in `research/diagnostics/oracle-vendoring-policy.md`. (The 649-vs-653 phantom-build lesson is captured there as provenance hygiene: build once into repo-root, never per-peer.) |
| ~~**run-s4 oracle-path defaults**~~ ✅ DONE | C, Ada, Ruby, Prolog (+ Rust, Python) | — | **CLOSED.** All `run-s4.sh` + `run-origination-core.sh` defaults normalized to the repo-root `/work/output/s4-oracles/…` convention; they now run with no `ORACLE` override. (Lean keeps `/repo/output/…` by its distinct `-v "$PWD":/repo` mount convention — correct as-is.) |
| ~~**Re-normalize cohort onto public-HEAD oracle**~~ ✅ DONE | whole cohort | — | **CLOSED (2026-07-10).** The public `entity-core-go` mirror rewrote history — the pinned `e8524ed` no longer resolves. Re-pinned `tools/oracle-pin.env` (+ `protocol-generator/cpp/tools/oracle-pin.env`) to the reproducible public HEAD `cc1970f`, and **hardened the core-gate anchor**: `oracle-bootstrap.sh` now fingerprints the *normalized category set + 53-type floor* (`core_gate_fingerprint = 8261a03…`), comment/format-invariant, instead of the raw `profile.go` sha256 — so the V8 comment reword that flipped `e09a865`→`74e04e3` no longer false-alarms "core gate moved" (regression-tested: comment reword → fingerprint unchanged; category drop → fingerprint moves). The `cc1970f` core gate is thereby **provably** the gate the cohort converged against, so every peer's `--profile core` 0-FAIL carries. Cohort table + reading note re-normalized to `cc1970f`. *Optional remaining (non-gating):* a fresh full-suite re-run of the 21 non-COBOL peers on `cc1970f` to re-measure their extension-inflated `665` totals natively (COBOL already runs natively at `cc1970f`); deferred, as core is the gate and it carries. |
| ~~**Scorecard label fix** `62044c5 → b30a589`~~ ✅ DONE | provenance | — | **CLOSED (2026-07-12).** A-C-008 / A-ADA-013: `62044c5` was off-by-one; `b30a589` is the true v7.75 baseline where `resource_bounds` activates under `--profile core` (clean `62044c5` auto-skips it → 574·0F·90S, not the recorded 576·0F·89S). Corrected in-repo across the 9 v7.75-re-run peer reports that paired `576·0F·89S` with `62044c5` (common-lisp, csharp, elixir, haskell, java, ocaml, swift, typescript, zig); C/Ada already carried `b30a589`. Remaining `62044c5` mentions tree-wide are accurate history (the clean-subset evidence runs) and left intact. |
| ~~**CLI normalization** (`--name`)~~ ✅ DONE | C, Ada, Ruby, Go, Prolog | — | **CLOSED (2026-07-12).** The audit found the deviation was wider than "C/Ada lack `--name`": **neither Go nor Ruby actually had `--name`** (only `--seed`; the matrix had overclaimed it), and **Prolog's `--name` was a fake** (parsed then ignored, seed hardcoded). Standardized all five on the canonical convention (OCaml/Swift/Haskell/COBOL): default seed `0x11×32`; `--name NAME` loads the seed from `~/.entity/peers/NAME/keypair`. Go/Ada default seed normalized `0x01`→`0x11`. Each `run-s4.sh` provisions the conformance keypair + boots `--name conformance`. |
| ~~**Verify genuine multisig** on later-folded peers~~ ✅ DONE | C, Ada, Ruby, Prolog, Go, COBOL | — | **CLOSED (2026-07-12) — with a real finding.** Making the accept-path RUN exposed **4 of 5 as FRAME-ONLY** (Ruby/Go/C/Ada rejected a valid co-signed 2-of-3 — a masked conformance defect the reject-dominated `multisig` category hid). All four fixed with genuine §3.6 M3/M4/M6 (`multisig_root_ok`, modeled on the genuine Prolog peer) → accept-path PASS @ `cc1970f`; Ruby/Go carry in-repo unit tests, C/Ada guard via the now-genuine S4 accept-path. Prolog + COBOL were already genuine. The Ada fix additionally uncovered **A-ADA-014** (a latent §PR-8 fixed-length-String crash). Finding note in `research/stewardship/`. |
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
