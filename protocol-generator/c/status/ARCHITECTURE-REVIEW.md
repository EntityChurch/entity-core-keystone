# Architecture Review — entity-core-protocol-c (peer #10)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data v7.75;
codec corpus v0.8.0 (byte-stable v7.71→v7.75). · **Audience:** architecture (spec-tightness
feedback) + operators (publishing decision). · **Status:** peer #10 at `validate-peer --profile
core` PASS · **576** / 291P / 196W / **0F** / 89skip @ the v7.75 cohort oracle **`b30a589`**;
origination-core 3/3; codec 69/69; 53-type registry 53/53; ASan/LSan/UBSan-clean.

This review follows the format/depth of the Zig peer #4 and Common-Lisp peer #5
`ARCHITECTURE-REVIEW.md` (themselves extensions of the three-peer architecture
milestone review), carried to **the
tenth peer and the cohort's last untried memory axis**. Part A is the idiom-fidelity +
spec-refinement retrospective; Part B is the publishing-options decision surface; Part C the
one-paragraph arch summary; Part D the consolidated findings ledger (owner + escalation status).

---

## 0. The thesis peer #10 was chosen to test

The convergence thesis (three-peer review; reinforced by Zig #4, CL #5, and the v7.75 9-peer
re-run): *if the spec is tight, independently-derived peers converge on the same conformance fixed
point with no wire divergence; the idiom seams diverge cleanly by profile at impl locality; and a
spec-first peer surfaces contradictions the port-peers inherited-correctly-but-never-flagged.*

Every prior peer delegates **object lifetime** to a runtime: C#/TS/OCaml/Java are GC'd, Elixir is
BEAM-actor, Haskell is GC+STM, Swift is ARC, Common Lisp is GC. **C is the cohort's last untried
memory axis: raw `malloc`/`free`, no garbage collector, no actor mailbox, no STM, no ARC — the
program owns every allocation by hand.** It is also distant on two coupled axes the cohort had only
partially probed: the **return-code error model** (an `ec_status` int + out-param on every fallible
call — no exceptions, no result-ADT, no condition system, no `setjmp`) and **POSIX pthreads**
concurrency with hand-managed shared state. The open question: **does the convergence thesis survive
the idiom where the *runtime owns nothing* — where a lifetime bug is a use-after-free, not a
deferred GC, and a race is a crash, not a lost message?**

**Result: the thesis held — and the no-runtime memory axis surfaced the cohort's single most
load-bearing *behavioral* finding to date (A-C-009).** Everything that touches the wire converged to
the same fixed point as the cohort (576 · 291P/196W/**0F**/89skip @ `b30a589`, the recorded cohort
figure exactly — see §A.5 on the off-by-one oracle label), reached spec-first, byte-identical codec
(69/69, first run, 0 codec fixes) + 53-type registry (53/53). The idiom seams (manual memory,
return codes, pthreads) diverged exactly at impl locality and **changed no wire byte** — *except*
that the no-GC memory axis exposed a §4.8 conformance requirement (atomic refcounts under
concurrency) that **every GC'd/actor/STM/ARC peer structurally could not surface** because its
runtime owns object lifetime. That is the strongest form of the thesis's corollary: a maximally
distant idiom both converges on the wire *and* contributes a probe nothing else could.

---

## PART A — Architecture review

### A.1 Did the C idiom pay off? (the three seams, scored)

**(1) Manual memory (raw `malloc`/`free`, no GC) — PAID OFF, the headline, with a *behavioral*
finding no prior peer could surface.** This is the largest divergence from all nine prior peers,
every one of which has a runtime that owns object lifetime. The payoff is two-fold:

  - **Free-correctness as a first-class conformance gate (sharper even than Zig's).** The codec, the
    two-peer smoke, and the 53-type byte-diff all build `-fsanitize=address,undefined` and run with
    `ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1` — a leaked node, a use-after-free, an
    overflow, or any UB is a **test FAILURE**, not an invisible GC deferral. Two real bring-up
    defects were caught this way at S2 alone (a `qsort(NULL,0,…)`/0-length-key UB; a base58
    long-division truncation). This is a *stronger* guarantee than any GC'd peer can make, and one
    step beyond Zig's `std.testing.allocator`: C has no allocator-as-parameter discipline to lean on,
    so the sanitizer *is* the safety net, and it is wired into every gate.

  - **It surfaced A-C-009 — the cohort's net-new §4.8 conformance datapoint (⚑ arch-bound).** Under
    the live oracle's sustained `concurrency` (§7b) load, the peer **crashed**: ASan reported a
    `heap-use-after-free in ec_entity_ref`. Root cause: `ec_entity`'s reference count was a plain
    `int`; materialized entities are shared across the per-EXECUTE dispatch threads (one thread per
    inbound EXECUTE, §4.8), and a plain `refcount++/--` from two threads races → a lost decrement
    frees a still-referenced entity. The crash *cascaded* — once the host died, every later category
    that re-dialed got "connection refused", so **22 of the 31 run-1 FAILs were this one bug**, not
    independent failures. Fix: `refcount → atomic_int` (`atomic_fetch_add` relaxed on ref,
    `atomic_fetch_sub` acq/rel on unref so the last-drop thread sees all prior writes before it
    frees). Re-run: `concurrency` 5/5, host stays alive, ASan-clean.

    **Why only this peer surfaced it:** the GC'd/actor/STM/ARC cohort never hits it because the
    *runtime* owns object lifetime — Java/CL/Haskell/Swift/Elixir/etc. would race the same logical
    refcount, but the runtime's GC/RC machinery makes the increment/decrement atomic or the object
    immortal-until-collected, so the bug is invisible. **A no-GC manual-memory peer is the only one
    that can surface the §4.8 atomic-refcount requirement, because it is the only one doing the
    refcount by hand.** This is the structural sibling to A-JAVA-010 (a "passes smoke green, breaks
    under the live §7b/concurrency gate" latent-bug class) — except where A-JAVA-010 was a data-shape
    trap, A-C-009 is a *memory-model* trap that the spec's prose leaves implicit. **Verdict: the
    manual-memory seam is the highest-value reason to build peer #10 — it produced the cohort's only
    concurrency-memory-model conformance ruling.**

**(2) Return-code error model (`ec_status` + out-param) — PAID OFF as idiom fidelity, neutral to the
wire.** Deliberate divergence from exceptions (C#/TS/Java/Swift), result-ADTs (OCaml/Haskell), and
the condition system (CL). Every fallible function returns an `ec_status` (`EC_OK == 0`; negative =
a specific failure enum, e.g. `EC_ERR_TAG_REJECTED`, `EC_ERR_CHAIN_DEPTH_EXCEEDED`,
`EC_ERR_AUTHN`/`EC_ERR_AUTHZ`) and writes its result through an out-pointer; protocol status is a
*value*, never smuggled across an error return. This re-derives the cohort's status-as-value
invariant by a fourth mechanism (after exceptions-don't-carry-status, result-ADTs, conditions).
The one fidelity cost — C will not enforce that the caller checks the return — is paid down by the
sanitizer gates + `-Werror` (an unused-result on a fallible path tends to surface as a UB/leak
under ASan). **Verdict: the seam that *should* differ from all prior peers differed cleanly, and
landed entirely at impl locality.** The §5.2 trichotomy (401 authn / 403 authz / 401 unresolvable)
maps directly onto three status enums, exactly as the cohort converged.

**(3) POSIX pthreads + hand-managed shared state — PAID OFF as the manual analogue, and the seam
that *carried* A-C-009.** One reader thread per connection demuxing `EXECUTE_RESPONSE` by
`request_id`, one thread per inbound EXECUTE (§4.8/§6.11), a `pthread_rwlock_t` guarding the content
store (read-dominated dispatch), a per-connection write mutex, `TCP_NODELAY` on every connection
socket (the inherited Zig Nagle finding). This is the direct manual analogue of OCaml's
stdlib-threads / Zig's `std.Thread` / Java's virtual threads — and the *only* peer where the shared
mutable state under those threads is owned by hand, which is precisely why it surfaced the
atomic-refcount requirement the rwlock-guarded *store* did not cover (the store was guarded; the
*entities flowing out of it* were refcounted with a plain int). **Verdict: correct for the core
floor; a `--profile core` peer has no handler-initiated outbound origination (extension-only, §9.0),
so one-thread-per-connection-and-per-EXECUTE is sufficient, and the seam earned its keep by exposing
A-C-009.**

**Net: all three idiom seams paid off** — one (manual memory) as the cohort's highest-value
*behavioral* probe (A-C-009), and two (return codes, pthreads) as clean idiom-fidelity wins. None
changed a wire byte; the one that touched *behavior* did so by surfacing a latent spec requirement,
not by diverging from the wire.

### A.2 Spec-refinement value — what C contributed

The discovery well was largely **dry on the *wire* surface** — nine independent prior peers had
already mined the v7.75 spec, and C re-confirmed (did not re-discover) the settled contradictions:
the §1.5-canonical-vs-§7.4 peer-id construction (built to §1.5 from the start, PRE-RESOLVED P1; the
**5th+ spec-first corroboration** after A-OC-007/A-ZIG-001/A-CL-002/A-SW-008/A-JAVA-004), the §5.2
401/403 boundary (P3), the A-JAVA-010 arbitrary-`data` shape (P4), the §4.10(b) 400-not-403
chain-depth ruling (P5), lowercase hex (P2). None of these is a new ask — they are corroboration
from the most-distant memory idiom, which is itself signal (the contradictions reproduce regardless
of memory model).

**C's net-new contributions are two, both ⚑:**

**Top — A-C-009 (§4.8 atomic-refcount requirement), the headline.** Covered in A.1. The
**recommendation to arch:** add a §4.8 conformance note stating that *shared/refcounted entities
MUST use atomic (or lock-guarded) refcounts on a multi-threaded peer*. The spec's §4.8 data-race
prose is correct but implicit about the refcount granularity; a no-GC peer makes the requirement
load-bearing. This is the only **concurrency-memory-model** conformance ruling in the cohort, and a
reusable generator datapoint for the next no-runtime peer (the atomic-refcount pattern is now in the
C profile menu, so the next systems-C/C++/Rust-no-std peer does not re-grind the crash).

**Second — A-C-008 (the cohort scorecard's oracle-commit label is off-by-one), a provenance
correction ⚑.** Verified READ-ONLY from the oracle source: the 9-peer scorecard records its v7.75
oracle as `62044c5` (576·0F·89S, resource_bounds PASS), but `62044c5`'s
`cmd/internal/validate/profile.go` `coreProfileCategories` has `catConcurrency: true` but **NOT**
`catResourceBounds` — so `resource_bounds` *skips* under `--profile core` there (→ 574·0F·90S,
exactly what this peer scored at `62044c5`). The **next commit `b30a589`** ("v7.75: pair §9.0 drift
gate post-arch-fold; resource_bounds enumerated") adds `catResourceBounds: true` → `resource_bounds`
becomes an ACTIVE core category → **576·0F·89S** (the actual recorded cohort number). So `b30a589`
is the true v7.75 cohort oracle; the scorecard's "62044c5" is a label **off by one commit**.
**Recommendation to mainline/arch:** correct the scorecard's recorded oracle commit to `b30a589`.
Non-blocking — this peer is 0 FAIL at the `62044c5` subset (574), the `b30a589` baseline (576), AND
the `7e5ab04` superset (631), so the verdict is conformance-safe at every inventory; the correction
is bookkeeping, not a re-cert.

**Informational (routed to arch, not a defect):** the spec's silence on memory ownership is fine for
the wire and fine for runtime-managed peers, but it leaves a no-runtime peer to author the entire
ownership + concurrency-safety contract from scratch. A-C-009 is the *behavioral* tip of that; the
broader datapoint is that the C profile now carries the no-runtime memory ruling (caller-frees
ownership + `goto`-cleanup + `atomic_int` shared refcounts + `pthread_rwlock_t` store) the way Zig's
profile carries the arena-per-request ruling — reusable, not re-litigated.

### A.3 Codec / transport design retrospective

**Codec — convergent, native, the simplest supply chain in the cohort.** Hand-rolled canonical CBOR
(the pattern every native peer hit): shortest-float ladder (f16⊂f32⊂f64, narrowest bit-exact
round-trip; exact IEEE bits via `memcpy(&u,&f,…)` — no strict-aliasing UB; f16 via pure-integer
mantissa/exponent test), length-then-lex map-key sort on encoded key bytes (`qsort` + a
length-then-`memcmp` comparator, guarded for n≤1 and 0-length keys — UBSan-clean), recursive
major-type-6 tag rejection at any depth, head-form int carrier. 69/69 byte-identical, first run,
**0 codec fixes** — the codec was byte-green before the peer existed, so the only S4 risk was
field-shape *data* (caught per-type by the 53/53 registry byte-diff), not codec behavior. C's
distinctive contribution to the codec axis: **full uint64 / −2⁶⁴ head-form via native `uint64_t`** —
the cleanest int story in the cohort alongside Zig (no `ulong` reinterpretation like C#, no int63
trap like OCaml, no `BigInteger` carrier like Java). And the supply chain is the **simplest in the
cohort by construction**: one audited C lib (libsodium, via the reviewed fedora dnf channel) + the
toolchain; **zero** registry-pulled (crates.io/npm/PyPI/Hackage-style) ecosystem deps — even Zig's
"std-only" posture pulls the std crypto from the toolchain, whereas C's CBOR/base58/varint/test
harness are *all* hand-rolled in-repo and the one crypto dep is distro-channel.

**Transport — convergent shape, pthreads primitive (profile-local, validated).** The spec-forced
cohort shape: 4-byte BE length-prefix + CBOR @ 16 MiB cap; one reader thread per connection demuxing
EXECUTE_RESPONSE by `request_id`; inbound EXECUTE on its own thread so it never blocks outbound;
transport-agnostic dispatch brain. The *primitive* is `pthreads` + `pthread_rwlock_t`/`pthread_mutex_t`
over a hashtable→condvar rendezvous — the direct C analogue of OCaml's per-thread-blocking / Zig's
`std.Thread` / Java's `ConcurrentHashMap` demux. `TCP_NODELAY` mandatory on every connection socket
(the Zig Nagle finding). The smoke proved 11/11 over real loopback; the live oracle proved 5/5 §7b
(after A-C-009). **Retrospective verdict:** correct for the core floor and de-risks nothing volatile
(pthreads is the most stable concurrency surface in the cohort — no async-runtime flux like Zig's).

### A.4 Where peer #10 sits vs the cohort

| Axis | Zig (#6) | CL (#5) | Java (#9) | **C (#10)** |
|---|---|---|---|---|
| Derivation | spec-first, distant idiom | spec-first, distant idiom | spec-first | **spec-first, distant idiom** |
| Memory | no-GC, explicit allocators | GC + bignums | GC | **no runtime — raw malloc/free** |
| Error model | error unions | condition system | checked exceptions | **return-code + out-param** |
| Concurrency | std.Thread | sb-thread + CLOS | virtual threads | **POSIX pthreads** |
| Codec | hand-rolled, comptime | hand-rolled | hand-rolled | **hand-rolled, native uint64** |
| Third-party deps | std-only | ironclad | ZERO (JDK SunEC) | **libsodium only (distro channel)** |
| Int carrier | native u64 + trap | native bignum | BigInteger | **native uint64_t** |
| Ed448 agility | native gap | native pure-Lisp | SunEC native | **native gap (A-C-001)** |
| Leak/free-correctness | testing.allocator gate | (GC) | (GC) | **ASan/LSan/UBSan gate (every test)** |
| Net-new ⚑ finding | peer-id (corrob), 401/403 | hex-case (NEW) | data-shape A-JAVA-010 (NEW) | **A-C-009 atomic-refcount (NEW, behavioral)** |
| Core verdict | 0 FAIL | 0 FAIL | 0 FAIL | **0 FAIL (576 @ b30a589)** |

**Position:** peer #10 is the cohort's **convergence stress-test at the last untried memory axis,
and the source of its only concurrency-memory-model conformance ruling.** It confirms every
wire-touching decision converges even when *the runtime owns nothing*; it adds the sharpest
free-correctness gate in the cohort (ASan/LSan/UBSan on every test, not a leak-detector on the unit
suite only); it independently re-confirms the settled spec contradictions from the most-distant
memory idiom; it is the simplest supply chain in the cohort (one distro-channel crypto lib, zero
registry deps); and it is the only peer to surface a *behavioral* §4.8 finding (A-C-009), because it
is the only peer doing object lifetime by hand.

### A.5 The oracle-provenance correction (A-C-008) — the handoff item

**The single item for the orchestrator's merge/handoff to surface upstream.** Stated plainly: the
9-peer cohort scorecard's recorded v7.75 oracle commit `62044c5` is **off-by-one** — at `62044c5`
`resource_bounds` SKIPs under `--profile core` (`catResourceBounds` absent from
`coreProfileCategories`), yielding 574·0F·90S, exactly what this peer scored there. The **next
commit `b30a589`** enumerates `catResourceBounds: true` → `resource_bounds` becomes active →
**576·0F·89S**, the figure the scorecard actually records. So `b30a589` is the true v7.75 cohort
oracle; "62044c5" is a label off by one commit. This peer is **0 FAIL at the 574 subset
(`62044c5`), the 576 baseline (`b30a589`), and the 631 superset (`7e5ab04`)** → conformance-safe at
every inventory (the Java-peer precedent: 0-FAIL at subset and superset means no category is dodged
by the smaller inventory). **For the merge decision:** the C verdict is 0 FAIL regardless of which
oracle label is canonical; the correction is bookkeeping for the scorecard, not a re-cert. Surface
the off-by-one to mainline/arch so the recorded cohort oracle commit reads `b30a589`.

---

## PART B — Publishing options (operator-decides)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface; the
recommendation is at the end. **No action is taken on it.**

### B.1 In-repo vs standalone repo

**Option 1 — keep in-repo under `protocol-generator/c/` (current keystone default).** Per-language
sibling repos are deferred keystone-wide (S10); all peers live in the keystone monorepo today.
  - *For:* zero lift cost; shared spec-data / test-vectors / oracle stay co-located (the peer reads
    `../shared/...` directly); cross-peer changes (spec bumps) land atomically; the CI workflow's
    relative paths (`protocol-generator/c/...`) already assume this root.
  - *Against:* a vendoring C consumer pulls the *whole keystone repo* at a tag rather than a minimal
    peer tree. Not fatal (the source tarball from `make dist` already scopes to the peer's own
    `src`/`include`/header/Makefile/`.pc.in`), but the standalone-repo lift would give a cleaner
    fetch surface.

**Option 2 — lift to a standalone `entity-core-protocol-c` repo (S10).**
  - *For:* a clean minimal surface for distro packagers / vendoring; a natural home for the CI
    workflow (`.github/workflows/c.yml` is already authored to run there); an independent
    tag/version cadence; the README's `repository_url` becomes concrete.
  - *Against:* the lift must vendor or submodule `shared/spec-data` + `test-vectors` + the oracle
    (the peer can't conform without them); spec bumps then require a sync step; it is an S10 step the
    keystone has deliberately deferred cohort-wide — doing it for C alone fragments the uniform
    "all peers in-repo" posture.

### B.2 Distribution mechanism (C-specific)

C has **no central package registry** (no crates.io/npm/Maven/Hex/Hackage/opam). The most
decentralized stance in the cohort, sibling to Zig's:
  - **(a) Versioned source tarball + pkg-config (the C-idiomatic path).** "Publishing" = `make dist`
    → `entity-core-protocol-c-0.1.0-pre.tar.gz` (sources + public header + `entity-core-protocol.pc.in`
    + LICENSE/README/CHANGELOG), hosted at a tagged release. A downstream `make && make install` lays
    down the static `.a` + shared `.so` + header + the rendered `entity-core-protocol.pc` under
    `$(PREFIX)`; consumers then `pkg-config --cflags --libs entity-core-protocol`. Distro packagers
    (Fedora/Debian/etc.) wrap this tarball in a spec/control file. **No publish command, no index.**
  - **(b) Distro packaging.** A distro maintainer packages the tarball (the `.pc` makes this
    mechanical). Coarser cadence, but the canonical way a C library reaches consumers.
  - **(c) Git submodule / vendored copy** at a pinned commit — fully offline, audit-friendly,
    appropriate for a consumer with the keystone's supply-chain stance.
  - **(d) No central-registry submission** is possible or needed — there is nothing to submit to.

**Packaging concern — the self-contained `.so` (A-C-006).** Fedora's `libsodium.a` is built without
`-fPIC`, so it cannot be linked into the peer `.so` (an `R_X86_64_PC32` relocation error). The `.a`
consumer path statically links the distro `libsodium.a` (fully self-contained — the profile's
preferred shape); the `.so` links shared `-lsodium` and carries a normal `libsodium.so` `NEEDED`
(reflected in the `.pc` `Requires.private: libsodium`). A self-contained `.so` bundling a *private*
libsodium needs a `-fPIC` libsodium built from source — a release-prep step (the manylinux-style
rebuild already flagged for old-glibc portability), **not** a conformance one. The `.a` path already
meets the self-contained goal. This is the one genuine S5/publish work item C carries that the
managed-runtime peers do not.

### B.3 License / version posture

  - **License: Apache-2.0** (keystone S9 default; explicit patent grant). The C ecosystem is
    license-mixed with no dominant norm, so the safe default stands (`profile.toml [license]` — not
    overridden). libsodium is **ISC** (permissive, Apache-2.0-compatible — statically linkable into
    an Apache-2.0 artifact). No change recommended.
  - **Version: `0.1.0-pre`** (set this phase). The cohort-wide pre-release line. **Promotes to
    `0.1.0`** only when (a) S4 fully green [met] AND (b) ≥1 external C consumer confirms it works
    [not yet met]. The `Makefile` `VERSION` + the `make dist` tarball name carry the full `-pre`
    marker; the `pkg-config` `Version:` field is dotted-numeric-only by convention, so it carries the
    numeric `0.1.0` (`PC_VERSION`) — the same `-pre`/numeric split Common Lisp hit with ASDF
    (A-CL-010). `CHANGELOG.md` tracks the spec version literally (V7 v7.75).

### B.4 Recommendation (operator-decides — not acted on)

**Keep the peer in-repo under `protocol-generator/c/` for v0.1, distribute via the `make dist`
source tarball + the `entity-core-protocol.pc` pkg-config file (mechanism (a)), at
`0.1.0-pre`/Apache-2.0.** Rationale: the standalone-repo lift (S10) is deferred cohort-wide and
lifting C alone fragments the uniform posture for marginal benefit before any consumer exists; the
`make dist` tarball + `.pc` already give consumers a clean, reproducible install; and the
one-distro-dep/zero-registry-dep profile means there is no distribution friction to solve. **Resolve
the self-contained-`.so` `-fPIC` libsodium question (A-C-006) at the same time the cohort defines the
S10 per-language-repo + CI home** — it is the one C-specific release work item, and it is a packaging
concern, not a conformance one. Promote to `0.1.0` once the external-consumer gate is met. Hold the
**Ed448 sibling-FFI-`.a`** route (A-C-001) as an explicit post-v0.1 agility-scope item. This is a
recommendation only — **the operator decides; the pipeline does not publish, tag, or push.**

---

## C. Summary for arch (one paragraph)

Peer #10 vindicates the convergence thesis at the cohort's last untried memory axis: a no-runtime C
peer — raw `malloc`/`free`, return-code errors, POSIX pthreads — reached the identical 0-FAIL fixed
point spec-first (576 @ the v7.75 cohort oracle `b30a589`, the recorded cohort figure exactly), with
every idiom seam landing at impl locality and **zero wire-byte divergence**. Its highest-value
contributions are (1) **A-C-009 ⚑** — the cohort's only *behavioral* §4.8 finding: under live §7b
concurrency a plain-`int` shared-entity refcount raced into a heap-use-after-free (22 of 31 run-1
FAILs were that one crash cascading), fixed with `atomic_int`; **only a no-GC manual-memory peer can
surface this** because every GC'd/actor/STM/ARC peer's runtime owns object lifetime — recommend a
§4.8 note that shared-entity refcounts MUST be atomic/lock-guarded on a multi-threaded peer (sibling
to A-JAVA-010); (2) **A-C-008 ⚑** — the 9-peer scorecard's v7.75 oracle label `62044c5` is
off-by-one: `b30a589` is the commit that folds `catResourceBounds:true` into core and yields the
recorded 576·0F·89S figure (this peer is 0-FAIL at the 574 subset, 576 baseline, and 631 superset →
conformance-safe; the correction is bookkeeping); and (3) the cohort's simplest supply chain (one
distro-channel crypto lib, zero registry deps) plus the sharpest free-correctness gate
(ASan/LSan/UBSan on every test). The two ⚑ items are the actionable asks: add the §4.8 atomic-refcount
conformance note, and correct the scorecard's recorded oracle commit to `b30a589`. Ed448 agility
(A-C-001) and the self-contained-`.so` `-fPIC` libsodium (A-C-006) remain documented, non-v0.1 items.

---

## PART D — Consolidated findings ledger (owner + escalation status)

Full text per item in `status/SPEC-AMBIGUITY-LOG.md`. None block release.

| Item | Severity | Owner | Status |
|---|---|---|---|
| **A-C-009** shared-entity refcount MUST be atomic/lock-guarded (§4.8) under concurrency | ⚑ arch-bound | **arch** | NEW (behavioral); resolved in-peer (`atomic_int`); recommend §4.8 note. Sibling to A-JAVA-010. |
| **A-C-008** cohort scorecard oracle label `62044c5` is off-by-one; `b30a589` is the true v7.75 oracle | ⚑ provenance | **mainline/arch** | Verified read-only; 0-FAIL at subset/baseline/superset → conformance-safe; correct the recorded commit. |
| **A-C-006** Fedora `libsodium.a` not `-fPIC` → self-contained `.so` needs a `-fPIC` libsodium build | packaging | **research/packaging** | The one C-specific S5/publish work item; `.a` path already self-contained. NON-blocking. |
| **A-C-010** clock-derived nonce → cross-connection replay (F12) | resolved | peer | RESOLVED via libsodium CSPRNG nonce (`ec_random_bytes`). |
| **A-C-011** §4.5 disjoint-negotiation reject / §1.4 path validation / §2.6 delegate-501 / §6 ops-match | resolved | peer | RESOLVED (peer bugs, spec/closeout-clear); the precise S4 grind. |
| **A-C-001** Ed448 native gap | deferred | **research/agility** | DEFERRED (3rd+ peer; sibling-FFI-`.a` route novel for C). Does not affect §9.1 floor. |
| **A-C-002 / -003 / -007** spec-snapshot header / §7a-§7b scaffolding source / oracle-HEAD provenance | notes | research/operator | Non-blocking documentation/provenance notes. |
| **A-C-004 / -005** pthreads / native-codec strategy | resolved | operator | RESOLVED local decisions (S3/S2 sign-off). |
| peer-id §1.5-vs-§7.4 (PRE-RESOLVED P1) | corroboration | arch | 5th+ spec-first corroboration (A-OC-007/A-ZIG-001/A-CL-002/A-SW-008/A-JAVA-004); built to §1.5; no new ask. |
| §5.2 401/403 (P3) · A-JAVA-010 data-shape (P4) · §4.10(b) 400-not-403 (P5) · hex-case (P2) | corroboration | arch | Inherited-settled; built in from the start; corroboration from the most-distant memory idiom. |
