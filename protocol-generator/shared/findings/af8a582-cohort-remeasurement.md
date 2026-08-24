# HANDOFF TO ARCH — 2026-07-27 — the cohort re-measured at `entity-core-go` `af8a582`

**From:** entity-core-keystone (research/stewardship) · **To:** entity-system-architecture
**Supersedes the numbers in:** `bucket-B-cohort-application.md`
(which reported *source* state; this reports *measured* state)
**Pins:** oracle `entity-core-go` **`af8a582`** · spec `entity-core-protocol` **`c32d2c5`** ·
keystone `e562ade` + the container re-pins in this commit
**Method:** every number below was produced by `validate-peer --profile core` run **inside the
peer's own pinned `containers/<toolchain>/` image under podman**. No host toolchain was used for
any measurement. Where a peer could not be measured, it is reported as *not measured* with the
blocker — never as a pass, never as a carry-forward.

---

## 0. Why this document exists

The predecessor handoff reported which peers had been *edited*. Arch cannot act on that. This one
reports what the oracle actually says, per peer, per vector, at the pin where the bucket-B vectors
exist — 45 of 46 peers, each in its own container. Everything in it that is not a number is a
finding a source read could not have produced.

---

## 1. HEADLINE FINDING — the core-gate fingerprint does not detect a moved gate

**This is the most important thing in this document, and it is a defect in keystone's own anchor
that arch relies on too.**

`tools/oracle-pin.env` carries `core_gate_fingerprint`, the normalized *category set + 53-type
floor* parsed out of `cmd/internal/validate/profile.go`. The committed policy — and
`CONFORMANCE-MATRIX.md` §3 — reason as follows: *if a rebuilt oracle reproduces the fingerprint, its
core surface is identical to what the cohort converged against, so every peer's verdict carries
forward unchanged.*

Measured, both binaries built in `containers/go`:

| | `cc1970f` (retired pin) | `af8a582` (bucket-B) |
|---|---|---|
| `core_gate_fingerprint` | `8261a033fe1af5…` | `8261a033fe1af5…` — **identical** |
| `handshake_nonce_single_use` in binary | **absent** | present |
| `f40_id_scope_exclude_literal` | **absent** | present |
| `f40_id_scope_include_no_overgrant` | **absent** | present |
| `t1_4_frame_write_atomicity` | **absent** | present |

The fingerprint is byte-identical across a gate that gained **four new hard-FAIL vectors inside
existing core categories** (`connectivity`, `authz`, `concurrency`) and that flipped most of the
cohort from PASS to FAIL. The anchor tracks *which categories run*; it is blind to *what the checks
inside them assert*.

**Consequence.** Every "the verdict carries forward at the same fingerprint" statement in
`CONFORMANCE-MATRIX.md` §3 is unsound in the direction that matters. A same-fingerprint rebuild is
evidence that no category was added or removed — nothing more. Keystone is fixing its own side
(the pin file gains a check-set digest and the carry-forward wording goes away). **The ask on arch
is narrower:** when a bucket adds vectors to an existing core category, say so explicitly in the
handoff packet, because the fingerprint will not.

---

## 2. RT-6 (§4.6 replayed authenticate) — measured cohort status

The vector (`connectivity/handshake_nonce_single_use`, `connectivity_f12.go`) scores `pass` on
`401 invalid_nonce`, `warn` on 401-with-another-code, **`fail` on anything else**. `connectivity`
is a core-gate category, so this is a hard gate.

**Five** distinct behaviours are present in the cohort, and **only a live run distinguishes them** —
the source census in the predecessor handoff got several peers wrong in both directions:

1. **`401 invalid_nonce`** — conformant.
2. **`401` with a different code** — scored WARN; gate-green but not RT-6 (see `nim` below).
3. **`409 connection_already_established`** — the cohort's original reading; scored FAIL.
   The large majority.
4. **`200`, replay accepted** — the replayed authenticate is *honoured*. The security-relevant
   case, and not rare: seven peers.
5. **Connection closed, no response at all** (`status 0`, empty code) — three peers. The oracle's
   own text is explicit that a close "does not confirm" RT-6, so this scores FAIL too. Worth
   naming as its own class because a peer author reading "we reject the replay" will believe they
   are conformant while emitting nothing the oracle can attribute. Counts and peers: §6 roll-up.

See §6 for the full per-peer table.

**The WARN band lets a peer be gate-green and still non-conformant, and one peer is in it.**
`nim` measures **718·0F — a clean gate pass** — while its replayed authenticate returns
`401` with `code="missing_author"`. It reaches 401 by a different route (the replayed frame
fails an author check) rather than by implementing nonce single-use, and the vector correctly
scores that WARN. This is the right call by the vector, but it means **"RT-6 green" and
"0-FAIL" are not the same statement**, and a cohort roll-up that only counts FAILs will report
`nim` as RT-6-done. Keystone will track the code, not just the status.

**Correction to the predecessor handoff, from measurement not grep.** Its W1b list of "11 targets
with no established-gate" was derived from `grep connection_already_established`. That census is
unreliable in both directions:

- `ruby` was listed as having *no* gate; it measurably returns **409**.
- `sql` carries the string in source but measurably returns **200**.
- `rust-wasm` / `rust-wasm-wasmtime` carry neither string and measurably return **401** — they are
  thin transport seams over the `rust` peer's crate (`entity-core-protocol-rust` path dep), so they
  inherit its fix. They are **not** independent data points; they are the `rust` interior measured
  through a wasm seam.

No further RT-6 conclusions should be drawn from source greps. The peers are running; ask them.

---

## 3. F40 (§5.2 typed scope matching) — measured, and one important surprise

Arch shipped **both** rows we asked for in Ask 5 — including the exclude inversion
(`f40_id_scope_exclude_literal`), which is the half a naive probe omits and the only row a
canonicalizing peer cannot pass by accident. That was the right call and it earned its keep
immediately: it is the row that fails, and on peers the include row passes.

**The surprise: `sql` FAILS `f40_id_scope_exclude_literal`.**

`sql` is the peer the original F40 finding was built on — the one that matched id-scope raw while
the other 42 canonicalized, and which the cohort audit therefore recorded as *already conformant,
no conversion needed*. Against the vector it is not conformant on the accept path: an `operations`
exclude of `"/*/get"` **denies** a real `get` (403 `capability_denied`).

The lesson generalizes past `sql`: the F40 audit that produced the "already conformant / not yet
converted" split was a source read. At the vector, the split is different. Keystone is re-deriving
the cohort's F40 state from measurement, and will not publish a source-derived conformance claim
again.

**The two rows are wildly asymmetric in practice, which vindicates Ask 5 empirically.**
Measured across the cohort:

- `f40_id_scope_exclude_literal` FAILs on **8** peers: `cobol` `datalog` `forth` `io` `smalltalk`
  `sql` `swift` `wasm-wat`.
- `f40_id_scope_include_no_overgrant` FAILs on **3**: `forth`, plus `cobol` and `io` — and those
  two are crash-cascade casualties (§8), so the include row has exactly **one** real failure.

**Five peers fail the exclude row and pass the include row.** A vector set carrying only the
include row would have reported them clean. Please note this in the vector notes so the exclude
inversion is never trimmed as redundant — it is doing nearly all of the work.

### One caveat on the exclude row: its FAIL is not *attributable* as written

The row's failure message asserts a specific cause — *"the peer canonicalized an id-scope entry
as a §5.4 path"*. The probe cannot actually distinguish that from any other 403 on the delegated
path (resource-scope coverage, chain subset-validation, handler scope), because the only other
row that varies the same cap shape — the include row — **expects a deny**, so it cannot serve as
a control.

Concrete counterexample: `swift` FAILs the exclude row, yet its §5.2 matcher is demonstrably
kind-branched — `Capability.matchesScope(_:_:frame:kind:)`
(`Sources/EntityCoreProtocol/Capability.swift`) takes a required `kind`, its `.id` branch runs
`matchesIDPattern` over **both** include and exclude, and all three call sites pass the correct
kind (`operations` → `.id`, `handlers` → `.path`, `peers` → `.id`). The attributed cause does
not hold for that peer, so the 403 is coming from somewhere else on the delegation path — which
is exactly what the vector cannot currently tell us.

**Ask:** add a **control row** — the same child cap with the `operations` include and **no
exclude**, expecting 2xx. Then `control PASS + exclude FAIL` is an attributable F40 defect, and
`control FAIL` says the denial is upstream of the id-scope question. Without it, keystone cannot
tell an F40 defect from an unrelated delegation denial, and five peers' root causes are
currently unresolved.

---

## 4. Two interaction findings the run surfaced

### 4a. A slow peer's `t2_2` starves `authz`, and F40 is then silently *not measured*

On `asm-x86_64`, `asm-arm64` and `riscv64`, `concurrency/t2_2_connection_churn` consumed
**~53–59 s of the oracle's 60 s global `-timeout`** (i/o timeout mid-churn), after which the entire
`authz` category reported:

> `category skipped: budget_exhausted: prior categories consumed the -timeout window`

`authz` is where the F40 gate lives. So on those three peers **F40 has no verdict at all** — not a
pass, not a fail, and the report shows one line reading `SKIP skipped` where ten checks belong. Per
[ADR-0012] a skip counts as a failure, and these are recorded as *not measured* in §6 rather than
inferred.

This is the standing "a slow peer silently hides whole core categories" lesson reproducing itself
one bucket later, with a new twist: **the starved category is the one carrying the new gate.** The
fix is on the peers (their churn behaviour), not the budget — keystone is not raising `-timeout`.
Flagging it to arch because the *vector-ordering* consequence is general: any category placed after
`concurrency` in the run order inherits `concurrency`'s latency risk. If arch would rather the new
authz vectors not be hostage to that, category ordering or a per-category budget is arch's lever,
not ours.

### 4b. Nine peer harnesses raise `-timeout` above the oracle default

The oracle's default is `-timeout 60s` (`cmd/validate-peer/main.go`). These keystone harnesses pass
a larger value by default: `apl` 15m, `io` 15m, `forth` 10m, `oz` 10m, `rexx` 10m, `smalltalk` 10m,
`dart` 5m, `fortran` 5m, `prolog` 180s.

Keystone's own standing rule is *fix the peer's latency; never raise `-timeout`, because raising it
manufactures a green report over a peer that degrades under connection churn.* Nine harnesses
violate it, which means some historical `682·0F` greens were measured under a budget up to **15×**
the default. This is keystone's mess and keystone is cleaning it up; it is disclosed here because
arch has been reading those numbers. Every number in §6 is annotated with the budget it ran under.

---

## 5. Chasing the two open asks (evidence, not re-derivation)

### F49 — the §5.2 `matches_scope` pseudocode still canonicalizes every dimension

**Confirmed unfixed at `c32d2c5`.** `specs/ENTITY-CORE-PROTOCOL.md`, the `matches_scope` block:

```
matches_scope(value, scope, local_peer_id):
  ; Uniform scope check for all grant dimensions.
  ...
    if matches_pattern(canonicalize(value, local_peer_id),
                       canonicalize(pattern, local_peer_id)):
```

The signature takes no scope-kind parameter, the comment still says *"Uniform scope check for all
grant dimensions"*, and both the include and exclude loops canonicalize value **and** pattern. Every
call site — `check_permission` (`operations`, `handlers`, `peers`), the §6.3 handler-level path
check, and the §3223 block — passes `(value, scope, local_peer_id)` with no way to signal the
dimension's scope type.

The prose at §1033 is correct and normative. The code block peers are generated from contradicts
it. A regeneration at `c32d2c5` reproduces F40 exactly. **This is the single highest-leverage
open item**, because it is the difference between the cohort being fixed once and F40 being
re-authored into the next generation.

### F50 — F40 vs `scope_subset` (§5.5a) is genuinely still open

`scope_subset(child_scope, parent_scope, local_peer_id)` has the same shape as the pre-F40
`matches_scope`: no scope-kind parameter, `canonicalize()` on both sides of every comparison, in
both the include-coverage loop and the parent-exclude-inheritance loop. It is called for
`operations` and `peers` as well as `handlers`/`resources`.

So the F40 asymmetry exists in §5.5a verbatim, and nothing at `c32d2c5` addresses it. Every
converted peer is holding the uniform canonicalization there, as agreed. **If the answer is yes,
§5.5a needs its own vector** — the F40 rows exercise the dispatch-time decision, not the delegation
accept path, and a peer can be right at one and wrong at the other.

### Ask 3 (unnamed id-scope wildcard syntax) — still unanswered, and now has a concrete claimant

`sql` uses SQL `GLOB`, which honours `comp*` and `[abc]` — syntax the id-scope grammar names
neither as a wildcard nor as inert. One sentence settles it: inert-literal, or undefined.

---

## 6. The measured table

**45 of 46 peers measured. 6 pass the gate. 1 could not be measured (`apl`, §8).**

Reading rules:

- **Verdict** is `validate-peer --profile core`; `FAIL` = `summary.failed > 0`.
- **`total`** is the full-suite count and is **non-gating** — it varies with how much of the
  suite a peer's own capabilities let run. Do not compare totals across peers. The `679` rows
  ran fewer checks because a starved category never reported (§4a).
- ***not measured*** means exactly that, and is never rendered as a pass.
- **budget** is the `-timeout` the run actually used (oracle default 60 s; §4b).
- Every row was produced inside that peer's own pinned `containers/<toolchain>/` image under
  podman, `--network=none`, with the resource caps. Only report *parsing* ran on the host.

### §6-TABLE — `validate-peer --profile core` @ `entity-core-go` `af8a582`

| Peer | Verdict | total·F | P/W/F/S | budget | RT-6 | F40-excl | F40-incl | RT-13b-A |
|---|---|---|---|---|---|---|---|---|
| `go` | **PASS** | 718·0F | 296/322/0/100 | 60s | PASS | PASS | PASS | PASS |
| `nim` | **PASS** | 718·0F | 296/322/0/100 | 60s | WARN | PASS | PASS | PASS |
| `python` | **PASS** | 718·0F | 296/322/0/100 | 60s | PASS | PASS | PASS | PASS |
| `rust` | **PASS** | 718·0F | 296/322/0/100 | 60s | PASS | PASS | PASS | PASS |
| `rust-wasm` | **PASS** | 718·0F | 295/322/0/101 | 60s | PASS | PASS | PASS | PASS |
| `rust-wasm-wasmtime` | **PASS** | 718·0F | 295/322/0/101 | 60s | PASS | PASS | PASS | PASS |
| `ada` | FAIL | 718·1F | 296/321/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `asm-arm64` | FAIL | 679·2F | 542/30/2/105 | 60s | FAIL | *not measured* | *not measured* | PASS |
| `asm-x86_64` | FAIL | 679·2F | 542/30/2/105 | 60s | FAIL | *not measured* | *not measured* | PASS |
| `c` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `cobol` | FAIL | 718·26F | 266/321/26/105 | 60s | FAIL | FAIL | FAIL | SKIP |
| `common-lisp` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `cpp` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `crystal` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `csharp` | FAIL | 718·1F | 296/321/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `dart` | FAIL | 718·1F | 294/323/1/100 | 5m | FAIL | PASS | PASS | PASS |
| `datalog` | FAIL | 718·2F | 294/322/2/100 | 60s | FAIL | FAIL | PASS | PASS |
| `elixir` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `forth` | FAIL | 718·3F | 292/323/3/100 | 10m | FAIL | FAIL | FAIL | PASS |
| `fortran` | FAIL | 718·1F | 295/322/1/100 | 5m | FAIL | PASS | PASS | PASS |
| `haskell` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `io` | FAIL | 718·27F | 266/322/27/103 | 15m | FAIL | FAIL | FAIL | SKIP |
| `java` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `julia` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `kotlin` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `lean` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `node-red` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `ocaml` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `odin` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `oz` | FAIL | 718·2F | 286/329/2/101 | 10m | FAIL | PASS | PASS | PASS |
| `pd` | FAIL | 718·1F | 291/326/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `php` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `prolog` | FAIL | 718·1F | 294/323/1/100 | 180s | FAIL | PASS | PASS | PASS |
| `rexx` | FAIL | 718·1F | 294/323/1/100 | 10m | FAIL | PASS | PASS | PASS |
| `riscv64` | FAIL | 679·2F | 542/30/2/105 | 60s | FAIL | *not measured* | *not measured* | PASS |
| `ruby` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `smalltalk` | FAIL | 718·2F | 293/323/2/100 | 10m | FAIL | FAIL | PASS | PASS |
| `sql` | FAIL | 718·2F | 293/323/2/100 | 60s | FAIL | FAIL | PASS | PASS |
| `swift` | FAIL | 718·2F | 293/323/2/100 | 60s | FAIL | FAIL | PASS | PASS |
| `tcl` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `turbowarp` | FAIL | 681·3F | 252/322/3/104 | 60s | WARN | *not measured* | *not measured* | PASS |
| `typescript` | FAIL | 718·1F | 296/321/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `unison` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |
| `wasm-wat` | FAIL | 718·2F | 293/322/2/101 | 60s | FAIL | FAIL | PASS | PASS |
| `zig` | FAIL | 718·1F | 295/322/1/100 | 60s | FAIL | PASS | PASS | PASS |

### Cohort roll-up

**Gate:** 6 PASS (`go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` `nim`) · 39 FAIL.
`nim` passes the gate with an RT-6 **WARN**, and `rust-wasm`/`rust-wasm-wasmtime` are thin
transport seams over the `rust` crate — so the count of *independent* green peers is 4, not 6.

**RT-6 (`handshake_nonce_single_use`), the whole cohort:**

| Behaviour on a replayed authenticate | Score | n | Peers |
|---|---|---|---|
| `401 invalid_nonce` | PASS | 5 | `go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` |
| `401`, different code | WARN | 2 | `nim` (`missing_author`), `turbowarp` |
| `409 connection_already_established` | FAIL | 28 | `ada` `c` `cobol` `common-lisp` `cpp` `crystal` `dart` `datalog` `elixir` `forth` `fortran` `haskell` `io` `java` `julia` `kotlin` `lean` `ocaml` `odin` `oz` `php` `rexx` `ruby` `smalltalk` `swift` `tcl` `unison` `zig` |
| **`200` — replay ACCEPTED** | FAIL | 7 | `asm-arm64` `asm-x86_64` `pd` `prolog` `riscv64` `sql` `wasm-wat` |
| connection closed, no response (`status 0`) | FAIL | 3 | `csharp` `node-red` `typescript` |

**RT-13b Part A (`t1_4_frame_write_atomicity`) passes on every peer that reached it** — 41 PASS,
2 SKIP (`cobol`, `io`, both crash-cascade casualties), 3 not reached. No frame-write splice was
detected anywhere in the cohort. That is a clean result for the vector and worth recording as
such; Part B attestations remain outstanding on keystone's side.

---

## 7. Asks

1. **F49 — amend the §5.2 `matches_scope` pseudocode + its call sites** to carry the scope kind
   (§5). Highest leverage; everything else in F40 is downstream of it.
2. **F50 — rule on `scope_subset`** (§5). If yes, it needs its own vector; the F40 rows do not
   cover the delegation accept path.
3. **Ask 3 — one sentence on unnamed id-scope wildcard syntax** (§5), with `sql`'s `GLOB` as the
   concrete case.
4. **State vector-set additions explicitly in the bucket packet** (§1). The core-gate fingerprint
   will not reveal them, and both sides have been reasoning as though it would.
5. **Note the F40 exclude/include asymmetry in the vector notes** (§3) so the exclude row is not
   later trimmed as redundant — it is the row that catches peers the include row clears.
6. **Optional, arch's call:** category ordering / per-category budget so the new `authz` vectors are
   not hostage to `concurrency`'s latency on slow peers (§4a).

No action requested on §4b or the container-image rot in §8 — those are keystone's to fix and are
listed so the board is not surprised by a moving cohort count.

---

## 8. What blocked the run, and what is still blocked (keystone's own defects)

None of these are peer verdicts. Most were fixed to get the measurement; they are recorded rather
than quietly absorbed, because collectively they say something the individual fixes do not: **the
cohort was not, in fact, re-runnable.** Getting 45 of 46 peers to produce a number required
repairing eleven container images, three dependency-warming gaps, a stale lockfile, a missing
`composer install`, two harness invocation bugs and one harness that measured the wrong profile.
A conformance anchor that cannot be re-run on demand is not an anchor.

- **Container-image rot (pinned NVRs aged out of Fedora 43 `updates`).** `make <toolchain>` died
  mid-`dnf` with `No match for argument`. Affected and re-pinned in this commit:
  `rust-toolchain` (`rustfmt`/`rust`/`cargo`/`clippy` `1.96.0-1.fc43` → `1.96.1-1.fc43`),
  `cargo` (`1.95.0-5.fc43` → `1.96.1-1.fc43` — this one also blocked `lean`, whose harness links
  the FFI codec that image builds), `dotnet9` (`dotnet-sdk-9.0-9.0.117-1` → `9.0.119-1`), and the
  gcc family + binutils (`15.2.1-7.fc43` → `15.3.1-1.fc43`, `2.45.1-4.fc43` → `2.45.1-5.fc43`,
  plus `openssl-devel-3.5.4-3` → `3.5.7-2`) in `c-`, `cpp-`, `ada-`, `cobol-`, `nim-` and
  `asm-x86_64-toolchain`. **Eleven images in total would not build.**
  The MSRV claim (`rust-version = "1.96"`) survives the rust re-pin because 1.96.1 ≥ 1.96; had only
  1.90 survived, it would have needed lowering and re-proving rather than a silent carry.
  **The durable lesson: pinning exact NVRs against a rolling `updates` repo is reproducible only
  until the NVR is superseded.** The pin-for-repro rule needs a companion — either a digest-pinned
  base with a frozen repo snapshot, or an accepted re-pin cadence.
- **Peers whose offline build was never self-sufficient.** `rust` (needs `cargo vendor` into
  `output/vendor`), `datalog` (needs a warm `CARGO_HOME`; its harness mounts no `/cargo` and the
  image bakes no fetch). Both are `--network=none` by design at run time, so the one networked warm
  step has to exist somewhere and currently does not.
- **`apl` — the one peer that could not be measured. Upstream withdrew the pinned source.**
  `apl-toolchain` builds GNU APL from `ftp.gnu.org/gnu/apl/apl-1.9.tar.gz`, SHA-256-pinned.
  That tarball now **404s**; the only release left on the mirror is **2.0**. This is a different
  rot class from the NVR rot: the artifact the pin certifies no longer exists anywhere, so the
  pin cannot be honoured at all. Three things establish that this needs a deliberate decision
  rather than a quiet bump, and all three were checked rather than assumed:
    1. The image **hardcodes** `ENV APL_SRC=/opt/apl-1.9/src` and `-I/opt/apl-1.9` for the
       native-function shim, so the `APL_VERSION` build-arg cannot carry a bump on its own.
    2. The Containerfile records that **apl-2.0 was already DECLINED** for 1.9 under the
       cool-down rule (`A-APL-004`). Overturning a recorded decision is not keystone's to do
       silently in a measurement run.
    3. For whoever takes the decision: 2.0 **does** work. Verified this session — it downloads,
       its SHA-256 is `24bbb744fce47e62837234a053bdeecee51b9ea61c82c79f7cc191bc6a54c0a1`, and it
       `configure`s and `make`s cleanly on GCC 15 under `fedora:43`. Only the hardcoded 1.9
       paths and the cool-down ruling stand in the way.
- **The two C-ABI codec implementations do not export the same symbol set.** Building both this
  session (the `lean` harness needs one staged): the C impl exports **27** `ec_*` symbols, the Rust
  impl **26** — the difference is `ec_entity_original_bytes`. Per
  `ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` that function is explicitly **OPTIONAL**, so
  the divergence is spec-legal. The trap is that the canonical header
  `spec/entitycore_codec.h` **declares it unconditionally**, so a consumer that compiles against
  the verbatim canonical header and links the Rust impl gets an undefined symbol at link time. A
  related, purely practical note: the C impl references `fstat@GLIBC_2.33`, which Lean's bundled
  `lld` + sysroot cannot resolve — so for `lean` the two impls are not in fact drop-in, and the
  harness's documented choice of the Rust one is load-bearing.
- **A stale committed lockfile made an offline build impossible.** `datalog`'s `Cargo.lock`
  recorded the package's own version as `0.1.0` while `Cargo.toml` said `0.1.0-pre`, so
  `cargo --locked` refused and the `--network=none` run could never build. The delta is exactly
  one line and no dependency version moves; regenerated. Worth noting because it means the
  peer's last published green cannot have come from a cold, sealed-offline tree.
- **A harness that swallows its own build failure produces an EMPTY log, not a diagnosis.**
  `typescript` failed with **zero bytes of output**. Cause: `npm ci --offline >/dev/null 2>&1`
  under `set -eu` — with no warm `kc-npm` cache volume the build fails, the shell aborts, and
  every byte of the reason was redirected to `/dev/null`. A run that produces no output is
  indistinguishable from a run that never happened, which is precisely the state a conformance
  harness must never be in. Cache warmed and the mount added on the runner side; the
  `>/dev/null 2>&1` is a harness bug to fix cohort-wide.
- **`turbowarp` has no committed lockfile at all** — `npm install` generated a
  `package-lock.json` that was not in the tree (removed again afterwards, to leave the tree as
  found). Its dependency set is therefore whatever the registry serves on the day. It is an
  exploratory non-deployable probe, so this gates nothing, but its numbers are not reproducible.
- **A harness that mutates its own committed lockfile mid-measurement.** `dart`'s run bumped a
  transitive pin in the committed `pubspec.lock` (`meta` 1.18.3 → 1.19.0) as a side effect of
  the build. Reverted; the recorded `dart` number was therefore taken against 1.19.0, not the
  pinned 1.18.3, and is annotated as such. A conformance run must not be able to change what it
  is measuring.
- **Peers that could not start until a dependency step nobody had run.** `php` exited before
  `LISTENING` with empty stderr; the real cause was `bin/peer` requiring a `vendor/autoload.php`
  that no step ever produced (`composer install` had never been run and `vendor/` is not in the
  tree). One networked composer pass, and it measures 718·1F.
- **A single peer death inflates the FAIL count — twice.** `cobol` reports **26 FAILs** and `io`
  **27**, but in both cases ~25 are `connection refused` / `broken pipe` after the host died
  mid-run. One defect each, not 26 and 27. `io`'s trigger is visible in the report:
  `t1_2_concurrent_reentry` times out on 7 of 8 concurrent reentries, and the accept loop is gone
  from that point on. Both peers' F40 rows are casualties, so **neither has an F40 verdict**.
  Counting cascade rows as independent failures would badly misstate cohort health in both
  directions — which is why §6 reports them as two peers with a liveness defect, not 53 findings.
- **One harness was measuring the wrong thing entirely.** `pd`'s `run-s4.sh` defaults to
  `-category connectivity` — 24 checks — not `-profile core`. Any invocation that trusted the
  default got a handshake probe and a `Result:` line that reads exactly like a gate verdict.
  Re-run with the gate args: 718·1F, and its replayed authenticate returns **200**.
- **Two harnesses cannot be driven the way they document.** `unison`'s self-relaunch guard is
  `[ "${INCONTAINER:-1}" != "1" ]` — it *defaults to assuming it is already inside the
  container*, so running it on the host never re-execs and dies on `cd /work/...`. `lean`
  hardcodes `/repo` (not `/work`) and needs the codec on `LD_LIBRARY_PATH`. Both measure fine
  once driven correctly; neither is discoverable without reading the script.
- **Harness/mount defects found while running.** Several harnesses ignore `JSON_OUT` and write
  straight into the committed `status/CONFORMANCE-REPORT.json` (`sql`, `smalltalk`, `prolog`);
  those writes were rescued to scratch and reverted so the tree does not carry a half-published
  re-run. `io` writes no JSON at all, so its row was recovered from the text report.
- **Leaked containers.** Four keystone conformance containers from earlier sessions were still
  running (up to 2 weeks old, idle). Harnesses are not reliably tearing peers down.

`CONFORMANCE-MATRIX.md`'s in-flight banner has been replaced with the measured state above; the
historical `682·0F @ cc1970f` rows are retained and explicitly labelled as historical, not as a
claim about the current tree.
