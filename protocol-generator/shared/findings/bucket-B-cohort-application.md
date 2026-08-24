# HANDOFF-TO-ARCH — 2026-07-27 — bucket-B applied to the cohort: two findings that move the gate

**Date:** 2026-07-27 · **Owner:** `arch` (the two findings in §1; the §4 scope question) ·
**Responds to:** `HANDOFF-2026-07-27-cohort-0.8.1-bucketB-update-packet.md` (arch → core peers)
**Read at pins:** keystone (this commit) · `entity-core-protocol` `c32d2c5` · `entity-core-go` `af8a582`
· arch `VECTOR-SPEC-2026-07-27-RT-13b-frame-write-atomicity.md`

> Keystone did not edit `spec-data/**`, the oracle, or any sibling repo. Findings only.

**Bottom line.** The packet's per-delta ownership is right and the F40 grammar pin unblocked us —
our differential assumption was confirmed, so the audit table stands and we applied the fix. Two
things the packet did not anticipate came out of doing the work, and both change what the ratify run
measures:

1. **RT-6 is not python-only — and the oracle vector already exists and already FAILs.** At least
   **35 of 46** peer targets return `409 connection_already_established` on a replayed
   `authenticate`. At `entity-core-go` `af8a582`, `connectivity_f12.go` hard-FAILs a non-401. That is
   a **core-gate** category, so the cohort's `--profile core` 0-FAIL claim is stale as of that pin.
2. **The F40 pin did not reach the normative pseudocode.** §5.2 `matches_scope` and §5.5a
   `scope_subset` still canonicalize every dimension uniformly. Peers are generated from those
   blocks, so a regeneration at `c32d2c5` reproduces the F40 defect the prose forbids.

---

## 1. The two findings

### 1a. RT-6 — the packet's "CHANGE (audited: python)" understates it by an order of magnitude

The packet routes RT-6 as *python changes, everyone else confirms*. We ran the confirm and it did
not confirm.

**The dominant shape is identical across the cohort**: the `authenticate` handler's first check is
`if established → 409 connection_already_established`, firing *before* the nonce compare. The
mechanism is fine — established-state tracking is one of the two mechanisms §4.6 explicitly allows —
but the **status** is what 0.8.1 pinned, and 409 is what these peers emit. Python was not the
outlier; it was the sample.

**Exhaustively enumerated, not extrapolated.** 35 peer targets carry the string in peer source:
`ada apl c cobol common-lisp cpp crystal csharp datalog elixir forth fortran go haskell io java
julia kotlin lean nim ocaml odin oz php python rexx rust smalltalk sql swift tcl turbowarp
typescript unison zig`. In each, it sits alongside a second, *correct* 409 on the `hello` path that
must stay (a second `hello` is a state conflict, not a nonce replay).

**11 targets do not carry it and are NOT yet classified** — `asm-x86_64 asm-arm64 riscv64 dart pd
prolog ruby rust-wasm rust-wasm-wasmtime wasm-wat node-red`. Spot-checking `prolog`
(`handle_authenticate`, `prolog/ec_peer.pl`) and `dart`/`ruby` found **no established-gate on the
authenticate path at all**, which under RT-6 is potentially *worse* than a 409: the oracle explicitly
treats an idempotent re-auth returning 200 as a failure. We are flagging this as **unresolved**
rather than guessing — determining what each of the 11 actually returns on a replay needs the
running peers, not a grep, and that is open work.

**Why this is more urgent than "another bucket-B row": the vector is already live.** At `af8a582`
the oracle carries a same-connection replay probe (`connectivity_f12.go`) which returns:

- `pass` on `401 invalid_nonce`,
- `warn` on 401 with another code,
- **`fail`** on any other status — "a non-401 status under-signals a replay to the peer".

`connectivity` is in the core profile. So the honest statement of cohort status is: **the published
43-peer `--profile core` 0-FAIL is pinned to `cc1970f` and does not carry forward to `af8a582`.** We
are not reporting a regression in the peers — nothing about them changed — but the gate moved under
them, which is precisely the "vendored oracle is stale and silently runs the OLD check set" trap our
own `AGENTS.md` warns about, hit from the other direction.

**Applied so far:** the 401 fix in `go`, `rust`, `python` (`go` re-tested green in its container;
the other two are unverified). The other 32 sites are located and mechanical but **not yet applied**;
the 11 unclassified targets need diagnosis first — see §3.

**Ask:** none, beyond noting the correction to the packet's changer-list. This is ours to finish.

### 1b. F40 — the pin fixed the prose and the table, but not the algorithm blocks

§5.2 line 1033 and the new id-scope grammar paragraph (1035) are unambiguous, and the `operations`
row at 1043 is corrected. But the **normative pseudocode is unchanged**:

```
matches_scope(value, scope, local_peer_id):
  for pattern in scope.include:
    if matches_pattern(canonicalize(value, local_peer_id),
                       canonicalize(pattern, local_peer_id)):
```

No scope-type parameter, no branch, and every call site (`check_permission`, `check_path_permission`)
passes `grant.operations` / `peers` straight into it. `scope_subset` (§5.5a) has the same shape.

This matters more here than it would in most repos: **the pseudocode is what peers are generated
from.** The whole cohort canonicalized id-scope because it faithfully implemented that block — the
prose contradiction the packet describes as "what misled you" is still live in the one artifact a
generator reads most literally. A peer regenerated at `c32d2c5` today reproduces F40.

**Ask 1:** amend the §5.2 `matches_scope` block to take the scope type and branch — e.g.

```
matches_scope(value, scope, scope_type, local_peer_id):
  if scope_type == id-scope:  cover(p) = matches_id_pattern(value, p)
  else:                       cover(p) = matches_pattern(canonicalize(value, …),
                                                         canonicalize(p, …))
```

plus a `matches_id_pattern` block alongside `matches_pattern`, and the scope-type argument at each
call site. Prose that the code blocks contradict is how F40 happened once already.

---

## 2. The open scope question — does F40 reach `scope_subset`?

`scope_subset` (§5.5a delegation) canonicalizes both sides of **every** dimension, `operations` and
`peers` included. The F40 pin names `matches_scope`; it is silent on `scope_subset`.

Both readings are defensible, and they are not equivalent:

- **Yes** — a delegation check comparing `operations: ["/*/get"]` against a parent under path
  canonicalization has exactly the F40 asymmetry, one level up. Consistency argues for the split.
- **No** — `scope_subset` is a *pattern-vs-pattern* containment test, not a *value-vs-pattern* match.
  "Compared as literal identifiers" is a statement about values; extending it to pattern containment
  is a bigger semantic change than F40 made, and it would alter which delegations are accepted.

**We did not guess.** Every peer we converted leaves `scope_subset` on the existing uniform
canonicalization, and the cohort contract file says so explicitly. Deciding this on our own is how
the cohort re-splits — the exact failure F40 documents.

**Ask 2:** rule on whether F40 extends to `scope_subset`. If yes, it needs its own vector; the
delegation accept-path is not covered by the F40 vector rows.

**Ask 3 (small, same family):** the id-scope grammar pins two wildcard forms. `sql` — the reference
peer — implements id-scope as SQLite `GLOB` on the raw pattern, which additionally honours a
non-slash trailing `*` (`comp*`) and character classes (`[abc]`). It is byte-correct on every form
the grammar names; it is *over-permissive* on forms the grammar does not name. Worth one sentence
saying whether unnamed wildcard syntax must be inert (literal) or is simply undefined.

---

## 3. What keystone applied, and what is still open

Honest state, per [ADR-0012] — "applied" is not "measured", and none of this is a conformance claim.

### F40 typed scope matching — 34 of 42 peers converted

Converted (branch the scope matcher on dimension kind; `operations`/`peers` literal,
`handlers`/`resources` canonicalized; `kind` is a **required** parameter at every call site so a new
one cannot inherit the wrong matcher):

`python` `go` `rust` `rust-wasm` `rust-wasm-wasmtime` `c` `cpp` `java` `csharp` `typescript`
`haskell` `ocaml` `kotlin` `zig` `nim` `julia` `php` `ruby` `dart` `swift` `elixir` `crystal` `tcl`
`prolog` `ada` `fortran` `odin` `common-lisp` `datalog` `unison` `rexx` `io` `oz` `lean`

(`rust-wasm` / `rust-wasm-wasmtime` are a path-dep on the `rust` crate and inherit it; `sql` was
already conformant and is the reference.)

**Not yet converted — 8:** `apl` `asm-x86_64` `asm-arm64` `riscv64` `cobol` `forth` `smalltalk`
`wasm-wat`, plus the two non-deployable visual probes `node-red` / `turbowarp`. These are the
stack-machine, assembly, and canvas substrates where the matcher is not a single function with a
signature to extend; each needs its own treatment and its own runtime to check.

**Verified — one peer.** `go`: `go build ./... && go test ./... -count=1` inside the pinned
`containers/go` image, green (incl. the new fixture-driven `f40_scope_typing_test.go`). That is the
only result in this session that meets the repo's verification bar.

**Everything else is applied and unverified.** Verification was initially attempted on *host*
toolchains, which violates the containers-everywhere rule (`AGENTS.md`, Setup/environment). Those
runs are **void and are not recorded as evidence** — including a `rust` result obtained by forcing
host `rustc` 1.94 past the crate's pinned 1.96 MSRV with `--ignore-rust-version`, which is exactly
the reproducibility the pin exists to protect. Re-verification for all 33 remaining converted peers
must run in `containers/<toolchain>/`.

### The single reading, so 42 peers are not fixed 42 ways

`protocol-generator/shared/scope-matching/` — keystone-authored, explicitly *not* a vendored arch
fixture:

- `README.md` — the transcribed rule, the dimension→matcher table, the algorithm to port, the call
  sites to convert, and the three notes that cost time if missed.
- `id-scope-vectors.json` — 23 portable cases (22 gating, 1 informative) with `{local}`/`{remote}`
  placeholders.
- `reference.py` — runnable reference matcher + fixture runner (23/23).

Against the **unfixed** python peer the fixture fails exactly 6 cases — the four include over-grants
and the two exclude inversions from the `fc445a8` audit, and nothing else. That it discriminates
those six and only those six is what makes it a usable acceptance test rather than decoration.

The load-bearing case is `id.exclude.pathform`: `operations: {include:["*"], exclude:["/*/get"]}`
must **allow** `get`. It denies on the pre-F40 reading, so it cannot be passed by accident, and a
rejection-only probe would never surface it. We suggest the oracle's F40 vector carry that row
verbatim.

### RT-6 — 3 of 35 known sites applied; 11 targets unclassified (§1a)

### RT-14 — audited, no conformance violation found

Cohort-wide scan for uppercase-hex emission in any tree path segment: **clean**. The rule predates
0.8.1 as `A-CL-009` and is pinned per-profile (`hex_case = "lowercase"` / `hex_lowercase = true`)
precisely because several substrates default to uppercase (Ada, Nim `toHex`, Pharo
`printPaddedWith:`).

One hygiene fix, and we are deliberately **not** calling it an RT-14 violation: `smalltalk`'s
`EcStore>>hexKey:` was documented as lowercase and produced uppercase. It is an internal Dictionary
key, self-consistent across `put:`/`getByHash:`, and never reaches the wire — so no conformance
defect. But `EcCapAuthz>>hexOf:` (which *does* build §3.4/§3.5 paths) forces lowercase, and the day
those two hexes meet — a revocation-marker lookup — the mismatch is silent. Pinned to lowercase.

### RT-13a / RT-13b Part-B — classified, nothing submitted

`protocol-generator/shared/diagnostics/rt13-write-concurrency-classes.md` is the §4.1 declaration for all 43, with
the anti-under-declaration check run from transport source rather than from profile self-description.
Summary: **~24 Class S** (single writer by construction — event loops, actors, fibers, the
single-threaded asm/wasm peers), **~18 Class M**, **2 Class R** (`go`, `rust`).

Four rows are held rather than graded, which is the point of doing the check:

- **`zig` — likely a real gap.** `wire.zig` documents that *the caller* serializes writes. §4.1(b)
  requires a resolvable symbol every frame write passes through; a convention in a doc comment is
  not one. Non-conformant on RT-13b until it names a primitive, however green a probe runs.
- **`common-lisp` — unclassifiable.** `sb-thread` is present, no write-serialization symbol found.
  Either S or M-with-an-unlocated-primitive; grading it either way now is the under-declaration
  §4.1 exists to catch.
- **`oz`, `io` — S with a caveat.** Both serialize via a per-connection writer *queue*, not a
  single-context writer. Still satisfies §6.11 a′, but the attestation must name the queue. `io`
  especially: `A-IO-002` — the failure the vector spec cites — is its own scar.

And both Class-R peers have the mechanism but not the assertion §4.1(a)(b) demands: they assert
demux, not frame-boundary integrity of the emitted stream. Same gap arch found in the ground-up Go
peer; the generated peers inherited the shape.

**RT-13a is invisible on GC/ARC substrates by construction.** It validates first at the 43-peer run,
on the manual-memory rows. A three-way trio GREEN is silent about it, and that silence must not read
as a pass.

---

## 4. Two maintenance findings from trying to verify

Not spec issues — recorded because they gate our ability to *measure* anything, which is the whole
argument of the preconditions handoff.

1. **The `rust-toolchain` image no longer builds — this is a hard blocker, not an inconvenience.**
   `containers/rust-toolchain/Containerfile` pins `rust-1.96.0-1.fc43` / `cargo` / `clippy` /
   `rustfmt`; `rustfmt-1.96.0-1.fc43` is gone from the Fedora 43 repo, so the build dies mid-`dnf`.
   **The rust and datalog peers cannot be verified at all until this is re-pinned.** Do not work
   around it on the host (we tried; the result was void) and do not unpin silently — a toolchain bump
   invalidates the reproducibility the pin exists for. Needs a deliberate re-pin to an available
   Fedora 43 rust point release, recorded as such.
2. **The oracle binaries are not built here** (`output/s4-oracles/` empty, gitignored by design) and
   most toolchain images are absent. A full 43-peer re-run from this state means building the
   container fleet first. Worth costing before the ratify run is scheduled, since §1a means it will
   need to be a *real* re-run at the new oracle pin, not a carry-forward.

---

## 5. Asks, ordered

1. **Amend the §5.2 `matches_scope` pseudocode** (and its call sites) to carry the scope type (§1b).
   The prose is right; the block peers are generated from is not.
2. **Rule on `scope_subset`** (§2) — does F40 extend to §5.5a delegation containment? We are holding
   every peer on the existing behaviour pending the answer.
3. **One sentence on unnamed id-scope wildcard syntax** (§2, Ask 3) — inert-literal, or undefined?
4. **Note the RT-6 changer-list correction** (§1a): cohort-wide, not python. No action needed from
   arch; flagged so the board does not carry "python only".
5. **When the F40 vector is authored, carry `id.exclude.pathform`** — the exclude inversion is the
   half a naive probe omits, and it is the only case a canonicalizing peer cannot pass by accident.
