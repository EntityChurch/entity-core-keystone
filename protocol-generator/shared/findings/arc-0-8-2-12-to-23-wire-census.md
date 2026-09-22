# The `0.8.2.12 → 0.8.2.23` arc, measured on the wire across the cohort

**Date:** 2026-09-14
**Instrument:** `tools/arc-probe` (probe, runner and summarizer committed beside this file)
**Cohort:** 46 generated peers, spec snapshot pin `v0.8.2.11`, all at `778 · 0F` on executed check
set `7aa6f3de…` (oracle `78db4a9`)
**Measured:** 45 of 46 — `turbowarp` alone is structurally out of reach (§5). **45 is the
denominator of every count here.**

---

> ## ⛔ UPDATE 2026-09-14 — TWO OF THE FOUR FAMILIES ARE CLOSED, AND THE THIRD TURNED UP SOMETHING BIGGER
>
> Everything below is the measurement **as taken**, and it is left standing: a dated
> measurement that gets back-edited stops being evidence of anything. This box says what
> has moved since, and **§7 is new**.
>
> - **§3 `K1` — CLOSED at 12 of 12.** All seven peers on which the forgery reproduced now
>   bind the included key at the single read site every caller goes through; all seven
>   answer `401 authentication_failed` on the author arm and `403 capability_denied` on the
>   capability arm, which is `io`'s answer and was already graded conformant. The five that
>   refused by dropping the connection now answer `400 non_canonical_ecf`. **`0 of 740`
>   severities moved on the seven; exactly `1` moved on each of the five, and that one is
>   `ingest_rejects_unrepresentable_expiry` WARN → PASS** — CAP-6a had been scoring those
>   silent drops all along and its own detail said so.
> - **§4 the sentinel — CLOSED at 39 of 44 measurable**, including all 13 that answered
>   `500`. `canonicalize` is total, `matches_pattern` refuses either operand being the
>   sentinel, and both exclude-reading sites deny. Four peers are **deliberately not swept**
>   and one class of two is unmeasurable — see §7.
> - **§2 the ladder — UNCHANGED and still owed.** Held behind vectors on purpose; the
>   reasoning in §6 has not changed.
> - **§7 is new and is the largest single finding of the whole exercise**: four peers do not
>   read a grant `exclude` at dispatch at all, which §4's own probe case is structurally
>   unable to see.
>
> **Closing verification, with its one wrinkle stated rather than smoothed:** the cohort was
> re-censused whole, **46 of 46 at `778 · 0F`**, every peer on the identical check set, and
> **3 of 34 040 severities different** from the committed reports — all three
> `t1_1_concurrent_demux`, two against and one for, which is the same signature and the same
> count this repo recorded at the last pin flip. None banked.
> **The FIRST full census returned `ocaml` and `common-lisp` at `1F` each** —
> `t2_1_sustained_load` and `t1_2_concurrent_reentry`, both load-shaped. Re-run in isolation:
> **0 of 3 each.** Re-run as a full census: **0 of 1.** So the rate is *2 peer-runs of 92
> across two full censuses, 0 of 6 isolated* — a load-dependent intermittent of the class
> `AGENTS.md` already records for `t1_2_concurrent_reentry` on `go` with this exact signature
> (fails once under cohort load, passes isolated, not root-caused). **It is recorded as a rate
> and not as an adjective, and it is NOT attributed to this sweep** — the checks are in a
> family none of these changes touch, and both peers were individually censused at `0F` with
> `0 of 740` moved when their own change landed.

---

> ## ✅ SECOND UPDATE 2026-09-16 — **THE LADDER IS NO LONGER OWED, AND THE BOX ABOVE IS SUPERSEDED ON THAT ONE POINT**
>
> The 2026-09-14 box above says *"**§2 the ladder — UNCHANGED and still owed.** Held behind vectors
> on purpose."* **That was true when written and is false at HEAD**: the `0.8.2.25` sweep landed the
> §3.3 effective-targets ladder across the cohort. Both boxes are left standing, dated, rather than
> reconciled into one.
>
> Re-measured on a **single-age** roster run (`tools/arc-probe`, **46 of 46**, report-age span
> **0.04 h**) plus `run-mint-floor.sh` for the five peers the §6.9a floor voids:
>
> - **§2 the ladder** — `A1`/`A2`/`A3`/`A4`: **44 of 46 conform**, against **0 of 45** on three of
>   the four rows when this document was written.
> - **§3 `K1`** — `B1`/`B2`: **46 of 46**, unchanged from the first update box.
> - **§4 the sentinel** — `A5`: **46 of 46**.
> - **§7 the grant exclude** (`E2`, the control this document's §7 added): **46 of 46** — the four
>   peers §7 names now read the field.
>
> ⛔ **The entire residual is `fortran` and `unison`, and they are a different finding: no
> `sweep tranche` or vanguard commit ever touched them** — **44 swept against a 46-peer roster**,
> verified as a set difference. They owe six `arc-probe` rows each and **5 of 6 §4.11 arms**, which
> is the pre-sweep baseline exactly. `CONFORMANCE-MATRIX.md` footnote ¹³ carries it.
>
> **The mechanism is worth more than the two peers.** *A sweep run tranche-by-tranche measures each
> peer as its tranche lands, so a peer that no tranche touched is measured by nothing and appears in
> no tranche's report as anything.* Every tranche truthfully reported `0 of 15` about its own peers.
> `output/scratch/arc/` then read as a cohort picture while spanning **29.5 h**, with seven peers'
> reports older than their own sweep commit. **The control is a set difference, not a measurement.**

---

## 0. Why this was taken, and what it is not

Twelve spec revisions landed while this seat reviewed them, and none had been measured. The
standing rule in `AGENTS.md` is that a source read is a hypothesis and a vocabulary-keyed grep
under-reports itself — this repo has published a false negative from one four times. The four
previous cohort-scale questions answered on the wire all came back surprising **in both
directions**: put-admission `0 of 46`, H1 `26 of 46`, the §4.7 corner `36 of 45`, the pre-hello
census `38/6/1` then `46 of 46` after a sweep.

**This is a measurement, not a conformance verdict.** Every peer here is `778 · 0F`, and the
executed check set drives **none** of the rows below. Nothing in this document says any peer is
non-conformant against the set it was measured on; it says what each peer does on inputs the arc's
revisions are about.

**The peers are one generation lineage.** 45 agreeing is cohort-consistency, not independent
convergence, and where a number is used as evidence below it is used as evidence about *the spec's
readability*, which is the thing 45 independent readings of one text can speak to.

### The instrument, and the two ways it was wrong first

`arc-probe` drives four families against each peer, one fresh session per case, with a positive
control everywhere and an **antecedent** control on the two families whose finding is an
acceptance. The peer is launched from its **own** `run-s4.sh` with exactly one flag removed —
`--debug-open-grants`, the degenerate `default → *` seed policy — so it falls back to the §6.9a
discovery floor, a real shipped grant. Nothing else about the launch differs from the census
configuration.

Two grading defects were found by the cohort and fixed before these numbers were taken, and both
would have published a wrong claim:

- **A family whose own control fails cannot report a conformant row.** `asm-x86_64`, `asm-arm64`,
  `riscv64`, `sql` and `wasm-wat` refuse **every** `system/capability:request`, so their `403` on a
  mistyped scope read as *the only five peers in the cohort enforcing `J4` clause 2* — and they
  refuse the well-typed control identically. Those rows now read `VOID`. Ungraded, that was a
  `5 of 45` where the truth is `0`, in the flattering direction nobody re-checks.
- **A refusal on an address with nothing behind it is a MISS, not a mechanism.** The capability arm
  points at a key that holds nothing, so a key-trusting peer and a key-discarding peer both refuse.
  Only the author arm — where the entity **is** present, at the wrong address — discriminates. The
  report now says so on every peer that fails the author arm and passes the capability one.

*(And the runner itself had a guard that could never execute: its image-name pattern omitted `_`, so
`asm-x86_64-toolchain` never matched, `grep` exited 1, and under `pipefail` the assignment killed the
script **before** the `[ -n "$img" ]` guard written to report exactly that. The first roster run
stopped at peer 29 and took the 17 behind it with it, leaving a bare non-zero exit as the only trace.
Fixed in both this runner and `f68-probe`'s, which had carried it latent since it was written.)*

---

## 1. ⛔ The correction we owe: `J4` clause 2 obliges ~every implementation to add a read of a field whose absence is what makes it safe

**This is ours.** `F72` asked for two things and arch folded both as `0.8.2.22` `J4`:

> **Clause 1** — *the scope type is a property of the DIMENSION and is supplied by the call site …
> An implementation MUST NOT take the dispatch type from a received entity's `scope.type` field.*
> **Clause 2** — *A received `scope` whose declared `type` contradicts its dimension is a malformed
> token and MUST be refused `403 capability_denied` `[MUST]`.*

Clause 1 is right, costs zero, and is what every implementation already executes. **Clause 2 is a
mechanism-shaped MUST and its cost is the inverse of what both of us recorded.** Arch's routing to
`entity-core-go` says *"`J4` is the one to read first for build impact, and the impact is zero"*;
our own tracker row asked for it in these words: *"plus a malformed disposition for a scope whose
declared type contradicts its dimension."*

**Measured — `C1`/`C2`, a `system/capability:request` whose `operations` scope declares
`path-scope` (and, the other direction, whose `resources` scope declares `id-scope`):**

| answer | peers |
|---|---:|
| `200` — minted; the declared type was never read | **40 of 40 measured** |
| `403 capability_denied` | 0 |
| VOID (peer refuses the well-typed control too) | 5 |

**Zero.** And the differential says why: `C3`, the same request with **no** `type` key at all, is
answered identically by all 40 — so nothing in the cohort is reading that field in any direction.

The three ground-up implementations are the same by construction, verified at the line rather than
by grep:

- `entity-core-rust` — `matches_scope(value, include: &[String], exclude: &[String], local_peer_id)`
  (`core/capability/src/lib.rs:676`). There is no scope object to carry a type.
- `entity-core-py` — `CapabilityScope` is `{include, exclude}`; `from_dict` reads those two keys and
  nothing else (`capability/token.py:74-99`). Its own docstring: *"On wire, this maps to either
  path-scope or id-scope depending on usage"* — which is clause 1, written down.
- `entity-core-go` — grants are a struct of named dimensions (`g.Handlers.Include`,
  `g.Operations.Include`); the type is structural.

**So the population clause 2 obliges to change is not "2 of 3 seats", it is ~48 of 49 implementations
— and the property that makes them safe is precisely that they do not read the field.** Clause 1
tells an implementer to ignore `scope.type`; clause 2 tells the same implementer to parse it,
compare it against a dimension→type table, and refuse. An implementation that ignores the field
completely — the one clause 1 describes as correct — **cannot detect the contradiction at all**.

**Ask: withdraw clause 2 and keep clause 1.** If a disposition is wanted for a mistyped grant, the
place it costs nothing is the **admission** path a peer already has (§6.3 `put` explicitly does not
validate `data` against `type`; M3 checks multi-granter shape only), stated as MAY rather than MUST
— not the matcher, which is the one site clause 1 just finished removing the field from.

**The general form, and it is the third instance in three days:** when a finding says *nobody
validates X*, the fix is a rule about **who supplies X**, and the temptation is to demand a refusal
when X is wrong. The refusal is what puts the mechanism back. `K1.5`/`K1.7` is the same shape
(caught), and so is this one (arch caught it; we caused it).

---

## 2. The §3.3 effective-targets ladder is unimplemented cohort-wide — 0 of 45 on three of its four rows

`0.8.2.20` rules that a resource-requiring operation resolves through `effective_targets` and
answers **from that list**: empty → `400 path_required`, more than one → `400 ambiguous_resource`,
exactly one → proceed **on that entry**, and a single entry that `is_pattern` → `400
malformed_resource`.

Driven on `system/tree:get` with **both** targets inside the discovery floor's grant and both bound,
so authorization is not a variable in any row:

| row | required | measured |
|---|---|---|
| `targets:[qA] exclude:[qA]` — empty effective set | `400 path_required` | **45 × `200`, acting on qA.** 0 conform |
| `targets:[qA,qB]` — two entries | `400 ambiguous_resource` | 41 × `200` on qA · 3 × `400 handler_error` (`csharp` `node-red` `typescript`) · **1 × `400 ambiguous_resource` (`nim`)** |
| `targets:[qA,qB] exclude:[qA]` — effective `{qB}` | proceed **on qB** | **41 return qA — the EXCLUDED target** · 4 refuse a legitimate single-entry set. 0 conform |
| `targets:["system/type/*"]` — pattern subject | `400 malformed_resource` | **45 × `404 not_found`** — the pattern was resolved as a literal path and missed. 0 conform |

**Row 3 is `F71` confirmed at cohort scale and with the grant removed as an explanation.** The F68
census measured five backends against an *out-of-grant* target; here both targets are in-grant, so a
`200` on qA is a **selection** defect and can be nothing else. 39 of 45 peers index `targets[0]`.

**Row 3 is also `F71`'s warning measured:** the four peers that refuse — `csharp`, `node-red`,
`typescript` on a raw arity check, `nim` on its `ambiguous_resource` — are refusing a request the
ruling says to **proceed on**. A count-only fix makes their effective count 1 and opens that arm.
The selection form `0.8.2.20` adopted is what closes it; it is simply not implemented anywhere yet.

**`nim` is the only peer in the cohort with any of this**, and it has the `>1` code and not the
`=0` one — which is the *"having the arity check does not imply having the codes"* half of `F71`,
now with a cohort denominator.

---

## 3. ⛔ `K1`'s forgery reproduces on 7 of 45 peers, and 5 more refuse it by dropping the connection

The author arm: `author` names the probe's own identity hash; the entity filed **under that hash** is
a second, real keypair's `system/peer` — valid, self-consistent, wrong only under the key — and the
request is signed by that second key with `signer` naming the same hash. A peer resolving by key
verifies a genuine signature against a genuine public key and attributes it to an identity whose
private key nobody in the exchange holds.

| answer | mechanism | peers |
|---|---|---:|
| `400 non_canonical_ecf` | **(a) bind the key**, at the decode boundary | 32 |
| `401 authentication_failed` | **(b) discard the key**, §5.2a author row | 1 — `io` |
| *no response* — connection dropped | refused, but not as a status | 5 — `datalog` `node-red` `rust-wasm` `rust-wasm-wasmtime` `smalltalk` |
| **`200`** | **resolved through an unverified address** | **7 — `asm-arm64` `asm-x86_64` `cobol` `pd` `riscv64` `sql` `wasm-wat`** |

Both controls green on all 45: the impostor acting as **itself**, correctly keyed, is refused
everywhere (so a `200` is attributable to the address, not to the peer accepting any signer); and a
bogus address with nothing behind it is refused everywhere.

**Source-corroborated on 4 of the 7**, at the line:

- `cobol` — `capability.cob:324` `inc-find-hash` compares the 33-byte wire key and returns the value
  offset. No recomputation anywhere on that path.
- `asm-arm64` — `dispatch.s:8148` `included_find_by_key`: `memeq` on the key bytes. `asm-x86_64` and
  `riscv64` are the same lineage and measure identically.
- `pd` — `ecodec.c:381` `included_find`: `memcmp(r.p + r.pos, key33, 33)`.
- `sql` — `peer.c:825` `project_included` inserts `project_peer(key, …)`, i.e. it **stores the
  impostor's public key in the peer table under the victim's hash**, and every ladder query
  downstream resolves it.

`wasm-wat` is wire-measured only.

**Two things worth routing with it.**

- **The 32 refusing peers answer `400 non_canonical_ecf`, not the `400 hash_mismatch` `0.8.2.23`
  pins at the decode boundary.** They are conformant on the property and divergent on the code —
  one string standing in for several canonicalization branches, which is the shape that made a
  `csharp` refusal read as a peer defect once already. This is `F60`'s unspecified-code vocabulary
  with a new instance.
- **`datalog`, `node-red`, `rust-wasm`, `rust-wasm-wasmtime` and `smalltalk` refuse by transport drop.** That is a refusal and it is not
  a disposition — the §6.3 *"rejection returns a STATUS, not silence"* class this repo ratified
  cohort-wide in August, recurring on a path that class never covered. Ours to fix.

**The capability arm** (the real token filed under a bogus address, `capability` pointing there)
reproduces on **`cobol` alone**. The other six vulnerable peers refuse it — and that refusal is a
**miss**, not a check: the address holds nothing, so a key-trusting peer misses exactly as a
key-discarding one does. Reading those `403`s as mechanism (b) would be a claim the measurement
cannot support, and the report says so per peer.

---

## 4. The unmatchable grant exclude is honoured as "no exclude" on 20 peers — and 13 more raise from a `canonicalize` that is not total

`0.8.2.21` rules that an unmatchable **grant** exclude is fail-**closed** — *"carves out nothing"*
means the grant is silently wider than its author wrote, so the arm MUST DENY — while the same
sentinel in a **caller** exclude carves out nothing and the request proceeds. The asymmetry is the
whole of the revision. Both directions were driven.

**Grant side** (`E1`): mint a narrowed capability whose `resources.exclude` is `../nope` — which
§5.4's `canonicalize` maps to `NEVER_MATCH` — then use it.

| answer | reading | peers |
|---|---|---:|
| `200` | minted **and honoured**; the exclude carved out nothing | **20** |
| `500 internal_error` | the peer **raised** (see below) | 13 |
| `400 request_error` / `400 invalid_path` | refused on use, not the `403` §5.2 pins | 5 |
| VOID (the mint-and-use control failed) | — | 7 |

**0 of 45 answer the ruled `403`.**

**Caller side** (`A5`): 27 peers proceed correctly; 5 refuse the malformed path at **admission**
(`csharp` `node-red` `typescript` `oz` `rexx`), which is not a defect and is graded as conforming —
`0.8.2.20`'s own comment says the diagnostic it removed *"belongs at admission (§6.5), which has a
caller to answer."* What the rule forbids is a raise from inside the matcher, and that is what the
remaining 13 do.

**The 13 are one shape and it is the pre-`0.8.2.20` text, generated identically into thirteen
languages** — `ada common-lisp crystal dart elixir haskell java kotlin ocaml php prolog ruby tcl`.
Read at the line in three:

```java
static String canonicalize(String localPeer, String path) {                 // java
    if (startsWith("./", path) || startsWith("../", path)) {
        throw new IllegalArgumentException("canonicalize: reserved directory-relative path");
```
```ocaml
let canonicalize ~local_peer (path : string) : string =                     (* ocaml *)
  if starts_with ~prefix:"./" path || starts_with ~prefix:"../" path then
    invalid_arg "canonicalize: reserved directory-relative path";
```
```ruby
def canonicalize(local_peer, path)                                          # ruby
  if path.start_with?("./") || path.start_with?("../")
    raise ProtocolError, "canonicalize: reserved directory-relative path"
```

Identical strings, three languages — a generated shape, not three independent decisions.

**This is evidence FOR `0.8.2.20`'s totality ruling, and it is the kind that was missing.** The
revision's stated reason is that the two `error(...)` returns were *"a declared failure mode that
every caller structurally discards"*. Measured, it is worse than discarded: on 13 of 45 peers the
raise escapes the matcher, is caught by the peer's resilience frame, and any caller who puts `../x`
in a resource exclude gets a `500` — a remotely reachable internal error on ordinary wire input,
reachable from two different call sites in the same run. **The peers implement the text that was
withdrawn, and they implement it exactly.**

---

## 5. What this did NOT drive

Printed in every report, because a count with no stated surface grows while its coverage does not.

- **§6.8's handler/caller authority intersection for derived paths (`0.8.2.22`).** The discovery
  floor grants whole subtrees, so it cannot produce a *partially* covered listing and there is
  nothing for `filter_listing` to filter. Driving it needs an authored grant, and using one would
  make the result about a synthetic configuration rather than about the peers as they ship. This is
  the sharpest remaining hole and it is `F73`'s `L2 0/28` region.
- **§6.3's `handler_pattern` owner frame, REQUIRED and fail-closed (`0.8.2.23`, `K4`/`K5`).** A core
  peer has one path-resource handler, so owner and runner coincide at every reachable call site and
  the wire cannot separate the readings. Arch's own §3 note says the arm needs a **split**
  capability; that is an extension-tier harness, not a core probe.
- **§6.8 outbound sub-dispatch authorization, PD-2 (`0.8.2.17`/`.18`/`.19`).** Needs a second peer;
  that is `validate-peer -reference-peer`, not a probe.
- **`effective_targets` returning RAW survivors (`0.8.2.21`).** Consumed internally, echoed in no
  response field. Unobservable from the wire.
- **§5.2a's chain-granter, per-link-signer and grantee rows.** Need a delegated chain this probe
  does not build. The author and capability rows are driven.
- **`turbowarp`** launches its peer through a WS bridge with its grants in the Scratch project
  rather than behind a CLI flag, so the one-flag edit that keeps every other peer comparable is not
  available. Not measured, and named rather than dropped.
- **`rust-wasm` and `rust-wasm-wasmtime` are measured under `NOBUILD=1`, and that is a choice worth
  stating.** Their cargo build reaches `index.crates.io`, which `--network=none` correctly refuses,
  so they are driven from their committed artifact exactly as `run-cohort-census.sh` drives them.
  The standing stale-artifact rule was honoured rather than waved: `find <peer>/src ../rust/src
  -newer out/peer.wasm -name '*.rs'` returns **0** on both, and `rust-wasm-wasmtime`'s `.cwasm` sits
  beside its `.wasm` at the same timestamp — the AOT artifact that made a parent fix read as
  un-propagated once before. `NOBUILD` is forwarded **generally** by the runner rather than
  special-cased for these two, so the decision is visible at the call site instead of buried in the
  measurement tooling.

---

## 6. What is owed, and to whom

**Arch, and only the first is a ruling:**

1. **Withdraw `J4` clause 2** (§1). One sentence out; clause 1 stands.
2. **Rule the decode-boundary code.** 32 peers refuse a mis-keyed envelope with
   `400 non_canonical_ecf` where `0.8.2.23` pins `400 hash_mismatch`. Is the pinned code a MUST at
   that boundary, or is any 400 conformant there? Folds into `F60`.
3. **Nothing is asked about §2 or §4** — the ladder and the sentinel are landed text and the cohort
   simply has not implemented them. They are ours.

**Ours, in the order the measurement puts them.** *(Dispositions added 2026-09-14; the list
itself is as written.)*

1. ✅ **`K1` resolution integrity on the 7** — `asm-arm64` `asm-x86_64` `cobol` `pd` `riscv64` `sql`
   `wasm-wat`. A security defect, one shape (`included_find_by_key` and its four siblings), and the
   fix is the §3.1 bind at the point the map is read or the ingest-time equivalent.
   **CLOSED. One shape in seven substrates, `0 of 740` severities moved on every one.**
2. ✅ **The 5 transport-drop refusals** — `datalog` `node-red` `rust-wasm` `rust-wasm-wasmtime` `smalltalk`.
   **CLOSED, and it moved a published number:** `ingest_rejects_unrepresentable_expiry`
   WARN → PASS on all five. **Three of the five are thin seams over a parent that was already
   fixed — a read-loop fix is not inherited by a peer that REIMPLEMENTS the read loop, and
   depending on the crate that holds it looks exactly like inheriting it.**
3. **The §3.3 ladder** — 45 peers, four rows, one authored shape propagated. `nim`'s partial
   implementation is the reference for the `>1` arm. **UNCHANGED and still owed** — see the
   sequencing note, which has not moved.
4. ✅ **`canonicalize` totality** — 13 peers, a three-line edit each, and the 5 admission-refusing
   peers are already conformant and must not be swept with them.
   **CLOSED on all 13, and the 5 were correctly left alone.**
5. ⚠ **The `0.8.2.21` grant-exclude arm** — 20 peers silently widen a grant.
   **CLOSED on 39 of 44 measurable. FOUR are deliberately NOT swept** — `asm-arm64`
   `asm-x86_64` `riscv64` `wasm-wat` do not read a grant exclude at dispatch **at all** (§7),
   so adding a sentinel guard to a dimension that is never consulted would be papering; the
   repair they need is the dimension. **Two are unmeasurable** — `forth` and `smalltalk` mint
   a capability and then deny it on use, which is its own question.
6. **Decide what to do about `turbowarp`** — the one peer this instrument cannot reach.
   **Partly answered by accident:** it is reachable through its own unmodified harness, so §7's
   `E2` measured it (`403`, conforming). The A and B families remain out of reach, because those
   need the one-flag edit and its grants live in a Scratch project rather than behind a flag.
7. ⛔ **NEW — the grant-exclude dimension on the four** (§7). Larger than item 5 and ahead of it
   in sequence.

**Sequencing:** none of this gates the current pin, and the re-pin still waits on `go`'s vectors.
The ladder and the sentinel are the two items where implementing before the vectors exist would
mean writing 43 versions of a rule nothing can check — which is exactly the position this
measurement was taken to get out of, and the reason `F73`'s cell table wants adopting before the
next revision rather than after it.

**That argument held for the ladder and it did NOT hold for the sentinel, which is worth
recording rather than smoothing over.** The sentinel was swept anyway because `arc-probe`'s
`A5`/`E1` rows *are* a gate on it — our own instrument, graded per peer, with controls — and
because 13 peers were answering a remotely reachable `500` on ordinary wire input, which is not
a thing to hold behind anyone's vectors. The ladder has no such instrument row and no such
acute failure, so it stays sequenced. **The test is not "are there vectors", it is "is there
something that can tell me I got it wrong".**

---

## 7. ⛔ The control §4 never had: four peers do not read a grant `exclude` at dispatch at all

**Added 2026-09-14, after the sweep.** This is the finding the arc's own instrument was
structurally unable to make, and it was found by trying to close §4 on the peers that
report it `VOID`.

### 7a. Why §4's `E1` cannot see it

`E1` mints a capability whose `resources.exclude` is `../nope` — an **unmatchable** value.
Two completely different peers answer it identically:

| peer reads grant excludes | what it does with `../nope` | answer |
|---|---|---|
| yes | canonicalizes it, matches nothing, carves out nothing | `200` |
| **no** | never looks at the field | `200` |

So every `200` in §4's grant table is ambiguous between *0.8.2.21's defect* and *a strictly
larger one*. The report said `no — minted AND honoured; the exclude carved out nothing`,
and on four peers the second half of that sentence was not true.

**The general form, and it is the reusable half: a probe whose subject is an UNMATCHABLE
value cannot distinguish "the value was read and carved nothing" from "the field was never
read." Every sentinel-shaped check needs a matchable-value control beside it.**

### 7b. The control, and the measurement

`E2` mints a capability whose `resources.exclude` is **`qA` — the very target the request
then asks for**. Any peer that consults grant excludes at all must refuse it. `E0` (the
same mint and the same use, minus the exclude) is the positive control and is green on
every row counted.

| answer | reading | peers |
|---|---|---:|
| `403 capability_denied` | the grant exclude denied its own target | **40** |
| **`200`** | **the exclude dimension is not read on the dispatch path** | **4 — `asm-arm64` `asm-x86_64` `riscv64` `wasm-wat`** |
| VOID (`E0` control failed) | — | 2 — `forth` `smalltalk` |

On those four, **a capability's `exclude` has no effect at dispatch on any dimension** —
not `resources`, not `operations`, not `handlers`, not `peers`. An attenuated capability is
honoured as if it were not attenuated.

**Source-corroborated after the measurement, not before it:** `grant_scope_ok`
(`asm-x86_64` `src/dispatch.s:7734` onward) tests `include` for all four dimensions and the
string `exclude` does not occur in it; `ka_exclude` is referenced only from the
chain-attenuation path, which is a different surface. The read was a hypothesis and the
`200` is the finding — `go`, `java` and `sql` were driven as controls first.

### 7c. Two things this says beyond the four peers

- **They are exactly the four HAND-AUTHORED peers.** That is this repo's own standing rule
  paying out again: when a cohort defect is about *effort*, its distribution follows
  authoring cost rather than language family. The exclude arm is the laborious half of
  §5.2 to write by hand, so it is the half that was deferred — in assembly and in WAT
  alike, exactly as the §5.5 chain walk was.
- **`forth` and `smalltalk` are VOID for a PEER reason, not a floor reason**, and that is
  worth separating. Both mint a narrowed capability successfully (`200`) and then deny it
  on use (`403`) — including the `E0` control, which carries no exclude at all. A peer that
  issues a capability it will not honour is its own question and it is not this one.

### 7d. What made it measurable, and why that is a second setup rather than a flag

Seven peers report family E `VOID` under `run.sh` because they refuse
`system/capability:request` under the §6.9a discovery floor, so nothing can be minted to
test with. `run.sh` removes `--debug-open-grants` for a reason that is about the **caller's**
grant — under the degenerate `default → *` policy the F68 composition has nothing to bypass
— and that reasoning **does not transfer to family E**, whose subject is a capability the
probe *mints during the run* and whose value under test is that minted token's own
`resources.exclude`. Widening the caller's floor decides only whether the mint is
permitted; it cannot make a narrowed cap's exclude look enforced when it is not, and `E0`
rides along to prove the arm is live.

`tools/arc-probe/run-mint-floor.sh` encodes that, with the reasoning in its header rather
than in someone's memory, and says in the same place that **only the E family may be read
out of it** — the A and B rows in those reports are measured under open grants and are not
comparable with `run.sh`'s. Five of the seven become measurable; the other two are §7c.

---
