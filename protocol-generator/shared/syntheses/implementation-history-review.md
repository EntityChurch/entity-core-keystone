# Implementation-History Review — the fourth attack dimension (by paradigm)

**Date:** 2026-07-18 · **Companion to** [`red-team-critical-review.md`](red-team-critical-review.md)
and [`research/PROJECT-RETROSPECTIVE.md`](../../../research/PROJECT-RETROSPECTIVE.md) (both unmodified). · **Method:** adversarial.

## 0. Why this pass exists

The red-team's first three passes attacked core by **reading the spec**. This pass attacks from the other
direction the reviewer flagged: **what did the 45 implementations actually reveal** — where did core look
right on paper but a real peer hit friction, ambiguity, or bad ergonomics? The archetype is A-PL-006 (the
401-vs-403 split reads clean in prose; Prolog's mono-valued failure showed it needs a second channel). That
class of signal is structurally invisible to spec-reading and only the build surfaces it.

**Corpus:** 427 distinct `A-*` ambiguity-log entries across 43 per-language `SPEC-AMBIGUITY-LOG.md` files,
mined in four paradigm clusters against `SUBSTRATE-TAKEAWAYS.md` and the F1–F46 findings log.

**The filter (the whole method).** Each `A-*` entry is sorted:
- **(S) substrate-idiosyncratic** — the substrate being hard (no bignum / no CBOR lib / fixed-width ints /
  concurrency model / no sockets / crypto gaps). *Not* a core signal.
- **(C) core-design signal** — reveals something about the CORE PROTOCOL: an ambiguity two impls could read
  differently, underspecified/misleading prose, bad ergonomics core forces, or "looked right on paper but
  broke in practice."
- Every (C) is checked against F1–F46: **captured** or **UNCAPTURED**. The uncaptured ones are the point.

The governing test (the reviewer's): does core *force* bad/risky design, or was it just the substrate?

## 1. Headline verdict

**Re-checking all 427 entries with adversarial eyes strongly CONFIRMS core is paradigm-neutral**, exactly as
`SUBSTRATE-TAKEAWAYS` claimed — but the pass was not vacuous: it surfaced **a coherent new pattern of
concurrency-contract under-specification** (two genuinely uncaptured MUSTs) plus a handful of smaller
uncaptured prose/coverage gaps, and it *corrected two agent-flagged "uncaptured" items that are actually
already fixed in the spec* (the Lean §5.10 findings — landed as v7.76). Net:

- **Overwhelming majority of the 427 entries are (S)** — substrate-idiosyncratic. Across decimal (COBOL,
  Rexx), fixed-width (C, Zig, Nim, Fortran, Odin), three ISAs (x86-64, ARM64, RISC-V), WASM, pure-OO /
  prototype / live-image / event-loop / dataflow, and untyped-string scripting, the wire contract + dispatch
  logic + verify ladder ported everywhere. The substrate decided *how much seam*, never *whether it fit*.
- **Every (C) that reached an F-finding is a corroboration of a known item** (F7, F12, F13, F20, F30, F32,
  F36, F37, F38, F39, F40, F41, F44, F45; arch errata E1/A2). No landed finding is a new *axis*.
- **The declarative/logic/proof cluster is structurally the only one that taught us about the protocol** —
  it *inspects* the authority interior the imperative peers only *compute* (SQL→F40, Datalog→F41,
  Prolog→A-PL-006, Lean→the §5.10 v7.76 amendments).
- **The genuinely-new yield is small, real, and concentrated in the concurrency contracts** (§1.6, §4.8) —
  see §3.

This is a strong core-vindication result *earned by re-checking the raw record*, not assumed.

## 2. How each paradigm fared

| Cluster | Peers | Fared | (C) yield |
|---|---|---|---|
| **Imperative / ISA / scripting** | C, C++, Ada, COBOL, Fortran, Odin, Nim, Zig, x86-64, ARM64, RISC-V, WAT, Tcl, Rexx | Substrate-heavy; ISA ports ~free; Tcl/Rexx *deliberate* EIAS/decimal precision probes came back **clean** (core-vindication) | corroborations (F7/F20/F30/F32/F36/F45) + **1 new: A-C-009** |
| **Object-oriented** | Java, C#, Kotlin, Swift, Ruby, Python, Dart, Crystal, PHP, Smalltalk, Io | New spec signal only from the *early* peers (C#/Java/Swift), all on the 4 known wire axes; pure-OO/prototype/dynamic/event-loop paradigms → **zero** new spec findings | corroborations (F11/12/13/20/24/36/37/45) + **1 new: A-IO-002** + 1 unnumbered (A-JAVA-010) |
| **Functional / logic / query / array** | Haskell, OCaml, Common Lisp, Forth, Prolog, Datalog, SQL, Oz, Lean, APL, Julia | **The richest cluster** — the query/logic/proof substrates probe the authority interior; array/decimal/dataflow (APL/Julia/Forth/Oz) explicitly dry | F40, F41, A-PL-006, **Lean→§5.10 v7.76** + new prose/coverage gaps (§3) |
| **Concurrency / visual / web** | Elixir, Go, TS, Rust ×3, Pure Data, Node-RED, TurboWarp | Dry by composition (native/threaded + shared-lineage wasm); **wasm interiors compiled byte-identical** — 100% of friction in the transport seam (clean negative result); all novel findings from Pure Data, all captured | corroborations only (F20/33/36/38/39/41/44); **0 uncaptured** |

**Cross-cutting "how they fared" facts worth keeping:**
- **The wasm peers are a strong negative result** for "does compiling to a sandbox stress the protocol?" —
  the interior cross-compiled *unmodified*; every friction was the transport ABI (framing, socket-accept
  model, JIT-as-crypto-execution-mode). Zero core cost.
- **ISA ports (arm64/riscv64) add ~zero core signal** — riscv was 0-FAIL on the first parallel run. Confirms
  "discovery yield is substrate-bound, not idiom-bound."
- **Tcl/Rexx are deliberate core-precision probes that PASSED** — they asked "is any wire field's
  byte-vs-text / int-vs-float kind under-specified?" and answered *no, the spec is tight.* A positive
  vindication, not an absence of effort.
- **The no-GC / manual-memory sub-cluster (C, Zig, Odin, Fortran, asm) surfaces a §4.8 class the GC cohort
  structurally cannot** — because the GC runtime owns object lifetime, GC'd peers never hit the refcount race
  (→ A-C-009, §3).

## 3. The genuinely-uncaptured core signals (the yield)

Ranked. Each passed the governing test (core under-specification, not substrate hardness) and is **absent
from F1–F46** (verified by grep over the whole `research/stewardship/` tree, not from memory).

### U1 — The concurrency-contract under-specification pattern (the headline) — MED
Two independent peers, two different core sections, **the same shape**: a core safety contract with an
**unstated MUST that the runtime provides for free on the "easy" substrates but is real and load-bearing on
the hard ones.** This is precisely the class spec-reading structurally cannot see (the reader is on an easy
substrate in their head).

- **A-C-009 (C peer) — §4.8 store-safety never states atomic/lock-guarded refcounts.** A plain-`int`
  refcount on shared entities passes S2/S3 smoke-green, then use-after-frees under the live §4.8 concurrency
  gate (22 of 31 run-1 FAILs cascaded from the one crash). GC'd peers never hit it (the runtime owns
  lifetime); C++ gets it free (atomic `shared_ptr` control block) — *confirming it is a no-GC-specific
  surface*. The peer escalated ⚑ARCH-BOUND and recommended a §4.8 note: *"refcounted shared entities MUST
  use atomic (or lock-guarded) refcounts on a multi-threaded peer."* **UNCAPTURED.**
- **A-IO-002 (Io peer) — §1.6 never states frame-write atomicity under concurrent dispatch.** Log: *"the
  spec assumes frames are contiguous on the wire but never says 'a frame MUST be written atomically with
  respect to concurrent dispatch' … single-threaded event-loop peers get it for free only if their write
  primitive never yields (Tcl's doesn't; Io's does)."* Invisible on atomic-write substrates; corrupts the
  wire on a yielding write primitive. Candidate one-liner: *"concurrent dispatch MUST NOT interleave bytes
  of distinct frames."* **UNCAPTURED.**

**Disposition:** one HANDOFF-TO-ARCH proposing two one-line normative notes (§4.8 atomic-refcount, §1.6
frame-write atomicity), framed as "the concurrency-contract MUSTs that are free on GC/atomic-write substrates
and load-bearing elsewhere." Neither is a wire-format change; both are exactly the "silently-violable
MUST-prose" family the project already knows how to close.

### U2 — Address hex-case is unspecified; lowercase is a de-facto Go-ism (A-CL-009) — MED, and it's the RT-3 receipt
Common Lisp: *"address-space tree-path hex-case is unspecified in V7 — lowercase is de-facto from the
reference impl's `hex.EncodeToString` default. Case-sensitive keys → a latent interop trap for any peer
whose stdlib hex defaults to uppercase (CL, some Pascal/Ada/SQL hex builtins)."* A peer that emits uppercase
hex passes self-loopback and fails only against the oracle. **UNCAPTURED** (cohort-known — Julia lists it as
a settled trap — but no F-number, no handoff). **This is the concrete receipt RT-3 asked for:** a Go
*representation choice* that became de-facto normative without ever being stated in the spec. Modest blast
radius, but exactly the monoculture mechanism RT-3 described, caught in the wild. **Disposition:** a one-line
normative statement ("content-hash hex in tree paths MUST be lowercase") + folds into the RT-3 residual.

### U3 — `format_code=128` construct-vs-receive asymmetry (A-OC-004 / A-CL-007 / A-PL-011) — LOW–MED, 3× convergent
Three independent peers (OCaml, Common Lisp, Prolog) escalated the same thing: the forward-compat
`format_code=128` is *construct-emitted but receive-rejected*, and that asymmetry "is stated nowhere — a
spec-first reader deriving the codec from §4.3/§4.7 alone would plausibly reject 128 on both sides and then
fail `content_hash.4`." The *behavior* was gated (F16 decode-and-validate), but the requested clarifying
**sentence** never landed. **UNCAPTURED as a prose gap.** Notable for the 3× independent convergence with
zero capture. **Disposition:** one clarifying sentence in §4.3/§4.7.

### U4 — `unregister` has no type-ownership/refcount model (C# A-012 / OCaml A-OC-009) — LOW, convergent
Two peers: `system/handler:unregister` leaves the handler's `system/type/*` entities in the tree, but types
may be shared across handlers and the spec pins no ownership/refcount model, so blind removal is unsafe and
"leave in place" is the only safe default. **UNCAPTURED**, minor, informational — a candidate spec addition,
not a defect. (Thematically the *same* refcount-ownership gap as A-C-009, one layer up.)

### Minor coverage/altitude gaps (record, don't over-weight)
- **A-JAVA-010 — §1.1 scalar entity `data`.** Entity `data` is any ECF value, not necessarily a map; a
  map-only model passes S2/S3 then silent-500s on the first scalar-`data` entity. *Captured in prose* (folded
  v7.75) but **no F-number**, and the recommended accept-path vector (a stored scalar-`data` entity) is
  unverified — the vacuous-green shape. Confirm the vector exists or file it.
- **A-ZIG-005 / A-ASM-016** — peer_id corpus doesn't discriminate the (now-resolved) §7.4-vs-§1.5
  construction; f16-subnormal decode is an untested (fail-safe) reject-gap. Minor corpus coverage.
- **A-ADA-011** — EXECUTE `params` is an *entity* wire-form, not a bare map; multiple peers 401'd reading the
  handshake at "params has a nonce field" altitude. Not escalated; a candidate GUIDE altitude note.

## 4. Corrections — agent-flagged "uncaptured" that are actually captured (honesty)

Verifying the cluster reports against the pinned spec caught **two over-claims**, the same discipline that
caught F37 last pass:

- **A-LEAN-1 (time determinism) — CAPTURED, landed as v7.76.** The Lean proof showed §5.5 sampling `now()`
  per-link contradicts §5.10 cross-peer determinism, and *forces* time to a single entry-sampled Layer-1
  input. The pinned §5.10 (§2876/§2878) now says exactly that: *"TTL evaluated against a single evaluation
  timestamp `t` sampled once per verdict … per-link re-sampling of `now()` is non-conformant."* The proof
  almost certainly **drove** the v7.76 amendment. Not a gap — a keystone→arch win on the highest-signal
  channel.
- **A-LEAN-2 (revocation determinism) — CAPTURED, landed as v7.76.** The proof asked: revocation is Layer-2,
  OR determinism is "relative to a tree snapshot." §5.10 (§2880) now picks the latter explicitly: *"Revocation
  as a convergent Layer-1 input … the cross-peer determinism MUST holds given the same Layer 1 state —
  including the same set of *observed* revocation entries."* Captured; pairs with RT-9 (the posture note).

Lesson reinforced: **re-derive against the pinned snapshot before calling anything uncaptured.** Two of the
"top uncaptured" candidates this pass were already fixed; F37 was already filed last pass. The signal-to-gap
ratio of the raw logs is lower than a first read suggests.

## 5. Confirmed patterns (what the whole pass says about core)

1. **Core is paradigm-neutral — re-verified against the raw 427, not just asserted.** Every wire-touching
   axis (integer/float/string/byte/crypto) is saturated and produces only corroboration; every off-wire axis
   (object model, concurrency style, error idiom, packaging) produces *zero* spec findings. The two places
   core genuinely strains a substrate (bignum-free integer width, thread-local-free concurrency) are small
   and mapped.
2. **The authority verdict is "easy to fold/implement wrong" — a real, recurring core-ergonomics signal.**
   From under-specification (A-GO-006 and the F20 cohort: flat ALLOW/DENY pseudocode is operationally a
   4-way verdict) and from fold-masking (A-PD-010: a folded verify→resolve→permission hid a dead-ALLOW
   path behind passing DENY probes). Both point at the same property — the decision surface is a monotone
   deductive system whose fail-closed default and within-grant conjunction are silently-violable MUST-prose.
   → this is **F41** (authority-as-derivation) + **RT-2/W6** (the §PR-8 foot-gun + mint-time absolutization).
   The implementation record is the *evidence base* for those two.
3. **Vacuous-green recurs on the security surface** (A-PD-014 chain-caveats passing until the type store
   resolves; A-CPP-012 needing a real K-of-N accept vector; tag_reject rejecting on trailing-data). → **F44
   is still OPEN** on exactly this; the implementation record shows it is not hypothetical.
4. **The declarative/logic/proof substrates are the protocol's microscope.** They are the only peers that
   *inspect* the authority interior rather than compute it, and they are where every genuine protocol finding
   (F40/F41/§5.10-via-Lean/A-PL-006) came from. If any future spec-discovery bet exists, it is here —
   consistent with the retrospective, and re-confirmed.
5. **Keep keystone-tooling/pipeline "findings" out of the core ledger.** Corpus-dir skew, reported-total
   mismatches, snapshot lag, "does GUIDE-CONFORMANCE join the SHA-pinned snapshot," oracle-assumes-TCP —
   these indict the *apparatus/docs*, not the wire core, and must not inflate a core red-team.

## 6. Dispositions

- **New HANDOFF-TO-ARCH (U1):** two one-line normative notes — §4.8 atomic/lock-guarded refcount MUST for
  shared entities on multi-threaded peers; §1.6 frame-write atomicity ("concurrent dispatch MUST NOT
  interleave bytes of distinct frames"). Framed as the concurrency-contract-free-on-easy-substrates pattern.
- **Fold U2 into the RT-3 residual:** state hex-case normatively (lowercase); it's the concrete Go-ism
  receipt.
- **U3 (format_code=128 sentence), U4 (unregister ownership), A-JAVA-010 (scalar-data vector), A-ZIG-005 /
  A-ASM-016 / A-ADA-011:** batch as low-priority prose/coverage notes in the aggregate arch digest.
- **Promote U1/U2 into the red-team doc** as RT-13/RT-14 (done).
- **Credit the Lean channel:** A-LEAN-1/2 → §5.10 v7.76 is a proof-vector success; record it in the
  retrospective's keystone→arch-loop evidence, not as a gap.

## 7. Bottom line

The fourth attack dimension did its job: it **re-confirmed core paradigm-neutrality from the raw record**
(not the synthesis), surfaced **one coherent new class of finding** (concurrency-contract under-specification
— §1.6/§4.8 unstated MUSTs invisible on easy substrates), produced **the concrete Go-ism receipt RT-3
wanted** (hex-case), and — importantly — **corrected two over-claims** (the Lean §5.10 findings are already
landed as v7.76). The implementation dimension is where the real bugs came from (it caught F37 before
spec-reading re-found it; it caught the §5.10 tensions and got them fixed), and it remains the sharpest lens
— but on the *current* wire surface its well, too, is now nearly dry: the yield of re-mining 427 entries is
two small unstated-MUST notes and a hex-case sentence. That convergence — spec-reading and implementation-
mining both bottoming out at the same small residue — is itself the strongest evidence the core is close to
done.

---

*Companion to the red-team review and the retrospective (both unmodified). Spec citations to
`spec-data/v0.8.0` (read-only). No sibling-repo writes.*
