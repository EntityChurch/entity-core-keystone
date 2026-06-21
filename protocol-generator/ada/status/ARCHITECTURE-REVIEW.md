# Architecture Review — entity-core-protocol-ada (peer #10, 10th byte-compatible core impl)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data
**v7.75** (the current-state surface verified directly at S1); codec corpus v0.8.0 (byte-stable
v7.71→v7.75). · **Audience:** architecture (spec-tightness feedback) + operators (publishing
decision). · **Status:** peer #10 at `validate-peer --profile core` PASS · **576 / 292P / 195W /
0F / 89skip** at the v7.75 cohort baseline oracle `b30a589` (`summary.failed == 0`);
origination-core 3/3; §9.5 53-type floor 53/53; concurrency 5/5 (genuinely concurrent);
resource_bounds ACTIVE in core (413/400/WARN).

This review follows the format/depth of the Java peer #7 and Common-Lisp peer #5
`ARCHITECTURE-REVIEW.md` (themselves extensions of the three-peer milestone review), carried to
**the cohort's safety-critical / strong-typing member** — the two most-distant idiom axes left in
the batch. Part A is the idiom-fidelity + spec-refinement retrospective; Part B is the
publishing-options decision surface; Part C is the one-paragraph arch summary; Part D is the
consolidated findings ledger for the arch escalation bundle.

---

## 0. The thesis peer #10 was chosen to test

The convergence thesis (three-peer review, reinforced through Zig #4 / CL #5 / Java #7): *if the
spec is tight, independently-derived peers converge on the same conformance fixed point with no
wire divergence; the idiom seams diverge cleanly by profile at impl locality; and a spec-first
peer surfaces contradictions the port-peers inherited-correctly-but-never-flagged.* Nine prior
peers had spanned managed-GC → no-GC systems → homoiconic multiple-dispatch → mainstream static-OO
idioms, and the spec-discovery well had gone **dry** — eight independent spec-first peers found no
new defect on the v7.75 surface.

Ada is the cohort's **safety-critical / strong-typing** member and brings the **two most-distant
idiom axes remaining**, neither exercised by any prior peer:

- **Concurrency = tasks + protected objects + rendezvous** — a *first-class, in-language*
  concurrency model. The cohort had used BEAM actors, STM, GHC green threads, raw OS threads, JVM
  virtual threads, goroutines, and cooperative async — but **no peer had a protected-object /
  rendezvous (monitor) model**. The §4.8 data-race-safe store maps *naturally* onto a **protected
  object**: language-enforced mutual exclusion, no lock to forget, no map to race. This is the
  centerpiece.
- **Design-by-contract = Pre/Post/Type_Invariant/Predicate aspects** (Ada 2012+),
  compiler/runtime-checked. The static-rigor analogue of Zig's error sets and Java's checked
  exceptions, via a mechanism no prior peer had.

The open question was therefore not "does a distant idiom diverge on the wire?" (the well is dry —
that answer is *no* with high prior) but: **does a language whose concurrency safety is a
*structural language guarantee* express the §4.8/§7b floor more cleanly than the cohort's
library-or-discipline approaches — and does it converge on the same 0-FAIL fixed point?**

**Result: the thesis held, and the two distant axes paid off exactly where their selection
predicted — at impl locality, with zero wire-byte divergence, AND with the cleanest §4.8
store-safety story in the 11-peer cohort.** Every wire-touching decision converged: byte-identical
codec (69/69, first run), byte-identical 53-type registry (53/53), the §1.5 peer_id construction.
The tasking + protected-object + design-by-contract seams diverged cleanly at impl locality and
**changed no wire byte.** No NEW spec defect surfaced (the dry well held); the Ada-distinct entries
are local idiom decisions and corroborations, plus one oracle-provenance correction (A-ADA-013).

---

## PART A — Architecture review

### A.1 Did the Ada idiom pay off? (the distant seams, scored)

The bet of generating peer #10 was that the safety-critical / strong-typing idiom — with its two
genuinely-new axes — would *express the protocol idiomatically* and, where it has a structural
language guarantee no prior peer had (protected objects, contract aspects, strong typing), produce
something the prior peers couldn't.

**(1) Tasks + protected objects + rendezvous (the concurrency seam) — PAID OFF as the cohort's
cleanest §4.8 story, and the *headline idiom win*.** This is the single biggest *structural*
divergence from the prior nine peers' concurrency models, and the place Ada's selection paid the
most. Every prior peer made the §4.8 data-race-safe store safe by **library or discipline**: a
mutex around a map (C#/Zig/CL/Java's `ConcurrentHashMap`), an actor mailbox (Elixir BEAM), an STM
transaction (Haskell `TVar`), an actor (Swift). Two of them *fell over* on store-safety under the
v7.75 §7b load gates — the Zig and CL store-race fall-overs that drove §4.8 into the floor — and
**the C sibling carries a live heap race (A-C-009)** that is real but masked at the current gate.
Ada expresses the §4.8 store as a **protected object**: the content store + tree index are the
protected data, reads are protected *functions*, writes are protected *procedures*, and
**mutual exclusion is enforced by the language** — there is *no lock to forget and no map to race*.
The payoff is concrete and **structural**: the store-race the C sibling lives with (A-C-009) and
the Zig/CL manual store-safety bugs are **structurally unrepresentable** here — they cannot be
written behind a protected object. And it is **genuinely concurrent, not serialized to buy safety**:
the §7b `t1_3_no_head_of_line` (no head-of-line blocking) and `t2_1_sustained_load` (10000 reqs, 0
dropped, ~8.5s) checks PASS *together*, which is the proof the dispatch is concurrent across
connections (a protected object serializes only the store critical sections, not the request
pipeline; reads are protected *functions* that allow concurrent readers). One **task per
connection** (A-ADA-006; GNAT maps tasks to OS threads, so a blocking read never stalls others —
sidestepping the §7b cooperative-pool-starvation trap *structurally*, not with a backpressure
knob), and a child task spawned ONLY for the §6.11 reentry op (avoiding the per-request task storm
that exhausted earlier designs under the load gates). **Verdict:** the protected-object seam is the
**highest-value seam in the cohort on the §4.8 axis** — it is the only peer where store-race safety
is a *language guarantee* rather than a contract the implementer must keep, the cleanest §4.8 story
across all 11 peers, and it changed **zero wire bytes** while making the cohort's recurring
store-race bug class *unrepresentable*.

**(2) Design-by-contract — Pre/Post/Type_Invariant aspects (the rigor seam) — PAID OFF as fidelity,
no wire effect.** Ada's idiomatic error mechanism is the **exception** (the C#-family shape) —
*paired* with the distinctive Ada seam: **design-by-contract**. Pre/Post/Type_Invariant aspects
(Ada 2012+), enforced by the compiler/runtime under `-gnata`, guard the INTERNAL invariants — a
`Content_Hash` is exactly 32 bytes (`Type_Invariant`), a canonical buffer is well-formed (`Post` on
the encoder), a `Peer_Id` is a valid multihash. This is a compiler/runtime-checked rigor seam **no
prior peer exercised** — the static analogue of Zig's error sets and Java's checked exceptions, via
a different mechanism. The cohort invariant — *protocol status is a value, never carried by the
exception type across dispatch* — holds for the same reason it held everywhere: the dispatch brain
maps an exception subtype → status code *at the dispatcher boundary*
(`Authentication_Error`→401, `Authorization_Error`→403, `Chain_Depth_Exceeded_Error`→**400** per
§4.10(b), `Payload_Too_Large_Error`→413); the contract aspects guard *internal* invariants, never
cross the dispatch boundary as a status carrier. SPARK formal proof is out of scope for v0.1 (the
aspects are runtime guards, not discharged proofs). **Verdict:** the contract seam differs
structurally (compiler/runtime-checked invariants) yet produces no wire divergence — the
convergence thesis holding under the cohort's first design-by-contract idiom.

**(3) Strong typing — the discriminated-variant ECF value (the data-model seam) — PAID OFF as the
*pointed* A-JAVA-010 decision.** §1.1 entity `data` is an *arbitrary* ECF value — not necessarily a
map. A-JAVA-010 (the silent-500 trap): a map-only model passes S2/S3 green then 500s on the first
scalar-data entity at the live gate. Ada's strong, static typing makes this **especially**
load-bearing: a map-only `data` field is a type-level commitment the compiler *accepts* and only the
oracle catches. Ada modeled `data` as a **discriminated-record variant** over the full ECF value
space from the start (A-ADA-009), so the trap was dodged at S1 by construction rather than debugged
at S4. **Verdict:** strong typing made the cohort's highest-signal data-model finding a *type-level*
decision — the place a careless model would have been a compile-accepted, oracle-only-caught bug,
turned into a structural correctness property. No wire divergence; the codec's ECF value type *is*
this discriminated type.

**(4) The native codec + libsodium binding (the supply-chain/crypto seam) — PAID OFF as the
lightest supply-chain in the cohort, the no-unsigned-trap advantage, and a clean crypto binding.**
Hand-rolled canonical CBOR (the pattern every native peer hit) + Ed25519/SHA-256 over a thin
`Interfaces.C` libsodium binding. **One runtime dependency** (system libsodium), no Alire crates —
tying Zig/Elixir/Java for the lightest supply-chain. Two Ada-specific advantages over prior peers:
(a) **no unsigned trap** — Ada has native modular integer types (`Interfaces.Unsigned_64`), so the
full §3.2 0..2⁶⁴−1 head-form range is native, *unlike* the C# `ulong` / Java `long` no-native-
unsigned workaround (an outright Ada advantage, the cleanest int story with Zig/CL by a third
mechanism); and (b) **no peer_id point-extraction** — libsodium returns the *raw* 32-byte public key
directly from `crypto_sign_seed_keypair`, so the §1.5 identity-multihash peer_id needs no
point-encoding decode (contrast the JDK EdEC `(sign-bit, y-coordinate)` decode the Java peer flagged,
A-JAVA-007). **Verdict:** the crypto/supply-chain seam paid off as the lightest-dependency posture
plus two concrete idiom advantages, with the documented Ed448/SHA-384 agility gap (A-ADA-002, the
OCaml/Zig company — libsodium has neither) as the only non-floor deferral.

**Net: all four seams paid off** — the protected-object store as the cohort's cleanest §4.8 story
(the headline idiom win), design-by-contract as a fidelity win, strong typing as the *pointed*
A-JAVA-010 decision, and the native libsodium codec as the lightest-supply-chain + no-unsigned-trap
advantage. Critically, **none changed a wire byte** — the seams landed at impl locality, which is
the convergence thesis holding under the cohort's safety-critical / strong-typing idiom (the
discovery end of the spectrum was dry; the value here is the *structural* §4.8 story, not a new
defect).

### A.2 Spec-refinement value — what Ada contributed

The keystone's *end* is spec refinement. Peer #10's harvest is the **corroboration-heavy profile
the dry well predicted**: no genuinely-new spec defect, the standing multi-peer corroborations
re-confirmed, plus one oracle-provenance correction (A-ADA-013) that is the most actionable item for
the orchestrator.

**Top contribution — A-ADA-013 (the cohort oracle is `b30a589`, not `62044c5` — off-by-one-commit),
the actionable handoff item.** The cohort scorecard labels the v7.75 oracle `62044c5` and reports a
uniform **576·0F·89S**. But a *clean* `git archive 62044c5` build's `coreProfileCategories`
(`cmd/internal/validate/profile.go`) folds `concurrency` into core **but NOT `resource_bounds`**, so
`--profile core` auto-skips `resource_bounds` → the Ada peer scores **574·0F·90S**, not 576. The
real v7.75 oracle is the **immediate child `b30a589`** ("v7.75: pair §9.0 drift gate post-arch-fold;
resource_bounds enumerated"), which adds `catResourceBounds: true` to `coreProfileCategories`
(joining `catConcurrency: true`) — so `resource_bounds` runs ACTIVE under `--profile core` → the
real **576·0F·89S**. Verified read-only from oracle source AND corroborated by the live S4 re-run
(no oracle modification, peer NOT rebuilt). The binary gate (`Result: PASS`, 0 FAIL) holds across
`62044c5` (574), `62044c5` + standalone-`resource_bounds` (GREEN), and `b30a589` (576) — the only
correction was selecting the correct cohort baseline commit as the certification oracle.
**This independently confirms the cohort's `62044c5` label is off-by-one and the true 576 oracle is
`b30a589`** — a provenance correction the orchestrator should propagate to the scorecard at merge.
**Escalation: mainline/arch** (resolved-in-peer; the scorecard label needs the one-commit fix).

**Second contribution — A-ADA-011 (EXECUTE `params` is an ENTITY wire-form), the wire-altitude
caution.** The Go reference puts the `params` of an EXECUTE as the **wire form of an ENTITY**
(`Params: ecf.Encode(authEntity)` — `{type, data, content_hash}`), NOT a bare data map. So the §3.5
proof-of-possession signature target at authenticate is the authenticate ENTITY's content_hash, and
the responder MUST materialize `params` as an entity (read its `data` fields, recompute its hash) —
**`params.data.entity`, not `params.entity`**. A first cut that read `key_type`/`nonce`/`public_key`
off the params-map *top level* got `nonce-not-found → 401` against the Go client; materializing
params first (the `Params_Entity` helper) fixed it and matched the cohort. **This drove the biggest
S4 fix cluster.** It is **not a spec defect** (V7 §3.2 does say params is an entity-shaped value) —
but it is a SHARP, easy-to-miss wire detail that a peer author reading the §4.1 handshake at the
"params has a nonce field" altitude can get wrong, and it only shows up at the live oracle (Ada-to-
Ada loopback passes with *either* convention). **Escalation: none** — implementation note; the §3.x
text is adequate, the trap is altitude. Recorded as a peer-author caution.

**Third contribution — A-ADA-010 (GNAT float-validity over-strictness), a toolchain note.** GNAT's
validity model treats IEEE-754 special floats (NaN, ±Inf, -0.0) as "invalid data" the moment a value
is produced via `Ada.Unchecked_Conversion` (the bit-exact float encode/decode path), raising
`Constraint_Error` on perfectly canonical wire bytes (the `float.5/6/7` corpus vectors). Special
floats are legitimate normative ECF values, so blanket float-validity checking is incorrect for a
faithful codec — `-gnatVa` is deliberately NOT used project-wide; validity checks are scoped-
suppressed in the two codec bodies that traffic in raw float bits, with the design-by-contract
aspects staying LIVE under `-gnata`. This is the Ada analogue of "don't let a language's default
float handling corrupt canonical bytes" (the cbor2 float16 lesson, reached from the *other*
direction — Ada is *too strict* about floats, not too lossy). **Escalation: operator** — local
compiler-configuration decision; conformance-neutral (69/69 byte-identical with the suppression).

**Standing corroborations re-confirmed (the dry-well profile).** A-ADA-001 (§7.4-vs-§1.5 peer_id
construction — the §1.5 identity-multihash form, NOT the stale §7.4 SHA-256 form) is the **N-th
spec-first corroboration** (Zig/OCaml/CL/Java/Swift before it) — baked into the profile at S1 to
dodge the `401 identity_mismatch` debug burn. A-ADA-003 (hex-case lowercase — Ada hex builtins
default UPPERCASE, the A-CL-009 trap that the CL log *explicitly named Ada as carrying*) was pinned
proactively. A-ADA-008 (§5.2 401/403/401-unresolvable trichotomy) and A-ADA-007 (resource_bounds
413/400-not-403/WARN) held exactly as pre-resolved. **None is a new defect; each is the dry well
holding** — the Ada idiom axes (protected-object store, contract aspects) map cleanly onto V7, a
spec-tightness signal.

### A.3 Codec / crypto / transport / concurrency design retrospective

**Codec — convergent, native, zero-Alire-dep.** Hand-rolled canonical CBOR (the pattern every
native peer hit): shortest-float ladder (f16⊂f32⊂f64, narrowest bit-exact round-trip),
length-then-lex map-key sort on encoded key bytes, recursive major-type-6 tag rejection, definite
lengths. 69/69 byte-identical, first run, **0 codec fixes** — the codec was byte-green before the
peer existed, so the only S4 risk was field-shape *data* (caught per-type by the 53/53 registry
byte-diff). The Ada-distinctive contribution: the **no-unsigned-trap** advantage — native
`Interfaces.Unsigned_64` carries the full 0..2⁶⁴−1 head-form range with zero workaround (the
cleanest int story with Zig/CL, by a third mechanism — modular types vs Zig's `u64`+trap vs CL's
bignums), cleanly above the C# `ulong` reinterpret and OCaml's 63-bit trap (A-OC-001). Base58 + the
multicodec LEB128 varint are hand-rolled (neither in a stock Ada library). Wire bytes are
`Stream_Element_Array` / `Unsigned_8`, never `String` — dodging char-encoding ambiguity at the type
level.

**Crypto — libsodium via Interfaces.C, the raw-pubkey advantage, the documented agility gap.** The
§9.1 floor needs only Ed25519 + SHA-256, both from libsodium over a thin, well-typed
`pragma Import, Convention => C` binding (the cleanest, most-audited crypto source for Ada — a
binding, not a re-implementation). **Ada-specific advantage over Java's crypto wrinkle:** libsodium
returns the **raw 32-byte public key directly** from `crypto_sign_seed_keypair` — no point-encoding
extraction (contrast the JDK EdEC decode, A-JAVA-007), so the raw-pubkey the §1.5 identity-multihash
peer_id needs is in hand immediately. **The documented gap (A-ADA-002):** libsodium has **no Ed448**
and ships **SHA-256 + SHA-512 only (no SHA-384)** — the agility higher bar (Ed448 + SHA-384) is the
same gap OCaml (A-OC-002, C-ABI Ed448) and Zig (A-ZIG-002, flat gap) hit. The §9.1 core floor is
unaffected; when taken the agility overlay comes via the libentitycore_codec C-ABI surface or an
OpenSSL curve448 binding (`openssl-devel` is in the base image), NOT libsodium. The crypto ledger now
reads: Ada is in the OCaml/Zig company on the agility axis (libsodium gap) but with the *cleanest
floor crypto* (raw-pubkey direct, no point decode).

**Transport + concurrency — the protected-object store, the cohort's structural §4.8 win
(A-ADA-006).** The shape is the spec-forced cohort shape: 4-byte BE length-prefix + CBOR frame; one
reader **task** per connection demuxing `EXECUTE_RESPONSE` by `request_id` (N7); inbound EXECUTE
dispatched so it never blocks outbound (N6); a transport-agnostic dispatch brain. The *primitives*
are Ada's first-class **tasks + protected objects**: the §4.8 store + tree index are a **protected
object** (language-enforced mutual exclusion — reads are protected functions, writes are protected
procedures), the §6.11/N7 demux (`Demux_Table`) and the shared-stream write serialization
(`Write_Guard`) are themselves protected objects, and TCP_NODELAY is set on accepted sockets (the
Zig §7b finding). **One task per connection** (A-ADA-006-resolved; GNAT maps tasks to OS threads, so
a blocking socket read in one connection's task does NOT stall others — the §7b cooperative-pool-
starvation trap, the Swift `read()`-on-a-bounded-pool 60s stall, is sidestepped *structurally*); a
child task is spawned ONLY for the §6.11 reentry op, avoiding the per-request task storm. The result
is the **cleanest store-safety story in the cohort**: the Zig/CL store-race fall-overs and the C
sibling's live heap race (A-C-009) are structurally unrepresentable behind a protected object, AND
the design is genuinely concurrent (the no-head-of-line + sustained-10000-req gates PASS together,
proving it's not accidentally serialized — 5/5). **Retrospective verdict:** the protected-object
choice is the correct, idiomatic, and *structurally-safest* §4.8 expression in the cohort.

### A.4 Where peer #10 sits vs the cohort

| Axis | Java (#7) | CL (#5) | Zig (#4) | C (sibling) | **Ada (#10)** |
|---|---|---|---|---|---|
| Derivation | spec-first | spec-first | spec-first | spec-first | **spec-first** |
| Distance / role | mainstream OO bookend | program model | memory/control-flow | systems / C-ABI floor | **safety-critical / strong-typing** |
| Error model | checked exceptions | condition system | error unions | errno/return-code | **exceptions + design-by-contract** |
| Concurrency primitive | JVM virtual threads | `sb-thread` | `std.Thread` | OS threads (heap race A-C-009) | **tasks + PROTECTED OBJECTS + rendezvous** |
| §4.8 store safety | `ConcurrentHashMap` | mutex+map (race fixed) | mutex+map (race fixed) | live heap race (A-C-009) | **protected object — race STRUCTURALLY unrepresentable** |
| Int carrier | `BigInteger` (no native unsigned) | native bignums | native `u64`+trap | native `uint64_t` | **native `Unsigned_64` (no unsigned trap)** |
| Ed448 agility | NATIVE SunEC (raw-pubkey hand-rolled) | NATIVE pure-Lisp | native gap (A-ZIG-002) | (sibling) | **deferred — libsodium gap (A-ADA-002), raw-pubkey DIRECT** |
| Third-party runtime deps | ZERO (JDK-only) | ONE (ironclad) | ZERO (std-only) | libsodium | **ONE (system libsodium; no Alire crates)** |
| Core verdict | 0 FAIL | 0 FAIL | 0 FAIL | 0 FAIL | **0 FAIL** |
| Conformance split | 289P/195W (573, older split) | 284P/195W (568) | 291P/196W (576) | (sibling) | **292P/195W (576 @ b30a589)** |

**Position:** peer #10 is the cohort's **safety-critical / strong-typing member and the structural-
§4.8-safety bookend.** It confirms that the two most-distant idiom axes left in the batch — a
first-class tasking + protected-object + rendezvous concurrency model, and design-by-contract — still
converge on every wire-touching decision (codec 69/69, registry 53/53, §1.5 peer_id), spec-first,
with **zero wire-byte divergence**; and it delivers the **cleanest §4.8 store-safety story across all
11 peers** — the only peer where store-race safety is a *language guarantee* (a protected object),
making the cohort's recurring store-race bug class (Zig/CL fall-overs, the C sibling's live A-C-009)
*structurally unrepresentable*. It re-confirms the standing corroborations (peer-id A-ADA-001,
hex-case A-ADA-003, 401/403 A-ADA-008, resource_bounds A-ADA-007) and surfaces no NEW spec defect —
the dry well holding, as the honest S1 framing predicted. Its most actionable harvest is the
oracle-provenance correction **A-ADA-013** (the cohort's `62044c5` label is off-by-one; the true
v7.75 oracle is `b30a589`, which folds `resource_bounds` into core → the real 576·0F·89S).

---

## PART B — Publishing options (operator-decides)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface; the
recommendation is at the end. **No action is taken on it.**

### B.1 In-repo vs standalone repo

**Option 1 — keep in-repo under `protocol-generator/ada/` (current keystone default).**
Per-language sibling repos are deferred keystone-wide (S10); all peers live in the keystone monorepo
today.
  - *For:* zero lift cost; shared spec-data / test-vectors / oracle stay co-located (the runbooks
    read `../shared/...` and `output/s4-oracles/...` directly); cross-peer changes (spec bumps) land
    atomically; the runbooks' relative paths already assume this root.
  - *Against:* an Ada consumer can't `alr get` a monorepo path directly — they would depend on a
    published Alire crate (or a `with`'d `.gpr` against a vendored copy), not the repo layout.

**Option 2 — lift to a standalone `entity-core-protocol-ada` repo (S10).**
  - *For:* a clean crate root with `alire.toml` + `entity_core_protocol.gpr` at the repo root (the
    Alire-idiomatic layout for a published crate); independent version cadence; the natural home for
    the CI workflow and the concrete `repository_url`/`origin` (currently empty).
  - *Against:* the lift must vendor or submodule `shared/spec-data` + `test-vectors` + the oracle
    (the peer can't conform without them); spec bumps then require a cross-repo sync; it is an S10
    step the keystone has **deliberately deferred cohort-wide** — doing it for Ada alone fragments
    the uniform "all peers in-repo" posture.

### B.2 Distribution mechanism (Ada-specific)

Ada's registry is **Alire** (the Ada Library Repository) — a git-repo-indexed community registry (the
crates.io/Hex analogue), not an upload-an-artifact registry like Maven Central:
  - **(a) Alire crate index.** `alr publish` submits a crate manifest to the Alire community index
    (a PR to the `alire-index` repo) that points at a tagged git commit; consumers then `alr get
    entity_core_protocol` / `alr with entity_core_protocol`. This is the mainstream path; the
    crate-index submission is the one-time operator gate (A-ADA-005, the Maven-namespace analogue)
    that **cannot be done by the pipeline** and is why publishing is deferred.
  - **(b) Direct `.gpr` dependency (no Alire at all).** A consumer `with`s the committed
    `entity_core_protocol.gpr` from a vendored/submoduled copy and builds with gprbuild — fully
    offline, audit-friendly, the same supply-chain stance as the keystone. This is how the peer is
    consumed *today* (the runbooks build the `.gpr` in-container). The core build needs **no Alire
    at all** (no crate deps), so this path is first-class, not a fallback.
  - **(c) A private/internal Alire index.** Lower-ceremony than the community index for an
    internal consumer; the consumer adds the index URL to their Alire config.

The **single-runtime-dependency posture** (system libsodium only; NO Alire crates) makes distribution
light: a consumer inherits *no* Alire crate graph — the only pin is a system libsodium 1.0.22 (the
lightest supply-chain in the cohort, with Zig/Elixir/Java).

### B.3 License / version posture

  - **License: Apache-2.0** (keystone S9 default; explicit patent grant). The FSF-GNAT *compiler* is
    GPL-with-runtime-exception, but the toolchain license does not bind the generated peer, so the
    Apache-2.0 default stands (`profile.toml [license]` — not overridden). `alire.toml` carries the
    SPDX `licenses = "Apache-2.0"`; the one runtime dep (libsodium) is ISC (third-party notice in
    `LICENSE`). No change recommended.
  - **Version: `0.1.0-pre`** (set this phase, in `alire.toml version` directly). The cohort-wide
    pre-release line. **Alire's `version` accepts the SemVer `-pre` qualifier directly** — the
    contrast with CL's A-CL-010 (ASDF forced the `-pre` into the CHANGELOG only). **Promotes to
    `0.1.0`** only when (a) S4 fully green [met] AND (b) ≥1 external Ada consumer confirms it works
    [not yet met — the C#-class "Avalonia confirms" analogue]. `CHANGELOG.md` tracks the spec version
    literally (`tracks V7 v7.75`).
  - **Ed448 / SHA-384 agility higher bar** is the documented non-v0.1 item (A-ADA-002): libsodium has
    neither, the §9.1 floor needs only Ed25519 + SHA-256 (69/69 byte-green), and the overlay comes via
    the C-ABI surface or an OpenSSL curve448 binding when taken — NOT libsodium. SPARK formal proof is
    likewise out of scope for v0.1 (the contract aspects are runtime guards).

### B.4 Recommendation (operator-decides — not acted on)

**Keep the peer in-repo under `protocol-generator/ada/` for v0.1, consume via a direct `with`'d
`.gpr` (or an Alire crate-index entry on the keystone repo), at the `0.1.0-pre`/Apache-2.0 line;
defer the `alr publish` crate-index submission until the operator submits the index PR and arch signs
off v0.1 + a first external consumer confirms.** Rationale: the standalone-repo lift (S10) is deferred
cohort-wide and lifting Ada alone fragments the uniform posture; the single-runtime-dependency crate
(no Alire crate graph) has no distribution friction to solve; and the Alire crate-index submission
gate (A-ADA-005) is genuinely a one-time operator action the pipeline cannot take. **Lift to a
standalone repo + submit the Alire crate-index entry at the same time the cohort does** (when arch
defines the S10 per-language-repo + CI home), promoting to `0.1.0` once the external-consumer gate is
met. Hold the **Ed448/SHA-384 agility overlay** as an explicit post-v0.1 item. This is a
recommendation only — **the operator decides; the pipeline does not publish, tag, or push.**

---

## C. Summary for arch (one paragraph)

Peer #10 vindicates the convergence thesis at the cohort's *safety-critical / strong-typing* member —
the two most-distant idiom axes left in the batch (a first-class **tasks + protected objects +
rendezvous** concurrency model, and **design-by-contract**) reached **0 FAIL spec-first** with a
byte-identical codec (69/69), registry (53/53), and §1.5 peer_id, every distant seam landing at impl
locality with **zero wire-byte divergence.** Its **headline contribution is the cleanest §4.8
store-safety story in the 11-peer cohort:** the §4.8 store as a **protected object** makes the
store-race a *language-guaranteed* impossibility — the Zig/CL store-race fall-overs and the **C
sibling's live heap race (A-C-009)** are **structurally unrepresentable** here, and the design is
genuinely concurrent (no-head-of-line + sustained-10000-req §7b gates PASS together, 5/5, not
serialized). No NEW spec defect surfaced (the discovery well held DRY, as predicted); the harvest is
the standing multi-peer corroborations re-confirmed (§7.4-vs-§1.5 peer-id A-ADA-001; hex-case
A-ADA-003; §5.2 401/403 A-ADA-008; resource_bounds A-ADA-007) plus two implementation notes
(A-ADA-011 the `params`-is-an-entity wire-altitude trap that drove the biggest S4 fix cluster;
A-ADA-010 the GNAT float-validity over-strictness, conformance-neutral). **The one actionable
arch/mainline item: A-ADA-013 — the cohort scorecard's `62044c5` oracle label is off-by-one-commit;
the true v7.75 oracle is the immediate child `b30a589`, which folds `resource_bounds` into
`coreProfileCategories` → the real 576·0F·89S** (a clean `62044c5` build auto-skips `resource_bounds`
→ 574·0F·90S); independently confirmed read-only from oracle source + the live re-run, no doctoring,
peer not rebuilt — the scorecard label should take the one-commit fix. Ada's verdict is 0 FAIL at the
correct baseline, so the merge is safe. The Ed448/SHA-384 agility higher bar (A-ADA-002, libsodium
gap, OCaml/Zig company) and the Alire crate publish (A-ADA-005) are deferred non-v0.1/operator items.

---

## PART D — Consolidated findings ledger (for the arch escalation bundle)

Every A-ADA-### with its arch-bound flag, criticality, and one-line state. Ready to lift into the
cross-peer arch escalation bundle.

| Finding | Arch-bound | Criticality | One-line state |
|---|---|---|---|
| **A-ADA-013** cohort oracle off-by-one | ⚑ mainline/arch | **Medium — corrects the scorecard's canonical oracle label** | RESOLVED; the `62044c5` scorecard label is off-by-one — true v7.75 oracle is the child `b30a589` (folds `resource_bounds` into core → 576·0F·89S; clean `62044c5` auto-skips it → 574·0F·90S); verified read-only + live re-run, no doctoring, peer not rebuilt. |
| **A-ADA-001** §7.4-vs-§1.5 peer-id | ⚑ arch | High — silent handshake kill | N-th spec-first corroboration (Zig/OCaml/CL/Java/Swift); §7.4 stale SHA-256 form contradicts §1.5 identity-multihash table; resolved via §1.5 (raw pubkey, `hash_type=0x00`); baked at S1. |
| **A-ADA-003** hex-case lowercase | ⚑ arch | High — case-sensitive path 404 | Ada hex builtins default UPPERCASE (the A-CL-009 trap the CL log named Ada as carrying); §3.4/§3.5/§6.9a tree-path keys are case-sensitive; pinned proactively (custom nibble→char table, never `Integer'Image`/`Integer_IO Base=>16`). |
| **A-ADA-008** §5.2 401/403 trichotomy | ⚑ arch | High — wrong auth status class | §5.2 401 (authn) / 403 (authz) / 401 (unresolvable) trichotomy; multi-peer-convergent (OCaml/Zig/Java/Swift); pre-resolved + held. |
| **A-ADA-011** `params` is an ENTITY wire-form | (impl note) | Medium — biggest S4 fix cluster | `params.data.entity`, not `params.entity`; reading nonce/key_type/public_key off the params-map top level → `nonce-not-found → 401`; materialize params as an entity first. NOT a spec defect (§3.2 adequate); a wire-altitude trap. |
| **A-ADA-010** GNAT float-validity over-strictness | (operator) | Low — toolchain note | `-gnatVa` flags IEEE float specials (NaN/±Inf) as invalid on canonical bytes; validity checks scoped-suppressed in the two float-bit codec bodies (contract aspects stay live); conformance-neutral (69/69). |
| **A-ADA-007** resource_bounds 413/400/WARN | — | RESOLVED (settled v7.75) | r1 over-payload → 413 + keep serving; r2 over-deep chain → 400 (NOT 403, §4.10(b) structural pre-check before authz walk); r3 conn-flood → WARN (SHOULD/external). Pre-resolved + held. |
| **A-ADA-002** Ed448/SHA-384 agility defer | (operator) | Low — non-floor deferral | libsodium has no Ed448 + no SHA-384 (OCaml/Zig company); §9.1 floor needs only Ed25519+SHA-256; overlay via C-ABI surface or OpenSSL curve448, NOT libsodium. Non-blocking. |
| **A-ADA-005** Alire crate publish | (operator) | Low — packaging step | Deferred; `alr publish` needs an Alire crate-index submission (sets `origin`/`repository_url`). Alire `version` accepts `-pre` directly (contrast A-CL-010). Manifest publish-ready. |
| **A-ADA-006** task topology | — | RESOLVED | One task per connection (GNAT tasks → OS threads; no cooperative-pool starvation); protected-object store fixed at S1; reentry-only child task. |
| **A-ADA-004** build/test tooling | (operator) | RESOLVED | gprbuild against the committed `.gpr` (no Alire resolve) + hand-rolled test runner (no AUnit); lightest-supply-chain, fully offline. |
| **A-ADA-012** grant-list duplication | — | Cosmetic / non-blocking | default-policy seed grants double the discovery floor in the GRANT-LIST PRESENTATION (no authz-verdict effect; cohort-consistent with Java). |
