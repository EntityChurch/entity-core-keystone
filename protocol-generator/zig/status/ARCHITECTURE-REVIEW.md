# Architecture Review — entity-core-protocol-zig (peer #4)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data v7.72 +
v7.74 (§10.1 core-register + §9.5a CORE-TREE) · **Audience:** architecture (spec-tightness
feedback) + operators (publishing decision). · **Status:** peer #4 at `validate-peer --profile
core` PASS · 568 / 284P / 195W / **0F** / 89skip.

This review follows the format/depth of the three-peer
architecture milestone review, extended to **the fourth, distant-idiom peer**. Part A is the idiom-fidelity +
spec-refinement retrospective; Part B is the publishing-options decision surface for the operator.

---

## 0. The thesis peer #4 was chosen to test

The three-peer review established: *if the spec is tight, independently-derived peers converge on
the same conformance fixed point with no behavioral divergence, and a spec-first peer surfaces
contradictions the port-peers inherited-correctly-but-never-flagged.* Peers #1–#3 were all **GC'd
managed/scripting languages** (C#, TS, OCaml). The open question: **does the convergence thesis
survive a *distant idiom* — a systems language with no garbage collector, explicit caller-threaded
allocators, error-union (not exception/result) control flow, and `comptime`?** If the wire-touching
decisions still converge while the idiom seams diverge cleanly by profile, the thesis is much
stronger; if Zig's no-GC/error-union model forced a *different wire answer* anywhere, that would be
a spec-tightness counter-signal.

**Result: the thesis held, and strengthened.** Everything that touches the wire converged to the
same fixed point as #1–#3 (same 0-FAIL, byte-identical codec + 53-type registry), reached
spec-first. The four genuinely-new idiom seams (no-GC allocator threading, error unions, `comptime`
dispatch, fixed-width-int overflow-trapping) diverged exactly where they *should* — at impl
locality the spec is (correctly) silent on — and **none of them changed a single wire byte.** The
one place Zig pushed *into* the spec is the same place OCaml did (peer-id construction, 401/403),
now corroborated from a fourth, maximally-distant idiom.

---

## PART A — Architecture review

### A.1 Did the Zig idiom pay off? (the four seams, scored)

The bet of generating peer #4 was that a no-GC systems idiom would *stress the codec/peer
differently* and surface probes the GC'd cohort structurally couldn't. Scoring the four seams the
profile called out:

**(1) No-GC + explicit allocator threading — PAID OFF (the headline).** This is the single biggest
divergence from #1–#3, all GC'd. Every allocating API takes an `allocator: std.mem.Allocator`; the
codec owns no global state; decode follows a documented caller-frees contract; the peer dispatch
path runs each request against a per-request `std.heap.ArenaAllocator` and **deep-clones the
response envelope into the long-lived allocator** before the arena resets (A-ZIG-007). The payoff
is two-fold:
  - **Free-correctness became a first-class conformance concern no prior peer had.**
    `std.testing.allocator` fails any test that leaks; the smoke + conformance run under a
    safety-on `GeneralPurposeAllocator`. A leaked decoded entity is a *test failure*, not an
    invisible GC deferral. The codec (69/69), the 28-test suite, and the two-peer smoke all run
    leak-clean — which is a *stronger* guarantee than any GC'd peer can make at all.
  - **It surfaced a design question the spec is silent on and GC hides:** who frees a decoded
    entity, its `included` map, its borrowed byte slices (A-ZIG-004), and — materially harder at
    the peer surface — entities with overlapping lifetimes flowing through the store, the
    capability chain walk, and out into response envelopes (A-ZIG-007). The clean Zig answer
    (arena-per-request for the recursive borrow graph; clone-into-gpa for the survivor; store
    dupes on bind) is *reusable generator guidance* the GC'd peers never had to produce. **Verdict:
    the no-GC seam was the highest-value reason to build peer #4.** It didn't find a *wire* bug, but
    it produced the only memory-ownership architecture ruling in the cohort and a free-correctness
    conformance dimension nothing else has.

**(2) Error unions (`!T` over `error{...}` sets) — PAID OFF as a correctness asset.** Deliberate
divergence from C#/TS exceptions and OCaml's result-ADT. Zig has *no exceptions at all*, and error
sets are **compiler-checked for exhaustiveness** — every decode rejection condition is an enumerated
error tag (`CodecError{ NonCanonicalEcf, Truncated, TagRejected, DuplicateKey, ... }`) and the
compiler enforces the decode-path switch is total. This is a *stronger* compile-time guarantee than
any prior peer's error model: the three-peer review noted all peers converge on "protocol status is
a value record, never carried by the exception type across dispatch" — Zig makes that the *only*
expressible option, because there is no exception type to misuse. Crucially `error.OutOfMemory` is a
first-class error-union member (allocation is fallible and explicit, every alloc site is a `try`),
so the encoder/decoder is correct under allocation failure with `errdefer` rollback — a path **no
prior peer exercised**. **Verdict: the idiom seam that *should* differ from #1–#3 differed from all
three, and the exhaustive-switch decode path is a genuine fidelity win, not just an idiom-tax.**

**(3) `comptime` encode dispatch — PAID OFF (idiom fidelity), modest architectural novelty.** The
encoder dispatches on the Zig value type / CBOR major type at *compile time* with zero runtime
reflection (vs C#'s runtime reflection, OCaml's pattern-match). This is the most idiomatically-Zig
choice in the codec and keeps the "encode any value" surface allocation-light without a reflection
layer. It paid off as *idiom fidelity* — the code reads as code a Zig developer would write (the
PROMPT-CONSTANTS "idiom over translation" contract) — and it re-derived the same float-ladder /
head-form-int / recursive-tag-reject the cohort converged on, by a different mechanism. It did not
surface a new *spec* probe (the canonical layer is mechanical), but it confirms the codec design is
expressible idiomatically across the widest idiom span in the cohort.

**(4) Fixed-width ints + ReleaseSafe overflow-trapping — PAID OFF as the cleanest int story in the
cohort.** Where OCaml hit a 63-bit-int trap (A-OC-001, can't even hold `int.10` = 2⁶³−1) and TS
escalated to bigint (F7), Zig has native `u64` and the head-form carrier maps *directly* — full
0..2⁶⁴−1 with no reinterpretation. And because conformance builds run in ReleaseSafe, an off-by-one
in varint/length math **traps loudly rather than wrapping silently**. **Verdict:** Zig is the only
cohort member whose native integer model fits the §3.2 range without a workaround *and* whose
default build catches the overflow class the other peers had to reason about by hand. The standing
corpus blind-spot the three-peer review flagged ([2⁶³, 2⁶⁴−1] unexercised, F7 / A-OC-001) is the
same here — Zig is correct-by-construction-and-trap there but the *corpus still doesn't probe it*.

**Net: all four idiom seams paid off** — three as fidelity wins (error unions, comptime, ints) and
one (no-GC) as the highest-value *new probe surface* in the cohort. Critically, **none changed a
wire byte** — the seams landed exactly at impl locality, which is the convergence thesis holding
under the maximum idiom stress the cohort has applied.

### A.2 Spec-refinement value — what Zig contributed

The keystone's *end* is spec refinement. Peer #4's harvest (full text in `SPEC-AMBIGUITY-LOG.md`):

**Top contribution — A-ZIG-001 (peer-id construction), the headline.** §7.4's pseudocode, labelled
**NORMATIVE**, derives an Ed25519 peer_id as `base58(varint(0x01) ‖ varint(0x01) ‖ SHA256(pubkey))`
— `hash_type=0x01`, digest = SHA-256 *of* the pubkey. The §1.5 v7.65 **canonical-form table**
mandates the *opposite*: `hash_type=0x00` **identity-multihash**, digest = the **raw pubkey**, and
§1.5 says wire peer_ids MUST use canonical form (the SHA-256-form is demoted to a decode-only
backwards-compat carve-out). The two constructions are byte-different; **a peer that follows §7.4
literally produces non-canonical identities that fail tree-path / cap-pattern match and the
`authenticate` identity binding against the oracle.** This is *the* spec-tightness payoff of the
spec-first method: **two independent spec-first peers (OCaml A-OC-007, now Zig A-ZIG-001), deriving
from V7 fresh in maximally-different idioms, both read §7.4 literally and would both fail handshake;
the C#/TS port-peers inherited the correct v7.65 reading from prior knowledge and never flagged the
§7.4 staleness.** Two independent passes hitting the identical contradiction is strong signal the
spec text needs the fix (reference the §1.5 table from §7.4, or carry the identity-multihash
construction directly; state SHA-256-form is decode-only). **Validated live** here: connectivity
22/22 + `authz_grantee_1` confirm the §1.5-canonical construction is what the oracle expects.

**Second contribution — A-ZIG-006 (401/403 request-time boundary), now FOUR-peer convergence.**
§5.2's request-verification pseudocode collapses every failure to a flat "DENY → 403", but §4.6
distinguishes authentication (401 — caller never proved *who*) from authorization (403 — capability
doesn't admit). Implemented as a 3-way `ReqVerdict{ allow, authn_fail→401, authz_deny→403 }` + the
§5.5 unresolvable-grantee→401 carve-out. The three-peer review already called this "no longer an
opinion, it's a spec defect" (C# F20 + TS + OCaml A-OC-008). **Zig is the fourth independent peer to
hit it, and the first from a no-exception error-union idiom** — which makes the split *explicit in
the type* (`ReqVerdict` is an enumerated error/verdict set, not a convention). Validated live:
`authz_deny_default_1`→403, `authz_scope_exceeds_1`→403, `authz_grantee_1`→401, exactly matching the
oracle. **Recommend: arch ratifies the 401/403 boundary and retires the F14 401→403 ruling for
auth-class rows** — the four-peer convergence (one with the split compiler-enforced) is decisive.

**Third — A-ZIG-005, a corroborating coverage-gap data point.** The S2 peer_id corpus uses *opaque*
synthetic digests with `hash_type=0x01` only, so it tests byte-assembly + Base58 + multi-byte
varint but **does not discriminate the A-ZIG-001 contradiction** — a §7.4-literal peer passes S2 and
only fails at live handshake (S4). Vector request to arch: add a real-Ed25519-pubkey,
`hash_type=0x00` identity-multihash peer_id vector so the corpus catches the contradiction at the
codec gate. (Pairs with the standing [2⁶³,2⁶⁴−1] u64-range vector request.)

**What Zig surfaced that the GC'd peers structurally couldn't (informational, routed to arch):** the
spec's *silence on memory ownership* is fine for the wire and fine for GC peers, but leaves a no-GC
peer to author a materially richer ownership contract from scratch — at the codec (A-ZIG-004) and,
harder, at the peer surface with overlapping entity lifetimes (A-ZIG-007). This is not a spec
*defect* (ownership is correctly impl-private), but it is a *data point* arch should hold: the
generator profile-menu now has a concrete no-GC ownership ruling (arena-per-request + clone-into-gpa
+ store-dupes-on-bind) for the next systems-language peer, so it doesn't re-grind the question.

### A.3 Codec / transport design retrospective

**Codec — convergent, native, the lightest in the cohort.** Hand-rolled canonical CBOR (the A-005
pattern every native peer hit): shortest-float ladder (f16⊂f32⊂f64, narrowest bit-exact
round-trip), length-then-lex map-key sort on encoded key bytes, recursive major-type-6 tag
rejection, head-form int carrier. 69/69 byte-identical, first run, **0 codec fixes** — the codec was
byte-green before the peer existed, which is why the only S4 risk was field-shape *data* (caught
per-type by the 53/53 registry byte-diff), not codec behavior. Zig's distinctive contribution to
the codec axis: it is **`std`-only with zero third-party packages** — `std.crypto` ships audited
Ed25519 + SHA-2 in-tree, so unlike OCaml (`mirage-crypto-ec`, `digestif`) or C# (NSec/BouncyCastle),
the *entire* peer pulls nothing off any registry. This makes Zig the **lightest supply-chain
posture in the cohort**: the single S11 pin is the toolchain version.

**Transport — convergent shape, threaded primitive (profile-local, validated).** The shape is the
spec-forced cohort shape: 4-byte BE length-prefix + CBOR @ 16 MiB cap; one reader thread per
connection demuxing EXECUTE_RESPONSE by `request_id` (N7); inbound EXECUTE dispatched on its own
thread so it never blocks outbound (N6); transport-agnostic dispatch brain. The *primitive* is
`std.Thread` + `std.Thread.Mutex`/`Condition` over a `StringHashMapUnmanaged` pending table — the
direct Zig analogue of C#'s `ConcurrentDictionary<id,TCS>` / OCaml's per-thread-blocking, chosen
because **Zig's `async` is in flux** (the pre-0.15 colorless async was removed; the `std.Io` evented
model is still landing across 0.15/0.16 — "Writergate"). Betting a conformance-bearing peer on an
unsettled language feature was the wrong call; OS threads are stable, in `std`, zero-dep. This
mirrors the OCaml S3 eio→threads revision (A-OC-003) and reaches the same conclusion: **a
`--profile core` peer has no handler-initiated outbound origination (extension-only, §9.0), so its
concurrency needs are modest enough that the heavyweight async runtime each ecosystem reaches for
first is overkill.** The S3 smoke proved 8 concurrent EXECUTEs each correlate to their own response
(8/8) over real loopback. The swap to `std.Io` is localized to `transport.zig` if origination ever
enters the core. **Retrospective verdict:** the threaded choice is correct for the core floor and
de-risks the most volatile part of the current Zig language surface.

### A.4 Where peer #4 sits vs the C#/TS/OCaml cohort

| Axis | C# (#1) | TS (#2) | OCaml (#3) | **Zig (#4)** |
|---|---|---|---|---|
| Derivation | reference | port | spec-first | **spec-first, distant idiom** |
| Memory | GC | GC | GC | **no GC, explicit allocators** |
| Error model | exceptions | exceptions | result ADT | **error unions (no exceptions)** |
| Codec | hybrid (Ctap2+hand) | hand-rolled | hand-rolled | **hand-rolled, comptime dispatch** |
| Third-party deps | NSec, BouncyCastle, … | @noble/curves | mirage-crypto, digestif | **ZERO — std-only** |
| Int carrier | native `ulong` | `bigint` (F7) | unsigned-`int64` (A-OC-001) | **native `u64` + ReleaseSafe trap** |
| Ed448 agility | BouncyCastle | @noble | native gap (A-OC-002) | **native gap (A-ZIG-002)** |
| Leak-correctness | (GC) | (GC) | (GC) | **first-class conformance gate** |
| Core verdict | 0 FAIL | 0 FAIL | 0 FAIL | **0 FAIL** |
| Total checks | 552 | 552 | 558 | **568** (v7.74 oracle, +16) |

**Position:** peer #4 is the cohort's **convergence stress-test at maximum idiom distance, and the
supply-chain floor.** It confirms every wire-touching decision converges even when the language has
no GC and no exceptions; it adds the only memory-ownership + free-correctness dimension in the
cohort; it independently re-confirms the two highest-value spec defects (peer-id, 401/403) from the
most-distant idiom; and it is the only peer with a *zero-third-party-dependency* posture — which is
also why its publishing story (Part B) is the simplest in the cohort. The 568-vs-552 total is purely
the newer v7.74 oracle (§10.1 core-register + §9.5a CORE-TREE), not a scope difference.

**On the Ed448 agility higher bar (A-ZIG-002), as a documented non-v0.1 item.** `std.crypto` has
Ed25519 but **no Ed448**, no audited pure-Zig Ed448 exists, and Zig has **no BouncyCastle-equivalent**
— so the "second managed-crypto provider" strategy that rescued C# does **not** generalize to Zig,
exactly as it didn't to OCaml. Two distant-idiom peers now independently land on the same conclusion.
This does **not** affect the ECF/Ed25519 conformance floor (Ed25519 is native, 69/69 byte-green); it
blocks only the agility *higher bar* (Ed448 + SHA-384 matrix). The recommended shape when agility
enters scope is **hybrid**: native Ed25519 (shipped) + **FFI Ed448 only** (consume
`libentitycore_codec` for the one family the ecosystem can't supply). Zig's C-ABI FFI is first-class
(`@cImport`/`extern`), so this hybrid is arguably *cleaner in Zig than in any prior peer* — the
FFI-codec's reason-for-being, demonstrated by a second real ecosystem. **It is an explicit non-v0.1
item, logged not papered over, and gated behind the agility scope decision.**

---

## PART B — Publishing options (operator-decides)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface; the
recommendation is at the end. **No action is taken on it.**

### B.1 In-repo vs standalone repo

**Option 1 — keep in-repo under `protocol-generator/zig/` (current keystone default).** Per-language
sibling repos are deferred keystone-wide (S10); all four peers live in the keystone monorepo today.
  - *For:* zero lift cost; shared spec-data / test-vectors / oracle stay co-located (the peer reads
    `../shared/...` directly); cross-peer changes (spec bumps) land atomically across all peers; the
    CI workflow's relative paths (`/work/protocol-generator/zig`) already assume this root.
  - *Against:* a Zig consumer fetching by `build.zig.zon` URL+hash pulls the *whole keystone repo*
    at a tag (Zig's `.url` fetches a tarball and content-hashes it; `.paths` in *this* peer's
    `build.zig.zon` already scopes the package to `build.zig`/`build.zig.zon`/`src`, but the fetched
    tarball is repo-wide). Not fatal — the hash still pins exact bytes — but it's a larger fetch and
    couples the consumer's pin to unrelated keystone history.

**Option 2 — lift to a standalone `entity-core-protocol-zig` repo (S10).**
  - *For:* a clean, minimal fetch surface for consumers (just the peer); a natural home for the CI
    workflow (`.github/workflows/conformance.yml` is already authored to run there); an independent
    tag/version cadence; the README's `repository_url` becomes concrete.
  - *Against:* the lift must vendor or submodule `shared/spec-data` + `test-vectors` + the oracle
    (the peer can't conform without them); spec bumps now require a sync step across repos; it is an
    S10 step the keystone has *deliberately deferred cohort-wide* — doing it for Zig alone fragments
    the cohort's uniform "all peers in-repo" posture.

### B.2 Distribution mechanism (Zig-specific)

Zig has **no central package registry** (no crates.io/npm/opam). Options, all decentralized:
  - **(a) Tagged-release tarball fetched by URL+hash** (the Zig-idiomatic path). "Publishing" = a git
    tag at a reviewed commit; consumers add to *their* `build.zig.zon`:
    `.dependencies = .{ .entity_core_protocol_zig = .{ .url = "<repo>/archive/<tag>.tar.gz", .hash = "..." } }`.
    The consumer's build *fails* if the fetched bytes don't match the hash — **hash-pinned by
    design**, a supply-chain-friendly property. No publish command, no index. Works from either an
    in-repo tag (Option 1, repo-wide tarball) or a standalone-repo tag (Option 2, minimal tarball).
  - **(b) Git submodule / vendored copy.** A consumer vendors the peer at a pinned commit. Coarser
    than (a) but fully offline and audit-friendly; appropriate for a consumer with the same
    supply-chain stance as the keystone.
  - **(c) No central-registry submission** is possible or needed — there is nothing to submit to.
    (Contrast OCaml's optional `opam-repository` PR; Zig has no analogue.)

The **std-only posture makes distribution trivial**: zero transitive deps means a consumer inherits
*no* lockfile fan-out — the only pin they take on is the Zig toolchain version (`minimum_zig_version
= "0.15.1"` in `build.zig.zon`).

### B.3 License / version posture

  - **License: Apache-2.0** (keystone S9 default; explicit patent grant). Zig is MIT and the
    ecosystem leans MIT but mandates nothing, so the safe Apache-2.0 default stands
    (`profile.toml [license]` — not overridden). No change recommended.
  - **Version: `0.1.0-pre`** (set this phase, replacing an S2 placeholder `0.2.0`). The cohort-wide
    pre-release line. **Promotes to `0.1.0`** only when (a) S4 fully green [met] AND (b) ≥1 external
    consumer confirms it works [not yet met]. `build.zig.zon` carries the spec/oracle pins in
    comments; `CHANGELOG.md` tracks the spec version literally.

### B.4 Recommendation (operator-decides — not acted on)

**Keep the peer in-repo under `protocol-generator/zig/` for v0.1, distribute via a tagged-release
tarball pinned by URL+hash in `build.zig.zon` (mechanism (a)), at `0.1.0-pre`/Apache-2.0.** Rationale:
the standalone-repo lift (S10) is deferred cohort-wide and lifting Zig alone fragments the uniform
posture for marginal benefit before any consumer exists; the in-repo `.paths`-scoped package + a
hash-pinned tarball already gives consumers an exact, reproducible pin; and the std-only/zero-dep
profile means there is no distribution friction to solve. **Lift to a standalone repo at the same
time the cohort does** (when arch defines the S10 per-language-repo + CI home), promoting to `0.1.0`
once the external-consumer promotion gate is met. Hold the **Ed448 hybrid-FFI** (A-ZIG-002) as an
explicit post-v0.1 agility-scope item. This is a recommendation only — **the operator decides; the
pipeline does not publish, tag, or push.**

---

## C. Summary for arch (one paragraph)

Peer #4 vindicates the convergence thesis under the cohort's maximum idiom distance: a no-GC,
no-exception, `comptime` systems language reached the identical 0-FAIL fixed point spec-first, with
every idiom seam landing at impl locality and **zero wire-byte divergence**. Its highest-value
contributions are (1) the only memory-ownership + free-correctness conformance dimension in the
cohort (a no-GC ruling the next systems peer can reuse), (2) independent corroboration of the two
standing spec defects — §7.4-vs-§1.5 peer-id construction (A-ZIG-001 ⚑, now two spec-first peers)
and the §5.2 401/403 boundary (A-ZIG-006 ⚑, now four peers, one compiler-enforced) — from the
most-distant idiom, and (3) the cohort's lightest supply-chain posture (std-only, zero third-party
deps). The two ⚑ items are the actionable arch asks: ratify the §1.5-canonical peer-id construction
in §7.4, and ratify the 401/403 request-time split in §5.2. Ed448 agility remains a documented,
non-v0.1, hybrid-FFI item.
