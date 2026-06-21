# Architecture Review — entity-core-protocol-common-lisp (peer #5)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data v7.72 +
the v7.73/v7.74 peer-surface closeout (register/outbound/emit §6.13 + §6.9a owner-cap + §7a
conformance handlers); codec corpus v0.8.0. · **Audience:** architecture (spec-tightness feedback) +
operators (publishing decision). · **Status:** peer #5 at `validate-peer --profile core` PASS ·
568 / 284P / 195W / **0F** / 89skip; origination-core 3/3.

This review follows the format/depth of the Zig peer #4 `ARCHITECTURE-REVIEW.md` (itself an
extension of the three-peer architecture milestone review),
carried to **the fifth, and most distant, idiom in the cohort**. Part A is the idiom-fidelity +
spec-refinement retrospective; Part B is the publishing-options decision surface; Part C is the
one-paragraph arch summary.

---

## 0. The thesis peer #5 was chosen to test

The convergence thesis (three-peer review, reinforced by Zig #4): *if the spec is tight,
independently-derived peers converge on the same conformance fixed point with no wire divergence;
the idiom seams diverge cleanly by profile at impl locality; and a spec-first peer surfaces
contradictions the port-peers inherited-correctly-but-never-flagged.* Peers #1–#3 were GC'd
managed/scripting (C#, TS, OCaml); peer #4 (Zig) stressed it with a no-GC systems idiom and the
thesis held + strengthened.

Common Lisp is the cohort's **maximum idiom distance to date along a *different axis* than Zig**.
Where Zig was distant in the *memory/control-flow* direction (no GC, error unions, `comptime`),
Common Lisp is distant in the *program-model* direction: **homoiconic S-expressions, CLOS
multiple dispatch (not single-dispatch methods), the condition system + restarts (not
exceptions or result-ADTs), native arbitrary-precision bignums, dynamic typing, macros, and
image-based interactive development.** The open question: **does the convergence thesis survive an
idiom whose *dispatch model and error model are structurally different from every prior peer's*?**
If the wire-touching decisions still converge while the program-model seams diverge cleanly, the
thesis is much stronger across two orthogonal distance axes; if CLOS multiple dispatch or the
condition system forced a *different wire answer* anywhere, that would be a tightness counter-signal.

**Result: the thesis held, on the second orthogonal distance axis.** Everything that touches the
wire converged to the **same fixed point as OCaml #3** (568 / 284P/195W/**0F**/89skip — the
identical 284P/195W split, not merely "0 fail"), reached spec-first, byte-identical codec (69/69,
first run) + 53-type registry (53/53). The structurally-new program-model seams — CLOS multiple
dispatch, the condition system, native bignums, image-based dev — diverged exactly where they
*should*, at impl locality the spec is correctly silent on, and **none of them changed a single
wire byte.** The places CL pushed *into* the spec are the same places OCaml and Zig did (peer-id
construction; format_code asymmetry), now corroborated from a third spec-first peer in a
maximally-distant program model, plus **one NEW spec finding (hex-case)** the distant idiom
surfaced that the four prior peers' stdlib-hex defaults structurally hid.

---

## PART A — Architecture review

### A.1 Did the Common Lisp idiom pay off? (the four program-model seams, scored)

The bet of generating peer #5 was that a homoiconic, multiple-dispatch, condition-system idiom
would *express the protocol differently* and surface probes the single-dispatch / exception-or-result
cohort structurally couldn't. Scoring the four seams the profile called out:

**(1) CLOS multiple dispatch for §6.5/§6.6 — PAID OFF as the headline idiom-neutrality probe
(A-CL-008).** This is the single biggest *structural* divergence from #1–#4, which all express
§6.6 operation dispatch as a **single-dispatch** `switch`/`match op with` ladder inside one
function per handler. Common Lisp expresses it as a CLOS **generic function with multiple
dispatch**: each MUST handler is a *class*, each operation is a *method on `HANDLE-OP`* specialized
by the handler class **and** an EQL specializer on the operation keyword, and "unknown operation →
501" is the **default method**, not a fall-through `case`. The payoff:
  - The §6.6 dispatch key the spec *already* treats as `(handler, operation)` is **literally the
    CLOS specializer tuple.** The multiple-dispatch decomposition lands on byte/behavior-identical
    dispatch with **zero spec ambiguity surfaced.** The §6.6 contract is *idiom-neutral*: it reads
    the same whether you destructure the pair in a `match` or let the method combination do it.
  - **The convergence of four single-dispatch idioms + one genuine multiple-dispatch idiom on the
    same dispatch behavior is a tightness signal** — §6.6 is specified at the right altitude (it
    names the dispatch *key*, not a dispatch *mechanism*), so the widest dispatch-model span in the
    cohort produces no divergence. This is the CL-specific contribution to the convergence ledger:
    it is the first peer that *could* have diverged on dispatch shape and didn't.
  - **Verdict:** the multiple-dispatch seam is the highest-value *idiom-neutrality* probe in the
    cohort — it confirms the §6.6 surface is mechanism-agnostic, the dispatch-model analogue of
    Zig's "every wire byte converged under no-GC."

**(2) The condition system + restarts (not exceptions, not a result-ADT) — PAID OFF as fidelity,
no wire effect.** Deliberate divergence from C#/TS exceptions and OCaml's `result`/Zig's error
unions. Common Lisp has a **condition system**: errors are CLOS condition objects signalled up a
dynamically-bound handler stack, and — uniquely — *restarts* let a handler resume computation at a
chosen point without unwinding. Decode rejections + protocol errors are a typed condition lattice
(`entity-core-error` ⊃ `non-canonical-ecf`, `truncated-input`, `tag-rejected`,
`unsupported-content-hash-format`, `unsupported-key-type`, `duplicate-map-key`, …). The cohort
invariant from the three-peer review — *"protocol status is a value record, never carried by the
error type across dispatch"* — holds here for the same reason it held everywhere: the dispatch
brain returns a status *value*; a signalled condition is a *codec/local* fault, never the
cross-dispatch protocol-status carrier. The restart machinery (available, idiomatic) is not used
to cross the dispatch boundary. **Verdict:** the most expressive error model in the cohort still
converges on the same status-as-value discipline — the error-model seam differed structurally
from all four prior peers (it is neither exception nor result) and produced **no wire divergence**,
which is the convergence thesis holding under the cohort's richest error model.

**(3) Native arbitrary-precision integers — PAID OFF as the cleanest int story in the cohort,
tied with Zig by a different mechanism.** The §3.2 CBOR head-form carrier is full 0..2⁶⁴−1. Where
OCaml hit a 63-bit-int trap (A-OC-001 — can't even hold `int.10` = 2⁶³−1) and TS escalated to
`bigint` (F7), Common Lisp has **native bignums**: an integer that exceeds a fixnum *transparently
promotes* to arbitrary precision with no type change, no reinterpretation, no carrier struct. The
codec reads/writes the full u64 range as ordinary `integer`s. **Verdict:** CL is, with Zig, one of
two cohort members whose native integer model fits the §3.2 range with *zero* workaround — but by
the opposite mechanism (Zig: fixed-width `u64` + overflow trap; CL: unbounded bignums that never
overflow). The standing corpus blind-spot — `[2⁶³, 2⁶⁴−1]` unexercised (F7 / A-OC-001 / A-ZIG-005)
— is the same here: CL is correct-by-construction across it, but the *corpus still doesn't probe
it*, so the corroboration is structural, not test-witnessed.

**(4) Pure-Lisp native Ed448 (ironclad) — PAID OFF as the cohort's agility-primitive high-water
mark (A-CL-005).** This is the **headline contrast with OCaml AND Zig on the crypto axis.** OCaml
had no conformant native Ed448 and sourced it over a C-ABI (A-OC-002, hybrid FFI); Zig's
`std.crypto` has no Ed448 at all and no audited pure-Zig impl exists (A-ZIG-002, deferred). Common
Lisp reaches **both** the §9.1 floor (Ed25519 + SHA-256) **and** the agility higher-bar primitives
(Ed448 + SHA-384) from a **single pure-Lisp library (`ironclad`)** — no FFI, no opt-in
sub-library, no second crypto provider. It is the second native-Ed448 peer (after Elixir) but the
first via a *pure-Lisp* impl rather than an OpenSSL NIF. Because a pure-Lisp curve impl is a
*larger trust surface* than an audited primitive, S2 gated trusting it on **RFC-8032 §7.4
known-answer-test byte-equality** (57-B pubkey, 114-B signature, §1.5 peer_id, all byte-equal to
the locked v7.71 pins) before accepting it for the agility corpus. **Verdict:** CL is the cohort's
*primitive-completeness* peer on crypto — it is the only peer that needs no FFI and no second
provider to have *both* curve families natively. (The agility *full MATRIX* harness is still a
cohort-wide deferral — primitives proven, matrix not wired; see §B.3.)

**Net: all four program-model seams paid off** — A-CL-008 as the cohort's headline *idiom-neutrality*
probe (multiple dispatch converges), the condition system as a fidelity win (richest error model,
same status-as-value discipline), bignums as the cleanest-by-a-different-mechanism int story, and
pure-Lisp native Ed448 as the agility-primitive high-water mark. Critically, **none changed a wire
byte** — the seams landed at impl locality, which is the convergence thesis holding under the
cohort's maximum *program-model* distance (the orthogonal axis to Zig's memory/control-flow distance).

### A.2 Spec-refinement value — what Common Lisp contributed

The keystone's *end* is spec refinement. Peer #5's harvest (full text in `SPEC-AMBIGUITY-LOG.md`):

**Top NEW contribution — A-CL-009 (address-space hex-case), the headline finding.** The §3.4/§3.5
invariant-pointer paths (`system/signature/{hash}`), the §5.1 revocation marker path
(`system/capability/revocations/{hash}`), and the §6.9a policy paths are **case-sensitive string
keys** rendered from the **hex of the entity content_hash** — but V7 **states the hex-CASE
nowhere normatively.** The Go oracle and all four sibling peers happen to render lowercase
(`hex.EncodeToString` / `%02x`), purely because that is their stdlib hex default. Common Lisp's
stdlib hex default (`~x` / `~2,'0x`) is **uppercase**, so the CL peer produced an
**internally-consistent-but-cross-incompatible** address space: its S3 CL-to-CL loopback PASSED
(both sides uppercase), and it only failed at the live S4 oracle gate — 404 on the register
grant-signature path and the §5.1 revoke marker, because the oracle's lowercase keys weren't found.
**This is the exact class of interop trap a self-consistent peer hides until cross-impl, and it is
the distant idiom *paying off as a spec probe*:** four lowercase-defaulting stdlibs converged by
accident and never flagged the silence; the first uppercase-defaulting stdlib surfaced it
immediately. It is a **latent trap for any future peer** whose hex builtin defaults uppercase (CL,
some Pascal/Ada/SQL hex functions). **Escalation: arch** — V7 §3.4/§3.5 (and the §1.5 content_hash
hex rendering) SHOULD state hex-case explicitly (lowercase), since the paths are case-sensitive
keys. Resolved locally (lowercase `hex`; all path writes AND reads route through it).

**Second contribution — A-CL-002 (peer-id construction), now the THIRD spec-first corroboration.**
§7.4's pseudocode, labelled **NORMATIVE**, derives an Ed25519 peer_id as
`base58(0x01 ‖ 0x01 ‖ SHA256(pubkey))` — `hash_type=0x01`, digest = SHA-256 *of* the pubkey. The
§1.5 v7.65 **canonical-form table** mandates the *opposite*: `hash_type=0x00` **identity-multihash**,
digest = the **raw pubkey** (no hash); §1.5 demotes the SHA-256-form to a decode-only
backwards-compat carve-out. The two are byte-different; a §7.4-literal peer fails the `authenticate`
identity binding (`peer_id == derive(pubkey)`) and gets `401 identity_mismatch`. **CL is the third
independent spec-first peer to read §7.4 literally and would have failed handshake — after OCaml
A-OC-007 and Zig A-ZIG-001.** Baked the §1.5 form into the profile at S1 to dodge the third
debug-cycle burn (the §1.5-canonical Ed448 peer_id `3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4`
is byte-equal to the locked v7.71 pin). **Three spec-first peers from three maximally-different
idioms hitting the identical contradiction is decisive signal the spec text needs the fix**
(reference the §1.5 table from §7.4, or carry the identity-multihash construction directly; state
the SHA-256-form is decode-only). **Escalation: architecture** (high-priority; silent-handshake-kill).

**Third contribution — A-CL-007 (format_code 128 asymmetry), second independent corroboration of
A-OC-004.** The ECF `content_hash.4` (construct) and the agility `VARINT-MULTIBYTE-1` (decode/reject)
corpora treat `format_code = 128` **oppositely**, and the asymmetry is **not stated** in
ENTITY-CBOR-ENCODING §4.3/§4.7 — a fresh reader could plausibly reject 128 on both sides and fail
`content_hash.4`. CL's fresh derivation hit the same fork OCaml (A-OC-004) did and landed on the
**same resolution independently**: on construction, emit `varint(format_code) ‖ SHA256(ECF(body))`
for the caller-supplied code (so `content_hash.4` with 128 passes, byte-equal to the corpus pin);
on receive/verify, reject any unallocated code with `unsupported-content-hash-format` (so
`VARINT-MULTIBYTE-1` rejects 0x80 01). **Second spec-first peer (OCaml, now CL) to independently
reach the asymmetry — additional corroboration of the A-OC-004 arch proposal.** **Escalation: arch**
— §4.3/§4.7 should state the construct-serialises / receive-rejects split explicitly.

**Idiom-neutrality data point — A-CL-008 (CLOS multiple dispatch).** Detailed in §A.1(1):
five idioms (four single-dispatch + one multiple-dispatch) converge on the same §6.6 dispatch
behavior. **Escalation: none** — a tightness signal for the architectural review ledger, not a gap.

**Provenance gap — A-CL-001 (v7.73/v7.74 spec-data snapshot missing), STILL OPEN.** The local
`spec-data/` stops at v7.72; the oracle was rebuilt from `entity-core-go` HEAD so the conformance
*check-set IS at HEAD*, and the build is oracle-verified-correct — but the peer's v7.73+ behavior
(register's five normative writes §6.13, the §PR-8 granter frame, §5.7 caveats, §6.9a owner-cap,
§7a handlers) was authored against the **cohort + the oracle's own check messages**, not a
SHA-pinned v7.73/v7.74 spec-data snapshot. Byte provenance therefore traces to siblings + oracle,
not to a pinned spec copy. **Escalation: research/arch** — land the SHA-pinned v7.74 spec-data
snapshot so the peer-layer's byte provenance traces to a pinned spec, not to sibling peers.
NON-blocking for the gate; blocking for clean byte-provenance.

**Packaging note — A-CL-010 (ASDF version field has no SemVer pre-release channel), NEW.** Surfaced
at S5 packaging: ASDF's `:version` accepts dotted-integer only and rejects `0.1.0-pre` (→ NIL +
warning). Resolved by carrying numeric `0.1.0` in the `.asd` and the `-pre` LINE in CHANGELOG/README.
A small distant-idiom packaging wrinkle no SemVer-suffix-accepting build system (opam, build.zig.zon,
package.json, .csproj, mix.exs) hit. **Escalation: operator** — recorded for future promotions.

**What CL surfaced that the prior peers structurally couldn't (informational, routed to arch):**
the spec's *silence on hex-case* is fine for any peer whose stdlib hex happens to default lowercase
(four of five), but bites the first peer whose default is uppercase — and CL is that peer. Unlike
Zig's memory-ownership data point (a contract the spec correctly leaves impl-private), A-CL-009 is
a *genuine spec gap*: tree paths are case-sensitive keys, so hex-case is wire-observable and SHOULD
be normative. This is the clearest "the distant idiom found a real defect" result of peer #5.

### A.3 Codec / transport design retrospective

**Codec — convergent, native, the agility-complete one.** Hand-rolled canonical CBOR (the pattern
every native peer hit): shortest-float ladder (f16⊂f32⊂f64, narrowest bit-exact round-trip),
length-then-lex map-key sort on encoded key bytes, recursive major-type-6 tag rejection, head-form
int carrier. 69/69 byte-identical, first full run, **0 codec fixes** — the codec was byte-green
before the peer existed, so the only S4 risk was field-shape *data* (caught per-type by the 53/53
registry byte-diff), not codec behavior. CL's distinctive contribution on the codec axis: it is
the **agility-primitive-complete native peer** — `ironclad` supplies Ed25519 **and** Ed448 **and**
SHA-256/384 from one pure-Lisp library, so unlike OCaml (FFI Ed448) or Zig (no Ed448), the *entire*
crypto surface including the agility higher bar is reachable with **a single third-party dependency
and zero FFI**. The supply-chain posture is one library (`ironclad` BSD-3, pinned 0.61) pulled at
container-build time from a pinned Quicklisp dist, then run fully offline — heavier than Zig's
std-only floor but lighter than C#'s multi-provider fan-out, and FFI-free unlike OCaml's agility.

**Transport — convergent shape, native-thread primitive (profile-local, validated, A-CL-003).** The
shape is the spec-forced cohort shape: 4-byte BE length-prefix + CBOR frame; one reader thread per
connection demuxing `EXECUTE_RESPONSE` by `request_id` (N7); inbound EXECUTE dispatched on its own
thread so it never blocks outbound (N6); a transport-agnostic dispatch brain. The *primitive* is
**`sb-thread`** (SBCL native threads) + a mutex-guarded `request_id → waitqueue` correlation table —
the direct CL analogue of C#'s `ConcurrentDictionary<id,TCS>` / OCaml's per-thread-blocking / Zig's
`std.Thread`. `sb-thread` needs **no third-party dependency**; `bordeaux-threads` (the cross-impl
portability layer) is deferred until ECL/CCL/ABCL portability is actually wanted (a localized swap
in the transport module). This mirrors the OCaml S3 eio→threads revision (A-OC-003) and the Zig
threads-over-async choice (A-ZIG-003) and reaches the same conclusion: **a `--profile core` peer has
no handler-initiated outbound origination (extension-only, §9.0), so its concurrency needs are
modest enough that the heavyweight runtime each ecosystem reaches for first is overkill.** The S3
smoke proved 8 concurrent EXECUTEs each correlate to their own response (8/8) over real loopback,
and origination-core's `dispatch_outbound_reentry` proved the §6.11 reentry seam over real two-peer
TCP (carry-in exercised, not SKIPped). **Retrospective verdict:** the native-thread choice is
correct for the core floor and zero-dep.

### A.4 Where peer #5 sits vs the C#/TS/OCaml/Zig cohort

| Axis | C# (#1) | TS (#2) | OCaml (#3) | Zig (#4) | **CL (#5)** |
|---|---|---|---|---|---|
| Derivation | reference | port | spec-first | spec-first | **spec-first** |
| Distance axis | — | — | (managed) | memory/control-flow | **program model** |
| Dispatch model | single (switch) | single (match) | single (match) | single (comptime) | **CLOS MULTIPLE dispatch** |
| Error model | exceptions | exceptions | result ADT | error unions | **condition system + restarts** |
| Memory | GC | GC | GC | no GC | **GC** |
| Codec | hybrid | hand-rolled | hand-rolled | hand-rolled | **hand-rolled** |
| Third-party deps | NSec, BouncyCastle, … | @noble/curves | mirage-crypto, digestif | ZERO (std-only) | **ONE (ironclad)** |
| Int carrier | native `ulong` | `bigint` (F7) | unsigned-`int64` (A-OC-001) | native `u64`+trap | **native bignums (unbounded)** |
| Ed448 agility | BouncyCastle | @noble | native gap (FFI, A-OC-002) | native gap (A-ZIG-002) | **NATIVE pure-Lisp (ironclad)** |
| Core verdict | 0 FAIL | 0 FAIL | 0 FAIL | 0 FAIL | **0 FAIL** |
| Conformance split | 285P/194W | 285P/194W | 284P/195W | 284P/195W | **284P/195W (= OCaml)** |
| Total checks | 552 | 552 | 558 | 568 | **568** (v7.74 oracle) |

**Position:** peer #5 is the cohort's **convergence stress-test along the second orthogonal idiom
axis** — *program model* (multiple dispatch + condition system + bignums + image-based dev), where
Zig stressed *memory/control-flow*. It confirms every wire-touching decision converges even when
the dispatch model and error model are structurally different from all four prior peers; it is the
first peer that *could* have diverged on dispatch shape (A-CL-008) and didn't, making it the
cohort's headline *idiom-neutrality* probe; it independently re-confirms the two highest-value
standing spec defects (peer-id A-CL-002 = third spec-first corroboration; format_code A-CL-007 =
second independent); and it surfaced **one genuinely-new spec defect (hex-case A-CL-009)** that
four lowercase-defaulting stdlibs hid by accident. It is also the cohort's **agility-primitive-
complete native peer** (Ed25519 + Ed448 + SHA-256/384 from one pure-Lisp library, zero FFI). The
568-vs-552 total is purely the newer v7.74 oracle (+16 checks vs the C#/TS era), not a scope
difference; the 284P/195W split is the **identical fixed point as OCaml**.

**On the crypto-agility higher bar (A-CL-005), as a documented item.** Unlike OCaml (A-OC-002,
FFI) and Zig (A-ZIG-002, deferred — no Ed448 in the ecosystem), CL has the agility *primitives*
natively and byte-proven (Ed448 + SHA-384, RFC-8032-KAT-gated at S2). What remains a **cohort-wide
deferral** is the agility *full MATRIX* harness — the M2/M3/M6 cross-product corpus that exercises
every key-type × hash-format combination end-to-end (OCaml wired a 25/25 slice via `run-agility.sh`;
the full matrix is not wired for any peer). For CL the primitives are done; only the matrix harness
is deferred. This does **not** affect the §9.1 conformance floor (Ed25519 + SHA-256, 69/69 byte-green)
nor the connect-path agility slice. **It is an explicit non-v0.1 item, logged not papered over.**

---

## PART B — Publishing options (operator-decides)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface; the
recommendation is at the end. **No action is taken on it.**

### B.1 In-repo vs standalone repo

**Option 1 — keep in-repo under `protocol-generator/common-lisp/` (current keystone default).**
Per-language sibling repos are deferred keystone-wide (S10); all five peers live in the keystone
monorepo today.
  - *For:* zero lift cost; shared spec-data / test-vectors / oracle stay co-located (the peer reads
    `../shared/...` directly); cross-peer changes (spec bumps) land atomically across all peers; the
    runbooks' relative paths already assume this root.
  - *Against:* a CL consumer would register the *whole keystone repo* with Quicklisp/Ultralisp (both
    index git repos) rather than a minimal peer repo; the ASDF system is `.pathname`-scoped to
    `src/`/`test/` so the load surface is clean, but the indexed repo is keystone-wide.

**Option 2 — lift to a standalone `entity-core-protocol-common-lisp` repo (S10).**
  - *For:* a clean, minimal surface for a Quicklisp/Ultralisp index entry (just the peer + its
    `.asd`); an independent version cadence; the `repository_url` becomes concrete; the natural home
    for any CI workflow.
  - *Against:* the lift must vendor or submodule `shared/spec-data` + `test-vectors` + the oracle
    (the peer can't conform without them); spec bumps then require a cross-repo sync; it is an S10
    step the keystone has **deliberately deferred cohort-wide** — doing it for CL alone fragments the
    uniform "all peers in-repo" posture.

### B.2 Distribution mechanism (Common-Lisp-specific)

CL has **two community dists, both indexing git repositories** (no upload-an-artifact registry):
  - **(a) Quicklisp** — the de-facto community dist. Monthly, immutable-once-published dists; a
    package is a git repo registered with the dist maintainer. "Publishing" = getting the repo into
    a dist build. Consumers then `(ql:quickload :entity-core)`. This is the mainstream path.
  - **(b) Ultralisp** — a faster-moving alternative dist that auto-rebuilds from a registered git
    repo on push (closer to "continuous publishing"); same `ql:quickload` consumer surface once the
    Ultralisp dist is added. Appropriate if a faster cadence than Quicklisp's monthly is wanted.
  - **(c) Direct ASDF (no dist at all)** — a consumer clones/submodules the repo and adds it to
    `asdf:*central-registry*` (or symlinks the `.asd` into `~/common-lisp/`). Fully offline,
    audit-friendly, the same supply-chain stance as the keystone; no dist submission needed. This is
    how the peer is consumed *today* (the runbooks push the worktree onto the central registry).

The **single-dependency posture** (`ironclad` only) makes distribution light: a consumer inherits
one transitive crypto dep (itself pulling nibbles + alexandria), not a lockfile fan-out — lighter
than C#'s multi-provider graph, heavier than Zig's std-only zero.

### B.3 License / version posture

  - **License: Apache-2.0** (keystone S9 default; explicit patent grant). The CL ecosystem is
    license-mixed (MIT/BSD/LLGPL common; `ironclad` is BSD-3) but mandates nothing, so the safe
    Apache-2.0 default stands (`profile.toml [license]` — not overridden). No change recommended.
  - **Version: `0.1.0-pre` LINE** (set this phase). The cohort-wide pre-release line. ASDF's
    `:version` field is dotted-integer only and cannot carry the `-pre` suffix (A-CL-010), so the
    `.asd` carries the parseable `0.1.0` and the `-pre` marker lives in CHANGELOG/README. **Promotes
    to `0.1.0`** only when (a) S4 fully green [met] AND (b) ≥1 external consumer confirms it works
    [not yet met — the C#-class "Avalonia confirms" analogue]. `CHANGELOG.md` tracks the spec
    version literally.
  - **Agility full MATRIX** is the documented non-v0.1 item: primitives are native + byte-proven
    (Ed25519 + Ed448 + SHA-256/384, RFC-8032-KAT-gated); only the M2/M3/M6 cross-product matrix
    harness is deferred (cohort-wide). No FFI, no second crypto provider needed when it lands.

### B.4 Recommendation (operator-decides — not acted on)

**Keep the peer in-repo under `protocol-generator/common-lisp/` for v0.1, consume via direct ASDF
(`asdf:*central-registry*`) or a Quicklisp/Ultralisp index entry on the keystone repo, at the
`0.1.0-pre`/Apache-2.0 line.** Rationale: the standalone-repo lift (S10) is deferred cohort-wide
and lifting CL alone fragments the uniform posture for marginal benefit before any consumer exists;
the `.pathname`-scoped ASDF system already gives a clean load surface from the monorepo; and the
single-dependency profile means there is no distribution friction to solve. **Lift to a standalone
repo + register a dedicated Quicklisp/Ultralisp entry at the same time the cohort does** (when arch
defines the S10 per-language-repo + CI home), promoting to `0.1.0` once the external-consumer gate
is met. Hold the **agility full MATRIX** as an explicit post-v0.1 item (primitives done; matrix
harness deferred). This is a recommendation only — **the operator decides; the pipeline does not
publish, tag, or push.**

---

## C. Summary for arch (one paragraph)

Peer #5 vindicates the convergence thesis along the cohort's *second orthogonal* idiom axis — a
homoiconic, CLOS-multiple-dispatch, condition-system, native-bignum, image-based language reached
the **identical 0-FAIL / 284P/195W fixed point as OCaml**, spec-first, with every program-model
seam landing at impl locality and **zero wire-byte divergence.** Its highest-value contributions
are (1) the cohort's headline *idiom-neutrality* probe — the first peer that *could* have diverged
on dispatch shape (CLOS multiple dispatch, A-CL-008) and didn't, confirming §6.6 is specified at the
right altitude; (2) **one genuinely-new spec defect — A-CL-009 ⚑ address-space hex-case is
unspecified in §3.4/§3.5** (tree paths are case-sensitive keys; four lowercase-defaulting stdlibs
hid it by accident, the first uppercase-defaulting stdlib surfaced it) — a real interop trap; (3)
independent corroboration of the two standing spec defects — §7.4-vs-§1.5 peer-id construction
(A-CL-002 ⚑, now **three** spec-first peers) and the format_code-128 construct/receive asymmetry
(A-CL-007 ⚑, now **two** spec-first peers); and (4) the cohort's agility-primitive-complete native
crypto (Ed25519 + Ed448 + SHA-256/384 from one pure-Lisp library, zero FFI). The actionable arch
asks are three ⚑ items: **state hex-case (lowercase) normatively in §3.4/§3.5** (A-CL-009, new);
**ratify the §1.5-canonical peer-id construction in §7.4** (A-CL-002, three-peer); and **state the
format_code construct/receive split in §4.3/§4.7** (A-CL-007, two-peer). The v7.73/v7.74 spec-data
snapshot (A-CL-001) remains the standing provenance ask; the agility full MATRIX is a documented,
non-v0.1, primitives-already-native item.
