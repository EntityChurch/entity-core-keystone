# Architecture Review — entity-core-protocol-ruby (peer #12)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data **v7.75**
(the COMPLETE ratified snapshot — register/outbound/emit §6.13 + §6.9a owner-cap + §7a conformance
handlers AND the §4.8/§4.9/§4.10 substrate floor all present as ratified text); codec corpus
byte-identical v7.73→v7.75. · **Audience:** architecture (spec-tightness feedback) + operators
(publishing decision). · **Status:** peer #12 at `validate-peer --profile core` PASS · 653 / 291P /
268W / **0F** / 94S (oracle `entity-core-go @75c532e`); origination-core 3/3; 53-type registry 53/53.

This review follows the format/depth of the Common-Lisp peer #5 and Java peer #7
`ARCHITECTURE-REVIEW.md`, carried to the **first dynamic / duck-typed / scripting peer** in the
cohort. Part A is the idiom-fidelity + convergence retrospective; Part B is the publishing-options
decision surface; Part C is the one-paragraph arch summary.

---

## 0. The thesis peer #12 was chosen to test

The convergence thesis (three-peer review → reinforced by Zig #4's no-GC distance, CL #5's
program-model distance, and the v7.75 8-peer re-run's uniform 576·0F fixed point): *if the spec is
tight, independently-derived peers converge on the same conformance fixed point with no wire
divergence; the idiom seams diverge cleanly by profile at impl locality; and a spec-first peer
corroborates (or, early in the cohort, surfaces) the spec's load-bearing decisions.* By peer #12 the
cohort spans reference (Go/Rust/Python), GC-managed static-typed (C#, Java), GC-managed gradually-
typed (TS), GC functional (OCaml, Haskell), BEAM-actor (Elixir), homoiconic-multiple-dispatch (CL),
no-GC-systems (Zig), and value-type-ARC (Swift). **The one major idiom axis still unrepresented was
the dynamic / duck-typed / metaprogramming *scripting* language** — open classes, blocks, mixins,
`method_missing`/`send` reflection, and (the concurrency wrinkle) a **Global VM Lock**.

The open question for #12: **does the convergence thesis survive a duck-typed, reflective scripting
idiom whose value model is "whatever responds to the right methods" and whose concurrency runtime
serializes bytecode under a GVL?** If the wire-touching decisions still converge to the cohort fixed
point while the dynamic-idiom seams diverge cleanly, the thesis is confirmed across the *runtime-
typing* axis (orthogonal to Zig's memory axis and CL's program-model axis). If duck-typing or the
GVL forced a *different wire answer* anywhere, that would be a tightness counter-signal.

**Result: the thesis held, on the runtime-typing axis.** Everything that touches the wire converged
to the **same 0-FAIL fixed point as the rest of the cohort** — codec 69/69 byte-identical (first
full run, 0 codec fixes), §9.5 registry 53/53 byte-identical, all 16 core categories 0-FAIL,
origination-core 3/3 over real two-peer TCP. The dynamic-idiom seams (duck-typed `data`, `send`-
reflection dispatch, the GVL concurrency story, arbitrary-precision `Integer`) diverged exactly where
they *should*, at impl locality the spec is correctly silent on, and **none changed a single wire
byte.** Critically — and this is the honest cohort-fit framing — **Ruby surfaced NO new spec defect.**
By peer #12 the well of spec ambiguities is dry: the inherited findings (peer-id §1.5, 401/403
§5.2a, §4.10 resource_bounds, the A-JAVA-010 data-shape, §4.3/§4.7 format_code asymmetry) are folded
normative in v7.75, and Ruby read them *as ratified text* and corroborated them live against the
oracle. Peer #12's contribution is therefore **idiom breadth + convergence evidence**, not a defect.

---

## PART A — Architecture review

### A.1 Did the Ruby (dynamic/scripting) idiom pay off? (the seams, scored)

The bet of generating peer #12 was that a duck-typed, reflective, GVL-concurrency idiom would
*express the protocol differently* from every prior peer and still land on the same wire fixed point.
Scoring the seams the profile called out:

**(1) Duck-typed entity `data` — PAID OFF as the most *natural* statement of A-JAVA-010 in the
cohort.** Java surfaced A-JAVA-010 (§1.1 entity `data` is an arbitrary ECF value, *not* necessarily a
map) as a real interop trap: a map-only model passes S2/S3 then silently 500s on the first scalar-
data entity. Every statically-typed peer must *choose* a sum type (a `sealed interface EcfValue`, a
`type ecf_value = | …`, a tagged union) to carry "any ECF value." Ruby's duck-typing makes this the
**path of least resistance instead of a trap**: `data` is simply "whatever ECF value the codec
round-trips" — a `String`, `Integer`, `Float`, `Array`, `Hash`, `true/false/nil` — with no carrier
type to get wrong. The codec dispatches on `case value when Integer … when ::String … when Hash …`
(plus the ASCII-8BIT-vs-text `String` distinction for the byte-`data`/text axis), never assuming a
`Hash`. **The payoff:** the peer that could most easily have hard-coded the map-only assumption is
the one for which the general model is the *idiomatic* one — a convergence data point that the
A-JAVA-010 generalization is right (a scalar-data entity stores and relays correctly), reached by a
*different mechanism* (runtime duck-typing) than the statically-typed peers' explicit sum types.
**Verdict:** the duck-typed value model lands on the same wire behavior as the cohort's sum-typed
models — confirming §1.1's "arbitrary ECF value" is idiom-neutral and that A-JAVA-010 is a genuine
generalization, not a Java-specific artifact.

**(2) `send`-reflection §6.5/§6.6 dispatch — PAID OFF as the 12th independent dispatch arrival.**
The cohort has now expressed §6.6 operation dispatch as: a single-dispatch `switch` (C#/Java), a
pattern-match `match`/`case` (TS/OCaml/Elixir/Haskell/Swift), a `comptime` ladder (Zig), and CLOS
**multiple** dispatch (CL, A-CL-008). Ruby adds a 12th independent arrival: a **`send`-reflection op
ladder** — the dispatch key `(handler, operation)` resolves a handler instance and the operation
selects a method, idiomatically reachable by `handler.public_send(op_method, …)` /
a `respond_to?`-guarded reflective call, with "unknown operation → 501" as the no-such-method
fallback. This is the dynamic-language analogue of CL's "501 is the default method": the *open*,
reflective dispatch surface. The payoff is the same idiom-neutrality signal CL produced from the
other end of the spectrum — **a reflective, runtime-resolved dispatch idiom converges on byte/
behavior-identical §6.6 dispatch with zero spec ambiguity surfaced**, because §6.6 names the dispatch
*key*, not a dispatch *mechanism*. Twelve idioms — static switch, pattern match, comptime, CLOS
multiple dispatch, and now `send`-reflection — all converge. **Verdict:** the widest-possible span of
dispatch mechanisms produces no wire divergence; §6.6 is specified at the right altitude.

**(3) The GVL concurrency story — PAID OFF as fidelity, no wire effect; an honest accounting
(A-RUBY-004).** Deliberate divergence: MRI/CRuby has a **Global VM Lock** — native OS `Thread`s exist
and the scheduler is preemptive, but only one thread runs Ruby bytecode at a time. The load-bearing
nuance the profile insisted on accounting for honestly: **the GVL is *released* during blocking IO**
(socket read/write/accept, and OpenSSL C calls), so a **thread-per-connection** peer is genuinely
concurrent for this **IO-bound** workload (§4.8/§4.9/§7b) — while one thread blocks in `recv`, others
run. The §6.11 reentrant demux is a `pending {request_id => Waiter}` map + `ConditionVariable`; the
per-connection write is `Mutex`-guarded. The subtle, *correct* point: **the GVL does NOT make a
compound read-then-write atomic**, so the §3.9 CAS store still needs an explicit `Mutex` critical
section — proven load-bearing by a 64-thread CAS-from-absent race that yields **exactly one winner**
(`test/peer_test.rb`). The cohort invariant — *protocol status is a value record, never carried by
the error type across dispatch* — holds for the same reason it held everywhere. **Ractors** (MRI's
true-parallel, no-shared-GVL primitive) are declined: their share-nothing object model fights the
shared store and they remain experimental — the wrong tool at core; noted as the parallelism escape
hatch. **Verdict:** the GVL concurrency model meets §4.8/§4.9/§6.11/§7b with no wire effect — the
thread-per-connection shape is the same cohort shape (OCaml threads, CL `sb-thread`, Zig
`std.Thread`, Swift connection-actors), reached under a fundamentally different scheduling
constraint, and the honest GVL accounting (concurrent-on-IO, not-atomic-on-compound) is the
Ruby-specific contribution to the concurrency ledger.

**(4) Native full crypto-agility via stdlib `openssl` — PAID OFF as the 3rd native-full-agility
substrate, zero FFI (A-RUBY-002/003).** This is the headline crypto contribution. The agility higher
bar (v7.67) needs Ed25519 + **Ed448** + SHA-256/384/512. The cohort's crypto-agility ledger:
OCaml sourced Ed448 over a C-ABI (A-OC-002, hybrid FFI); Zig has no Ed448 at all (A-ZIG-002,
deferred); Swift the same native gap (A-SW-001); Java closes sign/verify via SunEC but hand-rolls the
SHAKE256 + seed→public raw-pubkey gap (A-JAVA-007, ~250 lines); C# reaches for BouncyCastle. The
**native-full-agility** club — both curve families *and* the SHA family from one in-stdlib source,
**no FFI, no second provider** — was Elixir (`:crypto`, A-ELX-002) and Haskell (crypton, A-HS-007).
**Ruby is the third member, and the first via OpenSSL stdlib:** the bundled `openssl` gem (OpenSSL
3.x backend, ships with Ruby 3.4) reaches *both* Ed25519 AND Ed448 through the identical generic
PKey path (`OpenSSL::PKey.new_raw_private_key(alg, seed)` / `sign(nil, msg)` / `verify(nil, sig,
msg)` / `raw_{private,public}_key`), plus SHA-256/384/512 via `OpenSSL::Digest`/`Digest`. Byte-
verified against the v7.67 agility pins (Ed448 seed→pubkey, peer_id, the `system/peer` content_hash,
the 114-byte signature). **Verdict:** Ruby is the cohort's third zero-FFI both-curve peer — the most
*available* full-agility substrate (OpenSSL ships with the runtime; no opt-in sub-library, no NIF, no
C-ABI), demonstrating the agility bar is reachable from a vendor-curated stdlib on a third
independent crypto backend.

**(5) Arbitrary-precision `Integer` — PAID OFF as a clean int story, by the BEAM mechanism.** The
§3.2 CBOR head-form carrier is full 0..2⁶⁴−1. The cohort's int-carrier ledger is a catalogue of
workarounds: OCaml's 63-bit-int trap (A-OC-001, can't hold `2⁶³−1`), TS's escalation to `bigint`
(F7), C#/Java's `ulong`/`BigInteger` choice (no native unsigned), Zig's fixed-width `u64`+overflow-
trap. Ruby — like Elixir/CL on the BEAM/bignum mechanism — has **arbitrary-precision `Integer`**: an
int that exceeds a fixnum transparently promotes with no type change, no carrier struct, no
reinterpretation. The codec reads/writes the full u64 range as ordinary `Integer`s. **Verdict:**
Ruby joins Elixir, CL (bignums), and Zig (fixed-width+trap) as a cohort member whose native integer
model fits §3.2 with *zero* workaround — by the unbounded-integer mechanism. The standing corpus
blind-spot — `[2⁶³, 2⁶⁴−1]` unexercised (F7 / A-OC-001 / A-ZIG-005) — is the same here: Ruby is
correct-by-construction across it, but the *corpus still doesn't probe it*, so the corroboration is
structural, not test-witnessed.

**Net: all five seams paid off** — duck-typed `data` as the most natural statement of A-JAVA-010, the
`send`-reflection ladder as the 12th independent dispatch arrival, the GVL story as an honest
concurrency accounting (concurrent-on-IO / not-atomic-on-compound), native-full-agility on a 3rd
substrate (zero FFI), and the arbitrary-precision int story. Critically, **none changed a wire byte**
— the seams landed at impl locality, which is the convergence thesis holding under the cohort's
runtime-typing distance (the orthogonal axis to Zig's memory and CL's program-model distance).

### A.2 Spec-refinement value — what Ruby contributed (the honest "dry well" note)

The keystone's *end* is spec refinement. **Peer #12's harvest of NEW spec defects is empty — and
that is itself the finding.** By the 12th peer (10th byte-compatible impl), the spec ambiguities that
the early spec-first peers surfaced (peer-id §7.4-vs-§1.5, 401/403 §5.2a, format_code §4.3/§4.7
asymmetry, address-space hex-case, the §1.1 data-shape) are **folded normative in v7.75**, and Ruby
reads them as ratified text. Ruby therefore **corroborated rather than re-litigated**:

- **Peer-id §1.5 canonical form** — read from the v7.75 §1.5 table (not the stale §7.4 pseudocode);
  the seed-`0x11` peer_id is byte-identical to the cohort. No re-derivation burn (the §1.5 form was
  baked into the profile at S1 precisely because OCaml/Zig/CL/Swift/Java already established it).
- **401/403/401 §5.2/§5.2a trichotomy** — read as the v7.73-E2-folded normative verdict; live 0-FAIL
  on the authz category. (The 5-peer convergence that *produced* the fold is the spec history; Ruby
  is post-fold corroboration.)
- **§4.10 resource_bounds** (413 payload_too_large + the 403→400 chain-depth ruling) — read as v7.75
  floor MUSTs; both live PASS. This was *net-new for the whole 8-peer re-run cohort* in v7.75; Ruby
  implemented it directly from ratified text with no debug cycle.
- **A-JAVA-010 data-shape** — generalized from S2; the duck-typed model makes it the natural state
  (see A.1(1)). Corroborated on a dynamically-typed peer.
- **Lowercase hex** (the A-CL-009 trap) — rendered lowercase everywhere from the start; live 0-FAIL
  on the register grant-signature path + §5.1 revoke marker (the paths CL's uppercase default broke
  on). Ruby's stdlib hex (`%02x` / `unpack1("H*")`) defaults lowercase, so it never hit the trap —
  another lowercase-defaulting stdlib, but post-A-CL-009 the rendering is *deliberately* lowercased,
  not accidentally.

**The single NEW item is a packaging wrinkle, not a spec defect — A-RUBY-010 (RubyGems version
spelling).** RubyGems treats a literal `-` in a version string as a `.pre.` separator, so the cohort
`0.1.0-pre` label canonicalizes to the malformed `0.1.0.pre.pre`; the idiomatic pre-release spelling
is the dotted `0.1.0.pre`. This is the exact distant-idiom packaging shape as Common Lisp's A-CL-010
(ASDF's dotted-integer-only `:version` rejecting `0.1.0-pre`) — two ecosystems whose version grammar
disagrees with the SemVer-dash, against the SemVer-suffix-accepting majority (Maven `-pre`, opam,
build.zig.zon, package.json, mix.exs, Cargo). **Escalation: operator** — recorded for future
promotions; no spec impact.

**What the dry well *means* for the review ledger (informational, routed to arch):** the 12th peer
finding nothing new is the **convergence thesis's strongest single data point** — the spec is tight
enough that a maximally-distant *runtime-typing* idiom, derived spec-first, reaches the cohort fixed
point with zero new ambiguity. Eleven prior peers across reference, GC-static, GC-functional, BEAM,
homoiconic, no-GC, and value-type idioms drained the ambiguity well; the dynamic/scripting idiom
confirms the bottom is reached. This is the "tightness signal" CL's A-CL-008 was for dispatch,
generalized to the *whole spec surface*: by peer #12 there is nothing left to surface.

### A.3 Codec / transport design retrospective

**Codec — convergent, native, full-agility, zero runtime gem.** Hand-rolled canonical CBOR (the
pattern every native peer hit, now 12-for-12 — A-RUBY-001): shortest-float ladder (f16⊂f32⊂f64,
narrowest bit-exact round-trip — with the Ruby-specific wrinkle that `Array#pack` has *no half-float
directive*, so f16 is assembled from the binary64 bits, A-RUBY-006), length-then-lex map-key sort on
encoded key bytes, recursive major-type-6 tag rejection, arbitrary-precision-`Integer` head-form
carrier. Wire bytes are ASCII-8BIT (`String#b`) throughout — the byte/text `String` distinction is
the Ruby analogue of the cohort's byte-buffer discipline (Haskell's `ByteString`, Swift's
grapheme→UTF-8-byte axis A-SW-002). 69/69 byte-identical, first full run, **0 codec fixes** — the
codec was byte-green before the peer existed, so the only S4 risk was field-shape *data* (caught
per-type by the 53/53 registry byte-diff via render-from-shapes, decoded by the Ruby codec and
asserted equal to the Go reference, *not* ingested), not codec behavior. The supply-chain posture is
the cohort's lightest tier: **zero runtime gem dependencies** — crypto/hashing from stdlib openssl/
digest, CBOR/base58/varint hand-rolled, Minitest+Rake dev-only default gems. Lighter than C#'s
multi-provider graph and Swift's one SwiftPM dep; tied with Elixir/Haskell/Java/Zig at the zero-
runtime-dep floor, and uniquely reaching *full crypto agility* there via OpenSSL stdlib (no FFI).

**Transport — convergent shape, native-thread primitive under the GVL (A-RUBY-004).** The shape is
the spec-forced cohort shape: 4-byte BE length-prefix + CBOR frame; one reader `Thread` per
connection demuxing `EXECUTE_RESPONSE` by `request_id` (N7); inbound EXECUTE dispatched on its own
`Thread` so it never blocks outbound (N6); a transport-agnostic dispatch brain. The *primitive* is
MRI `Thread` + a `Mutex`-guarded `pending {request_id => Waiter}` correlation table +
`ConditionVariable` — the direct Ruby analogue of OCaml's per-thread-blocking + condvar, CL's
`sb-thread` + waitqueue, Java's `ConcurrentHashMap` rendezvous. `TCP_NODELAY` on every socket (the
Zig small-frame-throughput lesson). All stdlib `socket`/`thread` — **no dependency**. The S3 smoke
proved 8 concurrent EXECUTEs each correlate to their own response (8/8 over real loopback), and
origination-core's `dispatch_outbound_reentry` proved the §6.11 reentry seam over real two-peer TCP
(carry-in exercised, not SKIPped). One Ruby-specific transport note (S4): the `exe/entity-core-peer`
host's signal trap uses `exit!(0)` rather than `listener.close`, because killing the accept-loop
`Thread` while it is blocked in the C `accept(2)` CFUNC segfaults MRI (`Thread#kill` racing a
blocking CFUNC) — the harness tears down the whole container, so a hard exit is the race-free
shutdown. **Retrospective verdict:** the native-thread-under-GVL choice is correct for the IO-bound
core floor and zero-dep; the honest GVL accounting is the contribution.

### A.4 Where peer #12 sits vs the cohort

| Axis | static-OO (C#/Java) | pattern-match (TS/OCaml/Elixir/Haskell/Swift) | CLOS (CL) | no-GC (Zig) | **Ruby (#12)** |
|---|---|---|---|---|---|
| Derivation | reference / spec-first | spec-first | spec-first | spec-first | **spec-first** |
| Distance axis | (mainstream) | (functional / BEAM / value-type) | program model | memory/control-flow | **runtime typing (dynamic/duck/scripting)** |
| Typing | static | static / gradual | dynamic (typed values) | static+comptime | **dynamic / duck-typed** |
| Dispatch model | single (switch) | single (match) | CLOS MULTIPLE | comptime | **`send`-reflection ladder (12th arrival)** |
| Error model | exceptions / checked | result / tagged-tuple / typed-throws | condition system | error unions | **`StandardError` exception lattice** |
| Concurrency | threads / virtual threads | threads / BEAM procs / green threads / actors | `sb-thread` | `std.Thread` | **thread-per-conn under the GVL (honest accounting)** |
| Codec | hybrid / hand-rolled | hand-rolled | hand-rolled | hand-rolled | **hand-rolled** |
| Runtime deps | multi / zero | one / zero | one (ironclad) | ZERO | **ZERO (stdlib openssl/digest)** |
| Int carrier | `ulong` / `BigInteger` | `bigint` / int63-trap / native | native bignums | `u64`+trap | **arbitrary-precision `Integer` (no trap)** |
| Ed448 agility | BouncyCastle / SunEC+handroll | @noble / FFI / native-gap / crypton-native | NATIVE pure-Lisp | native gap | **NATIVE stdlib openssl, ZERO FFI (3rd substrate)** |
| Core verdict | 0 FAIL | 0 FAIL | 0 FAIL | 0 FAIL | **0 FAIL** |
| NEW spec defect | (early-cohort) | (early-cohort) | A-CL-009 hex-case | A-ZIG-006 401/403 | **NONE — dry well; corroboration-only** |

**Position:** peer #12 is the cohort's **convergence confirmation along the runtime-typing axis** —
*dynamic / duck-typed / scripting* (open classes, blocks, `send`-reflection, the GVL), the one major
idiom family unrepresented through peer #11. It confirms every wire-touching decision converges even
when the value model is duck-typed and the runtime serializes bytecode under a GVL; it is the **12th
independent dispatch arrival** (`send`-reflection joins static-switch / pattern-match / comptime /
CLOS-multiple); it makes A-JAVA-010's "arbitrary ECF value" the *idiomatic* state rather than a trap;
it is the cohort's **third native-full-crypto-agility substrate** (Ed25519 + Ed448 + SHA-2 from
stdlib OpenSSL, zero FFI — after Elixir/Haskell); and — the headline cohort-fit result — it surfaced
**zero new spec defects**, corroborating the now-ratified v7.75 findings live against the oracle. The
653-vs-576 total is purely the later oracle's auto-skipped extension categories (`relay`/`discovery`/
`registry`/`published_root`), not a scope difference; the FAIL gate and every core category match the
cohort 0-FAIL fixed point.

**On the crypto-agility higher bar (A-RUBY-002), as a documented item.** Ruby has the agility
*primitives* natively and byte-proven (Ed448 + SHA-384 via stdlib openssl, zero FFI) AND the M2/M3/M6
`root_cap` cap-token shapes byte-confirmed (A-RUBY-007). What remains a **cohort-wide deferral** is
the agility *full MATRIX* harness — the M2/M3/M6 key-type × hash-format cross-product exercised
end-to-end (no peer has it fully wired). For Ruby the primitives are done and the cap-token shapes
are proven; only the matrix harness is deferred. This does **not** affect the §9.1 conformance floor
(Ed25519 + SHA-256, 69/69 byte-green) nor the connect-path agility slice. **It is an explicit
non-v0.1 item, logged not papered over.**

---

## PART B — Publishing options (operator-decides)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface; the
recommendation is at the end. **No action is taken on it.**

### B.1 In-repo vs standalone repo

**Option 1 — keep in-repo under `protocol-generator/ruby/` (current keystone default).**
Per-language sibling repos are deferred keystone-wide (S10); all peers live in the keystone monorepo
today.
  - *For:* zero lift cost; shared spec-data / test-vectors / oracle stay co-located (the peer reads
    `../shared/...` and `run-s4.sh` builds the oracle from the co-located `entity-core-go`);
    cross-peer changes (spec bumps) land atomically; the runbooks' relative paths assume this root.
  - *Against:* a RubyGems consumer installs from a published `.gem`, not from the repo layout, so the
    in-repo `gemspec` `spec.files` (`lib/**/*.rb` + LICENSE/README/CHANGELOG) already scopes a clean
    artifact — but `repository_url` / the gemspec homepage links stay unset until a repo is chosen.

**Option 2 — lift to a standalone `entity-core-protocol-ruby` repo (S10).**
  - *For:* a clean minimal surface; an independent version cadence; a concrete `repository_url` /
    `homepage` / `source_code_uri` / `changelog_uri` (RubyGems validates these as real http(s) URLs —
    they are deliberately UNSET today, which is why `gem build` warns "no homepage specified"); the
    natural home for a CI workflow.
  - *Against:* the lift must vendor or submodule `shared/spec-data` + `test-vectors` + the oracle
    (the peer can't conform without them); spec bumps then require a cross-repo sync; it is an S10
    step the keystone has **deliberately deferred cohort-wide** — doing it for Ruby alone fragments
    the uniform "all peers in-repo" posture.

### B.2 Distribution mechanism (Ruby-specific)

RubyGems is a **real upload-an-artifact registry** (`https://rubygems.org`) — `gem push
entity_core_protocol-0.1.0.pre.gem` after a `gem signin` / API-key step. Contrast the
git-repo-indexed dists (Quicklisp/Ultralisp for CL, build.zig.zon URLs for Zig). Two RubyGems
specifics:
  - **The gem id `entity_core_protocol`** (snake_case, no redundant `_ruby` suffix; A-RUBY-005, the
    Elixir-Hex-id reasoning) must be **confirmed non-squatted** before first push; fall back to
    `entity_core_protocol_ruby` if taken. This is a one-time operator check.
  - **Pre-release coordinate `0.1.0.pre`** (A-RUBY-010): `gem push` of a `.pre` gem is fine; consumers
    only get it with an explicit `gem install entity_core_protocol --pre` or a `gem
    "entity_core_protocol", "0.1.0.pre"` Gemfile pin (RubyGems hides pre-releases from default
    resolution) — which is exactly the right behavior for an unpromoted peer.

The **zero-runtime-gem-dependency posture** makes distribution maximally light: a consumer of the
published gem inherits *no* transitive runtime deps (crypto/hashing from stdlib openssl/digest); the
only pin a consumer takes is Ruby `>= 3.2` (for `Data.define` + openssl ≥ 3.0). Lighter than C#'s
multi-provider graph; tied with Elixir/Haskell/Java/Zig at the zero-dep floor.

### B.3 License / version posture

  - **License: Apache-2.0** (keystone S9 default; explicit patent grant). The Ruby gem ecosystem is
    MIT-heavy with no mandate (Ruby itself is Ruby-license/BSD-2), so the safe Apache-2.0 default
    stands (`profile.toml [license]` — not overridden). No change recommended.
  - **Version: `0.1.0-pre` line, gem coordinate `0.1.0.pre`** (set this phase). RubyGems treats the
    SemVer-dash `-pre` as a `.pre.` separator (→ malformed `0.1.0.pre.pre`), so the gemspec carries
    the dotted `0.1.0.pre` (canonicalizes to itself; `.prerelease?` true) and the prose/CHANGELOG/
    README carry the cohort `0.1.0-pre` label (A-RUBY-010 — the Ruby analogue of CL's A-CL-010).
    **Promotes to `0.1.0`** only when (a) S4 fully green [met] AND (b) ≥1 external consumer confirms
    it works [not yet met — the C#-class "Avalonia confirms" analogue].
  - **Agility full MATRIX** is the documented non-v0.1 item: primitives are native + byte-proven
    (Ed25519 + Ed448 + SHA-256/384 via stdlib openssl, zero FFI) and the M2/M3/M6 cap-token shapes
    are byte-confirmed (A-RUBY-007); only the cross-product matrix harness is deferred (cohort-wide).

### B.4 Recommendation (operator-decides — not acted on)

**Keep the peer in-repo under `protocol-generator/ruby/` for v0.1 at the `0.1.0.pre` / Apache-2.0
line; the publish-ready `.gem` builds clean today (zero runtime deps, valid gemspec, the only warning
being the deliberately-unset homepage).** Rationale: the standalone-repo lift (S10) is deferred
cohort-wide and lifting Ruby alone fragments the uniform posture for marginal benefit before any
consumer exists; the gemspec `spec.files` already scopes a clean artifact from the monorepo; and the
zero-dependency profile means there is no distribution friction to solve. **Lift to a standalone repo
+ set the gemspec homepage/source/changelog URLs + `gem push` at the same time the cohort does** (when
arch defines the S10 per-language-repo + CI home), confirming the `entity_core_protocol` id is
non-squatted (A-RUBY-005) and promoting to `0.1.0` once the external-consumer gate is met. Hold the
**agility full MATRIX** as an explicit post-v0.1 item. This is a recommendation only — **the operator
decides; the pipeline does not publish, tag, or push.**

---

## C. Summary for arch (one paragraph)

Peer #12 vindicates the convergence thesis along the cohort's **runtime-typing axis** — a dynamic,
duck-typed, reflective scripting language with a Global VM Lock reached the **same 0-FAIL fixed point
as the cohort**, spec-first, with every dynamic-idiom seam landing at impl locality and **zero
wire-byte divergence.** Its contributions are **idiom breadth + convergence evidence, not a new
defect** (the honest cohort-fit framing — by peer #12 the spec-ambiguity well is dry): (1) the **12th
independent dispatch arrival** — a `send`-reflection op ladder joining static-switch / pattern-match
/ comptime / CLOS-multiple, all converging on §6.6, confirming the dispatch surface is mechanism-
agnostic across the widest possible span; (2) **duck-typed entity `data`** making A-JAVA-010's
"arbitrary ECF value" the *idiomatic* state rather than a trap, corroborating that generalization on
a dynamically-typed peer; (3) the cohort's **third native-full-crypto-agility substrate** (Ed25519 +
Ed448 + SHA-2 from stdlib OpenSSL, **zero FFI** — after Elixir/Haskell, and the first via OpenSSL);
(4) an **honest GVL concurrency accounting** (thread-per-connection is genuinely concurrent on
blocking IO, but the GVL does NOT make compound read-then-write atomic, so the §3.9 CAS store needs
an explicit Mutex — proven by a 64-thread one-winner race); and (5) the **arbitrary-precision
`Integer`** int story (no uint64 head-form trap — the BEAM result, replicated). The single NEW item
is a packaging wrinkle, not a spec defect: **A-RUBY-010** (RubyGems treats `0.1.0-pre` as
`0.1.0.pre.pre`; idiomatic spelling is dotted `0.1.0.pre`) — the Ruby analogue of CL's A-CL-010, owner
operator. **There are no ⚑ arch asks from this peer** — Ruby read the now-ratified v7.75 findings
(peer-id §1.5, 401/403 §5.2a, §4.10 resource_bounds, the §1.1 data-shape, lowercase hex) as text and
corroborated them live against the oracle. A 12th peer finding nothing new is the convergence thesis's
strongest single data point: the spec is tight enough that a maximally-distant runtime-typing idiom,
derived spec-first, reaches the cohort fixed point with zero new ambiguity.
