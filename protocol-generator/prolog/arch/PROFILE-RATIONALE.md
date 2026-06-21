# entity-core-protocol-prolog — Profile Rationale

Audit trail for every major S1 profile choice. Prolog is an **EXPERIMENTAL PROBE**
of the **logic / declarative paradigm** — the first logic-programming peer, and the
most paradigm-distant probe attempted. Each choice below was derived from the V7
spec + SWI-Prolog ecosystem research, **not** ported from the
C#/TS/OCaml/Elixir/Zig/CL/Swift/Haskell/Java profiles. Where a value matches a prior
peer it is by independent arrival; the idiom seams (DCG binary grammars, unification
decode, failure-vs-exception error model, the clause database as store) deliberately
differ.

**Read the "Does this idiom map?" section at the bottom first if you only read one
thing — it carries the honest go/defer verdict S1 exists to produce.**

---

## Why Prolog is a worthwhile probe (and why it might NOT map)

The prior peers spanned static-OO (C#), gradual-structural (TS), functional-static
(OCaml), actor-dynamic (Elixir), no-GC-systems (Zig), homoiconic-CLOS (CL),
protocol-oriented (Swift), pure-lazy-functional (Haskell), and JVM-OO (Java). Every
one of them is, at bottom, an **imperative or functional** program model: you
*compute a value* or *execute a sequence*. Prolog is neither. Its computation model
is **SLD-resolution over a Horn-clause database**: you *declare relations* and the
engine *searches* (with unification + backtracking + the cut) for terms that satisfy
them. That is a genuinely orthogonal axis — and exactly why it is worth probing
whether the V7 spec's contracts assume a non-relational model anywhere.

But the same orthogonality is the risk. A core protocol peer is, irreducibly:
**read N bytes from a TCP stream → decode canonical CBOR → check a capability chain →
mutate a store → write N bytes back**. Four of those five steps are *effectful,
sequential, byte-exact* operations. Logic programming's strength is **search over a
relational model**; this peer has **almost no search** and a great deal of
**ordered side-effecting I/O**. The honest question — answered at the bottom — is
whether the parts that *do* fit (the CBOR grammar as a DCG; capability-chain walking
as a recursive relation) are enough idiom to justify the build, or whether the
byte-exact I/O + canonical-ordering scaffolding swamps them.

## Codec strategy: native (primitives + crypto native), FFI the documented — and likelier — fallback

`research/LANDSCAPE.md` carries no committed strategy for Prolog (it is a probe, not
a planned cohort slot). Research lands it as **native** for the §9.1 floor, with two
caveats sharper than any prior peer's:

1. **Crypto via `library(crypto)`.** SWI-Prolog bundles `library(crypto)` (the
   crypto/ssl extension over the system OpenSSL). On an OpenSSL-3 image it provides
   `ed25519_new_key/sign/verify` and `crypto_data_hash/3` (SHA-256/384/512). So the
   floor (Ed25519 + SHA-256) is **native, no pack dependency, no FFI** — *if* the
   in-container OpenSSL is v3 and the bundled `library(crypto)` exposes the ed25519
   predicates. Because swipl is not runnable under the S1 no-build boundary, that
   availability is asserted from SWI documentation and **gated A-PL-002 at S2** (the
   honest S1 posture — the same "confirm the exact symbol at S2" the CL profile took
   for ironclad). If the predicates are absent on the pinned image, the FFI fallback
   (C-ABI `ec_ed25519_*`) is the documented route (A-PL-003).

2. **No SWI CBOR pack gives ECF canonicality** — the A-005 pattern **all six prior
   native peers hit** (now seven). The SWI pack list has no maintained CBOR pack
   targeting ECF's length-then-lex map ordering, shortest-float ladder (incl. f16),
   recursive tag-6 rejection, or full uint64/nint range. Hand-rolling the canonical
   layer is the faithful and the simpler path regardless.

Net: a floor peer whose only third-party runtime concern is the bundled
`library(crypto)` (OpenSSL-backed); CBOR + base58 + varint hand-rolled. **`ffi` is
the documented fallback and is MORE LIKELY to be exercised here than for any prior
native peer** — both for Ed448 (below) and, structurally, as the escape hatch if the
declarative codec spike at S2 shows the canonical layer cannot be expressed without
collapsing into imperative glue (see "Does this idiom map?").

## CBOR: hand-rolled as a DCG (the headline idiom — and the headline risk)

The idiomatic Prolog way to describe a **binary wire grammar** is a **DCG**
(definite-clause grammar): `cbor_value(Term) --> ...` rules that *relate* a Prolog
term to its byte-code-list encoding, run in both directions via `phrase/2,3`. This is
genuinely elegant for the *structural* part of CBOR: major types, length headers,
nested arrays/maps fall out of a few dozen clean DCG clauses, and the *same grammar*
can encode and decode (the bidirectionality logic programming is famous for).

The risk — and it is the load-bearing S1 finding (A-PL-004) — is that **ECF's
canonical requirements are not structural; they are imperative side conditions on an
otherwise-declarative grammar**:

- **Length-then-lexicographic map-key ordering** requires *encoding each key first,
  then sorting the encoded byte-strings, then emitting* — a sort over computed byte
  vectors, which is an imperative pipeline (`maplist` encode → `predsort` by encoded
  bytes → emit), not a relation. A DCG cannot "sort its own output" declaratively.
- **Shortest-float minimisation (f16/f32/f64 ladder)** requires IEEE-754 bit
  manipulation: decompose the double, test whether the f16/f32 round-trips
  bit-exactly, pick the shortest that does. SWI exposes floats as 64-bit doubles
  with no native f16 and limited bit-level float introspection — this is **raw
  arithmetic + `float/2`/`int_to_float-bits` glue**, the *least* declarative corner
  of the codec, and the one the kickoff flagged as the likely pain point. It will
  read as imperative arithmetic predicates regardless of paradigm.
- **Recursive major-type-6 tag rejection on decode** is a clean clause (a guard that
  fails/throws on tag major type) — this part *does* stay idiomatic.

So the codec splits: the **frame/structure** is idiomatic DCG; the **canonical side
conditions** (ordering + shortest-float) are imperative predicates bolted onto it.
SWI's **native GMP bignums** are a real win — the full uint64/nint range carries with
**no special-casing** (the CL/Elixir advantage; the inverse of the int-width traps
that bit OCaml/C#/TS/Zig). **Spike `map_keys` + `float` at S2** before committing —
if the shortest-float predicate plus the sort-encoded-keys pipeline dominate the
codec, that is concrete evidence for the defer verdict, and `ffi` (consume the C-ABI
canonical layer) is the clean fallback.

## Crypto: library(crypto) over OpenSSL-3 (Ed25519 + SHA-256/384 native)

SWI-Prolog's `library(crypto)` is the de-facto crypto surface, backed by the system
OpenSSL — so it is **native to the runtime without a pack dependency**, the cleanest
supply-chain position available (one fewer pinned third-party than even CL's
ironclad, since `library(crypto)` ships in the SWI distribution). The trade vs CL's
pure-Lisp ironclad: the trust surface is OpenSSL (audited, ubiquitous) rather than
in-language code — a *better* trust surface, at the cost of a system-OpenSSL
dependency (the OCaml "no system deps" virtue is NOT achieved here; this peer links
OpenSSL like the C/Go peers do). The exact predicate spellings and OpenSSL-3
requirement are gated A-PL-002 at S2.

## Ed448: FFI-fallback-likely (the OCaml/Zig gap recurs — and is expected to)

The crypto-agility higher bar (v7.67: key_type Ed448 `0x02`; SHA-384 content_hash
`0x01`) is the **less-certain** crypto surface. OpenSSL-3 *implements* Ed448, but
SWI's `library(crypto)` historically wrapped ed25519 helpers without a guaranteed
ed448 predicate. Two outcomes, resolved at S2 (A-PL-003):

- **If** the bundled `library(crypto)` exposes a generic EVP key path that reaches
  OpenSSL's Ed448 → native, no FFI (collapses to the Elixir position: agility from
  the runtime's OpenSSL).
- **Else** → source Ed448 over the **C-ABI** (`libentitycore_codec`,
  `ec_ed448_{seed_to_pubkey,sign,verify}`), scoped to an **opt-in agility module** so
  the shipped Ed25519+SHA-256 floor peer stays FFI-free — **exactly the OCaml
  A-OC-002 hybrid shape**. SWI's C FFI (`library(ffi)` / the C interface) makes this
  clean when scoped.

Either way the §9.1 floor (Ed25519 + SHA-256) is unaffected. This **corroborates the
OCaml A-OC-002 / Zig A-ZIG-002 finding** a fourth time: "a second managed crypto
provider gives you Ed448" does **not** generalize to languages without a
BouncyCastle-equivalent; OpenSSL-via-FFI is the recurring escape. Expectation: FFI
needed for Ed448; native sufficient for the floor.

## Base58 + varint: hand-rolled

Both small and dependency-free. Base58 (Bitcoin alphabet, encode+decode,
`prolog/base58.pl`) for peer_id; LEB128 multikey varints (`prolog/varint.pl`,
DCG-described) for the N1 format-code / key-type / hash-type framing. Hand-rolling
dodges two more packs and matches the dependency-minimization stance (the
OCaml/Elixir/CL/Zig precedent).

## Error model: failure + ISO exceptions (the logic-paradigm two-level seam)

Prolog's error story is a **two-level split** no prior peer had, and it is the
cleanest paradigm seam the language offers: **failure** (the predicate fails /
backtracks) for in-band "this relation does not hold" — the relational analogue of a
boolean/Option — and **`throw/catch` ISO exceptions** (`error(Formal, Context)`
terms) for out-of-band hard rejects. The design: decode-as-relation predicates
**fail** for genuine "this term is not that" queries; the codec public surface
**throws** `error(entity_core_error(Kind, Detail), Context)` on N2/N3 violations
(non-canonical, truncated, tag-6, bad-seed) — because a malformed encoding must NOT
silently "fail and let the engine try another clause" (that would mask corruption as
absence). This differs from C#/TS exceptions, OCaml result, Elixir tagged-tuple, CL
conditions, Zig error-unions. The probe (A-PL-006): does any V7 error path actually
want *relational failure* (backtrack and try an alternative) rather than a thrown
term? Expectation: all codec-floor rejects are terminal throws; failure earns its
keep only at the *query* surface (e.g. "is there a capability granting X?" naturally
fails when absent).

**Determinism discipline (A-PL-005) is load-bearing:** an encode/decode is a
*function*, not a backtrackable relation. Codec entry points MUST be deterministic
(`once/1` / cut / `det` declarations) so the wire boundary never leaks a choice point
— uncontrolled backtracking across an I/O side effect is a correctness bug unique to
this paradigm. This is the Prolog analogue of "the codec is pure"; here purity must
be *enforced* against the engine's default nondeterminism.

## Async: SWI native OS threads (library(thread)); the §7b store is the clause DB

The Prolog analogue of the prior peers' concurrency models. SWI-Prolog has **real OS
threads** via `library(thread)` (preemptive, not green/coroutine) with message queues
and mutexes. The N6/N7 reentrancy invariants are satisfied by **one native thread per
connection** + a `request_id → message_queue` correlation table — the same
one-thread-per-conn shape CL/OCaml/Zig converged on, with SWI **message queues**
(`thread_send_message`/`thread_get_message`) as a cleaner correlation primitive than a
raw condvar.

**§7b store model (A-PL-007):** the §4.8 data-race-safe store is the **clause
database** itself (`assertz`/`retract` of `system/...` facts). SWI gives a
**logical-update view** with an implicit per-predicate lock, so a single
assert/retract is atomic — but a **multi-step read-modify-write** (read a tree node,
compute, write it back) is **NOT** atomic and needs an explicit `with_mutex/2`
critical section. This is precisely the **Zig/CL store-race lesson** that drove the
v7.75 §4.8 floor — flagged here proactively so S3 wraps every RMW, not just the
single ops. TCP_NODELAY is set on accepted streams (`tcp_setopt(S, nodelay(true))`);
no blocking syscall holds a shared lock.

## Naming: SWI-Prolog-native (language-ENFORCED, not a style choice)

Prolog has a **hard lexical rule**, not a convention: an identifier starting
uppercase or `_` **is a variable**; atoms/functors **must** start lowercase. So
predicates/functors/atoms/modules/files are `snake_case` (mandatory), logic variables
are `PascalCase`/`_Leading` (mandatory), and DCG non-terminals are `name//arity`. There
is no constant keyword — **atoms ARE the constants** (`max_depth`, `ed25519`,
`identity_multihash`), so the CL `+earmuff+`/`*star*` distinction has no analogue.
Atoms are **case-EXACT** (unlike CL's upcasing reader) — which means the **lowercase
`%02x` hex** tree-path convention (A-CL-009, settled) is naturally honored as long as
the hex predicate emits lowercase; flagged so S3 does not regress it.

## Build / test / packaging: consult + SWI pack + hand-rolled harness

SWI-Prolog has **no compile gate** — the clause DB is loaded dynamically, so "build"
is consulting the modules + a smoke load. There is no cargo/dotnet-class build tool;
the ecosystem norm is a load file (or Makefile) plus the **`pack`** system for
distribution (`pack.pl` metadata, `prolog/` source dir, git-indexed registry — the
Quicklisp analogue). Tests are a **hand-rolled harness** (`test/run_conformance.pl`)
loaded via `swipl -g` — no test-pack dependency, honoring minimization. SWI bundles
`library(plunit)` (the ecosystem-standard unit framework) **in the base install**, so
plunit is "free" and layerable for a richer S5 report at zero supply-chain cost.

## The no-compile-gate caveat (sharper than CL's)

SWI-Prolog is **dynamically typed with no static coverage check** — sharper than even
CL's dynamic typing, because there is not even a compile pass that catches an
undefined predicate until it is *called*. Correctness rests **entirely** on the
conformance corpus, which stresses the corpus's completeness even harder than the CL
peer did. The Containerfile must run from a clean `swipl` invocation each time (no
saved-state image), the same image-determinism caveat CL flagged.

## License: Apache-2.0 (S9 default)

SWI-Prolog itself is BSD-2; the pack ecosystem is license-mixed with no mandate, so
the repo's Apache-2.0 default (explicit patent grant) stands.

## Toolchain pins (S11)

- **SWI-Prolog 9.2.9** (~21 months at authoring — far over the
  30-day floor). The **9.2.x line is the stable/LTS branch** (even minor = stable in
  SWI's even/odd scheme; 9.3.x is development and is NOT used). Distro-packaged or
  source-built in-container; the exact patch tag available on fedora:43 is gated
  A-PL-008 (if fedora:43's `swi-prolog` package is a different 9.2.x patch, pin THAT
  and re-stamp — any 9.2.x stable patch is acceptable; the build asserts the
  resolved version).
- **OpenSSL** — image-provided (fedora:43 ships OpenSSL 3.x). `library(crypto)` links
  it; the Ed25519/SHA + (maybe) Ed448 surface depends on it being v3 (A-PL-002).
- `library(crypto)`, `library(socket)`, `library(thread)`, `library(dcg/basics)`,
  `library(plunit)` all ship **inside** the SWI distribution — no separate pin.
- The C-ABI FFI lib (if Ed448 needs it, A-PL-003) is pinned at the ffi-generator
  layer, not here.

## peer_id construction: §1.5 canonical-form table — now SETTLED, baked in (A-PL-010)

The profile mandates deriving the Ed25519 peer_id from the **§1.5 v7.65
canonical-form table** — `hash_type = 0x00` identity-multihash, digest = the **raw
public-key bytes** (no hash, for the ≤32B Ed25519 pubkey) — wire form
`Base58(key_type || hash_type || digest)`. **Confirmed in `spec-data/v7.75`:** §1.5
line 459 declares Ed25519 → `0x00` identity-multihash; lines 446–447 state "digest =
public_key (raw 32 bytes; the digest IS the public key, v7.64)." On the v7.75
snapshot the v7.73 **E1 erratum has already reconciled §7.4** to defer to the §1.5
table, so this is **no longer even a contradiction** — but it is baked in proactively
because the conformance corpus uses opaque digests (a wrong construction passes S2 and
only blows up at the S4 handshake), exactly the cycle Zig (A-ZIG-001) and OCaml
(A-OC-007) burned. Logged A-PL-010 as a corroboration-and-bake-in, not a discovery.

---

# *** Does this idiom map? — the honest go/defer verdict ***

This is the section S1 exists to produce. The question: **can byte-exact framed-TCP
binary I/O + canonical CBOR be expressed in SWI-Prolog without so much imperative
scaffolding that the logic-programming idiom is gone?**

## What genuinely maps (the idiom is real here)

1. **CBOR structure as a DCG.** Major types, length headers, nested arrays/maps,
   tag rejection — these are a few dozen clean, bidirectional `cbor_value//1`
   clauses. This is *better* than the imperative peers: one grammar encodes AND
   decodes. Real idiom, real win.
2. **Capability-chain walking as a recursive relation.** §5.5 chain verification is
   "this cap is granted by that cap, recursively to a root" — a textbook Prolog
   recursive relation, and the **chain-depth pre-check** (A-PL, §4.10(b)) is a clean
   `length`-bounded recursion. The §5.2 auth/authz verdict trichotomy maps onto
   distinct clause heads naturally.
3. **Unification as decode.** Pattern-matching a byte stream against an ECF term is
   what unification *is*. The natural Prolog parse is the natural ECF decode.
4. **Native bignums** remove the integer-width trap entirely.

## What does NOT map (the scaffolding the idiom can't hide)

1. **Byte-exact framed-TCP I/O is irreducibly imperative.** `set_stream(type(binary))`
   + `get_byte`/`put_byte`/`read_string`, read-exactly-N-bytes framing, the accept
   loop, TCP_NODELAY — this is sequential side-effecting code that looks identical in
   Prolog to how it looks in C, only with `:- ` in front. There is no declarative
   reading of "read the 4-byte length prefix, then read exactly that many bytes." A
   large fraction of a *core* peer is exactly this.
2. **Canonical CBOR's side conditions defeat the grammar.** Length-then-lex map
   ordering = "encode all keys, sort the encoded byte-strings, emit" — an imperative
   pipeline a DCG cannot express declaratively (a grammar can't sort its own output).
   **Shortest-float** = IEEE-754 bit manipulation in a language whose floats are
   opaque doubles — the single least-declarative corner, and unavoidable. These two
   are *the* canonical guarantees; they are precisely where the paradigm yields.
3. **Determinism must be forced against the engine.** The whole value of Prolog is
   nondeterministic search; this peer must *suppress* it everywhere (`once`/cut/`det`)
   because the wire is a function. You spend idiom budget fighting the language's
   defining feature.
4. **The store is a mutable clause DB with explicit locking** — `assertz`/`retract`
   + `with_mutex`. That is imperative shared-mutable-state concurrency wearing a
   logic-programming hat; it is not relational.

## Verdict: **DOCUMENT-AND-DEFER (lean), with a narrow GO option gated on the S2 codec spike**

On balance, **the imperative surface dominates**. A core peer is ~70–80% byte-exact
I/O + canonical-encoding side conditions + forced-deterministic locked-store
mutation, and ~20–30% genuinely-relational logic (chain walking, dispatch, decode
unification). The genuinely-relational parts are elegant and *are* a real probe of
whether V7's contracts assume a non-relational model — but they sit on top of a thick
imperative substrate that reads as "C with `:-`," and the two canonical CBOR
guarantees (map ordering, shortest-float) actively *resist* the one idiom (DCG) that
would have carried the codec. The logic-programming "idiom" would survive in pockets
but **would not characterize the peer** — which is the bar the experimental question
sets ("without so much imperative scaffolding that the idiom is gone").

This is a **VALID, clean outcome**, and the full S1 set is authored so the call rests
on real design work. Recommendation, in priority order:

1. **Preferred — DEFER with a documented narrow-GO trigger.** Park the peer at S1 as
   a recorded probe. **Do not** spend the S2–S5 build budget on a peer whose dominant
   surface is imperative-looking I/O. The standing-cohort value (re-running existing
   peers per amendment) is higher-yield than a 10th-language build whose paradigm is
   largely suppressed. The new-language well is documented dry (peer8-haskell memory),
   and this probe's honest finding *reinforces* that, rather than contradicting it.

2. **Narrow GO, IF taken — gate the whole build on a single S2 spike.** Before any
   peer-layer work, hand-roll *only* `cbor.pl` (the DCG + the two canonical side
   conditions) and push the **`map_keys` + `float` test vectors** through it. If the
   sort-encoded-keys pipeline and the shortest-float predicate stay readable and the
   DCG carries the rest, that is positive evidence and the build may proceed (with the
   honest framing that the I/O layer is imperative by necessity — true of the C peer
   too, which nobody pretends is idiomatic-functional). If those two predicates
   dominate or get ugly, **fall back to `codec_strategy = "ffi"`** (consume the C-ABI
   canonical layer; let Prolog own only the relational chain/dispatch logic over a
   foreign codec) — which honestly answers "the codec doesn't map, the orchestration
   partly does." A pure-FFI Prolog peer is a *defensible* shape but a weaker probe.

3. **What the probe is WORTH regardless of go/defer:** even deferred, this S1 records
   a real paradigm finding — **the canonical-CBOR side conditions (map-key ordering +
   shortest-float) are the specific feature that resists declarative expression**,
   and a fourth corroboration that Ed448 needs OpenSSL-via-FFI outside BouncyCastle
   languages. Those are spec/landscape signal, not wasted work.

**Bottom line for the orchestrator: DEFER is the recommended call.** The author the
full set is done; the idiom does not characterize the peer; the narrow-GO path exists
but is gated on an S2 codec spike that the S1 analysis predicts will lean toward FFI.
