# Architecture Review — entity-core-protocol-prolog (peer #13)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data v7.75;
codec corpus v0.8.0. · **Audience:** architecture (spec-tightness feedback) + operators (publishing
decision). · **Status:** `validate-peer --profile core` PASS · 653 / 291P / 269W / **0F** / 93S
@ `entity-core-go @75c532e`; origination-core 3/3.

This review follows the format of the Zig #4 / Common Lisp #5 `ARCHITECTURE-REVIEW.md`, carried to
**the cohort's first logic-programming peer** — a relational program model (SLD-resolution over a
Horn-clause database), distant from the substrate along a *third* axis: not Zig's memory/control-flow
distance, not CL's program-model (multiple-dispatch + conditions) distance, but the **computation
model** itself (search over relations, not value-computation or sequenced effects). Part A is the
idiom-fidelity + spec-refinement retrospective; Part B is the publishing-options surface; Part C is
the one-paragraph arch summary. The deeper idiom write-up — the actual point of this peer — is
[`IDIOM-FINDINGS-SYNTHESIS.md`](IDIOM-FINDINGS-SYNTHESIS.md); this review references it.

---

## 0. The thesis peer #13 was chosen to test (and the revival correction)

The convergence thesis: *if the spec is tight, independently-derived peers converge on the same
conformance fixed point with no wire divergence; the idiom seams diverge cleanly by profile at impl
locality.* Twelve peers across static-OO, functional, actor, no-GC-systems, homoiconic-CLOS,
JVM-OO, and dynamic-scripting idioms held it.

Prolog stresses it on a genuinely orthogonal axis. **The S1 verdict was DEFER** (`PROFILE-RATIONALE.md`
"Does this idiom map?"): a core peer is ~70–80% byte-exact I/O + canonical-encoding + forced-
deterministic locked-store mutation, and the logic idiom would survive only in pockets. **The
revival overturned it** (`HANDOFF-PROLOG-REVIVAL.md`) on the grounds that the DEFER answered the
*wrong* question — it counted the byte-floor *against* Prolog, the floor we FFI anyway. The right
question is: **does the protocol's operational semantics express as a convergent logic layer?** The
S2 spike never "failed" (20/20 byte-exact on the two hardest vector classes); what it showed was
(a) shortest-float is imperative bit arithmetic and (b) SWI `library(crypto)` 9.2.9 has no
`ed25519_*` predicates at all — both *floor* facts, neither a protocol problem. So the peer was
built **codec_strategy = "ffi"**: the C-ABI owns the byte-floor, Prolog owns the relational core.

**Result: the thesis held, and the revival was vindicated.** Every wire-touching decision converged
to the same 653·0F fixed point Ruby + Go reached against this oracle; the logic-idiom seams (chain
walk as relation, dispatch as clause table, store as clause DB) landed at impl locality and changed
no wire byte. And the protocol genuinely *did* express as logic — the deliverable
(`IDIOM-FINDINGS-SYNTHESIS.md`) shows where, with code. The floor reads as "C with `:-`" (A-PL-014),
exactly as predicted, and that is fine — it is the FFI floor, by design.

---

## PART A — Architecture review

### A.1 Module layout

The peer is a flat module set under `prolog/` (the SWI pack source dir), layered floor → core:

| Module | Layer | Role |
|---|---|---|
| `ec_codec.pl` | floor | the **deterministic** (`once/1`) predicate API over the C-ABI: canonical-CBOR entity framing, content_hash, peer_id, Ed25519/Ed448 sign/verify, SHA-256/384 |
| `c/ec_codec_pl.c` → `ec_codec_pl.so` | floor | the SWI foreign shim (`use_foreign_library/1`) over `libentitycore_codec` (C-ABI v1.1) — byte-built, gitignored |
| `ec_cbor.pl` | floor⁺ | the **data-VALUE** canonical CBOR codec the peer owns (A-PL-013: the C-ABI treats `data` as opaque) |
| `ec_entity.pl` | L1 | the materialized entity `{type, data, content_hash}` (§1.1/§3.4) + the §3.1 envelope |
| `ec_identity.pl` | L1 | a peer's Ed25519 keypair + §1.5 peer_id (size-cutoff branch) + §3.5 signature |
| `ec_wire.pl` | L1/§1.6 | 4-byte BE length-prefix framing + §3.2 EXECUTE / §3.3 EXECUTE_RESPONSE builders |
| `ec_types.pl` | §9.5 | the 53 core type data-models (render-from-model; 53/53 byte-identical) |
| `ec_capability.pl` | L3/§5 | **the relational verification core** — chain walk, §5.2 trichotomy, §3.6 multisig, §5.6/§5.7 attenuation |
| `ec_store.pl` | §3.9 | **the store as the clause database** (`content_fact/3`, `tree_fact/3`); RMW under `with_mutex/2` |
| `ec_peer.pl` | §6 | peer assembly, the four MUST handlers, §6.5 dispatch chain, **§6.6 dispatch as a multi-head clause table** |
| `ec_transport.pl` | L4 | TCP listener + per-connection serve thread + the §6.11 `request_id → message_queue` demux |
| `ec_client.pl` | L4 | initiator-side §4.1 handshake + authenticated EXECUTE construction (drives the loopback) |
| `ec_host.pl` | — | the standalone host entrypoint (S4 conformance target; `--port`/`--validate`) — not a stable surface |

### A.2 The FFI seam (the load-bearing architectural decision)

The seam between the Prolog logic core and the C-ABI byte-floor is `ec_codec.pl`, a thin
**deterministic** predicate API. Three properties make it the right shape:

1. **Determinism discipline (A-PL-005).** The wire is a *function*, not a relation — a leaked
   choice point could re-emit bytes or re-decode on backtrack. Every public predicate in `ec_codec`
   is `once/1`-wrapped; the foreign predicates are `semidet` (true on `EC_OK`, fail otherwise) and
   `once/1` forecloses re-entry. This is the Prolog analogue of "the codec is pure" — but here purity
   must be *enforced against the engine's default nondeterminism*, not assumed. (One reporting nuance:
   `deterministic/1` after a foreign call inside `(If->Then)` can report `false` from a frame-teardown
   artifact even when the single-solution invariant holds; the authoritative check is single-solution
   `findall`, which passes.)
2. **No external `ffi` pack.** The shim is a plain `use_foreign_library/1` load of `ec_codec_pl.so`
   (built by `swipl-ld` linking `-lentitycore_codec`). Bytes are SWI strings of code-points 0..255
   (`REP_ISO_LATIN_1` in the shim) — NUL-safe, length-carried. Zero supply-chain surface beyond the
   C-ABI itself.
3. **The peer still owns data-value canonical CBOR (A-PL-013).** `ec_encode_ecf(Type, Data)`
   canonicalizes only the outer `{data, type}` map; the nested `data` value is wrapped opaque. So
   `ec_cbor.pl` is a peer-owned canonical CBOR value codec — "FFI the codec" does **not** eliminate a
   canonical-CBOR obligation at the data-value layer. The 53/53 type-registry byte-diff is the proof
   the Prolog data-value canon matches the cross-impl encoder. **Routed to arch as a note for every
   FFI peer.**

### A.3 Threading / store model

**Concurrency (one native thread per connection).** SWI has real OS threads (`library(thread)`,
preemptive). The accept loop spawns a reader thread per accepted socket; the reader demuxes inbound
frames (§6.11): an EXECUTE_RESPONSE routes to its awaiting outbound caller by `request_id` via a
per-connection `message_queue`, an inbound EXECUTE dispatches on its **own** thread (N6) so a handler
that originates an outbound EXECUTE and awaits its reply never blocks the reader. The correlation
primitive is SWI **message queues** (`thread_send_message`/`thread_get_message`) — a cleaner analogue
of the CL condvar+hashtable / OCaml Condition+Hashtbl. Three SWI-specific footguns were hit and
recorded so maintainers don't regress them:
  - **A-PL-016** — SWI global vars (`nb_setval`/`b_setval`) are **thread-local**; the request-id
    counter + emit counter had to move to the **shared clause DB** (`req_counter/2` dynamic) — the
    8-way demux failed 0/8 until they did.
  - **A-PL-017** — **named-alias mutexes leak** under connection churn (process-lifetime, never GC'd);
    under the oracle's 100+-connect/close probe the named-mutex table exhausted and `mutex_create`
    threw. Per-connection mutexes are now **anonymous** + explicitly `mutex_destroy`'d at teardown.
  - **A-PL-018** — the §6.11 reentry seam handed across modules must be a **module-qualified closure
    term** (`ec_transport:outbound_via(IO)`), else `call/3` resolves it in the *caller's* module
    (`ec_peer`) → `existence_error` → 503. (Sibling of A-PL-015: cross-module callbacks need
    `:- meta_predicate`.)

**Store (the clause database itself).** The §3.9 content store and entity tree are dynamic
predicates — `content_fact(StoreId, HashHex, Entity)` and `tree_fact(StoreId, Path, HashHex)` — and
the store ops *are* `assertz`/`retract`. The store is not a hash-table bolted onto Prolog; it is
Prolog's native fact base. **A-PL-007** (the Zig/CL store-race lesson, flagged proactively at S1):
a single `assertz`/`retract` is atomic under SWI's logical-update view, but a read-modify-write
(read-old ‖ retract ‖ assert ‖ emit) is **not**, so every RMW (`store_bind`/`store_unbind`) runs
inside `with_mutex/2`, keyed per `StoreId` (so two loopback peers in one process don't serialize).
The §6.10/§6.13(c) emit bus is a live zero-consumer hook — and the consumers are themselves clauses
(`tree_consumer/2`). This is the cleanest expression of "the store as the clause DB" in the cohort;
it is also, honestly, imperative shared-mutable-state concurrency wearing a logic hat (the §A.4 caveat).

### A.4 Where the idiom paid off — and where it didn't (scored)

Full development in `IDIOM-FINDINGS-SYNTHESIS.md`. Scored briefly:

- **§5.5 chain walk as a recursive relation — PAID OFF (headline).** `verify_chain/3` over parent
  pointers; **conjunction-failure IS the deny**. `\+ verify_capability_chain(...)` reads the failure
  directly as `authz_deny` — no boolean flag threaded through a loop. This is the single cleanest
  idiom win and the genuine probe payoff.
- **§5.2 trichotomy as guarded clause heads — PAID OFF.** `verify_request/4` is five ordered clauses,
  one per verdict; the first whose body holds wins. The cohort writes this as a nested if/else ladder.
- **§6.6 dispatch as a multi-head clause table — PAID OFF (idiom-neutrality).** `handle_op/4` — each
  `(handler, op)` pair its own clause head, first-argument-indexed, "unknown → 501" the catch-all
  clause. **The clause DB is the router.** This is the structural analogue of CL's CLOS method table
  (A-CL-008): a different mechanism reaching byte-identical dispatch — a tightness signal that §6.6 is
  specified at the right altitude (it names the dispatch *key*, not a mechanism).
- **A-PL-006 — the one place the idiom is genuinely TOO WEAK, and the genuinely-Prolog finding.**
  Relational failure is mono-valued ("no"); it cannot say "no, specifically 401-no". The §5.5
  unresolvable-grantee 401 carve-out, which must diverge in status class from a 403 deny, therefore
  needs a **thrown term** (caught at the dispatcher), not failure. Two-channel split: failure for the
  dominant deny, a thrown marker only where the status class must diverge. (Developed in the synthesis.)
- **Byte-floor "C with `:-`" — EXPECTED, fine (A-PL-014).** Framed binary TCP I/O and the
  shortest-float ladder are irreducibly imperative; the predicate arrows are punctuation, not logic.
  This is the FFI floor's job — no different from the C peer.

### A.5 Spec-refinement value — what Prolog contributed

The keystone's *end* is spec refinement. Peer #13's harvest (full text in `SPEC-AMBIGUITY-LOG.md`):

- **A-PL-006 — the failure/exception verdict-channel boundary (the genuinely-Prolog finding).** Not a
  spec *defect*, but a paradigm-fit landscape signal arch + research should hold: the §5.2/§5.5 verdict
  semantics fit a *two-channel* error model (relational failure for "deny", a distinct channel only
  where the HTTP status class must diverge). The logic-paradigm analogue of CL's conditions/restarts
  probe. **Escalation: research** (landscape signal).
- **A-PL-013 — the C-ABI `data`-is-opaque obligation.** An FFI peer building entity data through the
  public `ec_encode_ecf` still owns data-value canonical CBOR. **Escalation: arch + note for the other
  FFI peers** (the public-ABI contract delegates data-value canonicalization to the caller).
- **A-PL-011 — the forward-compat format_code 128 ABI-surface seam.** `content_hash.4` pins a
  `format_code = 128` content_hash the public `ec_content_hash_with_format` deliberately rejects;
  the peer composes it from public symbols (`ec_content_hash` + `ec_hash_format_code_encode`). Same
  class as OCaml A-OC-004 / CL A-CL-007 (construct-vs-receive asymmetry), surfaced here as an
  ABI-surface note. **Escalation: arch** (the public-ABI contract vs the corpus forward-compat vector).
- **A-PL-010a — corroboration with a teeth-mark.** The §1.5 key registry codes Ed25519 = `0x01`
  (not `0x00`; only `hash_type` is `0x00`). The peer shipped `0x00` and the cross-impl oracle caught
  it at the very first handshake check — the opaque-digest S2/S3 corpus hid it (both loopback peers
  shared the wrong byte). Re-confirms the standing §1.5/§7.4 peer-id finding (OCaml A-OC-007, Zig
  A-ZIG-001, CL A-CL-002) AND adds the lesson: peer_id key_type must be validated against the oracle,
  not just self-consistency. **Escalation: corroboration** (no new ⚑; reinforces the standing ask).
- **A-PL-002 / A-PL-003 (RESOLVED NEGATIVE) — the crypto-floor surprise.** SWI `library(crypto)` 9.2.9
  exports **no** `ed25519_*`/`ed448_*` predicates at all — not even a generic EVP route — so the
  *entire* signature surface (not just Ed448 agility, as S1 predicted) is an FFI obligation. A
  landscape data point: "a managed crypto library gives you the floor" does not generalize to SWI.
  **Escalation: research** (the 4th corroboration that OpenSSL-via-FFI is the recurring escape).
- **A-PL-014 / A-PL-004 (paradigm) — the byte-floor is irreducibly imperative.** Framed I/O +
  shortest-float read as "C with `:-`"; legitimately the C-ABI's job. **Escalation: research**
  (paradigm-fit landscape signal; expected, not a problem).
- **A-PL-019 (NEW, packaging) — SWI pack version grammar is dotted-numeric only.** No pre-release
  channel at all (rejects `0.1.0-pre`/`0.1.0pre`/`0.1.0-alpha.1`); `pack.pl` carries `0.1.0`, the
  `-pre` line lives in docs. The SWI analogue of CL A-CL-010 + Ruby A-RUBY-010, and the strictest of
  the three. **Escalation: operator.**
- **A-PL-015 / A-PL-016 / A-PL-017 / A-PL-018 / A-PL-007** — SWI concurrency/module footguns
  (resolved-in-peer; recorded so maintainers don't regress). No arch ask.

**Net:** Prolog surfaced **no new spec *defect*** (the well was drained by the prior spec-first peers —
the same dry-well-corroboration result Ruby reported), but it contributed the cohort's **most
distinctive paradigm-fit finding (A-PL-006)** and a genuinely-useful FFI-peer note (A-PL-013), plus a
teeth-mark corroboration of the standing §1.5 peer-id ask (A-PL-010a).

### A.6 Where peer #13 sits vs the cohort

| Axis | OO/scripting cohort | CL (#5) | **Prolog (#13)** |
|---|---|---|---|
| Derivation | reference / port / spec-first | spec-first | **spec-first** |
| Distance axis | — / memory / program-model | program model (dispatch + errors) | **computation model (relational / SLD)** |
| Dispatch model | single-dispatch match ladder | CLOS multiple dispatch | **multi-head clause table (the clause DB IS the router)** |
| Error model | exceptions / result / error-union | condition system + restarts | **relational FAILURE + ISO `throw/catch` (two-channel, A-PL-006)** |
| Capability chain | flag-threaded loop | recursive function | **recursive RELATION (conjunction-failure = deny)** |
| Store | hash-table / map | hash-table | **the clause database (`assertz`/`retract`)** |
| Codec | hand-rolled / FFI | hand-rolled (native) | **FFI (C-ABI byte-floor) + peer-owned data-value CBOR** |
| Crypto | various | pure-Lisp (ironclad) | **C-ABI (libentitycore_codec); library(crypto) has NO ed25519 — A-PL-002)** |
| Core verdict | 0 FAIL | 0 FAIL | **0 FAIL (653·0F·93S @ 75c532e)** |

**Position:** peer #13 is the cohort's **convergence stress-test along the computation-model axis** —
relational search vs value-computation/sequenced-effects. It confirms every wire-touching decision
converges under a program model whose *defining feature (nondeterministic search) had to be
suppressed everywhere* (`once`/cut/`det`), and it is the first peer to express the protocol's
operational semantics as a **convergent logic layer** — the operator's stated payoff. Its distinctive
contribution is the idiom-findings synthesis: *the protocol does not resist Prolog; only the byte-floor
does, and that is the FFI floor's legitimate job.*

---

## PART B — Publishing options (operator-decides — not acted on)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface.

### B.1 In-repo vs standalone repo
Same as the cohort: **keep in-repo under `protocol-generator/prolog/` for v0.1** (per-language sibling
repos are deferred keystone-wide, S10; lifting Prolog alone fragments the uniform posture). The SWI
pack is `pack.pl`-scoped to the `prolog/` source dir, so the load surface is clean from the monorepo.

### B.2 Distribution mechanism (SWI-Prolog-specific)
SWI's channel is the **pack registry** — `pack_install(Name)` resolves by name to a registered git
URL / tarball, or installs directly from a URL. "Publishing" registers the pack or points
`download(URL)` at the release archive at the reviewed tag. Closer to CL's git-indexed Quicklisp than
to RubyGems' upload registry. **Today the peer is consumed via `attach_packs/2`** from the worktree,
fully offline. **Zero runtime pack dependencies** — `library(crypto/socket/thread/dcg)` all ship in
the SWI distribution; the only external is the C-ABI floor (built in-container, not a pack dep).

### B.3 License / version posture
- **License: Apache-2.0** (keystone S9 default; SWI is BSD-2, pack ecosystem license-mixed, mandates
  nothing — the Apache default stands). No change recommended.
- **Version: `0.1.0-pre` LINE** (set this phase). SWI's pack version grammar is dotted-numeric only
  (A-PL-019) — it rejects every pre-release suffix, so `pack.pl` carries `0.1.0` and the `-pre` marker
  lives in CHANGELOG/README. **Promotes to `0.1.0`** when (a) S4 fully green [met] AND (b) ≥1 external
  consumer confirms it works [not yet met]. On promotion, `pack.pl` needs no change — only the docs
  drop the `-pre`.
- **Agility full MATRIX** is the documented non-v0.1 item (cohort-wide deferral): the Ed25519 + Ed448 +
  SHA-256/384 primitives are byte-proven via the C-ABI (KAT 10/10) and the connect-path slice is
  exercised; the M2/M3/M6 cross-product harness is not wired.

### B.4 Recommendation (operator-decides)
**Keep in-repo under `protocol-generator/prolog/` for v0.1, consume via `attach_packs/2` or a pack
registry entry on the keystone repo, at the `0.1.0-pre`/Apache-2.0 line.** Lift to a standalone repo +
register a dedicated pack entry at the same time the cohort does (S10). Promote to `0.1.0` once the
external-consumer gate is met. Hold the agility full MATRIX as a post-v0.1 item. **The operator
decides; the pipeline does not publish, tag, or push.**

---

## C. Summary for arch (one paragraph)

Peer #13 vindicates the convergence thesis along the cohort's *third orthogonal* idiom axis — the
**computation model** (relational SLD-resolution, not value-computation or sequenced effects) — and
vindicates the **revival decision**: a logic-programming peer reached the identical 0-FAIL fixed point
(653·0F·93S @ 75c532e) as Ruby + Go, spec-first, with the codec/crypto byte-floor sourced over the
C-ABI (`strategy = "ffi"`, forced by A-PL-002: SWI `library(crypto)` has no Ed25519 at all) and Prolog
owning the relational core. **The protocol genuinely expressed as a convergent logic layer** — the §5.5
chain as a recursive relation where conjunction-failure IS the deny, the §5.2 trichotomy as guarded
clause heads, §6.6 dispatch as a multi-head clause table (the clause DB as router, the structural
analogue of CL's CLOS method table), and the §3.9 store as the clause database itself — all landing at
impl locality with zero wire-byte divergence. The distinctive contributions are (1) the cohort's most
paradigm-specific finding, **A-PL-006**: the protocol's verdict semantics fit a two-channel error model
(relational failure for the dominant "deny", a thrown term only where the status class must diverge —
the §5.5 401 carve-out), because Prolog failure is mono-valued; (2) the FFI-peer note **A-PL-013** (the
C-ABI treats `data` as opaque, so an FFI peer still owns data-value canonical CBOR); and (3) a
teeth-mark corroboration of the standing §1.5 peer-id ask (**A-PL-010a** — Ed25519 key_type 0x01, caught
only by the cross-impl oracle). No new spec defect (the well is drained); the byte-floor reads as "C
with `:-`" exactly as predicted (A-PL-014) — which is fine, it is the FFI floor by design. Packaging
note **A-PL-019**: SWI's pack version grammar is dotted-numeric only (strictest of ASDF/RubyGems/SWI).
