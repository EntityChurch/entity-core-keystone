# Authority-as-query — what SQL and Datalog taught us about the §5/§6.6 interior

**The probe (2026-07-16).** Two peers, built in parallel S1→S5 as a *spec-discovery* probe (not a
substrate probe): **SQL** (`protocol-generator/sql/`, SQLite 3.50.4 + a C seam host) and **Datalog**
(`protocol-generator/datalog/`, embedded Ascent 0.8.0 + a Rust seam host). Both clear the full core
gate — **`validate-peer --profile core` → Result: PASS, 682·0F @ `cc1970f`** (SQL 291P/295W/0F/96S;
Datalog 292P/294W/0F/96S), origination-core 3/3, live 2-of-3 multisig accept, 71/71 wire corpus.

The question these answer is **not** "can the substrate hold the wire" (of course — the seam does the
bytes). It is: **how much of the §5/§6.6 authority interior stays expressible in a query/logic
language, and where does it leak to the host?** The finding is co-equal with the green gate — and this
is the well the substrate sweep went dry in, so a spec-shaped result here is the payoff.

Companion desk-analysis that predicted this: `declarative-query-viability.md`. The whole-territory
map: `../PARADIGM-MAP.md` §declarative.

---

## The one-line finding

**Authorization is a query; the protocol around it is a state machine.** Everything that is a *pure
function of the projected request facts* (the §5.2 verdict, the §5.5 delegation closure, §5.5a
scope-match, §3.6 K-of-N, §6.6 resolution) expresses **cleanly and legibly** in both SQL and Datalog —
often *more* legibly than the imperative spec prose. Everything *stateful-sequential* (§6.5 dispatch
ordering, the §4 handshake state machine, framing, crypto, the store's byte I/O) **leaks to the host**,
and the query language rightly fights it. The seam falls almost exactly where S1 predicted.

This is a mild **protocol-understanding** result, not a wire finding: it says which half of entity-core
is "what databases/logic were built for" and which half is "what an imperative runtime is for."

---

## The seam split, from the running artifacts

| Protocol region | SQL (SQLite) | Datalog (Ascent) | Verdict |
|---|---|---|---|
| §5.2 verify ladder | ✅ one `CASE` ladder, arm-order = algorithm-order, `ed25519_verify` inline (`verify_ladder.sql`) | ✅ `allow(c)` **derived**; fail-closed = **absence of a tuple** (`authority.rs`) | **Fits — legibility gain** |
| §5.5 delegation-chain closure | ✅ `WITH RECURSIVE` = `collect_authority_chain` verbatim (`chain_walk.sql`) | ✅ 2-rule transitive closure to least fixpoint — the SecPAL/Binder shape | **Fits — home turf** |
| §5.5a scope-match | ✅ JOIN + `GLOB` over normalized scope | ✅ prefix rule + a host-asserted `scope_covers` fact for the glob | **Fits (with one edge, below)** |
| §3.6 K-of-N multisig | ✅ `GROUP BY … HAVING count(DISTINCT signer) >= k` | ✅ counting aggregate over distinct signer facts | **Fits — sharpest substrate match** |
| §6.6 handler resolution | ✅ `ORDER BY length(pattern) DESC LIMIT 1` | ✅ longest-prefix as stratified negation | **Fits** |
| §6.5 dispatch sequencing / op-switch | ◐ leaks to host | ✗ (no sequencing) | **Host** |
| §4 handshake state machine | ✗ | ✗ | **Host** |
| §6.11 concurrency / §7b store-safety | host — SQLite serialized + fork-per-conn | host — `RwLock` store; engine stateless per request | **Host (no new §7b shape)** |
| Canonical CBOR, Ed25519/SHA, framing | ✗ seam | ✗ seam | **Host / `libentitycore_codec`** |

The wrapper-guard (FLOW-DESIGN, from the visual probes) was load-bearing and **held through S4 on both
peers**: completing the S4 handler surface added **zero** imperative allow/deny to either dispatch
path. SQL's `project_and_verify()` projects `envelope.included` into tables and asks
`verify_ladder.sql` for the verdict; Datalog's host verifies crypto → asserts `verified_signer` facts →
Ascent derives `allow`. The verdict never migrated out of the authored interior.

---

## What the encoding surfaced that imperative peers obscured

Four findings, two of them spec-shaped (routed to arch, F40/F41):

1. **F40 / A-SQL-008 — scope typing wants to be two match strategies, not one.** §3.6 gives
   *id-scope* dims and *path-scope* dims; the prose reads as a single uniform `matches_scope`. Encoding
   it in SQL forced the split into the open: **id dims match raw; path dims canonicalize** — and it
   surfaced as a *real ALLOW bug* (canonicalizing an operation as a path broke a legitimate grant), whose
   fix **is** the split. The relational encoding made an implicit typing distinction explicit and
   testable — sharper than the prose. (Companion: A-SQL-007 — SQLite `GLOB *` is not segment-anchored,
   byte-exact for the core pattern set `{*, /*/*, exact, trailing-subtree}` but a `/*/specific`
   peer-wildcard would over-match; a note, not a gate failure.)

2. **F41 / A-DL-013 — the whole §5/§6.6 decision surface is a monotone deductive system.** The spec
   prescribes §5.2/§5.5 imperatively (`verify_request` walks a chain; `check_permission` loops grants),
   but the underlying logic is monotone and derivable: `allow` is a least-fixpoint relation over
   `verified_signer`, `authorized` (the delegation closure), `temporal_valid`, and `scope_match`.
   Expressed as rules, two properties the prose states as MUSTs become **structural invariants an
   implementation cannot violate silently**: **fail-closed** (no derived tuple = deny — not a
   fallthrough an imperative peer can forget) and the **within-grant conjunction** (§5.5a's "one grant
   must cover all four dims" is a single join, not four checks that can drift apart). The ask: an
   *authority-as-derivation* appendix to GUIDE-CONFORMANCE stating the verdict as a derivation, so these
   invariants are specified, not merely conventional.

3. **A-DL-012 — Ascent dedups *derived* tuples but not pre-seeded EDB.** A cohort-relevant
   implementation trap: counting a raw signer relation for K-of-N double-counted a duplicate signature
   (one signer satisfied a 2-of-3 threshold). Distinctness in a bottom-up engine is a fixpoint property,
   not an EDB property — the fix is a one-line copy-rule into the IDB before the aggregate. Silent if
   missed; only the accept-path exposes it (the rejection-only oracle category never would — the
   vacuous-green trap again). Now a durable lesson (SUBSTRATE-TAKEAWAYS, AGENTS.md).

4. **A-DL-015 / the SQL analogue — the *absence* of a new authority finding at S4 is itself a datum.**
   Every S4 fix on both peers was a host-seam gap (type-floor render, register/unregister, tree CAS,
   negotiation, dispatch-outbound), never authority logic. The interior authored at S3 passed the full
   live-peer oracle with no new rules/queries. That the seam split held at the higher bar *confirms* it.

---

## Two hosts, two §7b idioms (host-side, not a new taxonomy shape)

Neither substrate introduces a new §7b concurrency shape — both put store-safety in the host, as the
visual probes did. But they chose differently, and both are structural:
- **SQL:** fork-per-connection (process isolation) + SQLite serialized writes.
- **Datalog:** a `RwLock` store (`Peer: Send + Sync`; unshared mutable = compile error); the Ascent
  engine is stateless per request (assert → fixpoint → read → drop).

The §6.11 reentry, notably, is where the two hosts diverged on cost: SQL rebuilt it as a `request_id`
correlation map (non-blocking send + route-by-id), Datalog as a `conn.outbound` seam — the same
correlation-map tax the concurrency taxonomy predicts for non-actor/dataflow substrates.

---

## When to stop / re-run value

This **closes the declarative-query/logic frontier** (`../PARADIGM-MAP.md` §declarative, the last
high-interest corner). SQL is the relational-query representative; Datalog is the deductive-logic
representative and the one that lands closest to the security literature (trust-management logics *are*
Datalog dialects). What remains after these is esoteric/substrate-limit curiosities (Brainfuck,
Befunge, term-rewriting, R) — "where does authoring stop being possible," not "what does the protocol
mean." Steady-state value of these two peers going forward is **re-running the authority interior
against each amendment**: because the verdict is authored as legible queries/rules, an amendment to §5
that the imperative cohort would absorb as a code diff shows up here as a *diff to the derivation* —
the clearest possible read on whether an authority change is monotone/fail-closed-preserving.

## Cross-references
- Predicted by: `declarative-query-viability.md` · Territory map: `../PARADIGM-MAP.md` §declarative
- Arch routing: `protocol-generator/shared/evaluations/authority-as-query.md` (F40/F41)
- Durable lessons: `../SUBSTRATE-TAKEAWAYS.md` §authority-as-query · `AGENTS.md` durable-lessons
- Peers: `../../protocol-generator/{sql,datalog}/` (profiles carry the filled
  `[authority_interior_expressibility]` sections)
