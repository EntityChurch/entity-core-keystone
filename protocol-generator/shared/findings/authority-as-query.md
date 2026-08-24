# HANDOFF-TO-ARCH — F40/F41: the §5/§6.6 authority interior is a monotone deductive system (authority-as-query probe)

**Date:** 2026-07-16 · **Findings:** F40 / F41 (`research/stewardship/SPEC-FINDINGS-LOG.md`);
surfaced as **A-SQL-008** (`protocol-generator/sql/status/SPEC-AMBIGUITY-LOG.md`) and **A-DL-013**
(`protocol-generator/datalog/status/SPEC-AMBIGUITY-LOG.md`)
**Owner:** `arch` (GUIDE-CONFORMANCE / spec appendix note) · **Severity:** guidance gap (a legibility +
silent-violability gap; no vector gates either directly) · **Blocks:** nothing
**Spec surface:** ENTITY-CORE-PROTOCOL.md §5.2 / §5.5 / §5.5a / §3.6 / §6.6 + GUIDE-CONFORMANCE @
`spec-data/v0.8.0`

> Keystone cannot edit `spec-data/**` (immutable, boundary). This is a request for arch to fold notes
> on its own schedule; the keystone side is already fixed and gate-green (SQL + Datalog peers land
> `682·0F Result: PASS @ cc1970f`, full retrospective `protocol-generator/shared/evaluations/authority-as-query.md`).

## Context — why these two peers exist

The **authority-as-query** probe (the last two declarative-query/logic frontier bets) built a peer whose
§5/§6.6 authority interior is authored **in a query/logic language** rather than imperatively: SQL
(SQLite, recursive CTEs) and Datalog (embedded Ascent, bottom-up rules). Authorization is historically a
database/logic problem — the trust-management logics (SecPAL, Binder, DKAL) are *literally* Datalog
dialects for delegation — so this is the region most likely to teach us about the *protocol*, not just a
substrate. It did. The seam split is the headline (`protocol-generator/shared/evaluations/authority-as-query.md`); two sub-findings are
spec-shaped and routed here.

---

## F41 (primary) — state the authority verdict as a *derivation*, so fail-closed + within-grant become structural invariants

**What the encoding showed.** The spec prescribes §5.2/§5.5 **imperatively**: `verify_request` walks a
capability chain, `check_permission` loops grants, the verdict is assembled by an if/return ladder. But
the underlying logic is **monotone and derivable**. Authored as rules (Datalog peer `src/authority.rs`),
the verdict is a least-fixpoint relation:

```
authorized(P, R) :- granted(P, R).
authorized(P, R) :- delegated(P, Q, R), authorized(Q, R).      % §5.5 delegation closure
allow(C)         :- verified_signer(C), authorized(C, _),
                    temporal_valid(C), scope_match(C).          % §5.2 verdict, derived
```

Two properties the prose states as MUST-prose become **invariants an implementation cannot violate
silently**:

1. **Fail-closed is structural.** `deny` is not a rule — it is the *absence of a derived `allow`
   tuple*. An imperative peer can forget a `return 403` on a new code path (this is exactly the class of
   bug the resilience-frame lesson catches after the fact); a derivation cannot. Denial is the default of
   the fixpoint, not a branch.
2. **The §5.5a within-grant conjunction is one join.** "A single grant must cover all four scope dims"
   is a 5-way join in the rule; imperatively it is four separate checks that can drift apart across
   edits. The join makes "same grant, all dims" a correctness property for free.

**The ask.** An **authority-as-derivation appendix** to GUIDE-CONFORMANCE (informative, non-normative)
that specifies the §5.2 verdict as a derivation over `{verified_signer, authorized, temporal_valid,
scope_match}`, with fail-closed = no-derivation and the within-grant conjunction = single-grant join
stated as invariants. This does not change the wire or any verdict — every peer already computes the same
answer — it makes two silently-violable MUSTs *specified* rather than conventional, and gives future §5
amendments a monotone reference form to check changes against.

## F40 (companion) — §3.6 scope typing is two match strategies, and the prose's single `matches_scope` hides it

**What the encoding showed.** §3.6 defines *id-scope* dims and *path-scope* dims; the prose reads as one
uniform `matches_scope`. Encoding it in SQL (`scope_match.sql`) forced the distinction into the open and
it surfaced as a **real ALLOW bug**: canonicalizing an operation dim as a path broke a legitimate grant.
The fix **is** the split — **id dims match raw; path dims canonicalize** — now the two strategies in the
peer. The relational encoding made an implicit typing distinction explicit and testable.

**Companion note (A-SQL-007, not spec-shaped):** SQLite `GLOB *` is not segment-anchored. It is
byte-exact for the core pattern set `{*, /*/*, exact, trailing-subtree}`, but a hypothetical
`/*/specific` peer-wildcard would over-match. Flagged so a future scope-pattern extension doesn't assume
naive glob semantics; no core gate touches it.

**The ask.** A GUIDE-CONFORMANCE clarification that §3.6 scope matching is **typed** — id dims compared
literally, path dims compared under §1.4 canonicalization — rather than a single uniform match. Small,
but it is a latent interop hazard: two peers that guess the typing differently disagree on ALLOW for a
mixed-dim grant, and no vector currently pins it.

---

## Not escalated (kept as durable keystone lessons)

- **A-DL-012** — Ascent (any bottom-up engine) dedups *derived* tuples but not pre-seeded EDB, so K-of-N
  distinctness needs an explicit IDB copy-rule before the counting aggregate. An implementation
  discipline for logic-substrate peers, folded to `SUBSTRATE-TAKEAWAYS.md` + `AGENTS.md`. Not a spec gap
  (§3.6 is fine) — but it pairs with the standing rejection-only-oracle lesson: only the **accept path**
  exposes it, which is why the mandatory 2-of-3 accept-path unit test earns its keep.
- **A-DL-015 / A-SQL-011** — the type floor is a host *render* of published data, orthogonal to the
  authority logic; and the *absence* of any new authority finding at S4 confirms the seam split at the
  live-peer bar. Implementation data, not spec gaps.

## Provenance / reproduce
- Peers: `protocol-generator/{sql,datalog}/` — `run-s4.sh` (core gate), `run-origination-core.sh`.
- Gate: `validate-peer --profile core` → `Result: PASS 682·0F @ cc1970f` (oracle fingerprint
  `8261a033…`, rebuilt via `tools/oracle-bootstrap.sh` from pinned `cc1970f`).
- Retrospective: `protocol-generator/shared/evaluations/authority-as-query.md`. Desk-prediction:
  `protocol-generator/shared/evaluations/declarative-query-viability.md`.
