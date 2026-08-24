# Declarative-query viability — SQL & Datalog as peer substrates

**Question.** Can the entity-core authority interior be authored in a relational-query (SQL) or
deductive-logic (Datalog) language, and if so *where does it actually run* — what hosts it, what's the
seam, what does the code look like? Companion to `../PARADIGM-MAP.md` (which flags both high-interest).

**Short answer.** Yes, and more naturally than imperative code for the *authorization* half — because
authorization *is* a query/logic problem. Both run **embedded, in-process, behind a thin host** that
owns sockets + canonical CBOR + crypto *primitives*; the authority *verdict logic* is authored in the
query/rule language. The finding is the **seam split**: which half of the protocol is relational/logical
(fits) vs stateful-sequential (fights).

---

## 1. Where it runs (the hosting model)

Neither SQL nor Datalog opens a socket or parses CBOR. So the shape is the same seam pattern our
alien-substrate peers (Rexx/Forth/Smalltalk) already use — just with a *bigger* seam:

```
  TCP socket  ─┐
  CBOR codec  ─┤  HOST (thin driver: C / Rust / Python)   ← I/O + framing + crypto primitive
  Ed25519     ─┘        │  asserts facts / binds params
                        ▼
              QUERY ENGINE (SQLite / embedded Datalog)    ← the authority verdict logic (authored here)
                        │  returns (status, code) / derived `authorized` relation
                        ▼
              HOST emits response frame
```

The host is a **byte-pump + FFI seam**, structurally identical to the peers we've already built. What's
novel is that the §5.2 verify ladder / §6.9 delegation closure / §3.6 K-of-N live in the query language.

### SQL runtime options

| Runtime | Model | Fit |
|---|---|---|
| **SQLite** | Embedded C lib, in-process, single file / `:memory:`. Recursive CTEs ✓. **Application-defined functions** (register a host `ed25519_verify` callable *from* SQL) ✓. Transactions ✓. | **Best first probe** — smallest host, crypto-callable-from-SQL tightens the seam, transactions give a real §7b store story. |
| **DuckDB** | Embedded analytical, in-process, recursive CTEs ✓, UDFs ✓. | Modern alt to SQLite; analytical bias, less transactional. |
| **PostgreSQL + PL/pgSQL** | Full server; PL/pgSQL is Turing-complete procedural stored-proc language; MVCC. | Heavier (server + sockets still need host / `plpython` / bg-worker). MVCC = structural §7b. Use only if we want the *procedural-SQL* axis. |

**Recommendation: SQLite.** In-process, ubiquitous, recursive CTEs for the chain walk, and
app-defined functions let the *whole ladder incl. the crypto-call sequencing* stay in SQL (only the
primitive is host).

### Datalog runtime options

| Runtime | Model | Fit |
|---|---|---|
| **Soufflé** | Datalog→parallel-C++; **batch** (facts in, fixpoint, relations out). User-defined functors → C++ (crypto seam). | Powerful but per-request process-spawn tax unless run as a persistent harness. |
| **Ascent / Datafrog / Crepe** (Rust) | **Embedded** Datalog as a Rust library/macro; in-process, no spawn. Datafrog is what Polonius/rust-analyzer use. | **Best embedded Datalog** — a Rust host does I/O+CBOR+crypto, rules are in-process. |
| **XSB / Datomic / DDlog** | Tabled-Prolog / Clojure-DB / incremental. | Niche; DDlog (incremental) interesting if we ever want live-updating grants. |

**Recommendation: a Rust host + Ascent (or Datafrog).** In-process, and Rust already has our codec/crypto
story — the seam is clean.

---

## 2. What it looks like (the authority interior, illustratively)

### SQL — the §5.2 verify ladder as a query

Grants and the presented token are tables; the verdict is a query. Sketch (SQLite dialect):

```sql
-- tables: grant(subject, path_prefix, granted_by, expires_at, not_before, caveats)
--         request(author, path, op, sig, content_hash, now)

WITH RECURSIVE
  -- §6.9 delegation closure: who can this token's issuer speak for?
  chain(subject, path_prefix, depth) AS (
    SELECT subject, path_prefix, 0 FROM grant WHERE granted_by = :root_peer
    UNION ALL
    SELECT g.subject, g.path_prefix, chain.depth + 1
    FROM grant g JOIN chain ON g.granted_by = chain.subject
    WHERE chain.depth < :max_chain_depth        -- §9.1 depth floor
  )
SELECT
  CASE
    WHEN NOT ed25519_verify(r.sig, r.author, r.content_hash) THEN ('401','authentication_failed') -- app-defined fn
    WHEN r.now >= (SELECT expires_at FROM ...)                THEN ('403','capability_expired')
    WHEN NOT EXISTS (SELECT 1 FROM chain
                     WHERE :req_path GLOB path_prefix || '*')  THEN ('403','capability_denied')
    ELSE ('200','ok')
  END AS verdict
FROM request r;
```

The delegation walk is a **recursive CTE** (the canonical transitive-closure pattern); K-of-N is
`HAVING count(DISTINCT signer) >= :threshold`; crypto is an **application-defined function** the host
registers, so even the verify *sequencing* is in SQL. That is genuinely most of the §5.2 interior.

### Datalog — the §6.9 delegation model as rules

Authorization is *derived*; the host asserts cryptographically-established facts, Datalog closes over
delegation. Sketch:

```prolog
% host-asserted facts:  grant(Subject, PathPrefix, GrantedBy).  verified_signer(Author).  request(Author, Path).
% (host verifies the Ed25519 sig FIRST, then asserts verified_signer/1 — Datalog never touches crypto)

authorized(P, Path) :- grant(P, Prefix, root),        prefix(Prefix, Path).
authorized(P, Path) :- grant(P, Prefix, Q), authorized(Q, _), prefix(Prefix, Path).   % recursive delegation

allow(Author, Path) :- request(Author, Path), verified_signer(Author), authorized(Author, Path).
```

This is **exactly the trust-management pattern** (Binder = Datalog + `says`; SecPAL; DKAL). The recursive
delegation rule is the textbook Datalog "ancestor" closure. The host establishes `verified_signer` (it
did the crypto); Datalog derives `allow`. Clean separation.

---

## 3. The seam split (the finding)

The reason this is worth a probe: it **partitions the protocol** precisely.

| Protocol region | SQL | Datalog | Verdict |
|---|---|---|---|
| §5.2 verify ladder (grant match, temporal, content-hash) | ✅ query | ✅ rules | **Relational/logical — fits naturally** |
| §6.9 delegation-chain closure | ✅ recursive CTE | ✅ recursive rule (its home turf) | **Fits — this is the canonical use case** |
| §3.6 K-of-N multisig | ✅ count-aggregate | ✅ count over distinct signer facts | **Fits** |
| §6.5 dispatch *sequencing* / op-switch | ◐ awkward (CASE) | ✗ (no sequencing) | **Leaks to host** |
| Connection lifecycle / §4 handshake state | ✗ | ✗ | **Host-only (stateful-imperative)** |
| §6.11 concurrency / §7b store-safety | ✅ transactions (SQLite serialized / PG MVCC) | ✅ trivially (stateless fixpoint) | **SQL has a real structural story; Datalog is stateless-safe** |
| Canonical CBOR, Ed25519/SHA | ✗ seam | ✗ seam | **Host / `libentitycore_codec`** |

**The finding is that split itself:** the *authorization decision* half of entity-core is relational/
deductive (and SQL/Datalog express it more cleanly than imperative code), while the *protocol
sequencing + I/O* half is stateful-imperative (and the query language fights it → host). That maps
exactly which half of the protocol is "what databases/logic were built for" vs "what an imperative
runtime is for" — a mild **protocol-understanding** result, not just a substrate one.

Bonus: **SQL's transaction model is a genuine §7b store-safety story** (SQLite serialized writes /
Postgres MVCC = structural, no manual locking) — a new concurrency shape for the taxonomy.

---

## 4. Recommendation

- **Build SQLite-hosted SQL first.** Most viable, most legible, smallest host, crypto-callable-from-SQL,
  and a real transactional §7b story. This is the practical "authority-as-query" probe.
- **Then Datalog (Rust + Ascent) as the conceptual showcase** — the one that lands closest to the
  security literature (trust-management logics *are* Datalog). Purest separation: host establishes
  crypto facts, logic derives authorization.
- Both land as **exploratory / hybrid probes** (large seam; the *interior authorship* is real but
  scoped to the authority core, not the whole peer). Honesty framing per ADR-0012: the host does enough
  that this is not an independent peer — it's a paradigm probe of the authorization interior.
- **Expected yield:** the seam-split characterization above + a §7b transaction shape; **possibly** a
  mild protocol-understanding note (authority-as-trust-management-logic). Not a wire finding.

## Cross-references
- Whole-territory map: `../PARADIGM-MAP.md` (§declarative)
- Build queue: `../COMPLETENESS-ROADMAP.md` (frontier probes)
- Seam doctrine (author the interior, seam what the substrate can't do): `../SUBSTRATE-TAKEAWAYS.md`
