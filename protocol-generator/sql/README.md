# entity-core-protocol-sql

A full **entity-core protocol** core peer (V8 / v0.8.0, Layers 0–4) whose
authorization interior is authored as **real SQL** over **SQLite 3.50.4**, with a
thin C host owning sockets, framing, canonical CBOR, crypto, and the store. Peer
target `sql`; the cohort's **authority-as-query probe**.

> **Status: exploratory probe (Tier: probe).** Not a deployable-tier, independent
> peer. It is a **seam-hybrid**: the wire codec, Ed25519/SHA, and byte I/O are
> delegated to `libentitycore_codec` (shared C-ABI lineage), so this is a
> **cohort-consistent** 0-fail against one author's vectors — *not* an independent
> reimplementation (ADR-0012). The payoff is the *finding*, not a deployment: see
> `arch/PROFILE-RATIONALE.md` and `status/SPEC-AMBIGUITY-LOG.md`.

## The probe — authorization is a query; the protocol around it is a state machine

The bet: the *authorization decision* half of entity-core is relational and
expresses **cleanly** in SQL, while the *protocol sequencing + I/O* half is
stateful-imperative and **leaks to the host**. Characterizing exactly where that
line falls is the deliverable — and it fell exactly where hypothesized. The
decision half is authored, legibly, in `src/sql/`:

- **§5.2 verify ladder** (`verify_ladder.sql`) — one `CASE` ladder; the arm order
  *is* the algorithm order, crypto inline as an app-defined function.
- **§5.5 delegation chain-walk** (`chain_walk.sql`) — `WITH RECURSIVE`, the
  canonical transitive-closure form; §4.10(b) depth pre-check is `max(depth) > 64`
  over the walk CTE.
- **§3.6 K-of-N multisig** (`k_of_n.sql`) — `GROUP BY … HAVING
  count(DISTINCT signer) >= k`, the sharpest fit in the whole encoding.
- **§6.6 handler resolution** (`resolve.sql`) — longest-prefix as
  `ORDER BY length(path_prefix) DESC LIMIT 1`.
- **§5.4 scope matching** (`scope_match.sql`) — `value GLOB canonicalize(pattern)`;
  §5.10 verdict-time is a *bound column* (`now_ms`) → pure-function determinism.

**The finding (A-SQL-003):** *everything that is a pure function of the projected
request facts stays SQL; everything stateful-sequential leaks to the host.* Two
spec-shaped sub-findings fell out of the relational encoding — A-SQL-007 (GLOB `*`
is not segment-anchored, unlike §5.4's peer-wildcard) and A-SQL-008 (the §3.6
path-scope/id-scope split maps onto *two* SQL match strategies, sharper than the
prose's single uniform `matches_scope`). Both are escalated to architecture.

## Architecture — the seam boundary

The seam is drawn at exactly what SQL genuinely cannot do (bytes / CBOR / crypto /
sockets / store I/O); everything above it is authored.

- **Codec / crypto / transport seam** — a thin C host (`src/host/`) links
  `libentitycore_codec` (the language-agnostic C-ABI) for canonical ECF CBOR,
  content-hash, peer-id, and Ed25519 + SHA-2, plus the SQLite amalgamation compiled
  in-process. The host owns TCP sockets, §1.6 framing + frame-cap, the §6.5
  op-switch, the §4 handshake state machine + PoP, and the §5.8 authority-chain
  **projection** into the SQL tables. Crypto **re-enters SQL** as app-defined
  functions (`ed25519_verify`, `sha256`, `content_hash`) so the *verify sequencing*
  stays in SQL and only the primitive crosses the C-ABI.
- **Authority interior in SQL** — `src/host/project_and_verify()` projects the
  §5.8 chain (`envelope.included` → `peer`/`cap`/`grant_scope`/`signature`/
  `multi_signer` tables), binds the request row + `now_ms`, and runs the ladder for
  the `(status, code)` verdict; the resolved handler body runs **only** on `'ok'`.
  The wrapper-guard holds: no host allow/deny branch ever short-circuits the SQL
  verdict.
- **Store / concurrency** — fork-per-connection over a file-backed WAL store (§7b
  store-safety is structural via process isolation + SQLite journaling); the
  authority projection is a per-request `:memory:` db (determinism structural).
  §6.11 reentry is a host **request_id correlation map** (the non-actor/non-CSP
  shape) — dispatch-outbound sends the reentry non-blocking and records `(orid→rid)`;
  the connection loop routes each `EXECUTE_RESPONSE` by request_id.

## Build & run (container-bound)

Everything runs inside `containers/sqlite-toolchain/` (SQLite 3.50.4 amalgamation,
SHA-pinned; `libentitycore_codec` built from source; a baked GO-gate self-test).
Host writes never leave the working tree — build artifacts go to a container-local
scratch dir (see the `Makefile` header).

```
./run-s2.sh                 # S2: codec seam + wire corpus 71/71 gate
./run-s3.sh                 # S3: the authority-as-query harness (make authority-check)
./run-s4.sh                 # S4: validate-peer --profile core (the live gate)
./run-s4.sh -category multisig
./run-origination-core.sh   # §10.2 origination-core (SQL A-role, Go B-role) 3/3
make dist                   # S5: source tarball (dist/entity-core-protocol-sql-0.1.0-pre.tar.gz)
```

Inside the container:

```
make check            # wire corpus 71/71 + N1–N4 + Ed25519 KAT + crypto-from-SQL KAT
make authority-check  # run the VERBATIM src/sql/*.sql over real Ed25519 facts (13/0F)
make peer             # compile the C host (embeds the .sql)
```

`--name NAME` loads the persistent Ed25519 identity from
`~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed).
`--validate` enables the `system/validate/*` conformance handlers (off by default).
`--debug-open-grants` is the degenerate `default→*` seed (conformance only; the
open seed uses the dual `resources = ["*", "/*/*"]` form — §5.5a bare-star is
granter-local, A-PD-017).

## Conformance

[![conformance: 682·0F @ cc1970f — Result: PASS](https://img.shields.io/badge/conformance-682%C2%B70F%20%40%20cc1970f-brightgreen)](status/CONFORMANCE-REPORT.md)

**`validate-peer --profile core` → `Result: PASS` — 682·0F @ cc1970f**
(291 P / 295 W / 0 F / 96 S). See `status/CONFORMANCE-REPORT.md` for the
oracle-pinned per-category P/W/F/S breakdown. Additional mandatory coverage the
core gate can't reach: **origination-core 3/3** (`run-origination-core.sh`),
**live 2-of-3 multisig accept** (the `multisig` oracle category is rejection-only —
a vacuous-green trap — so the accept path is proven by a genuine unit test), and
the **71/71 wire corpus** re-confirmed byte-identical (`make check`).

### Honest framing (ADR-0012)

- **Cohort-consistent, not independent convergence.** The codec/crypto is
  `libentitycore_codec` (shared C-ABI lineage) and the peer shares the keystone
  generation lineage. This is a 0-fail against one author's vectors, not an
  independent reimplementation.
- **The type registry is served, not reflected.** SQL has no data model to reflect
  over, so this peer serves the shared Go-rendered §9.5 type-registry vectors (the
  one legitimate byte-exact exception) — scoped to the core floor + operational +
  bootstrap types; extension vocabularies are NOT pre-published (they WARN by
  absence). Honestly a seam, not an independent type system.
- **Probe-tier, not deployable.** The value is the authority-as-query finding, not
  a production peer. It is a readable reference for the SQL / database community:
  the entity-core authorization model as legible relational queries.

## License

Apache-2.0 (`LICENSE`). SQLite is public-domain; `libentitycore_codec` is
Apache-2.0 (links libsodium, ISC).
