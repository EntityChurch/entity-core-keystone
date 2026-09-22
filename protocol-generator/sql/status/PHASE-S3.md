# Phase S3 — SQL peer machinery + the authored authority interior

**The declarative-query / authority-as-query probe · exploratory ‡ (probe) tier · seam-hybrid ·
S3 completed 2026-07-16**

S3 is the **heart of the probe**: author the §5/§6.6 authority INTERIOR as legible SQL over
grant/token/handler tables (the wrapper-guard), build the C host imperative shell on the S2 seam,
and characterize the **seam split** — how much of entity-core's authority stays expressible as SQL
vs. leaks to the host. The finding is the deliverable, co-equal with the smoke gate.

## Honest framing (ADR-0012)

Not independent convergence — the codec/crypto is `libentitycore_codec` (shared C-ABI lineage) and
the peer shares the keystone generation lineage. The live-oracle number below is **cohort-consistent
against one author's vectors**, not independent convergence. Every number is oracle-pinned and
reproduced in-container, capped, `--network=none`.

## The three S3 gates — all GREEN

Reproduce: `./run-s3.sh` (gates 1+2) or `./run-s3.sh oracle` (adds gate 3). In-container
(`entity-core-keystone/sqlite-toolchain:latest`), capped (`$PODMAN_RUN_CAPS`), `--network=none`
(loopback up in the isolated netns).

### Gate 1 — the AUTHORITY-AS-QUERY harness (the probe's headline): **13 pass, 0 fail**

`make authority-check` runs the VERBATIM `src/sql/*.sql` (verify_ladder / resolve / k_of_n) over
**real Ed25519-signed facts** — an oracle-driven interpreter of the actual authored artifact
(the TurboWarp-#32 pattern on the relational substrate; no reimplementation of the authority logic
in C). Coverage:

| Check | Verdict | Surface |
|---|---|---|
| allow_tree_get | 200 ok | full ALLOW path (verify + resolve + check_permission) |
| auth_fail_no_exec_sig / wrong_signer | 401 authentication_failed | §5.2 step-2 auth-class |
| authz_grantee_mismatch | 403 capability_denied | §5.2 step-3 |
| unresolvable_grantee | 401 unresolvable_grantee | §5.5 PR-3 carve-out (interior link) |
| authz_scope_deny_operation | 403 capability_denied | §5.2 check_permission |
| not_found_unregistered_path | 404 not_found | §6.6 resolve → no handler |
| authz_expired | 403 capability_denied | §5.2 temporal |
| chain_depth_exceeded_400 | 400 chain_depth_exceeded | §4.10(b) STRUCTURAL pre-check (66-link chain) |
| resolve_longest_prefix | picks the longer prefix | §6.6 ORDER BY length DESC LIMIT 1 |
| **multisig_2of3_ACCEPT** | **200 ok** | **§3.6 K-of-N ACCEPT (A-SQL-004 mandatory)** |
| k_of_n_having_accept | satisfied=1 | k_of_n.sql GROUP BY … HAVING standalone |
| multisig_1of3_REJECT | 403 capability_denied | K-of-N below threshold |

The crypto (`ed25519_verify`) runs INLINE inside the queries — the verify sequencing stays in SQL.

### Gate 2 — the peer WIRE smoke (`ec-sql-peer --selftest`): **0 checks failed**

A real loopback TCP handshake, self-driven (the responder + a forked initiator sharing the same
proven CBOR machinery):

- **leg 1 hello** → EXECUTE_RESPONSE `system/protocol/connect/hello` (status 200, 32-byte nonce)
- **leg 2 authenticate** → real Ed25519 PoP (nonce-echo + signature-verify + identity-binding) →
  EXECUTE_RESPONSE `system/capability/grant` (status 200)
- **404** on a post-auth EXECUTE to an unregistered path — via the authored `resolve.sql` running
  in the LIVE host (not just the harness)
- **request_id demux** — two interleaved requests, each response echoes its own id (rid-A:200, rid-B:404)

### Gate 3 — LIVE Go oracle (higher-bar S4 preview): **connectivity 22 / 0F — Result: PASS**

`validate-peer -category connectivity` (the REAL Go initiator doing the §4.1 handshake) against the
peer: **22 passed, 0 warned, 0 failed** — every connectivity check green, including
`authenticate_granter_identity`, `authenticate_capability_signature`, the six §4.6 handshake-probe
rows (nonce-echo / signature / impersonation / peer-id-binding / cross-connection replay), and
`request_id_echoed`. Oracle pinned at `cc1970f` (vendored; **rebuild from go HEAD before S4** per
AGENTS.md — this run is the S4 preview, not the S4 gate).

## The wrapper-guard held — the interior is REAL SQL

Point to the artifact: `src/sql/` — `schema.sql` (the relational projection of the store),
`verify_ladder.sql` (§5.2/§6.5 verdict as one CASE ladder), `chain_walk.sql` (§5.5 WITH RECURSIVE),
`scope_match.sql` (§5.4/§5.5a JOIN + GLOB), `k_of_n.sql` (§3.6 GROUP BY … HAVING), `resolve.sql`
(§6.6 longest-prefix). None of this is folded into a host call — the C host (`src/host/peer.c`)
PROJECTS facts into tables and asks SQL for the verdict; the §6.6 resolve query runs in the live
peer's 404 path. The FLOW-DESIGN decomposition guard (Node-RED #31 / TurboWarp #32 / Pd #33) applied
to a query substrate.

## THE AUTHORITY-AS-QUERY FINDING (A-SQL-003 resolved)

The seam split falls **exactly where hypothesized**, now characterized from the running artifact
(full detail in `profile.toml [authority_interior_expressibility]` + the ambiguity log):

- **Stays SQL, expresses cleanly** (the authorization DECISION): §5.2 verify ladder, §5.5 recursive-
  CTE chain-walk, §3.6 K-of-N (`GROUP BY … HAVING` — the single sharpest fit), §6.6 longest-prefix,
  §5.10 verdict-time (a bound column → structural determinism), §4.10(b) depth pre-check.
- **Leaks to host, as predicted** (the protocol SEQUENCING + I/O): §6.5 op-switch + framing, §4
  handshake state machine + PoP.
- **The precise rule:** *everything that is a PURE FUNCTION of the projected request facts stays SQL;
  everything STATEFUL-SEQUENTIAL leaks to the host.* Authorization is a query; the protocol around it
  is a state machine. Trust-management logics (SecPAL/Binder) were right — the entity-core authority
  interior has a genuine relational structure the imperative spec text obscures.

Two spec-shaped sub-findings surfaced FROM the encoding (candidate `HANDOFF-TO-ARCH`):

- **A-SQL-008** — §3.6 already types the grant dimensions into path-scope vs id-scope; the relational
  form makes that a TWO-strategy split (id dims match RAW, path dims canonicalize) that is SHARPER
  than the prose's single uniform `matches_scope(canonicalize(value), canonicalize(pattern))`. (Found
  as a real bug first: canonicalizing operations as paths broke the ALLOW path; the fix IS the split.)
- **A-SQL-007** — SQLite GLOB `*` is not segment-anchored, so it is a faithful `matches_pattern` for
  the core pattern set (`*`, `/*/*`, exact, trailing-subtree — byte-exact) but would over-match a
  `/*/specific` peer-wildcard; the fully-general encoding needs segment-anchoring.

## v7.75 non-functional floor — baked in (not rediscovered at S4)

- §4.10(a) **413 payload_too_large** — frame-cap checked on the length prefix BEFORE buffering the body.
- §4.10(b) **400 chain_depth_exceeded** — the depth>64 pre-check is the FIRST arm of verify_ladder.sql,
  before the O(depth) authz walk; a 400 (structural), not 403. Proven by the 66-link harness check.
- §4.9(c) **deliver-or-signal** — the dispatch scaffold maps every path to a coded response; the host
  ROOT error class → 500 (resilience frame), never a silent drop/hang.
- §4.8 **store-safety** — fork-per-connection: process isolation makes concurrent inbound dispatch
  race-free structurally (each connection its own store copy). §7b **TCP_NODELAY** on the raw socket.

## New / updated findings this phase

A-SQL-003 RESOLVED (the seam split). New: A-SQL-007 (GLOB peer-wildcard), A-SQL-008 (path/id-scope
split — candidate HANDOFF-TO-ARCH), A-SQL-009 (resource pattern-overlap arm — S4 completion item),
A-SQL-010 (compound-failure verdict precedence). See `SPEC-AMBIGUITY-LOG.md`.

## Files written this phase

- `src/sql/schema.sql` — the relational projection of the entity store (the probe's tables).
- `src/sql/verify_ladder.sql` — §5.2/§6.5 verdict trichotomy as one CASE ladder over CTEs (centerpiece).
- `src/sql/chain_walk.sql` — §5.5 collect_authority_chain as WITH RECURSIVE.
- `src/sql/scope_match.sql` — §5.4/§5.5a matches_scope as JOIN + GLOB.
- `src/sql/k_of_n.sql` — §3.6 K-of-N as GROUP BY … HAVING count(DISTINCT signer) >= k.
- `src/sql/resolve.sql` — §6.6 longest-prefix resolution as one query.
- `src/test/authority_test.c` — the authority-as-query harness (13 checks; verbatim .sql over real facts).
- `src/host/peer.c` — the C host imperative shell (sockets + framing + frame-cap + §4 handshake +
  §6.5 dispatch scaffold + SQLite store running the authored SQL + the `--selftest` smoke initiator).
- `run-s3.sh` — the container-bound, capped, offline S3 gate runner (authority + smoke + optional oracle).
- `Makefile` — added `authority-check` + `peer` targets.
- `status/PHASE-S3.md` (this file); `status/SPEC-AMBIGUITY-LOG.md` (A-SQL-003 resolved; 007–010 added);
  `profile.toml` `[authority_interior_expressibility]` filled in.

## Phase exit criteria — MET

- [x] Authority interior authored as legible, foregrounded SQL (wrapper-guard held — real SQL, not a
      folded host call; the §6.6 query runs in the live peer).
- [x] Authority-as-query gate GREEN: 13/13 over real Ed25519 facts, in-container, capped, offline.
- [x] Mandatory 2-of-3 multisig ACCEPT proven (A-SQL-004) — the direction the oracle can't cover.
- [x] Smoke gate GREEN: real §4.1 handshake both ways + §6.6 404 + §6.11 request_id demux.
- [x] Live-oracle connectivity 22·0F PASS (S4 preview) — the peer talks at the wire level, confirmed
      by the real Go initiator.
- [x] v7.75 non-functional floor baked in (413 / 400-before-authz / deliver-or-signal / TCP_NODELAY /
      store-safety).
- [x] `[authority_interior_expressibility]` filled per element (hypothesis → outcome → finding).
- [x] Peer compiles cleanly (no warnings) in-container; the code reads as C + SQL, not transpiled.

## Handoff to S4 (conformance)

1. **Rebuild the oracle binaries from `entity-core-go` HEAD** (`CGO_ENABLED=0 GOWORK=off` in
   `containers/go`) and verify new validator vectors compiled (`strings validate-peer | grep <vector>`)
   — the vendored `cc1970f` is fine for the S3 preview but MUST be rebuilt before the S4 gate.
2. **Wire the full §5.2 verify_request cap-chain projection into the live host.** S3's live host runs
   the §6.6 resolve query on the post-auth path (404 surface) + the full handshake; the remaining work
   is projecting the presented cap chain / signatures / identities from `envelope.included` into the
   `cap`/`signature`/`peer`/`grant_scope` tables so verify_ladder.sql runs on every authenticated
   EXECUTE. The authority harness already proves the ladder is correct over those facts — S4 is the
   PROJECTION plumbing (host, mechanical), not new SQL. Target the `authz` + `security` categories.
3. **Complete the §5.2 resource pattern-overlap arm** (A-SQL-009) if an S4 vector reaches it; author
   `is_attenuated` scope_subset for the delegate-handler-gated attenuation vectors (currently
   honest-SKIP for a core peer). Consider the §6.9a policy-table lookup as a SQL query (moves the
   authenticate-grant verdict INTO SQL — a natural authority-as-query extension).
4. **Route A-SQL-008 (and A-SQL-007)** as a packet in `docs/outbox/` — the path/id-scope
   two-strategy clarification is the probe's spec-shaped payoff.
5. **`--profile core` target:** 682·0F (per the profile `[conformance]`). Rebuild oracle, run
   `run-s4.sh` (single-peer honest-SKIPs the reference-peer-gated origination-core probes; run those
   via `run-origination-core.sh`).
