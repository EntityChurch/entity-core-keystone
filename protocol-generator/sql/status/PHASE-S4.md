# Phase S4 — Conformance (the SQL / authority-as-query peer)

**`validate-peer --profile core` → `Result: PASS` — 682·0F @ cc1970f
(291 P / 295 W / 0 F / 96 S). S4 completed 2026-07-16.**

S4 turned the S3 authority-as-query core (handshake + §6.6 resolve + the proven ladder over a
harness) into a full live core peer: the §5.8 authority-chain PROJECTION into the SQL tables,
the MUST handler bodies (tree/type/capability/handler/validate), and the §6.11 reentry seam —
all driven to a clean core gate against the fresh `cc1970f` oracle. **The wrapper-guard
survived**: the authority verdict is still the authored `src/sql/verify_ladder.sql`; the host
projects facts and dispatches the body only on `'ok'`.

## Gate

`./run-s4.sh` — container-bound, capped, `--network=none`; peer `--name conformance
--debug-open-grants --validate`. Result **`PASS`, 0 fail**. `./run-origination-core.sh`
(reference-peer-gated) → **origination 3/3**. `make authority-check` → **13/0F** (ladder still
correct). `make check` → **71/71** wire corpus (79 with self-tests).

## Iteration log (what each FAIL taught) — ~8 gate iterations

1. **Baseline** 64·P / 159·F: the S3 peer answered only handshake + 404. Every post-connect
   EXECUTE 404'd — the wire URI carries the `entity://{peer}/…` scheme; handler paths +
   `resolve.sql` are `/{peer}/…`. Normalize the scheme → resolve fires. *(→ 103 P)*
2. **Resource shape**: `exec.data.resource` is a **bare map** `{targets:[…]}`, not an entity
   with a `.data` level — my projection + `exec_target` went a level too deep, so type/tree
   fetches fell back to the handler root. Fix the path. *(→ 181 P)*
3. **Type registry** (the 108-check wall): (a) the vector `data` is a CBOR **byte string
   wrapping** the ECF TypeDefinition map — store the inner map, not the envelope; (b) the
   `included` map + listing `entries` map + listing-entry keys were **not canonically
   ordered** (byte-sorted keys / length-then-lex). Sort them. Seed `system/handler/interface`
   entities so the handler listing resolves. *(→ 262 P, type_system 0-fail)*
4. **Handler/capability/tree completion**: register creates interface+manifest+grant(+sig) and
   returns `register-result{pattern}` + supports unregister; revoke rejects a zero token and
   writes the §5.1 revocation marker entity; configure validates the peer_pattern (rejects
   partial prefixes) and writes the policy entry; tree `put` gains §6.3 CAS (`expected_hash`,
   zero-hash=create) + §1.4 path-flex (`./ ../ //`, embedded NUL, leading-slash-must-be-a-
   valid-peer-id) + §6.3 deletion-marker omission from listings. *(→ 287 P)*
5. **Handshake edges**: §4.5 hello rejects a disjoint `hash_formats`/`key_types` (→ 400);
   authenticate rejects an unknown key_type in the claimed peer_id (0xfd agility probe → 400,
   not a 401 id-mismatch). §5.2 arm precedence: the unresolvable-grantee (401) arm must precede
   the grantee-mismatch (403) arm (AUTHZ-GRANTEE-1) — **resolved A-SQL-010** in the ladder.
6. **§6.11 reentry** (`concurrency.t1_2`): the naive "originate reentry, block-read the next
   frame" recurses through pipelined concurrent reentries on ONE fd and discards responses that
   outer levels await → deadlock/timeout. Rebuilt as the profile's declared **request_id
   correlation map**: dispatch-outbound sends the reentry non-blocking + records `(orid→rid)`;
   the main loop routes each reentry EXECUTE_RESPONSE (by request_id) back to a dispatch-outbound
   response. Clears t1_2 (8/8) AND origination-core `dispatch_outbound_reentry`. *(→ 291·0F)*

## What survived the substrate (durable notes)

- **The seam split held under load.** The authority DECISION stayed a pure SQL query invoked
  once per request; everything new at S4 (URI normalization, the §5.8 → tables projection, the
  handler bodies, framing, the reentry correlation map) is **host imperative shell** — exactly
  the A-SQL-003 line. The projection is mechanical host plumbing feeding the already-proven
  ladder; no new authority SQL was needed beyond the A-SQL-010 arm reorder.
- **§6.11 on a request/response substrate is a host correlation-map tax** (the non-actor/
  non-CSP shape the profile predicted), not a dataflow-variable freebie (Oz) nor an actor demux
  (Swift) — the reentry is send-nonblocking + route-by-request_id in the single-fd loop.
- **Type registry: served, not reflected.** SQL has no data model to reflect, so this peer
  serves the shared Go-rendered vectors (the legitimate byte-exact exception) — honestly a
  seam, not an independent type system. It scopes to the §9.5 floor + operational + bootstrap;
  extension vocabularies are NOT pre-published (WARN by absence).

## Files written / changed this phase

- `src/host/peer.c` — the §5.8 projection (`project_and_verify` + `project_*`), the store
  (file-backed WAL: node/handler_reg/revoked), `seed_types` (byte-string-unwrapped),
  `seed_handler_entities`, per-child DB init, canonical `wb_included`, §4.5 hello negotiation,
  authenticate key_type gate, `--debug-open-grants` open seed, `reentry_route` demux.
- `src/host/handlers.inc.c` (new) — the MUST handler BODIES: tree get/put/list (CAS + path-flex
  + deletion-marker), type serve + `:validate`, capability request/delegate/revoke/configure,
  handler register/unregister, validate echo + `dispatch-outbound` (§6.11 non-blocking reentry).
- `src/sql/verify_ladder.sql` — A-SQL-010 resolved: unresolvable-grantee (401) precedes
  grantee-mismatch (403).
- `run-s4.sh`, `run-origination-core.sh` (new); `Makefile` (peer dep on the .inc.c).
- `status/CONFORMANCE-REPORT.{md,json}`, this file, `status/SPEC-AMBIGUITY-LOG.md`.

## Handoff to S5 (stabilization / publish)

1. **Publish** `0.1.0-pre` (probe-tier, seam-hybrid) once the overseer accepts — the gate is
   green (`682·0F @ cc1970f`), origination 3/3, corpus 71/71, wrapper-guard intact.
2. **A-SQL-009 partially resolved**: the §5.2 concrete resource-target arm is live + gated
   (tree_operations green). The heavier PATTERN-overlap arm + `is_attenuated` scope_subset are
   still only exercised by delegate-handler-gated ext vectors a core peer honest-SKIPs — carry
   forward as a documented completion item, not a gap.
3. **Route A-SQL-008 / A-SQL-007** to arch as a packet in `docs/outbox/` (the
   id-scope/path-scope two-strategy clarification + GLOB segment-anchoring) — the probe's
   spec-shaped payoff, unchanged by S4.
4. **Tier-tracking**: this is an exploratory ‡ probe, not a Tier-1 lockstep peer. Re-run
   `./run-s4.sh` on each amendment that touches the wire/authority core; the value is the
   authority-as-query FINDING, not per-amendment lockstep.
5. **Non-plumbing caveat for a reviewer**: the peer is fork-per-connection with a file-backed
   WAL store (§7b store-safety structural via process isolation + SQLite journaling); the
   authority projection is a per-request `:memory:` db (determinism structural). This is host
   design, documented — not a §7b finding.
