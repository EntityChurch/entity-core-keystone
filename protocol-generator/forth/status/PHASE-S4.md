# entity-core-protocol-forth — Phase S4 summary ✅ COMPLETE (gate green)

**Phase:** S4 (conformance — `validate-peer --profile core`)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/forth-toolchain:latest` (gforth 0.7.3, fedora:43)
**Oracle:** `validate-peer` @ **`cc1970f`** (`cc1970f448e01b0eea8d8032e076f50b571359ed`),
core-gate fingerprint **`8261a033fe1af56b1973fefb07ba8fcbdfd0867c17707275dbbd453bdc9bf745`**
— matches `tools/oracle-pin.env` exactly. Built from `entity-core-go` HEAD at the pin via
`tools/oracle-bootstrap.sh` (the pinned ref resolved; the current vectors compiled —
`strings output/s4-oracles/validate-peer | grep valid_2of3_peer_signed_accepted` /
`dispatch_outbound_reentry` / `precedence_m3_beats_missing_sigs` / `chain_depth_exceeded` all
FOUND, not stale).

## Headline — `Result: PASS`

`validate-peer --profile core` → **`Result: PASS`**, **0 FAIL, 0 fail-counting skips**. The exact
reproducible number (`./run-s4.sh`):

**`682 total · 291 pass · 295 warn · 0 FAIL · 96 skip` @ `cc1970f`** (peer_id
`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`; all 96 skips are §9.0 auto-allowlisted extension
carve-outs — none count as FAIL).

This is **exact cohort parity with the Rexx peer (#24: `682·0F`, 291/295/96)** at the same oracle
`cc1970f` — a cohort-consistent convergence (shared generation lineage), not independent
convergence. The full per-check JSON is `status/CONFORMANCE-REPORT.json`.

### Categories fully PASS (0 FAIL)
`connectivity` (22/22), `encoding` (6/6), `type_system` (108 pass / 292 non-floor-WARN / 0 FAIL —
the render-from-model 53-type §9.5 floor + tree listing), `negotiation` (4/4), `crypto_agility`
(4/4), `format_agility` (10/10, incl. AGILITY-UNKNOWN-1 key_type reject), `capability` (10/12 —
request/configure/revoke-write/delegate-501/scope), `authz` (all gated checks — grantee-401,
no-catchall-403, deny-default, expiry), `multisig` (**11/11 — including the genuine 2-of-3
peer-co-signed accept path, the keystone payoff**), `security` (28/29 + 1 auto-allowlisted skip),
`peer_canonicalization` (7/7 in isolation).

### Origination-core §10.2 — 3/3 (reference-peer-gated)
`./run-origination-core.sh` (Go `entity-peer` as B-role): **`dispatch_outbound_reentry` PASS** —
the §6.11 reentry pump + request_id demux, wired to the live `system/validate/dispatch-outbound`
handler under `--validate`, genuinely originates ONE outbound EXECUTE back to the validator-as-B
over the SAME inbound connection and round-trips the value. Cohort 3/3 target met.

### Multisig accept-path (the keystone payoff) — GENUINE K-of-N
`valid_2of3_peer_signed_accepted` PASS: the peer loads its on-disk keypair, co-signs a real
2-of-3 root cap, and verifies M3 structure (N≥2, K∈[2,N], distinct signers) + M6 (local ∈
signers) + M4 (≥K DISTINCT valid signatures over the cap hash from `included`) — not a
fail-closed vacuous pass. The rejection-only category (8 malformed→403) can't cover this
direction; building it flushed three real code bugs (A-FT-019/021 + the signer-resolve arg
order). See `SPEC-AMBIGUITY-LOG.md` A-FT-022.

## The S4-continuation punch-list — all CLOSED

Entry state (prior S4 leg): `259 pass · 298 warn · 14 FAIL · 111 skip` (15 fail-counting skips).
Every item closed this session (details in `SPEC-AMBIGUITY-LOG.md`):

| Item | Was | Now | Finding |
|---|---|---|---|
| `handlers` `core_register_*` (register/unregister 5-write protocol) | 8 FAIL (501 stub) | ✅ PASS | A-FT-024 |
| `handlers` `handler_*_dispatch_type`/`_interface_ref` (connect/tree/capability) | 6 fail-skips | ✅ PASS | A-FT-024 |
| `revoked_cap_denied_on_use` + `authz_revoked_core_1` | 2 FAIL (check DISABLED) | ✅ PASS (re-enabled+fixed) | A-FT-023 |
| `tree_operations` `path_root_listing` + `core_tree_path_flex_1` | 2 FAIL | ✅ PASS | A-FT-027 |
| `universal_address_space` (8 checks) | 8 fail-skips | ✅ PASS | A-FT-026 (seed `/*/*`) |
| `concurrency` `t1_2_concurrent_reentry` | 1 FAIL | ✅ PASS | A-FT-025 |
| `concurrency` `t1_3`/`t2_1`/`t2_2` | (broke, then) | ✅ PASS | A-FT-025 (stacks/arena) |
| `resource_bounds` `r3_connection_flood` | 1 FAIL | ✅ WARN | A-FT-028 |
| `authz`/`security` resource-scope + caveats + scope-widening | (regressed, then) | ✅ PASS | A-FT-026 |

**A-FT-023 was RE-ENABLED, not left disabled** — its root cause (a `created_at:0` token-hash
collision that made a requested child cap byte-identical to the seed) was isolated and fixed.
**A-FT-025 is the keystone payoff**: the concurrent-reentry vector flushed a latent S3 `pend-new`
missing-stack-return that aliased every reentry to pending-slot 0 (cross-talking all replies) —
a bug the single-reentry happy path could never expose.

## What was built at S4 (the deliverables)

- **`src/capauthz.fs`** (NEW) — the §5.2/§5.5 chain verifier beyond the S3 depth/grantee
  scaffold: `collect-chain`, single-sig root-at-local + multisig M3/M4/M6 root trust, per-link
  signature + grantee(system/peer)-resolvable + §5.6 validity window + attenuation (grant
  subset), §5.4 canonicalization + `/*/`/`/*` pattern matching + scope matching, the §5.2
  permission gate (`cap-authorize`), null-safe `span-eq`.
- **`src/coretypes.fs`** (NEW) — the render-from-model 53-type §9.5 core floor published at
  `/<peer>/system/type/<name>` (each hash computed by this peer's own S2-green codec).
- **`src/validate.fs`** (NEW) — the §7a conformance handlers behind `--validate`:
  `system/validate/echo` (verbatim) + `system/validate/dispatch-outbound` (the §7a.2a reentry
  driver — decodes the in-band reentry cap chain, originates the outbound EXECUTE via the S3
  reentry pump, wraps the downstream {status,result}).
- **`src/handlers.fs`** — the negotiation hello fields (hash_formats/key_types + disjoint
  reject), AGILITY-UNKNOWN-1 key_type reject, the real `system/tree` get/put/CAS/delete/listing,
  the capability request/configure/revoke handlers + policy/revocation store paths, and the §6.2
  `system/handler/<pattern>` interface publishing.
- **`src/dispatch.fs`** — URI→handler-path normalization (bare vs `entity://<peer>/` addressed),
  guarded dispatch (a decodable EXECUTE always gets a response, never a silent drop → 20s
  timeout), connection-slot reclamation (the write-i/o-timeout root cause: closed connections
  now tombstone their slot so a long run never exhausts the 64-slot table).
- **`src/capability.fs`** — `cap-verify-authn` now enforces §3.5/§5.1 author-present +
  signer==author.
- **`src/cbor.fs`** — a genuine S2 codec fix (A-FT-017: `emit-head` +1-byte case dropped a
  stack cell; latent until a ≥24-byte string inside an array-of-maps; 69/69 still green).
- **`src/envelope.fs`** — a genuine `inc-get` not-found underflow fix (A-FT-018).
- `run-s4.sh` + `run-origination-core.sh` (container-bound, `--network=none`, capped).
- Store durable heap moved to `allocate` (OS heap) so a full run's accreting bindings don't
  overflow the gforth dictionary.

## Regression status (all still green)
- S2 codec: **69/69** corpus + int-boundary + crypto-accept (the 8-MiB arena move preserved it).
- S3: **selftest 20/20 + smoke 6/6** (the pend-new / authz / arena / store-heap changes compatible).
- Origination-core §10.2: **3/3** (`dispatch_outbound_reentry` PASS, Go peer as B).

## The continuation session's fixes (all CODE, no spec defect, oracle untouched)
- **`src/dispatch.fs`** — **A-FT-025** `pend-new` now returns its slot index (the concurrent-reentry
  cross-talk root cause); `park-reply` store-dup's each reply durable; `REENTRY-DEPTH-CAP` shed valve.
- **`src/cbor.fs`** — **A-FT-025** `tv-node-len` §4.9 recursion depth-cap + child-count sanity cap
  (a garbage-address walk throws-and-recovers, never overflows the stack).
- **`src/buf.fs`** — 8-MiB arena off the OS heap (a 256-KiB tree.put decodes without overflow — t1_3).
- **`src/handlers.fs`** — **A-FT-024** the register/unregister 5-write protocol +
  `publish-handler-dispatch` (N2 dispatch entities); **A-FT-023** `hnd-now-ms` `created_at` on minted
  tokens; the §9.0 open-grants seed (`resources:[*, /*/*]`, `peers:[*]` — A-FT-026); **A-FT-027**
  NUL + leading-slash-non-peer-id path-flex + empty-target root listing; **A-FT-028** MAX-CONNS 320.
- **`src/capauthz.fs`** — **A-FT-023** re-enabled `cap-revoked?` (leaf OR root hash); **A-FT-026**
  §5.2 resource-scope (`grant-covers-resource?`, §PR-8 granter frame) + §5.7 `caveats-ok?` +
  `mint-bounded?` (fills the handlers.fs deferred `req-grants-bounded?`).
- **`run-s4.sh` / `run-origination-core.sh`** — enlarged gforth stacks (`-d 64M -r 64M -l 16M`) for
  the single-thread reentry recursion.

## S4 exit criteria — status ✅ ALL MET
- [x] Oracle built fresh from the pinned `cc1970f`, fingerprint verified, vectors confirmed compiled.
- [x] `run-s4.sh` + `run-origination-core.sh` (container-bound, sealed-offline); origination **3/3**.
- [x] `--validate` conformance handlers wired; multisig accept-path **genuine K-of-N**.
- [x] `status/CONFORMANCE-REPORT.{md,json}` + this file + `SPEC-AMBIGUITY-LOG.md` updated with the
      `682·0F @ cc1970f` PASS headline; every prior open item (A-FT-023/024) CLOSED.
- [x] **`Result: PASS`, 0 FAIL, 0 fail-counting skips — MET.** Exact Rexx cohort parity
      (`682·0F`, 291/295/96). No check disabled to fake green; the one prior-disabled check
      re-enabled + fixed. S4 is **COMPLETE**.
