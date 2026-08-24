# Changelog — entity-core-protocol-sql

## v0.1.0-pre (2026-07-16)

Initial full core peer — **tracks ENTITY-CORE-PROTOCOL v0.8.0 / V8** (Layers 0–4).
The cohort's **authority-as-query probe** (peer target `sql`): the entity-core
authorization interior authored as legible SQL over SQLite, with a thin C seam
host. Seam-hybrid, probe-tier; cohort-consistent, not independent convergence
(ADR-0012).

### Codec / crypto seam (S2)
- Thin C host (`src/host/ec_seam.c`) over `libentitycore_codec` (**C-ABI 1.1**,
  `ec_abi_version` pinned): canonical ECF CBOR + content-hash + peer-id + Ed25519 +
  SHA-2. SQL cannot assemble wire bytes — the codec/crypto floor is delegated by
  definition; crypto **re-enters SQL** as app-defined functions.
- Wire corpus **71/71 byte-identical** to the oracle (79 with the N1–N4 + Ed25519
  RFC-8032 KAT + crypto-callable-from-SQL self-tests). `content_hash.4` is
  PASS-by-correct-unsupported (format 128 ∉ {0,1} → refuse, don't fabricate;
  A-SQL-005).
- V7→V8 core wire byte-unchanged, **wire-confirmed** by byte-identity, not assumed
  (A-SQL-001); the codec's `spec-data v7.71` provenance string is a cosmetic
  build-metadata lag, not a wire divergence.

### Authority interior (S3)
- The §5/§6.6 decision half authored as real SQL in `src/sql/`: §5.2 verify ladder
  (`verify_ladder.sql`), §5.5 chain-walk (`chain_walk.sql`, `WITH RECURSIVE`), §3.6
  K-of-N (`k_of_n.sql`, `GROUP BY … HAVING`), §6.6 longest-prefix
  (`resolve.sql`), §5.4 scope matching (`scope_match.sql`, `GLOB`).
- **The seam-split finding (A-SQL-003):** everything that is a pure function of the
  projected request facts stays SQL; everything stateful-sequential leaks to the
  host. Authorization is a query; the protocol around it is a state machine.
- Authority harness (`make authority-check`): the **verbatim** authored `.sql` run
  over real Ed25519-signed facts → **13/0F** (the §5.2a trichotomy + §4.10 depth-400
  pre-check + §6.6 longest-prefix + the mandatory 2-of-3 multisig ACCEPT).

### Conformance (S4)
- **`validate-peer --profile core` → `Result: PASS` — 682·0F @ cc1970f**
  (291 P / 295 W / 0 F / 96 S). connectivity 22/22; type_system 108/292/0 (§9.5
  floor served byte-exact); security 28/0; multisig 11/0; concurrency 5/0.
- **origination-core 3/3** (`reference_connect`, `reference_ready`,
  `dispatch_outbound_reentry`) against the Go `entity-peer` B-role.
- §6.11 reentry rebuilt as the host **request_id correlation map** — the
  non-actor/non-CSP shape the profile predicted (clears `concurrency.t1_2` 8/8).
- Genuine **2-of-3 multisig accept-path** unit test (the `multisig` oracle category
  is rejection-only — vacuous-green trap; A-SQL-004).
- A-SQL-010 resolved (unresolvable-grantee 401 precedes grantee-mismatch 403);
  A-SQL-009 partially resolved (concrete resource-target arm live + gated).

### Toolchain / deps
- SQLite **3.50.4** (amalgamation, SHA-256 pinned), source-built; recursive CTEs +
  application-defined functions + GLOB + `GROUP BY`/`HAVING` are all core (no
  extensions/flags).
- `libentitycore_codec` **C-ABI 1.1** (built from `entity-core-codec-ffi-c`;
  libsodium 1.0.22 statically + privately linked). Built against the **canonical**
  C-ABI header (`ffi-generator/c-abi/spec`), not the image's drift-prone bundled
  copy (A-SQL-006).
- gcc 15.2.1 (fedora:43); all pins mirrored in
  `containers/sqlite-toolchain/Containerfile`.

### Packaging
- `make dist` → source tarball `dist/entity-core-protocol-sql-0.1.0-pre.tar.gz`
  (the `.sql` interior + C host + run/conformance scripts + `profile.toml` +
  `status/` + `LICENSE`). Registry publish **deferred** like the cohort — SQLite has
  no peer registry for such an artifact; publish = an operator-tagged git release.

### Known / escalated
- **A-SQL-007** (GLOB `*` is not segment-anchored, unlike §5.4's peer-wildcard) and
  **A-SQL-008** (id-scope vs path-scope → two match strategies, sharper than the
  prose's uniform `matches_scope`) — escalated to architecture (overseer-routed
  `HANDOFF-TO-ARCH`). Non-blocking for the core gate.
- **A-SQL-009** completion item: the heavier §5.2 pattern-overlap arm +
  `is_attenuated` scope_subset are exercised only by delegate-handler-gated ext
  vectors a core peer honest-SKIPs — documented, not a gap.
