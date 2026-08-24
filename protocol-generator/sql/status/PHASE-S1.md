# Phase S1 — SQL (authority-as-query) feasibility gate + profile

**The declarative-query / authority-as-query probe · exploratory ‡ (probe) tier ·
seam-hybrid · started 2026-07-16**

First of the two last major spec-discovery bets (SQL + Datalog). NOT a wire-axis or a
substrate probe — the axis is **spec-shaped**: how much of the §5/§6.6 authority interior
stays expressible as SQL vs. leaks to the host seam. See the handoff
`docs/status/HANDOFF-2026-07-16-sql-datalog-parallel-build.md` and the deep-dive
`research/evaluations/declarative-query-viability.md`.

## Honest framing (ADR-0012)

**Not independent convergence.** The codec/crypto is `libentitycore_codec` (shared C-ABI
lineage), so any conformance pass is **cohort-consistent, not independent**. State it
precisely. The peer is a **hybrid probe** with a large seam — the host does enough
(sockets, framing, CBOR, crypto, store I/O) that this is not an independent peer; it is a
**paradigm probe of the authorization interior**. Lands as an **exploratory ‡ row**, not a
deployable peer; publish `0.1.0-pre`. No matrix row until it is real (a green oracle number
at S4).

## The GO gate — RESOLVED: **GO** (2026-07-16)

The three things S1 had to establish, proven headless inside the capped
`entity-core-keystone/sqlite-toolchain` image and **baked as a build-time self-test**
(`containers/sqlite-toolchain/gogate-selftest.{c,sh}`) — FATAL on any failure, so the image
is only valid if the gate is green. Real container build + a standalone `--network=none`
re-run both green:

| Gate item | Result |
|---|---|
| SQLite in fedora:43? | Source-built from the **pinned amalgamation** (cleaner S11 pin than the distro NVR; lets the C host compile SQLite in). SQLite **3.50.4**, SHA-256 `1d3049dd…`, verified fail-closed. |
| **CHECK 1** — query engine boots + runs a **recursive CTE** (the §5.5 chain-walk primitive) | **YES** — `WITH RECURSIVE c(n) …` fixpoint `count=10 sum=55`. Recursive CTEs run; the delegation chain-walk is expressible in SQL. |
| **CHECK 2** — host seam reaches `libentitycore_codec`, **crypto callable FROM SQL** (ec_sha256 KAT) | **YES** — `sha256()` registered via `sqlite3_create_function` (backed by `ec_sha256`); `SELECT hex(sha256(x'616263'))` = `BA7816BF…F20015AD` = SHA-256("abc"). Proves the FFI link **and** the tight-seam move (verify sequencing can stay in SQL). Provenance `c 0.1.0 / ecf-c-abi 1.1 / …` (see A-SQL-001). |
| **CHECK 3** — host transport **8-bit clean** (0x00/0xFF) | **YES** — loopback TCP echo round-trips a payload incl. `0x00`/`0xFF` byte-identical. Framed binary CBOR is safe on the C-socket transport. |

**Verdict: GO.** All three checks pass, reproducibly, under the resource caps.

### GO-gate evidence (verbatim, standalone `--network=none` run)

```
SQL peer S1 GO-gate self-test (sqlite-toolchain)
  sqlite version: 3.50.4
  CHECK 1 OK: recursive CTE fixpoint count=10 sum=55 (§5.5 chain-walk expressible)
  provenance: c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 / libsodium 1.0.22 (+ hand-rolled sha384; ed448 via vendored openssl-3.3.2 curve448 + shake256)
  CHECK 2 OK: SELECT hex(sha256(x'616263')) = BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
  CHECK 3 OK: loopback TCP echo byte-clean over 10 bytes incl. 0x00/0xFF
GO-GATE OK: recursive-CTE + ec_sha256-callable-from-SQL + 8-bit-clean transport all proven
```

## Decisions (all recorded in profile.toml + PROFILE-RATIONALE.md)

- **Query engine: SQLite 3.50.4** (over DuckDB / PL/pgSQL). Embedded, in-process, strong
  recursive CTEs, and — decisively — **application-defined functions** so `ed25519_verify`/
  `sha256`/`content_hash` are callable **from SQL**, keeping even the §5.2 crypto sequencing
  in the query. PL/pgSQL is a server, lacks native Ed25519, and can't socket without a host
  anyway; DuckDB adds nothing here.
- **Host language: C** (over Python / Rust). One seam language spans the whole imperative
  shell — SQLite *is* C, the codec *is* a C-ABI, sockets *are* C — with zero extra FFI
  layers, native `sqlite3_create_function`, and the amalgamation compiled straight into the
  peer (tightest supply-chain pin). The host is deliberately thin, so C's verbosity falls on
  the shell, not the authority interior.
- **Runtime pin: the amalgamation, SHA-256, ≥30 days.** 3.50.4 (2025-07-30, ~11.5 mo old);
  the current 3.53.3 (2026) is too new for the cool-down, so pinned back to the aged 3.50
  line. `sha256sum -c` in the Containerfile, fail-closed.
- **Seam boundary (the whole design):**
  - **HOST (C):** sockets, §1.6 framing + 16 MiB frame-cap, the §6.5 dispatch *scaffold*, the
    §4 handshake connection state machine, canonical CBOR bytes, Ed25519/SHA, store byte I/O.
  - **SQL:** §5.2 verify ladder (a CASE ladder calling app-defined crypto fns), §5.5
    chain-walk (`WITH RECURSIVE`), scope-match (JOIN + `GLOB`), K-of-N (`GROUP BY … HAVING
    count(*) >= k`), §6.6 resolution (`ORDER BY length(pattern) DESC LIMIT 1`).
  - **Opaque handles:** signatures, hashes, keys, raw CBOR, out-of-int64 ints ride as BLOB /
    rowid; readable fields (paths, scopes, depths, timestamps, thresholds) are real columns.
- **Number model:** SQLite INTEGER is int64-signed → the uint64 head-form + shortest-float
  tax lives in the **host codec seam** (A-SQL-002). SQL computes only authority-domain
  numbers, all within int64.
- **Concurrency:** host-owned single-thread select loop; §7b store-safety structural. Not a
  new taxonomy shape — but a bonus hypothesis to test at S3/S4: a SQLite-table-backed store
  makes transactions a genuine structural §7b story.

## The wrapper-guard (load-bearing)

The profile **commits** the authority interior to actual, legible SQL queries; the FFI seam
is drawn only at what SQL genuinely can't do. The `authority_interior_expressibility` section
of `profile.toml` is the stub S3 fills in as it authors — each element carries an S1
hypothesis (clean / awkward / leaks-to-host) and an S3 outcome + finding. Decomposing the
folded logic is what surfaces the finding, which is the deliverable co-equal with a green
gate (A-SQL-003 is the open umbrella item).

## Ambiguity log

`SPEC-AMBIGUITY-LOG.md` initialized. **No blocking-severity items.** Entries:
A-SQL-001 (codec provenance-label lag, non-blocking), A-SQL-002 (int64/uint64 tax location,
resolved in host seam), A-SQL-003 (OPEN — the seam-split, the probe's central S3 question),
A-SQL-004 (NOTE — multisig rejection-only oracle → mandatory accept-path test at S3/S4).

## Files written this phase

- `containers/sqlite-toolchain/Containerfile` — SQLite 3.50.4 amalgamation (SHA-pinned) +
  `libentitycore_codec` built from source + the baked GO-gate self-test.
- `containers/sqlite-toolchain/gogate-selftest.c` — the 3-check GO-gate (recursive CTE /
  ec_sha256-from-SQL KAT / 8-bit-clean TCP echo).
- `containers/sqlite-toolchain/gogate-selftest.sh` — compiles + runs the self-test.
- `protocol-generator/sql/profile.toml` — every field populated; no blocking TBD.
- `protocol-generator/sql/arch/PROFILE-RATIONALE.md` — one paragraph per major choice.
- `protocol-generator/sql/status/PHASE-S1.md` — this file.
- `protocol-generator/sql/status/SPEC-AMBIGUITY-LOG.md` — initialized.

## Phase exit criteria — MET

- [x] GO-gate green (recursive CTE + ec_sha256-from-SQL + 8-bit-clean transport), baked as an
  image self-test, reproduced standalone under the caps.
- [x] `profile.toml` complete — every field populated, no blocking `TBD`.
- [x] `PROFILE-RATIONALE.md` written.
- [x] Container authored + built + self-test green.
- [x] Ambiguity log initialized; **no blocking-severity items**.

## Handoff to S2 (codec/seam)

Build the C host: link `sqlite3.c` (amalgamation) + `libentitycore_codec`, register the
crypto app-defined functions, and run the **wire-conformance / 71-vector differential** vs
`libentitycore_codec` (byte-identical). Then S3 authors the SQL authority interior under the
wrapper-guard (the heart of the probe). Rebuild the oracle binaries from `entity-core-go`
HEAD (`CGO_ENABLED=0 GOWORK=off`) before S4 — never trust a vendored stale `validate-peer`.
Target: `--profile core` **682·0F Result: PASS @ cc1970f** + origination-core 3/3 + a genuine
2-of-3 multisig accept-path (A-SQL-004) + the 71-vector wire corpus.
