# SQL peer — profile rationale

Audit trail for `protocol-generator/sql/profile.toml`. One paragraph per major choice.
This is the **authority-as-query probe**: a spec-discovery probe (not a substrate probe)
whose finding is *how much of the §5/§6.6 authority interior stays expressible as SQL vs.
leaks to the host seam*. Companion: `protocol-generator/shared/evaluations/declarative-query-viability.md`.

## Query engine — SQLite 3.50.4 (over DuckDB / PostgreSQL PL/pgSQL)

SQLite is the clean first pick and S1 evidence confirmed it, not just desk reasoning.
It is **embedded and in-process** (no server, no second socket, smallest possible host),
has **strong recursive CTEs** (the §5.5 delegation chain-walk is the canonical
transitive-closure pattern — proven runnable at the GO-gate), and — decisively —
**application-defined functions** (`sqlite3_create_function`) let the host register
`ed25519_verify`/`sha256`/`content_hash` as functions **callable from SQL**. That last
point is why SQLite beats the alternatives for *this* probe: the whole §5.2 verify ladder
*including the crypto-call sequencing* can stay in SQL (the verdict query calls
`ed25519_verify()` itself), so the seam tightens to the bare primitive. **DuckDB** (also
embedded, excellent recursive CTEs, UDFs) is an analytical engine with a less
transactional store story and no advantage here. **PostgreSQL + PL/pgSQL** would push
*more* logic server-side, but it is a full server (heavier), `pgcrypto` gives SHA/HMAC but
**not Ed25519**, and PL/pgSQL cannot open a raw socket without an untrusted procedural
language — so it would need a host *anyway* while adding a server. SQLite gives the
smallest host, the tightest crypto-in-SQL seam, and a real transactional §7b store story
if we back the entity store with a SQLite table.

## Runtime pin — the amalgamation, SHA-256, ≥30 days

SQLite ships a **single-file amalgamation** (`sqlite3.c` + `sqlite3.h`) that pins cleanly
by a documented per-release SHA-256 — the tighter S11 supply-chain pin, versus the fedora
`sqlite-libs` package which pins only by NVR. It also lets the C host **compile SQLite in**,
so the engine version is fully controlled (no dependence on the distro `libsqlite3`). This
is the puredata/tcl source-build discipline. Pinned **3.50.4** (released **2025-07-30**,
`SQLITE_SOURCE_ID 2025-07-30 19:33:53 4d8adfb3…`), the current 3.50 stable line — **~11.5
months old** at authoring (2026-07-16), comfortably past the 30-day cool-down. The current
release at authoring was 3.53.3 (2026), which is *too new* for the floor, so we
deliberately pinned back to the well-aged 3.50 line. Amalgamation SHA-256
`1d3049dd0f830a025a53105fc79fd2ab9431aea99e137809d064d8ee8356b032`, verified in the
Containerfile (`sha256sum -c`, fail-closed on mismatch).

## Host language — C (over Python / Rust)

The host owns what SQL genuinely can't do: sockets, §1.6 framing, canonical CBOR bytes,
crypto, and the store's byte I/O. **C is the single cleanest seam language** here because
**SQLite *is* C, the codec *is* a C-ABI, and sockets *are* C** — one language spans the
whole imperative shell with zero additional FFI layers, and `sqlite3_create_function`
(registering the crypto primitives as SQL functions) is a native C call. It also lets the
amalgamation compile directly into the peer binary, giving the tightest supply-chain story.
Python (stdlib `sqlite3` + `ctypes`) is *lighter to write* but muddies the SQLite pin (it
links the distro `libsqlite3`, not our amalgamation, without pulling in a third-party
binding like `apsw`) and inserts an extra runtime layer between the codec and SQLite; Rust
(`rusqlite` + bindgen) is heavier to build for no gain over C on this substrate. Since the
host is *deliberately thin* (a byte-pump + FFI-registration + socket loop — the same seam
every FFI-hybrid peer already has), C's verbosity falls on the shell, not the authority
interior, which is exactly where we *want* the effort to be minimal. The GO-gate proved the
C host links SQLite + `libentitycore_codec`, registers `sha256` as a SQL function, and runs
an 8-bit-clean TCP echo — all three in one binary.

## Codec strategy — ffi-c-host (delegated), crypto callable from SQL

`codec_strategy` is effectively **ffi**: SQL/SQLite has no byte-assembly, no CBOR, and no
crypto, so canonical ECF + Ed25519/SHA-2 + peer-id are delegated to `libentitycore_codec`
over the C-ABI — the documented fallback for a substrate that can't produce canonical CBOR
(and *no* substrate produces it for free; SQL can't produce bytes at all). The distinctive
move is registering the crypto primitives as **SQLite application-defined functions** so the
authority ladder's crypto *sequencing* stays in SQL rather than being pre-computed in the
host and handed in as a boolean. This is the tight-seam realization the feasibility
deep-dive called for, and it is what keeps the §5.2 ladder legibly *in SQL*.

## Number model — the tax lives in the host codec seam

SQLite `INTEGER` is **64-bit signed**, so it cannot natively hold uint64 `[2^63, 2^64-1]`.
This is fine because the CBOR integer head-form + the uint64 boundary + the mt7
shortest-float ladder are all **host codec-seam** concerns anyway (`libentitycore_codec`
owns every wire byte). SQL only ever computes over **authority-domain** numbers — chain
depth (cap 64), K-of-N signer counts and thresholds, evaluation timestamps
(ms-precision, §5.10), and path/scope lengths (§6.6 longest-prefix) — all comfortably
inside int64. Any out-of-int64 wire integer rides as an opaque host-owned blob/handle,
never as a SQLite `INTEGER`. So unlike the fixed-width-int peers (Zig/C#) there is no
head-form self-test obligation *in SQL*: the tax is entirely in the host seam that already
carries it.

## Concurrency — host-owned, not a new §7b shape

Neither SQL nor SQLite introduces a new structural concurrency shape here: the peer is a
**single-threaded host select/poll loop** (the COBOL/Rexx shape), each frame dispatched to
completion before the next, so §7b store-safety is **structural** (one thread, no
concurrent store access). The frame-cap (§1.6, 16 MiB) is load-bearing on a single-thread
host — an oversize frame stalls the loop and cascades (the TurboWarp #32 t2_2 lesson) — so
it is enforced in the host before assembly. There is **one bonus hypothesis worth testing
at S3/S4** (from the deep-dive): if the entity store is backed by a SQLite *table*, SQLite's
transaction model (serialized writes) is a genuine *structural* store-safety story — a
mild addition to the §7b taxonomy. We flag it to characterize, not claim.

## Wrapper-guard — the commitment that makes this a probe

The load-bearing discipline (carried from the visual-paradigm probes, FLOW-DESIGN): if §5
collapses to a single host call with SQLite as decoration, the probe yields nothing. So the
profile *commits* that the authority interior — the §5.2 verdict ladder, the §5.5
chain-walk (`WITH RECURSIVE`), scope-matching (JOIN + `GLOB`), K-of-N (`GROUP BY … HAVING
count(*) >= k`), and §6.6 resolution (`ORDER BY length(pattern) DESC LIMIT 1`) — is authored
as **actual, legible SQL queries** over grant/token/handler tables, and the FFI seam is
drawn **only** at what SQL genuinely can't do. The `authority_interior_expressibility`
section of the profile is the stub S3 fills in as it authors; decomposing the folded logic
is what *surfaces* the finding, which is the deliverable co-equal with a green gate.
