# entity-core-protocol-rexx — Phase S4 summary (COMPLETE)

**Phase:** S4 (conformance — live-peer oracle)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/rexx-toolchain:latest` (Regina Rexx **3.9.6**, fedora:43)
**Oracle:** `validate-peer` @ **`cc1970f`** (core-gate fingerprint `8261a033…`; rebuilt-from-
go-HEAD binaries in `output/s4-oracles/`, `valid_2of3_peer_signed_accepted` accept-path
vector verified present).
**Status:** ✅ **COMPLETE — `--profile core` Result: PASS, 0 FAIL.**

## Result — `--profile core`, oracle `cc1970f`

**682 total · 291 pass · 295 warn · 0 FAIL · 96 skip** (all 96 skips auto-allowlisted by
the V7 v7.72 §9.0 profile carve-out — **0 fail-counting skips**). Reproduce:

```
./run-s4.sh                    # full core gate (self-execs under podman, --network=none)
./run-origination-core.sh      # the §10.2 two-peer origination probe (Go entity-peer as B)
```

- **Every gated core category is green.** The 295 warns are non-gating: 292 are
  `type_system` render-native informational WARNs (matched-if-present), + `tree_operations`
  (1), `concurrency.t1_1` (single-thread no-parallel-speedup, expected), `resource_bounds.r3`
  (below). peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`.
- **§6.11 concurrency — PASS.** `t1_2` reentry + `t1_3` head-of-line PASS; `t2_1` sustained
  load (10 000 tree.gets, 16 workers) **0 drops, stable p50**; `t2_2` connection churn
  (100 cycles) PASS. `t1_1` WARNs (no parallel speedup — a single-thread select-pump; the
  §6.11(a) MUST is enforced by `t1_3`, which passes).
- **Multisig accept path is genuine, not vacuous.** `valid_2of3_peer_signed_accepted` PASS —
  the peer co-signs AS the keypair the harness provisions at `~/.entity/peers/conformance/`
  and authorizes a real 2-of-3 (M4 quorum + M6 root-at-local). The oracle covers the accept
  direction, so the "rejection-only category → vacuous pass" trap does not apply here.
- **Origination-core (§10.2) — PASS 3/3** via `run-origination-core.sh` (Rexx A-role vs the
  Go `entity-peer` B-role): `dispatch_outbound_reentry` runs live (the peer originates an
  outbound EXECUTE back to B over the SAME inbound connection — §6.11 reentry). In the
  single-peer `run-s4.sh` the origination category honest-SKIPs (no reference peer).

Regression floors intact: **S3 two-peer smoke 8/8 + foundation self-test 31/31; S2 codec
69/69.**

## What S4 added (the CLI host + the harnesses)

- **`bin/peer.rex`** — the standalone S4 host: parses `--name/--port/--net/--base/--validate/
  --debug-open-grants` from the one Regina arg string, loads the persistent Ed25519 identity
  from `~/.entity/peers/NAME/keypair` (a base64-of-32-byte-seed PEM; base64 decoded in pure
  Rexx — `B64_Decode`), starts the ecnet daemon (crypto-carrying, A-RX-011) BEFORE
  `Peer_Create`, prints `LISTENING <port>`, and runs `Transport_Serve` forever. It is
  `s3_responder.rex` generalized to a persistent on-disk identity. **Classic-Rexx gotcha
  banked:** comment TEXT must not contain the literal `/*` — Regina nests comments, so
  `system/validate/*` inside a header comment opened an unterminated nested comment that
  corrupted parsing far downstream (§ below).
- **`run-s4.sh`** — builds the ecnet daemon + eccrypto helper + the concatenated host
  (`make s4peer`), provisions the keypair, launches the peer, waits for `LISTENING`, points
  `validate-peer -profile core` at it. Self-execs under podman when run from the host;
  `--network=none` (intra-container loopback). Default `-timeout 10m` (see below).
- **`run-origination-core.sh`** — the two-peer §10.2 probe (mirrors the cohort's shape):
  Go `entity-peer -open-access` as B, the Rexx host `--validate` as A, `-category
  origination -reference-peer …`.
- **Makefile `s4peer` target** — concatenates `bin/peer.rex` ahead of the full routine
  library into `/tmp/rexx-peer.rex` (the same link-order model as the S3 combined mains).

## S4 findings & resolutions (all fixes in the PEER; oracle/spec untouched)

The peer machinery was correct on a fresh peer from the first run (every category passes in
isolation). The three real issues were **resilience-under-sustained-load** (§4.9/§4.10) —
exactly the S4 watch-items — plus one operator-budget knob:

- **A-RX-014 (the headline S4 finding): unbounded per-request signature ingest.**
  `_ingest_signatures` ran on EVERY inbound envelope and (a) `Store_PutEntity`'d the
  signature entity and (b) `Store_Bind`'d it at `/{pid}/system/signature/{targethex}`. A
  signature is UNIQUE per request (fresh `request_id` → fresh signed bytes → fresh content
  hash), so this grew the content store **and** the tree's `SPATHS` list by one **per
  request** — unbounded growth driven purely by request traffic (a §4.9/§4.10 resource-
  exhaustion vector). Under the `t2_1` 10 000-request flood the peer ballooned to ~117 MB,
  and — because `Store_Listing` walks `SPATHS` via `Lst_Item` (O(i) each → **O(n²)**) — every
  later listing-touching op (`universal_address_space` foreign-namespace listing,
  `peer_canonicalization`, then the whole tail) hung for the full 20 s per-request cap.
  **Resolution:** ingest only the (bounded, dedup-ing) signer **peer** entities that chain
  resolution may look up from the store; do NOT persist or tree-bind the per-request
  signature entities — `Cap_VerifyRequest` verifies straight from the envelope's `included`,
  never from the store, so nothing is lost. **Finding for arch:** a core peer MUST NOT
  persist inbound request-auth signatures (unbounded by design); the spec should say so
  explicitly under §4.9/§4.10.
- **§4.10(c) connection-flood admission (`r3_connection_flood`).** The daemon's
  `EC_MAXCONN` hard cap of **256** exactly equalled the flood's 256-connection burst, so the
  daemon accepted all 256 then hard-closed the 257th keep-serving probe → the oracle's
  "accepted-all-then-fell-over" **FAIL** shape. **Resolution:** raise `EC_MAXCONN` to **512**
  (> flood + the follow-up probe; well under `select()`'s FD_SETSIZE 1024; per-conn buffers
  are malloc'd lazily so idle slots cost ~0) → the peer accepts the flood AND keeps serving →
  **external-admission-delegation WARN** (a §4.10(c) SHOULD, not gated). A hard cap == the
  flood size can never reach the PASS/self-bounded outcome (the flood holds every slot during
  the keep-serving probe).
- **`EC.!EVQ` O(n²) → O(1).** The deferred-network-event queue (events read while a crypto
  `_await_result` awaits its `R` result) was a packed-list — every enqueue/dequeue copied the
  whole string. Rebuilt as a head/tail stem ring (`EC.!EVQH`/`EC.!EVQT`, `drop` per dequeue,
  reset-to-1 when drained). Robustness; not the wedge root cause but a real degrade-under-
  burst hazard.
- **`-timeout 10m` (operator budget, not a peer defect).** This peer is the cohort's
  **slowest**: A-RX-011 forbids an in-process crypto shim, so every §9.1 op crosses a FIFO to
  the ecnet co-process (~17 ms/request where a compiled peer is sub-ms). The default 60 s
  oracle budget is consumed by `concurrency` alone (10 000 requests) before the later
  categories surface (a budget-exhaustion cascade). The test's own doctrine is *"a slow
  language passes by being correct, not by being fast"* — the real gate is the 20 s
  per-request cap — and `-timeout` is the operator knob, as **dart** (5m) and **prolog**
  (180s) already set for the same reason. (After the A-RX-014 fix the full run dropped from
  8m34s to **3m40s** — the leak was also most of the slowness.)

## The debugging note worth carrying

A false-alarm cost a cycle and is banked: a **concurrent second heavy podman container**
(an orphaned `rexx-toolchain` build stuck 2 h) starved a peer under test into 20 s timeouts
that looked exactly like a wedge. The single-container repro was clean. **Run the S4 gate
alone** (or with headroom under the memory cap); check `podman ps` for orphans before
trusting a wedge signal.

## One-line status

Peer #24 (Rexx, native-decimal probe): **S1→S4 COMPLETE.** `--profile core` **682·0F @
cc1970f** (291P/295W/0F/96S, 0 fail-counting skips); origination-core 3/3; S3 8/8 + 31/31;
S2 69/69. Two genuine §4.9/§4.10 resilience findings surfaced and fixed (A-RX-014 unbounded
signature ingest; §4.10(c) admission cap). **S5 (packaging) is next.**
