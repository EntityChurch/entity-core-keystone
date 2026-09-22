<!-- current-pin-banner:c34abcae04c4 -->
> **CURRENT (2026-09-04) — spec snapshot `v0.8.2.3`, executed check set `c34abcae04c4…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **758 total · 316 pass · 337 warn · 0 FAIL · 105 skip** (elapsed 69710 ms).
>
> That digest is the pinned `core_executed_check_set_digest`, so this number is
> comparable to every other row in `CONFORMANCE-MATRIX.md` §1 — and it is a CONTENT
> anchor, which is the only kind that survives the release boundary ([ADR-0012] Am. 1).
> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative
> artifact; `tools/check-set-gate.py --tracked` gates it, and this banner is generated
> from it by `tools/status-banner.py` rather than typed.
>
> **Everything below this line predates this measurement and is retained as build
> history.** Where it disagrees with the figures above, the figures above win;
> `CONFORMANCE-MATRIX.md` §1 is authoritative for the cohort.

---

# entity-core-protocol-io — Conformance Report

**Oracle:** `validate-peer` @ **`cc1970f`** (public HEAD; matches
`tools/oracle-pin.env` core-gate fingerprint `8261a03…`). Measured **natively**
in the `io-toolchain` container, sealed-offline (`--network=none`; oracle + peer
share one loopback). **Reproduce:** `./run-s2.sh`, `./run-s4.sh`,
`./run-origination-core.sh`.

## Headline

- **S2 codec (wire-conformance):** **71 / 71 byte-identical, 0 fail** (the pinned
  v0.8.0 ECF corpus, incl. the uint64 tower via EcBig; peer_id, signature,
  envelope, content_hash Class-B vectors). §9.5 **type floor 53 / 53
  byte-identical** to the oracle's type-registry vectors (render-from-model, 0
  drift).
- **S4 live peer — `validate-peer --profile core`:** **`Result: PASS` — 0 FAIL
  across every gated category, `concurrency` included.** `682 total: 291 P /
  295 W / 0 F / 96 S` (the 96 skips are extension categories auto-allowlisted by
  the §9.0 profile carve-out; the 295 warns are informational — absent extension
  types + the single-thread no-parallel-speedup note). `t2_1` sustained-load
  (10 000 requests, **0 drops**) and `t2_2` connection-churn both **PASS** after
  the A-IO-025/A-IO-026 fixes; `t1_2` reentry + `t1_3` no-head-of-line PASS;
  `t1_1` demux WARN (informational — a single event loop shows no physical
  parallel speedup; the oracle marks this a non-violation, enforced elsewhere by
  the passing `t1_3`).
- **origination-core:** **3 / 3 PASS** (`reference_connect` + `reference_ready` +
  `dispatch_outbound_reentry` — the §6.11 reentry, Io A-role vs Go B-role).
- **Multisig ACCEPT-path unit test:** PASS — a genuine 2-of-3 K-of-N root cap
  ALLOWs (§3.6 M3 / §5.5 M4·M6), with M3/M4/M6 negatives, closing the
  rejection-only-oracle vacuity gap (`test/multisig-accept.io`).

## Per-category — `validate-peer --profile core @ cc1970f`

Measured per-category against the peer (launched via `run-s4.sh`:
`io src/main.io --name conformance --validate --debug-open-grants`). Every gated
category clears the 0-FAIL bar; the cumulative sequence (all categories against
one long-lived peer) shows **no degradation**.

| Category | P | W | F | S | Note |
|---|---:|---:|---:|---:|---|
| connectivity | 22 | 0 | **0** | 0 | handshake both legs, §4.6 hardening, request_id echo, 404 |
| encoding | 6 | 0 | **0** | 0 | wire canonicality |
| type_system | 108 | 292 | **0** | 0 | 53-type floor byte-exact; all 292 W = extension types absent (not-a-FAIL-if-absent), **0 mismatch** |
| handlers | 35 | 0 | **0** | 32 | core handler gates; §6.13(a) register round-trip; extension ops SKIP |
| capability | 12 | 0 | **0** | 0 | §5 verdicts |
| tree_operations | 24 | 1 | **0** | 31 | CORE-TREE vectors incl. root/CAS/delete/listing; EXTENSION-TREE §9 ops SKIP |
| security | 28 | 0 | **0** | 1 | §4.6 + §5.2a + §5.5a per-link granter-frame (foreign-granter attenuation); tamper→AUTHZ_DENY via hashOk (A-IO-025) |
| **multisig** | **11** | 0 | **0** | 0 | genuine §3.6 K-of-N (peer co-signed accept path RAN) |
| authz | 6 | 0 | **0** | 2 | §5.2a trichotomy incl. `unresolvable_grantee`→401, `scope_exceeds_authority`, expired, deny_default |
| resource_bounds | 2 | 1 | **0** | 0 | §4.10(a) 413 payload / §4.10(b) 400 chain_depth; 1 W = §4.10(c) admission SHOULD (external-layer) |
| universal_address_space | 8 | 0 | **0** | 0 | §1.4 path/peer-frame rules (reserved-path → 400 via isReservedPath, A-IO-025) |
| peer_canonicalization | 7 | 0 | **0** | 0 | §1.5 identity-multihash canonical form |
| format_agility | 10 | 0 | **0** | 0 | incl. unsupported key_type=0xFD → 400 |
| crypto_agility | 4 | 0 | **0** | 0 | SHA-256/384 + Ed25519 surface |
| negotiation | 4 | 0 | **0** | 0 | §4.5 hash_formats / key_types |
| **concurrency** | **4** | 1 | **0** | 0 | t1_2 PASS, t1_3 PASS, **t2_1 sustained-load (0/10000 dropped) PASS, t2_2 churn PASS**; t1_1 demux WARN (informational) |

**Gated-category total:** **291 P / 295 W / 0 F / 96 S** (`682 total`).
`Result: PASS (with warnings)` — 0 FAIL; the 96 skips are §9.0 profile-carve-out
extension categories, exempt from the FAIL gate.

## The gate verdict — honest

The `--profile core` **binary gate is `Result: PASS` iff 0 FAIL.** This peer is a
**clean 0-FAIL** on `--profile core @ cc1970f`: every gated category — the entire
functional core surface, `concurrency` included — reports **0 FAIL**, cumulatively
(no degradation across a full single-peer sequence). The only non-PASS lines are
WARNs, all informational and explicitly marked non-violations by the oracle
(chiefly `t1_1`'s single-thread no-parallel-speedup note, whose §6.11(a)
no-serialization MUST is separately proven by the passing `t1_3` head-of-line).

**On the earlier A-IO-023 "throughput ceiling" claim — retracted.** A prior draft
recorded `t2_1`/`t2_2` as an unfixable raw-crypto-throughput ceiling of the
single-threaded interpreter. That was a **misdiagnosis**, disproven by
measurement (see A-IO-023 in the ambiguity log): the sibling Oz/Mozart peer
passes `t2_1`/`t2_2` with *slower* pipe-to-co-process crypto, so crypto rate was
never the binding constraint. Bisection isolated two real, fixable defects:

- **A-IO-025 — Io `try` clones a Coroutine per call.** The per-request `try`
  guarding the dispatch stack leaked ~55 KB/request (the spawned coroutine's
  retain stack never drains) → GC-mark thrash → throughput collapse (measured
  163→31 req/s, RSS 125 MB). Fixed by making the whole decode→verify→dispatch
  path **total** (non-raising sentinels: `tryDecode`→nil, `Entity/Envelope
  fromWire`→nil + `hashOk` flag for §5.2 step-1, `canonicalize`→reserved-path
  passthrough) and removing every per-request `try`. In-process dispatch is now
  **flat** (~196 req/s, RSS bounded).
- **A-IO-026 — blocking send stalled the single-threaded loop.** `_sendFrame`
  used a `while + System sleep(0.0005)` retry on partial/would-block writes; on a
  single coroutine that stalls **every other connection** whenever one client
  reads slowly (cross-connection head-of-line) → `t2_1` dropped 6714/10000 with
  i/o timeout *even with the leak gone*. Fixed with **non-blocking buffered
  sends**: a per-conn `wbuf`, flushed opportunistically at the top of each poll
  pass, never sleeping inside the send. With both fixes `t2_1` completes 10 000
  requests with **0 drops** (1m3s) and `t2_2` churn passes (6.8s).

## Watch-item outcomes (S1 → S4)

- **Half-close quirk** — honoured by construction: the poll loop drops a closed
  socket before any pending write; never answers after peer-FIN. No issue.
- **t2_2-class churn / §6.11 reentry** — root-caused and CLEARED. The
  coroutine-per-connection model deep-recursed the EventManager and wedged
  (A-IO-020) → replaced with the single-coroutine poll loop; the residual
  sustained-load/churn edge was **A-IO-025 (try-coroutine leak) + A-IO-026
  (blocking-send stall)**, both fixed. §6.11 reentry is a bounded synchronous
  send+wait on the same fd (origination-core 3/3, concurrent reentry t1_2 PASS).
  Root causes proven by measurement + revert-the-suspect (A-IO-024: an over-eager
  connection reaper, not the logic, caused the transient security "wedge").
- **A-PD-016 ms mints** — `EntityCodec nowMs` is gettimeofday-backed ms; verified
  distinct same-second mints. **A-PD-017 open seed** — `resources: ["*", "/*/*"]`.
  **Frame-cap (§1.6)** — 16 MiB length-prefix pre-check → the transport closes an
  over-limit connection before buffering (resource_bounds 413/400 pass).

## Provenance

Oracle pin `cc1970f` (core-gate fingerprint `8261a033…`, `tools/oracle-pin.env`);
codec impl (`ec_impl_info`): `c 0.1.0 / ecf-c-abi 1.1 / libsodium 1.0.22 / …`.
The oracle binaries in `output/s4-oracles/` were NOT rebuilt (pin-verified as
installed).
