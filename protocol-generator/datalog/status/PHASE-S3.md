# entity-core-protocol-datalog — Phase S3 (Peer machinery + authored authority interior)

**Deductive-logic / query-native spec-discovery probe** · **probe tier (‡, seam-hybrid)**
· S3 completed 2026-07-16 · **Verdict: GATE GREEN** (loopback both-ways + authorized 404 +
8-way demux; cross-impl handshake + authorized 404 against the Go reference peer; 26 lib +
2 integration tests; clippy `-D warnings` + fmt clean — all in-container / capped / offline).

## The headline — authority-as-query CONFIRMED (the co-equal deliverable)

The §5/§6.6 authority interior is authored as **genuine bottom-up Datalog rules**
(`src/authority.rs`, two `ascent!` blocks: `Authorizer` + `Resolver`), and the
**wrapper-guard held** — the rules DRIVE the verdict end-to-end (the S3 gate exercises
`authorize()` on every authenticated request), not decoration over a host if-ladder.

| §-surface | Expressibility | What the rule is |
|---|---|---|
| §5.5 delegation | **clean-rule** | 2-rule transitive closure to least fixpoint (SecPAL/Binder shape) |
| §5.2 verdict | **clean-rule** | derived `allow(c)`; **fail-closed = absence of a tuple** (closed-world) |
| §5.5a scope | **rule + host-fact** | host glob DECISION → per-grant facts; **within-grant conjunction = a join** |
| §3.6 K-of-N | **clean-rule + caveat** | counting aggregate over `distinct_signer`; distinctness is a fixpoint property (A-DL-012) |
| §6.6 resolution | **clean-rule** | longest-prefix as stratified negation (`!longer_exists`) |
| §6.5 dispatch / §4 handshake / temporal | **leaks-to-host** | sequencing + mutable connection state + clock → Rust (expected) |

**The seam split IS the finding** (A-DL-013): the authorization-DECISION half of
entity-core is deductive and legible as rules; the protocol-SEQUENCING + I/O half is
stateful-imperative and correctly host-side. The seam fell almost exactly where S1
predicted. Candidate `HANDOFF-TO-ARCH`: the spec prescribes §5.2/§5.5 imperatively, but the
underlying logic is a monotone deductive system — an *authority-as-query* appendix could
specify the verdict as a DERIVATION, making fail-closed + the within-grant conjunction
structural invariants rather than prose MUSTs an imperative impl can violate silently.
Full findings → `SPEC-AMBIGUITY-LOG.md` A-DL-010..014; profile `[expressibility]` filled
with the observed outcomes; the synthesized retrospective is authored at S5.

## What S3 built

The stateful-sequential host half + the authored interior, on the S2 codec seam.

| Path | Role |
|---|---|
| `src/authority.rs` | **THE PROBE ARTIFACT** — the `ascent!` §5.2/§5.5/§5.5a/§3.6/§6.6 rules + host-facing fact wrappers (`authorize`, `resolve_handler`) + 10 rule unit tests |
| `src/cbor_host.rs` | host CBOR *structure* layer (naive encode + decode with N2 tag-reject); canonicalization DELEGATED to the C-ABI |
| `src/model.rs` | Entity / Envelope (`content_hash` + canonical frame via `codec_ffi`) |
| `src/identity.rs` | peer keypair + `system/signature` (all crypto via the C-ABI; sign over the 33-byte content_hash) |
| `src/store.rs` | §1.7 two-layer in-memory store; §4.8 race-safety STRUCTURAL (`RwLock`, the profile's §7b idiom) |
| `src/dispatch.rs` | §6.5 dispatch + §4 handshake state machine + §6.9a seed bootstrap + the FACT-ESTABLISHMENT layer feeding `authority` |
| `src/host.rs` | TCP + §1.6 framing (§4.10 `413` pre-check) + §6.11 `request_id` demux + §4.1 initiator + §4.9 resilience-frame (panic→500) |
| `src/main.rs` | the runnable peer (`--name`/`--validate`/`--port`) |
| `src/bin/interop.rs` | cross-impl smoke driver (dials the Go `entity-peer`) |
| `tests/loopback.rs` | the deterministic in-tree gate (two Datalog peers over real TCP) |
| `run-s3.sh` | container-bound / capped / offline smoke runner (both legs) |

## The S3 gate

`./run-s3.sh` — two legs, both in one capped `--network=none` container:

- **LEG 1 — loopback (deterministic).** Two Datalog peers over real loopback TCP:
  §4.1 handshake **both legs** (hello + authenticate) → **authorized EXECUTE to an
  unregistered path → 404** (the seed cap flows through `authority::authorize` → ALLOW,
  then the §6.6 `Resolver` finds no handler) → **8-way concurrent `request_id` demux**
  (N7) → clean teardown. `test result: ok. 1 passed`.
- **LEG 2 — cross-impl interop.** The Datalog peer (INITIATOR) dials the reference
  `entity-core-go entity-peer` (`-open-access -validate`) and completes the handshake +
  an authorized 404 — **byte-level wire interop with an independent implementation**:
  `INTEROP: PASS (handshake both legs + authorized 404 against the Go reference peer)`.
  This proves the Datalog peer's canonical-CBOR envelope, content_hash, Ed25519-over-the-
  33-byte-hash signature, and identity-multihash peer_id are all accepted by Go.

Plus `cargo test` (26 lib unit tests incl. the **mandatory 2-of-3 K-of-N accept path** +
the duplicate-signer negative + scope-conjunction + delegation-closure + FFI KAT/N1–N4)
and the lint floor (`clippy -D warnings` + `fmt --check`) — all GREEN.

## Cohort traps pre-resolved (owed at S3, not re-burned)

- **A-PD-016** ms-precision mint `created_at` — `now_ms()` (not second-truncated).
- **A-PD-017** open/debug seed dual resource form `["*", "/*/*"]` — `open_grants_scope()`.
- **§1.6 frame-cap** — `MAX_FRAME = 16 MiB`, checked on the length prefix BEFORE buffering
  the body → `413 payload_too_large` (`host::read_frame`).
- **§4.10(b) chain-depth** — a structural pre-check BEFORE the authz walk → `400
  chain_depth_exceeded` (NOT 403); an unreachable parent stays 403 (`chain_exceeds_depth`).
- **§4.9 resilience frame** — `dispatch_one` wraps the request path in `catch_unwind`;
  the host ROOT error class (a panic at the boundary) → **500**, never a dropped connection.
- **§6.5 signature-ingestion scoping** (A-IO-022 / A-RX-014, memory-primary) — the
  transient per-request EXECUTE signature (target == the root EXECUTE hash) is NOT bound
  into the store; only reused cap/identity/handshake sigs are ingested.
- **K-of-N accept path** (A-DL-006) — a genuine 2-of-3 ACCEPT unit test (the `multisig`
  oracle category is rejection-only → vacuous-green trap).

## §7b store-safety idiom + v7.75 floor

Store-race safety is **structural in Rust**: the shared store is `RwLock`-guarded and
`Peer: Send + Sync`, so an unlocked shared-mutable store is a compile error — the race that
crashed raw-thread peers is unrepresentable. Thread-per-connection (reader) + thread-per-
inbound-EXECUTE (dispatch) means no bounded cooperative pool to starve (the Swift trap does
not apply). `TCP_NODELAY` on every stream. The Datalog engine is invoked synchronously per
request and is stateless between requests (assert → fixpoint → read → drop) — trivially
race-free, no new §7b taxonomy shape (host-owned concurrency, as the profile documents).

## Notes / handoff for S4

1. **Scope of the authored surface.** S3 wired the full authorization pipeline (authn →
   chain facts → `authorize` → resolution → 404) + the connect handshake + tree get/put +
   capability request/revoke + validate/echo. S4 surface still to wire for `--profile core`:
   `system/handler` register/unregister (stubbed 501), `system/type` publication (the type
   floor — render-natively per the durable lesson), `capability delegate`, the
   dispatch-outbound §6.11 reentry handler body (the seam is present in `host.rs`; the
   handler is stubbed), and the full attenuation/caveat/revocation edge cases (the host
   fact-establishment helpers are present but exercised only on the happy path).
2. **The oracle must be REBUILT from entity-core-go HEAD** for the S4 gate (never trust the
   vendored `validate-peer`; `strings | grep <vector>` to confirm new validator vectors
   compiled). Target: `validate-peer --profile core` + origination-core 3/3.
3. **The fact-based verdict is the invariant to preserve at S4.** When wiring more
   categories, keep the split: the host establishes FACTS (crypto/glob/clock/structure);
   `authority.rs` DERIVES the verdict. Adding an imperative allow/deny branch in `dispatch.rs`
   would re-introduce the wrapper the probe exists to avoid.
4. **A-DL-012 is a standing Datalog discipline** — any threshold/count over an externally-
   loaded relation must route through a derived copy-rule for set semantics.
5. Nothing was committed — files are left for the overseer to stage + commit.
