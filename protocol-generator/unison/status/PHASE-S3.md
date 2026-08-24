# entity-core-protocol-unison — Phase S3 (Peer machinery) Summary

**Peer:** #43 (Unison, operator-directed) · **Spec basis:** v0.8.0 / V8 ·
**Phase:** S3 (peer machinery + smoke) · **Status:** COMPLETE — the full peer
(L1–L4 + foundation) compiles clean under UCM; **smoke 8/8 GREEN over real
loopback TCP**, deterministic across repeated runs; S2 codec unregressed
(`PASS 71/71 sha_ok=true`). Container-bound, headless, `--network=none`.

Built on the green S2 codec (`Codec`/`Protocol`/`Ed25519`), spec-first from
`spec-data/v0.8.0`, with the Haskell peer as the nearest idiom-family reference and
DERIVING core semantics from the spec text. Idiom seam: **abilities/algebraic
effects over `IO` — `forkComp` green threads + an MVar-serialized store + a
per-request `Promise` demux** (A-UN-004), the novel §7b store-safety shape.

---

## Modules (`src/*.u`, on top of the S2 codec)

| Module | Core layer | Responsibility |
|--------|-----------|----------------|
| `Model.u`      | foundation | materialized `{type,data,content_hash}` (§1.1/§3.4) + envelope (§3.1); fidelity-validating `entityOfCbor` (§1.8); field accessors; path/text helpers (`splitSlash`/`isPeerId`/…) |
| `Wire.u`       | L2 | §1.6 framing (4-byte BE length); EXECUTE/EXECUTE_RESPONSE builders; `errorResult`; empty-params `0xA0` |
| `Identity.u`   | L1 | keypair → peer_id (§1.5 identity-multihash) / peer entity / signing (§3.5/§7.3); `verifySignature`; raw-PoP verify |
| `Store.u`      | foundation | **`MVar StoreState` single-owner store** (content + tree, §1.7); take→pure-modify→put serialization; N8 snapshots (pure resolver + revocation predicate); §3.9 listing |
| `Capability.u` | L3 | §5.2 `verifyRequest` (3-way verdict) + `checkPermission`; §5.4 patterns + §1.4 `normalizeUri`; §5.5 single-sig chain walk + §5.5a/§PR-8 per-link granter frame; §5.6 attenuation; §5.1 revocation; **§4.10(b) `chainExceedsDepth` pre-check**; **pure verdict over a snapshot (N8)** |
| `SeedPolicy.u` | foundation | §6.9a seed-policy selection (`SeedStandard` / `SeedDebugOpen`) |
| `TypeDefs.u`   | foundation | §9.5 type-floor render-from-model seam + minimal name-only seed (A-UN-012; full 53-render byte-diff deferred to S4) |
| `Peer.u`       | L1–L4 | the four MUST handlers (connect/tree/capability/handler), §6.5 dispatch chain + signature ingestion, §6.6 backward resolution, §6.9 bootstrap, §6.9a Peer Authority Bootstrap, §6.13a register (five writes), §6.13b outbound closure, §7a echo + dispatch-outbound, per-connection state |
| `Transport.u`  | L4 | TCP listener + dialer (builtin `io2.IO` sockets); **`forkComp` per connection, `Promise` request_id↔reply demux**; §4.8 inbound-concurrent-with-outbound; §6.11 reentry seam; **§4.9 resilience root-catch** (`tryEval` + Exception handler → 500); §4.10 payload bound |
| `Host.u`       | — | standalone host (`--port`/`--name`/`--debug-open-grants`/`--validate`; PEM base64 seed load; `LISTENING` line) — the S4 target |
| `Smoke.u`      | — | two-peer loopback smoke runner (client built from the library's own builders/codec) |

## Idiom seams (the Unison-faithful translation, A-UN-004/005)

- **Pure `Either CodecError a` codec underneath; the `IO`/`Exception` abilities only
  at the transport edge.** The capability verdict is a **pure function** of a
  one-time store snapshot (`Bytes -> Optional Entity`) — no IO in the verdict path
  (N8 by construction).
- **`MVar`-serialized single-owner store** = an actor-like structural guarantee via
  the effect system (take → pure-modify → put). Distinct from the actor-isolation /
  STM / raw-thread / single-thread-event-loop / dataflow-variable families.
- **`Promise` per outbound request** for the §6.11 demux — the caller registers a
  Promise keyed by `request_id`, sends, then `Promise.read` blocks until the reader
  writes it; connection close fills every pending Promise with `None` (deliver-or-
  signal). The Promise IS the demux — no condition variable, no lost wakeup (the
  dataflow-variable twin, realized as a library value over `IO`).
- Records over the `Value` ADT; abilities/ability-handlers for the root-catch;
  pattern matching throughout. No transpiled-Haskell STM/`TVar`.

## Concurrency + store-safety (§4.8 / §7b) + N5–N8

- **§4.8 / §7b store data-race-freedom is STRUCTURAL.** All store state is one
  `MVar StoreState`; every mutation is `take → pure fn → put`, so two concurrent
  per-request `bind`s serialize at the take/put point — a bare mutable map would
  race; the MVar-serialized cell cannot. Met by construction, the §9.1 v7.75 floor.
- **`forkComp` green threads** on the Unison runtime scheduler: one reader per
  connection demuxes frames; each inbound EXECUTE dispatches on its OWN forked
  thread (§4.8, **N6**) so a handler that originates an outbound EXECUTE (§6.13b)
  and awaits its reply does not block the reader. Blocking socket reads run on the
  runtime's green-thread scheduler (not a bounded cooperative pool — no Swift-style
  starvation trap). **Proven: 16 concurrent EXECUTEs each correlate to their own
  EXECUTE_RESPONSE, deterministically.**
- **N5** envelope `included` preservation — request side (every authed EXECUTE
  bundles author+sig+cap+granter) and result side (`okI`/`ocIncluded` carries the
  minted token+sig+granter through the response); the §6.13b outbound closure
  rebuilds the full included set.
- **N7** reentrant transport + `request_id` demux (the `Promise` map above).
- **N8** verdict determinism — the Layer-1 verdict is a pure function of a fixed
  snapshot; timing cannot perturb it.

## v7.75 non-functional substrate floor (built in, gated at S4)

- **§4.9 resilience root-catch (the cohort lesson).** Each inbound EXECUTE is
  dispatched under `tryCatch` = `io2.IO.tryEval` handled by an `Exception` ability
  handler, so an UNCAUGHT per-request failure — the host's ROOT error class, not
  just the codec's `CodecError` — becomes a **500** response, never a hung request
  (§4.9(c)). Verified live: a strict-evaluation `bug` during chain verification was
  caught and surfaced as `500:internal_error` (then fixed at the source — see
  Findings), proving the frame catches the root class.
- **§4.10(b) chain-depth pre-check (the one net-new v7.75 helper).** A single
  structural `chainExceedsDepth resolve cap` walks parent pointers WITHOUT verifying
  signatures, gated at the dispatch site BEFORE the per-link authz walk → **400
  `chain_depth_exceeded`** (structural excess), distinct from 403; an *unreachable*
  parent is not a depth problem (stays 403). Default depth 64.
- **§4.10(a) payload bound.** `readFrame` checks the 4-byte length prefix and
  rejects an over-`maxFrame` (16 MiB) connection BEFORE buffering the body. A
  `request_id` lives only in the body, so a `413`-with-body result is not
  constructable pre-buffer; the S3 floor **rejects-by-close** (keeps the peer alive,
  no OOM) — the precise 413 status is an S4-measured refinement (A-UN-014).
- **Memory-primary discipline (A-UN-013).** `ingestSignatures` ingests handler-
  discoverable signatures but SKIPS the transient per-request EXECUTE signature
  (target == the root exec hash), so the in-memory (assoc-list) store does not grow
  an entry per request (the Io A-IO-022 / Rexx A-RX-014 lesson, applied structurally).

## §6.9a Peer Authority Bootstrap + seed policy

Wired per the keystone `shared/seed-policy/` convention: an owner cap (detached-sig
shape) at `.../policy/{owner_hash}` + its signature at the §3.5 pointer; a `default`
policy-entry (the §4.4 discovery floor under `SeedStandard`, or the degenerate
`default → *` under `SeedDebugOpen` = `--debug-open-grants`). Authenticate-time
derivation does the dual-form lookup (hex → peer_id → default) UNION the discovery
floor. `created_at` on every mint is **ms precision** (the A-PD-016 content-addressed
mint-timestamp lesson — avoids same-scope same-second hash-aliasing).

## Smoke result (the S3 hard exit) — 8/8 GREEN, deterministic

`ucm transcript transcripts/smoke.md` → golden `transcripts/smoke.output.md`
(`"SMOKE 8/8"`). Boots two peers (server `--validate` + open seed; a client peer
that also serves the reentrant leg) over real loopback TCP:

1. §4.1 handshake both directions (hello → authenticate; §4.4/§6.9a initial cap;
   remote peer_id present). ✅
2. **UNauthenticated** EXECUTE on an unknown path → **401** (§6.5 authenticates
   before resolving — the F31 auth-ordering: 401 wins over 404). ✅
3. Authenticated EXECUTE on an unknown path → **404**. ✅
4. Authority-gated tree get (`system/type/primitive/any`) → **200**. ✅
5. capability request → **200** (mints a bounded child cap, subset-checked). ✅
6. **request_id demux (N7): 16 concurrent EXECUTEs each correlate → all 200.** ✅
7. register → **200** (the §6.13a writes). ✅
8. **dispatch-outbound reentry → 200 + echo value passthrough** (§6.11 reentry,
   B-role on the same connection). ✅

Reproduce (in-container, under caps, offline):
```
. tools/podman-caps.sh
podman run --rm --network=none $PODMAN_RUN_CAPS \
  -v "$PWD":/work:Z -w /work/protocol-generator/unison \
  localhost/entity-core-keystone/unison-toolchain:latest \
  ucm transcript transcripts/smoke.md
```
Compile-clean gate: `transcripts/peer-build.md` (loads + `add`s all `src/*.u`
including `Host.u`, no run) — the "peer compiles clean under UCM" artifact.

## Findings / escalations (this phase) — see SPEC-AMBIGUITY-LOG.md

No new **spec-text** contradiction (expected for a coverage peer — auth-ordering
401/403/404, the §PR-8 granter frame, the peer-id §1.5 reconciliation all landed
consistently with the cohort). Recorded S3 decisions: **A-UN-010** (seed-policy
file-parse deferred; in-code builders are the S3 floor), **A-UN-011** (multi-sig
§3.6 granter deferred to S4; single-sig root-at-local is the S3 floor — not smoke-
exercised), **A-UN-012** (type floor minimal name-only seed at S3; full 53-render
byte-diff at S4), **A-UN-013** (memory-primary signature-ingestion discipline),
**A-UN-014** (`TCP_NODELAY` not settable via UCM socket builtins — no
`setSocketOption`; §7b transport-menu partial, logged; + the 413-pre-buffer
reject-by-close note).

### Generator-robustness datums (Unison idiom, for the ratchet — NOT spec findings)

The peer surfaced five substrate/syntax datums the generator should carry forward:
1. **Strict evaluation makes `optOr x (bug …)` a live trap** — the raising default
   is evaluated eagerly, so it ALWAYS raises. The resilience root-catch correctly
   turned it into a 500, which is how it was caught; the fix was to recurse with
   lookahead instead of index-with-bug-default. (Lesson: never put a raising
   expression in argument position expecting laziness.)
2. **Inline `;`-separated match cases are fragile** as a sub-expression / with
   comparison operators in a case body — use newline-separated cases in named
   helpers.
3. **Multi-line infix (`&&`/`Text.++`) chains** need the continuation indented past
   the RHS start (or bind operands to names + combine on one line).
4. **`handle` is a reserved keyword** (ability handlers) — not usable as a binding.
5. **List cons `+:` does not chain in patterns** (`a +: b +: rest` mis-groups) —
   match a single `head +: tail` and destructure the tail separately.

## Exit criteria

Peer compiles clean under UCM (`peer-build.md`) · reads as idiomatic Unison
(abilities/effects, `MVar`/`Promise`/`forkComp`, records, pattern matching — not
transpiled STM) · smoke 8/8 green over real loopback TCP, deterministic · §4.8/§4.9/
§4.10 + N5–N8 built in · S2 codec unregressed (71/71). **S3 PASS.**

## S4 entry checklist

1. Wire `Host.u` into a `run-s4.sh` (twin of the Haskell/OCaml scripts): compile
   the peer (`ucm run.compiled peer.uc` or `run`), launch `--name --validate
   --debug-open-grants`, wait for `LISTENING`, point `validate-peer` at it.
2. Land the full §9.5 53-type byte-exact render + type-registry byte-diff (A-UN-012).
3. Multi-sig §3.6 root (A-UN-011) for the `multisig` category accept-path.
4. Confirm §4.10 413/`chain_depth_exceeded`/connection-admission against the live
   `resource_bounds`/`concurrency` categories; refine the payload-bound status if
   the oracle expects a body-bearing 413.
5. Agility (Ed448/SHA-384) stays honestly SKIPPED/WARN (A-UN-001) — not gating under
   `--profile core`.
