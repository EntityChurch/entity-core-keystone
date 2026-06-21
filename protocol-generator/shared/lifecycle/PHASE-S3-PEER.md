# Phase S3 — Peer machinery

> Loaded by `/entity-rosetta <lang> --phase peer` or as third phase of full `/entity-rosetta <lang>`.

## Objective

Build the peer machinery of `entity-core-protocol-<lang>` on top of the S2 codec. V7 Layers 1–4 plus foundation.

## Surfaces

| V7 layer | What you implement |
|---|---|
| **L1 Identity** | Identity bundle + keystore primitive; peer-id resolution; signature target rules; `system/peer` and `system/signature` entity types fully integrated with the codec |
| **L2 Interaction** | **Only two wire message types: `EXECUTE` and `EXECUTE_RESPONSE`** (V7 §3.3) — typed builders + parsers + dispatchers; any other root type → close connection. `hello`/`authenticate` are *operations* on the `system/protocol/connect` handler (§4.1), **not** message types. `request_id` demux for out-of-order replies (V7 §6.11); per-request transport error codes (§6.12: `recv_timeout`/`connection_broken`/`protocol_error`) |
| **L3 Capability** | `system/capability/token` shape; chain-walk + signature verification (Layer 1 verdict per §5.10); attenuation enforcement; TTL; §5.8 cross-peer chain-construction registry shape; two-layer enforcement boundary |
| **L4 Bootstrap** | TCP listener + dialer; connection management; inbound concurrent with outbound dispatch (§4.8); reentrant transport (§7.55 / §6.11) |
| **Foundation** | Content-addressed store interface (in-memory minimal impl); processor loop + queue; **handler interface contract** (`HandlerContext` shape, registration, dispatch — actual handlers are community-installed) |
| **Observability** | Inspect taps + content streams + dump primitives per `GUIDE-INSPECTABILITY` |

## What you do NOT implement

- Any standard extension (TREE, CONTENT, IDENTITY-as-extension, ATTESTATION, QUORUM, REGISTRY, RELAY, GROUP, ROLE, ENCRYPTION, GC, BRIDGE-HTTP, COMPUTE, SUBSCRIPTION, CONTINUATION, REVISION, INBOX, DURABILITY, DISCOVERY)
- Concrete domain handlers (`local/files`, `local/processes`, …)
- The standard-peer composition (which extensions are bundled — community decision)

## Idiom rules per profile

The peer surface is where idiom matters most. Per the profile:
- Async or sync? E.g. `async Task` on .NET, callbacks on Node, `async fn` in Rust, threads in Java
- Error model: throw vs Result vs Either
- Concurrency primitive: tasks, goroutines, threads, futures, actors
- Hosting pattern: dependency injection, plain functions, builder pattern

If the profile's idiom guidance is silent on a question, log it in the ambiguity log and pick a reasonable default — flag it as a profile-gap candidate.

## Smoke runner

Write a smoke runner that:
1. Boots a `entity-core-protocol-<lang>` peer on a localhost port
2. Boots a reference peer (e.g. `entity-core-go entity-peer` binary, pulled into the container)
3. Completes the connection handshake both directions — EXECUTE `system/protocol/connect` `hello` then `authenticate` (V7 §4.1: 3 EXECUTE + 3 EXECUTE_RESPONSE)
4. Sends an EXECUTE targeting an unregistered path → expects an EXECUTE_RESPONSE with status 404 (no handler resolved)
5. Confirms reply correlation by `request_id` for out-of-order replies (V7 §6.11)
6. Tears down cleanly

Smoke runner passing means the peer can talk to the network at the wire level. Conformance details come in S4.

## Pinned conformance invariants (read before building)

The peer-side bug classes that bit all three reference impls (Go, Rust, Python) — `research/diagnostics/conformance-invariants.md` **N5–N8**: envelope `included` preservation request+result side (N5, V7 §3.1/§3.3), inbound-concurrent-with-outbound dispatch (N6, §4.8), reentrant transport + `request_id` demux (N7, §6.11/§6.12), capability verdict determinism (N8, §5.10 — tested by `validate-peer` convergence mode). Enforce at design time, not at S4.

## v7.75 non-functional substrate floor (build it in — don't rediscover it at S4)

These are §9.1 floor MUSTs under **both** profiles as of v7.75, gated by the `concurrency` (§7b) and `resource_bounds` validate-peer categories. They are language-runtime axes — the 9-peer cohort each hit them and fixed them; bake them in so this peer doesn't:

- **§4.8 store data-race safety under concurrent dispatch.** The store MUST stay consistent under simultaneous inbound dispatches (a data race = crash is a FAIL). Pick the idiom that makes it structural, not bolted-on: actor/mailbox (Swift, Elixir), STM transactions (Haskell), RW-lock / sharded / single-writer (Zig, Common-Lisp, Go raw-thread). The actor and STM runtimes get it *by construction*; raw-thread/image runtimes enforce it by hand — that choice belongs in the profile.
- **§4.9 resilience under sustained load.** Stay responsive; bound resources; **deliver-or-signal, never silently drop**; don't crash; recover. Gated by `concurrency` T2.1/T2.2.
- **§4.10 resource bounds.** Enforce a **finite max inbound payload** → reject over-limit with **`413 payload_too_large`** before buffering the body (check the length prefix). Enforce a **finite max capability-chain depth** → reject an over-deep chain with **`400 chain_depth_exceeded`** (NOT 403 — structural excess ≠ authz denial), and crucially do the depth check **BEFORE the per-link authz walk** (a structural pre-check that walks parents counting depth; an *unreachable* parent is not a depth problem and stays 403). Recommended (informative, non-normative) defaults: **16 MiB / 64**. Connection admission (§4.10(c)) is a SHOULD with an external-layer carve-out (`503 too_many_connections` / close, or honest WARN). Keep serving after every rejection.
- **§7b transport menu.** Set **TCP_NODELAY** on raw-socket peers. **Never run blocking syscalls (`read`/`accept`/etc.) on a bounded cooperative/structured-concurrency pool** — it starves the pool (Swift's structured-concurrency bounded pool stalled on `read()` → 60s; fixed by moving the blocking I/O to dedicated OS threads). If the runtime's default executor is a small cooperative pool, the profile MUST say where blocking I/O runs.

The chain-depth pre-check is the only one that was net-new peer code across the whole v7.75 cohort (all nine returned 403 before the ruling) — implement it as one structural `chainExceedsDepth(cap, resolve)` helper at the dispatch site, mapping over-depth → `400 chain_depth_exceeded`.

## Phase output

- `protocol-generator/<lang>/src/` filled in with peer modules per the profile's layout
- `protocol-generator/<lang>/src/<smoke-runner>` — runs the smoke scenario
- `protocol-generator/<lang>/status/PHASE-S3.md` — phase summary
- `protocol-generator/<lang>/status/SPEC-AMBIGUITY-LOG.md` — updated

## Phase exit criteria

Smoke runner green; peer compiles cleanly; idiom-level review done (the code reads as `<lang>` code, not transpiled).
