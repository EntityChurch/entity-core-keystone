# entity-core-protocol-rexx — Phase S3 summary (COMPLETE)

**Phase:** S3 (peer machinery)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/rexx-toolchain:latest` (Regina Rexx **3.9.6**)
**Status:** ✅ **COMPLETE — two-peer loopback smoke 8/8 + foundation self-test 31/31 (0 fail).**
Reproduce: `./run-s3.sh` (→ `make s3`: self-test 31/31 + smoke 8/8). Container-bound,
sealed-offline (`--network=none`; loopback is intra-container 127.0.0.1). S2 codec gate
unaffected: still **69/69**.

## What S3 built (Core Layers 1–4 + foundation, on the S2 codec)

The full peer, in idiomatic classic Rexx — flat `Module_Verb` labels (no ANSI
namespaces), the `EC.` global stem for all state, handles (`peer1`/`store1`/`conn1`/…)
as the object analogue, and the **RC-flag** error model (`EC.!OK` codec reject /
`EC.!EXC` peer-layer throw, mapped once at the dispatch top — A-RX-010: Regina does not
propagate SYNTAX across a CALL). Every value rides the S2 self-delimiting tagged-value
(TV) byte string (the EIAS resolution); `src/ecf.rex` is the protocol-altitude map/field
layer over it, and an **entity is itself a byte string** (`'E' len·type len·hash data`)
so it passes by value through the whole peer with no record type.

| Layer | Module(s) | Notes |
|---|---|---|
| **value model** | `col.rex` `ecf.rex` `entity.rex` `envelope.rex` `wire.rex` | packed-list collection; map/array builders + typed reads; entity/envelope byte-string reps; §1.6 framing + EXECUTE/EXECUTE_RESPONSE |
| **L1 identity** | `identity.rex` `hash.rex` `peerid.rex` | §1.5 identity-multihash peer_id; §3.5 signature; content_hash (varint fmt + SHA) |
| **foundation** | `store.rex` | content store (hash→entity) + tree (path→hash) over `EC.` stems; §6.10/§6.13(c) emit hook; §4.8 store-safety STRUCTURAL (single thread) |
| **§9.5 floor** | `coretypes.rex` | all 53 core types render-from-model |
| **L3 capability** | `capability.rex` | §5 verify_request/chain/attenuation/caveats/revocation + §3.6 M3 multisig; packed scope/grant structs |
| **L2/L4 peer** | `peer.rex` `handlers.rex` `conn.rex` | §6.5 dispatch chain, §6.9/§6.9a bootstrap + seed policy, the MUST handlers (connect/tree/handler/capability/type) + §7a echo/dispatch-outbound |
| **transport** | `transport.rex` + `ext/ecnet.c` | the co-process daemon bridge (below) |

Non-functional floor baked in (not rediscovered at S4): §4.10(a) 16-MiB frame bound (in
the daemon de-framer), §4.10(b) `chain_depth_exceeded` structural pre-check (400, before
the authz walk), §7b TCP_NODELAY, §4.5 present-empty-vs-absent negotiation (`Ecf_Has`,
A-RX-007), the §6.11 request_id demux (proven by the 8-way concurrent test).

## The transport — the novel S3 piece (A-RX-008 → A-RX-011)

Since `rxfuncadd` is dead (A-RX-005), sockets can be neither a C extension nor a
per-invocation helper. So the transport is a **persistent `ecnet` C co-process daemon**
that OWNS the real sockets + a `select()` loop + the §1.6 de-framing, driven by the
single-threaded Rexx peer over two named pipes (FIFOs): the peer writes commands
(`LISTEN`/`DIAL`/`SEND`/`CLOSE`) and reads events (`LISTENING`/`ACCEPT`/`FRAME`/`CLOSED`).
C owns I/O + select; Rexx owns the protocol brain. One Rexx thread + one select loop give
**structural §7b store-safety** (no concurrency to race). The §6.11 reentry is a nested
pump on the same loop (the correlation-map tax the non-actor peers pay).

Three hard Regina realities surfaced and were resolved *in the transport* — each a
durable finding (see `SPEC-AMBIGUITY-LOG.md`):

1. **Two-FIFO deadlock.** A blocking event write + a blocking command read wedge both
   processes. → the daemon is **fully non-blocking on every write** (evt + per-socket
   output queues drained via `select` write-readiness); it never blocks.
2. **Regina FIFO reads lose data.** `linein` AND char-at-a-time `charin` drop bytes
   across a pipe-read boundary under a burst. → events are **length-prefixed**
   (`<8-hex-len><bytes>`) and read with an **exact-byte-count `charin(,,N)` loop**, which
   is reliable.
3. **`ADDRESS SYSTEM` corrupts an open FIFO stream (A-RX-011, the headline finding).**
   ANY fork/exec (even `address system 'true'`) while the evt FIFO is open desyncs
   Regina's read buffer — so the eccrypto **subprocess crypto is incompatible with the
   FIFO transport**. → crypto is **folded INTO the ecnet daemon** (it links
   `libentitycore_codec`): the networked peer's §9.1 crypto crosses the C-ABI over the
   same FIFO channel (a `SHA256`/`SIGN`/… command answered by an `R <hex>` event the
   caller demuxes, deferring interleaved network events to the main pump). The OFFLINE
   paths (S2 codec, S3 self-test) keep the eccrypto helper — no FIFO open, no corruption
   — via a `EC.!CRYPTO_VIA` mode switch.

## Smoke scenario (8/8, two OS processes over loopback TCP)

A bash driver launches a RESPONDER peer (its own daemon, ephemeral port) + an INITIATOR
peer (a second identity) that dials it and drives: session established (cap minted) ·
remote peer_id is/matches the responder · unregistered path → 404 · authority-gated tree
get → 200 returning a `system/handler/interface` · capability request → 200 · **8
concurrently-issued tree gets each correlated by request_id** (N7 §6.11). Process model
is genuinely two peers in two processes (unlike Tcl's one-interp two-peer loop) — the
Rexx-native shape.

## Findings / decisions (S3)

- **A-RX-011 (NEW, durable):** `ADDRESS SYSTEM` fork/exec corrupts a concurrently-open
  Regina FIFO read stream → crypto must live in the transport daemon, not a spawned
  helper, for the networked peer. The deepest transport lesson in the cohort.
- **A-RX-008 (RESOLVED):** the co-process-daemon-over-FIFOs socket plan is proven; the
  daemon is fully non-blocking (evt + per-conn output queues) and length-prefixes events.
- No spec-precision finding at S3 — the peer machinery is a faithful port of the
  language-agnostic protocol layers (now proven a third time after Tcl/COBOL) onto the
  Rexx substrate; the probe's value was S2 (the decimal↔IEEE number model, corroboration).

## Exit criteria — MET

Smoke 8/8 + self-test 31/31, both offline in-container; peer reads as classic Rexx.
**Next: S4** — `validate-peer --profile core` against the go oracle (`cc1970f`), driven
via `run-s4.sh` (per-language). A perf note for S4: crypto now round-trips through the
daemon FIFO (no per-op process spawn — *faster* than the S2 eccrypto path under a flood).
