# entity-core-protocol-cobol — Phase S3 status

**Gate (smoke runner green): MET for the connect path.**
The S3 foundation (data plane + transport) plus the connect handshake + TCP host
are built and **live-verified** against the Go `validate-peer` oracle:
`connectivity 22/22` + `encoding 6/6` PASS over real TCP. The rest of the peer
brain (the §6.5 dispatch chain → tree/capability/type/security/multisig/etc.)
moves to **S4** — see `status/PHASE-S4.md`. The section below is the original
S3-foundation snapshot.

## Built + verified (green via `make test`, sealed-offline)

| Layer | Module | Verified by | Status |
|---|---|---|---|
| Canonical CBOR value codec | `src/cbor.cob` | `cbor-unit` 8/8, `codec-selftest` 68/0/1 | ✅ |
| Entity + envelope model (§1.1/§3.1/§3.4) | `src/model.cob` | `model-test` (encode→corpus-hash→decode+fidelity) | ✅ |
| Wire framing (§1.6, 4-byte BE len, 16 MiB bound) | `src/wire.cob` | `transport-test` | ✅ |
| TCP transport seam (listen/accept/connect/rw, NODELAY §7b) | `src/netshim.c` | `transport-test` (socket round-trip) | ✅ |

The data plane round-trips end-to-end: a framed envelope crosses a real socket,
bytes identical, the root entity is recovered with §1.8 content-hash fidelity.
This proves the COBOL FFI-hybrid stack (canonical CBOR + FFI crypto/hash +
sockets) carries a core protocol peer's substrate. The hardest COBOL risks are
all retired: recursion (LOCAL-STORAGE), canonical CBOR (transcoder + sort),
byte-exact FFI, decimal-first uint64 carrier, and now sockets + framing.

## Remaining S3 work (the peer "brain") — scoped, not yet built

Porting the reference peer's protocol logic (OCaml `peer.ml` 854 LOC +
`capability.ml` 568 LOC) into COBOL:

1. **Connect handshake (§4.1/§4.6)** — `hello` (issue nonce) + `authenticate`
   (verify Ed25519 sig over the nonce via FFI; derive peer-id; seed grants).
   This is the gate for *any* validate-peer connectivity.
2. **Dispatch (§6.5)** — EXECUTE → resolve handler → verify cap → check perm →
   handler; unregistered → 404; non-EXECUTE root → close.
3. **Capability chain-walk (§5.5/§5.10)** — attenuation, TTL, signature verify
   (FFI), granter-frame authz, the §4.10(b) depth pre-check (400 vs 403),
   multi-sig §3.6 K-of-N.
4. **Store** (content-addressed, §4.8 single-writer lock) + **register/unregister**
   (§6.13a) + **type registry** render (53-type §9.5 floor).
5. **v7.74 foundations** (register/outbound/emit/owner-cap) + **v7.75 floor**
   (concurrency §7b, resource_bounds §4.10) + **§7a conformance handlers**.
6. **TCP host binary** (`bin/host.cob`): accept loop, per-connection threads
   (blocking I/O off any bounded pool, §7b), `LISTENING` readiness line, `--name`
   identity, `--validate`/`--debug-open-grants` flags.
7. **Smoke runner**: handshake vs a Go `entity-peer` reference + 404 dispatch +
   request_id demux.

## Honest assessment

A full `validate-peer --profile core` 0-FAIL COBOL peer replicates ~1400+ LOC of
mature-language protocol brain across ~16 categories with heavy oracle iteration —
a larger effort than one session. S1 (profile) and S2 (codec, 68/0/1) are
**complete + green**; the S3 substrate is **complete + verified**; the brain (S3
remainder), S4 convergence, and S5 packaging are the continuation. No conformance
is claimed that isn't demonstrated (S5/S7). Continuation plan + COBOL idiom notes
are captured in the S1–S3 foundation session handoff.
