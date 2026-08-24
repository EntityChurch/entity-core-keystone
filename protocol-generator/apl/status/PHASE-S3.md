# entity-core-protocol-apl — Phase S3 summary (COMPLETE)

**Phase:** S3 (peer machinery)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/apl-toolchain:latest` (GNU APL 1.9, source-built)
**Status:** ✅ **COMPLETE — offline foundation self-test 18/18 + two-peer loopback smoke 5/5
(0 fail).** Reproduce: `./run-s3.sh` (→ `make s3`). Container-bound, sealed-offline
(`--network=none`; loopback is intra-container 127.0.0.1). S2 codec gate unaffected: still
**69/69** (`make conf`) + unit ALL PASS.

## What S3 built (Core Layers 1–4 + foundation, on the S2 codec)

The full peer in APL-native idiom — the (kind payload) nested-array value model, PascalCase
tradfns for all dispatch/stateful/loop logic + branch-free dfns for pure transforms
(A-APL-012 forces `→`-branch flow control), and native `⎕FIO` Berkeley sockets (NO C
net-shim — A-APL-006). One GNU APL image = one peer (the profile `[async]` single-image
model); §4.8/§7b store-safety is STRUCTURAL (one image, one `⎕FIO[40]` select-pump, one
frame dispatched to completion before the next event is polled — no lock, no race).

| Layer | Module(s) | Notes |
|---|---|---|
| value helpers | `val.apl` | map/array builders + typed field reads over the S2 value model; hex/list bridges |
| **L1 identity** | `identity.apl` `keystore.apl` | §1.5 identity-multihash peer_id (base58 via C-ABI); §3.5 sign/verify; keystore `~/.entity/peers/NAME/keypair` PEM (hand-rolled base64) |
| materialized entity | `ent.apl` | `(present type data hash)`; §1.1 content_hash via C-ABI floor; §1.8 recompute-and-verify on decode |
| foundation | `store.apl` | content store (hash→entity) + tree (path→hash) + §3.9 listing; **§4.8 store-safety STRUCTURAL** |
| §9.5 floor | `coretypes.apl` | all 53 core types render-from-model |
| **L2 wire** | `wire.apl` | §3.1 envelope (byte-keyed `included`, N5), §3.2/§3.3 EXECUTE/EXECUTE_RESPONSE builders+parsers, `WirePeek` demux helper |
| **L3 capability** | `capability.apl` | §5 verify_request/chain-walk/attenuation/caveats/revocation + §3.6 M3 multisig K-of-N; ALLOW/DENY + unresolvable trichotomy; the §4.10(b) chain-depth pre-check |
| **L4 transport** | `net.apl` `transport.apl` | native `⎕FIO` sockets + §1.6 framing + per-fd rx buffers + §6.11 request_id demux table |
| **L2/L4 peer** | `peer.apl` | §6.5 dispatch chain, §6.9/§6.9a bootstrap + seed policy, MUST handlers (connect/tree/handler/type/capability) + §7a echo/dispatch-outbound, initiator session + §4.1 handshake + the `⎕FIO` serve/reentry pump |
| host | `bin/peer.apl` | the S4-ready `--name/--port/--seed/--validate/--debug-open-grants` host (prints `LISTENING <port>`); CLI via `⎕ARG` |

## The transport — native GNU APL ⎕FIO sockets (contrast Fortran/COBOL)

GNU APL provides Berkeley sockets natively (`⎕FIO[32/33/34/35/36/37/38/40/47]`), so — unlike
Fortran/COBOL, which hand-wrote a C net-shim — there is **no shim and no co-process**: the
`⎕FIO[40]` select loop + §1.6 de-framing live directly in APL (`peer.apl` `PeerServe` /
`ServeReadable` + `transport.apl` `TrRxExtract`). The verified `⎕FIO` socket ABI and TWO
worked-around GNU-APL-1.9 `select` bugs are logged as **A-APL-015** (single-integer IPv4;
accept returns `(handle …)`; the timeout is inoperative → select is a pure block-until-ready
primitive; `fds_to_val`'s off-by-one drops the highest ready fd → recovered via
`count > #reported`; the `1 ⎕FIO[60]` vector-random crash → `/dev/urandom`). The §6.11
reentry (`HndDispatchOutbound`) is a MANUAL reentrant pump (`PumpUntil`) on the same loop —
the correlation-map tax the non-actor peers pay.

## v7.75 §9.1 non-functional floor — baked in (not deferred to S4)

- **§4.8 store-safety = STRUCTURAL** (single image, single select-pump; stated in
  `store.apl` / `peer.apl`).
- **§4.10(a) 413**: `TrRxExtract` checks the 4-byte length prefix and, on a frame >
  `MAX_FRAME` (16 MiB), flags oversize **before buffering the body**; the peer answers
  **`413 payload_too_large`** (`Send413`, empty request_id — the body was never read) and
  keeps serving. Covered by the self-test framing check.
- **§4.10(b) chain depth**: `CapChainExceedsDepth` is a STRUCTURAL pre-check run BEFORE the
  per-link authz walk in `CapVerifyRequest`; over-depth → **`400 chain_depth_exceeded`** (NOT
  403). An unreachable parent is NOT a depth error (stays 403). Informative bound 64.
- **§7b**: `TCP_NODELAY` set on every accepted/dialed socket (`NetNodelay`); no blocking call
  on the select path (the `⎕FIO[40]` block-until-ready is the only waiter — there is no
  cooperative pool to starve, GNU APL being one image).

## N5–N8 coverage

- **N5** envelope `included` preservation both sides: `EnvToCbor`/`EnvOfCbor` carry the
  byte-keyed `included` map, dedup first-seen, and verify each content_hash == its key (§3.1);
  the authenticated-request path round-trips a 5-entity `included` (cap, granter, author,
  cap-sig, exec-sig) through the responder and back.
- **N6** inbound-concurrent-with-outbound dispatch: the single `⎕FIO` pump dispatches an
  inbound EXECUTE to completion before polling the next event (§4.8 by construction).
- **N7** reentrant transport + request_id demux: the **8-way** concurrent smoke leg fires 8
  EXECUTEs in flight and correlates every reply by request_id (`transport.apl` pending table
  + `WirePeek`). **PASS (5/5).**
- **N8** capability verdict determinism: `CapVerifyRequest` is a pure function of
  (local, store, envelope) — no clock-dependent branch except explicit TTL/temporal bounds.

## Smoke result (two OS processes over loopback TCP)

```
responder bound on 127.0.0.1:<port> (peer_id 2KHoAk7A5Jmh...)
  [PASS] session established both ways (capability minted)
  [PASS] remote peer_id is a base58 peer id
  [PASS] remote peer_id matches responder
  [PASS] unregistered path -> 404
  [PASS] 8 interleaved requests each correlated by request_id
SMOKE: PASS (5/5)
```

Handshake both directions (hello → authenticate → seed-policy grant mint), a real §5.2
chain-verify on the minted discovery-floor cap gating the 404 path, out-of-order demux, clean
teardown. The offline self-test (18/18) adds the accept-path coverage the network gate can't
isolate: store round-trip, entity content_hash + wire fidelity, sign/verify (+ negative),
base64 keystore round-trip, the full §5.2 verify-request chain (A grants to B; B's request
ALLOWs; a mis-signed request → 401 AUTHN_FAIL), the chain-depth pre-check, and the 413
length-prefix pre-check — the "direction the oracle can't cover" discipline.

## Findings / decisions (S3)

- **A-APL-015 (⎕FIO socket ABI + two upstream `select` bugs — NEW).** Single-integer IPv4;
  accept returns `(handle AF ip port)`; the `⎕FIO[40]` timeout is inoperative (a NULL-timeout
  bug) so select is a clean block-until-ready primitive; `fds_to_val`'s `m<max_fd` off-by-one
  drops the highest ready fd (recovered); `1 ⎕FIO[60]` vector-random crashes the interpreter
  (→ `/dev/urandom`). A durable GNU-APL socket cookbook.
- **A-APL-016 (niladic dfns eval at load; `{}X` errors — NEW).** GNU APL 1.9 `--script`
  evaluates a niladic dfn at definition time (so niladic *functions* must be tradfns), and the
  empty-dfn-for-effect idiom `{}expr` throws VALUE ERROR (→ `zz←expr`). A durable GNU-APL
  idiom note beyond A-APL-012's control-flow finding.
- **No spec-precision finding at S3** — the peer machinery is a faithful port of the
  language-agnostic protocol layers onto APL's array/value substrate (the probe's headline
  value was S2, the array-model codec; S3 corroborates that the generator survives a language
  with no statement control flow AND upstream socket/eval quirks).

## What S4 must know

- **Launch:** `apl --script <S3 modules> -f bin/peer.apl -- --name NAME [--port N]
  [--validate] [--debug-open-grants]`. `--name` loads/creates the Ed25519 seed at
  `~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of the 32-byte seed; peer_id
  `2KHoAk7A5Jmh…` for seed 0x11 — matches the Fortran/cohort). `--seed HH` is the
  deterministic fallback. Prints `LISTENING <port>`; `--port-file` writes `<port>\n<peer_id>`.
  `--validate` bootstraps the §7a `system/validate/{echo,dispatch-outbound}` handlers (OFF by
  default). `--debug-open-grants` selects the degenerate `default→*` policy.
- **`bin/peer.apl` is caught by the repo-root `**/bin/` gitignore** (same as
  `protocol-generator/fortran/bin/peer.f90`) — the overseer must `git add -f
  protocol-generator/apl/bin/peer.apl` to commit the host entry point. (Root `.gitignore` was
  NOT modified — a boundary-sensitive repo-wide change; flagging instead.)
- **Seed policy** is wired per the keystone convention: an owner cap at
  `system/capability/policy/{id_hash_hex}` (detached-signature shape) + a `default`
  policy-entry (discovery floor, or the open scope under `--debug-open-grants`); authenticate
  derives grants = UNION(discovery_floor, policy_entry.grants).
- **`run-s4.sh` is NOT yet authored** — author it against
  `apl --script <modules> -f bin/peer.apl -- --name conformance --port 0 --debug-open-grants
  --validate`, scrape `LISTENING`, run `validate-peer -profile core -addr 127.0.0.1:$PORT`.
  Output must be **file-redirected, never piped** (A-APL-013). The go oracle builds via
  `tools/oracle-bootstrap.sh` to `output/s4-oracles/{validate-peer,entity-peer}` (commit
  `cc1970f`).
- **Known S4 gaps to expect:** (1) `dispatch-outbound` (`HndDispatchOutbound`) wires the
  §6.13(b) reentry pump but is only exercised under `--validate` + a live reentry connection;
  (2) `system/type:validate` is a minimal required-field presence check (not full structural
  validation); (3) handler `register` routes new patterns to the echo stub routine (no
  expression-path execution — extensions are community-installed). Everything else
  (connect/tree/handler/type/capability, chain verify, multisig, revocation, the §4.10 floor)
  is implemented and offline-verified.
- **Reproduce:** `./run-s3.sh` (full), `./run-s3.sh selftest`, `./run-s3.sh smoke`. The shim
  is rebuilt by `make shim`; the S2 corpus gate stays green (`make conf` → 69/69).
