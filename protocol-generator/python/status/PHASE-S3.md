# Phase S3 — Python peer — Peer machinery — Summary

**Peer:** `entity-core-protocol-python` (CPython) — clean-room clone of the hand-
written sibling `entity-core-py`. **Branch:** `lang/python` (worktree).
**Phase:** S3 (peer machinery). **Spec authority:**
`spec-data/v7.75` (full ENTITY-CORE-PROTOCOL-V7.md body). **Built on** the S2
codec (`entity_core/{_cbor,_varint,_base58,content_hash,peer_id,signature,
errors}.py`) — unchanged, still 69/69 wire-conformance.

**Clean-room discipline:** the peer machinery was authored from V7 + the keystone
`shared/lifecycle` + `shared/seed-policy` conventions + STUDYING the cohort
siblings' *machinery shape* (`protocol-generator/{go,ocaml}/src/` — fair game per
the prompt). **No source under the Python sibling `entity-core-py` was opened.**
Where a value matches the Go peer it is by independent arrival on the same spec.

## Exit criteria — met (the S3 gate is GREEN)

```
S3 peer gate (offline, python-toolchain image):
  two-peer LOOPBACK over real TCP ....... 11/11 checks PASS (2 scenarios)
  type-registry byte-identical .......... 53/53 §9.5 floor types PASS
  §3.6 multisig ACCEPT-path unit test ... 7/7 PASS
  S2 wire-conformance (regression) ...... 69/69 PASS, 0 FAIL (unchanged)
```

- [x] **Two-peer loopback over real TCP** — 11/11 checks (handshake §4.1, 404 on
      unregistered path, authority-gated tree get, capability request, 8-way
      `request_id` demux §6.11, register live-hook, emit hook §6.13(c), §7a echo).
- [x] **Type-registry conformance** — all 53 V7 §9.5 floor types rendered from the
      peer's OWN in-code model reproduce the cross-blessed golden content_hashes
      byte-for-byte (`tests/peer/test_type_registry.py`).
- [x] **Genuine §3.6 K-of-N multisig** + accept-path unit test — 7/7
      (`tests/peer/test_multisig.py`): 2-of-3 → ALLOW; M3 (n<2, dup signers,
      threshold<2) deny flips; M4 (1<threshold sigs) deny; M6 (local∉signers)
      deny; single-sig path strict superset still ALLOWs.
- [x] **`host.py`** — the S4 `validate-peer --profile core` oracle-driver entry
      point (`python -m entity_core.host`). Verified live: `--help`, `--name`
      keypair load, `LISTENING <port>`, real dial + handshake + §7a echo.
- [x] `status/PHASE-S3.md` (this file) + `CONFORMANCE-REPORT.{md,json}` updated +
      `SPEC-AMBIGUITY-LOG.md` appended (A-PY-009/010 new).

## What was built (`src/entity_core/peer/` + `host.py`)

| Module | Surface | Spec |
|---|---|---|
| `model.py` | `Entity` (frozen dataclass) + `Envelope` + `Included`; §1.8 validate-before-trust hash fidelity | §1.1, §3.1, §3.4 |
| `identity.py` | `Identity` (Ed25519 seed → peer_id/peer_entity/identity_hash); §1.5 canonical peer-id; `sign_entity` / `verify_signature` | §1.5, §3.5, §7.3 |
| `wire.py` | §1.6 length-prefixed framing (`MAX_FRAME` 16 MiB, **413 before buffering** §4.10(a)); EXECUTE / EXECUTE_RESPONSE builders; error result | §1.6, §3.2, §3.3, §4.10(a) |
| `store.py` | **`threading.Lock`-guarded** content store + entity tree; §6.10 emit consumers fired OUTSIDE the lock | §1.7, §4.8, §6.10 |
| `capability.py` | §5.4 pattern match, §5.2 verify-request + check-permission, §5.5 chain-walk + §5.6 attenuation, §4.10(b) **400 chain_depth_exceeded** structural pre-check, **genuine §3.6 K-of-N multisig (M3/M4/M6)** | §3.6, §4.10(b), §5.2, §5.5, §5.6 |
| `typedefs.py` | the V7 §9.5 core type floor (53 types) rendered from an in-code model | §9.5 |
| `handlers.py` | the four MUST handlers (connect/tree/capability/handlers) + §7a echo / dispatch-outbound | §6.2, §6.3, §4.1, §4.6, §7a |
| `peer.py` | bootstrap (§6.9 + §6.9a owner-cap + seed-policy default), §6.5 dispatch chain, §6.6 resolution, §6.11 reentrant-outbound seam, §6.9a authenticate-time dual-form seed derivation | §6.5, §6.6, §6.9, §6.9a, §6.11 |
| `transport.py` | TCP listener + thread-per-connection reader-demux (`Condition` + request_id correlation), TCP_NODELAY, §4.8 inbound-on-own-thread, client dialer + §4.1 handshake | §1.6, §4.8, §6.11, §7b |
| `host.py` | the `python -m entity_core.host` CLI (S4 validate-peer target) | — |

Concurrency idiom (profile `[async]`): **threaded** (thread-per-connection),
**Lock-guarded store**, **`Condition` request_id demux** — the cohort reader-
thread + condvar shape (OCaml/Ruby). CPython releases the GIL on blocking socket
IO and inside the `cryptography`/`hashlib` C extensions, so the IO-bound peer is
genuinely concurrent (A-PY-007). The GIL does NOT make a §3.9 CAS atomic, so the
explicit Lock is mandatory.

## Pinned conformance invariants (built in at design time, not S4)

- **N5** `included` preservation request+result side — the codec carries
  `included` verbatim; signatures are ingested + re-bound at canonical paths.
- **N6** inbound-concurrent-with-outbound dispatch (§4.8) — each inbound EXECUTE
  runs on its own thread so a §6.11 reentrant outbound does not deadlock the
  reader (verified by the 8-way demux + the dispatch-outbound seam).
- **N7** reentrant transport + `request_id` demux (§6.11) — pending-map +
  `Condition`; the loopback's 8 interleaved requests each correlate (8/8).
- **N8** capability verdict determinism (§5.10) — the verdict is a pure function
  of (request, store, included); no RNG in the authz path.

## v7.75 non-functional substrate floor (built in)

- **§4.8 store data-race safety** — `threading.Lock` (explicit; GIL ≠ compound-
  atomic). **§4.9** — per-request isolation (an adversarial EXECUTE returns a
  coded response, never tears down the connection; reader keeps serving).
- **§4.10(a)** — finite `MAX_FRAME` (16 MiB), rejected by **checking the length
  prefix before buffering** the body → `413 payload_too_large`.
- **§4.10(b)** — `chain_exceeds_depth` structural pre-check (walks parents, NO sig
  work) called BEFORE the per-link authz walk → over-depth = **`400
  chain_depth_exceeded`** (NOT 403); an *unreachable* parent stays a 403/deny.
- **§7b** — **TCP_NODELAY** on every accepted/dialed socket; blocking socket IO
  runs on dedicated OS threads (thread-per-connection), never on a bounded
  cooperative pool.

## §3.6 multisig (the headline peer-surface call)

`granter` is polymorphic: a single `system/hash` (single-sig) or a
`system/capability/multi-granter` `{signers, threshold}` (root-only K-of-N).
Per the §5.5 normative pseudocode:

- **M3** (precedence: BEFORE any signature work, surfaces 403): for every chain
  entity whose granter is a multi-granter — `parent` null (root-only),
  `len(signers) >= 2`, no duplicate signers, `threshold ∈ [2, len(signers)]`.
- **M6** root check: the local peer MUST be in `signers` AND have signed.
- **M4** per-link: count **distinct-signer** valid signatures; ALLOW iff
  `valid >= threshold`.

Single-sig caps verify byte-identically (strict superset). The oracle's multisig
category is rejection-heavy, so the ACCEPT path is covered by the peer's own
`tests/peer/test_multisig.py` (2-of-3 → ALLOW, the positive vector).

## Seed-policy bootstrap (§6.9a, per `shared/seed-policy/`)

The peer materializes at L0: (1) the **self owner-cap** — detached-signature
shape: a `system/capability/token` at `system/capability/policy/{owner_hash_hex}`
with full scope over `/{peer_id}/*`, its self-signature at
`/{peer_id}/system/signature/{cap_hash}`; (2) a **`default` policy-entry** =
the §4.4 discovery floor (or the degenerate `default → *` under
`--debug-open-grants`). Authenticate derives grants via the dual-form lookup
(`identity_hash_hex` → Base58 `peer_id` → `default`) UNION'd with the discovery
floor. No `initialGrants()/openGrants()` fork (non-conformant per §6.9a).

## New ambiguity entries (S3)

- **A-PY-009** — `host.py` `--name` keypair file format (base64 of a 32-byte
  seed; PEM-armor tolerated). *operator*.
- **A-PY-010** — S3 test runner: a stdlib zero-dep runner (`tests/peer/_run.py`)
  drives the peer suites because the offline core image ships no pytest. The
  tests are plain-`assert` pytest functions (pytest-runnable in a dev layer too).
  *operator*.

No NEW spec-semantics ambiguity — the §3.6/§5.5/§6.9a surfaces were fully
specified in the v7.75 snapshot (same-as-sibling adoption peer, dry discovery
well; matches the S1/S2 expectation).

## Anything blocking S4 (`validate-peer --profile core`) — NONE

The peer surface is complete and the host entry point is live. S4 drives
`validate-peer --profile core` against `python -m entity_core.host` (with
`--validate` for the §7a categories and a real owner seed / `--debug-open-grants`
for the grant-gated write surface, per the seed-policy convention). The S3/S4
boundary is honored: S3 stands up the green machinery + gate; S4 runs the live
oracle. No oracle results are doctored (that is S5).

### Reproduce the S3 gate

```bash
podman run --rm --network=none -v "$PWD:/work:Z" \
  -w /work/protocol-generator/python \
  entity-core-keystone/python-toolchain:latest \
  sh -c 'PYTHONPATH=src python tests/peer/_run.py'
```
