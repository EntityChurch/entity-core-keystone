# entity-core-protocol-kotlin — Conformance Report

**Peer:** entity-core-protocol-kotlin (REACH peer; JVM/Kotlin ecosystem axis).
**Toolchain:** `entity-core-keystone/kotlin-toolchain:latest` — Temurin JDK 21.0.10+7 +
Kotlin 1.9.25 + Gradle 8.10.2; build + run `--offline --no-daemon`, conformance RUN
`--network=none`.

Two conformance bars, both GREEN:

| Bar | Gate | Result |
|---|---|---|
| **Lower (codec)** | `wire-conformance` byte-identity, v0.8.0 corpus | **69 / 69 PASS** |
| **Higher (peer)** | `validate-peer --profile core` (oracle `e8524ed`/v7.77) | **665 total · 0 FAIL · `Result: PASS`** |

---

## Higher bar — `validate-peer --profile core` (S4)

**Oracle:** Go `validate-peer` + `entity-peer` built from sibling `entity-core-go` pinned
at **v7.77 `e8524ed`** via `tools/oracle-bootstrap.sh`. **`core_gate_sha256` matches the
committed pin** (`e09a865ffea690ce207149eb68851f7afbc2fa3a9ba522a0ca9d9c72f9923308`) — the
mirror-stable identity proving the core surface == the cohort-converged surface. The
SACRED sibling go tree was clean before and after (clean-room `git archive`).

```
Summary: 665 total, 292 passed, 278 warned, 0 failed, 95 skipped
Result: PASS (with warnings)
```

- **0 FAIL.** 278 WARN = type_system non-§9.5-floor type vocabulary (matched-if-present) +
  r3 connection-flood SHOULD; 95 SKIP = §9.0 extension-category carve-outs (auto-allowlisted).
- **0 peer-correctness fixes** — the S3 peer cleared every core gate on the first oracle run
  (the reach-peer corroboration-only expectation; S3 pre-built the §7a reentry surface,
  genuine §3.6 K-of-N, §10.1 register, and the v7.75 non-functional floor).

### Per-category (core)

| Category | Result | Notes |
|---|---|---|
| connectivity | 22/22 PASS | §4.1 mutual handshake both legs; request_id echo |
| encoding | 6/6 PASS | ECF wire surface |
| type_system | 108 PASS / 276 WARN | 53-type §9.5 floor; non-floor types WARN (matched-if-present) |
| handlers | 35 PASS (core) / 32 SKIP | core get/put/list/connect/capability; ext handlers auto-skip; **§10.1 register 10/10** |
| capability | 12/12 PASS | §5.2/§5.6/§5.7 attenuation, caveats, revocation |
| tree_operations | 24 PASS (core) / 1 WARN / 31 SKIP | core ops; EXTENSION-TREE §9 ops auto-skip |
| security | 28/28 PASS | §5.2 request-verify (401 auth-class / 403 authz) |
| **multisig** | **11/11 PASS, 0 SKIP** | genuine §3.6 K-of-N incl `valid_2of3_peer_signed_accepted` (accept-path runs, not skipped) |
| **concurrency** | **5/5 PASS** | §7b store-safety + resilience (T1.1–3 / T2.1–2) |
| **resource_bounds** | **2 PASS / 1 WARN** | r1 payload→413 PASS · r2 chain-depth→400 PASS · r3 conn-flood WARN (SHOULD) |
| universal_address_space | 8/8 PASS | §1.4 foreign-namespace addressing |
| peer_canonicalization | 7/7 PASS | §3.6 PEER-PATTERN |
| format_agility | 10/10 PASS | format-code reject ladder |
| crypto_agility | 4/4 PASS | key-type / hash-format negotiation |
| negotiation | 4/4 PASS | §4.5 hello advertise + disjoint-reject |
| authz | 6 PASS (core) / 2 SKIP | core authz; ROLE-coupled checks auto-skip |

### §10.1 core-register gate — 10/10 PASS

`core_register_{body_binding, op_status, op_result, manifest_at_path, handler_at_path,
grant_at_path, grant_signature_at_invariant_path, unregister_status,
unregister_signature_removed}` + `validate_echo_dispatch` — all PASS. The §3.4
invariant-pointer grant-signature at `system/signature/{grant_hash}` is enforced;
unregister symmetry tested.

### multisig accept-path — genuinely runs (not a vacuous skip)

The Host's `--name conformance` surface loads the on-disk Ed25519 identity
(`~/.entity/peers/conformance/keypair`, entity-core PEM = base64 of the 32-byte seed
`0x11`×32 → peer_id `2KHoAk…`), so the validator co-signs a valid 2-of-3 AS the peer and
the peer verifies the quorum (§3.6 M3 + §5.5 M4 distinct-signer threshold + M6
local∈signers) → 200. `valid_2of3_peer_signed_accepted` PASS, NOT env-skipped.

## §10.2 origination-core (reference-peer-gated) — 3/3 PASS

`./run-origination-core.sh` (Kotlin A-role, Go `entity-peer --open-access` B-role, shared
loopback `--network=none`): `reference_connect` · `reference_ready` ·
`dispatch_outbound_reentry` all PASS over real two-peer TCP. The §6.11 reentry seam
(kotlinx.coroutines reader-coroutine demux + `Peer.outboundDispatch` over the inbound
`Conn`) round-trips: the validator-as-B mints the reentry cap, the peer originates the
outbound EXECUTE back over the same inbound connection → inner 200. Resolves A-KT-012.
origination is extension-only under `--profile core` (single-peer `run-s4.sh`
honest-SKIPs it).

---

## Lower bar — codec (S2): 69 / 69 PASS — byte-identical

**Corpus:** `test-vectors/v0.8.0/conformance-vectors-v1.cbor` (LOCKED ECF v1, byte-identical
v7.56→v7.75; 3-way Go × Rust × Python byte-locked). **Oracle:**
`entity-core-go/cmd/internal/wire-conformance`.

```
ECF conformance: 69/69 PASS (0 fail)
```

64 `encode_equal` + 5 `decode_reject` testable vectors. Every encode vector is
byte-identical to the embedded cross-blessed `canonical`; every reject vector is rejected
by this peer's own decoder.

| Category | Vectors | Result |
|---|---|---|
| `float.*` (f16/f32/f64 ladder + Rule-4a specials) | 14 | PASS |
| `int.*` (minimal head-form, both signs, boundaries) | 14 | PASS |
| `map_keys.*` (length-then-lex ordering) | 6 | PASS |
| `length.*` (definite-length only) | 8 | PASS |
| `primitive.*` (bool/null/empty) | 6 | PASS |
| `nested.*` (deep maps, entity carrier) | 4 | PASS |
| `tag_reject.*` (recursive major-type-6 rejection, §6.3) | 5 | PASS |
| `content_hash.*` | 4 | PASS |
| `peer_id.*` | 3 | PASS |
| `signature.*` (RFC-8032 Ed25519) | 3 | PASS |
| `envelope.*` | 2 | PASS |

The independent oracle diff (`tools/oracle-diff.sh`) confirmed this peer's `EmitCanonical`
byte-identical to Go's `emit-canonical` under a shared `impl` identity (SHA-256
`01b8aa07…`). Full codec detail: PHASE-S2.md.

---

## Provenance

- Oracle: `output/s4-oracles/PROVENANCE.txt` (ref `e8524ed`, core_gate_sha256
  `e09a865…`).
- Raw oracle output: `status/CONFORMANCE-REPORT.json` (665 checks).
- Harnesses: `run-s4.sh` (core gate), `run-origination-core.sh` (§10.2 reference-peer-gated).
