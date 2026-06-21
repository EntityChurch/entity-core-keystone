# entity-core-protocol-python — Conformance Report (S4 + S3 + S2)

> **S5 (publish) stamp.** Final release: version **`0.1.0`** /
> Apache-2.0 / dist `entity-core-protocol-python` / import `entity_core`. Wheel +
> sdist build clean in the `python-toolchain` image (hatchling backend);
> `entity_core` + `entity_core.peer` import from the **installed wheel** (not src/),
> console-script `entity-core-peer` registered, `Requires-Dist: cryptography==48.0.0`
> (dev tools gated behind the `dev` extra), `Requires-Python >=3.9`. **Codec gate
> re-ran GREEN at S5: 69/69 PASS, 0 FAIL** (stdlib zero-dep runner, sealed-offline).
> No conformance change — the S4 figure below stands. Not published (operator action
> deferred; see `PHASE-S5.md`).
>
> **S4 (conformance) gate — branch `lang/python`.** `validate-peer
> --profile core` against the Go oracle pinned at **`e8524ed`** points at the live
> Python host (`python -m entity_core.host`, port 7778, sealed-offline
> `--network=none`). **`Result: PASS` — machine-verified `summary.failed == 0`.**
>
> ```
> validate-peer --profile core  (oracle entity-core-go e8524ed, peer @ 127.0.0.1:7778)
> → 665 total · 292 pass · 268 warn · 0 FAIL · 93 skip · Result: PASS (with warnings)
>   recorded figure: 665 · 0F @ e8524ed  (both verified: failed==0 AND total==665)
> ```
>
> All **16 core-profile categories 0-FAIL**: connectivity 22/0F, encoding 6/0F,
> type_system 108p/262w/0F, handlers 35p/32skip/0F (incl. §10.1 register 10/10 —
> the `core_register_*` checks all PASS), capability 12/0F, tree_operations
> 24p/1w/0F, security 28/0F, **multisig 11/11 · 0 skip** (incl.
> `valid_2of3_peer_signed_accepted` PASS — the oracle co-signs AS the peer using
> the on-disk `conformance` keypair, seed `0x11`×32 → peer_id `2KHoAk…`),
> universal_address_space 8/0F, peer_canonicalization 7/0F, format_agility 10/0F,
> crypto_agility 4/0F, negotiation 4/0F, authz 6p/2skip/0F, **concurrency 5/5 · 0F**
> (§7b store-safety + T2.1/T2.2 resilience), **resource_bounds 2p/1w/0F** (r1
> payload→413 MUST PASS, r2 chain-depth→400 chain_depth_exceeded MUST PASS, r3
> conn-flood→WARN SHOULD).
>
> The 93 skips are §9.0 profile carve-out auto-allowlists (extension-only
> categories), exempt from the FAIL gate. The 268 warns are non-§9.5-floor type
> vocabulary (matched-if-present) + the r3 SHOULD. **origination-core 3/3** —
> reference-peer-gated, run via `./run-origination-core.sh`: `reference_connect`,
> `reference_ready`, and `dispatch_outbound_reentry` (§6.11 reentry over real
> two-peer TCP, validator-as-B over the inbound connection) all PASS.
>
> **One peer fix this phase** (iteration 1→2): the `authenticate` handler now
> parses the claimed `peer_id` and rejects a non-Ed25519 embedded `key_type` (e.g.
> the unknown `0xFD`) with **`400 unsupported_key_type`** BEFORE the identity
> binding (§4.6 / §7.1; AGILITY-UNKNOWN-1) — it previously fell through to `401
> identity_mismatch`. No oracle results doctored (that is S5). Reproduce:
> `./run-s4.sh` and `./run-origination-core.sh` from `protocol-generator/python`.
> Detail of the S3 + S2 gates below.

---

# entity-core-protocol-python — Conformance Report (S2 codec + S3 peer)

> **S3 (peer machinery) gate — branch `lang/python`.** Built the live
> peer on the S2 codec; the S3 gate is GREEN. Detail below the S2 section.
>
> ```
> S3 peer gate (offline, python-toolchain image):
>   two-peer LOOPBACK over real TCP ....... 11/11 checks PASS (2 scenarios)
>   type-registry byte-identical .......... 53/53 §9.5 floor types PASS
>   §3.6 multisig ACCEPT-path unit test ... 7/7 PASS (2-of-3 ALLOW + M3/M4/M6
>                                           deny flips + single-sig superset)
>   S2 wire-conformance (regression) ...... 69/69 PASS, 0 FAIL (unchanged)
> ```
>
> Peer surfaces wired: TCP transport (length-prefixed §1.6, TCP_NODELAY,
> thread-per-connection + Condition reader-demux, request_id correlation, §4.10(a)
> 413-before-buffer) · Lock-guarded store (§4.8; explicit Lock — the GIL is NOT
> compound-atomic) · type registry + §6.6 dispatch · §5.5 chain-walk + attenuation
> + §4.10(b) 400 chain_depth_exceeded structural pre-check + §5.2 verdict
> trichotomy · genuine §3.6 K-of-N multisig (M3/M4/M6, root-only) · §6.13
> register-live + handler outbound closure (§6.11 reentry) + emit (§6.10) ·
> peer-owner cap + §6.9a seed-policy dual-form read · §7a `system/validate/{echo,
> dispatch-outbound}` (opt-in `--validate`, off by default) · `host.py` CLI
> (`--name` / `--port` / `--validate` / `--seed` / `--debug-open-grants` / `--help`).
>
> `host.py` is the S4 `validate-peer --profile core` target (prints `LISTENING
> <port>`, dials cleanly). No oracle results doctored (that is S5).

---

# entity-core-protocol-python — S2 Wire-Conformance Report

**Phase:** S2 (codec). **Branch:** `lang/python` (worktree).
**Corpus:** `protocol-generator/shared/test-vectors/v7.56/conformance-vectors-v1.cbor`
(fixture `v1`, `ENTITY-CBOR-ENCODING.md` v1.5 Appendix E; SHA `41d68d2d…`).
**Result:** **69 / 69 PASS · 0 FAIL.**

## Gate result

```
wire-conformance (core-python, corpus v1, spec 1.5): 69/69 PASS, 0 FAIL
  float 14/14 · int 14/14 · map_keys 6/6 · length 8/8 · primitive 6/6 ·
  nested 4/4 · tag_reject 5/5 · content_hash 4/4 · peer_id 3/3 ·
  signature 3/3 · envelope 2/2
```

The corpus array holds 69 testable vectors (64 `encode_equal` + 5
`decode_reject`); the manifest's headline "71" counts 2 metadata-agreement
checks that are not array entries. 69/69 is the S7 lower bar and is met.

pytest (`python -m pytest`): **71 passed** (69 per-vector parametrized cases +
`test_no_failures` + `test_full_corpus_count`).

## Per-category coverage

| Category | N | Kind | Notes |
|---|---|---|---|
| `float` | 14 | encode_equal | Rule 4 f16/f32/f64 minimization + Rule 4a specials (NaN/±Inf/±0). |
| `int` | 14 | encode_equal | Major-type-0/1 minimal head at boundaries (0…2⁶³, signed analogs). |
| `map_keys` | 6 | encode_equal | §4.2.1 length-then-lex on ENCODED keys incl. mixed text+byte keys. |
| `length` | 8 | encode_equal | Definite-length only at length boundaries. |
| `primitive` | 6 | encode_equal | bool/null/empty containers/mixed-primitive maps. |
| `nested` | 4 | encode_equal | `included` maps, hash-keyed maps, envelope carrier shape. |
| `tag_reject` | 5 | decode_reject | §6.3 — recursive major-type-6 rejection incl. nested-in-`included` (N2). |
| `content_hash` | 4 | encode_equal | `varint(format_code) ‖ SHA256(ECF({type,data}))`; incl. `format_code=128` (N1). |
| `peer_id` | 3 | encode_equal | `ECF(Base58(varint(kt)‖varint(ht)‖digest))`; incl. `key_type=128` (N1). |
| `signature` | 3 | encode_equal | Deterministic Ed25519 (RFC 8032) over `ECF(entity)`. |
| `envelope` | 2 | encode_equal | `system/envelope/v1` carrier; map-key sort + hash-keyed included. |

Invariant coverage (`conformance-invariants.md`): **N1** synthetic codes ≥`0x80`
routed through real LEB128 varint primitives (`content_hash.4`, `peer_id.3`) —
PASS. **N2** recursive tag-6 reject on decode (`tag_reject.*`) — PASS. **N3**
empty-map = single byte `0xA0` (`content_hash.1` empty-data boundary) — PASS.

## Oracle cross-check (byte-identity)

The cross-blessed corpus `canonical` bytes ARE the conformance contract, but as a
second independent oracle the Go `wire-conformance` reference encoder was run over
the same corpus and diffed:

- **Oracle:** `entity-core-go` `cmd/internal/wire-conformance`, commit **`e8524ed`**
  (impl `core-go`, corpus `v1`, spec `1.5`).
- **Build isolation:** the oracle was vendored with `git archive e8524ed | tar -x`
  into a temp dir **outside** `entity-core-go`; the binary was built and run there
  (go 1.25.9, `GOTOOLCHAIN=local`). The `entity-core-go` tree was confirmed clean
  before AND after — no binaries leaked into the oracle tree (a prior-run hazard).
  The temp dir was removed afterward.
- **Result:** three-way **byte-identity** Python == corpus == Go for all 64
  `encode_equal` vectors, and Go rejected all 5 `decode_reject` vectors. **0
  mismatches across 69 vectors.**

## Crypto / Ed448 agility byte-pin

Beyond the `signature.*` Ed25519 vectors, the Ed448 native path (crypto-agility
higher bar) was byte-verified against the v7.71 agility corpus pin
`KEY-TYPE-ED448-1` (seed `0x42`×57):

- 57-byte public key — **byte-match**.
- 114-byte signature over the fixture message — **byte-match** (deterministic
  RFC 8032 PureEdDSA).
- `verify` round-trip — **OK**.
- Base58 `peer_id` `(key_type=0x02, hash_type=0x01, SHA-256(pubkey))` under the
  §1.5 size-cutoff (pubkey > 32B → SHA-256 digest, not identity-multihash) —
  **byte-match** (`3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4`).

This closes A-PY-002 (native-full-agility, no FFI) at the byte level. The
container build also asserts Ed25519+Ed448 sign/verify/tamper-reject at image-build
time.

## Reproduce

```bash
# Conformance gate (offline; image carries the one pinned runtime dep):
podman run --rm --network=none -v "$PWD:/work:Z" \
  -w /work/protocol-generator/python \
  entity-core-keystone/python-toolchain:latest \
  python3 -c "import sys; sys.path[:0]=['src','.']; \
    from tests.conformance.harness import main; raise SystemExit(main([]))"

# Full pytest (dev deps):
podman run --rm -v "$PWD:/work:Z" -w /work/protocol-generator/python \
  entity-core-keystone/python-toolchain:latest \
  sh -c "pip install -q 'pytest>=8,<9' hatchling editables && \
         pip install -q --no-build-isolation -e . && python -m pytest -q"
```
