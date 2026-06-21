# entity-core-protocol-cpp — Phase S4 (Conformance) Summary

**Release "reach" peer** (C++23) · **Status: COMPLETE — `validate-peer
--profile core` → 665 total · 0 FAIL · Result: PASS** on the v7.77 oracle (`e8524ed`, core_gate
`e09a865f…`). §10.1 register **10/10**, §10.2 origination-core **3/3** (incl
`dispatch_outbound_reentry`), multisig **11/11** (incl `valid_2of3_peer_signed_accepted` genuinely
running, **0 skip**), concurrency **5/5**, resource_bounds r1/r2 PASS + r3 WARN.

## The gate (binary): `validate-peer --profile core` → 0 FAIL

| Metric | Value |
|---|---|
| Oracle | `validate-peer` from `entity-core-go @ e8524ed` (v7.77 line; pinned by `tools/oracle-pin.env`) |
| core_gate_sha256 | `e09a865ffea690ce207149eb68851f7afbc2fa3a9ba522a0ca9d9c72f9923308` — **matches the committed pin** (mirror-stable: core surface == the 17-peer cohort's) |
| **Summary** | **665 total · 292 passed · 278 warned · 0 FAIL · 95 skipped** |
| **Result** | **PASS** (with warnings) |

665 total · 0 FAIL is exactly the current cohort floor on `e8524ed`/v7.77. The 278 warns are the
non-§9.5-floor type vocabulary (matched-if-present, non-blocking); the 95 skips are the §9.0
extension carve-outs (auto-allowlisted, exempt from the FAIL gate).

## The named gate checks (RELEASE-READINESS §4)

| Gate | Result |
|---|---|
| **§10.1 core-register gate** | **10/10** — `core_register_{body_binding, op_status, op_result, manifest_at_path, handler_at_path, grant_at_path, grant_signature_at_invariant_path, unregister_status, unregister_signature_removed}` + `validate_echo_dispatch` all PASS |
| **§10.2 origination-core** (reference-peer-gated, `run-origination-core.sh`) | **3/3** — `reference_connect` · `reference_ready` · **`dispatch_outbound_reentry`** PASS over real two-peer TCP (validator-as-B over the same inbound connection; Go `entity-peer --open-access` reference on :7778) |
| **multisig** | **11/11, 0 skip** — incl **`valid_2of3_peer_signed_accepted` PASS** (genuinely RUNS: the `--name conformance` persistent identity lets the validator co-sign AS the peer; the peer verifies the §3.6 M3/M4/M6 quorum → 200). The other 10 are the rejection battery. |
| **concurrency** (§7b) | **5/5** — `t1_1_concurrent_demux` · `t1_2_concurrent_reentry` · `t1_3_no_head_of_line` · `t2_1_sustained_load` · `t2_2_connection_churn` |
| **resource_bounds** (§4.10) | r1 payload→`413` (MUST) **PASS** · r2 chain-depth→`400 chain_depth_exceeded` (MUST) **PASS** · r3 connection-flood **WARN** (§4.10(c) SHOULD, admission delegated externally — not gated) |
| `register` (§10.1 §register 10/10 in --profile core) | covered above; the 2 `type_system_registry_register_*` WARNs are non-floor type vocabulary, non-blocking |

## The one genuine peer bug S4 surfaced (and fixed) — A-CPP-014

First run had **1 FAIL**: `tree_operations / core_tree_path_flex_1` — the peer accepted a resource
target with an embedded NUL (`…/path-flex/with\x00null`) → 200 instead of `400 invalid_path`.

Root cause: `path_flex_ok()` (`src/dispatch.cpp`) detected an embedded NUL by comparing
`raw_len != target.size()`, but `exec_resource_target()` materializes the target as
`std::string(ptr, size)` from the length-prefixed wire text — the NUL survives into the
`std::string` and `target.size()` counts it, so the comparison was **never true**. The smoke harness
never sends a control-byte path, so S3 didn't catch it — exactly the kind of corner validate-peer
exists to surface (S5: fix the code, not the oracle).

**Fix:** `path_flex_ok()` now scans the bytes directly and rejects any control byte (`< 0x20`, incl.
NUL, plus `0x7f`) in any segment (the §1.4 R1 reading the C# pathfinder took). → `core_tree_path_flex_1`
PASS, full re-run **0 FAIL**, no regression (codec 69/69, smoke 13/13, typereg 53/53, multisig 9/9
all green on g++ AND clang++; the host builds `-Werror -pedantic` on both compilers).

## What was built this phase (S4 scaffolding — no protocol logic)

| File | Purpose |
|---|---|
| `test/host.cpp` | the standalone conformance host: `--port` / `--name NAME` / `--debug-open-grants` / `--validate`; prints `LISTENING 127.0.0.1:<port> <peer_id>` then blocks. `--name` loads the Ed25519 seed from `~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed; `sodium_base642bin`). Built sanitizer-free (the smoke target carries the sanitized coverage). |
| `CMakeLists.txt` | `host` target added (no sanitizers; not a CTest target — launched by the run scripts). |
| `run-s4.sh` | the C++ S4 harness: builds `host` offline in the `cpp-toolchain` image, provisions `~/.entity/peers/conformance/keypair` (seed `0x11`×32 → peer_id `2KHoAk…`), starts `host --port 7777 --name conformance --debug-open-grants --validate`, points `validate-peer -profile core` at it. `--network=none` (sealed offline; oracle ELF + peer share one loopback). |
| `run-origination-core.sh` | the §10.2 probe: Go `entity-peer --open-access` reference on :7778 + the C++ `host --validate` (A-role) on :7777; `validate-peer -reference-peer … -category origination`. |

The one code change is `src/dispatch.cpp` `path_flex_ok` (A-CPP-014). The peer source is otherwise the
S3 build (the reentry transport + §7a conformance handlers were already in place — no from-zero S4
transport rewrite, the trap OCaml/COBOL hit).

## Exact reproduction (orchestrator re-verify)

```bash
# from the worktree root (cd [internal]/projects/keystone-worktrees/cpp):
GO_REPO=~/projects/[internal]/[internal]/entity-core-go tools/oracle-bootstrap.sh
# -> builds output/s4-oracles/{validate-peer,entity-peer}; confirm core_gate_sha256 == oracle-pin.env

# the gate (665 total, 0 FAIL):
podman run --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/cpp-toolchain:latest \
  sh -c 'sh /work/protocol-generator/cpp/run-s4.sh'

# §10.2 origination-core (3/3 incl dispatch_outbound_reentry):
podman run --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/cpp-toolchain:latest \
  sh -c 'sh /work/protocol-generator/cpp/run-origination-core.sh'
```

`NOBUILD=1` reuses `build-s4/` across runs; `VALIDATE=0` exercises the §7a honest-SKIP path.

## Phase exit

`validate-peer --profile core` → **665 / 0 FAIL / PASS**; §10.1 10/10; §10.2 3/3 incl
`dispatch_outbound_reentry`; multisig 11/11 (genuine accept, 0 skip); concurrency 5/5;
resource_bounds green. Sibling go tree (`entity-core-go @ 71b6ba8`) untouched — clean, read-only
confinement honored. One peer bug found + fixed (A-CPP-014); no new spec defect. Code uncommitted for
orchestrator review (S5 packaging is the next phase, NOT done here).
