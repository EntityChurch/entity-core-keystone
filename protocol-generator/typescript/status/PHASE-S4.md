# entity-core-protocol-typescript — Phase S4 Summary

**Phase:** S4 — conformance (`validate-peer --profile core`)
**Outcome:** 🟢 **PASS, first run, zero code fixes.** The second generated peer
reaches the same machine verdict the C# reference reached —
`552 total · 269 pass · 194 warn · 0 fail · 89 skip` — on the very first
validate-peer run. Iteration count: **0 fix cycles.**

## The verdict

```
Oracle:   entity-core-go HEAD cb54f5b  (v7.72 §9.0 core-profile; post F21/F22 oracle fixes)
Spec-data: v7.72
Peer:     node dist/test/host.js --port 7777 --debug-open-grants   (node24, --network=none)

Summary: 552 total, 269 passed, 194 warned, 0 failed, 89 skipped (elapsed 1.241s)
         89 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out
Result: PASS (with warnings)
```

JSON `summary.failed == 0` (verified). Per-category table + warn/skip breakdown in
`CONFORMANCE-REPORT.md`.

## What this phase built (the only new surface)

The peer machinery was already complete and smoke-green at S3; S4 added **no peer
logic**, only the conformance scaffolding:

1. **`test/host.ts`** — the standalone peer host (twin of C#'s
   `EntityCore.Protocol.Host`): `--port N`, `--debug-open-grants`, a single
   `LISTENING …` readiness line, graceful SIGINT/SIGTERM → `peer.dispose()`.
2. **`run-s4.sh`** — the in-container harness: builds offline, launches the host,
   waits for `LISTENING`, points `validate-peer` at it, tears down. The Go oracle is
   a fedora:43 ELF that runs inside the `node24` container, so oracle + peer share
   one loopback — no `--network host`, no second container, stays sealed-offline.
3. **`test/type-registry.test.ts` (A-006)** — the type-registry byte-diff (below).

## A-006 — the one precursor, closed before the live run

The 53-type `CoreTypeRegistry` renders natively (single source of truth in code) and
seeds at `system/type/*`, but S3 never byte-checked it. `test/type-registry.test.ts`
renders all 53 and diffs each `content_hash` against the Go-rendered
`type-registry-vectors-v1.cbor` → **53/53 byte-identical, first run.** A byte-equal
content_hash is a hard equality: the TS ECF render of every core type's data is
byte-for-byte the Go render. This is what then made the live `type_system` category
land 108 pass / 0 core fail with no surprises. Full `node:test` suite **55/55**, no
regression on the S2 codec gate (54 prior + A-006).

## Per-category read (all core checks green)

| Category | P/total | Status |
|---|---|---|
| connectivity | 22/22 | ✅ (F12 nonce-echo PoP, ported) |
| encoding | 6/6 | ✅ |
| type_system | 108/302 | ✅ core green (194 warn = non-§9.5-floor types, 0 core fail) |
| handlers | 25/57 | ✅ core green (32 skip = extension ops) |
| capability | 12/12 | ✅ |
| tree_operations | 25/56 | ✅ core green (31 skip = EXTENSION-TREE §9) |
| security | 22/23 | ✅ (1 skip = extension scope) |
| multisig | 10/10 | ✅ |
| universal_address_space | 8/8 | ✅ |
| peer_canonicalization | 7/7 | ✅ |
| format_agility | 10/10 | ✅ |
| crypto_agility | 4/4 | ✅ |
| negotiation | 4/4 | ✅ |
| authz | 6/8 | ✅ core green (2 skip = ROLE §5.5 extension) |
| origination | (skip) | outside `--profile core` — see A-009 below |

**194 warns** are 100% in `type_system`: the matched-if-present non-floor type
vocabulary, non-blocking by §9.5 design. **89 skips** are all §9.0 extension
carve-outs (auto-allowlisted, exempt from the FAIL gate).

## Findings

- **A-009 (new) — `origination` is outside `--profile core`.** The lifecycle
  `PHASE-S4-CONFORMANCE.md` lists origination as "extension-free, required for v0.1";
  the authoritative v7.72 §9.0 oracle auto-allowlists it as "extension-only category."
  Exercised under the *full* profile with the Go `entity-peer` as `-reference-peer`:
  `reference_connect` + `reference_ready` **PASS** (TS outbound dispatch to a foreign
  peer works), the 3 fails are pure extension over-demand (`async_202_A` = ASYNC §1
  `deliver_to`/202; `rexec_put_b` + `xsub_setup_transport` = NETWORK §10 + a cross-peer
  cap the harness never grants). The peer is correct; the lifecycle doc row is stale.
  → research → arch (reconcile the lifecycle doc with v7.72 §9.0).
- **No new spec ambiguity surfaced.** Consistent with S3 (faithful peer#1→peer#2
  derivation): the carried findings F12/F17/F18/F19/F20 all resolved exactly as in C#,
  and the only doc-vs-oracle gap (A-009) is in the keystone's own lifecycle doc, not V7.

## Carried scars from peer #1 (all landed clean, no re-derivation)

- **F12** nonce-echo PoP — already implemented at S3; connectivity 22/22.
- **F17** type_system extension over-demand → the 194 warns / non-floor split.
- **F18** core-vs-extension scoping → the 89 §9.0 skips.
- **F20** request-time auth-class sig failure is **401**, not 403 → authz green.

## Standards honored

- **S1** every build + the live oracle run in `entity-core-keystone/node24`, sealed
  offline (`--network=none`). No host writes outside the working tree.
- **S5** no doctored oracles: the verdict is the raw `validate-peer` JSON; the one
  category that skips (origination) skips because the *oracle* allowlists it, and we
  proved the underlying behavior works under the full profile rather than hiding it.
- **S7** both bars green: codec byte-identical (69/69) + full peer core PASS.
- **S8** convergence: peer #2, structurally different runtime, reaches the identical
  oracle fixed point as peer #1 — the reproducibility contract is the verdict, not the
  source.

## Phase exit

All required core categories `PASS`; conformance report finalized; A-006 closed,
A-009 logged + escalated. **S4 complete.** Next: S5 (publish) — README, license,
package metadata, CI in Podman, version-pins; resolve A-002 (npm scope) and the
profile `cbor_library` field note (A-005).
