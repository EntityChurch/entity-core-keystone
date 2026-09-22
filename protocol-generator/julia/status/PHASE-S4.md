# entity-core-protocol-julia — Phase S4 (Conformance) Summary

**Peer** (Julia, Tier-3 corroboration / generator-robustness — single-threaded Task
scheduler, multiple-dispatch codec, store-based handler resolution) ·
**Status: COMPLETE — `validate-peer --profile core` = PASS, 0 FAIL.**

```
682·0F @ cc1970f   P 292 · W 294 · F 0 · S 96      (oracle fingerprint 8261a033…)
```

## What S4 built (on the S3 machinery)

The S3 peer resolved handlers over an in-memory `Dict{String,Function}` with all bodies
returning `501 no_handler_body`. S4 replaced that with the proven **store-based** design (a
faithful port of the settled Zig peer onto Julia's substrate):

| Module | S4 work |
|---|---|
| `typedefs.jl` | **NEW.** The 53-type §9.5 core floor rendered natively (multiple-dispatch over the peer's own field-spec model + omit-empty), published at `/{peer}/system/type/<name>`. **53/53 byte-identical** to `type-registry-vectors.cbor` (test/typedefs_bytecheck.jl). |
| `capability.jl` | **NEW.** Full §5.2 `verify_request` (4-way §5.2a verdict), §5.4 pattern matching, §5.5 multi-link chain-walk + §5.6 attenuation + §5.7 caveats, §5.1 revocation, §4.10(b) chain-depth pre-check, and the §3.6 M3 K-of-N multi-signature root (M3 structure → M4 quorum → M6 root-at-local). |
| `store.jl` | Tree ops added: `store_bind!` / `store_unbind!` / `store_hash_at` / `store_listing` (directory-style child listing with deletion-marker tombstones). |
| `peer.jl` | **Rewritten.** Store bootstrap (types + 5 MUST handlers + §7a validate handlers + §6.9a owner cap & default policy), §6.5 dispatch chain (ingest signatures → verify_request → resolve → check_permission → body), and all core handler bodies: **tree** (get/put/list, mode=hash, §3.9 CAS), **capability** (request/delegate/revoke/configure with §6.2 subset-validation → `403 scope_exceeds_authority`), **handler** (register/unregister + §10.1 entity-native round-trip), **type** (bootstrap-only), **validate** (echo + dispatch-outbound). |
| `bin/peer.jl` | `--debug-open-grants` now wired to the degenerate `default→*` seed policy (was ignored). |

## Gate results

- **`validate-peer --profile core` → PASS, 0 FAIL.** 292 P / 294 W / 0 F / 96 S. All 294
  WARN are `type_system` non-floor vocabulary (matched-if-present). All 96 skips are §9.0
  extension carve-outs, auto-allowlisted — **bisected in CONFORMANCE-REPORT.md, none masks a
  core primitive** (multisig / type_system / capability / concurrency / resource_bounds have
  0 skips).
- **Multisig accept-path (non-vacuous):** live `valid_2of3_peer_signed_accepted` PASS +
  peer-side `test/multisig_accept.jl` **8/8** (ALLOW + M3/M4/M6 deny flips).
- **Origination-core:** `run-origination-core.sh` vs the Go `entity-peer` → **3/3 PASS**
  incl. `dispatch_outbound_reentry` (§6.11 reentry live from the coroutine idiom). Single-peer
  `run-s4.sh` honest-SKIPs it (extension-only under core).
- **Regressions:** S3 smoke still 6/6; S2 codec 71/71; type registry 53/53.

## Iteration count

Two oracle runs. Run 1: 1 FAIL (`format_agility.agility_unknown_1` — an unsupported
`key_type=0xFD` at authenticate returned `401 identity_mismatch`; AGILITY-UNKNOWN-1 wants
`400 unsupported_key_type`). Fix: check the claimed peer_id's key_type prefix (varint) and
reject a non-`0x01` prefix with 400 before the identity-binding check (matches the cohort).
Run 2: **PASS, 0 FAIL.**

## Ambiguity log

- **A-JULIA-010** (S3 single-link root cap) — **RESOLVED**: multi-link chain-walk +
  attenuation + `check_permission` scope + §4.10(b) chain-depth pre-check now implemented in
  `capability.jl`; oracle `capability`/`authz`/`security` categories green.
- **A-JULIA-011** (413-before-buffering vs request_id correlation) — **RESOLVED as
  cohort-settled**: the oracle's `resource_bounds.r1` accepts *connection close without a
  response frame* on the over-large length prefix ("wrote 16778240-byte length prefix;
  connection closed without a response frame → PASS"). Close-without-correlated-413 is
  conformant on a length-prefixed transport, exactly as flagged. No arch escalation needed.
- No new blocking items. One provenance note added (A-JULIA-012, format-agility key_type
  prefix).

## Deliverables

`src/{typedefs,capability}.jl` (new) · `src/{peer,store}.jl` (extended) · `bin/peer.jl` ·
`run-s4.sh` · `run-origination-core.sh` · `test/{multisig_accept,typedefs_bytecheck}.jl` ·
`status/CONFORMANCE-REPORT.{md,json}` · this file · `SPEC-AMBIGUITY-LOG.md`.

## Exit criteria

`validate-peer --profile core` PASS / 0 FAIL @ cc1970f · every skip a bisected §9.0 carve-out
· multisig accept-path non-vacuous (live + unit) · origination-core 3/3 vs reference · type
registry 53/53 · S3 smoke + S2 codec regression-free · container reproducible + offline
(`--network=none`, capped). **S4 PASS.**
