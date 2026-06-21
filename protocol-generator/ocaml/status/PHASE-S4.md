# entity-core-protocol-ocaml — Phase S4 (Conformance) Summary

**Skill:** `/entity-rosetta ocaml --phase verify`
**Outcome: 🟢 `validate-peer --profile core` PASS — 0 fail, machine-verified.**

## Scoreboard (oracle `output/s4-oracles/validate-peer`, v7.72 §9.0)

```
552 total · 268 passed · 195 warned · 0 FAILED · 89 skipped → PASS
```

The **same conformance fixed-point** the C# (#1, 269/194/0/89) and TS (#2, 269/194/0/89)
peers reached — landed here from a **spec-first distant idiom**. The 1-check delta
(268P/195W vs 269P/194W) is a single non-gating `tree_operations.cleanup` warn
("failed to remove test entity (non-critical)"); 0 fail is the S7 gate.

Run sealed-offline in the `ocaml-toolchain` container (`--network=none`); the Go
`validate-peer` ELF and the OCaml host share one loopback. Harness: `run-s4.sh`.

```
podman run --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/ocaml-toolchain:latest sh /work/protocol-generator/ocaml/run-s4.sh
```

## The grind: 190 → 0 fails

| Fix | Spec | What it unblocked |
|---|---|---|
| peer-id identity-multihash | §1.5 (vs stale §7.4) | connectivity 0→22 (**A-OC-007**) |
| URI `entity://` normalize | §1.4 | type_system + tree + universal-address-space |
| per-request serve-loop isolation | §3.3 | security/multisig/tree (broken-pipe → proper status) |
| authn(401)/authz(403) verdict split | §4.6 / §5.2 | security 6 (**A-OC-008**, corroborates F20) |
| §5.7 delegation caveats | §5.7 | security chain caveats 2 |
| §5.1 revocation marker check | §5.1 | revoked-cap-on-use, authz_revoked |
| deletion-marker listing omit + root listing | §6.3 / §3.9 | tree CORE-TREE-DELETE-1, path_root_listing |
| path-flex validation (abs-path aware) | §1.4 / §9.5a | PATH-FLEX-1 + universal address space 7 |
| capability handler (delegate-parent/501, revoke-zero, configure peer_pattern + lazy-canon) | §6.2 | capability 6 + peer_canonicalization |
| hello negotiation (disjoint hash/key reject) | §4.5 | negotiation 2 |
| AGILITY-UNKNOWN-1 key_type reject (field + pubkey-len + peer_id prefix) | §4.6 / v7.66 | format_agility 1 |
| unresolvable-grantee 401 carve-out (chain-before-mismatch) | §5.2 / PR-3 | authz_grantee 1 |

## Standards honored
- **S1** — all in `ocaml-toolchain`, sealed offline.
- **S5** — raw oracle verdict; the one warn is oracle-marked non-critical, not hidden.
- **S7** — lower bar (codec 69/69) + higher bar (`--profile core` 0 fail) both green.
- **S8** — convergence: a spec-first peer in a distant idiom reaches the same fixed point.

## Carried findings → arch (via stewardship)
A-OC-004 (format_code 128 asymmetry), **A-OC-007** (§7.4/§1.5 peer-id divergence),
**A-OC-008** (§5.2/§4.6 status-split), A-OC-003-revised (eio→threads, operator review).
Bundle them at session close per the operator's "bring them all to architecture" call.

## Not in scope (unchanged)
Ed448 / agility higher-bar (A-OC-002 native gap) · origination (outside `--profile core`,
F23) · `.mli` codec interfaces + packaging (S5).
