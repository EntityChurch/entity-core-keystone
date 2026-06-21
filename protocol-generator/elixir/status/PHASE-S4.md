# entity-core-protocol-elixir — Phase S4 (Conformance) Summary

**Skill:** `/entity-rosetta elixir --phase verify`
**Outcome: 🟢 `validate-peer --profile core` PASS — 0 fail, first run, 0 fixes.**

## Scoreboard (oracle `output/s4-oracles/validate-peer`, go HEAD `9c624aa`, v7.74 §10)

```
568 total · 284 passed · 195 warned · 0 FAILED · 89 skipped → PASS
§10.1 core-register gate   10/10 PASS
§10.2 origination-core      3/3 PASS  (dispatch_outbound_reentry over real TCP)
```

**Identical** to the OCaml fixed-point (#3, 284P/195W/0F/89skip post-v7.74). Peer
#4 reaches it on the **first run with zero fixes** — the opposite of OCaml's
190→0 grind. Elixir ports the §5/§6 surface validated across peers #1–3 and adds
nothing the wire forces differently, so there was no grind to do. This is the
predicted corroboration / generator-robustness result: the BEAM substrate
(`:crypto`, arbitrary-precision ints, actor concurrency) replicates the inherited
findings rather than surfacing new ones.

Run sealed-offline in the `beam` container (`--network=none`); the Go
`validate-peer` ELF and the Elixir escript host share one loopback. Harnesses:
`run-s4.sh` (profile core) + `run-origination-core.sh` (§10.2 reentry).

```
podman run --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/beam:latest sh /work/protocol-generator/elixir/run-s4.sh
podman run --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/beam:latest sh /work/protocol-generator/elixir/run-origination-core.sh
```

## Gate detail

| Gate | Result | Notes |
|---|---|---|
| `--profile core` (14 categories) | 568/284P/195W/**0F**/89skip | category scoreboard matches OCaml exactly |
| §10.1 register (9 `core_register_*` + `validate_echo_dispatch`) | **10/10 PASS** | §3.4 grant-sig at `system/signature/{grant_hash}`; unregister symmetry; A-011 compute-half retired |
| §10.2 origination-core | **3/3 PASS** | `dispatch_outbound_reentry` proves the BEAM process-per-connection §6.11 reentry seam; reference Go peer connected only for input-shape |
| §10.3 drift | n/a per-peer | oracle-side category-list self-check, verified once at keystone signoff |

The 89 SKIPs are V7 v7.72 §9.0 extension-profile carve-outs (auto-allowlisted,
exempt from the FAIL gate); the 195 WARNs are type_system extension-vocab
advertisements (S6 profile-local, not core MUSTs).

## Standards honored
- **S1** — all in the `beam` container, sealed offline.
- **S5** — raw oracle verdict; every SKIP is a §9.0 carve-out or honest
  setup-absence, every PASS against the real go-HEAD oracle. No relaxation,
  no oracle patch.
- **S7** — lower bar (codec 69/69 + agility 35 native) + higher bar
  (`--profile core` 0 fail, incl. §10.1/§10.2) both green.
- **S8** — convergence: a fourth peer on a distant BEAM idiom reaches the same
  conformance fixed-point.

## Spec findings → arch (via stewardship)
**None new at S4.** Corroborates A-OC-007 (§7.4/§1.5 peer-id), A-OC-008
(§5.2/§4.6 401/403), A-011/A-013 (§7a). S3-stage items carry forward: A-ELX-005
(positive root_cap byte-pin), A-ELX-006 (actor-model idiom), A-ELX-007
(emit-delivery async fork — compute-readiness seam). Signed off in the
Elixir peer-4 S4 conformance handoff.

## Not in scope (unchanged)
S5 packaging (Hex/rebar3 docs, `mix hex.build`) — next. Ed448 is **native**
(no FFI, unlike OCaml A-OC-002), already proven at S2/S3.
