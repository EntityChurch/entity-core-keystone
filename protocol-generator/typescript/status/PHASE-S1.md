# Phase S1 — TypeScript profile · summary

**Peer:** #2 · **Spec:** v7.72 · **Profile:** `core`

## Status: COMPLETE (A-001 resolved — crypto = @noble, lean browser-compatible)

Phase exit criteria (per `lifecycle/PHASE-S1-PROFILE.md`):
- [x] `profile.toml` — every field populated; no `"TBD"` blocking values (open items are non-blocking A-NNN)
- [x] `arch/PROFILE-RATIONALE.md` — written
- [x] `status/SPEC-AMBIGUITY-LOG.md` — initialized; 4 non-blocking profile decisions logged
- [x] container specified — `containers/node24/Containerfile` (offline two-phase)
- [x] no blocking-severity ambiguity items

## Decisions (detail in PROFILE-RATIONALE.md)
- **Codec:** native (cborg + @noble), no FFI on critical path.
- **CBOR:** `cborg` 5.1.1 — deterministic-first; length-first map sort + tag-reject defaults favor ECF.
- **Crypto:** `@noble/curves` 2.2.0 (Ed25519 + **Ed448** from one pure-JS package) + `@noble/hashes` 2.2.0 (SHA-2, audited). **Browser-portable** (A-001 resolved: lean browser-compatible). One package spans the agility seam (vs C#'s NSec+BouncyCastle). `node:crypto` is the Node-only zero-dep alt behind the seam.
- **Base58:** hand-rolled → runtime tree = **3 zero-transitive packages** (cborg + @noble/curves + @noble/hashes).
- **Integers:** always-`bigint` (R1; collides with F7 — own vectors required).
- **Runtime:** Node 24 LTS (Node 20 EOL; stub retired). **Test:** `node:test` (zero deps). **Module:** ESM-only.
- **Container:** pull-once-then-offline network lockdown (S11 + user requirement).

## Load-bearing risks (full analysis in research/evaluations/typescript.md)
- **R1 (HIGH)** — BigInt integer surface; collides with **F7**. The defining TS risk.
- **R2 (HIGH)** — raw-byte entity-data fidelity (N4); never decode→re-encode on hash path.
- **R3 (MED)** — verify cborg map-sort byte-exact + add decode-side float-minimality check.
- **R4 (LOW)** — tag reject (mostly free via cborg default).
- **R5 (MED)** — zero-hash sentinels on decode.
- **R6 (LOW)** — raw-key handling; resolved by @noble (raw bytes, no DER). Only relevant if switched to node:crypto.

## Next phase
S2 codec — `/entity-rosetta typescript --phase codec`. First moves: stand up `containers/node24/`, run the cborg map_keys/float spike, build the bigint-backed canonical value model + the >i64max vector set.
