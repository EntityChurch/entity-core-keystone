# Finding — 2026-07-12 — frame-only §3.6 multisig in 4 of 5 later-folded peers

**Type:** keystone peer-quality finding (NOT a spec defect; no arch handoff). Records a
masked conformance defect the catch-up backlog surfaced, the fix, and two secondary
language-specific bugs it exposed. Corroborates the durable lesson *"conformance-green can
be vacuous."*

## Summary

The catch-up backlog asked to "verify genuine §3.6 K-of-N multisig on the later-folded
peers (C, Ada, Ruby, Prolog, Go, COBOL) + add accept-path tests." Verifying meant making
the oracle's one **accept-path** probe (`valid_2of3_peer_signed_accepted`) actually RUN — it
had been **SKIPping** on every one of these peers because no peer keypair was provisioned on
disk for the validator to co-sign *as* the peer. That skip was hiding the answer:

**4 of the 5 were FRAME-ONLY.** Ruby, Go, C, and Ada each **rejected a valid co-signed
2-of-3 cap** (`403`/`500`/deny) — their capability verifier only handled a single-`granter`
delegation chain and fell through to deny on a multi-sig root (`granter = {signers,
threshold}` map). The `multisig` oracle category is **reject-dominated** (10 malformed→reject
probes vs 1 accept), so a fail-closed peer that rejects *everything* passed all 10 vacuously.
Only the accept probe could catch it, and it was skipping. Prolog (`verify_multisig_root/4`)
and COBOL were already genuine.

**This is a real 0-FAIL risk, not a cosmetic gap:** the accept-path FAIL *gates* — a SKIP is
auto-allowlisted by the §9.0 carve-out, a FAIL is not. Once the keypair was provisioned, each
frame-only peer's `--profile core` flipped to `Result: FAIL` until fixed.

## Method (reusable)

To exercise the accept-path, the harness must (a) provision the peer's keypair at
`~/.entity/peers/conformance/keypair` (seed `0x11×32`, base64 `ERER…`) so the validator can
scan the peers-dir, match the live peer by `peer_id`, and co-sign as it; and (b) boot the
peer with an identity matching that keypair. The mechanism is the validator's on-disk
keypair scan, **not** the `--name` flag per se ("accept-path requires the peer's on-disk key
(M6 root-at-local): peer keypair not locally available" is the skip reason). Standardizing
`--name` was the clean way to give every peer a matching identity.

## The fix

Genuine §3.6/§5.5 multi-sig root verification, modeled on the genuine Prolog peer
(`multisig_root_ok` / `Multisig_Root_Ok` per language):
- **M3** (structure): root-only (no `parent`), `N ≥ 2`, `2 ≤ threshold ≤ N`, distinct signers.
- **M6**: the local peer is one of the signers.
- **M4**: at least `threshold` DISTINCT signers each carry a valid signature over the root
  content hash.

Result @ oracle `cc1970f`: all four → **682 · 0 FAIL**, `valid_2of3_peer_signed_accepted`
PASS. Ruby + Go carry in-repo unit tests (`test/multisig_test.rb` 5/5, `peer/multisig_test.go`
5/5); C + Ada guard via the now-genuine (non-vacuous) S4 accept-path (their verify entry is
not a cheap in-process hook).

## Secondary finds exposed by making the path run

- **A-ADA-014** (Ada, fixed): the §PR-8 granter-frame fallback `Granter := Local_Peer (Peer)`
  reassigned a 44-char peer_id onto the length-0 `""` that `Resolve_Granter_Peer_Id` returns
  for a multi-sig root → `CONSTRAINT_ERROR` (Ada Strings are fixed-length) → `500`. **Dead
  code that would always have crashed if reached** — never exercised because multisig was
  frame-only (denied before this path). Fixed by computing `Granter` as one
  conditional-expression `constant`. Language-specific, not a spec defect.
- **A-C-011** (C, logged/open): 1 of 3 re-gate runs aborted (SIGABRT) at
  `concurrency.t2_2_connection_churn` cycle ~48 — a pre-existing raw-pthread race (A-C-009
  substrate), unrelated to this change; the other runs were clean 682·0F. Candidate for a §7b
  churn-teardown hardening pass.

## Identity-CLI standardization (the enabling work)

The audit found the CLI deviation was wider than the backlog's framing ("C/Ada lack
`--name`"):
- **Go and Ruby never had `--name`** — only `--seed`. The matrix table 2 had *overclaimed*
  it. (The overclaim is now true — `--name` was added.)
- **Prolog's `--name` was a fake** — parsed into an ignored variable, seed hardcoded `0x11`.
- **Go and Ada defaulted to seed `0x01×32`**, off from the cohort's `0x11×32`.

All five normalized onto the canonical convention (OCaml/Swift/Haskell/COBOL + `AGENTS.md`):
default seed `0x11×32`; `--name NAME` loads the 32-byte seed from
`~/.entity/peers/NAME/keypair` (base64 PEM). Per-language base64: Ruby `unpack1("m")`, Go
`encoding/base64`, C `sodium_base642bin`, Ada + Prolog hand-rolled decoders (both gem/lib-free).

## Per-peer outcome

| Peer | multisig before | `--name` before | Action | After |
|---|---|---|---|---|
| Ruby | frame-only (FAIL) | absent (overclaimed) | impl M3/M4/M6 + `--name` + unit test | 682·0F, accept PASS |
| Go | frame-only (FAIL) | absent (overclaimed) | impl M3/M4/M6 + `--name` + default `0x01`→`0x11` + unit test | 682·0F, accept PASS |
| C | frame-only (FAIL) | absent | impl M3/M4/M6 + `--name` (libsodium b64) | 682·0F, accept PASS (A-C-011 flake) |
| Ada | frame-only (FAIL, 500) | absent | impl M3/M4/M6 + `--name` (hand b64); **fix A-ADA-014** | 682·0F, accept PASS |
| Prolog | genuine (PASS) | fake (ignored) | make `--name` real (hand b64 load) | 682·0F, accept PASS |
| COBOL | genuine (per S4) | real | — (already genuine) | unchanged |

## Durable lessons

1. **"Conformance-green can be vacuous"** — caught red-handed in 4 peers. A rejection-only
   oracle category lets a fail-closed peer pass without implementing the primitive. Always
   drive the accept path.
2. **A "✅verify" flag in a consolidation is a liability, not a status** — it marked
   "multisig code present, genuineness not re-checked," and 4 of 5 turned out defective. Verify
   or don't claim.
3. **Making a skipped path run is high-yield** — it exposed 4 masked multisig defects + 2
   secondary language bugs (A-ADA-014 dead-code crash, A-C-011 race) that no green run showed.
