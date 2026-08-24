# Phase S5 — Publish (entity-core-protocol-unison)

**Phase:** S5 (release readiness) · **Status:** COMPLETE · **Version:** `0.1.0-pre`
· **Spec:** Entity Core v0.8.0 (V8) · **Oracle:** `cc1970f`

S5 was executed **directly by the overseer, with no container runs** — every artifact is
text. This was deliberate: the host suffered two unclean lockups during S4 that correlate
with sustained Unison container load (see "Host-stability note" below), so the phase was
scoped to work that requires no compute.

## Release-readiness checklist

| Item | State |
|---|---|
| `README.md` | ✅ written — what it is, build/test, running a peer, known gaps, honesty statement |
| `CHANGELOG.md` | ✅ `0.1.0-pre`, spec-version pinned to v0.8.0, oracle pinned to `cc1970f` |
| `LICENSE` | ✅ Apache-2.0 (per `[license] generated_outputs`; Unison's own MIT does not bind us) |
| Conformance badge | ✅ in README, links to `status/CONFORMANCE-REPORT.md` |
| `CONFORMANCE-MATRIX.md` row | ✅ added to both tables (primary + capability/idiom) |
| Package metadata | ⚠️ **N/A by substrate** — see below |
| CI config | ⚠️ **deferred** — see below |
| Ambiguity log finalized | ✅ every entry resolved or escalated with a named owner |
| **No green report → no publish** | ✅ gate is green and reproduced: `682·0F @ cc1970f` |

## Packaging — N/A by substrate, not skipped

Unison has no manifest file. There is no `.cabal`, `Cargo.toml`, or `package.json`
equivalent: code lives in a **content-addressed codebase**, and "packaging" means either a
`ucm push` to Unison Share or a compiled `.uc` plus a codebase export. The profile records
this (`pack_command`, `registry = "unison-share"`).

**Registry publish is deferred**, consistent with the rest of the cohort (Tcl, Rexx,
Forth, Smalltalk, Fortran, APL, Julia and Nim all ship `0.1.0-pre` with registry publish
deferred). Publishing is an operator decision after review, and `/entity-rosetta` never
publishes.

The reproducible artifact is the repo itself: `src/*.u` plus the committed transcripts
regenerate the codebase deterministically from a fresh container.

## CI — deferred, with the reason recorded

No `.github/workflows/unison.yml` is authored. The honest reason is not "forgot": a CI job
would run the S4 harness, and the pure-Unison Ed25519 keygen is CPU-intensive enough that
it saturates a core for minutes per run. Given the host-stability incidents below, adding
an automated recurring job that does exactly the thing under suspicion would be the wrong
move. The harnesses (`run-s4.sh`, `run-origination-core.sh`) are CI-shaped and can be
wired up in one step once the substrate question is settled.

**This is a tracked gap, not a silent omission.**

## Version-pin discipline

- Library version: **`0.1.0-pre`**. Promotion to `0.1.0` requires (a) S4 green — met — and
  (b) at least one external consumer confirming the peer. (b) is unmet, so the version
  stays `-pre`.
- Spec version: tracked literally in `CHANGELOG.md` (`0.1.0-pre tracks Entity Core v0.8.0`).
- Oracle: `cc1970f`, **not re-pinned** for this peer. Measured at the same pin the whole
  cohort is certified at, so the number is cohort-comparable.
- Toolchain: UCM `release/1.3.0` (published 2026-05-20, ~60 days old at authoring — clears
  the ≥30-day supply-chain cool-down), sha256-pinned fail-closed in the Containerfile.

## Ambiguity-log final state

16 entries (`A-UN-001` … `A-UN-016`), all closed or escalated with an owner:

- **→ architecture (spec-shaped, 2):** `A-UN-015` (§3013 `peer_pattern` enumeration
  contradicts v7.65 §3.6 rule 3 — implementing §3013 literally fails `PEER-PATTERN-2`);
  `A-UN-016` (unsupported-key_type check ordering vs the identity binding is unstated;
  natural implementation returns `401 identity_mismatch` where `AGILITY-UNKNOWN-1` wants
  `400 unsupported_key_type`, and it forces a Base58 decoder into every peer).
- **→ research (cohort ledger):** `A-UN-001`/`A-UN-009` (the no-C-FFI crypto-spectrum
  position and its consequence — hand-rolled keygen), `A-UN-004` (abilities as a §7b
  store-safety shape), `A-UN-006` (headless content-addressed-codebase build model).
- **→ operator (local decisions):** the remainder, all resolved.

No blocking-severity item is open.

## Deliberate non-claims

Recorded so a future reader does not over-read this peer's result:

1. **Ed448 / SHA-384 agility deferred** — not a UCM builtin, no C-FFI hatch. Core crypto
   floor is native.
2. **§4.10(c) connection admission not implemented** (SHOULD) — `r3_connection_flood`
   WARNs, matching the Go reference.
3. **The peer-side multisig accept unit is UNVERIFIED** — authored, never run green (a
   Unison *parse* error in the test source, not a peer defect). The accept path is carried
   by the oracle's own `valid_2of3_peer_signed_accepted`, which was a hard FAIL before
   K-of-N landed and passes after. Tracked as open; do not cite leg 2 as evidence.
4. **Cohort-consistent, not independent convergence** (ADR-0012).

## Host-stability note (why this phase was container-free)

During S4 the host suffered **two unclean lockups** (boots ending 16:34 and 18:09 on
2026-07-19) after **nine days of continuous stability** under heavy podman use (36,839
podman/libpod log lines in the stable boot, zero crashes). In both crash boots
`unison-toolchain` was the **most-run image**, and the image did not exist before 13:56
that day. No OOM, no panic, no thermal or MCE entry was logged — which is uninformative
rather than exculpatory, since a hard lockup or power cut flushes nothing to disk.

Observed mechanism: the pure-Unison Ed25519 keygen pegs a core at ~99.7% for 5+ minute
stretches, and containers were running uncapped in ad-hoc invocations. Mitigation applied:
podman-level enforcement via `~/.config/containers/containers.conf` (`cpu.max` 2 CPUs,
`memory.max` 2 GiB, `memory.swap.max` 0, `pids_limit` 1024) — defaults that bind on every
container regardless of caller flags, verified empirically on a flagless run.

**This is a correlation, not a proven cause.** It is recorded here because it materially
shaped the phase and because it is a real hazard for anyone rebuilding this peer.

## Operator handoff

Ready for review. Remaining operator decisions:

1. Whether to publish to Unison Share (deferred by default, cohort-consistent).
2. Whether to wire CI, given the CPU-cost caveat above.
3. Whether to fix and run the multisig unit (non-gating).
4. Route `A-UN-015` / `A-UN-016` to architecture via `research/stewardship/`.
