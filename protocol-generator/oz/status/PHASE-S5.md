# PHASE-S5 — close-out — entity-core-protocol-oz

**Date:** 2026-07-15. **Verdict: COMPLETE — release-ready (v0.1.0-pre).**

## Release-readiness checklist

| Item | State |
|---|---|
| S2 codec 71/71 | ✅ `make s2` |
| S4 `--profile core` 0 FAIL @ cc1970f | ✅ `682 · 285P/301W/0F/96S` |
| Origination-core 3/3 | ✅ `run-origination-core.sh` |
| Multisig ACCEPT-path unit test | ✅ `make multisig-accept` |
| README | ✅ `protocol-generator/oz/README.md` |
| LICENSE | Apache-2.0 (repo `LICENSE`; bundled by `make dist`) |
| Toolchain image + baked GO-gate | ✅ `containers/mozart-toolchain/` |
| Ambiguity log finalized | ✅ A-OZ-001…007, all 🟢 |
| Packaging | `make dist` → source tarball (.oz tree + daemon recipe + run scripts) |

## What ships

A full core-protocol peer for **Oz 3 / Mozart 2.0.1** — the fourth structural §7b
concurrency shape (**dataflow variables**). Native `Open.socket` transport;
hand-rolled canonical ECF in pure Oz (bignum ints; IEEE floats as pure-integer bit
patterns, A-OZ-002); crypto/clock/entropy via the `entity-codec-daemon` co-process
over `Open.pipe` (the reusable seam convention, `src/daemon/DAEMON-PROTOCOL.md`).

No package registry exists for Oz (MOGUL defunct) — distribution is a git tag +
source tarball. `libentitycore_codec` is a documented runtime dependency (the daemon
links it), not bundled.

## Publishing

`/entity-rosetta` does not publish. Operator step after review: tag a release with
the `.oz` tree + `src/daemon/eccodecd.c` + `DAEMON-PROTOCOL.md` + run scripts.

## Handoff

The peer resumes from these status files + `profile.toml` + the pinned toolchain
image. The distinct §7b payoff (dataflow-variable §6.11 demux, no correlation pump)
is recorded in A-OZ-006 for `research/SUBSTRATE-TAKEAWAYS.md`; the `"" == nil`
list-substrate lesson in A-OZ-005. Neither is arch-blocking.
