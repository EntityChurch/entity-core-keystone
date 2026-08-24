# entity-core-protocol-fortran — Phase S4 summary (COMPLETE)

**Phase:** S4 (conformance — THE gating stage)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/fortran-toolchain:latest` (gfortran 15.2, fedora:43)
**Status:** ✅ **COMPLETE — `Result: PASS`, 682·0F @ cc1970f (292 P / 294 W / 0 F / 96 S).**
Reproduce: `./protocol-generator/fortran/run-s4.sh` (container-bound, sealed-offline
`--network=none`; capped `$PODMAN_RUN_CAPS`). JSON: `status/CONFORMANCE-REPORT.json`.

## Result

`validate-peer --profile core` → **`Result: PASS`, 0 FAIL**, measured against oracle
**`cc1970f`** (core-gate fingerprint `8261a033…`). 96 skips are the §9.0 extension carve-outs,
**auto-allowlisted by the profile** (none gates). See `CONFORMANCE-REPORT.md` for the full
per-category table.

## Iteration count: 3 rounds

- **Round 1 (baseline):** 24 FAIL. Root cause was a **single crash**: the peer terminated
  during the `concurrency` category, so every later category cascaded to `connection
  refused` / `broken pipe`. Only ~4 failures were independent; the rest were downstream of
  the dead listener.
- **Round 2 (crash + reentry fixed):** 3 FAIL — the three real handshake-negotiation gaps.
- **Round 3 (negotiation fixed):** **0 FAIL — PASS.**

## Every FAIL and how it was fixed

1. **The crash — unhandled SIGPIPE (A-FTN-016).** The C net-shim wrote responses with
   `write(2)` and never set a SIGPIPE disposition. When a probe closed its socket mid-exchange
   (the reentry `t1_2` and churn `t2_2` legs do), the next write raised SIGPIPE → **default
   action terminated the process, silently** (empty stderr). **Fix:** `signal(SIGPIPE,
   SIG_IGN)` at listen init + `send(..., MSG_NOSIGNAL)` in the flush path (`src/ext/net_shim.c`).
   This alone cleared the whole downstream cascade.
2. **Serve loop stopped on EV_NONE (A-FTN-017).** `peer_serve` had `case default; exit` for a
   non-event poll result — but a blocking poll's `EV_NONE` also means EINTR/spurious wakeup,
   and the listener is never closed while serving. **Fix:** `cycle` (re-poll) instead of
   `exit` (`src/peer.f90`). Belt-and-suspenders liveness alongside #1.
3. **`concurrency.t1_2_concurrent_reentry` FAIL (503) — dispatch-outbound was a stub
   (A-FTN-018).** S3 shipped `hnd_dispatch_outbound` as an honest `503 no_outbound_seam`.
   This `--validate`-gated probe is a **core** (`concurrency`) check, not origination, so the
   stub was a real gate FAIL. **Fix:** wired the §6.13(b) reentry — the handler builds+signs
   an outbound EXECUTE to `system/handler/{target}` from the params `{target, operation,
   value, reentry_capability, reentry_granter, reentry_cap_signature}`, sends it on the **same
   inbound connection** (`c_io(slot)`), and reentrant-pumps `pump_until` until the reply
   correlates by request_id, returning `{status, result}`. 8-deep nested reentry is safe on
   the one single-thread pump (each level awaits its own `out-N` rid).
4. **`negotiation.format_disjoint_reject` + `keytype_disjoint_reject` FAIL (returned 200).**
   The hello handler never inspected `hash_formats` / `key_types`. **Fix:** added
   `negotiation_disjoint(params, key, supported)` (present-and-disjoint → reject; a
   present-but-empty array rejects, absent defaults to include) and wired it into
   `connect_hello`: disjoint `hash_formats` → **400 incompatible_hash_format**; disjoint
   `key_types` → **400 unsupported_key_type** (§4.5, the canonical earliest reject point).
5. **`format_agility.agility_unknown_1` FAIL (401 identity_mismatch for key_type=0xFD).** The
   authenticate handler read `key_type` only as a text field; a claimed `peer_id` whose
   multihash encodes an unsupported key_type fell through to the identity check → 401. **Fix:**
   added `peer_id_key_type()` (via `ec_peerid_parse` in `identity.f90`) and, in
   `connect_authenticate`, reject a claimed peer_id whose key_type ≠ ed25519(1) with **400
   unsupported_key_type** before the identity comparison (AGILITY-UNKNOWN-1 / §7.1).

## Answers to the S4 checklist

- **Multisig accept path — genuine K-of-N.** `valid_2of3_peer_signed_accepted` PASS: the peer
  co-signs as the harness-provisioned `~/.entity/peers/conformance/keypair` (seed 0x11), real
  2-of-3. Not env-skipped, not vacuous.
- **A-FTN-013 (build-value heap leak) — no arena needed.** Measured, not asserted: `t2_1`
  streamed **160 000** gets (+ nested reentry + 100 churn cycles) at the 4 GiB cap → PASS,
  zero drops, no OOM. The leak's constant factor stays within cap; the bump-arena is deferred
  hardening, NOT a gate blocker. Entry resolved in the ambiguity log.
- **dispatch-outbound / origination — SKIP not FAIL under core.** The `origination` category
  honest-SKIPs in single-peer mode (reference-peer-gated) and is auto-allowlisted; its **core
  reentry leg runs live** under `concurrency.t1_2` (PASS). No dispatch-outbound FAIL remains.
- **A-FTN-014 (413 empty request_id) — confirmed conformant.** `resource_bounds.r1` checks
  status (413 payload_too_large) + keep-serving, not request_id correlation. Closed.
- **No spec-vs-oracle divergence.** All fixes were peer bugs derived from the spec (§4.5,
  §6.11/§6.13(b), §7.1) — the oracle was right in every case. No `HANDOFF-TO-ARCH` candidate
  opened at S4. The dispatch-outbound params shape follows the §7a GUIDE-CONFORMANCE
  test-scaffolding contract (mirrored from the rexx precedent).
- **No S2/S3 regression.** S2 codec 69/69; S3 self-test 18/18 + smoke 5/5 — re-verified after
  the net-shim / peer / identity changes.

## Files created / modified at S4

- **`run-s4.sh`** (new) — the S4 harness: self-re-exec under capped podman, `make peer`,
  provision `~/.entity/peers/conformance/keypair` (seed 0x11 → co-sign accept path), launch
  `build/peer --name conformance --port 7777 --debug-open-grants --validate`, scrape
  `LISTENING`, run `validate-peer -profile core -timeout 5m -json-out …`, teardown trap.
  (No `make` target added — the existing `peer:` target builds the single host binary.)
- **`src/ext/net_shim.c`** — SIGPIPE ignore + `MSG_NOSIGNAL` (A-FTN-016).
- **`src/peer.f90`** — serve-loop `EV_NONE` → `cycle` (A-FTN-017); `hnd_dispatch_outbound`
  live reentry (A-FTN-018); `negotiation_disjoint` + hello negotiation rejects; authenticate
  peer_id key_type reject.
- **`src/identity.f90`** — `peer_id_key_type()` helper (via `ec_peerid_parse`).
- **`status/`** — this file, `CONFORMANCE-REPORT.{md,json}`, `SPEC-AMBIGUITY-LOG.md`
  (A-FTN-013/014 resolved; A-FTN-016/017/018 added).

## What S5 (packaging) must know

- **Build:** `make peer` → single `build/peer` binary (net-shim + libentitycore_codec linked;
  `-Wl,-rpath` to the codec build, `LD_LIBRARY_PATH` also set by the harness). No co-process.
- **Launch contract (unchanged):** `bin/peer --name NAME [--port N] [--validate]
  [--debug-open-grants]`; prints `LISTENING <port>`. `--validate` bootstraps the §7a handlers
  (incl. the now-live dispatch-outbound); OFF by default (a standing originator must not ship).
- **The dispatch-outbound reentry is now real**, not a stub — S5 should keep `--validate`
  gating it so the shipped default peer has no standing outbound originator.
- **No packaging blockers surfaced at S4.** The `resource_bounds/r3` and `concurrency/t1_1`
  WARNs are expected single-thread-select outcomes, not defects.
