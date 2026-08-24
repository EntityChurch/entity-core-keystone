# entity-core-protocol-tcl — Phase S4 summary (COMPLETE)

**Phase:** S4 (conformance)
**Date:** 2026-07-11
**Oracle:** `validate-peer` @ **`cc1970f`** (public HEAD; matches `tools/oracle-pin.env`
core-gate fingerprint `8261a03…`)
**Status:** ✅ **COMPLETE — `--profile core` PASS, `682 · 0F`** (292 P / 294 W / 0 **F** /
96 S). Measured **natively** at `cc1970f`, sealed-offline (`--network=none`).
Reproduce: `./run-s4.sh`. Report: `status/CONFORMANCE-REPORT.{md,json}`.

## What ran

`run-s4.sh` (mirror of the cohort harness) launches the peer via
`bin/peer.tcl --port 7777 --name conformance --debug-open-grants --validate`, waits
for its `LISTENING` line, points the Go `validate-peer` oracle at it over intra-
container loopback (so oracle + peer share one host and the run stays offline), then
tears the host down. Crypto (Ed25519 + SHA) crosses the C-ABI via the shim
(`make shim`); everything else is pure Tcl in-repo (zero runtime package deps).

The peer's persistent identity is provisioned at `~/.entity/peers/conformance/keypair`
(seed `0x11×32`, base64 `ERER…`) so the validator's multisig accept-path probe finds
the keypair (`crypto.LookupKeypairByPeerID`) and co-signs AS the peer — exercising
genuine K-of-N, not an env-skip.

## Result — 0-FAIL, genuine multisig, structural concurrency

- **0 FAIL** across every `--profile core` category. The gate is MET.
- **Genuine §3.6 K-of-N multisig.** `multisig` = 11 P / 0 F, and crucially
  **`valid_2of3_peer_signed_accepted` PASSED** ("peer authorized a valid 2-of-3
  multi-sig cap it co-signed" — M4 quorum + M6 root-at-local). Not vacuously
  rejection-only: the accept-path RAN. (Multisig is not in `--profile core`, so this
  is above-and-beyond the gate.)
- **type_system: 108 P / 292 W / 0 F — zero byte-mismatch.** Every published §9.5
  floor type renders byte-identical to the oracle's Go-rendered vector
  (render-from-model, 0 drift). All 292 warnings are the oracle probing for
  extension/`compute/*` types a core peer intentionally does NOT publish
  ("not-a-FAIL-if-absent").
- **concurrency 5 P / 0 F** — §7b store-safety is structural (single event thread; no
  lock), verified under the oracle's concurrent-dispatch probes.
- **resource_bounds 2 P / 1 W** — §4.10(a) 16 MiB payload pre-check → 413 and §4.10(b)
  chain-depth pre-check → 400 hold; the 1 W is the §4.10(c) connection-admission
  SHOULD (delegated externally — the honest-WARN carve-out).

## Number-honesty note

The `682` total is a **fresh** `cc1970f` measurement (like COBOL's `291`). The other
21 cohort peers carry `665` from the retired `e8524ed` build — the full-suite total is
**non-gating** and varies by oracle build and by how many extension probes a peer's
answers let run; what `cc1970f` certifies is the **`--profile core` 0-FAIL gate**,
proven-uniform via the core-gate fingerprint (see `CONFORMANCE-MATRIX.md` reading
note). The 682 vs 665 gap is that reproducibility working as designed, not a
regression.

## Findings

No spec-precision finding — the EIAS probe is clean corroboration across the full
conformance surface (S2 codec 69/69 → S3 peer 12/12 → S4 `--profile core` 0-FAIL). The
experimental question the profile posed is answered: **the spec is precise enough to
oblige an Everything-Is-A-String peer to carry the CBOR major type explicitly, with no
leak into ad-hoc convention** — proven all the way to the oracle. See
`SPEC-AMBIGUITY-LOG.md` S3 resolutions.

## Exit criteria — MET

`validate-peer --profile core` **0-FAIL** at the pinned oracle; matrix row added
(`CONFORMANCE-MATRIX.md`, tier *probe*, `682·0F`). **S5 packaging done** (see
`PHASE-S5.md` — `pkgIndex.tcl` works via `package require entity::core`); registry
publish deferred like the cohort (`0.1.0-pre`). Steady-state is the Tier-tracked
re-run cadence on future spec amendments.
