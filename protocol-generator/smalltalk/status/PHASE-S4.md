# entity-core-protocol-smalltalk — Phase S4 summary ✅ COMPLETE (gate green)

**Phase:** S4 (conformance — `validate-peer --profile core`)
**Date:** 2026-07-12
**Peer:** #26 — Pharo Smalltalk, the FIRST pure-object / live-image / message-passing peer.
**Container:** `entity-core-keystone/pharo-toolchain:latest` (Pharo 13.0 build.732, fedora:43).
**Oracle:** `validate-peer` @ **`cc1970f`**, core-gate fingerprint `8261a033…` — matches
`tools/oracle-pin.env`; overseer-prepared, NOT rebuilt.

## Headline — `Result: PASS`

**`682 total · 291 pass · 295 warn · 0 FAIL · 96 skip` @ `cc1970f`** (peer_id
`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`). **0 FAIL, 0 fail-counting skips.** Exact cohort
parity with Rexx (#24) and Forth (#25) — cohort-consistent (shared generation lineage), not
independent convergence. Per-category detail + JSON in `CONFORMANCE-REPORT.{md,json}`.

## Iteration count + whether it needed a bounce

Reached green in **one S4 session** (the overseer front-loaded the register/unregister + revocation
warning). The entry state (S3 scaffold + minimal handlers) opened at `50P/296W/229F/107S` — the 229
FAILs were a SINGLE cascading root cause (a live DNU crashed the serve loop; see bug #1 below), not
229 distinct bugs. After the crash was contained and the handlers built out, the run converged
through a short sequence of real peer bugs (below), each caught by the oracle and fixed in code —
never a bounce back to an earlier phase, never a disabled check.

## Bugs found + fixed in the generated peer (the keystone payoff)

All CODE fixes; the oracle was never doctored. Details in `SPEC-AMBIGUITY-LOG.md` (A-ST-014…017).

1. **Dispatch caught only `EntityCoreError`, not `Error` → a live DNU crashed the whole peer
   (A-ST-016, the headline).** The first oracle run hit `ByteString >> #tokenize:` (a non-existent
   Pharo selector — the right one is `findTokens:`) deep in `pathFlexOk:`. On a dynamic/no-static-
   check substrate that DNU escaped the `on: EntityCoreError do:` frame and crashed `serveForever`
   → every subsequent request got a broken pipe → **229 cascaded FAILs from one bug**. Fix:
   `handleExecute:` catches `Error` (→ 500) and `serveConn:`/`onFrame:` catch `Error` (→ swallow +
   keep serving). This is §4.9 deliver-or-signal, but the resilience frame MUST be the language's
   ROOT error class on a no-static-check substrate — a real generator-robustness lesson for any
   future dynamic/live-image peer.
2. **Per-connection nonce counter → cross-connection handshake replay (A-ST-014, F12).** The §4.6
   nonce used the per-connection out-counter, which resets to 0 on each fresh connection, so every
   connection's first nonce was the IDENTICAL `SHA256(1‖id_hash)` — a captured `authenticate`
   replayed byte-for-byte on another connection (`connectivity/handshake_replay_cross_connection`
   FAIL). Fix: a PEER-GLOBAL monotonic `nonceCounter`.
3. **Uppercase hex on revocation/signature tree paths (A-ST-015).** `hexOf:` used
   `printPaddedWith:to:base:`, which yields UPPERCASE; the oracle's tree paths are lowercase
   (§3.4/§3.5). So `revoke` bound a marker at `…/revocations/00537D46…` but the follow-up `tree.get`
   canonicalized to `…/00537d46…` → 404 (`revoke_happy_path` + `revoked_cap_denied_on_use` FAIL).
   Fix: force `asLowercase`.
4. **Root single-sig granter (== our id_hash) didn't resolve → all authenticated authz 403.**
   `EcCapAuthz` resolves the granter peer from the envelope `included`; a seed cap whose granter is
   our OWN id_hash isn't echoed back by the client. Fix: inject our own peer entity into the inbound
   envelope's included set before authz (root-at-local resolves).
5. **§4.5 negotiation key_type reject missing.** Added `helloKeyTypeBad:` (peer_id multihash
   key_type prefix ≠ ed25519 → 400) — cleared the 2 `negotiation` FAILs.
6. **Single-event-loop accept-poll timeout starved throughput (A-ST-017).** The S3 loop ran a
   1-second blocking `waitForAcceptFor:` per tick; with pipelined tree traffic every tick blocked
   up to 1s even while ready connections had data → the oracle's 20s per-request budget expired
   (`tree_operations` i/o timeouts; ~47s/category). Fix: NON-BLOCKING accept poll
   (`waitForAcceptFor: 0`), drain every ready connection of all frames each tick, 2ms `Delay` only
   when idle. Throughput went ~47s → sub-second per category; `concurrency` went from a collapsed
   skip to **5/5 PASS** (t2_1 = 16×10000 sustained, zero drops).
7. **§4.10(c) admission for the r3 connection flood.** `tryAccept:` made error-safe (the Pharo VM's
   ExternalSemaphoreTable registration can throw transiently under a 256-socket burst — that threw
   from OUTSIDE the serve-loop frame and felled the peer). With the error-safe accept + a working-set
   cap + a 300-deep backlog, the peer accepts the whole flood AND keeps serving the post-flood probe
   → r3 is a spec-allowed WARN (§4.10(c) SHOULD), peer stays alive.

The full §5.5 chain verifier (`EcCapAuthz`, ported NATIVELY from the converged Forth `capauthz.fs`
as message-sends over `EcEntity`/`EcValue` objects) — root single-sig + multisig M3/M4/M6, per-link
signature + attenuation + grantee/expiry, §5.7 caveats, §5.1 revocation, §5.2 permission-scope,
§6.2 mint-bounded — landed CORRECT on the first green run once bugs #2–#5 above were fixed (no
chain-logic bug survived to the gate), a strong signal the value-object model maps §5 cleanly.

## Multisig accept-path (the keystone payoff) — GENUINE K-of-N

`multisig` is rejection-only (8 malformed → 403), so a fail-closed peer passes it vacuously.
`tests/multisig-accept.st` (`make multisig-accept`) builds a genuine 2-of-3 root cap in-image,
co-signs it as two of three signers (one the local peer), and asserts §5.5 M3/M4/M6 **ACCEPT** +
each M-rule reject: **MULTISIG-ACCEPT 4/4**. The oracle's own `valid_2of3_peer_signed_accepted`
also PASSES (the peer loads its on-disk keypair and co-signs AS the peer). Not a vacuous pass.

## Origination-core §10.2 — 3/3 (reference-peer-gated)

`./run-origination-core.sh` (Go `entity-peer` as B-role): `reference_connect` / `reference_ready`
PASS, and **`dispatch_outbound_reentry` PASS** — the §6.11 reentry pump wired to the live
`system/validate/dispatch-outbound` handler genuinely originates ONE outbound EXECUTE back to the
validator-as-B over the SAME inbound connection. Under single-peer `--profile core` the origination
category **honest-SKIPs** (extension-only, §9.0 auto-allowlisted) — NOT counted as a core-gate FAIL.

## What was built at S4 (deliverables)

- **`src/EntityCore-Capability/EcCapAuthz.st`** (NEW) — the §5.2/§5.5 chain verifier (native
  message-send port of the converged cohort logic): chain collection, root single-sig + multisig
  M3/M4/M6 trust, per-link signature + grantee(system/peer) + §5.6 validity + attenuation subset,
  §5.4 canonicalization + `/*/`/`/*` pattern + scope matching, §5.7 caveats, §5.1 revocation
  (leaf OR chain-root hash), the §5.2 permission gate, and §6.2 mint-bounded.
- **`src/EntityCore-Peer/EcCoreTypes.st`** (NEW) — the render-from-model 53-type §9.5 core floor
  published at `/<peer>/system/type/<name>` (each hash computed by this peer's own S2-green codec).
- **`src/EntityCore-Peer/EcValidate.st`** (NEW) — the §7a conformance handlers behind `--validate`:
  `system/validate/echo` (verbatim) + `system/validate/dispatch-outbound` (the §7a.2a reentry
  driver decoding the in-band reentry cap chain and re-entering the §6.11 pump).
- **`src/EntityCore-Peer/EcPeerHandlers2.st`** (NEW) — the expanded handler surface: tree put/CAS/
  deletion-marker + listing, `system/capability` (request/configure/revoke), `system/handler`
  (register/unregister — the five spec writes), `system/type`, §6.2 manifest + N2 dispatch
  publishing, the open-grants seed scope, §1.4 path-flex validation.
- **`src/EntityCore-Peer/EcPeer.st`** — bootstrap wires the type floor + all handlers + manifests +
  dispatch entities + (under `--validate`) the §7a handlers; dispatch now routes authz through
  `EcCapAuthz`; the serve loop is non-blocking + throughput-tuned + §4.10(c)-admission-safe;
  peer-global nonce counter; catch-`Error` resilience.
- **`src/EntityCore-Peer/EcPeerHandlers.st`** — the §4.5 key_type reject; peer-global nonce.
- **`src/EntityCore-Codec/EcPeerId.st`** — `parseKeyType:` (for the negotiation reject).
- **`src/EntityCore-Peer/EcNet.st`** — error-safe `tryAccept:`; §4.10(c) backlog.
- **`bin/peer.st`** — reads `EC_PEER_VALIDATE` / `EC_PEER_OPEN_GRANTS` and passes them to bootstrap.
- **`tests/multisig-accept.st`** (NEW) + `Makefile` `multisig-accept` target.
- **`run-s4.sh`** + **`run-origination-core.sh`** (container-bound, sealed-offline `--network=none`,
  capped via `tools/podman-caps.sh`).

## Regression status (all still green)

S2 corpus 69/69 · int-boundary OK · crypto-accept OK · S3 selftest 25/25 · smoke 6/6 ·
origination-core 3/3.

## What S5 needs

- **The gate is GREEN and reproducible** (`./run-s4.sh` → `682·0F @ cc1970f`); S5 packages ON this.
- **New src files to include in the dist** (`make dist` already globs `src/*`): EcCapAuthz,
  EcCoreTypes, EcValidate, EcPeerHandlers2 are in `load.st`'s srcFiles — no manual dist edit needed,
  but confirm the `dist` tarball carries them + `tests/multisig-accept.st` + both S4 run-scripts.
- **`--validate` / `--debug-open-grants` are OFF by default** (production-safe): the shipped default
  peer boots FFI-free of the validate handlers and without the degenerate open-grants seed. S5's
  packaged-peer boot smoke should confirm a plain `pharo … bin/peer.st` still reaches `LISTENING`.
- No blocking items; no open ambiguity-log escalations (all A-ST-014…017 resolved in code).

## S4 exit criteria — ✅ ALL MET

- [x] Oracle fingerprint-verified current (`cc1970f`, `8261a033…`); NOT rebuilt.
- [x] `run-s4.sh` + `run-origination-core.sh` (container-bound, sealed-offline, capped).
- [x] `--validate` conformance handlers wired; multisig accept-path GENUINE K-of-N (4/4 unit + oracle).
- [x] Origination-core 3/3 (reference-peer-gated); single-peer honest-SKIP under core.
- [x] `CONFORMANCE-REPORT.{md,json}` + this file + `SPEC-AMBIGUITY-LOG.md` updated.
- [x] **`Result: PASS`, 0 FAIL, 0 fail-counting skips — MET.** `682·0F @ cc1970f`, 291/295/96.
      No check disabled to fake green. S4 is **COMPLETE**.
