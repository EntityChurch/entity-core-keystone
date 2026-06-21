# entity-core-protocol-php — Phase S4 (Conformance) Summary

**Release "reach" peer** · **Status: COMPLETE — GREEN on
all three RELEASE-READINESS §4 gates.** Zero peer-correctness fixes required: the
S3 peer converged on the oracle first-try.

## Oracle provenance (NOT rebuilt this phase)

The vendored `output/s4-oracles/{validate-peer,entity-peer}` are the pinned
`e8524ed` fedora:43 Go ELF binaries, `core_gate_sha256 =
e09a865ffea690ce207149eb68851f7afbc2fa3a9ba522a0ca9d9c72f9923308` (matches
`tools/oracle-pin.env`, spec_line v7.77). `tools/oracle-bootstrap.sh` was NOT run;
`entity-core-go` was NOT touched. Binaries are gitignored.

## The gate — all three PASS

| Gate | Result |
|---|---|
| **`validate-peer --profile core`** | **665 total, 0 FAILED** (292 pass / 278 warn / 95 skip auto-allowlisted by §9.0). `Result: PASS (with warnings)`. |
| **`origination-core` (§10.2)** | **3/3** — `reference_connect`, `reference_ready`, **`dispatch_outbound_reentry`** all PASS, 0 skip. |
| **`multisig`** | **11/11, 0 skip** — incl. **`valid_2of3_peer_signed_accepted`** which shows `RUN` then `PASS` (genuinely co-signed AS the peer via the on-disk `--name conformance` keypair; NOT env-skipped). |

The `--profile core` total has moved 568→573→576→653→665 across oracle versions;
**665** is the e8524ed/v7.77 cohort total (the value C++/Kotlin landed at). The gate
is `failed==0`, which holds. `status/CONFORMANCE-REPORT.json` is this green run
(`summary.failed == 0`, total 665, peer_id `2KHoAk…`).

## Harness (this phase's deliverables)

- **`run-s4.sh`** — modeled on `cpp/run-s4.sh`, adapted to PHP: **no compile step**
  (the host is `php bin/peer`, ext-sodium + ext-gmp bundled in the image). Sealed
  `--network=none`; provisions `~/.entity/peers/conformance/keypair` (seed `0x11`×32 →
  PEM `ERER…` → peer_id `2KHoAk…`) in-container; launches
  `bin/peer --port 7777 --name conformance --debug-open-grants --validate`; waits for
  `LISTENING`; runs `validate-peer -profile core -json-out status/CONFORMANCE-REPORT.json`.
- **`run-origination-core.sh`** — modeled on `cpp/run-origination-core.sh`: PHP target
  (A-role, `--validate`) on TPORT 7777 + Go `entity-peer --open-access` reference
  (B-role) on RPORT 7778; runs `validate-peer -profile core -category origination`. The
  `dispatch_outbound_reentry` probe drives the §6.11 same-connection reentry the S3
  transport was built for (B→A outbound over the inbound connection).

Both run via:
```
podman run --rm --network=none -v <worktree>:/work:Z \
  entity-core-keystone/php-toolchain:latest sh /work/protocol-generator/php/<script>
```

## dispatch_outbound_reentry — the S3 prediction held

PHASE-S3 item #2 noted the smoke's inner verdict was 403 (session cap), and that S4's
validator would supply the cross-peer reentry cap to flip it to 200. That is exactly
what happened: with `--validate` live, the validator mints the reentry cap, EXECUTEs
`system/validate/dispatch-outbound`, and the PHP peer originates the outbound EXECUTE
back to the validator-as-B over the SAME inbound connection → PASS. The reentry-capable
transport built up front at S3 (avoiding the OCaml/COBOL from-zero rewrite) paid off.

## multisig accept-path — genuine K-of-N, RUN not SKIP

`--name conformance` loads the seed-`0x11` Ed25519 identity (peer_id parity verified at
S3); the oracle's `crypto.LookupKeypairByPeerID` finds the on-disk keypair and co-signs
AS the peer. The accept check `valid_2of3_peer_signed_accepted` therefore executes the
real `Capability::verifyMultiSigRoot` union granter (§3.6 M3 structure → §5.5 M6 local∈
signers → M4 distinct-signer count ≥ threshold) and verdicts ALLOW. The 10 deny/precedence
checks (the rejection-only surface) also PASS. 0 skip on the category.

## Peer-correctness fixes this phase

**None.** No FAILs surfaced; the peer matched the oracle on every core check. No oracle
or test was patched (S5 discipline). No spec ambiguity surfaced (reach peers are
corroboration-only) — `SPEC-AMBIGUITY-LOG.md` unchanged from S3 (A-PHP-001..011).

## Warnings (non-blocking)

278 warns are the §9.5 matched-if-present non-floor type vocabulary + SHOULD-level
surfaces (e.g. `resource_bounds` r3 conn-flood WARN). All exempt from the FAIL gate.
The single `resource_bounds` non-pass on the summary line is the r3 SHOULD-WARN, not a
FAIL (failed==0).

## No sacred-tree writes

All work confined to `protocol-generator/php/` in the `lang/php` worktree. No writes to
the primary keystone, the meta-rooted clone, or `entity-core-go`. Oracle not rebuilt.

## Exit criteria

`validate-peer --profile core` → 665·0F GREEN · `origination-core` 3/3 incl.
`dispatch_outbound_reentry` GREEN · `multisig` 11/11 0-skip with accept-path RUN GREEN ·
CONFORMANCE-REPORT.json is the green run · oracle pin verified · no peer fixes needed ·
ambiguity log has no blocking items. **S4 PASS.**
