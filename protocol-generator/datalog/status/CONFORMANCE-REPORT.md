<!-- current-pin-banner:95edd774f4a2 -->
> **CURRENT (2026-08-28) — spec snapshot `v0.8.2`, executed check set `95edd774f4a2…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **755 total · 312 pass · 337 warn · 0 FAIL · 106 skip** (elapsed 83627 ms).
>
> That digest is the pinned `core_executed_check_set_digest`, so this number is
> comparable to every other row in `CONFORMANCE-MATRIX.md` §1 — and it is a CONTENT
> anchor, which is the only kind that survives the release boundary ([ADR-0012] Am. 1).
> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative
> artifact; `tools/check-set-gate.py --tracked` gates it, and this banner is generated
> from it by `tools/status-banner.py` rather than typed.
>
> **Everything below this line predates this measurement and is retained as build
> history.** Where it disagrees with the figures above, the figures above win;
> `CONFORMANCE-MATRIX.md` §1 is authoritative for the cohort.

---

# entity-core-protocol-datalog — S4 Live-Peer Conformance Report

**Phase:** S4 (conformance) · **Oracle:** `validate-peer --profile core` @ **cc1970f**
(`core_gate_fingerprint 8261a033…9cbf745`) · **Run:** 2026-07-16, in-container
(`datalog-toolchain`) + capped (`$PODMAN_RUN_CAPS`) + `--network=none` (offline).

## Gate result — `Result: PASS`, 0 fail

```
Summary: 682 total, 292 passed, 294 warned, 0 failed, 96 skipped (elapsed ~22s)
         96 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate
Result: PASS (with warnings)
```

**`682·0F @ cc1970f`** — the cohort constant, exactly. P/W/F/S = **292 / 294 / 0 / 96**.
The 294 warns are all `type_system` non-floor vocabulary (extension types — matched-if-
present, not-a-FAIL-if-absent under `--profile core`) + one `resource_bounds` r3 conn-flood
SHOULD; the 96 skips are the whole extension categories the profile auto-allowlists. No
skip is a masked failure — every skip is an extension-only category the core profile
exempts (no `-allow-skip` was needed; the profile carve-out owns them).

## Per-category (the core-profile surface)

| Category | P | W | F | S | Notes |
|---|--:|--:|--:|--:|---|
| connectivity | 22 | 0 | 0 | 0 | §4.1 handshake, nonce/PoP, replay |
| encoding | 6 | 0 | 0 | 0 | ECF wire |
| type_system | 108 | 292 | 0 | 0 | 53-type §9.5 floor served; non-floor types WARN |
| handlers | 35 | 0 | 0 | 32 | core register/unregister + get/put/connect/capability; ext handlers skip |
| capability | 12 | 0 | 0 | 0 | request / configure / revoke |
| tree_operations | 25 | 0 | 0 | 31 | get/put/list/CAS/deletion-marker/path-validity; ext TREE ops skip |
| security | 28 | 0 | 0 | 1 | §5.2 verify_request DENY surface |
| multisig | 11 | 0 | 0 | 0 | incl. the live **2-of-3 accept** (Ascent K-of-N) |
| concurrency | 5 | 0 | 0 | 0 | §7b store-safety + §6.11 reentry (T1.2) |
| resource_bounds | 2 | 1 | 0 | 0 | r1 413 / r2 400 chain-depth (MUST); r3 WARN |
| universal_address_space | 8 | 0 | 0 | 0 | §1.4 |
| peer_canonicalization | 7 | 0 | 0 | 0 | §3.6 v7.65 canonical/Base58 policy patterns |
| format_agility | 10 | 0 | 0 | 0 | unsupported key_type → 400 |
| crypto_agility | 4 | 0 | 0 | 0 | |
| negotiation | 4 | 0 | 0 | 0 | §4.5 disjoint hash_formats / key_types → 400 |
| authz | 5 | 1 | 0 | 2 | §5.2 DENY ladder (Ascent verdict) |
| *(extension-only categories)* | — | — | — | 96 | auto-allowlisted §9.0 carve-out |

Raw oracle output: `status/CONFORMANCE-REPORT.json` (`-json-out`).

## origination-core — 3/3 PASS (reference-peer-gated)

`./run-origination-core.sh` (Datalog A-role target + Go `entity-peer` B-role reference,
both in-container, offline):

```
[origination]  reference_connect PASS · reference_ready PASS · dispatch_outbound_reentry PASS
Result: PASS (3 total, 3 passed, 0 failed, 0 skipped)
```

`dispatch_outbound_reentry` exercises the §6.11 reentry seam live: the validator EXECUTEs
`system/validate/dispatch-outbound`; the peer originates one outbound EXECUTE back over the
SAME inbound connection (`conn.outbound` in `host.rs`, driven by the `dispatch_outbound`
handler in `dispatch.rs`) and returns the downstream response. No leg was honest-SKIPped.

## The K-of-N accept path — confirmed LIVE (not just the unit test)

`multisig.valid_2of3_peer_signed_accepted` **PASS**: the validator mints a 2-of-3 multisig
root, co-signs AS the peer (its keypair provisioned at `~/.entity/peers/conformance/keypair`
with the cohort `0x11×32` seed), and EXECUTEs — the peer ALLOWs. The verdict is the Ascent
counting aggregate (`quorum_met(c) <-- threshold(c,k), agg n = count() in distinct_signer(c,_)`),
NOT a host loop. The rejection-only `multisig` category (10 malformed→reject checks) stays
vacuous without this; the in-tree `k_of_n_2_of_3_accept_path` unit test + the live probe
together cover the accept direction the oracle otherwise can't.

## Wire corpus (S2, re-confirmed at S4)

`./run-s2.sh` → **71/71 PASS** — byte-identical encode + decode_reject + content_hash +
peer_id + signature against the pinned v0.8.0 corpus, via `libentitycore_codec`
(`spec-data v7.71`, core-wire-unchanged across V7→V8; A-DL-003 closed). Unchanged by S4.

## The wrapper-guard SURVIVED S4

Completing the handlers added ZERO imperative allow/deny to `dispatch.rs`. The §5.2 verdict
still comes end-to-end from the `ascent!` rules in `src/authority.rs` (`authority::authorize`
returns the ALLOW; absence of a derived `allow` IS the denial). Everything added at S4 is
either a handler BODY (register/unregister, configure, dispatch-outbound, type-floor render),
STRUCTURAL request validation returning a 4xx (path validity → 400, CAS → 409, zero-token →
400, negotiation → 400), or the connection state machine (key_type reject) — none of it is an
authorization decision. The S3 loopback + Go-interop gate (which drives `authorize()` on every
request) still passes: `./run-s3.sh` GREEN.

## How the gate is run

- Container `entity-core-keystone/datalog-toolchain:latest`; capped + `--network=none`; the
  Go `validate-peer` ELF runs INSIDE the image alongside the peer (shared loopback, sealed).
- `./run-s4.sh` builds `entity-peer-datalog` offline and launches it
  `--port 7737 --name conformance --debug-open-grants --validate`, then points
  `validate-peer -addr 127.0.0.1:7737 -profile core -json-out …` at it.
- `CARGO_TARGET_DIR` is a named podman volume (`kc-dl-target`) mounted at `/tmp/dl-target` —
  container-managed storage, off the `:Z` bind mount (A-DL-009's SELinux `ld` denial applies
  only to the relabelled mount), giving fast incremental rebuilds.
- **The oracle is NOT rebuilt here** — the overseer's fresh `cc1970f` binaries (fingerprint
  reproduced) are the gate for this build; go HEAD moved past `cc1970f` on NETWORK work and
  re-pinning is a policy-§4 decision, not an S4 step.
