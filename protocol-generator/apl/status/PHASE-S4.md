# entity-core-protocol-apl — Phase S4 summary (COMPLETE)

**Phase:** S4 (conformance)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/apl-toolchain:latest` (GNU APL 1.9, source-built, fedora:43)
**Oracle:** `validate-peer` @ **`cc1970f`** (core-gate fingerprint `8261a033…`), sealed-offline
in-container.
**Result:** ✅ **`validate-peer --profile core` → `Result: PASS` — 682·0F @ cc1970f**
(P/W/F/S = **291 / 295 / 0 / 96**). S2 corpus 69/69 + unit ALL PASS; S3 self-test 18/18 +
smoke 5/5 stay green. Reproduce: `./protocol-generator/apl/run-s4.sh`.

## Harness

`run-s4.sh` (mirrors `protocol-generator/fortran/run-s4.sh`, adapted for INTERPRETED APL):
re-execs under capped podman `--network=none`; builds `libentitycore_codec` (CMake) +
`src/ext/ec_native.so` (`make shim`); provisions the persistent identity at
`~/.entity/peers/conformance/keypair` (entity PEM = base64 seed `0x11 × 32` = `ERER…ERE=`, so
peer_id is unchanged AND the multisig accept-path can co-sign as the peer); launches
`apl --script <S3 modules> -f bin/peer.apl -- --name conformance --port 7777
--debug-open-grants --validate`; scrapes the `LISTENING 7777` line (output FILE-redirected,
never piped — A-APL-013); points the oracle at `127.0.0.1:7777`; tears down. Budget 15m
(`ORACLE_TIMEOUT` overridable) — interpreted APL is slow under the `concurrency` flood
(~1m40s), but the gate is the per-request cap, not wall-clock.

## Iteration loop (6 iterations, each FAIL → peer fix)

| # | Symptom | Root cause (all peer bugs; oracle is ground truth) | Fix |
|---|---|---|---|
| 1 | 35 fail; peer DIED in `concurrency` (`SYNTAX ERROR HndDispatchOutbound … ok←…`), cascading `connection refused`/`broken pipe` across every later category | **Label∥variable name collision**: `ok` was both an `ok:` label AND `ok←PumpUntil rid` in `HndDispatchOutbound` → SYNTAX ERROR on assigning to a label constant + parser corruption. Latent — the `--validate` dispatch-outbound path was never exercised before S4 | Rename the variable `ok`→`pumped` |
| 1b | concurrent-reentry flood re-entered a *pendent* `HndDispatchOutbound` (2nd connection's inbound dispatch-outbound serviced inside the 1st's pump) | GNU APL single-image reentry hazard | `fd PumpUntil rid` services ONLY the reentry fd; nested inbound EXECUTEs DEFERRED to `gDefer` (gated by `gReentryDepth`), drained by `PeerServe` at depth 0 → `HndDispatchOutbound` never pendent twice. `concurrency` → 4P/1W/0F |
| 2 | listing 404s (`system/type/`, `system/handler/`, tree listings); `type_system`/`handlers`/`tree_operations` fails | **`(¯1↑target)≡'/'` is ALWAYS false** (1-elem vector vs scalar — `≡` compares rank), so trailing-slash listings were never detected | trailing-slash via `EndsWith` (see iter 5); + `StoreListing` same bug |
| 3 | `path_reject_empty_segment` + `reject_null_byte` + `reject_leading_slash` accepted (200) | §1.4 path validation absent | `CapCanonicalize` rejects null bytes, empty segments (`//`), reserved `./ ../ */`, and leading `/` whose first segment isn't a valid peer_id → 400 `invalid_path`; `TreePut`/`TreeGet` honor the flag (pattern canon via `Canon` ignores it, so `/*/…` grants unaffected) |
| 4 | `universal_address_space` foreign put → 403 | **`pattern≡'*'` false when `3↓pattern` yields the 1-elem vector `,'*'`** (rank again) → the trailing-`*` wildcard never matched, so `/*/*` failed to cover `/{peer_id}/…` | `CapMatchesPattern`: ravel both sides (`(,pattern)≡,'*'`, `(,path)≡,pattern`). UAS → 8/8 |
| 4b | `multisig.valid_2of3_peer_signed_accepted` → 403 | threshold parsed as `(2⊃p)⊃(0)(1⊃p)` → index=present(1) picked the `0` element, so threshold was always 0 | `th←(1⊃p)×2⊃p`. THEN exposed `SlHas←{∨/⍺∘≡¨⍵}` → **`⍺∘≡¨⍵` DOMAIN ERRORs in GNU APL** → `{∨/(⊂⍺)≡¨⍵}`. multisig → 11/11 |
| 5 | 77 fail — massive regression: gets returned `system/tree/listing`, put/get wrong entity, concurrency demux "cross-talk" | **My iter-2 fix `'/'=⊃⌽target` was itself buggy: monadic `⊃` is DISCLOSE (identity on simple arrays), NOT first** — `⊃⌽v` returned the reversed string, `'/'=` made a bit-vector truthy for ANY `/` → every path with a slash resolved as a listing | trailing-slash via the existing `EndsWith` idiom (both `TreeGet` and `StoreListing`) |
| 6 | `core_tree_path_flex_1: reject_leading_slash` accepted `/system/…/bad` (200) | absolute path with a non-peer_id first segment wasn't rejected | `CapCanonicalize` abs branch: `→(~CapIsPeerId FirstSegment path)/bad` |

**Final: `Result: PASS`, 0 fail, 682·0F @ cc1970f.**

## Findings

All findings are GNU-APL array-idiom traps + peer-code bugs — **no spec-vs-oracle
divergence**, **no arch handoff** (APL was authored as a *corroboration* probe; this confirms
the prediction of zero fresh wire findings). Logged as **A-APL-017** (four reusable
GNU-APL-1.9 traps: `⊃`=disclose-not-first · `≡`=rank-sensitive so a 1-elem vector never
matches a scalar · `⍺∘≡¨⍵`=DOMAIN ERROR · label∥variable=SYNTAX ERROR; plus the single-thread
reentry-serialization pattern). These extend the S2/S3 GNU-APL cookbook (A-APL-012/013/015/016).

## Multisig accept-path — genuine K-of-N

`valid_2of3_peer_signed_accepted` PASS with the peer co-signing (keypair provisioned at
`~/.entity/peers/conformance/keypair`); `VerifyMultisigRoot` verifies ≥ threshold real
signatures with the local peer as one of the N signers. Not an env-skip.

## Files written / changed

- `run-s4.sh` (new) — the S4 harness.
- `status/CONFORMANCE-REPORT.{md,json}` (report + raw oracle output).
- `status/PHASE-S4.md` (this file); `status/SPEC-AMBIGUITY-LOG.md` (+ A-APL-017).
- Peer fixes: `src/peer.apl` (`ok`→`pumped`; single-fd `PumpUntil` + `gDefer`/`gReentryDepth`
  + `DrainDeferred`; `EndsWith` trailing-slash; `TreePut`/`TreeGet` path-validation),
  `src/capability.apl` (`CapMatchesPattern` ravel; `CapCanonicalize` null/empty-seg/leading-
  slash validation; multisig threshold; `SlHas`), `src/store.apl` (`EndsWith` in `StoreListing`).
