# PHASE-S3 — entity-core-protocol-wasm-wat (peer machinery)

Increment 3: porting the authority interior to hand-authored WAT.

## ✅ FULL COHORT PARITY (2026-07-15) — §7a `--validate` dialer landed

**291 pass / 294 warn / 0 FAIL / 97 skip @ oracle `cc1970f`** — `run-s4.sh` → **Result: PASS**,
**no `-allow-skip`** (the two §7a checks now RUN and PASS). Launch:
`wasmedge --enable-jit out/peer.wasm --debug-open-grants --validate`.

The last two deferred checks are green:
- **`t1_2_concurrent_reentry`** (concurrency) — *"M=8 concurrent reentrant dispatch-outbound calls
  all round-tripped; validator-as-B served 8 inbound echos (exactly-one per dispatch under
  concurrency)."* Stable across repeated runs (~44 ms).
- **`validate_echo_dispatch`** (handlers) — verbatim-echo round-trips the dispatch half (§7a.1).

**How it works — the same-connection insight.** §7a.2a reentry reuses the *inbound* connection, so
no client socket / `sock_connect` is needed and the whole suspend/resume collapses to *"`dispatch()`
always returns exactly one frame; the existing `on_readable` send-loop is unchanged."* Flow on the
single fd: `Di` (dispatch-outbound) arrives → `serve_dispatch_outbound` authors a **full authorized**
outbound echo EXECUTE (author-signed root + `capability` + `included{author-sig, cap, granter,
cap-sig}`), registers `pending[Ei]=Di`, and returns the echo frame → host sends it (Di suspended).
`Ei`'s EXECUTE_RESPONSE arrives → `serve_resume` matches `pending[Ei]`, wraps `{result:<echo
result>, status}` and emits the deferred Di reply. Host-side change is minimal: a `--validate` flag
+ a `-1` no-send sentinel. Pending table @0x990000 (16 slots).

**Note (F35):** the outbound envelope is built **fully authorized** even though the validator's
armed echo (`handleReentryEcho`) runs *zero* §5.2 verification — building the minimal unsigned frame
it would accept is the vacuous shortcut the keystone exists to catch. Logged as F35 → arch.

## ✅ `--profile core` GREEN (2026-07-15) — `run-s4.sh` → **Result: PASS**

**289 pass / 294 warn / 0 FAIL / 99 skip @ oracle `cc1970f`** (`status/CONFORMANCE-REPORT.json`;
go HEAD since the pin is docs-only, core-gate fingerprint intact). Launch:
`wasmedge --enable-jit out/peer.wasm --debug-open-grants`.

Landed this session (each committed + oracle-verified):
- **§10.1 handler register/unregister** — the five normative writes (interface/handler/grant/
  grant-signature) + unregister teardown. 8 `core_register_*` + both unregister checks PASS.
- **§6.11 concurrency t2_1/t2_2** — root cause was crypto speed: WasmEdge's default interpreter
  runs the codec Ed25519 verify at ~9 ms/op (2/req ≈ 18 ms) → the 10k-request robustness probes
  timed out. `--enable-jit` drops it to ~84 µs (107×); full **per-request** §5.2 verification is
  then fast enough — **no auth cache** (which `security.tampered_signature` proves is
  non-conformant). Frame-batching (drain ≤256 pipelined frames/wakeup) aids throughput.
- **§6.2 N2/N5 handler dispatch entities** — a `system/handler` entity at each core pattern path
  (connect/tree/capability) with an `interface` field. 6 checks PASS.
- **§1.4 universal address space** — `$canon_path` (peer-relative ≡ `/{local}/…`; `/{other}/…`
  distinct + isolated), absolute-path validation (peer-id-prefix gate; CORE-TREE-PATH-FLEX-1),
  immediate-child deduped listings, `/*/*` peer-wildcard in the debug grant. 8 checks PASS.

**Remaining (honest, non-gating):**
- `validate_echo_dispatch` + `t1_2_concurrent_reentry` — the §7a `--validate` conformance-handler
  scaffold. Both gate on `system/handler/system/validate/dispatch-outbound` presence, and t1_2
  requires a **reentrant outbound dialer** (the peer dials the validator back mid-request and
  relays an echo) — the highest-complexity item on a single-threaded poll-loop substrate.
  Deferred; allow-listed in run-s4 per §7a.4 (code-attestation floor). Publishing echo alone
  cannot clear either (the gate checks dispatch-outbound). This is the one real feature left.
- `multisig.valid_2of3_peer_signed_accepted` — local-test-env exempt; needs `--name` keypair load
  + multi-granter cap acceptance in `$verify_cap` (currently 403s a §5.5 multi-granter, deferred).

---

### Earlier increment-3 progress (pre-green)

## Done (committed, each unit-tested / oracle-checked)

| Layer | File | Status |
|---|---|---|
| Canonical-CBOR wire (reader/writer) | `src/wire.wat` | ✅ unit test PASS (`make wire-test`) |
| Identity (peer_id + identity_hash) | `src/identity.wat` | ✅ KAT PASS (`make identity-test`) — conformance seed → run-s4 peer_id |
| Transport spine (framing, recv_n/send_n) | `src/host.wat` | ✅ framed round-trip PASS (`make run-frame`) |
| connect/hello handler | `src/dispatch.wat` | ✅ byte-structure validated vs WIRE-GROUNDTRUTH (hexdump) |
| Non-blocking event loop (poll_oneoff + per-conn state machine) | `src/host.wat` | ✅ substrate-forced (A-WAT-006 / A-ASM-014); handshake live |
| authenticate handler (§4.6 PoP + §4.4 token mint/sign) | `src/dispatch.wat` | ✅ **connectivity 22/22 PASS** (oracle @ output/s4-oracles) |
| §6.5 resolution-first fallthrough (unhandled op → 404 handler_not_found) | `src/dispatch.wat` | ✅ request_id echo probe PASS |
| system/capability handler (request/revoke/configure/delegate) + write store + is_revoked | `src/dispatch.wat` | ✅ **capability 7 pass / 0 fail / 5 skip** (skips = floor-cap can't exercise configure/revoke; matches reference peer) |

**Oracle status (validate-peer @ output/s4-oracles, category connectivity):** **22 PASS / 0 WARN /
0 FAIL / 0 SKIP — Result: PASS.** authenticate is live: it runs the §4.6 three checks (nonce-echo
/ PoP / identity-binding, each → 401 with its coded error) + the §7.1 key_type gate (→ 400), then
mints + Ed25519-signs the §4.4 floor token and returns a 200 `system/capability/grant` with the
token + peer + signature in a canonically-sorted `included`. All positive §4.4/§4.6/§5.5/§1.5
checks pass (token in result, capability in included, grant scopes, granter identity, capability
signature verifies, entity hashes) AND all six negative handshake checks still reject correctly.
An authenticated EXECUTE to an unrouted operation returns 404 `handler_not_found` (§6.5 resolution-
first), which satisfies the §6.11(b) request_id-echo probe.

> Oracle is the vendored build in `output/s4-oracles/` (from the asm work). Re-verify/rebuild from
> `entity-core-go` HEAD before publishing any conformance number (CLAUDE.md: not auto-rebuilt).

## Architecture (the merged peer)

`peer.wasm` = `wasm-merge`(wire + identity + dispatch + host + codec.wasm) → one module on
stock WasmEdge. Interior modules import the codec's memory (one shared linear memory);
transport is WasmEdge's flat `wasi_snapshot_preview1` sockets; codec/crypto is the seam.
Constants via passive data + `memory.init`. Concurrency is the single-thread poll loop.

## Next (in dependency order)

1. ✅ **authenticate** (the unblock) — DONE, connectivity 22/22 PASS. Parses params +
   `included`, verifies the PoP (`ec_ed25519_verify` over the 33-byte auth content_hash), mints
   the system/capability/token (2 discovery grants, grantee = client identity_hash, granter =
   peer identity_hash, created_at), signs it (`ec_ed25519_sign`), and builds the grant response
   with token + peer + peer-signature in a canonically-sorted `included`. See `src/dispatch.wat`
   `$build_auth` (+ helpers `$build_error`, `$emit_grant_floor1/2`, `$find_sig`, `$emit_incl3`).
2. **§9.1 pre-dispatch floor** — the ordered verdict (413 → 400 malformed → §5.2 3-way
   {401/400 chain-depth/403} → URI normalize → handler resolve 404 → permission 403).
3. **The dispatch table** — system/tree (get/put/CAS/listing/delete), system/capability
   (request/delegate/revoke/configure), system/handler (register/unregister), system/type
   (501 stub), and (if `--validate`) system/validate/{echo,dispatch-outbound}.
4. **Identity from `--name` keypair file** + `--port`/`--validate`/`--debug-open-grants` arg
   parsing (WASI args_get + path_open/fd_read + base64 decode) — replaces the hardcoded seed.
5. Corpus selfcheck (WAT analog of asm `selfcheck.s`) → `run-s4.sh` → `--profile core` 0-FAIL.

**Progress (this session):** authenticate ✅ (connectivity 22/22); §4.5/§7.1 hello negotiation +
agility ✅; **tree GET + full §5.2 authority interior + served store ✅ (5a)**; tree listing ✅;
**§9.5 Core Type Floor — all 53 `system/type/*` byte-exact ✅ (5b)**; §6.5/§6.2 resolution-first
dispatch for authenticated ops ✅. `--profile core` went **66→~200 pass, 167→~8 fail**.

**GREEN now:** connectivity, encoding, negotiation, format/crypto_agility, handlers (0-fail),
type_system (0-fail), security (0-fail), **capability (0-fail)**.

**Progress (capability handler — landed this session):** the `system/capability` handler is
implemented and conformant — `--profile core` capability went **2 pass / 2 warn / 6 fail / 2 skip
→ 7 pass / 0 warn / 0 fail / 5 skip**, and full core **193→198 pass, 9→3 fail** (the 3 are the
untouched `resource_bounds` r1/r2/r3). Ports asm `build_request_response` / serve_revoke /
serve_configure / serve_delegate. What landed:
- **write store** (`$store_put`) — persists an entity blob at a canonical path into the arena
  (path+blob copied out of the per-frame request buffer); `$store_get` scans the unified index so
  writes are visible on later requests. Overwrites in place. `$store_init` runs once at startup
  (`host.wat`), so markers persist globally across connections.
- **`request`** (`$build_request`) — §5.2 auth+cap + **§6.2 op-scope** + **§6.2 attenuation**
  (`$grants_attenuated`/`$grant_covers`/`$array_subset_star`/`$resources_subset`): every requested
  grant MUST be covered by the caller's token, else 403. Mints `{grants:<verbatim>, grantee=author,
  granter=my idhash, created_at}`, signs, returns 200 `system/capability/grant` with sorted included.
- **`revoke`** (`$serve_revoke`) — writes a `system/capability/revocation` marker at
  `system/capability/revocations/<hex(token)>` (handler-set `revoked_at`, optional verbatim reason);
  the **`is_revoked` gate** in `$verify_cap` 403s a revoked cap on any later authenticated op.
- **`configure`** (`$serve_configure`) — writes the params policy-entry verbatim at
  `system/capability/policy/<peer_pattern>` and echoes it 200; rejects a partial-prefix (`*`)
  peer_pattern with 400 invalid_params.
- **`delegate`** (`$serve_delegate`) — same-peer-only (F1): parent present → 501
  unsupported_operation, no parent → 400 invalid_params (no auth gate; unsupported in v1).
- **§6.2 operation-scope gate** (`$verify_op_scope`/`$op_scope_ok`) on request/configure/revoke —
  op×handler check with the resource dimension skipped (these carry no `resource.targets`), mirroring
  the go peer's `FindMatchingGrant`. Under the floor cap (capability:request only), configure/revoke
  → 403.

**FINDING (the 5 capability skips):** configure/revoke/their sub-tests SKIP under the run-s4 floor
identity — **identical to the reference `entity-peer` with a default identity** (verified: launched
it, got the same 403→SKIP for configure/revoke). The floor cap grants only `capability:request`, so
configure/revoke are correctly 403'd and the oracle SKIPs (`revoke refused 403 …`). Turning these
5 into PASS needs a **broad-grant identity** — the §8 handshake **seed-policy** consultation
(`readHandshakePolicyGrants` in go: authenticate unions `system/capability/policy/{caller|default}`
grants into the connection cap) + arg parsing for a seed policy / `--debug-open-grants`. That is a
distinct, deferred piece (PHASE-S3 next item 4), NOT a capability-handler bug. The handler itself is
verified correct: under a broad cap, op-scope passes → configure/revoke 200 → readback path-scope
passes → all 5 PASS.

**resource_bounds — FIXED (host.wat), + a 4× peer speedup.** `resource_bounds` is now **2 pass /
1 warn / 0 fail** (r1 oversize→**413 payload_too_large**+keep-serving PASS — see the frame-cap
section below; r2 chain-depth→400+keep-serving PASS, r3 connection-flood WARN — the §4.10(c) SHOULD
external-admission carve-out, non-gating). Three host.wat changes:
- **Single-send framing** (the big win): `on_readable` shipped the response as two `sock_send`s (the
  4-byte length prefix, then the body). On a fresh connection each cold round trip stalled ~40–200 ms
  on Nagle+delayed-ACK holding the body until the prefix was ACKed. Dispatch now writes the body at
  `0x1800004` with the length prefix right before it at `0x1800000`, shipped in ONE send. **Churn
  (§6.11 t2_2) dropped 44 s → 10 s; type_system 12 s → 4 s; the full `--profile core` run 59 s → 15 s.**
- **NCONN 64 → 320 + a metadata relayout** (subs `0x480000`, events `0x484000`, nevents `0x487000`,
  table `0x490000`, sessions `0x4A0000`; memory grows to 1792 pages; conn buffers end exactly at
  `0x7000000`). Sizing past the 256-connection flood peak fixes r3 (the flood + probe all get slots →
  keep serving → WARN) and eliminates slot starvation (0 refused accepts across the full run). NB:
  idle flood sockets whose FIN this runtime never surfaces via poll/recv would zombie their slot; at
  64 slots that wedged the table — capacity absorbs them (a peek-recv reaper caught only 8/256, so the
  runtime genuinely won't report an idle-socket close).
- **§6.11 fairness:** `on_readable` yields to the poll loop after ONE frame (buffered pipelined bytes
  re-trigger FD_READ), so a single busy connection can't starve accepts.

**FIXED — cumulative broken-pipe in 7 deep-suite tests (the 256 KiB frame cap RST-ing a pooled
connection).** The speedup made 35 more checks run (592 → 627 total), reaching 7 that failed with
`write: broken pipe` — `peer_canonicalization.peer_mut_2` + 6 `authz_*`. **Root-caused** by
stderr-tagging the 4 `slot_free` sites in `$on_readable` and running the full suite: the
`concurrency` `t1_2` probe sends a **legitimate 258 KiB** `tree.put system/validate/concurrency/
slow`; at `CONNBUF=256 KiB` that hit `framelen > CONNBUF → slot_free (fd_close)`, RST-ing the
connection with data pending. The oracle **reuses one pooled client connection** across categories,
so every later test on it broke — hence isolation-green (each category reopens) but full-run-red.

Fix (`src/host.wat` + a 413 emitter in `src/dispatch.wat`):
- **`CONNBUF` 256 KiB → 1 MiB** (`$CONNBUF`; memory grows to 5632 pages, conn buffers end
  `0x16000000`). The 258 KiB legit payload is now buffered + dispatched (→ 403/SKIP, conn stays
  alive). 1 MiB is the declared §4.10(a) max payload — deliberately lower than the 16 MiB
  recommended default (§4.10 permits lowering; a flat 320-slot table can't afford 16 MiB/slot; the
  gate checks clean-reject + keeps-serving, not the value).
- **Over-max → drain + `413 payload_too_large` + keep-alive** (new DRAIN state=2 in `$on_readable`
  + exported `$emit_413`), replacing the RST — §4.10(a) "reject while **continuing to serve**."
  Over-size is detected pre-parse → best-effort empty `request_id` (spec MAY path).

**Result: full `--profile core` = 627 / 227 pass / 297 warn / 0 FAIL / 103 skip.** The 7:
`peer_mut_2` + `authz_{deny_default,grantee,no_catchall,expired}` PASS, `authz_scope_exceeds` WARN,
`authz_revoked_core` SKIP. Unit tests (wire/identity/ffi-smoke) PASS; no isolation regressions.

**Remaining skips-as-FAIL (the path to a GREEN *result*, not just 0-FAIL):** 36 skips still gate.
The 5 capability skips (above, need seed policy); `core_register_*` (handler register/unregister
§6.13a); `validate_echo_dispatch` + the `system/validate/*` concurrency probes (`--validate`
scaffold); `handler_*_interface_ref` (N5 dispatch entities). All are the seed-policy / `--validate`
/ `--name` feature increment (next-items 3–4) — honest skips (match the reference peer under the
floor identity), not defects.

Memory map additions landed: authority/store constants `0x462000+`; capability write-handler
constants `0x462ac0`–`0x462bcf` (policy/revocations path prefixes, `configure`, `invalid_params`,
hexchars); §9.5 type constants `0x463000–0x4666ff`; store index `0xA00000`, arena `0xA10000`, data
temp `0xA08000`/ch `0xA09000`, path-build scratch `0x977000`, get/listing scratch `0x974000`–`0x976000`;
capability scratch — path/hex `0x978000`/`0x978100`, revoke data `0x979000`, revoke entity `0x97A000`;
request mint reuses `$build_auth`'s buffers (`0x940000`/`0x958000`/`0x959000`/`0x960000`/`0x968000`,
hashes `0x920100`–`0x9201c0`, sig `0x920200`).

## tree GET build plan (increment 5 — the keystone unblock, ports asm `serve_tree_get`)

**Flow** (`$serve_tree_get`, routed on op `"get"`), each stage returns a built error length or 0:
1. `$chain_depth_check` — walk `capability`→`included`token→`parent`… ; >64 → **400 chain_depth_exceeded**.
2. `$verify_auth` (§5.2 auth-class) — `author`(33) present; `included` present; author's system/peer
   in included → pubkey(32); `root.content_hash`(33); find a `system/signature` in included with
   signer==author ∧ target==root_ch → sig(64); `ec_ed25519_verify(pubkey, root_ch, 33, sig)` → else **401 authentication_failed**.
3. `$verify_cap` (§5.2 cap-class) — `capability`(33) present; token=included_find_by_key(cap);
   recompute `content_hash(system/capability/token, token.data)` == cap key (substitution guard);
   grantee(33) present, resolves to a system/peer in included (else **401 unresolvable_grantee**),
   grantee==author; granter(33)==my idhash (root-trust; multisig = granter is a map, defer);
   token signed by granter (signer==granter ∧ target==cap, verify) → else **403 capability_denied**.
4. `$verify_scope` (§5.2 grant-scope) — `$derive_handler` (strip `entity://<peerid>/` from data.uri →
   handler, default system/tree); temporal (expires_at/not_before); `$grant_scope_ok(token.data,
   target, op, handler)` = ∃ grant with op∈operations.include ∧ handler∈handlers.include ∧
   target matches resources.include (`$array_contains_star` honors `*`; `$resource_matches`: bare
   `*` / trailing `/*` prefix / exact) → else **403 capability_denied**.
5. parse `resource.targets[0]` (text); `$path_valid` (no dot-relative/empty-seg/NUL → **400 invalid_path**);
   empty or trailing `/` → `$serve_listing`; else `$store_get(target)` → **200** entity blob or **404 not_found**.

**Response** `$build_get_ok(out, blob, bloblen, rid, rlen)`: data `{result:<blob raw>, status:200,
request_id}` → content_hash(execute/response) → envelope `{root:<resp entity>}` (no included).

**Store** (`$store_init` from `disp_init`; index @0xA00000 {count i32; entries@+0x10 = 16B
{path_ptr,path_len,blob_ptr,blob_len}}; arena @0xA10000). Each entry's blob is a COMPLETE entity
`{data,type,content_hash}`. `$store_get` = linear scan, exact path match.
- 5a: 3 handler-interface entities (`system/handler/interface`, data `{name, pattern,
  operations:{op:{input_type:"primitive/any", output_type:"primitive/any"}}}`) at
  `system/handler/system/{protocol/connect,tree,capability}` (ops: connect=hello/authenticate,
  tree=get/put, cap=request/delegate/revoke) + `system/handler/` listing. Unblocks handlers,
  concurrency churn, resource_bounds serve.
- 5b: the **53 `system/type/*` floor entities** (`system/type`, data per §3.5/§3.6 CDDL —
  required fields + type_refs are the FAIL-gated bits; optional/hash diffs are WARN, per the
  oracle's `compareTypeDefsOutcome`) + `system/type/` listing. Port from asm `typestore.s`
  (proven). Unblocks type_system. (Candidate for a fork once the 5a store pattern compiles.)

New rodata for 5a at `0x462000+` (authority field keys author/capability/resource/targets/uri/
parent/expires_at/not_before; codes capability_denied/chain_depth_exceeded/invalid_path/not_found/
unresolvable_grantee; store paths/keys/values). Store scratch: data temp 0xA08000, ch temp 0xA08100.

## authenticate — build plan (✅ IMPLEMENTED — `$build_auth` in `src/dispatch.wat`)

> Landed as specced below. Notes from the build: check order follows the asm-proven sequence
> (nonce → identity-binding → PoP → §3.5 signer) — all single-flaw negative checks pass either
> way. Constants live at `0x461000+` (slot `i` → `0x461000 + i*0x40`); auth scratch/hashes per
> the buffer plan below; `included` is emitted UNSORTED-then-bubble-sorted by the 33-byte key
> (`$emit_incl3`) — the sort was necessary (the three content-hash keys are runtime-ordered).

Groundwork done: per-connection session state (issued nonce) is plumbed; the exact spec
structures are gathered below (from ENTITY-CORE-PROTOCOL.md §3.5/§3.6/§4.4/§4.6). The handler
goes in `dispatch.wat`, routed on operation `"authenticate"`; it needs new imports
(`ec_ed25519_sign`, `ec_ed25519_verify`, identity `identity_hash`) and ~30 rodata constants.

**Entities (canonical key order matters — length then bytewise):**
- `system/peer` data = `{key_type, public_key}` (2 keys; peer_id is NOT hashable — v7.65,
  confirmed §3.5). identity_hash = `content_hash(system/peer)`. (identity.wat already right.)
- `system/signature` data = `{signer, target, algorithm, signature}` (that canonical order).
- `system/capability/token` data = `{grants, grantee, granter, created_at}` (that order).
- `system/capability/grant` (result) data = `{token}` (the 33-byte token content_hash).
- `grant-entry` = `{handlers, resources, operations}`; each scope = `{include:[...]}`.
- `system/protocol/error` data = `{code}` (text) [+ optional `message`].

**The authenticate entity** = `{type:"system/protocol/connect/authenticate", data:<params.data>}`
— params.data IS `{nonce, peer_id, key_type, public_key}`, so auth_hash =
`ec_content_hash("system/protocol/connect/authenticate", params.data_bytes)` (get params via
root.data→params→data; length via `skip`). public_key/nonce/peer_id read from params.data.

**§4.6 three checks (in order; each → 401 with its code, built by a shared $build_error):**
1. nonce-echo: `!hello_done` OR params.nonce(32) != session.nonce(32) → `invalid_nonce`.
2. PoP: scan envelope `included` for a `system/signature` whose data.target == auth_hash;
   `ec_ed25519_verify(public_key, auth_hash[33], 33, signature[64])`; absent/invalid →
   `authentication_failed`.
3. identity-binding: `format_peer_id(public_key)` != params.peer_id → `identity_mismatch`.

**On pass — mint + respond (the 2 SHOULD-floor discovery grants, §4.4):**
- grant1 = handlers[`system/tree`] resources[`system/type/*`,`system/handler/*`] operations[`get`]
- grant2 = handlers[`system/capability`] resources[] operations[`request`]
- token data = `{grants:[g1,g2], grantee=identity_hash(client_pubkey), granter=<my idhash @0x440000>,
  created_at=<ms>}`; token_ch = `content_hash("system/capability/token", token_data)`.
- sign: `ec_ed25519_sign(seed@0x420000, token_ch[33], 33, sig[64])`.
- result = `system/capability/grant {token: token_ch}` entity; response data
  `{result, status:200, request_id}`; response entity type `.../execute/response`.
- envelope = `{root:<response entity>, included:<map(3)>}` where included =
  `{token_ch→token entity, my_idhash→my system/peer entity, sig_ch→signature entity}`.
  (Signature data = `{signer:my_idhash, target:token_ch, algorithm:"ed25519", signature:sig}`.)
  FIRST TRY: emit included UNSORTED; if the validator rejects on canonical map ordering, sort
  the 3 bstr(33) keys bytewise.
- Scratch buffer plan (clear of hello's 0x900000–0x930040): token_data@0x940000,
  grant_data@0x958000, resp_data@0x959000, sig_data@0x960000, peer_data@0x968000; hashes at
  0x920080+ (auth/grantee/token_ch/grant_ch/sig_ch/resp_ch), sig(64)@0x920200.

After authenticate returns 200, connectivity should clear the FAIL/WARN and discovery + the
authenticated-EXECUTE categories open up — then the §9.1 floor + the rest of the dispatch table.

## Open items

- A-WAT-005: `codec.wasm` committed-artifact home (ffi-generator wasm shape).
- ✅ RESOLVED — per-conn buffer now 1 MiB (declared §4.10(a) max payload); over-max drains +
  `413 payload_too_large` + keeps serving (was: 256 KiB, dropped-by-RST). See the frame-cap
  section above. A true 16 MiB max would need a shared jumbo buffer (flat 320×16 MiB is
  infeasible); the lowered bound is spec-legal and, if arch wants the anchor at the 16 MiB cohort
  default, that jumbo design is the follow-up.
- Oracle at `output/s4-oracles/` is the vendored build from the asm work — re-verify/rebuild
  from go HEAD before any published conformance number (CLAUDE.md: not auto-rebuilt).
