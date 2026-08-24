# HANDOFF-TO-ARCH — 2026-08-13 — the `peers` grant dimension has zero oracle coverage

**Date:** 2026-08-13 · **Owner:** `arch` (oracle vector authoring) + optionally `go` (reference-impl fix)
**Severity:** real conformance-oracle gap; cohort impact confirmed on 7/44 measured peers
**Companion to:** `SESSION-2026-07-28-fceb61f-RT6-F40-remediation.md` §5 item 2 (the flag this discharges)
**Read at pins:** keystone `9292a3a` · `entity-core-go` `a02ab5e`
**Trigger:** two independent F40 fix-agents reported forth/smalltalk never check a grant's `peers`
dimension. This handoff is the follow-up investigation: what the spec requires, whether the claim is
real, how far it extends across the cohort, and why conformance-green never caught it.

---

## 0. Headline

**The spec is unambiguous: `check_permission` MUST evaluate all four grant dimensions — handlers,
operations, peers, resources — on every dispatch (§5.2, `ENTITY-CORE-PROTOCOL.md` lines 2059–2083).**
`peers` is not conditional on any particular operation; it defaults to `{include: [local_peer_id]}`
when the grant omits it, and is checked against `target_peer = extract_peer(execute.data.uri,
local_peer_id)` — the peer segment of the EXECUTE's own dispatch URI, which is foreign whenever the
URI addresses another peer's namespace (the spec's own example: `resources: ["/{remote_peer_id}/data/*"]`
for cached copies, §3.6 "Peers vs resources", line 3228).

**7 of 44 measured peers never enforce this dimension**: `forth`, `smalltalk`, `asm-arm64`,
`asm-x86_64`, `riscv64`, `wasm-wat` (silently absent — the field is parsed into the seed grant's CBOR
but never read back at dispatch), and `pd` (absent by a documented, deliberate assumption: "floor
grants omit it; request is local → skip", which holds for the shipped floor grants but not for a
user-authored grant that sets `peers` explicitly).

**Why it was never caught: the oracle has zero test coverage of this dimension.** `grep -rn '"peers"'
cmd/internal/validate/*.go` (excluding `_test.go`) in `entity-core-go` returns **nothing** — no
conformance vector ever mints a grant with an explicit `peers` restriction and checks it is enforced.
This is the AGENTS.md "conformance-green can be vacuous" pattern by the book: the cohort's `--profile
core` gate is 100% green on all 7 affected peers today.

**A second, independent finding surfaced investigating this: the `go` reference implementation itself
(`entity-core-go`'s `core/capability/check.go`, NOT the oracle) does not implement the spec's §5.2
`target_peer` extraction.** `FindMatchingGrant` calls `MatchesPeerScope(string(localPeerID),
*grant.Peers, localPeerID)` — always checking the running peer's OWN identity (a per-process constant),
never a value derived from `execute.URI` — and only runs the check at all when `grant.Peers != nil`
(no default-to-`{include:[local_peer_id]}` fallback when absent, contra spec). `rust`'s and `python`'s
generated peers implement the spec's `extract_peer` + default fallback correctly (see §3), so this
looks like a go-specific gap, not a spec ambiguity — flagging per the "spec-vs-oracle/reference
divergence is a finding" discipline (AGENTS.md), since we cannot fix `entity-core-go` from here.

---

## 1. What the spec requires (citation)

`protocol-generator/shared/spec-data/v0.8.0/ENTITY-CORE-PROTOCOL.md`:

- **Grant field table**, line 2378 / line 1040: `peers` — `system/capability/id-scope`, optional.
  "Peer scope — which peers the grant applies to. When absent, defaults to local peer only
  (`{include: [local_peer_id]}` constructed at evaluation time). Peer IDs are explicit — there is no
  `"self"` alias."
- **§5.2 pseudocode**, lines 2059–2083 (`check_permission`) and 2085–2116 (`check_grant_covers`):

  ```
  target_peer = extract_peer(execute.data.uri, local_peer_id)
  ...
  for grant in capability.data.grants:
    if not matches_scope(operation, grant.operations, local_peer_id): continue
    if not matches_scope(handler_pattern, grant.handlers, local_peer_id): continue
    peers_scope = grant.peers or {include: [local_peer_id]}
    if not matches_scope(target_peer, peers_scope, local_peer_id): continue
    if resource_target is not null:
      if not check_resource_scope(...): continue
    return ALLOW
  ```

  The doc comment is explicit: "Checks all four grant dimensions: handler, operation, peer, resource,"
  unconditionally — there is no operation-class carve-out.
- **§5.2 prose**, line 2390: "The capability MUST contain a grant where the `handlers` scope matches
  the resolved handler pattern, the `operations` scope includes the requested operation, and the
  `peers` scope includes the target peer... All matched dimensions must come from a single grant
  entry."
- **§3.6 "Peers vs resources"**, line 3228: clarifies `peers` (network scope — which peers a grant
  authorizes interaction with) is orthogonal to peer-ID-prefixed `resources` paths (local tree
  namespace, e.g. cached foreign-peer data) — the example given is exactly a case where `target_peer`
  differs from `local_peer_id`: a peer serving `/{remote_peer_id}/data/*` locally.
- **`extract_peer`**, line 2196: `first = first_segment(uri); if is_peer_id(first): return first; else
  return local_peer_id` — reads the EXECUTE's own dispatch URI, not the resource-target field.

No hedge, no MAY, no operation-scoped exception. This is a plain MUST.

---

## 2. Cohort census — who implements it, who doesn't

Verified by reading each peer's `check_permission`-equivalent function directly (not the oracle, not
grep alone — every classification below was read in context).

**Correctly implement `extract_peer` + default-fallback + `peers`-scope match (37 peers):**
`ada`, `c`, `cobol`, `common-lisp`, `cpp`, `crystal`, `csharp`, `dart`, `datalog`, `elixir`, `fortran`,
`go` (the *generated* peer under `protocol-generator/go/`, distinct from the `entity-core-go`
reference/oracle repo), `haskell`, `io`, `java`, `julia`, `kotlin`, `lean`, `nim`, `ocaml`, `odin`,
`oz`, `php`, `prolog`, `python`, `rexx`, `ruby`, `rust`, `sql`, `swift`, `tcl`, `typescript`, `unison`,
`zig`, plus three delegated/derived peers that inherit correctness from a verified sibling:
`node-red` (delegates `checkPermission` to the compiled `typescript` dist bundle,
`node-red/src/lib/peer-kernel.js`), `rust-wasm` / `rust-wasm-wasmtime` (thin transport seams over the
`rust` crate per AGENTS.md), and `turbowarp` (bundles the same `typescript`-derived code,
`turbowarp/src/dist/ec-core-browser.js`).

**Missing entirely — the dimension is never read at dispatch (6 peers):**

| Peer | Evidence |
|---|---|
| `forth` | `capauthz.fs` `grant-covers-op-handler` (line 487) checks `operations`, `handlers`, `resources` only; `peers` appears nowhere outside comments. |
| `smalltalk` | `EcCapAuthz.st` `grantCoversOpHandler:exec:local:granter:` (line 442) — same three dimensions, no `peers`. |
| `asm-arm64` | `dispatch.s`: `ka_peers` constant is written into the seed-grant CBOR (~line 1031) but never referenced again; the permission-check body (lines 5554+) only re-reads `ka_operations`/`ka_handlers`/`ka_resources`. |
| `asm-x86_64` | Identical shape, `dispatch.s` lines 848/1030 vs. 5701–6043. |
| `riscv64` | Identical shape, `dispatch.s` lines 870/1084 vs. 5945–6307. |
| `wasm-wat` | `dispatch.wat`: `$grant_scope_ok` / `$op_scope_ok` (lines 2741, 2828) walk `operations`→`handlers`→`resources` only; the `peers` string constant (`$t_035`) is used once, in the seed-grant memory-init block (line 544), never in either scope-check function. |

**Missing by documented (but still unsound) design assumption (1 peer):**

| Peer | Evidence |
|---|---|
| `pd` | `ecodec.c` `cap_permits` (line 1779): `/* peers: floor grants omit it (default local); request is local → skip. */` — true for the shipped floor grants, but a user-authored (or delegated/attenuated) grant that sets `peers` explicitly to something other than local is silently unenforced, same practical gap as the other 6. |

**7 of 44 total** — real, not "most of the cohort," but well above the 2–3-peer budget this
investigation was scoped to fix without checking back.

---

## 3. Reference shapes (what "correct" looks like)

`rust/src/peer/capability.rs` (`check_permission`, lines 239–274) and `python/src/entity_core/peer/capability.py`
(`check_permission`, lines 578–599) both implement the spec pseudocode byte-for-byte: `extract_peer`
strips the wire scheme, reads the URI's first path segment, returns it if it's a peer ID else
`local_peer`; `check_permission` defaults `grant.peers` to `{include: [local_peer]}` when absent and
always calls `matches_scope(target_peer, peers_scope, ScopeKind::Id)` before considering the grant a
match. 35 other peers (see §2) follow the identical shape in-idiom. This is the pattern `forth`/
`smalltalk`/the three CPU-architecture peers/`wasm-wat`/`pd` would need to adopt.

---

## 4. Severity assessment

This is a genuine MUST-violation, not a vestigial or inert dimension: whenever an affected peer serves
or addresses a foreign peer's namespace under a peer-ID-prefixed path (the spec's own worked example —
cached remote-peer data, or any deployment using the universal-tree convention), a capability's `peers`
restriction is silently bypassed — the `handlers`/`operations`/`resources` dimensions alone decide the
outcome, exactly as if every grant carried `peers: {include: ["*"]}`. It is not reachable through
anything the *shipped seed/floor policy* authors (which — like F40's finding — uses only local-peer-
implicit grants), so, mirroring the F40 handoff's framing: **this is live in any deployment that mints
or receives a `peers`-scoped capability on one of the 7 peers, not in the out-of-the-box default.**
Whether that makes it "conformance/interop defect" or "live vulnerability" depends on how the affected
peer is deployed — we recommend arch make that call the same way it did for F40.

---

## 5. What we recommend

1. **Author an `authz` oracle vector for the `peers` dimension** — mint a capability whose `peers`
   scope excludes the target peer (either via an explicit non-matching `include`, or via a peer-ID-
   prefixed URI/resource target with `peers` narrowed away from it) and assert `403
   scope_exceeds_authority` / `capability_denied`. Pair it with an accept-path control (a `peers`
   scope that *does* include the target) so a peer can't satisfy the vector by fail-closing
   everything — same rejection-only-oracle trap called out for `multisig` in AGENTS.md. This closes
   the "conformance-green can be vacuous" hole directly — still open, arch's to pick up.
2. **Check `entity-core-go`'s own `core/capability/check.go`** against the §5.2 pseudocode — it is the
   reference implementation used to build the oracle, and it currently neither extracts `target_peer`
   from the URI nor applies the spec's default-when-absent fallback (§0 above). We can't fix that repo
   from here; flagging it since a vector authored only against the *current* go behavior would encode
   the same gap into the oracle itself. Still open.
3. ~~**We are holding the peer-side fix**~~ **DONE, same session (2026-08-13).** All 7 peers
   (`forth`, `smalltalk`, `asm-x86_64`, `asm-arm64`, `riscv64`, `wasm-wat`, `pd`) fixed, each mirroring
   the rust/python reference shape in-idiom: `extract_peer` derived from the EXECUTE's dispatch URI,
   a grant's `peers` scope defaulted to `{include:[local_peer_id]}` when absent, checked as a genuine
   MUST-gate alongside operations/handlers/resources. Since the oracle has zero coverage of this
   dimension (item 1 above is still unaddressed), every peer got its own accept+reject unit test as
   the only regression guard (`smalltalk`'s and `wasm-wat`'s were mutation-tested: reverting the gate
   makes exactly the new reject-path tests fail, confirming they're non-vacuous). `pd`'s fix turned
   out lower-risk than expected — the check lives entirely in `ecodec.c` (the C codec seam), not on
   the canvas, so none of the earlier route-object wiring risk applied. Verified with a full,
   *serialized* `tools/run-cohort-census.sh` run (all 7 peers, one invocation, against the correctly
   re-synced `fceb61f` pin) after the fix: **0 new FAILs on any of the 7** — `forth`/`smalltalk`/
   `wasm-wat`/`pd` fully green, `asm-x86_64`/`asm-arm64`/`riscv64` each show only their pre-existing,
   unrelated `t2_2_connection_churn` FAIL, unchanged. Items 1/2 above remain open asks for arch;
   nothing else in this handoff is still pending on the keystone side.

---

## 6. Evidence appendix

| Claim | Evidence |
|---|---|
| Spec MUST, unconditional | `ENTITY-CORE-PROTOCOL.md` lines 2059–2116 (`check_permission`/`check_grant_covers`), line 2390 |
| `peers` field semantics + default | `ENTITY-CORE-PROTOCOL.md` line 1040, line 2378 |
| Peers-vs-resources orthogonality + worked example | `ENTITY-CORE-PROTOCOL.md` line 3228 |
| `extract_peer` | `ENTITY-CORE-PROTOCOL.md` line 2196–2200 |
| Oracle has no `peers`-keyed vector | `grep -rn '"peers"' cmd/internal/validate/*.go` (excl. `_test.go`) @ `entity-core-go` `a02ab5e` → empty |
| go reference impl doesn't extract target_peer / doesn't default | `core/capability/check.go` lines 100–142 (`FindMatchingGrant`), esp. lines 139–142 |
| go's `ExecuteData.URI` field exists but unused for peers | `core/types/protocol.go` lines 84–99 |
| rust reference shape | `rust/src/peer/capability.rs` lines 195–274 |
| python reference shape | `python/src/entity_core/peer/capability.py` lines 186, 578–599 |
| forth gap | `forth/src/capauthz.fs` lines 484–506 |
| smalltalk gap | `smalltalk/src/EntityCore-Capability/EcCapAuthz.st` lines 442–452 |
| asm-arm64/asm-x86_64/riscv64 gap | `<arch>/src/dispatch.s`, `ka_peers` referenced only in seed-grant construction, never in the permission-check body |
| wasm-wat gap | `wasm-wat/src/dispatch.wat` lines 2741–2828 (`$grant_scope_ok`, `$op_scope_ok`) |
| pd documented shortcut | `pd/src/ecodec/ecodec.c` line ~1779 comment + `cap_permits` body |
| node-red delegates to typescript dist | `node-red/src/lib/peer-kernel.js` (`TS_DIST` load), `node-red/src/lib/session.js` line 286 |
| rust-wasm(-wasmtime) thin seam over rust | AGENTS.md precedent note; no independent capability source in either dir |
| turbowarp bundles the same typescript-derived code | `turbowarp/src/dist/ec-core-browser.js` lines 4415–4776 |
