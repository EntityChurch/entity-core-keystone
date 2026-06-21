# entity-core-protocol-haskell — Phase S3 (Peer machinery) Summary

**Peer:** #8 (Haskell) · **Phase:** S3 (peer machinery + smoke) ·
**Spec basis:** v7.74 · **Status:** COMPLETE — peer compiles `-Wall -Werror` clean;
**smoke 7/7 (10 assertions) GREEN over real loopback TCP**, deterministic; S2 codec
unregressed (106/106).

Built the full peer (V7 L1–L4 + foundation + the v7.74 live hooks) on the green
S2 codec, spec-first from `spec-data/v7.74`, with the OCaml peer as the structural
reference (closest ML-family precedent) and DERIVING core semantics from the spec
text. Idiom seam: **GHC green threads (`forkIO`) + STM (`TVar`)** — a 3rd
data-race-free store shape, genuinely distinct from all 7 prior peers.

---

## Modules (`src/EntityCore/`, on top of the S2 codec)

| Module | V7 layer | LoC | Responsibility |
|--------|----------|----:|----------------|
| `Model.hs`      | foundation | 173 | materialized `{type,data,content_hash}` (§1.1/§3.4) + envelope (§3.1); fidelity-validating `entityOfCbor` (§1.8); strict fields |
| `Identity.hs`   | L1 | 108 | keypair → peer_id (§1.5 identity-multihash) / peer entity / signing (§3.5/§7.3); `verifySignature` |
| `Store.hs`      | foundation | 201 | **STM-`TVar` content store + tree** (§1.7) + §6.10 emit pathway (content/tree consumers, null-`new_hash`=deleted); §3.9 listing |
| `Capability.hs` | L3 | 420 | §5.2 `verifyRequest` (3-way verdict) + `checkPermission`; §5.4 patterns + §1.4 `normalizeUri` (incl. `entity://` scheme strip); §5.5 chain walk + §5.5a/§PR-8 per-link granter frame (preferred hard-fail); §5.6 attenuation; §5.7 caveats; §5.1 revocation; **pure verdict over a snapshot resolver (N8)** |
| `Wire.hs`       | L2 | 105 | §1.6 framing (4-byte BE length); EXECUTE/EXECUTE_RESPONSE builders; error result; empty-params `0xA0` |
| `TypeDefs.hs`   | foundation | 69 | §9.5 type-floor **render-from-model seam** + minimal core-type seed (A-HS-009: full 53-render deferred to S4) |
| `SeedPolicy.hs` | foundation | 35 | §6.9a seed-policy selection (standard / debug-open); the Haskell builder shape of the keystone convention |
| `Peer.hs`       | L1–L4 | 882 | the four MUST handlers (connect/tree/handler/capability), §6.5 dispatch chain + signature ingestion, §6.6 backward resolution, §6.9 bootstrap, §6.9a Peer Authority Bootstrap, §6.13a register/unregister (five writes), §6.13b outbound closure, §7a echo + dispatch-outbound, per-connection state |
| `Transport.hs`  | L4 | 231 | TCP listener + dialer; **`forkIO` per connection, STM-`TVar` request_id↔reply demux**; §4.8 inbound-concurrent-with-outbound; §6.11 reentry seam; `TCP_NODELAY` |
| `app/Host.hs`   | — | 65 | standalone host (`--port`/`--validate`/`--debug-open-grants`; `LISTENING` line) — the S4 target |
| `test/Smoke.hs` | — | 319 | two-peer loopback smoke runner (client built from the library's own builders/codec) |

Total ~2.6 KLoC. `-Wall -Werror -Wcompat -Wincomplete-record-updates
-Wincomplete-uni-patterns -Wredundant-constraints` clean across the whole closure.

## Idiom seams (deliberate, the Haskell-faithful translation)

- **Pure `Either CodecError a` codec underneath; IO/exceptions only at the
  transport edge** (A-HS-001). The capability verdict is a **pure function** of a
  one-time store snapshot (`Resolver = ByteString -> Maybe Entity`) — no IO in the
  verdict path (the cleanest N8 shape across the cohort).
- **`Data.Map.Strict` behind `TVar`s** for the store; **`IORef`** for
  per-connection mutable handshake state (single-threaded per conn);
  **`atomicModifyIORef'`** for the connection-scoped outbound counter.
- `Text` for paths/peer-ids (ASCII Base58 / UTF-8), strict `ByteString` for hashes
  + wire bytes. `LambdaCase`/`OverloadedStrings`/`BangPatterns`.

---

## Concurrency model (A-HS-003 — the headline) + N5–N8

**Green threads + STM, a 3rd data-race-free store shape** (after the Elixir actor
= message-serialized, and the Swift actor = await-serialized). Here it is
*transactional*: every store mutation commits inside `atomically`; emit-consumer
IO effects run *after* the commit (STM is pure).

- **§7b store data-race-freedom is STRUCTURAL, not a discipline.** Two concurrent
  per-request `bind`s serialize at the STM commit point with **no manual locking
  and no lost update** — the exact race that crashed Zig (HashMap double-free) and
  Common Lisp (raced `gethash` → 500s) **cannot occur**: a bare-map store fails
  §7b, an STM-`TVar` store passes it by construction. The store's content-put +
  tree-bind compose into **one** transaction, so a put/bind is atomic w.r.t.
  readers. This is the §4.8 store-safety floor (v7.75 §9.1) met for free, the same
  way Swift's actor made the race a compile error — a *different mechanism*, same
  outcome.
- **GHC `-threaded` RTS sidesteps Swift's cooperative-pool trap.** Swift starved
  its bounded cooperative pool when blocking `read()`/`accept()` ran on it. GHC's
  IO manager multiplexes blocking socket I/O over `epoll`: a green thread parked in
  `recv` **yields its capability** to others, so blocking reads do not starve the
  scheduler. The 16-concurrent-EXECUTE demux + the reentry-under-load leg ran clean
  with one `forkIO` reader per connection + one `forkIO` per inbound EXECUTE — no
  pool to starve. (crypton's C is called from pure code, not on the socket path, so
  no `unsafe`-FFI-blocks-a-capability concern arises in core; noted for the agility
  sub-lib if it ever runs concurrently.) **`TCP_NODELAY` is set on every socket**
  (the Zig/Swift Nagle-churn lesson) from the start.

**N5–N8 coverage (enforced at design time):**
- **N5** envelope `included` preservation — both request side (every EXECUTE the
  client/handler builds bundles author+sig+cap) and result side (`okI`/`ocIncluded`
  carries the minted token+sig+granter through the response). The §6.13b outbound
  closure rebuilds the full included set (cap, granter, grantee/author, cap-sig,
  exec-sig).
- **N6** inbound-concurrent-with-outbound — the reader **never blocks**: an EXECUTE
  is dispatched on its own `forkIO`, so a handler that originates an outbound
  EXECUTE (§6.13b) and awaits its reply does not stall the reader (proven by the
  dispatch-outbound reentry leg, which is exactly this shape).
- **N7** reentrant transport + request_id demux — replies route by `request_id`
  through an STM-`TVar` pending map; the outbound await `retry`s on an empty slot
  (no condition variable, no lost wakeup). **Proven: 16 concurrent EXECUTEs each
  correlate to their own EXECUTE_RESPONSE**, deterministically. (Found + fixed the
  N7 trap *in the smoke client itself*: a non-atomic request-id counter collided
  ids under 16 threads → `atomicModifyIORef'`.)
- **N8** verdict determinism — the Layer-1 verdict is a pure function of a fixed
  chain-state snapshot; timing cannot perturb it.

---

## §6.9a Peer Authority Bootstrap + seed policy

Wired exactly per the keystone `shared/seed-policy/` convention:
- **Owner cap at L0 (detached-signature shape):** a root `system/capability/token`
  granting full scope over `/{peer}/*`, grantee = own identity, written at
  `system/capability/policy/{owner_hash_hex}` with its self-signature at the §3.5
  pointer `system/signature/{cap_hash}`.
- **`default` policy-entry** (the §4.4 discovery floor, or the degenerate
  `default → *` under `--debug-open-grants`).
- **Authenticate-time dual-form lookup** (hex → Base58 → `default`) UNION the
  discovery floor (v7.62 §8); reads both §6.9a.0 shapes (a cap-token whose detached
  sig verifies, or a policy-entry's `grants`).
- CLI: `--owner-identity`* / `--seed-policy`* (A-HS-011 — file-parse is the next
  increment) / `--debug-open-grants` (deprecated, routed through the real §6.9a
  mechanism). Builder: `createPeer seed SeedPolicy conformance`. The
  `initialGrants/openGrants` fork is retired.

## §7a + §7b conformance scaffolding

- **§7a echo + dispatch-outbound** built as native handlers behind the
  `conformance` opt-in (`createPeer … True`) → host `--validate`, **OFF by
  default** (dispatch-outbound is a standing originator). echo passes the value
  **through** (no re-wrap). dispatch-outbound originates **back to the caller over
  the inbound connection** (§6.11 reentry, B-role on the same connection — NOT a
  third-peer dial); cap-passing **(a) in-band params** (matches the cohort).
  **Proven over real two-peer TCP in the smoke runner** (status 200 + value
  passthrough). Cap-passing for the reentry direction: the *caller* mints a cap
  granting the *target peer*, valid at the caller — surfaced + handled in the smoke
  (the client mints a client→server reentry cap; passing the server-granted cap
  instead correctly 403s, confirming the §7a.2a authority direction).
- **§7b** store concurrency-safety is structural (above). The smoke exercises the
  demux + reentry-under-concurrency legs green; the full 5-check §7b validate-peer
  gate runs at S4.

## Smoke result (the S3 hard exit) — 7/7 (10 assertions) GREEN over loopback TCP

`cabal test smoke` boots two Haskell peers (server `--validate` + open seed; a
client peer that also serves the reentrant leg), all green, deterministic:
1. §4.1 handshake both directions (hello → authenticate; session + §4.4/§6.9a
   initial cap; **remote peer_id correct**). ✅
2. EXECUTE on an unregistered path → **404**. ✅
3. Authority-gated tree get → **200** (discovery floor admits `system/type/*`). ✅
4. capability request → **200** (mints a bounded child cap; subset-checked). ✅
5. **request_id demux (N7): 16 concurrent EXECUTEs each correlate** → all 200. ✅
6. register → **200** (the five §6.13a writes). ✅
7. **dispatch-outbound reentry → 200 + echo value passthrough** (§6.11 reentry,
   value round-trips). ✅
8. Clean teardown (no hangs; STM/green-thread cleanup). ✅

The standalone `host` boots + prints the `LISTENING … peer_id=…` line (`--validate`
+ default), ready for the S4 `validate-peer` oracle.

---

## New findings / ambiguities (this phase) — see SPEC-AMBIGUITY-LOG.md

No new **spec-text** contradiction surfaced (expected for a coverage peer — the
peer-id §7.4/§1.5 reconciliation, the 401/403 boundary, the §PR-8 granter frame all
landed consistently with the cohort, an 8th independent corroboration). Recorded
decisions:
- **A-HS-009** — §9.5 53-type registry: render seam + minimal seed at S3; full
  byte-exact render + type-registry byte-diff deferred to S4 (mirrors Swift
  A-SW-009 / OCaml render-table). Non-blocking.
- **A-HS-010** — entity-native dispatch still evaluates the minimal
  `compute/literal` body (the §10.1 round-trip half); carries the compute vocab
  into the core path (mirrors OCaml A-OC-010 / the cohort's A-011). Harmless,
  kept until Go drops it (no flag-day). Informational.
- **A-HS-011** — `--seed-policy <file>` JSON parse (the shared schema) is the next
  increment; in-code builders (`standard`/`debug-open`) are the S3 floor (mirrors
  the cohort).
- **A-HS-012** — S3 adds `network`/`stm`/`time`/`containers` deps; pinned in the
  committed freeze at the pinned index-state (all in LTS 23.27 except
  `network`, which the pinned snapshot selects at `3.2.8.0`). Operator: confirm the
  `network` pin clears the S11 30-day floor at re-pin (the index-state caps it ≤
  the LTS snapshot).

## Exit criteria

Peer compiles clean (`-Wall -Werror`) · reads as idiomatic Haskell (pure
`Either` codec + STM/green-thread IO edge), not transpiled OCaml · smoke 7/7 green
over real TCP · S2 codec unregressed (106/106) · container-reproducible (warm
`.cabal-home` store + committed freeze, A-HS-005 offline pattern). **S3 PASS.**

## S4 entry checklist

1. **Wire the host into `run-s4.sh`** (twin of the C#/OCaml/Zig scripts):
   rebuild the Go `entity-peer` + oracle from go HEAD (GOWORK=off), run
   `--profile core`, `--validate` for the §7a/§7b gates, origination-core via a
   reference peer.
2. **Land the full §9.5 53-type render** (A-HS-009) + the type-registry byte-diff
   (drop the full model list into `TypeDefs.coreTypes`; the publisher + seam are
   already there).
3. **Agility higher bar is reachable** (Ed448 native, proven at S2) — the S4
   agility categories are in scope without an FFI detour (the only such peer with
   it native; A-HS-007).
4. Verify N5–N8 against the live oracle (the design-time enforcement should hold);
   converge any reds spec-first (S5: fix the code, not the test).
5. Confirm the offline build/run path under `--network=none` against the warm
   store for the S4 harness.
