# Pd peer — PATCH-DESIGN (the #32 BLOCK-DESIGN analog)

How the protocol is laid out across `.pd` patches. The governing rule (FLOW-DESIGN wrapper-guard):
**the algorithm is visible on the canvas** — decomposed into **named units** (a dispatch *spine* + one
abstraction per handler), with only bytes/maps/crypto/store delegated to the `[ecodec]` C external.
One 400-object tower is as unreadable as the code it replaced; a single delegated `dispatch(frame)`
object is a wrapper, not a probe.

Status: **design sketch** (S1). Object/wire specifics settle at S3 when patches are authored.

## Layer map (native transport → authored logic → delegated seam)

```
 TCP client (the Go validate-peer oracle, dials directly — no bridge)
        │  raw bytes
        ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  main.pd  — the connection front + dispatch SPINE                      │
 │                                                                        │
 │  [netreceive -b <port>]        ← NATIVE bidirectional binary TCP        │
 │     │ per-byte floats                     ▲ reply: list → inlet         │
 │     ▼                                      │ (same socket)              │
 │  [pd frame-assembler]  ── §1.6 4-byte-BE length prefix, per-socket ─────│
 │     │ complete frame (opaque handle via [ecodec])                       │
 │     ▼                                                                   │
 │  [pd conn-state]  ── §4.1 lifecycle state machine, keyed by socket ─────│
 │     │  (which leg: pre-hello / hello-seen / authenticated / established)│
 │     ▼                                                                   │
 │  [pd dispatch-spine]  ── §6.5/§5.2 sequence: decode → op-switch →        │
 │     │                     §6.6 handler tree-walk → guard ladder → reply │
 │     ├─────────────► [pd handler-system-echo]      (abstraction)         │
 │     ├─────────────► [pd handler-system-type]      (abstraction)         │
 │     ├─────────────► [pd handler-system-peer]      (abstraction)         │
 │     └─────────────► … one .pd abstraction per handler …                 │
 └──────────────────────────────────────────────────────────────────────┘
        │  seam (only what the substrate genuinely can't do)
        ▼
 [ecodec]  — Pd C external over libentitycore_codec (m_pd.h ↔ ec_*):
            canonical CBOR encode/decode, Ed25519 sign/verify, SHA-2, peer-id.
            Byte buffers / maps / keys / u64 ints ride as OPAQUE HANDLES;
            readable fields (status code, op selector, small counts) come back
            as plain float/symbol atoms.
```

## Named units (the decomposition — legibility = named units, not "on the canvas")

| Unit | File | Role | Analogy (#32) |
|---|---|---|---|
| **Front + spine** | `src/main.pd` | `[netreceive -b]`, frame-assembler wiring, the dispatch spine, and one send-back path | the top-level `dispatch` script |
| **Frame assembler** | `src/frame-assembler.pd` | §1.6: accumulate per-byte floats, read the 4-byte-BE length (via `[ecodec]` — never one float, A-PD-003), emit complete frames; per-socket buffer | the framing blocks |
| **Connection state** | `src/conn-state.pd` | §4.1 lifecycle state machine keyed by socket: pre-hello → hello-seen → authenticated → established; the reactive-mismatch core (A-PD-004) | per-connection state lists |
| **Dispatch spine** | `src/dispatch.pd` | §6.5/§5.2 decode → op-switch → §6.6 handler resolution as the VISIBLE longest-prefix-first tree walk → fail-closed guard ladder → status-envelope reply | `define dispatch` |
| **Per-handler** | `src/handler-*.pd` | one abstraction per §6.6 handler; adding a handler = adding a file (the intuitive-handlers goal) | `define dispatch-<handler>` |
| **Codec seam** | `src/ecodec/` | the `[ecodec]` C external (`.c` + Makefile → `.pd_linux`) wrapping `libentitycore_codec` | the bundled TS codec |

## The two authored mechanisms that must NOT fold (wrapper-guard focus)

1. **§6.6 handler resolution = a visible tree walk.** Repeat-until longest-prefix-first over the
   handler table, on the canvas — not `[ecodec resolve]` behind an `if pattern == "system/tree"`
   ladder. The remaining pattern→body selection may be a genuine Pd limit (no call-abstraction-by-
   dynamic-name); if so, label it **body-selection**, not resolution (the exact #32 caveat).
2. **§5.2 authorization verdict = the explicit guard ladder.** chain-depth-before-authz, the
   single-401 grantee carve-out, revocation checks — authored as visible guards, not folded into one
   `[ecodec authorize]` verdict. #31 and #32 both proved a folded verdict hides real carve-outs.

## Scope (type registry etc.)

Per the cross-language "render natively" lesson: `system/type/*` covers **core + operational + the
type-system bootstrap only** — a core peer never pre-publishes extension vocabularies. Where Pd can't
reflect its own data model (it barely has one — values live in `[ecodec]` handles), the type vectors
come from `[ecodec]` with the Go-rendered vectors as the byte-exact drift target.

## Verification harness (S4)

`harness/run-patch.mjs` — an oracle-driven interpreter over the **real `.pd` text** (parse `#N canvas`
/ `#X obj` / `#X connect` into a box+wire graph; evaluate against `validate-peer --profile core`). The
`[ecodec]` calls resolve to the real `libentitycore_codec` so the codec path is genuine; the
interpreter models Pd's depth-first right-to-left message scheduling. A run under the genuine `pd`
binary is the final confirmation caveat. **Cooperative-yield note (the #32 t2_2 lesson):** under rapid
open→handshake→close churn, the interpreter must model per-message yielding so responses flush before
the oracle tears connections down — watch §6.11 `t2_2`.

---

## S3 design — spec-grounded (from the pinned v0.8.0 study, 2026-07-14)

Read of §1.6, §3.1–3.3, §4.1, §5.2, §6.5, §6.6 of `spec-data/v0.8.0/ENTITY-CORE-PROTOCOL.md`. This
fixes the seam precisely: **`[ecodec]` owns bytes/CBOR/crypto/store/chain-verification primitives and
returns readable dispatch fields as atoms + everything else as handles; the canvas authors the §6.5
*sequence*, the §6.6 *tree walk*, the §5.2 *guard-ladder ordering*, and the status-code mapping.**

### Wire facts that shape the design

- **§1.6 frame** = `[4-byte BE length][CBOR payload]`; 16 MiB default cap (§4.10). The length is up to
  ~4 GiB → **never a Pd float** (A-PD-003): the frame assembler reads 4 raw byte-atoms and hands them
  to `[ecodec]`; length math lives in the external.
- **§3.1 envelope** = `system/protocol/envelope {root, included}`. `root` is the EXECUTE (or
  EXECUTE_RESPONSE) entity; `included` is a **map keyed by CBOR byte-string content-hashes** carrying
  capabilities, identities, signatures. Signature is NOT in EXECUTE — found by scanning `included` for
  a `system/signature` whose `data.target == execute.content_hash` (§3.2).
- **§3.2 EXECUTE** fields: `request_id` (str), `uri` (path), `operation` (str), `params` (entity),
  optional `resource`/`bounds`/`author`/`capability`. **Connection-path requests are the sole
  no-auth case** (§3.2/§4/§6.5); all others MUST carry `author`+`capability`.
- **§3.3 EXECUTE_RESPONSE** = `{request_id, status:uint, result:entity, budget_consumed?}`. Status set
  §3.3 table (200/400/401/403/404/409/429/500/501/503); errors carry `system/protocol/error {code,
  message?}`. **Only these two wire types exist — anything else → close the connection.**

### `[ecodec]` frame surface (the S3 API to build atop the S2 smoke stubs)

Each returns readable fields as Pd atoms (symbols/floats) and byte/entity/map values as **opaque
handles** (an int handle into an external-owned table). Grow incrementally as the spine needs each.

| `[ecodec]` message | In | Out (atoms unless noted) | Spec |
|---|---|---|---|
| `decode_frame` | frame bytes handle | `root_type` sym, `exec` handle, `included` handle, or `err` | §6.5 decode + hash-validate |
| `exec_field <name>` | exec handle | `request_id`/`operation` sym; `uri` sym; `author`/`capability`/`params` handle | §3.2 |
| `validate_hashes` | envelope handle | `ok` / `err code` | §1.8, §6.5 |
| `find_signature` | included handle, exec handle | sig handle / `none` | §3.2 target-match |
| `verify_sig` | sig handle, exec handle | `ok`/`fail` | §5.2, §7.3 |
| `cap_get` | included handle, cap hash | cap handle / `none` | §5.2 |
| `cap_dim <handlers\|operations\|peers\|resources>` | cap handle | list/handle for the guard ladder | §5.2 check_permission |
| `chain_verify` | cap handle, verify-ctx | `ok`/`fail` + depth | §5.5 delegation chain |
| `grantee_match` | cap handle, author hash | `ok` / `unresolvable` | §5.2 (the 401 carve-out) |
| `revoked?` | cap handle | `yes`/`no`/`unsupported` | §5.2 revocation |
| `pattern_match` | pattern sym, path sym | `1`/`0` | §5.4 |
| `tree_get` | path sym | entity handle + `type` sym / `null` | §6.6, §1.7 |
| `build_response` | request_id sym, status float, result handle | frame bytes handle | §3.3 |
| `error_result` | code sym, message sym | result handle | §3.3 error |

**Store note:** the entity tree + content store (§1.7) live in `[ecodec]` (a Pd patch can't hold a
keyed entity store). `tree_get` is the §6.6 primitive; the dispatcher-level **signature ingestion**
(§6.5, bind `system/signature` at `/{signer}/system/signature/{target_hex}`) also lives in `[ecodec]`
as one `ingest_signatures` call — it is content-store mutation, not dispatch logic.

### §6.5 dispatch spine — authored on the canvas (the visible sequence)

`decode_frame` → `validate_hashes` → **root type switch**:
`system/protocol/execute` → *(is uri the connect path AND connection not established?)* →
 **yes:** connection handler (no auth, §4.1) → **no:** the guard ladder →
`system/protocol/execute/response` → correlate by `request_id` (§6.5) → *(other)* → **close**.

The **guard ladder** (each rung a visible guard calling one `[ecodec]` primitive, fail-closed with the
§3.3 status on the canvas — NOT one folded `authorize` verdict):
1. `ingest_signatures` (§6.5 dispatcher step) — before resolution.
2. `verify_sig` — integrity; fail → 401.
3. `chain_verify` **before** authz (the flagged carve-out; #31/#32 both hid a chain-depth-before-authz
   bug in a folded verdict) — fail → 401/403 per §5.2a.
4. `grantee_match` — the **single 401 carve-out** (`unresolvable_grantee`) vs the 403 default.
5. `revoked?` — fail → 401 `capability_revoked`.
6. peer-id == local (§1.4) else reject.
7. `resolve_handler` (§6.6 tree walk, below) → null → **404**.
8. `check_permission` — all four grant dims (`handlers`/`operations`/`peers`/`resources`) from **one**
   grant entry (§6.5) → deny → **403 capability_denied** (or specific authz code, §5.2a).
9. dispatch to the per-handler abstraction; wrap the result in `build_response`.

### §6.6 tree walk — the canvas centerpiece (must be visible, not a seam)

Authored as the explicit backward longest-prefix loop, calling `tree_get` per prefix:
```
segments = split(path)              ; on the canvas
for i = len(segments) down to 1:    ; repeat-until / countdown
  prefix = join(segments[0..i])
  (entity, type) = ecodec tree_get prefix
  if type == "system/handler": return {handler, pattern=prefix, suffix=path[len(prefix)..]}
return null                          ; → 404
```
The **type-directed filter** (`type == "system/handler"`) is the visible discriminator — data entities
at intermediate paths are skipped. This is THE algorithm the wrapper-guard protects; it stays on the
canvas. The residual `pattern → which handler abstraction` selection is a genuine Pd limit (no
call-abstraction-by-dynamic-name, the #32 caveat) → label it **body-selection**, not resolution.

### Handshake / connection lifecycle (§4.1) — the reactive-mismatch core

Per-socket state machine keyed by connection: `pre-hello → hello-seen → authenticated → established`.
No `await` → each inbound frame consults the socket's leg and routes. The connect path
(`system/protocol/connect`) is the §6.5 no-auth special case; §4.6 authenticate signature verified via
`[ecodec] verify_sig`. **This is A-PD-004 — characterize how much stays legible vs collapses into
opaque per-socket state.** Read §4.1 in full at authoring time (offset 1562).

### Build order (S3)

1. Grow `[ecodec]`: `decode_frame`/`exec_field`/`build_response`/`tree_get` first (enough for a 404 +
   an unauth echo round-trip), then the §5.2 primitives.
2. `frame-assembler.pd` (§1.6) + `main.pd` front → prove a decoded EXECUTE reaches the spine.
3. `dispatch.pd` spine + `resolve_handler` tree walk → a real **404** for an unknown path (first
   oracle-meaningful behavior).
4. `conn-state.pd` handshake → first authenticated request.
5. The §5.2 guard ladder + one real handler (`handler-system-tree.pd` get) → the accept path.
6. S4 harness + `validate-peer --profile core` loop to 0-F.
