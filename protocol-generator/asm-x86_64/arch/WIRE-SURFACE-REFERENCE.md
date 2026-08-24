# Wire-Surface Reference — the live-peer runtime the asm peer must reproduce

> **Provenance + status.** This is an *interop-context* cross-check derived from reading
> the sibling **Zig** peer (`protocol-generator/zig/src/{wire,model,transport,peer,host,
> capability,identity,store}.zig`) as a concrete reference implementation — NOT the
> oracle, and NOT a substitute for the spec. Authoritative behavior is the **spec-data**
> (`shared/spec-data/v0.8.0/`); this doc is a byte-level scaffold to accelerate the asm
> build, and every claim is re-anchored to the spec §-refs the Zig peer cites. Where this
> doc and the spec ever diverge, the spec wins and the divergence is a finding
> (SPEC-AMBIGUITY-LOG). Pinned to Zig peer symbols so it stays resolvable as files move.

## The Level-1 FFI boundary (the key scope finding — A-ASM-004)

The C-ABI (`libentitycore_codec`) decomposes **entities** (`ec_decode_entity` →
type-slice + data-slice + orig-bytes; `ec_encode_ecf`; `ec_content_hash`), plus crypto,
peer-id, base58, and `ec_envelope_{verify_root_hash,find_signature_for}`. It does **NOT**
parse the **envelope map** (`{"root": <entity>, "included": {<hash>: <entity>}}`) nor the
**EXECUTE/RESPONSE `data` map** (`{request_id, uri, operation, params, author,
capability, resource}`). Those are bare canonical-CBOR maps that the peer's own model
layer owns. So even at "Level 1 = FFI the whole codec", the asm peer MUST hand-roll a
**minimal canonical-CBOR map reader + writer** for the envelope/data-map layer:

- **Reader primitives:** read major-type+argument (the 5-bit head + 1/2/4/8-byte
  extension), iterate a map's key/value pairs, fetch a value by text-key, read
  text-string / byte-string / uint / nested map+array as raw slices.
- **Writer primitives:** emit uint, text-string, byte-string, array header, map header
  (canonical length-then-lex key order is required *within* a data map the peer builds —
  but the peer builds small fixed-shape maps, so keys are emitted in pre-sorted order,
  no general sort needed). Entity-level bytes come from `ec_encode_ecf`; `ec_content_hash`
  gives the 33-byte hash. The peer never hand-emits the shortest-float ladder or the
  recursive tag-reject — those stay behind the FFI (entities go through `ec_encode_ecf`).

This is the honest Level-1 hand-roll surface: transport + **envelope/data-map CBOR** +
dispatch + store + capability walk + §9.1 floor + identity + CLI. Entity ECF, content
hashing, Ed25519, SHA-256, peer-id, base58 are all FFI. Level-2 would pull the entity ECF
codec itself into asm; a fully-pure build adds SHA-256 + Ed25519.

---

## 1. Transport framing (§1.6)  — Zig: `wire.zig`, `transport.zig`

- Frame = `[4-byte BE uint32 length][length bytes: canonical-CBOR envelope]`.
- Max frame = **16 MiB** (`16*1024*1024`). Oversize → 413 (or drop if un-encodable).
- **Many requests per connection**, demuxed by `request_id`. Writes serialized.
- Server: TCP listen on `127.0.0.1:port`; accept → handle stream; read 4-byte len, then body.

## 2. Request envelope (canonical-CBOR map)  — Zig: `model.zig`, `wire.zig`

```
{ "root": <EXECUTE entity>, "included": { <33-byte hash>: <entity>, ... } }
```
EXECUTE entity: `type = "system/protocol/execute"`, `data` map =
- `request_id`  (text)  — correlation id, echoed in the response
- `uri`         (text)  — target path (e.g. "system/tree", "system/protocol/connect")
- `operation`   (text)  — "get"/"put"/"hello"/"authenticate"/"request"/...
- `params`      (entity) — operation params, itself an entity (type/data/content_hash)
- `author`      (bytes, opt) — 33-byte identity_hash of the request author (absent for connect)
- `capability`  (bytes, opt) — 33-byte content_hash of the authorizing token (absent for connect)
- `resource`    (map, opt) — `{ "targets": [text...], "exclude": [text...]? }`

Entity = `{ "type": text, "data": <map/value>, "content_hash": 33 bytes }` (the
content_hash is recomputed on parse, §1.8 — trust the recompute, not the wire bytes).

## 3. Response envelope (canonical-CBOR map)

```
{ "root": <EXECUTE_RESPONSE entity>, "included": { <hash>: <entity>, ... } }
```
Response entity: `type = "system/protocol/execute/response"`, `data` map =
- `request_id` (text) — **echoes the request's request_id exactly**
- `status`     (uint) — 200/400/401/403/404/409/500/501/503/504
- `result`     (value) — success entity, or `system/protocol/error` `{code:text, message:text?}`

## 4. Dispatch table (which the `--profile core` oracle drives)

| URI | operations | store effect | key verdicts |
|---|---|---|---|
| `system/protocol/connect` | `hello`, `authenticate` | issues 32-byte nonce; `authenticate` mints the §4.4 initial grant | 200 / 401 (auth_failed, invalid_nonce, unsupported_key_type, identity_mismatch) / 409 (already established) |
| `system/tree` | `get`, `put` | read / CAS-gated write of an entity by path | 200 / 404 (not_found) / 400 (invalid_path, ambiguous_resource, unexpected_params) / 409 (hash_mismatch) |
| `system/capability` | `request`, `delegate`, `revoke`, `configure` | mint/chain/revoke token; write policy entry | 200 / 403 (scope_exceeds_authority) / 400 (unexpected_params) / 501 (delegate cross-peer) |
| `system/handler` | `register`, `unregister` | write handler + interface + self-grant entities | 200 / 400 (ambiguous_resource, invalid_resource, unexpected_params) |
| `system/type` | — (stub) | — | 501 |
| `system/validate/echo` | `echo` | — (returns params verbatim) | 200 — **only if `--validate`** |
| `system/validate/dispatch-outbound` | `dispatch` | originates outbound via §6.11 reentry | 200 / 400 / 503 (no_outbound_seam) / 504 (timeout) — **only if `--validate`** |

### Handler details worth the asm build
- **hello** → 200, result `system/protocol/connect/hello` `{peer_id, nonce(32B),
  protocols:["entity-core/1.0"], timestamp(uint ms), hash_formats:["ecfv1-sha256"],
  key_types:["ed25519"]}`.
- **authenticate** (params `{peer_id, public_key(32B), key_type:"ed25519", nonce(32B echo)}`,
  + PoP signature in `included`) → 200, result `system/capability/grant {token: 33B}`; the
  minted token + this peer + the signature go in `included`.
- **tree get**: params opt `{mode:"hash"}`; path in `resource.targets[0]`; trailing "/" →
  `system/tree/listing {path, entries:{seg→{has_children,hash}}, count, offset:0}`.
- **tree put**: params `{entity:<entity>, expected_hash: 33B opt}`; CAS: all-zero hash ⇒ must
  be empty; nonzero ⇒ must match current; absent ⇒ unconditional. → `system/hash {33B}`.
- **capability request**: params `{grants:[grant...]}` (grant =
  `{handlers:{include:[..]}, resources:{include:[..]}, operations:{include:[..]},
  peers:{include:[..]}?}`) → `system/capability/grant {token:33B}` + token/peer/sig in included.

## 5. §9.1 pre-dispatch floor (order)  — Zig: `peer.zig` dispatchOutcome, `capability.zig`

1. **413** — frame length > 16 MiB (before decode).
2. **400** — CBOR/envelope malformed (bad map, missing root/included, wrong key type).
3. Non-`system/protocol/execute` root → ignored/routed (not dispatched as a request).
4. **Signature ingestion** — pull `system/signature` + signer peers from `included`, store.
5. **§5.2 3-way verdict:**
   - **401** — EXECUTE signature missing/invalid, or `signer != author`, or pubkey verify fails
     (`unresolvable_grantee` is a 401 carve-out).
   - **400 chain_depth_exceeded** — capability parent-chain depth > **64** (structural, before authz).
   - **403 capability_denied** — link authz fail / revoked / `grantee != author` / permission deny.
6. **URI normalize** — strip `entity://`, resolve peer-relative → `/{peer_id}/rest`; reject non-local.
7. **Handler resolve** — longest-prefix match over registered handler patterns; else **404**.
8. **§PR-8 granter frame** — resolve capability granter → peer_id (resource-match frame).
9. **§5.2 permission check** — operation × handler × resource-targets vs the capability's grant
   scopes (handlers/operations/peers on local frame; resources on granter frame). deny → **403**.

## 6. Capability / authority (§6.6, §6.9a)

- **Token** `system/capability/token`: `{granter(33B|multisig-map), grantee(33B),
  grants:[...], created_at(uint ms), parent(33B opt), expires_at?, not_before?,
  delegation_caveats?}`.
- **Grant**: `{handlers:{include:[],exclude:[]}, resources:{...}, operations:{...},
  peers:{...}?}` — patterns matched per §5.4.
- **`--debug-open-grants`**: default seed policy becomes degenerate `default → *`
  (handlers/resources/operations/peers all `["*"]` / `["*","/*/*"]`). Deprecated but the
  conformance harness sets it. Without it: discovery floor only (system/tree get on
  type/*+handler/* , system/capability request).
- **Seed-policy bootstrap (§6.9a)**: at peer create, write `…/policy/{identity_hash_hex}`
  (self-owner token, full scope over `/{peer_id}/*`, detached signature) and
  `…/policy/default` (fallback policy-entry). On authenticate: lookup hex identity_hash →
  base58 peer_id → default; union found grants with the discovery floor.
- **Discovery floor (§4.4)**: every authed peer gets ≥ `system/tree {get}` on `system/type/*`
  + `system/handler/*`, and `system/capability {request}`.
- **Mint-time subset (§6.2)**: on request/delegate, each requested grant MUST be a subset of
  the caller's on the local frame; else **403 scope_exceeds_authority**.

## 7. Identity loading  — Zig: `host.zig`, `identity.zig`, `peer_id.zig`

- File `~/.entity/peers/{NAME}/keypair`, PEM:
  `-----BEGIN ENTITY PRIVATE KEY-----` / base64 body (multi-line ok) / `-----END …-----`.
  base64 body → **32-byte Ed25519 seed** (reject if ≠ 32).
- seed → pubkey (`ec_ed25519_seed_to_pubkey`). peer_id = base58 of
  `varint(key_type=1) ‖ varint(hash_type=0) ‖ pubkey(32B)` (§1.5 canonical identity
  multihash — NOT a SHA-256 of the key). Use `ec_peerid_format`.
- `system/peer` entity `{type:"system/peer", data:{public_key:32B, key_type:"ed25519"}}`;
  its 33-byte content_hash is the **identity_hash** used as author/granter/grantee bytes.
- `system/signature` `{type, data:{target:33B, signer:33B, algorithm:"ed25519",
  signature:64B}}` — sign the target entity's 33-byte content_hash.

## 8. Startup contract  — Zig: `host.zig`

- Args: `--port N` (7777), `--name NAME`, `--validate`, `--debug-open-grants`, `-h`.
- Bind loopback listener, then print **exactly one** readiness line to stdout:
  `LISTENING 127.0.0.1:{port} peer_id={base58} open_grants={bool} validate={bool}\n`
  (run-s4.sh greps `^LISTENING`). Then accept loop.

## Concrete frame example (hello request)
```
[00 00 01 AB]  # 4-byte BE length
CBOR: { "root": { type:"system/protocol/execute",
                  data:{request_id:"h-1", uri:"system/protocol/connect",
                        operation:"hello", params:{type:"primitive/any",data:{},content_hash:..}},
                  content_hash:.. },
        "included": {} }
```
