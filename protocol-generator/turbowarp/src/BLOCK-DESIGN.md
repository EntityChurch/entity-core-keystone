# BLOCK-DESIGN — the entity-core peer, authored in Scratch

The goal: **the §6.5 dispatch logic IS a Scratch program** — readable, editable, studyable on
the canvas — with only the things Scratch physically cannot do exposed as small utility blocks.
Not a wrapper around a JS peer; the protocol, in the language.

## The seam (what stays JavaScript, and why)

Scratch has **no byte type, no map type, no sockets, no crypto**. Exactly those, and only those,
live in the `ecutils` custom extension (`extension/ec-utils-extension.js`). Everything else is
blocks. Values Scratch can't hold (envelopes, entities, hashes) ride through the blocks as **opaque
handles** (short string ids); the readable fields are plain reporters. The utility surface:

| Group | Blocks | Why it can't be Scratch |
|---|---|---|
| transport | `connect`, `disconnect`, `when execute arrives`, `inbound conn/execute`, `send response … to conn` | no raw WebSocket/TCP; §1.6 framing is byte work |
| read fields | `uri of`, `request id of`, `dispatch path of`, `params of`, `author present in`, `capability present in` | no map type to index an entity |
| crypto verdicts | `signature valid in`, `capability chain valid in`, `capability permits handler … in` | Ed25519 / SHA-256 / capability-chain math |
| resolve | `handler registered at`, `parent prefix of`, `handler pattern at`, `is connect path`, `conn … established?` | §6.6: the walk is authored; these are per-prefix store lookup + path slice |
| build | `ok response for … result …`, `error response … status/code/message`, `run handler body … on conn` | canonical CBOR encode + the handler store mechanics |

There is deliberately **no `dispatch` block**. If dispatch logic ends up in the extension, it's in
the wrong place — it belongs on the canvas.

## The dispatch, as blocks (a short spine + one procedure per handler)

Authored in `project/build-sb3.mjs` (compiled to sb3 blocks), this is a faithful, top-to-bottom
map of `dispatch/dispatcher.ts#dispatchCore`. The canvas is **seven separate scripts**, not one
tower: a green-flag setup, the **dispatch spine** (`when execute arrives`), and a **labeled
`define dispatch-<handler>` custom block for each handler** (connect / echo / tree / handlers /
capability), each placed as its own stack. The spine reads as a **guard ladder** — each denial is
`if <condition> { send <error>; stop this script }` — then it **routes to the matched handler's
procedure**. (`stop this script` inside a procedure stops that *procedure*, the Scratch early-return;
the spine's own `stop` after the call terminates dispatch — so a matched handler always ends the run.)

```
when execute arrives:                                // ── the dispatch spine ──
  set conn    = (inbound conn)
  set exec    = (inbound execute)
  set path    = (dispatch path of (exec))          // §1.4 local dispatch path
  set last path = (path)                            // dashboard

  if <(is connect path (path)) and (not (conn (conn) established?))>:   // §4.2 connect pre-auth
      dispatch connect ; stop
  if <not (author present in (exec))>:              send (error … 401 missing_author);         stop
  if <not (capability present in (exec))>:          send (error … 403 missing_authorization);  stop
  if <not (signature valid in (exec))>:             send (error … 401 invalid_signature);      stop   // §5.2
  … the full §5.2 verify sequence, each sub-verdict → its pinned code …

  resolve handler §6.6                              // ── walk the tree (below) → sets (pattern) ──
  if <(pattern) = []>:                              send (error … 404 not_found);              stop
  if <not (capability permits handler (pattern) in (exec))>: send (error … 403 capability_denied); stop // §5.2

  if <(pattern) = "system/validate/echo">: dispatch echo ; stop     // ── run the resolved body ──
  if <(pattern) = "system/tree">:          dispatch tree ; stop     //    (a match against the bodies
  if <(pattern) = "system/handler">:       dispatch handlers ; stop //    we hand-authored — Scratch
  if <(pattern) = "system/capability">:    dispatch capability ; stop //  can't call a proc by name)
  change dispatch count by 1                         // fall-through: a resolved-but-un-authored
  set last status = (status OK)                      //   handler (e.g. dynamically registered) delegates
  send (run handler body (pattern) for (exec) on conn (conn)) to (conn)

define resolve handler §6.6:                         // ── the §6.6 walk, AUTHORED (not a name lookup) ──
  set pattern = []
  set resolve path = (path)                          // start at the full dispatch path
  repeat until <not ((pattern) = []) or ((resolve path) = [])>:
     if   <handler registered at (resolve path)>:  set pattern = (handler pattern at (resolve path))
     else:                                         set resolve path = (parent prefix of (resolve path))
  // longest registered `system/handler` prefix wins == HandlerRegistry#resolve; the store lookup +
  // path slice are the only seam bits — the WALK is on the canvas.

define dispatch tree:                                // ── each handler is its own legible stack ──
  set op = (operation of (exec))
  if <(op) = "get">:  … the §6.3 get ladder …
  if <(op) = "put">:  … the §6.3 put ladder …
  send (error … 501 operation_not_supported)
```

Every `if`, every status code, the ordering — that's the protocol, visible — now split into a spine
plus five named procedures so each handler reads as a unit instead of a 400-block wall. The stage
shows the peer id + last path + last status + dispatch count as monitors, driven by the script's own
variables (Scratch-owned state, not a JS readout).

## Conformance — the authored blocks, measured (ADR-0012)

The `when execute arrives` guard ladder — including the full §5.2 verify sequence and the echo
handler — is authored on the canvas and **passes the oracle clean**:

> **`validate-peer --profile core` @ `cc1970f`: 682 total → 291 P / 294 W / 0 F / 97 S — Result:
> PASS** (all 97 skips exempt: 96 profile carve-out + 1 local-key). Zero failures — cleaner than the
> earlier JS wrapper (`249·2F`, the throughput pair).

**How it's run (`harness/run-blocks.mjs`):** a faithful interpreter loads the real `project.json`
and executes the genuine block graph (`control_if` / `control_stop` / `operator_*` / `data_*` /
`ecutils_*`) against live oracle frames through the bridge — the block program itself, not a
re-implementation. **Caveat:** this is the block *interpreter*, not the TurboWarp VM's own runtime;
a manual editor run is the final confirmation (the remaining, small, gap).

Getting to 0 F drove three fixes worth noting — each surfaced *because* the pipeline is now visible:
- the §5.2 verify sequence had to split into per-step blocks (single-401 grantee carve-out /
  400 chain-depth-before-authz / 403 capability_revoked) — folding them lost the pinned codes;
- the §1.6 16 MiB frame cap belongs in the transport util (an oversize frame stalled the JS peer);
- the §6.11 reentry + outbound seam (per-conn `ReentrantSender`) drives `dispatch-outbound`.

## Handlers authored on the canvas

- **echo** (`system/validate/echo`) — response = request params.
- **tree** (`system/tree`, §6.3) — the operation switch (`get`/`put`) + the get/put branching +
  every 400/403/404/409/501 decision + listing-vs-single, authored as blocks. The store iteration
  (listing w/ capability filter + deletion markers), path canonicalization, per-path permission,
  and CAS writes are `ecutils` seam blocks (Scratch has no store/bytes/map) that the canvas drives.
- **handler** (`system/handler`, §6.2) — the `register`/`unregister` operation switch + the
  resource validation (single target, `system/handler/{pattern}` shape → 400 ambiguous/invalid) +
  the params-type check + 501 fall-through, on the canvas. The five normative register writes
  (manifest / types / signed grant / grant-signature / interface) and their reversal are seam blocks.
- **capability** (`system/capability`, §6.2) — the `request`/`configure`/`revoke`/`delegate`
  operation switch + each op's guard ladder with its pinned code, on the canvas: request's
  403 `missing_authorization` / 400 `unresolvable_grantee` / 403 `scope_exceeds_authority`;
  configure's three 400 `invalid_params` guards (type / peer_pattern / ≥1 grant); revoke's
  400 non-zero-token guard; delegate → 501 (same-peer-only in v1) + the default 501. Token
  minting/signing, the scope-attenuation verdict, and the policy/revocation store writes are
  `ecutils` seam blocks (crypto/CBOR the canvas can't do). Oracle-exercised on the accept path
  (request mints a real token, configure writes a policy-entry, revoke writes a marker).

## Honest boundary (what is NOT yet on the canvas)

- **All five handler bodies are now authored** (§4 connect / echo / §6.3 tree / §6.2 handlers /
  §6.2 capability). `run handler body` survives only as the **catch-all** for any handler that
  resolves but isn't authored — nothing in the core surface hits it.
- **Concurrency:** the inbound hat processes one EXECUTE at a time (queue + single slot), which
  passes the oracle including §6.11 `t2_2_connection_churn` — *once the interpreter yields between
  hats* (see `harness/run-blocks.mjs`: a serial queue-drain flushes no responses until it finishes,
  so under connection churn responses miss their connection → dropped-request cascade; `await
  setImmediate` between hats, the model real Scratch already uses, fixes it). A true per-conn fan-out
  is blocked by Scratch's shared-variable model (no thread-locals → concurrent hats would clobber the
  working vars) — cooperative yielding is the right and only lever on this substrate.
- **Real-VM run:** the number above is via the block interpreter; confirm once in the TurboWarp
  editor against the bridge+oracle.

## Running it

`run-viz.sh` serves the `ecutils` extension (`dist/ecutils.js`) + the WS↔TCP bridge; load the
extension, open `project/entity-core-peer.sb3`, green flag. (Browser localhost is blocked from
`turbowarp.org` by default — use TurboWarp Desktop or the Firefox `network.lna.blocking` toggle; see
the README.) The dispatch runs as the blocks you can read.
