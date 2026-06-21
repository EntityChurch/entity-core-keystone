# entity-core-protocol-common-lisp — Phase S3 (Peer machinery) Summary

**Peer #5** (Common Lisp) · **Status: COMPLETE — two-peer
loopback smoke GREEN (11/11 checks), peer compiles clean, S2 codec regression
unbroken (69/69 + selftest + Ed448 KAT).**

## Gate result — the two-peer loopback

Two Common Lisp peers talk over real loopback TCP through the full §6.5 dispatch
chain. Run offline (`--network=none`, loopback only) via `./run-s3.sh`:

```
Scenario 1 — core ops (responder = default seed policy):
  [PASS] session established (capability minted)        (§4.1 handshake)
  [PASS] remote peer_id matches responder               (§4.6 identity binding)
  [PASS] unregistered path -> 404                        (§6.6 no handler resolved)
  [PASS] granted tree get -> 200                         (§4.4 discovery floor authority)
  [PASS] tree get returns a system/handler/interface entity
  [PASS] capability request -> 200                       (§6.2 mint-bounded)
  [PASS] 8 interleaved requests each correlated -> 8/8   (N7 / §6.11 request_id demux)

Scenario 2 — Core Extensibility Boundary (responder = --debug-open-grants + --validate):
  [PASS] handler register -> 200 (live, not 501)         (§6.13(a) register live-hook)
  [PASS] emit hook fired on register's tree writes        (§6.13(c) emit live-hook)
  [PASS] §7a echo -> 200                                  (§7a resolve→dispatch)
  [PASS] §7a echo returns params verbatim
SMOKE: PASS
```

The full `validate-peer --profile core` conformance run is S4; this smoke proves the
wire-level peer surface (transport + handshake + register/dispatch/emit + capability
gating + request_id demux) is wired end-to-end, leaving the peer S4-ready.

## What was built (`src/`, ASDF system `entity-core/peer`, package `entity-core/peer` / `ECP`)

The peer machinery lives in its OWN package (`ECP`) layered above the S2 codec
package (`EC`), so the codec stays a clean unit and the peer surface is the new S3
namespace. Built on the proven S2 codec + crypto with zero new third-party deps
(sb-thread + sb-bsd-sockets ship inside SBCL; ironclad already pinned).

| File | V7 layer | Responsibility |
|---|---|---|
| `peer-package.lisp`    | — | the `ECP` package; lisp-case exports |
| `peer-model.lisp`      | foundation | materialized entity `{type,data,content_hash}` (§1.1/§3.4) + envelope (§3.1); fidelity-validating `entity-of-cbor` (§1.8) on the S2 cbor-map value model |
| `peer-identity.lisp`   | L1 | keypair → peer_id (§1.5 identity-multihash, A-CL-002) / peer entity / signing (§3.5, §7.3) |
| `peer-store.lisp`      | foundation | content store (hash→entity) + entity tree (path→hash) + one-level listing (§1.7/§3.9) + the §6.10/§6.13(c) **emit bus** (live even with zero consumers) |
| `peer-capability.lisp` | L3 | §5.2 `verify-request` (3-way authn/authz verdict), `check-permission`, §5.4 patterns + `canonicalize` + §1.4 `normalize-uri`, §5.5 chain walk, §5.6 attenuation, §5.1 `is-revoked` |
| `peer-wire.lisp`       | L2 | §1.6 framing (4-byte BE length ‖ CBOR); EXECUTE / EXECUTE_RESPONSE / error builders |
| `peer.lisp`            | L1–L4 | the four MUST handlers (connect/tree/handler/capability) **as CLOS classes**, the §6.5 dispatch chain, §6.5 signature ingestion, §6.6 resolution, §6.9 bootstrap, §6.9a peer-authority bootstrap, §7a conformance handlers, §6.13(b) outbound seam, per-connection state |
| `peer-transport.lisp`  | L4 | TCP listener + per-connection serve thread (sb-bsd-sockets + sb-thread) + the §6.11 request_id demux + the **client dialer/handshake** that drives the loopback |
| `test/smoke.lisp`      | — | the two-peer loopback gate (two scenarios above) |
| `run-s3.sh`            | — | container-bound, offline smoke runner |

## Concurrency — native sb-thread (A-CL-003 VALIDATED)

The peer is built on **one native SBCL thread per connection** (`sb-thread:make-thread`):
- the **accept loop** spawns one **serve thread** per accepted connection;
- each serve thread runs a **reader loop** that demuxes inbound frames (§6.11): an
  EXECUTE_RESPONSE routes to its awaiting outbound caller by `request_id`; an inbound
  EXECUTE is dispatched on **its own thread** (§4.8) so a handler that originates an
  outbound EXECUTE (§6.13(b)) and awaits its response does NOT block the reader;
- writes (inbound responses + outbound requests share the stream) are serialized by
  an `sb-thread:make-mutex`;
- the `request_id → (slot . waitqueue)` correlation table is guarded by a mutex; a
  blocking caller waits on an `sb-thread:make-waitqueue` via `condition-wait`,
  woken by `condition-broadcast` (on response arrival OR connection close).

This is the CL analogue of the C#-`Task` / TS-`Promise` / OCaml-stdlib-`Thread` /
Elixir-process fork, and matches the shape **OCaml arrived at** (A-OC-003-revised):
for a `--profile core` peer the N6/N7 invariants are met by one-thread-per-connection
+ a condvar correlation table, with no structured-concurrency machinery and **no
third-party dep** (bordeaux-threads stays deferred until ECL/CCL/ABCL portability is
wanted). The 8-way request_id demux check exercises it: 8 EXECUTEs issued
concurrently from 8 initiator threads each correlate to their own response.

## CLOS multiple dispatch — the distant-idiom probe (what it revealed)

The headline distinct idiom: **operation dispatch is a CLOS generic function with
MULTIPLE DISPATCH on (handler-class × operation)**. Each MUST handler is a CLOS
class (`connect-handler`, `tree-handler`, `capability-handler`, `handlers-handler`,
…); each operation is a method on `HANDLE-OP` specialized by the handler's class
AND an **EQL specializer on the operation keyword** (`(op (eql :hello))`,
`(op (eql :get))`, …). The §6.6 backward tree-walk resolves a request URI to a
bootstrapped handler **instance**; `(handle-op instance op-keyword ctx)` then
dispatches through the CLOS method table.

What the distant idiom revealed vs the prior peers:
- Where C#/TS/OCaml/Elixir each express the operation router as a single-dispatch
  `switch`/`match op with` **ladder inside one function per handler**, CL externalizes
  the same surface into the **method table the metaobject system already maintains**.
  Adding an operation = adding a method, not editing a ladder; the "unknown operation
  → 501" arm is the **default method** `(handle-op (h handler) op ctx)`, not a
  fall-through `| other ->`. This is a genuinely different decomposition of the exact
  same §6.6 dispatch surface — the router is data (the GF's method set), not control
  flow.
- The probe surfaced **no new spec ambiguity** — the §6.5/§6.6 dispatch contract maps
  cleanly onto multiple dispatch; the (handler, op) pair the spec already treats as
  the dispatch key is literally the CLOS specializer tuple. The convergence is the
  finding: four single-dispatch idioms and one multiple-dispatch idiom land on
  byte/behavior-identical dispatch, which is mild corroboration that the §6.6 surface
  is idiom-neutral (a tightness signal, not a defect).
- One CL-specific footgun hit + handled: **`cl:identity` is a locked standard
  symbol**, so the L1 identity struct could not be named `identity`. Named the struct
  `keypair` with `(:conc-name identity-)` so the public accessors stay `identity-hash`
  / `identity-peer-id` / … (the cohort's surface) while the type name dodges the lock.

## v7.74 resync (A-CL-001) — all four foundations reachable

Resynced the peer layer to the **v7.74 peer surface**, mirroring the
C#/TS/OCaml/Elixir builds (the v7.73/v7.74 spec-data snapshot is still missing —
escalation re-stated in the ambiguity log):

- **register live-hook (§6.13(a))** — `system/handler:register` performs the five
  normative writes (handler manifest, associated types, self-issued signed grant,
  grant-signature at the §3.5 pointer, interface index); NOT a 501 stub. Verified
  200 over the wire (scenario 2). `unregister` reverses them.
- **outbound-dispatch seam (§6.13(b))** — `outbound-dispatch` builds+signs an
  outbound EXECUTE and sends it through the §6.11 reentry seam on the serving
  connection (`conn-outbound`, set by the transport). Present on every peer even
  with no core originator; reachable the moment a handler is registered.
- **emit live-hook (§6.10 / §6.13(c))** — the store's emit bus produces tree- and
  content-change events on every bind/put. **Live even with zero consumers** (events
  are produced and discarded); a consumer is registerable post-bootstrap. Core
  registers zero consumers, but the seam is exercised on every write — verified by
  the scenario-2 check that the register's tree writes fire the hook.
- **§7a conformance handlers** — `system/validate/echo` (the §6.13(a)
  resolve→dispatch half) and `system/validate/dispatch-outbound` (the §6.13(b)/§6.11
  outbound seam via reentry) are bootstrapped ONLY under `--validate` (off by
  default → unreachable, 404). Echo verified 200 + params-verbatim over the wire;
  cap convention = in-band params (matches the signed-off cohort, zero rework).
- **owner-cap bootstrap (§6.9a)** — the self-owner capability (root cap, full scope
  over `/{peer_id}/*`, grantee = own identity; §6.9a.0 detached-sig shape: cap token
  at the hex policy path + its self-signature at the §3.5 pointer) and the default
  scope-template entry are written at bootstrap and read back by authenticate via the
  v7.64 dual-form lookup (hex → Base58 → default), UNION'd with the §4.4 discovery
  floor. `--debug-open-grants` selects the degenerate `[default → *]` (the cohort's
  non-conformant debug wildcard).

## F27 / owner-authority — matched the cohort, no friction

Per the carry-in, F27 (Peer Authority Bootstrap) is an OPEN arch finding deferred
past v7.74; this peer does NOT try to solve it. It mirrors the cohort exactly:
write/grant-gated ops (register, configure, delegate) are reached via the
**`--debug-open-grants`** degenerate seed (`make-peer :open-grants t`), the explicitly
non-conformant debug wildcard the other keystone peers use. The §6.9a seed-policy
machinery (identity-keyed policy entries materialized in the tree, read at
authenticate) is built exactly as OCaml's signed-off shape, so when F27's
Phase-2 PROPOSAL lands the peer generalizes rather than conflicts. **No F27 friction
hit** — the default-seed scenario (discovery floor only) and the open-grants scenario
(register/echo) both pass, confirming the authn(401)/authz(403) split is clean.

## Agility — deferred (following Elixir's lead)

The full agility matrix (MATRIX-M2/M3/M6 7-gate tuples, cap-token content_hash,
key_type registry refusals) is **deferred** to a later phase, exactly the deferral
Elixir made: it needs the §3.6 cap-token content_hash shape + key_type registry
surface, and it does NOT block the core loopback. The **crypto primitives** the
agility corpus needs (native Ed448 + SHA-384 via ironclad) are already proven
byte-equal at S2 (A-CL-005 KAT PASS), so the deferral is peer-layer wiring only, not
a crypto gap. The authenticate handler already rejects an unsupported key_type riding
in the key_type field / a non-32-byte public_key / a non-0x01 peer_id (§4.6
hardening / AGILITY-UNKNOWN-1), which is the connect-path slice of the matrix.

## Pinned conformance invariants (N5–N8) — enforced at design time

- **N5 (envelope `included` preservation)** — entities round-trip through
  `entity-to-cbor`/`entity-of-cbor` with content_hash fidelity (§1.8); the §3.1
  included-key == content_hash check is enforced on parse.
- **N6 (inbound concurrent with outbound dispatch)** — each inbound EXECUTE
  dispatches on its own thread; the reader keeps reading (§4.8).
- **N7 (reentrant transport + request_id demux)** — the mutex-guarded request_id →
  waitqueue table; verified by the 8-way demux check.
- **N8 (capability verdict determinism)** — `verify-request` is a pure function of
  (envelope, store); §5.10 Layer-1 bare ALLOW/DENY, no nondeterminism.

## Dev loop

```
# the two-peer loopback smoke gate (container-bound, sealed offline):
./run-s3.sh

# S2 codec regression (still 69/69 + selftest + Ed448 KAT):
./run-s2.sh
```

## Exit criteria

Two-peer loopback smoke GREEN (11/11) · peer compiles clean (no peer-code
warnings) · reads as Common Lisp (CLOS GFs + conditions + sb-thread, not transpiled)
· S2 codec regression unbroken (69/69 + selftest + Ed448 KAT) · ambiguity log
updated (A-CL-001 escalation re-stated; A-CL-003/F27 resolutions recorded; one new
idiom finding A-CL-008) · container reproducible. **S3 PASS.**

## Not in this phase (S4, next session)

- `validate-peer --profile core` conformance run against the Go oracle (the live
  superset of this smoke); rebuild the oracle from Go HEAD with the §7a wire-gate.
- The 53 core type entities (§9.5 type-registry render-from-model) — the smoke
  probes a handler-interface path inside the discovery floor instead; S4 needs the
  full `system/type/*` publish for the type_system oracle category.
- The full crypto-agility matrix wiring (deferred per above).
- The v7.73/v7.74 spec-data snapshot remains missing (A-CL-001 escalation to arch).
