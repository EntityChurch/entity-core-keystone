# entity-core-protocol-ada — Phase S3 (Peer machinery) Summary

**Peer #10** (Ada 2012/2022, GNAT — safety-critical /
strong-typing; the two most-distant idiom axes in the batch: TASKS + PROTECTED
OBJECTS + RENDEZVOUS concurrency, and DESIGN-BY-CONTRACT aspects) · **Status:
COMPLETE — two-direction loopback smoke GREEN against the Go reference peer,
peer compiles clean (no warnings), S2 codec regression unbroken (69/69
conformance + 37/37 self-tests).**

## Gate result — the two-direction loopback (`./run-s3.sh`)

The Ada peer talks to the **Go reference peer** (`entity-peer`) over real
loopback TCP, in BOTH roles, inside one fedora:43 container (`--network=none`,
loopback only). The Go binaries are vendored from the Go oracle by a host
`go build` (CGO_ENABLED=0 → a static fedora:43-runnable ELF, the cohort
pattern); the Ada peer is built by gprbuild in-container, offline.

```
Scenario A — Ada initiator dials the Go reference peer:
  [PASS] session established (§4.1 handshake hello+authenticate)
  [PASS] remote peer_id observed (= the Go peer's id)
  [PASS] unregistered path → 404 (EXECUTE tree:get to an unbound system/handler/* leaf)
  [PASS] 6 interleaved requests each correlated by request_id (N7 / §6.11)
  [PASS] clean teardown

Scenario B — Go probe-peer dials the Ada Host (Ada as RESPONDER):
  [PASS] Go client completed §4.1 handshake against the Ada responder
  [PASS] Go client: unregistered path on the Ada responder → 404

S3 SMOKE: 3 check-group(s) PASS, 0 FAIL → GREEN
```

Both directions over the real Go reference (not Ada-to-Ada): the Ada DIALER +
handshake-as-initiator is wire-compatible with the Go responder (Scenario A),
and the Ada RESPONDER + the four MUST handlers are wire-compatible with the Go
client (Scenario B). The full `validate-peer --profile core` conformance run is
S4; this smoke proves the wire-level peer surface (transport + handshake +
dispatch + capability gating + request_id demux) end-to-end, leaving the peer
S4-ready.

## Go reference vendored

- **Commit:** `entity-core-go` HEAD **`a053670`** (`a05367082d00b4b61c17e3ce30ad302cf5ae470b`),
  working tree clean (`git -C … status -s` empty), verified at the S3 smoke run.
  (The S3 prompt cited `7e5ab04`; the actual oracle HEAD at run time was
  `a053670` — recorded honestly. The vendor is read-only — NO doctoring; the Go
  peer is ground truth, S5.)
- **Binaries:** `entity-peer` (the reference responder for Scenario A) +
  `probe-peer` (the reference client/dialer for Scenario B), both built
  `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` from `entity-core-go/cmd/`. Vendored to
  the gitignored `protocol-generator/ada/.s3-oracle/`.

## Task-topology decision (A-ADA-006, decided at S3): ONE TASK PER CONNECTION

The standout Ada idiom axis. Resolved A-ADA-006 in favour of **one task per
connection** over a bounded task pool:

- **Why one-task-per-connection.** GNAT maps tasks to OS threads, so a blocking
  socket read in one connection's task does NOT stall any other connection — the
  §7b cooperative-pool-starvation trap (the Swift `read()`-on-a-bounded-pool
  60s stall) is sidestepped **structurally**, not by a backpressure knob. A
  bounded pool would have to keep socket I/O per-task / non-blocking to avoid
  that trap; one-task-per-connection removes the question. The §4.8 store-safety
  is already handled by the protected-object store, so the connection tasks
  share no unsynchronized state. This is the simplest topology that satisfies N6
  (inbound concurrent with outbound) + N7 (reentrant demux) for a `--profile
  core` peer — the shape OCaml/Zig/CL/Java converged on (per-connection +
  per-request reader), reached here via Ada's first-class tasks.
- **The accept loop** is its own task; each accepted socket spawns a
  `Reader_Task`; the dialer spawns one for the client side (the client also
  serves, so it is §6.11-reentry-capable).

## §4.8 store data-race safety — the headline finding (the protected object)

The §4.8 content store + tree index live INSIDE a **protected object**
(`Entity_Core.Protocol.Store.Safe_Store`): reads are protected FUNCTIONS
(shared, concurrent), writes are protected PROCEDURES (exclusive). Mutual
exclusion is enforced by the LANGUAGE — there is no lock to forget and no map to
race. **The two store-race fall-overs that drove §4.8 into the v7.75 floor (Zig
double-free panic, CL hash-table corruption under per-request dispatch) are
STRUCTURALLY UNREPRESENTABLE here**: a caller cannot reach the underlying maps
except through the protected operations, which the runtime serializes. The
demux (`Demux_Table`) and the per-socket write serialization (`Write_Guard`) are
likewise protected objects — the §6.11/N7 request_id map and the shared-stream
write lock are language-enforced, not bolted-on. This is the cleanest §4.8 story
in the cohort and the centerpiece concurrency result of the peer.

## §4.10 substrate floor — baked in (the chain-depth pre-check confirmed)

- **§4.10 max inbound payload → 413 on the LENGTH PREFIX, before buffering the
  body.** `Wire.Read_Frame` reads the 4-byte BE length, checks it against
  `Max_Frame` (16 MiB) BEFORE allocating/reading the payload, and raises
  `Errors.Payload_Too_Large` (→ 413) on excess. The body is never buffered for
  an over-limit frame.
- **§4.10 max capability-chain depth → 400 chain_depth_exceeded (NOT 403),
  CONFIRMED via the one structural pre-check.** `Capability.Chain_Exceeds_Depth`
  is the single structural helper: it walks parent pointers counting depth (max
  64), doing **NO signature work**, gated in `Verify_Request` **BEFORE** the
  per-link authz walk (`Verify_Capability_Chain`). An over-deep chain →
  `Chain_Too_Deep` → 400; an *unreachable* parent is NOT a depth problem
  (returns False here, left for the chain walk to deny 403). The over-depth
  verdict is modelled as a distinct case of the discriminated `Request_Verdict`
  type, mapped at the single dispatch site — exactly the cohort's one net-new
  v7.75 peer code. **Get-it-right confirmed: 400 ≠ 403, pre-check ≠ authz walk,
  unreachable-parent stays 403.**
- **§4.9 resilience.** The reader skips a malformed frame and keeps reading
  (deliver-or-skip, never crash the connection on one bad frame); a handler
  fault is caught at the dispatch boundary and mapped to 500 with the connection
  kept alive (per-request isolation, N6). Resources are bounded by the frame cap
  and the chain-depth cap.
- **§7b TCP_NODELAY** is set on every connection socket (accepted + dialed) —
  Nagle off so small EXECUTE_RESPONSE frames flush promptly (the Zig finding).

## Design-by-contract — the Ada rigor seam (where it earns it)

Pre/Post/Type_Invariant aspects guard the load-bearing invariants and are
runtime-checked (`-gnata` on; SPARK proof out-of-scope v0.1 per the profile):

- the codec carries the S2 contract aspects (Content_Hash length, value-kind
  preconditions on every accessor) up into the peer untouched;
- `Entity.Make` Posts `Hash'Length = 33`; the wire builders (`Wire`,
  `Cbor_Util`) Post the value KIND of their results (K_Map / K_Array) so a
  mis-shaped builder is a contract failure, not a silent wire bug;
- the §5 verdict surface is a strongly-typed discriminated `Request_Verdict`
  (Allow / Authn_Fail / Authz_Deny / Chain_Too_Deep) — the §5.2 trichotomy +
  the §4.10 structural case are exhaustive case arms at the single dispatch
  site (the compiler enforces exhaustiveness), and the §5.5 unresolvable-grantee
  carve-out (401, not 403) is a distinct exception caught at the boundary.

## Pinned conformance invariants (N5–N8) — enforced at design time

- **N5 (envelope `included` preservation).** `Envelope.Of_Cbor` enforces the
  §3.1 included-key == content_hash check on parse (request + result side);
  `included` is carried verbatim through dispatch and is never dropped before the
  wire.
- **N6 (inbound concurrent with outbound).** One reader task per connection;
  outbound (the session's `Send`/await) runs on a DIFFERENT task than the
  reader, so an inbound dispatch never blocks the reader — the reader keeps
  reading/routing while a caller awaits a correlated reply.
- **N7 (reentrant transport + request_id demux).** The protected-object
  `Demux_Table` correlates EXECUTE_RESPONSE to its awaiting caller by
  request_id; verified by the 6-way interleaved-correlation check in Scenario A.
- **N8 (capability verdict determinism).** `Verify_Request` is a deterministic
  function of (local peer, store state, envelope) — the Layer-1 verdict carries
  no nondeterminism.

## §1.1 data model (A-JAVA-010 / A-ADA-009) — held

An entity's `data` is the RAW `Ecf_Value` (the discriminated variant from S2),
not a map. `Entity.Make` / `Of_Cbor` accept any ECF node; the field-read helpers
(`Cbor_Util`) are null-safe over a non-map data. A scalar-data entity round-trips
without a 500 — the map-only trap is structurally avoided.

## §7a conformance seam (built; wired at S4)

The §7a `system/validate/echo` (+ the dispatch-outbound slot) handler is
bootstrapped ONLY under the host `--validate` opt-in (OFF by default — a standing
dispatch-outbound originator must never ship live; the keystone cohort
mechanism). `echo` echoes its params entity verbatim (the cohort contract). The
default smoke path runs WITHOUT `--validate`, so the §7a handlers are
unreachable (404) there. The dispatch-outbound reentry wiring (the §6.11
validator-as-B-over-the-inbound-connection surface) lands at S4 — the seam (the
reentry-capable client reader + the per-connection outbound) is present now.

## lowercase-hex address space (A-ADA-003 / A-CL-009) — exercised

All peer-layer tree-path keys (`system/signature/{hash}`, the §6.9a policy path
`system/capability/policy/{identity_hash}`, the owner-sig pointer,
`system/capability/grants/{pattern}`) render hex via the codec's lowercase
`To_Hex` (re-exported through `Cbor_Util.Hex`) — never an Ada uppercase builtin.
Lowercase by construction, dodging the CL uppercase trap; the Go client's
lowercase-hex paths matched on the wire (Scenario B handshake + tree gets).

## What was built (`protocol-generator/ada/src/`, on the S2 codec)

| Unit | V7 layer | Responsibility |
|---|---|---|
| `entity_core-protocol(.ads)`              | — | parent of the peer layer; the concurrency-idiom overview |
| `…-cbor_util`                             | — | map/array builders + typed field reads over the S2 Ecf_Value + lowercase hex |
| `…-entity`                                | foundation | materialized {type,data,content_hash} (§1.1/§3.4); fidelity-validating `Of_Cbor` (§1.8/N5); RAW Ecf_Value data (A-ADA-009) |
| `…-envelope`                              | foundation | §3.1 envelope (root + included); included-key==content_hash on parse (N5) |
| `…-identity`                              | L1 | seed → §1.5 identity-multihash peer_id (A-ADA-001) / system/peer / §3.5 sign / verify (raw libsodium pubkey — no point-extraction) |
| `…-store`                                 | foundation | the §4.8 PROTECTED-OBJECT content store + tree index + sorted listing (§3.9) — the headline |
| `…-capability`                            | L3 | §5.2 Verify_Request (discriminated trichotomy + Chain_Too_Deep), §5.4 patterns, §5.5 chain walk, §5.6 attenuation, §5.7 TTL, §5.1 revocation, the §4.10 `Chain_Exceeds_Depth` pre-check; contract aspects |
| `…-wire`                                  | L2 | §1.6 framing (4-byte BE length, 413-on-prefix) + EXECUTE / EXECUTE_RESPONSE builders + GNAT.Sockets read/write |
| `…-handlers`                              | L1–L4 | the four MUST handlers (connect/tree/handler/capability) + §7a echo, the §6.5 dispatch chain, §6.6 backward resolution, §6.5 signature ingestion, §6.9/§6.9a bootstrap — the single-dispatch ladder (pattern + operation case) |
| `…-transport`                             | L4 | TCP listener + dialer; one task per connection; the protected-object `Demux_Table` (N7) + `Write_Guard`; TCP_NODELAY; the initiator dialer/handshake |
| `tests/host.adb`                          | — | standalone S4-ready host (`--port`/`--seed`/`--debug-open-grants`/`--validate`, `LISTENING <port>` line) |
| `tests/smoke_s3.adb`                      | — | the Scenario-A smoke (Ada dials Go) |
| `run-s3.sh`                               | — | the two-direction smoke gate (vendors Go binaries, runs both scenarios offline in-container) |

## Dev loop

```
# the two-direction loopback smoke gate (container-bound, sealed offline):
./run-s3.sh

# build the Ada peer only:
./run-s3.sh build

# reuse already-vendored Go binaries (skip the host go build):
NOBUILD_GO=1 ./run-s3.sh
```

## Exit criteria

Two-direction loopback smoke GREEN against the Go reference · peer compiles
clean (no warnings, `-gnatwa`) · S2 codec regression unbroken (69/69 + 37/37) ·
reads as idiomatic Ada (tasks + protected objects + rendezvous-style entry
synchronisation + discriminated verdict types + contract aspects + strong
typing), not transpiled.
