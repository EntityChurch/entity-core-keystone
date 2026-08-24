# entity-core-protocol-io — Spec Ambiguity Log

Per PROMPT-CONSTANTS: every unauthorized guess lands here. Prefix `A-IO-…`.

## A-IO-001: IoNumber is a C double — wire-integer carrier decision

**V8 section:** ENTITY-CBOR-ENCODING.md §7.6.1 (primitive/uint 0..2^64−1); ENTITY-CORE-PROTOCOL.md §2.4
**Profile field:** `[codec] integer_model = "double-plus-carrier"`
**Decision:** Io Number carries integers only for |x| ≤ 2^53 (exact in a double);
CBOR ints outside that range decode to an `EcBig` wrapper (sign + 8-byte
magnitude Sequence) and encode from it with the minimal head derived from the
magnitude. `Number` always means *integer* on the wire; floats are explicit
`EcFloat` wrappers (int-vs-float intent is never inferred from an Io value).
**Rationale:** the fixed-width-class durable lesson (head form + self-test on
[2^63, 2^64−1]) applied to a double-typed dynamic language; the JS-family
precedent (TS bigint) with no native bignum available here.
**Escalation:** none — implementation decision inside profile authority; S2
self-tests the tower (int.* corpus vectors cover 2^63−1, 2^63, 2^64−1).
**Status:** RESOLVED at S2 — corpus 71/71 incl. the uint64 tower via EcBig.

## A-IO-002: coroutine mid-frame write interleaving — per-connection writer FIFO

**V8 section:** §1.6 (frame atomicity is implied, not stated); §4.8/§6.11
**Profile field:** `[async] coroutine_write_lock`
**Decision:** every frame write goes through a per-connection FIFO writer queue
(one writing coroutine at a time). The Socket addon's `streamWrite` chunks at
`bytesPerWrite` and can yield mid-frame, so two concurrently-completing handlers
would interleave frame bytes without it.
**Rationale:** the spec assumes frames are contiguous on the wire but never says
"a frame MUST be written atomically with respect to concurrent dispatch" — every
concurrent substrate needs this rule; single-threaded event-loop peers get it
for free only if their write primitive never yields (Tcl's doesn't; Io's does).
**Escalation:** research — candidate one-liner for the §1.6 notes ("concurrent
dispatch MUST NOT interleave bytes of distinct frames"); cohort peers all comply,
so doc-class at most.

## A-IO-003: TCP_NODELAY not exposed by the frozen Socket addon

**V8 section:** ENTITY-CORE-PROTOCOL.md §7b transport menu (PHASE-S3 "§7b: set TCP_NODELAY on raw-socket peers")
**Profile field:** `[async] tcp_nodelay`
**Decision:** proceed without it. The frozen Socket addon (e348c23) exposes no
setsockopt surface for TCP_NODELAY, and patching the pinned archived addon for a
SHOULD-class latency knob is worse than documenting the gap. Loopback conformance
(the whole S4 surface) is unaffected by Nagle.
**Rationale:** §7b's NODELAY item is a latency recommendation, not a gated MUST;
the alternative (forking the archived addon) breaks the pin discipline.
**Escalation:** operator — revisit only if a real deployment shows Nagle-induced
latency; the fix would be a ~10-line addition to the addon compile.

## A-IO-004: message-send op dispatch must not expose inherited slots

**V8 section:** §6.2 ("unknown operation → 501"); §6.6 (dispatch is type-directed)
**Profile field:** `[idiom] message_send_everything`
**Decision:** the paradigm rendering dispatches an operation as a real message
send (`handler perform(opName, ctx)`), but ONLY after checking the op against the
handler's *declared operation set* (its interface entity). A bare `perform` would
expose every inherited Object slot (`clone`, `print`, …) as a callable
"operation" — a prototype-OO-specific dispatch hazard.
**Rationale:** the declared-op guard is what the manifest's `operations` map is
for; the hazard is exactly the kind of paradigm-shaped finding this probe exists
to record (delegation makes *everything* reachable unless scoped).
**Escalation:** research — worth a line in the substrate-takeaways when S5 closes
(prototype/delegation substrates: guard dynamic dispatch with the declared-op
set, or inherited slots become wire-reachable).

## A-IO-005: `System version` is unusable for provenance on the frozen tag

**V8 section:** absent (operational)
**Profile field:** `[language] io_version`
**Decision:** provenance strings cite the git tag (`2026.04.20-native-final`) +
image label, not `System version` (reports the build date `20260302`-style
number, not the tag).
**Rationale:** the tag is the pin; the runtime string is informational only.
**Escalation:** none.

## A-IO-006: Socket addon readBuffer is text-typed — binary-safe only via `asBinary`-free byte ops

**V8 section:** §1.6 (binary framing)
**Profile field:** `[async]` reader design
**Decision:** the reader treats `readBuffer` strictly as a byte Sequence (indexing
via `at`, slicing via `exSlice`), never via text ops (`asString`
re-interpretation, split, etc.). S1 proved byte-cleanliness of the buffer itself
(0x00/0xFF round-trip); the discipline is about which Sequence methods are legal.
**Rationale:** same byte-vs-text seam class as A-TCL-001, milder (Sequence is a
real byte array; only the *API surface* is text-flavored).
**Escalation:** none — coding discipline, enforced by the S2/S3 binary tests.

## A-IO-007: op-name collision between wire operations and Io method slots on handler clones

**V8 section:** §6.2 operation names (`get`, `put`, `register`, …)
**Profile field:** `[naming] method_names`
**Decision:** handler operation methods are named `op_<operation>` (`op_get`,
`op_put`, `op_hello`) on the handler prototypes; the dispatcher maps the wire
operation string to the slot name. Bare wire names would collide with inherited
Io slots (`Object print`… none of the core op names collide *today*, but `type`
does — `Object type` is the proto name — and future extension ops would be one
collision away).
**Rationale:** deterministic, collision-free, keeps A-IO-004's declared-op guard
simple.
**Escalation:** none — naming convention inside profile authority.

## A-IO-008: EvOutResponse compile hazard in the hand-built addon — not exercised

**V8 section:** absent (toolchain)
**Profile field:** `[deps] socket_addon`
**Decision:** the addon compiles all of the archived repo's C sources (incl. the
evhttp surface the peer never uses) because the io/ layer's protos file
references them at load; the peer exercises only Server/Socket/EventManager/
Event/IPAddress. Any latent bug in the unexercised evhttp legs is out of scope.
**Rationale:** minimal-diff faithfulness to the archived tree beats trimming.
**Escalation:** none.

## A-IO-009: `Map hasKey` misses inherited-slot shadowing — EcMap avoids Io Map entirely for wire data

**V8 section:** §3.1 (included map keyed by bytes)
**Profile field:** `[codec]` value model
**Decision:** wire maps never use Io's `Map` (string-keyed, unordered, and a
`Map atPut` with a raw-byte key would go through symbol interning of arbitrary
bytes); `EcMap` (ordered entry list + linear/keyed lookup) is the only wire-map
representation. Io `Map` is used only for internal peer state keyed by
hex/ascii strings (store index, pending tables).
**Rationale:** correctness of byte-keys + deterministic iteration for encode.
**Escalation:** none.

## A-IO-010: coroutine-per-request vs response ordering

**V8 section:** §6.11(b) (out-of-order replies are the caller's problem to demux)
**Profile field:** `[async] style`
**Decision:** each inbound EXECUTE runs in its own coroutine; responses are
written when ready (possibly out of request order) through the A-IO-002 writer
FIFO. No per-connection response re-ordering is attempted.
**Rationale:** §6.11(b) makes request_id the demux key — order is explicitly not
part of the contract; serializing responses would reintroduce the §4.8 deadlock
class for reentrant handlers.
**Escalation:** none — direct spec reading.

## A-IO-011: unresolvable-granter in `resolve_granter_peer_id` defaults to the local frame

**V8 section:** §5.5a (granter-frame canonicalization); §5.2 check_permission
**Profile field:** absent
**Decision:** when a verified cap's granter identity cannot be resolved to a
peer_id at *check_permission* time (it always can for chains that passed §5.5 —
the granter identity is required by the chain walk), fall back to the local peer
frame, matching the Tcl/pd cohort behavior.
**Rationale:** unreachable in practice post-§5.5; the fallback only affects
pathological inputs already destined for DENY.
**Escalation:** none — cohort-consistent.

## A-IO-013 (S3): Io `try(...)` returns nil/exception, NOT the block's value

**V8 section:** absent (language semantics)
**Profile field:** `[error_model]`
**Decision:** NEVER write `x := try(expr)` expecting x to be expr's value — Io's
`try` returns nil on success or the Exception object, discarding the value. Use
`x := nil; e := try(x = expr)` throughout. This trap surfaced TWO real conformance
bugs before it was caught: (1) the dispatch result was discarded → every EXECUTE
synthesized a 500 (connectivity total failure); (2) the authenticate key_type
guard's `peeridParse` result was discarded → key_type=0xFD returned 401
identity_mismatch instead of 400 unsupported_key_type (format_agility FAIL).
**Escalation:** none — language gotcha, coding discipline. Worth flagging to any
future Io-substrate agent (the sharpest Io-specific footgun found).
**Status:** RESOLVED — all try-for-value sites converted.

## A-IO-014 (S4): unresolvable-grantee is a returned verdict, not a raised exception

**V8 section:** §5.2 / PR-3 (unresolvable_grantee → 401 carve-out)
**Profile field:** absent
**Decision:** `verify_capability_chain` returns a distinct `"UNRESOLVABLE"`
verdict for a per-link grantee that does not resolve; `verify_request` maps it to
`UNRESOLVABLE_GRANTEE`; the dispatcher maps THAT to 401 `unresolvable_grantee`.
The earlier design RAISED an exception with a magic message and string-matched it
in the dispatch catch — but the message did not survive the addon/`IoState_error_`
boundary reliably, surfacing as **500** (the AUTHZ-GRANTEE-1 FAIL). A returned
verdict is robust.
**Escalation:** none — the spec is clear; this is the robust rendering.
**Status:** RESOLVED — AUTHZ-GRANTEE-1 passes.

## A-IO-015 (S3): stored Io Block loses invocation binding across handler call sites

**V8 section:** §6.11 / §6.13(b) (handler-initiated outbound dispatch)
**Profile field:** `[async]`
**Decision:** the §6.11 reentry seam is a Transport METHOD (`reentry(conn, env,
rid)`) called via `conn at("outbound_transport")`, NOT a stored `block(...)`
closure invoked with `send call(env)`. A block created in one method and invoked
from a different handler call site silently did NOT enter its body (`send call`
returned without running the block) — Io block `self`/scope binding across those
boundaries is fragile. A plain method call is robust. This was THE origination /
concurrent-reentry blocker (dispatch-outbound → 500); with the method it is 3/3.
**Escalation:** research — worth a substrate-takeaways note (prototype/message-send
substrates: prefer a method over a stored block for a seam invoked from foreign
call sites).
**Status:** RESOLVED — origination-core 3/3; concurrency t1_2/t1_3 PASS.

## A-IO-020 (S3): coroutine-per-connection yield-recursion wedge → single-coroutine poll loop

**V8 section:** §4.8 (inbound concurrent with outbound) / §7b
**Profile field:** `[async] style`
**Decision:** the Socket addon's coroutine-per-connection model
(`@serveConnection` per accept) deep-recurses `EventManager yield → ReadEvent/
WriteEvent handleEvent → yield` under the oracle's concurrent connections and
wedges (the peer stops responding). Replaced with a SINGLE-coroutine non-blocking
poll loop over `asyncAccept`/`asyncStreamRead`/`asyncStreamWrite` — the Pd/Scratch
single-threaded-event-peer model. This is the documented single-threaded-substrate
edge; the poll loop is the substrate-shaped answer.
**Escalation:** research — a genuine SUBSTRATE finding for the prototype-OO/
coroutine-runtime probe (Io's default concurrency primitive is disqualified for a
many-connection server at the scheduler level; the manual poll loop is the seam).
**Status:** RESOLVED (connectivity 22/22, t1_2/t1_3 PASS). The residual
sustained-load/churn drops were NOT a substrate ceiling but two fixable bugs in
this same poll loop — A-IO-025 (per-request `try` coroutine leak) + A-IO-026
(blocking send stall); both fixed → t2_1/t2_2 now PASS. (A-IO-023 retracted.)

## A-IO-021 (S4): retain-stack draining is load-bearing for throughput

**V8 section:** §4.9 (resilience under load)
**Profile field:** `[codec]` / `[async]`
**Decision:** the iovm allocators auto-stack-retain each new object onto the
current coroutine's retain stack, drained only at a message-send boundary. (1) In
the addon C decoder, a deeply-recursive decode accumulates the whole object tree
until the enclosing send returns; without an explicit
`pushRetainPool`/`popRetainPoolExceptFor(root)` in `decode`, the retain stack
grows → GC-mark thrash → ~6 req/s. (2) The transport poll loop's body is a METHOD
(`_pollPass`) so its pool drains every pass — the loop-as-one-activation would
never drain. Both are the same "drain the retain stack at the right boundary"
lesson.
**Escalation:** research — substrate-takeaway (Io C-addons + long-lived loops:
manage the retain pool explicitly at the O(1) boundary).
**Status:** RESOLVED for the common path (type_system 108/292/0, all core
categories pass in isolation).

## A-IO-022 (S4): per-request signature ingestion grows the store unboundedly

**V8 section:** §6.5 (dispatcher-level signature ingestion)
**Profile field:** absent
**Decision:** §6.5's ingestion binds signatures so a handler can find them by
tree lookup. The EXECUTE's OWN request signature (target == the root EXECUTE hash)
is consumed inline by verify_request and never looked up post-dispatch; binding
one per request grows the in-memory store by a unique entity per request →
thousands of live entities under sustained load → GC thrash → later-category
request timeouts. Skip binding the transient request signature; still ingest
cap/identity/handshake signatures (which are reused → idempotent).
**Escalation:** research — arguably a general note (a memory-primary peer should
scope §6.5 ingestion to handler-discoverable signatures, not the transient request
sig); doc-class, not a spec defect.
**Status:** RESOLVED — removes the per-request store growth.

## A-IO-024 (S4): connection reaping MUST be wall-clock, not poll-pass count

**V8 section:** §4.9(b) (bound resource use) / §4.6 (connection lifecycle)
**Profile field:** `[async]`
**Decision:** the poll loop reaps a connection idle beyond a WALL-CLOCK window
(60 s), never by poll-pass count. An earlier pass-count reap (3000 passes ≈ 0.3 s
at the poll rate) reaped an ACTIVE connection merely paused between the oracle's
requests → the peer closed it mid-check → 5 spurious `security` §5.5a
foreign-granter FAILs ("peer crashed or closed the connection … not fail-closed",
actually the reap) AND an apparent post-security wedge. The pass rate is not a
time proxy (it varies with load); a wall-clock idle window is the correct signal.
**Escalation:** none — implementation bug, fixed. Diagnostic lesson: an
apparent "wedge / crash / not-fail-closed" can be an over-eager resource reaper,
not the logic under test — prove the root by reverting the suspect (the S1
watch-item discipline: heavier work only *exposes* a latent bug).
**Status:** RESOLVED — security back to 28P/0F; no wedge; every gated category
passes 0-FAIL cumulatively.

## A-IO-023 (S4): sustained-load / churn — RETRACTED "throughput ceiling"; the real cause was two fixable bugs

**V8 section:** §4.9 (resilience) / GUIDE-CONFORMANCE §7b T2.1/T2.2
**Profile field:** `[async] concurrency_shape`
**Original (WRONG) claim:** `concurrency` t2_1 (sustained load: 10 000 requests)
and t2_2 (connection churn) FAIL because a single-threaded interpreted Io poll
loop doing per-request §5.2 crypto simply can't hit the oracle's deadline — a
"raw-throughput substrate ceiling."
**Why it was wrong (the reconciliation):** the sibling **Oz/Mozart** peer passes
t2_1 AND t2_2 with *slower* pipe-to-co-process crypto — so crypto rate was never
the binding constraint. And t2_1 is sustained **sequential** load, so a
"no-parallelism" argument cannot explain it either. Measurement (the method the
ceiling claim skipped) settled it: latency did not climb-then-plateau at a
crypto-bound rate; it **collapsed** (163→31 req/s, RSS 125 MB) — the signature of
*accumulation*, not a flat ceiling. Bisection found two independent, fixable
defects, **A-IO-025** and **A-IO-026** (below). With both fixed, t2_1 processes
10 000 requests with **0 drops** (1m3s) and t2_2 churn passes (6.8s) → `--profile
core` is a clean **0 FAIL**. t1_1 (demux) still WARNs informationally (no physical
parallel speedup on one event loop — the oracle marks this a non-violation, and
the no-serialization MUST is proven by the passing t1_3).
**Lesson (durable):** "single-threaded substrate ceiling" is a *hypothesis that
demands a measured req/s + the oracle deadline + a named mechanism* before it can
be recorded — an unreconciled ceiling contradicted by a slower-crypto sibling is a
missed bug, not a substrate law. Distinguish accumulation (latency climbs) from a
true ceiling (flat-but-slow) by measuring across the run.
**Status:** CLOSED — retracted; superseded by A-IO-025 + A-IO-026 (both FIXED).

## A-IO-025 (S4): Io `try` clones a Coroutine per call — per-request retain-stack leak

**V8 section:** cross-cutting (error-model implementation) / §4.9 robustness
**Profile field:** `[idiom] error_model`
**Decision:** Io's `try(expr)` is implemented as `coro := Coroutine clone; …;
coro run` (`Exception.io`) — it **spawns a new Coroutine on every call**, and that
coroutine's retain stack (holding the whole evaluated object tree) does not drain
promptly. A per-request `try` guarding the deep §6.5 dispatch stack therefore
leaked **~55 KB/request** → GC-mark thrash → the throughput collapse misfiled as
A-IO-023. Micro-measured: `try` over a shallow body ≈ 0.2 KB, over the deep
dispatch ≈ 55 KB (cost scales with the guarded stack depth).
**Fix:** make the entire per-request path **total (non-raising)** so no hot-path
`try` is needed — (a) a C-addon `tryDecode` returning nil (vs the raising `decode`
kept for the S2 reject corpus); (b) `Entity/Envelope fromWire` → nil on
structural breakage and an `hashOk=false` flag on a carried-hash mismatch, read by
§5.2 step-1 → AUTHZ_DENY (replacing a raise); (c) `Capability canonicalize` returns
a reserved (`./ ../ */`) path unchanged (it matches nothing → fail-closed) with an
explicit `isReservedPath` → 400 at the request boundary; (d) `drainFrames` sets a
conn `overlimit` flag instead of raising. Every per-request `try` in `Peer
dispatch`, `Transport _serviceFrame`, and `_pollPass` removed. In-process dispatch
is now flat (~196 req/s, RSS bounded); security/authz/universal_address_space stay
0 FAIL (the non-raising verdict path is byte-for-byte equivalent).
**Escalation:** none (implementation lesson) — carried to SUBSTRATE-TAKEAWAYS as a
fixed-substrate gotcha: on Io, never wrap a hot path in `try`; design the path as a
total function and reserve `try` for genuinely-rare, shallow, non-per-request cases.
**Status:** FIXED.

## A-IO-026 (S4): blocking send stalls the single-threaded poll loop (cross-connection head-of-line)

**V8 section:** §4.9 (resilience) / §6.11 / GUIDE-CONFORMANCE §7b T2.1
**Profile field:** `[async] concurrency_shape`
**Decision:** even with the A-IO-025 leak gone, t2_1 still dropped 6714/10000 with
`i/o timeout`. Root cause: `_sendFrame` flushed a response with a `while(out size
> 0) … System sleep(0.0005)` retry loop. On a **single coroutine** servicing all
connections, a partial/would-block write (one client reading slowly) put the loop
to sleep **holding up every other connection** — a cross-connection head-of-line
stall (t1_3's single-connection head-of-line passed because it never contends
across connections). At 10 000 requests over many connections the stalled peers
time out client-side → mass drops, *not* a throughput limit (196 req/s over the
6-min window could serve far more than 10 000).
**Fix:** **non-blocking buffered sends** — each conn carries a `wbuf`; `_sendFrame`
appends the frame and attempts one non-blocking `asyncStreamWrite`; unwritten bytes
stay buffered and flush at the **top of the next poll pass** (`_flushWrites`,
called before the per-conn read). The send never sleeps, so one slow reader only
buffers on its own conn (bounded by `maxWbuf` → drop) and never stalls the loop.
`reentry` (§6.11) flushes its buffered outbound each poll iteration. Result: t2_1
0/10000 drops, t2_2 churn PASS, origination-core still 3/3.
**Escalation:** none (implementation lesson) — carried to SUBSTRATE-TAKEAWAYS: a
single-threaded event peer MUST make **both** read and write non-blocking; a
blocking write is as fatal to fairness as a blocking read (the Pd/Scratch
cooperative-yield lesson, applied to the egress path).
**Status:** FIXED.

## A-IO-012 (S4): `Date now asNumber` resolution and ms mints

**V8 section:** §6.2 cross-cutting timestamp convention (ms since epoch)
**Profile field:** `[idiom] ms_timestamps`
**Decision:** `now_ms = (Date now asNumber * 1000) floor` — gettimeofday-backed,
genuine ms precision; verified at S2 smoke that two mints in the same second get
distinct `created_at` when ≥1 ms apart (the A-PD-016 aliasing trap).
**Escalation:** none — lesson carried, no ambiguity.
