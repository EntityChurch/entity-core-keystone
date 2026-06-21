# Prolog peer — PHASE S3 report (peer machinery + the relational core)

**Phase:** S3 — peer machinery + the relational core (THE point of this peer)
**Verdict line:** **`S3: GREEN`**

Two Prolog peers talk over real loopback TCP through the full §6.5 dispatch chain.
The byte-floor (codec/crypto) stays sourced over the entity-codec C-ABI (S2, unbroken
— 69/69 + 10/10 KAT re-verified), and Prolog owns the **relational core**: §5.5
capability-chain verification as a recursive relation, the §5.2 auth/authz trichotomy
as distinct clause heads, §4.10(b) chain-depth as bounded recursion, §3.6 multisig
k-of-n, the §3.9 store as the clause DB, and §6.5/§6.6 dispatch as a multi-head clause
table. S4 (Go-oracle conformance) and S5 (packaging) are NOT started — S3-only, per scope.

---

## 1. Gate result

| Gate | Result | How verified |
|---|---|---|
| Type-registry (§9.5) | **53 / 53 byte-identical** | render all 53 core types from the in-code model, diff each content_hash digest against the cross-impl Go-rendered `type-registry-vectors-v1.diag`, in-container |
| Two-peer loopback smoke | **11 / 11** | boot a responder peer on a localhost port; an initiator peer drives §4.1 handshake + core ops over real TCP, `--network=none`, in-container |
| S2 codec regression | **69/69 + 10/10 KAT** | `run-s2.sh` re-run after the shim gained `ec_ed25519_seed_to_pubkey` — unbroken |

### Raw in-container gate output (`run-s3.sh`, clean from-scratch build)
```
── [2/3] type-registry (53 core types, §9.5) ──
type-registry: 53/53 byte-identical

── [3/3] two-peer loopback smoke (11 checks) ──
Responder on 127.0.0.1:43183 (peer 11F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4)
Handshake:
  [PASS] session established (capability minted)
  [PASS] remote peer_id matches responder
Dispatch:
  [PASS] unregistered path -> 404
  [PASS] granted tree get -> 200
  [PASS] tree get returns a system/handler/interface entity
  [PASS] capability request -> 200
Concurrency (request_id demux):
  [PASS] 8 interleaved requests each correlated -> 8/8
Extensibility (open-grants + --validate):
  [PASS] handler register -> 200 (live, not 501)
  [PASS] emit hook fired on register's tree writes (§6.13(c))
  [PASS] §7a echo -> 200
  [PASS] §7a echo returns params verbatim

Teardown clean.   ->   SMOKE: PASS (11/11)
==============================================================
 type-registry rc=0   smoke rc=0
 S3 GATE: GREEN
```

### The exact in-container commands
```
# full S3 gate (build C-ABI + shim, type-registry, loopback smoke):
podman run --rm --network=none -v "$PWD":/work:Z -w /work \
  entity-core-keystone/prolog-toolchain:latest \
  protocol-generator/prolog/run-s3.sh

# S2 regression (unbroken after the shim gained ec_ed25519_seed_to_pubkey):
podman run --rm --network=none -v "$PWD":/work:Z -w /work \
  entity-core-keystone/prolog-toolchain:latest \
  protocol-generator/prolog/run-s2.sh
#   → conformance rc=0   kat rc=0   →   S2-FFI GATE: GREEN
```

The loopback ran **end-to-end over real TCP in the container** (verified, not faked):
the responder binds a localhost port via `library(socket)`, the initiator dials it,
and both handshake legs + every core op + the 8-way request_id demux cross the wire as
length-framed CBOR envelopes. The hangs I hit while bringing it up (below) were all
real TCP/threading bugs found by running it, not stubbed around.

## 2. What was built (files under `protocol-generator/prolog/`)

| File | V7 layer | Responsibility |
|---|---|---|
| `prolog/ec_cbor.pl` | data-value codec | canonical CBOR encode/decode of the peer's value-term language — the one piece the C-ABI delegates to the caller (A-PL-013, below). DCG frame + imperative map-key canon-sort (the A-PL-004 shape, minimal). |
| `prolog/ec_entity.pl` | foundation | materialized entity `{type,data,content_hash}` (§1.1/§3.4) + §3.1 envelope; content_hash via the C-ABI over the ec_cbor-canonical data bytes; field reads = unification (`ent_field/3`). |
| `prolog/ec_identity.pl` | L1 | keypair→peer_id (§1.5 identity-multihash, A-PL-010) / peer entity / signing (§3.5, §7.3), all crypto over the C-ABI. |
| `prolog/ec_store.pl` | foundation | the §3.9 store **as the Prolog clause DB** (`assertz`/`retract`), `with_mutex/2` around every RMW (A-PL-007), one-level listing as a `findall`, the §6.10/§6.13(c) emit bus (live with zero consumers). |
| `prolog/ec_capability.pl` | L3 | **the relational core**: §5.2 trichotomy (clause heads), §5.5 chain walk (recursive relation), §4.10(b) chain-depth (bounded recursion → 400), §3.6 multisig k-of-n, §5.4 patterns, §5.6 attenuation, §5.7 caveats. |
| `prolog/ec_wire.pl` | L2 | §1.6 framing (4-byte BE length ‖ CBOR), EXECUTE/EXECUTE_RESPONSE/error builders. The "C with `:-`" part (A-PL-014). |
| `prolog/ec_transport.pl` | L4 | TCP listener + per-connection serve thread + the §6.11 request_id→message_queue demux (N6/N7) + the client dialer (A-PL-015). |
| `prolog/ec_peer.pl` | L1–L4 | bootstrap (§6.9/§6.9a), the four MUST handlers + §7a, the §6.5 dispatch chain, §6.6 resolution, **operation dispatch as a multi-head clause table** (the idiom probe). |
| `prolog/ec_client.pl` | — | the initiator §4.1 handshake + authenticated EXECUTE construction (drives the loopback). |
| `prolog/ec_types.pl` | §9.5 | the 53 core-type data-models (generated from the cross-impl shapes; render-from-model). |
| `test/type_registry.pl` | — | the 53/53 byte-diff harness. |
| `test/smoke.pl` | — | the two-peer loopback gate (the two scenarios above). |
| `test/dispatch_probe.pl` | — | an in-process (no-TCP) dispatch-chain probe (debugging aid; isolates dispatch logic from transport). |
| `run-s3.sh` | — | the container-bound, sealed-offline gate runner. |
| `c/ec_codec_pl.c` | — | **modified** — bound one more C-ABI symbol, `ec_ed25519_seed_to_pubkey` (S3 needs seed→pubkey for identity; S2 only needed sign/verify). |
| `prolog/ec_codec.pl` | — | **modified** — exposes `ec_ed25519_seed_to_pubkey/2`. |

## 3. THE RELATIONAL CORE — what the logic idiom revealed (the deliverable)

The PROFILE-RATIONALE predicted three places the logic idiom pays off. All three landed,
and the contrast with the cohort's single-/multiple-dispatch idioms is the finding.

### 3a. §5.5 capability-chain verification = a recursive relation (the headline)

The rationale called this "a textbook Prolog recursive relation." It is. The chain walk
collects parent links to the root, then `verify_chain/3` is the per-link recursion — a
chain is valid iff its head link is self-consistent AND attenuates its parent AND the
parent chain is valid:
```prolog
verify_chain(_LocalPeer, Ctx, [Single]) :- !,
    ( is_multisig(Single) -> true ; single_link_self_ok(Ctx, Single) ).
verify_chain(LocalPeer, Ctx, [Child, Parent | Rest]) :-
    \+ is_multisig(Child),                  % multi-sig is ROOT-ONLY
    single_link_self_ok(Ctx, Child),
    link_attenuates(LocalPeer, Ctx, Child, Parent),
    verify_chain(LocalPeer, Ctx, [Parent | Rest]).
```
This reads as the §5.5 inductive definition transcribed: base case = the root link,
inductive case = a link that attenuates the rest. Where the C/Go/CL peers write an
imperative `for i in chain { check link i against i+1; ... }` with an explicit `good`
flag threaded through, the Prolog version has **no flag and no loop counter** — the
recursion *is* the iteration and conjunction-failure *is* the deny. `link_attenuates`
is itself a relation between a child grant and a parent grant (grantee==granter, scope
subset per the §5.5a per-link frame, §5.7 caveats). This is the single place the peer
reads most unlike the cohort and most like the spec.

### 3b. §5.2 auth/authz trichotomy = distinct clause heads

The rationale said the trichotomy "maps onto distinct clause heads naturally." Realized:
`verify_request/4` is an ordered set of guarded clauses, each producing one verdict TERM,
read top-to-bottom as the §5.2 decision tree:
```prolog
verify_request(_,_, Env, authn_fail)    :- \+ author_signature_ok(Env), !.
verify_request(_,_, Env, authz_deny)    :- \+ envelope_capability(Env, _), !.
verify_request(_, S, Env, chain_too_deep):- ... chain_depth_exceeded(S, Cap, Inc), !.
verify_request(L, S, Env, authz_deny)   :- \+ verify_capability_chain(L,S,Cap,Inc), !.
verify_request(_,_, Env, authz_deny)    :- \+ grantee_binds_author(Env), !.
verify_request(L, S, Env, authz_deny)   :- is_revoked(L,S,Cap,Inc), !.
verify_request(_,_, _, allow).
```
The verdict is data (a term the dispatcher maps to a status), not control flow — there
is no nested `if/else` ladder, just the first clause whose body holds. Adding a verdict
arm = adding a clause. (The dispatcher then maps `authn_fail→401, authz_deny→403,
chain_too_deep→400, allow→dispatch`.)

### 3c. §4.10(b) chain-depth pre-check = bounded recursion → 400

`chain_depth_exceeded/3` is a 5-line bounded recursion over parent pointers that
*succeeds* iff the chain is over-deep, gated before the per-link authz walk. The
v7.75 cohort ruling (400 `chain_depth_exceeded`, NOT 403) is honored: the dispatcher
clause `verdict_outcome(chain_too_deep, ..., outcome(400, R, []))` returns 400 with
code `chain_depth_exceeded`. Confirmed structurally; the live oracle exercise is S4.

### 3d. §6.5/§6.6 dispatch = a multi-head clause table (the idiom contrast)

The cohort's distinct-idiom probe was CLOS multiple dispatch (CL); here it is the
**clause database**. Each `(handler, operation)` is its own clause head:
```prolog
handle_op("system/tree",       "get",      Ctx, Out) :- ...
handle_op("system/tree",       "put",      Ctx, Out) :- ...
handle_op("system/capability", "request",  Ctx, Out) :- ...
handle_op("system/handler",    "register", Ctx, Out) :- ...    % §6.13(a) live-hook
handle_op("system/validate/echo","echo",   Ctx, Out) :- ...    % §7a
handle_op(_Pattern, Op, _Ctx, outcome(501, R, [])) :- error_result(...).  % §6.6 default arm
```
The §6.6 resolver picks the handler pattern, the operation rides as a ground atom, and
first-argument indexing selects the clause. The "unknown (handler, op) → 501" arm is the
**final catch-all clause** — the analogue of CL's CLOS default method and the other peers'
`| other ->`. So the router is the predicate's clause set, selected by unification, not a
match-ladder inside one function (C#/TS/OCaml/Elixir) nor a metaobject method table (CL).
Three decompositions of the identical §6.6 surface; they converge on byte/behavior-identical
dispatch — mild corroboration that §6.6 is idiom-neutral.

### 3e. §3.9 store = the clause DB; §3.6 multisig = a quorum count relation

The store IS `assertz/retract` over `content_fact/3` + `tree_fact/3` (keyed by an opaque
StoreId so two peers share one process). The one-level listing is a `findall` + aggregate
— a relational read, not an imperative scan. §3.6 multisig k-of-n is `findall` of the
distinct signers with a valid signature over the root hash, then `length >= threshold` —
the quorum as a set-cardinality relation.

## 4. A-PL-006 — the open probe ANSWERED (does any error path want relational failure?)

**This was the genuinely-Prolog question, and the build gave a concrete two-part answer.**

**Yes — and the split is informative.** Relational FAILURE is the *pervasive, idiomatic*
"deny" channel in the §5.5 walk: a link that doesn't satisfy `single_link_self_ok` /
`link_attenuates` simply **fails**, and `\+ verify_capability_chain(...)` in
`verify_request` reads that failure directly as `authz_deny`. There is no `good` flag, no
`return DENY` — *failure is denial*, which is exactly the relational reading the spec's
"the chain is valid iff …" invites. This is cleaner than the cohort's boolean-flag walks
and is the strongest idiom win at the verification layer.

BUT there is **exactly one path that genuinely wants a distinct channel rather than plain
failure**: the **§5.5 unresolvable-grantee 401 carve-out**. A capability whose grantee
cannot be resolved must surface as **401** (authentication-class), *distinct* from a 403
authz denial. If that were modeled as relational failure it would be indistinguishable
from "denied" (403) — the two collapse. So it is modeled as a **thrown term**
(`throw(ec_capability(unresolvable_grantee))`) caught at the dispatcher and mapped to 401,
mirroring CL's `unresolvable-grantee` condition. 

**The finding:** the failure/exception boundary is NOT "all terminal throws" (the S1
expectation) — it is a clean two-channel split that the *verdict semantics* dictate:
ordinary "this link doesn't authorize" is relational failure (backtrackable, idiomatic);
a verdict that must be **a different HTTP-class than its neighbors** (401 amid 403s) needs
a non-failure channel (a thrown term), because Prolog failure is mono-valued — it can only
say "no", not "no, and specifically 401-no". This is the logic-paradigm analogue of the CL
conditions/restarts probe, and it lands on: *failure for the dominant deny, a thrown marker
only where the status class must diverge.* (Logged as A-PL-006 RESOLVED below.)

## 5. Determinism discipline (A-PL-005) — held, with a transport caveat

Wire/codec/dispatch predicates stay `det`: `cbor_encode/2`, `cbor_decode/2`, `make_entity/3`,
and the public codec surface are `once`-guarded; `dispatch/4` commits via cuts on the
verdict clauses; `verify_request/4` is committed (`!`) per verdict. One real correctness
fix the build forced: `client_send` is `once/1`-wrapped — without it, a failed `require_ok`
backtracked into `io_outbound`, which re-created the message queue and re-sent, manifesting
as an apparent infinite hang (a genuine "uncontrolled backtracking across an I/O side effect"
bug — exactly the A-PL-005 hazard, caught and fixed).

## 6. New / resolved spec-ambiguity + paradigm findings

- **A-PL-006 RESOLVED** — failure-vs-exception boundary answered (see §4): relational
  failure for the dominant "deny", a thrown term only for the §5.5 401 carve-out where the
  status class must diverge from its 403 neighbors.
- **A-PL-007 VALIDATED** — the store RMW (`store_bind`/`store_unbind`) runs inside
  `with_mutex/2`, keyed per StoreId. The 8-way demux exercised concurrent dispatch with no
  store corruption.
- **A-PL-013 (NEW)** — the C-ABI `ec_encode_ecf(type, data)` treats `data` as OPAQUE
  pre-encoded bytes (`ev_preencoded`); it canonicalizes only the outer `{data,type}` map,
  NOT the nested data value. So an FFI peer MUST hand the data value to the ABI *already in
  canonical CBOR* — the data-value canonicalization is delegated to the caller. This forced
  `ec_cbor.pl` (a peer-side canonical CBOR value codec) even though the byte-floor is "FFI'd."
  The 53/53 type-registry is the byte-proof that the Prolog data-value canon matches the
  cross-impl encoder. Worth surfacing to arch + the other FFI peers: "FFI the codec" does
  not eliminate a canonical-CBOR obligation at the data-value layer.
- **A-PL-014 (NEW, paradigm)** — framed binary TCP I/O is the irreducibly-imperative part,
  as predicted. `read_frame`/`write_frame` (read-exactly-N + 4-byte BE length) are "C with
  `:-`": the predicate arrows are punctuation, not logic. This is fine and expected — it is
  the same imperative floor every peer has; Prolog does not make it worse, just visibly
  procedural.
- **A-PL-015 (NEW, paradigm + correctness)** — SWI **module-meta-call** semantics bit twice
  and are a real adoption hazard for this style: a closure passed across a thread boundary
  (the transport's serve goal; the store's emit consumer) is called with `call/N` in the
  *callee* module unless the receiving predicate is declared `:- meta_predicate`. Both the
  serve goal and the emit consumer silently resolved in the wrong module
  (`ec_transport:serve_goal`, `ec_store:on_tree_event` — neither existing) and failed/threw,
  surfacing as a 10s-timeout hang and a 500. Fix: `meta_predicate` on `start_listener/3` and
  `register_*_consumer/2`. Logged because it is the kind of cross-module callback bug a
  logic-paradigm peer hits that the OO/functional peers don't phrase the same way.
- **A-PL-016 (NEW, correctness)** — SWI **global variables (`nb_setval`/`nb_getval`) are
  thread-local**. The request-id counter and the smoke's emit counter, set on one thread and
  read on the per-connection/dispatch thread, must live in the **shared clause DB**
  (`assertz`/`retract` under a mutex), not in global vars. The 8-way demux failed 0/8 until
  this was fixed. Consistent with the store-as-clause-DB idiom: shared mutable state belongs
  in the clause DB, full stop.

## 7. Rabbit holes / things I stubbed or simplified (be skeptical here)

- **Temporal validity (`not_before`/`expires_at`) is a no-op pass on the chain walk**
  (`temporal_ok/1` succeeds unconditionally). The smoke uses non-expiring caps and the CL
  cohort likewise leaves now-ms-driven temporal off the smoke path. This is **documented,
  not faked** — but it is a real simplification that S4 (oracle conformance) must light up
  and verify. Flagging explicitly: if the oracle has a temporal-expiry vector, this will need
  the actual `now_ms` comparison wired (the predicate is there, just stubbed to `true`).
- **The data-value CBOR codec (`ec_cbor.pl`) is new peer-owned canonical-encoding code.**
  The 53/53 registry proves its map-key ordering + minimal-int encoding match the cross-impl
  encoder byte-for-byte, but it is the one place a subtle canonical bug could hide (e.g. a
  data shape the registry doesn't exercise). S4's full wire conformance against the oracle is
  the real test of it. The float path is lifted from the proven S2 spike and is not on any
  protocol hot path (protocol data carries no floats).
- **The smoke's "granted tree get" probes a handler-interface entity inside the discovery
  floor**, mirroring the CL smoke exactly — it is NOT the full `system/type/*` publish that
  the S4 type_system oracle category needs. S4 needs the type-registry entities served over
  the wire; S3 proves the dispatch+authz path with a floor-reachable entity.
- **`dispatch_probe.pl`** is a debugging aid (in-process, no TCP) left in `test/`; it is not
  part of the gate. It was invaluable for isolating dispatch-logic bugs (the envelope-wrap
  bug, the included-order bug) from transport bugs (the meta-call hangs).
- **I did NOT run S4.** No oracle, no `validate-peer`. The 11/11 smoke is self-contained
  (two Prolog peers), exactly the S3 scope. The smoke proves the wire surface is wired
  end-to-end; it does NOT prove byte-conformance against the Go oracle (that is S4).

---

**Verdict:** **`S3: GREEN`** — type-registry **53/53** byte-identical + two-peer loopback
smoke **11/11**, verified end-to-end over real loopback TCP through swipl + the foreign
codec, in-container, `--network=none`, reproducible from a clean build. S2 codec regression
unbroken (69/69 + 10/10 KAT). The relational core landed where the rationale predicted; the
A-PL-006 failure/exception split is the substantive paradigm finding. Ready for S4 on operator GO.
