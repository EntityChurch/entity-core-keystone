# Idiom-Findings Synthesis — the protocol as a convergent logic layer

**Peer #13** (SWI-Prolog) · The cohort's **first logic-programming peer**.

> **This document is the actual point of the Prolog peer.** The operator goal
> (`HANDOFF-PROLOG-REVIVAL.md` §2) was *not* "prove the bytes round-trip in Prolog" — we already
> knew that was achievable (the S2 spike hit 20/20 byte-exact on the hardest vector classes). The
> goal was: **show that the protocol can be implemented in Prolog as a convergent logic layer, and
> report what the logic idiom reveals.** This is that report. It is honest about the FFI floor, the
> WARNs, and the one place Prolog's model is genuinely too weak — because an idealized story would
> be worthless to the team.

The headline: **the protocol does not resist Prolog. Only the byte-floor does — and that is the
C-ABI's legitimate job.** The peer reached the same 0-FAIL conformance fixed point as the OO/scripting
cohort (653·0F·93S @ `entity-core-go @75c532e`), with the byte-floor over the C-ABI
(`strategy = "ffi"`) and **the protocol's operational semantics expressed as Horn-clause relations**.
Below, with code excerpts from the real peer, is where the logic idiom genuinely paid off, where it
read as "C with `:-`," the one place it was too weak, and what that tells the team.

---

## 1. Where the protocol genuinely expressed as logic

### 1.1 §5.5 capability-chain verification — conjunction-failure IS the deny

The single cleanest idiom win. §5.5 says a capability is valid *iff* each link is self-consistent
*and* attenuates its parent *and* the parent chain is valid, recursively to a root the local peer
controls. That "valid iff …, recursively" is a textbook Prolog recursive relation — and the crucial
property is that **a link that does not satisfy the relation simply FAILS, and failure reads directly
as denial.** No boolean `good` flag threaded through a loop, no `if (!ok) return DENY` (`ec_capability.pl`):

```prolog
% verify_chain — the recursive relation over links. A chain is valid iff the head
% link is self-consistent AND it attenuates its parent AND the parent chain is valid.
verify_chain(_LocalPeer, Ctx, [Single]) :- !,
    ( is_multisig(Single) -> true ; single_link_self_ok(Ctx, Single) ).
verify_chain(LocalPeer, Ctx, [Child, Parent | Rest]) :-
    \+ is_multisig(Child),                          % multi-sig is root-only
    single_link_self_ok(Ctx, Child),
    link_attenuates(LocalPeer, Ctx, Child, Parent),
    verify_chain(LocalPeer, Ctx, [Parent | Rest]).
```

And at the call site, the denial *is* the relational failure — `\+` (negation-as-failure) on the
relation is read literally as the §5.2 `authz_deny` verdict (`verify_request/4`):

```prolog
verify_request(LocalPeer, StoreId, Env, authz_deny) :-
    envelope_capability(Env, Cap),
    envelope_included(Env, Included),
    \+ verify_capability_chain(LocalPeer, StoreId, Cap, Included), !.
```

**Contrast with the cohort.** The C / Ada / Go / Ruby peers walk the same chain with an imperative
loop carrying a boolean: `ok = true; for link in chain { if !attenuates(link, parent) { ok = false;
break } } if !ok return DENY`. The flag exists only because the host language has no notion of "this
relation does not hold" as a first-class control-flow value. In Prolog the relation's *failure* IS
that value, so the flag and the `break` and the `return DENY` all disappear — the conjunction in the
clause body (`single_link_self_ok , link_attenuates , verify_chain`) is the AND, and any conjunct
failing short-circuits the whole relation to "no". This is the protocol's §5.5 contract read in its
native logical form: it was *written* as "valid iff", and Prolog lets you write the verifier the same
way the spec states the property.

### 1.2 §5.2 auth/authz trichotomy — guarded clause heads, not an if/else ladder

§5.2 is a decision tree: authn-fail → 401, no-capability/denied/revoked → 403, over-deep chain → 400,
otherwise allow. Prolog expresses the verdict tree as **ordered clause heads**, one per outcome; the
first whose body holds determines the verdict, and the verdict is a *term* the dispatcher later maps to
a status (`ec_capability.pl`):

```prolog
verify_request(_LocalPeer, _StoreId, Env, authn_fail) :-
    \+ author_signature_ok(Env), !.
verify_request(_LocalPeer, _StoreId, Env, authz_deny) :-
    \+ envelope_capability(Env, _Cap), !.
verify_request(_LocalPeer, StoreId, Env, chain_too_deep) :-
    envelope_capability(Env, Cap), envelope_included(Env, Included),
    chain_depth_exceeded(StoreId, Cap, Included), !.
verify_request(LocalPeer, StoreId, Env, authz_deny) :-
    envelope_capability(Env, Cap), envelope_included(Env, Included),
    \+ verify_capability_chain(LocalPeer, StoreId, Cap, Included), !.
% … (grantee-binds-author, revoked) …
verify_request(_LocalPeer, _StoreId, _Env, allow).      % the otherwise
```

The verdict→status mapping is itself a clause table (`ec_peer.pl`):

```prolog
verdict_outcome(authn_fail,    _,_,_,_, outcome(401, R, [])) :- !, error_result("authentication_failed", "", R).
verdict_outcome(authz_deny,    _,_,_,_, outcome(403, R, [])) :- !, error_result("capability_denied", "", R).
verdict_outcome(chain_too_deep,_,_,_,_, outcome(400, R, [])) :- !, error_result("chain_depth_exceeded", "", R).
verdict_outcome(allow, Peer, Env, Exec, Outbound, Outcome) :- authorized_dispatch(Peer, Env, Exec, Outbound, Outcome).
```

The §4.10(b) over-deep case returns **400 `chain_depth_exceeded`** (the v7.75 ruling: structural
excess ≠ authz denial), via a separate bounded recursion (`chain_depth_exceeded/3`) that walks parent
pointers *without* verifying signatures — depth is purely structural. The cohort writes the trichotomy
as a nested `match verdict { ... }` or if/else ladder inside one function; here each verdict is a
syntactically separate clause, which is closer to how the spec's decision tree is *drawn*.

### 1.3 §6.5/§6.6 dispatch — the clause database as the router

§6.6 dispatch keys on `(handler, operation)`. Prolog expresses the whole dispatch table as **multi-head
clauses** of `handle_op(HandlerPattern, Op, Ctx, Outcome)` — each `(handler, op)` pair is its own clause
head, first-argument-indexed by the engine, and "unknown → 501" is the final catch-all clause
(`ec_peer.pl`):

```prolog
handle_op("system/tree",       "get",      ctx(Peer,_,Exec,_,_), Outcome) :- !, … .
handle_op("system/tree",       "put",      ctx(Peer,_,Exec,_,_), Outcome) :- !, … .
handle_op("system/capability", "request",  ctx(Peer,_,Exec,CallerCap,_), Outcome) :- !, … .
handle_op("system/capability", "delegate", ctx(Peer,_,Exec,CallerCap,_), Outcome) :- !, … .
handle_op("system/capability", "revoke",   ctx(Peer,_,Exec,_,_), Outcome) :- !, … .
handle_op("system/handler",    "register", ctx(Peer,_,Exec,_,_), Outcome) :- !, … .
% … the §7a conformance handlers …
handle_op(_Pattern, Op, _Ctx, outcome(501, R, [])) :- error_result("unsupported_operation", Op, R).
```

**The clause database IS the router.** Where C#/TS/OCaml/Go write a single-dispatch `switch`/`match op`
ladder inside one function, and Common Lisp externalizes the same surface to the CLOS metaobject method
table (A-CL-008), **Prolog externalizes it to the clause set**: selection is unification + first-argument
indexing, and adding an operation is *adding a clause*, not editing a ladder. This is a clean
idiom-neutrality data point: a third dispatch mechanism (clause table, after match-ladder and CLOS
method table) reaching byte-identical §6.6 behavior — corroborating that §6.6 is specified at the right
altitude (it names the dispatch *key*, not a *mechanism*).

### 1.4 §3.9 store — the clause database, literally

The store is not a hash-table bolted onto Prolog; it *is* the clause database, and the store operations
*are* `assertz`/`retract` (`ec_store.pl`):

```prolog
:- dynamic content_fact/3.       % StoreId, HashHex, Entity   (hash → entity, immutable)
:- dynamic tree_fact/3.          % StoreId, Path, HashHex     (path → hash, mutable index)

store_bind(StoreId, Path, E) :-
    entity_hash(E, H), bytes_hash(H, HexA), atom_string(HexA, NewHex),
    store_mutex(StoreId, Mtx),
    with_mutex(Mtx,                                   % A-PL-007: the RMW critical section
        ( ( content_fact(StoreId, NewHex, _) -> true
          ; assertz(content_fact(StoreId, NewHex, E)), notify_content(StoreId, E) ),
          ( tree_fact(StoreId, Path, PrevHex) -> true ; PrevHex = (-) ),
          ( PrevHex == NewHex -> true
          ;  ( PrevHex == (-) -> true ; retract(tree_fact(StoreId, Path, PrevHex)) ),
             assertz(tree_fact(StoreId, Path, NewHex)),
             notify_tree(StoreId, …) ) )).
```

A one-level listing (§3.9) is then a *pure query over the tree clauses* — a `findall` + aggregation,
the relational read. **Contrast with the cohort's `HashMap<Path, Hash>` + a `Mutex`.** Same shape, but
the Prolog version is the language's native fact base, not a library container. The honest caveat: this
is the *least* idiomatic of the four wins — it is imperative shared-mutable-state concurrency (A-PL-007:
single `assertz`/`retract` is atomic under SWI's logical-update view, a read-modify-write is not, so
every RMW is wrapped in `with_mutex/2`). It *reads* relational on the query side and imperative on the
write side. We count it as a genuine expression of "store = clause DB" but flag that the locking is
plumbing, not logic.

---

## 2. A-PL-006 answered — the two-channel error model (the genuinely-Prolog finding)

The S1 expectation (`PROFILE-RATIONALE.md`) was "all codec-floor rejects are terminal throws; failure
earns its keep only at the query surface." The S3/S4 reality is sharper and more interesting, and it is
**the finding most specific to the logic paradigm**:

**Relational failure is the dominant, idiomatic "deny" channel** — see §1.1: a §5.5 link that doesn't
satisfy the relation simply fails, and `\+ verify_capability_chain(...)` reads that failure directly as
`authz_deny`. The temporal check folds into the same channel (`ec_capability.pl`):

```prolog
% temporal validity: failure here = relational deny, folded into the §5.5 chain-walk
% failure → 403, the same channel as any other link inconsistency.
temporal_ok(Cap) :-
    cap_now_ms(Now),
    ( ent_uint(Cap, "not_before", NB) -> Now >= NB ; true ),
    ( ent_uint(Cap, "expires_at", EX) -> Now <  EX ; true ).
```

**But there is exactly ONE path that needs a distinct *channel*, not plain failure: the §5.5
unresolvable-grantee 401 carve-out.** A capability whose grantee does not resolve must surface as **401**
— distinct from a **403** authz denial. The problem is structural to the paradigm: **Prolog failure is
mono-valued.** Failing means "no" — it cannot carry "no, and specifically the 401 kind of no." If the
unresolvable-grantee case merely *failed*, it would be indistinguishable from every other link failure
and collapse into the 403 deny. So it must use a non-failure channel — a **thrown term** caught at the
dispatcher (`ec_capability.pl`):

```prolog
% §5.5 401 carve-out: an unresolvable grantee is NOT a plain deny — it must surface
% as 401. Relational failure would be indistinguishable from "denied" (403), so we
% raise a distinct term.
grantee_resolves(ctx(Env, StoreId), Cap) :-
    ( ent_bytes(Cap, "grantee", GH), cap_resolve(Env, StoreId, GH, _)
    -> true
    ;  throw(ec_capability(unresolvable_grantee)) ).
```

caught at the dispatch boundary and mapped to 401 (`ec_peer.pl`):

```prolog
chain_error_outcome(ec_capability(unresolvable_grantee), outcome(401, R, [])) :- !,
    error_result("unresolvable_grantee", "", R).
```

**The finding, stated precisely:** the protocol's verdict semantics fit a *two-channel* error model —
**relational failure for the dominant "deny", and a thrown marker ONLY where the resulting HTTP status
class must diverge from its neighbors.** Failure handles "deny" (403) beautifully and idiomatically; a
verdict whose status class must *diverge* (401, while the surrounding failures all mean 403) is the one
place failure is too weak, because it cannot distinguish *kinds* of "no". This is the logic-paradigm
analogue of the CL conditions/restarts probe — and it is a genuinely new data point: the boundary is not
"floor = throw, query = fail" (the S1 guess), it is **"deny = fail, status-class-divergence = throw."**
The byte-floor rejects (truncation, non-canonical) do throw, but the *interesting* boundary is in the
authorization verdict layer, exactly where the logic idiom is strongest.

---

## 3. Where it read as "C with `:-`" (the FFI floor — and why that's fine)

Two regions of the peer are irreducibly imperative; the predicate arrows are punctuation, not logic.
**This was predicted, and it is by design.**

### 3.1 Framed binary TCP I/O (A-PL-014)

`read_frame`/`write_frame` — read-exactly-N bytes + a 4-byte BE length prefix over a binary stream —
are procedural by nature. There is no declarative reading of "read the 4-byte length, then read exactly
that many bytes." The accept loop, `set_stream(type(binary))`, `tcp_setopt(nodelay)`, the
per-connection reader thread (`ec_transport.pl`) all look identical to how they look in C, only with
`:- ` in front:

```prolog
read_loop_(IO, OnExecute, Stream) :-
    ( catch(read_frame(Stream, Payload), _, fail)
    -> ( catch(envelope_of_bytes(Payload, Env), _, fail)
       -> ( is_response(Env) -> route_response(IO, Env)
          ; thread_create(ignore(call(OnExecute, IO, Env)), _, [detached(true)]) )
       ;  true ),
       read_loop_(IO, OnExecute, Stream)        % tail-recursive accept loop = a while(true)
    ;  true ).
```

### 3.2 The shortest-float ladder + the crypto/codec floor (A-PL-004 / A-PL-002)

The canonical-CBOR shortest-float minimization is IEEE-754 bit manipulation in a language whose floats
are opaque doubles — the S2 spike measured it at ~112 lines of purely imperative bit/branch arithmetic,
zero DCG content. And SWI `library(crypto)` 9.2.9 exports **no `ed25519_*` predicates at all** (A-PL-002,
resolved NEGATIVE — a harder finding than S1 predicted, which expected only Ed448 to need FFI). So the
*entire* byte-floor (canonical CBOR, content_hash, peer_id, Ed25519/Ed448, SHA) is sourced over the
C-ABI through `ec_codec.pl`, a thin **deterministic** (`once/1`-wrapped, A-PL-005) predicate API.

**Why this is fine.** The C peer is ~all imperative byte I/O and nobody calls it non-idiomatic-C or
non-viable. The byte-floor is not where the *protocol's semantics* live — it is the substrate every peer
shares. The S1 DEFER verdict's error was counting this floor *against* Prolog. The revival corrected
that: the floor is the FFI's job, and removing it from the idiom ledger is not cheating, it is reading
the experiment correctly.

---

## 4. The FFI-floor verdict — the byte-floor is legitimately the C-ABI's job

Three pieces of evidence that the byte-floor is the C-ABI's responsibility, not a Prolog failure:

1. **A-PL-002 (RESOLVED NEGATIVE).** The signature surface is simply *not reachable* in SWI-Prolog
   without FFI — `library(crypto)` has no Ed25519/Ed448 path, not even a generic EVP route. This is a
   runtime fact, not an idiom weakness. Every peer in a language without a BouncyCastle-equivalent hits
   the same wall (the 4th corroboration; OCaml A-OC-002, Zig A-ZIG-002, …).
2. **A-PL-004.** Canonical CBOR is byte-*achievable* in pure Prolog (the S2 spike: 20/20 byte-exact),
   but the shortest-float side condition is irreducibly imperative IEEE-754 scaffolding. The structure
   maps (a DCG); the determinism side conditions do not. The floor's imperative-ness is intrinsic to the
   *bytes*, not to Prolog.
3. **A-PL-013 — even an FFI peer still owns data-value canonical CBOR.** The C-ABI `ec_encode_ecf(Type,
   Data)` canonicalizes only the outer entity map; the nested `data` value is wrapped opaque
   (`ev_preencoded`). So the peer must hand the `data` value to the ABI *already* in canonical CBOR — and
   `ec_cbor.pl` is the peer-owned canonical value codec that does it. **"FFI the codec" does not eliminate
   the canonical-CBOR obligation at the data-value layer.** The 53/53 type-registry byte-diff is the
   proof the Prolog data-value canon matches the cross-impl encoder. (Routed to arch as a note for every
   FFI peer.)

**This vindicates the revival decision.** The S1 DEFER asked "does the logic idiom *characterize* the
peer?" and tallied the floor as ~70–80% imperative → defer. But that bar counts the floor against
Prolog. The right question — "does the *protocol* express as logic?" — is answered yes by §§1–2 above:
the §5.5 chain, the §5.2 trichotomy, the §6.6 dispatch table, the §3.9 store. **The protocol does NOT
resist Prolog. Only the byte-floor does — and the byte-floor is the C-ABI's job, exactly as the C-ABI
was built for.** The peer reached 653·0F·93S as a real, cross-impl-verified peer doing this.

---

## 5. What this tells the team (the operator's payoff)

1. **The protocol IS a convergent logic layer.** Its core operational semantics — capability-chain
   verification, the authz verdict trichotomy, operation dispatch, the entity store — all express
   *natively* as Horn-clause relations, and reaching the same 0-FAIL fixed point as twelve
   imperative/functional peers means the spec is tight enough that even a relational program model
   converges on identical wire behavior. The §5.5 "valid iff …, recursively" contract is *literally* a
   recursive relation; §6.6's `(handler, op)` dispatch key is *literally* a clause-head tuple. The spec
   reads as logic because, at its core, it *is* a set of relations — a useful thing to know about the
   protocol's essential shape.

2. **Conjunction-failure as denial is the protocol's authorization model in its purest form.** The team
   can read the §5.5 verifier as a single declarative statement ("a request is allowed iff this
   conjunction of relations holds") with no control-flow scaffolding — the clearest possible statement
   of the authorization contract. If the spec text ever wants a reference verifier that *is* the
   property it states, this is it.

3. **The one paradigm-fit limit (A-PL-006) is informative for the spec's error model.** The protocol's
   verdict layer wants a two-channel error model: most denials are mono-valued "no" (fine as failure),
   but a verdict whose *status class diverges* (the 401 unresolvable-grantee, distinct from 403 deny)
   needs a separate channel. This is a property of the *spec's* status taxonomy, surfaced by the
   paradigm that makes mono-valued failure first-class — it tells the team that 401-vs-403 is a genuine
   *kind* distinction in §5.5, not just a different number, and any implementation must carry that
   distinction out-of-band from its primary deny path.

4. **FFI is the right floor strategy for a relational peer, and the C-ABI earns its keep.** The
   byte-floor (canonical CBOR, crypto) is genuinely the C-ABI's job; Prolog owning only the relational
   core is not a "weaker probe" (the S1 framing) — for the goal of *showing the protocol as logic*, it
   is *the* probe. This is the protocol-design lesson: the C-ABI is what lets a maximally-distant
   paradigm participate as a first-class peer by carrying the substrate-level bytes so the host language
   can express only what it expresses well.

**Bottom line:** Prolog is the only paradigm in the cohort that can express the protocol as a convergent
logic layer, and it did — at full 0-FAIL conformance, with the floor over the C-ABI as designed. What it
revealed: the protocol's authorization and dispatch semantics are *relations* at heart (conjunction-
failure = deny, the clause DB = router, the store = a fact base), the one place a logic peer strains is
the 401-vs-403 status-class divergence (A-PL-006), and the byte-floor is legitimately not the protocol's
concern but the substrate's. The revival was right.
