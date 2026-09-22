% ec_capability.pl — Capability system (L3): the §5 verification core, expressed
% in Prolog's RELATIONAL idiom. THIS IS THE POINT OF THE PROLOG PEER.
%
% The PROFILE-RATIONALE predicted three places the logic idiom pays off; this file
% realizes each:
%
%   §5.2 auth/authz trichotomy  → verify_request/4 with DISTINCT CLAUSE HEADS
%        (allow / authn_fail / authz_deny / chain_too_deep / unresolvable_grantee),
%        selected by the verdict the body computes — the verdict is a TERM, the
%        dispatcher maps it to a status. No nested if/else verdict ladder.
%
%   §5.5 capability-chain verification → collect_chain/3 + verify_chain/4 as a
%        RECURSIVE RELATION over parent pointers ("textbook Prolog recursive
%        relation", PROFILE-RATIONALE). Each link is a relation between a child
%        token and its parent (attenuation, delegation caveats, signature).
%
%   §4.10(b) chain-depth pre-check → chain_depth_exceeded/3: bounded recursion that
%        counts parent links and SUCCEEDS (relationally) iff the chain is over-deep
%        → 400 chain_depth_exceeded (the v7.75 cohort ruling: 400, NOT 403).
%
%   §3.6 multisig K-of-N → verify_multisig_root/4: a structural relation (M3) then
%        a k-of-n quorum count over distinct signers (M4) at the chain root (M6).
%
% A-PL-006 (the open probe — does any error path want relational FAILURE rather
% than a thrown term?): see the header comment on verify_request/4. Answer, in
% short: the §5.5 walk uses relational FAILURE as "deny" PERVASIVELY and idiomatically
% (a link that doesn't satisfy the relation simply fails, and failure = :deny is the
% natural reading); the ONE path that genuinely wants a distinct *channel* (not
% plain failure) is the §5.5 unresolvable-grantee 401 carve-out — a missing grantee
% must surface as 401, distinct from a 403 authz denial, so it cannot be folded into
% the same failure that means "denied". We model that as a THROWN term caught at the
% dispatcher (mirroring CL's condition) — failure for "denied", a thrown marker for
% "unresolvable". That two-channel split is the genuinely-Prolog finding.

:- module(ec_capability,
          [ verify_request/4,           % +LocalPeer, +StoreId, +Envelope, -Verdict
            check_permission/6,         % +LocalPeer, +GranterPeer, +Exec, +Token, +HandlerPattern, -Verdict
            verify_capability_chain/4,  % +LocalPeer, +StoreId, +Cap, +Included  (semidet: allow)
            chain_depth_exceeded/3,     % +StoreId, +Cap, +Included            (semidet: over-deep)
            normalize_uri/2,            % +Uri, -Path
            canonicalize/3,             % +LocalPeer, +Path, -Abs
            matches_pattern/2,          % +Path, +Pattern (semidet)
            grant_subset/5,             % +LocalPeer,+ChildPeer,+ParentPeer,+ChildGrant,+ParentGrant
            effective_targets/3,        % +LocalPeer, +Exec, -Survivors  (fails: no resource)
            check_path_permission/5,    % +LocalPeer, +Operation, +Path, +Token, +HandlerPattern (semidet)
            extract_peer/3,             % +LocalPeer, +Uri, -TargetPeer
            is_peer_id/1,               % +Seg (semidet: looks like a peer_id)
            cap_resolve/4,              % +Envelope, +StoreId, +Hash, -Entity (semidet)
            % §1.4 PD-2 outbound sub-dispatch gate
            verify_capability_chain_rooted_at/5,
            peer_relative_of/2,         % +Uri, -PeerRelativePath
            grant_path_for/3,           % +LocalPeer, +Pattern, -GrantStorePath
            target_minted_peers_relaxation/6,
            check_outbound_sub_dispatch/7
          ]).

:- use_module(ec_codec).
:- use_module(ec_entity).
:- use_module(ec_identity).
:- use_module(ec_store).
:- use_module(library(lists)).

% ═══════════════════════════════════════════════════════════════════════════
% §5.2 verify_request — THE TRICHOTOMY AS DISTINCT CLAUSE HEADS.
%
% Returns one of: allow | authn_fail | authz_deny | chain_too_deep. May THROW
% unresolvable_grantee (the §5.5 401 carve-out — see A-PL-006 note in the file
% header). The clauses are ordered guards that read top-to-bottom as the §5.2
% decision tree; the FIRST whose body holds determines the verdict.
% ═══════════════════════════════════════════════════════════════════════════

verify_request(_LocalPeer, _StoreId, Env, authn_fail) :-
    \+ author_signature_ok(Env), !.
verify_request(_LocalPeer, _StoreId, Env, authz_deny) :-
    \+ envelope_capability(Env, _Cap), !.
verify_request(_LocalPeer, StoreId, Env, chain_too_deep) :-
    envelope_capability(Env, Cap),
    envelope_included(Env, Included),
    chain_depth_exceeded(StoreId, Cap, Included), !.
verify_request(LocalPeer, StoreId, Env, authz_deny) :-
    envelope_capability(Env, Cap),
    envelope_included(Env, Included),
    \+ verify_capability_chain(LocalPeer, StoreId, Cap, Included), !.
verify_request(_LocalPeer, _StoreId, Env, authz_deny) :-
    \+ grantee_binds_author(Env), !.
verify_request(LocalPeer, StoreId, Env, authz_deny) :-
    envelope_capability(Env, Cap),
    envelope_included(Env, Included),
    is_revoked(LocalPeer, StoreId, Cap, Included), !.
verify_request(_LocalPeer, _StoreId, _Env, allow).

% authn (§5.2 step 1): a signature over the exec whose signer == author, and the
% author entity resolves + the signature verifies against it.
author_signature_ok(Env) :-
    envelope_root(Env, Exec),
    entity_hash(Exec, ExecHash),
    find_signature(Env, ExecHash, Sig),
    ent_bytes(Exec, "author", AuthorH),
    ent_bytes(Sig, "signer", SignerH),
    AuthorH == SignerH,
    included_get(Env, AuthorH, Author),
    verify_signature(Sig, Author).

envelope_capability(Env, Cap) :-
    envelope_root(Env, Exec),
    ent_bytes(Exec, "capability", CapH),
    included_get(Env, CapH, Cap).

grantee_binds_author(Env) :-
    envelope_capability(Env, Cap),
    envelope_root(Env, Exec),
    ent_bytes(Cap, "grantee", Grantee),
    ent_bytes(Exec, "author", AuthorH),
    Grantee == AuthorH.

% ═══════════════════════════════════════════════════════════════════════════
% §5.5 chain verification — THE RECURSIVE RELATION.
%
% collect_chain/3 walks parent pointers to the root (bounded). verify_chain/5 is
% the per-link recursion: a chain is valid iff the head link is self-consistent
% (signature, grantee resolves, temporal) AND it attenuates its parent AND the
% parent chain is valid. Failure of any link = the relation fails = :deny.
% ═══════════════════════════════════════════════════════════════════════════

% resolve a hash to an entity: included first, then the store.
cap_resolve(Env, StoreId, H, E) :-
    ( included_get(Env, H, E) -> true
    ; store_get_by_hash(StoreId, H, E) ).

% collect_chain(+Env/+StoreId, +Cap, -Chain): root-first→leaf list [Leaf..Root].
% Bounded at 64 (defensive; the depth pre-check is the spec gate). Fails if a
% parent is unreachable (→ the relation denies).
collect_chain(Ctx, Cap, Chain) :- collect_chain_(Ctx, Cap, 0, Chain).
collect_chain_(_, _, Depth, _) :- Depth > 64, !, fail.
collect_chain_(Ctx, Cap, Depth, [Cap|Rest]) :-
    ( ent_bytes(Cap, "parent", PH)
    -> Ctx = ctx(Env, StoreId),
       cap_resolve(Env, StoreId, PH, Parent),
       Depth1 is Depth + 1,
       collect_chain_(Ctx, Parent, Depth1, Rest)
    ;  Rest = [] ).

verify_capability_chain(LocalPeer, StoreId, Cap, Included) :-
    verify_capability_chain_rooted_at(LocalPeer, LocalPeer, StoreId, Cap, Included).

% verify_capability_chain with the expected ROOT granter named separately from the
% verifying peer.
%
% §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is minted by
% the TARGET peer, so root-trust is relaxed away from the local peer — and every other
% clause (per-link signatures, grantee resolution, temporal validity, attenuation,
% caveats) is unchanged. Parameterized rather than forked because a second copy of a chain
% walk is a second copy that drifts.
%
% A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When RootPeer
% differs from LocalPeer the quorum arm is REFUSED outright rather than verified: "minted
% by the target" means the target SOLELY minted it, and a K-of-N root is a GROUP's
% authority — its co-signers authorized it too. Accepting it would let any one signer's
% target confer the whole group's grant, which is E3/F66's over-acceptance. §5.5's M6 also
% requires the LOCAL peer in the signer set, so the quorum arm has no meaning in a foreign
% frame even on its own terms.
verify_capability_chain_rooted_at(LocalPeer, RootPeer, StoreId, Cap, Included) :-
    envelope_with_included(Included, Env),
    Ctx = ctx(Env, StoreId),
    collect_chain(Ctx, Cap, Chain),
    last(Chain, Root),
    root_authority_ok(LocalPeer, RootPeer, Ctx, Root),
    verify_chain(LocalPeer, Ctx, Chain).

% wrap a bare included-list as a query-able pseudo-envelope for cap_resolve.
envelope_with_included(Included, envelope(_, Included)).

% root authority (§5.5): a single-sig root must root at the LOCAL peer; a §3.6 M3
% multi-sig root must pass k-of-n quorum.
root_authority_ok(LocalPeer, RootPeer, Ctx, Root) :-
    ( is_multisig(Root)
    -> RootPeer == LocalPeer,               % §1.4: a quorum root is LOCAL-frame only
       verify_multisig_root(LocalPeer, Ctx, Root)
    ;  Ctx = ctx(Env, StoreId),
       ent_bytes(Root, "granter", GH),
       cap_resolve(Env, StoreId, GH, G),
       ent_bytes(G, "public_key", PK),
       peer_id_of_pubkey(PK, RootPeer) ).

% verify_chain — the recursive relation over links. A 1-element chain (the root)
% has no link obligations beyond root_authority_ok + its own self-consistency.
% A multi-sig token is ROOT-ONLY: it may appear only as the final element.
verify_chain(_LocalPeer, Ctx, [Single]) :- !,
    ( is_multisig(Single) -> true ; single_link_self_ok(Ctx, Single) ).
verify_chain(LocalPeer, Ctx, [Child, Parent | Rest]) :-
    \+ is_multisig(Child),                          % multi-sig is root-only
    single_link_self_ok(Ctx, Child),
    link_attenuates(LocalPeer, Ctx, Child, Parent),
    verify_chain(LocalPeer, Ctx, [Parent | Rest]).

% per-token self-consistency: signature (signer==granter, verifies), grantee
% resolves (else the §5.5 401 carve-out THROWS), temporal validity.
single_link_self_ok(Ctx, Cap) :-
    Ctx = ctx(Env, StoreId),
    ent_bytes(Cap, "granter", GH),
    entity_hash(Cap, CapHash),
    find_signature(Env, CapHash, Sig),
    ent_bytes(Sig, "signer", SignerH), SignerH == GH,
    cap_resolve(Env, StoreId, GH, Granter),
    verify_signature(Sig, Granter),
    grantee_resolves(Ctx, Cap),                    % may throw unresolvable_grantee
    temporal_ok(Cap).

% §5.5 401 carve-out: an unresolvable grantee is NOT a plain deny — it must surface
% as 401. Relational failure would be indistinguishable from "denied" (403), so we
% raise a distinct term (A-PL-006: the one path that wants a channel, not failure).
grantee_resolves(ctx(Env, StoreId), Cap) :-
    ( ent_bytes(Cap, "grantee", GH), cap_resolve(Env, StoreId, GH, _)
    -> true
    ;  throw(ec_capability(unresolvable_grantee)) ).

% §5.5 / §3.6 temporal validity (S4: lit up against the oracle's expired /
% not-yet-valid vectors). not_before / expires_at are optional uint epoch-ms. A
% cap is temporally valid iff (not_before absent OR now >= not_before) AND
% (expires_at absent OR now < expires_at). Failure here = relational deny (folded
% into the §5.5 chain-walk failure → 403), the same channel as any other link
% inconsistency. Absent fields = no constraint (a non-expiring cap stays valid).
temporal_ok(Cap) :-
    % CAP-6a FIRST (§6.2): a present-but-unrepresentable expires_at / not_before /
    % created_at is MALFORMED and must be refused outright. This has to run BEFORE
    % the two range checks below, because those are what the ambiguity defeats.
    %
    % Prolog's fail-open is the ARITHMETIC one, not the null-collapse one, and the
    % distinction matters because the grep that catches the other misses this:
    % `ent_uint(E, Key, I) :- ent_field(E, Key, int(I)), integer(I)` succeeds for
    % ANY integer, negative included. So the guard did not SKIP -- it RAN and
    % answered wrong: for a negative not_before, `Now >= NB` is trivially true and
    % the capability passed. No absent/present distinction anywhere in sight.
    %
    % Prolog integers are arbitrary-precision, so the >2^64 half is likewise a
    % DELIBERATE range check rather than an overflow trap.
    %
    % An absent field stays legal and is NOT rejected here. Refusal is the §5.2
    % capability_denied disposition (this failure folds into the §5.5 chain-walk
    % failure -> 403), never a decode-layer drop or a transport close.
    temporal_fields_representable(Cap),
    cap_now_ms(Now),
    ( ent_uint(Cap, "not_before", NB) -> Now >= NB ; true ),
    ( ent_uint(Cap, "expires_at", EX) -> Now < EX ; true ).

% §6.2 CAP-6a: every temporal field on a RECEIVED token is either absent (legal) or
% representable as a uint64. Present-but-anything-else => malformed.
temporal_fields_representable(Cap) :-
    forall(member(Key, ["expires_at", "not_before", "created_at"]),
           ( ent_field(Cap, Key, V)
           -> ( V = int(I), integer(I), I >= 0, I < 18446744073709551616 )
           ;  true )).

cap_now_ms(Ms) :- get_time(T), Ms is integer(T * 1000).

% a link relation: Child's grantee == Parent's granter, Child attenuates Parent,
% and Parent's §5.7 delegation caveats admit Child.
link_attenuates(LocalPeer, Ctx, Child, Parent) :-
    ent_bytes(Parent, "grantee", PG),
    ent_bytes(Child, "granter", CG),
    PG == CG,
    link_granter_peer(Ctx, LocalPeer, Child, ChildPeer),
    link_granter_peer(Ctx, LocalPeer, Parent, ParentPeer),
    is_attenuated(LocalPeer, ChildPeer, ParentPeer, Child, Parent),
    check_delegation_caveats(Parent, Child).

% §5.5a per-link canonicalization frame = the link's granter peer_id. Multi-sig
% root (no granter hash) → LocalPeer. Unresolvable → fail (deny), never silent fallback.
link_granter_peer(ctx(_,_), LocalPeer, Cap, LocalPeer) :- \+ ent_bytes(Cap, "granter", _), !.
link_granter_peer(ctx(Env, StoreId), _LocalPeer, Cap, Peer) :-
    ent_bytes(Cap, "granter", GH),
    cap_resolve(Env, StoreId, GH, G),
    ent_bytes(G, "public_key", PK),
    peer_id_of_pubkey(PK, Peer).

% ═══════════════════════════════════════════════════════════════════════════
% §4.10(b) chain-depth pre-check — bounded recursion → 400 chain_depth_exceeded.
% SUCCEEDS iff the chain rooted at Cap exceeds the max depth (64), walking parent
% pointers WITHOUT verifying signatures (depth is purely structural). An
% unreachable parent is NOT a depth problem (it fails here, denied later at 403).
% ═══════════════════════════════════════════════════════════════════════════
chain_depth_exceeded(StoreId, Cap, Included) :-
    envelope_with_included(Included, Env),
    depth_walk(ctx(Env, StoreId), Cap, 0).
depth_walk(_, _, Depth) :- Depth > 64, !.
depth_walk(ctx(Env, StoreId), Cap, Depth) :-
    ent_bytes(Cap, "parent", PH),
    cap_resolve(Env, StoreId, PH, Parent),
    Depth1 is Depth + 1,
    depth_walk(ctx(Env, StoreId), Parent, Depth1).

% ═══════════════════════════════════════════════════════════════════════════
% §3.6 multi-signature granter (k-of-n quorum, ROOT-ONLY).
% ═══════════════════════════════════════════════════════════════════════════
is_multisig(Cap) :- ent_field(Cap, "granter", map(_)).

multi_granter(Cap, Signers, Threshold) :-
    ent_field(Cap, "granter", map(GP)),
    memberchk("signers"-SignersV, GP),
    findall(SH, (member(bytes(C), SignersV), string_codes(SH, C)), Signers),
    ( memberchk("threshold"-int(Threshold), GP) -> true ; Threshold = 0 ).

verify_multisig_root(LocalPeer, ctx(Env, StoreId), Root) :-
    multi_granter(Root, Signers, Threshold),
    length(Signers, N),
    \+ ent_bytes(Root, "parent", _),               % M3: root-only
    N >= 2, Threshold >= 2, Threshold =< N,
    \+ has_duplicate(Signers),
    % M6: the local peer MUST be a quorum member.
    member(SH, Signers), signer_peer_id(ctx(Env, StoreId), SH, LocalPeer), !,
    % grantee resolves (as for any root).
    ent_bytes(Root, "grantee", GeH), cap_resolve(Env, StoreId, GeH, _),
    % M4: count DISTINCT signers with a valid signature over the root content hash.
    entity_hash(Root, RootHash),
    findall(SH2,
            ( member(SH2, Signers),
              cap_resolve(Env, StoreId, SH2, SignerPeer),
              signature_by(Env, RootHash, SH2, Sig),
              verify_signature(Sig, SignerPeer) ),
            Valid0),
    sort(Valid0, Valid),
    length(Valid, K), K >= Threshold.

signer_peer_id(ctx(Env, StoreId), SH, PeerId) :-
    cap_resolve(Env, StoreId, SH, P),
    ent_bytes(P, "public_key", PK),
    peer_id_of_pubkey(PK, PeerId).

signature_by(Env, Target, SignerH, Sig) :-
    envelope_included(Env, Included),
    member(_-Sig, Included),
    entity_type(Sig, "system/signature"),
    ent_bytes(Sig, "target", T), T == Target,
    ent_bytes(Sig, "signer", S), S == SignerH.

has_duplicate([X|Xs]) :- ( memberchk(X, Xs) -> true ; has_duplicate(Xs) ).

% ═══════════════════════════════════════════════════════════════════════════
% §5.6 attenuation + §5.7 delegation caveats.
% ═══════════════════════════════════════════════════════════════════════════
is_attenuated(LocalPeer, ChildPeer, ParentPeer, Child, Parent) :-
    grants_of(Child, CG), grants_of(Parent, PG),
    forall(member(C, CG), ( member(P, PG), grant_subset(LocalPeer, ChildPeer, ParentPeer, C, P) )),
    ttl_attenuates(Child, Parent).

ttl_attenuates(Child, Parent) :-
    ( ent_uint(Parent, "expires_at", PE)
    -> ( ent_uint(Child, "expires_at", CE) -> CE =< PE ; fail )  % child infinite under finite parent → deny
    ;  true ).

check_delegation_caveats(Parent, _Child) :-
    \+ ent_field(Parent, "delegation_caveats", map(_)), !.
check_delegation_caveats(Parent, Child) :-
    ent_field(Parent, "delegation_caveats", map(Cav)),
    \+ memberchk("no_delegation"-bool(true), Cav),
    ( memberchk("max_delegation_depth"-int(_), Cav) -> true ; true ),
    ( memberchk("max_delegation_ttl"-int(MaxTtl), Cav)
    -> ( ent_uint(Child, "expires_at", CE), ent_uint(Child, "created_at", CC)
       -> Diff is CE - CC, Diff =< MaxTtl
       ;  ent_uint(Child, "expires_at", _) )          % created_at absent → admit
    ;  true ).

% ═══════════════════════════════════════════════════════════════════════════
% Grant / scope parse + §5.4 pattern matching.
% ═══════════════════════════════════════════════════════════════════════════
grants_of(Token, Grants) :-
    ( ent_field(Token, "grants", G), is_list(G) -> Grants = G ; Grants = [] ).

scope_incl(map(M), Incl) :- !, ( memberchk("include"-L, M), is_list(L) -> texts(L, Incl) ; Incl = [] ).
scope_incl(_, []).
scope_excl(map(M), Excl) :- !, ( memberchk("exclude"-L, M), is_list(L) -> texts(L, Excl) ; Excl = [] ).
scope_excl(_, []).
texts(L, T) :- findall(S, (member(S, L), string(S)), T).

grant_field(map(Pairs), Key, Scope) :- ( memberchk(Key-Scope, Pairs) -> true ; Scope = map([]) ).

normalize_uri(Uri, Path) :-
    ( string_concat("entity://", Rest, Uri) -> string_concat("/", Rest, Path) ; Path = Uri ).

% NEVER_MATCH — the unmatchable value (0.8.2.20). Unreachable as a canonical path by
% CONSTRUCTION: its first segment cannot be a peer_id, since is_peer_id/1 requires
% >= 46 Base58 characters and "-" is outside the Base58 alphabet.
never_match("/never-match").

% canonicalize/3 is TOTAL (0.8.2.20): the return domain is "a canonical path OR
% NEVER_MATCH". These clauses used to THROW, and the throw was reachable from the wire
% -- every normative call site is a matcher with no error channel to consume one, so
% the ball escaped the matcher, was caught by the peer's resilience frame, and "../x"
% in a resource exclude answered 500 (measured 2026-09-14). The diagnostic belongs at
% admission (6.5), which has a caller to answer. NOTE the prolog-specific half: a throw
% does NOT fall through to the next clause, so the clause below a throwing one was
% never the answer -- the generic catch was.
canonicalize(_LocalPeer, Path, NM) :- string_concat("./", _, Path), !, never_match(NM).
canonicalize(_LocalPeer, Path, NM) :- string_concat("../", _, Path), !, never_match(NM).
canonicalize(_LocalPeer, Path, NM) :- string_concat("*/", _, Path), !, never_match(NM).
canonicalize(_LocalPeer, Path, Path) :- string_concat("/", _, Path), !.
canonicalize(LocalPeer, Path, Abs) :- atomics_to_string(["/", LocalPeer, "/", Path], Abs).

% AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED in
% an include (covers nothing -> the grant grants nothing) and fail-OPEN in an exclude
% (carves out nothing -> the grant is SILENTLY WIDER than its author wrote): same value,
% same matcher, opposite safety direction, so the reading is chosen where the POSITION
% is known and matches_pattern/2 stays uniform over its operands.
%
% ASK THIS ONLY OF A PATH-SCOPE DIMENSION (0.8.2.24, N2/N3). NEVER_MATCH is a §5.4
% PATH-canonicalization sentinel; an id-scope pattern is a literal identifier that §5.2's
% own id-scope arm forbids putting through the §5.4 transforms. This guard used to sit
% OUTSIDE the type dispatch -- as its own FIRST clause of matches_scope/4, with `_Kind`
% in the head -- transcribing §5.2's loop as it read before that loop grew one. That ran
% an id pattern through those transforms purely to classify it and then DENIED THE WHOLE
% DIMENSION on a property unrelated to whether the exclude carves anything out: an
% `operations` exclude of "*/apply", an ordinary namespaced operation name and a literal
% that matches nothing under the id-scope grammar, canonicalized to the sentinel and
% denied every operation. Over-denial, and invisible on any well-formed grant.
%
% §5.4 says outright that the rule "does NOT reach `operations` or `peers` [MUST]", and
% it does NOT leave the id-scope dimensions unprotected by oversight: under the id-scope
% grammar every non-"*" pattern is a literal and a literal is never structurally
% unmatchable, so there is nothing here for this sentinel to detect. A scope boundary,
% not an omission.
exclude_unmatchable(Frame, Excl) :-
    never_match(NM),
    member(P, Excl), canonicalize(Frame, P, NM), !.

% §5.4 pattern matching. Both PATH and PATTERN are canonical (absolute).
% NEVER_MATCH never matches, in EITHER operand (0.8.2.20). These clauses are FIRST, and
% the rule is a matcher rule rather than a property of the string: the clause below
% succeeds for a bare "*" pattern, so safety must not rest on a value merely looking
% unmatchable.
matches_pattern(Path, _Pattern) :- never_match(Path), !, fail.
matches_pattern(_Path, Pattern) :- never_match(Pattern), !, fail.
matches_pattern(_Path, "*") :- !.
matches_pattern(Path, Pattern) :-
    string_concat("/*/", Remainder, Pattern), !,
    string_length(Path, PL), PL >= 1,
    sub_string(Path, 1, _, _, _),
    ( sub_string(Path, After, _, _, "/"), After >= 1
    -> AfterLen is After,
       sub_string(Path, AfterLen, _, 0, Tail),    % from the next slash onward
       matches_pattern(Tail, Remainder)
    ;  fail ).
matches_pattern(Path, Pattern) :-
    string_concat(Prefix, "/*", Pattern), !,
    string_concat(Prefix, "/", PrefixSlash),
    ( Path == Prefix -> true ; string_concat(PrefixSlash, _, Path) -> true ; string_concat(Prefix, _, Path) ).
matches_pattern(Path, Pattern) :- Path == Pattern.

% §5.2 id-scope match (0.8.1, F40) — operations and peers. Literal comparison with
% exactly two wildcard forms: bare "*" and a trailing slash-star segment-prefix. None of
% the §5.4 path transforms apply, so a pattern carrying path syntax is matched as a
% literal string: a non-match, never a fault.
matches_id_pattern(_Value, "*") :- !.
matches_id_pattern(Value, Pattern) :-
    string_concat(Prefix, "/*", Pattern), !,
    string_concat(Prefix, "/", PrefixSlash),
    string_concat(PrefixSlash, _, Value).
matches_id_pattern(Value, Pattern) :- Value == Pattern.

% §5.2 typed scope match. Kind is `id` (operations, peers) or `path` (handlers,
% resources) and is given at every call site — there is no default, so a new one cannot
% inherit the wrong matcher silently, which is exactly the F40 defect.
% THE SENTINEL GUARD IS SCOPED TO PATH-SCOPE (0.8.2.24) AND THE CLAUSE HEAD IS WHERE
% THAT SCOPING LIVES. §5.2's exclude loop tests the sentinel INSIDE
% `if dimension_type == "system/capability/path-scope"`, and §5.4 scopes its own
% invalid-capability rule the same way. This guard's head used to carry `_Kind`, so it
% ran ahead of BOTH arms; naming `path` in the head is the whole fix, and a new call site
% cannot get it wrong because the Kind argument is mandatory at every one.
matches_scope(LocalPeer, _Value, Scope, path) :-
    scope_excl(Scope, Excl0), exclude_unmatchable(LocalPeer, Excl0), !, fail.   % 0.8.2.21
matches_scope(_LocalPeer, Value, Scope, id) :- !,
    scope_incl(Scope, Incl), scope_excl(Scope, Excl),
    once(( member(P, Incl), matches_id_pattern(Value, P) )),
    \+ ( member(Q, Excl), matches_id_pattern(Value, Q) ).
matches_scope(LocalPeer, Value, Scope, path) :-
    canonicalize(LocalPeer, Value, CV),
    scope_incl(Scope, Incl), scope_excl(Scope, Excl),
    once(( member(P, Incl), canonicalize(LocalPeer, P, CP), matches_pattern(CV, CP) )),
    \+ ( member(Q, Excl), canonicalize(LocalPeer, Q, CQ), matches_pattern(CV, CQ) ).

% ═══════════════════════════════════════════════════════════════════════════
% §5.2 check_permission — gate the wire request at the dispatch authz boundary.
% Distinct heads: allow / deny.
% ═══════════════════════════════════════════════════════════════════════════
check_permission(LocalPeer, GranterPeer, Exec, Token, HandlerPattern, allow) :-
    grants_of(Token, Grants),
    ( ent_text(Exec, "operation", Op) -> true ; Op = "" ),
    ( ent_text(Exec, "uri", Uri) -> true ; Uri = "" ),
    extract_peer(LocalPeer, Uri, TargetPeer),
    member(G, Grants),
    grant_ok(LocalPeer, GranterPeer, Op, HandlerPattern, TargetPeer, Exec, G), !.
check_permission(_,_,_,_,_, deny).

grant_ok(LocalPeer, GranterPeer, Op, HandlerPattern, TargetPeer, Exec, G) :-
    grant_field(G, "operations", OpScope), matches_scope(LocalPeer, Op, OpScope, id),
    grant_field(G, "handlers", HScope), matches_scope(LocalPeer, HandlerPattern, HScope, path),
    peer_scope_ok(LocalPeer, TargetPeer, G),
    resource_ok(LocalPeer, GranterPeer, Exec, G).

peer_scope_ok(LocalPeer, TargetPeer, G) :-
    ( ent_field_or_default(G, "peers", PScope)
    -> matches_scope(LocalPeer, TargetPeer, PScope, id)
    ;  TargetPeer == LocalPeer ).
ent_field_or_default(map(P), "peers", Scope) :- memberchk("peers"-Scope, P).

resource_ok(LocalPeer, GranterPeer, Exec, G) :-
    ( ent_field(Exec, "resource", map(R))
    -> check_resource_scope(LocalPeer, GranterPeer, map(R), G)
    ;  true ).

% concrete-target subset: every caller target must be covered by the grant's
% resource include (canonicalized against the GRANTER frame, §PR-8) and not by its
% exclude, unless the caller itself excludes it.
check_resource_scope(LocalPeer, GranterPeer, map(R), G) :-
    ( memberchk("targets"-Tgs, R), is_list(Tgs) -> texts(Tgs, Targets) ; Targets = [] ),
    ( memberchk("exclude"-Ex, R), is_list(Ex) -> texts(Ex, CallerExcl) ; CallerExcl = [] ),
    grant_field(G, "resources", RScope),
    scope_incl(RScope, Incl), scope_excl(RScope, Excl),
    Targets \= [],
    % An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    % target: the coverage test below is correct in isolation and is simply never
    % reached on a sentinel, because matches_pattern/2 fails.
    %
    % UNGUARDED BY KIND ON PURPOSE, unlike matches_scope/4's (0.8.2.24): RScope here is
    % ALWAYS the RESOURCES dimension, which §5.2 fixes as path-scope, so the type test
    % that predicate performs would be a constant here. Naming the dimension in the body
    % (grant_field(G, "resources", RScope), two lines up) is what makes that checkable --
    % a granter frame reaching an id-scope call site is the defect, and this predicate
    % cannot be one.
    \+ exclude_unmatchable(GranterPeer, Excl),
    forall(member(T, Targets),
           ( canonicalize(LocalPeer, T, CT),
             ( member(CE, CallerExcl), canonicalize(LocalPeer, CE, CCE), matches_pattern(CT, CCE)
             -> true
             ;  once(( member(I, Incl), canonicalize(GranterPeer, I, CI), matches_pattern(CT, CI) )),
                \+ ( member(E2, Excl), canonicalize(GranterPeer, E2, CE2), matches_pattern(CT, CE2) ) ) )).

% ═══════════════════════════════════════════════════════════════════════════
% §3.3 effective targets + §6.3 check_path_permission.
% ═══════════════════════════════════════════════════════════════════════════

% §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude` removes
% entries from `resource.targets` BEFORE anything else looks at the request.
%
% Survivors come back in the caller's OWN SPELLING, not canonicalized -- 0.8.2.21 is
% explicit that effective_targets yields raw survivors, and the distinction is
% load-bearing because the value flows on to the store lookup, which canonicalizes for
% itself.
%
% FAILURE IS "NO `resource` AT ALL", AND THAT IS THE NON-LOSSY PROJECTION §3.3 REQUIRES
% [MUST] (0.8.2.25, N11). "Where an implementation projects resource.targets onto the
% effective set ahead of the handler, that projection MUST NOT be lossy about its own
% emptiness -- narrow when narrowing leaves something, and retain the raw pair when
% narrowing would empty it." A predicate that answered `[]` for both would delete the
% two-empties discriminator before any handler could read it, and the handler's refusal
% arm becomes dead code that only a WIRE drive can detect. Prolog carries the
% discriminator as relational FAILURE rather than as a second argument -- the same
% property, spelled the way this substrate spells "absent", and the same choice the §5.5
% walk makes for "deny".
%
% An ABSENT resource and a resource whose every target was excluded are DIFFERENT
% REQUESTS for a resource-OPTIONAL operation (0.8.2.24, N7), not merely different inputs
% to one disposition.
%
% A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list --
% `texts/2` filters non-strings and `[]` is a legal answer. Reporting it absent would
% serve the WIDER absent-case answer to a request that named a resource, which is N11's
% own defect one field over.
%
% The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it separately
% from the grant arm) and that is INHERITED here rather than restated: canonicalize/3
% answers the sentinel, matches_pattern/2 then fails, and the target simply survives.
%
% This peer has exactly ONE narrowing seam -- this predicate, called by the tree handler
% -- and §6.5's dispatch chain does not project: run_chain/5 passes Exec through
% untouched and check_permission/6 reads `resource` for itself. So there is no second
% door to keep in step, and adding a projection at dispatch would create one.
effective_targets(LocalPeer, Exec, Survivors) :-
    ent_field(Exec, "resource", map(R)),
    memberchk("targets"-Tgs0, R),
    ( is_list(Tgs0) -> texts(Tgs0, Targets) ; Targets = [] ),
    ( memberchk("exclude"-Ex, R), is_list(Ex) -> texts(Ex, CallerExcl) ; CallerExcl = [] ),
    findall(T, ( member(T, Targets),
                 canonicalize(LocalPeer, T, CT),
                 \+ ( member(X, CallerExcl),
                      canonicalize(LocalPeer, X, CX),
                      matches_pattern(CT, CX) ) ),
            Survivors).

% §6.3's handler-level path check: may the caller access Path AS A TREE PATH, under
% HandlerPattern, with Token? Semidet -- success is ALLOW, failure is DENY, which is the
% same relational reading the rest of this module uses.
%
% IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
% subject is derived after dispatch, and the dispatch-level check can be made VACUOUS by
% caller-controlled input: a caller who excludes the one target its capability does not
% cover removes that target from check_permission/6's view entirely, and a handler that
% then acts on it has authorized nothing.
%
% THREE DIMENSIONS, NOT FOUR. `peers` is not consulted -- the path is local by
% construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
% step 3, before any handler runs), and §6.3's signature names only handlers, operations
% and resources.
%
% THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
% rather than a choice: §6.3's block reads
% `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` -- there
% is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject is
% a pattern compared against a parent's pattern; this call site compares a CONCRETE local
% path the handler is about to touch.
%
% Scope types: handlers -> path-scope, operations -> id-scope, resources -> path-scope.
% An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no tree
% paths) and DENIES every path here, which is what that note says it should -- the
% once/1 over an empty include list fails. A malformed path canonicalizes to NEVER_MATCH,
% which matches no grant, so it falls through to DENY rather than being matched against
% anything.
check_path_permission(LocalPeer, Operation, Path, Token, HandlerPattern) :-
    grants_of(Token, Grants),
    member(G, Grants),
    grant_field(G, "handlers", HScope),
    matches_scope(LocalPeer, HandlerPattern, HScope, path),
    grant_field(G, "operations", OScope),
    matches_scope(LocalPeer, Operation, OScope, id),
    grant_field(G, "resources", RScope),
    matches_scope(LocalPeer, Path, RScope, path),
    !.

% ═══════════════════════════════════════════════════════════════════════════
% §5.6 grant_subset (attenuation predicate, used by mint-bounded + chain walk).
% Resource dimension uses the §5.5a per-link granter frames; handlers/ops/peers
% stay on LocalPeer.
% ═══════════════════════════════════════════════════════════════════════════
% §5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
% dimensions stay on the local frame. The scope KIND is a property of the DIMENSION and
% is named at every call site, never defaulted (F50 / 0.8.2.16).
grant_subset(LocalPeer, ChildPeer, ParentPeer, Child, Parent) :-
    grant_field(Child, "handlers", CH), grant_field(Parent, "handlers", PH),
    scope_subset(LocalPeer, LocalPeer, CH, PH, path),
    grant_field(Child, "operations", CO), grant_field(Parent, "operations", PO),
    scope_subset(LocalPeer, LocalPeer, CO, PO, id),
    grant_field(Child, "resources", CR), grant_field(Parent, "resources", PR),
    scope_subset(ChildPeer, ParentPeer, CR, PR, path),
    peers_subset(LocalPeer, Child, Parent).

peers_subset(LocalPeer, Child, Parent) :-
    child_peers(LocalPeer, Child, CP),
    child_peers(LocalPeer, Parent, PP),
    scope_subset(LocalPeer, LocalPeer, CP, PP, id).
child_peers(LocalPeer, G, Scope) :-
    ( ent_field_or_default(G, "peers", Scope) -> true ; Scope = map(["include"-[LocalPeer]]) ).

% scope_subset: every child include is covered by some parent include (frames per
% dimension), and every parent exclude is covered by some child exclude.
%
% TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; entity-core-formalization K-7).
% §3.6's id-scope grammar binds the scope TYPE, not one predicate -- "An implementation
% on the canonicalizing reading is non-conformant and MUST adopt the literal matcher" --
% so the rule F40 landed on matches_scope/4 reaches here too, with delegation-chain
% WIDENING named as the reason: on the canonicalizing reading a bare id include reads as
% covered by a path-form parent pattern it does not literally match, and a child grant
% comes out wider than its parent. `lean`'s differential put it at 2 of 64 include pairs
% and 2 of 64 exclude pairs, fail-closed, with a 16-pair control alphabet reporting 0 --
% which is why every hand-tried example missed it.
%
% Kind has NO DEFAULT and is named at all four call sites above, because a default is how
% the next dimension inherits the wrong matcher silently -- the original F40 defect. The
% per-link granter frames are meaningless on the id arm (an id pattern is never
% canonicalized) and are simply unread there, which is why frame_for/4 ignores them.
scope_subset(ChildFrame, ParentFrame, ChildScope, ParentScope, Kind) :-
    scope_incl(ChildScope, CI), scope_excl(ChildScope, CE),
    scope_incl(ParentScope, PI), scope_excl(ParentScope, PE),
    forall(member(C, CI), ( subset_frame(Kind, ChildFrame, C, CC),
                            once(( member(P, PI), subset_frame(Kind, ParentFrame, P, CP),
                                   subset_covers(Kind, CP, CC) )) )),
    forall(member(Pe, PE), ( subset_frame(Kind, ParentFrame, Pe, CPe),
                             once(( member(Ce, CE), subset_frame(Kind, ChildFrame, Ce, CCe),
                                    subset_covers(Kind, CCe, CPe) )) )).

subset_frame(path, Frame, Pattern, Canon) :- !, canonicalize(Frame, Pattern, Canon).
subset_frame(id, _Frame, Pattern, Pattern).

subset_covers(path, Pattern, Value) :- !, matches_pattern(Value, Pattern).
subset_covers(id, Pattern, Value) :- matches_id_pattern(Value, Pattern).

% ── helpers ──────────────────────────────────────────────────────────────────
first_segment(Uri, Seg) :-
    ( string_concat("/", Rest, Uri) -> true ; Rest = Uri ),
    ( sub_string(Rest, B, _, _, "/") -> sub_string(Rest, 0, B, _, Seg) ; Seg = Rest ).

extract_peer(LocalPeer, Uri, Peer) :-
    normalize_uri(Uri, NU), first_segment(NU, First),
    ( is_peer_id(First) -> Peer = First ; Peer = LocalPeer ).

is_peer_id(Seg) :- string_length(Seg, L), L >= 46.

find_signature(Env, Target, Sig) :-
    envelope_included(Env, Included),
    member(_-Sig, Included),
    entity_type(Sig, "system/signature"),
    ent_bytes(Sig, "target", T), T == Target, !.

is_revoked(LocalPeer, StoreId, Cap, Included) :-
    envelope_with_included(Included, Env),
    Ctx = ctx(Env, StoreId),
    ( collect_chain(Ctx, Cap, Chain), last(Chain, Root) -> entity_hash(Root, RootHash) ; entity_hash(Cap, RootHash) ),
    entity_hash(Cap, CapHash),
    ( revocation_at(LocalPeer, StoreId, CapHash) ; revocation_at(LocalPeer, StoreId, RootHash) ), !.
revocation_at(LocalPeer, StoreId, Hash) :-
    bytes_hex(Hash, HexA), atom_string(HexA, Hex),
    atomics_to_string(["/", LocalPeer, "/system/capability/revocations/", Hex], Path),
    store_hash_at(StoreId, Path, _).

atomics_to_string(List, S) :- atomic_list_concat(List, A), atom_string(A, S).


% ── §1.4 PD-2: outbound sub-dispatch authorization ──────────────────────────

% peer_relative_of(+Uri, -Rel): strip the §1.4 scheme and leading peer segment.
%
% §1.4 admits three spellings of one address — "system/tree", "/{peer}/system/tree" and
% "entity://{peer}/system/tree" — and §1.4's PD-2 block requires Dimension 1's handler
% pattern to be the target uri's peer-relative path, because a grant names HANDLERS and a
% handler pattern never carries a peer segment. Matching a grant against the absolute or
% schemed form matches nothing, silently, which reads at the wire as an authority refusal.
%
% The first segment is dropped ONLY when it is a peer_id. A peer-relative
% "system/protocol/connect" must not lose "system" — the standing defect on smalltalk and
% forth, where an unconditional strip made every self-minted grant unusable while the
% handshake stayed green.
peer_relative_of(Uri, Rel) :-
    normalize_uri(Uri, P),
    ( string_concat("/", Body, P)
    -> ( split_string(Body, "/", "", [First|Rest]), Rest \== [], is_peer_id(First)
       -> atomic_list_concat(Rest, '/', RelAtom), atom_string(RelAtom, Rel)
       ;  Rel = Body )
    ;  Rel = P ).

% grant_path_for(+LocalPeer, +Pattern, -Path): the store key of a handler's OWN grant
% (§6.8), tolerant of the pattern arriving absolute or peer-relative.
%
% §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while the
% grant path is built from the PEER-RELATIVE one. The two are one segment apart and
% concatenating the wrong one yields a doubled peer segment whose lookup misses — which
% fails closed as "no handler grant" and is indistinguishable, at the wire, from a genuine
% authority refusal.
grant_path_for(LocalPeer, Pattern, Path) :-
    atomics_to_string(["/", LocalPeer, "/"], Prefix),
    ( string_concat(Prefix, Rel, Pattern) -> true ; Rel = Pattern ),
    atomics_to_string(["/", LocalPeer, "/system/capability/grants/", Rel], Path).

% target_minted_peers_relaxation(+LocalPeer, +TargetPeer, +StoreId, +Cred, +Included,
%                                -Relax)
%
% Relax is `relax(Scope)` when every §1.4 clause holds and the credential names a `peers`
% scope, `relax_to_target` when it holds and the credential does NOT (an absent `peers`
% dimension relaxes to the TARGET — the ordinary reentry shape, "you may dispatch back to
% me"), and `no_relax` otherwise.
%
% THREE ATOMS, NOT A SCOPE-OR-FAIL. A missing scope is a legitimate RESULT, so a predicate
% that simply failed would collapse it into "relaxes nothing" — the absent-vs-present
% conflation §6.2's CAP-6a records for temporal accessors, one layer up and in the
% direction that REFUSES a valid reentry.
target_minted_peers_relaxation(LocalPeer, TargetPeer, StoreId, Cred, Included, Relax) :-
    (   TargetPeer \== LocalPeer,
        verify_capability_chain_rooted_at(LocalPeer, TargetPeer, StoreId, Cred, Included),
        \+ is_revoked(LocalPeer, StoreId, Cred, Included),
        envelope_with_included(Included, Env),
        ent_bytes(Cred, "grantee", GH),
        cap_resolve(Env, StoreId, GH, GE),
        ent_bytes(GE, "public_key", PK),
        peer_id_of_pubkey(PK, LocalPeer),
        grants_of(Cred, [G|_])
    ->  ( ent_field_or_default(G, "peers", Scope)
        -> Relax = relax(Scope)
        ;  Relax = relax_to_target )
    ;   Relax = no_relax ).

% check_outbound_sub_dispatch(+LocalPeer, +TargetPeer, +HandlerPattern, +Operation,
%                             +HandlerGrant, +Resource, +Relax) (semidet)
%
% §1.4's PD-2 gate: check_permission run before a locally-originated sub-dispatch LEAVES
% the peer, with all four dimensions applied.
%
% ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT decides
% all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's pattern the
% target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE TARGET PEER naming
% this peer as grantee relaxes Dimension 4 (peers) AND ONLY DIMENSION 4.
%
% "The target answers WHERE; the handler's grant answers WHAT." A credential is NOT a
% grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
% sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
% BYPASS it is distinguished from is a peer that treats the credential as a standalone
% authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
% obvious vectors agree under either reading, so the only input that separates them is a
% VALID credential presented to a handler whose own grant does NOT cover the request.
%
% Relax = no_relax is the ambient arm: Dimension 4 is decided by the grant alone.
check_outbound_sub_dispatch(LocalPeer, TargetPeer, HandlerPattern, Operation,
                            HandlerGrant, Resource, Relax) :-
    grants_of(HandlerGrant, Grants),
    member(G, Grants),
    grant_field(G, "handlers", HScope), matches_scope(LocalPeer, HandlerPattern, HScope, path),
    grant_field(G, "operations", OScope), matches_scope(LocalPeer, Operation, OScope, id),
    check_resource_scope(LocalPeer, LocalPeer, Resource, G),
    % Dimension 4. §5.2's default for an absent `peers` scope is {include:[local]}, so a
    % foreign target fails unless this grant names it or a target-minted credential
    % relaxes it.
    (   peer_scope_ok(LocalPeer, TargetPeer, G)
    ;   Relax == relax_to_target
    ;   Relax = relax(RScope), matches_scope(LocalPeer, TargetPeer, RScope, id)
    ), !.
