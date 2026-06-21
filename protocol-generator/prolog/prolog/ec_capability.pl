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
            extract_peer/3,             % +LocalPeer, +Uri, -TargetPeer
            is_peer_id/1                % +Seg (semidet: looks like a peer_id)
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
    envelope_with_included(Included, Env),
    Ctx = ctx(Env, StoreId),
    collect_chain(Ctx, Cap, Chain),
    last(Chain, Root),
    root_authority_ok(LocalPeer, Ctx, Root),
    verify_chain(LocalPeer, Ctx, Chain).

% wrap a bare included-list as a query-able pseudo-envelope for cap_resolve.
envelope_with_included(Included, envelope(_, Included)).

% root authority (§5.5): a single-sig root must root at the LOCAL peer; a §3.6 M3
% multi-sig root must pass k-of-n quorum.
root_authority_ok(LocalPeer, Ctx, Root) :-
    ( is_multisig(Root)
    -> verify_multisig_root(LocalPeer, Ctx, Root)
    ;  Ctx = ctx(Env, StoreId),
       ent_bytes(Root, "granter", GH),
       cap_resolve(Env, StoreId, GH, G),
       ent_bytes(G, "public_key", PK),
       peer_id_of_pubkey(PK, LocalPeer) ).

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
    cap_now_ms(Now),
    ( ent_uint(Cap, "not_before", NB) -> Now >= NB ; true ),
    ( ent_uint(Cap, "expires_at", EX) -> Now < EX ; true ).

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

canonicalize(_LocalPeer, Path, _) :- string_concat("./", _, Path), !, throw(ec_capability(reserved_rel_path)).
canonicalize(_LocalPeer, Path, _) :- string_concat("../", _, Path), !, throw(ec_capability(reserved_rel_path)).
canonicalize(_LocalPeer, Path, _) :- string_concat("*/", _, Path), !, throw(ec_capability(ambiguous_wildcard)).
canonicalize(_LocalPeer, Path, Path) :- string_concat("/", _, Path), !.
canonicalize(LocalPeer, Path, Abs) :- atomics_to_string(["/", LocalPeer, "/", Path], Abs).

% §5.4 pattern matching. Both PATH and PATTERN are canonical (absolute).
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

matches_scope(LocalPeer, Value, Scope) :-
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
    grant_field(G, "operations", OpScope), matches_scope(LocalPeer, Op, OpScope),
    grant_field(G, "handlers", HScope), matches_scope(LocalPeer, HandlerPattern, HScope),
    peer_scope_ok(LocalPeer, TargetPeer, G),
    resource_ok(LocalPeer, GranterPeer, Exec, G).

peer_scope_ok(LocalPeer, TargetPeer, G) :-
    ( ent_field_or_default(G, "peers", PScope)
    -> matches_scope(LocalPeer, TargetPeer, PScope)
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
    forall(member(T, Targets),
           ( canonicalize(LocalPeer, T, CT),
             ( member(CE, CallerExcl), canonicalize(LocalPeer, CE, CCE), matches_pattern(CT, CCE)
             -> true
             ;  once(( member(I, Incl), canonicalize(GranterPeer, I, CI), matches_pattern(CT, CI) )),
                \+ ( member(E2, Excl), canonicalize(GranterPeer, E2, CE2), matches_pattern(CT, CE2) ) ) )).

% ═══════════════════════════════════════════════════════════════════════════
% §5.6 grant_subset (attenuation predicate, used by mint-bounded + chain walk).
% Resource dimension uses the §5.5a per-link granter frames; handlers/ops/peers
% stay on LocalPeer.
% ═══════════════════════════════════════════════════════════════════════════
grant_subset(LocalPeer, ChildPeer, ParentPeer, Child, Parent) :-
    grant_field(Child, "handlers", CH), grant_field(Parent, "handlers", PH),
    scope_subset(LocalPeer, LocalPeer, CH, PH),
    grant_field(Child, "operations", CO), grant_field(Parent, "operations", PO),
    scope_subset(LocalPeer, LocalPeer, CO, PO),
    grant_field(Child, "resources", CR), grant_field(Parent, "resources", PR),
    scope_subset(ChildPeer, ParentPeer, CR, PR),
    peers_subset(LocalPeer, Child, Parent).

peers_subset(LocalPeer, Child, Parent) :-
    child_peers(LocalPeer, Child, CP),
    child_peers(LocalPeer, Parent, PP),
    scope_subset(LocalPeer, LocalPeer, CP, PP).
child_peers(LocalPeer, G, Scope) :-
    ( ent_field_or_default(G, "peers", Scope) -> true ; Scope = map(["include"-[LocalPeer]]) ).

% scope_subset: every child include is covered by some parent include (frames per
% dimension), and every parent exclude is covered by some child exclude.
scope_subset(ChildFrame, ParentFrame, ChildScope, ParentScope) :-
    scope_incl(ChildScope, CI), scope_excl(ChildScope, CE),
    scope_incl(ParentScope, PI), scope_excl(ParentScope, PE),
    forall(member(C, CI), ( canonicalize(ChildFrame, C, CC),
                            once(( member(P, PI), canonicalize(ParentFrame, P, CP), matches_pattern(CC, CP) )) )),
    forall(member(Pe, PE), ( canonicalize(ParentFrame, Pe, CPe),
                             once(( member(Ce, CE), canonicalize(ChildFrame, Ce, CCe), matches_pattern(CPe, CCe) )) )).

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
