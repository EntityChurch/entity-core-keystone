% spec0831.pl — the 0.8.2.31 §1.4 PD-2 outbound sub-dispatch gate.
%
% §1.4's "ONE GATE AND ONE EXEMPTION": a locally-originated sub-dispatch is authorized by
% the EXECUTING HANDLER'S OWN GRANT across all four dimensions in the LOCAL frame, and a
% valid capability MINTED BY THE TARGET PEER naming this peer as grantee relaxes
% Dimension 4 (peers) AND ONLY DIMENSION 4.
%
% ⛔ WHY THIS FILE HAS TO EXIST — THE WIRE CANNOT MEASURE THE RULE IT IS ABOUT.
% §6.8 states outright that its confused-deputy substitution is WIRE-INVISIBLE: "both
% readings produce a well-formed response and differ only in which authority was
% consulted." The only input that separates them is a VALID credential presented to a
% handler whose OWN grant does not cover the request — and the oracle does not drive one.
% So `dispatch_outbound_*` going green is not evidence for this rule, and a peer with no
% unit seam leaves it UNMEASURED rather than passing it. This peer has a seam, so it is
% measured here, and `t_bypass_discriminator` is the case that does it.
%
% ⛔ AND THE MULTI-SIGNATURE ARM NEEDS AN ANTECEDENT OR IT MEASURES NOTHING.
% The oracle's own K-of-N vector is refused by §5.5's M6 (the local peer must be a
% validated quorum member) BEFORE §1.4 is ever consulted, so a green row there says
% nothing about the foreign-frame rule. `t_multisig_root_never_relaxes` therefore asserts
% FIRST that the very same quorum root verifies in the LOCAL frame — without that
% antecedent the deny is unattributable and the control is inert, which is exactly how the
% go vanguard's first version shipped.
%
% THE PROLOG TRAP THIS FILE INHERITS FROM spec0825.pl: a refusal written as throw/1 does
% NOT fall through to the clause below it. Every refusal exercised here is a relational
% FAILURE, so `\+ Goal` is the assertion and a thrown ball would surface as a warning
% through check/2 rather than as a silent pass.

:- module(spec0831, [run_spec0831/0, run_spec0831_main/0]).

:- use_module('../prolog/ec_codec').
:- use_module('../prolog/ec_cbor').
:- use_module('../prolog/ec_entity').
:- use_module('../prolog/ec_identity').
:- use_module('../prolog/ec_store').
:- use_module('../prolog/ec_capability').
:- use_module('../prolog/ec_peer').
:- use_module(library(lists)).

:- dynamic result/2.

check(Name, Goal) :-
    ( catch(Goal, E, (print_message(warning, E), fail)) -> OK = true ; OK = false ),
    assertz(result(Name, OK)),
    ( OK == true -> format("  [PASS] ~w~n", [Name]) ; format("  [FAIL] ~w~n", [Name]) ),
    flush_output.

run_spec0831_main :- ( run_spec0831 -> halt(0) ; halt(1) ).

run_spec0831 :-
    retractall(result(_,_)),
    format("Section 1.4 peer_relative_of — three spellings, one form:~n", []),
    t_peer_relative,
    format("Section 6.8 the handler's own grant decides all four dimensions:~n", []),
    t_own_grant_dimensions,
    format("Section 1.4 a target-minted credential relaxes Dimension 4 and ONLY it:~n", []),
    t_relaxation_scope,
    format("Section 6.8 THE BYPASS DISCRIMINATOR (wire-invisible):~n", []),
    t_bypass_discriminator,
    format("Section 1.4 a multi-signature root NEVER relaxes a foreign frame:~n", []),
    t_multisig_root_never_relaxes,
    format("Section 7a.1 the reentry triple is ALL-OR-NONE:~n", []),
    t_all_or_none,
    findall(N, result(N, false), Fails),
    findall(N, result(N, _), All),
    length(All, Total), length(Fails, NF), Pass is Total - NF,
    % ASSERT THE COUNT, not merely the absence of failures: a file whose cases all
    % vanished reports "0 failures" exactly like one where every case ran and passed.
    ( Total >= 16 -> Floor = ok ; Floor = under ),
    ( NF =:= 0, Floor == ok -> V = 'PASS' ; V = 'FAIL' ),
    format("~nspec-0831: ~w (~d/~d, floor 16)~n", [V, Pass, Total]),
    NF =:= 0, Floor == ok.

% ── fixtures ────────────────────────────────────────────────────────────────

fixed_seed(B, S) :- length(C, 32), maplist(=(B), C), string_codes(S, C).

% Two distinct identities: the LOCAL peer and a FOREIGN target.
local_identity(I)  :- fixed_seed(0x21, S), make_identity(S, I).
target_identity(I) :- fixed_seed(0x22, S), make_identity(S, I).
third_identity(I)  :- fixed_seed(0x23, S), make_identity(S, I).

local_peer(P)  :- local_identity(I),  identity_peer_id(I, P).
target_peer(P) :- target_identity(I), identity_peer_id(I, P).

% The NARROW scaffold grant, byte-for-byte what handler_own_grants/2 mints for
% `system/validate/dispatch-outbound`. No `peers` dimension, on purpose: §5.2's default
% is {include:[local]}, which is the thing a credential has to relax.
narrow_grant_token(Token) :-
    local_identity(I), identity_hash(I, H),
    G = map(["handlers"-map(["include"-["system/validate/echo"]]),
             "resources"-map(["include"-["system/handler/system/validate/echo"]]),
             "operations"-map(["include"-["echo"]])]),
    ec_peer:mint_token(I, H, [G], Token, _).

% A grant that additionally names the TARGET in its `peers` dimension — the ambient way
% to be allowed to dispatch outward, with no credential in play at all.
peers_naming_grant_token(Token) :-
    local_identity(I), identity_hash(I, H), target_peer(TP),
    G = map(["handlers"-map(["include"-["system/validate/echo"]]),
             "resources"-map(["include"-["system/handler/system/validate/echo"]]),
             "operations"-map(["include"-["echo"]]),
             "peers"-map(["include"-[TP]])]),
    ec_peer:mint_token(I, H, [G], Token, _).

echo_resource(map(["targets"-["system/handler/system/validate/echo"]])).
other_resource(map(["targets"-["system/handler/system/tree"]])).

% ── §1.4: the three spellings of one address ────────────────────────────────

t_peer_relative :-
    target_peer(TP),
    atomic_list_concat(['/', TP, '/system/validate/echo'], AbsA),
    atom_string(AbsA, Abs),
    atomic_list_concat(['entity://', TP, '/system/validate/echo'], SchemedA),
    atom_string(SchemedA, Schemed),
    % ⚠ ONE VARIABLE PER ASSERTION, NEVER ONE PER CLAUSE. check/2 commits with `->`, so a
    % binding made inside a successful check SURVIVES into every check below it in the same
    % clause body. Reusing a single `R` here made checks 2 and 3 pass by COINCIDENCE (both
    % answers happen to equal check 1's) and check 4 fail against a value it never computed
    % — three assertions saying nothing and one reporting a defect in the wrong predicate.
    % The generalizable half: on a substrate where an assertion can leave a binding behind,
    % a shared variable is an inert control that also manufactures a false failure.
    check('peer-relative form is unchanged',
          ( peer_relative_of("system/validate/echo", R1), R1 == "system/validate/echo" )),
    check('absolute form loses exactly the peer segment',
          ( peer_relative_of(Abs, R2), R2 == "system/validate/echo" )),
    check('schemed absolute form loses scheme and peer',
          ( peer_relative_of(Schemed, R3), R3 == "system/validate/echo" )),
    % THE DEFECT THIS GUARDS, and it has bitten smalltalk and forth: an UNCONDITIONAL
    % strip of the first segment turns `system/protocol/connect` into `protocol/connect`,
    % which makes every self-minted grant unusable while the handshake stays green.
    check('a NON-peer first segment is NOT stripped',
          ( peer_relative_of("system/protocol/connect", R4), R4 == "system/protocol/connect" )).

% ── §6.8: all four dimensions, on the handler's own grant ───────────────────

t_own_grant_dimensions :-
    local_peer(LP), target_peer(TP),
    narrow_grant_token(Narrow), peers_naming_grant_token(WithPeers),
    echo_resource(EchoRes), other_resource(OtherRes),
    % Dimension 4 by the grant alone (the AMBIENT arm), target == local.
    check('ambient, in-grant, local target ALLOWS',
          check_outbound_sub_dispatch(LP, LP, "system/validate/echo", "echo",
                                      Narrow, EchoRes, no_relax)),
    % D1 handlers
    check('ambient, handler OUTSIDE the grant REFUSES',
          \+ check_outbound_sub_dispatch(LP, LP, "system/tree", "echo",
                                         Narrow, EchoRes, no_relax)),
    % D2 operations
    check('ambient, operation OUTSIDE the grant REFUSES',
          \+ check_outbound_sub_dispatch(LP, LP, "system/validate/echo", "put",
                                         Narrow, EchoRes, no_relax)),
    % D3 resources
    check('ambient, resource OUTSIDE the grant REFUSES',
          \+ check_outbound_sub_dispatch(LP, LP, "system/validate/echo", "echo",
                                         Narrow, OtherRes, no_relax)),
    % D4 peers — §5.2's default for an ABSENT `peers` scope is {include:[local]}, so a
    % foreign target is refused on a grant that does not name it. Getting this wrong is a
    % VACUOUS PASS rather than a visible failure, which is why it is asserted directly.
    check('ambient, FOREIGN target REFUSES on a grant with no peers scope',
          \+ check_outbound_sub_dispatch(LP, TP, "system/validate/echo", "echo",
                                         Narrow, EchoRes, no_relax)),
    check('ambient, FOREIGN target ALLOWS when the grant NAMES it',
          check_outbound_sub_dispatch(LP, TP, "system/validate/echo", "echo",
                                      WithPeers, EchoRes, no_relax)).

% ── §1.4: the relaxation is Dimension 4 and only Dimension 4 ────────────────

t_relaxation_scope :-
    local_peer(LP), target_peer(TP),
    narrow_grant_token(Narrow),
    echo_resource(EchoRes), other_resource(OtherRes),
    check('relax_to_target opens D4 for the foreign target',
          check_outbound_sub_dispatch(LP, TP, "system/validate/echo", "echo",
                                      Narrow, EchoRes, relax_to_target)),
    % ⭐ AND ONLY D4. Each of these presents the SAME relaxation and still refuses,
    % because the relaxation has nothing to say about handlers, operations or resources.
    % Without these three the test would pass against an implementation that treated a
    % valid credential as a blanket authorizer — which IS the bypass.
    check('relaxation does NOT open D1 (handlers)',
          \+ check_outbound_sub_dispatch(LP, TP, "system/tree", "echo",
                                         Narrow, EchoRes, relax_to_target)),
    check('relaxation does NOT open D2 (operations)',
          \+ check_outbound_sub_dispatch(LP, TP, "system/validate/echo", "put",
                                         Narrow, EchoRes, relax_to_target)),
    check('relaxation does NOT open D3 (resources)',
          \+ check_outbound_sub_dispatch(LP, TP, "system/validate/echo", "echo",
                                         Narrow, OtherRes, relax_to_target)).

% ── §6.8: the discriminator the wire cannot see ─────────────────────────────

t_bypass_discriminator :-
    local_peer(LP), target_peer(TP),
    narrow_grant_token(Narrow),
    other_resource(OtherRes),
    % THE ANTECEDENT: the same credential relaxation on an IN-GRANT request must ALLOW.
    % Without it, a peer that refuses everything passes the next case for free — the
    % deny-only failure this repo filed against the oracle as F70, committed here.
    echo_resource(EchoRes),
    check('antecedent — the credential DOES authorize an in-grant sub-dispatch',
          check_outbound_sub_dispatch(LP, TP, "system/validate/echo", "echo",
                                      Narrow, EchoRes, relax_to_target)),
    % THE CASE ITSELF: a VALID target-minted credential, presented to a handler whose own
    % grant does NOT cover the request. The correct reading REFUSES (the grant answers
    % WHAT); the confused-deputy reading ALLOWS (the credential is treated as a standalone
    % authorizer and steers the handler past its own grant). Both produce a well-formed
    % response, which is why §6.8 calls it wire-invisible.
    check('THE BYPASS — a valid credential does NOT steer past the handler grant',
          \+ check_outbound_sub_dispatch(LP, TP, "system/tree", "get",
                                         Narrow, OtherRes, relax_to_target)).

% ── §1.4: a quorum root is LOCAL-FRAME ONLY ─────────────────────────────────
%
% "Minted by the target" means the target SOLELY minted it. A K-of-N root is a GROUP's
% authority — its co-signers authorized it too — so accepting one in a foreign frame lets
% any single signer's target confer the whole group's grant. That is E3/F66.

t_multisig_root_never_relaxes :-
    local_peer(LP), target_peer(TP),
    local_identity(LI), third_identity(TI),
    store_new(StoreId),
    multisig_root(LI, TI, StoreId, Root, Included),
    % ⛔ THE ANTECEDENT, and the whole case is unattributable without it: the SAME quorum
    % root must verify in the LOCAL frame. If it does not, the deny below is explained by
    % §5.5's M6 or by a malformed fixture rather than by §1.4, and the control is inert —
    % which is precisely how the oracle's own K-of-N row passes on peers that have never
    % implemented this rule.
    check('antecedent — the quorum root DOES verify in the local frame',
          verify_capability_chain_rooted_at(LP, LP, StoreId, Root, Included)),
    check('the SAME quorum root is REFUSED in the target frame',
          \+ verify_capability_chain_rooted_at(LP, TP, StoreId, Root, Included)),
    % And therefore it relaxes nothing: the relaxation is computed from a chain walk that
    % refuses, so `no_relax` is the only reachable answer.
    check('so a quorum-rooted credential yields no_relax',
          ( target_minted_peers_relaxation(LP, TP, StoreId, Root, Included, Rx),
            Rx == no_relax )).

% A §3.6 M3 multi-signature root co-signed by the local peer and a third party.
%
% ⚠ THE GRANTER IS A MAP CARRYING `signers` + `threshold`, NOT a top-level array — that is
% what is_multisig/1 dispatches on (`ent_field(Cap, "granter", map(_))`). A fixture written
% with a top-level `granters` list is simply a SINGLE-SIG token with an unread field, so it
% takes the single-granter arm, fails to resolve a granter, and the foreign-frame case then
% "passes" having measured nothing. The antecedent assertion is what caught that.
multisig_root(LocalId, ThirdId, StoreId, Root, Included) :-
    identity_hash(LocalId, LH), identity_hash(ThirdId, TH),
    identity_peer_entity(LocalId, LPE), identity_peer_entity(ThirdId, TPE),
    string_codes(LH, LHC), string_codes(TH, THC),
    G = map(["handlers"-map(["include"-["system/validate/echo"]]),
             "resources"-map(["include"-["system/handler/system/validate/echo"]]),
             "operations"-map(["include"-["echo"]])]),
    ec_peer:now_ms(Created),
    make_entity("system/capability/token",
                map(["granter"-map(["signers"-[bytes(LHC), bytes(THC)],
                                    "threshold"-int(2)]),
                     "grantee"-bytes(LHC),
                     "grants"-[G],
                     "created_at"-int(Created)]), Root),
    sign_entity(LocalId, Root, SigA),
    sign_entity(ThirdId, Root, SigB),
    store_put_entity(StoreId, LPE), store_put_entity(StoreId, TPE),
    ec_peer:included_pairs([Root, LPE, TPE, SigA, SigB], Included).

% ── §7a.1: the reentry triple is all-or-none ────────────────────────────────

t_all_or_none :-
    make_entity("system/capability/token", map(["granter"-bytes([1,2,3])]), Cap),
    make_entity("system/peer", map(["public_key"-bytes([1,2,3])]), Gr),
    make_entity("system/signature", map(["target"-bytes([9])]), Sg),
    entity_to_cbor(Cap, CapV), entity_to_cbor(Gr, GrV), entity_to_cbor(Sg, SgV),
    params_with(["reentry_capability"-CapV,
                 "reentry_granters"-[GrV],
                 "reentry_cap_signatures"-[SgV]], PAll),
    params_with([], PNone),
    params_with(["reentry_capability"-CapV], PPartial),
    % An EMPTY array carries no credential, so it is PARTIAL rather than present —
    % the absent-vs-present conflation, in the direction that would silently downgrade a
    % caller who believes they presented authority to the ambient arm.
    params_with(["reentry_capability"-CapV,
                 "reentry_granters"-[],
                 "reentry_cap_signatures"-[SgV]], PEmpty),
    % THE SINGULAR SPELLINGS ARE STILL ACCEPTED, as an array of one. This case is the
    % thing that keeps this peer 0-FAIL at the PINNED check set, whose oracle sends them;
    % it should be DELETED at the oracle re-pin, together with the fallback it covers.
    params_with(["reentry_capability"-CapV,
                 "reentry_granter"-GrV,
                 "reentry_cap_signature"-SgV], PSingular),
    % One variable per assertion — see the note in t_peer_relative/0. A shared `A` here
    % made the ambient, partial and empty cases fail against the FIRST case's binding
    % while the last case passed by matching it, which reads as four defects in
    % reentry_authority/2 and was four defects in the test.
    check('all three present selects the PRESENTED arm',
          ( ec_peer:reentry_authority(PAll, A1), A1 = cred(_, [_], [_]) )),
    check('all three absent selects the AMBIENT arm',
          ( ec_peer:reentry_authority(PNone, A2), A2 == ambient )),
    check('a PARTIAL triple is neither — it is malformed',
          ( ec_peer:reentry_authority(PPartial, A3), A3 == partial )),
    check('an EMPTY carrier array is PARTIAL, not present',
          ( ec_peer:reentry_authority(PEmpty, A4), A4 == partial )),
    check('TRANSITIONAL — the singular spellings still read as an array of one',
          ( ec_peer:reentry_authority(PSingular, A5), A5 = cred(_, [_], [_]) )).

params_with(Pairs, P) :- make_entity("primitive/any", map(Pairs), P).
