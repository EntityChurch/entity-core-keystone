% spec0825.pl — the 0.8.2.20 -> 0.8.2.25 scope-algebra units.
%
% §3.3's effective-target projection, §6.3's handler-level path check, §5.2's PATH-SCOPED
% sentinel guard, and §5.5a's scope-kind-typed subset check.
%
% WHAT IS HERE AND WHAT IS NOT, deliberately. These are the pure relations. The §3.3
% LADDER (which arm answers which code) and the operation-before-resource ordering are
% driven over a real socket in smoke.pl scenario 3, because both are properties of the
% handler's clause table rather than of any one relation, and because §4.11's frame
% obligation is a RUNTIME property that only a socket can measure. The code-by-cause table
% IS pinned here — it is a pure relation and it is the half a unit can reach.
%
% THE PROLOG TRAP THIS FILE EXISTS PARTLY TO GUARD: a refusal written as `throw/1` does
% NOT fall through to the clause below it — it unwinds to the dispatcher's catch, where
% the generic handler turns it into 500 internal_error, and the tidy fallback clause that
% LOOKS like the refusal is dead code. This peer has been bitten by that twice (the §1.4
% address gate, and canonicalize/3's reserved arms). Every refusal added by the 0.8.2.25
% work is therefore an OUTCOME TERM or a relational FAILURE, never a thrown ball, and the
% classifier below is a relation over an ALREADY-CAUGHT term rather than a new throw site.

:- module(spec0825, [run_spec0825/0, run_spec0825_main/0]).

:- use_module('../prolog/ec_codec').
:- use_module('../prolog/ec_cbor').
:- use_module('../prolog/ec_entity').
:- use_module('../prolog/ec_capability').
:- use_module('../prolog/ec_wire').
:- use_module(library(lists)).

:- dynamic result/2.

check(Name, Goal) :-
    ( catch(Goal, E, (print_message(warning, E), fail)) -> OK = true ; OK = false ),
    assertz(result(Name, OK)),
    ( OK == true -> format("  [PASS] ~w~n", [Name]) ; format("  [FAIL] ~w~n", [Name]) ),
    flush_output.

run_spec0825_main :- ( run_spec0825 -> halt(0) ; halt(1) ).

run_spec0825 :-
    retractall(result(_,_)),
    format("Section 3.3 effective targets (0.8.2.20/.21, N11):~n", []),
    t_effective_targets,
    format("Section 6.3 check_path_permission:~n", []),
    t_check_path_permission,
    format("Section 5.2 the sentinel is PATH-SCOPE only (0.8.2.24 N2/N3):~n", []),
    t_sentinel_scope,
    format("Section 5.5a scope_subset is typed by scope kind (F50 / 0.8.2.16):~n", []),
    t_scope_subset_typing,
    findall(N, result(N, false), Fails),
    findall(N, result(N, _), All),
    length(All, Total), length(Fails, NF), Pass is Total - NF,
    ( NF =:= 0 -> V = 'PASS' ; V = 'FAIL' ),
    format("~nspec-0825: ~w (~d/~d)~n", [V, Pass, Total]),
    NF =:= 0.

local("2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg").
pattern("/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/system/tree").
covered_path("/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/system/type/qA").
outside_path("/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/secrets/qB").

% An EXECUTE carrying `operation`, `uri` and optionally a `resource`.
exec_with(Op, Resource, Exec) :-
    pattern(P),
    ( Resource == (-)
    -> Pairs = ["operation"-Op, "uri"-P]
    ;  Pairs = ["operation"-Op, "uri"-P, "resource"-Resource] ),
    make_entity("system/protocol/execute", map(Pairs), Exec).

resource(Targets, [], map(["targets"-Targets])) :- !.
resource(Targets, Excl, map(["targets"-Targets, "exclude"-Excl])).

% include/exclude are BOTH emitted so an empty include is DISTINGUISHABLE from an absent
% one — §5.2 makes an empty include a legal grant shape that denies everything, and a
% fixture that dropped the key would test the wrong thing.
scope(Incl, Excl, map(["include"-Incl, "exclude"-Excl])).

grant(HI-HX, OI-OX, RI-RX, map(["handlers"-H, "operations"-O, "resources"-R])) :-
    scope(HI, HX, H), scope(OI, OX, O), scope(RI, RX, R).

token(Grants, Tok) :- make_entity("system/capability/token", map(["grants"-Grants]), Tok).

% ── §3.3 effective targets ───────────────────────────────────────────────────

t_effective_targets :-
    local(L),
    % ABSENT resource — the two empties must be TELLABLE APART (N11). A projection that
    % answered [] here would delete the discriminator before any handler could read it,
    % and `get`'s absent arm (a root listing) and its self-excluded arm (400
    % path_required) would collapse into one. On this substrate the discriminator is
    % relational FAILURE, the same channel §5.5 uses for "deny".
    check("absent resource: effective_targets/3 FAILS (not [])",
          ( exec_with("get", (-), E1), \+ effective_targets(L, E1, _) )),

    % PRESENT, every target carved out by the caller's own exclude: SUCCEEDS with [].
    % This is the other half of the discriminator.
    check("present resource, all excluded: succeeds with []",
          ( resource(["a/b"], ["a/*"], R2), exec_with("get", R2, E2),
            effective_targets(L, E2, S2), S2 == [] )),

    % SURVIVORS COME BACK IN THE CALLER'S OWN SPELLING, not canonicalized (0.8.2.21). The
    % value flows on to the store lookup, which canonicalizes for itself; handing back a
    % canonical form here would double-canonicalize a relative target.
    check("survivors keep the caller's own spelling",
          ( resource(["x/one", "x/two"], ["x/two"], R3), exec_with("get", R3, E3),
            effective_targets(L, E3, S3), S3 == ["x/one"] )),

    % THE SELECTION MUST (F84): the survivor is the one the exclude LEFT, never
    % targets[0]. That is the whole point — a handler that counts the effective list and
    % then indexes the raw targets has the arithmetic right and reads a path no
    % authorization covered.
    check("the survivor is targets[1] when targets[0] is excluded",
          ( resource(["x/one", "x/two"], ["x/one"], R4), exec_with("get", R4, E4),
            effective_targets(L, E4, S4), S4 == ["x/two"] )),

    % THE CALLER-EXCLUDE ARM IS FAIL-OPEN ON AN UNMATCHABLE PATTERN. §5.4 rules it
    % separately from the grant arm: canonicalize/3 answers the sentinel,
    % matches_pattern/2 then fails, and the target simply SURVIVES. Inherited, not
    % restated — this case exists so the inheritance is measured rather than assumed.
    check("an unmatchable CALLER exclude carves out nothing",
          ( resource(["x/one"], ["../nope"], R5), exec_with("get", R5, E5),
            effective_targets(L, E5, S5), S5 == ["x/one"] )),

    % A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
    % Reporting it absent would serve the WIDER absent-case answer to a request that
    % named a resource — N11's own defect one field over.
    check("an ill-typed targets is still a PRESENT resource",
          ( exec_with("get", map(["targets"-int(7)]), E6),
            effective_targets(L, E6, S6), S6 == [] )).

% ── §6.3 check_path_permission ───────────────────────────────────────────────

t_check_path_permission :-
    local(L), pattern(P), covered_path(CP), outside_path(OP),
    grant(["system/tree"]-[], ["get"]-[], ["system/type/*"]-[], G1), token([G1], T1),

    % The ACCEPT case first, and it is the one that validates the FIXTURE: a suite built
    % only from deny cases is indistinguishable from one asserting False == False, which a
    % mis-built grant fixture guarantees for free.
    check("a grant covering handler+operation+resource ALLOWS",
          check_path_permission(L, "get", CP, T1, P)),
    % One deny per DIMENSION — a single deny cannot distinguish "the relation checks the
    % dimension I care about" from "the relation denies".
    check("RESOURCES: a path outside resources.include DENIES",
          \+ check_path_permission(L, "get", OP, T1, P)),
    check("OPERATIONS: an operation outside operations.include DENIES",
          \+ check_path_permission(L, "put", CP, T1, P)),
    check("HANDLERS: a handler pattern outside handlers.include DENIES",
          \+ check_path_permission(L, "get", CP, T1, "/x/system/other")),

    % AN EMPTY `resources.include` IS A LEGAL GRANT SHAPE and denies EVERY path (§5.2:
    % handlers that touch no tree paths). The once/1 over an empty include list fails,
    % which is what that note says it should do.
    check("an empty resources.include denies every path",
          ( grant(["system/tree"]-[], ["get"]-[], []-[], G2), token([G2], T2),
            \+ check_path_permission(L, "get", CP, T2, P) )),

    % A GRANT EXCLUDE COVERING THE SUBJECT DENIES, even though the include covers it.
    check("a grant exclude covering the subject denies",
          ( grant(["system/tree"]-[], ["get"]-[], ["system/type/*"]-["system/type/qA"], G3),
            token([G3], T3), \+ check_path_permission(L, "get", CP, T3, P) )),

    % A MALFORMED PATH canonicalizes to the §5.4 sentinel, which matches no grant, so it
    % falls through to DENY rather than being matched against anything — including against
    % a grant whose include is a bare star.
    grant(["system/tree"]-[], ["get"]-[], ["*"]-[], G4), token([G4], T4),
    check("control: the bare-star grant does allow an ordinary path",
          check_path_permission(L, "get", CP, T4, P)),
    check("a path that canonicalizes to NEVER_MATCH denies",
          \+ check_path_permission(L, "get", "../nope", T4, P)),

    % THE OPERATIONS DIMENSION IS ID-SCOPE, NOT PATH-SCOPE (F40). A path-form pattern in
    % `operations` is matched as a LITERAL string: a non-match, never a fault, and never a
    % canonicalizing match against an unrelated operation name.
    check("operations is id-scope: a path-form pattern is a literal, not a match",
          ( grant(["system/tree"]-[], ["/*/get"]-[], ["*"]-[], G5), token([G5], T5),
            \+ check_path_permission(L, "get", CP, T5, P) )).

% ── §5.2 the sentinel guard is scoped to PATH-SCOPE ──────────────────────────

t_sentinel_scope :-
    local(L), pattern(P),
    % AN ID-SCOPE EXCLUDE THAT PATH-CANONICALIZES TO THE SENTINEL MUST NOT DENY THE WHOLE
    % DIMENSION. "*/apply" is an ordinary namespaced operation name and a literal under
    % the id-scope grammar; putting it through the §5.4 transforms purely to classify it
    % produced the sentinel and denied EVERY operation. Over-denial, and invisible on any
    % well-formed grant — which is why this needs a driven case rather than a reading.
    check("an id-scope exclude that path-canonicalizes to the sentinel does not deny",
          ( grant(["*"]-[], ["*"]-["*/apply"], ["*"]-[], G1), token([G1], T1),
            exec_with("get", (-), E1),
            check_permission(L, L, E1, T1, P, allow) )),

    % THE PATH-SCOPE ARM STILL DENIES — the control that says the guard was SCOPED rather
    % than DELETED. An unmatchable exclude on `resources` excludes everything (0.8.2.21),
    % because there the sentinel means the author wrote a carve-out that carves nothing
    % and the grant is silently wider than written.
    check("an unmatchable PATH-SCOPE (resources) exclude still denies",
          ( grant(["*"]-[], ["*"]-[], ["*"]-["../nope"], G2), token([G2], T2),
            resource(["system/type/qA"], [], R2), exec_with("get", R2, E2),
            check_permission(L, L, E2, T2, P, deny) )),

    % And the same guard on the HANDLERS dimension, the other path-scope one.
    check("an unmatchable handlers exclude still denies (handlers is path-scope)",
          ( grant(["*"]-["../nope"], ["*"]-[], ["*"]-[], G3), token([G3], T3),
            exec_with("get", (-), E3),
            check_permission(L, L, E3, T3, P, deny) )).

% ── §5.5a scope_subset is typed by scope kind ────────────────────────────────

subset(ChildOps, ParentOps, ChildRes, ParentRes) :-
    local(L),
    grant(["*"]-[], ChildOps, ChildRes, C),
    grant(["*"]-[], ParentOps, ParentRes, Pa),
    grant_subset(L, L, L, C, Pa).

t_scope_subset_typing :-
    % THE DIFFERENTIAL. entity-core-formalization measured 2 of 64 include pairs
    % disagreeing between the two readings, FAIL-CLOSED, with a 16-pair control alphabet
    % reporting 0 — which is why every hand-tried example missed it. Both witnesses
    % ("*/apply", "/tree/get") are OPERATIONS patterns, which §3.6 types as id-scope:
    % under the literal matcher a bare-star parent covers any child pattern, and under
    % the canonicalizing matcher the child canonicalizes to the sentinel (or to an
    % absolute path the parent's peer-framed star cannot cover) and the subset is wrongly
    % REFUSED.
    check("id-scope: a namespaced operation child is covered by a bare-star parent",
          subset(["*/apply"]-[], ["*"]-[], ["*"]-[], ["*"]-[])),
    check("id-scope: a path-form operation child is covered by a bare-star parent",
          subset(["/tree/get"]-[], ["*"]-[], ["*"]-[], ["*"]-[])),

    % THE CONTROL ALPHABET — the pairs that agree under both readings. Without these the
    % two cases above are equally explained by a subset check that has stopped checking.
    check("control: get is covered by a bare-star parent",
          subset(["get"]-[], ["*"]-[], ["*"]-[], ["*"]-[])),
    check("control: put is NOT covered by a get-only parent",
          \+ subset(["put"]-[], ["get"]-[], ["*"]-[], ["*"]-[])),

    % A WIDENING ON THE PATH-SCOPE DIMENSION IS STILL REFUSED — the Kind argument selected
    % the matcher, it did not disable the check.
    check("path-scope: a bare-star child is NOT covered by a narrower parent",
          \+ subset(["get"]-[], ["get"]-[], ["*"]-[], ["system/type/*"]-[])),

    % A PARENT EXCLUDE MUST BE INHERITED BY THE CHILD, on the id arm too.
    check("id-scope: a child that does not inherit the parent's exclude is refused",
          \+ subset(["get"]-[], ["*"]-["put"], ["*"]-[], ["*"]-[])).
