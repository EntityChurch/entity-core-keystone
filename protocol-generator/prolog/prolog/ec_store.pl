% ec_store.pl — Storage (foundation, §1.7/§3.9) as the PROLOG CLAUSE DATABASE.
%
% THE IDIOM PAYOFF (profile [idiom].store_as_clausedb): the content store and the
% entity tree are not hash-tables bolted on — they are dynamic predicates, and the
% store operations ARE assertz/retract. The two layers:
%
%   content store:  content_fact(StoreId, HashHex, Entity)   hash → entity (immutable)
%   entity tree:    tree_fact(StoreId, Path, HashHex)         path → hash  (mutable index)
%
% A-PL-007 (the Zig/CL store-race lesson): a SINGLE assertz/retract is atomic under
% SWI's logical-update view, but a read-modify-write (bind = read-old ‖ retract ‖
% assert ‖ emit) is NOT — so EVERY RMW runs inside with_mutex/2. The mutex is keyed
% per StoreId so two peers in one process (the loopback) don't serialize each other.
%
% Two peers share one SWI process in the loopback, so every fact is keyed by an
% opaque StoreId (the peer_id) — the clause DB is global; StoreId partitions it.
%
% EMIT (§6.10 / §6.13(c)): tree/content writes notify registered consumers; the
% hook is LIVE with zero consumers (events produced + discarded) so an extension
% can register post-bootstrap without a rebuild. Consumers are themselves clauses.

:- module(ec_store,
          [ store_new/1,             % -StoreId (fresh)
            store_put_entity/2,      % +StoreId, +Entity
            store_get_by_hash/3,     % +StoreId, +Hash33(byte-string), -Entity (semidet)
            store_bind/3,            % +StoreId, +Path, +Entity      (RMW + emit)
            store_unbind/2,          % +StoreId, +Path               (RMW + emit)
            store_hash_at/3,         % +StoreId, +Path, -HashHex (semidet)
            store_get_at/3,          % +StoreId, +Path, -Entity (semidet)
            store_listing/3,         % +StoreId, +Prefix, -Entries (sorted)
            register_tree_consumer/2,    % +StoreId, +Goal/1
            register_content_consumer/2  % +StoreId, +Goal/1
          ]).

:- use_module(ec_entity).
:- use_module(library(lists)).

% consumer goals are called as call(Goal, Event) from notify_*; declare them meta so
% SWI module-qualifies the goal at the registration call site (so a consumer defined
% in another module resolves correctly when fired from this module's notify_*).
:- meta_predicate register_tree_consumer(+, 1), register_content_consumer(+, 1).

:- dynamic content_fact/3.       % StoreId, HashHex, Entity
:- dynamic tree_fact/3.          % StoreId, Path, HashHex
:- dynamic tree_consumer/2.      % StoreId, Goal
:- dynamic content_consumer/2.   % StoreId, Goal
:- dynamic store_counter/1.

store_new(StoreId) :-
    ( retract(store_counter(N)) -> true ; N = 0 ),
    N1 is N + 1,
    assertz(store_counter(N1)),
    format(atom(StoreId), 'store~d', [N1]).

store_mutex(StoreId, Mutex) :- atom_concat('ec_store_', StoreId, Mutex).

% ── content store ─────────────────────────────────────────────────────────────
% A content-store event fires only when the entity is NEW to the store (re-put of
% an existing hash fires nothing). The put+test is the RMW critical section.
store_put_entity(StoreId, E) :-
    entity_hash(E, H), bytes_hash(H, HexA), atom_string(HexA, HashHex),
    store_mutex(StoreId, Mtx),
    with_mutex(Mtx,
        ( content_fact(StoreId, HashHex, _)
        -> true
        ;  assertz(content_fact(StoreId, HashHex, E)),
           notify_content(StoreId, E) )).

store_get_by_hash(StoreId, H, E) :-
    bytes_hash(H, HexA), atom_string(HexA, HashHex),
    content_fact(StoreId, HashHex, E), !.

% ── entity tree (location index) ────────────────────────────────────────────
% Bind is a read-modify-write: read previous, store content, swap the binding,
% emit on change. The whole sequence is one with_mutex critical section (A-PL-007).
store_bind(StoreId, Path, E) :-
    entity_hash(E, H), bytes_hash(H, HexA), atom_string(HexA, NewHex),
    store_mutex(StoreId, Mtx),
    with_mutex(Mtx,
        ( ( content_fact(StoreId, NewHex, _) -> true
          ; assertz(content_fact(StoreId, NewHex, E)), notify_content(StoreId, E) ),
          ( tree_fact(StoreId, Path, PrevHex) -> true ; PrevHex = (-) ),
          ( PrevHex == NewHex
          -> true
          ;  ( PrevHex == (-) -> true ; retract(tree_fact(StoreId, Path, PrevHex)) ),
             assertz(tree_fact(StoreId, Path, NewHex)),
             event_type(PrevHex, NewHex, ET),
             notify_tree(StoreId, ET, Path, NewHex, PrevHex) ) )).

store_unbind(StoreId, Path) :-
    store_mutex(StoreId, Mtx),
    with_mutex(Mtx,
        ( tree_fact(StoreId, Path, PrevHex)
        -> retract(tree_fact(StoreId, Path, PrevHex)),
           notify_tree(StoreId, "deleted", Path, (-), PrevHex)
        ;  true )).

store_hash_at(StoreId, Path, HashHex) :- tree_fact(StoreId, Path, HashHex), !.

store_get_at(StoreId, Path, E) :-
    tree_fact(StoreId, Path, HashHex), !,
    content_fact(StoreId, HashHex, E).

event_type((-), _, "created") :- !.
event_type(_, (-), "deleted") :- !.
event_type(_, _, "modified").

% ── one-level listing (§3.9) ──────────────────────────────────────────────────
% Returns a sorted list of entry(Segment, HashHex-or-(-), HasChildren) under
% PREFIX (a path ending in "/"). This is a pure query over the tree clauses — a
% findall + aggregation, the relational read.
store_listing(StoreId, Prefix0, Entries) :-
    ( sub_atom_or_string_suffix(Prefix0, "/") -> Prefix = Prefix0
    ; string_concat(Prefix0, "/", Prefix) ),
    string_length(Prefix, PLen),
    findall(Seg-Deeper-Hash,
            ( tree_fact(StoreId, Path, HashHex),
              string_length(Path, Len), Len > PLen,
              sub_string(Path, 0, PLen, _, Prefix),
              AfterLen is Len - PLen,
              sub_string(Path, PLen, AfterLen, 0, Rest),
              ( sub_string(Rest, SlashAt, _, _, "/")
              -> sub_string(Rest, 0, SlashAt, _, Seg), Deeper = true, Hash = (-)
              ;  Seg = Rest, Deeper = false, Hash = HashHex ) ),
            Raw),
    aggregate_entries(Raw, Entries).

sub_atom_or_string_suffix(S, Suf) :-
    string_length(Suf, SL), string_length(S, L), L >= SL,
    Start is L - SL, sub_string(S, Start, SL, 0, Suf).

% collapse duplicate segments (a seg may appear as both a leaf and a parent):
% a leaf hash + any deeper sighting → HasChildren true if any deeper.
aggregate_entries(Raw, Sorted) :-
    setof(Seg, D^H^member(Seg-D-H, Raw), Segs), !,
    maplist(fold_seg(Raw), Segs, Entries),
    sort(0, @=<, Entries, Sorted).
aggregate_entries(_, []).

fold_seg(Raw, Seg, entry(Seg, Hash, HasChildren)) :-
    ( member(Seg-true-_, Raw) -> HasChildren = true ; HasChildren = false ),
    ( member(Seg-false-H, Raw) -> Hash = H ; Hash = (-) ).

% ── emit bus (§6.10 / §6.13(c)) ────────────────────────────────────────────────
register_tree_consumer(StoreId, Goal) :- assertz(tree_consumer(StoreId, Goal)).
register_content_consumer(StoreId, Goal) :- assertz(content_consumer(StoreId, Goal)).

notify_tree(StoreId, ET, Path, NewHex, PrevHex) :-
    forall(tree_consumer(StoreId, Goal),
           ignore(call(Goal, event(tree, ET, Path, NewHex, PrevHex)))).

notify_content(StoreId, E) :-
    forall(content_consumer(StoreId, Goal),
           ignore(call(Goal, event(content, "created", E)))).
