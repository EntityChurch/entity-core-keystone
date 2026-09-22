% ec_transport.pl — Transport (L4): TCP listener + per-connection serve thread
% (library(socket) + native threads), the §6.11 request_id demux (N6/N7), and the
% client dialer/handshake that drives the two-peer loopback.
%
% CONCURRENCY MODEL (A-PL-015): one native SWI thread per connection. The accept
% loop spawns a reader thread per accepted socket; the reader demuxes inbound
% frames (§6.11): an EXECUTE_RESPONSE is routed to its awaiting outbound caller by
% request_id (via a per-connection message_queue keyed table); an inbound EXECUTE
% is dispatched on its OWN thread (§4.8 / N6) so a handler that originates an
% outbound EXECUTE and awaits its reply does NOT block the reader.
%
% request_id → message_queue correlation: each outbound caller creates a fresh
% message_queue, registers it under its request_id (guarded by a mutex — the RMW
% lesson again), sends, then thread_get_message/2 blocks on the queue; the reader
% thread_send_message's the response in. This is the idiomatic SWI analogue of the
% CL condvar+hashtable / OCaml Condition+Hashtbl (A-PL-006/N7).
%
% Binary streams: set_stream(type(binary)) on both ends; tcp_setopt(nodelay) per
% §1.6. read/write go through ec_wire (length-framed).

:- module(ec_transport,
          [ start_listener/3,            % +ServeGoal/2(:Conn,+Env), +Port, -ListenSock-BoundPort
            stop_listener/1,            % +ListenSock
            dial/3,                      % +Host, +Port, -ClientConn
            client_send/3,               % +ClientConn, +RequestEnv, -ResponseEnv
            client_close/1,              % +ClientConn
            conn_outbound/3,             % +Conn, +RequestEnv, -ResponseEnv  (server-side §6.13b seam)
            new_request_id/2,            % +ClientConn, -ReqId
            register_conn_close_hook/1   % +Goal/1(+ConnId) — called at teardown
          ]).

:- use_module(ec_wire).
:- use_module(ec_entity).
:- use_module(library(socket)).
:- use_module(library(lists)).

% start_listener's ServeGoal is a closure called as call(Goal, Env, Outbound, Resp)
% — declare it meta so SWI module-qualifies it at the CALL SITE (the caller's
% module), so it resolves correctly when invoked from a transport serve thread
% (which otherwise would look the goal up in ec_transport and not find it).
:- meta_predicate start_listener(3, +, -).

:- dynamic conn_state/2.       % ConnId, state(Stream, MutexName, WriteMutex)
:- dynamic pending/3.          % ConnId, RequestId, QueueId
:- dynamic conn_counter/1.
:- dynamic req_counter/2.      % CKey, N  (thread-SHARED via the clause DB — global
                               % vars are thread-local in SWI, so the 8-way demux
                               % needs the shared clause DB, not nb_setval)

% ATOMIC. accept_loop spawns one thread per connection and each calls make_io, so
% a retract/assert pair here is a read-modify-write RACE: two threads can retract
% the same N and both mint `conn<N+1>`. That was harmless while ConnId was only a
% label; it stopped being harmless the moment the peer keyed its per-connection
% HANDSHAKE STATE on it (ec_peer conn_key/2) — two connections sharing an id share
% whether a nonce was issued and whether the connection is established. `flag/3` is
% SWI's atomic get-and-set and needs no mutex of its own.
new_conn_id(Id) :-
    flag(ec_conn_counter, N, N + 1), N1 is N + 1,
    format(atom(Id), 'conn~d', [N1]).

% ── connection-teardown hooks ─────────────────────────────────────────────────
% Per-connection state that lives ABOVE the transport (the peer's handshake state)
% has to be released when the connection goes, or it accumulates one record per
% connection for the life of the process — which a 256-connection flood or a
% 100-cycle churn makes measurable. The transport must not know what that state IS,
% so it publishes the event and the owner registers for it.
:- dynamic conn_close_hook/1.
register_conn_close_hook(Goal) :-
    ( conn_close_hook(Goal) -> true ; assertz(conn_close_hook(Goal)) ).

% ── per-connection I/O object ─────────────────────────────────────────────────
%   io(ConnId, In, Out, PendingMutex, WriteMutex)
% A-PL-017 (S4 resource lesson): use ANONYMOUS mutexes (mutex_create/1 with an
% unbound arg), NOT named-alias mutexes. A named global mutex (`conn7_pend`)
% persists for the process lifetime; under the oracle's connection-churn probe
% (t2_2) the host exhausts the named-mutex table and mutex_create starts to throw
% "No permission to create mutex". Anonymous mutexes are reclaimable; we also
% destroy them explicitly at connection teardown (io_destroy/1).
make_io(In, Out, io(ConnId, In, Out, PMtx, WMtx)) :-
    new_conn_id(ConnId),
    mutex_create(PMtx), mutex_create(WMtx).

% release a connection's anonymous mutexes (called at serve/dialer teardown).
io_destroy(io(ConnId, _, _, PMtx, WMtx)) :-
    forall(conn_close_hook(G), ignore(catch(call(G, ConnId), _, true))),
    catch(mutex_destroy(PMtx), _, true),
    catch(mutex_destroy(WMtx), _, true).

io_write(io(_, _, Out, _, WMtx), Env) :-
    envelope_to_bytes(Env, Bytes),
    with_mutex(WMtx, write_frame(Out, Bytes)).

% Route an EXECUTE_RESPONSE to its awaiting caller by request_id (§6.11 demux).
route_response(io(ConnId, _, _, PMtx, _), Env) :-
    envelope_root(Env, Root),
    ( ent_text(Root, "request_id", ReqId) -> true ; ReqId = "" ),
    with_mutex(PMtx, ( pending(ConnId, ReqId, Q) -> true ; Q = (-) )),
    ( Q == (-) -> true ; thread_send_message(Q, Env) ).

% §6.13(b)/outbound: send a request, await its correlated response on a fresh queue.
io_outbound(IO, Request, Response) :-
    IO = io(ConnId, _, _, PMtx, _),
    envelope_root(Request, Root),
    ( ent_text(Root, "request_id", ReqId) -> true ; ReqId = "" ),
    message_queue_create(Q),
    with_mutex(PMtx, assertz(pending(ConnId, ReqId, Q))),
    io_write(IO, Request),
    ( catch(thread_get_message(Q, Resp, [timeout(10)]), _, fail) -> Response = Resp ; Response = (-) ),
    with_mutex(PMtx, retractall(pending(ConnId, ReqId, _))),
    message_queue_destroy(Q).

% ── reader loop (§6.11 demux) ──────────────────────────────────────────────────
% EXECUTE_RESPONSE → route; EXECUTE → dispatch on its OWN thread (N6). OnExecute is
% called with the IO + decoded envelope; it must write the response itself.
read_loop(IO, OnExecute) :-
    IO = io(_, In, _, _, _),
    catch(read_loop_(IO, OnExecute, In), _, true).
read_loop_(IO, OnExecute, Stream) :-
    ( catch(read_frame_result(Stream, R), _, R = closed)
    -> true
    ;  R = closed ),
    read_loop_step(R, IO, OnExecute, Stream).

% A clean EOF AT A FRAME BOUNDARY is an ordinary hangup and is owed NOTHING. Answering it
% is as wrong as dropping a refusal, in the other direction.
read_loop_step(closed, _, _, _) :- !.
% §4.11 (0.8.2.25): A FRAMING FAILURE IS A REFUSAL OWED A CODED FRAME, and both arms that
% reach here -- the oversize prefix and the truncation -- used to be a bare loop exit,
% i.e. "closing with no coded frame", which is indistinguishable from a network fault
% and, on a multiplexed connection, destroys unrelated ADMITTED requests.
%
% The stream is desynchronized on both arms -- an oversize body was never drained, a
% truncated one never arrived -- so the frame goes out and THEN the loop ends. §4.11 makes
% the frame mandatory and leaves the close to us; closing is the only sound choice once
% the framing is lost, and it is a CHOICE rather than an alternative to answering.
%
% §4.11's best-effort UNCORRELATED form: no request_id can be recovered from a frame whose
% body never arrived, and guessing one would correlate the refusal to somebody else's
% in-flight request.
read_loop_step(refuse(Status, Code, Message), IO, _, _) :- !,
    refuse_pre_admission(IO, "", Status, Code, Message).
% A BINDING MADE IN A catch/3 RECOVERY GOAL THAT THEN FAILS IS UNDONE, so the thrown
% term cannot be carried out of a `catch(G, E, fail)` -- the obvious spelling loses
% exactly the value the classifier needs and leaves E unbound in the else branch, which
% would silently collapse every cause onto the catch-all. Recover with `true` and
% discriminate on var/1 instead; a decode that FAILS without throwing takes the same
% catch-all arm, named here rather than left to the unbound variable.
read_loop_step(frame(Payload), IO, OnExecute, Stream) :-
    (   catch(envelope_of_bytes(Payload, Env), Err, true)
    ->  (   var(Err)
        ->  (   is_response(Env)
            ->  route_response(IO, Env)
            ;   thread_create(ignore(call(OnExecute, IO, Env)), _, [detached(true)]) )
        ;   reject_frame(IO, Payload, Err) )
    ;   reject_frame(IO, Payload, decode_failed) ),
    read_loop_(IO, OnExecute, Stream).

% THE CODE BELONGS TO THE CAUSE (§4.11, §5.2a; 0.8.2.24 N4/N5).
%
% "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" -- a
% single code for the class would answer an honest caller under the wrong reason and send
% them to the wrong layer.
%
%   resolution integrity (mis-keyed included, carried-hash mismatch)  400 hash_mismatch
%   CBOR tag-policy violation                                         400 non_canonical_ecf
%   anything else that never becomes an Envelope                      400 invalid_request
%
% THE TAG ARM KEEPS non_canonical_ecf AND THAT IS DELIBERATE. §4.11 rules that code
% non-conformant "on the framing arm" and gives its reason in the same sentence:
% ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations specifically, which that
% document still MUSTs at decode time (§6.3). The two rows are disjoint by CAUSE rather
% than in conflict. Everything else this decoder calls non-canonical -- a non-minimal
% head, a bad simple value, a duplicate key -- is genuinely "non-canonical CBOR that never
% becomes an Envelope".
%
% This peer answered non_canonical_ecf for EVERY decode-boundary refusal until
% 0.8.2.24/.25 pinned them apart (measured on the wire, arc-probe B1/B2). A mis-keyed
% `included` entry carries no tag at all: its encoding is canonical, what is false is the
% claim the KEY makes, and the remedy non_canonical_ecf selects -- *re-encode* -- sends an
% honest caller to the wrong layer.
%
% The messages are a FIXED TABLE, never the thrown term: a wire-visible string stays ASCII
% and nothing here echoes attacker-supplied bytes back.
%
% Clause order is NOT load-bearing here -- the heads are distinct ground terms and the
% catch-all is last -- but the ORDER OF THE FIRST TWO IS the reason this is three clauses
% rather than a chain of ->: a defect that collapsed them would have to delete a head,
% which is visible, rather than reorder a guard, which is not.
pre_admission_refusal(error(ec_entity(included_key_mismatch), _), 400, "hash_mismatch",
                      "an entity was addressed by a hash that does not bind to it") :- !.
pre_admission_refusal(error(ec_entity(content_hash_mismatch), _), 400, "hash_mismatch",
                      "an entity was addressed by a hash that does not bind to it") :- !.
pre_admission_refusal(error(ec_cbor(tag_rejected_major6), _), 400, "non_canonical_ecf",
                      "CBOR tags are forbidden anywhere in an entity data field") :- !.
pre_admission_refusal(_, 400, "invalid_request", "frame did not decode into an envelope").

% Put the coded EXECUTE_RESPONSE §4.11 requires on the wire for a frame refused BEFORE it
% becomes an admitted request.
%
% "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the wire
% [MUST] -- correlated by `request_id` where the id is available, and otherwise as a
% best-effort coded frame carrying no correlation."
%
% §4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS" and
% therefore reaches none of these, which is why §4.11 exists. AN EMPTY ReqId IS THE
% BEST-EFFORT FORM, not a bug: it is what the section prescribes where no id can be
% recovered. Best-effort on the WRITE only -- a dead socket is not a protocol decision.
refuse_pre_admission(IO, ReqId, Status, Code, Message) :-
    ignore(( error_result(Code, Message, ErrE),
             make_response(ReqId, Status, ErrE, Resp),
             catch(io_write(IO, envelope(Resp, [])), _, true) )).

% A COMPLETE frame the decoder refused. The framing is intact, so we answer and KEEP
% SERVING -- and the refusal MUST be a status rather than silence (§4.11; §4.9(c) says the
% same from the other direction). The `true` this replaced rejected the frame (correct)
% and then dropped it on the floor (wrong): the sender saw no response at all and blocked
% until its own timeout, so a refusal was indistinguishable from a dead peer.
%
% The frame is still REJECTED -- only enough is salvaged to correlate the response, and an
% UNRECOVERABLE id now takes §4.11's uncorrelated best-effort form rather than the silence
% it used to take. That silence was the OTHER non-conformant behaviour §4.11 scores, "the
% weaker of the two precisely because nothing surfaces it".
reject_frame(IO, Payload, Err) :-
    ( salvage_request_id(Payload, ReqId0) -> ReqId = ReqId0 ; ReqId = "" ),
    pre_admission_refusal(Err, Status, Code, Message),
    refuse_pre_admission(IO, ReqId, Status, Code, Message).

is_response(Env) :- envelope_root(Env, R), entity_type(R, "system/protocol/execute/response").

% ── server side ─────────────────────────────────────────────────────────────────

start_listener(ServeGoal, Port, Sock-BoundPort) :-
    tcp_socket(Sock),
    tcp_setopt(Sock, reuseaddr),
    ( Port =:= 0 -> Bind = '127.0.0.1':BoundPort ; Bind = '127.0.0.1':Port, BoundPort = Port ),
    tcp_bind(Sock, Bind),     % with an unbound port var, returns the assigned port
    tcp_listen(Sock, 64),
    thread_create(accept_loop(Sock, ServeGoal), _, [detached(true)]).

accept_loop(Sock, ServeGoal) :-
    catch(
      ( tcp_accept(Sock, Client, _Peer),
        thread_create(serve_connection(Client, ServeGoal), _, [detached(true)]),
        accept_loop(Sock, ServeGoal) ),
      _, true).

serve_connection(Client, ServeGoal) :-
    tcp_open_socket(Client, In, Out),
    set_stream(In, type(binary)),
    set_stream(Out, type(binary)),
    make_io(In, Out, IO),
    OnExecute = serve_on_execute(ServeGoal),
    catch(read_loop(IO, OnExecute), _, true),
    catch(close(In), _, true), catch(close(Out), _, true),
    io_destroy(IO).   % A-PL-017: reclaim the connection's anonymous mutexes

% serve_on_execute(+ServeGoal, +IO, +Env): run the dispatch ServeGoal, write resp.
% Per-request isolation: a dispatch or write failure on one adversarial request
% must NOT tear down the connection (§3.3 every EXECUTE receives a response). The
% write is inside the catch so an encode/IO error becomes a dropped response, not a
% dead serve thread.
serve_on_execute(ServeGoal, IO, Env) :-
    % MODULE-QUALIFY the seam term: the dispatcher (ec_peer) invokes it via
    % call(Outbound, Req, Resp); an unqualified outbound_via(IO) would be looked
    % up in the CALLER's module (ec_peer) and fail existence_error. Qualifying it
    % here pins resolution to ec_transport. (A-PL-018, the §6.11 reentry seam.)
    Outbound = ec_transport:outbound_via(IO),
    catch(
        ( call(ServeGoal, Env, Outbound, Resp),
          ( Resp == (-) -> true ; io_write(IO, Resp) ) ),
        _E, true).

% the server-side §6.13(b) reentry seam handed to the dispatcher.
outbound_via(IO, Request, Response) :- io_outbound(IO, Request, Response).
conn_outbound(IO, Request, Response) :- io_outbound(IO, Request, Response).

stop_listener(Sock) :- catch(tcp_close_socket(Sock), _, true).

% ── client side: dialer + initiator handshake ────────────────────────────────────

% ClientConn = client(IO, CounterKey, CounterMutex). CMtx is an ANONYMOUS mutex
% (A-PL-017) reclaimed in client_close — not a per-dial named-global leak.
dial(Host, Port, client(IO, CKey, CMtx)) :-
    ( atom(Host) -> HostA = Host ; atom_string(HostA, Host) ),
    tcp_socket(Sock),
    tcp_connect(Sock, HostA:Port),
    tcp_open_socket(Sock, In, Out),
    set_stream(In, type(binary)), set_stream(Out, type(binary)),
    make_io(In, Out, IO),
    IO = io(ConnId, _, _, _, _),
    atom_concat(ConnId, '_cnt', CKey),
    assertz(req_counter(CKey, 0)),
    mutex_create(CMtx),
    % client reader: only EXECUTE_RESPONSEs arrive from a core responder — route all.
    thread_create(read_loop(IO, client_ignore_execute), _, [detached(true)]).

client_ignore_execute(_IO, _Env).

new_request_id(client(_IO, CKey, CMtx), ReqId) :-
    with_mutex(CMtx, ( retract(req_counter(CKey, N)), N1 is N+1, assertz(req_counter(CKey, N1)) )),
    format(string(ReqId), "req-~d", [N1]).

client_send(client(IO, _, _), Request, Response) :- io_outbound(IO, Request, Response).

client_close(client(IO, _, CMtx)) :-
    IO = io(_, In, Out, _, _),
    % force-close: the reader thread may be blocked in read_frame on In; a plain
    % close/1 deadlocks waiting for it, so force the close to unblock the reader.
    catch(close(Out, [force(true)]), _, true),
    catch(close(In, [force(true)]), _, true),
    catch(mutex_destroy(CMtx), _, true),
    io_destroy(IO).
