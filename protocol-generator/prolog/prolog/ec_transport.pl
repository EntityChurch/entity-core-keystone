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
            new_request_id/2             % +ClientConn, -ReqId
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

new_conn_id(Id) :-
    ( retract(conn_counter(N)) -> true ; N = 0 ), N1 is N+1,
    assertz(conn_counter(N1)), format(atom(Id), 'conn~d', [N1]).

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
io_destroy(io(_, _, _, PMtx, WMtx)) :-
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
    ( catch(read_frame(Stream, Payload), _, fail)
    -> ( catch(envelope_of_bytes(Payload, Env), _, fail)
       -> ( is_response(Env)
          -> route_response(IO, Env)
          ;  thread_create(ignore(call(OnExecute, IO, Env)), _, [detached(true)]) )
       ;  true ),
       read_loop_(IO, OnExecute, Stream)
    ;  true ).   % stream closed / framing ended

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
