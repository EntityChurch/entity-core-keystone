% ec_client.pl — initiator-side driver: the §4.1 forward handshake (hello →
% authenticate) and authenticated EXECUTE construction (§5.8 full authority chain
% in `included`). Used by the two-peer loopback to drive a responder peer.

:- module(ec_client,
          [ client_handshake/3,      % +ClientConn, +Identity, -Session
            client_execute_as/7,     % +CC,+Identity,+Session,+Uri,+Op,+Params,-RespEnv
            client_execute_as/8,     % +CC,+Identity,+Session,+Uri,+Op,+Params,+Resource,-RespEnv
            response_status/2,       % +RespEnv, -Status
            response_result/2,       % +RespEnv, -ResultEntity (semidet)
            session_remote_peer/2,   % +Session, -RemotePeerId
            session_capability/2     % +Session, -CapToken (semidet)
          ]).

:- use_module(ec_codec).
:- use_module(ec_entity).
:- use_module(ec_identity).
:- use_module(ec_wire).
:- use_module(ec_transport).
:- use_module(library(lists)).

% Session = session(RemotePeerId, CapToken, GranterPeer, CapSig)

client_handshake(CC, Identity, session(RemotePeerId, CapToken, GranterPeer, CapSig)) :-
    identity_peer_id(Identity, MyPeerId),
    identity_public_key(Identity, MyPub),
    % ── hello ──
    new_request_id(CC, R1),
    random_bytes(32, Nonce), string_codes(Nonce, NC),
    make_entity("system/protocol/connect/hello",
                map(["peer_id"-MyPeerId, "nonce"-bytes(NC),
                     "protocols"-["entity-core/1.0"], "timestamp"-int(0),
                     "hash_formats"-["ecfv1-sha256"], "key_types"-["ed25519"]]),
                Hello),
    make_execute(R1, "system/protocol/connect", "hello", Hello, Exec1),
    envelope(Exec1, [], Env1),
    once(client_send(CC, Env1, Resp1)),     % det: never backtrack into a re-send
    require_ok(Resp1, "hello"),
    response_result(Resp1, RemoteHello),
    ent_text(RemoteHello, "peer_id", RemotePeerId),
    ent_bytes(RemoteHello, "nonce", RemoteNonce), string_codes(RemoteNonce, RNC),
    % ── authenticate ──
    new_request_id(CC, R2),
    string_codes(MyPub, PubC),
    make_entity("system/protocol/connect/authenticate",
                map(["peer_id"-MyPeerId, "public_key"-bytes(PubC),
                     "key_type"-"ed25519", "nonce"-bytes(RNC)]),
                Auth),
    sign_entity(Identity, Auth, AuthSig),
    make_execute(R2, "system/protocol/connect", "authenticate", Auth, Exec2),
    identity_peer_entity(Identity, MyPeerEntity),
    included_pairs([MyPeerEntity, AuthSig], Inc2),
    envelope(Exec2, Inc2, Env2),
    once(client_send(CC, Env2, Resp2)),
    require_ok(Resp2, "authenticate"),
    % parse the §4.4 initial capability grant out of the response.
    response_result(Resp2, Grant),
    ent_bytes(Grant, "token", TokenH),
    included_get(Resp2, TokenH, CapToken),
    ent_bytes(CapToken, "granter", GranterH),
    included_get(Resp2, GranterH, GranterPeer),
    entity_hash(CapToken, CapHash),
    find_signature_in(Resp2, CapHash, CapSig).

session_remote_peer(session(R,_,_,_), R).
session_capability(session(_,C,_,_), C).

% ── authenticated EXECUTE (§5.8) — the full authority chain travels in `included` ──
client_execute_as(CC, Identity, Session, Uri, Op, Params, Resp) :-
    client_execute_as(CC, Identity, Session, Uri, Op, Params, (-), Resp).

client_execute_as(CC, Identity, session(_, CapToken, GranterPeer, CapSig), Uri, Op, Params, Resource, Resp) :-
    new_request_id(CC, ReqId),
    identity_hash(Identity, AuthorH),
    entity_hash(CapToken, CapH),
    ( Resource == (-) -> Opts = [author=AuthorH, capability=CapH]
    ; Opts = [author=AuthorH, capability=CapH, resource=Resource] ),
    make_execute(ReqId, Uri, Op, Params, Opts, Exec),
    sign_entity(Identity, Exec, ExecSig),
    identity_peer_entity(Identity, MyPeerEntity),
    included_pairs([CapToken, GranterPeer, MyPeerEntity, CapSig, ExecSig], Inc),
    envelope(Exec, Inc, Env),
    once(client_send(CC, Env, Resp)).

response_status(Resp, Status) :-
    envelope_root(Resp, Root), ( ent_uint(Root, "status", Status) -> true ; Status = 0 ).

response_result(Resp, Result) :-
    envelope_root(Resp, Root),
    ent_field(Root, "result", map(P)),
    entity_of_cbor(map(P), Result).

require_ok(Resp, Step) :-
    response_status(Resp, Status),
    ( Status =:= 200 -> true
    ; ( response_result(Resp, R), ent_text(R, "code", Code) -> true ; Code = "?" ),
      throw(error(ec_client(step_failed(Step, Status, Code)), _)) ).

find_signature_in(Env, Target, Sig) :-
    envelope_included(Env, Inc), member(_-Sig, Inc),
    entity_type(Sig, "system/signature"),
    ent_bytes(Sig, "target", T), T == Target, !.

included_pairs(Entities, Pairs) :- findall(H-E, ( member(E, Entities), entity_hash(E, H) ), Pairs).

random_bytes(N, Bytes) :-
    length(Codes, N), maplist([C]>>(C is random(256)), Codes), string_codes(Bytes, Codes).
