/* entity-core-protocol-rexx — transport (L4): drives the ecnet co-process daemon
 * (ext/ecnet.c) over two FIFOs, plus the §6.11 request_id demux, the §4.8
 * inbound-concurrent-with-outbound dispatch, the §6.13(b) reentry seam, and the
 * initiator dialer/handshake that runs the two-peer loopback.
 *
 * == Concurrency model (profile [async] = single-thread-select). The daemon owns the
 * real sockets + the select() loop + the §1.6 de-framing; the Rexx peer is a single
 * thread that PUMPS events one at a time (Transport_EventLine = a blocking `linein`
 * on the evt FIFO). An inbound EXECUTE is dispatched inline (Peer_Dispatch); a handler
 * that originates an outbound EXECUTE (§6.13(b)) calls Peer_OutboundDispatch ->
 * Transport_Outbound, which re-enters the SAME pump (the natural §6.11 reentry) until
 * the reply correlates by request_id — no thread, no lock. §4.8 store-safety holds by
 * construction (one frame dispatched to completion before the next event is read).
 *
 * State: EC.!IO2CONN.<connid> -> conn handle;  EC.!DONE.<rid>/!PENDING.<rid> -> the
 * §6.11 demux rendezvous;  EC.!SERVE_PEER -> the peer serving this process (one peer
 * per process — the Rexx process model, unlike Tcl's one-interp two-peer loop).
 */

/* ── daemon lifecycle ── */
Transport_Start: procedure expose EC.
  parse arg base
  cmdf = base || '.cmd'
  evtf = base || '.evt'
  address system 'rm -f' cmdf evtf
  address system 'mkfifo' cmdf evtf
  if EC.!DBG \== '' then address system EC.!ECNET_BIN cmdf evtf '>>' || base || '.log 2>&1 &'
  else address system EC.!ECNET_BIN cmdf evtf '>/dev/null 2>&1 &'
  EC.!ECNET_CMD = cmdf
  EC.!ECNET_EVT = evtf
  call stream cmdf, 'c', 'open write'
  call stream evtf, 'c', 'open read'
  return

Transport_Stop: procedure expose EC.
  call Transport_Cmd 'SHUTDOWN'
  call stream EC.!ECNET_CMD, 'c', 'close'
  call stream EC.!ECNET_EVT, 'c', 'close'
  address system 'rm -f' EC.!ECNET_CMD EC.!ECNET_EVT
  return

Transport_Cmd: procedure expose EC.
  parse arg line
  call lineout EC.!ECNET_CMD, line
  call stream EC.!ECNET_CMD, 'c', 'flush'
  return

/* Read ONE event from the evt FIFO. Events are LENGTH-PREFIXED (8 hex digits of the
 * byte length, then the bytes) because Regina's newline-based FIFO reads (linein AND
 * char-at-a-time charin) LOSE data across pipe-read boundaries under load, whereas an
 * exact byte-count charin(,,N) is reliable (A-RX-011). Returns '' on EOF (daemon exit). */
Transport_EventLine: procedure expose EC.
  numeric digits 40
  lh = _read_exact(8)
  if length(lh) < 8 then return ''
  n = x2d(lh)
  return _read_exact(n)

/* the next NETWORK event: drain the deferred-event queue first (events read while a
 * nested crypto call awaited its "R" result — _await_result), else read the FIFO. */
_next_event: procedure expose EC.
  if EC.!EVQH < EC.!EVQT then do
    h = EC.!EVQH
    ev = EC.!EVQ.h
    drop EC.!EVQ.h                        /* reclaim the slot */
    EC.!EVQH = h + 1
    if EC.!EVQH == EC.!EVQT then do        /* drained: reset indices so they stay small */
      EC.!EVQH = 1; EC.!EVQT = 1
    end
    return ev
  end
  return Transport_EventLine()

/* await a daemon crypto "R <hex>" result, deferring any NETWORK events read meanwhile
 * to EC.!EVQ so the main pump processes them after the current dispatch (§9.1 crypto
 * runs INSIDE a dispatch that was itself triggered by a FRAME). */
_await_result: procedure expose EC.
  do forever
    ev = Transport_EventLine()
    if ev == '' then return ''
    if left(ev, 2) == 'R ' then return substr(ev, 3)
    t = EC.!EVQT
    EC.!EVQ.t = ev
    EC.!EVQT = t + 1
  end

/* read EXACTLY n bytes from the evt FIFO, looping over short charin() reads (a large
 * charin(,,n) can return fewer than n bytes across a pipe-read boundary; without the
 * loop that desyncs the length-prefix framing). Returns '' on EOF. */
_read_exact: procedure expose EC.
  parse arg n
  buf = ''
  do while length(buf) < n
    chunk = charin(EC.!ECNET_EVT, , n - length(buf))
    if chunk == '' then return ''
    buf = buf || chunk
  end
  return buf

/* ── listener / dialer ── */
Transport_Listen: procedure expose EC.
  parse arg peer_h, port
  call Transport_Cmd 'LISTEN' port
  do forever
    ev = _next_event()
    if ev == '' then return -1
    parse var ev tag rest
    if tag == 'LISTENING' then return rest
    call Transport_HandleEvent peer_h, ev
  end

/* ── the event pump ── */
Transport_HandleEvent: procedure expose EC.
  parse arg peer_h, ev
  parse var ev tag rest
  select
    when tag == 'ACCEPT' then do
      id = rest
      conn = Conn_New()
      call Conn_Set conn, 'io', id
      EC.!IO2CONN.id = conn
    end
    when tag == 'CLOSED' then do
      id = rest
      EC.!IO2CONN.id = ''
    end
    when tag == 'FRAME' then do
      parse var rest id hex
      call Transport_OnFrame peer_h, id, x2c(hex)
    end
    otherwise nop
  end
  return

Transport_OnFrame: procedure expose EC.
  parse arg peer_h, id, payload
  call Throw_Clear
  env = Wire_EnvelopeOfFrame(payload)
  if env == '' then do
    /* §6.3: "Rejection returns 400 non_canonical_ecf" -- a rejected frame is owed a
     * STATUS, not silence. This used to be a bare `return`, which rejected the frame
     * (correct) and then dropped it on the floor (wrong): the sender saw no response at
     * all and blocked until its own timeout, violating §6.3's second sentence and
     * §4.9(c) deliver-or-signal. It also made a refusal indistinguishable from a dead
     * peer, and on a single-connection oracle run it poisons every later request on the
     * same connection.
     *
     * The frame is still REJECTED -- only enough is salvaged to correlate the response.
     * If even the request_id is unrecoverable the frame is unattributable and silence is
     * the only option left. */
    call Throw_Clear
    rid = Wire_SalvageRequestId(payload)
    call Throw_Clear
    if rid \== '' then do
      rej = Env_Make(Wire_MakeResponse(rid, 400, Wire_ErrorResult('non_canonical_ecf', '')))
      call Transport_SendRaw id, rej
    end
    return
  end
  root = Env_Root(env)
  if Ent_Type(root) == 'system/protocol/execute/response' then do
    rid = Ent_Text(root, 'request_id')
    EC.!PENDING.rid = env
    EC.!DONE.rid = 1
    return
  end
  conn = EC.!IO2CONN.id
  if left(conn, 4) \== 'conn' then do
    conn = Conn_New()
    call Conn_Set conn, 'io', id
    EC.!IO2CONN.id = conn
  end
  resp = Peer_Dispatch(peer_h, conn, env)
  if resp \== '' then call Transport_SendRaw id, resp
  return

Transport_SendRaw: procedure expose EC.
  parse arg io, env
  payload = Wire_FrameOfEnvelope(env)
  call Transport_Cmd 'SEND' io c2x(payload)
  return

/* register a waiter, send, then PUMP the loop until the correlated EXECUTE_RESPONSE
 * arrives (§6.11 reentry). Returns the response envelope, or ''. */
Transport_Outbound: procedure expose EC.
  parse arg io, env
  rid = Ent_Text(Env_Root(env), 'request_id')
  EC.!DONE.rid = 0
  call Transport_SendRaw io, env
  do forever
    if EC.!DONE.rid == 1 then leave
    ev = _next_event()
    if ev == '' then return ''
    call Transport_HandleEvent EC.!SERVE_PEER, ev
  end
  e = EC.!PENDING.rid
  EC.!PENDING.rid = ''
  return e

/* ── responder serve loop ── */
Transport_Serve: procedure expose EC.
  parse arg peer_h
  EC.!SERVE_PEER = peer_h
  do forever
    ev = _next_event()
    if ev == '' then leave
    call Transport_HandleEvent peer_h, ev
  end
  return

/* ═════ session (§4.4) — initiator side ═════ */
Transport_Dial: procedure expose EC.
  parse arg peer_h, port
  EC.!SERVE_PEER = peer_h
  call Transport_Cmd 'DIAL' port
  io = ''
  do forever
    ev = _next_event()
    if ev == '' then return ''
    parse var ev tag rest
    if tag == 'DIALED' then do; io = rest; leave; end
    if tag == 'DIALFAIL' then return ''
    call Transport_HandleEvent peer_h, ev
  end
  conn = Conn_New()
  call Conn_Set conn, 'io', io
  EC.!IO2CONN.io = conn
  EC.!SESS_CTR = EC.!SESS_CTR + 1
  s = 'sess' || EC.!SESS_CTR
  k = 'io';             EC.!SESS.s.k = io
  k = 'conn';           EC.!SESS.s.k = conn
  k = 'ident';          EC.!SESS.s.k = Peer_Identity(peer_h)
  k = 'req_counter';    EC.!SESS.s.k = 0
  k = 'remote_peer_id'; EC.!SESS.s.k = ''
  k = 'capability';     EC.!SESS.s.k = ''
  k = 'granter_peer';   EC.!SESS.s.k = ''
  k = 'cap_signature';  EC.!SESS.s.k = ''
  call _handshake s
  return s

Sess_Get: procedure expose EC.
  parse arg s, key
  return EC.!SESS.s.key
_sess_set: procedure expose EC.
  parse arg s, key, val
  EC.!SESS.s.key = val
  return
_next_rid: procedure expose EC.
  parse arg s
  k = 'req_counter'
  EC.!SESS.s.k = EC.!SESS.s.k + 1
  return 'req-' || EC.!SESS.s.k

/* send a request envelope, pump until its reply correlates, return the response env. */
_sess_send: procedure expose EC.
  parse arg s, env
  return Transport_Outbound(Sess_Get(s, 'io'), env)

/* fire WITHOUT awaiting (multiple in-flight -> the §6.11 out-of-order demux). */
_sess_send_async: procedure expose EC.
  parse arg s, env
  rid = Ent_Text(Env_Root(env), 'request_id')
  EC.!DONE.rid = 0
  call Transport_SendRaw Sess_Get(s, 'io'), env
  return rid

Sess_Await: procedure expose EC.
  parse arg rid
  do forever
    if EC.!DONE.rid == 1 then return
    ev = _next_event()
    if ev == '' then return
    call Transport_HandleEvent EC.!SERVE_PEER, ev
  end

/* the §5.8 authority chain that travels with an authenticated EXECUTE. */
_auth_included: procedure expose EC.
  parse arg s, ident, exec
  exec_sig = Id_Sign(ident, exec)
  inc = Lst_Add('', Sess_Get(s, 'capability'))
  inc = Lst_Add(inc, Sess_Get(s, 'granter_peer'))
  inc = Lst_Add(inc, Id_PeerEntity(ident))
  inc = Lst_Add(inc, Sess_Get(s, 'cap_signature'))
  inc = Lst_Add(inc, exec_sig)
  return inc

/* build + sign + send an authenticated EXECUTE; await the response. */
Sess_Execute: procedure expose EC.
  parse arg s, uri, operation, params, resource
  ident = Sess_Get(s, 'ident')
  cap = Sess_Get(s, 'capability')
  exec = Wire_MakeExecute(_next_rid(s), uri, operation, params, Id_IdHash(ident), Ent_Hash(cap), resource)
  return _sess_send(s, Env_Make(exec, _auth_included(s, ident, exec)))

Sess_ExecuteAsync: procedure expose EC.
  parse arg s, uri, operation, params, resource
  ident = Sess_Get(s, 'ident')
  cap = Sess_Get(s, 'capability')
  exec = Wire_MakeExecute(_next_rid(s), uri, operation, params, Id_IdHash(ident), Ent_Hash(cap), resource)
  return _sess_send_async(s, Env_Make(exec, _auth_included(s, ident, exec)))

Sess_Close: procedure expose EC.
  parse arg s
  call Transport_Cmd 'CLOSE' Sess_Get(s, 'io')
  return

/* drive the §4.1 forward handshake as initiator: hello then authenticate. */
_handshake: procedure expose EC.
  parse arg s
  ident = Sess_Get(s, 'ident')
  hm = Ecf_Map('peer_id', Ecf_Str(Id_PeerId(ident)), 'nonce', Ecf_Bytes(Peer_RandomBytes(32)))
  hm = Ecf_MapPut(hm, 'protocols', Ecf_TextArray(_pl('entity-core/1.0')))
  hm = Ecf_MapPut(hm, 'timestamp', Ecf_Int(Cap_NowMs()))
  hm = Ecf_MapPut(hm, 'hash_formats', Ecf_TextArray(_pl('ecfv1-sha256')))
  hm = Ecf_MapPut(hm, 'key_types', Ecf_TextArray(_pl('ed25519')))
  hello = Ent_Make('system/protocol/connect/hello', hm)
  ex1 = Wire_MakeExecute(_next_rid(s), 'system/protocol/connect', 'hello', hello, '', '', '')
  r1 = _sess_send(s, Env_Make(ex1, ''))
  if Wire_ResponseStatus(r1) \== 200 then call _hs_fail 'hello'
  remote_hello = Wire_ResponseResult(r1)
  call _sess_set s, 'remote_peer_id', Ent_Text(remote_hello, 'peer_id')
  remote_nonce = Ent_Bytes(remote_hello, 'nonce')
  if remote_nonce == '' then call _hs_fail 'hello: missing remote nonce'

  am = Ecf_Map('peer_id', Ecf_Str(Id_PeerId(ident)), 'public_key', Ecf_Bytes(Id_Pub(ident)))
  am = Ecf_MapPut(am, 'key_type', Ecf_Str('ed25519'))
  am = Ecf_MapPut(am, 'nonce', Ecf_Bytes(remote_nonce))
  auth = Ent_Make('system/protocol/connect/authenticate', am)
  auth_sig = Id_Sign(ident, auth)
  auth_inc = Lst_Add(Lst_Add('', Id_PeerEntity(ident)), auth_sig)
  ex2 = Wire_MakeExecute(_next_rid(s), 'system/protocol/connect', 'authenticate', auth, '', '', '')
  r2 = _sess_send(s, Env_Make(ex2, auth_inc))
  if Wire_ResponseStatus(r2) \== 200 then call _hs_fail 'authenticate'

  grant = Wire_ResponseResult(r2)
  token_h = ''
  if grant \== '' then token_h = Ent_Bytes(grant, 'token')
  token = ''
  if token_h \== '' then token = Env_IncludedGet(r2, token_h)
  if token == '' then call _hs_fail 'authenticate grant omits the capability token'
  granter_h = Ent_Bytes(token, 'granter')
  granter_peer = ''
  if granter_h \== '' then granter_peer = Env_IncludedGet(r2, granter_h)
  if granter_peer == '' then call _hs_fail 'authenticate grant omits the granter identity'
  cap_sig = Cap_FindSignature(Ent_Hash(token), Env_Included(r2))
  if cap_sig == '' then call _hs_fail 'authenticate grant omits the capability signature'
  call _sess_set s, 'capability', token
  call _sess_set s, 'granter_peer', granter_peer
  call _sess_set s, 'cap_signature', cap_sig
  return

_hs_fail: procedure expose EC.
  parse arg why
  say 'HANDSHAKE FAILED: ' why
  exit 4
