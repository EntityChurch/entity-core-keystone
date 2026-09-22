/* entity-core-protocol-rexx — peer assembly: bootstrap (§6.9 / §6.9a), the MUST
 * system handlers (§6.2: connect, tree, handler, capability, type), the §6.5 dispatch
 * chain, §6.6 resolution, and the §6.9a peer-authority seed policy.
 *
 * The pure protocol brain — dispatch is a function from an inbound envelope to an
 * outbound response envelope; transport lives in transport.rex. Each handler is a
 * routine returning an OUTCOME (status + result entity + included list) — the
 * recoverable seam; the EC.!EXC flag (util.rex Throw) is the unrecoverable-throw
 * analogue mapped once at the dispatch top (A-RX-010: no cross-CALL SYNTAX).
 *
 * A peer is a HANDLE ("peer<n>") into the EC. stem; the store + identity are their own
 * handles under it. Handler routine tokens (connect/tree/...) map to labels in
 * Peer_CallHandler (a fixed dispatch table — no `interpret`, so a §6.11 reentry that
 * re-enters dispatch cannot clobber a shared ctx global; ctx passes by value).
 *
 * OUTCOME packing:  len(status,2) || len(result,4)||resultEntity || includedList
 * CTX packing:      len(conn,2)||conn || len(callerCap,4)||callerCap || env
 */

/* ── outcome helpers ── */
Out_Make: procedure
  parse arg status, result, included
  return d2c(status, 2) || d2c(length(result), 4) || result || included
Out_Ok: procedure expose EC.
  parse arg result, included
  return Out_Make(200, result, included)
Out_Err: procedure expose EC.
  parse arg status, code, message
  return Out_Make(status, Wire_ErrorResult(code, message), '')
Out_Status: procedure
  parse arg o
  numeric digits 20
  return c2d(substr(o, 1, 2))
Out_Result: procedure
  parse arg o
  numeric digits 40
  rl = c2d(substr(o, 3, 4))
  return substr(o, 7, rl)
Out_Included: procedure
  parse arg o
  numeric digits 40
  rl = c2d(substr(o, 3, 4))
  return substr(o, 7 + rl)

/* ── ctx helpers ──
 * The ctx is a length-prefixed packing (classic Rexx has no record type):
 *   conn(2) | caller_cap(4) | handler_pattern(2) | env(rest)
 *
 * handler_pattern is CARRIED, never recomputed: §6.3's path check needs the handler
 * pattern and the caller's capability, and the dispatch-level check has already computed
 * both. Recomputing invites the two to drift, and §6.8 is explicit that the authority is
 * selected by who named the path. It is the OWNING handler's pattern (§6.3, 0.8.2.23) --
 * for the tree handler owner and runner coincide, so the distinction is not observable
 * here, but the field is named for the owner. It is '' on the unauthenticated connect
 * path, which has no resolved handler entity. */
Ctx_Make: procedure
  parse arg conn, caller_cap, env, handler_pattern
  return d2c(length(conn), 2) || conn || d2c(length(caller_cap), 4) || caller_cap || ,
         d2c(length(handler_pattern), 2) || handler_pattern || env
Ctx_Conn: procedure
  parse arg ctx
  numeric digits 20
  cl = c2d(substr(ctx, 1, 2))
  return substr(ctx, 3, cl)
Ctx_CallerCap: procedure
  parse arg ctx
  numeric digits 40
  cl = c2d(substr(ctx, 1, 2))
  p = 3 + cl
  kl = c2d(substr(ctx, p, 4))
  return substr(ctx, p + 4, kl)
Ctx_HandlerPattern: procedure
  parse arg ctx
  numeric digits 40
  cl = c2d(substr(ctx, 1, 2))
  p = 3 + cl
  kl = c2d(substr(ctx, p, 4))
  q = p + 4 + kl
  hl = c2d(substr(ctx, q, 2))
  return substr(ctx, q + 2, hl)
Ctx_Env: procedure
  parse arg ctx
  numeric digits 40
  cl = c2d(substr(ctx, 1, 2))
  p = 3 + cl
  kl = c2d(substr(ctx, p, 4))
  q = p + 4 + kl
  hl = c2d(substr(ctx, q, 2))
  return substr(ctx, q + 2 + hl)
Ctx_Exec: procedure expose EC.
  parse arg ctx
  return Env_Root(Ctx_Env(ctx))
Ctx_Included: procedure expose EC.
  parse arg ctx
  return Env_Included(Ctx_Env(ctx))

/* ── construction + bootstrap ── */
Peer_Create: procedure expose EC.
  parse arg seed, open_grants, conformance
  if open_grants == '' then open_grants = 0
  if conformance == '' then conformance = 0
  EC.!PEER_CTR = EC.!PEER_CTR + 1
  h = 'peer' || EC.!PEER_CTR
  ident = Id_OfSeed(seed)
  k = 'identity';    EC.!PEER.h.k = ident
  k = 'store';       EC.!PEER.h.k = Store_New()
  k = 'local_peer';  EC.!PEER.h.k = Id_PeerId(ident)
  k = 'open_grants'; EC.!PEER.h.k = open_grants
  k = 'conformance'; EC.!PEER.h.k = conformance
  call _bootstrap h
  return h

Peer_Identity: procedure expose EC.
  parse arg h
  k = 'identity'; return EC.!PEER.h.k
Peer_Store: procedure expose EC.
  parse arg h
  k = 'store'; return EC.!PEER.h.k
Peer_LocalPeer: procedure expose EC.
  parse arg h
  k = 'local_peer'; return EC.!PEER.h.k
Peer_Abs: procedure expose EC.
  parse arg h, rel
  return '/' || Peer_LocalPeer(h) || '/' || rel

/* §4.6 nonce randomness (>=32-byte CSPRNG) via the helper's /dev/urandom. */
Peer_RandomBytes: procedure expose EC.
  parse arg n
  return Crypto_Random(n)

/* is a handler routine registered for the (stripped) pattern? (an unset compound
 * defaults to its uppercased name, never '', so a dedicated presence marker is used). */
Peer_HasHandler: procedure expose EC.
  parse arg h, pattern
  return (EC.!PEER_HAS.h.pattern == 1)
Peer_HandlerRoutine: procedure expose EC.
  parse arg h, pattern
  return EC.!PEER_HANDLER.h.pattern

/* fixed handler dispatch table (token -> label). */
Peer_CallHandler: procedure expose EC.
  parse arg routine, peer_h, operation, ctx
  select
    when routine == 'connect'    then return Hnd_Connect(peer_h, operation, ctx)
    when routine == 'tree'       then return Hnd_Tree(peer_h, operation, ctx)
    when routine == 'handlers'   then return Hnd_Handlers(peer_h, operation, ctx)
    when routine == 'type'       then return Hnd_Type(peer_h, operation, ctx)
    when routine == 'capability' then return Hnd_Capability(peer_h, operation, ctx)
    when routine == 'echo'       then return Hnd_Echo(peer_h, operation, ctx)
    when routine == 'dispatch_outbound' then return Hnd_DispatchOutbound(peer_h, operation, ctx)
    otherwise return Out_Err(501, 'unsupported_operation', routine)
  end

/* ── grant construction (§4.4 / §5.4) — return packed lists of grant MAP TVs ── */
_pl: procedure                                  /* packed list from a blank-separated string */
  parse arg s
  out = ''
  do while strip(s) \== ''
    parse var s word s
    if word \== '' then out = Lst_Add(out, word)
  end
  return out

_discovery_floor: procedure expose EC.
  parse arg h
  g1 = Cap_Grant(_pl('system/tree'), _pl('system/type/* system/handler/*'), _pl('get'), '')
  g2 = Cap_Grant(_pl('system/capability'), '', _pl('request'), '')
  return Lst_Add(Lst_Add('', g1), g2)
_open_grants_scope: procedure expose EC.
  parse arg h
  g = Cap_Grant(_pl('*'), _pl('* /*/*'), _pl('*'), _pl('*'))
  return Lst_Add('', g)
_owner_grants: procedure expose EC.
  parse arg h
  g = Cap_Grant(_pl('*'), _pl('*'), _pl('*'), _pl(Peer_LocalPeer(h)))
  return Lst_Add('', g)

/* ── token mint (§4.4 / §6.9a) -> a minted pair: len(token,4)||token||signature ── */
/* Mint_Token_At at the current instant with no §5.6 ceiling. Used by the paths that
 * mint a self-issued grant from local authority (bootstrap, handler registration, the
 * §4.4 handshake), where no MIN_DEFINED term is in play. */
Peer_MintToken: procedure expose EC.
  parse arg h, grantee_hash, grants, parent
  return Peer_MintTokenAt(h, Cap_NowMs(), grantee_hash, grants, parent, '')

/* Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
 *
 * An empty `expires_at` means no term was defined and the token genuinely has no expiry
 * (the ONLY "no bound" spelling). A present value is emitted verbatim -- including one
 * equal to `created_at`, which §5.6 rule 2 requires for ttl_ms == 0 and which means
 * "already expired at every observable instant", not "unbounded".
 *
 * `created_at` is supplied rather than sampled here so a computed expiry is guaranteed
 * to be relative to the SAME instant that lands in the token; sampling the clock twice
 * skews the two. */
Peer_MintTokenAt: procedure expose EC.
  parse arg h, created_at, grantee_hash, grants, parent, expires_at
  ident = Peer_Identity(h)
  m = Ecf_Map('granter', Ecf_Bytes(Id_IdHash(ident)), 'grantee', Ecf_Bytes(grantee_hash))
  m = Ecf_MapPut(m, 'grants', Ecf_Array(grants))
  m = Ecf_MapPut(m, 'created_at', Ecf_Int(created_at))
  if expires_at \== '' then m = Ecf_MapPut(m, 'expires_at', Ecf_Int(expires_at))
  if parent \== '' then m = Ecf_MapPut(m, 'parent', Ecf_Bytes(parent))
  token = Ent_Make('system/capability/token', m)
  sig = Id_Sign(ident, token)
  return d2c(length(token), 4) || token || sig
Minted_Token: procedure
  parse arg m
  numeric digits 40
  tl = c2d(substr(m, 1, 4))
  return substr(m, 5, tl)
Minted_Sig: procedure
  parse arg m
  numeric digits 40
  tl = c2d(substr(m, 1, 4))
  return substr(m, 5 + tl)

Peer_CapIncluded: procedure expose EC.
  parse arg h, minted
  ident = Peer_Identity(h)
  inc = Lst_Add('', Minted_Token(minted))
  inc = Lst_Add(inc, Id_PeerEntity(ident))
  inc = Lst_Add(inc, Minted_Sig(minted))
  return inc

/* ── §6.9a seed policy (authenticate-time grant derivation) ── */
_seed_entry_grants: procedure expose EC.
  parse arg h, e
  ident = Peer_Identity(h)
  store_h = Peer_Store(h)
  type = Ent_Type(e)
  if type == 'system/capability/token' then do
    sig_path = '/' || Peer_LocalPeer(h) || '/system/signature/' || Hexlc(Ent_Hash(e))
    sgn = Store_GetAt(store_h, sig_path)
    if sgn \== '' & Id_VerifySignature(sgn, Id_PeerEntity(ident)) then return Ecf_MapList(Ent_DataMap(e), 'grants')
    return ''
  end
  if type == 'system/capability/policy-entry' then return Ecf_MapList(Ent_DataMap(e), 'grants')
  return ''

Peer_DeriveSeedGrants: procedure expose EC.
  parse arg h, remote_peer, remote_peer_id
  store_h = Peer_Store(h)
  base = '/' || Peer_LocalPeer(h) || '/system/capability/policy/'
  entry = Store_GetAt(store_h, base || Hexlc(Ent_Hash(remote_peer)))
  if entry == '' then entry = Store_GetAt(store_h, base || remote_peer_id)
  if entry == '' then entry = Store_GetAt(store_h, base || 'default')
  floor = _discovery_floor(h)
  if entry == '' then return floor
  policy = _seed_entry_grants(h, entry)
  if Lst_Count(policy) == 0 then return floor
  /* union floor ++ policy */
  out = floor
  do i = 1 to Lst_Count(policy)
    out = Lst_Add(out, Lst_Item(policy, i))
  end
  return out

/* ── §6.13(b) handler-facing outbound dispatch (§6.11 reentry) ── */
Peer_OutboundDispatch: procedure expose EC.
  parse arg h, conn_h, uri, operation, params, capability, granter_peer, cap_sig, resource
  ident = Peer_Identity(h)
  io = Conn_Get(conn_h, 'io')
  if io == '' then return ''
  request_id = 'out-' || Conn_NextOut(conn_h)
  exec = Wire_MakeExecute(request_id, uri, operation, params, Id_IdHash(ident), Ent_Hash(capability), resource)
  exec_sig = Id_Sign(ident, exec)
  inc = Lst_Add('', capability)
  inc = Lst_Add(inc, granter_peer)
  inc = Lst_Add(inc, Id_PeerEntity(ident))
  inc = Lst_Add(inc, cap_sig)
  inc = Lst_Add(inc, exec_sig)
  return Transport_Outbound(io, Env_Make(exec, inc))

/* ── dispatcher-level signature ingestion (§6.5) ── */
/* Make the granter/signer PEER entities an inbound envelope carries available to
 * later chain resolution (Cap_ResolveGranterPeerId falls back to the store) — bounded:
 * distinct peers dedup by content hash. The SIGNATURE entities themselves are
 * deliberately NOT persisted or tree-bound: a signature is unique per request (a fresh
 * request_id → fresh signed bytes → fresh content hash), so storing + binding one at
 * `/pid/system/signature/<target>` per inbound request is UNBOUNDED growth driven by
 * request traffic — a §4.9/§4.10 resource-exhaustion vector — and it is not needed:
 * Cap_VerifyRequest verifies signatures straight from the envelope's `included`, never
 * from the store. (Finding A-RX-014: the earlier ingest also made every listing O(n²)
 * over the accreting `SPATHS`, which wedged listing-touching ops under a sustained
 * flood.) Signatures that are legitimately PUBLISHED still land via tree.put. */
_ingest_signatures: procedure expose EC.
  parse arg h, env
  store_h = Peer_Store(h)
  inc = Env_Included(env)
  do i = 1 to Lst_Count(inc)
    e = Lst_Item(inc, i)
    if Ent_Type(e) \== 'system/signature' then iterate
    signer_h = Ent_Bytes(e, 'signer')
    if signer_h == '' then iterate
    signer_peer = Env_IncludedGet(env, signer_h)
    if signer_peer == '' then iterate
    call Store_PutEntity store_h, signer_peer
  end
  return

/* ── handler resolution (§6.6) — backward tree-walk ── */
_resolve_handler: procedure expose EC.
  parse arg h, path
  store_h = Peer_Store(h)
  /* split path on '/' into segments; walk longest prefix down to shortest */
  cnt = 0
  rest = path
  do while rest \== ''
    slash = pos('/', rest)
    if slash == 0 then do; cnt = cnt + 1; seg.cnt = rest; rest = ''; end
    else do; cnt = cnt + 1; seg.cnt = substr(rest, 1, slash - 1); rest = substr(rest, slash + 1); end
  end
  do i = cnt to 1 by -1
    prefix = ''
    do j = 1 to i
      if j == 1 then prefix = seg.j
      else prefix = prefix || '/' || seg.j
    end
    e = Store_GetAt(store_h, prefix)
    if e \== '' & Ent_Type(e) == 'system/handler' then return prefix
  end
  return ''

_strip_local: procedure expose EC.
  parse arg h, pattern
  pfx = '/' || Peer_LocalPeer(h) || '/'
  if length(pattern) >= length(pfx) & substr(pattern, 1, length(pfx)) == pfx then return substr(pattern, length(pfx) + 1)
  return pattern

/* ── entity-native dispatch (§6.13(a)) ── */
_entity_native_dispatch: procedure expose EC.
  parse arg h, handler_path
  store_h = Peer_Store(h)
  he = Store_GetAt(store_h, handler_path)
  if he == '' then return Out_Err(404, 'handler_not_found', handler_path)
  expr_path = Ent_Text(he, 'expression_path')
  if expr_path == '' then return Out_Err(501, 'no_handler_body', handler_path)
  abs_ = Cap_Canonicalize(Peer_LocalPeer(h), expr_path)
  expr = Store_GetAt(store_h, abs_)
  if expr == '' then return Out_Err(404, 'expression_not_found', abs_)
  if Ent_Type(expr) == 'compute/literal' then do
    value = Ent_Field(expr, 'value')
    if value == '' then return Out_Err(400, 'unexpected_params', 'compute/literal missing value')
    m = Ecf_Map('value', value, 'expression', Ecf_Bytes(Ent_Hash(expr)))
    return Out_Ok(Ent_Make('compute/result', m), '')
  end
  return Out_Err(501, 'unsupported_expression', Ent_Type(expr))

/* ── dispatch chain (§6.5) — returns an EXECUTE_RESPONSE envelope, or '' for a
 * non-EXECUTE root (§3.3). ── */
Peer_Dispatch: procedure expose EC.
  parse arg h, conn_h, env
  exec = Env_Root(env)
  if Ent_Type(exec) \== 'system/protocol/execute' then do
    /* §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400 invalid_request,
     * coded frame; MAY then close (§3.3, §4.11). NOT a bare close -- that is
     * indistinguishable from a network fault."
     *
     * §3.3 read "the connection MUST be closed", assigning no code and requiring no frame,
     * and §9.1's floor row that MANDATED the bare close was REPLACED at the same revision
     * (N18). This peer did something weaker still: it returned '', the transport wrote
     * NOTHING, and the connection stayed open -- which is §4.11's OTHER non-conformant
     * behaviour, the silent drop, "the weaker of the two precisely because nothing
     * surfaces it". This is a PRE-ADMISSION refusal: the root is not an EXECUTE, so
     * nothing was ever admitted and §4.9(c) does not reach it.
     *
     * The request_id is read best-effort -- an arbitrary root type is under no obligation
     * to carry one, and §4.11 licenses the uncorrelated frame exactly there. We do NOT
     * close: on a multiplexed connection that would cost every ADMITTED in-flight request
     * its response, and §4.11 leaves the close to us. */
    parse value Wire_PreAdmissionRefusal('non_execute_root') with pa_status pa_code pa_msg
    pa_msg = 'root entity is neither EXECUTE nor EXECUTE_RESPONSE'
    return Env_Make(Wire_MakeResponse(Ent_Text(exec, 'request_id'), pa_status, Wire_ErrorResult(pa_code, pa_msg)), '')
  end
  request_id = Ent_Text(exec, 'request_id')
  call Throw_Clear
  outcome = _dispatch_inner(h, conn_h, env, exec)
  if EC.!EXC == 'UNRESOLVABLE_GRANTEE' then outcome = Out_Err(401, 'unresolvable_grantee', '')
  else if EC.!EXC == 'reserved_relative' | EC.!EXC == 'ambiguous_wildcard' then outcome = Out_Err(400, 'invalid_path', '')
  else if _is_codec_exc(EC.!EXC) then do
    /* THE CODE BELONGS TO THE CAUSE (§4.11, §5.2a; 0.8.2.24 N4/N5). A nested entity
     * decoded here can fail for either reason and this arm used to answer
     * non_canonical_ecf for both: that code is ENTITY-CBOR-ENCODING's, for a CBOR
     * tag-policy violation, and §5.2a rules it "NOT conformant" for a resolution-integrity
     * failure whose encoding is perfectly canonical. Shared with the transport's
     * pre-admission classifier so the two cannot drift. */
    parse value Wire_PreAdmissionRefusal(EC.!EXC) with dx_status dx_code dx_msg
    outcome = Out_Err(dx_status, dx_code, dx_msg)
  end
  resp = Wire_MakeResponse(request_id, Out_Status(outcome), Out_Result(outcome))
  return Env_Make(resp, Out_Included(outcome))

_is_codec_exc: procedure
  parse arg k
  return (k == 'not_a_map' | k == 'missing_root' | k == 'missing_type' | k == 'missing_data' | ,
          k == 'content_hash_mismatch' | k == 'included_key_not_bytes' | ,
          k == 'included_value_not_map' | k == 'included_key_mismatch')

_dispatch_inner: procedure expose EC.
  parse arg h, conn_h, env, exec
  store_h = Peer_Store(h)
  uri = Ent_Text(exec, 'uri')
  operation = Ent_Text(exec, 'operation')
  if uri == 'system/protocol/connect' then do
    ctx = Ctx_Make(conn_h, '', env, '')
    return Peer_CallHandler('connect', h, operation, ctx)
  end
  call _ingest_signatures h, env
  /* §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to  */
  /* sit below the §5.2 verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace  */
  /* took the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the  */
  /* caller to authenticate and retry, and for a foreign-namespace address that retry  */
  /* cannot succeed at any authentication state — so the 401 names a remedy that does not  */
  /* exist." §6.5 step 3 calls it "a gate, not an ordering preference".  */
  path = Cap_Canonicalize(Peer_LocalPeer(h), Cap_NormalizeUri(uri))
  if Cap_ExtractPeer(Peer_LocalPeer(h), path) \== Peer_LocalPeer(h) then return Out_Err(400, 'invalid_request', 'not local peer')
  rv = Cap_VerifyRequest(Peer_LocalPeer(h), store_h, env)
  select
    when rv == 'AUTHN_FAIL'     then return Out_Err(401, 'authentication_failed', '')
    when rv == 'AUTHZ_DENY'     then return Out_Err(403, 'capability_denied', '')
    when rv == 'CHAIN_TOO_DEEP' then return Out_Err(400, 'chain_depth_exceeded', '')
    otherwise nop
  end
  /* (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7  */
  /* 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)  */
  pattern = _resolve_handler(h, path)
  if pattern == '' then return Out_Err(404, 'handler_not_found', path)
  cap_h = Ent_Bytes(exec, 'capability')
  caller_cap = ''
  if cap_h \== '' then caller_cap = Env_IncludedGet(env, cap_h)
  if caller_cap == '' then return Out_Err(403, 'capability_denied', '')
  granter_peer = Cap_ResolveGranterPeerId(Env_Included(env), store_h, caller_cap)
  if granter_peer == '' then granter_peer = Peer_LocalPeer(h)
  if Cap_CheckPermission(Peer_LocalPeer(h), granter_peer, exec, caller_cap, pattern) == 'DENY' then return Out_Err(403, 'capability_denied', '')
  stripped = _strip_local(h, pattern)
  if Peer_HasHandler(h, stripped) then do
    ctx = Ctx_Make(conn_h, caller_cap, env, pattern)
    return Peer_CallHandler(Peer_HandlerRoutine(h, stripped), h, operation, ctx)
  end
  return _entity_native_dispatch(h, pattern)

/* ── bootstrap (§6.9) ── */
_op_spec: procedure expose EC.
  parse arg input, output
  m = ''
  if input \== '' then m = Ecf_MapPut(m, 'input_type', Ecf_Str(input))
  if output \== '' then m = Ecf_MapPut(m, 'output_type', Ecf_Str(output))
  if m == '' then return Ecf_EmptyMap()
  return m

/* register one MUST/conformance handler: the instance-map token + the store entities.
 * ops is a packed list of "opname<TAB>input<TAB>output" rows. */
_bootstrap_handler: procedure expose EC.
  parse arg h, pattern, routine, name, ops
  store_h = Peer_Store(h)
  ident = Peer_Identity(h)
  EC.!PEER_HANDLER.h.pattern = routine
  EC.!PEER_HAS.h.pattern = 1
  operations = ''
  do i = 1 to Lst_Count(ops)
    row = Lst_Item(ops, i)
    parse var row opname '09'x input '09'x output
    operations = Ecf_MapPut(operations, opname, _op_spec(input, output))
  end
  if operations == '' then operations = Ecf_EmptyMap()
  call Store_Bind store_h, Peer_Abs(h, pattern), Ent_Make('system/handler', Ecf_Map('interface', Ecf_Str('system/handler/' || pattern)))
  im = Ecf_Map('pattern', Ecf_Str(pattern), 'name', Ecf_Str(name))
  im = Ecf_MapPut(im, 'operations', operations)
  call Store_Bind store_h, Peer_Abs(h, 'system/handler/' || pattern), Ent_Make('system/handler/interface', im)
  m = Peer_MintToken(h, Id_IdHash(ident), '', '')
  call Store_Bind store_h, Peer_Abs(h, 'system/capability/grants/' || pattern), Minted_Token(m)
  return

_op: procedure                                  /* build one "opname<TAB>in<TAB>out" row */
  parse arg opname, input, output
  return opname || '09'x || input || '09'x || output

_bootstrap: procedure expose EC.
  parse arg h
  store_h = Peer_Store(h)
  ident = Peer_Identity(h)
  call Store_PutEntity store_h, Id_PeerEntity(ident)
  call Ct_Publish store_h, Peer_LocalPeer(h)

  /* MUST handler instances (§6.6 -> instance map). */
  ops = Lst_Add(Lst_Add('', _op('get', '', '')), _op('put', '', ''))
  call _bootstrap_handler h, 'system/tree', 'tree', 'Tree', ops
  ops = Lst_Add(Lst_Add('', _op('register', 'system/handler/register-request', 'system/handler/register-result')), _op('unregister', 'system/handler/unregister-request', ''))
  call _bootstrap_handler h, 'system/handler', 'handlers', 'Handlers', ops
  ops = Lst_Add('', _op('validate', 'system/type/validate-request', 'system/type/validate-result'))
  call _bootstrap_handler h, 'system/type', 'type', 'Types', ops
  ops = Lst_Add(Lst_Add(Lst_Add(Lst_Add('', _op('request', 'system/capability/request', 'system/capability/grant')), _op('revoke', 'system/capability/revoke-request', '')), _op('configure', 'system/capability/policy-entry', '')), _op('delegate', 'system/capability/delegate-request', 'system/capability/grant'))
  call _bootstrap_handler h, 'system/capability', 'capability', 'Capability', ops
  ops = Lst_Add(Lst_Add('', _op('hello', '', '')), _op('authenticate', '', ''))
  call _bootstrap_handler h, 'system/protocol/connect', 'connect', 'Connect', ops

  /* §6.9a Peer Authority Bootstrap: self-owner cap + default scope-template entry. */
  policy_base = '/' || Peer_LocalPeer(h) || '/system/capability/policy/'
  owner = Peer_MintToken(h, Id_IdHash(ident), _owner_grants(h), '')
  call Store_Bind store_h, policy_base || Hexlc(Id_IdHash(ident)), Minted_Token(owner)
  call Store_Bind store_h, '/' || Peer_LocalPeer(h) || '/system/signature/' || Hexlc(Ent_Hash(Minted_Token(owner))), Minted_Sig(owner)
  k = 'open_grants'
  if EC.!PEER.h.k then default_grants = _open_grants_scope(h)
  else default_grants = _discovery_floor(h)
  pe = Ecf_Map('peer_pattern', Ecf_Str('default'), 'grants', Ecf_Array(default_grants))
  call Store_Bind store_h, policy_base || 'default', Ent_Make('system/capability/policy-entry', pe)

  /* §7a conformance handlers — only under --validate. */
  k = 'conformance'
  if EC.!PEER.h.k then do
    ops = Lst_Add('', _op('echo', '', ''))
    call _bootstrap_handler h, 'system/validate/echo', 'echo', 'validate-echo', ops
    ops = Lst_Add('', _op('dispatch', '', ''))
    call _bootstrap_handler h, 'system/validate/dispatch-outbound', 'dispatch_outbound', 'validate-dispatch-outbound', ops
  end
  return
