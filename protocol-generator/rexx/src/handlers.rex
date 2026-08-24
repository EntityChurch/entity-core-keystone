/* entity-core-protocol-rexx — the MUST system handlers (§6.2) + §7a conformance
 * handlers. Each is a routine Hnd_X(peer_h, operation, ctx) returning an OUTCOME
 * (peer.rex Out_*); the per-operation dispatch is a SELECT with an "unknown operation
 * -> 501" default. A handler that originates an outbound EXECUTE (§6.13(b)/§6.11
 * reentry) calls Peer_OutboundDispatch, which pumps the single serve loop until the
 * reply correlates (no thread to block).
 *
 * ctx (peer.rex Ctx_*): the inbound envelope + conn handle + resolved caller cap.
 */

_hparams: procedure expose EC.
  parse arg ctx
  return Ent_EntityField(Ctx_Exec(ctx), 'params')

/* ── stateless helpers (path/resource parsing + §3.9 zero-hash) ── */
Hnd_ExecResourceTarget: procedure expose EC.
  parse arg exec
  r = Ent_MapField(exec, 'resource')
  if r == '' then return ''
  targets = Ecf_TextList(r, 'targets')
  if Lst_Count(targets) == 0 then return ''
  return Lst_Item(targets, 1)

/* §1.4 path validity (no NUL, no empty/./.. segments; abs paths peer-rooted). */
Hnd_PathFlexOk: procedure expose EC.
  parse arg target
  if pos('00'x, target) > 0 then return 0
  if _sw(target, '/') then do
    /* split "/a/b/..." -> body after the peer segment; first seg after '/' must be a peer_id */
    rest = substr(target, 2)
    slash = pos('/', rest)
    if slash == 0 then do; abs_ok = Cap_IsPeerId(rest); body = ''; end
    else do
      first = substr(rest, 1, slash - 1)
      abs_ok = Cap_IsPeerId(first)
      body = substr(rest, slash + 1)
    end
  end
  else do
    abs_ok = 1
    body = target
  end
  if \abs_ok then return 0
  /* strip a single trailing slash, then reject empty/./.. segments */
  if right(body, 1) == '/' then body = substr(body, 1, length(body) - 1)
  do while body \== ''
    slash = pos('/', body)
    if slash == 0 then do; seg = body; body = ''; end
    else do; seg = substr(body, 1, slash - 1); body = substr(body, slash + 1); end
    if seg == '' | seg == '.' | seg == '..' then return 0
  end
  return 1

Hnd_IsZeroHash: procedure
  parse arg h
  return (strip(h, 'B', '00'x) == '')

Hnd_ReqGrants: procedure expose EC.
  parse arg params
  if params == '' then return ''
  return Ecf_MapList(Ent_DataMap(params), 'grants')

Hnd_RegisterPattern: procedure expose EC.
  parse arg exec
  target = Hnd_ExecResourceTarget(exec)
  if target == '' then return ''
  pfx = 'system/handler/'
  if length(target) <= length(pfx) then return ''
  if substr(target, 1, length(pfx)) \== pfx then return ''
  return substr(target, length(pfx) + 1)

Hnd_RegisterPatternError: procedure expose EC.
  parse arg exec
  if Hnd_ExecResourceTarget(exec) == '' then return Out_Err(400, 'ambiguous_resource', 'register/unregister require exactly one resource target')
  return Out_Err(400, 'invalid_resource', 'resource target MUST be system/handler/{pattern}')

/* ═════ §4.1 / §4.6 connect handler ═════ */
Hnd_Connect: procedure expose EC.
  parse arg peer_h, operation, ctx
  select
    when operation == 'hello'        then return _connect_hello(peer_h, ctx)
    when operation == 'authenticate' then return _connect_authenticate(peer_h, ctx)
    otherwise return Out_Err(501, 'unsupported_operation', operation)
  end

/* is a §4.5-declared format list PRESENT and DISJOINT from our single supported value?
 * Ecf_Has distinguishes a present-but-EMPTY array (reject) from absent (skip) —
 * A-RX-007 present-empty-vs-absent seam. */
_negotiation_disjoint: procedure expose EC.
  parse arg params, key, supported
  if params == '' then return 0
  d = Ent_DataMap(params)
  if \Ecf_Has(d, key) then return 0
  declared = Ecf_TextList(d, key)
  return \_lst_has(declared, supported)

_connect_hello: procedure expose EC.
  parse arg peer_h, ctx
  conn = Ctx_Conn(ctx)
  exec = Ctx_Exec(ctx)
  if Conn_Get(conn, 'established') then return Out_Err(409, 'connection_already_established', '')
  params = Ent_EntityField(exec, 'params')
  if _negotiation_disjoint(params, 'hash_formats', 'ecfv1-sha256') then return Out_Err(400, 'incompatible_hash_format', '')
  if _negotiation_disjoint(params, 'key_types', 'ed25519') then return Out_Err(400, 'unsupported_key_type', '')
  if params \== '' then call Conn_Set conn, 'hello_peer_id', Ent_Text(params, 'peer_id')
  nonce = Peer_RandomBytes(32)
  call Conn_Set conn, 'issued_nonce', nonce
  hm = Ecf_Map('peer_id', Ecf_Str(Peer_LocalPeer(peer_h)), 'nonce', Ecf_Bytes(nonce))
  hm = Ecf_MapPut(hm, 'protocols', Ecf_TextArray(_pl('entity-core/1.0')))
  hm = Ecf_MapPut(hm, 'timestamp', Ecf_Int(Cap_NowMs()))
  hm = Ecf_MapPut(hm, 'hash_formats', Ecf_TextArray(_pl('ecfv1-sha256')))
  hm = Ecf_MapPut(hm, 'key_types', Ecf_TextArray(_pl('ed25519')))
  return Out_Ok(Ent_Make('system/protocol/connect/hello', hm), '')

_connect_authenticate: procedure expose EC.
  parse arg peer_h, ctx
  conn = Ctx_Conn(ctx)
  exec = Ctx_Exec(ctx)
  included = Ctx_Included(ctx)
  /* RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
   * single-use nonce. The anti-replay property is the MUST and the mechanism
   * (established-state tracking) is impl-defined, but the STATUS is pinned to
   * 401 invalid_nonce — a 409 state-conflict under-signals the replay. */
  if Conn_Get(conn, 'established') then return Out_Err(401, 'invalid_nonce', '')
  issued_nonce = Conn_Get(conn, 'issued_nonce')
  if issued_nonce == '' then return Out_Err(401, 'invalid_nonce', '')
  auth = Ent_EntityField(exec, 'params')
  if auth == '' then return Out_Err(401, 'authentication_failed', '')
  bad_kt = 0
  kt = Ent_Text(auth, 'key_type')
  if kt \== '' & kt \== 'ed25519' then bad_kt = 1
  pub = Ent_Bytes(auth, 'public_key')
  if \bad_kt & pub \== '' & length(pub) \== 32 then bad_kt = 1
  claimed = Ent_Text(auth, 'peer_id')
  if \bad_kt & claimed \== '' then do
    EC.!OK = 1
    parsed = Peerid_Parse(claimed)
    if EC.!OK then do
      parse var parsed pkt .
      if pkt \= 1 then bad_kt = 1
    end
    EC.!OK = 1
  end
  if bad_kt then return Out_Err(400, 'unsupported_key_type', '')
  echoed = Ent_Bytes(auth, 'nonce')
  if \(echoed \== '' & echoed == issued_nonce) then return Out_Err(401, 'invalid_nonce', '')
  if pub == '' then return Out_Err(401, 'authentication_failed', '')
  sgn = Cap_FindSignature(Ent_Hash(auth), included)
  sig_ok = 0
  if sgn \== '' then do
    sb = Ent_Bytes(sgn, 'signature')
    if sb \== '' & length(sb) == 64 then sig_ok = Crypto_Ed25519Verify(pub, Ent_Hash(auth), sb)
  end
  if \sig_ok then return Out_Err(401, 'authentication_failed', '')
  if claimed \== Id_PeerIdOfPubkey(pub) then return Out_Err(401, 'identity_mismatch', '')
  hello_pid = Conn_Get(conn, 'hello_peer_id')
  if hello_pid \== '' & hello_pid \== claimed then return Out_Err(401, 'identity_mismatch', '')
  remote_peer = Id_PeerEntityOfPubkey(pub)
  grants = Peer_DeriveSeedGrants(peer_h, remote_peer, claimed)
  m = Peer_MintToken(peer_h, Ent_Hash(remote_peer), grants, '')
  call Conn_Set conn, 'established', 1
  gm = Ecf_Map('token', Ecf_Bytes(Ent_Hash(Minted_Token(m))))
  return Out_Ok(Ent_Make('system/capability/grant', gm), Peer_CapIncluded(peer_h, m))

/* ═════ §6.3 tree handler ═════ */
Hnd_Tree: procedure expose EC.
  parse arg peer_h, operation, ctx
  select
    when operation == 'get' then return _tree_get(peer_h, ctx)
    when operation == 'put' then return _tree_put(peer_h, ctx)
    otherwise return Out_Err(501, 'unsupported_operation', operation)
  end

_tree_get: procedure expose EC.
  parse arg peer_h, ctx
  exec = Ctx_Exec(ctx)
  local = Peer_LocalPeer(peer_h)
  store_h = Peer_Store(peer_h)
  target = Hnd_ExecResourceTarget(exec)
  if target \== '' & \Hnd_PathFlexOk(target) then return Out_Err(400, 'invalid_path', target)
  if target == '' then return _tree_listing(peer_h, '/' || local || '/')
  if right(target, 1) == '/' then return _tree_listing(peer_h, Cap_Canonicalize(local, target))
  path = Cap_Canonicalize(local, target)
  e = Store_GetAt(store_h, path)
  if e == '' then return Out_Err(404, 'not_found', path)
  params = Ent_EntityField(exec, 'params')
  mode = ''
  if params \== '' then mode = Ent_Text(params, 'mode')
  if mode == 'hash' then return Out_Ok(Ent_Make('system/hash', Ecf_Map('hash', Ecf_Bytes(Ent_Hash(e)))), '')
  return Out_Ok(e, '')

_tree_put: procedure expose EC.
  parse arg peer_h, ctx
  exec = Ctx_Exec(ctx)
  local = Peer_LocalPeer(peer_h)
  store_h = Peer_Store(peer_h)
  target = Hnd_ExecResourceTarget(exec)
  if target == '' then return Out_Err(400, 'ambiguous_resource', 'tree: missing resource target')
  if \Hnd_PathFlexOk(target) then return Out_Err(400, 'invalid_path', target)
  path = Cap_Canonicalize(local, target)
  params = Ent_EntityField(exec, 'params')
  entity = ''
  expected = ''
  if params \== '' then do
    entity = Ent_EntityField(params, 'entity')
    expected = Ent_Bytes(params, 'expected_hash')
  end
  current = Store_HashAt(store_h, path)
  if expected == '' then cas_ok = 1
  else if Hnd_IsZeroHash(expected) then cas_ok = (current == '')
  else cas_ok = (current \== '' & current == Hexlc(expected))
  if \cas_ok then return Out_Err(409, 'hash_mismatch', path)
  if entity == '' then return Out_Err(400, 'unexpected_params', 'put: missing entity')
  call Store_Bind store_h, path, entity
  return Out_Ok(Ent_Make('system/hash', Ecf_Map('hash', Ecf_Bytes(Ent_Hash(entity)))), '')

_tree_listing: procedure expose EC.
  parse arg peer_h, path
  store_h = Peer_Store(peer_h)
  rows = Store_Listing(store_h, path)
  em = ''
  count = 0
  do i = 1 to Lst_Count(rows)
    row = Lst_Item(rows, i)
    parse var row seg '09'x hashhex '09'x haschild
    if hashhex \== '' & haschild == 0 then do
      me = Store_GetByHash(store_h, x2c(translate(hashhex)))
      if me \== '' & Ent_Type(me) == 'system/deletion-marker' then iterate
    end
    if hashhex \== '' then led = Ent_Make('system/tree/listing-entry', Ecf_Map('has_children', Ecf_Bool(haschild), 'hash', Ecf_Bytes(x2c(translate(hashhex)))))
    else led = Ent_Make('system/tree/listing-entry', Ecf_Map('has_children', Ecf_Bool(haschild)))
    em = Ecf_MapPut(em, seg, Ent_ToCbor(led))
    count = count + 1
  end
  if em == '' then em = Ecf_EmptyMap()
  lm = Ecf_Map('path', Ecf_Str(path), 'entries', em)
  lm = Ecf_MapPut(lm, 'count', Ecf_Int(count))
  lm = Ecf_MapPut(lm, 'offset', Ecf_Int(0))
  return Out_Ok(Ent_Make('system/tree/listing', lm), '')

/* ═════ §6.2/§6.13(a) handlers handler ═════ */
Hnd_Handlers: procedure expose EC.
  parse arg peer_h, operation, ctx
  select
    when operation == 'register'   then return _handlers_register(peer_h, ctx)
    when operation == 'unregister' then return _handlers_unregister(peer_h, ctx)
    otherwise return Out_Err(501, 'unsupported_operation', operation)
  end

_handlers_register: procedure expose EC.
  parse arg peer_h, ctx
  exec = Ctx_Exec(ctx)
  store_h = Peer_Store(peer_h)
  ident = Peer_Identity(peer_h)
  pattern = Hnd_RegisterPattern(exec)
  if pattern == '' then return Hnd_RegisterPatternError(exec)
  req = Ent_EntityField(exec, 'params')
  if req == '' then return Out_Err(400, 'unexpected_params', 'register: missing params')
  if Ent_Type(req) \== 'system/handler/register-request' then return Out_Err(400, 'unexpected_params', 'register expects register-request')
  manifest = Ent_MapField(req, 'manifest')
  if manifest == '' then manifest = Ecf_EmptyMap()
  name = Ecf_Text(manifest, 'name')
  if name == '' then name = pattern
  operations = Ecf_MapField(manifest, 'operations')
  if operations == '' then operations = Ecf_EmptyMap()
  expr_path = Ecf_Text(manifest, 'expression_path')
  internal_scope = Ecf_Get(manifest, 'internal_scope')
  grant_scope = Ecf_MapList(Ent_DataMap(req), 'requested_scope')
  if Lst_Count(grant_scope) == 0 & internal_scope \== '' then grant_scope = Ecf_MapList(Ent_DataMap(req), 'internal_scope')
  interface_rel = 'system/handler/' || pattern
  hp = Ecf_Map('interface', Ecf_Str(interface_rel))
  if expr_path \== '' then hp = Ecf_MapPut(hp, 'expression_path', Ecf_Str(expr_path))
  if internal_scope \== '' then hp = Ecf_MapPut(hp, 'internal_scope', internal_scope)
  call Store_Bind store_h, Peer_Abs(peer_h, pattern), Ent_Make('system/handler', hp)
  /* associated types */
  types = Ent_MapField(req, 'types')
  if types \== '' then do
    do i = 1 to Ecf_MapCount(types)
      tk = Ecf_MapKey(types, i)
      tv = Ecf_MapVal(types, i)
      if Tv_Tag(tk) \== 't' then iterate
      tname = Tv_Payload(tk)
      if Tv_Tag(tv) == 'm' then td = tv
      else td = Ecf_Map('def', tv)
      call Store_Bind store_h, Peer_Abs(peer_h, 'system/type/' || tname), Ent_Make('system/type', td)
    end
  end
  m = Peer_MintToken(peer_h, Id_IdHash(ident), grant_scope, '')
  call Store_Bind store_h, Peer_Abs(peer_h, 'system/capability/grants/' || pattern), Minted_Token(m)
  call Store_Bind store_h, Peer_Abs(peer_h, 'system/signature/' || Hexlc(Ent_Hash(Minted_Token(m)))), Minted_Sig(m)
  im = Ecf_Map('pattern', Ecf_Str(pattern), 'name', Ecf_Str(name))
  im = Ecf_MapPut(im, 'operations', operations)
  call Store_Bind store_h, Peer_Abs(peer_h, interface_rel), Ent_Make('system/handler/interface', im)
  rm = Ecf_Map('pattern', Ecf_Str(pattern), 'grant', Ent_Data(Minted_Token(m)))
  return Out_Ok(Ent_Make('system/handler/register-result', rm), '')

_handlers_unregister: procedure expose EC.
  parse arg peer_h, ctx
  exec = Ctx_Exec(ctx)
  store_h = Peer_Store(peer_h)
  pattern = Hnd_RegisterPattern(exec)
  if pattern == '' then return Hnd_RegisterPatternError(exec)
  g = Store_GetAt(store_h, Peer_Abs(peer_h, 'system/capability/grants/' || pattern))
  if g \== '' then do
    call Store_Unbind store_h, Peer_Abs(peer_h, 'system/signature/' || Hexlc(Ent_Hash(g)))
    call Store_Unbind store_h, Peer_Abs(peer_h, 'system/capability/grants/' || pattern)
  end
  call Store_Unbind store_h, Peer_Abs(peer_h, pattern)
  call Store_Unbind store_h, Peer_Abs(peer_h, 'system/handler/' || pattern)
  return Out_Ok(Wire_EmptyParams(), '')

/* ═════ system/type:validate handler (EXTENSION shape kept minimal) ═════ */
Hnd_Type: procedure expose EC.
  parse arg peer_h, operation, ctx
  if operation \== 'validate' then return Out_Err(501, 'unsupported_operation', operation)
  store_h = Peer_Store(peer_h)
  req = _hparams(ctx)
  if req == '' then return Out_Err(400, 'invalid_params', 'validate requires a params entity')
  subject = Ent_EntityField(req, 'entity')
  if subject == '' then return Out_Err(400, 'unexpected_params', 'validate-request missing entity')
  type_name = Ent_Text(req, 'type_path')
  if type_name == '' then type_name = Ent_Type(subject)
  type_def = Store_GetAt(store_h, Peer_Abs(peer_h, 'system/type/' || type_name))
  if type_def == '' then do
    vm = Ecf_Map('valid', Ecf_Bool(0))
    return Out_Ok(Ent_Make('system/type/validate-result', vm), '')
  end
  fields = Ent_MapField(type_def, 'fields')
  subj_data = Ecf_AsMap(Ent_Data(subject))
  valid = 1
  vlist = ''
  if fields \== '' then do
    do i = 1 to Ecf_MapCount(fields)
      fk = Ecf_MapKey(fields, i)
      fv = Ecf_MapVal(fields, i)
      if Tv_Tag(fk) \== 't' then iterate
      fname = Tv_Payload(fk)
      spec = Ecf_AsMap(fv)
      optional = (spec \== '' & Ecf_BoolIs(spec, 'optional'))
      present = (subj_data \== '' & Ecf_Has(subj_data, fname))
      if \optional & \present then do
        valid = 0
        vlist = Lst_Add(vlist, Ecf_Map('kind', Ecf_Str('missing_required_field'), 'field', Ecf_Str(fname)))
      end
    end
  end
  vm = Ecf_Map('valid', Ecf_Bool(valid))
  if Lst_Count(vlist) > 0 then vm = Ecf_MapPut(vm, 'violations', Ecf_Array(vlist))
  return Out_Ok(Ent_Make('system/type/validate-result', vm), '')

/* ═════ §6.2 capability handler ═════ */
Hnd_Capability: procedure expose EC.
  parse arg peer_h, operation, ctx
  select
    when operation == 'request'   then return _cap_request(peer_h, ctx)
    when operation == 'delegate'  then return _cap_delegate(peer_h, ctx)
    when operation == 'revoke'    then return _cap_revoke(peer_h, ctx)
    when operation == 'configure' then return _cap_configure(peer_h, ctx)
    otherwise return Out_Err(501, 'unsupported_operation', operation)
  end

_cap_request: procedure expose EC.
  parse arg peer_h, ctx
  params = _hparams(ctx)
  author = Ent_Bytes(Ctx_Exec(ctx), 'author')
  if author == '' then return Out_Err(403, 'capability_denied', '')
  return _cap_mint_bounded(peer_h, Ctx_CallerCap(ctx), Hnd_ReqGrants(params), author, '')

_cap_delegate: procedure expose EC.
  parse arg peer_h, ctx
  params = _hparams(ctx)
  author = Ent_Bytes(Ctx_Exec(ctx), 'author')
  ph = ''
  if params \== '' then ph = Ent_Bytes(params, 'parent')
  if ph == '' then return Out_Err(400, 'unexpected_params', 'delegate: parent required')
  if Hnd_IsZeroHash(ph) then return Out_Err(400, 'unexpected_params', 'delegate: zero parent')
  id_hash = Id_IdHash(Peer_Identity(peer_h))
  if \(author \== '' & id_hash == author) then return Out_Err(501, 'unsupported_operation', 'delegate: same-peer-only in v1')
  return _cap_mint_bounded(peer_h, Ctx_CallerCap(ctx), Hnd_ReqGrants(params), author, ph)

_cap_revoke: procedure expose EC.
  parse arg peer_h, ctx
  params = _hparams(ctx)
  store_h = Peer_Store(peer_h)
  token_h = ''
  if params \== '' then token_h = Ent_Bytes(params, 'token')
  if token_h == '' then return Out_Err(400, 'unexpected_params', 'revoke: missing token')
  if Hnd_IsZeroHash(token_h) then return Out_Err(400, 'unexpected_params', 'revoke: zero token')
  rm = Ecf_Map('token', Ecf_Bytes(token_h), 'revoked_at', Ecf_Int(Cap_NowMs()))
  marker = Ent_Make('system/capability/revocation', rm)
  call Store_Bind store_h, '/' || Peer_LocalPeer(peer_h) || '/system/capability/revocations/' || Hexlc(token_h), marker
  return Out_Ok(Wire_EmptyParams(), '')

_cap_configure: procedure expose EC.
  parse arg peer_h, ctx
  params = _hparams(ctx)
  store_h = Peer_Store(peer_h)
  pp = ''
  if params \== '' then pp = Ent_Text(params, 'peer_pattern')
  if pp == '' then return Out_Err(400, 'unexpected_params', 'configure: missing peer_pattern')
  is_hex = (length(pp) == 66 & datatype(pp, 'X') & translate(pp, 'abcdef', 'ABCDEF') == pp)
  if \(pp == 'default' | is_hex | Cap_IsPeerId(pp)) then return Out_Err(400, 'invalid_peer_pattern', pp)
  call Store_Bind store_h, '/' || Peer_LocalPeer(peer_h) || '/system/capability/policy/' || pp, params
  return Out_Ok(Wire_EmptyParams(), '')

_cap_mint_bounded: procedure expose EC.
  parse arg peer_h, caller_cap, req_grants, grantee_hash, parent
  local = Peer_LocalPeer(peer_h)
  bounded = 0
  if caller_cap \== '' then do
    parent_grants = Cap_GrantsOfToken(caller_cap)
    bounded = 1
    do i = 1 to Lst_Count(req_grants)
      c = Cap_ParseGrant(Lst_Item(req_grants, i))
      covered = 0
      do j = 1 to Lst_Count(parent_grants)
        if Cap_GrantSubset(local, local, local, c, Lst_Item(parent_grants, j)) then do; covered = 1; leave; end
      end
      if \covered then do; bounded = 0; leave; end
    end
  end
  if \bounded then return Out_Err(403, 'scope_exceeds_authority', '')
  m = Peer_MintToken(peer_h, grantee_hash, req_grants, parent)
  gm = Ecf_Map('token', Ecf_Bytes(Ent_Hash(Minted_Token(m))))
  return Out_Ok(Ent_Make('system/capability/grant', gm), Peer_CapIncluded(peer_h, m))

/* ═════ §7a conformance handlers (--validate only) ═════ */
Hnd_Echo: procedure expose EC.
  parse arg peer_h, operation, ctx
  if operation \== 'echo' then return Out_Err(501, 'unsupported_operation', operation)
  p = _hparams(ctx)
  if p == '' then return Out_Err(400, 'invalid_params', 'echo requires params')
  return Out_Ok(p, '')

Hnd_DispatchOutbound: procedure expose EC.
  parse arg peer_h, operation, ctx
  if operation \== 'dispatch' then return Out_Err(501, 'unsupported_operation', operation)
  p = _hparams(ctx)
  if p == '' then return Out_Err(400, 'invalid_params', 'dispatch-outbound requires a params entity')
  target = Ent_Text(p, 'target')
  op = Ent_Text(p, 'operation')
  value = Ent_Field(p, 'value')
  cap = Ent_EntityField(p, 'reentry_capability')
  granter = Ent_EntityField(p, 'reentry_granter')
  cap_sig = Ent_EntityField(p, 'reentry_cap_signature')
  if \(value \== '' & cap \== '' & granter \== '' & cap_sig \== '') then return Out_Err(400, 'invalid_params', 'dispatch-outbound requires value + reentry authority')
  /* §7a.1 generic relay: `value` is the downstream params data, forwarded VERBATIM. */
  vm = Ecf_AsMap(value)
  if vm \== '' then inner_data = vm
  else inner_data = Ecf_Map('value', value)
  inner = Ent_Make('primitive/any', inner_data)
  resource = Wire_ResourceTarget('system/handler/' || target)
  resp = Peer_OutboundDispatch(peer_h, Ctx_Conn(ctx), target, op, inner, cap, granter, cap_sig, resource)
  if resp == '' then return Out_Err(503, 'no_outbound_seam', 'no live §6.11 reentry connection')
  root = Env_Root(resp)
  status = Ent_Uint(root, 'status')
  if status == '' then status = 0
  result_cbor = Ent_Field(root, 'result')
  if result_cbor == '' then result_cbor = Ecf_EmptyMap()
  om = Ecf_Map('status', Ecf_Int(status), 'result', result_cbor)
  return Out_Ok(Ent_Make('primitive/any', om), '')
