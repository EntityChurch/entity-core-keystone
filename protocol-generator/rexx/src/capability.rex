/* entity-core-protocol-rexx — capability system (L3): the §5 verification core.
 *
 * Pattern matching (§5.4), request verification (§5.2), delegation-chain verification
 * (§5.5), attenuation (§5.6), caveats (§5.7), revocation (§5.1), and genuine §3.6 M3
 * multi-signature K-of-N. Derived from the §5 pseudocode (the Tcl ::capability::
 * namespace, in Rexx idiom).
 *
 * Layer-1 verdict is 'ALLOW'/'DENY' (§5.10); DENY -> 403, the §5.5 unresolvable-grantee
 * carve-out sets EC.!EXC = UNRESOLVABLE_GRANTEE -> 401. The three-way request verdict
 * folds in §4.10(b) CHAIN_TOO_DEEP -> 400: ALLOW / AUTHN_FAIL / AUTHZ_DENY / CHAIN_TOO_DEEP.
 *
 * §PR-8 granter-frame: the RESOURCE dimension canonicalizes against the GRANTER's
 * peer_id; handlers/operations/peers stay local. For the self-issued dominant path
 * (granter = local) this is byte-identical.
 *
 * Head-form note: thresholds / temporal bounds / depth come off the wire as decimal
 * bignums — plain integer comparison is exact with NO fixed-width trap (the decimal
 * advantage; contrast OCaml int63 / C# ulong).
 *
 * Packed representations (col.rex-style, all pass by value):
 *   scope = len(incl,4)||inclLst || exclLst          (incl/excl = packed pattern lists)
 *   grant = len(h,4)||h len(r,4)||r len(o,4)||o len(p,4)||p   (scopes; p len 0 = peers absent)
 *   grants-of-token = a packed list of grant structs
 *   included = the envelope packed list of entity strings; store_h resolves the rest
 */

/* §4.10(b) / §5.5 max delegation-chain depth lives in EC.!MAX_CHAIN_DEPTH (set once in
 * Ec_Init) so every `procedure expose EC.` sees it — a bare file-level constant would
 * be an unset local (hence a string) inside the routines. */

/* §6.2 CAP-6a: 1 iff every temporal field on a RECEIVED token is either absent (legal)
 * or representable as a uint64.
 *
 * This is the reader-side half of CAP-6 and it is where a peer fails OPEN. Ent_Uint
 * answers '' BOTH when a field is ABSENT and when it is PRESENT but not an 'i'-tagged
 * value; and REXX's native decimal number model means an 'i' value is a plain decimal
 * STRING with no width at all, so a negative or a >2^64 magnitude passes through the tag
 * check unharmed. Either way the range comparison could not fire and a hostile
 * expires_at:-1 was honored with 200. §6.2 CAP-6a: such a token "is malformed. A
 * verifier MUST refuse it and MUST NOT treat the unrepresentable field as absent." An
 * absent field stays legal and is NOT rejected here.
 *
 * Both halves are therefore DELIBERATE range checks rather than overflow traps -- REXX
 * arithmetic has no fixed width to overflow. `numeric digits 40` is required or the
 * 2^64 comparison silently rounds. */
Cap_TemporalFieldsRepresentable: procedure expose EC.
  parse arg tok
  numeric digits 40
  keys = 'expires_at not_before created_at'
  do i = 1 to words(keys)
    k = word(keys, i)
    v = Ent_Field(tok, k)
    if v == '' then iterate
    if Tv_Tag(v) \== 'i' then return 0
    n = Tv_Payload(v)
    if \datatype(n, 'W') then return 0
    if n < 0 | n >= 18446744073709551616 then return 0
  end
  return 1

/* §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
 * `created_at`. Rule 3: a conversion that is not representable is treated as ABSENT ('')
 * exactly as a null term is -- it MUST NOT wrap and MUST NOT saturate to a representable
 * maximum, since saturation manufactures expires_at == 2^64-1, a finite bound no reader
 * can distinguish from a deliberate one. REXX decimals do not wrap, so this is a
 * deliberate range check.
 *
 * ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
 * yielding `created_at` (expire immediately). The absent field is the only "no bound"
 * spelling, and falling out of the arithmetic is what keeps the two from collapsing. */
Cap_AddTtl: procedure expose EC.
  parse arg created_at, ttl
  numeric digits 40
  if \datatype(ttl, 'W') then return ''
  if ttl < 0 then return ''
  sum = created_at + ttl
  if sum >= 18446744073709551616 then return ''
  return sum

Cap_NowMs: procedure expose EC.
  return Crypto_NowMs()

/* ── string prefix / suffix ── */
_sw: procedure                                  /* starts-with */
  parse arg s, p
  return (length(s) >= length(p) & substr(s, 1, length(p)) == p)
_ew: procedure                                  /* ends-with */
  parse arg s, p
  if length(p) == 0 then return 1
  return (length(s) >= length(p) & right(s, length(p)) == p)

/* ── scope / grant pack + accessors ── */
Scope_Make: procedure
  parse arg incl, excl
  return d2c(length(incl), 4) || incl || excl
Scope_Incl: procedure
  parse arg sc
  numeric digits 40
  il = c2d(substr(sc, 1, 4))
  return substr(sc, 5, il)
Scope_Excl: procedure
  parse arg sc
  numeric digits 40
  il = c2d(substr(sc, 1, 4))
  return substr(sc, 5 + il)

Grant_Make: procedure
  parse arg gh, gr, go, gp
  a = d2c(length(gh), 4) || gh || d2c(length(gr), 4) || gr
  b = d2c(length(go), 4) || go || d2c(length(gp), 4) || gp
  return a || b
_g_field: procedure                             /* the i-th (1..4) length-prefixed field */
  parse arg g, idx
  numeric digits 40
  p = 1
  do k = 1 to idx
    fl = c2d(substr(g, p, 4))
    if k == idx then return substr(g, p + 4, fl)
    p = p + 4 + fl
  end
  return ''
Grant_Handlers: procedure
  parse arg g
  return _g_field(g, 1)
Grant_Resources: procedure
  parse arg g
  return _g_field(g, 2)
Grant_Operations: procedure
  parse arg g
  return _g_field(g, 3)
Grant_Peers: procedure
  parse arg g
  return _g_field(g, 4)

Cap_ParseScope: procedure expose EC.
  parse arg mtv
  if mtv == '' then return Scope_Make('', '')
  return Scope_Make(Ecf_TextList(mtv, 'include'), Ecf_TextList(mtv, 'exclude'))

Cap_ParseGrant: procedure expose EC.
  parse arg mtv
  peers = ''
  if mtv \== '' & Ecf_Get(mtv, 'peers') \== '' then peers = Cap_ParseScope(Ecf_MapField(mtv, 'peers'))
  sh = Cap_ParseScope(Ecf_MapField(mtv, 'handlers'))
  sr = Cap_ParseScope(Ecf_MapField(mtv, 'resources'))
  so = Cap_ParseScope(Ecf_MapField(mtv, 'operations'))
  return Grant_Make(sh, sr, so, peers)

/* the packed list of grant structs of a token entity. */
Cap_GrantsOfToken: procedure expose EC.
  parse arg token
  gl = Ecf_MapList(Ent_DataMap(token), 'grants')
  out = ''
  n = Lst_Count(gl)
  do i = 1 to n
    out = Lst_Add(out, Cap_ParseGrant(Lst_Item(gl, i)))
  end
  return out

/* build a grant map (handlers/resources/operations [+ peers]) — the §4.4 helper.
 * peers == '' -> OMIT the peers dimension; a non-empty packed list -> explicit scope. */
Cap_Grant: procedure expose EC.
  parse arg handlers, resources, operations, peers
  m = Ecf_Map('handlers', Ecf_Scope(handlers), 'resources', Ecf_Scope(resources))
  m = Ecf_MapPut(m, 'operations', Ecf_Scope(operations))
  if peers \== '' then m = Ecf_MapPut(m, 'peers', Ecf_Scope(peers))
  return m

/* ── §5.4 pattern matching ── */
Cap_NormalizeUri: procedure
  parse arg uri
  if _sw(uri, 'entity://') then return '/' || substr(uri, 10)
  return uri

/* may set EC.!EXC on a reserved/ambiguous path (mapped to 400 at the top). */
Cap_Canonicalize: procedure expose EC.
  parse arg local_peer, path
  if _sw(path, './') | _sw(path, '../') then do; call Throw 'reserved_relative', 'reserved directory-relative path'; return path; end
  if _sw(path, '*/') then do; call Throw 'ambiguous_wildcard', 'ambiguous bare peer wildcard'; return path; end
  if _sw(path, '/') then return path
  return '/' || local_peer || '/' || path

Cap_MatchesPattern: procedure expose EC.
  parse arg path, pattern
  if pattern == '*' then return 1
  if _sw(pattern, '/*/') then do
    remainder = substr(pattern, 4)
    if path == '' then return 0
    i = pos('/', path, 2)
    if i == 0 then return 0
    return Cap_MatchesPattern(substr(path, i + 1), remainder)
  end
  if length(pattern) >= 2 & _ew(pattern, '/*') then return _sw(path, substr(pattern, 1, length(pattern) - 1))
  return (path == pattern)

/* is canonicalized value `cv` covered by any pattern in packed list `pats` (frame)? */
_covered: procedure expose EC.
  parse arg frame, pats, cv
  n = Lst_Count(pats)
  do i = 1 to n
    if Cap_MatchesPattern(cv, Cap_Canonicalize(frame, Lst_Item(pats, i))) then return 1
  end
  return 0

/* §5.2 id-scope match (0.8.1, F40) -- operations and peers. Literal comparison with
   exactly two wildcard forms: bare '*' and a trailing slash-star segment-prefix. None
   of the §5.4 path transforms apply, so a pattern carrying path syntax is matched as a
   literal string: a non-match, never a fault. */
Cap_MatchesIdPattern: procedure expose EC.
  parse arg value, pattern
  if pattern == '*' then return 1
  plen = length(pattern)
  if plen >= 2 & right(pattern, 2) == '/*' then do
    prefix = left(pattern, plen - 1)
    return (left(value, plen - 1) == prefix)
  end
  return (value == pattern)

/* is `value` covered by any id-scope pattern in packed list `pats`? (no canonicalize) */
_covered_id: procedure expose EC.
  parse arg pats, value
  n = Lst_Count(pats)
  do i = 1 to n
    if Cap_MatchesIdPattern(value, Lst_Item(pats, i)) then return 1
  end
  return 0

/* §5.2 typed scope match. `kind` is 'id' (operations, peers) or 'path' (handlers,
   resources) and is given at every call site -- there is no default, so a new one
   cannot inherit the wrong matcher silently, which is exactly the F40 defect. */
Cap_MatchesScope: procedure expose EC.
  parse arg local_peer, value, s, kind
  if kind == 'id' then do
    if \_covered_id(Scope_Incl(s), value) then return 0
    return \_covered_id(Scope_Excl(s), value)
  end
  cv = Cap_Canonicalize(local_peer, value)
  if \_covered(local_peer, Scope_Incl(s), cv) then return 0
  return \_covered(local_peer, Scope_Excl(s), cv)

/* ── §5.2 check-permission ── */
Cap_FirstSegment: procedure
  parse arg uri
  if _sw(uri, '/') then u = substr(uri, 2)
  else u = uri
  i = pos('/', u)
  if i > 0 then return substr(u, 1, i - 1)
  return u

Cap_IsPeerId: procedure
  parse arg seg
  BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  if length(seg) < 46 then return 0
  do i = 1 to length(seg)
    if pos(substr(seg, i, 1), BASE58) == 0 then return 0
  end
  return 1

Cap_ExtractPeer: procedure expose EC.
  parse arg local_peer, uri
  first = Cap_FirstSegment(Cap_NormalizeUri(uri))
  if Cap_IsPeerId(first) then return first
  return local_peer

Cap_CheckResourceScope: procedure expose EC.
  parse arg local_peer, granter_peer, resource, s
  targets = Ecf_TextList(resource, 'targets')
  caller_excl = Ecf_TextList(resource, 'exclude')
  if Lst_Count(targets) == 0 then return 0
  do i = 1 to Lst_Count(targets)
    ct = Cap_Canonicalize(local_peer, Lst_Item(targets, i))
    if Lst_Count(caller_excl) > 0 & _covered(local_peer, caller_excl, ct) then iterate
    if \_covered(granter_peer, Scope_Incl(s), ct) then return 0
    if _covered(granter_peer, Scope_Excl(s), ct) then return 0
  end
  return 1

/* §PR-8: the granter's peer_id frames a cap's resource patterns. */
Cap_ResolveGranterPeerId: procedure expose EC.
  parse arg included, store_h, cap
  gh = Ent_Bytes(cap, 'granter')
  if gh == '' then return ''
  g = Cap_Resolve(included, store_h, gh)
  if g == '' then return ''
  pk = Ent_Bytes(g, 'public_key')
  if pk == '' then return ''
  return Id_PeerIdOfPubkey(pk)

/* gate the wire request at the dispatch authorization boundary -> ALLOW / DENY. */
Cap_CheckPermission: procedure expose EC.
  parse arg local_peer, granter_peer, exec, token, handler_pattern
  operation = Ent_Text(exec, 'operation')
  uri = Ent_Text(exec, 'uri')
  target_peer = Cap_ExtractPeer(local_peer, uri)
  resource = Ent_MapField(exec, 'resource')
  grants = Cap_GrantsOfToken(token)
  do i = 1 to Lst_Count(grants)
    g = Lst_Item(grants, i)
    ok = (Cap_MatchesScope(local_peer, operation, Grant_Operations(g), 'id') & ,
          Cap_MatchesScope(local_peer, handler_pattern, Grant_Handlers(g), 'path'))
    if ok then do
      peers = Grant_Peers(g)
      if peers == '' then peers = Scope_Make(Lst_Add('', local_peer), '')
      ok = Cap_MatchesScope(local_peer, target_peer, peers, 'id')
    end
    if ok & resource \== '' then ok = Cap_CheckResourceScope(local_peer, granter_peer, resource, Grant_Resources(g))
    if ok then return 'ALLOW'
  end
  return 'DENY'

/* ── §5.5 chain verification + attenuation ── */
Cap_FindSignature: procedure expose EC.
  parse arg target, included
  n = Lst_Count(included)
  do i = 1 to n
    e = Lst_Item(included, i)
    if Ent_Type(e) == 'system/signature' & Ent_Bytes(e, 'target') == target & target \== '' then return e
  end
  return ''

_signatures_targeting: procedure expose EC.
  parse arg target, included
  out = ''
  n = Lst_Count(included)
  do i = 1 to n
    e = Lst_Item(included, i)
    if Ent_Type(e) == 'system/signature' & Ent_Bytes(e, 'target') == target & target \== '' then out = Lst_Add(out, e)
  end
  return out

Cap_Resolve: procedure expose EC.
  parse arg included, store_h, h
  n = Lst_Count(included)
  do i = 1 to n
    e = Lst_Item(included, i)
    if Ent_Hash(e) == h then return e
  end
  return Store_GetByHash(store_h, h)

/* ── §3.6 M3 multi-signature granter ── */
Cap_IsMultisig: procedure expose EC.
  parse arg cap
  g = Ent_Field(cap, 'granter')
  return (g \== '' & Tv_Tag(g) == 'm')

/* parse the granter union -> "threshold" with signers left in the EC.!MG_SIGNERS
 * packed list (exposed); '' threshold if single-sig. */
Cap_MultiGranterOf: procedure expose EC.
  parse arg cap
  m = Ent_Field(cap, 'granter')
  if m == '' then do; EC.!MG_SIGNERS = ''; return ''; end
  if Tv_Tag(m) \== 'm' then do; EC.!MG_SIGNERS = ''; return ''; end
  signers = ''
  arr = Ecf_Get(m, 'signers')
  if arr \== '' & Tv_Tag(arr) == 'a' then do
    do i = 1 to Ecf_ArrCount(arr)
      it = Ecf_ArrItem(arr, i)
      if Tv_Tag(it) == 'b' then signers = Lst_Add(signers, Tv_Payload(it))
    end
  end
  EC.!MG_SIGNERS = signers
  th = Ecf_Uint(m, 'threshold')
  if th == '' then return 0
  return th

_has_dup_signers: procedure expose EC.
  parse arg signers
  n = Lst_Count(signers)
  do i = 1 to n
    do j = i + 1 to n
      if Lst_Item(signers, i) == Lst_Item(signers, j) then return 1
    end
  end
  return 0

_peer_id_of_signer: procedure expose EC.
  parse arg included, store_h, signer_hash
  p = Cap_Resolve(included, store_h, signer_hash)
  if p == '' then return ''
  pk = Ent_Bytes(p, 'public_key')
  if pk == '' then return ''
  return Id_PeerIdOfPubkey(pk)

/* validate a multi-sig root capability (§3.6 M3 / §5.5 M4·M6) -> 1 (ALLOW) / 0.
 * signers arrive in the packed list `signers`; threshold in `threshold`. */
_verify_multisig_root: procedure expose EC.
  parse arg local_peer, included, store_h, cap, signers, threshold
  n = Lst_Count(signers)
  if Ent_Bytes(cap, 'parent') \== '' then return 0
  if n < 2 then return 0
  if threshold < 2 | threshold > n then return 0
  if _has_dup_signers(signers) then return 0
  local_in = 0
  do i = 1 to n
    if _peer_id_of_signer(included, store_h, Lst_Item(signers, i)) == local_peer then do; local_in = 1; leave; end
  end
  if \local_in then return 0
  now = Cap_NowMs()
  nb = Ent_Uint(cap, 'not_before')
  if nb \== '' & now < nb then return 0
  ex = Ent_Uint(cap, 'expires_at')
  if ex \== '' & ex < now then return 0
  grantee = Ent_Bytes(cap, 'grantee')
  if grantee == '' | Cap_Resolve(included, store_h, grantee) == '' then return 0
  /* §5.5 M4 k-of-n: >= threshold DISTINCT quorum members validly signed the cap hash. */
  sigs = _signatures_targeting(Ent_Hash(cap), included)
  valid = ''
  do i = 1 to n
    signer_hash = Lst_Item(signers, i)
    if _lst_has(valid, signer_hash) then iterate
    signer_peer = Cap_Resolve(included, store_h, signer_hash)
    if signer_peer == '' then iterate
    do j = 1 to Lst_Count(sigs)
      sgn = Lst_Item(sigs, j)
      if Ent_Bytes(sgn, 'signer') == signer_hash & Id_VerifySignature(sgn, signer_peer) then do
        valid = Lst_Add(valid, signer_hash); leave
      end
    end
  end
  return (Lst_Count(valid) >= threshold)

_lst_has: procedure
  parse arg lst, item
  n = Lst_Count(lst)
  do i = 1 to n
    if Lst_Item(lst, i) == item then return 1
  end
  return 0

/* §PR-8 per-link frame = the cap's granter peer_id (root/no-granter -> local; single
 * sig unresolvable -> ''). */
_link_granter_peer: procedure expose EC.
  parse arg included, store_h, local_peer, cap
  gh = Ent_Bytes(cap, 'granter')
  if gh == '' then return local_peer
  g = Cap_Resolve(included, store_h, gh)
  if g == '' then return ''
  pk = Ent_Bytes(g, 'public_key')
  if pk == '' then return ''
  return Id_PeerIdOfPubkey(pk)

_scope_subset: procedure expose EC.
  parse arg child_peer, parent_peer, child, parent
  ci = Scope_Incl(child)
  do i = 1 to Lst_Count(ci)
    cc = Cap_Canonicalize(child_peer, Lst_Item(ci, i))
    covered = 0
    pin = Scope_Incl(parent)
    do j = 1 to Lst_Count(pin)
      if Cap_MatchesPattern(cc, Cap_Canonicalize(parent_peer, Lst_Item(pin, j))) then do; covered = 1; leave; end
    end
    if \covered then return 0
  end
  pex = Scope_Excl(parent)
  do i = 1 to Lst_Count(pex)
    cpe = Cap_Canonicalize(parent_peer, Lst_Item(pex, i))
    covered = 0
    cex = Scope_Excl(child)
    do j = 1 to Lst_Count(cex)
      if Cap_MatchesPattern(cpe, Cap_Canonicalize(child_peer, Lst_Item(cex, j))) then do; covered = 1; leave; end
    end
    if \covered then return 0
  end
  return 1

Cap_GrantSubset: procedure expose EC.
  parse arg local_peer, child_peer, parent_peer, child, parent
  if \_scope_subset(local_peer, local_peer, Grant_Handlers(child), Grant_Handlers(parent)) then return 0
  if \_scope_subset(local_peer, local_peer, Grant_Operations(child), Grant_Operations(parent)) then return 0
  if \_scope_subset(child_peer, parent_peer, Grant_Resources(child), Grant_Resources(parent)) then return 0
  cp = Grant_Peers(child); if cp == '' then cp = Scope_Make(Lst_Add('', local_peer), '')
  pp = Grant_Peers(parent); if pp == '' then pp = Scope_Make(Lst_Add('', local_peer), '')
  return _scope_subset(local_peer, local_peer, cp, pp)

_is_attenuated: procedure expose EC.
  parse arg local_peer, child_peer, parent_peer, child, parent
  cg = Cap_GrantsOfToken(child)
  pg = Cap_GrantsOfToken(parent)
  do i = 1 to Lst_Count(cg)
    c = Lst_Item(cg, i)
    ok = 0
    do j = 1 to Lst_Count(pg)
      if Cap_GrantSubset(local_peer, child_peer, parent_peer, c, Lst_Item(pg, j)) then do; ok = 1; leave; end
    end
    if \ok then return 0
  end
  pe = Ent_Uint(parent, 'expires_at')
  ce = Ent_Uint(child, 'expires_at')
  if pe \== '' & ce == '' then return 0
  if pe \== '' then return (ce <= pe)
  return 1

_check_delegation_caveats: procedure expose EC.
  parse arg parent, child, depth
  caveats = Ent_MapField(parent, 'delegation_caveats')
  if caveats == '' then return 1
  if Ecf_BoolIs(caveats, 'no_delegation') then return 0
  depth_ok = 1
  mdd = Ecf_Uint(caveats, 'max_delegation_depth')
  if mdd \== '' then depth_ok = (depth < mdd)
  ttl_ok = 1
  maxttl = Ecf_Uint(caveats, 'max_delegation_ttl')
  if maxttl \== '' then do
    ex = Ent_Uint(child, 'expires_at')
    cr = Ent_Uint(child, 'created_at')
    if ex \== '' & cr \== '' then ttl_ok = ((ex - cr) <= maxttl)
    else if ex \== '' then ttl_ok = 1
    else ttl_ok = 0
  end
  return (depth_ok & ttl_ok)

/* collect the parent chain -> the packed list left in EC.!CHAIN (exposed); returns 1
 * ok / 0. */
_collect_chain: procedure expose EC.
  parse arg cap, included, store_h
  acc = ''; current = cap; depth = 0
  do forever
    if depth > EC.!MAX_CHAIN_DEPTH then do; EC.!CHAIN = ''; return 0; end
    acc = Lst_Add(acc, current)
    ph = Ent_Bytes(current, 'parent')
    if ph == '' then do; EC.!CHAIN = acc; return 1; end
    parent = Cap_Resolve(included, store_h, ph)
    if parent == '' then do; EC.!CHAIN = ''; return 0; end
    current = parent; depth = depth + 1
  end

/* §4.10(b) structural pre-check: 1 iff the chain exceeds MAX depth. Walks parent
 * pointers WITHOUT verifying sigs — an unreachable parent is NOT a depth problem. */
Cap_ChainExceedsDepth: procedure expose EC.
  parse arg store_h, cap, included
  current = cap; depth = 0
  do forever
    if depth > EC.!MAX_CHAIN_DEPTH then return 1
    ph = Ent_Bytes(current, 'parent')
    if ph == '' then return 0
    parent = Cap_Resolve(included, store_h, ph)
    if parent == '' then return 0
    current = parent; depth = depth + 1
  end

/* §5.5 chain verification -> ALLOW / DENY (may set EC.!EXC UNRESOLVABLE_GRANTEE -> 401). */
Cap_VerifyChain: procedure expose EC.
  parse arg local_peer, store_h, capability, included
  if \_collect_chain(capability, included, store_h) then return 'DENY'
  chain = EC.!CHAIN
  nn = Lst_Count(chain)
  root = Lst_Item(chain, nn)
  root_th = Cap_MultiGranterOf(root)
  if root_th \== '' then root_ok = _verify_multisig_root(local_peer, included, store_h, root, EC.!MG_SIGNERS, root_th)
  else do
    rgh = Ent_Bytes(root, 'granter')
    g = ''
    if rgh \== '' then g = Cap_Resolve(included, store_h, rgh)
    pk = ''
    if g \== '' then pk = Ent_Bytes(g, 'public_key')
    root_ok = (pk \== '' & Id_PeerIdOfPubkey(pk) == local_peer)
  end
  if \root_ok then return 'DENY'

  good = 1
  do i = 1 to nn
    if \good then leave
    current = Lst_Item(chain, i)
    if Cap_IsMultisig(current) then do
      if i \== nn then good = 0
      iterate
    end
    gh = Ent_Bytes(current, 'granter')
    if gh \== '' then do
      sgn = Cap_FindSignature(Ent_Hash(current), included)
      granter = Cap_Resolve(included, store_h, gh)
      if sgn \== '' & granter \== '' then do
        signer = Ent_Bytes(sgn, 'signer')
        if \(signer \== '' & signer == gh & Id_VerifySignature(sgn, granter)) then good = 0
      end
      else good = 0
    end
    else good = 0
    geh = Ent_Bytes(current, 'grantee')
    if geh \== '' then do
      if Cap_Resolve(included, store_h, geh) == '' then do; call Throw 'UNRESOLVABLE_GRANTEE', 'grantee unresolvable'; return 'DENY'; end
    end
    else do; call Throw 'UNRESOLVABLE_GRANTEE', 'grantee absent'; return 'DENY'; end
    /* CAP-6a FIRST (§6.2): a present-but-unrepresentable expires_at / not_before /
     * created_at is MALFORMED and must be refused outright. This has to run BEFORE the
     * two range checks below, because those are what the ambiguity defeats -- see
     * Cap_TemporalFieldsRepresentable for the mechanism. */
    if \Cap_TemporalFieldsRepresentable(current) then good = 0
    now = Cap_NowMs()
    nb = Ent_Uint(current, 'not_before')
    if nb \== '' & now < nb then good = 0
    ex = Ent_Uint(current, 'expires_at')
    if ex \== '' & ex < now then good = 0
    if i < nn then do
      parent = Lst_Item(chain, i + 1)
      child_peer = _link_granter_peer(included, store_h, local_peer, current)
      parent_peer = _link_granter_peer(included, store_h, local_peer, parent)
      if child_peer == '' | parent_peer == '' then good = 0
      else do
        pg = Ent_Bytes(parent, 'grantee')
        cg = Ent_Bytes(current, 'granter')
        link_ok = (pg \== '' & cg \== '' & pg == cg)
        if link_ok then link_ok = _is_attenuated(local_peer, child_peer, parent_peer, current, parent)
        if link_ok then link_ok = _check_delegation_caveats(parent, current, i)
        if \link_ok then good = 0
      end
    end
  end
  if good then return 'ALLOW'
  return 'DENY'

_revoke_marker: procedure expose EC.
  parse arg local_peer, store_h, h
  return Store_GetAt(store_h, '/' || local_peer || '/system/capability/revocations/' || Hexlc(h))

Cap_IsRevoked: procedure expose EC.
  parse arg local_peer, store_h, capability, included
  if _collect_chain(capability, included, store_h) then root_hash = Ent_Hash(Lst_Item(EC.!CHAIN, Lst_Count(EC.!CHAIN)))
  else root_hash = Ent_Hash(capability)
  if _revoke_marker(local_peer, store_h, Ent_Hash(capability)) \== '' then return 1
  return (_revoke_marker(local_peer, store_h, root_hash) \== '')

/* ── §5.2 verify-request (3-way verdict) -> ALLOW / AUTHN_FAIL / AUTHZ_DENY / CHAIN_TOO_DEEP ── */
Cap_VerifyRequest: procedure expose EC.
  parse arg local_peer, store_h, env
  exec = Env_Root(env)
  included = Env_Included(env)
  sgn = Cap_FindSignature(Ent_Hash(exec), included)
  if sgn == '' then return 'AUTHN_FAIL'
  author_h = Ent_Bytes(exec, 'author')
  signer = Ent_Bytes(sgn, 'signer')
  if \(signer \== '' & author_h \== '' & signer == author_h) then return 'AUTHN_FAIL'
  author = Env_IncludedGet(env, author_h)
  if author == '' then return 'AUTHN_FAIL'
  if \Id_VerifySignature(sgn, author) then return 'AUTHN_FAIL'
  ch = Ent_Bytes(exec, 'capability')
  cap = ''
  if ch \== '' then cap = Env_IncludedGet(env, ch)
  if cap == '' then return 'AUTHZ_DENY'
  if Cap_ChainExceedsDepth(store_h, cap, included) then return 'CHAIN_TOO_DEEP'
  if Cap_VerifyChain(local_peer, store_h, cap, included) == 'DENY' then return 'AUTHZ_DENY'
  grantee = Ent_Bytes(cap, 'grantee')
  if \(grantee \== '' & grantee == author_h) then return 'AUTHZ_DENY'
  if Cap_IsRevoked(local_peer, store_h, cap, included) then return 'AUTHZ_DENY'
  return 'ALLOW'
