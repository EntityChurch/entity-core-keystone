/* entity-core-protocol-rexx — the protocol envelope (§3.1): a `root` entity plus an
 * `included` list of protocol entities keyed by content_hash. `included` is the §5.8
 * authority carrier (capabilities, peer identities, signatures travel here).
 *
 * Held as a self-delimiting byte string: len(root,4) || rootEntity || includedList,
 * where includedList is a packed list (col.rex) of entity strings (the content_hash
 * is INSIDE each entity, so no separate key is stored — lookup scans by Ent_Hash).
 * On the wire (§3.1) `included` is a content_hash -> entity MAP with BYTE-string keys
 * (the major-2 seam, NOT text keys); duplicate hashes collapse, so we dedup preserving
 * first-seen order before encoding (the canonical codec rejects a duplicate map key).
 */

/* Env_Make: an envelope from a root entity + a packed list of included entities. */
Env_Make: procedure
  parse arg root, included
  return d2c(length(root), 4) || root || included

Env_Root: procedure
  parse arg env
  numeric digits 40
  rl = c2d(substr(env, 1, 4))
  return substr(env, 5, rl)

/* the included packed list. */
Env_Included: procedure
  parse arg env
  numeric digits 40
  rl = c2d(substr(env, 1, 4))
  return substr(env, 5 + rl)

/* find an included entity by content_hash octets, or ''. */
Env_IncludedGet: procedure expose EC.
  parse arg env, h
  inc = Env_Included(env)
  n = Lst_Count(inc)
  do i = 1 to n
    e = Lst_Item(inc, i)
    if Ent_Hash(e) == h then return e
  end
  return ''

/* the wire envelope map {root, included}. Dedup `included` by content_hash,
 * first-seen order (a repeated entity — e.g. granter == local identity — would emit
 * a duplicate byte key the codec rejects). */
Env_ToCbor: procedure expose EC.
  parse arg env
  numeric digits 40
  inc = Env_Included(env)
  n = Lst_Count(inc)
  seen = ' '
  pairs = ''
  cnt = 0
  do i = 1 to n
    e = Lst_Item(inc, i)
    hex = c2x(Ent_Hash(e))
    if pos(' ' || hex || ' ', seen) > 0 then iterate
    seen = seen || hex || ' '
    pairs = pairs || Tv_MkBytes(Ent_Hash(e)) || Ent_ToCbor(e)
    cnt = cnt + 1
  end
  incmap = 'm' || d2c(cnt, 4) || pairs
  return Ecf_Map('root', Ent_ToCbor(Env_Root(env)), 'included', incmap)

/* parse a wire envelope map. Verifies each included content_hash == its map key
 * (§3.1) and dedups first-seen. On a bad shape, sets EC.!EXC and returns ''. */
Env_OfCbor: procedure expose EC.
  parse arg mtv
  numeric digits 40
  rootv = Ecf_MapField(mtv, 'root')
  if rootv == '' then do; call Throw 'missing_root', 'envelope: missing root'; return ''; end
  root = Ent_OfCbor(rootv)
  if EC.!EXC \== '' then return ''
  inc = ''
  incm = Ecf_MapField(mtv, 'included')
  if incm \== '' then do
    n = Ecf_MapCount(incm)
    seen = ' '
    do i = 1 to n
      ktv = Ecf_MapKey(incm, i)
      vtv = Ecf_MapVal(incm, i)
      if Tv_Tag(ktv) \== 'b' then do; call Throw 'included_key_not_bytes', 'envelope: included key not bytes'; return ''; end
      if Tv_Tag(vtv) \== 'm' then do; call Throw 'included_value_not_map', 'envelope: included value not a map'; return ''; end
      kb = Tv_Payload(ktv)
      ent = Ent_OfCbor(vtv)
      if EC.!EXC \== '' then return ''
      if kb \== Ent_Hash(ent) then do; call Throw 'included_key_mismatch', 'included key != content_hash'; return ''; end
      hex = c2x(kb)
      if pos(' ' || hex || ' ', seen) > 0 then iterate
      seen = seen || hex || ' '
      inc = Lst_Add(inc, ent)
    end
  end
  return Env_Make(root, inc)
