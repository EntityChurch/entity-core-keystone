/* entity-core-protocol-rexx — internal tagged-value (TV) navigation + builders.
 * The TV rep is the self-delimiting byte string produced by the codec (see cbor.rex).
 * These helpers walk it (skip a node, look up a map field, unwrap a scalar) and build
 * leaf nodes — the value-model layer the harness and the peer (S3) build on.
 */

/* Tv_NodeLen: the byte length of the TV node starting at position pos in tv. */
Tv_NodeLen: procedure
  parse arg tv, pos
  numeric digits 200
  tag = substr(tv, pos, 1)
  if tag == 'R' | tag == 'F' | tag == 'N' | tag == 'U' then return 1
  if tag == 'i' | tag == 'b' | tag == 't' | tag == 'f' | tag == 's' then do
    n = c2d(substr(tv, pos + 1, 4))
    return 5 + n
  end
  if tag == 'a' then do
    n = c2d(substr(tv, pos + 1, 4))
    tot = 5; p = pos + 5
    do i = 1 to n; l = Tv_NodeLen(tv, p); tot = tot + l; p = p + l; end
    return tot
  end
  if tag == 'm' then do
    n = c2d(substr(tv, pos + 1, 4))
    tot = 5; p = pos + 5
    do i = 1 to 2 * n; l = Tv_NodeLen(tv, p); tot = tot + l; p = p + l; end
    return tot
  end
  return 1

/* Tv_MapGet: value TV bound to TEXT key `key` in map TV `tv`, or '' (absent). */
Tv_MapGet: procedure
  parse arg tv, key
  numeric digits 200
  if substr(tv, 1, 1) \== 'm' then return ''
  n = c2d(substr(tv, 2, 4))
  p = 6
  do i = 1 to n
    kl = Tv_NodeLen(tv, p)
    vpos = p + kl
    vl = Tv_NodeLen(tv, vpos)
    if substr(tv, p, 1) == 't' then do
      klen = c2d(substr(tv, p + 1, 4))
      if substr(tv, p + 5, klen) == key then return substr(tv, vpos, vl)
    end
    p = vpos + vl
  end
  return ''

/* Tv_Has: is TEXT key `key` present in map TV `tv`? */
Tv_Has: procedure
  parse arg tv, key
  numeric digits 200
  if substr(tv, 1, 1) \== 'm' then return 0
  n = c2d(substr(tv, 2, 4))
  p = 6
  do i = 1 to n
    kl = Tv_NodeLen(tv, p)
    if substr(tv, p, 1) == 't' then do
      klen = c2d(substr(tv, p + 1, 4))
      if substr(tv, p + 5, klen) == key then return 1
    end
    vpos = p + kl
    p = vpos + Tv_NodeLen(tv, vpos)
  end
  return 0

/* Tv_Tag: the tag char of the whole TV node. */
Tv_Tag: procedure
  parse arg tv
  return substr(tv, 1, 1)

/* scalar unwraps (tv is the whole leaf node). */
Tv_Payload: procedure
  parse arg tv
  numeric digits 200
  return substr(tv, 6, c2d(substr(tv, 2, 4)))
Tv_Int: procedure
  parse arg tv
  return Tv_Payload(tv)
Tv_Text: procedure
  parse arg tv
  return Tv_Payload(tv)
Tv_Bytes: procedure
  parse arg tv
  return Tv_Payload(tv)

/* leaf builders. */
Tv_MkInt: procedure
  parse arg n
  return 'i' || d2c(length(n), 4) || n
Tv_MkBytes: procedure
  parse arg b
  return 'b' || d2c(length(b), 4) || b
Tv_MkText: procedure
  parse arg s
  return 't' || d2c(length(s), 4) || s
