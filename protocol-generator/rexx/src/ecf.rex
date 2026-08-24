/* entity-core-protocol-rexx — peer-layer value helpers over the S2 codec value model.
 *
 * The codec (src/cbor.rex) speaks an internal self-delimiting tagged-value (TV) byte
 * string (see tv.rex): 'i'/'b'/'t'/'f' scalars, 'a' array, 'm' map, 'R'/'F'/'N'
 * simples. This module is the protocol-altitude analogue: map/array BUILDERS + typed
 * field READS, so the peer code reads as map builders and field accessors instead of
 * restating the TV layout at every call site (the Tcl ::ecf:: namespace, in Rexx idiom).
 *
 * == The absent sentinel (A-RX-007). The empty string is a legitimate wire value
 * (empty mt2/mt3 -> 'b'/'t' with len 0, which is a 5-byte non-empty TV). A field read
 * returns '' (the bare empty string) IFF the key is truly absent — a present value is
 * ALWAYS a >=1-byte TV. Callers that must tell present-empty-array from absent (the
 * §4.5 hello negotiation) use Ecf_Has.
 *
 * Map keys built here are always TEXT keys; the one byte-keyed map on the wire (the
 * envelope `included` content_hash -> entity map) is assembled directly in envelope.rex.
 * Canonical key ordering is NOT done here — the codec sorts on encode (§4.2.1), so the
 * internal map order is irrelevant.
 */

/* ── constructors ── */
Ecf_Str: procedure    /* text value (mt3) */
  parse arg s
  return Tv_MkText(s)
Ecf_Bytes: procedure  /* byte value (mt2) */
  parse arg b
  return Tv_MkBytes(b)
Ecf_Int: procedure    /* int value (mt0/1) */
  parse arg n
  return Tv_MkInt(n)
Ecf_Bool: procedure
  parse arg b
  if b == 0 | b == '' then return 'F'
  return 'R'
Ecf_Null: procedure
  return 'N'
Ecf_EmptyMap: procedure
  return 'm' || d2c(0, 4)

/* a float TV from an 8-byte f64 bit pattern (mt7). */
Ecf_Float: procedure
  parse arg f64
  return 'f' || d2c(8, 4) || f64

/* Ecf_Map: build a map TV from alternating (bare-text-key, value-TV) pairs. */
Ecf_Map: procedure
  numeric digits 40
  n = arg() % 2
  body = ''
  do i = 1 by 2 to arg() - 1
    j = i + 1
    body = body || Tv_MkText(arg(i)) || arg(j)
  end
  return 'm' || d2c(n, 4) || body

/* Ecf_MapPut: append (bare-text-key, value-TV) to a map TV -> a new map TV. Used to
 * build a map with OPTIONAL fields (the fixed-arity Ecf_Map cannot). */
Ecf_MapPut: procedure
  parse arg mtv, key, val
  numeric digits 40
  if mtv == '' then mtv = 'm' || d2c(0, 4)
  n = c2d(substr(mtv, 2, 4)) + 1
  return 'm' || d2c(n, 4) || substr(mtv, 6) || Tv_MkText(key) || val

/* Ecf_Array: an array TV (mt4) from a packed list (col.rex) of item TVs. */
Ecf_Array: procedure
  parse arg lst
  numeric digits 40
  n = Lst_Count(lst)
  body = ''
  do i = 1 to n
    body = body || Lst_Item(lst, i)
  end
  return 'a' || d2c(n, 4) || body

/* Ecf_TextArray: an array TV from a packed list of bare strings. */
Ecf_TextArray: procedure
  parse arg lst
  numeric digits 40
  n = Lst_Count(lst)
  body = ''
  do i = 1 to n
    body = body || Tv_MkText(Lst_Item(lst, i))
  end
  return 'a' || d2c(n, 4) || body

/* a §5.4 scope map {include: <text array>} from a packed list of pattern strings. */
Ecf_Scope: procedure
  parse arg lst
  return Ecf_Map('include', Ecf_TextArray(lst))

/* ── field reads (null-safe over a map TV) ── */

/* the value TV bound to TEXT key `key`, or '' (absent). Tv_MapGet does the walk. */
Ecf_Get: procedure
  parse arg mtv, key
  return Tv_MapGet(mtv, key)

Ecf_Has: procedure
  parse arg mtv, key
  return Tv_Has(mtv, key)

/* a TEXT field's string, or '' if absent / not text. */
Ecf_Text: procedure
  parse arg mtv, key
  v = Tv_MapGet(mtv, key)
  if v == '' then return ''
  if Tv_Tag(v) \== 't' then return ''
  return Tv_Payload(v)

/* a BYTE field's raw octets, or '' if absent / not bytes. NOTE the READER is
 * Ecf_GetBytes, distinct from the byte-value CONSTRUCTOR Ecf_Bytes(b) above — classic
 * Rexx binds a call to the FIRST label of a duplicated name, so the two MUST differ. */
Ecf_GetBytes: procedure
  parse arg mtv, key
  v = Tv_MapGet(mtv, key)
  if v == '' then return ''
  if Tv_Tag(v) \== 'b' then return ''
  return Tv_Payload(v)

/* an INTEGER field (decimal bignum — no fixed-width trap), or '' if absent/not int. */
Ecf_Uint: procedure
  parse arg mtv, key
  v = Tv_MapGet(mtv, key)
  if v == '' then return ''
  if Tv_Tag(v) \== 'i' then return ''
  return Tv_Payload(v)

/* is the value TV bound to `key` the boolean true? */
Ecf_BoolIs: procedure
  parse arg mtv, key
  v = Tv_MapGet(mtv, key)
  return (v == 'R')

/* the map-view value TV at `key` ('m' tag), or '' if absent / not a map. */
Ecf_MapField: procedure
  parse arg mtv, key
  v = Tv_MapGet(mtv, key)
  if v == '' then return ''
  if Tv_Tag(v) \== 'm' then return ''
  return v

/* the map view of a value TV: itself if a map, else ''. */
Ecf_AsMap: procedure
  parse arg v
  if v == '' then return ''
  if Tv_Tag(v) \== 'm' then return ''
  return v

/* ── array helpers ── */

/* count of items in an array TV, or 0. */
Ecf_ArrCount: procedure
  parse arg atv
  numeric digits 40
  if atv == '' then return 0
  if Tv_Tag(atv) \== 'a' then return 0
  return c2d(substr(atv, 2, 4))

/* the i-th item TV (1-indexed) of an array TV, or ''. */
Ecf_ArrItem: procedure
  parse arg atv, i
  numeric digits 200
  if Tv_Tag(atv) \== 'a' then return ''
  n = c2d(substr(atv, 2, 4))
  if i < 1 | i > n then return ''
  p = 6
  do k = 1 to n
    l = Tv_NodeLen(atv, p)
    if k == i then return substr(atv, p, l)
    p = p + l
  end
  return ''

/* the text items of an array FIELD as a packed list (col.rex), or '' if the field is
 * absent / not an array. An absent field and a present-empty array both yield the
 * empty packed list '' (Lst_Count 0) — callers that need present-vs-absent use
 * Ecf_Has (the §4.5 negotiation seam); every other caller treats them the same. */
Ecf_TextList: procedure
  parse arg mtv, key
  v = Tv_MapGet(mtv, key)
  if v == '' then return ''
  if Tv_Tag(v) \== 'a' then return ''
  n = Ecf_ArrCount(v)
  out = ''
  do i = 1 to n
    it = Ecf_ArrItem(v, i)
    if Tv_Tag(it) == 't' then out = Lst_Add(out, Tv_Payload(it))
  end
  return out

/* the map items of an array FIELD as a packed list of map TVs, or '' if absent. */
Ecf_MapList: procedure
  parse arg mtv, key
  v = Tv_MapGet(mtv, key)
  if v == '' then return ''
  if Tv_Tag(v) \== 'a' then return ''
  n = Ecf_ArrCount(v)
  out = ''
  do i = 1 to n
    it = Ecf_ArrItem(v, i)
    if Tv_Tag(it) == 'm' then out = Lst_Add(out, it)
  end
  return out

/* map entry iteration: count of (k,v) pairs. */
Ecf_MapCount: procedure
  parse arg mtv
  numeric digits 40
  if mtv == '' then return 0
  if Tv_Tag(mtv) \== 'm' then return 0
  return c2d(substr(mtv, 2, 4))

/* the i-th (1-indexed) key TV of a map, or ''. */
Ecf_MapKey: procedure
  parse arg mtv, i
  numeric digits 200
  n = Ecf_MapCount(mtv)
  if i < 1 | i > n then return ''
  p = 6
  do k = 1 to n
    kl = Tv_NodeLen(mtv, p)
    if k == i then return substr(mtv, p, kl)
    vpos = p + kl
    p = vpos + Tv_NodeLen(mtv, vpos)
  end
  return ''

/* the i-th (1-indexed) value TV of a map, or ''. */
Ecf_MapVal: procedure
  parse arg mtv, i
  numeric digits 200
  n = Ecf_MapCount(mtv)
  if i < 1 | i > n then return ''
  p = 6
  do k = 1 to n
    kl = Tv_NodeLen(mtv, p)
    vpos = p + kl
    vl = Tv_NodeLen(mtv, vpos)
    if k == i then return substr(mtv, vpos, vl)
    p = vpos + vl
  end
  return ''
