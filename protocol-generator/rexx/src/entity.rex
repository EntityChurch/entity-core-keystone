/* entity-core-protocol-rexx — a materialized entity {type, data, content_hash}
 * (§1.1, §3.4) on top of the S2 codec value model.
 *
 * An entity has no record/object type in classic Rexx, and must pass by value through
 * the whole peer, so it is itself a self-delimiting byte STRING (the EIAS discipline,
 * same as the TV rep):
 *     'E' || len(type,4) || type || len(hash,4) || hash || dataTV
 * The leading 'E' + the fixed framing make it unambiguous, and the bare empty string
 * '' is the safe absent sentinel (a present entity is always >=1 byte, tag 'E').
 *
 * content_hash covers ONLY {type, data} (§1.1); the WIRE form (Ent_ToCbor) carries it
 * as a third field so entities are self-describing across serialization (§3.1) — the
 * hash is NEVER recomputed over a map that already contains content_hash.
 *
 * `data` is an ARBITRARY ECF value (§1.1 / A-JAVA-010): a map for every core-protocol
 * entity, a scalar for e.g. primitive/string. The field-read helpers take the map VIEW
 * (the empty map for scalar data) so reads never fault.
 */

/* Ent_Make: construct a materialized entity, computing the §9.1 content_hash. */
Ent_Make: procedure expose EC.
  parse arg type, data
  h = Hash_Content(type, data)
  return 'E' || d2c(length(type), 4) || type || d2c(length(h), 4) || h || data

Ent_Type: procedure
  parse arg e
  numeric digits 40
  tl = c2d(substr(e, 2, 4))
  return substr(e, 6, tl)

Ent_Hash: procedure
  parse arg e
  numeric digits 40
  tl = c2d(substr(e, 2, 4))
  hp = 6 + tl
  hl = c2d(substr(e, hp, 4))
  return substr(e, hp + 4, hl)

/* the raw `data` TV. */
Ent_Data: procedure
  parse arg e
  numeric digits 40
  tl = c2d(substr(e, 2, 4))
  hp = 6 + tl
  hl = c2d(substr(e, hp, 4))
  return substr(e, hp + 4 + hl)

/* the `data` as a MAP view: the map TV when data IS a map, else the empty map. */
Ent_DataMap: procedure
  parse arg e
  d = Ent_Data(e)
  if Tv_Tag(d) == 'm' then return d
  return 'm' || d2c(0, 4)

/* the wire entity map {type, data, content_hash}. */
Ent_ToCbor: procedure expose EC.
  parse arg e
  ch = Ecf_Bytes(Ent_Hash(e))
  return Ecf_Map('type', Ecf_Str(Ent_Type(e)), 'data', Ent_Data(e), 'content_hash', ch)

/* Ent_OfCbor: parse a wire entity map, recompute the hash from {type, data}, and
 * validate it against the carried content_hash (§1.8 fidelity — trust the recomputed
 * hash, not the wire bytes). On a bad shape / mismatch, set EC.!EXC and return ''. */
Ent_OfCbor: procedure expose EC.
  parse arg mtv
  type = Ecf_Text(mtv, 'type')
  if type == '' & \Ecf_Has(mtv, 'type') then do; call Throw 'missing_type', 'entity: missing/invalid type'; return ''; end
  if \Ecf_Has(mtv, 'data') then do; call Throw 'missing_data', 'entity: missing data'; return ''; end
  data = Ecf_Get(mtv, 'data')
  e = Ent_Make(type, data)
  carried = Ecf_GetBytes(mtv, 'content_hash')
  if carried \== '' & carried \== Ent_Hash(e) then do
    call Throw 'content_hash_mismatch', 'content_hash mismatch (§1.8 fidelity)'
    return ''
  end
  return e

/* ── field reads off the data map view ── */
Ent_Text: procedure expose EC.
  parse arg e, key
  return Ecf_Text(Ent_DataMap(e), key)
Ent_Bytes: procedure expose EC.
  parse arg e, key
  return Ecf_GetBytes(Ent_DataMap(e), key)
Ent_Uint: procedure expose EC.
  parse arg e, key
  return Ecf_Uint(Ent_DataMap(e), key)
Ent_Field: procedure expose EC.
  parse arg e, key
  return Ecf_Get(Ent_DataMap(e), key)
Ent_MapField: procedure expose EC.
  parse arg e, key
  return Ecf_MapField(Ent_DataMap(e), key)

/* decode a nested entity carried at `key` (a wire entity map), or '' if absent. */
Ent_EntityField: procedure expose EC.
  parse arg e, key
  m = Ent_MapField(e, key)
  if m == '' then return ''
  return Ent_OfCbor(m)
