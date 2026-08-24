## Entity model + protocol envelope (V8 §1.1, §3.1, §3.4) lifted onto the S2
## `EcValue` codec. An `Entity` is the materialized `{type, data, content_hash}`
## form; an `Envelope` is `{root, included}` (§3.1).
##
## Idiom (profile [memory]): ARC/ORC value types with move semantics — `Entity`
## and `Envelope` are plain `object`s holding an `EcValue` ref tree, a `string`
## type name, and a 33-byte `seq[byte]` content hash; the GC reclaims the tree at
## scope exit, so there is no caller-frees seam (contrast the no-GC Zig peer).
##
## §5.2 validate-before-trust: a decoded wire entity is re-materialized through
## our own codec — the hash is RECOMPUTED from {type, data} and checked against
## the carried `content_hash` (§1.8 fidelity), never trusted from the wire bytes.
##
## SPDX-License-Identifier: Apache-2.0

import std/options
import ./ecf
import ./content_hash
import ./errors

type
  Entity* = object
    typ*: string           ## entity type (e.g. "system/protocol/execute")
    data*: EcValue         ## §1.1: an ARBITRARY ECF value (not necessarily a map)
    hash*: seq[byte]       ## content_hash: 33 bytes (format byte 0x00 ‖ SHA-256)

  Included* = tuple[key: seq[byte], entity: Entity]

  Envelope* = object
    root*: Entity
    included*: seq[Included]

  ModelError* = object of EcError
  BadEntity* = object of ModelError
  ContentHashMismatch* = object of ModelError
  IncludedKeyMismatch* = object of ModelError

# ── entity construction ────────────────────────────────────────────────────────

proc entityOfValue*(v: EcValue): Entity   ## forward decl (used by entityField)

proc makeEntity*(typ: string; data: EcValue): Entity =
  ## Materialize an entity, computing its content_hash under the ecfv1-sha256
  ## floor (format_code 0 → 33-byte hash).
  Entity(typ: typ, data: data, hash: contentHash(0'u64, typ, data))

# ── field accessors (data is normally a map) ───────────────────────────────────

proc mapGet*(v: EcValue; key: string): EcValue =
  ## Value of `key` in an ECF map, or nil if absent / not a map.
  if v == nil or v.kind != ekMap: return nil
  for p in v.pairs:
    if p.key != nil and p.key.kind == ekText and p.key.t == key:
      return p.val
  nil

proc field*(e: Entity; key: string): EcValue = mapGet(e.data, key)

proc textField*(e: Entity; key: string): Option[string] =
  let v = e.field(key)
  if v != nil and v.kind == ekText: some(v.t) else: none(string)

proc bytesField*(e: Entity; key: string): Option[seq[byte]] =
  let v = e.field(key)
  if v != nil and v.kind == ekBytes: some(v.b) else: none(seq[byte])

proc uintField*(e: Entity; key: string): Option[uint64] =
  let v = e.field(key)
  if v != nil and v.kind == ekUint: some(v.u) else: none(uint64)

proc boolField*(e: Entity; key: string): Option[bool] =
  let v = e.field(key)
  if v != nil and v.kind == ekBool: some(v.boolean) else: none(bool)

proc arrayField*(e: Entity; key: string): seq[EcValue] =
  ## The array at `key`, or an empty seq if absent / not an array.
  let v = e.field(key)
  if v != nil and v.kind == ekArray: v.arr else: @[]

proc entityField*(e: Entity; key: string): Option[Entity] =
  ## Parse a sub-entity carried as a map field (e.g. `params`, `result`).
  let v = e.field(key)
  if v == nil or v.kind != ekMap: return none(Entity)
  some(entityOfValue(v))

# ── §3.7 resource-target (system/protocol/resource-target) ─────────────────────

type ResourceTarget* = object
  targets*: seq[string]
  exclude*: seq[string]

proc textArray(v: EcValue): seq[string] =
  if v != nil and v.kind == ekArray:
    for it in v.arr:
      if it != nil and it.kind == ekText: result.add it.t

proc resourceTarget*(e: Entity): Option[ResourceTarget] =
  ## Parse the optional `resource` field of an EXECUTE (§3.7): {targets, exclude?}.
  let v = e.field("resource")
  if v == nil or v.kind != ekMap: return none(ResourceTarget)
  var rt = ResourceTarget(targets: textArray(mapGet(v, "targets")),
                          exclude: textArray(mapGet(v, "exclude")))
  some(rt)

# ── wire (Value) form ──────────────────────────────────────────────────────────

proc toValue*(e: Entity): EcValue =
  ## Self-describing wire form (§3.1): `{type, data, content_hash}`. The encoder
  ## sorts keys, so field order here is irrelevant to the wire bytes.
  mapV(@[
    EcPair(key: textV("type"), val: textV(e.typ)),
    EcPair(key: textV("data"), val: e.data),
    EcPair(key: textV("content_hash"), val: bytesV(e.hash)),
  ])

proc entityOfValue*(v: EcValue): Entity =
  ## Parse a wire entity, recompute the hash from {type,data}, and validate it
  ## against the carried `content_hash` (§1.8 / §5.2 validate-before-trust).
  if v == nil or v.kind != ekMap: raise newException(BadEntity, "entity not a map")
  let t = mapGet(v, "type")
  if t == nil or t.kind != ekText: raise newException(BadEntity, "entity has no text type")
  let d = mapGet(v, "data")
  if d == nil: raise newException(BadEntity, "entity has no data")
  result = makeEntity(t.t, d)
  let ch = mapGet(v, "content_hash")
  if ch != nil and ch.kind == ekBytes and ch.b != result.hash:
    raise newException(ContentHashMismatch, "content_hash != recomputed hash")

# ── envelope ───────────────────────────────────────────────────────────────────

proc includedGet*(env: Envelope; h: seq[byte]): Option[Entity] =
  for inc in env.included:
    if inc.key == h: return some(inc.entity)
  none(Entity)

proc envelopeToValue*(env: Envelope): EcValue =
  var incPairs: seq[EcPair]
  for inc in env.included:
    incPairs.add EcPair(key: bytesV(inc.key), val: inc.entity.toValue())
  mapV(@[
    EcPair(key: textV("root"), val: env.root.toValue()),
    EcPair(key: textV("included"), val: mapV(incPairs)),
  ])

proc encodeEnvelope*(env: Envelope): seq[byte] = encode(envelopeToValue(env))

proc envelopeOfValue*(v: EcValue): Envelope =
  ## Build an owned Envelope from a decoded value; each included key MUST equal
  ## its entity's recomputed content_hash (§3.1).
  let rootV = mapGet(v, "root")
  if rootV == nil: raise newException(BadEntity, "envelope has no root")
  result.root = entityOfValue(rootV)
  let incV = mapGet(v, "included")
  if incV != nil:
    if incV.kind != ekMap: raise newException(BadEntity, "included not a map")
    for p in incV.pairs:
      if p.key == nil or p.key.kind != ekBytes:
        raise newException(BadEntity, "included key not bytes")
      let e = entityOfValue(p.val)
      if p.key.b != e.hash:
        raise newException(IncludedKeyMismatch, "included key != entity hash")
      result.included.add (key: p.key.b, entity: e)

proc envelopeOfFrame*(payload: openArray[byte]): Envelope =
  envelopeOfValue(decode(payload))

# ── hex (lowercase, for §3.4/§3.5 tree-path hash segments) ─────────────────────

const HexDigits = "0123456789abcdef"

proc hexLower*(b: openArray[byte]): string =
  ## Lowercase hex (A-CL-009: Nim `toHex` is uppercase — force lower).
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add HexDigits[int(x shr 4)]
    result.add HexDigits[int(x and 0x0f)]
