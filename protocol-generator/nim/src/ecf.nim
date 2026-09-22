## Entity Canonical Form (ECF) — hand-rolled canonical CBOR (profile [codec],
## strategy = native, A-NIM-001).
##
## Why hand-rolled and not the Nim `cbor` nimble package (A-005, the Nth native
## peer): ECF (ENTITY-CBOR-ENCODING.md v1.5, RFC 8949 §4.2 + Entity
## clarifications) needs (a) length-then-lex map-key ordering (CTAP2/RFC-7049,
## NOT RFC-8949 pure-bytewise), (b) shortest-float minimisation incl. f16 with
## exact specials, (c) recursive major-type-6 tag rejection on decode (N2),
## (d) full uint64/nint head-form range, (e) byte-exact raw-slice fidelity. No
## Nim lib offers these and a faithful ECF codec must own the canonical layer.
##
## Nim generator-stress axis (profile [idiom].compile_time_metaprogramming): the
## CBOR head emission + major-type selection are expressed as `template`s the
## compiler inlines with zero runtime reflection, and the encoder is proven to
## execute at COMPILE TIME via the `static:` self-test at the foot of this file
## (the Zig `comptime` result carried onto a GC'd, C-backend substrate).
##
## Memory (profile [memory]): ARC/ORC deterministic destructors; `EcValue` is a
## ref-object variant, `seq[byte]`/`string` are move-optimised value types.
##
## SPDX-License-Identifier: Apache-2.0

import std/[algorithm, math]
import ./errors

type
  EcKind* = enum
    ekUint, ekNint, ekBytes, ekText, ekArray, ekMap, ekBool, ekNull, ekFloat

  EcValue* = ref EcValueObj
  EcPair* = object
    key*: EcValue
    val*: EcValue
  EcValueObj = object
    case kind*: EcKind
    of ekUint: u*: uint64
    of ekNint: n*: uint64          ## encodes -(1 + n); nint(0) == -1
    of ekBytes: b*: seq[byte]
    of ekText: t*: string
    of ekArray: arr*: seq[EcValue]
    of ekMap: pairs*: seq[EcPair]
    of ekBool: boolean*: bool
    of ekNull: discard
    of ekFloat: f*: float64

# ── constructors ─────────────────────────────────────────────────────────────

proc uintV*(u: uint64): EcValue = EcValue(kind: ekUint, u: u)
proc nintV*(n: uint64): EcValue = EcValue(kind: ekNint, n: n)
proc bytesV*(b: seq[byte]): EcValue = EcValue(kind: ekBytes, b: b)
proc textV*(t: string): EcValue = EcValue(kind: ekText, t: t)
proc arrV*(a: seq[EcValue]): EcValue = EcValue(kind: ekArray, arr: a)
proc mapV*(p: seq[EcPair]): EcValue = EcValue(kind: ekMap, pairs: p)
proc boolV*(x: bool): EcValue = EcValue(kind: ekBool, boolean: x)
proc nullV*(): EcValue = EcValue(kind: ekNull)
proc floatV*(x: float64): EcValue = EcValue(kind: ekFloat, f: x)

# ── half-precision (float16) bit helpers (ported from the Zig peer) ───────────

proc halfToDouble(h: uint16): float64 =
  ## Exact float16 -> f64; used on decode and for the encoder round-trip check.
  let
    sign = (h shr 15) and 1'u16
    exp = (h shr 10) and 0x1f'u16
    mant = h and 0x3ff'u16
    s = if sign == 1'u16: -1.0 else: 1.0
  if exp == 0'u16:
    if mant == 0'u16: return s * 0.0                       # ±0
    return s * float64(mant) * pow(2.0, -24.0)             # subnormal
  elif exp == 0x1f'u16:
    if mant == 0'u16: return s * Inf
    return NaN
  else:
    let e = int(exp) - 15
    return s * (1.0 + float64(mant) / 1024.0) * pow(2.0, float64(e))

proc doubleToHalfBits(x: float64): uint16 =
  ## Round-to-nearest-even f64 -> float16 bits. The encoder EMITS the result only
  ## when it round-trips bit-exactly through `halfToDouble`, so imperfect
  ## rounding can never emit wrong canonical bytes — it just falls back to f32/f64.
  let bits = cast[uint64](x)
  let sign = uint16((bits shr 63) and 1'u64)
  let sbit = sign shl 15
  let exp = uint16((bits shr 52) and 0x7ff'u64)
  let mant = bits and 0xFFFFFFFFFFFFF'u64
  if exp == 0x7ff'u16:
    return (if mant == 0'u64: sbit or 0x7c00'u16 else: 0x7e00'u16)
  let e = int(exp) - 1023
  if e > 15: return sbit or 0x7c00'u16
  if e >= -14:
    # normal half: top 10 of the 52 mantissa bits, round half-to-even.
    const drop = 42
    var m = uint32(mant shr drop)
    let rem = mant and ((1'u64 shl drop) - 1)
    let halfway = 1'u64 shl (drop - 1)
    if rem > halfway or (rem == halfway and (m and 1'u32) == 1'u32): inc m
    var halfExp = e + 15
    if m == 1024'u32:
      inc halfExp
      m = 0'u32
    if halfExp >= 0x1f: return sbit or 0x7c00'u16
    return sbit or (uint16(halfExp) shl 10) or uint16(m and 0x3ff'u32)
  if e < -25: return sbit                                   # underflow -> ±0
  # subnormal half: value = m * 2^-24.
  let full = (1'u64 shl 52) or mant
  let shift = 28 - e
  var m = uint32(full shr shift)
  let rem = full and ((1'u64 shl shift) - 1)
  let halfway = 1'u64 shl (shift - 1)
  if rem > halfway or (rem == halfway and (m and 1'u32) == 1'u32): inc m
  if m >= 1024'u32: return sbit or (1'u16 shl 10)
  return sbit or uint16(m and 0x3ff'u32)

# ── canonical encode ─────────────────────────────────────────────────────────

template addBe(dst: var seq[byte]; v: uint64; nbytes: int) =
  ## Big-endian minimal-width unsigned argument emitter (compile-time inlined).
  var i = nbytes
  while i > 0:
    dec i
    dst.add byte((v shr (i * 8)) and 0xff'u64)

template addHead(dst: var seq[byte]; major: uint8; arg: uint64) =
  ## CBOR head: major type (0..7) + minimal-length unsigned argument. The
  ## length-class ladder is selected at compile time per the template body.
  let mt = major shl 5
  if arg < 24'u64:
    dst.add (mt or uint8(arg))
  elif arg < 0x100'u64:
    dst.add (mt or 24'u8); addBe(dst, arg, 1)
  elif arg < 0x10000'u64:
    dst.add (mt or 25'u8); addBe(dst, arg, 2)
  elif arg < 0x100000000'u64:
    dst.add (mt or 26'u8); addBe(dst, arg, 4)
  else:
    dst.add (mt or 27'u8); addBe(dst, arg, 8)

proc canonCmp(a, b: seq[byte]): int =
  ## Deterministic key ordering: encoded-key length ascending, then bytewise-lex.
  if a.len != b.len: return (if a.len < b.len: -1 else: 1)
  for i in 0 ..< a.len:
    if a[i] != b[i]: return (if a[i] < b[i]: -1 else: 1)
  return 0

proc encodeFloat(dst: var seq[byte]; x: float64) =
  if x != x:                                                # NaN: canonical f9 7e00
    dst.add 0xf9'u8
    addBe(dst, 0x7e00'u64, 2)
    return
  let h = doubleToHalfBits(x)
  if cast[uint64](halfToDouble(h)) == cast[uint64](x):
    dst.add 0xf9'u8
    addBe(dst, uint64(h), 2)
    return
  let f32 = float32(x)
  if cast[uint64](float64(f32)) == cast[uint64](x):
    dst.add 0xfa'u8
    addBe(dst, uint64(cast[uint32](f32)), 4)
    return
  dst.add 0xfb'u8
  addBe(dst, cast[uint64](x), 8)

proc encodeInto*(dst: var seq[byte]; v: EcValue) {.raises: [DuplicateKey].} =
  ## Canonical ECF encode of `v` appended to `dst`. Dispatch on `v.kind` — the
  ## Nim compiler lowers the variant case to a jump (no runtime reflection).
  case v.kind
  of ekUint: addHead(dst, 0'u8, v.u)
  of ekNint: addHead(dst, 1'u8, v.n)
  of ekBytes:
    addHead(dst, 2'u8, uint64(v.b.len))
    dst.add v.b
  of ekText:
    addHead(dst, 3'u8, uint64(v.t.len))
    for i in 0 ..< v.t.len: dst.add byte(v.t[i])
  of ekArray:
    addHead(dst, 4'u8, uint64(v.arr.len))
    for it in v.arr: encodeInto(dst, it)
  of ekMap:
    # Encode each key, sort by encoded-key (length-then-lex), reject dups.
    var encoded = newSeq[tuple[k: seq[byte], val: EcValue]](v.pairs.len)
    for i, p in v.pairs:
      var kb: seq[byte]
      encodeInto(kb, p.key)
      encoded[i] = (k: kb, val: p.val)
    encoded.sort(proc(a, b: tuple[k: seq[byte], val: EcValue]): int =
      canonCmp(a.k, b.k))
    for i in 1 ..< encoded.len:
      if encoded[i - 1].k == encoded[i].k:
        raise newException(DuplicateKey, "duplicate map key in canonical ECF")
    addHead(dst, 5'u8, uint64(v.pairs.len))
    for e in encoded:
      dst.add e.k
      encodeInto(dst, e.val)
  of ekBool: dst.add (if v.boolean: 0xf5'u8 else: 0xf4'u8)
  of ekNull: dst.add 0xf6'u8
  of ekFloat: encodeFloat(dst, v.f)

proc encode*(v: EcValue): seq[byte] {.raises: [DuplicateKey].} =
  ## Encode `v` to a fresh canonical-ECF byte buffer.
  result = @[]
  encodeInto(result, v)

# ── decode (rejects tags + indefinite lengths + trailing bytes) ───────────────

type Decoder = object
  s: seq[byte]
  pos: int
  ## keepTags makes `item` yield the tag's INNER value instead of raising
  ## TagRejected. It exists for ONE caller -- `decodeSalvage` -- and is never set on
  ## the strict path. See `decodeSalvage` for why this is not a weakening of §6.3.
  keepTags: bool

proc need(d: Decoder; k: int) {.raises: [TruncatedInput].} =
  if d.pos + k > d.s.len:
    raise newException(TruncatedInput, "ECF input truncated")

proc readByte(d: var Decoder): byte {.raises: [TruncatedInput].} =
  d.need(1)
  result = d.s[d.pos]
  inc d.pos

proc take(d: var Decoder; k: int): seq[byte] {.raises: [TruncatedInput].} =
  d.need(k)
  result = d.s[d.pos ..< d.pos + k]
  d.pos += k

proc be(d: var Decoder; k: int): uint64 {.raises: [TruncatedInput].} =
  d.need(k)
  result = 0'u64
  for _ in 0 ..< k:
    result = (result shl 8) or uint64(d.s[d.pos])
    inc d.pos

proc readArg(d: var Decoder; ai: uint8): uint64 {.raises: [TruncatedInput, NonCanonicalEcf].} =
  if ai < 24'u8: return uint64(ai)
  case ai
  of 24'u8: return d.be(1)
  of 25'u8: return d.be(2)
  of 26'u8: return d.be(4)
  of 27'u8: return d.be(8)
  else: raise newException(NonCanonicalEcf, "indefinite / reserved length argument")

proc item(d: var Decoder): EcValue =
  let ib = d.readByte()
  let major = ib shr 5
  let ai = ib and 0x1f'u8
  case major
  of 0'u8: return uintV(d.readArg(ai))
  of 1'u8: return nintV(d.readArg(ai))
  of 2'u8:
    let n = int(d.readArg(ai))
    return bytesV(d.take(n))
  of 3'u8:
    let n = int(d.readArg(ai))
    let raw = d.take(n)
    var t = newString(n)
    for i in 0 ..< n: t[i] = char(raw[i])
    return textV(t)
  of 4'u8:
    let n = int(d.readArg(ai))
    var a = newSeq[EcValue](n)
    for i in 0 ..< n: a[i] = d.item()
    return arrV(a)
  of 5'u8:
    let n = int(d.readArg(ai))
    var p = newSeq[EcPair](n)
    for i in 0 ..< n:
      let k = d.item()
      let v = d.item()
      p[i] = EcPair(key: k, val: v)
    return mapV(p)
  of 6'u8:                                                  # N2: any tag, any depth
    if not d.keepTags:
      raise newException(TagRejected, "CBOR tag (major type 6) rejected")
    # Salvage path only (`decodeSalvage`): consume the tag head and yield the value it
    # wrapped, so the caller can locate the request_id and SIGNAL the rejection. The
    # frame is still rejected -- the tag is never interpreted and the value never
    # reaches an entity.
    discard d.readArg(ai)
    return d.item()
  else:                                                     # major 7: simple / float
    case ai
    of 20'u8: return boolV(false)
    of 21'u8: return boolV(true)
    of 22'u8: return nullV()
    of 25'u8: return floatV(halfToDouble(uint16(d.be(2))))
    of 26'u8: return floatV(float64(cast[float32](uint32(d.be(4)))))
    of 27'u8: return floatV(cast[float64](d.be(8)))
    else: raise newException(UnsupportedSimple, "unsupported simple/float value")

proc decode*(s: openArray[byte]): EcValue {.raises: [EcCodecError].} =
  ## Decode a single top-level ECF item; rejects tags, indefinite lengths, and
  ## trailing bytes. Any violation raises an `EcCodecError` (fail-closed).
  var d = Decoder(s: @s, pos: 0, keepTags: false)
  result = d.item()
  if d.pos != d.s.len:
    raise newException(TrailingBytes, "trailing bytes after a single ECF item")

proc decodeSalvage*(s: openArray[byte]): EcValue {.raises: [EcCodecError].} =
  ## Decode `s` for the sole purpose of REPORTING a rejection, not of accepting one.
  ## Identical to `decode` except that a major-type-6 tag yields the item it wrapped
  ## instead of raising `TagRejected`.
  ##
  ## Why this exists (§6.3, a conformance requirement rather than a convenience): the
  ## tag rule is "Implementations MUST reject any received protocol frame containing a
  ## CBOR tag on a data field. Rejection returns 400 non_canonical_ecf." Rejecting by
  ## dropping the frame on the floor satisfies the first sentence and violates the
  ## second -- the peer owes the sender a status, and §4.9(c) deliver-or-signal says
  ## the same from the other direction. But the status must ride a response correlated
  ## by request_id, and the strict decoder cannot reach the request_id in a frame it
  ## refuses to parse. This recovers exactly that much and nothing more.
  ##
  ## This is NOT a weakening of the tag reject. The frame stays rejected: the value
  ## this returns is never converted to an Entity, never stored, never forwarded and
  ## never interpreted, so §6.3's MUST NOT silently strip / MUST NOT preserve / MUST
  ## NOT attempt to interpret all still hold. The strict `decode` path that every real
  ## ingestion route uses is unchanged, which is what keeps the `tag_reject`
  ## wire-conformance vectors meaningful.
  var d = Decoder(s: @s, pos: 0, keepTags: true)
  result = d.item()
  if d.pos != d.s.len:
    raise newException(TrailingBytes, "trailing bytes after a single ECF item")

# ── entity helper (shared by content_hash + signature) ────────────────────────

proc ecfOfEntity*(typ: string; data: EcValue): seq[byte] {.raises: [DuplicateKey].} =
  ## ECF of the {type, data} entity. The encoder sorts keys, so "data" precedes
  ## "type" (both 5 encoded bytes, lexicographic).
  encode(mapV(@[
    EcPair(key: textV("type"), val: textV(typ)),
    EcPair(key: textV("data"), val: data),
  ]))

# ── compile-time proof: the encoder runs at COMPILE TIME (A-NIM-002 axis) ──────
# This `static:` block executes the encoder in the Nim VM at compile time — the
# profile's compile-time-metaprogramming claim, and the fixed-width head-form
# self-test proven before a single runtime instruction. A signed-int64 carrier
# would trap/overflow here in the [2^63, 2^64-1] band; the uint64 carrier does not.
static:
  doAssert encode(uintV(0'u64)) == @[0x00'u8]
  doAssert encode(uintV(23'u64)) == @[0x17'u8]
  doAssert encode(uintV(24'u64)) == @[0x18'u8, 0x18'u8]
  # [2^63, 2^64-1] — the >int64-max band (fixed-width trap boundary):
  doAssert encode(uintV(0x8000000000000000'u64)) ==
    @[0x1b'u8, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  doAssert encode(uintV(0xffffffffffffffff'u64)) ==
    @[0x1b'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
  doAssert encode(nintV(0xffffffffffffffff'u64)) ==      # -(2^64) == nint(2^64-1)
    @[0x3b'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
  doAssert encode(floatV(1.0)) == @[0xf9'u8, 0x3c, 0x00]
