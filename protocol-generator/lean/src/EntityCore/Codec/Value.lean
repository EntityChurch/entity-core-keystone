/-
  The ECF value model the encoder / decoder operate over.

  Integers carry the FULL CBOR range: major-type-0 unsigned as a `UInt64`
  (0 .. 2^64-1) and major-type-1 negative as a `UInt64` *argument* (the wire
  value is `-1 - arg`, so `arg = 0` is -1 and `arg = 2^64-1` is -2^64). We do
  NOT clamp to `Int`/`Int64` — that is the codec-review uncovered-range trap
  (and on this peer it would also be an unsound `Nat`/`Int` model for T1).

  Text is a Lean `String` (UTF-8 internally); the CBOR length is the UTF-8 BYTE
  count, taken at encode time via `String.toUTF8`, never the code-point count.

  Float carries a `Float` (binary64). Per S1 1a finding #2 the codec's float
  PATH is pure bit arithmetic (`Float.toBits`/`ofBits` the only `Float` contact,
  in `EntityCore.Codec.Float`); the model node just transports the value.

  No `DecidableEq Value` is derived (Float has none, and we never need it):
  map-key ordering + duplicate detection compare ENCODED key bytes, not Values.
-/
namespace EntityCore

/-- A decoded ECF value. Map entries are an association list in decoded order;
the encoder re-sorts canonically (length-then-lex over encoded key bytes), and
the decoder enforces that received maps are already canonically ordered with no
duplicate keys. -/
inductive Value where
  /-- Major type 0. Full unsigned 64-bit (0 .. 2^64-1). -/
  | uint (n : UInt64)
  /-- Major type 1. Carries the on-wire *argument*; the value is `-1 - arg`.
      `nint 0` is -1; `nint 0xFFFFFFFFFFFFFFFF` is -2^64. -/
  | nint (arg : UInt64)
  /-- Major type 2 (byte string), forwarded verbatim. -/
  | bytes (b : ByteArray)
  /-- Major type 3 (text string), UTF-8 on the wire. -/
  | text (s : String)
  /-- Major type 4 (definite-length array). -/
  | array (xs : List Value)
  /-- Major type 5 (definite-length map). Entries in decoded order. -/
  | map (kvs : List (Value × Value))
  /-- Major type 7 float. The encoder picks the shortest IEEE-754 width that
      round-trips it (Rule 4 / Rule 4a), via the bit-level float ladder. -/
  | float (d : Float)
  /-- `0xF5` / `0xF4`. -/
  | bool (b : Bool)
  /-- `0xF6`. -/
  | null
  deriving Inhabited

end EntityCore
