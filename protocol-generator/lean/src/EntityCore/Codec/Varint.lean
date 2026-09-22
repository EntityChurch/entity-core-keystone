/-
  Multicodec-style LEB128 varints (V7 §7.3, NORMATIVE) — invariant N1.

  All format-code / key-type / hash-type framing routes through these real
  LEB128 primitives, NOT a fixed byte. Currently-allocated codes (< 0x80) encode
  as a single byte, byte-identical to a fixed-width field; codes ≥ 0x80 extend
  to 2+ bytes (continuation bit set on every byte but the last). The `peer_id.3`
  / `content_hash.4` corpus vectors exercise the synthetic ≥ 0x80 code.
-/
namespace EntityCore.Codec.Varint

private def varintEncodeGo (n : Nat) : List UInt8 :=
  if n < 128 then [UInt8.ofNat n]
  else UInt8.ofNat ((n % 128) ||| 0x80) :: varintEncodeGo (n / 128)
termination_by n
decreasing_by simp_wf; omega

/-- Encode a `Nat` as a multicodec-style LEB128 varint (low 7 bits per byte,
little-endian groups, continuation bit `0x80` on all but the final byte). -/
def varintEncode (n : Nat) : ByteArray := ByteArray.mk (varintEncodeGo n).toArray

/-- Decode one multicodec-style LEB128 varint from the front of `bs`, returning
`(value, bytesConsumed)`. `none` when the prefix is empty, truncated (every byte
carried a continuation bit), or non-minimal (a `0x00` final byte after a
continuation group). Written as a bounded loop over the array indices so it
carries no termination obligation. -/
def varintDecode (bs : ByteArray) : Option (Nat × Nat) := Id.run do
  let mut acc : Nat := 0
  let mut shift : Nat := 0
  for i in [0 : bs.size] do
    let b := (bs.get! i).toNat
    acc := acc ||| ((b &&& 0x7f) <<< shift)
    if b &&& 0x80 == 0 then
      if shift > 0 && b == 0 then return none
      return some (acc, i + 1)
    shift := shift + 7
  return none

end EntityCore.Codec.Varint
