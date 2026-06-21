/-
  Shortest-form float encoding (ENTITY-CBOR-ENCODING §4.1 Rule 4 + Rule 4a).

  A `Float` (binary64) is encoded in the SHORTEST IEEE-754 width that preserves
  its value EXACTLY: try float16 (`0xF9`), then float32 (`0xFA`), else float64
  (`0xFB`). "Preserves value exactly" = the narrowed bits widen back to a value
  BIT-IDENTICAL to the original (so `-0.0` stays `-0.0`; NaN/±Inf take their
  Rule-4a float16 forms). The decoder reads any width; the encoder only emits
  the shortest.

  THE LOAD-BEARING S1 DESIGN (1a finding #2, 1b T3): Lean's `Float` is OPAQUE to
  the kernel — it cannot reduce or reason about float ops. So this entire module
  is PURE BIT ARITHMETIC over `UInt16/32/64`. `Float.toBits` and `Float.ofBits`
  are the ONLY points of contact with `Float`, both at the module boundary. This
  is simultaneously the shortest-float mechanism AND what makes T3 provable: the
  narrow/widen ladder is a kernel-reducible function of `UInt` bits.

  Narrowing is by TRUNCATION (drop low mantissa bits, map out-of-range exponents
  to ±Inf/±0); a candidate is accepted only if it widens back bit-identically, so
  truncation yields a *some* result IFF the value is exactly representable in the
  narrower width (a non-representable value loses bits and is rejected). Widening
  (f16/f32 → f64) is exact and total.
-/
namespace EntityCore.Codec.Float

private def msbPosGo (m : UInt64) (i : Nat) : Nat :=
  match i with
  | 0 => 0
  | j + 1 => if ((m >>> UInt64.ofNat (j + 1)) &&& 1) == 1 then j + 1 else msbPosGo m j
termination_by i
decreasing_by simp_wf <;> omega

/-- Highest set bit index of `m` (assumes `m ≠ 0`, `m < 2^53`). Used to
normalize subnormal-source mantissas when widening. -/
def msbPos (m : UInt64) : Nat := msbPosGo m 52

-- ── Widen: f16 / f32 → f64 bits (exact, total, pure bits) ────────────────────

/-- Widen a 16-bit half-precision pattern to the equivalent f64 bit pattern. -/
def widen16 (h : UInt16) : UInt64 :=
  let h64 : UInt64 := h.toUInt64
  let s   : UInt64 := (h64 >>> 15) &&& 1
  let e   : UInt64 := (h64 >>> 10) &&& 0x1F
  let m   : UInt64 := h64 &&& 0x3FF
  let signBit := s <<< 63
  if e == 0x1F then
    -- Inf (m = 0) or NaN (m ≠ 0)
    if m == 0 then signBit ||| ((0x7FF : UInt64) <<< 52)
    else signBit ||| ((0x7FF : UInt64) <<< 52) ||| (0x8000000000000 : UInt64)  -- quiet NaN
  else if e == 0 then
    if m == 0 then signBit                                 -- ±0
    else
      -- subnormal half: value = m * 2^-24, normalize
      let p := msbPos m                                    -- 0..9
      let exp64 : UInt64 := UInt64.ofNat (999 + p)
      let mant64 : UInt64 := (m - ((1 : UInt64) <<< UInt64.ofNat p)) <<< UInt64.ofNat (52 - p)
      signBit ||| (exp64 <<< 52) ||| mant64
  else
    -- normal half: unbiased = e - 15 ; exp64 = e + 1008 ; mant64 = m << 42
    signBit ||| ((e + 1008) <<< 52) ||| (m <<< 42)

/-- Widen a 32-bit single-precision pattern to the equivalent f64 bit pattern. -/
def widen32 (g : UInt32) : UInt64 :=
  let g64 : UInt64 := g.toUInt64
  let s   : UInt64 := (g64 >>> 31) &&& 1
  let e   : UInt64 := (g64 >>> 23) &&& 0xFF
  let m   : UInt64 := g64 &&& 0x7FFFFF
  let signBit := s <<< 63
  if e == 0xFF then
    if m == 0 then signBit ||| ((0x7FF : UInt64) <<< 52)
    else signBit ||| ((0x7FF : UInt64) <<< 52) ||| (0x8000000000000 : UInt64)
  else if e == 0 then
    if m == 0 then signBit
    else
      let p := msbPos m                                    -- 0..22
      let exp64 : UInt64 := UInt64.ofNat (874 + p)
      let mant64 : UInt64 := (m - ((1 : UInt64) <<< UInt64.ofNat p)) <<< UInt64.ofNat (52 - p)
      signBit ||| (exp64 <<< 52) ||| mant64
  else
    -- normal single: exp64 = e + 896 ; mant64 = m << 29
    signBit ||| ((e + 896) <<< 52) ||| (m <<< 29)

-- ── Narrow candidates: f64 bits → f16 / f32 (truncating) ─────────────────────

/-- Candidate float16 bits for an f64 bit pattern, by truncation. Trusted only
after `tryHalf` confirms it widens back exactly. -/
def doubleToHalf (bits : UInt64) : UInt16 :=
  let s16 : UInt64 := (bits >>> 48) &&& 0x8000
  let exp : UInt64 := (bits >>> 52) &&& 0x7FF
  let mant : UInt64 := bits &&& 0xFFFFFFFFFFFFF
  let out : UInt64 :=
    if exp == 0x7FF then
      if mant == 0 then s16 ||| 0x7C00 else s16 ||| 0x7E00
    else if exp == 0 then s16                              -- ±0 / f64-subnormal underflow
    else
      let unbiased : Int := (exp.toNat : Int) - 1023
      if unbiased > 15 then s16 ||| 0x7C00                 -- overflow → Inf
      else if unbiased < -24 then s16                      -- underflow → ±0
      else if unbiased < -14 then
        let shiftAmt : Nat := (-14 - unbiased).toNat       -- 1..10
        let mant23 : UInt64 := (mant ||| 0x10000000000000) >>> UInt64.ofNat (42 + shiftAmt)
        s16 ||| (mant23 &&& 0x3FF)
      else
        let he : UInt64 := UInt64.ofNat (unbiased + 15).toNat  -- 1..30
        let hm : UInt64 := (mant >>> 42) &&& 0x3FF
        s16 ||| (he <<< 10) ||| hm
  out.toUInt16

/-- Candidate float32 bits for an f64 bit pattern, by truncation. -/
def doubleToSingle (bits : UInt64) : UInt32 :=
  let s32 : UInt64 := ((bits >>> 63) &&& 1) <<< 31
  let exp : UInt64 := (bits >>> 52) &&& 0x7FF
  let mant : UInt64 := bits &&& 0xFFFFFFFFFFFFF
  let out : UInt64 :=
    if exp == 0x7FF then
      if mant == 0 then s32 ||| 0x7F800000 else s32 ||| 0x7FC00000
    else if exp == 0 then s32
    else
      let unbiased : Int := (exp.toNat : Int) - 1023
      if unbiased > 127 then s32 ||| 0x7F800000
      else if unbiased < -149 then s32
      else if unbiased < -126 then
        let shiftAmt : Nat := (-126 - unbiased).toNat      -- 1..23
        let mantFull : UInt64 := mant ||| 0x10000000000000
        let m23 : UInt64 := mantFull >>> UInt64.ofNat (29 + shiftAmt)
        s32 ||| (m23 &&& 0x7FFFFF)
      else
        let se : UInt64 := UInt64.ofNat (unbiased + 127).toNat
        let sm : UInt64 := (mant >>> 29) &&& 0x7FFFFF
        s32 ||| (se <<< 23) ||| sm
  out.toUInt32

/-- `some h` iff `bits` is exactly representable as float16 (widens back). -/
def tryHalf (bits : UInt64) : Option UInt16 :=
  let h := doubleToHalf bits
  if widen16 h == bits then some h else none

/-- `some g` iff `bits` is exactly representable as float32 (widens back). -/
def trySingle (bits : UInt64) : Option UInt32 :=
  let g := doubleToSingle bits
  if widen32 g == bits then some g else none

-- ── Big-endian byte splits ───────────────────────────────────────────────────

def be16 (w : UInt16) : ByteArray :=
  ⟨#[ (w >>> 8).toUInt8, w.toUInt8 ]⟩

def be32 (w : UInt32) : ByteArray :=
  ⟨#[ (w >>> 24).toUInt8, (w >>> 16).toUInt8, (w >>> 8).toUInt8, w.toUInt8 ]⟩

def be64 (w : UInt64) : ByteArray :=
  ⟨#[ (w >>> 56).toUInt8, (w >>> 48).toUInt8, (w >>> 40).toUInt8, (w >>> 32).toUInt8,
      (w >>> 24).toUInt8, (w >>> 16).toUInt8, (w >>> 8).toUInt8, w.toUInt8 ]⟩

-- ── The encoder: pick the shortest width (Rule 4 / Rule 4a) ──────────────────

/-- The bit-level shortest-float encoder — pure `UInt`, kernel-reducible, the T3
proof surface. Rule 4a specials (NaN → `F9 7E00`, ±Inf) are forced explicitly on
the bit pattern before the narrow ladder; otherwise the shortest width that
widens back exactly (`tryHalf`, then `trySingle`, else f64). -/
def encodeFloatBits (bits : UInt64) : ByteArray :=
  let exp : UInt64 := (bits >>> 52) &&& 0x7FF
  let mant : UInt64 := bits &&& 0xFFFFFFFFFFFFF
  let sign : UInt64 := (bits >>> 63) &&& 1
  if exp == 0x7FF then
    if mant == 0 then
      -- ±Inf
      let h : UInt16 := if sign == 1 then 0xFC00 else 0x7C00
      ByteArray.mk #[0xF9] ++ be16 h
    else
      -- NaN → canonical quiet NaN (Rule 4a), sign dropped
      ByteArray.mk #[0xF9] ++ be16 0x7E00
  else
    match tryHalf bits with
    | some h => ByteArray.mk #[0xF9] ++ be16 h
    | none =>
      match trySingle bits with
      | some g => ByteArray.mk #[0xFA] ++ be32 g
      | none => ByteArray.mk #[0xFB] ++ be64 bits

/-- Encode a `Float` in the shortest CBOR float width that preserves it exactly.
`Float.toBits` is the SOLE `Float` contact — everything below it is the
kernel-reducible bit ladder `encodeFloatBits`. -/
def encodeFloatShortest (d : Float) : ByteArray := encodeFloatBits d.toBits

-- ── Decode helpers (widen bits → Float) ──────────────────────────────────────

def decodeFloat16 (h : UInt16) : Float := Float.ofBits (widen16 h)
def decodeFloat32 (g : UInt32) : Float := Float.ofBits (widen32 g)
def decodeFloat64 (w : UInt64) : Float := Float.ofBits w

end EntityCore.Codec.Float
