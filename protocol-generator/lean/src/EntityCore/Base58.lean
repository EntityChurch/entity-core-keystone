/-
  Base58 (Bitcoin alphabet) encode, leading-zero preserving.

  Lean's `Nat` IS arbitrary-precision, so the base-256 → base-58 conversion goes
  through a `Nat` bignum directly (cleaner than explicit byte long-division; the
  result is identical). Each leading `0x00` input byte maps to one leading `'1'`
  output character. Only `base58Encode` is on the S2 gate path (peer_id format).
-/
namespace EntityCore.Base58

/-- Bitcoin Base58 alphabet (no 0, O, I, l). -/
def alphabet : Array Char :=
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toList.toArray

private def toDigitsGo (n : Nat) (acc : List Nat) : List Nat :=
  match n with
  | 0 => acc
  | m + 1 => toDigitsGo ((m + 1) / 58) ((m + 1) % 58 :: acc)
termination_by n
decreasing_by simp_wf; omega

/-- Base-58 digit list (most-significant first) of a `Nat`. -/
def toDigits (n : Nat) : List Nat := toDigitsGo n []

/-- Encode bytes to a Base58 string. Leading `0x00` bytes become leading `'1'`. -/
def base58Encode (input : ByteArray) : String :=
  let bytes := input.toList
  let zeros := (bytes.takeWhile (· == 0)).length
  let n : Nat := bytes.foldl (fun acc b => acc * 256 + b.toNat) 0
  let digits := toDigits n
  let leading := String.ofList (List.replicate zeros '1')
  let body := String.ofList (digits.map (fun d => alphabet[d]!))
  leading ++ body

private def natToBytesGo (n : Nat) (acc : List UInt8) : List UInt8 :=
  match n with
  | 0 => acc
  | m + 1 => natToBytesGo ((m + 1) / 256) (UInt8.ofNat ((m + 1) % 256) :: acc)
termination_by n
decreasing_by simp_wf; omega

/-- Decode a Base58 string to bytes (leading `'1'` → leading `0x00`). `none` on a
non-alphabet character. Through a `Nat` bignum (Lean `Nat` is arbitrary-precision)
— the inverse of `base58Encode`. -/
def base58Decode (s : String) : Option ByteArray := do
  let chars := s.toList
  let ones := (chars.takeWhile (· == '1')).length
  let n ← chars.foldlM (fun acc c => (alphabet.findIdx? (· == c)).map (fun d => acc * 58 + d)) 0
  let body := if n == 0 then [] else natToBytesGo n []
  some (ByteArray.mk (List.replicate ones (0 : UInt8) ++ body).toArray)

end EntityCore.Base58
