/-
  Canonical ECF (Entity Canonical Form) CBOR encode / decode.

  The hand-rolled canonical layer (A-005, the cohort's 9th confirmation): a
  faithful ECF codec OWNS the canonical guarantees —

    * map keys sorted by ENCODED length then lexicographically over the encoded
      key bytes (§4.1 Rule 2);
    * minimal integer head form (Rule 1), full UInt64 / -2^64 range (no Int clamp);
    * shortest-form float ladder (Rule 4 / 4a) — `EntityCore.Codec.Float`, bit-level;
    * definite lengths only (Rule 3); indefinite heads rejected on decode;
    * recursive major-type-6 (tag) rejection on decode (§6.3 Option B);
    * canonical key order + duplicate-key rejection enforced on decode.

  PROVE-VS-RUN CUT (S1 stance-1): `encode` (`buildValue`) is TOTAL and structurally
  recursive — it is the running encoder AND the T2/T3 proof surface. The decoder is
  `partial` for now (Track A floor); a kernel-reducible decode for the T1 round-trip
  is a Track-B refinement attempted in the proofs phase (time-boxed per the stance).
-/
import EntityCore.Codec.Value
import EntityCore.Codec.Error
import EntityCore.Codec.Float

namespace EntityCore.Codec

open EntityCore (Value CodecError)
open EntityCore.Codec.Float (be16 be32 be64 encodeFloatShortest decodeFloat16 decodeFloat32 decodeFloat64)

-- ── Canonical key ordering (length-then-lex over encoded key bytes) ──────────

/-- Lexicographic compare of two byte arrays from index `i`. Total (recurses
toward the shorter length). -/
def lexCmp (a b : ByteArray) (i : Nat) : Ordering :=
  if i ≥ a.size then (if i ≥ b.size then .eq else .lt)
  else if i ≥ b.size then .gt
  else if (a[i]!).toNat < (b[i]!).toNat then .lt
  else if (a[i]!).toNat > (b[i]!).toNat then .gt
  else lexCmp a b (i + 1)
termination_by a.size - i
decreasing_by simp_wf; omega

/-- Canonical key order: by encoded length, then bytewise lexicographic. -/
def keyCmp (a b : ByteArray) : Ordering :=
  if a.size < b.size then .lt
  else if a.size > b.size then .gt
  else lexCmp a b 0

/-- `a ≤ b` under canonical key order. -/
def keyLe (a b : ByteArray) : Bool :=
  match keyCmp a b with | .gt => false | _ => true

-- ── Encoded-pair sort (insertion sort — maps are small) ──────────────────────

def insertPair (p : ByteArray × ByteArray)
    : List (ByteArray × ByteArray) → List (ByteArray × ByteArray)
  | [] => [p]
  | q :: qs => if keyLe p.1 q.1 then p :: q :: qs else q :: insertPair p qs

def sortPairs : List (ByteArray × ByteArray) → List (ByteArray × ByteArray)
  | [] => []
  | p :: ps => insertPair p (sortPairs ps)

def concatPairs : List (ByteArray × ByteArray) → ByteArray
  | [] => ByteArray.empty
  | (k, v) :: rest => k ++ v ++ concatPairs rest

-- ── CBOR head (major type + minimal-length argument, Rule 1) ─────────────────

def buildHead (major : UInt8) (arg : UInt64) : ByteArray :=
  let mt : UInt8 := major <<< 5
  if arg < 24 then ByteArray.mk #[mt ||| arg.toUInt8]
  else if arg ≤ 0xFF then ByteArray.mk #[mt ||| 24, arg.toUInt8]
  else if arg ≤ 0xFFFF then ByteArray.mk #[mt ||| 25] ++ be16 arg.toUInt16
  else if arg ≤ 0xFFFFFFFF then ByteArray.mk #[mt ||| 26] ++ be32 arg.toUInt32
  else ByteArray.mk #[mt ||| 27] ++ be64 arg

-- ── Encode (total, pure; canonical by construction) ──────────────────────────

mutual
  /-- Canonically ECF-encode a `Value`. Total — the model only represents
  canonical-encodable shapes, so encode never fails. -/
  def buildValue : Value → ByteArray
    | .uint n => buildHead 0 n
    | .nint a => buildHead 1 a
    | .bytes b => buildHead 2 (UInt64.ofNat b.size) ++ b
    | .text s =>
        let enc := s.toUTF8
        buildHead 3 (UInt64.ofNat enc.size) ++ enc
    | .array xs => buildHead 4 (UInt64.ofNat xs.length) ++ buildArray xs
    | .map kvs =>
        buildHead 5 (UInt64.ofNat kvs.length) ++ concatPairs (sortPairs (encodePairs kvs))
    | .float d => encodeFloatShortest d
    | .bool b => ByteArray.mk #[if b then (0xF5 : UInt8) else 0xF4]
    | .null => ByteArray.mk #[0xF6]

  def buildArray : List Value → ByteArray
    | [] => ByteArray.empty
    | v :: vs => buildValue v ++ buildArray vs

  def encodePairs : List (Value × Value) → List (ByteArray × ByteArray)
    | [] => []
    | (k, v) :: rest => (buildValue k, buildValue v) :: encodePairs rest
end

/-- The public canonical encoder. -/
def encode (v : Value) : ByteArray := buildValue v

-- ── Decode (partial; canonical-form-enforcing; recursive tag rejection) ──────

/-- Read `n` big-endian bytes as a `UInt64` (n ≤ 8). -/
def readBE (n : Nat) (bs : ByteArray) (pos : Nat) : Option (UInt64 × Nat) :=
  if pos + n ≤ bs.size then
    some ((List.range n).foldl
      (fun acc i => (acc <<< 8) ||| (bs[pos + i]!).toUInt64) (0 : UInt64), pos + n)
  else none

/-- Read a CBOR head argument, enforcing MINIMAL encoding (Rule 1) and rejecting
indefinite (31) + reserved (28..30). -/
def readArg (ai : UInt8) (bs : ByteArray) (pos : Nat) : Except CodecError (UInt64 × Nat) :=
  let n := ai.toNat
  if n < 24 then .ok (ai.toUInt64, pos)
  else if n == 24 then
    match readBE 1 bs pos with
    | none => .error (.truncated "head: 1-byte arg")
    | some (v, p) => if v < 24 then .error (.nonCanonical "non-minimal 1-byte arg") else .ok (v, p)
  else if n == 25 then
    match readBE 2 bs pos with
    | none => .error (.truncated "head: 2-byte arg")
    | some (v, p) => if v ≤ 0xFF then .error (.nonCanonical "non-minimal 2-byte arg") else .ok (v, p)
  else if n == 26 then
    match readBE 4 bs pos with
    | none => .error (.truncated "head: 4-byte arg")
    | some (v, p) => if v ≤ 0xFFFF then .error (.nonCanonical "non-minimal 4-byte arg") else .ok (v, p)
  else if n == 27 then
    match readBE 8 bs pos with
    | none => .error (.truncated "head: 8-byte arg")
    | some (v, p) => if v ≤ 0xFFFFFFFF then .error (.nonCanonical "non-minimal 8-byte arg") else .ok (v, p)
  else if n == 31 then .error (.nonCanonical "indefinite-length head forbidden in ECF")
  else .error (.nonCanonical s!"reserved additional-info {n}")

mutual
  partial def decodeItem (bs : ByteArray) (pos : Nat) : Except CodecError (Value × Nat) :=
    if pos < bs.size then
      let ib := bs[pos]!
      let major := (ib >>> 5).toNat
      let ai := ib &&& 0x1F
      match major with
      | 0 => do let (a, p) ← readArg ai bs (pos + 1); pure (.uint a, p)
      | 1 => do let (a, p) ← readArg ai bs (pos + 1); pure (.nint a, p)
      | 2 => do
          let (len, p) ← readArg ai bs (pos + 1)
          let k := len.toNat
          if p + k ≤ bs.size then pure (.bytes (bs.extract p (p + k)), p + k)
          else .error (.truncated "byte string payload")
      | 3 => do
          let (len, p) ← readArg ai bs (pos + 1)
          let k := len.toNat
          if p + k ≤ bs.size then
            match String.fromUTF8? (bs.extract p (p + k)) with
            | some s => pure (.text s, p + k)
            | none => .error (.badUtf8 "text: invalid UTF-8")
          else .error (.truncated "text string payload")
      | 4 => do let (len, p) ← readArg ai bs (pos + 1); decodeArray bs p len.toNat []
      | 5 => do let (len, p) ← readArg ai bs (pos + 1); decodeMap bs p len.toNat [] none
      | 6 => .error (.tagRejected s!"major-type-6 tag (ai={ai.toNat}) on the wire (§6.3)")
      | 7 => decodeSimple ai bs (pos + 1)
      | _ => .error (.nonCanonical "impossible major type")
    else .error (.truncated "decode: unexpected end of input")

  partial def decodeArray (bs : ByteArray) (pos count : Nat) (acc : List Value)
      : Except CodecError (Value × Nat) :=
    match count with
    | 0 => pure (.array acc.reverse, pos)
    | k + 1 => do
        let (v, p) ← decodeItem bs pos
        decodeArray bs p k (v :: acc)

  partial def decodeMap (bs : ByteArray) (pos count : Nat) (acc : List (Value × Value))
      (prevKey : Option ByteArray) : Except CodecError (Value × Nat) :=
    match count with
    | 0 => pure (.map acc.reverse, pos)
    | k + 1 => do
        let (key, p1) ← decodeItem bs pos
        let (val, p2) ← decodeItem bs p1
        let kb := buildValue key
        match prevKey with
        | none => decodeMap bs p2 k ((key, val) :: acc) (some kb)
        | some pb =>
            match keyCmp pb kb with
            | .lt => decodeMap bs p2 k ((key, val) :: acc) (some kb)
            | .eq => .error (.duplicateKey "map: duplicate key")
            | .gt => .error (.nonCanonical "map: keys not in canonical order")

  partial def decodeSimple (ai : UInt8) (bs : ByteArray) (pos : Nat)
      : Except CodecError (Value × Nat) :=
    match ai.toNat with
    | 20 => pure (.bool false, pos)
    | 21 => pure (.bool true, pos)
    | 22 => pure (.null, pos)
    | 23 => .error (.unsupported "undefined (0xF7) not used in ECF")
    | 25 =>
        match readBE 2 bs pos with
        | none => .error (.truncated "float16")
        | some (w, p) => pure (.float (decodeFloat16 w.toUInt16), p)
    | 26 =>
        match readBE 4 bs pos with
        | none => .error (.truncated "float32")
        | some (w, p) =>
            let d := decodeFloat32 w.toUInt32
            if encodeFloatShortest d == ByteArray.mk #[0xFA] ++ be32 w.toUInt32
            then pure (.float d, p) else .error (.nonCanonical "float32 not shortest")
    | 27 =>
        match readBE 8 bs pos with
        | none => .error (.truncated "float64")
        | some (w, p) =>
            let d := decodeFloat64 w
            if encodeFloatShortest d == ByteArray.mk #[0xFB] ++ be64 w
            then pure (.float d, p) else .error (.nonCanonical "float64 not shortest")
    | 24 => .error (.unsupported "simple value with 1-byte arg not in ECF")
    | n => .error (.unsupported s!"simple value ai={n} not in ECF")
end

/-- Decode a single top-level value, rejecting trailing bytes. -/
def decode (bs : ByteArray) : Except CodecError Value :=
  match decodeItem bs 0 with
  | .error e => .error e
  | .ok (v, p) =>
      if p == bs.size then .ok v
      else .error (.trailing s!"{bs.size - p} trailing byte(s)")

end EntityCore.Codec
