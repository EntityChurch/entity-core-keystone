/-
  Entity model — the materialized {type, data, content_hash} form (V7 §1.1, §3.4)
  and the protocol envelope (§3.1). Sits directly on the S2 codec `Value`:
  `hash` is `ContentHash.contentHash 0 type data` (varint(0x00) ‖ SHA-256(ECF
  {type,data})), computed over the FFI boundary.

  Spec-first note (matches the cohort): an entity's content_hash covers only
  {type, data} (§1.1); the wire form additionally carries `content_hash` as a
  field so entities are self-describing (§3.1). We keep the two forms distinct —
  `make` never sees a carried content_hash; it recomputes from {type, data} and
  trusts our hash, not the wire bytes (§5.2 validate-before-trust, §1.8 fidelity).

  These field accessors are PURE/total over `Value` — they are the substrate the
  pure verdict core (Capability) consumes, so nothing here may be `@[extern]`.
-/
import EntityCore.Codec.Value
import EntityCore.ContentHash

namespace EntityCore.Model

open EntityCore (Value)

/-- ByteArray structural equality (compares the underlying `Array UInt8`). Used
for content-hash / target / signer / parent byte-string comparisons. -/
def baEq (a b : ByteArray) : Bool := a.data == b.data

/-- A materialized entity. `hash` is the 33-byte content_hash
(format byte 0x00 ‖ 32-byte SHA-256 digest). -/
structure Entity where
  typ : String
  data : Value
  hash : ByteArray
  deriving Inhabited

/-- Construct an entity, computing its content_hash under the ecfv1-sha256 floor
(format_code 0). -/
def make (typ : String) (data : Value) : Entity :=
  { typ, data, hash := EntityCore.ContentHash.contentHash 0 typ data }

-- ── CBOR field helpers (data is a Map keyed by text strings) ─────────────────

/-- Look up a text-keyed entry in a `Value.map`. -/
def mapGet (v : Value) (key : String) : Option Value :=
  match v with
  | .map kvs => (kvs.find? (fun kv => match kv.1 with | .text t => t == key | _ => false)).map (·.2)
  | _ => none

def field (e : Entity) (key : String) : Option Value := mapGet e.data key

def textField (e : Entity) (key : String) : Option String :=
  match field e key with | some (.text s) => some s | _ => none

def bytesField (e : Entity) (key : String) : Option ByteArray :=
  match field e key with | some (.bytes b) => some b | _ => none

def uintField (e : Entity) (key : String) : Option UInt64 :=
  match field e key with | some (.uint n) => some n | _ => none

/-- Lowercase hex of a byte string (revocation-marker path segment, §5.1). -/
def hex (b : ByteArray) : String :=
  let digit (n : Nat) : Char :=
    if n < 10 then Char.ofNat (48 + n) else Char.ofNat (97 + n - 10)
  b.data.foldl (fun acc byte =>
    let v := byte.toNat
    (acc.push (digit (v / 16))).push (digit (v % 16))) ""

-- ── wire form: entity carries its content_hash (§3.1) ────────────────────────

/-- Serialize an entity to its wire `Value` (carries `content_hash`). -/
def toCbor (e : Entity) : Value :=
  .map [(.text "type", .text e.typ), (.text "data", e.data), (.text "content_hash", .bytes e.hash)]

/-- Parse a wire entity, recomputing the hash from {type,data} and validating it
against the carried `content_hash` (§1.8 fidelity); we trust our hash, not the
wire bytes (§5.2). `none` on a malformed or mismatched entity. -/
def ofCbor (v : Value) : Option Entity :=
  match mapGet v "type", mapGet v "data" with
  | some (.text typ), some d =>
      let e := make typ d
      match mapGet v "content_hash" with
      | some (.bytes h) => if baEq h e.hash then some e else none
      | _ => some e
  | _, _ => none

-- ── envelope (§3.1) ──────────────────────────────────────────────────────────

/-- The protocol envelope: a root entity plus an `included` map keyed by each
entity's content_hash bytes (§3.1). -/
structure Envelope where
  root : Entity
  included : List (ByteArray × Entity)
  deriving Inhabited

/-- Resolve an included entity by its content_hash key. -/
def includedGet (env : Envelope) (h : ByteArray) : Option Entity :=
  (env.included.find? (fun ke => baEq ke.1 h)).map (·.2)

/-- Serialize an envelope to its wire `Value` (§3.1: `included` keyed by hash). -/
def envelopeToCbor (env : Envelope) : Value :=
  .map [(.text "root", toCbor env.root),
        (.text "included", .map (env.included.map (fun ke => (.bytes ke.1, toCbor ke.2))))]

/-- Parse an envelope; the `included` key MUST equal each entity's content_hash. -/
def envelopeOfCbor (v : Value) : Option Envelope := do
  let rootV ← mapGet v "root"
  let root ← ofCbor rootV
  let included ← match mapGet v "included" with
    | some (.map kvs) =>
        kvs.foldrM (fun kv acc =>
          match kv.1 with
          | .bytes h => do
              let e ← ofCbor kv.2
              if baEq h e.hash then some ((h, e) :: acc) else none
          | _ => none) []
    | none => some []
    | some _ => none
  some { root, included }

end EntityCore.Model
