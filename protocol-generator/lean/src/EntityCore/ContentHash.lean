/-
  content_hash construction (V7 §1.2 / §7.3, ECF §4.2).

    content_hash = varint(format_code) ‖ SHA-256(ECF{type, data})

  The preimage is the canonical ECF encoding of the two-field entity carrier
  `{"type": <type>, "data": <data>}` — the canonical encoder sorts the keys
  (`"data"` before `"type"`: both 4 bytes, lex `data` < `type`). The leading
  varint binds the hash to its digest function; the floor is `0x00` → SHA-256.
  The corpus `content_hash.4` synthetic ≥ 0x80 code still uses SHA-256 under a
  2-byte varint prefix (forward-compat). SHA-256 is sourced over the FFI
  boundary (`EntityCore.Crypto`).
-/
import EntityCore.Codec.Value
import EntityCore.Codec.CBOR
import EntityCore.Codec.Varint
import EntityCore.Crypto

namespace EntityCore.ContentHash

open EntityCore (Value)

/-- Canonical ECF bytes of the entity carrier `{type, data}` — the content_hash
preimage AND the message the corpus `signature.*` vectors sign over. -/
def ecfOfEntity (typ : String) (dataV : Value) : ByteArray :=
  EntityCore.Codec.encode (.map [(.text "type", .text typ), (.text "data", dataV)])

/-- content_hash for an entity under a format code. SHA-256 digest under a
LEB128 `format_code` prefix (the corpus pins SHA-256 for codes 0x00 and the
synthetic ≥ 0x80). -/
def contentHash (fmtCode : Nat) (typ : String) (dataV : Value) : ByteArray :=
  EntityCore.Codec.Varint.varintEncode fmtCode ++ EntityCore.Crypto.sha256 (ecfOfEntity typ dataV)

end EntityCore.ContentHash
