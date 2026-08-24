⍝ entity-core-protocol-apl — src/entity.apl
⍝
⍝ Entity-framing surface composed from the pure-APL canonical codec (cbor.apl) +
⍝ the C-ABI crypto/base58 floor (ffi.apl). The core protocol codec operations the
⍝ profile names for S2: content_hash, peer-id format/parse, Ed25519 sign/verify.
⍝ CORE TYPES ONLY — no TREE/CONTENT/IDENTITY/extension encoding.
⍝
⍝ content_hash (§4.1): content_hash = varint(format_code) || SHA-256(ECF({type,data})).
⍝ We build the {type,data} map with OUR encoder (which canonically sorts the keys:
⍝ "data" < "type"), SHA-256 it via the C-ABI, and prepend OUR LEB128 varint (N1).
⍝ content_hash.4 (format_code=128 -> 0x80 0x01) proves the multibyte varint prefix
⍝ over the same SHA-256 digest — the C-ABI's ec_content_hash rejects format 128,
⍝ so composing the prefix ourselves is both correct AND the right exercise.

⍝ content_hash of entity {type,data} under an explicit format_code (0 = SHA-256).
⍝ ⍺ = format_code ; ⍵ = (typeVal)(dataVal). Returns the content_hash octet vector.
∇Z←fmt ContentHash td;typev;datav;entity;ecf;digest;prefix
 typev←1⊃td
 datav←2⊃td
 entity←EV_MAP((MkText'type')typev(MkText'data')datav)
 ecf←CborEncode entity
 digest←EcSha256 ecf
 prefix←VarintEncode fmt
 Z←prefix,digest
∇

⍝ peer-id: Base58(varint(key_type) || varint(hash_type) || digest) via the C-ABI
⍝ (no APL exact bignum — A-APL-010). ⍵ = (keyType)(hashType)(digestBytes).
⍝ Returns the base58 ASCII octet vector.
∇Z←PeeridFormat kd;kt;ht;dig
 kt←1⊃kd
 ht←2⊃kd
 dig←3⊃kd
 Z←EcPeeridFmt kt ht dig
∇

⍝ peer-id parse (round-trip surface): base58 ASCII -> (keyType hashType digestBytes).
∇Z←PeeridParse b58;r
 r←EcPeeridParse b58
 Z←(r[1])(r[2])(2↓r)
∇

⍝ deterministic Ed25519 signature over ECF(entity). ⍺ = 32-byte seed (= private
⍝ key) ; ⍵ = the entity value. Returns the 64-byte signature.
∇Z←seed Sign entity;msg
 msg←CborEncode entity
 Z←EcSign seed msg
∇

⍝ verify an Ed25519 signature over ECF(entity). ⍺ = 32-byte pubkey ;
⍝ ⍵ = (entity)(sig64). Returns 1 (valid) / 0.
∇Z←pub Verify es;entity;sig;msg
 entity←1⊃es
 sig←2⊃es
 msg←CborEncode entity
 Z←EC_OK=EcVerify pub msg sig
∇
