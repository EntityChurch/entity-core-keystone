⍝ entity-core-protocol-apl — src/varint.apl
⍝
⍝ Unsigned LEB128 varint (multicodec key_type / hash_type / content-hash format
⍝ codes). N1: route ALL format-code / key-type / hash-type framing through a real
⍝ LEB128 varint primitive, NEVER a fixed byte. Today's allocated codes (< 0x80)
⍝ encode as a single byte — byte-identical to a fixed field — but a code >= 0x80
⍝ widens to 2+ bytes and a fixed-width impl breaks silently. content_hash.4
⍝ (format_code=128 -> 0x80 0x01) exercises the widening through THIS primitive;
⍝ peer_id.3's key_type widening rides the C-ABI.
⍝
⍝ Codes are small (< 2^63), so scalar arithmetic is exact — no octet-array carrier
⍝ needed here (that lives in cbor.apl for CBOR unsigned-integer HEADS). Encode is a
⍝ recursive dfn (the array/functional expression of the shift/mask ladder); decode
⍝ is a →-branch tradfn (A-APL-012: GNU APL 1.9 has no :If/:For in --script).

⍝ Encode a non-negative code as an unsigned-LEB128 octet vector (→-branch tradfn;
⍝ GNU APL 1.9's --script reader rejects dfn `:` guards — A-APL-012).
∇Z←VarintEncode code
 →(code<128)/lo
 Z←(128+128|code),VarintEncode ⌊code÷128 ⋄ →0
 lo:Z←,code
∇

⍝ Decode an unsigned LEB128 varint from `buf` at `pos` (1-indexed, ⍺). Returns
⍝ (code newPos rc); advances past the varint. Rejects truncated input and a
⍝ non-minimal (multi-byte form ending in 0x00) encoding.
∇Z←pos VarintDecode buf;result;shift;nbytes;b;p
 result←0 ⋄ shift←0 ⋄ nbytes←0 ⋄ p←pos
 lp:→(p>≢buf)/trunc
 b←buf[p] ⋄ p←p+1 ⋄ nbytes←nbytes+1
 result←result+(128|b)×2*shift
 →(0≠⌊b÷128)/cont
 →((nbytes>1)∧(b=0))/noncanon
 Z←result p EC_OK ⋄ →0
 cont:shift←shift+7 ⋄ →lp
 trunc:Z←0 p EC_TRUNCATED_INPUT ⋄ →0
 noncanon:Z←0 p EC_NON_CANONICAL_ECF ⋄ →0
∇
