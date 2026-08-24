⍝ entity-core-protocol-apl — test/conformance.apl
⍝
⍝ S2 FULL codec conformance driver (THE GATE). Decodes the pinned v0.8.0 corpus
⍝ (conformance-vectors-v1.cbor) with OUR OWN array decoder and asserts per vector:
⍝   encode_equal : our re-encode of `input` == `canonical` bytes, byte-identical
⍝   decode_reject: our decoder REJECTS `canonical` (N2 tag scan OR trailing bytes)
⍝ Class B (content_hash / peer_id / signature) is reconstructed through the codec
⍝ + the C-ABI crypto/base58 (native-fn shim). A byte disagreement means OUR code
⍝ is wrong (never the vector). Target: 69/69 (0 fail, 0 skip).
⍝
⍝ Prints a machine-greppable  CONFORMANCE: ALL PASS  marker on success (the
⍝ Makefile's gate). Loaded last, after status/varint/cbor/ffi/entity.
⍝ →-branch flow control (A-APL-012).

⍝ value bound to TEXT key `key` (octet vector, ⍺) in map value m (⍵), or ABSENT.
∇Z←key MapGetV m;p;np;i;kv
 Z←EV_ABSENT ⍬
 →(EV_MAP≠1⊃m)/0
 p←2⊃m ⋄ np←(≢p)÷2 ⋄ i←0
 lp:→(i≥np)/0
 i←i+1 ⋄ kv←(¯1+2×i)⊃p
 →((EV_TEXT≠1⊃kv)∨(key≢2⊃kv))/nxt
 Z←(2×i)⊃p ⋄ →0
 nxt:→lp
∇

⍝ a TEXT field's value as an APL char string (⍺ = field name, ⍵ = vector map).
∇Z←key GetStr vec
 Z←⎕UCS 2⊃(⎕UCS key)MapGetV vec
∇

⍝ category = id up to the first '.' (e.g. "peer_id.3" -> "peer_id").
∇Z←Category s;p
 p←s⍳'.' ⋄ Z←(p-1)↑s
∇

⍝ lowercase hex of an octet vector (mismatch reporting).
∇Z←HexStr b;d;i;v
 d←'0123456789abcdef' ⋄ Z←'' ⋄ i←0
 lp:→(i≥≢b)/0
 i←i+1 ⋄ v←b[i]
 Z←Z,d[1+⌊v÷16],d[1+16|v]
 →lp
∇

⍝ a decode_reject vector passes iff decoding CANON as a COMPLETE message fails:
⍝ the decoder errors (N2 tag scanner) OR it does not consume the whole input.
∇Z←AssertReject canon;dec
 dec←CborDecode canon
 Z←(EC_OK≠3⊃dec)∨(≢canon)≠2⊃dec
∇

⍝ ── the gate ──
∇RunConformance;st;buf;dec;top;vecs;nvec;i;vec;ids;kinds;cat;canon;inputv;got;npass;nfail;fmt;fcv;typev;datav;kt;ht;dig;ascii;seed;entity;ok
 st←HeadFormSelfTest
 →(0=1⊃st)/hfbad
 ⎕←'head-form self-test: ',⊃2⊃st
 buf←⎕FIO[26]'../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor'
 buf←⎕UCS buf
 dec←CborDecode buf
 →(EC_OK≠3⊃dec)/decbad
 top←1⊃dec
 →(EV_ARRAY≠1⊃top)/arrbad
 vecs←2⊃top ⋄ nvec←≢vecs ⋄ npass←0 ⋄ nfail←0 ⋄ i←0
 lp:→(i≥nvec)/done
 i←i+1 ⋄ vec←i⊃vecs
 ids←'id'GetStr vec ⋄ kinds←'kind'GetStr vec ⋄ cat←Category ids
 canon←2⊃(⎕UCS'canonical')MapGetV vec
 →(kinds≡'decode_reject')/rej
 inputv←(⎕UCS'input')MapGetV vec
 →(cat≡'peer_id')/cpeer
 →(cat≡'content_hash')/chash
 →(cat≡'signature')/csig
 got←CborEncode inputv ⋄ →cmp
 cpeer:kt←256⊥2⊃(⎕UCS'key_type')MapGetV inputv ⋄ ht←256⊥2⊃(⎕UCS'hash_type')MapGetV inputv ⋄ dig←2⊃(⎕UCS'digest')MapGetV inputv ⋄ ascii←PeeridFormat kt ht dig ⋄ got←CborEncode EV_TEXT ascii ⋄ →cmp
 chash:typev←(⎕UCS'type')MapGetV inputv ⋄ datav←(⎕UCS'data')MapGetV inputv ⋄ fcv←(⎕UCS'format_code')MapGetV inputv ⋄ fmt←0 ⋄ →(EV_UINT≠1⊃fcv)/chdo ⋄ fmt←256⊥2⊃fcv
 chdo:got←fmt ContentHash typev datav ⋄ →cmp
 csig:seed←2⊃(⎕UCS'seed')MapGetV inputv ⋄ entity←(⎕UCS'entity')MapGetV inputv ⋄ got←seed Sign entity ⋄ →cmp
 cmp:→(got≡canon)/pass
 nfail←nfail+1 ⋄ ⎕←'  FAIL ',ids,': want=',(HexStr canon),' got=',HexStr got ⋄ →lp
 rej:→(AssertReject canon)/pass
 nfail←nfail+1 ⋄ ⎕←'  FAIL ',ids,': expected decode reject, decoded cleanly' ⋄ →lp
 pass:npass←npass+1 ⋄ →lp
 done:⎕←''
 ⎕←'=== conformance: ',(⍕nvec),' vectors — ',(⍕npass),' pass / ',(⍕nfail),' fail / 0 skip ==='
 →(nfail≠0)/failmark
 ⎕←'CONFORMANCE: ALL PASS (',(⍕npass),'/',(⍕nvec),')' ⋄ →0
 failmark:⎕←'CONFORMANCE: FAIL' ⋄ →0
 hfbad:⎕←'FATAL: head-form self-test FAILED: ',⊃2⊃st ⋄ ⎕←'CONFORMANCE: FAIL' ⋄ →0
 decbad:⎕←'FATAL: corpus did not decode, rc=',⍕3⊃dec ⋄ ⎕←'CONFORMANCE: FAIL' ⋄ →0
 arrbad:⎕←'FATAL: corpus top-level is not an array' ⋄ ⎕←'CONFORMANCE: FAIL' ⋄ →0
∇

RunConformance
)OFF
