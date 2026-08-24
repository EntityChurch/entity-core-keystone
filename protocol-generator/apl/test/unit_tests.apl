⍝ entity-core-protocol-apl — test/unit_tests.apl
⍝
⍝ S2 codec unit suite: a covering test for EACH of N1–N4 plus the accept-path
⍝ directions the rejection-heavy corpus can't reach (the "always add an accept-path
⍝ test" durable lesson). Hand-rolled harness (no APL xUnit — profile [testing]).
⍝ Prints a machine-greppable  UNIT: ALL PASS  marker (the Makefile's gate).
⍝ →-branch flow control (A-APL-012). Loaded last, after the codec modules.

gFail←0

⍝ ⍺ = condition (1 pass / 0 fail) ; ⍵ = test name.
∇cond Check name
 →(cond)/ok
 ⎕←'  FAIL ',name ⋄ gFail←gFail+1 ⋄ →0
 ok:⎕←'  ok   ',name
∇

⍝ N1 — LEB128 varint widening routed through a real primitive (never a fixed byte).
∇TestN1;d
 ((VarintEncode 127)≡,127)Check'N1 varint 127 = 7f (single byte)'
 ((VarintEncode 128)≡128 1)Check'N1 varint 128 = 80 01 (LEB128 widening)'
 ((VarintEncode 300)≡172 2)Check'N1 varint 300 = ac 02'
 d←1 VarintDecode 128 1
 (((1⊃d)=128)∧((2⊃d)=3)∧((3⊃d)=EC_OK))Check'N1 varint 128 decode round-trip'
∇

⍝ N2 — explicit recursive major-type-6 tag REJECT at every value head.
∇TestN2
 ((EC_TAG_REJECTED=3⊃CborDecode 192 97 65))Check'N2 top-level tag 0 (0xc0) rejected'
 ((EC_TAG_REJECTED=3⊃CborDecode 217 217 247 160))Check'N2 tag 55799 (d9 d9 f7) self-describe rejected'
 ((EC_TAG_REJECTED=3⊃CborDecode 161 97 107 192 0))Check'N2 tag nested in map value rejected (recursive)'
∇

⍝ N3 — the empty map is the single byte 0xA0 (and empty text/array/bytes boundaries).
∇TestN3;dec
 ((CborEncode EV_MAP ⍬)≡,160)Check'N3 empty map encodes to single byte 0xa0'
 dec←CborDecode ,160
 (((EV_MAP=1⊃1⊃dec)∧(2⊃dec)=1))Check'N3 0xa0 decodes to empty map (consumes 1)'
 ((CborEncode MkText'')≡,96)Check'N3 empty text -> 0x60'
 ((CborEncode EV_ARRAY ⍬)≡,128)Check'N3 empty array -> 0x80'
 ((CborEncode EV_BYTES ⍬)≡,64)Check'N3 empty bytes -> 0x40'
∇

⍝ N4 — entity fidelity: the ORIGINAL byte span is recoverable without re-serialize.
∇TestN4;ent;enc;sl;dec
 ent←EV_MAP((MkText'type')(MkText'a')(MkText'data')(EV_MAP((MkText'x')(MkUintI 1))))
 enc←CborEncode ent
 sl←CborScanLen enc 1
 (((1⊃sl)=≢enc)∧((2⊃sl)=EC_OK))Check'N4 scan_len spans exactly the entity bytes'
 dec←CborDecode enc
 (((2⊃dec)=≢enc)∧(EV_MAP=1⊃1⊃dec))Check'N4 decode consumes exactly the original span'
∇

⍝ accept-path: canonical map-key sort (length-then-lex) from NON-canonical input —
⍝ the corpus decode->encode path never exercises the sort (input is already
⍝ canonical), so this is its only coverage.
∇TestMapSort;m
 m←EV_MAP((MkText'aa')(MkUintI 2)(MkText'z')(MkUintI 1))
 ((CborEncode m)≡162 97 122 1 98 97 97 2)Check'accept-path: map key sort length-then-lex (z before aa)'
∇

⍝ accept-path: the Rule-4 shortest-float ladder MINIMIZES f64 -> f16/f32, plus
⍝ f16/f32/f64 identity round-trips (the octet-domain bit path, A-APL-005).
∇TestFloat
 ((CborEncode 1⊃CborDecode 251,63 240 0 0 0 0 0 0)≡249 60 0)Check'float f64 1.0 minimizes to f16 f93c00'
 ((CborEncode 1⊃CborDecode 251,127 240 0 0 0 0 0 0)≡249 124 0)Check'float f64 +inf minimizes to f16 f97c00'
 ((CborEncode 1⊃CborDecode 251,127 248 0 0 0 0 0 0)≡249 126 0)Check'float f64 NaN -> canonical f9 7e00'
 ((CborEncode 1⊃CborDecode 249 123 255)≡249 123 255)Check'float f16 65504 (max normal) round-trips'
 ((CborEncode 1⊃CborDecode 250 71 127 223 0)≡250 71 127 223 0)Check'float 65503 stays f32 (not f16)'
 ((CborEncode 1⊃CborDecode 251 63 241 153 153 153 153 153 154)≡251 63 241 153 153 153 153 153 154)Check'float 1.1 stays f64'
∇

⍝ mt1 negative-integer minimal head (value = -1 - n).
∇TestNint
 ((CborEncode EV_NINT(8⍴0))≡,32)Check'nint -1 -> 0x20'
 ((CborEncode EV_NINT((8⍴256)⊤24))≡56 24)Check'nint -25 -> 0x3818'
 ((CborEncode EV_NINT((8⍴256)⊤255))≡56 255)Check'nint -256 -> 0x38ff'
∇

⍝ the head-form self-test as a unit (A-APL-002 signed-tower via octet carrier).
∇TestHeadForm;st
 st←HeadFormSelfTest
 ((1⊃st)=1)Check'A-APL-002 head-form self-test {0,2^63-1,2^63,2^64-2,2^64-1}'
∇

⍝ accept-path CRYPTO: sign then VERIFY (the direction the sig corpus can't cover),
⍝ plus tamper-rejection. Ed25519 via the C-ABI native-fn shim.
∇TestCryptoAccept;seed;ent;sig;pub;bad
 seed←32⍴0
 ent←EV_MAP((MkText'type')(MkText'test/v1')(MkText'data')(EV_MAP((MkText'x')(MkUintI 1))))
 sig←seed Sign ent
 ((≢sig)=64)Check'accept-path: Ed25519 sign produces a 64-byte signature'
 pub←EcSeedPub seed
 ((pub Verify ent sig)=1)Check'accept-path: sign->verify round-trips (VALID)'
 bad←1,63⍴0
 ((pub Verify ent bad)=0)Check'accept-path: verify REJECTS a tampered signature'
∇

∇Summary
 →(gFail≠0)/bad
 ⎕←'' ⋄ ⎕←'UNIT: ALL PASS' ⋄ →0
 bad:⎕←'' ⋄ ⎕←'UNIT: ',(⍕gFail),' FAIL'
∇

TestHeadForm
TestN1
TestN2
TestN3
TestN4
TestMapSort
TestFloat
TestNint
TestCryptoAccept
Summary
)OFF
