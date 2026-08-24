⍝ entity-core-protocol-apl — src/cbor.apl
⍝
⍝ THE ARRAY-MODEL PROBE. Canonical ECF (RFC 8949 §4.2 deterministic CBOR) VALUE
⍝ codec in PURE APL. The whole codec is ARRAY transforms — base-256 ⊤/⊥ over octet
⍝ vectors, a ⍋-graded length-then-lex map-key permutation, ∊/,/↑/↓/⊂/⊃ for buffer
⍝ assembly — not scalar byte-shuffling. Read as native APL, not Fortran-in-APL.
⍝
⍝ ── Value model (A-APL-011) ──
⍝ A value is a nested (kind payload) pair. `kind` is an integer major-type
⍝ discriminant (EV_*, status.apl) carrying int-vs-float AND byte-vs-text intent
⍝ EXPLICITLY. payload: EV_UINT/EV_NINT -> an 8-octet big-endian vector (carrier);
⍝ EV_BYTES/EV_TEXT -> octet vector (poss. ⍬); EV_ARRAY -> nested vector of values;
⍝ EV_MAP -> nested vector alternating k,v,k,v; EV_FLOAT -> 8-octet f64-BIT vector;
⍝ EV_BOOL -> 0|1 ; EV_NULL -> 0.
⍝
⍝ ── The uint64 octet-array carrier (A-APL-002/003) ──
⍝ GNU APL's exact integer is signed int64 (ceiling 2^63-1); at/above 2^63 it
⍝ SILENTLY promotes to lossy IEEE double. So a CBOR unsigned-integer HEAD in
⍝ [2^63, 2^64-1] is NEVER materialized as an APL scalar: unsigned / negative-int
⍝ payloads live as an 8-octet big-endian vector end-to-end. 256⊥ is used ONLY for
⍝ values provably < 2^63 (container lengths). The minimal-head ladder compares
⍝ octet RANGES (which high octets are zero), never a >2^63 scalar. Guarded by the
⍝ head-form self-test on {0, 2^63-1, 2^63, 2^64-2, 2^64-1}.
⍝
⍝ ── The float tower (A-APL-005) ──
⍝ APL has native IEEE binary64 but NO bit-reinterpret primitive (no `transfer`).
⍝ f64/f32/f16 IEEE bits are hand-rolled arithmetic decomposition: sign / biased
⍝ exponent / mantissa via ⌊ , | (modulo) and ×/÷ powers of two — never ∧ (boolean
⍝ AND, not bitwise). The Rule-4 shortest-float ladder tries f16 then f32 then f64,
⍝ and VERIFIES each downcast by converting back up and comparing octets. All
⍝ conversions work in the OCTET domain so the f64 sign bit never forces a >2^63
⍝ scalar.
⍝
⍝ ── N2 / N3 / N4 ──  Decode runs an explicit recursive major-type-6 REJECT at
⍝ every value head (N2); the empty map is the single byte 0xA0 (N3, via the
⍝ shortest-head ladder); CborScanLen spans a value's ORIGINAL bytes without
⍝ re-serializing (N4).
⍝
⍝ ── Control flow (A-APL-012) ── GNU APL 1.9's --script ∇-editor does NOT accept
⍝ the :If/:For/:Select control-structure extension (nor does its ⎕FX). So the pure
⍝ codec transforms are single-line DFNS (guards + ⋄) per the profile's intent, and
⍝ the stateful decode / float-with-loop / self-test paths are TRADFNS with classic
⍝ →-branch flow control + labels. Decode threads position through workspace globals
⍝ gBuf / gPos / gRc (single image, one thread — §7b structural).

⍝ ════════════════════════════ pure helpers (dfns) ════════════════════════════
Oct8←{(8⍴256)⊤⍵}                                  ⍝ int (< 2^63) -> 8 big-endian octets
MkText←{EV_TEXT(⎕UCS ⍵)}                          ⍝ APL char string -> EV_TEXT value
MkBytes←{EV_BYTES ⍵}                              ⍝ octet vector -> EV_BYTES value
MkUintI←{EV_UINT((8⍴256)⊤⍵)}                      ⍝ small int (< 2^63) -> EV_UINT value

⍝ ════════════════════════════════ ENCODE (tradfns) ════════════════════════════════
⍝ (A-APL-012: dispatch/guard logic is →-branch tradfns — GNU APL 1.9's --script
⍝ reader rejects the dfn `:` guard as immediate-mode control flow. Branch-free pure
⍝ transforms below stay dfns, per the profile's dfn intent.)

⍝ Emit a CBOR head: major-type base byte (⍺) + the SHORTEST argument encoding of
⍝ the 8-octet big-endian bit pattern ⍵. The ladder compares which high octets are
⍝ zero, so a value in [2^63, 2^64-1] (top-octet high bit set) still lands in the
⍝ 8-byte arm without forming the scalar.
∇Z←base EmitHead oc
 →(∧/0=7↑oc)/lt256
 →(∧/0=6↑oc)/lt64k
 →(∧/0=4↑oc)/lt4g
 Z←(base+27),oc ⋄ →0
 lt256:→((8⊃oc)<24)/tiny ⋄ Z←(base+24),8⊃oc ⋄ →0
 tiny:Z←,base+8⊃oc ⋄ →0
 lt64k:Z←(base+25),¯2↑oc ⋄ →0
 lt4g:Z←(base+26),¯4↑oc ⋄ →0
∇

⍝ concat-encode a nested vector of values (array elements / already-ordered pairs).
∇Z←EncSeq p
 →(0=≢p)/empty
 Z←∊CborEncode¨p ⋄ →0
 empty:Z←⍬
∇

⍝ Canonical-encode one value (a (kind payload) pair) into an octet vector.
∇Z←CborEncode V;k;p
 k←1⊃V ⋄ p←2⊃V
 →(k=EV_UINT)/uk
 →(k=EV_NINT)/nk
 →(k=EV_BYTES)/bk
 →(k=EV_TEXT)/tk
 →(k=EV_ARRAY)/ak
 →(k=EV_MAP)/mk
 →(k=EV_FLOAT)/fk
 →(k=EV_BOOL)/bok
 →(k=EV_NULL)/nlk
 Z←⍬ ⋄ →0
 uk:Z←0 EmitHead p ⋄ →0
 nk:Z←32 EmitHead p ⋄ →0
 bk:Z←(64 EmitHead Oct8 ≢p),p ⋄ →0
 tk:Z←(96 EmitHead Oct8 ≢p),p ⋄ →0
 ak:Z←(128 EmitHead Oct8 ≢p),EncSeq p ⋄ →0
 mk:Z←EncMap p ⋄ →0
 fk:Z←EncFloat p ⋄ →0
 bok:Z←,244+p ⋄ →0
 nlk:Z←,246 ⋄ →0
∇

⍝ Emit a map's k,v pairs in RFC 8949 §4.2.1 order (encoded-key length-then-lex).
⍝ N3: an empty map is the single header byte 0xA0. Keys are encoded once, sorted
⍝ by the ⍋-graded (length,bytes) matrix, then emitted with their values.
∇Z←EncMap p;np;keys;vals;ord;i;j
 np←(≢p)÷2
 →(np=0)/empty
 keys←CborEncode¨p[¯1+2×⍳np]
 vals←p[2×⍳np]
 ord←KeySort keys
 Z←160 EmitHead Oct8 np
 i←0
 lp:→(i≥np)/0
 i←i+1 ⋄ j←ord[i]
 Z←Z,(j⊃keys),CborEncode j⊃vals
 →lp
 empty:Z←,160
∇

⍝ permutation ordering encoded-key octet-vectors by length-then-lex. Build a
⍝ (np , 1+maxlen) matrix [length , bytes , zero-pad] and grade its rows: the length
⍝ column dominates (different lengths never tie), so pad value is immaterial.
∇Z←KeySort keys;mx;m;i;k
 mx←⌈/≢¨keys
 m←(0,1+mx)⍴0
 i←0
 lp:→(i≥≢keys)/g
 i←i+1 ⋄ k←i⊃keys
 m←m⍪(≢k),k,(mx-≢k)⍴0
 →lp
 g:Z←⍋m
∇

⍝ ──────────────────── float encode (Rule 4 ladder) ────────────────────
⍝ ⍵ = 8 f64-bit octets. Try f16, then f32, then f64; NaN -> canonical f9 7e00.
∇Z←EncFloat oc;f;h;g
 f←F64Fields oc
 →(((2⊃f)=2047)∧(3⊃f)≠0)/nan
 h←TryF16 oc
 →(¯1≢h)/f16
 g←TryF32 oc
 →(¯1≢g)/f32
 Z←251,oc ⋄ →0
 nan:Z←249 126 0 ⋄ →0
 f16:Z←249,h ⋄ →0
 f32:Z←250,g ⋄ →0
∇

⍝ assemble 8 f64 octets from fields (s e11 m52); m52 < 2^52 so all exact.
F64Octets←{s←1⊃⍵ ⋄ e11←2⊃⍵ ⋄ m52←3⊃⍵ ⋄ ((128×s)+⌊e11÷16),((16×16|e11)+⌊m52÷2*48),(6⍴256)⊤(2*48)|m52}

⍝ extract (s e11 m52) from 8 f64 octets; m52 via 256⊥ over 7 items (< 2^52, exact).
F64Fields←{s←⌊⍵[1]÷128 ⋄ e11←(16×128|⍵[1])+⌊⍵[2]÷16 ⋄ m52←256⊥(16|⍵[2]),⍵[2+⍳6] ⋄ s e11 m52}

⍝ ════════════════════════════════ DECODE (tradfns) ════════════════════════════════

⍝ Decode ONE canonical value from `buf` (from position 1). Returns (value consumed
⍝ rc). Runs the recursive major-type-6 tag REJECT (N2) and rejects indefinite /
⍝ reserved additional-info.
∇Z←CborDecode buf;v
 gBuf←buf ⋄ gPos←1 ⋄ gRc←EC_OK
 v←DecOne 0
 Z←v(gPos-1)gRc
∇

∇Z←DecOne depth;b;major;ai;arg;n;i;kids
 Z←EV_ABSENT ⍬
 →(gRc≠EC_OK)/0
 →(depth>MAX_DEPTH)/derr
 →(gPos>≢gBuf)/dtrunc
 b←gBuf[gPos] ⋄ major←⌊b÷32 ⋄ ai←32|b ⋄ gPos←gPos+1
 →(major=6)/dtag
 →(major=7)/dsimple
 arg←ReadArg ai
 →(gRc≠EC_OK)/0
 →(major=0)/m0
 →(major=1)/m1
 →(major=2)/m2
 →(major=3)/m3
 →(major=4)/m4
 →(major=5)/m5
 →0
 m0:Z←EV_UINT arg ⋄ →0
 m1:Z←EV_NINT arg ⋄ →0
 m2:n←256⊥arg ⋄ Z←EV_BYTES(TakeBytes n) ⋄ →0
 m3:n←256⊥arg ⋄ Z←EV_TEXT(TakeBytes n) ⋄ →0
 m4:n←256⊥arg ⋄ kids←⍬ ⋄ i←0
 m4lp:→(i≥n)/m4done ⋄ kids←kids,⊂DecOne depth+1 ⋄ →(gRc≠EC_OK)/0 ⋄ i←i+1 ⋄ →m4lp
 m4done:Z←EV_ARRAY kids ⋄ →0
 m5:n←256⊥arg ⋄ kids←⍬ ⋄ i←0
 m5lp:→(i≥2×n)/m5done ⋄ kids←kids,⊂DecOne depth+1 ⋄ →(gRc≠EC_OK)/0 ⋄ i←i+1 ⋄ →m5lp
 m5done:Z←EV_MAP kids ⋄ →0
 dsimple:Z←DecSimple ai ⋄ →0
 dtag:gRc←EC_TAG_REJECTED ⋄ →0
 dtrunc:gRc←EC_TRUNCATED_INPUT ⋄ →0
 derr:gRc←EC_NON_CANONICAL_ECF ⋄ →0
∇

⍝ major-7 simple / float head. Reject undefined (0xf7) / break / reserved.
∇Z←DecSimple ai;raw
 Z←EV_ABSENT ⍬
 →(ai=20)/s20
 →(ai=21)/s21
 →(ai=22)/s22
 →(ai=25)/s25
 →(ai=26)/s26
 →(ai=27)/s27
 gRc←EC_NON_CANONICAL_ECF ⋄ →0
 s20:Z←EV_BOOL 0 ⋄ →0
 s21:Z←EV_BOOL 1 ⋄ →0
 s22:Z←EV_NULL 0 ⋄ →0
 s25:→((gPos+1)>≢gBuf)/strunc ⋄ raw←gBuf[gPos+¯1+⍳2] ⋄ gPos←gPos+2 ⋄ Z←EV_FLOAT(F16toF64 raw) ⋄ →0
 s26:→((gPos+3)>≢gBuf)/strunc ⋄ raw←gBuf[gPos+¯1+⍳4] ⋄ gPos←gPos+4 ⋄ Z←EV_FLOAT(F32toF64 raw) ⋄ →0
 s27:→((gPos+7)>≢gBuf)/strunc ⋄ raw←gBuf[gPos+¯1+⍳8] ⋄ gPos←gPos+8 ⋄ Z←EV_FLOAT raw ⋄ →0
 strunc:gRc←EC_TRUNCATED_INPUT ⋄ →0
∇

⍝ read a major-0..5 argument per the additional-info byte; reject indefinite (31)
⍝ and reserved 28..30. Returns an 8-octet big-endian arg (the uint carrier).
∇Z←ReadArg ai;nb;raw
 Z←8⍴0
 →(ai<24)/tiny
 →(ai=24)/n1
 →(ai=25)/n2
 →(ai=26)/n4
 →(ai=27)/n8
 gRc←EC_NON_CANONICAL_ECF ⋄ →0
 tiny:Z←(8⍴256)⊤ai ⋄ →0
 n1:nb←1 ⋄ →rd
 n2:nb←2 ⋄ →rd
 n4:nb←4 ⋄ →rd
 n8:nb←8 ⋄ →rd
 rd:→((gPos+nb-1)>≢gBuf)/rtrunc ⋄ raw←gBuf[gPos+¯1+⍳nb] ⋄ gPos←gPos+nb ⋄ Z←((8-nb)⍴0),raw ⋄ →0
 rtrunc:gRc←EC_TRUNCATED_INPUT ⋄ →0
∇

∇Z←TakeBytes n
 Z←⍬
 →(n<0)/ttrunc
 →((gPos+n-1)>≢gBuf)/ttrunc
 →(n=0)/tz
 Z←gBuf[gPos+¯1+⍳n]
 tz:gPos←gPos+n ⋄ →0
 ttrunc:gRc←EC_TRUNCATED_INPUT ⋄ →0
∇

⍝ ──────────────────── float decode (arithmetic bit assembly) ────────────────────

∇Z←F16toF64 oc;hi;lo;s;e5;m10;m;E
 hi←oc[1] ⋄ lo←oc[2]
 s←⌊hi÷128 ⋄ e5←32|⌊hi÷4 ⋄ m10←(256×4|hi)+lo
 →(e5=0)/zero
 →(e5=31)/special
 Z←F64Octets s((e5-15)+1023)(m10×2*42) ⋄ →0
 zero:→(m10≠0)/subn
 Z←F64Octets s 0 0 ⋄ →0
 subn:E←¯14 ⋄ m←m10
 sl:→(0≠⌊m÷1024)/sd ⋄ m←m×2 ⋄ E←E-1 ⋄ →sl
 sd:Z←F64Octets s(E+1023)((1024|m)×2*42) ⋄ →0
 special:→(m10≠0)/nan
 Z←F64Octets s 2047 0 ⋄ →0
 nan:Z←F64Octets s 2047(2*51) ⋄ →0
∇

∇Z←F32toF64 oc;f32i;s;e8;m23;m;E
 f32i←256⊥oc
 s←⌊f32i÷2*31 ⋄ e8←256|⌊f32i÷2*23 ⋄ m23←(2*23)|f32i
 →(e8=255)/special
 →(e8=0)/zero
 Z←F64Octets s((e8-127)+1023)(m23×2*29) ⋄ →0
 zero:→(m23≠0)/subn
 Z←F64Octets s 0 0 ⋄ →0
 subn:E←¯126 ⋄ m←m23
 sl:→(0≠⌊m÷2*23)/sd ⋄ m←m×2 ⋄ E←E-1 ⋄ →sl
 sd:Z←F64Octets s(E+1023)(((2*23)|m)×2*29) ⋄ →0
 special:→(m23≠0)/nan
 Z←F64Octets s 2047 0 ⋄ →0
 nan:Z←F64Octets s 2047(2*51) ⋄ →0
∇

⍝ try to represent the f64 value (8 octets) EXACTLY as f16 -> 2 octets, else ¯1.
⍝ Verified by converting the candidate back up and comparing octets.
∇Z←TryF16 oc;f;s;e11;m52;E;e5;m10;hi;lo;cand
 Z←¯1
 f←F64Fields oc ⋄ s←1⊃f ⋄ e11←2⊃f ⋄ m52←3⊃f
 →(e11=2047)/isinf
 →(e11=0)/iszero
 E←e11-1023
 →((E<¯14)∨(E>15))/0
 →(0≠(2*42)|m52)/0
 e5←E+15 ⋄ m10←⌊m52÷2*42 ⋄ →build
 isinf:→(m52≠0)/0 ⋄ e5←31 ⋄ m10←0 ⋄ →build
 iszero:→(m52≠0)/0 ⋄ e5←0 ⋄ m10←0 ⋄ →build
 build:hi←(128×s)+(4×e5)+⌊m10÷256 ⋄ lo←256|m10 ⋄ cand←hi,lo ⋄ →(oc≢F16toF64 cand)/0 ⋄ Z←cand
∇

⍝ try to represent the f64 value (8 octets) EXACTLY as f32 -> 4 octets, else ¯1.
∇Z←TryF32 oc;f;s;e11;m52;E;e8;m23;f32i;cand
 Z←¯1
 f←F64Fields oc ⋄ s←1⊃f ⋄ e11←2⊃f ⋄ m52←3⊃f
 →(e11=2047)/isinf
 →(e11=0)/iszero
 E←e11-1023
 →((E<¯126)∨(E>127))/0
 →(0≠(2*29)|m52)/0
 e8←E+127 ⋄ m23←⌊m52÷2*29 ⋄ →build
 isinf:→(m52≠0)/0 ⋄ e8←255 ⋄ m23←0 ⋄ →build
 iszero:→(m52≠0)/0 ⋄ e8←0 ⋄ m23←0 ⋄ →build
 build:f32i←((2*31)×s)+((2*23)×e8)+m23 ⋄ cand←(4⍴256)⊤f32i ⋄ →(oc≢F32toF64 cand)/0 ⋄ Z←cand
∇

⍝ ──────────────────── scan / fidelity (N4) ────────────────────

⍝ byte length of the CBOR item at (buf pos) WITHOUT building a value — the
⍝ entity-fidelity primitive (N4): a peer forwards the ORIGINAL span, never a
⍝ re-encode. Also runs the N2 tag reject. ⍵ = (buf)(pos). Returns (length rc).
∇Z←CborScanLen bp;start
 gBuf←1⊃bp ⋄ gPos←2⊃bp ⋄ gRc←EC_OK ⋄ start←gPos
 ScanOne 0
 Z←(gPos-start)gRc
∇

∇ScanOne depth;b;major;ai;arg;n;i
 →(gRc≠EC_OK)/0
 →(depth>MAX_DEPTH)/serr
 →(gPos>≢gBuf)/strunc
 b←gBuf[gPos] ⋄ major←⌊b÷32 ⋄ ai←32|b ⋄ gPos←gPos+1
 →(major=6)/stag
 →(major=7)/s7
 arg←ReadArg ai
 →(gRc≠EC_OK)/0
 →(major=2)/sbytes
 →(major=3)/sbytes
 →(major=4)/sarr
 →(major=5)/smap
 →0
 sbytes:n←256⊥arg ⋄ →((n<0)∨(gPos+n-1)>≢gBuf)/strunc ⋄ gPos←gPos+n ⋄ →0
 sarr:n←256⊥arg ⋄ i←0
 salp:→(i≥n)/0 ⋄ ScanOne depth+1 ⋄ →(gRc≠EC_OK)/0 ⋄ i←i+1 ⋄ →salp
 smap:n←256⊥arg ⋄ i←0
 smlp:→(i≥2×n)/0 ⋄ ScanOne depth+1 ⋄ →(gRc≠EC_OK)/0 ⋄ i←i+1 ⋄ →smlp
 s7:→(ai=20)/0 ⋄ →(ai=21)/0 ⋄ →(ai=22)/0 ⋄ →(ai=25)/s7a ⋄ →(ai=26)/s7b ⋄ →(ai=27)/s7c ⋄ gRc←EC_NON_CANONICAL_ECF ⋄ →0
 s7a:gPos←gPos+2 ⋄ →s7chk
 s7b:gPos←gPos+4 ⋄ →s7chk
 s7c:gPos←gPos+8 ⋄ →s7chk
 s7chk:→((gPos-1)>≢gBuf)/strunc ⋄ →0
 stag:gRc←EC_TAG_REJECTED ⋄ →0
 strunc:gRc←EC_TRUNCATED_INPUT ⋄ →0
 serr:gRc←EC_NON_CANONICAL_ECF ⋄ →0
∇

⍝ ──────────────────── head-form self-test (A-APL-002) ────────────────────

⍝ MANDATORY fixed-width uint64-boundary self-test: encode + decode round-trip
⍝ {0, 2^63-1, 2^63, 2^64-2, 2^64-1} byte-exact via the OCTET-ARRAY path — the five
⍝ payloads are authored directly as octet vectors (NOT via 256⊤, which would
⍝ overflow). Returns (ok report).
∇Z←HeadFormSelfTest;vals;exp;i;oc;enc;expv;dec;dv
 vals←(⊂8⍴0),(⊂127,7⍴255),(⊂128,7⍴0),(⊂(7⍴255),254),(⊂8⍴255)
 exp←(⊂,0),(⊂27,127,7⍴255),(⊂27,128,7⍴0),(⊂27,(7⍴255),254),(⊂27,8⍴255)
 i←0
 lp:→(i≥5)/ok
 i←i+1
 oc←i⊃vals ⋄ enc←CborEncode EV_UINT oc ⋄ expv←i⊃exp
 →(enc≢expv)/bad
 dec←CborDecode enc ⋄ dv←1⊃dec
 →((EV_UINT≠1⊃dv)∨(oc≢2⊃dv))/bad
 →lp
 bad:Z←0(⊂'head-form mismatch at value ',⍕i) ⋄ →0
 ok:Z←1(⊂'all five {0, 2^63-1, 2^63, 2^64-2, 2^64-1} round-trip byte-exact via the octet-array path')
∇
