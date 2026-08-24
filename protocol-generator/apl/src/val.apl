⍝ entity-core-protocol-apl — src/val.apl (peer-altitude value helpers on the S2 codec).
⍝
⍝ The S2 codec (cbor.apl) speaks the tagged (kind payload) value model (A-APL-011): a
⍝ value is a 2-element nested array — kind scalar (EV_*, status.apl) + a payload array.
⍝ A MAP payload is a nested vector of enclosed values alternating k,v,k,v; an ARRAY
⍝ payload is a nested vector of enclosed values. This module is the protocol-altitude
⍝ analogue of the Fortran val.f90 / Rexx ecf.rex layer: map/array BUILDERS + typed field
⍝ READS, so peer code reads `m VmPut('peer_id')(VText pid)` and `map MText'peer_id'`
⍝ rather than restating the value layout at every call site.
⍝
⍝ Control flow is →-branch tradfns for scans/loops + branch-free dfns for pure builders
⍝ (A-APL-012: GNU APL 1.9 --script rejects :If/:For AND the dfn `:` guard). Text is ASCII
⍝ protocol vocabulary → ⎕UCS is byte-identical (UTF-8 caveat A-APL-011 for non-ASCII).

⍝ ════════════ pure value constructors (dfns) ════════════
VMapEmpty←EV_MAP ⍬                               ⍝ the empty map value (payload ⍬)
VArrEmpty←EV_ARRAY ⍬                             ⍝ the empty array value
VText←{EV_TEXT(,⎕UCS ⍵)}                         ⍝ APL char string -> EV_TEXT value (ASCII; raveled)
VTextB←{EV_TEXT ⍵}                               ⍝ text value from raw octet vector
VBytes←{EV_BYTES ⍵}                              ⍝ octet vector -> EV_BYTES value
VUint←{EV_UINT((8⍴256)⊤⍵)}                       ⍝ small int (< 2^63) -> EV_UINT value
VBool←{EV_BOOL ⍵}                                ⍝ 0|1 -> EV_BOOL value
VNull←EV_NULL 0
VKindOf←{1⊃⍵}                                    ⍝ a value's kind discriminant
VPayload←{2⊃⍵}
VIsMap←{EV_MAP≡1⊃⍵} ⋄ VIsArray←{EV_ARRAY≡1⊃⍵}
VIsText←{EV_TEXT≡1⊃⍵} ⋄ VIsBytes←{EV_BYTES≡1⊃⍵}
VStr←{⎕UCS ,2⊃⍵}                                 ⍝ EV_TEXT/EV_BYTES value -> APL char string
ArrCount←{(EV_ARRAY=1⊃⍵)×≢2⊃⍵}                  ⍝ #elements (0 if not an array)

⍝ ════════════ map / array mutators (dyadic tradfns) ════════════
⍝ append (key val) to a map -> a NEW map. The encoder re-sorts to canonical order
⍝ (§4.2.1), so build order is irrelevant. ⍺=map value ; ⍵=(keyString)(value).
∇Z←m VmPut kv;key;val
 key←1⊃kv ⋄ val←2⊃kv
 Z←EV_MAP((2⊃m),(⊂VText key),(⊂val))
∇

⍝ append a value to an array -> a NEW array. ⍺=array value ; ⍵=value.
∇Z←a VArrAdd v
 Z←EV_ARRAY((2⊃a),⊂v)
∇

⍝ i-th element (1-based) of an array value (EV_ABSENT if out of range).
∇Z←a ArrItem i;p
 Z←EV_ABSENT ⍬
 →(EV_ARRAY≠1⊃a)/0
 p←2⊃a
 →((i<1)∨(i>≢p))/0
 Z←i⊃p
∇

⍝ ════════════ map field reads (dyadic tradfns) ════════════
⍝ value at text key `⍵` in map `⍺` (EV_ABSENT if absent / not a map).
∇Z←m MGet key;p;np;i;kv;target
 Z←EV_ABSENT ⍬
 →(EV_MAP≠1⊃m)/0
 p←2⊃m ⋄ np←⌊(≢p)÷2 ⋄ target←,⎕UCS key ⋄ i←0
 lp:→(i≥np)/0
 i←i+1
 kv←(¯1+2×i)⊃p
 →(EV_TEXT≠1⊃kv)/nx
 →(~target≡,2⊃kv)/nx
 Z←(2×i)⊃p ⋄ →0
 nx:→lp
∇

⍝ is text key `⍵` present in map `⍺` (present-empty vs absent — the §4.5 seam).
∇Z←m MHas key
 Z←EV_ABSENT≢1⊃m MGet key
∇

⍝ text field as an APL char string; '' if absent or not text.
∇Z←m MText key;v
 Z←''
 v←m MGet key
 →(EV_TEXT≠1⊃v)/0
 Z←⎕UCS ,2⊃v
∇

⍝ byte field as raw octets; ⍬ if absent or not bytes.
∇Z←m MBytes key;v
 Z←⍬
 v←m MGet key
 →((EV_BYTES≠1⊃v)∧(EV_TEXT≠1⊃v))/0
 Z←,2⊃v
∇

⍝ uint field -> (value present): value is the 8-octet carrier; present←0 if absent/not uint.
⍝ For timestamps/status/thresholds (all << 2^63) the caller collapses via 256⊥ safely.
∇Z←m MUintOct key;v
 Z←(8⍴0)0
 v←m MGet key
 →(EV_UINT≠1⊃v)/0
 Z←(2⊃v)1
∇

⍝ uint field as a scalar (caller-guaranteed < 2^63: ms timestamps, depths, thresholds).
∇Z←m MUint key;r
 r←m MUintOct key
 Z←(256⊥1⊃r)(2⊃r)
∇

⍝ bool field (0/1); 0 if absent or not bool.
∇Z←m MBool key;v
 Z←0
 v←m MGet key
 →(EV_BOOL≠1⊃v)/0
 Z←2⊃v
∇

⍝ sub-map field; EV_ABSENT if absent / not a map.
∇Z←m MSubmap key;v
 v←m MGet key
 Z←v
 →(EV_MAP=1⊃v)/0
 Z←EV_ABSENT ⍬
∇

⍝ array field; EV_ABSENT if absent / not an array.
∇Z←m MArray key;v
 v←m MGet key
 Z←v
 →(EV_ARRAY=1⊃v)/0
 Z←EV_ABSENT ⍬
∇

⍝ ════════════ list helpers ════════════
⍝ the TEXT items of an array value as a nested vector of APL char strings (non-text
⍝ items skipped); empty for absent / non-array / present-empty.
∇Z←TextList a;n;i;it
 Z←⍬ ⋄ n←ArrCount a ⋄ i←0
 lp:→(i≥n)/0
 i←i+1
 it←a ArrItem i
 →(EV_TEXT≠1⊃it)/lp
 Z←Z,⊂⎕UCS 2⊃it
 →lp
∇

⍝ a text array value from a blank-separated word string (the §4.4 helper).
∇Z←VTextArray words;w;i;s;n
 Z←VArrEmpty ⋄ w←,words ⋄ n←≢w ⋄ i←1
 lp:→(i>n)/0
 →(w[i]=' ')/adv
 s←i
 sc:→(i>n)/emit ⋄ →(w[i]=' ')/emit ⋄ i←i+1 ⋄ →sc
 emit:Z←Z VArrAdd VText w[(s-1)+⍳i-s] ⋄ →lp
 adv:i←i+1 ⋄ →lp
∇

⍝ a §5.4 scope map {include: [patterns...]} from a blank-separated pattern string.
∇Z←VScope patterns
 Z←VMapEmpty VmPut('include')(VTextArray patterns)
∇

⍝ ════════════ hex / string bridges ════════════
HexLc←{H←'0123456789abcdef' ⋄ ∊H[1+,⍉(16 16)⊤⍵]}   ⍝ lowercase hex of an octet vector
∇Z←HexToBytes s;n;hi;lo;i;D
 D←'0123456789abcdef'
 n←⌊(≢s)÷2 ⋄ Z←n⍴0 ⋄ i←0
 lp:→(i≥n)/0
 i←i+1
 hi←¯1+D⍳s[¯1+2×i] ⋄ lo←¯1+D⍳s[2×i]
 Z[i]←(16×16|hi)+16|lo
 →lp
∇
IsHexStr←{∧/⍵∊'0123456789abcdef'}
