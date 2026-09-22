⍝ entity-core-protocol-apl — src/ent.apl (materialized entity {type,data,content_hash}).
⍝
⍝ A materialized entity (§1.1, §3.4) is a 4-element nested array
⍝   (present typeString dataValue hashBytes)
⍝ over the S2 value model. `present` (0|1) is the absent sentinel (A-APL-011 — an empty
⍝ type/data is a real wire value, so presence is an explicit cell, never inferred). The
⍝ content_hash covers ONLY {type,data} (§1.1) and is computed by the audited C-ABI floor
⍝ (0x00 varint || SHA-256(ECF({type,data}))) via entity.apl's ContentHash. The WIRE form
⍝ (EntToCbor) carries it as a third field; on decode (EntOfCbor) it is RECOMPUTED and
⍝ verified (§1.8 fidelity — trust the recompute, not the wire bytes).
⍝
⍝ →-branch tradfns for the stateful builders/readers (A-APL-012).

⍝ ── accessors (dfns) ──
EntPresent←{1⊃⍵} ⋄ EntType←{2⊃⍵} ⋄ EntDataV←{3⊃⍵} ⋄ EntHash←{4⊃⍵}
EntAbsent←0 '' (EV_ABSENT ⍬)(⍬)

⍝ the data as a MAP view (itself if a map, else the empty map — so field reads never fault).
∇Z←EntDataMap e;d
 d←3⊃e
 Z←d
 →(EV_MAP=1⊃d)/0
 Z←VMapEmpty
∇

⍝ construct a materialized entity, computing the §1.1 content_hash via the C-ABI floor.
∇Z←type EntMake dataV;h
 h←0 ContentHash(VText type)(dataV)
 Z←1(,type)(dataV)h
∇

⍝ the wire entity map {type, data, content_hash}.
∇Z←EntToCbor e;m
 m←VMapEmpty
 m←m VmPut('type')(VText 2⊃e)
 m←m VmPut('data')(3⊃e)
 m←m VmPut('content_hash')(VBytes 4⊃e)
 Z←m
∇

⍝ parse a wire entity map -> (entity rc); recompute + verify the §1.8 hash.
∇Z←EntOfCbor mv;type;data;e;carried
 Z←EntAbsent EC_DECODE_ERROR
 →(EV_MAP≠1⊃mv)/0
 →(~mv MHas'type')/0
 →(~mv MHas'data')/0
 type←mv MText'type'
 data←mv MGet'data'
 e←type EntMake data
 carried←mv MBytes'content_hash'
 →(0=≢carried)/ok
 →((33≠≢carried)∨(~carried≡4⊃e))/mism
 ok:Z←e EC_OK ⋄ →0
 mism:Z←EntAbsent EC_HASH_MISMATCH
∇

⍝ ── field reads off the data-map view ──
∇Z←e EntText key
 Z←(EntDataMap e)MText key
∇
∇Z←e EntBytes key
 Z←(EntDataMap e)MBytes key
∇
∇Z←e EntUint key            ⍝ -> (value present)
 Z←(EntDataMap e)MUint key
∇
∇Z←e EntUintState key       ⍝ -> 0 absent · 1 uint64 · ¯1 present-but-unrepresentable
 Z←(EntDataMap e)MUintState key
∇
∇Z←e EntFieldV key          ⍝ raw value at key
 Z←(EntDataMap e)MGet key
∇
∇Z←e EntSubmap key
 Z←(EntDataMap e)MSubmap key
∇

⍝ decode a nested entity carried at `key` (a wire entity map), or EntAbsent.
∇Z←e EntEntityField key;m;r
 Z←EntAbsent
 m←(EntDataMap e)MSubmap key
 →(EV_MAP≠1⊃m)/0
 r←EntOfCbor m
 →(EC_OK≠2⊃r)/0
 Z←1⊃r
∇

⍝ ── hash helpers ──
HashEq←{(0<≢,⍺)∧(,⍺)≡,⍵}                         ⍝ both non-empty + equal (≡ is shape-safe)
HashZero←{(0=≢,⍵)∨∧/0=,⍵}
