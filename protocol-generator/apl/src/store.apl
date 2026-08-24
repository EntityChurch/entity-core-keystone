⍝ entity-core-protocol-apl — src/store.apl (foundation storage, §1.7).
⍝
⍝   Content Store: hash -> entity   (immutable, content-addressed, dedup)
⍝   Entity Tree:   path -> hash      (mutable location index)
⍝
⍝ In-memory over WORKSPACE-GLOBAL parallel nested vectors in the one image. Keys are
⍝ lowercase-hex content hashes (A-CL-009) and NUL-free paths.
⍝
⍝ == §4.8 store data-race safety — STRUCTURAL. The peer is ONE image driven by a
⍝ single-threaded ⎕FIO[40] select-pump (one frame dispatched to completion before the
⍝ next event is polled — see peer.apl / transport.apl), so these globals are NEVER
⍝ accessed concurrently: the §4.8 MUST holds by construction, no lock, no possible race
⍝ (the profile [async] single-thread-select model — GNU APL has no native reactor and one
⍝ interpreter image). Lookups are linear scans — fine at the core-profile scale.

∇StoreReset
 gCHex←⍬ ⋄ gCEnt←⍬ ⋄ gTPath←⍬ ⋄ gTHex←⍬
∇

⍝ ── content store ──
∇StorePutEntity e;hex;i
 hex←HexLc EntHash e
 i←0
 lp:→(i≥≢gCHex)/add
 i←i+1
 →((i⊃gCHex)≡hex)/0                     ⍝ dedup: already stored
 →lp
 add:gCHex←gCHex,⊂hex ⋄ gCEnt←gCEnt,⊂e
∇

∇Z←StoreGetByHash hb;hex;i
 Z←EntAbsent
 →(0=≢hb)/0
 hex←HexLc hb ⋄ i←0
 lp:→(i≥≢gCHex)/0
 i←i+1
 →(~(i⊃gCHex)≡hex)/lp
 Z←i⊃gCEnt
∇

⍝ ── entity tree ──
∇Z←TreeIndex path;i
 Z←0 ⋄ i←0
 lp:→(i≥≢gTPath)/0
 i←i+1
 →(~(i⊃gTPath)≡path)/lp
 Z←i ⋄ →0
∇

∇path StoreBind e;hex;idx
 StorePutEntity e
 hex←HexLc EntHash e
 idx←TreeIndex path
 →(idx>0)/upd
 gTPath←gTPath,⊂path ⋄ gTHex←gTHex,⊂hex ⋄ →0
 upd:gTHex[idx]←⊂hex
∇

∇StoreUnbind path;idx
 idx←TreeIndex path
 →(idx=0)/0
 gTHex[idx]←⊂''
∇

∇Z←StoreHashAt path;idx
 Z←''
 idx←TreeIndex path
 →(idx=0)/0
 Z←idx⊃gTHex
∇

∇Z←StoreGetAt path;idx;hex;i
 Z←EntAbsent
 idx←TreeIndex path
 →(idx=0)/0
 hex←idx⊃gTHex
 →(0=≢hex)/0
 i←0
 lp:→(i≥≢gCHex)/0
 i←i+1
 →(~(i⊃gCHex)≡hex)/lp
 Z←i⊃gCEnt ⋄ →0
∇

⍝ ── one-level listing under `prefix` (§3.9) -> (segs hexes kids) sorted by segment.
⍝ hexes item '' for an interior node; kids item 1 iff the segment has children. ──
∇Z←StoreListing prefix;p;plen;i;path;rest;slash;seg;acc;ord;segs
 p←prefix
 →(p EndsWith'/')/have    ⍝ already ends with '/' (monadic ⊃ is DISCLOSE in GNU APL, not first)
 →(0=≢p)/root
 p←p,'/' ⋄ →have
 root:p←'/'
 have:plen←≢p
 acc←(⍬)(⍬)(⍬)
 i←0
 lp:→(i≥≢gTPath)/sort
 i←i+1
 →(0=≢i⊃gTHex)/lp                       ⍝ unbound
 path←i⊃gTPath
 →((≢path)≤plen)/lp
 →(~p≡(plen)↑path)/lp
 rest←(plen)↓path
 slash←rest⍳'/'
 →(slash>≢rest)/leaf
 seg←(slash-1)↑rest
 acc←acc AccRow(seg)('')(1) ⋄ →lp
 leaf:acc←acc AccRow(rest)(i⊃gTHex)(0) ⋄ →lp
 sort:segs←1⊃acc ⋄ ord←⍋segs
 Z←(segs[ord])((2⊃acc)[ord])((3⊃acc)[ord])
∇

⍝ merge one listing row into acc=(segs hexes kids). ⍵=(seg hex child). Dedup by segment:
⍝ children flag ORs in, a leaf hash overrides ''. Returns updated (segs hexes kids).
∇Z←acc AccRow row;segs;hexes;kids;seg;hex;child;j
 segs←1⊃acc ⋄ hexes←2⊃acc ⋄ kids←3⊃acc
 seg←1⊃row ⋄ hex←2⊃row ⋄ child←3⊃row
 j←0
 lp:→(j≥≢segs)/new
 j←j+1
 →(~(j⊃segs)≡seg)/lp
 →(child=0)/hh
 kids[j]←1
 hh:→(0=≢hex)/keep
 hexes[j]←⊂hex
 keep:Z←segs hexes kids ⋄ →0
 new:Z←(segs,⊂seg)(hexes,⊂hex)(kids,child)
∇
