⍝ entity-core-protocol-apl — src/capability.apl (L3: the §5 verification core).
⍝
⍝ Pattern matching (§5.4), request verification (§5.2), delegation-chain verification
⍝ (§5.5), attenuation (§5.6), caveats (§5.7), revocation (§5.1), and §3.6 M3 multi-sig
⍝ K-of-N — ported from the §5 pseudocode (the Fortran capability.f90 shape) onto APL's
⍝ (kind payload) value model. Layer-1 verdict is ALLOW/DENY (§5.10, N8: a pure function of
⍝ (local, store, envelope) — no clock branch except explicit temporal bounds). The 3-way
⍝ request verdict folds in the §4.10(b) structural CHAIN_TOO_DEEP (→ 400, NOT 403 —
⍝ structural excess is not an authz denial) and the §5.5 unresolvable-grantee carve-out
⍝ (→ 401). The store is the global content store (store.apl); inc is the envelope's
⍝ nested vector of included entities. →-branch tradfns throughout (A-APL-012).

MAX_CHAIN_DEPTH←64
CV_ALLOW←0 ⋄ CV_AUTHN_FAIL←1 ⋄ CV_AUTHZ_DENY←2 ⋄ CV_CHAIN_TOO_DEEP←3
∇Z←CapNowMs                                      ⍝ tradfn: niladic dfns eval at load (A-APL-016)
 Z←⎕FIO[50] 1000
∇
B58AL←'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

⍝ ── string prefix / suffix (⍺=string ⍵=affix) ──
StartsWith←{((≢⍵)≤≢⍺)∧(,⍵)≡(≢⍵)↑,⍺}
EndsWith←{((≢⍵)≤≢⍺)∧(,⍵)≡(-≢⍵)↑,⍺}

⍝ ── §4.4 grant builder: {handlers, resources, operations [, peers]} scope map ──
∇Z←CapGrant a;h;r;o;p;m
 h←1⊃a ⋄ r←2⊃a ⋄ o←3⊃a ⋄ p←4⊃a
 m←VMapEmpty
 m←m VmPut('handlers')(VScope h)
 m←m VmPut('resources')(VScope r)
 m←m VmPut('operations')(VScope o)
 →(0=≢p~' ')/fin
 m←m VmPut('peers')(VScope p)
 fin:Z←m
∇

⍝ ── §5.4 pattern matching ──
∇Z←CapNormalizeUri uri
 Z←uri
 →(~uri StartsWith'entity://')/0
 Z←'/',9↓uri
∇

⍝ canonicalize `path` against `local` -> (out invalid). invalid on a reserved-relative
⍝ or ambiguous bare-wildcard path (→ 400 at the dispatch top).
∇Z←local CapCanonicalize path
 →((∨/path=⎕UCS 0)∨∨/'//'⍷path)/bad   ⍝ §1.4: no null bytes, no empty segments (consecutive //)
 →(path StartsWith'./')/bad
 →(path StartsWith'../')/bad
 →(path StartsWith'*/')/bad
 →(path StartsWith'/')/abs
 Z←('/',local,'/',path)0 ⋄ →0
 abs:→(~CapIsPeerId FirstSegment path)/bad   ⍝ §1.4: absolute path MUST be /{peer_id}/... (leading / else peer-relative)
 Z←path 0 ⋄ →0
 bad:Z←path 1
∇
Canon←{1⊃⍺ CapCanonicalize ⍵}                   ⍝ invalid-ignoring form

∇Z←path CapMatchesPattern pattern;sub;i
 →((,pattern)≡,'*')/yes    ⍝ ,-ravel both: 3↓pattern yields a 1-elem VECTOR; ≡ also compares rank
 →(~pattern StartsWith'/*/')/nomid
 →(0=≢path)/no
 sub←1↓path
 i←sub⍳'/'
 →(i>≢sub)/no
 Z←((1+i)↓path)CapMatchesPattern(3↓pattern) ⋄ →0
 nomid:→(~pattern EndsWith'/*')/exact
 Z←path StartsWith ¯1↓pattern ⋄ →0
 exact:Z←(,path)≡,pattern ⋄ →0
 yes:Z←1 ⋄ →0
 no:Z←0
∇

⍝ is canonicalized value cv covered by any pattern in pats (canonicalized in frame)?
⍝ ⍺=frame ; ⍵=(pats cv). pats a nested vector of pattern strings.
∇Z←frame Covered pc;pats;cv;i
 pats←1⊃pc ⋄ cv←2⊃pc ⋄ Z←0 ⋄ i←0
 lp:→(i≥≢pats)/0
 i←i+1
 →(~cv CapMatchesPattern frame Canon(i⊃pats))/lp
 Z←1 ⋄ →0
∇

⍝ ⍺=local ; ⍵=(value scope). does `value` match the include/exclude scope?
∇Z←local CapMatchesScope vs;value;scope;cv;incl;excl
 value←1⊃vs ⋄ scope←2⊃vs
 cv←local Canon value
 incl←TextList scope MArray'include'
 →(~local Covered incl cv)/no
 excl←TextList scope MArray'exclude'
 Z←~local Covered excl cv ⋄ →0
 no:Z←0
∇

⍝ ⍵=(local granterPeer resource scope) — §PR-8 resource dimension framed by granter.
∇Z←CheckResourceScope a;local;gp;resource;scope;targets;cexcl;incl;excl;i;ct
 local←1⊃a ⋄ gp←2⊃a ⋄ resource←3⊃a ⋄ scope←4⊃a
 Z←0
 targets←TextList resource MArray'targets'
 cexcl←TextList resource MArray'exclude'
 incl←TextList scope MArray'include'
 excl←TextList scope MArray'exclude'
 →(0=≢targets)/0
 i←0
 lp:→(i≥≢targets)/ok
 i←i+1 ⋄ ct←local Canon(i⊃targets)
 →((0<≢cexcl)∧local Covered cexcl ct)/lp    ⍝ caller-excluded target: skip
 →(~gp Covered incl ct)/0
 →(gp Covered excl ct)/0
 →lp
 ok:Z←1
∇

∇Z←CapIsPeerId seg
 Z←0
 →(46>≢seg)/0
 Z←∧/seg∊B58AL
∇

∇Z←FirstSegment uri;u;i
 u←uri
 →(~uri StartsWith'/')/nn
 u←1↓uri
 nn:i←u⍳'/'
 Z←(i-1)↑u
∇

∇Z←local CapExtractPeer uri;first
 first←FirstSegment CapNormalizeUri uri
 Z←(1+CapIsPeerId first)⊃(local)(first)
∇

⍝ resolve an entity by hash from inc (then the global store).
∇Z←inc CapResolve h;i
 Z←EntAbsent
 →(0=≢h)/0
 i←0
 lp:→(i≥≢inc)/store
 i←i+1
 →(~(EntHash i⊃inc)HashEq h)/lp
 Z←i⊃inc ⋄ →0
 store:Z←StoreGetByHash h
∇

⍝ the system/signature entity in inc over `target` (EntAbsent if none).
∇Z←CapFindSignature ti;target;inc;i
 target←1⊃ti ⋄ inc←2⊃ti ⋄ Z←EntAbsent
 →(0=≢target)/0
 i←0
 lp:→(i≥≢inc)/0
 i←i+1
 →(~'system/signature'≡EntType i⊃inc)/lp
 →(~((i⊃inc)EntBytes'target')HashEq target)/lp
 Z←i⊃inc ⋄ →0
∇

CapGrantsOfToken←{(EntDataMap ⍵)MArray'grants'}

⍝ §PR-8: the granter's peer_id frames a cap's resource patterns.
∇Z←inc CapResolveGranterPeerId cap;gh;g;pk
 Z←''
 gh←cap EntBytes'granter'
 →(0=≢gh)/0
 g←inc CapResolve gh
 →(~EntPresent g)/0
 pk←g EntBytes'public_key'
 →(0=≢pk)/0
 Z←PeerIdOfPubkey pk
∇

⍝ §5.2 check-permission. ⍵=(local granterPeer exec token handlerPattern).
∇Z←CapCheckPermission a;local;gp;exec;token;hp;op;uri;tp;resource;garr;n;i;g;ok;peers
 local←1⊃a ⋄ gp←2⊃a ⋄ exec←3⊃a ⋄ token←4⊃a ⋄ hp←5⊃a
 Z←0
 op←exec EntText'operation'
 uri←exec EntText'uri'
 tp←local CapExtractPeer uri
 resource←exec EntSubmap'resource'
 garr←CapGrantsOfToken token ⋄ n←ArrCount garr ⋄ i←0
 lp:→(i≥n)/0
 i←i+1 ⋄ g←garr ArrItem i
 ok←(local CapMatchesScope op(g MSubmap'operations'))∧(local CapMatchesScope hp(g MSubmap'handlers'))
 →(~ok)/lp
 peers←g MSubmap'peers'
 →(EV_MAP=1⊃peers)/pk
 ok←tp≡local ⋄ →rc
 pk:ok←local CapMatchesScope tp peers
 rc:→(~ok)/lp
 →(EV_MAP≠1⊃resource)/allw
 ok←CheckResourceScope local gp resource(g MSubmap'resources')
 →(~ok)/lp
 allw:Z←1 ⋄ →0
∇

⍝ §4.10(b) structural pre-check: 1 iff the chain exceeds MAX depth. Walks parent pointers
⍝ WITHOUT verifying sigs — an unreachable parent is NOT a depth problem (stays 403 in the
⍝ authz walk), so this maps ONLY genuine over-depth -> 400 chain_depth_exceeded.
∇Z←cap CapChainExceedsDepth inc;current;depth;ph;parent
 current←cap ⋄ depth←0
 lp:→(depth>MAX_CHAIN_DEPTH)/deep
 ph←current EntBytes'parent'
 →(0=≢ph)/nodeep
 parent←inc CapResolve ph
 →(~EntPresent parent)/nodeep
 current←parent ⋄ depth←depth+1 ⋄ →lp
 deep:Z←1 ⋄ →0
 nodeep:Z←0
∇

⍝ collect the cap..root parent chain -> (chain ok); ok=0 on a broken/over-deep chain.
∇Z←cap CollectChain inc;chain;current;depth;ph;parent
 chain←⍬ ⋄ current←cap ⋄ depth←0
 lp:→(depth>MAX_CHAIN_DEPTH)/bad
 chain←chain,⊂current
 ph←current EntBytes'parent'
 →(0=≢ph)/ok
 parent←inc CapResolve ph
 →(~EntPresent parent)/bad
 current←parent ⋄ depth←depth+1 ⋄ →lp
 ok:Z←chain 1 ⋄ →0
 bad:Z←chain 0
∇

⍝ §PR-8 per-link frame = the cap's granter peer_id (root/no-granter -> local; single-sig
⍝ unresolvable -> '').
∇Z←inc LinkGranterPeer lc;local;cap;gh;g;pk
 local←1⊃lc ⋄ cap←2⊃lc
 gh←cap EntBytes'granter'
 →(0=≢gh)/loc
 g←inc CapResolve gh
 →(~EntPresent g)/empty
 pk←g EntBytes'public_key'
 →(0=≢pk)/empty
 Z←PeerIdOfPubkey pk ⋄ →0
 loc:Z←local ⋄ →0
 empty:Z←''
∇

⍝ ⍵=(childPeer parentPeer childScope parentScope) -> scope-subset boolean.
∇Z←ScopeSubset a;cp;pp;child;parent;ci;pin;pex;cex;i;j;cc;cov;cpe
 cp←1⊃a ⋄ pp←2⊃a ⋄ child←3⊃a ⋄ parent←4⊃a
 Z←0
 ci←TextList child MArray'include'
 pin←TextList parent MArray'include'
 i←0
 il:→(i≥≢ci)/idone
 i←i+1 ⋄ cc←cp Canon(i⊃ci) ⋄ cov←0 ⋄ j←0
 ij:→(j≥≢pin)/ichk
 j←j+1 ⋄ →(~cc CapMatchesPattern pp Canon(j⊃pin))/ij
 cov←1
 ichk:→(~cov)/0
 →il
 idone:pex←TextList parent MArray'exclude'
 cex←TextList child MArray'exclude'
 i←0
 el:→(i≥≢pex)/ok
 i←i+1 ⋄ cpe←pp Canon(i⊃pex) ⋄ cov←0 ⋄ j←0
 ej:→(j≥≢cex)/echk
 j←j+1 ⋄ →(~cpe CapMatchesPattern cp Canon(j⊃cex))/ej
 cov←1
 echk:→(~cov)/0
 →el
 ok:Z←1
∇

⍝ ⍵=(local childPeer parentPeer childGrant parentGrant) -> grant-subset boolean.
∇Z←GrantSubset a;local;cpe;ppe;child;parent;cp;pp
 local←1⊃a ⋄ cpe←2⊃a ⋄ ppe←3⊃a ⋄ child←4⊃a ⋄ parent←5⊃a
 Z←0
 →(~ScopeSubset local local(child MSubmap'handlers')(parent MSubmap'handlers'))/0
 →(~ScopeSubset local local(child MSubmap'operations')(parent MSubmap'operations'))/0
 →(~ScopeSubset cpe ppe(child MSubmap'resources')(parent MSubmap'resources'))/0
 cp←child MSubmap'peers' ⋄ →(EV_MAP=1⊃cp)/hc ⋄ cp←VScope local
 hc:pp←parent MSubmap'peers' ⋄ →(EV_MAP=1⊃pp)/hp ⋄ pp←VScope local
 hp:Z←ScopeSubset local local cp pp
∇

⍝ public: is grant child a subset of grant parent in the local frame (bounded-mint check).
∇Z←local CapGrantSubsetLocal cp
 Z←GrantSubset local local local(1⊃cp)(2⊃cp)
∇

⍝ ⍵=(local childPeer parentPeer childTok parentTok) -> attenuation boolean (§5.6).
∇Z←IsAttenuated a;local;cpe;ppe;child;parent;cg;pg;i;j;c;p;ok;pe;ce;pep;cep
 local←1⊃a ⋄ cpe←2⊃a ⋄ ppe←3⊃a ⋄ child←4⊃a ⋄ parent←5⊃a
 Z←0
 cg←CapGrantsOfToken child ⋄ pg←CapGrantsOfToken parent
 i←0
 lp:→(i≥ArrCount cg)/temporal
 i←i+1 ⋄ c←cg ArrItem i ⋄ ok←0 ⋄ j←0
 jl:→(j≥ArrCount pg)/jchk
 j←j+1 ⋄ p←pg ArrItem j
 →(~GrantSubset local cpe ppe c p)/jl
 ok←1
 jchk:→(~ok)/0
 →lp
 temporal:pe←parent EntUint'expires_at' ⋄ ce←child EntUint'expires_at'
 pep←2⊃pe ⋄ cep←2⊃ce
 →(pep∧~cep)/0
 →(~pep)/atten
 Z←(1⊃ce)≤(1⊃pe) ⋄ →0
 atten:Z←1
∇

⍝ ⍵=(parent child depth) -> delegation-caveat boolean (§5.7).
∇Z←CheckDelegationCaveats a;parent;child;depth;caveats;mdd;maxttl;ex;cr;dok;tok;p1;p2;p3;p4
 parent←1⊃a ⋄ child←2⊃a ⋄ depth←3⊃a
 Z←1
 caveats←parent EntSubmap'delegation_caveats'
 →(EV_MAP≠1⊃caveats)/0
 →(caveats MBool'no_delegation')/deny
 dok←1 ⋄ tok←1
 mdd←caveats MUint'max_delegation_depth' ⋄ p1←2⊃mdd
 →(~p1)/ttl
 dok←depth<1⊃mdd
 ttl:maxttl←caveats MUint'max_delegation_ttl' ⋄ p2←2⊃maxttl
 →(~p2)/fin
 ex←child EntUint'expires_at' ⋄ p3←2⊃ex
 cr←child EntUint'created_at' ⋄ p4←2⊃cr
 →(p3∧p4)/both
 →(p3)/onlyex
 tok←0 ⋄ →fin
 both:tok←((1⊃ex)-1⊃cr)≤1⊃maxttl ⋄ →fin
 onlyex:tok←1
 fin:Z←dok∧tok ⋄ →0
 deny:Z←0
∇

⍝ ── §3.6 M3 multi-signature root ──
IsMultisig←{EV_MAP=1⊃(EntDataMap ⍵)MGet'granter'}

∇Z←HasDup l;i;j
 Z←0 ⋄ i←0
 il:→(i≥≢l)/0
 i←i+1 ⋄ j←i
 jl:→(j≥≢l)/il
 j←j+1
 →(~(i⊃l)≡j⊃l)/jl
 Z←1 ⋄ →0
∇
SlHas←{∨/(⊂⍺)≡¨⍵}                                ⍝ ⍺=string ⍵=nested strings -> membership (⍺∘≡¨ DOMAIN-errors in GNU APL)

⍝ parse the granter union of a multisig root -> (threshold signersHex). th<0 = single-sig.
∇Z←MultiGranterOf cap;g;arr;signers;i;it;th;p
 g←(EntDataMap cap)MGet'granter'
 →(EV_MAP≠1⊃g)/single
 signers←⍬ ⋄ arr←g MArray'signers' ⋄ i←0
 lp:→(i≥ArrCount arr)/thr
 i←i+1 ⋄ it←arr ArrItem i
 →(EV_BYTES≠1⊃it)/lp
 signers←signers,⊂HexLc,2⊃it
 →lp
 thr:p←g MUint'threshold'
 th←(1⊃p)×2⊃p            ⍝ MUint→(value present): threshold value if present, else 0
 Z←th signers ⋄ →0
 single:Z←¯1(⍬)
∇

∇Z←inc PeerIdOfSigner signerHex;p;i;pk
 Z←'' ⋄ p←EntAbsent ⋄ i←0
 lp:→(i≥≢inc)/0
 i←i+1
 →(~(HexLc EntHash i⊃inc)≡signerHex)/lp
 p←i⊃inc ⋄ →found
 found:pk←p EntBytes'public_key'
 →(0=≢pk)/0
 Z←PeerIdOfPubkey pk
∇

⍝ ⍵=(local inc cap signers threshold) -> §5.5 M4 k-of-n boolean.
∇Z←VerifyMultisigRoot a;local;inc;cap;signers;threshold;n;i;lin;caph;valid;sp;j;sh;now;nb;ex;pnb;pex;grantee;ge
 local←1⊃a ⋄ inc←2⊃a ⋄ cap←3⊃a ⋄ signers←4⊃a ⋄ threshold←5⊃a
 Z←0 ⋄ n←≢signers
 →(0≠≢cap EntBytes'parent')/0
 →(n<2)/0
 →((threshold<2)∨(threshold>n))/0
 →(HasDup signers)/0
 lin←0 ⋄ i←0
 ll:→(i≥n)/lchk
 i←i+1 ⋄ →(~local≡inc PeerIdOfSigner i⊃signers)/ll
 lin←1
 lchk:→(~lin)/0
 now←CapNowMs
 nb←cap EntUint'not_before' ⋄ pnb←2⊃nb ⋄ →(pnb∧now<1⊃nb)/0
 ex←cap EntUint'expires_at' ⋄ pex←2⊃ex ⋄ →(pex∧(1⊃ex)<now)/0
 grantee←cap EntBytes'grantee'
 →(0=≢grantee)/0
 ge←inc CapResolve grantee ⋄ →(~EntPresent ge)/0
 caph←EntHash cap ⋄ valid←⍬ ⋄ i←0
 vl:→(i≥n)/count
 i←i+1
 →((i⊃signers)SlHas valid)/vl
 sp←EntAbsent ⋄ j←0
 fpl:→(j≥≢inc)/vl
 j←j+1 ⋄ →(~(HexLc EntHash j⊃inc)≡i⊃signers)/fpl
 sp←j⊃inc
 →(~EntPresent sp)/vl
 j←0
 fsl:→(j≥≢inc)/vl
 j←j+1
 →(~'system/signature'≡EntType j⊃inc)/fsl
 →(~((j⊃inc)EntBytes'target')HashEq caph)/fsl
 sh←(j⊃inc)EntBytes'signer'
 →(~(HexLc sh)≡i⊃signers)/fsl
 →(~(j⊃inc)IdVerifySignature sp)/fsl
 valid←valid,⊂i⊃signers ⋄ →vl
 count:Z←(≢valid)≥threshold
∇

⍝ ── §5.5 chain verification -> CV_ALLOW / CV_AUTHZ_DENY; sets unresolvable (-> 401). ──
⍝ ⍵=(local cap inc) -> (verdict unresolvable).
∇Z←VerifyChain a;local;cap;inc;cr;chain;nn;root;mg;rootTh;signers;rootOk;rgh;granter;pk;good;i;current;gh;sgn;signer;geh;ge;now;nb;ex;pnb;pex;parent;cpe;ppe;pg;cg;linkOk;unres
 local←1⊃a ⋄ cap←2⊃a ⋄ inc←3⊃a
 Z←CV_AUTHZ_DENY 0 ⋄ unres←0
 cr←cap CollectChain inc
 →(0=2⊃cr)/0
 chain←1⊃cr ⋄ nn←≢chain ⋄ root←nn⊃chain
 mg←MultiGranterOf root ⋄ rootTh←1⊃mg ⋄ signers←2⊃mg
 →(rootTh<0)/single
 rootOk←VerifyMultisigRoot local inc root signers rootTh ⋄ →rchk
 single:rgh←root EntBytes'granter' ⋄ granter←EntAbsent
 →(0=≢rgh)/rok0
 granter←inc CapResolve rgh
 rok0:pk←⍬ ⋄ →(~EntPresent granter)/rok1
 pk←granter EntBytes'public_key'
 rok1:rootOk←0 ⋄ →(0=≢pk)/rchk
 rootOk←local≡PeerIdOfPubkey pk
 rchk:→(~rootOk)/0
 good←1 ⋄ i←0
 wl:→(i≥nn)/final
 →(~good)/final
 i←i+1 ⋄ current←i⊃chain
 →(~IsMultisig current)/notms
 →(i≠nn)/msbad
 →wl
 msbad:good←0 ⋄ →wl
 notms:gh←current EntBytes'granter'
 →(0=≢gh)/nogr
 sgn←CapFindSignature(EntHash current)inc
 granter←inc CapResolve gh
 →(~(EntPresent sgn)∧EntPresent granter)/nogr
 signer←sgn EntBytes'signer'
 →(~((0<≢signer)∧(signer HashEq gh))∧(sgn IdVerifySignature granter))/nogr
 →grantee
 nogr:good←0
 grantee:geh←current EntBytes'grantee'
 →(0=≢geh)/unresmark
 ge←inc CapResolve geh
 →(~EntPresent ge)/unresmark
 →temporal
 unresmark:Z←CV_AUTHZ_DENY 1 ⋄ →0
 temporal:now←CapNowMs
 nb←current EntUint'not_before' ⋄ pnb←2⊃nb ⋄ →(~(pnb∧now<1⊃nb))/e2 ⋄ good←0
 e2:ex←current EntUint'expires_at' ⋄ pex←2⊃ex ⋄ →(~(pex∧(1⊃ex)<now))/link ⋄ good←0
 link:→(i≥nn)/wl
 parent←(i+1)⊃chain
 cpe←inc LinkGranterPeer local current
 ppe←inc LinkGranterPeer local parent
 →((0=≢cpe)∨(0=≢ppe))/linkbad
 pg←parent EntBytes'grantee' ⋄ cg←current EntBytes'granter'
 linkOk←((0<≢pg)∧(0<≢cg))∧(pg HashEq cg)
 →(~linkOk)/linkset
 linkOk←IsAttenuated local cpe ppe current parent
 →(~linkOk)/linkset
 linkOk←CheckDelegationCaveats parent current i
 linkset:→(linkOk)/wl
 linkbad:good←0 ⋄ →wl
 final:→(~good)/0
 Z←CV_ALLOW 0
∇

∇Z←RevokeMarker a;local;h;e
 local←1⊃a ⋄ h←2⊃a
 e←StoreGetAt'/',local,'/system/capability/revocations/',HexLc h
 Z←EntPresent e
∇

⍝ ⍵=(local cap inc) -> revoked boolean (§5.1).
∇Z←CapIsRevoked a;local;cap;inc;cr;rootHash;chain
 local←1⊃a ⋄ cap←2⊃a ⋄ inc←3⊃a
 Z←0
 cr←cap CollectChain inc ⋄ chain←1⊃cr
 →(0=2⊃cr)/self
 rootHash←EntHash(≢chain)⊃chain ⋄ →chk
 self:rootHash←EntHash cap
 chk:→(RevokeMarker local(EntHash cap))/yes
 Z←RevokeMarker local rootHash ⋄ →0
 yes:Z←1
∇

⍝ ── §5.2 verify-request (3-way + unresolvable). ⍵=(local env) -> (verdict unresolvable). ──
∇Z←CapVerifyRequest le;local;env;exec;inc;sgn;authorH;signer;author;ch;cap;vc;verdict;unres;grantee
 local←1⊃le ⋄ env←2⊃le
 exec←EnvRoot env ⋄ inc←EnvInc env ⋄ unres←0
 sgn←CapFindSignature(EntHash exec)inc
 →(~EntPresent sgn)/authn
 authorH←exec EntBytes'author'
 signer←sgn EntBytes'signer'
 →(~((0<≢signer)∧(0<≢authorH))∧(signer HashEq authorH))/authn
 author←env EnvIncludedGet authorH
 →(~EntPresent author)/authn
 →(~sgn IdVerifySignature author)/authn
 ch←exec EntBytes'capability'
 cap←EntAbsent
 →(0=≢ch)/deny
 cap←env EnvIncludedGet ch
 →(~EntPresent cap)/deny
 →(cap CapChainExceedsDepth inc)/toodeep
 vc←VerifyChain local cap inc ⋄ verdict←1⊃vc ⋄ unres←2⊃vc
 →(unres)/deny
 →(verdict≠CV_ALLOW)/deny
 grantee←cap EntBytes'grantee'
 →(~((0<≢grantee)∧(grantee HashEq authorH)))/deny
 →(CapIsRevoked local cap inc)/deny
 Z←CV_ALLOW 0 ⋄ →0
 authn:Z←CV_AUTHN_FAIL 0 ⋄ →0
 deny:Z←CV_AUTHZ_DENY unres ⋄ →0
 toodeep:Z←CV_CHAIN_TOO_DEEP 0
∇
