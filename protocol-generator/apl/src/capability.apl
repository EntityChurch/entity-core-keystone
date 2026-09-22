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
⍝ NeverMatch — the unmatchable value (0.8.2.20). Unreachable as a canonical path by
⍝ CONSTRUCTION: its only segment cannot be a peer_id, since CapIsPeerId requires
⍝ >= 46 Base58 characters and "-" is outside B58AL.
NeverMatch←'/never-match'

⍝ Canon — CapCanonicalize FOR THE MATCHERS, which have no error channel. TOTAL
⍝ (0.8.2.20): the result is "a canonical path OR NeverMatch". CapCanonicalize keeps
⍝ its `invalid` flag for the dispatch top, which is exactly the caller 0.8.2.20 says
⍝ SHOULD have the diagnostic. The defect was HERE: this wrapper IGNORED `invalid` and
⍝ returned the input unchanged, which matched nothing — the desired outcome in an
⍝ INCLUDE and the opposite of it in an EXCLUDE, so a grant exclude carrying "../x"
⍝ carved out nothing and the grant was silently wider than its author wrote (measured
⍝ on the wire 2026-09-14).
⍝ NOTE THE FAILURE SET, because reusing CapCanonicalize's `invalid` here was WRONG and
⍝ the census said so: that flag is BROADER than §5.4's. CapCanonicalize also refuses a
⍝ null byte, an empty segment, and — the one that bit — an absolute path whose first
⍝ segment is not a peer_id, which is §5.4's validate_absolute_path and is explicitly
⍝ "NOT called on patterns". Mapping the whole flag to the sentinel turned every `/*/…`
⍝ pattern unmatchable: 6 FAILs, all foreign-namespace and id-scope. Only the three
⍝ RESERVED prefixes §5.4's canonicalize names may become NeverMatch.
∇Z←local Canon path
 →(path StartsWith'./')/nm
 →(path StartsWith'../')/nm
 →(path StartsWith'*/')/nm
 Z←1⊃local CapCanonicalize path ⋄ →0
 nm:Z←NeverMatch
∇

⍝ AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
⍝ in an include (covers nothing → the grant grants nothing) and fail-OPEN in an
⍝ exclude (carves out nothing), so the reading is chosen where the POSITION is known
⍝ and CapMatchesPattern stays uniform over its operands. The guard sits outside the
⍝ scope-type dispatch, transcribing §5.2's loop literally.
∇Z←frame ExcludeUnmatchable pats;i
 Z←0 ⋄ i←0
 lp:→(i≥≢pats)/0
 i←i+1
 →(~(,NeverMatch)≡,frame Canon(i⊃pats))/lp
 Z←1 ⋄ →0
∇

∇Z←path CapMatchesPattern pattern;sub;i
 ⍝ NeverMatch never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher rule
 ⍝ rather than a property of the string: the arm below answers 1 for a bare "*", so
 ⍝ safety must not rest on a value merely looking unmatchable.
 →(((,NeverMatch)≡,path)∨((,NeverMatch)≡,pattern))/no
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

⍝ is `v` covered by any pattern in pats, matched LITERALLY (no peer frame)?
⍝ ⍵=(pats v). The id-scope twin of `Covered` above.
∇Z←CoveredLiteral pv;pats;v;i
 pats←1⊃pv ⋄ v←2⊃pv ⋄ Z←0 ⋄ i←0
 lp:→(i≥≢pats)/0
 i←i+1
 →(~v CapMatchesPattern(i⊃pats))/lp
 Z←1 ⋄ →0
∇

⍝ ⍵=(value scope). does `value` match the include/exclude scope, LITERALLY?
⍝
⍝ §5.2 / F40: the handlers, operations and peers dimensions are ID-SCOPE. Their
⍝ values are IDENTIFIERS, not paths, so they are compared literally and are never
⍝ canonicalized against a peer frame. Only `resources` takes §5.5a framing —
⍝ a frame argument on an id-scope call site IS the defect.
⍝
⍝ Over-canonicalizing an id-scope dimension fails in BOTH directions at once, and
⍝ one of the two is not what a reviewer is looking for: canonicalization turns a
⍝ non-matching literal into a match, and "a match" is a GRANT on the include side
⍝ and a REFUSAL on the exclude side. Measured on this peer before the fix, in one
⍝ run: an operations include of only "/{local}/get" AUTHORIZED the bare operation
⍝ `get` (f40_id_scope_include_no_overgrant), while an exclude of "/*/get" DENIED
⍝ it (f40_id_scope_exclude_literal).
∇Z←CapMatchesIdScope vs;value;scope;incl;excl
 value←1⊃vs ⋄ scope←2⊃vs
 incl←TextList scope MArray'include'
 →(~CoveredLiteral incl value)/no
 excl←TextList scope MArray'exclude'
 Z←~CoveredLiteral excl value ⋄ →0
 no:Z←0
∇

⍝ ⍺=local ; ⍵=(value scope). does `value` match the include/exclude scope?
∇Z←local CapMatchesScope vs;value;scope;cv;incl;excl
 value←1⊃vs ⋄ scope←2⊃vs
 cv←local Canon value
 excl←TextList scope MArray'exclude'
 →(local ExcludeUnmatchable excl)/no      ⍝ 0.8.2.21 — deny, do not carve out nothing
 incl←TextList scope MArray'include'
 →(~local Covered incl cv)/no
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
 ⍝ An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
 ⍝ target: the coverage test below is correct in isolation and is simply never
 ⍝ reached on a sentinel, because CapMatchesPattern answers 0.
 →(gp ExcludeUnmatchable excl)/0
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
⍝ handlers / operations / peers are ID-SCOPE (§5.2, F40) — literal, unframed.
⍝ `hp` arrives as the BARE handler id ("system/capability"), not the absolute
⍝ resolved path: grants name handlers relatively, and comparing the absolute form
⍝ only ever worked because the matcher canonicalized both sides. Removing the
⍝ canonicalization without also fixing the value takes every CAP check to 403 —
⍝ the two defects were holding each other up, and neither is visible alone.
 ok←(CapMatchesIdScope op(g MSubmap'operations'))∧(CapMatchesIdScope hp(g MSubmap'handlers'))
 →(~ok)/lp
 peers←g MSubmap'peers'
 →(EV_MAP=1⊃peers)/pk
 ok←tp≡local ⋄ →rc
 pk:ok←CapMatchesIdScope tp peers
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

⍝ ⍵=(childPeer parentPeer childScope parentScope kind) -> scope-subset boolean.
⍝ `kind` is SK_PATH or SK_ID.
⍝
⍝ TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; entity-core-formalization K-7).
⍝ section 3.6's id-scope grammar binds the scope TYPE, not one function -- "an
⍝ implementation on the canonicalizing reading is non-conformant and MUST adopt the
⍝ literal matcher" -- so the rule F40 landed on the MATCHES side reaches the SUBSET side
⍝ too, with delegation-chain WIDENING named as the reason: on the canonicalizing reading
⍝ a concrete id is covered by a bare star in one direction and a namespaced operation
⍝ name is not, and a child grant can come out wider than its parent. lean's differential
⍝ put it at 2 of 64 include pairs and 2 of 64 exclude pairs, fail-closed, with a 16-pair
⍝ control alphabet reporting 0 -- which is why every hand-tried example missed it.
⍝
⍝ `kind` has NO DEFAULT and is named at every call site: a default is how the next
⍝ dimension inherits the wrong matcher silently, which is the original F40 defect. The
⍝ per-link granter frames are meaningless on the ID arm (an id pattern is never
⍝ canonicalized) and are simply UNREAD there rather than being a second thing to get
⍝ wrong.
SK_PATH←1
SK_ID←0
⍝ Frame one pattern for the comparison: PATH-scope canonicalizes against the frame,
⍝ ID-scope compares the literal. ⍺=frame ; ⍵=(pattern kind).
⍝
⍝ WRITTEN AS A BRANCH RATHER THAN AS AN INDEX INTO A TWO-ELEMENT VECTOR, because the
⍝ index form was wrong in a way that COMPILED AND RAN: `(1+kind)⊃(,⊂raw)(⊂canon)` picks a
⍝ one-element vector CONTAINING the string, not the string, so every comparison was
⍝ against a nested value and no include ever matched. Measured on the wire: the §6.2
⍝ mint-bound subset refused the probe's narrow capability with 403 scope_exceeds_authority
⍝ and family G went from four green rows to a failed control. A branch cannot express that
⍝ mistake.
∇Z←frame FramePattern pk;pat;kind
 pat←1⊃pk ⋄ kind←2⊃pk
 Z←pat
 →(kind=SK_ID)/0
 Z←frame Canon pat
∇

∇Z←ScopeSubset a;cp;pp;child;parent;kind;ci;pin;pex;cex;i;j;cc;cov;cpe
 cp←1⊃a ⋄ pp←2⊃a ⋄ child←3⊃a ⋄ parent←4⊃a ⋄ kind←5⊃a
 Z←0
 ci←TextList child MArray'include'
 pin←TextList parent MArray'include'
 i←0
 il:→(i≥≢ci)/idone
 i←i+1 ⋄ cc←cp FramePattern(i⊃ci)kind ⋄ cov←0 ⋄ j←0
 ij:→(j≥≢pin)/ichk
 j←j+1 ⋄ →(~cc CapMatchesPattern pp FramePattern(j⊃pin)kind)/ij
 cov←1
 ichk:→(~cov)/0
 →il
 idone:pex←TextList parent MArray'exclude'
 cex←TextList child MArray'exclude'
 i←0
 el:→(i≥≢pex)/ok
 i←i+1 ⋄ cpe←pp FramePattern(i⊃pex)kind ⋄ cov←0 ⋄ j←0
 ej:→(j≥≢cex)/echk
 j←j+1 ⋄ →(~cpe CapMatchesPattern cp FramePattern(j⊃cex)kind)/ej
 cov←1
 echk:→(~cov)/0
 →el
 ok:Z←1
∇

⍝ ⍵=(local childPeer parentPeer childGrant parentGrant) -> grant-subset boolean.
⍝ The scope KIND is a property of the DIMENSION, named here and never defaulted
⍝ (F50 / 0.8.2.16). Only RESOURCES takes the section 5.5a per-link granter frames;
⍝ handlers stays local, and the two id dimensions do not canonicalize at all.
∇Z←GrantSubset a;local;cpe;ppe;child;parent;cp;pp
 local←1⊃a ⋄ cpe←2⊃a ⋄ ppe←3⊃a ⋄ child←4⊃a ⋄ parent←5⊃a
 Z←0
 →(~ScopeSubset local local(child MSubmap'handlers')(parent MSubmap'handlers')SK_PATH)/0
 →(~ScopeSubset local local(child MSubmap'operations')(parent MSubmap'operations')SK_ID)/0
 →(~ScopeSubset cpe ppe(child MSubmap'resources')(parent MSubmap'resources')SK_PATH)/0
 cp←child MSubmap'peers' ⋄ →(EV_MAP=1⊃cp)/hc ⋄ cp←VScope local
 hc:pp←parent MSubmap'peers' ⋄ →(EV_MAP=1⊃pp)/hp ⋄ pp←VScope local
 hp:Z←ScopeSubset local local cp pp SK_ID
∇

⍝ ── section 5.2 EFFECTIVE TARGETS + section 6.3 check_path_permission ──────────────

⍝ ⍺=local ; ⍵=exec -> (survivors hadResource).
⍝
⍝ section 5.2's effective target list (0.8.2.20): the caller's own `resource.exclude`
⍝ removes entries from `resource.targets` BEFORE anything else looks at the request.
⍝
⍝ The survivors are returned in the caller's OWN SPELLING, not canonicalized -- 0.8.2.21
⍝ is explicit that effective_targets yields RAW survivors, and the distinction is
⍝ load-bearing because the value flows on to the store lookup, which canonicalizes for
⍝ itself, and to the trailing-slash test, which is about what the caller WROTE.
⍝
⍝ THE SECOND RESULT IS THE NON-LOSSY PROJECTION section 3.3 REQUIRES [MUST] (0.8.2.25,
⍝ N11): an ABSENT resource and a resource whose every target the caller excluded are
⍝ DIFFERENT REQUESTS for a resource-OPTIONAL operation (0.8.2.24, N7), not merely
⍝ different inputs to one answer. A function returning only a list collapses them and
⍝ deletes the discriminator before any handler can read it.
⍝
⍝ THE CALLER-EXCLUDE ARM IS FAIL-OPEN ON AN UNMATCHABLE PATTERN, and section 5.4 rules it
⍝ separately from the GRANT arm: Canon answers NeverMatch, CapMatchesPattern then answers
⍝ 0, and the target simply SURVIVES. That asymmetry is inherited from the primitives here
⍝ rather than restated.
∇Z←local CapEffectiveTargets exec;r;targets;cexcl;out;i;j;t;ct;dropped
 r←exec EntSubmap'resource'
 →(EV_MAP=1⊃r)/hasr
 Z←(⍬)0 ⋄ →0
 hasr:→(r MHas'targets')/hast
 Z←(⍬)0 ⋄ →0
 hast:targets←TextList r MArray'targets'
 cexcl←TextList r MArray'exclude'
 out←⍬ ⋄ i←0
 lp:→(i≥≢targets)/done
 i←i+1 ⋄ t←i⊃targets ⋄ ct←local Canon t
 dropped←0 ⋄ j←0
 xl:→(j≥≢cexcl)/keep
 j←j+1 ⋄ →(~ct CapMatchesPattern local Canon(j⊃cexcl))/xl
 dropped←1
 keep:→(dropped)/lp
 out←out,⊂t
 →lp
 done:Z←out 1
∇

⍝ ⍵=(local operation path token handlerPattern) -> section 6.3's handler-level check.
⍝
⍝ IT IS NOT A SECONDARY CHECK (section 5.2, 0.8.2.20). It is the SOLE enforcement wherever
⍝ the subject is derived after dispatch, because the dispatch-level check can be made
⍝ VACUOUS by caller-controlled input: a caller who excludes the one target its capability
⍝ does not cover removes that target from CheckResourceScope's view entirely, and a
⍝ handler that then acts on it has authorized nothing.
⍝
⍝ THREE DIMENSIONS, NOT FOUR. `peers` is not consulted -- the path is local by
⍝ construction at this point (section 1.4's inbound rule refuses a foreign namespace at
⍝ section 6.5 step 3, before any handler runs), and section 6.3's signature names only
⍝ handlers, operations and resources.
⍝
⍝ THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
⍝ rather than a choice: section 6.3's block passes local_peer_id and has no granter
⍝ parameter to pass. Section 5.5a governs chain ATTENUATION, where the subject is a
⍝ PATTERN compared against a parent's pattern; this call site compares a CONCRETE LOCAL
⍝ PATH the handler is about to touch. CapMatchesScope takes the local frame, so the
⍝ correct frame here is the one it already uses.
⍝
⍝ `hp` is the BARE handler id, exactly as CapCheckPermission receives it -- this peer's
⍝ handlers dimension is matched literally against the relative form, and handing the
⍝ absolute resolved pattern to a literal matcher denies everything (the two defects that
⍝ were holding each other up; see CapCheckPermission).
⍝
⍝ There is no caller-exclude set at this call site: the subject is a single concrete path
⍝ and the caller's own exclusions were already applied in deriving it. An empty
⍝ resources.include is a LEGAL grant shape (section 5.2) and DENIES every path here, which
⍝ is what that note says it should -- Covered over an empty include list is 0. A malformed
⍝ path Canons to NeverMatch, which matches no grant, so it falls through to DENY rather
⍝ than being matched against anything.
∇Z←CapCheckPathPermission a;local;op;path;token;hp;garr;n;i;g;ok
 local←1⊃a ⋄ op←2⊃a ⋄ path←3⊃a ⋄ token←4⊃a ⋄ hp←5⊃a
 Z←0
 garr←CapGrantsOfToken token ⋄ n←ArrCount garr ⋄ i←0
 lp:→(i≥n)/0
 i←i+1 ⋄ g←garr ArrItem i
 ok←(CapMatchesIdScope hp(g MSubmap'handlers'))∧(CapMatchesIdScope op(g MSubmap'operations'))
 →(~ok)/lp
 →(~local CapMatchesScope path(g MSubmap'resources'))/lp
 Z←1 ⋄ →0
∇

⍝ ⍵=target -> 1 iff the target is a section 5.4 PATTERN rather than a concrete path.
⍝ A resource-requiring operation takes a concrete path (0.8.2.20); a trailing "/" is a
⍝ LISTING request rather than a pattern -- only a star makes it one.
∇Z←CapIsPatternPath t
 Z←∨/t='*'
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
 →(~TemporalRepresentable cap)/0    ⍝ §6.2 CAP-6a — BEFORE the range checks below
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

⍝ ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ──────────────────
⍝ 1 iff every temporal field on `cap` is either ABSENT or a representable uint64.
⍝
⍝ §6.2 CAP-6a: a verifier "MUST NOT treat the unrepresentable field as absent".
⍝ EntUint answers present←0 for BOTH an absent field and a present NEGATIVE one,
⍝ so `→(pex∧...)` below would silently skip the expiry comparison for
⍝ expires_at:¯1 and honour a hostile token with 200 — a fail-OPEN, and the whole
⍝ point of the rule. This MUST run BEFORE the range checks, because the range
⍝ checks are exactly what the ambiguity defeats.
⍝
⍝ All THREE temporal fields are tested, not just expires_at: the oracle probes
⍝ created_at too, and a guard covering only the two obvious ones reads as correct
⍝ while leaving a third way in.
⍝
⍝ (The >2^64 half of CAP-6a cannot reach here at all: a bignum can only arrive as
⍝ a major-type-6 tag, which the decoder rejects outright per §6.3.)
∇Z←TemporalRepresentable cap
 Z←0
 →(0>cap EntUintState'expires_at')/0
 →(0>cap EntUintState'not_before')/0
 →(0>cap EntUintState'created_at')/0
 Z←1
∇

⍝ ── §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6) ───────────────────────
⍝ Every term below is a (value present) pair — the same shape EntUint answers in.

⍝ §5.6 rule 3 as an exact VALUE test.
⍝
⍝ A term whose conversion created_at+ttl_ms is not representable as uint64 is
⍝ treated as ABSENT, exactly as a null term is. It MUST NOT wrap and MUST NOT
⍝ saturate to a representable maximum — a saturated 2^64-1 is a finite bound no
⍝ reader can distinguish from a deliberate one.
⍝
⍝ GNU APL has no fixed-width integer to overflow: past 2^53 its integers promote
⍝ to FLOAT, so the carry-flag test a C or asm peer writes here would silently
⍝ lose precision and answer "representable" for a value that is not. The test is
⍝ therefore done in the 8-octet base-256 carrier the value model already uses,
⍝ where it is exact — the sum overflows iff it carries out of the top octet.
⍝ The invariant is the VALUE, never the mechanism.
⍝
⍝ ttl_ms == 0 is NOT special-cased, deliberately: §5.6 rule 2 makes 0 a DEFINED
⍝ term yielding created_at (expire immediately), and an ABSENT field is the only
⍝ "no bound" spelling. Letting 0 fall out of the arithmetic is what stops the two
⍝ collapsing into each other.
∇Z←createdAt AddTtlOct ttlOct;s;c;i;d;x
 x←(8⍴256)⊤createdAt
 s←8⍴0 ⋄ c←0 ⋄ i←9
 al:→(i≤1)/done
 i←i-1
 d←(i⊃x)+(i⊃ttlOct)+c
 s[i]←256|d ⋄ c←⌊d÷256
 →al
 done:Z←0 0
 →(0≠c)/0
 Z←(256⊥s)1
∇

⍝ MIN over the DEFINED terms only; no expiry at all when no term is defined.
⍝
⍝ This is a value reached by CONSTRUCTION, not a bound verified by COMPARISON.
⍝ The oracle's own CAP-5 message makes the distinction: "a `<= caller_exp` check
⍝ would pass this; CAP-5 requires the exact clamped value" — so an implementation
⍝ that merely verifies the minted expiry is within the caller's satisfies a
⍝ strictly weaker test than the one being run.
∇Z←MinDefinedExpiry terms;i;t
 Z←0 0 ⋄ i←0
 ml:→(i≥≢terms)/0
 i←i+1 ⋄ t←i⊃terms
 →(~2⊃t)/ml
 →((2⊃Z)∧(1⊃Z)≤1⊃t)/ml
 Z←(1⊃t)1
 →ml
∇

⍝ the absolute caller_capability.expires_at term. A request presenting no
⍝ capability contributes no term.
∇Z←CallerCapExpiryTerm cap
 Z←0 0
 →(~EntPresent cap)/0
 Z←cap EntUint'expires_at'
∇

⍝ the absolute parent.expires_at term, for the delegate path. `request` mints a
⍝ ROOT token (parent nil) and contributes no term here — which is exactly why the
⍝ caller-cap term above has to carry the ceiling.
∇Z←inc ParentExpiryTerm parent;tok
 Z←0 0
 →(0=≢parent)/0
 →(HashZero parent)/0
 tok←inc CapResolve parent
 →(~EntPresent tok)/0
 Z←tok EntUint'expires_at'
∇

⍝ read a DURATION field (ttl_ms) off `e` and convert it to an absolute timestamp
⍝ against createdAt, per §5.6 rule 1. No term when the field is absent; no term
⍝ when the conversion is unrepresentable (rule 3). Mixing a duration in
⍝ UNCONVERTED would yield a timestamp near the epoch and clamp every token to
⍝ already-expired — the failure mode §5.6 names.
∇Z←createdAt DurationTerm a;e;key;r
 e←1⊃a ⋄ key←2⊃a
 Z←0 0
 →(~EntPresent e)/0
 r←(EntDataMap e)MUintOct key
 →(~2⊃r)/0
 Z←createdAt AddTtlOct 1⊃r
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
 temporal:→(TemporalRepresentable current)/e0    ⍝ §6.2 CAP-6a — BEFORE the range checks
 good←0 ⋄ →wl
 e0:now←CapNowMs
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
