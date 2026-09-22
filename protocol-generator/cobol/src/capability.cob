>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — capability system (L3 / §5 verification core).
*>
*> Ported from the spec-first OCaml capability.ml: §5.4 pattern matching, §5.2
*> verify_request / check_permission, §5.5 delegation-chain verification, §5.6
*> attenuation, §6.6 handler resolution, and §6.5 dispatcher signature ingestion.
*>
*> Verdict is a bare ALLOW/DENY (§5.10 Layer-1 determinism); the dispatcher maps
*> DENY→403 with the unresolvable_grantee→401 carve-out surfaced as a flag.
*>
*> verify-request verdict codes:  0 allow  1 authn_fail(401)  2 authz_deny(403)
*>                                3 chain_too_deep(400)  4 unresolvable_grantee(401)
*>
*> Resolution model: a hash resolves to an entity via the envelope `included` map
*> first (returned as a copy), then the content store. Patterns/values are pure
*> string ops; the chain walk is a bounded (max 64) iterative loop over a table.
*> ===================================================================

*> ---- cap-ispid : §5.2 is_peer_id (len>=46, all Base58 alphabet) -----
identification division.
program-id. cap-ispid.
data division.
working-storage section.
01 b58 pic x(58) value
   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".
01 i   pic 9(9) comp-5.
01 p   pic 9(9) comp-5.
01 ok  pic 9(1).
linkage section.
01 lk-seg  pic x(128).
01 lk-len  pic 9(9) comp-5.
01 lk-res  pic 9(1).
procedure division using lk-seg lk-len lk-res.
    move 0 to lk-res
    if lk-len < 46 then goback end-if
    perform varying i from 1 by 1 until i > lk-len
        move 0 to ok
        perform varying p from 1 by 1 until p > 58
            if lk-seg(i:1) = b58(p:1) then move 1 to ok exit perform end-if
        end-perform
        if ok = 0 then goback end-if
    end-perform
    move 1 to lk-res
    goback.
end program cap-ispid.

*> ---- cap-canon : §1.4 canonicalize (frame = peer_id) ----------------
*> leading "/" -> as-is; else "/"+frame+"/"+in.
*>
*> TOTAL (0.8.2.20): the result is "a canonical path OR /never-match". This program
*> used to carry the comment "(./../*/ rejection is gated upstream by path_flex_ok;
*> here we keep the simple prepend form)" -- true of the REQUEST path, which does
*> reach path_flex_ok, and false of a GRANT PATTERN, which does not. A grant exclude
*> of "../x" became "/{granter}/../x", matched nothing, and carved out nothing, so
*> the grant was silently wider than its author wrote (measured on the wire
*> 2026-09-14). The sentinel is unreachable as a canonical path by CONSTRUCTION: its
*> only segment cannot be a peer_id, which needs >= 46 Base58 characters, and "-" is
*> outside the Base58 alphabet.
identification division.
program-id. cap-canon.
data division.
working-storage section.
01 p pic 9(9) comp-5.
linkage section.
01 lk-in    pic x(900).
01 lk-inlen pic 9(9) comp-5.
01 lk-frame pic x(128).
01 lk-framelen pic 9(9) comp-5.
01 lk-out   pic x(900).
01 lk-outlen pic 9(9) comp-5.
procedure division using lk-in lk-inlen lk-frame lk-framelen lk-out lk-outlen.
    if (lk-inlen >= 2 and lk-in(1:2) = "./")
       or (lk-inlen >= 3 and lk-in(1:3) = "../")
       or (lk-inlen >= 2 and lk-in(1:2) = "*/")
        move "/never-match" to lk-out(1:12)
        move 12 to lk-outlen
        goback
    end-if
    if lk-inlen >= 1 and lk-in(1:1) = "/"
        move lk-in(1:lk-inlen) to lk-out(1:lk-inlen)
        move lk-inlen to lk-outlen
        goback
    end-if
    move "/" to lk-out(1:1)
    if lk-framelen > 0 then move lk-frame(1:lk-framelen) to lk-out(2:lk-framelen) end-if
    compute p = 2 + lk-framelen
    move "/" to lk-out(p:1)
    add 1 to p
    if lk-inlen > 0 then move lk-in(1:lk-inlen) to lk-out(p:lk-inlen) end-if
    compute lk-outlen = 1 + lk-framelen + 1 + lk-inlen
    goback.
end program cap-canon.

*> ---- cap-match (RECURSIVE) : §5.4 matches_pattern -------------------
*> Both path and pattern MUST already be canonical (absolute).
identification division.
program-id. cap-match recursive.
data division.
local-storage section.
01 pos    pic 9(9) comp-5.
01 j      pic 9(9) comp-5.
01 plen2  pic 9(9) comp-5.
01 rlen   pic 9(9) comp-5.
01 sub    pic x(900).
01 sublen pic 9(9) comp-5.
01 rem    pic x(900).
01 remlen pic 9(9) comp-5.
linkage section.
01 lk-path   pic x(900).
01 lk-plen   pic 9(9) comp-5.
01 lk-pat    pic x(900).
01 lk-patlen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-path lk-plen lk-pat lk-patlen lk-res.
    move 0 to lk-res
    *> /never-match never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
    *> rule rather than a property of the string: the bare-"*" arm below answers 1 for
    *> any path, so safety must not rest on a value merely looking unmatchable.
    if (lk-plen = 12 and lk-path(1:12) = "/never-match")
       or (lk-patlen = 12 and lk-pat(1:12) = "/never-match")
        goback
    end-if
    *> pattern == "*"
    if lk-patlen = 1 and lk-pat(1:1) = "*"
        move 1 to lk-res  goback
    end-if
    *> pattern starts with "/*/"
    if lk-patlen >= 3 and lk-pat(1:3) = "/*/"
        compute remlen = lk-patlen - 3
        if remlen > 0 then move lk-pat(4:remlen) to rem(1:remlen) end-if
        if lk-plen < 1 then goback end-if
        move 0 to j
        perform varying pos from 2 by 1 until pos > lk-plen
            if lk-path(pos:1) = "/" then move pos to j  exit perform end-if
        end-perform
        if j = 0 then goback end-if
        compute sublen = lk-plen - j
        if sublen > 0 then move lk-path(j + 1:sublen) to sub(1:sublen) end-if
        call "cap-match" using sub sublen rem remlen lk-res
        goback
    end-if
    *> pattern ends with "/*"
    if lk-patlen >= 2 and lk-pat(lk-patlen - 1:2) = "/*"
        compute plen2 = lk-patlen - 1
        if lk-plen >= plen2 and lk-path(1:plen2) = lk-pat(1:plen2)
            move 1 to lk-res
        end-if
        goback
    end-if
    *> exact
    if lk-plen = lk-patlen and lk-path(1:lk-plen) = lk-pat(1:lk-patlen)
        move 1 to lk-res
    end-if
    goback.
end program cap-match.

*> ---- cap-extract-peer : §5.2 extract_peer ---------------------------
*> first segment of normalize_uri(uri); if it is a peer_id, that peer else local.
identification division.
program-id. cap-extract-peer.
data division.
working-storage section.
01 u      pic x(900).
01 ulen   pic 9(9) comp-5.
01 sstart  pic 9(9) comp-5.
01 pos    pic 9(9) comp-5.
01 seg    pic x(128).
01 seglen pic 9(9) comp-5.
01 ispid  pic 9(1).
linkage section.
01 lk-uri    pic x(900).
01 lk-urilen pic 9(9) comp-5.
01 lk-local  pic x(128).
01 lk-locallen pic 9(9) comp-5.
01 lk-out    pic x(128).
01 lk-outlen pic 9(9) comp-5.
procedure division using lk-uri lk-urilen lk-local lk-locallen lk-out lk-outlen.
    *> normalize_uri: strip "entity://"
    if lk-urilen >= 9 and lk-uri(1:9) = "entity://"
        compute ulen = lk-urilen - 9 + 1
        move "/" to u(1:1)
        compute ulen = lk-urilen - 9
        if ulen > 0 then move lk-uri(10:ulen) to u(2:ulen) end-if
        compute ulen = ulen + 1
    else
        move lk-uri(1:lk-urilen) to u(1:lk-urilen)
        move lk-urilen to ulen
    end-if
    *> first_segment: strip leading "/", take up to next "/"
    move 1 to sstart
    if ulen >= 1 and u(1:1) = "/" then move 2 to sstart end-if
    move 0 to seglen
    perform varying pos from sstart by 1 until pos > ulen
        if u(pos:1) = "/" then exit perform end-if
        add 1 to seglen
    end-perform
    if seglen > 0 and seglen <= 128 then move u(sstart:seglen) to seg(1:seglen) end-if
    call "cap-ispid" using seg seglen ispid
    if ispid = 1
        move seg(1:seglen) to lk-out(1:seglen)
        move seglen to lk-outlen
    else
        move lk-local(1:lk-locallen) to lk-out(1:lk-locallen)
        move lk-locallen to lk-outlen
    end-if
    goback.
end program cap-extract-peer.

*> ---- cap-arr-covers : exists pattern in array covering canonical value
*> lk-cv is already canonical; each array element is canonicalized with lk-frame.
identification division.
program-id. cap-arr-covers.
data division.
working-storage section.
01 cur   pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 cnt   pic 9(9) comp-5.
01 i     pic 9(9) comp-5.
01 plen  pic 9(9) comp-5.
01 st    pic s9(9) comp-5.
01 pat   pic x(900).
01 cpat  pic x(900).
01 cpatlen pic 9(9) comp-5.
01 m     pic 9(1).
linkage section.
01 lk-buf    pic x(524288).
01 lk-arroff pic 9(9) comp-5.
01 lk-cv     pic x(900).
01 lk-cvlen  pic 9(9) comp-5.
01 lk-frame  pic x(128).
01 lk-framelen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-buf lk-arroff lk-cv lk-cvlen lk-frame lk-framelen lk-res.
    move 0 to lk-res
    move lk-arroff to cur
    call "cbor-read-head" using lk-buf cur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-buf cur maj addl arg st
        move arg to plen
        move spaces to pat
        if plen > 0 and plen <= 900 then move lk-buf(cur:plen) to pat(1:plen) end-if
        add plen to cur
        call "cap-canon" using pat plen lk-frame lk-framelen cpat cpatlen
        call "cap-match" using lk-cv lk-cvlen cpat cpatlen m
        if m = 1 then move 1 to lk-res  goback end-if
    end-perform
    goback.
end program cap-arr-covers.

*> ---- cap-arr-unmatchable : does any pattern in the array canonicalize to the
*> §5.4 sentinel? AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The
*> sentinel is fail-CLOSED in an include (covers nothing -> the grant grants
*> nothing) and fail-OPEN in an exclude (carves out nothing), so the reading is
*> chosen where the POSITION is known and cap-match stays uniform over its operands.
identification division.
program-id. cap-arr-unmatchable.
data division.
working-storage section.
01 cur   pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 cnt   pic 9(9) comp-5.
01 i     pic 9(9) comp-5.
01 plen  pic 9(9) comp-5.
01 st    pic s9(9) comp-5.
01 pat   pic x(900).
01 cpat  pic x(900).
01 cpatlen pic 9(9) comp-5.
linkage section.
01 lk-buf    pic x(524288).
01 lk-arroff pic 9(9) comp-5.
01 lk-frame  pic x(128).
01 lk-framelen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-buf lk-arroff lk-frame lk-framelen lk-res.
    move 0 to lk-res
    move lk-arroff to cur
    call "cbor-read-head" using lk-buf cur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-buf cur maj addl arg st
        move arg to plen
        move spaces to pat
        if plen > 0 and plen <= 900 then move lk-buf(cur:plen) to pat(1:plen) end-if
        add plen to cur
        call "cap-canon" using pat plen lk-frame lk-framelen cpat cpatlen
        if cpatlen = 12 and cpat(1:12) = "/never-match"
            move 1 to lk-res  goback
        end-if
    end-perform
    goback.
end program cap-arr-unmatchable.

*> ---- cap-id-covers : exists pattern in array covering an ID-SCOPE value ----
*> Identical to cap-arr-covers except that NOTHING is canonicalized — neither the
*> value nor the patterns. §5.2 / F40: handlers, operations and peers are
*> ID-scope, matched literally (bare "*", leading "/*/", trailing "/*", exact);
*> only resources are PATH-scope and take §5.5a canonicalization.
identification division.
program-id. cap-id-covers.
data division.
working-storage section.
01 cur   pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 cnt   pic 9(9) comp-5.
01 i     pic 9(9) comp-5.
01 plen  pic 9(9) comp-5.
01 st    pic s9(9) comp-5.
01 pat   pic x(900).
01 m     pic 9(1).
linkage section.
01 lk-buf    pic x(524288).
01 lk-arroff pic 9(9) comp-5.
01 lk-cv     pic x(900).
01 lk-cvlen  pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-buf lk-arroff lk-cv lk-cvlen lk-res.
    move 0 to lk-res
    move lk-arroff to cur
    call "cbor-read-head" using lk-buf cur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-buf cur maj addl arg st
        move arg to plen
        move spaces to pat
        if plen > 0 and plen <= 900 then move lk-buf(cur:plen) to pat(1:plen) end-if
        add plen to cur
        call "cap-match" using lk-cv lk-cvlen pat plen m
        if m = 1 then move 1 to lk-res  goback end-if
    end-perform
    goback.
end program cap-id-covers.

*> ---- cap-scope-match : matches_scope for an ID-SCOPE dimension -------
*> lk-scopeoff -> a scope map {include:[...], exclude:[...]}.
*>
*> Both sides used to be canonicalized against the local peer frame, which is the
*> §5.5a frame applied to a dimension that has none. §5.2 F40 makes handlers,
*> operations and peers ID-scope: an operations include of "/{local}/get" is a
*> LITERAL that must not authorize the bare operation `get` (canonicalizing the
*> value turns it into an overgrant), and an exclude of "/*/get" must not deny
*> `get` (canonicalizing turns a non-matching literal into a denial). Both
*> directions were measured: include_no_overgrant allowed what it should refuse,
*> exclude_literal refused what it should allow. Same defect as over-applying the
*> §5.5a frame in the attenuation path, reached from the dispatch side.
identification division.
program-id. cap-scope-match.
data division.
working-storage section.
01 cv     pic x(900).
01 cvlen  pic 9(9) comp-5.
01 ioff   pic 9(9) comp-5.
01 ifnd   pic 9(1).
01 eoff   pic 9(9) comp-5.
01 efnd   pic 9(1).
01 cov    pic 9(1).
01 st     pic s9(9) comp-5.
01 k-incl pic x(7) value "include".
01 k-incl-len pic 9(9) comp-5 value 7.
01 k-excl pic x(7) value "exclude".
01 k-excl-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-buf    pic x(524288).
01 lk-scopeoff pic 9(9) comp-5.
01 lk-val    pic x(900).
01 lk-vallen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-buf lk-scopeoff lk-val lk-vallen lk-res.
    move 0 to lk-res
    call "cbor-find-key" using lk-buf lk-scopeoff k-incl k-incl-len ioff ifnd st
    if ifnd = 0 then goback end-if
    call "cap-id-covers" using lk-buf ioff lk-val lk-vallen cov
    if cov = 0 then goback end-if
    call "cbor-find-key" using lk-buf lk-scopeoff k-excl k-excl-len eoff efnd st
    if efnd = 1
        call "cap-id-covers" using lk-buf eoff lk-val lk-vallen cov
        if cov = 1 then goback end-if
    end-if
    move 1 to lk-res
    goback.
end program cap-scope-match.

*> ---- inc-find-hash : entity offset in the included map by 33-byte key
*>
*> §3.1 RESOLUTION INTEGRITY. The key is wire-supplied and so is the value, so a
*> byte compare on the key alone makes the included map an ATTACKER-CHOSEN ADDRESS
*> BOOK: whoever knows a victim's identity hash files their own system/peer under
*> it, signs with their own key, and is attributed the victim's authority. Every
*> signature in that exchange is genuine. Measured on the wire 2026-09-14: this
*> peer answered 200.
*>
*> The bind recomputes content_hash({type,data}) from the candidate entity's own
*> verbatim bytes and requires it to equal the key. This is mechanism (b) of §1.8
*> (discard the key, address by validated hash), so a forged address produces a
*> MISS rather than a new refusal class, and each caller's existing rung answers
*> the §5.2a row that lookup already owns. 0.8.2.23 ruled that a uniform verdict
*> MUST NOT be required, which is what makes the per-site answer conformant.
*>
*> Fails CLOSED: an entry whose type or data cannot be read, or whose hash cannot
*> be recomputed, is not a resolution.
identification division.
program-id. inc-find-hash.
data division.
working-storage section.
01 cur   pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 cnt   pic 9(9) comp-5.
01 i     pic 9(9) comp-5.
01 klen  pic 9(9) comp-5.
01 koff  pic 9(9) comp-5.
01 st    pic s9(9) comp-5.
01 kn      pic x(32).
01 knl     pic 9(9) comp-5.
01 voff    pic 9(9) comp-5.
01 fnd     pic 9(1).
01 scan    pic 9(9) comp-5.
01 toff    pic 9(9) comp-5.
01 tlen    pic 9(9) comp-5.
01 doff    pic 9(9) comp-5.
01 dlen    pic 9(9) comp-5.
01 hash33  pic x(33).
01 rc      pic s9(9) comp-5.
linkage section.
01 lk-buf    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-hash   pic x(33).
01 lk-entoff pic 9(9) comp-5.
01 lk-found  pic 9(1).
procedure division using lk-buf lk-incoff lk-hash lk-entoff lk-found.
    move 0 to lk-found
    move lk-incoff to cur
    call "cbor-read-head" using lk-buf cur maj addl arg st
    if maj not = 5 then goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-buf cur maj addl arg st
        move arg to klen
        move cur to koff
        add klen to cur
        if klen = 33 and lk-buf(koff:33) = lk-hash(1:33)
            perform key-binds
            if lk-found = 1
                move cur to lk-entoff
            end-if
            goback
        end-if
        call "cbor-skip" using lk-buf cur st
    end-perform
    goback.

*> Recompute the candidate entity's content_hash and require it to equal the key.
*> Sets lk-found to 1 only when it binds.
key-binds.
    move 0 to lk-found
    move "type" to kn  move 4 to knl
    call "cbor-find-key" using lk-buf cur kn knl voff fnd st
    if fnd = 0 then exit paragraph end-if
    move voff to scan
    call "cbor-read-head" using lk-buf scan maj addl arg st
    move arg to tlen
    move scan to toff
    move "data" to kn  move 4 to knl
    call "cbor-find-key" using lk-buf cur kn knl voff fnd st
    if fnd = 0 then exit paragraph end-if
    move voff to doff
    move voff to scan
    call "cbor-skip" using lk-buf scan st
    compute dlen = scan - doff
    call "ec_content_hash" using
        by reference lk-buf(toff:tlen) by value tlen
        by reference lk-buf(doff:dlen) by value dlen
        by reference hash33
        returning rc
    if rc not = 0 then exit paragraph end-if
    if hash33(1:33) = lk-hash(1:33)
        move 1 to lk-found
    end-if.
end program inc-find-hash.

*> ---- inc-keys-bind : §3.1 / §1.8 at the DECODE BOUNDARY -------------
*>
*> Every `included` entry must hash to the key it is filed under. inc-find-hash
*> above asks the same question at the LOOKUP, which is §1.8 mechanism (b) -- the
*> key is discarded, a forged address MISSES, and each caller's existing rung
*> answers the §5.2a row that lookup owns. This sweep is mechanism (a) at the
*> boundary, and it is what the WIRE observes: §4.11 requires a coded refusal
*> BEFORE admission, so a mis-keyed map cannot be allowed to reach the §1.4
*> address gate and come back as `invalid_request` -- §5.2a pins 400
*> hash_mismatch for a peer that refuses at the decode boundary, and
*> `non_canonical_ecf` is not conformant there because the bytes ARE canonical;
*> what is false is the claim the KEY makes.
*>
*> Keeping both is deliberate: this one is the wire answer, inc-find-hash is the
*> backstop for any future caller that reaches the map without coming through
*> here, and they spell the same rule.
*>
*> SCOPE, stated because it is a hole and not an omission: only 33-byte keys are
*> checked. A key of any other length cannot be an ecfv1-sha256 content_hash, and
*> inc-find-hash only ever MATCHES 33-byte keys, so an entry filed under a 7-byte
*> key is unresolvable by construction and refusing it would refuse a frame
*> nothing can act on.
identification division.
program-id. inc-keys-bind.
data division.
working-storage section.
01 incoff pic 9(9) comp-5.
01 incf   pic 9(1).
01 cur    pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 cnt    pic 9(9) comp-5.
01 i      pic 9(9) comp-5.
01 klen   pic 9(9) comp-5.
01 koff   pic 9(9) comp-5.
01 eoff   pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 key33  pic x(33).
01 fnd    pic 9(1).
linkage section.
01 lk-buf pic x(524288).
01 lk-res pic 9(1).
procedure division using lk-buf lk-res.
    move 1 to lk-res
    call "env-inc-off" using lk-buf incoff incf
    if incf = 0 then goback end-if
    move incoff to cur
    call "cbor-read-head" using lk-buf cur maj addl arg st
    if maj not = 5 then move 0 to lk-res  goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-buf cur maj addl arg st
        move arg to klen
        move cur to koff
        add klen to cur
        move cur to eoff
        if klen = 33
            move lk-buf(koff:33) to key33(1:33)
            call "inc-find-hash" using lk-buf incoff key33 eoff fnd
            if fnd = 0 then move 0 to lk-res  goback end-if
        end-if
        call "cbor-skip" using lk-buf cur st
    end-perform
    goback.
end program inc-keys-bind.

*> ---- cap-resolve : hash -> entity bytes (included then store) -------
identification division.
program-id. cap-resolve.
data division.
working-storage section.
01 eoff  pic 9(9) comp-5.
01 cap-entmax pic 9(9) comp-5 value 524288.
01 endo  pic 9(9) comp-5.
01 f     pic 9(1).
01 st    pic s9(9) comp-5.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-hash   pic x(33).
01 lk-out    pic x(524288).
01 lk-outlen pic 9(9) comp-5.
01 lk-found  pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-hash
                        lk-out lk-outlen lk-found.
    move 0 to lk-found
    if lk-incfnd = 1
        call "inc-find-hash" using lk-env lk-incoff lk-hash eoff f
        if f = 1
            move eoff to endo
            call "cbor-skip" using lk-env endo st
            compute lk-outlen = endo - eoff
            *> Same unchecked-copy shape as tree-handler's do-put, on the capability
            *> path: `lk-out` is a fixed-extent field and the included entity comes
            *> straight off the wire. Over capacity is answered as NOT RESOLVED (fail
            *> closed) rather than copied — a capability whose token cannot be read is
            *> not a capability that has been verified.
            if lk-outlen > 0 and lk-outlen <= cap-entmax
                move lk-env(eoff:lk-outlen) to lk-out(1:lk-outlen)
                move 1 to lk-found
                goback
            end-if
            move 0 to lk-outlen
            move 0 to lk-found
            goback
        end-if
    end-if
    call "store-get-by-hash" using lk-hash lk-out lk-outlen lk-found
    goback.
end program cap-resolve.

*> ---- cap-verify-sig : verify a system/signature entity vs a peer entity
identification division.
program-id. cap-verify-sig.
data division.
working-storage section.
01 voff  pic 9(9) comp-5.
01 f     pic 9(1).
01 tgt   pic x(33).
01 tl    pic 9(9) comp-5.
01 sig   pic x(64).
01 sl    pic 9(9) comp-5.
01 pub   pic x(32).
01 pl    pic 9(9) comp-5.
01 k-tgt pic x(6) value "target".
01 k-tgt-len pic 9(9) comp-5 value 6.
01 k-sig pic x(9) value "signature".
01 k-sig-len pic 9(9) comp-5 value 9.
01 k-pk  pic x(10) value "public_key".
01 k-pk-len pic 9(9) comp-5 value 10.
linkage section.
01 lk-sbuf pic x(524288).
01 lk-soff pic 9(9) comp-5.
01 lk-pbuf pic x(524288).
01 lk-poff pic 9(9) comp-5.
01 lk-res  pic 9(1).
procedure division using lk-sbuf lk-soff lk-pbuf lk-poff lk-res.
    move 0 to lk-res
    call "ent-field" using lk-sbuf lk-soff k-tgt k-tgt-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-sbuf voff tgt tl
    call "ent-field" using lk-sbuf lk-soff k-sig k-sig-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-sbuf voff sig sl
    call "ent-field" using lk-pbuf lk-poff k-pk k-pk-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-pbuf voff pub pl
    if tl not = 33 or sl not = 64 or pl not = 32 then goback end-if
    call "verify-sig" using pub tgt sig lk-res
    goback.
end program cap-verify-sig.

*> ---- cap-resource-match : §5.4 / §PR-8 check_resource_scope ----------
*> resource map at lk-resoff {targets:[...], exclude:[...]} (env frame); grant
*> resources sub-map at the grant map lk-gmapoff (granter frame for incl/excl).
identification division.
program-id. cap-resource-match.
data division.
working-storage section.
01 toff  pic 9(9) comp-5.
01 tf    pic 9(1).
01 exoff pic 9(9) comp-5.
01 exf   pic 9(1).
01 rsoff pic 9(9) comp-5.
01 rsf   pic 9(1).
01 gioff pic 9(9) comp-5.
01 gif   pic 9(1).
01 geoff pic 9(9) comp-5.
01 gef   pic 9(1).
01 cur   pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 cnt   pic 9(9) comp-5.
01 i     pic 9(9) comp-5.
01 tlen  pic 9(9) comp-5.
01 tgt   pic x(900).
01 ctgt  pic x(900).
01 ctlen pic 9(9) comp-5.
01 cov   pic 9(1).
01 st    pic s9(9) comp-5.
01 k-tgts pic x(7) value "targets".
01 k-tgts-len pic 9(9) comp-5 value 7.
01 k-excl pic x(7) value "exclude".
01 k-excl-len pic 9(9) comp-5 value 7.
01 k-res  pic x(9) value "resources".
01 k-res-len pic 9(9) comp-5 value 9.
01 k-incl pic x(7) value "include".
01 k-incl-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-env   pic x(524288).
01 lk-resoff pic 9(9) comp-5.
01 lk-tbuf  pic x(524288).
01 lk-gmapoff pic 9(9) comp-5.
01 lk-local pic x(128).
01 lk-locallen pic 9(9) comp-5.
01 lk-granter pic x(128).
01 lk-granterlen pic 9(9) comp-5.
01 lk-out   pic 9(1).
procedure division using lk-env lk-resoff lk-tbuf lk-gmapoff
                        lk-local lk-locallen lk-granter lk-granterlen lk-out.
    move 0 to lk-out
    call "cbor-find-key" using lk-env lk-resoff k-tgts k-tgts-len toff tf st
    if tf = 0 then goback end-if
    move toff to cur
    call "cbor-read-head" using lk-env cur maj addl arg st
    if maj not = 4 or arg = 0 then goback end-if
    move arg to cnt
    call "cbor-find-key" using lk-env lk-resoff k-excl k-excl-len exoff exf st
    *> grant resources sub-map -> include/exclude
    call "cbor-find-key" using lk-tbuf lk-gmapoff k-res k-res-len rsoff rsf st
    move 0 to gif  move 0 to gef
    if rsf = 1
        call "cbor-find-key" using lk-tbuf rsoff k-incl k-incl-len gioff gif st
        call "cbor-find-key" using lk-tbuf rsoff k-excl k-excl-len geoff gef st
    end-if
    *> An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    *> target: the coverage test below is correct in isolation and is simply never
    *> reached on a sentinel, because cap-match answers 0.
    if gef = 1
        call "cap-arr-unmatchable" using lk-tbuf geoff lk-granter lk-granterlen cov
        if cov = 1 then move 0 to lk-out  goback end-if
    end-if
    move 1 to lk-out
    move toff to cur
    call "cbor-read-head" using lk-env cur maj addl arg st
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-env cur maj addl arg st
        move arg to tlen
        move spaces to tgt
        if tlen > 0 and tlen <= 900 then move lk-env(cur:tlen) to tgt(1:tlen) end-if
        add tlen to cur
        call "cap-canon" using tgt tlen lk-local lk-locallen ctgt ctlen
        *> caller exclude (local frame) -> target satisfied
        move 0 to cov
        if exf = 1
            call "cap-arr-covers" using lk-env exoff ctgt ctlen lk-local lk-locallen cov
        end-if
        if cov = 0
            *> grant include (granter frame)
            move 0 to cov
            if gif = 1
                call "cap-arr-covers" using lk-tbuf gioff ctgt ctlen lk-granter lk-granterlen cov
            end-if
            if cov = 0 then move 0 to lk-out  goback end-if
            *> grant exclude (granter frame)
            move 0 to cov
            if gef = 1
                call "cap-arr-covers" using lk-tbuf geoff ctgt ctlen lk-granter lk-granterlen cov
            end-if
            if cov = 1 then move 0 to lk-out  goback end-if
        end-if
    end-perform
    goback.
end program cap-resource-match.

*> ---- cap-check-perm : §5.2 check_permission -------------------------
*> lk-tbuf is the capability TOKEN (offset 1); lk-hpat/lk-hlen the resolved
*> handler pattern (absolute); lk-granter/lk-granterlen the §PR-8 granter frame.
*> Returns lk-verdict 1=allow 0=deny.
identification division.
program-id. cap-check-perm.
data division.
working-storage section.
01 voff   pic 9(9) comp-5.
01 vf     pic 9(1).
01 op     pic x(64).
01 oplen  pic 9(9) comp-5.
01 uri    pic x(900).
01 urilen pic 9(9) comp-5.
01 resoff pic 9(9) comp-5.
01 resf   pic 9(1).
01 local  pic x(128).
01 locallen pic 9(9) comp-5.
01 tp     pic x(128).
01 tplen  pic 9(9) comp-5.
01 gsoff  pic 9(9) comp-5.
01 gsf    pic 9(1).
01 gcur   pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 gcnt   pic 9(9) comp-5.
01 gi     pic 9(9) comp-5.
01 gmap   pic 9(9) comp-5.
01 soff   pic 9(9) comp-5.
01 sf     pic 9(1).
01 r      pic 9(1).
01 st     pic s9(9) comp-5.
01 ok     pic 9(1).
01 k-op   pic x(9) value "operation".
01 k-op-len pic 9(9) comp-5 value 9.
01 k-uri  pic x(3) value "uri".
01 k-uri-len pic 9(9) comp-5 value 3.
01 k-rsrc pic x(8) value "resource".
01 k-rsrc-len pic 9(9) comp-5 value 8.
01 k-grants pic x(6) value "grants".
01 k-grants-len pic 9(9) comp-5 value 6.
01 k-ops  pic x(10) value "operations".
01 k-ops-len pic 9(9) comp-5 value 10.
01 k-hdl  pic x(8) value "handlers".
01 k-hdl-len pic 9(9) comp-5 value 8.
01 k-peers pic x(5) value "peers".
01 k-peers-len pic 9(9) comp-5 value 5.
01 one    pic 9(9) comp-5 value 1.
linkage section.
01 lk-env    pic x(524288).
01 lk-rootoff pic 9(9) comp-5.
01 lk-tbuf   pic x(524288).
01 lk-hpat   pic x(900).
01 lk-hlen   pic 9(9) comp-5.
01 lk-granter pic x(128).
01 lk-granterlen pic 9(9) comp-5.
01 lk-verdict pic 9(1).
procedure division using lk-env lk-rootoff lk-tbuf lk-hpat lk-hlen
                        lk-granter lk-granterlen lk-verdict.
    move 0 to lk-verdict
    call "ps-peerid" using local locallen
    *> operation
    move spaces to op  move 0 to oplen
    call "ent-field" using lk-env lk-rootoff k-op k-op-len voff vf
    if vf = 1 then call "read-text" using lk-env voff op oplen end-if
    *> uri
    move spaces to uri  move 0 to urilen
    call "ent-field" using lk-env lk-rootoff k-uri k-uri-len voff vf
    if vf = 1 then call "read-text" using lk-env voff uri urilen end-if
    *> resource present?
    call "ent-field" using lk-env lk-rootoff k-rsrc k-rsrc-len resoff resf
    *> target_peer
    call "cap-extract-peer" using uri urilen local locallen tp tplen
    *> grants array (token.data.grants)
    call "ent-field" using lk-tbuf one k-grants k-grants-len gsoff gsf
    if gsf = 0 then goback end-if
    move gsoff to gcur
    call "cbor-read-head" using lk-tbuf gcur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to gcnt
    perform varying gi from 1 by 1 until gi > gcnt
        move gcur to gmap
        perform grant-ok
        if ok = 1 then move 1 to lk-verdict  goback end-if
        call "cbor-skip" using lk-tbuf gcur st
    end-perform
    goback.

grant-ok.
    move 0 to ok
    *> operations (id-scope: literal, no frame)
    call "cbor-find-key" using lk-tbuf gmap k-ops k-ops-len soff sf st
    if sf = 0 then exit paragraph end-if
    call "cap-scope-match" using lk-tbuf soff op oplen r
    if r = 0 then exit paragraph end-if
    *> handlers (id-scope: literal, no frame)
    call "cbor-find-key" using lk-tbuf gmap k-hdl k-hdl-len soff sf st
    if sf = 0 then exit paragraph end-if
    call "cap-scope-match" using lk-tbuf soff lk-hpat lk-hlen r
    if r = 0 then exit paragraph end-if
    *> peers (optional; default {include:[local]})
    call "cbor-find-key" using lk-tbuf gmap k-peers k-peers-len soff sf st
    if sf = 1
        call "cap-scope-match" using lk-tbuf soff tp tplen r
        if r = 0 then exit paragraph end-if
    else
        if not (tplen = locallen and tp(1:tplen) = local(1:locallen))
            exit paragraph
        end-if
    end-if
    *> resource (granter frame on grant patterns)
    if resf = 1
        call "cap-resource-match" using lk-env resoff lk-tbuf gmap
            local locallen lk-granter lk-granterlen r
        if r = 0 then exit paragraph end-if
    end-if
    move 1 to ok.
end program cap-check-perm.

*> ---- cap-check-path-perm : §6.3 check_path_permission ---------------
*>
*> AND IT IS NOT A SECONDARY CHECK (0.8.2.20). It is the enforcement wherever the
*> subject is derived AFTER dispatch, because the dispatch-level check can be made
*> VACUOUS by caller-controlled input: a caller that excludes the one target its
*> capability does not cover removes that target from cap-check-perm's view
*> entirely, and a handler that then acts on it has authorized nothing. Measured
*> on the wire 2026-09-15: targets:[qB,qA] exclude:[qB] under a grant covering
*> only qA served qB.
*>
*> THREE DIMENSIONS, NOT FOUR, and the LOCAL frame -- both from §6.3's own
*> signature, matches_scope(canonical_path, grant.resources, "path-scope",
*> local_peer_id), which has no granter parameter to pass. `peers` is not
*> consulted: the path is local by construction here, since §1.4's inbound rule
*> refused a foreign namespace before any handler ran.
*>
*> There is no caller-exclude set at this call site: the subject is ONE concrete
*> path and the caller's exclusions were applied in deriving it, so every grant
*> exclude covering the subject denies.
identification division.
program-id. cap-check-path-perm.
data division.
working-storage section.
01 gsoff  pic 9(9) comp-5.
01 gsf    pic 9(1).
01 gcur   pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 gcnt   pic 9(9) comp-5.
01 gi     pic 9(9) comp-5.
01 gmap   pic 9(9) comp-5.
01 soff   pic 9(9) comp-5.
01 sf     pic 9(1).
01 ioff   pic 9(9) comp-5.
01 iff    pic 9(1).
01 eoff   pic 9(9) comp-5.
01 eff    pic 9(1).
01 local  pic x(128).
01 locallen pic 9(9) comp-5.
01 cp     pic x(900).
01 cplen  pic 9(9) comp-5.
01 cov    pic 9(1).
01 r      pic 9(1).
01 ok     pic 9(1).
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 k-grants pic x(6) value "grants".
01 k-grants-len pic 9(9) comp-5 value 6.
01 k-ops  pic x(10) value "operations".
01 k-ops-len pic 9(9) comp-5 value 10.
01 k-hdl  pic x(8) value "handlers".
01 k-hdl-len pic 9(9) comp-5 value 8.
01 k-res  pic x(9) value "resources".
01 k-res-len pic 9(9) comp-5 value 9.
01 k-incl pic x(7) value "include".
01 k-incl-len pic 9(9) comp-5 value 7.
01 k-excl pic x(7) value "exclude".
01 k-excl-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-tbuf   pic x(524288).
01 lk-op     pic x(64).
01 lk-oplen  pic 9(9) comp-5.
01 lk-path   pic x(900).
01 lk-pathlen pic 9(9) comp-5.
01 lk-hpat   pic x(900).
01 lk-hlen   pic 9(9) comp-5.
01 lk-verdict pic 9(1).
procedure division using lk-tbuf lk-op lk-oplen lk-path lk-pathlen
                        lk-hpat lk-hlen lk-verdict.
    move 0 to lk-verdict
    call "ps-peerid" using local locallen
    call "cap-canon" using lk-path lk-pathlen local locallen cp cplen
    call "ent-field" using lk-tbuf one k-grants k-grants-len gsoff gsf
    if gsf = 0 then goback end-if
    move gsoff to gcur
    call "cbor-read-head" using lk-tbuf gcur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to gcnt
    perform varying gi from 1 by 1 until gi > gcnt
        move gcur to gmap
        perform grant-ok
        if ok = 1 then move 1 to lk-verdict  goback end-if
        call "cbor-skip" using lk-tbuf gcur st
    end-perform
    goback.

grant-ok.
    move 0 to ok
    *> operations (id-scope: literal, no frame)
    call "cbor-find-key" using lk-tbuf gmap k-ops k-ops-len soff sf st
    if sf = 0 then exit paragraph end-if
    call "cap-scope-match" using lk-tbuf soff lk-op lk-oplen r
    if r = 0 then exit paragraph end-if
    *> handlers (id-scope: literal, no frame -- the same reading cap-check-perm
    *> uses; the value is the STRIPPED handler id, not the absolute path)
    call "cbor-find-key" using lk-tbuf gmap k-hdl k-hdl-len soff sf st
    if sf = 0 then exit paragraph end-if
    call "cap-scope-match" using lk-tbuf soff lk-hpat lk-hlen r
    if r = 0 then exit paragraph end-if
    *> resources (path-scope, LOCAL frame -- see the header)
    call "cbor-find-key" using lk-tbuf gmap k-res k-res-len soff sf st
    if sf = 0 then exit paragraph end-if
    call "cbor-find-key" using lk-tbuf soff k-excl k-excl-len eoff eff st
    if eff = 1
        *> An unmatchable GRANT exclude DENIES (0.8.2.21), asked FIRST.
        call "cap-arr-unmatchable" using lk-tbuf eoff local locallen cov
        if cov = 1 then exit paragraph end-if
    end-if
    call "cbor-find-key" using lk-tbuf soff k-incl k-incl-len ioff iff st
    if iff = 0 then exit paragraph end-if
    call "cap-arr-covers" using lk-tbuf ioff cp cplen local locallen cov
    if cov = 0 then exit paragraph end-if
    if eff = 1
        call "cap-arr-covers" using lk-tbuf eoff cp cplen local locallen cov
        if cov = 1 then exit paragraph end-if
    end-if
    move 1 to ok.
end program cap-check-path-perm.

*> ---- cap-granter-peer : §PR-8 resolve_granter_peer_id ---------------
*> The leaf cap's granter -> peer_id (single-sig). Multisig/unreachable -> local.
identification division.
program-id. cap-granter-peer.
data division.
working-storage section.
01 voff pic 9(9) comp-5.
01 f    pic 9(1).
01 maj  pic 9(2) comp-5.
01 addl pic 9(2) comp-5.
01 arg  pic 9(18) comp-5.
01 st   pic s9(9) comp-5.
01 gh   pic x(33).
01 gl   pic 9(9) comp-5.
01 gp   pic x(524288).
01 gplen pic 9(9) comp-5.
01 found pic 9(1).
01 pub  pic x(32).
01 pl   pic 9(9) comp-5.
01 n32  pic 9(9) comp-5 value 32.
01 k-grr pic x(7) value "granter".
01 k-grr-len pic 9(9) comp-5 value 7.
01 k-pk pic x(10) value "public_key".
01 k-pk-len pic 9(9) comp-5 value 10.
01 one  pic 9(9) comp-5 value 1.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-cap    pic x(524288).
01 lk-out    pic x(128).
01 lk-outlen pic 9(9) comp-5.
procedure division using lk-env lk-incoff lk-incfnd lk-cap lk-out lk-outlen.
    *> default = local frame
    call "ps-peerid" using lk-out lk-outlen
    call "ent-field" using lk-cap one k-grr k-grr-len voff f
    if f = 0 then goback end-if
    *> multisig granter (map) -> local frame
    move voff to st
    call "cbor-read-head" using lk-cap st maj addl arg gl
    if maj = 5 then goback end-if
    call "read-bytes" using lk-cap voff gh gl
    if gl not = 33 then goback end-if
    call "cap-resolve" using lk-env lk-incoff lk-incfnd gh gp gplen found
    if found = 0 then goback end-if
    call "ent-field" using gp one k-pk k-pk-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using gp voff pub pl
    if pl not = 32 then goback end-if
    call "peer-id-of-pubkey" using pub n32 lk-out lk-outlen
    goback.
end program cap-granter-peer.

*> ---- cap-chain-depth : §4.10(b) structural depth pre-check ----------
*> true (1) iff the parent-chain rooted at the cap exceeds 64 links; an
*> unreachable parent is NOT a depth problem (left for verify-chain -> 403).
identification division.
program-id. cap-chain-depth.
data division.
working-storage section.
01 depth pic 9(9) comp-5.
01 cur   pic x(524288).
01 curlen pic 9(9) comp-5.
01 voff  pic 9(9) comp-5.
01 f     pic 9(1).
01 phash    pic x(33).
01 pl    pic 9(9) comp-5.
01 nxt   pic x(524288).
01 nxtlen pic 9(9) comp-5.
01 found pic 9(1).
01 done  pic 9(1).
01 one   pic 9(9) comp-5 value 1.
01 k-parent pic x(6) value "parent".
01 k-parent-len pic 9(9) comp-5 value 6.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-cap    pic x(524288).
01 lk-caplen pic 9(9) comp-5.
01 lk-exceeds pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-cap lk-caplen lk-exceeds.
    move 0 to lk-exceeds
    move 0 to depth
    move lk-cap(1:lk-caplen) to cur(1:lk-caplen)
    move lk-caplen to curlen
    move 0 to done
    perform until done = 1
        if depth > 64
            move 1 to lk-exceeds  move 1 to done
        else
            call "ent-field" using cur one k-parent k-parent-len voff f
            if f = 0
                move 1 to done
            else
                call "read-bytes" using cur voff phash pl
                call "cap-resolve" using lk-env lk-incoff lk-incfnd phash
                    nxt nxtlen found
                if found = 0
                    move 1 to done
                else
                    move nxt(1:nxtlen) to cur(1:nxtlen)
                    move nxtlen to curlen
                    add 1 to depth
                end-if
            end-if
        end-if
    end-perform
    goback.
end program cap-chain-depth.

*> ---- cap-verify-chain : §5.5 delegation-chain verification ----------
*> Single-sig root-at-local + per-link sig/grantee/temporal (+ parent linkage).
*> Multisig roots + full §5.6 attenuation are layered in a later step.
*> lk-verdict 1=allow 0=deny; lk-unres 1 => unresolvable_grantee (401 carve-out).
identification division.
program-id. cap-verify-chain.
data division.
working-storage section.
01 ws-n   pic 9(9) comp-5.
01 ws-chain.
   05 ws-ce occurs 64.
      10 ws-ce-buf pic x(32768).
      10 ws-ce-len pic 9(9) comp-5.
01 cur    pic x(524288).
01 curlen pic 9(9) comp-5.
01 voff   pic 9(9) comp-5.
01 f      pic 9(1).
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 phash     pic x(33).
01 pl     pic 9(9) comp-5.
01 tmp    pic x(524288).
01 tmplen pic 9(9) comp-5.
01 found  pic 9(1).
01 done   pic 9(1).
01 k      pic 9(9) comp-5.
01 chash  pic x(33).
01 cgrr   pic x(33).
01 cgl    pic 9(9) comp-5.
01 sigoff pic 9(9) comp-5.
01 sf     pic 9(1).
01 signer pic x(33).
01 snl    pic 9(9) comp-5.
01 gp     pic x(524288).
01 gplen  pic 9(9) comp-5.
01 vres   pic 9(1).
01 msrok  pic 9(1).
01 cpeer  pic x(128).
01 cpeerlen pic 9(9) comp-5.
01 cok    pic 9(1).
01 ppeer  pic x(128).
01 ppeerlen pic 9(9) comp-5.
01 pok    pic 9(1).
01 att    pic 9(1).
01 gee    pic x(33).
01 gel    pic 9(9) comp-5.
01 pgr    pic x(33).
01 pgl    pic 9(9) comp-5.
01 ws-now pic s9(18) comp-5.
01 nb     pic 9(18) comp-5.
01 ex     pic 9(18) comp-5.
01 pub    pic x(32).
01 pbl    pic 9(9) comp-5.
01 rpid   pic x(128).
01 rpidlen pic 9(9) comp-5.
01 local  pic x(128).
01 locallen pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 n32    pic 9(9) comp-5 value 32.
01 one    pic 9(9) comp-5 value 1.
01 k-parent pic x(6) value "parent".
01 k-parent-len pic 9(9) comp-5 value 6.
01 k-grr  pic x(7) value "granter".
01 k-grr-len pic 9(9) comp-5 value 7.
01 k-gre  pic x(7) value "grantee".
01 k-gre-len pic 9(9) comp-5 value 7.
01 k-signer pic x(6) value "signer".
01 k-signer-len pic 9(9) comp-5 value 6.
01 k-pk   pic x(10) value "public_key".
01 k-pk-len pic 9(9) comp-5 value 10.
01 k-nb   pic x(10) value "not_before".
01 k-nb-len pic 9(9) comp-5 value 10.
01 k-ex   pic x(10) value "expires_at".
01 k-ex-len pic 9(9) comp-5 value 10.
01 k-ca   pic x(10) value "created_at".
01 k-ca-len pic 9(9) comp-5 value 10.
01 ca     pic 9(18) comp-5.
01 tok-ck pic 9(1).
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-cap    pic x(524288).
01 lk-caplen pic 9(9) comp-5.
01 lk-rootpid pic x(128).
01 lk-rootpidlen pic 9(9) comp-5.
01 lk-verdict pic 9(1).
01 lk-unres  pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-cap lk-caplen
                        lk-rootpid lk-rootpidlen lk-verdict lk-unres.
    move 0 to lk-verdict
    move 0 to lk-unres
    call "ps-peerid" using local locallen
    *> ---- collect chain (leaf .. root) ----
    move lk-cap(1:lk-caplen) to ws-ce-buf(1)(1:lk-caplen)
    move lk-caplen to ws-ce-len(1)
    move 1 to ws-n
    move 0 to done
    perform until done = 1
        call "ent-field" using ws-ce-buf(ws-n) one k-parent k-parent-len voff f
        if f = 0
            move 1 to done
        else
            call "read-bytes" using ws-ce-buf(ws-n) voff phash pl
            call "cap-resolve" using lk-env lk-incoff lk-incfnd phash tmp tmplen found
            if found = 0
                goback                          *> unreachable -> deny
            end-if
            if ws-n >= 64
                goback                          *> too deep -> deny (depth gate ran earlier)
            end-if
            add 1 to ws-n
            move tmp(1:tmplen) to ws-ce-buf(ws-n)(1:tmplen)
            move tmplen to ws-ce-len(ws-n)
        end-if
    end-perform
    *> ---- root authority: single-sig root-at-local OR §3.6 M3 multisig ----
    call "ent-field" using ws-ce-buf(ws-n) one k-grr k-grr-len voff f
    if f = 0 then goback end-if
    move voff to st
    call "cbor-read-head" using ws-ce-buf(ws-n) st maj addl arg cgl
    if maj = 5
        *> §1.4 (0.8.2.19): A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY, so
        *> a foreign root frame REFUSES the quorum arm OUTRIGHT rather than
        *> verifying it. "Minted by the target" means the target SOLELY minted it;
        *> a K-of-N root is a GROUP's authority and its co-signers authorized it
        *> too, so accepting one here would let any single signer's target confer
        *> the whole group's grant (E3/F66). §5.5's M6 independently requires the
        *> LOCAL peer in the signer set, which is exactly why THE WIRE CANNOT
        *> MEASURE THIS CLAUSE -- the oracle's K-of-2 root is not co-signed by us,
        *> so M6 refuses it first for a reason unrelated to §1.4, and planting this
        *> guard out leaves the row GREEN. The unit gate is what measures it.
        if not (lk-rootpidlen = locallen
                and lk-rootpid(1:lk-rootpidlen) = local(1:locallen))
            goback
        end-if
        call "cap-verify-msr" using lk-env lk-incoff lk-incfnd
            ws-ce-buf(ws-n) voff msrok
        if msrok = 0 then goback end-if
    else
        call "read-bytes" using ws-ce-buf(ws-n) voff phash pl
        if pl not = 33 then goback end-if
        call "cap-resolve" using lk-env lk-incoff lk-incfnd phash gp gplen found
        if found = 0 then goback end-if
        call "ent-field" using gp one k-pk k-pk-len voff f
        if f = 0 then goback end-if
        call "read-bytes" using gp voff pub pbl
        if pbl not = 32 then goback end-if
        call "peer-id-of-pubkey" using pub n32 rpid rpidlen
        *> The root granter must resolve to the EXPECTED ROOT PEER, which is the
        *> local peer for §5.5 dispatch and the TARGET for §1.4's PD-2 presented
        *> arm. Parameterized rather than forked: a second copy of a chain walk is
        *> a second copy that drifts, and every other clause below is unchanged.
        if not (rpidlen = lk-rootpidlen
                and rpid(1:rpidlen) = lk-rootpid(1:lk-rootpidlen))
            goback
        end-if
    end-if
    *> ---- per-link checks ----
    call "ec_now_ms" using ws-now
    perform varying k from 1 by 1 until k > ws-n
        *> signature: find sig targeting current.hash, signer == granter, verify
        call "ent-hash" using ws-ce-buf(k) one chash
        call "ent-field" using ws-ce-buf(k) one k-grr k-grr-len voff f
        if f = 0 then goback end-if
        move voff to st
        call "cbor-read-head" using ws-ce-buf(k) st maj addl arg cgl
        if maj = 5
            *> §3.6 M3 multisig: root-only and fully verified above; a multisig
            *> token anywhere but the chain root is rejected.
            if k not = ws-n then goback end-if
            exit perform cycle
        end-if
        call "read-bytes" using ws-ce-buf(k) voff cgrr cgl
        if lk-incfnd = 0 then goback end-if
        call "inc-find-sig-for" using lk-env lk-incoff chash sigoff sf
        if sf = 0 then goback end-if
        call "ent-field" using lk-env sigoff k-signer k-signer-len voff f
        if f = 0 then goback end-if
        call "read-bytes" using lk-env voff signer snl
        if not (snl = 33 and cgl = 33 and signer(1:33) = cgrr(1:33))
            goback
        end-if
        call "cap-resolve" using lk-env lk-incoff lk-incfnd cgrr gp gplen found
        if found = 0 then goback end-if
        call "cap-verify-sig" using lk-env sigoff gp one vres
        if vres = 0 then goback end-if
        *> grantee resolution -> 401 carve-out
        call "ent-field" using ws-ce-buf(k) one k-gre k-gre-len voff f
        if f = 0 then move 1 to lk-unres  goback end-if
        call "read-bytes" using ws-ce-buf(k) voff gee gel
        call "cap-resolve" using lk-env lk-incoff lk-incfnd gee tmp tmplen found
        if found = 0 then move 1 to lk-unres  goback end-if
        *> temporal, per link. §6.2 CAP-6a: representability is tested FIRST and on
        *> ALL THREE fields — created_at is the one an audit shaped around expiry
        *> checks misses. A field that is present but not a representable uint is
        *> MALFORMED, not absent, and absent means "no bound"; collapsing the two
        *> honours a capability whose expiry is a bignum or a negative number.
        call "ent-field" using ws-ce-buf(k) one k-ca k-ca-len voff f
        if f = 1
            call "read-uint-ck" using ws-ce-buf(k) voff ca tok-ck
            if tok-ck = 0 then goback end-if
        end-if
        call "ent-field" using ws-ce-buf(k) one k-nb k-nb-len voff f
        if f = 1
            call "read-uint-ck" using ws-ce-buf(k) voff nb tok-ck
            if tok-ck = 0 then goback end-if
            if ws-now < nb then goback end-if
        end-if
        call "ent-field" using ws-ce-buf(k) one k-ex k-ex-len voff f
        if f = 1
            call "read-uint-ck" using ws-ce-buf(k) voff ex tok-ck
            if tok-ck = 0 then goback end-if
            *> §5.6 CAP-6: expiry is an EXCLUSIVE upper bound — expired at
            *> now >= expires_at. This pairs with ttl_ms:0 minting
            *> expires_at == created_at, which must be expired at every
            *> observable instant rather than valid for one and racing.
            if ex <= ws-now then goback end-if
        end-if
        *> delegation linkage: parent.grantee == current.granter
        if k < ws-n
            call "ent-field" using ws-ce-buf(k + 1) one k-gre k-gre-len voff f
            if f = 0 then goback end-if
            call "read-bytes" using ws-ce-buf(k + 1) voff pgr pgl
            if not (pgl = 33 and cgl = 33 and pgr(1:33) = cgrr(1:33))
                goback
            end-if
            *> §5.5a per-link granter frames + §5.6 attenuation (hard-fail on
            *> an unresolvable link granter rather than fall back to local).
            call "cap-link-granter" using lk-env lk-incoff lk-incfnd
                ws-ce-buf(k) cpeer cpeerlen cok
            call "cap-link-granter" using lk-env lk-incoff lk-incfnd
                ws-ce-buf(k + 1) ppeer ppeerlen pok
            if cok = 0 or pok = 0 then goback end-if
            call "cap-is-attenuated" using lk-env ws-ce-buf(k) cpeer cpeerlen
                ws-ce-buf(k + 1) ppeer ppeerlen att
            if att = 0 then goback end-if
        end-if
    end-perform
    move 1 to lk-verdict
    goback.
end program cap-verify-chain.

*> ---- cap-is-revoked : §5.1 marker check ----------------------------
*> Revoked iff a marker is bound at /{local}/system/capability/revocations/{hex}
*> for either the leaf cap hash or the chain-root hash.
identification division.
program-id. cap-is-revoked.
data division.
working-storage section.
01 caphash pic x(33).
01 cur     pic x(524288).
01 curlen  pic 9(9) comp-5.
01 voff    pic 9(9) comp-5.
01 f       pic 9(1).
01 phash   pic x(33).
01 pl      pic 9(9) comp-5.
01 nxt     pic x(524288).
01 nxtlen  pic 9(9) comp-5.
01 found   pic 9(1).
01 done    pic 9(1).
01 rk      pic 9(1).
01 one     pic 9(9) comp-5 value 1.
01 one33   pic 9(9) comp-5 value 33.
01 hexh    pic x(256).
01 hexlen  pic 9(9) comp-5.
01 rel     pic x(700).
01 rellen  pic 9(9) comp-5.
01 path    pic x(700).
01 pathlen pic 9(9) comp-5.
01 ent     pic x(524288).
01 entlen  pic 9(9) comp-5.
01 efound  pic 9(1).
01 s-revs  pic x(30) value "system/capability/revocations/".
01 k-parent pic x(6) value "parent".
01 k-parent-len pic 9(9) comp-5 value 6.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-cap    pic x(524288).
01 lk-caplen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-cap lk-caplen lk-res.
    move 0 to lk-res
    call "ent-hash" using lk-cap one caphash
    perform check-marker
    if rk = 1 then move 1 to lk-res  goback end-if
    move lk-cap(1:lk-caplen) to cur(1:lk-caplen)
    move lk-caplen to curlen
    move 0 to done
    perform until done = 1
        call "ent-field" using cur one k-parent k-parent-len voff f
        if f = 0
            move 1 to done
        else
            call "read-bytes" using cur voff phash pl
            call "cap-resolve" using lk-env lk-incoff lk-incfnd phash nxt nxtlen found
            if found = 0
                move 1 to done
            else
                move nxt(1:nxtlen) to cur(1:nxtlen)
                move nxtlen to curlen
            end-if
        end-if
    end-perform
    call "ent-hash" using cur one caphash
    perform check-marker
    if rk = 1 then move 1 to lk-res end-if
    goback.

check-marker.
    move 0 to rk
    call "to-hex" using caphash one33 hexh hexlen
    move s-revs to rel(1:30)
    move hexh(1:hexlen) to rel(31:hexlen)
    compute rellen = 30 + hexlen
    call "mkpath" using rel rellen path pathlen
    call "store-get-at" using path pathlen ent entlen efound
    if efound = 1 then move 1 to rk end-if.
end program cap-is-revoked.

*> ---- verify-request : §5.2 -----------------------------------------
*> verdict 0 allow / 1 authn(401) / 2 authz(403) / 3 depth(400) / 4 unres(401)
identification division.
program-id. verify-request.
data division.
working-storage section.
01 exechash pic x(33).
01 author  pic x(33).
01 al      pic 9(9) comp-5.
01 sigoff  pic 9(9) comp-5.
01 sf      pic 9(1).
01 signer  pic x(33).
01 snl     pic 9(9) comp-5.
01 abuf    pic x(524288).
01 ablen   pic 9(9) comp-5.
01 found   pic 9(1).
01 vres    pic 9(1).
01 caph    pic x(33).
01 cl      pic 9(9) comp-5.
01 capbuf  pic x(524288).
01 caplen  pic 9(9) comp-5.
01 exceeds pic 9(1).
01 cverdict pic 9(1).
01 unres   pic 9(1).
01 vr-local pic x(128).
01 vr-locallen pic 9(9) comp-5.
01 gee     pic x(33).
01 gel     pic 9(9) comp-5.
01 voff    pic 9(9) comp-5.
01 f       pic 9(1).
01 rev     pic 9(1).
01 one     pic 9(9) comp-5 value 1.
01 k-author pic x(6) value "author".
01 k-author-len pic 9(9) comp-5 value 6.
01 k-signer pic x(6) value "signer".
01 k-signer-len pic 9(9) comp-5 value 6.
01 k-cap   pic x(10) value "capability".
01 k-cap-len pic 9(9) comp-5 value 10.
01 k-gre   pic x(7) value "grantee".
01 k-gre-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-env    pic x(524288).
01 lk-rootoff pic 9(9) comp-5.
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-verdict pic 9(1).
procedure division using lk-env lk-rootoff lk-incoff lk-incfnd lk-verdict.
    move 1 to lk-verdict                       *> default authn-fail
    *> author (required for signer match)
    call "ent-field" using lk-env lk-rootoff k-author k-author-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-env voff author al
    if al not = 33 then goback end-if
    *> signature targeting exec.hash
    if lk-incfnd = 0 then goback end-if
    call "ent-hash" using lk-env lk-rootoff exechash
    call "inc-find-sig-for" using lk-env lk-incoff exechash sigoff sf
    if sf = 0 then goback end-if
    call "ent-field" using lk-env sigoff k-signer k-signer-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-env voff signer snl
    if not (snl = 33 and signer(1:33) = author(1:33)) then goback end-if
    *> resolve author entity, verify sig
    call "inc-resolve" using lk-env lk-incoff lk-incfnd author abuf ablen found
    if found = 0 then goback end-if
    call "cap-verify-sig" using lk-env sigoff abuf one vres
    if vres = 0 then goback end-if
    *> ---- authorization class (403) ----
    move 2 to lk-verdict
    call "ent-field" using lk-env lk-rootoff k-cap k-cap-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-env voff caph cl
    if cl not = 33 then goback end-if
    call "inc-resolve" using lk-env lk-incoff lk-incfnd caph capbuf caplen found
    if found = 0 then goback end-if
    *> §4.10(b) depth pre-check -> 400
    call "cap-chain-depth" using lk-env lk-incoff lk-incfnd capbuf caplen exceeds
    if exceeds = 1 then move 3 to lk-verdict  goback end-if
    *> chain verification (raises unres -> 401). §5.5 dispatch is LOCALLY ROOTED:
    *> the expected root granter is this peer. §1.4's PD-2 presented arm is the one
    *> call site that names a different root, and it names the TARGET.
    call "ps-peerid" using vr-local vr-locallen
    call "cap-verify-chain" using lk-env lk-incoff lk-incfnd capbuf caplen
        vr-local vr-locallen cverdict unres
    if unres = 1 then move 4 to lk-verdict  goback end-if
    if cverdict = 0 then move 2 to lk-verdict  goback end-if
    *> grantee == author
    call "ent-field" using capbuf one k-gre k-gre-len voff f
    if f = 0 then move 2 to lk-verdict  goback end-if
    call "read-bytes" using capbuf voff gee gel
    if not (gel = 33 and gee(1:33) = author(1:33)) then move 2 to lk-verdict  goback end-if
    *> revocation
    call "cap-is-revoked" using lk-env lk-incoff lk-incfnd capbuf caplen rev
    if rev = 1 then move 2 to lk-verdict  goback end-if
    move 0 to lk-verdict
    goback.
end program verify-request.

*> ---- resolve-handler : §6.6 backward tree-walk ----------------------
*> Walk decreasing path prefixes; the longest prefix bound to a system/handler
*> entity is the dispatch target. Returns the absolute pattern + found.
identification division.
program-id. resolve-handler.
data division.
working-storage section.
01 curlen pic 9(9) comp-5.
01 j      pic 9(9) comp-5.
01 pos    pic 9(9) comp-5.
01 ent    pic x(524288).
01 elen   pic 9(9) comp-5.
01 ef     pic 9(1).
01 etype  pic x(64).
01 etlen  pic 9(9) comp-5.
01 done   pic 9(1).
01 one    pic 9(9) comp-5 value 1.
01 t-hdl  pic x(14) value "system/handler".
linkage section.
01 lk-path pic x(900).
01 lk-plen pic 9(9) comp-5.
01 lk-pat  pic x(900).
01 lk-patlen pic 9(9) comp-5.
01 lk-found pic 9(1).
procedure division using lk-path lk-plen lk-pat lk-patlen lk-found.
    move 0 to lk-found
    move lk-plen to curlen
    move 0 to done
    perform until done = 1 or curlen <= 0
        call "store-get-at" using lk-path(1:curlen) curlen ent elen ef
        if ef = 1
            call "ent-type" using ent one etype etlen
            if etlen = 14 and etype(1:14) = t-hdl
                move lk-path(1:curlen) to lk-pat(1:curlen)
                move curlen to lk-patlen
                move 1 to lk-found
                move 1 to done
            end-if
        end-if
        if done = 0
            *> strip the last segment
            move 0 to j
            perform varying pos from curlen by -1 until pos < 1
                if lk-path(pos:1) = "/" then move pos to j  exit perform end-if
            end-perform
            if j <= 1
                move 1 to done
            else
                compute curlen = j - 1
            end-if
        end-if
    end-perform
    goback.
end program resolve-handler.

*> store-get-at expects a 700-byte path + len; resolve-handler passes a slice.
*> A tiny shim keeps the 900-byte path buffer usable with the 700 store iface.

*> ---- ingest-signatures : §6.5 (no-op) -------------------------------
*> Resolution is envelope-first: every entity a request references (cap chain,
*> granter/grantee/author peers, signatures) is carried in the request's
*> `included` map, which cap-resolve checks before the store. Content-addressing
*> all included entities into the store added nothing for resolution and grew the
*> bounded store without limit over a long conformance run — so this is a no-op.
*> Cross-request state (revocation markers, registered handlers, policy entries,
*> tree puts) is written by the handlers via store-bind, not here.
identification division.
program-id. ingest-signatures.
data division.
working-storage section.
01 dummy pic 9(1).
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd.
    goback.
end program ingest-signatures.

*> ---- inc-resolve : included-only resolve (no store fallback) --------
*> §5.2 author + capability MUST be carried in the envelope `included` map; the
*> store fallback (cap-resolve) is only for chain-link resolution (§5.5).
identification division.
program-id. inc-resolve.
data division.
working-storage section.
01 eoff pic 9(9) comp-5.
01 endo pic 9(9) comp-5.
01 f    pic 9(1).
01 st   pic s9(9) comp-5.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-hash   pic x(33).
01 lk-out    pic x(524288).
01 lk-outlen pic 9(9) comp-5.
01 lk-found  pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-hash
                        lk-out lk-outlen lk-found.
    move 0 to lk-found
    if lk-incfnd = 0 then goback end-if
    call "inc-find-hash" using lk-env lk-incoff lk-hash eoff f
    if f = 0 then goback end-if
    move eoff to endo
    call "cbor-skip" using lk-env endo st
    compute lk-outlen = endo - eoff
    if lk-outlen > 0 then move lk-env(eoff:lk-outlen) to lk-out(1:lk-outlen) end-if
    move 1 to lk-found
    goback.
end program inc-resolve.

*> ---- path-flex-ok : §1.4 / CORE-TREE-PATH-FLEX-1 path validation ---
*> Reject null byte, a leading "/" whose first segment is not a peer_id,
*> ./ ../ prefixes, and interior empty segments (//). A single trailing "/"
*> is the listing marker and is allowed. Returns 1 ok / 0 reject.
identification division.
program-id. path-flex-ok.
data division.
working-storage section.
01 i        pic 9(9) comp-5.
01 p        pic 9(9) comp-5.
01 bstart   pic 9(9) comp-5.
01 segstart pic 9(9) comp-5.
01 seglen   pic 9(9) comp-5.
01 fseg    pic x(128).
01 fseglen pic 9(9) comp-5.
01 ispid    pic 9(1).
linkage section.
01 lk-tgt    pic x(900).
01 lk-tgtlen pic 9(9) comp-5.
01 lk-ok     pic 9(1).
procedure division using lk-tgt lk-tgtlen lk-ok.
    move 0 to lk-ok
    if lk-tgtlen = 0 then move 1 to lk-ok  goback end-if
    *> null byte anywhere
    perform varying i from 1 by 1 until i > lk-tgtlen
        if lk-tgt(i:1) = x"00" then goback end-if
    end-perform
    move 1 to bstart
    if lk-tgt(1:1) = "/"
        *> fseg segment after leading slash must be a peer_id
        move 0 to fseglen
        perform varying p from 2 by 1 until p > lk-tgtlen
            if lk-tgt(p:1) = "/" then exit perform end-if
            add 1 to fseglen
        end-perform
        if fseglen > 0 and fseglen <= 128 then move lk-tgt(2:fseglen) to fseg(1:fseglen) end-if
        call "cap-ispid" using fseg fseglen ispid
        if ispid = 0 then goback end-if
        move 2 to bstart
    end-if
    *> walk segments; reject empty (//), ".", ".." — a single trailing "/" is ok
    move bstart to segstart
    perform varying i from bstart by 1 until i > lk-tgtlen
        if lk-tgt(i:1) = "/"
            compute seglen = i - segstart
            if seglen = 0
                if i not = lk-tgtlen then goback end-if
            else
                if seglen = 1 and lk-tgt(segstart:1) = "." then goback end-if
                if seglen = 2 and lk-tgt(segstart:2) = ".." then goback end-if
            end-if
            compute segstart = i + 1
        end-if
    end-perform
    *> final segment after the last slash
    compute seglen = lk-tgtlen - segstart + 1
    if seglen = 1 and lk-tgt(segstart:1) = "." then goback end-if
    if seglen = 2 and lk-tgt(segstart:2) = ".." then goback end-if
    move 1 to lk-ok
    goback.
end program path-flex-ok.

*> ---- cap-msr-find-sig : included system/signature for (target,signer) ---
identification division.
program-id. cap-msr-find-sig.
data division.
working-storage section.
01 cur    pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 cnt    pic 9(9) comp-5.
01 i      pic 9(9) comp-5.
01 klen   pic 9(9) comp-5.
01 entoff pic 9(9) comp-5.
01 etype  pic x(32).
01 etlen  pic 9(9) comp-5.
01 voff   pic 9(9) comp-5.
01 tf     pic 9(1).
01 sf     pic 9(1).
01 tb     pic x(33).
01 tbl    pic 9(9) comp-5.
01 sb     pic x(33).
01 sbl    pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 k-tgt  pic x(6) value "target".
01 k-tgt-len pic 9(9) comp-5 value 6.
01 k-signer pic x(6) value "signer".
01 k-signer-len pic 9(9) comp-5 value 6.
01 t-sig  pic x(16) value "system/signature".
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-target pic x(33).
01 lk-sigr   pic x(33).
01 lk-sigoff pic 9(9) comp-5.
01 lk-found  pic 9(1).
procedure division using lk-env lk-incoff lk-target lk-sigr lk-sigoff lk-found.
    move 0 to lk-found
    move lk-incoff to cur
    call "cbor-read-head" using lk-env cur maj addl arg st
    if maj not = 5 then goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-env cur maj addl arg st
        move arg to klen
        add klen to cur
        move cur to entoff
        call "ent-type" using lk-env entoff etype etlen
        if etlen = 16 and etype(1:16) = t-sig
            call "ent-field" using lk-env entoff k-tgt k-tgt-len voff tf
            if tf = 1
                call "read-bytes" using lk-env voff tb tbl
                if tbl = 33 and tb(1:33) = lk-target(1:33)
                    call "ent-field" using lk-env entoff k-signer k-signer-len voff sf
                    if sf = 1
                        call "read-bytes" using lk-env voff sb sbl
                        if sbl = 33 and sb(1:33) = lk-sigr(1:33)
                            move entoff to lk-sigoff
                            move 1 to lk-found
                            exit perform
                        end-if
                    end-if
                end-if
            end-if
        end-if
        call "cbor-skip" using lk-env entoff st
        move entoff to cur
    end-perform
    goback.
end program cap-msr-find-sig.

*> ---- cap-verify-msr : §3.6 M3 / §5.5 M4·M6 multisig root ------------
*> lk-rootbuf is the root cap (offset 1); lk-groff is the granter map offset
*> within it. ALLOW (1) iff the quorum is well-formed AND a threshold of
*> distinct signers signed the root cap's content hash.
identification division.
program-id. cap-verify-msr.
data division.
working-storage section.
01 groff   pic 9(9) comp-5.
01 sgoff   pic 9(9) comp-5.
01 sgf     pic 9(1).
01 thoff   pic 9(9) comp-5.
01 thf     pic 9(1).
01 thr     pic 9(18) comp-5.
01 cur     pic 9(9) comp-5.
01 maj     pic 9(2) comp-5.
01 addl    pic 9(2) comp-5.
01 arg     pic 9(18) comp-5.
01 nsign   pic 9(9) comp-5.
01 i       pic 9(9) comp-5.
01 j       pic 9(9) comp-5.
01 jstart  pic 9(9) comp-5.
01 st      pic s9(9) comp-5.
01 voff    pic 9(9) comp-5.
01 f       pic 9(1).
01 sigtab.
   05 sg occurs 16.
      10 sg-hash pic x(33).
01 roothash pic x(33).
01 gp      pic x(524288).
01 gplen   pic 9(9) comp-5.
01 found   pic 9(1).
01 pub     pic x(32).
01 pbl     pic 9(9) comp-5.
01 spid    pic x(128).
01 spidlen pic 9(9) comp-5.
01 local   pic x(128).
01 locallen pic 9(9) comp-5.
01 m6      pic 9(1).
01 vcnt   pic 9(9) comp-5.
01 sigoff  pic 9(9) comp-5.
01 sfnd    pic 9(1).
01 vres    pic 9(1).
01 ws-now  pic s9(18) comp-5.
01 nb      pic 9(18) comp-5.
01 ex      pic 9(18) comp-5.
01 dup     pic 9(1).
01 n32     pic 9(9) comp-5 value 32.
01 one     pic 9(9) comp-5 value 1.
01 k-signers pic x(7) value "signers".
01 k-signers-len pic 9(9) comp-5 value 7.
01 k-threshold pic x(9) value "threshold".
01 k-threshold-len pic 9(9) comp-5 value 9.
01 k-parent pic x(6) value "parent".
01 k-parent-len pic 9(9) comp-5 value 6.
01 k-gre   pic x(7) value "grantee".
01 k-gre-len pic 9(9) comp-5 value 7.
01 k-pk    pic x(10) value "public_key".
01 k-pk-len pic 9(9) comp-5 value 10.
01 k-nb    pic x(10) value "not_before".
01 k-nb-len pic 9(9) comp-5 value 10.
01 k-ex    pic x(10) value "expires_at".
01 k-ex-len pic 9(9) comp-5 value 10.
01 gee     pic x(33).
01 gel     pic 9(9) comp-5.
01 tmp     pic x(524288).
01 tmplen  pic 9(9) comp-5.
linkage section.
01 lk-env     pic x(524288).
01 lk-incoff  pic 9(9) comp-5.
01 lk-incfnd  pic 9(1).
01 lk-rootbuf pic x(524288).
01 lk-groff   pic 9(9) comp-5.
01 lk-ok      pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-rootbuf lk-groff lk-ok.
    move 0 to lk-ok
    call "ps-peerid" using local locallen
    *> M3: root-only (no parent)
    call "ent-field" using lk-rootbuf one k-parent k-parent-len voff f
    if f = 1 then goback end-if
    *> parse signers array + threshold from the granter map at lk-groff
    call "cbor-find-key" using lk-rootbuf lk-groff k-signers k-signers-len sgoff sgf st
    if sgf = 0 then goback end-if
    call "cbor-find-key" using lk-rootbuf lk-groff k-threshold k-threshold-len thoff thf st
    if thf = 0 then goback end-if
    call "read-uint" using lk-rootbuf thoff thr
    *> read signer hashes
    move sgoff to cur
    call "cbor-read-head" using lk-rootbuf cur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to nsign
    if nsign < 2 or nsign > 16 then goback end-if
    perform varying i from 1 by 1 until i > nsign
        call "cbor-read-head" using lk-rootbuf cur maj addl arg st
        if maj not = 2 or arg not = 33 then goback end-if
        move lk-rootbuf(cur:33) to sg-hash(i)
        add 33 to cur
    end-perform
    *> M3: 2 <= threshold <= n
    if thr < 2 or thr > nsign then goback end-if
    *> M3: distinct signers
    perform varying i from 1 by 1 until i > nsign
        compute jstart = i + 1
        perform varying j from jstart by 1 until j > nsign
            if sg-hash(i)(1:33) = sg-hash(j)(1:33) then goback end-if
        end-perform
    end-perform
    *> M6: local peer must be a quorum member
    move 0 to m6
    perform varying i from 1 by 1 until i > nsign
        call "cap-resolve" using lk-env lk-incoff lk-incfnd sg-hash(i) gp gplen found
        if found = 1
            call "ent-field" using gp one k-pk k-pk-len voff f
            if f = 1
                call "read-bytes" using gp voff pub pbl
                if pbl = 32
                    call "peer-id-of-pubkey" using pub n32 spid spidlen
                    if spidlen = locallen and spid(1:spidlen) = local(1:locallen)
                        move 1 to m6
                    end-if
                end-if
            end-if
        end-if
    end-perform
    if m6 = 0 then goback end-if
    *> temporal validity
    move 0 to nb  move 0 to ex
    call "ec_now_ms" using ws-now
    call "ent-field" using lk-rootbuf one k-nb k-nb-len voff f
    if f = 1 then call "read-uint" using lk-rootbuf voff nb end-if
    call "ent-field" using lk-rootbuf one k-ex k-ex-len voff f
    if f = 1 then call "read-uint" using lk-rootbuf voff ex end-if
    if nb > 0 and ws-now < nb then goback end-if
    if ex > 0 and ex < ws-now then goback end-if
    *> grantee resolution
    call "ent-field" using lk-rootbuf one k-gre k-gre-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-rootbuf voff gee gel
    call "cap-resolve" using lk-env lk-incoff lk-incfnd gee tmp tmplen found
    if found = 0 then goback end-if
    *> M4: count distinct signers with a vcnt signature over the root hash
    call "ent-hash" using lk-rootbuf one roothash
    move 0 to vcnt
    perform varying i from 1 by 1 until i > nsign
        call "cap-resolve" using lk-env lk-incoff lk-incfnd sg-hash(i) gp gplen found
        if found = 1
            call "cap-msr-find-sig" using lk-env lk-incoff roothash sg-hash(i)
                sigoff sfnd
            if sfnd = 1
                call "cap-verify-sig" using lk-env sigoff gp one vres
                if vres = 1 then add 1 to vcnt end-if
            end-if
        end-if
    end-perform
    if vcnt >= thr then move 1 to lk-ok end-if
    goback.
end program cap-verify-msr.

*> ---- cap-arr-subset : every pattern in C-arr covered by P-arr -------
*> C patterns canon with c-frame; P patterns canon with p-frame. Absent
*> source (cf=0) is vacuously a subset; absent target (pf=0) covers nothing.
identification division.
program-id. cap-arr-subset.
data division.
working-storage section.
01 cur   pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 cnt   pic 9(9) comp-5.
01 i     pic 9(9) comp-5.
01 plen  pic 9(9) comp-5.
01 st    pic s9(9) comp-5.
01 pat   pic x(900).
01 cpat  pic x(900).
01 cpatlen pic 9(9) comp-5.
01 cov   pic 9(1).
linkage section.
01 lk-cbuf   pic x(524288).
01 lk-coff   pic 9(9) comp-5.
01 lk-cf     pic 9(1).
01 lk-cframe pic x(128).
01 lk-cframelen pic 9(9) comp-5.
01 lk-pbuf   pic x(524288).
01 lk-poff   pic 9(9) comp-5.
01 lk-pf     pic 9(1).
01 lk-pframe pic x(128).
01 lk-pframelen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-cbuf lk-coff lk-cf lk-cframe lk-cframelen
                        lk-pbuf lk-poff lk-pf lk-pframe lk-pframelen lk-res.
    move 1 to lk-res
    if lk-cf = 0 then goback end-if
    move lk-coff to cur
    call "cbor-read-head" using lk-cbuf cur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-cbuf cur maj addl arg st
        move arg to plen
        move spaces to pat
        if plen > 0 and plen <= 900 then move lk-cbuf(cur:plen) to pat(1:plen) end-if
        add plen to cur
        call "cap-canon" using pat plen lk-cframe lk-cframelen cpat cpatlen
        if lk-pf = 0
            move 0 to lk-res  goback
        end-if
        call "cap-arr-covers" using lk-pbuf lk-poff cpat cpatlen
            lk-pframe lk-pframelen cov
        if cov = 0 then move 0 to lk-res  goback end-if
    end-perform
    goback.
end program cap-arr-subset.

*> ---- cap-dim-subset : §5.6 scope_subset for one dimension ----------
*> child include ⊆ parent include AND parent exclude ⊆ child exclude.
identification division.
program-id. cap-dim-subset.
data division.
working-storage section.
01 ciOff pic 9(9) comp-5.
01 cif   pic 9(1).
01 piOff pic 9(9) comp-5.
01 pif   pic 9(1).
01 ceOff pic 9(9) comp-5.
01 cef   pic 9(1).
01 peOff pic 9(9) comp-5.
01 pef   pic 9(1).
01 ok1   pic 9(1).
01 ok2   pic 9(1).
01 st    pic s9(9) comp-5.
01 k-incl pic x(7) value "include".
01 k-incl-len pic 9(9) comp-5 value 7.
01 k-excl pic x(7) value "exclude".
01 k-excl-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-cbuf   pic x(524288).
01 lk-csc    pic 9(9) comp-5.
01 lk-cscp   pic 9(1).
01 lk-cframe pic x(128).
01 lk-cframelen pic 9(9) comp-5.
01 lk-pbuf   pic x(524288).
01 lk-psc    pic 9(9) comp-5.
01 lk-pscp   pic 9(1).
01 lk-pframe pic x(128).
01 lk-pframelen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-cbuf lk-csc lk-cscp lk-cframe lk-cframelen
                        lk-pbuf lk-psc lk-pscp lk-pframe lk-pframelen lk-res.
    move 0 to lk-res
    move 0 to cif  move 0 to pif  move 0 to cef  move 0 to pef
    if lk-cscp = 1
        call "cbor-find-key" using lk-cbuf lk-csc k-incl k-incl-len ciOff cif st
        call "cbor-find-key" using lk-cbuf lk-csc k-excl k-excl-len ceOff cef st
    end-if
    if lk-pscp = 1
        call "cbor-find-key" using lk-pbuf lk-psc k-incl k-incl-len piOff pif st
        call "cbor-find-key" using lk-pbuf lk-psc k-excl k-excl-len peOff pef st
    end-if
    *> child include ⊆ parent include
    call "cap-arr-subset" using lk-cbuf ciOff cif lk-cframe lk-cframelen
        lk-pbuf piOff pif lk-pframe lk-pframelen ok1
    if ok1 = 0 then goback end-if
    *> parent exclude ⊆ child exclude
    call "cap-arr-subset" using lk-pbuf peOff pef lk-pframe lk-pframelen
        lk-cbuf ceOff cef lk-cframe lk-cframelen ok2
    if ok2 = 0 then goback end-if
    move 1 to lk-res
    goback.
end program cap-dim-subset.

*> ---- cap-grant-subset : §5.6 grant_subset --------------------------
*> handlers/operations/peers on the local frame; resources on the per-link
*> granter frames (child-frame / parent-frame), per §5.5a / §PR-8.
identification division.
program-id. cap-grant-subset.
data division.
working-storage section.
01 local  pic x(128).
01 locallen pic 9(9) comp-5.
01 chOff pic 9(9) comp-5.  01 chf pic 9(1).
01 phOff pic 9(9) comp-5.  01 phf pic 9(1).
01 coOff pic 9(9) comp-5.  01 cof pic 9(1).
01 poOff pic 9(9) comp-5.  01 pof pic 9(1).
01 crOff pic 9(9) comp-5.  01 crf pic 9(1).
01 prOff pic 9(9) comp-5.  01 prf pic 9(1).
01 cpOff pic 9(9) comp-5.  01 cpf pic 9(1).
01 ppOff pic 9(9) comp-5.  01 ppf pic 9(1).
01 okH   pic 9(1).
01 okO   pic 9(1).
01 okR   pic 9(1).
01 okP   pic 9(1).
01 st    pic s9(9) comp-5.
01 k-hdl pic x(8) value "handlers".
01 k-hdl-len pic 9(9) comp-5 value 8.
01 k-ops pic x(10) value "operations".
01 k-ops-len pic 9(9) comp-5 value 10.
01 k-res pic x(9) value "resources".
01 k-res-len pic 9(9) comp-5 value 9.
01 k-peers pic x(5) value "peers".
01 k-peers-len pic 9(9) comp-5 value 5.
linkage section.
01 lk-cbuf   pic x(524288).
01 lk-gc     pic 9(9) comp-5.
01 lk-cframe pic x(128).
01 lk-cframelen pic 9(9) comp-5.
01 lk-pbuf   pic x(524288).
01 lk-gp     pic 9(9) comp-5.
01 lk-pframe pic x(128).
01 lk-pframelen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-cbuf lk-gc lk-cframe lk-cframelen
                        lk-pbuf lk-gp lk-pframe lk-pframelen lk-res.
    move 0 to lk-res
    call "ps-peerid" using local locallen
    call "cbor-find-key" using lk-cbuf lk-gc k-hdl k-hdl-len chOff chf st
    call "cbor-find-key" using lk-pbuf lk-gp k-hdl k-hdl-len phOff phf st
    call "cap-dim-subset" using lk-cbuf chOff chf local locallen
        lk-pbuf phOff phf local locallen okH
    if okH = 0 then goback end-if
    call "cbor-find-key" using lk-cbuf lk-gc k-ops k-ops-len coOff cof st
    call "cbor-find-key" using lk-pbuf lk-gp k-ops k-ops-len poOff pof st
    call "cap-dim-subset" using lk-cbuf coOff cof local locallen
        lk-pbuf poOff pof local locallen okO
    if okO = 0 then goback end-if
    call "cbor-find-key" using lk-cbuf lk-gc k-res k-res-len crOff crf st
    call "cbor-find-key" using lk-pbuf lk-gp k-res k-res-len prOff prf st
    call "cap-dim-subset" using lk-cbuf crOff crf lk-cframe lk-cframelen
        lk-pbuf prOff prf lk-pframe lk-pframelen okR
    if okR = 0 then goback end-if
    call "cbor-find-key" using lk-cbuf lk-gc k-peers k-peers-len cpOff cpf st
    call "cbor-find-key" using lk-pbuf lk-gp k-peers k-peers-len ppOff ppf st
    *> §5.2: AN OMITTED `peers` SCOPE IS THE VALUE {include:[local_peer_id]}, NOT
    *> AN ABSENCE, and cap-dim-subset reads an absent parent dimension as covering
    *> nothing. So a child that spells the default out explicitly -- which is what
    *> every SDK and every wire probe does -- was refused 403
    *> scope_exceeds_authority AT MINT, and the whole `peers` dimension became
    *> unmeasurable on this peer. Measured 2026-09-15.
    *>
    *> Both asymmetric cases are materialized rather than only the one that was
    *> measured: the other direction (child omits, parent names) would otherwise
    *> be vacuously a subset, so a parent whose peers EXCLUDES this peer could be
    *> escaped by a child that simply leaves the dimension out.
    evaluate true
        when cpf = 0 and ppf = 0
            move 1 to okP
        when cpf = 1 and ppf = 0
            call "cap-peers-default-sub" using lk-cbuf cpOff okP
        when cpf = 0 and ppf = 1
            call "cap-scope-match" using lk-pbuf ppOff local locallen okP
        when other
            call "cap-dim-subset" using lk-cbuf cpOff cpf local locallen
                lk-pbuf ppOff ppf local locallen okP
    end-evaluate
    if okP = 0 then goback end-if
    move 1 to lk-res
    goback.
end program cap-grant-subset.

*> ---- cap-peers-default-sub : child `peers` subset of the §5.2 DEFAULT --
*> Answers 1 iff every entry of the child's `peers.include` is literally the local
*> peer id -- i.e. the child is a subset of the omitted-scope default
*> {include:[local_peer_id]}.
*>
*> `peers` is an ID-SCOPE dimension (§3.6 / F40), so the comparison is LITERAL: no
*> §5.4 canonicalization, and a bare "*" is WIDER than the default and is refused
*> here, which is the direction that matters.
identification division.
program-id. cap-peers-default-sub.
data division.
working-storage section.
01 cur   pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 cnt   pic 9(9) comp-5.
01 i     pic 9(9) comp-5.
01 plen  pic 9(9) comp-5.
01 st    pic s9(9) comp-5.
01 pat   pic x(900).
01 local pic x(128).
01 locallen pic 9(9) comp-5.
01 ioff  pic 9(9) comp-5.
01 iff   pic 9(1).
01 k-incl pic x(7) value "include".
01 k-incl-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-cbuf pic x(524288).
01 lk-csc  pic 9(9) comp-5.
01 lk-res  pic 9(1).
procedure division using lk-cbuf lk-csc lk-res.
    move 0 to lk-res
    call "ps-peerid" using local locallen
    call "cbor-find-key" using lk-cbuf lk-csc k-incl k-incl-len ioff iff st
    *> an absent include grants nothing, which is a subset of anything
    if iff = 0 then move 1 to lk-res  goback end-if
    move ioff to cur
    call "cbor-read-head" using lk-cbuf cur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to cnt
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-cbuf cur maj addl arg st
        move arg to plen
        move spaces to pat
        if plen > 0 and plen <= 900
            move lk-cbuf(cur:plen) to pat(1:plen)
        end-if
        add plen to cur
        if plen not = locallen then goback end-if
        if pat(1:plen) not = local(1:locallen) then goback end-if
    end-perform
    move 1 to lk-res
    goback.
end program cap-peers-default-sub.

*> ---- cap-link-granter : §5.5a per-link granter frame (hard-fail) ----
*> single-sig granter -> derive peer_id; multisig (map) -> local; an
*> unresolvable granter / no public_key -> ok=0 (deny the link, no fallback).
identification division.
program-id. cap-link-granter.
data division.
working-storage section.
01 voff pic 9(9) comp-5.
01 f    pic 9(1).
01 maj  pic 9(2) comp-5.
01 addl pic 9(2) comp-5.
01 arg  pic 9(18) comp-5.
01 st   pic s9(9) comp-5.
01 gh   pic x(33).
01 gl   pic 9(9) comp-5.
01 gp   pic x(524288).
01 gplen pic 9(9) comp-5.
01 found pic 9(1).
01 pub  pic x(32).
01 pl   pic 9(9) comp-5.
01 n32  pic 9(9) comp-5 value 32.
01 one  pic 9(9) comp-5 value 1.
01 k-grr pic x(7) value "granter".
01 k-grr-len pic 9(9) comp-5 value 7.
01 k-pk pic x(10) value "public_key".
01 k-pk-len pic 9(9) comp-5 value 10.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-cap    pic x(524288).
01 lk-out    pic x(128).
01 lk-outlen pic 9(9) comp-5.
01 lk-ok     pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-cap
                        lk-out lk-outlen lk-ok.
    move 0 to lk-ok
    call "ent-field" using lk-cap one k-grr k-grr-len voff f
    if f = 0
        *> no granter field: multisig root M3 -> local frame
        call "ps-peerid" using lk-out lk-outlen
        move 1 to lk-ok
        goback
    end-if
    move voff to st
    call "cbor-read-head" using lk-cap st maj addl arg gl
    if maj = 5
        *> multisig granter map -> local frame
        call "ps-peerid" using lk-out lk-outlen
        move 1 to lk-ok
        goback
    end-if
    call "read-bytes" using lk-cap voff gh gl
    if gl not = 33 then goback end-if
    call "cap-resolve" using lk-env lk-incoff lk-incfnd gh gp gplen found
    if found = 0 then goback end-if
    call "ent-field" using gp one k-pk k-pk-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using gp voff pub pl
    if pl not = 32 then goback end-if
    call "peer-id-of-pubkey" using pub n32 lk-out lk-outlen
    move 1 to lk-ok
    goback.
end program cap-link-granter.

*> ---- cap-is-attenuated : §5.6 every child grant ⊆ some parent grant -
identification division.
program-id. cap-is-attenuated.
data division.
working-storage section.
01 cgOff pic 9(9) comp-5.  01 cgf pic 9(1).
01 pgOff pic 9(9) comp-5.  01 pgf pic 9(1).
01 ccur  pic 9(9) comp-5.
01 pcur  pic 9(9) comp-5.
01 pstart pic 9(9) comp-5.
01 maj   pic 9(2) comp-5.
01 addl  pic 9(2) comp-5.
01 arg   pic 9(18) comp-5.
01 ccnt  pic 9(9) comp-5.
01 pcnt  pic 9(9) comp-5.
01 ci    pic 9(9) comp-5.
01 pj    pic 9(9) comp-5.
01 covered pic 9(1).
01 gsr   pic 9(1).
01 st    pic s9(9) comp-5.
01 voff  pic 9(9) comp-5.
01 f     pic 9(1).
01 cex   pic 9(18) comp-5.
01 pex   pic 9(18) comp-5.
01 cexf  pic 9(1).
01 pexf  pic 9(1).
01 one   pic 9(9) comp-5 value 1.
01 k-grants pic x(6) value "grants".
01 k-grants-len pic 9(9) comp-5 value 6.
01 k-ex  pic x(10) value "expires_at".
01 k-ex-len pic 9(9) comp-5 value 10.
linkage section.
01 lk-env    pic x(524288).
01 lk-cbuf   pic x(524288).
01 lk-cframe pic x(128).
01 lk-cframelen pic 9(9) comp-5.
01 lk-pbuf   pic x(524288).
01 lk-pframe pic x(128).
01 lk-pframelen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-env lk-cbuf lk-cframe lk-cframelen
                        lk-pbuf lk-pframe lk-pframelen lk-res.
    move 0 to lk-res
    call "ent-field" using lk-cbuf one k-grants k-grants-len cgOff cgf
    call "ent-field" using lk-pbuf one k-grants k-grants-len pgOff pgf
    if cgf = 0 then move 1 to lk-res  goback end-if
    move cgOff to ccur
    call "cbor-read-head" using lk-cbuf ccur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to ccnt
    *> every child grant covered by some parent grant
    perform varying ci from 1 by 1 until ci > ccnt
        move 0 to covered
        if pgf = 1
            move pgOff to pcur
            call "cbor-read-head" using lk-pbuf pcur maj addl arg st
            move arg to pcnt
            perform varying pj from 1 by 1 until pj > pcnt
                call "cap-grant-subset" using lk-cbuf ccur lk-cframe lk-cframelen
                    lk-pbuf pcur lk-pframe lk-pframelen gsr
                if gsr = 1 then move 1 to covered end-if
                call "cbor-skip" using lk-pbuf pcur st
            end-perform
        end-if
        if covered = 0 then goback end-if
        call "cbor-skip" using lk-cbuf ccur st
    end-perform
    *> expiry monotonicity: parent finite & child infinite -> deny
    call "ent-field" using lk-pbuf one k-ex k-ex-len voff pexf
    if pexf = 1 then call "read-uint" using lk-pbuf voff pex end-if
    call "ent-field" using lk-cbuf one k-ex k-ex-len voff cexf
    if cexf = 1 then call "read-uint" using lk-cbuf voff cex end-if
    if pexf = 1 and cexf = 0 then goback end-if
    if pexf = 1 and cexf = 1 and cex > pex then goback end-if
    move 1 to lk-res
    goback.
end program cap-is-attenuated.

*> ---- cap-peer-relative : §1.4's three spellings -> the ONE form a grant
*> can match ---------------------------------------------------------------
*>
*> `system/tree`, `/{peer}/system/tree` and `entity://{peer}/system/tree` are one
*> address, and §1.4's PD-2 block requires Dimension 1's handler pattern to be the
*> target uri's PEER-RELATIVE path -- a grant names HANDLERS, and a handler pattern
*> never carries a peer segment. Matching a grant against the absolute or schemed
*> form matches nothing, SILENTLY, which reads at the wire as an authority refusal
*> rather than as a lookup miss.
*>
*> THE FIRST SEGMENT IS DROPPED ONLY WHEN IT IS A PEER_ID. An unconditional strip
*> turns `system/protocol/connect` into `protocol/connect` -- the standing
*> smalltalk/forth defect, where every self-minted grant became unusable while the
*> handshake stayed green because its own grants are all `*`.
identification division.
program-id. cap-peer-relative.
data division.
working-storage section.
01 s      pic x(900).
01 slen   pic 9(9) comp-5.
01 i      pic 9(9) comp-5.
01 sl     pic 9(9) comp-5.
01 seg    pic x(128).
01 seglen pic 9(9) comp-5.
01 ispid  pic 9(1).
linkage section.
01 lk-uri    pic x(900).
01 lk-urilen pic 9(9) comp-5.
01 lk-out    pic x(900).
01 lk-outlen pic 9(9) comp-5.
procedure division using lk-uri lk-urilen lk-out lk-outlen.
    move spaces to lk-out
    move 0 to lk-outlen
    if lk-urilen <= 0 then goback end-if
    *> strip the `entity://` scheme, leaving the absolute form
    move spaces to s
    if lk-urilen > 9 and lk-uri(1:9) = "entity://"
        compute slen = lk-urilen - 9
        move lk-uri(10:slen) to s(1:slen)
    else
        move lk-urilen to slen
        move lk-uri(1:slen) to s(1:slen)
        *> an absolute path keeps its leading slash; drop it for the scan below
        if s(1:1) = "/"
            compute slen = slen - 1
            if slen > 0 then move lk-uri(2:slen) to s(1:slen) end-if
        end-if
    end-if
    if slen <= 0 then goback end-if
    *> first segment
    move 0 to sl
    perform varying i from 1 by 1 until i > slen
        if s(i:1) = "/" and sl = 0 then move i to sl end-if
    end-perform
    if sl = 0
        *> a single segment: nothing to strip -- and nothing that could be a
        *> peer-relative path's leading `system` either
        move slen to lk-outlen
        move s(1:slen) to lk-out(1:slen)
        goback
    end-if
    compute seglen = sl - 1
    move spaces to seg
    if seglen > 0 and seglen <= 128 then move s(1:seglen) to seg(1:seglen) end-if
    call "cap-ispid" using seg seglen ispid
    if ispid = 1
        compute lk-outlen = slen - sl
        if lk-outlen > 0 then move s(sl + 1:lk-outlen) to lk-out(1:lk-outlen) end-if
    else
        move slen to lk-outlen
        move s(1:slen) to lk-out(1:slen)
    end-if
    goback.
end program cap-peer-relative.

*> ---- cap-path-scope-match : matches_scope for a PATH-SCOPE dimension ---
*>
*> §3.6 fixes the mapping and a grant does not get to restate it: `handlers` and
*> `resources` are path-scope and are CANONICALIZED to absolute form (§1.4) before
*> comparison; `operations` and `peers` are id-scope and are compared literally.
*> "The two MUST NOT be interchanged -- a path dimension matched literally, or an
*> id dimension canonicalized, is a conformance defect."
*>
*> cap-scope-match beside this one is the ID-scope matcher. This peer's §5.2
*> dispatch check calls it for `handlers` too, under a comment asserting F40 made
*> handlers id-scope; it did not. That is a PRE-EXISTING defect on a different rule
*> (0.8.2.22) and is disclosed rather than smoothed into this tranche -- it is
*> invisible for the patterns this peer writes, because a peer-relative value
*> compared literally against a peer-relative pattern agrees with the canonicalized
*> comparison, and it diverges on §5.4's leading-`/` universal reading and `/*/`
*> interior peer-wildcard. The §1.4 gate below uses the CORRECT matcher for its own
*> Dimension 1.
identification division.
program-id. cap-path-scope-match.
data division.
working-storage section.
01 cv     pic x(900).
01 cvlen  pic 9(9) comp-5.
01 ioff   pic 9(9) comp-5.
01 ifnd   pic 9(1).
01 eoff   pic 9(9) comp-5.
01 efnd   pic 9(1).
01 cov    pic 9(1).
01 st     pic s9(9) comp-5.
01 k-incl pic x(7) value "include".
01 k-incl-len pic 9(9) comp-5 value 7.
01 k-excl pic x(7) value "exclude".
01 k-excl-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-buf    pic x(524288).
01 lk-scopeoff pic 9(9) comp-5.
01 lk-val    pic x(900).
01 lk-vallen pic 9(9) comp-5.
01 lk-frame  pic x(128).
01 lk-framelen pic 9(9) comp-5.
01 lk-res    pic 9(1).
procedure division using lk-buf lk-scopeoff lk-val lk-vallen
                        lk-frame lk-framelen lk-res.
    move 0 to lk-res
    call "cap-canon" using lk-val lk-vallen lk-frame lk-framelen cv cvlen
    call "cbor-find-key" using lk-buf lk-scopeoff k-excl k-excl-len eoff efnd st
    *> AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21), tested FIRST: the
    *> coverage test below is correct in isolation and is simply never reached on a
    *> sentinel, because cap-match answers 0.
    if efnd = 1
        call "cap-arr-unmatchable" using lk-buf eoff lk-frame lk-framelen cov
        if cov = 1 then goback end-if
    end-if
    call "cbor-find-key" using lk-buf lk-scopeoff k-incl k-incl-len ioff ifnd st
    if ifnd = 0 then goback end-if
    call "cap-arr-covers" using lk-buf ioff cv cvlen lk-frame lk-framelen cov
    if cov = 0 then goback end-if
    if efnd = 1
        call "cap-arr-covers" using lk-buf eoff cv cvlen lk-frame lk-framelen cov
        if cov = 1 then goback end-if
    end-if
    move 1 to lk-res
    goback.
end program cap-path-scope-match.

*> ---- cap-target-relax : §1.4's ONE EXEMPTION ---------------------------
*>
*> Verify a presented reentry credential against §1.4's clauses and, where they ALL
*> hold, answer the `peers` scope Dimension 4 relaxes TO. lk-relaxes = 0 means
*> "relaxes nothing", which is EVERY failure mode -- a credential failing a clause
*> is not an error, it simply supplies nothing, and the handler grant then gates
*> unrelaxed.
*>
*> Every clause is required:
*>   * the chain ROOT `granter` resolves to the TARGET peer, and is NOT a
*>     multi-signature root (cap-verify-chain refuses the quorum arm in a foreign
*>     frame, which is where that rule lands);
*>   * the LEAF `grantee` is the LOCAL peer -- a credential minted at the target
*>     FOR SOMEBODY ELSE relaxes nothing here;
*>   * valid (per-link signatures, temporal, attenuation) and not revoked.
identification division.
program-id. cap-target-relax.
data division.
working-storage section.
01 local  pic x(128).
01 locallen pic 9(9) comp-5.
01 cverdict pic 9(1).
01 unres  pic 9(1).
01 revoked pic 9(1).
01 voff   pic 9(9) comp-5.
01 f      pic 9(1).
01 gee    pic x(33).
01 gel    pic 9(9) comp-5.
01 gbuf   pic x(524288).
01 gblen  pic 9(9) comp-5.
01 found  pic 9(1).
01 pub    pic x(32).
01 pbl    pic 9(9) comp-5.
01 gpid   pic x(128).
01 gpidlen pic 9(9) comp-5.
01 gsoff  pic 9(9) comp-5.
01 gsf    pic 9(1).
01 gcur   pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 gcnt   pic 9(9) comp-5.
01 poff   pic 9(9) comp-5.
01 pfnd     pic 9(1).
01 pend   pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 n32    pic 9(9) comp-5 value 32.
01 n1     pic 9(18) comp-5 value 1.
01 k-gre  pic x(7) value "grantee".
01 k-gre-len pic 9(9) comp-5 value 7.
01 k-pk   pic x(10) value "public_key".
01 k-pk-len pic 9(9) comp-5 value 10.
01 k-grants pic x(6) value "grants".
01 k-grants-len pic 9(9) comp-5 value 6.
01 k-peers pic x(5) value "peers".
01 k-peers-len pic 9(9) comp-5 value 5.
01 k-incl pic x(7) value "include".
01 k-incl-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-target pic x(128).
01 lk-targetlen pic 9(9) comp-5.
01 lk-cred   pic x(524288).
01 lk-credlen pic 9(9) comp-5.
01 lk-peers  pic x(4096).
01 lk-peerslen pic 9(9) comp-5.
01 lk-relaxes pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-target lk-targetlen
                        lk-cred lk-credlen lk-peers lk-peerslen lk-relaxes.
    move 0 to lk-relaxes
    move 0 to lk-peerslen
    call "ps-peerid" using local locallen
    *> NOTHING TO RELAX when the target IS this peer -- §5.2's default already
    *> covers it, and treating a self-targeted credential as a relaxation would make
    *> the exemption reachable with no foreign mint at all.
    if lk-targetlen = locallen and lk-target(1:lk-targetlen) = local(1:locallen)
        goback
    end-if
    *> the chain, rooted at the TARGET rather than at this peer
    call "cap-verify-chain" using lk-env lk-incoff lk-incfnd lk-cred lk-credlen
        lk-target lk-targetlen cverdict unres
    if cverdict = 0 or unres = 1 then goback end-if
    call "cap-is-revoked" using lk-env lk-incoff lk-incfnd lk-cred lk-credlen revoked
    if revoked = 1 then goback end-if
    *> the LEAF grantee must be this peer
    call "ent-field" using lk-cred one k-gre k-gre-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using lk-cred voff gee gel
    if gel not = 33 then goback end-if
    call "cap-resolve" using lk-env lk-incoff lk-incfnd gee gbuf gblen found
    if found = 0 then goback end-if
    call "ent-field" using gbuf one k-pk k-pk-len voff f
    if f = 0 then goback end-if
    call "read-bytes" using gbuf voff pub pbl
    if pbl not = 32 then goback end-if
    call "peer-id-of-pubkey" using pub n32 gpid gpidlen
    if not (gpidlen = locallen and gpid(1:gpidlen) = local(1:locallen))
        goback
    end-if
    *> The credential's OWN `peers` scope is what Dimension 4 relaxes TO. ABSENT
    *> means the granter -- the target peer -- which is the ordinary reentry shape:
    *> "you may dispatch back to me".
    call "ent-field" using lk-cred one k-grants k-grants-len gsoff gsf
    if gsf = 0 then goback end-if
    move gsoff to gcur
    call "cbor-read-head" using lk-cred gcur maj addl arg st
    if maj not = 4 or arg = 0 then goback end-if
    move arg to gcnt
    call "cbor-find-key" using lk-cred gcur k-peers k-peers-len poff pfnd st
    move 1 to lk-relaxes
    if pfnd = 1
        move poff to pend
        call "cbor-skip" using lk-cred pend st
        compute lk-peerslen = pend - poff
        if lk-peerslen > 0 and lk-peerslen <= 4096
            move lk-cred(poff:lk-peerslen) to lk-peers(1:lk-peerslen)
            goback
        end-if
        *> over capacity: fail CLOSED rather than relax to something unread
        move 0 to lk-peerslen
        move 0 to lk-relaxes
        goback
    end-if
    move 0 to lk-peerslen
    call "b-map"  using lk-peers lk-peerslen n1
    call "b-text" using lk-peers lk-peerslen k-incl k-incl-len
    call "b-arr"  using lk-peers lk-peerslen n1
    call "b-text" using lk-peers lk-peerslen lk-target lk-targetlen
    goback.
end program cap-target-relax.

*> ---- cap-outbound-perm : §1.4's PD-2 gate ------------------------------
*>
*> check_permission run BEFORE a locally-originated sub-dispatch LEAVES the peer,
*> with all four dimensions applied.
*>
*> ONE GATE AND ONE EXEMPTION, in §1.4's own words:
*>   * the EXECUTING HANDLER'S GRANT decides all four dimensions (§6.8), evaluated
*>     in the LOCAL frame, with Dimension 1's pattern the target uri's PEER-RELATIVE
*>     path;
*>   * a valid capability MINTED BY THE TARGET PEER naming this peer as `grantee`
*>     relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4, to the peers that
*>     capability covers.
*>
*> "The target answers WHERE; the handler's grant answers WHAT." A CREDENTIAL IS
*> NOT A GRANT: with no handler grant there is nothing to supply Dimensions 1-3, so
*> the sub-dispatch is refused however good the credential is. That is the COMPOSE,
*> and the BYPASS it is distinguished from is a peer that treats the credential as a
*> standalone authorizer and steers past its own grant -- §6.8's confused-deputy
*> substitution, which §6.8 itself calls WIRE-INVISIBLE: "both readings produce a
*> well-formed response and differ only in which authority was consulted." Both
*> obvious vectors agree under either reading (sources agree -> allow, no source ->
*> refuse), so the ONLY input that separates them is a VALID credential presented to
*> a handler whose own grant does NOT cover the request, which MUST refuse.
*>
*> lk-credlen = 0 is the AMBIENT arm: Dimension 4 is decided by the handler's grant
*> alone. It is its OWN BIT rather than an empty-map test, because an absent
*> credential and a credential that happens to carry nothing are different inputs.
*>
*> lk-target is supplied by the CALLER rather than derived here: on the §6.11 seam
*> the uri may be peer-relative and the destination is the connection's remote, so
*> cap-extract-peer would answer the LOCAL peer and Dimension 4 would pass
*> VACUOUSLY on §5.2's default {include:[local]} -- the exemption would never be
*> exercised and a bypass would read as a compose.
identification division.
program-id. cap-outbound-perm.
data division.
working-storage section.
01 local  pic x(128).
01 locallen pic 9(9) comp-5.
01 relaxes pic 9(1).
01 relaxsc pic x(4096).
01 relaxlen pic 9(9) comp-5.
01 gsoff  pic 9(9) comp-5.
01 gsf    pic 9(1).
01 gcur   pic 9(9) comp-5.
01 gmap   pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 gcnt   pic 9(9) comp-5.
01 gi     pic 9(9) comp-5.
01 soff   pic 9(9) comp-5.
01 sf     pic 9(1).
01 r      pic 9(1).
01 st     pic s9(9) comp-5.
01 ok     pic 9(1).
01 one    pic 9(9) comp-5 value 1.
01 k-grants pic x(6) value "grants".
01 k-grants-len pic 9(9) comp-5 value 6.
01 k-hdl  pic x(8) value "handlers".
01 k-hdl-len pic 9(9) comp-5 value 8.
01 k-ops  pic x(10) value "operations".
01 k-ops-len pic 9(9) comp-5 value 10.
01 k-peers pic x(5) value "peers".
01 k-peers-len pic 9(9) comp-5 value 5.
linkage section.
01 lk-env    pic x(524288).
01 lk-incoff pic 9(9) comp-5.
01 lk-incfnd pic 9(1).
01 lk-target pic x(128).
01 lk-targetlen pic 9(9) comp-5.
01 lk-hpat   pic x(900).
01 lk-hlen   pic 9(9) comp-5.
01 lk-op     pic x(64).
01 lk-oplen  pic 9(9) comp-5.
01 lk-grant  pic x(524288).
01 lk-resbuf pic x(524288).
01 lk-cred   pic x(524288).
01 lk-credlen pic 9(9) comp-5.
01 lk-verdict pic 9(1).
procedure division using lk-env lk-incoff lk-incfnd lk-target lk-targetlen
                        lk-hpat lk-hlen lk-op lk-oplen lk-grant lk-resbuf
                        lk-cred lk-credlen lk-verdict.
    move 0 to lk-verdict
    call "ps-peerid" using local locallen
    *> COMPUTED FIRST AND CONSULTED LAST, so no credential can stand in for
    *> Dimensions 1-3.
    move 0 to relaxes
    move 0 to relaxlen
    if lk-credlen > 0
        call "cap-target-relax" using lk-env lk-incoff lk-incfnd
            lk-target lk-targetlen lk-cred lk-credlen
            relaxsc relaxlen relaxes
    end-if
    call "ent-field" using lk-grant one k-grants k-grants-len gsoff gsf
    if gsf = 0 then goback end-if
    move gsoff to gcur
    call "cbor-read-head" using lk-grant gcur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to gcnt
    perform varying gi from 1 by 1 until gi > gcnt
        move gcur to gmap
        perform grant-ok
        if ok = 1 then move 1 to lk-verdict  goback end-if
        call "cbor-skip" using lk-grant gcur st
    end-perform
    goback.

grant-ok.
    move 0 to ok
    *> Dimension 1 -- handlers, PATH-scope (§3.6 fixes the mapping).
    call "cbor-find-key" using lk-grant gmap k-hdl k-hdl-len soff sf st
    if sf = 0 then exit paragraph end-if
    call "cap-path-scope-match" using lk-grant soff lk-hpat lk-hlen
        local locallen r
    if r = 0 then exit paragraph end-if
    *> Dimension 2 -- operations, ID-scope (literal, no frame).
    call "cbor-find-key" using lk-grant gmap k-ops k-ops-len soff sf st
    if sf = 0 then exit paragraph end-if
    call "cap-scope-match" using lk-grant soff lk-op lk-oplen r
    if r = 0 then exit paragraph end-if
    *> Dimension 3 -- resources. The grant is self-issued, so the §5.5a granter
    *> frame and the local frame are the same peer on both sides.
    call "cap-resource-match" using lk-resbuf one lk-grant gmap
        local locallen local locallen r
    if r = 0 then exit paragraph end-if
    *> Dimension 4 -- peers. §5.2's default for an ABSENT peers scope is
    *> {include:[local]}, so a FOREIGN target fails unless this grant names it or a
    *> target-minted credential relaxes it.
    call "cbor-find-key" using lk-grant gmap k-peers k-peers-len soff sf st
    if sf = 1
        call "cap-scope-match" using lk-grant soff lk-target lk-targetlen r
        if r = 1 then move 1 to ok  exit paragraph end-if
    else
        if lk-targetlen = locallen
           and lk-target(1:lk-targetlen) = local(1:locallen)
            move 1 to ok
            exit paragraph
        end-if
    end-if
    if relaxes = 1
        call "cap-scope-match" using relaxsc one lk-target lk-targetlen r
        if r = 1 then move 1 to ok  exit paragraph end-if
    end-if.
end program cap-outbound-perm.
