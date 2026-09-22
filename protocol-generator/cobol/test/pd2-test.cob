>>SOURCE FORMAT FREE
*> entity-core-protocol-cobol — §1.4 PD-2 outbound sub-dispatch gate (0.8.2.31).
*>
*> NOTHING IN THE PINNED 778-CHECK SET MEASURES THIS, and nothing in the candidate
*> 790 measures §1.4's MULTI-SIGNATURE clause on any peer: the oracle's K-of-2 root
*> is co-signed by the target and a third party and NOT by the local peer, so §5.5's
*> M6 refuses it FIRST for a reason that has nothing to do with §1.4 — planting the
*> foreign-frame guard out leaves that row GREEN. This is the gate for both, and the
*> §6.8 confused-deputy discriminator is measurable at all only because the scaffold
*> grant is NARROW.
*>
*> ONE PROCEDURE RATHER THAN A FRAMEWORK, matching the other unit drivers: a
*> PASS/FAIL count, a FLOOR on the number examined, and a non-zero exit when any
*> check fails. THE COUNT IS PRINTED AND THE FLOOR ASSERTED — a gate that examined
*> zero things prints the same word as one that examined sixteen.
identification division.
program-id. pd2-test.
data division.
working-storage section.
01 passed  pic 9(4) comp-5 value 0.
01 failed  pic 9(4) comp-5 value 0.
01 checked pic 9(4) comp-5 value 0.
01 floor   pic 9(4) comp-5 value 16.
01 nm      pic x(72).
01 cond    pic 9(1).
*> --- identities ---
01 seed-self pic x(32).
01 seed-tgt  pic x(32).
01 seed-x    pic x(32).
01 open0   pic 9(1) value 0.
01 conf1   pic 9(1) value 1.
01 local   pic x(128).  01 locallen pic 9(9) comp-5.
01 idhash  pic x(33).
01 pent    pic x(524288).  01 pentlen pic 9(9) comp-5.
01 tpub    pic x(32).  01 tpid pic x(128).  01 tpidlen pic 9(9) comp-5.
01 tpent   pic x(524288).  01 tpentlen pic 9(9) comp-5.  01 tidhash pic x(33).
01 xpub    pic x(32).  01 xpid pic x(128).  01 xpidlen pic 9(9) comp-5.
01 xpent   pic x(524288).  01 xpentlen pic 9(9) comp-5.  01 xidhash pic x(33).
*> --- scope / grant construction ---
01 gr      pic x(8192).  01 grlen pic 9(9) comp-5.
01 tokd    pic x(8192).  01 tokdlen pic 9(9) comp-5.
01 cred    pic x(524288).  01 credlen pic 9(9) comp-5.  01 credhash pic x(33).
01 cred2   pic x(524288).  01 cred2len pic 9(9) comp-5.  01 cred2hash pic x(33).
01 cred3   pic x(524288).  01 cred3len pic 9(9) comp-5.  01 cred3hash pic x(33).
01 qcred   pic x(524288).  01 qcredlen pic 9(9) comp-5.  01 qcredhash pic x(33).
01 nocred  pic x(524288).  01 nocredlen pic 9(9) comp-5 value 0.
01 sig1    pic x(524288).  01 sig1len pic 9(9) comp-5.  01 sig1hash pic x(33).
01 sig2    pic x(524288).  01 sig2len pic 9(9) comp-5.  01 sig2hash pic x(33).
01 sig3    pic x(524288).  01 sig3len pic 9(9) comp-5.  01 sig3hash pic x(33).
01 qsigs   pic x(524288).  01 qsigslen pic 9(9) comp-5.  01 qsigshash pic x(33).
01 qsigt   pic x(524288).  01 qsigtlen pic 9(9) comp-5.  01 qsigthash pic x(33).
*> --- the handler's own grant + an EMPTY one ---
01 grant   pic x(524288).  01 grantlen pic 9(9) comp-5.  01 grantfd pic 9(1).
01 egrant  pic x(524288).  01 egrantlen pic 9(9) comp-5.  01 egranthash pic x(33).
*> --- bundles ---
01 bun     pic x(524288).  01 bunlen pic 9(9) comp-5.
01 bunq    pic x(524288).  01 bunqlen pic 9(9) comp-5.
01 bone    pic 9(9) comp-5 value 1.
01 bfnd    pic 9(1) value 1.
*> --- resources ---
01 resecho pic x(524288).  01 resecholen pic 9(9) comp-5.
01 restree pic x(524288).  01 restreelen pic 9(9) comp-5.
*> --- verdicts ---
01 perm    pic 9(1).
01 cverdict pic 9(1).  01 unres pic 9(1).
01 rel     pic x(900).  01 rellen pic 9(9) comp-5.
01 gpath   pic x(700).  01 gpathlen pic 9(9) comp-5.
01 grel    pic x(700).  01 grellen pic 9(9) comp-5.
01 uri     pic x(900).  01 urilen pic 9(9) comp-5.
01 abspath pic x(900).  01 abspathlen pic 9(9) comp-5.
*> --- literals ---
01 t-tok   pic x(23) value "system/capability/token".
01 t-tok-len pic 9(9) comp-5 value 23.
01 k-grr   pic x(7) value "granter".   01 k-grr-len pic 9(9) comp-5 value 7.
01 k-gre   pic x(7) value "grantee".   01 k-gre-len pic 9(9) comp-5 value 7.
01 k-ca    pic x(10) value "created_at". 01 k-ca-len pic 9(9) comp-5 value 10.
01 k-grants pic x(6) value "grants".   01 k-grants-len pic 9(9) comp-5 value 6.
01 k-hdl   pic x(8) value "handlers".  01 k-hdl-len pic 9(9) comp-5 value 8.
01 k-ops   pic x(10) value "operations". 01 k-ops-len pic 9(9) comp-5 value 10.
01 k-rsrc  pic x(9) value "resources". 01 k-rsrc-len pic 9(9) comp-5 value 9.
01 k-peers pic x(5) value "peers".     01 k-peers-len pic 9(9) comp-5 value 5.
01 k-incl  pic x(7) value "include".   01 k-incl-len pic 9(9) comp-5 value 7.
01 k-tgts  pic x(7) value "targets".   01 k-tgts-len pic 9(9) comp-5 value 7.
01 k-sgrs  pic x(7) value "signers".   01 k-sgrs-len pic 9(9) comp-5 value 7.
01 k-thr   pic x(9) value "threshold". 01 k-thr-len pic 9(9) comp-5 value 9.
01 star    pic x(1) value "*".         01 star-len pic 9(9) comp-5 value 1.
01 p-echo  pic x(20) value "system/validate/echo".
01 p-echo-len pic 9(9) comp-5 value 20.
01 p-tree  pic x(11) value "system/tree".
01 p-tree-len pic 9(9) comp-5 value 11.
01 v-echo  pic x(4) value "echo".      01 v-echo-len pic 9(9) comp-5 value 4.
01 v-put   pic x(3) value "put".       01 v-put-len pic 9(9) comp-5 value 3.
01 r-echo  pic x(35) value "system/handler/system/validate/echo".
01 r-echo-len pic 9(9) comp-5 value 35.
01 r-tree  pic x(26) value "system/handler/system/tree".
01 r-tree-len pic 9(9) comp-5 value 26.
01 s-grants pic x(25) value "system/capability/grants/".
01 p-dob   pic x(33) value "system/validate/dispatch-outbound".
01 p-dob-len pic 9(9) comp-5 value 33.
01 s-conn  pic x(23) value "system/protocol/connect".
01 s-conn-len pic 9(9) comp-5 value 23.
01 s-sch   pic x(9) value "entity://".
01 one     pic 9(9) comp-5 value 1.
01 n33     pic 9(9) comp-5 value 33.
01 n1      pic 9(18) comp-5 value 1.
01 n2      pic 9(18) comp-5 value 2.
01 n3      pic 9(18) comp-5 value 3.
01 n4      pic 9(18) comp-5 value 4.
01 n0      pic 9(18) comp-5 value 0.
01 n9      pic 9(18) comp-5 value 9.
01 ca18    pic 9(18) comp-5 value 1700000000000.
01 st      pic s9(9) comp-5.
*> scratch for the scope/grant builders
01 w-pat   pic x(900).  01 w-patlen pic 9(9) comp-5.
01 w-op    pic x(64).   01 w-oplen pic 9(9) comp-5.
01 w-res   pic x(900).  01 w-reslen pic 9(9) comp-5.
01 w-peer  pic x(128).  01 w-peerlen pic 9(9) comp-5.
01 w-wpeer pic 9(1).
01 w-grr   pic x(33).   01 w-gre pic x(33).
01 w-out   pic x(524288).  01 w-outlen pic 9(9) comp-5.  01 w-hash pic x(33).
procedure division.
    move all x"5A" to seed-self
    move all x"2B" to seed-tgt
    move all x"7C" to seed-x
    *> A peer with the §7a validate handlers bootstrapped (conf=1) and NOT the
    *> degenerate open-grants seed: the whole point is a grant narrower than the
    *> request, and `default -> *` leaves nothing to refuse.
    call "ps-init" using seed-self open0 conf1
    call "bootstrap"
    call "ps-peerid" using local locallen
    call "ps-idhash" using idhash
    call "ps-pent" using pent pentlen
    call "ident-of-seed" using seed-tgt tpub tpid tpidlen tpent tpentlen tidhash
    call "ident-of-seed" using seed-x xpub xpid xpidlen xpent xpentlen xidhash

    display "-- section 1.4 PD-2: the outbound sub-dispatch gate (0.8.2.31) --"

    *> ---- §1.4's three spellings onto the ONE form a grant can match ----
    call "cap-peer-relative" using p-echo p-echo-len rel rellen
    move "peer_relative: a peer-relative path is unchanged" to nm
    move 0 to cond
    if rellen = p-echo-len and rel(1:rellen) = p-echo(1:p-echo-len)
        move 1 to cond
    end-if
    perform chk
    *> absolute
    move "/" to uri(1:1)
    move local(1:locallen) to uri(2:locallen)
    move "/" to uri(locallen + 2:1)
    move p-echo(1:p-echo-len) to uri(locallen + 3:p-echo-len)
    compute urilen = locallen + 2 + p-echo-len
    call "cap-peer-relative" using uri urilen rel rellen
    move "...the absolute form loses its peer segment" to nm
    move 0 to cond
    if rellen = p-echo-len and rel(1:rellen) = p-echo(1:p-echo-len)
        move 1 to cond
    end-if
    perform chk
    *> schemed
    move s-sch to uri(1:9)
    move local(1:locallen) to uri(10:locallen)
    move "/" to uri(locallen + 10:1)
    move p-echo(1:p-echo-len) to uri(locallen + 11:p-echo-len)
    compute urilen = locallen + 10 + p-echo-len
    call "cap-peer-relative" using uri urilen rel rellen
    move "...and so does the schemed form" to nm
    move 0 to cond
    if rellen = p-echo-len and rel(1:rellen) = p-echo(1:p-echo-len)
        move 1 to cond
    end-if
    perform chk
    *> ⛔ the standing smalltalk/forth defect: an UNCONDITIONAL strip turns
    *> system/protocol/connect into protocol/connect, and every self-minted grant
    *> becomes unusable while the handshake stays green.
    move "/" to uri(1:1)
    move s-conn(1:s-conn-len) to uri(2:s-conn-len)
    compute urilen = 1 + s-conn-len
    call "cap-peer-relative" using uri urilen rel rellen
    move "...and a NON-peer-id first segment is NOT stripped" to nm
    move 0 to cond
    if rellen = s-conn-len and rel(1:rellen) = s-conn(1:s-conn-len)
        move 1 to cond
    end-if
    perform chk

    *> ---- the handler's OWN grant, as boot-handler minted it ----
    move s-grants to grel(1:25)
    move p-dob(1:p-dob-len) to grel(26:p-dob-len)
    compute grellen = 25 + p-dob-len
    call "mkpath" using grel grellen gpath gpathlen
    call "store-get-at" using gpath gpathlen grant grantlen grantfd
    move "section 6.8: the bootstrap handler has an own grant at all" to nm
    move grantfd to cond
    perform chk

    *> an EMPTY grants array -- a handler that never dispatches onward
    perform build-empty-grant

    *> ---- resources ----
    move 0 to resecholen
    call "b-map"  using resecho resecholen n1
    call "b-text" using resecho resecholen k-tgts k-tgts-len
    call "b-arr"  using resecho resecholen n1
    call "b-text" using resecho resecholen r-echo r-echo-len
    move 0 to restreelen
    call "b-map"  using restree restreelen n1
    call "b-text" using restree restreelen k-tgts k-tgts-len
    call "b-arr"  using restree restreelen n1
    call "b-text" using restree restreelen r-tree r-tree-len

    *> ---- credentials ----
    *> (a) minted BY THE TARGET for US, `peers` naming the target: the ordinary
    *> reentry shape.
    move tidhash to w-grr  move idhash to w-gre
    move tpid to w-peer  move tpidlen to w-peerlen  move 1 to w-wpeer
    perform build-cred
    move w-out(1:w-outlen) to cred(1:w-outlen)
    move w-outlen to credlen  move w-hash to credhash
    call "sign-entity" using seed-tgt tidhash credhash sig1 sig1len sig1hash
    *> (b) minted by a THIRD PARTY: relaxes nothing.
    move xidhash to w-grr  move idhash to w-gre
    perform build-cred
    move w-out(1:w-outlen) to cred2(1:w-outlen)
    move w-outlen to cred2len  move w-hash to cred2hash
    call "sign-entity" using seed-x xidhash cred2hash sig2 sig2len sig2hash
    *> (c) minted by the target FOR SOMEBODY ELSE: relaxes nothing.
    move tidhash to w-grr  move xidhash to w-gre
    perform build-cred
    move w-out(1:w-outlen) to cred3(1:w-outlen)
    move w-outlen to cred3len  move w-hash to cred3hash
    call "sign-entity" using seed-tgt tidhash cred3hash sig3 sig3len sig3hash
    *> (d) a §3.6 K-of-2 QUORUM root this peer IS a member of.
    perform build-quorum-cred
    call "sign-entity" using seed-self idhash qcredhash qsigs qsigslen qsigshash
    call "sign-entity" using seed-tgt tidhash qcredhash qsigt qsigtlen qsigthash

    *> §7a.2a's merged bundle. Keyed by each entity's own content_hash, which is
    *> what inc-find-hash RECOMPUTES and requires the key to equal.
    perform build-bundle
    perform build-quorum-bundle

    *> ---- the AMBIENT arm ----
    call "cap-outbound-perm" using bun bone bfnd local locallen
        p-echo p-echo-len v-echo v-echo-len grant resecho
        nocred nocredlen perm
    move "ambient: inside the handler grant, to THIS peer, is allowed" to nm
    move perm to cond
    perform chk
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-echo p-echo-len v-echo v-echo-len grant resecho
        nocred nocredlen perm
    move "ambient: the SAME request to a FOREIGN peer is refused" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk

    *> ---- the PRESENTED arm ----
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-echo p-echo-len v-echo v-echo-len grant resecho
        cred credlen perm
    move "presented: a target-minted credential relaxes Dimension 4" to nm
    move perm to cond
    perform chk
    *> ⛔ THE DISCRIMINATOR. A VALID target-minted credential presented to a handler
    *> whose OWN grant does not cover the request. Both obvious vectors agree under
    *> either reading; this is the only input that separates the compose from
    *> §6.8's confused-deputy substitution.
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-echo p-echo-len v-put v-put-len grant resecho
        cred credlen perm
    move "presented: an out-of-grant OPERATION is refused (6.8 bypass)" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-tree p-tree-len v-echo v-echo-len grant resecho
        cred credlen perm
    move "presented: an out-of-grant HANDLER is refused (6.8 bypass)" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-echo p-echo-len v-echo v-echo-len grant restree
        cred credlen perm
    move "presented: an out-of-grant RESOURCE is refused (6.8 bypass)" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-echo p-echo-len v-echo v-echo-len grant resecho
        cred2 cred2len perm
    move "presented: a credential rooted at a THIRD party relaxes nothing" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-echo p-echo-len v-echo v-echo-len grant resecho
        cred3 cred3len perm
    move "presented: a credential granted to SOMEBODY ELSE relaxes nothing" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk
    call "cap-outbound-perm" using bun bone bfnd tpid tpidlen
        p-echo p-echo-len v-echo v-echo-len egrant resecho
        cred credlen perm
    move "presented: with no handler grant a credential authorizes nothing" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk

    *> ---- §1.4's multi-signature clause, which NO check set measures ----
    *> THE ANTECEDENT (F70) FIRST. Without it the row below is a deny that
    *> establishes nothing: a malformed quorum refuses for reasons unrelated to
    *> §1.4, which is exactly how the wire's own multisig row passes vacuously.
    call "cap-verify-chain" using bunq bone bfnd qcred qcredlen
        local locallen cverdict unres
    move "antecedent: the SAME quorum root verifies in the LOCAL frame" to nm
    move 0 to cond
    if cverdict = 1 and unres = 0 then move 1 to cond end-if
    perform chk
    call "cap-outbound-perm" using bunq bone bfnd tpid tpidlen
        p-echo p-echo-len v-echo v-echo-len grant resecho
        qcred qcredlen perm
    move "...and NEVER relaxes Dimension 4 in a foreign frame" to nm
    move 0 to cond
    if perm = 0 then move 1 to cond end-if
    perform chk

    display " "
    display "== pd2-test: " passed " passed, " failed " failed, of "
        checked " examined =="
    *> A GATE THAT EXAMINED ZERO THINGS PRINTS THE SAME WORD AS ONE THAT EXAMINED
    *> FIFTEEN. The floor is asserted so a dropped block is a RED, not a silent
    *> green.
    if checked < floor
        display "  FAIL: examined " checked " checks, floor is " floor
        add 1 to failed
    end-if
    if failed > 0
        display "=== pd2-test: FAILED ==="
        move 1 to return-code
    else
        display "=== pd2-test: PASS ==="
        move 0 to return-code
    end-if
    goback.

chk.
    add 1 to checked
    if cond = 1
        add 1 to passed
    else
        add 1 to failed
        display "  FAIL: " nm
    end-if.

*> A four-dimension grant scope, with `peers` only when w-wpeer = 1.
build-scope.
    move 0 to grlen
    if w-wpeer = 1
        call "b-map" using gr grlen n4
    else
        call "b-map" using gr grlen n3
    end-if
    call "b-text" using gr grlen k-hdl k-hdl-len
    call "b-map"  using gr grlen n1
    call "b-text" using gr grlen k-incl k-incl-len
    call "b-arr"  using gr grlen n1
    call "b-text" using gr grlen w-pat w-patlen
    call "b-text" using gr grlen k-ops k-ops-len
    call "b-map"  using gr grlen n1
    call "b-text" using gr grlen k-incl k-incl-len
    call "b-arr"  using gr grlen n1
    call "b-text" using gr grlen w-op w-oplen
    call "b-text" using gr grlen k-rsrc k-rsrc-len
    call "b-map"  using gr grlen n1
    call "b-text" using gr grlen k-incl k-incl-len
    call "b-arr"  using gr grlen n1
    call "b-text" using gr grlen w-res w-reslen
    if w-wpeer = 1
        call "b-text" using gr grlen k-peers k-peers-len
        call "b-map"  using gr grlen n1
        call "b-text" using gr grlen k-incl k-incl-len
        call "b-arr"  using gr grlen n1
        call "b-text" using gr grlen w-peer w-peerlen
    end-if.

*> A ROOT credential: granter = w-grr, grantee = w-gre, one wide grant whose
*> `peers` names w-peer. Root-only, so its granter IS its root.
build-cred.
    move star to w-pat  move star-len to w-patlen
    move star to w-op   move star-len to w-oplen
    move star to w-res  move star-len to w-reslen
    perform build-scope
    move 0 to tokdlen
    call "b-map"  using tokd tokdlen n4
    call "b-text" using tokd tokdlen k-grr k-grr-len
    call "b-bytes" using tokd tokdlen w-grr one n33
    call "b-text" using tokd tokdlen k-gre k-gre-len
    call "b-bytes" using tokd tokdlen w-gre one n33
    call "b-text" using tokd tokdlen k-ca k-ca-len
    call "b-uint" using tokd tokdlen ca18
    call "b-text" using tokd tokdlen k-grants k-grants-len
    call "b-arr"  using tokd tokdlen n1
    call "b-raw"  using tokd tokdlen gr one grlen
    call "b-entity" using t-tok t-tok-len tokd tokdlen
        w-out w-outlen w-hash st.

*> A §3.6 K-of-2 quorum root: `granter` is a {signers, threshold} MAP rather than
*> a single granter hash, and the LOCAL peer is one of the signers (§5.5 M6).
build-quorum-cred.
    move star to w-pat  move star-len to w-patlen
    move star to w-op   move star-len to w-oplen
    move star to w-res  move star-len to w-reslen
    move tpid to w-peer  move tpidlen to w-peerlen  move 1 to w-wpeer
    perform build-scope
    move 0 to tokdlen
    call "b-map"  using tokd tokdlen n4
    call "b-text" using tokd tokdlen k-grr k-grr-len
    call "b-map"  using tokd tokdlen n2
    call "b-text" using tokd tokdlen k-sgrs k-sgrs-len
    call "b-arr"  using tokd tokdlen n2
    call "b-bytes" using tokd tokdlen idhash one n33
    call "b-bytes" using tokd tokdlen tidhash one n33
    call "b-text" using tokd tokdlen k-thr k-thr-len
    call "b-uint" using tokd tokdlen n2
    call "b-text" using tokd tokdlen k-gre k-gre-len
    call "b-bytes" using tokd tokdlen idhash one n33
    call "b-text" using tokd tokdlen k-ca k-ca-len
    call "b-uint" using tokd tokdlen ca18
    call "b-text" using tokd tokdlen k-grants k-grants-len
    call "b-arr"  using tokd tokdlen n1
    call "b-raw"  using tokd tokdlen gr one grlen
    call "b-entity" using t-tok t-tok-len tokd tokdlen
        qcred qcredlen qcredhash st.

*> A token whose grants array is EMPTY: nothing to supply Dimensions 1-3, so no
*> credential can authorize through it.
build-empty-grant.
    move 0 to tokdlen
    call "b-map"  using tokd tokdlen n4
    call "b-text" using tokd tokdlen k-grr k-grr-len
    call "b-bytes" using tokd tokdlen idhash one n33
    call "b-text" using tokd tokdlen k-gre k-gre-len
    call "b-bytes" using tokd tokdlen idhash one n33
    call "b-text" using tokd tokdlen k-ca k-ca-len
    call "b-uint" using tokd tokdlen ca18
    call "b-text" using tokd tokdlen k-grants k-grants-len
    call "b-arr"  using tokd tokdlen n0
    call "b-entity" using t-tok t-tok-len tokd tokdlen
        egrant egrantlen egranthash st.

*> §7a.2a's merged bundle. ONE map whose header count matches what follows it,
*> keyed by each entity's own content_hash -- which is what inc-find-hash
*> RECOMPUTES and requires the key to equal (§3.1), so a forged key is a MISS
*> rather than a resolution. Every credential and every identity the negative
*> cases need rides the SAME bundle on purpose: a link the verifier cannot reach
*> fails closed, and the point of those cases is that the chain IS resolvable and
*> the CLAUSE refuses.
build-bundle.
    move 0 to bunlen
    call "b-map" using bun bunlen n9
    call "b-bytes" using bun bunlen credhash one n33
    call "b-raw"   using bun bunlen cred one credlen
    call "b-bytes" using bun bunlen sig1hash one n33
    call "b-raw"   using bun bunlen sig1 one sig1len
    call "b-bytes" using bun bunlen cred2hash one n33
    call "b-raw"   using bun bunlen cred2 one cred2len
    call "b-bytes" using bun bunlen sig2hash one n33
    call "b-raw"   using bun bunlen sig2 one sig2len
    call "b-bytes" using bun bunlen cred3hash one n33
    call "b-raw"   using bun bunlen cred3 one cred3len
    call "b-bytes" using bun bunlen sig3hash one n33
    call "b-raw"   using bun bunlen sig3 one sig3len
    call "b-bytes" using bun bunlen tidhash one n33
    call "b-raw"   using bun bunlen tpent one tpentlen
    call "b-bytes" using bun bunlen xidhash one n33
    call "b-raw"   using bun bunlen xpent one xpentlen
    call "b-bytes" using bun bunlen idhash one n33
    call "b-raw"   using bun bunlen pent one pentlen.

build-quorum-bundle.
    move 0 to bunqlen
    call "b-map" using bunq bunqlen n4
    call "b-bytes" using bunq bunqlen qcredhash one n33
    call "b-raw"   using bunq bunqlen qcred one qcredlen
    call "b-bytes" using bunq bunqlen qsigshash one n33
    call "b-raw"   using bunq bunqlen qsigs one qsigslen
    call "b-bytes" using bunq bunqlen qsigthash one n33
    call "b-raw"   using bunq bunqlen qsigt one qsigtlen
    call "b-bytes" using bunq bunqlen tidhash one n33
    call "b-raw"   using bunq bunqlen tpent one tpentlen.
end program pd2-test.
