>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — storage (§1.7): content store + entity tree.
*>
*>   Content store: hash(33) -> entity wire bytes   (immutable, dedup)
*>   Entity tree:   path      -> hash(33)            (mutable location index)
*>
*> One stateful module; ENTRY points share the static WORKING-STORAGE tables
*> (GnuCOBOL retains them across calls). Paths are the canonical absolute form
*> "/{peer_id}/rest" (§1.4); callers canonicalize before binding.
*>
*> Entries: store-init, store-put, store-bind, store-unbind, store-hash-at,
*>          store-get-by-hash, store-get-at, store-listing.
*> ===================================================================
identification division.
program-id. store.
data division.
working-storage section.
01 ws-cn       pic 9(9) comp-5 value 0.       *> content entry count
01 ws-tn       pic 9(9) comp-5 value 0.       *> tree entry count
*> Content entries carry an OFFSET into one shared arena, not a fixed slot.
*>
*> The slot form multiplies: 1024 entries x a per-entity ceiling is the whole
*> table's size whether or not anything that large is ever stored, so the
*> ceiling and the footprint could not be varied independently. At the 32768
*> slot this table was 33.6 MB to hold a measured peak of 116-119 entries whose
*> real content is a few tens of KB; raising the slot to the frame capacity
*> would have made it 537 MB.
*>
*> With an arena the two are separate: the ceiling on ONE entity is ws-entmax
*> (the frame capacity — an entity that arrived in a frame can always be
*> stored), and the ceiling on ALL of them is the arena, sized for the
*> workload rather than for the worst case times the slot count.
*>
*> Allocation is bump-only: the content store is immutable and dedups by hash
*> (§1.7), so an entry is written once and never resized or released, and a
*> free list would have nothing to reclaim. store-init resets the bump.
01 ws-content.
   05 ws-c occurs 1024.
      10 ws-c-hash  pic x(33).
      10 ws-c-len   pic 9(9) comp-5.
      10 ws-c-off   pic 9(9) comp-5.
01 ws-arena    pic x(8388608).
01 ws-arenamax pic 9(9) comp-5 value 8388608.
01 ws-arenause pic 9(9) comp-5 value 0.
01 ws-tree.
   05 ws-t occurs 8192.
      10 ws-t-plen  pic 9(9) comp-5.
      10 ws-t-path  pic x(700).
      10 ws-t-hash  pic x(33).
01 ws-cmax     pic 9(9) comp-5 value 1024.
*> Per-entity capacity, in bytes: the size of the largest single entity the
*> store will accept. Every caller of store-put / store-bind / store-get-*
*> passes a frame-capacity buffer, so this is the one number that has to agree
*> across the whole store surface — and it is checked BEFORE each copy rather
*> than assumed. An entity larger than this used to be memcpy'd into the slot
*> regardless: glibc's _FORTIFY_SOURCE caught it and killed the process, so ONE
*> oversized (but under-frame-cap) tree.put from any caller terminated the peer.
*> Callers reject over-capacity entities at the handler, where a status can be
*> returned; this guard is the backstop that makes the buffer size stop being
*> load-bearing for memory safety.
*>
*> It now equals the frame capacity (netshim.c EC_FRAMECAP), which is the only
*> value that makes the guard invisible in practice: an entity small enough to
*> have ARRIVED is small enough to store. While it was smaller, a frame the
*> transport had accepted could still be refused here, which is a capacity
*> boundary in the middle of the peer rather than at its edge.
01 ws-entmax   pic 9(9) comp-5 value 524288.
01 ws-tmax     pic 9(9) comp-5 value 8192.
01 ws-i        pic 9(9) comp-5.
01 ws-idx      pic 9(9) comp-5.
01 ws-found    pic 9(1).
01 ws-prefix-end pic 9(9) comp-5.
01 ws-rest     pic x(700).
01 ws-rest-len pic 9(9) comp-5.
01 ws-seg      pic x(700).
01 ws-seg-len  pic 9(9) comp-5.
01 ws-slash    pic 9(9) comp-5.
01 ws-q        pic 9(9) comp-5.
01 ws-li       pic 9(9) comp-5.
01 ws-mi       pic 9(9) comp-5.
01 ws-mfound   pic 9(1).
01 ws-gethash  pic x(33).
01 ws-lcnt     pic 9(9) comp-5.
01 ws-list.
   05 ws-l occurs 256.
      10 ws-l-seg     pic x(256).
      10 ws-l-seglen  pic 9(9) comp-5.
      10 ws-l-hash    pic x(33).
      10 ws-l-hashp   pic 9(1).
      10 ws-l-child   pic 9(1).
linkage section.
01 lk-hash     pic x(33).
01 lk-ent      pic x(524288).
01 lk-len      pic 9(9) comp-5.
01 lk-path     pic x(700).
01 lk-plen     pic 9(9) comp-5.
01 lk-found    pic 9(1).
*> listing output accessors
01 lk-cnt      pic 9(9) comp-5.
01 lk-idx      pic 9(9) comp-5.
01 lk-seg      pic x(256).
01 lk-seglen   pic 9(9) comp-5.
01 lk-hashp    pic 9(1).
01 lk-child    pic 9(1).
procedure division.
*> default entry: initialize
    move 0 to ws-cn
    move 0 to ws-tn
    move 0 to ws-arenause
    goback.

*> ---- store-init ----------------------------------------------------
entry "store-init".
    move 0 to ws-cn
    move 0 to ws-tn
    move 0 to ws-arenause
    goback.

*> ---- store-put : content store, dedup by hash ----------------------
*> Bounded: silently drop past the table cap rather than write OOB (which would
*> corrupt the tables and cascade into resolution failures over a long run).
entry "store-put" using lk-ent lk-len lk-hash.
    if lk-len > ws-entmax then goback end-if
    perform find-content
    if ws-found = 0
        perform arena-admit
    end-if
    goback.

*> ---- store-bind : put + set tree[path] = hash ----------------------
entry "store-bind" using lk-path lk-plen lk-ent lk-len lk-hash.
    if lk-len > ws-entmax then goback end-if
    perform find-content
    if ws-found = 0
        perform arena-admit
    end-if
    perform find-tree
    if ws-found = 1
        move lk-hash to ws-t-hash(ws-idx)
    else
        if ws-tn < ws-tmax
            add 1 to ws-tn
            move lk-plen to ws-t-plen(ws-tn)
            move lk-path(1:lk-plen) to ws-t-path(ws-tn)(1:lk-plen)
            move lk-hash to ws-t-hash(ws-tn)
        end-if
    end-if
    goback.

*> ---- store-unbind : tombstone the tree binding --------------------
entry "store-unbind" using lk-path lk-plen.
    perform find-tree
    if ws-found = 1
        move 0 to ws-t-plen(ws-idx)
    end-if
    goback.

*> ---- store-hash-at : tree lookup -> hash + found ------------------
entry "store-hash-at" using lk-path lk-plen lk-hash lk-found.
    perform find-tree
    move ws-found to lk-found
    if ws-found = 1 then move ws-t-hash(ws-idx) to lk-hash end-if
    goback.

*> ---- store-get-by-hash : content lookup --------------------------
entry "store-get-by-hash" using lk-hash lk-ent lk-len lk-found.
    perform find-content
    move ws-found to lk-found
    if ws-found = 1
        move ws-c-len(ws-idx) to lk-len
        move ws-arena(ws-c-off(ws-idx):lk-len) to lk-ent(1:lk-len)
    end-if
    goback.

*> ---- store-get-at : tree -> hash -> content ----------------------
entry "store-get-at" using lk-path lk-plen lk-ent lk-len lk-found.
    move 0 to lk-found
    perform find-tree
    if ws-found = 0 then goback end-if
    move ws-t-hash(ws-idx) to ws-gethash
    perform find-content-g
    move ws-found to lk-found
    if ws-found = 1
        move ws-c-len(ws-idx) to lk-len
        move ws-arena(ws-c-off(ws-idx):lk-len) to lk-ent(1:lk-len)
    end-if
    goback.

*> ---- store-listing : distinct child segments under a prefix ------
*> Prefix MUST end with "/". Populates an internal table read via
*> store-list-entry. Each entry: child segment, optional leaf hash
*> (bound exactly at prefix+seg), has_children (deeper paths exist).
entry "store-listing" using lk-path lk-plen lk-cnt.
    move 0 to ws-lcnt
    perform varying ws-i from 1 by 1 until ws-i > ws-tn
        if ws-t-plen(ws-i) > lk-plen
           and ws-t-path(ws-i)(1:lk-plen) = lk-path(1:lk-plen)
            compute ws-rest-len = ws-t-plen(ws-i) - lk-plen
            move ws-t-path(ws-i)(lk-plen + 1:ws-rest-len)
                to ws-rest(1:ws-rest-len)
            move 0 to ws-slash
            perform varying ws-q from 1 by 1 until ws-q > ws-rest-len
                if ws-rest(ws-q:1) = "/" then move ws-q to ws-slash  exit perform end-if
            end-perform
            if ws-slash = 0
                move ws-rest-len to ws-seg-len
                move ws-rest(1:ws-rest-len) to ws-seg(1:ws-rest-len)
                perform merge-leaf
            else
                compute ws-seg-len = ws-slash - 1
                move ws-rest(1:ws-seg-len) to ws-seg(1:ws-seg-len)
                perform merge-child
            end-if
        end-if
    end-perform
    move ws-lcnt to lk-cnt
    goback.

entry "store-list-entry" using lk-idx lk-seg lk-seglen lk-hash lk-hashp lk-child.
    move ws-l-seg(lk-idx) to lk-seg
    move ws-l-seglen(lk-idx) to lk-seglen
    move ws-l-hash(lk-idx) to lk-hash
    move ws-l-hashp(lk-idx) to lk-hashp
    move ws-l-child(lk-idx) to lk-child
    goback.

*> ---- helper paragraphs -------------------------------------------
find-seg.
    move 0 to ws-mfound
    move 0 to ws-mi
    perform varying ws-li from 1 by 1 until ws-li > ws-lcnt
        if ws-l-seglen(ws-li) = ws-seg-len
           and ws-l-seg(ws-li)(1:ws-seg-len) = ws-seg(1:ws-seg-len)
            move ws-li to ws-mi
            move 1 to ws-mfound
            exit perform
        end-if
    end-perform.

add-seg.
    if ws-lcnt < 256
        add 1 to ws-lcnt
        move ws-lcnt to ws-mi
        move ws-seg-len to ws-l-seglen(ws-mi)
        move ws-seg(1:ws-seg-len) to ws-l-seg(ws-mi)(1:ws-seg-len)
        move all x"00" to ws-l-hash(ws-mi)
        move 0 to ws-l-hashp(ws-mi)
        move 0 to ws-l-child(ws-mi)
    else
        move 0 to ws-mi
    end-if.

merge-leaf.
    perform find-seg
    if ws-mfound = 0 then perform add-seg end-if
    if ws-mi > 0
        move ws-t-hash(ws-i) to ws-l-hash(ws-mi)
        move 1 to ws-l-hashp(ws-mi)
    end-if.

merge-child.
    perform find-seg
    if ws-mfound = 0 then perform add-seg end-if
    if ws-mi > 0 then move 1 to ws-l-child(ws-mi) end-if.

*> Admit LK-ENT(1:LK-LEN) as a new content entry: bump-allocate arena space,
*> record (hash, len, offset), copy once. Callers have already established that
*> the hash is not present (dedup) and that LK-LEN is within ws-entmax.
*>
*> BOTH bounds are tested BEFORE the copy and a failure is a silent no-admit,
*> which is the behaviour the fixed-slot form had at its table cap: the entity
*> is simply not resolvable afterwards. It is not a new failure mode, and the
*> alternative — writing past the arena — is the _FORTIFY_SOURCE abort this
*> module's per-entity guard exists to have already prevented once.
arena-admit.
    if ws-cn < ws-cmax and ws-arenause + lk-len <= ws-arenamax
        add 1 to ws-cn
        move lk-hash to ws-c-hash(ws-cn)
        move lk-len  to ws-c-len(ws-cn)
        compute ws-c-off(ws-cn) = ws-arenause + 1
        if lk-len > 0
            move lk-ent(1:lk-len) to ws-arena(ws-c-off(ws-cn):lk-len)
        end-if
        add lk-len to ws-arenause
    end-if.

find-content.
    move 0 to ws-found
    move 0 to ws-idx
    perform varying ws-i from 1 by 1 until ws-i > ws-cn
        if ws-c-hash(ws-i) = lk-hash
            move ws-i to ws-idx
            move 1 to ws-found
            exit perform
        end-if
    end-perform.

find-content-g.
    move 0 to ws-found
    move 0 to ws-idx
    perform varying ws-i from 1 by 1 until ws-i > ws-cn
        if ws-c-hash(ws-i) = ws-gethash
            move ws-i to ws-idx
            move 1 to ws-found
            exit perform
        end-if
    end-perform.

find-tree.
    move 0 to ws-found
    move 0 to ws-idx
    perform varying ws-i from 1 by 1 until ws-i > ws-tn
        if ws-t-plen(ws-i) = lk-plen and ws-t-plen(ws-i) > 0
           and ws-t-path(ws-i)(1:lk-plen) = lk-path(1:lk-plen)
            move ws-i to ws-idx
            move 1 to ws-found
            exit perform
        end-if
    end-perform.
end program store.
