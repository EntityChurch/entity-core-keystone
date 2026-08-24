// entity-core-protocol-io — storage (§1.7): the two layers + the emit pathway
// (§6.10 / §6.13(c)) + THE PARADIGM RENDERING of §6.6 dispatch.
//
//   Content Store: hex(content_hash) -> Entity   (immutable, dedup)
//   Entity Tree:   absolute path -> hex           (mutable location index)
//
// == §6.6 AS DIFFERENTIAL INHERITANCE (the probe's payoff) ==
// The dispatch surface is a NETWORK OF PROTOTYPES mirroring the path tree: the
// node for /a/b/c is a CLONE of the node for /a/b (differential inheritance).
// Binding a system/handler entity at a path DEFINES handlerPattern on that
// path's node; every descendant node inherits it through the proto chain unless
// a deeper handler shadows it. §6.6 longest-prefix resolution is therefore NOT
// a hand-written backward loop — it is Io's own delegation lookup:
//     resolve(path) = deepestExistingNode(path) handlerPattern
// The nearest definition wins in a delegation chain exactly as the longest
// prefix wins in §6.6; unbinding a handler removeSlot()s the definition and the
// ancestor's shows through again. (The spec's type-directed filter holds: only
// system/handler-typed bindings define the slot.)
//
// == §4.8 store-safety: STRUCTURAL — one OS thread, and no coroutine yield
// occurs inside any store mutation (coroutines switch only at socket waits).

DispatchNode := Object clone do(handlerPattern := nil)

Store := Object clone do(
    init := method(
        self content := Map clone          // hex -> Entity
        self tree := Map clone             // path -> hex
        self nodes := Map clone            // path -> DispatchNode (the proto network)
        self contentConsumers := List clone
        self treeConsumers := List clone
    )

    registerContentConsumer := method(blk, contentConsumers append(blk); self)
    registerTreeConsumer := method(blk, treeConsumers append(blk); self)

    // ── content store (§6.10 Store step: event only when NEW) ──
    putEntity := method(e,
        hx := e hashHex
        if(content hasKey(hx) not,
            content atPut(hx, e)
            contentConsumers foreach(c, c call(e hash, e))
        )
        self
    )

    getByHash := method(hashSeq,
        content at(EntityCodec hexEncode(hashSeq) asSymbol)
    )

    // ── the dispatch-node network ──
    nodeFor := method(path,
        n := nodes at(path)
        if(n != nil, return n)
        segs := path split("/") select(s, s size > 0)
        parent := DispatchNode
        prefix := Sequence clone
        segs foreach(seg,
            prefix = (prefix .. "/" .. seg) asSymbol
            n = nodes at(prefix)
            if(n == nil,
                n = parent clone            // differential inheritance
                nodes atPut(prefix, n)
            )
            parent = n
        )
        parent
    )

    deepestNode := method(path,
        // the deepest EXISTING node along path (its proto chain carries the
        // nearest handler definition upward)
        segs := path split("/") select(s, s size > 0)
        found := nil
        prefix := Sequence clone
        segs foreach(seg,
            prefix = (prefix .. "/" .. seg) asSymbol
            n := nodes at(prefix)
            if(n == nil, break)
            found = n
        )
        found
    )

    // §6.6: resolve the governing handler pattern for an absolute path, or nil.
    // The delegation walk IS the longest-prefix walk.
    resolveHandlerPattern := method(path,
        n := deepestNode(path)
        if(n == nil, nil, n handlerPattern)
    )

    // ── entity tree (§6.10 Bind step) ──
    bind := method(path, e,
        putEntity(e)
        next := e hashHex
        prev := tree at(path)
        tree atPut(path asSymbol, next)
        node := nodeFor(path)
        if(e entityType == "system/handler",
            node setSlot("handlerPattern", path asSymbol)
        ,
            // a non-handler entity rebinding a former handler path un-defines it
            if(node hasLocalSlot("handlerPattern"), node removeSlot("handlerPattern"))
        )
        if(next != prev,
            ev := Map clone atPut("event_type", if(prev == nil, "created", "modified")) \
                atPut("path", path) atPut("new_hash", next)
            if(prev != nil, ev atPut("previous_hash", prev))
            treeConsumers foreach(c, c call(ev))
        )
        self
    )

    unbind := method(path,
        prev := tree at(path)
        if(prev != nil,
            tree removeAt(path)
            node := nodes at(path)
            if(node != nil and(node hasLocalSlot("handlerPattern")), node removeSlot("handlerPattern"))
            ev := Map clone atPut("event_type", "deleted") atPut("path", path) atPut("previous_hash", prev)
            treeConsumers foreach(c, c call(ev))
        )
        self
    )

    hashAt := method(path, tree at(path))

    getAt := method(path,
        hx := tree at(path)
        if(hx == nil, nil, content at(hx))
    )

    // one-level listing under prefix (trailing / normalized), sorted by segment
    // (§3.9). Returns a List of list(segment, hexOrNil, hasChildren).
    listing := method(prefix,
        p := if(prefix endsWithSeq("/"), prefix, prefix .. "/")
        plen := p size
        acc := Map clone       // segment -> list(hex, hasChildren)
        tree foreach(path, hx,
            if(path size > plen and(path beginsWithSeq(p)),
                rest := path exSlice(plen)
                slash := rest findSeq("/")
                if(slash != nil,
                    seg := rest exSlice(0, slash) asSymbol
                    cell := acc atIfAbsentPut(seg, list(nil, false))
                    cell atPut(1, true)
                ,
                    seg := rest asSymbol
                    cell := acc atIfAbsentPut(seg, list(nil, false))
                    cell atPut(0, hx)
                )
            )
        )
        out := List clone
        acc keys sort foreach(seg,
            cell := acc at(seg)
            out append(list(seg, cell at(0), cell at(1)))
        )
        out
    )
)
