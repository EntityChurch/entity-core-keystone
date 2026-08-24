// entity-core-protocol-io — the protocol envelope (§3.1): a root entity plus an
// insertion-ordered `included` pool of protocol entities keyed by content_hash.
// On the wire `included` is a byte-keyed CBOR map; we dedup first-seen before
// encoding (a duplicate byte key is a canonicality violation) and verify each
// included key == its entity's recomputed content_hash on parse (§3.1).

Envelope := Object clone do(
    root ::= nil          // Entity
    included ::= nil      // List of Entity (hash is intrinsic to each)

    with := method(r, inc,
        e := self clone
        e setRoot(r)
        e setIncluded(if(inc == nil, List clone, inc))
        e
    )

    includedGet := method(hashSeq,       // raw 33-byte Sequence -> Entity or nil
        found := nil
        included foreach(e, if(e hash == hashSeq, found = e; break))
        found
    )

    toWire := method(
        incl := EcMap clone
        seen := Map clone
        included foreach(e,
            hx := e hashHex
            if(seen hasKey(hx) not,
                seen atPut(hx, true)
                incl atPut(EcBytes with(e hash), e toWire)
            )
        )
        EcMap with("root", root toWire, "included", incl)
    )

    // parse a wire envelope EcMap. NON-RAISING (A-IO-025): structurally-broken
    // input → nil; a root/included hash mismatch → the entity's hashOk=false
    // (the §5.2 step-1 check DENYs). Included entities whose key != content_hash
    // are dropped (they cannot be resolved by hash anyway). No `try` on the hot
    // path — Io's `try` spawns a Coroutine per call (the concurrency leak).
    fromWire := method(m,
        if(m == nil or((m hasSlot("ecKind")) not) or(m ecKind != "map"), return nil)
        rootV := m at("root")
        if(rootV == nil, return nil)
        r := Entity fromWire(rootV)
        if(r == nil, return nil)
        inc := List clone
        incm := m at("included")
        if(incm != nil and(incm hasSlot("ecKind")) and(incm ecKind == "map"),
            seen := Map clone
            incm foreachEntry(k, v,
                if((k hasSlot("ecKind")) and(k ecKind == "bytes"),
                    ent := Entity fromWire(v)
                    if(ent != nil and(k seq == ent hash),
                        hx := ent hashHex
                        if(seen hasKey(hx) not,
                            seen atPut(hx, true)
                            inc append(ent))
                    )
                )
            )
        )
        with(r, inc)
    )
)
