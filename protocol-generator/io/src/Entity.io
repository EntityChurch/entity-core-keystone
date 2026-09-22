// entity-core-protocol-io — a materialized entity {type, data, content_hash}
// (§1.1, §3.4) on top of the S2 EntityCodec value model.
//
// `data` is an ARBITRARY ECF value (§1.1 / A-JAVA-010): an EcMap for every core
// protocol entity, or a scalar. The content_hash covers ONLY {type, data} and is
// held as a RAW 33-byte Sequence (EcBytes only at the wire boundary). Field reads
// go through the map VIEW (an empty EcMap for scalar data) so reads never throw.

Entity := Object clone do(
    entityType ::= nil     // text Sequence — "type" collides with Object type (A-IO-007)
    data ::= nil           // Ec value
    hash ::= nil           // raw 33-byte Sequence
    hashOk ::= true        // false iff the wire carried a content_hash != recomputed (§1.8/§5.2 step1)

    // construct + hash (§7.1). dataBytes computed once through the seam.
    with := method(t, d,
        e := self clone
        e setEntityType(t)
        e setData(d)
        e setHash(EntityCodec contentHash(t, EntityCodec encode(d)))
        e
    )

    // The §6.3 RECEIPT constructor: bind an entity to a content_hash the CALLER
    // has already verified against contentHash({type, data}).
    //
    // `with` AUTHORS a hash. On the system/tree:put path that is exactly what
    // §6.3 (0.8.2.11) forbids — the submitter authors, the peer verifies. This
    // constructor takes the carried bytes verbatim and is reachable only from
    // the admission ladder, which has just proved they match.
    admitted := method(t, d, verifiedHash,
        e := self clone
        e setEntityType(t)
        e setData(d)
        e setHash(verifiedHash)
        e
    )

    // parse a wire entity EcMap {type, data, content_hash}; recompute the hash
    // (§1.8 fidelity). NON-RAISING (A-IO-025): structurally-broken input → nil;
    // a carried-hash mismatch → the entity with hashOk=false (the §5.2 step-1
    // content-hash check reads the flag → AUTHZ_DENY). No `try` on the hot path.
    fromWire := method(m,
        if(m == nil or((m hasSlot("ecKind")) not) or(m ecKind != "map"), return nil)
        t := m at("type")
        if(t == nil or(t hasSlot("ecKind")), return nil)
        if(m hasKey("data") not, return nil)
        e := with(t, m at("data"))
        carried := m at("content_hash")
        if(carried != nil,
            if((carried hasSlot("ecKind")) and(carried ecKind == "bytes") and(carried seq == e hash),
                e setHashOk(true),
                e setHashOk(false))
        )
        e
    )

    toWire := method(
        EcMap with("type", entityType, "data", data, "content_hash", EcBytes with(hash))
    )

    hashHex := method(EntityCodec hexEncode(hash) asSymbol)

    // `data` as a map view (empty EcMap when data is a scalar)
    dataMap := method(
        if(data != nil and(data hasSlot("ecKind")) and(data ecKind == "map"), data, EcMap clone)
    )

    // ── typed field reads off the data map view ──
    text := method(key,
        v := dataMap at(key)
        if(v != nil and(v hasSlot("ecKind") not) and(v isKindOf(Sequence)), v, nil)
    )
    bytes := method(key,       // raw Sequence of an EcBytes field, or nil
        v := dataMap at(key)
        if(v != nil and(v hasSlot("ecKind")) and(v ecKind == "bytes"), v seq, nil)
    )
    uint := method(key,
        v := dataMap at(key)
        if(v != nil and(v isKindOf(Number)), v, nil)
    )
    field := method(key, dataMap at(key))
    mapField := method(key,
        v := dataMap at(key)
        if(v != nil and(v hasSlot("ecKind")) and(v ecKind == "map"), v, nil)
    )
    listField := method(key,
        v := dataMap at(key)
        if(v != nil and(v isKindOf(List)), v, nil)
    )
    textList := method(key,    // List of text Sequences, or empty list
        out := List clone
        v := listField(key)
        if(v != nil, v foreach(x, if(x isKindOf(Sequence) and(x hasSlot("ecKind") not), out append(x))))
        out
    )
    // decode a nested wire-entity map carried at key, or nil
    entityField := method(key,
        v := mapField(key)
        if(v == nil, nil, Entity fromWire(v))
    )
)
