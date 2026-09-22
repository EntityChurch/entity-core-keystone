// entity-core-protocol-io — wire framing (§1.6) + the two message builders
// (§3.2 EXECUTE, §3.3 EXECUTE_RESPONSE) + the recoverable Outcome seam.
// Frame := [4-byte BE length][canonical-ECF envelope]. Only EXECUTE and
// EXECUTE_RESPONSE are wire message types (§3.3).

Wire := Object clone do(
    maxFrame := 16 * 1024 * 1024      // §1.6 / §4.10(a)

    frameOfEnvelope := method(env,
        payload := EntityCodec encode(env toWire)
        EntityCodec packU32be(payload size) .. payload
    )

    // NON-RAISING (A-IO-025): tryDecode → nil on malformed CBOR, Envelope
    // fromWire → nil on a structurally-broken envelope. The caller treats nil as
    // an undecodable frame (drop / no coded response) WITHOUT a per-frame `try`
    // (Io's `try` clones a Coroutine — the concurrency leak).
    envelopeOfFrame := method(payload,
        m := EntityCodec tryDecode(payload)
        if(m == nil, return nil)
        Envelope fromWire(m)
    )

    // §6.3 rejection reporting: recover ONLY the request_id from a frame the strict
    // decoder rejected, so the rejection can be delivered as a correlated
    // `400 non_canonical_ecf` response instead of silence. The frame stays rejected —
    // nothing else is read out of it. Returns nil when even the request_id is
    // unrecoverable (an unattributable frame, where silence is the only option left).
    //
    // The envelope and entity-wrapper shapes are fixed maps with no legal tag position
    // (§6.3), so a frame whose ONLY defect is a tag inside some entity's `data` still has
    // a structurally sound root — which is exactly the case this recovers.
    salvageRequestId := method(payload,
        m := EntityCodec decodeSalvage(payload)
        if(m == nil, return nil)
        root := m at("root")
        if(root == nil, return nil)
        data := root at("data")
        if(data == nil, return nil)
        rid := data at("request_id")
        if(rid isKindOf(Sequence), rid asString, nil)
    )

    // ── EXECUTE builder (§3.2). author/capability are raw hash Sequences (nil
    // to omit); resource is an EcMap (nil to omit); params is an Entity. ──
    makeExecute := method(requestId, uri, operation, params, author, capability, resource,
        d := EcMap with(
            "request_id", requestId,
            "uri", uri,
            "operation", operation,
            "params", params toWire)
        if(author != nil, d atPut("author", EcBytes with(author)))
        if(capability != nil, d atPut("capability", EcBytes with(capability)))
        if(resource != nil, d atPut("resource", resource))
        Entity with("system/protocol/execute", d)
    )

    // ── EXECUTE_RESPONSE builder (§3.3) ──
    makeResponse := method(requestId, status, result,
        Entity with("system/protocol/execute/response", EcMap with(
            "request_id", requestId,
            "status", status,
            "result", result toWire))
    )

    errorResult := method(code, message,
        d := EcMap with("code", code)
        if(message != nil and(message size > 0), d atPut("message", message))
        Entity with("system/protocol/error", d)
    )

    // empty-params (§3.2 N3): primitive/any whose data is the canonical empty map
    emptyParams := method(Entity with("primitive/any", EcMap clone))

    resourceTarget := method(
        targets := List clone
        call message arguments foreach(a, targets append(call sender doMessage(a) asSymbol))
        EcMap with("targets", targets)
    )

    responseStatus := method(env,
        s := env root uint("status")
        if(s == nil, 0, s)
    )
    responseResult := method(env,
        env root entityField("result")
    )
)

// ── the recoverable handler-result seam: {status, result Entity, included} ──
Outcome := Object clone do(
    status ::= 200
    result ::= nil
    included ::= nil

    ok := method(res, inc,
        o := self clone
        o setStatus(200)
        o setResult(res)
        o setIncluded(if(inc == nil, List clone, inc))
        o
    )
    err := method(st, code, message,
        o := self clone
        o setStatus(st)
        o setResult(Wire errorResult(code, message))
        o setIncluded(List clone)
        o
    )
)
