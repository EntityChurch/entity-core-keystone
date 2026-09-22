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
    //
    // EVERY STEP TESTS THAT WHAT IT GOT IS A MAP BEFORE INDEXING IT, and that is not
    // defensive style — it closes a REMOTELY-TRIGGERABLE PROCESS KILL that had been live
    // since the §6.3 salvage path landed. This walk indexes ATTACKER-CONTROLLED
    // structure: `decodeSalvage` succeeds on exactly the frames the strict decoder
    // refuses, and the tag it steps over can wrap ANY value. For the canonical §6.3 probe
    // -- a tag in the root entity's `data` field -- `data` comes back a NUMBER, and
    // `Number at("request_id")` raises `argument 0 to method 'at' must be a Number, not a
    // 'Sequence'`. On this single-threaded event loop an uncaught raise is the whole
    // PROCESS, so one malformed frame took the peer down and every later check on every
    // later connection reported connection-refused.
    //
    // Measured at HEAD before the fix (output/scratch/preadm411.c, "tag in a data field"
    // arm): CLOSED, with the peer's own STDOUT carrying `message 'at' in 'src/Wire.io' on
    // line 40`. It is stdout and not stderr because that is where Io writes an uncaught
    // exception -- the harness dumps both for exactly this reason, and it is what turned
    // "the peer closed" into a named line in one run.
    //
    // NOT a `try`: A-IO-025 rules that out on any path a frame can reach (Io's `try`
    // clones a Coroutine per call -- the concurrency-throughput leak), and a type test is
    // cheaper and says what it means.
    _ecMapAt := method(v, key,
        if(v == nil, return nil)
        if(v hasSlot("ecKind") not or(v ecKind != "map"), return nil)
        v at(key)
    )

    salvageRequestId := method(payload,
        m := EntityCodec decodeSalvage(payload)
        rid := _ecMapAt(_ecMapAt(_ecMapAt(m, "root"), "data"), "request_id")
        if(rid != nil and(rid isKindOf(Sequence)), rid asString, nil)
    )

    // ── §4.11 pre-admission refusal classification (0.8.2.25) ──
    //
    // list(status, code, message) for a pre-admission failure's CAUSE.
    //
    // "The frame obligation belongs to the class; the CODE belongs to the cause
    // [MUST]" -- a single code for the class would answer an honest caller under the
    // wrong reason and send them to the wrong layer.
    //
    //   connect-auth proof-of-possession      401 authentication_failed  (§4.6/§4.7 --
    //                                            the connect handler's, not here)
    //   envelope over the configured maximum  413 payload_too_large      (§4.10(a), N14)
    //   resolution integrity (mis-keyed inc.) 400 hash_mismatch          (§5.2a, §1.8)
    //   framing / never becomes an Envelope   400 invalid_request        (§4.7, §4.11)
    //   root is neither EXECUTE nor E_R       400 invalid_request        (§3.3, §4.11 --
    //                                            in Peer dispatch, not here)
    //
    // THE TAG ARM KEEPS non_canonical_ecf AND THAT IS DELIBERATE. §4.11 rules that
    // code non-conformant "on the framing arm" and gives its reason in the same
    // sentence: ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations
    // specifically, which that document still MUSTs at decode time (§6.3). The two
    // rows are disjoint by CAUSE rather than in conflict. Everything else this
    // decoder calls non-canonical (a non-minimal head, an indefinite length,
    // mis-ordered keys) is genuinely "non-canonical CBOR that never becomes an
    // Envelope".
    //
    // The input is the codec's STRUCTURED kind (EntityCodec decodeErrorKind), never a
    // message string: a classifier that recognises a cause by matching on prose is one
    // string edit away from silently re-collapsing the codes.
    //
    // The messages are a FIXED TABLE, never an internal detail string: A WIRE-VISIBLE
    // STRING STAYS ASCII, and this peer is one of the two whose crash established that
    // rule -- its own UTF-8 validator rejected byte-correct UTF-8 in an error message
    // and killed the process, cascading 104 FAILs. Nothing here echoes
    // attacker-supplied bytes back either.
    preAdmissionRefusal := method(kind,
        if(kind == "payload_too_large",
            return list(413, "payload_too_large", "inbound frame exceeds the configured maximum size"))
        // THIS ROW IS NOT REACHED ON THIS PEER, AND THAT IS A CONFORMANT CHOICE RATHER
        // THAN A GAP — measured, not assumed (arc-probe families B1/B2 grade both arms
        // `yes` here). §5.2a's `400 hash_mismatch` is scoped to "a peer that REFUSES AT
        // THE DECODE BOUNDARY", i.e. §1.8 mechanism (a), bind-the-key. This peer
        // implements mechanism (b) instead: `Envelope fromWire` DISCARDS an `included`
        // entry whose map key is not the entity's recomputed content_hash, and every
        // authority lookup then addresses by validated content_hash. Under (b) a forged
        // entry is not DETECTED anywhere — the lookup simply MISSES — and §5.2a's own
        // table answers that miss with `401 authentication_failed` (author row) and
        // `403 capability_denied` (capability row), which is what this peer returns.
        //
        // Routing it to `hash_mismatch` would mean abandoning a conformant mechanism to
        // satisfy a code the other mechanism's detection point selects. The row is kept
        // because this table is SHARED with the framing and non-EXECUTE paths and a
        // classifier with a hole is worse than one with an unreached row — but it is
        // labelled so the next reader does not record it as implemented behaviour.
        if(kind == "included_key_mismatch" or(kind == "content_hash_mismatch"),
            return list(400, "hash_mismatch", "an entity was addressed by a hash that does not bind to it"))
        if(kind == "tag_rejected",
            return list(400, "non_canonical_ecf", "CBOR tags are forbidden anywhere in an entity data field"))
        list(400, "invalid_request", "frame did not decode into an envelope")
    )

    // The cause of the refusal `envelopeOfFrame` just answered nil for.
    //
    // TWO STAGES, AND ONLY THE FIRST HAS A CAUSE TO REPORT. A frame can fail in the
    // CODEC (decodeErrorKind names the cause) or in `Envelope fromWire`, which
    // answers nil for a structurally-broken envelope and has no error channel at all
    // -- it is non-raising by design (A-IO-025). A codec kind therefore wins, and the
    // envelope stage falls through to §4.11's framing arm, which is the correct answer
    // for "decoded as CBOR, is not an Envelope".
    refusalKind := method(payload,
        k := EntityCodec decodeErrorKind(payload)
        if(k != nil, return k asString)
        "not_an_envelope"
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
