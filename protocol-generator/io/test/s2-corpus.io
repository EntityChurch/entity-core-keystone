// S2 corpus gate — run the pinned v0.8.0 ECF conformance corpus
// (conformance-vectors.cbor, 71 vectors) through the EntityCodec addon.
//
// Per ENTITY-CBOR-ENCODING.md Appendix E §E.3: the fixture itself is loaded
// with the impl's own decoder (a decoder bug here is itself a conformance
// failure), then each vector branches on kind:
//   encode_equal  — encode(input) byte-identical to `canonical`
//                   (content_hash / peer_id / signature categories apply their
//                    Class-B construction on top of the decoded input)
//   decode_reject — decode(canonical) MUST raise
//
// Usage: io test/s2-corpus.io <path-to-conformance-vectors.cbor>

EntityCodec  // force addon load

path := System args at(1)
if(path == nil, "usage: io s2-corpus.io <corpus.cbor>" println; System exit(2))

bytes := File with(path) contents
vectors := EntityCodec decode(bytes)
("corpus: " .. vectors size .. " vectors loaded (decoder survived the fixture)") println

pass := 0
fail := 0
skip := 0
failIds := List clone
catStats := Map clone

seqOf := method(v,
    // canonical/bytes fields decode as EcBytes; inputs sometimes raw Sequence
    if(v hasSlot("ecKind") and(v ecKind == "bytes"), v seq, v)
)

catOf := method(id, id beforeSeq("."))

bump := method(cat, ok,
    cell := catStats atIfAbsentPut(cat, list(0, 0))
    if(ok, cell atPut(0, cell at(0) + 1), cell atPut(1, cell at(1) + 1))
)

vectors foreach(vec,
    id := vec at("id") asSymbol
    kind := vec at("kind") asSymbol
    canonical := seqOf(vec at("canonical"))
    cat := catOf(id)
    ok := nil

    if(kind == "decode_reject",
        e := try(EntityCodec decode(canonical))
        ok = (e != nil)
    ,
        input := vec at("input")
        produced := nil
        e := try(
            if(cat == "content_hash",
                type := input at("type")
                dataBytes := EntityCodec encode(input at("data"))
                fc := input at("format_code")
                produced = if(fc == nil,
                    EntityCodec contentHash(type, dataBytes),
                    EntityCodec contentHashWithFormat(type, dataBytes, fc))
            ,
            if(cat == "peer_id",
                pid := EntityCodec peeridFormat(input at("key_type"), input at("hash_type"), input at("digest") seq)
                produced = EntityCodec encode(pid)
            ,
            if(cat == "signature",
                ent := input at("entity")
                ecf := EcMap with("data", ent at("data"), "type", ent at("type"))
                msg := EntityCodec encode(ecf)
                produced = EntityCodec ed25519Sign(input at("seed") seq, msg)
            ,
                produced = EntityCodec encode(input)
            )))
        )
        if(e != nil,
            ok = false
        ,
            ok = (produced == canonical)
        )
    )

    bump(cat, ok)
    if(ok, pass = pass + 1, fail = fail + 1; failIds append(id))
)

"" println
"category            P    F" println
catStats keys sort foreach(cat,
    cell := catStats at(cat)
    (cat alignLeft(18) .. cell at(0) asString alignLeft(5) .. cell at(1) asString) println
)
"" println
("TOTAL: " .. pass .. " pass / " .. fail .. " fail / " .. vectors size .. " vectors") println
if(fail > 0,
    ("FAILED: " .. failIds join(", ")) println
    System exit(1)
)
"S2 GATE: PASS (byte-identical corpus)" println
