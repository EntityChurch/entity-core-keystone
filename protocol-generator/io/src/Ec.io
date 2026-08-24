// entity-core-protocol-io — small constructors over the EntityCodec value model
// (EcMap/EcBytes/EcBig/EcFloat/EcNull live in the addon io layer). Keeps the
// protocol sources terse: Ec map/scope/array/bytes/tarray.

Ec := Object clone do(
    // a {include:[...], exclude:[...]} scope EcMap from a List of pattern strings
    // (empty exclude omitted; an empty include is a valid "handler-only" scope).
    scope := method(patterns,
        s := EcMap with("include", patterns)
        s
    )

    // a CBOR array (List) of EcMap entries
    array := method(items, items)

    bytes := method(seq, EcBytes with(seq))

    // wrap a List of EcMap grants as a token/grants array
    grants := method(gs, gs)
)
