// EntityCodec addon — Io layer: the explicit CBOR value model (profile [codec],
// A-IO-001/A-IO-009). Wire values are Io values with wrappers wherever Io's
// value model is ambiguous:
//   EcMap   — CBOR map (insertion-ordered; keys text Sequence OR EcBytes)
//   EcBytes — CBOR byte string (mt2) — the byte-vs-text seam
//   EcBig   — integer outside the double-exact range (|x| > 2^53)
//   EcFloat — CBOR float (mt7) — a bare Number ALWAYS means integer
//   EcNull  — CBOR null (nil is the ABSENT sentinel, not a wire value)
// The addon C recognizes wrappers by their ecKind slot; _setWrappers hands the
// protos to C for decode-side cloning.

EcBytes := Object clone do(
    ecKind := "bytes"
    seq ::= nil
    with := method(s, self clone setSeq(s))
    == := method(other,
        if(other == nil, return false)
        if(other hasSlot("ecKind") not, return false)
        if(other ecKind != "bytes", return false)
        seq == other seq
    )
    hex := method(EntityCodec hexEncode(seq) asSymbol)
    size := method(seq size)
    isZero := method(
        z := true
        seq foreach(b, if(b != 0, z = false; break))
        z
    )
)

EcBig := Object clone do(
    ecKind := "big"
    neg := false
    mag := nil          // 8-byte BE Sequence: the head VALUE n (for mt1, int = -1-n)
)

EcFloat := Object clone do(
    ecKind := "float"
    num := 0
    with := method(n, c := self clone; c num := n; c)
)

EcNull := Object clone do(ecKind := "null")

EcMap := Object clone do(
    ecKind := "map"

    init := method(
        self keys := List clone
        self vals := List clone
    )

    size := method(keys size)

    _keyMatches := method(k, key,
        if(key hasSlot("ecKind") and(key ecKind == "bytes"),
            (k hasSlot("ecKind")) and(k ecKind == "bytes") and(k seq == key seq)
        ,
            (k hasSlot("ecKind") not) and(k == key)
        )
    )

    indexOf := method(key,
        i := 0
        found := nil
        keys foreach(k,
            if(_keyMatches(k, key), found = i; break)
            i = i + 1
        )
        found
    )

    at := method(key,
        i := indexOf(key)
        if(i == nil, nil, vals at(i))
    )

    hasKey := method(key, indexOf(key) != nil)

    atPut := method(key, value,
        i := indexOf(key)
        if(i == nil,
            keys append(key)
            vals append(value)
        ,
            vals atPut(i, value)
        )
        self
    )

    removeKey := method(key,
        i := indexOf(key)
        if(i != nil,
            keys removeAt(i)
            vals removeAt(i)
        )
        self
    )

    // convenience constructors
    with := method(
        mp := self clone
        i := 0
        while(i < call argCount,
            k := call evalArgAt(i)
            v := call evalArgAt(i + 1)
            mp atPut(k, v)
            i = i + 2
        )
        mp
    )

    foreachEntry := method(
        // foreachEntry(k, v, body)
        kName := call argAt(0) name
        vName := call argAt(1) name
        i := 0
        while(i < keys size,
            call sender setSlot(kName, keys at(i))
            call sender setSlot(vName, vals at(i))
            call evalArgAt(2)
            i = i + 1
        )
        self
    )
)

// hand the wrapper protos to the C decoder
EntityCodec _setWrappers(EcMap, EcBytes, EcBig, EcFloat, EcNull)
