// Render-from-model drift check: compute content_hash for every §9.5 floor type
// via THIS peer's codec and diff against the oracle's type-registry-vectors
// (the Go-rendered golden set). Catches type_system drift before S4.
// Usage: io test/typecheck.io <type-registry-vectors-v1.cbor>

EntityCodec
doRelativeFile("../src/Ec.io")
doRelativeFile("../src/Entity.io")
doRelativeFile("../src/CoreTypes.io")

path := System args at(1)
vectors := EntityCodec decode(File with(path) contents)
golden := Map clone
vectors foreach(v,
    ch := v at("content_hash")
    hx := ch afterSeq("ecf-sha256:")
    golden atPut(v at("name") asSymbol, hx asSymbol)
)

miss := 0
drift := 0
ok := 0
CoreTypes models foreach(pair,
    name := pair at(0)
    data := pair at(1)
    ent := Entity with("system/type", data)
    mine := ent hashHex exSlice(2)     // strip the 00 format byte -> 64 hex
    g := golden at(name asSymbol)
    if(g == nil,
        ("MISSING-IN-ORACLE " .. name) println; miss = miss + 1
    ,
        if(mine == g,
            ok = ok + 1
        ,
            ("DRIFT " .. name) println
            ("   mine:   " .. mine) println
            ("   oracle: " .. g) println
            drift = drift + 1
        )
    )
)

("" ) println
("floor types rendered: " .. CoreTypes models size) println
("match: " .. ok .. "  drift: " .. drift .. "  missing-in-oracle: " .. miss) println
if(drift > 0 or(CoreTypes models size != 53),
    ("FAIL: " .. drift .. " drift, " .. CoreTypes models size .. " types (expect 53)") println
    System exit(1)
)
"TYPECHECK: PASS (53/53 byte-identical to oracle)" println
