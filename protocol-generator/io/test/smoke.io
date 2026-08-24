// S2.0 codec-seam smoke — the addon loads headless, reaches libentitycore_codec,
// and the value model round-trips. FATAL (exit 1) on any failure.

fails := 0
check := method(name, ok,
    if(ok, ("ok   " .. name) println, fails = fails + 1; ("FAIL " .. name) println)
)

// force the addon to load
EntityCodec

("EntityCodec provenance: " .. EntityCodec implInfo .. " / abi " .. EntityCodec abiVersion) println

// SHA-256("abc") KAT: ba7816bf...
h := EntityCodec sha256("abc")
check("sha256(abc)[0] == 0xba", h at(0) == 186)
check("sha256(abc) size == 32", h size == 32)

// canonical empty map == A0
em := EntityCodec encode(EcMap clone)
check("encode({}) == a0", EntityCodec hexEncode(em) asSymbol == "a0")

// int + text + bytes + nested round-trip
m := EcMap with("value", 42)
enc := EntityCodec encode(m)
check("encode({value:42}) hex", EntityCodec hexEncode(enc) asSymbol == "a16576616c7565182a")
dec := EntityCodec decode(enc)
check("decode round-trip value == 42", dec at("value") == 42)

// bytes vs text distinction
bm := EcMap with("data", EcBytes with(EntityCodec hexDecode("deadbeef")))
check("bytes field encodes mt2", EntityCodec hexEncode(EntityCodec encode(bm)) asSymbol == "a1646461746144deadbeef")

// float ladder
check("1.5 -> f93e00", EntityCodec hexEncode(EntityCodec encode(EcFloat with(1.5))) asSymbol == "f93e00")
check("1.1 -> fb...", EntityCodec hexEncode(EntityCodec encode(EcFloat with(1.1))) asSymbol == "fb3ff199999999999a")

// uint64 tower head-form (A-IO-001 self-test): 2^64-1 via EcBig
big := EcBig clone
big neg := false
big mag := EntityCodec hexDecode("ffffffffffffffff")
check("2^64-1 -> 1bffffffffffffffff", EntityCodec hexEncode(EntityCodec encode(big)) asSymbol == "1bffffffffffffffff")
rt := EntityCodec decode(EntityCodec hexDecode("1bffffffffffffffff"))
check("2^64-1 decodes to EcBig", rt hasSlot("ecKind") and(rt ecKind == "big") and(EntityCodec hexEncode(rt mag) asSymbol == "ffffffffffffffff"))

// tag reject (N2)
tagRejected := try(EntityCodec decode(EntityCodec hexDecode("c11a514b67b0")))
check("tag reject raises", tagRejected != nil)

// duplicate key reject
dup := try(EntityCodec decode(EntityCodec hexDecode("a2616101616102")))
check("dup key reject raises", dup != nil)

// content hash of the empty entity (corpus content_hash.1)
ch := EntityCodec contentHash("system/empty", EntityCodec encode(EcMap clone))
check("contentHash(system/empty,{})", EntityCodec hexEncode(ch) asSymbol == "005f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b")

// ed25519: seed->pub, sign, verify
seed := EntityCodec hexDecode("0000000000000000000000000000000000000000000000000000000000000000")
pub := EntityCodec ed25519SeedToPub(seed)
sig := EntityCodec ed25519Sign(seed, "hello")
check("ed25519 verify(own sig)", EntityCodec ed25519Verify(pub, "hello", sig))
check("ed25519 verify(bad sig) fails", EntityCodec ed25519Verify(pub, "hellx", sig) not)

// ms clock (A-PD-016 lesson): two mints >= 1ms apart differ
t1 := EntityCodec nowMs
System sleep(0.003)
t2 := EntityCodec nowMs
check("nowMs has ms precision", t2 > t1)

if(fails > 0, "SMOKE FAIL" println; System exit(1))
"SMOKE OK: EntityCodec seam + value model live" println
