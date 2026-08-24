# entity-core-protocol-unison — pinned-invariant self-tests (N1–N4 + fixed-width)

Direct unit coverage for the pinned conformance invariants, complementing the
corpus gate (`conformance.md`). Each `>` watch prints its own PASS/FAIL so the
invariant is legible in the diffable output.

```ucm
scratch/main> builtins.mergeio
scratch/main> load src/Codec.u
scratch/main> add
scratch/main> load src/Protocol.u
scratch/main> add
scratch/main> load src/Ed25519.u
scratch/main> add
```

```unison
hx : Bytes -> Text
hx b = bytesToText (Bytes.toBase16 b)

fromHx : Text -> Bytes
fromHx h = match Bytes.fromBase16 (Text.toUtf8 h) with
  Right b -> b
  Left _ -> Bytes.empty

chk : Text -> Boolean -> Text
chk label ok = (if ok then "PASS " else "FAIL ") Text.++ label

rejects : Text -> Boolean
rejects h = match decode (fromHx h) with
  Left _ -> true
  Right _ -> false

roundtrips : Text -> Boolean
roundtrips h = match decode (fromHx h) with
  Right v -> (hx (encode v)) == h
  Left _ -> false

-- N1 — varint framing is real LEB128, not a fixed byte (codes >= 0x80 extend).
> chk "N1 varint 128 -> 8001" ((hx (varintEncode 128)) == "8001")
> chk "N1 varint 300 -> ac02" ((hx (varintEncode 300)) == "ac02")
> chk "N1 varint 127 -> 7f (1 byte)" ((hx (varintEncode 127)) == "7f")

-- N2 — recursive major-type-6 tag rejection at ANY depth (not just top level).
> chk "N2 tag top-level 55799" (rejects "d9d9f7a0")
> chk "N2 tag inside array elem" (rejects "81c001")
> chk "N2 tag nested in map value" (rejects "a1616bc001")

-- N3 — empty map pins to the single byte 0xA0 (and empty array to 0x80).
> chk "N3 empty map == a0" ((hx (encode (VMap []))) == "a0")
> chk "N3 empty array == 80" ((hx (encode (VArray []))) == "80")

-- N4 — entity fidelity: decode->encode is byte-identical for canonical input
--      (no lossy re-serialization); byte strings forwarded verbatim.
> chk "N4 fidelity: entity round-trips" (roundtrips "a26464617461a261610161626374776f647479706567746573742f7631")
> chk "N4 fidelity: bytes verbatim" (roundtrips "44deadbeef")

-- Fixed-width self-test [2^63, 2^64-1] (A-UN-003): the high-bit-set uint64 head
-- form, and the largest nint magnitude (-2^64) that Int cannot hold but VNInt's
-- Nat argument carries.
> chk "FW uint 2^63 head" ((hx (encode (VUInt 9223372036854775808))) == "1b8000000000000000")
> chk "FW uint 2^64-1 head" ((hx (encode (VUInt 18446744073709551615))) == "1bffffffffffffffff")
> chk "FW uint 2^64-1 round-trip" (roundtrips "1bffffffffffffffff")
> chk "FW nint -2^64 (max magnitude)" ((hx (encode (VNInt 18446744073709551615))) == "3bffffffffffffffff")
> chk "FW nint -2^64 round-trip" (roundtrips "3bffffffffffffffff")
```
