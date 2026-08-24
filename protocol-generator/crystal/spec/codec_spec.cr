require "./spec_helper"

# Fixed-width uint64 head-form self-test + targeted decode-reject probes. Crystal
# ints are FIXED-WIDTH: a uint in [2^63, 2^64-1] does NOT fit Int64 and must be
# carried as UInt64 with the correct CBOR major-0 head form (the profile's
# native_fixed_width_int trap — the Ruby peer's native_bignum does NOT hold).
describe "EntityCore::Cbor fixed-width uint64 head-form" do
  it "encodes 2^63 with the 9-byte major-0 head (1b 8000000000000000)" do
    v = EntityCore::Cbor::EcInt.new(0_u8, 0x8000_0000_0000_0000_u64)
    EntityCore::Cbor.encode(v).hexstring.should eq("1b8000000000000000")
  end

  it "encodes 2^64-1 (max uint64) with the 9-byte major-0 head (1b ffffffffffffffff)" do
    v = EntityCore::Cbor::EcInt.new(0_u8, 0xFFFF_FFFF_FFFF_FFFF_u64)
    EntityCore::Cbor.encode(v).hexstring.should eq("1bffffffffffffffff")
  end

  it "encodes 2^63-1 (max signed i64) from a native Int64 with the same head" do
    EntityCore::Cbor.encode(Int64::MAX).hexstring.should eq("1b7fffffffffffffff")
  end

  it "round-trips 2^64-1 through decode preserving the full-range EcInt" do
    wire = "1bffffffffffffffff".hexbytes
    decoded = EntityCore::Cbor.decode(wire)
    ec = decoded.as(EntityCore::Cbor::EcInt)
    ec.major.should eq(0_u8)
    ec.arg.should eq(0xFFFF_FFFF_FFFF_FFFF_u64)
    EntityCore::Cbor.encode(decoded).should eq(wire)
  end

  it "encodes -2^64 (min nint) with the 9-byte major-1 head (3b ffffffffffffffff)" do
    # value = -1 - arg; arg = 2^64-1 => value = -2^64
    v = EntityCore::Cbor::EcInt.new(1_u8, 0xFFFF_FFFF_FFFF_FFFF_u64)
    EntityCore::Cbor.encode(v).hexstring.should eq("3bffffffffffffffff")
  end
end

describe "EntityCore::Cbor decode rejection (N2 / non-canonical)" do
  it "rejects a bare CBOR tag anywhere (major type 6)" do
    expect_raises(EntityCore::NonCanonicalError) do
      EntityCore::Cbor.decode("c000".hexbytes) # tag 0 wrapping 0
    end
  end

  it "rejects a non-minimal integer argument (18 01 == 1 in long form)" do
    expect_raises(EntityCore::NonCanonicalError) do
      EntityCore::Cbor.decode("1801".hexbytes)
    end
  end

  it "rejects indefinite-length arrays (9f ... ff)" do
    expect_raises(EntityCore::NonCanonicalError) do
      EntityCore::Cbor.decode("9f01ff".hexbytes)
    end
  end

  it "rejects duplicate map keys" do
    expect_raises(EntityCore::NonCanonicalError) do
      EntityCore::Cbor.decode("a2616101616102".hexbytes) # {a:1, a:2}
    end
  end

  it "rejects trailing bytes after a complete value" do
    expect_raises(EntityCore::NonCanonicalError) do
      EntityCore::Cbor.decode("0000".hexbytes)
    end
  end
end

# byte-string vs text-string fidelity: the map-key sort must distinguish the two
# major types (map_keys.5 in the corpus). Regression guard on the tagged union.
describe "EntityCore::Cbor byte/text key distinction" do
  it "sorts a byte-string key before a longer text key (length-first)" do
    map = Hash(EntityCore::Cbor::EcValue, EntityCore::Cbor::EcValue).new
    map[Bytes[0x6b, 0x65, 0x79]] = EntityCore::Cbor::EcInt.from(2)
    map["text_key"] = EntityCore::Cbor::EcInt.from(1)
    EntityCore::Cbor.encode(map).hexstring.should eq("a2436b65790268746578745f6b657901")
  end
end
