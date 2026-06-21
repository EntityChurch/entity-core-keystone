# frozen_string_literal: true

require_relative "test_helper"

class CodecTest < Minitest::Test
  include EntityCore

  def hex(bytes)
    bytes.b.unpack1("H*")
  end

  def from_hex(str)
    [str].pack("H*")
  end

  # ── encode spot-checks ────────────────────────────────────────────────────

  def test_integer_minimal_encoding
    assert_equal "00", hex(Cbor.encode(0))
    assert_equal "17", hex(Cbor.encode(23))
    assert_equal "1818", hex(Cbor.encode(24))
    assert_equal "1b7fffffffffffffff", hex(Cbor.encode(9_223_372_036_854_775_807))
    assert_equal "20", hex(Cbor.encode(-1))
    assert_equal "3818", hex(Cbor.encode(-25))
  end

  def test_uint64_full_range_no_native_int_trap
    # Ruby Integer is arbitrary-precision — max uint64 is just an Integer.
    assert_equal "1bffffffffffffffff", hex(Cbor.encode(0xFFFF_FFFF_FFFF_FFFF))
  end

  def test_float_ladder
    assert_equal "f93c00", hex(Cbor.encode(1.0))         # f16
    assert_equal "f97bff", hex(Cbor.encode(65_504.0))    # max f16
    assert_equal "fa477fdf00", hex(Cbor.encode(65_503.0)) # f32 (not f16)
    assert_equal "fb3ff199999999999a", hex(Cbor.encode(1.1)) # f64
  end

  def test_float_specials
    assert_equal "f97e00", hex(Cbor.encode(Float::NAN))
    assert_equal "f97c00", hex(Cbor.encode(Float::INFINITY))
    assert_equal "f9fc00", hex(Cbor.encode(-Float::INFINITY))
    assert_equal "f98000", hex(Cbor.encode(-0.0))
    assert_equal "f90000", hex(Cbor.encode(0.0))
  end

  def test_map_key_ordering_length_then_lex
    # 'z' (len 1) before 'aa' (len 2): length-first.
    assert_equal "a2617a0162616102", hex(Cbor.encode({ "aa" => 2, "z" => 1 }))
    # 'a' before 'b': lexicographic at equal length.
    assert_equal "a2616101616202", hex(Cbor.encode({ "b" => 2, "a" => 1 }))
  end

  def test_byte_vs_text_string_via_encoding
    assert_equal "43abcdef", hex(Cbor.encode(from_hex("abcdef"))) # BINARY → major 2
    assert_equal "63666f6f", hex(Cbor.encode("foo"))             # UTF-8 → major 3
  end

  # ── round-trip ────────────────────────────────────────────────────────────

  def test_roundtrip_nested_entity
    value = { "type" => "test/v1", "data" => { "a" => 1, "b" => "two" } }
    assert_equal value, Cbor.decode(Cbor.encode(value))
  end

  def test_roundtrip_specials_and_floats
    [Float::INFINITY, -Float::INFINITY, -0.0, 1.5, 1.1, 65_504.0].each do |f|
      decoded = Cbor.decode(Cbor.encode(f))
      assert_equal [f].pack("G"), [decoded].pack("G"), "roundtrip #{f}"
    end
    assert Cbor.decode(Cbor.encode(Float::NAN)).nan?
  end

  # ── N1: varint (multicodec LEB128) ────────────────────────────────────────

  def test_n1_varint_multibyte
    assert_equal "8001", hex(Varint.encode(128))
    val, rest = Varint.decode(from_hex("8001"))
    assert_equal 128, val
    assert_equal "", rest
  end

  # ── N2: recursive tag rejection ───────────────────────────────────────────

  def test_n2_rejects_top_level_tag
    assert_raises(EntityCore::NonCanonicalError) { Cbor.decode(from_hex("c000")) }
  end

  def test_n2_rejects_nested_tag
    # {"data": <tag 0> "..."} — tag buried in a map value.
    wire = "a164646174 61c074323032362d30362d30365431323a30303a30305a".delete(" ")
    assert_raises(EntityCore::NonCanonicalError) { Cbor.decode(from_hex(wire)) }
  end

  def test_n2_rejects_self_describe_frame
    assert_raises(EntityCore::NonCanonicalError) { Cbor.decode(from_hex("d9d9f7a0")) }
  end

  # ── N3: empty map is the single byte 0xA0 ─────────────────────────────────

  def test_n3_empty_map_is_a0
    assert_equal "a0", hex(Cbor.encode({}))
    assert_equal({}, Cbor.decode(from_hex("a0")))
  end

  # ── decode rejects non-canonical ──────────────────────────────────────────

  def test_rejects_non_minimal_int
    assert_raises(EntityCore::NonCanonicalError) { Cbor.decode(from_hex("1800")) } # 0 in 1-byte form
  end

  def test_rejects_indefinite_length
    assert_raises(EntityCore::NonCanonicalError) { Cbor.decode(from_hex("9fff")) }
  end

  def test_rejects_trailing_bytes
    assert_raises(EntityCore::NonCanonicalError) { Cbor.decode(from_hex("0000")) }
  end

  def test_rejects_duplicate_map_key
    assert_raises(EntityCore::NonCanonicalError) { Cbor.decode(from_hex("a2616101616102")) }
  end

  # ── base58 + peer_id ──────────────────────────────────────────────────────

  def test_base58_roundtrip_with_leading_zeros
    raw = from_hex("0000ff")
    assert_equal raw, Base58.decode(Base58.encode(raw))
  end

  def test_peer_id_format_and_parse
    digest = from_hex("00" * 32)
    pid = PeerId.format(1, 1, digest)
    kt, ht, dig = PeerId.parse(pid)
    assert_equal [1, 1, digest], [kt, ht, dig]
  end

  # ── A-RUBY-003: raw-key crypto API confirmation ───────────────────────────

  def test_ed25519_raw_key_roundtrip
    seed = from_hex("00" * 32)
    pub = Signature.public_key(seed, :ed25519)
    assert_equal 32, pub.bytesize
    msg = "hello".b
    sig = Signature.sign_raw(seed, msg, :ed25519)
    assert_equal 64, sig.bytesize
    assert Signature.verify_raw(pub, msg, sig, :ed25519)
    refute Signature.verify_raw(pub, "hellp".b, sig, :ed25519)
  end

  def test_ed448_raw_key_roundtrip
    seed = from_hex("42" * 57)
    pub = Signature.public_key(seed, :ed448)
    assert_equal 57, pub.bytesize
    msg = "hello".b
    sig = Signature.sign_raw(seed, msg, :ed448)
    assert_equal 114, sig.bytesize
    assert Signature.verify_raw(pub, msg, sig, :ed448)
  end
end
