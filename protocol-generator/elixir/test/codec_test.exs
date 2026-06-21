defmodule EntityCore.CodecTest do
  @moduledoc "Selftest: round-trips and crypto behavior beyond the corpus."
  use ExUnit.Case, async: true

  alias EntityCore.{Base58, Cbor, Hash, PeerId, Signature, Varint}

  describe "CBOR round-trip" do
    test "encode |> decode is identity for representative shapes" do
      values = [
        0,
        -1,
        9_223_372_036_854_775_807,
        1.5,
        1.1,
        :nan,
        :inf,
        :neg_inf,
        "hello 世界",
        {:bytes, <<0xDE, 0xAD, 0xBE, 0xEF>>},
        [],
        [1, 2, 3],
        %{},
        %{"type" => "test/v1", "data" => %{"z" => 1, "a" => 2, "bb" => 3}},
        %{{:bytes, <<1, 2, 3>>} => true, "k" => nil}
      ]

      for v <- values do
        assert {:ok, decoded} = Cbor.decode(Cbor.encode(v))
        assert decoded == v
      end
    end

    test "-0.0 survives the round-trip distinctly from +0.0" do
      assert {:ok, neg} = Cbor.decode(Cbor.encode(-0.0))
      assert neg === -0.0
      assert Cbor.encode(-0.0) == <<0xF9, 0x80, 0x00>>
      assert Cbor.encode(0.0) == <<0xF9, 0x00, 0x00>>
    end

    test "decode rejects CBOR tags (N2) and trailing bytes" do
      assert {:error, %EntityCore.Error{kind: :non_canonical_ecf}} = Cbor.decode(<<0xC0, 0x00>>)
      assert {:error, %EntityCore.Error{kind: :trailing_bytes}} = Cbor.decode(<<0x00, 0x00>>)
    end
  end

  describe "crypto (OTP :crypto, native)" do
    test "Ed25519 sign/verify over an entity, tamper rejects" do
      seed = :binary.copy(<<7>>, 32)
      pub = Signature.public_key(seed, :ed25519)
      entity = %{"type" => "test/v1", "data" => %{"x" => 1}}
      sig = Signature.sign(seed, entity)
      assert byte_size(sig) == 64
      assert Signature.verify(pub, entity, sig)
      refute Signature.verify(pub, %{"type" => "test/v1", "data" => %{"x" => 2}}, sig)
    end

    test "Ed448 sign/verify (native, no FFI), tamper rejects" do
      seed = :binary.copy(<<9>>, 57)
      pub = Signature.public_key(seed, :ed448)
      assert byte_size(pub) == 57
      entity = %{"type" => "test/v1", "data" => %{"x" => 1}}
      sig = Signature.sign(seed, entity, :ed448)
      assert byte_size(sig) == 114
      assert Signature.verify(pub, entity, sig, :ed448)
      refute Signature.verify(pub, %{"type" => "test/v1", "data" => %{"x" => 2}}, sig, :ed448)
    end
  end

  describe "peer-id + base58 + varint" do
    test "peer-id parse is the inverse of format" do
      digest = :binary.copy(<<0xAB>>, 32)
      pid = PeerId.format(1, 0, digest)
      assert {:ok, {1, 0, ^digest}} = PeerId.parse(pid)
    end

    test "base58 round-trips, preserving leading-zero bytes" do
      for b <- [<<>>, <<0>>, <<0, 0, 1, 2, 3>>, :crypto.strong_rand_bytes(20)] do
        assert {:ok, ^b} = Base58.decode(Base58.encode(b))
      end
    end

    test "varint round-trips across the byte boundary" do
      for n <- [0, 1, 127, 128, 255, 16_383, 16_384, 1_000_000] do
        assert {:ok, ^n, <<>>} = Varint.decode(Varint.encode(n))
      end
    end
  end

  describe "content hash" do
    test "format registry: 0/1 resolve, others rejected" do
      assert {:ok, :sha256} = Hash.resolve_format(0)
      assert {:ok, :sha384} = Hash.resolve_format(1)
      assert {:error, :unsupported_content_hash_format} = Hash.resolve_format(128)
      assert {:error, :unsupported_content_hash_format} = Hash.resolve_wire_format(<<0x80, 0x01>>)
    end
  end
end
