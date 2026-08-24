require "./spec_helper"

# Ed25519 sign -> verify accept-path unit via the direct in-process libsodium C
# binding. The corpus `signature` category is an ENCODE-side byte-pin (produced
# sig == canonical); this adds the ACCEPT path the corpus can't cover — a real
# verify(true) plus a tamper-negative — the "conformance-green can be vacuous"
# lesson (always add the direction the oracle can't reach).
describe EntityCore::Signature do
  seed = Bytes.new(32, 0_u8) # all-zero deterministic seed (RFC 8032)
  entity = begin
    data = Hash(EntityCore::Cbor::EcValue, EntityCore::Cbor::EcValue).new
    data["x"] = EntityCore::Cbor::EcInt.from(1)
    m = Hash(EntityCore::Cbor::EcValue, EntityCore::Cbor::EcValue).new
    m["type"] = "test/v1"
    m["data"] = data
    m.as(EntityCore::Cbor::EcValue)
  end

  it "derives a 32-byte public key from a 32-byte seed" do
    pk = EntityCore::Signature.public_key(seed)
    pk.size.should eq(32)
  end

  it "sign -> verify round-trips (accept path)" do
    sig = EntityCore::Signature.sign(seed, entity)
    sig.size.should eq(64)
    pk = EntityCore::Signature.public_key(seed)
    EntityCore::Signature.verify(pk, entity, sig).should be_true
  end

  it "matches the corpus signature.1 byte-pin (deterministic Ed25519)" do
    sig = EntityCore::Signature.sign(seed, entity)
    sig.hexstring.should eq(
      "3f0b5d06636ea267199dc27eb20d8c9b37684d681adc5be43be465819ad643e3" \
      "b152e5c024bf67ce862699fe439462d7852b029cb125cd917d12a3151529230c"
    )
  end

  it "rejects a tampered signature (negative path)" do
    sig = EntityCore::Signature.sign(seed, entity)
    tampered = sig.dup
    tampered[0] ^= 0xFF_u8
    pk = EntityCore::Signature.public_key(seed)
    EntityCore::Signature.verify(pk, entity, tampered).should be_false
  end

  it "rejects a signature over a different message (negative path)" do
    sig = EntityCore::Signature.sign(seed, entity)
    pk = EntityCore::Signature.public_key(seed)
    other = Hash(EntityCore::Cbor::EcValue, EntityCore::Cbor::EcValue).new
    other["type"] = "test/v1"
    other["data"] = "different"
    EntityCore::Signature.verify(pk, other.as(EntityCore::Cbor::EcValue), sig).should be_false
  end
end
