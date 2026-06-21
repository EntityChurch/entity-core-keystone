# frozen_string_literal: true

require_relative "entity"
require_relative "peer_id"
require_relative "signature"

module EntityCore
  # A peer's identity (L1): an Ed25519 seed and everything derived from it
  # (§1.5, §3.5, §7.3).
  #
  #   public_key    = Ed25519 public key of seed                  (32 bytes)
  #   peer_id       = §1.5 canonical-form identity-multihash       (A-SW-008)
  #   peer_entity   = system/peer {public_key, key_type}           (§3.5; v7.65 —
  #                   NO peer_id in the hashable basis)
  #   identity_hash = content_hash(peer_entity)                    (33 bytes)
  #
  # Signing is over the full 33-byte content_hash (format byte + digest, §7.3),
  # so a signature is bound to the hash format. peer_id is the §1.5
  # identity-multihash form — the §7.4 SHA-256 pseudocode is stale and fails the
  # handshake; this follows §1.5 (A-SW-008 erratum).
  class Identity
    attr_reader :seed, :public_key, :peer_id, :peer_entity, :identity_hash

    def initialize(seed)
      @seed = seed.b
      @public_key = Signature.public_key(@seed, :ed25519)
      @peer_entity = self.class.peer_entity_of_public_key(@public_key)
      @peer_id = PeerId.from_public_key(@public_key, :ed25519)
      @identity_hash = @peer_entity.content_hash
      freeze
    end

    def self.of_seed(seed)
      new(seed)
    end

    # The system/peer entity for a raw public key (v7.65: no peer_id field).
    def self.peer_entity_of_public_key(public_key)
      Entity.make("system/peer",
                  { "public_key" => public_key.b, "key_type" => "ed25519" })
    end

    # The §1.5 canonical (identity-multihash) peer_id for a raw Ed25519 pubkey.
    def self.peer_id_of_public_key(public_key)
      PeerId.from_public_key(public_key.b, :ed25519)
    end

    # Sign a target entity's content_hash → a system/signature entity (§3.5):
    # +target+ = the signed entity's hash, +signer+ = our identity hash.
    def sign(target)
      sig = Signature.sign_raw(@seed, target.content_hash, :ed25519)
      Entity.make("system/signature",
                  {
                    "target" => target.content_hash,
                    "signer" => @identity_hash,
                    "algorithm" => "ed25519",
                    "signature" => sig
                  })
    end

    # Verify a system/signature entity against the signer's system/peer entity.
    # The §5.2 signer-hash binding is the caller's responsibility.
    def self.verify_signature(signature, signer_peer)
      target = signature.bytes("target")
      sig = signature.bytes("signature")
      pub = signer_peer.bytes("public_key")
      return false if target.nil? || sig.nil? || pub.nil?

      Signature.verify_raw(pub, target, sig, :ed25519)
    rescue OpenSSL::PKey::PKeyError, OpenSSL::OpenSSLError
      false
    end
  end
end
