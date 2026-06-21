defmodule EntityCore.Identity do
  @moduledoc """
  Identity (L1) — a peer's keypair and the entities derived from it (§1.5, §3.5,
  §7.3). The peer's identity is an Ed25519 seed; everything else derives:

      public_key    = Ed25519 pub of seed                          (32 bytes)
      peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)   (§1.5 identity-multihash)
      peer entity   = system/peer {public_key, key_type}           (§3.5; v7.65 — NO
                      peer_id in the hashable basis)
      identity_hash = content_hash(peer entity)                    (33 bytes)

  Signing is over the full 33-byte content_hash (format byte ‖ digest, §7.3), so a
  signature is bound to the hash format.

  Spec-first note (A-OC-007, inherited): §7.4's NORMATIVE peer-id pseudocode shows
  the pre-v7.65 SHA-256-form (`hash_type = 0x01`, `SHA256(public_key)`), which
  contradicts the §1.5 v7.65 canonical-form table (identity-multihash, `hash_type
  = 0x00`, raw public_key) for Ed25519. We follow §1.5 (the later, specific
  contract) — same reading as peers #1-3.
  """

  alias EntityCore.{Entity, Model, PeerId, Signature}

  @enforce_keys [:seed, :public_key, :peer_id, :peer_entity, :identity_hash]
  defstruct [:seed, :public_key, :peer_id, :peer_entity, :identity_hash]

  @type t :: %__MODULE__{
          seed: binary(),
          public_key: binary(),
          peer_id: String.t(),
          peer_entity: Entity.t(),
          identity_hash: binary()
        }

  @doc "The `system/peer` entity for a raw public key (§3.5; key_type ed25519)."
  @spec peer_entity_of_pubkey(binary()) :: Entity.t()
  def peer_entity_of_pubkey(public_key) when is_binary(public_key) do
    Model.make("system/peer", %{"public_key" => {:bytes, public_key}, "key_type" => "ed25519"})
  end

  @doc "The Ed25519 canonical peer_id for a raw public key (§1.5 identity-multihash)."
  @spec peer_id_of_pubkey(binary()) :: String.t()
  def peer_id_of_pubkey(public_key) when is_binary(public_key) do
    PeerId.from_public_key(public_key, :ed25519)
  end

  @doc "Build the identity bundle from a 32-byte Ed25519 seed."
  @spec of_seed(binary()) :: t()
  def of_seed(seed) when is_binary(seed) do
    public_key = Signature.public_key(seed, :ed25519)
    peer_entity = peer_entity_of_pubkey(public_key)

    %__MODULE__{
      seed: seed,
      public_key: public_key,
      peer_id: peer_id_of_pubkey(public_key),
      peer_entity: peer_entity,
      identity_hash: peer_entity.hash
    }
  end

  @doc """
  Sign a target entity's content_hash and produce the `system/signature` entity
  (§3.5): `target` = signed entity hash, `signer` = our identity hash.
  """
  @spec sign_entity(t(), Entity.t()) :: Entity.t()
  def sign_entity(%__MODULE__{} = id, %Entity{} = target) do
    sig = Signature.sign_raw(id.seed, target.hash, :ed25519)

    Model.make("system/signature", %{
      "target" => {:bytes, target.hash},
      "signer" => {:bytes, id.identity_hash},
      "algorithm" => "ed25519",
      "signature" => {:bytes, sig}
    })
  end

  @doc """
  Verify a `system/signature` entity against the signer's `system/peer` entity.
  Reads `public_key` from the peer entity; the §5.2 signer-hash check is the
  caller's responsibility.
  """
  @spec verify_signature(Entity.t(), Entity.t()) :: boolean()
  def verify_signature(%Entity{} = signature, %Entity{} = signer_peer) do
    with target when is_binary(target) <- Model.bytes_field(signature, "target"),
         sig when is_binary(sig) <- Model.bytes_field(signature, "signature"),
         pub when is_binary(pub) <- Model.bytes_field(signer_peer, "public_key") do
      curve = if Model.text_field(signer_peer, "key_type") == "ed448", do: :ed448, else: :ed25519
      Signature.verify_raw(pub, target, sig, curve)
    else
      _ -> false
    end
  end
end
