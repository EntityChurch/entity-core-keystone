defmodule EntityCore.Signature do
  @moduledoc """
  Ed25519 (and Ed448) sign/verify over canonical-ECF-encoded entities, via OTP
  `:crypto` (OpenSSL backend). RFC 8032 deterministic signing — a fixed seed +
  fixed message yields fixed signature bytes.

  Ed25519 seeds are 32 bytes (64-byte signature); Ed448 seeds are 57 bytes
  (114-byte signature). Ed448 is reachable natively here (no FFI) — see the S1
  rationale.
  """

  alias EntityCore.Cbor

  @doc "Sign a raw message (already-serialized bytes) with a raw seed."
  @spec sign_raw(binary(), binary(), :ed25519 | :ed448) :: binary()
  def sign_raw(seed, message, curve \\ :ed25519) when is_binary(seed) and is_binary(message) do
    :crypto.sign(:eddsa, :none, message, [seed, curve])
  end

  @doc "Sign the canonical ECF encoding of `entity` with a raw seed."
  @spec sign(binary(), map(), :ed25519 | :ed448) :: binary()
  def sign(seed, entity, curve \\ :ed25519) when is_binary(seed) and is_map(entity) do
    :crypto.sign(:eddsa, :none, Cbor.encode(entity), [seed, curve])
  end

  @doc "Verify a signature over the canonical ECF encoding of `entity`."
  @spec verify(binary(), map(), binary(), :ed25519 | :ed448) :: boolean()
  def verify(public_key, entity, signature, curve \\ :ed25519)
      when is_binary(public_key) and is_map(entity) and is_binary(signature) do
    :crypto.verify(:eddsa, :none, Cbor.encode(entity), signature, [public_key, curve])
  end

  @doc "Verify a signature over a raw message (already-serialized bytes, e.g. a content_hash)."
  @spec verify_raw(binary(), binary(), binary(), :ed25519 | :ed448) :: boolean()
  def verify_raw(public_key, message, signature, curve \\ :ed25519)
      when is_binary(public_key) and is_binary(message) and is_binary(signature) do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, curve])
  end

  @doc "Derive the public key from a raw seed (seed -> pubkey, V7 §1.2 identity)."
  @spec public_key(binary(), :ed25519 | :ed448) :: binary()
  def public_key(seed, curve \\ :ed25519) when is_binary(seed) do
    {pub, ^seed} = :crypto.generate_key(:eddsa, curve, seed)
    pub
  end
end
